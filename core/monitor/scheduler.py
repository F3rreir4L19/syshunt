"""Celery tasks for platform monitoring with automatic Beat scheduling."""
from __future__ import annotations

import os
from urllib.parse import urlparse

import structlog

from core.pipeline.tasks import celery_app

_log = structlog.get_logger()

_MAX_RECON_TARGETS_DEFAULT = 10

# Non-web asset types that should not be turned into recon Targets.
_SKIP_ASSET_TYPES = frozenset(
    {
        "android",
        "ios",
        "cidr",
        "executable",
        "other",
        "hardware",
        "source_code",
        "smart_contract",
    }
)


def _domain_from_scope_identifier(identifier: str) -> str | None:
    """Extract a recon-safe hostname from a scope asset identifier.

    Handles URL-style (https://example.com), bare domains, and wildcards
    (*.example.com → example.com).  Returns None for IPs, CIDRs, empty
    strings, and other non-domain identifiers.
    """
    import ipaddress

    if not identifier or not identifier.strip():
        return None

    s = identifier.strip()

    # Strip leading wildcard
    if s.startswith("*."):
        s = s[2:]

    # Parse hostname
    if "://" in s:
        parsed = urlparse(s)
        hostname = parsed.hostname or ""
    else:
        parsed = urlparse("https://" + s)
        hostname = parsed.hostname or ""

    if not hostname or " " in hostname:
        return None

    # Reject IP addresses
    try:
        ipaddress.ip_address(hostname)
        return None
    except ValueError:
        pass

    return hostname.lower() or None


@celery_app.task(name="core.monitor.poll_hackerone")
def poll_hackerone() -> dict:
    """Fetch HackerOne programs and sync to DB.

    Reads HACKERONE_USERNAME and HACKERONE_API_TOKEN from environment.
    Returns stats dict: {fetched, new, scope_changed, errors}.
    Skips silently if credentials are not configured.
    """
    username = os.getenv("HACKERONE_USERNAME", "")
    api_token = os.getenv("HACKERONE_API_TOKEN", "")

    if not username or not api_token:
        _log.info("hackerone_poll_skipped", reason="credentials_not_configured")
        return {"skipped": True, "reason": "credentials_not_configured"}

    from core.db.session import SessionLocal
    from core.monitor.hackerone import HackerOneMonitor

    monitor = HackerOneMonitor(username=username, api_token=api_token)
    try:
        with SessionLocal() as session:
            return monitor.sync_programs(session)
    except Exception as exc:
        _log.warning("hackerone_poll_error", error=str(exc))
        return {"skipped": True, "error": str(exc)}


@celery_app.task(name="core.monitor.poll_bugcrowd")
def poll_bugcrowd() -> dict:
    """Fetch Bugcrowd programs and sync to DB.

    Reads BUGCROWD_API_TOKEN from environment.
    Returns stats dict: {fetched, new, scope_changed, errors}.
    Skips silently if credentials are not configured.
    """
    api_token = os.getenv("BUGCROWD_API_TOKEN", "")

    if not api_token:
        _log.info("bugcrowd_poll_skipped", reason="credentials_not_configured")
        return {"skipped": True, "reason": "credentials_not_configured"}

    from core.db.session import SessionLocal
    from core.monitor.bugcrowd import BugcrowdMonitor

    monitor = BugcrowdMonitor(api_token=api_token)
    try:
        with SessionLocal() as session:
            return monitor.sync_programs(session)
    except Exception as exc:
        _log.warning("bugcrowd_poll_error", error=str(exc))
        return {"skipped": True, "error": str(exc)}


@celery_app.task(name="core.monitor.poll_intigriti")
def poll_intigriti() -> dict:
    """Fetch Intigriti programs and sync to DB.

    Reads INTIGRITI_CLIENT_ID and INTIGRITI_CLIENT_SECRET from environment.
    Returns stats dict: {fetched, new, scope_changed, errors}.
    Skips silently if credentials are not configured.
    """
    client_id = os.getenv("INTIGRITI_CLIENT_ID", "")
    client_secret = os.getenv("INTIGRITI_CLIENT_SECRET", "")

    if not client_id or not client_secret:
        _log.info("intigriti_poll_skipped", reason="credentials_not_configured")
        return {"skipped": True, "reason": "credentials_not_configured"}

    from core.db.session import SessionLocal
    from core.monitor.intigriti import IntigritiMonitor

    monitor = IntigritiMonitor(client_id=client_id, client_secret=client_secret)
    try:
        with SessionLocal() as session:
            return monitor.sync_programs(session)
    except Exception as exc:
        _log.warning("intigriti_poll_error", error=str(exc))
        return {"skipped": True, "error": str(exc)}


@celery_app.task(name="core.monitor.poll_all_platforms")
def poll_all_platforms() -> dict:
    """Orchestrate polling of all configured platforms.

    Calls each platform task in sequence and aggregates results.
    Returns {platforms: {hackerone: {}, bugcrowd: {}, intigriti: {}},
             total_new: int, total_scope_changed: int, total_errors: int}.
    """
    platform_tasks = [
        ("hackerone", poll_hackerone),
        ("bugcrowd", poll_bugcrowd),
        ("intigriti", poll_intigriti),
    ]

    results: dict[str, dict] = {}
    total_new = 0
    total_scope_changed = 0
    total_errors = 0

    for name, task_fn in platform_tasks:
        try:
            r = task_fn()
            results[name] = r
            if not r.get("skipped"):
                total_new += r.get("new", 0)
                total_scope_changed += r.get("scope_changed", 0)
                total_errors += r.get("errors", 0)
        except Exception as exc:
            _log.warning("poll_all_platforms_task_error", platform=name, error=str(exc))
            results[name] = {"skipped": True, "error": str(exc)}

    return {
        "platforms": results,
        "total_new": total_new,
        "total_scope_changed": total_scope_changed,
        "total_errors": total_errors,
    }


@celery_app.task(name="core.monitor.trigger_recon_for_new_program")
def trigger_recon_for_new_program(program_id: int) -> dict:
    """Create Targets from a BountyProgram's scope and dispatch the full pipeline.

    Respects:
    - ``auto_recon_enabled`` flag on the program record
    - ``ALLOW_LOCAL_TARGETS`` env var (private/loopback targets blocked by default)
    - ``MAX_RECON_TARGETS_PER_PROGRAM`` env var (default 10)

    Returns {program_id, targets_created, targets_reused, dispatched, skipped}.
    """
    from sqlalchemy.exc import IntegrityError

    from core.db.models import BountyProgram, Target
    from core.db.queries import _allow_local_targets, _is_local_or_private, normalize_domain
    from core.db.session import SessionLocal
    from core.pipeline.tasks import run_full_pipeline

    max_targets = int(
        os.getenv("MAX_RECON_TARGETS_PER_PROGRAM", str(_MAX_RECON_TARGETS_DEFAULT))
    )

    with SessionLocal() as session:
        program = session.get(BountyProgram, program_id)
        if program is None:
            _log.warning("trigger_recon_program_not_found", program_id=program_id)
            return {"program_id": program_id, "error": "program_not_found", "skipped": True}

        if not program.auto_recon_enabled:
            _log.info(
                "trigger_recon_auto_disabled",
                program_id=program_id,
                handle=program.program_handle,
            )
            return {
                "program_id": program_id,
                "skipped": True,
                "reason": "auto_recon_disabled",
            }

        scope: list[dict] = list(program.scope or [])
        platform = program.platform
        program_handle = program.program_handle

    # Extract unique domain candidates from scope items
    allow_local = _allow_local_targets()
    seen: set[str] = set()
    candidates: list[str] = []

    for item in scope:
        asset_type = item.get("asset_type", "").lower()
        if asset_type in _SKIP_ASSET_TYPES:
            continue
        identifier = item.get("asset_identifier", "")
        domain = _domain_from_scope_identifier(identifier)
        if domain and domain not in seen:
            seen.add(domain)
            candidates.append(domain)

    limited = candidates[:max_targets]

    targets_created = 0
    targets_reused = 0
    dispatched = 0
    skipped = 0

    for domain in limited:
        try:
            normalized = normalize_domain(domain)
        except ValueError:
            skipped += 1
            continue

        if not allow_local and _is_local_or_private(normalized):
            skipped += 1
            continue

        target_id: int | None = None

        with SessionLocal() as session:
            existing = session.query(Target).filter_by(domain=normalized).first()
            if existing is not None:
                target_id = existing.id
                targets_reused += 1
            else:
                try:
                    target = Target(
                        domain=normalized,
                        scope_includes=[normalized],
                        scope_excludes=[],
                        platform=platform,
                        program_id=str(program_id),
                    )
                    session.add(target)
                    session.commit()
                    session.refresh(target)
                    target_id = target.id
                    targets_created += 1
                except IntegrityError:
                    session.rollback()
                    # Race: another worker created the same target between our check and insert
                    existing = session.query(Target).filter_by(domain=normalized).first()
                    if existing is not None:
                        target_id = existing.id
                        targets_reused += 1
                    else:
                        skipped += 1
                        continue

        if target_id is not None:
            run_full_pipeline.apply_async(args=[target_id])
            dispatched += 1

    _log.info(
        "trigger_recon_complete",
        program_id=program_id,
        handle=program_handle,
        targets_created=targets_created,
        targets_reused=targets_reused,
        dispatched=dispatched,
        skipped=skipped,
    )

    return {
        "program_id": program_id,
        "targets_created": targets_created,
        "targets_reused": targets_reused,
        "dispatched": dispatched,
        "skipped": skipped,
    }


# ---------------------------------------------------------------------------
# Celery Beat schedule — per-platform configurable polling intervals
# ---------------------------------------------------------------------------

_default_interval = int(os.getenv("PLATFORM_POLL_INTERVAL_SECONDS", "1800"))
_h1_interval = int(os.getenv("HACKERONE_POLL_INTERVAL_SECONDS", str(_default_interval)))
_bc_interval = int(os.getenv("BUGCROWD_POLL_INTERVAL_SECONDS", str(_default_interval)))
_ig_interval = int(os.getenv("INTIGRITI_POLL_INTERVAL_SECONDS", str(_default_interval)))

celery_app.conf.beat_schedule.update(
    {
        "poll-hackerone": {
            "task": "core.monitor.poll_hackerone",
            "schedule": _h1_interval,
        },
        "poll-bugcrowd": {
            "task": "core.monitor.poll_bugcrowd",
            "schedule": _bc_interval,
        },
        "poll-intigriti": {
            "task": "core.monitor.poll_intigriti",
            "schedule": _ig_interval,
        },
    }
)
