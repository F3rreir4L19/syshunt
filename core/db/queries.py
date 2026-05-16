from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
from typing import Any

from celery import Celery
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy import or_
from sqlalchemy.orm import Session

from core.db.models import BountyProgram, Finding, ReconResult, SystemSetting, Target

# Valid domain: labels of letters/digits/hyphens separated by dots, no leading/trailing
# hyphens per label.  Also accepts plain hostnames without a dot (e.g. "localhost").
_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?$"
)


# ---------------------------------------------------------------------------
# Target helpers
# ---------------------------------------------------------------------------


def _is_local_or_private(domain: str) -> bool:
    """Return True if *domain* looks like a local/private/loopback target.

    Checks performed (in order):
    - Exact name: localhost, localdomain
    - TLD suffix: .local, .localhost
    - IP address: loopback, private, link-local, reserved, multicast
    """
    lower = domain.lower()
    if lower in {"localhost", "localdomain"}:
        return True
    if lower.endswith(".local") or lower.endswith(".localhost"):
        return True
    try:
        addr = ipaddress.ip_address(lower)
        return (
            addr.is_loopback
            or addr.is_private
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
        )
    except ValueError:
        return False


def normalize_domain(domain: str) -> str:
    cleaned = domain.strip().lower()
    if cleaned.startswith("http://"):
        cleaned = cleaned.removeprefix("http://")
    elif cleaned.startswith("https://"):
        cleaned = cleaned.removeprefix("https://")
    cleaned = cleaned.strip("/")
    if cleaned and not _DOMAIN_RE.match(cleaned):
        raise ValueError(
            f"Invalid domain {domain!r}: only letters, digits, hyphens and dots are allowed"
        )
    return cleaned


def _allow_local_targets() -> bool:
    return os.getenv("ALLOW_LOCAL_TARGETS", "false").lower() in {"true", "1", "yes"}


def create_target(
    session: Session,
    domain: str,
    auto_analyze: bool = True,
    scope_includes: list[str] | None = None,
    scope_excludes: list[str] | None = None,
    platform: str | None = None,
    program_id: str | None = None,
    recon_depth: int = 2,
) -> Target:
    normalized = normalize_domain(domain)
    if not normalized:
        raise ValueError("Domain is required.")
    if not _allow_local_targets() and _is_local_or_private(normalized):
        raise ValueError(
            f"Local/private target {normalized!r} is blocked by default. "
            "Set ALLOW_LOCAL_TARGETS=true to allow scanning local/private targets."
        )

    target = Target(
        domain=normalized,
        scope_includes=scope_includes if scope_includes is not None else [normalized],
        scope_excludes=scope_excludes if scope_excludes is not None else [],
        auto_analyze=auto_analyze,
        platform=platform,
        program_id=program_id,
        recon_depth=recon_depth,
    )
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


def bulk_create_targets(
    session: Session, domains: list[str]
) -> tuple[int, int, list[str]]:
    """Create multiple targets from a list of domain strings.

    Returns (created, skipped, errors) where errors is a list of problem strings.
    Skips duplicates silently (existing domain = already present).
    """
    from sqlalchemy.exc import IntegrityError

    allow_local = _allow_local_targets()
    created = 0
    skipped = 0
    errors: list[str] = []
    for raw in domains:
        try:
            normalized = normalize_domain(raw)
        except ValueError as exc:
            errors.append(str(exc))
            continue
        if not normalized:
            errors.append(f"Empty domain (raw: {raw!r})")
            continue
        if not allow_local and _is_local_or_private(normalized):
            errors.append(
                f"Local/private target {normalized!r} blocked "
                "(set ALLOW_LOCAL_TARGETS=true to allow)"
            )
            continue
        try:
            session.add(Target(domain=normalized, scope_includes=[normalized]))
            session.flush()
            created += 1
        except IntegrityError:
            session.rollback()
            skipped += 1
    session.commit()
    return created, skipped, errors


def check_in_scope(
    domain: str,
    scope_includes: list[str],
    scope_excludes: list[str],
) -> bool:
    """Return True if *domain* is within scope for the given target.

    Pattern semantics:
    - ``example.com``   — matches the root domain AND all its subdomains.
    - ``*.example.com`` — matches ONLY proper subdomains, not the root.

    Excludes always override includes.
    An empty *scope_includes* means everything is in-scope.
    """
    def _matches(d: str, pattern: str) -> bool:
        d = d.lower()
        pattern = pattern.lower()
        if pattern.startswith("*."):
            base = pattern[2:]
            return d.endswith("." + base)
        return d == pattern or d.endswith("." + pattern)

    if scope_includes and not any(_matches(domain, p) for p in scope_includes):
        return False
    if any(_matches(domain, p) for p in scope_excludes):
        return False
    return True


def list_targets(session: Session) -> list[dict[str, object]]:
    targets = session.query(Target).order_by(Target.created_at.desc()).all()
    return [
        {
            "id": t.id,
            "domain": t.domain,
            "status": t.status,
            "platform": t.platform or "",
            "recon_depth": t.recon_depth,
            "last_recon_at": t.last_recon_at,
        }
        for t in targets
    ]


# ---------------------------------------------------------------------------
# Finding helpers
# ---------------------------------------------------------------------------


def finding_exists(
    session: Session,
    target_id: int,
    template_id: str | None,
    url: str | None,
) -> bool:
    """Return True when a Finding with the same (target_id, template_id, url) exists."""
    q = session.query(Finding).filter(Finding.target_id == target_id)
    if template_id is not None:
        q = q.filter(Finding.template_id == template_id)
    else:
        q = q.filter(Finding.template_id.is_(None))
    if url is None:
        q = q.filter(Finding.url.is_(None))
    else:
        q = q.filter(Finding.url == url)
    return q.first() is not None


def _findings_base_query(
    session: Session,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    search: str = "",
    target_id: int | None = None,
    vuln_types: list[str] | None = None,
    score_min: int = 0,
    score_max: int = 100,
):
    """Return a filtered SQLAlchemy query over Finding — no limit/offset applied."""
    query = session.query(Finding).join(Target).order_by(Finding.created_at.desc())

    if severities:
        query = query.filter(Finding.severity.in_(severities))
    if statuses:
        query = query.filter(Finding.status.in_(statuses))
    if target_id is not None:
        query = query.filter(Finding.target_id == target_id)
    if vuln_types:
        query = query.filter(Finding.type.in_(vuln_types))
    query = query.filter(
        Finding.auto_score >= score_min,
        Finding.auto_score <= score_max,
    )
    cleaned_search = search.strip()
    if cleaned_search:
        pattern = f"%{cleaned_search}%"
        query = query.filter(
            or_(
                Finding.title.ilike(pattern),
                Finding.url.ilike(pattern),
                Finding.template_id.ilike(pattern),
            )
        )
    return query


def count_findings(
    session: Session,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    search: str = "",
    target_id: int | None = None,
    vuln_types: list[str] | None = None,
    score_min: int = 0,
    score_max: int = 100,
) -> int:
    """Return the total number of findings matching the given filters."""
    return _findings_base_query(
        session,
        severities=severities,
        statuses=statuses,
        search=search,
        target_id=target_id,
        vuln_types=vuln_types,
        score_min=score_min,
        score_max=score_max,
    ).count()


def list_findings(
    session: Session,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    search: str = "",
    target_id: int | None = None,
    vuln_types: list[str] | None = None,
    score_min: int = 0,
    score_max: int = 100,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict[str, object]]:
    query = _findings_base_query(
        session,
        severities=severities,
        statuses=statuses,
        search=search,
        target_id=target_id,
        vuln_types=vuln_types,
        score_min=score_min,
        score_max=score_max,
    )
    if offset:
        query = query.offset(offset)
    if limit is not None:
        query = query.limit(limit)

    return [
        {
            "id": f.id,
            "severity": f.severity,
            "status": f.status,
            "title": f.title,
            "target": f.target.domain,
            "target_id": f.target_id,
            "url": f.url or "",
            "confidence": f.confidence,
            "auto_score": f.auto_score,
            "type": f.type,
            "description": f.description or "",
            "exploitation_difficulty": f.exploitation_difficulty,
            "raw_evidence": f.raw_evidence,
        }
        for f in query.all()
    ]


def get_finding(session: Session, finding_id: int) -> dict[str, object] | None:
    """Return full details for a single finding, or None if not found."""
    f = session.get(Finding, finding_id)
    if f is None:
        return None
    return {
        "id": f.id,
        "title": f.title,
        "type": f.type,
        "severity": f.severity,
        "confidence": f.confidence,
        "exploitation_difficulty": f.exploitation_difficulty,
        "auto_score": f.auto_score,
        "status": f.status,
        "url": f.url or "",
        "description": f.description or "",
        "template_id": f.template_id or "",
        "raw_evidence": f.raw_evidence,
        "screenshots": f.screenshots,
        "target_id": f.target_id,
        "target_domain": f.target.domain,
        "created_at": f.created_at,
        "reviewed_at": f.reviewed_at,
        "classifier_used": f.classifier_used,
        "confidence_note": f.confidence_note or "",
        "ai_reasoning": f.ai_reasoning or "",
        "ai_report_draft": f.ai_report_draft or "",
    }


def get_target_screenshot_paths(target_id: int, output_dir: str) -> list[str]:
    """List screenshot image paths for a target from the filesystem."""
    import os
    from pathlib import Path

    shot_dir = Path(output_dir) / "screenshots" / str(target_id)
    if not shot_dir.exists():
        return []
    return sorted(
        str(p) for p in shot_dir.iterdir() if p.suffix.lower() in {".png", ".jpg", ".jpeg"}
    )


# ---------------------------------------------------------------------------
# Pipeline status
# ---------------------------------------------------------------------------


def get_pipeline_status(app: Celery) -> dict[str, object]:
    from core.pipeline.tasks import get_redis_url

    redis_url = str(app.conf.broker_url or get_redis_url())
    try:
        client = Redis.from_url(redis_url, socket_connect_timeout=0.5)
        client.ping()
        queued = client.llen("celery")
    except RedisError as exc:
        return {
            "state": "offline",
            "queued": None,
            "error": f"Redis unavailable: {exc.__class__.__name__}",
        }

    return {
        "state": "online",
        "queued": int(queued),
        "error": None,
    }


# ---------------------------------------------------------------------------
# ReconResult helpers — deduplication and re-scan supersession
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# System settings
# ---------------------------------------------------------------------------


def get_setting(session: Session, key: str, default: str | None = None) -> str | None:
    """Return the value for *key* from system_settings, or *default* if absent."""
    row = session.get(SystemSetting, key)
    if row is None or row.value is None:
        return default
    return row.value


def set_setting(session: Session, key: str, value: str | None) -> None:
    """Persist *value* for *key* in system_settings.

    Passing None or an empty string removes the entry (reverts to env var fallback).
    Uses session.merge() so concurrent upserts never raise IntegrityError.
    """
    from datetime import UTC, datetime

    if not value:
        row = session.get(SystemSetting, key)
        if row is not None:
            session.delete(row)
        return

    session.merge(SystemSetting(key=key, value=value, updated_at=datetime.now(UTC)))
    session.flush()  # ensure identity map is updated so repeated calls see the same row


def _data_hash(data: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


def insert_recon_results_with_dedup(
    session: Session,
    target_id: int,
    tool: str,
    result_type: str,
    data_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Insert new ReconResults with deduplication and re-scan supersession.

    Compares incoming items against active results (superseded_by IS NULL) by
    data hash.  Items already present are skipped.  Active results that are no
    longer in the new set are marked superseded by the first newly inserted
    result (re-scan semantics).

    Returns the list of data items that were actually inserted.
    """
    incoming_by_hash: dict[str, dict[str, Any]] = {
        _data_hash(d): d for d in data_items
    }

    existing = (
        session.query(ReconResult)
        .filter(
            ReconResult.target_id == target_id,
            ReconResult.tool == tool,
            ReconResult.result_type == result_type,
            ReconResult.superseded_by.is_(None),
        )
        .all()
    )
    existing_by_hash: dict[str, ReconResult] = {
        _data_hash(r.data): r for r in existing
    }

    new_objects: list[ReconResult] = []
    inserted_data: list[dict[str, Any]] = []
    for h, data in incoming_by_hash.items():
        if h in existing_by_hash:
            continue  # already stored — deduplicated
        obj = ReconResult(
            target_id=target_id,
            tool=tool,
            result_type=result_type,
            data=data,
        )
        session.add(obj)
        new_objects.append(obj)
        inserted_data.append(data)

    if new_objects:
        session.flush()  # assign IDs before updating superseded_by
        first_new_id = new_objects[0].id
        # Re-scan: supersede old results that are no longer in the new data
        for h, old in existing_by_hash.items():
            if h not in incoming_by_hash:
                old.superseded_by = first_new_id

    return inserted_data


# ---------------------------------------------------------------------------
# Export helpers
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "id",
    "target",
    "severity",
    "status",
    "title",
    "url",
    "confidence",
    "auto_score",
    "type",
]


def export_findings_csv(
    session: Session,
    target_id: int | None = None,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    score_min: int = 0,
    score_max: int = 100,
) -> str:
    """Return findings as a CSV string with the canonical set of fields."""
    import csv
    import io

    rows = list_findings(
        session,
        target_id=target_id,
        severities=severities,
        statuses=statuses,
        score_min=score_min,
        score_max=score_max,
    )
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_FIELDS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


def export_findings_markdown(
    session: Session,
    target_id: int | None = None,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    score_min: int = 0,
    score_max: int = 100,
) -> str:
    """Return findings as a Markdown document suitable for manual review."""
    rows = list_findings(
        session,
        target_id=target_id,
        severities=severities,
        statuses=statuses,
        score_min=score_min,
        score_max=score_max,
    )
    if not rows:
        return "# Findings\n\n_No findings match the current filters._\n"

    lines: list[str] = ["# Findings\n"]
    for f in rows:
        sev = str(f.get("severity", "")).upper()
        title = f.get("title", "")
        target = f.get("target", "")
        url = f.get("url", "")
        score = f.get("auto_score", 0)
        confidence = f.get("confidence", "")
        status = f.get("status", "")
        ftype = f.get("type", "")
        desc = f.get("description", "")

        lines.append(f"## [{sev}] {title}")
        lines.append(f"- **Target:** {target}")
        lines.append(f"- **URL:** {url}")
        lines.append(f"- **Type:** {ftype}")
        lines.append(f"- **Score:** {score}/100")
        lines.append(f"- **Confidence:** {confidence}")
        lines.append(f"- **Status:** {status}")
        if desc:
            lines.append(f"\n{desc}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# BountyProgram helpers
# ---------------------------------------------------------------------------


def get_bounty_program_by_handle(
    session: Session, platform: str, program_handle: str
) -> BountyProgram | None:
    """Return the BountyProgram for the given platform + handle, or None."""
    return (
        session.query(BountyProgram)
        .filter(
            BountyProgram.platform == platform,
            BountyProgram.program_handle == program_handle,
        )
        .first()
    )


def upsert_bounty_program(
    session: Session,
    platform: str,
    program_handle: str,
    name: str,
    scope: list[dict[str, Any]],
    bounty_table: dict[str, Any],
    auto_recon_enabled: bool = False,
) -> tuple["BountyProgram", bool, list[str], list[str]]:
    """Insert or update a BountyProgram.

    Returns ``(program, is_new, added_scope_ids, removed_scope_ids)``.
    ``is_new`` is True only on first insert.  ``first_seen_at`` is never
    overwritten for existing programs.  ``last_checked_at`` is always updated.
    """
    from datetime import UTC, datetime

    now = datetime.now(UTC)
    existing = get_bounty_program_by_handle(session, platform, program_handle)

    if existing is None:
        program = BountyProgram(
            platform=platform,
            program_handle=program_handle,
            name=name,
            scope=scope,
            bounty_table=bounty_table,
            auto_recon_enabled=auto_recon_enabled,
            last_checked_at=now,
            first_seen_at=now,
        )
        session.add(program)
        session.flush()
        return program, True, [], []

    # Compute scope diff before updating
    key = "asset_identifier"
    old_ids = {item.get(key, "") for item in (existing.scope or []) if item.get(key)}
    new_ids = {item.get(key, "") for item in scope if item.get(key)}
    added = sorted(new_ids - old_ids)
    removed = sorted(old_ids - new_ids)

    existing.name = name
    existing.scope = scope
    existing.bounty_table = bounty_table
    existing.last_checked_at = now
    session.flush()
    return existing, False, added, removed


def list_bounty_programs(session: Session) -> list[dict[str, Any]]:
    """Return all BountyPrograms ordered by first_seen_at desc."""
    programs = (
        session.query(BountyProgram).order_by(BountyProgram.first_seen_at.desc()).all()
    )
    return [
        {
            "id": p.id,
            "platform": p.platform,
            "program_handle": p.program_handle,
            "name": p.name,
            "auto_recon_enabled": p.auto_recon_enabled,
            "last_checked_at": p.last_checked_at,
            "first_seen_at": p.first_seen_at,
            "scope_count": len(p.scope or []),
        }
        for p in programs
    ]
