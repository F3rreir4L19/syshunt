"""Discord webhook notifications — fire-and-forget, never propagate."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from core.db.models import BountyProgram, Finding, Target

_log = structlog.get_logger()


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _get_webhook_url(session: object = None) -> str | None:
    """Return Discord webhook URL from system_settings or env, whichever has a value."""
    if session is not None:
        try:
            from core.db.queries import get_setting

            url = get_setting(session, "DISCORD_WEBHOOK_URL")  # type: ignore[arg-type]
            if url:
                return url
        except Exception:
            pass
    return os.getenv("DISCORD_WEBHOOK_URL") or None


def _get_flag(session: object, key: str) -> bool:
    """Return True when a notify_* system setting is explicitly "true"."""
    if session is None:
        return False
    try:
        from core.db.queries import get_setting

        return (get_setting(session, key) or "").lower() == "true"  # type: ignore[arg-type]
    except Exception:
        return False


def _post_discord(webhook_url: str, content: str) -> None:
    """POST a plain-text message to a Discord webhook. Logs warning on failure."""
    try:
        payload = json.dumps({"content": content}).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        _log.warning("discord_webhook_failed", error=str(exc))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def notify_recon_completed(
    target: "Target",
    stats: dict,
    session: object = None,
) -> None:
    """Send a recon-completed notification to Discord.

    Respects the ``notify_recon_done`` system setting flag.
    Never raises; logs warning on any failure.
    """
    try:
        if not _get_flag(session, "notify_recon_done"):
            return
        webhook_url = _get_webhook_url(session)
        if not webhook_url:
            return
        domain = getattr(target, "domain", str(target))
        findings_count = stats.get("findings", 0)
        high_critical = stats.get("high_critical", 0)
        content = (
            "✅ [RECON CONCLUÍDO]\n"
            f"Target: {domain}\n"
            f"Findings: {findings_count}\n"
            f"High/Critical: {high_critical}\n"
            "Dashboard: http://localhost:8501"
        )
        _post_discord(webhook_url, content)
    except Exception as exc:
        _log.warning("notify_recon_completed_failed", error=str(exc))


def notify_high_score_finding(
    finding: "Finding",
    target: "Target",
    session: object = None,
) -> None:
    """Send a high-score finding notification to Discord.

    Respects the ``notify_high_score_finding`` system setting flag.
    Never raises; logs warning on any failure.
    """
    try:
        if not _get_flag(session, "notify_high_score_finding"):
            return
        webhook_url = _get_webhook_url(session)
        if not webhook_url:
            return
        domain = getattr(target, "domain", str(target))
        score = getattr(finding, "auto_score", 0) or 0
        severity = (getattr(finding, "severity", "unknown") or "unknown").upper()
        finding_type = getattr(finding, "type", "unknown") or "unknown"
        url = getattr(finding, "url", "") or ""
        content = (
            "🔴 [HIGH SCORE FINDING]\n"
            f"Target: {domain}\n"
            f"Type: {finding_type}\n"
            f"Score: {score}/100\n"
            f"Severity: {severity}\n"
            f"URL: {url}"
        )
        _post_discord(webhook_url, content)
    except Exception as exc:
        _log.warning("notify_high_score_finding_failed", error=str(exc))


def notify_new_program(program: "BountyProgram") -> None:
    """Stub — Phase 4 will implement platform-monitoring notifications."""


def notify_scope_changed(
    program: "BountyProgram",
    added: list[str],
    removed: list[str],
) -> None:
    """Stub — Phase 4 will implement scope-change notifications."""


def notify_pipeline_error(
    target_id: int,
    task_name: str,
    error: str,
) -> None:
    """Stub — can be wired to a Celery error handler in a future phase."""
