"""Celery tasks for platform monitoring.

Polling is NOT automatically scheduled — tasks must be triggered manually or
via Celery Beat configuration.  Aggressive auto-recon is handled in a later phase.
"""
from __future__ import annotations

import os

import structlog

from core.pipeline.tasks import celery_app

_log = structlog.get_logger()


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
