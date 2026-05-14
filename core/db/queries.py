from __future__ import annotations

import hashlib
import json
from typing import Any

from celery import Celery
from redis import Redis
from redis.exceptions import RedisError
from sqlalchemy.orm import Session

from core.db.models import Finding, ReconResult, Target


# ---------------------------------------------------------------------------
# Target helpers
# ---------------------------------------------------------------------------


def normalize_domain(domain: str) -> str:
    cleaned = domain.strip().lower()
    if cleaned.startswith("http://"):
        cleaned = cleaned.removeprefix("http://")
    elif cleaned.startswith("https://"):
        cleaned = cleaned.removeprefix("https://")
    return cleaned.strip("/")


def create_target(session: Session, domain: str) -> Target:
    normalized = normalize_domain(domain)
    if not normalized:
        raise ValueError("Domain is required.")

    target = Target(domain=normalized, scope_includes=[normalized])
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


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


def list_findings(
    session: Session,
    severities: list[str] | None = None,
    statuses: list[str] | None = None,
    search: str = "",
) -> list[dict[str, object]]:
    query = session.query(Finding).join(Target).order_by(Finding.created_at.desc())

    if severities:
        query = query.filter(Finding.severity.in_(severities))
    if statuses:
        query = query.filter(Finding.status.in_(statuses))

    cleaned_search = search.strip().lower()
    findings = query.all()
    if cleaned_search:
        findings = [
            f
            for f in findings
            if cleaned_search in f.title.lower()
            or (f.url is not None and cleaned_search in f.url.lower())
            or (f.template_id is not None and cleaned_search in f.template_id.lower())
        ]

    return [
        {
            "id": f.id,
            "severity": f.severity,
            "status": f.status,
            "title": f.title,
            "target": f.target.domain,
            "url": f.url or "",
            "confidence": f.confidence,
            "auto_score": f.auto_score,
        }
        for f in findings
    ]


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


def _data_hash(data: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(data, sort_keys=True).encode()
    ).hexdigest()[:16]


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
