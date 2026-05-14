from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

import structlog
from celery import Celery
from redis import Redis
from redis.exceptions import RedisError

from core.db import queries
from core.db.models import Target
from core.db.session import SessionLocal
from tools.amass_wrapper import AmassWrapper
from tools.subfinder_wrapper import SubfinderWrapper


def _redis_client() -> Redis:
    url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    return Redis.from_url(url, decode_responses=True)


def _session_key(root_target_id: int) -> str:
    return f"syshunt:recon:{root_target_id}:processed"


def _mark_processed(client: Redis, key: str, domain: str) -> None:
    try:
        client.sadd(key, domain)
        client.expire(key, 86400)  # 24 h TTL
    except RedisError:
        pass  # best-effort; missing entry may cause duplicate work, not loops


def _is_processed(client: Redis, key: str, domain: str) -> bool:
    try:
        return bool(client.sismember(key, domain))
    except RedisError:
        return False


def _get_celery_app() -> Celery:
    """Return the Celery app lazily to avoid circular imports."""
    from core.pipeline.tasks import celery_app
    return celery_app


def run_recursive_subdomain_enum(
    domain: str,
    root_target_id: int,
    depth: int,
    session_key: str | None = None,
) -> dict[str, Any]:
    """Enumerate subdomains for *domain* and store results under root_target_id.

    For each new subdomain discovered (not already in the Redis tracking set),
    if depth > 0 a Celery task is dispatched asynchronously (non-blocking).
    All results are stored under root_target_id so the entire recursive tree
    is queryable from the root target.

    Args:
        domain: The domain to enumerate subdomains for.
        root_target_id: All ReconResults are stored under this target.
        depth: Remaining recursion depth; 0 means no further recursion.
        session_key: Redis set key for deduplication; auto-derived when None.
    """
    log = structlog.get_logger().bind(
        domain=domain, root_target_id=root_target_id, depth=depth
    )

    key = session_key or _session_key(root_target_id)
    redis = _redis_client()

    _mark_processed(redis, key, domain)

    all_subdomains: set[str] = set()
    errors: list[str] = []

    for wrapper_cls in (SubfinderWrapper, AmassWrapper):
        wrapper = wrapper_cls()
        result = wrapper.run(domain)
        if not result.success:
            log.warning(
                "subdomain_tool_failed",
                tool=wrapper.name,
                error=result.error,
            )
            errors.append(f"{wrapper.name}: {result.error}")
            continue
        all_subdomains.update(result.parsed_data)

    if not all_subdomains and errors:
        log.error("all_tools_failed", errors=errors)
        return {"domain": domain, "inserted": 0, "errors": errors, "dispatched": 0}

    with SessionLocal() as session:
        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=root_target_id,
            tool="recursive_recon",
            result_type="subdomain",
            data_items=[{"value": s, "source_domain": domain} for s in all_subdomains],
        )
        session.commit()

    log.info("subdomains_stored", count=len(inserted))

    dispatched = 0
    if depth > 0:
        celery_app = _get_celery_app()
        # Import the Celery task for recursive recon dispatch
        from core.pipeline.tasks import run_recursive_subdomain_enum_task

        for subdomain in all_subdomains:
            if _is_processed(redis, key, subdomain):
                continue
            log.debug("dispatching_recursive", subdomain=subdomain, remaining_depth=depth - 1)
            run_recursive_subdomain_enum_task.apply_async(
                kwargs={
                    "domain": subdomain,
                    "root_target_id": root_target_id,
                    "depth": depth - 1,
                    "session_key": key,
                }
            )
            dispatched += 1

    return {
        "domain": domain,
        "inserted": len(inserted),
        "errors": errors,
        "dispatched": dispatched,
    }


def get_active_subdomains(root_target_id: int) -> list[str]:
    """Return all active (non-superseded) subdomains stored for a target."""
    with SessionLocal() as session:
        target = session.get(Target, root_target_id)
        if target is None:
            return []

        from core.db.models import ReconResult
        rows = (
            session.query(ReconResult)
            .filter(
                ReconResult.target_id == root_target_id,
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.is_(None),
            )
            .all()
        )
        seen: set[str] = set()
        result: list[str] = []
        for r in rows:
            val = r.data.get("value", "")
            if val and val not in seen:
                seen.add(val)
                result.append(val)
        return sorted(result)
