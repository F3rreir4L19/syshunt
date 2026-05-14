from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import structlog
from celery import Celery

from core.db import queries
from core.db.models import Finding, ReconResult, Target
from core.db.session import SessionLocal
from tools.httpx_wrapper import HttpxWrapper
from tools.nuclei_wrapper import NucleiWrapper
from tools.subfinder_wrapper import SubfinderWrapper


DEFAULT_REDIS_URL = "redis://localhost:6379/0"


def get_redis_url() -> str:
    return os.getenv("REDIS_URL", DEFAULT_REDIS_URL)


def should_run_tasks_eagerly() -> bool:
    return os.getenv("CELERY_TASK_ALWAYS_EAGER", "false").lower() in {
        "1",
        "true",
        "yes",
    }


celery_app = Celery(
    "syshunt",
    broker=get_redis_url(),
    backend=get_redis_url(),
)
celery_app.conf.update(
    task_always_eager=should_run_tasks_eagerly(),
    task_eager_propagates=True,
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
)


@celery_app.task(name="core.pipeline.run_subdomain_enum")
def run_subdomain_enum(target_id: int) -> dict[str, int | str]:
    log = structlog.get_logger().bind(target_id=target_id, tool="subfinder")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        result = SubfinderWrapper().run(target.domain)
        if not result.success:
            log.warning("subdomain_enum_failed", error=result.error)
            raise RuntimeError(result.error or "subfinder failed")

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="subfinder",
            result_type="subdomain",
            data_items=[{"value": s} for s in result.parsed_data],
        )
        session.commit()

    log.info("subdomain_enum_completed", created=len(inserted))
    return {
        "target_id": target_id,
        "tool": "subfinder",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_http_probe")
def run_http_probe(target_id: int) -> dict[str, int | str]:
    log = structlog.get_logger().bind(target_id=target_id, tool="httpx")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        subdomains = [
            r.data["value"]
            for r in session.query(ReconResult)
            .filter(
                ReconResult.target_id == target.id,
                ReconResult.tool == "subfinder",
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.is_(None),
            )
            .all()
            if "value" in r.data
        ]
        probe_targets = subdomains or [target.domain]

        errors: list[str] = []
        data_items: list[dict[str, Any]] = []

        for probe_target in probe_targets:
            probe_result = HttpxWrapper().run(probe_target)
            if not probe_result.success:
                log.warning(
                    "http_probe_item_failed",
                    probe_target=probe_target,
                    error=probe_result.error,
                )
                errors.append(f"{probe_target}: {probe_result.error}")
                continue
            data_items.extend(probe_result.parsed_data)

        if not data_items and errors:
            raise RuntimeError(
                f"httpx failed for all targets: {'; '.join(errors)}"
            )

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="httpx",
            result_type="http_service",
            data_items=data_items,
        )
        session.commit()

    log.info("http_probe_completed", created=len(inserted), errors=len(errors))
    return {
        "target_id": target_id,
        "tool": "httpx",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_nuclei_scan")
def run_nuclei_scan(target_id: int) -> dict[str, int | str]:
    log = structlog.get_logger().bind(target_id=target_id, tool="nuclei")
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        urls = [
            r.data["url"]
            for r in session.query(ReconResult)
            .filter(
                ReconResult.target_id == target.id,
                ReconResult.tool == "httpx",
                ReconResult.result_type == "http_service",
                ReconResult.superseded_by.is_(None),
            )
            .all()
            if "url" in r.data
        ]
        scan_targets = urls or [target.domain]

        errors: list[str] = []
        finding_data_items: list[dict[str, Any]] = []

        for scan_target in scan_targets:
            scan_result = NucleiWrapper().run(scan_target)
            if not scan_result.success:
                log.warning(
                    "nuclei_scan_item_failed",
                    scan_target=scan_target,
                    error=scan_result.error,
                )
                errors.append(f"{scan_target}: {scan_result.error}")
                continue
            finding_data_items.extend(scan_result.parsed_data)

        if not finding_data_items and errors:
            raise RuntimeError(
                f"nuclei failed for all targets: {'; '.join(errors)}"
            )

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="nuclei",
            result_type="finding",
            data_items=finding_data_items,
        )
        for finding_data in inserted:
            session.add(_finding_from_nuclei_result(target.id, finding_data))

        target.status = "recon_done"
        target.last_recon_at = datetime.now(UTC)
        session.commit()

    log.info("nuclei_scan_completed", created=len(inserted), errors=len(errors))
    return {
        "target_id": target_id,
        "tool": "nuclei",
        "created": len(inserted),
    }


@celery_app.task(name="core.pipeline.run_full_pipeline")
def run_full_pipeline(target_id: int) -> dict[str, int | str]:
    log = structlog.get_logger().bind(target_id=target_id)
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")
        target.status = "recon_running"
        session.commit()

    log.info("pipeline_started")
    result = run_subdomain_enum.apply_async(
        args=[target_id],
        link=run_http_probe.si(target_id).set(link=run_nuclei_scan.si(target_id)),
    )
    return {
        "target_id": target_id,
        "workflow_id": result.id or "",
        "status": "scheduled",
    }


def _finding_from_nuclei_result(target_id: int, data: dict[str, Any]) -> Finding:
    info = data.get("info") if isinstance(data.get("info"), dict) else {}
    template_id = str(data.get("template-id") or data.get("template") or "nuclei")
    title = str(info.get("name") or template_id)
    severity = str(info.get("severity") or data.get("severity") or "info").lower()
    matched_url = data.get("matched-at") or data.get("url") or data.get("host")

    return Finding(
        target_id=target_id,
        type=template_id,
        title=title,
        description=info.get("description"),
        url=str(matched_url) if matched_url else None,
        severity=severity,
        confidence="possible",
        template_id=template_id,
        raw_evidence=data,
    )
