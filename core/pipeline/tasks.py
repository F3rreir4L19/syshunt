from __future__ import annotations

import os

from celery import Celery, chain

from typing import Any

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
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        result = SubfinderWrapper().run(target.domain)
        if not result.success:
            target.status = "subdomain_enum_failed"
            session.commit()
            raise RuntimeError(result.error or "subfinder failed")

        for subdomain in result.parsed_data:
            session.add(
                ReconResult(
                    target_id=target.id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": subdomain},
                )
            )

        target.status = "subdomain_enum_completed"
        session.commit()

        return {
            "target_id": target.id,
            "tool": "subfinder",
            "created": len(result.parsed_data),
        }


@celery_app.task(name="core.pipeline.run_http_probe")
def run_http_probe(target_id: int) -> dict[str, int | str]:
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        subdomains = [
            result.data["value"]
            for result in session.query(ReconResult)
            .filter_by(target_id=target.id, tool="subfinder", result_type="subdomain")
            .all()
            if "value" in result.data
        ]
        probe_targets = subdomains or [target.domain]
        created = 0

        for probe_target in probe_targets:
            result = HttpxWrapper().run(probe_target)
            if not result.success:
                target.status = "http_probe_failed"
                session.commit()
                raise RuntimeError(result.error or "httpx failed")

            for service in result.parsed_data:
                session.add(
                    ReconResult(
                        target_id=target.id,
                        tool="httpx",
                        result_type="http_service",
                        data=service,
                    )
                )
                created += 1

        target.status = "http_probe_completed"
        session.commit()

        return {
            "target_id": target.id,
            "tool": "httpx",
            "created": created,
        }


@celery_app.task(name="core.pipeline.run_nuclei_scan")
def run_nuclei_scan(target_id: int) -> dict[str, int | str]:
    with SessionLocal() as session:
        target = session.get(Target, target_id)
        if target is None:
            raise ValueError(f"Target {target_id} not found")

        urls = [
            result.data["url"]
            for result in session.query(ReconResult)
            .filter_by(target_id=target.id, tool="httpx", result_type="http_service")
            .all()
            if "url" in result.data
        ]
        scan_targets = urls or [target.domain]
        created = 0

        for scan_target in scan_targets:
            result = NucleiWrapper().run(scan_target)
            if not result.success:
                target.status = "nuclei_scan_failed"
                session.commit()
                raise RuntimeError(result.error or "nuclei failed")

            for finding_data in result.parsed_data:
                session.add(
                    ReconResult(
                        target_id=target.id,
                        tool="nuclei",
                        result_type="finding",
                        data=finding_data,
                    )
                )
                session.add(_finding_from_nuclei_result(target.id, finding_data))
                created += 1

        target.status = "nuclei_scan_completed"
        session.commit()

        return {
            "target_id": target.id,
            "tool": "nuclei",
            "created": created,
        }


@celery_app.task(name="core.pipeline.run_full_pipeline")
def run_full_pipeline(target_id: int) -> dict[str, int | str]:
    workflow = chain(
        run_subdomain_enum.si(target_id),
        run_http_probe.si(target_id),
        run_nuclei_scan.si(target_id),
    )
    result = workflow.apply_async()

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
