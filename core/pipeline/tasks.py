from __future__ import annotations

import os

from celery import Celery

from core.db.models import ReconResult, Target
from core.db.session import SessionLocal
from tools.httpx_wrapper import HttpxWrapper
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
