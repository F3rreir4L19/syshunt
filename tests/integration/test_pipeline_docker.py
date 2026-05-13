import os
from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import Finding, ReconResult, Target
from core.pipeline import tasks


@dataclass
class FakeToolResult:
    success: bool
    parsed_data: list[Any]
    error: str | None = None


class FakeSubfinderWrapper:
    def run(self, target: str) -> FakeToolResult:
        assert target == "example.com"
        return FakeToolResult(success=True, parsed_data=["api.example.com"])


class FakeHttpxWrapper:
    def run(self, target: str) -> FakeToolResult:
        assert target == "api.example.com"
        return FakeToolResult(
            success=True,
            parsed_data=[{"url": "https://api.example.com", "status_code": 200}],
        )


class FakeNucleiWrapper:
    def run(self, target: str) -> FakeToolResult:
        assert target == "https://api.example.com"
        return FakeToolResult(
            success=True,
            parsed_data=[
                {
                    "template-id": "exposed-panel",
                    "matched-at": "https://api.example.com",
                    "info": {"name": "Exposed panel", "severity": "medium"},
                }
            ],
        )


@pytest.mark.skipif(
    os.getenv("RUN_DOCKER_INTEGRATION") != "1",
    reason="set RUN_DOCKER_INTEGRATION=1 and TEST_DATABASE_URL to run docker tests",
)
def test_full_pipeline_with_docker_database(monkeypatch) -> None:
    database_url = os.environ["TEST_DATABASE_URL"]
    engine = create_engine(database_url, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "SubfinderWrapper", FakeSubfinderWrapper)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapper)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapper)
    monkeypatch.setattr(tasks.celery_app.conf, "task_always_eager", True)

    try:
        with Session(engine) as session:
            target = Target(domain="example.com")
            session.add(target)
            session.commit()
            target_id = target.id

        summary = tasks.run_full_pipeline(target_id)

        with Session(engine) as session:
            target = session.get(Target, target_id)
            recon_results = session.query(ReconResult).count()
            findings = session.query(Finding).count()

        assert summary["status"] == "scheduled"
        assert target is not None
        assert target.status == "nuclei_scan_completed"
        assert recon_results == 3
        assert findings == 1
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
