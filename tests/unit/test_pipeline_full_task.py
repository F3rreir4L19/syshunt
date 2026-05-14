from dataclasses import dataclass
from typing import Any

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


def build_session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_run_full_pipeline_executes_chain_in_eager_mode(monkeypatch) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "SubfinderWrapper", FakeSubfinderWrapper)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapper)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapper)
    monkeypatch.setattr(tasks.celery_app.conf, "task_always_eager", True)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    summary = tasks.run_full_pipeline(target_id)

    with session_factory() as session:
        saved_target = session.get(Target, target_id)
        recon_results = session.query(ReconResult).count()
        findings = session.query(Finding).count()

    assert summary["target_id"] == target_id
    assert summary["status"] == "scheduled"
    assert summary["workflow_id"]
    assert saved_target is not None
    assert saved_target.status == "recon_done"
    assert recon_results == 3
    assert findings == 1
