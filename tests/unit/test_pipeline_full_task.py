from dataclasses import dataclass
from pathlib import Path
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


class FakeNmapWrapper:
    name = "nmap"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=[
                {
                    "ip": "1.2.3.4",
                    "hostname": target,
                    "port": 443,
                    "protocol": "tcp",
                    "service": "https",
                    "product": "",
                    "version": "",
                }
            ],
        )


class FakeKatanaWrapper:
    name = "katana"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(success=True, parsed_data=["https://api.example.com/page"])


class FakeGauWrapper:
    name = "gau"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(success=True, parsed_data=["https://api.example.com/old"])


class FakeGoWitnessWrapper:
    name = "gowitness"

    def run(self, target: str, options: Any = None) -> FakeToolResult:
        return FakeToolResult(success=True, parsed_data=["✔ 200 - https://api.example.com"])


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


def test_run_full_pipeline_executes_chain_in_eager_mode(monkeypatch, tmp_path: Path) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "SubfinderWrapper", FakeSubfinderWrapper)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapper)
    monkeypatch.setattr(tasks, "NmapWrapper", FakeNmapWrapper)
    monkeypatch.setattr(tasks, "KatanaWrapper", FakeKatanaWrapper)
    monkeypatch.setattr(tasks, "GauWrapper", FakeGauWrapper)
    monkeypatch.setattr(tasks, "GoWitnessWrapper", FakeGoWitnessWrapper)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapper)
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
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
    # subfinder(1) + httpx(1) + nmap(1) + webcrawl(2) + screenshot(1) + nuclei(1) = 7
    assert recon_results == 7
    assert findings == 1


def test_run_full_pipeline_skip_recon_runs_only_nuclei(monkeypatch, tmp_path: Path) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapper)
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))
    monkeypatch.setattr(tasks.celery_app.conf, "task_always_eager", True)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        session.add(
            ReconResult(
                target_id=target.id,
                tool="httpx",
                result_type="http_service",
                data={"url": "https://api.example.com"},
            )
        )
        session.commit()
        target_id = target.id

    summary = tasks.run_full_pipeline(target_id, skip_recon=True)

    with session_factory() as session:
        saved_target = session.get(Target, target_id)
        findings = session.query(Finding).count()

    assert summary["skip_recon"] is True
    assert saved_target.status == "recon_done"
    assert findings == 1
