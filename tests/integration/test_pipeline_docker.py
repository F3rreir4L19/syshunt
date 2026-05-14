import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

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
    raw_stdout: str = ""
    raw_stderr: str = ""


class FakeSubfinderWrapper:
    name = "subfinder"

    def run(self, target: str, options=None) -> FakeToolResult:
        assert target == "example.com"
        return FakeToolResult(success=True, parsed_data=["api.example.com"])


class FakeHttpxWrapper:
    name = "httpx"

    def run(self, target: str, options=None) -> FakeToolResult:
        assert target == "api.example.com"
        return FakeToolResult(
            success=True,
            parsed_data=[{"url": "https://api.example.com", "status_code": 200}],
        )


class FakeNmapWrapper:
    name = "nmap"

    def run(self, target: str, options=None) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=[{"host": target, "port": 443, "state": "open"}],
        )


class FakeKatanaWrapper:
    name = "katana"

    def run(self, target: str, options=None) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=["https://api.example.com/login"],
        )


class FakeGauWrapper:
    name = "gau"

    def run(self, target: str, options=None) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=["https://api.example.com/old"],
        )


class FakeGoWitnessWrapper:
    name = "gowitness"

    def run(self, target: str, options=None) -> FakeToolResult:
        # Simulate writing a file if screenshot_dir is provided
        if options and options.screenshot_dir:
            path = Path(options.screenshot_dir) / "api_example_com.png"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"fake-png")
        return FakeToolResult(success=True, parsed_data=[])


class FakeNucleiWrapper:
    name = "nuclei"

    def run(self, target: str, options=None) -> FakeToolResult:
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
def test_full_pipeline_with_docker_database(monkeypatch, tmp_path) -> None:
    database_url = os.environ["TEST_DATABASE_URL"]
    engine = create_engine(database_url, pool_pre_ping=True)
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
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
        assert target.status == "recon_done"
        # subdomain(1) + http_service(1) + open_port(1) + crawled_url(2) + screenshot(1) + nuclei(1) = 7
        assert recon_results == 7
        assert findings == 1
    finally:
        Base.metadata.drop_all(engine)
        engine.dispose()
