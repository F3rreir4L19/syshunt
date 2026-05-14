"""Tests for run_screenshot Celery task."""

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import ReconResult, Target
from core.pipeline import tasks


@dataclass
class FakeToolResult:
    success: bool
    parsed_data: list[Any]
    error: str | None = None


class FakeGoWitnessWrapper:
    name = "gowitness"

    def run(self, target: str, options: Any = None) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=[f"✔ 200 - {target}"],
        )


class FakeGoWitnessWrapperFailing:
    name = "gowitness"

    def run(self, target: str, options: Any = None) -> FakeToolResult:
        return FakeToolResult(success=False, parsed_data=[], error="timeout")


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_run_screenshot_stores_screenshot_records(monkeypatch, tmp_path: Path) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "GoWitnessWrapper", FakeGoWitnessWrapper)
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        session.add(
            ReconResult(
                target_id=target.id,
                tool="httpx",
                result_type="http_service",
                data={"url": "https://example.com"},
            )
        )
        session.commit()
        target_id = target.id

    result = tasks.run_screenshot(target_id)

    assert result["tool"] == "gowitness"
    assert result["created"] == 1

    with sf() as session:
        rows = session.query(ReconResult).filter(
            ReconResult.target_id == target_id,
            ReconResult.tool == "gowitness",
        ).all()
    assert len(rows) == 1
    assert rows[0].data["url"] == "https://example.com"


def test_run_screenshot_raises_when_all_fail(monkeypatch, tmp_path: Path) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "GoWitnessWrapper", FakeGoWitnessWrapperFailing)
    monkeypatch.setenv("OUTPUT_DIR", str(tmp_path))

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        session.add(
            ReconResult(
                target_id=target.id,
                tool="httpx",
                result_type="http_service",
                data={"url": "https://example.com"},
            )
        )
        session.commit()
        target_id = target.id

    try:
        tasks.run_screenshot(target_id)
        assert False, "should have raised"
    except RuntimeError as exc:
        assert "gowitness failed" in str(exc)
