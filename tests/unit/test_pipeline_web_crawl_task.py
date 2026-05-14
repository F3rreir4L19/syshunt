"""Tests for run_web_crawl Celery task."""

from dataclasses import dataclass
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


class FakeKatanaWrapper:
    name = "katana"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=["https://example.com/login", "https://example.com/api"],
        )


class FakeGauWrapper:
    name = "gau"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=["https://example.com/old", "https://example.com/login"],
        )


class FakeFailingWrapper:
    name = "katana"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(success=False, parsed_data=[], error="not found")


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_run_web_crawl_deduplicates_across_tools(monkeypatch) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "KatanaWrapper", FakeKatanaWrapper)
    monkeypatch.setattr(tasks, "GauWrapper", FakeGauWrapper)

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

    result = tasks.run_web_crawl(target_id)

    # katana: /login, /api | gau: /old, /login → 3 unique
    assert result["tool"] == "webcrawl"
    assert result["created"] == 3

    with sf() as session:
        rows = session.query(ReconResult).filter(
            ReconResult.target_id == target_id,
            ReconResult.tool == "webcrawl",
        ).all()
    urls = {r.data["url"] for r in rows}
    assert "https://example.com/login" in urls


def test_run_web_crawl_falls_back_to_https_root(monkeypatch) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "KatanaWrapper", FakeKatanaWrapper)
    monkeypatch.setattr(tasks, "GauWrapper", FakeGauWrapper)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = tasks.run_web_crawl(target_id)

    assert result["created"] > 0
