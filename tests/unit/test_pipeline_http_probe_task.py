from dataclasses import dataclass
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import ReconResult, Target
from core.pipeline import tasks


@dataclass
class FakeToolResult:
    success: bool
    parsed_data: list[dict[str, Any]]
    error: str | None = None


class FakeHttpxWrapper:
    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=[
                {
                    "url": f"https://{target}",
                    "status_code": 200,
                }
            ],
        )


class FakeHttpxWrapperAlwaysFails:
    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(success=False, parsed_data=[], error="connection refused")


class FakeHttpxWrapperPartialFailure:
    """Succeeds for 'good.example.com', fails for 'bad.example.com'."""

    def run(self, target: str) -> FakeToolResult:
        if target == "bad.example.com":
            return FakeToolResult(success=False, parsed_data=[], error="timeout")
        return FakeToolResult(
            success=True,
            parsed_data=[{"url": f"https://{target}", "status_code": 200}],
        )


def build_session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_run_http_probe_uses_subdomain_results(monkeypatch) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapper)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()
        session.add_all(
            [
                ReconResult(
                    target_id=target.id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": "api.example.com"},
                ),
                ReconResult(
                    target_id=target.id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": "www.example.com"},
                ),
            ]
        )
        session.commit()
        target_id = target.id

    summary = tasks.run_http_probe(target_id)

    with session_factory() as session:
        saved_target = session.get(Target, target_id)
        results = (
            session.query(ReconResult)
            .filter_by(tool="httpx", result_type="http_service")
            .order_by(ReconResult.id)
            .all()
        )

    assert summary == {
        "target_id": target_id,
        "tool": "httpx",
        "created": 2,
    }
    assert saved_target is not None
    assert saved_target.status == "pending"  # only full pipeline changes status
    assert [result.data["url"] for result in results] == [
        "https://api.example.com",
        "https://www.example.com",
    ]


def test_run_http_probe_falls_back_to_target_domain(monkeypatch) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapper)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    summary = tasks.run_http_probe(target_id)

    with session_factory() as session:
        result = session.query(ReconResult).filter_by(tool="httpx").one()

    assert summary["created"] == 1
    assert result.data["url"] == "https://example.com"


def test_run_http_probe_raises_only_if_all_targets_fail(monkeypatch) -> None:
    """All probes fail → task raises RuntimeError."""
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapperAlwaysFails)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    with pytest.raises(RuntimeError, match="httpx failed for all targets"):
        tasks.run_http_probe(target_id)


def test_run_http_probe_continues_on_partial_failure(monkeypatch) -> None:
    """One probe fails but another succeeds → task succeeds with partial results."""
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapperPartialFailure)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()
        session.add_all(
            [
                ReconResult(
                    target_id=target.id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": "bad.example.com"},
                ),
                ReconResult(
                    target_id=target.id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": "good.example.com"},
                ),
            ]
        )
        session.commit()
        target_id = target.id

    summary = tasks.run_http_probe(target_id)

    with session_factory() as session:
        results = (
            session.query(ReconResult)
            .filter_by(tool="httpx", result_type="http_service")
            .all()
        )

    assert summary["created"] == 1
    assert results[0].data["url"] == "https://good.example.com"


def test_run_http_probe_skips_out_of_scope_subdomains(monkeypatch) -> None:
    """Subdomains in scope_excludes are not probed."""
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "HttpxWrapper", FakeHttpxWrapper)

    with session_factory() as session:
        target = Target(
            domain="example.com",
            scope_includes=["example.com"],
            scope_excludes=["staging.example.com"],
        )
        session.add(target)
        session.flush()
        session.add_all(
            [
                ReconResult(
                    target_id=target.id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": "api.example.com"},
                ),
                ReconResult(
                    target_id=target.id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": "staging.example.com"},
                ),
            ]
        )
        session.commit()
        target_id = target.id

    summary = tasks.run_http_probe(target_id)

    with session_factory() as session:
        results = (
            session.query(ReconResult)
            .filter_by(tool="httpx", result_type="http_service")
            .all()
        )

    assert summary["created"] == 1
    assert results[0].data["url"] == "https://api.example.com"
