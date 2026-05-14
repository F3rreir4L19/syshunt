"""Tests for core/recon/recursive.py.

All Redis and subprocess calls are mocked so these tests run without
external dependencies.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import ReconResult, Target
from core.recon import recursive


@dataclass
class FakeToolResult:
    success: bool
    parsed_data: list[str]
    error: str | None = None


class _FakeSubfinder:
    name = "subfinder"

    def run(self, domain: str) -> FakeToolResult:
        if domain == "example.com":
            return FakeToolResult(success=True, parsed_data=["api.example.com", "mail.example.com"])
        return FakeToolResult(success=True, parsed_data=[])


class _FakeAmass:
    name = "amass"

    def run(self, domain: str) -> FakeToolResult:
        if domain == "example.com":
            return FakeToolResult(success=True, parsed_data=["cdn.example.com", "api.example.com"])
        return FakeToolResult(success=True, parsed_data=[])


def _make_session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _fake_redis() -> MagicMock:
    redis = MagicMock()
    redis.sismember.return_value = False
    return redis


def test_recursive_stores_deduplicated_subdomains(monkeypatch: Any) -> None:
    sf = _make_session_factory()
    redis = _fake_redis()

    monkeypatch.setattr(recursive, "SubfinderWrapper", lambda: _FakeSubfinder())
    monkeypatch.setattr(recursive, "AmassWrapper", lambda: _FakeAmass())
    monkeypatch.setattr(recursive, "SessionLocal", sf)
    monkeypatch.setattr(recursive, "_redis_client", lambda: redis)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = recursive.run_recursive_subdomain_enum(
        domain="example.com",
        root_target_id=target_id,
        depth=0,
    )

    assert result["domain"] == "example.com"
    assert result["inserted"] == 3  # api, mail, cdn (api deduplicated cross-tool)
    assert result["errors"] == []
    assert result["recursed"] == 0

    with sf() as session:
        rows = (
            session.query(ReconResult)
            .filter(ReconResult.target_id == target_id)
            .all()
        )
        stored_values = {r.data["value"] for r in rows}

    assert stored_values == {"api.example.com", "mail.example.com", "cdn.example.com"}


def test_recursive_does_not_recurse_when_depth_zero(monkeypatch: Any) -> None:
    sf = _make_session_factory()
    redis = _fake_redis()

    monkeypatch.setattr(recursive, "SubfinderWrapper", lambda: _FakeSubfinder())
    monkeypatch.setattr(recursive, "AmassWrapper", lambda: _FakeAmass())
    monkeypatch.setattr(recursive, "SessionLocal", sf)
    monkeypatch.setattr(recursive, "_redis_client", lambda: redis)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = recursive.run_recursive_subdomain_enum(
        domain="example.com",
        root_target_id=target_id,
        depth=0,
    )

    assert result["recursed"] == 0


def test_recursive_skips_processed_domains(monkeypatch: Any) -> None:
    sf = _make_session_factory()
    redis = _fake_redis()
    # All subdomains already processed
    redis.sismember.return_value = True

    monkeypatch.setattr(recursive, "SubfinderWrapper", lambda: _FakeSubfinder())
    monkeypatch.setattr(recursive, "AmassWrapper", lambda: _FakeAmass())
    monkeypatch.setattr(recursive, "SessionLocal", sf)
    monkeypatch.setattr(recursive, "_redis_client", lambda: redis)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = recursive.run_recursive_subdomain_enum(
        domain="example.com",
        root_target_id=target_id,
        depth=1,
    )

    # depth=1 but all subdomains are marked processed → no recursion
    assert result["recursed"] == 0


def test_recursive_tolerates_tool_failure(monkeypatch: Any) -> None:
    class _FailingTool:
        name = "subfinder"

        def run(self, _: str) -> FakeToolResult:
            return FakeToolResult(success=False, parsed_data=[], error="timeout")

    class _WorkingAmass:
        name = "amass"

        def run(self, _: str) -> FakeToolResult:
            return FakeToolResult(success=True, parsed_data=["x.example.com"])

    sf = _make_session_factory()
    redis = _fake_redis()

    monkeypatch.setattr(recursive, "SubfinderWrapper", lambda: _FailingTool())
    monkeypatch.setattr(recursive, "AmassWrapper", lambda: _WorkingAmass())
    monkeypatch.setattr(recursive, "SessionLocal", sf)
    monkeypatch.setattr(recursive, "_redis_client", lambda: redis)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = recursive.run_recursive_subdomain_enum(
        domain="example.com",
        root_target_id=target_id,
        depth=0,
    )

    assert result["inserted"] == 1
    assert len(result["errors"]) == 1


def test_recursive_fails_when_all_tools_fail(monkeypatch: Any) -> None:
    class _FailingTool:
        name = "subfinder"

        def run(self, _: str) -> FakeToolResult:
            return FakeToolResult(success=False, parsed_data=[], error="not found")

    sf = _make_session_factory()
    redis = _fake_redis()

    monkeypatch.setattr(recursive, "SubfinderWrapper", lambda: _FailingTool())
    monkeypatch.setattr(recursive, "AmassWrapper", lambda: _FailingTool())
    monkeypatch.setattr(recursive, "SessionLocal", sf)
    monkeypatch.setattr(recursive, "_redis_client", lambda: redis)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = recursive.run_recursive_subdomain_enum(
        domain="example.com",
        root_target_id=target_id,
        depth=0,
    )

    assert result["inserted"] == 0
    assert len(result["errors"]) == 2


def test_get_active_subdomains(monkeypatch: Any) -> None:
    sf = _make_session_factory()
    monkeypatch.setattr(recursive, "SessionLocal", sf)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id
        session.add(
            ReconResult(
                target_id=target_id,
                tool="recursive_recon",
                result_type="subdomain",
                data={"value": "api.example.com", "source_domain": "example.com"},
            )
        )
        session.commit()

    result = recursive.get_active_subdomains(target_id)

    assert result == ["api.example.com"]
