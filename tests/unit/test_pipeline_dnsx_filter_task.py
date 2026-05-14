"""Tests for run_dnsx_filter Celery task."""

from __future__ import annotations

from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import ReconResult, Target
from core.pipeline import tasks


@dataclass
class FakeDnsxResult:
    success: bool
    parsed_data: list[str]
    error: str | None = None


class FakeDnsxWrapper:
    """Resolves only domains containing 'api' or 'www'."""

    def run(self, target: str) -> FakeDnsxResult:
        resolved = [
            line.strip()
            for line in target.splitlines()
            if line.strip() and ("api" in line or "www" in line)
        ]
        return FakeDnsxResult(success=True, parsed_data=resolved)


class FakeDnsxWrapperAllResolve:
    def run(self, target: str) -> FakeDnsxResult:
        resolved = [line.strip() for line in target.splitlines() if line.strip()]
        return FakeDnsxResult(success=True, parsed_data=resolved)


class FakeDnsxWrapperFails:
    def run(self, target: str) -> FakeDnsxResult:
        return FakeDnsxResult(success=False, parsed_data=[], error="dnsx not found")


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _add_subdomains(session_factory: sessionmaker[Session], target_id: int, domains: list[str]) -> None:
    with session_factory() as session:
        for d in domains:
            session.add(
                ReconResult(
                    target_id=target_id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": d},
                )
            )
        session.commit()


def test_dnsx_filter_supersedes_nonresolving(monkeypatch) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "DnsxWrapper", FakeDnsxWrapper)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    _add_subdomains(sf, target_id, ["api.example.com", "www.example.com", "ghost.example.com"])

    result = tasks.run_dnsx_filter(target_id)

    with sf() as session:
        active = (
            session.query(ReconResult)
            .filter(
                ReconResult.target_id == target_id,
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.is_(None),
            )
            .all()
        )
        superseded = (
            session.query(ReconResult)
            .filter(
                ReconResult.target_id == target_id,
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.isnot(None),
            )
            .all()
        )

    assert result["filtered"] == 1
    assert result["kept"] == 2
    assert len(active) == 2
    assert {r.data["value"] for r in active} == {"api.example.com", "www.example.com"}
    assert len(superseded) == 1
    assert superseded[0].data["value"] == "ghost.example.com"


def test_dnsx_filter_nonfatal_when_dnsx_fails(monkeypatch) -> None:
    """If dnsx fails, task returns without modifying the database."""
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "DnsxWrapper", FakeDnsxWrapperFails)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    _add_subdomains(sf, target_id, ["api.example.com", "ghost.example.com"])

    result = tasks.run_dnsx_filter(target_id)

    with sf() as session:
        active = (
            session.query(ReconResult)
            .filter(
                ReconResult.target_id == target_id,
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.is_(None),
            )
            .all()
        )

    # No subdomains superseded; task continues non-fatally
    assert result.get("skipped") is True
    assert result["filtered"] == 0
    assert len(active) == 2


def test_dnsx_filter_skips_when_no_subdomains(monkeypatch) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "DnsxWrapper", FakeDnsxWrapper)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = tasks.run_dnsx_filter(target_id)

    assert result["filtered"] == 0
    assert result["kept"] == 0


def test_dnsx_filter_when_all_resolve(monkeypatch) -> None:
    """No subdomains are superseded when all resolve."""
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "DnsxWrapper", FakeDnsxWrapperAllResolve)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    _add_subdomains(sf, target_id, ["api.example.com", "www.example.com"])

    result = tasks.run_dnsx_filter(target_id)

    with sf() as session:
        superseded = (
            session.query(ReconResult)
            .filter(
                ReconResult.target_id == target_id,
                ReconResult.result_type == "subdomain",
                ReconResult.superseded_by.isnot(None),
            )
            .all()
        )

    assert result["filtered"] == 0
    assert result["kept"] == 2
    assert len(superseded) == 0
