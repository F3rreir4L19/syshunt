"""Tests for run_port_scan Celery task."""

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


class FakeNmapWrapper:
    name = "nmap"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=[
                {
                    "ip": "1.2.3.4",
                    "hostname": target,
                    "port": 80,
                    "protocol": "tcp",
                    "service": "http",
                    "product": "",
                    "version": "",
                }
            ],
        )


class FakeNmapWrapperFailing:
    name = "nmap"

    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(success=False, parsed_data=[], error="nmap not found")


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_run_port_scan_stores_open_ports(monkeypatch) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "NmapWrapper", FakeNmapWrapper)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        session.add(
            ReconResult(
                target_id=target.id,
                tool="httpx",
                result_type="http_service",
                data={"url": "https://example.com", "host": "example.com"},
            )
        )
        session.commit()
        target_id = target.id

    result = tasks.run_port_scan(target_id)

    assert result["tool"] == "nmap"
    assert result["created"] == 1

    with sf() as session:
        rows = session.query(ReconResult).filter(
            ReconResult.target_id == target_id,
            ReconResult.tool == "nmap",
        ).all()
    assert len(rows) == 1
    assert rows[0].data["port"] == 80


def test_run_port_scan_falls_back_to_domain_when_no_httpx_results(monkeypatch) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "NmapWrapper", FakeNmapWrapper)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    result = tasks.run_port_scan(target_id)

    assert result["created"] == 1


def test_run_port_scan_raises_when_all_fail(monkeypatch) -> None:
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "NmapWrapper", FakeNmapWrapperFailing)

    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    try:
        tasks.run_port_scan(target_id)
        assert False, "should have raised"
    except RuntimeError as exc:
        assert "nmap failed" in str(exc)


def test_run_port_scan_skips_out_of_scope_hosts(monkeypatch) -> None:
    """Hosts in scope_excludes are not port-scanned."""
    sf = _session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", sf)
    monkeypatch.setattr(tasks, "NmapWrapper", FakeNmapWrapper)

    with sf() as session:
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
                    tool="httpx",
                    result_type="http_service",
                    data={"url": "https://api.example.com", "host": "api.example.com"},
                ),
                ReconResult(
                    target_id=target.id,
                    tool="httpx",
                    result_type="http_service",
                    data={"url": "https://staging.example.com", "host": "staging.example.com"},
                ),
            ]
        )
        session.commit()
        target_id = target.id

    result = tasks.run_port_scan(target_id)

    with sf() as session:
        rows = session.query(ReconResult).filter(
            ReconResult.target_id == target_id,
            ReconResult.tool == "nmap",
        ).all()

    assert result["created"] == 1
    assert rows[0].data["hostname"] == "api.example.com"
