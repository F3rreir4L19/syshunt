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
    parsed_data: list[dict[str, Any]]
    error: str | None = None


class FakeNucleiWrapper:
    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(
            success=True,
            parsed_data=[
                {
                    "template-id": "exposed-panel",
                    "matched-at": target,
                    "info": {
                        "name": "Exposed panel",
                        "severity": "medium",
                        "description": "Administrative panel exposed.",
                    },
                }
            ],
        )


class FakeNucleiWrapperAlwaysFails:
    def run(self, target: str) -> FakeToolResult:
        return FakeToolResult(success=False, parsed_data=[], error="nuclei crashed")


class FakeNucleiWrapperPartialFailure:
    """Succeeds for 'https://good.example.com', fails for 'https://bad.example.com'."""

    def run(self, target: str) -> FakeToolResult:
        if "bad" in target:
            return FakeToolResult(success=False, parsed_data=[], error="timeout")
        return FakeToolResult(
            success=True,
            parsed_data=[
                {
                    "template-id": "exposed-panel",
                    "matched-at": target,
                    "info": {"name": "Exposed panel", "severity": "medium"},
                }
            ],
        )


def build_session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_run_nuclei_scan_persists_recon_results_and_findings(monkeypatch) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapper)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()
        session.add(
            ReconResult(
                target_id=target.id,
                tool="httpx",
                result_type="http_service",
                data={"url": "https://api.example.com", "status_code": 200},
            )
        )
        session.commit()
        target_id = target.id

    summary = tasks.run_nuclei_scan(target_id)

    with session_factory() as session:
        saved_target = session.get(Target, target_id)
        recon_result = session.query(ReconResult).filter_by(tool="nuclei").one()
        finding = session.query(Finding).one()

    assert summary == {
        "target_id": target_id,
        "tool": "nuclei",
        "created": 1,
    }
    assert saved_target is not None
    assert saved_target.status == "recon_done"
    assert saved_target.last_recon_at is not None
    assert recon_result.data["template-id"] == "exposed-panel"
    assert finding.title == "Exposed panel"
    assert finding.severity == "medium"
    assert finding.url == "https://api.example.com"
    assert finding.template_id == "exposed-panel"


def test_finding_from_nuclei_result_uses_safe_defaults() -> None:
    finding = tasks._finding_from_nuclei_result(
        target_id=42,
        data={"raw": "unparsed finding"},
    )

    assert finding.target_id == 42
    assert finding.type == "nuclei"
    assert finding.title == "nuclei"
    assert finding.severity == "info"
    assert finding.raw_evidence == {"raw": "unparsed finding"}


def test_run_nuclei_scan_raises_only_if_all_targets_fail(monkeypatch) -> None:
    """All scans fail → task raises RuntimeError."""
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapperAlwaysFails)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    with pytest.raises(RuntimeError, match="nuclei failed for all targets"):
        tasks.run_nuclei_scan(target_id)


def test_run_nuclei_scan_continues_on_partial_failure(monkeypatch) -> None:
    """One scan fails but another succeeds → task succeeds with partial results."""
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapperPartialFailure)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()
        session.add_all(
            [
                ReconResult(
                    target_id=target.id,
                    tool="httpx",
                    result_type="http_service",
                    data={"url": "https://bad.example.com", "status_code": 200},
                ),
                ReconResult(
                    target_id=target.id,
                    tool="httpx",
                    result_type="http_service",
                    data={"url": "https://good.example.com", "status_code": 200},
                ),
            ]
        )
        session.commit()
        target_id = target.id

    summary = tasks.run_nuclei_scan(target_id)

    with session_factory() as session:
        finding = session.query(Finding).one()

    assert summary["created"] == 1
    assert finding.url == "https://good.example.com"


def test_run_nuclei_scan_skips_out_of_scope_urls(monkeypatch) -> None:
    """URLs whose hostname is in scope_excludes are not scanned."""
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "NucleiWrapper", FakeNucleiWrapper)

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
                    tool="httpx",
                    result_type="http_service",
                    data={"url": "https://api.example.com", "status_code": 200},
                ),
                ReconResult(
                    target_id=target.id,
                    tool="httpx",
                    result_type="http_service",
                    data={"url": "https://staging.example.com", "status_code": 200},
                ),
            ]
        )
        session.commit()
        target_id = target.id

    summary = tasks.run_nuclei_scan(target_id)

    with session_factory() as session:
        findings = session.query(Finding).filter_by(target_id=target_id).all()

    # Only api.example.com scanned (staging excluded)
    assert summary["created"] == 1
    assert len(findings) == 1
    assert findings[0].url == "https://api.example.com"
