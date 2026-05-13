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
    assert saved_target.status == "nuclei_scan_completed"
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
