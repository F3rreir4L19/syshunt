from dataclasses import dataclass

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import ReconResult, Target
from core.pipeline import tasks


@dataclass
class FakeToolResult:
    success: bool
    parsed_data: list[str]
    error: str | None = None


class FakeSubfinderWrapper:
    def run(self, target: str) -> FakeToolResult:
        assert target == "example.com"
        return FakeToolResult(
            success=True,
            parsed_data=["api.example.com", "www.example.com"],
        )


def build_session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def test_run_subdomain_enum_persists_recon_results(monkeypatch) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)
    monkeypatch.setattr(tasks, "SubfinderWrapper", FakeSubfinderWrapper)

    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        target_id = target.id

    summary = tasks.run_subdomain_enum(target_id)

    with session_factory() as session:
        saved_target = session.get(Target, target_id)
        results = session.query(ReconResult).order_by(ReconResult.id).all()

    assert summary == {
        "target_id": target_id,
        "tool": "subfinder",
        "created": 2,
    }
    assert saved_target is not None
    assert saved_target.status == "subdomain_enum_completed"
    assert [result.data["value"] for result in results] == [
        "api.example.com",
        "www.example.com",
    ]


def test_run_subdomain_enum_errors_for_missing_target(monkeypatch) -> None:
    session_factory = build_session_factory()
    monkeypatch.setattr(tasks, "SessionLocal", session_factory)

    with pytest.raises(ValueError, match="Target 999 not found"):
        tasks.run_subdomain_enum(999)
