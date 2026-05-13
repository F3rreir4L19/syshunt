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
    assert saved_target.status == "http_probe_completed"
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
