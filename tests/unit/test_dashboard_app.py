from dashboard import app
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.db.base import Base
from core.db.models import Finding, Target


def test_dashboard_pages_are_declared() -> None:
    assert [
        app.PAGE_TARGETS,
        app.PAGE_FINDINGS,
        app.PAGE_PROGRAMS,
        app.PAGE_SETTINGS,
    ] == ["Targets", "Findings", "Programs", "Settings"]


def test_create_target_normalizes_and_persists_domain() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        target = app.create_target(session, " HTTPS://Example.com/ ")

        saved = session.get(Target, target.id)

    assert saved is not None
    assert saved.domain == "example.com"
    assert saved.scope_includes == ["example.com"]


def test_list_targets_returns_dashboard_rows() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        session.add(Target(domain="example.com", status="pending"))
        session.commit()

        rows = app.list_targets(session)

    assert rows[0]["domain"] == "example.com"
    assert rows[0]["status"] == "pending"


def test_list_findings_filters_by_severity_status_and_search() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()
        session.add_all(
            [
                Finding(
                    target_id=target.id,
                    type="exposure",
                    title="Exposed admin panel",
                    url="https://admin.example.com",
                    severity="high",
                    status="new",
                    template_id="exposed-panel",
                ),
                Finding(
                    target_id=target.id,
                    type="headers",
                    title="Missing header",
                    severity="info",
                    status="closed",
                ),
            ]
        )
        session.commit()

        rows = app.list_findings(
            session,
            severities=["high"],
            statuses=["new"],
            search="admin",
        )

    assert len(rows) == 1
    assert rows[0]["title"] == "Exposed admin panel"
    assert rows[0]["target"] == "example.com"
