from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from core.db.base import Base
from core.db.models import Finding, Target


def test_target_model_has_expected_fields() -> None:
    columns = Target.__table__.columns

    assert set(columns.keys()) >= {
        "id",
        "domain",
        "scope_includes",
        "scope_excludes",
        "status",
        "platform",
        "program_id",
        "created_at",
        "updated_at",
        "last_recon_at",
        "recon_depth",
    }


def test_target_model_can_persist_to_database() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        target = Target(domain="example.com", scope_includes=["*.example.com"])
        session.add(target)
        session.commit()

        saved = session.get(Target, target.id)

    assert saved is not None
    assert saved.status == "pending"
    assert saved.recon_depth == 2
    assert inspect(engine).has_table("targets")


def test_finding_model_has_expected_fields() -> None:
    columns = Finding.__table__.columns

    assert set(columns.keys()) >= {
        "id",
        "target_id",
        "type",
        "title",
        "description",
        "url",
        "parameter",
        "severity",
        "confidence",
        "exploitation_difficulty",
        "auto_score",
        "status",
        "template_id",
        "raw_evidence",
        "screenshots",
        "created_at",
        "updated_at",
        "reviewed_at",
    }


def test_finding_model_can_persist_with_target_relationship() -> None:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)

    with Session(engine) as session:
        target = Target(domain="example.com")
        finding = Finding(
            target=target,
            type="exposure",
            title="Exposed admin panel",
            url="https://admin.example.com",
        )
        session.add(finding)
        session.commit()

        saved = session.get(Finding, finding.id)
        assert saved is not None
        assert saved.target.domain == "example.com"

    assert saved.status == "new"
    assert saved.severity == "info"
