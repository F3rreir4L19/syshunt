from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from core.db.base import Base
from core.db.models import Target


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
