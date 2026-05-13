from sqlalchemy import Engine

from core.db.base import Base
from core.db.session import create_db_engine


def test_create_db_engine_accepts_explicit_database_url() -> None:
    engine = create_db_engine("sqlite+pysqlite:///:memory:")

    assert isinstance(engine, Engine)


def test_base_has_naming_convention() -> None:
    assert Base.metadata.naming_convention["pk"] == "pk_%(table_name)s"
