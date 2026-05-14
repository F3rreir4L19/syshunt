"""Tests for get_setting / set_setting in core/db/queries.py."""

from __future__ import annotations

import datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.db.base import Base
from core.db.models import SystemSetting
from core.db.queries import get_setting, set_setting


def _session_factory():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class TestGetSetting:
    def test_returns_default_when_key_absent(self) -> None:
        sf = _session_factory()
        with sf() as session:
            assert get_setting(session, "missing_key") is None
            assert get_setting(session, "missing_key", "fallback") == "fallback"

    def test_returns_stored_value(self) -> None:
        sf = _session_factory()
        with sf() as session:
            session.add(SystemSetting(key="ANTHROPIC_API_KEY", value="sk-test", updated_at=datetime.datetime.utcnow()))
            session.commit()
            assert get_setting(session, "ANTHROPIC_API_KEY") == "sk-test"

    def test_returns_default_when_value_is_none(self) -> None:
        sf = _session_factory()
        with sf() as session:
            session.add(SystemSetting(key="nullable_key", value=None, updated_at=datetime.datetime.utcnow()))
            session.commit()
            assert get_setting(session, "nullable_key", "default") == "default"


class TestSetSetting:
    def test_inserts_new_entry(self) -> None:
        sf = _session_factory()
        with sf() as session:
            set_setting(session, "NEW_KEY", "hello")
            session.commit()
            assert get_setting(session, "NEW_KEY") == "hello"

    def test_updates_existing_entry(self) -> None:
        sf = _session_factory()
        with sf() as session:
            set_setting(session, "MY_KEY", "v1")
            session.commit()
            set_setting(session, "MY_KEY", "v2")
            session.commit()
            assert get_setting(session, "MY_KEY") == "v2"

    def test_removes_entry_when_value_is_none(self) -> None:
        sf = _session_factory()
        with sf() as session:
            set_setting(session, "TEMP_KEY", "value")
            session.commit()
            set_setting(session, "TEMP_KEY", None)
            session.commit()
            assert get_setting(session, "TEMP_KEY") is None
            assert session.get(SystemSetting, "TEMP_KEY") is None

    def test_removes_entry_when_value_is_empty_string(self) -> None:
        sf = _session_factory()
        with sf() as session:
            set_setting(session, "API_KEY", "sk-abc")
            session.commit()
            set_setting(session, "API_KEY", "")
            session.commit()
            assert get_setting(session, "API_KEY") is None

    def test_roundtrip(self) -> None:
        sf = _session_factory()
        with sf() as session:
            set_setting(session, "ROUNDTRIP", "test-value-123")
            session.commit()
            result = get_setting(session, "ROUNDTRIP")
        assert result == "test-value-123"
