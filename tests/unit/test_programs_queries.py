"""Tests for Phase 4 Group 5 — Programs DB queries (badge, scope history)."""
from __future__ import annotations


def _make_session():
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    import core.db.models  # noqa: F401 — ensures all models are registered in Base.metadata
    from core.db.base import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session()


# ---------------------------------------------------------------------------
# upsert_bounty_program — badge behaviour
# ---------------------------------------------------------------------------


class TestUpsertBadge:
    def _upsert(self, session, handle="acme", platform="hackerone", scope=None, **kw):
        from core.db.queries import upsert_bounty_program

        return upsert_bounty_program(
            session,
            platform=platform,
            program_handle=handle,
            name=f"{handle} Program",
            scope=scope or [],
            bounty_table={},
            **kw,
        )

    def test_badge_new_on_insert(self):
        session = _make_session()
        prog, is_new, _, _ = self._upsert(session)
        assert is_new is True
        assert prog.badge == "new"

    def test_badge_unchanged_when_no_scope_change(self):
        session = _make_session()
        scope = [{"asset_identifier": "https://acme.com", "asset_type": "url"}]
        prog, _, _, _ = self._upsert(session, scope=scope)
        assert prog.badge == "new"

        # Second upsert — same scope, no change
        prog2, is_new, added, removed = self._upsert(session, scope=scope)
        assert is_new is False
        assert added == []
        assert removed == []
        assert prog2.badge == "new"  # badge not cleared by a no-change poll

    def test_badge_scope_changed_when_scope_changes(self):
        session = _make_session()
        scope1 = [{"asset_identifier": "https://acme.com"}]
        prog, _, _, _ = self._upsert(session, scope=scope1)
        # Manually dismiss badge so we can test scope_changed separately
        prog.badge = None
        session.flush()

        scope2 = [
            {"asset_identifier": "https://acme.com"},
            {"asset_identifier": "https://api.acme.com"},
        ]
        prog2, is_new, added, removed = self._upsert(session, scope=scope2)
        assert is_new is False
        assert "https://api.acme.com" in added
        assert prog2.badge == "scope_changed"

    def test_badge_new_not_downgraded_by_scope_change(self):
        """A 'new' badge should not be overwritten by a scope change."""
        session = _make_session()
        scope1 = [{"asset_identifier": "https://acme.com"}]
        prog, _, _, _ = self._upsert(session, scope=scope1)
        assert prog.badge == "new"

        # Second poll — scope changed, but badge should stay "new"
        scope2 = [
            {"asset_identifier": "https://acme.com"},
            {"asset_identifier": "https://api.acme.com"},
        ]
        prog2, _, added, _ = self._upsert(session, scope=scope2)
        assert added  # scope did change
        assert prog2.badge == "new"  # not downgraded

    def test_scope_history_empty_on_insert(self):
        session = _make_session()
        prog, _, _, _ = self._upsert(session)
        assert prog.scope_history == []

    def test_scope_history_appended_on_change(self):
        session = _make_session()
        scope1 = [{"asset_identifier": "https://acme.com"}]
        prog, _, _, _ = self._upsert(session, scope=scope1)

        scope2 = [
            {"asset_identifier": "https://acme.com"},
            {"asset_identifier": "https://new.acme.com"},
        ]
        prog2, _, _, _ = self._upsert(session, scope=scope2)
        assert len(prog2.scope_history) == 1
        assert "https://new.acme.com" in prog2.scope_history[0]["added"]
        assert prog2.scope_history[0]["removed"] == []

    def test_scope_history_records_removal(self):
        session = _make_session()
        scope1 = [
            {"asset_identifier": "https://acme.com"},
            {"asset_identifier": "https://old.acme.com"},
        ]
        prog, _, _, _ = self._upsert(session, scope=scope1)

        scope2 = [{"asset_identifier": "https://acme.com"}]
        prog2, _, added, removed = self._upsert(session, scope=scope2)
        assert "https://old.acme.com" in removed
        assert "https://old.acme.com" in prog2.scope_history[0]["removed"]

    def test_scope_history_not_appended_when_no_change(self):
        session = _make_session()
        scope = [{"asset_identifier": "https://acme.com"}]
        self._upsert(session, scope=scope)
        prog2, _, added, removed = self._upsert(session, scope=scope)
        assert added == []
        assert removed == []
        assert prog2.scope_history == []

    def test_scope_history_accumulates_multiple_changes(self):
        session = _make_session()
        prog, _, _, _ = self._upsert(session, scope=[{"asset_identifier": "https://a.com"}])
        prog.badge = None
        session.flush()

        self._upsert(
            session,
            scope=[
                {"asset_identifier": "https://a.com"},
                {"asset_identifier": "https://b.com"},
            ],
        )
        prog3, _, _, _ = self._upsert(
            session,
            scope=[
                {"asset_identifier": "https://a.com"},
                {"asset_identifier": "https://b.com"},
                {"asset_identifier": "https://c.com"},
            ],
        )
        assert len(prog3.scope_history) == 2


# ---------------------------------------------------------------------------
# dismiss_program_badge
# ---------------------------------------------------------------------------


class TestDismissProgramBadge:
    def test_clears_new_badge(self):
        from core.db.queries import dismiss_program_badge, upsert_bounty_program

        session = _make_session()
        prog, _, _, _ = upsert_bounty_program(
            session, "hackerone", "acme-dismiss", "Acme", [], {}
        )
        assert prog.badge == "new"

        dismiss_program_badge(session, prog.id)
        session.commit()

        from core.db.models import BountyProgram

        reloaded = session.get(BountyProgram, prog.id)
        assert reloaded.badge is None

    def test_clears_scope_changed_badge(self):
        from core.db.models import BountyProgram
        from core.db.queries import dismiss_program_badge, upsert_bounty_program

        session = _make_session()
        prog, _, _, _ = upsert_bounty_program(
            session, "hackerone", "acme-sc", "Acme SC",
            [{"asset_identifier": "https://acme.com"}], {}
        )
        prog.badge = "scope_changed"
        session.flush()

        dismiss_program_badge(session, prog.id)
        session.commit()

        reloaded = session.get(BountyProgram, prog.id)
        assert reloaded.badge is None

    def test_noop_when_program_not_found(self):
        from core.db.queries import dismiss_program_badge

        session = _make_session()
        # Should not raise
        dismiss_program_badge(session, 99999)

    def test_noop_when_badge_already_none(self):
        from core.db.models import BountyProgram
        from core.db.queries import dismiss_program_badge, upsert_bounty_program

        session = _make_session()
        prog, _, _, _ = upsert_bounty_program(
            session, "hackerone", "acme-none", "Acme None", [], {}
        )
        prog.badge = None
        session.flush()

        dismiss_program_badge(session, prog.id)
        session.commit()

        reloaded = session.get(BountyProgram, prog.id)
        assert reloaded.badge is None


# ---------------------------------------------------------------------------
# set_program_auto_recon
# ---------------------------------------------------------------------------


class TestSetProgramAutoRecon:
    def test_enables_auto_recon(self):
        from core.db.models import BountyProgram
        from core.db.queries import set_program_auto_recon, upsert_bounty_program

        session = _make_session()
        prog, _, _, _ = upsert_bounty_program(
            session, "hackerone", "acme-auto", "Acme Auto", [], {},
            auto_recon_enabled=False,
        )
        assert prog.auto_recon_enabled is False

        set_program_auto_recon(session, prog.id, True)
        session.commit()

        reloaded = session.get(BountyProgram, prog.id)
        assert reloaded.auto_recon_enabled is True

    def test_disables_auto_recon(self):
        from core.db.models import BountyProgram
        from core.db.queries import set_program_auto_recon, upsert_bounty_program

        session = _make_session()
        prog, _, _, _ = upsert_bounty_program(
            session, "hackerone", "acme-dis", "Acme Dis", [], {},
            auto_recon_enabled=True,
        )
        assert prog.auto_recon_enabled is True

        set_program_auto_recon(session, prog.id, False)
        session.commit()

        reloaded = session.get(BountyProgram, prog.id)
        assert reloaded.auto_recon_enabled is False

    def test_noop_when_program_not_found(self):
        from core.db.queries import set_program_auto_recon

        session = _make_session()
        # Should not raise
        set_program_auto_recon(session, 99999, True)


# ---------------------------------------------------------------------------
# list_bounty_programs — badge and scope_history included
# ---------------------------------------------------------------------------


class TestListBountyProgramsFields:
    def test_badge_included_in_list(self):
        from core.db.queries import list_bounty_programs, upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(session, "hackerone", "acme-list", "Acme", [], {})
        session.commit()

        programs = list_bounty_programs(session)
        assert programs
        assert "badge" in programs[0]
        assert programs[0]["badge"] == "new"

    def test_scope_history_included_in_list(self):
        from core.db.queries import list_bounty_programs, upsert_bounty_program

        session = _make_session()
        upsert_bounty_program(session, "hackerone", "acme-hist", "Acme", [], {})
        session.commit()

        programs = list_bounty_programs(session)
        assert "scope_history" in programs[0]
        assert isinstance(programs[0]["scope_history"], list)

    def test_scope_array_included_in_list(self):
        from core.db.queries import list_bounty_programs, upsert_bounty_program

        session = _make_session()
        scope = [{"asset_identifier": "https://acme.com", "asset_type": "url"}]
        upsert_bounty_program(session, "hackerone", "acme-scope", "Acme", scope, {})
        session.commit()

        programs = list_bounty_programs(session)
        assert "scope" in programs[0]
        assert programs[0]["scope"] == scope
        assert programs[0]["scope_count"] == 1

    def test_scope_history_with_changes(self):
        from core.db.queries import list_bounty_programs, upsert_bounty_program

        session = _make_session()
        prog, _, _, _ = upsert_bounty_program(
            session, "hackerone", "acme-chg", "Acme",
            [{"asset_identifier": "https://a.com"}], {}
        )
        prog.badge = None
        session.flush()

        upsert_bounty_program(
            session, "hackerone", "acme-chg", "Acme",
            [{"asset_identifier": "https://a.com"}, {"asset_identifier": "https://b.com"}], {}
        )
        session.commit()

        programs = list_bounty_programs(session)
        target = next(p for p in programs if p["program_handle"] == "acme-chg")
        assert len(target["scope_history"]) == 1
        assert target["badge"] == "scope_changed"
