from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.db.base import Base
from core.db.models import ReconResult, Target
from core.db import queries


def build_session() -> Session:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Session(engine)


# ---------------------------------------------------------------------------
# insert_recon_results_with_dedup
# ---------------------------------------------------------------------------


def test_insert_new_results_when_none_exist() -> None:
    with build_session() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()

        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="subfinder",
            result_type="subdomain",
            data_items=[{"value": "api.example.com"}, {"value": "www.example.com"}],
        )
        session.commit()

        results = (
            session.query(ReconResult)
            .filter_by(tool="subfinder", result_type="subdomain")
            .all()
        )

    assert len(inserted) == 2
    assert len(results) == 2
    assert all(r.superseded_by is None for r in results)


def test_dedup_skips_already_stored_result() -> None:
    with build_session() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()

        # First insert
        queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="subfinder",
            result_type="subdomain",
            data_items=[{"value": "api.example.com"}],
        )
        session.commit()

        # Second insert with same data — should be deduplicated
        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="subfinder",
            result_type="subdomain",
            data_items=[{"value": "api.example.com"}],
        )
        session.commit()

        results = (
            session.query(ReconResult)
            .filter_by(tool="subfinder", result_type="subdomain")
            .all()
        )

    assert len(inserted) == 0  # no new rows
    assert len(results) == 1  # still only one row


def test_rescan_supersedes_removed_results() -> None:
    """Results from a previous scan that are absent in the new scan get superseded."""
    with build_session() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()

        # First scan: two subdomains
        queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="subfinder",
            result_type="subdomain",
            data_items=[{"value": "api.example.com"}, {"value": "old.example.com"}],
        )
        session.commit()

        # Second scan: only one subdomain (old.example.com disappeared)
        inserted = queries.insert_recon_results_with_dedup(
            session,
            target_id=target.id,
            tool="subfinder",
            result_type="subdomain",
            data_items=[{"value": "api.example.com"}, {"value": "new.example.com"}],
        )
        session.commit()

        active = (
            session.query(ReconResult)
            .filter(
                ReconResult.tool == "subfinder",
                ReconResult.superseded_by.is_(None),
            )
            .all()
        )
        superseded = (
            session.query(ReconResult)
            .filter(
                ReconResult.tool == "subfinder",
                ReconResult.superseded_by.isnot(None),
            )
            .all()
        )

    # api.example.com deduplicated (1 old kept active) + new.example.com inserted
    assert len(inserted) == 1
    assert inserted[0]["value"] == "new.example.com"
    # Active: api.example.com (kept) + new.example.com (inserted) = 2
    active_values = {r.data["value"] for r in active}
    assert active_values == {"api.example.com", "new.example.com"}
    # Superseded: old.example.com (absent from new scan)
    assert len(superseded) == 1
    assert superseded[0].data["value"] == "old.example.com"
