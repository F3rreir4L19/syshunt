from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from core.db.base import Base
from core.db.models import Finding, ReconResult, Target
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


# ---------------------------------------------------------------------------
# bulk_create_targets
# ---------------------------------------------------------------------------


def test_bulk_create_targets_inserts_all_valid_domains() -> None:
    with build_session() as session:
        created, skipped, errors = queries.bulk_create_targets(
            session, ["example.com", "test.io", "https://strip-me.com/"]
        )

    assert created == 3
    assert skipped == 0
    assert errors == []


def test_bulk_create_targets_skips_duplicates() -> None:
    with build_session() as session:
        queries.bulk_create_targets(session, ["example.com"])
        created, skipped, errors = queries.bulk_create_targets(
            session, ["example.com", "new.com"]
        )

    assert created == 1
    assert skipped == 1


def test_bulk_create_targets_reports_empty_domains() -> None:
    with build_session() as session:
        created, skipped, errors = queries.bulk_create_targets(session, ["", "  "])

    assert created == 0
    assert len(errors) == 2


# ---------------------------------------------------------------------------
# get_finding
# ---------------------------------------------------------------------------


def test_get_finding_returns_full_detail() -> None:
    with build_session() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()
        finding = Finding(
            target_id=target.id,
            type="xss",
            title="XSS in search",
            severity="high",
            url="https://example.com/search?q=<>",
            confidence="likely",
        )
        session.add(finding)
        session.commit()
        fid = finding.id

        result = queries.get_finding(session, fid)

    assert result is not None
    assert result["title"] == "XSS in search"
    assert result["severity"] == "high"
    assert result["target_domain"] == "example.com"


def test_get_finding_returns_none_for_missing_id() -> None:
    with build_session() as session:
        result = queries.get_finding(session, 99999)

    assert result is None


# ---------------------------------------------------------------------------
# list_findings advanced filters
# ---------------------------------------------------------------------------


def test_list_findings_filters_by_score_range() -> None:
    with build_session() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.flush()
        session.add_all([
            Finding(target_id=target.id, type="a", title="low score", severity="info", auto_score=10),
            Finding(target_id=target.id, type="b", title="high score", severity="high", auto_score=80),
        ])
        session.commit()

        rows = queries.list_findings(session, score_min=50, score_max=100)

    assert len(rows) == 1
    assert rows[0]["title"] == "high score"


def test_list_findings_filters_by_target_id() -> None:
    with build_session() as session:
        t1 = Target(domain="example.com")
        t2 = Target(domain="other.com")
        session.add_all([t1, t2])
        session.flush()
        session.add_all([
            Finding(target_id=t1.id, type="a", title="from t1", severity="info"),
            Finding(target_id=t2.id, type="b", title="from t2", severity="info"),
        ])
        session.commit()

        rows = queries.list_findings(session, target_id=t1.id)

    assert len(rows) == 1
    assert rows[0]["title"] == "from t1"


# ---------------------------------------------------------------------------
# get_target_screenshot_paths
# ---------------------------------------------------------------------------


def test_get_target_screenshot_paths_returns_png_files(tmp_path: Path) -> None:
    shot_dir = tmp_path / "screenshots" / "42"
    shot_dir.mkdir(parents=True)
    (shot_dir / "https-example-com.png").write_bytes(b"")
    (shot_dir / "https-api-example-com.jpg").write_bytes(b"")
    (shot_dir / "notes.txt").write_bytes(b"")  # excluded

    paths = queries.get_target_screenshot_paths(42, str(tmp_path))

    assert len(paths) == 2
    assert all(p.endswith(".png") or p.endswith(".jpg") for p in paths)


def test_get_target_screenshot_paths_returns_empty_when_dir_missing(tmp_path: Path) -> None:
    paths = queries.get_target_screenshot_paths(99, str(tmp_path))

    assert paths == []


# ---------------------------------------------------------------------------
# normalize_domain validation
# ---------------------------------------------------------------------------

import pytest


def test_normalize_domain_strips_url_prefix() -> None:
    assert queries.normalize_domain("https://example.com/") == "example.com"


def test_normalize_domain_lowercases() -> None:
    assert queries.normalize_domain("Example.COM") == "example.com"


def test_normalize_domain_accepts_hyphen_in_label() -> None:
    assert queries.normalize_domain("my-site.example.com") == "my-site.example.com"


def test_normalize_domain_rejects_spaces() -> None:
    with pytest.raises(ValueError, match="Invalid domain"):
        queries.normalize_domain("bad domain.com")


def test_normalize_domain_rejects_special_chars() -> None:
    with pytest.raises(ValueError, match="Invalid domain"):
        queries.normalize_domain("bad!domain.com")


def test_normalize_domain_rejects_underscore() -> None:
    with pytest.raises(ValueError, match="Invalid domain"):
        queries.normalize_domain("bad_domain.com")


def test_normalize_domain_empty_returns_empty() -> None:
    assert queries.normalize_domain("") == ""


# ---------------------------------------------------------------------------
# check_in_scope
# ---------------------------------------------------------------------------


def test_check_in_scope_exact_match() -> None:
    assert queries.check_in_scope("example.com", ["example.com"], []) is True


def test_check_in_scope_subdomain_match() -> None:
    assert queries.check_in_scope("api.example.com", ["example.com"], []) is True


def test_check_in_scope_not_in_includes() -> None:
    assert queries.check_in_scope("other.com", ["example.com"], []) is False


def test_check_in_scope_excluded() -> None:
    assert queries.check_in_scope("staging.example.com", ["example.com"], ["staging.example.com"]) is False


def test_check_in_scope_subdomain_excluded() -> None:
    assert queries.check_in_scope("x.staging.example.com", ["example.com"], ["staging.example.com"]) is False


def test_check_in_scope_empty_includes_allows_all() -> None:
    assert queries.check_in_scope("anything.com", [], []) is True


def test_check_in_scope_exclude_overrides_include() -> None:
    assert queries.check_in_scope("api.example.com", ["example.com"], ["api.example.com"]) is False


# ---------------------------------------------------------------------------
# bulk_create_targets rejects invalid domains
# ---------------------------------------------------------------------------


def test_bulk_create_targets_rejects_invalid_domain() -> None:
    with build_session() as session:
        created, skipped, errors = queries.bulk_create_targets(
            session, ["valid.com", "bad domain!"]
        )
    assert created == 1
    assert len(errors) == 1
    assert "bad domain!" in errors[0]
