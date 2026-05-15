"""Tests for Phase 3.7 Group B — Bugs e consistência.

Covers:
  B1 — run_dnsx_filter consistent return on all paths
  B2 — force_reanalyze includes already-classified findings + run_ai_analysis_for_finding
  B3 — Finding deduplication in run_nuclei_scan
  B4 — list_findings limit/offset pagination
  B5 — CSV with UTF-8 BOM parsed correctly
  B6 — check_in_scope wildcard (*.example.com) and excludes
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import Finding, ReconResult, Target
from core.db import queries
from core.pipeline import tasks


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _session_factory() -> sessionmaker[Session]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _add_target(sf: sessionmaker[Session]) -> int:
    with sf() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        return target.id


def _add_subdomains(sf: sessionmaker[Session], target_id: int, domains: list[str]) -> None:
    with sf() as session:
        for d in domains:
            session.add(
                ReconResult(
                    target_id=target_id,
                    tool="subfinder",
                    result_type="subdomain",
                    data={"value": d},
                )
            )
        session.commit()


def _noop_classify(finding, target, session, force_reanalyze: bool = False, **kwargs) -> None:
    finding.classifier_used = "heuristic"
    finding.confidence = "possible"
    finding.confidence_note = "test"


# ---------------------------------------------------------------------------
# B1 — run_dnsx_filter consistent return
# ---------------------------------------------------------------------------


@dataclass
class _FakeDnsxOk:
    success: bool = True
    parsed_data: list[str] = None
    error: str | None = None

    def __post_init__(self):
        if self.parsed_data is None:
            self.parsed_data = []


class _DnsxWrapperOk:
    def run(self, target: str) -> _FakeDnsxOk:
        return _FakeDnsxOk(success=True, parsed_data=["api.example.com"])


class _DnsxWrapperFail:
    def run(self, target: str) -> _FakeDnsxOk:
        return _FakeDnsxOk(success=False, parsed_data=[], error="dnsx not found")


class _DnsxWrapperRaises:
    def run(self, target: str) -> None:
        raise FileNotFoundError("dnsx: command not found")


_REQUIRED_KEYS = {"target_id", "tool", "filtered", "kept", "skipped"}


class TestDnsxFilterConsistentReturn:
    def test_success_path_has_all_keys(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        monkeypatch.setattr(tasks, "DnsxWrapper", _DnsxWrapperOk)
        target_id = _add_target(sf)
        _add_subdomains(sf, target_id, ["api.example.com", "ghost.example.com"])

        result = tasks.run_dnsx_filter(target_id)

        assert _REQUIRED_KEYS <= result.keys()
        assert result["skipped"] is False

    def test_no_subdomains_path_has_all_keys(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        monkeypatch.setattr(tasks, "DnsxWrapper", _DnsxWrapperOk)
        target_id = _add_target(sf)

        result = tasks.run_dnsx_filter(target_id)

        assert _REQUIRED_KEYS <= result.keys()
        assert result["skipped"] is False
        assert result["filtered"] == 0
        assert result["kept"] == 0

    def test_wrapper_fail_returns_skipped_true_with_zeros(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        monkeypatch.setattr(tasks, "DnsxWrapper", _DnsxWrapperFail)
        target_id = _add_target(sf)
        _add_subdomains(sf, target_id, ["api.example.com"])

        result = tasks.run_dnsx_filter(target_id)

        assert _REQUIRED_KEYS <= result.keys()
        assert result["skipped"] is True
        assert result["filtered"] == 0
        assert result["kept"] == 0

    def test_exception_path_has_all_keys_and_skipped_true(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        monkeypatch.setattr(tasks, "DnsxWrapper", _DnsxWrapperRaises)
        target_id = _add_target(sf)
        _add_subdomains(sf, target_id, ["api.example.com"])

        result = tasks.run_dnsx_filter(target_id)

        assert _REQUIRED_KEYS <= result.keys()
        assert result["skipped"] is True
        assert result["filtered"] == 0
        assert result["kept"] == 0

    def test_runtime_error_exception_path(self, monkeypatch) -> None:
        class _Raises:
            def run(self, t):
                raise RuntimeError("unexpected crash")

        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        monkeypatch.setattr(tasks, "DnsxWrapper", _Raises)
        target_id = _add_target(sf)
        _add_subdomains(sf, target_id, ["api.example.com"])

        result = tasks.run_dnsx_filter(target_id)

        assert result["skipped"] is True
        assert result["filtered"] == 0
        assert result["kept"] == 0


# ---------------------------------------------------------------------------
# B2 — force_reanalyze includes already-classified findings
# ---------------------------------------------------------------------------


class TestForceReanalyze:
    def test_force_reanalyze_processes_heuristic_classified_finding(
        self, monkeypatch
    ) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)

        with sf() as session:
            session.add(
                Finding(
                    target_id=target_id,
                    type="test",
                    title="Already classified",
                    severity="medium",
                    auto_score=50,
                    status="new",
                    classifier_used="heuristic",  # already classified
                )
            )
            session.commit()

        classified_ids: list[int] = []

        def track(finding, target, session, force_reanalyze: bool = False, **kwargs) -> None:
            classified_ids.append(finding.id)
            finding.classifier_used = "heuristic"

        with patch("core.analysis.classifier.classify_finding", side_effect=track):
            result = tasks.run_ai_analysis(target_id, force_reanalyze=True)

        assert result["classified"] == 1
        assert len(classified_ids) == 1

    def test_without_force_reanalyze_skips_classified_findings(
        self, monkeypatch
    ) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)

        with sf() as session:
            session.add(
                Finding(
                    target_id=target_id,
                    type="test",
                    title="Already classified",
                    severity="medium",
                    auto_score=50,
                    status="new",
                    classifier_used="heuristic",
                )
            )
            session.commit()

        classified_ids: list[int] = []

        def track(finding, target, session, force_reanalyze: bool = False, **kwargs) -> None:
            classified_ids.append(finding.id)

        with patch("core.analysis.classifier.classify_finding", side_effect=track):
            result = tasks.run_ai_analysis(target_id, force_reanalyze=False)

        assert result["classified"] == 0
        assert classified_ids == []

    def test_run_ai_analysis_for_finding_classifies_single_finding(
        self, monkeypatch
    ) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)

        with sf() as session:
            f = Finding(
                target_id=target_id,
                type="xss",
                title="XSS finding",
                severity="high",
                status="new",
            )
            session.add(f)
            session.commit()
            finding_id = f.id

        classified: list[int] = []

        def track(finding, target, session, force_reanalyze: bool = False, **kwargs) -> None:
            classified.append(finding.id)
            finding.classifier_used = "heuristic"

        with patch("core.analysis.classifier.classify_finding", side_effect=track):
            result = tasks.run_ai_analysis_for_finding(finding_id, force_reanalyze=True)

        assert result == {"finding_id": finding_id, "classified": 1}
        assert classified == [finding_id]

    def test_run_ai_analysis_for_finding_raises_for_missing_finding(
        self, monkeypatch
    ) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)

        with pytest.raises(ValueError, match="Finding"):
            tasks.run_ai_analysis_for_finding(99999)


# ---------------------------------------------------------------------------
# B3 — Finding deduplication in run_nuclei_scan
# ---------------------------------------------------------------------------


@dataclass
class _NucleiResult:
    success: bool
    parsed_data: list[dict[str, Any]]
    error: str | None = None


def _make_nuclei_wrapper(data: list[dict[str, Any]]):
    class _Wrapper:
        def run(self, target):
            return _NucleiResult(success=True, parsed_data=data)

    return _Wrapper


class TestFindingDedup:
    def _setup_with_existing_finding(self, sf):
        """Create target + existing Finding for template 'exposed-panel' at /admin."""
        with sf() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            session.add(
                Finding(
                    target_id=target.id,
                    type="exposed-panel",
                    title="Exposed panel",
                    url="https://example.com/admin",
                    template_id="exposed-panel",
                    severity="high",
                    status="new",
                )
            )
            session.commit()
            return target.id

    def test_rescan_does_not_duplicate_finding(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = self._setup_with_existing_finding(sf)

        nuclei_data = [
            {
                "template-id": "exposed-panel",
                "info": {"name": "Exposed panel", "severity": "high"},
                "matched-at": "https://example.com/admin",
            }
        ]
        monkeypatch.setattr(tasks, "NucleiWrapper", _make_nuclei_wrapper(nuclei_data))
        monkeypatch.setattr(tasks.run_ai_analysis, "apply_async", lambda *a, **kw: None)

        tasks.run_nuclei_scan(target_id)

        with sf() as session:
            count = (
                session.query(Finding)
                .filter_by(target_id=target_id, template_id="exposed-panel")
                .count()
            )
        assert count == 1

    def test_new_finding_is_inserted(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = self._setup_with_existing_finding(sf)

        # Different URL → new finding
        nuclei_data = [
            {
                "template-id": "exposed-panel",
                "info": {"name": "Exposed panel", "severity": "high"},
                "matched-at": "https://example.com/dashboard",  # different URL
            }
        ]
        monkeypatch.setattr(tasks, "NucleiWrapper", _make_nuclei_wrapper(nuclei_data))
        monkeypatch.setattr(tasks.run_ai_analysis, "apply_async", lambda *a, **kw: None)

        tasks.run_nuclei_scan(target_id)

        with sf() as session:
            count = (
                session.query(Finding)
                .filter_by(target_id=target_id, template_id="exposed-panel")
                .count()
            )
        assert count == 2

    def test_finding_exists_helper_finds_match(self) -> None:
        engine = create_engine("sqlite+pysqlite:///:memory:")
        Base.metadata.create_all(engine)
        with Session(engine) as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            session.add(
                Finding(
                    target_id=target.id,
                    template_id="xss",
                    type="xss",
                    title="XSS",
                    severity="high",
                    url="https://example.com/search",
                )
            )
            session.commit()

            assert queries.finding_exists(session, target.id, "xss", "https://example.com/search")
            assert not queries.finding_exists(session, target.id, "xss", "https://example.com/other")
            assert not queries.finding_exists(session, target.id, "sqli", "https://example.com/search")


# ---------------------------------------------------------------------------
# B4 — list_findings pagination
# ---------------------------------------------------------------------------


def _make_session_with_findings(count: int) -> tuple[Session, int]:
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = Session(engine)
    target = Target(domain="example.com")
    session.add(target)
    session.flush()
    for i in range(count):
        session.add(
            Finding(
                target_id=target.id,
                type="test",
                title=f"Finding {i:03d}",
                severity="info",
                auto_score=i,
                status="new",
            )
        )
    session.commit()
    return session, target.id


class TestListFindingsPagination:
    def test_limit_returns_at_most_n_results(self) -> None:
        with _make_session_with_findings(10)[0] as session:
            engine = session.get_bind()
            Base.metadata.create_all(engine)

        # Fresh session
        session, _ = _make_session_with_findings(10)
        with session:
            results = queries.list_findings(session, limit=5)
        assert len(results) == 5

    def test_offset_skips_first_n_results(self) -> None:
        session, _ = _make_session_with_findings(10)
        with session:
            all_results = queries.list_findings(session)
            offset_results = queries.list_findings(session, offset=3)
        assert len(offset_results) == len(all_results) - 3

    def test_limit_and_offset_together(self) -> None:
        session, _ = _make_session_with_findings(10)
        with session:
            results = queries.list_findings(session, limit=4, offset=2)
        assert len(results) == 4

    def test_offset_beyond_total_returns_empty(self) -> None:
        session, _ = _make_session_with_findings(3)
        with session:
            results = queries.list_findings(session, offset=10)
        assert results == []

    def test_limit_zero_returns_empty(self) -> None:
        session, _ = _make_session_with_findings(5)
        with session:
            results = queries.list_findings(session, limit=0)
        assert results == []

    def test_no_limit_returns_all(self) -> None:
        session, _ = _make_session_with_findings(7)
        with session:
            results = queries.list_findings(session)
        assert len(results) == 7


# ---------------------------------------------------------------------------
# B5 — CSV with UTF-8 BOM
# ---------------------------------------------------------------------------


class TestCsvBom:
    def test_parse_domains_with_bom_header(self) -> None:
        from dashboard import app

        # Simulate file saved with UTF-8 BOM (e.g. from Excel)
        bom_csv = b"\xef\xbb\xbfdomain,notes\nexample.com,test\nother.com,\n"
        domains = app._parse_domains_from_csv(bom_csv)
        assert domains == ["example.com", "other.com"]

    def test_parse_domains_without_bom_still_works(self) -> None:
        from dashboard import app

        csv_bytes = b"domain,notes\nexample.com,test\n"
        domains = app._parse_domains_from_csv(csv_bytes)
        assert domains == ["example.com"]

    def test_parse_domains_bom_no_header(self) -> None:
        from dashboard import app

        # BOM + plain list (no header)
        bom_list = b"\xef\xbb\xbfexample.com\nother.com\n"
        domains = app._parse_domains_from_csv(bom_list)
        # First token is stripped of BOM; but since "example.com" is not a valid
        # CSV "domain" header, it falls through to the no-header path.
        assert "example.com" in domains
        assert "other.com" in domains


# ---------------------------------------------------------------------------
# B6 — check_in_scope wildcard patterns
# ---------------------------------------------------------------------------


class TestScopeWildcard:
    def test_wildcard_matches_subdomain(self) -> None:
        assert queries.check_in_scope("api.example.com", ["*.example.com"], []) is True

    def test_wildcard_does_not_match_root(self) -> None:
        assert queries.check_in_scope("example.com", ["*.example.com"], []) is False

    def test_wildcard_matches_deep_subdomain(self) -> None:
        assert queries.check_in_scope("a.b.example.com", ["*.example.com"], []) is True

    def test_exact_pattern_matches_root_and_subdomain(self) -> None:
        assert queries.check_in_scope("example.com", ["example.com"], []) is True
        assert queries.check_in_scope("api.example.com", ["example.com"], []) is True

    def test_excludes_override_wildcard_include(self) -> None:
        assert (
            queries.check_in_scope(
                "staging.example.com",
                ["*.example.com"],
                ["staging.example.com"],
            )
            is False
        )

    def test_wildcard_exclude_blocks_subdomain_but_not_root(self) -> None:
        # *.example.com in excludes should block subdomains but not the root
        assert (
            queries.check_in_scope("api.example.com", ["example.com"], ["*.example.com"])
            is False
        )
        assert (
            queries.check_in_scope("example.com", ["example.com"], ["*.example.com"])
            is True
        )

    def test_no_includes_allows_everything(self) -> None:
        assert queries.check_in_scope("anything.example.com", [], []) is True

    def test_wildcard_does_not_match_sibling_domain(self) -> None:
        # *.example.com should not match other.com
        assert queries.check_in_scope("other.com", ["*.example.com"], []) is False

    def test_excludes_always_win_over_includes(self) -> None:
        assert (
            queries.check_in_scope(
                "api.example.com",
                ["example.com"],
                ["api.example.com"],
            )
            is False
        )
