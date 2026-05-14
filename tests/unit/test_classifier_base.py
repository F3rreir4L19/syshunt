"""Unit tests for the heuristic classifier in core/analysis/classifier_base.py."""

from __future__ import annotations

import pytest

from core.analysis.classifier_base import FindingScore, classify


class TestClassifyAlwaysReturnsHeuristic:
    def test_classifier_used_is_heuristic(self) -> None:
        result = classify("info", "test-template", {}, None)
        assert result.classifier_used == "heuristic"

    def test_confidence_is_possible(self) -> None:
        result = classify("info", "test-template", {}, None)
        assert result.confidence == "possible"

    def test_confidence_note_is_non_empty(self) -> None:
        result = classify("info", "test-template", {}, None)
        assert result.confidence_note


class TestSeverityScoring:
    def test_critical_severity_scores_highest(self) -> None:
        critical = classify("critical", "t", {}, None)
        high = classify("high", "t", {}, None)
        assert critical.score > high.score

    def test_high_gt_medium(self) -> None:
        assert classify("high", "t", {}, None).score > classify("medium", "t", {}, None).score

    def test_medium_gt_low(self) -> None:
        assert classify("medium", "t", {}, None).score > classify("low", "t", {}, None).score

    def test_info_no_severity_points(self) -> None:
        result = classify("info", "t", {}, None)
        # With no evidence and no URL context: 0 severity * 0.8 = 0
        assert result.score == 0

    def test_unknown_severity_treated_as_info(self) -> None:
        result = classify("unknown", "t", {}, None)
        assert result.score == 0


class TestCategoryScoring:
    def test_cve_category_adds_points(self) -> None:
        with_cve = classify("info", "cve-2024-12345", {}, None)
        without_cve = classify("info", "test-template", {}, None)
        assert with_cve.score > without_cve.score

    def test_exposure_category(self) -> None:
        result = classify("info", "aws-exposure", {}, None)
        assert result.score > 0

    def test_misconfiguration_category(self) -> None:
        result = classify("info", "nginx-misconfiguration", {}, None)
        assert result.score > 0


class TestEvidenceScoring:
    def test_matched_at_adds_points(self) -> None:
        with_match = classify("info", "t", {"matched-at": "https://example.com/x"}, None)
        without_match = classify("info", "t", {}, None)
        assert with_match.score > without_match.score

    def test_request_response_diff_adds_points(self) -> None:
        full_evidence = classify(
            "info", "t",
            {"request": "GET /", "response": "HTTP 200"},
            None,
        )
        partial = classify("info", "t", {"matched-at": "https://x.com"}, None)
        assert full_evidence.score > partial.score


class TestUrlContextScoring:
    def test_admin_path_adds_points(self) -> None:
        admin = classify("info", "t", {}, "https://example.com/admin")
        plain = classify("info", "t", {}, "https://example.com/page")
        assert admin.score > plain.score

    def test_api_path_adds_points(self) -> None:
        api = classify("info", "t", {}, "https://example.com/api/v1/data")
        plain = classify("info", "t", {}, "https://example.com/page")
        assert api.score > plain.score

    def test_staging_subdomain_penalises(self) -> None:
        staging = classify("high", "t", {}, "https://staging.example.com/page")
        prod = classify("high", "t", {}, "https://example.com/page")
        assert staging.score < prod.score

    def test_dev_subdomain_penalises(self) -> None:
        dev = classify("high", "t", {}, "https://dev.example.com/page")
        prod = classify("high", "t", {}, "https://example.com/page")
        assert dev.score < prod.score


class TestPenalisation:
    def test_score_is_penalised_by_0_8(self) -> None:
        # A critical finding with matched-at: severity=40 + evidence=10 = 50 → 50 * 0.8 = 40
        result = classify("critical", "t", {"matched-at": "https://x.com"}, None)
        expected = int((40 + 10) * 0.8)
        assert result.score == expected

    def test_score_never_negative(self) -> None:
        # Staging penalty on info (0 pts) → 0 * 0.8 - 10 penalty would go negative
        result = classify("info", "t", {}, "https://staging.example.com/x")
        assert result.score >= 0

    def test_score_never_exceeds_100(self) -> None:
        # Max possible: critical(40) + cve(20) + matched-at(10) + req/resp(15) + admin(8) = 93 → *0.8 = 74
        result = classify(
            "critical",
            "cve-2024-12345",
            {"matched-at": "https://x.com/admin", "request": "GET /", "response": "200"},
            "https://x.com/admin",
        )
        assert result.score <= 100


class TestFindingScoreDataclass:
    def test_dataclass_fields(self) -> None:
        fs = FindingScore(score=50, confidence="possible", classifier_used="heuristic", confidence_note="note")
        assert fs.score == 50
        assert fs.confidence == "possible"
        assert fs.classifier_used == "heuristic"
        assert fs.confidence_note == "note"
