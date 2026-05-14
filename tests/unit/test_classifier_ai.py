"""Tests for AIClassifier in core/analysis/classifier_ai.py."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from core.analysis.classifier_ai import AIClassifier
from core.analysis.classifier_base import FindingScore


def _make_finding(
    type_: str = "exposed-panel",
    url: str | None = "https://api.example.com/admin",
    severity: str = "medium",
    raw_evidence: dict | None = None,
) -> MagicMock:
    f = MagicMock()
    f.type = type_
    f.url = url
    f.severity = severity
    f.raw_evidence = raw_evidence or {"matched-at": url}
    return f


def _make_target(domain: str = "example.com", platform: str | None = None) -> MagicMock:
    t = MagicMock()
    t.domain = domain
    t.platform = platform
    return t


def _valid_json_response(**overrides) -> str:
    data = {
        "score": 75,
        "confidence": "likely",
        "exploitation_difficulty": "medium",
        "severity": "high",
        "reasoning": "Exposed admin panel without authentication.",
        "false_positive_risk": "low",
    }
    data.update(overrides)
    return json.dumps(data)


class TestAIClassifierValidResponse:
    def test_returns_finding_score(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response()

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert isinstance(result, FindingScore)

    def test_score_from_response(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(score=82)

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is not None
        assert result.score == 82

    def test_classifier_used_contains_provider_name(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response()
        type(provider).__name__ = "AnthropicProvider"

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is not None
        assert result.classifier_used.startswith("ai:")

    def test_ai_reasoning_populated(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(reasoning="Critical admin endpoint.")

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is not None
        assert result.ai_reasoning == "Critical admin endpoint."

    def test_severity_overridden(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(severity="critical")

        result = AIClassifier(provider).classify(_make_finding(severity="medium"), _make_target())

        assert result is not None
        assert result.severity == "critical"

    def test_exploitation_difficulty_set(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(exploitation_difficulty="trivial")

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is not None
        assert result.exploitation_difficulty == "trivial"

    def test_report_draft_generated_when_score_gte_60(self) -> None:
        provider = MagicMock()
        provider.complete.side_effect = [
            _valid_json_response(score=70),
            "## Report\n\nThis is the draft.",
        ]

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is not None
        assert result.ai_report_draft == "## Report\n\nThis is the draft."
        assert provider.complete.call_count == 2

    def test_report_draft_not_generated_when_score_lt_60(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(score=55)

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is not None
        assert result.ai_report_draft is None
        assert provider.complete.call_count == 1

    def test_strips_markdown_code_fences(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = (
            "```json\n" + _valid_json_response() + "\n```"
        )

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is not None
        assert result.score == 75


class TestAIClassifierInvalidResponse:
    def test_returns_none_on_invalid_json(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = "this is not json"

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None

    def test_returns_none_on_missing_score(self) -> None:
        provider = MagicMock()
        data = json.loads(_valid_json_response())
        del data["score"]
        provider.complete.return_value = json.dumps(data)

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None

    def test_returns_none_on_invalid_score_range(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(score=150)

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None

    def test_returns_none_on_invalid_confidence(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(confidence="maybe")

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None

    def test_returns_none_on_invalid_difficulty(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(exploitation_difficulty="impossible")

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None

    def test_returns_none_on_invalid_severity(self) -> None:
        provider = MagicMock()
        provider.complete.return_value = _valid_json_response(severity="blocker")

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None

    def test_returns_none_when_provider_raises_exception(self) -> None:
        provider = MagicMock()
        provider.complete.side_effect = RuntimeError("connection refused")

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None

    def test_returns_none_when_provider_times_out(self) -> None:
        import socket

        provider = MagicMock()
        provider.complete.side_effect = TimeoutError("timed out")

        result = AIClassifier(provider).classify(_make_finding(), _make_target())

        assert result is None
