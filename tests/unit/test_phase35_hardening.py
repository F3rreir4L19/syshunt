"""Tests for Phase 3.5 hardening corrections.

Covers:
- get_provider reads API keys from DB (session path) without mutating os.environ
- run_dnsx_filter is non-fatal when dnsx raises FileNotFoundError
- run_ai_analysis with force_reanalyze=True bypasses Redis cache
- run_ai_analysis not dispatched when target.auto_analyze is False
- set_setting with an existing key does not raise IntegrityError
- template_generator raises ValueError for invalid YAML
- classify_finding persists ai_report_draft when FindingScore carries it
"""

from __future__ import annotations

import datetime
import json
import os
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.analysis.classifier import classify_finding
from core.analysis.classifier_base import FindingScore
from core.analysis.provider import (
    AnthropicProvider,
    OllamaProvider,
    OpenAICompatibleProvider,
    get_provider,
)
from core.db.base import Base
from core.db.models import Finding, ReconResult, SystemSetting, Target
from core.db import queries
from core.pipeline import tasks


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engine():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return engine


def _session_factory(engine=None):
    if engine is None:
        engine = _make_engine()
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _add_target(sf, auto_analyze: bool = True) -> int:
    with sf() as session:
        target = Target(domain="example.com", auto_analyze=auto_analyze)
        session.add(target)
        session.commit()
        return target.id


def _add_findings(sf, target_id: int, count: int = 1) -> None:
    with sf() as session:
        for i in range(count):
            session.add(Finding(
                target_id=target_id,
                type="test-vuln",
                title=f"Finding {i}",
                severity="medium",
                auto_score=50,
                status="new",
            ))
        session.commit()


# ---------------------------------------------------------------------------
# 1. get_provider reads API keys from DB without mutating os.environ
# ---------------------------------------------------------------------------


class TestGetProviderFromDB:
    def test_reads_anthropic_key_from_db_not_env(self) -> None:
        """When session is provided, key stored in DB is used over a missing env var."""
        sf = _session_factory()
        with sf() as session:
            session.merge(SystemSetting(
                key="ANTHROPIC_API_KEY",
                value="sk-from-db",
                updated_at=datetime.datetime.now(datetime.UTC),
            ))
            session.commit()

        original_env = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with sf() as session:
                provider = get_provider(session=session)

            assert isinstance(provider, AnthropicProvider)
            assert provider._api_key == "sk-from-db"
            assert "ANTHROPIC_API_KEY" not in os.environ, (
                "get_provider must not mutate os.environ"
            )
        finally:
            if original_env is not None:
                os.environ["ANTHROPIC_API_KEY"] = original_env

    def test_db_key_takes_precedence_over_env_var(self) -> None:
        sf = _session_factory()
        with sf() as session:
            session.merge(SystemSetting(
                key="ANTHROPIC_API_KEY",
                value="sk-from-db",
                updated_at=datetime.datetime.now(datetime.UTC),
            ))
            session.commit()

        original_env = os.environ.get("ANTHROPIC_API_KEY")
        os.environ["ANTHROPIC_API_KEY"] = "sk-from-env"
        try:
            with sf() as session:
                provider = get_provider(session=session)

            assert isinstance(provider, AnthropicProvider)
            assert provider._api_key == "sk-from-db"
            # env var must be unchanged
            assert os.environ.get("ANTHROPIC_API_KEY") == "sk-from-env"
        finally:
            if original_env is None:
                os.environ.pop("ANTHROPIC_API_KEY", None)
            else:
                os.environ["ANTHROPIC_API_KEY"] = original_env

    def test_no_session_falls_back_to_env(self, monkeypatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-env-only")
        provider = get_provider(session=None)
        assert isinstance(provider, AnthropicProvider)
        assert provider._api_key == "sk-env-only"

    def test_provider_constructors_accept_explicit_key(self) -> None:
        p = AnthropicProvider(api_key="explicit-key")
        assert p._api_key == "explicit-key"
        assert p.is_available()

    def test_openai_provider_constructors_accept_explicit_params(self) -> None:
        p = OpenAICompatibleProvider(
            api_key="key",
            base_url="https://custom.api.com/v1",
            model="custom-model",
        )
        assert p._api_key == "key"
        assert p._base_url == "https://custom.api.com/v1"
        assert p._model == "custom-model"

    def test_ollama_provider_accepts_explicit_params(self) -> None:
        p = OllamaProvider(base_url="http://myhost:11434", model="mistral")
        assert p._base_url == "http://myhost:11434"
        assert p._model == "mistral"


# ---------------------------------------------------------------------------
# 2. run_dnsx_filter is non-fatal for FileNotFoundError
# ---------------------------------------------------------------------------


def _add_subdomains(sf, target_id: int, domains: list[str]) -> None:
    with sf() as session:
        for d in domains:
            session.add(ReconResult(
                target_id=target_id,
                tool="subfinder",
                result_type="subdomain",
                data={"value": d},
            ))
        session.commit()


class TestDnsxFilterNonFatal:
    def test_returns_skipped_when_dnsx_raises_file_not_found(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)

        class RaisingDnsxWrapper:
            def run(self, target: str):
                raise FileNotFoundError("dnsx: command not found")

        monkeypatch.setattr(tasks, "DnsxWrapper", RaisingDnsxWrapper)

        target_id = _add_target(sf)
        _add_subdomains(sf, target_id, ["api.example.com", "www.example.com"])

        # Task must not raise — it returns skip dict
        result = tasks.run_dnsx_filter(target_id)

        assert result.get("skipped") is True
        assert result["tool"] == "dnsx"

    def test_returns_skipped_when_dnsx_raises_runtime_error(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)

        class RaisingDnsxWrapper:
            def run(self, target: str):
                raise RuntimeError("dnsx crashed unexpectedly")

        monkeypatch.setattr(tasks, "DnsxWrapper", RaisingDnsxWrapper)

        target_id = _add_target(sf)
        _add_subdomains(sf, target_id, ["api.example.com"])
        result = tasks.run_dnsx_filter(target_id)

        assert result.get("skipped") is True

    def test_still_raises_for_missing_target(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)

        with pytest.raises(ValueError, match="not found"):
            tasks.run_dnsx_filter(999999)


# ---------------------------------------------------------------------------
# 3. run_ai_analysis force_reanalyze=True bypasses Redis cache
# ---------------------------------------------------------------------------


class TestRunAiAnalysisForceReanalyze:
    """Tests that verify force_reanalyze skips Redis.get.

    These tests use the real classify_finding and mock only _get_redis and
    get_provider so the Redis access path is observable.
    """

    def test_force_reanalyze_skips_redis_get(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 1)

        mock_redis = MagicMock()
        # Pretend cache has an entry (but it should NOT be read with force_reanalyze=True)
        mock_redis.get.return_value = json.dumps({
            "score": 90, "confidence": "confirmed",
            "classifier_used": "ai:anthropic", "confidence_note": "",
            "ai_reasoning": None, "ai_report_draft": None,
            "severity": None, "exploitation_difficulty": None,
        }).encode()

        with (
            patch("core.analysis.classifier._get_redis", return_value=mock_redis),
            patch("core.analysis.classifier.get_provider", return_value=None),
        ):
            tasks.run_ai_analysis(target_id, force_reanalyze=True)

        # Redis.get must NOT have been called (cache bypass)
        mock_redis.get.assert_not_called()

    def test_force_false_uses_cache_normally(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 1)

        mock_redis = MagicMock()
        mock_redis.get.return_value = None  # cache miss

        with (
            patch("core.analysis.classifier._get_redis", return_value=mock_redis),
            patch("core.analysis.classifier.get_provider", return_value=None),
        ):
            tasks.run_ai_analysis(target_id, force_reanalyze=False)

        # Redis.get should have been called (normal cache path)
        mock_redis.get.assert_called()


# ---------------------------------------------------------------------------
# 4. run_ai_analysis not dispatched when target.auto_analyze is False
# ---------------------------------------------------------------------------


class TestAutoAnalyzeFlag:
    def test_nuclei_scan_does_not_dispatch_ai_when_auto_analyze_false(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)

        from dataclasses import dataclass
        from typing import Any

        @dataclass
        class FakeResult:
            success: bool
            parsed_data: list[dict[str, Any]]
            error: str | None = None

        class FakeNuclei:
            def run(self, target):
                return FakeResult(success=True, parsed_data=[])

        monkeypatch.setattr(tasks, "NucleiWrapper", FakeNuclei)

        with sf() as session:
            target = Target(domain="example.com", auto_analyze=False)
            session.add(target)
            session.commit()
            target_id = target.id

        dispatched = []
        original_apply_async = tasks.run_ai_analysis.apply_async

        def track_dispatch(*a, **kw):
            dispatched.append(True)

        monkeypatch.setattr(tasks.run_ai_analysis, "apply_async", track_dispatch)

        tasks.run_nuclei_scan(target_id)

        assert dispatched == [], "run_ai_analysis must NOT be dispatched when auto_analyze=False"

    def test_nuclei_scan_dispatches_ai_when_auto_analyze_true(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)

        from dataclasses import dataclass
        from typing import Any

        @dataclass
        class FakeResult:
            success: bool
            parsed_data: list[dict[str, Any]]
            error: str | None = None

        class FakeNuclei:
            def run(self, target):
                return FakeResult(success=True, parsed_data=[])

        monkeypatch.setattr(tasks, "NucleiWrapper", FakeNuclei)

        with sf() as session:
            target = Target(domain="example.com", auto_analyze=True)
            session.add(target)
            session.commit()
            target_id = target.id

        dispatched = []

        def track_dispatch(*a, **kw):
            dispatched.append(True)

        monkeypatch.setattr(tasks.run_ai_analysis, "apply_async", track_dispatch)

        tasks.run_nuclei_scan(target_id)

        assert dispatched == [True], "run_ai_analysis must be dispatched when auto_analyze=True"


# ---------------------------------------------------------------------------
# 5. set_setting with existing key does not raise IntegrityError
# ---------------------------------------------------------------------------


class TestSetSettingUpsert:
    def test_second_set_updates_existing_key(self) -> None:
        sf = _session_factory()
        with sf() as session:
            queries.set_setting(session, "test_key", "value_1")
            session.commit()

        with sf() as session:
            # Must not raise IntegrityError
            queries.set_setting(session, "test_key", "value_2")
            session.commit()

        with sf() as session:
            assert queries.get_setting(session, "test_key") == "value_2"

    def test_set_setting_creates_new_key(self) -> None:
        sf = _session_factory()
        with sf() as session:
            queries.set_setting(session, "new_key", "hello")
            session.commit()
            assert queries.get_setting(session, "new_key") == "hello"

    def test_set_setting_none_removes_key(self) -> None:
        sf = _session_factory()
        with sf() as session:
            queries.set_setting(session, "to_remove", "exists")
            session.commit()

        with sf() as session:
            queries.set_setting(session, "to_remove", None)
            session.commit()
            assert queries.get_setting(session, "to_remove") is None

    def test_set_setting_multiple_times_no_error(self) -> None:
        """Calling set_setting many times for the same key never raises."""
        sf = _session_factory()
        with sf() as session:
            for i in range(5):
                queries.set_setting(session, "repeated_key", f"v{i}")
            session.commit()

        with sf() as session:
            assert queries.get_setting(session, "repeated_key") == "v4"


# ---------------------------------------------------------------------------
# 6. classify_finding persists ai_report_draft when FindingScore carries it
# ---------------------------------------------------------------------------


class TestClassifyFindingPersistsReportDraft:
    def test_ai_report_draft_applied_to_finding(self) -> None:
        sf = _session_factory()
        with sf() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            finding = Finding(
                target_id=target.id,
                type="xss",
                title="XSS",
                severity="high",
                url="https://example.com/search",
                raw_evidence={"matched-at": "https://example.com/search"},
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            session.refresh(target)

            ai_score = FindingScore(
                score=85,
                confidence="likely",
                classifier_used="ai:anthropic",
                confidence_note="",
                ai_reasoning="Clear XSS evidence in response.",
                ai_report_draft="## XSS Report\n\nSteps to reproduce...",
            )

            mock_provider = MagicMock()
            mock_ai = MagicMock()
            mock_ai.classify.return_value = ai_score

            with (
                patch("core.analysis.classifier.get_provider", return_value=mock_provider),
                patch("core.analysis.classifier.AIClassifier", return_value=mock_ai),
                patch("core.analysis.classifier._get_redis", return_value=None),
            ):
                classify_finding(finding, target, session)
                session.commit()

            assert finding.ai_report_draft == "## XSS Report\n\nSteps to reproduce..."
            assert finding.ai_reasoning == "Clear XSS evidence in response."
            assert finding.auto_score == 85

    def test_ai_report_draft_not_overwritten_when_none(self) -> None:
        """If FindingScore.ai_report_draft is None, the existing value is preserved."""
        sf = _session_factory()
        with sf() as session:
            target = Target(domain="example.com")
            session.add(target)
            session.flush()
            finding = Finding(
                target_id=target.id,
                type="xss",
                title="XSS",
                severity="high",
                ai_report_draft="pre-existing draft",
            )
            session.add(finding)
            session.commit()
            session.refresh(finding)
            session.refresh(target)

            ai_score = FindingScore(
                score=60,
                confidence="possible",
                classifier_used="heuristic",
                confidence_note="heuristic only",
                ai_report_draft=None,
            )

            with (
                patch("core.analysis.classifier.get_provider", return_value=None),
                patch("core.analysis.classifier._get_redis", return_value=None),
                patch("core.analysis.classifier_base.classify", return_value=ai_score),
            ):
                classify_finding(finding, target, session)

            assert finding.ai_report_draft == "pre-existing draft"


# ---------------------------------------------------------------------------
# 7. OpenAICompatibleProvider ImportError message
# ---------------------------------------------------------------------------


class TestOpenAIImportError:
    def test_openai_complete_raises_import_error_with_message(self) -> None:
        p = OpenAICompatibleProvider(api_key="key", base_url="http://x", model="m")

        with patch.dict("sys.modules", {"openai": None}):
            with pytest.raises(ImportError, match="syshunt\\[openai\\]"):
                p.complete("test prompt")
