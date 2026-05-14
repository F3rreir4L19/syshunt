"""Tests for classify_finding orchestrator and Redis cache in classifier.py."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from core.analysis.classifier import classify_finding
from core.analysis.classifier_base import FindingScore
from core.db.base import Base
from core.db.models import Finding, Target


def _engine_and_factory():
    engine = create_engine("sqlite+pysqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def _make_finding_in_db(session_factory, target_id: int) -> Finding:
    with session_factory() as session:
        finding = Finding(
            target_id=target_id,
            type="exposed-panel",
            title="Exposed panel",
            severity="medium",
            url="https://example.com/admin",
            raw_evidence={"matched-at": "https://example.com/admin"},
        )
        session.add(finding)
        session.commit()
        session.refresh(finding)
        return finding


def _make_target_in_db(session_factory) -> Target:
    with session_factory() as session:
        target = Target(domain="example.com")
        session.add(target)
        session.commit()
        session.refresh(target)
        return target


class TestOrchestratorWithAI:
    def test_uses_ai_when_provider_available(self) -> None:
        sf = _engine_and_factory()
        target = _make_target_in_db(sf)
        finding = _make_finding_in_db(sf, target.id)

        ai_score = FindingScore(
            score=80,
            confidence="likely",
            classifier_used="ai:anthropic",
            confidence_note="",
            ai_reasoning="clear evidence",
        )
        mock_provider = MagicMock()
        mock_ai_classifier = MagicMock()
        mock_ai_classifier.classify.return_value = ai_score

        with sf() as session:
            session.add(finding)
            with (
                patch("core.analysis.classifier.get_provider", return_value=mock_provider),
                patch("core.analysis.classifier.AIClassifier", return_value=mock_ai_classifier),
                patch("core.analysis.classifier._get_redis", return_value=None),
            ):
                classify_finding(finding, target, session)
                session.commit()

        assert finding.classifier_used == "ai:anthropic"
        assert finding.auto_score == 80
        assert finding.confidence == "likely"
        assert finding.ai_reasoning == "clear evidence"

    def test_fallback_to_heuristic_when_ai_returns_none(self) -> None:
        sf = _engine_and_factory()
        target = _make_target_in_db(sf)
        finding = _make_finding_in_db(sf, target.id)

        mock_provider = MagicMock()
        mock_ai_classifier = MagicMock()
        mock_ai_classifier.classify.return_value = None  # AI failed

        with sf() as session:
            session.add(finding)
            with (
                patch("core.analysis.classifier.get_provider", return_value=mock_provider),
                patch("core.analysis.classifier.AIClassifier", return_value=mock_ai_classifier),
                patch("core.analysis.classifier._get_redis", return_value=None),
            ):
                classify_finding(finding, target, session)
                session.commit()

        assert finding.classifier_used == "heuristic"

    def test_uses_heuristic_when_no_provider(self) -> None:
        sf = _engine_and_factory()
        target = _make_target_in_db(sf)
        finding = _make_finding_in_db(sf, target.id)

        with sf() as session:
            session.add(finding)
            with (
                patch("core.analysis.classifier.get_provider", return_value=None),
                patch("core.analysis.classifier._get_redis", return_value=None),
            ):
                classify_finding(finding, target, session)
                session.commit()

        assert finding.classifier_used == "heuristic"

    def test_ai_exception_triggers_heuristic_fallback(self) -> None:
        sf = _engine_and_factory()
        target = _make_target_in_db(sf)
        finding = _make_finding_in_db(sf, target.id)

        mock_provider = MagicMock()
        mock_ai_classifier = MagicMock()
        mock_ai_classifier.classify.side_effect = RuntimeError("API down")

        with sf() as session:
            session.add(finding)
            with (
                patch("core.analysis.classifier.get_provider", return_value=mock_provider),
                patch("core.analysis.classifier.AIClassifier", return_value=mock_ai_classifier),
                patch("core.analysis.classifier._get_redis", return_value=None),
            ):
                classify_finding(finding, target, session)
                session.commit()

        assert finding.classifier_used == "heuristic"


class TestOrchestratorCache:
    def _make_cache_payload(self) -> str:
        return json.dumps({
            "score": 70,
            "confidence": "likely",
            "classifier_used": "ai:anthropic",
            "confidence_note": "",
            "ai_reasoning": "cached reasoning",
            "ai_report_draft": None,
            "severity": "high",
            "exploitation_difficulty": "medium",
        })

    def test_cache_hit_skips_provider(self) -> None:
        sf = _engine_and_factory()
        target = _make_target_in_db(sf)
        finding = _make_finding_in_db(sf, target.id)

        mock_redis = MagicMock()
        mock_redis.get.return_value = self._make_cache_payload().encode()

        with sf() as session:
            session.add(finding)
            with (
                patch("core.analysis.classifier._get_redis", return_value=mock_redis),
                patch("core.analysis.classifier.get_provider") as mock_get_provider,
            ):
                classify_finding(finding, target, session)
                mock_get_provider.assert_not_called()

        assert finding.auto_score == 70
        assert ":cached" in finding.classifier_used

    def test_cache_hit_adds_cached_suffix(self) -> None:
        sf = _engine_and_factory()
        target = _make_target_in_db(sf)
        finding = _make_finding_in_db(sf, target.id)

        mock_redis = MagicMock()
        mock_redis.get.return_value = self._make_cache_payload().encode()

        with sf() as session:
            session.add(finding)
            with (
                patch("core.analysis.classifier._get_redis", return_value=mock_redis),
                patch("core.analysis.classifier.get_provider", return_value=None),
            ):
                classify_finding(finding, target, session)

        assert finding.classifier_used == "ai:anthropic:cached"

    def test_cache_miss_stores_result(self) -> None:
        sf = _engine_and_factory()
        target = _make_target_in_db(sf)
        finding = _make_finding_in_db(sf, target.id)

        mock_redis = MagicMock()
        mock_redis.get.return_value = None  # cache miss

        ai_score = FindingScore(
            score=75,
            confidence="likely",
            classifier_used="ai:openai",
            confidence_note="",
        )
        mock_provider = MagicMock()
        mock_ai_classifier = MagicMock()
        mock_ai_classifier.classify.return_value = ai_score

        with sf() as session:
            session.add(finding)
            with (
                patch("core.analysis.classifier._get_redis", return_value=mock_redis),
                patch("core.analysis.classifier.get_provider", return_value=mock_provider),
                patch("core.analysis.classifier.AIClassifier", return_value=mock_ai_classifier),
            ):
                classify_finding(finding, target, session)

        mock_redis.setex.assert_called_once()
