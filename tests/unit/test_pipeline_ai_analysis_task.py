"""Tests for run_ai_analysis Celery task."""

from __future__ import annotations

import datetime
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from core.db.base import Base
from core.db.models import Finding, SystemSetting, Target
from core.pipeline import tasks


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


def _add_findings(sf: sessionmaker[Session], target_id: int, count: int, scores: list[int] | None = None) -> None:
    with sf() as session:
        for i in range(count):
            f = Finding(
                target_id=target_id,
                type="test-vuln",
                title=f"Finding {i}",
                severity="medium",
                auto_score=scores[i] if scores else (50 - i * 5),
                status="new",
            )
            session.add(f)
        session.commit()


def _noop_classify(finding, target, session, force_reanalyze: bool = False) -> None:
    """Stub that marks findings as heuristic without calling AI."""
    finding.classifier_used = "heuristic"
    finding.auto_score = finding.auto_score or 30
    finding.confidence = "possible"
    finding.confidence_note = "test"


class TestRunAiAnalysisBasic:
    def test_classifies_all_new_findings(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 3)

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            result = tasks.run_ai_analysis(target_id)

        assert result["classified"] == 3

        with sf() as session:
            target = session.get(Target, target_id)
            assert target.status == "ready_for_review"
            findings = session.query(Finding).filter_by(target_id=target_id).all()
            assert all(f.classifier_used == "heuristic" for f in findings)

    def test_transitions_status_to_ready_for_review(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 1)

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            tasks.run_ai_analysis(target_id)

        with sf() as session:
            assert session.get(Target, target_id).status == "ready_for_review"


class TestRunAiAnalysisLimit:
    def test_respects_explicit_limit(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 5, scores=[90, 80, 70, 60, 50])

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            result = tasks.run_ai_analysis(target_id, limit=2)

        assert result["classified"] == 2

        with sf() as session:
            classified = session.query(Finding).filter(
                Finding.target_id == target_id,
                Finding.classifier_used.isnot(None),
            ).count()
            unclassified = session.query(Finding).filter(
                Finding.target_id == target_id,
                Finding.classifier_used.is_(None),
            ).count()

        assert classified == 2
        assert unclassified == 3

    def test_limit_2_processes_highest_scoring_first(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 3, scores=[30, 90, 60])

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            tasks.run_ai_analysis(target_id, limit=2)

        with sf() as session:
            classified = (
                session.query(Finding)
                .filter(Finding.classifier_used.isnot(None))
                .all()
            )
            classified_scores = sorted([f.auto_score for f in classified], reverse=True)

        assert classified_scores == [90, 60]

    def test_reads_limit_from_system_settings(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 4)

        with sf() as session:
            session.add(SystemSetting(
                key="ai_analysis_limit",
                value="2",
                updated_at=datetime.datetime.utcnow(),
            ))
            session.commit()

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            result = tasks.run_ai_analysis(target_id)

        assert result["classified"] == 2

    def test_no_limit_processes_all_when_setting_absent(self, monkeypatch) -> None:
        sf = _session_factory()
        monkeypatch.setattr(tasks, "SessionLocal", sf)
        target_id = _add_target(sf)
        _add_findings(sf, target_id, 5)

        with patch("core.analysis.classifier.classify_finding", side_effect=_noop_classify):
            result = tasks.run_ai_analysis(target_id)

        assert result["classified"] == 5
