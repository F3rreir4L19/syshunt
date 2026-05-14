"""Orchestrator: classify a finding using AI (with cache) or heuristic fallback."""

from __future__ import annotations

import hashlib
import json
import os
from typing import TYPE_CHECKING

import structlog

from core.analysis.classifier_base import FindingScore, classify as heuristic_classify
from core.analysis.classifier_ai import AIClassifier
from core.analysis.provider import get_provider

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from core.db.models import Finding, Target

_CACHE_TTL = int(os.getenv("AI_CACHE_TTL", "86400"))  # 24 h default
_CACHE_KEY_PREFIX = "syshunt:analysis:"

_log = structlog.get_logger()


def _analysis_hash(finding: "Finding") -> str:
    raw = (finding.type or "") + (finding.url or "") + str(finding.raw_evidence)[:500]
    return hashlib.sha256(raw.encode()).hexdigest()


def _cache_key(h: str) -> str:
    return f"{_CACHE_KEY_PREFIX}{h}"


def _get_redis():
    """Return a Redis client or None if unavailable."""
    try:
        from redis import Redis
        from redis.exceptions import RedisError

        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
        client = Redis.from_url(redis_url, socket_connect_timeout=0.5)
        client.ping()
        return client
    except Exception:
        return None


def _score_from_cache(client, key: str) -> FindingScore | None:
    try:
        raw = client.get(key)
        if raw is None:
            return None
        data = json.loads(raw)
        return FindingScore(**data)
    except Exception:
        return None


def _score_to_cache(client, key: str, score: FindingScore) -> None:
    try:
        payload = json.dumps({
            "score": score.score,
            "confidence": score.confidence,
            "classifier_used": score.classifier_used,
            "confidence_note": score.confidence_note,
            "ai_reasoning": score.ai_reasoning,
            "ai_report_draft": score.ai_report_draft,
            "severity": score.severity,
            "exploitation_difficulty": score.exploitation_difficulty,
        })
        client.setex(key, _CACHE_TTL, payload)
    except Exception:
        pass


def classify_finding(finding: "Finding", target: "Target", session: "Session") -> None:
    """Classify *finding* in-place: applies score fields and persists via *session*.

    Uses AIClassifier when a provider is available, with Redis-backed caching.
    Falls back to the heuristic classifier on any AI failure.
    """
    log = _log.bind(finding_id=finding.id, target_id=finding.target_id)
    h = _analysis_hash(finding)
    cache_key = _cache_key(h)
    redis = _get_redis()

    score: FindingScore | None = None

    # Check cache first
    if redis is not None:
        cached = _score_from_cache(redis, cache_key)
        if cached is not None:
            score = FindingScore(
                score=cached.score,
                confidence=cached.confidence,
                classifier_used=cached.classifier_used + ":cached",
                confidence_note=cached.confidence_note,
                ai_reasoning=cached.ai_reasoning,
                ai_report_draft=cached.ai_report_draft,
                severity=cached.severity,
                exploitation_difficulty=cached.exploitation_difficulty,
            )
            log.info("classifier_cache_hit", classifier_used=score.classifier_used)

    if score is None:
        provider = get_provider()
        if provider is not None:
            try:
                score = AIClassifier(provider).classify(finding, target)
            except Exception as exc:
                log.warning("ai_classifier_exception", error=str(exc))
                score = None

            if score is None:
                log.warning("ai_classify_failed_fallback_heuristic")
                score = heuristic_classify(
                    finding.severity, finding.type, finding.raw_evidence, finding.url
                )
            elif redis is not None:
                _score_to_cache(redis, cache_key, score)
        else:
            score = heuristic_classify(
                finding.severity, finding.type, finding.raw_evidence, finding.url
            )

    # Apply score fields to the finding
    finding.auto_score = score.score
    finding.confidence = score.confidence
    finding.classifier_used = score.classifier_used
    finding.confidence_note = score.confidence_note
    if score.ai_reasoning is not None:
        finding.ai_reasoning = score.ai_reasoning
    if score.ai_report_draft is not None:
        finding.ai_report_draft = score.ai_report_draft
    if score.severity is not None:
        finding.severity = score.severity
    if score.exploitation_difficulty is not None:
        finding.exploitation_difficulty = score.exploitation_difficulty
