"""AI-powered finding classifier using an AIProvider backend."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import structlog

from core.analysis.classifier_base import FindingScore
from core.analysis.provider import AIProvider

if TYPE_CHECKING:
    from core.db.models import Finding, Target

_VALID_CONFIDENCE = {"confirmed", "likely", "possible", "unlikely"}
_VALID_DIFFICULTY = {"trivial", "easy", "medium", "hard"}
_VALID_SEVERITY = {"critical", "high", "medium", "low", "info"}

_CLASSIFY_PROMPT = """\
You are a security vulnerability analyst. Analyse the finding below and respond with
a single JSON object — no markdown, no extra text.

## Finding
Type / Template ID: {type}
URL: {url}
Severity (reported by scanner): {severity}
Raw evidence (truncated to 1000 chars):
{evidence}

Target context:
{target_context}

## Required JSON fields
{{
  "score": <integer 0-100>,
  "confidence": "confirmed"|"likely"|"possible"|"unlikely",
  "exploitation_difficulty": "trivial"|"easy"|"medium"|"hard",
  "severity": "critical"|"high"|"medium"|"low"|"info",
  "reasoning": "<one paragraph explaining the score>",
  "false_positive_risk": "low"|"medium"|"high"
}}

Return ONLY the JSON object."""

_REPORT_PROMPT = """\
Write a bug bounty report for the vulnerability below in HackerOne/Bugcrowd format.
Include: Title, Description, Steps to Reproduce, Impact, Recommended Severity,
Suggested CVSS score. Be concise and professional.

Type: {type}
URL: {url}
Severity: {severity}
Score: {score}
Reasoning: {reasoning}
Evidence: {evidence}"""


class AIClassifier:
    """Classify a finding using an AI provider."""

    def __init__(self, provider: AIProvider) -> None:
        self._provider = provider
        self._log = structlog.get_logger().bind(classifier="ai")

    def classify(self, finding: "Finding", target: "Target") -> FindingScore | None:
        """Classify *finding* and return a FindingScore, or None on failure."""
        provider_name = type(self._provider).__name__.lower().replace("provider", "")

        evidence_snippet = json.dumps(finding.raw_evidence, ensure_ascii=False)[:1000]
        target_context = self._build_target_context(target)

        prompt = _CLASSIFY_PROMPT.format(
            type=finding.type,
            url=finding.url or "(unknown)",
            severity=finding.severity,
            evidence=evidence_snippet,
            target_context=target_context,
        )

        try:
            raw_response = self._provider.complete(prompt)
        except Exception as exc:
            self._log.warning("ai_classify_error", error=str(exc), provider=provider_name)
            return None

        parsed = self._parse_classify_response(raw_response)
        if parsed is None:
            return None

        score_value = parsed["score"]
        confidence = parsed["confidence"]
        difficulty = parsed["exploitation_difficulty"]
        severity = parsed["severity"]
        reasoning = parsed.get("reasoning", "")

        report_draft: str | None = None
        if score_value >= 60:
            report_draft = self._generate_report_draft(
                finding=finding,
                score=score_value,
                severity=severity,
                reasoning=reasoning,
                evidence_snippet=evidence_snippet,
            )

        classifier_used = f"ai:{provider_name}"
        return FindingScore(
            score=score_value,
            confidence=confidence,
            classifier_used=classifier_used,
            confidence_note="",
            ai_reasoning=reasoning,
            ai_report_draft=report_draft,
            severity=severity,
            exploitation_difficulty=difficulty,
        )

    def _generate_report_draft(
        self,
        finding: "Finding",
        score: int,
        severity: str,
        reasoning: str,
        evidence_snippet: str,
    ) -> str | None:
        """Make a second API call to generate a report draft. Returns None on failure."""
        prompt = _REPORT_PROMPT.format(
            type=finding.type,
            url=finding.url or "(unknown)",
            severity=severity,
            score=score,
            reasoning=reasoning,
            evidence=evidence_snippet[:500],
        )
        try:
            return self._provider.complete(prompt)
        except Exception as exc:
            self._log.warning("report_draft_error", error=str(exc))
            return None

    def _parse_classify_response(self, raw: str) -> dict[str, Any] | None:
        """Parse and validate the JSON response from the AI. Returns None on failure."""
        raw = raw.strip()
        # Strip markdown code fences if present
        if raw.startswith("```"):
            lines = raw.splitlines()
            raw = "\n".join(
                line for line in lines if not line.startswith("```")
            ).strip()

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            self._log.warning("ai_response_invalid_json", error=str(exc), raw=raw[:200])
            return None

        if not isinstance(data, dict):
            self._log.warning("ai_response_not_dict", raw=raw[:200])
            return None

        score = data.get("score")
        if not isinstance(score, int) or not 0 <= score <= 100:
            self._log.warning("ai_response_invalid_score", score=score)
            return None

        confidence = data.get("confidence", "")
        if confidence not in _VALID_CONFIDENCE:
            self._log.warning("ai_response_invalid_confidence", confidence=confidence)
            return None

        difficulty = data.get("exploitation_difficulty", "")
        if difficulty not in _VALID_DIFFICULTY:
            self._log.warning("ai_response_invalid_difficulty", difficulty=difficulty)
            return None

        severity = data.get("severity", "")
        if severity not in _VALID_SEVERITY:
            self._log.warning("ai_response_invalid_severity", severity=severity)
            return None

        return {
            "score": score,
            "confidence": confidence,
            "exploitation_difficulty": difficulty,
            "severity": severity,
            "reasoning": str(data.get("reasoning", "")),
        }

    @staticmethod
    def _build_target_context(target: "Target") -> str:
        parts = [f"Domain: {target.domain}"]
        if target.platform:
            parts.append(f"Platform: {target.platform}")
        return "; ".join(parts)
