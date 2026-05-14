from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FindingScore:
    score: int
    confidence: str
    classifier_used: str
    confidence_note: str


_SEVERITY_POINTS: dict[str, int] = {
    "critical": 40,
    "high": 30,
    "medium": 15,
    "low": 5,
    "info": 0,
}

_CATEGORY_POINTS: dict[str, int] = {
    "cve": 20,
    "exposure": 15,
    "misconfiguration": 10,
}

_CONFIDENCE_NOTE = (
    "Score calculated by heuristic classifier (no AI provider configured). "
    "Results may have a high false-positive rate and should be manually reviewed."
)


def classify(
    severity: str,
    template_id: str,
    raw_evidence: dict[str, Any],
    url: str | None,
) -> FindingScore:
    """Score a finding using deterministic heuristics.

    Returns a FindingScore with score already penalised (×0.8) and
    classifier_used set to ``"heuristic"``.

    Args:
        severity: Nuclei severity string (critical/high/medium/low/info).
        template_id: Nuclei template identifier (used to infer category).
        raw_evidence: Raw JSON evidence dict from nuclei.
        url: Matched URL (matched-at), if any.
    """
    score = 0

    # --- severity (up to 40 pts) ---
    score += _SEVERITY_POINTS.get(severity.lower(), 0)

    # --- template category (up to 20 pts) ---
    tid_lower = template_id.lower()
    for category, pts in _CATEGORY_POINTS.items():
        if category in tid_lower:
            score += pts
            break

    # --- evidence quality (up to 25 pts) ---
    matched_at = raw_evidence.get("matched-at") or raw_evidence.get("url")
    if matched_at:
        score += 10
    if "request" in raw_evidence and "response" in raw_evidence:
        score += 15

    # --- URL context ---
    if url:
        url_lower = url.lower()
        if any(p in url_lower for p in ("/admin", "/manage", "/console")):
            score += 8
        elif any(p in url_lower for p in ("/api/", "/v1/", "/v2/")):
            score += 5
        # Staging/dev/test subdomain penalty
        host_part = url_lower.split("/")[2] if url_lower.count("/") >= 2 else url_lower
        if any(part in host_part for part in ("staging.", "dev.", "test.")):
            score -= 10

    # Apply heuristic penalty (×0.8) and clamp to [0, 100]
    penalised = int(score * 0.8)
    final_score = max(0, min(100, penalised))

    return FindingScore(
        score=final_score,
        confidence="possible",
        classifier_used="heuristic",
        confidence_note=_CONFIDENCE_NOTE,
    )
