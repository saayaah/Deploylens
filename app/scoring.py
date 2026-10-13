"""Deterministic readiness scoring.

  possible = sum of severity weights over APPLICABLE checks
  earned   = sum of weight * credit, where credit is
             PASS = 1.0, WARN = 0.5, UNVERIFIED = 0.5, FAIL = 0.0
  score    = round(100 * earned / possible)

NOT_APPLICABLE checks are excluded from both sides, so they neither reward nor penalize.
The score measures readiness against DeployLens's implemented checks only.
It does not guarantee security or successful deployment.
"""
from __future__ import annotations

from .rules import FAIL, NOT_APPLICABLE, PASS, UNVERIFIED, WARN

SEVERITY_WEIGHTS = {"critical": 10, "high": 6, "medium": 4, "low": 2}
CREDIT = {PASS: 1.0, WARN: 0.5, UNVERIFIED: 0.5, FAIL: 0.0}

LABELS = [
    (90, "Strong readiness"),
    (75, "Good readiness with improvements"),
    (50, "Needs attention"),
    (0, "Significant improvements required"),
]


def label_for(score: int) -> str:
    return next(label for threshold, label in LABELS if score >= threshold)


def compute_score(findings: list[dict]) -> tuple[int | None, str | None, dict]:
    """Return (score, label, breakdown). score is None when nothing was applicable."""
    possible = 0
    earned = 0.0
    for f in findings:
        if f["status"] == NOT_APPLICABLE:
            continue
        w = SEVERITY_WEIGHTS[f["severity"]]
        possible += w
        earned += w * CREDIT[f["status"]]
    if possible == 0:
        return None, None, {"possible_points": 0, "earned_points": 0.0}
    score = round(100 * earned / possible)
    label = label_for(score)
    return score, label, {"possible_points": possible, "earned_points": round(earned, 2)}


METHOD_TEXT = (
    "Each applicable check carries a weight by severity: critical 10, high 6, medium 4, low 2. "
    "A PASS earns full weight, a WARN or UNVERIFIED earns half, and a FAIL earns none. "
    "The score is earned weight divided by possible weight, scaled to 100 and rounded. "
    "Checks that do not apply are excluded from both totals."
)
