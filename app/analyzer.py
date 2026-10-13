"""Orchestrates the scan: validate archive, detect technologies, run rules, score, serialize.

Pure function of its input. No disk writes, no code execution, no network.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import context as C
from .context import ProjectContext, detect_technologies
from .redaction import redact
from .rules import CATEGORIES, NOT_APPLICABLE, PASS, FAIL, UNVERIFIED, WARN, RULES
from .scoring import METHOD_TEXT, compute_score
from .zip_safety import read_entries, validate_archive

LIMITATIONS = [
    "Static analysis only. DeployLens never runs the uploaded project, its tests, or its install scripts.",
    "Secret detection uses pattern matching and can report false positives or miss secrets in unusual formats.",
    "No live vulnerability database is consulted, so dependency versions are not checked for known CVEs.",
    "The score reflects DeployLens's implemented checks. It is not a security certification or a guarantee of successful deployment.",
    "Files larger than 1 MB are not inspected.",
]


def analyze_files(files: dict[str, bytes], project_name: str,
                  scanned_at: datetime | None = None) -> dict:
    ctx = ProjectContext(files=files)
    ctx.technologies = detect_technologies(ctx)

    findings = []
    for rule in RULES:
        if not rule.applies(ctx):
            status, evidence, explanation = NOT_APPLICABLE, [], (
                "This rule does not apply to the detected project. " + _na_reason(rule))
        else:
            status, evidence, explanation = rule.check(ctx)
        findings.append({
            "id": rule.id,
            "title": rule.title,
            "category": rule.category,
            "severity": rule.severity,
            "status": status,
            "explanation": redact(explanation),
            "remediation": None if status in (PASS, NOT_APPLICABLE) else rule.remediation,
            "evidence": [redact(e) for e in evidence],
        })

    score, label, breakdown = compute_score(findings)
    applicable = [f for f in findings if f["status"] != NOT_APPLICABLE]
    counts = {
        "total_checks": len(applicable),
        "passed": sum(f["status"] == PASS for f in applicable),
        "warnings": sum(f["status"] == WARN for f in applicable),
        "failed": sum(f["status"] == FAIL for f in applicable),
        "unverified": sum(f["status"] == UNVERIFIED for f in applicable),
        "not_applicable": sum(f["status"] == NOT_APPLICABLE for f in findings),
        "critical_findings": sum(1 for f in applicable if f["severity"] == "critical" and f["status"] in (FAIL, WARN)),
    }
    by_category = {c: {"total": 0, "passed": 0, "warnings": 0, "failed": 0} for c in CATEGORIES}
    for f in applicable:
        cat = by_category[f["category"]]
        cat["total"] += 1
        if f["status"] == PASS:
            cat["passed"] += 1
        elif f["status"] == WARN:
            cat["warnings"] += 1
        elif f["status"] == FAIL:
            cat["failed"] += 1

    ts = (scanned_at or datetime.now(timezone.utc)).isoformat()
    return {
        "project_name": project_name,
        "scanned_at": ts,
        "technologies": ctx.technologies,
        "file_count": len(files),
        "score": score,
        "label": label,
        "score_breakdown": breakdown,
        "method": METHOD_TEXT,
        "counts": counts,
        "categories": by_category,
        "findings": findings,
        "limitations": LIMITATIONS,
    }


def analyze_archive(data: bytes, project_name: str, scanned_at: datetime | None = None) -> dict:
    entries = validate_archive(data)
    files = read_entries(data, entries)
    return analyze_files(files, project_name, scanned_at)


def _na_reason(rule) -> str:
    return f"Not applicable: {rule.not_applicable_when}" if rule.not_applicable_when else ""


def analyze_directory(root: str, project_name: str | None = None,
                      scanned_at: datetime | None = None) -> dict:
    """Analyze a directory on disk (used for the bundled demo). Reads only; never executes."""
    import os

    files: dict[str, bytes] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in ("node_modules", "__pycache__", ".git")]
        for name in filenames:
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if os.path.getsize(full) <= 1024 * 1024:
                with open(full, "rb") as fh:
                    files[rel] = fh.read()
    return analyze_files(files, project_name or os.path.basename(os.path.abspath(root)), scanned_at)
