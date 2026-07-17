from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable


@dataclass
class ScoredFinding:
    finding: dict
    confidence_score: float
    confidence_rationale: str
    canonical_hash: str
    validation_count: int


def canonical_fingerprint(finding: dict) -> str:
    title = str(finding.get("title", "")).strip().lower()
    source = str(finding.get("source", "")).strip().lower()
    target = str(finding.get("target") or finding.get("url") or "").strip().lower()
    category = str(finding.get("category", "")).strip().lower()
    return hashlib.sha256(f"{title}|{source}|{target}|{category}".encode("utf-8")).hexdigest()


def score_confidence(finding: dict, validation_count: int = 0, require_cross_validation: bool = False) -> ScoredFinding:
    severity = str(finding.get("severity", "info")).lower()
    base = 0.35
    if severity in {"high", "critical"}:
        base += 0.2
    if str(finding.get("source", "")).lower() in {"nuclei", "sqlmap", "nmap"}:
        base += 0.15
    evidence_items = finding.get("evidence_count", 0)
    if isinstance(evidence_items, int):
        base += min(0.2, evidence_items * 0.03)
    if validation_count > 0:
        base += min(0.25, validation_count * 0.08)
    if require_cross_validation and validation_count == 0:
        base = min(base, 0.45)
    score = max(0.0, min(1.0, round(base, 2)))
    rationale = (
        f"severity={severity}, source={finding.get('source','unknown')}, "
        f"validation_count={validation_count}, cross_validation_required={require_cross_validation}"
    )
    return ScoredFinding(
        finding=finding,
        confidence_score=score,
        confidence_rationale=rationale,
        canonical_hash=canonical_fingerprint(finding),
        validation_count=validation_count,
    )


def merge_duplicate_findings(findings: Iterable[dict]) -> list[dict]:
    merged: dict[str, dict] = {}
    for finding in findings:
        fp = canonical_fingerprint(finding)
        if fp not in merged:
            merged[fp] = dict(finding)
            merged[fp]["merged_from"] = []
            merged[fp]["canonical_hash"] = fp
            continue
        existing = merged[fp]
        existing["merged_from"].append(str(finding.get("source", "unknown")))
        if len(str(finding.get("description", ""))) > len(str(existing.get("description", ""))):
            existing["description"] = finding.get("description")
    return list(merged.values())
