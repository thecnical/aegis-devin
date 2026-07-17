from __future__ import annotations

from aegis.core.signal_quality import canonical_fingerprint, merge_duplicate_findings, score_confidence


def test_canonical_fingerprint_stable() -> None:
    finding = {"title": "X", "source": "nuclei", "target": "https://example.com", "category": "web"}
    assert canonical_fingerprint(finding) == canonical_fingerprint(finding)


def test_merge_duplicate_findings() -> None:
    findings = [
        {"title": "A", "source": "nuclei", "target": "x", "category": "web", "description": "short"},
        {"title": "A", "source": "nuclei", "target": "x", "category": "web", "description": "longer text"},
    ]
    merged = merge_duplicate_findings(findings)
    assert len(merged) == 1
    assert merged[0]["description"] == "longer text"


def test_score_confidence_cross_validation_gate() -> None:
    finding = {"title": "A", "severity": "high", "source": "nuclei"}
    score = score_confidence(finding, validation_count=0, require_cross_validation=True)
    assert score.confidence_score <= 0.45
