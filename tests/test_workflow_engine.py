from __future__ import annotations

from aegis.core.workflow_engine import WorkflowEngine


def test_workflow_run_minimal(db) -> None:
    engine = WorkflowEngine(db=db, workspace="default", profile="default", workers=1, retries=0)
    engine._parallel_fetch = lambda urls: [(u, 200, "ok") for u in urls]  # type: ignore[method-assign]
    engine._stage_fingerprint = lambda target, state: {"fingerprint": {"server": "test"}}  # type: ignore[method-assign]
    engine._stage_vuln_checks = lambda target, state: {  # type: ignore[method-assign]
        "findings": [
            {
                "title": "Session cookie missing hardened attributes",
                "severity": "medium",
                "category": "auth-session",
                "description": "x",
                "source": "advanced-web",
                "remediation": "set secure cookies",
                "reproducibility": "GET /",
            }
        ]
    }
    result = engine.run("https://example.com")
    assert result["run_id"]
    assert "report_prep" in result["state"]
    rows = db.get_all_findings()
    assert len(rows) == 1
    assert rows[0]["confidence_score"] is not None
