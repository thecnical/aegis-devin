from __future__ import annotations

import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Callable

import httpx

from aegis.core.advanced_web_checks import run_advanced_authorized_checks
from aegis.core.db_manager import DatabaseManager
from aegis.core.signal_quality import merge_duplicate_findings, score_confidence

STAGES = ["discovery", "fingerprint", "mapping", "vuln_checks", "validation", "report_prep"]


class WorkflowEngine:
    def __init__(
        self,
        db: DatabaseManager,
        workspace: str,
        profile: str,
        *,
        workers: int = 4,
        rate_limit_per_sec: int = 5,
        retries: int = 1,
        require_cross_validation: bool = False,
        dangerous_checks: bool = False,
    ) -> None:
        self.db = db
        self.workspace = workspace
        self.profile = profile
        self.workers = max(1, workers)
        self.rate_limit_per_sec = max(1, rate_limit_per_sec)
        self.retries = max(0, retries)
        self.require_cross_validation = require_cross_validation
        self.dangerous_checks = dangerous_checks
        self.checkpoint_dir = Path("data/workflows")
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)

    def _checkpoint_file(self, run_id: str) -> Path:
        return self.checkpoint_dir / f"{run_id}.json"

    def _save_checkpoint(self, run_id: str, stage: str, state: dict) -> None:
        payload = {"run_id": run_id, "stage": stage, "state": state, "updated_at": int(time.time())}
        self._checkpoint_file(run_id).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        self.db.upsert_workflow_run(run_id, state.get("target", ""), self.profile, "running", stage)

    def _load_checkpoint(self, run_id: str) -> dict | None:
        path = self._checkpoint_file(run_id)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _run_stage_with_retry(self, stage: str, fn: Callable[[], dict], run_id: str) -> dict:
        last_error = ""
        for attempt in range(self.retries + 1):
            try:
                self.db.add_workflow_event(run_id, stage, "running", f"attempt={attempt + 1}")
                result = fn()
                self.db.add_workflow_event(run_id, stage, "ok", "")
                return result
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                self.db.add_workflow_event(run_id, stage, "failed", last_error)
                if attempt >= self.retries:
                    return {"error": last_error}
        return {"error": last_error}

    def run(self, target: str, resume_run_id: str | None = None) -> dict:
        run_id = resume_run_id or str(uuid.uuid4())
        state: dict = {"target": target, "findings": [], "notes": []}
        start_idx = 0
        loaded = self._load_checkpoint(run_id) if resume_run_id else None
        if loaded:
            state = loaded.get("state", state)
            stage = loaded.get("stage", STAGES[0])
            if stage in STAGES:
                start_idx = STAGES.index(stage) + 1
        self.db.upsert_workflow_run(run_id, target, self.profile, "running", STAGES[start_idx - 1] if start_idx else "")
        for stage in STAGES[start_idx:]:
            handler = getattr(self, f"_stage_{stage}")
            out = self._run_stage_with_retry(stage, lambda: handler(target, state), run_id)
            if out.get("error"):
                state.setdefault("errors", []).append({"stage": stage, "error": out["error"]})
                # failure isolation: continue to next stage
            else:
                state.update(out)
            self._save_checkpoint(run_id, stage, state)
        self.db.upsert_workflow_run(run_id, target, self.profile, "completed", STAGES[-1])
        self.db.add_audit_log(self.workspace, "workflow-engine", "workflow_completed", f"run_id={run_id} target={target}")
        return {"run_id": run_id, "state": state}

    def _parallel_fetch(self, urls: list[str]) -> list[tuple[str, int, str]]:
        interval = 1.0 / float(self.rate_limit_per_sec)
        out: list[tuple[str, int, str]] = []
        with ThreadPoolExecutor(max_workers=self.workers) as pool:
            futures = {}
            for u in urls:
                time.sleep(interval)
                futures[pool.submit(self._fetch_url, u)] = u
            for fut in as_completed(futures):
                out.append(fut.result())
        return out

    def _fetch_url(self, url: str) -> tuple[str, int, str]:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:  # noqa: S501
            r = client.get(url)
            return (url, r.status_code, r.text[:400])

    def _stage_discovery(self, target: str, state: dict) -> dict:
        candidates = [target.rstrip("/") + p for p in ["/", "/robots.txt", "/sitemap.xml", "/.well-known/security.txt"]]
        results = self._parallel_fetch(candidates)
        notes = [f"{u} status={s}" for (u, s, _) in results]
        return {"discovery": results, "notes": state.get("notes", []) + notes}

    def _stage_fingerprint(self, target: str, state: dict) -> dict:
        with httpx.Client(timeout=10, follow_redirects=True, verify=False) as client:  # noqa: S501
            r = client.get(target)
        return {"fingerprint": {"server": r.headers.get("server", ""), "powered_by": r.headers.get("x-powered-by", "")}}

    def _stage_mapping(self, target: str, state: dict) -> dict:
        paths = ["/login", "/admin", "/api", "/graphql", "/swagger", "/openapi.json"]
        results = self._parallel_fetch([target.rstrip("/") + p for p in paths])
        mapped = [u for (u, status, _) in results if status < 500]
        return {"mapping": mapped}

    def _stage_vuln_checks(self, target: str, state: dict) -> dict:
        findings = run_advanced_authorized_checks(target, include_dangerous=self.dangerous_checks)
        return {"findings": state.get("findings", []) + findings}

    def _stage_validation(self, target: str, state: dict) -> dict:
        merged = merge_duplicate_findings(state.get("findings", []))
        validated: list[dict] = []
        seen_by_title: dict[str, int] = {}
        for finding in merged:
            title = str(finding.get("title", ""))
            seen_by_title[title] = seen_by_title.get(title, 0) + 1
        for finding in merged:
            score = score_confidence(
                finding,
                validation_count=seen_by_title.get(str(finding.get("title", "")), 1) - 1,
                require_cross_validation=self.require_cross_validation,
            )
            row = dict(finding)
            row["confidence_score"] = score.confidence_score
            row["confidence_rationale"] = score.confidence_rationale
            row["validation_count"] = score.validation_count
            row["canonical_hash"] = score.canonical_hash
            validated.append(row)
        return {"findings": validated}

    def _stage_report_prep(self, target: str, state: dict) -> dict:
        counts: dict[str, int] = {}
        for f in state.get("findings", []):
            sev = str(f.get("severity", "info")).lower()
            counts[sev] = counts.get(sev, 0) + 1
            self.db.add_finding(
                target_id=self.db.upsert_target(target),
                host_id=None,
                port_id=None,
                title=str(f.get("title", "workflow finding")),
                severity=sev,
                category=str(f.get("category", "workflow")),
                description=str(f.get("description", "")),
                source=str(f.get("source", "workflow")),
                confidence_score=float(f.get("confidence_score", 0)),
                confidence_rationale=str(f.get("confidence_rationale", "")),
                validation_count=int(f.get("validation_count", 0)),
                canonical_hash=str(f.get("canonical_hash", "")),
                merged_from=str(f.get("merged_from", "")),
                remediation=str(f.get("remediation", "")),
                reproducibility=str(f.get("reproducibility", "")),
            )
        return {"report_prep": {"severity_counts": counts, "finding_count": len(state.get("findings", []))}}
