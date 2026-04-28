"""Arq background worker for async audit processing.

Run standalone:  python -m arq webapp.worker.WorkerSettings
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from arq.connections import RedisSettings

# Ensure project root is on sys.path so engine modules resolve
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _write_status(results_dir: Path, status: str, progress: str,
                  started_at: str, completed_at: str | None = None) -> None:
    """Atomically write scan_status.json."""
    payload: dict = {
        "status": status,
        "progress": progress,
        "started_at": started_at,
    }
    if completed_at is not None:
        payload["completed_at"] = completed_at
    tmp = results_dir / "scan_status.json.tmp"
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(results_dir / "scan_status.json")


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Task function
# ---------------------------------------------------------------------------

async def run_audit(
    ctx: dict,
    audit_id: str,
    uploaded_paths: list,
    license_key: str,
    user_id: str,
) -> None:
    """Execute a full audit scan in the background.

    Mirrors the orchestration logic from the ``/audit`` POST handler in
    ``main.py`` but writes progress to ``scan_status.json`` at each phase.
    """
    from webapp.config import RESULTS_DIR, UPLOAD_DIR, LOGO_PATH
    from license_manager import (
        LicenseManager,
        AI_COPILOT,
        ATTACK_GRAPH,
        BRANDED_REPORTS,
    )
    from heuristic_scanner import (
        HeuristicFinding,
        RULE_CATEGORIES,
        HEURISTIC_RULES,
        scan_target,
    )
    from report_generator import (
        AuditReport,
        Finding,
        create_audit_report,
        generate_html_report,
        generate_markdown_report,
        save_sarif_report,
    )
    try:
        from report_generator import generate_pdf_report as _generate_pdf_report_impl

        def generate_pdf_report(report: AuditReport, output_path: str, logo_path: str | None = None) -> None:
            _generate_pdf_report_impl(report, output_path, logo_path=logo_path)
    except (ImportError, AttributeError):
        def generate_pdf_report(report: AuditReport, output_path: str, logo_path: str | None = None) -> None:
            raise RuntimeError("generate_pdf_report is not available")

    from attack_graph import build_graph, export_graph_json
    from visualizer import generate_attack_graph_html

    results_dir = RESULTS_DIR / audit_id
    upload_dir = UPLOAD_DIR / audit_id
    results_dir.mkdir(parents=True, exist_ok=True)

    started_at = _iso_now()
    _write_status(results_dir, "running", "Starting scan...", started_at)

    _license = LicenseManager()

    # --- helpers (same as main.py) ---
    def _heuristic_finding_to_finding(hf: HeuristicFinding) -> Finding:
        return Finding(
            rule_id=hf.rule_id,
            severity=hf.severity,
            category="Heuristic",
            title=hf.rule_id.replace("_", " ").title(),
            description=hf.message,
            file=hf.file,
            line_no=hf.line_no,
            code_snippet=hf.line_text,
            remediation="",
            references=[],
        )

    def _count_lines(path: str) -> int:
        with open(path, encoding="utf-8", errors="ignore") as f:
            return sum(1 for _ in f)

    try:
        # 1. Heuristic scan
        _write_status(results_dir, "running", "Running heuristic scan...", started_at)
        findings: List[Finding] = []
        for fp_str in uploaded_paths:
            heuristic_findings = scan_target(fp_str)
            for hf in heuristic_findings:
                findings.append(_heuristic_finding_to_finding(hf))
        heuristic_count = len(findings)

        # 2. Slither analysis
        _write_status(results_dir, "running", "Running Slither analysis...", started_at)
        from webapp.main import run_slither_analysis
        slither_findings: list[Finding] = []
        slither_status = "skipped"
        for fp_str in uploaded_paths:
            if fp_str.endswith(".sol"):
                sf, status = run_slither_analysis(fp_str)
                slither_findings.extend(sf)
                if status != "completed" and slither_status == "skipped":
                    slither_status = status
                elif status == "completed":
                    slither_status = "completed"
        findings.extend(slither_findings)

        # 3. AI Copilot
        _write_status(results_dir, "running", "Running AI Copilot analysis...", started_at)
        from webapp.main import run_ai_copilot
        ai_summary = ""
        ai_status = "skipped"
        if findings and _license.check_pro_feature(AI_COPILOT):
            ai_summary, ai_status = run_ai_copilot(findings, "")
        elif findings:
            ai_status = "pro_required"

        if ai_summary:
            ai_path = results_dir / "ai_summary.txt"
            ai_path.write_text(ai_summary, encoding="utf-8")

        # 4. Report generation
        _write_status(results_dir, "running", "Generating reports...", started_at)

        # Derive project_name from scan_status or upload dir
        project_name = audit_id  # fallback
        # Check if scan_meta was pre-seeded by the handler
        pre_meta_path = results_dir / "scan_meta.json"
        if pre_meta_path.exists():
            try:
                pre_meta = json.loads(pre_meta_path.read_text())
                project_name = pre_meta.get("project_name", project_name)
            except Exception:
                pass

        report = create_audit_report(
            project_name=project_name,
            target_path=str(upload_dir),
            findings=findings,
        )

        # Save findings JSON
        findings_data = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "file": f.file,
                "line_no": f.line_no,
                "code_snippet": f.code_snippet,
                "remediation": f.remediation,
                "references": f.references,
                "cwe": f.cwe,
                "owasp": f.owasp,
            }
            for f in findings
        ]
        findings_path = results_dir / "findings.json"
        findings_path.write_text(json.dumps(findings_data, indent=2), encoding="utf-8")

        # HTML report (PRO)
        html_path: Path | None = results_dir / "report.html"
        if _license.check_pro_feature(BRANDED_REPORTS):
            generate_html_report(
                report, str(html_path),
                logo_path=str(LOGO_PATH) if LOGO_PATH.exists() else None,
            )
            pdf_path = results_dir / "report.pdf"
            try:
                generate_pdf_report(
                    report, str(pdf_path),
                    logo_path=str(LOGO_PATH) if LOGO_PATH.exists() else None,
                )
            except Exception:
                pass
        else:
            html_path = None

        # Markdown
        md_path = results_dir / "report.md"
        generate_markdown_report(report, str(md_path))

        # SARIF
        sarif_path = results_dir / "report.sarif"
        sarif_metadata = {
            "project_name": project_name,
            "target_path": str(upload_dir),
            "timestamp": report.timestamp,
        }
        save_sarif_report(findings, str(sarif_path), sarif_metadata)

        # 5. Attack graph
        _write_status(results_dir, "running", "Generating attack graph...", started_at)
        attack_graph_generated = False
        if findings and _license.check_pro_feature(ATTACK_GRAPH):
            try:
                finding_dicts = [
                    {
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "file": f.file,
                        "line_no": f.line_no,
                        "message": f.description,
                    }
                    for f in findings
                ]
                graph = build_graph(finding_dicts, source_files=uploaded_paths)
                graph_json = export_graph_json(graph)
                attack_graph_path = results_dir / "attack_graph.html"
                generate_attack_graph_html(
                    graph_json,
                    str(attack_graph_path),
                    f"Attack Path Analysis - {project_name}",
                    logo_path=str(LOGO_PATH) if LOGO_PATH.exists() else None,
                )
                attack_graph_generated = True
            except Exception:
                pass

        # 6. Save scan metadata
        findings_per_category: dict[str, int] = {}
        for cat, rule_ids in RULE_CATEGORIES.items():
            findings_per_category[cat] = sum(
                1 for fd in findings_data if fd["rule_id"] in rule_ids
            )

        ai_copilot_analyzer: dict = {
            "name": "AI Audit Copilot",
            "status": ai_status,
            "findings_count": 0,
        }
        if ai_status == "pro_required":
            ai_copilot_analyzer["pro_only"] = True

        analyzers_list = [
            {
                "name": "Heuristic Pattern Scanner",
                "status": "completed",
                "patterns_checked": len(HEURISTIC_RULES),
                "categories": {
                    cat: {
                        "patterns": len(rules),
                        "findings": findings_per_category.get(cat, 0),
                    }
                    for cat, rules in RULE_CATEGORIES.items()
                },
                "findings_count": heuristic_count,
            },
            {
                "name": "Slither Static Analysis",
                "status": slither_status,
                "findings_count": len(slither_findings),
            },
            ai_copilot_analyzer,
        ]
        if findings:
            ag_status = (
                "completed" if attack_graph_generated
                else ("pro_required"
                      if not _license.check_pro_feature(ATTACK_GRAPH)
                      else "skipped")
            )
            attack_graph_analyzer: dict = {
                "name": "Attack Graph Generator",
                "status": ag_status,
                "findings_count": 0,
            }
            if attack_graph_analyzer["status"] == "pro_required":
                attack_graph_analyzer["pro_only"] = True
            analyzers_list.append(attack_graph_analyzer)

        scan_meta = {
            "owner_user_id": user_id or None,
            "project_name": project_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(uploaded_paths),
            "total_source_lines": sum(_count_lines(fp) for fp in uploaded_paths),
            "analyzers": analyzers_list,
            "rules_triggered": sorted(str(fd["rule_id"]) for fd in findings_data),
        }
        meta_path = results_dir / "scan_meta.json"
        meta_path.write_text(json.dumps(scan_meta, indent=2), encoding="utf-8")

        # Done!
        _write_status(results_dir, "complete", "Scan complete", started_at, _iso_now())
        logger.info("Audit %s completed successfully", audit_id)

    except Exception as exc:
        logger.exception("Audit %s failed: %s", audit_id, exc)
        _write_status(
            results_dir, "failed",
            f"Error: {exc}",
            started_at, _iso_now(),
        )


# ---------------------------------------------------------------------------
# Worker settings
# ---------------------------------------------------------------------------

def _redis_settings() -> RedisSettings:
    dsn = os.environ.get("REDIS_URL", "redis://localhost:6379")
    return RedisSettings.from_dsn(dsn)


class WorkerSettings:
    """arq worker configuration.

    Start with:  python -m arq webapp.worker.WorkerSettings
    """

    functions = [run_audit]
    redis_settings = _redis_settings()
    max_jobs = 4
    job_timeout = 600  # 10 minutes per audit
