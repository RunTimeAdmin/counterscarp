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


import threading

_user_audit_index_lock = threading.Lock()


def _update_user_audit_index_worker(user_id: str, audit_summary: dict) -> None:
    """Append an audit summary to the per-user audit index (worker variant)."""
    if not user_id:
        return
    index_path = _project_root / "data" / "user_audit_index.json"
    with _user_audit_index_lock:
        data: dict = {}
        if index_path.exists():
            try:
                data = json.loads(index_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}
        user_audits = data.get(user_id, [])
        user_audits.append(audit_summary)
        data[user_id] = user_audits
        index_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp.replace(index_path)


def _send_scan_notification(email: str, audit_id: str, status: str, project_name: str) -> None:
    """Send an email notification on scan completion/failure.

    Wraps in try/except so notification failure never crashes the worker.
    """
    try:
        from webapp.config import (
            SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM,
            NOTIFICATIONS_ENABLED,
        )
        if not NOTIFICATIONS_ENABLED or not email:
            return
        if not SMTP_HOST:
            logger.debug("SMTP not configured — skipping notification")
            return

        import smtplib
        from email.mime.text import MIMEText
        from email.mime.multipart import MIMEMultipart

        subject = f"Counterscarp Scan {status.title()}: {project_name}"
        link = f"https://app.counterscarp.io/results/{audit_id}"
        html_body = (
            f"<p>Your Counterscarp scan for <strong>{project_name}</strong> "
            f"is <strong>{status}</strong>.</p>"
            f'<p><a href="{link}">View results</a></p>'
        )

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_FROM or SMTP_USER or "noreply@counterscarp.io"
        msg["To"] = email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, int(SMTP_PORT or 587)) as server:
            server.starttls()
            if SMTP_USER and SMTP_PASSWORD:
                server.login(SMTP_USER, SMTP_PASSWORD)
            server.sendmail(msg["From"], [email], msg.as_string())

        logger.info("Notification sent to %s for audit %s", email, audit_id)
    except Exception as exc:
        logger.warning("Failed to send notification to %s: %s", email, exc)


def _write_scan_index_worker(results_dir: Path, audit_id: str, findings_data: list, scan_meta: dict) -> None:
    """Write a lightweight scan_index.json for fast dashboard reads."""
    severity_weights = {
        "CRITICAL": 10.0, "HIGH": 5.0,
        "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.1,
    }
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for fd in findings_data:
        sev = fd.get("severity", "INFO").upper()
        key = sev.lower()
        if key in sev_counts:
            sev_counts[key] += 1

    total = len(findings_data)
    if total:
        total_w = sum(severity_weights.get(fd.get("severity", "INFO"), 0) for fd in findings_data)
        max_w = total * severity_weights["CRITICAL"]
        risk_score = round(min(100.0, (total_w / max(max_w, 1.0)) * 100), 1)
    else:
        risk_score = 0.0

    index = {
        "audit_id": audit_id,
        "project_name": scan_meta.get("project_name", "Unknown"),
        "timestamp": scan_meta.get("timestamp", ""),
        "severity_counts": sev_counts,
        "risk_score": risk_score,
        "total_findings": total,
        "has_pdf": (results_dir / "report.pdf").exists(),
        "has_html": (results_dir / "report.html").exists(),
        "has_md": (results_dir / "report.md").exists(),
    }
    index_path = results_dir / "scan_index.json"
    index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")


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
    from webapp.scan_utils import (
        heuristic_finding_to_finding,
        count_lines,
        run_slither_analysis,
        run_ai_copilot,
        serialize_findings,
        generate_reports,
        generate_attack_graph,
        build_analyzers_list,
    )
    from heuristic_scanner import scan_target
    from report_generator import Finding, create_audit_report

    results_dir = RESULTS_DIR / audit_id
    upload_dir = UPLOAD_DIR / audit_id
    results_dir.mkdir(parents=True, exist_ok=True)

    started_at = _iso_now()
    _write_status(results_dir, "running", "Starting scan...", started_at)

    _license = LicenseManager()

    try:
        # 1. Heuristic scan
        _write_status(results_dir, "running", "Running heuristic scan...", started_at)
        findings: List[Finding] = []
        for fp_str in uploaded_paths:
            heuristic_findings = scan_target(fp_str)
            for hf in heuristic_findings:
                findings.append(heuristic_finding_to_finding(hf))
        heuristic_count = len(findings)

        # 2. Slither analysis
        _write_status(results_dir, "running", "Running Slither analysis...", started_at)
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

        # Derive project_name from scan_meta or upload dir
        project_name = audit_id  # fallback
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
        findings_data = serialize_findings(findings)
        findings_path = results_dir / "findings.json"
        findings_path.write_text(json.dumps(findings_data, indent=2), encoding="utf-8")

        # Generate all report formats
        generate_reports(
            report=report,
            findings=findings,
            findings_data=findings_data,
            results_dir=results_dir,
            logo_path=LOGO_PATH,
            branded=_license.check_pro_feature(BRANDED_REPORTS),
            project_name=project_name,
            upload_dir=upload_dir,
        )

        # 5. Attack graph
        _write_status(results_dir, "running", "Generating attack graph...", started_at)
        attack_graph_generated = False
        if findings and _license.check_pro_feature(ATTACK_GRAPH):
            attack_graph_generated = generate_attack_graph(
                findings=findings,
                uploaded_paths=uploaded_paths,
                results_dir=results_dir,
                project_name=project_name,
                logo_path=LOGO_PATH,
            )

        # 6. Save scan metadata
        analyzers_list = build_analyzers_list(
            heuristic_count=heuristic_count,
            slither_findings_count=len(slither_findings),
            slither_status=slither_status,
            ai_status=ai_status,
            attack_graph_generated=attack_graph_generated,
            has_findings=bool(findings),
            has_attack_graph_feature=_license.check_pro_feature(ATTACK_GRAPH),
            findings_data=findings_data,
        )

        scan_meta = {
            "owner_user_id": user_id or None,
            "project_name": project_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "files_scanned": len(uploaded_paths),
            "total_source_lines": sum(count_lines(fp) for fp in uploaded_paths),
            "analyzers": analyzers_list,
            "rules_triggered": sorted(str(fd["rule_id"]) for fd in findings_data),
        }
        meta_path = results_dir / "scan_meta.json"
        meta_path.write_text(json.dumps(scan_meta, indent=2), encoding="utf-8")

        # Write lightweight scan index for fast dashboard reads
        _write_scan_index_worker(results_dir, audit_id, findings_data, scan_meta)

        # Update per-user audit index for O(1) dashboard performance
        _update_user_audit_index_worker(user_id, {
            "audit_id": audit_id,
            "project_name": scan_meta.get("project_name", "Unknown"),
            "timestamp": scan_meta.get("timestamp", ""),
            "severity_counts": {
                "critical": sum(1 for fd in findings_data if fd.get("severity", "").upper() == "CRITICAL"),
                "high": sum(1 for fd in findings_data if fd.get("severity", "").upper() == "HIGH"),
                "medium": sum(1 for fd in findings_data if fd.get("severity", "").upper() == "MEDIUM"),
                "low": sum(1 for fd in findings_data if fd.get("severity", "").upper() == "LOW"),
            },
            "risk_score": round(min(100.0, (sum(
                {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.1}.get(fd.get("severity", "INFO"), 0)
                for fd in findings_data
            ) / max(len(findings_data) * 10.0, 1.0)) * 100), 1) if findings_data else 0.0,
        })

        # Done!
        _write_status(results_dir, "complete", "Scan complete", started_at, _iso_now())
        logger.info("Audit %s completed successfully", audit_id)

        # Send email notification on success
        if user_id:
            from webapp.user_manager import user_manager
            notif_email = user_manager.get_notification_email(user_id)
            if notif_email:
                _send_scan_notification(notif_email, audit_id, "complete", project_name)

    except Exception as exc:
        # Determine current try number from arq context
        job_try: int = ctx.get("job_try", 1)
        max_tries: int = 3
        if job_try < max_tries:
            # Will be retried by arq — write retrying status so pending page
            # shows appropriate feedback instead of a hard failure.
            logger.warning(
                "Audit %s failed (attempt %d/%d), will retry: %s",
                audit_id, job_try, max_tries, exc,
            )
            _write_status(
                results_dir, "retrying",
                f"Transient failure (attempt {job_try}/{max_tries}). Retrying soon\u2026",
                started_at,
            )
            raise  # re-raise so arq schedules the retry
        logger.exception("Audit %s failed permanently after %d attempts: %s", audit_id, max_tries, exc)
        _write_status(
            results_dir, "failed",
            "Scan failed. Please try again or contact support.",
            started_at, _iso_now(),
        )

        # Send email notification on failure
        if user_id:
            try:
                from webapp.user_manager import user_manager as _um
                notif_email = _um.get_notification_email(user_id)
                if notif_email:
                    _pname = audit_id
                    pre_meta_path = results_dir / "scan_meta.json"
                    if pre_meta_path.exists():
                        try:
                            _pname = json.loads(pre_meta_path.read_text()).get("project_name", audit_id)
                        except Exception:
                            pass
                    _send_scan_notification(notif_email, audit_id, "failed", _pname)
            except Exception:
                pass


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
    max_tries = 3          # retry transient failures up to 3 attempts
    retry_delay = 30       # seconds between retries
