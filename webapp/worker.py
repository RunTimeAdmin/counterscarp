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
from concurrent.futures import ThreadPoolExecutor, as_completed

from arq.connections import RedisSettings

# Ensure project root is on sys.path so engine modules resolve
_project_root = Path(__file__).resolve().parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from logger import get_logger

logger = get_logger(__name__)


def _merge_slither_status(current: str, new_status: str) -> str:
    """Merge slither run statuses with deterministic precedence."""
    if current == "completed" or new_status == "completed":
        return "completed"
    precedence = {
        "error": 3,
        "not_installed": 2,
        "skipped": 1,
    }
    return (
        new_status
        if precedence.get(new_status, 0) >= precedence.get(current, 0)
        else current
    )


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


from webapp import audit_index as _audit_index


def _update_user_audit_index_worker(user_id: str, audit_summary: dict) -> None:
    """Append an audit summary to the per-user audit index (cross-process safe)."""
    _audit_index.append(user_id, audit_summary)


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
    from webapp.scan_utils import summarize_findings_data
    summary = summarize_findings_data(findings_data)

    index = {
        "audit_id": audit_id,
        "project_name": scan_meta.get("project_name", "Unknown"),
        "timestamp": scan_meta.get("timestamp", ""),
        "severity_counts": summary["severity_counts_lower"],
        "risk_score": summary["risk_score"],
        "total_findings": summary["total_findings"],
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
    from webapp.scan_utils import (
        heuristic_finding_to_finding,
        count_lines,
        run_slither_analysis,
        run_ai_copilot,
        serialize_findings,
        generate_reports,
        generate_attack_graph,
        build_analyzers_list,
        summarize_findings_data,
    )
    from heuristic_scanner import scan_target
    from report_generator import Finding, create_audit_report
    from license_manager import LicenseManager
    from webapp.web_pipeline import build_web_scan_context, run_web_pipeline

    results_dir = RESULTS_DIR / audit_id
    upload_dir = UPLOAD_DIR / audit_id
    results_dir.mkdir(parents=True, exist_ok=True)

    started_at = _iso_now()
    _write_status(results_dir, "running", "Starting scan...", started_at)

    # Resolve license tier for pipeline gating
    _lm = LicenseManager()
    _tier = _lm.get_tier()

    # --- Engine pipeline scan (replaces bespoke per-phase calls below) ---
    try:
        scan_ctx = build_web_scan_context(
            target=str(upload_dir),
            output_dir=results_dir,
            license_tier=_tier,
        )
        _write_status(results_dir, "running", "Running analysis pipeline...", started_at)
        await run_web_pipeline(scan_ctx)
        logger.info("Audit %s: pipeline complete", audit_id)
    except Exception as _pipeline_exc:
        # Pipeline failure is non-fatal for the bespoke fallback path so that
        # users still get results. Log as error and continue with legacy flow.
        logger.error(
            "Audit %s: engine pipeline failed (%s) — falling back to legacy scan",
            audit_id, _pipeline_exc,
        )
        scan_ctx = None  # type: ignore[assignment]

    if scan_ctx is not None:
        # Fast-path: convert pipeline context results into Finding objects
        findings: List[Finding] = []
        for h in scan_ctx.heuristic_results:
            findings.append(heuristic_finding_to_finding(
                type("_HF", (), h)()  # thin shim — heuristic_finding_to_finding expects an object
                if False else type("_HF", (), {
                    "rule_id": h.get("rule_id", "UNKNOWN"),
                    "severity": h.get("severity", "INFO"),
                    "message": h.get("message", ""),
                    "file": h.get("file", ""),
                    "line_no": h.get("line_no", 0),
                    "line_text": h.get("line_text", ""),
                    "category": h.get("category", "Heuristic"),
                    "hint": h.get("hint", ""),
                    "references": h.get("references", []),
                    "suppressed": h.get("suppressed", False),
                })()
            ))
        for s in scan_ctx.static_issues:
            from webapp.scan_utils import _slither_dict_to_finding
            if callable(getattr(__import__("webapp.scan_utils", fromlist=["_slither_dict_to_finding"]), "_slither_dict_to_finding", None)):
                try:
                    findings.append(
                        __import__("webapp.scan_utils", fromlist=["_slither_dict_to_finding"])
                        ._slither_dict_to_finding(s)
                    )
                except Exception:
                    pass
        for fp in scan_ctx.fingerprint_results:
            try:
                findings.append(heuristic_finding_to_finding(
                    type("_FP", (), {
                        "rule_id": fp.get("rule_id", "FINGERPRINT"),
                        "severity": fp.get("severity", "INFO"),
                        "message": fp.get("message", fp.get("description", "")),
                        "file": fp.get("file", ""),
                        "line_no": fp.get("line_no", 0),
                        "line_text": fp.get("line_text", ""),
                        "category": fp.get("category", "Fingerprint"),
                        "hint": fp.get("hint", ""),
                        "references": fp.get("references", []),
                        "suppressed": False,
                    })()
                ))
            except Exception:
                pass
        heuristic_count = len([f for f in findings if not hasattr(f, "_from_static")])
        fingerprint_findings = [f for f in findings if getattr(f, "_category", "") == "Fingerprint"]
        fingerprint_status = "completed" if fingerprint_findings else "skipped"
        fingerprint_meta: dict = {}
        slither_findings = [
            f for f in findings
            if getattr(f, "rule_id", "").startswith("SLITHER") or getattr(f, "_from_static", False)
        ]
        slither_status = "completed" if slither_findings else "skipped"
        ai_status = "skipped"
    else:
        # Legacy bespoke scan path (fallback only)
        findings = []
        heuristic_count = 0
        slither_findings = []
        slither_status = "skipped"
        fingerprint_findings = []
        fingerprint_status = "skipped"
        fingerprint_meta = {}
        ai_status = "skipped"

    try:
        if scan_ctx is None:
            # Legacy bespoke scan (fallback when pipeline fails)
            # 1. Heuristic scan
            _write_status(results_dir, "running", "Running heuristic scan...", started_at)
            for fp_str in uploaded_paths:
                heuristic_findings = scan_target(fp_str)
                for hf in heuristic_findings:
                    findings.append(heuristic_finding_to_finding(hf))
            heuristic_count = len(findings)

            # 2. Protocol fingerprint + fork logic checks
            _write_status(
                results_dir, "running", "Running protocol fingerprint scan...", started_at,
            )
            from webapp.scan_utils import run_protocol_fingerprint_analysis
            fingerprint_findings, fingerprint_status, fingerprint_meta = (
                run_protocol_fingerprint_analysis(uploaded_paths)
            )
            findings.extend(fingerprint_findings)

            # 3. Slither analysis
            _write_status(results_dir, "running", "Running Slither analysis...", started_at)
            slither_findings_local: list[Finding] = []
            sol_paths = [fp for fp in uploaded_paths if fp.endswith(".sol")]
            if sol_paths:
                slither_project_mode = (
                    os.environ.get("SLITHER_PROJECT_MODE", "1").lower()
                    in {"1", "true", "yes", "on"}
                )
                if slither_project_mode:
                    sf, status = run_slither_analysis(str(upload_dir), UPLOAD_DIR)
                    slither_findings_local.extend(sf)
                    slither_status = _merge_slither_status(slither_status, status)
                else:
                    max_workers = min(4, len(sol_paths))
                    with ThreadPoolExecutor(max_workers=max_workers) as pool:
                        futures = [pool.submit(run_slither_analysis, fp) for fp in sol_paths]
                        for future in as_completed(futures):
                            sf, status = future.result()
                            slither_findings_local.extend(sf)
                            slither_status = _merge_slither_status(slither_status, status)
            slither_findings = slither_findings_local
            findings.extend(slither_findings)

        # 3. AI Copilot
        _write_status(results_dir, "running", "Running AI Copilot analysis...", started_at)
        ai_summary = ""
        ai_status = "skipped"
        if findings:
            ai_summary, ai_status = run_ai_copilot(findings, "")

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
        findings_summary = summarize_findings_data(findings_data)
        findings_path = results_dir / "findings.json"
        findings_path.write_text(json.dumps(findings_data, indent=2), encoding="utf-8")

        # Generate all report formats
        generate_reports(
            report=report,
            findings=findings,
            findings_data=findings_data,
            results_dir=results_dir,
            logo_path=LOGO_PATH,
            branded=True,
            project_name=project_name,
            upload_dir=upload_dir,
        )

        # 5. Attack graph
        _write_status(results_dir, "running", "Generating attack graph...", started_at)
        attack_graph_generated = False
        if findings:
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
            fingerprint_status=fingerprint_status,
            fingerprint_findings_count=len(fingerprint_findings),
            fingerprint_meta=fingerprint_meta,
            ai_status=ai_status,
            attack_graph_generated=attack_graph_generated,
            has_findings=bool(findings),
            has_attack_graph_feature=True,
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
            "severity_counts": findings_summary["severity_counts_lower"],
            "risk_score": findings_summary["risk_score"],
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


async def _on_startup(ctx: dict) -> None:
    """Initialise shared state before the first job runs."""
    _audit_index.configure(_project_root / "data" / "user_audit_index")
    logger.info("audit_index configured at %s", _project_root / "data" / "user_audit_index")


class WorkerSettings:
    """arq worker configuration.

    Start with:  python -m arq webapp.worker.WorkerSettings
    """

    functions = [run_audit]
    on_startup = _on_startup
    redis_settings = _redis_settings()
    max_jobs = 4
    job_timeout = 600  # 10 minutes per audit
    max_tries = 3          # retry transient failures up to 3 attempts
    retry_delay = 30       # seconds between retries
