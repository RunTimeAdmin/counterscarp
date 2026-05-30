"""Audit route handler extracted from the main webapp module."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List

from fastapi import HTTPException, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse, Response

from heuristic_scanner import scan_target
from report_generator import Finding, create_audit_report
from webapp.auth import (
    get_current_user,
    get_license_key_for_request,
    validate_csrf_token,
)
from webapp.config import ALLOWED_EXTENSIONS, LOGO_PATH, RESULTS_DIR, UPLOAD_DIR
from webapp.rate_limiter import add_rate_limit_headers, get_client_ip
from webapp.scan_utils import (
    build_analyzers_list,
    generate_attack_graph,
    generate_reports,
    heuristic_finding_to_finding,
    run_ai_copilot,
    serialize_findings,
    summarize_findings_data,
)

GracePeriodContextFn = Callable[[Request], Dict[str, Any]]
WriteScanIndexFn = Callable[[Path, str, list, dict], None]
UpdateUserAuditIndexFn = Callable[[str, dict], None]
RunSlitherBatchAsyncFn = Callable[
    [List[str], int],
    Awaitable[tuple[list[Finding], str]],
]
SaveUploadFileStreamingFn = Callable[[UploadFile, Path], Awaitable[int]]


async def handle_audit_request(
    request: Request,
    project_name: str,
    files: List[UploadFile],
    *,
    audit_limiter: Any,
    license_manager: Any,
    get_grace_period_context: GracePeriodContextFn,
    templates: Any,
    write_scan_index: WriteScanIndexFn,
    update_user_audit_index: UpdateUserAuditIndexFn,
    run_slither_batch_async: RunSlitherBatchAsyncFn,
    save_upload_file_streaming: SaveUploadFileStreamingFn,
) -> Response:
    """Handle POST /audit with rate limits, uploads, and scan dispatch."""
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    client_ip = get_client_ip(request)
    if not audit_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"detail": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(resp_429, audit_limiter, client_ip)
        resp_429.headers["Retry-After"] = str(
            audit_limiter.get_reset_time(client_ip)
        )
        return resp_429

    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    valid_files = []
    for upload in files:
        ext = Path(upload.filename or "").suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Invalid file type: {upload.filename}. "
                    f"Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
                ),
            )
        valid_files.append(upload)

    if not valid_files:
        raise HTTPException(status_code=400, detail="No valid files to process")

    audit_id = str(uuid.uuid4())
    upload_dir = UPLOAD_DIR / audit_id
    results_dir = RESULTS_DIR / audit_id

    upload_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    uploaded_paths: list[str] = []
    uploaded_total_source_lines = 0
    for upload in valid_files:
        safe_name = re.sub(
            r"[^a-zA-Z0-9._-]",
            "_",
            Path(upload.filename or "unnamed").name,
        )[:100]
        file_path = upload_dir / safe_name
        uploaded_total_source_lines += await save_upload_file_streaming(
            upload,
            file_path,
        )
        uploaded_paths.append(str(file_path))
        await upload.close()

    arq_pool = getattr(request.app.state, "arq_pool", None)
    current_user = get_current_user(request)
    user_id = current_user["id"] if current_user else ""
    license_key = get_license_key_for_request(request, current_user) or ""

    if arq_pool is not None:
        status_payload = {
            "status": "pending",
            "progress": "Queued...",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        status_path = results_dir / "scan_status.json"
        with open(status_path, "w", encoding="utf-8") as status_file:
            json.dump(status_payload, status_file, indent=2)

        pre_meta = {
            "project_name": project_name,
            "owner_user_id": user_id or None,
        }
        pre_meta_path = results_dir / "scan_meta.json"
        with open(pre_meta_path, "w", encoding="utf-8") as meta_file:
            json.dump(pre_meta, meta_file, indent=2)

        await arq_pool.enqueue_job(
            "run_audit",
            audit_id,
            uploaded_paths,
            license_key,
            user_id,
        )

        redirect = RedirectResponse(
            url=f"/results/{audit_id}/pending",
            status_code=303,
        )
        add_rate_limit_headers(redirect, audit_limiter, client_ip)
        return redirect

    findings: List[Finding] = []
    for fp_str in uploaded_paths:
        heuristic_findings = scan_target(fp_str)
        for heuristic_finding in heuristic_findings:
            findings.append(heuristic_finding_to_finding(heuristic_finding))

    heuristic_count = len(findings)

    from webapp.scan_utils import run_protocol_fingerprint_analysis

    fingerprint_findings, fingerprint_status, fingerprint_meta = (
        run_protocol_fingerprint_analysis(uploaded_paths)
    )
    findings.extend(fingerprint_findings)

    sol_paths = [path for path in uploaded_paths if path.endswith(".sol")]
    slither_findings, slither_status = await run_slither_batch_async(
        sol_paths,
        max_concurrency=4,
    )
    findings.extend(slither_findings)

    ai_summary = ""
    ai_status = "skipped"
    if findings:
        ai_summary, ai_status = run_ai_copilot(findings, "")

    if ai_summary:
        ai_path = results_dir / "ai_summary.txt"
        with open(ai_path, "w", encoding="utf-8") as ai_file:
            ai_file.write(ai_summary)

    report = create_audit_report(
        project_name=project_name,
        target_path=str(upload_dir),
        findings=findings,
    )

    findings_data = serialize_findings(findings)
    findings_summary = summarize_findings_data(findings_data)

    findings_path = results_dir / "findings.json"
    with open(findings_path, "w", encoding="utf-8") as findings_file:
        json.dump(findings_data, findings_file, indent=2)

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

    attack_graph_generated = False
    if findings:
        attack_graph_generated = generate_attack_graph(
            findings=findings,
            uploaded_paths=uploaded_paths,
            results_dir=results_dir,
            project_name=project_name,
            logo_path=LOGO_PATH,
        )

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

    current_user = get_current_user(request)
    scan_meta = {
        "owner_user_id": current_user["id"] if current_user else None,
        "project_name": project_name,
        "timestamp": datetime.now().isoformat(),
        "files_scanned": len(uploaded_paths),
        "total_source_lines": uploaded_total_source_lines,
        "analyzers": analyzers_list,
        "rules_triggered": sorted(str(fd["rule_id"]) for fd in findings_data),
    }

    meta_path = results_dir / "scan_meta.json"
    with open(meta_path, "w", encoding="utf-8") as meta_file:
        json.dump(scan_meta, meta_file, indent=2)

    write_scan_index(results_dir, audit_id, findings_data, scan_meta)
    update_user_audit_index(
        user_id,
        {
            "audit_id": audit_id,
            "project_name": scan_meta.get("project_name", "Unknown"),
            "timestamp": scan_meta.get("timestamp", ""),
            "severity_counts": findings_summary["severity_counts_lower"],
            "risk_score": findings_summary["risk_score"],
        },
    )

    redirect = RedirectResponse(url=f"/results/{audit_id}", status_code=303)
    add_rate_limit_headers(redirect, audit_limiter, client_ip)
    return redirect


