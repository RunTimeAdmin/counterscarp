"""FastAPI web application for Counterscarp Engine."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import sys
import time
import uuid
import codecs
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from webapp.auth import auth_router, admin_router, get_current_user, get_license_key_for_request, generate_csrf_token, validate_csrf_token
from webapp.user_manager import user_manager
from webapp.config import (
    ALLOWED_EXTENSIONS,
    BASE_DIR,
    LOGO_PATH,
    MAX_FILE_SIZE,
    RESULTS_DIR,
    TEMPLATES_DIR,
    UPLOAD_DIR,
    SESSION_SECRET,
    validate_production_config,
)

from license_manager import (
    LicenseManager,
    AI_COPILOT,
    ATTACK_GRAPH,
    BRANDED_REPORTS,
    DEVELOPER,
    FEATURE_TIERS,
    FEATURE_NAMES,
    GRACE_PERIOD_DAYS,
    LICENSE_PREFIXES,
    PAYG,
    TIER_HIERARCHY,
    TIER_PREFIXES,
)

from webapp.license_api import license_router
from webapp.license_api import append_audit_log
from webapp.license_api import consume_credit
from webapp.rate_limiter import RateLimiter, RedisRateLimiter, get_client_ip, add_rate_limit_headers
from webapp.stripe_integration import (
    create_checkout_session,
    create_payg_checkout,
    find_license_by_subscription,
    handle_checkout_completed,
    get_session_license_key,
    update_license_in_db,
    check_and_mark_event,
    is_event_processed,
    mark_event_processed,
    PAYG_PACKS,
    STRIPE_PUBLISHABLE_KEY,
    STRIPE_WEBHOOK_SECRET,
    PRODUCTS,
)
import stripe as _stripe
from logger import get_logger

logger = get_logger(__name__)

# Rate limiter for the Stripe webhook endpoint (30 req/min per IP)
_stripe_webhook_limiter = RateLimiter(max_requests=30, window_seconds=60)

_redis_url = os.environ.get("REDIS_URL")

# Rate limiters per endpoint group (Redis-backed with in-memory fallback)
_login_limiter = RedisRateLimiter(max_requests=5, window_seconds=900, redis_url=_redis_url, prefix="rl:login")
_register_limiter = RedisRateLimiter(max_requests=3, window_seconds=3600, redis_url=_redis_url, prefix="rl:register")
_audit_limiter = RedisRateLimiter(max_requests=10, window_seconds=3600, redis_url=_redis_url, prefix="rl:audit")
_license_limiter = RedisRateLimiter(max_requests=100, window_seconds=3600, redis_url=_redis_url, prefix="rl:license")
_admin_limiter = RedisRateLimiter(max_requests=30, window_seconds=3600, redis_url=_redis_url, prefix="rl:admin")
_totp_limiter = RedisRateLimiter(max_requests=10, window_seconds=1800, redis_url=_redis_url, prefix="rl:totp")
security_logger = logging.getLogger("counterscarp.security")

_license = LicenseManager()


from webapp.scan_utils import (
    heuristic_finding_to_finding,
    run_slither_analysis,
    run_ai_copilot,
    serialize_findings,
    generate_reports,
    generate_attack_graph,
    build_analyzers_list,
    summarize_findings_data,
)


def validate_audit_id(audit_id: str) -> str:
    """Validate audit_id is a UUID and resolves inside RESULTS_DIR."""
    return _normalize_audit_id(audit_id)


def _normalize_audit_id(audit_id: str) -> str:
    """Canonicalize and validate a UUID audit ID."""
    try:
        return str(uuid.UUID(audit_id))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid audit ID format")


def _resolve_audit_dir(base_dir: Path, audit_id: str) -> Path:
    """Resolve and constrain an audit directory to the provided base path."""
    normalized_id = _normalize_audit_id(audit_id)
    resolved = (base_dir / normalized_id).resolve()
    base_resolved = base_dir.resolve()
    if not resolved.is_relative_to(base_resolved):
        raise HTTPException(status_code=403, detail="Access denied")
    return resolved


# Import Counterscarp Engine modules (scan_utils re-exports shared logic)
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
)

app = FastAPI(
    title="Counterscarp Engine",
    description="Smart Contract Security Audit Platform",
    version="5.1.0",
)

app.add_middleware(SessionMiddleware, secret_key=SESSION_SECRET)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security-related HTTP headers to every response."""

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://app.counterscarp.io",
        "https://counterscarp.io",
        "http://localhost:8000",
        "http://localhost:8001",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# Include auth and admin routes
app.include_router(auth_router)
app.include_router(admin_router)

# Include license validation API routes
app.include_router(license_router)

# Mount static files
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def ensure_directories():
    """Ensure required directories exist."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)


async def async_run_slither_analysis(file_path: str) -> tuple[list[Finding], str]:
    """Async version of run_slither_analysis.

    Runs Slither without blocking the event loop via thread executor.
    Returns a tuple of (list of Finding objects, status string).
    """
    import asyncio
    try:
        import async_subprocess as _async_subprocess
    except ImportError:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, run_slither_analysis, file_path, UPLOAD_DIR
        )

    try:
        upload_dir = Path(UPLOAD_DIR).resolve()
        resolved = Path(file_path).resolve()
        if not resolved.is_relative_to(upload_dir):
            raise HTTPException(status_code=400, detail="Invalid file path")

        venv_bin = Path(sys.executable).parent
        slither_bin = str(venv_bin / "slither")

        result = await _async_subprocess.run_tool(
            [slither_bin, "--json", "-", "--", str(resolved)],
            timeout=120,
        )

        if result.returncode not in (0, 1):
            return [], "error"

        data = json.loads(result.stdout) if result.stdout else {}
        detectors = data.get("results", {}).get("detectors", [])

        slither_findings: list[Finding] = []
        severity_map = {
            "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW",
            "Informational": "INFO", "Optimization": "INFO",
        }

        for det in detectors:
            elements = det.get("elements", [])
            file_name = ""
            line_no = 0
            code_snippet = ""
            if elements:
                src = elements[0].get("source_mapping", {})
                file_name = src.get("filename_short", "")
                lines = src.get("lines", [])
                line_no = lines[0] if lines else 0
                code_snippet = elements[0].get("name", "")

            finding = Finding(
                rule_id=f"SLITHER-{det.get('check', 'unknown').upper()}",
                severity=severity_map.get(det.get("impact", ""), "INFO"),
                category="Slither",
                title=det.get("check", "Unknown").replace("-", " ").title(),
                description=det.get("description", ""),
                file=file_name,
                line_no=line_no,
                code_snippet=code_snippet,
                remediation=det.get("markdown", ""),
                references=[],
            )
            slither_findings.append(finding)

        return slither_findings, "completed"
    except FileNotFoundError:
        return [], "not_installed"
    except Exception:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            None, run_slither_analysis, file_path, UPLOAD_DIR
        )


async def run_slither_batch_async(file_paths: List[str], max_concurrency: int = 4) -> tuple[list[Finding], str]:
    """Run Slither across files concurrently with bounded parallelism."""
    import asyncio

    if not file_paths:
        return [], "skipped"

    semaphore = asyncio.Semaphore(max(1, max_concurrency))

    async def _run_one(path: str) -> tuple[list[Finding], str]:
        async with semaphore:
            return await async_run_slither_analysis(path)

    results = await asyncio.gather(*(_run_one(path) for path in file_paths))

    all_findings: list[Finding] = []
    status = "skipped"
    for finding_batch, batch_status in results:
        all_findings.extend(finding_batch)
        if batch_status == "completed":
            status = "completed"
        elif status == "skipped" and batch_status != "completed":
            status = batch_status
    return all_findings, status


async def _save_upload_file_streaming(upload: UploadFile, destination: Path) -> int:
    """Stream uploaded content to disk with size and UTF-8 validation.

    Returns the number of source lines detected while streaming.
    """
    total_bytes = 0
    line_count = 0
    decoder = codecs.getincrementaldecoder("utf-8")(errors="strict")
    chunk_size = 1024 * 1024

    try:
        with open(destination, "wb") as fw:
            while True:
                chunk = await upload.read(chunk_size)
                if not chunk:
                    break
                total_bytes += len(chunk)
                if total_bytes > MAX_FILE_SIZE:
                    raise HTTPException(
                        status_code=400,
                        detail=(
                            f"File too large: {upload.filename} "
                            f"(max {MAX_FILE_SIZE // 1024 // 1024}MB)"
                        ),
                    )
                try:
                    decoded = decoder.decode(chunk, final=False)
                except UnicodeDecodeError:
                    raise HTTPException(
                        status_code=400,
                        detail=f"File {upload.filename} is not valid text",
                    )
                line_count += decoded.count("\n")
                fw.write(chunk)

            try:
                decoded_tail = decoder.decode(b"", final=True)
            except UnicodeDecodeError:
                raise HTTPException(
                    status_code=400,
                    detail=f"File {upload.filename} is not valid text",
                )
            line_count += decoded_tail.count("\n")
            return line_count
    except Exception:
        if destination.exists():
            destination.unlink(missing_ok=True)
        raise


# Load persisted API keys from data/.env.local
_env_local = Path(__file__).parent.parent / "data" / ".env.local"
if _env_local.exists():
    for _line in _env_local.read_text().splitlines():
        if "=" in _line and not _line.startswith("#"):
            _k, _v = _line.split("=", 1)
            _k, _v = _k.strip(), _v.strip()
            if _k and not os.environ.get(_k):  # Don't override system env vars
                os.environ[_k] = _v


def _cleanup_old_directories(base_dir: Path, max_age_days: int, logger, label: str):
    """Remove subdirectories older than max_age_days."""
    if not base_dir.exists():
        return
    cutoff = time.time() - (max_age_days * 86400)
    removed = 0
    for entry in base_dir.iterdir():
        if entry.is_dir() and entry.stat().st_mtime < cutoff:
            shutil.rmtree(entry, ignore_errors=True)
            removed += 1
    if removed:
        logger.info("Removed %d old %s directories (>%d days)", removed, label, max_age_days)


@app.on_event("startup")
async def startup_event():
    """Initialize on startup."""
    validate_production_config()
    ensure_directories()
    # Expose rate limiters via app.state for use in auth router
    app.state.login_limiter = _login_limiter
    app.state.register_limiter = _register_limiter
    app.state.audit_limiter = _audit_limiter
    app.state.license_limiter = _license_limiter
    app.state.admin_limiter = _admin_limiter
    app.state.totp_limiter = _totp_limiter

    # Initialize arq Redis pool for async job queue (graceful fallback)
    app.state.arq_pool = None
    if _redis_url:
        try:
            from arq import create_pool
            from arq.connections import RedisSettings
            app.state.arq_pool = await create_pool(
                RedisSettings.from_dsn(_redis_url)
            )
            logger.info("arq Redis pool initialized for async audit processing")
        except Exception as exc:
            logger.warning("arq Redis pool unavailable, falling back to sync: %s", exc)
            app.state.arq_pool = None


@app.on_event("startup")
async def startup_cleanup():
    """Run housekeeping cleanup on app startup."""
    _cleanup_logger = logging.getLogger("counterscarp.cleanup")

    # 1. Clean old scan state files (>30 days)
    try:
        from state_manager import ScanStateManager
        sm = ScanStateManager()
        sm.cleanup_old_sessions(max_age_days=30)
        _cleanup_logger.info("Cleaned old scan state files (>30 days)")
    except Exception as e:
        _cleanup_logger.warning("State cleanup failed: %s", e)

    # 2. Clean old report directories (>90 days)
    try:
        _cleanup_old_directories(
            Path(__file__).parent.parent / "reports",
            max_age_days=90,
            logger=_cleanup_logger,
            label="reports",
        )
    except Exception as e:
        _cleanup_logger.warning("Report cleanup failed: %s", e)

    # 3. Clean old uploads (>7 days)
    try:
        _cleanup_old_directories(
            Path(__file__).parent.parent / "uploads",
            max_age_days=7,
            logger=_cleanup_logger,
            label="uploads",
        )
    except Exception as e:
        _cleanup_logger.warning("Upload cleanup failed: %s", e)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the upload page."""
    license_tier = _license.get_tier()
    current_user = get_current_user(request)
    scan_credits = 0
    if current_user:
        from webapp.user_manager import user_manager as _um
        scan_credits = _um.get_scan_credits(current_user["id"])
    return templates.TemplateResponse(
        request, "upload.html",
        context={
            "current_user": current_user,
            "license_tier": license_tier,
            "scan_credits": scan_credits,
            "csrf_token": generate_csrf_token(request),
            **_get_grace_period_context(request),
        },
    )


@app.get("/health")
async def health():
    """Health check endpoint."""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


@app.post("/audit")
async def audit(
    request: Request,
    project_name: str = Form(...),
    files: List[UploadFile] = File(...),
):
    """Run security audit on uploaded files."""
    # CSRF validation — skip if no token was ever generated
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    # Enforce per-IP audit rate limit
    client_ip = get_client_ip(request)
    if not _audit_limiter.is_allowed(client_ip):
        resp_429 = JSONResponse(
            {"detail": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(resp_429, _audit_limiter, client_ip)
        resp_429.headers["Retry-After"] = str(
            _audit_limiter.get_reset_time(client_ip)
        )
        return resp_429

    # Validate files
    if not files:
        raise HTTPException(status_code=400, detail="No files uploaded")

    valid_files = []
    for file in files:
        # Check file extension
        ext = Path(file.filename or "").suffix.lower()
        if ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid file type: {file.filename}. Allowed: {', '.join(ALLOWED_EXTENSIONS)}"
            )
        valid_files.append(file)

    if not valid_files:
        raise HTTPException(status_code=400, detail="No valid files to process")

    # Generate audit ID
    audit_id = str(uuid.uuid4())
    upload_dir = UPLOAD_DIR / audit_id
    results_dir = RESULTS_DIR / audit_id

    upload_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    # Save uploaded files with streaming validation to reduce memory spikes.
    uploaded_paths: list[str] = []
    uploaded_total_source_lines = 0
    for file in valid_files:
        # Sanitize filename: strip path separators, allow only safe chars, limit length
        safe_name = re.sub(r'[^a-zA-Z0-9._-]', '_', Path(file.filename or "unnamed").name)[:100]
        file_path = upload_dir / safe_name
        uploaded_total_source_lines += await _save_upload_file_streaming(file, file_path)
        uploaded_paths.append(str(file_path))
        await file.close()

    # --- Async (arq) vs sync scan dispatch ---
    arq_pool = getattr(request.app.state, "arq_pool", None)
    current_user = get_current_user(request)
    user_id = current_user["id"] if current_user else ""
    license_key = get_license_key_for_request(request, current_user) or ""

    # --- PAYG Credit Gate ---
    # Determine user's effective tier
    user_tier = "community"  # default
    if license_key:
        for _tier, _prefix in TIER_PREFIXES.items():
            if license_key.startswith(_prefix):
                user_tier = _tier
                break

    # Check if user needs credits (below DEVELOPER tier)
    tier_index = TIER_HIERARCHY.index(user_tier) if user_tier in TIER_HIERARCHY else 0
    developer_index = TIER_HIERARCHY.index(DEVELOPER)

    if tier_index < developer_index:
        if current_user:
            from webapp.user_manager import user_manager as _um
            credits = _um.get_scan_credits(current_user["id"])
            # HF-V4-01: PAYG users MUST have credits — no credits means blocked
            if user_tier == PAYG:
                if credits <= 0:
                    return templates.TemplateResponse(
                        request, "payg_no_credits.html",
                        context={
                            "current_user": current_user,
                            "scan_credits": 0,
                            **_get_grace_period_context(request),
                        },
                        status_code=402,
                    )
            if credits > 0:
                # Consume a credit
                success = consume_credit(current_user["id"], audit_id, request.client.host if request.client else "")
                if not success:
                    return templates.TemplateResponse(
                        request, "payg_no_credits.html",
                        context={
                            "current_user": current_user,
                            "scan_credits": 0,
                            **_get_grace_period_context(request),
                        },
                        status_code=402,
                    )
            # Community tier with no credits — allowed via rate limiter (existing behavior)
        else:
            # HF-V4-02: Unauthenticated users below DEVELOPER tier
            # must have a valid license key to scan
            if not license_key:
                raise HTTPException(
                    status_code=401,
                    detail="Authentication or a valid license key is required to run scans.",
                )
    # DEVELOPER+ tiers bypass credit gate entirely (unlimited scans via subscription)
    # --- End Credit Gate ---

    if arq_pool is not None:
        # Write initial pending status
        status_payload = {
            "status": "pending",
            "progress": "Queued...",
            "started_at": datetime.now(timezone.utc).isoformat(),
        }
        status_path = results_dir / "scan_status.json"
        with open(status_path, "w", encoding="utf-8") as sf:
            json.dump(status_payload, sf, indent=2)

        # Pre-seed scan_meta so the worker can read project_name
        pre_meta = {"project_name": project_name, "owner_user_id": user_id or None}
        pre_meta_path = results_dir / "scan_meta.json"
        with open(pre_meta_path, "w", encoding="utf-8") as mf:
            json.dump(pre_meta, mf, indent=2)

        await arq_pool.enqueue_job(
            "run_audit", audit_id, uploaded_paths, license_key, user_id,
        )

        redirect = RedirectResponse(
            url=f"/results/{audit_id}/pending", status_code=303,
        )
        add_rate_limit_headers(redirect, _audit_limiter, client_ip)
        return redirect

    # --- Synchronous fallback (no Redis) ---

    # Run heuristic scanner
    findings: List[Finding] = []
    for fp_str in uploaded_paths:
        heuristic_findings = scan_target(fp_str)
        for hf in heuristic_findings:
            findings.append(heuristic_finding_to_finding(hf))

    heuristic_count = len(findings)

    # Run Slither static analysis on Solidity files with bounded concurrency.
    sol_paths = [path for path in uploaded_paths if path.endswith(".sol")]
    slither_findings, slither_status = await run_slither_batch_async(sol_paths, max_concurrency=4)
    findings.extend(slither_findings)

    # Run AI Audit Copilot (PRO feature)
    ai_summary = ""
    ai_status = "skipped"
    if findings and _license.check_pro_feature(AI_COPILOT):
        ai_summary, ai_status = run_ai_copilot(findings, "")
    elif findings:
        ai_status = "pro_required"

    # Save AI summary to results
    if ai_summary:
        ai_path = results_dir / "ai_summary.txt"
        with open(ai_path, "w", encoding="utf-8") as f:
            f.write(ai_summary)

    # Create audit report
    report = create_audit_report(
        project_name=project_name,
        target_path=str(upload_dir),
        findings=findings,
    )

    # Save findings as JSON
    findings_data = serialize_findings(findings)
    findings_summary = summarize_findings_data(findings_data)

    findings_path = results_dir / "findings.json"
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(findings_data, f, indent=2)

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

    # Generate attack graph (PRO feature)
    attack_graph_generated = False
    if findings and _license.check_pro_feature(ATTACK_GRAPH):
        attack_graph_generated = generate_attack_graph(
            findings=findings,
            uploaded_paths=uploaded_paths,
            results_dir=results_dir,
            project_name=project_name,
            logo_path=LOGO_PATH,
        )

    # Save scan metadata (coverage / what was checked)
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

    current_user = get_current_user(request)
    scan_meta = {
        "owner_user_id": current_user["id"] if current_user else None,
        "project_name": project_name,
        "timestamp": datetime.now().isoformat(),
        "files_scanned": len(uploaded_paths),
        "total_source_lines": uploaded_total_source_lines,
        "analyzers": analyzers_list,
        "rules_triggered": sorted(
            str(fd["rule_id"]) for fd in findings_data
        ),
    }

    meta_path = results_dir / "scan_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(scan_meta, f, indent=2)

    # Write lightweight scan index for fast dashboard reads
    _write_scan_index(results_dir, audit_id, findings_data, scan_meta)

    # Update per-user audit index for O(1) dashboard performance
    _update_user_audit_index(user_id, {
        "audit_id": audit_id,
        "project_name": scan_meta.get("project_name", "Unknown"),
        "timestamp": scan_meta.get("timestamp", ""),
        "severity_counts": findings_summary["severity_counts_lower"],
        "risk_score": findings_summary["risk_score"],
    })

    redirect = RedirectResponse(
        url=f"/results/{audit_id}", status_code=303,
    )
    add_rate_limit_headers(redirect, _audit_limiter, client_ip)
    return redirect


@app.get("/results/{audit_id}/pending", response_class=HTMLResponse)
async def results_pending(request: Request, audit_id: str = Depends(validate_audit_id)):
    """Show the scan-in-progress page for an async audit."""
    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    if not results_dir.exists():
        raise HTTPException(status_code=404, detail="Audit not found")
    return templates.TemplateResponse(
        request, "pending.html",
        context={
            "current_user": get_current_user(request),
            "audit_id": audit_id,
            **_get_grace_period_context(request),
        },
    )


@app.get("/api/audit/{audit_id}/status")
async def audit_status_api(audit_id: str = Depends(validate_audit_id)):
    """Return the current scan status JSON for an async audit."""
    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    status_path = results_dir / "scan_status.json"
    if not status_path.exists():
        raise HTTPException(status_code=404, detail="Audit not found")
    with open(status_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return JSONResponse(data)


@app.delete("/api/audit/{audit_id}")
async def delete_audit(request: Request, audit_id: str = Depends(validate_audit_id)):
    """Delete an audit and its results with ownership verification."""
    current_user = get_current_user(request)
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    if not results_dir.exists():
        raise HTTPException(status_code=404, detail="Audit not found")

    # Verify ownership via scan_meta.json
    owner = _get_audit_owner(results_dir)
    if owner is None:
        raise HTTPException(status_code=404, detail="Audit metadata not found")
    if owner != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")

    user_id = current_user["id"]

    # Remove the results directory
    shutil.rmtree(results_dir, ignore_errors=True)

    # Remove from per-user audit index
    _remove_from_user_audit_index(user_id, audit_id)

    # Also clean up the upload directory if it exists
    upload_dir = _resolve_audit_dir(UPLOAD_DIR, audit_id)
    if upload_dir.exists():
        shutil.rmtree(upload_dir, ignore_errors=True)

    # Log the deletion
    append_audit_log(
        "audit_deleted",
        audit_id,
        user_id,
        request.client.host if request.client else "unknown",
        {"audit_id": audit_id},
    )

    return JSONResponse({"status": "deleted", "audit_id": audit_id})


@app.get("/results/{audit_id}", response_class=HTMLResponse)
async def results(request: Request, audit_id: str = Depends(validate_audit_id)):
    """Display audit results."""
    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    findings_path = results_dir / "findings.json"

    if not findings_path.exists():
        raise HTTPException(status_code=404, detail="Audit not found")

    # Ownership check
    current_user = get_current_user(request)
    owner_id = _get_audit_owner(results_dir)
    if owner_id and current_user:
        if owner_id != current_user["id"]:
            raise HTTPException(status_code=403, detail="Access denied")
    elif owner_id and not current_user:
        return RedirectResponse(url="/auth/login")

    # Load findings
    with open(findings_path, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    # Calculate severity counts
    severity_counts = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0,
    }
    for finding in findings_data:
        severity = finding.get("severity", "INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Calculate risk score
    severity_weights = {
        "CRITICAL": 10.0, "HIGH": 5.0,
        "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.1,
    }
    total_weight = sum(
        severity_weights.get(f.get("severity", "INFO"), 0)
        for f in findings_data
    )
    max_possible = len(findings_data) * severity_weights["CRITICAL"]
    risk_score = min(100.0, (total_weight / max(max_possible, 1.0)) * 100) if findings_data else 0.0
    risk_score = round(risk_score, 1)

    # Determine pass/fail
    critical_count = severity_counts.get("CRITICAL", 0)
    high_count = severity_counts.get("HIGH", 0)
    if critical_count > 0 or high_count > 3:
        pass_fail = "FAIL"
    elif high_count > 0:
        pass_fail = "WARNING"
    else:
        pass_fail = "PASS"

    # Check for attack graph
    attack_graph_exists = (results_dir / "attack_graph.html").exists()

    # Check for PDF report
    pdf_report_exists = (results_dir / "report.pdf").exists()

    # Load scan metadata
    meta_path = results_dir / "scan_meta.json"
    scan_meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            scan_meta = json.load(f)

    # Load AI summary
    ai_summary = ""
    ai_path = results_dir / "ai_summary.txt"
    if ai_path.exists():
        with open(ai_path, "r", encoding="utf-8") as f:
            ai_summary = f.read()

    license_tier = _license.get_tier()
    return templates.TemplateResponse(
        request,
        "results.html",
        context={
            "current_user": get_current_user(request),
            "audit_id": audit_id,
            "findings": findings_data,
            "severity_counts": severity_counts,
            "total_findings": len(findings_data),
            "risk_score": risk_score,
            "pass_fail": pass_fail,
            "attack_graph_exists": attack_graph_exists,
            "pdf_report_exists": pdf_report_exists,
            "scan_meta": scan_meta,
            "ai_summary": ai_summary,
            "license_tier": license_tier,
            **_get_grace_period_context(request),
        },
    )


@app.get("/pricing")
async def pricing_page(request: Request):
    """Render the pricing / upgrade page."""
    current_user = get_current_user(request)
    scan_credits = 0
    if current_user:
        from webapp.user_manager import user_manager as _um
        scan_credits = _um.get_scan_credits(current_user["id"])
    return templates.TemplateResponse(
        request, "pricing.html",
        context={
            "current_user": current_user,
            "stripe_key": STRIPE_PUBLISHABLE_KEY,
            "products": PRODUCTS,
            "payg_packs": PAYG_PACKS,
            "scan_credits": scan_credits,
            "csrf_token": generate_csrf_token(request),
            **_get_grace_period_context(request),
        },
    )


@app.get("/privacy")
async def privacy_page(request: Request):
    return templates.TemplateResponse(request, "privacy.html", context={"current_user": get_current_user(request), **_get_grace_period_context(request)})


@app.get("/terms")
async def terms_page(request: Request):
    return templates.TemplateResponse(request, "terms.html", context={"current_user": get_current_user(request), **_get_grace_period_context(request)})


def _write_scan_index(results_dir: Path, audit_id: str, findings_data: list, scan_meta: dict) -> None:
    """Write a lightweight scan_index.json for fast dashboard reads."""
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


_USER_AUDIT_INDEX_PATH: Path = BASE_DIR / "data" / "user_audit_index.json"
_USER_AUDIT_INDEX_DIR: Path = BASE_DIR / "data" / "user_audit_index"
_user_audit_index_lock = __import__("threading").Lock()


def _user_index_file(user_id: str) -> Path:
    """Return a per-user audit index path constrained to safe filename chars."""
    safe_user = re.sub(r"[^a-zA-Z0-9_-]", "_", user_id)[:128]
    return _USER_AUDIT_INDEX_DIR / f"{safe_user}.json"


def _get_audit_owner(results_dir: Path) -> Optional[str]:
    """Read owner_user_id from scan metadata if available."""
    meta_path = results_dir / "scan_meta.json"
    if not meta_path.exists():
        return None
    try:
        with open(meta_path, "r", encoding="utf-8") as meta_file:
            meta = json.load(meta_file)
    except (json.JSONDecodeError, OSError):
        return None
    owner = meta.get("owner_user_id")
    return str(owner) if owner else None


def _update_user_audit_index(user_id: str, audit_summary: dict) -> None:
    """Append an audit summary to the per-user audit index for O(1) dashboard reads."""
    if not user_id:
        return
    with _user_audit_index_lock:
        index_path = _user_index_file(user_id)
        user_audits: List[Dict[str, Any]] = []
        if index_path.exists():
            try:
                loaded = json.loads(index_path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    user_audits = loaded
            except (json.JSONDecodeError, OSError):
                user_audits = []
        user_audits.append(audit_summary)
        index_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(user_audits, indent=2), encoding="utf-8")
        tmp.replace(index_path)


def _remove_from_user_audit_index(user_id: str, audit_id: str) -> None:
    """Remove an audit entry from the per-user audit index."""
    if not user_id:
        return
    with _user_audit_index_lock:
        index_path = _user_index_file(user_id)
        user_audits: List[Dict[str, Any]] = []
        if index_path.exists():
            try:
                loaded = json.loads(index_path.read_text(encoding="utf-8"))
                if isinstance(loaded, list):
                    user_audits = loaded
            except (json.JSONDecodeError, OSError):
                user_audits = []
        updated = [entry for entry in user_audits if entry.get("audit_id") != audit_id]
        tmp = index_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(updated, indent=2), encoding="utf-8")
        tmp.replace(index_path)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    """Per-user audit history dashboard with pagination."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/auth/login", status_code=302)

    user_id = current_user.get("id")
    audits: List[Dict] = []

    # --- Fast path: read from per-user audit index ---
    _used_user_index = False
    per_user_index = _user_index_file(str(user_id))
    if per_user_index.exists():
        try:
            _user_entries = json.loads(per_user_index.read_text(encoding="utf-8"))
            if isinstance(_user_entries, list):
                for entry in _user_entries:
                    ts = None
                    ts_raw = entry.get("timestamp", "")
                    try:
                        ts = datetime.fromisoformat(ts_raw)
                    except (ValueError, TypeError):
                        pass
                    raw_sev = entry.get("severity_counts", {})
                    audits.append({
                        "audit_id": entry.get("audit_id", ""),
                        "project_name": entry.get("project_name", "Unknown"),
                        "timestamp": ts,
                        "timestamp_display": ts.strftime("%b %d, %Y %H:%M") if ts else "N/A",
                        "severity_counts": {
                            "CRITICAL": raw_sev.get("critical", 0),
                            "HIGH": raw_sev.get("high", 0),
                            "MEDIUM": raw_sev.get("medium", 0),
                            "LOW": raw_sev.get("low", 0),
                        },
                        "risk_score": entry.get("risk_score", 0.0),
                        "has_report": True,
                    })
                _used_user_index = True
        except (json.JSONDecodeError, OSError):
            pass
    elif _USER_AUDIT_INDEX_PATH.exists():
        # Backward-compatible fallback for legacy global index format.
        try:
            _idx_data = json.loads(_USER_AUDIT_INDEX_PATH.read_text(encoding="utf-8"))
            _user_entries = _idx_data.get(user_id, [])
            if _user_entries:
                for entry in _user_entries:
                    ts = None
                    ts_raw = entry.get("timestamp", "")
                    try:
                        ts = datetime.fromisoformat(ts_raw)
                    except (ValueError, TypeError):
                        pass
                    raw_sev = entry.get("severity_counts", {})
                    audits.append({
                        "audit_id": entry.get("audit_id", ""),
                        "project_name": entry.get("project_name", "Unknown"),
                        "timestamp": ts,
                        "timestamp_display": ts.strftime("%b %d, %Y %H:%M") if ts else "N/A",
                        "severity_counts": {
                            "CRITICAL": raw_sev.get("critical", 0),
                            "HIGH": raw_sev.get("high", 0),
                            "MEDIUM": raw_sev.get("medium", 0),
                            "LOW": raw_sev.get("low", 0),
                        },
                        "risk_score": entry.get("risk_score", 0.0),
                        "has_report": True,
                    })
                _used_user_index = True
        except (json.JSONDecodeError, OSError):
            pass

    severity_weights = {
        "CRITICAL": 10.0, "HIGH": 5.0,
        "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.1,
    }

    if not _used_user_index and RESULTS_DIR.exists():
        for entry in RESULTS_DIR.iterdir():
            if not entry.is_dir():
                continue
            meta_path = entry / "scan_meta.json"
            if not meta_path.exists():
                continue
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue

            if meta.get("owner_user_id") != user_id:
                continue

            audit_id = entry.name

            # Try lightweight scan_index.json first (fast path)
            index_path = entry / "scan_index.json"
            if index_path.exists():
                try:
                    with open(index_path, "r", encoding="utf-8") as f:
                        idx = json.load(f)
                    project_name = idx.get("project_name", "Unknown")
                    timestamp_raw = idx.get("timestamp", "")
                    try:
                        ts = datetime.fromisoformat(timestamp_raw)
                    except (ValueError, TypeError):
                        ts = None
                    # scan_index stores lowercase keys
                    raw_sev = idx.get("severity_counts", {})
                    sev_counts = {
                        "CRITICAL": raw_sev.get("critical", 0),
                        "HIGH": raw_sev.get("high", 0),
                        "MEDIUM": raw_sev.get("medium", 0),
                        "LOW": raw_sev.get("low", 0),
                    }
                    risk_score = idx.get("risk_score", 0.0)
                    has_report = idx.get("has_pdf", False) or idx.get("has_html", False) or idx.get("has_md", False)
                    audits.append({
                        "audit_id": audit_id,
                        "project_name": project_name,
                        "timestamp": ts,
                        "timestamp_display": ts.strftime("%b %d, %Y %H:%M") if ts else "N/A",
                        "severity_counts": sev_counts,
                        "risk_score": risk_score,
                        "has_report": has_report,
                    })
                    continue
                except (json.JSONDecodeError, OSError):
                    pass  # Fall through to legacy path

            # Legacy fallback: read findings.json for old audits without scan_index
            project_name = meta.get("project_name", "Unknown")
            timestamp_raw = meta.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(timestamp_raw)
            except (ValueError, TypeError):
                ts = None

            sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            findings_path = entry / "findings.json"
            findings_data: list = []
            if findings_path.exists():
                try:
                    with open(findings_path, "r", encoding="utf-8") as f:
                        findings_data = json.load(f)
                    if isinstance(findings_data, list):
                        for fd in findings_data:
                            sev = fd.get("severity", "INFO")
                            if sev in sev_counts:
                                sev_counts[sev] += 1
                except (json.JSONDecodeError, OSError):
                    pass

            if findings_data:
                total_w = sum(
                    severity_weights.get(fd.get("severity", "INFO"), 0)
                    for fd in findings_data
                )
                max_w = len(findings_data) * severity_weights["CRITICAL"]
                risk_score = round(min(100.0, (total_w / max(max_w, 1.0)) * 100), 1)
            else:
                risk_score = 0.0

            has_report = (
                (entry / "report.pdf").exists()
                or (entry / "report.html").exists()
                or (entry / "report.md").exists()
            )

            audits.append({
                "audit_id": audit_id,
                "project_name": project_name,
                "timestamp": ts,
                "timestamp_display": ts.strftime("%b %d, %Y %H:%M") if ts else "N/A",
                "severity_counts": sev_counts,
                "risk_score": risk_score,
                "has_report": has_report,
            })

    # Sort by timestamp descending (None last)
    audits.sort(key=lambda a: a["timestamp"] or datetime.min, reverse=True)

    # Pagination
    page_str = request.query_params.get("page", "1")
    try:
        page = max(1, int(page_str))
    except (ValueError, TypeError):
        page = 1
    per_page = 20
    total = len(audits)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    start = (page - 1) * per_page
    page_audits = audits[start:start + per_page]

    scan_credits = 0
    if current_user:
        from webapp.user_manager import user_manager as _um
        scan_credits = _um.get_scan_credits(current_user["id"])

    return templates.TemplateResponse(
        request,
        "dashboard.html",
        context={
            "current_user": current_user,
            "audits": page_audits,
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "scan_credits": scan_credits,
            **_get_grace_period_context(request),
        },
    )

@app.post("/checkout/create-session")
async def create_checkout(request: Request):
    """Create a Stripe Checkout Session and redirect."""
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    product_key = str(form.get("product", "pro_monthly"))
    base_url = str(request.base_url).rstrip("/")
    success_url = (
        f"{base_url}/checkout/success"
        f"?session_id={{CHECKOUT_SESSION_ID}}"
    )
    cancel_url = f"{base_url}/pricing"
    session_url = create_checkout_session(
        product_key, success_url, cancel_url,
    )
    return RedirectResponse(url=session_url, status_code=303)

@app.get("/checkout/success")
async def checkout_success(request: Request):
    """Show the checkout success page with the license key."""
    session_id = request.query_params.get("session_id", "")
    license_info = get_session_license_key(session_id)

    auto_linked = False
    prompt_login = False

    if license_info:
        current_user = get_current_user(request)
        if current_user:
            # Auto-link the license to the logged-in user's account
            license_key = license_info.get("key", "")
            if license_key and not current_user.get("license_key"):
                user_manager.set_license_key(
                    current_user["id"],
                    license_key,
                    stripe_customer_id=str(license_info.get("stripe_customer_id") or ""),
                    stripe_subscription_id=str(license_info.get("stripe_subscription_id") or "")
                )
                # Store in session for immediate use (never in os.environ)
                request.session["user_license"] = license_key
                auto_linked = True
        else:
            prompt_login = True

    return templates.TemplateResponse(
        request, "checkout_success.html",
        context={
            "current_user": get_current_user(request),
            "license_key": (
                license_info.get("key", "") if license_info else ""
            ),
            "tier": (
                license_info.get("tier", "pro") if license_info else "pro"
            ),
            "email": (
                license_info.get("customer_email", "")
                if license_info else ""
            ),
            "auto_linked": auto_linked,
            "prompt_login": prompt_login,
            **_get_grace_period_context(request),
        },
    )


@app.post("/payg/checkout")
async def payg_checkout(request: Request):
    """Initiate Stripe checkout for a PAYG credit pack."""
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse("/auth/login", status_code=303)

    pack_key = str(form.get("pack_key", ""))
    if pack_key not in PAYG_PACKS:
        return JSONResponse({"error": "Invalid pack"}, status_code=400)

    base_url = os.environ.get("COUNTERSCARP_BASE_URL", str(request.base_url).rstrip("/"))
    success_url = f"{base_url}/payg/success?session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{base_url}/pricing"

    try:
        session = create_payg_checkout(
            pack_key=pack_key,
            user_email=current_user["email"],
            user_id=current_user["id"],
            success_url=success_url,
            cancel_url=cancel_url,
        )
        return RedirectResponse(session.url, status_code=303)
    except Exception:
        logger.exception("PAYG checkout failed")
        return templates.TemplateResponse(
            request, "pricing.html",
            context={
                "current_user": current_user,
                "error": "Payment processing unavailable. Please try again.",
                "stripe_key": STRIPE_PUBLISHABLE_KEY,
                "products": PRODUCTS,
                "payg_packs": PAYG_PACKS,
                "csrf_token": generate_csrf_token(request),
                **_get_grace_period_context(request),
            },
        )


@app.get("/payg/success")
async def payg_success(request: Request):
    """Post-purchase confirmation page for PAYG credit packs."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse("/auth/login", status_code=303)

    session_id = request.query_params.get("session_id", "")
    checkout_data = get_session_license_key(session_id) or {}

    credits_added = checkout_data.get("credits", 0)
    pack_key = checkout_data.get("pack_key", "")
    pack_name = PAYG_PACKS.get(pack_key, {}).get("name", "Credit Pack")

    from webapp.user_manager import user_manager as _um
    scan_credits = _um.get_scan_credits(current_user["id"])

    return templates.TemplateResponse(
        request, "payg_success.html",
        context={
            "current_user": current_user,
            "credits_added": credits_added,
            "pack_name": pack_name,
            "scan_credits": scan_credits,
            **_get_grace_period_context(request),
        },
    )


@app.post("/api/stripe/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events.

    # Stripe webhook events handled:
    # - checkout.session.completed: Initial purchase, generates license key
    # - invoice.paid: Subscription renewal, extends license expiry
    # - customer.subscription.deleted: Cancellation, revokes license
    # - invoice.payment_failed: Failed payment, flags for grace period
    # - customer.subscription.created: New subscription, logged for audit
    # - customer.subscription.updated: Tier/interval change, updates license
    # - customer.subscription.resumed: Paused subscription resumed, un-revokes license
    """
    ip = request.client.host if request.client else "unknown"

    if not _stripe_webhook_limiter.is_allowed(ip):
        resp_429 = JSONResponse(
            {"error": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(
            resp_429, _stripe_webhook_limiter, ip,
        )
        resp_429.headers["Retry-After"] = str(
            _stripe_webhook_limiter.get_reset_time(ip)
        )
        return resp_429

    if not STRIPE_WEBHOOK_SECRET:
        logger.error("Stripe webhook secret not configured — rejecting request")
        raise HTTPException(
            status_code=500,
            detail="Stripe webhook secret not configured",
        )

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature", "")

    try:
        event = _stripe.Webhook.construct_event(
            payload, sig_header, STRIPE_WEBHOOK_SECRET,
        )
    except (ValueError, _stripe.error.SignatureVerificationError) as e:
        security_logger.warning("Stripe webhook signature invalid: ip=%s", ip)
        logger.warning("Invalid Stripe webhook signature: %s", e)
        return JSONResponse({"error": "Invalid signature"}, status_code=400)

    # Atomic idempotency check-and-mark — eliminates TOCTOU race in file fallback
    if check_and_mark_event(event["id"]):
        return JSONResponse({"status": "already_processed"})

    event_type = event.get("type")

    if event_type == "checkout.session.completed":
        session = event["data"]["object"]
        handle_checkout_completed(session)

    elif event_type == "invoice.paid":
        # Subscription renewal — extend license expiry
        invoice = event["data"]["object"]
        subscription_id = invoice.get("subscription", "")
        if subscription_id:
            license_entry = find_license_by_subscription(subscription_id)
            if license_entry:
                # Determine extension period from billing_interval
                interval = license_entry.get("billing_interval", "month")
                now = datetime.now(timezone.utc)
                if interval == "year":
                    new_expiry = now + timedelta(days=365)
                else:
                    new_expiry = now + timedelta(days=30)

                update_license_in_db(license_entry["key"], {
                    "expires_at": new_expiry.strftime("%Y-%m-%d"),
                    "payment_failed_at": None,  # Clear any failed payment flag
                })
                logger.info(
                    f"License renewed: {license_entry['key'][:12]}... extended to {new_expiry.strftime('%Y-%m-%d')}"
                )
                append_audit_log(
                    "subscription_renewed",
                    license_entry["key"], "stripe_webhook", ip,
                    {"new_expiry": new_expiry.strftime("%Y-%m-%d")},
                )

    elif event_type == "customer.subscription.deleted":
        # Subscription cancelled — revoke license
        subscription = event["data"]["object"]
        subscription_id = subscription.get("id", "")
        if subscription_id:
            license_entry = find_license_by_subscription(subscription_id)
            if license_entry:
                update_license_in_db(license_entry["key"], {
                    "revoked": True,
                    "revoked_at": datetime.now(timezone.utc).isoformat(),
                    "revoke_reason": "subscription_cancelled",
                })
                logger.info(
                    f"License revoked (subscription cancelled): {license_entry['key'][:12]}..."
                )
                append_audit_log(
                    "subscription_cancelled",
                    license_entry["key"], "stripe_webhook", ip,
                    {"reason": "subscription_cancelled"},
                )

    elif event_type == "invoice.payment_failed":
        # Payment failed — flag but don't revoke immediately (grace period)
        invoice = event["data"]["object"]
        subscription_id = invoice.get("subscription", "")
        if subscription_id:
            license_entry = find_license_by_subscription(subscription_id)
            if license_entry:
                update_license_in_db(license_entry["key"], {
                    "payment_failed_at": datetime.now(timezone.utc).isoformat(),
                })
                logger.info(
                    f"Payment failed for license: {license_entry['key'][:12]}... (grace period active)"
                )
                append_audit_log(
                    "payment_failed",
                    license_entry["key"], "stripe_webhook", ip,
                    {"subscription_id": subscription_id},
                )

    elif event_type == "customer.subscription.created":
        # New subscription created — log for audit; license already generated by checkout.session.completed
        subscription = event["data"]["object"]
        subscription_id = subscription.get("id", "")
        customer_email = subscription.get("customer_email") or subscription.get("customer", "")
        logger.info(f"Subscription created: {subscription_id} for {customer_email}")

    elif event_type == "customer.subscription.updated":
        # Subscription changed (tier upgrade/downgrade, billing interval change)
        subscription = event["data"]["object"]
        subscription_id = subscription.get("id", "")
        if subscription_id:
            license_entry = find_license_by_subscription(subscription_id)
            if license_entry:
                # Determine new tier from product_key metadata on the price
                product_key = (
                    subscription.get("items", {})
                    .get("data", [{}])[0]
                    .get("price", {})
                    .get("metadata", {})
                    .get("product_key", "")
                )
                tier_map = {
                    "dev_monthly": "developer", "dev_annual": "developer",
                    "pro_monthly": "pro", "pro_annual": "pro",
                    "team_monthly": "team", "team_annual": "team",
                }
                max_activations_map = {
                    "developer": 1, "pro": 3, "team": 10,
                }
                new_tier = tier_map.get(product_key, license_entry.get("tier", "developer"))
                new_max_activations = max_activations_map.get(new_tier, 1)
                new_billing_interval = "annual" if product_key.endswith("_annual") else "monthly"

                license_key = license_entry["key"]
                update_license_in_db(license_key, {
                    "tier": new_tier,
                    "max_activations": new_max_activations,
                    "billing_interval": new_billing_interval,
                })
                logger.info(
                    f"Subscription updated: {license_key[:12]}... tier changed to {new_tier}"
                )

    elif event_type == "customer.subscription.resumed":
        # Paused subscription resumed — un-revoke license and extend expiry
        subscription = event["data"]["object"]
        subscription_id = subscription.get("id", "")
        if subscription_id:
            license_entry = find_license_by_subscription(subscription_id)
            if license_entry:
                license_key = license_entry["key"]
                # Extend expiry based on billing interval
                interval = license_entry.get("billing_interval", "monthly")
                now = datetime.now(timezone.utc)
                if interval == "annual":
                    new_expiry = now + timedelta(days=365)
                else:
                    new_expiry = now + timedelta(days=30)

                update_license_in_db(license_key, {
                    "revoked": False,
                    "revoked_at": None,
                    "revoke_reason": None,
                    "expires_at": new_expiry.strftime("%Y-%m-%d"),
                })
                logger.info(f"Subscription resumed: {license_key[:12]}...")

    resp_ok = JSONResponse({"status": "ok"})
    add_rate_limit_headers(resp_ok, _stripe_webhook_limiter, ip)
    return resp_ok

@app.get("/settings")
async def settings_page(request: Request):
    """Render the API key settings page."""
    current_user = get_current_user(request)
    if not current_user:
        return RedirectResponse(url="/auth/login", status_code=302)

    has_key = bool(os.environ.get("OPENAI_API_KEY", ""))
    masked_key = ""
    if has_key:
        key = os.environ.get("OPENAI_API_KEY", "")
        masked_key = "sk-..." + key[-4:] if len(key) > 4 else "****"

    # License context for the template
    license_tier = _license.get_tier()
    user_license_key = get_license_key_for_request(request, current_user)
    license_key_set = bool(user_license_key)
    license_masked_key = _mask_license_key(user_license_key) if user_license_key else ""
    license_features = _get_tier_features(license_tier)

    return templates.TemplateResponse(
        request, "settings.html",
        context={
            "current_user": current_user,
            "has_key": has_key,
            "masked_key": masked_key,
            "license_tier": license_tier,
            "license_key_set": license_key_set,
            "license_masked_key": license_masked_key,
            "license_features": license_features,
            "csrf_token": generate_csrf_token(request),
            **_get_grace_period_context(request),
        },
    )


@app.post("/settings/api-key")
async def save_api_key(request: Request):
    """Save the OpenAI API key to env and persist it."""
    if not get_current_user(request):
        return RedirectResponse(url="/auth/login", status_code=302)
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    api_key = str(form.get("openai_api_key", "")).strip()
    if api_key:
        os.environ["OPENAI_API_KEY"] = api_key
        # Persist to data/.env.local so it survives restarts
        env_file = Path(__file__).parent.parent / "data" / ".env.local"
        env_file.parent.mkdir(parents=True, exist_ok=True)
        # Read existing vars, update, write back
        env_vars: dict[str, str] = {}
        if env_file.exists():
            for line in env_file.read_text().splitlines():
                if "=" in line and not line.startswith("#"):
                    k, v = line.split("=", 1)
                    env_vars[k.strip()] = v.strip()
        env_vars["OPENAI_API_KEY"] = api_key
        env_file.write_text(
            "\n".join(f"{k}={v}" for k, v in env_vars.items()) + "\n"
        )
    return RedirectResponse(url="/settings?saved=1", status_code=303)


@app.post("/settings/test-key")
async def test_api_key(request: Request):
    """Quick test that the OpenAI key works."""
    if not get_current_user(request):
        return JSONResponse({"ok": False, "error": "Unauthorized"}, status_code=401)
    # Accept optional key from JSON body (for testing a new key before saving)
    body_key = None
    try:
        body = await request.json()
        body_key = body.get("key", None)
    except Exception:
        pass

    key = body_key or os.environ.get("OPENAI_API_KEY", "")
    if not key:
        return JSONResponse({"ok": False, "error": "No API key configured"})
    try:
        import openai
        client = openai.OpenAI(api_key=key)
        client.models.list()
        return JSONResponse({"ok": True, "message": "API key is valid"})
    except ImportError:
        return JSONResponse(
            {"ok": False, "error": "openai package is not installed on the server"}
        )
    except Exception as e:
        return JSONResponse({"ok": False, "error": str(e)})


def _get_grace_period_context(request: Request) -> Dict[str, Any]:
    """Compute grace period status for the current user's license.

    Returns a dict with ``grace_period_active`` and ``grace_days_remaining``
    suitable for injection into Jinja template contexts.

    Results are cached on request.state to avoid redundant DB/license lookups
    when called multiple times within the same HTTP request.
    """
    if hasattr(request.state, '_grace_period_ctx'):
        cached: Dict[str, Any] = request.state._grace_period_ctx
        return cached

    current_user = get_current_user(request)
    if not current_user:
        result: Dict[str, Any] = {"grace_period_active": False, "grace_days_remaining": None}
        request.state._grace_period_ctx = result
        return result

    license_key = get_license_key_for_request(request, current_user)
    if not license_key:
        result = {"grace_period_active": False, "grace_days_remaining": None}
        request.state._grace_period_ctx = result
        return result

    lic_entry = find_license_in_db(license_key)
    if not lic_entry:
        result = {"grace_period_active": False, "grace_days_remaining": None}
        request.state._grace_period_ctx = result
        return result

    if lic_entry.get("revoked"):
        result = {"grace_period_active": False, "grace_days_remaining": None}
        request.state._grace_period_ctx = result
        return result

    now = datetime.now(timezone.utc)

    # Check payment_failed_at first — grace window from failure date
    payment_failed_at_str = lic_entry.get("payment_failed_at")
    if payment_failed_at_str:
        try:
            failed_at = datetime.fromisoformat(
                payment_failed_at_str.replace("Z", "+00:00")
            )
            grace_end = failed_at + timedelta(days=GRACE_PERIOD_DAYS)
            if now < grace_end:
                days_left = max((grace_end - now).days, 0)
                result = {"grace_period_active": True, "grace_days_remaining": days_left}
                request.state._grace_period_ctx = result
                return result
        except (ValueError, TypeError):
            pass

    # Standard expiry grace period
    expires_at_str = lic_entry.get("expires_at")
    if expires_at_str:
        try:
            expires_at_date = date.fromisoformat(expires_at_str)
            today = date.today()
            if expires_at_date < today:
                grace_end_date = expires_at_date + timedelta(days=GRACE_PERIOD_DAYS)
                if today <= grace_end_date:
                    days_left = (grace_end_date - today).days
                    result = {"grace_period_active": True, "grace_days_remaining": days_left}
                    request.state._grace_period_ctx = result
                    return result
        except (ValueError, TypeError):
            pass

    result = {"grace_period_active": False, "grace_days_remaining": None}
    request.state._grace_period_ctx = result
    return result


@app.get("/api/license/status")
async def api_license_status(request: Request):
    """Return JSON license status including grace period info."""
    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse({
            "valid": False,
            "tier": "community",
            "expires_at": None,
            "grace_period": False,
            "grace_days_remaining": None,
        })

    license_key = get_license_key_for_request(request, current_user)
    if not license_key:
        return JSONResponse({
            "valid": False,
            "tier": "community",
            "expires_at": None,
            "grace_period": False,
            "grace_days_remaining": None,
        })

    lic_entry = find_license_in_db(license_key)
    if not lic_entry or lic_entry.get("revoked"):
        return JSONResponse({
            "valid": False,
            "tier": "community",
            "expires_at": None,
            "grace_period": False,
            "grace_days_remaining": None,
        })

    gp_ctx = _get_grace_period_context(request)
    tier = lic_entry.get("tier", "community")
    expires_at = lic_entry.get("expires_at")

    # License is valid if not expired, or if in grace period
    is_expired = False
    if expires_at:
        try:
            is_expired = date.fromisoformat(expires_at) < date.today()
        except (ValueError, TypeError):
            pass

    valid = not is_expired or gp_ctx["grace_period_active"]

    return JSONResponse({
        "valid": valid,
        "tier": tier,
        "expires_at": expires_at,
        "grace_period": gp_ctx["grace_period_active"],
        "grace_days_remaining": gp_ctx["grace_days_remaining"],
    })


@app.get("/license/status")
async def license_status(request: Request):
    """Return current license tier and available features."""
    info = _license.get_license_info()
    return {"tier": _license.get_tier(), "features": info.features}



def find_license_in_db(license_key: str) -> Optional[Dict]:
    """Look up a license entry in licenses.json by key."""
    licenses_path = Path(__file__).parent.parent / "data" / "licenses.json"
    if not licenses_path.exists():
        return None
    with open(licenses_path, "r") as f:
        data = json.load(f)
    for lic in data.get("licenses", []):
        if lic.get("key") == license_key:
            return dict(lic)
    return None


def _mask_license_key(key: str) -> str:
    """Mask a license key for display (show first 7 chars and last 4)."""
    if not key or len(key) < 12:
        return "****"
    return key[:7] + "****-****-" + key[-4:]


def _get_tier_features(tier: str) -> list[str]:
    """Get list of feature names available for a tier."""
    tier_idx = TIER_HIERARCHY.index(tier) if tier in TIER_HIERARCHY else 0
    features = []
    for feature, min_tier in FEATURE_TIERS.items():
        min_idx = TIER_HIERARCHY.index(min_tier)
        if tier_idx >= min_idx:
            features.append(FEATURE_NAMES.get(feature, feature))
    return sorted(features)


@app.post("/settings/license-key")
async def save_license_key(request: Request):
    """Save the license key to env and persist it."""
    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse({"success": False, "error": "Unauthorized"}, status_code=401)
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    license_key = str(form.get("license_key", "")).strip()

    if not license_key:
        return JSONResponse(
            {"success": False, "error": "No license key provided"},
            status_code=400,
        )

    # Validate key format
    if not any(license_key.upper().startswith(prefix) for prefix in LICENSE_PREFIXES):
        return JSONResponse(
            {
                "success": False,
                "error": "Invalid key format. Key must start with SE-DEV-, SE-PRO-, SE-TEAM-, or SE-ENT-",
            },
            status_code=400,
        )

    # Verify the key exists in licenses.json, is not revoked, and is not expired
    lic_entry = find_license_in_db(license_key)
    if not lic_entry:
        ip = request.client.host if request.client else "unknown"
        security_logger.warning(
            "License validation failed: key=%s ip=%s reason=%s",
            license_key[:10] + "...", ip, "key_not_found",
        )
        return JSONResponse(
            {"success": False, "error": "License key not found. Please check your key and try again."},
            status_code=400,
        )
    if lic_entry.get("revoked"):
        ip = request.client.host if request.client else "unknown"
        security_logger.warning(
            "License validation failed: key=%s ip=%s reason=%s",
            license_key[:10] + "...", ip, "key_revoked",
        )
        return JSONResponse(
            {"success": False, "error": "This license key has been revoked."},
            status_code=400,
        )
    expires_at = lic_entry.get("expires_at")
    if expires_at:
        try:
            if date.fromisoformat(expires_at) < date.today():
                ip = request.client.host if request.client else "unknown"
                security_logger.warning(
                    "License validation failed: key=%s ip=%s reason=%s",
                    license_key[:10] + "...", ip, "key_expired",
                )
                return JSONResponse(
                    {"success": False, "error": "This license key has expired."},
                    status_code=400,
                )
        except ValueError:
            pass

    # Ensure the key is not already linked to a different user
    existing_owner = user_manager.find_by_license_key(license_key)
    if existing_owner and existing_owner["id"] != current_user["id"]:
        ip = request.client.host if request.client else "unknown"
        security_logger.warning(
            "License validation failed: key=%s ip=%s reason=%s",
            license_key[:10] + "...", ip, "key_already_linked",
        )
        return JSONResponse(
            {"success": False, "error": "This license key is already linked to another account."},
            status_code=400,
        )

    # Persist the key to the user's account record
    user_manager.set_license_key(current_user["id"], license_key)

    # Store in the session for this user (never in os.environ)
    request.session["user_license"] = license_key

    # Clear LicenseManager cache so it picks up the new key
    _license.clear_cache()

    # Determine tier and features
    tier = _license.get_tier()
    features = _get_tier_features(tier)

    return JSONResponse(
        {
            "success": True,
            "tier": tier,
            "features": features,
        }
    )


@app.post("/settings/remove-license")
async def remove_license(request: Request):
    """Remove the license key from env and persistence."""
    current_user = get_current_user(request)
    if not current_user:
        return JSONResponse({"success": False, "error": "Unauthorized"}, status_code=401)

    # CSRF validation
    form = await request.form()
    session_token = request.session.get("_csrf_token")
    if session_token:
        csrf_token = str(form.get("_csrf_token", ""))
        if not validate_csrf_token(request, csrf_token):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    # Log deactivation attempt
    ip = request.client.host if request.client else "unknown"
    user_key = get_license_key_for_request(request, current_user)
    if user_key:
        security_logger.info(
            "License deactivation: key=%s machine=%s ip=%s",
            user_key[:10] + "...", current_user.get("id", "unknown"), ip,
        )

    # Clear the license key from the user's account record
    user_manager.clear_license_key(current_user["id"])

    # Clear license from the user's session
    request.session.pop("user_license", None)

    # Clear LicenseManager cache
    _license.clear_cache()

    return JSONResponse(
        {
            "success": True,
            "tier": "community",
        }
    )


@app.get("/settings/license-status")
async def get_license_status(request: Request):
    """Return current license status for the settings page."""
    current_user = get_current_user(request)
    # Read license key from user record, fall back to env var
    key = ""
    if current_user:
        key = current_user.get("license_key") or ""
    if not key:
        key = get_license_key_for_request(request, current_user)

    tier = _license.get_tier()
    masked_key = _mask_license_key(key) if key else ""
    features = _get_tier_features(tier)

    return JSONResponse(
        {
            "tier": tier,
            "masked_key": masked_key,
            "features": features,
        }
    )


@app.get("/results/{audit_id}/report/{format}")
async def download_report(
    request: Request,
    audit_id: str = Depends(validate_audit_id),
    format: str = "",
):
    """Download a report file."""
    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)

    format_map = {
        "html": ("report.html", "text/html"),
        "md": ("report.md", "text/markdown"),
        "sarif": ("report.sarif", "application/json"),
        "json": ("findings.json", "application/json"),
        "pdf": ("report.pdf", "application/pdf"),
    }

    if format not in format_map:
        raise HTTPException(status_code=400, detail=f"Invalid format: {format}")

    current_user = get_current_user(request)
    owner_id = _get_audit_owner(results_dir)
    if owner_id and current_user and owner_id != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if owner_id and not current_user:
        return RedirectResponse(url="/auth/login")

    filename, content_type = format_map[format]
    file_path = results_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        path=str(file_path),
        media_type=content_type,
        filename=f"counterscarp_audit_{audit_id}_{filename}",
    )


@app.get("/results/{audit_id}/attack-graph", response_class=HTMLResponse)
async def attack_graph(request: Request, audit_id: str = Depends(validate_audit_id)):
    """View the attack graph."""
    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    graph_path = results_dir / "attack_graph.html"

    if not graph_path.exists():
        raise HTTPException(status_code=404, detail="Attack graph not found")

    # Ownership check
    current_user = get_current_user(request)
    owner_id = _get_audit_owner(results_dir)
    if owner_id and current_user and owner_id != current_user["id"]:
        raise HTTPException(status_code=403, detail="Access denied")
    if owner_id and not current_user:
        return RedirectResponse(url="/auth/login")

    return FileResponse(path=str(graph_path), media_type="text/html")
