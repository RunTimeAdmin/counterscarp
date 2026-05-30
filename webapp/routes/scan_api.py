"""Machine-facing scan API (v1) for agents and integrations."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field, field_validator

from webapp.api_auth import ApiClient, require_api_client
from webapp.config import ALLOWED_EXTENSIONS, MAX_FILE_SIZE, RESULTS_DIR, UPLOAD_DIR
from webapp.rate_limiter import add_rate_limit_headers

router = APIRouter(prefix="/api/v1", tags=["scan-api"])

MAX_API_FILES = 10


class ScanFileInput(BaseModel):
    filename: str = Field(..., min_length=1, max_length=120)
    content: str = Field(..., max_length=MAX_FILE_SIZE)


class ScanCreateRequest(BaseModel):
    project_name: str = Field(default="API Scan", max_length=200)
    files: List[ScanFileInput] = Field(
        ...,
        min_length=1,
        max_length=MAX_API_FILES,
    )

    @field_validator("files")
    @classmethod
    def validate_file_extensions(
        cls,
        files: List[ScanFileInput],
    ) -> List[ScanFileInput]:
        for item in files:
            ext = Path(item.filename).suffix.lower()
            if ext not in ALLOWED_EXTENSIONS:
                allowed = ", ".join(sorted(ALLOWED_EXTENSIONS))
                raise ValueError(
                    f"Invalid file type: {item.filename}. "
                    f"Allowed: {allowed}"
                )
        return files


def _normalize_audit_id(audit_id: str) -> str:
    try:
        return str(uuid.UUID(audit_id))
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail="Invalid audit ID format",
        ) from exc


def _resolve_audit_dir(base_dir: Path, audit_id: str) -> Path:
    normalized_id = _normalize_audit_id(audit_id)
    resolved = (base_dir / normalized_id).resolve()
    base_resolved = base_dir.resolve()
    if not resolved.is_relative_to(base_resolved):
        raise HTTPException(status_code=403, detail="Access denied")
    return resolved


def _safe_filename(name: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]", "_", Path(name).name)[:100]


def _count_source_lines(content: str) -> int:
    if not content:
        return 0
    lines = content.count("\n")
    if not content.endswith("\n"):
        lines += 1
    return lines


def _write_source_file(destination: Path, content: str) -> int:
    encoded = content.encode("utf-8")
    if len(encoded) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=400,
            detail=(
                f"File too large: {destination.name} "
                f"(max {MAX_FILE_SIZE // 1024 // 1024}MB)"
            ),
        )
    try:
        destination.write_text(content, encoding="utf-8")
    except UnicodeEncodeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"File {destination.name} is not valid UTF-8 text",
        ) from exc
    return _count_source_lines(content)


def _load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _assert_api_access(results_dir: Path, client: ApiClient) -> None:
    meta_path = results_dir / "scan_meta.json"
    if not meta_path.exists():
        raise HTTPException(status_code=404, detail="Scan not found")
    meta = _load_json(meta_path)
    owner = meta.get("api_client")
    if owner and owner != client.client_id:
        raise HTTPException(status_code=403, detail="Access denied")


def _build_scan_response(
    audit_id: str,
    results_dir: Path,
    *,
    include_findings: bool = False,
    base_url: str = "",
) -> dict[str, Any]:
    status_path = results_dir / "scan_status.json"
    meta_path = results_dir / "scan_meta.json"
    findings_path = results_dir / "findings.json"
    ai_path = results_dir / "ai_summary.txt"

    payload: dict[str, Any] = {"audit_id": audit_id}

    if status_path.exists():
        payload.update(_load_json(status_path))
    elif findings_path.exists():
        payload["status"] = "complete"
        payload["progress"] = "Scan complete"
    else:
        payload["status"] = "unknown"
        payload["progress"] = "No status available"

    if meta_path.exists():
        meta = _load_json(meta_path)
        payload["project_name"] = meta.get("project_name")
        payload["files_scanned"] = meta.get("files_scanned")
        payload["analyzers"] = meta.get("analyzers")

    if payload.get("status") == "complete" and findings_path.exists():
        from webapp.scan_utils import summarize_findings_data

        findings_data = _load_json(findings_path)
        if not isinstance(findings_data, list):
            findings_data = []
        summary = summarize_findings_data(findings_data)
        payload["summary"] = {
            "risk_score": summary["risk_score"],
            "severity_counts": summary["severity_counts_lower"],
            "total_findings": summary["total_findings"],
        }
        if include_findings:
            payload["findings"] = findings_data
        prefix = f"{base_url}/api/v1/scan/{audit_id}/report"
        payload["report_urls"] = {
            "json": f"{prefix}/json",
            "md": f"{prefix}/md",
            "html": f"{prefix}/html",
            "sarif": f"{prefix}/sarif",
        }

    if ai_path.exists():
        payload["ai_summary"] = ai_path.read_text(encoding="utf-8")

    return payload


@router.get("/scan/{audit_id}/summary")
async def get_scan_summary(
    request: Request,
    audit_id: str,
    client: ApiClient = Depends(require_api_client),
):
    """Plain-text scan summary for agents — paste curl output directly into chat."""
    from webapp.scan_utils import format_agent_scan_summary, summarize_findings_data

    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    if not results_dir.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    _assert_api_access(results_dir, client)
    base = str(request.base_url).rstrip("/")

    status_path = results_dir / "scan_status.json"
    meta_path = results_dir / "scan_meta.json"
    findings_path = results_dir / "findings.json"

    status = "unknown"
    if status_path.exists():
        status = _load_json(status_path).get("status", "unknown")
    elif findings_path.exists():
        status = "complete"

    project_name = audit_id
    analyzers = None
    if meta_path.exists():
        meta = _load_json(meta_path)
        project_name = meta.get("project_name") or project_name
        analyzers = meta.get("analyzers")

    findings_data: list = []
    summary = None
    if findings_path.exists():
        raw = _load_json(findings_path)
        if isinstance(raw, list):
            findings_data = raw
            summary = summarize_findings_data(findings_data)

    text = format_agent_scan_summary(
        audit_id,
        project_name=project_name,
        status=status,
        findings_data=findings_data,
        summary=summary,
        analyzers=analyzers,
        base_url=base,
    )

    if status in {"pending", "running", "queued"}:
        return PlainTextResponse(text, status_code=202)
    return PlainTextResponse(text, status_code=200)


@router.post("/scan")
async def create_scan(
    request: Request,
    body: ScanCreateRequest,
    client: ApiClient = Depends(require_api_client),
):
    """Submit contract source files for an async security scan."""
    limiter = request.app.state.api_scan_limiter
    if not limiter.is_allowed(client.client_id):
        resp = JSONResponse(
            {"detail": "Rate limit exceeded. Try again later."},
            status_code=429,
        )
        add_rate_limit_headers(resp, limiter, client.client_id)
        resp.headers["Retry-After"] = str(
            limiter.get_reset_time(client.client_id)
        )
        return resp

    audit_id = str(uuid.uuid4())
    upload_dir = UPLOAD_DIR / audit_id
    results_dir = RESULTS_DIR / audit_id
    upload_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    uploaded_paths: list[str] = []
    total_source_lines = 0
    for item in body.files:
        safe_name = _safe_filename(item.filename)
        file_path = upload_dir / safe_name
        total_source_lines += _write_source_file(file_path, item.content)
        uploaded_paths.append(str(file_path))

    started_at = datetime.now(timezone.utc).isoformat()
    status_payload = {
        "status": "pending",
        "progress": "Queued...",
        "started_at": started_at,
    }
    status_path = results_dir / "scan_status.json"
    status_path.write_text(
        json.dumps(status_payload, indent=2),
        encoding="utf-8",
    )

    pre_meta = {
        "project_name": body.project_name,
        "owner_user_id": None,
        "api_client": client.client_id,
        "source": "api_v1",
        "files_scanned": len(uploaded_paths),
        "total_source_lines": total_source_lines,
    }
    pre_meta_path = results_dir / "scan_meta.json"
    pre_meta_path.write_text(
        json.dumps(pre_meta, indent=2),
        encoding="utf-8",
    )

    arq_pool = getattr(request.app.state, "arq_pool", None)
    if arq_pool is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Scan queue unavailable. Configure REDIS_URL "
                "and run the arq worker."
            ),
        )

    await arq_pool.enqueue_job(
        "run_audit",
        audit_id,
        uploaded_paths,
        "",
        "",
    )

    base = str(request.base_url).rstrip("/")
    response = JSONResponse(
        {
            "audit_id": audit_id,
            "status": "pending",
            "status_url": f"{base}/api/v1/scan/{audit_id}",
            "summary_url": f"{base}/api/v1/scan/{audit_id}/summary",
            "poll_interval_seconds": 5,
        },
        status_code=202,
    )
    add_rate_limit_headers(response, limiter, client.client_id)
    return response


@router.get("/scan/{audit_id}")
async def get_scan(
    request: Request,
    audit_id: str,
    include_findings: bool = Query(default=False),
    client: ApiClient = Depends(require_api_client),
):
    """Poll scan status and retrieve results when complete."""
    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    if not results_dir.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    _assert_api_access(results_dir, client)
    base = str(request.base_url).rstrip("/")
    return _build_scan_response(
        audit_id,
        results_dir,
        include_findings=include_findings,
        base_url=base,
    )


@router.get("/scan/{audit_id}/report/{format}")
async def download_scan_report(
    audit_id: str,
    format: str,
    client: ApiClient = Depends(require_api_client),
):
    """Download a generated report for a completed API scan."""
    audit_id = _normalize_audit_id(audit_id)
    results_dir = _resolve_audit_dir(RESULTS_DIR, audit_id)
    if not results_dir.exists():
        raise HTTPException(status_code=404, detail="Scan not found")

    _assert_api_access(results_dir, client)

    format_map = {
        "html": ("report.html", "text/html"),
        "md": ("report.md", "text/markdown"),
        "sarif": ("report.sarif", "application/json"),
        "json": ("findings.json", "application/json"),
    }
    if format not in format_map:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid format: {format}",
        )

    filename, content_type = format_map[format]
    file_path = results_dir / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        path=str(file_path),
        media_type=content_type,
        filename=f"counterscarp_audit_{audit_id}_{filename}",
    )
