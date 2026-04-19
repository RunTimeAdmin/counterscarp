"""FastAPI web application for Sentinel Engine."""

from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import List

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from webapp.config import (
    ALLOWED_EXTENSIONS,
    BASE_DIR,
    LOGO_PATH,
    MAX_FILE_SIZE,
    RESULTS_DIR,
    TEMPLATES_DIR,
    UPLOAD_DIR,
)

# Import Sentinel Engine modules
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
from attack_graph import build_graph, export_graph_json
from visualizer import generate_attack_graph_html

app = FastAPI(
    title="Sentinel Engine",
    description="Smart Contract Security Audit Platform",
    version="2.3.0",
)

# Mount static files
app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")

# Templates
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


def ensure_directories():
    """Ensure required directories exist."""
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def heuristic_finding_to_finding(hf: HeuristicFinding) -> Finding:
    """Convert HeuristicFinding to Finding."""
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


@app.on_event("startup")
async def startup_event():
    """Initialize on startup."""
    ensure_directories()


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render the upload page."""
    return templates.TemplateResponse(request, "upload.html")


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

    # Save uploaded files
    uploaded_paths = []
    for file in valid_files:
        file_path = upload_dir / file.filename
        content = await file.read()

        # Check file size
        if len(content) > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=400,
                detail=f"File too large: {file.filename} (max {MAX_FILE_SIZE // 1024 // 1024}MB)"
            )

        with open(file_path, "wb") as f:
            f.write(content)
        uploaded_paths.append(str(file_path))

    # Run heuristic scanner
    findings: List[Finding] = []
    for file_path in uploaded_paths:
        heuristic_findings = scan_target(file_path)
        for hf in heuristic_findings:
            findings.append(heuristic_finding_to_finding(hf))

    # Create audit report
    report = create_audit_report(
        project_name=project_name,
        target_path=str(upload_dir),
        findings=findings,
    )

    # Save findings as JSON
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
    with open(findings_path, "w", encoding="utf-8") as f:
        json.dump(findings_data, f, indent=2)

    # Save scan metadata (coverage / what was checked)
    findings_per_category: dict[str, int] = {}
    for cat, rule_ids in RULE_CATEGORIES.items():
        findings_per_category[cat] = sum(
            1 for fd in findings_data if fd["rule_id"] in rule_ids
        )

    scan_meta = {
        "project_name": project_name,
        "timestamp": datetime.now().isoformat(),
        "files_scanned": len(uploaded_paths),
        "total_source_lines": sum(
            len(
                open(fp, encoding="utf-8", errors="ignore").readlines()
            )
            for fp in uploaded_paths
        ),
        "analyzers": [
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
                "findings_count": len(findings),
            },
            {
                "name": "Attack Graph Generator",
                "status": (
                    "completed"
                    if (results_dir / "attack_graph.html").exists()
                    else "skipped"
                ),
                "findings_count": 0,
            },
            {
                "name": "Slither Static Analysis",
                "status": "not_configured",
                "findings_count": 0,
            },
            {
                "name": "Aderyn Analyzer",
                "status": "not_configured",
                "findings_count": 0,
            },
            {
                "name": "AI Audit Copilot",
                "status": "not_configured",
                "findings_count": 0,
            },
        ],
        "rules_triggered": sorted(
            set(f["rule_id"] for f in findings_data)
        ),
    }

    meta_path = results_dir / "scan_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(scan_meta, f, indent=2)

    # Generate reports
    html_path = results_dir / "report.html"
    generate_html_report(report, str(html_path), logo_path=str(LOGO_PATH) if LOGO_PATH.exists() else None)

    md_path = results_dir / "report.md"
    generate_markdown_report(report, str(md_path))

    sarif_path = results_dir / "report.sarif"
    metadata = {
        "project_name": project_name,
        "target_path": str(upload_dir),
        "timestamp": report.timestamp,
    }
    save_sarif_report(findings, str(sarif_path), metadata)

    # Generate attack graph
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
    except Exception:
        # Attack graph is optional
        pass

    return RedirectResponse(url=f"/results/{audit_id}", status_code=303)


@app.get("/results/{audit_id}", response_class=HTMLResponse)
async def results(request: Request, audit_id: str):
    """Display audit results."""
    results_dir = RESULTS_DIR / audit_id
    findings_path = results_dir / "findings.json"

    if not findings_path.exists():
        raise HTTPException(status_code=404, detail="Audit not found")

    # Load findings
    with open(findings_path, "r", encoding="utf-8") as f:
        findings_data = json.load(f)

    # Calculate severity counts
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings_data:
        severity = finding.get("severity", "INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # Calculate risk score
    severity_weights = {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.1}
    total_weight = sum(severity_weights.get(f.get("severity", "INFO"), 0) for f in findings_data)
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

    # Load scan metadata
    meta_path = results_dir / "scan_meta.json"
    scan_meta = {}
    if meta_path.exists():
        with open(meta_path, "r", encoding="utf-8") as f:
            scan_meta = json.load(f)

    return templates.TemplateResponse(
        request,
        "results.html",
        context={
            "audit_id": audit_id,
            "findings": findings_data,
            "severity_counts": severity_counts,
            "total_findings": len(findings_data),
            "risk_score": risk_score,
            "pass_fail": pass_fail,
            "attack_graph_exists": attack_graph_exists,
            "scan_meta": scan_meta,
        },
    )


@app.get("/results/{audit_id}/report/{format}")
async def download_report(audit_id: str, format: str):
    """Download a report file."""
    results_dir = RESULTS_DIR / audit_id

    format_map = {
        "html": ("report.html", "text/html"),
        "md": ("report.md", "text/markdown"),
        "sarif": ("report.sarif", "application/json"),
        "json": ("findings.json", "application/json"),
    }

    if format not in format_map:
        raise HTTPException(status_code=400, detail=f"Invalid format: {format}")

    filename, content_type = format_map[format]
    file_path = results_dir / filename

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(
        path=str(file_path),
        media_type=content_type,
        filename=f"sentinel_audit_{audit_id}_{filename}",
    )


@app.get("/results/{audit_id}/attack-graph", response_class=HTMLResponse)
async def attack_graph(audit_id: str):
    """View the attack graph."""
    results_dir = RESULTS_DIR / audit_id
    graph_path = results_dir / "attack_graph.html"

    if not graph_path.exists():
        raise HTTPException(status_code=404, detail="Attack graph not found")

    with open(graph_path, "r", encoding="utf-8") as f:
        content = f.read()

    return HTMLResponse(content=content)
