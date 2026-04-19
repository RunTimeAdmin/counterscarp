"""FastAPI web application for Sentinel Engine."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
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


def run_slither_analysis(file_path: str) -> tuple[list[Finding], str]:
    """Run Slither on a file, return findings and status.

    Gracefully degrades if Slither is not installed or times out.
    Returns a tuple of (list of Finding objects, status string).
    Status can be: 'completed', 'not_installed', 'timeout', 'error'.
    """
    try:
        # Use the slither binary from the same venv as this process
        import sys
        venv_bin = Path(sys.executable).parent
        slither_bin = str(venv_bin / "slither")

        result = subprocess.run(
            [slither_bin, file_path, "--json", "-"],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode not in (0, 1):  # 1 means findings found
            return [], "error"

        # Parse Slither JSON output
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
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except Exception:
        return [], "error"


def run_ai_copilot(
    findings: list[Finding], source_code: str,
) -> tuple[str, str]:
    """Run AI Copilot to get summary insights.

    Returns a tuple of (summary_text, status string).
    Status can be: 'completed', 'error'.
    """
    try:
        from rag_engine import AuditCopilot
        copilot = AuditCopilot()

        if not findings:
            return "No findings to analyze.", "completed"

        # Build query from findings
        query = f"Analyze these {len(findings)} security findings:\n"
        for f in findings[:10]:  # Limit to top 10 for performance
            query += f"- [{f.severity}] {f.title}: {f.description[:100]}\n"

        # Query the RAG vector store for relevant context
        results = copilot.vector_store.query(query, top_k=5)

        if not results:
            return (
                "AI Copilot: No relevant historical context "
                "found in the knowledge base.",
                "completed",
            )

        # Build summary from RAG results
        summary_parts = ["AI Audit Copilot Insights:\n"]
        for i, res in enumerate(results, 1):
            metadata = res.get("metadata", {})
            source = metadata.get("source", "unknown")
            text = res.get("text", "")
            similarity = res.get("similarity", 0)
            summary_parts.append(
                f"{i}. [Similarity: {similarity:.2f}] ({source})\n"
                f"   {text[:300]}\n"
            )

        # Enrich findings with RAG context
        findings_dicts = [
            {"rule_id": f.rule_id, "title": f.title,
             "description": f.description, "severity": f.severity}
            for f in findings
        ]
        enriched = copilot.enrich_findings_batch(findings_dicts)

        # Add remediation guidance if available
        remediations = []
        for ef in enriched:
            rem = ef.get("rag_remediation", "")
            if rem and rem not in remediations:
                remediations.append(rem)

        if remediations:
            summary_parts.append("\nRemediation Guidance:\n")
            for j, rem in enumerate(remediations[:5], 1):
                summary_parts.append(f"{j}. {rem}\n")

        return "".join(summary_parts), "completed"
    except Exception:
        return "", "error"


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

    heuristic_count = len(findings)

    # Run Slither static analysis on Solidity files
    slither_findings: list[Finding] = []
    slither_status = "skipped"
    for file_path in uploaded_paths:
        if file_path.endswith(".sol"):
            sf, status = run_slither_analysis(file_path)
            slither_findings.extend(sf)
            if status != "completed" and slither_status == "skipped":
                slither_status = status
            elif status == "completed":
                slither_status = "completed"
    findings.extend(slither_findings)

    # Run AI Audit Copilot
    ai_summary = ""
    ai_status = "skipped"
    if findings:
        ai_summary, ai_status = run_ai_copilot(findings, "")

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

    # Generate reports
    html_path = results_dir / "report.html"
    generate_html_report(
        report, str(html_path),
        logo_path=str(LOGO_PATH) if LOGO_PATH.exists() else None,
    )

    md_path = results_dir / "report.md"
    generate_markdown_report(report, str(md_path))

    sarif_path = results_dir / "report.sarif"
    sarif_metadata = {
        "project_name": project_name,
        "target_path": str(upload_dir),
        "timestamp": report.timestamp,
    }
    save_sarif_report(findings, str(sarif_path), sarif_metadata)

    # Generate attack graph (before scan_meta so status is accurate)
    attack_graph_generated = False
    if findings:
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
            # Attack graph is optional
            pass

    # Save scan metadata (coverage / what was checked)
    findings_per_category: dict[str, int] = {}
    for cat, rule_ids in RULE_CATEGORIES.items():
        findings_per_category[cat] = sum(
            1 for fd in findings_data if fd["rule_id"] in rule_ids
        )

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
        {
            "name": "AI Audit Copilot",
            "status": ai_status,
            "findings_count": 0,
        },
    ]
    if findings:
        analyzers_list.append({
            "name": "Attack Graph Generator",
            "status": "completed" if attack_graph_generated else "skipped",
            "findings_count": 0,
        })

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
        "analyzers": analyzers_list,
        "rules_triggered": sorted(
            set(f["rule_id"] for f in findings_data)
        ),
    }

    meta_path = results_dir / "scan_meta.json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(scan_meta, f, indent=2)

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
            "ai_summary": ai_summary,
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
