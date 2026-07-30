"""Shared scan orchestration utilities.

This module contains scan logic shared between the async worker (worker.py)
and the synchronous fallback path in the web application (main.py).

IMPORTANT: This module must NOT import from webapp.main or webapp.worker
to avoid circular dependencies.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

from heuristic_scanner import (
    HeuristicFinding,
    RULE_CATEGORIES,
    HEURISTIC_RULES,
)
from report_generator import (
    AuditReport,
    Finding,
    generate_html_report,
    generate_markdown_report,
    save_sarif_report,
)

try:
    from report_generator import generate_pdf_report as _generate_pdf_report_impl

    def generate_pdf_report(
        report: AuditReport, output_path: str, logo_path: str | None = None
    ) -> None:
        _generate_pdf_report_impl(report, output_path, logo_path=logo_path)
except (ImportError, AttributeError):

    def generate_pdf_report(
        report: AuditReport, output_path: str, logo_path: str | None = None
    ) -> None:
        raise RuntimeError("generate_pdf_report is not available in this environment")


from attack_graph import build_graph, export_graph_json
from visualizer import generate_attack_graph_html
from logger import get_logger
from counterscarp_core.severity import SEVERITY_RANK as _SEVERITY_ORDER
from counterscarp_core.severity_scoring import (
    SEVERITY_WEIGHTS,
    empty_counts,
    normalize_counts,
    risk_score_from_findings,
    pass_fail_from_counts,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------


def heuristic_finding_to_finding(hf: HeuristicFinding) -> Finding:
    """Convert a HeuristicFinding to a report Finding."""
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


def count_lines(path: str) -> int:
    """Count lines in a file using binary chunks."""
    chunk_size = 1024 * 1024
    total_newlines = 0
    with open(path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            total_newlines += chunk.count(b"\n")
    return total_newlines


def summarize_findings_data(findings_data: list[dict]) -> dict:
    """Compute severity counts and normalized risk score in one pass."""
    severity_counts_lower = empty_counts(lowercase=True)
    for finding in findings_data:
        sev_key = str(finding.get("severity", "INFO")).lower()
        if sev_key in severity_counts_lower:
            severity_counts_lower[sev_key] += 1

    return {
        "severity_counts_lower": severity_counts_lower,
        "risk_score": risk_score_from_findings(findings_data),
        "total_findings": len(findings_data),
    }


# _SEVERITY_ORDER imported from counterscarp_core.severity above

SCAN_DISCLAIMER = (
    "Disclaimer: Automated scan only — not a formal audit or investment advice. "
    "Results may include false positives or false negatives; verify before mainnet."
)


def _format_scan_footer(
    lines: list[str],
    audit_id: str,
    base_url: str,
) -> None:
    lines.extend(
        [
            "",
            SCAN_DISCLAIMER,
            "",
            f"Full report: {base_url}/api/v1/scan/{audit_id}/report/html",
            "Run your own scan: https://app.counterscarp.io",
        ]
    )


def format_agent_scan_summary(
    audit_id: str,
    *,
    project_name: str,
    status: str,
    findings_data: list[dict],
    summary: dict | None = None,
    analyzers: list[dict] | None = None,
    base_url: str = "https://app.counterscarp.io",
) -> str:
    """Plain-text scan summary for agents (OpenClaw, curl, chat paste)."""
    if status in {"pending", "running", "queued"}:
        return (
            f"Scan still running (status: {status}). "
            f"Poll again: GET {base_url}/api/v1/scan/{audit_id}/summary"
        )

    if status == "failed":
        return (
            f"ScarpShield scan failed — {project_name}\n"
            f"Audit ID: {audit_id}\n\n"
            "The scan did not complete. Do not treat this as a valid deliverable.\n"
            "Retry the scan or use https://app.counterscarp.io"
        )

    stats = summary or summarize_findings_data(findings_data)
    counts = stats.get("severity_counts_lower") or {}
    info_count = sum(
        1 for f in findings_data if str(f.get("severity", "")).upper() == "INFO"
    )
    crit = counts.get("critical", 0)
    high = counts.get("high", 0)
    med = counts.get("medium", 0)
    low = counts.get("low", 0)
    risk = stats.get("risk_score", 0)
    total = stats.get("total_findings", len(findings_data))

    lines = [
        f"ScarpShield scan complete — {project_name}",
        f"Audit ID: {audit_id}",
        "",
    ]
    lines.extend(_format_tests_run_section(analyzers))

    if total == 0:
        lines.extend(
            [
                "Risk score: 0/100 | No issues detected by Counterscarp at scan time.",
            ]
        )
        _format_scan_footer(lines, audit_id, base_url)
        return "\n".join(lines)

    count_tail = f"({crit} critical, {high} high, {med} medium, {low} low"
    if info_count:
        count_tail += f", {info_count} info"
    count_tail += ")"

    lines.extend(
        [
            f"Risk score: {risk}/100 | {total} findings {count_tail}",
            "",
            "Top issues:",
        ]
    )

    ranked = sorted(
        findings_data,
        key=lambda f: (
            _SEVERITY_ORDER.get(str(f.get("severity", "INFO")).upper(), 99),
            str(f.get("title", "")),
        ),
    )
    for idx, finding in enumerate(ranked[:5], start=1):
        sev = str(finding.get("severity", "INFO")).upper()
        title = finding.get("title") or finding.get("rule_id", "Finding")
        line_no = finding.get("line_no") or "?"
        desc = (finding.get("description") or "").split("\n")[0].strip()
        if len(desc) > 120:
            desc = desc[:117] + "..."
        detail = desc or title
        lines.append(f"{idx}. [{sev}] {title} — {detail} (line {line_no})")

    _format_scan_footer(lines, audit_id, base_url)
    return "\n".join(lines)


def build_acp_deliverable(
    audit_id: str,
    *,
    project_name: str,
    status: str,
    findings_data: list[dict],
    summary: dict | None = None,
    analyzers: list[dict] | None = None,
    base_url: str = "https://app.counterscarp.io",
) -> dict:
    """Structured JSON deliverable for ACP jobs and payment evaluation."""
    summary_text = format_agent_scan_summary(
        audit_id,
        project_name=project_name,
        status=status,
        findings_data=findings_data,
        summary=summary,
        analyzers=analyzers,
        base_url=base_url,
    )
    stats = summary or summarize_findings_data(findings_data)
    deliverable_valid = summary_text.startswith("ScarpShield scan complete")
    prefix = f"{base_url}/api/v1/scan/{audit_id}/report"

    return {
        "audit_id": audit_id,
        "project_name": project_name,
        "status": status,
        "deliverable_valid": deliverable_valid,
        "summary_text": summary_text,
        "disclaimer": SCAN_DISCLAIMER,
        "risk_score": stats.get("risk_score", 0),
        "findings_count": stats.get("total_findings", len(findings_data)),
        "severity_counts": stats.get("severity_counts_lower", {}),
        "report_urls": {
            "html": f"{prefix}/html",
            "md": f"{prefix}/md",
            "json": f"{prefix}/json",
            "sarif": f"{prefix}/sarif",
        },
        "summary_url": f"{base_url}/api/v1/scan/{audit_id}/summary",
    }


# ---------------------------------------------------------------------------
# Slither analysis
# ---------------------------------------------------------------------------

_PROJECT_MARKERS = (
    "foundry.toml",
    "hardhat.config.js",
    "hardhat.config.ts",
    "truffle-config.js",
    "truffle.js",
)


def _resolve_slither_bin() -> str:
    """Resolve Slither from the active venv, then PATH."""
    venv_bin = Path(sys.executable).parent
    for name in ("slither.exe", "slither"):
        candidate = venv_bin / name
        if candidate.exists():
            return str(candidate)
    return shutil.which("slither") or "slither"


def _is_slither_project_dir(path: Path) -> bool:
    return any((path / marker).exists() for marker in _PROJECT_MARKERS)


def _parse_slither_json(stdout: str) -> dict:
    """Parse Slither JSON output, tolerating leading log lines."""
    text = (stdout or "").strip()
    if not text:
        return {}
    json_start = text.find("{")
    if json_start == -1:
        return {}
    payload = text[json_start:]
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        brace_count = 0
        end_idx = -1
        for i, ch in enumerate(payload):
            if ch == "{":
                brace_count += 1
            elif ch == "}":
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        if end_idx != -1:
            return json.loads(payload[:end_idx])
        raise


def _slither_detectors_to_findings(detectors: list) -> list[Finding]:
    slither_findings: list[Finding] = []
    severity_map = {
        "High": "HIGH",
        "Medium": "MEDIUM",
        "Low": "LOW",
        "Informational": "INFO",
        "Optimization": "INFO",
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

        slither_findings.append(
            Finding(
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
        )

    return slither_findings


def _invoke_slither(
    args: list[str],
    *,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONWARNINGS"] = "ignore"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(
        [_resolve_slither_bin(), *args],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=cwd,
        env=env,
    )


def _slither_stdout_to_findings(stdout: str) -> list[Finding] | None:
    """Parse Slither JSON stdout; return findings or None if output unusable."""
    if not (stdout or "").strip():
        return None
    try:
        data = _parse_slither_json(stdout)
    except json.JSONDecodeError:
        return None
    if data.get("success") is False and data.get("error"):
        return None
    if "results" not in data:
        return None
    detectors = data.get("results", {}).get("detectors", [])
    return _slither_detectors_to_findings(detectors)


def _run_slither_on_file(resolved: Path) -> tuple[list[Finding], str]:
    """Run Slither on a single .sol file with solc fallback."""
    attempts: list[tuple[list[str], str | None]] = [
        (["--json", "-", str(resolved.name)], str(resolved.parent)),
        (["--json", "-", "--compile-force-framework", "solc", str(resolved.name)], str(resolved.parent)),
        (["--json", "-", "--", str(resolved)], None),
        (["--json", "-", "--compile-force-framework", "solc", str(resolved)], None),
    ]
    last_stderr = ""

    for args, cwd in attempts:
        try:
            result = _invoke_slither(args, cwd=cwd)
        except FileNotFoundError:
            return [], "not_installed"
        except subprocess.TimeoutExpired:
            return [], "timeout"

        last_stderr = result.stderr or last_stderr
        findings = _slither_stdout_to_findings(result.stdout)
        if findings is not None:
            return findings, "completed"

    logger.warning(
        "Slither failed on %s (last stderr: %s)",
        resolved,
        (last_stderr or "none")[:500],
    )
    return [], "error"


def run_slither_analysis(
    file_path: str, upload_dir: Path | None = None
) -> tuple[list[Finding], str]:
    """Run Slither on a file or upload directory, return findings and status.

    Gracefully degrades if Slither is not installed or times out.
    Returns a tuple of (list of Finding objects, status string).
    Status can be: 'completed', 'not_installed', 'timeout', 'error', 'skipped'.

    For bare upload directories (API single-file scans without Foundry/Hardhat),
    runs Slither per .sol file instead of treating the folder as a project root.
    """
    try:
        resolved = Path(file_path).resolve()

        if upload_dir is not None:
            upload_dir_resolved = Path(upload_dir).resolve()
            if not resolved.is_relative_to(upload_dir_resolved):
                raise ValueError("Invalid file path: outside upload directory")

        if resolved.is_dir():
            if _is_slither_project_dir(resolved):
                try:
                    result = _invoke_slither(["--json", "-", "--", str(resolved)])
                except FileNotFoundError:
                    return [], "not_installed"
                except subprocess.TimeoutExpired:
                    return [], "timeout"

                findings = _slither_stdout_to_findings(result.stdout)
                if findings is not None:
                    return findings, "completed"

                logger.warning(
                    "Slither project mode failed on %s, falling back to per-file solc",
                    resolved,
                )

            sol_files = sorted(resolved.glob("*.sol"))
            if not sol_files:
                return [], "skipped"

            all_findings: list[Finding] = []
            any_completed = False
            for sol_file in sol_files:
                findings, status = _run_slither_on_file(sol_file)
                all_findings.extend(findings)
                if status == "completed":
                    any_completed = True
                elif status == "not_installed":
                    return [], "not_installed"
                elif status == "timeout":
                    return [], "timeout"

            return all_findings, "completed" if any_completed else "error"

        if resolved.suffix.lower() != ".sol":
            return [], "skipped"

        return _run_slither_on_file(resolved)
    except ValueError:
        raise
    except FileNotFoundError:
        return [], "not_installed"
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except Exception as exc:
        logger.warning("Slither unexpected error on %s: %s", file_path, exc)
        return [], "error"


# ---------------------------------------------------------------------------
# Protocol fingerprint + fork logic
# ---------------------------------------------------------------------------

API_SCAN_NOT_INCLUDED = (
    "Mythril symbolic execution, Medusa fuzzing, Aderyn static analysis, "
    "supply-chain OSV (available in full CLI/Docker audit)"
)


def _analyzer_status_label(status: str) -> str:
    return {
        "completed": "completed",
        "error": "failed",
        "skipped": "skipped",
        "not_installed": "not available",
        "pro_required": "pro only",
    }.get(status, status)


def _format_tests_run_section(analyzers: list[dict] | None) -> list[str]:
    """Human-readable list of engines executed for this scan."""
    lines = ["Tests run:"]

    if not analyzers:
        lines.append("• Heuristic Pattern Scanner — status unknown")
        lines.append("• Protocol Fingerprint Scanner — status unknown")
        lines.append("• Slither Static Analysis — status unknown")
        lines.append("• AI Audit Copilot — status unknown")
        lines.append("• Attack Graph Generator — status unknown")
    else:
        for analyzer in analyzers:
            name = analyzer.get("name", "Analyzer")
            status = _analyzer_status_label(analyzer.get("status", "unknown"))
            details: list[str] = []

            if "Heuristic" in name:
                patterns = analyzer.get("patterns_checked")
                if patterns:
                    details.append(f"{patterns} patterns")
                categories = analyzer.get("categories") or {}
                if categories:
                    details.append(f"{len(categories)} categories")
                count = analyzer.get("findings_count", 0)
                details.append(f"{count} finding{'s' if count != 1 else ''}")
            elif "Fingerprint" in name or "Protocol" in name:
                protocols = analyzer.get("protocols_checked", 0)
                matches = analyzer.get("matches_found", 0)
                if protocols:
                    details.append(f"{protocols} protocol fingerprints")
                details.append(f"{matches} protocol match{'es' if matches != 1 else ''}")
                count = analyzer.get("findings_count", 0)
                if count:
                    details.append(f"{count} finding{'s' if count != 1 else ''}")
            elif "Slither" in name:
                details.append("Slither detector suite")
                count = analyzer.get("findings_count", 0)
                details.append(f"{count} finding{'s' if count != 1 else ''}")
            elif "AI" in name:
                details.append("RAG enrichment on findings")
            elif "Attack" in name:
                details.append("attack-path visualization")

            suffix = f" ({', '.join(details)})" if details else ""
            lines.append(f"• {name} — {status}{suffix}")
            err = analyzer.get("error")
            if err and status in ("failed", "error"):
                lines.append(f"    ↳ {err}")

    lines.extend(["", f"Not included in this scan: {API_SCAN_NOT_INCLUDED}", ""])
    return lines


def _protocol_slug(name: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "-", name.upper()).strip("-")
    return slug[:48] or "UNKNOWN"


def run_protocol_fingerprint_analysis(
    file_paths: list[str],
    *,
    min_similarity: float = 0.5,
) -> tuple[list[Finding], str, dict]:
    """Match .sol files to known protocol forks and run fork-specific checks."""
    try:
        from fingerprint_scanner import scan_for_protocol_similarity
        from fork_logic_checks import run_fork_checks
        from protocol_db import get_default_fingerprints
    except ImportError:
        return [], "not_installed", {}

    findings: list[Finding] = []
    match_count = 0
    protocols_checked = len(get_default_fingerprints())

    for fp_str in file_paths:
        if not fp_str.endswith(".sol"):
            continue
        try:
            source = Path(fp_str).read_text(encoding="utf-8")
        except OSError as exc:
            logger.warning("Fingerprint skipped %s: %s", fp_str, exc)
            continue

        try:
            matches = scan_for_protocol_similarity(
                fp_str,
                min_similarity=min_similarity,
            )
        except Exception as exc:
            logger.warning("Fingerprint failed on %s: %s", fp_str, exc)
            continue

        if not matches:
            continue

        match_count += len(matches)
        top = matches[0]
        confidence = float(top.get("confidence", 0))
        protocol = str(top.get("protocol", "Unknown"))
        known = top.get("known_vulnerabilities") or []
        high_crit = sum(
            1
            for item in known
            if str(item.get("severity", "")).upper() in {"CRITICAL", "HIGH"}
        )

        if confidence >= min_similarity:
            severity = "INFO"
            if high_crit >= 2:
                severity = "HIGH"
            elif high_crit >= 1:
                severity = "MEDIUM"

            checks = top.get("recommended_checks") or []
            description = str(top.get("risk_assessment", ""))
            if checks:
                description += "\n\nInherited fork risks to review:\n" + "\n".join(
                    f"- {item}" for item in checks[:3]
                )

            findings.append(
                Finding(
                    rule_id=f"PROTOCOL-MATCH-{_protocol_slug(protocol)}",
                    severity=severity,
                    category="Protocol Fingerprint",
                    title=f"Similar to {protocol} ({confidence:.0%} match)",
                    description=description,
                    file=Path(fp_str).name,
                    line_no=0,
                    code_snippet=protocol,
                    remediation=(
                        "This contract resembles a known protocol fork. Review inherited "
                        "vulnerability patterns and confirm mitigations are in place."
                    ),
                    references=[],
                )
            )

        for match in matches:
            if float(match.get("confidence", 0)) < min_similarity:
                continue
            try:
                for hf in run_fork_checks(source, match["protocol"], fp_str):
                    base = heuristic_finding_to_finding(hf)
                    findings.append(
                        Finding(
                            rule_id=f"FORK-{base.rule_id}",
                            severity=base.severity,
                            category="Fork Logic",
                            title=base.title,
                            description=base.description,
                            file=base.file,
                            line_no=base.line_no,
                            code_snippet=base.code_snippet,
                            remediation=base.remediation,
                            references=base.references,
                            confidence=base.confidence,
                        )
                    )
            except Exception as exc:
                logger.warning("Fork checks failed on %s: %s", fp_str, exc)

    status = "completed" if protocols_checked else "skipped"
    return findings, status, {
        "matches_found": match_count,
        "protocols_checked": protocols_checked,
    }


# ---------------------------------------------------------------------------
# AI Copilot
# ---------------------------------------------------------------------------


def run_ai_copilot(
    findings: list[Finding],
    source_code: str,
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
            {
                "rule_id": f.rule_id,
                "title": f.title,
                "description": f.description,
                "severity": f.severity,
            }
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


# ---------------------------------------------------------------------------
# Report generation helpers
# ---------------------------------------------------------------------------


def serialize_findings(findings: list[Finding]) -> list[dict]:
    """Serialize a list of Finding objects to JSON-serializable dicts."""
    return [
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


def generate_reports(
    *,
    report: AuditReport,
    findings: list[Finding],
    findings_data: list[dict],
    results_dir: Path,
    logo_path: Path | None,
    branded: bool,
    project_name: str,
    upload_dir: Path,
) -> Path | None:
    """Generate all report artifacts (HTML, PDF, Markdown, SARIF).

    Returns the HTML path if branded reports were generated, else None.
    """
    # HTML report (PRO)
    html_path: Path | None = results_dir / "report.html"
    if branded:
        logo_str = str(logo_path) if logo_path and logo_path.exists() else None
        generate_html_report(report, str(html_path), logo_path=logo_str)
        pdf_path = results_dir / "report.pdf"
        try:
            generate_pdf_report(report, str(pdf_path), logo_path=logo_str)
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

    return html_path


def generate_attack_graph(
    *,
    findings: list[Finding],
    uploaded_paths: list[str],
    results_dir: Path,
    project_name: str,
    logo_path: Path | None,
) -> bool:
    """Generate attack graph HTML. Returns True on success."""
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
        logo_str = str(logo_path) if logo_path and logo_path.exists() else None
        generate_attack_graph_html(
            graph_json,
            str(attack_graph_path),
            f"Attack Path Analysis - {project_name}",
            logo_path=logo_str,
        )
        return True
    except Exception:
        return False


def build_analyzers_list(
    *,
    heuristic_count: int,
    slither_findings_count: int,
    slither_status: str,
    slither_error: str | None = None,
    fingerprint_status: str = "skipped",
    fingerprint_findings_count: int = 0,
    fingerprint_meta: dict | None = None,
    ai_status: str,
    attack_graph_generated: bool,
    has_findings: bool,
    has_attack_graph_feature: bool,
    findings_data: list[dict],
) -> list[dict]:
    """Build the analyzers metadata list for scan_meta.json."""
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

    _slither_analyzer: dict = {
        "name": "Slither Static Analysis",
        "status": slither_status,
        "findings_count": slither_findings_count,
    }
    # Carry the compile/analysis failure reason so the UI can show WHY Slither
    # produced nothing, instead of a misleading "0 findings".
    if slither_error and slither_status == "error":
        _slither_analyzer["error"] = slither_error

    analyzers = [
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
            "name": "Protocol Fingerprint Scanner",
            "status": fingerprint_status,
            "findings_count": fingerprint_findings_count,
            "protocols_checked": (fingerprint_meta or {}).get("protocols_checked", 0),
            "matches_found": (fingerprint_meta or {}).get("matches_found", 0),
        },
        _slither_analyzer,
        ai_copilot_analyzer,
    ]

    if has_findings:
        ag_status = (
            "completed"
            if attack_graph_generated
            else ("pro_required" if not has_attack_graph_feature else "skipped")
        )
        attack_graph_analyzer: dict = {
            "name": "Attack Graph Generator",
            "status": ag_status,
            "findings_count": 0,
        }
        if attack_graph_analyzer["status"] == "pro_required":
            attack_graph_analyzer["pro_only"] = True
        analyzers.append(attack_graph_analyzer)

    return analyzers
