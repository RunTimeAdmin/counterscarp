#!/usr/bin/env python3
"""
Professional Report Generator for Counterscarp Engine
Generates client-ready HTML/Markdown reports with risk ratings and remediation
"""

from __future__ import annotations

import math
import os
import json
from typing import Callable, Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from logger import get_logger
from exceptions import CounterscarpReportError

try:
    from importlib.metadata import version as _pkg_version
    _ENGINE_VERSION = _pkg_version("counterscarp-engine")
except Exception:
    _ENGINE_VERSION = "3.4.0"
from license_manager import LicenseManager, BRANDED_REPORTS

logger = get_logger(__name__)

# Optional attack graph imports (graceful fallback)
try:
    from attack_graph import build_graph, export_graph_json, trace_attack_paths
    from visualizer import generate_attack_graph_html
    ATTACK_GRAPH_AVAILABLE = True
except ImportError:
    ATTACK_GRAPH_AVAILABLE = False
    build_graph: Optional[Callable[..., Any]] = None  # type: ignore[no-redef]
    export_graph_json: Optional[Callable[..., Any]] = None  # type: ignore[no-redef]
    trace_attack_paths: Optional[Callable[..., Any]] = None  # type: ignore[no-redef]
    generate_attack_graph_html: Optional[Callable[..., Any]] = None  # type: ignore[no-redef]


@dataclass
class Finding:
    """Unified finding format across all analyzers.

    Attributes:
        rule_id: Unique identifier for the rule that triggered.
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        category: Category of the finding (e.g., "Heuristic", "Slither").
        title: Short title describing the finding.
        description: Detailed description of the issue.
        file: Path to the file where the finding occurred.
        line_no: Line number where the finding occurred.
        code_snippet: Relevant code snippet.
        remediation: Suggested remediation.
        references: List of reference URLs.
        cwe: Optional CWE identifier.
        owasp: Optional OWASP category.
    """
    rule_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "Heuristic", "Liar Detector", "Access Matrix", "Slither", "Aderyn"
    title: str
    description: str
    file: str
    line_no: int
    code_snippet: str = ""
    remediation: str = ""
    references: List[str] = field(default_factory=list)
    cwe: Optional[str] = None
    owasp: Optional[str] = None
    similar_locations: List[str] = field(default_factory=list)
    duplicate_count: int = 0
    confidence: int = 5  # 1-10 confidence score
    rag_similar_findings: List[Dict[str, Any]] = field(default_factory=list)
    rag_remediation: str = ""
    rag_references: List[Dict[str, str]] = field(default_factory=list)
    exploit_code: str = ""   # Generated exploit PoC source code (Pro)
    exploit_path: str = ""   # Path to generated exploit file (Pro)


@dataclass
class ReportSection:
    """Represents a section in the final report.

    Attributes:
        title: Section title.
        findings: List of findings in this section.
        summary: Optional section summary.
    """
    title: str
    findings: List[Finding]
    summary: str = ""


@dataclass
class AuditReport:
    """Complete audit report structure.

    Attributes:
        project_name: Name of the audited project.
        target_path: Path to the analyzed target.
        timestamp: Report generation timestamp.
        engine_version: Version of Counterscarp Engine used.
        executive_summary: Dict with severity counts.
        sections: List of report sections.
        risk_score: Overall risk score (0-100).
        pass_fail: Pass/fail status (PASS, FAIL, WARNING).
    """
    project_name: str
    target_path: str
    timestamp: str
    engine_version: str
    executive_summary: Dict[str, int]  # {severity: count}
    sections: List[ReportSection]
    risk_score: float  # 0-100
    pass_fail: str  # PASS, FAIL, WARNING
    analyzer_status: Dict[str, Dict[str, Any]] = field(default_factory=dict)


# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    "CRITICAL": 10.0,
    "HIGH": 5.0,
    "MEDIUM": 2.0,
    "LOW": 0.5,
    "INFO": 0.1
}

# SARIF severity mapping
SARIF_LEVEL_MAP = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note"
}

# Counterscarp Engine version for SARIF reports
COUNTERSCARP_ENGINE_VERSION = "3.4.0"
COUNTERSCARP_ENGINE_SEMANTIC_VERSION = "3.4.0"
COUNTERSCARP_INFORMATION_URI = "https://github.com/RunTimeAdmin/counterscarp"

# Remediation knowledge base
REMEDIATION_KB = {
    # Heuristics
    "UNCHECKED_EXTERNAL_CALL": {
        "fix": "Always check return values: `(bool success, ) = target.call{value: amount}(data); require(success, \"Call failed\");`",
        "references": ["https://consensys.github.io/smart-contract-best-practices/attacks/denial-of-service/"],
        "cwe": "CWE-252: Unchecked Return Value"
    },
    "ORACLE_STALENESS_CHECK": {
        "fix": "Check `updatedAt` timestamp: `require(block.timestamp - updatedAt < STALENESS_THRESHOLD, \"Stale price\");`",
        "references": ["https://docs.chain.link/data-feeds/price-feeds/historical-data"],
        "cwe": "CWE-829: Inclusion of Functionality from Untrusted Control Sphere"
    },
    "FLASH_LOAN_REENTRANCY": {
        "fix": "Add `nonReentrant` modifier from OpenZeppelin ReentrancyGuard to all flash loan callbacks.",
        "references": ["https://docs.openzeppelin.com/contracts/4.x/api/security#ReentrancyGuard"],
        "cwe": "CWE-841: Improper Enforcement of Behavioral Workflow"
    },
    "STORAGE_COLLISION_RISK": {
        "fix": "Use storage gaps: `uint256[50] private __gap;` and follow OpenZeppelin upgrade guidelines.",
        "references": ["https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable"],
        "cwe": "CWE-664: Improper Control of a Resource Through its Lifetime"
    },
    "MISSING_SLIPPAGE_PROTECTION": {
        "fix": "Set minimum output amount: `swapExactTokensForTokens(amountIn, minAmountOut, path, to, deadline);`",
        "references": ["https://docs.uniswap.org/contracts/v2/guides/smart-contract-integration/trading"],
        "cwe": "CWE-841: Improper Enforcement of Behavioral Workflow"
    },
    
    # Access Control
    "TX_ORIGIN_USAGE": {
        "fix": "Replace `tx.origin` with `msg.sender` and use role-based access control (AccessControl from OpenZeppelin).",
        "references": ["https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/"],
        "cwe": "CWE-306: Missing Authentication for Critical Function"
    },
    "EMERGENCY_WITHDRAW_PUBLIC": {
        "fix": "Add `onlyOwner` modifier and consider adding a timelock for emergency functions.",
        "references": ["https://docs.openzeppelin.com/contracts/4.x/api/access#Ownable"],
        "cwe": "CWE-284: Improper Access Control"
    },
    
    # Liar Detector
    "INTENT_IMPLEMENTATION_MISMATCH": {
        "fix": "Add missing access control modifier (onlyOwner, onlyRole) or change visibility to internal/private.",
        "references": ["https://docs.soliditylang.org/en/latest/security-considerations.html#visibility"],
        "cwe": "CWE-284: Improper Access Control"
    },
    
    # Upgrade Safety
    "STORAGE_COLLISION": {
        "fix": "CRITICAL: Do not reorder or remove storage variables. Only append new variables at the end.",
        "references": ["https://docs.openzeppelin.com/upgrades-plugins/1.x/proxies#storage-collisions-between-implementation-versions"],
        "cwe": "CWE-664: Improper Control of a Resource Through its Lifetime"
    },
    "AUTH_REMOVED": {
        "fix": "CRITICAL: Restore removed access control modifier or add equivalent check. Audit all callers.",
        "references": ["https://docs.openzeppelin.com/contracts/4.x/access-control"],
        "cwe": "CWE-284: Improper Access Control"
    }
}


def calculate_risk_score(findings: List[Finding]) -> float:
    """Calculate overall risk score (0-100) based on finding severity distribution.

    Formula: weighted_sum / (max_possible_weight_for_finding_count)

    Args:
        findings: List of findings to calculate score from.

    Returns:
        Risk score between 0 and 100.
    """
    if not findings:
        return 0.0
    
    total_weight = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)
    # Normalize to 0-100 scale (assume max 10 critical findings = 100)
    max_possible = len(findings) * SEVERITY_WEIGHTS["CRITICAL"]
    # Guard against zero division
    max_possible = max(max_possible, 1)
    score = min(100.0, (total_weight / max_possible) * 100)

    # Guard against NaN / infinity from corrupted inputs
    if math.isnan(score) or math.isinf(score):
        logger.error("Risk score calculation produced invalid result")
        score = 50.0  # Default to medium risk

    return round(score, 1)


def get_pass_fail_status(findings: List[Finding]) -> str:
    """Determine overall pass/fail status.

    Args:
        findings: List of findings to evaluate.

    Returns:
        Status string: "PASS", "FAIL", or "WARNING".
    """
    critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
    high_count = sum(1 for f in findings if f.severity == "HIGH")
    
    if critical_count > 0:
        return "FAIL"
    elif high_count > 3:  # Configurable threshold
        return "FAIL"
    elif high_count > 0:
        return "WARNING"
    else:
        return "PASS"


def enrich_finding(finding: Finding) -> Finding:
    """Add remediation advice and references from knowledge base.

    Args:
        finding: Finding to enrich.

    Returns:
        Enriched finding with remediation and references.
    """
    kb_entry = REMEDIATION_KB.get(finding.rule_id, {})
    
    if kb_entry:
        if not finding.remediation:
            finding.remediation = str(kb_entry.get("fix", ""))
        if not finding.references:
            refs = kb_entry.get("references", [])
            finding.references = list(refs) if isinstance(refs, list) else []
        if not finding.cwe:
            cwe_val = kb_entry.get("cwe")
            finding.cwe = str(cwe_val) if cwe_val is not None else None
    
    # Fallback generic remediation
    if not finding.remediation:
        finding.remediation = f"Review and address this {finding.severity} severity issue in {finding.file}."
    
    return finding


def generate_html_report(report: AuditReport, output_path: str, logo_path: Optional[str] = None) -> Optional[str]:
    """Generate professional HTML report.

    Args:
        report: AuditReport object to generate report from.
        output_path: Path to save the HTML file.
        logo_path: Optional path to a logo image file to embed in the report.

    Returns:
        Path to the generated HTML file, or None if pro feature not available.
    """
    _license = LicenseManager()
    if not _license.check_pro_feature(BRANDED_REPORTS):
        print(_license.get_upgrade_message(BRANDED_REPORTS))
        return None

    # Process logo if provided (never crash on logo issues)
    logo_html = ""
    if logo_path and Path(logo_path).exists():
        try:
            import base64
            with open(logo_path, 'rb') as f:
                logo_data = f.read()
            logo_b64 = base64.b64encode(logo_data).decode('utf-8')
            ext = Path(logo_path).suffix.lower().lstrip('.')
            mime = {'png': 'image/png', 'jpg': 'image/jpeg', 'jpeg': 'image/jpeg', 'svg': 'image/svg+xml'}.get(ext, 'image/png')
            logo_html = f'<img src="data:{mime};base64,{logo_b64}" alt="Counterscarp Engine" style="height: 60px; margin-right: 15px; vertical-align: middle;">'
        except (IOError, OSError, Exception) as e:
            logger.warning(f"Failed to load logo from {logo_path}: {e}. Continuing without logo.")
            logo_html = ""
    
    # Determine status badge color
    status_colors = {
        "PASS": "#28a745",
        "WARNING": "#ffc107", 
        "FAIL": "#dc3545"
    }
    status_color = status_colors.get(report.pass_fail, "#6c757d")
    
    # Build HTML
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Audit Report - {report.project_name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ font-size: 2.5em; margin-bottom: 10px; }}
        .header .meta {{ opacity: 0.9; font-size: 0.95em; }}
        .status-badge {{ display: inline-block; padding: 8px 20px; background: {status_color}; color: white; border-radius: 20px; font-weight: bold; margin-top: 15px; }}
        .risk-score {{ font-size: 3em; font-weight: bold; margin: 20px 0; }}
        .risk-low {{ color: #28a745; }}
        .risk-medium {{ color: #ffc107; }}
        .risk-high {{ color: #fd7e14; }}
        .risk-critical {{ color: #dc3545; }}
        .summary {{ background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 20px; margin-top: 20px; }}
        .summary-card {{ text-align: center; padding: 20px; border-radius: 8px; }}
        .summary-card.critical {{ background: #fff5f5; border-left: 4px solid #dc3545; }}
        .summary-card.high {{ background: #fff8e1; border-left: 4px solid #fd7e14; }}
        .summary-card.medium {{ background: #fffbea; border-left: 4px solid #ffc107; }}
        .summary-card.low {{ background: #f0f9ff; border-left: 4px solid #17a2b8; }}
        .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
        .summary-card .label {{ text-transform: uppercase; font-size: 0.85em; color: #666; margin-top: 5px; }}
        .section {{ background: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .section h2 {{ color: #667eea; border-bottom: 3px solid #667eea; padding-bottom: 10px; margin-bottom: 20px; }}
        .finding {{ border-left: 4px solid #ddd; padding: 20px; margin-bottom: 20px; background: #fafafa; border-radius: 5px; }}
        .finding.critical {{ border-left-color: #dc3545; background: #fff5f5; }}
        .finding.high {{ border-left-color: #fd7e14; background: #fff8e1; }}
        .finding.medium {{ border-left-color: #ffc107; background: #fffbea; }}
        .finding.low {{ border-left-color: #17a2b8; background: #f0f9ff; }}
        .finding-header {{ display: flex; justify-content: space-between; align-items: start; margin-bottom: 15px; }}
        .finding-title {{ font-size: 1.2em; font-weight: bold; color: #333; }}
        .severity-badge {{ padding: 5px 15px; border-radius: 20px; font-size: 0.85em; font-weight: bold; color: white; }}
        .severity-badge.critical {{ background: #dc3545; }}
        .severity-badge.high {{ background: #fd7e14; }}
        .severity-badge.medium {{ background: #ffc107; color: #333; }}
        .severity-badge.low {{ background: #17a2b8; }}
        .finding-meta {{ color: #666; font-size: 0.9em; margin-bottom: 10px; }}
        .finding-description {{ margin: 15px 0; }}
        .code-block {{ background: #2d2d2d; color: #f8f8f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.9em; margin: 10px 0; }}
        .remediation {{ background: #e8f5e9; border-left: 4px solid #4caf50; padding: 15px; border-radius: 5px; margin: 15px 0; }}
        .remediation-title {{ font-weight: bold; color: #2e7d32; margin-bottom: 8px; }}
        .references {{ margin-top: 10px; }}
        .references a {{ color: #667eea; text-decoration: none; }}
        .references a:hover {{ text-decoration: underline; }}
        .footer {{ text-align: center; color: #999; margin-top: 50px; padding: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            {logo_html}<h1 style="display: inline-block; vertical-align: middle;">🛡️ Security Audit Report</h1>
            <div class="meta">
                <strong>Project:</strong> {report.project_name}<br>
                <strong>Target:</strong> {report.target_path}<br>
                <strong>Generated:</strong> {report.timestamp}<br>
                <strong>Engine:</strong> Counterscarp Engine {report.engine_version}
            </div>
            <div class="status-badge">{report.pass_fail}</div>
        </div>

        <div class="summary">
            <h2>Executive Summary</h2>
            <div class="risk-score {"risk-critical" if report.risk_score >= 70 else "risk-high" if report.risk_score >= 40 else "risk-medium" if report.risk_score >= 20 else "risk-low"}">
                Risk Score: {report.risk_score}/100
            </div>
            <div class="summary-grid">
                <div class="summary-card critical">
                    <div class="count">{report.executive_summary.get("CRITICAL", 0)}</div>
                    <div class="label">Critical</div>
                </div>
                <div class="summary-card high">
                    <div class="count">{report.executive_summary.get("HIGH", 0)}</div>
                    <div class="label">High</div>
                </div>
                <div class="summary-card medium">
                    <div class="count">{report.executive_summary.get("MEDIUM", 0)}</div>
                    <div class="label">Medium</div>
                </div>
                <div class="summary-card low">
                    <div class="count">{report.executive_summary.get("LOW", 0)}</div>
                    <div class="label">Low</div>
                </div>
            </div>
        </div>
"""

    # Sections
    for section in report.sections:
        if not section.findings:
            continue
            
        html += f"""
        <div class="section">
            <h2>{section.title}</h2>
            {f"<p>{section.summary}</p>" if section.summary else ""}
"""
        
        for finding in section.findings:
            severity_class = finding.severity.lower()
            html += f"""
            <div class="finding {severity_class}">
                <div class="finding-header">
                    <div class="finding-title">{finding.title}</div>
                    <span class="severity-badge {severity_class}">{finding.severity}</span>
                </div>
                <div class="finding-meta">
                    <strong>Category:</strong> {finding.category} | 
                    <strong>Rule:</strong> {finding.rule_id} | 
                    <strong>Location:</strong> {finding.file}:{finding.line_no}
                    {f" | <strong>CWE:</strong> {finding.cwe}" if finding.cwe else ""}
                     | <strong>Confidence:</strong> {getattr(finding, 'confidence', 5)}/10
                </div>
                <div class="finding-description">{finding.description}</div>
"""
            
            if finding.code_snippet:
                html += f"""
                <div class="code-block">{finding.code_snippet}</div>
"""
            
            if finding.remediation:
                html += f"""
                <div class="remediation">
                    <div class="remediation-title">🛠️ Remediation</div>
                    {finding.remediation}
                </div>
"""
            
            if finding.references:
                html += """
                <div class="references">
                    <strong>References:</strong><br>
"""
                for ref in finding.references:
                    html += f'                    <a href="{ref}" target="_blank">{ref}</a><br>\n'
                html += "                </div>\n"
            
            if finding.duplicate_count > 0:
                locations_text = ", ".join(finding.similar_locations[:5])
                if finding.duplicate_count > 5:
                    locations_text += f" ... and {finding.duplicate_count - 5} more"
                html += f'<div class="duplicate-note" style="color:#666;font-size:0.85em;margin-top:4px;">Also found in {finding.duplicate_count} other location(s): {locations_text}</div>'

            # RAG: AI Analysis
            rag_remediation = getattr(finding, 'rag_remediation', None)
            if rag_remediation:
                html += f"""
                <div style="background:#1a1a2e;border-left:4px solid #7c3aed;padding:12px 16px;margin:10px 0;border-radius:4px;">
                    <strong style="color:#a78bfa;">AI Analysis</strong>
                    <p style="color:#e0e0e0;margin:8px 0 0 0;">{rag_remediation}</p>
                </div>
"""

            # RAG: Similar Past Findings (top 3)
            rag_similar = getattr(finding, 'rag_similar_findings', None)
            if rag_similar:
                html += """
                <div style="margin:10px 0;">
                    <strong style="color:#94a3b8;">Related Past Findings:</strong>
                    <ul style="margin:4px 0;">
"""
                for entry in rag_similar[:3]:
                    text = entry.get('text', '')
                    score = entry.get('similarity', 0.0)
                    source = entry.get('metadata', {}).get('source', '')
                    html += f'                        <li style="color:#cbd5e1;">{text} <span style="color:#7c3aed;">(similarity: {score:.0%})</span> — <em>{source}</em></li>\n'
                html += """                    </ul>
                </div>
"""

            # RAG: AI References
            rag_references = getattr(finding, 'rag_references', None)
            if rag_references:
                html += """
                <div style="margin:10px 0;">
                    <strong style="color:#94a3b8;">AI References:</strong>
                    <ul style="margin:4px 0;">
"""
                for ref in rag_references:
                    url = ref.get('url', '#')
                    source = ref.get('source', url)
                    html += f'                        <li><a href="{url}" style="color:#60a5fa;">{source}</a></li>\n'
                html += """                    </ul>
                </div>
"""

            # Exploit PoC (Pro tier)
            exploit_code = getattr(finding, 'exploit_code', '')
            exploit_path = getattr(finding, 'exploit_path', '')
            if exploit_code:
                import html as _html_escape
                escaped_code = _html_escape.escape(exploit_code)
                path_note = f' &nbsp;<span style="color:#94a3b8;font-size:0.85em;">({_html_escape.escape(exploit_path)})</span>' if exploit_path else ''
                html += f"""
                <details style="margin:12px 0;">
                    <summary style="cursor:pointer;background:#1a0a00;border-left:4px solid #f97316;padding:8px 14px;border-radius:4px;color:#fb923c;font-weight:bold;">
                        &#x1F4A5; Exploit PoC (Foundry){path_note}
                    </summary>
                    <div style="background:#120800;border-left:4px solid #f97316;padding:12px 16px;border-radius:0 0 4px 4px;margin-top:2px;">
                        <p style="color:#94a3b8;font-size:0.85em;margin:0 0 8px 0;">Generated Foundry test &mdash; run with <code style="background:#1e1e1e;padding:2px 6px;border-radius:3px;">forge test</code></p>
                        <pre style="background:#0d0d0d;border:1px solid #374151;border-radius:4px;padding:12px;overflow-x:auto;margin:0;"><code style="color:#e2e8f0;font-size:0.85em;font-family:monospace;">{escaped_code}</code></pre>
                    </div>
                </details>
"""

            html += "            </div>\n"
        
        html += "        </div>\n"

    html += """
        <div class="footer">
            Generated by <strong>Counterscarp Security Engine</strong> • counterscarp.io<br>
            For questions or clarifications, contact your security team.
        </div>
    </div>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return output_path


def generate_pdf_report(
    report: AuditReport,
    output_path: Optional[str] = None,
    logo_path: Optional[str] = None,
) -> Optional[Any]:
    """Generate a PDF audit report by converting the HTML report to PDF.

    Requires xhtml2pdf: ``pip install xhtml2pdf`` (or ``pip install counterscarp-engine[pdf]``).

    This is a Pro feature — the caller must hold a valid ``BRANDED_REPORTS`` license.

    Args:
        report: AuditReport object to generate the report from.
        output_path: File path to write the PDF to. When provided the function
            writes the file and returns the path string. When *None* the raw
            PDF bytes are returned so callers can stream it directly.
        logo_path: Optional path to a logo image to embed (forwarded to the
            underlying HTML generator).

    Returns:
        * ``str`` — the *output_path* when a path was provided and the file was
          written successfully.
        * ``bytes`` — raw PDF bytes when *output_path* is ``None``.
        * ``None`` — when the feature is unavailable (missing license or missing
          ``xhtml2pdf`` dependency) or when generation fails.
    """
    _license = LicenseManager()
    if not _license.check_pro_feature(BRANDED_REPORTS):
        print(_license.get_upgrade_message(BRANDED_REPORTS))
        return None

    # ------------------------------------------------------------------ #
    # Step 1 – Produce the HTML source via the existing HTML generator.   #
    # We write to a temp file, read it back, then delete it.              #
    # ------------------------------------------------------------------ #
    import io
    import tempfile

    try:
        with tempfile.NamedTemporaryFile(
            suffix=".html", mode="w", delete=False, encoding="utf-8"
        ) as tmp:
            tmp_path = tmp.name

        html_result = generate_html_report(report, tmp_path, logo_path=logo_path)
        if not html_result:
            logger.error("PDF generation failed: HTML generation returned None")
            return None

        with open(tmp_path, "r", encoding="utf-8") as f:
            html_content = f.read()

        try:
            import os as _os
            _os.unlink(tmp_path)
        except OSError:
            pass

    except Exception as e:
        logger.error(f"PDF generation failed during HTML phase: {e}")
        return None

    # ------------------------------------------------------------------ #
    # Step 2 – Inject PDF-specific CSS (page size, pagination, breaks).   #
    # ------------------------------------------------------------------ #
    pdf_css = """
<style>
@page {
    size: A4;
    margin: 2cm;
}
body { font-size: 10pt; background: #fff !important; color: #333 !important; }
.container { max-width: 100% !important; padding: 0 !important; }
.header {
    background: #667eea !important;
    color: #fff !important;
    padding: 20px !important;
    border-radius: 6px !important;
    margin-bottom: 20px !important;
    page-break-inside: avoid;
}
.finding { page-break-inside: avoid; }
.section { page-break-inside: avoid; }
h1, h2, h3 { page-break-after: avoid; }
pre { white-space: pre-wrap !important; word-wrap: break-word !important; font-size: 8pt !important; }
a { color: #667eea !important; }
.code-block { font-size: 8pt !important; }
</style>
"""

    if "</head>" in html_content:
        pdf_html = html_content.replace("</head>", pdf_css + "</head>", 1)
    else:
        pdf_html = pdf_css + html_content

    # ------------------------------------------------------------------ #
    # Step 3 – Convert HTML to PDF via xhtml2pdf (pisa).                  #
    # ------------------------------------------------------------------ #
    try:
        from xhtml2pdf import pisa

        result_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(pdf_html, dest=result_buffer)

        if pisa_status.err:
            logger.error(
                f"PDF generation failed: xhtml2pdf reported {pisa_status.err} error(s)"
            )
            return None

        pdf_bytes = result_buffer.getvalue()

        if output_path:
            with open(output_path, "wb") as fout:
                fout.write(pdf_bytes)
            logger.info(f"PDF report saved: {output_path}")
            return output_path

        return pdf_bytes

    except ImportError:
        logger.warning(
            "PDF generation requires xhtml2pdf: pip install xhtml2pdf  "
            "(or: pip install counterscarp-engine[pdf])"
        )
        return None
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        return None


def generate_sarif_report(findings: List[Finding], metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a SARIF 2.1.0 compliant report from findings.

    Args:
        findings: List of Finding objects to include in the report.
        metadata: Optional metadata dict with keys like 'project_name', 'target_path'.

    Returns:
        A dictionary representing a valid SARIF 2.1.0 JSON document.
        Always returns a valid SARIF structure with a non-null 'runs' array.

    Raises:
        CounterscarpReportError: If report generation fails.

    Example:
        >>> findings = [Finding(...), Finding(...)]
        >>> sarif = generate_sarif_report(findings, {"project_name": "MyProject"})
        >>> json.dump(sarif, open("report.sarif", "w"))
    """
    try:
        metadata = metadata or {}
        
        # Build unique rules from findings
        rules = []
        rule_ids = set()
        for finding in findings:
            if finding.rule_id not in rule_ids:
                rule_ids.add(finding.rule_id)
                rule = {
                    "id": finding.rule_id,
                    "name": finding.rule_id.replace("_", " ").title(),
                    "shortDescription": {
                        "text": finding.title
                    },
                    "fullDescription": {
                        "text": finding.description
                    },
                    "defaultConfiguration": {
                        "level": SARIF_LEVEL_MAP.get(finding.severity, "warning")
                    }
                }
                # Add CWE as a tag if available
                if finding.cwe:
                    rule["properties"] = {
                        "tags": [finding.cwe]
                    }
                rules.append(rule)
        
        # Build results from findings
        results = []
        for finding in findings:
            result: Dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                "message": {
                    "text": finding.description
                },
                "locations": []
            }
            
            # Add location if file path is available
            if finding.file:
                location: Dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": finding.file
                        }
                    }
                }
                # Add region if line number is available and valid
                if finding.line_no and finding.line_no > 0:
                    location["physicalLocation"]["region"] = {
                        "startLine": finding.line_no
                    }
                    # Add snippet if available
                    if finding.code_snippet:
                        location["physicalLocation"]["region"]["snippet"] = {
                            "text": finding.code_snippet
                        }
                result["locations"].append(location)
            
            # Add remediation as a related location if available
            if finding.remediation:
                result["message"]["text"] += f"\n\nRemediation: {finding.remediation}"

            # Add RAG-enriched data to properties (SARIF extensibility point)
            rag_properties: Dict[str, Any] = {}

            rag_remediation = getattr(finding, "rag_remediation", None)
            if rag_remediation:
                rag_properties["ai_remediation"] = rag_remediation

            rag_references = getattr(finding, "rag_references", None)
            if rag_references:
                urls = [ref.get("url", "") for ref in rag_references if ref.get("url")]
                if urls:
                    rag_properties["ai_references"] = urls

            rag_similar = getattr(finding, "rag_similar_findings", None)
            if rag_similar:
                similar_list = [
                    {
                        "text": sf.get("text", ""),
                        "similarity": round(sf.get("similarity", 0), 3),
                        "source": sf.get("metadata", {}).get("source", "unknown"),
                    }
                    for sf in rag_similar[:3]
                ]
                if similar_list:
                    rag_properties["similar_findings"] = similar_list

            # Exploit PoC (Pro tier)
            _exploit_code = getattr(finding, "exploit_code", "")
            _exploit_path = getattr(finding, "exploit_path", "")
            if _exploit_code:
                rag_properties["exploit_code"] = _exploit_code
            if _exploit_path:
                rag_properties["exploit_path"] = _exploit_path

            if rag_properties:
                result["properties"] = rag_properties

            results.append(result)
        
        # Build the SARIF document - ALWAYS has valid runs array
        sarif_doc: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Counterscarp Engine",
                            "version": COUNTERSCARP_ENGINE_VERSION,
                            "semanticVersion": COUNTERSCARP_ENGINE_SEMANTIC_VERSION,
                            "informationUri": COUNTERSCARP_INFORMATION_URI,
                            "rules": rules
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": metadata.get("timestamp", datetime.now().isoformat())
                        }
                    ]
                }
            ]
        }
        
        # Add automation details if project name is available
        if metadata.get("project_name"):
            sarif_doc["runs"][0]["automationDetails"] = {
                "id": metadata["project_name"],
                "description": {
                    "text": f"Security audit for {metadata['project_name']}"
                }
            }
        
        logger.info(f"Generated SARIF report with {len(results)} results and {len(rules)} rules")
        return sarif_doc
        
    except Exception as e:
        logger.error(f"Failed to generate SARIF report: {e}")
        raise CounterscarpReportError(
            "Failed to generate SARIF report",
            details={"error": str(e), "finding_count": len(findings)}
        ) from e


def save_sarif_report(findings: List[Finding], output_path: str, metadata: Optional[Dict[str, Any]] = None) -> str:
    """Generate and save a SARIF 2.1.0 report to a file.

    ALWAYS produces a valid SARIF file with a non-null 'runs' array, even if
    there are no findings or if an error occurs during generation.

    Args:
        findings: List of Finding objects to include in the report.
        output_path: Path where the SARIF JSON file will be written.
        metadata: Optional metadata dict with keys like 'project_name', 'target_path'.

    Returns:
        The output file path.

    Raises:
        CounterscarpReportError: If the file cannot be written.

    Example:
        >>> findings = [Finding(...), Finding(...)]
        >>> path = save_sarif_report(findings, "report.sarif")
        >>> print(f"SARIF report saved to: {path}")
    """
    # Default valid SARIF structure as fallback
    default_sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Counterscarp Engine",
                        "version": COUNTERSCARP_ENGINE_VERSION,
                        "informationUri": COUNTERSCARP_INFORMATION_URI
                    }
                },
                "results": []
            }
        ]
    }

    try:
        sarif_doc = generate_sarif_report(findings, metadata)

        # Ensure we always have a valid SARIF structure with runs array
        if sarif_doc is None:
            sarif_doc = default_sarif
        elif not isinstance(sarif_doc, dict):
            sarif_doc = default_sarif
        elif "runs" not in sarif_doc or sarif_doc["runs"] is None:
            sarif_doc["runs"] = default_sarif["runs"]

    except Exception as e:
        logger.warning(f"SARIF generation failed, using default structure: {e}")
        sarif_doc = default_sarif

    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_doc, f, indent=2)

        logger.info(f"SARIF report saved to: {output_path}")
        return output_path

    except Exception as e:
        logger.error(f"Failed to save SARIF report to {output_path}: {e}")
        # Try to write the default structure as last resort
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(default_sarif, f, indent=2)
            logger.info(f"Default SARIF report saved to: {output_path}")
            return output_path
        except Exception:
            pass
        raise CounterscarpReportError(
            "Failed to save SARIF report",
            details={"output_path": output_path, "error": str(e)}
        ) from e


def generate_markdown_report(report: AuditReport, output_path: str) -> str:
    """Generate Markdown report (GitHub/GitLab friendly).

    Args:
        report: AuditReport object to generate report from.
        output_path: Path to save the Markdown file.

    Returns:
        Path to the generated Markdown file.
    """
    
    status_emoji = {"PASS": "✅", "WARNING": "⚠️", "FAIL": "❌"}
    
    md = f"""# 🛡️ Security Audit Report

**Project:** `{report.project_name}`  
**Target:** `{report.target_path}`  
**Generated:** {report.timestamp}  
**Engine:** Counterscarp Engine {report.engine_version}  
**Status:** {status_emoji.get(report.pass_fail, "❓")} **{report.pass_fail}**

---

## Executive Summary

**Risk Score:** {report.risk_score}/100

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | {report.executive_summary.get("CRITICAL", 0)} |
| 🟠 HIGH | {report.executive_summary.get("HIGH", 0)} |
| 🟡 MEDIUM | {report.executive_summary.get("MEDIUM", 0)} |
| 🔵 LOW | {report.executive_summary.get("LOW", 0)} |

"""

    # Collect top 10 findings across all sections (already sorted by severity)
    _top_findings: List[Finding] = []
    for _section in report.sections:
        for _finding in _section.findings:
            if len(_top_findings) < 10:
                _top_findings.append(_finding)

    if _top_findings:
        _severity_emoji_map = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}
        md += "### Top 10 Priority Issues\n\n"
        md += "| # | Severity | Confidence | Issue | Location | Description |\n"
        md += "|---|----------|-----------|-------|----------|-------------|\n"
        for _i, _f in enumerate(_top_findings, 1):
            _sev = _f.severity
            _sev_em = _severity_emoji_map.get(_sev, "❓")
            _issue = (_f.rule_id or _f.title or "unknown")
            _loc = f"{_f.file}:{_f.line_no}" if _f.file else "unknown"
            _desc = (_f.title or _f.description or "")[:80].replace("|", "\\|")
            _conf = getattr(_f, 'confidence', 5)
            md += f"| {_i} | {_sev_em} {_sev} | [{_conf}/10] | {_issue} | {_loc} | {_desc} |\n"
        md += "\n"

    md += "---\n\n"

    # Analyzer Coverage section
    _analyzer_status = getattr(report, 'analyzer_status', {})
    if _analyzer_status:
        md += "## Analyzer Coverage\n\n"
        md += "| Analyzer | Status | Findings |\n"
        md += "|----------|--------|----------|\n"
        _failed_analyzers = []
        for _aname, _astatus in _analyzer_status.items():
            if _astatus.get("ran"):
                _acount = _astatus.get("finding_count", 0)
                md += f"| {_aname} | Completed | {_acount} |\n"
            elif _astatus.get("error") == "Not enabled":
                md += f"| {_aname} | Skipped (not enabled) | — |\n"
            else:
                _aerr = _astatus.get("error", "Unknown error")
                md += f"| {_aname} | **FAILED** | — |\n"
                _failed_analyzers.append((_aname, _aerr))
        md += "\n"
        for _aname, _aerr in _failed_analyzers:
            md += f"> **Warning:** {_aname} did not complete successfully ({_aerr}). Results below may be incomplete.\n\n"
        md += "---\n\n"

    for section in report.sections:
        if not section.findings:
            continue
        
        md += f"## {section.title}\n\n"
        if section.summary:
            md += f"{section.summary}\n\n"
        
        for i, finding in enumerate(section.findings, 1):
            severity_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "ℹ️"}
            emoji = severity_emoji.get(finding.severity, "❓")
            
            md += f"### {i}. {emoji} {finding.title}\n\n"
            _conf_val = getattr(finding, 'confidence', 5)
            md += f"**Severity:** {finding.severity} | **Confidence:** {_conf_val}/10  \n"
            md += f"**Category:** {finding.category}  \n"
            md += f"**Rule ID:** `{finding.rule_id}`  \n"
            md += f"**Location:** `{finding.file}:{finding.line_no}`  \n"
            if finding.cwe:
                md += f"**CWE:** {finding.cwe}  \n"
            md += "\n"
            
            md += f"**Description:**  \n{finding.description}\n\n"
            
            if finding.code_snippet:
                md += f"```solidity\n{finding.code_snippet}\n```\n\n"
            
            if finding.remediation:
                md += f"**🛠️ Remediation:**  \n{finding.remediation}\n\n"
            
            if finding.references:
                md += "**References:**\n"
                for ref in finding.references:
                    md += f"- {ref}\n"
                md += "\n"

            rag_remediation = getattr(finding, 'rag_remediation', None)
            if rag_remediation:
                md += "> **AI Analysis:**  \n"
                for line in rag_remediation.splitlines():
                    md += f"> {line}  \n"
                md += "\n"

            rag_similar = getattr(finding, 'rag_similar_findings', None)
            if rag_similar:
                md += "**Similar Past Findings:**\n"
                for entry in rag_similar[:3]:
                    text = entry.get('text', '')
                    score = entry.get('similarity', 0.0)
                    source = entry.get('metadata', {}).get('source', 'unknown')
                    md += f"- {text} (similarity: {score:.0%}) — *{source}*\n"
                md += "\n"

            rag_refs = getattr(finding, 'rag_references', None)
            if rag_refs:
                md += "**AI References:**\n"
                for ref in rag_refs:
                    url = ref.get('url', '')
                    source = ref.get('source', url)
                    md += f"- [{source}]({url})\n"
                md += "\n"

            if finding.duplicate_count > 0:
                md += f"\n> **Also found in {finding.duplicate_count} other location(s):** "
                md += ", ".join(finding.similar_locations[:5])
                if finding.duplicate_count > 5:
                    md += f" ... and {finding.duplicate_count - 5} more"
                md += "\n"

            # Exploit PoC (Pro tier)
            _md_exploit_code = getattr(finding, 'exploit_code', '')
            _md_exploit_path = getattr(finding, 'exploit_path', '')
            if _md_exploit_code:
                md += "\n**💥 Exploit PoC (Foundry)**"
                if _md_exploit_path:
                    md += f"  \n*File: `{_md_exploit_path}`*"
                md += "  \nGenerated Foundry test — run with `forge test`\n\n"
                md += f"```solidity\n{_md_exploit_code}\n```\n\n"
            
            md += "---\n\n"

    md += """
---

*Generated by **Counterscarp Security Engine** • CyberShield Austin / TokenAudit*
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(md)
    
    return output_path


def aggregate_findings_from_orchestrator(
    static_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
    liar_results: List[Dict[str, Any]],
    access_matrix_results: List[Dict[str, Any]],
    aderyn_results: Optional[Dict[str, Any]],
    upgrade_diff_results: Optional[Dict[str, Any]],
    solana_results: Optional[Dict[str, Any]]
) -> List[Finding]:
    """Convert orchestrator results into unified Finding objects.

    Args:
        static_results: Results from static analysis.
        heuristic_results: Results from heuristic scanning.
        liar_results: Results from intent checking.
        access_matrix_results: Results from access matrix analysis.
        aderyn_results: Optional results from Aderyn.
        upgrade_diff_results: Optional results from upgrade diff.
        solana_results: Optional results from Solana analysis.

    Returns:
        List of unified Finding objects.
    """
    findings = []
    
    # Static analysis (Slither)
    for item in static_results:
        findings.append(Finding(
            rule_id=item.get("check", "unknown"),
            severity=item.get("impact", "MEDIUM").upper(),
            category="Slither",
            title=item.get("title", "Slither Finding"),
            description=item.get("description", ""),
            file=item.get("location", "").split(":")[0] if ":" in item.get("location", "") else item.get("location", ""),
            line_no=int(item.get("location", ":0").split(":")[-1]) if ":" in item.get("location", "") else 0
        ))
    
    # Heuristics
    for item in heuristic_results:
        findings.append(Finding(
            rule_id=item["rule_id"],
            severity=item["severity"],
            category="Heuristic",
            title=item["rule_id"].replace("_", " ").title(),
            description=item["message"],
            file=item["file"],
            line_no=item["line_no"],
            code_snippet=item.get("line_text", ""),
            confidence=item.get("confidence", 5)
        ))
    
    # Liar Detector
    for item in liar_results:
        findings.append(Finding(
            rule_id="INTENT_IMPLEMENTATION_MISMATCH",
            severity="CRITICAL",
            category="Liar Detector",
            title=f"Intent Mismatch: {item['function']}",
            description=f"Comment implies '{item['trigger_word']}' but function is public/external with no modifiers.",
            file=item.get("file", ""),
            line_no=item.get("line", 0)
        ))
    
    # Access Matrix (HIGH risk items only)
    for item in access_matrix_results:
        if item.get("risk") == "HIGH":
            findings.append(Finding(
                rule_id="UNPROTECTED_PUBLIC_FUNCTION",
                severity="HIGH",
                category="Access Matrix",
                title=f"Public Function Without Auth: {item['name']}",
                description=f"Function '{item['name']}' is {item['visibility']} with mutability {item['mutability']} and no access control.",
                file=item.get("file", ""),
                line_no=0
            ))
    
    # Aderyn
    if aderyn_results and isinstance(aderyn_results, dict):
        for issue in aderyn_results.get("high", [])[:10]:
            findings.append(Finding(
                rule_id=issue.get("detector_name", "unknown"),
                severity="HIGH",
                category="Aderyn",
                title=issue.get("title", "Aderyn Finding"),
                description=issue.get("description", ""),
                file="",
                line_no=0
            ))
    
    # Upgrade Diff
    if upgrade_diff_results and isinstance(upgrade_diff_results, dict):
        for issue in upgrade_diff_results.get("issues", []):
            findings.append(Finding(
                rule_id=issue.category,
                severity=issue.severity,
                category="Upgrade Diff",
                title=issue.title,
                description=issue.description,
                file="",
                line_no=issue.line_no or 0
            ))
    
    # Solana
    if solana_results and isinstance(solana_results, dict):
        for f in solana_results.get("pattern_findings", []):
            if hasattr(f, 'severity'):
                findings.append(Finding(
                    rule_id=f.category,
                    severity=f.severity,
                    category="Solana",
                    title=f.title,
                    description=f.description,
                    file=f.file,
                    line_no=f.line_no,
                    remediation=f.fix_suggestion if hasattr(f, 'fix_suggestion') else ""
                ))
    
    # Enrich all findings
    findings = [enrich_finding(f) for f in findings]
    
    return findings


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Group similar findings across network-variant contract files.

    Creates a fingerprint from rule_id + severity + normalized description,
    keeping one primary finding per group with 'also found in' references.
    """
    import re

    def _normalize_desc(desc: str) -> str:
        """Strip file-specific paths and line numbers from description."""
        normalized = re.sub(r'[\w/\\]+\.sol', '<file>', desc)
        normalized = re.sub(r'(?:line|L|:)\s*\d+', '', normalized)
        normalized = re.sub(r'0x[0-9a-fA-F]+', '<addr>', normalized)
        return normalized.strip().lower()

    def _normalize_filename(filepath: str) -> str:
        """Strip network suffixes from filenames for grouping.
        E.g., Token_Sepolia.sol -> Token, TokenBSC.sol -> Token"""
        basename = os.path.splitext(os.path.basename(filepath))[0]
        suffixes = [
            '_Sepolia', '_sepolia', '_BSC', '_bsc', '_Polygon', '_polygon',
            '_Base', '_base', '_Mainnet', '_mainnet', '_Goerli', '_goerli',
            '_Arbitrum', '_arbitrum', '_Optimism', '_optimism',
            'Sepolia', 'BSC', 'Polygon', 'Base', 'Mainnet', 'Goerli',
            'Arbitrum', 'Optimism',
            '_testnet', '_Testnet',
        ]
        for suffix in suffixes:
            if basename.endswith(suffix):
                basename = basename[:-len(suffix)]
                break
        return basename

    # Build fingerprints and group
    groups: Dict[str, List[Finding]] = {}
    for finding in findings:
        normalized_file = _normalize_filename(finding.file)
        normalized_desc = _normalize_desc(finding.description or finding.title)
        fingerprint = f"{finding.rule_id}|{finding.severity}|{normalized_file}|{normalized_desc}"

        if fingerprint not in groups:
            groups[fingerprint] = []
        groups[fingerprint].append(finding)

    # Deduplicate: keep first, annotate with similar locations
    deduplicated = []
    for fingerprint, group in groups.items():
        primary = group[0]
        if len(group) > 1:
            primary.duplicate_count = len(group) - 1
            primary.similar_locations = [
                f"{f.file}:{f.line_no}" for f in group[1:]
            ]
        deduplicated.append(primary)

    return deduplicated


def create_audit_report(
    project_name: str,
    target_path: str,
    findings: List[Finding],
    engine_version: str = _ENGINE_VERSION,
    analyzer_status: Optional[Dict] = None
) -> AuditReport:
    """Build complete audit report from findings.

    Args:
        project_name: Name of the project being audited.
        target_path: Path to the analyzed target.
        findings: List of findings to include in the report.
        engine_version: Version of the Counterscarp Engine.
        analyzer_status: Optional dict mapping analyzer names to status dicts.

    Returns:
        Complete AuditReport object.
    """
    
    # Consolidate duplicate findings across network variants
    findings = deduplicate_findings(findings)

    # Group by category
    sections: Dict[str, List[Finding]] = {}
    for finding in findings:
        if finding.category not in sections:
            sections[finding.category] = []
        sections[finding.category].append(finding)
    
    # Build sections
    report_sections = []
    for category, category_findings in sections.items():
        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        category_findings.sort(key=lambda f: severity_order.get(f.severity, 5))
        
        section = ReportSection(
            title=f"{category} Analysis",
            findings=category_findings,
            summary=f"Found {len(category_findings)} issue(s) in {category} analysis."
        )
        report_sections.append(section)
    
    # Executive summary
    exec_summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        exec_summary[f.severity] = exec_summary.get(f.severity, 0) + 1
    
    report = AuditReport(
        project_name=project_name,
        target_path=target_path,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        engine_version=engine_version,
        executive_summary=exec_summary,
        sections=report_sections,
        risk_score=calculate_risk_score(findings),
        pass_fail=get_pass_fail_status(findings),
        analyzer_status=analyzer_status or {}
    )
    
    return report


# CLI for standalone testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate professional audit report")
    parser.add_argument("--project", default="Test Project", help="Project name")
    parser.add_argument("--target", default="./contracts", help="Target path")
    parser.add_argument("--format", choices=["html", "markdown", "sarif", "pdf", "attack-graph", "all"], default="all")
    parser.add_argument("--output", default="audit_report", help="Output filename (without extension)")
    args = parser.parse_args()
    
    # Demo findings
    demo_findings = [
        Finding(
            rule_id="UNCHECKED_EXTERNAL_CALL",
            severity="CRITICAL",
            category="Heuristic",
            title="Unchecked External Call",
            description="Low-level call without return value check. Funds may be lost if call fails silently.",
            file="contracts/Vault.sol",
            line_no=42,
            code_snippet="target.call{value: amount}(data);"
        ),
        Finding(
            rule_id="INTENT_IMPLEMENTATION_MISMATCH",
            severity="CRITICAL",
            category="Liar Detector",
            title="Intent Mismatch: withdrawFunds",
            description="Comment says 'only owner' but function is public with no modifiers.",
            file="contracts/Token.sol",
            line_no=100
        )
    ]
    
    report = create_audit_report(args.project, args.target, demo_findings)
    
    if args.format in ["html", "all"]:
        html_path = generate_html_report(report, f"{args.output}.html")
        print(f"[+] HTML report: {html_path}")
    
    if args.format in ["markdown", "all"]:
        md_path = generate_markdown_report(report, f"{args.output}.md")
        print(f"[+] Markdown report: {md_path}")
    
    if args.format in ["sarif", "all"]:
        metadata = {
            "project_name": args.project,
            "target_path": args.target,
            "timestamp": report.timestamp
        }
        sarif_path = save_sarif_report(demo_findings, f"{args.output}.sarif", metadata)
        print(f"[+] SARIF report: {sarif_path}")
    
    if args.format in ["pdf", "all"]:
        pdf_result = generate_pdf_report(report, f"{args.output}.pdf")
        if pdf_result:
            print(f"[+] PDF report: {pdf_result}")
        else:
            print("[!] PDF report not generated (check license or install xhtml2pdf)")

    if args.format in ["attack-graph", "all"]:
        if ATTACK_GRAPH_AVAILABLE:
            try:
                # Convert Finding objects to dicts for attack graph
                finding_dicts = []
                for f in demo_findings:
                    finding_dicts.append({
                        "rule_id": f.rule_id,
                        "severity": f.severity,
                        "file": f.file,
                        "line_no": f.line_no,
                        "message": f.description
                    })
                
                graph = build_graph(finding_dicts)
                graph_json = export_graph_json(graph)
                graph_path = generate_attack_graph_html(
                    graph_json,
                    f"{args.output}_attack_graph.html",
                    f"Attack Path Analysis - {args.project}"
                )
                print(f"[+] Attack graph: {graph_path}")
            except Exception as e:
                logger.error(f"Failed to generate attack graph: {e}")
                print(f"[!] Failed to generate attack graph: {e}")
        else:
            print("[!] Attack graph generation not available (attack_graph module not found)")
