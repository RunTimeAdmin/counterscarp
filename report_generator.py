#!/usr/bin/env python3
"""
Professional Report Generator for Sentinel Engine
Generates client-ready HTML/Markdown reports with risk ratings and remediation
"""

from __future__ import annotations

import math
import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from logger import get_logger
from exceptions import SentinelReportError
from license_manager import LicenseManager, BRANDED_REPORTS

logger = get_logger(__name__)

# Optional attack graph imports (graceful fallback)
try:
    from attack_graph import build_graph, export_graph_json, trace_attack_paths
    from visualizer import generate_attack_graph_html
    ATTACK_GRAPH_AVAILABLE = True
except ImportError:
    ATTACK_GRAPH_AVAILABLE = False
    build_graph = None
    export_graph_json = None
    trace_attack_paths = None
    generate_attack_graph_html = None


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
        engine_version: Version of Sentinel Engine used.
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

# Sentinel Engine version for SARIF reports
SENTINEL_ENGINE_VERSION = "3.1.3"
SENTINEL_ENGINE_SEMANTIC_VERSION = "3.1.3"
SENTINEL_INFORMATION_URI = "https://github.com/RunTimeAdmin/sentinel-engine"

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
            finding.remediation = kb_entry.get("fix", "")
        if not finding.references:
            finding.references = kb_entry.get("references", [])
        if not finding.cwe:
            finding.cwe = kb_entry.get("cwe")
    
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
            logo_html = f'<img src="data:{mime};base64,{logo_b64}" alt="Sentinel Engine" style="height: 60px; margin-right: 15px; vertical-align: middle;">'
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
                <strong>Engine:</strong> Sentinel Engine {report.engine_version}
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
            
            html += "            </div>\n"
        
        html += "        </div>\n"

    html += """
        <div class="footer">
            Generated by <strong>Sentinel Security Engine</strong> • sentinel-engine.io<br>
            For questions or clarifications, contact your security team.
        </div>
    </div>
</body>
</html>
"""

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html)
    
    return output_path


def generate_sarif_report(findings: List[Finding], metadata: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Generate a SARIF 2.1.0 compliant report from findings.

    Args:
        findings: List of Finding objects to include in the report.
        metadata: Optional metadata dict with keys like 'project_name', 'target_path'.

    Returns:
        A dictionary representing a valid SARIF 2.1.0 JSON document.
        Always returns a valid SARIF structure with a non-null 'runs' array.

    Raises:
        SentinelReportError: If report generation fails.

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
            result = {
                "ruleId": finding.rule_id,
                "level": SARIF_LEVEL_MAP.get(finding.severity, "warning"),
                "message": {
                    "text": finding.description
                },
                "locations": []
            }
            
            # Add location if file path is available
            if finding.file:
                location = {
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
            
            results.append(result)
        
        # Build the SARIF document - ALWAYS has valid runs array
        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Sentinel Engine",
                            "version": SENTINEL_ENGINE_VERSION,
                            "semanticVersion": SENTINEL_ENGINE_SEMANTIC_VERSION,
                            "informationUri": SENTINEL_INFORMATION_URI,
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
        raise SentinelReportError(
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
        SentinelReportError: If the file cannot be written.

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
                        "name": "Sentinel Engine",
                        "version": SENTINEL_ENGINE_VERSION,
                        "informationUri": SENTINEL_INFORMATION_URI
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
        raise SentinelReportError(
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
**Engine:** Sentinel Engine {report.engine_version}  
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

---

"""

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
            md += f"**Severity:** {finding.severity}  \n"
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
            
            md += "---\n\n"

    md += """
---

*Generated by **Sentinel Security Engine** • CyberShield Austin / TokenAudit*
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
            code_snippet=item.get("line_text", "")
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


def create_audit_report(
    project_name: str,
    target_path: str,
    findings: List[Finding],
    engine_version: str = "2.2"
) -> AuditReport:
    """Build complete audit report from findings.

    Args:
        project_name: Name of the project being audited.
        target_path: Path to the analyzed target.
        findings: List of findings to include in the report.
        engine_version: Version of the Sentinel Engine.

    Returns:
        Complete AuditReport object.
    """
    
    # Group by category
    sections = {}
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
        pass_fail=get_pass_fail_status(findings)
    )
    
    return report


# CLI for standalone testing
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate professional audit report")
    parser.add_argument("--project", default="Test Project", help="Project name")
    parser.add_argument("--target", default="./contracts", help="Target path")
    parser.add_argument("--format", choices=["html", "markdown", "sarif", "attack-graph", "all"], default="all")
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
