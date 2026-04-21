from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime


@dataclass
class Finding:
    """Unified finding format across all analyzers."""
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    file: str
    line_no: int
    code_snippet: str = ""
    remediation: str = ""
    references: List[str] = ...
    cwe: Optional[str] = None
    owasp: Optional[str] = None


@dataclass
class ReportSection:
    """Represents a section in the final report."""
    title: str
    findings: List[Finding]
    summary: str


@dataclass
class AuditReport:
    """Complete audit report structure."""
    project_name: str
    target_path: str
    timestamp: str
    engine_version: str
    executive_summary: Dict[str, int]
    sections: List[ReportSection]
    risk_score: float
    pass_fail: str


# Severity weights for risk scoring
SEVERITY_WEIGHTS: Dict[str, float]

# SARIF severity mapping
SARIF_LEVEL_MAP: Dict[str, str]

# Garrison Engine version for SARIF reports
GARRISON_ENGINE_VERSION: str
GARRISON_ENGINE_SEMANTIC_VERSION: str
GARRISON_INFORMATION_URI: str

# Remediation knowledge base
REMEDIATION_KB: Dict[str, Dict[str, Any]]


def calculate_risk_score(findings: List[Finding]) -> float: ...
def get_pass_fail_status(findings: List[Finding]) -> str: ...
def enrich_finding(finding: Finding) -> Finding: ...
def generate_html_report(report: AuditReport, output_path: str, logo_path: Optional[str] = None) -> str: ...
def generate_sarif_report(
    findings: List[Finding], metadata: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]: ...
def save_sarif_report(
    findings: List[Finding], output_path: str, metadata: Optional[Dict[str, Any]] = None
) -> str: ...
def generate_markdown_report(report: AuditReport, output_path: str) -> str: ...
def aggregate_findings_from_orchestrator(
    static_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
    liar_results: List[Dict[str, Any]],
    access_matrix_results: List[Dict[str, Any]],
    aderyn_results: Optional[Dict[str, Any]],
    upgrade_diff_results: Optional[Dict[str, Any]],
    solana_results: Optional[Dict[str, Any]]
) -> List[Finding]: ...
def create_audit_report(
    project_name: str,
    target_path: str,
    findings: List[Finding],
    engine_version: str = "2.2"
) -> AuditReport: ...
