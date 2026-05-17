from __future__ import annotations

import asyncio
import sys
import os
import argparse
import datetime
import tempfile
import types as _types
from typing import List, Dict, Optional, Any, Type, cast
from pathlib import Path

from logger import get_logger, setup_logging

try:
    from importlib.metadata import version as _pkg_version
    _ENGINE_VERSION = _pkg_version("counterscarp-engine")
except Exception:
    _ENGINE_VERSION = "5.0.0"

from license_manager import (
    LicenseManager, AI_COPILOT, TIME_TRAVEL, FINGERPRINT,
    SOLANA, BRANDED_REPORTS, EXPLOIT_GEN
)

logger = get_logger(__name__)
_license = LicenseManager()

# Import your specialists
try:
    import red_team_scan
    from exceptions import CounterscarpAnalysisError
    import supply_chain_check
    import fuzz_wrapper
    import heuristic_scanner
    import symbolic_wrapper
    logger.debug("Core modules imported successfully")
except ImportError as e:
    logger.critical("Missing a core module: %s", e)
    sys.exit(1)

# Optional fingerprint scanner
try:
    import fingerprint_scanner
    from protocol_db import get_default_fingerprints, load_fingerprint_db
    FINGERPRINT_AVAILABLE = True
    logger.debug("Fingerprint scanner imported successfully")
except ImportError as e:
    logger.info(f"Fingerprint scanner not available: {e}")
    FINGERPRINT_AVAILABLE = False

# Optional advanced analyzers (best-effort imports)
aderyn_wrapper: Optional[_types.ModuleType] = None
try:
    import aderyn_wrapper
    logger.debug("Aderyn wrapper imported successfully")
except ImportError as e:
    logger.info(f"Aderyn wrapper not available: {e}")
    aderyn_wrapper = None

medusa_wrapper: Optional[_types.ModuleType] = None
try:
    import medusa_wrapper
    logger.debug("Medusa wrapper imported successfully")
except ImportError as e:
    logger.info(f"Medusa wrapper not available: {e}")
    medusa_wrapper = None

solana_analyzer: Optional[_types.ModuleType] = None
try:
    import solana_analyzer
    logger.debug("Solana analyzer imported successfully")
except ImportError as e:
    logger.info(f"Solana analyzer not available: {e}")
    solana_analyzer = None

upgrade_diff: Optional[_types.ModuleType] = None
try:
    import upgrade_diff
    logger.debug("Upgrade diff module imported successfully")
except ImportError as e:
    logger.info(f"Upgrade diff module not available: {e}")
    upgrade_diff = None

history_scanner: Optional[_types.ModuleType] = None
try:
    import history_scanner
    logger.debug("History scanner imported successfully")
except ImportError as e:
    logger.info(f"History scanner not available: {e}")
    history_scanner = None

CounterscarpConfig: Optional[Type[Any]] = None
load_config: Optional[Any] = None
try:
    from config_loader import load_config, CounterscarpConfig
    CONFIG_AVAILABLE = True
    logger.debug("Config loader imported successfully")
except ImportError as e:
    logger.info(f"Config loader not available: {e}")
    CONFIG_AVAILABLE = False

# Optional plugin manager
PluginManager: Optional[Type[Any]] = None
try:
    from plugin_manager import PluginManager
    PLUGIN_MANAGER_AVAILABLE = True
    logger.debug("Plugin manager imported successfully")
except ImportError as e:
    logger.info(f"Plugin manager not available: {e}")
    PLUGIN_MANAGER_AVAILABLE = False

try:
    from report_generator import (
        aggregate_findings_from_orchestrator,
        create_audit_report,
        generate_html_report,
        generate_pdf_report,
        generate_markdown_report
    )
    REPORT_GENERATOR_AVAILABLE = True
    logger.debug("Report generator imported successfully")
except ImportError as e:
    logger.info(f"Report generator not available: {e}")
    REPORT_GENERATOR_AVAILABLE = False

# Optional RAG engine
AuditCopilot: Optional[Type[Any]] = None
try:
    from rag_engine import AuditCopilot
    RAG_AVAILABLE = True
    logger.debug("RAG engine imported successfully")
except ImportError as e:
    logger.info(f"RAG engine not available: {e}")
    RAG_AVAILABLE = False

# --- KNOWLEDGE BASE: HOW TO FIX THINGS ---
# Maps specific vulnerability types to concrete code actions.
REMEDIATION_DB = {
    # Reentrancy
    "reentrancy-eth": "Apply OpenZeppelin's `ReentrancyGuard` to this function and add the `nonReentrant` modifier. Ensure state changes happen BEFORE external calls.",
    "reentrancy-no-eth": "Even if no ETH is sent, external calls can re-enter. Add `nonReentrant` or move the external call to the end of the function.",

    # Access Control
    "protected-vars": "This function is `public`/`external` but lacks access control. Add `onlyOwner` (from Ownable) or a specific role check.",
    "unprotected-upgrade": "The `upgradeTo` function is unprotected. Add `onlyOwner` or `onlyProxyAdmin` immediately to prevent takeover.",

    # Math & Logic
    "divide-before-multiply": "Precision loss detected. Change the order of operations: Multiply first, then divide. Example: `(a * b) / c` instead of `(a / c) * b`.",
    "incorrect-equality": "Do not compare strictly equal to (`==`) for funds/balance checks, as forceful sends can break this. Use `>=`.",

    # Best Practices
    "timestamp": "Block timestamp can be manipulated by miners (~15s). Do not use `block.timestamp` for randomness or critical logic. Use Chainlink VRF for randomness.",
    "shadowing-state": "This variable name overrides a state variable. Rename the local variable to avoid confusion (e.g., `_owner` instead of `owner`).",
}


def get_remediation(issue_type: str, context: str) -> str:
    """Look up the fix. If not found, generate a generic action.

    Args:
        issue_type: The type of vulnerability/issue.
        context: Additional context about the issue location.

    Returns:
        Remediation guidance string.
    """
    # Try exact match
    if issue_type in REMEDIATION_DB:
        return REMEDIATION_DB[issue_type]

    # Try partial match (e.g., "reentrancy" matches "reentrancy-benign")
    for key, fix in REMEDIATION_DB.items():
        if key in issue_type:
            return fix

    return f"Review logic at `{context[:20]}...`. Ensure strict validation of inputs and access control."


def _aggregate_findings(
    static_results: List[Dict[str, Any]],
    supply_results: List[Dict[str, Any]],
    fuzz_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
    symbolic_results: List[Dict[str, Any]],
    aderyn_results: Optional[Dict[str, Any]] = None,
    medusa_results: Optional[Dict[str, Any]] = None,
    solana_results: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Aggregate all analyzer outputs into a unified findings list.

    Takes raw results from each analyzer and normalizes them into a common
    schema with severity, rule_id, location, and message fields.

    Returns:
        Sorted list of unified finding dicts (CRITICAL first).
    """
    all_findings: List[Dict[str, Any]] = []

    # static_results
    for item in static_results:
        all_findings.append({
            "severity": item.get("impact", "MEDIUM").upper(),
            "rule_id": item.get("check") or item.get("rule_id") or item.get("title", "unknown"),
            "location": f"{item.get('file', item.get('location', 'unknown'))}:{item.get('line_no', item.get('line', '?'))}",
            "message": (item.get("message") or item.get("description", ""))[:80],
        })

    # heuristic_results
    for item in heuristic_results:
        all_findings.append({
            "severity": item.get("severity", "MEDIUM").upper(),
            "rule_id": item.get("rule_id") or item.get("check") or item.get("title", "unknown"),
            "location": f"{item.get('file', 'unknown')}:{item.get('line_no', item.get('line', '?'))}",
            "message": (item.get("message") or item.get("description", ""))[:80],
        })

    # fuzz_results — all CRITICAL
    for item in fuzz_results:
        all_findings.append({
            "severity": "CRITICAL",
            "rule_id": item.get("test_name") or item.get("rule_id") or item.get("title", "fuzz_violation"),
            "location": item.get("file", item.get("location", "unknown")),
            "message": (item.get("message") or item.get("description", ""))[:80],
        })

    # symbolic_results
    for item in symbolic_results:
        all_findings.append({
            "severity": item.get("severity", "MEDIUM").upper(),
            "rule_id": item.get("rule_id") or item.get("check") or item.get("title", "symbolic_issue"),
            "location": f"{item.get('file', 'unknown')}:{item.get('line_no', item.get('line', '?'))}",
            "message": (item.get("message") or item.get("description", ""))[:80],
        })

    # aderyn_results
    if aderyn_results and isinstance(aderyn_results, dict):
        for item in aderyn_results.get("issues", []):
            all_findings.append({
                "severity": item.get("severity", "MEDIUM").upper(),
                "rule_id": item.get("rule_id") or item.get("check") or item.get("title", "aderyn_issue"),
                "location": f"{item.get('file', 'unknown')}:{item.get('line_no', item.get('line', '?'))}",
                "message": (item.get("message") or item.get("description", ""))[:80],
            })

    # medusa_results
    if medusa_results and isinstance(medusa_results, dict):
        for item in medusa_results.get("findings", []):
            all_findings.append({
                "severity": item.get("severity", "HIGH").upper(),
                "rule_id": item.get("test") or item.get("rule_id") or item.get("title", "medusa_violation"),
                "location": f"{item.get('file', 'unknown')}:{item.get('line_no', item.get('line', '?'))}",
                "message": (item.get("message") or item.get("description", ""))[:80],
            })

    # solana_results
    if solana_results and isinstance(solana_results, dict):
        for item in solana_results.get("pattern_findings", []):
            sev = getattr(item, "severity", None) or item.get("severity", "MEDIUM") if isinstance(item, dict) else getattr(item, "severity", "MEDIUM")
            rid = getattr(item, "rule_id", None) or (item.get("rule_id") if isinstance(item, dict) else None) or "solana_issue"
            loc_file = getattr(item, "file", None) or (item.get("file") if isinstance(item, dict) else "unknown") or "unknown"
            loc_line = getattr(item, "line_no", None) or (item.get("line_no") if isinstance(item, dict) else "?") or "?"
            msg = getattr(item, "description", None) or (item.get("description") if isinstance(item, dict) else "") or ""
            all_findings.append({
                "severity": str(sev).upper(),
                "rule_id": str(rid),
                "location": f"{loc_file}:{loc_line}",
                "message": str(msg)[:80],
            })

    # Sort: CRITICAL first
    _severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    all_findings.sort(key=lambda _x: _severity_order.get(_x.get("severity", "MEDIUM").upper(), 5))

    return all_findings


def _maybe_print_cli_alias_notice() -> None:
    """Show migration hint when legacy command names are used."""
    invoked_as = os.path.basename(sys.argv[0]).lower()
    if invoked_as in {"counterscarp", "counterscarp-engine"}:
        logger.info(
            "Command alias note: '%s' remains supported; preferred commands are "
            "'scarpshield' and 'scarpshield-engine'.",
            invoked_as,
        )


def _compute_risk_metrics(
    all_findings: List[Dict[str, Any]],
    fuzz_results: List[Dict[str, Any]],
    static_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Compute aggregate risk score, severity distribution, and pass/fail.

    Args:
        all_findings: Unified findings list from _aggregate_findings.
        fuzz_results: Raw fuzz results (for critical count).
        static_results: Raw static results (for critical count).
        heuristic_results: Raw heuristic results (for critical count).

    Returns:
        Dict with severity_counts, critical_count, status_icon, total_findings.
    """
    critical_count = len(fuzz_results)
    for result in static_results:
        if result.get("impact", "").lower() in ("high", "critical"):
            critical_count += 1
    for result in heuristic_results:
        if result.get("severity", "").upper() == "CRITICAL":
            critical_count += 1
    status_icon = "[CRITICAL]" if critical_count > 0 else "[STABLE]"

    _severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for _f in all_findings:
        _sev = _f.get("severity", "MEDIUM").upper()
        if _sev in _severity_counts:
            _severity_counts[_sev] += 1

    _total_findings = sum(_severity_counts.values())

    return {
        "severity_counts": _severity_counts,
        "critical_count": critical_count,
        "status_icon": status_icon,
        "total_findings": _total_findings,
    }


def _resolve_writable_log_dir() -> str:
    """Pick a writable directory for runtime scan logs.

    Package-install locations (for example site-packages in containers) can be
    read-only for non-root users. This helper ensures logs are always written
    to a writable location.
    """
    candidates = [
        Path.cwd(),
        Path.home() / ".scarpshield",
        Path(tempfile.gettempdir()) / "scarpshield",
    ]
    for candidate in candidates:
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            probe = candidate / ".log_write_probe"
            with open(probe, "w", encoding="utf-8") as fh:
                fh.write("ok")
            probe.unlink(missing_ok=True)
            return str(candidate)
        except OSError:
            continue
    return tempfile.gettempdir()


def _render_markdown_report(
    f,
    project_name: str,
    all_findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    static_results: List[Dict[str, Any]],
    supply_results: List[Dict[str, Any]],
    fuzz_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
    symbolic_results: List[Dict[str, Any]],
    aderyn_results: Optional[Dict[str, Any]] = None,
    medusa_results: Optional[Dict[str, Any]] = None,
    solana_results: Optional[Dict[str, Any]] = None,
    upgrade_results: Optional[Dict[str, Any]] = None,
    fingerprint_results: Optional[List[Dict[str, Any]]] = None,
    exploit_results: Optional[List] = None,
    analyzer_status: Optional[Dict[str, Any]] = None,
) -> None:
    """Render the Markdown version of the action plan report.

    Writes the full Markdown report content to the given file handle.
    """
    critical_count = metrics["critical_count"]
    status_icon = metrics["status_icon"]
    _severity_counts = metrics["severity_counts"]
    _total_findings = metrics["total_findings"]

    # Executive Summary
    f.write("# Security Remediation Plan\n")
    f.write(f"**Target:** `{project_name}`\n")
    f.write(f"**Status:** {status_icon} ({critical_count} Critical Issues)\n")
    f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")

    f.write("> **Objective:** This document lists specific, actionable steps to patch identified vulnerabilities. Prioritize 'Critical' items immediately.\n\n")

    f.write("---\n\n")

    # Executive Summary table
    f.write("## Executive Summary\n\n")
    f.write("| Severity | Count |\n")
    f.write("|----------|-------|\n")
    f.write(f"| CRITICAL | {_severity_counts['CRITICAL']} |\n")
    f.write(f"| HIGH | {_severity_counts['HIGH']} |\n")
    f.write(f"| MEDIUM | {_severity_counts['MEDIUM']} |\n")
    f.write(f"| LOW | {_severity_counts['LOW']} |\n")
    f.write(f"| INFO | {_severity_counts['INFO']} |\n")
    f.write(f"| **Total** | **{_total_findings}** |\n\n")

    top10 = all_findings[:10]
    if top10:
        f.write("### Top 10 Priority Issues\n\n")
        f.write("| # | Severity | Issue | Location | Description |\n")
        f.write("|---|----------|-------|----------|-------------|\n")
        for _idx, _finding in enumerate(top10, 1):
            _sev = _finding.get("severity", "MEDIUM")
            _issue = _finding.get("rule_id", "unknown")
            _loc = _finding.get("location", "unknown")
            _desc = _finding.get("message", "").replace("|", "\\|")
            f.write(f"| {_idx} | {_sev} | {_issue} | {_loc} | {_desc} |\n")
        f.write("\n")

    f.write("---\n\n")

    # ANALYZER COVERAGE TABLE
    if analyzer_status:
        f.write("## Analyzer Coverage\n\n")
        f.write("| Analyzer | Status | Findings |\n")
        f.write("|----------|--------|----------|\n")
        _failed_analyzers = []
        for _aname, _astatus in analyzer_status.items():
            if _astatus.get("ran"):
                _acount = _astatus.get("finding_count", 0)
                f.write(f"| {_aname} | Completed | {_acount} |\n")
            elif _astatus.get("error") == "Not enabled":
                f.write(f"| {_aname} | Skipped (not enabled) | — |\n")
            else:
                f.write(f"| {_aname} | **FAILED** | — |\n")
                _failed_analyzers.append((_aname, _astatus.get("error", "Unknown error")))
        f.write("\n")
        for _aname, _aerr in _failed_analyzers:
            f.write(f"> **Warning:** {_aname} did not complete successfully ({_aerr}). Results below may be incomplete.\n\n")
        f.write("---\n\n")

    # SECTION 1: SUPPLY CHAIN (DEPENDENCIES)
    f.write("## 1. Dependency Updates (Supply Chain)\n")
    if not supply_results:
        f.write("[OK] **No Action Required.** All dependencies are up to date.\n\n")
    else:
        f.write("| Severity | Library | Action Required |\n")
        f.write("| :--- | :--- | :--- |\n")
        for item in supply_results:
            f.write(
                f"| [!] | `{item['library']}` | **Run:** `npm update {item['library']}` <br> **Reason:** {item.get('summary', 'Known Vulnerability')} |\n"
            )
        f.write("\n")

    f.write("---\n\n")

    # SECTION 2: CODE VULNERABILITIES (STATIC)
    f.write("## 2. Code Patches (Static Analysis)\n")
    if not static_results:
        f.write("[OK] **No Action Required.** No critical patterns found.\n\n")
    else:
        for i, item in enumerate(static_results, 1):
            impact = item.get("impact", "Unknown")
            priority = "[IMMEDIATE]" if impact == "High" else "[HIGH]"
            action = get_remediation(item.get("title", ""), item.get("description", ""))

            f.write(f"### {i}. {item.get('title', 'Unknown Issue')} ({priority})\n")
            f.write(f"- **Location:** `{item.get('location', 'Unknown location')}`\n")
            f.write(f"- **The Issue:** {item.get('description', 'No description provided')}\n")
            f.write(f"- **ACTION:** {action}\n\n")

    f.write("---\n\n")

    # SECTION 3: LOGIC FAILURES (FUZZING)
    f.write("## 3. Logic & Invariant Patches (Dynamic)\n")
    if not fuzz_results:
        f.write("[OK] **No Action Required.** Logic held up against stress testing.\n\n")
    else:
        for item in fuzz_results:
            test_name = item.get("test_name", "UnknownTest")
            steps = item.get("steps", [])

            f.write(f"### Logic Failure: `{test_name}`\n")
            f.write("**Diagnosis:** The protocol entered an invalid state (Invariant broken).\n\n")
            f.write("**ACTION:**\n")
            f.write("1. Create a new test file `test/Exploit.t.sol`.\n")
            f.write("2. Paste the 'Kill Shot' sequence below into it.\n")
            f.write(f"3. Modify `{test_name}` to handle this edge case (usually by adding `require()` checks).\n\n")

            f.write("**The Kill Shot (Trace):**\n")
            f.write("```solidity\n")
            for step in steps:
                f.write(f"{step}\n")
            f.write("```\n\n")

    f.write("---\n\n")

    # SECTION 4: HEURISTIC FINDINGS (PATTERN-BASED)
    f.write("## 4. Heuristic Findings (Pattern-Based)\n")
    if not heuristic_results:
        f.write("[OK] **No heuristic red flags detected.** (Note: this does *not* guarantee safety.)\n\n")
    else:
        for item in heuristic_results:
            severity = item.get("severity", "INFO")
            rule_id = item.get("rule_id", "")
            message = item.get("message", "")
            location = f"{item.get('file', 'unknown_file')}:{item.get('line_no', '?')}"
            code = (item.get("line_text", "") or "").strip()

            f.write(f"- **[{severity}] {rule_id}:** {message}\n")
            f.write(f"  - Location: `{location}`\n")
            if code:
                f.write(f"  - Code: `{code}`\n")
            f.write("\n")

    f.write("---\n\n")

    # SECTION 5: SYMBOLIC ANALYSIS (MYTHRIL)
    f.write("## 5. Symbolic Analysis (Mythril)\n")
    if not symbolic_results:
        f.write("[OK] **No issues reported by Mythril for this run.**\n\n")
    else:
        for i, issue in enumerate(symbolic_results, 1):
            title = issue.get("title") or "Unnamed issue"
            severity = issue.get("severity") or "UNKNOWN"
            f.write(f"### {i}. {title} ({severity})\n")
            if issue.get("swc_id"):
                f.write(f"- **SWC:** {issue['swc_id']}\n")
            if issue.get("function"):
                f.write(f"- **Function:** `{issue['function']}`\n")
            if issue.get("address"):
                f.write(f"- **Address/PC:** `{issue['address']}`\n")
            desc = issue.get("description") or ""
            if desc:
                f.write(f"- **Details:** {desc}\n")
            f.write("\n")

    # SECTION 6: ADERYN STATIC ANALYSIS (OPTIONAL)
    f.write("---\n\n")
    f.write("## 6. Aderyn Static Analysis (Optional)\n")
    if not aderyn_results:
        f.write("\u2139\ufe0f Aderyn analysis not run or produced no results.\n\n")
    elif isinstance(aderyn_results, dict) and aderyn_results.get("error"):
        f.write(f"[!] Aderyn error: {aderyn_results['error']}\n\n")
    else:
        total = aderyn_results.get("total", 0)
        high_count = len(aderyn_results.get("high", []))
        low_count = len(aderyn_results.get("low", []))
        nc_count = len(aderyn_results.get("nc", []))
        f.write(
            f"[*] Total issues: {total} (High: {high_count}, Low: {low_count}, Non-critical: {nc_count})\n\n"
        )
        high_issues = aderyn_results.get("high", [])[:5]
        if high_issues:
            f.write("### Top High Severity Findings (Aderyn)\n")
            for issue in high_issues:
                title = issue.get("title", "Unknown issue")
                detector = issue.get("detector_name", "unknown")
                f.write(f"- **{title}** (Detector: {detector})\n")
            f.write("\n")

    # SECTION 7: MEDUSA FUZZING (OPTIONAL)
    f.write("---\n\n")
    f.write("## 7. Medusa Fuzzing (Coverage-Guided)\n")
    if not medusa_results:
        f.write("\u2139\ufe0f Medusa fuzzing not run or produced no results.\n\n")
    elif isinstance(medusa_results, dict) and medusa_results.get("error"):
        f.write(f"[!] Medusa error: {medusa_results['error']}\n\n")
    else:
        findings = medusa_results.get("findings", [])
        stats = medusa_results.get("statistics", {})
        total_seq = medusa_results.get("total_sequences", "unknown")
        coverage = stats.get("coverage_percent", "N/A")
        f.write(f"[*] Total sequences run: {total_seq}, Coverage: {coverage}%\n\n")
        if not findings:
            f.write("[+] No invariant violations found by Medusa.\n\n")
        else:
            f.write(f"[!] Medusa found {len(findings)} invariant violations.\n\n")
            for finding in findings[:5]:
                test_name = finding.get("test", "unknown")
                status = finding.get("status", "")
                f.write(f"- **{test_name}** ({status})\n")
            if len(findings) > 5:
                f.write(f"- ... ({len(findings) - 5} more violations)\n")
            f.write("\n")

    # SECTION 8: SOLANA/ANCHOR STATIC ANALYSIS (OPTIONAL)
    f.write("---\n\n")
    f.write("## 8. Solana/Anchor Static Analysis (Optional)\n")
    if not solana_results:
        f.write("\u2139\ufe0f Solana analysis not run or no Solana project configured.\n\n")
    elif isinstance(solana_results, dict) and solana_results.get("summary"):
        summary = solana_results["summary"]
        f.write(
            f"[*] Findings \u2192 CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
            f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}\n\n"
        )
        pattern_findings = solana_results.get("pattern_findings", [])
        criticals = [
            f_item for f_item in pattern_findings if getattr(f_item, "severity", None) == "CRITICAL"
        ][:5]
        if criticals:
            f.write("### Top Critical Solana Findings\n")
            for finding in criticals:
                f.write(
                    f"- **{finding.title}** in `{finding.file}:{finding.line_no}` \u2013 {finding.description}\n"
                )
            f.write("\n")

    # SECTION 9: UPGRADE DIFF ANALYSIS (OPTIONAL)
    f.write("---\n\n")
    f.write("## 9. Upgrade Diff Analysis (Optional)\n")
    if not upgrade_results:
        f.write("\u2139\ufe0f No upgrade diff analysis run for this report.\n\n")
    elif isinstance(upgrade_results, dict) and upgrade_results.get("summary"):
        summary = upgrade_results["summary"]
        f.write(
            f"[*] Issues \u2192 CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
            f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}\n\n"
        )
        if upgrade_results.get("safe"):
            f.write("[OK] SAFE TO UPGRADE (no critical/high issues detected).\n\n")
        else:
            f.write("[!] UNSAFE TO UPGRADE - address critical/high issues before deploying.\n\n")

    # SECTION 10: PROTOCOL FINGERPRINT ANALYSIS (OPTIONAL)
    f.write("---\n\n")
    f.write("## 10. Protocol Fingerprint Analysis (Optional)\n")
    if not fingerprint_results:
        f.write("\u2139\ufe0f No protocol fingerprint analysis run for this report.\n\n")
    else:
        total_matches = sum(len(r.get("matches", [])) for r in fingerprint_results)
        f.write(f"[*] Found {len(fingerprint_results)} contract(s) with {total_matches} protocol match(es)\n\n")

        for result in fingerprint_results:
            file_path = result.get("file", "unknown")
            matches = result.get("matches", [])
            risk = result.get("risk_assessment", {})

            f.write(f"### {os.path.basename(file_path)}\n")
            f.write(f"- **Path:** `{file_path}`\n")
            f.write(f"- **Risk Level:** {risk.get('risk_level', 'N/A')}\n")
            f.write(f"- **Risk Score:** {risk.get('risk_score', 0)}/100\n")
            f.write(f"- **Inherited Vulnerabilities:** {risk.get('total_vulnerabilities', 0)}\n\n")

            if matches:
                f.write("**Protocol Matches:**\n")
                for match in matches[:3]:  # Show top 3
                    f.write(f"- **{match.get('protocol', 'Unknown')}** ({match.get('category', 'Unknown')}) - {match.get('confidence', 0) * 100:.1f}% confidence\n")
                    if match.get('known_vulnerabilities'):
                        high_crit = sum(1 for v in match.get('known_vulnerabilities', []) if v.get('severity') in ['CRITICAL', 'HIGH'])
                        if high_crit > 0:
                            f.write(f"  [!] {high_crit} high/critical vulnerabilities inherited\n")
                if len(matches) > 3:
                    f.write(f"- ... and {len(matches) - 3} more match(es)\n")
                f.write("\n")

            if risk.get('recommendations'):
                f.write("**Recommendations:**\n")
                for rec in risk.get('recommendations', [])[:3]:
                    f.write(f"- {rec}\n")
                f.write("\n")

    # SECTION 11: EXPLOIT PROOF-OF-CONCEPT TESTS (PRO TIER)
    if exploit_results:
        f.write("---\n\n")
        f.write("## 11. Exploit Proof-of-Concept Tests\n\n")
        successful_exploits = [r for r in exploit_results if r.status == "success"]
        if successful_exploits:
            f.write(f"Generated **{len(successful_exploits)}** exploit PoC test(s) for critical findings.\n\n")
            f.write("| Finding | Severity | Output File | Status |\n")
            f.write("|---------|----------|-------------|--------|\n")
            for r in exploit_results:
                finding_name = r.finding.get("rule_id", r.finding.get("check", "unknown"))
                severity = r.finding.get("severity", "N/A")
                output_path = r.output_path or "\u2014"
                f.write(f"| {finding_name} | {severity} | `{output_path}` | {r.status} |\n")
            f.write("\n> **Run:** `forge test --match-path exploits/` to validate generated PoCs\n\n")
        else:
            f.write("No exploit PoCs were successfully generated for the detected findings.\n\n")


def _resolve_action_plan_path(output_dir: Optional[str] = None) -> str:
    """Compute the output file path for the action plan report.

    Args:
        output_dir: Optional directory to place the report in (created if absent).

    Returns:
        Resolved file path string.
    """
    _action_plan_name = "ACTION_PLAN.md"
    if output_dir:
        from pathlib import Path as _Path
        _Path(output_dir).mkdir(parents=True, exist_ok=True)
        return str(_Path(output_dir) / _action_plan_name)
    return f"ACTION_PLAN_{datetime.date.today()}.md"


def _format_action_plan_section(
    project_name: str,
    all_findings: List[Dict[str, Any]],
    metrics: Dict[str, Any],
    static_results: List[Dict[str, Any]],
    supply_results: List[Dict[str, Any]],
    fuzz_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
    symbolic_results: List[Dict[str, Any]],
    aderyn_results: Optional[Dict[str, Any]] = None,
    medusa_results: Optional[Dict[str, Any]] = None,
    solana_results: Optional[Dict[str, Any]] = None,
    upgrade_results: Optional[Dict[str, Any]] = None,
    fingerprint_results: Optional[List[Dict[str, Any]]] = None,
    exploit_results: Optional[List] = None,
    analyzer_status: Optional[Dict[str, Any]] = None,
) -> str:
    """Pure formatting: render the complete action plan as a Markdown string.

    Delegates to ``_render_markdown_report`` using an in-memory buffer so that
    no file I/O occurs in this function.

    Returns:
        The full Markdown report content as a string.
    """
    import io
    buf = io.StringIO()
    _render_markdown_report(
        buf,
        project_name=project_name,
        all_findings=all_findings,
        metrics=metrics,
        static_results=static_results,
        supply_results=supply_results,
        fuzz_results=fuzz_results,
        heuristic_results=heuristic_results,
        symbolic_results=symbolic_results,
        aderyn_results=aderyn_results,
        medusa_results=medusa_results,
        solana_results=solana_results,
        upgrade_results=upgrade_results,
        fingerprint_results=fingerprint_results,
        exploit_results=exploit_results,
        analyzer_status=analyzer_status,
    )
    return buf.getvalue()


def _write_action_plan_file(path: str, content: str) -> None:
    """Write action plan content to the specified file path.

    Args:
        path: Destination file path.
        content: Markdown content to write.
    """
    with open(path, "w", encoding="utf-8", errors="replace") as f:
        f.write(content)


def _generate_action_plan_report(
    project_name: str,
    static_results: List[Dict[str, Any]],
    supply_results: List[Dict[str, Any]],
    fuzz_results: List[Dict[str, Any]],
    heuristic_results: List[Dict[str, Any]],
    symbolic_results: List[Dict[str, Any]],
    aderyn_results: Optional[Dict[str, Any]] = None,
    medusa_results: Optional[Dict[str, Any]] = None,
    solana_results: Optional[Dict[str, Any]] = None,
    upgrade_results: Optional[Dict[str, Any]] = None,
    fingerprint_results: Optional[List[Dict[str, Any]]] = None,
    exploit_results: Optional[List] = None,
    analyzer_status: Optional[Dict[str, Any]] = None,
    output_dir: Optional[str] = None,
) -> str:
    """Generates an action-plan report focused on REMEDIATION (Fixing the bugs).

    Thin orchestrator that delegates to focused helpers:
    - ``_resolve_action_plan_path`` — file path resolution
    - ``_aggregate_findings`` / ``_compute_risk_metrics`` — data aggregation
    - ``_format_action_plan_section`` — pure Markdown formatting
    - ``_write_action_plan_file`` — file I/O

    Returns:
        Path to the generated markdown report file.
    """
    filename = _resolve_action_plan_path(output_dir)

    all_findings = _aggregate_findings(
        static_results=static_results,
        supply_results=supply_results,
        fuzz_results=fuzz_results,
        heuristic_results=heuristic_results,
        symbolic_results=symbolic_results,
        aderyn_results=aderyn_results,
        medusa_results=medusa_results,
        solana_results=solana_results,
    )

    metrics = _compute_risk_metrics(
        all_findings=all_findings,
        fuzz_results=fuzz_results,
        static_results=static_results,
        heuristic_results=heuristic_results,
    )

    content = _format_action_plan_section(
        project_name=project_name,
        all_findings=all_findings,
        metrics=metrics,
        static_results=static_results,
        supply_results=supply_results,
        fuzz_results=fuzz_results,
        heuristic_results=heuristic_results,
        symbolic_results=symbolic_results,
        aderyn_results=aderyn_results,
        medusa_results=medusa_results,
        solana_results=solana_results,
        upgrade_results=upgrade_results,
        fingerprint_results=fingerprint_results,
        exploit_results=exploit_results,
        analyzer_status=analyzer_status,
    )

    _write_action_plan_file(filename, content)
    return filename


def _safe_line_no(location_str: str) -> int:
    """Extract line number from location string, handling various formats.

    Handles:
    - Standard ``file:line`` format (e.g. ``Contract.sol:42``)
    - Slither multi-line format ``file (Lines: [80, 81, 82, ...])``
    """
    if not location_str or ":" not in location_str:
        return 0
    try:
        part = location_str.split(":")[-1].strip()
        # Handle "(Lines: [80, 81, ...])" suffix — extract first number
        if part.startswith("[") or part.startswith(" ["):
            import re
            nums = re.findall(r'\d+', part)
            return int(nums[0]) if nums else 0
        return int(part)
    except (ValueError, IndexError):
        return 0


def _restore_ctx_from_cache(phase: Any, ctx: Any, cached: Any) -> None:
    """Restore a cached phase result into the appropriate ScanContext field(s).

    Called during --resume when a phase was already completed in a prior session.
    Each phase class may have a custom ``load_cached`` method; otherwise we apply
    a simple name-based dispatch to update the right ctx field.
    """
    if hasattr(phase, "load_cached"):
        # Phase provides its own restore logic (e.g. RagEnrichPhase)
        phase.load_cached(ctx, cached)
        return

    name = phase.name
    if name == "supply_chain":
        ctx.supply_issues = cached or []
    elif name == "slither":
        ctx.static_issues = cached or []
    elif name == "aderyn":
        ctx.aderyn_results = cached
    elif name == "foundry_fuzz":
        ctx.fuzz_issues = cached or []
    elif name == "medusa_fuzz":
        ctx.medusa_results = cached
    elif name == "heuristic":
        ctx.heuristic_results = cached or []
    elif name == "plugins":
        ctx.heuristic_results.extend(cached or [])
    elif name == "fingerprint":
        ctx.fingerprint_results = cached or []
    elif name == "mythril":
        ctx.symbolic_results = cached or []
    elif name == "solana":
        ctx.solana_results = cached
    elif name == "upgrade_diff":
        ctx.upgrade_results = cached
    elif name == "exploit_gen":
        # exploit_results objects not easily re-serialized; skip (None is safe)
        ctx.exploit_results = None
    elif name == "time_travel":
        ctx.history_timeline = cached or []
    # "rag_enrichment" and "report" are handled by load_cached / skip respectively


# ---------------------------------------------------------------------------
# Async phase execution helpers (used by webapp / async callers)
# ---------------------------------------------------------------------------


# Concurrency groups for run_phases_async.
# Phases within a group run concurrently; groups run sequentially.
# _CONCURRENT_GROUPS: List[List[str]] = [
#     ["supply_chain"],
#     ["slither", "aderyn"],
#     ["foundry_fuzz", "medusa_fuzz"],
#     ["heuristic", "fingerprint"],
#     ["plugins"],
#     ["mythril"],
#     ["solana", "upgrade_diff"],
#     ["rag_enrichment"],
#     ["exploit_gen", "time_travel"],
#     ["report"],
# ]


def _build_concurrent_groups(registry):
    """Build concurrent execution groups from phase metadata.

    If a phase is missing the `group` attribute, it is assigned to group 0
    (default sequential group) and a warning is logged.  If the result is
    empty (no phases processed), a fallback single-group containing all
    phase names is returned so execution is never silently skipped.
    """
    from collections import defaultdict
    groups = defaultdict(list)
    for phase in registry:
        try:
            group = getattr(phase, "group", 0)
        except Exception as exc:
            logger.warning(
                "Phase %s missing group metadata, defaulting to group 0: %s",
                getattr(phase, "name", repr(phase)),
                exc,
            )
            group = 0
        phase_name = getattr(phase, "name", None)
        if phase_name is None:
            logger.warning("Phase object %r has no 'name' attribute, skipping", phase)
            continue
        groups[group].append(phase_name)

    if not groups:
        logger.warning(
            "_build_concurrent_groups produced empty result; "
            "falling back to sequential single-group with all phases"
        )
        # Fallback: put every phase into one group so nothing is silently skipped
        fallback_names = [
            getattr(p, "name", None) for p in registry
            if getattr(p, "name", None) is not None
        ]
        if fallback_names:
            return [fallback_names]
        return []

    return [groups[k] for k in sorted(groups.keys())]


async def _run_single_phase_async(ctx: Any, phase: Any) -> None:
    """Run a single phase asynchronously with timing and error handling.

    Args:
        ctx: ScanContext instance.
        phase: ScanPhase instance to execute.
    """
    import time as _time_mod
    from exceptions import CounterscarpAnalysisError

    _t0 = _time_mod.time()
    try:
        findings = await phase.run_async(ctx)
    except CounterscarpAnalysisError as e:
        logger.error("Phase %s failed: %s", phase.name, e)
        findings = []
    except Exception as e:
        logger.error("Unexpected error in phase %s: %s", phase.name, e)
        findings = []

    # Determine finding count for state tracking
    if isinstance(findings, list):
        _count = len(findings)
    elif isinstance(findings, dict):
        _count = len(findings.get("heuristic", [])) + len(findings.get("static", []))
    else:
        _count = 0

    ctx.state_mgr.save_phase_results(phase.name, findings)
    ctx.state_mgr.mark_phase_complete(phase.name, _count, _time_mod.time() - _t0)


async def run_phases_async(ctx: Any, phases: List[Any]) -> None:
    """Run phases with concurrency for independent groups.

    Phases within each group run concurrently via asyncio.gather().
    Groups themselves run sequentially to honour data dependencies.

    Args:
        ctx: ScanContext populated before calling this function.
        phases: Ordered list of ScanPhase instances (e.g. PHASE_REGISTRY).
    """
    phase_map = {p.name: p for p in phases}

    for group_names in _build_concurrent_groups(phases):
        group_phases = [phase_map[n] for n in group_names if n in phase_map]
        runnable = [
            p for p in group_phases
            if p.should_run(ctx) and ctx.state_mgr.is_phase_pending(p.name)
        ]

        # ALWAYS restore completed peers' caches, regardless of runnable state
        for p in group_phases:
            if p not in runnable and not ctx.state_mgr.is_phase_pending(p.name):
                cached = ctx.state_mgr.load_phase_results(p.name)
                if cached:
                    _restore_ctx_from_cache(p, ctx, cached)

        if not runnable:
            continue

        if len(runnable) == 1:
            await _run_single_phase_async(ctx, runnable[0])
        else:
            await asyncio.gather(*[
                _run_single_phase_async(ctx, p) for p in runnable
            ])


def main() -> None:
    """Main entry point for the Counterscarp orchestrator.

    Parses command-line arguments, runs all configured security checks,
    and generates comprehensive remediation reports.
    """
    # Set up dual logging: console + timestamped log file
    # This ensures scan metadata, errors, and summary stats are always
    # persisted to a log file regardless of shell piping or redirection.
    _log_file = os.path.join(
        _resolve_writable_log_dir(),
        f"scarpshield_scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.log",
    )
    setup_logging(log_file=_log_file)
    logger.info("Counterscarp Engine scan initializing...")
    logger.info("Log file: %s", _log_file)
    _maybe_print_cli_alias_notice()

    parser = argparse.ArgumentParser(description="Action-Oriented Security Engine")
    parser.add_argument("--target", required=False, default=None, help="Path to project root or .sol file")
    parser.add_argument(
        "--fuzz-contract",
        help="Name of the Invariant Test contract (e.g., InvariantTest)",
    )
    parser.add_argument(
        "--symbolic",
        action="store_true",
        help="Run Mythril symbolic analysis (requires 'myth' CLI)",
    )
    parser.add_argument(
        "--aderyn",
        action="store_true",
        help="Run Aderyn static analysis (requires 'aderyn' CLI)",
    )
    parser.add_argument(
        "--medusa",
        action="store_true",
        help="Run Medusa coverage-guided fuzzing (requires 'medusa' CLI)",
    )
    parser.add_argument(
        "--solana-root",
        help="Path to Solana/Anchor project root for Solana static analysis",
    )
    parser.add_argument(
        "--upgrade-old",
        help="Path to OLD contract version for upgrade diff analysis",
    )
    parser.add_argument(
        "--upgrade-new",
        help="Path to NEW contract version for upgrade diff analysis",
    )
    parser.add_argument(
        "--config",
        help=(
            "Path to config file "
            "(supports scarpshield.toml or counterscarp.toml)"
        ),
        default=None,
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate professional HTML/Markdown audit report",
    )
    parser.add_argument(
        "--output-dir",
        default=None,
        help="Directory for scan reports and action plans (default: engine reports dir). "
             "Useful with Docker: -v /host/reports:/output --output-dir /output",
    )
    parser.add_argument(
        "--project-name",
        help="Project name for report (default: extracted from target path)",
        default=None,
    )
    # History scanning options
    parser.add_argument(
        "--history",
        action="store_true",
        help="Run time-travel historical vulnerability scan",
    )
    parser.add_argument(
        "--time-travel",
        action="store_true",
        dest="history",
        help="Alias for --history",
    )
    parser.add_argument(
        "--commits",
        type=int,
        default=50,
        help="Maximum commits to scan in history mode (default: 50)",
    )
    parser.add_argument(
        "--since",
        help="Only scan commits since this date (ISO format, e.g., 2024-01-01)",
    )
    parser.add_argument(
        "--branch",
        default="main",
        help="Branch to scan in history mode (default: main)",
    )
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help="Run protocol fingerprint similarity scan",
    )
    # RAG options
    parser.add_argument(
        "--rag",
        action="store_true",
        help="Enable RAG enrichment for findings",
    )
    parser.add_argument(
        "--build-rag-index",
        action="store_true",
        help="Rebuild the RAG knowledge base index",
    )
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Enable LLM-powered analysis for findings (requires OPENAI_API_KEY)",
    )
    parser.add_argument(
        "--preflight",
        action="store_true",
        help="Run tool version checks before scanning",
    )
    parser.add_argument(
        "--min-confidence",
        type=int,
        default=0,
        help="Minimum confidence score (1-10) to include in report (default: 0 = all)",
    )
    parser.add_argument(
        "--min-severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="INFO",
        help="Minimum severity level to include in report (default: INFO = all)",
    )
    parser.add_argument(
        "--update-signatures",
        action="store_true",
        help="Update threat intelligence databases from GitHub (requires network)",
    )
    parser.add_argument(
        "--update-from-file",
        default=None,
        metavar="PATH",
        help="Import threat intel from a pre-downloaded JSON file (offline import)",
    )
    parser.add_argument(
        "--resume",
        default=None,
        help="Resume a previous scan by session ID",
    )
    parser.add_argument(
        "--gui",
        action="store_true",
        help="Launch the local web interface (FastAPI/Uvicorn on http://localhost:8000)",
    )
    parser.add_argument(
        "--dev",
        action="store_true",
        help="Development mode — bypass license tier restrictions for local testing",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Run environment diagnostics — check all external tool dependencies",
    )
    args = parser.parse_args()

    # --- Doctor mode (no --target needed) ---
    if args.doctor:
        import doctor as _doctor
        result = _doctor.run_doctor()
        sys.exit(result["exit_code"])

    # --- GUI mode (no --target needed) ---
    if args.gui:
        from gui import create_gui
        create_gui()
        return

    # --- Update signatures (no --target needed) ---
    if args.update_signatures:
        from signature_updater import update_from_github
        logger.info("Updating threat intelligence databases from GitHub...")
        updated, failed = update_from_github()
        if updated:
            logger.info("Updated: %s", ", ".join(updated))
        if failed:
            logger.warning("Failed: %s", ", ".join(failed))
        sys.exit(0 if not failed else 1)

    if args.update_from_file:
        from signature_updater import update_from_file
        logger.info("Importing threat intel from: %s", args.update_from_file)
        success = update_from_file(args.update_from_file)
        sys.exit(0 if success else 1)

    # Validate --target is provided for scanning operations (unless resuming)
    if not args.target and not args.resume:
        parser.error("--target is required for scanning operations (or use --resume <session_id>)")

    # --- Preflight tool version check ---
    if args.preflight:
        from healthcheck import run_healthcheck
        if not run_healthcheck():
            logger.error("Preflight check failed. Aborting scan.")
            sys.exit(1)
        logger.info("Preflight check passed — all tools verified.")

    # --- Data freshness check (warn if databases are stale) ---
    try:
        from signature_updater import check_data_freshness
        _data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
        check_data_freshness(data_dir=_data_dir, warn_days=90)
    except Exception:
        pass  # Non-fatal — never block a scan

    # --- State manager initialization ---
    import time as _time
    from pathlib import Path
    from state_manager import ScanStateManager

    state_mgr = ScanStateManager()

    if args.resume:
        session = state_mgr.load_session(args.resume)
        args.target = session["target"]
        completed = state_mgr.get_completed_phases()
        logger.info("Resuming scan %s — %d phases already done", args.resume, len(completed))
    else:
        cli_args = {k: v for k, v in vars(args).items() if v is not None}
        session_id = state_mgr.start_session(str(args.target), cli_args)
        logger.info(f"New scan session: {session_id}")

    stderr_log = str(
        state_mgr.storage_dir / f"scan_stderr_{state_mgr._session_id}.log"
    )

    # --- Per-scan output directory (prevents overwriting previous reports) ---
    # Resolved after session is established so we have the session ID.
    # Format: reports/{ProjectName}_{YYYY-MM-DD}_{session[:8]}/
    # The project name is derived from the target path at this stage; it may be
    # overridden later if --project-name is supplied, but the directory is named
    # from the target basename to keep it stable across resumes.
    _scan_date_str = datetime.date.today().strftime("%Y-%m-%d")
    _raw_proj = args.project_name or (os.path.basename(os.path.abspath(args.target)) if args.target else "scan")
    # Sanitise for use as directory component
    _proj_slug = "".join(c if c.isalnum() or c in "-_." else "_" for c in _raw_proj)
    _session_short = str(state_mgr._session_id)[:8]
    _engine_root = Path(os.path.dirname(os.path.abspath(__file__)))
    if args.output_dir:
        _reports_base = Path(args.output_dir)
    else:
        _reports_base = _engine_root / "reports"
    scan_output_dir = _reports_base / f"{_proj_slug}_{_scan_date_str}_{_session_short}"
    scan_output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Per-scan output directory: %s", scan_output_dir)

    # --- Path validation (fast-fail before any scan work) ---
    if not os.path.exists(args.target):
        msg = f"Target path does not exist: {args.target}"
        logger.error(msg)
        sys.exit(1)
    if os.path.isfile(args.target) and not args.target.lower().endswith(".sol"):
        msg = f"Target file must be a Solidity (.sol) file, got: {args.target}"
        logger.error(msg)
        sys.exit(1)
    if args.upgrade_old and not os.path.exists(args.upgrade_old):
        msg = f"--upgrade-old path does not exist: {args.upgrade_old}"
        logger.error(msg)
        sys.exit(1)
    if args.upgrade_new and not os.path.exists(args.upgrade_new):
        msg = f"--upgrade-new path does not exist: {args.upgrade_new}"
        logger.error(msg)
        sys.exit(1)

    # --- Dev mode banner ---
    if args.dev:
        logger.info("=== DEVELOPMENT MODE — All features unlocked for local testing ===")
        print("\n" + "=" * 65)
        print(" *** DEVELOPMENT MODE — All Pro features unlocked for local testing ***")
        print("=" * 65 + "\n")

    # Load config
    config = None
    if CONFIG_AVAILABLE:
        try:
            assert load_config is not None
            config = load_config(args.config)
            if config:
                logger.info("Loaded config: %s v%s", config.engine.name, config.engine.version)
                logger.info("Fail on: %s+ severity", config.engine.fail_on_severity)
                if config.heuristics.disabled_rules:
                    logger.info("Disabled heuristic rules: %d", len(config.heuristics.disabled_rules))
                if config.suppressions:
                    logger.info("Active suppressions: %d", len(config.suppressions))
        except FileNotFoundError:
            # config path was explicitly provided but not found
            logger.error("Config file not found: %s", args.config)
            logger.info("Continuing with default settings...")
        except PermissionError as e:
            logger.error(
                "Permission denied reading config '%s': %s",
                args.config or "scarpshield.toml/counterscarp.toml",
                e,
            )
            logger.info("Continuing with default settings...")
        except Exception as e:
            logger.error(
                "Error loading config '%s' (%s): %s",
                args.config or "scarpshield.toml/counterscarp.toml",
                type(e).__name__,
                e,
            )
            logger.info("Continuing with default settings...")

    # Extract exclude_paths from config for use across scanning phases
    exclude_paths: List[str] = []
    if config and config.ci and config.ci.exclude_paths:
        exclude_paths = config.ci.exclude_paths
        logger.info("Path exclusions active: %s", exclude_paths)

    # Auto-detect Foundry projects and ensure lib/** is excluded
    _target_root = getattr(args, "target", None)
    if _target_root and os.path.isfile(os.path.join(_target_root, "foundry.toml")):
        if "lib/**" not in exclude_paths:
            exclude_paths = list(exclude_paths) + ["lib/**"]
            logger.info("Foundry project detected — appended 'lib/**' to path exclusions")

    # Initialize plugin manager
    plugin_mgr = None
    if PLUGIN_MANAGER_AVAILABLE and config and config.plugins.enabled:
        try:
            assert PluginManager is not None
            plugin_mgr = PluginManager()
            plugin_count = plugin_mgr.discover_plugins(config.plugins.dirs)
            if plugin_count > 0:
                logger.info("Plugins loaded: %d (%d analyzers, %d rule sets)",
                            plugin_count, plugin_mgr.get_analyzer_count(),
                            plugin_mgr.get_rule_plugin_count())
        except Exception as e:
            logger.warning(f"Plugin initialization failed: {e}")
            plugin_mgr = None

    # Handle RAG index build
    if args.build_rag_index:
        if not (args.dev or _license.check_pro_feature(AI_COPILOT)):
            logger.info("RAG index build requires Pro license: %s", _license.get_upgrade_message(AI_COPILOT))
            return
        if not RAG_AVAILABLE:
            logger.error("RAG engine not available. Install dependencies: pip install sentence-transformers numpy")
            sys.exit(1)
        
        print("\n" + "=" * 60)
        print(" [*] BUILDING RAG KNOWLEDGE BASE INDEX")
        print("=" * 60 + "\n")
        
        try:
            # Get RAG config from config file
            rag_config = {}
            if config and hasattr(config, 'ai'):
                rag_config = {
                    "embedding_backend": config.ai.embedding_backend,
                    "rag_index_path": config.ai.rag_index_path,
                    "top_k": config.ai.top_k
                }
            
            assert AuditCopilot is not None
            copilot = AuditCopilot(rag_config)
            
            # Build from remediation DB
            sources = {"remediation_db": REMEDIATION_DB}
            counts = copilot.rebuild_index(sources)
            
            logger.info("RAG index built successfully")
            for source, count in counts.items():
                logger.info("  %s: %d entries", source, count)
            logger.info("Index saved to: %s", copilot.index_path)
            
            return
            
        except Exception as e:
            logger.error("Failed to build RAG index: %s", e)
            logger.exception("RAG index build failed")
            sys.exit(1)

    # Handle history scan mode
    if args.history:
        if not (args.dev or _license.check_pro_feature(TIME_TRAVEL)):
            logger.info("History scan requires Pro license: %s", _license.get_upgrade_message(TIME_TRAVEL))
            return
        if history_scanner is None:
            logger.warning("History scanner not available")
            sys.exit(1)
        
        print("\n" + "=" * 60)
        print(" [*] TIME-TRAVEL HISTORICAL VULNERABILITY SCAN")
        print("=" * 60 + "\n")
        
        try:
            # Get output directory from config or use default
            output_dir = "."
            if config and hasattr(config, 'history') and config.history:
                output_dir = config.history.output_dir
            
            results = history_scanner.scan_history(
                repo_path=args.target,
                max_commits=args.commits,
                since=args.since,
                branch=args.branch,
                output_dir=output_dir,
                config=config
            )
            
            print("\n" + "=" * 60)
            print(" Historical Scan Complete")
            print("=" * 60)
            print(f"Duration: {results['duration_seconds']}s")
            print(f"Commits scanned: {results['commits_scanned']}")
            print(f"Vulnerabilities found: {results['total_vulnerabilities']}")
            print(f"  - Active: {results['active_vulnerabilities']}")
            print(f"  - Fixed: {results['fixed_vulnerabilities']}")
            print(f"Fix rate: {results['fix_rate_percent']}%")
            print(f"Avg fix time: {results['average_fix_time_days']} days")
            print("\nReports:")
            print(f"  JSON: {results['reports']['json']}")
            print(f"  Markdown: {results['reports']['markdown']}")
            print("=" * 60 + "\n")
            
            return
            
        except Exception as e:
            logger.error("History scan failed: %s", e)
            logger.exception("History scan failed")
            sys.exit(1)

    print("\n" + "=" * 60)
    print(" [*] GENERATING REMEDIATION PLAN")
    print("=" * 60 + "\n")
    logger.info("=== GENERATING REMEDIATION PLAN ===")
    logger.info("Target: %s", args.target)

    # Build shared scan context
    from phases import PHASE_REGISTRY
    from scan_phase import ScanContext

    # Determine license tier for context
    _license_tier = "pro" if _license.check_pro_feature(AI_COPILOT) else "free"

    ctx = ScanContext(
        target=args.target,
        config=config,
        state_mgr=state_mgr,
        logger=logger,
        license_tier=_license_tier,
        args=args,
        scan_output_dir=scan_output_dir,
        stderr_log=stderr_log,
        exclude_paths=exclude_paths,
        plugin_mgr=plugin_mgr,
    )

    # --- Phase execution loop ---
    for phase in PHASE_REGISTRY:
        if not phase.should_run(ctx):
            # Populate default analyzer_status for skipped phases that track status
            _defaults: Dict[str, Any] = {
                "Aderyn (Static Analysis)": {"ran": False, "finding_count": 0, "error": "Not enabled"},
                "Foundry Fuzz":             {"ran": False, "finding_count": 0, "error": "Not enabled"},
                "Medusa (Fuzzing)":         {"ran": False, "finding_count": 0, "error": "Not enabled"},
                "Mythril (Symbolic)":       {"ran": False, "finding_count": 0, "error": "Not enabled"},
                "Solana Analyzer":          {"ran": False, "finding_count": 0, "error": "Not enabled"},
            }
            # Only insert if the phase hasn't already written a status entry
            # (e.g. SolanaPhase.should_run writes "License required" when key is missing)
            _dn = phase.display_name
            for _key, _val in _defaults.items():
                if _dn in _key and _key not in ctx.analyzer_status:
                    ctx.analyzer_status[_key] = _val
            continue

        if ctx.state_mgr.is_phase_pending(phase.name):
            _t0 = _time.time()
            results = phase.run(ctx)
            # Determine finding count for state tracking
            if isinstance(results, list):
                _count = len(results)
            elif isinstance(results, dict):
                # RagEnrichPhase returns {"heuristic": [...], "static": [...]}
                _count = len(results.get("heuristic", [])) + len(results.get("static", []))
            else:
                _count = 0
            ctx.state_mgr.save_phase_results(phase.name, results)
            ctx.state_mgr.mark_phase_complete(phase.name, _count, _time.time() - _t0)
        else:
            # Reload cached results and update context
            cached = ctx.state_mgr.load_phase_results(phase.name)
            logger.info("%s — loaded from cache (resumed)", phase.display_name)
            _restore_ctx_from_cache(phase, ctx, cached)

    # Pull local variables out of ctx for _generate_action_plan_report
    supply_issues = ctx.supply_issues
    static_issues = ctx.static_issues
    fuzz_issues = ctx.fuzz_issues
    heuristic_results = ctx.heuristic_results
    symbolic_results = ctx.symbolic_results
    aderyn_results = ctx.aderyn_results
    medusa_results = ctx.medusa_results
    solana_results = ctx.solana_results
    upgrade_results = ctx.upgrade_results
    fingerprint_results = ctx.fingerprint_results
    exploit_results = ctx.exploit_results
    analyzer_status = ctx.analyzer_status

    # --- Noise Control Filters (applied after RAG enrichment, before report) ---
    _severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    # Resolve effective thresholds: CLI args take precedence over config defaults
    effective_min_confidence = args.min_confidence or getattr(
        config.heuristics, 'min_confidence', 0
    ) if config else args.min_confidence
    effective_min_severity = (
        args.min_severity if args.min_severity != "INFO"
        else getattr(config.heuristics, 'min_severity', 'INFO')
    ) if config else args.min_severity

    if effective_min_confidence > 0:
        pre_filter = len(heuristic_results)
        heuristic_results = [
            h for h in heuristic_results
            if h.get("confidence", 5) >= effective_min_confidence
        ]
        logger.info(
            "Confidence filter (>=%d): %d -> %d findings",
            effective_min_confidence, pre_filter, len(heuristic_results)
        )
        ctx.heuristic_results = heuristic_results

    if effective_min_severity != "INFO":
        pre_filter = len(heuristic_results)
        min_level = _severity_order[effective_min_severity]
        heuristic_results = [
            h for h in heuristic_results
            if _severity_order.get(h.get("severity", "INFO").upper(), 4) <= min_level
        ]
        logger.info(
            "Severity filter (>=%s): %d -> %d findings",
            effective_min_severity, pre_filter, len(heuristic_results)
        )
        ctx.heuristic_results = heuristic_results

    report_file = _generate_action_plan_report(
        args.project_name or os.path.basename(os.path.abspath(args.target)),
        static_issues,
        supply_issues,
        fuzz_issues,
        heuristic_results,
        symbolic_results,
        aderyn_results,
        medusa_results,
        solana_results,
        upgrade_results,
        fingerprint_results if args.fingerprint else None,
        exploit_results=exploit_results,
        analyzer_status=analyzer_status,
        output_dir=str(scan_output_dir),
    )

    print("\n" + "=" * 60)
    print(f" [OK] ACTION PLAN READY: {os.path.abspath(report_file)}")
    print("=" * 60 + "\n")
    logger.info("Action Plan ready: %s", os.path.abspath(report_file))

    # Mark scan session complete
    state_mgr.mark_session_complete()
    logger.info(f"Scan session complete: {state_mgr._session_id}")

    # Copy scan log into the per-scan output directory
    _scan_log_dest = str(scan_output_dir / "scan.log")
    try:
        import shutil as _shutil
        _shutil.copy2(_log_file, _scan_log_dest)
    except Exception:
        pass  # Non-fatal — original log is still accessible

    # Final summary — always printed so users know where to find results
    logger.info("Scan complete. Log file: %s", _log_file)
    print(f"\n{'=' * 60}")
    print(f" Log file: {_log_file}")
    print(f" Reports saved to: {scan_output_dir.resolve()}")
    print(f"{'=' * 60}")

    # Add log file reference to the ACTION_PLAN and audit_report files
    _audit_md_in_dir = str(scan_output_dir / "audit_report.md")
    for _report_path in [report_file, _audit_md_in_dir]:
        if os.path.exists(_report_path):
            try:
                with open(_report_path, "a", encoding="utf-8", errors="replace") as _rf:
                    _rf.write(f"\n---\n\n**Scan Log File:** `{_log_file}`\n")
            except Exception:
                pass


if __name__ == "__main__":
    main()
