from __future__ import annotations

import sys
import os
import argparse
import datetime
from typing import List, Dict, Optional, Any

from logger import get_logger

logger = get_logger(__name__)

# Import your specialists
try:
    import red_team_scan
    from exceptions import SentinelAnalysisError
    import supply_chain_check
    import fuzz_wrapper
    import heuristic_scanner
    import symbolic_wrapper
    logger.debug("Core modules imported successfully")
except ImportError as e:
    logger.critical(f"Missing a core module: {e}")
    print(f"[!] CRITICAL: Missing a core module. {e}")
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
try:
    import aderyn_wrapper
    logger.debug("Aderyn wrapper imported successfully")
except ImportError as e:
    logger.info(f"Aderyn wrapper not available: {e}")
    aderyn_wrapper = None

try:
    import medusa_wrapper
    logger.debug("Medusa wrapper imported successfully")
except ImportError as e:
    logger.info(f"Medusa wrapper not available: {e}")
    medusa_wrapper = None

try:
    import solana_analyzer
    logger.debug("Solana analyzer imported successfully")
except ImportError as e:
    logger.info(f"Solana analyzer not available: {e}")
    solana_analyzer = None

try:
    import upgrade_diff
    logger.debug("Upgrade diff module imported successfully")
except ImportError as e:
    logger.info(f"Upgrade diff module not available: {e}")
    upgrade_diff = None

try:
    import history_scanner
    logger.debug("History scanner imported successfully")
except ImportError as e:
    logger.info(f"History scanner not available: {e}")
    history_scanner = None

try:
    from config_loader import load_config, SentinelConfig
    CONFIG_AVAILABLE = True
    logger.debug("Config loader imported successfully")
except ImportError as e:
    logger.info(f"Config loader not available: {e}")
    CONFIG_AVAILABLE = False
    SentinelConfig = None

# Optional plugin manager
try:
    from plugin_manager import PluginManager
    PLUGIN_MANAGER_AVAILABLE = True
    logger.debug("Plugin manager imported successfully")
except ImportError as e:
    logger.info(f"Plugin manager not available: {e}")
    PLUGIN_MANAGER_AVAILABLE = False
    PluginManager = None

try:
    from report_generator import (
        aggregate_findings_from_orchestrator,
        create_audit_report,
        generate_html_report,
        generate_markdown_report as generate_audit_markdown_report
    )
    REPORT_GENERATOR_AVAILABLE = True
    logger.debug("Report generator imported successfully")
except ImportError as e:
    logger.info(f"Report generator not available: {e}")
    REPORT_GENERATOR_AVAILABLE = False

# Optional RAG engine
try:
    from rag_engine import AuditCopilot
    RAG_AVAILABLE = True
    logger.debug("RAG engine imported successfully")
except ImportError as e:
    logger.info(f"RAG engine not available: {e}")
    RAG_AVAILABLE = False
    AuditCopilot = None

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


def generate_markdown_report(
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
) -> str:
    """Generates a report focused on REMEDIATION (Fixing the bugs).

    Args:
        project_name: Name of the project being audited.
        static_results: Results from static analysis (Slither).
        supply_results: Results from supply chain vulnerability scan.
        fuzz_results: Results from fuzzing tests.
        heuristic_results: Results from heuristic pattern matching.
        symbolic_results: Results from symbolic execution (Mythril).
        aderyn_results: Optional results from Aderyn static analysis.
        medusa_results: Optional results from Medusa fuzzing.
        solana_results: Optional results from Solana analysis.
        upgrade_results: Optional results from upgrade diff analysis.
        fingerprint_results: Optional results from protocol fingerprint scan.

    Returns:
        Path to the generated markdown report file.
    """

    filename = f"ACTION_PLAN_{datetime.date.today()}.md"

    # Risk Calculation
    critical_count = len(fuzz_results) + len([x for x in static_results if x.get("impact") == "High"])
    status_icon = "[CRITICAL]" if critical_count > 0 else "[STABLE]"

    with open(filename, "w", encoding="utf-8") as f:
        # Executive Summary
        f.write("# Security Remediation Plan\n")
        f.write(f"**Target:** `{project_name}`\n")
        f.write(f"**Status:** {status_icon} ({critical_count} Critical Issues)\n")
        f.write(f"**Generated:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}\n\n")

        f.write("> **Objective:** This document lists specific, actionable steps to patch identified vulnerabilities. Prioritize 'Critical' items immediately.\n\n")

        f.write("---\n\n")

        # ---------------------------------------------------------
        # SECTION 1: SUPPLY CHAIN (DEPENDENCIES)
        # ---------------------------------------------------------
        f.write("## 1. Dependency Updates (Supply Chain)\n")
        if not supply_results:
            f.write("[OK] **No Action Required.** All dependencies are up to date.\n\n")
        else:
            f.write("| Severity | Library | Action Required |\n")
            f.write("| :--- | :--- | :--- |\n")
            for item in supply_results:
                # Assuming Supply Chain script returns 'library', 'installed', 'id'
                f.write(
                    f"| [!] | `{item['library']}` | **Run:** `npm update {item['library']}` <br> **Reason:** {item.get('summary', 'Known Vulnerability')} |\n"
                )
            f.write("\n")

        f.write("---\n\n")

        # ---------------------------------------------------------
        # SECTION 2: CODE VULNERABILITIES (STATIC)
        # ---------------------------------------------------------
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

        # ---------------------------------------------------------
        # SECTION 3: LOGIC FAILURES (FUZZING)
        # ---------------------------------------------------------
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

        # ---------------------------------------------------------
        # SECTION 4: HEURISTIC FINDINGS (PATTERN-BASED)
        # ---------------------------------------------------------
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

        # ---------------------------------------------------------
        # SECTION 5: SYMBOLIC ANALYSIS (MYTHRIL)
        # ---------------------------------------------------------
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

        # ---------------------------------------------------------
        # SECTION 6: ADERYN STATIC ANALYSIS (OPTIONAL)
        # ---------------------------------------------------------
        f.write("---\n\n")
        f.write("## 6. Aderyn Static Analysis (Optional)\n")
        if not aderyn_results:
            f.write("ℹ️ Aderyn analysis not run or produced no results.\n\n")
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

        # ---------------------------------------------------------
        # SECTION 7: MEDUSA FUZZING (OPTIONAL)
        # ---------------------------------------------------------
        f.write("---\n\n")
        f.write("## 7. Medusa Fuzzing (Coverage-Guided)\n")
        if not medusa_results:
            f.write("ℹ️ Medusa fuzzing not run or produced no results.\n\n")
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

        # ---------------------------------------------------------
        # SECTION 8: SOLANA/ANCHOR STATIC ANALYSIS (OPTIONAL)
        # ---------------------------------------------------------
        f.write("---\n\n")
        f.write("## 8. Solana/Anchor Static Analysis (Optional)\n")
        if not solana_results:
            f.write("ℹ️ Solana analysis not run or no Solana project configured.\n\n")
        elif isinstance(solana_results, dict) and solana_results.get("summary"):
            summary = solana_results["summary"]
            f.write(
                f"[*] Findings → CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
                f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}\n\n"
            )
            pattern_findings = solana_results.get("pattern_findings", [])
            criticals = [
                f for f in pattern_findings if getattr(f, "severity", None) == "CRITICAL"
            ][:5]
            if criticals:
                f.write("### Top Critical Solana Findings\n")
                for finding in criticals:
                    f.write(
                        f"- **{finding.title}** in `{finding.file}:{finding.line_no}` – {finding.description}\n"
                    )
                f.write("\n")

        # ---------------------------------------------------------
        # SECTION 9: UPGRADE DIFF ANALYSIS (OPTIONAL)
        # ---------------------------------------------------------
        f.write("---\n\n")
        f.write("## 9. Upgrade Diff Analysis (Optional)\n")
        if not upgrade_results:
            f.write("ℹ️ No upgrade diff analysis run for this report.\n\n")
        elif isinstance(upgrade_results, dict) and upgrade_results.get("summary"):
            summary = upgrade_results["summary"]
            f.write(
                f"[*] Issues → CRITICAL: {summary.get('CRITICAL', 0)}, HIGH: {summary.get('HIGH', 0)}, "
                f"MEDIUM: {summary.get('MEDIUM', 0)}, LOW: {summary.get('LOW', 0)}\n\n"
            )
            if upgrade_results.get("safe"):
                f.write("[OK] SAFE TO UPGRADE (no critical/high issues detected).\n\n")
            else:
                f.write("[!] UNSAFE TO UPGRADE - address critical/high issues before deploying.\n\n")

        # ---------------------------------------------------------
        # SECTION 10: PROTOCOL FINGERPRINT ANALYSIS (OPTIONAL)
        # ---------------------------------------------------------
        f.write("---\n\n")
        f.write("## 10. Protocol Fingerprint Analysis (Optional)\n")
        if not fingerprint_results:
            f.write("ℹ️ No protocol fingerprint analysis run for this report.\n\n")
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

    return filename


def main() -> None:
    """Main entry point for the Sentinel orchestrator.

    Parses command-line arguments, runs all configured security checks,
    and generates comprehensive remediation reports.
    """
    parser = argparse.ArgumentParser(description="Action-Oriented Security Engine")
    parser.add_argument("--target", required=True, help="Path to project root or .sol file")
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
        help="Path to sentinel.toml config file",
        default=None,
    )
    parser.add_argument(
        "--report",
        action="store_true",
        help="Generate professional HTML/Markdown audit report",
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
    args = parser.parse_args()

    # Load config
    config = None
    if CONFIG_AVAILABLE:
        try:
            config = load_config(args.config)
            if config:
                print(f"[*] Loaded config: {config.engine.name} v{config.engine.version}")
                print(f"    Fail on: {config.engine.fail_on_severity}+ severity")
                if config.heuristics.disabled_rules:
                    print(f"    Disabled heuristic rules: {len(config.heuristics.disabled_rules)}")
                if config.suppressions:
                    print(f"    Active suppressions: {len(config.suppressions)}")
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            print("[*] Continuing with default settings...\n")

    # Initialize plugin manager
    plugin_mgr = None
    if PLUGIN_MANAGER_AVAILABLE and config and config.plugins.enabled:
        try:
            plugin_mgr = PluginManager()
            plugin_count = plugin_mgr.discover_plugins(config.plugins.dirs)
            if plugin_count > 0:
                print(f"[*] Plugins loaded: {plugin_count} "
                      f"({plugin_mgr.get_analyzer_count()} analyzers, "
                      f"{plugin_mgr.get_rule_plugin_count()} rule sets)")
        except Exception as e:
            logger.warning(f"Plugin initialization failed: {e}")
            plugin_mgr = None

    # Handle RAG index build
    if args.build_rag_index:
        if not RAG_AVAILABLE:
            print("[!] RAG engine not available. Install dependencies: pip install sentence-transformers numpy")
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
            
            copilot = AuditCopilot(rag_config)
            
            # Build from remediation DB
            sources = {"remediation_db": REMEDIATION_DB}
            counts = copilot.rebuild_index(sources)
            
            print(f"\n[+] Index built successfully:")
            for source, count in counts.items():
                print(f"    {source}: {count} entries")
            print(f"\n[+] Index saved to: {copilot.index_path}")
            print("=" * 60 + "\n")
            
            return
            
        except Exception as e:
            print(f"[!] Failed to build RAG index: {e}")
            logger.exception("RAG index build failed")
            sys.exit(1)

    # Handle history scan mode
    if args.history:
        if history_scanner is None:
            print("[!] History scanner not available")
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
            print(f"[!] History scan failed: {e}")
            logger.exception("History scan failed")
            sys.exit(1)

    print("\n" + "=" * 60)
    print(" [*] GENERATING REMEDIATION PLAN")
    print("=" * 60 + "\n")

    # Initialize containers
    supply_issues: List[Dict] = []
    static_issues: List[Dict] = []
    fuzz_issues: List[Dict] = []
    heuristic_results: List[Dict] = []
    symbolic_results: List[Dict] = []
    aderyn_results: Optional[Dict] = None
    medusa_results: Optional[Dict] = None
    solana_results: Optional[Dict] = None
    upgrade_results: Optional[Dict] = None

    # [PHASE 1] Supply Chain
    print(">>> Assessing Supply Chain...")
    if os.path.isdir(args.target):
        pkg_json = os.path.join(args.target, "package.json")
        if os.path.exists(pkg_json):
            try:
                supply_issues = supply_chain_check.scan_package_json(pkg_json)
            except Exception as e:
                logger.warning(f"Supply chain check failed for {pkg_json}: {e}")
                supply_issues = []

    # [PHASE 2] Static Analysis (Slither)
    print("\n>>> Analyzing Code Patterns...")
    try:
        raw_slither = red_team_scan.run_slither(args.target)
        static_issues = red_team_scan.filter_vulnerabilities(raw_slither)
    except SentinelAnalysisError as e:
        logger.warning(f"Slither analysis failed: {e}")
        print(f"    [!] Slither analysis failed: {e}")
        static_issues = []
        raw_slither = None
    except Exception:
        # Fail silently for now; in production, log this.
        static_issues = []
        raw_slither = None

    # [PHASE 2B] Aderyn Static Analysis (optional)
    if args.aderyn and os.path.isdir(args.target):
        print("\n>>> Running Aderyn Static Analysis...")
        if aderyn_wrapper is None:
            print("[!] Aderyn wrapper not available in this environment.")
        else:
            try:
                import sys as _sys

                old_exit = _sys.exit
                _sys.exit = lambda code=0: None
                aderyn_results = aderyn_wrapper.run_aderyn(args.target)
            except Exception:
                print("[!] Aderyn analysis failed; continuing without Aderyn results.")
                aderyn_results = {"error": "Aderyn run failed"}
            finally:
                try:
                    _sys.exit = old_exit
                except Exception:
                    pass

    # [PHASE 3] Fuzzing (Foundry)
    if args.fuzz_contract:
        print("\n>>> Stress Testing Logic (Foundry)...")
        try:
            raw_fuzz = fuzz_wrapper.run_foundry_fuzz(args.fuzz_contract)
            fuzz_issues = fuzz_wrapper.parse_counterexamples(raw_fuzz)
        except Exception:
            fuzz_issues = []

    # [PHASE 3B] Medusa Fuzzing (optional)
    if args.medusa:
        print("\n>>> Running Medusa Fuzzing (coverage-guided)...")
        if medusa_wrapper is None:
            print("[!] Medusa wrapper not available in this environment.")
        else:
            medusa_target = args.target if os.path.isdir(args.target) else os.path.dirname(args.target)
            try:
                import sys as _sys

                old_exit = _sys.exit
                _sys.exit = lambda code=0: None
                medusa_results = medusa_wrapper.run_medusa_fuzz(
                    medusa_target, target_contract=args.fuzz_contract
                )
            except Exception:
                print("[!] Medusa fuzzing failed; continuing without Medusa results.")
                medusa_results = {"error": "Medusa run failed"}
            finally:
                try:
                    _sys.exit = old_exit
                except Exception:
                    pass

    # [PHASE 4] Heuristic Scan
    print("\n>>> Running Heuristic Scan...")
    try:
        heuristic_findings = heuristic_scanner.scan_target(
            args.target, config, plugin_mgr
        )
        for hf in heuristic_findings:
            # Only include non-suppressed findings in report
            if not hf.suppressed:
                heuristic_results.append(
                    {
                        "rule_id": hf.rule_id,
                        "severity": hf.severity,
                        "message": hf.message,
                        "file": hf.file,
                        "line_no": hf.line_no,
                        "line_text": hf.line_text,
                    }
                )
    except Exception:
        # Fail silently for now; in production, log this.
        heuristic_results = []

    # [PHASE 4C] Plugin Analyzers (optional)
    if plugin_mgr and plugin_mgr.get_analyzer_count() > 0:
        print("\n>>> Running Plugin Analyzers...")
        for plugin in plugin_mgr.get_analyzers():
            try:
                logger.info("Running plugin analyzer: %s", plugin.name)
                config_dict = {
                    "target": args.target,
                    "project_name": args.project_name,
                } if config else {}
                plugin_findings = plugin.analyze(args.target, config_dict)
                for pf in plugin_findings:
                    heuristic_results.append({
                        "rule_id": pf.get("rule_id", f"PLUGIN-{plugin.name}"),
                        "severity": pf.get("severity", "Info"),
                        "message": pf.get("description", ""),
                        "file": pf.get("file", ""),
                        "line_no": pf.get("line_no", 0),
                        "line_text": pf.get("code_snippet", ""),
                    })
            except Exception as exc:
                logger.warning("Plugin %s failed: %s", plugin.name, exc)

    # [PHASE 4B] Protocol Fingerprint Scan (optional)
    fingerprint_results: List[Dict] = []
    if args.fingerprint:
        print("\n>>> Running Protocol Fingerprint Scan...")
        if FINGERPRINT_AVAILABLE:
            try:
                # Get config values
                min_similarity = 0.7
                database_path = None
                if config and hasattr(config, 'fingerprint'):
                    min_similarity = config.fingerprint.min_similarity
                    database_path = config.fingerprint.database_path

                # Load fingerprints
                if database_path and os.path.exists(database_path):
                    fingerprints = load_fingerprint_db(database_path)
                else:
                    fingerprints = get_default_fingerprints()

                # Run scan
                scan_config = {
                    'fingerprints': fingerprints,
                    'min_similarity': min_similarity,
                }
                fingerprint_results = fingerprint_scanner.scan_project(
                    args.target,
                    scan_config
                )

                if fingerprint_results:
                    print(f"    Found {len(fingerprint_results)} contract(s) with protocol matches")
                    for result in fingerprint_results:
                        matches = result.get('matches', [])
                        risk = result.get('risk_assessment', {})
                        print(f"    - {result['file']}: {len(matches)} match(es)")
                        if risk:
                            print(f"      Risk Level: {risk.get('risk_level', 'N/A')}")
                else:
                    print("    No protocol matches found")

            except Exception as e:
                logger.warning(f"Fingerprint scan failed: {e}")
                print(f"[!] Fingerprint scan failed: {e}")
        else:
            print("[!] Fingerprint scanner not available")

    # [PHASE 5] Symbolic Analysis (optional)
    if args.symbolic and os.path.isfile(args.target):
        print("\n>>> Running Symbolic Analysis (Mythril)...")
        try:
            raw_symbolic = symbolic_wrapper.run_mythril(args.target)
            symbolic_results = symbolic_wrapper.parse_issues(raw_symbolic)
        except Exception:
            # In case Mythril or the CLI fails, don't crash the whole pipeline
            symbolic_results = []

    # [PHASE 6] Solana Static Analysis (optional)
    if args.solana_root:
        print("\n>>> Running Solana Static Analysis...")
        if solana_analyzer is None:
            print("[!] solana_analyzer module not available in this environment.")
        else:
            try:
                solana_results = solana_analyzer.analyze_solana_program(args.solana_root)
            except Exception:
                print("[!] Solana analysis failed; continuing without Solana results.")
                solana_results = {"error": "Solana analysis failed"}

    # [PHASE 7] Upgrade Diff Analysis (optional)
    if args.upgrade_old and args.upgrade_new:
        print("\n>>> Running Upgrade Diff Analyzer...")
        if upgrade_diff is None:
            print("[!] upgrade_diff module not available in this environment.")
        else:
            try:
                upgrade_results = upgrade_diff.analyze_upgrade(
                    args.upgrade_old, args.upgrade_new
                )
            except Exception:
                print("[!] Upgrade diff analysis failed; continuing without upgrade results.")
                upgrade_results = {"error": "Upgrade diff analysis failed"}

    # [PHASE 7.5] RAG Enrichment (optional)
    if args.rag and RAG_AVAILABLE:
        print("\n>>> Enriching Findings with RAG Context...")
        try:
            # Get RAG config
            rag_config = {}
            if config and hasattr(config, 'ai'):
                rag_config = {
                    "embedding_backend": config.ai.embedding_backend,
                    "rag_index_path": config.ai.rag_index_path,
                    "top_k": config.ai.top_k
                }
            
            copilot = AuditCopilot(rag_config)
            
            # Check if index exists
            if copilot.vector_store.entries:
                # Enrich heuristic results
                if heuristic_results:
                    heuristic_results = copilot.enrich_findings_batch(
                        heuristic_results
                    )
                    print(f"    Enriched {len(heuristic_results)} heuristic findings")
                
                # Enrich static issues
                if static_issues:
                    static_issues = copilot.enrich_findings_batch(
                        static_issues
                    )
                    print(f"    Enriched {len(static_issues)} static analysis findings")
                
                print("    [+] RAG enrichment complete")
            else:
                print("    [!] No RAG index found. Build with: --build-rag-index")
                
        except Exception as e:
            logger.warning(f"RAG enrichment failed: {e}")
            print(f"    [!] RAG enrichment failed: {e}")
    elif args.rag and not RAG_AVAILABLE:
        print("\n>>> RAG Enrichment Requested...")
        print("    [!] RAG engine not available. Install: pip install sentence-transformers numpy")

    # [PHASE 8] Action Report
    print("\n>>> Writing Action Plan...")
    report_file = generate_markdown_report(
        "Target Protocol",
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
    )

    print("\n" + "=" * 60)
    print(f" [OK] ACTION PLAN READY: {os.path.abspath(report_file)}")
    print("=" * 60 + "\n")

    # [PHASE 9] Professional Report (Optional)
    if args.report and REPORT_GENERATOR_AVAILABLE:
        print("\n>>> Generating Professional Audit Report...")
        
        # Aggregate findings from all sources
        from report_generator import Finding
        
        # Convert results to unified Finding objects
        all_findings = []
        
        # Heuristics
        for h in heuristic_results:
            all_findings.append(Finding(
                rule_id=h["rule_id"],
                severity=h["severity"],
                category="Heuristic",
                title=h["rule_id"].replace("_", " ").title(),
                description=h["message"],
                file=h["file"],
                line_no=h["line_no"],
                code_snippet=h.get("line_text", "")
            ))
        
        # Static (Slither)
        for s in static_issues:
            all_findings.append(Finding(
                rule_id=s.get("check", "slither_finding"),
                severity=s.get("impact", "MEDIUM").upper(),
                category="Slither",
                title=s.get("title", "Slither Finding"),
                description=s.get("description", ""),
                file=s.get("location", "").split(":")[0] if ":" in s.get("location", "") else s.get("location", ""),
                line_no=int(s.get("location", ":0").split(":")[-1]) if ":" in s.get("location", "") else 0
            ))
        
        # Aderyn (if available)
        if aderyn_results and isinstance(aderyn_results, dict):
            for issue in aderyn_results.get("high", [])[:10]:
                all_findings.append(Finding(
                    rule_id=issue.get("detector_name", "aderyn_finding"),
                    severity="HIGH",
                    category="Aderyn",
                    title=issue.get("title", "Aderyn Finding"),
                    description=issue.get("description", ""),
                    file="",
                    line_no=0
                ))
        
        # Upgrade Diff (if available)
        if upgrade_results and isinstance(upgrade_results, dict):
            for issue in upgrade_results.get("issues", []):
                all_findings.append(Finding(
                    rule_id=issue.category if hasattr(issue, 'category') else "upgrade_issue",
                    severity=issue.severity if hasattr(issue, 'severity') else "HIGH",
                    category="Upgrade Diff",
                    title=issue.title if hasattr(issue, 'title') else "Upgrade Issue",
                    description=issue.description if hasattr(issue, 'description') else "",
                    file="",
                    line_no=issue.line_no if hasattr(issue, 'line_no') and issue.line_no else 0
                ))
        
        # Solana (if available)
        if solana_results and isinstance(solana_results, dict):
            for f in solana_results.get("pattern_findings", []):
                if hasattr(f, 'severity'):
                    all_findings.append(Finding(
                        rule_id=f.category,
                        severity=f.severity,
                        category="Solana",
                        title=f.title,
                        description=f.description,
                        file=f.file,
                        line_no=f.line_no,
                        remediation=f.fix_suggestion if hasattr(f, 'fix_suggestion') else ""
                    ))
        
        # Create report
        project_name = args.project_name or os.path.basename(os.path.abspath(args.target))
        audit_report = create_audit_report(
            project_name=project_name,
            target_path=args.target,
            findings=all_findings,
            engine_version="2.2"
        )
        
        # Generate both HTML and Markdown
        html_file = f"audit_report_{datetime.date.today()}.html"
        md_file = f"audit_report_{datetime.date.today()}.md"
        
        html_path = generate_html_report(audit_report, html_file)
        md_path = generate_audit_markdown_report(audit_report, md_file)
        
        print(f"\n[*] Professional Reports Generated:")
        print(f"   HTML: {os.path.abspath(html_path)}")
        print(f"   Markdown: {os.path.abspath(md_path)}")
        print(f"\n   Risk Score: {audit_report.risk_score}/100")
        print(f"   Status: {audit_report.pass_fail}")
        print(f"   Findings: {len(all_findings)} total")
    elif args.report and not REPORT_GENERATOR_AVAILABLE:
        print("[!] Report generation requested but report_generator.py not available")


if __name__ == "__main__":
    main()
