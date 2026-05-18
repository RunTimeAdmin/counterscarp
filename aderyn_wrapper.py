#!/usr/bin/env python3
"""
Aderyn Static Analyzer Wrapper
Cyfrin's Rust-based Solidity analyzer with custom detector support
Complements Slither with different analysis engine
"""

from __future__ import annotations

import subprocess
import json
import sys
import argparse
from typing import Dict, Any, List, Optional

from logger import get_logger, append_stderr_log
from exceptions import (
    CounterscarpAnalysisError,
    CounterscarpToolNotFoundError,
    CounterscarpTimeoutError,
)
from path_security import sanitize_cli_path

# Import config loader
try:
    from config_loader import load_config, CounterscarpConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

logger = get_logger(__name__)

# Load configuration with fallback to defaults
_config = None


def get_config() -> CounterscarpConfig:
    """Get or load the configuration."""
    global _config
    if _config is None:
        if CONFIG_AVAILABLE:
            try:
                _config = load_config()
            except Exception:
                _config = CounterscarpConfig()
        else:
            _config = CounterscarpConfig()
    return _config


def get_aderyn_timeout() -> int:
    """Get Aderyn timeout from config or use default."""
    try:
        return int(get_config().external_tools.aderyn_timeout)
    except Exception:
        return 120


def check_aderyn_installed() -> bool:
    """Check if Aderyn is available on the system.

    Returns:
        True if Aderyn is installed and accessible, False otherwise.
    """
    try:
        result = subprocess.run(
            ["aderyn", "--version"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return result.returncode == 0
    except FileNotFoundError:
        logger.debug("Aderyn not found in PATH")
        return False
    except subprocess.TimeoutExpired:
        logger.warning("Aderyn version check timed out")
        return False
    except Exception as e:
        logger.warning(f"Error checking Aderyn installation: {e}")
        return False


def run_aderyn(
    project_root: str,
    output_format: str = "json",
    scope: Optional[str] = None,
    stderr_log: Optional[str] = None
) -> Dict[str, Any]:
    """Run Aderyn static analyzer on a Solidity project.

    Args:
        project_root: Path to project root (must contain foundry.toml or hardhat.config).
        output_format: Output format (json, markdown, sarif).
        scope: Optional file/folder to limit analysis.

    Returns:
        Dict with findings categorized by severity.

    Raises:
        CounterscarpToolNotFoundError: If Aderyn is not installed.
        CounterscarpTimeoutError: If analysis times out.
        CounterscarpAnalysisError: If analysis fails.
    """
    safe_root = sanitize_cli_path(project_root, expect_file=False)
    project_root = str(safe_root)

    if not check_aderyn_installed():
        logger.error("Aderyn not installed")
        print("[!] Aderyn not installed.")
        print("    Install: cargo install aderyn")
        print("    Or via Foundry: foundryup")
        print("    Docs: https://cyfrin.gitbook.io/cyfrin-docs/aderyn-cli")
        raise CounterscarpToolNotFoundError(
            "Aderyn not found in PATH",
            details={
                "tool": "aderyn",
                "install_cmd": "cargo install aderyn"
            }
        )
    
    # Build command
    cmd = ["aderyn", project_root]
    
    # Add output format
    if output_format == "json":
        # Keep JSON on stdout to avoid unsafe file path handling.
        pass
    elif output_format == "markdown":
        cmd.extend(["--output", "aderyn-report.md"])
    elif output_format == "sarif":
        cmd.extend(["--output", "aderyn-report.sarif"])
    
    # Add scope if specified
    if scope:
        cmd.extend(["--scope", scope])
    
    logger.info(f"Running Aderyn on {project_root}")
    logger.debug(f"Command: {' '.join(cmd)}")
    print(f"[*] Running Aderyn on {project_root}")
    print(f"[*] Command: {' '.join(cmd)}")
    
    timeout = get_aderyn_timeout()
    try:
        result = subprocess.run(
            cmd,
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.stderr:
            append_stderr_log(result.stderr, "aderyn", stderr_log or "")
        return parse_aderyn_output(result.stdout, result.stderr)
        
    except subprocess.TimeoutExpired as e:
        logger.error(f"Aderyn timed out after {timeout}s")
        raise CounterscarpTimeoutError(
            "Aderyn analysis timed out",
            details={"operation": "aderyn_analysis", "timeout_seconds": timeout}
        ) from e
    except FileNotFoundError as e:
        logger.error(f"Aderyn not found during execution: {e}")
        raise CounterscarpToolNotFoundError(
            "Aderyn not found in PATH",
            details={"tool": "aderyn"}
        ) from e
    except PermissionError as e:
        logger.error(f"Permission denied running Aderyn: {e}")
        raise CounterscarpAnalysisError(
            "Permission denied running Aderyn",
            details={"error": str(e)}
        ) from e
    except Exception as e:
        logger.error(f"Error running Aderyn: {e}")
        raise CounterscarpAnalysisError(
            "Aderyn analysis failed",
            details={"error": str(e)}
        ) from e


def parse_aderyn_output(stdout: str, stderr: str) -> Dict[str, Any]:
    """Parse Aderyn JSON output.

    Aderyn output format:
    {
      "files_summary": {...},
      "issue_count": {...},
      "high_issues": [...],
      "low_issues": [...],
      "nc_issues": [...]
    }

    Args:
        stdout: Standard output from Aderyn.
        stderr: Standard error from Aderyn.

    Returns:
        Parsed findings dictionary.
    """
    findings: Dict[str, Any] = {
        "high": [],
        "low": [],
        "nc": [],  # Non-critical
        "total": 0
    }
    
    try:
        # Try to find JSON in stdout
        json_start = stdout.find('{')
        if json_start != -1:
            data = json.loads(stdout[json_start:])
            
            # Extract issues
            findings["high"] = list(data.get("high_issues", {}).get("issues", []))
            findings["low"] = list(data.get("low_issues", {}).get("issues", []))
            findings["nc"] = list(data.get("nc_issues", {}).get("issues", []))
            
            findings["total"] = (
                len(findings["high"]) +
                len(findings["low"]) +
                len(findings["nc"])
            )
            
            # Add issue counts
            findings["issue_count"] = data.get("issue_count", {})
            findings["files_summary"] = data.get("files_summary", {})
    
    except json.JSONDecodeError:
        # Fallback: Parse text output
        if "High" in stdout or "Low" in stdout:
            findings["raw_output"] = stdout
    
    return findings


def print_results(results: Dict[str, Any]) -> None:
    """Pretty-print Aderyn analysis results.

    Args:
        results: Results dictionary from run_aderyn().
    """
    print("\n" + "="*60)
    print(" ADERYN STATIC ANALYSIS RESULTS")
    print("="*60)
    
    if "error" in results:
        print(f"\n[!] ERROR: {results['error']}")
        return
    
    # Summary
    issue_count = results.get("issue_count", {})
    print(f"\n[*] Total issues found: {results.get('total', 0)}")
    print(f"    High:        {len(results.get('high', []))}")
    print(f"    Low:         {len(results.get('low', []))}")
    print(f"    Non-Critical: {len(results.get('nc', []))}")
    
    # Files summary
    files_summary = results.get("files_summary", {})
    if files_summary:
        print(f"\n[*] Files analyzed: {files_summary.get('total_source_units', 'unknown')}")
        print(f"    Total SLoC: {files_summary.get('total_sloc', 'unknown')}")
    
    # High severity issues
    high_issues = results.get("high", [])
    if high_issues:
        print("\n" + "-"*60)
        print("HIGH SEVERITY ISSUES:")
        print("-"*60)
        
        for i, issue in enumerate(high_issues[:10], 1):  # Show first 10
            print(f"\n[{i}] {issue.get('title', 'Unknown issue')}")
            print(f"    Detector: {issue.get('detector_name', 'unknown')}")
            
            # Show instances
            instances = issue.get("instances", [])
            if instances:
                print(f"    Instances: {len(instances)}")
                for inst in instances[:3]:  # Show first 3
                    contract = inst.get("contract_path", "unknown")
                    line = inst.get("line_no", "?")
                    print(f"      • {contract}:{line}")
                
                if len(instances) > 3:
                    print(f"      ... ({len(instances) - 3} more)")
    
    # Low severity issues
    low_issues = results.get("low", [])
    if low_issues:
        print(f"\n[*] {len(low_issues)} low severity issues found")
        print("    (Use --verbose to see details)")
    
    # Non-critical issues
    nc_issues = results.get("nc", [])
    if nc_issues:
        print(f"\n[*] {len(nc_issues)} non-critical issues found")
        print("    (Gas optimizations, best practices)")
    
    if results.get("total", 0) == 0:
        print("\n✅ No issues detected by Aderyn!")


def compare_with_slither(
    aderyn_results: Dict[str, Any],
    slither_results: Dict[str, Any]
) -> Dict[str, Any]:
    """Compare Aderyn and Slither findings to identify unique issues.

    Args:
        aderyn_results: Results from run_aderyn().
        slither_results: Results from red_team_scan.run_slither().

    Returns:
        Dict with comparison results including aderyn_only, slither_only, and both.
    """
    comparison: Dict[str, Any] = {
        "aderyn_only": [],
        "slither_only": [],
        "both": [],
        "summary": {}
    }
    
    # Extract issue titles/patterns
    aderyn_titles = set()
    for severity in ["high", "low"]:
        for issue in aderyn_results.get(severity, []):
            aderyn_titles.add(issue.get("title", "").lower())
    
    slither_titles = set()
    if "results" in slither_results and "detectors" in slither_results["results"]:
        for detector in slither_results["results"]["detectors"]:
            slither_titles.add(detector.get("check", "").lower())
    
    # Find overlaps
    both_found = aderyn_titles & slither_titles
    aderyn_unique = aderyn_titles - slither_titles
    slither_unique = slither_titles - aderyn_titles
    
    comparison["both"] = list(both_found)
    comparison["aderyn_only"] = list(aderyn_unique)
    comparison["slither_only"] = list(slither_unique)
    
    comparison["summary"] = {
        "aderyn_unique_count": len(aderyn_unique),
        "slither_unique_count": len(slither_unique),
        "overlap_count": len(both_found),
        "total_unique_issues": len(aderyn_unique) + len(slither_unique)
    }
    
    return comparison


def main() -> None:
    """Main entry point for the Aderyn wrapper CLI."""
    parser = argparse.ArgumentParser(
        description="Aderyn static analyzer wrapper - Cyfrin's Rust-based Solidity analyzer"
    )
    parser.add_argument(
        "project_root",
        help="Path to Foundry/Hardhat project root"
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "sarif"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--scope",
        help="Limit analysis to specific file/folder"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show all issues including low/NC"
    )
    
    args = parser.parse_args()
    
    results = run_aderyn(
        str(sanitize_cli_path(args.project_root, expect_file=False)),
        output_format=args.format,
        scope=args.scope
    )
    
    print_results(results)
    
    # Exit with error code if high severity issues found
    high_count = len(results.get("high", []))
    sys.exit(1 if high_count > 0 else 0)


if __name__ == "__main__":
    main()
