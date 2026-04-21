from __future__ import annotations

import subprocess
import json
import argparse
import sys
from typing import List, Dict, Any, Optional

from logger import get_logger, append_stderr_log
from exceptions import (
    GarrisonAnalysisError,
    GarrisonToolNotFoundError,
    GarrisonTimeoutError,
)

# Import config loader
try:
    from config_loader import load_config, GarrisonConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

logger = get_logger(__name__)

# Load configuration with fallback to defaults
_config = None


def get_config() -> GarrisonConfig:
    """Get or load the configuration."""
    global _config
    if _config is None:
        if CONFIG_AVAILABLE:
            try:
                _config = load_config()
            except Exception:
                _config = GarrisonConfig()
        else:
            _config = GarrisonConfig()
    return _config


def get_mythril_timeout() -> int:
    """Get Mythril timeout from config or use default."""
    try:
        return get_config().external_tools.mythril_timeout
    except Exception:
        return 600


def run_mythril(
    target: str,
    function: Optional[str] = None,
    timeout: Optional[int] = None,
    stderr_log: Optional[str] = None
) -> str:
    """Run Mythril against a contract and return raw JSON output.

    Requires Mythril to be installed and available as the `myth` CLI:
        pip install mythril

    Args:
        target: Path to the Solidity file to analyze.
        function: Optional specific function to focus analysis on.
        timeout: Execution timeout in seconds (default: from config or 600).

    Returns:
        Raw JSON output from Mythril.

    Raises:
        GarrisonToolNotFoundError: If Mythril is not installed.
        GarrisonTimeoutError: If analysis times out.
        GarrisonAnalysisError: If analysis fails.
    """
    # Use config value if not provided
    if timeout is None:
        timeout = get_mythril_timeout()
    cmd = [
        "myth",
        "analyze",
        target,
        "-o",
        "jsonv2",
        "--execution-timeout",
        str(timeout),
    ]
    if function:
        cmd.extend(["--function", function])

    result = None  # Initialize to prevent UnboundLocalError
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 30,
        )
    except FileNotFoundError as e:
        logger.error("Mythril (myth) not found")
        raise GarrisonToolNotFoundError(
            "Mythril not found in PATH",
            details={
                "tool": "mythril",
                "install_cmd": "pip install mythril"
            }
        ) from e
    except subprocess.TimeoutExpired as e:
        logger.error(f"Mythril analysis timed out after {timeout}s")
        raise GarrisonTimeoutError(
            "Mythril analysis timed out",
            details={
                "operation": "mythril_analysis",
                "timeout_seconds": timeout
            }
        ) from e
    except PermissionError as e:
        logger.error(f"Permission denied running Mythril: {e}")
        raise GarrisonAnalysisError(
            "Permission denied running Mythril",
            details={"error": str(e)}
        ) from e

    # Mythril may return non-zero when issues are found; we still care about stdout
    if result and result.stderr:
        append_stderr_log(result.stderr, "mythril", stderr_log)
    return result.stdout if result else ""


def parse_issues(raw_output: str) -> List[Dict[str, Any]]:
    """Parse Mythril JSON output into a normalized list of issues.

    Args:
        raw_output: Raw JSON string from Mythril.

    Returns:
        List of normalized issue dictionaries.
    """
    logger.debug("Parsing Mythril output")
    if not raw_output or not raw_output.strip():
        logger.debug("Empty Mythril output, returning empty list")
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError as e:
        logger.warning(f"Failed to parse Mythril JSON output: {e}")
        return []

    if isinstance(data, dict):
        issues = data.get("issues", [])
    elif isinstance(data, list):
        issues = data
    else:
        issues = []

    normalized: List[Dict[str, Any]] = []
    for issue in issues:
        description = issue.get("description")
        if isinstance(description, dict):
            desc_text = description.get("head") or description.get("tail") or ""
        else:
            desc_text = description or ""

        normalized.append(
            {
                "swc_id": issue.get("swc-id") or issue.get("swcId"),
                "title": issue.get("title"),
                "description": desc_text,
                "severity": issue.get("severity"),
                "function": issue.get("function"),
                "address": issue.get("address"),
            }
        )

    return normalized


def print_report(issues: List[Dict[str, Any]]) -> None:
    """Pretty-print a CLI report for symbolic analysis results.

    Args:
        issues: List of parsed issues to report.
    """
    logger.info(f"Symbolic analysis report: {len(issues)} issues found")
    print("\n" + "=" * 60)
    print(f" SYMBOLIC ANALYSIS REPORT - {len(issues)} ISSUES FOUND")
    print("=" * 60 + "\n")

    if not issues:
        print("[+] STATUS: No issues reported by Mythril for this run.")
        return

    for i, issue in enumerate(issues, 1):
        title = issue.get("title") or "Unnamed issue"
        severity = issue.get("severity") or "UNKNOWN"
        print(f"[{i}] {severity} - {title}")

        if issue.get("swc_id"):
            print(f"    SWC: {issue['swc_id']}")
        if issue.get("function"):
            print(f"    Function: {issue['function']}")
        if issue.get("address"):
            print(f"    Address/PC: {issue['address']}")

        desc = issue.get("description") or ""
        if desc:
            print(f"    Description: {desc}")

        print("-" * 60)


def main() -> None:
    """Main entry point for the symbolic wrapper CLI."""
    parser = argparse.ArgumentParser(
        description="Symbolic execution wrapper for Mythril.",
    )
    parser.add_argument(
        "target",
        help="Path to Solidity file or compiled contract to analyze",
    )
    parser.add_argument(
        "--function",
        help="Specific function name to focus on",
        default=None,
    )
    parser.add_argument(
        "--timeout",
        type=int,
        help="Execution timeout in seconds",
        default=600,
    )
    args = parser.parse_args()

    try:
        raw = run_mythril(args.target, args.function, args.timeout)
        issues = parse_issues(raw)
        print_report(issues)
    except Exception as e:
        logger.error(f"Symbolic analysis failed: {e}")
        raise


if __name__ == "__main__":
    main()
