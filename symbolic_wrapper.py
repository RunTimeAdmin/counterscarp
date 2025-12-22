import subprocess
import json
import argparse
import sys
from typing import List, Dict, Any


def run_mythril(target: str, function: str = None, timeout: int = 600) -> str:
    """Run Mythril against a contract and return raw JSON output.

    Requires Mythril to be installed and available as the `myth` CLI:
        pip install mythril
    """
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
    except FileNotFoundError:
        print("[!] ERROR: 'myth' (Mythril) not found. Install it with: pip install mythril")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"[!] ERROR: Mythril analysis timed out after {timeout} seconds.")
        return ""

    # Mythril may return non-zero when issues are found; we still care about stdout
    return result.stdout if result else ""


def parse_issues(raw_output: str) -> List[Dict[str, Any]]:
    """Parse Mythril JSON output into a normalized list of issues."""
    if not raw_output or not raw_output.strip():
        return []

    try:
        data = json.loads(raw_output)
    except json.JSONDecodeError:
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
    """Pretty-print a CLI report for symbolic analysis results."""
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

    raw = run_mythril(args.target, args.function, args.timeout)
    issues = parse_issues(raw)
    print_report(issues)


if __name__ == "__main__":
    main()
