"""
healthcheck.py — Garrison Engine tool version verification
Loads tool-versions.json and checks each tool's installed version.

Usage:
    python healthcheck.py          # standalone
    from healthcheck import run_healthcheck; run_healthcheck()  # API
"""

import json
import re
import subprocess
import sys
from pathlib import Path

# ---------------------------------------------------------------------------
# Tool command definitions: (command_args, version_regex)
# ---------------------------------------------------------------------------
TOOL_COMMANDS: dict[str, tuple[list[str], str]] = {
    "slither": (["slither", "--version"], r"(\d+\.\d+\.\d+)"),
    "aderyn": (["aderyn", "--version"], r"(\d+\.\d+\.\d+)"),
    "medusa": (["medusa", "version"], r"(\d+\.\d+\.\d+)"),
    "mythril": (["myth", "version"], r"(\d+\.\d+\.\d+)"),
    "foundry": (["forge", "--version"], r"(\d+\.\d+\.\d+)"),
    "solc_default": (["solc", "--version"], r"(\d+\.\d+\.\d+)"),
}

STATUS_OK = "OK"
STATUS_MISMATCH = "MISMATCH"
STATUS_MISSING = "NOT FOUND"

COL_W = {"tool": 14, "expected": 10, "found": 10, "status": 10}


def _load_expected(json_path: Path | None = None) -> dict[str, str]:
    """Load expected versions from tool-versions.json."""
    candidates = [
        json_path,
        Path(__file__).parent / "tool-versions.json",
        Path("/app/tool-versions.json"),
    ]
    for path in candidates:
        if path and path.exists():
            with path.open() as f:
                return json.load(f)
    raise FileNotFoundError(
        "tool-versions.json not found in any expected location"
    )


def _get_installed_version(cmd: list[str]) -> str | None:
    """Run a tool's version command and return raw stdout+stderr, or None."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        return (result.stdout + result.stderr).strip()
    except FileNotFoundError:
        return None
    except subprocess.TimeoutExpired:
        return None


def _extract_version(output: str, pattern: str) -> str | None:
    match = re.search(pattern, output)
    return match.group(1) if match else None


def run_healthcheck(json_path: Path | None = None) -> bool:
    """
    Run version checks for all tools.
    Prints a status table to stdout.
    Returns True if all tools are OK, False otherwise.
    """
    try:
        expected_versions = _load_expected(json_path)
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}")
        return False

    header = (
        f"{'Tool':<{COL_W['tool']}} "
        f"{'Expected':<{COL_W['expected']}} "
        f"{'Found':<{COL_W['found']}} "
        f"{'Status':<{COL_W['status']}}"
    )
    separator = "-" * len(header)
    print(separator)
    print(header)
    print(separator)

    all_ok = True

    for tool_key, (cmd, pattern) in TOOL_COMMANDS.items():
        expected = expected_versions.get(tool_key, "N/A")
        raw_output = _get_installed_version(cmd)

        if raw_output is None:
            found = "—"
            status = STATUS_MISSING
            all_ok = False
        else:
            found = _extract_version(raw_output, pattern) or "?"
            if found == expected:
                status = STATUS_OK
            else:
                status = STATUS_MISMATCH
                all_ok = False

        print(
            f"{tool_key:<{COL_W['tool']}} "
            f"{expected:<{COL_W['expected']}} "
            f"{found:<{COL_W['found']}} "
            f"{status:<{COL_W['status']}}"
        )

    print(separator)
    if all_ok:
        print("All tools verified successfully.")
    else:
        print("One or more tools are missing or have version mismatches.")

    return all_ok


if __name__ == "__main__":
    ok = run_healthcheck()
    sys.exit(0 if ok else 1)
