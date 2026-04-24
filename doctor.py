"""Counterscarp Engine — Environment Diagnostic Tool (counterscarp doctor)"""

from __future__ import annotations

import shutil
import subprocess
import sys
import re
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Version helpers
# ---------------------------------------------------------------------------

def _get_engine_version() -> str:
    try:
        from importlib.metadata import version as _pkg_version
        return _pkg_version("counterscarp-engine")
    except Exception:
        pass
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # noqa: F811
        except ImportError:
            return "5.0.3"
    import pathlib
    toml_path = pathlib.Path(__file__).parent / "pyproject.toml"
    try:
        with open(toml_path, "rb") as f:
            data = tomllib.load(f)
        return str(data["project"]["version"])
    except Exception:
        return "5.0.3"


def _parse_semver(version_str: str) -> Tuple[int, int, int]:
    """Extract (major, minor, patch) from a version string, best-effort."""
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", version_str)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    m2 = re.search(r"(\d+)\.(\d+)", version_str)
    if m2:
        return int(m2.group(1)), int(m2.group(2)), 0
    m3 = re.search(r"(\d+)", version_str)
    if m3:
        return int(m3.group(1)), 0, 0
    return (0, 0, 0)


def _version_ok(installed: str, required: str) -> bool:
    """Return True if installed >= required (semver comparison)."""
    return _parse_semver(installed) >= _parse_semver(required)


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------

def _run_cmd(cmd: List[str]) -> Tuple[bool, str]:
    """
    Run *cmd* and return (success, output_text).
    Returns (False, error_reason) on any failure.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = (result.stdout + result.stderr).strip()
        return True, output
    except FileNotFoundError:
        return False, "NOT_FOUND"
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except Exception as exc:  # noqa: BLE001
        return False, f"ERROR: {exc}"


# ---------------------------------------------------------------------------
# Individual tool checks
# ---------------------------------------------------------------------------

def _check_tool(
    name: str,
    binary: str,
    version_args: List[str],
    version_pattern: str,
    min_version: Optional[str],
    notes: str,
    is_core: bool = False,
) -> Dict:
    """Return a status dict for a single external tool."""
    found = shutil.which(binary) is not None
    if not found:
        return {
            "name": name,
            "binary": binary,
            "found": False,
            "status": "MISSING",
            "version": None,
            "min_version": min_version,
            "notes": notes,
            "is_core": is_core,
        }

    ok, output = _run_cmd([binary] + version_args)
    if not ok:
        return {
            "name": name,
            "binary": binary,
            "found": True,
            "status": "ERROR",
            "version": None,
            "min_version": min_version,
            "notes": output,
            "is_core": is_core,
        }

    # Try to extract version from output — search every line so that
    # tools like Mythril (which emit tracebacks/warnings before the
    # actual version string) are handled correctly.
    version: Optional[str] = None
    lines = output.splitlines()
    if version_pattern:
        for line in lines:
            m = re.search(version_pattern, line)
            if m:
                version = m.group(1)
                break
    if version is None:
        # fallback: scan every line for any semver-looking token
        for line in lines:
            m2 = re.search(r"v?(\d+\.\d+\.\d+)", line)
            if m2:
                version = m2.group(1)
                break

    if version is None:
        status = "ERROR"
        notes_out = f"Version parse failed. Raw: {output[:80]}"
    elif min_version and not _version_ok(version, min_version):
        status = "OUTDATED"
        notes_out = notes
    else:
        status = "OK"
        notes_out = notes

    return {
        "name": name,
        "binary": binary,
        "found": True,
        "status": status,
        "version": version,
        "min_version": min_version,
        "notes": notes_out,
        "is_core": is_core,
    }


def _check_python_package(pkg_name: str, notes: str) -> Dict:
    """Check if a Python package is importable."""
    try:
        from importlib.metadata import version as pkg_ver
        ver = pkg_ver(pkg_name)
        return {"name": pkg_name, "status": "OK", "version": ver, "notes": notes}
    except Exception:
        pass
    return {"name": pkg_name, "status": "MISSING", "version": None, "notes": notes}


# ---------------------------------------------------------------------------
# Unicode / ASCII detection
# ---------------------------------------------------------------------------

def _supports_unicode() -> bool:
    try:
        enc = sys.stdout.encoding or ""
        "✓".encode(enc)
        return True
    except (UnicodeEncodeError, LookupError):
        return False


# ---------------------------------------------------------------------------
# Main doctor function
# ---------------------------------------------------------------------------

TOOL_SPECS = [
    # (name, binary, version_args, version_pattern, min_version, notes, is_core)
    ("Slither",  "slither",  ["--version"],  r"(\d+\.\d+\.\d+)",          "0.11.5", "Static analysis (core)",      True),
    ("Mythril",  "myth",     ["version"],    r"(\d+\.\d+\.\d+)",          "0.24.8", "pip install mythril",         False),
    ("Medusa",   "medusa",   ["--version"],  r"(\d+\.\d+\.\d+)",          "0.1.8",  "Coverage-guided fuzzing",     False),
    ("Aderyn",   "aderyn",   ["--version"],  r"(\d+\.\d+\.\d+)",          "0.6.2",  "See QUICKSTART.md",           False),
    ("Forge",    "forge",    ["--version"],  r"(\d+\.\d+\.\d+)",          "1.0.0",  "Foundry fuzzing & build",     True),
    ("solc",     "solc",     ["--version"],  r"Version:\s*(\d+\.\d+\.\d+)", "0.8.0", "Solidity compiler",          False),
]


def run_doctor() -> Dict:
    """
    Run all environment checks and print a formatted diagnostic table.

    Returns a result dict with keys:
        - tools: list of tool status dicts
        - python: Python version dict
        - go: Go version dict
        - packages: list of package status dicts
        - all_core_ok: bool — True if all core tools are present and OK
        - exit_code: 0 or 1
    """
    engine_ver = _get_engine_version()
    use_unicode = _supports_unicode()

    OK      = "✓ OK"      if use_unicode else "+ OK"
    MISSING = "✗ MISSING" if use_unicode else "x MISSING"
    OUTDATED = "! OUTDATED" if use_unicode else "! OUTDATED"
    ERROR   = "? ERROR"   if use_unicode else "? ERROR"
    SEP     = "─" * 22   if use_unicode else "-" * 22

    def fmt_status(s: str) -> str:
        if s == "OK":       return OK
        if s == "MISSING":  return MISSING
        if s == "OUTDATED": return OUTDATED
        if s == "OPTIONAL": return "~ OPTIONAL" if use_unicode else "~ OPTIONAL"
        return ERROR

    # ---- collect tool results ----
    tool_results = []
    for (name, binary, vargs, vpat, minver, notes, is_core) in TOOL_SPECS:
        r = _check_tool(name, binary, vargs, vpat, minver, notes, is_core)
        tool_results.append(r)

    # ---- Python ----
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    python_result = {"name": "Python", "status": "OK", "version": py_version, "notes": ""}

    # ---- Go ----
    # Go is only needed at build time (to compile Medusa); it is intentionally
    # absent from the Docker runtime image.  We report it as informational /
    # OPTIONAL so that a missing Go binary never counts as a failure.
    go_result: Dict
    go_ok, go_out = _run_cmd(["go", "version"])
    if go_ok:
        m = re.search(r"go(\d+\.\d+(?:\.\d+)?)", go_out)
        go_ver = m.group(1) if m else go_out[:20]
        go_result = {"name": "Go", "status": "OK", "version": go_ver, "notes": "OPTIONAL (build-time only, for Medusa install)"}
    else:
        go_result = {"name": "Go", "status": "OPTIONAL", "version": None, "notes": "OPTIONAL (build-time only, Medusa already compiled)"}

    # ---- Python packages ----
    pkg_results = [
        _check_python_package("sentence-transformers", "(RAG engine)"),
        _check_python_package("numpy", "(RAG engine)"),
    ]

    # ---- Print header ----
    header = f"Counterscarp Engine v{engine_ver} \u2014 Environment Check" if use_unicode else \
             f"Counterscarp Engine v{engine_ver} -- Environment Check"
    print(header)
    print("=" * len(header))
    print()

    # ---- External Tools table ----
    print("External Tools:")
    col = {"tool": 11, "status": 11, "version": 11, "required": 11}
    hdr_line = (
        f"  {'Tool':<{col['tool']}}  {'Status':<{col['status']}}  "
        f"{'Version':<{col['version']}}  {'Required':<{col['required']}}  Notes"
    )
    print(hdr_line)
    div = (
        f"  {SEP[:col['tool']]:<{col['tool']}}  {SEP[:col['status']]:<{col['status']}}  "
        f"{SEP[:col['version']]:<{col['version']}}  {SEP[:col['required']]:<{col['required']}}  "
        f"{SEP[:22]}"
    )
    print(div)

    for r in tool_results:
        status_str  = fmt_status(r["status"])
        version_str = r["version"] if r["version"] else "\u2014" if use_unicode else "-"
        req_str     = f"\u2265{r['min_version']}" if r["min_version"] else "" if use_unicode else \
                      (f">={r['min_version']}" if r["min_version"] else "")
        row = (
            f"  {r['name']:<{col['tool']}}  {status_str:<{col['status']}}  "
            f"{version_str:<{col['version']}}  {req_str:<{col['required']}}  {r['notes']}"
        )
        print(row)

    # ---- Runtime ----
    print()
    print("Runtime:")
    rt_col = {"name": 11, "status": 11, "version": 14}
    for rt in [python_result, go_result]:
        status_str  = fmt_status(rt["status"])
        version_str = rt["version"] if rt["version"] else ("\u2014" if use_unicode else "-")
        notes_str   = rt.get("notes", "")
        print(
            f"  {rt['name']:<{rt_col['name']}}  {status_str:<{rt_col['status']}}  "
            f"{version_str:<{rt_col['version']}}  {notes_str}"
        )

    # ---- Python Packages ----
    print()
    print("Python Packages:")
    for pkg in pkg_results:
        status_str = fmt_status(pkg["status"])
        print(f"  {pkg['name']:<23}  {status_str:<{col['status']}}  {pkg['notes']}")

    # ---- Summary ----
    print()
    # Go is build-time only and excluded from the ready/missing counts.
    total_checks = len(tool_results) + 1 + len(pkg_results)  # tools + Python + packages (Go excluded)
    ok_count = (
        sum(1 for r in tool_results if r["status"] == "OK")
        + (1 if python_result["status"] == "OK" else 0)
        + sum(1 for p in pkg_results if p["status"] == "OK")
    )
    missing_tools = [r["name"] for r in tool_results if r["status"] in ("MISSING", "OUTDATED", "ERROR")]
    missing_core  = [r["name"] for r in tool_results if r["is_core"] and r["status"] != "OK"]

    summary_line = f"Summary: {ok_count}/{total_checks} analyzers ready"
    if missing_tools:
        summary_line += f" ({len(missing_tools)} tools missing: {', '.join(missing_tools)})"
    print(summary_line)

    if missing_core:
        fail_sym = "\u2717" if use_unicode else "x"
        print(f"  Core analyzers: {fail_sym} MISSING — {', '.join(missing_core)} required for scans")
    else:
        ok_sym = "\u2713" if use_unicode else "+"
        print(f"  Core analyzers: {ok_sym} All operational")

    if missing_tools:
        print("  Optional tools missing will be skipped gracefully during scans.")

    all_core_ok = len(missing_core) == 0
    exit_code = 0 if all_core_ok else 1

    return {
        "tools": tool_results,
        "python": python_result,
        "go": go_result,
        "packages": pkg_results,
        "all_core_ok": all_core_ok,
        "exit_code": exit_code,
    }


# ---------------------------------------------------------------------------
# CLI entry point (direct execution)
# ---------------------------------------------------------------------------

def main() -> None:
    result = run_doctor()
    sys.exit(result["exit_code"])


if __name__ == "__main__":
    main()
