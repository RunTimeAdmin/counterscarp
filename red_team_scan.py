from __future__ import annotations

import logging
import os
import re
import subprocess
import json
import shutil
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, cast
from path_security import sanitize_cli_path

# Import exceptions (core module — must always be available)
from exceptions import (
    CounterscarpAnalysisError,
    CounterscarpToolNotFoundError,
)

# Import logger with fallback
try:
    from logger import get_logger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False

    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

    def append_stderr_log(  # noqa: E501
        stderr_text: str, tool_name: str, stderr_log_path: str
    ) -> None:
        pass

# Import config loader
try:
    from config_loader import load_config, CounterscarpConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

# Initialize logger
logger: logging.Logger = get_logger(__name__)

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


# CONFIGURATION: What defines "Noise" vs "Signal"
# We ignore "Low" and "Informational" by default.
# These defaults are used if config is not available.
DEFAULT_SEVERITY_ALLOWLIST = ["High", "Medium"]

# IGNORE LIST: Specific check IDs that are often noise in modern contracts
# Example: 'solc-version' is usually just complaining you aren't on the
# latest nightly build.
DEFAULT_IGNORE_CHECKS = [
    "solc-version",
    "naming-convention",
    "assembly",  # Often used intentionally for optimization
    "redundant-statements"
]


def get_severity_allowlist() -> List[str]:
    """Get severity allowlist from config or use default."""
    try:
        return get_config().red_team.severity_allowlist
    except Exception:
        return DEFAULT_SEVERITY_ALLOWLIST


def get_ignore_checks() -> List[str]:
    """Get ignore checks list from config or use default."""
    try:
        return get_config().red_team.ignore_checks
    except Exception:
        return DEFAULT_IGNORE_CHECKS


def _validate_path_containment(
    file_path: str, project_root: str
) -> Path:
    """Ensure file_path is contained within project_root.

    Prevents path traversal attacks.

    Args:
        file_path: The file or directory path to validate.
        project_root: The expected root directory that must contain file_path.

    Returns:
        Resolved Path object for file_path.

    Raises:
        ValueError: If file_path resolves outside of project_root.
    """
    resolved = Path(file_path).resolve()
    root = Path(project_root).resolve()
    resolved.relative_to(root)  # Raises ValueError if path escapes root
    return resolved


def find_project_root(target_path: str) -> Optional[str]:
    """Walk up from target to find Foundry/Hardhat project root.

    Looks for foundry.toml, hardhat.config.js, or hardhat.config.ts
    in ancestor directories.

    Args:
        target_path: Path to the Solidity file or directory being analyzed.

    Returns:
        Absolute path to project root, or None if not found.
    """
    path = Path(target_path).resolve()
    if path.is_file():
        path = path.parent
    while path != path.parent:
        foundry = (path / "foundry.toml").exists()
        hardhat = (
            (path / "hardhat.config.js").exists()
            or (path / "hardhat.config.ts").exists()
        )
        if foundry or hardhat:
            return str(path)
        path = path.parent
    return None


def _resolve_slither_bin() -> str:
    """Resolve the Slither binary path from the current venv.

    Checks for slither and slither.exe in the venv Scripts directory,
    falls back to shutil.which("slither"), then bare "slither".

    Returns:
        Path to the Slither binary.
    """
    venv_bin_dir = Path(sys.executable).parent

    # Check for slither.exe first (Windows), then slither (Unix)
    for candidate in ("slither.exe", "slither"):
        candidate_path = venv_bin_dir / candidate
        if candidate_path.exists():
            logger.debug(f"Resolved slither binary: {candidate_path}")
            return str(candidate_path)

    # Fallback: use shutil.which to search PATH
    which_result = shutil.which("slither")
    if which_result:
        logger.debug(
            f"Resolved slither binary via shutil.which: {which_result}"
        )
        return which_result

    # Last resort: bare name, rely on OS PATH resolution
    logger.debug("Falling back to bare 'slither' (relying on PATH)")
    return "slither"


# Directories whose .sol files are dependencies/tests, not the project's own
# sources — excluded when inferring the required solc version from pragmas.
_SOL_SKIP_DIRS = {
    "node_modules", "lib", ".git", "out", "artifacts", "cache",
    "test", "tests", "mock", "mocks",
}


def _resolve_sibling_bin(slither_bin: str, name: str) -> Optional[str]:
    """Resolve a tool (e.g. solc, solc-select) from slither's own venv bin dir.

    Falls back to PATH so a globally-installed tool is still found.
    """
    try:
        sibling = Path(slither_bin).parent / name
        if sibling.exists():
            return str(sibling)
    except (OSError, ValueError):
        pass
    return shutil.which(name)


def _version_tuple(text: str) -> Optional[Tuple[int, int, int]]:
    """Extract a leading semantic version (e.g. '0.8.34') as an int tuple."""
    m = re.match(r"\s*v?(\d+)\.(\d+)\.(\d+)", text)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _installed_solc_versions(
    solc_select_bin: str,
) -> List[Tuple[int, int, int]]:
    """List installed solc versions via `solc-select versions`, newest first."""
    try:
        res = subprocess.run(
            [solc_select_bin, "versions"],
            capture_output=True, text=True, check=False, timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    versions = set()
    for line in res.stdout.splitlines():
        vt = _version_tuple(line.strip())
        if vt:
            versions.add(vt)
    return sorted(versions, reverse=True)


def _solc_can_run(version: str, solc_bin: str) -> bool:
    """True iff the solc binary crytic-compile will actually invoke can run
    ``version``.

    Guards against a solc-select install list that differs from the compiler
    on PATH: ``solc-select versions`` (which we read) and the ``solc`` shim
    crytic uses can point at different install dirs, so selecting a version the
    real compiler lacks would fail the scan for the wrong reason ("Solidity
    version not found") instead of surfacing the true issue.
    """
    env = os.environ.copy()
    env["SOLC_VERSION"] = version
    try:
        res = subprocess.run(
            [solc_bin, "--version"],
            capture_output=True, text=True, check=False, timeout=30, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    blob = f"{res.stdout}\n{res.stderr}".lower()
    return res.returncode == 0 and "version:" in blob and "not installed" not in blob


def _parse_pragma_constraints(
    pragma: str,
) -> List[Tuple[str, Tuple[int, int, int]]]:
    """Parse a Solidity version pragma into (operator, version) constraints.

    Handles ^, ~, >=, >, <=, <, = and bare exact versions. Partial versions
    (e.g. ``0.8``) are padded to three parts. Unrecognized tokens are skipped.
    """
    constraints: List[Tuple[str, Tuple[int, int, int]]] = []
    for op, ver in re.findall(
        r"(\^|~|>=|<=|>|<|=)?\s*(\d+(?:\.\d+){0,2})", pragma
    ):
        parts = [int(x) for x in ver.split(".")]
        while len(parts) < 3:
            parts.append(0)
        constraints.append((op or "=", (parts[0], parts[1], parts[2])))
    return constraints


def _version_satisfies(
    v: Tuple[int, int, int],
    constraints: List[Tuple[str, Tuple[int, int, int]]],
) -> bool:
    """Return True if version ``v`` satisfies every parsed pragma constraint."""
    for op, ref in constraints:
        if op == "=":
            if v != ref:
                return False
        elif op == ">":
            if not v > ref:
                return False
        elif op == ">=":
            if not v >= ref:
                return False
        elif op == "<":
            if not v < ref:
                return False
        elif op == "<=":
            if not v <= ref:
                return False
        elif op in ("^", "~"):
            if not v >= ref:
                return False
            # ^ bumps the major (or minor/patch for 0.x); ~ bumps the minor.
            if op == "^" and ref[0] > 0:
                upper = (ref[0] + 1, 0, 0)
            elif op == "^" and ref[1] > 0:
                upper = (ref[0], ref[1] + 1, 0)
            elif op == "^":
                upper = (ref[0], ref[1], ref[2] + 1)
            else:  # ~
                upper = (ref[0], ref[1] + 1, 0)
            if not v < upper:
                return False
    return True


def _collect_sol_files(target: str, cap: int = 300) -> List[Path]:
    """Collect the project's own .sol files (bounded), skipping deps/tests."""
    tp = Path(target)
    if tp.is_file():
        return [tp]
    if not tp.is_dir():
        return []
    top = sorted(tp.glob("*.sol"))
    if top:
        return top[:cap]
    files: List[Path] = []
    for p in sorted(tp.rglob("*.sol")):
        if any(part in _SOL_SKIP_DIRS for part in p.parts):
            continue
        files.append(p)
        if len(files) >= cap:
            break
    return files


def _select_solc_version(
    target: str, solc_select_bin: Optional[str]
) -> Optional[str]:
    """Pick the newest installed solc that satisfies the target's pragma(s).

    Returns a version string like ``"0.8.34"`` to pass via ``SOLC_VERSION``,
    or None when it cannot be determined (caller keeps the environment
    default). This stops projects on a newer pragma (e.g. ``^0.8.28``) from
    silently failing against a stale default compiler.
    """
    if not solc_select_bin:
        return None
    constraints: List[Tuple[str, Tuple[int, int, int]]] = []
    for f in _collect_sol_files(target):
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for pragma in re.findall(r"pragma\s+solidity\s+([^;]+);", text):
            if "||" in pragma:  # disjunctions unsupported — skip
                continue
            constraints.extend(_parse_pragma_constraints(pragma))
    if not constraints:
        return None
    # Verify a candidate against the solc crytic will actually invoke (PATH
    # resolution, same as the compile subprocess), not just solc-select's list.
    verify_solc = shutil.which("solc")
    for v in _installed_solc_versions(solc_select_bin):  # newest first
        if not _version_satisfies(v, constraints):
            continue
        candidate = f"{v[0]}.{v[1]}.{v[2]}"
        if verify_solc is None or _solc_can_run(candidate, verify_solc):
            return candidate
        logger.warning(
            "solc %s satisfies the pragma and is listed by solc-select, but the "
            "compiler on PATH cannot run it; trying an older installed version",
            candidate,
        )
    return None


def _diagnose_compile_failure(
    target: str, slither_bin: str, selected_solc: Optional[str]
) -> Optional[str]:
    """Probe solc directly to surface why compilation failed.

    Slither on a bare directory can exit non-zero with EMPTY stdout and
    stderr, hiding the cause. Run the solc binary on a sample source file,
    honouring the selected compiler, and classify the error into a
    human-readable diagnosis (version mismatch / missing deps / syntax).
    """
    solc_bin = _resolve_sibling_bin(slither_bin, "solc")
    if not solc_bin:
        return None
    samples = _collect_sol_files(target, cap=1)
    if not samples:
        return None
    sample = samples[0]
    env = os.environ.copy()
    if selected_solc:
        env["SOLC_VERSION"] = selected_solc
    try:
        res = subprocess.run(
            [solc_bin, sample.name],
            cwd=str(sample.parent),
            capture_output=True, text=True, check=False, timeout=120, env=env,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    blob = f"{res.stdout}\n{res.stderr}".strip()
    low = blob.lower()
    if "requires different compiler version" in low:
        detail = f" (selected {selected_solc})" if selected_solc else ""
        return (
            "solc version mismatch: no installed compiler satisfies the "
            f"contract's `pragma solidity` requirement{detail}. Install a "
            "matching one, e.g. `solc-select install <version>`."
        )
    if ("not found: file not found" in low) or (
        'source "' in low and "not found" in low
    ):
        return (
            "unresolved imports / missing dependencies: the contracts import "
            "external libraries (e.g. @openzeppelin, @account-abstraction) but "
            "no node_modules, lib/, or remappings were provided. Submit the "
            "full Foundry/Hardhat project (with its dependency tree), a "
            "remappings.txt, or a flattened single-file contract."
        )
    if any(tok in low for tok in ("parsererror", "declarationerror", "typeerror")):
        for line in blob.splitlines():
            if "error" in line.lower():
                return f"Solidity compile error: {line.strip()[:240]}"
    for line in blob.splitlines():
        if line.strip():
            return f"compile probe: {line.strip()[:240]}"
    return None


def _parse_json_with_fallback(json_str: str, context: str = "") -> Any:
    """Parse JSON with brace-counting fallback for trailing data.

    Attempts json.loads() first.  If that fails, tries to find the
    matching closing brace by counting braces, then parses just
    that substring.

    Args:
        json_str: String starting with '{' containing JSON data.
        context: Optional context for warning messages.

    Returns:
        Parsed JSON data.

    Raises:
        json.JSONDecodeError: If parsing fails even after fallback.
    """
    try:
        return json.loads(json_str)
    except json.JSONDecodeError:
        brace_count = 0
        end_idx = -1
        for i, ch in enumerate(json_str):
            if ch == '{':
                brace_count += 1
            elif ch == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        if end_idx != -1:
            truncated = json_str[end_idx:].strip()
            if truncated:
                ctx = f" for {context}" if context else ""
                logger.warning(
                    f"Truncated trailing data from JSON output{ctx} "
                    f"({len(truncated)} chars after closing brace)"
                )
            return json.loads(json_str[:end_idx])
        raise


def _slither_per_file_fallback(
    target: str,
    project_root: str,
    slither_bin: str,
    original_cmd: List[str],
    stderr_log: Optional[str] = None,
    solc_version: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Run Slither on individual .sol files using solc.

    When Foundry-based Slither analysis fails (e.g., due to
    tload/unsupported Yul instructions in dependencies),
    fall back to running Slither on each .sol file in the
    target directory individually using solc with remappings.

    Args:
        target: Original target path (directory of .sol files).
        project_root: Foundry project root directory.
        slither_bin: Path to the Slither binary.
        original_cmd: The original Slither command (for remaps).

    Returns:
        Aggregated Slither JSON output, or None on failure.
    """
    import glob as glob_mod

    target_path = Path(target).resolve()
    if not target_path.is_dir():
        return None

    sol_files = sorted(glob_mod.glob(str(target_path / "*.sol")))
    if not sol_files:
        print("    [!] No .sol files found for per-file fallback")
        return None

    # Extract remappings from original command
    remaps = None
    if "--solc-remaps" in original_cmd:
        idx = original_cmd.index("--solc-remaps")
        if idx + 1 < len(original_cmd):
            remaps = original_cmd[idx + 1]

    # Make target relative to project root
    root = Path(project_root).resolve()

    all_detectors: List[Dict[str, Any]] = []
    errors: List[str] = []
    success_count = 0
    fail_count = 0

    for sol_file in sol_files:
        sol_name = Path(sol_file).name
        # Build relative path from project root
        try:
            rel_file = str(Path(sol_file).relative_to(root))
        except ValueError:
            rel_file = sol_name

        file_cmd = [
            slither_bin, rel_file,
            "--json", "-",
            "--compile-force-framework", "solc",
        ]
        if remaps:
            file_cmd.extend(["--solc-remaps", remaps])

        try:
            # Security: validate sol_file is contained within project_root
            try:
                _validate_path_containment(sol_file, project_root)
            except ValueError:
                logger.warning(
                    f"[SECURITY] Path traversal rejected for per-file"
                    f" slither: {sol_file!r} escapes root {project_root!r}"
                )
                fail_count += 1
                errors.append(f"{sol_name}: path traversal rejected")
                continue
            _env = os.environ.copy()
            _env["PYTHONWARNINGS"] = "ignore"
            _env["PYTHONDONTWRITEBYTECODE"] = "1"
            if solc_version:
                _env["SOLC_VERSION"] = solc_version
            result = subprocess.run(
                file_cmd,
                cwd=project_root,
                capture_output=True,
                text=True,
                check=False,
                timeout=600,
                env=_env,
            )
            if result.stderr and stderr_log:
                logger.debug(
                    "slither-per-file stderr captured (%d chars)",
                    len(result.stderr),
                )
            output = result.stdout
            json_start = output.find("{")
            if json_start == -1:
                fail_count += 1
                reason = (result.stderr or result.stdout or "").strip()
                first = next(
                    (ln for ln in reason.splitlines() if ln.strip()), ""
                )
                if first:
                    errors.append(f"{sol_name}: {first[:200]}")
                continue

            data = _parse_json_with_fallback(
                output[json_start:], context=sol_name
            )
            if data.get("success", True):
                success_count += 1
                detectors = data.get("results", {}).get("detectors", [])
                all_detectors.extend(detectors)
            else:
                fail_count += 1
                err = data.get("error", "unknown")
                errors.append(f"{sol_name}: {err}")
        except subprocess.TimeoutExpired:
            fail_count += 1
            logger.warning(f"Slither timed out on {sol_name} (600s)")
            errors.append(f"{sol_name}: timeout after 600s")
        except Exception as exc:
            fail_count += 1
            errors.append(f"{sol_name}: {exc}")

    print(
        f"    [*] Per-file solc results:"
        f" {success_count} succeeded, {fail_count} failed,"
        f" {len(all_detectors)} total detectors"
    )
    if errors:
        for e in errors[:3]:
            print(f"    [!]   Error: {e}")
        if len(errors) > 3:
            print(f"    [!]   ... and {len(errors) - 3} more")

    if not all_detectors and fail_count > 0:
        return None

    # Return in standard Slither JSON format
    return {
        "success": True,
        "error": None,
        "results": {
            "detectors": all_detectors,
        },
    }


def run_slither(
    target: str,
    stderr_log: Optional[str] = None,
    exclude_paths: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Runs Slither via subprocess and captures JSON output.

    Detects Foundry/Hardhat project root so Slither can resolve
    import remappings and framework-specific compilation settings.

    Args:
        target: Path to the Solidity file or directory to analyze.
        stderr_log: Optional path for Slither stderr log.
        exclude_paths: Optional list of glob patterns to pass to Slither
            via ``--filter-paths`` (e.g. ``test/**``).

    Returns:
        Parsed JSON output from Slither.

    Raises:
        CounterscarpToolNotFoundError: If Slither is not installed.
        CounterscarpAnalysisError: If Slither analysis fails or
            output cannot be parsed.
    """
    _target_is_file = Path(target).expanduser().is_file()
    safe_target = sanitize_cli_path(
        target,
        must_exist=False,
        expect_file=_target_is_file,
        allowed_suffixes={".sol"} if _target_is_file else None,
    )
    target = str(safe_target)
    print(f"[*] Spawning Slither process for target: {target}...")

    # Resolve Slither binary from venv
    slither_bin = _resolve_slither_bin()

    # Pragma-aware solc selection: pick the newest installed solc that
    # satisfies the contract's `pragma solidity`, so a newer-pragma project
    # (e.g. ^0.8.28) doesn't silently fail against a stale default compiler.
    solc_select_bin = _resolve_sibling_bin(slither_bin, "solc-select")
    selected_solc = _select_solc_version(target, solc_select_bin)
    if selected_solc:
        print(f"[*] Pragma-aware solc: using {selected_solc} (SOLC_VERSION)")
    else:
        print(
            "[*] Pragma-aware solc: no matching override;"
            " using environment default"
        )

    # Detect Foundry/Hardhat project root
    project_root = find_project_root(target)
    if project_root:
        project_root = str(
            sanitize_cli_path(project_root, must_exist=True, expect_file=False)
        )
    forge_available = shutil.which("forge") is not None

    # Determine working directory for subprocess
    if project_root and forge_available:
        # forge is available — safe to use project root as cwd
        cwd = project_root
        # Make target relative to project root so
        # Slither resolves paths correctly
        try:
            root = Path(project_root).resolve()
            rel_target = str(
                Path(target).resolve().relative_to(root)
            )
        except ValueError:
            rel_target = target
        effective_target = rel_target
        print(
            f"[*] Foundry/Hardhat project root detected:"
            f" {project_root} (forge available)"
        )
    elif project_root and not forge_available:
        # forge NOT available — must NOT set cwd to project root
        # because crytic-compile will auto-detect foundry.toml
        # and crash trying to run `forge remappings`.
        # Use the target directory itself as cwd instead.
        target_path = Path(target).resolve()
        if target_path.is_file():
            cwd = str(target_path.parent)
            effective_target = target_path.name
        else:
            cwd = str(target_path)
            effective_target = "."
        print(
            f"[*] Foundry project detected at {project_root}"
            f" but forge not in PATH;"
            f" using target dir as cwd"
        )
    else:
        # No project root found — run from target's parent directory
        target_path = Path(target).resolve()
        if target_path.is_file():
            cwd = str(target_path.parent)
            effective_target = target_path.name  # Just the filename
        else:
            cwd = str(target_path)
            effective_target = "."
        project_root = None

    # Build the Slither command
    cmd = [slither_bin, effective_target, "--json", "-"]

    # Add Foundry-specific flags if a foundry.toml was found
    is_foundry = (
        project_root
        and (Path(project_root) / "foundry.toml").exists()
    )
    if is_foundry:
        if forge_available:
            # Strategy: Use Foundry framework with project root as
            # target and --foundry-ignore-compile (forge already
            # built). This avoids compile_all iterating over .sol
            # files (which causes NotADirectoryError) and the
            # overhead of re-running forge build.
            cmd[1] = "."
            cmd.extend([
                "--compile-force-framework", "foundry",
                "--foundry-ignore-compile",
            ])
            print(
                "[*] Foundry mode: project root + ignore-compile"
                " (using existing forge build artifacts)"
            )
            # Use Foundry default out dir for build-info discovery.
            foundry_out = "out"
            cmd.extend(["--foundry-out-directory", foundry_out])
            print(
                f"[*] Foundry out directory: {foundry_out!r}"
                f" (--foundry-out-directory)"
            )
        else:
            # Force solc to prevent crytic-compile from
            # auto-detecting foundry.toml and invoking forge
            # (which would crash if forge is unavailable)
            cmd.append("--compile-force-framework")
            cmd.append("solc")

    # Note: explicit remappings.txt parsing is disabled here to avoid
    # propagating user-controlled filesystem paths through path construction.

    # Pass exclusion patterns to Slither via --filter-paths
    if exclude_paths:
        # Slither's --filter-paths accepts a comma-separated list of
        # path substrings / regex patterns.  Strip trailing glob
        # wildcards so they work as substring filters
        # (e.g. "node_modules/**" → "node_modules").
        filter_parts = []
        for p in exclude_paths:
            bare = p.rstrip("/").rstrip("*").rstrip("/")
            if bare:
                filter_parts.append(bare)
        if filter_parts:
            cmd.extend(["--filter-paths", ",".join(filter_parts)])
            logger.info("Slither filter-paths: %s", ",".join(filter_parts))

    # Run forge build --build-info before Slither when using
    # --foundry-ignore-compile (Slither won't build itself, so we
    # must ensure build artifacts exist in the out/build-info dir).
    if is_foundry and forge_available and project_root:
        forge_bin = shutil.which("forge")
        if forge_bin:
            print(
                "[*] Running 'forge build --build-info'"
                " to generate build artifacts..."
            )
            try:
                forge_result = subprocess.run(
                    [forge_bin, "build", "--build-info"],
                    cwd=cwd,
                    capture_output=True,
                    text=True,
                    check=False,
                    timeout=600,
                )
                if forge_result.returncode == 0:
                    print(
                        "[*] forge build succeeded"
                        " — build artifacts ready for Slither"
                    )
                else:
                    logger.warning(
                        "forge build --build-info exited with"
                        " code %d; Slither may fall back to"
                        " solc. stderr: %s",
                        forge_result.returncode,
                        forge_result.stderr[:500]
                        if forge_result.stderr
                        else "",
                    )
                    print(
                        f"[!] forge build failed"
                        f" (exit {forge_result.returncode});"
                        " continuing with Slither anyway"
                    )
            except subprocess.TimeoutExpired:
                logger.warning(
                    "forge build timed out;"
                    " continuing with Slither anyway"
                )
                print(
                    "[!] forge build timed out;"
                    " proceeding with Slither"
                )
            except OSError as exc:
                logger.warning(
                    "Could not run forge build: %s", exc
                )
                print(
                    f"[!] Could not run forge build ({exc});"
                    " proceeding with Slither"
                )

    print(f"[*] Slither command: {' '.join(cmd)}")
    print(f"[*] Working directory: {cwd}")

    try:
        # Security: validate target is within cwd before invoking slither
        try:
            _validate_path_containment(target, cwd)
        except ValueError:
            logger.warning(
                f"[SECURITY] Path traversal rejected for run_slither:"
                f" {target!r} escapes cwd {cwd!r}"
            )
            raise CounterscarpAnalysisError(
                "Path traversal detected: target escapes working directory",
                details={"target": target, "cwd": cwd},
            )
        # Run slither and capture stdout/stderr
        _slither_env = os.environ.copy()
        _slither_env["PYTHONWARNINGS"] = "ignore"
        _slither_env["PYTHONDONTWRITEBYTECODE"] = "1"
        if selected_solc:
            _slither_env["SOLC_VERSION"] = selected_solc
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,  # Slither exits non-zero on findings
            timeout=600,
            env=_slither_env,
        )

        if result.stderr and stderr_log:
            logger.debug("slither stderr captured (%d chars)", len(result.stderr))

        # Slither may mix logs in stdout, but --json -
        # usually dumps pure JSON. Handle setup logs before
        # the JSON payload.
        output = result.stdout

        # Attempt to find the start of the JSON structure
        json_start = output.find('{')
        if json_start == -1:
            # Try per-file solc fallback for directory targets
            # (covers plain .sol directories with no project root)
            target_path_obj = Path(target).resolve()
            if target_path_obj.is_dir():
                print(
                    "[!] Slither produced no JSON for directory;"
                    " trying per-file solc fallback..."
                )
                fallback = _slither_per_file_fallback(
                    target,
                    str(target_path_obj),  # use target dir as root
                    slither_bin,
                    cmd,
                    stderr_log,
                    selected_solc,
                )
                if fallback is not None:
                    return fallback
            # Slither can exit non-zero with EMPTY stdout+stderr on a compile
            # failure, hiding the cause. Probe solc directly to surface it so
            # the scan reports a real reason instead of an opaque failure.
            diagnosis = _diagnose_compile_failure(
                target, slither_bin, selected_solc
            )
            stderr_tail = (result.stderr or "").strip()[-1500:]
            stdout_tail = (result.stdout or "").strip()[-1500:]
            print("[!] CRITICAL: Slither produced no JSON output.")
            if diagnosis:
                print(f"[!] Diagnosis: {diagnosis}")
            if stderr_tail:
                print(f"[!] Slither stderr: {stderr_tail}")
            raise CounterscarpAnalysisError(
                diagnosis or "Slither failed to produce JSON output",
                details={
                    "tool": "slither",
                    "diagnosis": diagnosis,
                    "selected_solc": selected_solc,
                    "stderr": stderr_tail,
                    "stdout_tail": stdout_tail,
                    "cwd": cwd,
                }
            )

        json_data = output[json_start:]
        parsed = _parse_json_with_fallback(json_data, context="Slither")

        # Handle "success: false" from Slither (e.g., tload
        # or other IR analysis errors). Try fallback to
        # per-file solc analysis if Foundry mode failed.
        if not parsed.get("success", True):
            error_msg = parsed.get("error", "unknown")
            print(
                f"    [!] Slither analysis partial failure:"
                f" {error_msg}"
            )

            # If we were in Foundry mode, try per-file solc
            # as fallback for the original target directory
            if is_foundry and forge_available:
                print(
                    "    [*] Falling back to per-file solc"
                    " analysis for target directory"
                )
                fallback = _slither_per_file_fallback(
                    target, project_root or target, slither_bin, cmd,
                    stderr_log, selected_solc,
                )
                if fallback is not None:
                    return fallback

            # If no fallback worked, return the partial
            # result (may have 0 detectors but is valid JSON)
            if parsed.get("results", {}).get("detectors"):
                print(
                    f"    [*] Returning {len(parsed['results']['detectors'])}"
                    f" detectors from partial Slither run"
                )
            else:
                print(
                    "    [!] No detectors from Slither"
                    " (analysis error prevented detection)"
                )

        return cast(Dict[str, Any], parsed)

    except FileNotFoundError as e:
        logger.error("Slither command not found")
        raise CounterscarpToolNotFoundError(
            "Slither not found in PATH",
            details={
                "tool": "slither",
                "install_cmd": "pip3 install slither-analyzer"
            }
        ) from e
    except json.JSONDecodeError as e:
        logger.error(f"Could not parse Slither output: {e}")
        # Add partial recovery: return raw output for debugging
        error_data = {
            "error": "json_parse_failed",
            "message": str(e),
            "raw_stderr": result.stderr if result else "No stderr available",
            "raw_stdout_preview": (
                (result.stdout[:500] + "...")
                if result and len(result.stdout) > 500
                else (result.stdout if result else "")
            )
        }
        raise CounterscarpAnalysisError(
            "Could not parse Slither output - tool may have crashed",
            details=error_data
        ) from e
    except subprocess.CalledProcessError as e:
        logger.error(f"Slither process failed: {e}")
        raise CounterscarpAnalysisError(
            "Slither analysis failed",
            details={"returncode": e.returncode, "stderr": e.stderr}
        ) from e
    except subprocess.TimeoutExpired:
        logger.error("Slither analysis timed out (600s)")
        raise CounterscarpAnalysisError(
            "Slither analysis timed out after 600 seconds",
            details={"tool": "slither", "timeout": 600}
        )
    except PermissionError as e:
        logger.error(f"Permission denied running Slither: {e}")
        raise CounterscarpAnalysisError(
            "Permission denied running Slither",
            details={"error": str(e)}
        ) from e


def validate_slither_output(data: Dict[str, Any]) -> bool:
    """Validate that Slither JSON output contains expected fields.

    Checks for required keys in the Slither output schema:
    - 'results' key must exist
    - 'results.detectors' key should exist for findings

    Args:
        data: The parsed JSON data from Slither.

    Returns:
        True if the output appears valid, False otherwise.
    """
    if data is None:
        logger.warning("Slither output is None")
        return False

    if not isinstance(data, dict):
        logger.warning(f"Slither output is not a dict: {type(data)}")
        return False

    # Check for required top-level key
    if 'results' not in data:
        logger.warning("Slither output missing 'results' key")
        return False

    results = data['results']
    if not isinstance(results, dict):
        logger.warning(
            f"Slither 'results' is not a dict: {type(results)}"
        )
        return False

    # Check for detectors (may not exist if no findings)
    if 'detectors' not in results:
        logger.debug(
            "Slither output has no 'detectors' key "
            "(may have no findings)"
        )
        # This is not an error, just means no findings

    # Check for other expected fields and log warnings
    if 'errors' in results and results['errors']:
        logger.warning(f"Slither reported errors: {results['errors']}")

    # Log successful validation
    logger.debug("Slither output validation passed")
    return True


def filter_vulnerabilities(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Filters the raw Slither data for things that actually matter.

    Args:
        data: Raw JSON output from Slither.

    Returns:
        List of filtered vulnerability findings.
    """

    # Validate Slither output before processing
    if not validate_slither_output(data):
        logger.warning(
            "Slither output validation failed, returning empty findings"
        )
        return []

    # Handle case when Slither fails or returns None
    if data is None:
        return []

    # Handle case when data is not a dict (e.g., string error message)
    if not isinstance(data, dict):
        return []

    if not data.get("results") or not data["results"].get("detectors"):
        return []

    relevant_findings = []

    for finding in data["results"]["detectors"]:
        impact = finding.get("impact", "Unknown")
        check_id = finding.get("check", "Unknown")

        # 1. Filter by Severity
        if impact not in get_severity_allowlist():
            continue

        # 2. Filter by Ignore List (Noise)
        if check_id in get_ignore_checks():
            continue

        # 3. Construct clean finding object
        clean_finding = {
            "title": finding.get("check", "Unknown Issue"),
            "impact": impact,
            "description": finding.get(
                "description", "No description provided"
            ),
            "location": parse_location(finding.get("elements", []))
        }
        relevant_findings.append(clean_finding)

    return relevant_findings


def parse_location(elements: List[Dict[str, Any]]) -> str:
    """Extracts the first useful file/line number from the elements list.

    Args:
        elements: List of element dictionaries from Slither output.

    Returns:
        Formatted location string (file:line).
    """
    if not elements:
        return "Unknown location"

    # Usually the first element is the source of the bug
    el = elements[0]
    source_map = el.get("source_mapping", {})
    filename = source_map.get("filename_short", "unknown_file")
    lines = source_map.get("lines", [])

    if lines:
        return f"{filename} (Lines: {lines})"
    return str(filename)


def print_report(findings: List[Dict[str, Any]]) -> None:
    """Prints a Red Team style report.

    Args:
        findings: List of vulnerability findings to report.
    """
    logger.info(f"Vulnerability report: {len(findings)} critical issues found")
    print("\n" + "="*60)
    print(f" VULNERABILITY REPORT - {len(findings)} CRITICAL ISSUES FOUND")
    print("="*60 + "\n")

    if not findings:
        print("[+] CLEAN: No critical vulnerabilities found matching "
              "criteria.")
        return

    for i, f in enumerate(findings, 1):
        # Color coding for terminal (simple ANSI)
        # Red for High, Yellow for Medium
        color = "\033[91m" if f['impact'] == "High" else "\033[93m"
        reset = "\033[0m"

        print(f"{color}[{f['impact']}] {f['title']}{reset}")
        print(f"Location: {f['location']}")
        print(f"Context: {f['description']}")
        print("-" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Wrapper for Slither to find real bugs."
    )
    parser.add_argument("target", help="The .sol file or directory to scan")
    args = parser.parse_args()
    _cli_target_is_file = Path(args.target).expanduser().is_file()
    safe_cli_target = str(
        sanitize_cli_path(
            args.target,
            must_exist=True,
            expect_file=_cli_target_is_file,
            allowed_suffixes={".sol"} if _cli_target_is_file else None,
        )
    )

    try:
        raw_data = run_slither(safe_cli_target)
        critical_intel = filter_vulnerabilities(raw_data)
        print_report(critical_intel)
    except CounterscarpAnalysisError:
        raise
    except Exception as e:
        logger.error(f"Red team scan failed: {e}")
        raise