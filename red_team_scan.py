from __future__ import annotations

import logging
import os
import subprocess
import json
import shutil
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, cast

# Import logger and exceptions
try:
    from logger import get_logger, append_stderr_log
    from exceptions import (
        CounterscarpAnalysisError,
        CounterscarpToolNotFoundError,
    )
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)
    def append_stderr_log(stderr_text: str, tool_name: str, stderr_log_path: str) -> None:  # noqa: E501
        pass
    CounterscarpAnalysisError = Exception  # type: ignore[assignment,misc]
    CounterscarpToolNotFoundError = Exception  # type: ignore[assignment,misc]

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


def _validate_path_containment(file_path: str, project_root: str) -> Path:
    """Ensure file_path is contained within project_root to prevent path traversal.

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


def _parse_foundry_out_dir(project_root: str) -> str:
    """Parse the `out` directory from foundry.toml.

    Attempts to read ``out`` from ``[profile.default]`` (or bare ``out =``)
    using tomllib (Python 3.11+) or tomli as fallback, then falls back to
    a simple regex search.  Returns ``'out'`` if parsing fails or the key
    is not present.

    Args:
        project_root: Path to the Foundry project root.

    Returns:
        The configured output directory name (e.g. ``'foundry-out'``).
    """
    toml_path = Path(project_root) / "foundry.toml"
    if not toml_path.exists():
        return "out"

    # Try structured TOML parsing first
    try:
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            import tomli as tomllib  # type: ignore[no-redef]
        data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        # foundry.toml uses [profile.default] as its primary section
        out_val = (
            data.get("profile", {}).get("default", {}).get("out")
            or data.get("out")  # bare top-level fallback
        )
        if out_val and isinstance(out_val, str):
            logger.debug(
                f"foundry.toml out directory (TOML parser): {out_val!r}"
            )
            return out_val
    except Exception as exc:
        logger.debug(f"TOML parser unavailable or failed ({exc}); using regex")

    # Regex fallback — handles files that are syntactically valid but
    # whose TOML library is not installed.
    import re
    try:
        content = toml_path.read_text(encoding="utf-8")
        match = re.search(r'^\s*out\s*=\s*["\']([^"\']+)["\']', content, re.MULTILINE)
        if match:
            out_val = match.group(1)
            logger.debug(
                f"foundry.toml out directory (regex): {out_val!r}"
            )
            return out_val
    except OSError as exc:
        logger.warning(f"Could not read foundry.toml for out-dir: {exc}")

    return "out"


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
                append_stderr_log(result.stderr, "slither-per-file", stderr_log)
            output = result.stdout
            json_start = output.find("{")
            if json_start == -1:
                fail_count += 1
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
    print(f"[*] Spawning Slither process for target: {target}...")

    # Resolve Slither binary from venv
    slither_bin = _resolve_slither_bin()

    # Detect Foundry/Hardhat project root
    project_root = find_project_root(target)
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
        cwd = str(
            target_path.parent if target_path.is_file()
            else target_path
        )
        effective_target = target
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
            # Pass the custom out directory so Slither can find build-info
            foundry_out = _parse_foundry_out_dir(project_root)
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

    # Read remappings.txt and pass via --solc-remaps
    # whether forge is available or not — Slither needs
    # them for solc-based compilation too.
    if is_foundry and project_root:
        remappings_file = (
            Path(project_root) / "remappings.txt"
        )
        if remappings_file.exists():
            try:
                remaps_content = remappings_file.read_text(
                    encoding="utf-8"
                ).strip()
                if remaps_content:
                    # Slither expects remappings as a
                    # single comma-separated string
                    remaps_joined = ",".join(
                        line.strip()
                        for line in remaps_content.splitlines()
                        if line.strip()
                        and not line.strip().startswith("#")
                    )
                    if remaps_joined:
                        cmd.extend(["--solc-remaps", remaps_joined])
                        print(
                            f"[*] Applied remappings:"
                            f" {remaps_joined}"
                        )
            except OSError as e:
                logger.warning(
                    f"Could not read remappings.txt: {e}"
                )

    # Pass exclusion patterns to Slither via --filter-paths (comma-separated regex)
    if exclude_paths:
        # Slither's --filter-paths accepts a comma-separated list of path substrings /
        # regex patterns.  Strip trailing glob wildcards so they work as substring
        # filters (e.g. "node_modules/**" → "node_modules").
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
            print("[*] Running 'forge build --build-info' to generate build artifacts...")
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
                    print("[*] forge build succeeded — build artifacts ready for Slither")
                else:
                    logger.warning(
                        "forge build --build-info exited with code %d; "
                        "Slither may fall back to solc. stderr: %s",
                        forge_result.returncode,
                        forge_result.stderr[:500] if forge_result.stderr else "",
                    )
                    print(
                        f"[!] forge build failed (exit {forge_result.returncode});"
                        " continuing with Slither anyway"
                    )
            except subprocess.TimeoutExpired:
                logger.warning("forge build timed out; continuing with Slither anyway")
                print("[!] forge build timed out; proceeding with Slither")
            except OSError as exc:
                logger.warning("Could not run forge build: %s", exc)
                print(f"[!] Could not run forge build ({exc}); proceeding with Slither")

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
            append_stderr_log(result.stderr, "slither", stderr_log)

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
                )
                if fallback is not None:
                    return fallback
            print("[!] CRITICAL: Slither failed to generate JSON. Raw output:")
            print(result.stderr)
            raise CounterscarpAnalysisError(
                "Slither failed to produce JSON output",
                details={
                    "tool": "slither",
                    "stderr": result.stderr,
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
                    target, project_root or target, slither_bin, cmd, stderr_log
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
    return cast(str, filename)


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

    try:
        raw_data = run_slither(args.target)
        critical_intel = filter_vulnerabilities(raw_data)
        print_report(critical_intel)
    except CounterscarpAnalysisError:
        raise
    except Exception as e:
        logger.error(f"Red team scan failed: {e}")
        raise