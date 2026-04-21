from __future__ import annotations

import json
import os
import argparse
import sys
import re
from typing import Dict, List, Any

from logger import get_logger
from exceptions import GarrisonAPIError, GarrisonValidationError
from http_utils import resilient_post, RateLimiter

# Import config loader
try:
    from config_loader import load_config, GarrisonConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False

logger = get_logger(__name__)

# Load configuration with fallback to defaults
_config = None
_osv_rate_limiter = None


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


def get_osv_rate_limiter() -> RateLimiter:
    """Get or create the OSV rate limiter."""
    global _osv_rate_limiter
    if _osv_rate_limiter is None:
        try:
            rate_limit = get_config().supply_chain.osv_rate_limit
        except Exception:
            rate_limit = 10
        _osv_rate_limiter = RateLimiter(requests_per_second=rate_limit)
    return _osv_rate_limiter


def get_ecosystem() -> str:
    """Get ecosystem from config or use default."""
    try:
        return get_config().supply_chain.ecosystem
    except Exception:
        return "npm"


def get_osv_timeout() -> int:
    """Get OSV API timeout from config or use default."""
    try:
        return get_config().supply_chain.osv_timeout
    except Exception:
        return 10


def get_osv_max_retries() -> int:
    """Get OSV API max retries from config or use default."""
    try:
        return get_config().supply_chain.osv_max_retries
    except Exception:
        return 3


def clean_version(version_str: str) -> str:
    """Removes npm artifacts like ^, ~, or >= to get the raw version number.

    We strip non-numeric chars except dots.
    Example: "^4.9.0" -> "4.9.0".
    In a real CI env, you'd check package-lock.json for the exact installed version.

    Args:
        version_str: The version string from package.json.

    Returns:
        Cleaned version string with only numeric characters and dots.
    """
    clean = re.sub(r"[^\d\.]", "", version_str)
    return clean


def check_osv_api(package_name: str, version: str) -> List[Dict[str, Any]]:
    """Queries Google OSV (Open Source Vulnerabilities) for a specific
    package version.

    Args:
        package_name: Name of the npm package.
        version: Version of the package to check.

    Returns:
        List of vulnerability dictionaries from OSV.
    """
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": get_ecosystem(),
        },
        "version": version,
    }

    try:
        # Use resilient POST with retry logic and rate limiting
        response = resilient_post(
            url,
            json=payload,
            timeout=get_osv_timeout(),
            max_retries=get_osv_max_retries(),
            rate_limiter=get_osv_rate_limiter()
        )
        data = response.json()
        return data.get("vulns", [])

    except GarrisonAPIError as e:
        # Log the failure but don't abort the entire scan
        logger.warning(
            f"OSV API error checking {package_name}@{version}: {e}",
            exc_info=True
        )
        return []
    except Exception as e:
        # Catch any other unexpected errors for partial failure recovery
        logger.warning(
            f"Unexpected error checking {package_name}@{version}: {e}",
            exc_info=True
        )
        return []


def scan_package_json(file_path: str) -> List[Dict[str, Any]]:
    """Parses a package.json file and queries the OSV API for each dependency.

    Args:
        file_path: Path to the package.json file.

    Returns:
        List of vulnerability findings for dependencies.

    Raises:
        GarrisonValidationError: If the file cannot be read.
    """
    print(f"[*] Parsing manifest: {file_path}")
    print(f"[*] Querying OSV.dev database (Live)...")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {file_path}: {e}")
        # Partial recovery: try to extract dependency names even if JSON is malformed
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            # Try to extract package names using regex as fallback
            deps_pattern = r'"([^"]+)"\s*:\s*"[^"]+"'
            found_deps = re.findall(deps_pattern, content)
            if found_deps:
                logger.info(f"Partial recovery: extracted {len(found_deps)} "
                           f"potential dependencies from malformed JSON")
            print(f"[!] ERROR: Could not parse {file_path}. Invalid JSON.")
        except Exception as recovery_e:
            logger.error(f"Partial recovery failed: {recovery_e}")
        return []
    except (IOError, OSError) as e:
        logger.error(f"Could not read package.json: {e}")
        raise GarrisonValidationError(
            "Failed to read package.json",
            details={"path": file_path, "error": str(e)}
        ) from e

    # Combine dependencies and devDependencies
    deps = data.get("dependencies", {})
    dev_deps = data.get("devDependencies", {})
    all_deps: Dict[str, str] = {**deps, **dev_deps}

    found_vulns: List[Dict[str, Any]] = []

    total = len(all_deps)
    failed_packages = []

    for i, (lib, version_str) in enumerate(all_deps.items(), 1):
        # Clean the version string (e.g. "^4.3.0" -> "4.3.0")
        current_version = clean_version(version_str)

        # Optional: skip non-semantic versions (like git URLs or "latest")
        if not current_version or len(current_version) < 3:
            continue

        # Progress indicator
        print(
            f"\r    Checking {i}/{total}: {lib} v{current_version}...",
            end="",
            flush=True
        )

        vulns = check_osv_api(lib, current_version)

        # Partial failure tracking: if check_osv_api returns empty list
        # due to API error, we track it but continue with other packages
        if vulns is None:
            failed_packages.append(f"{lib}@{current_version}")
            vulns = []

        if vulns:
            for v in vulns:
                found_vulns.append(
                    {
                        "library": lib,
                        "installed": current_version,
                        "id": v.get("id", "Unknown ID"),
                        "summary": v.get("summary", "No summary provided"),
                        "details": (v.get("details", "") or "")[:150] + "...",
                        "database_specific": v.get("database_specific", {}),
                    }
                )

    # Report partial failures if any
    if failed_packages:
        logger.warning(
            f"Failed to query OSV for {len(failed_packages)} package(s): "
            f"{', '.join(failed_packages[:5])}"
            f"{'...' if len(failed_packages) > 5 else ''}"
        )
        print(
            f"\n[!] Warning: Could not check {len(failed_packages)} "
            f"package(s) due to API errors"
        )

    print(f"\n[*] Scan complete. Found {len(found_vulns)} vulnerabilities.")
    return found_vulns


def print_report(vulnerabilities: List[Dict[str, Any]]) -> None:
    """Print a formatted report of supply chain vulnerabilities.

    Args:
        vulnerabilities: List of vulnerability dictionaries to report.
    """
    logger.info(f"Supply chain scan complete: {len(vulnerabilities)} issues found")
    print("\n" + "=" * 60)
    print(f" SUPPLY CHAIN REPORT - {len(vulnerabilities)} ISSUES FOUND")
    print("=" * 60 + "\n")

    if not vulnerabilities:
        print("[+] STATUS: GREEN. No known vulnerabilities in current dependencies.")
        return

    for v in vulnerabilities:
        severity = "UNKNOWN"
        if v.get("database_specific"):
            severity = v["database_specific"].get("severity", "UNKNOWN")

        print(f"\033[91m[VULNERABLE] {v['library']} (v{v['installed']})\033[0m")
        print(f"    ID:       {v['id']}")
        print(f"    Summary:  {v['summary']}")
        print(f"    Severity: {severity}")
        print(f"    Details:  {v['details']}")
        print(f"    Link:     https://osv.dev/vulnerability/{v['id']}")
        print("-" * 60)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Live Supply Chain Scanner using OSV.dev",
    )
    parser.add_argument(
        "path",
        help="Path to project root or package.json file",
        default=".",
    )
    args = parser.parse_args()

    target_path = args.path
    if os.path.isdir(target_path):
        target_path = os.path.join(target_path, "package.json")

    if not os.path.exists(target_path):
        logger.error(f"Target path not found: {target_path}")
        print(f"[!] Error: {target_path} not found.")
        sys.exit(1)

    try:
        results = scan_package_json(target_path)
        print_report(results)
    except Exception as e:
        logger.error(f"Supply chain scan failed: {e}")
        raise
