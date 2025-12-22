import json
import os
import argparse
import sys
import re
import requests
from typing import Dict, List, Any

# CONFIGURATION
# We explicitly check the 'npm' ecosystem because that's how most
# Solidity-related libraries (OpenZeppelin, Hardhat, etc.) are distributed.
ECOSYSTEM = "npm"


def clean_version(version_str: str) -> str:
    """Removes npm artifacts like ^, ~, or >= to get the raw version number."""
    # We strip non-numeric chars except dots.
    # Example: "^4.9.0" -> "4.9.0".
    # In a real CI env, you'd check package-lock.json for the exact installed version.
    clean = re.sub(r"[^\d\.]", "", version_str)
    return clean


def check_osv_api(package_name: str, version: str) -> List[Dict]:
    """Queries Google OSV (Open Source Vulnerabilities) for a specific package version."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": ECOSYSTEM,
        },
        "version": version,
    }

    try:
        # Standard timeout to prevent hanging if API is down
        response = requests.post(url, json=payload, timeout=5)

        if response.status_code != 200:
            # Silently fail on non-200 to keep the report clean
            return []

        data = response.json()
        return data.get("vulns", [])

    except requests.exceptions.RequestException:
        print(f"[!] Warning: Network error checking {package_name}. Skipping.")
        return []


def scan_package_json(file_path: str) -> List[Dict[str, Any]]:
    """Parses a package.json file and queries the OSV API for each dependency."""
    print(f"[*] Parsing manifest: {file_path}")
    print(f"[*] Querying OSV.dev database (Live)...")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        print(f"[!] ERROR: Could not parse {file_path}. Invalid JSON.")
        return []

    # Combine dependencies and devDependencies
    deps = data.get("dependencies", {})
    dev_deps = data.get("devDependencies", {})
    all_deps: Dict[str, str] = {**deps, **dev_deps}

    found_vulns: List[Dict[str, Any]] = []

    total = len(all_deps)
    for i, (lib, version_str) in enumerate(all_deps.items(), 1):
        # Clean the version string (e.g. "^4.3.0" -> "4.3.0")
        current_version = clean_version(version_str)

        # Optional: skip non-semantic versions (like git URLs or "latest")
        if not current_version or len(current_version) < 3:
            continue

        # Progress indicator
        print(f"\r    Checking {i}/{total}: {lib} v{current_version}...", end="", flush=True)

        vulns = check_osv_api(lib, current_version)

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

    print(f"\n[*] Scan complete. Found {len(found_vulns)} vulnerabilities.")
    return found_vulns


def print_report(vulnerabilities: List[Dict[str, Any]]) -> None:
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
        print(f"[!] Error: {target_path} not found.")
        sys.exit(1)

    results = scan_package_json(target_path)
    print_report(results)
