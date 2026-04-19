from __future__ import annotations

import sys
import subprocess
import json
import argparse
from typing import List, Dict, Any

# Import logger and exceptions
try:
    from logger import get_logger
    from exceptions import (
        SentinelAnalysisError,
        SentinelToolNotFoundError,
    )
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    get_logger = None
    SentinelAnalysisError = None
    SentinelToolNotFoundError = None

# Initialize logger
if LOGGER_AVAILABLE and get_logger:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# CONFIGURATION: What defines "Noise" vs "Signal"
# We ignore "Low" and "Informational" by default.
SEVERITY_ALLOWLIST = ["High", "Medium"] 

# IGNORE LIST: Specific check IDs that are often noise in modern contracts
# Example: 'solc-version' is usually just complaining you aren't on the latest nightly build.
IGNORE_CHECKS = [
    "solc-version",
    "naming-convention", 
    "assembly",  # Often used intentionally for optimization
    "redundant-statements"
]

def run_slither(target: str) -> Dict[str, Any]:
    """Runs Slither via subprocess and captures JSON output.

    Args:
        target: Path to the Solidity file or directory to analyze.

    Returns:
        Parsed JSON output from Slither.

    Raises:
        SentinelToolNotFoundError: If Slither is not installed.
        SentinelAnalysisError: If Slither analysis fails or output cannot be parsed.
    """
    print(f"[*] Spawning Slither process for target: {target}...")
    
    cmd = ["slither", target, "--json", "-"]
    
    try:
        # Run slither and capture stdout/stderr
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            check=False # Don't crash on exit code 255 (Slither returns this on finding bugs)
        )
        
        # Slither often mixes logs in stdout, but the JSON should be the last thing or the only thing
        # However, using --json - usually dumps pure JSON to stdout.
        # We need to handle cases where Slither outputs setup logs before the JSON.
        output = result.stdout
        
        # Attempt to find the start of the JSON structure
        json_start = output.find('{')
        if json_start == -1:
            print("[!] CRITICAL: Slither failed to generate JSON. Raw output:")
            print(result.stderr)
            sys.exit(1)
            
        json_data = output[json_start:]
        return json.loads(json_data)

    except FileNotFoundError as e:
        logger.error("Slither command not found")
        raise SentinelToolNotFoundError(
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
            "raw_stdout_preview": (result.stdout[:500] + "...") if result and len(result.stdout) > 500 else (result.stdout if result else "")
        }
        raise SentinelAnalysisError(
            "Could not parse Slither output - tool may have crashed",
            details=error_data
        ) from e
    except subprocess.CalledProcessError as e:
        logger.error(f"Slither process failed: {e}")
        raise SentinelAnalysisError(
            "Slither analysis failed",
            details={"returncode": e.returncode, "stderr": e.stderr}
        ) from e
    except PermissionError as e:
        logger.error(f"Permission denied running Slither: {e}")
        raise SentinelAnalysisError(
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
        logger.debug("Slither output has no 'detectors' key (may have no findings)")
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
        if impact not in SEVERITY_ALLOWLIST:
            continue
            
        # 2. Filter by Ignore List (Noise)
        if check_id in IGNORE_CHECKS:
            continue
            
        # 3. Construct clean finding object
        clean_finding = {
            "title": finding.get("check", "Unknown Issue"),
            "impact": impact,
            "description": finding.get("description", "No description provided"),
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
    return filename

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
        print("[+] CLEAN: No critical vulnerabilities found matching criteria.")
        return

    for i, f in enumerate(findings, 1):
        # Color coding for terminal (simple ANSI)
        color = "\033[91m" if f['impact'] == "High" else "\033[93m" # Red for High, Yellow for Medium
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
    except SentinelAnalysisError:
        raise
    except Exception as e:
        logger.error(f"Red team scan failed: {e}")
        raise