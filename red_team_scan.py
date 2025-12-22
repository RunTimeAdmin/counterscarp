import sys
import subprocess
import json
import argparse
from typing import List, Dict, Any

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
    """Runs Slither via subprocess and captures JSON output."""
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

    except FileNotFoundError:
        print("[!] ERROR: 'slither' command not found. Install it with: pip3 install slither-analyzer")
        sys.exit(1)
    except json.JSONDecodeError:
        print("[!] ERROR: Could not parse Slither output. It might have crashed.")
        print("Raw stderr:", result.stderr)
        sys.exit(1)

def filter_vulnerabilities(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Filters the raw Slither data for things that actually matter."""
    
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

def parse_location(elements: List[Dict]) -> str:
    """Extracts the first useful file/line number from the elements list."""
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

def print_report(findings: List[Dict[str, Any]]):
    """Prints a Red Team style report."""
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
    parser = argparse.ArgumentParser(description="Wrapper for Slither to find real bugs.")
    parser.add_argument("target", help="The .sol file or directory to scan")
    args = parser.parse_args()
    
    raw_data = run_slither(args.target)
    critical_intel = filter_vulnerabilities(raw_data)
    print_report(critical_intel)