#!/usr/bin/env python3
"""
Solana/Anchor Static Analyzer
Full static analysis for Rust-based Solana programs
Complements solana_intel.py (which only does threat intel)
"""

import subprocess
import re
import os
import sys
import argparse
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass


@dataclass
class SolanaFinding:
    """Represents a security finding in Solana/Anchor code."""
    severity: str
    category: str
    title: str
    description: str
    file: str
    line_no: int
    code_snippet: str
    fix_suggestion: str


# Anchor-specific vulnerability patterns
ANCHOR_PATTERNS = [
    {
        "id": "MISSING_SIGNER_CHECK",
        "severity": "CRITICAL",
        "pattern": re.compile(r'#\[account\(.*\)\](?!.*signer).*\bpub\s+(\w+):\s*AccountInfo'),
        "description": "Account without signer validation - anyone can impersonate",
        "fix": "Add 'signer' constraint: #[account(signer)] pub authority: AccountInfo"
    },
    {
        "id": "MISSING_OWNER_CHECK",
        "severity": "CRITICAL",
        "pattern": re.compile(r'let\s+\w+\s*=\s*\w+\.to_account_info\(\)(?!.*owner)'),
        "description": "Account deserialization without owner check",
        "fix": "Verify account.owner == expected_program_id before deserializing"
    },
    {
        "id": "UNCHECKED_ARITHMETIC",
        "severity": "HIGH",
        "pattern": re.compile(r'(\+|\-|\*|\/)\s*(?!checked_)'),
        "description": "Unchecked arithmetic operation (overflow/underflow risk)",
        "fix": "Use checked_add(), checked_sub(), checked_mul(), checked_div()"
    },
    {
        "id": "UNVALIDATED_ACCOUNT_DATA",
        "severity": "HIGH",
        "pattern": re.compile(r'Account::try_from\(&.*\)(?!.*\.map_err)'),
        "description": "Account deserialization without error handling",
        "fix": "Use .map_err() or ? operator to handle deserialization errors"
    },
    {
        "id": "MISSING_RENT_EXEMPTION",
        "severity": "MEDIUM",
        "pattern": re.compile(r'create_account\((?!.*rent)'),
        "description": "Account creation without rent exemption check",
        "fix": "Ensure account is rent-exempt: rent.minimum_balance(space)"
    },
    {
        "id": "UNSAFE_INVOKE_SIGNED",
        "severity": "HIGH",
        "pattern": re.compile(r'invoke_signed\(.*\bseeds\b.*\)'),
        "description": "invoke_signed with user-controlled seeds (PDA exploitation)",
        "fix": "Ensure seeds are derived from program-controlled data only"
    },
    {
        "id": "MISSING_DISCRIMINATOR_CHECK",
        "severity": "CRITICAL",
        "pattern": re.compile(r'#\[account\](?!.*discriminator)'),
        "description": "Account without discriminator check (type confusion)",
        "fix": "Add discriminator validation in account struct"
    },
    {
        "id": "UNCLOSED_ACCOUNT",
        "severity": "MEDIUM",
        "pattern": re.compile(r'close\s*=\s*\w+(?!.*realloc)'),
        "description": "Account close without realloc (resurrection attack)",
        "fix": "Use realloc(0) before closing to prevent resurrection"
    }
]


def check_cargo_audit() -> bool:
    """Check if cargo-audit is installed."""
    try:
        result = subprocess.run(
            ["cargo", "audit", "--version"],
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def run_cargo_audit(project_root: str) -> Dict[str, Any]:
    """
    Run cargo-audit for dependency vulnerabilities.
    """
    if not check_cargo_audit():
        print("[!] cargo-audit not installed")
        print("    Install: cargo install cargo-audit")
        return {"error": "cargo-audit not found", "vulnerabilities": []}
    
    print("[*] Running cargo-audit...")
    
    try:
        result = subprocess.run(
            ["cargo", "audit", "--json"],
            cwd=project_root,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode == 0:
            import json
            return json.loads(result.stdout)
        else:
            return {"vulnerabilities": [], "warnings": result.stderr}
    
    except Exception as e:
        return {"error": str(e), "vulnerabilities": []}


def scan_anchor_patterns(file_path: str) -> List[SolanaFinding]:
    """
    Scan Rust/Anchor file for vulnerability patterns.
    """
    findings = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        content = ''.join(lines)
    
    for pattern_def in ANCHOR_PATTERNS:
        for match in pattern_def["pattern"].finditer(content):
            # Find line number
            line_no = content[:match.start()].count('\n') + 1
            
            # Get code snippet (3 lines context)
            start_line = max(0, line_no - 2)
            end_line = min(len(lines), line_no + 2)
            snippet = ''.join(lines[start_line:end_line])
            
            findings.append(SolanaFinding(
                severity=pattern_def["severity"],
                category=pattern_def["id"],
                title=pattern_def["id"].replace("_", " ").title(),
                description=pattern_def["description"],
                file=file_path,
                line_no=line_no,
                code_snippet=snippet.strip(),
                fix_suggestion=pattern_def["fix"]
            ))
    
    return findings


def detect_anchor_accounts(file_path: str) -> List[Dict[str, str]]:
    """
    Parse Anchor #[account] structs for security analysis.
    """
    accounts = []
    
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Find #[account] structs
    account_pattern = re.compile(
        r'#\[account\((.*?)\)\]\s*pub\s+struct\s+(\w+)',
        re.DOTALL
    )
    
    for match in account_pattern.finditer(content):
        constraints = match.group(1)
        struct_name = match.group(2)
        
        # Check for missing critical constraints
        has_signer = 'signer' in constraints
        has_mut = 'mut' in constraints
        has_owner = 'owner' in constraints or 'constraint' in constraints
        
        accounts.append({
            "name": struct_name,
            "has_signer": has_signer,
            "has_mut": has_mut,
            "has_owner": has_owner,
            "constraints": constraints
        })
    
    return accounts


def analyze_solana_program(project_root: str) -> Dict[str, Any]:
    """
    Full static analysis of Solana/Anchor program.
    
    Returns:
        Dict with:
        - dependency_vulns: From cargo-audit
        - pattern_findings: From Anchor pattern matching
        - account_analysis: Account constraint validation
        - summary: Severity counts
    """
    print("\n" + "="*60)
    print(" SOLANA STATIC ANALYZER")
    print("="*60)
    print(f"\n[*] Analyzing Solana program: {project_root}")
    
    results = {
        "dependency_vulns": [],
        "pattern_findings": [],
        "account_analysis": [],
        "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    }
    
    # 1. Dependency vulnerabilities (cargo-audit)
    print("\n[*] Checking dependencies for known vulnerabilities...")
    audit_results = run_cargo_audit(project_root)
    
    if "vulnerabilities" in audit_results:
        results["dependency_vulns"] = audit_results["vulnerabilities"]
        print(f"    Found {len(audit_results['vulnerabilities'])} dependency vulnerabilities")
    
    # 2. Pattern-based scanning
    print("\n[*] Scanning for Anchor/Solana vulnerability patterns...")
    
    # Find all .rs files
    rust_files = []
    for root, dirs, files in os.walk(project_root):
        # Skip target directory
        if 'target' in root.split(os.sep):
            continue
        
        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))
    
    print(f"    Found {len(rust_files)} Rust files")
    
    # Scan each file
    for rs_file in rust_files:
        findings = scan_anchor_patterns(rs_file)
        results["pattern_findings"].extend(findings)
        
        # Account analysis
        accounts = detect_anchor_accounts(rs_file)
        results["account_analysis"].extend(accounts)
    
    # 3. Summarize by severity
    for finding in results["pattern_findings"]:
        results["summary"][finding.severity] += 1
    
    print(f"\n[*] Pattern analysis complete:")
    print(f"    CRITICAL: {results['summary']['CRITICAL']}")
    print(f"    HIGH:     {results['summary']['HIGH']}")
    print(f"    MEDIUM:   {results['summary']['MEDIUM']}")
    print(f"    LOW:      {results['summary']['LOW']}")
    
    return results


def print_report(results: Dict[str, Any]) -> None:
    """Pretty-print Solana analysis report."""
    print("\n" + "="*60)
    print(" SOLANA SECURITY ANALYSIS REPORT")
    print("="*60)
    
    summary = results["summary"]
    total = sum(summary.values())
    
    print(f"\n[*] Total findings: {total}")
    print(f"    CRITICAL: {summary['CRITICAL']}")
    print(f"    HIGH:     {summary['HIGH']}")
    print(f"    MEDIUM:   {summary['MEDIUM']}")
    print(f"    LOW:      {summary['LOW']}")
    
    # Dependency vulnerabilities
    dep_vulns = results.get("dependency_vulns", [])
    if dep_vulns:
        print("\n" + "-"*60)
        print("DEPENDENCY VULNERABILITIES:")
        print("-"*60)
        
        for vuln in dep_vulns:
            advisory = vuln.get("advisory", {})
            print(f"\n[{advisory.get('severity', 'UNKNOWN')}] {advisory.get('title', 'Unknown')}")
            print(f"  Package: {vuln.get('package', {}).get('name', 'unknown')}")
            print(f"  ID: {advisory.get('id', 'N/A')}")
            print(f"  URL: {advisory.get('url', 'N/A')}")
    
    # Pattern findings
    pattern_findings = results.get("pattern_findings", [])
    if pattern_findings:
        print("\n" + "-"*60)
        print("VULNERABILITY PATTERNS:")
        print("-"*60)
        
        # Group by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            severity_findings = [f for f in pattern_findings if f.severity == severity]
            
            if severity_findings:
                print(f"\n[{severity}]")
                
                for i, finding in enumerate(severity_findings[:10], 1):
                    print(f"\n  {i}. {finding.title}")
                    print(f"     File: {finding.file}:{finding.line_no}")
                    print(f"     {finding.description}")
                    print(f"     Fix: {finding.fix_suggestion}")
                
                if len(severity_findings) > 10:
                    print(f"\n  ... ({len(severity_findings) - 10} more {severity} findings)")
    
    # Account analysis summary
    accounts = results.get("account_analysis", [])
    if accounts:
        risky_accounts = [a for a in accounts if not a["has_signer"] or not a["has_owner"]]
        
        if risky_accounts:
            print("\n" + "-"*60)
            print("RISKY ACCOUNT CONFIGURATIONS:")
            print("-"*60)
            
            for acc in risky_accounts[:5]:
                print(f"\n  Struct: {acc['name']}")
                if not acc["has_signer"]:
                    print("    ⚠️  Missing signer constraint")
                if not acc["has_owner"]:
                    print("    ⚠️  Missing owner validation")
                print(f"    Constraints: {acc['constraints']}")


def main():
    parser = argparse.ArgumentParser(
        description="🔍 Solana/Anchor Static Analyzer - Security analysis for Rust programs"
    )
    parser.add_argument(
        "project_root",
        help="Path to Solana/Anchor project root (contains Cargo.toml)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output JSON format"
    )
    
    args = parser.parse_args()
    
    # Validate project root
    if not os.path.exists(os.path.join(args.project_root, "Cargo.toml")):
        print(f"[!] Not a valid Rust project: {args.project_root}")
        print("    Missing Cargo.toml")
        sys.exit(1)
    
    results = analyze_solana_program(args.project_root)
    
    if args.json:
        import json
        # Convert findings to dicts
        json_findings = [
            {
                "severity": f.severity,
                "category": f.category,
                "title": f.title,
                "description": f.description,
                "file": f.file,
                "line_no": f.line_no,
                "fix": f.fix_suggestion
            }
            for f in results["pattern_findings"]
        ]
        print(json.dumps({
            "pattern_findings": json_findings,
            "dependency_vulns": results["dependency_vulns"],
            "summary": results["summary"]
        }, indent=2))
    else:
        print_report(results)
    
    # Exit with error if critical/high issues
    critical_high = results["summary"]["CRITICAL"] + results["summary"]["HIGH"]
    sys.exit(1 if critical_high > 0 else 0)


if __name__ == "__main__":
    main()
