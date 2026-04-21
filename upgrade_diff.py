#!/usr/bin/env python3
"""
Upgrade Diff Analyzer - Contract Upgrade Security Checker
Detects dangerous changes between old and new contract versions
Critical for UUPS/Transparent proxy upgrades
"""

from __future__ import annotations

import re
import argparse
import sys
from typing import Dict, List, Any, Tuple, Optional
from dataclasses import dataclass
from pathlib import Path

# Import logger and exceptions
try:
    from logger import get_logger
    from exceptions import GarrisonValidationError
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    get_logger = None
    GarrisonValidationError = None

# Initialize logger
if LOGGER_AVAILABLE and get_logger:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)


@dataclass
class StorageVariable:
    """Represents a storage variable in a contract.

    Attributes:
        name: Variable name.
        type: Solidity type of the variable.
        slot: Storage slot index.
        line_no: Line number where declared.
    """
    name: str
    type: str
    slot: int
    line_no: int


@dataclass
class Function:
    """Represents a function in a contract.

    Attributes:
        name: Function name.
        visibility: Function visibility (public, external, etc.).
        mutability: State mutability (pure, view, payable).
        modifiers: List of function modifiers.
        is_payable: Whether the function is payable.
        line_no: Line number where declared.
        signature: Full function signature.
    """
    name: str
    visibility: str
    mutability: str
    modifiers: List[str]
    is_payable: bool
    line_no: int
    signature: str


@dataclass
class UpgradeIssue:
    """Represents a safety issue found during upgrade analysis.

    Attributes:
        severity: Issue severity (CRITICAL, HIGH, MEDIUM, LOW).
        category: Issue category (e.g., STORAGE_COLLISION).
        title: Short issue title.
        description: Detailed issue description.
        old_value: Value in the old contract.
        new_value: Value in the new contract.
        line_no: Optional line number where issue occurs.
    """
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str
    title: str
    description: str
    old_value: str
    new_value: str
    line_no: Optional[int] = None


def parse_storage_layout(contract_path: str) -> List[StorageVariable]:
    """Parse storage variables from Solidity contract.

    Storage layout rules:
    - Variables declared at contract level
    - Order matters (determines slot)
    - Mappings/dynamic arrays take full slot

    Args:
        contract_path: Path to the Solidity contract.

    Returns:
        List of storage variable definitions.
    """
    storage_vars = []
    current_slot = 0
    
    with open(contract_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
    
    in_contract = False
    in_function = False
    brace_depth = 0
    
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        
        # Track contract scope
        if re.match(r'contract\s+\w+', stripped):
            in_contract = True
            continue
        
        if in_contract:
            # Track brace depth to know when we're inside functions
            brace_depth += stripped.count('{') - stripped.count('}')
            
            # Detect function start
            if 'function ' in stripped:
                in_function = True
            
            # Only parse storage variables (contract-level, outside functions)
            if not in_function and brace_depth == 1:
                # Match storage variable declarations
                # Format: type visibility name;
                var_match = re.match(
                    r'(uint\d*|int\d*|address|bool|bytes\d*|string|mapping\(.+\)|.+\[\])\s+(public|private|internal)?\s*(\w+)\s*;',
                    stripped
                )
                
                if var_match:
                    var_type = var_match.group(1)
                    var_name = var_match.group(3)
                    
                    storage_vars.append(StorageVariable(
                        name=var_name,
                        type=var_type,
                        slot=current_slot,
                        line_no=i
                    ))
                    current_slot += 1
            
            # Function ends when braces balance
            if in_function and brace_depth == 1:
                in_function = False
    
    return storage_vars


def validate_storage_layout(layout: List[StorageVariable]) -> List[str]:
    """Validate parsed storage layout for schema compliance and edge cases.

    Checks:
    - Each variable has required fields (name, type, slot number)
    - No empty layouts (warning)
    - No duplicate slot assignments
    - Valid type names

    Args:
        layout: List of StorageVariable objects to validate.

    Returns:
        List of validation error/warning strings.
    """
    errors: List[str] = []

    # Check for empty layout
    if not layout:
        errors.append(
            "Storage layout is empty - contract may have no state variables"
        )
        return errors

    # Track seen slots and names for duplicates
    seen_slots: Dict[int, str] = {}
    seen_names: Dict[str, int] = {}

    # Valid Solidity type patterns
    valid_type_patterns = [
        r'^(uint|int)(\d+)?$',  # uint256, int8, etc.
        r'^address$',  # address
        r'^bool$',  # bool
        r'^bytes(\d+)?$',  # bytes32, bytes, etc.
        r'^string$',  # string
        r'^mapping\(.+\)$',  # mapping(key => value)
        r'^.+\[\]$',  # dynamic array
        r'^.+\[\d+\]$',  # fixed-size array
    ]

    for i, var in enumerate(layout):
        # Check required fields
        if not var.name:
            errors.append(f"Storage variable at index {i} has no name")
            continue

        if not var.type:
            errors.append(f"Storage variable '{var.name}' has no type")
            continue

        if var.slot is None:
            errors.append(f"Storage variable '{var.name}' has no slot number")
            continue

        # Check for duplicate slot assignments
        if var.slot in seen_slots:
            errors.append(
                f"Duplicate slot assignment: slot {var.slot} assigned to "
                f"'{var.name}' and '{seen_slots[var.slot]}'"
            )
        else:
            seen_slots[var.slot] = var.name

        # Check for duplicate variable names
        if var.name in seen_names:
            errors.append(
                f"Duplicate variable name: '{var.name}' at slots "
                f"{seen_names[var.name]} and {var.slot}"
            )
        else:
            seen_names[var.name] = var.slot

        # Validate type name
        type_valid = any(
            re.match(pattern, var.type) for pattern in valid_type_patterns
        )
        if not type_valid:
            errors.append(
                f"Invalid type name for '{var.name}': '{var.type}'"
            )

        # Check for negative slot (shouldn't happen but be safe)
        if var.slot < 0:
            errors.append(
                f"Negative slot number for '{var.name}': {var.slot}"
            )

    return errors


def parse_functions(contract_path: str) -> List[Function]:
    """Extract all functions with their visibility and modifiers.

    Args:
        contract_path: Path to the Solidity contract.

    Returns:
        List of function definitions.
    """
    functions = []
    
    with open(contract_path, 'r', encoding='utf-8') as f:
        content = f.read()
        lines = content.split('\n')
    
    # Find all function declarations
    function_pattern = re.compile(
        r'function\s+(\w+)\s*\([^)]*\)\s*(public|external|internal|private)?\s*(view|pure|payable)?\s*(.*?)\s*(?:returns|{)',
        re.MULTILINE
    )
    
    for match in function_pattern.finditer(content):
        func_name = match.group(1)
        visibility = match.group(2) or 'public'  # Default visibility
        mutability = match.group(3) or 'nonpayable'
        modifiers_str = match.group(4) or ''
        
        # Extract modifiers (onlyOwner, nonReentrant, etc.)
        modifiers = re.findall(r'\b(\w+)\b', modifiers_str)
        modifiers = [m for m in modifiers if m not in ['returns', 'return', 'memory', 'calldata', 'storage']]
        
        # Find line number
        line_no = content[:match.start()].count('\n') + 1
        
        functions.append(Function(
            name=func_name,
            visibility=visibility,
            mutability=mutability,
            modifiers=modifiers,
            is_payable='payable' in mutability,
            line_no=line_no,
            signature=match.group(0)
        ))
    
    return functions


def compare_storage_layouts(
    old_vars: List[StorageVariable],
    new_vars: List[StorageVariable]
) -> List[UpgradeIssue]:
    """Detect storage layout collisions between old and new contracts.

    CRITICAL issues:
    - Reordered variables (slot mismatch)
    - Removed variables (data loss)
    - Type changes in same slot (corruption)

    Args:
        old_vars: Storage variables from the old contract.
        new_vars: Storage variables from the new contract.

    Returns:
        List of upgrade issues found.
    """
    issues = []
    
    # Build slot maps
    old_slots = {var.slot: var for var in old_vars}
    new_slots = {var.slot: var for var in new_vars}
    
    # Check for slot collisions
    for slot, old_var in old_slots.items():
        if slot in new_slots:
            new_var = new_slots[slot]
            
            # Same slot, different name = CRITICAL (variable replaced)
            if old_var.name != new_var.name:
                issues.append(UpgradeIssue(
                    severity="CRITICAL",
                    category="STORAGE_COLLISION",
                    title=f"Storage slot {slot} reassigned",
                    description=f"Variable '{old_var.name}' replaced with '{new_var.name}' in slot {slot}. Existing data will be misinterpreted!",
                    old_value=f"{old_var.type} {old_var.name}",
                    new_value=f"{new_var.type} {new_var.name}",
                    line_no=new_var.line_no
                ))
            
            # Same slot, same name, different type = CRITICAL (type corruption)
            elif old_var.type != new_var.type:
                issues.append(UpgradeIssue(
                    severity="CRITICAL",
                    category="TYPE_CHANGE",
                    title=f"Type changed for '{old_var.name}'",
                    description=f"Variable '{old_var.name}' changed from {old_var.type} to {new_var.type}. Data corruption guaranteed!",
                    old_value=old_var.type,
                    new_value=new_var.type,
                    line_no=new_var.line_no
                ))
    
    # Check for removed storage variables (data loss)
    old_names = {var.name for var in old_vars}
    new_names = {var.name for var in new_vars}
    removed_vars = old_names - new_names
    
    for var_name in removed_vars:
        old_var = next(v for v in old_vars if v.name == var_name)
        issues.append(UpgradeIssue(
            severity="HIGH",
            category="STORAGE_REMOVED",
            title=f"Storage variable '{var_name}' removed",
            description=f"Variable '{var_name}' existed in old contract but not in new. Data will be lost!",
            old_value=f"{old_var.type} {old_var.name}",
            new_value="(removed)"
        ))
    
    # Check for new variables inserted in middle (slot shift)
    if len(new_vars) > len(old_vars):
        for i, new_var in enumerate(new_vars):
            if i < len(old_vars):
                old_var = old_vars[i]
                if new_var.name != old_var.name:
                    issues.append(UpgradeIssue(
                        severity="CRITICAL",
                        category="SLOT_SHIFT",
                        title=f"New variable inserted at position {i}",
                        description=f"Variable '{new_var.name}' inserted before '{old_var.name}', shifting all subsequent storage slots!",
                        old_value=f"Position {i}: {old_var.name}",
                        new_value=f"Position {i}: {new_var.name}",
                        line_no=new_var.line_no
                    ))
                    break  # One detection is enough
    
    return issues


def compare_access_control(
    old_funcs: List[Function],
    new_funcs: List[Function]
) -> List[UpgradeIssue]:
    """Detect removed or weakened access controls.

    CRITICAL issues:
    - onlyOwner removed (privilege escalation)
    - external -> public (unintended exposure)
    - Removed nonReentrant (reentrancy risk)

    Args:
        old_funcs: Functions from the old contract.
        new_funcs: Functions from the new contract.

    Returns:
        List of upgrade issues found.
    """
    issues = []
    
    # Build function maps by name
    old_func_map = {f.name: f for f in old_funcs}
    new_func_map = {f.name: f for f in new_funcs}
    
    for func_name in old_func_map:
        if func_name in new_func_map:
            old_func = old_func_map[func_name]
            new_func = new_func_map[func_name]
            
            # Check for removed modifiers
            old_mods = set(old_func.modifiers)
            new_mods = set(new_func.modifiers)
            removed_mods = old_mods - new_mods
            
            # CRITICAL: Removed auth modifiers
            auth_mods = {'onlyOwner', 'onlyRole', 'onlyAdmin', 'auth', 'authorized'}
            removed_auth = removed_mods & auth_mods
            
            if removed_auth:
                issues.append(UpgradeIssue(
                    severity="CRITICAL",
                    category="AUTH_REMOVED",
                    title=f"Authorization removed from {func_name}()",
                    description=f"Function '{func_name}' had modifier {removed_auth} which is now removed. Anyone can call it!",
                    old_value=f"{func_name} with {old_func.modifiers}",
                    new_value=f"{func_name} with {new_func.modifiers}",
                    line_no=new_func.line_no
                ))
            
            # HIGH: Removed reentrancy protection
            if 'nonReentrant' in removed_mods:
                issues.append(UpgradeIssue(
                    severity="HIGH",
                    category="REENTRANCY_RISK",
                    title=f"nonReentrant removed from {func_name}()",
                    description=f"Function '{func_name}' no longer protected against reentrancy attacks!",
                    old_value="nonReentrant",
                    new_value="(removed)",
                    line_no=new_func.line_no
                ))
            
            # MEDIUM: Visibility changed (internal → public)
            if old_func.visibility in ['internal', 'private'] and new_func.visibility in ['public', 'external']:
                issues.append(UpgradeIssue(
                    severity="MEDIUM",
                    category="VISIBILITY_WEAKENED",
                    title=f"Visibility widened for {func_name}()",
                    description=f"Function '{func_name}' changed from {old_func.visibility} to {new_func.visibility}. New attack surface!",
                    old_value=old_func.visibility,
                    new_value=new_func.visibility,
                    line_no=new_func.line_no
                ))
    
    return issues


def detect_new_external_calls(old_path: str, new_path: str) -> List[UpgradeIssue]:
    """Detect new external calls in upgraded contract (increased attack surface).

    Args:
        old_path: Path to the old contract.
        new_path: Path to the new contract.

    Returns:
        List of upgrade issues for new external calls.
    """
    issues = []
    
    with open(old_path, 'r') as f:
        old_content = f.read()
    
    with open(new_path, 'r') as f:
        new_content = f.read()
    
    # Find external calls (address.call, IERC20.transfer, etc.)
    call_pattern = re.compile(r'(\w+)\.(call|delegatecall|staticcall|transfer|transferFrom|approve)')
    
    old_calls = set(call_pattern.findall(old_content))
    new_calls = set(call_pattern.findall(new_content))
    
    added_calls = new_calls - old_calls
    
    if added_calls:
        for target, method in added_calls:
            issues.append(UpgradeIssue(
                severity="MEDIUM",
                category="NEW_EXTERNAL_CALL",
                title=f"New external call: {target}.{method}()",
                description=f"Upgrade introduces new external interaction with {target}.{method}(). Review for reentrancy and trust assumptions.",
                old_value="(not present)",
                new_value=f"{target}.{method}()"
            ))
    
    return issues


def analyze_upgrade(old_contract: str, new_contract: str) -> Dict[str, Any]:
    """Main upgrade analysis function.

    Args:
        old_contract: Path to the old contract version.
        new_contract: Path to the new contract version.

    Returns:
        Dict with issues, summary counts, and safety status.
    """
    print("\n" + "="*60)
    print(" UPGRADE DIFF ANALYZER")
    print("="*60)
    print(f"\n[*] Analyzing upgrade:")
    print(f"    Old: {old_contract}")
    print(f"    New: {new_contract}")
    
    all_issues = []
    
    # 1. Storage layout comparison
    print("\n[*] Checking storage layout...")
    old_storage = parse_storage_layout(old_contract)
    new_storage = parse_storage_layout(new_contract)
    storage_issues = compare_storage_layouts(old_storage, new_storage)
    all_issues.extend(storage_issues)
    
    # 2. Access control comparison
    print("[*] Checking access control...")
    old_functions = parse_functions(old_contract)
    new_functions = parse_functions(new_contract)
    auth_issues = compare_access_control(old_functions, new_functions)
    all_issues.extend(auth_issues)
    
    # 3. New external calls
    print("[*] Checking for new external calls...")
    call_issues = detect_new_external_calls(old_contract, new_contract)
    all_issues.extend(call_issues)
    
    # Summarize by severity
    summary = {
        "CRITICAL": len([i for i in all_issues if i.severity == "CRITICAL"]),
        "HIGH": len([i for i in all_issues if i.severity == "HIGH"]),
        "MEDIUM": len([i for i in all_issues if i.severity == "MEDIUM"]),
        "LOW": len([i for i in all_issues if i.severity == "LOW"])
    }
    
    safe = summary["CRITICAL"] == 0 and summary["HIGH"] == 0
    
    return {
        "issues": all_issues,
        "summary": summary,
        "safe": safe,
        "old_storage_count": len(old_storage),
        "new_storage_count": len(new_storage),
        "old_function_count": len(old_functions),
        "new_function_count": len(new_functions)
    }


def print_report(results: Dict[str, Any]) -> None:
    """Pretty-print upgrade safety report.

    Args:
        results: Results dictionary from analyze_upgrade().
    """
    issues = results["issues"]
    summary = results["summary"]
    
    print("\n" + "="*60)
    print(" UPGRADE SAFETY REPORT")
    print("="*60)
    
    # Summary
    print(f"\n[*] Storage variables: {results['old_storage_count']} → {results['new_storage_count']}")
    print(f"[*] Functions: {results['old_function_count']} → {results['new_function_count']}")
    
    print(f"\n[*] Issues found:")
    print(f"    CRITICAL: {summary['CRITICAL']}")
    print(f"    HIGH:     {summary['HIGH']}")
    print(f"    MEDIUM:   {summary['MEDIUM']}")
    print(f"    LOW:      {summary['LOW']}")
    
    if results["safe"]:
        print("\n✅ SAFE TO UPGRADE (No critical/high severity issues)")
    else:
        print("\n⚠️  UNSAFE TO UPGRADE - Critical issues must be fixed!")
    
    if not issues:
        print("\n[+] No issues detected. Upgrade appears safe.")
        return
    
    # Group by severity
    print("\n" + "-"*60)
    print("DETAILED FINDINGS:")
    print("-"*60)
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_issues = [i for i in issues if i.severity == severity]
        if severity_issues:
            print(f"\n[{severity}]")
            for i, issue in enumerate(severity_issues, 1):
                print(f"\n  {i}. {issue.title}")
                print(f"     Category: {issue.category}")
                print(f"     {issue.description}")
                print(f"     Old: {issue.old_value}")
                print(f"     New: {issue.new_value}")
                if issue.line_no:
                    print(f"     Line: {issue.line_no}")


def main() -> None:
    """Main entry point for the upgrade diff analyzer CLI."""
    parser = argparse.ArgumentParser(
        description="🔍 Upgrade Diff Analyzer - Detect dangerous changes in contract upgrades"
    )
    parser.add_argument("old_contract", help="Path to old contract version")
    parser.add_argument("new_contract", help="Path to new contract version")
    parser.add_argument("--json", action="store_true", help="Output JSON format")
    
    args = parser.parse_args()
    
    # Validate files exist
    if not Path(args.old_contract).exists():
        print(f"[!] Old contract not found: {args.old_contract}")
        sys.exit(1)
    
    if not Path(args.new_contract).exists():
        print(f"[!] New contract not found: {args.new_contract}")
        sys.exit(1)
    
    results = analyze_upgrade(args.old_contract, args.new_contract)
    
    if args.json:
        import json
        # Convert dataclasses to dicts
        json_issues = [
            {
                "severity": i.severity,
                "category": i.category,
                "title": i.title,
                "description": i.description,
                "old_value": i.old_value,
                "new_value": i.new_value,
                "line_no": i.line_no
            }
            for i in results["issues"]
        ]
        print(json.dumps({
            "issues": json_issues,
            "summary": results["summary"],
            "safe": results["safe"]
        }, indent=2))
    else:
        print_report(results)
    
    # Exit with error code if unsafe
    sys.exit(0 if results["safe"] else 1)


if __name__ == "__main__":
    main()
