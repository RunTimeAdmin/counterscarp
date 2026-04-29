#!/usr/bin/env python3
"""
Solana/Anchor Static Analyzer
Full static analysis for Rust-based Solana programs
Complements solana_intel.py (which only does threat intel)
"""

from __future__ import annotations

import subprocess
import re
import os
import sys
import argparse
from typing import Dict, List, Any, Optional, cast

from dataclasses import dataclass

# Import IDL validator
try:
    from idl_validator import (
        validate_idl,
        find_idl_files
    )
    IDL_VALIDATOR_AVAILABLE = True
except ImportError:
    IDL_VALIDATOR_AVAILABLE = False


@dataclass
class SolanaFinding:
    """Represents a security finding in Solana/Anchor code.

    Attributes:
        severity: Finding severity (CRITICAL, HIGH, MEDIUM, LOW).
        category: Vulnerability category.
        title: Short finding title.
        description: Detailed finding description.
        file: Path to the file where finding occurred.
        line_no: Line number where finding occurred.
        code_snippet: Relevant code snippet.
        fix_suggestion: Suggested fix for the issue.
    """
    severity: str
    category: str
    title: str
    description: str
    file: str
    line_no: int
    code_snippet: str
    fix_suggestion: str

    @property
    def rule_id(self) -> str:
        """Alias for category, used by orchestrator aggregation."""
        return self.category


# Anchor-specific vulnerability patterns
# Expanded to 40 patterns for comprehensive Solana/Anchor security coverage
ANCHOR_PATTERNS: List[Dict[str, Any]] = [
    # ========== ACCOUNT VALIDATION (8 patterns) ==========
    {
        "id": "MISSING_SIGNER_CHECK",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'#\[account\(.*\)\](?!.*signer).*\bpub\s+(\w+):\s*AccountInfo'
        ),
        "description": "Account without signer validation",
        "fix": "Add 'signer' constraint: #[account(signer)]"
    },
    {
        "id": "MISSING_OWNER_CHECK",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'let\s+\w+\s*=\s*\w+\.to_account_info\(\)(?!.*owner)'
        ),
        "description": "Account deserialization without owner check",
        "fix": "Verify account.owner == expected_program_id"
    },
    {
        "id": "MISSING_HAS_ONE_CONSTRAINT",
        "severity": "HIGH",
        "pattern": re.compile(
            r'#\[account\([^)]*\)\]\s*pub\s+\w+:\s*Box<Account<'
            r'\w+>>\s*\{(?!.*has_one)'
        ),
        "description": "Missing has_one constraint for associated accounts",
        "fix": "Add has_one constraint: #[account(has_one = authority)]"
    },
    {
        "id": "MISSING_DISCRIMINATOR_CHECK",
        "severity": "CRITICAL",
        "pattern": re.compile(r'#\[account\](?!.*discriminator)'),
        "description": "Account without discriminator check (type confusion)",
        "fix": "Add discriminator validation in account struct"
    },
    {
        "id": "UNVALIDATED_PDA_SEEDS",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'Pubkey::create_program_address\([^)]+\)(?!.*seeds)'
        ),
        "description": "PDA derived without proper seed validation",
        "fix": "Use find_program_address with validated seeds and bump"
    },
    {
        "id": "MISSING_IS_SIGNER_RAW",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'account_info\.key\s*==\s*[^\n]+(?!.*is_signer)'
        ),
        "description": "Raw Solana program missing is_signer check",
        "fix": "Add check: if !account_info.is_signer { return Err(...) }"
    },
    {
        "id": "MISSING_ACCOUNT_DATA_VALIDATION",
        "severity": "HIGH",
        "pattern": re.compile(
            r'Account::try_from_unchecked\(|try_from_slice_unchecked\('
        ),
        "description": "Unchecked account data deserialization",
        "fix": "Use Account::try_from() or validate discriminator first"
    },
    {
        "id": "UNVALIDATED_ACCOUNT_INFO",
        "severity": "HIGH",
        "pattern": re.compile(r'pub\s+\w+:\s*AccountInfo\s*[^,\n]*$'),
        "description": "Raw AccountInfo without validation constraints",
        "fix": "Use typed Account<T> wrappers or add validation"
    },

    # ========== CPI SECURITY (4 patterns) ==========
    {
        "id": "ARBITRARY_CPI",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'invoke\s*\([^)]*\w+\.key\)(?!.*program_id)'
        ),
        "description": "CPI without program ID verification",
        "fix": "Verify target program ID matches expected"
    },
    {
        "id": "MISSING_CPI_AUTHORITY",
        "severity": "HIGH",
        "pattern": re.compile(r'CpiContext::new\([^)]+\)(?!.*with_signer)'),
        "description": "CPI context missing signer seeds for PDA authority",
        "fix": "Use CpiContext::new_with_signer() when invoking from a PDA"
    },
    {
        "id": "UNVERIFIED_PROGRAM_ACCOUNT",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'program_id:\s*&\w+\.to_account_info\(\)'
        ),
        "description": "CPI using unverified program account",
        "fix": "Hardcode expected program IDs or verify against known"
    },
    {
        "id": "UNSAFE_INVOKE_SIGNED",
        "severity": "HIGH",
        "pattern": re.compile(r'invoke_signed\(.*\bseeds\b.*\)'),
        "description": "invoke_signed with user-controlled seeds",
        "fix": "Ensure seeds are program-controlled only"
    },

    # ========== ARITHMETIC & LOGIC (5 patterns) ==========
    {
        "id": "UNCHECKED_ARITHMETIC",
        "severity": "HIGH",
        "pattern": re.compile(
            r'(\+\s|(?<!checked_)-\s|(?<!checked_)\*\s|(?<!checked_)/\s)'
        ),
        "description": "Unchecked arithmetic operation",
        "fix": "Use checked_add(), checked_sub(), checked_mul(), checked_div()"
    },
    {
        "id": "INTEGER_OVERFLOW_RISK",
        "severity": "HIGH",
        "pattern": re.compile(r'\.wrapping_(add|sub|mul)\('),
        "description": "Wrapping arithmetic can silently overflow",
        "fix": "Use checked_* operations or document why wrapping is safe"
    },
    {
        "id": "UNSAFE_CASTING",
        "severity": "MEDIUM",
        "pattern": re.compile(r'as\s+u64|as\s+i64|as\s+u32|as\s+i32'),
        "description": "Unsafe type casting without bounds checking",
        "fix": "Use try_from() or verify value fits before casting"
    },
    {
        "id": "DIVISION_BY_ZERO_RISK",
        "severity": "MEDIUM",
        "pattern": re.compile(r'/\s*\w+[^;\n]*$'),
        "description": "Division without zero-check on divisor",
        "fix": "Add check: if divisor == 0 { return Err(...) }"
    },
    {
        "id": "PRECISION_LOSS",
        "severity": "MEDIUM",
        "pattern": re.compile(r'/\s*\w+\s*\*\s*\w+'),
        "description": "Division before multiplication causes precision loss",
        "fix": "Reorder: multiply first, then divide (a * c / b)"
    },

    # ========== STATE MANAGEMENT (6 patterns) ==========
    {
        "id": "MISSING_RENT_EXEMPTION",
        "severity": "MEDIUM",
        "pattern": re.compile(r'create_account\((?!.*rent)'),
        "description": "Account creation without rent exemption check",
        "fix": "Ensure account is rent-exempt: rent.minimum_balance(space)"
    },
    {
        "id": "UNINITIALIZED_ACCOUNT_USAGE",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'if\s+\w+\.data_len\(\)\s*==\s*0\s*\{(?!.*return|.*Err)'
        ),
        "description": "Uninitialized account check without error handling",
        "fix": "Return error for uninitialized accounts"
    },
    {
        "id": "ACCOUNT_REINITIALIZATION",
        "severity": "CRITICAL",
        "pattern": re.compile(r'\.init_if_needed\('),
        "description": "init_if_needed allows reinitialization",
        "fix": "Use init constraint or verify reinitialization safety"
    },
    {
        "id": "MISSING_CLOSE_ACCOUNT",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'lamports\(\)\s*=\s*0|\.assign\(\s*&system_program'
        ),
        "description": "Account close without proper close constraint",
        "fix": "Use #[account(close = destination)]"
    },
    {
        "id": "STALE_ACCOUNT_DATA",
        "severity": "HIGH",
        "pattern": re.compile(
            r'invoke\s*\(.*\).*\n.*\w+\.\w+\s*[^=](?!.*reload)'
        ),
        "description": "Account data used after CPI without reload",
        "fix": "Call account.reload()? after CPI"
    },
    {
        "id": "UNCLOSED_ACCOUNT",
        "severity": "MEDIUM",
        "pattern": re.compile(r'close\s*=\s*\w+(?!.*realloc)'),
        "description": "Account close without realloc (resurrection attack)",
        "fix": "Use realloc(0) before closing to prevent resurrection"
    },

    # ========== ACCESS CONTROL (4 patterns) ==========
    {
        "id": "MISSING_ACCESS_CONTROL",
        "severity": "HIGH",
        "pattern": re.compile(
            r'pub\s+fn\s+(withdraw|transfer|mint|burn|upgrade|set_authority)'
            r'\s*\([^)]*\)\s*->\s*Result'
        ),
        "description": "Sensitive instruction missing #[access_control]",
        "fix": "Add #[access_control] with authorization checks"
    },
    {
        "id": "HARDCODED_AUTHORITY",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'Pubkey::from_str\("[1-9A-HJ-NP-Za-km-z]{32,44}"\)'
            r'|pubkey!\s*\(\s*"[1-9A-HJ-NP-Za-km-z]{32,44}"\s*\)'
        ),
        "description": "Hardcoded authority pubkey reduces flexibility",
        "fix": "Use configurable authority stored in program state"
    },
    {
        "id": "MISSING_MULTISIG",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'pub\s+fn\s+(upgrade|set_authority|emergency|pause)'
            r'\s*\([^)]*\).*only'
        ),
        "description": "Admin function may lack multi-signature protection",
        "fix": "Implement multi-sig or timelock for admin functions"
    },
    {
        "id": "WEAK_AUTHORITY_CHECK",
        "severity": "HIGH",
        "pattern": re.compile(
            r'authority\s*==\s*ctx\.accounts\.\w+\.key\(\)'
        ),
        "description": "Authority check without signer verification",
        "fix": "Verify key match AND is_signer"
    },

    # ========== TOKEN SECURITY (4 patterns) ==========
    {
        "id": "MISSING_TOKEN_ACCOUNT_VALIDATION",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'TokenAccount::try_from\(&.*\)(?!.*mint)'
        ),
        "description": "Token account validation missing mint verification",
        "fix": "Verify token_account.mint == expected_mint"
    },
    {
        "id": "UNCHECKED_TOKEN_BALANCE",
        "severity": "HIGH",
        "pattern": re.compile(r'token::transfer\([^)]*\)(?!.*balance)'),
        "description": "Token transfer without checking source balance",
        "fix": "Check source_token_account.amount >= amount"
    },
    {
        "id": "MISSING_FREEZE_AUTHORITY_CHECK",
        "severity": "MEDIUM",
        "pattern": re.compile(r'token::mint_to\(|token::burn\('),
        "description": "Token mint/burn without freeze authority check",
        "fix": "Consider checking mint.freeze_authority"
    },
    {
        "id": "UNVALIDATED_TOKEN_PROGRAM",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'token::\w+\s*\(\s*CpiContext::new\('
            r'\s*ctx\.accounts\.token_program'
        ),
        "description": "Token program CPI without verifying program",
        "fix": "Verify ctx.accounts.token_program.key == &token::ID"
    },

    # ========== GENERAL VALIDATION (4 patterns) ==========
    {
        "id": "UNVALIDATED_ACCOUNT_DATA",
        "severity": "HIGH",
        "pattern": re.compile(r'Account::try_from\(&.*\)(?!.*\.map_err)'),
        "description": "Account deserialization without error handling",
        "fix": "Use .map_err() or ? operator to handle deserialization errors"
    },
    {
        "id": "UNCONSTRAINED_SYSTEM_PROGRAM",
        "severity": "MEDIUM",
        "pattern": re.compile(r'system_program::create_account\('),
        "description": "System program CPI without program ID verification",
        "fix": "Verify system_program account matches system_program::ID"
    },
    {
        "id": "MISSING_CLOCK_VALIDATION",
        "severity": "LOW",
        "pattern": re.compile(r'Clock::get\(\)\?\.(unix_timestamp|slot)'),
        "description": "Clock usage without timestamp/slot validation",
        "fix": "Document clock dependency and drift tolerance"
    },
    {
        "id": "DUPLICATE_MUTABLE_ACCOUNTS",
        "severity": "HIGH",
        "pattern": re.compile(r'&mut\s+\w+.*&mut\s+\w+.*same\s+account'),
        "description": "Multiple mutable borrows of same account",
        "fix": "Ensure accounts are distinct"
    },

    # ========== AUTHORITY & GOVERNANCE (4 patterns) ==========
    {
        "id": "AUTHORITY_PUBKEY_MISMATCH",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'(?:authority|admin)\s*:\s*AccountInfo(?!.*constraint\s*=)'
        ),
        "description": (
            "Authority/admin AccountInfo without constraint matching signer"
        ),
        "fix": (
            "Add constraint to verify authority matches expected signer: "
            "#[account(constraint = authority.key() == state.authority)]"
        )
    },
    {
        "id": "MISSING_MULTISIG_UPGRADE",
        "severity": "HIGH",
        "pattern": re.compile(
            r'pub\s+fn\s+upgrade\s*\([^)]*\)(?!.*multisig)'
        ),
        "description": "Upgrade function without multi-sig requirement",
        "fix": (
            "Require multi-sig approval for upgrades: "
            "add multisig signer account to the instruction context"
        )
    },
    {
        "id": "TWO_STEP_TRANSFER_NOT_USED",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'set_authority\s*\((?!.*nominate|.*accept|.*pending)'
        ),
        "description": (
            "Single-step authority transfer without nominate/accept pattern"
        ),
        "fix": (
            "Implement two-step authority transfer: "
            "nominate_new_authority() + accept_authority()"
        )
    },
    {
        "id": "AUTHORITY_IS_DEFAULT",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'(?:authority|admin|owner)\s*=\s*system_program::ID'
        ),
        "description": "Authority set to system program ID (default/zero-like)",
        "fix": "Use a dedicated keypair for authority, not the system program"
    },

    # ========== CPI SAFETY (2 patterns) ==========
    {
        "id": "CPI_ACCOUNT_LAMPORT_BALANCE_MISMATCH",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'(?:invoke|invoke_signed)\s*\('
            r'(?!.*lamports.*before|.*pre_balance|.*lamport.*check)'
        ),
        "description": (
            "CPI invoke without pre/post lamport balance verification"
        ),
        "fix": (
            "Record lamports before CPI and verify expected delta after: "
            "let pre = account.lamports(); invoke(...); "
            "assert!(account.lamports() == pre - amount);"
        )
    },
    {
        "id": "CPI_RETURN_VALUE_NOT_CHECKED",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'invoke\s*\([^)]*\)\s*;'
        ),
        "description": "CPI invoke result not checked (missing ? or match)",
        "fix": (
            "Always check CPI result: invoke(...)? or match invoke(...) {}"
        )
    },

    # ========== NUMERIC SAFETY (2 patterns) ==========
    {
        "id": "UNSAFE_NARROWING_CAST",
        "severity": "HIGH",
        "pattern": re.compile(
            r'\bas\s+u(?:8|16|32|64)\b(?!.*try_from|.*try_into|.*checked)'
        ),
        "description": (
            "Potentially unsafe narrowing cast (as u8/u16/u32/u64) "
            "without bounds check"
        ),
        "fix": "Use TryFrom/TryInto or validate value fits before casting"
    },
    {
        "id": "SIGN_CHANGE_WITHOUT_CHECK",
        "severity": "MEDIUM",
        "pattern": re.compile(
            r'(?:i64|i128|i32|i16|i8)\b[^;]*\bas\s+u(?:64|128|32|16|8)\b'
            r'(?!.*>=\s*0|.*is_negative|.*abs|.*unsigned_abs)'
        ),
        "description": (
            "Signed-to-unsigned cast without non-negative check"
        ),
        "fix": (
            "Verify value >= 0 before casting: "
            "require!(val >= 0, MyError::Negative); let uval = val as u64;"
        )
    },

    # ========== TOKEN PROGRAM VERIFICATION (1 pattern) ==========
    {
        "id": "UNVALIDATED_SPL_TOKEN_PROGRAM",
        "severity": "CRITICAL",
        "pattern": re.compile(
            r'(?:invoke|invoke_signed)\s*\([^)]*token[^)]*\)'
            r'(?!.*spl_token::ID|.*spl_token::id\(\)|.*token::ID)'
        ),
        "description": (
            "Token program CPI without verifying program ID against "
            "spl_token::ID"
        ),
        "fix": (
            "Verify token program before CPI: "
            "assert!(token_program.key == &spl_token::ID);"
        )
    },
]


def check_cargo_audit() -> bool:
    """Check if cargo-audit is installed.

    Returns:
        True if cargo-audit is installed, False otherwise.
    """
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
    """Run cargo-audit for dependency vulnerabilities.

    Args:
        project_root: Path to the Rust project root.

    Returns:
        Dictionary with audit results.
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
            return cast(Dict[str, Any], json.loads(result.stdout))
        else:
            return {"vulnerabilities": [], "warnings": result.stderr}
    
    except Exception as e:
        return {"error": str(e), "vulnerabilities": []}


def scan_anchor_patterns(file_path: str) -> List[SolanaFinding]:
    """Scan Rust/Anchor file for vulnerability patterns.

    Args:
        file_path: Path to the Rust file to scan.

    Returns:
        List of security findings.
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


def detect_anchor_accounts(file_path: str) -> List[Dict[str, Any]]:
    """Parse Anchor #[account] structs for security analysis.

    Args:
        file_path: Path to the Rust file to analyze.

    Returns:
        List of account configuration dictionaries.
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


def analyze_solana_program(
    project_root: str,
    idl_path: Optional[str] = None,
    validate_idl_constraints: bool = True,
    trace_cpi: bool = True
) -> Dict[str, Any]:
    """Full static analysis of Solana/Anchor program.

    Backward-compatible entry point that delegates to SolanaAnalyzer.

    Args:
        project_root: Path to the Solana/Anchor project root.
        idl_path: Optional explicit path to IDL file/directory.
        validate_idl_constraints: Whether to validate IDL constraints.
        trace_cpi: Whether to trace CPI calls in IDL.

    Returns:
        Dict with dependency vulnerabilities, pattern findings,
        account analysis, IDL findings, and severity summary.
    """
    try:
        from config_loader import SolanaIDLConfig
        config = SolanaIDLConfig(
            idl_path=idl_path or "target/idl",
            validate_constraints=validate_idl_constraints,
            trace_cpi=trace_cpi,
        )
    except ImportError:
        config = None

    analyzer = SolanaAnalyzer(project_root, config=config, idl_path_override=idl_path)
    return analyzer.analyze()


class SolanaAnalyzer:
    """Structured Solana/Anchor static analyzer.

    Wraps pattern scanning, IDL validation, and dependency auditing
    into a single cohesive class.

    Args:
        project_root: Path to the Solana/Anchor project root.
        config: Optional SolanaIDLConfig for IDL settings.
        idl_path_override: Explicit IDL path (file or dir) that takes
            precedence over config.idl_path when provided.
    """

    def __init__(
        self,
        project_root: str,
        config: Optional[Any] = None,
        idl_path_override: Optional[str] = None,
    ) -> None:
        self.project_root = project_root
        self._config = config
        self._idl_path_override = idl_path_override

        # Extract config values with safe defaults
        if config is not None:
            self._idl_search_path: str = getattr(config, "idl_path", "target/idl")
            self._validate_constraints: bool = getattr(config, "validate_constraints", True)
            self._trace_cpi: bool = getattr(config, "trace_cpi", True)
        else:
            self._idl_search_path = "target/idl"
            self._validate_constraints = True
            self._trace_cpi = True

    # ------------------------------------------------------------------
    # Discovery helpers
    # ------------------------------------------------------------------

    def find_rust_files(self) -> List[str]:
        """Find all .rs files under project_root, skipping target/."""
        rust_files: List[str] = []
        for root, _dirs, files in os.walk(self.project_root):
            if "target" in root.split(os.sep):
                continue
            for fname in files:
                if fname.endswith(".rs"):
                    rust_files.append(os.path.join(root, fname))
        return rust_files

    def find_idl_files(self) -> List[str]:
        """Find Anchor IDL JSON files.

        Uses the explicit override path first, then config idl_path,
        then auto-discovery via ``idl_validator.find_idl_files``.
        """
        # 1. Explicit override
        if self._idl_path_override:
            return self._resolve_idl_path(self._idl_path_override)

        # 2. Config-based path (relative to project root)
        config_path = os.path.join(self.project_root, self._idl_search_path)
        if os.path.exists(config_path):
            resolved = self._resolve_idl_path(config_path)
            if resolved:
                return resolved

        # 3. Auto-discover via idl_validator
        if IDL_VALIDATOR_AVAILABLE:
            return find_idl_files(self.project_root)

        return []

    @staticmethod
    def _resolve_idl_path(path: str) -> List[str]:
        """Resolve an IDL path (file or directory) to a list of files."""
        if os.path.isfile(path):
            return [path]
        if os.path.isdir(path):
            result: List[str] = []
            for root, _dirs, files in os.walk(path):
                for fname in files:
                    if fname.endswith(".json"):
                        result.append(os.path.join(root, fname))
            return result
        return []

    # ------------------------------------------------------------------
    # Analysis passes
    # ------------------------------------------------------------------

    def scan_rust_patterns(self, file_path: str) -> List[SolanaFinding]:
        """Scan a single Rust file for vulnerability patterns."""
        return scan_anchor_patterns(file_path)

    def validate_idl_files(self) -> List[Dict[str, Any]]:
        """Run IDL validation on discovered IDL files.

        Returns an empty list when the IDL validator is unavailable or
        no IDL files are found.
        """
        if not IDL_VALIDATOR_AVAILABLE:
            print("    [!] IDL validator not available")
            return []

        idl_files = self.find_idl_files()
        if not idl_files:
            print("    No IDL files found")
            return []

        print(f"    Found {len(idl_files)} IDL file(s)")
        all_findings: List[Dict[str, Any]] = []
        for idl_file in idl_files:
            print(f"    Validating: {os.path.basename(idl_file)}")
            try:
                findings = validate_idl(
                    idl_file,
                    program_source_dir=self.project_root,
                    validate_constraints=self._validate_constraints,
                    trace_cpi=self._trace_cpi,
                )
                all_findings.extend(findings)
            except Exception as exc:
                print(f"    [!] IDL validation error for {idl_file}: {exc}")
        return all_findings

    def scan_dependencies(self) -> List[Dict[str, Any]]:
        """Run cargo-audit and return vulnerability list."""
        audit_results = run_cargo_audit(self.project_root)
        vulns: List[Dict[str, Any]] = audit_results.get("vulnerabilities", [])
        return vulns

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def analyze(self) -> Dict[str, Any]:
        """Run the full Solana analysis pipeline.

        Returns:
            Dict with ``pattern_findings``, ``idl_findings``,
            ``dependency_vulns``, ``account_analysis``, and ``summary``.
        """
        print("\n" + "=" * 60)
        print(" SOLANA STATIC ANALYZER")
        print("=" * 60)
        print(f"\n[*] Analyzing Solana program: {self.project_root}")

        results: Dict[str, Any] = {
            "dependency_vulns": [],
            "pattern_findings": [],
            "account_analysis": [],
            "idl_findings": [],
            "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
        }

        # 1. Dependency vulnerabilities (cargo-audit)
        print("\n[*] Checking dependencies for known vulnerabilities...")
        dep_vulns = self.scan_dependencies()
        results["dependency_vulns"] = dep_vulns
        print(f"    Found {len(dep_vulns)} dependency vulnerabilities")

        # 2. Pattern-based scanning
        print("\n[*] Scanning for Anchor/Solana vulnerability patterns...")
        rust_files = self.find_rust_files()
        print(f"    Found {len(rust_files)} Rust files")

        for rs_file in rust_files:
            findings = self.scan_rust_patterns(rs_file)
            results["pattern_findings"].extend(findings)

            accounts = detect_anchor_accounts(rs_file)
            results["account_analysis"].extend(accounts)

        # 3. IDL validation
        print("\n[*] Checking for Anchor IDL files...")
        idl_findings = self.validate_idl_files()
        results["idl_findings"] = idl_findings

        # 4. Summarize by severity — aggregate all three sources
        summary = results["summary"]

        for finding in results["pattern_findings"]:
            sev = finding.severity
            summary[sev] = summary.get(sev, 0) + 1

        for finding in idl_findings:
            sev = finding.get("severity", "INFO")
            summary[sev] = summary.get(sev, 0) + 1

        for vuln in dep_vulns:
            advisory = vuln.get("advisory", {})
            sev = str(advisory.get("severity", "MEDIUM")).upper()
            summary[sev] = summary.get(sev, 0) + 1

        print("\n[*] Analysis complete:")
        print(f"    CRITICAL: {summary.get('CRITICAL', 0)}")
        print(f"    HIGH:     {summary.get('HIGH', 0)}")
        print(f"    MEDIUM:   {summary.get('MEDIUM', 0)}")
        print(f"    LOW:      {summary.get('LOW', 0)}")

        return results


def print_report(results: Dict[str, Any]) -> None:
    """Pretty-print Solana analysis report.

    Args:
        results: Results dictionary from analyze_solana_program().
    """
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
            sev = advisory.get('severity', 'UNKNOWN')
            title = advisory.get('title', 'Unknown')
            print(f"\n[{sev}] {title}")
            pkg = vuln.get('package', {}).get('name', 'unknown')
            print(f"  Package: {pkg}")
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
            severity_findings = [
                f for f in pattern_findings if f.severity == severity
            ]
            
            if severity_findings:
                print(f"\n[{severity}]")
                
                for i, finding in enumerate(severity_findings[:10], 1):
                    print(f"\n  {i}. {finding.title}")
                    print(f"     File: {finding.file}:{finding.line_no}")
                    print(f"     {finding.description}")
                    print(f"     Fix: {finding.fix_suggestion}")
                
                if len(severity_findings) > 10:
                    more = len(severity_findings) - 10
                    print(f"\n  ... ({more} more {severity} findings)")
    
    # Account analysis summary
    accounts = results.get("account_analysis", [])
    if accounts:
        risky_accounts = [
            a for a in accounts if not a["has_signer"] or not a["has_owner"]
        ]

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

    # IDL findings
    idl_findings = results.get("idl_findings", [])
    if idl_findings:
        print("\n" + "-"*60)
        print("IDL VALIDATION FINDINGS:")
        print("-"*60)

        # Group by severity
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            sev_findings = [
                f for f in idl_findings if f.get("severity") == severity
            ]

            if sev_findings:
                print(f"\n[{severity}]")

                for i, finding in enumerate(sev_findings[:10], 1):
                    rule_id = finding.get("rule_id", "UNKNOWN")
                    instr = finding.get("instruction", "")
                    acc = finding.get("account", "")
                    desc = finding.get("description", "")

                    print(f"\n  {i}. [{rule_id}]")
                    if instr:
                        loc = f"Instruction: {instr}"
                        if acc:
                            loc += f", Account: {acc}"
                        print(f"     {loc}")
                    print(f"     {desc}")

                if len(sev_findings) > 10:
                    more = len(sev_findings) - 10
                    print(f"\n  ... ({more} more {severity} findings)")


def main() -> None:
    """Main entry point for the Solana analyzer CLI."""
    parser = argparse.ArgumentParser(
        description="Solana/Anchor Static Analyzer - Security analysis"
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
    parser.add_argument(
        "--idl-path",
        help="Path to IDL file or directory (auto-detected if not specified)"
    )
    parser.add_argument(
        "--no-idl-constraints",
        action="store_true",
        help="Disable IDL constraint validation"
    )
    parser.add_argument(
        "--no-cpi-trace",
        action="store_true",
        help="Disable CPI tracing"
    )

    args = parser.parse_args()

    # Validate project root
    if not os.path.exists(os.path.join(args.project_root, "Cargo.toml")):
        print(f"[!] Not a valid Rust project: {args.project_root}")
        print("    Missing Cargo.toml")
        sys.exit(1)

    results = analyze_solana_program(
        args.project_root,
        idl_path=args.idl_path,
        validate_idl_constraints=not args.no_idl_constraints,
        trace_cpi=not args.no_cpi_trace
    )
    
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
            "idl_findings": results["idl_findings"],
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
