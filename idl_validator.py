#!/usr/bin/env python3
"""
Anchor IDL Security Validator

Validates Anchor IDL JSON files for security issues including:
- Missing signer constraints on authority/admin accounts
- Missing mutability constraints on writable accounts
- PDA seed validation
- Missing has_one constraints for ownership enforcement
- CPI tracing and program ID verification

Example:
    >>> from idl_validator import validate_idl
    >>> findings = validate_idl("target/idl/my_program.json")
    >>> for finding in findings:
    ...     print(f"{finding['severity']}: {finding['description']}")
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from logger import get_logger
from exceptions import CounterscarpValidationError, CounterscarpAnalysisError

logger = get_logger(__name__)


@dataclass
class IDLAccount:
    """Represents an account in an Anchor IDL.

    Attributes:
        name: Account name.
        is_mut: Whether the account is mutable.
        is_signer: Whether the account is a signer.
        is_optional: Whether the account is optional.
        docs: Documentation strings for the account.
        pda: PDA configuration if applicable.
        relations: List of has_one relations.
    """
    name: str
    is_mut: bool = False
    is_signer: bool = False
    is_optional: bool = False
    docs: List[str] = field(default_factory=list)
    pda: Optional[Dict[str, Any]] = None
    relations: List[str] = field(default_factory=list)


@dataclass
class IDLInstruction:
    """Represents an instruction in an Anchor IDL.

    Attributes:
        name: Instruction name.
        accounts: List of accounts required by the instruction.
        args: List of instruction arguments.
        docs: Documentation strings for the instruction.
    """
    name: str
    accounts: List[IDLAccount] = field(default_factory=list)
    args: List[Dict[str, Any]] = field(default_factory=list)
    docs: List[str] = field(default_factory=list)


@dataclass
class IDLProgram:
    """Represents a parsed Anchor IDL program.

    Attributes:
        name: Program name.
        version: Program version.
        instructions: List of program instructions.
        accounts: List of account types.
        types: List of custom types.
        events: List of event types.
        errors: List of error codes.
        metadata: Additional program metadata.
    """
    name: str
    version: str
    instructions: List[IDLInstruction] = field(default_factory=list)
    accounts: List[Dict[str, Any]] = field(default_factory=list)
    types: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class IDLParser:
    """Parser for Anchor IDL JSON files."""

    @staticmethod
    def parse(idl_path: str) -> IDLProgram:
        """Parse an Anchor IDL JSON file.

        Args:
            idl_path: Path to the IDL JSON file.

        Returns:
            Parsed IDLProgram object.

        Raises:
            CounterscarpValidationError: If the IDL file is invalid or cannot
                be parsed.
        """
        logger.debug(f"Parsing IDL file: {idl_path}")

        if not os.path.exists(idl_path):
            raise CounterscarpValidationError(
                f"IDL file not found: {idl_path}",
                details={"path": idl_path}
            )

        try:
            with open(idl_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            raise CounterscarpValidationError(
                f"Invalid JSON in IDL file: {e}",
                details={"path": idl_path, "error": str(e)}
            ) from e
        except IOError as e:
            raise CounterscarpValidationError(
                f"Failed to read IDL file: {e}",
                details={"path": idl_path, "error": str(e)}
            ) from e

        # Parse basic program info
        name = data.get('name', 'unknown')
        version = data.get('version', '0.0.0')
        metadata = data.get('metadata', {})

        # Parse instructions
        instructions = []
        for instr_data in data.get('instructions', []):
            instruction = IDLParser._parse_instruction(instr_data)
            instructions.append(instruction)

        # Parse accounts, types, events, errors
        accounts = data.get('accounts', [])
        types = data.get('types', [])
        events = data.get('events', [])
        errors = data.get('errors', [])

        program = IDLProgram(
            name=name,
            version=version,
            instructions=instructions,
            accounts=accounts,
            types=types,
            events=events,
            errors=errors,
            metadata=metadata
        )

        logger.debug(f"Successfully parsed IDL for program: {name} v{version}")
        logger.debug(f"  Instructions: {len(instructions)}")
        logger.debug(f"  Accounts: {len(accounts)}")
        logger.debug(f"  Types: {len(types)}")

        return program

    @staticmethod
    def _parse_instruction(data: Dict[str, Any]) -> IDLInstruction:
        """Parse an instruction from IDL data.

        Args:
            data: Raw instruction data from IDL.

        Returns:
            Parsed IDLInstruction object.
        """
        name = data.get('name', 'unknown')
        docs = data.get('docs', [])
        args = data.get('args', [])

        accounts = []
        for acc_data in data.get('accounts', []):
            account = IDLParser._parse_account(acc_data)
            accounts.append(account)

        return IDLInstruction(
            name=name,
            accounts=accounts,
            args=args,
            docs=docs
        )

    @staticmethod
    def _parse_account(data: Dict[str, Any]) -> IDLAccount:
        """Parse an account from IDL data.

        Args:
            data: Raw account data from IDL.

        Returns:
            Parsed IDLAccount object.
        """
        name = data.get('name', 'unknown')
        is_mut = data.get('isMut', False)
        is_signer = data.get('isSigner', False)
        is_optional = data.get('isOptional', False)
        docs = data.get('docs', [])
        pda = data.get('pda')
        relations = data.get('relations', [])

        return IDLAccount(
            name=name,
            is_mut=is_mut,
            is_signer=is_signer,
            is_optional=is_optional,
            docs=docs,
            pda=pda,
            relations=relations
        )


class ConstraintValidator:
    """Validates account constraints in IDL instructions."""

    # Account name patterns that typically require signer
    SIGNER_KEYWORDS = {
        'authority', 'admin', 'owner', 'signer', 'payer', 'creator',
        'initializer', 'updater', 'manager', 'controller', 'fee_payer'
    }

    # Account name patterns that typically indicate mutable state
    MUTABILITY_KEYWORDS = {
        'state', 'account', 'data', 'config', 'settings', 'vault',
        'pool', 'reserve', 'balance', 'position', 'metadata'
    }

    @staticmethod
    def validate_signer_constraints(
        instruction: IDLInstruction
    ) -> List[Dict[str, Any]]:
        """Validate signer constraints for an instruction.

        Detects accounts that should be signers based on naming conventions
        but are not marked as such in the IDL.

        Args:
            instruction: The instruction to validate.

        Returns:
            List of findings for missing signer constraints.
        """
        findings = []

        for account in instruction.accounts:
            # Skip if already marked as signer
            if account.is_signer:
                continue

            # Skip optional accounts (might be passed as None)
            if account.is_optional:
                continue

            # Check if account name suggests it should be a signer
            account_lower = account.name.lower()
            should_be_signer = any(
                keyword in account_lower
                for keyword in ConstraintValidator.SIGNER_KEYWORDS
            )

            if should_be_signer:
                findings.append({
                    "rule_id": "IDL_MISSING_SIGNER",
                    "severity": "HIGH",
                    "description": (
                        f"Account '{account.name}' in instruction "
                        f"'{instruction.name}' has a name suggesting it "
                        f"should be a signer, but 'isSigner' is not set. "
                        f"This may allow unauthorized transactions."
                    ),
                    "file": "",
                    "line_no": 0,
                    "instruction": instruction.name,
                    "account": account.name,
                    "fix_suggestion": (
                        f"Add 'isSigner: true' to account '{account.name}'"
                    )
                })

        return findings

    @staticmethod
    def validate_mutability_constraints(
        instruction: IDLInstruction
    ) -> List[Dict[str, Any]]:
        """Validate mutability constraints for an instruction.

        Detects accounts that are likely to be mutated based on instruction
        naming patterns but are not marked as mutable.

        Args:
            instruction: The instruction to validate.

        Returns:
            List of findings for potentially missing mutability constraints.
        """
        findings = []

        # Instructions that typically mutate state
        mutating_prefixes = (
            'initialize', 'init', 'create', 'update', 'modify', 'set',
            'change', 'deposit', 'withdraw', 'transfer', 'mint', 'burn',
            'swap', 'claim', 'stake', 'unstake', 'vote', 'execute'
        )

        instruction_lower = instruction.name.lower()
        is_likely_mutating = instruction_lower.startswith(mutating_prefixes)

        if not is_likely_mutating:
            return findings

        for account in instruction.accounts:
            # Skip if already mutable
            if account.is_mut:
                continue

            # Skip signer accounts (often read-only authorities)
            if account.is_signer:
                continue

            # Skip program accounts
            if 'program' in account.name.lower():
                continue

            # Check if account name suggests mutable state
            account_lower = account.name.lower()
            suggests_state = any(
                keyword in account_lower
                for keyword in ConstraintValidator.MUTABILITY_KEYWORDS
            )

            if suggests_state:
                findings.append({
                    "rule_id": "IDL_MISSING_MUTABILITY",
                    "severity": "MEDIUM",
                    "description": (
                        f"Account '{account.name}' in instruction "
                        f"'{instruction.name}' may need 'isMut: true'. "
                        f"Instruction name suggests state mutation, but "
                        f"account is marked read-only."
                    ),
                    "file": "",
                    "line_no": 0,
                    "instruction": instruction.name,
                    "account": account.name,
                    "fix_suggestion": (
                        f"Add 'isMut: true' to account '{account.name}'"
                    )
                })

        return findings

    @staticmethod
    def validate_pda_constraints(
        instruction: IDLInstruction
    ) -> List[Dict[str, Any]]:
        """Validate PDA constraints for an instruction.

        Checks that PDA accounts have proper seeds and bump constraints.

        Args:
            instruction: The instruction to validate.

        Returns:
            List of findings for PDA constraint issues.
        """
        findings = []

        for account in instruction.accounts:
            # Check if account has PDA configuration
            if account.pda is None:
                continue

            pda = account.pda

            # Check for missing seeds
            seeds = pda.get('seeds', [])
            if not seeds:
                findings.append({
                    "rule_id": "IDL_PDA_MISSING_SEEDS",
                    "severity": "CRITICAL",
                    "description": (
                        f"PDA account '{account.name}' in instruction "
                        f"'{instruction.name}' has no seeds defined. "
                        f"PDAs must have at least one seed for derivation."
                    ),
                    "file": "",
                    "line_no": 0,
                    "instruction": instruction.name,
                    "account": account.name,
                    "fix_suggestion": (
                        "Define PDA seeds in the account constraints"
                    )
                })

            # Check for missing bump
            has_bump = 'bump' in pda or any(
                seed.get('kind') == 'bump' for seed in seeds
            )
            if not has_bump:
                findings.append({
                    "rule_id": "IDL_PDA_MISSING_BUMP",
                    "severity": "HIGH",
                    "description": (
                        f"PDA account '{account.name}' in instruction "
                        f"'{instruction.name}' may be missing bump "
                        f"constraint. Explicit bump is recommended for "
                        f"deterministic PDA derivation."
                    ),
                    "file": "",
                    "line_no": 0,
                    "instruction": instruction.name,
                    "account": account.name,
                    "fix_suggestion": "Add bump constraint to PDA definition"
                })

            # Validate seed types
            for seed in seeds:
                seed_kind = seed.get('kind', '')
                if seed_kind == 'const' and not seed.get('value'):
                    findings.append({
                        "rule_id": "IDL_PDA_EMPTY_CONST_SEED",
                        "severity": "MEDIUM",
                        "description": (
                            f"PDA account '{account.name}' has empty "
                            f"const seed. This may be unintentional."
                        ),
                        "file": "",
                        "line_no": 0,
                        "instruction": instruction.name,
                        "account": account.name,
                        "fix_suggestion": (
                            "Verify const seed value is intentional"
                        )
                    })

        return findings

    @staticmethod
    def validate_has_one_constraints(
        instruction: IDLInstruction
    ) -> List[Dict[str, Any]]:
        """Validate has_one constraints for ownership enforcement.

        Detects accounts that may need has_one constraints for ownership
        validation.

        Args:
            instruction: The instruction to validate.

        Returns:
            List of findings for missing has_one constraints.
        """
        findings = []

        # Find authority-like accounts
        authority_accounts = [
            acc for acc in instruction.accounts
            if any(keyword in acc.name.lower()
                   for keyword in ['authority', 'owner', 'admin'])
            and acc.is_signer
        ]

        for account in instruction.accounts:
            # Skip if already has relations
            if account.relations:
                continue

            # Skip signer accounts
            if account.is_signer:
                continue

            # Check if account name suggests ownership relationship
            account_lower = account.name.lower()
            ownership_indicators = [
                'account', 'state', 'data', 'vault', 'pool'
            ]

            if any(ind in account_lower for ind in ownership_indicators):
                # Check if there's a matching authority account
                for auth in authority_accounts:
                    # Simple heuristic: if account and authority share context
                    # e.g., "user_account" and "user_authority"
                    account_prefix = account_lower.split('_')[0]
                    auth_prefix = auth.name.lower().split('_')[0]

                    if account_prefix == auth_prefix:
                        findings.append({
                            "rule_id": "IDL_MISSING_HAS_ONE",
                            "severity": "MEDIUM",
                            "description": (
                                f"Account '{account.name}' in instruction "
                                f"'{instruction.name}' may need a has_one "
                                f"constraint to enforce ownership by "
                                f"'{auth.name}'. Without this, ownership "
                                f"validation must be done manually in "
                                f"the handler."
                            ),
                            "file": "",
                            "line_no": 0,
                            "instruction": instruction.name,
                            "account": account.name,
                            "fix_suggestion": (
                                f"Add 'has_one = {auth.name}' constraint to "
                                f"account '{account.name}'"
                            )
                        })

        return findings


class CPITracer:
    """Traces Cross-Program Invocations (CPI) in IDL."""

    # Known program IDs for common Solana programs
    KNOWN_PROGRAMS = {
        'token': 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA',
        'token_2022': 'TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb',
        'associated_token': 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL',
        'system': '11111111111111111111111111111111',
        'metadata': 'metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s',
    }

    @staticmethod
    def detect_cpi_accounts(
        instruction: IDLInstruction
    ) -> List[Dict[str, Any]]:
        """Detect accounts that may be used for CPI.

        Identifies instruction accounts that appear to be program accounts
        or token accounts used in CPI calls.

        Args:
            instruction: The instruction to analyze.

        Returns:
            List of findings for potential CPI security issues.
        """
        findings = []

        for account in instruction.accounts:
            account_lower = account.name.lower()

            # Detect program accounts
            if 'program' in account_lower:
                findings.append({
                    "rule_id": "IDL_CPI_PROGRAM_ACCOUNT",
                    "severity": "INFO",
                    "description": (
                        f"Account '{account.name}' in instruction "
                        f"'{instruction.name}' appears to be a program "
                        f"account. Ensure program ID is verified before CPI."
                    ),
                    "file": "",
                    "line_no": 0,
                    "instruction": instruction.name,
                    "account": account.name,
                    "fix_suggestion": (
                        "Verify program ID matches expected before invocation"
                    )
                })

            # Detect token-related CPI
            token_keywords = ['token_program', 'token']
            if any(keyword in account_lower for keyword in token_keywords):
                if not account.is_signer and not account.is_mut:
                    findings.append({
                        "rule_id": "IDL_CPI_TOKEN_PROGRAM",
                        "severity": "LOW",
                        "description": (
                            f"Token program account '{account.name}' "
                            f"detected in instruction '{instruction.name}'. "
                            f"Ensure proper token program ID verification."
                        ),
                        "file": "",
                        "line_no": 0,
                        "instruction": instruction.name,
                        "account": account.name,
                        "fix_suggestion": (
                            "Verify token_program.key == &token::ID"
                        )
                    })

        return findings

    @staticmethod
    def build_cpi_flow_matrix(
        program: IDLProgram
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Build a CPI flow matrix for the program.

        Maps which instructions may call which programs based on
        account usage patterns.

        Args:
            program: The parsed IDL program.

        Returns:
            Dictionary mapping instruction names to potential CPI targets.
        """
        cpi_flow = {}

        for instruction in program.instructions:
            targets = []

            for account in instruction.accounts:
                account_lower = account.name.lower()

                # Map program accounts to potential CPI targets
                if 'token_program' in account_lower:
                    targets.append({
                        "program": "token",
                        "account": account.name,
                        "program_id": CPITracer.KNOWN_PROGRAMS.get(
                            'token', ''
                        ),
                        "risk": "Verify program ID before CPI"
                    })
                elif 'system_program' in account_lower:
                    targets.append({
                        "program": "system",
                        "account": account.name,
                        "program_id": CPITracer.KNOWN_PROGRAMS.get(
                            'system', ''
                        ),
                        "risk": "Low - system program is standard"
                    })
                elif 'associated_token' in account_lower:
                    targets.append({
                        "program": "associated_token",
                        "account": account.name,
                        "program_id": CPITracer.KNOWN_PROGRAMS.get(
                            'associated_token', ''
                        ),
                        "risk": "Verify program ID before CPI"
                    })
                elif ('metadata' in account_lower and
                      'program' in account_lower):
                    targets.append({
                        "program": "metadata",
                        "account": account.name,
                        "program_id": CPITracer.KNOWN_PROGRAMS.get(
                            'metadata', ''
                        ),
                        "risk": "Verify program ID before CPI"
                    })

            if targets:
                cpi_flow[instruction.name] = targets

        return cpi_flow


class AccountPermissionMatrix:
    """Generates account permission matrices for IDL programs."""

    @staticmethod
    def generate_matrix(program: IDLProgram) -> Dict[str, Any]:
        """Generate a permission matrix for all instructions.

        Creates a structured matrix showing:
        - Each instruction × which accounts it requires
        - Access level per account (read/write/signer)
        - PDA derivation info

        Args:
            program: The parsed IDL program.

        Returns:
            Dictionary containing the permission matrix.
        """
        matrix = {
            "program_name": program.name,
            "program_version": program.version,
            "instructions": {},
            "account_summary": {}
        }

        # Collect all unique accounts across instructions
        all_accounts: Set[str] = set()
        account_usage: Dict[str, Dict[str, Any]] = {}

        for instruction in program.instructions:
            instr_matrix = {
                "accounts": {},
                "signer_required": False,
                "mutable_accounts": [],
                "pda_accounts": []
            }

            for account in instruction.accounts:
                all_accounts.add(account.name)

                # Track account usage
                if account.name not in account_usage:
                    account_usage[account.name] = {
                        "used_by": [],
                        "is_signer_count": 0,
                        "is_mut_count": 0,
                        "is_pda": account.pda is not None
                    }

                account_usage[account.name]["used_by"].append(instruction.name)
                if account.is_signer:
                    account_usage[account.name]["is_signer_count"] += 1
                    instr_matrix["signer_required"] = True
                if account.is_mut:
                    account_usage[account.name]["is_mut_count"] += 1
                    instr_matrix["mutable_accounts"].append(account.name)
                if account.pda is not None:
                    instr_matrix["pda_accounts"].append({
                        "name": account.name,
                        "seeds": account.pda.get('seeds', []),
                        "bump": account.pda.get('bump')
                    })

                # Determine access level
                if account.is_signer and account.is_mut:
                    access_level = "signer+write"
                elif account.is_signer:
                    access_level = "signer"
                elif account.is_mut:
                    access_level = "write"
                else:
                    access_level = "read"

                instr_matrix["accounts"][account.name] = {
                    "access_level": access_level,
                    "is_optional": account.is_optional,
                    "is_pda": account.pda is not None,
                    "relations": account.relations
                }

            matrix["instructions"][instruction.name] = instr_matrix

        matrix["account_summary"] = account_usage
        matrix["total_accounts"] = len(all_accounts)
        matrix["total_instructions"] = len(program.instructions)

        return matrix

    @staticmethod
    def print_matrix(matrix: Dict[str, Any]) -> str:
        """Format the permission matrix as a readable string.

        Args:
            matrix: The permission matrix dictionary.

        Returns:
            Formatted string representation.
        """
        lines = []
        lines.append("=" * 80)
        prog_name = matrix['program_name']
        prog_ver = matrix['program_version']
        lines.append(f"Account Permission Matrix: {prog_name} v{prog_ver}")
        lines.append("=" * 80)
        lines.append("")

        # Summary
        lines.append(f"Total Instructions: {matrix['total_instructions']}")
        lines.append(f"Total Unique Accounts: {matrix['total_accounts']}")
        lines.append("")

        # Per-instruction breakdown
        lines.append("-" * 80)
        lines.append("Instruction Account Requirements:")
        lines.append("-" * 80)

        for instr_name, instr_data in matrix["instructions"].items():
            lines.append(f"\n  {instr_name}:")

            if instr_data["signer_required"]:
                lines.append("    [SIGNER REQUIRED]")

            for acc_name, acc_data in instr_data["accounts"].items():
                access = acc_data["access_level"]
                optional = " (optional)" if acc_data["is_optional"] else ""
                pda = " [PDA]" if acc_data["is_pda"] else ""
                lines.append(f"      - {acc_name}: {access}{optional}{pda}")

        lines.append("")
        lines.append("-" * 80)
        lines.append("Account Usage Summary:")
        lines.append("-" * 80)

        for acc_name, usage in matrix["account_summary"].items():
            used_count = len(usage["used_by"])
            signer_pct = (
                usage["is_signer_count"] / used_count * 100
            ) if used_count > 0 else 0
            mut_pct = (
                usage["is_mut_count"] / used_count * 100
            ) if used_count > 0 else 0
            pda_marker = " [PDA]" if usage["is_pda"] else ""

            lines.append(f"\n  {acc_name}{pda_marker}:")
            lines.append(f"    Used by: {used_count} instruction(s)")
            lines.append(f"    As signer: {signer_pct:.0f}%")
            lines.append(f"    As mutable: {mut_pct:.0f}%")

        lines.append("")
        lines.append("=" * 80)

        return "\n".join(lines)


def validate_idl(
    idl_path: str,
    program_source_dir: Optional[str] = None,
    validate_constraints: bool = True,
    trace_cpi: bool = True
) -> List[Dict[str, Any]]:
    """Validate an Anchor IDL file for security issues.

    Main entry point for IDL validation. Parses the IDL file and runs
    all security checks.

    Args:
        idl_path: Path to the IDL JSON file.
        program_source_dir: Optional path to Rust source for cross-referencing.
        validate_constraints: Whether to run constraint validation.
        trace_cpi: Whether to run CPI tracing.

    Returns:
        List of findings as dictionaries.

    Raises:
        CounterscarpAnalysisError: If validation fails unexpectedly.
    """
    logger.info(f"Starting IDL validation: {idl_path}")

    findings = []

    try:
        # Parse the IDL
        program = IDLParser.parse(idl_path)

        # Run constraint validation
        if validate_constraints:
            logger.debug("Running constraint validation...")
            for instruction in program.instructions:
                # Signer constraints
                findings.extend(
                    ConstraintValidator.validate_signer_constraints(
                        instruction
                    )
                )

                # Mutability constraints
                findings.extend(
                    ConstraintValidator.validate_mutability_constraints(
                        instruction
                    )
                )

                # PDA constraints
                findings.extend(
                    ConstraintValidator.validate_pda_constraints(instruction)
                )

                # has_one constraints
                findings.extend(
                    ConstraintValidator.validate_has_one_constraints(
                        instruction
                    )
                )

        # Run CPI tracing
        if trace_cpi:
            logger.debug("Running CPI tracing...")
            for instruction in program.instructions:
                findings.extend(
                    CPITracer.detect_cpi_accounts(instruction)
                )

        # Cross-reference with source if provided
        if program_source_dir and os.path.exists(program_source_dir):
            logger.debug(
                f"Cross-referencing with source: {program_source_dir}"
            )
            source_findings = _cross_reference_source(
                program, program_source_dir
            )
            findings.extend(source_findings)

        # Add file path to all findings
        for finding in findings:
            finding["file"] = idl_path

        logger.info(
            f"IDL validation complete. Found {len(findings)} issue(s)."
        )

    except CounterscarpValidationError:
        raise
    except Exception as e:
        raise CounterscarpAnalysisError(
            f"IDL validation failed: {e}",
            details={"path": idl_path, "error": str(e)}
        ) from e

    return findings


def _cross_reference_source(
    program: IDLProgram,
    source_dir: str
) -> List[Dict[str, Any]]:
    """Cross-reference IDL with Rust source code.

    Args:
        program: The parsed IDL program.
        source_dir: Path to the Rust source directory.

    Returns:
        List of additional findings from source cross-reference.
    """
    findings = []

    # Find all Rust files
    rust_files = []
    for root, dirs, files in os.walk(source_dir):
        # Skip target directory
        if 'target' in root.split(os.sep):
            continue

        for file in files:
            if file.endswith('.rs'):
                rust_files.append(os.path.join(root, file))

    # Build a map of instruction handlers
    instruction_handlers: Dict[str, str] = {}

    for rs_file in rust_files:
        try:
            with open(rs_file, 'r', encoding='utf-8') as f:
                content = f.read()

            # Look for instruction handlers (pub fn <instruction_name>)
            for instruction in program.instructions:
                pattern = rf'pub\s+fn\s+{re.escape(instruction.name)}\s*\('
                if re.search(pattern, content):
                    instruction_handlers[instruction.name] = rs_file

        except IOError:
            continue

    # Check for missing handlers
    for instruction in program.instructions:
        if instruction.name not in instruction_handlers:
            findings.append({
                "rule_id": "IDL_MISSING_HANDLER",
                "severity": "HIGH",
                "description": (
                    f"No handler found for instruction "
                    f"'{instruction.name}'. Expected a function with "
                    f"signature 'pub fn {instruction.name}(...)'"
                ),
                "file": "",
                "line_no": 0,
                "instruction": instruction.name,
                "account": "",
                "fix_suggestion": (
                    f"Implement handler function for '{instruction.name}'"
                )
            })

    logger.debug(
        f"Found handlers for {len(instruction_handlers)}/"
        f"{len(program.instructions)} instructions"
    )

    return findings


def find_idl_files(project_root: str) -> List[str]:
    """Find IDL files in common Anchor project locations.

    Searches for IDL JSON files in:
    - target/idl/
    - idl/
    - Project root

    Args:
        project_root: Path to the project root directory.

    Returns:
        List of paths to IDL files.
    """
    idl_paths = []

    search_paths = [
        os.path.join(project_root, 'target', 'idl'),
        os.path.join(project_root, 'idl'),
        project_root
    ]

    for search_path in search_paths:
        if not os.path.exists(search_path):
            continue

        if os.path.isdir(search_path):
            for file in os.listdir(search_path):
                if file.endswith('.json'):
                    full_path = os.path.join(search_path, file)
                    # Validate it's an Anchor IDL by checking structure
                    try:
                        with open(full_path, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                        # Check for required Anchor IDL fields
                        if 'instructions' in data and 'name' in data:
                            idl_paths.append(full_path)
                            logger.debug(f"Found valid IDL: {full_path}")
                    except (json.JSONDecodeError, IOError):
                        continue

    return idl_paths


def generate_idl_report(
    idl_path: str,
    findings: List[Dict[str, Any]],
    include_matrix: bool = True
) -> str:
    """Generate a formatted report for IDL validation results.

    Args:
        idl_path: Path to the validated IDL file.
        findings: List of findings from validation.
        include_matrix: Whether to include the permission matrix.

    Returns:
        Formatted report string.
    """
    lines = []
    lines.append("=" * 80)
    lines.append("ANCHOR IDL SECURITY VALIDATION REPORT")
    lines.append("=" * 80)
    lines.append(f"\nIDL File: {idl_path}")
    lines.append("")

    # Summary by severity
    severity_counts = {
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
    }
    for finding in findings:
        sev = finding.get("severity", "INFO")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    lines.append("-" * 80)
    lines.append("FINDINGS SUMMARY:")
    lines.append("-" * 80)
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = severity_counts.get(sev, 0)
        lines.append(f"  {sev}: {count}")

    # Detailed findings
    if findings:
        lines.append("")
        lines.append("-" * 80)
        lines.append("DETAILED FINDINGS:")
        lines.append("-" * 80)

        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for severity in severities:
            sev_findings = [
                f for f in findings if f.get("severity") == severity
            ]
            if sev_findings:
                lines.append(f"\n[{severity}]")
                for finding in sev_findings:
                    rule_id = finding.get("rule_id", "UNKNOWN")
                    desc = finding.get("description", "")
                    instr = finding.get("instruction", "")
                    acc = finding.get("account", "")

                    lines.append(f"\n  [{rule_id}]")
                    if instr:
                        loc = f"Instruction: {instr}"
                        if acc:
                            loc += f", Account: {acc}"
                        lines.append(f"  Location: {loc}")
                    lines.append(f"  Description: {desc}")

                    fix = finding.get("fix_suggestion")
                    if fix:
                        lines.append(f"  Fix: {fix}")
    else:
        lines.append("\n  No issues found.")

    # Permission matrix
    if include_matrix:
        try:
            program = IDLParser.parse(idl_path)
            matrix = AccountPermissionMatrix.generate_matrix(program)
            lines.append("\n")
            lines.append(AccountPermissionMatrix.print_matrix(matrix))
        except Exception as e:
            logger.warning(f"Failed to generate permission matrix: {e}")

    lines.append("")
    lines.append("=" * 80)

    return "\n".join(lines)


# CLI entry point
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Anchor IDL Security Validator"
    )
    parser.add_argument(
        "idl_path",
        help="Path to the IDL JSON file"
    )
    parser.add_argument(
        "--source-dir",
        help="Path to Rust source directory for cross-referencing",
        default=None
    )
    parser.add_argument(
        "--no-constraints",
        action="store_true",
        help="Disable constraint validation"
    )
    parser.add_argument(
        "--no-cpi",
        action="store_true",
        help="Disable CPI tracing"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output findings as JSON"
    )
    parser.add_argument(
        "--matrix",
        action="store_true",
        help="Include permission matrix in output"
    )

    args = parser.parse_args()

    findings = validate_idl(
        idl_path=args.idl_path,
        program_source_dir=args.source_dir,
        validate_constraints=not args.no_constraints,
        trace_cpi=not args.no_cpi
    )

    if args.json:
        import json as json_mod
        print(json_mod.dumps(findings, indent=2))
    else:
        report = generate_idl_report(
            args.idl_path,
            findings,
            include_matrix=args.matrix
        )
        print(report)

    # Exit with error code if critical/high issues found
    critical_high = sum(
        1 for f in findings
        if f.get("severity") in ("CRITICAL", "HIGH")
    )
    exit(1 if critical_high > 0 else 0)
