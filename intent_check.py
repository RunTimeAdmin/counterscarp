#!/usr/bin/env python3
"""
Enhanced Liar Detector - NatSpec Intent vs Implementation Analyzer.

Detects mismatches between developer intent (NatSpec comments) and
actual implementation (function signatures, modifiers, and body patterns).
Catches psychological security bugs where devs *thought* they secured
something but didn't.

Example:
    >>> from intent_check import analyze_intent, NatSpecAnalyzer
    >>> findings = analyze_intent("Contract.sol")
    >>> for finding in findings:
    ...     print(f"{finding.severity}: {finding.description}")
"""

from __future__ import annotations

import re
import argparse
import sys
from typing import List, Dict, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

# Import project logging and exceptions
try:
    from logger import get_logger
    from exceptions import CounterscarpAnalysisError, CounterscarpValidationError
    HAS_DEPENDENCIES = True
except ImportError:
    HAS_DEPENDENCIES = False
    # Fallback implementations
    import logging

    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

    class CounterscarpAnalysisError(Exception):  # type: ignore[no-redef]
        def __init__(self, message: str, details: Optional[Dict] = None):
            super().__init__(message)
            self.message = message
            self.details = details or {}

    class CounterscarpValidationError(Exception):  # type: ignore[no-redef]
        def __init__(self, message: str, details: Optional[Dict] = None):
            super().__init__(message)
            self.message = message
            self.details = details or {}

# Initialize logger
logger = get_logger(__name__)


class Severity(Enum):
    """Severity levels for findings."""
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class FunctionCategory(Enum):
    """Categories of function behavior."""
    STATE_MODIFYING = "state_modifying"
    VIEW = "view"
    PURE = "pure"
    PAYABLE = "payable"
    TRANSFER = "transfer"
    ADMINISTRATIVE = "administrative"
    ACCESS_CONTROLLED = "access_controlled"


class ModifierType(Enum):
    """Types of modifiers for classification."""
    ACCESS_CONTROL = "access_control"
    STATE_MODIFIER = "state_modifier"
    REENTRANCY_PROTECTION = "reentrancy_protection"
    PAUSE_CONTROL = "pause_control"
    CUSTOM = "custom"


@dataclass
class NatSpecInfo:
    """Structured NatSpec comment information.
    
    Attributes:
        notice: User-facing description from @notice
        dev: Developer notes from @dev
        params: Parameter descriptions from @param tags
        returns: Return value description from @return
        raw: Raw comment text for reference
    """
    notice: Optional[str] = None
    dev: Optional[str] = None
    params: Dict[str, str] = field(default_factory=dict)
    returns: Optional[str] = None
    raw: str = ""
    
    def claims_public_access(self) -> bool:
        """Check if NatSpec claims this function is publicly accessible."""
        text = f"{self.notice or ''} {self.dev or ''}".lower()
        public_indicators = [
            "anyone can call", "anyone can", "public function",
            "callable by anyone", "no restrictions", "open to all",
            "permissionless", "external access"
        ]
        return any(indicator in text for indicator in public_indicators)
    
    def claims_restricted_access(self) -> bool:
        """Check if NatSpec claims this function has restricted access."""
        text = f"{self.notice or ''} {self.dev or ''}".lower()
        restriction_indicators = [
            "only owner", "only admin", "restricted", "authorized",
            "permissioned", "admin only", "owner only", "governance",
            "protected", "requires auth", "only role"
        ]
        return any(indicator in text for indicator in restriction_indicators)
    
    def claims_view_behavior(self) -> bool:
        """Check if NatSpec claims this is a view/pure function."""
        text = f"{self.notice or ''} {self.dev or ''}".lower()
        view_indicators = [
            "view function", "read-only", "read only", "returns",
            "gets the", "retrieves", "queries", "checks if", "view "
        ]
        return any(indicator in text for indicator in view_indicators)
    
    def claims_state_modification(self) -> bool:
        """Check if NatSpec claims this function modifies state."""
        text = f"{self.notice or ''} {self.dev or ''}".lower()
        state_indicators = [
            "sets", "updates", "modifies", "changes", "writes",
            "stores", "mints", "burns", "transfers", "deposits",
            "withdraws", "creates", "deletes"
        ]
        return any(indicator in text for indicator in state_indicators)


@dataclass
class ModifierInfo:
    """Information about a function modifier.
    
    Attributes:
        name: The modifier name
        mod_type: Classification type of the modifier
        args: Arguments passed to the modifier
    """
    name: str
    mod_type: ModifierType
    args: List[str] = field(default_factory=list)


@dataclass
class FunctionInfo:
    """Comprehensive function information.
    
    Attributes:
        name: Function name
        line_no: Line number in source file
        visibility: Function visibility (public, external, internal, private)
        state_mutability: State mutability (pure, view, payable, or None)
        modifiers: List of modifier information
        params: Function parameters
        returns: Return type(s)
        natspec: Associated NatSpec info
        body: Function body content (first few lines)
    """
    name: str
    line_no: int
    visibility: str
    state_mutability: Optional[str]
    modifiers: List[ModifierInfo] = field(default_factory=list)
    params: List[Tuple[str, str]] = field(default_factory=list)  # (type, name)
    returns: Optional[str] = None
    natspec: Optional[NatSpecInfo] = None
    body: str = ""
    
    def is_access_controlled(self) -> bool:
        """Check if function has access control modifiers."""
        return any(
            m.mod_type == ModifierType.ACCESS_CONTROL 
            for m in self.modifiers
        )
    
    def has_reentrancy_protection(self) -> bool:
        """Check if function has reentrancy protection."""
        return any(
            m.mod_type == ModifierType.REENTRANCY_PROTECTION 
            for m in self.modifiers
        )
    
    def get_categories(self) -> Set[FunctionCategory]:
        """Determine function categories based on actual implementation."""
        categories = set()
        
        # Check state mutability
        if self.state_mutability == "pure":
            categories.add(FunctionCategory.PURE)
        elif self.state_mutability == "view":
            categories.add(FunctionCategory.VIEW)
        elif self.state_mutability == "payable":
            categories.add(FunctionCategory.PAYABLE)
        else:
            categories.add(FunctionCategory.STATE_MODIFYING)
        
        # Check access control
        if self.is_access_controlled():
            categories.add(FunctionCategory.ACCESS_CONTROLLED)
            categories.add(FunctionCategory.ADMINISTRATIVE)
        
        # Check visibility for administrative functions
        if self.visibility in ["internal", "private"]:
            categories.add(FunctionCategory.ADMINISTRATIVE)
        
        return categories


@dataclass
class IntentFinding:
    """Structured finding for intent/implementation mismatches.
    
    Attributes:
        function_name: Name of the function with the issue
        file_path: Path to the source file
        line_no: Line number
        severity: Severity level
        claimed_behavior: What the NatSpec claimed
        actual_behavior: What the code actually does
        description: Detailed description of the mismatch
        evidence: Supporting evidence
    """
    function_name: str
    file_path: str
    line_no: int
    severity: Severity
    claimed_behavior: str
    actual_behavior: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for serialization."""
        return {
            "function_name": self.function_name,
            "file_path": self.file_path,
            "line_no": self.line_no,
            "severity": self.severity.value,
            "claimed_behavior": self.claimed_behavior,
            "actual_behavior": self.actual_behavior,
            "description": self.description,
            "evidence": self.evidence
        }


class ModifierClassifier:
    """Classifier for Solidity modifiers."""
    
    ACCESS_CONTROL_MODIFIERS = {
        "onlyowner", "onlyadmin", "only_role", "onlyrole",
        "auth", "authorized", "onlygovernance", "only_governance",
        "onlydao", "only_dao", "requireauth", "require_auth",
        "onlyvalidator", "only_validator", "onlyoperator", "only_operator"
    }
    
    REENTRANCY_MODIFIERS = {
        "nonreentrant", "non_reentrant", "reentrancyguard",
        "preventreentrancy", "no_reentrancy"
    }
    
    PAUSE_MODIFIERS = {
        "whennotpaused", "when_not_paused", "pausable",
        "notpaused", "not_paused"
    }
    
    STATE_MODIFIERS = {
        "lock", "locked", "mutex", "synchronized"
    }
    
    @classmethod
    def classify(cls, modifier_name: str) -> ModifierType:
        """Classify a modifier by name."""
        name_lower = modifier_name.lower()
        
        if name_lower in cls.ACCESS_CONTROL_MODIFIERS:
            return ModifierType.ACCESS_CONTROL
        elif name_lower in cls.REENTRANCY_MODIFIERS:
            return ModifierType.REENTRANCY_PROTECTION
        elif name_lower in cls.PAUSE_MODIFIERS:
            return ModifierType.PAUSE_CONTROL
        elif name_lower in cls.STATE_MODIFIERS:
            return ModifierType.STATE_MODIFIER
        else:
            return ModifierType.CUSTOM


class NatSpecParser:
    """Parser for Solidity NatSpec comments."""
    
    # Regex patterns for NatSpec tags
    TAG_PATTERNS = {
        "notice": re.compile(
            r"@notice\s+(.+?)(?=\s*@|$)", re.IGNORECASE | re.DOTALL
        ),
        "dev": re.compile(
            r"@dev\s+(.+?)(?=\s*@|$)", re.IGNORECASE | re.DOTALL
        ),
        "param": re.compile(
            r"@param\s+(\w+)\s+(.+?)(?=\s*@|$)", re.IGNORECASE | re.DOTALL
        ),
        "return": re.compile(
            r"@return\s+(.+?)(?=\s*@|$)", re.IGNORECASE | re.DOTALL
        ),
    }
    
    @classmethod
    def parse(cls, comment_text: str) -> NatSpecInfo:
        """Parse NatSpec from comment text.
        
        Handles both /// single-line and /** */ multi-line formats.
        """
        # Normalize comment text
        lines = comment_text.split("\n")
        normalized_lines = []
        
        for line in lines:
            stripped = line.strip()
            # Remove comment markers
            if stripped.startswith("///"):
                normalized_lines.append(stripped[3:].strip())
            elif stripped.startswith("/**"):
                normalized_lines.append(stripped[3:].strip())
            elif stripped.startswith("*/"):
                normalized_lines.append(stripped[2:].strip())
            elif stripped.startswith("*"):
                normalized_lines.append(stripped[1:].strip())
            elif stripped.startswith("//"):
                normalized_lines.append(stripped[2:].strip())
            else:
                normalized_lines.append(stripped)
        
        normalized = " ".join(normalized_lines)
        
        # Extract tags
        notice_match = cls.TAG_PATTERNS["notice"].search(normalized)
        dev_match = cls.TAG_PATTERNS["dev"].search(normalized)
        param_matches = cls.TAG_PATTERNS["param"].findall(normalized)
        return_match = cls.TAG_PATTERNS["return"].search(normalized)
        
        # Build params dict
        params = {}
        for param_name, param_desc in param_matches:
            params[param_name] = param_desc.strip()
        
        return NatSpecInfo(
            notice=notice_match.group(1).strip() if notice_match else None,
            dev=dev_match.group(1).strip() if dev_match else None,
            params=params,
            returns=return_match.group(1).strip() if return_match else None,
            raw=comment_text
        )
    
    @classmethod
    def extract_comment_block(
        cls, lines: List[str], start_idx: int
    ) -> Tuple[str, int]:
        """Extract a complete NatSpec comment block.
        
        Returns:
            Tuple of (comment_text, end_index)
        """
        comment_lines = []
        i = start_idx
        
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            
            # Single-line NatSpec (///)
            if stripped.startswith("///"):
                comment_lines.append(line)
                i += 1
            # Multi-line NatSpec start (/**)
            elif stripped.startswith("/**"):
                comment_lines.append(line)
                i += 1
                # Continue until we find */
                while i < len(lines):
                    comment_lines.append(lines[i])
                    if "*/" in lines[i]:
                        i += 1
                        break
                    i += 1
            # Regular single-line comments
            elif stripped.startswith("//") and not stripped.startswith("///"):
                comment_lines.append(line)
                i += 1
            else:
                break
        
        return "\n".join(comment_lines), i - 1


class FunctionParser:
    """Parser for Solidity function definitions."""
    
    # Pattern to match function definitions
    FUNCTION_PATTERN = re.compile(
        r"function\s+(\w+)\s*\(([^)]*)\)"  # function name(params)
        r"(?:\s+(\w+))?"  # visibility (optional here, captured separately)
        r"(?:\s+(pure|view|payable))?"  # state mutability
        r"((?:\s+\w+(?:\([^)]*\))?)*)",  # modifiers
        re.IGNORECASE
    )
    
    VISIBILITY_PATTERN = re.compile(r"\b(public|external|internal|private)\b")
    MODIFIER_PATTERN = re.compile(r"(\w+)(?:\(([^)]*)\))?")
    
    @classmethod
    def parse(
        cls,
        line: str,
        line_no: int,
        natspec: Optional[NatSpecInfo] = None
    ) -> Optional[FunctionInfo]:
        """Parse a function definition line."""
        match = cls.FUNCTION_PATTERN.search(line)
        if not match:
            return None
        
        func_name = match.group(1)
        params_str = match.group(2)
        visibility = match.group(3) or cls._extract_visibility(line)
        state_mutability = match.group(4)
        modifiers_str = match.group(5) or ""
        
        # Parse parameters
        params = cls._parse_params(params_str)
        
        # Parse modifiers
        modifiers = cls._parse_modifiers(modifiers_str)
        
        return FunctionInfo(
            name=func_name,
            line_no=line_no,
            visibility=visibility or "public",  # Default visibility
            state_mutability=state_mutability,
            modifiers=modifiers,
            params=params,
            natspec=natspec
        )
    
    @classmethod
    def _extract_visibility(cls, line: str) -> Optional[str]:
        """Extract visibility from function line."""
        match = cls.VISIBILITY_PATTERN.search(line)
        return match.group(1) if match else None
    
    @classmethod
    def _parse_params(cls, params_str: str) -> List[Tuple[str, str]]:
        """Parse function parameters."""
        params: List[Tuple[str, str]] = []
        if not params_str.strip():
            return params
        
        # Split by comma, handling nested types
        param_parts = []
        depth = 0
        current = ""
        for char in params_str:
            if char == "(":
                depth += 1
                current += char
            elif char == ")":
                depth -= 1
                current += char
            elif char == "," and depth == 0:
                param_parts.append(current.strip())
                current = ""
            else:
                current += char
        if current.strip():
            param_parts.append(current.strip())
        
        for part in param_parts:
            # Extract type and name (last word is usually the name)
            words = part.split()
            if len(words) >= 2:
                param_name = words[-1]
                param_type = " ".join(words[:-1])
                params.append((param_type, param_name))
            elif len(words) == 1:
                # Just type, no name
                params.append((words[0], ""))
        
        return params
    
    @classmethod
    def _parse_modifiers(cls, modifiers_str: str) -> List[ModifierInfo]:
        """Parse modifier list."""
        modifiers: List[ModifierInfo] = []
        if not modifiers_str:
            return modifiers
        
        # Find all modifier patterns
        for match in cls.MODIFIER_PATTERN.finditer(modifiers_str):
            mod_name = match.group(1)
            mod_args = match.group(2)
            
            # Skip visibility keywords and state mutability
            skip_keywords = [
                "public", "external", "internal", "private",
                "pure", "view", "payable"
            ]
            if mod_name.lower() in skip_keywords:
                continue
            
            args = []
            if mod_args:
                args = [a.strip() for a in mod_args.split(",")]
            
            mod_type = ModifierClassifier.classify(mod_name)
            modifiers.append(ModifierInfo(
                name=mod_name,
                mod_type=mod_type,
                args=args
            ))
        
        return modifiers


class IntentComparator:
    """Compares NatSpec claims against actual implementation."""
    
    @classmethod
    def compare(
        cls, func: FunctionInfo, file_path: str
    ) -> List[IntentFinding]:
        """Compare function NatSpec against implementation.
        
        Returns a list of findings for any mismatches.
        """
        findings: List[IntentFinding] = []
        
        if not func.natspec:
            return findings
        
        # Check 1: Access control mismatch
        findings.extend(cls._check_access_control(func, file_path))
        
        # Check 2: State mutability mismatch
        findings.extend(cls._check_state_mutability(func, file_path))
        
        # Check 3: Visibility vs NatSpec claims
        findings.extend(cls._check_visibility(func, file_path))
        
        return findings
    
    @classmethod
    def _check_access_control(
        cls, func: FunctionInfo, file_path: str
    ) -> List[IntentFinding]:
        """Check for access control mismatches."""
        findings: List[IntentFinding] = []
        natspec = func.natspec
        
        if not natspec:
            return findings
        
        is_protected = func.is_access_controlled()
        claims_restricted = natspec.claims_restricted_access()
        claims_public = natspec.claims_public_access()
        
        # Case 1: Claims restricted but no access control
        if claims_restricted and not is_protected:
            if func.visibility in ["public", "external"]:
                findings.append(IntentFinding(
                    function_name=func.name,
                    file_path=file_path,
                    line_no=func.line_no,
                    severity=Severity.HIGH,
                    claimed_behavior="Restricted access (owner/admin only)",
                    actual_behavior="Public with no access control modifiers",
                    description=(
                        f"Function '{func.name}' claims restricted access "
                        "in NatSpec but lacks access control modifiers"
                    ),
                    evidence={
                        "natspec": natspec.raw[:200],
                        "modifiers": [m.name for m in func.modifiers],
                        "visibility": func.visibility
                    }
                ))
        
        # Case 2: Claims public but has access control
        elif claims_public and is_protected:
            access_mods = [
                m.name for m in func.modifiers
                if m.mod_type == ModifierType.ACCESS_CONTROL
            ]
            findings.append(IntentFinding(
                function_name=func.name,
                file_path=file_path,
                line_no=func.line_no,
                severity=Severity.MEDIUM,
                claimed_behavior="Publicly accessible (anyone can call)",
                actual_behavior="Access-controlled function",
                description=(
                    f"Function '{func.name}' claims to be publicly "
                    "accessible but has access control modifiers"
                ),
                evidence={
                    "natspec": natspec.raw[:200],
                    "access_modifiers": access_mods
                }
            ))
        
        return findings
    
    @classmethod
    def _check_state_mutability(
        cls, func: FunctionInfo, file_path: str
    ) -> List[IntentFinding]:
        """Check for state mutability mismatches."""
        findings: List[IntentFinding] = []
        natspec = func.natspec
        
        if not natspec:
            return findings
        
        claims_view = natspec.claims_view_behavior()
        claims_state_mod = natspec.claims_state_modification()
        
        is_view = func.state_mutability in ["view", "pure"]
        
        # Case 1: Claims view but modifies state
        if claims_view and not is_view and not claims_state_mod:
            findings.append(IntentFinding(
                function_name=func.name,
                file_path=file_path,
                line_no=func.line_no,
                severity=Severity.MEDIUM,
                claimed_behavior="View/read-only function",
                actual_behavior=(
                    f"State-modifying (mutability: "
                    f"{func.state_mutability or 'default'})"
                ),
                description=(
                    f"Function '{func.name}' claims to be read-only "
                    "but may modify state"
                ),
                evidence={
                    "state_mutability": func.state_mutability,
                    "natspec_excerpt": natspec.notice or natspec.dev or ""
                }
            ))
        
        return findings
    
    @classmethod
    def _check_visibility(
        cls, func: FunctionInfo, file_path: str
    ) -> List[IntentFinding]:
        """Check for visibility-related mismatches."""
        findings: List[IntentFinding] = []
        natspec = func.natspec
        
        if not natspec:
            return findings
        
        # Check for internal/private functions with external-facing NatSpec
        if func.visibility in ["internal", "private"]:
            text = f"{natspec.notice or ''} {natspec.dev or ''}".lower()
            external_indicators = ["users can", "callers can", "external"]
            
            if any(ind in text for ind in external_indicators):
                findings.append(IntentFinding(
                    function_name=func.name,
                    file_path=file_path,
                    line_no=func.line_no,
                    severity=Severity.LOW,
                    claimed_behavior="External/user-facing functionality",
                    actual_behavior=(
                        f"{func.visibility} function "
                        "(not externally accessible)"
                    ),
                    description=(
                        f"Function '{func.name}' has external-facing "
                        f"documentation but is {func.visibility}"
                    ),
                    evidence={
                        "visibility": func.visibility,
                        "natspec_excerpt": natspec.notice or ""
                    }
                ))
        
        return findings


class NatSpecAnalyzer:
    """Main analyzer for NatSpec intent vs implementation."""
    
    def __init__(self):
        self.findings: List[IntentFinding] = []
        self.functions: List[FunctionInfo] = []
    
    def analyze_file(
        self, filepath: str
    ) -> List[IntentFinding]:
        """Analyze a Solidity file for intent/implementation mismatches."""
        path = Path(filepath)
        if not path.exists():
            raise CounterscarpValidationError(
                f"File not found: {filepath}",
                details={"path": filepath}
            )
        
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                lines = f.readlines()
        except Exception as e:
            raise CounterscarpAnalysisError(
                f"Failed to read file: {filepath}",
                details={"path": filepath, "error": str(e)}
            ) from e
        
        self.findings = []
        self.functions = []
        
        i = 0
        current_natspec: Optional[NatSpecInfo] = None
        
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            
            # Check for comment start
            is_natspec = (
                stripped.startswith("///") or
                stripped.startswith("/**") or
                stripped.startswith("//")
            )
            if is_natspec:
                comment_block, end_idx = NatSpecParser.extract_comment_block(
                    lines, i
                )
                current_natspec = NatSpecParser.parse(comment_block)
                i = end_idx + 1
                continue
            
            # Check for function definition
            if stripped.startswith("function "):
                func = FunctionParser.parse(stripped, i + 1, current_natspec)
                if func:
                    self.functions.append(func)
                    # Compare and generate findings
                    findings = IntentComparator.compare(func, filepath)
                    self.findings.extend(findings)
                current_natspec = None
            
            # Reset natspec on blank lines or certain keywords
            elif stripped == "" or any(
                stripped.startswith(kw) for kw in
                ["struct ", "contract ", "library ", "interface "]
            ):
                current_natspec = None
            
            i += 1
        
        logger.info(
            f"Analyzed {len(lines)} lines, found {len(self.functions)} "
            f"functions, {len(self.findings)} mismatches"
        )
        return self.findings
    
    def analyze_directory(self, dirpath: str) -> List[IntentFinding]:
        """Analyze all .sol files in a directory."""
        path = Path(dirpath)
        if not path.is_dir():
            raise CounterscarpValidationError(
                f"Not a directory: {dirpath}",
                details={"path": dirpath}
            )
        
        all_findings = []
        for sol_file in path.rglob("*.sol"):
            try:
                findings = self.analyze_file(str(sol_file))
                all_findings.extend(findings)
            except Exception as e:
                logger.warning(f"Failed to analyze {sol_file}: {e}")
        
        return all_findings


# Legacy constants for backward compatibility
TRUST_KEYWORDS = [
    "admin", "owner", "restrict", "internal", "private",
    "lock", "withdraw", "protected", "authorized", "secure"
]
AUTH_MODIFIERS = [
    "onlyOwner", "onlyRole", "auth", "nonReentrant",
    "lock", "whenNotPaused", "onlyGovernance"
]


def analyze_intent(filepath: str, verbose: bool = True) -> List[Dict[str, Any]]:
    """Detects mismatches between developer intent and implementation.

    This is the main entry point called by orchestrator.py and CLI.
    Maintains backward compatibility with the original API.

    Args:
        filepath: Path to the Solidity file or directory to analyze.
        verbose: Whether to print results to console.

    Returns:
        List of finding dictionaries (backward compatible format).
    """
    """
    Detects mismatches between developer intent (NatSpec comments)
    and implementation. Catches psychological security bugs where
    devs *thought* they secured something but didn't.

    This is the main entry point called by orchestrator.py and CLI.
    Maintains backward compatibility with the original API.
    
    Args:
        filepath: Path to the Solidity file or directory to analyze
        verbose: Whether to print results to console
        
    Returns:
        List of finding dictionaries (backward compatible format)
    """
    analyzer = NatSpecAnalyzer()
    
    path = Path(filepath)
    if path.is_dir():
        findings = analyzer.analyze_directory(filepath)
    else:
        findings = analyzer.analyze_file(filepath)
    
    if verbose:
        _print_findings(findings, filepath)
    
    # Convert to backward-compatible format
    return [f.to_dict() for f in findings]


def _print_findings(findings: List[IntentFinding], filepath: str) -> None:
    """Print findings in a formatted way.

    Args:
        findings: List of intent findings to print.
        filepath: Path to the analyzed file.
    """
    print("\n" + "="*60)
    print(" 🤥 LIAR DETECTOR (Comment vs. Code Mismatch)")
    print("="*60)
    
    print(f"\n[*] Analyzed: {filepath}")
    print(f"[*] Detected {len(findings)} intent/implementation mismatches\n")
    
    if not findings:
        print("✅ CLEAN. Code appears to match developer intent.")
        print("   All restricted functions have proper access controls.")
    else:
        print(
            "\033[91m⚠️  CRITICAL: Developer intent does NOT "
            "match implementation!\033[0m"
        )
        print(
            "   These functions have mismatches between "
            "comments and code:\n"
        )
        
        for finding in findings:
            severity_color = {
                Severity.HIGH: "\033[91m",      # Red
                Severity.MEDIUM: "\033[93m",    # Yellow
                Severity.LOW: "\033[94m",       # Blue
                Severity.INFO: "\033[90m"       # Gray
            }.get(finding.severity, "")
            
            print(
                f"{severity_color}[{finding.severity.value}] "
                f"Line {finding.line_no}: {finding.function_name}\033[0m"
            )
            print(f"  • Claimed:  {finding.claimed_behavior}")
            print(f"  • Actual:   {finding.actual_behavior}")
            print(f"  • Issue:    {finding.description}")
            
            if finding.evidence:
                if "modifiers" in finding.evidence:
                    print(f"  • Modifiers: {finding.evidence['modifiers']}")
                if "visibility" in finding.evidence:
                    print(f"  • Visibility: {finding.evidence['visibility']}")

            print(
                "\n  \033[93m💡 FIX: Review and align NatSpec with "
                "implementation.\033[0m"
            )
            print("-" * 60)
    
    print("\n" + "="*60)


# Additional utility functions for advanced usage

def analyze_natspec(filepath: str) -> Dict[str, NatSpecInfo]:
    """Extract NatSpec info for all functions in a file.

    Args:
        filepath: Path to the Solidity file to analyze.

    Returns:
        Mapping of function names to their NatSpec info.
    """
    analyzer = NatSpecAnalyzer()
    analyzer.analyze_file(filepath)
    
    return {
        func.name: func.natspec 
        for func in analyzer.functions 
        if func.natspec
    }


def get_function_info(filepath: str) -> List[FunctionInfo]:
    """Get detailed function information for a file.

    Args:
        filepath: Path to the Solidity file to analyze.

    Returns:
        List of function information objects.
    """
    analyzer = NatSpecAnalyzer()
    analyzer.analyze_file(filepath)
    return analyzer.functions


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description=(
            "🤥 Liar Detector - Scan for Intent/Implementation "
            "mismatches in Solidity contracts"
        )
    )
    parser.add_argument("file", help="The .sol file or directory to analyze")
    parser.add_argument(
        "--json", 
        action="store_true",
        help="Output findings as JSON"
    )
    args = parser.parse_args()
    
    try:
        findings = analyze_intent(args.file, verbose=not args.json)
        
        if args.json:
            import json
            print(json.dumps(findings, indent=2))
            
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        sys.exit(1)
