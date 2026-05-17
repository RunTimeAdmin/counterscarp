from __future__ import annotations

import fnmatch
import os
import re
import argparse
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# Import logger
try:
    from logger import get_logger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

# Initialize logger
logger: logging.Logger
if LOGGER_AVAILABLE:
    logger = get_logger(__name__)
else:
    logger = logging.getLogger(__name__)

# Optional config loader (graceful fallback if not available)
try:
    from config_loader import load_config, CounterscarpConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    CounterscarpConfig = None  # type: ignore[assignment,misc]
    load_config = None  # type: ignore[assignment]

# Optional plugin manager (graceful fallback if not available)
try:
    from plugin_manager import PluginManager
    _PluginManager = PluginManager
    PLUGIN_MANAGER_AVAILABLE = True
except ImportError:
    PLUGIN_MANAGER_AVAILABLE = False
    PluginManager = None  # type: ignore[misc,assignment]


# Compiled regex for inline suppression pragmas (counterscarp-suppress).
# Matches: // counterscarp-suppress: RULE_ID [optional reason]
#          /* counterscarp-suppress: RULE_ID */
#          // counterscarp-suppress: ALL
SUPPRESS_PATTERN = re.compile(r'counterscarp-suppress:\s*(\w+)(?:\s+(.*))?')

# Module-level cache for DEFAULT_SAFE_PATTERNS (Task M5)
_DEFAULT_SAFE_PATTERNS_CACHE: Optional[List] = None


def _get_safe_patterns() -> List[Any]:
    """Return DEFAULT_SAFE_PATTERNS, importing and caching on first call."""
    global _DEFAULT_SAFE_PATTERNS_CACHE
    if _DEFAULT_SAFE_PATTERNS_CACHE is None:
        try:
            from config_loader import DEFAULT_SAFE_PATTERNS
            _DEFAULT_SAFE_PATTERNS_CACHE = DEFAULT_SAFE_PATTERNS
        except ImportError:
            _DEFAULT_SAFE_PATTERNS_CACHE = []
    return _DEFAULT_SAFE_PATTERNS_CACHE


# Rule categories: groups rule IDs by security domain for coverage reporting.
RULE_CATEGORIES: dict[str, list[str]] = {
    "Access Control": [
        "TX_ORIGIN_USAGE", "DELEGATECALL_USAGE", "EMERGENCY_WITHDRAW_PUBLIC",
        "FAKE_RENOUNCE_OWNER_ZERO", "CENTRALIZATION_RISK",
    ],
    "Reentrancy & External Calls": [
        "UNCHECKED_EXTERNAL_CALL", "LOWLEVEL_CALL_USAGE",
        "FLASH_LOAN_REENTRANCY", "ARBITRARY_EXTERNAL_CALL",
        "TRANSFER_DOSABLE_FALLBACK",
    ],
    "DeFi & Oracle Security": [
        "ORACLE_STALENESS_CHECK", "MISSING_SLIPPAGE_PROTECTION",
        "STRICT_BALANCE_EQUALITY",
    ],
    "Math & Precision": [
        "DIVIDE_BEFORE_MULTIPLY", "UNSAFE_CAST", "MSG_VALUE_LOOP",
    ],
    "Token Mechanics": [
        "HIDDEN_MINT", "TRADING_TOGGLE_BOOL", "SET_FEE_FUNCTION",
    ],
    "Upgrade & Proxy Patterns": [
        "STORAGE_COLLISION_RISK", "UPGRADE_FUNCTION",
    ],
    "Cryptographic & Signature": [
        "SIGNATURE_REPLAY", "BLOCK_TIMESTAMP_RANDOMNESS",
        "BLOCKHASH_RANDOMNESS",
    ],
    "Storage & Memory": [
        "ARRAY_LENGTH_UNDERFLOW",
    ],
    "Other": [
        "HARDCODED_ADDRESS", "BOOLEAN_TRANSFER_CHECK",
    ],
    "Hook Vulnerabilities": [
        "TI-084", "TI-085", "TI-086",
    ],
}


@dataclass
class HeuristicFinding:
    """Represents a heuristic scan finding.

    Attributes:
        rule_id: The ID of the rule that triggered this finding.
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).
        message: Human-readable description of the finding.
        file: Path to the file where the finding occurred.
        line_no: Line number where the finding occurred.
        line_text: The actual code line that triggered the finding.
        suppressed: Whether this finding is suppressed by config.
        suppression_reason: Reason for suppression if applicable.
        confidence: Confidence score for this finding (1-10 scale).
    """
    rule_id: str
    severity: str
    message: str
    file: str
    line_no: int
    line_text: str
    suppressed: bool = False
    suppression_reason: str = ""
    confidence: int = 5  # 1-10 scale
    similar_locations: List[str] = field(default_factory=list)
    duplicate_count: int = 0


def _deduplicate_findings(findings: List['HeuristicFinding']) -> List['HeuristicFinding']:
    """Collapse duplicate rule_id hits within the same file and line region."""
    seen: Dict[tuple, 'HeuristicFinding'] = {}
    for f in findings:
        line_bucket = (f.line_no // 3) * 3
        key = (f.rule_id, f.file, line_bucket)
        if key in seen:
            seen[key].similar_locations.append(f"{f.file}:{f.line_no}")
            seen[key].duplicate_count += 1
        else:
            seen[key] = f
    return list(seen.values())


@dataclass
class HeuristicRule:
    """Represents a heuristic detection rule.

    Attributes:
        id: Unique identifier for this rule.
        description: Human-readable description of what this rule detects.
        severity: Default severity level for findings from this rule.
        pattern: Compiled regex pattern to match against code.
        hint: Remediation hint for developers.
        confidence: Confidence score for findings from this rule (1-10 scale).
        refine: Optional callable for post-match refinement. Receives
            (line, match, lines, line_idx) and returns True to keep the
            finding or False to skip it.
    """
    id: str
    description: str
    severity: str
    pattern: re.Pattern[str]
    hint: str
    confidence: int = 5  # 1-10 scale
    refine: Optional[Callable[["HeuristicFinding", List[str], int], bool]] = None


# ---------------------------------------------------------------------------
# Per-rule refinement callables
# Each function receives (finding, lines, line_idx) where:
#   finding  – the HeuristicFinding already created for this match
#   lines    – all source lines of the file (0-based list)
#   line_idx – 0-based index of the matching line
# Return True  → keep the finding (possibly mutated in-place)
# Return False → discard the finding entirely
# ---------------------------------------------------------------------------

def _refine_block_timestamp(
    finding: "HeuristicFinding", lines: List[str], line_idx: int
) -> bool:
    """Refine BLOCK_TIMESTAMP_RANDOMNESS severity based on surrounding context."""
    line_lower = finding.line_text.lower()
    # Deadline comparison pattern — standard DeFi practice
    if any(op in line_lower for op in [">=", "<=", "> ", "< ", "require(", "assert("]) and \
       any(kw in line_lower for kw in ["deadline", "expir", "timeout", "valid"]):
        finding.severity = "INFO"
        finding.message = "block.timestamp used for deadline comparison (standard practice)"
        finding.confidence = 1
    # Even without deadline keywords, comparison operators suggest conditional check, not randomness
    elif any(op in finding.line_text for op in [">=", "<=", ">", "<"]) and "%" not in finding.line_text:
        finding.severity = "INFO"
        finding.message = "block.timestamp used in comparison (likely deadline check)"
        finding.confidence = 2
    # Modulo or arithmetic — potential randomness
    elif "%" in finding.line_text or "keccak256" in finding.line_text:
        finding.severity = "HIGH"
        finding.message = "block.timestamp used for randomness or entropy (exploitable by miners)"
        finding.confidence = 7
    return True


def _refine_hardcoded_address(
    finding: "HeuristicFinding", lines: List[str], line_idx: int
) -> bool:
    """Suppress HARDCODED_ADDRESS findings that are actually bytes32 constants."""
    line_upper = finding.line_text.upper()
    if any(kw in line_upper for kw in ["TYPEHASH", "MASK", "SLOT", "SELECTOR",
                                        "DOMAIN_SEPARATOR", "PERMIT", "DIRTY", "BITS"]):
        finding.suppressed = True
        finding.suppression_reason = "bytes32 constant, not an address"
    return True


def _refine_unchecked_external_call(
    finding: "HeuristicFinding", lines: List[str], line_idx: int
) -> bool:
    """Refine UNCHECKED_EXTERNAL_CALL severity based on return-value handling."""
    line_text = finding.line_text.strip()
    # Check if return value is captured: (bool success, ...) = ...
    if re.search(r'\(\s*bool\s+\w+', line_text):
        # Return captured — check next few lines for verification
        check_lines = ""
        for offset in range(1, 4):
            if finding.line_no + offset - 1 < len(lines):
                check_lines += lines[finding.line_no + offset - 1]
        if re.search(r'require\s*\(|assert\s*\(|if\s*\(\s*!?\s*success', check_lines):
            finding.severity = "INFO"
            finding.message = "External call with captured and verified return value"
            finding.confidence = 1
        else:
            finding.severity = "HIGH"
            finding.message = "External call return value captured but not verified"
            finding.confidence = 6
    # Also check for try/catch pattern
    elif "try " in line_text or line_text.startswith("try"):
        finding.severity = "INFO"
        finding.message = "External call wrapped in try/catch"
        finding.confidence = 1
    return True


# Core heuristic rules. These complement Slither/Mythril with simple
# pattern-based checks that are easy to understand and extend.
RULES: List[HeuristicRule] = [
    HeuristicRule(
        id="TX_ORIGIN_USAGE",
        description="Use of tx.origin (dangerous for auth checks)",
        severity="HIGH",
        pattern=re.compile(r"tx\.origin"),
        hint="Avoid tx.origin for authorization; use msg.sender and proper role-based access control.",
        confidence=6,
    ),
    HeuristicRule(
        id="BLOCK_TIMESTAMP_RANDOMNESS",
        description="Use of block.timestamp / now (weak randomness)",
        severity="MEDIUM",
        pattern=re.compile(r"block\.timestamp|\bnow\b"),
        hint="Do not use block.timestamp/now as randomness; use VRF or off-chain randomness.",
        confidence=2,
        refine=_refine_block_timestamp,
    ),
    HeuristicRule(
        id="DELEGATECALL_USAGE",
        description="Use of delegatecall (upgradeable/proxy risk)",
        severity="HIGH",
        pattern=re.compile(r"delegatecall\s*\("),
        hint="Ensure delegatecall targets are trusted and immutable; review proxy patterns carefully.",
        confidence=8,
    ),
    HeuristicRule(
        id="LOWLEVEL_CALL_USAGE",
        description="Use of low-level call (call(), staticcall(), callcode())",
        severity="MEDIUM",
        pattern=re.compile(r"\.call\s*\(|\.staticcall\s*\("),
        hint="Wrap low-level calls with return value checks and reentrancy protection.",
        confidence=2,
    ),
    HeuristicRule(
        id="HARDCODED_ADDRESS",
        description="Hardcoded address literal in code",
        severity="INFO",
        pattern=re.compile(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])"),
        hint="Verify hardcoded addresses are correct and documented; consider configurability.",
        confidence=1,
        refine=_refine_hardcoded_address,
    ),
    HeuristicRule(
        id="EMERGENCY_WITHDRAW_PUBLIC",
        description="Function name suggests emergency withdraw / rescue funds",
        severity="HIGH",
        pattern=re.compile(r"function\s+(emergencyWithdraw|withdrawAll|rescue|drain)\b"),
        hint="Ensure emergency/withdraw/rescue functions are admin-only and ideally timelocked.",
        confidence=6,
    ),
    HeuristicRule(
        id="UPGRADE_FUNCTION",
        description="Function name suggests upgrade or ownership change",
        severity="HIGH",
        pattern=re.compile(r"function\s+(upgradeTo|upgrade|setOwner|transferOwnership)\b"),
        hint="Confirm these functions are protected by strong access control (multi-sig, timelock).",
        confidence=5,
    ),
    # Kill Chain / Behavioral / Math heuristics (first-pass approximations)
    HeuristicRule(
        id="MSG_VALUE_LOOP",
        description="msg.value used inside a loop (possible double-credit per iteration)",
        severity="HIGH",
        pattern=re.compile(r"(for|while)\s*\(.*msg\.value"),
        hint="Ensure deposits are not multiplied by loop iterations; track value per user, not per iteration.",
        confidence=7,
    ),
    HeuristicRule(
        id="STRICT_BALANCE_EQUALITY",
        description="Strict equality on address(this).balance (fragile invariant)",
        severity="HIGH",
        pattern=re.compile(r"address\(this\)\.balance\s*=="),
        hint="Use >= or more robust accounting; forced ETH sends can break strict equality.",
        confidence=6,
    ),
    HeuristicRule(
        id="HIDDEN_MINT",
        description="_mint() call (possible hidden mint path)",
        severity="HIGH",
        pattern=re.compile(r"_mint\s*\("),
        hint="Review all mint paths; ensure they are expected (e.g., only in public mint/claim functions).",
        confidence=5,
    ),
    HeuristicRule(
        id="FAKE_RENOUNCE_OWNER_ZERO",
        description="owner set to address(0) (possible fake renounce)",
        severity="MEDIUM",
        pattern=re.compile(r"owner\s*=\s*address\(0\)"),
        hint="Verify there is no parallel manager/admin role keeping effective control.",
        confidence=3,
    ),
    HeuristicRule(
        id="TRADING_TOGGLE_BOOL",
        description="Presence of trading enable/disable boolean (possible honeypot)",
        severity="MEDIUM",
        pattern=re.compile(r"bool\s+(trading(Open|Enabled)|tradingOpen|tradingEnabled)"),
        hint="Ensure trading toggles are time-bound, documented, and not abusable to trap liquidity.",
        confidence=3,
    ),
    HeuristicRule(
        id="SET_FEE_FUNCTION",
        description="Configurable fee setter without obvious cap (possible fee rug)",
        severity="MEDIUM",
        pattern=re.compile(r"function\s+set(Fee|Tax)"),
        hint="Check for upper bounds on new fee values (e.g., <= 25%).",
        confidence=4,
    ),
    HeuristicRule(
        id="DIVIDE_BEFORE_MULTIPLY",
        description="Potential precision loss: division before multiplication",
        severity="MEDIUM",
        pattern=re.compile(r"\b\w+\s*/\s*\w+\s*\*\s*\w+"),
        hint="Prefer (a * c) / b over (a / b) * c to avoid rounding to zero.",
        confidence=4,
    ),
    HeuristicRule(
        id="BOOLEAN_TRANSFER_CHECK",
        description="Checking boolean return on ERC20.transfer (may be wrong with some libs)",
        severity="INFO",
        pattern=re.compile(r"if\s*\(!\s*\w+\.transfer\s*\("),
        hint="Ensure this pattern matches the token library semantics (e.g., Solmate SafeTransferLib reverts instead of returning bool).",
        confidence=1,
    ),
    
    # ========== BUG BOUNTY PATTERNS (High-value Immunefi/Code4rena targets) ==========
    
    HeuristicRule(
        id="UNCHECKED_EXTERNAL_CALL",
        description="Low-level call/transfer without return value check (funds may be lost)",
        severity="CRITICAL",
        pattern=re.compile(r"(\w+(?:\([^)]*\))?)\.(call[{(]|transfer\(|transferFrom\()"),
        hint="CRITICAL: Always check return values of external calls. Unchecked calls are top bug bounty targets ($10K-$100K).",
        confidence=9,
        refine=_refine_unchecked_external_call,
    ),
    
    HeuristicRule(
        id="ORACLE_STALENESS_CHECK",
        description="Chainlink oracle without staleness/validity check (price manipulation risk)",
        severity="CRITICAL",
        pattern=re.compile(r"(latestAnswer|latestRoundData)\(\)(?!.*require.*updatedAt|.*block\.timestamp)"),
        hint="CRITICAL: Check updatedAt timestamp and answeredInRound to prevent stale price attacks ($50K-$500K bounties).",
        confidence=9,
    ),
    
    HeuristicRule(
        id="SIGNATURE_REPLAY",
        description="Signature verification without nonce/deadline protection (replay attack)",
        severity="HIGH",
        pattern=re.compile(r"ecrecover\((?!.*nonce|.*deadline)"),
        hint="HIGH: Add nonce and deadline to prevent signature replay attacks. Common in account abstraction ($20K-$100K).",
        confidence=8,
    ),
    
    HeuristicRule(
        id="FLASH_LOAN_REENTRANCY",
        description="Flash loan callback without reentrancy protection",
        severity="CRITICAL",
        pattern=re.compile(r"function\s+\w*flash\w*.*\{(?!.*nonReentrant|.*ReentrancyGuard)"),
        hint="CRITICAL: Flash loan callbacks must have nonReentrant modifier. Major DeFi exploit vector ($100K-$1M+ bounties).",
        confidence=10,
    ),
    
    HeuristicRule(
        id="STORAGE_COLLISION_RISK",
        description="Upgradeable proxy pattern detected - verify storage layout",
        severity="HIGH",
        pattern=re.compile(r"(UUPS|TransparentUpgradeableProxy|initializer|__gap)"),
        hint="HIGH: Storage collisions in upgrades can brick contracts. Use storage gap patterns and OpenZeppelin guidelines ($30K-$200K).",
        confidence=8,
    ),
    
    HeuristicRule(
        id="UNSAFE_CAST",
        description="Unsafe type casting (uint256 -> uint128/uint64) without bounds check",
        severity="HIGH",
        pattern=re.compile(r"uint(128|64|32|16|8)\(\w+\)(?!.*require|.*assert)"),
        hint="HIGH: Downcasting without overflow check can cause critical bugs. Use SafeCast library ($10K-$50K).",
        confidence=7,
    ),
    
    HeuristicRule(
        id="MISSING_SLIPPAGE_PROTECTION",
        description="DEX swap without minimum output amount (MEV/sandwich attack)",
        severity="HIGH",
        pattern=re.compile(r"(swapExactTokensFor|swap)\(.*,\s*0\s*[,\)]"),
        hint="HIGH: Zero slippage protection allows MEV bots to sandwich trade. Always set minAmountOut ($5K-$30K).",
        confidence=7,
    ),
    
    HeuristicRule(
        id="CENTRALIZATION_RISK",
        description="Single owner can upgrade/pause/withdraw without timelock",
        severity="MEDIUM",
        pattern=re.compile(r"function\s+(pause|unpause|setImplementation)\s*\(.*\).*onlyOwner(?!.*timelock)"),
        hint="MEDIUM: Centralization risk. Use multi-sig + timelock for critical admin functions. Common Code4rena Medium finding.",
        confidence=4,
    ),

    # ========== STORAGE & MEMORY PATTERNS ==========

    HeuristicRule(
        id="BLOCKHASH_RANDOMNESS",
        description="Use of blockhash() for randomness — predictable and manipulable by miners",
        severity="MEDIUM",
        pattern=re.compile(r"blockhash\s*\("),
        hint="Do not use blockhash() for randomness; use Chainlink VRF or commit-reveal schemes.",
        confidence=3,
    ),

    HeuristicRule(
        id="ARRAY_LENGTH_UNDERFLOW",
        description="Direct array length manipulation may cause storage collision in Solidity < 0.8",
        severity="HIGH",
        pattern=re.compile(r"\.length\s*(?:--|=\s*0\s*-|-=)"),
        hint="Avoid manipulating array.length directly. Use pop() or ensure Solidity >= 0.8 for overflow protection.",
        confidence=5,
    ),

    HeuristicRule(
        id="TRANSFER_DOSABLE_FALLBACK",
        description="ETH transfer to msg.sender or variable address may be blocked by reverting fallback (King-style DoS)",
        severity="MEDIUM",
        pattern=re.compile(r"\.transfer\s*\(|\.send\s*\("),
        hint="Prefer pull-payment pattern or use call() with reentrancy guards instead of transfer()/send().",
        confidence=3,
    ),

    # ========== UNISWAP V4 HOOK VULNERABILITY PATTERNS (TI-084, TI-085, TI-086) ==========

    HeuristicRule(
        id="TI-084",
        description="[TI-084] PoolManager Access Control Bypass: Uniswap V4 hook callback function missing msg.sender == poolManager guard",
        severity="CRITICAL",
        pattern=re.compile(
            r"function\s+(?:beforeSwap|afterSwap|beforeAddLiquidity|afterAddLiquidity|"
            r"beforeRemoveLiquidity|afterRemoveLiquidity|beforeDonate|afterDonate)\s*\(",
            re.IGNORECASE,
        ),
        hint="[TI-084] CRITICAL: All V4 hook callbacks must restrict callers to the official PoolManager via "
             "require(msg.sender == address(poolManager)). Without this guard an attacker can invoke the hook "
             "directly to corrupt fee accumulators, LP reward points, or governance state without executing a "
             "real pool operation. Add an onlyPoolManager modifier or inline require check.",
        confidence=9,
    ),

    HeuristicRule(
        id="TI-085",
        description="[TI-085] Flash Accounting Delta Settlement Failure: Uniswap V4 hook after-liquidity callback accepts BalanceDelta parameter — verify poolManager.settle()/take() are called to resolve transient storage debt",
        severity="CRITICAL",
        pattern=re.compile(
            r"function\s+(?:afterAddLiquidity|afterRemoveLiquidity)\s*\(",
            re.IGNORECASE,
        ),
        hint="[TI-085] CRITICAL: Uniswap V4 uses EIP-1153 transient storage for flash accounting — all "
             "BalanceDelta values MUST settle to zero before the transaction ends. A hook that accepts a "
             "BalanceDelta parameter and returns without calling poolManager.settle() or take() leaves the "
             "pool's transient debt imbalanced and can be exploited to drain tokens. Ensure every "
             "afterAddLiquidity / afterRemoveLiquidity callback calls poolManager.settle() or properly "
             "accounts for any take() calls before returning.",
        confidence=9,
    ),

    HeuristicRule(
        id="TI-086",
        description="[TI-086] Custom Oracle Manipulation: Uniswap V4 hook updates price state in beforeSwap without TWAP protection",
        severity="HIGH",
        pattern=re.compile(
            r"function\s+beforeSwap\s*\([^)]*\)[^{]*\{[^}]*(?:price|oracle|lastPrice|priceAccumulator|reserve)\s*[+\-*]?=",
            re.DOTALL,
        ),
        hint="[TI-086] HIGH: Updating an oracle/price variable inside beforeSwap() without time-weighted "
             "smoothing allows single-transaction flash loan manipulation. Add a minimum observation window, "
             "TWAP accumulator, or multi-block validation before recording price state.",
        confidence=7,
    ),
]

# Alias used by webapp and coverage helpers
HEURISTIC_RULES: List[HeuristicRule] = RULES


def get_scan_coverage() -> dict:
    """Return scan coverage metadata for the heuristic scanner."""
    return {
        "analyzer": "Heuristic Pattern Scanner",
        "version": "2.3.0",
        "total_patterns": len(RULES),
        "categories": {
            cat: len(rules)
            for cat, rules in RULE_CATEGORIES.items()
        },
    }


def get_all_rules(plugin_mgr: Optional[PluginManager] = None) -> List[HeuristicRule]:
    """Return built-in rules plus any plugin-contributed rules.

    Args:
        plugin_mgr: Optional PluginManager instance to load plugin rules from.

    Returns:
        List of all heuristic rules (built-in + plugin rules).
    """
    all_rules = list(RULES)
    if plugin_mgr:
        try:
            plugin_rules = plugin_mgr.get_rules()
            all_rules.extend(plugin_rules)
            if plugin_rules:
                logger.info(
                    "Loaded %d built-in + %d plugin rules",
                    len(RULES), len(plugin_rules)
                )
        except Exception as exc:
            logger.warning("Failed to load plugin rules: %s", exc)
    return all_rules


def _check_inline_suppression(
    lines: List[str], line_idx: int, rule_id: str
) -> Tuple[bool, str]:
    """Check current line and line above for a counterscarp-suppress pragma.

    Args:
        lines: All lines of the file (0-based list).
        line_idx: 0-based index of the line that triggered the finding.
        rule_id: The rule ID to check suppression for.

    Returns:
        Tuple of (is_suppressed, reason_string).
    """
    for check_idx in (line_idx, line_idx - 1):
        if 0 <= check_idx < len(lines):
            match = SUPPRESS_PATTERN.search(lines[check_idx])
            if match:
                suppressed_rule = match.group(1)
                reason = match.group(2) or "inline suppression"
                if suppressed_rule == rule_id or suppressed_rule == "ALL":
                    return True, reason.strip()
    return False, ""


def is_in_code_context(line: str, match_start: int) -> bool:
    """Check if a regex match is in actual code vs. a comment or string literal.

    Args:
        line: The line of code being analyzed.
        match_start: The starting position of the match in the line.

    Returns:
        True if the match is in actual code (not comment/string), False otherwise.
    """
    # Check for single-line comments (//)
    # If match is after //, it's in a comment
    comment_pos = line.find('//')
    if comment_pos != -1 and match_start > comment_pos:
        return False

    # Check for string literals
    # We need to track whether match_start is inside "..." or '...'
    in_double_quote = False
    in_single_quote = False
    escape_next = False

    for i, char in enumerate(line):
        if i >= match_start:
            # We've reached the match position, check state
            break

        if escape_next:
            escape_next = False
            continue

        if char == '\\':
            escape_next = True
            continue

        if char == '"' and not in_single_quote:
            in_double_quote = not in_double_quote
        elif char == "'" and not in_double_quote:
            in_single_quote = not in_single_quote

    # If we're inside a string literal, the match is not in code context
    if in_double_quote or in_single_quote:
        return False

    return True


def _build_comment_map(lines: List[str]) -> List[bool]:
    """Build a per-line boolean map indicating multi-line comment state (Task H6).

    Makes a single O(n) pass through all lines and returns a list of booleans
    where ``True`` at index ``i`` means line ``i`` begins while the parser is
    already inside a ``/* ... */`` block (i.e. the first character of that line
    is inside a comment).

    Handles multiple ``/*`` and ``*/`` tokens on the same line correctly, which
    mirrors the logic used by :func:`is_in_multiline_comment`.

    Args:
        lines: All lines of the file (as returned by ``f.readlines()``).

    Returns:
        A ``List[bool]`` of the same length as *lines*.
    """
    result: List[bool] = []
    in_comment = False

    for line in lines:
        # Record whether this line *starts* inside a comment
        result.append(in_comment)

        # Walk the whole line to update the comment state for the next line
        pos = 0
        while pos < len(line):
            if not in_comment:
                open_pos = line.find('/*', pos)
                if open_pos == -1:
                    break
                in_comment = True
                pos = open_pos + 2
            else:
                close_pos = line.find('*/', pos)
                if close_pos == -1:
                    break
                in_comment = False
                pos = close_pos + 2

    return result


# DEPRECATED: use _build_comment_map() + comment_map[line_idx] instead.
# Kept for backward compatibility with any external callers.
def is_in_multiline_comment(
    lines: List[str], line_idx: int, match_start: int
) -> bool:
    """Check if a position is inside a multi-line comment (/* */).

    .. deprecated::
        Build a comment map once with :func:`_build_comment_map` and index it
        instead of calling this function per-match (O(n²) → O(n)).

    Args:
        lines: All lines of the file.
        line_idx: Index of the current line (0-based).
        match_start: Starting position in the current line.

    Returns:
        True if the position is inside a multi-line comment.
    """
    in_multiline_comment = False

    for i in range(line_idx + 1):
        line = lines[i]

        if i < line_idx:
            # For previous lines, just track comment state
            pos = 0
            while pos < len(line):
                if not in_multiline_comment:
                    comment_start = line.find('/*', pos)
                    if comment_start == -1:
                        break
                    in_multiline_comment = True
                    pos = comment_start + 2
                else:
                    comment_end = line.find('*/', pos)
                    if comment_end == -1:
                        break
                    in_multiline_comment = False
                    pos = comment_end + 2
        else:
            # For current line, check up to match_start
            pos = 0
            while pos < match_start:
                if not in_multiline_comment:
                    comment_start = line.find('/*', pos)
                    if comment_start == -1 or comment_start >= match_start:
                        break
                    in_multiline_comment = True
                    pos = comment_start + 2
                else:
                    comment_end = line.find('*/', pos)
                    if comment_end == -1:
                        break
                    in_multiline_comment = False
                    pos = comment_end + 2

    return in_multiline_comment


def _check_safe_patterns(
    finding: "HeuristicFinding",
    header_text: str,
    safe_patterns: Optional[List[Any]] = None,
) -> None:
    """Check if a finding matches a known-safe library pattern and downgrade severity.

    Scans the precomputed file header text for known import/inheritance patterns
    (e.g., OpenZeppelin, Uniswap). When a match is found, the finding's severity
    is downgraded and an explanatory note is appended to the message.

    Args:
        finding: The HeuristicFinding to (potentially) modify in-place.
        header_text: Precomputed source header text (typically first 100 lines).
        safe_patterns: Override list of SafePattern objects. Defaults to
            DEFAULT_SAFE_PATTERNS from config_loader.
    """
    if CONFIG_AVAILABLE:
        patterns = safe_patterns if safe_patterns is not None else _get_safe_patterns()
    else:
        return

    for sp in patterns:
        if sp.rule_id != finding.rule_id:
            continue
        if re.search(sp.pattern, header_text):
            finding.severity = sp.downgrade_to
            finding.message = f"{finding.message} [{sp.library}: {sp.reason}]"
            finding.confidence = max(1, finding.confidence - 3)
            break  # First match wins


def _read_source_file(path: str) -> Optional[Tuple[List[str], str]]:
    """Open *path* and return ``(lines, content)`` or ``None`` on I/O error.

    Args:
        path: Path to the Solidity source file.

    Returns:
        Tuple of (lines list, joined content string) on success, or None if
        the file cannot be read.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            content = "".join(lines)
        return lines, content
    except OSError as e:
        logger.warning("Failed to read file %s: %s", path, e)
        return None


def _create_finding(
    rule: "HeuristicRule",
    effective_severity: str,
    path: str,
    line_no: int,
    line: str,
) -> "HeuristicFinding":
    """Construct a :class:`HeuristicFinding` from a rule match.

    Args:
        rule: The rule that triggered.
        effective_severity: Resolved severity (may differ from rule default due to config override).
        path: Path to the scanned file.
        line_no: 1-based line number of the match.
        line: Raw line text (will be rstripped of newline).

    Returns:
        A freshly constructed HeuristicFinding.
    """
    return HeuristicFinding(
        rule_id=rule.id,
        severity=effective_severity,
        message=rule.description,
        file=path,
        line_no=line_no,
        line_text=line.rstrip("\n"),
        confidence=rule.confidence,
    )


def _apply_suppressions(
    finding: "HeuristicFinding",
    lines: List[str],
    line_idx: int,
    config: Optional["CounterscarpConfig"],
    path: str,
) -> None:
    """Apply inline and config-based suppressions to *finding* in-place.

    Args:
        finding: The finding to (potentially) mark as suppressed.
        lines: All source lines of the file.
        line_idx: 0-based index of the matching line.
        config: Optional config for rule-based suppressions.
        path: Path to the scanned file (used for config lookup).
    """
    suppressed, suppression_reason = _check_inline_suppression(lines, line_idx, finding.rule_id)
    if suppressed:
        finding.suppressed = True
        finding.suppression_reason = suppression_reason
        logger.debug(
            "Inline suppression applied for %s at %s:%d: %s",
            finding.rule_id, path, finding.line_no, suppression_reason,
        )
        return

    if config:
        suppression = config.is_finding_suppressed(finding.rule_id, path, finding.line_no)
        if suppression:
            finding.suppressed = True
            finding.suppression_reason = suppression.reason


def _scan_lines_for_rules(
    lines: List[str],
    path: str,
    all_rules: List["HeuristicRule"],
    config: Optional["CounterscarpConfig"],
) -> List["HeuristicFinding"]:
    """Scan *lines* rule-by-rule and return raw findings (pre-dedup).

    Performs the per-line, per-rule pattern matching loop including:
    - single-line comment / string-literal filtering via :func:`is_in_code_context`
    - multi-line comment filtering via :func:`_build_comment_map`
    - finding construction via :func:`_create_finding`
    - suppression via :func:`_apply_suppressions`
    - per-rule refinement callbacks
    - safe-pattern downgrading via :func:`_check_safe_patterns`

    Args:
        lines: Source lines of the file to scan.
        path: File path (used for finding metadata and logging).
        all_rules: Full rule list (built-in + plugin).
        config: Optional scanner configuration.

    Returns:
        List of HeuristicFinding objects (not yet deduplicated).
    """
    findings: List[HeuristicFinding] = []
    comment_map = _build_comment_map(lines)
    header_text = "".join(lines[:min(100, len(lines))])

    active_rules: List[Tuple["HeuristicRule", str]] = []
    if config and config.heuristics:
        for rule in all_rules:
            if not config.heuristics.is_rule_enabled(rule.id):
                continue
            effective_severity = config.heuristics.get_rule_severity(rule.id, rule.severity)
            active_rules.append((rule, effective_severity))
    else:
        active_rules = [(rule, rule.severity) for rule in all_rules]

    safe_patterns_by_rule: Dict[str, List[Any]] = {}
    if CONFIG_AVAILABLE:
        safe_patterns = _get_safe_patterns()
        for pattern in safe_patterns:
            safe_patterns_by_rule.setdefault(pattern.rule_id, []).append(pattern)

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("//"):
            continue  # Skip comment-only lines early

        for rule, effective_severity in active_rules:
            if not rule.pattern.search(line):
                continue

            for match in rule.pattern.finditer(line):
                match_start = match.start()

                if not is_in_code_context(line, match_start):
                    logger.debug(
                        "Skipping match for %s in comment/string at %s:%d:%d",
                        rule.id, path, i, match_start,
                    )
                    continue

                if comment_map[i - 1]:
                    logger.debug(
                        "Skipping match for %s in multi-line comment at %s:%d:%d",
                        rule.id, path, i, match_start,
                    )
                    continue

                finding = _create_finding(rule, effective_severity, path, i, line)
                _apply_suppressions(finding, lines, i - 1, config, path)

                if rule.refine and not rule.refine(finding, lines, i - 1):
                    continue

                _check_safe_patterns(
                    finding,
                    header_text=header_text,
                    safe_patterns=safe_patterns_by_rule.get(finding.rule_id),
                )
                findings.append(finding)
                break  # One finding per rule per line

    return findings


def _scan_arbitrary_external_calls(
    content: str,
    path: str,
    config: Optional["CounterscarpConfig"],
) -> List["HeuristicFinding"]:
    """H-05: function-level scan for unprotected arbitrary external calls.

    Splits the file content on ``function`` keywords and checks each block for
    a public/external function whose caller controls both the target address and
    the calldata — without access-control modifiers.

    Args:
        content: Full file content as a single string.
        path: File path (used for finding metadata and suppression lookup).
        config: Optional scanner configuration.

    Returns:
        List of HeuristicFinding objects for any matched functions.
    """
    findings: List[HeuristicFinding] = []
    functions = content.split("function ")

    for func_block in functions[1:]:  # Skip preamble before first 'function'
        header_match = re.search(
            r"^(\w+)\s*\((.*?)\).*?(public|external)", func_block, re.DOTALL
        )
        if not header_match:
            continue

        func_name = header_match.group(1)
        params = header_match.group(2)
        header = func_block.split("{")[0]

        if "address" not in params or ("bytes" not in params and "calldata" not in params):
            continue

        if re.search(r"(onlyOwner|auth|onlyRole)", header):
            continue

        call_match = re.search(r"(\w+)\.call\s*\{.*\}\s*\(\s*(\w+)\s*\)", func_block)
        if not call_match:
            continue

        target_var = call_match.group(1)
        data_var = call_match.group(2)

        if target_var in params and data_var in params:
            finding = HeuristicFinding(
                rule_id="ARBITRARY_EXTERNAL_CALL",
                severity="HIGH",
                message="Unprotected arbitrary external call: user controls target and calldata.",
                file=path,
                line_no=0,
                line_text=f"function {func_name}(...)",
                confidence=7,
            )
            if config:
                suppression = config.is_finding_suppressed("ARBITRARY_EXTERNAL_CALL", path, 0)
                if suppression:
                    finding.suppressed = True
                    finding.suppression_reason = suppression.reason
            findings.append(finding)

    return findings


def scan_file(
    path: str,
    config: Optional[CounterscarpConfig] = None,
    plugin_mgr: Optional[PluginManager] = None
) -> List[HeuristicFinding]:
    """Scan a single .sol file and return heuristic findings.

    Args:
        path: Path to the Solidity file to scan.
        config: Optional configuration object for rule enablement and suppressions.
        plugin_mgr: Optional PluginManager to load plugin rules from.

    Returns:
        List of heuristic findings for the file.
    """
    # Guard: heuristics disabled
    heuristics_enabled = True
    if config and config.heuristics:
        heuristics_enabled = config.heuristics.enabled
    if not heuristics_enabled:
        return []

    # Read source — bail early on I/O failure
    result = _read_source_file(path)
    if result is None:
        return []
    lines, content = result

    all_rules = get_all_rules(plugin_mgr)

    # Per-line pattern scan (all built-in + plugin rules)
    findings = _scan_lines_for_rules(lines, path, all_rules, config)

    # Function-level scan for arbitrary external calls (H-05)
    findings.extend(_scan_arbitrary_external_calls(content, path, config))

    return _deduplicate_findings(findings)


def should_exclude(file_path: str, exclude_patterns: List[str], base_dir: str = "") -> bool:
    """Check if a file path matches any exclusion glob pattern.

    Args:
        file_path: Path to check (absolute or relative).
        exclude_patterns: List of glob patterns to match against (e.g. ``test/**``).
        base_dir: Optional base directory to make ``file_path`` relative to before
            pattern matching.  When empty, ``file_path`` is used as-is.

    Returns:
        True if the path matches at least one exclusion pattern.
    """
    if not exclude_patterns:
        return False

    if base_dir:
        try:
            rel_path = str(Path(file_path).relative_to(base_dir))
        except ValueError:
            rel_path = file_path
    else:
        rel_path = file_path

    # Normalise to forward slashes for consistent cross-platform matching
    rel_path = rel_path.replace("\\", "/")

    for pattern in exclude_patterns:
        if fnmatch.fnmatch(rel_path, pattern):
            return True
        # Also match each path component against the bare pattern stem
        # so that ``node_modules/**`` can prune a bare directory name
        # ``node_modules`` as well.
        bare = pattern.rstrip("/").rstrip("*").rstrip("/")
        if bare:
            parts = rel_path.split("/")
            for part in parts:
                if fnmatch.fnmatch(part, bare):
                    return True
    return False


def scan_target(
    target: str,
    config: Optional[CounterscarpConfig] = None,
    plugin_mgr: Optional[PluginManager] = None,
    exclude_paths: Optional[List[str]] = None,
) -> List[HeuristicFinding]:
    """Scan a .sol file or all .sol files under a directory.

    Args:
        target: Path to a .sol file or directory containing Solidity files.
        config: Optional configuration object for rule enablement and suppressions.
        plugin_mgr: Optional PluginManager to load plugin rules from.
        exclude_paths: Optional list of glob patterns (e.g. ``test/**``) for paths
            that should be skipped.  Patterns are matched against relative paths
            normalised to forward slashes.

    Returns:
        List of all heuristic findings.
    """
    exclude_patterns: List[str] = exclude_paths or []

    if exclude_patterns:
        logger.info("Path exclusions active: %s", exclude_patterns)

    all_findings: List[HeuristicFinding] = []

    if Path(target).is_file() and target.endswith(".sol"):
        # Single-file scan: check whether the file itself is excluded
        rel_single = Path(target).name
        if exclude_patterns and should_exclude(rel_single, exclude_patterns, ""):
            logger.debug("Excluded: %s", target)
        else:
            all_findings.extend(scan_file(target, config, plugin_mgr))
    elif Path(target).is_dir():
        for root, dirs, files in os.walk(target):
            # Prune excluded directories in-place to avoid descending into them
            if exclude_patterns:
                rel_root = str(Path(root).relative_to(target)).replace("\\", "/")
                dirs[:] = [
                    d for d in dirs
                    if not should_exclude(
                        f"{rel_root}/{d}" if rel_root != "." else d,
                        exclude_patterns,
                        "",
                    )
                ]

            for name in files:
                if name.endswith(".sol"):
                    path = str(Path(root) / name)
                    if exclude_patterns:
                        rel_path = str(Path(path).relative_to(target)).replace("\\", "/")
                        if should_exclude(rel_path, exclude_patterns, ""):
                            logger.debug("Excluded: %s", rel_path)
                            continue
                    all_findings.extend(scan_file(path, config, plugin_mgr))
    else:
        # Not a file or directory; nothing to do
        return []

    return _deduplicate_findings(all_findings)


def print_report(findings: List[HeuristicFinding], show_suppressed: bool = False) -> None:
    """Print a formatted report of heuristic findings.

    Args:
        findings: List of findings to report.
        show_suppressed: Whether to include suppressed findings in the output.
    """
    # Separate suppressed from active findings
    active_findings = [f for f in findings if not f.suppressed]
    suppressed_findings = [f for f in findings if f.suppressed]

    print("\n" + "=" * 60)
    print(f" HEURISTIC SCAN REPORT - {len(active_findings)} ACTIVE FLAGS")
    print("=" * 60 + "\n")

    if not active_findings:
        print("[+] No active heuristic flags detected. (This does not guarantee safety.)")
    else:
        # Sort by severity then file/line
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings_sorted = sorted(
            active_findings,
            key=lambda f: (severity_order.get(f.severity, 5), f.file, f.line_no),
        )

        for f in findings_sorted:
            print(
                f"[{f.severity}] {f.rule_id} - {f.message}\n"
                f"    File: {f.file}:{f.line_no}\n"
                f"    Code: {f.line_text.strip()}"
            )

    # Print suppressed findings if requested
    if suppressed_findings:
        print(f"\n🔕 {len(suppressed_findings)} finding(s) suppressed via config")
        if show_suppressed:
            print("\n--- SUPPRESSED FINDINGS ---")
            for f in suppressed_findings:
                print(
                    f"[{f.severity}] {f.rule_id} - {f.message}\n"
                    f"    File: {f.file}:{f.line_no}\n"
                    f"    Reason: {f.suppression_reason}"
                )


def main() -> None:
    """Main entry point for the heuristic scanner CLI."""
    parser = argparse.ArgumentParser(
        description="Heuristic scanner for Solidity contracts (pattern-based checks).",
    )
    parser.add_argument(
        "target",
        help="Path to a .sol file or a directory containing Solidity files",
    )
    parser.add_argument(
        "--config",
        help="Path to counterscarp.toml config file",
        default=None,
    )
    parser.add_argument(
        "--show-suppressed",
        action="store_true",
        help="Show suppressed findings in output",
    )
    args = parser.parse_args()

    # Load config if available
    config = None
    if CONFIG_AVAILABLE:
        try:
            config = load_config(args.config)
            if config:
                print(f"[*] Config loaded: {len(config.heuristics.disabled_rules)} rules disabled, "
                      f"{len(config.suppressions)} suppressions active")
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            print("[*] Continuing with default settings...\n")

    findings = scan_target(args.target, config)
    print_report(findings, show_suppressed=args.show_suppressed)


if __name__ == "__main__":
    main()
