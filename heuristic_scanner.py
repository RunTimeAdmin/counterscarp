from __future__ import annotations

import os
import re
import argparse
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Import logger
try:
    from logger import get_logger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False
    get_logger = None

# Initialize logger
if LOGGER_AVAILABLE and get_logger:
    logger = get_logger(__name__)
else:
    import logging
    logger = logging.getLogger(__name__)

# Optional config loader (graceful fallback if not available)
try:
    from config_loader import load_config, SentinelConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    SentinelConfig = None

# Optional plugin manager (graceful fallback if not available)
try:
    from plugin_manager import PluginManager
    PLUGIN_MANAGER_AVAILABLE = True
except ImportError:
    PLUGIN_MANAGER_AVAILABLE = False
    PluginManager = None


# Compiled regex for inline suppression pragmas (sentinel-ignore).
# Matches: // sentinel-ignore: RULE_ID [optional reason]
#          /* sentinel-ignore: RULE_ID */
#          // sentinel-ignore: ALL
SUPPRESS_PATTERN = re.compile(r'sentinel-ignore:\s*(\w+)(?:\s+(.*))?')


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
    """
    id: str
    description: str
    severity: str
    pattern: re.Pattern[str]
    hint: str
    confidence: int = 5  # 1-10 scale


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
        pattern=re.compile(r"0x[0-9a-fA-F]{38,40}"),
        hint="Verify hardcoded addresses are correct and documented; consider configurability.",
        confidence=1,
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
        pattern=re.compile(r"/[^*].*\*"),
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
        pattern=re.compile(r"(\w+(?:\([^)]*\))?)\.\(call\{|transfer\(|transferFrom\("),
        hint="CRITICAL: Always check return values of external calls. Unchecked calls are top bug bounty targets ($10K-$100K).",
        confidence=9,
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
    """Check current line and line above for a sentinel-ignore pragma.

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


def is_in_multiline_comment(
    lines: List[str], line_idx: int, match_start: int
) -> bool:
    """Check if a position is inside a multi-line comment (/* */).

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


def scan_file(
    path: str,
    config: Optional[SentinelConfig] = None,
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
    findings: List[HeuristicFinding] = []

    # Get heuristics config
    heuristics_enabled = True
    if config and config.heuristics:
        heuristics_enabled = config.heuristics.enabled

    if not heuristics_enabled:
        return findings

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
            content = "".join(lines)
    except OSError as e:
        logger.warning("Failed to read file %s: %s", path, e)
        return findings

    # Get all rules (built-in + plugin rules)
    all_rules = get_all_rules(plugin_mgr)

    # Simple rule-based line scanning
    for i, line in enumerate(lines, start=1):
        # Skip obvious comments-only lines to reduce noise
        stripped = line.strip()
        if stripped.startswith("//"):
            continue

        for rule in all_rules:
            # Check if rule is disabled in config
            if config and config.heuristics and not config.heuristics.is_rule_enabled(rule.id):
                continue

            # Get effective severity (considering overrides)
            effective_severity = rule.severity
            if config and config.heuristics:
                effective_severity = config.heuristics.get_rule_severity(rule.id, rule.severity)

            # Find all matches for this rule
            for match in rule.pattern.finditer(line):
                match_start = match.start()

                # Skip if match is in a single-line comment or string literal
                if not is_in_code_context(line, match_start):
                    logger.debug(
                        f"Skipping match for {rule.id} in comment/string "
                        f"at {path}:{i}:{match_start}"
                    )
                    continue

                # Skip if match is inside a multi-line comment
                if is_in_multiline_comment(lines, i - 1, match_start):
                    logger.debug(
                        f"Skipping match for {rule.id} in multi-line comment "
                        f"at {path}:{i}:{match_start}"
                    )
                    continue

                finding = HeuristicFinding(
                    rule_id=rule.id,
                    severity=effective_severity,
                    message=rule.description,
                    file=path,
                    line_no=i,
                    line_text=line.rstrip("\n"),
                    confidence=rule.confidence,
                )

                # Check inline suppression pragmas first (current line + line above)
                suppressed, suppression_reason = _check_inline_suppression(
                    lines, i - 1, rule.id
                )
                if suppressed:
                    finding.suppressed = True
                    finding.suppression_reason = suppression_reason
                    logger.debug(
                        "Inline suppression applied for %s at %s:%d: %s",
                        rule.id, path, i, suppression_reason,
                    )

                # Check config-based suppressions (only if not already suppressed inline)
                if not finding.suppressed and config:
                    suppression = config.is_finding_suppressed(rule.id, path, i)
                    if suppression:
                        finding.suppressed = True
                        finding.suppression_reason = suppression.reason

                findings.append(finding)
                # Only report one finding per rule per line
                break

    # H-05: Arbitrary External Call (approximate, function-level scan)
    # Quick split by 'function' to keep context (not a full parser).
    functions = content.split("function ")
    for func_block in functions[1:]:  # Skip preamble
        header_match = re.search(
            r"^(\w+)\s*\((.*?)\).*?(public|external)", func_block, re.DOTALL
        )
        if not header_match:
            continue

        func_name = header_match.group(1)
        params = header_match.group(2)
        header = func_block.split("{")[0]

        # Require an address and bytes/calldata param
        if "address" not in params or ("bytes" not in params and "calldata" not in params):
            continue

        # Skip if protected by common auth modifiers in the header
        if re.search(r"(onlyOwner|auth|onlyRole)", header):
            continue

        # Look for low-level .call using variables
        call_match = re.search(r"(\w+)\.call\s*\{.*\}\s*\(\s*(\w+)\s*\)", func_block)
        if not call_match:
            continue

        target_var = call_match.group(1)
        data_var = call_match.group(2)

        # Verify that target/data vars appear in the parameter list
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

            # Check suppressions
            if config:
                suppression = config.is_finding_suppressed("ARBITRARY_EXTERNAL_CALL", path, 0)
                if suppression:
                    finding.suppressed = True
                    finding.suppression_reason = suppression.reason

            findings.append(finding)

    return findings


def scan_target(
    target: str,
    config: Optional[SentinelConfig] = None,
    plugin_mgr: Optional[PluginManager] = None
) -> List[HeuristicFinding]:
    """Scan a .sol file or all .sol files under a directory.

    Args:
        target: Path to a .sol file or directory containing Solidity files.
        config: Optional configuration object for rule enablement and suppressions.
        plugin_mgr: Optional PluginManager to load plugin rules from.

    Returns:
        List of all heuristic findings.
    """
    all_findings: List[HeuristicFinding] = []

    if os.path.isfile(target) and target.endswith(".sol"):
        all_findings.extend(scan_file(target, config, plugin_mgr))
    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            for name in files:
                if name.endswith(".sol"):
                    path = os.path.join(root, name)
                    all_findings.extend(scan_file(path, config, plugin_mgr))
    else:
        # Not a file or directory; nothing to do
        return []

    return all_findings


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
        help="Path to sentinel.toml config file",
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
