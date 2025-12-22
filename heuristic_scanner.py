import os
import re
import argparse
from dataclasses import dataclass
from typing import List, Optional

# Optional config loader (graceful fallback if not available)
try:
    from config_loader import load_config, SentinelConfig
    CONFIG_AVAILABLE = True
except ImportError:
    CONFIG_AVAILABLE = False
    SentinelConfig = None


@dataclass
class HeuristicFinding:
    rule_id: str
    severity: str
    message: str
    file: str
    line_no: int
    line_text: str
    suppressed: bool = False
    suppression_reason: str = ""


@dataclass
class HeuristicRule:
    id: str
    description: str
    severity: str
    pattern: re.Pattern
    hint: str


# Core heuristic rules. These complement Slither/Mythril with simple
# pattern-based checks that are easy to understand and extend.
RULES: List[HeuristicRule] = [
    HeuristicRule(
        id="TX_ORIGIN_USAGE",
        description="Use of tx.origin (dangerous for auth checks)",
        severity="HIGH",
        pattern=re.compile(r"tx\.origin"),
        hint="Avoid tx.origin for authorization; use msg.sender and proper role-based access control.",
    ),
    HeuristicRule(
        id="BLOCK_TIMESTAMP_RANDOMNESS",
        description="Use of block.timestamp / now (weak randomness)",
        severity="MEDIUM",
        pattern=re.compile(r"block\.timestamp|\bnow\b"),
        hint="Do not use block.timestamp/now as randomness; use VRF or off-chain randomness.",
    ),
    HeuristicRule(
        id="DELEGATECALL_USAGE",
        description="Use of delegatecall (upgradeable/proxy risk)",
        severity="HIGH",
        pattern=re.compile(r"delegatecall\s*\("),
        hint="Ensure delegatecall targets are trusted and immutable; review proxy patterns carefully.",
    ),
    HeuristicRule(
        id="LOWLEVEL_CALL_USAGE",
        description="Use of low-level call (call(), staticcall(), callcode())",
        severity="MEDIUM",
        pattern=re.compile(r"\.call\s*\(|\.staticcall\s*\("),
        hint="Wrap low-level calls with return value checks and reentrancy protection.",
    ),
    HeuristicRule(
        id="HARDCODED_ADDRESS",
        description="Hardcoded address literal in code",
        severity="INFO",
        pattern=re.compile(r"0x[0-9a-fA-F]{38,40}"),
        hint="Verify hardcoded addresses are correct and documented; consider configurability.",
    ),
    HeuristicRule(
        id="EMERGENCY_WITHDRAW_PUBLIC",
        description="Function name suggests emergency withdraw / rescue funds",
        severity="HIGH",
        pattern=re.compile(r"function\s+(emergencyWithdraw|withdrawAll|rescue|drain)\b"),
        hint="Ensure emergency/withdraw/rescue functions are admin-only and ideally timelocked.",
    ),
    HeuristicRule(
        id="UPGRADE_FUNCTION",
        description="Function name suggests upgrade or ownership change",
        severity="HIGH",
        pattern=re.compile(r"function\s+(upgradeTo|upgrade|setOwner|transferOwnership)\b"),
        hint="Confirm these functions are protected by strong access control (multi-sig, timelock).",
    ),
    # Kill Chain / Behavioral / Math heuristics (first-pass approximations)
    HeuristicRule(
        id="MSG_VALUE_LOOP",
        description="msg.value used inside a loop (possible double-credit per iteration)",
        severity="HIGH",
        pattern=re.compile(r"(for|while)\s*\(.*msg\.value"),
        hint="Ensure deposits are not multiplied by loop iterations; track value per user, not per iteration.",
    ),
    HeuristicRule(
        id="STRICT_BALANCE_EQUALITY",
        description="Strict equality on address(this).balance (fragile invariant)",
        severity="HIGH",
        pattern=re.compile(r"address\(this\)\.balance\s*=="),
        hint="Use >= or more robust accounting; forced ETH sends can break strict equality.",
    ),
    HeuristicRule(
        id="HIDDEN_MINT",
        description="_mint() call (possible hidden mint path)",
        severity="HIGH",
        pattern=re.compile(r"_mint\s*\("),
        hint="Review all mint paths; ensure they are expected (e.g., only in public mint/claim functions).",
    ),
    HeuristicRule(
        id="FAKE_RENOUNCE_OWNER_ZERO",
        description="owner set to address(0) (possible fake renounce)",
        severity="MEDIUM",
        pattern=re.compile(r"owner\s*=\s*address\(0\)"),
        hint="Verify there is no parallel manager/admin role keeping effective control.",
    ),
    HeuristicRule(
        id="TRADING_TOGGLE_BOOL",
        description="Presence of trading enable/disable boolean (possible honeypot)",
        severity="MEDIUM",
        pattern=re.compile(r"bool\s+(trading(Open|Enabled)|tradingOpen|tradingEnabled)"),
        hint="Ensure trading toggles are time-bound, documented, and not abusable to trap liquidity.",
    ),
    HeuristicRule(
        id="SET_FEE_FUNCTION",
        description="Configurable fee setter without obvious cap (possible fee rug)",
        severity="MEDIUM",
        pattern=re.compile(r"function\s+set(Fee|Tax)"),
        hint="Check for upper bounds on new fee values (e.g., <= 25%).",
    ),
    HeuristicRule(
        id="DIVIDE_BEFORE_MULTIPLY",
        description="Potential precision loss: division before multiplication",
        severity="MEDIUM",
        pattern=re.compile(r"/.*\*"),
        hint="Prefer (a * c) / b over (a / b) * c to avoid rounding to zero.",
    ),
    HeuristicRule(
        id="BOOLEAN_TRANSFER_CHECK",
        description="Checking boolean return on ERC20.transfer (may be wrong with some libs)",
        severity="INFO",
        pattern=re.compile(r"if\s*\(!\s*\w+\.transfer\s*\("),
        hint="Ensure this pattern matches the token library semantics (e.g., Solmate SafeTransferLib reverts instead of returning bool).",
    ),
    
    # ========== BUG BOUNTY PATTERNS (High-value Immunefi/Code4rena targets) ==========
    
    HeuristicRule(
        id="UNCHECKED_EXTERNAL_CALL",
        description="Low-level call/transfer without return value check (funds may be lost)",
        severity="CRITICAL",
        pattern=re.compile(r"\w+\.(call\{|transfer\(|transferFrom\()"),
        hint="CRITICAL: Always check return values of external calls. Unchecked calls are top bug bounty targets ($10K-$100K).",
    ),
    
    HeuristicRule(
        id="ORACLE_STALENESS_CHECK",
        description="Chainlink oracle without staleness/validity check (price manipulation risk)",
        severity="CRITICAL",
        pattern=re.compile(r"(latestAnswer|latestRoundData)\(\)(?!.*require.*updatedAt|.*block\.timestamp)"),
        hint="CRITICAL: Check updatedAt timestamp and answeredInRound to prevent stale price attacks ($50K-$500K bounties).",
    ),
    
    HeuristicRule(
        id="SIGNATURE_REPLAY",
        description="Signature verification without nonce/deadline protection (replay attack)",
        severity="HIGH",
        pattern=re.compile(r"ecrecover\((?!.*nonce|.*deadline)"),
        hint="HIGH: Add nonce and deadline to prevent signature replay attacks. Common in account abstraction ($20K-$100K).",
    ),
    
    HeuristicRule(
        id="FLASH_LOAN_REENTRANCY",
        description="Flash loan callback without reentrancy protection",
        severity="CRITICAL",
        pattern=re.compile(r"function\s+\w*flash\w*.*\{(?!.*nonReentrant|.*ReentrancyGuard)"),
        hint="CRITICAL: Flash loan callbacks must have nonReentrant modifier. Major DeFi exploit vector ($100K-$1M+ bounties).",
    ),
    
    HeuristicRule(
        id="STORAGE_COLLISION_RISK",
        description="Upgradeable proxy pattern detected - verify storage layout",
        severity="HIGH",
        pattern=re.compile(r"(UUPS|TransparentUpgradeableProxy|initializer|__gap)"),
        hint="HIGH: Storage collisions in upgrades can brick contracts. Use storage gap patterns and OpenZeppelin guidelines ($30K-$200K).",
    ),
    
    HeuristicRule(
        id="UNSAFE_CAST",
        description="Unsafe type casting (uint256 -> uint128/uint64) without bounds check",
        severity="HIGH",
        pattern=re.compile(r"uint(128|64|32|16|8)\(\w+\)(?!.*require|.*assert)"),
        hint="HIGH: Downcasting without overflow check can cause critical bugs. Use SafeCast library ($10K-$50K).",
    ),
    
    HeuristicRule(
        id="MISSING_SLIPPAGE_PROTECTION",
        description="DEX swap without minimum output amount (MEV/sandwich attack)",
        severity="HIGH",
        pattern=re.compile(r"(swapExactTokensFor|swap)\(.*,\s*0\s*[,\)]"),
        hint="HIGH: Zero slippage protection allows MEV bots to sandwich trade. Always set minAmountOut ($5K-$30K).",
    ),
    
    HeuristicRule(
        id="CENTRALIZATION_RISK",
        description="Single owner can upgrade/pause/withdraw without timelock",
        severity="MEDIUM",
        pattern=re.compile(r"function\s+(pause|unpause|setImplementation)\s*\(.*\).*onlyOwner(?!.*timelock)"),
        hint="MEDIUM: Centralization risk. Use multi-sig + timelock for critical admin functions. Common Code4rena Medium finding.",
    ),
]


def scan_file(path: str, config: Optional[SentinelConfig] = None) -> List[HeuristicFinding]:
    """Scan a single .sol file and return heuristic findings."""
    findings: List[HeuristicFinding] = []

    # Get heuristics config
    heuristics_enabled = True
    if config and config.heuristics:
        heuristics_enabled = config.heuristics.enabled

    if not heuristics_enabled:
        return findings

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            content = "".join(lines)
    except OSError:
        return findings

    # Simple rule-based line scanning
    for i, line in enumerate(lines, start=1):
        # Skip obvious comments-only lines to reduce noise
        stripped = line.strip()
        if stripped.startswith("//"):
            continue

        for rule in RULES:
            # Check if rule is disabled in config
            if config and config.heuristics and not config.heuristics.is_rule_enabled(rule.id):
                continue

            # Get effective severity (considering overrides)
            effective_severity = rule.severity
            if config and config.heuristics:
                effective_severity = config.heuristics.get_rule_severity(rule.id, rule.severity)

            if rule.pattern.search(line):
                finding = HeuristicFinding(
                    rule_id=rule.id,
                    severity=effective_severity,
                    message=rule.description,
                    file=path,
                    line_no=i,
                    line_text=line.rstrip("\n"),
                )

                # Check suppressions
                if config:
                    suppression = config.is_finding_suppressed(rule.id, path, i)
                    if suppression:
                        finding.suppressed = True
                        finding.suppression_reason = suppression.reason

                findings.append(finding)

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
            )

            # Check suppressions
            if config:
                suppression = config.is_finding_suppressed("ARBITRARY_EXTERNAL_CALL", path, 0)
                if suppression:
                    finding.suppressed = True
                    finding.suppression_reason = suppression.reason

            findings.append(finding)

    return findings


def scan_target(target: str, config: Optional[SentinelConfig] = None) -> List[HeuristicFinding]:
    """Scan a .sol file or all .sol files under a directory."""
    all_findings: List[HeuristicFinding] = []

    if os.path.isfile(target) and target.endswith(".sol"):
        all_findings.extend(scan_file(target, config))
    elif os.path.isdir(target):
        for root, _, files in os.walk(target):
            for name in files:
                if name.endswith(".sol"):
                    path = os.path.join(root, name)
                    all_findings.extend(scan_file(path, config))
    else:
        # Not a file or directory; nothing to do
        return []

    return all_findings


def print_report(findings: List[HeuristicFinding], show_suppressed: bool = False) -> None:
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
