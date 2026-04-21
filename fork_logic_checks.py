"""Fork-specific logic checks for known protocol vulnerabilities.

This module implements targeted vulnerability checks for known fork-specific
issues. It is called after a protocol fingerprint match is detected in
fingerprint_scanner.py.
"""

import re
import logging
from typing import List

from heuristic_scanner import HeuristicFinding

logger = logging.getLogger("sentinel.fork_logic_checks")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_BLOCK_COMMENT_OPEN = re.compile(r"/\*")
_BLOCK_COMMENT_CLOSE = re.compile(r"\*/")


def _is_comment_line(line: str) -> bool:
    """Return True if the line is a pure single-line comment."""
    stripped = line.strip()
    return stripped.startswith("//") or stripped.startswith("*")


def _strip_inline_comment(line: str) -> str:
    """Remove everything after // on a code line."""
    idx = line.find("//")
    return line[:idx] if idx != -1 else line


def _build_non_comment_map(lines: List[str]) -> List[bool]:
    """Return a boolean list: True = line is inside active code (not block comment)."""
    active = []
    in_block = False
    for line in lines:
        if in_block:
            active.append(False)
            if _BLOCK_COMMENT_CLOSE.search(line):
                in_block = False
        else:
            if _is_comment_line(line):
                active.append(False)
            else:
                active.append(True)
                if _BLOCK_COMMENT_OPEN.search(line) and not _BLOCK_COMMENT_CLOSE.search(line):
                    in_block = True
    return active


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_fork_checks(
    source_code: str,
    protocol_name: str,
    file_path: str,
) -> List[HeuristicFinding]:
    """Run fork-specific vulnerability checks based on matched protocol.

    Args:
        source_code: Full source code of the Solidity contract.
        protocol_name: Name of the matched protocol (e.g. ``"Uniswap V2"``).
        file_path: Filesystem path of the contract (used in findings).

    Returns:
        List of :class:`HeuristicFinding` instances for any issues detected.
    """
    findings: List[HeuristicFinding] = []
    lines = source_code.splitlines()
    protocol_lower = protocol_name.lower()

    # Route to protocol-category checks
    if any(p in protocol_lower for p in ["uniswap", "sushiswap", "pancakeswap", "quickswap"]):
        findings.extend(_check_amm_rounding(lines, file_path))

    if any(p in protocol_lower for p in ["compound", "cream", "venus", "benqi"]):
        findings.extend(_check_compound_oracle_staleness(lines, file_path))

    if any(p in protocol_lower for p in ["aave", "radiant", "spark"]):
        findings.extend(_check_aave_flash_loan_callback(lines, file_path))

    if any(p in protocol_lower for p in ["gmx", "vela", "myx"]):
        findings.extend(_check_gmx_price_validation(lines, file_path))

    # Universal DeFi check applied to all matched protocols
    findings.extend(_check_fee_on_transfer(lines, file_path))

    logger.debug(
        "fork_logic_checks: %d finding(s) for protocol '%s' in %s",
        len(findings),
        protocol_name,
        file_path,
    )
    return findings


# ---------------------------------------------------------------------------
# Check implementations
# ---------------------------------------------------------------------------

def _check_amm_rounding(lines: List[str], file_path: str) -> List[HeuristicFinding]:
    """Detect Uniswap V2-style rounding errors in getAmountOut / getAmountIn.

    A division that lacks ``+ 1`` or ``.ceil`` rounding can be exploited to
    extract value from the pool via precision loss.

    Rule ID: FORK_AMM_ROUNDING_ERROR
    """
    findings: List[HeuristicFinding] = []
    active = _build_non_comment_map(lines)

    # Patterns: function definitions for getAmountOut / getAmountIn
    func_re = re.compile(r"\bfunction\s+(getAmountOut|getAmountIn)\b")
    # Division without rounding correction
    div_re = re.compile(r"(numerator|amountIn|amountOut)\s*[*/]\s*(denominator|\w+)")
    rounding_re = re.compile(r"(\+\s*1|\.ceil\b)")

    i = 0
    while i < len(lines):
        if active[i] and func_re.search(lines[i]):
            # Scan the function body (up to 40 lines)
            body_end = min(i + 40, len(lines))
            for j in range(i, body_end):
                if not active[j]:
                    j += 1
                    continue
                code = _strip_inline_comment(lines[j])
                if div_re.search(code) and not rounding_re.search(code):
                    findings.append(HeuristicFinding(
                        rule_id="FORK_AMM_ROUNDING_ERROR",
                        severity="HIGH",
                        message=(
                            "AMM calculation may be missing rounding correction (+1 / .ceil). "
                            "Uniswap V2 forks are susceptible to precision-loss exploits when "
                            "integer division truncates the result without compensating for remainder."
                        ),
                        file=file_path,
                        line_no=j + 1,
                        line_text=lines[j].rstrip(),
                        confidence=7,
                    ))
                    break  # one finding per function
            i = body_end
            continue
        i += 1

    return findings


def _check_compound_oracle_staleness(lines: List[str], file_path: str) -> List[HeuristicFinding]:
    """Detect Compound-fork oracle calls without freshness validation.

    A ``getUnderlyingPrice`` call without a ``require`` / ``updatedAt`` /
    ``timestamp`` check within 5 lines may consume a stale price feed.

    Rule ID: FORK_COMPOUND_ORACLE_STALE
    """
    findings: List[HeuristicFinding] = []
    active = _build_non_comment_map(lines)

    call_re = re.compile(r"\bgetUnderlyingPrice\s*\(")
    freshness_re = re.compile(
        r"\b(require|updatedAt|timestamp|staleness|maxDelay|heartbeat|freshness)\b",
        re.IGNORECASE,
    )

    for i, line in enumerate(lines):
        if not active[i]:
            continue
        if call_re.search(_strip_inline_comment(line)):
            # Check ±5 lines for a staleness guard
            window_start = max(0, i - 2)
            window_end = min(len(lines), i + 6)
            context = "\n".join(lines[window_start:window_end])
            if not freshness_re.search(context):
                findings.append(HeuristicFinding(
                    rule_id="FORK_COMPOUND_ORACLE_STALE",
                    severity="CRITICAL",
                    message=(
                        "getUnderlyingPrice() called without apparent staleness validation. "
                        "Compound forks that omit updatedAt / heartbeat checks are vulnerable "
                        "to stale price oracle exploitation and incorrect liquidation pricing."
                    ),
                    file=file_path,
                    line_no=i + 1,
                    line_text=line.rstrip(),
                    confidence=8,
                ))

    return findings


def _check_aave_flash_loan_callback(lines: List[str], file_path: str) -> List[HeuristicFinding]:
    """Detect Aave-fork executeOperation callbacks missing initiator validation.

    An unguarded ``executeOperation`` function allows any caller to replay
    the callback and trigger unintended logic on behalf of the pool.

    Rule ID: FORK_AAVE_FLASHLOAN_CALLBACK
    """
    findings: List[HeuristicFinding] = []
    active = _build_non_comment_map(lines)

    func_re = re.compile(r"\bfunction\s+executeOperation\b")
    initiator_re = re.compile(
        r"\b(initiator\s*==|require\s*\(\s*\w*initiator|_initiator\s*==)\b",
        re.IGNORECASE,
    )

    i = 0
    while i < len(lines):
        if active[i] and func_re.search(lines[i]):
            # Scan the function body (up to 60 lines)
            body_end = min(i + 60, len(lines))
            body = "\n".join(lines[i:body_end])
            if not initiator_re.search(body):
                findings.append(HeuristicFinding(
                    rule_id="FORK_AAVE_FLASHLOAN_CALLBACK",
                    severity="CRITICAL",
                    message=(
                        "executeOperation() does not appear to validate the `initiator` "
                        "parameter. Aave-fork flash loan callbacks without initiator checks "
                        "can be called by arbitrary actors to exploit pool assets."
                    ),
                    file=file_path,
                    line_no=i + 1,
                    line_text=lines[i].rstrip(),
                    confidence=8,
                ))
            i = body_end
            continue
        i += 1

    return findings


def _check_gmx_price_validation(lines: List[str], file_path: str) -> List[HeuristicFinding]:
    """Detect GMX-fork position functions without price validation.

    ``increasePosition``, ``decreasePosition``, and ``createOrder`` that do
    not call ``validatePrices`` / ``getPrice`` with min/max bounds are
    susceptible to price manipulation during execution.

    Rule ID: FORK_GMX_PRICE_MANIPULATION
    """
    findings: List[HeuristicFinding] = []
    active = _build_non_comment_map(lines)

    func_re = re.compile(
        r"\bfunction\s+(increasePosition|decreasePosition|createOrder)\b"
    )
    price_validation_re = re.compile(
        r"\b(validatePrices?|getPrice\s*\(|minPrice|maxPrice|priceWithImpact|_validatePrice)\b",
        re.IGNORECASE,
    )

    i = 0
    while i < len(lines):
        if active[i] and func_re.search(lines[i]):
            func_match = func_re.search(lines[i])
            func_name = func_match.group(1) if func_match else "position function"
            body_end = min(i + 80, len(lines))
            body = "\n".join(lines[i:body_end])
            if not price_validation_re.search(body):
                findings.append(HeuristicFinding(
                    rule_id="FORK_GMX_PRICE_MANIPULATION",
                    severity="HIGH",
                    message=(
                        f"{func_name}() does not appear to call validatePrices() or "
                        "bound getPrice() with min/max checks. GMX-fork contracts that "
                        "skip price validation are vulnerable to sandwich and oracle "
                        "manipulation attacks during position execution."
                    ),
                    file=file_path,
                    line_no=i + 1,
                    line_text=lines[i].rstrip(),
                    confidence=7,
                ))
            i = body_end
            continue
        i += 1

    return findings


def _check_fee_on_transfer(lines: List[str], file_path: str) -> List[HeuristicFinding]:
    """Detect transferFrom calls that ignore actual received amounts.

    Fee-on-transfer tokens silently deliver less than requested. Any code
    that uses the *requested* amount after ``transferFrom`` — without
    comparing ``balanceOf`` before and after — will overstate the deposit.

    Rule ID: FORK_FEE_ON_TRANSFER
    """
    findings: List[HeuristicFinding] = []
    active = _build_non_comment_map(lines)

    transfer_re = re.compile(r"\btransferFrom\s*\(")
    balance_re = re.compile(r"\bbalanceOf\s*\(")

    for i, line in enumerate(lines):
        if not active[i]:
            continue
        if transfer_re.search(_strip_inline_comment(line)):
            # Check 3 lines before and 3 lines after for a balanceOf guard
            window_start = max(0, i - 3)
            window_end = min(len(lines), i + 4)
            context = "\n".join(lines[window_start:window_end])
            if not balance_re.search(context):
                findings.append(HeuristicFinding(
                    rule_id="FORK_FEE_ON_TRANSFER",
                    severity="MEDIUM",
                    message=(
                        "transferFrom() used without surrounding balanceOf() checks. "
                        "Fee-on-transfer tokens reduce the actual received amount; "
                        "recording the requested amount inflates internal accounting "
                        "and can be drained via repeated deposits."
                    ),
                    file=file_path,
                    line_no=i + 1,
                    line_text=line.rstrip(),
                    confidence=6,
                ))

    return findings
