#!/usr/bin/env python3
"""Seed script to populate the RAG vector index with 100+ curated vulnerability entries.

Covers 12 categories:
  Reentrancy, Oracle Manipulation, Access Control, Flash Loan,
  Integer/Precision, Storage Collision, Front-running, Delegate Call,
  Logic Bugs, Cross-chain/Bridge, Token Standard, Governance

Usage:
    python scripts/seed_rag_index.py
    python scripts/seed_rag_index.py --output .scarpshield/rag_index.json
    python scripts/seed_rag_index.py --append   # keep existing entries
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# ── Ensure sentinel-engine root is on sys.path when run from any CWD ──────────
_SCRIPT_DIR = Path(__file__).resolve().parent
_ENGINE_ROOT = _SCRIPT_DIR.parent
if str(_ENGINE_ROOT) not in sys.path:
    sys.path.insert(0, str(_ENGINE_ROOT))

from rag_engine import VectorStore, RAGError  # noqa: E402

# ─────────────────────────────────────────────────────────────────────────────
# SEED DATA  — 101 curated entries across 12 vulnerability categories
# ─────────────────────────────────────────────────────────────────────────────

SEED_DATA = [
    # =========================================================================
    # REENTRANCY (15 entries)
    # =========================================================================
    {
        "text": (
            "Classic reentrancy vulnerability: A contract sends ETH to an external address "
            "before updating its internal state. An attacker deploys a malicious contract "
            "whose fallback function calls back into the victim before the balance is set to "
            "zero, draining the entire balance. The DAO hack (2016) lost 3.6 M ETH via this "
            "exact pattern. Pattern: external call → attacker re-enters → state not yet updated."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "CRITICAL",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN", "REENTRANCY_ETH"],
            "remediation": (
                "Apply the checks-effects-interactions pattern: update all state variables "
                "BEFORE making any external call. Use OpenZeppelin ReentrancyGuard "
                "(nonReentrant modifier) on any function that transfers value."
            ),
            "reference": "https://github.com/nicksdjohnson/TheDAO",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Read-only reentrancy (Curve Finance 2023 pattern): A view function is called "
            "while another function's state transition is in-flight, producing a stale/incorrect "
            "value. Protocols integrating Curve pool prices were at risk because "
            "get_virtual_price() was callable during a reentrancy window when token balances "
            "were temporarily inconsistent. Exploited for $73k in Curve integrations 2022-2023."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["READ_ONLY_REENTRANCY"],
            "remediation": (
                "Do not treat view functions as safe from reentrancy. Apply reentrancy locks "
                "to read functions that are used as price oracles. Check reentrancy status "
                "before reading sensitive state in integrating protocols."
            ),
            "reference": "https://code4rena.com/reports/2023-01-popcorn",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Cross-function reentrancy: Two functions in the same contract share state. "
            "Function A makes an external call, allowing the attacker to call Function B "
            "before A completes. The attacker exploits the intermediate state to gain an "
            "advantage (e.g., double-counting a balance). Common in lending protocols where "
            "deposit() and borrow() share collateral accounting."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN", "CROSS_FUNCTION_REENTRANCY"],
            "remediation": (
                "Use a single global reentrancy lock (ReentrancyGuard) across all "
                "sensitive functions in a contract, not just the function making the "
                "external call. Map all shared-state functions and guard them collectively."
            ),
            "reference": "https://code4rena.com/reports/2022-12-tigris",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Cross-contract reentrancy: Two separate contracts interact and share logical "
            "state. Contract A calls an external function, which triggers Contract B to "
            "call back into Contract A's sibling Contract C before A finalises. Compound "
            "compound-finance vulnerabilities documented this in the cToken/controller split."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN"],
            "remediation": (
                "Design state machines so cross-contract invariants hold at every external "
                "call boundary. Apply reentrancy guards at the protocol level, not just per "
                "contract. Use a mutex stored in a shared registry contract."
            ),
            "reference": "https://blog.openzeppelin.com/reentrancy-after-istanbul/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "ERC721 onERC721Received reentrancy: When an NFT is minted or transferred to a "
            "smart contract, the safeTransferFrom function invokes the recipient's "
            "onERC721Received callback. An attacker implements this callback to re-enter "
            "the minting contract before the tokenId counter is incremented, minting "
            "duplicate tokens. Exploited in several NFT drops in 2021-2022."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_ERC721", "REENTRANCY_PATTERN"],
            "remediation": (
                "Update tokenId counter and ownership mappings BEFORE calling "
                "safeTransferFrom or any function that triggers callbacks. Apply "
                "nonReentrant to mint functions."
            ),
            "reference": "https://code4rena.com/reports/2022-10-holograph",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "ERC1155 batch callback reentrancy: The ERC1155 standard calls "
            "onERC1155BatchReceived on the recipient during safeBatchTransferFrom. "
            "An attacker's contract uses this callback to re-enter the source protocol, "
            "claiming rewards or manipulating balances before the transfer is finalised. "
            "Euler Finance had a related pattern in their donation mechanism."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_ERC1155"],
            "remediation": (
                "Apply nonReentrant to all functions interacting with ERC1155 tokens. "
                "Commit state changes before initiating batch transfers."
            ),
            "reference": "https://code4rena.com/reports/2023-04-caviar",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Reentrancy via fallback function: When a contract sends ETH using transfer() or "
            "call{value:}(\"\"), the recipient's fallback/receive function executes. With "
            "call(), there is no 2300 gas stipend limit, enabling full reentrancy. Many "
            "contracts migrated from transfer() to call() for EIP-1884 compatibility but "
            "forgot to add reentrancy guards."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN", "REENTRANCY_ETH"],
            "remediation": (
                "Use call() but always add nonReentrant modifier. Never use address.transfer() "
                "or address.send() in new code — use call{value:}() with CEI pattern."
            ),
            "reference": "https://consensys.github.io/smart-contract-best-practices/attacks/reentrancy/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Single-function reentrancy: The simplest form where one function makes an "
            "external call before zeroing out the sender's balance. Attacker's receive() "
            "function repeatedly calls withdraw() until the contract is drained. "
            "Seen in basic Ethernaut challenges and real deployments lacking CEI pattern."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN"],
            "remediation": (
                "Zero the balance mapping entry before the external call. "
                "Pattern: require check → update balances[msg.sender] = 0 → send ETH."
            ),
            "reference": "https://ethernaut.openzeppelin.com/level/10",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Vyper reentrancy lock bypass (Curve Finance July 2023): Vyper versions 0.2.15, "
            "0.2.16, and 0.3.0 had a compiler bug where the @nonreentrant decorator failed "
            "to generate proper locking code under certain conditions. Curve pools compiled "
            "with affected Vyper versions lost ~$70M in liquidity to reentrancy attacks."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "CRITICAL",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN"],
            "remediation": (
                "Upgrade Vyper to 0.3.10+. Audit all contracts compiled with Vyper 0.2.15, "
                "0.2.16, or 0.3.0 for reentrancy exposure. For Solidity, prefer Solidity "
                "with OpenZeppelin ReentrancyGuard."
            ),
            "reference": "https://hackmd.io/@LlamaRisk/BJoRgjN_h",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Cross-protocol reentrancy via flash loans: An attacker takes a flash loan, "
            "enters Protocol A, which triggers an external callback to the attacker contract. "
            "Inside the callback the attacker re-enters a different protocol B that relies on "
            "Protocol A's price or state. Both protocols are drained before the flash loan "
            "is repaid. Seen in Euler Finance $197M hack (March 2023)."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "CRITICAL",
            "cwe": "CWE-841",
            "rule_ids": ["FLASH_LOAN_REENTRANCY", "REENTRANCY_PATTERN"],
            "remediation": (
                "Add reentrancy guards to all state-mutating functions. Validate "
                "oracle prices are not stale. Euler's fix included a donation restriction "
                "and health factor checks prior to liquidation."
            ),
            "reference": "https://immunefi.com/bounty/euler/",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Reentrancy in withdrawal patterns (pull-payment vulnerability): Contracts that "
            "allow users to withdraw accumulated funds are particularly vulnerable. If the "
            "external call to transfer funds occurs before the user's balance is zeroed, "
            "repeated withdrawal in a single transaction drains the contract."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN"],
            "remediation": (
                "Use OpenZeppelin's PullPayment pattern for accumulator-style withdrawals. "
                "Always zero the withdrawable amount before initiating the transfer."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/security#PullPayment",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Reentrancy via CREATE2: A contract deployed via CREATE2 can be destroyed "
            "(selfdestruct) and redeployed at the same address with different bytecode. "
            "If a protocol caches trust for an address, a malicious actor can exploit the "
            "deployment window to re-enter using the new bytecode."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "MEDIUM",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN"],
            "remediation": (
                "Do not cache trust based on address alone. Verify contract bytecode hash. "
                "Use allowlists with strict onboarding rather than implicit trust."
            ),
            "reference": "https://code4rena.com/reports/2022-05-cudos",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Modifier-only reentrancy guard insufficiency: Using a custom modifier "
            "like `locked` without also guarding sibling functions. An attacker calls "
            "an unguarded function that shares state with the guarded function during "
            "the locked window."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "MEDIUM",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN"],
            "remediation": (
                "Apply the reentrancy modifier to every function that reads or writes "
                "shared state with the locked function. Use OpenZeppelin ReentrancyGuard "
                "inheritance rather than ad-hoc modifier implementations."
            ),
            "reference": "https://solodit.xyz/issues/m-01-reentrancy-guard-insufficient",
            "source": "Solodit",
        },
    },
    {
        "text": (
            "View function reentrancy: External view functions are called during another "
            "function's execution, reading inconsistent intermediate state. This is "
            "particularly dangerous when the view function is used as a price oracle by "
            "another protocol. The Mango Markets exploit used this approach."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["READ_ONLY_REENTRANCY"],
            "remediation": (
                "Treat view functions as non-reentrant when they access mutable state "
                "referenced by external callers. Apply storage-slot reentrancy checks "
                "to critical view functions."
            ),
            "reference": "https://code4rena.com/reports/2022-10-mango",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Reentrancy in multicall: A multicall dispatcher executes multiple sub-calls. "
            "If one sub-call triggers an external callback that re-enters the multicall "
            "dispatcher, an attacker can repeat earlier sub-calls. Uniswap V3's multicall "
            "was vulnerable to ETH refund reentrancy (fixed in Permit2)."
        ),
        "metadata": {
            "category": "Reentrancy",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_PATTERN"],
            "remediation": (
                "Apply nonReentrant at the multicall entry point. Ensure ETH refund "
                "logic occurs after all sub-calls complete. Validate msg.value is not "
                "reused across calls within a single multicall transaction."
            ),
            "reference": "https://blog.uniswap.org/uniswap-v3-math-primer",
            "source": "Manual Curation",
        },
    },

    # =========================================================================
    # ORACLE MANIPULATION (10 entries)
    # =========================================================================
    {
        "text": (
            "TWAP manipulation via flash loan: An attacker takes a flash loan, "
            "dramatically moves a pool's spot price, waits for the TWAP to catch up "
            "(or uses very short TWAP windows), then exploits the manipulated price in a "
            "second protocol before repaying the loan. Shorter TWAP windows (< 30 min) "
            "are most vulnerable. CREAM Finance exploit November 2021 ($130M)."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION", "FLASH_LOAN_ORACLE"],
            "remediation": (
                "Use minimum 30-minute TWAP windows for on-chain oracles. "
                "Cross-validate with Chainlink price feeds. Implement circuit breakers "
                "that reject prices deviating more than 5-10% from TWAP."
            ),
            "reference": "https://medium.com/cream-finance/c.r.e.a.m.-finance-post-mortem-amp-exploit-6ceb20a630c5",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Spot price oracle manipulation: Using the current spot price of an AMM pool "
            "as an oracle is trivially manipulatable within a single transaction. An attacker "
            "can move the pool price arbitrarily using a large swap, exploit the target "
            "protocol, then swap back in the same transaction at near-zero net cost. "
            "Hundreds of DeFi exploits have used this vector."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION"],
            "remediation": (
                "Never use AMM spot prices as price oracles in the same block. "
                "Always use time-weighted average prices or external oracle providers "
                "like Chainlink, Pyth, or Band Protocol."
            ),
            "reference": "https://blog.openzeppelin.com/secure-smart-contract-guidelines-the-dangers-of-price-oracles",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Chainlink stale price data: Chainlink oracles have a heartbeat and deviation "
            "threshold that trigger updates. If a price has not been updated within the "
            "expected interval (e.g., 1 hour), the contract may use stale data. Venus Protocol "
            "suffered losses when LUNA price feed was stale during the Terra collapse (May 2022)."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["CHAINLINK_STALE_PRICE", "ORACLE_MANIPULATION"],
            "remediation": (
                "Check updatedAt timestamp from Chainlink: require(block.timestamp - updatedAt < MAX_DELAY). "
                "Also check answeredInRound >= roundId. Implement fallback to secondary "
                "oracle if primary is stale."
            ),
            "reference": "https://code4rena.com/reports/2022-04-backd",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Chainlink L2 sequencer downtime: On L2 networks (Optimism, Arbitrum), "
            "the Chainlink sequencer uptime feed must be checked. If the sequencer is down, "
            "all transactions are queued and prices may be stale by the time sequencer "
            "recovers. Protocol should also enforce a grace period after sequencer restarts."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["CHAINLINK_L2_SEQUENCER"],
            "remediation": (
                "Query the L2 sequencer uptime feed before using any Chainlink price. "
                "Require sequencer to have been up for at least GRACE_PERIOD (e.g., 1 hour) "
                "before allowing price-sensitive operations."
            ),
            "reference": "https://docs.chain.link/data-feeds/l2-sequencer-feeds",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Band Protocol oracle deviation: Band Protocol oracles can have wider "
            "price deviation bands than Chainlink. Protocols integrating Band without "
            "checking for large deviations may accept manipulated prices. Always validate "
            "returned prices against expected ranges and compare with secondary sources."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "MEDIUM",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION"],
            "remediation": (
                "Implement min/max price bounds. Cross-validate Band prices against "
                "on-chain TWAP. Revert if deviation exceeds a configurable threshold (e.g., 5%)."
            ),
            "reference": "https://docs.bandchain.org/develop/developer-tools/price-data",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Uniswap V3 TWAP oracle manipulation: Uniswap V3's observe() function returns "
            "cumulative tick data for computing TWAP. A well-resourced attacker can "
            "manipulate the tick over a window period by consistently moving the price. "
            "Shorter windows (< 30 min) are cheaply manipulatable on low-liquidity pools."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION", "UNISWAP_TWAP"],
            "remediation": (
                "Use at least 30-minute observation windows. Add liquidity depth checks: "
                "if pool TVL is below a minimum threshold, reject the price. "
                "Always use Chainlink as primary oracle with TWAP as sanity check."
            ),
            "reference": "https://uniswap.org/whitepaper-v3.pdf",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Compound price feed manipulation (DAI depeg 2020): Compound used Coinbase Pro "
            "as a single price source for DAI. When DAI traded at $1.30 on Coinbase during "
            "a liquidity crunch, Compound's oracle reflected this elevated price. Borrowers "
            "exploited the inflated collateral value to drain $89M from the protocol."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION"],
            "remediation": (
                "Never rely on a single price source. Use a median of 3+ independent "
                "oracle feeds. Implement time-weighted medians and anomaly detection. "
                "Compound v3 now uses Chainlink as primary with multiple fallbacks."
            ),
            "reference": "https://thedefiant.io/compound-dai-hack",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Oracle sandwich attack: An attacker front-runs an oracle price update. "
            "Knowing that a Chainlink price will update (visible in the mempool or predicted "
            "from heartbeat), the attacker positions a trade before the update lands, "
            "profiting from the price delta at the protocol's expense."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "MEDIUM",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION", "FRONT_RUNNING"],
            "remediation": (
                "Implement commit-reveal for price-sensitive operations. Add slippage "
                "tolerance checks. Use private mempools or flashbots bundles for sensitive "
                "protocol operations."
            ),
            "reference": "https://medium.com/coinmonks/oracle-manipulation-sandwich-attack",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Dual oracle inconsistency: A protocol uses two oracles and takes the more "
            "favorable price for the user. An attacker manipulates one oracle so the "
            "protocol always selects the manipulated price. Inverse Finance lost $15.6M "
            "in April 2022 due to this pattern with a TWAP and spot price."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION"],
            "remediation": (
                "When using multiple oracles, take the median or the MORE conservative "
                "(not more favorable) price. Alert and halt when oracles diverge by "
                "more than an acceptable threshold."
            ),
            "reference": "https://medium.com/inverse-finance/inv-hack-post-mortem",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Oracle front-running (latency arbitrage): Off-chain oracle price updates have "
            "latency. Sophisticated arbitrageurs observe off-chain prices and front-run the "
            "on-chain update, effectively trading against a stale price at protocol cost. "
            "Synthetix has suffered multiple oracle latency attacks totaling ~$1B in losses."
        ),
        "metadata": {
            "category": "Oracle Manipulation",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["ORACLE_MANIPULATION"],
            "remediation": (
                "Implement trading fees high enough to negate latency arbitrage. "
                "Use EIP-7516 or similar mechanisms for faster price updates. "
                "Add per-block price change limits."
            ),
            "reference": "https://blog.synthetix.io/how-we-fixed-the-synthetix-oracle-bug/",
            "source": "Manual Curation",
        },
    },

    # =========================================================================
    # ACCESS CONTROL (10 entries)
    # =========================================================================
    {
        "text": (
            "Missing onlyOwner modifier: A privileged function (e.g., withdrawFunds, "
            "setFee, upgradeProxy) lacks any access control. Any external caller can "
            "invoke it. Multiple DeFi protocols have been drained by attackers calling "
            "unprotected admin functions. Ronin Bridge lost $625M partly due to "
            "key compromise of multi-sig signers."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "rule_ids": ["ACCESS_CONTROL_MISSING", "MISSING_ONLY_OWNER"],
            "remediation": (
                "Use OpenZeppelin Ownable or AccessControl for all privileged operations. "
                "Every function that modifies critical state, transfers funds, or controls "
                "protocol parameters must have an explicit access control check."
            ),
            "reference": "https://blog.openzeppelin.com/access-control/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Unprotected initializer in upgradeable proxy: An initialize() function "
            "meant to replace the constructor in a proxy pattern lacks the initializer "
            "modifier, allowing anyone to call it and set themselves as owner. "
            "Parity Multisig Wallet hack November 2017 ($300M frozen) used this vector."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "rule_ids": ["UNPROTECTED_INITIALIZER", "ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Use OpenZeppelin Initializable's initializer modifier. Call "
                "_disableInitializers() in the implementation contract's constructor "
                "to prevent direct initialization. Use initializer modifier for all "
                "init functions and ensure they can only be called once."
            ),
            "reference": "https://blog.openzeppelin.com/parity-wallet-hack-reloaded/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Privilege escalation via delegatecall: A contract with ADMIN role delegates "
            "a call to an untrusted contract. The callee runs in the caller's context and "
            "can overwrite admin storage slots. Used in the Wormhole governance exploit "
            "and several proxy-related hacks."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "rule_ids": ["DELEGATECALL_USAGE", "ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Never delegatecall to untrusted or user-supplied addresses. "
                "Whitelist all valid implementation targets. Validate logic contract "
                "bytecode hash before upgrading."
            ),
            "reference": "https://blog.openzeppelin.com/a-critical-vulnerability-in-delegatecall-proxy-contracts/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Missing role checks on protocol admin functions: OpenZeppelin AccessControl "
            "is used but specific roles are not assigned to functions or the DEFAULT_ADMIN "
            "role is given to address(0). An attacker who obtains the admin role can grant "
            "themselves any role and take full control."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "HIGH",
            "cwe": "CWE-284",
            "rule_ids": ["ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Explicitly assign specific roles (MINTER_ROLE, PAUSER_ROLE, etc.) to "
                "each privileged function. Use two-step admin transfer with a timelock. "
                "Never assign DEFAULT_ADMIN_ROLE to address(0) or EOAs in production."
            ),
            "reference": "https://code4rena.com/reports/2022-09-frax",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "tx.origin authentication bypass: A function uses tx.origin instead of msg.sender "
            "to verify the caller. An attacker tricks a legitimate contract into calling the "
            "vulnerable function. Since tx.origin is the original EOA, the check passes. "
            "Phishing-style attacks exploit this pattern."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "HIGH",
            "cwe": "CWE-284",
            "rule_ids": ["TX_ORIGIN_AUTH"],
            "remediation": (
                "Always use msg.sender for authentication. Never use tx.origin for access "
                "control. tx.origin may only be used to prevent contract-to-contract calls "
                "when that is explicitly the desired behavior."
            ),
            "reference": "https://swcregistry.io/docs/SWC-115",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Unprotected selfdestruct: A selfdestruct() call in a function without "
            "onlyOwner guard allows any attacker to permanently destroy the contract and "
            "steal its ETH balance. Parity Multisig bug November 2017 enabled an attacker "
            "to selfdestruct a library contract, bricking $150M in wallets."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "rule_ids": ["UNPROTECTED_SELFDESTRUCT", "ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Always guard selfdestruct with onlyOwner or multisig. Consider removing "
                "selfdestruct entirely (it is deprecated in Solidity 0.8.18+). "
                "Use pausable patterns instead of self-destruction."
            ),
            "reference": "https://github.com/openethereum/parity-ethereum/issues/6995",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Admin key compromise patterns: Protocols controlled by a single EOA private "
            "key are vulnerable to key theft. Ronin Bridge ($625M, March 2022) used a "
            "5-of-9 multisig but 4 keys were held by one organization. Key compromise "
            "enabled attackers to forge withdrawal approvals."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "rule_ids": ["ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Use hardware security modules for key storage. Require geographically "
                "distributed multisig signers. Use timelock contracts (minimum 48h) for "
                "all admin operations. Implement on-chain governance for major changes."
            ),
            "reference": "https://roninnetwork.com/post/ronin-security-breach",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Missing zero-address checks: Functions accepting address parameters don't "
            "validate against address(0). Setting owner, fee recipient, or token address "
            "to zero permanently bricks contract functionality or loses ETH/tokens "
            "sent to the zero address."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "MEDIUM",
            "cwe": "CWE-284",
            "rule_ids": ["ZERO_ADDRESS_CHECK"],
            "remediation": (
                "Add require(addr != address(0), 'Zero address') checks for all "
                "address-type parameters in constructor and setter functions. "
                "Use OpenZeppelin's Address library utilities."
            ),
            "reference": "https://code4rena.com/reports/2023-02-ethos",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Unprotected upgrade function in UUPS proxy: The upgradeTo() or upgradeToAndCall() "
            "function in a UUPS proxy implementation lacks access control. Any caller can "
            "replace the implementation contract with malicious code. OpenZeppelin's UUPS "
            "module requires overriding _authorizeUpgrade() with onlyOwner."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "rule_ids": ["UNPROTECTED_UPGRADE", "ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Override _authorizeUpgrade with appropriate access control (onlyOwner, "
                "onlyGovernance, etc.). Use OpenZeppelin UUPSUpgradeable. Add a timelock "
                "and announcement period before upgrades take effect."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/proxy#UUPSUpgradeable",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Default admin role exposure: When using OpenZeppelin AccessControl, the "
            "DEFAULT_ADMIN_ROLE is automatically assigned to the deployer. If the deployer "
            "address is later compromised or if admin role is not properly rotated to a "
            "multisig/timelock, a single point of failure exists."
        ),
        "metadata": {
            "category": "Access Control",
            "severity": "HIGH",
            "cwe": "CWE-284",
            "rule_ids": ["ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Transfer DEFAULT_ADMIN_ROLE to a multisig/timelock immediately after "
                "deployment. Renounce the deployer's admin role. Use "
                "AccessControlDefaultAdminRules extension for a two-step admin transfer "
                "with mandatory delay."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/5.x/api/access#AccessControlDefaultAdminRules",
            "source": "Manual Curation",
        },
    },

    # =========================================================================
    # FLASH LOAN (8 entries)
    # =========================================================================
    {
        "text": (
            "Price manipulation via flash loan: An attacker borrows large amounts with no "
            "collateral (flash loan), uses them to move AMM pool prices, exploits a "
            "dependent protocol that uses the manipulated price, then repays the loan in "
            "the same transaction. bZx Protocol lost $350k in February 2020 — one of the "
            "first major flash loan exploits."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["FLASH_LOAN_ORACLE", "ORACLE_MANIPULATION"],
            "remediation": (
                "Use time-weighted prices instead of spot prices. Add reentrancy guards "
                "that prevent flash-loan-within-execution patterns. Implement per-block "
                "borrow limits to make large flash loans uneconomical."
            ),
            "reference": "https://medium.com/peckshield/bzx-hack-full-disclosure-with-detailed-profit-analysis-e6b1fa9b18fc",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Collateral drain via flash loan: An attacker uses a flash loan to temporarily "
            "increase their collateral, borrows against it, withdraws the collateral, and "
            "exits. The protocol is left with under-collateralised positions. Seen in "
            "Compound and Aave when collateral factors were set too high."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["FLASH_LOAN_ORACLE"],
            "remediation": (
                "Block flash loans from the same token used as collateral within one block. "
                "Apply conservative collateral factors. Use time-delayed price oracle for "
                "collateral valuation."
            ),
            "reference": "https://compound.finance/governance/proposals/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Governance vote manipulation via flash loan: An attacker takes a flash loan "
            "of governance tokens to acquire temporary voting power, votes on a malicious "
            "proposal, executes the proposal in the same transaction, and repays the loan. "
            "Beanstalk Farms lost $182M in April 2022 using this exact vector."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["GOVERNANCE_FLASH_LOAN", "FLASH_LOAN_ORACLE"],
            "remediation": (
                "Snapshot voting power at a prior block (block.number - 1 or earlier). "
                "Never count flash-borrowed tokens for governance. Add minimum holding "
                "period requirements before tokens confer voting rights."
            ),
            "reference": "https://medium.com/beanstalk-farms/beanstalk-farms-post-mortem-and-governance-proposals",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Flash mint exploit: Protocols that mint tokens to callers (ERC20FlashMint) "
            "can have their entire supply temporarily available to an attacker. If the "
            "minted tokens can be used as collateral within the same transaction, the "
            "attacker gains enormous leverage. MakerDAO's flash mint module was "
            "specifically designed to prevent this."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["FLASH_LOAN_ORACLE"],
            "remediation": (
                "Flash-minted tokens must not be usable as collateral within the same "
                "transaction. Add transient storage flags (EIP-1153) or reentrancy guards "
                "to prevent within-transaction collateral deposits."
            ),
            "reference": "https://eips.ethereum.org/EIPS/eip-3156",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Flash loan + reentrancy combination: The most dangerous attacks combine a "
            "flash loan to gain capital with reentrancy to execute multiple state-corrupting "
            "calls. Euler Finance March 2023 ($197M) used a donation function that skipped "
            "health factor checks combined with self-liquidation via a flash loan."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "CRITICAL",
            "cwe": "CWE-841",
            "rule_ids": ["FLASH_LOAN_REENTRANCY", "REENTRANCY_PATTERN"],
            "remediation": (
                "Apply reentrancy guards to all flash loan callback paths. Enforce health "
                "factor checks at the END of every execution path, not just entry points. "
                "Review all donation/transfer functions for health factor bypass."
            ),
            "reference": "https://immunefi.com/bounty/euler/",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "LP token price manipulation via flash loan: Protocols using LP token prices "
            "as collateral can be exploited by flash-swapping to manipulate pool reserves. "
            "Alpha Homora V2 ($37.5M, February 2021) was exploited via Cream Finance's "
            "cyWETH market using this technique."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["FLASH_LOAN_ORACLE", "ORACLE_MANIPULATION"],
            "remediation": (
                "Use fair LP pricing models that cannot be manipulated by single-block "
                "reserve changes. Alpha Finance model: LP_value = 2 * sqrt(r0 * r1) * p "
                "is less manipulatable than reserve-ratio-based models."
            ),
            "reference": "https://blog.alphafinance.io/alpha-homora-v2-post-mortem/",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Vault share inflation (first-depositor attack) via flash loan: An attacker "
            "makes a tiny initial deposit to a vault, then donates a large amount directly "
            "to inflate the share price. Subsequent depositors receive far fewer shares "
            "than expected. The attacker redeems their shares for a profit exceeding "
            "the depositor's loss."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "HIGH",
            "cwe": "CWE-682",
            "rule_ids": ["VAULT_INFLATION", "INTEGER_PRECISION"],
            "remediation": (
                "Add virtual shares (OpenZeppelin ERC4626 offset): use "
                "totalAssets() + 1 and totalSupply() + 10**decimalsOffset() in share "
                "calculations to make the attack prohibitively expensive."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/erc4626",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Flash loan arbitrage in callback: The flash loan receiver callback can be "
            "used to perform multi-step DeFi arbitrage before repaying. While usually "
            "benign, some protocols naively allow arbitrary calldata in callbacks, enabling "
            "attackers to drain approved token allowances or exploit callback-specific logic."
        ),
        "metadata": {
            "category": "Flash Loan",
            "severity": "MEDIUM",
            "cwe": "CWE-20",
            "rule_ids": ["FLASH_LOAN_REENTRANCY"],
            "remediation": (
                "Restrict flash loan callback calldata strictly. Validate callback "
                "originates from your own contract. Do not execute arbitrary user-supplied "
                "calldata in flash loan callbacks."
            ),
            "reference": "https://code4rena.com/reports/2022-06-notional",
            "source": "Code4rena",
        },
    },

    # =========================================================================
    # INTEGER / PRECISION (8 entries)
    # =========================================================================
    {
        "text": (
            "Unsafe downcast from uint256 to uint128 (or smaller): Solidity 0.8 catches "
            "arithmetic overflow but NOT truncation from downcasting. A value like "
            "2**128 + 1 silently becomes 1 when cast to uint128. Uniswap V3's position "
            "accounting uses uint128 for liquidity and incorrect casting can cause "
            "accounting errors."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "HIGH",
            "cwe": "CWE-197",
            "rule_ids": ["UNSAFE_DOWNCAST", "INTEGER_PRECISION"],
            "remediation": (
                "Use OpenZeppelin SafeCast library for all type conversions. "
                "Add explicit bounds checks before downcasting: "
                "require(value <= type(uint128).max). Use toUint128() from SafeCast."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeCast",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Divide-before-multiply precision loss: Integer division truncates in Solidity. "
            "Computing (a / b) * c loses precision compared to (a * c) / b. "
            "In fee calculations and share price math, this can result in consistent "
            "underpayment or overpayment across thousands of transactions, leading to "
            "significant fund drainage over time."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "MEDIUM",
            "cwe": "CWE-682",
            "rule_ids": ["DIVIDE_BEFORE_MULTIPLY", "INTEGER_PRECISION"],
            "remediation": (
                "Always multiply before dividing. Scale up intermediate results using "
                "fixed-point math libraries (e.g., PRBMath, FixedPoint96 from Uniswap). "
                "Use mulDiv() with rounding direction control."
            ),
            "reference": "https://solodit.xyz/issues/divide-before-multiply-precision-loss",
            "source": "Solodit",
        },
    },
    {
        "text": (
            "Rounding direction exploitation in share redemption: Vaults that round shares "
            "DOWN during deposit and DOWN during redemption (or vice versa) can be exploited. "
            "An attacker repeatedly deposits and withdraws, each time extracting rounding "
            "error from other depositors. ERC4626 standard specifies rounding must always "
            "favor the VAULT, not the user."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "HIGH",
            "cwe": "CWE-682",
            "rule_ids": ["INTEGER_PRECISION", "VAULT_INFLATION"],
            "remediation": (
                "Follow ERC4626's rounding rules strictly: convertToShares ROUNDS DOWN "
                "(protects vault at deposit), convertToAssets ROUNDS DOWN (protects vault "
                "at redemption). Use mulDiv with rounding mode parameter."
            ),
            "reference": "https://eips.ethereum.org/EIPS/eip-4626",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Phantom overflow in unchecked blocks: Solidity 0.8+ wraps arithmetic in "
            "checked mode, but unchecked {} blocks disable this protection for gas savings. "
            "If a developer uses unchecked for a loop counter but also performs subtraction "
            "inside, underflow can produce a very large positive number."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "HIGH",
            "cwe": "CWE-190",
            "rule_ids": ["UNCHECKED_BLOCK", "INTEGER_PRECISION"],
            "remediation": (
                "Limit unchecked blocks to operations that are provably safe (e.g., "
                "loop counter increments where overflow is impossible). Never place "
                "subtraction or multiplication inside unchecked without explicit range proofs."
            ),
            "reference": "https://code4rena.com/reports/2022-11-stakehouse",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Fee calculation truncation: Protocols that compute fees as a percentage "
            "using integer math may truncate to zero for small transactions. An attacker "
            "can shard a large transaction into many small ones to pay zero fees. "
            "This drains the protocol's fee income and can be used for free transactions."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "MEDIUM",
            "cwe": "CWE-682",
            "rule_ids": ["INTEGER_PRECISION"],
            "remediation": (
                "Enforce minimum fee amounts. Use ceiling division (mulDivUp) when "
                "computing fees. Add a minimum transaction size to prevent micro-shard attacks."
            ),
            "reference": "https://code4rena.com/reports/2023-01-biconomy",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Share price manipulation via rounding (ERC4626 inflation attack): A first "
            "depositor mints 1 share for 1 wei, then donates large amounts to inflate the "
            "price per share. The next depositor deposits N tokens but receives 0 shares "
            "due to rounding, effectively gifting their tokens to the first depositor."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "HIGH",
            "cwe": "CWE-682",
            "rule_ids": ["VAULT_INFLATION", "INTEGER_PRECISION"],
            "remediation": (
                "Use OpenZeppelin's ERC4626 with virtual offset decimals. Deploy an "
                "initial seed deposit from the protocol treasury. Cap maximum share "
                "price inflation per block."
            ),
            "reference": "https://github.com/OpenZeppelin/openzeppelin-contracts/issues/3706",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Fixed-point arithmetic overflow in 256-bit math: Protocols using FixedPoint128 "
            "or FixedPoint96 can overflow 256-bit values when intermediate products exceed "
            "2**256. Uniswap V3 uses mulmod and specific 512-bit multiplication routines "
            "to avoid this. Protocols that copy Uniswap math without understanding can "
            "introduce subtle overflow bugs."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "HIGH",
            "cwe": "CWE-190",
            "rule_ids": ["INTEGER_PRECISION"],
            "remediation": (
                "Use Uniswap V3's FullMath library for 512-bit intermediate products. "
                "Test edge cases with type(uint256).max inputs. Use formal verification "
                "tools for critical arithmetic."
            ),
            "reference": "https://github.com/Uniswap/v3-core/blob/main/contracts/libraries/FullMath.sol",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Token decimal mismatch: A protocol assumes all tokens have 18 decimals but "
            "interacts with 6-decimal (USDC, USDT) or 8-decimal (WBTC) tokens. Price "
            "calculations are off by 10**12 or more, leading to extreme over/under-valuation "
            "of collateral. Seen in multiple early DeFi protocols."
        ),
        "metadata": {
            "category": "Integer/Precision",
            "severity": "HIGH",
            "cwe": "CWE-682",
            "rule_ids": ["INTEGER_PRECISION", "ORACLE_MANIPULATION"],
            "remediation": (
                "Always read decimals() from the token contract at runtime. Normalise all "
                "token amounts to a standard internal precision (e.g., 18 decimal WAD) "
                "before any cross-token arithmetic."
            ),
            "reference": "https://code4rena.com/reports/2022-08-mimo",
            "source": "Code4rena",
        },
    },

    # =========================================================================
    # STORAGE COLLISION (8 entries)
    # =========================================================================
    {
        "text": (
            "Proxy storage collision (EIP-1967): Early proxy patterns stored the "
            "implementation address at storage slot 0, which conflicts with the first state "
            "variable of the implementation contract. EIP-1967 standardises implementation "
            "storage at keccak256('eip1967.proxy.implementation') - 1. "
            "Projects not following EIP-1967 risk admin slot overwrites."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "CRITICAL",
            "cwe": "CWE-119",
            "rule_ids": ["STORAGE_COLLISION_RISK"],
            "remediation": (
                "Use EIP-1967 standard slots for all proxy storage. Use OpenZeppelin "
                "TransparentUpgradeableProxy or UUPS pattern. Run slither's proxy-storage "
                "checker before deployment."
            ),
            "reference": "https://eips.ethereum.org/EIPS/eip-1967",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Uninitialized proxy implementation: A proxy delegates to an implementation "
            "contract that has never been initialized. An attacker calls initialize() "
            "on the bare implementation, sets themselves as owner, and calls selfdestruct "
            "or upgradeTo with malicious code. Affects the proxy since implementation "
            "state bleeds through delegatecall context."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "CRITICAL",
            "cwe": "CWE-119",
            "rule_ids": ["UNPROTECTED_INITIALIZER", "STORAGE_COLLISION_RISK"],
            "remediation": (
                "Call _disableInitializers() in the implementation contract's constructor. "
                "This sets the initialized state variable to max, preventing any future "
                "initialization calls."
            ),
            "reference": "https://docs.openzeppelin.com/upgrades-plugins/1.x/writing-upgradeable#initializing_the_implementation_contract",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "UUPS upgrade storage gap: When an upgradeable contract adds new state variables "
            "in an upgrade, it shifts subsequent variables in storage. If the upgraded "
            "implementation does not maintain the same storage layout, inherited variable "
            "slots collide. Using __gap arrays reserves space for future variables."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "HIGH",
            "cwe": "CWE-119",
            "rule_ids": ["STORAGE_COLLISION_RISK"],
            "remediation": (
                "Add uint256[50] private __gap; at the end of each upgradeable base "
                "contract. Use OpenZeppelin Upgrades plugin storage layout validation "
                "before deploying any upgrade."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/upgradeable",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Diamond storage slot collision: EIP-2535 Diamond contracts use namespaced "
            "storage to avoid collisions, but incorrect slot calculation can lead to "
            "two facets sharing the same storage region. This results in one facet "
            "corrupting another's data."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "HIGH",
            "cwe": "CWE-119",
            "rule_ids": ["STORAGE_COLLISION_RISK"],
            "remediation": (
                "Use unique, well-documented storage positions: keccak256('diamond.storage.MyFacet') "
                "for each facet's struct. Use the Diamond Storage or AppStorage pattern. "
                "Run storage collision analysis before adding new facets."
            ),
            "reference": "https://eips.ethereum.org/EIPS/eip-2535",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Beacon proxy storage layout: Beacon proxies share a single implementation "
            "pointed to by a beacon. If the beacon address storage slot is not EIP-1967 "
            "compliant, upgrading the beacon can overwrite proxy state variables."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "HIGH",
            "cwe": "CWE-119",
            "rule_ids": ["STORAGE_COLLISION_RISK"],
            "remediation": (
                "Use OpenZeppelin BeaconProxy implementation that uses EIP-1967 beacon "
                "slot. Verify beacon upgrade operations with Hardhat Upgrades plugin."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/proxy#BeaconProxy",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Transparent proxy admin slot collision: In the Transparent Proxy pattern, "
            "the admin address is stored in a dedicated slot. If a function in the logic "
            "contract coincidentally uses the same slot (via inline assembly or a mapping "
            "key collision), the admin address can be overwritten."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "HIGH",
            "cwe": "CWE-119",
            "rule_ids": ["STORAGE_COLLISION_RISK"],
            "remediation": (
                "Use EIP-1967 compliant storage slots. Audit all assembly-level storage "
                "operations. Use Slither's proxy-related detectors."
            ),
            "reference": "https://blog.openzeppelin.com/the-transparent-proxy-pattern/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Delegatecall storage overwrite: A contract uses delegatecall to invoke "
            "library code that writes to specific storage slots. If the library was "
            "written for a different contract layout, its slot assignments overwrite "
            "critical state variables in the calling contract."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "CRITICAL",
            "cwe": "CWE-119",
            "rule_ids": ["DELEGATECALL_USAGE", "STORAGE_COLLISION_RISK"],
            "remediation": (
                "Only delegatecall to libraries whose storage layout matches or is "
                "compatible with the calling contract. Use Diamond Storage or namespaced "
                "structs to isolate library storage."
            ),
            "reference": "https://solodit.xyz/issues/delegatecall-storage-overwrite",
            "source": "Solodit",
        },
    },
    {
        "text": (
            "Mapping storage collision: Two mappings with different key types that hash to "
            "the same slot can overwrite each other's data. This is extremely rare in "
            "practice but can occur in complex protocols with many mappings at non-trivial "
            "starting slots, or when using assembly to compute mapping slots manually."
        ),
        "metadata": {
            "category": "Storage Collision",
            "severity": "MEDIUM",
            "cwe": "CWE-119",
            "rule_ids": ["STORAGE_COLLISION_RISK"],
            "remediation": (
                "Document all storage slot usage. Use the Solidity compiler's storage "
                "layout JSON output to verify no two variables occupy the same slot. "
                "Avoid manual slot computation."
            ),
            "reference": "https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html",
            "source": "Manual Curation",
        },
    },

    # =========================================================================
    # FRONT-RUNNING (8 entries)
    # =========================================================================
    {
        "text": (
            "Sandwich attack on DEX swap: MEV bots monitor the mempool for large pending "
            "swaps. They front-run by buying the same token before the victim's swap "
            "executes, then sell immediately after. The victim receives a worse price, "
            "and the sandwich bot profits from the artificially inflated buy price. "
            "Billions of dollars extracted from Ethereum users annually."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "HIGH",
            "cwe": "CWE-362",
            "rule_ids": ["FRONT_RUNNING", "MEV_SANDWICH"],
            "remediation": (
                "Set tight slippage tolerance (1-3%). Use private transaction relays "
                "(Flashbots Protect, MEV Blocker). Use commit-reveal or batch auction "
                "DEX designs. Add amountOutMinimum checks."
            ),
            "reference": "https://docs.flashbots.net/flashbots-protect/overview",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "MEV extraction from liquidations: Liquidation bots race to liquidate "
            "undercollateralised positions for the liquidation bonus. Front-runners can "
            "outbid legitimate liquidators, reducing protocol security as real liquidators "
            "are crowded out. In extreme cases, bad debt accumulates when no profitable "
            "liquidation opportunity exists for non-MEV actors."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "MEDIUM",
            "cwe": "CWE-362",
            "rule_ids": ["FRONT_RUNNING"],
            "remediation": (
                "Use Dutch auction liquidation mechanisms with gradually increasing "
                "incentives. Implement private liquidation queues or order auctions. "
                "Aave V3 uses a liquidation bonus that grows over time."
            ),
            "reference": "https://docs.aave.com/developers/guides/liquidations",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Front-running NFT mint: When an NFT mint transaction is broadcast, "
            "bots see the metadata or token ID being minted and insert a higher-gas "
            "transaction to acquire specific rare tokens before the original buyer. "
            "Common in lazy-mint NFT drops where tokenIds are predictable."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "MEDIUM",
            "cwe": "CWE-362",
            "rule_ids": ["FRONT_RUNNING"],
            "remediation": (
                "Use commit-reveal schemes for rare trait assignment. Randomize token "
                "ID assignment with verifiable on-chain randomness (Chainlink VRF). "
                "Use private mempools for mint transactions."
            ),
            "reference": "https://blog.openzeppelin.com/deconstructing-a-solidity-contract-part-vi-the-swarm-hash",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Commit-reveal scheme bypass: A two-phase commit-reveal meant to prevent "
            "front-running is insufficiently implemented. The commitment doesn't include "
            "enough entropy (e.g., missing nonce or timestamp), allowing attackers to "
            "pre-image attack or brute-force the commitment to reveal early."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "MEDIUM",
            "cwe": "CWE-362",
            "rule_ids": ["FRONT_RUNNING"],
            "remediation": (
                "Commitment must include: secret value, msg.sender, block number, and "
                "nonce. Hash as keccak256(abi.encodePacked(secret, sender, nonce)). "
                "Enforce a reveal window and punish non-reveals."
            ),
            "reference": "https://swcregistry.io/docs/SWC-114",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Approval front-running (ERC20 approve race condition): When a token holder "
            "changes an allowance from N to M (both > 0), an approved spender can "
            "front-run the change, first spending the original allowance N, then M, "
            "spending N+M in total. This is why increaseAllowance/decreaseAllowance "
            "functions were introduced."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "MEDIUM",
            "cwe": "CWE-362",
            "rule_ids": ["ERC20_APPROVE_RACE", "FRONT_RUNNING"],
            "remediation": (
                "Use increaseAllowance() and decreaseAllowance() instead of approve(). "
                "Alternatively set allowance to 0 first before setting a new non-zero "
                "allowance. Use ERC20Permit (EIP-2612) for gasless approvals."
            ),
            "reference": "https://swcregistry.io/docs/SWC-114",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "First-depositor share inflation attack (front-running variant): An attacker "
            "monitors the mempool for the first deposit transaction to a new vault. They "
            "front-run it with a tiny deposit, then immediately inflate the share price by "
            "donating directly. The original first depositor receives 0 shares."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "HIGH",
            "cwe": "CWE-362",
            "rule_ids": ["VAULT_INFLATION", "FRONT_RUNNING"],
            "remediation": (
                "Protocol should seed the vault with a non-trivial initial deposit at "
                "deployment (making the attack unprofitable). Use virtual shares offset "
                "(OpenZeppelin ERC4626 offset feature)."
            ),
            "reference": "https://code4rena.com/reports/2023-01-sherlock",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Auction sniping: In English auction contracts, bidders watch for the "
            "auction end block and submit winning bids at the last possible moment, "
            "giving competitors no time to respond. Gas price manipulation can even "
            "delay competitor transactions past the deadline."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "LOW",
            "cwe": "CWE-362",
            "rule_ids": ["FRONT_RUNNING"],
            "remediation": (
                "Use soft close mechanisms: extend the auction deadline each time a "
                "new bid arrives within the last N minutes. Use Vickrey (sealed-bid) "
                "auction designs."
            ),
            "reference": "https://code4rena.com/reports/2022-11-fractional",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Priority gas auction (PGA) / sandwich on governance: Governance proposal "
            "execution transactions are visible in the mempool. Sophisticated attackers "
            "can insert transactions between the proposal execution and the state it "
            "modifies, front-running the protocol configuration change."
        ),
        "metadata": {
            "category": "Front-running",
            "severity": "HIGH",
            "cwe": "CWE-362",
            "rule_ids": ["FRONT_RUNNING", "GOVERNANCE_FLASH_LOAN"],
            "remediation": (
                "Announce governance changes with a mandatory time delay (timelock). "
                "Use private mempools or flashbots bundles for governance execution. "
                "Add on-chain commitment schemes for sensitive parameter changes."
            ),
            "reference": "https://medium.com/coinmonks/on-the-risks-of-governance",
            "source": "Manual Curation",
        },
    },

    # =========================================================================
    # DELEGATE CALL (6 entries)
    # =========================================================================
    {
        "text": (
            "Storage hijack via delegatecall: A contract exposes a function that "
            "delegatecalls to a user-supplied address. The attacker passes the address "
            "of a malicious contract that overwrites storage slot 0 (owner variable) "
            "with the attacker's address. Parity Library hack (November 2017) used "
            "this exact pattern."
        ),
        "metadata": {
            "category": "Delegate Call",
            "severity": "CRITICAL",
            "cwe": "CWE-829",
            "rule_ids": ["DELEGATECALL_USAGE"],
            "remediation": (
                "Never allow user-controlled addresses in delegatecall. Whitelist "
                "implementation addresses. Use Proxy patterns from audited libraries only."
            ),
            "reference": "https://blog.openzeppelin.com/on-the-parity-wallet-multisig-hack/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Implementation contract selfdestruct via delegatecall: A proxy's "
            "implementation contract contains a selfdestruct instruction guarded "
            "only by an onlyOwner check. If the owner is address(0) or if the "
            "implementation is callable directly, an attacker can destroy the "
            "implementation, making the proxy non-functional. Parity Wallet Nov 2017."
        ),
        "metadata": {
            "category": "Delegate Call",
            "severity": "CRITICAL",
            "cwe": "CWE-829",
            "rule_ids": ["DELEGATECALL_USAGE", "UNPROTECTED_SELFDESTRUCT"],
            "remediation": (
                "Never include selfdestruct in implementation contracts. Call "
                "_disableInitializers() in implementation constructor to prevent "
                "direct invocation. Audit all code paths for selfdestruct presence."
            ),
            "reference": "https://github.com/nicksavers/ethereum-alarm-clock/issues/238",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Uninitialized implementation contract: A deployed but uninitialized "
            "implementation contract has its owner set to address(0) by default. "
            "Anyone can call initialize() directly on the implementation (not the proxy) "
            "and become the owner, then exploit any owner-only functionality."
        ),
        "metadata": {
            "category": "Delegate Call",
            "severity": "CRITICAL",
            "cwe": "CWE-829",
            "rule_ids": ["UNPROTECTED_INITIALIZER", "DELEGATECALL_USAGE"],
            "remediation": (
                "Call _disableInitializers() in the constructor of every implementation "
                "contract. This sets the internal initialized flag to type(uint8).max "
                "preventing any initialization."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Proxy function selector clash: In transparent proxy pattern, if a function "
            "selector in the implementation matches the proxy's admin functions (e.g., "
            "upgradeTo, changeAdmin), admin calls intended for the proxy are forwarded "
            "to the implementation instead. This can lock the admin out."
        ),
        "metadata": {
            "category": "Delegate Call",
            "severity": "HIGH",
            "cwe": "CWE-829",
            "rule_ids": ["DELEGATECALL_USAGE"],
            "remediation": (
                "Check for selector collisions before adding functions. Use "
                "OpenZeppelin's ProxyAdmin contract which routes admin calls through "
                "a separate admin contract, not through the proxy itself."
            ),
            "reference": "https://blog.openzeppelin.com/the-transparent-proxy-pattern/",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Delegatecall to untrusted contract: A contract performs a delegatecall "
            "to an address taken from user input or unchecked configuration. The target "
            "contract can perform arbitrary actions in the calling contract's storage "
            "context, potentially draining funds or corrupting state."
        ),
        "metadata": {
            "category": "Delegate Call",
            "severity": "CRITICAL",
            "cwe": "CWE-829",
            "rule_ids": ["DELEGATECALL_USAGE"],
            "remediation": (
                "Whitelist all addresses that can be delegatecalled. Use time-locked "
                "governance to update the whitelist. Validate bytecode hash of target "
                "before delegatecall."
            ),
            "reference": "https://swcregistry.io/docs/SWC-112",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Context confusion in delegatecall: A library called via delegatecall "
            "uses msg.sender and msg.value believing it is the direct caller. "
            "The library may grant permissions based on msg.sender being a trusted "
            "address, but in delegatecall context msg.sender is the original caller "
            "of the proxy, not the proxy itself."
        ),
        "metadata": {
            "category": "Delegate Call",
            "severity": "MEDIUM",
            "cwe": "CWE-829",
            "rule_ids": ["DELEGATECALL_USAGE"],
            "remediation": (
                "Library functions used via delegatecall must not rely on msg.sender "
                "for access control if called in proxy context. Document all delegatecall "
                "callsites and their expected context."
            ),
            "reference": "https://solodit.xyz/issues/context-confusion-delegatecall",
            "source": "Solodit",
        },
    },

    # =========================================================================
    # LOGIC BUGS (10 entries)
    # =========================================================================
    {
        "text": (
            "Off-by-one error in loop bounds: A for loop iterates with condition "
            "i <= length instead of i < length, accessing array[length] which is out "
            "of bounds. In Solidity, this reverts with a panic. In less-safe languages, "
            "it reads adjacent memory. Critical in reward distribution loops where one "
            "extra iteration drains extra tokens."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "HIGH",
            "cwe": "CWE-193",
            "rule_ids": ["OFF_BY_ONE"],
            "remediation": (
                "Use < (strictly less than) for array index bounds. Write unit tests "
                "with arrays of size 0, 1, and n. Use Foundry fuzz testing with "
                "arbitrary array sizes."
            ),
            "reference": "https://swcregistry.io/docs/SWC-101",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Incorrect return value handling: Low-level call() returns false instead of "
            "reverting when the target reverts. If the return value is not checked, "
            "the calling contract assumes the call succeeded and updates state incorrectly. "
            "The infamous King of Ether vulnerability used unchecked send() (pre-Solidity 0.4.13)."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "HIGH",
            "cwe": "CWE-252",
            "rule_ids": ["UNCHECKED_EXTERNAL_CALL"],
            "remediation": (
                "Always check bool success = call{...}(data) and revert on failure. "
                "Use OpenZeppelin Address.functionCall() which automatically checks "
                "and propagates reverts."
            ),
            "reference": "https://swcregistry.io/docs/SWC-104",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Missing return statement: A Solidity function declared to return a value "
            "has a code path that reaches the end without a return statement. Older Solidity "
            "versions return zero; newer versions revert. This can cause silent failures "
            "in ERC20 transfer functions that forgot to return true."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "MEDIUM",
            "cwe": "CWE-252",
            "rule_ids": ["MISSING_RETURN"],
            "remediation": (
                "Enable all compiler warnings. Use return statement in every code path. "
                "Declare function as view if it should return a value. Add unit tests "
                "that assert return values."
            ),
            "reference": "https://swcregistry.io/docs/SWC-104",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Wrong comparison operator: Using <= instead of < (or vice versa) in a "
            "critical comparison. For example, a collateral check using "
            "`collateral >= debt` when it should be `collateral > debt` allows a user "
            "to borrow exactly their collateral value, creating an immediate bad debt position."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "HIGH",
            "cwe": "CWE-697",
            "rule_ids": ["LOGIC_BUG"],
            "remediation": (
                "Use fuzz testing with boundary values. Formally verify all comparison "
                "operators in financial calculations. Code review should specifically "
                "check boundary conditions."
            ),
            "reference": "https://code4rena.com/reports/2023-03-wenwin",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Unchecked array length: A function accepts an array parameter and iterates "
            "over it without checking its length. An attacker passes a very large array, "
            "causing the function to hit the gas limit and revert, permanently blocking "
            "protocol operations (griefing/DoS)."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "MEDIUM",
            "cwe": "CWE-400",
            "rule_ids": ["GAS_LIMIT_DOS"],
            "remediation": (
                "Add require(array.length <= MAX_BATCH_SIZE) to all public/external "
                "functions accepting arrays. Process large arrays off-chain and submit "
                "Merkle proofs on-chain."
            ),
            "reference": "https://code4rena.com/reports/2022-10-blur",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Stale cache / state desynchronisation: A contract caches a value from an "
            "external contract at call time but uses it later when the external state "
            "may have changed. For example, caching a Chainlink price in memory at "
            "function start and using it after several external calls that may have "
            "updated the price."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "MEDIUM",
            "cwe": "CWE-362",
            "rule_ids": ["STALE_STATE"],
            "remediation": (
                "Re-read external state values immediately before using them in "
                "critical calculations. Use storage rather than memory for values that "
                "must remain consistent across a transaction."
            ),
            "reference": "https://solodit.xyz/issues/stale-cache-state",
            "source": "Solodit",
        },
    },
    {
        "text": (
            "Incorrect ternary logic: A ternary expression has the true and false "
            "branches swapped. For example: amount = isDeposit ? fee : principal "
            "when it should be isDeposit ? principal : fee. These bugs are hard to "
            "spot in review and can invert core protocol logic."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "HIGH",
            "cwe": "CWE-697",
            "rule_ids": ["LOGIC_BUG"],
            "remediation": (
                "Use descriptive variable names that make intent obvious. Write unit "
                "tests for both branches of every ternary. Consider extracting "
                "complex ternaries to named functions."
            ),
            "reference": "https://code4rena.com/reports/2023-02-notional",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Double-spend via race condition: A contract allows the same resource "
            "(e.g., a voucher, NFT entitlement, or reward) to be spent twice due to "
            "missing nonce or used-flag tracking. Concurrent transactions that both "
            "pass the validity check before either marks the resource as used."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "HIGH",
            "cwe": "CWE-362",
            "rule_ids": ["DOUBLE_SPEND"],
            "remediation": (
                "Use nonces mapped by address. Mark vouchers/signatures as consumed "
                "using a mapping(bytes32 => bool) before any state changes. "
                "Use EIP-712 structured signatures with nonce replay protection."
            ),
            "reference": "https://code4rena.com/reports/2022-09-nouns-builder",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Incorrect fee calculation direction: A protocol computes fee as "
            "amount * feeBps / 10000 but should use amount * feeBps / (10000 + feeBps) "
            "for inclusive fees, or vice versa. This is common in DEX router contracts "
            "and causes the protocol to collect either too much or too little in fees."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "MEDIUM",
            "cwe": "CWE-682",
            "rule_ids": ["LOGIC_BUG", "INTEGER_PRECISION"],
            "remediation": (
                "Clearly document whether fees are inclusive or exclusive. Write tests "
                "comparing fee amounts at 0%, 0.3%, 1%, and 10% fee rates. "
                "Cross-reference against the fee specification document."
            ),
            "reference": "https://code4rena.com/reports/2023-04-spool",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Unhandled edge case when totalSupply is zero: Reward distribution logic "
            "divides by totalSupply. When totalSupply is zero (all tokens burned or "
            "pool just created), the division reverts or produces infinity. This can "
            "permanently block reward distribution."
        ),
        "metadata": {
            "category": "Logic Bugs",
            "severity": "MEDIUM",
            "cwe": "CWE-369",
            "rule_ids": ["DIVIDE_BY_ZERO"],
            "remediation": (
                "Guard all division operations: if (totalSupply == 0) return 0; "
                "Test with empty pools and 0 supply conditions. Use fuzz testing "
                "with totalSupply from 0 to type(uint256).max."
            ),
            "reference": "https://code4rena.com/reports/2022-09-y2k-finance",
            "source": "Code4rena",
        },
    },

    # =========================================================================
    # CROSS-CHAIN / BRIDGE (5 entries)
    # =========================================================================
    {
        "text": (
            "Cross-chain replay attack: A signed message valid on one chain is replayed "
            "on another chain. Without a chain ID in the signed payload, the same signature "
            "grants the same permission on every EVM chain. Replay attacks are common after "
            "chain forks and during cross-chain airdrop claims."
        ),
        "metadata": {
            "category": "Cross-chain/Bridge",
            "severity": "HIGH",
            "cwe": "CWE-294",
            "rule_ids": ["SIGNATURE_REPLAY"],
            "remediation": (
                "Include block.chainid in all signed messages. Use EIP-712 domain "
                "separators which include chainId and verifyingContract. Update domain "
                "separator on chain ID changes (EIP-2612 pattern)."
            ),
            "reference": "https://swcregistry.io/docs/SWC-121",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Bridge message validation bypass: A bridge contract verifies incoming "
            "messages using a threshold of validator signatures. If the message format "
            "validation is insufficiently strict, an attacker can craft a message that "
            "passes signature checks but triggers unintended behavior. Wormhole $320M "
            "hack February 2022 exploited a guardian signature verification bypass."
        ),
        "metadata": {
            "category": "Cross-chain/Bridge",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["BRIDGE_VALIDATION"],
            "remediation": (
                "Strictly validate all message fields. Use a well-audited signature "
                "verification library. Employ strict message deduplication using "
                "nonces and sequence numbers."
            ),
            "reference": "https://wormhole.com/wormhole-launches-guardian-network/",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Wormhole VAA (Verified Action Approval) signature bypass: In the Wormhole "
            "bridge exploit (February 2022), an attacker exploited a deprecated Solana "
            "syscall (verify_signature) that had not been properly guarded, allowing "
            "forged VAA signatures. 120,000 wETH (~$320M) was minted without backing."
        ),
        "metadata": {
            "category": "Cross-chain/Bridge",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["BRIDGE_VALIDATION"],
            "remediation": (
                "Use the current, audited signature verification APIs. Remove or guard "
                "all deprecated functions. Implement automated detection of deprecated "
                "instruction usage in CI pipelines."
            ),
            "reference": "https://extropy-io.medium.com/solanas-wormhole-hack-post-mortem-analysis-3b68b9e88e13",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "LayerZero trust assumptions: Protocols using LayerZero must configure "
            "trusted remote addresses correctly. Failure to set trustedRemote for "
            "each (srcChainId, srcAddress) pair allows arbitrary chains to send "
            "messages to the contract. Incorrect configuration has led to multiple "
            "cross-chain message injection vulnerabilities."
        ),
        "metadata": {
            "category": "Cross-chain/Bridge",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["BRIDGE_VALIDATION"],
            "remediation": (
                "Explicitly set trustedRemote for every source chain. Use "
                "lzApp.setTrustedRemoteAddress() with type(address) checks. "
                "Monitor all lzReceive callbacks for unexpected source chains."
            ),
            "reference": "https://layerzero.gitbook.io/docs/evm-guides/master/set-trusted-remotes",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Optimistic bridge fraud window exploitation: Optimistic bridges (Optimism, "
            "Nomad, Hop) allow withdrawals after a challenge period (7 days for Optimism). "
            "If the fraud proof system has a bug or watchers are offline, invalid "
            "state transitions can be finalised. Nomad bridge hack ($190M, August 2022) "
            "exploited an initialisation bug that bypassed proof validation entirely."
        ),
        "metadata": {
            "category": "Cross-chain/Bridge",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["BRIDGE_VALIDATION"],
            "remediation": (
                "Run multiple independent watchers 24/7. Implement emergency pause "
                "mechanisms triggered by watcher consensus. Use ZK-proof bridges "
                "(zkBridge, Succinct) for trust-minimised cross-chain transfers."
            ),
            "reference": "https://medium.com/nomad-xyz-blog/nomad-bridge-hack-root-cause-analysis",
            "source": "Immunefi",
        },
    },

    # =========================================================================
    # TOKEN STANDARD (8 entries)
    # =========================================================================
    {
        "text": (
            "Fee-on-transfer token handling: Tokens like SafeMoon or PAXG deduct a "
            "transfer fee, so the recipient receives less than the sent amount. Protocols "
            "that record the sent amount (not the received amount) will have inflated "
            "balance accounting. Attackers can exploit this to extract excess collateral."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "HIGH",
            "cwe": "CWE-682",
            "rule_ids": ["FEE_ON_TRANSFER"],
            "remediation": (
                "Use balance-before/balance-after pattern: "
                "uint256 balBefore = token.balanceOf(address(this)); "
                "token.transferFrom(from, address(this), amount); "
                "uint256 received = token.balanceOf(address(this)) - balBefore;"
            ),
            "reference": "https://code4rena.com/reports/2022-11-redactedcartel",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Rebasing token in vault (Ampleforth/stETH): Rebasing tokens change all "
            "holder balances simultaneously (elastic supply). A vault that stores a "
            "fixed share count will drift from the true underlying balance after a rebase. "
            "stETH in lending protocols required special wstETH (wrapped) handling."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "HIGH",
            "cwe": "CWE-682",
            "rule_ids": ["REBASING_TOKEN"],
            "remediation": (
                "Use wrapped versions of rebasing tokens (wstETH, aUSDC). Store assets "
                "in share representation not absolute amounts. If supporting rebasing "
                "natively, implement balance reconciliation on each interaction."
            ),
            "reference": "https://lido.fi/developers/wsteth",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "ERC20 approve race condition: The standard ERC20 approve function has a "
            "known race condition when changing an allowance from non-zero to non-zero. "
            "The spender can front-run the approval change to spend both the old and new "
            "allowance, totalling more than intended."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "MEDIUM",
            "cwe": "CWE-362",
            "rule_ids": ["ERC20_APPROVE_RACE"],
            "remediation": (
                "Implement increaseAllowance and decreaseAllowance. Use EIP-2612 "
                "permit() for atomic approval and use. In contracts calling approve(), "
                "always set to 0 before setting to a new value."
            ),
            "reference": "https://eips.ethereum.org/EIPS/eip-20#approve",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "ERC777 hook reentrancy: ERC777 tokens call tokensToSend and tokensReceived "
            "hooks on the sender and recipient. These hooks can re-enter the calling "
            "contract before state is finalised. Uniswap V1 imBTC exploit ($300k, "
            "April 2020) used an ERC777 tokensToSend hook to re-enter swap."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "HIGH",
            "cwe": "CWE-841",
            "rule_ids": ["REENTRANCY_ERC777", "REENTRANCY_PATTERN"],
            "remediation": (
                "Add nonReentrant guards to all functions accepting ERC777 tokens. "
                "Prefer ERC20 over ERC777. If using ERC777, apply CEI pattern strictly. "
                "Register ERC1820 interface to control which hooks are called."
            ),
            "reference": "https://consensys.net/diligence/blog/2020/09/exploiting-uniswap-from-reentrancy-to-actual-profit/",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Non-standard ERC20 (no return value): Tokens like USDT do not return bool "
            "from transfer() and transferFrom(). Calling code that expects a bool will "
            "fail or silently succeed depending on the ABI decoder. Protocols must use "
            "SafeERC20 which handles these non-standard implementations."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "HIGH",
            "cwe": "CWE-252",
            "rule_ids": ["NON_STANDARD_ERC20"],
            "remediation": (
                "Always use OpenZeppelin SafeERC20.safeTransfer() and "
                "safeTransferFrom() which wraps calls to check low-level call success "
                "and handles missing return values."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#SafeERC20",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Token with blacklist (USDC/USDT): Circle's USDC and Tether's USDT can "
            "blacklist addresses, causing transfers to/from those addresses to revert. "
            "Protocols that use USDC as collateral may find themselves unable to liquidate "
            "or process withdrawals for blacklisted users, creating bad debt."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "MEDIUM",
            "cwe": "CWE-252",
            "rule_ids": ["BLACKLIST_TOKEN"],
            "remediation": (
                "Implement try/catch around token transfers where possible. Add emergency "
                "withdrawal mechanisms that bypass normal processing. Document blacklist "
                "risk in protocol terms of service."
            ),
            "reference": "https://code4rena.com/reports/2023-01-cooler",
            "source": "Code4rena",
        },
    },
    {
        "text": (
            "Inflationary/deflationary token supply: Some tokens have minting or burning "
            "mechanisms that change total supply. Protocols that compute value using "
            "totalSupply() at a fixed point may have stale data. Governance tokens with "
            "inflationary issuance inflate voting power calculations."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "MEDIUM",
            "cwe": "CWE-682",
            "rule_ids": ["REBASING_TOKEN"],
            "remediation": (
                "Snapshot supply at governance proposal creation time. Use ERC20Votes "
                "checkpoints for governance token voting power. "
                "Clearly document expected token supply behaviour."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20Votes",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Permit frontrunning (EIP-2612): EIP-2612 permit() allows gasless approvals "
            "via signed messages. An attacker can extract the permit signature from a "
            "pending transaction and front-run it with their own transaction that uses "
            "the permit but sets themselves as the spender."
        ),
        "metadata": {
            "category": "Token Standard",
            "severity": "MEDIUM",
            "cwe": "CWE-362",
            "rule_ids": ["PERMIT_FRONTRUN", "FRONT_RUNNING"],
            "remediation": (
                "Design permit-based flows so front-running the permit doesn't benefit "
                "the attacker (e.g., the permit beneficiary is hardcoded to msg.sender "
                "in the calling contract). Use try/catch around permit() calls so "
                "pre-approved allowances are used as fallback."
            ),
            "reference": "https://code4rena.com/reports/2023-01-rabbithole",
            "source": "Code4rena",
        },
    },

    # =========================================================================
    # GOVERNANCE (5 entries)
    # =========================================================================
    {
        "text": (
            "Flash loan governance attack: An attacker borrows a large quantity of "
            "governance tokens via flash loan, creates and passes a malicious proposal "
            "in a single transaction (bypassing timelock), executes it to drain the "
            "treasury, and repays the loan. Beanstalk Farms lost $182M in April 2022 "
            "due to no flash loan protection in governance."
        ),
        "metadata": {
            "category": "Governance",
            "severity": "CRITICAL",
            "cwe": "CWE-20",
            "rule_ids": ["GOVERNANCE_FLASH_LOAN"],
            "remediation": (
                "Use ERC20Votes snapshot voting (snapshot at prior block). "
                "Require tokens to be locked for a minimum period before conferring "
                "voting rights. Use timelocked governance execution with minimum 48h delay."
            ),
            "reference": "https://medium.com/beanstalk-farms/beanstalk-farms-post-mortem-and-governance-proposals",
            "source": "Immunefi",
        },
    },
    {
        "text": (
            "Governance proposal front-running: An attacker monitors the mempool for "
            "a governance proposal execution transaction. They front-run it with a "
            "transaction that changes protocol state such that the proposal executes "
            "with unintended consequences (e.g., draining a pool that is being upgraded)."
        ),
        "metadata": {
            "category": "Governance",
            "severity": "HIGH",
            "cwe": "CWE-362",
            "rule_ids": ["GOVERNANCE_FLASH_LOAN", "FRONT_RUNNING"],
            "remediation": (
                "Use private mempool relays for governance execution. Add invariant "
                "checks inside proposal execution that revert if pre-conditions are "
                "not met. Commit-reveal protocol parameters before execution."
            ),
            "reference": "https://medium.com/coinmonks/governance-front-running",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Quorum manipulation via token concentration: A protocol sets quorum at "
            "a fixed number of tokens (not percentage). As total supply inflates or "
            "tokens are locked, the relative quorum threshold effectively decreases, "
            "allowing small holders to pass proposals. Or as tokens are burned, "
            "quorum becomes unreachable."
        ),
        "metadata": {
            "category": "Governance",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["GOVERNANCE_FLASH_LOAN"],
            "remediation": (
                "Use percentage-based quorum (e.g., 4% of totalSupply). Use "
                "ERC20Votes totalSupply snapshots at proposal creation time. "
                "Set minimum participation thresholds that scale with supply."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/governance",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Timelock bypass: A governance timelock is supposed to delay execution "
            "of proposals. If the timelock contract has a privileged role that can "
            "execute without delay (emergency function), or if a subset of "
            "multi-sig owners can bypass the timelock, an attacker who compromises "
            "those keys can execute malicious proposals instantly."
        ),
        "metadata": {
            "category": "Governance",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
            "rule_ids": ["ACCESS_CONTROL_MISSING"],
            "remediation": (
                "Ensure all admin functions route through the timelock. Remove or "
                "heavily guard emergency bypass functions. Use Compound Governor Bravo "
                "or OpenZeppelin TimelockController with no privileged roles outside "
                "the timelock queue."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/governance#TimelockController",
            "source": "Manual Curation",
        },
    },
    {
        "text": (
            "Vote delegation exploitation: ERC20Votes allows users to delegate voting "
            "power. If a malicious proposal is created and an attacker self-delegates a "
            "large amount at the exact snapshot block, they acquire disproportionate "
            "voting power. Compound governance attack attempts have used delegation "
            "timing manipulation."
        ),
        "metadata": {
            "category": "Governance",
            "severity": "HIGH",
            "cwe": "CWE-20",
            "rule_ids": ["GOVERNANCE_FLASH_LOAN"],
            "remediation": (
                "Require voting power to be delegated for at least N blocks before "
                "the snapshot. Use ERC20VotesComp checkpoint model. Add a minimum "
                "proposal threshold that prevents low-holder attack."
            ),
            "reference": "https://docs.openzeppelin.com/contracts/4.x/api/token/erc20#ERC20Votes",
            "source": "Manual Curation",
        },
    },
]

# ─────────────────────────────────────────────────────────────────────────────
# Helper to compute category counts for the summary
# ─────────────────────────────────────────────────────────────────────────────

def _count_categories(data: list) -> dict:
    counts: dict = {}
    for item in data:
        cat = item.get("metadata", {}).get("category", "Unknown")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


# ─────────────────────────────────────────────────────────────────────────────
# Main seeding logic
# ─────────────────────────────────────────────────────────────────────────────

def seed(
    output: str = ".scarpshield/rag_index.json",
    append: bool = False,
) -> int:
    """Populate (or append to) the RAG vector store with curated seed data.

    Args:
        output: Path to the RAG index JSON file.
        append: If True, load existing entries first before adding new ones.

    Returns:
        Total number of entries in the index after seeding.
    """
    store = VectorStore()

    # Optionally preserve existing entries
    if append and Path(output).exists():
        try:
            store.load(output)
            print(f"[seed] Loaded {len(store.entries)} existing entries from {output}")
        except Exception as exc:
            print(f"[seed] Warning: could not load existing index: {exc}")

    existing_count = len(store.entries)
    print(f"[seed] Adding {len(SEED_DATA)} curated vulnerability entries …")

    # Use add_batch for efficiency
    try:
        store.add_batch(SEED_DATA)
    except RAGError as exc:
        print(f"[seed] RAGError during add_batch: {exc}")
        print("[seed] Aborting — no changes written.")
        return existing_count

    added = len(store.entries) - existing_count
    print(f"[seed] Successfully embedded {added} entries.")

    # Save index
    store.save(output)
    index_size = Path(output).stat().st_size
    print(f"[seed] Index saved → {output}  ({index_size:,} bytes)")

    # ── Summary ──────────────────────────────────────────────────────────────
    cats = _count_categories(SEED_DATA)
    print("\n" + "=" * 60)
    print(f"  RAG Seed Summary")
    print("=" * 60)
    print(f"  Total entries in index : {len(store.entries)}")
    print(f"  New entries added      : {added}")
    print(f"  Categories covered     : {len(cats)}")
    print(f"  Index file size        : {index_size:,} bytes")
    print(f"  Output path            : {output}")
    print()
    print("  Category breakdown:")
    for cat, count in sorted(cats.items(), key=lambda x: -x[1]):
        print(f"    {cat:<30} {count:>3} entries")
    print("=" * 60)

    return len(store.entries)


# ─────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Seed the Counterscarp RAG index with curated vulnerability data."
    )
    parser.add_argument(
        "--output",
        default=".scarpshield/rag_index.json",
        help="Path to the RAG index JSON (default: .scarpshield/rag_index.json)",
    )
    parser.add_argument(
        "--append",
        action="store_true",
        help="Append to existing index instead of replacing it.",
    )
    parser.add_argument(
        "--count",
        action="store_true",
        help="Just print the number of seed entries and exit.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    if args.count:
        cats = _count_categories(SEED_DATA)
        print(f"Total seed entries : {len(SEED_DATA)}")
        print(f"Categories         : {len(cats)}")
        for cat, n in sorted(cats.items()):
            print(f"  {cat}: {n}")
        sys.exit(0)

    total = seed(output=args.output, append=args.append)
    sys.exit(0 if total > 0 else 1)
