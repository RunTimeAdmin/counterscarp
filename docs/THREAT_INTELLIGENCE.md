# Threat Intelligence Signature Catalog

## Overview

Counterscarp Engine ships with a bundled offline threat intelligence database designed for air-gapped deployments. The database contains comprehensive smart contract vulnerability signatures covering the most critical DeFi attack vectors, sourced from Code4rena findings, Immunefi post-mortems, Solodit research, and real-world exploits.

| Attribute | Value |
|---|---|
| **Total Signatures** | 123 |
| **Total Categories** | 23 |
| **Database Location** | `data/threat_intel_db.json` |
| **Database Version** | 1.0.0 |
| **Last Updated** | 2026-04-21 |

---

## Severity Distribution

| Severity | Count | Description |
|---|---|---|
| **CRITICAL** | 35 | Direct path to fund loss or complete protocol compromise |
| **HIGH** | 60 | Significant risk with likely financial impact |
| **MEDIUM** | 26 | Moderate risk; exploitable under specific conditions |
| **LOW** | 2 | Minor risk or informational concern with limited impact |
| **INFO** | 0 | Informational only; no direct exploitability |
| **Total** | **123** | |

---

## Categories

Sorted by signature count (descending).

| Category | Signatures |
|---|---|
| DeFi-Specific | 13 |
| Access Control | 9 |
| Reentrancy | 8 |
| Governance Attack Expansion | 8 |
| Hook Vulnerabilities | 6 |
| Cross-Chain Bridge Vulnerabilities | 6 |
| Flash Loan Attacks | 5 |
| Oracle Manipulation | 5 |
| Integer/Math | 5 |
| Signature/Cryptographic | 5 |
| Proxy/Upgrade | 5 |
| L2 Sequencer and Oracle Failure Modes | 5 |
| Permit/Permit2 Ecosystem | 5 |
| ERC-4626 Vault Composability | 5 |
| Governance | 4 |
| MEV/Frontrunning | 4 |
| Unchecked Return Values | 4 |
| Denial of Service Patterns | 4 |
| CREATE2 and Metamorphic Contracts | 4 |
| MEV and Frontrunning Expansion | 4 |
| Token Approval Race Conditions | 3 |
| Diamond Proxy (EIP-2535) | 3 |
| Initializer Frontrunning | 3 |

---

## Full Signature Catalog

Organized alphabetically by category. Each table lists all signatures within that category.

### Access Control

| ID | Title | Severity |
|---|---|---|
| TI-019 | tx.origin Authentication Bypass | HIGH |
| TI-020 | Missing Access Control on Critical Functions | CRITICAL |
| TI-021 | Unprotected initialize() in Proxies | CRITICAL |
| TI-022 | Default Visibility (pre-Solidity 0.5.0) | HIGH |
| TI-023 | Centralization Risk (Single Admin Key) | HIGH |
| TI-024 | Unprotected selfdestruct | CRITICAL |
| TI-025 | Missing Two-Step Ownership Transfer | MEDIUM |
| TI-026 | Unprotected Function in Role-Based Access System | HIGH |
| TI-061 | Improper Input Validation on Token Amounts | MEDIUM |

### CREATE2 and Metamorphic Contracts

| ID | Title | Severity |
|---|---|---|
| TI-127 | CREATE2 Predictable Address Exploitation | HIGH |
| TI-128 | Metamorphic Contract via SELFDESTRUCT and Redeploy | CRITICAL |
| TI-129 | CREATE2 Front-Running in Factory Deployment | MEDIUM |
| TI-130 | CREATE2 Initialization Order Dependence | MEDIUM |

### Cross-Chain Bridge Vulnerabilities

| ID | Title | Severity |
|---|---|---|
| TI-087 | Bridge Message Authenticity Verification Failure | CRITICAL |
| TI-088 | Bridge Validator Key Compromise and Multisig Threshold Weakness | CRITICAL |
| TI-089 | Canonical vs Wrapped Token Confusion in Bridge Transfers | HIGH |
| TI-090 | Bridge Liquidity Pool Drain via Fraudulent Withdrawal Proofs | CRITICAL |
| TI-091 | Cross-Chain Replay Attack on Bridge Transactions | HIGH |
| TI-092 | Bridge Exit Mechanism Denial of Service | HIGH |

### DeFi-Specific

| ID | Title | Severity |
|---|---|---|
| TI-042 | AMM Rounding Errors in Uniswap V2 Forks | MEDIUM |
| TI-043 | Compound Oracle Staleness in Forks | HIGH |
| TI-044 | Missing Slippage Protection | HIGH |
| TI-045 | Fee-on-Transfer Token Accounting | HIGH |
| TI-046 | Sandwich Attack Surface (No Deadline on AMM Calls) | HIGH |
| TI-047 | First Depositor Share Inflation Attack | HIGH |
| TI-048 | Donation Attack on Vault Shares | HIGH |
| TI-049 | Rebasing Token Integration Errors | HIGH |
| TI-058 | Unchecked Return Value of External Call | HIGH |
| TI-059 | Denial of Service via Unexpected Revert | MEDIUM |
| TI-060 | Weak Randomness (block.timestamp / blockhash) | HIGH |
| TI-062 | Timestamp Manipulation (block.timestamp Dependence) | MEDIUM |
| TI-063 | Incorrect Event Emission / Silent State Mutation | LOW |

### Denial of Service Patterns

| ID | Title | Severity |
|---|---|---|
| TI-123 | Block Gas Limit DoS via Unbounded Loop | HIGH |
| TI-124 | External Call DoS via Revert or Gas Griefing | HIGH |
| TI-125 | Storage Write Amplification and Gas Griefing | MEDIUM |
| TI-126 | Computational Complexity DoS via Crafted Input | MEDIUM |

### Diamond Proxy (EIP-2535)

| ID | Title | Severity |
|---|---|---|
| TI-135 | Diamond Storage Layout Collision Across Facets | CRITICAL |
| TI-136 | Diamond Facet Initialization Ordering Attack | HIGH |
| TI-137 | Diamond Facet Removal Leaving Dangling State | MEDIUM |

### ERC-4626 Vault Composability

| ID | Title | Severity |
|---|---|---|
| TI-111 | ERC-4626 Share Precision Loss via Rounding Exploitation | HIGH |
| TI-112 | ERC-4626 Exit Queue Griefing and Withdrawal DoS | MEDIUM |
| TI-113 | ERC-4626 Multi-Step Liquidation Cascade | CRITICAL |
| TI-114 | ERC-4626 Yield Accrual Manipulation via Strategic Timing | HIGH |
| TI-115 | ERC-4626 Rebase Token Integration Accounting Errors | HIGH |

### Flash Loan Attacks

| ID | Title | Severity |
|---|---|---|
| TI-009 | Flash Loan Price Manipulation | CRITICAL |
| TI-010 | Flash Loan Governance Attack | CRITICAL |
| TI-011 | Flash Loan Liquidation Exploit | HIGH |
| TI-012 | Flash Mint Abuse | HIGH |
| TI-013 | Flash Loan Sandwich / Atomic Arbitrage | HIGH |

### Governance

| ID | Title | Severity |
|---|---|---|
| TI-050 | Flash Loan Voting Attack | CRITICAL |
| TI-051 | Proposal Frontrunning in Governance | MEDIUM |
| TI-052 | Vote Buying via Token Lending | HIGH |
| TI-053 | Governance Time-Lock Bypass | HIGH |

### Governance Attack Expansion

| ID | Title | Severity |
|---|---|---|
| TI-098 | Flash Loan Governance Vote Manipulation | CRITICAL |
| TI-099 | Governance Token Concentration and Whale Vote Dominance | HIGH |
| TI-100 | Delegation Sandwich Attack and Vote Weight Override | HIGH |
| TI-101 | Timelock Parameter Bypass and Governance Delay Manipulation | CRITICAL |
| TI-102 | Proposal Griefing and Governance Denial of Service | MEDIUM |
| TI-103 | Governor Contract Upgrade Hijacking via Self-Governance | CRITICAL |
| TI-104 | Governance Oracle and External Data Dependency Manipulation | MEDIUM |
| TI-105 | Vote Buying, Dark DAO Collusion, and Governance Bribery | HIGH |

### Hook Vulnerabilities

| ID | Title | Severity |
|---|---|---|
| TI-081 | Uniswap V4 Hook Re-entrancy During Swap/Liquidity Operations | CRITICAL |
| TI-082 | Malicious Fee-on-Transfer Hook Silently Drains Tokens | CRITICAL |
| TI-083 | Flash Loan Callback Manipulation Through Hook State Injection | HIGH |
| TI-084 | PoolManager Access Control Bypass in Hook Functions | CRITICAL |
| TI-085 | Flash Accounting Delta Settlement Failure via Malicious Hook | CRITICAL |
| TI-086 | Custom Oracle Manipulation via Hook State Update Ordering | HIGH |

### Initializer Frontrunning

| ID | Title | Severity |
|---|---|---|
| TI-138 | Unprotected Implementation Contract Initialization | CRITICAL |
| TI-139 | Re-Initialization via Reinitializer Version Gap | HIGH |
| TI-140 | Proxy Deployment Race Between Deploy and Initialize | HIGH |

### Integer/Math

| ID | Title | Severity |
|---|---|---|
| TI-027 | Integer Overflow (pre-Solidity 0.8.0) | CRITICAL |
| TI-028 | Integer Underflow (pre-Solidity 0.8.0) | CRITICAL |
| TI-029 | Unsafe Type Casting (uint256 to smaller uint) | HIGH |
| TI-030 | Division Before Multiplication (Precision Loss) | MEDIUM |
| TI-031 | Rounding Errors in Token Calculations | MEDIUM |

### L2 Sequencer and Oracle Failure Modes

| ID | Title | Severity |
|---|---|---|
| TI-093 | Chainlink L2 Sequencer Downtime Stale Price Consumption | CRITICAL |
| TI-094 | Sequencer Transaction Ordering Manipulation (L2 MEV) | HIGH |
| TI-095 | L2 State Root Submission Delay and Pre-Finalization Exploitation | HIGH |
| TI-096 | Oracle Price Feed Aggregator Multi-Source Failure and Stale Round Detection | HIGH |
| TI-097 | L2 Gas Price Oracle Manipulation via L1 Base Fee Distortion | MEDIUM |

### MEV and Frontrunning Expansion

| ID | Title | Severity |
|---|---|---|
| TI-131 | Multi-Block MEV and Cross-Block State Manipulation | HIGH |
| TI-132 | Builder/Proposer Collusion and Censorship MEV | HIGH |
| TI-133 | JIT (Just-In-Time) Liquidity MEV | MEDIUM |
| TI-134 | Backrunning and Atomic Arbitrage in DEX Aggregation | MEDIUM |

### MEV/Frontrunning

| ID | Title | Severity |
|---|---|---|
| TI-054 | Sandwich Attack on Swaps | HIGH |
| TI-055 | Liquidation Frontrunning | MEDIUM |
| TI-056 | Transaction Ordering Dependence (TOD) | MEDIUM |
| TI-057 | Backrunning Arbitrage Exposure | LOW |

### Oracle Manipulation

| ID | Title | Severity |
|---|---|---|
| TI-014 | Spot Price Manipulation via AMM | CRITICAL |
| TI-015 | TWAP Manipulation (Multi-Block) | HIGH |
| TI-016 | Chainlink Stale Price Feed | HIGH |
| TI-017 | Oracle Frontrunning | HIGH |
| TI-018 | Uniswap V2 Reserve Manipulation | HIGH |

### Permit/Permit2 Ecosystem

| ID | Title | Severity |
|---|---|---|
| TI-106 | Permit2 Universal Allowance Widening and Cross-Protocol Drainage | HIGH |
| TI-107 | EIP-2612 Permit Signature Frontrunning and Griefing | HIGH |
| TI-108 | ERC-721/ERC-1155 NFT Permit Nonce Reset on Transfer (EIP-4494) | MEDIUM |
| TI-109 | Permit Signature Phishing via Malicious DApp or Fake UI | HIGH |
| TI-110 | Permit2 Batch Transfer Atomicity Failure and Partial Approval Exploitation | MEDIUM |

### Proxy/Upgrade

| ID | Title | Severity |
|---|---|---|
| TI-037 | Storage Collision in Proxy Patterns | CRITICAL |
| TI-038 | Uninitialized Proxy Implementation | CRITICAL |
| TI-039 | Function Selector Clashing | HIGH |
| TI-040 | UUPS Missing Upgrade Authorization | CRITICAL |
| TI-041 | Delegatecall to Untrusted Contract | CRITICAL |

### Reentrancy

| ID | Title | Severity |
|---|---|---|
| TI-001 | Classic Single-Function Reentrancy | CRITICAL |
| TI-002 | Cross-Function Reentrancy | CRITICAL |
| TI-003 | Cross-Contract Reentrancy | CRITICAL |
| TI-004 | Read-Only Reentrancy (View Function Manipulation) | HIGH |
| TI-005 | ERC-777 Callback Reentrancy | CRITICAL |
| TI-006 | Create2 Reentrancy / Deployment-Time Reentrancy | HIGH |
| TI-007 | Delegatecall Reentrancy | HIGH |
| TI-008 | Batch/Loop Reentrancy | HIGH |

### Signature/Cryptographic

| ID | Title | Severity |
|---|---|---|
| TI-032 | Signature Replay (Missing Nonce) | CRITICAL |
| TI-033 | Signature Malleability (ECDSA s-value) | HIGH |
| TI-034 | Missing Deadline on EIP-2612 Permits | HIGH |
| TI-035 | ecrecover Returns address(0) Without Check | HIGH |
| TI-036 | Cross-Chain Signature Replay | HIGH |

### Token Approval Race Conditions

| ID | Title | Severity |
|---|---|---|
| TI-116 | ERC-20 Approve/TransferFrom Race Condition | MEDIUM |
| TI-117 | Infinite Approval Token Drain | HIGH |
| TI-118 | SafeERC20 and Non-Standard Token Approval Failures | MEDIUM |

### Unchecked Return Values

| ID | Title | Severity |
|---|---|---|
| TI-119 | Unchecked Low-Level Call Return Value | CRITICAL |
| TI-120 | Delegatecall Return Value and Storage Corruption | CRITICAL |
| TI-121 | Silent Token Transfer Failure (Non-Reverting ERC-20) | HIGH |
| TI-122 | External Call Exception Swallowing in Try/Catch | MEDIUM |

---

## Signature Schema

Each entry in `data/threat_intel_db.json` conforms to the following schema:

```json
{
  "id": "TI-001",
  "title": "Classic Single-Function Reentrancy",
  "category": "Reentrancy",
  "severity": "CRITICAL",
  "description": "Detailed vulnerability explanation...",
  "affected_patterns": [
    "external call before state update",
    "call.value() before balance = 0"
  ],
  "references": [
    "https://swcregistry.io/docs/SWC-107"
  ],
  "cve": null,
  "last_updated": "2026-04-21"
}
```

### Field Descriptions

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier in the format `TI-NNN` (e.g., `TI-001` through `TI-140`) |
| `title` | `string` | Concise, descriptive vulnerability title |
| `category` | `string` | One of the 23 vulnerability categories listed in the Categories section above |
| `severity` | `string` | One of: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `description` | `string` | Detailed explanation of the vulnerability, including attack mechanics, root cause, and recommended mitigations |
| `affected_patterns` | `array[string]` | List of Solidity/code patterns that indicate the presence of this vulnerability; used by static analysis detectors |
| `references` | `array[string]` | External links to CVEs, SWC registry entries, blog posts, and audit reports for further reading |
| `cve` | `string \| null` | Associated CVE identifier if one exists (e.g., `CVE-2018-10299`); `null` if no CVE is assigned |
| `last_updated` | `string` | ISO 8601 date string indicating when the signature was last reviewed or modified |

### Severity Definitions

| Severity | Criteria |
|---|---|
| `CRITICAL` | Direct path to irreversible fund loss, full protocol compromise, or complete access control bypass |
| `HIGH` | Likely financial impact; exploitable with moderate effort or under common conditions |
| `MEDIUM` | Exploitable under specific conditions; indirect financial risk or protocol degradation |
| `LOW` | Minimal exploitability; minor impact on user experience or off-chain monitoring |
| `INFO` | Informational — no direct exploitability but represents a best-practice deviation |

---

## Updating Signatures

### Online Update

Fetch the latest signatures from upstream threat intelligence sources:

```bash
counterscarp --update-signatures
```

This command fetches signatures from GitHub, Code4rena, Immunefi, and Solodit, merges them with the local database, and persists the result to `data/threat_intel_db.json`. Useful before entering an air-gapped environment.

### Offline Update

For air-gapped environments where network access is not available:

```bash
counterscarp --update-from-file path/to/updated_db.json
```

Provide a manually-obtained `threat_intel_db.json` file (downloaded on an open-network machine and transferred via secure media). The engine validates the schema before applying the update.

### Configuration

The threat intelligence database path and offline behavior can be configured in `counterscarp.toml`:

```toml
[threat_intel]
offline_mode = true                                    # Force bundled DB only; disable all network fetches
bundled_db_path = "custom/path/threat_intel_db.json"  # Override the default DB location
```

| Option | Default | Description |
|---|---|---|
| `offline_mode` | `false` | When `true`, the engine never attempts network access for signature updates |
| `bundled_db_path` | `data/threat_intel_db.json` | Path to the active threat intelligence database, relative to the project root |

When `offline_mode = true` and no network is available, the engine logs:

```
Network unavailable. Falling back to local heuristic scanning and offline threat intelligence.
```

---

## Sources

The threat intelligence signatures are derived from the following high-quality sources:

| Source | Description |
|---|---|
| **Code4rena** | High-severity and critical findings from competitive audit contests |
| **Immunefi** | Post-mortems and root cause analyses from major DeFi exploit bug bounty disclosures |
| **Solodit** | Deep vulnerability research and aggregated audit finding patterns |
| **SWC Registry** | Smart Contract Weakness Classification Registry — canonical vulnerability taxonomy |
| **OpenZeppelin Blog** | Security advisories and pattern-level vulnerability analyses |
| **Community Contributions** | Signatures submitted via `data/community_signatures/` and reviewed before inclusion |

### Contributing New Signatures

Community-contributed signatures can be placed in `data/community_signatures/` as individual JSON files matching the schema above. They are loaded alongside the bundled database at runtime and can be submitted upstream via pull request to the Counterscarp Engine repository.

```
data/
  threat_intel_db.json          ← Bundled, versioned signature database
  community_signatures/
    my-custom-signature.json    ← Local custom signatures (not shipped)
```

---

*Signature catalog generated from `data/threat_intel_db.json` v1.0.0 (2026-04-21). For the latest signatures, run `counterscarp --update-signatures`.*
