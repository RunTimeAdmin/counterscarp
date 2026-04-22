# Security Rules Catalog

## Table of Contents

- [Overview](#overview)
- [EVM Heuristic Rules (31 Rules)](#evm-heuristic-rules-31-rules)
  - [Access Control (5)](#access-control-5)
  - [Reentrancy & External Calls (4)](#reentrancy--external-calls-4)
  - [DeFi & Oracle Security (3)](#defi--oracle-security-3)
  - [Math & Precision (3)](#math--precision-3)
  - [Token Mechanics (3)](#token-mechanics-3)
  - [Upgrade & Proxy Patterns (2)](#upgrade--proxy-patterns-2)
  - [Cryptographic & Signature (2)](#cryptographic--signature-2)
  - [Other (2)](#other-2)
- [Solana Rules (35 Rules)](#solana-rules-35-rules)
  - [Account Validation (8)](#account-validation-8)
  - [CPI Security (4)](#cpi-security-4)
  - [Arithmetic & Logic (5)](#arithmetic--logic-5)
  - [State Management (6)](#state-management-6)
  - [Access Control (4)](#access-control-4)
  - [Token Security (4)](#token-security-4)
  - [General Validation (4)](#general-validation-4)
- [Bug Bounty Payout Reference](#bug-bounty-payout-reference)
- [Confidence Scoring](#confidence-scoring)
- [Slither Detector Categories](#slither-detector-categories)

---

## Overview

Counterscarp Engine detects vulnerabilities through two complementary rule sets:

- **31 EVM heuristic rules** — pattern-based checks for Solidity smart contracts
- **35 Solana rules** — pattern-based checks for Rust/Anchor Solana programs

These rules complement deeper analysis tools (Slither, Mythril, Aderyn) by catching patterns that static analyzers may miss, including behavioral and economic attack vectors.

---

## EVM Heuristic Rules (31 Rules)

### Access Control (5)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `TX_ORIGIN_USAGE` | HIGH | Use of `tx.origin` for authorization | Replace `tx.origin` with `msg.sender` and use role-based access control (AccessControl from OpenZeppelin) |
| `DELEGATECALL_USAGE` | HIGH | Use of `delegatecall` (upgradeable/proxy risk) | Ensure delegatecall targets are trusted and immutable; review proxy patterns carefully |
| `EMERGENCY_WITHDRAW_PUBLIC` | HIGH | Function name suggests emergency withdraw/rescue funds | Ensure emergency/withdraw/rescue functions are admin-only and ideally timelocked |
| `FAKE_RENOUNCE_OWNER_ZERO` | MEDIUM | Owner set to `address(0)` (possible fake renounce) | Verify there is no parallel manager/admin role keeping effective control |
| `CENTRALIZATION_RISK` | MEDIUM | Single owner can upgrade/pause/withdraw without timelock | Use multi-sig + timelock for critical admin functions |

### Reentrancy & External Calls (4)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `UNCHECKED_EXTERNAL_CALL` | CRITICAL | Low-level call/transfer without return value check | Always check return values of external calls. Unchecked calls are top bug bounty targets |
| `LOWLEVEL_CALL_USAGE` | MEDIUM | Use of low-level `call()` / `staticcall()` | Wrap low-level calls with return value checks and reentrancy protection |
| `FLASH_LOAN_REENTRANCY` | CRITICAL | Flash loan callback without reentrancy protection | Add `nonReentrant` modifier. Major DeFi exploit vector |
| `ARBITRARY_EXTERNAL_CALL` | HIGH | Unprotected arbitrary external call (user controls target and calldata) | Validate call targets and restrict calldata from user input |

### DeFi & Oracle Security (3)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `ORACLE_STALENESS_CHECK` | CRITICAL | Chainlink oracle without staleness/validity check | Check `updatedAt` timestamp and `answeredInRound` to prevent stale price attacks |
| `MISSING_SLIPPAGE_PROTECTION` | HIGH | DEX swap without minimum output amount (MEV/sandwich attack) | Always set `minAmountOut` parameter in swap calls |
| `STRICT_BALANCE_EQUALITY` | HIGH | Strict equality on `address(this).balance` (fragile invariant) | Use `>=` or more robust accounting; forced ETH sends can break strict equality |

### Math & Precision (3)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `DIVIDE_BEFORE_MULTIPLY` | MEDIUM | Potential precision loss: division before multiplication | Prefer `(a * c) / b` over `(a / b) * c` to avoid rounding to zero |
| `UNSAFE_CAST` | HIGH | Unsafe type casting (uint256 -> uint128/64) without bounds check | Use SafeCast library for downcasting operations |
| `MSG_VALUE_LOOP` | HIGH | `msg.value` used inside a loop (possible double-credit per iteration) | Track value per user, not per iteration; ensure deposits aren't multiplied by loop count |

### Token Mechanics (3)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `HIDDEN_MINT` | HIGH | `_mint()` call (possible hidden mint path) | Review all mint paths; ensure they are expected (e.g., only in public mint/claim functions) |
| `TRADING_TOGGLE_BOOL` | MEDIUM | Trading enable/disable boolean (possible honeypot) | Ensure trading toggles are time-bound, documented, and not abusable to trap liquidity |
| `SET_FEE_FUNCTION` | MEDIUM | Configurable fee setter without obvious cap (possible fee rug) | Check for upper bounds on new fee values (e.g., <= 25%) |

### Upgrade & Proxy Patterns (2)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `STORAGE_COLLISION_RISK` | HIGH | Upgradeable proxy pattern detected — verify storage layout | Use storage gap patterns and OpenZeppelin guidelines for upgradeable contracts |
| `UPGRADE_FUNCTION` | HIGH | Function name suggests upgrade or ownership change | Confirm these functions are protected by strong access control (multi-sig, timelock) |

### Cryptographic & Signature (2)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `SIGNATURE_REPLAY` | HIGH | Signature verification without nonce/deadline protection | Add nonce and deadline to prevent signature replay attacks |
| `BLOCK_TIMESTAMP_RANDOMNESS` | MEDIUM | Use of `block.timestamp` / `now` (weak randomness) | Do not use block.timestamp as randomness; use VRF or off-chain randomness |

### Other (2)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `HARDCODED_ADDRESS` | INFO | Hardcoded address literal in code | Verify hardcoded addresses are correct and documented; consider configurability |
| `BOOLEAN_TRANSFER_CHECK` | INFO | Checking boolean return on `ERC20.transfer` (may be wrong with some libs) | Ensure this pattern matches the token library semantics (e.g., Solmate reverts instead of returning bool) |

---

## Solana Rules (35 Rules)

### Account Validation (8)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `MISSING_SIGNER_CHECK` | CRITICAL | Account without signer validation | Add `signer` constraint: `#[account(signer)]` |
| `MISSING_OWNER_CHECK` | CRITICAL | Account deserialization without owner check | Verify `account.owner == expected_program_id` |
| `MISSING_HAS_ONE_CONSTRAINT` | HIGH | Missing `has_one` constraint for associated accounts | Add `has_one` constraint: `#[account(has_one = authority)]` |
| `MISSING_DISCRIMINATOR_CHECK` | CRITICAL | Account without discriminator check (type confusion) | Add discriminator validation in account struct |
| `UNVALIDATED_PDA_SEEDS` | CRITICAL | PDA derived without proper seed validation | Use `find_program_address` with validated seeds and bump |
| `MISSING_IS_SIGNER_RAW` | CRITICAL | Raw Solana program missing `is_signer` check | Add check: `if !account_info.is_signer { return Err(...) }` |
| `MISSING_ACCOUNT_DATA_VALIDATION` | HIGH | Unchecked account data deserialization | Use `Account::try_from()` or validate discriminator first |
| `UNVALIDATED_ACCOUNT_INFO` | HIGH | Raw `AccountInfo` without validation constraints | Use typed `Account<T>` wrappers or add validation |

### CPI Security (4)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `ARBITRARY_CPI` | CRITICAL | CPI without program ID verification | Verify target program ID matches expected |
| `MISSING_CPI_AUTHORITY` | HIGH | CPI context missing signer seeds for PDA authority | Use `CpiContext::new_with_signer()` when invoking from a PDA |
| `UNVERIFIED_PROGRAM_ACCOUNT` | CRITICAL | CPI using unverified program account | Hardcode expected program IDs or verify against known values |
| `UNSAFE_INVOKE_SIGNED` | HIGH | `invoke_signed` with user-controlled seeds | Ensure seeds are program-controlled only |

### Arithmetic & Logic (5)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `UNCHECKED_ARITHMETIC` | HIGH | Unchecked arithmetic operation | Use `checked_add()`, `checked_sub()`, `checked_mul()`, `checked_div()` |
| `INTEGER_OVERFLOW_RISK` | HIGH | Wrapping arithmetic can silently overflow | Use `checked_*` operations or document why wrapping is safe |
| `UNSAFE_CASTING` | MEDIUM | Unsafe type casting without bounds checking | Use `try_from()` or verify value fits before casting |
| `DIVISION_BY_ZERO_RISK` | MEDIUM | Division without zero-check on divisor | Add check: `if divisor == 0 { return Err(...) }` |
| `PRECISION_LOSS` | MEDIUM | Division before multiplication causes precision loss | Reorder: multiply first, then divide (`a * c / b`) |

### State Management (6)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `MISSING_RENT_EXEMPTION` | MEDIUM | Account creation without rent exemption check | Ensure account is rent-exempt: `rent.minimum_balance(space)` |
| `UNINITIALIZED_ACCOUNT_USAGE` | CRITICAL | Uninitialized account check without error handling | Return error for uninitialized accounts |
| `ACCOUNT_REINITIALIZATION` | CRITICAL | `init_if_needed` allows reinitialization | Use `init` constraint or verify reinitialization safety |
| `MISSING_CLOSE_ACCOUNT` | MEDIUM | Account close without proper close constraint | Use `#[account(close = destination)]` |
| `STALE_ACCOUNT_DATA` | HIGH | Account data used after CPI without reload | Call `account.reload()?` after CPI |
| `UNCLOSED_ACCOUNT` | MEDIUM | Account close without realloc (resurrection attack) | Use `realloc(0)` before closing to prevent resurrection |

### Access Control (4)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `MISSING_ACCESS_CONTROL` | HIGH | Sensitive instruction missing `#[access_control]` | Add `#[access_control]` with authorization checks |
| `HARDCODED_AUTHORITY` | MEDIUM | Hardcoded authority pubkey reduces flexibility | Use configurable authority stored in program state |
| `MISSING_MULTISIG` | MEDIUM | Admin function may lack multi-signature protection | Implement multi-sig or timelock for admin functions |
| `WEAK_AUTHORITY_CHECK` | HIGH | Authority check without signer verification | Verify key match AND `is_signer` |

### Token Security (4)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `MISSING_TOKEN_ACCOUNT_VALIDATION` | CRITICAL | Token account validation missing mint verification | Verify `token_account.mint == expected_mint` |
| `UNCHECKED_TOKEN_BALANCE` | HIGH | Token transfer without checking source balance | Check `source_token_account.amount >= amount` |
| `MISSING_FREEZE_AUTHORITY_CHECK` | MEDIUM | Token mint/burn without freeze authority check | Consider checking `mint.freeze_authority` |
| `UNVALIDATED_TOKEN_PROGRAM` | CRITICAL | Token program CPI without verifying program | Verify `ctx.accounts.token_program.key == &token::ID` |

### General Validation (4)

| Rule ID | Severity | Description | Remediation |
|---------|----------|-------------|-------------|
| `UNVALIDATED_ACCOUNT_DATA` | HIGH | Account deserialization without error handling | Use `.map_err()` or `?` operator to handle deserialization errors |
| `UNCONSTRAINED_SYSTEM_PROGRAM` | MEDIUM | System program CPI without program ID verification | Verify system_program account matches `system_program::ID` |
| `MISSING_CLOCK_VALIDATION` | LOW | Clock usage without timestamp/slot validation | Document clock dependency and drift tolerance |
| `DUPLICATE_MUTABLE_ACCOUNTS` | HIGH | Multiple mutable borrows of same account | Ensure accounts are distinct |

---

## Confidence Scoring

Each finding includes a confidence score from 1-10:

| Score | Level | Meaning |
|-------|-------|---------|
| 9-10 | Very High | Near-certain vulnerability, minimal false positive risk |
| 7-8 | High | Strong indicators, worth investigating |
| 5-6 | Medium | Possible issue, context-dependent |
| 3-4 | Low | Weak signal, likely informational |
| 1-2 | Very Low | Heuristic match only, high false positive chance |

Filter findings by confidence using:
```toml
[engine]
min_confidence = 5  # Only report findings with confidence >= 5
```

Or via CLI: `counterscarp --target ./contracts --min-confidence 5`

> **Inline Suppressions:** You can suppress individual findings directly in Solidity source using `// counterscarp-suppress: RULE_ID` comments. See [CONFIGURATION.md](CONFIGURATION.md#inline-comment-suppressions) for full syntax and examples.

---

## Bug Bounty Payout Reference

The following table shows typical bounty ranges for high-value vulnerability patterns that Counterscarp Engine detects. Based on Immunefi and Code4rena payout data.

| Pattern | Rule ID | Typical Bounty Range |
|---------|---------|---------------------|
| Unchecked External Call | `UNCHECKED_EXTERNAL_CALL` | $10K - $100K |
| Oracle Staleness | `ORACLE_STALENESS_CHECK` | $50K - $500K |
| Flash Loan Reentrancy | `FLASH_LOAN_REENTRANCY` | $100K - $1M+ |
| Storage Collision | `STORAGE_COLLISION_RISK` | $30K - $200K |
| Signature Replay | `SIGNATURE_REPLAY` | $20K - $100K |
| Missing Slippage Protection | `MISSING_SLIPPAGE_PROTECTION` | $5K - $30K |
| Unsafe Cast | `UNSAFE_CAST` | $10K - $50K |
| Arbitrary External Call | `ARBITRARY_EXTERNAL_CALL` | $50K - $500K |

**Warning:** Bounty ranges are indicative and depend on the protocol's TVL, bug bounty program terms, and impact severity.

---

## Slither Detector Categories

Slither detectors are organized by category. Counterscarp Engine filters Slither results based on the `[static_analysis.slither]` and `[red_team]` config sections.

| Category | Description | Example Detectors |
|----------|-------------|-------------------|
| Reentrancy | Reentrancy vulnerabilities | `reentrancy-eth`, `reentrancy-no-eth`, `reentrancy-benign` |
| Access Control | Missing or weak access control | `protected-vars`, `unprotected-upgrade` |
| Arithmetic | Integer overflow/precision issues | `divide-before-multiply`, `incorrect-equality` |
| Unchecked Return | Unchecked return values | `unchecked-lowlevel`, `unchecked-transfer` |
| Timestamp | Block timestamp dependencies | `timestamp` |
| Assembly | Inline assembly usage | `assembly` |
| Shadowing | Variable shadowing | `shadowing-state` |
| Optimization | Gas optimization opportunities | Various |
| Informational | Code quality / best practices | `naming-convention`, `redundant-statements` |

Configure Slither filtering in `counterscarp.toml`:

```toml
[static_analysis.slither]
exclude_detectors = "similar-names,unused-state"
include_impact = "High,Medium"

[red_team]
ignore_checks = ["solc-version", "naming-convention", "assembly"]
```

---

*Counterscarp Security Engine &bull; counterscarp.io*
