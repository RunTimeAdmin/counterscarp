# Sentinel Security Engine

**Production-ready smart contract security platform with 14 integrated analyzers, configurable rules, and professional audit reports.**

> One command. Zero false positives. Client-ready deliverables.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## ⚡ **Quick Start (5 Minutes)**

### **Installation**

```powershell
# 1. Clone or download
cd /path/to/sentinel-engine  # Or on Windows: C:\path\to\sentinel-engine

# 2. Install using pyproject.toml (recommended)
pip install -e .

# Or install core dependencies manually
pip install requests packaging tomli solc-select

# 3. Install Slither (static analysis)
pip install slither-analyzer
solc-select install 0.8.19
solc-select use 0.8.19

# 4. Verify installation
python orchestrator.py --help
# Or use CLI entry point (after pip install):
sentinel-engine --help
```

**Optional (for full functionality):**
```powershell
# Aderyn (Rust-based analyzer)
cargo install aderyn

# Medusa (fuzzing)
go install github.com/crytic/medusa/cmd/medusa@latest
```

---

### **Run Your First Audit**

**Option 1: GUI (Easiest)**
```powershell
python gui.py
# → Select contract → Check boxes → Click "Run Selected Checks"
```

**Option 2: CLI (Professional)**
```powershell
# Fast PR check (blockers only)
sentinel-engine --target ./contracts --config sentinel-pr.toml

# Full audit with HTML report
sentinel-engine --target ./contracts --config sentinel-audit.toml --report --project-name "MyDeFi"

# Bug bounty mode (max coverage)
sentinel-engine --target ./contracts --config sentinel-bounty.toml --medusa

# Alternative: Use python directly
python orchestrator.py --target ./contracts --config sentinel-pr.toml
```

**Output:**
- `ACTION_PLAN_*.md` - Technical findings summary
- `audit_report_*.html` - Client-ready report with risk scoring
- `audit_report_*.md` - GitHub-friendly Markdown

---

## 🎯 **What You Get**

### **14 Integrated Analyzers**
1. **Heuristic Scanner** - 31 vulnerability patterns (reentrancy, oracle issues, access control)
2. **Slither** - Trail of Bits static analyzer
3. **Aderyn** - Cyfrin Rust-based analyzer (complementary to Slither)
4. **Liar Detector** - NatSpec comment vs implementation mismatch detection
5. **Access Matrix** - Function permission analysis
6. **Upgrade Diff** - UUPS/proxy storage collision detection
7. **Solana Analyzer** - 35 Rust/Anchor security patterns
8. **Medusa** - Coverage-guided fuzzing
9. **Foundry** - Invariant testing
10. **Mythril** - Symbolic execution
11. **Supply Chain** - OSV.dev dependency scanner
12. **Threat Intel** - Code4rena, Immunefi, Solodit historical exploit database
13. **Knowledge Fetcher** - EVM-specific vulnerability research
14. **Inflation Scaffold** - ERC4626 attack test generator

### **Professional Reports**
- **Risk Scoring** (0-100) based on severity distribution
- **Pass/Fail Status** (auto-fail on CRITICAL or >3 HIGH findings)
- **Remediation Steps** with CWE mappings and references
- **Code Snippets** with exact file:line locations
- **HTML + Markdown** formats for clients and GitHub

### **Zero False Positives**
- **Configurable suppressions** via `sentinel.toml`
- **Per-rule severity overrides** (e.g., downgrade timestamp usage for timelocks)
- **Expiry-based accepted risks** ("This is safe until 2026-12-31")
- **File/line-specific suppressions** (suppress specific occurrences, not all)

### **3 Execution Profiles**

**Audit Mode** (`sentinel-audit.toml`)
- Maximum thoroughness for client deliverables
- All analyzers enabled, deep fuzzing (250K tests)
- Fail on MEDIUM+ severity
- Verbose reporting with all context

**PR Mode** (`sentinel-pr.toml`)
- Fast blocker checks for CI/CD (< 2 minutes)
- Skip slow analyzers (Aderyn, fuzzing)
- Fail on HIGH+ only
- Common false positives pre-suppressed

**Bounty Hunter Mode** (`sentinel-bounty.toml`)
- Maximum coverage for exploit discovery
- All rules enabled, extreme fuzzing (500K tests)
- Never fails (report everything)
- AI exploit PoC generation
- Group by severity (show $$$ bugs first)

---

## 📊 **Usage Examples**

### **Client Audit Workflow**
```powershell
# 1. Full automated scan
sentinel-engine --target ./client-project --config sentinel-audit.toml --report --project-name "Client DeFi Protocol"

# 2. Review HTML report
# → audit_report_2025-12-21.html
#    Risk Score: 42.3/100
#    Status: WARNING
#    Findings: 23 (2 CRITICAL, 5 HIGH, 12 MEDIUM, 4 LOW)

# 3. Send to client with remediation steps
```

### **GitHub Actions Integration**
```yaml
# .github/workflows/security.yml already configured
# Two jobs:
#   1. blocker-checks (fails PR on CRITICAL/HIGH)
#   2. advisory-checks (comments MEDIUM/LOW, never fails)

on:
  pull_request:
    branches: [main]

jobs:
  sentinel:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Sentinel Engine
        run: pip install -e .
      - name: Sentinel PR Check
        run: |
          sentinel-engine --target ./contracts --config sentinel-pr.toml
```

### **Bug Bounty Hunting**
```powershell
# Max coverage mode
sentinel-engine --target ./target-protocol --config sentinel-bounty.toml --medusa --aderyn --report

# Generate exploit PoCs (requires OpenAI API key)
export OPENAI_API_KEY="sk-..."
python exploit_generator.py --finding-json findings.json --output exploits/

# Submit to Immunefi/Code4rena
```

### **Standalone Module Usage**

**Heuristic Scanner** (no dependencies):
```powershell
python heuristic_scanner.py ./contracts --config sentinel-pr.toml
# Detects: reentrancy, unchecked calls, oracle staleness, access control issues
```

**Liar Detector** (semantic analysis):
```powershell
python intent_check.py ./contracts/Token.sol
# Finds: "/// @notice Only admin" but function is public with no modifier
```

**Upgrade Diff** (proxy safety):
```powershell
python upgrade_diff.py ./VaultV1.sol ./VaultV2.sol
# Detects: storage collisions, removed auth, new reentrancy risks
```

**Access Matrix** (permission audit):
```powershell
python access_matrix.py ./contracts/Vault.sol
# Shows: 🚨 emergencyWithdraw (external, WRITE) -> Anyone [HIGH RISK]
```

---

## 🔧 **Configuration System**

### **Complete Configuration Reference**

Sentinel Engine uses TOML configuration files. Below are all available sections:

#### `[engine]` - Core Engine Settings
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | "Sentinel Security Engine" | Engine name |
| `version` | string | "2.3.0" | Engine version |
| `fail_on_severity` | string | "HIGH" | Minimum severity to fail CI (CRITICAL, HIGH, MEDIUM, LOW, INFO) |
| `max_findings` | int | 0 | Maximum findings before stopping (0 = unlimited) |

#### `[heuristics]` - Heuristic Scanner
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable heuristic scanning |
| `severity_overrides` | table | {} | Override rule severities (RULE_ID = "SEVERITY") |
| `disabled_rules` | table | {} | Disable specific rules (RULE_ID = true) |

#### `[[suppressions]]` - False Positive Management
| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `rule_id` | string | Yes | Rule to suppress |
| `file` | string | No | Specific file to suppress |
| `line` | int | No | Specific line to suppress |
| `reason` | string | Yes | Explanation for suppression |
| `expires` | string | No | Expiration date (YYYY-MM-DD) |

#### `[static_analysis]` - Static Analyzers
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `slither.enabled` | bool | true | Enable Slither analysis |
| `slither.exclude_detectors` | string | "" | Comma-separated detectors to exclude |
| `slither.include_impact` | string | "High,Medium" | Impact levels to include |
| `aderyn.enabled` | bool | false | Enable Aderyn analysis (opt-in) |
| `aderyn.scope` | string | "" | Limit analysis to specific paths |

#### `[fuzzing]` - Fuzzing Configuration
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `foundry.enabled` | bool | false | Enable Foundry fuzzing |
| `foundry.runs` | int | 10000 | Number of fuzz runs |
| `medusa.enabled` | bool | false | Enable Medusa fuzzing |
| `medusa.test_limit` | int | 100000 | Test limit for Medusa |
| `medusa.timeout` | int | 300 | Timeout in seconds |
| `medusa.workers` | int | 10 | Number of workers |

#### `[red_team]` - Red Team Scan Settings
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `severity_allowlist` | list | ["High", "Medium"] | Severities to include |
| `ignore_checks` | list | [...] | Check IDs to ignore (noise filtering) |

#### `[external_tools]` - Tool Timeouts
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `aderyn_timeout` | int | 120 | Aderyn timeout (seconds) |
| `mythril_timeout` | int | 600 | Mythril timeout (seconds) |
| `foundry_fuzz_runs` | int | 1000 | Foundry default fuzz runs |

#### `[supply_chain]` - Supply Chain Security
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ecosystem` | string | "npm" | Package ecosystem (npm, pypi) |
| `osv_timeout` | int | 10 | OSV API timeout (seconds) |
| `osv_max_retries` | int | 3 | OSV API max retries |
| `osv_rate_limit` | int | 10 | OSV API rate limit (requests/sec) |

#### `[threat_intel]` - Threat Intelligence
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `c4_timeout` | int | 10 | Code4rena API timeout (seconds) |
| `immunefi_timeout` | int | 10 | Immunefi RSS timeout (seconds) |
| `solana_github_timeout` | int | 10 | Solana GitHub timeout (seconds) |
| `api_rate_limit` | int | 5 | Default API rate limit (requests/sec) |

#### `[http]` - HTTP Client Settings
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_timeout` | int | 30 | Default HTTP timeout (seconds) |
| `max_retries` | int | 3 | Max retries for failed requests |
| `base_delay` | float | 1.0 | Base delay for exponential backoff (seconds) |
| `max_delay` | float | 30.0 | Maximum delay cap (seconds) |
| `backoff_factor` | float | 2.0 | Backoff multiplier |

#### `[chains]` - Chain-Specific Settings
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `solana.enabled` | bool | false | Enable Solana analysis |
| `solana.project_root` | string | "./programs" | Path to Solana project |
| `evm.solc_version` | string | ">=0.8.0" | Expected Solidity version |
| `evm.trusted_contracts` | list | [] | Known safe external contracts |

#### `[upgrade_diff]` - Upgrade Safety
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `old_implementation_path` | string | "" | Path to old implementation |
| `new_implementation_path` | string | "" | Path to new implementation |
| `ignore_patterns.ignore_new_view_functions` | bool | true | Ignore new view functions |
| `ignore_patterns.ignore_comment_changes` | bool | true | Ignore comment changes |

#### `[reporting]` - Report Generation
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | "markdown" | Output format (markdown, json, sarif, html) |
| `sections.executive_summary` | bool | true | Include executive summary |
| `sections.supply_chain` | bool | true | Include supply chain section |
| `sections.static_analysis` | bool | true | Include static analysis |
| `sections.heuristic_scan` | bool | true | Include heuristic scan |
| `sections.fuzzing` | bool | false | Include fuzzing results |
| `sections.threat_intel` | bool | false | Include threat intel |
| `sections.access_matrix` | bool | true | Include access matrix |
| `verbosity` | string | "standard" | Report verbosity (minimal, standard, verbose) |
| `group_by` | string | "severity" | Group findings by (severity, file, rule) |

#### `[ci]` - CI/CD Integration
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `fail_on_findings` | bool | true | Fail pipeline if issues found |
| `post_pr_comment` | bool | true | Post results as PR comment |
| `upload_sarif` | bool | false | Upload SARIF to GitHub Security |
| `exclude_paths` | list | [...] | Paths to exclude from scanning |

---

### **Execution Profiles Comparison**

| Feature | PR Mode | Audit Mode | Bounty Mode |
|---------|---------|------------|-------------|
| **Config File** | `sentinel-pr.toml` | `sentinel-audit.toml` | `sentinel-bounty.toml` |
| **Time** | < 2 min | 10-30 min | 1-2 hours |
| **Fail Threshold** | HIGH+ | MEDIUM+ | Never fails |
| **Heuristic Scanner** | ✅ Fast | ✅ Full | ✅ Full |
| **Slither** | ✅ | ✅ | ✅ |
| **Aderyn** | ❌ | ✅ | ✅ |
| **Medusa Fuzzing** | ❌ | ✅ (250K) | ✅ (500K) |
| **Mythril** | ❌ | ✅ | ✅ |
| **Supply Chain** | ✅ | ✅ | ✅ |
| **Threat Intel** | ❌ | ✅ | ✅ |
| **Liar Detector** | ✅ | ✅ | ✅ |
| **Report Formats** | Markdown | HTML + MD | HTML + MD + SARIF |
| **Suppressions** | Pre-configured | Project-specific | None (all rules) |
| **AI Exploit Gen** | ❌ | ❌ | ✅ |

### **Profile Selection**
```powershell
# Use pre-built profiles
sentinel-engine --target ./contracts --config sentinel-audit.toml    # Full audit
sentinel-engine --target ./contracts --config sentinel-pr.toml       # Fast PR check
sentinel-engine --target ./contracts --config sentinel-bounty.toml   # Bug bounty

# Or create custom config
sentinel-engine --target ./contracts --config my-custom.toml
```

---

## 🚨 **Key Features**

### **1. Liar Detector (Semantic Analysis with NatSpec Parsing)**
Finds mismatches between developer intent (NatSpec comments) and actual implementation:

**NatSpec Parsing Capabilities:**
- Parses `@notice`, `@dev`, `@param`, and `@return` tags
- Supports both `///` single-line and `/** */` multi-line formats
- Extracts trust keywords and access control claims
- Compares documented behavior against actual function modifiers and visibility

**Supported NatSpec Tags:**
- `@notice` - High-level description of function purpose
- `@dev` - Developer notes and implementation details
- `@param` - Parameter documentation
- `@return` - Return value documentation

```solidity
/// @notice Only owner can withdraw funds  ← Says "owner"
/// @dev Transfers entire balance to owner
/// @param token The token address to withdraw
/// @return success Whether the withdrawal succeeded
function withdraw(address token) public returns (bool success) {  ← Code says "public" (NO MODIFIER!)
    // ❌ CRITICAL: Intent mismatch detected!
}
```

**Output:**
```
⚠️  CRITICAL: Developer intent does NOT match implementation!
[MISMATCH] Line 42: withdraw
  • Comment implies: 'owner'
  • Code reality:    Public/External with NO detected modifiers.
  💡 FIX: Add modifier (onlyOwner, onlyRole) or change visibility to internal.
```

### **2. Professional HTML Reports**

**Client-ready deliverables with:**
- Executive summary with risk score (0-100)
- Pass/Fail status badge
- Findings grouped by analyzer (Slither, Heuristics, Liar Detector, etc.)
- Severity badges (CRITICAL/HIGH/MEDIUM/LOW)
- Code snippets with syntax highlighting
- Remediation steps with references (CWE, OWASP)
- Professional gradient styling

**Example:**
```
🛡️ Security Audit Report
━━━━━━━━━━━━━━━━━━━━━━━━
Project: DeFi Vault
Risk Score: 42.3/100
Status: ⚠️ WARNING

Findings:
  🔴 CRITICAL: 2
  🟠 HIGH: 5
  🟡 MEDIUM: 12
  🔵 LOW: 4
```

### **3. GitHub Actions Blocker/Advisory Separation**

**Two-tier CI/CD checks:**

**Blockers** (fail PR):
- CRITICAL/HIGH heuristics
- Liar Detector mismatches
- Upgrade Diff storage collisions
- Removed access control

**Advisories** (comment only):
- MEDIUM/LOW findings
- Timestamp usage (safe for timelocks)
- Hardcoded addresses (expected for oracles)
- Gas optimizations

**Example PR comment:**
```markdown
## 🔍 Advisory Security Findings (Non-Blocking)

Found 3 MEDIUM and 5 LOW severity issues that do not block this PR.

### Summary
- 🟡 MEDIUM: 3
- 🔵 LOW: 5

### Sample Findings
[MEDIUM] TX_ORIGIN_USAGE @ contracts/Auth.sol:42
[LOW] HARDCODED_ADDRESS @ contracts/Oracle.sol:15

---
These are advisory findings that **do not block** the PR.
Consider addressing them in a follow-up.
```

### **4. Upgrade Safety Analysis**

Detects dangerous proxy upgrade patterns:

```
⚠️  UNSAFE TO UPGRADE - Critical issues found!

[CRITICAL] Storage slot 2 reassigned
  Variable 'owner' replaced with 'admin' in slot 2.
  Existing data will be misinterpreted!
  Old: address owner
  New: address admin

[CRITICAL] Authorization removed from emergencyWithdraw()
  Function had modifier ['onlyOwner'] which is now removed.
  Anyone can call it!
```

---

## 🐳 **Docker Deployment**

### **Quick Start**
```bash
# Build image
docker build -t sentinel-engine .

# Run audit
docker run --rm -v $(pwd):/scan sentinel-engine --target /scan --config /scan/sentinel-pr.toml

# Generate report
docker run --rm -v $(pwd):/scan sentinel-engine --target /scan --report
```

### **Docker Compose**
```bash
docker-compose run --rm audit --target /scan --config /scan/sentinel-audit.toml --report
```

**Includes:**
- Python 3.10, Slither, Mythril, solc (0.8.19/0.8.20/0.8.23)
- All dependencies pre-installed
- ~600MB optimized image

---

## 📚 **Advanced Features**

### **AI Exploit Generation** (GPT-4)
```powershell
# Set API key
export OPENAI_API_KEY="sk-..."

# Generate exploit from finding
python exploit_generator.py \
  --rule-id UNCHECKED_EXTERNAL_CALL \
  --file contracts/Vault.sol \
  --line 300 \
  --description "External call without return check"

# Output: test/exploits/Exploit_UNCHECKED_EXTERNAL_CALL.t.sol
```

### **Threat Intelligence**
```powershell
# Query historical exploits
python threat_intel.py contracts/Vault.sol
# → Searches Code4rena, Immunefi, Solodit for similar bugs

# Solana-specific
python threat_intel.py programs/staking/lib.rs
# → Searches Neodyme, OtterSec, Sec3
```

### **Medusa Fuzzing**
```powershell
python medusa_wrapper.py ./foundry-project --test-limit 50000 --timeout 300
# Coverage-guided fuzzing (10-100x faster than Echidna)
```

---

## 🧠 **Vulnerability Patterns**

### **High-Value Bug Bounty Patterns**
| Rule ID | Severity | Typical Payout |
|---------|----------|----------------|
| `UNCHECKED_EXTERNAL_CALL` | CRITICAL | $10K-$100K |
| `ORACLE_STALENESS_CHECK` | CRITICAL | $50K-$500K |
| `FLASH_LOAN_REENTRANCY` | CRITICAL | $100K-$1M+ |
| `SIGNATURE_REPLAY` | HIGH | $20K-$100K |
| `STORAGE_COLLISION_RISK` | HIGH | $30K-$200K |
| `UNSAFE_CAST` | HIGH | $10K-$50K |
| `MISSING_SLIPPAGE_PROTECTION` | HIGH | $5K-$30K |

### **Solana/Anchor Patterns (35 rules)**

**Account Validation (8):**
- MISSING_SIGNER_CHECK, MISSING_OWNER_CHECK, MISSING_HAS_ONE_CONSTRAINT
- MISSING_DISCRIMINATOR_CHECK, UNVALIDATED_PDA_SEEDS, MISSING_IS_SIGNER_RAW
- MISSING_ACCOUNT_DATA_VALIDATION, UNVALIDATED_ACCOUNT_INFO

**CPI Security (4):**
- ARBITRARY_CPI, MISSING_CPI_AUTHORITY, UNVERIFIED_PROGRAM_ACCOUNT, UNSAFE_INVOKE_SIGNED

**Arithmetic & Logic (5):**
- UNCHECKED_ARITHMETIC, INTEGER_OVERFLOW_RISK, UNSAFE_CASTING
- DIVISION_BY_ZERO_RISK, PRECISION_LOSS

**State Management (6):**
- MISSING_RENT_EXEMPTION, UNINITIALIZED_ACCOUNT_USAGE, ACCOUNT_REINITIALIZATION
- MISSING_CLOSE_ACCOUNT, STALE_ACCOUNT_DATA, UNCLOSED_ACCOUNT

**Access Control (4):**
- MISSING_ACCESS_CONTROL, HARDCODED_AUTHORITY, MISSING_MULTISIG, WEAK_AUTHORITY_CHECK

**Token Security (4):**
- MISSING_TOKEN_ACCOUNT_VALIDATION, UNCHECKED_TOKEN_BALANCE
- MISSING_FREEZE_AUTHORITY_CHECK, UNVALIDATED_TOKEN_PROGRAM

**General Validation (4):**
- UNVALIDATED_ACCOUNT_DATA, UNCONSTRAINED_SYSTEM_PROGRAM
- MISSING_CLOCK_VALIDATION, DUPLICATE_MUTABLE_ACCOUNTS

### **DeFi-Specific**
- ERC4626 inflation attacks
- Oracle manipulation
- AMM price manipulation
- Flash loan reentrancy
- Precision loss (divide before multiply)

### **Access Control**
- Missing modifiers (Liar Detector)
- tx.origin usage
- Unprotected initializers
- Admin centralization risks

---

## 🗂️ **Project Structure**

```
sentinel-engine/
│
├── gui.py                      # Interactive Tkinter interface
├── orchestrator.py             # CLI master pipeline + Markdown reports
├── threat_intel.py             # Unified launcher (auto-detects EVM vs Solana)
│
├── knowledge_fetcher.py        # EVM threat intel (C4 + Immunefi + Solodit)
├── solana_intel.py             # Solana threat intel (Neodyme + Sec3 + OtterSec)
│
├── heuristic_scanner.py        # Pattern-based vulnerability detection (31 rules)
├── access_matrix.py            # Function permission analyzer
├── intent_check.py             # 🤥 Liar Detector (NatSpec vs. code mismatch)
│
├── red_team_scan.py            # Slither wrapper
├── aderyn_wrapper.py           # 🆕 Aderyn analyzer (Rust-based)
├── symbolic_wrapper.py         # Mythril wrapper
├── fuzz_wrapper.py             # Foundry invariant test wrapper
├── medusa_wrapper.py           # 🆕 Medusa coverage-guided fuzzing
├── supply_chain_check.py       # OSV.dev dependency scanner
├── inflation_scaffold.py       # ERC4626 test generator
│
├── exploit_generator.py        # 🤖 GPT-4 PoC generation
├── upgrade_diff.py             # 🔍 Proxy upgrade safety checker
│
├── Dockerfile                  # 🐳 Single-command deployment
├── docker-compose.yml          # ⚡ Easy orchestration
├── .dockerignore               # Image optimization
│
└── [Design Documents]
    ├── Pragmatic Security Engine.txt
    ├── Action-Oriented Orchestrator.txt
    ├── God Mode Matrix.txt
    └── Directions for tools.txt
```

---

## 🔧 **Configuration**

### **Python Interpreter Path**
Edit scripts if using custom Python installation:
```python
# Default: System Python
python orchestrator.py

# Custom path (Windows):
& "C:\Python310\python.exe" orchestrator.py
```

### **Slither Configuration**
To skip specific checks, edit `red_team_scan.py`:
```python
IGNORE_CHECKS = [
    "solc-version",
    "naming-convention",
    "assembly",
    # Add more...
]
```

### **Heuristic Scanner Tuning**
Adjust severity thresholds in `heuristic_scanner.py`:
```python
SEVERITY_ALLOWLIST = ["HIGH", "MEDIUM"]  # Filter out INFO/LOW
```

### **Liar Detector Customization**
Add custom trust keywords in `intent_check.py`:
```python
TRUST_KEYWORDS = ["admin", "owner", "restrict", "protected", "secure", "authorized"]
AUTH_MODIFIERS = ["onlyOwner", "onlyRole", "auth", "nonReentrant", "whenNotPaused"]
```

---

## 💼 **Use Cases**

### **CyberShield Austin - Client Audits**
```powershell
# Phase 0: Research historical exploits
python threat_intel.py /path/to/client/contracts/Vault.sol

# Phase 1: Quick heuristic scan
python heuristic_scanner.py /path/to/client/contracts

# Phase 2: Full audit with report
python orchestrator.py --target /path/to/client/contracts --heuristic
# → Deliverable: ACTION_PLAN_*.md
```

### **TokenAudit YouTube - Content Creation**
```powershell
# Demo threat intelligence for educational content
python threat_intel.py examples/vulnerable_vault.sol

# Show GUI workflow for non-technical audience
python gui.py
```

### **Bug Bounty Hunting**
```powershell
# Scan target protocol
python heuristic_scanner.py target/contracts

# Check for known exploit patterns
python knowledge_fetcher.py target/contracts/Core.sol
```

### **Solana Projects ($PWD123, etc.)**
```powershell
# Research Anchor program vulnerabilities
python threat_intel.py programs/staking/lib.rs

# Manual audit with Solodit references
python solana_intel.py programs/token/lib.rs
```

---

## 🛡️ **Limitations & Caveats**

### **What This Tool Does**
✅ Fast pattern-based vulnerability detection  
✅ Historical exploit research and threat modeling  
✅ Access control verification  
✅ **Semantic analysis (intent vs. implementation)**  
✅ Automated report generation  
✅ **Runtime monitoring blueprints (Forta integration)**  
✅ **Mainnet fork testing guidance**  

### **What This Tool Does NOT Replace**
❌ Manual code review by experienced auditors  
❌ Formal verification  
❌ Runtime monitoring / incident response (provides templates, not full deployment)  
❌ Legal compliance audits  

### **Known Issues**
- **Slither/Mythril optional** - GUI gracefully degrades if not installed
- **False positives** - Heuristic patterns may flag safe code (review manually)
- **Liar Detector** - Relies on comment keywords (can miss context-specific security assumptions)
- **Solana support** - Threat intel only (no static analysis for Rust yet)
- **Watchtower** - Provides Forta templates; manual deployment required

---

## 📚 **Documentation**

### **Design Philosophy**
Read [Pragmatic Security Engine.txt](./Pragmatic%20Security%20Engine.txt) for the original vision:
- Action-oriented (not academic)
- Noise filtering (only show what matters)
- Remediation-focused (not just detection)

### **Module Details**
- [Action-Oriented Orchestrator.txt](./Action-Oriented%20Orchestrator.txt) - CLI pipeline design
- [God Mode Matrix.txt](./God%20Mode%20Matrix.txt) - Access control analysis methodology
- [Directions for tools.txt](./Directions%20for%20tools.txt) - Module integration guide

---

## 📝 **Logging Configuration**

Sentinel Engine uses a centralized logging system via `logger.py`:

### **Log Levels**
Set via `SENTINEL_LOG_LEVEL` environment variable:
- `DEBUG` - Detailed debugging information
- `INFO` - General operational information
- `WARNING` - Warning messages for potential issues
- `ERROR` - Error messages
- `CRITICAL` - Critical errors that may prevent operation

### **Log Formats**
Set via `SENTINEL_LOG_FORMAT` environment variable:
- `text` - Human-readable colored output (default)
- `json` - Structured JSON lines for machine parsing

### **File Logging**
Set `SENTINEL_LOG_FILE` to enable logging to a file:
```bash
export SENTINEL_LOG_FILE=/var/log/sentinel.log
python orchestrator.py --target ./contracts
```

---

## 📊 **SARIF Report Support**

Sentinel Engine supports SARIF 2.1.0 (Static Analysis Results Interchange Format) for integration with GitHub Advanced Security and other tools.

### **Generating SARIF Reports**

**Via CLI:**
```bash
# Generate SARIF report using report generator
python report_generator.py --format sarif --output report

# Aderyn also supports SARIF output
python aderyn_wrapper.py ./project --format sarif
```

**Via Configuration:**
```toml
[reporting]
format = "sarif"
sarif_upload = true  # Enable GitHub SARIF upload
```

### **GitHub Actions Integration**

Upload SARIF results to GitHub Advanced Security:

```yaml
- name: Install Sentinel Engine
  run: pip install -e .

- name: Run Sentinel Scan
  run: |
    sentinel-engine --target ./contracts --report
    python report_generator.py --format sarif --output sentinel-results

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: sentinel-results.sarif
```

---

## 🌐 **API Resilience Features**

The `http_utils.py` module provides resilient HTTP communication for threat intelligence APIs:

### **Retry Logic**
- Exponential backoff with jitter for failed requests
- Configurable max retries (default: 3)
- Automatic retry on 5xx errors and timeouts
- Respects `Retry-After` headers for rate limiting

### **Rate Limiting**
- Token bucket rate limiter to control request rates
- Configurable requests per second/minute
- Prevents API quota exhaustion

### **Error Classification**
- Automatic classification of HTTP status codes
- Different retry strategies for different error types
- Structured error reporting via `SentinelAPIError`

---

## 🐛 **Troubleshooting**

### **Missing External Tools**

**Slither not found:**
```bash
# Install Slither
pip install slither-analyzer

# Verify installation
slither --version
```

**Aderyn not found:**
```bash
# Install Aderyn (requires Rust)
cargo install aderyn

# Or via Foundry
foundryup
```

**Medusa not found:**
```bash
# Install Medusa (requires Go)
go install github.com/crytic/medusa/cmd/medusa@latest
```

### **OpenAI API Key Not Set**

If you see errors when using exploit generation:
```bash
# Set your OpenAI API key
export OPENAI_API_KEY="sk-..."

# Or on Windows
set OPENAI_API_KEY=sk-...
```

### **Solc Version Not Installed**

If Slither fails with "solc version not installed":
```bash
# Install solc-select
pip install solc-select

# Install and use specific Solidity version
solc-select install 0.8.19
solc-select use 0.8.19
```

### **Network Timeouts for Threat Intel APIs**

If threat intelligence lookups timeout:
```bash
# Increase timeout via environment
export SENTINEL_LOG_LEVEL=DEBUG  # See detailed retry attempts

# Check network connectivity
python -c "from http_utils import resilient_get; resilient_get('https://osv.dev')"

# The system automatically retries with exponential backoff
# You can also check your firewall/proxy settings
```

### **Common Issues**

**"Cannot find contract file"**
- Ensure the target path exists and is accessible
- Use absolute paths or verify relative paths from your current directory
- Check file permissions

**"Docker build fails"**
- Ensure Docker daemon is running
- Check available disk space (~600MB required)
- Try building with `--no-cache` flag

**"Permission denied"**
- On Linux/Mac: `chmod +x` scripts if needed
- Check write permissions for output directories

---

## 🤝 **Contributing**

### **Adding New Heuristic Rules**
Edit `heuristic_scanner.py`:
```python
HeuristicRule(
    id="MY_NEW_RULE",
    description="Brief description",
    severity="HIGH",  # CRITICAL, HIGH, MEDIUM, INFO
    pattern=re.compile(r"your_regex_pattern"),
    hint="Remediation guidance..."
)
```

### **Adding Threat Intelligence Sources**
- **EVM:** Edit `knowledge_fetcher.py` → Add new API/RSS feed
- **Solana:** Edit `solana_intel.py` → Add audit firm GitHub repos

---

## 📄 **License**

**MIT License** - Free for commercial and personal use.

See LICENSE for details.

---

## 🙏 **Credits**

**Built by:**
- CyberShield Austin (professional security audits)
- [@defiauditccie](https://twitter.com/defiauditccie) (Twitter/X)

**Powered by:**
- [Slither](https://github.com/crytic/slither) - Trail of Bits
- [Aderyn](https://github.com/Cyfrin/aderyn) - Cyfrin
- [Medusa](https://github.com/crytic/medusa) - Crytic  
- [Mythril](https://github.com/ConsenSys/mythril) - ConsenSys
- [Foundry](https://github.com/foundry-rs/foundry) - Paradigm
- [OSV.dev](https://osv.dev) - Google

**Threat Intelligence:**
- Code4rena, Immunefi, Solodit (EVM)
- Neodyme, OtterSec, Sec3 (Solana)

---

## 🔧 **Environment Variables**

Sentinel Engine supports the following environment variables for configuration:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SENTINEL_LOG_LEVEL` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | INFO | No |
| `SENTINEL_LOG_FORMAT` | Output format ("text" or "json") | text | No |
| `SENTINEL_LOG_FILE` | Optional file path for log output | (none) | No |
| `OPENAI_API_KEY` | OpenAI API key for GPT-4 exploit generation | (none) | For AI features |

### Usage Examples

```bash
# Debug logging to file
export SENTINEL_LOG_LEVEL=DEBUG
export SENTINEL_LOG_FILE=/var/log/sentinel.log
sentinel-engine --target ./contracts

# JSON format for structured logging
export SENTINEL_LOG_FORMAT=json
sentinel-engine --target ./contracts 2>&1 | jq

# OpenAI for exploit generation
export OPENAI_API_KEY="sk-..."
python exploit_generator.py --finding-json findings.json
```

---

## 📧 **Support**

**Professional Audits:**
- CyberShield Austin
- Twitter: [@defiauditccie](https://twitter.com/defiauditccie)
- Website: [sentinel-engine.io](https://sentinel-engine.io)

**GitHub:**
- Issues: [github.com/RunTimeAdmin/sentinel-engine/issues](https://github.com/RunTimeAdmin/sentinel-engine/issues)

---

**Version:** 2.3.0  
**Last Updated:** April 18, 2026  
**License:** MIT  
**Chains:** EVM, Solana  
**Analyzers:** 14  
**Patterns:** 31 EVM + 35 Solana  
**Profiles:** 3  

---

**⭐ If this helped you find bugs, please star the repo!**
