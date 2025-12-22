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
cd "C:\Users\David\Desktop\Pragmatic Security Engine"

# 2. Install core dependencies
pip install requests packaging tomli

# 3. Install Slither (static analysis)
pip install slither-analyzer
pip install solc-select
solc-select install 0.8.19
solc-select use 0.8.19

# 4. Verify installation
python orchestrator.py --help
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
python orchestrator.py --target ./contracts --config sentinel-pr.toml

# Full audit with HTML report
python orchestrator.py --target ./contracts --config sentinel-audit.toml --report --project-name "MyDeFi"

# Bug bounty mode (max coverage)
python orchestrator.py --target ./contracts --config sentinel-bounty.toml --medusa
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
7. **Solana Analyzer** - Rust/Anchor pattern detection
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
python orchestrator.py --target ./client-project --config sentinel-audit.toml --report --project-name "Client DeFi Protocol"

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
      - name: Sentinel PR Check
        run: |
          python orchestrator.py --target ./contracts --config sentinel-pr.toml
```

### **Bug Bounty Hunting**
```powershell
# Max coverage mode
python orchestrator.py --target ./target-protocol --config sentinel-bounty.toml --medusa --aderyn --report

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

### **Basic Config** (`sentinel.toml`)

```toml
[engine]
fail_on_severity = "HIGH"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
max_findings = 50

[heuristics]
enabled = true

# Disable noisy rules
[heuristics.disabled_rules]
CONSOLE_LOG = true
FLOATING_PRAGMA = true

# Override severities
[heuristics.severity_overrides]
UNCHECKED_EXTERNAL_CALL = "CRITICAL"
BLOCK_TIMESTAMP_RANDOMNESS = "LOW"  # Safe for timelocks

# Suppress false positives
[[suppressions]]
rule_id = "HARDCODED_ADDRESS"
file = "contracts/Oracle.sol"
line = 42
reason = "Chainlink oracle address (expected)"
expires = "2025-12-31"

[static_analysis]
slither_enabled = true
aderyn_enabled = true

[fuzzing]
medusa_enabled = true
medusa_test_limit = 50000

[reporting]
format = "markdown"
html_enabled = true
verbosity = "verbose"
```

### **Profile Selection**
```powershell
# Use pre-built profiles
python orchestrator.py --target ./contracts --config sentinel-audit.toml    # Full audit
python orchestrator.py --target ./contracts --config sentinel-pr.toml       # Fast PR check
python orchestrator.py --target ./contracts --config sentinel-bounty.toml   # Bug bounty

# Or create custom config
python orchestrator.py --target ./contracts --config my-custom.toml
```

---

## 🚨 **Key Features**

### **1. Liar Detector (Semantic Analysis)**
Finds mismatches between developer intent (comments) and implementation:

```solidity
/// @notice Only owner can withdraw funds  ← Says "owner"
function withdraw() public {                 ← Code says "public" (NO MODIFIER!)
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
Pragmatic Security Engine/
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
& "C:\Users\David\AppData\Local\Programs\Python\Python310\python.exe" orchestrator.py
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
python threat_intel.py Z:\client\contracts\Vault.sol

# Phase 1: Quick heuristic scan
python heuristic_scanner.py Z:\client\contracts

# Phase 2: Full audit with report
python orchestrator.py --target Z:\client\contracts --heuristic
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

## 📧 **Support**

**Professional Audits:**
- CyberShield Austin
- Twitter: [@defiauditccie](https://twitter.com/defiauditccie)
- Website: [scamhoundcrypto.com](https://scamhoundcrypto.com)

**GitHub:**
- Issues: [github.com/RunTimeAdmin/sentinel-engine/issues](https://github.com/RunTimeAdmin/sentinel-engine/issues)

---

**Version:** 2.2.0  
**Last Updated:** December 21, 2025  
**License:** MIT  
**Chains:** EVM, Solana  
**Analyzers:** 14  
**Patterns:** 31  
**Profiles:** 3  

---

**⭐ If this helped you find bugs, please star the repo!**
- Neodyme, OtterSec, Sec3 (Solana)

**Powered by:**
- Slither (Trail of Bits)
- Mythril (ConsenSys)
- Foundry (Paradigm)
- OSV.dev (Google)

---

## 📞 **Support**

For professional security audits:
- **CyberShield Austin**: [Contact via TokenAudit]
- **YouTube**: TokenAudit channel
- **Scam detection**: scamhoundcrypto.com

---

**Version:** 2.2 (Multi-Chain + AI + Dual Static Analysis Release)  
**Last Updated:** December 21, 2025  
**Chains Supported:** EVM, Solana  
**Vulnerability Patterns:** 31  
**Threat Intel Sources:** 7  
**Analysis Modules:** 14  
**Static Analyzers:** 2 (Slither + Aderyn)  
**🆕 Semantic Analysis:** Liar Detector (Intent Mismatch Detection)  
**🤖 AI-Powered:** GPT-4 Exploit Generation  
**🔍 Upgrade Safety:** Proxy Diff Analyzer  
**📡 Runtime Monitoring:** Forta Watchtower Templates  
**⏰ Fork Testing:** Mainnet Simulation Guidance
