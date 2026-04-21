# Garrison Security Engine

**Production-ready smart contract security platform with 21 integrated analyzers, configurable rules, and professional audit reports.**

> One command. Zero false positives. Client-ready deliverables.

[![PyPI](https://img.shields.io/pypi/v/garrison-engine)](https://pypi.org/project/garrison-engine/)
[![Python](https://img.shields.io/pypi/pyversions/garrison-engine)](https://pypi.org/project/garrison-engine/)
[![License](https://img.shields.io/pypi/l/garrison-engine)](https://pypi.org/project/garrison-engine/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## ⚡ **Quick Start (5 Minutes)**

### **Installation**

```powershell
# 1. Install from PyPI (recommended)
pip install garrison-engine

# 2. Install with web UI support
pip install garrison-engine[web]

# 3. Install with AI/RAG features
pip install garrison-engine[ai]

# 4. Install with development dependencies
pip install garrison-engine[dev]

# 5. Verify installation
garrison-engine --help
```

**Required Dependencies:**
```powershell
# Foundry (forge) — Required for Slither static analysis on Foundry/Hardhat projects
# Install (macOS/Linux):
curl -L https://foundry.paradigm.xyz | bash && foundryup
# Windows: Download from https://github.com/foundry-rs/foundry/releases
# Verify:
forge --version
```

**Optional External Tools (for full functionality):**
```powershell
# Slither (static analysis)
pip install slither-analyzer
solc-select install 0.8.19
solc-select use 0.8.19

# Aderyn (Rust-based analyzer)
cargo install aderyn

# Medusa (fuzzing)
go install github.com/crytic/medusa/cmd/medusa@latest
```

---

## Pricing Tiers

Garrison Engine includes both free and pro features in a single package. Pro features require a license key.

| Feature | Community (Free) | Developer ($49/mo) | Pro ($149/mo) | Team ($399/mo) | Enterprise |
|---------|-----------------|-------------------|---------------|----------------|-----------|
| 14 Free Analyzers | Yes | Yes | Yes | Yes | Yes |
| CLI + Markdown/JSON Reports | Yes | Yes | Yes | Yes | Yes |
| Web App Access | - | 5 scans/mo | Unlimited | Unlimited | Unlimited |
| Solana Analyzer (35 rules) | - | Yes | Yes | Yes | Yes |
| Branded HTML/SARIF Reports | - | Yes | Yes | Yes | Yes |
| AI Audit Copilot (RAG) | - | - | Yes | Yes | Yes |
| Attack Graph Visualization | - | - | Yes | Yes | Yes |
| Exploit PoC Generator | - | - | Yes | Yes | Yes |
| Time-Travel Git Scanner | - | - | Yes | Yes | Yes |
| Protocol Fingerprinting | - | - | Yes | Yes | Yes |
| Machine Activations | - | 1 | 3 | 10 | Unlimited |
| Support | GitHub | Email | Priority (24hr) | Dedicated | CSM |

See full pricing at https://garrisonsec.io/pricing

### Activating Pro

```bash
export GARRISON_PRO_LICENSE=your-key-here
garrison-engine path/to/contract.sol --rag --report html
```

Or add to `garrison.toml`:
```toml
[license]
key = "your-key-here"
```

Get your license at [garrisonsec.io/pricing](https://garrisonsec.io/pricing).

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
garrison-engine --target ./contracts --config garrison-pr.toml

# Full audit with HTML report
garrison-engine --target ./contracts --config garrison-audit.toml --report --project-name "MyDeFi"

# Bug bounty mode (max coverage)
garrison-engine --target ./contracts --config garrison-bounty.toml --medusa

# Alternative: Use python directly
python orchestrator.py --target ./contracts --config garrison-pr.toml
```

**Output:**
- `ACTION_PLAN_*.md` - Technical findings summary
- `audit_report_*.html` - Client-ready report with risk scoring
- `audit_report_*.md` - GitHub-friendly Markdown

---

## 🎯 **What You Get**

### **21 Integrated Analyzers**
1. **Heuristic Scanner** - 34 vulnerability patterns (reentrancy, oracle issues, access control)
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
15. **AI Audit Copilot** - RAG-based knowledge retrieval with LLM integration
16. **Attack Path Visualizer** - Interactive D3.js cross-contract attack graphs
17. **Time-Travel Scanner** - Git-based historical vulnerability tracking
18. **Anchor IDL Validator** - Solana IDL constraint and CPI flow analysis
19. **CI/CD Pipeline Generator** - Multi-platform security pipeline generation
20. **Enhanced Exploit Generator** - Pattern-to-template exploit PoC generation
21. **Protocol Fingerprint Scanner** - Protocol similarity and inherited vulnerability detection

### **Professional Reports**
- **Risk Scoring** (0-100) based on severity distribution
- **Pass/Fail Status** (auto-fail on CRITICAL or >3 HIGH findings)
- **Remediation Steps** with CWE mappings and references
- **Code Snippets** with exact file:line locations
- **HTML + Markdown** formats for clients and GitHub

### **Noise-Free Results**
- **Configurable suppressions** via `garrison.toml`
- **Per-rule severity overrides** (e.g., downgrade timestamp usage for timelocks)
- **Expiry-based accepted risks** ("This is safe until 2026-12-31")
- **File/line-specific suppressions** (suppress specific occurrences, not all)

### **3 Execution Profiles**

**Audit Mode** (`garrison-audit.toml`)
- Maximum thoroughness for client deliverables
- All analyzers enabled, deep fuzzing (250K tests)
- Fail on MEDIUM+ severity
- Verbose reporting with all context

**PR Mode** (`garrison-pr.toml`)
- Fast blocker checks for CI/CD (< 2 minutes)
- Skip slow analyzers (Aderyn, fuzzing)
- Fail on HIGH+ only
- Common false positives pre-suppressed

**Bounty Hunter Mode** (`garrison-bounty.toml`)
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
garrison-engine --target ./client-project --config garrison-audit.toml --report --project-name "Client DeFi Protocol"

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
  garrison:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Install Garrison Engine
        run: pip install garrison-engine
      - name: Garrison PR Check
        run: |
          garrison-engine --target ./contracts --config garrison-pr.toml
```

### **Bug Bounty Hunting**
```powershell
# Max coverage mode
garrison-engine --target ./target-protocol --config garrison-bounty.toml --medusa --aderyn --report

# Generate exploit PoCs (requires OpenAI API key)
export OPENAI_API_KEY="sk-..."
python exploit_generator.py --finding-json findings.json --output exploits/

# Submit to Immunefi/Code4rena
```

### **Standalone Module Usage**

**Heuristic Scanner** (no dependencies):
```powershell
python heuristic_scanner.py ./contracts --config garrison-pr.toml
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

Garrison Engine uses TOML configuration files. Below are all available sections:

#### `[engine]` - Core Engine Settings
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | "Garrison Security Engine" | Engine name |
| `version` | string | "3.1.3" | Engine version |
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
| **Config File** | `garrison-pr.toml` | `garrison-audit.toml` | `garrison-bounty.toml` |
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
garrison-engine --target ./contracts --config garrison-audit.toml    # Full audit
garrison-engine --target ./contracts --config garrison-pr.toml       # Fast PR check
garrison-engine --target ./contracts --config garrison-bounty.toml   # Bug bounty

# Or create custom config
garrison-engine --target ./contracts --config my-custom.toml
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

## 🌐 **Web Application**

Try Garrison Engine online at **https://garrisonsec.io** — no installation required.

The web app provides:
- Upload and audit `.sol` or `.rs` files via browser
- View risk scores and severity breakdowns
- Download reports in HTML, Markdown, SARIF, or JSON
- Interactive attack graph visualization

---

## 🐳 **Docker Deployment**

### **Quick Start**
```bash
# Build image
docker build -t garrison-engine .

# Run audit
docker run --rm -v $(pwd):/scan garrison-engine --target /scan --config /scan/garrison-pr.toml

# Generate report
docker run --rm -v $(pwd):/scan garrison-engine --target /scan --report
```

### **Docker Compose**
```bash
docker-compose run --rm audit --target /scan --config /scan/garrison-audit.toml --report
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

## 🚀 **Innovative Features**

Garrison Engine includes 7 cutting-edge features that differentiate it from traditional security scanners:

### **1. AI Audit Copilot** 🤖

RAG-based knowledge retrieval system that provides intelligent vulnerability explanations and remediation guidance using local embeddings with optional OpenAI/Anthropic integration.

**Features:**
- Local vector database for audit report embeddings
- Context-aware vulnerability explanations
- Pattern-based fix suggestions
- Multi-LLM support (OpenAI GPT-4, Anthropic Claude)

**CLI Usage:**
```powershell
# Enable RAG enrichment during audit
garrison-engine --target ./contracts --rag

# Build/update RAG index from historical reports
garrison-engine --build-rag-index ./past-audits

# Use specific LLM provider
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
garrison-engine --target ./contracts --rag --llm-provider anthropic
```

**Configuration:**
```toml
[ai]
enabled = false
llm_provider = "openai"  # "openai" or "anthropic"
embedding_model = "text-embedding-3-small"
context_window = 4000
rag_top_k = 5
local_embeddings = true
embedding_cache_dir = "./.garrison/embeddings"
```

---

### **2. Attack Path Visualizer** 🕸️

Interactive D3.js force-directed graph showing cross-contract attack paths and vulnerability chains. Reveals multi-step exploits that individual checks miss.

**Features:**
- Cross-contract interaction tracing
- Multi-step attack chain visualization
- Standalone HTML output with interactive controls
- Export to Mermaid/PlantUML

**CLI Usage:**
```powershell
# Generate attack graph as HTML
garrison-engine --target ./contracts --format attack-graph

# Output to specific file
garrison-engine --target ./contracts --format attack-graph --output attack_paths.html
```

**Configuration:**
```toml
[visualization]
enabled = true
attack_graph = true
output_format = "html"  # "html", "mermaid", "dot"
max_nodes = 100
cluster_by_severity = true
include_safe_paths = false
```

---

### **3. Time-Travel Scanner** ⏰

Git-based historical vulnerability tracking that scans commit history to find when vulnerabilities were introduced and fixed.

**Features:**
- Scan entire git history for vulnerability introduction
- Track security debt accumulation over time
- Identify high-risk commits and contributors
- Generate vulnerability lineage reports

**CLI Usage:**
```powershell
# Scan last 50 commits
garrison-engine --target ./contracts --history --commits 50

# Scan since specific date
garrison-engine --target ./contracts --history --since "2025-01-01"

# Full history scan with blame attribution
garrison-engine --target ./contracts --history --blame
```

**Configuration:**
```toml
[history]
enabled = false
max_commits = 100
since_date = ""
blame_attribution = true
ignore_merge_commits = true
incremental_scan = true
storage_path = "./.garrison/history"
```

---

### **4. Anchor IDL Validator** ⚓

Dedicated Anchor IDL JSON parser for Solana programs. Validates constraints, traces CPI flows, and generates account permission matrices.

**Features:**
- IDL constraint validation
- Cross-program invocation (CPI) flow tracing
- Account permission matrix generation
- Anchor-specific security patterns (35+ rules)

**CLI Usage:**
```powershell
# Validate IDL file
python idl_validator.py ./target/idl/my_program.json

# Full Solana analysis with IDL validation
garrison-engine --target ./programs --solana --idl-path ./target/idl
```

**Configuration:**
```toml
[chains.solana]
enabled = false
project_root = "./programs"
idl_path = "./target/idl"

[chains.solana.idl]
validate_constraints = true
trace_cpi_flows = true
generate_permission_matrix = true
check_account_initialization = true
strict_signer_validation = true
```

---

### **5. CI/CD Pipeline Generator** 🔄

Dynamic pipeline generation for GitHub Actions, GitLab CI, Azure DevOps, and Jenkins. Generates production-ready security pipelines with PR comments and gate conditions.

**Features:**
- Multi-platform pipeline templates
- PR comment integration
- SARIF upload configuration
- Slack/Discord notifications
- Customizable gate conditions

**CLI Usage:**
```powershell
# Generate GitHub Actions workflow
garrison-generate-pipeline --platform github --output .github/workflows/

# Generate GitLab CI config
garrison-generate-pipeline --platform gitlab --output .gitlab-ci.yml

# Generate Azure DevOps pipeline
garrison-generate-pipeline --platform azure --output azure-pipelines.yml

# Generate Jenkinsfile
garrison-generate-pipeline --platform jenkins --output Jenkinsfile
```

**Configuration:**
```toml
[ci.generator]
enabled = true
platform = "github"  # "github", "gitlab", "azure", "jenkins"
pr_comments = true
sarif_upload = true
slack_webhook = ""
discord_webhook = ""
fail_threshold = "HIGH"
```

---

### **6. Enhanced Exploit Generator** 💥

Pattern-to-template mapping system that generates working Foundry exploit test cases with contract state inference and assertion oracles.

**Features:**
- Pattern-to-template vulnerability mapping
- Contract state inference
- Assertion oracle generation
- Batch exploit generation
- Output validation
- Multi-LLM support
- 6 Foundry exploit templates included

**CLI Usage:**
```powershell
# Generate exploit from finding
python exploit_generator.py --finding-json findings.json --output exploits/

# Batch generate for all HIGH/CRITICAL findings
python exploit_generator.py --finding-json findings.json --severity HIGH,CRITICAL --batch

# Use specific template
python exploit_generator.py --rule-id REENTRANCY --template reentrancy.sol --output test/
```

**Configuration:**
```toml
[exploit_generation]
enabled = false
llm_provider = "openai"
templates_dir = "./exploit_templates"
output_dir = "./test/exploits"
validate_output = true
max_attempts = 3
include_setup = true
batch_mode = false
```

**Included Templates:**
- `reentrancy.sol` - Reentrancy attack PoC
- `flash_loan.sol` - Flash loan manipulation
- `oracle_manipulation.sol` - Price oracle attacks
- `access_control.sol` - Privilege escalation
- `integer_overflow.sol` - Arithmetic exploits
- `front_running.sol` - MEV/sandwich attacks

---

### **7. Protocol Fingerprint Scanner** 🔍

Identifies which known protocol a contract resembles (Uniswap, Compound, Aave, etc.) and reports inherited vulnerabilities from upstream code.

**Features:**
- Protocol fingerprint database (Uniswap V2/V3, Compound, Aave, OpenZeppelin)
- AST-level similarity comparison
- Inherited vulnerability detection
- Fork genealogy analysis

**CLI Usage:**
```powershell
# Fingerprint contracts against known protocols
garrison-engine --target ./contracts --fingerprint

# Detailed similarity report
garrison-engine --target ./contracts --fingerprint --verbose
```

**Configuration:**
```toml
[fingerprint]
enabled = false
database_path = "./data/protocol_fingerprints.json"
similarity_threshold = 0.75
include_forks = true
check_known_vulnerabilities = true
report_inherited_risks = true
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
garrison-engine/
│
├── gui.py                      # Interactive Tkinter interface
├── orchestrator.py             # CLI master pipeline + Markdown reports
├── threat_intel.py             # Unified launcher (auto-detects EVM vs Solana)
│
├── knowledge_fetcher.py        # EVM threat intel (C4 + Immunefi + Solodit)
├── solana_intel.py             # Solana threat intel (Neodyme + Sec3 + OtterSec)
│
├── heuristic_scanner.py        # Pattern-based vulnerability detection (34 rules)
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
- **Solana support** — Available with 35 security rules and IDL validation
- **Watchtower** - Provides Forta templates; manual deployment required

---

## 📚 **Documentation**

- **[Getting Started](docs/GETTING_STARTED.md)** - Installation and first audit
- **[CLI Reference](docs/CLI_REFERENCE.md)** - All commands and flags
- **[Configuration](docs/CONFIGURATION.md)** - Full garrison.toml reference
- **[Web App Guide](docs/WEB_APP_GUIDE.md)** - Web UI features and API
- **[Deployment](docs/DEPLOYMENT.md)** - Production server setup

### **Module Details**
See the source code for detailed module documentation.

---

## 📝 **Logging Configuration**

Garrison Engine uses a centralized logging system via `logger.py`:

### **Log Levels**
Set via `GARRISON_LOG_LEVEL` environment variable:
- `DEBUG` - Detailed debugging information
- `INFO` - General operational information
- `WARNING` - Warning messages for potential issues
- `ERROR` - Error messages
- `CRITICAL` - Critical errors that may prevent operation

### **Log Formats**
Set via `GARRISON_LOG_FORMAT` environment variable:
- `text` - Human-readable colored output (default)
- `json` - Structured JSON lines for machine parsing

### **File Logging**
Set `GARRISON_LOG_FILE` to enable logging to a file:
```bash
export GARRISON_LOG_FILE=/var/log/garrison.log
python orchestrator.py --target ./contracts
```

---

## 📊 **SARIF Report Support**

Garrison Engine supports SARIF 2.1.0 (Static Analysis Results Interchange Format) for integration with GitHub Advanced Security and other tools.

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
- name: Install Garrison Engine
  run: pip install garrison-engine

- name: Run Garrison Scan
  run: |
    garrison-engine --target ./contracts --report
    python report_generator.py --format sarif --output garrison-results

- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: garrison-results.sarif
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
- Structured error reporting via `GarrisonAPIError`

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
export GARRISON_LOG_LEVEL=DEBUG  # See detailed retry attempts

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

- **Community features:** MIT License (see [LICENSE](LICENSE))
- **Pro features:** Commercial License (see [LICENSE-PRO](LICENSE-PRO))

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

Garrison Engine supports the following environment variables for configuration:

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `GARRISON_LOG_LEVEL` | Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL) | INFO | No |
| `GARRISON_LOG_FORMAT` | Output format ("text" or "json") | text | No |
| `GARRISON_LOG_FILE` | Optional file path for log output | (none) | No |
| `OPENAI_API_KEY` | OpenAI API key for GPT-4 exploit generation | (none) | For AI features |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude exploit generation | (none) | For AI features |

### Usage Examples

```bash
# Debug logging to file
export GARRISON_LOG_LEVEL=DEBUG
export GARRISON_LOG_FILE=/var/log/garrison.log
garrison-engine --target ./contracts

# JSON format for structured logging
export GARRISON_LOG_FORMAT=json
garrison-engine --target ./contracts 2>&1 | jq

# OpenAI for exploit generation
export OPENAI_API_KEY="sk-..."
python exploit_generator.py --finding-json findings.json
```

---

## 📧 **Support**

**Professional Audits:**
- CyberShield Austin
- Twitter: [@defiauditccie](https://twitter.com/defiauditccie)
- Website: [garrisonsec.io](https://garrisonsec.io)

**GitHub:**
- Issues: [github.com/RunTimeAdmin/garrison-engine/issues](https://github.com/RunTimeAdmin/garrison-engine/issues)

---

**Version:** 3.1.3  
**Last Updated:** April 20, 2026  
**License:** MIT  
**Chains:** EVM, Solana  
**Analyzers:** 21  
**Patterns:** 34 EVM + 35 Solana  
**Profiles:** 3  
**Innovative Features:** 7  

---

**⭐ If this helped you find bugs, please star the repo!**
