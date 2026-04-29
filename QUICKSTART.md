# Counterscarp Engine — Quick Start Guide

> **Version 5.1.0** | Smart contract security auditing for EVM + Solana

---

## Table of Contents

1. [Installation](#installation)
2. [External Tool Dependencies](#external-tool-dependencies)
3. [Quick Scan](#quick-scan)
4. [Local GUI Mode](#local-gui-mode)
5. [Configuration](#configuration)
6. [Report Formats](#report-formats)
7. [CI/CD Integration](#cicd-integration)
8. [Execution Profiles](#execution-profiles)
9. [Advanced Features](#advanced-features)
10. [Offline / Air-Gapped Setup](#offline--air-gapped-setup)
11. [License Tiers](#license-tiers)
12. [Web Application Authentication](#web-application-authentication)
13. [Environment Variables](#environment-variables)
14. [Updating](#updating)
15. [Troubleshooting](#troubleshooting)

---

## Installation

### Basic (CLI scanner — no extra dependencies)

```bash
pip install counterscarp-engine
```

Requires Python 3.10+. Includes heuristic scanning, Markdown/JSON reports, and CLI usage.

### With web interface

```bash
pip install "counterscarp-engine[web]"
```

Adds FastAPI + Uvicorn server, Jinja2 templates, Stripe integration, and file upload support.

### With PDF reports (Pro)

```bash
pip install "counterscarp-engine[pdf]"
```

Adds `xhtml2pdf` for printable PDF audit documents (pure Python, no system deps).

### With AI / RAG features

```bash
pip install "counterscarp-engine[ai,advanced]"
```

Adds `sentence-transformers`, `numpy`, and `openai` for local vector embeddings and LLM analysis.

### Full installation

```bash
pip install "counterscarp-engine[web,pdf,ai,advanced]"
```

### Development / testing

```bash
pip install "counterscarp-engine[dev]"
```

Adds `pytest`, `pytest-cov`, `mypy`, `pytest-benchmark`.

### Docker

The Docker image bundles the complete 21-analyzer stack including Python 3.12, Slither, Mythril, Foundry, Aderyn, Medusa, solc-select, and all required dependencies (~1.5 GB).

#### Build from source (primary)

```bash
# Build the image from the repository root
docker build -t counterscarp-engine:5.1.0 .

# Run a full audit with report persistence (recommended)
docker run --rm \
  -v /path/to/contracts:/scan \
  -v /path/to/reports:/output \
  counterscarp-engine:5.1.0 \
  --target /scan --output-dir /output --report
```

> **`--output-dir /output`** writes all reports to the host-mounted `/output` directory instead of the engine's internal `reports/` folder. Without this flag, reports are written inside the container and lost when it exits (`--rm`).

#### Official registry image (if available)

```bash
# If using the official registry image:
docker pull counterscarp-engine:5.1.0

docker run --rm \
  -v /path/to/contracts:/scan \
  -v /path/to/reports:/output \
  counterscarp-engine:5.1.0 \
  --target /scan --output-dir /output --report
```

#### docker-compose services

The project's `docker-compose.yml` defines four pre-configured services with resource limits (4 CPUs, 4 GB RAM) already set:

| Service | Description |
|---------|-------------|
| `counterscarp` | Main audit service — full 21-analyzer stack |
| `doctor` | Diagnostics / dependency health check |
| `heuristic` | Heuristic-only scan (no external tools required) |
| `symbolic` | Mythril symbolic execution only |

```bash
# Run a full audit
docker compose run --rm counterscarp scan /scan/MyContract.sol

# Run diagnostics (verify all tools are installed and healthy)
docker compose run --rm doctor

# Run heuristic-only analysis (fastest, no external tools needed)
docker compose run --rm heuristic scan /scan/MyContract.sol

# Run symbolic execution only
docker compose run --rm symbolic scan /scan/MyContract.sol
```

Volume mounts `/scan` (source input) and `/output` (report output) are pre-configured in the compose file.

### Optional external tools

These are not required for basic scanning but unlock additional analyzers:

```bash
# Slither — Trail of Bits static analyzer
pip install slither-analyzer
pip install solc-select && solc-select install 0.8.28 && solc-select use 0.8.28

# Aderyn — Cyfrin static analyzer (Linux/macOS only)
# curl --proto '=https' --tlsv1.2 -LsSf \
#   https://github.com/cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-installer.sh | sh

# Medusa — coverage-guided fuzzing (requires Go ≥ 1.21)
# Use root module path — do NOT add /cmd/medusa suffix
go install github.com/crytic/medusa@latest

# Mythril — symbolic execution (requires pipx or pip)
pip install mythril

# Foundry — forge/anvil for fuzzing and compilation
# macOS/Linux: curl -L https://foundry.paradigm.xyz | bash && foundryup
# Windows: download from https://github.com/foundry-rs/foundry/releases
forge --version
```

> See the [External Tool Dependencies](#external-tool-dependencies) section for full per-platform install instructions, minimum version requirements, and Windows-specific notes.

### Verify installation

```bash
counterscarp-engine --help
counterscarp --help          # short alias
```

---

## External Tool Dependencies

Counterscarp Engine supports a 21-analyzer stack. The core engine runs out of the box with just Python, but unlocking the full suite requires the following external binaries.

> **Graceful degradation:** All optional tools degrade gracefully. If a binary is not found on `PATH`, the engine emits a warning and skips that analyzer — your scan still completes with the remaining analyzers.

Run `counterscarp --doctor` at any time to check which tools are installed and their versions.

### Quick Reference

| Tool | Required? | Activates | Install Method |
|------|:---------:|-----------|----------------|
| **Slither** | Core | Static analysis (always runs) | `pip install slither-analyzer` |
| **Forge / Foundry** | Core | Fuzzing & compilation | `foundryup` (Linux/macOS) / GitHub release (Windows) |
| **solc** | Core | Solidity compilation | `pip install solc-select` |
| **Mythril** | Optional | Symbolic execution (`--symbolic`) | `pip install mythril` |
| **Medusa** | Optional | Coverage-guided fuzzing (`--medusa`) | `go install github.com/crytic/medusa@latest` |
| **Aderyn** | Optional | Cyfrin static analysis (`--aderyn`) | Installer script (Linux/macOS only) |

---

### 1. Slither — Static Analysis (core, always runs)

Minimum version: **0.11.5**

```bash
# All platforms
pip install slither-analyzer

# Verify
slither --version
```

---

### 2. Forge / Foundry — Fuzzing & Build (core)

Minimum version: **1.0.0**

**Linux / macOS:**

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Verify
forge --version
```

**Windows:**

Download the latest release ZIP from https://github.com/foundry-rs/foundry/releases, extract the `forge.exe` / `cast.exe` / `anvil.exe` binaries, and add the directory to your `PATH`.

Alternatively, use `foundryup` inside **WSL** (Windows Subsystem for Linux):

```bash
# Inside WSL
curl -L https://foundry.paradigm.xyz | bash && foundryup
```

---

### 3. solc — Solidity Compiler (core)

Recommended install via `solc-select` (manages multiple compiler versions):

```bash
# All platforms
pip install solc-select
solc-select install 0.8.28
solc-select use 0.8.28

# Verify
solc --version
```

Alternatively, download prebuilt binaries directly from https://github.com/ethereum/solidity/releases.

---

### 4. Mythril — Symbolic Execution (optional — `--symbolic` flag)

Minimum version: **0.24.8**

```bash
# Linux / macOS
pip install mythril

# Verify
myth version
```

> **Windows note:** Mythril requires a C compiler. Install **Visual C++ Build Tools 14.0+** (via Visual Studio Installer or `winget install Microsoft.VisualStudio.2022.BuildTools`) before running `pip install mythril`. Linux/macOS is recommended for production symbolic execution.

---

### 5. Medusa — Coverage-Guided Fuzzing (optional — `--medusa` flag)

Minimum version: **0.1.8**

Requires **Go ≥ 1.21**.

```bash
# All platforms (requires Go installed)
go install github.com/crytic/medusa@latest
```

> **Important:** Use the root module path `github.com/crytic/medusa@latest` — **not** `github.com/crytic/medusa/cmd/medusa@latest`. The `/cmd/medusa` suffix causes a module resolution error.

After installation, ensure `~/go/bin` (Linux/macOS) or `%USERPROFILE%\go\bin` (Windows) is on your `PATH`:

```bash
# Linux / macOS — add to ~/.bashrc or ~/.zshrc
export PATH="$HOME/go/bin:$PATH"

# Windows PowerShell — add to your profile
$env:PATH += ";$env:USERPROFILE\go\bin"

# Verify
medusa --version
```

---

### 6. Aderyn — Cyfrin Static Analysis (optional — `--aderyn` flag)

Minimum version: **0.6.2**

> **Platform availability:** No Windows binary is currently available. Aderyn is supported on Linux and macOS only.

**Linux / macOS:**

```bash
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-installer.sh | sh

# Verify
aderyn --version
```

> The `--proto '=https' --tlsv1.2` flags are required for security and TLS compatibility. Do not omit them.

---

### Checking your environment

```bash
# Run the built-in environment doctor
counterscarp --doctor

# Or run the preflight check before a scan
counterscarp-engine --preflight --target ./contracts
```

Both commands report which tools are found, their detected versions, and whether they meet minimum version requirements.

---

## Quick Scan

### CLI — scan a contracts directory

```bash
counterscarp-engine --target ./contracts --report
```

### Scan a single Solidity file

```bash
counterscarp-engine --target ./contracts/Vault.sol --report
```

### With a specific output format

```bash
counterscarp-engine --target ./contracts --report --format html
counterscarp-engine --target ./contracts --report --format sarif
counterscarp-engine --target ./contracts --report --format json
```

### With a named project

```bash
counterscarp-engine --target ./contracts --report --project-name "MyDeFi Protocol"
```

### With a custom config profile

```bash
counterscarp-engine --target ./contracts --config counterscarp-pr.toml      # fast PR check
counterscarp-engine --target ./contracts --config counterscarp-audit.toml   # full audit
counterscarp-engine --target ./contracts --config counterscarp-bounty.toml  # bug bounty
```

### Resume an interrupted scan

```bash
counterscarp-engine --resume <SESSION_ID>
```

Session IDs are printed at scan start and stored in `.counterscarp/`.

### Run preflight tool check

```bash
counterscarp-engine --preflight --target ./contracts
```

Verifies that Slither, Foundry, Mythril, and Medusa are available before scanning.

### Filter by severity or confidence

```bash
counterscarp-engine --target ./contracts --min-severity HIGH
counterscarp-engine --target ./contracts --min-confidence 7
```

---

## Local GUI Mode

Launch the built-in web interface for a visual scanning experience:

```bash
counterscarp --gui
```

This starts a local FastAPI/Uvicorn server at `http://localhost:8000` with:
- Drag-and-drop contract upload
- Visual scan configuration
- Interactive results dashboard with severity breakdown and risk score
- Report downloads (HTML, Markdown, SARIF, JSON)
- License key management via Settings page
- Attack graph visualization

No external server required — everything runs on your machine.

> **Requires the web extras:** `pip install "counterscarp-engine[web]"`

---

## Configuration

### Auto-discovery

Counterscarp Engine automatically searches for `counterscarp.toml` starting from the target directory, walking up to 5 parent directories. If no config is found, safe defaults are used.

```bash
# Explicit config path
counterscarp-engine --target ./contracts --config /path/to/counterscarp.toml
```

### counterscarp.toml Reference

Below are all supported sections. Copy and paste the sections you need.

#### `[engine]` — Core Settings

```toml
[engine]
name = "Counterscarp Security Engine"
version = "5.0.0"

# Minimum severity that causes a non-zero exit code (CI gate)
# Values: CRITICAL, HIGH, MEDIUM, LOW, INFO
fail_on_severity = "HIGH"

# Stop scanning after this many findings (0 = unlimited)
max_findings = 0
```

#### `[heuristics]` — Pattern-Based Scanner (34 rules)

```toml
[heuristics]
enabled = true
min_confidence = 0       # 1-10; 0 = include all findings
min_severity = "INFO"    # CRITICAL, HIGH, MEDIUM, LOW, INFO

# Downgrade or upgrade individual rule severities
[heuristics.severity_overrides]
BLOCK_TIMESTAMP_RANDOMNESS = "LOW"   # safe for timelocks

# Disable noisy rules for this project
[heuristics.disabled_rules]
HARDCODED_ADDRESS = true             # expected for oracle contracts
DIVIDE_BEFORE_MULTIPLY = true        # project uses safe precision patterns
```

#### `[[suppressions]]` — False Positive Management

```toml
# Suppress by rule + file + line
[[suppressions]]
rule_id = "DELEGATECALL_IN_LOOP"
file = "contracts/Proxy.sol"
line = 88
reason = "Proxy pattern — delegatecall is safe via strict access control"
expires = "2027-01-01"   # optional: suppression auto-expires

# Suppress all occurrences of a rule in one file
[[suppressions]]
rule_id = "HARDCODED_ADDRESS"
file = "contracts/Oracle.sol"
reason = "Oracle address is intentionally hardcoded per deployment spec"

# Suppress a rule project-wide
[[suppressions]]
rule_id = "EMERGENCY_WITHDRAW_PUBLIC"
reason = "All emergency functions have onlyOwner — false positive"
```

#### `[static_analysis]` — Slither + Aderyn

```toml
[static_analysis.slither]
enabled = true
exclude_detectors = "solc-version,naming-convention"
include_impact = "High,Medium"

[static_analysis.aderyn]
enabled = false     # opt-in
scope = ""          # limit to specific paths
```

#### `[fuzzing]` — Foundry + Medusa

```toml
[fuzzing.foundry]
enabled = false
runs = 10000
max_test_rejects = 100000

[fuzzing.medusa]
enabled = false
test_limit = 100000
timeout = 300    # seconds
workers = 10
```

#### `[reporting]` — Output Format and Sections

```toml
[reporting]
# Options: markdown, json, sarif, html, pdf
format = "markdown"
verbosity = "standard"    # minimal, standard, verbose
group_by = "severity"     # severity, file, rule

[reporting.sections]
executive_summary = true
supply_chain = true
static_analysis = true
heuristic_scan = true
fuzzing = false            # opt-in
threat_intel = false       # opt-in
access_matrix = true
```

#### `[ci]` — CI/CD Settings and Path Exclusions

```toml
[ci]
fail_on_findings = true
post_pr_comment = true
upload_sarif = false

# Glob patterns to skip entirely
exclude_paths = [
    "test/**",
    "script/**",
    "node_modules/**",
    "lib/**",
    ".git/**",
]
```

#### `[threat_intel]` — Threat Intelligence APIs

```toml
[threat_intel]
c4_timeout = 10
immunefi_timeout = 10
api_rate_limit = 5
offline_mode = false
bundled_db_path = "data/threat_intel_db.json"
```

#### `[ai]` — RAG + LLM Analysis

```toml
[ai]
embedding_backend = "local"   # local, openai
llm_backend = "none"          # none, openai, ollama
llm_model = "gpt-4o-mini"

# Ollama (local LLM)
ollama_url = "http://localhost:11434"

rag_index_path = ".counterscarp/rag_index.json"
top_k = 5
auto_enrich = false
llm_enrichment = false
```

#### `[license]` — Pro License Key

```toml
[license]
# Set here or via COUNTERSCARP_PRO_LICENSE environment variable
key = "your-license-key-here"
```

### Path exclusions

Exclude directories to reduce noise and speed up scans:

```toml
[ci]
exclude_paths = [
    "test/**",
    "tests/**",
    "script/**",
    "scripts/**",
    "lib/**",
    "node_modules/**",
    "mocks/**",
    ".git/**",
]
```

### Rule configuration

Disable, downgrade, or suppress rules for your project:

```toml
# Disable individual rules
[heuristics.disabled_rules]
BLOCK_TIMESTAMP_RANDOMNESS = true   # project uses timestamp for vesting, not randomness
TX_ORIGIN_USAGE = true              # legacy compatibility layer

# Override severity levels
[heuristics.severity_overrides]
MISSING_ZERO_ADDRESS_CHECK = "LOW"  # contract validates in constructor

# Suppress a specific line as accepted risk
[[suppressions]]
rule_id = "UNCHECKED_EXTERNAL_CALL"
file = "contracts/Bridge.sol"
line = 204
reason = "Return value intentionally ignored — token transfer reverts on failure"
expires = "2026-12-31"
```

### Inline Comment Suppressions

Suppress specific rules directly in your Solidity source code:

```solidity
// counterscarp-suppress: TX_ORIGIN_USAGE reason: Used intentionally for gas relay pattern
function relay() external {
    require(tx.origin == msg.sender);
}
```

Format: `// counterscarp-suppress: RULE_ID [reason: explanation]`

Inline suppressions apply only to the finding on the immediately following line. They do not require changes to `counterscarp.toml` and are useful for one-off accepted risks within the contract source.

### Common configuration scenarios

**DeFi project with oracle integration:**

```toml
[heuristics.disabled_rules]
HARDCODED_ADDRESS = true
BLOCK_TIMESTAMP_RANDOMNESS = true

[chains.evm]
trusted_contracts = [
    "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419",  # Chainlink ETH/USD
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
]
```

**Upgradeable proxy with known patterns:**

```toml
[[suppressions]]
rule_id = "DELEGATECALL_IN_LOOP"
file = "contracts/Proxy.sol"
reason = "Proxy pattern — safe via access control"

[upgrade_diff]
old_implementation_path = "contracts/old/Implementation.sol"
new_implementation_path = "contracts/Implementation.sol"
```

**Strict audit-ready mode:**

```toml
[engine]
fail_on_severity = "MEDIUM"

[reporting]
verbosity = "verbose"
[reporting.sections]
fuzzing = true
threat_intel = true
```

---

## Report Formats

### Free Tier

| Format | Flag | Notes |
|--------|------|-------|
| **Markdown** | `--format markdown` (default) | GitHub-friendly, human-readable |
| **JSON** | `--format json` | Machine-parseable findings array |

### Pro Tier (requires license key)

| Format | Flag | Notes |
|--------|------|-------|
| **HTML** | `--format html` | Styled report with severity badges, code snippets |
| **SARIF** | `--format sarif` | SARIF 2.1.0 for GitHub Advanced Security |
| **PDF** | `--format pdf` | Printable document; requires `pip install "counterscarp-engine[pdf]"` |

### Generating multiple formats

```bash
# HTML + Markdown
counterscarp-engine --target ./contracts --report --format html

# SARIF for GitHub Code Scanning
counterscarp-engine --target ./contracts --report --format sarif
```

Report output files are created in the working directory with timestamped filenames:
- `audit_report_YYYYMMDD_HHMMSS.html`
- `audit_report_YYYYMMDD_HHMMSS.md`
- `audit_report_YYYYMMDD_HHMMSS.sarif`

### Per-Scan Report Directories

Each scan produces its own isolated output folder so that successive scans never overwrite previous results:

```
reports/{ProjectName}_{YYYY-MM-DD}_{session}/
├── audit_report.md
├── audit_report.html
├── ACTION_PLAN.md
├── scan.log
└── exploits/
```

- `{ProjectName}` is taken from `--project-name` or inferred from the target directory.
- `{YYYY-MM-DD}` is the scan date.
- `{session}` is a short unique identifier for the run.

This means you can run multiple audits against the same project on the same day and each set of results is preserved independently.

---

## CI/CD Integration

### GitHub Actions — minimal workflow

```yaml
# .github/workflows/counterscarp.yml
name: Counterscarp Security Audit

on:
  pull_request:
    branches: [main, develop]
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  counterscarp-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install Counterscarp Engine
        run: pip install counterscarp-engine

      - name: Install Slither
        run: |
          pip install slither-analyzer
          pip install solc-select
          solc-select install 0.8.19 && solc-select use 0.8.19

      - name: Run Counterscarp PR Check
        run: counterscarp-engine --target ./contracts --config counterscarp-pr.toml
        env:
          COUNTERSCARP_PRO_LICENSE: ${{ secrets.COUNTERSCARP_PRO_LICENSE }}
```

### GitHub Actions — with SARIF upload

```yaml
      - name: Run Counterscarp Scan (SARIF)
        run: counterscarp-engine --target ./contracts --report --format sarif
        env:
          COUNTERSCARP_PRO_LICENSE: ${{ secrets.COUNTERSCARP_PRO_LICENSE }}

      - name: Upload SARIF to GitHub Security tab
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: audit_report_*.sarif
```

### Generate a pipeline automatically

```bash
# GitHub Actions
counterscarp-generate-pipeline --platform github --output .github/workflows/

# GitLab CI
counterscarp-generate-pipeline --platform gitlab --output .gitlab-ci.yml

# Azure DevOps
counterscarp-generate-pipeline --platform azure --output azure-pipelines.yml

# Jenkins
counterscarp-generate-pipeline --platform jenkins --output Jenkinsfile
```

Or via the main CLI:

```bash
counterscarp-engine --generate-pipeline github
```

Configure the generator in `counterscarp.toml`:

```toml
[ci.generator]
platform = "github"          # github, gitlab, azure, jenkins
triggers = ["push", "pull_request"]
notifications = []           # "slack", "discord"
```

### GitLab CI — minimal example

```yaml
# .gitlab-ci.yml
counterscarp-security:
  image: python:3.11
  stage: test
  script:
    - pip install counterscarp-engine slither-analyzer
    - solc-select install 0.8.19 && solc-select use 0.8.19
    - counterscarp-engine --target ./contracts --config counterscarp-pr.toml
  only:
    - merge_requests
    - main
```

### SARIF → GitHub Security Tab

To surface findings directly in the GitHub Security tab:

1. Generate SARIF: `counterscarp-engine --target ./contracts --report --format sarif`
2. Upload via `github/codeql-action/upload-sarif@v3` (see workflow above)
3. View findings under **Security → Code scanning alerts**

Requires a Pro license key for SARIF output.

---

## Execution Profiles

Three pre-built `*.toml` profiles ship with Counterscarp Engine:

| Profile | Config File | Scan Time | Fail Threshold | Use Case |
|---------|-------------|-----------|----------------|----------|
| **PR Mode** | `counterscarp-pr.toml` | < 2 min | HIGH+ | Block bad PRs fast |
| **Audit Mode** | `counterscarp-audit.toml` | 10–30 min | MEDIUM+ | Client deliverables |
| **Bounty Mode** | `counterscarp-bounty.toml` | 1–2 hours | Never fails | Max exploit coverage |

```bash
counterscarp-engine --target ./contracts --config counterscarp-pr.toml
counterscarp-engine --target ./contracts --config counterscarp-audit.toml --report
counterscarp-engine --target ./contracts --config counterscarp-bounty.toml --medusa --aderyn --report
```

---

## Advanced Features

### Time-Travel Scanner (git history)

Scans commit history to find when vulnerabilities were introduced or fixed.

```bash
# Scan last 50 commits on main
counterscarp-engine --target ./contracts --history --commits 50 --branch main

# Scan since a specific date
counterscarp-engine --target ./contracts --history --since 2025-01-01

# Alias
counterscarp-engine --target ./contracts --time-travel
```

Configure in `counterscarp.toml`:

```toml
[history]
max_commits = 50
scan_branches = ["main"]
include_fixed = true
output_dir = "."
```

### AI Audit Copilot (RAG + LLM)

RAG-based knowledge retrieval enriches findings with context from past audits.

**How RAG enrichment works:** The `--rag` flag performs a vector similarity search over your indexed codebase (or a pre-built knowledge base of past audit reports). For each finding, the top-K most similar code patterns and remediation examples are retrieved and appended to the finding's context — giving you better explanations and fix suggestions without sending your source code to any external service.

```bash
# Enable RAG enrichment
counterscarp-engine --target ./contracts --rag

# Enable RAG + LLM analysis
counterscarp-engine --target ./contracts --rag --llm

# Build a vector index of your codebase for similarity search
counterscarp-engine --build-rag-index

# Use OpenAI as LLM backend
export OPENAI_API_KEY="sk-..."
counterscarp-engine --target ./contracts --rag --llm
```

**`--build-rag-index`** scans all `.sol` files in the project, computes local embeddings, and writes a vector index to `.counterscarp/rag_index.json`. Re-run this command whenever your codebase changes significantly. The index is used by `--rag` at scan time to find similar patterns.

**Model recommendations:**

| Option | Model | Cost | Privacy | Best For |
|--------|-------|------|---------|----------|
| **Local (recommended)** | Ollama + `deepseek-coder` | Free | Full — nothing leaves your machine | Air-gapped environments, confidential audits |
| **Cloud** | OpenAI `gpt-4o-mini` | ~$0.15 / 1M tokens | Only finding summaries sent (never source code) | Better accuracy, faster setup |

Configure in `counterscarp.toml`:

```toml
[ai]
embedding_backend = "local"
llm_backend = "openai"       # none, openai, ollama
llm_model = "gpt-4o-mini"
auto_enrich = false
llm_enrichment = false
```

### Protocol Fingerprint Scanner

Identifies which known protocol (Uniswap, Compound, Aave, etc.) a contract resembles and flags inherited vulnerabilities.

```bash
counterscarp-engine --target ./contracts --fingerprint
counterscarp-engine --target ./contracts --fingerprint --verbose
```

Configure in `counterscarp.toml`:

```toml
[fingerprint]
enabled = false
min_similarity = 0.7
database_path = "data/protocol_fingerprints.json"
include_risk_assessment = true
```

### Upgrade Diff Analysis

Detects storage collisions and removed access control in proxy upgrades.

```bash
counterscarp-engine --upgrade-old ./VaultV1.sol --upgrade-new ./VaultV2.sol
```

Configure in `counterscarp.toml`:

```toml
[upgrade_diff]
old_implementation_path = "contracts/old/Implementation.sol"
new_implementation_path = "contracts/Implementation.sol"

[upgrade_diff.ignore_patterns]
ignore_new_view_functions = true
ignore_comment_changes = true
```

### Exploit PoC Generator

Generates Foundry test exploits for detected findings using local templates (+ optional LLM enhancement).

**What it generates:** Foundry test files (`.t.sol`) that attempt to reproduce each detected vulnerability. For common rule categories (reentrancy, flash loan, oracle manipulation, access control, integer overflow, front-running), purpose-built templates are used. For other findings, a generic fallback template is applied.

**Pro tier required** — the Exploit PoC generator is available on Professional, Team, and Enterprise plans.

**Running the exploits:**

```bash
# Generate exploits alongside your scan report
counterscarp-engine --target ./contracts --report

# This creates an exploits/ directory with .t.sol files
# Run them with Foundry:
forge test --match-path "exploits/*.t.sol" -vvv
```

**Available templates:**

```bash
# Included templates: reentrancy, flash_loan, oracle_manipulation,
#                     access_control, integer_overflow, front_running
```

**Enable in `counterscarp.toml`:**

```toml
[exploit_generation]
auto_generate = true
min_severity = "HIGH"
validate_compilation = true
output_dir = "exploits/"
llm_backend = "none"       # none, openai, anthropic
template_dir = "exploit_templates/"
```

### Solana / Anchor Analysis

35 security rules for Rust/Anchor programs, plus IDL constraint validation and CPI flow tracing.

```bash
counterscarp-engine --solana-root ./programs
```

Configure in `counterscarp.toml`:

```toml
[chains.solana]
enabled = false
project_root = "./programs"

[chains.solana.idl]
idl_path = "target/idl"
validate_constraints = true
trace_cpi = true
```

### Attack Graph Visualization

Generates interactive D3.js HTML showing cross-contract attack paths.

```toml
[visualization]
enabled = false
include_source_analysis = true
trace_attack_paths = true
output_format = "html"   # html, json, both
max_path_depth = 10
```

### Plugin System

Drop custom analyzer plugins into `.counterscarp/plugins/`:

```toml
[plugins]
enabled = true
dirs = [".counterscarp/plugins"]
```

---

## Offline / Air-Gapped Setup

### Step 1 — Update signatures before going offline

```bash
counterscarp-engine --update-signatures
```

Downloads the latest threat intel databases from GitHub and stores them in `data/`.

### Step 2 — Or import from a pre-downloaded file

```bash
counterscarp-engine --update-from-file /path/to/threat_intel_db.json
```

### Step 3 — Configure for air-gapped use

```toml
[threat_intel]
offline_mode = true
bundled_db_path = "data/threat_intel_db.json"

[ai]
embedding_backend = "local"
llm_backend = "ollama"
llm_model = "deepseek-coder"
ollama_url = "http://localhost:11434"
```

### Local LLM with Ollama

1. Install Ollama: https://ollama.ai
2. Pull a code model:
   ```bash
   ollama pull deepseek-coder
   # or
   ollama pull codellama
   ```
3. Update `counterscarp.toml`:
   ```toml
   [ai]
   llm_backend = "ollama"
   llm_model = "deepseek-coder"
   ollama_url = "http://localhost:11434"
   ```
4. Run with LLM enrichment:
   ```bash
   counterscarp-engine --target ./contracts --rag --llm
   ```

---

## License Tiers

Counterscarp Engine ships as a single package. Pro features are gated by a license key.

| Feature | Community (Free) | Developer ($49/mo) | Professional ($199/mo) | Team ($399/mo) | Enterprise (Custom) |
|---------|:---:|:---:|:---:|:---:|:---:|
| Heuristic scanning (34 rules) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Markdown / JSON reports | ✅ | ✅ | ✅ | ✅ | ✅ |
| CLI usage | ✅ | ✅ | ✅ | ✅ | ✅ |
| Supply chain scanning | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTML / SARIF / PDF reports | — | ✅ | ✅ | ✅ | ✅ |
| Slither integration | — | ✅ | ✅ | ✅ | ✅ |
| Solana analyzer (35 rules) | — | ✅ | ✅ | ✅ | ✅ |
| Protocol fingerprinting | — | ✅ | ✅ | ✅ | ✅ |
| Web app access | — | 5 scans/mo | Unlimited | Unlimited | Unlimited |
| AI Copilot (RAG + LLM) | — | — | ✅ | ✅ | ✅ |
| Exploit PoC generator | — | — | ✅ | ✅ | ✅ |
| Time-travel git scanner | — | — | ✅ | ✅ | ✅ |
| Attack graph visualization | — | — | ✅ | ✅ | ✅ |
| Machine activations | — | 1 | 3 | 5 | Unlimited |
| Support | GitHub | Email | Priority (24 hr) | Dedicated | Dedicated + SLA |
| Custom integrations | — | — | — | — | ✅ |
| Dedicated account manager | — | — | — | — | ✅ |

> **Enterprise (SE-ENT-xxx):** Custom pricing, unlimited seats, unlimited activations, custom integrations, priority support, and a dedicated account manager. All Pro features included. Contact [contact@counterscarp.io](mailto:contact@counterscarp.io) for a quote.

Get your license at **https://counterscarp.io/pricing**

### Activating a Pro license

**Option A — environment variable (recommended for CI):**

```bash
export COUNTERSCARP_PRO_LICENSE=your-license-key-here
counterscarp-engine --target ./contracts --report --format html
```

**Option B — `counterscarp.toml`:**

```toml
[license]
key = "your-license-key-here"
```

**Option C — GitHub Actions secret:**

```yaml
env:
  COUNTERSCARP_PRO_LICENSE: ${{ secrets.COUNTERSCARP_PRO_LICENSE }}
```

---

## Web Application Authentication

The Counterscarp Engine web application supports user accounts for personalized license management and access control.

### Creating an Account

Visit [app.counterscarp.io](https://app.counterscarp.io) and choose one of:

- **Google Sign-In** — Click "Sign in with Google" for one-click authentication
- **Email Registration** — Create an account with your name, email, and password at `/auth/register`

### Automatic License Linking

When you purchase a Pro license through Stripe Checkout:

1. **If logged in** — Your license is automatically linked to your account. No manual key entry needed.
2. **If not logged in** — The checkout success page prompts you to log in or create an account. Once you register with the same email used for purchase, your license is automatically discovered and linked.
3. **Manual entry** — You can always enter a license key manually on the Settings page (`/settings`).

### Cross-Device Access

Your license is stored with your account. Log in from any device or browser and your Pro features activate automatically.

### Settings Page

Access `/settings` (requires login) to:

- View your current license tier and features
- Manually activate or remove a license key
- Configure API keys and scan settings

### Admin Dashboard

The admin endpoint at `/admin/users` (restricted to the configured `ADMIN_EMAIL`) displays:

- All registered users with email, name, and auth method
- License key (masked) and tier for each user
- Registration date and last login timestamp

### Session Secret (Production Required)

The web application signs session cookies using the `SESSION_SECRET` environment variable. If this variable is not set, the app falls back to an insecure hardcoded default and prints a warning at startup.

> **Production deployments must set `SESSION_SECRET`** — leaving it unset exposes session data to forgery.

Generate a secure value and export it before starting the server:

```bash
# Generate a cryptographically secure secret
python -c "import secrets; print(secrets.token_urlsafe(32))"

# Export for the current shell session
export SESSION_SECRET="<paste-generated-value-here>"

# Or add to your systemd environment file / .env
SESSION_SECRET=<paste-generated-value-here>
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `COUNTERSCARP_PRO_LICENSE` | Pro license key | — |
| `COUNTERSCARP_LOG_LEVEL` | Log verbosity: `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` | `INFO` |
| `COUNTERSCARP_LOG_FORMAT` | Output format: `text` or `json` | `text` |
| `COUNTERSCARP_LOG_FILE` | File path for log output | — |
| `OPENAI_API_KEY` | OpenAI API key for GPT-based LLM analysis | — |
| `ANTHROPIC_API_KEY` | Anthropic API key for Claude-based analysis | — |

### Examples

```bash
# Debug logging to a file
export COUNTERSCARP_LOG_LEVEL=DEBUG
export COUNTERSCARP_LOG_FILE=/var/log/counterscarp.log
counterscarp-engine --target ./contracts

# Structured JSON logs (pipe to jq)
export COUNTERSCARP_LOG_FORMAT=json
counterscarp-engine --target ./contracts 2>&1 | jq

# OpenAI for LLM-enriched findings
export OPENAI_API_KEY="sk-..."
counterscarp-engine --target ./contracts --rag --llm
```

---

## Updating

### Update threat intelligence signatures

```bash
counterscarp-engine --update-signatures
```

Fetches the latest vulnerability databases from GitHub. Safe to run in CI pre-scan.

### Update the engine

```bash
pip install --upgrade counterscarp-engine
```

### Check current version

```bash
counterscarp-engine --help   # version shown in header
python -c "import importlib.metadata; print(importlib.metadata.version('counterscarp-engine'))"
```

---

## Troubleshooting

### Slither not found

```bash
pip install slither-analyzer

# Verify
slither --version
```

### Solc version mismatch

```bash
pip install solc-select
solc-select install 0.8.19
solc-select use 0.8.19

# List installed versions
solc-select versions
```

### Aderyn not found

```bash
# Requires Rust
cargo install aderyn

# Or install via Foundry
foundryup
aderyn --version
```

### Medusa not found

```bash
# Requires Go ≥ 1.21
go install github.com/crytic/medusa@latest
```

### Docker permission errors (Linux)

```bash
# Add your user to the docker group
sudo usermod -aG docker $USER

# Or run with --user flag
docker run --rm --user $(id -u):$(id -g) -v $(pwd):/scan \
  counterscarp-engine:5.1.0 --target /scan --report
```

### OpenAI API key not set

```bash
export OPENAI_API_KEY="sk-..."

# Windows PowerShell
$env:OPENAI_API_KEY = "sk-..."
```

### RAG dependencies missing

```bash
pip install "counterscarp-engine[ai,advanced]"
```

### Web server fails to start

```bash
pip install "counterscarp-engine[web]"
```

### Config not found

Counterscarp Engine searches up to 5 parent directories for `counterscarp.toml`. To specify an explicit path:

```bash
counterscarp-engine --target ./contracts --config /path/to/counterscarp.toml
```

### Scan fails immediately with "target does not exist"

- Use an absolute path: `counterscarp-engine --target /full/path/to/contracts`
- If targeting a single file, it must end in `.sol`
- Check that the path exists: `ls ./contracts`

### False positives

Use suppressions to mark findings as accepted risks:

```toml
[[suppressions]]
rule_id = "BLOCK_TIMESTAMP_RANDOMNESS"
file = "contracts/Vesting.sol"
reason = "Timestamp used for vesting schedule, not randomness"
```

Or downgrade severity:

```toml
[heuristics.severity_overrides]
BLOCK_TIMESTAMP_RANDOMNESS = "LOW"
```

### Rate Limiting

The web API enforces per-endpoint rate limits. If you exceed a limit you will receive an **HTTP 429** response.

| Endpoint | Limit |
|----------|-------|
| License validation (`POST /api/license/validate`) | 10 req/min |
| License deactivation (`POST /api/license/deactivate`) | 5 req/min |
| Stripe webhooks (`POST /webhook/stripe`) | 30 req/min |

Wait for the current minute window to reset, then retry. In automated pipelines, add a back-off/retry loop around license validation calls.

---

## Complete CLI Reference

```
counterscarp-engine [OPTIONS]

Scan options:
  --target PATH            Path to project root or .sol file (required for scanning)
  --config PATH            Path to counterscarp.toml (auto-discovered if not set)
  --report                 Generate audit report
  --format FORMAT          Report format: markdown, json, sarif, html, pdf
  --project-name NAME      Project name for report header
  --resume SESSION_ID      Resume an interrupted scan

Analyzer flags:
  --aderyn                 Run Aderyn static analyzer
  --medusa                 Run Medusa coverage-guided fuzzing
  --symbolic               Run Mythril symbolic execution
  --fuzz-contract NAME     Foundry invariant test contract name
  --solana-root PATH       Solana/Anchor project root for Solana analysis
  --fingerprint            Run protocol fingerprint similarity scan
  --history / --time-travel  Run time-travel git history scan
  --commits N              Max commits for history mode (default: 50)
  --since DATE             Scan commits since date (ISO: 2025-01-01)
  --branch BRANCH          Branch for history scan (default: main)

Upgrade diff:
  --upgrade-old PATH       Path to old contract version
  --upgrade-new PATH       Path to new contract version

AI / RAG:
  --rag                    Enable RAG knowledge enrichment
  --llm                    Enable LLM-powered analysis
  --build-rag-index        Rebuild the RAG knowledge base index

Filtering:
  --min-severity LEVEL     Minimum severity: CRITICAL, HIGH, MEDIUM, LOW, INFO
  --min-confidence N       Minimum confidence score (1-10, default: 0 = all)

Operations:
  --update-signatures      Update threat intel databases from GitHub
  --update-from-file PATH  Import threat intel from a local JSON file
  --preflight              Check external tool versions before scanning
  --generate-pipeline PLATFORM  Generate CI pipeline: github, gitlab, azure, jenkins
```

---

## Further Reading

- **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** — Complete `counterscarp.toml` reference
- **[docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)** — All flags with examples
- **[docs/WEB_APP_GUIDE.md](docs/WEB_APP_GUIDE.md)** — Self-hosted web interface
- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** — Production server setup
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — Adding rules and integrations
- **Web app:** https://counterscarp.io
- **Pricing:** https://counterscarp.io/pricing
- **Issues:** https://github.com/RunTimeAdmin/counterscarp-engine/issues

---

*Counterscarp Engine v5.1.0 — EVM + Solana | 21 analyzers | 34 EVM + 35 Solana patterns*
