# CLI Reference

> **Installation:** `pip install counterscarp-engine` — See [Getting Started](GETTING_STARTED.md) for details.

## Table of Contents

- [Command Entry Points](#command-entry-points)
- [All Flags Reference](#all-flags-reference)
- [Execution Profiles](#execution-profiles)
- [Usage Examples](#usage-examples)
- [Output Directory Structure](#output-directory-structure)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)
- [Troubleshooting](#troubleshooting)

---

## Command Entry Points

Counterscarp Engine provides three CLI commands:

| Command | Entry Point | Description |
|---------|-------------|-------------|
| `counterscarp-engine` | `orchestrator:main` | Primary audit orchestrator |
| `counterscarp` | `orchestrator:main` | Short alias (identical) |
| `counterscarp-generate-pipeline` | `pipeline_generator:main` | CI/CD pipeline generator |

---

## All Flags Reference

### Core Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target` | PATH | **(required)** | Path to project root or `.sol` file |
| `--config` | FILE | Auto-detect | Path to config file (`scarpshield.toml` preferred, `counterscarp.toml` supported) |
| `--report` | flag | `false` | Generate professional HTML/Markdown audit report |
| `--project-name` | NAME | From path | Project name for report headers |

### Static Analysis

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--aderyn` | flag | `false` | Run Aderyn static analysis (requires `aderyn` CLI) |

### Dynamic Analysis

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--fuzz-contract` | NAME | None | Foundry invariant test contract name |
| `--medusa` | flag | `false` | Run Medusa coverage-guided fuzzing |
| `--symbolic` | flag | `false` | Run Mythril symbolic execution (requires `myth` CLI) |

### Solana Analysis

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--solana-root` | PATH | None | Path to Solana/Anchor project root |

### Upgrade Safety

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--upgrade-old` | PATH | None | Path to OLD contract version |
| `--upgrade-new` | PATH | None | Path to NEW contract version |

### History Scanning

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--history` | flag | `false` | Run time-travel historical vulnerability scan |
| `--time-travel` | flag | `false` | Alias for `--history` |
| `--commits` | INT | `50` | Maximum commits to scan in history mode |
| `--since` | DATE | None | Only scan commits since this date (ISO format, e.g. `2024-01-01`) |
| `--branch` | NAME | `main` | Branch to scan in history mode |

### Protocol Fingerprinting

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--fingerprint` | flag | `false` | Run protocol fingerprint similarity scan |

### Web Interface

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--gui` | flag | `false` | Launch the local web interface (FastAPI/Uvicorn on http://localhost:8000). Opens an interactive browser-based dashboard for uploading contracts, running scans, viewing results, and downloading reports. |

### RAG / AI

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rag` | flag | `false` | Enable RAG enrichment for findings |
| `--build-rag-index` | flag | `false` | Build a vector index of the target codebase for RAG-powered AI enrichment. Required before using `--rag` on a new project. Uses sentence-transformers locally or OpenAI embeddings if OPENAI_API_KEY is set. |
| `--llm` | flag | `false` | Enable LLM-powered analysis insights. Requires OPENAI_API_KEY or local Ollama server. |

---

## Execution Profiles

Counterscarp Engine ships with three pre-configured profiles via TOML config files:

| Feature | PR Profile | Audit Profile | Bounty Profile |
|---------|-----------|---------------|----------------|
| Config file | `counterscarp-pr.toml` | `scarpshield.toml` | `counterscarp-bounty.toml` |
| Heuristic scan | Yes | Yes | Yes |
| Slither | High/Medium | High/Medium | All impacts |
| Aderyn | No | Optional | Yes |
| Fuzzing | No | Optional | Yes (Medusa) |
| Symbolic (Mythril) | No | Optional | Yes |
| RAG enrichment | No | Optional | Yes |
| Exploit generation | No | No | Yes (HIGH+) |
| Report format | Markdown | HTML + MD | HTML + MD + SARIF |
| Fail threshold | HIGH | MEDIUM | LOW |
| Typical runtime | 30-60s | 5-15 min | 30-60 min |

### PR Profile — Fast PR Check

Designed for CI/CD gates on pull requests. Fast, focused, actionable.

```bash
counterscarp --target ./contracts --config counterscarp-pr.toml
```

### Audit Profile — Full Audit

For professional security audits. Comprehensive analysis with professional reporting.

```bash
counterscarp --target ./contracts --config scarpshield.toml --report --project-name "ProtocolName"
```

### Bounty Profile — Bug Bounty Mode

Maximum depth for bug bounty hunters. All analyzers, all rules, exploit generation.

```bash
counterscarp --target ./contracts --config counterscarp-bounty.toml --report --fuzz-contract InvariantTest --medusa --symbolic --rag --project-name "BountyTarget"
```

---

## Usage Examples

### Fast PR Check

```bash
counterscarp --target ./contracts --config counterscarp-pr.toml
```

Runs heuristics + Slither (High/Medium only). Fails CI on HIGH+ findings.

### Full Audit with HTML Report

```bash
counterscarp --target ./contracts --report --project-name "UniswapV4"
```

Full pipeline with professional HTML + Markdown report generation.

### Bug Bounty Mode

```bash
counterscarp --target ./contracts \
  --config counterscarp-bounty.toml \
  --fuzz-contract InvariantTest \
  --medusa \
  --aderyn \
  --symbolic \
  --fingerprint \
  --rag \
  --report
```

All analyzers, RAG enrichment, protocol fingerprinting, exploit generation.

### Upgrade Safety Check

```bash
counterscarp --target ./contracts \
  --upgrade-old ./contracts/ImplementationV1.sol \
  --upgrade-new ./contracts/ImplementationV2.sol \
  --report
```

Compares old and new implementations for storage collisions, removed auth, and other upgrade risks.

### Time-Travel History Scan

```bash
# Scan last 100 commits on develop branch
counterscarp --target ./my-project --history --commits 100 --branch develop

# Scan commits since a specific date
counterscarp --target ./my-project --history --since 2024-06-01 --branch main
```

Traces vulnerability patterns across git history, identifying active vs. fixed issues.

### Solana Audit

```bash
counterscarp --target ./evm-contracts --solana-root ./programs --report
```

Runs EVM analysis on the first target and Solana/Anchor static analysis on the programs directory.

### RAG Enrichment

```bash
# Build the knowledge base index first
counterscarp --target ./contracts --build-rag-index

# Then enrich findings
counterscarp --target ./contracts --rag --report
```

Uses local sentence-transformers embeddings (no API key needed) to enrich findings with historical context and remediation guidance.

---

## Output Directory Structure

When `--report` is used, Counterscarp Engine writes all scan artefacts into a structured per-session directory under `reports/`.

### Directory Naming

The output directory name is derived from the `--project-name` flag and the current date/session token:

```
reports/{project-name}_{YYYY-MM-DD}_{session}/
```

| Component | Source | Example |
|-----------|--------|---------|
| `{project-name}` | Value of `--project-name` (sanitised); falls back to the target directory basename | `UniswapV4` |
| `{YYYY-MM-DD}` | Date at scan start (UTC) | `2026-04-22` |
| `{session}` | Short random hex token scoped to the process | `a3f1c9` |

**Example:** running
```bash
counterscarp --target ./contracts --report --project-name "UniswapV4"
```
produces:
```
reports/
└── UniswapV4_2026-04-22_a3f1c9/
    ├── audit_report.md       # Markdown audit report
    ├── audit_report.html     # HTML audit report (if HTML output enabled)
    ├── ACTION_PLAN.md        # Prioritised remediation action plan
    ├── scan.log              # Full scan log for this session
    └── exploits/             # Generated PoC exploit scripts (Bounty mode)
        ├── exploit_reentrancy.py
        └── ...
```

### `--project-name` flag

| Behaviour | Detail |
|-----------|--------|
| **Controls directory prefix** | The sanitised project name is used verbatim as the directory prefix |
| **Appears in report headers** | The raw value is embedded in the HTML/Markdown report title |
| **Default** | If omitted, the basename of the `--target` path is used |
| **Sanitisation** | Non-alphanumeric characters (except `_` and `-`) are replaced with `_` |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PYTHONUNBUFFERED` | Set to `1` for real-time log output in production |
| `COUNTERSCARP_UPLOAD_DIR` | Override upload directory for web app |
| `COUNTERSCARP_RESULTS_DIR` | Override results directory for web app |
| `OPENAI_API_KEY` | Required when using `llm_backend = "openai"` in `[ai]` config |
| `ANTHROPIC_API_KEY` | Required when using `llm_backend = "anthropic"` in `[ai]` config |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed, no findings at or above `fail_on_severity` threshold |
| `1` | Scan completed, findings detected at or above threshold (CI failure) |
| `2` | Fatal error (missing module, invalid config, etc.) |

**Note:** The exit code is determined by the `engine.fail_on_severity` config setting. With the default of `HIGH`, any HIGH or CRITICAL finding causes exit code 1.

**Result interpretation:** Exit status and findings provide risk signals for triage, not a guarantee of complete vulnerability detection. For production decisions, combine automated output with manual analysis and tests.

---

## Troubleshooting

### HTTP 429 — Rate Limit Exceeded (Web App API)

When running scans via the **web app API** (i.e., `counterscarp --gui` or calls to the FastAPI backend), per-IP rate limits are enforced on sensitive endpoints:

| Endpoint | Limit |
|----------|-------|
| `/api/validate-license` | 10 requests / 60 s |
| `/api/deactivate-license` | 5 requests / 60 s |
| `/api/webhook` | 30 requests / 60 s |

If you receive `HTTP 429 Too Many Requests`, wait for the 60-second window to expire before retrying. Automated tooling that calls these endpoints in a tight loop should add appropriate back-off delays.

> **Note:** Rate limits are per-IP and are reset on server restart. They do not apply to CLI invocations (non-GUI mode).

### Other Common Issues

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| `slither: command not found` | Slither not installed | `pip install slither-analyzer` |
| `aderyn: command not found` | Aderyn not installed | See [Aderyn install guide](https://github.com/Cyfrin/aderyn) |
| `myth: command not found` | Mythril not installed | `pip install mythril` |
| Exit code 2 with config error | Invalid TOML syntax | Validate with `python -c "import tomllib; tomllib.load(open('scarpshield.toml','rb'))"` |
| Empty `reports/` directory | `--report` flag not passed | Add `--report` to your command |
| License validation fails offline | DNS for `api.counterscarp.io` unreachable | Engine falls back to 72-hour grace-period cache |

---

*Counterscarp Security Engine &bull; counterscarp.io*
