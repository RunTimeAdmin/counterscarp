# CLI Reference

> **Installation:** `pip install garrison-engine` — See [Getting Started](GETTING_STARTED.md) for details.

## Table of Contents

- [Command Entry Points](#command-entry-points)
- [All Flags Reference](#all-flags-reference)
- [Execution Profiles](#execution-profiles)
- [Usage Examples](#usage-examples)
- [Environment Variables](#environment-variables)
- [Exit Codes](#exit-codes)

---

## Command Entry Points

Garrison Engine provides three CLI commands:

| Command | Entry Point | Description |
|---------|-------------|-------------|
| `garrison-engine` | `orchestrator:main` | Primary audit orchestrator |
| `garrison` | `orchestrator:main` | Short alias (identical) |
| `garrison-generate-pipeline` | `pipeline_generator:main` | CI/CD pipeline generator |

---

## All Flags Reference

### Core Flags

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--target` | PATH | **(required)** | Path to project root or `.sol` file |
| `--config` | FILE | Auto-detect | Path to `garrison.toml` config file |
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

### RAG / AI

| Flag | Type | Default | Description |
|------|------|---------|-------------|
| `--rag` | flag | `false` | Enable RAG enrichment for findings |
| `--build-rag-index` | flag | `false` | Rebuild the RAG knowledge base index |

---

## Execution Profiles

Garrison Engine ships with three pre-configured profiles via TOML config files:

| Feature | PR Profile | Audit Profile | Bounty Profile |
|---------|-----------|---------------|----------------|
| Config file | `garrison-pr.toml` | `garrison.toml` | `garrison-bounty.toml` |
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
garrison --target ./contracts --config garrison-pr.toml
```

### Audit Profile — Full Audit

For professional security audits. Comprehensive analysis with professional reporting.

```bash
garrison --target ./contracts --config garrison.toml --report --project-name "ProtocolName"
```

### Bounty Profile — Bug Bounty Mode

Maximum depth for bug bounty hunters. All analyzers, all rules, exploit generation.

```bash
garrison --target ./contracts --config garrison-bounty.toml --report --fuzz-contract InvariantTest --medusa --symbolic --rag --project-name "BountyTarget"
```

---

## Usage Examples

### Fast PR Check

```bash
garrison --target ./contracts --config garrison-pr.toml
```

Runs heuristics + Slither (High/Medium only). Fails CI on HIGH+ findings.

### Full Audit with HTML Report

```bash
garrison --target ./contracts --report --project-name "UniswapV4"
```

Full pipeline with professional HTML + Markdown report generation.

### Bug Bounty Mode

```bash
garrison --target ./contracts \
  --config garrison-bounty.toml \
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
garrison --target ./contracts \
  --upgrade-old ./contracts/ImplementationV1.sol \
  --upgrade-new ./contracts/ImplementationV2.sol \
  --report
```

Compares old and new implementations for storage collisions, removed auth, and other upgrade risks.

### Time-Travel History Scan

```bash
# Scan last 100 commits on develop branch
garrison --target ./my-project --history --commits 100 --branch develop

# Scan commits since a specific date
garrison --target ./my-project --history --since 2024-06-01 --branch main
```

Traces vulnerability patterns across git history, identifying active vs. fixed issues.

### Solana Audit

```bash
garrison --target ./evm-contracts --solana-root ./programs --report
```

Runs EVM analysis on the first target and Solana/Anchor static analysis on the programs directory.

### RAG Enrichment

```bash
# Build the knowledge base index first
garrison --target ./contracts --build-rag-index

# Then enrich findings
garrison --target ./contracts --rag --report
```

Uses local sentence-transformers embeddings (no API key needed) to enrich findings with historical context and remediation guidance.

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `PYTHONUNBUFFERED` | Set to `1` for real-time log output in production |
| `GARRISON_UPLOAD_DIR` | Override upload directory for web app |
| `GARRISON_RESULTS_DIR` | Override results directory for web app |
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

---

*Garrison Security Engine &bull; garrisonsec.com*
