# Getting Started with Sentinel Engine

## Table of Contents

- [What is Sentinel Engine?](#what-is-sentinel-engine)
- [Installation](#installation)
- [Your First Audit in 60 Seconds](#your-first-audit-in-60-seconds)
- [Web UI Quick Start](#web-ui-quick-start)
- [Next Steps](#next-steps)

---

## What is Sentinel Engine?

Sentinel Engine is a production-ready smart contract security auditing platform that combines static analysis, heuristic pattern scanning, fuzzing, symbolic execution, and AI-powered RAG enrichment into a single pipeline. It supports both EVM (Solidity) and Solana (Rust/Anchor) smart contracts, providing 31 EVM heuristic rules, 35 Solana vulnerability patterns, and integration with industry-standard tools like Slither, Aderyn, Medusa, and Mythril.

Whether you're running a quick PR check, a full audit, or a bug bounty sweep, Sentinel Engine adapts to your workflow through configurable execution profiles and a composable analysis pipeline.

---

## Installation

### Requirements

- **Python 3.10+** (3.10, 3.11, or 3.12)
- **pip** package manager

### Core Installation

```bash
pip install sentinel-engine
```

### Installation with Optional Features

```bash
# Web UI (FastAPI + uvicorn)
pip install "sentinel-engine[web]"

# AI/RAG enrichment (local embeddings, no API needed)
pip install "sentinel-engine[ai]"

# OpenAI-powered LLM features
pip install "sentinel-engine[advanced]"

# Everything at once
pip install "sentinel-engine[web,ai,advanced]"

# Development dependencies (pytest, mypy, benchmarks)
pip install "sentinel-engine[dev]"
```

### Verify Installation

```bash
sentinel --help
# or
sentinel-engine --help
```

**Tip:** The `sentinel` and `sentinel-engine` commands are interchangeable aliases.

---

## Your First Audit in 60 Seconds

### 1. Scan a Solidity project

```bash
sentinel --target ./contracts
```

This runs the default pipeline: heuristic pattern scan + Slither static analysis + supply chain check.

### 2. Generate a professional report

```bash
sentinel --target ./contracts --report --project-name "MyProtocol"
```

This produces both an HTML and Markdown audit report with risk scoring.

### 3. Use a config file

```bash
sentinel --target ./contracts --config sentinel.toml
```

Create a `sentinel.toml` in your project root to customize rules, suppressions, and analysis behavior. See the [Configuration Guide](CONFIGURATION.md) for the full reference.

### Minimal Config Example

```toml
[engine]
name = "MyProtocol Audit"
fail_on_severity = "HIGH"

[heuristics]
enabled = true
```

---

## Web UI Quick Start

### Start the Development Server

```bash
pip install "sentinel-engine[web]"
cd sentinel-engine
uvicorn webapp.main:app --reload --port 8001
```

Open **http://localhost:8001** in your browser.

### What You Can Do

1. **Upload** `.sol` or `.rs` files via the web form
2. **Run** a security audit with one click
3. **View** results with risk score, severity breakdown, and AI Copilot insights
4. **Download** reports in HTML, Markdown, SARIF, or JSON format
5. **Explore** the interactive attack graph visualization

### Production Deployment

For production deployment with nginx + SSL, see the [Deployment Guide](DEPLOYMENT.md).

---

## Next Steps

| Guide | Description |
|-------|-------------|
| [CLI Reference](CLI_REFERENCE.md) | All commands, flags, profiles, and exit codes |
| [Configuration](CONFIGURATION.md) | Full sentinel.toml reference with examples |
| [Rules Catalog](RULES_CATALOG.md) | All 31 EVM and 35 Solana security rules |
| [Web App Guide](WEB_APP_GUIDE.md) | Web UI features and API endpoints |
| [Deployment](DEPLOYMENT.md) | Production server setup with nginx + SSL |
| [Plugin Development](PLUGIN_DEVELOPMENT.md) | Write custom analyzers and rule plugins |
| [Report Formats](REPORT_FORMATS.md) | HTML, Markdown, SARIF, and JSON report details |

---

*Sentinel Security Engine &bull; sentinel-engine.io*
