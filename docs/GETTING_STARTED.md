# Getting Started with Counterscarp Engine

> **Try it online:** [https://counterscarp.io](https://counterscarp.io) — Run audits in your browser, no installation required.

## Table of Contents

- [What is Counterscarp Engine?](#what-is-counterscarp-engine)
- [Try It Online](#try-it-online)
- [Installation](#installation)
- [Your First Audit in 60 Seconds](#your-first-audit-in-60-seconds)
- [Web UI Quick Start](#web-ui-quick-start)
- [Docker Quick Start](#docker-quick-start)
- [Local Web Interface](#local-web-interface)
- [Pro License Activation](#pro-license-activation)
- [Next Steps](#next-steps)

---

## What is Counterscarp Engine?

Counterscarp Engine is a production-ready smart contract security auditing platform that combines static analysis, heuristic pattern scanning, fuzzing, symbolic execution, and AI-powered RAG enrichment into a single pipeline. It supports both EVM (Solidity) and Solana (Rust/Anchor) smart contracts, providing 31 EVM heuristic rules, 35 Solana vulnerability patterns, and integration with industry-standard tools like Slither, Aderyn, Medusa, and Mythril.

Whether you're running a quick PR check, a full audit, or a bug bounty sweep, Counterscarp Engine adapts to your workflow through configurable execution profiles and a composable analysis pipeline.

---

## Try It Online

The fastest way to try Counterscarp Engine is via the live web app:

**[https://counterscarp.io](https://counterscarp.io)**

The online demo allows you to:
- Upload and audit `.sol` or `.rs` files
- View risk scores and severity breakdowns
- Download professional audit reports
- Explore interactive attack graphs

---

## Installation

### PyPI Package

Counterscarp Engine is available on PyPI: [https://pypi.org/project/counterscarp-engine/](https://pypi.org/project/counterscarp-engine/)

### Requirements

- **Python 3.10+** (3.10, 3.11, or 3.12)
- **pip** package manager

### Core Installation

```bash
pip install counterscarp-engine
```

### Installation with Optional Features

```bash
# Web UI (FastAPI + uvicorn)
pip install "counterscarp-engine[web]"

# PDF report generation (Pro/Enterprise)
pip install "counterscarp-engine[pdf]"

# AI/RAG enrichment (local embeddings, no API needed)
pip install "counterscarp-engine[ai]"

# Everything at once
pip install "counterscarp-engine[web,pdf,ai]"

# Development dependencies (pytest, mypy, benchmarks)
pip install "counterscarp-engine[dev]"
```

### Verify Installation

```bash
counterscarp --help
# or
counterscarp-engine --help
```

**Tip:** The `counterscarp` and `counterscarp-engine` commands are interchangeable aliases.

---

## Your First Audit in 60 Seconds

### 1. Scan a Solidity project

```bash
counterscarp --target ./contracts
```

This runs the default pipeline: heuristic pattern scan + Slither static analysis + supply chain check.

### 2. Generate a professional report

```bash
counterscarp --target ./contracts --report --project-name "MyProtocol"
```

This produces both an HTML and Markdown audit report with risk scoring.

**Output location:** Reports are organized into per-scan directories under `reports/`:

```
reports/MyProtocol_2026-04-22_{session}/
├── audit_report.md
├── audit_report.html
├── ACTION_PLAN.md
└── scan.log
```

Each scan creates a new isolated directory — previous results are never overwritten. See [Report Formats](REPORT_FORMATS.md#per-scan-report-directories) for full details.

### 3. Use a config file

```bash
counterscarp --target ./contracts --config counterscarp.toml
```

Create a `counterscarp.toml` in your project root to customize rules, suppressions, and analysis behavior. See the [Configuration Guide](CONFIGURATION.md) for the full reference.

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
pip install "counterscarp-engine[web]"
cd counterscarp-engine
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

> **SESSION_SECRET requirement:** Production web deployments must set the `SESSION_SECRET` environment variable to a strong random string (minimum 32 characters). This secret signs session cookies. Without it, the server will refuse to start or fall back to an insecure default. Generate one with:
>
> ```bash
> python -c "import secrets; print(secrets.token_hex(32))"
> ```

---

## Docker Quick Start

Pull the official image and mount your contracts directory:

```bash
docker pull counterscarp/engine:latest
docker run -v $(pwd)/contracts:/scan counterscarp/engine --target /scan --report
```

Reports are written inside the container at `/scan`. To retrieve them, mount an output directory:

```bash
docker run \
  -v $(pwd)/contracts:/scan \
  -v $(pwd)/output:/output \
  counterscarp/engine --target /scan --report --output /output
```

**Environment variables** (pass with `-e`):

```bash
docker run -e COUNTERSCARP_PRO_LICENSE=SE-PRO-xxx \
  -v $(pwd)/contracts:/scan \
  counterscarp/engine --target /scan --report
```

---

## Local Web Interface

The `--gui` flag launches the full web UI without manually starting uvicorn:

```bash
counterscarp --gui
# Opens http://localhost:8000 in your browser
```

This is the quickest way to use the browser interface for one-off audits. To keep it running persistently, use the uvicorn command in the [Web UI Quick Start](#web-ui-quick-start) section above or follow the [Deployment Guide](DEPLOYMENT.md) for production use.

---

## Pro License Activation

Counterscarp Engine ships with both free and pro features in a single package. Pro features require a valid license key to unlock.


### Enabling PDF Reports

Pro and Enterprise users can generate PDF versions of audit reports:

```bash
pip install "counterscarp-engine[pdf]"
```

Once installed, PDF reports are generated automatically alongside HTML and Markdown outputs. Configure your company logo in `counterscarp.toml`:

```toml
[reporting]
logo_path = "path/to/your-logo.png"
```
### Setting Your License Key

**Option 1: Environment variable**

```bash
export COUNTERSCARP_PRO_LICENSE=SE-PRO-XXXXXXXXXXXX
```

Replace the prefix based on your tier: `SE-DEV-xxx`, `SE-PRO-xxx`, `SE-TEAM-xxx`, or `SE-ENT-xxx`.

**Option 2: Configuration file**

Add a `[license]` section to your `counterscarp.toml`:

```toml
[license]
key = "SE-PRO-XXXXXXXXXXXX"
```

The environment variable takes priority over the config file.

### License Tiers

Counterscarp Engine offers five license tiers:

| Tier | Price | Key Prefix | Features |
|------|-------|------------|----------|
| **Community** | Free | — | Core heuristic scanner, Slither, basic reports (Markdown/JSON), CLI |
| **Developer** | $49/mo | `SE-DEV-xxx` | Web app, Solana Analyzer, HTML/SARIF reports |
| **Pro** | $199/mo | `SE-PRO-xxx` | AI Copilot, Attack Graph, Exploit PoC, Time-Travel, Fingerprinting |
| **Team** | $399/mo | `SE-TEAM-xxx` | 5 seats, shared workspace, API access |
| **Enterprise** | Custom | `SE-ENT-xxx` | Unlimited seats, unlimited activations, custom integrations, priority support, dedicated account manager |

### Tier Features

**Developer tier** unlocks:

- **Web App** — Full web-based audit interface at counterscarp.io
- **Solana Analyzer** — 35 Rust/Anchor security patterns with IDL validation
- **Branded HTML/SARIF Reports** — Professional branded audit report output

**Pro tier** unlocks (includes all Developer features):

- **AI Audit Copilot** — RAG-based vulnerability explanations and remediation guidance
- **Attack Graph Visualization** — Interactive D3.js cross-contract attack path graphs
- **Exploit PoC Generator** — Automatic Foundry exploit test case generation
- **Time-Travel Scanner** — Git-based historical vulnerability tracking
- **Protocol Fingerprinting** — Protocol similarity and inherited vulnerability detection

**Team tier** unlocks (includes all Pro features):

- **10 Seats** — Shared team access with centralized management
- **Shared Workspace** — Collaborative audit projects and findings
- **API Access** — Programmatic integration with CI/CD pipelines

**Enterprise tier** unlocks (includes all Team features):

- **Unlimited Seats** — No per-seat restrictions, organisation-wide deployment
- **Unlimited Activations** — Deploy across any number of machines or CI runners
- **Custom Integrations** — Bespoke connectors and workflow automation
- **Priority Support** — Direct engineering escalation and SLA guarantees
- **Dedicated Account Manager** — Onboarding, quarterly reviews, and renewal management

### Getting a License

Visit [counterscarp.io/pricing](https://counterscarp.io/pricing) to purchase a Developer, Pro, Team, or Enterprise license.

---

## Next Steps

| Guide | Description |
|-------|-------------|
| [CLI Reference](CLI_REFERENCE.md) | All commands, flags, profiles, and exit codes |
| [Configuration](CONFIGURATION.md) | Full counterscarp.toml reference with examples |
| [Rules Catalog](RULES_CATALOG.md) | All 31 EVM and 35 Solana security rules |
| [Web App Guide](WEB_APP_GUIDE.md) | Web UI features and API endpoints |
| [Deployment](DEPLOYMENT.md) | Production server setup with nginx + SSL |
| [Plugin Development](PLUGIN_DEVELOPMENT.md) | Write custom analyzers and rule plugins |
| [Report Formats](REPORT_FORMATS.md) | HTML, Markdown, SARIF, and JSON report details |

---

*Counterscarp Security Engine &bull; counterscarp.io*
