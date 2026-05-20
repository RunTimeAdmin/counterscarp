# Scarpshield (Counterscarp&#8482; Engine)

**Production-ready smart contract security platform — 21 integrated analyzers, configurable rules, and professional audit reports.**

> Scarpshield is the unified product brand; `counterscarp-engine` is the package/CLI distribution.

> One command. Client-ready deliverables.

[![PyPI](https://img.shields.io/pypi/v/counterscarp-engine)](https://pypi.org/project/counterscarp-engine/)
[![Python](https://img.shields.io/pypi/pyversions/counterscarp-engine)](https://pypi.org/project/counterscarp-engine/)
[![License](https://img.shields.io/pypi/l/counterscarp-engine)](https://pypi.org/project/counterscarp-engine/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![codecov](https://codecov.io/gh/RunTimeAdmin/counterscarp/branch/main/graph/badge.svg)](https://codecov.io/gh/RunTimeAdmin/counterscarp)

---

## Current Status (May 2026)

- Runtime image hardening is complete with a multi-stage Docker build and reduced runtime surface.
- Container security guardrails are in place: CI blocks non-base `critical`/`high` image findings.
- Base-image CVEs are tracked through a documented allowlist and periodic review policy.
- Medusa is currently optional and auto-skipped in containers if unavailable, with a clear runtime warning.
- Remaining operational follow-up: ensure GitHub Actions billing is active and set `SNYK_TOKEN` / `SNYK_ORG` secrets for CI execution.

See `docs/CURRENT_STATUS.md` for operational details and next actions.

---

## Installation

```bash
pip install counterscarp-engine
```

Preferred command aliases (brand-forward, backward compatible):

```bash
scarpshield --help
scarpshield-engine --help
```

Legacy aliases `counterscarp` and `counterscarp-engine` remain supported.

For optional extras:

```bash
pip install "counterscarp-engine[web]"          # Web interface
pip install "counterscarp-engine[pdf]"          # PDF report export
pip install "counterscarp-engine[ai,advanced]"  # RAG + LLM analysis
pip install "counterscarp-engine[web,pdf,ai,advanced]"  # Full install
```

### PDF Report Generation (Pro/Enterprise)

PDF export requires the optional `pdf` extra:

```bash
pip install "counterscarp-engine[pdf]"
```

This installs [xhtml2pdf](https://github.com/xhtml2pdf/xhtml2pdf) for converting HTML audit reports to branded, print-ready PDFs with custom logos.

See **[QUICKSTART.md](QUICKSTART.md)** for Docker setup, optional external tools (Slither, Aderyn, Medusa), and full installation details.

---

## Quick Scan

```bash
# Scan a contracts directory and generate a report
scarpshield-engine --target ./contracts --report

# Use a pre-built execution profile
scarpshield-engine --target ./contracts --config counterscarp-pr.toml      # fast PR check
scarpshield-engine --target ./contracts --config counterscarp-audit.toml   # full audit
scarpshield-engine --target ./contracts --config counterscarp-bounty.toml  # bug bounty
# default config lookup supports scarpshield.toml (preferred) and counterscarp.toml

scarpshield --gui  # Launch local web interface
```

### Docker (report persistence)

```bash
docker run --rm \
  -v /path/to/contracts:/scan \
  -v /path/to/reports:/output \
  counterscarp-engine:5.1.0 \
  --target /scan --output-dir /output --report
```

Mount a host directory to `/output` and pass `--output-dir /output` so reports survive `--rm` container teardown. See [QUICKSTART.md](QUICKSTART.md) for full Docker setup.

---

## Interface Modes

### CLI (Headless)

```bash
counterscarp --target ./contracts
```

Headless mode designed for CI/CD pipelines and automation. Supports all scan profiles (PR, Audit, Bounty, Solana). Outputs JSON, Markdown, and SARIF for direct pipeline integration. No GUI dependencies required.

### Desktop GUI

```bash
counterscarp --gui
```

Launches a local Tkinter desktop interface. Provides 12 analyzer toggles for granular scan configuration, a file browser for contract selection, and real-time result streaming. Fully offline — no network connection required.

### Cloud App

`app.counterscarp.io` — multi-user web application with account system. Browser-based interface supporting scan upload, interactive results, and report downloads (HTML/PDF/SARIF/Markdown). Includes attack graph visualization and Stripe-integrated billing.

---

## Solana/Anchor Security Analysis

### Coverage (v5.0.3)

35 Rust/Anchor security patterns across 7 categories:

| Category | Rules | Examples |
|---|---|---|
| **Account Validation** | 8 | Missing signer/owner checks, unvalidated PDA seeds, missing discriminator checks |
| **CPI Security** | 4 | Arbitrary CPI, missing CPI authority, unverified program accounts |
| **Arithmetic & Logic** | 5 | Unchecked arithmetic, integer overflow, unsafe casting, precision loss |
| **State Management** | 6 | Uninitialized accounts, reinitialization, missing rent exemption, stale data |
| **Access Control** | 4 | Missing access control, hardcoded authority, weak authority checks |
| **Token Security** | 4 | Missing token account validation, unchecked balances, unvalidated token program |
| **General Validation** | 4 | Unconstrained system program, missing clock validation, duplicate mutable accounts |

### Additional Capabilities

- `cargo-audit` integration for Cargo.toml dependency CVEs
- Anchor IDL validation for security constraint verification

### Approach

Static regex-based pattern matching against Rust source files. Scans all `.rs` files, excluding the `/target` directory.

### Known Limitations

- **Single-file analysis** — no cross-contract taint tracking across Rust modules
- **Regex-based** — no data-flow or symbolic execution analysis
- **Anchor-focused** — raw Solana SDK (non-Anchor) coverage is lighter
- **No CPI tracing** — cross-program invocation paths are not traced across program boundaries

### Roadmap (v5.x)

- Cross-file CPI tracing
- Expanded raw Solana SDK patterns
- Integration with Anchor's built-in verification tools

---

## Key Features

- **21 Integrated Analyzers** — Heuristic scanner, Slither, Aderyn, Mythril, Medusa, supply chain, threat intel, and more
- **EVM + Solana** — 34 EVM vulnerability patterns, 35 Solana/Anchor rules, IDL validation
- **3 Execution Profiles** — PR check (< 2 min), full audit, bug bounty mode
- **Professional Reports** — HTML, Markdown, JSON, SARIF, PDF with risk scoring
- **CI/CD Native** — GitHub Actions, GitLab CI, Azure DevOps, Jenkins pipeline generator
- **AI Audit Copilot** — RAG + LLM enrichment with local (Ollama) or cloud (OpenAI) backends
- **Time-Travel Scanner** — Git history analysis to track vulnerability introduction
- **Attack Graph Visualization** — Interactive D3.js cross-contract attack path graphs
- **Exploit PoC Generator** — Foundry test exploits from detected findings
- **Protocol Fingerprinting** — Identifies forks of known protocols and inherited CVEs
- **Offline / Air-Gapped** — Bundled threat intel DB, local embeddings, Ollama LLM

---

## Realistic Expectations

Counterscarp improves review speed and coverage, but no static or hybrid analyzer can guarantee zero missed vulnerabilities or zero false positives. Treat results as a prioritized security triage queue and follow with manual review, tests, and (for high-risk systems) independent audit.

---

## Security & Privacy (Data Sovereignty)

Counterscarp Engine is built for environments where source-code confidentiality is non-negotiable — bank compliance teams, Web3 audit firms, and air-gapped infrastructure.

- **Local-first analysis** — Source code analysis runs on the host machine by default.
- **Local-first AI inference** — The AI Copilot defaults to local inference via [Ollama](https://ollama.com) when configured (`scarpshield.toml` or `counterscarp.toml` -> `[ai] provider = "ollama"`). If OpenAI is selected, the integration is designed to send finding summaries rather than raw source code.
- **Bundled threat intelligence** — Vulnerability databases and protocol signatures ship with the package and are queried locally. Network access only occurs if you explicitly run `counterscarp --update-signatures`. For fully air-gapped environments, use `counterscarp --update-from-file <path>` to import pre-downloaded signature packs.
- **No usage analytics** — The CLI is designed without usage telemetry or analytics callbacks.
- **API security hardening** — The web API enforces rate limiting (10 req/min on license validation, 5 req/min on deactivation, 30 req/min on webhooks), Pydantic input validation on all request fields, mandatory Stripe webhook signature verification, admin endpoint authentication, CORS restricted to known origins, and a dedicated `counterscarp.security` logger for all auth and validation events.

---

## Pricing

| Feature | Community (Free) | Developer ($49/mo) | Professional ($199/mo) | Team ($399/mo) | Enterprise |
|---------|:---:|:---:|:---:|:---:|:---:|
| Heuristic scanning + CLI | ✅ | ✅ | ✅ | ✅ | ✅ |
| Markdown / JSON reports | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTML / SARIF / PDF reports | — | ✅ | ✅ | ✅ | ✅ |
| Slither + Solana analyzer | — | ✅ | ✅ | ✅ | ✅ |
| AI Copilot + Exploit Gen | — | — | ✅ | ✅ | ✅ |
| Time-travel + Attack graph | — | — | ✅ | ✅ | ✅ |
| Machine activations | — | 1 | 3 | 5 | Unlimited |

> **Enterprise (SE-ENT-xxx):** Custom pricing — unlimited seats, unlimited activations, custom integrations, priority support, and a dedicated account manager. Contact [contact@counterscarp.io](mailto:contact@counterscarp.io).

Get your license: **https://counterscarp.io/pricing**

```bash
export SCARPSHIELD_PRO_LICENSE=your-key-here
scarpshield-engine --target ./contracts --report --format html
```

### Account-Based Licensing

Create an account at [app.counterscarp.io](https://app.counterscarp.io) using Google or email to manage your license:

- **Automatic linking** — Purchase Pro and your license is automatically linked to your account
- **Cross-device access** — Log in on any device and your Pro features activate automatically
- **Admin dashboard** — View registered users and license status at `/admin/users`

---

## Documentation

| Document | Description |
|----------|-------------|
| **[QUICKSTART.md](QUICKSTART.md)** | Full install, config reference, CI/CD, offline setup, troubleshooting |
| **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** | Complete config reference (`scarpshield.toml` preferred, `counterscarp.toml` supported) |
| **[docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)** | All CLI flags and examples |
| **[docs/WEB_APP_GUIDE.md](docs/WEB_APP_GUIDE.md)** | Self-hosted web interface |
| **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** | Production server setup |
| **[docs/SECURITY_CONTAINER_ALLOWLIST.md](docs/SECURITY_CONTAINER_ALLOWLIST.md)** | Container CVE allowlist scope and guardrail policy |
| **[docs/CURRENT_STATUS.md](docs/CURRENT_STATUS.md)** | Current hardening status, known blockers, and immediate next steps |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Adding rules and integrations |

---

## License

- **Community features:** MIT License — see [LICENSE](LICENSE)
- **Pro features:** Commercial License — see [LICENSE-PRO](LICENSE-PRO)

---

## Credits

**Built by CyberShield Austin** · [@counterscarpsec](https://twitter.com/counterscarpsec) · [@defiauditccie](https://twitter.com/defiauditccie) · [counterscarp.io](https://counterscarp.io)

Powered by [Slither](https://github.com/crytic/slither) · [Aderyn](https://github.com/Cyfrin/aderyn) · [Medusa](https://github.com/crytic/medusa) · [Mythril](https://github.com/ConsenSys/mythril) · [Foundry](https://github.com/foundry-rs/foundry) · [OSV.dev](https://osv.dev)

Threat intelligence: Code4rena · Immunefi · Solodit · Neodyme · OtterSec · Sec3

---

**Version:** 5.1.0 | **Chains:** EVM + Solana | **Analyzers:** 21 | **Patterns:** 34 EVM + 35 Solana

**⭐ If this helped you find bugs, please star the repo!**
