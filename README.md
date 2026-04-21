# Garrison Security Engine

**Production-ready smart contract security platform — 21 integrated analyzers, configurable rules, and professional audit reports.**

> One command. Zero false positives. Client-ready deliverables.

[![PyPI](https://img.shields.io/pypi/v/garrison-engine)](https://pypi.org/project/garrison-engine/)
[![Python](https://img.shields.io/pypi/pyversions/garrison-engine)](https://pypi.org/project/garrison-engine/)
[![License](https://img.shields.io/pypi/l/garrison-engine)](https://pypi.org/project/garrison-engine/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## Installation

```bash
pip install garrison-engine
```

For optional extras:

```bash
pip install "garrison-engine[web]"          # Web interface
pip install "garrison-engine[pdf]"          # PDF report export
pip install "garrison-engine[ai,advanced]"  # RAG + LLM analysis
pip install "garrison-engine[web,pdf,ai,advanced]"  # Full install
```

See **[QUICKSTART.md](QUICKSTART.md)** for Docker setup, optional external tools (Slither, Aderyn, Medusa), and full installation details.

---

## Quick Scan

```bash
# Scan a contracts directory and generate a report
garrison-engine --target ./contracts --report

# Use a pre-built execution profile
garrison-engine --target ./contracts --config garrison-pr.toml      # fast PR check
garrison-engine --target ./contracts --config garrison-audit.toml   # full audit
garrison-engine --target ./contracts --config garrison-bounty.toml  # bug bounty
```

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

## Pricing

| Feature | Community (Free) | Developer ($49/mo) | Professional ($149/mo) | Team ($399/mo) |
|---------|:---:|:---:|:---:|:---:|
| Heuristic scanning + CLI | ✅ | ✅ | ✅ | ✅ |
| Markdown / JSON reports | ✅ | ✅ | ✅ | ✅ |
| HTML / SARIF / PDF reports | — | ✅ | ✅ | ✅ |
| Slither + Solana analyzer | — | ✅ | ✅ | ✅ |
| AI Copilot + Exploit Gen | — | — | ✅ | ✅ |
| Time-travel + Attack graph | — | — | ✅ | ✅ |
| Machine activations | — | 1 | 3 | 10 |

Get your license: **https://garrisonsec.com/pricing**

```bash
export GARRISON_PRO_LICENSE=your-key-here
garrison-engine --target ./contracts --report --format html
```

---

## Documentation

| Document | Description |
|----------|-------------|
| **[QUICKSTART.md](QUICKSTART.md)** | Full install, config reference, CI/CD, offline setup, troubleshooting |
| **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** | Complete `garrison.toml` reference |
| **[docs/CLI_REFERENCE.md](docs/CLI_REFERENCE.md)** | All CLI flags and examples |
| **[docs/WEB_APP_GUIDE.md](docs/WEB_APP_GUIDE.md)** | Self-hosted web interface |
| **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** | Production server setup |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Adding rules and integrations |

---

## License

- **Community features:** MIT License — see [LICENSE](LICENSE)
- **Pro features:** Commercial License — see [LICENSE-PRO](LICENSE-PRO)

---

## Credits

**Built by CyberShield Austin** · [@defiauditccie](https://twitter.com/defiauditccie) · [garrisonsec.com](https://garrisonsec.com)

Powered by [Slither](https://github.com/crytic/slither) · [Aderyn](https://github.com/Cyfrin/aderyn) · [Medusa](https://github.com/crytic/medusa) · [Mythril](https://github.com/ConsenSys/mythril) · [Foundry](https://github.com/foundry-rs/foundry) · [OSV.dev](https://osv.dev)

Threat intelligence: Code4rena · Immunefi · Solodit · Neodyme · OtterSec · Sec3

---

**Version:** 4.4.0 | **Chains:** EVM + Solana | **Analyzers:** 21 | **Patterns:** 34 EVM + 35 Solana

**⭐ If this helped you find bugs, please star the repo!**
