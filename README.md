# Counterscarp Security Engine

**Production-ready smart contract security platform — 21 integrated analyzers, configurable rules, and professional audit reports.**

> One command. Zero false positives. Client-ready deliverables.

[![PyPI](https://img.shields.io/pypi/v/counterscarp-engine)](https://pypi.org/project/counterscarp-engine/)
[![Python](https://img.shields.io/pypi/pyversions/counterscarp-engine)](https://pypi.org/project/counterscarp-engine/)
[![License](https://img.shields.io/pypi/l/counterscarp-engine)](https://pypi.org/project/counterscarp-engine/)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

---

## Installation

```bash
pip install counterscarp-engine
```

For optional extras:

```bash
pip install "counterscarp-engine[web]"          # Web interface
pip install "counterscarp-engine[pdf]"          # PDF report export
pip install "counterscarp-engine[ai,advanced]"  # RAG + LLM analysis
pip install "counterscarp-engine[web,pdf,ai,advanced]"  # Full install
```

See **[QUICKSTART.md](QUICKSTART.md)** for Docker setup, optional external tools (Slither, Aderyn, Medusa), and full installation details.

---

## Quick Scan

```bash
# Scan a contracts directory and generate a report
counterscarp-engine --target ./contracts --report

# Use a pre-built execution profile
counterscarp-engine --target ./contracts --config counterscarp-pr.toml      # fast PR check
counterscarp-engine --target ./contracts --config counterscarp-audit.toml   # full audit
counterscarp-engine --target ./contracts --config counterscarp-bounty.toml  # bug bounty

counterscarp --gui  # Launch local web interface
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

## Security & Privacy (Data Sovereignty)

Counterscarp Engine is built for environments where source-code confidentiality is non-negotiable — bank compliance teams, Web3 audit firms, and air-gapped infrastructure.

- **Zero code exfiltration** — No source code, bytecode, or contract artifacts ever leave the host machine during a scan. All analysis is performed locally.
- **Local-first AI inference** — The AI Copilot defaults to local inference via [Ollama](https://ollama.com) when configured (`counterscarp.toml → [ai] provider = "ollama"`). If OpenAI is selected, only a one-paragraph natural-language summary of each finding is sent to the OpenAI API — never raw source code.
- **Bundled threat intelligence** — Vulnerability databases and protocol signatures ship with the package and are queried locally. Network access only occurs if you explicitly run `counterscarp --update-signatures`. For fully air-gapped environments, use `counterscarp --update-from-file <path>` to import pre-downloaded signature packs.
- **No telemetry** — The CLI contains zero usage telemetry, analytics callbacks, tracking pixels, or phone-home behavior. Period.

---

## Pricing

| Feature | Community (Free) | Developer ($49/mo) | Professional ($149/mo) | Team ($399/mo) | Enterprise |
|---------|:---:|:---:|:---:|:---:|:---:|
| Heuristic scanning + CLI | ✅ | ✅ | ✅ | ✅ | ✅ |
| Markdown / JSON reports | ✅ | ✅ | ✅ | ✅ | ✅ |
| HTML / SARIF / PDF reports | — | ✅ | ✅ | ✅ | ✅ |
| Slither + Solana analyzer | — | ✅ | ✅ | ✅ | ✅ |
| AI Copilot + Exploit Gen | — | — | ✅ | ✅ | ✅ |
| Time-travel + Attack graph | — | — | ✅ | ✅ | ✅ |
| Machine activations | — | 1 | 3 | 10 | Unlimited |

> **Enterprise (SE-ENT-xxx):** Custom pricing — unlimited seats, unlimited activations, custom integrations, priority support, and a dedicated account manager. Contact [contact@counterscarp.io](mailto:contact@counterscarp.io).

Get your license: **https://counterscarp.io/pricing**

```bash
export COUNTERSCARP_PRO_LICENSE=your-key-here
counterscarp-engine --target ./contracts --report --format html
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
| **[docs/CONFIGURATION.md](docs/CONFIGURATION.md)** | Complete `counterscarp.toml` reference |
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

**Built by CyberShield Austin** · [@defiauditccie](https://twitter.com/defiauditccie) · [counterscarp.io](https://counterscarp.io)

Powered by [Slither](https://github.com/crytic/slither) · [Aderyn](https://github.com/Cyfrin/aderyn) · [Medusa](https://github.com/crytic/medusa) · [Mythril](https://github.com/ConsenSys/mythril) · [Foundry](https://github.com/foundry-rs/foundry) · [OSV.dev](https://osv.dev)

Threat intelligence: Code4rena · Immunefi · Solodit · Neodyme · OtterSec · Sec3

---

**Version:** 5.0.0 | **Chains:** EVM + Solana | **Analyzers:** 21 | **Patterns:** 34 EVM + 35 Solana

**⭐ If this helped you find bugs, please star the repo!**
