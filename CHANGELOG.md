# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [3.3.0] - 2026-04-21

### Added
- Docker environment isolation with pinned tool versions (Slither 0.11.5, Aderyn 0.6.2, Medusa 0.1.8, Mythril 0.24.8, Foundry 1.0.0)
- Tool version manifest (`tool-versions.json`) for reproducible builds
- Container health check verifying all analyzer tools on startup
- `--preflight` CLI flag to validate tool versions before scanning
- Confidence scoring (1-10) for all 29 heuristic rules
- Inline suppression comments (`// sentinel-ignore: RULE_ID [reason]`)
- `--min-confidence` CLI filter to set minimum confidence threshold
- `--min-severity` CLI filter to set minimum severity threshold
- `.dockerignore` for optimized Docker builds

### Changed
- Dockerfile now pins exact versions for all security analysis tools
- docker-compose.yml includes container health checks
- Report output shows confidence scores in executive summary, top-10 table, and finding details
- Config file (`sentinel.toml`) supports `min_confidence` and `min_severity` under `[heuristics]`

## [3.2.0] - 2026-04-20

### Added
- Executive Summary section in all reports with severity breakdown and Top 10 priority issues
- Duplicate finding consolidation — groups similar findings across network-variant contracts with "Also found in" references
- Automatic exploit PoC generation for CRITICAL/HIGH findings (Pro tier, uses existing ExploitGenerator + 8 Foundry templates)
- New Section 11 in ACTION_PLAN: "Exploit Proof-of-Concept Tests" with forge test instructions

### Changed
- Finding dataclass extended with similar_locations and duplicate_count fields
- Report generator now deduplicates before grouping into sections

## [3.1.3] - 2026-04-20

### Fixed
- Report header now correctly reflects critical findings from all engines (heuristic, Slither, fuzz)
- Slither subprocess isolation with PYTHONWARNINGS=ignore prevents dependency warnings from corrupting JSON output
- Automatic per-file fallback when directory target produces no Slither JSON (handles non-Foundry projects)
- Engine version in reports now dynamically resolved from package metadata instead of hardcoded "2.2"
- ValueError crash in report generation for Slither multi-line location formats

## [3.1.2] - 2026-04-20

### Fixed
- Comprehensive robustness hardening across 9 source files (17 issues resolved)
- Subprocess timeout enforcement: Slither (300s), fuzzing (3600s), git log (300s), git show (30s)
- Windows Slither binary resolution with shutil.which() fallback
- JSON parsing with brace-counting fallback for trailing data
- License validation retry with exponential backoff (3 attempts)
- Thread-safe logging setup with threading.Lock
- TOML parse error handling with specific exception types
- Report generator NaN/infinity guard on risk scores
- Heuristic scanner encoding errors="replace" for non-UTF8 files
- Safe exception formatting with repr() for detail values

### Added
- Built-in dual-output file logging (FileHandler + StreamHandler) for guaranteed result persistence
- Git subprocess timeout with TimeoutExpired handling in history_scanner.py

## [3.1.1] - 2026-04-19

### Added
- Three new heuristic rules for enhanced pattern detection
- Foundry integration for Slither analysis on forge-based projects

### Fixed
- Slither solc fallback behavior when forge is unavailable
- Shell piping reliability issues with Tee-Object

## [3.1.0] - 2026-04-18

### Added
- 5-tier pricing restructure (Community Free, Developer $49, Pro $149, Team $399, Enterprise Custom)
- Solana Analyzer and branded HTML/SARIF reports available at Developer tier
- Stripe Checkout integration with license provisioning
- Web application with drag-and-drop upload
- SARIF 2.1.0 report format support

### Changed
- Feature gating moved to tier-based model
- AI Audit Copilot, Attack Graph, Exploit PoC Generator, Time-Travel Git Scanner, Protocol Fingerprinting gated at Pro tier

## [3.0.0] - 2026-04-15

### Added
- License-gated Pro features with server-side validation
- Commercial EULA for Pro tier
- PyPI package distribution
- 21 integrated security analyzers
- 31 EVM heuristic rules + 35 Solana vulnerability patterns
- Configurable execution profiles (sentinel.toml, sentinel-audit.toml, sentinel-pr.toml, sentinel-bounty.toml)
- Professional audit report generation (HTML, Markdown, SARIF, JSON)
- AI-powered RAG enrichment with customer-managed OpenAI API key

### Changed
- Migrated from open-source to commercial model with free Community tier
