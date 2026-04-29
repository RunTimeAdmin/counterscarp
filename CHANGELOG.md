# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## v5.1.0 — 2026-04-29

### Solana/Anchor Analyzer — Complete Implementation
- **40 security patterns** across 7 categories: Account Validation, CPI Security, Arithmetic & Logic, State Management, Access Control, Token Security, General Validation
- New `SolanaAnalyzer` class encapsulating discovery, scanning, IDL validation, and cargo-audit
- Full IDL validator integration — `idl_validator.validate_idl()` wired into analysis pipeline
- 9 new patterns added: `AUTHORITY_PUBKEY_MISMATCH`, `MISSING_MULTISIG_UPGRADE`, `UNSAFE_NARROWING_CAST`, `UNVALIDATED_SPL_TOKEN_PROGRAM`, `TWO_STEP_TRANSFER_NOT_USED`, `AUTHORITY_IS_DEFAULT`, `CPI_ACCOUNT_LAMPORT_BALANCE_MISMATCH`, `CPI_RETURN_VALUE_NOT_CHECKED`, `SIGN_CHANGE_WITHOUT_CHECK`
- `rule_id` property on `SolanaFinding` for proper orchestrator integration
- Enhanced severity aggregation across pattern, IDL, and dependency findings
- CLI: `counterscarp --chain solana --solana-root /path/to/project`

### Security Hardening (V4 Code Review Remediation)
- **HF-V4-01**: Block PAYG users with zero credits from free scans
- **HF-V4-02**: Require authentication or license key for unauthenticated scan requests
- **MF-V4-01**: Production config validation — PAYG price IDs (warning) + TOTP encryption key (required)
- **MF-V4-02**: Thread-safe session map with `_session_map_lock` and atomic file writes

### Marketing & Documentation
- CLI vs Webapp feature differentiation badges on all pricing/feature pages
- Honest about page timeline reflecting actual development history
- Removed false "zero false positives" claims across all pages
- Standardized analyzer count messaging: "14 free, up to 21 with Pro"
- Bidirectional navigation between app.counterscarp.io and counterscarp.io

## v5.0.7 — 2026-04-28

### Added
- **Pay-As-You-Go scan packs**: One-time purchase credit packs (Starter 1/$9.99, Standard 5/$29.99, Pro Pack 15/$69.99)
- Atomic credit consumption with thread-safe double-spend prevention
- Stripe one-time payment checkout integration (`mode="payment"`)
- Webhook fulfillment for PAYG credit grants
- Credit gate in scan handler — PAYG users consume 1 credit per audit
- Credit balance badges on upload and dashboard pages
- New templates: payg_success.html, payg_no_credits.html
- PAYG section in pricing page with 3 pack cards
- Comprehensive PAYG test suite (test_payg.py, test_stripe_payg.py)

### Changed
- TIER_HIERARCHY now includes PAYG between Community and Developer
- pricing.html extended with Pay-As-You-Go section
- docker-compose.yml includes STRIPE_PAYG_*_PRICE_ID env vars

## v5.0.6 — 2026-04-28

### Features
- **FS-06**: Audit trail logging — append-only JSONL log for all license operations (`data/audit_log.jsonl`)
- **FS-04**: Stripe webhook event idempotency — Redis-backed dedup with file fallback
- **FS-02**: Per-user audit history dashboard — `/dashboard` with paginated scan history
- **FS-03**: Rate limit headers — `X-RateLimit-Limit/Remaining/Reset` on all rate-limited endpoints
- **FS-01**: Async audit processing — `arq` Redis job queue with sync fallback and progress polling
- **FS-05**: TOTP/2FA for admin accounts — `pyotp` enrollment, challenge flow, Fernet-encrypted secrets
- **FS-07**: Grace period countdown notification — dismissible banner in web UI

### Fixes
- Docker: Medusa build switched from `go install` to `git clone` + `go build` (Go replace directive compat)
- Docker: Added `[web]` extras to pip install for full webapp support in container
- Removed stale `pytest.ini` (merged config into `pyproject.toml`)
- Fixed `threading.Lock` deadlock in license_api.py (changed to `RLock`)
- Fixed mypy variable shadowing in main.py Slither integration

## v5.0.5 — 2026-04-25

### Major Changes

- **H1: Orchestrator Phase Architecture** — Refactored the monolithic 1,361-line `main()` function into a clean phase-based architecture. New `ScanPhase` base class and `ScanContext` dataclass in `scan_phase.py`. 15 scan phases extracted into `phases/` package (6 modules: static_analysis, fuzzing, heuristic, analysis, enrichment, reporting). Orchestrator main() reduced to ~200 lines with a registry-driven phase loop. Full backward compatibility preserved: same CLI, same state checkpoints, same resume behavior.

- **M6: Async I/O** — Added async subprocess execution via `async_subprocess.py` with timeout-aware `run_tool()` coroutine. All scan phases gained `run_async()` methods with thread-executor fallback. Independent phases (Slither+Aderyn, FoundryFuzz+MedusaFuzz) now run concurrently via `asyncio.gather()`. Webapp audit endpoint converted to non-blocking async Slither analysis.

- **M9: Redis Rate Limiter** — Added `RedisRateLimiter` with sliding-window algorithm backed by Redis sorted sets, with automatic in-memory fallback when Redis is unavailable. Applied rate limits to 5 endpoint groups: login (5/15min), registration (3/hr), audit (10/hr), license API (100/hr), admin (30/hr). Trusted proxy validation for X-Forwarded-For header.

### Fixes

- Fixed plugin phase ordering to run after heuristic phase (was incorrectly concurrent)
- Fixed async resume cache restoration for partially-completed phase groups
- Replaced deprecated `asyncio.get_event_loop()` with `asyncio.get_running_loop()` across all async code
- Updated report_generator.pyi type stubs with missing Finding fields and function signatures

## [5.0.4] - 2026-04-25

### Security
- Subprocess path traversal validation with `Path.is_relative_to()` and `--` argument separator in webapp
- PBKDF2-HMAC key derivation (100k iterations) for license cache signatures
- DNS-aware grace period — reduced from 7 to 3 days, distinguishes network outage from targeted blocking

### Performance
- Lazy comment map initialization — O(n) comment state array only built when first match found, zero cost for files with no hits
- Lazy `%s` log formatting on scanner hot path — eliminates f-string allocation when debug logging disabled

### Changed
- Compatible-release dependency pins (`~=`) replacing lower-bound-only (`>=`) in pyproject.toml
- 62 `print()` calls converted to structured `logger.*` calls in orchestrator
- Narrowed bare `except: pass` to specific exception types with debug logging
- Per-instance RAG offline TTL (5min) prevents repeated failed network calls
- Created `data/licenses.example.json` safe template, removed legacy `fix_version.py`

### Post-5.0.4 Review Fixes

#### Batch 1 — Quick Fixes (commit e162e46)
- **M4**: Moved function-level imports to module top in `webapp/main.py` — eliminated redundant `import logging`, `from webapp.user_manager`, `from webapp.stripe_integration`, `from license_manager`, and `from datetime import date` inside route handlers
- **M7**: Added `version` and `last_updated` metadata to `data/protocol_fingerprints.json`; `protocol_db.py` now logs loaded version and warns on legacy unversioned format; new test `test_load_versioned_format`
- **M11**: Replaced TODO comments with ACTION REQUIRED markers in `inflation_scaffold.py` generated exploit templates
- **L4**: Verified all Python subdirectories have `__init__.py` (all already present — no changes required)
- **L6**: Centralized `LICENSE_PREFIXES` in `license_manager.py`; `webapp/main.py` now imports the constant instead of redefining it

#### Batch 2 — Medium Fixes (commit f43ff0e)
- **M2**: Added `refine: Optional[Callable]` field to `HeuristicRule` dataclass; extracted inline rule-specific post-match logic for BLOCK_TIMESTAMP_RANDOMNESS, HARDCODED_ADDRESS, and UNCHECKED_EXTERNAL_CALL into standalone refiner functions; replaced ~50 lines of `if rule.id ==` blocks with a single generic `rule.refine()` call
- **M8**: Added pagination (`?page=&limit=`) to `/admin/users` and `/admin/licenses` endpoints in `webapp/auth.py` with `total`/`pages` metadata envelope; defaults to page=1, limit=50 for backward compatibility
- **M10**: Separated `exceptions.py` imports from optional `logger.py` fallbacks across 9 modules (`fingerprint_scanner.py`, `config_loader.py`, `protocol_db.py`, `exploit_generator.py`, `embeddings.py`, `rag_engine.py`, `history_scanner.py`, `pipeline_generator.py`, `red_team_scan.py`) — core exceptions now always required, logger remains optional with stdlib fallback

## [5.0.3] - 2026-04-23

### Fixed
- Add `lib/**` to default path exclusions for Foundry projects (reduces noise from dependency scanning)
- Auto-detect Foundry projects via `foundry.toml` and ensure `lib/**` is excluded
- Fingerprint scanner now honors path exclusions (was scanning ~1080 lib files, now only src/)
- Parse `foundry.toml` custom `out` directory and pass `--foundry-out-directory` to Slither
- Add `forge build --build-info` pre-step before Slither when using `--foundry-ignore-compile`
- Bump Slither and forge build timeouts from 300s to 600s for large Foundry projects
- Resolve mypy type errors and lint issues in red_team_scan.py

### Changed
- Documentation version references updated from 5.0.1 to 5.0.2 (carried forward)
- **Docker:** Updated multi-stage Docker image now bundles the complete 21-analyzer stack on Python 3.12, with docker-compose support for four service profiles (full audit, diagnostics, heuristic-only, symbolic execution)
- **Docker docs:** Added Docker deployment sections to QUICKSTART.md, DEPLOYMENT.md, and wiki Deployment pages; fixed health-check intervals, foundry-cache volume mount, and removed stale image tag prefixes
- **Marketing:** Updated landing page title to "Counterscarp | Smart Contract Audit & Vulnerability Scanner" for SEO; replaced "No Docker" messaging with "Run standalone or containerized"


## [5.0.2] - 2026-04-23

### Fixed
- STORAGE_COLLISION_RISK: deduplicate to 1 finding per contract (was 4-10x inflation)
- BLOCK_TIMESTAMP_RANDOMNESS: deadline comparisons downgraded to INFO (standard DeFi practice)
- HARDCODED_ADDRESS: exclude bytes32 constants (TYPEHASH, MASK, SLOT, etc.)
- UNCHECKED_EXTERNAL_CALL: verify return value capture before assigning CRITICAL

### Added
- Analyzer coverage section in reports with warning banners for failed analyzers
- Context-aware severity whitelist for known-safe patterns (OpenZeppelin, Uniswap)
- 16 new exploit template mappings (DELEGATECALL_USAGE, incorrect-return, reentrancy-eth, etc.)
- Educational template labels and contract-specific context in exploit PoCs
- Counter-suffixed exploit filenames to prevent overwrites
- RAG index seeded with 101 curated vulnerability entries across 12 categories
- Protocol fingerprint database expanded to 47 protocols (from 27)
- Fingerprint matching threshold lowered from 0.7 to 0.5 for better partial-fork detection
- --dev flag to bypass license gates for local testing
- PDF setup instructions in onboarding documentation


## [5.0.1] - 2026-04-22

### Fixed
- License validation API hardened against 500 errors with top-level exception handling, atomic database writes, and JSON structure validation
- Exploit PoC files now correctly land inside per-scan report directories instead of root exploits/ folder
- License validation URL path corrected to include /api prefix matching FastAPI router mount
- Per-scan report directories organize scan outputs by project name, date, and session ID to prevent overwrites
- Auth dependencies (passlib, authlib, httpx, itsdangerous) added to core dependencies for CI compatibility
- Input validation added to all API request models (license key format, machine ID length, version format)
- Rate limiting added to license validation and deactivation endpoints
- Stripe webhook signature verification made mandatory
- Admin endpoint /api/license/info now requires authentication
- CORS middleware configured for production origins
- Security event logging added for failed validations, deactivations, and webhook failures
- MANIFEST.in updated from garrison.toml to counterscarp.toml references
- Automated cleanup for state files, reports, uploads, and log rotation

### Security
- API hardening: input validation, rate limiting, authentication controls
- Stripe webhook: unsigned payloads now rejected when webhook secret is not configured
- Session secret: warning issued when using insecure default
- Path traversal protection on report download endpoints
- File upload validation ensures UTF-8 text content only

## [5.0.0] - 2026-04-22

### Added
- Complete rebrand from Garrison Engine to Counterscarp Engine
- User authentication with Google OAuth 2.0 and email/password registration
- Per-user license management — licenses linked to user accounts instead of server-wide
- Automatic license auto-linking at Stripe checkout for logged-in users
- Automatic license discovery on registration (links pre-purchased licenses by email)
- Auto-apply user license on login across any device
- Enhanced `/admin/users` endpoint with license key (masked), tier, auth method, and last login
- Login/register pages with dark theme matching existing UI
- Session-based authentication with cookie management
- Protected settings page (requires login)
- Conditional navigation bar (logged-in vs guest)

### Changed
- License activation moved from server-wide environment variable to per-user account storage
- Settings page license management now per-user with backward-compatible env var fallback
- Checkout success page shows auto-link confirmation for logged-in users or login prompt for guests

### Dependencies
- Added `authlib>=1.3.0`, `httpx>=0.25.0`, `itsdangerous>=2.1.0`, `passlib[bcrypt]>=1.7.4`

## [4.0.0] - 2026-04-21

### Added
- Stripe Checkout integration with automatic license key provisioning
- Pricing page with Pro Monthly and Pro Annual plans
- Webhook handler for `checkout.session.completed` events
- GUI-based license key management on settings page

## [3.4.0] - 2026-04-21

### Added
- Bundled offline threat intelligence database (`data/threat_intel_db.json`) with 63 vulnerability patterns for air-gapped deployments
- Automatic offline fallback in threat intel fetchers — network failures gracefully fall back to bundled database
- `offline_mode` and `bundled_db_path` configuration in `[threat_intel]` section
- `--update-signatures` CLI command to refresh threat intel and protocol databases on demand
- Graceful AI Copilot offline failure — scan continues without LLM enrichment when API is unreachable
- 11 new protocol fork signatures: SushiSwap, PancakeSwap, QuickSwap, Cream Finance, Venus, Benqi, Radiant Capital, Spark Protocol, GMX V1, GMX V2, Vela Exchange
- Fork-specific logic checks: AMM rounding errors, Compound oracle staleness, Aave flash loan callback validation, GMX price manipulation, fee-on-transfer handling
- Community protocol signature contribution system (`data/community_signatures/`, `data/protocol_template.json`)
- `docs/CONTRIBUTING_SIGNATURES.md` documentation for signature contributors
- `signature_updater.py` module for programmatic database updates

### Changed
- `--target` is no longer required when using `--update-signatures`
- Protocol database (`protocol_db.py`) now loads from JSON file as source of truth with hardcoded fallback
- `fingerprint_scanner.py` auto-loads community signatures and runs fork-specific checks after protocol matches
- `knowledge_fetcher.py` catches network errors and falls back to bundled threat intel
- `rag_engine.py` skips remaining enrichments after first offline detection to avoid repeated timeouts

## [3.3.0] - 2026-04-21

### Added
- Docker environment isolation with pinned tool versions (Slither 0.11.5, Aderyn 0.6.2, Medusa 0.1.8, Mythril 0.24.8, Foundry 1.0.0)
- Tool version manifest (`tool-versions.json`) for reproducible builds
- Container health check verifying all analyzer tools on startup
- `--preflight` CLI flag to validate tool versions before scanning
- Confidence scoring (1-10) for all 29 heuristic rules
- Inline suppression comments (`// counterscarp-suppress: RULE_ID [reason]`)
- `--min-confidence` CLI filter to set minimum confidence threshold
- `--min-severity` CLI filter to set minimum severity threshold
- `.dockerignore` for optimized Docker builds

### Changed
- Dockerfile now pins exact versions for all security analysis tools
- docker-compose.yml includes container health checks
- Report output shows confidence scores in executive summary, top-10 table, and finding details
- Config file (`counterscarp.toml`) supports `min_confidence` and `min_severity` under `[heuristics]`

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
- 5-tier pricing restructure (Community Free, Developer $49, Pro $199, Team $399, Enterprise Custom)
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
- Configurable execution profiles (counterscarp.toml, counterscarp-audit.toml, counterscarp-pr.toml, counterscarp-bounty.toml)
- Professional audit report generation (HTML, Markdown, SARIF, JSON)
- AI-powered RAG enrichment with customer-managed OpenAI API key

### Changed
- Migrated from open-source to commercial model with free Community tier

---

## Project History

**Counterscarp Engine** was originally developed as **Garrison Engine** (later briefly known as **Sentinel Engine**) starting in late 2024. The project was conceived as an automated smart contract security analysis platform combining static analysis, heuristic scanning, and AI-augmented audit capabilities.

### Timeline
- **2024 Q4** — Initial development as Garrison Engine; core heuristic scanner, Slither integration, and CLI framework
- **2025 Q1** — Rebranded to Sentinel Engine; added fingerprint scanning, exploit generation, and HTML/PDF reporting
- **2025 Q2** — Rebranded to Counterscarp Engine (v3.0.0); domain moved to counterscarp.io; added RAG-powered audit copilot, protocol fingerprinting, and the webapp
- **2025 Q3** — v4.x series: Stripe integration, license management, Docker distribution, VPS deployment
- **2025 Q4–2026** — v5.x series: PyPI distribution, GitHub Actions CI/CD, comprehensive code review hardening
