# Configuration Reference

## Table of Contents

- [Overview](#overview)
- [Config File Discovery](#config-file-discovery)
- [Section Reference](#section-reference)
  - [engine](#engine)
  - [heuristics](#heuristics)
  - [[suppressions]](#suppressions)
  - [static_analysis](#static_analysis)
  - [fuzzing](#fuzzing)
  - [red_team](#red_team)
  - [external_tools](#external_tools)
  - [supply_chain](#supply_chain)
  - [threat_intel](#threat_intel)
  - [http](#http)
  - [chains](#chains)
  - [upgrade_diff](#upgrade_diff)
  - [reporting](#reporting)
  - [ci](#ci)
  - [exploit_generation](#exploit_generation)
  - [history](#history)
  - [visualization](#visualization)
  - [fingerprint](#fingerprint)
  - [ai](#ai)
  - [plugins](#plugins)
  - [Authentication Settings](#authentication-settings)
  - [Session and Authentication](#session-and-authentication)
  - [Cleanup Retention Periods](#cleanup-retention-periods)
- [Example Configs](#example-configs)

---

## Overview

Counterscarp Engine is configured via a `counterscarp.toml` file in TOML format. The configuration controls all aspects of the analysis pipeline: which rules are active, what severity thresholds apply, how reports are generated, and which external tools are used.

All settings have sensible defaults — a minimal config with zero customisation works out of the box.

---

## Config File Discovery

If `--config` is not specified, Counterscarp Engine searches for `counterscarp.toml` in the current directory and up to 5 parent directories. If no file is found, built-in defaults are used.

---

## Section Reference

### `[engine]`

Engine-wide settings that control the overall analysis behavior.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | `"Counterscarp Security Engine"` | Display name for reports |
| `version` | string | `"3.1.3"` | Engine version string |
| `fail_on_severity` | string | `"HIGH"` | Minimum severity to fail CI: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO` |
| `max_findings` | int | `0` | Maximum findings before stopping scan (`0` = unlimited) |

```toml
[engine]
name = "MyProtocol Security Audit"
fail_on_severity = "MEDIUM"
max_findings = 500
```

---

### `[heuristics]`

Controls the heuristic pattern scanner (31 EVM rules). See [Rules Catalog](RULES_CATALOG.md) for the full rule list.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Global toggle for all heuristic scanning |

#### `[heuristics.severity_overrides]`

Override the default severity of specific rules.

| Key | Type | Description |
|-----|------|-------------|
| `RULE_ID` | string | New severity level (e.g., `"LOW"`) |

```toml
[heuristics.severity_overrides]
BLOCK_TIMESTAMP_RANDOMNESS = "LOW"  # Downgrade for time-based contracts
```

#### `[heuristics.disabled_rules]`

Disable individual rules entirely.

| Key | Type | Description |
|-----|------|-------------|
| `RULE_ID` | bool | Set to `true` to disable the rule |

```toml
[heuristics.disabled_rules]
HARDCODED_ADDRESS = true           # Expected for oracle contracts
BLOCK_TIMESTAMP_RANDOMNESS = true  # Used for timelock/vesting
DIVIDE_BEFORE_MULTIPLY = true      # Project uses safe precision patterns
```

---

### `[[suppressions]]`

Suppress individual findings as accepted risks or false positives. Each suppression is a TOML array-of-tables entry.

| Key | Type | Required | Description |
|-----|------|----------|-------------|
| `rule_id` | string | Yes | Rule ID to suppress |
| `file` | string | No | File path to scope suppression (omitting = global) |
| `line` | int | No | Specific line number to scope |
| `reason` | string | No | Human-readable explanation |
| `expires` | string | No | ISO date string when suppression expires (e.g. `"2025-12-31"`) |

```toml
[[suppressions]]
rule_id = "HARDCODED_ADDRESS"
file = "contracts/Oracle.sol"
reason = "Oracle address is intentionally hardcoded per deployment"

[[suppressions]]
rule_id = "EMERGENCY_WITHDRAW_PUBLIC"
reason = "All emergency functions have onlyOwner, heuristic is false positive"
expires = "2025-12-31"
```

### Inline Comment Suppressions

You can suppress findings directly in your source code using special comments:

```solidity
// counterscarp-suppress: RULE_ID reason: explanation
function riskyOperation() external {
    // This line will not trigger RULE_ID
}
```

**Supported formats:**
- `// counterscarp-suppress: RULE_ID` — suppress without reason
- `// counterscarp-suppress: RULE_ID reason: explanation` — suppress with documented reason
- `// counterscarp-suppress: RULE_ID_1, RULE_ID_2` — suppress multiple rules on one line

Inline suppressions take precedence over TOML suppressions for the same file and line.

### Migrating from Garrison Engine (pre-v5.0.0)

If upgrading from Garrison Engine, rename your config file and update references:
1. Rename `garrison.toml` → `counterscarp.toml`
2. Update environment variables: `GARRISON_*` → `COUNTERSCARP_*`
3. Update data directory: `.garrison/` → `.counterscarp/`

---

### `[static_analysis]`

Configures static analysis tools (Slither, Aderyn).

#### `[static_analysis.slither]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable Slither analysis |
| `exclude_detectors` | string | `""` | Comma-separated detector names to exclude |
| `include_impact` | string | `"High,Medium"` | Only show issues with these impact levels |

#### `[static_analysis.aderyn]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Aderyn analysis (opt-in) |
| `scope` | string | `""` | Limit analysis to specific paths |

```toml
[static_analysis.slither]
enabled = true
exclude_detectors = "similar-names,unused-state"
include_impact = "High,Medium,Low"

[static_analysis.aderyn]
enabled = true
scope = "src/"
```

---

### `[fuzzing]`

Configures fuzzing tools (Foundry, Medusa).

#### `[fuzzing.foundry]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Foundry fuzzing |
| `runs` | int | `10000` | Number of fuzz runs |
| `max_test_rejects` | int | `100000` | Maximum rejected inputs before stopping |

#### `[fuzzing.medusa]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Medusa coverage-guided fuzzing |
| `test_limit` | int | `100000` | Maximum test sequences |
| `timeout` | int | `300` | Timeout in seconds |
| `workers` | int | `10` | Number of parallel workers |

```toml
[fuzzing.foundry]
enabled = true
runs = 50000

[fuzzing.medusa]
enabled = true
test_limit = 500000
timeout = 600
workers = 16
```

---

### `[red_team]`

Red team scan configuration for Slither-based vulnerability filtering.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `severity_allowlist` | list | `["High", "Medium"]` | Severity levels to include |
| `ignore_checks` | list | `["solc-version", ...]` | Slither check IDs to ignore |

```toml
[red_team]
severity_allowlist = ["High", "Medium", "Low"]
ignore_checks = ["solc-version", "naming-convention"]
```

---

### `[external_tools]`

Timeouts and settings for external analysis tools.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `aderyn_timeout` | int | `120` | Aderyn timeout in seconds |
| `mythril_timeout` | int | `600` | Mythril timeout in seconds |
| `foundry_fuzz_runs` | int | `1000` | Foundry fuzz default runs |

```toml
[external_tools]
aderyn_timeout = 300
mythril_timeout = 900
foundry_fuzz_runs = 5000
```

---

### `[supply_chain]`

Supply chain vulnerability scanning via OSV (Open Source Vulnerabilities) API.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ecosystem` | string | `"npm"` | Package ecosystem (`npm`, `pypi`, etc.) |
| `osv_timeout` | int | `10` | OSV API timeout in seconds |
| `osv_max_retries` | int | `3` | OSV API max retries |
| `osv_rate_limit` | int | `10` | OSV API rate limit (requests/sec) |

```toml
[supply_chain]
ecosystem = "pypi"
osv_timeout = 15
```

---

### `[threat_intel]`

Threat intelligence source configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `c4_timeout` | int | `10` | Code4rena GitHub API timeout (seconds) |
| `immunefi_timeout` | int | `10` | Immunefi RSS feed timeout (seconds) |
| `solana_github_timeout` | int | `10` | Solana GitHub API timeout (seconds) |
| `api_rate_limit` | int | `5` | Default API rate limit (requests/sec) |

```toml
[threat_intel]
c4_timeout = 30
immunefi_timeout = 30
api_rate_limit = 3
```

---

### `[http]`

HTTP client settings used for all API calls (OSV, Code4rena, Immunefi, etc.).

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `default_timeout` | int | `30` | Default request timeout (seconds) |
| `max_retries` | int | `3` | Maximum retries for failed requests |
| `base_delay` | float | `1.0` | Base delay for exponential backoff (seconds) |
| `max_delay` | float | `30.0` | Maximum delay cap for backoff (seconds) |
| `backoff_factor` | float | `2.0` | Backoff multiplier |

```toml
[http]
default_timeout = 60
max_retries = 5
backoff_factor = 3.0
```

---

### `[chains]`

Chain-specific configuration for EVM and Solana.

#### `[chains.solana]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable Solana analysis |
| `project_root` | string | `"./programs"` | Path to Solana program root |

#### `[chains.solana.idl]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `idl_path` | string | `"target/idl"` | Path to IDL files |
| `validate_constraints` | bool | `true` | Validate account constraints in IDL |
| `trace_cpi` | bool | `true` | Trace Cross-Program Invocations |

#### `[chains.evm]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `solc_version` | string | `">=0.8.0"` | Expected Solidity compiler version |
| `trusted_contracts` | list | `[]` | Known safe contract addresses (won't flag as risky) |

```toml
[chains.solana]
enabled = true
project_root = "./programs"

[chains.solana.idl]
idl_path = "target/idl"
validate_constraints = true
trace_cpi = true

[chains.evm]
solc_version = ">=0.8.0"
trusted_contracts = [
    "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  # USDC
    "0xdAC17F958D2ee523a2206206994597C13D831ec7",  # USDT
]
```

---

### `[upgrade_diff]`

Upgrade safety analysis for proxy contract upgrades.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `old_implementation_path` | string | `""` | Path to old implementation |
| `new_implementation_path` | string | `""` | Path to new implementation |

#### `[upgrade_diff.ignore_patterns]`

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `ignore_new_view_functions` | bool | `true` | Ignore new view functions (read-only) |
| `ignore_comment_changes` | bool | `true` | Ignore NatSpec/comment-only changes |

```toml
[upgrade_diff]
old_implementation_path = "contracts/old/Implementation.sol"
new_implementation_path = "contracts/Implementation.sol"

[upgrade_diff.ignore_patterns]
ignore_new_view_functions = false  # Flag new view functions too
ignore_comment_changes = true
```

---

### `[reporting]`

Report generation settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `format` | string | `"markdown"` | Output format: `markdown`, `json`, `sarif`, `html` |
| `verbosity` | string | `"standard"` | Verbosity: `minimal`, `standard`, `verbose` |
| `group_by` | string | `"severity"` | Group findings by: `severity`, `file`, `rule` |

#### `[reporting.sections]`

Toggle which sections appear in the report.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `executive_summary` | bool | `true` | Include executive summary |
| `supply_chain` | bool | `true` | Include supply chain analysis |
| `static_analysis` | bool | `true` | Include static analysis results |
| `heuristic_scan` | bool | `true` | Include heuristic scan results |
| `fuzzing` | bool | `false` | Include fuzzing results (opt-in) |
| `threat_intel` | bool | `false` | Include threat intelligence (opt-in) |
| `access_matrix` | bool | `true` | Include access control matrix |

```toml
[reporting]
format = "html"
verbosity = "verbose"
group_by = "severity"

[reporting.sections]
executive_summary = true
fuzzing = true
threat_intel = true
```

#### Per-Scan Output Directory Structure

Each scan produces an isolated output directory with the following naming pattern:

```
reports/{project_name}_{YYYY-MM-DD}_{session_id}/
```

**Example:**

```
reports/myprotocol_2026-04-22_a3f9b12c/
├── audit_report.md       # Full Markdown audit report
├── audit_report.html     # HTML version with styling
├── ACTION_PLAN.md        # Prioritised remediation action plan
├── scan.log              # Full scan log for this session
└── exploits/             # Auto-generated exploit PoCs (if enabled)
    ├── exploit_REENTRANCY_001.sol
    └── exploit_ACCESS_CONTROL_002.sol
```

Each scan is fully self-contained — reports from different scans never overwrite each other. The `session_id` is a short random identifier appended to prevent collisions when scanning the same project multiple times on the same day.

> **Cleanup:** Report directories older than **90 days** are automatically purged on service startup. See [Cleanup Retention Periods](#cleanup-retention-periods) below.

---

### `[ci]`

CI/CD integration settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `fail_on_findings` | bool | `true` | Fail pipeline if findings detected |
| `post_pr_comment` | bool | `true` | Post results as PR comment (GitHub Actions) |
| `upload_sarif` | bool | `false` | Upload SARIF to GitHub Security tab |
| `exclude_paths` | list | `["test/**", ...]` | Glob patterns for paths to exclude |

#### `[ci.generator]`

CI/CD pipeline generation settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `platform` | string | `"github"` | Target platform: `github`, `gitlab`, `azure`, `jenkins` |
| `triggers` | list | `["push", "pull_request"]` | Pipeline triggers |
| `notifications` | list | `[]` | Notification channels: `slack`, `discord` |
| `custom_steps` | list | `[]` | Custom steps to add to pipeline |

```toml
[ci]
fail_on_findings = true
upload_sarif = true
exclude_paths = ["test/**", "script/**", "node_modules/**"]

[ci.generator]
platform = "github"
triggers = ["push", "pull_request"]
notifications = ["slack"]
```

---

### `[exploit_generation]`

Auto-generate Foundry test exploits for findings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `auto_generate` | bool | `false` | Auto-generate exploits for findings |
| `min_severity` | string | `"HIGH"` | Minimum severity to generate exploits: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `validate_compilation` | bool | `true` | Verify generated exploits compile with `forge build` |
| `output_dir` | string | `"exploits/"` | Directory for generated exploit files |
| `llm_backend` | string | `"none"` | LLM backend: `none`, `openai`, `anthropic` |
| `template_dir` | string | `"exploit_templates/"` | Directory containing exploit templates |

```toml
[exploit_generation]
auto_generate = true
min_severity = "HIGH"
llm_backend = "none"  # Use local templates only
```

---

### `[history]`

Time-travel historical vulnerability scanning.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `max_commits` | int | `50` | Maximum commits to scan |
| `scan_branches` | list | `["main"]` | Branches to scan |
| `include_fixed` | bool | `true` | Include fixed vulnerabilities in reports |
| `output_dir` | string | `"."` | Output directory for history scan reports |

```toml
[history]
max_commits = 200
scan_branches = ["main", "develop"]
include_fixed = true
```

---

### `[visualization]`

Attack graph visualization settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Generate attack graph visualizations |
| `include_source_analysis` | bool | `true` | Parse contracts for structure |
| `trace_attack_paths` | bool | `true` | Trace attack paths through external calls |
| `output_format` | string | `"html"` | Output format: `html`, `json`, `both` |
| `max_path_depth` | int | `10` | Maximum depth for attack path tracing (`0` = unlimited) |

```toml
[visualization]
enabled = true
output_format = "both"
max_path_depth = 15
```

---

### `[fingerprint]`

Protocol fingerprint similarity scanning.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `false` | Enable fingerprint scanning |
| `min_similarity` | float | `0.7` | Minimum similarity threshold (0.0-1.0) |
| `database_path` | string | `"data/protocol_fingerprints.json"` | Path to fingerprint database |
| `include_risk_assessment` | bool | `true` | Include risk assessment in results |

```toml
[fingerprint]
enabled = true
min_similarity = 0.6
database_path = "data/protocol_fingerprints.json"
```

---

### `[ai]`

AI and RAG (Retrieval-Augmented Generation) configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `embedding_backend` | string | `"local"` | Embedding backend: `local`, `openai`, `anthropic` |
| `llm_backend` | string | `"none"` | LLM backend: `none`, `openai`, `anthropic` |
| `openai_model` | string | `"gpt-4-turbo-preview"` | OpenAI model for LLM features |
| `rag_index_path` | string | `".counterscarp/rag_index.json"` | Path to RAG vector index |
| `top_k` | int | `5` | Number of similar findings to retrieve |
| `auto_enrich` | bool | `false` | Automatically enrich findings with RAG |

```toml
[ai]
embedding_backend = "local"   # Uses sentence-transformers (no API key needed)
llm_backend = "none"          # Disable LLM features
top_k = 5
auto_enrich = false
```

**Note:** The `local` embedding backend uses `sentence-transformers` and works offline with no API keys required. Install with `pip install "counterscarp-engine[ai]"`.

---

### `[plugins]`

Plugin system for community-contributed analyzers and rules.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | `true` | Enable plugin system |
| `dirs` | list | `[".counterscarp/plugins"]` | Directories to scan for plugin modules |

```toml
[plugins]
enabled = true
dirs = [".counterscarp/plugins", "/opt/counterscarp-plugins"]
```

See the [Plugin Development Guide](PLUGIN_DEVELOPMENT.md) for writing custom plugins.

---

### Authentication Settings

Authentication is configured via environment variables (not the TOML config file):

- `SESSION_SECRET` — Secret key for cookie-based session encryption
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` — Google OAuth credentials
- `GOOGLE_REDIRECT_URI` — OAuth callback URL
- `ADMIN_EMAIL` — Admin user email for `/admin/users` access

**Note:** Authentication settings are intentionally kept in environment variables (not config files) for security. Never commit OAuth credentials to version control.

---

### Session and Authentication

#### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SESSION_SECRET` | **REQUIRED** in production | — | Secret key for cookie-based session encryption. A warning is logged on startup if not set. Generate with: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `ADMIN_EMAIL` | **REQUIRED** in production | — | Email address of the admin user. Restricts access to `/api/license/info` to this account. |
| `STRIPE_WEBHOOK_SECRET` | **REQUIRED** if accepting payments | — | Stripe webhook signing secret (`whsec_...`). Service returns HTTP 500 on webhook receipt if not configured. |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth 2.0 client ID (from Google Cloud Console) |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth 2.0 client secret |
| `GOOGLE_REDIRECT_URI` | No | `http://localhost:8001/auth/google/callback` | OAuth callback URL. Set to `https://app.counterscarp.io/auth/google/callback` in production. |

#### CORS Allowed Origins

The web application allows cross-origin requests from the following origins:

| Origin | Purpose |
|--------|---------|
| `https://app.counterscarp.io` | Production web app |
| `https://counterscarp.io` | Marketing site |
| `http://localhost:8000` | Local development (default port) |
| `http://localhost:8001` | Local development (alternate port) |

Additional origins can be added by modifying `webapp/main.py`. Never add wildcard origins (`*`) in production.

#### Security Notes

- `SESSION_SECRET` should be at least 32 characters of cryptographically random data. A warning is issued at startup if the variable is missing or too short, but the service will still start (for local development convenience).
- In production, always set `SESSION_SECRET` in the systemd unit file under `[Service]` — not in a `.env` file that could be world-readable.
- `ADMIN_EMAIL` gates access to `/api/license/info`. Without it set, the endpoint is inaccessible.

---

### Cleanup Retention Periods

The service automatically purges stale working data on startup. The following retention periods are currently hardcoded (configurable via `counterscarp.toml` is planned for a future release):

| Data Type | Location | Retention |
|-----------|----------|-----------|
| State / cache files | `.counterscarp/` | **30 days** |
| Report directories | `reports/` | **90 days** |
| Upload directories | `uploads/` | **7 days** |

**Behavior:**
- Cleanup runs once on service startup, before the first request is handled.
- Only directories and files older than the threshold (based on last-modified time) are removed.
- Files actively in use (e.g., open file handles) are skipped safely.
- A startup log entry is written for each directory purged.

> These values are hardcoded in the current release. A `[cleanup]` TOML section with per-type retention keys is planned for v5.1.0.

---

## Example Configs

### PR Mode — Fast CI Gate

```toml
[engine]
name = "PR Security Gate"
fail_on_severity = "HIGH"
max_findings = 50

[heuristics]
enabled = true

[heuristics.disabled_rules]
HARDCODED_ADDRESS = true
BLOCK_TIMESTAMP_RANDOMNESS = true

[static_analysis]
[static_analysis.slither]
enabled = true
include_impact = "High,Medium"

[reporting]
format = "markdown"
verbosity = "minimal"

[ci]
fail_on_findings = true
post_pr_comment = true
```

### Audit Mode — Full Professional Audit

```toml
[engine]
name = "Full Security Audit"
fail_on_severity = "MEDIUM"
max_findings = 0

[heuristics]
enabled = true

[reporting]
format = "html"
verbosity = "verbose"
group_by = "severity"

[reporting.sections]
executive_summary = true
supply_chain = true
static_analysis = true
heuristic_scan = true
fuzzing = true
threat_intel = true
access_matrix = true

[visualization]
enabled = true
output_format = "both"

[fingerprint]
enabled = true
min_similarity = 0.6
```

### Bounty Mode — Maximum Depth

```toml
[engine]
name = "Bug Bounty Deep Scan"
fail_on_severity = "LOW"
max_findings = 0

[heuristics]
enabled = true

[static_analysis]
[static_analysis.slither]
enabled = true
include_impact = "High,Medium,Low,Informational"

[static_analysis.aderyn]
enabled = true

[fuzzing]
[fuzzing.foundry]
enabled = true
runs = 50000

[fuzzing.medusa]
enabled = true
test_limit = 500000
timeout = 600
workers = 16

[exploit_generation]
auto_generate = true
min_severity = "MEDIUM"
llm_backend = "none"

[ai]
embedding_backend = "local"
auto_enrich = true
top_k = 10

[visualization]
enabled = true
output_format = "both"
max_path_depth = 0  # Unlimited
```

---

*Counterscarp Security Engine &bull; counterscarp.io*
