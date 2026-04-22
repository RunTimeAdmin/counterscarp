# Web Application Guide

> **Live Demo:** [https://counterscarp.io](https://counterscarp.io) — Official beta instance

## Table of Contents

- [Overview](#overview)
- [Accessing the Web UI](#accessing-the-web-ui)
- [Upload Flow Walkthrough](#upload-flow-walkthrough)
- [Understanding the Results Page](#understanding-the-results-page)
- [Downloading Reports](#downloading-reports)
- [Attack Graph Visualization](#attack-graph-visualization)
- [User Authentication](#user-authentication)
- [Per-User License Management](#per-user-license-management)
- [Admin Dashboard](#admin-dashboard)
- [API Endpoints Reference](#api-endpoints-reference)
- [API Rate Limiting](#api-rate-limiting)
- [CORS Policy](#cors-policy)

---

## Overview

The Counterscarp Engine web application provides a browser-based interface for running security audits on smart contracts. Upload `.sol` or `.rs` files, run a full analysis pipeline, and view results with risk scoring, severity breakdowns, and AI-powered insights — all without the CLI.

The web app is built with FastAPI and runs on uvicorn, supporting both local development and production deployment behind nginx.

---

## Accessing the Web UI

### Local Development

```bash
pip install "counterscarp-engine[web]"
uvicorn webapp.main:app --reload --port 8001
```

Open **http://localhost:8001** in your browser.

### Production (Official Beta)

The official beta instance is available at **https://counterscarp.io**.

This is the live production deployment where you can:
- Upload and audit smart contracts without any local installation
- Generate professional security reports
- Explore interactive attack graphs
- Download findings in multiple formats (HTML, Markdown, SARIF, JSON)

See the [Deployment Guide](DEPLOYMENT.md) for instructions on setting up your own instance.

---

## Upload Flow Walkthrough

1. **Open the upload page** — Navigate to the root URL (`/`)
2. **Enter project name** — Provide a descriptive name for the audit (e.g., "MyProtocol V2")
3. **Select files** — Click to browse or drag-and-drop `.sol` or `.rs` files
   - Maximum file size: **10 MB** per file
   - Supported formats: **individual `.sol` (Solidity) or `.rs` (Rust/Anchor) source files** — ZIP archives are not currently supported
   - To upload a multi-file project, select all source files at once using your OS file picker (Ctrl+click or Shift+click)
4. **Click "Run Audit"** — The analysis pipeline starts immediately
5. **Wait for results** — You'll be redirected to the results page when complete (120-second timeout for web uploads)

### Cross-File Analysis

Upload all related contract files together in a single submission. The engine analyses the full file set as one project, enabling detection of:

- **Cross-contract reentrancy** — attack paths that span multiple contracts
- **Shared state issues** — storage variables and proxy patterns across inheritance hierarchies
- **Inter-contract access control** — privilege escalation paths through delegatecall chains

Uploading contracts in separate sessions creates isolated audits and will miss vulnerabilities that only emerge from contract interactions.

### Server Limits

| Constraint | Limit |
|------------|-------|
| Max file size | 10 MB per file |
| Scan timeout | 120 seconds |
| Supported formats | `.sol` (Solidity) and `.rs` (Rust/Anchor) source files |

---

## Understanding the Results Page

The results page at `/results/{audit_id}` provides a comprehensive view of the audit findings.

### Scan Coverage Section

The scan coverage panel shows which analyzers ran and how many patterns they checked:

| Analyzer | What It Shows |
|----------|---------------|
| Heuristic Pattern Scanner | Number of patterns checked per category, findings count |
| Slither Static Analysis | Status (completed / not_installed / timeout / error), findings count |
| AI Audit Copilot | Status (completed / error / skipped) |
| Attack Graph Generator | Status (completed / skipped) |

### Risk Score Interpretation

The risk score is calculated on a 0-100 scale using weighted severity counts:

| Score Range | Status | Meaning |
|-------------|--------|---------|
| 0-19 | PASS | No significant issues detected |
| 20-39 | PASS / WARNING | Low-risk findings only |
| 40-69 | WARNING | High-severity findings present |
| 70-100 | FAIL | Critical or multiple high findings |

**Weighting formula:**
- CRITICAL = 10.0 points
- HIGH = 5.0 points
- MEDIUM = 2.0 points
- LOW = 0.5 points
- INFO = 0.1 points

### Severity Breakdown

The severity breakdown shows the count of findings at each level:

| Severity | Color | Typical Impact |
|----------|-------|----------------|
| CRITICAL | Red | Exploitable vulnerabilities leading to direct fund loss |
| HIGH | Orange | Serious vulnerabilities requiring immediate attention |
| MEDIUM | Yellow | Issues that could become exploitable under specific conditions |
| LOW | Blue | Minor issues or best practice violations |
| INFO | Gray | Informational findings, no direct security impact |

### AI Copilot Insights

When the AI Audit Copilot is available, it provides:

- **Similarity search** — Matches current findings against the RAG knowledge base of known vulnerabilities
- **Remediation guidance** — Suggests fixes based on historical patterns
- **Context enrichment** — Adds relevant references and CWE classifications

**Note:** The AI Copilot uses local sentence-transformers embeddings by default. No API keys are required. Install with `pip install "counterscarp-engine[ai]"`.

### Per-Scan Report Directory

Each scan creates an isolated output directory so multiple scans of the same project never overwrite each other:

```
reports/{ProjectName}_{YYYY-MM-DD}_{session}/
├── audit_report.md
├── audit_report.html
├── ACTION_PLAN.md
├── scan.log
└── exploits/          ← Exploit PoC files (Pro+ only)
```

- `{ProjectName}` is the name entered at upload time
- `{YYYY-MM-DD}` is the scan date
- `{session}` is a short unique identifier for the run

Running the same project on different days (or multiple times in a day) creates separate directories; no results are overwritten.

### Exploit PoC Files

When scanning with a Pro (or higher) license, the results page includes auto-generated Foundry exploit test files for critical and high-severity findings.

- Each CRITICAL or HIGH finding includes a link to a `.t.sol` Foundry test that demonstrates the attack vector
- The test file is runnable with `forge test` against a local Anvil fork — no manual scaffolding required
- Individual PoC files can be downloaded from the finding detail panel, or you can download the full `exploits/` directory as a ZIP from the results page footer
- Exploit PoCs are stored in the `exploits/` subdirectory within the per-scan report folder

**Requirements:** Foundry must be installed locally to execute the generated tests. See [foundry.paradigm.xyz](https://foundry.paradigm.xyz) for installation instructions.

---

## Downloading Reports

Four report formats are available for download from the results page:

| Format | URL Pattern | Content Type |
|--------|-------------|-------------|
| HTML | `/results/{id}/report/html` | `text/html` |
| Markdown | `/results/{id}/report/md` | `text/markdown` |
| SARIF | `/results/{id}/report/sarif` | `application/json` |
| JSON | `/results/{id}/report/json` | `application/json` |

For detailed information about each format, see the [Report Formats Guide](REPORT_FORMATS.md).

---

## Attack Graph Visualization

The attack graph is an interactive D3.js visualization that shows:

- **Contract structure** — Functions, state variables, and their relationships
- **Attack paths** — How findings connect through external calls and state changes
- **Severity mapping** — Color-coded nodes indicating vulnerability severity
- **Interactive exploration** — Click to expand/collapse nodes and trace paths

Access the attack graph at: `/results/{audit_id}/attack-graph`

The attack graph is generated automatically when findings are detected. If no findings exist, the graph is skipped.

**Configuration:** Attack graph behavior can be customized in `counterscarp.toml` under the `[visualization]` section. See the [Configuration Guide](CONFIGURATION.md#visualization) for details.

---

## User Authentication

The web application supports two authentication methods:

**Google OAuth 2.0:**
- Click "Sign in with Google" on the login page
- First-time users are automatically registered
- Uses OpenID Connect for secure token exchange

**Email/Password:**
- Register at `/auth/register` with name, email, and password
- Passwords are hashed with bcrypt
- Log in at `/auth/login`

---

## Per-User License Management

Licenses are linked to individual user accounts:

- **Automatic linking at purchase:** When a logged-in user completes a Stripe checkout, their license is automatically linked to their account
- **Automatic linking at registration:** If a user purchases before creating an account, the license is automatically discovered and linked when they register with the same email
- **Manual activation:** Users can enter a license key manually on the Settings page
- **Cross-device:** Licenses persist with the account and activate on login from any device

---

## Admin Dashboard

The `/admin/users` endpoint (JSON API) is restricted to the configured `ADMIN_EMAIL` and returns:
- User list with email, name, auth method, registration date, last login
- License key (masked) and current tier for each user

**Authentication required:** `/api/license/info` requires an active session **and** the logged-in user's email must match the `ADMIN_EMAIL` environment variable. All other authenticated users receive `403 Forbidden`.

---

## API Endpoints Reference

### `GET /`

Upload page (HTML form).

### `POST /audit`

Run a security audit on uploaded files.

**Request:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `project_name` | string | Yes | Name for the audit |
| `files` | File[] | Yes | `.sol` or `.rs` files (max 10 MB each) |

**Response:** Redirects to `/results/{audit_id}` (303).

**Errors:**

| Status | Condition |
|--------|-----------|
| 400 | No files uploaded |
| 400 | Invalid file type (not `.sol` or `.rs`) |
| 400 | File exceeds 10 MB limit |

### `GET /results/{audit_id}`

Display audit results page.

**Response:** HTML page with findings, risk score, severity breakdown, and download links.

**Errors:**

| Status | Condition |
|--------|-----------|
| 404 | Audit ID not found |

### `GET /results/{audit_id}/report/{format}`

Download a report file.

**Format options:** `html`, `md`, `sarif`, `json`

**Response:** File download with appropriate content type.

**Errors:**

| Status | Condition |
|--------|-----------|
| 400 | Invalid format |
| 404 | Report file not found |

### `GET /results/{audit_id}/attack-graph`

View the interactive attack graph visualization.

**Response:** HTML page with embedded D3.js graph.

**Errors:**

| Status | Condition |
|--------|-----------|
| 404 | Attack graph not generated (no findings or generation failed) |

### `GET /health`

Health check endpoint.

**Response:**

```json
{
  "status": "ok",
  "timestamp": "2024-01-15T10:30:00.000000"
}
```

---

### API Rate Limiting

Rate limiting is enforced per IP address on license and webhook endpoints to protect against abuse.

| Endpoint | Method | Limit |
|----------|--------|-------|
| `/api/license/validate` | POST | 10 requests per minute |
| `/api/license/deactivate` | POST | 5 requests per minute |
| `/api/stripe/webhook` | POST | 30 requests per minute |

**Response when exceeded:** `HTTP 429`

```json
{"detail": "Rate limit exceeded. Try again later."}
```

Rate limit windows reset after **60 seconds**. If you are hitting limits from a CI/CD pipeline, consider caching validation results locally rather than re-validating on every run.

---

### CORS Policy

The API accepts cross-origin requests only from the following origins:

- `https://app.counterscarp.io`
- `https://counterscarp.io`
- `http://localhost` (any port, for local development)

Requests from any other origin are rejected with `HTTP 403`. If you are self-hosting and need to add a custom origin, configure the `ALLOWED_ORIGINS` environment variable before starting the server.

---

*Counterscarp Security Engine &bull; counterscarp.io*
