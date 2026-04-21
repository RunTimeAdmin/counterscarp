# Web Application Guide

> **Live Demo:** [https://garrisonsec.io](https://garrisonsec.io) — Official beta instance

## Table of Contents

- [Overview](#overview)
- [Accessing the Web UI](#accessing-the-web-ui)
- [Upload Flow Walkthrough](#upload-flow-walkthrough)
- [Understanding the Results Page](#understanding-the-results-page)
- [Downloading Reports](#downloading-reports)
- [Attack Graph Visualization](#attack-graph-visualization)
- [API Endpoints Reference](#api-endpoints-reference)

---

## Overview

The Garrison Engine web application provides a browser-based interface for running security audits on smart contracts. Upload `.sol` or `.rs` files, run a full analysis pipeline, and view results with risk scoring, severity breakdowns, and AI-powered insights — all without the CLI.

The web app is built with FastAPI and runs on uvicorn, supporting both local development and production deployment behind nginx.

---

## Accessing the Web UI

### Local Development

```bash
pip install "garrison-engine[web]"
uvicorn webapp.main:app --reload --port 8001
```

Open **http://localhost:8001** in your browser.

### Production (Official Beta)

The official beta instance is available at **https://garrisonsec.io**.

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
3. **Select files** — Click to browse or drag-and-drop `.sol` and/or `.rs` files
   - Maximum file size: **10 MB** per file
   - Supported extensions: `.sol`, `.rs`
4. **Click "Run Audit"** — The analysis pipeline starts immediately
5. **Wait for results** — You'll be redirected to the results page when complete

**Tip:** Upload all related contract files at once for cross-contract analysis and accurate attack graph generation.

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

**Note:** The AI Copilot uses local sentence-transformers embeddings by default. No API keys are required. Install with `pip install "garrison-engine[ai]"`.

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

**Configuration:** Attack graph behavior can be customized in `garrison.toml` under the `[visualization]` section. See the [Configuration Guide](CONFIGURATION.md#visualization) for details.

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

*Garrison Security Engine &bull; garrisonsec.io*
