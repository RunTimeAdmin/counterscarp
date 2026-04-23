# Report Formats Guide

## Table of Contents

- [Overview](#overview)
- [Per-Scan Report Directories](#per-scan-report-directories)
- [HTML Report](#html-report)
- [Markdown Report](#markdown-report)
- [SARIF 2.1.0 Format](#sarif-21-format)
- [JSON Format](#json-format)
- [PDF Report](#pdf-report)
- [Customizing Reports via Configuration](#customizing-reports-via-configuration)
- [Logo Branding](#logo-branding)

---

## Overview

Counterscarp Engine generates audit reports in four formats, each serving a different audience and use case:

| Format | Extension | Best For | Audience |
|--------|-----------|----------|----------|
| HTML | `.html` | Presenting to clients, stakeholder review | Security teams, management |
| Markdown | `.md` | GitHub/GitLab integration, developer review | Developers, CI/CD |
| SARIF | `.sarif` | GitHub Advanced Security, automated tooling | CI/CD pipelines, IDE integrations |
| JSON | `.json` | Programmatic processing, custom tooling | Automation, scripts |

All reports share the same underlying data (findings, severity counts, risk scores) but present it differently.

---

## Per-Scan Report Directories

Each scan creates an isolated output directory, ensuring that multiple scans of the same project never overwrite previous results.

### Directory Structure

```
reports/{ProjectName}_{YYYY-MM-DD}_{session}/
├── audit_report.md
├── audit_report.html
├── ACTION_PLAN.md
├── scan.log
└── exploits/               ← Exploit PoC .t.sol files (Pro+ only)
```

| Component | Description |
|-----------|-------------|
| `{ProjectName}` | The project name provided at scan time |
| `{YYYY-MM-DD}` | The date the scan was run |
| `{session}` | Short unique identifier for the specific run |

### Key Behaviors

- **Isolation:** Each scan has its own directory — no report files are overwritten by subsequent scans
- **Multiple scans of the same project** create separate directories (e.g., `MyProtocol_2026-04-22_a1b2c3/`, `MyProtocol_2026-04-22_d4e5f6/`)
- **Exploit PoCs** are placed in the `exploits/` subdirectory within the per-scan folder, not in the engine root directory
- **Web uploads** follow the same structure; files are accessible via the results page download links

> **Note:** Prior to v5.0, reports were written directly to the engine root directory (e.g., `audit_report.md`, `audit_report.html`). From v5.0.2 onward, all output is scoped to per-scan subdirectories under `reports/`. (Behavior unchanged in v5.0.3.)

---

## HTML Report

### Structure

The HTML report is a self-contained, styled document with:

1. **Header** — Project name, target path, timestamp, engine version, pass/fail badge
2. **Executive Summary** — Risk score (0-100) with severity count cards
3. **Finding Sections** — Grouped by category, each finding includes:
   - Severity badge
   - Rule ID and category
   - File location with line number
   - Description
   - Code snippet (dark-themed block)
   - Remediation advice (green highlight box)
   - Reference links
4. **Footer** — Engine branding

### Features

- **Responsive layout** — Works on desktop and mobile
- **Color-coded severity** — Red (CRITICAL), Orange (HIGH), Yellow (MEDIUM), Blue (LOW)
- **Gradient header** — Professional purple gradient with status badge
- **Self-contained** — No external CSS/JS dependencies
- **Printable** — Clean layout for PDF generation

### Generation

```bash
# Via CLI
counterscarp --target ./contracts --report

# Via Python API
from report_generator import create_audit_report, generate_html_report

report = create_audit_report("MyProject", "./contracts", findings)
generate_html_report(report, "audit_report.html")
```

### Accessing via Web App

Download from the results page at `/results/{audit_id}/report/html`.

---

## Markdown Report

### Structure

The Markdown report uses GitHub-flavored markdown with:

1. **Header** — Project metadata with status emoji
2. **Executive Summary** — Risk score and severity count table
3. **Finding Sections** — Numbered findings with:
   - Severity emoji
   - Rule ID in code formatting
   - File location as inline code
   - Description as plain text
   - Code snippet in solidity code block
   - Remediation in bold
   - Reference list
4. **Footer** — Engine branding

### Features

- **GitHub/GitLab compatible** — Renders correctly on all major platforms
- **Emoji severity indicators** — Red circle (CRITICAL), Orange (HIGH), Yellow (MEDIUM), Blue (LOW)
- **Table formatting** — Clean severity summary table
- **Link support** — Clickable reference URLs

### Example Output

```markdown
# Security Audit Report

**Project:** `MyProtocol`  
**Status:** ⚠️ **WARNING**

---

## Executive Summary

**Risk Score:** 42.5/100

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 3 |
| LOW | 1 |

---

## Heuristic Analysis

### 1. 🔴 Unchecked External Call

**Severity:** CRITICAL  
**Rule ID:** `UNCHECKED_EXTERNAL_CALL`  
**Location:** `contracts/Vault.sol:42`

**Description:**
Low-level call without return value check.

```solidity
target.call{value: amount}(data);
```

**Remediation:**
Always check return values: `(bool success, ) = target.call{value: amount}(data); require(success, "Call failed");`
```

### Generation

```python
from report_generator import create_audit_report, generate_markdown_report

report = create_audit_report("MyProject", "./contracts", findings)
generate_markdown_report(report, "audit_report.md")
```

---

## SARIF 2.1.0 Format

### Overview

SARIF (Static Analysis Results Interchange Format) is an OASIS standard for exchanging static analysis results. Counterscarp Engine generates SARIF 2.1.0 compliant output that integrates with:

- **GitHub Advanced Security** — Upload via `github/codeql-action/upload-sarif`
- **Azure DevOps** — native SARIF support
- **VS Code** — SARIF Viewer extension
- **Other tools** — Any tool supporting the SARIF standard

### Structure

```json
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Counterscarp Engine",
          "version": "3.1.3",
          "semanticVersion": "3.1.3",
          "informationUri": "https://counterscarp.io",
          "rules": [
            {
              "id": "UNCHECKED_EXTERNAL_CALL",
              "name": "Unchecked External Call",
              "shortDescription": { "text": "..." },
              "fullDescription": { "text": "..." },
              "defaultConfiguration": { "level": "error" }
            }
          ]
        }
      },
      "results": [
        {
          "ruleId": "UNCHECKED_EXTERNAL_CALL",
          "level": "error",
          "message": { "text": "Low-level call without return value check..." },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "contracts/Vault.sol" },
                "region": {
                  "startLine": 42,
                  "snippet": { "text": "target.call{value: amount}(data);" }
                }
              }
            }
          ]
        }
      ],
      "invocations": [
        {
          "executionSuccessful": true,
          "startTimeUtc": "2024-01-15T10:30:00"
        }
      ]
    }
  ]
}
```

### Severity Mapping

| Counterscarp Severity | SARIF Level |
|-------------------|-------------|
| CRITICAL | `error` |
| HIGH | `error` |
| MEDIUM | `warning` |
| LOW | `note` |
| INFO | `note` |

### GitHub Actions Integration

```yaml
- name: Run Counterscarp Engine
  run: counterscarp --target ./contracts --config counterscarp.toml

- name: Upload SARIF to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: audit_report.sarif
```

### Generation

```python
from report_generator import save_sarif_report, Finding

findings = [Finding(...)]
metadata = {
    "project_name": "MyProject",
    "target_path": "./contracts",
    "timestamp": "2024-01-15T10:30:00"
}
save_sarif_report(findings, "report.sarif", metadata)
```

---

## JSON Format

### Structure

The JSON format is the raw machine-parseable representation of findings, used for custom tooling and automation.

```json
[
  {
    "rule_id": "UNCHECKED_EXTERNAL_CALL",
    "severity": "CRITICAL",
    "category": "Heuristic",
    "title": "Unchecked External Call",
    "description": "Low-level call without return value check...",
    "file": "contracts/Vault.sol",
    "line_no": 42,
    "code_snippet": "target.call{value: amount}(data);",
    "remediation": "Always check return values...",
    "references": ["https://consensys.github.io/..."],
    "cwe": "CWE-252: Unchecked Return Value",
    "owasp": null
  }
]
```

### Finding Fields

| Field | Type | Description |
|-------|------|-------------|
| `rule_id` | string | Unique rule identifier |
| `severity` | string | CRITICAL, HIGH, MEDIUM, LOW, INFO |
| `category` | string | Analyzer category (Heuristic, Slither, Aderyn, Solana, etc.) |
| `title` | string | Short finding title |
| `description` | string | Detailed description |
| `file` | string | Path to the affected file |
| `line_no` | int | Line number (0 if not available) |
| `code_snippet` | string | Relevant code snippet |
| `remediation` | string | Suggested fix |
| `references` | string[] | Reference URLs |
| `cwe` | string or null | CWE identifier (e.g., "CWE-252") |
| `owasp` | string or null | OWASP category |

### Accessing via Web App

Download from the results page at `/results/{audit_id}/report/json`.

---

## PDF Report

Professional-quality PDF reports for formal audit deliverables.

**Requirements:**
- Pro tier license or above
- PDF extras: `pip install "counterscarp-engine[pdf]"`
- Backend: xhtml2pdf

**Generation:**
```bash
counterscarp --target ./contracts --report --format pdf
```

**Features:**
- Branded cover page with project name and date
- Executive summary with risk score and severity breakdown
- Full findings with code snippets and remediation guidance
- Table of contents with page numbers
- Custom logo support via `[reporting].logo_path`

**Note:** PDF generation requires the `xhtml2pdf` library. Install it with the pdf extras package.

---

## Customizing Reports via Configuration

Control report generation in `counterscarp.toml`:

```toml
[reporting]
format = "html"          # Default output format: markdown, json, sarif, html
verbosity = "verbose"    # minimal, standard, verbose
group_by = "severity"    # severity, file, rule

[reporting.sections]
executive_summary = true
supply_chain = true
static_analysis = true
heuristic_scan = true
fuzzing = true           # Include fuzzing results
threat_intel = true      # Include threat intelligence
access_matrix = true
```

### Verbosity Levels

| Level | Description |
|-------|-------------|
| `minimal` | Summary only, no code snippets or references |
| `standard` | Finding details with remediation, no verbose context |
| `verbose` | Full details including code snippets, references, CWE, OWASP |

### Grouping Options

| Option | Description |
|--------|-------------|
| `severity` | Group findings by severity level (default) |
| `file` | Group findings by source file |
| `rule` | Group findings by rule ID |

### Executive Summary Section

All report formats (except JSON) include an executive summary:

- **Total Findings:** count by severity
- **Risk Score:** 0-100 with PASS/WARNING/FAIL assessment
- **Top 10 Critical Issues:** highest-severity findings with one-line descriptions
- **Scan Coverage:** analyzers run, files processed, time elapsed

---

## Logo Branding

### Embedding a Custom Logo

The HTML report and attack graph support custom logo branding. Pass the `logo_path` parameter:

```python
from report_generator import generate_html_report

generate_html_report(
    report,
    "audit_report.html",
    logo_path="assets/logo_small.png"  # PNG, JPG, or SVG
)
```

### How It Works

1. The logo file is read and Base64-encoded
2. The encoded image is embedded directly into the HTML as a `data:` URI
3. No external file references — the report remains self-contained

### Supported Formats

| Format | Extension | MIME Type |
|--------|-----------|-----------|
| PNG | `.png` | `image/png` |
| JPEG | `.jpg`, `.jpeg` | `image/jpeg` |
| SVG | `.svg` | `image/svg+xml` |

**Tip:** Use a small logo file (under 200 KB) to keep report file size manageable. The default `assets/logo_small.png` is ~154 KB.

### Web App Logo

The web app automatically uses `assets/logo_small.png` if it exists. Configure the path in `webapp/config.py`:

```python
LOGO_PATH = BASE_DIR / "assets" / "logo_small.png"
```

---

*Counterscarp Security Engine &bull; counterscarp.io*
