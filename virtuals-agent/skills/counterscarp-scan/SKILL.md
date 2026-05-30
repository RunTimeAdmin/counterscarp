---
name: counterscarp-scan
description: Scan Solidity or Rust smart contract source via Counterscarp security API. Use when user pastes .sol/.rs code or asks for a security audit.
metadata: {"openclaw":{"requires":{"env":["COUNTERSCARP_API_KEY"]}}}
---

# Counterscarp Security Scan

You audit smart contracts by calling the Counterscarp API at `https://app.counterscarp.io`.

## When to use

- User pastes Solidity (`.sol`) or Rust (`.rs`) source code
- User asks to scan, audit, or check a contract for vulnerabilities
- User provides an `audit_id` from a previous scan

## Credentials

Use environment variable `COUNTERSCARP_API_KEY` in the Authorization header:

```
Authorization: Bearer ${COUNTERSCARP_API_KEY}
```

If not set in env, use the key configured in OpenClaw skills settings for this skill.

## Step 1 — Submit scan

**POST** `https://app.counterscarp.io/api/v1/scan`

Headers:
- `Authorization: Bearer <API_KEY>`
- `Content-Type: application/json`

Body:
```json
{
  "project_name": "<project name or filename>",
  "files": [
    {
      "filename": "Contract.sol",
      "content": "<full source code>"
    }
  ]
}
```

Response (202): `{ "audit_id": "...", "status": "pending", "poll_interval_seconds": 5 }`

## Step 2 — Poll until complete

**GET** `https://app.counterscarp.io/api/v1/scan/{audit_id}?include_findings=true`

Same Authorization header. Poll every 5 seconds until `status` is `complete` or `failed` (max ~2 minutes).

## Step 3 — Report to user

Summarize:
- `summary.risk_score` (0–100)
- `summary.severity_counts` (critical, high, medium, low)
- `summary.total_findings`
- Top 3 findings: severity, title/rule_id, brief impact
- Link: https://app.counterscarp.io and https://counterscarp.io

Never invent findings. Never claim "safe" — say "no issues detected at scan time" if zero findings.

## Filename rules

- Must end in `.sol` or `.rs`
- Reject other extensions politely

## Error handling

- 401: API key invalid — tell user to check Console skill env config
- 429: Rate limited — wait and retry
- 503: Scan queue unavailable — ask user to retry later
