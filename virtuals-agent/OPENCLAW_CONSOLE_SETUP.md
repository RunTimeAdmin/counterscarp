# ScarpShield — OpenClaw Console Setup

Use this after deploying `/api/v1/scan` on `app.counterscarp.io` and setting `COUNTERSCARP_API_KEYS`.

## 1. Create agent (app.virtuals.io)

1. Connect wallet → **Create Agent** → **Agent Console**
2. **Runtime:** OpenClaw
3. **Name:** ScarpShield
4. **Description:** Smart contract security agent powered by Counterscarp. Audits Solidity and Rust code for vulnerabilities.
5. Launch (3 USDC tokenization fee → agent wallet)

## 2. Paste SOUL.md

Open **Settings → SOUL.md** (or personality editor) and paste the contents of `SCARPSHIELD_SOUL.md`.

## 3. Custom function: scan_contract

| Field | Value |
|-------|-------|
| **Function name** | `scan_contract` |
| **Description** | Run a Counterscarp security audit on smart contract source code. Use when the user provides Solidity (.sol) or Rust (.rs) source code to analyze for vulnerabilities. |
| **HTTP method** | `POST` |
| **URL** | `https://app.counterscarp.io/api/v1/scan` |
| **Content-Type** | `application/json` |

**Headers**

| Name | Value |
|------|-------|
| `Authorization` | `Bearer YOUR_COUNTERSCARP_API_KEY` |
| `Content-Type` | `application/json` |

**Arguments**

| Name | Type | Description |
|------|------|-------------|
| `filename` | string | Source filename, e.g. `Token.sol` |
| `source_code` | string | Full contract source code |
| `project_name` | string | Optional project name for the report |

**Request body (JSON template)**

```json
{
  "project_name": "{{project_name}}",
  "files": [
    {
      "filename": "{{filename}}",
      "content": "{{source_code}}"
    }
  ]
}
```

If the Console uses a separate body editor without `{{}}` templating, map arguments manually:

```json
{
  "project_name": "ScarpShield Scan",
  "files": [
    {
      "filename": "Contract.sol",
      "content": "<paste source here>"
    }
  ]
}
```

**Expected response (202)**

```json
{
  "audit_id": "uuid",
  "status": "pending",
  "status_url": "https://app.counterscarp.io/api/v1/scan/{audit_id}",
  "poll_interval_seconds": 5
}
```

Tell the agent in SOUL.md to poll until `status` is `complete` (typically 15–120 seconds).

---

## 4. Custom function: get_scan_status

| Field | Value |
|-------|-------|
| **Function name** | `get_scan_status` |
| **Description** | Check status and results of a Counterscarp scan by audit_id. Use after scan_contract or when user provides an audit ID. |
| **HTTP method** | `GET` |
| **URL** | `https://app.counterscarp.io/api/v1/scan/{{audit_id}}?include_findings=true` |

**Headers**

| Name | Value |
|------|-------|
| `Authorization` | `Bearer YOUR_COUNTERSCARP_API_KEY` |

**Arguments**

| Name | Type | Description |
|------|------|-------------|
| `audit_id` | string | UUID returned from scan_contract |

**Complete scan response fields to use**

- `status` — pending | running | complete | failed
- `summary.risk_score`
- `summary.severity_counts`
- `summary.total_findings`
- `findings[]` — when `include_findings=true`
- `report_urls.json`, `report_urls.html`, etc.

---

## 5. Verify from your machine

Replace `YOUR_KEY` with the Virtuals-only API key (label `virtuals-agent` on VPS).

```bash
# Submit scan
curl -sS -X POST https://app.counterscarp.io/api/v1/scan \
  -H "Authorization: Bearer YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "project_name": "Console Test",
    "files": [{
      "filename": "Test.sol",
      "content": "pragma solidity ^0.8.0; contract T { function f() external {} }"
    }]
  }'

# Poll (replace AUDIT_ID)
curl -sS "https://app.counterscarp.io/api/v1/scan/AUDIT_ID?include_findings=true" \
  -H "Authorization: Bearer YOUR_KEY"
```

---

## 6. Credits

- Free tier: 10 GAME requests / 5 min
- Pay-as-you-go: **$0.003 per API call** — recommended once scanning live
- Each scan uses **2+ calls** (submit + poll, sometimes multiple polls)

---

## Security notes

- Use a **dedicated** API key label (`virtuals-agent`) — not shared with other integrations
- Key is rate-limited to **60 scans/hour** per key on Counterscarp
- Rotate key in VPS env if compromised; update Console header
