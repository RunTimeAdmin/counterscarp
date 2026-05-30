# ScarpShield ACP Offering — `solidity_security_scan`

Register this offering when ScarpShield is ready to charge on Virtuals ACP.

## Offering

| Field | Value |
|-------|--------|
| **Offering ID** | `solidity_security_scan` |
| **Display name** | ScarpShield Contract Scan |
| **Price (launch)** | **$3 USDC** per job |
| **SLA** | Deliver within **120 seconds** or mark job failed (no valid deliverable) |
| **Input** | One `.sol` file, UTF-8 source, max 10 MB |
| **Output** | JSON deliverable from Counterscarp API |

## Counterscarp API flow

1. **Submit** — `POST https://app.counterscarp.io/api/v1/scan`
2. **Poll** — `GET …/scan/{audit_id}/deliverable` every 5s until HTTP **200**
3. **Accept job** only if `deliverable_valid: true`

### Poll endpoints

| Endpoint | Format | Use |
|----------|--------|-----|
| `/api/v1/scan/{id}/summary` | plain text | OpenClaw chat (paste verbatim) |
| `/api/v1/scan/{id}/deliverable` | JSON | ACP evaluation / Butler |

### Valid deliverable criteria

- HTTP **200** on `/deliverable`
- `deliverable_valid: true`
- `summary_text` starts with `ScarpShield scan complete`
- Includes `Tests run:` section and `disclaimer`

### Invalid deliverable (do not pay / refund)

- HTTP **202** — still running; keep polling
- HTTP **422** — failed scan or invalid deliverable
- Summary starts with `Scan still running` or `ScarpShield scan failed`

## Example deliverable (abbreviated)

```json
{
  "audit_id": "b2d2acaf-a7f2-45db-9d09-956c1bf4c383",
  "status": "complete",
  "deliverable_valid": true,
  "risk_score": 13.2,
  "findings_count": 4,
  "severity_counts": { "critical": 0, "high": 1, "medium": 0, "low": 0 },
  "summary_text": "ScarpShield scan complete — Token.sol\n...",
  "disclaimer": "Disclaimer: Automated scan only — not a formal audit...",
  "report_urls": {
    "html": "https://app.counterscarp.io/api/v1/scan/.../report/html"
  }
}
```

## Engines included (API scan)

- Heuristic Pattern Scanner (~29 rules)
- Protocol Fingerprint Scanner (fork similarity + fork logic checks)
- Slither Static Analysis
- AI Audit Copilot (RAG context)
- Attack Graph Generator

**Not included:** Mythril, Medusa, Aderyn, supply-chain OSV (full CLI/Docker only).

## Launch checklist

- [ ] Free beta on Telegram / Virtuals chat (10+ external scans)
- [ ] Register ACP Provider on Virtuals Console
- [ ] Set Tier 1 price ($3 USDC)
- [ ] Fund agent wallet (hosting + credits)
- [ ] SOUL.md updated with ACP paid-job section
- [ ] Monitor worker health on VPS

## Docs

- [Virtuals ACP](https://whitepaper.virtuals.io/builders-hub/acp-current-status)
- [ACP SDK](https://os.virtuals.io/acp)
