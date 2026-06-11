# INTERNAL: Launch Day Runbook

This document is for internal operations only. Do not publish it on public-facing websites.

## Scope

- Production launch validation flow (Phase 8).
- Support and uptime operations flow.
- Go / No-Go decision and rollback triggers.

## Go / No-Go Checklist

Mark each item `PASS` or `FAIL` and collect evidence.

1. Real card purchase succeeds in production.
2. Paid scan completes and report downloads.
3. Refund flow removes credits correctly.
4. Transactional email matrix passes (welcome, receipt, activation, reset, refund).
5. CLI online license validation passes.
6. CLI offline grace-period run passes.
7. Uptime monitor outage + recovery alerts hit primary phone channel.

If any item fails, decision is `NO-GO` until corrected and re-tested.

## Launch Day Order Of Operations

1. Confirm deployed app version:
   - `curl -sS https://app.counterscarp.io/version`
2. Execute non-payment smoke checks:
   - home page render
   - pricing page render
   - status page render
3. Execute payment flow:
   - new account signup
   - real card purchase
   - run scan
   - download report
4. Execute refund flow:
   - refund in Stripe
   - verify credit decrement in app/license state
5. Execute email matrix checks:
   - verify delivery, links, branding, and mobile rendering
6. Execute CLI validation:
   - online run with real license
   - offline run within grace window
7. Execute uptime drill:
   - 2-3 minute controlled outage
   - verify outage alert and recovery alert
8. Record evidence and finalize `GO` or `NO-GO`.

## Rollback Triggers (Automatic No-Go)

- Payment captured but credits are not granted.
- Credits are deducted without producing downloadable report output.
- Refund does not revoke or adjust credits as expected.
- Password reset or receipt emails fail delivery.
- License validation blocks legitimate paid users.
- Uptime alerting fails during controlled outage drill.
- Sustained production 5xx spike during load smoke checks.

## VPS Command Pack (Internal)

```bash
# 1) Health checks (local app + public app)
curl -sS http://127.0.0.1:8001/ | head -n 25
curl -sS https://app.counterscarp.io/ | head -n 25

# 2) Confirm premium UI markers
curl -sS https://app.counterscarp.io/ | grep -E "What You Get|Unlock the Full Power|FILE|SSL|AUD|RISK"

# 3) Confirm app version endpoint
curl -sS https://app.counterscarp.io/version

# 4) Confirm status page
curl -sS https://counterscarp.io/status.html | grep -E "Service Status|All systems operational"

# 5) Confirm docs anchors
curl -sS https://counterscarp.io/docs.html | grep -E "id=\"suppressions\"|id=\"cicd\""

# 6) Confirm sitemap includes expected public pages
curl -sS https://counterscarp.io/sitemap.xml | grep -E "status\\.html"

# 7) Save proof bundle
mkdir -p launch-proof
curl -sS https://app.counterscarp.io/version > launch-proof/app-version.json
curl -sS https://counterscarp.io/status.html > launch-proof/status.html
curl -sS https://counterscarp.io/sitemap.xml > launch-proof/sitemap.xml
```

## Evidence Log Template

```text
Run date:
Operator:
Environment:

Purchase flow:
- account email:
- charge id:
- audit id:
- report files:

Email matrix:
- welcome:
- receipt:
- activation:
- reset:
- refund:

CLI grace test:
- online result:
- offline result:

Load smoke:
- tool:
- p95 latency:
- error rate:

Uptime drill:
- outage alert time:
- recovery alert time:

Final decision: GO / NO-GO
```
