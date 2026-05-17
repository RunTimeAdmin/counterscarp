# License Management

> For pricing details and purchase options, visit [counterscarp.io/pricing](https://counterscarp.io/pricing.html).

## Table of Contents

- [Overview](#overview)
- [License Tiers](#license-tiers)
- [Activation Methods](#activation-methods)
- [Machine Fingerprinting](#machine-fingerprinting)
- [License Validation Flow](#license-validation-flow)
- [Managing Activations](#managing-activations)
- [Troubleshooting](#troubleshooting)
- [Purchasing a License](#purchasing-a-license)

---

## Overview

Counterscarp Engine uses a tiered licensing model. The **Community** tier is free and requires no license key. Paid tiers — Developer, Professional, Team, and Enterprise — require a valid license key for feature activation.

All tiers ship in a single `counterscarp-engine` package. Pro features are gated at runtime: without a valid key they display an upgrade prompt rather than silently failing.

---

## License Tiers

| Tier | Key Prefix | Price | Activations | Key Features |
|------|-----------|-------|-------------|--------------|
| **Community** | — | Free | Unlimited | 21 analyzers, Markdown/JSON reports, CLI |
| **Developer** | `SE-DEV-` | $49/mo | 1 machine | + Web app, Solana analyzer, HTML/SARIF reports |
| **Professional** | `SE-PRO-` | $199/mo | 3 machines | + AI Copilot, attack graphs, exploit PoC, protocol fingerprinting, time-travel |
| **Team** | `SE-TEAM-` | $399/mo | 5 machines | + All Pro features, team dashboard, API access |
| **Enterprise** | `SE-ENT-` | Custom | Unlimited | + Custom integrations, priority support, dedicated account manager |

The key prefix determines which features unlock. A `SE-PRO-` key will not unlock Team-only features; a `SE-TEAM-` key unlocks Pro features as well.

---

## Activation Methods

### Method 1: Environment Variable (Recommended for CI/CD)

Set `SCARPSHIELD_PRO_LICENSE` before running the engine
(legacy `COUNTERSCARP_PRO_LICENSE` still works):

```bash
export SCARPSHIELD_PRO_LICENSE=SE-PRO-your-key-here
scarpshield --target ./contracts --report
```

Environment variable priority order:
1. `SCARPSHIELD_PRO_LICENSE`
2. `COUNTERSCARP_PRO_LICENSE`
3. `[license].key` in TOML config

### Method 2: Configuration File

Add a `[license]` section to your `scarpshield.toml` (or legacy `counterscarp.toml`):

```toml
[license]
key = "SE-PRO-your-key-here"
```

If both a config file key and an environment variable are present, the environment variable wins.

### Method 3: Web Interface

1. Launch `counterscarp --gui`
2. Navigate to **Settings → License**
3. Enter your license key and click **Save**

The key is stored locally in `~/.scarpshield/settings.json` (legacy `~/.counterscarp/settings.json` may still exist) and loaded automatically on subsequent runs.

### Method 4: GitHub Actions

Store your key as a repository secret, then reference it in your workflow:

```yaml
env:
  SCARPSHIELD_PRO_LICENSE: ${{ secrets.SCARPSHIELD_PRO_LICENSE }}
```

Never hardcode license keys in source files — GitHub Push Protection will block commits containing key patterns.

---

## Machine Fingerprinting

License keys are bound to specific machines to prevent unauthorized sharing. On first use, the engine creates a fingerprint from:

- **Hostname** — the machine's network name
- **MAC address** — primary network interface identifier
- **Operating system** — OS type and version hash

The fingerprint is a SHA-256 hash of these combined values. This means:

- The same machine always produces the same fingerprint
- Different machines produce different fingerprints
- No personally identifiable information is transmitted to the validation server
- Changing the hostname or primary network interface may invalidate an activation

---

## License Validation Flow

1. The engine reads the license key from the environment variable, TOML config, or GUI settings (in that priority order)
2. A validation request is sent to `https://api.counterscarp.io/license/validate`
3. The server checks: key validity, tier, activation count against the machine fingerprint
4. A successful response is cached locally at `~/.scarpshield/license_cache.json` with a 24-hour TTL (legacy `~/.counterscarp/license_cache.json` is still read)
5. If the server is unreachable, the cached validation is used as a grace period for up to **7 days**

### Rate Limiting on License Endpoints

License API endpoints enforce per-IP rate limits to prevent abuse:

| Endpoint | Limit |
|----------|-------|
| `POST /api/license/validate` | 10 requests per minute |
| `POST /api/license/deactivate` | 5 requests per minute |

When a limit is exceeded, the server returns `HTTP 429`:

```json
{"detail": "Rate limit exceeded. Try again later."}
```

Rate limit windows reset after 60 seconds. The local 24-hour validation cache means that most normal use cases never approach these limits.

### Input Validation

License keys submitted to the API must conform to the following rules:

- **Format:** `SE-(DEV|PRO|TEAM|ENT)-{32 hex characters}` — e.g., `SE-PRO-a1b2c3d4...` (32 lowercase hex chars after the prefix)
- **`machine_id`** — maximum 255 characters

Requests that fail format validation are rejected with `HTTP 422` before any database lookup occurs.

### Stripe Webhook — License Provisioning via Payment

When a Stripe checkout session is completed, Counterscarp Engine receives a webhook event to provision the new license automatically. **Signature verification is mandatory:** every incoming webhook request is validated against the `STRIPE_WEBHOOK_SECRET` (`whsec_...`) to confirm it originates from Stripe. Requests with an invalid or missing signature are rejected with `HTTP 400` and no license is provisioned.

### Offline / Air-Gapped Use

The 7-day grace period supports offline and air-gapped deployments:

1. **Activate while online** — run any Pro command with a valid key on a connected machine
2. **Cache is stored locally** — the engine works offline for up to 7 days without contacting the server
3. **Reconnect before expiry** — any successful validation resets the 7-day window

For extended offline use beyond 7 days, contact [support@counterscarp.io](mailto:support@counterscarp.io) to discuss Enterprise air-gapped licensing options.

---

## Managing Activations

### View Current Activations

Log in to your account at [app.counterscarp.io](https://app.counterscarp.io) to see:

- Active machine fingerprints and their labels
- Last validation timestamp per machine
- Remaining activation slots for your tier

### Migrating to a New Machine

1. Log in to [app.counterscarp.io](https://app.counterscarp.io) and deactivate the old machine
2. Install Counterscarp Engine on the new machine
3. Set your license key — the new machine fingerprint is registered automatically on first run

### Activation Limit Reached

If you exceed your tier's activation limit, the engine displays:

```
Activation limit reached for this license key.
Deactivate an existing machine at app.counterscarp.io or upgrade your plan.
```

Options:
- Deactivate an inactive machine from the dashboard to free a slot
- Upgrade to a higher tier for more simultaneous activations
- Contact sales for an Enterprise licence with unlimited activations

---

## Troubleshooting

### "License validation failed" or "Could not reach license server"

**Cause:** DNS resolution failure for `api.counterscarp.io`, or a network connectivity issue.

**Steps to resolve:**

1. Verify DNS resolves: `nslookup api.counterscarp.io` should return an IP address
2. Check connectivity: `curl https://api.counterscarp.io/health`
3. If you are behind a corporate proxy, ensure outbound HTTPS to port 443 is permitted
4. If offline, check that your cache is less than 7 days old (see [Cache Location](#cache-location) below)

### "Pro features show upgrade prompt despite having a key"

**Cause:** Key prefix does not match the feature tier, key is not being read, or cache shows a lower tier.

**Steps to resolve:**

1. Verify the key prefix matches the intended tier:
   - Developer features require `SE-DEV-` or higher
   - Pro features require `SE-PRO-` or higher
2. Confirm the variable is exported: `echo $SCARPSHIELD_PRO_LICENSE` (or legacy `echo $COUNTERSCARP_PRO_LICENSE`)
3. Inspect the cached tier: open `~/.scarpshield/license_cache.json` (or legacy `~/.counterscarp/license_cache.json`) and check `"tier"`
4. Delete the cache file and re-run to force a fresh validation

### Cache Location

The local validation cache is stored at:

| Platform | Path |
|----------|------|
| Linux / macOS | `~/.scarpshield/license_cache.json` (legacy `~/.counterscarp/license_cache.json`) |
| Windows | `%USERPROFILE%\.scarpshield\license_cache.json` (legacy `%USERPROFILE%\.counterscarp\license_cache.json`) |

To force re-validation, delete this file. The engine will contact the server on the next run.

---

## Purchasing a License

Visit [counterscarp.io/pricing](https://counterscarp.io/pricing.html) to choose a plan and complete checkout via Stripe.

After purchase:

1. Your license key is emailed to the address used at checkout
2. Log in at [app.counterscarp.io](https://app.counterscarp.io) to view and manage your key
3. Activate using any of the [methods above](#activation-methods)

For volume pricing, multi-year agreements, or Enterprise contracts, contact [sales@counterscarp.io](mailto:sales@counterscarp.io).

---

*Counterscarp Security Engine &bull; counterscarp.io*
