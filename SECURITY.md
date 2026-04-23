# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 5.x.x   | Yes               |
| 4.x.x   | Yes               |
| < 4.0   | No                |

## Reporting a Vulnerability

If you discover a security vulnerability in Counterscarp Engine, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email us at: **contact@counterscarp.io**

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment**: Within 48 hours
- **Initial Assessment**: Within 5 business days
- **Fix Timeline**: Depends on severity
  - Critical: 24-72 hours
  - High: 1-2 weeks
  - Medium/Low: Next release cycle

### Scope

The following are in scope:
- Counterscarp Engine core analyzers and scanning logic
- License validation and key management
- Web application (app.counterscarp.io)
- CLI tools and report generation

The following are out of scope:
- Third-party dependencies (report to the respective maintainer)
- Social engineering attacks
- Denial of service attacks

## API Security Controls (v5.0.3)

The following security controls are enforced by the Counterscarp Engine web API:

### Rate Limiting

| Endpoint | Limit | Response when exceeded |
|----------|-------|------------------------|
| License validation (`POST /api/license/validate`) | 10 req/min | HTTP 429 |
| License deactivation (`POST /api/license/deactivate`) | 5 req/min | HTTP 429 |
| Stripe webhooks (`POST /webhook/stripe`) | 30 req/min | HTTP 429 |

Clients must wait for the rate-limit window to reset before retrying.

### Input Validation

All API request fields are validated via Pydantic constraints:
- License key: regex-constrained format
- Machine ID: maximum 255 characters
- Version: semver pattern (`X.Y.Z`)
- Timestamp: ISO 8601 format

Malformed payloads are rejected with HTTP 422.

### Admin Endpoint Authentication

`GET /api/license/info` requires both an active session **and** the session email must match the configured `ADMIN_EMAIL` environment variable. Unauthenticated or unauthorised requests receive `{"detail": "Authentication required"}` (HTTP 403).

### Stripe Webhook Signature Verification

All inbound Stripe webhook events must carry a valid `Stripe-Signature` header. Unsigned or tampered payloads are rejected with HTTP 500. Set `STRIPE_WEBHOOK_SECRET` in the environment to enable verification.

### CORS Policy

Cross-Origin requests are restricted to the following origins:
- `https://app.counterscarp.io`
- `https://counterscarp.io`
- `http://localhost` (any port — development only)

All other origins are blocked.

### Session Secret

The web app uses a signed session cookie. If the `SESSION_SECRET` environment variable is not set, the application falls back to an insecure default and emits a loud warning at startup. **Production deployments must set `SESSION_SECRET`.**

```bash
# Generate a secure secret
python -c "import secrets; print(secrets.token_urlsafe(32))"
export SESSION_SECRET="<generated-value>"
```

### Path Traversal Protection

- Audit IDs are validated as UUIDs before use in file paths.
- Report download paths are resolved and checked to ensure they remain within the reports directory.

### File Upload Validation

Uploaded contract files are validated for:
- UTF-8 encoding (binary blobs rejected)
- Sanitised filenames (path components stripped)

### Security Event Logging

All authentication and validation events are written to the dedicated `counterscarp.security` Python logger (separate from the main application log). This includes login attempts, admin access, rate-limit hits, and webhook verification failures.

---

## Recognition

We appreciate responsible disclosure and will credit reporters in our release notes (unless they prefer to remain anonymous).
