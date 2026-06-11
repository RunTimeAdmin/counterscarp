# Enterprise Check Provider API

This document defines a stable extension contract for enterprise custom checks and auditor-required controls.

It extends the existing plugin model in `plugin_manager.py` with a consistent output envelope, provenance metadata, and evidence requirements.

## Goals

- Allow proprietary checks without patching engine core.
- Preserve report compatibility across community and enterprise checks.
- Provide traceable evidence for auditors (who ran what, with which plugin/version, and why a gate failed).

## Provider model

A check provider is a plugin module that exposes `register(manager)` and registers either:

- analyzer checks (`register_analyzer`)
- rule packs (`register_rules`)

Enterprise providers SHOULD emit findings in the normalized output schema below.

## Normalized finding schema (v1)

```json
{
  "schema_version": "1.0",
  "finding_id": "UUID-or-deterministic-hash",
  "rule_id": "ACME_CTRL_001",
  "severity": "HIGH",
  "title": "Missing internal access control attestation",
  "description": "Function allows role-sensitive state mutation without policy guard.",
  "file": "contracts/Vault.sol",
  "line_no": 42,
  "code_snippet": "function setGuardian(address g) external { ... }",
  "remediation": "Require approved role and emit governance event.",
  "confidence": 8,
  "tags": ["compliance", "internal-policy", "access-control"],
  "source_plugin": {
    "name": "acme-compliance",
    "version": "1.2.3",
    "vendor": "Acme Security",
    "api_version": "1.0"
  },
  "provenance": {
    "scan_id": "2026-05-21T11:00:00Z-abc123",
    "target_sha": "git-commit-or-tree-sha",
    "executed_by": "github-actions",
    "execution_mode": "ci"
  }
}
```

## Compatibility contract

- **MAJOR** change (`2.x`) may break schema fields.
- **MINOR** change (`1.x`) can add optional fields only.
- Providers should declare `api_version` and fail fast on unsupported versions.

## Recommended plugin controls

For enterprise deployments:

- Maintain an allowlist of approved plugin directories.
- Require provider metadata (`name`, `version`, `vendor`) for all plugins.
- Optionally require signed plugin bundles and checksum verification.
- Block execution of unknown or unsigned providers in production scans.

## Audit trail requirements

Each scan should produce an evidence bundle including:

- scan metadata (timestamp, repo/ref, config hash)
- list of loaded plugins and versions
- all normalized findings
- final gate decision with threshold used (`fail_on_severity`)
- artifact checksums

Suggested file: `evidence/security_evidence.json`

## Reference implementation pattern

```python
def register(manager):
    manager.register_analyzer(EnterpriseChecks())


class EnterpriseChecks:
    name = "acme-compliance"
    version = "1.2.3"

    def analyze(self, target, config):
        return [{
            "rule_id": "ACME_CTRL_001",
            "severity": "HIGH",
            "description": "Custom control violation",
            "file": "contracts/Vault.sol",
            "line_no": 42,
            "source_plugin": self.name,
            "plugin_version": self.version,
        }]
```

## Governance workflow

1. Author provider and test locally.
2. Security platform team reviews plugin code and metadata.
3. Approve plugin version in allowlist.
4. Deploy to controlled plugin directory.
5. Record activation in change-management ticket.

This flow gives large teams a safe extension mechanism while preserving auditability.
