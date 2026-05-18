# Current Repository Status

Last updated: 2026-05-18

## Platform Status

- Core scan pipeline is stable; full local smoke tests and orchestrator regression tests are passing.
- Runtime Docker image is hardened using a multi-stage build and a reduced runtime footprint.
- Container security guardrail exists in CI and is configured to fail on non-base `critical`/`high` findings.
- Base-image Debian findings are tracked under `docs/SECURITY_CONTAINER_ALLOWLIST.md`.

## Security Posture Snapshot

- Application-layer Snyk code findings: remediated in current branch state.
- Container findings: remaining findings are inherited from the Debian base image supply chain.
- Medusa runtime binary is intentionally excluded from the container image until upstream dependency risk is cleared.
- CLI behavior for `--medusa` is now explicit: in containers without Medusa installed, it warns and skips.

## Operational Follow-Ups

- GitHub Actions billing/spend limit must be active for workflow jobs to run.
- Repository secrets required for CI container scanning:
  - `SNYK_TOKEN`
  - `SNYK_ORG`
- After billing/secrets are configured, run `Counterscarp Security Audit` on `main` to validate the guardrail end-to-end.

## Documentation Sync

- README status section reflects current hardening and CI guardrail state.
- GitHub Wiki Home page should mirror this status and link to the allowlist policy.
