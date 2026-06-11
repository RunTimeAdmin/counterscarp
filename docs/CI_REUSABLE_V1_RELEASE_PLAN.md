# Reusable CI Workflow v1 Release Plan

This plan defines how to ship and maintain `security-reusable.yml` as a stable contract for downstream repositories.

## Objective

Publish a major-tagged reusable workflow (`v1`) that:

- supports standardized PR security gates across repositories
- remains backward compatible within `v1.x`
- has clear upgrade and rollback procedures

## Scope (v1.0.0)

Workflow file:

- `.github/workflows/security-reusable.yml`

Supported inputs:

- `target_path`
- `config_path`
- `fail_on_severity`
- `enable_solana`
- `python_version`
- `upload_sarif`

Artifacts:

- `counterscarp_output.txt`
- `solana_output.txt`
- `counterscarp_audit_report.sarif`
- generated report files when present

## Versioning policy

- **Patch (`v1.0.1`)**: internal fixes only, no input/output contract changes.
- **Minor (`v1.1.0`)**: additive, backward-compatible fields/steps.
- **Major (`v2.0.0`)**: breaking changes to inputs, outputs, or behavior.

## Compatibility guarantees

For all `v1.x` releases:

- existing inputs remain valid
- default behavior does not become more strict without opt-in
- artifact names remain stable unless additive

## Release checklist

## 1) Pre-release validation

- Run workflow against:
  - EVM-only test repo
  - Solana-only test repo
  - mixed EVM+Solana repo
- Verify:
  - SARIF upload success
  - scan skip behavior when target missing
  - severity threshold behavior
  - artifacts generated consistently

## 2) Contract review

- Verify no breaking changes to `workflow_call` inputs.
- Verify docs and caller template remain accurate:
  - `docs/CI_REUSABLE_GITHUB.md`
  - `templates/ci/github/security-pr.yml`

## 3) Tag and publish

- Create annotated tag: `v1.0.0`
- Create moving major tag: `v1`
- Publish release notes with:
  - supported inputs
  - known limitations
  - migration notes (if any)

## 4) Post-release verification

- Update one canary downstream repository to use `@v1`
- Confirm successful PR scan run
- Confirm branch protection gate status name unchanged

## Rollback plan

If regression occurs:

1. Re-point `v1` tag to previous stable patch tag.
2. Publish incident note with affected versions and workaround.
3. Ship fixed patch as `v1.0.x` and re-point `v1`.

## Change-management requirements

Every release should include:

- changelog entry
- compatibility statement (`breaking` vs `non-breaking`)
- validation evidence (run IDs or artifacts)
- reviewer sign-off from security platform owner

## Recommended ownership

- **Workflow maintainer**: Security Platform team
- **Approver**: Application Security lead
- **Consumer onboarding**: DevEx/Platform Engineering
