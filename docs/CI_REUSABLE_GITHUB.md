# Reusable GitHub PR Security Pipeline

This guide defines a drop-in CounterScarp CI model for any repository:

1. a tiny repo-local workflow that triggers on PRs
2. a centrally maintained reusable workflow with scan logic

This keeps setup simple in downstream repos while preserving centralized governance.

## What ships in this repository

- Reusable workflow: `.github/workflows/security-reusable.yml`
- Bootstrap template: `templates/ci/github/security-pr.yml`

## Integration model

### 1) In the central CounterScarp repository

Keep the reusable workflow versioned and stable:

```yaml
uses: your-org/counterscarp-engine/.github/workflows/security-reusable.yml@v1
```

- Use a major tag (`v1`) for compatibility.
- Only introduce breaking input/output changes in `v2+`.

### 2) In each product/application repository

Create `.github/workflows/security-pr.yml` from `templates/ci/github/security-pr.yml`, then adjust:

- `uses` repository reference
- `target_path` (contracts/program root)
- `config_path` (`scarpshield.toml` or `counterscarp.toml`)
- `fail_on_severity` threshold by policy

## Required branch protection settings

For `main` (and optionally `develop`):

- Require status check: `CounterScarp Scan`
- Require pull request before merging
- Dismiss stale approvals on new commits
- Do not allow force pushes

## Required secrets

The reusable workflow does not require secrets for baseline operation. If downstream repos enable optional analyzers or private dependency sources, define secrets in the caller repository and pass with `secrets: inherit`.

## Trigger strategy (recommended)

Trigger on file changes rather than PR title heuristics:

- Solidity (`**/*.sol`)
- Rust (`**/*.rs`)
- Python analyzer wrapper/config files
- workflow and config files

This avoids missing security scans because a PR title did not contain specific keywords.

## Organization-level policy mapping

Use policy by repository risk class:

- `HIGH` for production protocol repos (default)
- `MEDIUM` for internal tooling or low-value systems
- `CRITICAL` for emergency fix branches if speed is required

## Output and audit evidence

Each run uploads:

- `counterscarp_output.txt`
- `solana_output.txt`
- `counterscarp_audit_report.sarif`
- generated reports (`audit_report.*`, `ACTION_PLAN.md`) when available

These artifacts provide auditable security evidence for release approvals.
