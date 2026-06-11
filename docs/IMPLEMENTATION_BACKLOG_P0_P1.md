# Implementation Backlog (P0/P1)

This backlog translates the architecture goals into ready-to-create GitHub issues.

## P0 — Execute first

## P0-1: Publish reusable workflow v1

- **Title:** `ci: release reusable security workflow v1`
- **Goal:** Make PR security scanning portable across repos via `workflow_call`.
- **Scope:**
  - finalize `.github/workflows/security-reusable.yml`
  - publish `v1.0.0` and `v1` tag
  - validate with canary downstream repo
- **Acceptance criteria:**
  - downstream repo runs workflow via `uses: ...@v1`
  - SARIF uploads successfully
  - severity threshold gate works as documented
- **Owner:** Security Platform
- **Labels:** `ci`, `security`, `p0`

## P0-2: Add drop-in PR template docs and examples

- **Title:** `docs: ship drop-in github PR workflow template`
- **Goal:** Enable any repo to onboard in under 10 minutes.
- **Scope:**
  - maintain `templates/ci/github/security-pr.yml`
  - complete setup guide in `docs/CI_REUSABLE_GITHUB.md`
  - add branch protection checklist
- **Acceptance criteria:**
  - docs contain copy/paste caller workflow
  - integration steps verified by non-author reviewer
- **Owner:** DevEx
- **Labels:** `documentation`, `ci`, `p0`

## P0-3: Define enterprise check provider contract v1

- **Title:** `plugins: define enterprise check provider API v1`
- **Goal:** Standardize custom/proprietary checks with auditable output.
- **Scope:**
  - document normalized finding schema
  - require plugin provenance fields (`name`, `version`, `vendor`)
  - publish compatibility and versioning policy
- **Acceptance criteria:**
  - schema and examples published
  - at least one internal custom plugin mapped to schema
- **Owner:** AppSec Architecture
- **Labels:** `plugins`, `enterprise`, `p0`

## P0-4: Add evidence bundle output contract

- **Title:** `reporting: add scan evidence bundle schema`
- **Goal:** Improve auditor traceability for CI and self-hosted scans.
- **Scope:**
  - define `security_evidence.json` format
  - include scan metadata, plugin inventory, gate outcome, checksums
  - ensure artifact upload in CI
- **Acceptance criteria:**
  - evidence bundle generated on each CI run
  - format validated in unit tests
- **Owner:** Reporting/Core Engine
- **Labels:** `reporting`, `compliance`, `p0`

## P1 — Next wave

## P1-1: Replace Solana title-based trigger with file-path trigger

- **Title:** `ci: make solana analysis trigger path-based`
- **Goal:** Ensure Solana checks run deterministically on relevant PRs.
- **Scope:**
  - trigger on `**/*.rs`, `**/Cargo.toml`, `**/Anchor.toml`, `**/target/idl/*.json`
  - remove dependency on PR title keyword matching
- **Acceptance criteria:**
  - Solana scan runs whenever Rust/Anchor files change
  - Solana scan does not run for unrelated changes
- **Owner:** CI/Platform
- **Labels:** `solana`, `ci`, `p1`

## P1-2: Solana rule metadata and confidence tuning

- **Title:** `solana: add rule tags and calibrated confidence defaults`
- **Goal:** Reduce triage noise and support policy-based filtering.
- **Scope:**
  - add tags (`anchor`, `raw-solana`, `cpi`, `token`)
  - tune confidence defaults by rule family
  - expose filter controls in config
- **Acceptance criteria:**
  - reports show rule tags and confidence
  - benchmark set shows lower false-positive rate
- **Owner:** Solana Analyzer
- **Labels:** `solana`, `rules`, `p1`

## P1-3: Self-hosted enterprise reference topologies

- **Title:** `docs: publish enterprise self-hosted topology pack`
- **Goal:** Provide compliance-friendly deployment guidance.
- **Scope:**
  - finalize `docs/SELF_HOSTED_ENTERPRISE_BLUEPRINT.md`
  - add HA and air-gapped reference diagrams/checklists
  - add secrets and backup/restore runbook sections
- **Acceptance criteria:**
  - blueprint reviewed by infrastructure + security stakeholders
  - includes required controls and evidence mapping
- **Owner:** Infra + Security Engineering
- **Labels:** `self-hosted`, `enterprise`, `p1`

## P1-4: Plugin trust and allowlist enforcement

- **Title:** `plugins: enforce allowlist and provider metadata in production mode`
- **Goal:** Prevent untrusted plugins from running in enterprise environments.
- **Scope:**
  - add plugin allowlist configuration
  - enforce required metadata fields
  - add strict mode switch for production scans
- **Acceptance criteria:**
  - unknown plugins are blocked in strict mode
  - policy decisions logged in scan output/evidence
- **Owner:** Core Engine
- **Labels:** `plugins`, `security-hardening`, `p1`

## P1-5: Solana roadmap milestone tracking

- **Title:** `solana: track parity milestones against EVM baseline`
- **Goal:** Make Solana parity progress measurable.
- **Scope:**
  - maintain `docs/SOLANA_GAP_MATRIX.md`
  - define quarterly milestone status updates
  - track acceptance criteria completion
- **Acceptance criteria:**
  - milestone table updated each release cycle
  - release notes reference completed Solana milestones
- **Owner:** Product + Solana Analyzer
- **Labels:** `solana`, `roadmap`, `p1`
