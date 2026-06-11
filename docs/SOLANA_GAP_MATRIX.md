# Solana Coverage Gap Matrix

This document tracks Solana-specific gaps relative to EVM maturity and defines concrete implementation priorities.

## Current state summary

CounterScarp already includes:

- Solana static analyzer (`solana_analyzer.py`)
- Anchor/IDL validation integration
- cargo-audit dependency checks
- substantial rule coverage

Primary gap is analysis depth and deterministic CI activation, not absence of Solana support.

## Gap matrix

| Area | Current state | Gap | Priority |
| --- | --- | --- | --- |
| CI trigger fidelity | Solana job depends on PR title/message heuristics in workflow | Trigger should use Rust/Anchor path changes | P0 |
| Rule precision | Regex-centric matching catches many patterns | Higher false-positive/false-negative risk in complex programs | P1 |
| Cross-file analysis | Mostly file-local detections | Limited multi-module and state-flow correlation | P1 |
| CPI path tracing | Basic checks and optional IDL tracing | No full inter-program call graph risk scoring | P2 |
| Raw Solana SDK coverage | Anchor-first focus | Lighter coverage for non-Anchor programs | P1 |
| Confidence calibration | Generic confidence guidance | Solana-specific confidence tuning and suppression ergonomics | P1 |

## Recommended Solana checks to add

- PDA seed canonicalization and bump-consistency checks across modules
- signer-to-authority binding validation with context lineage
- CPI destination allowlist checks with per-instruction policy
- account reload and stale-data usage checks after CPI chains
- token-2022 extension and transfer-hook policy checks
- authority handoff patterns (two-step transfer / timelock-style patterns)

## Tooling improvements

## Near-term (P0/P1)

- Update CI trigger logic to file-path detection (`**/*.rs`, `**/Anchor.toml`, `**/Cargo.toml`, `**/target/idl/*.json`)
- Add per-rule confidence defaults for Solana findings
- Add rule metadata tags (`anchor`, `raw-solana`, `cpi`, `token`) for filtering and policy gates

## Mid-term (P2)

- Add AST pass for Rust/Anchor instruction handlers
- Build CPI call graph from IDL + source and annotate trust boundaries
- Introduce rule suppression with rationale templates for auditors

## Acceptance criteria

- Solana scans run automatically on all relevant PRs without title conventions.
- At least 20% reduction in medium-severity false positives on internal benchmark corpus.
- New Solana report section: "CPI Trust Boundary Findings".
- Policy can gate on Solana-tagged findings independently of EVM findings.

## Suggested delivery phases

1. **Phase 1 (2 weeks):** CI trigger correction + rule metadata + confidence defaults
2. **Phase 2 (4 weeks):** AST-assisted checks for top 10 high-value Solana rules
3. **Phase 3 (4-6 weeks):** CPI graph analysis and advanced raw-Solana SDK expansion
