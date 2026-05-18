# Container Base Image Allowlist

This project enforces container security in CI with two lanes:

- Blocking guardrail: fail on `critical`/`high` findings that are not from the base image.
- Advisory reporting: publish full Snyk container output (including base-image findings).

## Why this allowlist exists

Current runtime images use `python:3.12-slim` on Debian 13. Snyk reports a recurring set of Debian OS package vulnerabilities from the base image supply chain. These findings are tracked as an allowlist because they are inherited from upstream image maintenance and cannot be fully eliminated without changing base image family.

## Allowed finding scope

Only the following are allowlisted:

- Findings introduced by the base image `python:3.12-slim` / Debian 13 packages.
- Current low/medium families observed in base image layers (for example: `systemd`, `glibc`, `util-linux`, `apt`, `zlib`, `xz-utils`, `sqlite3`, `coreutils`, `ncurses`, `tar`, `shadow`).

Not allowlisted:

- Any `critical`/`high` vulnerability outside the base image.
- Any application or bundled tool vulnerability in project-managed layers.

## CI enforcement

CI job `Container Security Guardrail` enforces:

- `snyk container test ... --severity-threshold=high --exclude-base-image-vulns` (blocking)
- Full advisory scan artifact with base-image findings attached for visibility.

## Review policy

- Re-evaluate this allowlist whenever:
  - the base image tag changes,
  - Snyk reports new `critical`/`high` base-image findings, or
  - Debian releases patched packages that clear existing advisories.
- Remove entries from this allowlist as upstream fixes become available.
