# Self-Hosted Enterprise Blueprint

This blueprint extends `docs/DEPLOYMENT.md` with enterprise-ready deployment patterns for regulated and security-sensitive environments.

## Deployment profiles

## 1) Single-node hardened

Use when teams need fast deployment with limited ops overhead.

- Runtime: Docker or systemd + uvicorn
- Reverse proxy: nginx with TLS
- Storage: local disk with encrypted filesystem
- Secrets: environment variables from host secret store

## 2) HA internal cluster

Use for production service continuity and shared team access.

- Multiple app instances behind internal load balancer
- Shared object storage for reports
- Redis-backed queue/cache for background jobs
- Centralized logs (SIEM/syslog)

## 3) Air-gapped / disconnected

Use when cloud egress is prohibited.

- Offline package mirror for Python dependencies
- Signed signature-pack import via `--update-from-file`
- No outbound network from scan workers
- Controlled ingress/egress through transfer gateway

## Minimum infrastructure requirements

Per active scan worker (baseline):

- CPU: 4 vCPU
- Memory: 8 GB
- Disk: 40 GB SSD (plus report retention)
- OS: Ubuntu 22.04 LTS or equivalent hardened distro

Scale linearly by concurrent scan demand.

## Security controls checklist

- Enforce least-privilege service account.
- Set strong `SESSION_SECRET`, `ADMIN_EMAIL`, and webhook secrets.
- Restrict inbound ports to reverse proxy only.
- Restrict outbound egress to approved destinations (or none in air-gapped mode).
- Enable TLS 1.2+ with managed certificate rotation.
- Store logs in immutable or append-only sink for audit retention.
- Enable scheduled backup/restore tests for reports and config state.
- Rotate secrets and access tokens on defined cadence.

## Network segmentation model

- DMZ/proxy tier: HTTPS ingress only
- App tier: CounterScarp API and workers
- Data tier: report storage, cache, audit logs
- Management tier: CI runners and admin endpoints

Deny direct traffic from internet to app or data tiers.

## Secrets management

Preferred order:

1. HSM-backed enterprise secrets manager
2. platform secret store (Kubernetes/Vault/systemd drop-ins)
3. encrypted local environment file (last resort)

Never commit runtime secrets into repo config files.

## Air-gapped operational workflow

1. Build release artifacts in connected build zone.
2. Sign artifacts and generate checksums.
3. Transfer via controlled media gateway.
4. Verify signatures/checksums in offline zone.
5. Deploy and record deployment evidence (ticket + artifact hashes).

## Required operational runbooks

- Disaster recovery (RTO/RPO targets + restore steps)
- Incident response (security finding escalation paths)
- Backup and retention policy
- Offline update and rollback procedure
- Key and secret rotation procedure

## Evidence package for auditors

Capture per release:

- deployment manifest (version, image digest, config hash)
- security control checklist completion
- vulnerability scan output + SARIF artifacts
- change approval reference and operator identity

This set is usually sufficient for internal audit and external assurance reviews.
