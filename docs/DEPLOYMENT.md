# Server Deployment Guide

## Table of Contents

- [Prerequisites](#prerequisites)
- [Docker Deployment](#docker-deployment)
  - [Building the Image](#building-the-image)
  - [Running with docker-compose](#running-with-docker-compose)
  - [Volume Mounts](#volume-mounts)
  - [Resource Limits](#resource-limits)
  - [Health Checks](#health-checks)
  - [Environment Variables](#environment-variables)
  - [Production Considerations](#production-considerations)
- [Step-by-Step VPS Deployment](#step-by-step-vps-deployment)
- [Nginx Reverse Proxy Configuration](#nginx-reverse-proxy-configuration)
- [SSL Certificate Setup](#ssl-certificate-setup-lets-encrypt)
- [Systemd Service Management](#systemd-service-management)
  - [Authentication & Session Configuration](#authentication--session-configuration)
- [Installing External Tools](#installing-external-tools)
- [Update Procedure](#update-procedure)
- [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)
- [Log Management](#log-management)

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| OS | Ubuntu 22.04 LTS | Ubuntu 22.04 LTS |
| Python | 3.10 | 3.11 or 3.12 |
| RAM | 2 GB | 4 GB+ |
| Disk | 20 GB | 40 GB+ |
| CPU | 2 cores | 4 cores+ |

**Required software:**

- Python 3.10+ with `venv`
- nginx
- certbot (Let's Encrypt)
- git

---

## Docker Deployment

Docker is the recommended deployment method for CI environments, local development, and any host where you prefer not to install external tools (Foundry, Slither, Mythril, Aderyn, Medusa) directly. The multi-stage Dockerfile bundles the complete 21-analyzer stack on Python 3.12 (image size ~1.5 GB).

### Building the Image

```bash
cd sentinel-engine
docker build -t counterscarp-engine:5.0.3 .
```

### Running with docker-compose

The project's `docker-compose.yml` defines four services:

| Service | Purpose |
|---------|---------|
| `counterscarp` | Main audit service (all 21 analyzers) |
| `doctor` | Diagnostics / health check |
| `heuristic` | Heuristic-only scan (no external tools required) |
| `symbolic` | Mythril symbolic execution only |

```bash
# Full audit
docker compose run --rm counterscarp scan /scan/MyContract.sol

# Health check
docker compose run --rm doctor

# Heuristic-only scan
docker compose run --rm heuristic scan /scan/MyContract.sol

# Symbolic execution only
docker compose run --rm symbolic scan /scan/MyContract.sol
```

### Volume Mounts

Two mount points are defined for contract input and report output:

| Mount | Purpose |
|-------|---------|
| `/scan` | Mount your contract source directory here |
| `/output` | Audit reports are written here |

Use `--output-dir /output` to direct reports to the host-mounted volume (required for `docker run --rm` so reports are not lost when the container exits):

```bash
# Recommended: persist reports to host via --output-dir
docker run --rm \
  -v /path/to/contracts:/scan \
  -v /path/to/reports:/output \
  counterscarp-engine:5.0.3 \
  --target /scan --output-dir /output --report

# docker-compose equivalent (volume mounts already pre-configured)
docker compose run --rm \
  counterscarp --target /scan --output-dir /output --report
```

### Resource Limits

Pre-configured in `docker-compose.yml` under `deploy.resources`:

| Resource | Limit |
|----------|-------|
| CPU | 4.0 cores |
| Memory | 4 GB |

Adjust these values in the `deploy.resources` section of `docker-compose.yml` to match your host's capacity.

### Health Checks

All services include an automatic health check that runs `counterscarp --doctor`:

| Setting | Value |
|---------|-------|
| Interval | 60s |
| Timeout | 30s |
| Retries | 3 |

Use `docker compose ps` to view current health status for each service.

### Environment Variables

| Variable | Description |
|----------|-------------|
| `SCARPSHIELD_PRO_LICENSE` | Set your Pro license key to enable premium features (legacy `COUNTERSCARP_PRO_LICENSE` also supported) |

```bash
docker compose run --rm \
  -e SCARPSHIELD_PRO_LICENSE=your-key \
  counterscarp scan /scan/MyContract.sol
```

For persistent configuration, add `SCARPSHIELD_PRO_LICENSE` to a `.env` file in the project root (legacy `COUNTERSCARP_PRO_LICENSE` also works) — Docker Compose picks it up automatically.

### Production Considerations

```bash
# Run the main service in the background
docker compose up -d counterscarp

# Follow live logs
docker compose logs -f counterscarp

# Stop all services
docker compose down
```

- The `foundry-cache` named volume persists the Foundry compilation cache across runs, significantly reducing re-compilation time.
- Bind-mount a dedicated output directory so reports survive container restarts.
- Rotate or prune the `foundry-cache` volume periodically if disk space is constrained: `docker volume rm sentinel-engine_foundry-cache`.

---

## Step-by-Step VPS Deployment

The `deploy/setup.sh` script automates the full deployment. Run as root:

```bash
sudo bash deploy/setup.sh
```

### What the script does (8 steps)

| Step | Action |
|------|--------|
| 1/8 | Creates service user `counterscarp` (no login shell) |
| 2/8 | Clones/updates repository to `/opt/counterscarp-engine` |
| 3/8 | Creates Python venv and installs `counterscarp-engine[web]` |
| 4/8 | Creates `uploads/` and `results/` directories |
| 5/8 | Sets ownership to `counterscarp:counterscarp` |
| 6/8 | Installs nginx config and reloads nginx |
| 7/8 | Obtains SSL certificate via certbot (if not already present) |
| 8/8 | Installs systemd service and starts it |

### Manual Deployment

If you prefer to deploy manually:

```bash
# 1. Create service user
useradd -r -s /bin/false counterscarp

# 2. Setup directory (choose one method)

# Method A: Install from PyPI (recommended for production)
mkdir -p /opt/counterscarp-engine
cd /opt/counterscarp-engine
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install "counterscarp-engine[web]"

# Method B: Clone from GitHub (for development/customization)
# mkdir -p /opt/counterscarp-engine
# cd /opt/counterscarp-engine
# git clone https://github.com/RunTimeAdmin/counterscarp.git .
# python3 -m venv venv
# ./venv/bin/pip install --upgrade pip
# ./venv/bin/pip install -e ".[web]"

# 3. Create directories
mkdir -p /opt/counterscarp-engine/uploads
mkdir -p /opt/counterscarp-engine/results

# 4. Set ownership
chown -R counterscarp:counterscarp /opt/counterscarp-engine

# 5. Configure nginx
cp deploy/nginx-counterscarp.conf /etc/nginx/sites-available/counterscarp
ln -sf /etc/nginx/sites-available/counterscarp /etc/nginx/sites-enabled/counterscarp
nginx -t && systemctl reload nginx

# 6. SSL certificate
certbot certonly --nginx -d counterscarp.io --non-interactive --agree-tos -m your@email.com

# 7. Start service
cp deploy/counterscarp-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable counterscarp-engine
systemctl start counterscarp-engine
```

---

## Nginx Reverse Proxy Configuration

The nginx configuration is located at `deploy/nginx-counterscarp.conf`:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name counterscarp.io;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name counterscarp.io;

    ssl_certificate /etc/letsencrypt/live/counterscarp.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/counterscarp.io/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    client_max_body_size 10M;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:8001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 120s;
        proxy_connect_timeout 10s;
    }

    location /static/ {
        alias /opt/counterscarp-engine/webapp/static/;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
```

### Key Configuration Points

- **Port 8001** — The app runs on port 8001 (not 8000) to avoid conflicts
- **`client_max_body_size 10M`** — Matches the web app's 10 MB upload limit
- **Security headers** — X-Frame-Options, X-Content-Type-Options, XSS-Protection, Referrer-Policy
- **Static file caching** — `/static/` served directly by nginx with 7-day cache
- **Proxy timeouts** — 120s read timeout to handle long-running analyses

**Warning:** If you change the domain, update both the `server_name` and the SSL certificate paths.

---

## SSL Certificate Setup (Let's Encrypt)

### Initial Certificate

```bash
sudo certbot certonly --nginx -d counterscarp.io --non-interactive --agree-tos -m your@email.com
```

### Certificate Renewal

Certbot installs a systemd timer for automatic renewal. Verify it's active:

```bash
systemctl list-timers | grep certbot
```

Manual renewal test:

```bash
sudo certbot renew --dry-run
```

### Certificate Files

| File | Path |
|------|------|
| Full chain | `/etc/letsencrypt/live/counterscarp.io/fullchain.pem` |
| Private key | `/etc/letsencrypt/live/counterscarp.io/privkey.pem` |
| SSL options | `/etc/letsencrypt/options-ssl-nginx.conf` |
| DH params | `/etc/letsencrypt/ssl-dhparams.pem` |

---

## Systemd Service Management

The service unit file is at `deploy/counterscarp-engine.service`:

```ini
[Unit]
Description=Counterscarp Engine Web Application
After=network.target

[Service]
Type=exec
User=counterscarp
Group=counterscarp
WorkingDirectory=/opt/counterscarp-engine
ExecStart=/opt/counterscarp-engine/venv/bin/uvicorn webapp.main:app --host 127.0.0.1 --port 8001 --workers 4
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=COUNTERSCARP_UPLOAD_DIR=/opt/counterscarp-engine/uploads
Environment=COUNTERSCARP_RESULTS_DIR=/opt/counterscarp-engine/results

[Install]
WantedBy=multi-user.target
```

### Authentication & Session Configuration

The following environment variables must be set for user authentication. Variables marked **REQUIRED** must be configured before starting the service in production.

| Variable | Required | Description |
|----------|----------|-------------|
| `SESSION_SECRET` | **REQUIRED** | Random secret key for session encryption (min 32 chars). Generate with: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"` |
| `STRIPE_WEBHOOK_SECRET` | **REQUIRED** (if accepting payments) | Stripe webhook signing secret. Retrieve from Stripe Dashboard > Webhooks > Signing secret. Service returns 500 if not set when a webhook is received. |
| `ADMIN_EMAIL` | **REQUIRED** | Email address of the admin user. Restricts access to `/api/license/info` to this user. |
| `GOOGLE_CLIENT_ID` | No | Google OAuth 2.0 client ID (from Google Cloud Console) |
| `GOOGLE_CLIENT_SECRET` | No | Google OAuth 2.0 client secret |
| `GOOGLE_REDIRECT_URI` | No | OAuth callback URL (default: `http://localhost:8001/auth/google/callback`). Set to `https://app.counterscarp.io/auth/google/callback` in production |

Add these to the systemd unit file under `[Service]`:

```ini
Environment=SESSION_SECRET=<your-generated-secret>
Environment=STRIPE_WEBHOOK_SECRET=whsec_<your-signing-secret>
Environment=ADMIN_EMAIL=you@example.com
Environment=GOOGLE_CLIENT_ID=<your-client-id>
Environment=GOOGLE_CLIENT_SECRET=<your-client-secret>
Environment=GOOGLE_REDIRECT_URI=https://app.counterscarp.io/auth/google/callback
```

**Generating SESSION_SECRET:**

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

**Retrieving STRIPE_WEBHOOK_SECRET:**
1. Go to [Stripe Dashboard](https://dashboard.stripe.com) > Developers > Webhooks
2. Select your webhook endpoint
3. Click "Reveal" under **Signing secret** — it starts with `whsec_`

**Google OAuth Setup:**
1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create an OAuth 2.0 Client ID (Web Application type)
3. Add authorized redirect URI: `https://your-domain.com/auth/google/callback`
4. Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in your systemd service or environment

---

### Service Commands

```bash
# Start the service
sudo systemctl start counterscarp-engine

# Stop the service
sudo systemctl stop counterscarp-engine

# Restart the service
sudo systemctl restart counterscarp-engine

# Check status
sudo systemctl status counterscarp-engine

# Enable auto-start on boot
sudo systemctl enable counterscarp-engine

# View live logs
sudo journalctl -u counterscarp-engine -f

# View recent logs
sudo journalctl -u counterscarp-engine -n 50
```

**Note:** After modifying the unit file, always run `systemctl daemon-reload` before restarting.

---

## Installing External Tools

For full functionality, install these optional tools on the server:

### Slither

```bash
./venv/bin/pip install slither-analyzer
```

### Aderyn

```bash
# Requires Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo install aderyn
```

### Medusa

```bash
# Requires Go toolchain
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
go install github.com/crytic/medusa@latest
```

### Foundry (forge, cast, anvil)

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### Mythril

```bash
./venv/bin/pip install mythril
```

### cargo-audit (for Solana projects)

```bash
cargo install cargo-audit
```

---

## Update Procedure

### Quick Update

Use the `deploy/update.sh` script:

```bash
sudo bash deploy/update.sh
```

This script:
1. Pulls latest code from `main`
2. Reinstalls Python dependencies
3. Fixes ownership
4. Restarts the service
5. Verifies health

### Manual Update

```bash
cd /opt/counterscarp-engine

# Method A: Update from PyPI (if installed via pip)
./venv/bin/pip install --upgrade "counterscarp-engine[web]"

# Method B: Update from Git (if cloned)
# git pull origin main
# ./venv/bin/pip install -e ".[web]" --quiet

chown -R counterscarp:counterscarp /opt/counterscarp-engine
sudo systemctl restart counterscarp-engine
```

### Verify Update

```bash
curl -s http://127.0.0.1:8001/health | python3 -m json.tool
```

---

## Monitoring and Troubleshooting

### Health Check

```bash
curl http://127.0.0.1:8001/health
```

Expected response:
```json
{"status": "ok", "timestamp": "2024-01-15T10:30:00.000000"}
```

### Common Issues

| Symptom | Likely Cause | Fix |
|---------|-------------|-----|
| 502 Bad Gateway | App not running | `systemctl restart counterscarp-engine` |
| 413 Request Entity Too Large | File exceeds 10 MB | Increase `client_max_body_size` in nginx config |
| SSL errors | Certificate expired | `certbot renew && systemctl reload nginx` |
| Slow responses | Analysis taking long | Increase `proxy_read_timeout` in nginx |
| Upload fails | Permissions wrong | `chown -R counterscarp:counterscarp /opt/counterscarp-engine/uploads` |
| Webhook returns 500 | `STRIPE_WEBHOOK_SECRET` not set | Set `STRIPE_WEBHOOK_SECRET` in systemd unit and reload |

> **Security:** Stripe webhook signature verification is **mandatory** in v5.0.3. If `STRIPE_WEBHOOK_SECRET` is not configured, the `/api/stripe/webhook` endpoint will return HTTP 500. Retrieve the signing secret from Stripe Dashboard > Developers > Webhooks > Signing secret (`whsec_...`).

### Check Disk Space

```bash
df -h /opt/counterscarp-engine
```

Uploads and results accumulate over time. Consider setting up a cron job to clean old audit data:

```bash
# Remove results older than 30 days
find /opt/counterscarp-engine/results -type d -mtime +30 -exec rm -rf {} +
find /opt/counterscarp-engine/uploads -type d -mtime +30 -exec rm -rf {} +
```

### Check Running Processes

```bash
ps aux | grep uvicorn
ss -tlnp | grep 8001
```

---

## Log Management

### Application Logs

```bash
# Follow live logs
sudo journalctl -u counterscarp-engine -f

# Last 100 lines
sudo journalctl -u counterscarp-engine -n 100

# Logs since yesterday
sudo journalctl -u counterscarp-engine --since yesterday

# Logs with specific severity
sudo journalctl -u counterscarp-engine -p err
```

### Nginx Logs

```bash
# Access log
sudo tail -f /var/log/nginx/access.log

# Error log
sudo tail -f /var/log/nginx/error.log
```

### Log Rotation

Journal logs are auto-rotated by systemd. Configure retention:

```bash
# Keep only last 7 days of journal logs
sudo journalctl --vacuum-time=7d
```

Nginx logs are rotated by `logrotate` (installed by default on Ubuntu).

---

### Log Management and Cleanup

#### Python Application Log Rotation

The web application uses Python's `RotatingFileHandler` for automatic log rotation:

- **Max file size:** 10 MB per file
- **Backup count:** 7 files retained (approx. 70 MB max total)
- Rotation is handled entirely within the Python process — no external cron job required for application logs.

#### System-Level Log Rotation (logrotate)

For system-level management of the application's on-disk log files, install the bundled logrotate config:

```bash
sudo cp deploy/logrotate-counterscarp /etc/logrotate.d/counterscarp
```

This handles compressed rotation, postrotate reloads, and log directory cleanup in coordination with the OS logrotate daemon.

#### Automatic Startup Cleanup

On every service startup, the application automatically purges stale working data based on the following retention policy:

| Data Type | Directory | Retention Period |
|-----------|-----------|-----------------|
| State / cache files | `.scarpshield/` (legacy `.counterscarp/` supported) | 30 days |
| Report directories | `reports/` | 90 days |
| Upload directories | `uploads/` | 7 days |

> **Note:** These retention periods are currently hardcoded. Configurable retention via `scarpshield.toml` (or legacy `counterscarp.toml`) is planned for a future release.

No additional cron jobs are needed for routine cleanup; however, you can still manually purge data if needed:

```bash
# Manual cleanup example (adjust paths as needed)
find /opt/counterscarp-engine/uploads -type d -mtime +7 -exec rm -rf {} +
find /opt/counterscarp-engine/reports -type d -mtime +90 -exec rm -rf {} +
```

---

*Counterscarp Security Engine &bull; counterscarp.io*
