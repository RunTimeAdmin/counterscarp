# Server Deployment Guide

## Table of Contents

- [Prerequisites](#prerequisites)
- [Step-by-Step VPS Deployment](#step-by-step-vps-deployment)
- [Nginx Reverse Proxy Configuration](#nginx-reverse-proxy-configuration)
- [SSL Certificate Setup](#ssl-certificate-setup-lets-encrypt)
- [Systemd Service Management](#systemd-service-management)
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

## Step-by-Step VPS Deployment

The `deploy/setup.sh` script automates the full deployment. Run as root:

```bash
sudo bash deploy/setup.sh
```

### What the script does (8 steps)

| Step | Action |
|------|--------|
| 1/8 | Creates service user `garrison` (no login shell) |
| 2/8 | Clones/updates repository to `/opt/garrison-engine` |
| 3/8 | Creates Python venv and installs `garrison-engine[web]` |
| 4/8 | Creates `uploads/` and `results/` directories |
| 5/8 | Sets ownership to `garrison:garrison` |
| 6/8 | Installs nginx config and reloads nginx |
| 7/8 | Obtains SSL certificate via certbot (if not already present) |
| 8/8 | Installs systemd service and starts it |

### Manual Deployment

If you prefer to deploy manually:

```bash
# 1. Create service user
useradd -r -s /bin/false garrison

# 2. Setup directory (choose one method)

# Method A: Install from PyPI (recommended for production)
mkdir -p /opt/garrison-engine
cd /opt/garrison-engine
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install "garrison-engine[web]"

# Method B: Clone from GitHub (for development/customization)
# mkdir -p /opt/garrison-engine
# cd /opt/garrison-engine
# git clone https://github.com/RunTimeAdmin/garrison-engine.git .
# python3 -m venv venv
# ./venv/bin/pip install --upgrade pip
# ./venv/bin/pip install -e ".[web]"

# 3. Create directories
mkdir -p /opt/garrison-engine/uploads
mkdir -p /opt/garrison-engine/results

# 4. Set ownership
chown -R garrison:garrison /opt/garrison-engine

# 5. Configure nginx
cp deploy/nginx-garrison.conf /etc/nginx/sites-available/garrison
ln -sf /etc/nginx/sites-available/garrison /etc/nginx/sites-enabled/garrison
nginx -t && systemctl reload nginx

# 6. SSL certificate
certbot certonly --nginx -d garrisonsec.com --non-interactive --agree-tos -m your@email.com

# 7. Start service
cp deploy/garrison-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable garrison-engine
systemctl start garrison-engine
```

---

## Nginx Reverse Proxy Configuration

The nginx configuration is located at `deploy/nginx-garrison.conf`:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name garrisonsec.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name garrisonsec.com;

    ssl_certificate /etc/letsencrypt/live/garrisonsec.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/garrisonsec.com/privkey.pem;
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
        alias /opt/garrison-engine/webapp/static/;
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
sudo certbot certonly --nginx -d garrisonsec.com --non-interactive --agree-tos -m your@email.com
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
| Full chain | `/etc/letsencrypt/live/garrisonsec.com/fullchain.pem` |
| Private key | `/etc/letsencrypt/live/garrisonsec.com/privkey.pem` |
| SSL options | `/etc/letsencrypt/options-ssl-nginx.conf` |
| DH params | `/etc/letsencrypt/ssl-dhparams.pem` |

---

## Systemd Service Management

The service unit file is at `deploy/garrison-engine.service`:

```ini
[Unit]
Description=Garrison Engine Web Application
After=network.target

[Service]
Type=exec
User=garrison
Group=garrison
WorkingDirectory=/opt/garrison-engine
ExecStart=/opt/garrison-engine/venv/bin/uvicorn webapp.main:app --host 127.0.0.1 --port 8001 --workers 4
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=GARRISON_UPLOAD_DIR=/opt/garrison-engine/uploads
Environment=GARRISON_RESULTS_DIR=/opt/garrison-engine/results

[Install]
WantedBy=multi-user.target
```

### Service Commands

```bash
# Start the service
sudo systemctl start garrison-engine

# Stop the service
sudo systemctl stop garrison-engine

# Restart the service
sudo systemctl restart garrison-engine

# Check status
sudo systemctl status garrison-engine

# Enable auto-start on boot
sudo systemctl enable garrison-engine

# View live logs
sudo journalctl -u garrison-engine -f

# View recent logs
sudo journalctl -u garrison-engine -n 50
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
cd /opt/garrison-engine

# Method A: Update from PyPI (if installed via pip)
./venv/bin/pip install --upgrade "garrison-engine[web]"

# Method B: Update from Git (if cloned)
# git pull origin main
# ./venv/bin/pip install -e ".[web]" --quiet

chown -R garrison:garrison /opt/garrison-engine
sudo systemctl restart garrison-engine
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
| 502 Bad Gateway | App not running | `systemctl restart garrison-engine` |
| 413 Request Entity Too Large | File exceeds 10 MB | Increase `client_max_body_size` in nginx config |
| SSL errors | Certificate expired | `certbot renew && systemctl reload nginx` |
| Slow responses | Analysis taking long | Increase `proxy_read_timeout` in nginx |
| Upload fails | Permissions wrong | `chown -R garrison:garrison /opt/garrison-engine/uploads` |

### Check Disk Space

```bash
df -h /opt/garrison-engine
```

Uploads and results accumulate over time. Consider setting up a cron job to clean old audit data:

```bash
# Remove results older than 30 days
find /opt/garrison-engine/results -type d -mtime +30 -exec rm -rf {} +
find /opt/garrison-engine/uploads -type d -mtime +30 -exec rm -rf {} +
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
sudo journalctl -u garrison-engine -f

# Last 100 lines
sudo journalctl -u garrison-engine -n 100

# Logs since yesterday
sudo journalctl -u garrison-engine --since yesterday

# Logs with specific severity
sudo journalctl -u garrison-engine -p err
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

*Garrison Security Engine &bull; garrisonsec.com*
