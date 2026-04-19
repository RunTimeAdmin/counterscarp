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
| 1/8 | Creates service user `sentinel` (no login shell) |
| 2/8 | Clones/updates repository to `/opt/sentinel-engine` |
| 3/8 | Creates Python venv and installs `sentinel-engine[web]` |
| 4/8 | Creates `uploads/` and `results/` directories |
| 5/8 | Sets ownership to `sentinel:sentinel` |
| 6/8 | Installs nginx config and reloads nginx |
| 7/8 | Obtains SSL certificate via certbot (if not already present) |
| 8/8 | Installs systemd service and starts it |

### Manual Deployment

If you prefer to deploy manually:

```bash
# 1. Create service user
useradd -r -s /bin/false sentinel

# 2. Clone repository
mkdir -p /opt/sentinel-engine
cd /opt/sentinel-engine
git clone https://github.com/RunTimeAdmin/sentinel-engine.git .

# 3. Setup Python environment
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -e ".[web]"

# 4. Create directories
mkdir -p /opt/sentinel-engine/uploads
mkdir -p /opt/sentinel-engine/results

# 5. Set ownership
chown -R sentinel:sentinel /opt/sentinel-engine

# 6. Configure nginx
cp deploy/nginx-sentinel.conf /etc/nginx/sites-available/sentinel
ln -sf /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/sentinel
nginx -t && systemctl reload nginx

# 7. SSL certificate
certbot certonly --nginx -d app.sentinel-engine.io --non-interactive --agree-tos -m your@email.com

# 8. Start service
cp deploy/sentinel-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable sentinel-engine
systemctl start sentinel-engine
```

---

## Nginx Reverse Proxy Configuration

The nginx configuration is located at `deploy/nginx-sentinel.conf`:

```nginx
server {
    listen 80;
    listen [::]:80;
    server_name app.sentinel-engine.io;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name app.sentinel-engine.io;

    ssl_certificate /etc/letsencrypt/live/app.sentinel-engine.io/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/app.sentinel-engine.io/privkey.pem;
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
        alias /opt/sentinel-engine/webapp/static/;
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
sudo certbot certonly --nginx -d app.sentinel-engine.io --non-interactive --agree-tos -m your@email.com
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
| Full chain | `/etc/letsencrypt/live/app.sentinel-engine.io/fullchain.pem` |
| Private key | `/etc/letsencrypt/live/app.sentinel-engine.io/privkey.pem` |
| SSL options | `/etc/letsencrypt/options-ssl-nginx.conf` |
| DH params | `/etc/letsencrypt/ssl-dhparams.pem` |

---

## Systemd Service Management

The service unit file is at `deploy/sentinel-engine.service`:

```ini
[Unit]
Description=Sentinel Engine Web Application
After=network.target

[Service]
Type=exec
User=sentinel
Group=sentinel
WorkingDirectory=/opt/sentinel-engine
ExecStart=/opt/sentinel-engine/venv/bin/uvicorn webapp.main:app --host 127.0.0.1 --port 8001 --workers 4
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
Environment=SENTINEL_UPLOAD_DIR=/opt/sentinel-engine/uploads
Environment=SENTINEL_RESULTS_DIR=/opt/sentinel-engine/results

[Install]
WantedBy=multi-user.target
```

### Service Commands

```bash
# Start the service
sudo systemctl start sentinel-engine

# Stop the service
sudo systemctl stop sentinel-engine

# Restart the service
sudo systemctl restart sentinel-engine

# Check status
sudo systemctl status sentinel-engine

# Enable auto-start on boot
sudo systemctl enable sentinel-engine

# View live logs
sudo journalctl -u sentinel-engine -f

# View recent logs
sudo journalctl -u sentinel-engine -n 50
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
cd /opt/sentinel-engine
git pull origin main
./venv/bin/pip install -e ".[web]" --quiet
chown -R sentinel:sentinel /opt/sentinel-engine
sudo systemctl restart sentinel-engine
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
| 502 Bad Gateway | App not running | `systemctl restart sentinel-engine` |
| 413 Request Entity Too Large | File exceeds 10 MB | Increase `client_max_body_size` in nginx config |
| SSL errors | Certificate expired | `certbot renew && systemctl reload nginx` |
| Slow responses | Analysis taking long | Increase `proxy_read_timeout` in nginx |
| Upload fails | Permissions wrong | `chown -R sentinel:sentinel /opt/sentinel-engine/uploads` |

### Check Disk Space

```bash
df -h /opt/sentinel-engine
```

Uploads and results accumulate over time. Consider setting up a cron job to clean old audit data:

```bash
# Remove results older than 30 days
find /opt/sentinel-engine/results -type d -mtime +30 -exec rm -rf {} +
find /opt/sentinel-engine/uploads -type d -mtime +30 -exec rm -rf {} +
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
sudo journalctl -u sentinel-engine -f

# Last 100 lines
sudo journalctl -u sentinel-engine -n 100

# Logs since yesterday
sudo journalctl -u sentinel-engine --since yesterday

# Logs with specific severity
sudo journalctl -u sentinel-engine -p err
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

*Sentinel Security Engine &bull; sentinel-engine.io*
