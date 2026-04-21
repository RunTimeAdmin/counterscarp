#!/bin/bash
# Garrison Engine Web App - VPS Deployment Script
# Run as root on Ubuntu 22.04
set -e

echo "=== Garrison Engine Deployment ==="

# Create service user (no login shell, no home)
echo "[1/8] Creating service user..."
useradd -r -s /bin/false garrison 2>/dev/null || true

# Clone or update repository
echo "[2/8] Cloning/updating repository..."
mkdir -p /opt/garrison-engine
cd /opt/garrison-engine
if [ -d ".git" ]; then
    git pull origin main
else
    git clone https://github.com/RunTimeAdmin/garrison-engine.git .
fi

# Create Python virtualenv and install
echo "[3/8] Setting up Python environment..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -e ".[web]"

# Create required directories
echo "[4/8] Creating directories..."
mkdir -p /opt/garrison-engine/uploads
mkdir -p /opt/garrison-engine/results

# Set ownership
echo "[5/8] Setting permissions..."
chown -R garrison:garrison /opt/garrison-engine

# Install nginx configuration
echo "[6/8] Configuring nginx..."
cp deploy/nginx-garrison.conf /etc/nginx/sites-available/garrison
ln -sf /etc/nginx/sites-available/garrison /etc/nginx/sites-enabled/garrison
nginx -t
systemctl reload nginx

# Obtain SSL certificate (nginx must be running first for challenge)
echo "[7/8] Obtaining SSL certificate..."
if [ ! -d "/etc/letsencrypt/live/app.sentinel-engine.io" ]; then
    certbot certonly --nginx -d app.sentinel-engine.io --non-interactive --agree-tos -m support@sentinel-engine.io
    systemctl reload nginx
else
    echo "   SSL certificate already exists, skipping..."
fi

# Install and start systemd service
echo "[8/8] Starting service..."
cp deploy/garrison-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable garrison-engine
systemctl restart garrison-engine

echo ""
echo "=== Deployment Complete ==="
echo "   URL: https://app.sentinel-engine.io"
echo "   Status: systemctl status garrison-engine"
echo "   Logs: journalctl -u garrison-engine -f"
echo ""

# Verify health
sleep 3
if curl -s http://127.0.0.1:8001/health | grep -q "ok"; then
    echo "   Health check: PASSED"
else
    echo "   Health check: FAILED - check logs with: journalctl -u garrison-engine -n 50"
fi
