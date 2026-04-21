#!/bin/bash
# Counterscarp Engine Web App - VPS Deployment Script
# Run as root on Ubuntu 22.04
set -e

echo "=== Counterscarp Engine Deployment ==="

# Create service user (no login shell, no home)
echo "[1/8] Creating service user..."
useradd -r -s /bin/false counterscarp 2>/dev/null || true

# Clone or update repository
echo "[2/8] Cloning/updating repository..."
mkdir -p /opt/counterscarp-engine
cd /opt/counterscarp-engine
if [ -d ".git" ]; then
    git pull origin main
else
    git clone https://github.com/RunTimeAdmin/counterscarp.git .
fi

# Create Python virtualenv and install
echo "[3/8] Setting up Python environment..."
python3 -m venv venv
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -e ".[web]"

# Create required directories
echo "[4/8] Creating directories..."
mkdir -p /opt/counterscarp-engine/uploads
mkdir -p /opt/counterscarp-engine/results

# Set ownership
echo "[5/8] Setting permissions..."
chown -R counterscarp:counterscarp /opt/counterscarp-engine

# Install nginx configuration
echo "[6/8] Configuring nginx..."
cp deploy/nginx-counterscarp.conf /etc/nginx/sites-available/counterscarp
ln -sf /etc/nginx/sites-available/counterscarp /etc/nginx/sites-enabled/counterscarp
nginx -t
systemctl reload nginx

# Obtain SSL certificate (nginx must be running first for challenge)
echo "[7/8] Obtaining SSL certificate..."
if [ ! -d "/etc/letsencrypt/live/app.counterscarp.io" ]; then
    certbot certonly --nginx -d app.counterscarp.io --non-interactive --agree-tos -m contact@counterscarp.io
    systemctl reload nginx
else
    echo "   SSL certificate already exists, skipping..."
fi

# Install and start systemd service
echo "[8/8] Starting service..."
cp deploy/counterscarp-engine.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable counterscarp-engine
systemctl restart counterscarp-engine

echo ""
echo "=== Deployment Complete ==="
echo "   URL: https://app.counterscarp.io"
echo "   Status: systemctl status counterscarp-engine"
echo "   Logs: journalctl -u counterscarp-engine -f"
echo ""

# Verify health
sleep 3
if curl -s http://127.0.0.1:8001/health | grep -q "ok"; then
    echo "   Health check: PASSED"
else
    echo "   Health check: FAILED - check logs with: journalctl -u counterscarp-engine -n 50"
fi
