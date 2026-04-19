#!/bin/bash
# Quick update script - pull latest code and restart service
set -e

echo "=== Updating Sentinel Engine ==="
cd /opt/sentinel-engine
git pull origin main
./venv/bin/pip install -e ".[web]" --quiet
chown -R sentinel:sentinel /opt/sentinel-engine
systemctl restart sentinel-engine
sleep 2

if curl -s http://127.0.0.1:8001/health | grep -q "ok"; then
    echo "Update complete - service healthy"
else
    echo "WARNING: Service may not be healthy. Check: journalctl -u sentinel-engine -n 20"
fi
