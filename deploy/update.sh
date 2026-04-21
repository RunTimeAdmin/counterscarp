#!/bin/bash
# Quick update script - pull latest code and restart service
set -e

echo "=== Updating Counterscarp Engine ==="
cd /opt/counterscarp-engine
git pull origin main
./venv/bin/pip install -e ".[web]" --quiet
chown -R counterscarp:counterscarp /opt/counterscarp-engine
systemctl restart counterscarp-engine
sleep 2

if curl -s http://127.0.0.1:8001/health | grep -q "ok"; then
    echo "Update complete - service healthy"
else
    echo "WARNING: Service may not be healthy. Check: journalctl -u counterscarp-engine -n 20"
fi
