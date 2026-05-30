#!/bin/bash
# Quick update script - pull latest code and restart services
set -e

echo "=== Updating Counterscarp Engine ==="
cd /opt/counterscarp-engine
git fetch origin main
git reset --hard origin/main
./venv/bin/pip install -e ".[web]" --quiet

# Slither + solc (optional; safe to re-run)
if [ -f scripts/install-slither-vps.sh ]; then
    bash scripts/install-slither-vps.sh || echo "WARNING: Slither install step failed — check solc/slither manually"
fi

chown -R garrison:garrison /opt/counterscarp-engine 2>/dev/null \
    || chown -R counterscarp:counterscarp /opt/counterscarp-engine
systemctl restart counterscarp-engine
if systemctl list-unit-files counterscarp-worker.service --no-legend 2>/dev/null | grep -q counterscarp-worker; then
    systemctl restart counterscarp-worker
fi
sleep 2

if curl -s http://127.0.0.1:8001/health | grep -q "ok"; then
    echo "Update complete - service healthy"
else
    echo "WARNING: Service may not be healthy. Check: journalctl -u counterscarp-engine -n 20"
fi
