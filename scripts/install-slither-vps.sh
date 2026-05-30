#!/usr/bin/env bash
# Install Slither + solc on Counterscarp VPS (bare-metal venv deploy).
# Run on the server as a user with sudo, from /opt/garrison-engine (or counterscarp-engine).

set -euo pipefail

VENV="${VENV:-/opt/counterscarp-engine/venv}"
SLITHER_VERSION="${SLITHER_VERSION:-0.11.5}"

echo "[1/4] Installing slither-analyzer==${SLITHER_VERSION} into ${VENV}"
"${VENV}/bin/pip" install --no-cache-dir "slither-analyzer==${SLITHER_VERSION}"

echo "[2/4] Installing solc-select"
"${VENV}/bin/pip" install --no-cache-dir solc-select

echo "[3/4] Installing common solc versions"
export PATH="${HOME}/.local/bin:${PATH}"
"${VENV}/bin/solc-select" install 0.8.0 || true
"${VENV}/bin/solc-select" install 0.8.19 || true
"${VENV}/bin/solc-select" install 0.8.25 || true
"${VENV}/bin/solc-select" use 0.8.25

echo "[4/4] Verify"
"${VENV}/bin/slither" --version
solc --version

echo "Done. Restart worker: sudo systemctl restart counterscarp-worker"
