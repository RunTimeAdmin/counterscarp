# ------------------------------------------------------------------------------
# THE SENTINEL ENGINE - DOCKERFILE
# Multi-Chain Smart Contract Security Auditing Toolkit
# ------------------------------------------------------------------------------
# Base Image: Python 3.10 (Slim version for speed)
FROM python:3.10-slim-bullseye

# Metadata
LABEL maintainer="CyberShield Austin / TokenAudit"
LABEL description="Professional-grade smart contract security auditing toolkit (EVM + Solana)"
LABEL version="2.0"

# 1. ENVIRONMENT VARIABLES
# Prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1 
# Keep Python output unbuffered (so you see logs immediately)
ENV PYTHONUNBUFFERED=1
# Add local bin to path for Foundry/Solc
ENV PATH="/root/.foundry/bin:/root/.local/bin:$PATH"

# 2. SYSTEM DEPENDENCIES
# We need git/curl for installing Foundry and build-essential for compiling deps
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    libssl-dev \
    libxml2 \
    && rm -rf /var/lib/apt/lists/*

# 3. INSTALL PYTHON TOOLS
# Install core dependencies for the Sentinel Engine
RUN pip install --no-cache-dir \
    slither-analyzer \
    solc-select \
    requests \
    packaging

# Initialize solc-select (install multiple stable versions)
RUN solc-select install 0.8.19 && \
    solc-select install 0.8.20 && \
    solc-select install 0.8.23 && \
    solc-select use 0.8.19

# 4. INSTALL FOUNDRY (Fuzzing Engine)
# We use the official install script (optional - graceful degradation if fails)
RUN curl -L https://foundry.paradigm.xyz | bash || echo "Foundry install skipped" && \
    (if [ -f /root/.foundry/bin/foundryup ]; then /root/.foundry/bin/foundryup || true; fi)

# 5. SETUP WORKSPACE
WORKDIR /app

# Copy all Sentinel Engine scripts
COPY orchestrator.py .
COPY red_team_scan.py .
COPY supply_chain_check.py .
COPY fuzz_wrapper.py .
COPY access_matrix.py .
COPY symbolic_wrapper.py .
COPY heuristic_scanner.py .
COPY inflation_scaffold.py .
COPY intent_check.py .

# Threat Intelligence Modules
COPY knowledge_fetcher.py .
COPY solana_intel.py .
COPY threat_intel.py .

# Advanced Analysis Tools (NEW)
COPY medusa_wrapper.py .
COPY exploit_generator.py .
COPY upgrade_diff.py .
COPY aderyn_wrapper.py .

# GUI (optional - for local runs)
COPY gui.py .

# Design Documentation (reference)
# Note: Skipping design docs to keep image lean (available in repo)
# COPY Pragmatic\ Security\ Engine.txt ./docs/
# COPY Action-Oriented\ Orchestrator.txt ./docs/
# COPY God\ Mode\ Matrix.txt ./docs/
# COPY Directions\ for\ tools.txt ./docs/

# 6. HEALTHCHECK
# Verify Python and core dependencies are installed
RUN python3 --version && \
    pip list | grep slither-analyzer && \
    echo "✓ Sentinel Engine core dependencies installed"

# 7. ENTRYPOINT
# Default: Show orchestrator help
ENTRYPOINT ["python3", "orchestrator.py"]
CMD ["--help"]

# ------------------------------------------------------------------------------
# USAGE EXAMPLES:
#
# Build:
#   docker build -t sentinel-engine .
#
# Scan EVM contract:
#   docker run --rm -v $(pwd):/scan sentinel-engine --target /scan
#
# Threat intel (EVM):
#   docker run --rm -v $(pwd):/scan sentinel-engine python3 threat_intel.py /scan/contracts/Vault.sol
#
# Threat intel (Solana):
#   docker run --rm -v $(pwd):/scan sentinel-engine python3 solana_intel.py /scan/programs/lib.rs
#
# Interactive shell:
#   docker run --rm -it -v $(pwd):/scan sentinel-engine /bin/bash
# ------------------------------------------------------------------------------
