# ------------------------------------------------------------------------------
# THE SENTINEL ENGINE - DOCKERFILE
# Multi-Chain Smart Contract Security Auditing Toolkit
# ------------------------------------------------------------------------------
# Stage 1: Build stage for Rust/Go tools
FROM python:3.10-slim-bullseye AS builder

# Install build dependencies for Rust and Go
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    libssl-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Rust (for Aderyn)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:$PATH"

# Install Aderyn (Rust-based Solidity static analyzer by Cyfrin)
RUN cargo install aderyn@0.6.2

# Install Go (for Medusa)
RUN curl -L https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xzf -
ENV PATH="/usr/local/go/bin:$PATH"

# Install Medusa (Go-based coverage-guided fuzzer by Crytic)
RUN go install github.com/crytic/medusa/cmd/medusa@v0.1.8

# ------------------------------------------------------------------------------
# Stage 2: Final runtime image
FROM python:3.10-slim-bullseye

# Metadata
LABEL maintainer="CyberShield Austin / TokenAudit"
LABEL description="Professional-grade smart contract security auditing toolkit (EVM + Solana)"
LABEL version="2.1"

# 1. ENVIRONMENT VARIABLES
# Prevent Python from writing .pyc files
ENV PYTHONDONTWRITEBYTECODE=1
# Keep Python output unbuffered (so you see logs immediately)
ENV PYTHONUNBUFFERED=1
# Add local bin to path for Foundry/Solc/Aderyn/Medusa
ENV PATH="/root/.foundry/bin:/root/.local/bin:/root/.cargo/bin:/usr/local/go/bin:/root/go/bin:$PATH"

# 2. SYSTEM DEPENDENCIES
# We need git/curl for installing Foundry and build-essential for compiling deps
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    libssl-dev \
    libxml2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 3. INSTALL PYTHON TOOLS
# Install core dependencies for the Sentinel Engine
RUN pip install --no-cache-dir \
    slither-analyzer==0.11.5 \
    mythril==0.24.8 \
    solc-select \
    requests \
    packaging

# Initialize solc-select (install commonly used versions)
# Legacy versions
RUN solc-select install 0.6.12 && \
    solc-select install 0.7.6

# Modern versions
RUN solc-select install 0.8.19 && \
    solc-select install 0.8.20 && \
    solc-select install 0.8.23 && \
    solc-select install 0.8.25 && \
    solc-select install 0.8.26 && \
    solc-select install 0.8.27 && \
    solc-select install 0.8.28

# Set default Solidity version
RUN solc-select use 0.8.19

# 4. INSTALL FOUNDRY (Fuzzing Engine)
# We use the official install script (optional - graceful degradation if fails)
RUN curl -L https://foundry.paradigm.xyz | bash || echo "Foundry install skipped" && \
    (if [ -f /root/.foundry/bin/foundryup ]; then /root/.foundry/bin/foundryup || true; fi)

# 5. COPY BINARIES FROM BUILDER STAGE
# Copy Aderyn binary
COPY --from=builder /root/.cargo/bin/aderyn /usr/local/bin/aderyn

# Copy Medusa binary
COPY --from=builder /root/go/bin/medusa /usr/local/bin/medusa

# 6. SETUP WORKSPACE
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

# Tool version manifest
COPY tool-versions.json /app/tool-versions.json
COPY healthcheck.py /app/healthcheck.py

# Design Documentation (reference)
# Note: Skipping design docs to keep image lean (available in repo)
# COPY Pragmatic\ Security\ Engine.txt ./docs/
# COPY Action-Oriented\ Orchestrator.txt ./docs/
# COPY God\ Mode\ Matrix.txt ./docs/
# COPY Directions\ for\ tools.txt ./docs/

# 7. HEALTHCHECK
# Verify Python and core dependencies are installed
RUN python3 --version && \
    pip list | grep slither-analyzer && \
    aderyn --version && \
    medusa --version && \
    echo "✓ Sentinel Engine core dependencies installed"

# 8. HEALTHCHECK DIRECTIVE
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python /app/healthcheck.py

# 9. ENTRYPOINT
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
