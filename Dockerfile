# ==============================================================================
# COUNTERSCARP ENGINE — DOCKERFILE
# Multi-stage build: 21-analyzer stack for smart contract security auditing
# ==============================================================================

# ------------------------------------------------------------------------------
# STAGE 1 — Go builder (Medusa coverage-guided fuzzer)
# ------------------------------------------------------------------------------
FROM golang:1.24-bookworm AS go-builder

ARG MEDUSA_VERSION=v0.1.8

# Clone and build Medusa from source (go install fails because
# Medusa's go.mod contains 'replace' directives, which are rejected
# by 'go install pkg@version' in every Go version).
RUN git clone --depth 1 --branch ${MEDUSA_VERSION} https://github.com/crytic/medusa.git /tmp/medusa \
    && cd /tmp/medusa \
    && go build -o /go/bin/medusa . \
    && rm -rf /tmp/medusa

# Confirm the binary was placed at the expected path
RUN ls /go/bin/medusa

# ------------------------------------------------------------------------------
# STAGE 2 — Final runtime image
# Base: python:3.12-slim-bookworm (Debian Bookworm, smaller than full image)
# ------------------------------------------------------------------------------
FROM python:3.12-slim-bookworm

# ── Metadata ──────────────────────────────────────────────────────────────────
ARG APP_VERSION=5.0.5
LABEL maintainer="Counterscarp Engine Team"
LABEL description="Smart contract security auditing platform — 21-analyzer stack"
LABEL version="${APP_VERSION}"

# ── Environment variables ─────────────────────────────────────────────────────
# Prevent .pyc files and enable unbuffered output for clean container logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Add all tool binary paths to PATH so they can be invoked by name anywhere
# Note: paths use /root/ during build; overridden to /home/counterscarp/ after USER switch
ENV PATH="/root/.foundry/bin:/root/.cargo/bin:/root/.local/bin:/usr/local/go/bin:/root/go/bin:$PATH"

# ── 1. System dependencies ────────────────────────────────────────────────────
# curl/git: needed for Foundry and Aderyn installers
# build-essential: required by Mythril's C extensions (leveldb bindings etc.)
# libssl-dev / ca-certificates: TLS for curl-based installers
# libxml2: required by xhtml2pdf (PDF report generation)
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        libssl-dev \
        libxml2 \
        libcairo2-dev \
        ca-certificates \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

# ── 2. Install Foundry (forge + cast + anvil + chisel) ────────────────────────
# The official installer drops binaries into ~/.foundry/bin
# We run foundryup immediately after to pull the latest stable release
RUN curl -L https://foundry.paradigm.xyz | bash \
    && /root/.foundry/bin/foundryup \
    && forge --version \
    && echo "[foundry] installed OK"

# ── 3. Install Aderyn (Rust-based Solidity static analyser by Cyfrin) ─────────
# cyfrinup was removed; install via the direct GitHub installer script
RUN curl --proto '=https' --tlsv1.2 -LsSf \
        https://github.com/cyfrin/aderyn/releases/download/aderyn-v0.6.8/aderyn-installer.sh \
        | sh \
    && aderyn --version \
    && echo "[aderyn] installed OK"

# ── 4. Copy Medusa binary from Stage 1 ───────────────────────────────────────
COPY --from=go-builder /go/bin/medusa /usr/local/bin/medusa
RUN medusa --version && echo "[medusa] installed OK"

# ── 5. Python tooling — solc-select + Solidity compiler ──────────────────────
RUN pip install --no-cache-dir solc-select==1.2.0 \
    && solc-select install 0.8.28 \
    && solc-select use 0.8.28 \
    && echo "[solc] 0.8.28 active"

# ── 6. Install the Counterscarp Engine package (with PDF extras) ──────────────
# Copy the full source first so pip can resolve pyproject.toml
WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir ".[web,pdf]" \
    && echo "[counterscarp-engine] installed OK"

# ── 7. Install Slither (Python-based EVM static analyser) ────────────────────
RUN pip install --no-cache-dir slither-analyzer==0.11.5 \
    && echo "[slither] installed OK"

# ── 8. Install Mythril (symbolic execution / EVM bytecode analyser) ───────────
# mythril has heavy C-extension deps — build-essential (above) satisfies them
RUN pip install --no-cache-dir mythril==0.24.8 \
    && echo "[mythril] installed OK"

# ── 9. Clean up caches to reduce final image size ────────────────────────────
RUN pip cache purge \
    && apt-get clean \
    && rm -rf /tmp/* /root/.cache

# ── 10. Pre-install additional solc versions commonly seen in audits ──────────
RUN solc-select install 0.8.19 \
    && solc-select install 0.8.25 \
    && solc-select install 0.7.6 \
    && solc-select install 0.6.12 \
    && echo "[solc] additional versions installed"

# ── 11. Working directory for scan mounts ────────────────────────────────────
# /scan is the conventional mount point for the target contract tree
WORKDIR /scan

# ── 12. Create non-root user ─────────────────────────────────────────────────
# Run as unprivileged user for defense-in-depth.  Copy Foundry/solc
# caches from root's home into the new user's home so tools still work.
RUN useradd -m -u 1000 counterscarp \
    && mkdir -p /output /scan \
    && cp -r /root/.foundry /home/counterscarp/.foundry || true \
    && cp -r /root/.solc-select /home/counterscarp/.solc-select || true \
    && cp -r /root/.svm /home/counterscarp/.svm 2>/dev/null || true \
    && chown -R counterscarp:counterscarp /app /scan /output /home/counterscarp

ENV PATH="/home/counterscarp/.foundry/bin:/home/counterscarp/.cargo/bin:/home/counterscarp/.local/bin:/usr/local/go/bin:/home/counterscarp/go/bin:$PATH"

USER counterscarp

# ── 13. Docker HEALTHCHECK ───────────────────────────────────────────────────
# Runs `counterscarp --doctor` — the built-in environment diagnostic command.
# exit 0 = all critical tools found; non-zero = something is missing.
HEALTHCHECK --interval=60s --timeout=30s --start-period=10s --retries=3 \
    CMD counterscarp --doctor

# ── 14. Entrypoint ───────────────────────────────────────────────────────────
# counterscarp is the console_scripts entry point defined in pyproject.toml:
#   counterscarp = "orchestrator:main"
# Pass `--help` as the default CMD so a bare `docker run` prints usage.
ENTRYPOINT ["counterscarp"]
CMD ["--help"]

# ==============================================================================
# USAGE EXAMPLES
# ==============================================================================
#
# Build the image:
#   docker build -t counterscarp-engine:5.0.5 .
#
# Run a full audit scan (mounts current directory as /scan):
#   docker run --rm -v $(pwd):/scan -v $(pwd)/output:/output \
#       counterscarp-engine:5.0.5 --target /scan --report --output-dir /output
#
# Run only heuristic + Slither (no fuzzing):
#   docker run --rm -v $(pwd):/scan counterscarp-engine:5.0.5 --target /scan
#
# Run environment diagnostics:
#   docker run --rm counterscarp-engine:5.0.5 --doctor
#
# Interactive shell:
#   docker run --rm -it -v $(pwd):/scan counterscarp-engine:5.0.5 /bin/bash
# ==============================================================================
