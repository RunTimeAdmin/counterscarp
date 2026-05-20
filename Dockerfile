# ==============================================================================
# COUNTERSCARP ENGINE — DOCKERFILE
# Multi-stage build: 21-analyzer stack for smart contract security auditing
# ==============================================================================

# ------------------------------------------------------------------------------
# STAGE 1 — Go builder (Medusa coverage-guided fuzzer)
# ------------------------------------------------------------------------------
FROM golang:1.24-bookworm AS go-builder

ARG MEDUSA_VERSION=v1.5.1

# Clone and build Medusa from source (go install fails because
# Medusa's go.mod contains 'replace' directives, which are rejected
# by 'go install pkg@version' in every Go version).
RUN git clone --depth 1 --branch ${MEDUSA_VERSION} https://github.com/crytic/medusa.git /tmp/medusa \
    && cd /tmp/medusa \
    && go get github.com/pion/dtls/v2@latest \
    && go mod tidy \
    && go build -o /go/bin/medusa . \
    && rm -rf /tmp/medusa

# Confirm the binary was placed at the expected path
RUN ls /go/bin/medusa

# ------------------------------------------------------------------------------
# STAGE 2 — Toolchain builder image
# Base: python:3.12-slim (tracks latest Debian stable slim image)
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS tools-builder

# ── Metadata ──────────────────────────────────────────────────────────────────
ARG APP_VERSION=5.1.1
LABEL maintainer="Counterscarp Engine Team"
LABEL description="Smart contract security auditing platform — 21-analyzer stack"
LABEL version="${APP_VERSION}"

# ── Environment variables ─────────────────────────────────────────────────────
# Prevent .pyc files and enable unbuffered output for clean container logs
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive

# Add all tool binary paths to PATH so they can be invoked by name anywhere
# Note: paths use /root/ during build; overridden to /home/scarpshield/ after USER switch
ENV PATH="/root/.foundry/bin:/root/.cargo/bin:/root/.local/bin:/usr/local/go/bin:/root/go/bin:$PATH"

# ── 1. System dependencies ────────────────────────────────────────────────────
# curl/git: needed for Foundry and Aderyn installers
# build-essential: required by Mythril's C extensions (leveldb bindings etc.)
# libssl-dev / ca-certificates: TLS for curl-based installers
# libxml2: required by xhtml2pdf (PDF report generation)
RUN apt-get update && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        curl \
        git \
        build-essential \
        libssl-dev \
        ca-certificates \
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
    && if [ -x "/root/.cyfrin/bin/aderyn" ]; then cp /root/.cyfrin/bin/aderyn /usr/local/bin/aderyn; fi \
    && if [ -x "/root/.cyfrin/bin/aderyn-update" ]; then cp /root/.cyfrin/bin/aderyn-update /usr/local/bin/aderyn-update; fi \
    && if [ -x "/root/.cargo/bin/aderyn" ]; then cp /root/.cargo/bin/aderyn /usr/local/bin/aderyn; fi \
    && if [ -x "/root/.cargo/bin/aderyn-update" ]; then cp /root/.cargo/bin/aderyn-update /usr/local/bin/aderyn-update; fi \
    && chmod +x /usr/local/bin/aderyn /usr/local/bin/aderyn-update 2>/dev/null || true \
    && aderyn --version \
    && echo "[aderyn] installed OK"

# ── 4. Medusa temporarily excluded from runtime image ────────────────────────
# Upstream currently pulls a vulnerable dtls dependency with no fixed release.
# Keep Medusa out of production images until upstream publishes a patch.

# ── 5. Python tooling — solc-select + Solidity compiler ──────────────────────
RUN pip install --no-cache-dir solc-select==1.2.0 \
    && solc-select install 0.8.28 \
    && solc-select use 0.8.28 \
    && echo "[solc] 0.8.28 active"

# ── 6. Install the Counterscarp Engine package (with PDF extras) ──────────────
# Copy the full source first so pip can resolve pyproject.toml
WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir ".[web]" \
    && echo "[counterscarp-engine] installed OK"

# ── 7. Install Slither (Python-based EVM static analyser) ────────────────────
RUN pip install --no-cache-dir slither-analyzer==0.11.5 \
    && echo "[slither] installed OK"

# ── 8. Install Mythril (symbolic execution / EVM bytecode analyser) ───────────
# mythril has heavy C-extension deps — build-essential (above) satisfies them
RUN pip install --no-cache-dir mythril==0.24.8 \
    && echo "[mythril] installed OK"

# Mythril still imports pkg_resources; keep a setuptools version that ships it.
RUN pip install --no-cache-dir "setuptools<81"

# ── 9. Pre-install additional solc versions commonly seen in audits ───────────
RUN solc-select install 0.8.19 \
    && solc-select install 0.8.25 \
    && solc-select install 0.7.6 \
    && solc-select install 0.6.12 \
    && echo "[solc] additional versions installed"

# ── 10. Working directory for scan mounts ─────────────────────────────────────
# /scan is the conventional mount point for the target contract tree
WORKDIR /scan

# ------------------------------------------------------------------------------
# STAGE 3 — Hardened runtime image
# Keep only runtime dependencies and required tool artifacts.
# ------------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

ARG APP_VERSION=5.1.1
LABEL maintainer="Counterscarp Engine Team"
LABEL description="Smart contract security auditing platform — 21-analyzer stack"
LABEL version="${APP_VERSION}"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DEBIAN_FRONTEND=noninteractive
ENV PATH="/root/.foundry/bin:/root/.cargo/bin:/root/.local/bin:/usr/local/go/bin:/root/go/bin:$PATH"

WORKDIR /app
COPY --from=tools-builder /usr/local /usr/local
COPY --from=tools-builder /app /app
COPY --from=tools-builder /root/.foundry /root/.foundry
COPY --from=tools-builder /root/.solc-select /root/.solc-select

RUN useradd -m -u 1000 scarpshield \
    && mkdir -p /output /scan \
    && cp -r /root/.foundry /home/scarpshield/.foundry || true \
    && cp -r /root/.solc-select /home/scarpshield/.solc-select || true \
    && cp -r /root/.svm /home/scarpshield/.svm 2>/dev/null || true \
    && ln -s /home/scarpshield /home/counterscarp \
    && chown -R scarpshield:scarpshield /app /scan /output /home/scarpshield

WORKDIR /scan
ENV PATH="/home/scarpshield/.foundry/bin:/home/scarpshield/.cargo/bin:/home/scarpshield/.local/bin:/usr/local/go/bin:/home/scarpshield/go/bin:$PATH"
USER scarpshield

# ── 11. Docker HEALTHCHECK ───────────────────────────────────────────────────
# Runs `scarpshield --doctor` — the built-in environment diagnostic command.
# exit 0 = all critical tools found; non-zero = something is missing.
HEALTHCHECK --interval=60s --timeout=30s --start-period=10s --retries=3 \
    CMD scarpshield --doctor

# ── 12. Entrypoint ────────────────────────────────────────────────────────────
# scarpshield is the preferred console_scripts entry point:
#   scarpshield = "orchestrator:main"
# Legacy aliases (counterscarp, counterscarp-engine) remain supported.
# Pass `--help` as the default CMD so a bare `docker run` prints usage.
ENTRYPOINT ["scarpshield"]
CMD ["--help"]

# ==============================================================================
# USAGE EXAMPLES
# ==============================================================================
#
# Build the image:
#   docker build -t counterscarp-engine:5.1.0 .
#
# Run a full audit scan (mounts current directory as /scan):
#   docker run --rm -v $(pwd):/scan -v $(pwd)/output:/output \
#       counterscarp-engine:5.1.0 --target /scan --report --output-dir /output
#
# Run only heuristic + Slither (no fuzzing):
#   docker run --rm -v $(pwd):/scan counterscarp-engine:5.1.0 --target /scan
#
# Run environment diagnostics:
#   docker run --rm counterscarp-engine:5.1.0 --doctor
#
# Interactive shell:
#   docker run --rm -it -v $(pwd):/scan counterscarp-engine:5.1.0 /bin/bash
# ==============================================================================
