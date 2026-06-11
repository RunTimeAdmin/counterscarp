#!/usr/bin/env bash
set -euo pipefail

# Internal launch preflight checks (non-transactional).
# Usage:
#   bash scripts/launch_preflight.sh
# Optional env vars:
#   APP_BASE_URL=https://app.counterscarp.io
#   SITE_BASE_URL=https://counterscarp.io
#   LOCAL_APP_URL=http://127.0.0.1:8001

APP_BASE_URL="${APP_BASE_URL:-https://app.counterscarp.io}"
SITE_BASE_URL="${SITE_BASE_URL:-https://counterscarp.io}"
LOCAL_APP_URL="${LOCAL_APP_URL:-http://127.0.0.1:8001}"
OUT_DIR="${OUT_DIR:-launch-proof}"

ok() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; exit 1; }
warn() { echo "[WARN] $1"; }
step() { echo; echo "==> $1"; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "Missing required command: $1"
}

check_contains() {
  local url="$1"
  local pattern="$2"
  local label="$3"
  local body
  body="$(curl -fsSL "$url")" || fail "$label (request failed: $url)"
  echo "$body" | grep -E "$pattern" >/dev/null || fail "$label (pattern not found)"
  ok "$label"
}

require_cmd curl
require_cmd grep
require_cmd head

step "1) Basic endpoint reachability"
if curl -fsSL "$LOCAL_APP_URL/" | head -n 5 >/dev/null; then
  ok "Local app endpoint"
else
  warn "Local app endpoint unavailable (skipping; expected if not running locally)"
fi
curl -fsSL "$APP_BASE_URL/" | head -n 5 >/dev/null || fail "Public app endpoint"
ok "Public app endpoint"

step "2) Premium UI marker check"
check_contains "$APP_BASE_URL/" "What You Get|Unlock the Full Power|FILE|SSL|AUD|RISK" "Premium marker content"

step "3) Version endpoint check"
if curl -fsSL "$APP_BASE_URL/version" | grep -E "\"version\"|\"app\"" >/dev/null; then
  ok "Version endpoint JSON"
else
  warn "Version endpoint unavailable or missing expected fields"
fi

step "4) Public support/status pages"
check_contains "$SITE_BASE_URL/status.html" "Service Status|All systems operational" "Status page content"
check_contains "$SITE_BASE_URL/verification-runbook.html" "Verification Resources|maintained internally" "Verification page sanitized"
check_contains "$SITE_BASE_URL/support-ops.html" "Support Resources|maintained internally" "Support ops page sanitized"

step "5) Docs anchor check"
check_contains "$SITE_BASE_URL/docs.html" "id=\"suppressions\"|id=\"cicd\"" "Docs anchors present"

step "6) Sitemap sanity check"
check_contains "$SITE_BASE_URL/sitemap.xml" "status\\.html" "Sitemap includes status page"
if curl -fsSL "$SITE_BASE_URL/sitemap.xml" | grep -E "verification-runbook\\.html|support-ops\\.html" >/dev/null; then
  fail "Sitemap should not include internal ops pages"
fi
ok "Sitemap excludes internal ops pages"

step "7) Save proof bundle"
mkdir -p "$OUT_DIR"
if curl -fsSL "$APP_BASE_URL/version" > "$OUT_DIR/app-version.json"; then
  ok "Saved version payload"
else
  warn "Could not save version payload (endpoint unavailable)"
fi
curl -fsSL "$SITE_BASE_URL/status.html" > "$OUT_DIR/status.html"
curl -fsSL "$SITE_BASE_URL/verification-runbook.html" > "$OUT_DIR/verification-runbook.html"
curl -fsSL "$SITE_BASE_URL/support-ops.html" > "$OUT_DIR/support-ops.html"
curl -fsSL "$SITE_BASE_URL/sitemap.xml" > "$OUT_DIR/sitemap.xml"
ok "Saved proof files under ./$OUT_DIR"

echo
echo "Preflight complete."
