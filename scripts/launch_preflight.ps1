$ErrorActionPreference = "Stop"

# Internal launch preflight checks (non-transactional).
# Usage:
#   pwsh scripts/launch_preflight.ps1
# Optional env vars:
#   APP_BASE_URL=https://app.counterscarp.io
#   SITE_BASE_URL=https://counterscarp.io
#   LOCAL_APP_URL=http://127.0.0.1:8001
#   OUT_DIR=launch-proof

$APP_BASE_URL = if ($env:APP_BASE_URL) { $env:APP_BASE_URL } else { "https://app.counterscarp.io" }
$SITE_BASE_URL = if ($env:SITE_BASE_URL) { $env:SITE_BASE_URL } else { "https://counterscarp.io" }
$LOCAL_APP_URL = if ($env:LOCAL_APP_URL) { $env:LOCAL_APP_URL } else { "http://127.0.0.1:8001" }
$OUT_DIR = if ($env:OUT_DIR) { $env:OUT_DIR } else { "launch-proof" }

function Step($msg) { Write-Host ""; Write-Host "==> $msg" }
function Pass($msg) { Write-Host "[PASS] $msg" }
function Warn($msg) { Write-Host "[WARN] $msg" }
function Fail($msg) { throw "[FAIL] $msg" }

function Test-Contains {
  param(
    [string]$Url,
    [string]$Pattern,
    [string]$Label
  )
  try {
    $body = (Invoke-WebRequest -Uri $Url -UseBasicParsing).Content
  } catch {
    Fail "$Label (request failed: $Url)"
  }
  if ($body -match $Pattern) {
    Pass $Label
  } else {
    Fail "$Label (pattern not found)"
  }
}

Step "1) Basic endpoint reachability"
try {
  (Invoke-WebRequest -Uri "$LOCAL_APP_URL/" -UseBasicParsing).Content | Out-Null
  Pass "Local app endpoint"
} catch { Warn "Local app endpoint unavailable (skipping; expected if not running locally)" }

try {
  (Invoke-WebRequest -Uri "$APP_BASE_URL/" -UseBasicParsing).Content | Out-Null
  Pass "Public app endpoint"
} catch { Fail "Public app endpoint" }

Step "2) Premium UI marker check"
Test-Contains -Url "$APP_BASE_URL/" -Pattern "What You Get|Unlock the Full Power|FILE|SSL|AUD|RISK" -Label "Premium marker content"

Step "3) Version endpoint check"
try {
  $versionBody = (Invoke-WebRequest -Uri "$APP_BASE_URL/version" -UseBasicParsing).Content
  if ($versionBody -match '"version"|"app"') {
    Pass "Version endpoint JSON"
  } else {
    Warn "Version endpoint reachable but missing expected fields"
  }
} catch {
  Warn "Version endpoint unavailable (continuing with other checks)"
}

Step "4) Public support/status pages"
Test-Contains -Url "$SITE_BASE_URL/status.html" -Pattern "Service Status|All systems operational" -Label "Status page content"
Test-Contains -Url "$SITE_BASE_URL/verification-runbook.html" -Pattern "Verification Resources|maintained internally" -Label "Verification page sanitized"
Test-Contains -Url "$SITE_BASE_URL/support-ops.html" -Pattern "Support Resources|maintained internally" -Label "Support ops page sanitized"

Step "5) Docs anchor check"
Test-Contains -Url "$SITE_BASE_URL/docs.html" -Pattern 'id="suppressions"|id="cicd"' -Label "Docs anchors present"

Step "6) Sitemap sanity check"
$sitemap = (Invoke-WebRequest -Uri "$SITE_BASE_URL/sitemap.xml" -UseBasicParsing).Content
if ($sitemap -match "status\.html") {
  Pass "Sitemap includes status page"
} else {
  Fail "Sitemap missing status page"
}
if ($sitemap -match "verification-runbook\.html|support-ops\.html") {
  Fail "Sitemap should not include internal ops pages"
} else {
  Pass "Sitemap excludes internal ops pages"
}

Step "7) Save proof bundle"
New-Item -Path $OUT_DIR -ItemType Directory -Force | Out-Null
try {
  (Invoke-WebRequest -Uri "$APP_BASE_URL/version" -UseBasicParsing).Content | Set-Content -Path "$OUT_DIR/app-version.json"
  Pass "Saved version payload"
} catch {
  Warn "Could not save version payload (endpoint unavailable)"
}
(Invoke-WebRequest -Uri "$SITE_BASE_URL/status.html" -UseBasicParsing).Content | Set-Content -Path "$OUT_DIR/status.html"
(Invoke-WebRequest -Uri "$SITE_BASE_URL/verification-runbook.html" -UseBasicParsing).Content | Set-Content -Path "$OUT_DIR/verification-runbook.html"
(Invoke-WebRequest -Uri "$SITE_BASE_URL/support-ops.html" -UseBasicParsing).Content | Set-Content -Path "$OUT_DIR/support-ops.html"
(Invoke-WebRequest -Uri "$SITE_BASE_URL/sitemap.xml" -UseBasicParsing).Content | Set-Content -Path "$OUT_DIR/sitemap.xml"
Pass "Saved proof files under ./$OUT_DIR"

Write-Host ""
Write-Host "Preflight complete."
