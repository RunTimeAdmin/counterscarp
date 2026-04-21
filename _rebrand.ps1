Set-Location "z:\Sentinal Engine\sentinel-engine"

$files = @(
    "webapp\templates\base.html",
    "webapp\templates\upload.html",
    "webapp\templates\results.html",
    "webapp\templates\pricing.html",
    "webapp\templates\checkout_success.html",
    "webapp\templates\settings.html",
    "webapp\templates\privacy.html",
    "webapp\templates\terms.html",
    "webapp\main.py",
    "webapp\config.py",
    "webapp\license_api.py",
    "webapp\stripe_integration.py"
)

foreach ($f in $files) {
    $path = $f
    if (-not (Test-Path $path)) { Write-Host "SKIP: $f"; continue }
    $c = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)

    # Brand name replacements
    $c = $c -replace 'Garrison Engine', 'Counterscarp Engine'
    $c = $c -replace 'garrison-engine', 'counterscarp-engine'
    $c = $c -replace 'garrisonsec\.com', 'counterscarp.io'
    $c = $c -replace 'app\.garrisonsec\.com', 'app.counterscarp.io'
    $c = $c -replace 'support@garrisonsec\.com', 'contact@counterscarp.io'
    $c = $c -replace 'help@protocol14019\.com', 'contact@counterscarp.io'
    $c = $c -replace 'support@counterscarp\.io', 'contact@counterscarp.io'
    $c = $c -replace 'GARRISON_PRO_LICENSE', 'COUNTERSCARP_PRO_LICENSE'
    $c = $c -replace '\.garrison/', '.counterscarp/'
    $c = $c -replace 'github\.com/RunTimeAdmin/garrison-engine', 'github.com/RunTimeAdmin/counterscarp'
    $c = $c -replace 'garrison_audit_', 'counterscarp_audit_'

    [System.IO.File]::WriteAllText((Resolve-Path $path).Path, $c, [System.Text.Encoding]::UTF8)
    Write-Host "Updated: $f"
}

Write-Host ""
Write-Host "Checking for remaining garrison refs in webapp:"
Select-String -Path "webapp\*.py","webapp\templates\*.html" -Pattern "[Gg]arrison"
