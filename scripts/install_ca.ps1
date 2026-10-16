# DLP Web Upload Prevention - Install Local Mitmproxy Root CA
# Installs the local mitmproxy CA certificate into Windows CurrentUser Trusted Root store.

param(
    [switch]$Uninstall
)

$certPath = "$HOME\.mitmproxy\mitmproxy-ca-cert.cer"

if ($Uninstall) {
    Write-Host "=== Removing mitmproxy Root CA from Windows Store ===" -ForegroundColor Cyan
    $certs = Get-ChildItem Cert:\CurrentUser\Root | Where-Object { $_.Subject -like "*mitmproxy*" }
    if ($certs) {
        foreach ($c in $certs) {
            certutil -user -delstore root $c.Thumbprint
            Write-Host "  Removed certificate: $($c.Subject) ($($c.Thumbprint))" -ForegroundColor Green
        }
    } else {
        Write-Host "  No mitmproxy certificate found in Trusted Root store." -ForegroundColor Yellow
    }
    exit 0
}

Write-Host "=== Installing mitmproxy Root CA for HTTPS Inspection ===" -ForegroundColor Cyan
Write-Host ""

if (-not (Test-Path $certPath)) {
    Write-Host "  Certificate not found at: $certPath" -ForegroundColor Yellow
    Write-Host "  Mitmproxy generates this certificate upon its first run." -ForegroundColor Yellow
    Write-Host "  Starting mitmproxy briefly to generate certificates..." -ForegroundColor Yellow
    
    $venvMitmdump = ".\.venv\Scripts\mitmdump.exe"
    if (Test-Path $venvMitmdump) {
        $p = Start-Process $venvMitmdump -ArgumentList "--listen-port 18080" -PassThru
        Start-Sleep -Seconds 2
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
}

if (Test-Path $certPath) {
    Write-Host "  Found certificate at: $certPath" -ForegroundColor Green
    Write-Host "  Installing to CurrentUser Trusted Root Certification Authorities store..." -ForegroundColor Yellow
    certutil -user -addstore root "`"$certPath`""
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "  [+] Success: mitmproxy Root CA is trusted by Windows and Edge/Chrome." -ForegroundColor Green
    } else {
        Write-Host "  [-] Failed to install certificate (exit code: $LASTEXITCODE)." -ForegroundColor Red
    }
} else {
    Write-Host "  [-] Could not locate mitmproxy-ca-cert.cer. Please run mitmdump once to generate it." -ForegroundColor Red
}

Write-Host ""
