# DLP Web Upload Prevention - Start All Services
# Run from the project root directory

param(
    [int]$TikaWaitSeconds = 30,
    [switch]$SkipTika
)

Write-Host "=== DLP Web Upload Prevention - Starting All Services ===" -ForegroundColor Cyan
Write-Host ""

$projectRoot = Split-Path -Parent $PSScriptRoot

# 1. Start Tika via Docker
if (-not $SkipTika) {
    Write-Host "[1/4] Starting Apache Tika server..." -ForegroundColor Yellow
    Push-Location $projectRoot
    docker-compose up -d tika
    Pop-Location

    if ($LASTEXITCODE -ne 0) {
        Write-Host "  WARNING: Failed to start Tika container. Is Docker running?" -ForegroundColor DarkYellow
    } else {
        Write-Host "  Waiting for Tika to become healthy..." -ForegroundColor Gray
        $tikaReady = $false
        for ($i = 0; $i -lt $TikaWaitSeconds; $i++) {
            try {
                $response = Invoke-WebRequest -Uri "http://localhost:9998/tika" -UseBasicParsing -TimeoutSec 2 -ErrorAction SilentlyContinue
                if ($response.StatusCode -eq 200) {
                    $tikaReady = $true
                    break
                }
            } catch {
                # Not ready yet
            }
            Start-Sleep -Seconds 1
            Write-Host "." -NoNewline
        }
        Write-Host ""
        if ($tikaReady) {
            Write-Host "  Tika is ready." -ForegroundColor Green
        } else {
            Write-Host "  WARNING: Tika did not respond within ${TikaWaitSeconds}s." -ForegroundColor DarkYellow
        }
    }
} else {
    Write-Host "[1/4] Skipping Tika startup (-SkipTika)" -ForegroundColor Gray
}

$pythonExe = "python"
if (Test-Path "$projectRoot\.venv\Scripts\python.exe") {
    $pythonExe = "$projectRoot\.venv\Scripts\python.exe"
}

$mitmExe = "mitmdump"
if (Test-Path "$projectRoot\.venv\Scripts\mitmdump.exe") {
    $mitmExe = "$projectRoot\.venv\Scripts\mitmdump.exe"
}

# 2. Start Policy Service
Write-Host "[2/4] Starting DLP Policy Service on port 8000..." -ForegroundColor Yellow
$policyProcess = Start-Process -PassThru -NoNewWindow -FilePath $pythonExe `
    -ArgumentList "-m", "uvicorn", "policy.service:app", "--host", "127.0.0.1", "--port", "8000" `
    -WorkingDirectory $projectRoot

Start-Sleep -Seconds 2
if ($policyProcess.HasExited) {
    Write-Host "  ERROR: Policy Service failed to start." -ForegroundColor Red
    exit 1
}
Write-Host "  Policy Service started (PID: $($policyProcess.Id))" -ForegroundColor Green

# 3. Start mitmproxy
Write-Host "[3/4] Starting mitmproxy on port 8080..." -ForegroundColor Yellow
$proxyProcess = Start-Process -PassThru -NoNewWindow -FilePath $mitmExe `
    -ArgumentList "--listen-host", "127.0.0.1", "--listen-port", "8080", "-s", "proxy/addon.py" `
    -WorkingDirectory $projectRoot

Start-Sleep -Seconds 2
if ($proxyProcess.HasExited) {
    Write-Host "  ERROR: mitmproxy failed to start." -ForegroundColor Red
    exit 1
}
Write-Host "  mitmproxy started (PID: $($proxyProcess.Id))" -ForegroundColor Green

# 4. Start Test Upload Server
Write-Host "[4/4] Starting Test Upload Server on port 5000..." -ForegroundColor Yellow
$uploadProcess = Start-Process -PassThru -NoNewWindow -FilePath $pythonExe `
    -ArgumentList "scripts/test_upload_server.py" `
    -WorkingDirectory $projectRoot

Start-Sleep -Seconds 2
if ($uploadProcess.HasExited) {
    Write-Host "  WARNING: Test Upload Server failed to start." -ForegroundColor DarkYellow
} else {
    Write-Host "  Test Upload Server started (PID: $($uploadProcess.Id))" -ForegroundColor Green
}

# Save PIDs for stop_all.ps1
$pidFile = Join-Path $projectRoot ".dlp_pids"
@(
    "POLICY_PID=$($policyProcess.Id)",
    "PROXY_PID=$($proxyProcess.Id)",
    "UPLOAD_PID=$($uploadProcess.Id)"
) | Set-Content -Path $pidFile

Write-Host ""
Write-Host "=== All Services Running ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Tika Server:        http://localhost:9998"   -ForegroundColor White
Write-Host "  Policy Service:     http://127.0.0.1:8000"  -ForegroundColor White
Write-Host "  Proxy (mitmproxy):    127.0.0.1:8080"       -ForegroundColor White
Write-Host "  Test Upload Server: http://127.0.0.1:5000"  -ForegroundColor White
Write-Host ""
Write-Host "  To stop all:  .\scripts\stop_all.ps1"    -ForegroundColor Gray
Write-Host "  PIDs saved to: $pidFile"                  -ForegroundColor Gray
Write-Host ""
