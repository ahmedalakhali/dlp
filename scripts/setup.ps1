# DLP Web Upload Prevention — Setup Script
# Run this script from the project root directory

Write-Host "=== DLP Web Upload Prevention — Setup ===" -ForegroundColor Cyan
Write-Host ""

# 1. Check Python version
Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Python not found. Install Python 3.11+ and add to PATH." -ForegroundColor Red
    exit 1
}
Write-Host "  Found: $pythonVersion" -ForegroundColor Green

# 2. Install Python dependencies
Write-Host "[2/5] Installing Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Failed to install Python dependencies." -ForegroundColor Red
    exit 1
}
Write-Host "  Dependencies installed successfully." -ForegroundColor Green

# 3. Check Docker
Write-Host "[3/5] Checking Docker..." -ForegroundColor Yellow
$dockerVersion = docker --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: Docker not found. Tika Server must be run manually (Java 11+ required)." -ForegroundColor DarkYellow
} else {
    Write-Host "  Found: $dockerVersion" -ForegroundColor Green
    Write-Host "  Pulling Apache Tika image..." -ForegroundColor Yellow
    docker pull apache/tika:2.9.1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  Tika image pulled successfully." -ForegroundColor Green
    } else {
        Write-Host "  WARNING: Failed to pull Tika image. Ensure Docker is running." -ForegroundColor DarkYellow
    }
}

# 4. Check Tesseract
Write-Host "[4/5] Checking Tesseract OCR..." -ForegroundColor Yellow
$tesseractVersion = tesseract --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: Tesseract not found. OCR features will be disabled." -ForegroundColor DarkYellow
    Write-Host "  Install from: https://github.com/UB-Mannheim/tesseract/wiki" -ForegroundColor DarkYellow
} else {
    $firstLine = ($tesseractVersion | Select-Object -First 1)
    Write-Host "  Found: $firstLine" -ForegroundColor Green
}

# 5. Create required directories
Write-Host "[5/5] Creating directories..." -ForegroundColor Yellow
$dirs = @("audit", "certs", "tests\fixtures")
foreach ($dir in $dirs) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "  Created: $dir" -ForegroundColor Green
    } else {
        Write-Host "  Exists:  $dir" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Next steps:" -ForegroundColor White
Write-Host "  1. Start Tika:          docker-compose up -d tika" -ForegroundColor Gray
Write-Host "  2. Start Policy Service: uvicorn policy.service:app --host 127.0.0.1 --port 8000" -ForegroundColor Gray
Write-Host "  3. Start Proxy:          mitmdump --listen-host 127.0.0.1 --listen-port 8080 -s proxy/addon.py" -ForegroundColor Gray
Write-Host "  Or run all at once:      .\scripts\start_all.ps1" -ForegroundColor Gray
