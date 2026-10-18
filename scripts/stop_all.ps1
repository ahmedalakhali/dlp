# DLP Web Upload Prevention - Stop All Services
# Reads PIDs from .dlp_pids and terminates processes cleanly.

Write-Host "=== DLP Web Upload Prevention - Stopping All Services ===" -ForegroundColor Cyan
Write-Host ""

$projectRoot = Split-Path -Parent $PSScriptRoot
$pidFile = Join-Path $projectRoot ".dlp_pids"

# 1. Stop processes by saved PIDs
if (Test-Path $pidFile) {
    $pidContent = Get-Content $pidFile
    foreach ($line in $pidContent) {
        if ($line -match '(\w+)=(\d+)') {
            $name = $Matches[1]
            $pid = [int]$Matches[2]
            try {
                $proc = Get-Process -Id $pid -ErrorAction SilentlyContinue
                if ($proc -and -not $proc.HasExited) {
                    Stop-Process -Id $pid -Force
                    Write-Host "  Stopped $name (PID: $pid)" -ForegroundColor Green
                } else {
                    Write-Host "  $name (PID: $pid) already stopped" -ForegroundColor Gray
                }
            } catch {
                Write-Host "  $name (PID: $pid) - could not stop: $_" -ForegroundColor DarkYellow
            }
        }
    }
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
} else {
    Write-Host "  No PID file found - checking ports and processes..." -ForegroundColor DarkYellow
}

# 2. Safety check: ensure ports 5000, 8000, 8080 are freed
$ports = 5000, 8000, 8080
foreach ($port in $ports) {
    $conns = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        if ($c.OwningProcess -gt 0) {
            Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "  Freed port $port (terminated PID $($c.OwningProcess))" -ForegroundColor Green
        }
    }
}

# 3. Ensure Windows system proxy is disabled and flush browser cache
Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -Name ProxyEnable -Value 0 -ErrorAction SilentlyContinue

try {
    $signature = @'
[DllImport("wininet.dll", SetLastError = true, CharSet=CharSet.Auto)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
    $wininet = Add-Type -MemberDefinition $signature -Name "WinINetFlush_$([System.Guid]::NewGuid().ToString('N'))" -Namespace "WinINet" -PassThru
    [void]$wininet::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0)
    [void]$wininet::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0)
} catch {
    # Ignore if already defined in session
}

# 4. Stop Tika container if running
if (Get-Command docker-compose -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "  Stopping Tika container..." -ForegroundColor Yellow
    Push-Location $projectRoot
    docker-compose down 2>$null
    Pop-Location
}

Write-Host ""
Write-Host "=== All Services Stopped & Proxy Reset to Direct ===" -ForegroundColor Cyan
Write-Host ""
