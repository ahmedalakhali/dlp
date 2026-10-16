# DLP Web Upload Prevention - Launch Edge through DLP Proxy
$tempProfile = Join-Path $env:TEMP "dlp_edge_profile"
if (-not (Test-Path $tempProfile)) {
    New-Item -ItemType Directory -Path $tempProfile -Force | Out-Null
}

$edgeArgs = @(
    "--proxy-server=http://127.0.0.1:8080",
    "--proxy-bypass-list=<-loopback>",
    "--user-data-dir=$tempProfile",
    "--no-first-run",
    "--no-default-browser-check",
    "http://127.0.0.1:5000"
)

Start-Process msedge.exe -ArgumentList $edgeArgs
Write-Host "Edge launched in isolated profile with proxy active." -ForegroundColor Green
