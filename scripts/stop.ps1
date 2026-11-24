param(
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ScriptRoot

$DataDir = Join-Path $ScriptRoot 'data'
$RuntimeFile = Join-Path $DataDir 'runtime.json'

if (-not (Test-Path $RuntimeFile)) {
    Write-Host "[INFO] Netmiko Web Console hien khong chay (khong co data\runtime.json)." -ForegroundColor Yellow
    exit 0
}

try {
    $rt = Get-Content $RuntimeFile -Raw | ConvertFrom-Json
} catch {
    Write-Host "[WARNING] Khong doc duoc data\runtime.json. Xoa file runtime." -ForegroundColor Yellow
    Remove-Item $RuntimeFile -Force -ErrorAction SilentlyContinue
    exit 0
}

$pidNum = $rt.pid
$port = $rt.port
$url = "http://127.0.0.1:$port/"

# Kiểm tra nếu còn run đang chạy
try {
    $res = Invoke-RestMethod -Uri "$($url)api/health" -TimeoutSec 2 -ErrorAction SilentlyContinue
    if ($res -and $res.active_runs -gt 0 -and -not $Force) {
        Write-Host "[CAUTION] Dang co $($res.active_runs) tien trinh run dang thuc thi tren thiet bi!" -ForegroundColor Red
        Write-Host "Vui long cho run hoan tat hoac dung: STOP_WINDOWS.bat -Force de bat buoc dung." -ForegroundColor Yellow
        exit 1
    }
} catch {
    # Co the backend khong phan hoi
}

Write-Host "[STOPPING] Dang tat Netmiko Web Console (PID: $pidNum)..." -ForegroundColor Cyan

# Dừng process backend
$killed = $false
try {
    $proc = Get-Process -Id $pidNum -ErrorAction Stop
    $proc.Kill()
    $proc.WaitForExit(3000)
    $killed = $true
} catch {
    Write-Host "[INFO] Tien trinh PID $pidNum khong con ton tai." -ForegroundColor Gray
}

# Dừng mcp child nếu còn sót lại
if ($rt.mcp_pid) {
    try {
        $mcpProc = Get-Process -Id $rt.mcp_pid -ErrorAction SilentlyContinue
        if ($mcpProc) {
            $mcpProc.Kill()
        }
    } catch {}
}

Remove-Item $RuntimeFile -Force -ErrorAction SilentlyContinue

Write-Host "==========================================================" -ForegroundColor Green
Write-Host " Netmiko Web Console da dung thanh cong." -ForegroundColor Green
Write-Host "==========================================================" -ForegroundColor Green
exit 0
