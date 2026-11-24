param(
    [int]$Port = 0,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$ScriptRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $ScriptRoot

$DataDir = Join-Path $ScriptRoot 'data'
$LogsDir = Join-Path $ScriptRoot 'logs'
$RuntimeFile = Join-Path $DataDir 'runtime.json'

if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Force -Path $DataDir | Out-Null }
if (-not (Test-Path $LogsDir)) { New-Item -ItemType Directory -Force -Path $LogsDir | Out-Null }

# 1. Kiểm tra nếu đã có instance đang chạy
if (Test-Path $RuntimeFile) {
    try {
        $rt = Get-Content $RuntimeFile -Raw | ConvertFrom-Json
        $existingPort = $rt.port
        $url = "http://127.0.0.1:$existingPort/"
        $res = Invoke-RestMethod -Uri "$($url)api/health" -TimeoutSec 2 -ErrorAction Stop
        if ($res.status -eq 'ok') {
            Write-Host "[INFO] Netmiko Web Console da chay tai: $url (PID: $($rt.pid))" -ForegroundColor Green
            if (-not $NoBrowser) {
                Start-Process $url
            }
            exit 0
        }
    } catch {
        # Instance cũ đã chết hoặc file rác, xóa runtime file
        Remove-Item $RuntimeFile -Force -ErrorAction SilentlyContinue
    }
}

# 2. Kiểm tra Python
$pyCmd = Get-Command python -ErrorAction SilentlyContinue
if (-not $pyCmd) {
    Write-Host "[ERROR] Khong tim thay Python! Vui long cai dat Python 3.10+ va Netmiko/FastAPI truoc." -ForegroundColor Red
    exit 1
}

# 3. Chọn port trống trong 8787-8800
function Test-PortAvailable([int]$p) {
    try {
        $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, $p)
        $listener.Start()
        $listener.Stop()
        return $true
    } catch {
        return $false
    }
}

$chosenPort = $Port
if ($chosenPort -eq 0) {
    for ($p = 8787; $p -le 8800; $p++) {
        if (Test-PortAvailable $p) {
            $chosenPort = $p
            break
        }
    }
}

if ($chosenPort -eq 0 -or -not (Test-PortAvailable $chosenPort)) {
    Write-Host "[ERROR] Khong tim duoc port trong khoang 8787-8800." -ForegroundColor Red
    exit 1
}

# 4. Chạy backend
Write-Host "[STARTING] Khoi dong Netmiko Web Console tren port $chosenPort..." -ForegroundColor Cyan

$serverScript = Join-Path $ScriptRoot 'backend\server.py'
$outLog = Join-Path $LogsDir 'server.out.log'
$errLog = Join-Path $LogsDir 'server.err.log'

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $pyCmd.Source
$psi.Arguments = "`"$serverScript`" --port $chosenPort"
$psi.WorkingDirectory = $ScriptRoot
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

# Dùng Start-Process với chuyển hướng log
$proc = Start-Process -FilePath $pyCmd.Source `
    -ArgumentList "`"$serverScript`"", "--port", "$chosenPort" `
    -WorkingDirectory $ScriptRoot `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError $errLog `
    -WindowStyle Hidden `
    -PassThru

# 5. Chờ Web và MCP sẵn sàng
$url = "http://127.0.0.1:$chosenPort/"
$ready = $false
$maxSeconds = 40
$sw = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "[WAIT] Dang khoi dong Web Console va MCP Server..." -NoNewline

while ($sw.Elapsed.TotalSeconds -lt $maxSeconds) {
    if ($proc.HasExited) {
        Write-Host ""
        Write-Host "[ERROR] Server bi dung dot ngot voi ma thoat $($proc.ExitCode)." -ForegroundColor Red
        if (Test-Path $errLog) {
            Get-Content $errLog -Tail 15 | Write-Host -ForegroundColor Yellow
        }
        exit 1
    }

    try {
        $res = Invoke-RestMethod -Uri "$($url)api/health" -TimeoutSec 2 -ErrorAction Stop
        if ($res.status -eq 'ok') {
            $ready = $true
            break
        }
    } catch {
        Write-Host "." -NoNewline
        Start-Sleep -Milliseconds 600
    }
}

Write-Host ""

if ($ready) {
    Write-Host "==========================================================" -ForegroundColor Green
    Write-Host " Netmiko Web Console da san sang tai: $url" -ForegroundColor Green
    Write-Host " Backend PID: $($proc.Id) | MCP State: $($res.mcp_state)" -ForegroundColor Green
    Write-Host "==========================================================" -ForegroundColor Green
    if (-not $NoBrowser) {
        Start-Process $url
    }
    exit 0
} else {
    Write-Host "[WARNING] Qua thoi gian cho 40s. Kiem tra log tai logs\server.err.log" -ForegroundColor Yellow
    exit 1
}
