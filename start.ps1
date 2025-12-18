<#
Start Web UI Only (Callback Server on VPS)

Sử dụng khi callback server đã deploy lên VPS.
Web UI sẽ kết nối tới VPS callback server (http://40.82.145.240:8888)

Usage:
  .\start_web_ui.ps1
#>

Write-Host "="*80
Write-Host "MICROSERVICE PENTEST TOOLKIT - WEB UI"
Write-Host "="*80
Write-Host ""

# Check .env exists
$envFile = Join-Path $PSScriptRoot ".env"
if (-not (Test-Path $envFile)) {
    Write-Error ".env file not found! Please create .env with CALLBACK_URL"
    exit 1
}

# Read CALLBACK_URL from .env
$callbackUrl = Get-Content $envFile | Where-Object { $_ -match "^CALLBACK_URL=" } | ForEach-Object { $_.Split('=')[1] }

if (-not $callbackUrl) {
    Write-Error "CALLBACK_URL not found in .env!"
    exit 1
}

Write-Host "📡 Callback Server: $callbackUrl"
Write-Host ""

# Test callback server connectivity
Write-Host "🔍 Testing callback server connectivity..."
try {
    $response = Invoke-WebRequest -Uri "$callbackUrl/health" -Method Get -TimeoutSec 5 -ErrorAction Stop
    if ($response.StatusCode -eq 200) {
        Write-Host "Callback server is reachable!" -ForegroundColor Green
    }
} catch {
    Write-Warning "Cannot reach callback server at $callbackUrl"
    Write-Warning "Make sure VPS callback server is running:"
    Write-Warning "ssh quang@40.82.145.240 'sudo systemctl status callback_server'"
    Write-Host ""
    $continue = Read-Host "Continue anyway? (y/n)"
    if ($continue -ne 'y') {
        exit 1
    }
}

Write-Host ""
Write-Host "="*80
Write-Host "Starting Web UI (port 5000)"
Write-Host "="*80
Write-Host ""

# Use venv python if exists
$venvPython = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (Test-Path $venvPython) {
    Write-Host "Using virtual environment Python: .venv\Scripts\python.exe"
    $pythonCmd = $venvPython
} else {
    Write-Host "Using system Python"
    $pythonCmd = "python"
}

# Change to web_ui directory
Push-Location (Join-Path $PSScriptRoot "web_ui")

try {
    Write-Host ""
    Write-Host "Web UI will be available at: http://localhost:5000" -ForegroundColor Cyan
    Write-Host "Callback Dashboard: $callbackUrl" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Press Ctrl+C to stop the server"
    Write-Host "="*80
    Write-Host ""
    
    # Start Flask app
    & $pythonCmd app.py
}
finally {
    Pop-Location
    Write-Host ""
    Write-Host "="*80
    Write-Host "Web UI stopped"
    Write-Host "="*80
}
