# Start callback_server.py and ngrok, then print public ngrok URL
# Usage: Open PowerShell in project root and run: .\tools\start_callback_with_ngrok.ps1

$ErrorActionPreference = 'Stop'

# Path to python script
$scriptPath = Join-Path $PSScriptRoot 'callback_server.py'

Write-Host "Starting callback server ($scriptPath) ..."
# Start Flask callback server in background
$pythonExe = 'python'
$proc1 = Start-Process -FilePath $pythonExe -ArgumentList $scriptPath -PassThru
Write-Host "Callback server started (PID $($proc1.Id))."

# Wait a moment for server to bind
Start-Sleep -Seconds 1

Write-Host "Starting ngrok to expose port 8888 ..."
# Start ngrok in background
# If ngrok is not in PATH, place ngrok.exe in project root or update this path
$ngrokExe = 'ngrok'
$ngrokArgs = 'http 8888'
$proc2 = Start-Process -FilePath $ngrokExe -ArgumentList $ngrokArgs -PassThru
Write-Host "ngrok started (PID $($proc2.Id)). Waiting for tunnel to establish..."

# Wait and poll local ngrok API for tunnel info
$maxWait = 15
$wait = 0
$tunnelUrl = $null
while ($wait -lt $maxWait -and -not $tunnelUrl) {
    Start-Sleep -Seconds 1
    try {
        $api = Invoke-RestMethod -Uri 'http://127.0.0.1:4040/api/tunnels' -Method Get -ErrorAction Stop
        if ($api.tunnels -and $api.tunnels.Count -gt 0) {
            # prefer https
            $httpsTunnel = $api.tunnels | Where-Object { $_.public_url -like 'https:*' } | Select-Object -First 1
            if ($httpsTunnel) { $tunnelUrl = $httpsTunnel.public_url }
            else { $tunnelUrl = $api.tunnels[0].public_url }
        }
    } catch {
        # ngrok web api may not be ready yet
    }
    $wait++
}

if ($tunnelUrl) {
    Write-Host ""
    Write-Host "============================================" -ForegroundColor Green
    Write-Host "  NGROK TUNNEL READY!" -ForegroundColor Green
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "Public URL: " -NoNewline
    Write-Host $tunnelUrl -ForegroundColor Cyan
    Write-Host "Ngrok Dashboard: " -NoNewline
    Write-Host "http://127.0.0.1:4040" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "NEXT STEPS:" -ForegroundColor Yellow
    Write-Host "1. Start Web UI: " -NoNewline
    Write-Host "python web_ui/app.py" -ForegroundColor Cyan
    Write-Host "2. Open browser: " -NoNewline
    Write-Host "http://localhost:5000" -ForegroundColor Cyan
    Write-Host "3. Upload HAR file and click 'Start Scan'" -ForegroundColor White
    Write-Host ""
    Write-Host "NOTE: Tool will AUTO-DETECT this ngrok URL!" -ForegroundColor Green
    Write-Host "      No need to paste URL manually." -ForegroundColor Green
    Write-Host ""
    Write-Host "Press Ctrl+C to stop..." -ForegroundColor Gray
    Write-Host "============================================" -ForegroundColor Green
    Write-Host ""
} else {
    Write-Warning "Could not retrieve ngrok tunnel URL. Check ngrok process output."
    Write-Host "If ngrok is running, open http://127.0.0.1:4040 to view tunnel info."
}

Write-Host "To stop: kill the processes with PID $($proc1.Id) and $($proc2.Id) or close this PowerShell session."