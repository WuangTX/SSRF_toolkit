<#
Run callback server, ngrok (to expose it), and the web UI Flask app.

Usage:
  .\tools\run_with_ngrok_and_app.ps1 [-NgrokPath <path-to-ngrok>] [-CallbackPort <8888>] [-NgrokWaitSeconds <10>]

Behavior:
  - Start callback server (tools/callback_server.py) on port 8888
  - Start ngrok in background to forward the callback port (default 8888)
  - Wait for ngrok API to return a public tunnel URL (polls http://127.0.0.1:4040/api/tunnels)
  - Start the Flask web UI (python web_ui/app.py) in the foreground so you can see logs
  - When the web UI exits, the script will stop both ngrok and callback server

Notes:
  - Requires ngrok in PATH or supply full path via -NgrokPath
  - Run this script from PowerShell (ExecutionPolicy may require adjustment)
  - Callback server runs on port 8888, web UI on port 5000
#>
param(
    [string]$NgrokPath = "ngrok",
    [int]$CallbackPort = 8888,
    [int]$NgrokWaitSeconds = 10
)

function Start-CallbackServer {
    param($port)
    try {
        $callbackPath = Join-Path $PSScriptRoot "callback_server.py"
        Write-Host "Starting callback server on port ${port}: $callbackPath"
        $proc = Start-Process -FilePath "python" -ArgumentList $callbackPath -PassThru -WindowStyle Normal
        Start-Sleep -Milliseconds 500
        # Verify it started
        try {
            Start-Sleep -Seconds 2
            $health = Invoke-RestMethod -Uri "http://localhost:${port}/health" -Method Get -TimeoutSec 2
            Write-Host "✅ Callback server is healthy: $($health.status)"
        } catch {
            Write-Warning "Callback server may not be fully ready yet: $_"
        }
        return $proc
    }
    catch {
        Write-Error "Failed to start callback server: $_"
        return $null
    }
}

function Start-NgrokProcess {
    param($path, $port)
    try {
        Write-Host "Starting ngrok: $path http $port"
        $proc = Start-Process -FilePath $path -ArgumentList "http $port" -PassThru -WindowStyle Hidden
        Start-Sleep -Milliseconds 300
        return $proc
    }
    catch {
        Write-Error "Failed to start ngrok: $_"
        return $null
    }
}

function Get-NgrokPublicUrl {
    param($maxAttempts = 10)
    $api = 'http://127.0.0.1:4040/api/tunnels'
    for ($i = 0; $i -lt $maxAttempts; $i++) {
        try {
            $resp = Invoke-RestMethod -Uri $api -Method Get -TimeoutSec 2
            if ($resp -and $resp.tunnels) {
                # Prefer https
                $https = $resp.tunnels | Where-Object { $_.proto -eq 'https' } | Select-Object -First 1
                if ($https) { return $https.public_url }
                return $resp.tunnels[0].public_url
            }
        } catch {
            # ignore and retry
        }
        Start-Sleep -Seconds 1
    }
    return $null
}

# Main
$callbackProc = $null
$ngrokProc = $null
try {
    # Start callback server first
    Write-Host "="*70
    Write-Host "🚀 STEP 1: Starting Callback Server"
    Write-Host "="*70
    $callbackProc = Start-CallbackServer -port $CallbackPort
    if (-not $callbackProc) {
        Write-Error "Callback server not started. Aborting."
        exit 1
    }

    # Start ngrok
    Write-Host ""
    Write-Host "="*70
    Write-Host "🌐 STEP 2: Starting ngrok tunnel"
    Write-Host "="*70
    $ngrokProc = Start-NgrokProcess -path $NgrokPath -port $CallbackPort
    if (-not $ngrokProc) {
        Write-Error "ngrok not started. Aborting. Please install ngrok or provide correct path via -NgrokPath."
        exit 1
    }

    Write-Host "Waiting for ngrok to expose tunnels (max $NgrokWaitSeconds s)..."
    $publicUrl = Get-NgrokPublicUrl -maxAttempts $NgrokWaitSeconds
    if ($publicUrl) {
        Write-Host "✅ ngrok public URL detected: $publicUrl"
        Write-Host "(The web UI will auto-detect this tunnel via http://127.0.0.1:4040/api/tunnels)"
    } else {
        Write-Warning "No ngrok tunnel detected after waiting $NgrokWaitSeconds s. You can still continue; the app will start but auto-detection won't find a public callback URL."
    }

    Write-Host ""
    Write-Host "="*70
    Write-Host "🎨 STEP 3: Starting Web UI (port 5000)"
    Write-Host "="*70
    Write-Host "Starting Flask web UI (web_ui/app.py) in foreground..."
    Write-Host "🌐 Access web UI at: http://localhost:5000"
    Write-Host "📊 Access callback dashboard at: http://localhost:8888 or $publicUrl"
    Write-Host ""
    # Run python app in the current session so logs are visible
    & python web_ui/app.py
}
finally {
    # Cleanup both processes
    Write-Host ""
    Write-Host "="*70
    Write-Host "🧹 Cleaning up..."
    Write-Host "="*70
    
    if ($ngrokProc -and -not $ngrokProc.HasExited) {
        Write-Host "Stopping ngrok (pid $($ngrokProc.Id))..."
        try { $ngrokProc.Kill() } catch { Write-Warning "Failed to kill ngrok process: $_" }
    }
    
    if ($callbackProc -and -not $callbackProc.HasExited) {
        Write-Host "Stopping callback server (pid $($callbackProc.Id))..."
        try { $callbackProc.Kill() } catch { Write-Warning "Failed to kill callback server process: $_" }
    }
    
    Write-Host "✅ Cleanup complete"
}
