# Deploy updated callback server to VPS

$VPS_IP = "40.82.145.240"
$VPS_USER = "quang"

Write-Host "📦 Deploying updated callback_server.py to VPS..." -ForegroundColor Cyan

# Copy updated file to VPS
scp tools/callback_server.py ${VPS_USER}@${VPS_IP}:/home/quang/callback_server/

Write-Host "🔄 Restarting callback server on VPS..." -ForegroundColor Yellow
ssh ${VPS_USER}@${VPS_IP} 'sudo systemctl restart callback_server'

Write-Host "✅ Checking callback server status..." -ForegroundColor Green
ssh ${VPS_USER}@${VPS_IP} 'sudo systemctl status callback_server --no-pager'

Write-Host ""
Write-Host "🧪 Testing callback server endpoints:" -ForegroundColor Magenta
Write-Host "   Health: http://${VPS_IP}:8888/health"
Write-Host "   Public API: http://${VPS_IP}:8888/api/callbacks/public"

# Test endpoints
Write-Host ""
Write-Host "Testing health endpoint..." -ForegroundColor Cyan
curl http://${VPS_IP}:8888/health

Write-Host ""
Write-Host "Testing public API endpoint..." -ForegroundColor Cyan
curl http://${VPS_IP}:8888/api/callbacks/public?limit=5

Write-Host ""
Write-Host "✅ Deployment complete!" -ForegroundColor Green
