# 🤖 Auto Discovery Mode - Full Automation

## Overview

**Auto Discovery Mode** là tính năng tự động hóa hoàn toàn - chỉ cần nhập domain, tool sẽ làm mọi thứ:
- 🔍 Tự động crawl website và phát hiện tất cả endpoints
- 🎯 Phát hiện intelligent các parameters có thể khai thác
- 🧠 Phân tích hành vi SSRF (time-based, error-based, content-based)
- ✅ Tự động xác nhận qua callback server
- 📊 Scoring thông minh dựa trên tên + hành vi

## Quick Start

### 1. Chế độ tự động (khuyến nghị)

```bash
# Chỉ cần nhập domain
cd web_ui
python app.py
```

Trong Web UI:
1. Nhập target URL: `https://quangtx.io.vn`
2. ✅ Bật **"AUTO DISCOVERY MODE"**
3. Click **"Start Scan"**
4. ☕ Chờ kết quả - tool làm tất cả!

### 2. Via API (nếu dùng script)

```python
from blackbox.reconnaissance.auto_discovery import AutoDiscovery
from blackbox.detection.external_callback import CallbackServer

# Start callback server
callback = CallbackServer(host='0.0.0.0', port=8888)
callback.start()

# Auto discover and test
auto_disco = AutoDiscovery(
    base_url='https://quangtx.io.vn',
    callback_server=callback,
    timeout=10
)

results = auto_disco.auto_discover_and_test()

print(f"Endpoints found: {len(results['endpoints'])}")
print(f"Suspicious params: {len(results['suspicious_params'])}")
print(f"Confirmed SSRF: {len(results['confirmed_ssrf'])}")
```

## How It Works

### Phase 1: Comprehensive Endpoint Discovery 🔍

Tool tự động tìm kiếm endpoints qua nhiều phương pháp:

1. **Crawling**
   - Phân tích HTML để tìm links
   - Theo dõi tất cả internal links
   - Tránh external domains

2. **JavaScript Parsing**
   - Trích xuất API endpoints từ JS files
   - Tìm patterns như `/api/`, `fetch()`, `axios.get()`
   - Phát hiện dynamic routes

3. **Common Path Brute-forcing**
   - Test các paths phổ biến: `/api`, `/callback`, `/webhook`, `/proxy`
   - Versioned APIs: `/api/v1`, `/api/v2`
   - Common endpoints: `/health`, `/metrics`, `/admin`

**Example Output:**
```
[*] Phase 1: Endpoint Discovery
[*] Found 45 endpoints via crawling
[*] Found 23 API endpoints in JavaScript
[*] Found 12 endpoints via path brute-force
[+] Total unique endpoints: 67
```

### Phase 2: Parameter Detection 🎯

Với mỗi endpoint, tool kiểm tra xem có nhận parameters không:

1. **GET Parameters**
   - Thử thêm random query params
   - Phân tích response status và nội dung
   - Detect nếu endpoint xử lý query strings

2. **POST Parameters**
   - Test JSON body với dummy data
   - Test form-urlencoded data
   - Phát hiện parameters được accept

**Example:**
```
[*] Testing endpoint: https://quangtx.io.vn/api/fetch
[+] Endpoint accepts GET parameters
[+] Endpoint accepts POST JSON body
```

### Phase 3: Intelligent Fuzzing 🧠

Tool test 50+ SSRF parameters với behavioral analysis:

#### 3.1 Critical Parameters (confidence: 0.60)
```python
CRITICAL_PARAMS = [
    'callback_url', 'webhook_url', 'redirect_url',
    'fetch_url', 'proxy_url', 'api_url', 'endpoint_url'
]
```

#### 3.2 High-Risk Parameters (confidence: 0.35)
```python
HIGH_RISK_PARAMS = [
    'url', 'uri', 'link', 'callback', 'webhook',
    'redirect', 'fetch', 'proxy', 'target'
]
```

#### 3.3 Behavioral Analysis
Tool inject các test URLs và phân tích:

**Time-based Detection:**
```python
# Inject slow URL
payload = "http://example.com:81"  # Port 81 timeout
if response_time > 5s:
    confidence += 0.30  # High confidence - server fetched URL
```

**Error-based Detection:**
```python
# Inject invalid URL
payload = "http://999.999.999.999"
if "connection" in error or "failed" in error:
    confidence += 0.25  # Server tried to connect
```

**Content-based Detection:**
```python
# Inject unique markers
payload = "http://callback.com/UNIQUE_MARKER_12345"
if "UNIQUE_MARKER_12345" in response:
    confidence += 0.20  # Server fetched and returned content
```

**Example Output:**
```
[*] Fuzzing: https://quangtx.io.vn/api/fetch
[*] Testing parameter: url
  [+] Critical name detected: 0.60
  [+] Timeout detected: +0.30
  [+] Error response detected: +0.25
  [!] Total confidence: 1.15 (capped at 1.0)
  [!] CRITICAL - High probability SSRF!
```

### Phase 4: Callback Confirmation ✅

Với parameters có confidence cao, tool test callback:

1. **Multi-address Strategy**
   ```python
   callback_addresses = [
       'host.docker.internal',  # Docker Desktop
       '172.17.0.1',            # Docker gateway
       '172.18.0.1',            # Additional gateway
       'callback-service',      # K8s service name
       get_local_ip(),          # Real LAN IP (172.20.10.x)
       'localhost',
       '127.0.0.1',
       '::1'
   ]
   ```

2. **Unique Tokens**
   - Mỗi test có unique token
   - Callback server verify token
   - Tránh false positives

3. **Stop on Success**
   - Test từng address cho đến khi nhận callback
   - Tiết kiệm thời gian
   - Xác nhận SSRF ngay lập tức

**Example:**
```
[*] Testing callback for: https://quangtx.io.vn/api/fetch?url=
[*] Trying: http://172.20.10.5:8888/callback/TOKEN_ABC
[+] Callback received from 172.20.10.x!
[!] CONFIRMED SSRF VULNERABILITY!
```

### Phase 5: Internal Scanning (if SSRF confirmed) 🔓

Nếu SSRF được xác nhận, tool tự động scan internal network:

```python
internal_targets = [
    'http://localhost:80',
    'http://localhost:8080',
    'http://localhost:3000',
    'http://127.0.0.1:6379',     # Redis
    'http://db-service:5432',     # PostgreSQL
    'http://cache-service:6379',  # Redis service
    'http://169.254.169.254/latest/meta-data/'  # Cloud metadata
]
```

**Example:**
```
[*] SSRF confirmed - scanning internal network...
[+] http://localhost:8080 - Accessible (200 OK)
[+] http://db-service:5432 - Accessible (Connection)
[!] HIGH - Internal services accessible via SSRF
```

## Environment Setup

### For LAN Testing (như quangtx.io.vn)

Nếu app chạy trên LAN (172.20.10.x), cần setup callback:

**Option A: Ngrok (Khuyến nghị - nhanh nhất)**
```bash
# Terminal 1: Start web UI
cd web_ui
python app.py

# Terminal 2: Setup ngrok tunnel
ngrok http 8888

# Use ngrok URL trong config
```

**Option B: Interactsh (Không cần setup)**
```python
# Tool tự động dùng Interactsh nếu local callback fail
# Không cần làm gì cả!
```

**Option C: Deploy Callback trong Docker Network**
```bash
# Nếu app ở Docker, deploy callback cùng network
docker run -d --name callback-server \
  --network app-network \
  -p 8888:8888 \
  python:3.9 python -c "
from blackbox.detection.external_callback import CallbackServer
callback = CallbackServer(host='0.0.0.0', port=8888)
callback.start()
callback.wait()
"
```

### For Docker Environment

Auto Discovery đã support Docker environment:

1. **Service Names**
   - Tool tự động test `http://service-name:port`
   - Hỗ trợ Docker Compose service discovery

2. **Gateway IPs**
   - `172.17.0.1` - Default Docker bridge
   - `172.18.0.1` - Custom networks
   - `host.docker.internal` - Docker Desktop

3. **Callback Addresses**
   - Tool tự động try tất cả Docker gateways
   - Fallback to `host.docker.internal`
   - Support multi-address strategy

## Output & Reporting

### Real-time Updates

Web UI hiển thị real-time:
- ✅ Discovered endpoints
- 🎯 Suspicious parameters
- 🔥 Confirmed SSRF
- 📊 Confidence scores
- 📝 Detailed logs

### Final Report

```json
{
  "endpoints": ["https://quangtx.io.vn/api/fetch", ...],
  "total_params_tested": 234,
  "suspicious_params": [
    {
      "parameter": "callback_url",
      "url": "https://quangtx.io.vn/api/fetch",
      "confidence": 0.85,
      "findings": ["critical_name", "timeout", "error_response"]
    }
  ],
  "confirmed_ssrf": [
    {
      "parameter": "callback_url",
      "url": "https://quangtx.io.vn/api/fetch",
      "callback_url": "http://172.20.10.5:8888/callback/TOKEN"
    }
  ],
  "internal_services": [
    {
      "target": "http://localhost:8080",
      "accessible": true,
      "via_ssrf": "https://quangtx.io.vn/api/fetch?callback_url="
    }
  ]
}
```

## Confidence Scoring System

Tool dùng scoring thông minh kết hợp tên + hành vi:

### Name-based Scoring
- **Critical names** (callback_url, webhook_url): `0.60`
- **High-risk names** (url, uri, callback): `0.35`
- **Medium names** (link, fetch, target): `0.20`
- **Low-risk names** (data, source, file): `0.10`

### Behavior-based Scoring
- **Timeout detected** (server tried to fetch): `+0.30`
- **Error messages** (connection failed, DNS error): `+0.25`
- **Response differences** (different content for valid/invalid URLs): `+0.15`
- **Status code changes**: `+0.10`

### Combined Scoring
```python
total_confidence = min(name_score + behavior_score, 1.0)

if total_confidence >= 0.7:
    severity = "CRITICAL"
elif total_confidence >= 0.5:
    severity = "HIGH"
elif total_confidence >= 0.3:
    severity = "MEDIUM"
else:
    severity = "LOW"
```

## Best Practices

### 1. Start with Auto Discovery
- Luôn dùng Auto Discovery trước
- Chỉ fallback manual nếu cần customize

### 2. Setup Callback Properly
- LAN testing: Dùng ngrok hoặc Interactsh
- Docker testing: Deploy callback trong same network
- Local testing: localhost callback works

### 3. Review Results
- Check confidence scores
- Verify confirmed SSRF manually
- Test internal access carefully

### 4. Report Responsibly
- Document all findings
- Include reproduction steps
- Suggest remediation

## Troubleshooting

### Issue: No Endpoints Found
```
[!] No endpoints discovered
```
**Solutions:**
- Check if target is accessible
- Verify no WAF blocking
- Try with different User-Agent
- Check robots.txt for hints

### Issue: No Callback Received
```
[!] No callback from suspicious parameter
```
**Solutions:**
- Check callback server is running: `curl http://localhost:8888/health`
- Verify network connectivity
- Try ngrok tunnel for LAN
- Check firewall rules

### Issue: False Positives
```
[!] Many low-confidence findings
```
**Solutions:**
- Focus on confidence >= 0.5
- Verify with manual testing
- Check for actual behavior changes
- Review error messages carefully

## Advanced Usage

### Custom Callback Server

```python
# Use custom callback domain
auto_disco = AutoDiscovery(
    base_url='https://quangtx.io.vn',
    callback_server=callback,
    timeout=10
)

# Override callback addresses
auto_disco.callback_addresses = [
    'http://your-ngrok.io',
    'http://your-public-ip:8888'
]
```

### Authenticated Testing

```python
# Add authentication headers
auto_disco = AutoDiscovery(
    base_url='https://quangtx.io.vn',
    callback_server=callback,
    timeout=10
)

auto_disco.headers = {
    'Authorization': 'Bearer YOUR_JWT_TOKEN',
    'Cookie': 'session=...'
}

results = auto_disco.auto_discover_and_test()
```

### Rate Limiting

```python
# Adjust delay between requests
auto_disco = AutoDiscovery(
    base_url='https://quangtx.io.vn',
    callback_server=callback,
    timeout=10
)

auto_disco.delay_between_requests = 0.5  # 500ms delay
```

## Example: Complete Workflow

```bash
# 1. Start Web UI
cd web_ui
python app.py

# 2. (Optional) Start ngrok for LAN callback
ngrok http 8888

# 3. Open browser: http://localhost:5000

# 4. Configure scan:
#    - Target: https://quangtx.io.vn
#    - Enable: Auto Discovery Mode
#    - Click: Start Scan

# 5. Watch real-time results:
#    ✅ 67 endpoints discovered
#    🎯 12 suspicious parameters (confidence >= 0.3)
#    🔥 2 confirmed SSRF (callback received)
#    🔓 5 internal services accessible

# 6. Export report:
#    Click "Export Report" → JSON file saved
```

## Security Notes

⚠️ **Warning:**
- Only test on systems you own or have permission to test
- SSRF can access internal services - be careful
- Always get written authorization before testing
- Report findings responsibly

## Support

Gặp vấn đề? Check:
- [USAGE_GUIDE.md](USAGE_GUIDE.md) - General usage
- [CONFIDENCE_SCORING.md](CONFIDENCE_SCORING.md) - Scoring details
- [INTERNAL_SCANNING.md](INTERNAL_SCANNING.md) - Internal scan behavior
- [BURP_SUITE_GUIDE.md](BURP_SUITE_GUIDE.md) - Traffic capture

---

**Happy Hunting! 🎯**
