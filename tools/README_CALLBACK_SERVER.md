# 🎯 Enhanced Callback Server - Hướng dẫn sử dụng

## Tổng quan
Callback Server đã được nâng cấp với giao diện realtime để theo dõi và phân tích các SSRF callbacks.

## Tính năng mới

### 1. Dashboard Realtime
- ✅ Giao diện web đẹp, tự động refresh mỗi 2 giây
- ✅ Hiển thị tất cả callbacks với đầy đủ thông tin
- ✅ Phát hiện service/library nào thực thi request (Python, Java, Node.js, curl, browser, etc.)
- ✅ Xem chi tiết headers, body, User-Agent
- ✅ Lưu trữ in-memory với giới hạn 1000 callbacks

### 2. Phân tích Service
Tool tự động phát hiện service dựa vào User-Agent:
- **python**: requests, urllib, httpx, aiohttp
- **java**: Apache HttpClient, OkHttp, Spring
- **node.js**: axios, got, superagent
- **php**: Guzzle, cURL
- **.NET**: HttpClient, RestSharp
- **browser**: Chrome, Firefox, Safari
- **aws-sdk**, **curl**, **wget**, v.v.

### 3. API Endpoints

#### GET `/` - Dashboard
```bash
# Mở trình duyệt
http://localhost:8888/
```

#### GET `/api/callbacks` - Lấy tất cả callbacks
```bash
curl http://localhost:8888/api/callbacks
```

Response:
```json
{
  "total": 5,
  "unique_services": 3,
  "callbacks": [...]
}
```

#### GET `/api/callbacks/<id>` - Chi tiết callback
```bash
curl http://localhost:8888/api/callbacks/1
```

#### DELETE `/api/callbacks` - Xóa tất cả
```bash
curl -X DELETE http://localhost:8888/api/callbacks
```

#### GET `/health` - Health check
```bash
curl http://localhost:8888/health
```

## Cách sử dụng

### Bước 1: Khởi động Callback Server
```powershell
# PowerShell
cd tools
python callback_server.py
```

Server sẽ chạy trên: `http://0.0.0.0:8888`

### Bước 2: Expose với ngrok (để test từ xa)
```powershell
# Terminal mới
ngrok http 8888
```

Bạn sẽ nhận được public URL, ví dụ: `https://abcd1234.ngrok.io`

### Bước 3: Mở Dashboard
```
Trình duyệt: http://localhost:8888/
```

Hoặc nếu dùng ngrok:
```
https://abcd1234.ngrok.io/
```

### Bước 4: Test SSRF
Khi target service thực hiện request tới callback URL, bạn sẽ thấy ngay trên dashboard:
- Thời gian nhận
- HTTP method (GET, POST, etc.)
- Path được gọi
- IP nguồn
- Service phát hiện (Python, Java, etc.)
- User-Agent đầy đủ
- Body data (nếu có)

### Bước 5: Xem chi tiết
Click nút "👁️ View" để xem:
- Tất cả headers (Authorization, Cookie, etc.)
- Body đầy đủ
- Metadata để phân tích service nào thực thi

## Ví dụ Test

### Test 1: Basic SSRF
```bash
# Target service thực thi:
curl https://abcd1234.ngrok.io/ssrf_test_1

# Dashboard sẽ hiển thị:
# - Method: GET
# - Path: /ssrf_test_1
# - Service: curl
# - User-Agent: curl/7.68.0
```

### Test 2: Python requests
```python
# Target service chạy:
import requests
requests.get('https://abcd1234.ngrok.io/api/check')

# Dashboard sẽ hiển thị:
# - Method: GET
# - Path: /api/check
# - Service: python
# - User-Agent: python-requests/2.28.0
```

### Test 3: Java application
```java
// Target service:
HttpClient.newHttpClient()
    .send(request, HttpResponse.BodyHandlers.ofString());

// Dashboard hiển thị:
# - Service: java
# - User-Agent: Java/17.0.2
```

## Tính năng Dashboard

### Stats Cards
- **Total Callbacks**: Tổng số callbacks nhận được
- **Last Received**: Thời gian callback cuối cùng
- **Unique Services**: Số lượng service khác nhau đã phát hiện

### Table Columns
- **Time**: Thời gian chính xác (giây + milliseconds)
- **Method**: HTTP method với màu sắc (GET=green, POST=blue, etc.)
- **Path**: URL path được gọi
- **From IP**: Địa chỉ IP nguồn
- **Service**: Service/library được phát hiện
- **User-Agent**: Preview User-Agent string
- **Body**: Kích thước body
- **Action**: Nút xem chi tiết

### Auto-refresh
- Tự động refresh mỗi 2 giây
- Có thể tắt/bật bằng checkbox

### Clear Data
- Nút "🗑️ Clear All" để xóa tất cả callbacks
- Hữu ích khi bắt đầu test mới

## Phân tích Service từ Headers

Dashboard giúp bạn xác định:

1. **Service Type**: Library/framework nào gửi request
   - `python-requests` → Python application
   - `Java/11` → Java service
   - `node-fetch` → Node.js backend
   - `curl` → Script/manual test
   - `Mozilla/5.0` → Browser-based

2. **Cloud Environment**:
   - `aws-sdk` → AWS Lambda/EC2
   - `google-cloud` → GCP service
   - `azure-sdk` → Azure function

3. **Framework Detection**:
   - `Spring` → Spring Boot application
   - `Django` → Django backend
   - `Express` → Node.js/Express

## Security Notes

### Bảo mật khi dùng ngrok
- Callback có thể chứa thông tin nhạy cảm (tokens, cookies)
- Không share ngrok URL công khai nếu nhận được sensitive data
- Sử dụng ngrok URLs có thời hạn ngắn
- Xóa callbacks sau khi test xong

### API Key Protection (Optional)
Nếu muốn bảo vệ API endpoints, set environment variable:
```powershell
$env:CALLBACK_API_KEY="your-secret-key"
python callback_server.py
```

Khi gọi API, thêm header:
```bash
curl -H "X-API-KEY: your-secret-key" http://localhost:8888/api/callbacks
```

## Tích hợp với Web UI Toolkit

Nếu bạn chạy Web UI chính của toolkit:
1. Web UI sẽ tự động phát hiện ngrok tunnel
2. Sử dụng public URL cho SSRF payloads
3. Callback server nhận và lưu trữ requests
4. Xem kết quả realtime trên dashboard này

## Troubleshooting

### Port 8888 đã được sử dụng
```powershell
# Tìm process đang dùng port
netstat -ano | findstr :8888

# Kill process (thay PID)
taskkill /PID <PID> /F
```

### ngrok không kết nối
```powershell
# Kiểm tra ngrok đang chạy
curl http://127.0.0.1:4040/api/tunnels

# Khởi động lại ngrok
ngrok http 8888
```

### Callbacks không hiển thị
1. Kiểm tra server đang chạy: `curl http://localhost:8888/health`
2. Kiểm tra ngrok forwarding đúng port
3. Refresh dashboard thủ công
4. Xem console logs để debug

## Performance

- **Memory**: Giới hạn 1000 callbacks trong memory
- **Body size**: Preview 2000 ký tự đầu tiên
- **Auto-cleanup**: Callbacks cũ sẽ bị xóa khi vượt quá limit
- **Thread-safe**: An toàn với concurrent requests

## Các use cases thực tế

### 1. Phát hiện SSRF trong microservices
```
Test → SSRF payload với ngrok URL → Service thực thi
→ Dashboard hiển thị service type → Phân tích impact
```

### 2. Xác định backend technology
```
Không biết target dùng gì → Trigger SSRF
→ Xem User-Agent → Biết Python/Java/Node.js
→ Chọn payload phù hợp cho framework đó
```

### 3. Debug webhook integrations
```
Tạo webhook URL (ngrok) → Config vào target
→ Dashboard nhận webhook data realtime
→ Xem headers/body để debug
```

### 4. Cloud metadata exfiltration
```
SSRF tới 169.254.169.254 → Data reflect qua callback
→ Xem body chứa AWS credentials/metadata
```

## Tips & Tricks

1. **Multiple tests**: Path khác nhau giúp phân biệt test cases
   - `/ssrf_test_1`, `/ssrf_test_2`, etc.

2. **Timing analysis**: Milliseconds giúp tính response time
   - Xem thời gian từ gửi payload đến nhận callback

3. **Header inspection**: Authorization/Cookie headers quan trọng
   - Có thể thấy internal tokens

4. **Body analysis**: POST/PUT requests có data
   - Xem service gửi gì (JSON, form data, etc.)

5. **Service fingerprinting**: User-Agent là key
   - Kết hợp với headers khác để chính xác hơn

## Kết luận

Callback server nâng cấp giúp:
- ✅ Theo dõi SSRF realtime với giao diện đẹp
- ✅ Phân tích service/technology stack của target
- ✅ Debug và verify SSRF payloads hiệu quả
- ✅ Lưu trữ và review callbacks sau này
- ✅ Tích hợp dễ dàng với toolkit chính

Chúc bạn pentest hiệu quả! 🎯
