# 🎯 SSRF Detection Logic - Giải thích chi tiết

## ⚠️ QUAN TRỌNG: Server fetch URL ≠ SSRF!

**Hiểu lầm phổ biến**: "Server gọi đến URL bên ngoài = SSRF"
**Sự thật**: Server gọi URL bên ngoài là **BÌNH THƯỜNG** và **CẦN THIẾT** trong nhiều tình huống!

### ✅ Các trường hợp HỢP LỆ khi server fetch external URL:

1. **Webhook callbacks**: Payment gateway gọi về khi thanh toán xong
2. **API integration**: Weather API, Map API, Payment API
3. **OAuth/SSO**: Lấy user info từ Google/Facebook
4. **CDN/Storage**: Download avatar, images từ S3/CDN
5. **Microservices**: Service A gọi Service B

### 🚨 SSRF chỉ là vấn đề KHI:

```python
# ❌ VULNERABLE - Attacker kiểm soát URL
url = request.args.get('url')  # User input!
response = requests.get(url)   # No validation!

# ✅ SAFE - Hardcoded hoặc whitelist
url = "https://api.weather.com/data"  # Fixed URL
response = requests.get(url)
```

## 🎯 Callback server phát hiện gì?

**Callback server CHỈ xác nhận**: "Server ĐÃ fetch URL do tôi (attacker) chỉ định"

**Điều này nghĩa là**:
- ✅ Tham số URL không được validate
- ✅ Attacker có thể control destination URL
- ✅ Server sẽ fetch BẤT KỲ URL nào attacker cung cấp
- 🚨 Attacker có thể exploit để: scan internal network, access internal services, read metadata

## 🔍 Định nghĩa SSRF (Server-Side Request Forgery)

**SSRF** là lỗ hổng cho phép attacker **BẮT server thực hiện HTTP request** đến địa chỉ do attacker chỉ định.

### 📊 So sánh Request bình thường vs SSRF

```
Request bình thường:
┌─────────┐           ┌──────────────┐
│ Browser │ ───────→  │ Victim.com   │
│ (Bạn)   │           │ Server       │
└─────────┘           └──────────────┘

SSRF xảy ra:
┌─────────┐           ┌──────────────┐           ┌─────────────┐
│ Browser │ ───────→  │ Victim.com   │ ───────→  │ Callback    │
│ (Bạn)   │           │ Server       │           │ Server (Bạn)│
└─────────┘           └──────────────┘           └─────────────┘
   Bước 1                  Bước 2                     Bước 3
```

**Bước 1**: Bạn gửi payload với callback URL
**Bước 2**: Victim server **TỰ TẠO request mới** đến callback URL
**Bước 3**: Callback server nhận request **TỪ victim server**

### 🎯 Vì sao nhận callback = xác nhận SSRF?

```python
# Khi callback server nhận request:

1. Request ĐẾN TỪ victim server (không phải từ browser của bạn)
2. IP nguồn là IP của victim server (ví dụ: 103.45.67.89)
3. Request này được victim server TỰ TẠO (không phải browser)
4. → Victim server đã FETCH URL do bạn cung cấp
5. → ✅ XÁC NHẬN SSRF!
```

### 📝 Ví dụ cụ thể:

```bash
# 1. Bạn gửi payload:
curl -X POST https://victim.com/api/fetch \
  -H "Content-Type: application/json" \
  -d '{"url": "https://your-callback.ngrok.dev/test-123"}'

# 2. Code của victim.com (vulnerable):
def fetch_api(request):
    url = request.json['url']  # Lấy URL từ input
    response = requests.get(url)  # ❌ SSRF: Fetch URL không validate!
    return response.text

# 3. Victim server TẠO request:
#    Source IP: 103.45.67.89 (victim server)
#    Target: https://your-callback.ngrok.dev/test-123
#    
# 4. Callback server của bạn nhận:
#    From: 103.45.67.89 (victim server IP)
#    Method: GET
#    Path: /test-123
#    
# 5. Kết luận:
#    ✅ Victim server đã FETCH URL do bạn cung cấp
#    ✅ Confirmed SSRF!
```

## 🔐 Logic phân biệt SSRF vs Test Request

### Vấn đề: Làm sao biết request từ victim hay từ bạn test?

```python
# Callback server check IP nguồn:
def _handle_request(self, method):
    client_ip = self.client_address[0]
    
    # Get real IP (qua proxy/ngrok)
    forwarded_for = self.headers.get('X-Forwarded-For')
    real_ip = forwarded_for.split(',')[0].strip() if forwarded_for else client_ip
    
    # Check IP type
    is_local = (
        real_ip in ['127.0.0.1', '::1', 'localhost'] or
        real_ip.startswith('192.168.') or  # Private Class C
        real_ip.startswith('10.') or       # Private Class A
        real_ip.startswith('172.')         # Private Class B
    )
    
    # Determine if SSRF
    is_ssrf = not is_local  # Public IP = SSRF candidate
```

### 📊 Decision Table:

| IP nguồn | Loại | Kết luận |
|----------|------|----------|
| 127.0.0.1 | localhost | ❌ Test request từ máy bạn |
| 192.168.x.x | Private IP | ❌ Request từ mạng LAN |
| 10.x.x.x | Private IP | ❌ Request từ mạng nội bộ |
| 103.45.67.89 | Public IP | ✅ **SSRF từ victim server!** |
| 8.8.8.8 | Public IP | ✅ **SSRF từ external server!** |

## 🚨 Các trường hợp đặc biệt

### 1. Ngrok/Proxy forwarding:

```
Browser → Victim → Ngrok Proxy → Callback Server
                    (IP: ngrok)    (sees ngrok IP)
```

**Giải pháp**: Check `X-Forwarded-For` header để lấy real IP

```python
forwarded_for = headers.get('X-Forwarded-For')
# Example: "103.45.67.89, 34.56.78.90"
real_ip = forwarded_for.split(',')[0].strip()  # 103.45.67.89
```

### 2. Cloud/Container environments:

Victim server có thể dùng NAT/proxy internal:
- AWS NAT Gateway
- Kubernetes ingress
- Cloud Load Balancer

→ Vẫn detect được SSRF vì IP nguồn là public IP của infrastructure

### 3. False negatives (bỏ sót SSRF):

**Trường hợp**: Victim có whitelist callback domain
```python
# Victim code:
allowed_domains = ['api.trusted.com']
if url_domain not in allowed_domains:
    return "Blocked"  # Không fetch URL
```
→ Callback server không nhận request → Không phát hiện được SSRF

**Giải pháp**: Test với nhiều technique:
- DNS rebinding
- URL parser confusion
- SSRF via redirect

## 🎓 Kết luận

**Nhận được callback từ public IP = SSRF vì:**

1. ✅ Request đến từ victim server (không phải browser của bạn)
2. ✅ IP nguồn là public IP (không phải localhost/test)
3. ✅ Victim server đã TỰ FETCH URL do bạn cung cấp
4. ✅ Đây là hành vi SSRF: server fetch external URL không validate

**Logic đơn giản:**
```
if (callback_received && source_ip_is_public):
    SSRF_CONFIRMED = True
else:
    SSRF_CONFIRMED = False
```
