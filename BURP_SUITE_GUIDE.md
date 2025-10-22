# 🎯 Hướng Dẫn Export Burp Suite Proxy History

## Tại sao dùng Burp Suite?

Khi bạn đã **browse và login** vào ứng dụng qua Burp Suite, proxy history đã capture:
- ✅ **Tất cả endpoints** (kể cả sau login)
- ✅ **JWT tokens** và session cookies
- ✅ **Requests giữa các microservices**
- ✅ **Dynamic routes** với ID thực (ví dụ: `/api/inventory/5/M`)

## 📋 Các Bước Export

### Cách 1: Export JSON (Khuyến nghị)

1. **Mở Burp Suite** và chắc chắn bạn đã browse qua ứng dụng
2. Vào tab **Proxy → HTTP History**
3. **Chọn tất cả requests** cần test:
   - Click vào request đầu tiên
   - Giữ `Shift` + Click request cuối cùng
   - Hoặc `Ctrl+A` để chọn tất cả
4. **Chuột phải** → **Save items**
5. Chọn format: **JSON** hoặc **XML**
6. Lưu file (ví dụ: `proxy_history.json`)

### Cách 2: Filter Specific Hosts

Nếu bạn chỉ muốn export requests tới specific host:

1. Trong **HTTP History**, click vào **Filter bar**
2. Enable filter: **Show only in-scope items**
3. Hoặc filter by hostname (ví dụ: `localhost:8083`)
4. Select filtered items → Save items

## 📤 Upload vào Tool

1. Start Web UI: `python web_ui/start.py`
2. Vào http://localhost:5000
3. Click **"Choose File"** ở phần **Traffic Capture File**
4. Chọn file `proxy_history.json` hoặc `proxy_history.xml`
5. Click **"Start Scan"**

Tool sẽ tự động:
- Parse tất cả requests
- Extract endpoints (kể cả có JWT)
- Fuzz các parameters với auth headers
- Test SSRF với credentials thật

## 🔍 Ví Dụ Request từ Burp Suite

```http
GET /api/inventory/5/M HTTP/1.1
Host: localhost:8083
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
Accept: application/json
Cookie: session=abc123; userId=user1
```

Tool sẽ:
1. ✅ Detect endpoint: `GET /api/inventory/5/M`
2. ✅ Extract JWT token: `Bearer eyJhbG...`
3. ✅ Test SSRF với auth header này
4. ✅ Fuzz parameter `M` với callback URLs

## 🆚 So Sánh: Burp vs Chrome HAR

| Feature | Burp Suite | Chrome HAR |
|---------|------------|------------|
| **Capture sau login** | ✅ Rất dễ | ⚠️ Phải browse lại |
| **JWT tokens** | ✅ Tự động | ✅ Tự động |
| **Microservice requests** | ✅ Thấy tất cả | ❌ Chỉ thấy từ browser |
| **WebSocket** | ✅ Support | ❌ Không support |
| **Request modification** | ✅ Có thể edit | ❌ Không thể |
| **Setup** | ⚠️ Cần config proxy | ✅ Built-in browser |

## 💡 Tips

### Nên Export Khi Nào?

- **Sau khi login** và browse đầy đủ ứng dụng
- **Sau khi test các features** (submit form, upload file, etc.)
- **Sau khi click tất cả buttons/tabs** quan trọng

### Filter Noise

Burp Suite có thể capture nhiều requests không cần thiết (CDN, analytics, etc.). 

**Trong Burp Suite:**
1. Proxy → Options → Intercept Client Requests
2. Add rule: **Only URLs in scope**
3. Target → Scope → Add: `http://localhost:8083`

Hoặc sau khi export, tool sẽ **tự động filter** chỉ giữ lại internal requests.

### Xem Trước Nội Dung

Trước khi upload, bạn có thể test parse:

```bash
python utils/burp_parser.py proxy_history.json
```

Output:
```
=== Burp Suite Export Statistics ===
Total Requests: 45
Unique Endpoints: 12
Methods: {'GET': 30, 'POST': 10, 'PUT': 3, 'DELETE': 2}
Hosts: localhost:8083
Authenticated Requests: 35

=== Unique Endpoints ===
  GET /api/inventory
  GET /api/inventory/5/M
  POST /api/orders
  ...
```

## 🎯 Use Case: Microservices

Nếu ứng dụng của bạn có nhiều microservices:

```
Frontend → API Gateway → Service A → Service B
```

Burp Suite sẽ capture **tất cả requests**:
- Frontend → API Gateway: `http://localhost:3000/api/...`
- Gateway → Service A: `http://localhost:8083/...`
- Service A → Service B: `http://localhost:8084/...`

Tool sẽ test SSRF trên **TẤT CẢ** các endpoints này!

## ⚠️ Lưu Ý Bảo Mật

Export từ Burp Suite chứa:
- 🔐 JWT tokens (có thể còn valid)
- 🍪 Session cookies
- 🔑 API keys

**KHÔNG share file export** này với người khác!

## 🚀 Next Steps

Sau khi upload Burp Suite export:

1. Tool sẽ **emit real-time logs** hiển thị endpoints đang test
2. Thấy **JWT tokens** trong console (preview 40 ký tự đầu)
3. **Findings panel** hiển thị SSRF vulnerabilities
4. **Export report** JSON khi scan xong

**Happy Hunting! 🎯**
