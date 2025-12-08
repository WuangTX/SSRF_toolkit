# 🎯 Multi-Method SSRF Testing Guide

## Tổng quan

Toolkit hiện hỗ trợ **test SSRF với nhiều HTTP methods** để phát hiện endpoint vulnerable với method nào.

---

## 🚀 Cách sử dụng

### 1. Test với một method duy nhất (như trước)

```python
from blackbox.detection.external_callback import ExternalCallbackDetector, CallbackServer

# Setup
callback_server = CallbackServer()
callback_server.start()
detector = ExternalCallbackDetector(callback_server)

# Test với POST
result = detector.test_ssrf(
    target_url='https://example.com/api/fetch',
    parameter='url',
    method='POST',
    timeout=10
)

if result['is_vulnerable']:
    print("✅ VULNERABLE!")
else:
    print("❌ Not vulnerable")
```

### 2. Test với nhiều methods (MỚI!)

```python
# Test với GET, POST, PUT
result = detector.test_ssrf_multi_method(
    target_url='https://example.com/api/fetch',
    parameter='url',
    methods=['GET', 'POST', 'PUT'],  # Danh sách methods cần test
    timeout=10
)

# Xem tổng quan
print(f"Tested {result['summary']['total_methods_tested']} methods")
print(f"Vulnerable: {result['summary']['vulnerable_methods_count']} methods")
print(f"Vulnerable methods: {', '.join(result['vulnerable_methods'])}")

# Xem chi tiết từng method
for method, method_result in result['method_results'].items():
    print(f"\n{method}:")
    if method_result['is_vulnerable']:
        print(f"  ✅ VULNERABLE - Received {method_result['callbacks_received']} callbacks")
    else:
        print(f"  ❌ Not vulnerable")
```

### 3. Trong Web UI (Tự động)

Khi upload **Burp Suite** hoặc **HAR file**, toolkit sẽ:

1. ✅ **Tự động detect** HTTP method từ captured request
2. ✅ **Test với đúng method** đã capture
3. ✅ **Hiển thị rõ ràng** method và test type trong report

**Ví dụ kết quả:**

```
┌─────────────────────────────────────────────────────────┐
│ 🔥 SSRF VULNERABILITY FOUND                             │
├─────────────────────────────────────────────────────────┤
│ Endpoint: https://quangtx.io.vn/api/products/1/compare │
│ HTTP Method: POST                                        │
│ Test Type: 📄 JSON POST Request                         │
│ Parameter: compare_url                                   │
│ Payload: http://169.254.169.254/latest/meta-data/      │
│ Evidence: ami-id, instance-id, security-groups         │
└─────────────────────────────────────────────────────────┘
```

---

## 📊 Kết quả trả về

### Single Method Test

```python
{
    'target_url': 'https://example.com/api/fetch',
    'parameter': 'url',
    'method': 'POST',
    'is_vulnerable': True,
    'callbacks_received': 1,
    'callback_url': 'http://callback-server:8888/test',
    'callback_details': [{
        'timestamp': '2025-11-21T10:30:00',
        'method': 'GET',
        'client_address': '203.0.113.42',
        'headers': {...}
    }]
}
```

### Multi-Method Test

```python
{
    'target_url': 'https://example.com/api/fetch',
    'parameter': 'url',
    'methods_tested': ['GET', 'POST', 'PUT'],
    'vulnerable_methods': ['POST'],  # Chỉ POST vulnerable
    'method_results': {
        'GET': {
            'is_vulnerable': False,
            'callbacks_received': 0,
            ...
        },
        'POST': {
            'is_vulnerable': True,
            'callbacks_received': 1,
            ...
        },
        'PUT': {
            'is_vulnerable': False,
            'callbacks_received': 0,
            ...
        }
    },
    'summary': {
        'total_methods_tested': 3,
        'vulnerable_methods_count': 1,
        'is_vulnerable': True,
        'vulnerability_rate': 0.333  # 33.3%
    }
}
```

---

## 🎨 UI Enhancements

### Endpoint Card hiển thị:

```
┌────────────────────────────────────────────────┐
│ https://example.com/api/fetch                  │
│ 🔥 SSRF VULNERABLE!  [POST]  📌 url            │
├────────────────────────────────────────────────┤
│ Method: POST  │  Type: 📄 JSON POST            │
│ Status: 200   │  Source: 📜 JavaScript         │
│ Payload sent  │  🔍 Click to view details      │
└────────────────────────────────────────────────┘
```

### Finding Modal hiển thị:

```
╔════════════════════════════════════════════════╗
║ 📊 Test Information                            ║
╠════════════════════════════════════════════════╣
║ HTTP Method:      [POST]                       ║
║ Test Type:        📄 JSON POST Request         ║
║ Test Parameter:   url                          ║
║ Response Status:  200                          ║
║ Discovery Source: 📜 JavaScript Analysis       ║
║ Vulnerable:       ✅ YES - SSRF CONFIRMED!     ║
╚════════════════════════════════════════════════╝
```

---

## 💡 Use Cases

### Case 1: Test endpoint có thể chấp nhận nhiều methods

```python
# Test xem endpoint có vulnerable với method nào
result = detector.test_ssrf_multi_method(
    target_url='https://api.example.com/webhook',
    parameter='callback_url',
    methods=['GET', 'POST', 'PUT', 'DELETE']
)

# Kết quả có thể là:
# - GET: Not vulnerable
# - POST: VULNERABLE ✅
# - PUT: VULNERABLE ✅
# - DELETE: Not vulnerable
```

### Case 2: Verify fix sau khi patch

```python
# Trước khi patch
result_before = detector.test_ssrf_multi_method(...)
# vulnerable_methods: ['GET', 'POST']

# ... developer fix ...

# Sau khi patch
result_after = detector.test_ssrf_multi_method(...)
# vulnerable_methods: []  ✅ Đã fix!
```

### Case 3: Compare vulnerability giữa methods

```python
result = detector.test_ssrf_multi_method(
    target_url='https://example.com/api/fetch',
    parameter='url',
    methods=['GET', 'POST']
)

# So sánh
get_result = result['method_results']['GET']
post_result = result['method_results']['POST']

if get_result['is_vulnerable'] and not post_result['is_vulnerable']:
    print("⚠️  Chỉ GET vulnerable, POST đã được protect!")
elif not get_result['is_vulnerable'] and post_result['is_vulnerable']:
    print("⚠️  Chỉ POST vulnerable, GET đã được protect!")
elif get_result['is_vulnerable'] and post_result['is_vulnerable']:
    print("🔥 Cả GET và POST đều vulnerable!")
else:
    print("✅ Cả GET và POST đều safe!")
```

---

## 📝 Test Type Mapping

| Content-Type Header | Method | Test Type |
|---------------------|--------|-----------|
| `application/json` | POST | `api_json_post` |
| `application/x-www-form-urlencoded` | POST | `api_form_post` |
| `multipart/form-data` | POST | `api_form_post` |
| N/A | GET | `api_get_param` |
| N/A | PUT | `api_json_put` |
| N/A | DELETE | `api_json_delete` |

---

## 🔍 Debugging

### Enable verbose logging

```python
import logging
logging.basicConfig(level=logging.DEBUG)

# Bây giờ bạn sẽ thấy:
# [DEBUG] Testing SSRF on https://example.com/api/fetch
# [DEBUG] Method: GET
# [DEBUG] Payload: http://callback:8888/test-abc123
# [DEBUG] Waiting for callback...
# [INFO] ✅ Callback received!
```

### Check raw request

```python
result = detector.test_ssrf(...)

# Xem full request đã gửi
if 'all_attempts' in result:
    for attempt in result['all_attempts']:
        print(f"Callback URL: {attempt['callback_url']}")
        print(f"Response: {attempt['initial_response']}")
```

---

## ⚙️ Configuration

### Timeout settings

```python
# Default timeout: 10 seconds
result = detector.test_ssrf(timeout=10)

# Longer timeout cho slow networks
result = detector.test_ssrf(timeout=30)

# Quick test
result = detector.test_ssrf(timeout=5)
```

### Custom methods list

```python
# Default: ['GET', 'POST']
result = detector.test_ssrf_multi_method(methods=['GET', 'POST'])

# Full test
result = detector.test_ssrf_multi_method(
    methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
)

# Specific methods only
result = detector.test_ssrf_multi_method(methods=['POST', 'PUT'])
```

---

## 🎯 Best Practices

1. ✅ **Luôn test với đúng method** được application sử dụng
2. ✅ **Sử dụng multi-method test** khi không chắc chắn
3. ✅ **Check test_type** để hiểu cách payload được gửi
4. ✅ **Verify với manual test** sau khi tìm thấy vulnerability
5. ✅ **Save report** để so sánh trước/sau khi fix

---

## 🐛 Troubleshooting

### Vấn đề: Không nhận được callback

**Kiểm tra:**
1. Callback server có đang chạy? (`callback_server.is_running`)
2. Firewall có block không?
3. Target có thể reach callback server?
4. Timeout có đủ dài?

**Giải pháp:**
```python
# 1. Check server status
print(f"Server running: {callback_server.is_running}")

# 2. Use ngrok/tunnel nếu cần
# 3. Increase timeout
result = detector.test_ssrf(timeout=30)

# 4. Check logs
logging.basicConfig(level=logging.DEBUG)
```

### Vấn đề: Method không được test

**Kiểm tra:**
```python
result = detector.test_ssrf_multi_method(
    methods=['GET', 'POST', 'CUSTOM']  # ❌ CUSTOM không support
)

# Chỉ GET và POST được test
print(result['methods_tested'])  # ['GET', 'POST']
```

**Hiện tại hỗ trợ:** GET, POST, PUT, DELETE, PATCH, OPTIONS

---

## 📚 Tài liệu thêm

- [TEST_METHOD_EXPLANATION.md](./TEST_METHOD_EXPLANATION.md) - Chi tiết về test types
- [SSRF_TESTING_GUIDE.md](./SSRF_TESTING_GUIDE.md) - Hướng dẫn test SSRF
- [API_REFERENCE.md](./API_REFERENCE.md) - API documentation

---

**📅 Last updated:** 2025-11-21  
**🔧 Version:** 2.0  
**✍️ Author:** SSRF Toolkit Team
