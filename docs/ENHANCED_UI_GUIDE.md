# Hướng Dẫn Sử Dụng SSRF Toolkit - Enhanced UI

## Tổng Quan

SSRF Toolkit Enhanced UI được thiết kế theo workflow 4 bước: **RECON → PAYLOAD → SCAN → EXPLOIT**

Giao diện mới cung cấp **7 nhóm tùy chọn chính** để tăng độ chính xác, giảm false positive, và kiểm soát an toàn khi kiểm thử SSRF trong môi trường microservices.

---

## 🎯 7 Nhóm Tùy Chọn Chính

### 1. **Test Mode** (Chế Độ Kiểm Thử)
Xác định phạm vi và chiến lược:
- **Blackbox**: Không có thông tin nội bộ → tự động discovery + fuzzing
- **Graybox**: Có token/API key/endpoint list → tăng độ chính xác
- **Whitebox**: Có source code/API spec → tự sinh SSRF checklist

### 2. **Target Type** (Loại Mục Tiêu)
Chọn loại service cần scan:
- HTTP Endpoint
- gRPC Endpoint
- Internal Service URLs
- Cloud Metadata (AWS/GCP/Azure)
- Container Services (Docker API, K8s API)
- Service Mesh (Istio/Linkerd)

### 3. **Attack Depth** (Mức Độ Tấn Công)
- **Quick**: Payload cơ bản (localhost, 169.254.169.254)
- **Deep**: Top 500 SSRF signatures
- **Cloud**: IMDSv1/v2, metadata proxy
- **Container**: Docker API, Consul, Redis
- **Side-Channel**: DNS callback, time delay

### 4. **Payload Strategy** (Kỹ Thuật Payload)
- URL Bypass (DNS rebinding, encoding, shortlink)
- Protocol Smuggling (gopher://, dict://, ftp://)
- Redirect-based SSRF
- Header Injection (Host, X-Forwarded-*)
- Template/SSTI → SSRF
- Blind SSRF (DNS Logging)

### 5. **Input Source** (Nguồn Dữ Liệu)
- Manual Input (nhập URL)
- API Spec (Swagger/OpenAPI)
- Burp Traffic (HAR/JSON export)
- Postman Collection
- Source Code (phân tích code)

### 6. **Service Discovery** (Phát Hiện Microservices)
- Kubernetes API
- Consul
- Docker
- API Gateway Logs
- Auto Dependency Graph

### 7. **Safe Mode** (Kiểm Soát An Toàn)
- Safe Scan (không tấn công phá hoại)
- Disable Destructive Protocols
- Throttle RPS
- Scope Protection

---

## 📋 Workflow 4 Bước

### **TAB 1: RECON / INPUT** 📡

**Mục đích**: Chọn chế độ kiểm thử và nguồn dữ liệu

**Các bước**:
1. Chọn Test Mode (Blackbox/Graybox/Whitebox)
2. Chọn Input Source
3. Nhập Target URL hoặc upload file (Swagger/Burp/Postman)
4. Nếu Graybox:
   - Bật Service Discovery (K8s/Consul/Docker)
   - Nhập Auth Token nếu có

**Ví dụ Blackbox**:
```
Test Mode: Blackbox
Input Source: Manual
Target URL: https://api.example.com
```

**Ví dụ Graybox**:
```
Test Mode: Graybox
Input Source: API Spec
File: swagger.json
Service Discovery: ✓ Kubernetes, ✓ Consul
Auth Token: Bearer eyJhbGciOiJI...
```

---

### **TAB 2: PAYLOAD STRATEGY** 🎯

**Mục đích**: Chọn loại payload và độ sâu tấn công

**Các bước**:
1. Chọn Target Types (HTTP, gRPC, Cloud Metadata...)
2. Chọn Attack Depth (Quick/Deep/Cloud/Container/Side-Channel)
3. Chọn Payload Techniques

**Ví dụ Quick Scan**:
```
Target Types: ✓ HTTP, ✓ Cloud Metadata
Attack Depth: Quick
Payload Techniques: ✓ URL Bypass, ✓ Blind SSRF
```

**Ví dụ Deep Scan**:
```
Target Types: ✓ HTTP, ✓ Internal Service, ✓ Container
Attack Depth: Deep
Payload Techniques: ✓ All (URL Bypass, Protocol Smuggling, Redirect, Header Injection)
```

---

### **TAB 3: SCAN & ANALYSIS** 🔍

**Mục đích**: Cấu hình phương thức scan và hiệu suất

**Các bước**:
1. Chọn phương thức scan (Parameters, Headers, Templating...)
2. Cấu hình timeout và threads
3. Bật Safe Mode và các kiểm soát an toàn

**Ví dụ Safe Scan**:
```
Scan Methods: ✓ Parameters, ✓ Headers, ✓ DNS Callback
Timeout: 10s
Threads: 5
Safe Mode: ✓ ON
Disable Destructive: ✓ ON
Throttle: 2 req/s
Scope Protection: ✓ ON (example.com, api.example.com)
```

---

### **TAB 4: EXPLOIT MODULE** 💥

**⚠️ CẢNH BÁO**: Chỉ sử dụng trong môi trường lab/test được phép!

**Mục đích**: Khai thác SSRF để kiểm chứng mức độ nghiêm trọng

**Các bước**:
1. ✓ Kích hoạt Exploit Module (cần xác nhận)
2. Chọn exploit types:
   - Docker API Takeover
   - Redis Arbitrary Write
   - AWS/GCP Credential Steal
   - Jump to Internal Service
   - Kubernetes API Access
3. Nhập target service cụ thể (nếu biết)

**Ví dụ**:
```
✓ Exploit Enabled
Selected: ✓ Docker API Takeover, ✓ Redis Arbitrary Write
Target Service: http://redis-internal:6379
```

---

## 💡 Ví Dụ Use Cases

### **Use Case 1: Quick Blackbox Scan**
**Tình huống**: Cần scan nhanh một API công khai

**Cấu hình**:
- Tab 1: Blackbox, Manual Input, URL: https://api.target.com
- Tab 2: HTTP, Quick Scan, URL Bypass
- Tab 3: Safe Mode ON, 2 req/s
- Tab 4: Exploit OFF

**Thời gian dự kiến**: 5-10 phút

---

### **Use Case 2: Graybox Deep Scan với Service Discovery**
**Tình huống**: Có auth token, muốn scan toàn bộ microservices trong K8s cluster

**Cấu hình**:
- Tab 1: Graybox, Manual, ✓ K8s Discovery, Auth Token
- Tab 2: HTTP + Internal + Container, Deep Scan, All Payloads
- Tab 3: Safe Mode ON, Scope: *.cluster.local
- Tab 4: Exploit OFF

**Thời gian dự kiến**: 30-60 phút

---

### **Use Case 3: Whitebox với Source Code**
**Tình huống**: Có source code, muốn tự sinh checklist SSRF

**Cấu hình**:
- Tab 1: Whitebox, Source Code, Upload: project.zip
- Tab 2: HTTP + Internal, Quick, URL Bypass
- Tab 3: Safe Mode ON
- Tab 4: Exploit OFF

**Kết quả**: Tự động phát hiện HTTP client calls, URL parameters, route definitions → tạo checklist

---

### **Use Case 4: Cloud SSRF Testing**
**Tình huống**: Kiểm tra SSRF đến AWS/GCP metadata

**Cấu hình**:
- Tab 1: Blackbox, Manual
- Tab 2: ✓ Cloud Metadata, Cloud Scan, Blind SSRF
- Tab 3: Safe Mode ON
- Tab 4: ✓ Exploit ON → AWS Credential Steal (chỉ trong lab!)

---

## 🛡️ Best Practices

### **1. Luôn bật Safe Mode khi scan production**
```
✓ Safe Mode
✓ Disable Destructive
✓ Throttle 1-2 req/s
✓ Scope Protection
```

### **2. Chọn Attack Depth phù hợp**
- **Production**: Quick hoặc Cloud
- **Staging**: Deep
- **Lab**: Container hoặc Side-Channel

### **3. Tránh Exploit Module trong production**
- Chỉ dùng trong lab được phép
- Có thể gây crash service
- Chỉ bật khi cần kiểm chứng PoC

### **4. Sử dụng Service Discovery hiệu quả**
- Graybox mode với K8s/Consul discovery giúp tìm được internal services
- Auto Dependency Graph giúp hiểu flow: API → Service A → Service B

### **5. Kết hợp Input Sources**
- Burp Traffic để tìm real-world endpoints
- Swagger để có full API coverage
- Source Code để tự sinh test cases

---

## 🔧 Troubleshooting

### **Lỗi: "Service Discovery failed"**
**Nguyên nhân**: Không có quyền truy cập K8s/Consul/Docker

**Giải pháp**:
- Kiểm tra kubeconfig path
- Kiểm tra Consul address
- Kiểm tra Docker socket permission

### **Lỗi: "Rate limit exceeded"**
**Nguyên nhân**: Gửi request quá nhanh

**Giải pháp**:
- Giảm Threads
- Tăng Throttle RPS
- Bật Safe Mode

### **Lỗi: "No callbacks received"**
**Nguyên nhân**: Callback server không accessible từ target

**Giải pháp**:
- Kiểm tra ngrok/public URL
- Kiểm tra firewall
- Dùng DNS-based callback thay vì HTTP

---

## 📊 So Sánh UI Cũ vs UI Mới

| Tính năng | UI Cũ | UI Enhanced |
|-----------|-------|-------------|
| Test Modes | 3 (B/G/W) | 3 + Service Discovery |
| Payload Types | Fixed | 6 loại + configurable |
| Attack Depth | 1 level | 5 levels |
| Input Sources | 2 | 5 (Swagger, Burp, Postman, Code) |
| Safe Controls | Basic | Advanced (throttle, scope, destructive filter) |
| Service Discovery | ❌ | ✓ K8s/Consul/Docker |
| Workflow | Linear | 4-tab workflow |

---

## 🎓 Kết Luận

UI Enhanced giúp:
- ✅ Tăng độ chính xác (ít false positive)
- ✅ Giảm noise (safe mode, scope protection)
- ✅ Đa năng (7 nhóm tùy chọn)
- ✅ Dễ sử dụng (workflow 4 bước rõ ràng)
- ✅ An toàn hơn (safe mode mặc định, exploit require confirmation)

**Khuyến nghị**:
- Bắt đầu với Quick Scan + Safe Mode
- Nâng cấp dần lên Deep Scan khi cần
- Chỉ dùng Exploit trong lab
- Luôn enable Scope Protection trong production
