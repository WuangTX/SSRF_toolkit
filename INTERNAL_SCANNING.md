# 🔍 Internal Network Scanning - Giải Thích

## ❓ Tại sao có Internal Scanning?

Khi phát hiện SSRF vulnerability, attacker có thể:
1. **Scan internal network** của target server
2. **Discover hidden services** (databases, caches, microservices)
3. **Lateral movement** - tấn công từ service này sang service khác

## 🎯 Cách hoạt động

### Trường hợp thực tế (Production):

```
Pentester Machine                    Target Server (192.168.1.100)
     |                                    |
     |  1. Send SSRF payload              |  - Web App (port 8080)
     |  ?url=http://localhost:5432        |  - PostgreSQL (port 5432)
     |  ---------------------------------> |  - Redis (port 6379)
     |                                    |  - Internal API (port 8081)
     |  2. Web app scans its localhost    |
     |     (192.168.1.100:5432)           |
     |                                    |
     |  3. Response reveals DB is open    |
     |  <-------------------------------- |
     |                                    |
     |  4. Exploit database via SSRF      |
     |  ?url=http://localhost:5432/...    |
```

**Kết quả**: Pentester phát hiện và có thể exploit internal services!

---

### Trường hợp test local (Development):

```
Your Machine (localhost)
     |
     |  - Tool (port 5000)
     |  - Target Service (port 8083)
     |  - PostgreSQL (port 5432)
     |  - Redis (port 6379)
     |
     |  1. Tool sends: ?url=http://localhost:5432
     |  2. Service 8083 scans localhost:5432
     |  3. Detects PostgreSQL (cùng máy)
```

**Vấn đề**: Localhost của service = Localhost của tool = Cùng 1 máy!

## ⚠️ Tại sao tool báo warning?

```
⚠️ Skipping internal scan - No confirmed SSRF vulnerability
💡 Internal scanning requires a confirmed SSRF to avoid scanning pentester's own machine
```

**Lý do**: 
- Nếu **KHÔNG CÓ SSRF** thực sự
- Tool sẽ scan **trực tiếp** localhost của máy pentester
- Không phải cách SSRF thật hoạt động
- Tạo false positive (báo lỗi services trên máy pentester)

## ✅ Khi nào Internal Scan chạy?

Tool CHỈ chạy internal scanning khi:

1. **Callback Testing thành công** 
   ```
   ✅ CONFIRMED SSRF via callback_url at http://localhost:8083/api/inventory/5/M
   ```

2. **Có SSRF vulnerability thật**
   - Service thực sự fetch external URLs
   - Callback server nhận được request

3. **Scan qua SSRF parameter**
   ```python
   # Tool GỬI payload qua SSRF:
   http://localhost:8083/api?callback_url=http://localhost:5432
   
   # Service 8083 TỰ request tới localhost:5432
   # Không phải tool scan trực tiếp
   ```

## 🎯 Trong trường hợp của bạn

### Nếu test với microservice_lab:

#### Scenario 1: Không có SSRF
```
Tool → localhost:8083/api/inventory/5/M
Service KHÔNG fetch external URLs
Callback test: ❌ FAILED
Internal scan: ⚠️ SKIPPED (correct behavior)
```

#### Scenario 2: Có SSRF
```
Tool → localhost:8083/api?url=http://callback.server
Service FETCH external URL
Callback test: ✅ CONFIRMED
Internal scan: ✅ RUN through SSRF parameter

Kết quả:
- localhost:5432 - PostgreSQL ✅
- localhost:6379 - Redis ✅  
- localhost:3306 - MySQL ✅
```

Nhưng vì đang test local → Đây là services trên **máy bạn**, không phải production environment thật.

## 💡 Để test đúng hơn

### Option 1: Test với Docker
```bash
# Service chạy trong Docker container
docker run -p 8083:8083 vulnerable-service

# Tool chạy trên host machine
python web_ui/start.py
```

Khi service scan `localhost:5432` → Scan **trong container**, không phải host!

### Option 2: Test trên remote server
```bash
# Service trên server production
https://target.com/api

# Tool trên máy bạn
Target URL: https://target.com/api
```

Khi có SSRF → Scan internal network của **production server**

### Option 3: Disable Internal Scanning
Nếu không cần test:
```
☐ Internal Scanning  # Uncheck this option
```

## 📊 Kết quả đúng là gì?

### Production Environment:
```
✅ CONFIRMED SSRF via url parameter
🔎 Phase 4: Internal Network Scanning
🎯 Using confirmed SSRF parameter: url at http://target.com/api/fetch
⚠️ Note: Scanning localhost of TARGET service, not pentester machine

Discovered internal services:
  - localhost:5432 - PostgreSQL ⚠️ HIGH RISK
  - localhost:6379 - Redis ⚠️ HIGH RISK
  - internal-api:8080 - HTTP Service
  - database:3306 - MySQL ⚠️ CRITICAL
```

### Local Testing:
```
✅ CONFIRMED SSRF via callback_url
🔎 Phase 4: Internal Network Scanning
🎯 Using confirmed SSRF parameter: callback_url

⚠️ Note: In local testing, "localhost" refers to your machine
Discovered services:
  - localhost:5432 - PostgreSQL (your local DB)
  - localhost:6379 - Redis (your local cache)
```

## 🎓 Tổng kết

**Internal Scanning đang hoạt động ĐÚNG**, nhưng:

1. **Chỉ chạy khi có SSRF confirmed** (qua callback test)
2. **Scan qua SSRF parameter**, không phải direct scan
3. **Trong local testing**: Scan localhost = máy bạn (expected)
4. **Trong production**: Scan localhost = target server (real attack)

**Recommendation**: 
- Test với Docker hoặc remote server để thấy sự khác biệt
- Hoặc disable internal scanning nếu không cần
- Hiểu rằng đây là **expected behavior** khi test locally

---

**Questions?**
- Muốn test với Docker environment? → Tôi hướng dẫn setup
- Muốn disable internal scanning? → Uncheck option trên UI
- Muốn hiểu thêm về SSRF exploitation? → Đọc USAGE_GUIDE.md
   