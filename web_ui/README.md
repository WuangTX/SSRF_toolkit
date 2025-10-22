# Microservice SSRF Pentest Toolkit - Web UI

## 🚀 Quick Start

### 1. Cài đặt dependencies

```bash
cd web_ui
pip install -r requirements.txt
```

### 2. Chạy Web Server

```bash
python app.py
```

### 3. Truy cập Dashboard

Mở browser và truy cập: **http://localhost:5000**

---

## 🎯 3 Cách Sử Dụng Tool (Từ Dễ → Khó)

### ⭐ **Cách 1: Tự Động Hoàn Toàn** (Đơn giản nhất - Không cần Burp)
**Người dùng CHỈ cần nhập URL → Tool tự động làm hết**

1. Nhập base URL vào ô input (ví dụ: `http://localhost:3000`)
2. Click "Start Scan"
3. Tool tự động:
   - Quét robots.txt, sitemap.xml
   - Parse JavaScript tìm API endpoints
   - Brute-force với wordlist
   - Spider trang web
   - Fuzz tất cả parameters
   - Test SSRF callback

**✅ Ưu điểm:** Không cần làm gì thêm, chạy ngay

**❌ Nhược điểm:** Chỉ tìm được public endpoints, không thấy endpoints sau login

**🎯 Phù hợp:** Quick scan, public API, initial reconnaissance

---

### 🔥 **Cách 2: Import Traffic Capture** (Khuyến nghị - Đã Login)
**Người dùng đã browse qua Burp/Chrome → Export → Upload → Tool test**

#### 🎯 Option 2A: Burp Suite (TỐT NHẤT nếu đã dùng Burp)

**Bước người dùng làm:**
1. **Đã browse** qua ứng dụng trong Burp Suite (đã login)
2. Burp Suite → **Proxy → HTTP History**
3. **Select All** requests (Ctrl+A) hoặc chọn specific requests
4. **Right-click → Save items** → Chọn **JSON** hoặc **XML**
5. Upload file vào tool (nút "Choose File" trên UI)

**✅ Ưu điểm Burp Suite:**
- ⚡ **ĐÃ CÓ SẴN** traffic từ lúc test
- 🔐 Có **JWT tokens, cookies** đầy đủ
- 🎯 Thấy **requests giữa các microservices**
- 🚀 Không cần browse lại từ đầu

**📖 Chi tiết:** [BURP_SUITE_GUIDE.md](../BURP_SUITE_GUIDE.md)

---

#### 🌐 Option 2B: Chrome DevTools HAR

**Bước người dùng làm:**
1. Mở Chrome → **F12** (DevTools) → Tab **Network**
2. Browse trang web như bình thường:
   - Login với tài khoản
   - Click các button
   - Submit form
   - Thực hiện các action như user thật
3. Chuột phải vào Network tab → **"Save all as HAR with content"**
4. Upload file HAR vào tool

---

**Tool tự động (cả 2 options):**
- Parse file (auto-detect Burp/HAR)
- Extract TẤT CẢ requests (kể cả có JWT token)
- Fuzz các parameters với auth headers
- Test SSRF với credentials thật

**✅ Ưu điểm chung:** 
- Thấy 100% traffic thực tế
- Có sẵn JWT token và cookies
- Test được endpoints sau login
- Đơn giản, chỉ mất 2-5 phút

**🎯 Phù hợp:** Authenticated apps, microservices, real-world testing

---

### ⚡ **Cách 3: Proxy Mode** (Nâng cao)
**Tool capture real-time như Burp Suite**

**Bước người dùng làm:**
1. Config Chrome proxy:
   - Settings → Search "proxy"
   - Manual proxy: `localhost:8080`
2. Browse trang web như bình thường
3. Tool capture mọi request real-time

**✅ Ưu điểm:** 
- Capture real-time
- Giống Burp Suite
- Tự động liên tục

**❌ Nhược điểm:**
- Phức tạp (cần config proxy)
- HTTPS cần install certificate
- Port conflict trên Windows

**🎯 Phù hợp:** Professional pentesting, continuous monitoring

---

## 📊 So Sánh 3 Cách

| Tiêu chí | Cách 1: Auto | Cách 2: HAR | Cách 3: Proxy |
|----------|--------------|-------------|---------------|
| **Người dùng làm** | Chỉ nhập URL | Export HAR | Config proxy |
| **Phát hiện endpoint** | 50% | 100% ⭐ | 100% ⭐ |
| **Có JWT token** | ❌ | ✅ | ✅ |
| **Độ khó** | Rất dễ ⭐ | Dễ ⭐⭐ | Khó ⭐⭐⭐⭐ |
| **Thời gian setup** | 0 phút | 5 phút | 15+ phút |

**💡 Khuyến nghị:** Dùng **Cách 2 (HAR Import)** cho kết quả tốt nhất với effort thấp

---

## ✨ Features

### 🎯 Dashboard Chính
- **Real-time scanning progress** với progress bar
- **Live console output** hiển thị logs trực tiếp
- **Statistics dashboard** với số lượng findings theo severity
- **Responsive design** cho mobile và desktop

### 🔧 Scan Configuration
- **4 Testing Modes:**
  - Black Box: External testing only
  - Gray Box: With Docker access
  - White Box: Source code analysis
  - Full Scan: All modes combined

- **Configurable Options:**
  - Target URL
  - Source code path
  - Timeout settings
  - Enable/disable specific modules

### 📊 Findings Panel
- **Real-time findings display**
- **Filter by severity:** All, Critical, High, Medium, Low
- **Color-coded alerts**
- **Timestamp tracking**

### 📝 Console Output
- **Live logs** với color coding theo level
- **Timestamp** cho mỗi log entry
- **Clear console** button
- **Auto-scroll** đến log mới nhất

### 📥 Export Reports
- **JSON format** với tất cả findings và logs
- **One-click download**
- **Timestamped filenames**

---

## 🎨 UI Components

### Status Badge
- 🟢 **Ready**: Sẵn sàng scan
- 🟡 **Scanning**: Đang chạy scan

### Progress Tracking
- **Phase indicator**: Hiển thị phase hiện tại (Discovery, Fuzzing, etc.)
- **Progress bar**: Visual progress 0-100%
- **Elapsed time**: Thời gian đã chạy
- **Findings counter**: Tổng số lỗ hổng tìm được

### Findings Display
- **Severity badges:**
  - 🔴 CRITICAL
  - 🟠 HIGH
  - 🟡 MEDIUM
  - 🟢 LOW
- **Filter buttons** để lọc theo severity
- **Timestamp** cho mỗi finding

---

## 🔌 API Endpoints

### Start Scan
```
POST /api/scan/start
Body: {
  "mode": "blackbox",
  "target": "http://localhost:8083",
  "timeout": 10,
  "endpoint_discovery": true,
  ...
}
```

### Stop Scan
```
POST /api/scan/stop
```

### Get Status
```
GET /api/scan/status
Response: {
  "is_running": true,
  "current_phase": "Parameter Fuzzing",
  "progress": 45,
  "findings_count": 5
}
```

### Get Findings
```
GET /api/findings
Response: [
  {
    "severity": "CRITICAL",
    "message": "SSRF detected...",
    "timestamp": "2025-10-11T..."
  }
]
```

### Export Report
```
POST /api/report/export
Body: { "format": "json" }
Response: File download
```

---

## ⚡ WebSocket Events

### Server → Client

#### `connected`
```javascript
{
  "message": "Connected to SSRF Pentest Toolkit"
}
```

#### `log`
```javascript
{
  "timestamp": "12:34:56",
  "level": "info",        // info, warning, error, finding
  "message": "Phase 1: Endpoint Discovery",
  "severity": "HIGH"      // Only for findings
}
```

#### `progress`
```javascript
{
  "phase": "Parameter Fuzzing",
  "progress": 45
}
```

---

## 🎮 Keyboard Shortcuts

- **Ctrl/Cmd + Enter**: Start scan
- **Escape**: Stop scan

---

## 🎨 Dark Theme

Interface sử dụng dark theme với:
- **Primary Color**: Blue (#2563eb)
- **Critical**: Red (#dc2626)
- **High**: Orange (#ea580c)
- **Medium**: Yellow (#f59e0b)
- **Low**: Green (#84cc16)

---

## 📱 Responsive Design

- **Desktop**: Full dashboard với sidebar
- **Tablet**: Stacked layout
- **Mobile**: Single column với collapsed panels

---

## 🔧 Customization

### Thay đổi Port
Edit `app.py`:
```python
socketio.run(app, host='0.0.0.0', port=5000)  # Change port here
```

### Thay đổi Theme Colors
Edit `static/css/style.css`:
```css
:root {
    --primary-color: #2563eb;  /* Change colors here */
    --bg-dark: #0f172a;
    ...
}
```

### Thêm Custom Modules
Edit `app.py` để thêm modules mới vào scan pipeline:
```python
def run_blackbox(config, db):
    # Add your custom module here
    your_custom_module.scan()
```

---

## 🐛 Troubleshooting

### Port Already in Use
```bash
# Find and kill process using port 5000
netstat -ano | findstr :5000
taskkill /PID <PID> /F
```

### WebSocket Connection Failed
- Check if firewall blocking port 5000
- Try accessing via `127.0.0.1:5000` instead of `localhost:5000`

### Flask Not Found
```bash
pip install --upgrade -r requirements.txt
```

---

## 📝 Development Mode

Run với auto-reload:
```bash
# Already enabled in app.py
socketio.run(app, debug=True)
```

---

## 🚀 Production Deployment

### Using Gunicorn
```bash
pip install gunicorn eventlet
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

### Using Docker
```bash
# Coming soon...
```

---

## 📄 License

Part of Microservice SSRF Pentest Toolkit

---

## 🙏 Credits

Built with:
- Flask
- Socket.IO
- Font Awesome
- Modern CSS3

---

**Enjoy your beautiful Web UI! 🎉**
