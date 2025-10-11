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
