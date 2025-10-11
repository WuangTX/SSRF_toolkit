# 📚 HƯỚNG DẪN SỬ DỤNG CHI TIẾT

## 🎯 **TỔNG QUAN WORKFLOW**

```
┌─────────────────────────────────────────────────────────────┐
│                    PENTEST WORKFLOW                          │
└─────────────────────────────────────────────────────────────┘

1. BLACK BOX (Không biết gì)
   ├── Reconnaissance → Tìm endpoints và parameters
   ├── Detection → Confirm SSRF với callback
   ├── Exploitation → Scan internal network
   └── Report → Findings + Attack scenarios
   
2. GRAY BOX (Có architecture info)
   ├── Architecture Analysis → Docker/K8s topology
   ├── Network Mapping → Service discovery
   ├── Targeted Testing → API endpoints
   └── Report → Attack paths + Remediation
   
3. WHITE BOX (Có source code)
   ├── Static Analysis → Code scanning
   ├── Data Flow Analysis → Track user input
   ├── Dependency Check → CVE scanning
   └── Report → Exact vulnerable code + Fixes
```

---

## 🕶️ **BLACK BOX MODE - STEP BY STEP**

### **Bước 1: Chuẩn bị**

```bash
# Tạo thư mục output
mkdir -p reports

# Check target accessibility
curl -I http://localhost:8083/inventory/1/M
```

### **Bước 2: Quick Scan**

```bash
# Scan nhanh với default config
python cli.py --mode blackbox --target http://localhost:8083/inventory/1/M
```

**Output mong đợi:**
```
╔════════════════════════════════════════════════════════════╗
║         🎯 MICROSERVICE SSRF PENTEST TOOLKIT               ║
╚════════════════════════════════════════════════════════════╝

────────────────────────────────────────────────────────────
📋 🕶️  BLACK BOX TESTING MODE
────────────────────────────────────────────────────────────

📡 Phase 1: Endpoint Discovery
[*] Testing 50 paths...
[*] Progress: 10/50
[*] Progress: 20/50
...
[+] Discovered 12 endpoints

🔍 Phase 2: Parameter Fuzzing
[*] Fuzzing http://localhost:8083/inventory/1/M with 45 parameters...
[+] Found parameter: callback_url
⚠️  [HIGH] Potential SSRF parameter: callback_url (confidence: 0.85)

🌐 Phase 3: External Callback Testing
[+] Callback server started on 0.0.0.0:8888
[*] Testing SSRF on http://localhost:8083/inventory/1/M
[*] Callback URL: http://localhost:8888/ssrf-test-abc123
[*] Waiting for callback...
[+] SSRF CONFIRMED! Received 1 callback(s)
    From: 172.18.0.4:42356
    Method: GET /ssrf-test-abc123
    User-Agent: python-requests/2.31.0

🔥 [CRITICAL] CONFIRMED SSRF: callback_url

🔬 Phase 4: Internal Network Scanning
[*] Discovering internal services...
[*] Scanning 172.18.0.2 for 15 ports...
[+] 172.18.0.2:8081 - HTTP-Service OPEN
[+] Found 3 internal services

📊 GENERATING REPORT
Total Findings: 5
By Severity: {'CRITICAL': 1, 'HIGH': 2, 'MEDIUM': 2}
✅ Report saved to: reports/pentest_report_20251008_143000.json

╔════════════════════════════════════════════════════════════╗
║          ✅ SCAN COMPLETED IN 145.23 seconds               ║
╚════════════════════════════════════════════════════════════╝
```

### **Bước 3: Advanced Scan với Custom Config**

```bash
# Tạo config file
cat > my_config.json << 'EOF'
{
  "mode": "blackbox",
  "blackbox": {
    "target_url": "http://localhost:8083/inventory/1/M",
    "timeout": 15,
    "threads": 10,
    "external_callback_test": true,
    "internal_scan": true,
    "max_scan_ports": 100
  }
}
EOF

# Run với config
python cli.py --config my_config.json
```

### **Bước 4: Analyze Results**

```bash
# Xem findings trong database
python -c "
from core.database import FindingDatabase
db = FindingDatabase('reports/findings.db')
findings = db.get_findings(severity='CRITICAL')
for f in findings:
    print(f'{f.severity}: {f.title}')
"

# Export to JSON
python -c "
from core.database import FindingDatabase
db = FindingDatabase('reports/findings.db')
db.export_json('my_report.json')
"
```

---

## 🔍 **GRAY BOX MODE - STEP BY STEP**

### **Bước 1: Verify Docker Access**

```bash
# Check Docker daemon
docker ps

# Check networks
docker network ls

# Check running containers
docker-compose ps
```

### **Bước 2: Run Docker Inspection**

```bash
python cli.py --mode graybox --docker --target http://localhost:8083
```

**Output:**
```
────────────────────────────────────────────────────────────
📋 🔍 GRAY BOX TESTING MODE
────────────────────────────────────────────────────────────

🐳 Docker Environment Analysis

════════════════════════════════════════════════════════════
DOCKER NETWORK TOPOLOGY
════════════════════════════════════════════════════════════

📡 Network: microservice_lab_default
   Subnet: 172.18.0.0/16
   Gateway: 172.18.0.1
   Containers:
      • user-service (172.18.0.2)
      • product-service (172.18.0.3)
      • inventory-service (172.18.0.4)
      • postgres-user (172.18.0.5)
      • postgres-product (172.18.0.6)

════════════════════════════════════════════════════════════

⚠️  Found 8 potential SSRF attack paths:
1. SSRF from inventory-service to user-service (172.18.0.2)
2. SSRF from inventory-service to product-service (172.18.0.3)
3. SSRF from inventory-service to postgres-user (172.18.0.5)
...

[+] Exported to reports/docker_inspection.json
```

### **Bước 3: Analyze Attack Paths**

```python
# Script để analyze attack paths
from graybox.architecture.docker_inspector import DockerInspector
import json

inspector = DockerInspector()
targets = inspector.find_ssrf_targets()

# Group by entry point
by_entry = {}
for target in targets:
    entry = target['entry_point']['name']
    if entry not in by_entry:
        by_entry[entry] = []
    by_entry[entry].append(target['target'])

# Print summary
for entry, targets in by_entry.items():
    print(f"\n{entry} can attack:")
    for t in targets:
        print(f"  → {t['name']} ({t['ip']})")
```

### **Bước 4: Test Attack Paths**

```bash
# Test specific attack path
curl "http://localhost:8083/inventory/1/M?callback_url=http://user-service:8081/api/users"

# Monitor logs
docker-compose logs -f user-service | grep "request from"
```

---

## 📖 **WHITE BOX MODE - STEP BY STEP**

### **Bước 1: Prepare Source Code**

```bash
# Clone hoặc cd vào project
cd /path/to/microservice_lab

# Verify structure
ls -la
# Expected: user-service/, product-service/, inventory-service/, frontend/
```

### **Bước 2: Run Code Scan**

```bash
python cli.py --mode whitebox --source-path . --output reports
```

**Output:**
```
────────────────────────────────────────────────────────────
📋 📖 WHITE BOX TESTING MODE
────────────────────────────────────────────────────────────

🔍 Static Code Analysis
[*] Scanning .
[*] Found 47 files to scan

[!] inventory-service/app.py:31
    callback_url = request.args.get('callback_url')
🔥 [CRITICAL] SSRF: Using user input without validation

[!] inventory-service/app.py:40
    response = requests.delete(callback_url)
🔥 [CRITICAL] Potential SSRF: requests.delete with user input

✅ Found 3 potential vulnerabilities

[+] Exported report to reports/code_scan_report.md
```

### **Bước 3: Review Code Scan Report**

```bash
cat reports/code_scan_report.md
```

**Example output:**
```markdown
# SSRF Static Analysis Report

## Summary
- Total Findings: 3
- By Severity: {'CRITICAL': 2, 'HIGH': 1}

## Findings

### 1. SSRF: Using user input variable "callback_url" in HTTP request
- **File**: `inventory-service/app.py`
- **Line**: 40
- **Severity**: CRITICAL
- **Code**: `response = requests.delete(callback_url)`
- **CWE**: CWE-918

**Remediation:**
```python
# BAD
callback_url = request.args.get('callback_url')
response = requests.delete(callback_url)

# GOOD
ALLOWED_HOSTS = ['user-service', 'product-service']
callback_url = request.args.get('callback_url')

# Validate URL
parsed = urlparse(callback_url)
if parsed.hostname not in ALLOWED_HOSTS:
    return jsonify({'error': 'Invalid callback URL'}), 400

response = requests.delete(callback_url)
```
```

### **Bước 4: Generate Fixes**

```python
# Script to generate automatic fixes
from whitebox.static_analysis.code_scanner import CodeScanner

scanner = CodeScanner(".")
findings = scanner.scan_directory()

for finding in findings:
    if finding['severity'] == 'CRITICAL':
        print(f"\n{'='*60}")
        print(f"File: {finding['file']}")
        print(f"Line: {finding['line']}")
        print(f"Vulnerable code: {finding['code']}")
        print(f"\nSuggested fix:")
        print(f"1. Add URL whitelist validation")
        print(f"2. Block private IP ranges (RFC1918)")
        print(f"3. Implement rate limiting")
```

---

## 🎯 **COMBINED MODE (ALL)**

### **Full Pentest Workflow**

```bash
# Step 1: Full scan
python cli.py --mode all \
  --target http://localhost:8083 \
  --source-path . \
  --docker \
  --output reports/full_scan

# Step 2: Analyze results
cd reports/full_scan
ls -la
# findings.db
# pentest_report_*.json
# docker_inspection.json
# code_scan_report.md
# *.log
```

### **Prioritize Findings**

```python
from core.database import FindingDatabase

db = FindingDatabase('reports/full_scan/findings.db')

# Get all CRITICAL findings
critical = db.get_findings(severity='CRITICAL')

print(f"CRITICAL vulnerabilities: {len(critical)}")
for f in critical:
    print(f"  [{f.mode}] {f.title}")
    print(f"      {f.affected_url}")

# Statistics
stats = db.get_statistics()
print(f"\nTotal findings: {stats['total']}")
print(f"By mode: {stats['by_mode']}")
print(f"By severity: {stats['by_severity']}")
```

---

## 🔧 **ADVANCED USAGE**

### **1. Custom Callback Server**

```python
from blackbox.detection.external_callback import CallbackServer, ExternalCallbackDetector

# Start server on custom port
server = CallbackServer(host='0.0.0.0', port=9999)
server.start()

# Use with ngrok for public URL
# Terminal 1: ngrok http 9999
# Terminal 2: Use ngrok URL in tests

detector = ExternalCallbackDetector(server)
result = detector.test_ssrf(
    "http://target.com/api",
    "callback_url"
)

print(f"Vulnerable: {result['is_vulnerable']}")
server.stop()
```

### **2. Batch Testing Multiple Targets**

```python
from blackbox.detection.external_callback import ExternalCallbackDetector

targets = [
    {'url': 'http://localhost:8083/inventory/1/M', 'parameter': 'callback_url'},
    {'url': 'http://localhost:8082/api/products', 'parameter': 'webhook_url'},
    {'url': 'http://localhost:8081/api/users', 'parameter': 'redirect_url'},
]

server = CallbackServer(host='0.0.0.0', port=8888)
server.start()

detector = ExternalCallbackDetector(server)
results = detector.bulk_test(targets)

print(f"\nResults:")
for r in results:
    status = "✅ VULNERABLE" if r['is_vulnerable'] else "❌ Not vulnerable"
    print(f"{status}: {r['url']} - {r['parameter']}")

server.stop()
```

### **3. Export to Different Formats**

```python
from core.database import FindingDatabase
import json
import csv

db = FindingDatabase('reports/findings.db')

# Export to JSON
db.export_json('report.json')

# Export to CSV
findings = db.get_findings()
with open('report.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Severity', 'Title', 'URL', 'CWE', 'CVSS'])
    
    for finding in findings:
        writer.writerow([
            finding.severity,
            finding.title,
            finding.affected_url,
            finding.cwe_id,
            finding.cvss_score
        ])
```

---

## 🎓 **BEST PRACTICES**

### **1. Khởi đầu với Black Box**
```bash
# Always start with reconnaissance
python cli.py --mode blackbox --target http://target.com --output phase1

# Analyze results
cat phase1/pentest_report_*.json | jq '.findings[] | select(.severity=="CRITICAL")'
```

### **2. Sau đó Gray Box (nếu có access)**
```bash
# Use Docker/K8s info to refine attacks
python cli.py --mode graybox --docker --output phase2

# Compare với Black Box findings
diff phase1/findings.db phase2/findings.db
```

### **3. Cuối cùng White Box (nếu có source)**
```bash
# Verify with code
python cli.py --mode whitebox --source-path . --output phase3

# Generate fix recommendations
python cli.py --mode whitebox --source-path . --generate-fixes
```

---

## 📊 **INTERPRETING RESULTS**

### **Severity Levels**

| Severity | CVSS | Meaning | Action |
|----------|------|---------|--------|
| **CRITICAL** | 9.0-10.0 | Confirmed SSRF, immediately exploitable | **Fix NOW** |
| **HIGH** | 7.0-8.9 | Probable SSRF, needs verification | Fix in 1-7 days |
| **MEDIUM** | 4.0-6.9 | Suspicious patterns, potential false positive | Investigate |
| **LOW** | 0.1-3.9 | Information disclosure, best practice | Nice to fix |

### **Confidence Scores (Black Box)**

| Confidence | Meaning |
|------------|---------|
| 0.8-1.0 | Very high confidence (external callback received) |
| 0.5-0.8 | High confidence (timing anomalies + error messages) |
| 0.3-0.5 | Medium confidence (suspicious responses) |
| 0.1-0.3 | Low confidence (worth investigating) |

---

## 🚨 **TROUBLESHOOTING**

### **Issue 1: "No Docker daemon"**
```bash
# Check Docker status
docker info

# Fix (Linux)
sudo systemctl start docker

# Fix (Windows)
# Start Docker Desktop
```

### **Issue 2: "Callback server port already in use"**
```bash
# Find process
netstat -ano | findstr :8888

# Kill process (Windows)
taskkill /PID <PID> /F

# Or use different port
python cli.py --mode blackbox --callback-port 9999
```

### **Issue 3: "No findings detected"**
```bash
# Enable verbose logging
python cli.py --mode blackbox --target http://target.com --log-level DEBUG

# Check logs
tail -f reports/*.log
```

---

**🎯 Chúc bạn pentest thành công!** 🚀
