# 🏗️ ARCHITECTURE & DESIGN DOCUMENT

## 📋 **MỤC LỤC**

1. [Tổng quan kiến trúc](#tổng-quan-kiến-trúc)
2. [Design Principles](#design-principles)
3. [Từng module chi tiết](#từng-module-chi-tiết)
4. [Data Flow](#data-flow)
5. [Extension Points](#extension-points)

---

## 🎯 **TỔNG QUAN KIẾN TRÚC**

### **High-Level Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI Tool (cli.py)                     │
│  Entry point - Parse args, Load config, Orchestrate scan    │
└────────────────────────┬────────────────────────────────────┘
                         │
         ┌───────────────┼───────────────┐
         │               │               │
    ┌────▼────┐    ┌────▼────┐    ┌────▼────┐
    │ BLACK   │    │  GRAY   │    │  WHITE  │
    │  BOX    │    │   BOX   │    │   BOX   │
    │ MODULES │    │ MODULES │    │ MODULES │
    └────┬────┘    └────┬────┘    └────┬────┘
         │               │               │
         └───────────────┼───────────────┘
                         │
         ┌───────────────▼───────────────┐
         │         CORE MODULES           │
         │  • Logger   • Database         │
         │  • Config   • Reporter         │
         └────────────────────────────────┘
```

### **Layered Architecture**

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: USER INTERFACE                                      │
│  └─ CLI (Argparse, interactive prompts)                     │
├─────────────────────────────────────────────────────────────┤
│ Layer 4: ORCHESTRATION                                       │
│  └─ SSRFPentestToolkit (Main workflow controller)           │
├─────────────────────────────────────────────────────────────┤
│ Layer 3: BUSINESS LOGIC                                      │
│  ├─ BlackBox: Discovery → Detection → Exploitation          │
│  ├─ GrayBox: Architecture → Targeted Testing                │
│  └─ WhiteBox: Static Analysis → Dynamic Analysis            │
├─────────────────────────────────────────────────────────────┤
│ Layer 2: CORE SERVICES                                       │
│  ├─ Configuration Management (config.py)                    │
│  ├─ Logging System (logger.py)                              │
│  ├─ Database (database.py)                                  │
│  └─ Report Generator (reporter.py)                          │
├─────────────────────────────────────────────────────────────┤
│ Layer 1: UTILITIES                                           │
│  ├─ HTTP Client (requests wrapper)                          │
│  ├─ Callback Server (HTTP listener)                         │
│  └─ Payload Generator (SSRF payloads)                       │
└─────────────────────────────────────────────────────────────┘
```

---

## 💡 **DESIGN PRINCIPLES**

### **1. Modularity**
- Mỗi module độc lập, có thể sử dụng riêng lẻ
- Clear interfaces giữa các modules
- Dễ dàng thêm/bớt modules

**Example:**
```python
# Có thể dùng độc lập
from blackbox.detection.external_callback import CallbackServer

server = CallbackServer()
server.start()
# Use server...
server.stop()
```

### **2. Separation of Concerns**
- **Black Box**: Không cần biết internal structure
- **Gray Box**: Cần architecture info, không cần code
- **White Box**: Cần source code, phân tích tĩnh

### **3. Progressive Enhancement**
```
Black Box (Basic)
    ↓
Gray Box (Add architecture knowledge)
    ↓
White Box (Add source code analysis)
    ↓
Full Coverage (100% vulnerability detection)
```

### **4. Data-Driven**
- Tất cả findings lưu vào SQLite database
- Standardized Finding structure
- Multiple export formats (JSON, CSV, PDF)

### **5. Extensibility**
- Easy to add new scanners
- Plugin architecture (planned)
- Custom payload support

---

## 🔧 **TỪNG MODULE CHI TIẾT**

### **1. CORE MODULES**

#### **config.py - Configuration Management**

```python
# Design: Hierarchical config với dataclasses
@dataclass
class BlackBoxConfig:
    target_url: str
    timeout: int = 10
    # ... other params

@dataclass
class ToolkitConfig:
    mode: str
    blackbox: Optional[BlackBoxConfig]
    graybox: Optional[GrayBoxConfig]
    whitebox: Optional[WhiteBoxConfig]
```

**Benefits:**
- ✅ Type safety với dataclasses
- ✅ Easy to serialize/deserialize (JSON)
- ✅ Default values
- ✅ Validation

#### **logger.py - Logging System**

```python
# Design: Custom logger với màu sắc
class PentestLogger:
    def finding(self, severity, message):
        # Color-coded output
        # Icons for each severity
        # Both console and file output
```

**Features:**
- ✅ Colored console output (ANSI codes)
- ✅ File logging (plain text)
- ✅ Progress bars
- ✅ Section headers
- ✅ Severity-based icons

#### **database.py - Finding Storage**

```python
# Design: SQLite với ORM-like interface
@dataclass
class Finding:
    severity: str
    category: str
    title: str
    # ... other fields

class FindingDatabase:
    def add_finding(self, finding: Finding)
    def get_findings(self, filters...)
    def export_json(self, output_file)
```

**Schema:**
```sql
CREATE TABLE findings (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    mode TEXT,
    severity TEXT,
    category TEXT,
    title TEXT,
    description TEXT,
    affected_url TEXT,
    proof_of_concept TEXT,
    remediation TEXT,
    cvss_score REAL,
    cwe_id TEXT
);

CREATE TABLE scan_sessions (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    mode TEXT,
    target_url TEXT,
    duration_seconds REAL,
    findings_count INTEGER
);
```

---

### **2. BLACK BOX MODULES**

#### **Architecture Overview**

```
BLACK BOX WORKFLOW:

Phase 1: RECONNAISSANCE
├─ endpoint_discovery.py
│  ├─ Wordlist fuzzing
│  ├─ robots.txt parsing
│  ├─ Sitemap parsing
│  └─ Spider (crawl)
│
└─ parameter_fuzzer.py
   ├─ Test SSRF-prone params
   ├─ Analyze responses
   └─ Calculate confidence

Phase 2: DETECTION
├─ external_callback.py
│  ├─ Start callback server
│  ├─ Send SSRF payloads
│  └─ Wait for callbacks
│
├─ time_based.py
│  ├─ Test with slow DNS
│  └─ Measure response time
│
└─ error_based.py
   └─ Analyze error messages

Phase 3: EXPLOITATION
├─ internal_scan.py
│  ├─ Port scanning via SSRF
│  ├─ Service fingerprinting
│  └─ Network mapping
│
└─ service_interaction.py
   ├─ Enumerate endpoints
   └─ Test authentication bypass
```

#### **parameter_fuzzer.py - Design Details**

```python
class ParameterFuzzer:
    # Predefined SSRF parameter names
    SSRF_PARAMETERS = [
        'url', 'uri', 'callback', 'webhook', ...
    ]
    
    # Test payloads
    TEST_PAYLOADS = [
        'http://example.com',  # External HTTP
        'http://127.0.0.1',    # Localhost
        'file:///etc/passwd',  # File protocol
        ...
    ]
    
    def _calculate_confidence(self, findings):
        # Scoring system:
        # - Timeout = 0.3 points
        # - Error message = 0.25 points
        # - Connection error = 0.2 points
        # - Response diff = 0.15 points
        # Total = confidence score
```

**Confidence Algorithm:**
```
Confidence = Σ (indicator_weights) / total_tests

Where:
- Timeout: 30%
- Error messages: 25%
- Connection errors: 20%
- Response differences: 15%
- Payload reflected: 10%

Score > 0.5 = Likely vulnerable
Score > 0.8 = Very likely vulnerable
```

#### **external_callback.py - Design Details**

```python
# Multi-threaded HTTP server
class CallbackServer:
    def __init__(self, host, port):
        self.server = HTTPServer((host, port), CallbackHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
    
    def start(self):
        self.thread.start()
        # Non-blocking!
```

**Flow:**
```
1. Start server (non-blocking thread)
2. Generate unique callback URL (with UUID)
3. Send SSRF payload with callback URL
4. Wait for callback (timeout = 10s)
5. Analyze callback details
6. Return result
```

---

### **3. GRAY BOX MODULES**

#### **docker_inspector.py - Design Details**

```python
class DockerInspector:
    def __init__(self, docker_host):
        self.client = docker.DockerClient(base_url=docker_host)
    
    def get_networks(self):
        # Get all Docker networks
        # Parse IPAM config (subnets, gateways)
        # List containers in each network
    
    def find_ssrf_targets(self):
        # Algorithm:
        # 1. Find entry points (containers with exposed ports)
        # 2. Find internal services (no exposed ports)
        # 3. Check if in same network
        # 4. Generate attack scenarios
```

**Attack Path Discovery Algorithm:**
```python
for entry_point in containers_with_exposed_ports:
    for internal_service in containers_without_exposed_ports:
        if share_common_network(entry_point, internal_service):
            attack_path = {
                'from': entry_point,
                'to': internal_service,
                'via': 'SSRF',
                'risk': calculate_risk(entry_point, internal_service)
            }
            attack_paths.append(attack_path)
```

**Risk Calculation:**
```
Risk = Base_Score * Factors

Base Score:
- Database = 9.0 (critical)
- Admin service = 8.0 (high)
- Internal API = 7.0 (high)
- Monitoring = 5.0 (medium)

Factors:
- No authentication: +20%
- IP-based auth only: +15%
- Same network: +10%
- Exposed ports: +5%
```

---

### **4. WHITE BOX MODULES**

#### **code_scanner.py - Design Details**

```python
class CodeScanner:
    # Pattern matching
    DANGEROUS_FUNCTIONS = {
        'python': ['requests.get', 'urllib.request.urlopen', ...],
        'java': ['HttpURLConnection', 'RestTemplate', ...],
        'javascript': ['fetch', 'axios.get', ...]
    }
    
    def _scan_python(self, file_path, content):
        # Two-phase analysis:
        # 1. Regex pattern matching (fast)
        # 2. AST analysis (accurate)
```

**Static Analysis Phases:**

```
Phase 1: PATTERN MATCHING (Fast)
├─ Search for dangerous functions
├─ Check for user input sources
└─ Look for validation keywords

Phase 2: AST ANALYSIS (Accurate)
├─ Parse code to AST
├─ Track variable assignments
├─ Trace data flow
└─ Identify taint propagation

Phase 3: CONFIDENCE SCORING
├─ User input → Dangerous function = HIGH
├─ Validation present = Lower confidence
└─ Whitelist found = No vulnerability
```

**AST Visitor Pattern:**
```python
class SSRFVisitor(ast.NodeVisitor):
    def __init__(self):
        self.user_input_vars = set()
        self.dangerous_calls = []
    
    def visit_Assign(self, node):
        # Track: var = request.args.get('url')
        if is_user_input(node.value):
            self.user_input_vars.add(get_var_name(node))
    
    def visit_Call(self, node):
        # Check: requests.get(var)
        if is_dangerous_function(node) and uses_tainted_var(node):
            self.dangerous_calls.append(node)
```

---

## 📊 **DATA FLOW**

### **Finding Lifecycle**

```
1. DETECTION
   └─ Module detects vulnerability
      └─ Create Finding object

2. VALIDATION
   └─ Calculate confidence/severity
      └─ Add context (PoC, remediation)

3. STORAGE
   └─ Save to SQLite database
      └─ Associate with scan session

4. AGGREGATION
   └─ Group by severity, category
      └─ Calculate statistics

5. EXPORT
   └─ Generate reports (JSON, HTML, PDF)
      └─ Send to user
```

### **Scan Session Flow**

```
START
  ├─ Create session in DB (get session_id)
  ├─ Load configuration
  ├─ Initialize logger
  │
  ├─ RUN SCANS
  │   ├─ Black Box modules
  │   ├─ Gray Box modules
  │   └─ White Box modules
  │
  ├─ Each finding → Database
  │
  ├─ GENERATE REPORT
  │   ├─ Query all findings
  │   ├─ Calculate statistics
  │   └─ Export to formats
  │
  └─ Update session (duration, findings_count)
END
```

---

## 🔌 **EXTENSION POINTS**

### **1. Adding New Scanner**

```python
# Step 1: Create scanner class
class MyCustomScanner:
    def __init__(self, config):
        self.config = config
    
    def scan(self) -> List[Dict]:
        findings = []
        # Scan logic here
        return findings

# Step 2: Register in CLI
def _run_blackbox(self):
    # Add your scanner
    from blackbox.custom.my_scanner import MyCustomScanner
    
    scanner = MyCustomScanner(self.config)
    results = scanner.scan()
    
    # Process results
    for result in results:
        finding = Finding(...)
        self.db.add_finding(finding)
```

### **2. Adding New Payload Type**

```python
# utils/payload_generator.py
class PayloadGenerator:
    @staticmethod
    def get_ssrf_payloads(category: str) -> List[str]:
        payloads = {
            'cloud_metadata': [
                'http://169.254.169.254/latest/meta-data/',  # AWS
                'http://metadata.google.internal/',          # GCP
                ...
            ],
            'localhost': [
                'http://localhost',
                'http://127.0.0.1',
                ...
            ],
            # Add your custom category
            'custom_category': [
                'http://custom-payload.com',
                ...
            ]
        }
        return payloads.get(category, [])
```

### **3. Adding New Report Format**

```python
# core/reporter.py
class Reporter:
    def export_pdf(self, findings, output_file):
        # Generate PDF report
        pass
    
    def export_html(self, findings, output_file):
        # Generate HTML report
        pass
    
    # Add your custom format
    def export_markdown(self, findings, output_file):
        # Generate Markdown report
        pass
```

---

## 🎯 **PERFORMANCE CONSIDERATIONS**

### **1. Multi-threading**

```python
# Endpoint discovery uses ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=self.threads) as executor:
    futures = [executor.submit(self._test_path, path) for path in paths]
    
    for future in futures:
        result = future.result()
        # Process result
```

**Benefits:**
- ✅ Faster scanning (parallel requests)
- ✅ Configurable thread count
- ✅ Non-blocking operations

### **2. Timeouts**

```python
# All HTTP requests have timeout
response = requests.get(url, timeout=self.timeout)

# Prevents hanging on slow/dead endpoints
```

### **3. Database Indexing**

```sql
-- Index on frequently queried columns
CREATE INDEX idx_severity ON findings(severity);
CREATE INDEX idx_mode ON findings(mode);
CREATE INDEX idx_timestamp ON findings(timestamp);
```

### **4. Memory Management**

```python
# Stream large files instead of loading to memory
def scan_large_file(file_path):
    with open(file_path, 'r') as f:
        for line in f:  # Stream line by line
            process_line(line)
```

---

## 🔒 **SECURITY CONSIDERATIONS**

### **1. Callback Server Security**

```python
# Only listen on localhost by default
CallbackServer(host='127.0.0.1', port=8888)

# For public access, use authentication
# TODO: Add authentication mechanism
```

### **2. SQL Injection Prevention**

```python
# Use parameterized queries
cursor.execute('''
    INSERT INTO findings (title, description) VALUES (?, ?)
''', (title, description))

# Never use string formatting
# BAD: f"INSERT INTO findings VALUES ('{title}')"
```

### **3. Path Traversal Prevention**

```python
# Validate file paths
def read_config(config_file):
    config_path = Path(config_file).resolve()
    
    # Ensure within allowed directory
    if not config_path.is_relative_to(ALLOWED_DIR):
        raise ValueError("Invalid config path")
    
    with open(config_path) as f:
        return json.load(f)
```

---

## 📈 **FUTURE ENHANCEMENTS**

### **Planned Features**

1. **GUI Interface**
   - Web-based dashboard
   - Real-time scan progress
   - Interactive reports

2. **Cloud Integration**
   - AWS metadata exploitation
   - GCP metadata exploitation
   - Azure metadata exploitation

3. **AI-Powered Detection**
   - ML models for false positive reduction
   - Anomaly detection
   - Automated exploit generation

4. **Distributed Scanning**
   - Master-slave architecture
   - Scan large networks faster
   - Load balancing

5. **Plugin System**
   - Community plugins
   - Custom scanners
   - Integration with other tools

---

**🎯 Architecture complete!** Toolkit is designed for **scalability**, **maintainability**, and **extensibility**. 🚀
