"""
HTTP Proxy Interceptor
Captures HTTP/HTTPS traffic like Burp Suite to discover real endpoints
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, urlunparse
import threading
import requests
import json
from typing import List, Dict, Set
from datetime import datetime


class ProxyRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for proxy"""
    
    # Shared storage for captured requests
    captured_requests = []
    captured_endpoints = set()
    
    def do_GET(self):
        self._handle_request('GET')
    
    def do_POST(self):
        self._handle_request('POST')
    
    def do_PUT(self):
        self._handle_request('PUT')
    
    def do_DELETE(self):
        self._handle_request('DELETE')
    
    def do_OPTIONS(self):
        """Handle CORS preflight"""
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()
    
    def _handle_request(self, method: str):
        """Handle any HTTP method"""
        try:
            # Parse request
            parsed = urlparse(self.path)
            
            # Reconstruct target URL
            if self.path.startswith('http://') or self.path.startswith('https://'):
                target_url = self.path
            else:
                # Relative URL, need to get host from headers
                host = self.headers.get('Host', 'localhost')
                scheme = 'https' if self.command == 'CONNECT' else 'http'
                target_url = f"{scheme}://{host}{self.path}"
            
            # Get request headers
            headers = dict(self.headers)
            
            # Remove hop-by-hop headers
            hop_headers = ['connection', 'keep-alive', 'proxy-authenticate', 
                          'proxy-authorization', 'te', 'trailers', 
                          'transfer-encoding', 'upgrade']
            for h in hop_headers:
                headers.pop(h, None)
            
            # Read request body if present
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None
            
            # Capture request details
            request_data = {
                'timestamp': datetime.now().isoformat(),
                'method': method,
                'url': target_url,
                'path': parsed.path,
                'query': parsed.query,
                'headers': dict(headers),
                'body': body.decode('utf-8', errors='ignore') if body else None
            }
            
            # Store for analysis
            self.captured_requests.append(request_data)
            self.captured_endpoints.add(f"{method} {target_url}")
            
            print(f"[PROXY] {method} {target_url}")
            
            # Forward request to actual server
            response = requests.request(
                method=method,
                url=target_url,
                headers=headers,
                data=body,
                allow_redirects=False,
                verify=False,
                timeout=10
            )
            
            # Send response back to client
            self.send_response(response.status_code)
            
            # Copy response headers
            for header, value in response.headers.items():
                if header.lower() not in hop_headers:
                    self.send_header(header, value)
            
            # Add CORS headers for browser compatibility
            self._send_cors_headers()
            
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            print(f"[PROXY ERROR] {str(e)}")
            self.send_error(500, f"Proxy Error: {str(e)}")
    
    def _send_cors_headers(self):
        """Send CORS headers to allow cross-origin requests"""
        origin = self.headers.get('Origin', '*')
        self.send_header('Access-Control-Allow-Origin', origin)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        self.send_header('Access-Control-Allow-Credentials', 'true')
    
    def log_message(self, format, *args):
        """Suppress default logging"""
        pass


class ProxyInterceptor:
    """HTTP Proxy to intercept and analyze traffic"""
    
    def __init__(self, host: str = '127.0.0.1', port: int = 8080):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.is_running = False
    
    def start(self):
        """Start proxy server"""
        if self.is_running:
            return
        
        self.server = HTTPServer((self.host, self.port), ProxyRequestHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.is_running = True
        
        print(f"[+] Proxy server started on {self.host}:{self.port}")
        print(f"[+] Configure your browser to use proxy: {self.host}:{self.port}")
    
    def stop(self):
        """Stop proxy server"""
        if self.server:
            self.server.shutdown()
            self.is_running = False
            print("[+] Proxy server stopped")
    
    def get_captured_requests(self) -> List[Dict]:
        """Get all captured requests"""
        return ProxyRequestHandler.captured_requests.copy()
    
    def get_captured_endpoints(self) -> Set[str]:
        """Get unique endpoints captured"""
        return ProxyRequestHandler.captured_endpoints.copy()
    
    def clear_captured(self):
        """Clear captured data"""
        ProxyRequestHandler.captured_requests.clear()
        ProxyRequestHandler.captured_endpoints.clear()
    
    def export_har(self, filepath: str):
        """Export captured traffic as HAR file"""
        har = {
            'log': {
                'version': '1.2',
                'creator': {
                    'name': 'SSRF Pentest Toolkit',
                    'version': '1.0'
                },
                'entries': []
            }
        }
        
        for req in self.get_captured_requests():
            entry = {
                'startedDateTime': req['timestamp'],
                'request': {
                    'method': req['method'],
                    'url': req['url'],
                    'headers': [{'name': k, 'value': v} for k, v in req['headers'].items()],
                    'queryString': req['query'] or '',
                    'postData': {
                        'text': req['body'] or ''
                    } if req['body'] else {}
                }
            }
            har['log']['entries'].append(entry)
        
        with open(filepath, 'w') as f:
            json.dump(har, f, indent=2)
        
        print(f"[+] Exported {len(har['log']['entries'])} requests to {filepath}")
    
    def analyze_for_ssrf(self) -> List[Dict]:
        """Analyze captured requests for potential SSRF parameters"""
        ssrf_candidates = []
        
        for req in self.get_captured_requests():
            # Check query parameters
            if req['query']:
                params = req['query'].split('&')
                for param in params:
                    if '=' in param:
                        key, value = param.split('=', 1)
                        # Check if parameter name suggests URL/SSRF
                        if any(keyword in key.lower() for keyword in 
                              ['url', 'uri', 'callback', 'webhook', 'redirect', 'link']):
                            ssrf_candidates.append({
                                'endpoint': req['url'],
                                'method': req['method'],
                                'parameter': key,
                                'current_value': value,
                                'reason': 'Parameter name suggests URL input'
                            })
            
            # Check POST body for JSON with URL-like fields
            if req['body'] and req['method'] == 'POST':
                try:
                    body_json = json.loads(req['body'])
                    if isinstance(body_json, dict):
                        for key, value in body_json.items():
                            if any(keyword in key.lower() for keyword in 
                                  ['url', 'uri', 'callback', 'webhook']):
                                ssrf_candidates.append({
                                    'endpoint': req['url'],
                                    'method': 'POST',
                                    'parameter': key,
                                    'current_value': value,
                                    'reason': 'JSON field name suggests URL input'
                                })
                except:
                    pass
        
        return ssrf_candidates


if __name__ == '__main__':
    """Test proxy"""
    proxy = ProxyInterceptor(host='127.0.0.1', port=8080)
    
    print("Starting HTTP Proxy Interceptor...")
    print("Configure your browser:")
    print("  1. Open browser settings")
    print("  2. Set HTTP Proxy: 127.0.0.1:8080")
    print("  3. Browse the target application")
    print("  4. Press Ctrl+C to stop and analyze")
    print()
    
    proxy.start()
    
    try:
        input("Press Enter to view captured requests...")
    except KeyboardInterrupt:
        pass
    
    print("\n[+] Captured Endpoints:")
    for endpoint in proxy.get_captured_endpoints():
        print(f"  {endpoint}")
    
    print(f"\n[+] Total requests captured: {len(proxy.get_captured_requests())}")
    
    # Analyze for SSRF
    candidates = proxy.analyze_for_ssrf()
    if candidates:
        print(f"\n[!] Potential SSRF parameters found: {len(candidates)}")
        for c in candidates:
            print(f"  [{c['method']}] {c['endpoint']}")
            print(f"    Parameter: {c['parameter']} = {c['current_value']}")
            print(f"    Reason: {c['reason']}")
    
    proxy.stop()
