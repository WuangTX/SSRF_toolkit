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
        callback_data = {
            'timestamp': datetime.now().isoformat(),
            'method': method,
            'path': self.path,
            'headers': dict(self.headers),
            'client_address': self.client_address[0],
            'client_port': self.client_address[1]
        }
        
        # Read body nếu có
        content_length = self.headers.get('Content-Length')
        if content_length:
            body = self.rfile.read(int(content_length))
            callback_data['body'] = body.decode('utf-8', errors='ignore')
        
        # Add to queue
        self.callback_queue.put(callback_data)
        
        # Send response
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'Callback received')
    
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
    
    def start(self):
        """Start callback server"""
        if self.is_running:
            return
        
        self.server = HTTPServer((self.host, self.port), CallbackHandler)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        self.is_running = True
        
        print(f"[+] Callback server started on {self.host}:{self.port}")
    
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
        """Clear callback queue"""
        while not CallbackHandler.callback_queue.empty():
            CallbackHandler.callback_queue.get()
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
            
            # Clear previous callbacks
            self.callback_server.clear_callbacks()
            
            # Send SSRF payload
            try:
                if method.upper() == 'GET':
                    test_url = f"{target_url}?{parameter}={callback_url}"
                    response = self.session.get(test_url, timeout=timeout)
                else:
                    response = self.session.post(
                        target_url,
                        data={parameter: callback_url},
                        timeout=timeout
                    )
                
                initial_response = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_length': len(response.content),
                    'response_time': response.elapsed.total_seconds()
                }
            except Exception as e:
                initial_response = {'error': str(e)}
            
            # Wait for callback
            callbacks = self.callback_server.get_callbacks(timeout=5)
            
            attempt = {
                'address': address,
                'callback_url': callback_url,
                'callbacks_received': len(callbacks),
                'callback_details': callbacks,
                'initial_response': initial_response
            }
            all_attempts.append(attempt)
            total_callbacks += len(callbacks)
            
            if len(callbacks) > 0:
                print(f"[+] ✅ SUCCESS! Received callback from {address}")
                # Found working address, no need to try others
                break
            else:
                print(f"[-] No callback received for {address}")
        
        # Analyze results
        is_vulnerable = total_callbacks > 0
        
        # Get successful attempt details
        successful_attempt = next((a for a in all_attempts if a['callbacks_received'] > 0), None)
        
        result = {
            'target_url': target_url,
            'parameter': parameter,
            'method': method,
            'is_vulnerable': is_vulnerable,
            'callbacks_received': total_callbacks,
            'all_attempts': all_attempts,
            'successful_address': successful_attempt['address'] if successful_attempt else None,
            'callback_url': successful_attempt['callback_url'] if successful_attempt else all_attempts[-1]['callback_url'],
            'callback_details': successful_attempt['callback_details'] if successful_attempt else [],
            'timestamp': datetime.now().isoformat()
        }
        
        if is_vulnerable:
            print(f"[+] SSRF CONFIRMED! Received {total_callbacks} callback(s)")
            if successful_attempt:
                for cb in successful_attempt['callback_details']:
                    print(f"    From: {cb['client_address']}:{cb['client_port']}")
                    print(f"    Method: {cb['method']} {cb['path']}")
                    print(f"    User-Agent: {cb['headers'].get('User-Agent', 'N/A')}")
        else:
            print(f"[-] No callback received (Not vulnerable or callback blocked)")
            print(f"    Tried addresses: {', '.join([a['address'] for a in all_attempts])}")
        
        self.test_results.append(result)
        return result
    
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
