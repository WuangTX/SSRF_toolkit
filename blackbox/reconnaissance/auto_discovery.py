"""
Auto Discovery & SSRF Detection
Tự động crawl, discover endpoints và test SSRF
User chỉ cần nhập domain!
"""

import requests
import re
import time
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, quote, unquote
from bs4 import BeautifulSoup
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class AutoDiscovery:
    """
    Tự động discover và test SSRF vulnerabilities
    Chỉ cần domain → Tool làm tất cả!
    """
    
    def __init__(self, base_url: str, timeout: int = 10, max_depth: int = 3):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_depth = max_depth
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        self.visited_urls = set()
        self.discovered_endpoints = set()
        self.discovered_parameters = {}  # {endpoint: [params]}
        
        # Parse base domain
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
    
    def run_full_discovery(self) -> Dict:
        """
        🎯 MAIN METHOD: Chạy toàn bộ discovery pipeline
        
        Returns:
            {
                'endpoints': [...],
                'parameters': {...},
                'forms': [...],
                'api_endpoints': [...],
                'testable_endpoints': [...]
            }
        """
        print(f"\n{'='*60}")
        print(f"🎯 AUTO-DISCOVERY: {self.base_url}")
        print(f"{'='*60}\n")
        
        results = {
            'endpoints': set(),
            'parameters': {},
            'forms': [],
            'api_endpoints': set(),
            'testable_endpoints': []
        }
        
        # Phase 1: Crawl website
        print("[1/5] 🕷️  Crawling website...")
        self._crawl_website(self.base_url, depth=0)
        results['endpoints'] = self.discovered_endpoints
        print(f"      ✓ Found {len(self.discovered_endpoints)} unique URLs")
        
        # Phase 2: Extract parameters
        print("\n[2/5] 🔍 Extracting parameters from URLs...")
        self._extract_parameters_from_urls()
        results['parameters'] = self.discovered_parameters
        param_count = sum(len(params) for params in self.discovered_parameters.values())
        print(f"      ✓ Found {param_count} parameters across {len(self.discovered_parameters)} endpoints")
        
        # Phase 3: Discover API endpoints
        print("\n[3/5] 🔌 Discovering API endpoints...")
        api_endpoints = self._discover_api_endpoints()
        results['api_endpoints'] = api_endpoints
        print(f"      ✓ Found {len(api_endpoints)} API endpoints")
        
        # Phase 4: Parse forms
        print("\n[4/5] 📝 Parsing forms...")
        forms = self._parse_all_forms()
        results['forms'] = forms
        print(f"      ✓ Found {len(forms)} forms")
        
        # Phase 5: Identify testable endpoints
        print("\n[5/5] 🎯 Identifying testable endpoints...")
        testable = self._identify_testable_endpoints(results)
        results['testable_endpoints'] = testable
        print(f"      ✓ {len(testable)} endpoints ready for SSRF testing")
        
        # Phase 6: SSRF Testing (NEW!)
        print("\n[6/6] 🔥 Testing for SSRF vulnerabilities...")
        ssrf_vulnerabilities = self._test_ssrf_vulnerabilities(testable)
        results['ssrf_vulnerabilities'] = ssrf_vulnerabilities
        print(f"      ✓ {len(ssrf_vulnerabilities)} SSRF vulnerabilities found!")
        
        return results
    
    def _crawl_website(self, url: str, depth: int = 0):
        """Crawl website và extract links"""
        if depth > self.max_depth:
            return
        
        if url in self.visited_urls:
            return
        
        # Check if same domain
        if not self._is_same_domain(url):
            return
        
        self.visited_urls.add(url)
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Add to discovered endpoints
            self.discovered_endpoints.add(url.split('?')[0])  # Remove query params
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Extract links
                links = soup.find_all('a', href=True)
                for link in links:
                    href = link['href']
                    full_url = urljoin(url, href)
                    
                    # Crawl recursively
                    if self._is_same_domain(full_url):
                        self._crawl_website(full_url, depth + 1)
                
                # Extract from scripts
                scripts = soup.find_all('script')
                for script in scripts:
                    if script.string:
                        api_urls = self._extract_urls_from_js(script.string)
                        for api_url in api_urls:
                            full_api_url = urljoin(url, api_url)
                            if self._is_same_domain(full_api_url):
                                self.discovered_endpoints.add(full_api_url.split('?')[0])
        
        except Exception as e:
            print(f"      ⚠️  Error crawling {url}: {str(e)[:50]}")
    
    def _extract_urls_from_js(self, js_code: str) -> Set[str]:
        """Extract URLs from JavaScript code"""
        urls = set()
        
        # Patterns for API endpoints
        patterns = [
            r'["\']/(api|v[0-9]+)/[^"\']*["\']',  # /api/..., /v1/...
            r'["\']https?://[^"\']+["\']',         # Full URLs
            r'fetch\(["\']([^"\']+)["\']',         # fetch("...")
            r'ajax\(\s*{[^}]*url:\s*["\']([^"\']+)["\']',  # $.ajax({url: "..."})
            r'axios\.\w+\(["\']([^"\']+)["\']',    # axios.get("...")
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_code, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ''
                urls.add(match.strip('\'"'))
        
        return urls
    
    def _extract_parameters_from_urls(self):
        """Extract parameters từ discovered URLs"""
        for endpoint in self.discovered_endpoints:
            parsed = urlparse(endpoint)
            if parsed.query:
                params = parse_qs(parsed.query)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                if base_url not in self.discovered_parameters:
                    self.discovered_parameters[base_url] = set()
                
                for param_name in params.keys():
                    self.discovered_parameters[base_url].add(param_name)
    
    def _discover_api_endpoints(self) -> Set[str]:
        """Discover API endpoints bằng brute-force common paths"""
        api_endpoints = set()
        
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1',
            '/graphql',
            '/api/users', '/api/user',
            '/api/products', '/api/product',
            '/api/inventory', '/api/items',
            '/api/orders', '/api/order',
            '/api/customers', '/api/customer',
            '/api/auth', '/api/login',
            '/api/data', '/api/fetch',
            '/api/callback', '/api/webhook',
            '/api/proxy', '/api/redirect',
            '/api/image', '/api/file',
            '/api/download', '/api/upload',
            '/services', '/service',
            '/internal', '/admin/api'
        ]
        
        # SSRF-prone paths - paths likely to accept URLs
        ssrf_paths = [
            '/check_price', '/price_check', '/compare_price',
            '/fetch', '/proxy', '/callback', '/webhook',
            '/import', '/export', '/download',
            '/validate', '/verify', '/check',
            '/thumbnail', '/preview', '/image',
            '/api_call', '/external', '/remote'
        ]
        
        base_root = f"{self.base_scheme}://{self.base_domain}"
        
        print(f"      Testing {len(common_api_paths)} common API paths...")
        
        for path in common_api_paths:
            test_url = base_root + path
            try:
                response = self.session.get(test_url, timeout=5, allow_redirects=False)
                
                # Check if endpoint exists
                if response.status_code in [200, 201, 400, 401, 403, 405, 422, 500]:
                    api_endpoints.add(test_url)
                    print(f"      ✓ Found: {path} [{response.status_code}]")
                    
                    # For discovered API endpoints, try to find SSRF-prone sub-paths
                    self._discover_ssrf_endpoints(test_url, ssrf_paths, api_endpoints)
                    
            except:
                pass
        
        return api_endpoints
    
    def _discover_ssrf_endpoints(self, base_api: str, ssrf_paths: List[str], api_endpoints: Set[str]):
        """
        Discover SSRF-prone endpoints like /api/products/1/check_price/
        """
        # Try with common ID patterns
        id_patterns = ['1', '2', '5', '{id}']
        
        for id_val in id_patterns:
            for ssrf_path in ssrf_paths:
                # Pattern: /api/products/5/check_price/
                test_endpoint = f"{base_api}/{id_val}{ssrf_path}/"
                
                try:
                    # Test both GET and POST
                    get_response = self.session.get(test_endpoint, timeout=3, allow_redirects=False)
                    if get_response.status_code in [200, 400, 401, 403, 405, 422, 500]:
                        api_endpoints.add(test_endpoint)
                        print(f"      ✓ SSRF endpoint found: {test_endpoint} [GET:{get_response.status_code}]")
                    
                    # Test POST với JSON
                    post_response = self.session.post(
                        test_endpoint, 
                        json={"test": "value"},
                        timeout=3, 
                        allow_redirects=False
                    )
                    if post_response.status_code in [200, 400, 401, 403, 405, 422, 500]:
                        api_endpoints.add(test_endpoint)
                        print(f"      ✓ SSRF endpoint found: {test_endpoint} [POST:{post_response.status_code}]")
                        
                except:
                    pass
    
    def _parse_all_forms(self) -> List[Dict]:
        """Parse tất cả HTML forms"""
        forms = []
        
        for url in self.visited_urls:
            try:
                response = self.session.get(url, timeout=self.timeout)
                
                if 'text/html' in response.headers.get('Content-Type', ''):
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    for form in soup.find_all('form'):
                        form_data = {
                            'url': url,
                            'action': urljoin(url, form.get('action', '')),
                            'method': form.get('method', 'GET').upper(),
                            'inputs': []
                        }
                        
                        # Extract input fields
                        for input_tag in form.find_all(['input', 'textarea', 'select']):
                            input_data = {
                                'name': input_tag.get('name', ''),
                                'type': input_tag.get('type', 'text'),
                                'value': input_tag.get('value', '')
                            }
                            if input_data['name']:
                                form_data['inputs'].append(input_data)
                        
                        forms.append(form_data)
            except:
                pass
        
        return forms
    
    def _identify_testable_endpoints(self, results: Dict) -> List[Dict]:
        """
        Identify endpoints có khả năng vulnerable với SSRF
        
        Criteria:
        1. Có parameters với tên suspicious
        2. Accepts URL-like input
        3. API endpoints
        4. Forms với URL inputs
        """
        testable = []
        
        # Suspicious parameter names
        url_params = [
            'url', 'uri', 'path', 'link', 'href', 'src',
            'callback', 'callback_url', 'callbackUrl',
            'webhook', 'webhook_url', 'webhookUrl',
            'redirect', 'redirect_url', 'redirectUrl',
            'return_url', 'returnUrl', 'return_to',
            'target', 'target_url', 'targetUrl',
            'dest', 'destination',
            'fetch', 'load', 'import', 'download',
            'proxy', 'host', 'endpoint', 'service',
            'image', 'img', 'picture', 'avatar',
            'file', 'document', 'resource', 'source',
            'next', 'continue', 'goto'
        ]
        
        # Check parameters from URLs
        for endpoint, params in results['parameters'].items():
            for param in params:
                if any(keyword in param.lower() for keyword in url_params):
                    testable.append({
                        'type': 'url_parameter',
                        'endpoint': endpoint,
                        'parameter': param,
                        'method': 'GET',
                        'confidence': 0.7,
                        'reason': f'Parameter name "{param}" suggests URL handling'
                    })
        
        # Check API endpoints (ADD SYNTHETIC PARAMETERS FOR GET)
        common_ssrf_params = ['url', 'callback', 'webhook', 'redirect', 'target', 'src', 'endpoint']
        
        for api_endpoint in results['api_endpoints']:
            # Test GET với query parameters
            for param in common_ssrf_params:
                testable.append({
                    'type': 'api_endpoint_synthetic',
                    'endpoint': api_endpoint,
                    'parameter': param,
                    'method': 'GET',
                    'confidence': 0.6,
                    'reason': f'API endpoint with synthetic parameter "{param}"'
                })
            
            # Test POST với JSON body cho SSRF-prone endpoints
            endpoint_path = api_endpoint.lower()
            ssrf_indicators = [
                'check_price', 'price_check', 'compare_price', 'compare_url',
                'fetch', 'proxy', 'callback', 'webhook', 'import', 'export',
                'validate', 'verify', 'check', 'thumbnail', 'preview', 'image'
            ]
            
            if any(indicator in endpoint_path for indicator in ssrf_indicators):
                for param in ['url', 'compare_url', 'callback_url', 'webhook_url', 'target_url', 'src_url']:
                    testable.append({
                        'type': 'api_endpoint_json_post',
                        'endpoint': api_endpoint,
                        'parameter': param,
                        'method': 'POST',
                        'confidence': 0.8,
                        'reason': f'SSRF-prone endpoint "{api_endpoint}" with JSON parameter "{param}"'
                    })
        
        # Check forms
        for form in results['forms']:
            for input_field in form['inputs']:
                input_name = input_field['name'].lower()
                if any(keyword in input_name for keyword in url_params):
                    testable.append({
                        'type': 'form_input',
                        'endpoint': form['action'],
                        'parameter': input_field['name'],
                        'method': form['method'],
                        'confidence': 0.6,
                        'reason': f'Form input "{input_field["name"]}" suggests URL handling'
                    })
        
        return testable
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is same domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self.base_domain or parsed.netloc == ''
        except:
            return False
    
    def test_parameter_accepts_url(self, endpoint: str, parameter: str, method: str = 'GET') -> Dict:
        """
        Test xem parameter có accept URL input không
        
        Returns confidence score và indicators
        """
        print(f"\n   Testing: {parameter} at {endpoint}")
        
        indicators = []
        test_results = []
        
        # Test payloads
        test_urls = [
            'http://example.com',
            'https://httpbin.org/delay/2',  # Causes timeout
            'http://invalid-domain-12345.com',  # Invalid domain
            'http://localhost:8080'  # Internal
        ]
        
        # Baseline request (no parameter)
        try:
            if method == 'GET':
                baseline = self.session.get(endpoint, timeout=self.timeout)
            else:
                baseline = self.session.post(endpoint, timeout=self.timeout)
            
            baseline_status = baseline.status_code
            baseline_length = len(baseline.content)
            baseline_time = baseline.elapsed.total_seconds()
        except:
            return {'confidence': 0, 'indicators': ['baseline_failed']}
        
        # Test with each payload
        for test_url in test_urls:
            try:
                if method == 'GET':
                    url_with_param = f"{endpoint}?{parameter}={quote(test_url)}"
                    response = self.session.get(url_with_param, timeout=self.timeout + 5)
                else:
                    response = self.session.post(
                        endpoint,
                        data={parameter: test_url},
                        timeout=self.timeout + 5
                    )
                
                # Analyze response
                status_changed = response.status_code != baseline_status
                length_changed = abs(len(response.content) - baseline_length) > 100
                time_changed = abs(response.elapsed.total_seconds() - baseline_time) > 2
                
                result = {
                    'payload': test_url,
                    'status': response.status_code,
                    'status_changed': status_changed,
                    'length_changed': length_changed,
                    'time_changed': time_changed,
                    'time': response.elapsed.total_seconds()
                }
                
                test_results.append(result)
                
                if status_changed or length_changed or time_changed:
                    indicators.append(f'response_diff_{test_url.split("//")[1].split("/")[0]}')
                
                # Check for URL in response
                if test_url in response.text:
                    indicators.append('url_reflected')
                
                # Check for error messages
                error_keywords = ['timeout', 'connection', 'refused', 'unreachable', 'invalid url', 'malformed']
                response_lower = response.text.lower()
                for keyword in error_keywords:
                    if keyword in response_lower:
                        indicators.append(f'error_{keyword}')
                        break
            
            except requests.exceptions.Timeout:
                indicators.append('timeout')
                test_results.append({
                    'payload': test_url,
                    'status': 'TIMEOUT',
                    'time': self.timeout
                })
            
            except Exception as e:
                if 'connection' in str(e).lower():
                    indicators.append('connection_error')
        
        # Calculate confidence
        confidence = len(indicators) * 0.15
        confidence = min(confidence, 1.0)
        
        return {
            'confidence': confidence,
            'indicators': indicators,
            'test_results': test_results
        }

    def _test_ssrf_vulnerabilities(self, testable_endpoints: List[Dict]) -> List[Dict]:
        """
        🔥 SSRF VULNERABILITY TESTING
        Test each endpoint với callback server để confirm SSRF 100%
        """
        vulnerabilities = []
        
        if not testable_endpoints:
            return vulnerabilities
        
        # Start callback server
        from ..detection.external_callback import CallbackServer
        
        try:
            # Khởi tạo callback server
            callback_server = CallbackServer(port=9999)  # Avoid conflict với MCP Burp (8888)
            callback_url = callback_server.start()
            print(f"      📡 Callback server started: {callback_url}")
            
            # Test từng endpoint
            for i, target in enumerate(testable_endpoints[:10], 1):  # Limit 10 để không spam
                endpoint = target['endpoint']
                parameter = target['parameter']
                confidence = target['confidence']
                
                print(f"      🎯 [{i:2d}] Testing {endpoint} (param: {parameter})")
                
                # Generate unique callback URL
                test_id = f"ssrf_{i}_{int(time.time())}"
                test_callback_url = f"{callback_url}/{test_id}"
                
                vulnerability = self._test_single_ssrf(endpoint, parameter, test_callback_url, test_id, callback_server, target.get('method', 'GET'), target.get('type', 'unknown'))
                
                if vulnerability:
                    vulnerability['confidence'] = confidence
                    vulnerability['original_confidence'] = confidence
                    vulnerabilities.append(vulnerability)
                    print(f"         🔥 SSRF CONFIRMED! {endpoint}")
                else:
                    print(f"         ❌ No SSRF detected")
                
                # Rate limiting
                time.sleep(0.5)
            
            # Stop callback server
            callback_server.stop()
            print(f"      📡 Callback server stopped")
            
        except Exception as e:
            print(f"         ❌ Error in SSRF testing: {e}")
        
        return vulnerabilities

    def _test_single_ssrf(self, endpoint: str, parameter: str, callback_url: str, test_id: str, callback_server, method: str = 'GET', test_type: str = 'unknown') -> Optional[Dict]:
        """
        Test single endpoint for SSRF vulnerability
        Supports both GET (query params) and POST (JSON body)
        """
        try:
            # Clear any existing callbacks
            callback_server.clear_callbacks()
            
            start_time = time.time()
            
            # Choose request method based on test type
            if method.upper() == 'POST' and 'json' in test_type.lower():
                # POST with JSON body
                json_payload = {parameter: callback_url}
                response = self.session.post(
                    endpoint, 
                    json=json_payload, 
                    timeout=10, 
                    allow_redirects=True
                )
                payload_info = f"POST JSON: {json_payload}"
            else:
                # GET with query parameters  
                if '?' in endpoint:
                    test_url = f"{endpoint}&{parameter}={callback_url}"
                else:
                    test_url = f"{endpoint}?{parameter}={callback_url}"
                
                response = self.session.get(test_url, timeout=10, allow_redirects=True)
                payload_info = f"GET: {test_url}"
            
            request_time = time.time()
            
            # Wait for callback (up to 5 seconds)
            max_wait = 5
            wait_time = 0
            
            while wait_time < max_wait:
                callbacks = callback_server.get_callbacks()
                for callback in callbacks:
                    if test_id in callback.get('path', ''):
                        # SSRF CONFIRMED!
                        return {
                            'endpoint': endpoint,
                            'parameter': parameter,
                            'method': method,
                            'payload': payload_info,
                            'callback_url': callback_url,
                            'callback_received': callback,
                            'response_status': response.status_code,
                            'response_time': request_time - start_time,
                            'callback_time': callback.get('timestamp'),
                            'severity': 'HIGH',
                            'type': 'SSRF',
                            'confirmed': True
                        }
                
                time.sleep(0.2)
                wait_time += 0.2
            
            # No callback received
            return None
            
        except Exception as e:
            print(f"         ⚠️  Error testing {endpoint}: {e}")
            return None


# Helper function cho easy usage
def auto_discover_ssrf(domain: str, max_depth: int = 2) -> Dict:
    """
    🎯 ONE-LINE DISCOVERY: Chỉ cần domain!
    
    Example:
        results = auto_discover_ssrf("https://quangtx.io.vn")
    """
    # Ensure domain has scheme
    if not domain.startswith('http'):
        domain = 'https://' + domain
    
    discoverer = AutoDiscovery(domain, max_depth=max_depth)
    return discoverer.run_full_discovery()


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python auto_discovery.py <domain>")
        print("Example: python auto_discovery.py https://quangtx.io.vn")
        sys.exit(1)
    
    domain = sys.argv[1]
    
    print("\n" + "="*60)
    print("🎯 AUTOMATED SSRF DISCOVERY")
    print("="*60)
    
    results = auto_discover_ssrf(domain)
    
    print("\n" + "="*60)
    print("📊 DISCOVERY COMPLETE")
    print("="*60)
    print(f"\n✓ Total Endpoints: {len(results['endpoints'])}")
    print(f"✓ Endpoints with Parameters: {len(results['parameters'])}")
    print(f"✓ API Endpoints: {len(results['api_endpoints'])}")
    print(f"✓ Forms: {len(results['forms'])}")
    print(f"✓ Testable Endpoints: {len(results['testable_endpoints'])}")
    
    if results['testable_endpoints']:
        print("\n🎯 HIGH-PRIORITY TARGETS:")
        for target in sorted(results['testable_endpoints'], key=lambda x: x['confidence'], reverse=True)[:10]:
            print(f"   [{target['confidence']:.2f}] {target['endpoint']}")
            if target['parameter']:
                print(f"         Parameter: {target['parameter']}")
            print(f"         Reason: {target['reason']}")
