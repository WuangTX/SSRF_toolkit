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
    
    def __init__(self, base_url: str, timeout: int = 10, max_depth: int = 3, auth_token: str = None, auth_header: str = 'Authorization'):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_depth = max_depth
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # ✅ Authentication support
        if auth_token:
            self.session.headers[auth_header] = auth_token
            print(f"      🔑 Authentication: {auth_header}: {auth_token[:20]}...")
        
        self.visited_urls = set()
        self.discovered_endpoints = set()
        self.discovered_parameters = {}  # {endpoint: [params]}
        
        # Parse base domain
        parsed = urlparse(base_url)
        self.base_domain = parsed.netloc
        self.base_scheme = parsed.scheme
    
    def run_full_discovery(self, callback_url: str = None, callback_server=None) -> Dict:
        """
        🎯 MAIN METHOD: Chạy toàn bộ discovery pipeline
        
        Args:
            callback_server: Existing callback server (optional)
        
        Returns:
            {
                'endpoints': [...],
                'parameters': {...},
                'forms': [...],
                'api_endpoints': [...],
                'testable_endpoints': [...],
                'ssrf_vulnerabilities': [...]
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
        
        # Phase 6: SSRF Testing (with callback server)
        print("\n[6/6] 🔥 Testing for SSRF vulnerabilities...")
        ssrf_vulnerabilities = self._test_ssrf_vulnerabilities(testable, callback_url, callback_server)
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
        """✅ ENHANCED: Deep discovery với ID paths và SSRF-prone endpoints"""
        api_endpoints = set()
        
        # Base API paths (removed fake/internal paths: /services, /service, /internal, /admin/api, /graphql)
        common_api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1',
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
            '/api/download', '/api/upload'
        ]
        
        # ✅ SMART: Chỉ test actions HỢP LÝ cho từng resource type
        resource_actions_map = {
            # Product/Inventory endpoints - price checking makes sense
            'product': ['check_price', 'price_check', 'compare_price', 'compare', 'review', 'thumbnail', 'preview', 'image'],
            'inventory': ['check_price', 'price_check', 'compare', 'image'],
            'item': ['check_price', 'price_check', 'compare', 'review', 'image'],
            'order': ['validate', 'verify', 'check'],
            
            # Data/Fetch endpoints - fetching/proxy makes sense
            'data': ['fetch', 'proxy', 'import', 'export', 'download'],
            'fetch': ['fetch', 'proxy', 'download'],
            
            # Callback/Webhook endpoints
            'callback': ['callback', 'webhook', 'validate'],
            'webhook': ['webhook', 'callback', 'verify'],
            'proxy': ['proxy', 'fetch', 'forward'],
            'redirect': ['proxy', 'forward', 'callback'],
            
            # File/Image endpoints
            'image': ['image', 'thumbnail', 'preview', 'download', 'upload'],
            'file': ['download', 'upload', 'fetch'],
            'download': ['download', 'fetch'],
            'upload': ['upload'],
            
            # Generic API endpoints - only test core SSRF actions
            'api': ['fetch', 'callback', 'webhook', 'proxy'],
            'rest': ['fetch', 'callback', 'webhook', 'proxy']
        }
        
        # ✅ Test IDs (chỉ test 2-3 IDs thôi)
        test_ids = ['1', '5']
        
        base_root = f"{self.base_scheme}://{self.base_domain}"
        
        print(f"      🔍 Phase 1: Testing {len(common_api_paths)} base API paths...")
        
        # Phase 1: Discover base API paths
        discovered_bases = []
        for path in common_api_paths:
            test_url = base_root + path
            try:
                response = self.session.get(test_url, timeout=3, allow_redirects=False)
                
                # ✅ FIXED: Chỉ accept status codes hợp lệ, BỎ 405!
                if response.status_code in [200, 201, 400, 401, 403, 422, 500]:
                    api_endpoints.add(test_url)
                    discovered_bases.append(test_url)
                    print(f"      ✓ {path} [{response.status_code}]")
            except:
                pass
        
        # Phase 2: Deep discovery - SMART action testing
        print(f"\n      🔍 Phase 2: Smart testing with resource-specific actions...")
        
        # ✅ OPTIMIZATION: Chỉ test với discovered_bases thực sự tồn tại
        if len(discovered_bases) == 0:
            print(f"      ⚠️  No valid base APIs found, skipping deep discovery")
            return api_endpoints
        
        for base_api in discovered_bases:
            # ✅ Xác định resource type từ base path (SMART matching)
            base_lower = base_api.lower()
            relevant_actions = []
            
            # ✅ BLACKLIST: Skip endpoints không có SSRF potential
            skip_patterns = ['user', 'auth', 'login', 'customer', 'order']
            should_skip = any(pattern in base_lower for pattern in skip_patterns)
            
            if should_skip:
                print(f"      ⏭️  Skipping {base_api} (no SSRF potential)")
                continue
            
            # Find matching resource type (match most specific first)
            # Sort by length DESC để match '/api/products' trước '/api'
            sorted_resources = sorted(resource_actions_map.items(), key=lambda x: len(x[0]), reverse=True)
            
            for resource_type, actions in sorted_resources:
                if resource_type in base_lower:
                    relevant_actions = actions
                    break
            
            # Skip nếu không tìm thấy relevant actions
            if not relevant_actions:
                print(f"      ⏭️  Skipping {base_api} (no matching actions)")
                continue
            
            print(f"      🎯 Testing {base_api} with {len(relevant_actions)} relevant actions...")
            tests_count = 0
            max_tests_per_base = 6  # Limit per base
            
            for test_id in test_ids:
                if tests_count >= max_tests_per_base:
                    break
                    
                for action in relevant_actions:
                    if tests_count >= max_tests_per_base:
                        break
                    
                    # Test pattern: /api/products/5/check_price/
                    deep_endpoint = f"{base_api}/{test_id}/{action}/"
                    
                    try:
                        # Test POST với JSON FIRST (more common for SSRF)
                        post_resp = self.session.post(
                            deep_endpoint,
                            json={"test": "probe"},
                            headers={'Content-Type': 'application/json'},
                            timeout=2,
                            allow_redirects=False
                        )
                        
                        # ✅ FIXED: BỎ 405! Chỉ accept valid responses
                        if post_resp.status_code in [200, 201, 400, 401, 403, 422, 500]:
                            api_endpoints.add(deep_endpoint)
                            print(f"      ✓ {deep_endpoint.replace(base_root, '')} [POST:{post_resp.status_code}]")
                            tests_count += 1
                        
                        # Test GET nếu POST không work
                        elif post_resp.status_code == 405:
                            get_resp = self.session.get(deep_endpoint, timeout=2, allow_redirects=False)
                            if get_resp.status_code in [200, 201, 400, 401, 403, 422, 500]:
                                api_endpoints.add(deep_endpoint)
                                print(f"      ✓ {deep_endpoint.replace(base_root, '')} [GET:{get_resp.status_code}]")
                                tests_count += 1
                    
                    except:
                        pass
        
        return api_endpoints
    

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
        ✅ ENHANCED: Identify SSRF-vulnerable endpoints với better parameter detection
        
        Criteria:
        1. Có parameters với tên suspicious
        2. Accepts URL-like input
        3. API endpoints (especially with actions like check_price, compare, review)
        4. Forms với URL inputs
        """
        testable = []
        
        # ✅ EXPANDED: More SSRF parameter names từ real-world labs
        url_params = [
            # Standard URL params
            'url', 'uri', 'path', 'link', 'href', 'src',
            
            # Callback/Webhook
            'callback', 'callback_url', 'callbackUrl',
            'webhook', 'webhook_url', 'webhookUrl',
            
            # Redirect
            'redirect', 'redirect_url', 'redirectUrl',
            'return_url', 'returnUrl', 'return_to',
            
            # Target/Destination
            'target', 'target_url', 'targetUrl',
            'dest', 'destination', 'destination_url',
            
            # Fetch/Load/Import
            'fetch', 'fetch_url', 'load', 'load_url',
            'import', 'import_url', 'download', 'download_url',
            
            # Proxy/Forward
            'proxy', 'proxy_url', 'host', 'endpoint', 'service',
            'forward', 'forward_url',
            
            # Media
            'image', 'image_url', 'img', 'img_url',
            'picture', 'picture_url', 'avatar', 'avatar_url',
            
            # File/Resource
            'file', 'file_url', 'document', 'document_url',
            'resource', 'resource_url', 'source', 'source_url',
            
            # ✅ Lab-specific params (từ PortSwigger, HackTheBox, etc.)
            'compare_url', 'compareUrl',  # Price comparison
            'review_url', 'reviewUrl',     # Product review
            'external_url', 'externalUrl', # External resource
            'api_url', 'apiUrl',           # API call
            'check_url', 'checkUrl',       # URL check
            'validate_url', 'validateUrl', # URL validation
            'verify_url', 'verifyUrl',     # URL verification
            
            # Navigation
            'next', 'continue', 'goto', 'navigate'
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
        
        # ✅ SMART API endpoint testing - ONLY for valid discovered endpoints
        print(f"      🔍 Analyzing {len(results['api_endpoints'])} API endpoints...")
        
        for api_endpoint in results['api_endpoints']:
            endpoint_path = api_endpoint.lower()
            
            # ✅ Identify SSRF action trong path
            ssrf_actions_in_path = [
                'check_price', 'price_check', 'compare_price', 'compare',
                'fetch', 'proxy', 'callback', 'webhook', 
                'import', 'export', 'download', 'upload',
                'validate', 'verify', 'check', 'review',
                'thumbnail', 'preview', 'image'
            ]
            
            has_ssrf_action = any(action in endpoint_path for action in ssrf_actions_in_path)
            
            # ✅ ONLY test endpoints với SSRF actions (bỏ generic endpoints)
            if has_ssrf_action:
                # ✅ OPTIMIZED: Chỉ test 3 parameters PHỔ BIẾN nhất
                # Giảm từ 6 → 3 parameters = giảm 50% tests
                json_params = []
                
                # Chọn parameters dựa trên action type
                if 'callback' in endpoint_path or 'webhook' in endpoint_path:
                    json_params = ['callback_url', 'webhook_url', 'url']
                elif 'fetch' in endpoint_path or 'proxy' in endpoint_path:
                    json_params = ['url', 'callback_url', 'target_url']
                elif 'compare' in endpoint_path or 'check_price' in endpoint_path:
                    json_params = ['compare_url', 'url', 'target_url']
                else:
                    # Default: most common params
                    json_params = ['url', 'callback_url', 'target_url']
                
                for param in json_params:
                    testable.append({
                        'type': 'api_json_post',
                        'endpoint': api_endpoint,
                        'parameter': param,
                        'method': 'POST',
                        'confidence': 0.9,  # HIGH confidence
                        'reason': f'SSRF action endpoint with POST JSON param "{param}"'
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

    def _test_ssrf_vulnerabilities(self, testable_endpoints: List[Dict], callback_url: str = None, callback_server=None, max_workers: int = 5) -> List[Dict]:
        """
        ✅ PARALLEL SSRF TESTING với ThreadPoolExecutor
        Test multiple endpoints đồng thời để tăng tốc độ
        
        Args:
            testable_endpoints: List of endpoints to test
            callback_server: Existing callback server (optional, will create new if None)
            max_workers: Number of parallel threads (default: 5)
        """
        vulnerabilities = []
        
        if not testable_endpoints:
            return vulnerabilities
        
        # ✅ SMART: Sử dụng public callback URL nếu có, fallback local server
        from ..detection.external_callback import CallbackServer, MockCallbackServer
        
        should_stop_server = False
        
        try:
            # PRIORITY 1: Dùng public callback URL nếu được cung cấp (NGROK - HIGHEST PRIORITY!)
            if callback_url:
                print(f"      📡 Using PUBLIC callback URL: {callback_url}")
                # Tạo mock callback server để giữ interface nhất quán
                # ⚠️ KHÔNG OVERRIDE callback_url!
                if callback_server is None:
                    callback_server = MockCallbackServer(callback_url)
                
            # PRIORITY 2: Dùng existing callback server (CHỈ nếu KHÔNG có public URL!)
            elif callback_server is not None:
                callback_url = callback_server.get_callback_url()
                print(f"      📡 Using existing callback server: {callback_url}")
            
            # PRIORITY 3: Tạo LOCAL callback server mới (fallback)
            else:
                callback_server = CallbackServer(port=8888)
                callback_url = callback_server.start()
                should_stop_server = True
                print(f"      📡 New LOCAL callback server started: {callback_url}")
                print(f"         ⚠️  NOTE: Target có thể KHÔNG truy cập được local server!")
                print(f"         💡 Tip: Dùng ngrok/serveo hoặc public callback URL")
            
            # ✅ AGGRESSIVE FILTERING
            print(f"      🔍 Filtering {len(testable_endpoints)} candidates...")
            
            valid_targets = []
            for t in testable_endpoints:
                endpoint = t['endpoint']
                
                # Skip placeholders
                if any(x in endpoint for x in ['{id}', '<id>', '{param}', '{code}']):
                    continue
                
                # ✅ Skip fake/synthetic endpoints (internal, service/services, admin/api, graphql)
                skip_patterns = ['/internal/', '/service/', '/services/', '/admin/api/', '/graphql/']
                if any(pattern in endpoint.lower() for pattern in skip_patterns):
                    continue
                
                # ✅ Only keep endpoints từ discovered_endpoints (thực sự tồn tại)
                # hoặc confidence cao (0.9+)
                if t['confidence'] >= 0.7:  # Only HIGH confidence
                    valid_targets.append(t)
            
            # Sort by confidence - test HIGH confidence first
            sorted_targets = sorted(valid_targets, key=lambda x: x['confidence'], reverse=True)
            
            # ✅ LIMIT: Chỉ test top 100 endpoints
            sorted_targets = sorted_targets[:100]
            total_to_test = len(sorted_targets)
            
            print(f"      📊 Filtered to {total_to_test} high-confidence endpoints")
            print(f"      🎯 Testing with {max_workers} parallel workers")
            
            # ✅ PARALLEL TESTING với ThreadPoolExecutor
            tested_count = 0
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                # Submit all test tasks
                future_to_target = {}
                for i, target in enumerate(sorted_targets, 1):
                    test_id = f"ssrf_{i}_{int(time.time()*1000)}"
                    test_callback_url = f"{callback_url}/{test_id}"
                    
                    future = executor.submit(
                        self._test_single_ssrf_wrapper,
                        target, test_callback_url, test_id, callback_server, i, total_to_test
                    )
                    future_to_target[future] = target
                
                # Collect results as they complete
                for future in as_completed(future_to_target):
                    target = future_to_target[future]
                    try:
                        result = future.result()
                        tested_count += 1
                        
                        if result:
                            result['confidence'] = target['confidence']
                            vulnerabilities.append(result)
                            print(f"         ✅ SSRF CONFIRMED: {target['endpoint'][:60]}")
                    
                    except KeyboardInterrupt:
                        print(f"\n      ⚠️  Testing interrupted by user")
                        executor.shutdown(wait=False, cancel_futures=True)
                        break
                    except Exception as e:
                        print(f"         ⚠️  Error testing {target['endpoint'][:50]}: {str(e)[:50]}")
            
            print(f"\n      ✅ Testing complete: {tested_count}/{total_to_test} endpoints tested")
            
            # Stop callback server nếu là server tạo mới
            if should_stop_server:
                callback_server.stop()
                print(f"      📡 Callback server stopped")
            else:
                print(f"      📡 Callback server kept alive (managed externally)")
            
        except Exception as e:
            print(f"         ❌ Error in SSRF testing: {e}")
            if should_stop_server and callback_server:
                try:
                    callback_server.stop()
                except:
                    pass
        
        return vulnerabilities
    
    def _test_single_ssrf_wrapper(self, target: Dict, callback_url: str, test_id: str, callback_server, index: int, total: int) -> Optional[Dict]:
        """Wrapper cho parallel testing"""
        endpoint = target['endpoint']
        parameter = target['parameter']
        method = target.get('method', 'GET')
        test_type = target.get('type', 'unknown')
        
        display_url = endpoint if len(endpoint) <= 60 else endpoint[:57] + '...'
        print(f"      🎯 [{index:2d}/{total}] {display_url} ({parameter}) [{method}]")
        
        return self._test_single_ssrf(endpoint, parameter, callback_url, test_id, callback_server, method, test_type)

    def _test_single_ssrf(self, endpoint: str, parameter: str, callback_url: str, test_id: str, callback_server, method: str = 'GET', test_type: str = 'unknown') -> Optional[Dict]:
        """
        ✅ ENHANCED: Test single endpoint với support cho POST + JSON
        """
        try:
            # Clear any existing callbacks
            callback_server.clear_callbacks()
            
            start_time = time.time()
            response = None
            payload_info = ""
            
            # ✅ PRIORITY 1: POST + JSON (for api_json_post type)
            if method.upper() == 'POST' and 'json' in test_type.lower():
                json_payload = {parameter: callback_url}
                
                try:
                    response = self.session.post(
                        endpoint, 
                        json=json_payload,
                        headers={'Content-Type': 'application/json'},
                        timeout=5,
                        allow_redirects=False,
                        verify=False
                    )
                    payload_info = f"POST JSON: {json_payload}"
                    print(f" [POST/JSON {response.status_code}]", end='', flush=True)
                    
                    # ✅ AUTO-FALLBACK: Nếu 405 → thử GET ngay
                    if response.status_code == 405:
                        print(f" → Trying GET...", end='', flush=True)
                        if '?' in endpoint:
                            test_url = f"{endpoint}&{parameter}={quote(callback_url)}"
                        else:
                            test_url = f"{endpoint}?{parameter}={quote(callback_url)}"
                        
                        response = self.session.get(
                            test_url, 
                            timeout=5,
                            allow_redirects=False,
                            verify=False
                        )
                        payload_info = f"GET (fallback): {test_url}"
                        print(f" [GET {response.status_code}]", end='', flush=True)
                
                except Exception as post_error:
                    print(f" [POST failed: {str(post_error)[:30]}]", end='', flush=True)
                    return None
            
            # ✅ PRIORITY 2: POST + Form Data (fallback)
            elif method.upper() == 'POST':
                form_data = {parameter: callback_url}
                
                try:
                    response = self.session.post(
                        endpoint,
                        data=form_data,
                        timeout=5,
                        allow_redirects=False,
                        verify=False
                    )
                    payload_info = f"POST Form: {form_data}"
                    print(f" [POST/Form {response.status_code}]", end='', flush=True)
                    
                    # ✅ AUTO-FALLBACK: Nếu 405 → thử GET ngay
                    if response.status_code == 405:
                        print(f" → Trying GET...", end='', flush=True)
                        if '?' in endpoint:
                            test_url = f"{endpoint}&{parameter}={quote(callback_url)}"
                        else:
                            test_url = f"{endpoint}?{parameter}={quote(callback_url)}"
                        
                        response = self.session.get(
                            test_url, 
                            timeout=5,
                            allow_redirects=False,
                            verify=False
                        )
                        payload_info = f"GET (fallback): {test_url}"
                        print(f" [GET {response.status_code}]", end='', flush=True)
                
                except Exception as post_error:
                    print(f" [POST failed: {str(post_error)[:30]}]", end='', flush=True)
                    return None
            
            # ✅ PRIORITY 3: GET with query parameters
            else:
                if '?' in endpoint:
                    test_url = f"{endpoint}&{parameter}={quote(callback_url)}"
                else:
                    test_url = f"{endpoint}?{parameter}={quote(callback_url)}"
                
                try:
                    response = self.session.get(
                        test_url, 
                        timeout=5,
                        allow_redirects=False,
                        verify=False
                    )
                    payload_info = f"GET: {test_url}"
                    print(f" [GET {response.status_code}]", end='', flush=True)
                
                except Exception as get_error:
                    print(f" [GET failed: {str(get_error)[:30]}]", end='', flush=True)
                    return None
            
            if response is None:
                return None
            
            # ✅ SKIP: Nếu vẫn nhận 405 sau fallback → bỏ qua luôn
            if response.status_code == 405:
                print(f" ❌ Method not allowed (skipped)")
                return None
            
            # ✅ SKIP: Nếu 404 → endpoint không tồn tại
            if response.status_code == 404:
                print(f" ❌ Not found (skipped)")
                return None
            
            request_time = time.time()

            # ✅ Wait for callback (single check with configurable timeout)
            # Use callback_server.check_callback_received() to avoid busy polling loops
            callback_wait = min(2, max(0.5, getattr(self, 'timeout', 2)))
            print(f" → Waiting for callback (up to {callback_wait}s)...", end='', flush=True)

            try:
                if callback_server and callback_server.check_callback_received(test_id, timeout=callback_wait):
                    # Retrieve latest callbacks to get details
                    callbacks = callback_server.get_callbacks(timeout=0.5)
                    found_cb = None
                    for cb in callbacks:
                        if test_id in cb.get('path', ''):
                            found_cb = cb
                            break

                    print(f" ✅ CALLBACK RECEIVED!")
                    return {
                        'endpoint': endpoint,
                        'parameter': parameter,
                        'method': method,
                        'test_type': test_type,
                        'payload': payload_info,
                        'callback_url': callback_url,
                        'callback_received': found_cb,
                        'response_status': response.status_code,
                        'response_time': request_time - start_time,
                        'callback_time': found_cb.get('timestamp') if found_cb else None,
                        'severity': 'HIGH',
                        'type': 'SSRF',
                        'confirmed': True
                    }
                else:
                    print(f" ❌ No callback")
                    return None
            except Exception:
                print(f" ❌ Callback check error")
                return None
            
        except requests.exceptions.Timeout:
            print(f" ⏱️ Timeout")
            return None
        except requests.exceptions.ConnectionError:
            print(f" 🔌 Connection failed")
            return None
        except requests.exceptions.TooManyRedirects:
            print(f" 🔄 Too many redirects")
            return None
        except Exception as e:
            print(f" ⚠️ Error: {str(e)[:50]}")
            return None


# Helper function cho easy usage
def auto_discover_ssrf(domain: str, max_depth: int = 2, auth_token: str = None, auth_header: str = 'Authorization', callback_url: str = None, callback_server = None) -> Dict:
    """
    ✅ ONE-LINE DISCOVERY với authentication support
    
    Example:
        # No auth
        results = auto_discover_ssrf("https://quangtx.io.vn")
        
        # With Bearer token
        results = auto_discover_ssrf(
            "https://quangtx.io.vn",
            auth_token="Bearer eyJhbGc..."
        )
        
        # With custom header + public callback
        results = auto_discover_ssrf(
            "https://quangtx.io.vn",
            auth_token="session123456",
            auth_header="X-Auth-Token",
            callback_url="http://abc123.oast.fun"  # Public callback domain
        )
    """
    # Ensure domain has scheme
    if not domain.startswith('http'):
        domain = 'https://' + domain
    
    discoverer = AutoDiscovery(domain, max_depth=max_depth, auth_token=auth_token, auth_header=auth_header)
    return discoverer.run_full_discovery(callback_url=callback_url, callback_server=callback_server)


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
