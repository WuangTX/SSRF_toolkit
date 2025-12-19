"""
JavaScript Endpoint Discovery Module
Phân tích JavaScript để tìm API endpoints với độ chính xác cao
"""

import re
import json
from typing import Set, List, Dict, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import requests
import logging


class JavaScriptAnalyzer:
    """Phân tích JavaScript để tìm API endpoints"""
    
    def __init__(self, target_url: str, session: requests.Session, logger: logging.Logger):
        self.target_url = target_url
        self.session = session
        self.logger = logger
        self.parsed_target = urlparse(target_url)
    
    def discover_from_javascript(self) -> Set[str]:
        """Main method để discover endpoints từ JavaScript"""
        all_endpoints = set()
        
        try:
            # 1. Get main page và parse scripts
            main_response = self.session.get(self.target_url)
            if main_response.status_code != 200:
                return all_endpoints
            
            soup = BeautifulSoup(main_response.text, 'html.parser')
            
            # 2. Extract all JavaScript content
            js_content = self._extract_all_javascript(soup)
            0
            # 3. Parse JavaScript with multiple techniques
            endpoints = self._parse_javascript_content(js_content)
            
            # 4. Validate và convert to full URLs
            base_url = f"{self.parsed_target.scheme}://{self.parsed_target.netloc}"
            for endpoint in endpoints:
                # ✅ SMART: Try both with/without /api prefix for endpoints starting with /
                endpoints_to_try = [endpoint]
                
                if endpoint.startswith('/') and not endpoint.startswith('/api/'):
                    # Try adding /api prefix (common React pattern)
                    endpoints_to_try.append(f"/api{endpoint}")
                
                for ep in endpoints_to_try:
                    if self._is_valid_endpoint(ep):
                        # ✅ Convert relative URLs to full URLs
                        if ep.startswith('/'):
                            full_url = base_url + ep
                        elif ep.startswith(('http://', 'https://')):
                            full_url = ep
                        else:
                            full_url = base_url + '/' + ep
                        
                        all_endpoints.add(full_url)
            
            # ❌ DISABLED: Heuristic endpoint guessing causes false positives
            # Only use endpoints actually found in JavaScript, not guessed patterns
            # 
            # base_url = f"{self.parsed_target.scheme}://{self.parsed_target.netloc}"
            # heuristic_patterns = {
            #     '/products/': [
            #         '/products/{id}/check_price/',
            #         '/products/{id}/fetch_review/',
            #         '/products/{id}/compare/',
            #         '/products/{id}/thumbnail/',
            #     ],
            #     '/api/products/': [
            #         '/api/products/{id}/check_price/',
            #         '/api/products/{id}/fetch_review/',
            #         '/api/products/{id}/compare/',
            #         '/api/products/{id}/thumbnail/',
            #     ],
            #     '/inventory/': [
            #         '/inventory/check_stock/',
            #         '/inventory/sync/',
            #     ],
            #     '/api/inventory/': [
            #         '/api/inventory/check_stock/',
            #         '/api/inventory/sync/',
            #     ],
            # }
            
            if False:  # Disabled heuristic patterns
                base_pattern, ssrf_endpoints = None, None
                # Check if we found this base endpoint
                base_found = any(base_pattern in ep for ep in all_endpoints)
                if base_found:
                    for ssrf_ep in ssrf_endpoints:
                        full_url = base_url + ssrf_ep
                        all_endpoints.add(full_url)
                        self.logger.debug(f"Added heuristic SSRF endpoint: {ssrf_ep}")
            
            self.logger.info(f"JavaScript analysis found {len(all_endpoints)} valid endpoints")
            
        except Exception as e:
            self.logger.error(f"JavaScript discovery failed: {e}")
        
        return all_endpoints
    
    def _extract_all_javascript(self, soup: BeautifulSoup) -> str:
        """Extract tất cả JavaScript content từ page"""
        all_js = []
        
        # 1. Inline scripts
        inline_scripts = soup.find_all('script', src=False)
        for script in inline_scripts:
            if script.string:
                all_js.append(script.string)
        
        # 2. External scripts (limit để tránh quá nhiều requests)
        external_scripts = soup.find_all('script', src=True)
        for script in external_scripts[:10]:  # Limit 10 files
            src = script.get('src')
            if src:
                try:
                    if src.startswith('//'):
                        src = f"{self.parsed_target.scheme}:{src}"
                    elif src.startswith('/'):
                        src = urljoin(self.target_url, src)
                    elif not src.startswith(('http://', 'https://')):
                        src = urljoin(self.target_url, src)
                    
                    # Only fetch from same domain hoặc CDNs an toàn
                    parsed_src = urlparse(src)
                    if (parsed_src.netloc == self.parsed_target.netloc or
                        self._is_safe_cdn(parsed_src.netloc)):
                        
                        js_response = self.session.get(src, timeout=10)
                        if js_response.status_code == 200:
                            all_js.append(js_response.text)
                            
                except Exception as e:
                    self.logger.debug(f"Failed to fetch script {src}: {e}")
        
        return '\n'.join(all_js)
    
    def _is_safe_cdn(self, hostname: str) -> bool:
        """Kiểm tra có phải CDN an toàn không"""
        safe_cdns = [
            'cdnjs.cloudflare.com',
            'unpkg.com',
            'jsdelivr.net',
            'ajax.googleapis.com',
            'code.jquery.com',
            'stackpath.bootstrapcdn.com'
        ]
        return hostname.lower() in safe_cdns
    
    def _parse_javascript_content(self, js_content: str) -> Set[str]:
        """Parse JavaScript content với multiple techniques"""
        endpoints = set()
        
        # 1. Direct API calls
        endpoints.update(self._extract_fetch_calls(js_content))
        endpoints.update(self._extract_axios_calls(js_content))
        endpoints.update(self._extract_jquery_calls(js_content))
        endpoints.update(self._extract_xhr_calls(js_content))
        
        # 2. URL assignments và constants
        endpoints.update(self._extract_url_assignments(js_content))
        endpoints.update(self._extract_string_literals(js_content))
        
        # 3. Configuration objects
        endpoints.update(self._extract_config_objects(js_content))
        
        # 4. Route definitions
        endpoints.update(self._extract_route_definitions(js_content))
        
        # ✅ 5. API Service definitions (React/Vue style)
        endpoints.update(self._extract_api_service_definitions(js_content))
        
        return endpoints
    
    def _extract_fetch_calls(self, content: str) -> Set[str]:
        """Extract fetch() calls"""
        patterns = [
            r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'fetch\s*\(\s*`([^`]+)`',
            r'\.fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            endpoints.update(matches)
        
        return endpoints
    
    def _extract_axios_calls(self, content: str) -> Set[str]:
        """✅ ENHANCED: Extract axios calls với template literals và parameter paths"""
        patterns = [
            # Direct method calls: axios.get('/api/products')
            r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Config object: axios({url: '/api/products'})
            r'axios\s*\(\s*\{\s*[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # Simple: axios('/api/products')
            r'axios\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # ✅ Template literals with variables: axios.get(`/api/products/${id}`)
            r'axios\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`',
            
            # ✅ Concatenation: axios.get('/api/products/' + id)
            r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]\s*\+',
            
            # ✅ BaseURL patterns in axios.create
            r'baseURL\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            
            # ✅ Generic API object methods: productAPI.post(`...`)
            r'\w+API\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`',
            r'\w+API\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    # Get URL part (skip method name)
                    url = match[1] if len(match) > 1 else match[0]
                else:
                    url = match
                
                # ✅ Clean template literals: /api/products/${id} → /api/products/{id}
                url = re.sub(r'\$\{[^}]+\}', '{id}', url)
                
                # ✅ Clean concatenations: /api/products/ + id → /api/products/{id}
                if url.endswith('/') and url.count('/') >= 2:
                    url = url + '{id}/'
                
                endpoints.add(url)
        
        return endpoints
    
    def _extract_jquery_calls(self, content: str) -> Set[str]:
        """Extract jQuery AJAX calls"""
        patterns = [
            r'\$\.(?:get|post|ajax|getJSON)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'jQuery\.(?:get|post|ajax|getJSON)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\$\.ajax\s*\(\s*\{\s*[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            endpoints.update(matches)
        
        return endpoints
    
    def _extract_xhr_calls(self, content: str) -> Set[str]:
        """Extract XMLHttpRequest calls"""
        patterns = [
            r'\.open\s*\(\s*[\'"`](?:GET|POST|PUT|DELETE)[\'"`]\s*,\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.setRequestHeader\s*\(\s*[\'"`]([^\'"`]*(?:api|endpoint)[^\'"`]*)[\'"`]'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            endpoints.update(matches)
        
        return endpoints
    
    def _extract_url_assignments(self, content: str) -> Set[str]:
        """Extract URL assignments và constants"""
        patterns = [
            r'(?:const|let|var)\s+\w*(?:url|endpoint|api)\w*\s*=\s*[\'"`]([^\'"`]+)[\'"`]',
            r'(?:apiUrl|baseUrl|endpointUrl|serviceUrl)\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
            r'url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            r'endpoint\s*:\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            endpoints.update(matches)
        
        return endpoints
    
    def _extract_string_literals(self, content: str) -> Set[str]:
        """✅ ENHANCED: Extract potential API paths từ string literals"""
        # Look for strings that look like API paths
        api_patterns = [
            r'[\'"`](/api/[^\'"`\s]+)[\'"`]',
            r'[\'"`](/v\d+/[^\'"`\s]+)[\'"`]',
            r'[\'"`](/graphql[^\'"`\s]*)[\'"`]',
            r'[\'"`](/rest/[^\'"`\s]+)[\'"`]',
            
            # ✅ Template literals: `/api/products/${id}/check_price`
            r'`(/api/[^`]+)`',
            r'`(/v\d+/[^`]+)`',
            r'`(/rest/[^`]+)`',
        ]
        
        endpoints = set()
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # ✅ Clean template literals
                url = re.sub(r'\$\{[^}]+\}', '{id}', match)
                endpoints.add(url)
        
        return endpoints
    
    def _extract_config_objects(self, content: str) -> Set[str]:
        """Extract URLs từ configuration objects"""
        endpoints = set()
        
        # Find JSON-like configuration objects
        config_patterns = [
            r'\{\s*[^}]*(?:api|endpoint|url)[^}]*\}',
            r'config\s*=\s*\{[^}]*\}',
            r'settings\s*=\s*\{[^}]*\}'
        ]
        
        for pattern in config_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                # Extract URLs from these objects
                urls = re.findall(r'[\'"`]([^\'"`]*(?:/api/|/v\d+/|/graphql)[^\'"`]*)[\'"`]', match)
                endpoints.update(urls)
        
        return endpoints
    
    def _extract_route_definitions(self, content: str) -> Set[str]:
        """Extract route definitions (for SPAs)"""
        patterns = [
            r'route\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'path\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.get\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'\.post\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            endpoints.update(matches)
        
        return endpoints
    
    def _extract_api_service_definitions(self, content: str) -> Set[str]:
        """✅ NEW: Extract API service definitions (React/Vue API modules)
        
        Example patterns:
        - productAPI.checkPrice(id, url) → /api/products/{id}/check_price/
        - userAPI.getById(id) → /api/users/{id}
        """
        endpoints = set()
        
        # ✅ Pattern 1: Direct method definitions
        # checkPrice: (productId, compareUrl) => productAPI.post(`/products/${productId}/check_price/`, ...)
        method_patterns = [
            r'(\w+)\s*:\s*\([^)]*\)\s*=>\s*\w+API\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`',
            r'(\w+)\s*:\s*\([^)]*\)\s*=>\s*\w+API\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
            
            # Function definition style
            r'function\s+(\w+)\s*\([^)]*\)\s*{\s*return\s+\w+API\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`',
            r'const\s+(\w+)\s*=\s*\([^)]*\)\s*=>\s*\w+API\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`',
        ]
        
        for pattern in method_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if len(match) >= 3:
                    method_name = match[0]
                    http_method = match[1]
                    url = match[2] if len(match) > 2 else match[-1]
                    
                    # Clean template literals
                    url = re.sub(r'\$\{[^}]+\}', '{id}', url)
                    
                    # Ensure starts with /
                    if not url.startswith('/'):
                        url = '/' + url
                    
                    endpoints.add(url)
                    self.logger.debug(f"Found API method: {method_name}() → {http_method.upper()} {url}")
        
        # ✅ Pattern 2: Broader service object search (handle minified code)
        # Look for any API service definition blocks
        service_patterns = [
            r'export\s+const\s+(\w+API)\s*=\s*\{([^}]{50,2000})\}',  # Expanded to handle larger objects
            r'const\s+(\w+API)\s*=\s*\{([^}]{50,2000})\}',
            r'(\w+ServiceAPI)\s*=\s*\{([^}]{50,2000})\}',
        ]
        
        for service_pattern in service_patterns:
            service_matches = re.findall(service_pattern, content, re.DOTALL | re.IGNORECASE)
            
            for service_name, service_body in service_matches:
                # ✅ Extract methods with template literals
                method_patterns_in_service = [
                    r'(\w+)\s*:\s*[^,}]*\.(get|post|put|delete|patch)\s*\(\s*`([^`]+)`',
                    r'(\w+)\s*:\s*[^,}]*\.(get|post|put|delete|patch)\s*\(\s*[\'"]([^\'"]+)[\'"]',
                ]
                
                for method_pattern in method_patterns_in_service:
                    method_matches = re.findall(method_pattern, service_body, re.IGNORECASE)
                    
                    for method_name, http_method, url in method_matches:
                        # Clean template literals
                        url = re.sub(r'\$\{[^}]+\}', '{id}', url)
                        
                        # Ensure starts with /
                        if not url.startswith('/'):
                            url = '/' + url
                        
                        endpoints.add(url)
                        self.logger.debug(f"Found {service_name}.{method_name}() → {http_method.upper()} {url}")
        
        return endpoints
    
    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Validate endpoint có đáng test không"""
        try:
            if not endpoint or len(endpoint) < 2:
                return False
            
            endpoint_lower = endpoint.lower()
            
            # Skip non-API files
            skip_extensions = [
                '.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico',
                '.woff', '.ttf', '.eot', '.pdf', '.zip'
            ]
            
            for ext in skip_extensions:
                if endpoint_lower.endswith(ext):
                    return False
            
            # Skip external domains (except internal ones)
            if endpoint.startswith(('http://', 'https://')):
                try:
                    parsed = urlparse(endpoint)
                    hostname = parsed.netloc.lower()
                    
                    # ✅ ALWAYS allow if same as target domain
                    if hostname == self.parsed_target.netloc.lower():
                        # Continue to check API indicators below
                        pass
                    else:
                        # Skip public domains
                        public_domains = [
                            'google.com', 'facebook.com', 'twitter.com',
                            'github.com', 'stackoverflow.com', 'w3.org'
                        ]
                        
                        for domain in public_domains:
                            if domain in hostname:
                                return False
                        
                        # Only allow internal services (ignore validation errors)
                        try:
                            if not self._is_internal_service(hostname):
                                return False
                        except:
                            # If validation fails, skip this endpoint
                            self.logger.debug(f"Skipping {endpoint} due to hostname validation error")
                            return False
                except Exception as e:
                    self.logger.debug(f"URL parse error for {endpoint}: {e}")
                    return False
            
            # Must look like an API endpoint
            api_indicators = [
                '/api/', '/v1/', '/v2/', '/v3/', '/rest/',
                '/graphql', '/webhook', '/callback'
            ]
            
            for indicator in api_indicators:
                if indicator in endpoint_lower:
                    return True
            
            # Or start with /
            if endpoint.startswith('/') and len(endpoint) > 1:
                return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Validation error for endpoint '{endpoint}': {e}")
            return False
    
    def _is_internal_service(self, hostname: str) -> bool:
        """Check if hostname is internal service"""
        try:
            if not hostname:
                return False
                
            internal_patterns = [
                r'^localhost(:\d+)?$',
                r'^127\.\d+\.\d+\.\d+(:\d+)?$',
                r'^10\.\d+\.\d+\.\d+(:\d+)?$',
                r'^192\.168\.\d+\.\d+(:\d+)?$',
                r'^172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+(:\d+)?$',
                r'^.*-service(:\d+)?$',
                r'^.*\.local(:\d+)?$',
                r'^[a-zA-Z0-9-]+:\d+$'  # service-name:port
            ]
            
            for pattern in internal_patterns:
                if re.match(pattern, hostname):
                    return True
            
            return False
        except Exception as e:
            self.logger.debug(f"Error checking hostname '{hostname}': {e}")
            return False