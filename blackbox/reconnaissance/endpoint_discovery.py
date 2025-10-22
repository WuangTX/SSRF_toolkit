"""
Endpoint Discovery Module
Tự động khám phá các endpoints của hệ thống
"""

import requests
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
from typing import List, Set, Dict
from concurrent.futures import ThreadPoolExecutor
import re

class EndpointDiscovery:
    """Khám phá endpoints tự động"""
    
    def __init__(self, target_url: str, timeout: int = 10, threads: int = 5):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.discovered_endpoints = set()
        self.session = requests.Session()
    
    def discover_from_wordlist(self, wordlist_path: str) -> List[Dict]:
        """Brute-force endpoints từ wordlist"""
        results = []
        
        try:
            with open(wordlist_path, 'r') as f:
                paths = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            # Sử dụng default wordlist
            paths = self._get_default_wordlist()
        
        print(f"[*] Testing {len(paths)} paths...")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self._test_path, path) for path in paths]
            
            for i, future in enumerate(futures):
                result = future.result()
                if result:
                    results.append(result)
                
                # Progress
                if (i + 1) % 10 == 0:
                    print(f"[*] Progress: {i + 1}/{len(paths)}")
        
        return results
    
    def discover_comprehensive(self, wordlist_path: str = None) -> List[Dict]:
        """
        Comprehensive endpoint discovery combining multiple techniques
        """
        all_endpoints = {}  # Use dict to deduplicate by URL
        
        print("[*] Starting comprehensive endpoint discovery...")
        
        # Method 1: robots.txt
        print("[*] Checking robots.txt...")
        robots_paths = self.discover_from_robots_txt()
        for path in robots_paths:
            result = self._test_path(path)
            if result:
                all_endpoints[result['url']] = result
        
        # Method 2: sitemap.xml
        print("[*] Checking sitemap.xml...")
        sitemap_paths = self.discover_from_sitemap()
        for path in sitemap_paths:
            result = self._test_path(path)
            if result:
                all_endpoints[result['url']] = result
        
        # Method 3: JavaScript parsing (CRITICAL for finding backend APIs in microservices)
        print("[*] Parsing JavaScript for API endpoints...")
        backend_services = set()  # Track backend service base URLs
        
        try:
            js_endpoints = self.discover_from_javascript()
            for endpoint in js_endpoints:
                # Handle both absolute and relative URLs
                if endpoint.startswith('http://') or endpoint.startswith('https://'):
                    test_url = endpoint
                    # Track backend services (different host/port from target)
                    parsed_endpoint = urlparse(endpoint)
                    parsed_target = urlparse(self.target_url)
                    
                    # Only treat as backend service if different netloc AND is internal
                    if parsed_endpoint.netloc != parsed_target.netloc:
                        hostname = parsed_endpoint.netloc.lower()
                        
                        # Filter: Only localhost or internal IPs (not external sites!)
                        is_internal = (
                            hostname.startswith('localhost') or
                            hostname.startswith('127.') or
                            hostname.startswith('192.168.') or
                            hostname.startswith('10.') or
                            hostname.startswith('172.') or
                            '-service' in hostname or  # microservice naming
                            '.local' in hostname or
                            ':' in hostname and not '.' in hostname.split(':')[0]  # service-name:8080
                        )
                        
                        if is_internal:
                            backend_base = f"{parsed_endpoint.scheme}://{parsed_endpoint.netloc}"
                            backend_services.add(backend_base)
                            print(f"  [!] Backend service detected: {backend_base}")
                else:
                    test_url = urljoin(self.target_url, endpoint)
                
                if test_url not in all_endpoints:
                    result = self._test_path(test_url)
                    if result:
                        all_endpoints[result['url']] = result
        except Exception as e:
            print(f"[!] JavaScript parsing failed: {str(e)}")
        
        # Method 4: Wordlist brute-force on main target
        if wordlist_path:
            print("[*] Brute-forcing main target with wordlist...")
            wordlist_results = self.discover_from_wordlist(wordlist_path)
            for result in wordlist_results:
                all_endpoints[result['url']] = result
        
        # Method 4.5: Brute-force discovered backend services (CRITICAL for microservices!)
        if backend_services and wordlist_path:
            print(f"[*] Brute-forcing {len(backend_services)} backend service(s)...")
            for backend_url in backend_services:
                print(f"  [*] Scanning backend: {backend_url}")
                # Create temporary discovery instance for this backend
                try:
                    backend_discovery = EndpointDiscovery(backend_url, self.timeout, self.threads)
                    backend_results = backend_discovery.discover_from_wordlist(wordlist_path)
                    for result in backend_results[:15]:  # Limit per service to avoid overwhelming
                        all_endpoints[result['url']] = result
                    print(f"  [+] Found {len(backend_results)} endpoints on {backend_url}")
                except Exception as e:
                    print(f"  [!] Failed to scan {backend_url}: {str(e)}")
        
        # Method 5: Spider (lightweight crawl)
        print("[*] Spidering for links...")
        try:
            spidered_urls = self.spider_endpoints(max_depth=1)
            for url in list(spidered_urls)[:20]:  # Limit to prevent too many
                if url not in all_endpoints:
                    result = self._test_path(url)
                    if result:
                        all_endpoints[result['url']] = result
        except Exception as e:
            print(f"[!] Spidering failed: {str(e)}")
        
        results = list(all_endpoints.values())
        print(f"[+] Total unique endpoints discovered: {len(results)}")
        if backend_services:
            print(f"[+] Backend microservices found: {', '.join(backend_services)}")
            print(f"[!] These backend services will be tested for SSRF vulnerabilities")
        
        return results
    
    def _test_path(self, path: str) -> Dict:
        """Test một path cụ thể"""
        url = urljoin(self.target_url, path)
        
        try:
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            # Chỉ log những endpoint thú vị
            if response.status_code in [200, 201, 301, 302, 401, 403]:
                self.discovered_endpoints.add(url)
                
                return {
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': len(response.content),
                    'content_type': response.headers.get('Content-Type', ''),
                    'redirect': response.url if response.url != url else None
                }
        except requests.exceptions.RequestException:
            pass
        
        return None
    
    def discover_from_robots_txt(self) -> List[str]:
        """Khám phá từ robots.txt"""
        paths = []
        robots_url = urljoin(self.target_url, '/robots.txt')
        
        try:
            response = self.session.get(robots_url, timeout=self.timeout)
            if response.status_code == 200:
                # Parse disallow paths
                for line in response.text.split('\n'):
                    if line.strip().lower().startswith('disallow:'):
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            paths.append(path)
        except:
            pass
        
        return paths
    
    def discover_from_sitemap(self) -> List[str]:
        """Khám phá từ sitemap.xml"""
        paths = []
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap-index.xml'
        ]
        
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(self.target_url, sitemap_path)
                response = self.session.get(sitemap_url, timeout=self.timeout)
                
                if response.status_code == 200:
                    # Extract URLs from XML
                    urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                    for url in urls:
                        parsed = urlparse(url)
                        if parsed.path:
                            paths.append(parsed.path)
            except:
                continue
        
        return paths
    
    def discover_from_javascript(self) -> Set[str]:
        """Extract API endpoints from JavaScript files"""
        api_endpoints = set()
        
        try:
            # Get main page HTML
            response = self.session.get(self.target_url, timeout=self.timeout)
            if response.status_code != 200:
                return api_endpoints
            
            # Find all script tags
            script_urls = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', response.text)
            
            # Also check inline scripts
            inline_scripts = re.findall(r'<script[^>]*>(.*?)</script>', response.text, re.DOTALL)
            
            all_js_content = '\n'.join(inline_scripts)
            
            # Fetch external scripts (limit to avoid too many requests)
            for script_url in script_urls[:5]:
                try:
                    full_url = urljoin(self.target_url, script_url)
                    js_response = self.session.get(full_url, timeout=self.timeout)
                    if js_response.status_code == 200:
                        all_js_content += '\n' + js_response.text
                except:
                    continue
            
            # Extract API endpoints using patterns
            # Pattern 1: fetch('...'), fetch("...")
            fetch_urls = re.findall(r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', all_js_content)
            api_endpoints.update(fetch_urls)
            
            # Pattern 2: axios.get/post('...'), axios.get/post("...")
            axios_urls = re.findall(r'axios\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', all_js_content)
            api_endpoints.update(axios_urls)
            
            # Pattern 3: http.get/post('...'), http.get/post("...")  
            http_urls = re.findall(r'http\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]', all_js_content)
            api_endpoints.update(http_urls)
            
            # Pattern 4: Direct URL patterns (http://..., https://...)
            url_patterns = re.findall(r'[\'"`](https?://[^\'"`\s]+)[\'"`]', all_js_content)
            
            # Filter to only internal/localhost URLs (not external sites like reactjs.org, w3.org)
            for url in url_patterns:
                parsed = urlparse(url)
                hostname = parsed.netloc.lower()
                
                # Only include localhost, internal IPs, or service names (no www., no public domains)
                if (hostname.startswith('localhost') or 
                    hostname.startswith('127.') or 
                    hostname.startswith('192.168.') or 
                    hostname.startswith('10.') or 
                    hostname.startswith('172.') or
                    hostname.endswith('-service') or  # microservice naming pattern
                    hostname.endswith('.local') or
                    ':' in hostname and not '.' in hostname.split(':')[0]):  # service-name:port
                    api_endpoints.add(url)
            
            # Pattern 5: Relative API paths (/api/..., /v1/...)
            relative_apis = re.findall(r'[\'"`](/(?:api|v\d+)/[^\'"`\s]+)[\'"`]', all_js_content)
            api_endpoints.update(relative_apis)
            
            print(f"[*] Found {len(api_endpoints)} potential API endpoints in JavaScript")
            
        except Exception as e:
            print(f"[!] JavaScript parsing failed: {str(e)}")
        
        return api_endpoints
    
    def spider_endpoints(self, max_depth: int = 2) -> Set[str]:
        """Spider để tìm thêm endpoints từ links"""
        visited = set()
        to_visit = {self.target_url}
        found_endpoints = set()
        
        for depth in range(max_depth):
            if not to_visit:
                break
            
            current_batch = to_visit.copy()
            to_visit.clear()
            
            for url in current_batch:
                if url in visited:
                    continue
                
                visited.add(url)
                
                try:
                    response = self.session.get(url, timeout=self.timeout)
                    
                    if response.status_code == 200:
                        # Extract links
                        links = re.findall(r'href=["\'](.*?)["\']', response.text)
                        
                        for link in links:
                            # Resolve relative URLs
                            full_url = urljoin(url, link)
                            
                            # Only follow same domain
                            if urlparse(full_url).netloc == urlparse(self.target_url).netloc:
                                found_endpoints.add(full_url)
                                if depth < max_depth - 1:
                                    to_visit.add(full_url)
                except:
                    continue
        
        return found_endpoints
    
    def _get_default_wordlist(self) -> List[str]:
        """Default wordlist cho microservices"""
        return [
            # API endpoints
            '/api', '/api/v1', '/api/v2',
            '/api/users', '/api/products', '/api/inventory',
            '/api/orders', '/api/auth', '/api/admin',
            
            # Health & Monitoring
            '/health', '/healthz', '/status',
            '/metrics', '/prometheus', '/actuator',
            '/actuator/health', '/actuator/metrics', '/actuator/env',
            
            # Admin panels
            '/admin', '/admin/login', '/dashboard',
            '/console', '/management',
            
            # Documentation
            '/docs', '/swagger', '/api-docs',
            '/swagger-ui', '/swagger-ui.html',
            '/openapi.json', '/api/swagger.json',
            
            # Common microservice paths
            '/user-service', '/product-service', '/inventory-service',
            '/auth-service', '/payment-service', '/order-service',
            
            # Config & Debug
            '/config', '/env', '/debug',
            '/trace', '/dump', '/heapdump',
            
            # Static files
            '/static', '/assets', '/public',
            '/js', '/css', '/images',
            
            # Files
            '/robots.txt', '/sitemap.xml',
            '/.git', '/.env', '/config.yml'
        ]
    
    def get_summary(self) -> Dict:
        """Lấy summary của discovery"""
        return {
            'total_endpoints': len(self.discovered_endpoints),
            'endpoints': list(self.discovered_endpoints)
        }

if __name__ == "__main__":
    # Test
    discovery = EndpointDiscovery("http://localhost:3000")
    results = discovery.discover_from_wordlist("")
    
    print(f"\n[+] Discovered {len(results)} endpoints:")
    for result in results:
        print(f"  [{result['status_code']}] {result['url']}")
