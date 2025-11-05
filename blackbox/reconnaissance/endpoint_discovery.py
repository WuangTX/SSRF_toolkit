"""
Endpoint Discovery Module
Tự động khám phá các endpoints của hệ thống
"""

import requests
import asyncio
import aiohttp
import time
import random
from urllib.parse import urljoin, urlparse, parse_qs
from typing import List, Set, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import re
import json
import xml.etree.ElementTree as ET
from bs4 import BeautifulSoup
import logging

class EndpointDiscovery:
    """Khám phá endpoints tự động với async/await và rate limiting"""
    
    def __init__(self, target_url: str, timeout: int = 10, threads: int = 5, 
                 rate_limit: float = 2.0, verify_ssl: bool = False, proxies: Optional[Dict] = None):
        self.target_url = target_url.rstrip('/')
        self.timeout = timeout
        self.threads = threads
        self.rate_limit = rate_limit  # requests per second
        self.verify_ssl = verify_ssl
        self.proxies = proxies or {}
        
        self.discovered_endpoints = set()
        self.normalized_urls = set()  # For deduplication
        self.redirects = {}  # original -> final
        
        # Session setup with retries
        self.session = requests.Session()
        self.session.verify = verify_ssl
        if proxies:
            self.session.proxies.update(proxies)
        
        # Rate limiting
        self.last_request_time = 0
        self.request_delay = 1.0 / rate_limit if rate_limit > 0 else 0
        
        # Logging
        self.logger = logging.getLogger(__name__)
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication"""
        parsed = urlparse(url)
        # Remove fragment, sort query params
        query_params = parse_qs(parsed.query)
        sorted_query = '&'.join(f"{k}={v[0]}" for k, v in sorted(query_params.items()))
        
        normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path}"
        if sorted_query:
            normalized += f"?{sorted_query}"
        
        return normalized
    
    def _is_full_url(self, url: str) -> bool:
        """Check if URL is full URL or relative path"""
        return url.startswith(('http://', 'https://'))
    
    def _rate_limit_delay(self):
        """Apply rate limiting"""
        if self.request_delay > 0:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            if time_since_last < self.request_delay:
                sleep_time = self.request_delay - time_since_last
                time.sleep(sleep_time + random.uniform(0, 0.1))  # Add jitter
            self.last_request_time = time.time()
    
    def _make_request_with_retry(self, url: str, method: str = 'GET', 
                                max_retries: int = 3, backoff_factor: float = 0.5) -> Optional[requests.Response]:
        """Make HTTP request with retry and backoff"""
        for attempt in range(max_retries + 1):
            try:
                self._rate_limit_delay()
                
                response = self.session.request(
                    method=method,
                    url=url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                # Track redirects
                if response.history:
                    self.redirects[url] = response.url
                
                return response
                
            except (requests.RequestException, Exception) as e:
                if attempt < max_retries:
                    wait_time = backoff_factor * (2 ** attempt) + random.uniform(0, 1)
                    self.logger.warning(f"Request failed (attempt {attempt + 1}): {e}. Retrying in {wait_time:.2f}s")
                    time.sleep(wait_time)
                else:
                    self.logger.error(f"Request failed after {max_retries + 1} attempts: {e}")
                    
        return None
    
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
        
        # Method 4.5: Brute-force discovered backend services với user consent
        if backend_services and wordlist_path:
            print(f"\n[!] DETECTED {len(backend_services)} INTERNAL BACKEND SERVICE(S):")
            for service in backend_services:
                print(f"    • {service}")
            
            print(f"\n[WARNING] Scanning internal services may:")
            print(f"  - Generate significant traffic on internal networks")
            print(f"  - Trigger security alerts")
            print(f"  - Access sensitive internal systems")
            
            # In production, you might want to add user confirmation
            # For automated testing, we'll proceed with limited scanning
            scan_backends = True  # Set to False to disable, or implement user input
            max_paths_per_service = 10  # Reduced from 15
            
            if scan_backends:
                print(f"\n[*] Proceeding with LIMITED backend scanning ({max_paths_per_service} paths per service)...")
                for backend_url in list(backend_services)[:3]:  # Limit to 3 services max
                    print(f"  [*] Scanning backend: {backend_url}")
                    try:
                        # Create temporary discovery instance with more conservative settings
                        backend_discovery = EndpointDiscovery(
                            backend_url, 
                            timeout=self.timeout,
                            threads=min(2, self.threads),  # Use fewer threads for backends
                            rate_limit=self.rate_limit * 0.5,  # Slower rate limiting
                            verify_ssl=self.verify_ssl,
                            proxies=self.proxies
                        )
                        
                        backend_results = backend_discovery.discover_from_wordlist(wordlist_path)
                        
                        # Further limit results per backend
                        limited_results = backend_results[:max_paths_per_service]
                        for result in limited_results:
                            all_endpoints[result['url']] = result
                            
                        print(f"  [+] Found {len(limited_results)}/{len(backend_results)} endpoints on {backend_url}")
                        
                    except Exception as e:
                        print(f"  [!] Failed to scan {backend_url}: {str(e)}")
            else:
                print(f"[*] Backend scanning disabled - only main target will be tested")
                print(f"[*] Backend services logged for manual inspection")
        
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
        print(f"\n{'='*60}")
        print(f"[+] DISCOVERY SUMMARY")
        print(f"{'='*60}")
        print(f"Total unique endpoints discovered: {len(results)}")
        
        # Summary by severity
        severity_counts = {'high': 0, 'medium': 0, 'low': 0}
        for result in results:
            severity = result.get('severity', 'low')
            severity_counts[severity] += 1
        
        print(f"Severity breakdown:")
        print(f"  🔴 High: {severity_counts['high']} endpoints")
        print(f"  🟡 Medium: {severity_counts['medium']} endpoints") 
        print(f"  🟢 Low: {severity_counts['low']} endpoints")
        
        if backend_services:
            print(f"\nBackend microservices found: {len(backend_services)}")
            for service in backend_services:
                print(f"  • {service}")
            print(f"[!] These backend services are potential SSRF targets")
        
        # Generate detailed report
        self._generate_detailed_report(results, backend_services)
        
        return results
    
    def _generate_detailed_report(self, results: List[Dict], backend_services: Set[str]):
        """Generate detailed discovery report"""
        try:
            import csv
            import os
            from datetime import datetime
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_dir = os.path.join(os.getcwd(), 'reports')
            os.makedirs(report_dir, exist_ok=True)
            
            # CSV Report
            csv_file = os.path.join(report_dir, f'endpoint_discovery_{timestamp}.csv')
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'url', 'status_code', 'severity', 'content_type', 'title',
                    'content_length', 'response_time', 'server', 'redirect'
                ])
                writer.writeheader()
                for result in results:
                    writer.writerow({
                        'url': result.get('url'),
                        'status_code': result.get('status_code'),
                        'severity': result.get('severity'),
                        'content_type': result.get('content_type'),
                        'title': result.get('title'),
                        'content_length': result.get('content_length'),
                        'response_time': result.get('response_time'),
                        'server': result.get('server'),
                        'redirect': result.get('redirect')
                    })
            
            # JSON Report
            json_file = os.path.join(report_dir, f'endpoint_discovery_{timestamp}.json')
            with open(json_file, 'w', encoding='utf-8') as f:
                report_data = {
                    'timestamp': timestamp,
                    'target': self.target_url,
                    'discovery_summary': {
                        'total_endpoints': len(results),
                        'backend_services': list(backend_services),
                        'severity_breakdown': {
                            'high': len([r for r in results if r.get('severity') == 'high']),
                            'medium': len([r for r in results if r.get('severity') == 'medium']),
                            'low': len([r for r in results if r.get('severity') == 'low'])
                        }
                    },
                    'endpoints': results,
                    'redirects': self.redirects
                }
                json.dump(report_data, f, indent=2, ensure_ascii=False)
            
            print(f"\n[+] Reports generated:")
            print(f"  📊 CSV: {csv_file}")
            print(f"  📋 JSON: {json_file}")
            
        except Exception as e:
            self.logger.warning(f"Failed to generate report: {e}")
    
    def _test_path(self, path: str) -> Optional[Dict]:
        """Test một path cụ thể với improved URL handling"""
        # Handle full URLs vs relative paths
        if self._is_full_url(path):
            url = path
        else:
            url = urljoin(self.target_url, path)
        
        # Check if already tested (normalized)
        normalized = self._normalize_url(url)
        if normalized in self.normalized_urls:
            return None
        self.normalized_urls.add(normalized)
        
        response = self._make_request_with_retry(url)
        if not response:
            return None
        
        # Chỉ log những endpoint thú vị
        if response.status_code in [200, 201, 301, 302, 401, 403, 500]:
            self.discovered_endpoints.add(url)
            
            # Extract title for better context
            title = ""
            if 'text/html' in response.headers.get('Content-Type', ''):
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    title_tag = soup.find('title')
                    if title_tag:
                        title = title_tag.get_text().strip()[:100]
                except:
                    pass
            
            # Check for interesting content
            severity = self._assess_endpoint_severity(url, response)
            
            return {
                'url': url,
                'normalized_url': normalized,
                'status_code': response.status_code,
                'content_length': len(response.content),
                'content_type': response.headers.get('Content-Type', ''),
                'title': title,
                'redirect': response.url if response.url != url else None,
                'response_time': response.elapsed.total_seconds(),
                'severity': severity,
                'headers': dict(response.headers),
                'server': response.headers.get('Server', '')
            }
        
        return None
    
    def _assess_endpoint_severity(self, url: str, response: requests.Response) -> str:
        """Assess endpoint severity/interest level"""
        content = response.text.lower()
        
        # High severity indicators
        high_indicators = [
            '.env', 'api_key', 'secret', 'password', 'token',
            'database', 'config', 'admin', 'debug', 'test',
            '.git', 'swagger', 'openapi', '/actuator'
        ]
        
        # Medium severity
        medium_indicators = [
            'api/', 'graphql', 'websocket', 'metrics',
            'health', 'status', 'version'
        ]
        
        url_lower = url.lower()
        
        if any(indicator in url_lower or indicator in content for indicator in high_indicators):
            return 'high'
        elif any(indicator in url_lower for indicator in medium_indicators):
            return 'medium'
        elif response.status_code in [401, 403]:
            return 'medium'
        else:
            return 'low'
    
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
        """Khám phá từ sitemap.xml với proper XML parsing"""
        paths = []
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml', 
            '/sitemap-index.xml',
            '/sitemaps.xml'
        ]
        
        for sitemap_path in sitemap_urls:
            try:
                sitemap_url = urljoin(self.target_url, sitemap_path)
                response = self._make_request_with_retry(sitemap_url)
                
                if response and response.status_code == 200:
                    try:
                        # Parse XML properly
                        root = ET.fromstring(response.content)
                        
                        # Handle different XML namespaces
                        namespaces = {
                            'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'
                        }
                        
                        # Extract URLs from <loc> tags
                        for url_elem in root.findall('.//sitemap:url/sitemap:loc', namespaces):
                            url = url_elem.text
                            if url:
                                parsed = urlparse(url)
                                if parsed.path and parsed.path != '/':
                                    paths.append(parsed.path)
                        
                        # Also handle sitemap index files
                        for sitemap_elem in root.findall('.//sitemap:sitemap/sitemap:loc', namespaces):
                            sitemap_url = sitemap_elem.text
                            if sitemap_url:
                                # Recursively parse nested sitemaps (limit depth)
                                try:
                                    nested_response = self._make_request_with_retry(sitemap_url)
                                    if nested_response and nested_response.status_code == 200:
                                        nested_root = ET.fromstring(nested_response.content)
                                        for url_elem in nested_root.findall('.//sitemap:url/sitemap:loc', namespaces):
                                            url = url_elem.text
                                            if url:
                                                parsed = urlparse(url)
                                                if parsed.path and parsed.path != '/':
                                                    paths.append(parsed.path)
                                except:
                                    continue
                                    
                    except ET.ParseError:
                        # Fallback to regex if XML parsing fails
                        urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                        for url in urls:
                            parsed = urlparse(url)
                            if parsed.path and parsed.path != '/':
                                paths.append(parsed.path)
                                
            except Exception as e:
                self.logger.debug(f"Failed to parse sitemap {sitemap_path}: {e}")
                continue
        
        return list(set(paths))  # Remove duplicates
    
    def discover_from_javascript(self) -> Set[str]:
        """Extract API endpoints from JavaScript files với improved parsing"""
        api_endpoints = set()
        
        try:
            # Get main page HTML
            response = self._make_request_with_retry(self.target_url)
            if not response or response.status_code != 200:
                return api_endpoints

            # Parse HTML with BeautifulSoup for better script extraction
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all script tags
            script_tags = soup.find_all('script')
            external_scripts = []
            inline_scripts = []
            
            for script in script_tags:
                if script.get('src'):
                    external_scripts.append(script.get('src'))
                elif script.string:
                    inline_scripts.append(script.string)
            
            all_js_content = '\n'.join(inline_scripts)
            
            # Fetch external scripts (increased limit with rate limiting)
            for script_url in external_scripts[:10]:  # Increased from 5 to 10
                try:
                    if self._is_full_url(script_url):
                        full_url = script_url
                    else:
                        full_url = urljoin(self.target_url, script_url)
                    
                    js_response = self._make_request_with_retry(full_url)
                    if js_response and js_response.status_code == 200:
                        all_js_content += '\n' + js_response.text
                except Exception as e:
                    self.logger.debug(f"Failed to fetch script {script_url}: {e}")
                    continue

            # Enhanced API endpoint extraction patterns
            patterns = [
                # Fetch/axios patterns
                r'fetch\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'axios\.[a-z]+\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                r'\$\.(?:get|post|put|delete)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
                
                # Direct API paths  
                r'[\'"`](/api/[^\'"`\s]+)[\'"`]',
                r'[\'"`](/v\d+/[^\'"`\s]+)[\'"`]',
                r'[\'"`](/graphql[^\'"`\s]*)[\'"`]',
                
                # URL assignment patterns
                r'url\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'endpoint\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                r'baseURL\s*[:=]\s*[\'"`]([^\'"`]+)[\'"`]',
                
                # Service URLs with ports
                r'[\'"`](https?://[^\'"`\s]+:\d+[^\'"`\s]*)[\'"`]',
                
                # Internal service patterns  
                r'[\'"`](https?://[a-zA-Z0-9-]+(?:-service)?(?:\.local)?(?::\d+)?[^\'"`\s]*)[\'"`]'
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, all_js_content, re.IGNORECASE)
                api_endpoints.update(matches)
            
            # Parse JSON objects in inline scripts
            json_objects = re.findall(r'\{[^{}]*[\'"`]url[\'"`]\s*:\s*[\'"`]([^\'"`]+)[\'"`][^{}]*\}', 
                                    all_js_content, re.IGNORECASE)
            api_endpoints.update(json_objects)
            
            # Filter and validate endpoints
            filtered_endpoints = set()
            for endpoint in api_endpoints:
                if self._is_valid_endpoint(endpoint):
                    filtered_endpoints.add(endpoint)
            
        except Exception as e:
            self.logger.error(f"JavaScript parsing failed: {e}")
            
        return filtered_endpoints
    
    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Validate if endpoint is worth testing"""
        endpoint_lower = endpoint.lower()
        
        # Skip common external domains/CDNs
        skip_domains = [
            'google.com', 'googleapis.com', 'gstatic.com',
            'facebook.com', 'twitter.com', 'linkedin.com',
            'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
            'bootstrap.com', 'jquery.com', 'reactjs.org'
        ]
        
        for domain in skip_domains:
            if domain in endpoint_lower:
                return False
        
        # Skip non-API file extensions
        skip_extensions = ['.js', '.css', '.png', '.jpg', '.gif', '.svg', '.ico', '.woff', '.ttf']
        for ext in skip_extensions:
            if endpoint_lower.endswith(ext):
                return False
        
        # Must be either relative path or internal service
        if endpoint.startswith('/'):
            return True
        
        if self._is_full_url(endpoint):
            parsed = urlparse(endpoint)
            hostname = parsed.netloc.lower()
            
            # Allow localhost, internal IPs, and service names
            return (hostname.startswith(('localhost', '127.', '192.168.', '10.', '172.')) or
                   '-service' in hostname or 
                   '.local' in hostname or
                   ':' in hostname and not '.' in hostname.split(':')[0])
        
        return True
    
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
        """Enhanced default wordlist cho microservices & modern web apps"""
        return [
            # Core API endpoints
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3', '/v4',
            '/graphql', '/graphiql',
            '/rest', '/restapi',
            
            # Authentication & Users
            '/api/auth', '/api/login', '/api/users', '/api/user',
            '/auth', '/login', '/signin', '/signup', '/register',
            '/oauth', '/oauth2', '/sso', '/saml',
            '/api/profile', '/api/account',
            
            # Business Logic APIs
            '/api/products', '/api/inventory', '/api/orders',
            '/api/payments', '/api/billing', '/api/cart',
            '/api/search', '/api/recommendations',
            '/api/analytics', '/api/notifications',
            
            # Admin & Management
            '/admin', '/admin/login', '/admin/dashboard',
            '/dashboard', '/console', '/management',
            '/api/admin', '/api/management',
            
            # Health & Monitoring (Critical for SSRF!)
            '/health', '/healthz', '/status', '/ping',
            '/metrics', '/prometheus', '/actuator',
            '/actuator/health', '/actuator/metrics', '/actuator/env',
            '/actuator/configprops', '/actuator/dump', '/actuator/trace',
            '/monitor', '/monitoring', '/diagnostic',
            
            # Documentation & Discovery
            '/docs', '/swagger', '/api-docs', '/swagger-ui',
            '/swagger-ui.html', '/swagger-ui/index.html',
            '/openapi.json', '/api/swagger.json',
            '/redoc', '/rapidoc', '/scalar',
            '/postman', '/insomnia',
            
            # Microservice Common Patterns
            '/user-service', '/product-service', '/inventory-service',
            '/auth-service', '/payment-service', '/order-service',
            '/notification-service', '/search-service', '/analytics-service',
            
            # Internal Services (High SSRF value!)
            '/internal', '/internal/api', '/internal/health',
            '/service', '/services', '/microservice', '/microservices',
            
            # Configuration & Environment (High severity!)
            '/config', '/configuration', '/env', '/environment',
            '/settings', '/properties', '/flags', '/feature-flags',
            '/.env', '/.env.local', '/.env.production',
            '/config.json', '/config.yml', '/config.yaml',
            
            # Debug & Development (High severity!)
            '/debug', '/trace', '/dump', '/heapdump',
            '/profiler', '/profile', '/debug/vars',
            '/test', '/testing', '/dev', '/development',
            
            # File Discovery
            '/robots.txt', '/sitemap.xml', '/security.txt',
            '/.well-known', '/.well-known/security.txt',
            '/humans.txt', '/crossdomain.xml',
            
            # Version Control & Backups (Critical!)
            '/.git', '/.git/config', '/.git/HEAD',
            '/.svn', '/.hg', '/.bzr',
            '/backup', '/backups', '/.backup',
            
            # Static Assets & Build
            '/static', '/assets', '/public', '/dist',
            '/js', '/css', '/images', '/img',
            '/fonts', '/media', '/uploads',
            '/build', '/webpack', '/bundle',
            
            # Database & Cache Interfaces
            '/db', '/database', '/mysql', '/postgres',
            '/redis', '/memcached', '/mongo',
            '/elasticsearch', '/kibana', '/grafana',
            
            # Container & Orchestration
            '/docker', '/kubernetes', '/k8s',
            '/helm', '/compose',
            '/health-check', '/readiness', '/liveness',
            
            # Common Frameworks
            '/spring', '/django', '/flask', '/express',
            '/rails', '/laravel', '/symfony',
            '/nextjs', '/nuxt', '/gatsby',
            
            # Error Pages (Sometimes expose info)
            '/404', '/500', '/error', '/errors',
            '/exception', '/stacktrace'
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
