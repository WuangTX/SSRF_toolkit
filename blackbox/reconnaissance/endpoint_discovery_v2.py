"""
Enhanced Endpoint Discovery Module v2.0
Xây dựng lại từ đầu với kiểm tra chặt chẽ và chính xác cao
"""

import requests
import asyncio
import aiohttp
import time
import random
import re
import json
import xml.etree.ElementTree as ET
from urllib.parse import urljoin, urlparse, parse_qs, unquote
from typing import List, Set, Dict, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from bs4 import BeautifulSoup
import logging
from dataclasses import dataclass
from pathlib import Path
import csv
from datetime import datetime
from .js_analyzer import JavaScriptAnalyzer


@dataclass
class EndpointResult:
    """Structured endpoint result"""
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
    source: str  # 'wordlist', 'sitemap', 'javascript', 'crawl', 'robots'
    parameters: List[str]
    headers: Dict[str, str]
    accepts_post: bool = False  # NEW: Endpoint accepts POST requests
    post_params: List[str] = None  # NEW: POST parameters discovered
    ssrf_potential: str = 'unknown'  # NEW: 'high', 'medium', 'low', 'unknown'
    error: Optional[str] = None


class URLValidator:
    """Chặt chẽ validate URLs và paths"""
    
    @staticmethod
    def is_valid_url(url: str) -> bool:
        """Kiểm tra URL có hợp lệ không"""
        try:
            parsed = urlparse(url)
            return bool(parsed.scheme and parsed.netloc)
        except:
            return False
    
    @staticmethod
    def is_internal_url(url: str, base_url: str) -> bool:
        """Kiểm tra URL có phải internal không"""
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            
            # Same domain
            if parsed_url.netloc == parsed_base.netloc:
                return True
            
            hostname = parsed_url.netloc.lower()
            
            # Internal IP ranges và localhost
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
        except:
            return False
    
    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalize path để loại bỏ duplicate"""
        if not path:
            return '/'
        
        # Remove multiple slashes
        path = re.sub(r'/+', '/', path)
        
        # Remove trailing slash except for root
        if len(path) > 1 and path.endswith('/'):
            path = path.rstrip('/')
        
        # URL decode
        try:
            path = unquote(path)
        except:
            pass
        
        return path
    
    @staticmethod
    def is_interesting_path(path: str) -> bool:
        """Kiểm tra path có thú vị cho SSRF testing không"""
        path_lower = path.lower()
        
        # Skip static files
        static_extensions = [
            '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
            '.woff', '.woff2', '.ttf', '.eot', '.pdf', '.zip', '.tar', '.gz'
        ]
        
        for ext in static_extensions:
            if path_lower.endswith(ext):
                return False
        
        # Skip common non-API paths
        skip_patterns = [
            r'/static/',
            r'/assets/',
            r'/images/',
            r'/img/',
            r'/css/',
            r'/js/',
            r'/fonts/',
            r'/media/',
            r'/uploads/',
            r'/node_modules/',
            r'/__pycache__/',
            r'/\.git/',
            r'/\.svn/'
        ]
        
        for pattern in skip_patterns:
            if re.search(pattern, path_lower):
                return False
        
        return True


class EndpointDiscoveryV2:
    """Enhanced endpoint discovery với kiểm tra chặt chẽ"""
    
    def __init__(self, 
                 target_url: str,
                 timeout: int = 10,
                 max_workers: int = 5,
                 rate_limit: float = 2.0,
                 verify_ssl: bool = False,
                 proxies: Optional[Dict] = None,
                 user_agent: str = None):
        
        self.target_url = target_url.rstrip('/')
        self.base_url = self.target_url  # Alias for JavaScript analyzer compatibility
        self.timeout = timeout
        self.max_workers = 1  # Giảm xuống 1 để tránh rate limit
        self.rate_limit = 0.5  # 0.5 requests per second (1 request per 2 seconds)
        self.verify_ssl = verify_ssl
        self.proxies = proxies or {}
        
        # Parse target info
        self.parsed_target = urlparse(self.target_url)
        self.base_domain = self.parsed_target.netloc
        
        # User agent
        self.user_agent = user_agent or (
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
            '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        )
        
        # Session setup
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.session.timeout = timeout
        if proxies:
            self.session.proxies.update(proxies)
        
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        # Rate limiting
        self.last_request_time = 0
        
        # Results storage
        self.discovered_endpoints: List[EndpointResult] = []
        self.tested_urls: Set[str] = set()
        self.backend_services: Set[str] = set()
        
        # Statistics
        self.stats = {
            'total_requests': 0,
            'successful_requests': 0,
            'failed_requests': 0,
            'unique_endpoints': 0,
            'backend_services_found': 0
        }
        
        # Setup logging
        self.logger = logging.getLogger(__name__)
    
    def _rate_limit(self):
        """Apply rate limiting với jitter"""
        if self.rate_limit <= 0:
            return
        
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        required_delay = 1.0 / self.rate_limit
        
        if time_since_last < required_delay:
            sleep_time = required_delay - time_since_last
            # Add jitter (±20%)
            jitter = random.uniform(-0.2, 0.2) * sleep_time
            time.sleep(sleep_time + jitter)
        
        self.last_request_time = time.time()
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Make HTTP request với error handling và retry"""
        if url in self.tested_urls:
            return None
        
        self.tested_urls.add(url)
        
        # Validate URL
        if not URLValidator.is_valid_url(url):
            self.logger.warning(f"Invalid URL: {url}")
            return None
        
        self._rate_limit()
        
        try:
            self.stats['total_requests'] += 1
            
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                allow_redirects=True,
                **kwargs
            )
            
            self.stats['successful_requests'] += 1
            return response
            
        except requests.exceptions.RequestException as e:
            self.stats['failed_requests'] += 1
            self.logger.debug(f"Request failed for {url}: {e}")
            return None
        except Exception as e:
            self.stats['failed_requests'] += 1
            self.logger.error(f"Unexpected error for {url}: {e}")
            return None
    
    def _assess_severity(self, url: str, response: requests.Response) -> str:
        """Đánh giá độ nghiêm trọng của endpoint"""
        url_lower = url.lower()
        content_lower = response.text[:1000].lower()  # Only check first 1KB
        
        # Critical severity indicators
        critical_patterns = [
            r'\.env', r'\.git', r'\.svn', r'backup', r'dump',
            r'config\.', r'database\.', r'db\.', r'secret',
            r'admin/config', r'/.aws/', r'/.ssh/'
        ]
        
        # High severity indicators  
        high_patterns = [
            r'/admin', r'/debug', r'/test', r'/actuator',
            r'/management', r'/console', r'/api/admin',
            r'api_key', r'password', r'token', r'secret',
            r'/internal', r'/private'
        ]
        
        # Medium severity indicators
        medium_patterns = [
            r'/api/', r'/graphql', r'/health', r'/status',
            r'/metrics', r'/swagger', r'/docs',
            r'/version', r'/info'
        ]
        
        # Check URL patterns
        for pattern in critical_patterns:
            if re.search(pattern, url_lower):
                return 'critical'
        
        for pattern in high_patterns:
            if re.search(pattern, url_lower):
                return 'high'
        
        for pattern in medium_patterns:
            if re.search(pattern, url_lower):
                return 'medium'
        
        # Check content patterns
        content_indicators = {
            'critical': [r'database', r'password', r'api_key', r'secret_key'],
            'high': [r'admin', r'unauthorized', r'forbidden'],
            'medium': [r'api', r'json', r'xml']
        }
        
        for severity, patterns in content_indicators.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    return severity
        
        # Check status code
        if response.status_code in [401, 403]:
            return 'medium'
        elif response.status_code in [500, 502, 503]:
            return 'low'
        
        return 'low'
    
    def _extract_title(self, response: requests.Response) -> str:
        """Extract title từ HTML response"""
        if 'text/html' not in response.headers.get('Content-Type', ''):
            return ''
        
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            title_tag = soup.find('title')
            if title_tag:
                return title_tag.get_text().strip()[:100]
        except:
            pass
        
        return ''

    def _test_post_capability(self, url: str) -> Tuple[bool, List[str], str]:
        """
        Test xem endpoint có accept POST requests không và assess SSRF potential
        
        Returns:
            (accepts_post, discovered_params, ssrf_potential)
        """
        try:
            # Test với OPTIONS method trước
            options_response = self._make_request(url, 'OPTIONS')
            allowed_methods = []
            
            if options_response:
                allow_header = options_response.headers.get('Allow', '')
                allowed_methods = [m.strip().upper() for m in allow_header.split(',')]
            
            # Test POST với common SSRF payloads
            ssrf_test_payloads = {
                # JSON payloads
                'application/json': [
                    '{"url": "http://example.com"}',
                    '{"callback": "http://example.com"}', 
                    '{"webhook": "http://example.com"}',
                    '{"redirect": "http://example.com"}',
                    '{"target": "http://example.com"}',
                    '{"endpoint": "http://example.com"}',
                    '{"api_url": "http://example.com"}',
                    '{"service_url": "http://example.com"}'
                ],
                # Form data payloads  
                'application/x-www-form-urlencoded': [
                    'url=http://example.com',
                    'callback=http://example.com',
                    'webhook=http://example.com', 
                    'redirect=http://example.com',
                    'target=http://example.com',
                    'endpoint=http://example.com'
                ],
                # XML payloads
                'application/xml': [
                    '<url>http://example.com</url>',
                    '<callback>http://example.com</callback>',
                    '<webhook>http://example.com</webhook>'
                ]
            }
            
            accepts_post = False
            discovered_params = []
            ssrf_potential = 'unknown'
            highest_potential = 0  # 0=unknown, 1=low, 2=medium, 3=high
            
            # Test each content type
            for content_type, payloads in ssrf_test_payloads.items():
                for payload in payloads:
                    try:
                        headers = {'Content-Type': content_type}
                        post_response = self.session.post(
                            url, 
                            data=payload,
                            headers=headers,
                            timeout=self.timeout,
                            allow_redirects=False  # Don't follow redirects for SSRF testing
                        )
                        
                        # Endpoint accepts POST if we get any meaningful response
                        if post_response.status_code not in [404, 501]:
                            accepts_post = True
                            
                            # Assess SSRF potential based on response
                            potential_score = self._assess_ssrf_potential(
                                url, post_response, payload, content_type
                            )
                            
                            if potential_score > highest_potential:
                                highest_potential = potential_score
                            
                            # Extract parameter name từ payload
                            param_name = self._extract_param_from_payload(payload, content_type)
                            if param_name and param_name not in discovered_params:
                                discovered_params.append(param_name)
                    
                    except requests.exceptions.RequestException:
                        continue
                    
                    # Rate limiting
                    time.sleep(0.1)
            
            # Convert score to string
            if highest_potential >= 3:
                ssrf_potential = 'high'
            elif highest_potential >= 2:
                ssrf_potential = 'medium'
            elif highest_potential >= 1:
                ssrf_potential = 'low'
            else:
                ssrf_potential = 'unknown'
            
            return accepts_post, discovered_params, ssrf_potential
            
        except Exception as e:
            self.logger.debug(f"POST capability test failed for {url}: {e}")
            return False, [], 'unknown'

    def _assess_ssrf_potential(self, url: str, response: requests.Response, payload: str, content_type: str) -> int:
        """
        Assess SSRF potential based on response patterns
        Returns: 0=unknown, 1=low, 2=medium, 3=high
        """
        url_lower = url.lower()
        response_text = response.text.lower()
        
        # High potential indicators
        high_indicators = [
            # URL patterns
            '/webhook', '/callback', '/api/webhook', '/api/callback',
            '/notify', '/notification', '/fetch', '/proxy',
            '/redirect', '/forward', '/import', '/export',
            
            # Response patterns indicating URL processing
            'invalid url', 'malformed url', 'connection refused',
            'connection timeout', 'host not found', 'dns resolution',
            'failed to connect', 'network unreachable'
        ]
        
        # Medium potential indicators
        medium_indicators = [
            '/api/', '/service/', '/internal/', '/admin/',
            'bad request', 'invalid input', 'parameter missing',
            'json parse', 'xml parse', 'validation error'
        ]
        
        # Response status code analysis
        if response.status_code in [400, 422]:  # Bad request often means parameter processed
            if any(indicator in response_text for indicator in high_indicators):
                return 3
            elif any(indicator in response_text for indicator in medium_indicators):
                return 2
            else:
                return 1
        
        # URL pattern analysis
        if any(pattern in url_lower for pattern in high_indicators):
            return 3
        elif any(pattern in url_lower for pattern in medium_indicators):
            return 2
        
        # Content analysis
        if any(indicator in response_text for indicator in high_indicators):
            return 3
        elif any(indicator in response_text for indicator in medium_indicators):
            return 2
        
        # If endpoint accepts the POST but no clear indicators
        if response.status_code in [200, 201, 202]:
            return 1
        
        return 0

    def _extract_param_from_payload(self, payload: str, content_type: str) -> Optional[str]:
        """Extract parameter name from test payload"""
        try:
            if 'json' in content_type:
                # Extract from JSON: {"url": "..."} -> "url"
                match = re.search(r'"([^"]+)"\s*:\s*"http://example\.com"', payload)
                if match:
                    return match.group(1)
            
            elif 'form' in content_type:
                # Extract from form: url=http://example.com -> "url"
                match = re.search(r'([^=]+)=http://example\.com', payload)
                if match:
                    return match.group(1)
            
            elif 'xml' in content_type:
                # Extract from XML: <url>...</url> -> "url"
                match = re.search(r'<([^>]+)>http://example\.com</[^>]+>', payload)
                if match:
                    return match.group(1)
        
        except Exception:
            pass
        
        return None

    def _extract_parameters(self, url: str) -> List[str]:
        """Extract parameters từ URL"""
        try:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                return list(params.keys())
        except:
            pass
        
        return []
    
    def _test_endpoint(self, url: str, method: str = 'GET', source: str = 'unknown') -> Optional[EndpointResult]:
        """Test một endpoint và trả về kết quả structured"""
        start_time = time.time()
        response = self._make_request(url, method)
        
        if not response:
            return None
        
        response_time = time.time() - start_time
        
        # Only process interesting responses
        if response.status_code not in [200, 201, 301, 302, 401, 403, 404, 405, 500, 502, 503]:
            return None
        
        # Extract information
        title = self._extract_title(response)
        parameters = self._extract_parameters(url)
        severity = self._assess_severity(url, response)
        
        # NEW: Test POST method capability và SSRF potential
        accepts_post, post_params, ssrf_potential = self._test_post_capability(url)
        
        # Build result
        result = EndpointResult(
            url=url,
            method=method,
            status_code=response.status_code,
            content_length=len(response.content),
            content_type=response.headers.get('Content-Type', ''),
            response_time=response_time,
            title=title,
            server=response.headers.get('Server', ''),
            redirect_url=response.url if response.url != url else None,
            severity=severity,
            source=source,
            parameters=parameters,
            headers=dict(response.headers),
            accepts_post=accepts_post,
            post_params=post_params or [],
            ssrf_potential=ssrf_potential
        )
        
        self.discovered_endpoints.append(result)
        self.stats['unique_endpoints'] += 1
        
        return result
    
    def discover_from_wordlist(self, wordlist: Union[str, List[str]] = None) -> List[EndpointResult]:
        """Discover endpoints từ wordlist"""
        print("[*] Starting wordlist-based discovery...")
        
        # Get wordlist
        if isinstance(wordlist, str):
            try:
                with open(wordlist, 'r', encoding='utf-8') as f:
                    paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            except FileNotFoundError:
                self.logger.error(f"Wordlist file not found: {wordlist}")
                paths = self._get_default_wordlist()
        elif isinstance(wordlist, list):
            paths = wordlist
        else:
            paths = self._get_default_wordlist()
        
        # Filter và validate paths
        valid_paths = []
        for path in paths:
            if not path.startswith('/'):
                path = '/' + path
            
            normalized_path = URLValidator.normalize_path(path)
            
            if URLValidator.is_interesting_path(normalized_path):
                valid_paths.append(normalized_path)
        
        # Remove duplicates
        valid_paths = list(set(valid_paths))
        
        print(f"[*] Testing {len(valid_paths)} paths from wordlist...")
        
        results = []
        
        # Test paths với threading
        def test_path(path):
            url = urljoin(self.target_url, path)
            return self._test_endpoint(url, source='wordlist')
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(test_path, path): path for path in valid_paths}
            
            for i, future in enumerate(as_completed(futures)):
                result = future.result()
                if result:
                    results.append(result)
                    print(f"  [+] [{result.status_code}] {result.url} ({result.severity.upper()})")
                
                # Progress
                if (i + 1) % 20 == 0:
                    print(f"[*] Progress: {i + 1}/{len(valid_paths)}")
        
        print(f"[+] Wordlist discovery completed: {len(results)} endpoints found")
        return results
    
    def discover_from_sitemap(self) -> List[EndpointResult]:
        """Discover endpoints từ sitemap.xml"""
        print("[*] Checking sitemap.xml...")
        
        sitemap_urls = [
            '/sitemap.xml',
            '/sitemap_index.xml',
            '/sitemap-index.xml',
            '/sitemaps.xml'
        ]
        
        all_urls = set()
        
        for sitemap_path in sitemap_urls:
            sitemap_url = urljoin(self.target_url, sitemap_path)
            response = self._make_request(sitemap_url)
            
            if not response or response.status_code != 200:
                continue
            
            try:
                # Parse XML properly
                root = ET.fromstring(response.content)
                
                # Handle namespaces
                namespaces = {'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                
                # Extract URLs
                for loc in root.findall('.//sitemap:loc', namespaces):
                    if loc.text:
                        all_urls.add(loc.text)
                
                # Also handle simple XML without namespaces
                for loc in root.findall('.//loc'):
                    if loc.text:
                        all_urls.add(loc.text)
                        
            except ET.ParseError:
                # Fallback to regex
                urls = re.findall(r'<loc>(.*?)</loc>', response.text)
                all_urls.update(urls)
            except Exception as e:
                self.logger.debug(f"Sitemap parsing error: {e}")
        
        # Filter URLs
        valid_urls = []
        for url in all_urls:
            if URLValidator.is_valid_url(url):
                parsed = urlparse(url)
                if parsed.netloc == self.base_domain and URLValidator.is_interesting_path(parsed.path):
                    valid_urls.append(url)
        
        print(f"[*] Found {len(valid_urls)} URLs in sitemaps")
        
        # Test URLs
        results = []
        for url in valid_urls[:50]:  # Limit để tránh quá nhiều requests
            result = self._test_endpoint(url, source='sitemap')
            if result:
                results.append(result)
        
        print(f"[+] Sitemap discovery completed: {len(results)} endpoints found")
        return results
    
    def discover_from_robots(self) -> List[EndpointResult]:
        """Discover endpoints từ robots.txt"""
        print("[*] Checking robots.txt...")
        
        robots_url = urljoin(self.target_url, '/robots.txt')
        response = self._make_request(robots_url)
        
        if not response or response.status_code != 200:
            print("[*] No robots.txt found")
            return []
        
        paths = []
        
        for line in response.text.split('\n'):
            line = line.strip()
            if line.lower().startswith('disallow:'):
                path = line.split(':', 1)[1].strip()
                if path and path != '/' and URLValidator.is_interesting_path(path):
                    paths.append(path)
            elif line.lower().startswith('allow:'):
                path = line.split(':', 1)[1].strip()
                if path and URLValidator.is_interesting_path(path):
                    paths.append(path)
        
        print(f"[*] Found {len(paths)} paths in robots.txt")
        
        results = []
        for path in paths:
            url = urljoin(self.target_url, path)
            result = self._test_endpoint(url, source='robots')
            if result:
                results.append(result)
        
        print(f"[+] Robots.txt discovery completed: {len(results)} endpoints found")
        return results
    
    def _get_default_wordlist(self) -> List[str]:
        """High-quality default wordlist for endpoint discovery"""
        return [
            # Core API endpoints - most important for SSRF
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/v1', '/v2', '/v3', '/rest', '/restapi',
            '/graphql', '/graphiql',
            
            # Authentication endpoints - high value
            '/auth', '/login', '/signin', '/logout',
            '/api/auth', '/api/login', '/oauth', '/oauth2',
            '/sso', '/saml', '/oidc',
            
            # User management
            '/api/users', '/api/user', '/users', '/user',
            '/api/profile', '/profile', '/account',
            
            # Admin endpoints - critical for SSRF
            '/admin', '/administrator', '/admin/login',
            '/admin/dashboard', '/dashboard', '/panel',
            '/api/admin', '/management', '/console',
            
            # Health & monitoring - excellent SSRF targets
            '/health', '/healthz', '/status', '/ping',
            '/metrics', '/monitor', '/diagnostic',
            '/actuator', '/actuator/health', '/actuator/env',
            '/actuator/metrics', '/actuator/info',
            
            # Configuration - high severity
            '/config', '/configuration', '/settings',
            '/env', '/environment', '/.env',
            '/properties', '/flags',
            
            # Debug & development - high severity
            '/debug', '/test', '/testing', '/dev',
            '/trace', '/dump', '/heapdump',
            '/profiler', '/profile',
            
            # Documentation
            '/docs', '/documentation', '/swagger',
            '/swagger-ui', '/api-docs', '/openapi.json',
            '/redoc', '/graphiql',
            
            # Internal services - prime SSRF targets
            '/internal', '/private', '/service',
            '/microservice', '/backend',
            
            # File endpoints
            '/files', '/upload', '/download',
            '/static', '/assets', '/public',
            
            # Search & data
            '/search', '/api/search', '/query',
            '/data', '/export', '/import',
            
            # Webhooks & callbacks - excellent for SSRF
            '/webhook', '/webhooks', '/callback',
            '/api/webhook', '/api/callback',
            '/notify', '/notification',
            
            # Version control
            '/.git', '/.git/config', '/.svn',
            '/backup', '/backups',
            
            # Common business endpoints - enhanced for e-commerce
            '/orders', '/api/orders', '/order',
            '/products', '/api/products', '/product',
            '/inventory', '/api/inventory', '/stock',
            '/api/inventory/1', '/api/inventory/2', '/api/inventory/3',
            '/api/inventory/4', '/api/inventory/5', '/api/inventory/6',
            '/api/inventory/7', '/api/inventory/8', '/api/inventory/9',
            '/api/inventory/10', '/api/inventory/100',
            # Size variations for inventory
            '/api/inventory/1/s', '/api/inventory/1/m', '/api/inventory/1/l',
            '/api/inventory/2/s', '/api/inventory/2/m', '/api/inventory/2/l',
            '/api/inventory/3/s', '/api/inventory/3/m', '/api/inventory/3/l',
            '/api/inventory/4/s', '/api/inventory/4/m', '/api/inventory/4/l',
            '/api/inventory/5/s', '/api/inventory/5/m', '/api/inventory/5/l',
            '/api/inventory/6/s', '/api/inventory/6/m', '/api/inventory/6/l',
            '/api/inventory/7/s', '/api/inventory/7/m', '/api/inventory/7/l',
            '/api/inventory/8/s', '/api/inventory/8/m', '/api/inventory/8/l',
            '/api/inventory/9/s', '/api/inventory/9/m', '/api/inventory/9/l',
            '/api/inventory/10/s', '/api/inventory/10/m', '/api/inventory/10/l',
            # Product size variations
            '/api/products/1/s', '/api/products/1/m', '/api/products/1/l',
            '/api/products/2/s', '/api/products/2/m', '/api/products/2/l',
            '/api/products/3/s', '/api/products/3/m', '/api/products/3/l',
            '/api/products/4/s', '/api/products/4/m', '/api/products/4/l',
            '/api/products/5/s', '/api/products/5/m', '/api/products/5/l',
            '/api/products/6/s', '/api/products/6/m', '/api/products/6/l',
            # Payments and billing
            '/payments', '/api/payments', '/billing', '/api/billing',
            '/cart', '/api/cart', '/checkout', '/api/checkout',
            # Reports and analytics  
            '/reports', '/api/reports', '/analytics', '/api/analytics'
        ]
    
    def get_summary(self) -> Dict:
        """Get discovery summary"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        
        for endpoint in self.discovered_endpoints:
            severity_counts[endpoint.severity] += 1
        
        return {
            'total_endpoints': len(self.discovered_endpoints),
            'severity_breakdown': severity_counts,
            'backend_services': len(self.backend_services),
            'statistics': self.stats.copy(),
            'target_url': self.target_url
        }
    
    def export_results(self, format: str = 'json', filename: str = None) -> str:
        """Export results to file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'endpoint_discovery_{timestamp}'
        
        if format.lower() == 'json':
            filepath = f'{filename}.json'
            data = {
                'summary': self.get_summary(),
                'endpoints': [
                    {
                        'url': ep.url,
                        'method': ep.method,
                        'status_code': ep.status_code,
                        'severity': ep.severity,
                        'source': ep.source,
                        'title': ep.title,
                        'content_type': ep.content_type,
                        'response_time': ep.response_time,
                        'parameters': ep.parameters
                    }
                    for ep in self.discovered_endpoints
                ]
            }
            
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
                
        elif format.lower() == 'csv':
            filepath = f'{filename}.csv'
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['URL', 'Method', 'Status', 'Severity', 'Source', 'Title', 'Content-Type'])
                
                for ep in self.discovered_endpoints:
                    writer.writerow([ep.url, ep.method, ep.status_code, ep.severity, 
                                   ep.source, ep.title, ep.content_type])
        
        return filepath

    def discover_from_javascript(self, include_external=False):
        """
        Discover endpoints from JavaScript files and inline scripts.
        
        Args:
            include_external (bool): Whether to include external script analysis
            
        Returns:
            List[EndpointResult]: Discovered endpoints from JavaScript analysis
        """
        print("[+] Discovering endpoints from JavaScript...")
        
        try:
            # ✅ FIX: JavaScriptAnalyzer constructor takes (target_url, session, logger)
            js_analyzer = JavaScriptAnalyzer(self.base_url, self.session, self.logger)
            
            # Call discover_from_javascript() directly - it handles page fetching internally
            # Returns: Set[str] of endpoint URLs
            js_endpoints = js_analyzer.discover_from_javascript()
            
            results = []
            
            # ✅ FIX: js_endpoints is a Set[str], not list of dicts
            for endpoint_url in js_endpoints:
                # Create EndpointResult from JavaScript analysis
                result = EndpointResult(
                    url=endpoint_url,
                    method='GET',  # Default method
                    status_code=0,  # Will be validated
                    response_time=0.0,
                    content_length=0,
                    content_type='unknown',
                    server='',
                    redirect_url=None,
                    severity='unknown',
                    source='javascript',
                    parameters=[],
                    headers={},
                    accepts_post=False,
                    post_params=[],
                    ssrf_potential='unknown'
                )
                
                # Validate endpoint by making actual request
                validated_result = self._validate_endpoint(result)
                if validated_result:
                    results.append(validated_result)
            
            print(f"[+] Found {len(results)} valid endpoints from JavaScript analysis")
            return results
            
        except Exception as e:
            print(f"[-] Error in JavaScript discovery: {str(e)}")
            return []

    def _validate_endpoint(self, endpoint_result):
        """
        Validate an endpoint by making actual HTTP request.
        
        Args:
            endpoint_result (EndpointResult): Endpoint to validate
            
        Returns:
            EndpointResult or None: Updated result if valid, None if invalid
        """
        try:
            response = self._make_request(endpoint_result.url)
            if response:
                # Update with actual response data
                return EndpointResult(
                    url=endpoint_result.url,
                    status_code=response.status_code,
                    response_time=response.elapsed.total_seconds(),
                    content_length=len(response.content),
                    content_type=response.headers.get('content-type', 'unknown'),
                    server_header=response.headers.get('server', ''),
                    severity=endpoint_result.severity,
                    source=endpoint_result.source,
                    metadata=endpoint_result.metadata
                )
            return None
        except Exception:
            return None

    def discover_comprehensive(self):
        """
        Comprehensive endpoint discovery using all available methods.
        
        Returns:
            List[EndpointResult]: All discovered endpoints from all methods
        """
        print("🔍 Starting comprehensive endpoint discovery...")
        all_results = []
        
        # Method 1: Wordlist discovery
        print("\n1️⃣ Wordlist-based discovery...")
        wordlist_results = self.discover_from_wordlist()
        all_results.extend(wordlist_results)
        
        # Method 2: Sitemap discovery
        print("\n2️⃣ Sitemap discovery...")
        sitemap_results = self.discover_from_sitemap()
        all_results.extend(sitemap_results)
        
        # Method 3: Robots.txt discovery
        print("\n3️⃣ Robots.txt discovery...")
        robots_results = self.discover_from_robots()
        all_results.extend(robots_results)
        
        # Method 4: JavaScript discovery
        print("\n4️⃣ JavaScript discovery...")
        js_results = self.discover_from_javascript(include_external=False)
        all_results.extend(js_results)
        
        # Deduplicate results
        unique_results = self._deduplicate_results(all_results)
        
        print(f"\n✅ Comprehensive discovery complete!")
        print(f"Total unique endpoints found: {len(unique_results)}")
        
        return unique_results

    def _deduplicate_results(self, results: List[EndpointResult]) -> List[EndpointResult]:
        """
        Remove duplicate endpoints based on URL
        
        Args:
            results: List of EndpointResult objects
            
        Returns:
            List of unique EndpointResult objects
        """
        seen_urls = set()
        unique_results = []
        
        for result in results:
            if result.url not in seen_urls:
                seen_urls.add(result.url)
                unique_results.append(result)
        
        return unique_results


# Test function
if __name__ == "__main__":
    # Test the new discovery
    discovery = EndpointDiscoveryV2(
        target_url="https://httpbin.org",
        timeout=5,
        max_workers=3,
        rate_limit=2.0
    )
    
    print("🧪 Testing Enhanced Endpoint Discovery V2...")
    
    # Test wordlist discovery
    results = discovery.discover_from_wordlist()
    
    # Print summary
    summary = discovery.get_summary()
    print(f"\n📊 Discovery Summary:")
    print(f"Total endpoints: {summary['total_endpoints']}")
    print(f"Severity breakdown: {summary['severity_breakdown']}")
    print(f"Success rate: {summary['statistics']['successful_requests']}/{summary['statistics']['total_requests']}")