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
        
        # Method 3: Wordlist brute-force
        if wordlist_path:
            print("[*] Brute-forcing with wordlist...")
            wordlist_results = self.discover_from_wordlist(wordlist_path)
            for result in wordlist_results:
                all_endpoints[result['url']] = result
        
        # Method 4: Spider (lightweight crawl)
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
