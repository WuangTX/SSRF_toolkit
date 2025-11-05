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
            
            # 3. Parse JavaScript with multiple techniques
            endpoints = self._parse_javascript_content(js_content)
            
            # 4. Validate và filter endpoints
            for endpoint in endpoints:
                if self._is_valid_endpoint(endpoint):
                    all_endpoints.add(endpoint)
            
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
        """Extract axios calls"""
        patterns = [
            r'axios\.(get|post|put|delete|patch)\s*\(\s*[\'"`]([^\'"`]+)[\'"`]',
            r'axios\s*\(\s*\{\s*[^}]*url\s*:\s*[\'"`]([^\'"`]+)[\'"`]',
            r'axios\s*\(\s*[\'"`]([^\'"`]+)[\'"`]'
        ]
        
        endpoints = set()
        for pattern in patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if isinstance(matches[0], tuple) if matches else False:
                endpoints.update([match[1] if len(match) > 1 else match[0] for match in matches])
            else:
                endpoints.update(matches)
        
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
        """Extract potential API paths từ string literals"""
        # Look for strings that look like API paths
        api_patterns = [
            r'[\'"`](/api/[^\'"`\s]+)[\'"`]',
            r'[\'"`](/v\d+/[^\'"`\s]+)[\'"`]',
            r'[\'"`](/graphql[^\'"`\s]*)[\'"`]',
            r'[\'"`](/rest/[^\'"`\s]+)[\'"`]'
        ]
        
        endpoints = set()
        for pattern in api_patterns:
            matches = re.findall(pattern, content)
            endpoints.update(matches)
        
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
    
    def _is_valid_endpoint(self, endpoint: str) -> bool:
        """Validate endpoint có đáng test không"""
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
            parsed = urlparse(endpoint)
            hostname = parsed.netloc.lower()
            
            # Skip public domains
            public_domains = [
                'google.com', 'facebook.com', 'twitter.com',
                'github.com', 'stackoverflow.com', 'w3.org'
            ]
            
            for domain in public_domains:
                if domain in hostname:
                    return False
            
            # Only allow internal services
            if not self._is_internal_service(hostname):
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
    
    def _is_internal_service(self, hostname: str) -> bool:
        """Check if hostname is internal service"""
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