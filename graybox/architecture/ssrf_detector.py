"""
SSRF Detector for Gray Box Testing
Phát hiện các SSRF vulnerabilities bằng cách phân tích:
- Docker network topology
- HTTP requests/parameters
- Service communication patterns
"""

import re
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urlparse, parse_qs
from dataclasses import dataclass
import logging

@dataclass
class SSRFEndpoint:
    """Detected SSRF endpoint"""
    url: str
    method: str
    parameter: str
    parameter_type: str  # 'query', 'body', 'header'
    confidence: str  # 'high', 'medium', 'low'
    reason: str
    potential_targets: List[str]
    detection_method: str  # 'pattern_match', 'network_topology', 'parameter_name'


class SSRFDetector:
    """
    Phát hiện SSRF endpoints bằng Gray Box approach
    Kết hợp:
    - Static patterns (URL/parameter names)
    - Network topology (Docker/K8s services)
    - Request analysis
    """
    
    # SSRF-prone parameter names (case-insensitive)
    SSRF_PARAMETER_NAMES = {
        'high_confidence': [
            'url', 'uri', 'link', 'href', 'redirect', 'return_url', 'redirect_uri',
            'callback', 'callback_url', 'webhook', 'webhook_url',
            'target', 'target_url', 'destination', 'dest',
            'endpoint', 'api_url', 'service_url', 'remote_url',
            'fetch_url', 'import_url', 'export_url', 'download_url',
            'review_url', 'avatar_url', 'image_url', 'file_url',
            'proxy', 'proxy_url', 'forward', 'forward_url'
        ],
        'medium_confidence': [
            'path', 'file', 'source', 'src', 'host', 'domain',
            'api', 'service', 'server', 'endpoint_url',
            'reference', 'ref', 'location', 'site',
            'validate', 'check_url', 'verify_url'
        ],
        'low_confidence': [
            'data', 'content', 'resource', 'link_to',
            'external', 'remote', 'upload'
        ]
    }
    
    # SSRF-prone URL patterns
    SSRF_URL_PATTERNS = [
        # Direct patterns
        r'/fetch[_-]?(?:url|resource|data)?',
        r'/webhook[s]?(?:/|$)',
        r'/callback[s]?(?:/|$)',
        r'/proxy(?:/|$)',
        r'/redirect(?:/|$)',
        r'/forward(?:/|$)',
        r'/import(?:/|$)',
        r'/export(?:/|$)',
        r'/download(?:/|$)',
        r'/upload(?:/|$)',
        r'/validate[_-]?(?:url|uri|link)?',
        r'/check[_-]?(?:url|uri|link)?',
        r'/verify[_-]?(?:url|uri|link)?',
        
        # API patterns
        r'/api/.*?/fetch',
        r'/api/.*?/webhook',
        r'/api/.*?/callback',
        r'/api/.*?/validate',
        r'/api/.*?/review',
        r'/api/.*?/avatar',
        r'/api/.*?/image',
        r'/api/.*?/file',
        
        # Specific vulnerable patterns
        r'/fetch_review',
        r'/fetch_data',
        r'/fetch_content',
        r'/get_url',
        r'/load_url',
        r'/open_url',
        r'/visit_url'
    ]
    
    # Internal service indicators
    INTERNAL_SERVICE_PATTERNS = [
        r'localhost',
        r'127\.0\.0\.\d+',
        r'10\.\d+\.\d+\.\d+',
        r'192\.168\.\d+\.\d+',
        r'172\.(1[6-9]|2[0-9]|3[01])\.\d+\.\d+',
        r'.*-service(?::\d+)?$',
        r'.*\.local(?::\d+)?$',
        r'^[a-zA-Z0-9-]+:\d+$'  # service-name:port format
    ]
    
    def __init__(self, docker_services: Optional[List[Dict]] = None, custom_parameters: Optional[List[str]] = None):
        """
        Args:
            docker_services: List of Docker services from DockerInspector
            custom_parameters: Custom parameter names to check (user-specified)
        """
        self.docker_services = docker_services or []
        self.custom_parameters = [p.lower() for p in (custom_parameters or [])]  # Normalize to lowercase
        self.logger = logging.getLogger(__name__)
        self.detected_endpoints: List[SSRFEndpoint] = []
    
    def detect_from_http_request(self, url: str, method: str, 
                                  query_params: Optional[Dict] = None,
                                  body_params: Optional[Dict] = None,
                                  headers: Optional[Dict] = None) -> List[SSRFEndpoint]:
        """
        Phát hiện SSRF từ HTTP request
        
        Args:
            url: Full URL của request
            method: HTTP method
            query_params: URL query parameters
            body_params: Body parameters (JSON/form data)
            headers: HTTP headers
            
        Returns:
            List of detected SSRF endpoints
        """
        findings = []
        
        # Parse URL
        parsed = urlparse(url)
        path = parsed.path
        
        # 1. Check URL path patterns
        path_confidence = self._check_url_pattern(path)
        if path_confidence:
            findings.append(SSRFEndpoint(
                url=url,
                method=method,
                parameter='N/A',
                parameter_type='path',
                confidence=path_confidence,
                reason=f'URL path matches SSRF pattern: {path}',
                potential_targets=self._get_potential_targets(),
                detection_method='pattern_match'
            ))
        
        # 2. Check query parameters
        if query_params:
            for param_name, param_value in query_params.items():
                confidence = self._check_parameter_name(param_name)
                if confidence:
                    # Check if value looks like URL/internal service
                    value_confidence = self._check_parameter_value(param_value)
                    
                    # If both name and value are suspicious, upgrade confidence
                    if value_confidence == 'high':
                        final_confidence = 'high'
                    elif value_confidence == 'medium' and confidence == 'high':
                        final_confidence = 'high'
                    else:
                        final_confidence = confidence if not value_confidence else max(confidence, value_confidence)
                    
                    findings.append(SSRFEndpoint(
                        url=url,
                        method=method,
                        parameter=param_name,
                        parameter_type='query',
                        confidence=final_confidence,
                        reason=f'Query parameter "{param_name}" is SSRF-prone',
                        potential_targets=self._get_potential_targets(),
                        detection_method='parameter_name'
                    ))
        
        # 3. Check body parameters
        if body_params:
            for param_name, param_value in body_params.items():
                confidence = self._check_parameter_name(param_name)
                if confidence:
                    value_confidence = self._check_parameter_value(param_value)
                    
                    # If both name and value are suspicious, upgrade confidence
                    if value_confidence == 'high':
                        final_confidence = 'high'
                    elif value_confidence == 'medium' and confidence == 'high':
                        final_confidence = 'high'
                    else:
                        final_confidence = confidence if not value_confidence else max(confidence, value_confidence)
                    
                    findings.append(SSRFEndpoint(
                        url=url,
                        method=method,
                        parameter=param_name,
                        parameter_type='body',
                        confidence=final_confidence,
                        reason=f'Body parameter "{param_name}" is SSRF-prone',
                        potential_targets=self._get_potential_targets(),
                        detection_method='parameter_name'
                    ))
        
        # 4. Check headers (less common but possible)
        if headers:
            suspicious_headers = ['X-Forwarded-For', 'X-Real-IP', 'Referer', 'Location']
            for header_name in suspicious_headers:
                if header_name in headers:
                    findings.append(SSRFEndpoint(
                        url=url,
                        method=method,
                        parameter=header_name,
                        parameter_type='header',
                        confidence='low',
                        reason=f'Header "{header_name}" might be processed server-side',
                        potential_targets=self._get_potential_targets(),
                        detection_method='header_analysis'
                    ))
        
        self.detected_endpoints.extend(findings)
        return findings
    
    def detect_from_burp_request(self, raw_request: str) -> List[SSRFEndpoint]:
        """
        Phát hiện SSRF từ raw HTTP request (Burp Suite format)
        
        Args:
            raw_request: Raw HTTP request string
            
        Returns:
            List of detected SSRF endpoints
        """
        findings = []
        
        try:
            # Parse raw request
            lines = raw_request.strip().split('\n')
            if not lines:
                return findings
            
            # Parse request line
            request_line = lines[0].strip()
            parts = request_line.split()
            if len(parts) < 2:
                return findings
            
            method = parts[0]
            url_path = parts[1]
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                line = line.strip()
                if not line:
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            # Get host
            host = headers.get('Host', '')
            full_url = f"https://{host}{url_path}" if host else url_path
            
            # Parse query parameters
            query_params = {}
            if '?' in url_path:
                query_string = url_path.split('?', 1)[1]
                parsed_qs = parse_qs(query_string)
                query_params = {k: v[0] if v else '' for k, v in parsed_qs.items()}
            
            # Parse body (if any)
            body_params = {}
            if body_start < len(lines):
                body = '\n'.join(lines[body_start:]).strip()
                if body:
                    # Try to parse as JSON
                    import json
                    try:
                        body_params = json.loads(body)
                    except:
                        # Try as form data
                        if 'application/x-www-form-urlencoded' in headers.get('Content-Type', ''):
                            parsed_form = parse_qs(body)
                            body_params = {k: v[0] if v else '' for k, v in parsed_form.items()}
            
            # Detect SSRF
            findings = self.detect_from_http_request(
                url=full_url,
                method=method,
                query_params=query_params,
                body_params=body_params,
                headers=headers
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing raw request: {e}")
        
        return findings
    
    def _check_url_pattern(self, path: str) -> Optional[str]:
        """
        Check if URL path matches SSRF patterns
        Returns: confidence level or None
        """
        path_lower = path.lower()
        
        for pattern in self.SSRF_URL_PATTERNS:
            if re.search(pattern, path_lower):
                # Determine confidence based on pattern specificity
                if any(word in path_lower for word in ['webhook', 'callback', 'fetch', 'proxy']):
                    return 'high'
                elif any(word in path_lower for word in ['validate', 'check', 'verify', 'review']):
                    return 'medium'
                else:
                    return 'low'
        
        return None
    
    def _check_parameter_name(self, param_name: str) -> Optional[str]:
        """
        Check if parameter name is SSRF-prone
        Returns: confidence level or None
        """
        param_lower = param_name.lower()
        
        # 🎯 Priority 1: Check custom parameters first (user-specified)
        if self.custom_parameters and param_lower in self.custom_parameters:
            return 'high'  # User knows what they're looking for - high confidence
        
        # Priority 2: Check high confidence names
        if param_lower in self.SSRF_PARAMETER_NAMES['high_confidence']:
            return 'high'
        
        # Priority 3: Check medium confidence names
        if param_lower in self.SSRF_PARAMETER_NAMES['medium_confidence']:
            return 'medium'
        
        # Priority 4: Check low confidence names
        if param_lower in self.SSRF_PARAMETER_NAMES['low_confidence']:
            return 'low'
        
        # Priority 5: Check partial matches for custom parameters
        if self.custom_parameters:
            for custom_param in self.custom_parameters:
                if custom_param in param_lower or param_lower in custom_param:
                    return 'medium'  # Partial match of custom param
        
        # Priority 6: Check partial matches for high confidence
        for keyword in self.SSRF_PARAMETER_NAMES['high_confidence']:
            if keyword in param_lower:
                return 'medium'  # Partial match = lower confidence
        
        return None
    
    def _check_parameter_value(self, value: str) -> Optional[str]:
        """
        Check if parameter value looks like internal service URL
        Returns: confidence level or None
        """
        if not isinstance(value, str):
            return None
        
        value_lower = value.lower()
        
        # Check for internal service patterns (high confidence)
        for pattern in self.INTERNAL_SERVICE_PATTERNS:
            if re.search(pattern, value_lower):
                return 'high'
        
        # Check for URL-like strings (medium confidence)
        if any(proto in value_lower for proto in ['http://', 'https://', 'ftp://']):
            return 'medium'
        
        return None
    
    def _get_potential_targets(self) -> List[str]:
        """
        Get list of potential internal targets based on Docker topology
        """
        targets = []
        
        # Add Docker services
        for service in self.docker_services:
            service_name = service.get('name', '')
            networks = service.get('networks', {})
            
            for network_name, network_info in networks.items():
                ip = network_info.get('ip_address')
                if ip:
                    targets.append(f"{service_name} ({ip})")
        
        # Add common internal ranges
        targets.extend([
            "localhost (127.0.0.1)",
            "Docker bridge network (172.17.0.0/16)",
            "Private network (192.168.0.0/16)",
            "Private network (10.0.0.0/8)"
        ])
        
        return targets
    
    def analyze_endpoints_batch(self, requests: List[Dict]) -> Dict:
        """
        Analyze multiple HTTP requests and generate report
        
        Args:
            requests: List of dicts with keys: url, method, query_params, body_params, headers
            
        Returns:
            Dict with analysis results
        """
        all_findings = []
        
        for req in requests:
            findings = self.detect_from_http_request(
                url=req.get('url', ''),
                method=req.get('method', 'GET'),
                query_params=req.get('query_params'),
                body_params=req.get('body_params'),
                headers=req.get('headers')
            )
            all_findings.extend(findings)
        
        # Group by confidence
        by_confidence = {
            'high': [f for f in all_findings if f.confidence == 'high'],
            'medium': [f for f in all_findings if f.confidence == 'medium'],
            'low': [f for f in all_findings if f.confidence == 'low']
        }
        
        return {
            'total_findings': len(all_findings),
            'by_confidence': by_confidence,
            'findings': all_findings,
            'summary': {
                'high_confidence': len(by_confidence['high']),
                'medium_confidence': len(by_confidence['medium']),
                'low_confidence': len(by_confidence['low'])
            }
        }
    
    def generate_report(self) -> str:
        """Generate text report of detected SSRF endpoints"""
        report = []
        report.append("=" * 80)
        report.append("SSRF DETECTION REPORT (GRAY BOX)")
        report.append("=" * 80)
        report.append(f"\nTotal detected endpoints: {len(self.detected_endpoints)}")
        
        # Group by confidence
        by_confidence = {}
        for endpoint in self.detected_endpoints:
            if endpoint.confidence not in by_confidence:
                by_confidence[endpoint.confidence] = []
            by_confidence[endpoint.confidence].append(endpoint)
        
        # Report by confidence level
        for confidence in ['high', 'medium', 'low']:
            endpoints = by_confidence.get(confidence, [])
            if endpoints:
                report.append(f"\n🔴 {confidence.upper()} CONFIDENCE ({len(endpoints)} findings)")
                report.append("-" * 80)
                
                for i, endpoint in enumerate(endpoints, 1):
                    report.append(f"\n{i}. {endpoint.url}")
                    report.append(f"   Method: {endpoint.method}")
                    report.append(f"   Parameter: {endpoint.parameter} ({endpoint.parameter_type})")
                    report.append(f"   Reason: {endpoint.reason}")
                    report.append(f"   Detection: {endpoint.detection_method}")
                    if endpoint.potential_targets:
                        report.append(f"   Targets: {', '.join(endpoint.potential_targets[:3])}...")
        
        report.append("\n" + "=" * 80)
        return "\n".join(report)


if __name__ == "__main__":
    # Test với request từ user
    detector = SSRFDetector()
    
    # Test case 1: /api/products/13/fetch_review/ với parameter review_url
    print("Test 1: Fetch Review Endpoint")
    findings1 = detector.detect_from_http_request(
        url="https://quangtx.io.vn/api/products/13/fetch_review/",
        method="POST",
        query_params=None,
        body_params={'review_url': 'http://example.com'},
        headers={}
    )
    for f in findings1:
        print(f"  - Found: {f.parameter} ({f.confidence} confidence)")
        print(f"    Reason: {f.reason}")
    
    # Test case 2: /api/users/me/avatar/validate với parameter url
    print("\nTest 2: Avatar Validate Endpoint")
    raw_request = """GET /api/users/me/avatar/validate?url=http://user-service:8081/api/users/1 HTTP/2
Host: quangtx.io.vn
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiVVNFUiIsInN1YiI6InVzZXIxIiwiaWF0IjoxNzY2MDQ4MzA3LCJleHAiOjE3NjYxMzQ3MDd9.cAqvSVQMVR2jnie5ZpAO5w3s3qBgxzGNW3NLcp7zzcg
Accept: application/json, text/plain, */*
"""
    findings2 = detector.detect_from_burp_request(raw_request)
    for f in findings2:
        print(f"  - Found: {f.parameter} ({f.confidence} confidence)")
        print(f"    Reason: {f.reason}")
    
    # Generate report
    print("\n" + detector.generate_report())
