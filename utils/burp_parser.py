"""
Burp Suite Proxy History Parser
Extracts HTTP requests from Burp Suite exports (JSON/XML)
"""
import json
import xml.etree.ElementTree as ET
import base64
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs, unquote


class BurpParser:
    """Parse Burp Suite proxy history exports"""
    
    def __init__(self, content: str, format_type: str = 'auto'):
        """
        Initialize with Burp Suite export content
        
        Args:
            content: JSON or XML string from Burp Suite
            format_type: 'json', 'xml', or 'auto' (auto-detect)
        """
        self.content = content
        self.format_type = format_type
        self.requests = []
        self.endpoints = set()
        
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse Burp Suite export and extract all HTTP requests
        
        Returns:
            List of request dictionaries with url, method, headers, params, body
        """
        # Auto-detect format
        if self.format_type == 'auto':
            content_stripped = self.content.strip()
            if content_stripped.startswith('{') or content_stripped.startswith('['):
                self.format_type = 'json'
            elif content_stripped.startswith('<'):
                self.format_type = 'xml'
            else:
                raise ValueError("Unable to detect format (expected JSON or XML)")
        
        # Parse based on format
        if self.format_type == 'json':
            return self._parse_json()
        elif self.format_type == 'xml':
            return self._parse_xml()
        else:
            raise ValueError(f"Unsupported format: {self.format_type}")
    
    def _parse_json(self) -> List[Dict[str, Any]]:
        """Parse Burp Suite JSON format"""
        data = json.loads(self.content)
        
        # Burp Suite JSON can be array or object with items
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            items = data.get('items', [])
        else:
            items = []
        
        for item in items:
            try:
                req = self._parse_burp_item(item)
                if req:
                    self.requests.append(req)
                    
                    # Track unique endpoints
                    endpoint_key = f"{req['method']} {req['path']}"
                    self.endpoints.add(endpoint_key)
            except Exception as e:
                # Skip malformed items
                continue
        
        return self.requests
    
    def _parse_xml(self) -> List[Dict[str, Any]]:
        """Parse Burp Suite XML format"""
        root = ET.fromstring(self.content)
        
        # Find all <item> elements
        for item in root.findall('.//item'):
            try:
                req = self._parse_burp_item_xml(item)
                if req:
                    self.requests.append(req)
                    
                    # Track unique endpoints
                    endpoint_key = f"{req['method']} {req['path']}"
                    self.endpoints.add(endpoint_key)
            except Exception as e:
                # Skip malformed items
                continue
        
        return self.requests
    
    def _parse_burp_item(self, item: Dict) -> Dict[str, Any]:
        """Parse single Burp Suite JSON item"""
        # Extract request data
        request_data = item.get('request', '')
        
        # Decode base64 if needed
        if isinstance(request_data, str):
            try:
                request_raw = base64.b64decode(request_data).decode('utf-8', errors='ignore')
            except:
                request_raw = request_data
        else:
            request_raw = str(request_data)
        
        # Parse HTTP request
        return self._parse_http_request(request_raw, item)
    
    def _parse_burp_item_xml(self, item: ET.Element) -> Dict[str, Any]:
        """Parse single Burp Suite XML item"""
        # Extract request from XML
        request_elem = item.find('request')
        if request_elem is None:
            return None
        
        request_data = request_elem.text or ''
        
        # Decode base64
        try:
            request_raw = base64.b64decode(request_data).decode('utf-8', errors='ignore')
        except:
            request_raw = request_data
        
        # Build item dict for consistency
        item_dict = {
            'host': item.find('host').text if item.find('host') is not None else '',
            'port': item.find('port').text if item.find('port') is not None else '',
            'protocol': item.find('protocol').text if item.find('protocol') is not None else 'http',
            'url': item.find('url').text if item.find('url') is not None else '',
            'time': item.find('time').text if item.find('time') is not None else ''
        }
        
        return self._parse_http_request(request_raw, item_dict)
    
    def _parse_http_request(self, request_raw: str, metadata: Dict) -> Dict[str, Any]:
        """
        Parse raw HTTP request string
        
        Args:
            request_raw: Raw HTTP request (e.g., "GET /api/users HTTP/1.1\\nHost: example.com\\n...")
            metadata: Additional metadata from Burp Suite
        """
        lines = request_raw.split('\n')
        if not lines:
            return None
        
        # Parse request line (e.g., "GET /api/users HTTP/1.1")
        request_line_parts = lines[0].strip().split(' ')
        if len(request_line_parts) < 2:
            return None
        
        method = request_line_parts[0]
        path = request_line_parts[1]
        
        # Parse headers
        headers = {}
        body_start_idx = 1
        for idx, line in enumerate(lines[1:], start=1):
            line = line.strip()
            if not line:
                # Empty line indicates start of body
                body_start_idx = idx + 1
                break
            
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # Extract body
        body = '\n'.join(lines[body_start_idx:]).strip() if body_start_idx < len(lines) else ''
        
        # Parse URL
        host = headers.get('Host', metadata.get('host', ''))
        protocol = metadata.get('protocol', 'http')
        url = f"{protocol}://{host}{path}"
        
        # Parse URL components
        parsed = urlparse(url)
        
        # Extract query parameters
        query_params = {}
        if parsed.query:
            query_params = dict(parse_qs(parsed.query, keep_blank_values=True))
            # Flatten single-item lists
            for key, value in query_params.items():
                if isinstance(value, list) and len(value) == 1:
                    query_params[key] = value[0]
        
        # Parse POST data if present
        post_data = None
        if body and method in ['POST', 'PUT', 'PATCH']:
            content_type = headers.get('Content-Type', '')
            
            if 'application/json' in content_type:
                try:
                    post_data = json.loads(body)
                except:
                    post_data = body
            elif 'application/x-www-form-urlencoded' in content_type:
                post_data = dict(parse_qs(body, keep_blank_values=True))
                # Flatten single-item lists
                for key, value in post_data.items():
                    if isinstance(value, list) and len(value) == 1:
                        post_data[key] = value[0]
            else:
                post_data = body
        
        return {
            'url': url,
            'method': method,
            'headers': headers,
            'query_params': query_params,
            'post_data': post_data,
            'scheme': protocol,
            'host': host,
            'path': parsed.path,
            'timestamp': metadata.get('time', ''),
            'raw_request': request_raw
        }
    
    def get_endpoints(self) -> List[str]:
        """Get list of unique endpoints"""
        return sorted(list(self.endpoints))
    
    def filter_internal(self, allowed_hosts: List[str] = None) -> List[Dict[str, Any]]:
        """Filter requests to only include internal/target hosts"""
        if not allowed_hosts:
            allowed_hosts = ['localhost', '127.0.0.1']
        
        filtered = []
        for req in self.requests:
            host = req['host']
            
            is_allowed = False
            for allowed in allowed_hosts:
                if allowed in host:
                    is_allowed = True
                    break
            
            # Check for private IP ranges
            if (host.startswith('192.168.') or 
                host.startswith('10.') or 
                host.startswith('172.') or
                host.startswith('localhost') or
                host.startswith('127.')):
                is_allowed = True
            
            if is_allowed:
                filtered.append(req)
        
        return filtered
    
    def extract_parameters(self) -> Dict[str, set]:
        """Extract all parameter names from requests"""
        query_params = set()
        post_params = set()
        
        for req in self.requests:
            # Query parameters
            for param in req['query_params'].keys():
                query_params.add(param)
            
            # POST parameters
            if req['post_data'] and isinstance(req['post_data'], dict):
                for param in req['post_data'].keys():
                    post_params.add(param)
        
        return {
            'query': query_params,
            'post': post_params
        }
    
    def get_authenticated_requests(self) -> List[Dict[str, Any]]:
        """Get requests that contain authentication headers"""
        auth_requests = []
        
        for req in self.requests:
            headers = req['headers']
            
            has_auth = False
            for header_name, header_value in headers.items():
                header_lower = header_name.lower()
                
                if (header_lower == 'authorization' or
                    header_lower == 'cookie' or
                    header_lower == 'x-api-key' or
                    'token' in header_lower):
                    has_auth = True
                    break
            
            if has_auth:
                auth_requests.append(req)
        
        return auth_requests
    
    def get_stats(self) -> Dict[str, Any]:
        """Get statistics about parsed requests"""
        methods = {}
        content_types = set()
        hosts = set()
        
        for req in self.requests:
            # Count methods
            method = req['method']
            methods[method] = methods.get(method, 0) + 1
            
            # Track content types
            if 'Content-Type' in req['headers']:
                content_types.add(req['headers']['Content-Type'])
            
            # Track hosts
            hosts.add(req['host'])
        
        auth_count = len(self.get_authenticated_requests())
        
        return {
            'total_requests': len(self.requests),
            'unique_endpoints': len(self.endpoints),
            'methods': methods,
            'hosts': list(hosts),
            'content_types': list(content_types),
            'authenticated_requests': auth_count
        }


def parse_burp_file(file_path: str, format_type: str = 'auto') -> BurpParser:
    """
    Parse Burp Suite export file
    
    Args:
        file_path: Path to Burp Suite export file
        format_type: 'json', 'xml', or 'auto'
    
    Returns:
        BurpParser instance
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = BurpParser(content, format_type)
    parser.parse()
    return parser


def parse_burp_content(content: str, format_type: str = 'auto') -> BurpParser:
    """
    Parse Burp Suite export content
    
    Args:
        content: Burp Suite export string
        format_type: 'json', 'xml', or 'auto'
    
    Returns:
        BurpParser instance
    """
    parser = BurpParser(content, format_type)
    parser.parse()
    return parser


# Example usage
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python burp_parser.py <burp_export_file>")
        sys.exit(1)
    
    file_path = sys.argv[1]
    parser = parse_burp_file(file_path)
    
    print("\n=== Burp Suite Export Statistics ===")
    stats = parser.get_stats()
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Unique Endpoints: {stats['unique_endpoints']}")
    print(f"Methods: {stats['methods']}")
    print(f"Hosts: {', '.join(stats['hosts'])}")
    print(f"Authenticated Requests: {stats['authenticated_requests']}")
    
    print("\n=== Unique Endpoints ===")
    for endpoint in parser.get_endpoints()[:20]:
        print(f"  {endpoint}")
    
    print("\n=== Parameters Found ===")
    params = parser.extract_parameters()
    print(f"Query params: {', '.join(list(params['query'])[:10])}")
    print(f"POST params: {', '.join(list(params['post'])[:10])}")
    
    print("\n=== Authenticated Requests (first 5) ===")
    auth_reqs = parser.get_authenticated_requests()[:5]
    for req in auth_reqs:
        print(f"  {req['method']} {req['url']}")
        if 'Authorization' in req['headers']:
            auth_header = req['headers']['Authorization']
            print(f"    Auth: {auth_header[:50]}..." if len(auth_header) > 50 else f"    Auth: {auth_header}")
