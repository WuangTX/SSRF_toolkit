"""
HAR (HTTP Archive) File Parser
Extracts HTTP requests from Chrome/Firefox DevTools exports
"""
import json
from typing import List, Dict, Any
from urllib.parse import urlparse, parse_qs


class HARParser:
    """Parse HAR files to extract requests for SSRF testing"""
    
    def __init__(self, har_content: str):
        """
        Initialize with HAR file content
        
        Args:
            har_content: JSON string from HAR file
        """
        self.data = json.loads(har_content)
        self.requests = []
        self.endpoints = set()
        
    def parse(self) -> List[Dict[str, Any]]:
        """
        Parse HAR file and extract all HTTP requests
        
        Returns:
            List of request dictionaries with url, method, headers, params, body
        """
        entries = self.data.get('log', {}).get('entries', [])
        
        for entry in entries:
            request = entry.get('request', {})
            
            # Extract basic info
            method = request.get('method', 'GET')
            url = request.get('url', '')
            
            # Skip non-HTTP URLs
            if not url.startswith('http'):
                continue
                
            # Parse URL components
            parsed = urlparse(url)
            
            # Extract headers
            headers = {}
            for header in request.get('headers', []):
                name = header.get('name', '')
                value = header.get('value', '')
                headers[name] = value
            
            # Extract query parameters
            query_params = {}
            for param in request.get('queryString', []):
                name = param.get('name', '')
                value = param.get('value', '')
                query_params[name] = value
            
            # Extract POST data
            post_data = None
            if method in ['POST', 'PUT', 'PATCH']:
                post_data_obj = request.get('postData', {})
                
                # Handle different content types
                mime_type = post_data_obj.get('mimeType', '')
                
                if 'application/json' in mime_type:
                    # JSON body
                    text = post_data_obj.get('text', '{}')
                    try:
                        post_data = json.loads(text)
                    except:
                        post_data = {}
                        
                elif 'application/x-www-form-urlencoded' in mime_type:
                    # Form data
                    post_data = {}
                    for param in post_data_obj.get('params', []):
                        name = param.get('name', '')
                        value = param.get('value', '')
                        post_data[name] = value
                else:
                    # Raw text
                    post_data = post_data_obj.get('text', '')
            
            # Build request object
            request_obj = {
                'url': url,
                'method': method,
                'headers': headers,
                'query_params': query_params,
                'post_data': post_data,
                'scheme': parsed.scheme,
                'host': parsed.netloc,
                'path': parsed.path,
                'timestamp': entry.get('startedDateTime', '')
            }
            
            self.requests.append(request_obj)
            
            # Track unique endpoints (method + path)
            endpoint_key = f"{method} {parsed.path}"
            self.endpoints.add(endpoint_key)
        
        return self.requests
    
    def get_endpoints(self) -> List[str]:
        """
        Get list of unique endpoints
        
        Returns:
            List of unique endpoint strings (method + path)
        """
        return sorted(list(self.endpoints))
    
    def filter_internal(self, allowed_hosts: List[str] = None) -> List[Dict[str, Any]]:
        """
        Filter requests to only include internal/target hosts
        
        Args:
            allowed_hosts: List of allowed hostnames (e.g., ['localhost', '192.168.1.100'])
        
        Returns:
            Filtered list of requests
        """
        if not allowed_hosts:
            # Default to localhost and private IPs
            allowed_hosts = ['localhost', '127.0.0.1']
        
        filtered = []
        for req in self.requests:
            host = req['host']
            
            # Check if host matches allowed list
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
        """
        Extract all parameter names from requests
        
        Returns:
            Dict with 'query' and 'post' parameter name sets
        """
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
        """
        Get requests that contain authentication headers
        
        Returns:
            List of requests with auth headers (Bearer, Cookie, etc.)
        """
        auth_requests = []
        
        for req in self.requests:
            headers = req['headers']
            
            # Check for common auth headers
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
        """
        Get statistics about parsed HAR file
        
        Returns:
            Dict with statistics
        """
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


def parse_har_file(file_path: str) -> HARParser:
    """
    Parse HAR file from disk
    
    Args:
        file_path: Path to .har file
    
    Returns:
        HARParser instance
    """
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    parser = HARParser(content)
    parser.parse()
    return parser


def parse_har_content(content: str) -> HARParser:
    """
    Parse HAR content from string
    
    Args:
        content: HAR JSON string
    
    Returns:
        HARParser instance
    """
    parser = HARParser(content)
    parser.parse()
    return parser


# Example usage
if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python har_parser.py <har_file>")
        sys.exit(1)
    
    har_file = sys.argv[1]
    parser = parse_har_file(har_file)
    
    print("\n=== HAR File Statistics ===")
    stats = parser.get_stats()
    print(f"Total Requests: {stats['total_requests']}")
    print(f"Unique Endpoints: {stats['unique_endpoints']}")
    print(f"Methods: {stats['methods']}")
    print(f"Hosts: {', '.join(stats['hosts'])}")
    print(f"Authenticated Requests: {stats['authenticated_requests']}")
    
    print("\n=== Unique Endpoints ===")
    for endpoint in parser.get_endpoints()[:20]:  # Show first 20
        print(f"  {endpoint}")
    
    print("\n=== Parameters Found ===")
    params = parser.extract_parameters()
    print(f"Query params: {', '.join(list(params['query'])[:10])}")
    print(f"POST params: {', '.join(list(params['post'])[:10])}")
