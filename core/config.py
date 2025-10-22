"""
Core Configuration Management
Quản lý cấu hình cho toàn bộ toolkit
"""

import json
import os
from dataclasses import dataclass, field
from typing import List, Dict, Optional

@dataclass
class BlackBoxConfig:
    """Cấu hình cho Black Box testing"""
    target_url: str
    timeout: int = 10
    threads: int = 5
    wordlist_path: str = "wordlists/common.txt"
    callback_server: Optional[str] = None
    
    # Auto Discovery Mode (Full Automation)
    auto_discovery: bool = False
    
    # Reconnaissance settings
    endpoint_discovery: bool = True
    parameter_fuzzing: bool = True
    port_scanning: bool = True
    
    # Detection settings
    external_callback_test: bool = True
    time_based_test: bool = True
    error_based_test: bool = True
    
    # Exploitation settings
    internal_scan: bool = True
    max_scan_ports: int = 100

@dataclass
class GrayBoxConfig:
    """Cấu hình cho Gray Box testing"""
    target_url: str
    docker_host: Optional[str] = None
    kubernetes_config: Optional[str] = None
    api_docs_path: Optional[str] = None
    architecture_file: Optional[str] = None
    
    # Architecture analysis
    docker_inspect: bool = True
    network_mapping: bool = True
    
    # API testing
    swagger_parse: bool = True
    targeted_endpoints: List[str] = field(default_factory=list)
    
    # Auth analysis
    auth_bypass_test: bool = True

@dataclass
class WhiteBoxConfig:
    """Cấu hình cho White Box testing"""
    source_code_path: str
    languages: List[str] = field(default_factory=lambda: ["python", "java", "javascript"])
    
    # Static analysis
    code_scan: bool = True
    dependency_check: bool = True
    config_audit: bool = True
    
    # Dynamic analysis
    instrumentation: bool = False
    runtime_trace: bool = False
    
    # Automated testing
    generate_tests: bool = True

@dataclass
class ToolkitConfig:
    """Cấu hình tổng thể"""
    mode: str  # "blackbox", "graybox", "whitebox", or "all"
    output_dir: str = "reports"
    log_level: str = "INFO"
    report_format: List[str] = field(default_factory=lambda: ["json", "html", "pdf"])
    
    blackbox: Optional[BlackBoxConfig] = None
    graybox: Optional[GrayBoxConfig] = None
    whitebox: Optional[WhiteBoxConfig] = None
    
    @classmethod
    def from_file(cls, config_file: str) -> 'ToolkitConfig':
        """Load config từ JSON file"""
        with open(config_file, 'r') as f:
            data = json.load(f)
        
        config = cls(
            mode=data.get('mode', 'all'),
            output_dir=data.get('output_dir', 'reports'),
            log_level=data.get('log_level', 'INFO'),
            report_format=data.get('report_format', ['json', 'html'])
        )
        
        # Load specific configs
        if 'blackbox' in data:
            config.blackbox = BlackBoxConfig(**data['blackbox'])
        if 'graybox' in data:
            config.graybox = GrayBoxConfig(**data['graybox'])
        if 'whitebox' in data:
            config.whitebox = WhiteBoxConfig(**data['whitebox'])
        
        return config
    
    def to_file(self, config_file: str):
        """Save config to JSON file"""
        data = {
            'mode': self.mode,
            'output_dir': self.output_dir,
            'log_level': self.log_level,
            'report_format': self.report_format
        }
        
        if self.blackbox:
            data['blackbox'] = self.blackbox.__dict__
        if self.graybox:
            data['graybox'] = self.graybox.__dict__
        if self.whitebox:
            data['whitebox'] = self.whitebox.__dict__
        
        with open(config_file, 'w') as f:
            json.dump(data, f, indent=2)

# Default configurations
DEFAULT_BLACKBOX_CONFIG = BlackBoxConfig(
    target_url="http://localhost:8083",
    timeout=10,
    threads=5
)

DEFAULT_GRAYBOX_CONFIG = GrayBoxConfig(
    target_url="http://localhost:8083",
    docker_host="unix:///var/run/docker.sock"
)

DEFAULT_WHITEBOX_CONFIG = WhiteBoxConfig(
    source_code_path=".",
    languages=["python", "java", "javascript"]
)
