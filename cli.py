"""
Microservice SSRF Pentest Toolkit - Main CLI
Công cụ tự động phát hiện và khai thác SSRF trong microservices
"""

import sys
import argparse
import time
from datetime import datetime
from pathlib import Path

# Import core modules
sys.path.insert(0, str(Path(__file__).parent))
from core.config import *
from core.logger import get_logger, init_logger
from core.database import FindingDatabase, Finding

# Import modules
from blackbox.reconnaissance.endpoint_discovery import EndpointDiscovery
from blackbox.reconnaissance.parameter_fuzzer import ParameterFuzzer
from blackbox.detection.external_callback import CallbackServer, ExternalCallbackDetector
from blackbox.exploitation.internal_scan import InternalScanner

from graybox.architecture.docker_inspector import DockerInspector

from whitebox.static_analysis.code_scanner import CodeScanner

class SSRFPentestToolkit:
    """Main toolkit orchestrator"""
    
    def __init__(self, config_file: str = None):
        if config_file:
            self.config = ToolkitConfig.from_file(config_file)
        else:
            self.config = self._create_default_config()
        
        self.logger = init_logger(self.config)
        self.db = FindingDatabase(f"{self.config.output_dir}/findings.db")
        self.session_id = None
        self.start_time = None
    
    def _create_default_config(self) -> ToolkitConfig:
        """Create default config"""
        return ToolkitConfig(
            mode='all',
            output_dir='reports',
            log_level='INFO'
        )
    
    def run(self):
        """Main entry point"""
        self.logger.banner("🎯 MICROSERVICE SSRF PENTEST TOOLKIT")
        
        self.start_time = time.time()
        self.session_id = self.db.start_session(
            mode=self.config.mode,
            target_url=getattr(self.config.blackbox, 'target_url', 'N/A'),
            config=self.config.__dict__
        )
        
        try:
            if self.config.mode == 'blackbox' or self.config.mode == 'all':
                self._run_blackbox()
            
            if self.config.mode == 'graybox' or self.config.mode == 'all':
                self._run_graybox()
            
            if self.config.mode == 'whitebox' or self.config.mode == 'all':
                self._run_whitebox()
            
            self._generate_report()
        
        finally:
            duration = time.time() - self.start_time
            findings_count = len(self.db.get_findings())
            self.db.end_session(self.session_id, duration, findings_count)
    
    def _run_blackbox(self):
        """Run Black Box testing"""
        self.logger.section("🕶️  BLACK BOX TESTING MODE")
        
        if not self.config.blackbox:
            self.logger.warning("Black Box config not provided, skipping...")
            return
        
        target_url = self.config.blackbox.target_url
        self.logger.info(f"Target: {target_url}")
        
        # Phase 1: Reconnaissance
        if self.config.blackbox.endpoint_discovery:
            self.logger.info("\n📡 Phase 1: Endpoint Discovery")
            discovery = EndpointDiscovery(target_url, timeout=self.config.blackbox.timeout)
            
            endpoints = discovery.discover_from_wordlist(
                self.config.blackbox.wordlist_path
            )
            
            self.logger.success(f"Discovered {len(endpoints)} endpoints")
            
            # Save discovered endpoints
            for endpoint in endpoints:
                if endpoint['status_code'] in [200, 201]:
                    self.logger.info(f"  [{endpoint['status_code']}] {endpoint['url']}")
        
        # Phase 2: Parameter Fuzzing
        if self.config.blackbox.parameter_fuzzing:
            self.logger.info("\n🔍 Phase 2: Parameter Fuzzing")
            fuzzer = ParameterFuzzer(timeout=self.config.blackbox.timeout)
            
            # Fuzz main endpoint
            fuzz_results = fuzzer.fuzz_endpoint(target_url)
            
            for result in fuzz_results:
                if result['is_vulnerable']:
                    self.logger.finding('HIGH', 
                        f"Potential SSRF parameter: {result['parameter']} "
                        f"(confidence: {result['confidence']:.2f})"
                    )
                    
                    # Save to database
                    finding = Finding(
                        mode='blackbox',
                        severity='HIGH',
                        category='SSRF',
                        title=f"Potential SSRF via parameter: {result['parameter']}",
                        description=f"Parameter '{result['parameter']}' shows SSRF indicators",
                        affected_url=target_url,
                        proof_of_concept=str(result['findings']),
                        cvss_score=7.5,
                        cwe_id='CWE-918'
                    )
                    self.db.add_finding(finding)
        
        # Phase 3: External Callback Testing
        if self.config.blackbox.external_callback_test:
            self.logger.info("\n🌐 Phase 3: External Callback Testing")
            
            # Start callback server
            callback_server = CallbackServer(host='0.0.0.0', port=8888)
            callback_server.start()
            
            detector = ExternalCallbackDetector(callback_server)
            
            # Test discovered parameters
            if fuzz_results:
                for result in fuzz_results:
                    if result['confidence'] >= 0.3:
                        test_result = detector.test_ssrf(
                            target_url,
                            result['parameter']
                        )
                        
                        if test_result['is_vulnerable']:
                            self.logger.finding('CRITICAL',
                                f"CONFIRMED SSRF: {result['parameter']}"
                            )
                            
                            # Save to database
                            finding = Finding(
                                mode='blackbox',
                                severity='CRITICAL',
                                category='SSRF',
                                title=f"Confirmed SSRF vulnerability",
                                description=f"External callback received from parameter '{result['parameter']}'",
                                affected_url=target_url,
                                proof_of_concept=str(test_result['callback_details']),
                                remediation="Implement URL whitelist and block private IP ranges",
                                cvss_score=9.1,
                                cwe_id='CWE-918'
                            )
                            self.db.add_finding(finding)
            
            callback_server.stop()
        
        # Phase 4: Internal Network Scanning
        if self.config.blackbox.internal_scan and fuzz_results:
            self.logger.info("\n🔬 Phase 4: Internal Network Scanning")
            
            # Use first vulnerable parameter
            vulnerable_params = [r for r in fuzz_results if r['is_vulnerable']]
            
            if vulnerable_params:
                param = vulnerable_params[0]['parameter']
                scanner = InternalScanner(target_url, param)
                
                self.logger.info("Discovering internal services...")
                services = scanner.discover_services()
                
                self.logger.success(f"Discovered {len(services)} internal services")
                
                for service in services:
                    self.logger.info(
                        f"  {service['host']}:{service['port']} - {service['service']}"
                    )
    
    def _run_graybox(self):
        """Run Gray Box testing"""
        self.logger.section("🔍 GRAY BOX TESTING MODE")
        
        if not self.config.graybox:
            self.logger.warning("Gray Box config not provided, skipping...")
            return
        
        # Docker Inspection
        if self.config.graybox.docker_inspect:
            self.logger.info("🐳 Docker Environment Analysis")
            
            inspector = DockerInspector(self.config.graybox.docker_host)
            
            if inspector.is_available:
                # Show network topology
                diagram = inspector.generate_network_diagram()
                self.logger.info("\n" + diagram)
                
                # Find SSRF targets
                targets = inspector.find_ssrf_targets()
                
                if targets:
                    self.logger.warning(f"\n⚠️  Found {len(targets)} potential SSRF attack paths:")
                    
                    for i, target in enumerate(targets, 1):
                        self.logger.info(f"{i}. {target['attack_scenario']}")
                        
                        # Save to database
                        finding = Finding(
                            mode='graybox',
                            severity='MEDIUM',
                            category='SSRF',
                            title="Potential SSRF attack path (network topology)",
                            description=target['attack_scenario'],
                            affected_url=self.config.graybox.target_url,
                            remediation="Implement network segmentation",
                            cvss_score=5.5,
                            cwe_id='CWE-918'
                        )
                        self.db.add_finding(finding)
                
                # Export to JSON
                inspector.export_to_json(f"{self.config.output_dir}/docker_inspection.json")
            else:
                self.logger.warning("Docker not available")
    
    def _run_whitebox(self):
        """Run White Box testing"""
        self.logger.section("📖 WHITE BOX TESTING MODE")
        
        if not self.config.whitebox:
            self.logger.warning("White Box config not provided, skipping...")
            return
        
        # Static Code Analysis
        if self.config.whitebox.code_scan:
            self.logger.info("🔍 Static Code Analysis")
            
            scanner = CodeScanner(self.config.whitebox.source_code_path)
            findings = scanner.scan_directory()
            
            self.logger.success(f"Found {len(findings)} potential vulnerabilities")
            
            # Display and save findings
            for finding in findings:
                severity_level = finding['severity']
                self.logger.finding(
                    severity_level,
                    f"{finding['file']}:{finding['line']} - {finding['description']}"
                )
                
                # Save to database
                db_finding = Finding(
                    mode='whitebox',
                    severity=severity_level,
                    category=finding['category'],
                    title=finding['description'],
                    description=f"Line {finding['line']}: {finding['code']}",
                    affected_url=finding['file'],
                    cvss_score=9.1 if severity_level == 'CRITICAL' else 5.0,
                    cwe_id=finding['cwe']
                )
                self.db.add_finding(db_finding)
            
            # Export report
            scanner.export_report(f"{self.config.output_dir}/code_scan_report.md")
    
    def _generate_report(self):
        """Generate final report"""
        self.logger.section("📊 GENERATING REPORT")
        
        # Get statistics
        stats = self.db.get_statistics()
        
        self.logger.info(f"Total Findings: {stats['total']}")
        self.logger.info(f"By Severity: {stats['by_severity']}")
        self.logger.info(f"By Mode: {stats['by_mode']}")
        
        # Export to JSON
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        json_file = f"{self.config.output_dir}/pentest_report_{timestamp}.json"
        self.db.export_json(json_file)
        
        self.logger.success(f"Report saved to: {json_file}")
        
        # Summary
        duration = time.time() - self.start_time
        self.logger.banner(f"✅ SCAN COMPLETED IN {duration:.2f} seconds")

def main():
    parser = argparse.ArgumentParser(
        description='Microservice SSRF Pentest Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Black Box scan
  python cli.py --mode blackbox --target http://localhost:8083/inventory/1/M
  
  # Gray Box scan với Docker
  python cli.py --mode graybox --target http://localhost:8083 --docker
  
  # White Box scan
  python cli.py --mode whitebox --source-path ./microservice_lab
  
  # Full scan (tất cả modes)
  python cli.py --mode all --target http://localhost:8083 --source-path ./microservice_lab --docker
        '''
    )
    
    parser.add_argument('--mode', choices=['blackbox', 'graybox', 'whitebox', 'all'],
                        default='all', help='Testing mode')
    parser.add_argument('--target', help='Target URL for testing')
    parser.add_argument('--source-path', help='Source code path for white box')
    parser.add_argument('--docker', action='store_true', help='Enable Docker inspection (gray box)')
    parser.add_argument('--config', help='Config file path')
    parser.add_argument('--output', default='reports', help='Output directory')
    
    args = parser.parse_args()
    
    # Create config
    if args.config:
        config = ToolkitConfig.from_file(args.config)
    else:
        config = ToolkitConfig(mode=args.mode, output_dir=args.output)
        
        # Black Box
        if args.mode in ['blackbox', 'all'] and args.target:
            config.blackbox = BlackBoxConfig(target_url=args.target)
        
        # Gray Box
        if args.mode in ['graybox', 'all']:
            config.graybox = GrayBoxConfig(
                target_url=args.target or 'http://localhost:8083',
                docker_inspect=args.docker
            )
        
        # White Box
        if args.mode in ['whitebox', 'all'] and args.source_path:
            config.whitebox = WhiteBoxConfig(source_code_path=args.source_path)
    
    # Create output directory
    Path(config.output_dir).mkdir(parents=True, exist_ok=True)
    
    # Run toolkit
    toolkit = SSRFPentestToolkit()
    toolkit.config = config
    toolkit.run()

if __name__ == "__main__":
    main()
