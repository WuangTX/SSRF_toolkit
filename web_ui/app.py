"""
Microservice SSRF Pentest Toolkit - Web UI
Flask-based web interface for the pentest toolkit
"""

from flask import Flask, render_template, request, jsonify, send_file
from flask_socketio import SocketIO, emit
import sys
import os
import json
import threading
import time
from datetime import datetime
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import ToolkitConfig, BlackBoxConfig, GrayBoxConfig, WhiteBoxConfig
from core.logger import get_logger, init_logger
from core.database import FindingDatabase, Finding

from blackbox.reconnaissance.endpoint_discovery import EndpointDiscovery
from blackbox.reconnaissance.parameter_fuzzer import ParameterFuzzer
from blackbox.detection.external_callback import CallbackServer, ExternalCallbackDetector
from blackbox.exploitation.internal_scan import InternalScanner
from graybox.architecture.docker_inspector import DockerInspector
from whitebox.static_analysis.code_scanner import CodeScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ssrf-pentest-toolkit-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Global state
scan_state = {
    'is_running': False,
    'current_phase': None,
    'progress': 0,
    'findings': [],
    'endpoints': [],
    'logs': [],
    'start_time': None,
    'callback_server': None
}

class WebUILogger:
    """Custom logger that emits to web UI"""
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def info(self, message):
        self.logger.info(message)
        self._emit_log('info', message)
    
    def warning(self, message):
        self.logger.warning(message)
        self._emit_log('warning', message)
    
    def error(self, message):
        self.logger.error(message)
        self._emit_log('error', message)
    
    def finding(self, severity, message):
        self.logger.info(f"[{severity}] {message}")
        self._emit_log('finding', message, severity)
        scan_state['findings'].append({
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
    
    def endpoint(self, endpoint_data):
        """Emit discovered endpoint to UI"""
        socketio.emit('endpoint', endpoint_data)
        scan_state['endpoints'].append(endpoint_data)
    
    def _emit_log(self, level, message, severity=None):
        log_entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'level': level,
            'message': message,
            'severity': severity
        }
        scan_state['logs'].append(log_entry)
        socketio.emit('log', log_entry)

# Initialize logger
web_logger = WebUILogger()

@app.route('/')
def index():
    """Main dashboard"""
    return render_template('index.html')

@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new scan"""
    if scan_state['is_running']:
        return jsonify({'error': 'Scan already running'}), 400
    
    data = request.json
    
    # Validate input
    mode = data.get('mode', 'blackbox')
    target = data.get('target')
    source_path = data.get('source_path')
    
    if not target and mode != 'whitebox':
        return jsonify({'error': 'Target URL is required'}), 400
    
    # Reset state
    scan_state['is_running'] = True
    scan_state['current_phase'] = 'Initializing'
    scan_state['progress'] = 0
    scan_state['findings'] = []
    scan_state['logs'] = []
    scan_state['start_time'] = datetime.now()
    
    # Create config
    config = ToolkitConfig(
        mode=mode,
        output_dir='reports',
        blackbox=BlackBoxConfig(
            target_url=target or "http://localhost:8083",
            endpoint_discovery=data.get('endpoint_discovery', True),
            parameter_fuzzing=data.get('parameter_fuzzing', True),
            external_callback_test=data.get('callback_testing', True),
            internal_scan=data.get('internal_scanning', True),
            timeout=data.get('timeout', 10)
        ),
        graybox=GrayBoxConfig(
            target_url=target or "http://localhost:8083",
            docker_inspect=data.get('docker_inspection', True)
        ),
        whitebox=WhiteBoxConfig(
            source_code_path=source_path or "./",
            code_scan=data.get('code_scanning', True)
        )
    )
    
    # Start scan in background thread
    thread = threading.Thread(target=run_scan, args=(config,))
    thread.daemon = True
    thread.start()
    
    return jsonify({'success': True, 'message': 'Scan started'})

@app.route('/api/scan/stop', methods=['POST'])
def stop_scan():
    """Stop current scan"""
    if not scan_state['is_running']:
        return jsonify({'error': 'No scan running'}), 400
    
    scan_state['is_running'] = False
    
    # Stop callback server if running
    if scan_state['callback_server']:
        try:
            scan_state['callback_server'].stop()
        except:
            pass
        scan_state['callback_server'] = None
    
    web_logger.info('🛑 Scan stopped by user')
    return jsonify({'success': True, 'message': 'Scan stopped'})

@app.route('/api/scan/reset', methods=['POST'])
def reset_scan():
    """Reset scan state (force unlock)"""
    scan_state['is_running'] = False
    scan_state['current_phase'] = None
    scan_state['progress'] = 0
    scan_state['start_time'] = None
    
    # Stop callback server if running
    if scan_state['callback_server']:
        try:
            scan_state['callback_server'].stop()
        except:
            pass
        scan_state['callback_server'] = None
    
    web_logger.info('🔄 Scan state reset')
    return jsonify({'success': True, 'message': 'Scan state reset'})

@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Get current scan status"""
    return jsonify({
        'is_running': scan_state['is_running'],
        'current_phase': scan_state['current_phase'],
        'progress': scan_state['progress'],
        'findings_count': len(scan_state['findings']),
        'start_time': scan_state['start_time'].isoformat() if scan_state['start_time'] else None
    })

@app.route('/api/findings', methods=['GET'])
def get_findings():
    """Get all findings"""
    return jsonify(scan_state['findings'])

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get all logs"""
    return jsonify(scan_state['logs'])

@app.route('/api/report/export', methods=['POST'])
def export_report():
    """Export report"""
    format_type = request.json.get('format', 'json')
    
    if format_type == 'json':
        report_file = Path('reports') / f'report_{int(time.time())}.json'
        report_file.parent.mkdir(exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump({
                'findings': scan_state['findings'],
                'logs': scan_state['logs'],
                'start_time': scan_state['start_time'].isoformat() if scan_state['start_time'] else None,
                'generated_at': datetime.now().isoformat()
            }, f, indent=2)
        
        return send_file(report_file, as_attachment=True)
    
    return jsonify({'error': 'Unsupported format'}), 400

def run_scan(config: ToolkitConfig):
    """Run the actual scan (background task)"""
    try:
        web_logger.info("🔧 Initializing scan...")
        db = FindingDatabase()
        
        if config.mode in ['blackbox', 'all']:
            run_blackbox(config, db)
        
        if config.mode in ['graybox', 'all']:
            run_graybox(config, db)
        
        if config.mode in ['whitebox', 'all']:
            run_whitebox(config, db)
        
        # Final phase
        update_progress('Scan Complete', 100)
        web_logger.info(f"✅ Scan completed successfully! Found {len(scan_state['findings'])} findings")
        
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        web_logger.error(f"❌ Scan failed: {str(e)}")
        web_logger.error(f"Details: {error_detail}")
        update_progress('Scan Failed', scan_state.get('progress', 0))
    finally:
        # Always reset state when scan ends
        scan_state['is_running'] = False
        if scan_state['callback_server']:
            try:
                scan_state['callback_server'].stop()
            except:
                pass
            scan_state['callback_server'] = None
        web_logger.info("🏁 Scan process terminated")

def run_blackbox(config: ToolkitConfig, db: FindingDatabase):
    """Run black box testing"""
    web_logger.info("🎯 Starting Black Box Testing")
    target_url = config.blackbox.target_url
    fuzz_results = []
    discovered_endpoints = []
    
    # Phase 1: Comprehensive Endpoint Discovery
    if config.blackbox.endpoint_discovery:
        update_progress('Endpoint Discovery', 10)
        web_logger.info("📡 Phase 1: Comprehensive Endpoint Discovery")
        web_logger.info(f"🎯 Target: {target_url}")
        
        try:
            discovery = EndpointDiscovery(target_url, timeout=config.blackbox.timeout)
            
            # Use comprehensive discovery (robots.txt, sitemap, wordlist, spider)
            endpoint_results = discovery.discover_comprehensive(config.blackbox.wordlist_path)
            
            # Extract URLs from discovery results and emit to UI
            for result in endpoint_results:
                discovered_endpoints.append(result['url'])
                web_logger.info(f"  ✓ {result['url']} [{result['status_code']}]")
                
                # Emit endpoint to UI
                web_logger.endpoint({
                    'url': result['url'],
                    'status_code': result['status_code'],
                    'content_length': result.get('content_length', 0),
                    'content_type': result.get('content_type', 'unknown')
                })
            
            web_logger.info(f"✅ Discovered {len(discovered_endpoints)} unique endpoints")
            
            # If no endpoints found, use base URL
            if not discovered_endpoints:
                web_logger.info("ℹ️ No endpoints found, will test base URL")
                discovered_endpoints = [target_url]
        except Exception as e:
            web_logger.warning(f"⚠️ Endpoint discovery failed: {str(e)}")
            import traceback
            web_logger.error(traceback.format_exc())
            web_logger.info("ℹ️ Proceeding with target URL directly")
            discovered_endpoints = [target_url]
        
        update_progress('Endpoint Discovery Complete', 20)
    else:
        # Skip discovery, just use target URL
        web_logger.info("ℹ️ Endpoint discovery disabled, using target URL directly")
        discovered_endpoints = [target_url]
    
    # Phase 2: Parameter Fuzzing on ALL discovered endpoints
    if config.blackbox.parameter_fuzzing:
        update_progress('Parameter Fuzzing', 30)
        web_logger.info(f"🔍 Phase 2: Parameter Fuzzing ({len(discovered_endpoints)} endpoints)")
        
        fuzzer = ParameterFuzzer(timeout=config.blackbox.timeout)
        
        # Fuzz each discovered endpoint
        for idx, endpoint_url in enumerate(discovered_endpoints):
            web_logger.info(f"[{idx+1}/{len(discovered_endpoints)}] Fuzzing: {endpoint_url}")
            
            endpoint_fuzz_results = fuzzer.fuzz_endpoint(endpoint_url)
            fuzz_results.extend(endpoint_fuzz_results)
        
        for result in fuzz_results:
            # Report all findings, not just high confidence ones
            if result['confidence'] >= 0.3:
                severity = 'HIGH' if result['is_vulnerable'] else 'MEDIUM'
                web_logger.finding(severity, 
                    f"Potential SSRF parameter: {result['parameter']} (confidence: {result['confidence']:.2f})"
                )
            elif len(result['findings']) > 0:
                # Even low confidence - report as INFO if there are ANY indicators
                web_logger.finding('LOW', 
                    f"Suspicious parameter: {result['parameter']} (confidence: {result['confidence']:.2f})"
                )
        
        update_progress('Parameter Fuzzing Complete', 45)
    
    # Phase 3: Callback Testing
    if config.blackbox.external_callback_test and len(fuzz_results) > 0:
        update_progress('Callback Testing', 50)
        web_logger.info("📞 Phase 3: External Callback Testing")
        
        callback_server = CallbackServer(host='0.0.0.0', port=8888)
        callback_server.start()
        scan_state['callback_server'] = callback_server
        
        detector = ExternalCallbackDetector(callback_server)
        
        # Test ALL suspicious parameters, not just high confidence ones
        for idx, result in enumerate(fuzz_results):
            web_logger.info(f"[{idx+1}/{len(fuzz_results)}] Testing callback for parameter: {result['parameter']} at {result['url']}")
            
            try:
                callback_result = detector.test_ssrf(
                    target_url=result['url'],  # Use the endpoint URL where parameter was found
                    parameter=result['parameter'],
                    timeout=10
                )
                
                if callback_result['is_vulnerable']:
                    web_logger.finding('CRITICAL',
                        f"✅ CONFIRMED SSRF via {result['parameter']} at {result['url']} - Received {callback_result['callbacks_received']} callbacks"
                    )
                else:
                    web_logger.info(f"❌ No callback received for {result['parameter']}")
            except Exception as e:
                web_logger.error(f"Error testing {result['parameter']}: {str(e)}")
        
        update_progress('Callback Testing Complete', 65)
    
    # Phase 4: Internal Scanning
    if config.blackbox.internal_scan and len(fuzz_results) > 0:
        update_progress('Internal Network Scanning', 70)
        web_logger.info("🔎 Phase 4: Internal Network Scanning")
        
        # Scan using ANY parameter we found (will verify SSRF during scan)
        # Use first parameter found - callback testing already confirmed if it works
        scan_param = fuzz_results[0]['parameter']
        
        web_logger.info(f"🎯 Attempting internal network scan using parameter: {scan_param}")
        
        try:
            scanner = InternalScanner(
                ssrf_url=target_url,
                ssrf_param=scan_param,
                timeout=5
            )
            
            services = scanner.discover_services()
            web_logger.info(f"🎯 Discovered {len(services)} internal services")
            
            for service in services:
                web_logger.finding('HIGH',
                    f"Internal service accessible: {service['host']}:{service['port']} - {service['service']}"
                )
        except Exception as e:
            web_logger.warning(f"Internal scanning failed: {str(e)}")
        
        update_progress('Internal Scanning Complete', 85)

def run_graybox(config: ToolkitConfig, db: FindingDatabase):
    """Run gray box testing"""
    web_logger.info("🔍 Starting Gray Box Testing")
    
    if config.graybox.docker_inspect:
        update_progress('Docker Inspection', 90)
        web_logger.info("🐳 Inspecting Docker Environment")
        
        try:
            inspector = DockerInspector()
            containers = inspector.list_containers()
            
            web_logger.info(f"Found {len(containers)} Docker containers")
            
            for container in containers:
                networks = inspector.get_container_networks(container['id'])
                for net in networks:
                    web_logger.info(f"Container {container['name']}: {net['ip']} in {net['network']}")
        except Exception as e:
            web_logger.warning(f"Docker inspection failed: {str(e)}")

def run_whitebox(config: ToolkitConfig, db: FindingDatabase):
    """Run white box testing"""
    web_logger.info("📝 Starting White Box Testing")
    
    if config.whitebox.code_scan and config.whitebox.source_code_path:
        update_progress('Code Scanning', 95)
        web_logger.info("🔍 Scanning source code")
        
        scanner = CodeScanner(config.whitebox.source_code_path)
        vulnerabilities = scanner.scan()
        
        for vuln in vulnerabilities:
            web_logger.finding(vuln['severity'],
                f"{vuln['type']} in {vuln['file']}:{vuln['line']} - {vuln['description']}"
            )

def update_progress(phase: str, progress: int):
    """Update scan progress"""
    scan_state['current_phase'] = phase
    scan_state['progress'] = progress
    socketio.emit('progress', {
        'phase': phase,
        'progress': progress
    })

@socketio.on('connect')
def handle_connect():
    """Handle client connection"""
    emit('connected', {'message': 'Connected to SSRF Pentest Toolkit'})

if __name__ == '__main__':
    print("🚀 Starting Microservice SSRF Pentest Toolkit Web UI")
    print("📊 Dashboard: http://localhost:5000")
    print("=" * 60)
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
