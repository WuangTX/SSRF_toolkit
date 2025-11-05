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
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import urllib3

# Suppress SSL warnings for target validation
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import ToolkitConfig, BlackBoxConfig, GrayBoxConfig, WhiteBoxConfig
from core.logger import get_logger, init_logger
from core.database import FindingDatabase, Finding

from blackbox.reconnaissance.endpoint_discovery_v2 import EndpointDiscoveryV2
from blackbox.reconnaissance.parameter_fuzzer import ParameterFuzzer
from blackbox.reconnaissance.auto_discovery import AutoDiscovery
from blackbox.detection.external_callback import CallbackServer, ExternalCallbackDetector
from blackbox.exploitation.internal_scan import InternalScanner
from graybox.architecture.docker_inspector import DockerInspector
from whitebox.static_analysis.code_scanner import CodeScanner

app = Flask(__name__)
app.config['SECRET_KEY'] = 'ssrf-pentest-toolkit-secret-key'
socketio = SocketIO(app, cors_allowed_origins="*")

# Thread safety lock
scan_state_lock = threading.RLock()  # Reentrant lock for nested access

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

# Global callback server (singleton to avoid port conflicts)
global_callback_server = None
callback_server_lock = threading.Lock()

# Thread-safe state accessors
def get_scan_running():
    """Thread-safe check if scan is running"""
    with scan_state_lock:
        return scan_state['is_running']

def set_scan_running(running: bool):
    """Thread-safe set scan running status"""
    with scan_state_lock:
        scan_state['is_running'] = running

def add_finding(finding: dict):
    """Thread-safe add finding"""
    with scan_state_lock:
        scan_state['findings'].append(finding)

def add_endpoint(endpoint: dict):
    """Thread-safe add endpoint"""
    with scan_state_lock:
        scan_state['endpoints'].append(endpoint)

def add_log(log_entry: dict):
    """Thread-safe add log"""
    with scan_state_lock:
        scan_state['logs'].append(log_entry)

def reset_scan_state():
    """Thread-safe reset scan state"""
    with scan_state_lock:
        scan_state['is_running'] = False
        scan_state['current_phase'] = None
        scan_state['progress'] = 0
        scan_state['findings'] = []
        scan_state['endpoints'] = []
        scan_state['logs'] = []
        scan_state['start_time'] = None
        scan_state['callback_server'] = None
    
    # Cleanup global callback server on hard reset
    cleanup_callback_server()

def get_scan_state_value(key: str, default=None):
    """Thread-safe get scan state value"""
    with scan_state_lock:
        return scan_state.get(key, default)

def set_callback_server(server):
    """Thread-safe set callback server"""
    with scan_state_lock:
        scan_state['callback_server'] = server

def get_or_create_callback_server(port: int = 8888):
    """
    Get or create a singleton callback server to avoid port conflicts.
    This ensures only one server runs on a given port at a time.
    """
    global global_callback_server
    
    with callback_server_lock:
        # Check if server exists and is running
        if global_callback_server is not None:
            try:
                # Test if server is still alive
                if hasattr(global_callback_server, 'is_running') and global_callback_server.is_running:
                    web_logger.info(f"♻️ Reusing existing callback server on port {port}")
                    return global_callback_server
                else:
                    # Server exists but not running - clean up
                    web_logger.info(f"🧹 Cleaning up stale callback server")
                    try:
                        global_callback_server.stop()
                    except:
                        pass
                    global_callback_server = None
            except:
                # Server object is corrupted - clean up
                global_callback_server = None
        
        # Create new server
        try:
            web_logger.info(f"🆕 Creating new callback server on port {port}")
            server = CallbackServer(host='0.0.0.0', port=port)
            server.start()
            global_callback_server = server
            return server
        except OSError as e:
            if "Address already in use" in str(e):
                web_logger.error(f"❌ Port {port} is already in use!")
                web_logger.error(f"💡 Try: 1) Wait 30s for old server to timeout, or 2) Use different port")
                raise Exception(f"Callback server port {port} is busy. Please wait or use another port.")
            raise

def cleanup_callback_server():
    """Thread-safe cleanup of global callback server"""
    global global_callback_server
    
    with callback_server_lock:
        if global_callback_server is not None:
            try:
                web_logger.info("🛑 Stopping callback server...")
                global_callback_server.stop()
            except Exception as e:
                web_logger.warning(f"⚠️ Error stopping callback server: {e}")
            finally:
                global_callback_server = None

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
        add_finding({
            'severity': severity,
            'message': message,
            'timestamp': datetime.now().isoformat()
        })
    
    def endpoint(self, endpoint_data):
        """Emit discovered endpoint to UI"""
        socketio.emit('endpoint', endpoint_data)
        add_endpoint(endpoint_data)
    
    def _emit_log(self, level, message, severity=None):
        log_entry = {
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'level': level,
            'message': message,
            'severity': severity
        }
        add_log(log_entry)
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
    # Debug logging
    web_logger.info(f"=== Scan Request Debug ===")
    web_logger.info(f"Content-Type: {request.content_type}")
    web_logger.info(f"Form data: {dict(request.form)}")
    web_logger.info(f"Files: {list(request.files.keys())}")
    web_logger.info(f"=======================")
    
    if get_scan_running():
        return jsonify({'error': 'Scan already in progress'}), 400
    
    # Check if traffic capture file is provided (HAR or Burp Suite)
    har_file = request.files.get('har_file')
    har_data = None
    
    if har_file:
        # Traffic capture file provided - auto-detect format and parse
        try:
            file_content = har_file.read().decode('utf-8')
            filename = har_file.filename.lower()
            
            # Auto-detect format
            parser = None
            source_type = "Unknown"
            
            # Try HAR format first (Chrome DevTools)
            if filename.endswith('.har') or '"log"' in file_content[:200]:
                from utils.har_parser import parse_har_content
                parser = parse_har_content(file_content)
                source_type = "Chrome DevTools HAR"
            
            # Try Burp Suite format (JSON/XML)
            elif filename.endswith('.json') or filename.endswith('.xml') or 'base64' in file_content[:500]:
                from utils.burp_parser import parse_burp_content
                parser = parse_burp_content(file_content, format_type='auto')
                source_type = "Burp Suite Proxy History"
            
            # Fallback: Try both formats
            else:
                try:
                    from utils.har_parser import parse_har_content
                    parser = parse_har_content(file_content)
                    source_type = "HAR"
                except:
                    from utils.burp_parser import parse_burp_content
                    parser = parse_burp_content(file_content, format_type='auto')
                    source_type = "Burp Suite"
            
            if parser:
                har_data = {
                    'requests': parser.requests,
                    'endpoints': parser.get_endpoints(),
                    'stats': parser.get_stats(),
                    'source': source_type
                }
                
                web_logger.info(f"📁 {source_type} file uploaded: {har_file.filename}")
                web_logger.info(f"📊 Parsed {har_data['stats']['total_requests']} requests, {har_data['stats']['unique_endpoints']} unique endpoints")
                
                # Log authenticated requests
                auth_count = har_data['stats']['authenticated_requests']
                if auth_count > 0:
                    web_logger.info(f"🔐 Found {auth_count} authenticated requests (with JWT/cookies)")
                
                # Extract target URL from parsed requests
                if har_data['requests']:
                    first_request = har_data['requests'][0]
                    parsed_url = urlparse(first_request['url'])
                    extracted_target = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    web_logger.info(f"🎯 Extracted target from Burp file: {extracted_target}")
                else:
                    extracted_target = None
            else:
                return jsonify({'error': 'Unable to detect file format (expected HAR or Burp Suite export)'}), 400
            
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            web_logger.error(f"Parse error: {error_detail}")
            return jsonify({'error': f'Failed to parse file: {str(e)}'}), 400
    
    # Get form data (either from multipart or JSON)
    # Always try form data first (since we're using FormData in frontend)
    if request.form:
        # Multipart form data or form-encoded
        mode = request.form.get('mode', 'blackbox')
        target = request.form.get('target')
        source_path = request.form.get('source_path', '')
        auto_discovery = request.form.get('auto_discovery') == 'on'
        endpoint_discovery = request.form.get('endpoint_discovery') == 'on'
        parameter_fuzzing = request.form.get('parameter_fuzzing') == 'on'
        callback_testing = request.form.get('callback_testing') == 'on'
        internal_scanning = request.form.get('internal_scanning') == 'on'
        docker_inspection = request.form.get('docker_inspection') == 'on'
        code_scanning = request.form.get('code_scanning') == 'on'
        timeout = int(request.form.get('timeout', 10))
        endpoint_source = request.form.get('endpoint_source', 'file')  # 'file', 'url', or 'both'
        
        # Burp import specific fields
        if not target:
            target = request.form.get('burp_target')
        
        # Use extracted target from file if no manual target provided
        if not target and 'extracted_target' in locals():
            target = extracted_target
            web_logger.info(f"🎯 Using extracted target: {target}")
            
        if request.form.get('burp_parameter_fuzzing') == 'on':
            parameter_fuzzing = True
        if request.form.get('burp_callback_testing') == 'on':
            callback_testing = True
        if request.form.get('burp_internal_scanning') == 'on':
            internal_scanning = True
        if request.form.get('burp_timeout'):
            timeout = int(request.form.get('burp_timeout', 10))
        
        # Get custom selections
        custom_params = request.form.get('custom_params')
        custom_payloads = request.form.get('custom_payloads')
        custom_endpoints = request.form.get('custom_endpoints')
        
        if custom_params:
            custom_params = json.loads(custom_params)
        if custom_payloads:
            custom_payloads = json.loads(custom_payloads)
        if custom_endpoints:
            custom_endpoints = json.loads(custom_endpoints)
    elif request.json:
        # JSON data (fallback)
        data = request.json
        mode = data.get('mode', 'blackbox')
        target = data.get('target')
        source_path = data.get('source_path', '')
        auto_discovery = data.get('auto_discovery', False)
        endpoint_discovery = data.get('endpoint_discovery', True)
        parameter_fuzzing = data.get('parameter_fuzzing', True)
        callback_testing = data.get('callback_testing', True)
        internal_scanning = data.get('internal_scanning', True)
        docker_inspection = data.get('docker_inspection', True)
        code_scanning = data.get('code_scanning', True)
        timeout = data.get('timeout', 10)
        endpoint_source = data.get('endpoint_source', 'file')  # 'file', 'url', or 'both'
        
        # Get custom selections
        custom_params = data.get('custom_params')
        custom_payloads = data.get('custom_payloads')
        custom_endpoints = data.get('custom_endpoints')
    else:
        return jsonify({'error': 'No form data or JSON data received. Please check your request.'}), 400
    
    # Validate input
    if not target and mode != 'whitebox' and not har_data:
        web_logger.error(f"Validation failed: target={target}, mode={mode}, har_data={har_data}")
        return jsonify({'error': 'Please provide a target URL or upload a HAR/Burp file to begin scanning.'}), 400
    
    # Validate target URL format and accessibility (if provided)
    if target and mode != 'whitebox':
        # Check URL format
        try:
            parsed = urlparse(target)
            if not parsed.scheme or not parsed.netloc:
                return jsonify({
                    'error': f'Invalid URL format. The URL must include http:// or https:// at the beginning.',
                    'example': 'Example: http://example.com or https://example.com:8080/path'
                }), 400
            
            if parsed.scheme not in ['http', 'https']:
                return jsonify({
                    'error': f'Invalid URL scheme "{parsed.scheme}". Only http:// and https:// are supported.',
                    'example': f'Try: http://{parsed.netloc}{parsed.path or "/"}'
                }), 400
        except Exception as e:
            return jsonify({'error': f'Invalid URL format: {str(e)}'}), 400
        
        # Try to connect to target (timeout 5s)
        # Don't log technical details - frontend will show user-friendly messages
        try:
            response = requests.get(target, timeout=5, allow_redirects=True, verify=False)
            # Target is accessible, no need to log success
        except requests.exceptions.ConnectionError as e:
            error_detail = str(e).lower()
            if 'nodename nor servname provided' in error_detail or 'name or service not known' in error_detail or 'no such host' in error_detail:
                return jsonify({
                    'error': f'Cannot connect to target: The domain "{parsed.netloc}" does not exist or cannot be found.'
                }), 400
            else:
                return jsonify({
                    'error': f'Cannot connect to target: {target}. The server might be offline or unreachable.'
                }), 400
        except requests.exceptions.Timeout:
            return jsonify({
                'error': f'Connection timeout: {target} is not responding. The server might be slow or offline.'
            }), 400
        except requests.exceptions.SSLError as e:
            # SSL errors are warnings, allow scan to continue
            pass
        except requests.exceptions.TooManyRedirects:
            return jsonify({
                'error': f'Too many redirects when connecting to {target}. The server configuration might be incorrect.'
            }), 400
        except requests.exceptions.RequestException as e:
            error_msg = str(e)
            return jsonify({
                'error': f'Failed to connect to target: {error_msg}'
            }), 400
    
    # Reset state (thread-safe)
    with scan_state_lock:
        scan_state['is_running'] = True
        scan_state['current_phase'] = 'Initializing'
        scan_state['progress'] = 0
        scan_state['findings'] = []
        scan_state['endpoints'] = []
        scan_state['logs'] = []
        scan_state['start_time'] = datetime.now()
        scan_state['har_data'] = har_data  # Store HAR data for use in scan
        scan_state['endpoint_source'] = endpoint_source  # Store endpoint source preference
        scan_state['custom_params'] = custom_params  # Store custom param selection
        scan_state['custom_payloads'] = custom_payloads  # Store custom payload selection
        scan_state['custom_endpoints'] = custom_endpoints  # Store custom endpoint selection
    
    # Log custom selections
    if custom_params:
        web_logger.info(f"⚙️ Custom parameters selected: {len(custom_params)} params")
    if custom_payloads:
        web_logger.info(f"💉 Custom payloads selected: {len(custom_payloads)} payloads")
    if custom_endpoints:
        web_logger.info(f"📍 Custom endpoints selected: {len(custom_endpoints)} endpoints")
    
    # Create config
    config = ToolkitConfig(
        mode=mode,
        output_dir='reports',
        blackbox=BlackBoxConfig(
            target_url=target or "http://localhost:8083",
            auto_discovery=auto_discovery,
            endpoint_discovery=endpoint_discovery,
            parameter_fuzzing=parameter_fuzzing,
            external_callback_test=callback_testing,
            internal_scan=internal_scanning,
            timeout=timeout
        ),
        graybox=GrayBoxConfig(
            target_url=target or "http://localhost:8083",
            docker_inspect=docker_inspection
        ),
        whitebox=WhiteBoxConfig(
            source_code_path=source_path or "./",
            code_scan=code_scanning
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
    if not get_scan_running():
        return jsonify({'error': 'No scan running'}), 400
    
    with scan_state_lock:
        scan_state['is_running'] = False
        
        # Clear callback server reference but don't stop it
        # Let it run for potential reuse
        scan_state['callback_server'] = None
    
    web_logger.info('🛑 Scan stopped by user (callback server kept alive)')
    return jsonify({'success': True, 'message': 'Scan stopped'})

@app.route('/api/scan/reset', methods=['POST'])
def reset_scan_endpoint():
    """Reset scan state (force unlock)"""
    reset_scan_state()
    web_logger.info('🔄 Scan state reset and callback server stopped')
    return jsonify({'success': True, 'message': 'Scan state reset'})

@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    """Get current scan status"""
    with scan_state_lock:
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
    with scan_state_lock:
        return jsonify(list(scan_state['findings']))  # Return copy to avoid race conditions

@app.route('/api/logs', methods=['GET'])
def get_logs():
    """Get all logs"""
    with scan_state_lock:
        return jsonify(list(scan_state['logs']))  # Return copy to avoid race conditions

@app.route('/api/report/export', methods=['POST'])
def export_report():
    """Export report"""
    format_type = request.json.get('format', 'json')
    
    if format_type == 'json':
        report_file = Path('reports') / f'report_{int(time.time())}.json'
        report_file.parent.mkdir(exist_ok=True)
        
        with scan_state_lock:
            report_data = {
                'findings': list(scan_state['findings']),
                'logs': list(scan_state['logs']),
                'start_time': scan_state['start_time'].isoformat() if scan_state['start_time'] else None,
                'generated_at': datetime.now().isoformat()
            }
        
        with open(report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
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
        # Always reset state when scan ends (thread-safe)
        with scan_state_lock:
            scan_state['is_running'] = False
            # Clear callback server reference but keep it running for reuse
            scan_state['callback_server'] = None
        web_logger.info("🏁 Scan process terminated (callback server kept alive)")

def run_blackbox(config: ToolkitConfig, db: FindingDatabase):
    """Run black box testing"""
    web_logger.info("🎯 Starting Black Box Testing")
    target_url = config.blackbox.target_url
    fuzz_results = []
    discovered_endpoints = []
    
    # Check if Auto Discovery mode is enabled
    if config.blackbox.auto_discovery:
        web_logger.info("🤖 AUTO DISCOVERY MODE - Full automation enabled")
        web_logger.info(f"🎯 Target domain: {target_url}")
        web_logger.info("📋 Process: Crawl → Discover → Test → Confirm → Report")
        
        # Phase 1: Auto Discovery and Intelligent Testing
        update_progress('Auto Discovery & Testing', 10)
        
        try:
            # Initialize auto discovery with callback server (singleton pattern)
            callback_server = get_or_create_callback_server(port=8888)
            set_callback_server(callback_server)
            
            web_logger.info(f"📡 Callback server ready on http://0.0.0.0:8888")
            
            # Get all callback addresses for Docker/LAN environments
            callback_addresses = callback_server.get_all_callback_addresses()
            web_logger.info(f"🌐 Callback addresses: {', '.join(callback_addresses)}")
            
            # Initialize auto discovery
            auto_disco = AutoDiscovery(
                base_url=target_url,
                timeout=config.blackbox.timeout
            )
            
            # Run full auto discovery and testing
            web_logger.info("🚀 Starting comprehensive auto-discovery...")
            auto_results = auto_disco.run_full_discovery()
            
            # Process results
            discovered_endpoints = auto_results.get('endpoints', [])
            testable_endpoints = auto_results.get('testable_endpoints', [])
            ssrf_vulnerabilities = auto_results.get('ssrf_vulnerabilities', [])
            forms = auto_results.get('forms', [])
            api_endpoints = auto_results.get('api_endpoints', [])
            
            web_logger.info(f"✅ Auto Discovery Complete!")
            web_logger.info(f"📊 Statistics:")
            web_logger.info(f"  • Endpoints discovered: {len(discovered_endpoints)}")
            web_logger.info(f"  • API endpoints: {len(api_endpoints)}")
            web_logger.info(f"  • Forms found: {len(forms)}")
            web_logger.info(f"  • Testable endpoints: {len(testable_endpoints)}")
            web_logger.info(f"  • SSRF vulnerabilities: {len(ssrf_vulnerabilities)}")
            
            # Emit SSRF vulnerabilities as HIGH severity findings
            for vuln in ssrf_vulnerabilities:
                endpoint = vuln.get('endpoint', '')
                parameter = vuln.get('parameter', '')
                payload = vuln.get('payload', '')
                callback_received = vuln.get('callback_received', {})
                
                msg = f"🔥 CONFIRMED SSRF: {endpoint} (param: {parameter})"
                web_logger.finding('HIGH', msg)
                web_logger.info(f"     💥 Payload: {payload}")
                web_logger.info(f"     📡 Callback received: {callback_received.get('path', 'N/A')}")
            
            # Emit discovered endpoints to UI
            for endpoint in discovered_endpoints:
                web_logger.endpoint({
                    'url': str(endpoint),
                    'status_code': 200,
                    'content_length': 0,
                    'content_type': 'auto-discovered'
                })
            
            # Emit testable endpoints as findings
            for testable in testable_endpoints:
                endpoint_url = testable.get('url', '')
                parameters = testable.get('parameters', [])
                
                if parameters:
                    param_list = ', '.join(parameters)
                    msg = f"🎯 Testable SSRF endpoint found: {endpoint_url} with parameters: {param_list}"
                    web_logger.finding('MEDIUM', msg)
            
            update_progress('Auto Discovery Complete', 70)
            
            # Phase 2: Internal Scanning (if testable endpoints found)
            if config.blackbox.internal_scan and testable_endpoints:
                update_progress('Internal Network Scanning', 75)
                web_logger.info("🔍 Phase: Internal Network Scanning")
                
                # Use first testable endpoint for internal scanning
                if testable_endpoints:
                    first_testable = testable_endpoints[0]
                    endpoint_url = first_testable.get('url', target_url)
                    params = first_testable.get('parameters', [])
                    
                    if params:
                        try:
                            scanner = InternalScanner(
                                ssrf_url=endpoint_url,
                                ssrf_param=params[0],  # Use first parameter
                                timeout=config.blackbox.timeout
                            )
                        
                            internal_results = scanner.scan_internal_network()
                            
                            for result in internal_results:
                                web_logger.info(f"  • {result['target']}: {result['status']}")
                                
                                if result['accessible']:
                                    msg = f"Internal host accessible: {result['target']} via SSRF at {endpoint_url}"
                                    web_logger.finding('HIGH', msg)
                                    
                                    finding = Finding(
                                        title=f"Internal Network Access via SSRF",
                                        severity='HIGH',
                                        description=f"Internal host {result['target']} accessible through SSRF",
                                        affected_endpoint=endpoint_url,
                                        evidence=f"Parameter: {params[0]}, Internal Target: {result['target']}",
                                        remediation="Restrict internal network access and implement network segmentation"
                                    )
                                    db.add_finding(finding)
                                    add_finding(finding.to_dict())
                            
                            web_logger.info("✅ Internal scanning complete")
                        except Exception as e:
                            web_logger.warning(f"⚠️ Internal scanning failed: {str(e)}")
                
                update_progress('Internal Scanning Complete', 90)
            
            # Don't stop callback server here - let it be reused by next scan
            # It will be cleaned up when app exits or explicitly stopped
            web_logger.info("✅ Keeping callback server alive for potential reuse")
            
            return  # Exit auto discovery mode
            
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            web_logger.error(f"❌ Auto Discovery failed: {str(e)}")
            web_logger.error(f"Details: {error_detail}")
            
            # Don't stop callback server on error - it may be reusable
            # Just clear the reference from scan_state
            set_callback_server(None)
            
            # Fall back to manual mode
            web_logger.info("⚠️ Falling back to manual discovery mode...")
    
    # Check if HAR data is available (Manual Mode)
    har_data = get_scan_state_value('har_data')
    endpoint_source = get_scan_state_value('endpoint_source', 'file')  # 'file', 'url', or 'both'
    
    # Determine which endpoints to use based on endpoint_source
    if har_data and endpoint_source in ['file', 'both']:
        # Phase 1: Extract Endpoints from Traffic Capture (Burp Suite or HAR)
        update_progress('Extracting Endpoints from Traffic Capture', 10)
        source = har_data.get('source', 'Traffic Capture')
        web_logger.info(f"📁 Phase 1: Extracting Endpoints from {source}")
        web_logger.info(f"📊 Stats: {har_data['stats']['total_requests']} requests, {har_data['stats']['unique_endpoints']} endpoints")
        
        # Log authenticated requests
        auth_count = har_data['stats']['authenticated_requests']
        if auth_count > 0:
            web_logger.info(f"🔐 Found {auth_count} authenticated requests (with JWT/cookies)")
        
        # Extract all unique URLs from capture
        for req in har_data['requests']:
            url = req['url']
            if url not in discovered_endpoints:
                discovered_endpoints.append(url)
                
                # Emit endpoint to UI
                web_logger.endpoint({
                    'url': url,
                    'status_code': 200,  # From capture, so it was successful
                    'content_length': len(str(req.get('post_data', ''))),
                    'content_type': req['headers'].get('Content-Type', 'unknown')
                })
                
                # Show method and auth info
                method = req.get('method', 'GET')
                log_msg = f"  ✓ {method} {url}"
                
                # Highlight if authenticated
                if 'Authorization' in req.get('headers', {}):
                    auth_header = req['headers']['Authorization']
                    if 'Bearer' in auth_header:
                        token_preview = auth_header.split('Bearer ')[-1][:40]
                        log_msg += f" 🔐 [JWT: {token_preview}...]"
                    else:
                        log_msg += f" 🔐 [Auth: {auth_header[:30]}...]"
                elif 'Cookie' in req.get('headers', {}):
                    log_msg += " 🍪 [Has Cookies]"
                
                web_logger.info(log_msg)
        
        web_logger.info(f"✅ Extracted {len(discovered_endpoints)} unique endpoints from {source}")
        update_progress('Traffic Capture Extraction Complete', 20)
    
    # Also discover from URL if requested ('url' or 'both')
    if (not har_data and config.blackbox.endpoint_discovery) or (har_data and endpoint_source in ['url', 'both']):
        # Phase: Comprehensive Endpoint Discovery from URL
        if endpoint_source == 'both':
            update_progress('Additional Discovery from URL', 25)
            web_logger.info("🔍 Phase: Additional Endpoint Discovery from URL")
        else:
            update_progress('Endpoint Discovery', 10)
            web_logger.info("📡 Phase 1: Comprehensive Endpoint Discovery")
        web_logger.info(f"🎯 Target: {target_url}")
        
        try:
            # Use Enhanced Endpoint Discovery V2
            discovery = EndpointDiscoveryV2(
                target_url, 
                timeout=config.blackbox.timeout,
                max_workers=3,
                rate_limit=2.0
            )
            
            # Use comprehensive discovery (robots.txt, sitemap, wordlist, javascript)
            endpoint_results = discovery.discover_comprehensive()
            
            # Extract URLs from V2 discovery results and emit to UI
            for result in endpoint_results:
                # Avoid duplicates when merging file + url discovery
                if result.url not in discovered_endpoints:
                    discovered_endpoints.append(result.url)
                    web_logger.info(f"  ✓ {result.url} [{result.status_code}] - {result.severity.upper()}")
                    
                    # Emit enhanced endpoint info to UI
                    web_logger.endpoint({
                        'url': result.url,
                        'status_code': result.status_code,
                        'content_length': result.content_length,
                        'content_type': result.content_type,
                        'severity': result.severity,
                        'source': result.source,
                        'accepts_post': result.accepts_post,
                        'ssrf_potential': result.ssrf_potential,
                        'response_time': result.response_time
                    })
            
            # Get discovery summary
            summary = discovery.get_summary()
            web_logger.info(f"📊 Discovery Summary:")
            web_logger.info(f"   Total endpoints: {summary['total_endpoints']}")
            web_logger.info(f"   Severity breakdown: {summary['severity_breakdown']}")
            web_logger.info(f"   Success rate: {summary['statistics']['successful_requests']}/{summary['statistics']['total_requests']}")
            
            if endpoint_source == 'both':
                web_logger.info(f"✅ Total endpoints: {len(discovered_endpoints)} (File + URL discovery)")
            else:
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
    elif not har_data or endpoint_source == 'url':
        # Skip discovery if we're using file-only and not in discovery mode
        if not config.blackbox.endpoint_discovery and not har_data:
            # Skip discovery, just use target URL
            web_logger.info("ℹ️ Endpoint discovery disabled, using target URL directly")
            discovered_endpoints = [target_url]
    
    # Fallback if no endpoints discovered
    if not discovered_endpoints:
        web_logger.info("ℹ️ No endpoints found, using target URL as fallback")
        discovered_endpoints = [target_url]
    
    # Filter endpoints if custom selection provided
    custom_endpoints = get_scan_state_value('custom_endpoints')
    if custom_endpoints:
        original_count = len(discovered_endpoints)
        discovered_endpoints = [e for e in discovered_endpoints if e in custom_endpoints]
        web_logger.info(f"🎯 Filtered to {len(discovered_endpoints)} selected endpoints (from {original_count})")
    
    # Phase 2: Parameter Fuzzing on ALL discovered endpoints
    if config.blackbox.parameter_fuzzing:
        update_progress('Parameter Fuzzing', 30)
        web_logger.info(f"🔍 Phase 2: Parameter Fuzzing ({len(discovered_endpoints)} endpoints)")
        
        # Get custom selections
        custom_params = get_scan_state_value('custom_params')
        custom_payloads = get_scan_state_value('custom_payloads')
        
        fuzzer = ParameterFuzzer(
            timeout=config.blackbox.timeout,
            custom_params=custom_params,
            custom_payloads=custom_payloads
        )
        
        # Fuzz each discovered endpoint
        for idx, endpoint_url in enumerate(discovered_endpoints):
            web_logger.info(f"[{idx+1}/{len(discovered_endpoints)}] Fuzzing: {endpoint_url}")
            
            endpoint_fuzz_results = fuzzer.fuzz_endpoint(endpoint_url)
            fuzz_results.extend(endpoint_fuzz_results)
        
        for result in fuzz_results:
            # Report based on confidence levels
            confidence = result['confidence']
            param = result['parameter']
            
            if confidence >= 0.7:
                severity = 'CRITICAL'
                msg = f"🔥 High-probability SSRF: {param} (confidence: {confidence:.2f})"
                web_logger.finding(severity, msg)
            elif confidence >= 0.5:
                severity = 'HIGH'
                msg = f"⚠️ Likely SSRF parameter: {param} (confidence: {confidence:.2f})"
                web_logger.finding(severity, msg)
            elif confidence >= 0.3:
                severity = 'MEDIUM'
                msg = f"🔍 Suspicious SSRF parameter: {param} (confidence: {confidence:.2f})"
                web_logger.finding(severity, msg)
            elif confidence >= 0.1:
                # Low confidence - only report if there are actual behavioral indicators
                if len(result.get('findings', [])) > 0:
                    severity = 'LOW'
                    msg = f"💡 Potential SSRF by name: {param} (confidence: {confidence:.2f})"
                    web_logger.finding(severity, msg)
                else:
                    # Very low confidence with no indicators - just log to console
                    web_logger.info(f"ℹ️ Parameter tested: {param} (confidence: {confidence:.2f}) - likely false positive")
            else:
                # Extremely low confidence (< 0.1) - don't report as finding
                web_logger.info(f"ℹ️ Noise filtered: {param} (confidence: {confidence:.2f})")
        
        update_progress('Parameter Fuzzing Complete', 45)
    
    # Phase 3: Callback Testing
    if config.blackbox.external_callback_test and len(fuzz_results) > 0:
        update_progress('Callback Testing', 50)
        web_logger.info("📞 Phase 3: External Callback Testing")
        
        # Use singleton callback server to avoid port conflicts
        callback_server = get_or_create_callback_server(port=8888)
        set_callback_server(callback_server)
        
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
    
    # Phase 4: Internal Scanning (Only if SSRF confirmed via callback)
    if config.blackbox.internal_scan and len(fuzz_results) > 0:
        # Check if we have ANY confirmed SSRF from callback testing
        confirmed_ssrf = False
        ssrf_param = None
        ssrf_url = None
        
        for result in fuzz_results:
            if result.get('is_vulnerable'):
                confirmed_ssrf = True
                ssrf_param = result['parameter']
                ssrf_url = result['url']
                break
        
        if not confirmed_ssrf:
            web_logger.warning("⚠️ Skipping internal scan - No confirmed SSRF vulnerability")
            web_logger.info("💡 Internal scanning requires a confirmed SSRF to avoid scanning pentester's own machine")
            update_progress('Internal Scan Skipped', 70)
        else:
            update_progress('Internal Network Scanning', 70)
            web_logger.info("🔎 Phase 4: Internal Network Scanning")
            web_logger.info(f"🎯 Using confirmed SSRF parameter: {ssrf_param} at {ssrf_url}")
            web_logger.info(f"⚠️ Note: Scanning localhost of TARGET service, not pentester machine")
            
            try:
                scanner = InternalScanner(
                    ssrf_url=ssrf_url,
                    ssrf_param=ssrf_param,
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
    """Update scan progress (thread-safe)"""
    with scan_state_lock:
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

@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection"""
    pass

@socketio.on('stop_scan')
def handle_stop_scan():
    """Handle scan stop request"""
    with scan_state_lock:
        scan_state['is_running'] = False
    web_logger.info("⏹️ Scan stopped by user")
    emit('scan_stopped', {'message': 'Scan stopped'}, broadcast=True)

def cleanup_on_exit():
    """Cleanup resources on app exit"""
    web_logger.info("🧹 Cleaning up resources...")
    cleanup_callback_server()

if __name__ == '__main__':
    import atexit
    atexit.register(cleanup_on_exit)
    
    print("🚀 Starting Microservice SSRF Pentest Toolkit Web UI")
    print("📊 Dashboard: http://localhost:5000")
    print("=" * 60)
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n⚠️ Shutting down...")
        cleanup_on_exit()
    except Exception as e:
        print(f"❌ Error: {e}")
        cleanup_on_exit()
