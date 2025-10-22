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
from blackbox.reconnaissance.auto_discovery import AutoDiscovery
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
            else:
                return jsonify({'error': 'Unable to detect file format (expected HAR or Burp Suite export)'}), 400
            
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            web_logger.error(f"Parse error: {error_detail}")
            return jsonify({'error': f'Failed to parse file: {str(e)}'}), 400
    
    # Get form data (either from multipart or JSON)
    if har_file:
        # Multipart form data
        mode = request.form.get('mode', 'blackbox')
        target = request.form.get('target')
        source_path = request.form.get('source_path')
        auto_discovery = request.form.get('auto_discovery') == 'on'
        endpoint_discovery = request.form.get('endpoint_discovery') == 'on'
        parameter_fuzzing = request.form.get('parameter_fuzzing') == 'on'
        callback_testing = request.form.get('callback_testing') == 'on'
        internal_scanning = request.form.get('internal_scanning') == 'on'
        docker_inspection = request.form.get('docker_inspection') == 'on'
        code_scanning = request.form.get('code_scanning') == 'on'
        timeout = int(request.form.get('timeout', 10))
    else:
        # JSON data
        data = request.json
        mode = data.get('mode', 'blackbox')
        target = data.get('target')
        source_path = data.get('source_path')
        auto_discovery = data.get('auto_discovery', False)
        endpoint_discovery = data.get('endpoint_discovery', True)
        parameter_fuzzing = data.get('parameter_fuzzing', True)
        callback_testing = data.get('callback_testing', True)
        internal_scanning = data.get('internal_scanning', True)
        docker_inspection = data.get('docker_inspection', True)
        code_scanning = data.get('code_scanning', True)
        timeout = data.get('timeout', 10)
    
    # Validate input
    if not target and mode != 'whitebox' and not har_data:
        return jsonify({'error': 'Target URL or HAR file is required'}), 400
    
    # Reset state
    scan_state['is_running'] = True
    scan_state['current_phase'] = 'Initializing'
    scan_state['progress'] = 0
    scan_state['findings'] = []
    scan_state['endpoints'] = []
    scan_state['logs'] = []
    scan_state['start_time'] = datetime.now()
    scan_state['har_data'] = har_data  # Store HAR data for use in scan
    
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
    
    # Check if Auto Discovery mode is enabled
    if config.blackbox.auto_discovery:
        web_logger.info("🤖 AUTO DISCOVERY MODE - Full automation enabled")
        web_logger.info(f"🎯 Target domain: {target_url}")
        web_logger.info("📋 Process: Crawl → Discover → Test → Confirm → Report")
        
        # Phase 1: Auto Discovery and Intelligent Testing
        update_progress('Auto Discovery & Testing', 10)
        
        try:
            # Initialize auto discovery with callback server
            callback_server = CallbackServer(host='0.0.0.0', port=8888)
            callback_server.start()
            scan_state['callback_server'] = callback_server
            
            web_logger.info(f"📡 Callback server started on http://0.0.0.0:8888")
            
            # Get all callback addresses for Docker/LAN environments
            callback_addresses = ExternalCallbackDetector.get_all_callback_addresses(port=8888)
            web_logger.info(f"🌐 Callback addresses: {', '.join(callback_addresses)}")
            
            # Initialize auto discovery
            auto_disco = AutoDiscovery(
                base_url=target_url,
                callback_server=callback_server,
                timeout=config.blackbox.timeout
            )
            
            # Run full auto discovery and testing
            web_logger.info("🚀 Starting comprehensive auto-discovery...")
            auto_results = auto_disco.auto_discover_and_test()
            
            # Process results
            discovered_endpoints = auto_results['endpoints']
            fuzz_results = auto_results['suspicious_params']
            confirmed_ssrf = auto_results['confirmed_ssrf']
            
            web_logger.info(f"✅ Auto Discovery Complete!")
            web_logger.info(f"📊 Statistics:")
            web_logger.info(f"  • Endpoints discovered: {len(discovered_endpoints)}")
            web_logger.info(f"  • Parameters tested: {auto_results['total_params_tested']}")
            web_logger.info(f"  • Suspicious parameters: {len(fuzz_results)}")
            web_logger.info(f"  • Confirmed SSRF: {len(confirmed_ssrf)}")
            
            # Emit discovered endpoints to UI
            for endpoint in discovered_endpoints:
                web_logger.endpoint({
                    'url': endpoint,
                    'status_code': 200,
                    'content_length': 0,
                    'content_type': 'auto-discovered'
                })
            
            # Report suspicious parameters
            for result in fuzz_results:
                confidence = result['confidence']
                param = result['parameter']
                url = result.get('url', target_url)
                
                if confidence >= 0.7:
                    severity = 'CRITICAL'
                    msg = f"🔥 High-probability SSRF: {param} at {url} (confidence: {confidence:.2f})"
                    web_logger.finding(severity, msg)
                elif confidence >= 0.5:
                    severity = 'HIGH'
                    msg = f"⚠️ Likely SSRF parameter: {param} at {url} (confidence: {confidence:.2f})"
                    web_logger.finding(severity, msg)
                elif confidence >= 0.3:
                    severity = 'MEDIUM'
                    msg = f"🔍 Suspicious parameter: {param} at {url} (confidence: {confidence:.2f})"
                    web_logger.finding(severity, msg)
                elif confidence >= 0.1:
                    severity = 'LOW'
                    msg = f"💡 Potential SSRF: {param} at {url} (confidence: {confidence:.2f})"
                    web_logger.finding(severity, msg)
            
            # Report confirmed SSRF
            if confirmed_ssrf:
                for ssrf in confirmed_ssrf:
                    msg = f"✅ CONFIRMED SSRF: {ssrf['parameter']} at {ssrf['url']} - Callback received!"
                    web_logger.finding('CRITICAL', msg)
                    
                    # Add to findings
                    finding = Finding(
                        title=f"Confirmed SSRF via {ssrf['parameter']}",
                        severity='CRITICAL',
                        description=f"SSRF confirmed through external callback at {ssrf['url']}",
                        affected_endpoint=ssrf['url'],
                        evidence=f"Parameter: {ssrf['parameter']}, Callback: {ssrf.get('callback_url', 'N/A')}",
                        remediation="Implement URL validation and whitelist allowed domains"
                    )
                    db.add_finding(finding)
                    scan_state['findings'].append(finding.to_dict())
            
            update_progress('Auto Discovery Complete', 70)
            
            # Phase 2: Internal Scanning (if SSRF confirmed)
            if config.blackbox.internal_scan and confirmed_ssrf:
                update_progress('Internal Network Scanning', 75)
                web_logger.info("🔍 Phase: Internal Network Scanning (SSRF confirmed)")
                
                for ssrf in confirmed_ssrf:
                    try:
                        scanner = InternalScanner(
                            ssrf_url=ssrf['url'],
                            ssrf_param=ssrf['parameter'],
                            timeout=config.blackbox.timeout
                        )
                        
                        internal_results = scanner.scan_internal_network()
                        
                        for result in internal_results:
                            web_logger.info(f"  • {result['target']}: {result['status']}")
                            
                            if result['accessible']:
                                msg = f"Internal host accessible: {result['target']} via SSRF at {ssrf['url']}"
                                web_logger.finding('HIGH', msg)
                                
                                finding = Finding(
                                    title=f"Internal Network Access via SSRF",
                                    severity='HIGH',
                                    description=f"Internal host {result['target']} accessible through SSRF",
                                    affected_endpoint=ssrf['url'],
                                    evidence=f"Parameter: {ssrf['parameter']}, Internal Target: {result['target']}",
                                    remediation="Restrict internal network access and implement network segmentation"
                                )
                                db.add_finding(finding)
                                scan_state['findings'].append(finding.to_dict())
                        
                        web_logger.info("✅ Internal scanning complete")
                    except Exception as e:
                        web_logger.warning(f"⚠️ Internal scanning failed: {str(e)}")
                
                update_progress('Internal Scanning Complete', 90)
            
            # Stop callback server
            if scan_state['callback_server']:
                callback_server.stop()
                scan_state['callback_server'] = None
            
            return  # Exit auto discovery mode
            
        except Exception as e:
            import traceback
            error_detail = traceback.format_exc()
            web_logger.error(f"❌ Auto Discovery failed: {str(e)}")
            web_logger.error(f"Details: {error_detail}")
            
            # Stop callback server on error
            if scan_state['callback_server']:
                try:
                    scan_state['callback_server'].stop()
                except:
                    pass
                scan_state['callback_server'] = None
            
            # Fall back to manual mode
            web_logger.info("⚠️ Falling back to manual discovery mode...")
    
    # Check if HAR data is available (Manual Mode)
    har_data = scan_state.get('har_data')
    
    if har_data:
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
        
    elif config.blackbox.endpoint_discovery:
        # Phase 1: Comprehensive Endpoint Discovery
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
