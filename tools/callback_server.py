"""
Enhanced Callback Server with Realtime Dashboard + SQLite Database
Receives SSRF callbacks and displays them in a web UI for analysis.
"""
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
import logging
from datetime import datetime
from threading import Lock
import os
import json
import sqlite3
from pathlib import Path
import ipaddress
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'change-me-in-production-QTX181004')
logging.basicConfig(level=logging.INFO)

# Dashboard credentials
DASHBOARD_USERNAME = os.environ.get('DASHBOARD_USER', 'admin')
DASHBOARD_PASSWORD = os.environ.get('DASHBOARD_PASS', 'QTX181004abc@')

def require_auth(f):
    """Decorator to require authentication for dashboard routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def is_private_ip(ip_str):
    """Check if IP address is private/local (not a real SSRF)"""
    try:
        ip = ipaddress.ip_address(ip_str)
        # Check if localhost or private
        return ip.is_loopback or ip.is_private or ip.is_link_local or ip.is_reserved
    except ValueError:
        # If not valid IP, assume it's not SSRF
        return True

# Enable CORS for all routes
@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

# Database setup
DB_PATH = Path(__file__).parent / 'callbacks.db'
db_lock = Lock()

def init_db():
    with sqlite3.connect(str(DB_PATH)) as conn:
        # HTTP callbacks table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                remote_addr TEXT NOT NULL,
                is_ssrf INTEGER DEFAULT 0,
                headers TEXT NOT NULL,
                body TEXT,
                body_length INTEGER DEFAULT 0,
                user_agent TEXT,
                service_detected TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON callbacks(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_service ON callbacks(service_detected)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_ssrf ON callbacks(is_ssrf)')
        
        # DNS callbacks table
        conn.execute('''
            CREATE TABLE IF NOT EXISTS dns_callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                domain TEXT NOT NULL,
                query_type TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                raw_query TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_dns_timestamp ON dns_callbacks(timestamp)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_callbacks(domain)')
        
        conn.commit()

init_db()
API_KEY = os.environ.get('CALLBACK_API_KEY', None)

def detect_service_from_ua(user_agent):
    if not user_agent:
        return 'Unknown'
    ua_lower = user_agent.lower()
    patterns = {
        'python': ['python', 'urllib', 'requests', 'httpx', 'aiohttp'],
        'java': ['java', 'apache-httpclient', 'okhttp', 'spring'],
        'node.js': ['node', 'axios', 'got', 'superagent'],
        'php': ['php', 'guzzle', 'curl'],
        'ruby': ['ruby', 'faraday', 'httparty'],
        'go': ['go-http', 'golang'],
        '.NET': ['dotnet', 'httpclient', 'restsharp'],
        'curl': ['curl'],
        'wget': ['wget'],
        'browser': ['mozilla', 'chrome', 'safari', 'edge', 'firefox'],
        'aws-sdk': ['aws-sdk', 'boto'],
        'cloud': ['google-cloud', 'azure-sdk'],
    }
    for service, keywords in patterns.items():
        if any(kw in ua_lower for kw in keywords):
            return service
    return 'Unknown'

def store_callback(path, method, remote_addr, headers, body):
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        try:
            user_agent = headers.get('User-Agent', 'N/A')
            service = detect_service_from_ua(user_agent)
            body_text = body[:5000] if body else ''
            
            # Check if this is a real SSRF
            # SSRF = server-side requests from TARGET application (python, java, curl, etc.)
            # NOT browser requests from users
            # NOT toolkit's internal requests (/addresses, /api/callbacks/public, /health)
            is_ssrf_flag = 0
            
            # Exclude toolkit's internal endpoints
            internal_paths = ['/addresses', '/api/', '/health', '/favicon.ico', '/robots.txt', '/']
            is_internal = any(path.startswith(p) for p in internal_paths)
            
            if not is_internal and service not in ['browser', 'Unknown']:
                # Likely a server-side request from target application
                is_ssrf_flag = 1
            
            cursor = conn.execute('''
                INSERT INTO callbacks (timestamp, path, method, remote_addr, is_ssrf, headers, body, body_length, user_agent, service_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), path, method, remote_addr, is_ssrf_flag, json.dumps(dict(headers)), body_text, len(body) if body else 0, user_agent, service))
            callback_id = cursor.lastrowid
            conn.commit()
            return {
                'id': callback_id,
                'timestamp': datetime.now().isoformat(),
                'path': path,
                'method': method,
                'remote_addr': remote_addr,
                'is_ssrf': bool(is_ssrf_flag),
                'user_agent': user_agent,
                'service_detected': service
            }
        finally:
            conn.close()

def get_callbacks_from_db(limit=100, offset=0, service_filter=None):
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            query = 'SELECT * FROM callbacks'
            params = []
            if service_filter:
                query += ' WHERE service_detected = ?'
                params.append(service_filter)
            query += ' ORDER BY id DESC LIMIT ? OFFSET ?'
            params.extend([limit, offset])
            rows = conn.execute(query, params).fetchall()
            callbacks = []
            for row in rows:
                callbacks.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'path': row['path'],
                    'method': row['method'],
                    'remote_addr': row['remote_addr'],
                    'is_ssrf': bool(row['is_ssrf']) if 'is_ssrf' in row.keys() else False,  # Access by key for sqlite3.Row
                    'headers': json.loads(row['headers']),
                    'body': row['body'],
                    'body_length': row['body_length'],
                    'user_agent': row['user_agent'],
                    'service_detected': row['service_detected']
                })
            count_query = 'SELECT COUNT(*) as total FROM callbacks'
            if service_filter:
                count_query += ' WHERE service_detected = ?'
                total = conn.execute(count_query, [service_filter]).fetchone()['total']
            else:
                total = conn.execute(count_query).fetchone()['total']
            return callbacks, total
        finally:
            conn.close()

def get_callback_by_id(callback_id):
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            row = conn.execute('SELECT * FROM callbacks WHERE id = ?', (callback_id,)).fetchone()
            if not row:
                return None
            return {
                'id': row['id'],
                'timestamp': row['timestamp'],
                'path': row['path'],
                'method': row['method'],
                'remote_addr': row['remote_addr'],
                'is_ssrf': bool(row['is_ssrf']) if 'is_ssrf' in row.keys() else False,  # Access by key for sqlite3.Row
                'headers': json.loads(row['headers']),
                'body': row['body'],
                'body_length': row['body_length'],
                'user_agent': row['user_agent'],
                'service_detected': row['service_detected']
            }
        finally:
            conn.close()

def get_unique_services():
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        try:
            rows = conn.execute('SELECT DISTINCT service_detected, COUNT(*) as count FROM callbacks GROUP BY service_detected').fetchall()
            return [{'service': row[0], 'count': row[1]} for row in rows]
        finally:
            conn.close()

def clear_all_callbacks():
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        try:
            conn.execute('DELETE FROM callbacks')
            conn.execute('DELETE FROM dns_callbacks')
            conn.commit()
        finally:
            conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if username == DASHBOARD_USERNAME and password == DASHBOARD_PASSWORD:
            session['authenticated'] = True
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error='Invalid credentials'), 401
    
    # If already authenticated, redirect to dashboard
    if session.get('authenticated'):
        return redirect(url_for('dashboard'))
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('authenticated', None)
    return redirect(url_for('login'))

@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
@require_auth
def dashboard():
    # Log and store ALL requests to root path, including GET requests from target servers
    app.logger.info('Root request: %s / from %s', request.method, request.remote_addr)
    
    # Store callback data for ANY request to root (including when target fetches the URL)
    try:
        body = request.get_data(as_text=True)
    except:
        body = ''
    
    callback_data = store_callback(
        path='/',
        method=request.method,
        remote_addr=request.remote_addr,
        headers=request.headers,
        body=body
    )
    app.logger.info('  Service detected: %s', callback_data['service_detected'])
    app.logger.info('  User-Agent: %s', callback_data['user_agent'])
    
    # Return dashboard HTML for browser requests, or simple OK for API calls
    return render_template('dashboard.html')

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint for monitoring"""
    return jsonify({'status': 'ok', 'service': 'callback-server'}), 200

@app.route('/api/callbacks', methods=['GET'])
@require_auth
def get_callbacks():
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    service = request.args.get('service')
    callbacks, total = get_callbacks_from_db(limit=limit, offset=offset, service_filter=service)
    services = get_unique_services()
    return jsonify({'total': total, 'limit': limit, 'offset': offset, 'unique_services': len(services), 'services': services, 'callbacks': callbacks})

@app.route('/api/callbacks/public', methods=['GET'])
def get_callbacks_public():
    """Public API endpoint for getting callbacks (no auth required) - for toolkit integration"""
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    callbacks, total = get_callbacks_from_db(limit=limit, offset=offset, service_filter=None)
    return jsonify({'total': total, 'callbacks': callbacks})

@app.route('/api/clear', methods=['POST'])
@require_auth
def clear_callbacks():
    """Clear all callbacks from database"""
    try:
        clear_all_callbacks()
        return jsonify({'success': True, 'message': 'All callbacks cleared'}), 200
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/callbacks/<int:callback_id>', methods=['GET'])
def get_callback_detail(callback_id):
    callback = get_callback_by_id(callback_id)
    if not callback:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(callback)

@app.route('/api/dns_callbacks', methods=['GET'])
def get_dns_callbacks():
    """Get DNS callbacks from database"""
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute('''
                SELECT * FROM dns_callbacks 
                ORDER BY id DESC LIMIT ? OFFSET ?
            ''', (limit, offset)).fetchall()
            
            dns_callbacks = []
            for row in rows:
                dns_callbacks.append({
                    'id': row['id'],
                    'timestamp': row['timestamp'],
                    'domain': row['domain'],
                    'query_type': row['query_type'],
                    'client_ip': row['client_ip'],
                    'raw_query': row['raw_query']
                })
            
            total = conn.execute('SELECT COUNT(*) as total FROM dns_callbacks').fetchone()['total']
            return jsonify({'total': total, 'limit': limit, 'offset': offset, 'dns_callbacks': dns_callbacks})
        finally:
            conn.close()

@app.route('/api/all_callbacks', methods=['GET'])
@require_auth
def get_all_callbacks():
    """Get both HTTP and DNS callbacks combined"""
    limit = int(request.args.get('limit', 50))
    
    # Get HTTP callbacks
    http_callbacks, http_total = get_callbacks_from_db(limit=limit, offset=0)
    
    # Get DNS callbacks
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            dns_rows = conn.execute('''
                SELECT * FROM dns_callbacks 
                ORDER BY id DESC LIMIT ?
            ''', (limit,)).fetchall()
            
            dns_callbacks = []
            for row in dns_rows:
                dns_callbacks.append({
                    'id': row['id'],
                    'type': 'dns',
                    'timestamp': row['timestamp'],
                    'domain': row['domain'],
                    'query_type': row['query_type'],
                    'client_ip': row['client_ip']
                })
            
            dns_total = conn.execute('SELECT COUNT(*) as total FROM dns_callbacks').fetchone()['total']
        finally:
            conn.close()
    
    # Add type to HTTP callbacks
    for cb in http_callbacks:
        cb['type'] = 'http'
    
    # Combine and sort by timestamp
    all_callbacks = http_callbacks + dns_callbacks
    all_callbacks.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return jsonify({
        'total': http_total + dns_total,
        'http_total': http_total,
        'dns_total': dns_total,
        'callbacks': all_callbacks[:limit]
    })

@app.route('/api/callbacks', methods=['DELETE'])
@require_auth
def delete_all_callbacks():
    clear_all_callbacks()
    app.logger.info('All callbacks cleared')
    return jsonify({'success': True, 'message': 'All callbacks cleared'})

@app.route('/api/addresses', methods=['GET'])
def get_addresses():
    """Return all possible callback addresses for this server"""
    import socket
    addresses = ['localhost', '127.0.0.1']
    
    # Try to get local IP addresses
    try:
        hostname = socket.gethostname()
        local_ips = socket.gethostbyname_ex(hostname)[2]
        addresses.extend([ip for ip in local_ips if not ip.startswith('127.')])
    except:
        pass
    
    return jsonify({'addresses': addresses})

@app.route('/api/check_callback', methods=['GET'])
def check_callback():
    """Check if a callback was received for a specific path"""
    path = request.args.get('path', '')
    timeout = int(request.args.get('timeout', 5))
    
    # Query database for callbacks matching this path
    with db_lock:
        conn = sqlite3.connect(str(DB_PATH))
        conn.row_factory = sqlite3.Row
        try:
            # Check if callback exists (received within last 60 seconds)
            from datetime import timedelta
            cutoff_time = (datetime.now() - timedelta(seconds=60)).isoformat()
            
            row = conn.execute('''
                SELECT COUNT(*) as count FROM callbacks 
                WHERE path = ? AND timestamp >= ?
            ''', (path, cutoff_time)).fetchone()
            
            received = row['count'] > 0
            
            # Get latest callback details if exists
            details = None
            if received:
                latest = conn.execute('''
                    SELECT * FROM callbacks 
                    WHERE path = ? AND timestamp >= ?
                    ORDER BY id DESC LIMIT 1
                ''', (path, cutoff_time)).fetchone()
                
                if latest:
                    details = {
                        'id': latest['id'],
                        'timestamp': latest['timestamp'],
                        'remote_addr': latest['remote_addr'],
                        'user_agent': latest['user_agent'],
                        'service_detected': latest['service_detected']
                    }
            
            return jsonify({
                'received': received,
                'path': path,
                'details': details
            })
        finally:
            conn.close()

@app.route('/health', methods=['GET'])
def health():
    _, total = get_callbacks_from_db(limit=1)
    return jsonify({'status': 'healthy', 'callbacks_count': total, 'port': 8888, 'database': str(DB_PATH)})

@app.route('/<path:p>', methods=['GET','POST','PUT','DELETE','PATCH','OPTIONS'])
def catch_all(p):
    app.logger.info('Callback received: %s %s from %s', request.method, p, request.remote_addr)
    try:
        body = request.get_data(as_text=True)
    except:
        body = ''
    callback_data = store_callback(path='/' + p, method=request.method, remote_addr=request.remote_addr, headers=request.headers, body=body)
    app.logger.info('  Service detected: %s', callback_data['service_detected'])
    app.logger.info('  User-Agent: %s', callback_data['user_agent'])
    return 'OK', 200

if __name__ == '__main__':
    print("="*60)
    print(" Enhanced Callback Server with Realtime Dashboard")
    print("="*60)
    print(" Dashboard: http://localhost:8888/")
    print(" Callback endpoint: http://localhost:8888/<any-path>")
    print(" API: http://localhost:8888/api/callbacks")
    print(" Public URL: http://40.82.145.240:8888 (VPS)")
    print(" Database: " + str(DB_PATH))
    print("="*60)
    app.run(host='0.0.0.0', port=8888, debug=False)
