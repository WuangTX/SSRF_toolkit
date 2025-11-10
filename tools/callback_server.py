"""
Enhanced Callback Server with Realtime Dashboard + SQLite Database
Receives SSRF callbacks and displays them in a web UI for analysis.
"""
from flask import Flask, request, jsonify, render_template
import logging
from datetime import datetime
from threading import Lock
import os
import json
import sqlite3
from pathlib import Path

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

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
        conn.execute('''
            CREATE TABLE IF NOT EXISTS callbacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                remote_addr TEXT NOT NULL,
                headers TEXT NOT NULL,
                body TEXT,
                body_length INTEGER DEFAULT 0,
                user_agent TEXT,
                service_detected TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON callbacks(timestamp DESC)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_service ON callbacks(service_detected)')
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
            cursor = conn.execute('''
                INSERT INTO callbacks (timestamp, path, method, remote_addr, headers, body, body_length, user_agent, service_detected)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (datetime.now().isoformat(), path, method, remote_addr, json.dumps(dict(headers)), body_text, len(body) if body else 0, user_agent, service))
            callback_id = cursor.lastrowid
            conn.commit()
            return {'id': callback_id, 'timestamp': datetime.now().isoformat(), 'path': path, 'method': method, 'remote_addr': remote_addr, 'user_agent': user_agent, 'service_detected': service}
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
                callbacks.append({'id': row['id'], 'timestamp': row['timestamp'], 'path': row['path'], 'method': row['method'], 'remote_addr': row['remote_addr'], 'headers': json.loads(row['headers']), 'body': row['body'], 'body_length': row['body_length'], 'user_agent': row['user_agent'], 'service_detected': row['service_detected']})
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
            return {'id': row['id'], 'timestamp': row['timestamp'], 'path': row['path'], 'method': row['method'], 'remote_addr': row['remote_addr'], 'headers': json.loads(row['headers']), 'body': row['body'], 'body_length': row['body_length'], 'user_agent': row['user_agent'], 'service_detected': row['service_detected']}
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
            conn.commit()
        finally:
            conn.close()

@app.route('/', methods=['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'])
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

@app.route('/api/callbacks', methods=['GET'])
def get_callbacks():
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    service = request.args.get('service')
    callbacks, total = get_callbacks_from_db(limit=limit, offset=offset, service_filter=service)
    services = get_unique_services()
    return jsonify({'total': total, 'limit': limit, 'offset': offset, 'unique_services': len(services), 'services': services, 'callbacks': callbacks})

@app.route('/api/callbacks/<int:callback_id>', methods=['GET'])
def get_callback_detail(callback_id):
    callback = get_callback_by_id(callback_id)
    if not callback:
        return jsonify({'error': 'Not found'}), 404
    return jsonify(callback)

@app.route('/api/callbacks', methods=['DELETE'])
def clear_callbacks():
    clear_all_callbacks()
    app.logger.info('All callbacks cleared')
    return jsonify({'success': True, 'message': 'All callbacks cleared'})

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
    print(" Use ngrok to expose: ngrok http 8888")
    print(" Database: " + str(DB_PATH))
    print("="*60)
    app.run(host='0.0.0.0', port=8888, debug=False)
