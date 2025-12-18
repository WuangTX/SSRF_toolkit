"""
DNS Callback Server for SSRF Detection
Logs all DNS queries to detect blind SSRF vulnerabilities
Integrates with HTTP callback server database
"""

import socket
import struct
import threading
import sqlite3
import json
from datetime import datetime
from pathlib import Path
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database path (shared with HTTP callback server)
DB_PATH = Path(__file__).parent / 'callbacks.db'

class DNSQuery:
    def __init__(self, data):
        self.data = data
        self.domain = ''
        tipo = (data[2] >> 3) & 15  # Opcode bits
        if tipo == 0:  # Standard query
            ini = 12
            lon = data[ini]
            while lon != 0:
                self.domain += data[ini+1:ini+lon+1].decode('utf-8') + '.'
                ini += lon + 1
                lon = data[ini]
            self.domain = self.domain[:-1]  # Remove trailing dot

def create_dns_response(query_data, client_ip):
    """Create a DNS response pointing to our VPS IP"""
    response = bytearray(query_data)
    
    # Set response flags
    response[2] = 0x81  # Response, no error
    response[3] = 0x80  # Recursion available
    
    # Answer count = 1
    response[6] = 0x00
    response[7] = 0x01
    
    # Add answer (Type A, Class IN, TTL 60s, IP address)
    response += query_data[12:]  # Copy question section
    response += b'\xc0\x0c'      # Pointer to domain name
    response += b'\x00\x01'      # Type A
    response += b'\x00\x01'      # Class IN
    response += b'\x00\x00\x00\x3c'  # TTL 60 seconds
    response += b'\x00\x04'      # Data length 4 bytes
    
    # VPS IP: 40.82.145.240
    response += bytes([40, 82, 145, 240])
    
    return bytes(response)

def store_dns_callback(domain, query_type, client_ip, raw_query):
    """Store DNS callback in database"""
    try:
        conn = sqlite3.connect(str(DB_PATH))
        cursor = conn.cursor()
        
        # Create DNS callbacks table if not exists
        cursor.execute('''
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
        
        cursor.execute('''
            INSERT INTO dns_callbacks (timestamp, domain, query_type, client_ip, raw_query)
            VALUES (?, ?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            domain,
            query_type,
            client_ip,
            raw_query.hex() if raw_query else None
        ))
        
        conn.commit()
        conn.close()
        
        logger.info(f'✓ DNS Query logged: {domain} from {client_ip}')
        return True
    except Exception as e:
        logger.error(f'Error storing DNS callback: {e}')
        return False

def handle_dns_query(data, addr, sock):
    """Handle incoming DNS query"""
    try:
        query = DNSQuery(data)
        
        if query.domain:
            logger.info(f'🔍 DNS Query: {query.domain} from {addr[0]}:{addr[1]}')
            
            # Store in database
            store_dns_callback(
                domain=query.domain,
                query_type='A',
                client_ip=addr[0],
                raw_query=data
            )
            
            # Send DNS response pointing to our VPS
            response = create_dns_response(data, addr[0])
            sock.sendto(response, addr)
            logger.info(f'✓ DNS Response sent to {addr[0]} -> 40.82.145.240')
        
    except Exception as e:
        logger.error(f'Error handling DNS query: {e}')

def start_dns_server(host='0.0.0.0', port=53):
    """Start DNS server"""
    try:
        # Create UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        
        logger.info(f'='*60)
        logger.info(f' DNS Callback Server Started')
        logger.info(f'='*60)
        logger.info(f' Listening on: {host}:{port}')
        logger.info(f' VPS IP: 40.82.145.240')
        logger.info(f' Database: {DB_PATH}')
        logger.info(f' ')
        logger.info(f' Test DNS query:')
        logger.info(f'   nslookup test.40.82.145.240 40.82.145.240')
        logger.info(f'   dig @40.82.145.240 test.example.com')
        logger.info(f'='*60)
        
        # Listen for DNS queries
        while True:
            try:
                data, addr = sock.recvfrom(512)  # DNS messages are typically < 512 bytes
                
                # Handle in separate thread to avoid blocking
                thread = threading.Thread(
                    target=handle_dns_query,
                    args=(data, addr, sock)
                )
                thread.daemon = True
                thread.start()
                
            except Exception as e:
                logger.error(f'Error receiving DNS query: {e}')
                
    except PermissionError:
        logger.error('='*60)
        logger.error(' ERROR: Permission denied to bind port 53')
        logger.error('='*60)
        logger.error(' DNS server requires elevated privileges (port 53)')
        logger.error(' ')
        logger.error(' On Linux/Mac: sudo python3 dns_callback_server.py')
        logger.error(' On Windows: Run as Administrator')
        logger.error(' ')
        logger.error(' Alternative: Use port 5353 (no admin required)')
        logger.error(' Change DNS_PORT in .env to 5353')
        logger.error('='*60)
        return False
    except Exception as e:
        logger.error(f'Failed to start DNS server: {e}')
        return False

if __name__ == '__main__':
    import sys
    
    # Allow custom port via command line
    port = 53
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            logger.error(f'Invalid port: {sys.argv[1]}')
            sys.exit(1)
    
    logger.info(f'Starting DNS Callback Server on port {port}...')
    
    if port == 53:
        logger.warning('⚠️  Port 53 requires administrator/root privileges')
        logger.info('💡 Alternative: Use port 5353 (no admin required)')
        logger.info('   python dns_callback_server.py 5353')
    
    start_dns_server(port=port)
