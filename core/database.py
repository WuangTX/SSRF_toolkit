"""
Finding Database
SQLite database để lưu trữ tất cả findings
"""

import sqlite3
import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, asdict

@dataclass
class Finding:
    """Cấu trúc của một finding"""
    id: Optional[int] = None
    timestamp: str = ""
    mode: str = ""  # blackbox, graybox, whitebox
    severity: str = ""  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str = ""  # SSRF, XSS, SQLi, etc.
    title: str = ""
    description: str = ""
    affected_url: str = ""
    request: str = ""
    response: str = ""
    proof_of_concept: str = ""
    remediation: str = ""
    cvss_score: float = 0.0
    cwe_id: str = ""
    references: List[str] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if self.references is None:
            self.references = []

class FindingDatabase:
    """Database quản lý findings"""
    
    def __init__(self, db_path: str = "pentest_findings.db"):
        self.db_path = db_path
        self.conn = None
        self._init_db()
    
    def _init_db(self):
        """Khởi tạo database"""
        # Create directory if needed
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        
        self.conn = sqlite3.connect(self.db_path)
        self.conn.row_factory = sqlite3.Row
        
        cursor = self.conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                mode TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                affected_url TEXT,
                request TEXT,
                response TEXT,
                proof_of_concept TEXT,
                remediation TEXT,
                cvss_score REAL,
                cwe_id TEXT,
                reference_links TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                mode TEXT NOT NULL,
                target_url TEXT,
                duration_seconds REAL,
                findings_count INTEGER,
                config TEXT
            )
        ''')
        
        self.conn.commit()
    
    def add_finding(self, finding: Finding) -> int:
        """Thêm finding mới"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO findings (
                timestamp, mode, severity, category, title, description,
                affected_url, request, response, proof_of_concept, 
                remediation, cvss_score, cwe_id, reference_links
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            finding.timestamp,
            finding.mode,
            finding.severity,
            finding.category,
            finding.title,
            finding.description,
            finding.affected_url,
            finding.request,
            finding.response,
            finding.proof_of_concept,
            finding.remediation,
            finding.cvss_score,
            finding.cwe_id,
            json.dumps(finding.references)
        ))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def get_findings(self, 
                     mode: Optional[str] = None,
                     severity: Optional[str] = None,
                     category: Optional[str] = None) -> List[Finding]:
        """Lấy findings với filters"""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []
        
        if mode:
            query += " AND mode = ?"
            params.append(mode)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if category:
            query += " AND category = ?"
            params.append(category)
        
        query += " ORDER BY timestamp DESC"
        
        cursor = self.conn.cursor()
        cursor.execute(query, params)
        
        findings = []
        for row in cursor.fetchall():
            finding = Finding(
                id=row['id'],
                timestamp=row['timestamp'],
                mode=row['mode'],
                severity=row['severity'],
                category=row['category'],
                title=row['title'],
                description=row['description'],
                affected_url=row['affected_url'],
                request=row['request'],
                response=row['response'],
                proof_of_concept=row['proof_of_concept'],
                remediation=row['remediation'],
                cvss_score=row['cvss_score'],
                cwe_id=row['cwe_id'],
                references=json.loads(row['reference_links']) if row['reference_links'] else []
            )
            findings.append(finding)
        
        return findings
    
    def get_statistics(self) -> Dict:
        """Lấy thống kê findings"""
        cursor = self.conn.cursor()
        
        # Total findings
        cursor.execute("SELECT COUNT(*) as count FROM findings")
        total = cursor.fetchone()['count']
        
        # By severity
        cursor.execute("""
            SELECT severity, COUNT(*) as count 
            FROM findings 
            GROUP BY severity
        """)
        by_severity = {row['severity']: row['count'] for row in cursor.fetchall()}
        
        # By mode
        cursor.execute("""
            SELECT mode, COUNT(*) as count 
            FROM findings 
            GROUP BY mode
        """)
        by_mode = {row['mode']: row['count'] for row in cursor.fetchall()}
        
        # By category
        cursor.execute("""
            SELECT category, COUNT(*) as count 
            FROM findings 
            GROUP BY category
        """)
        by_category = {row['category']: row['count'] for row in cursor.fetchall()}
        
        return {
            'total': total,
            'by_severity': by_severity,
            'by_mode': by_mode,
            'by_category': by_category
        }
    
    def start_session(self, mode: str, target_url: str, config: Dict) -> int:
        """Bắt đầu scan session"""
        cursor = self.conn.cursor()
        cursor.execute('''
            INSERT INTO scan_sessions (timestamp, mode, target_url, config)
            VALUES (?, ?, ?, ?)
        ''', (
            datetime.now().isoformat(),
            mode,
            target_url,
            json.dumps(config)
        ))
        
        self.conn.commit()
        return cursor.lastrowid
    
    def end_session(self, session_id: int, duration: float, findings_count: int):
        """Kết thúc scan session"""
        cursor = self.conn.cursor()
        cursor.execute('''
            UPDATE scan_sessions 
            SET duration_seconds = ?, findings_count = ?
            WHERE id = ?
        ''', (duration, findings_count, session_id))
        
        self.conn.commit()
    
    def export_json(self, output_file: str):
        """Export findings ra JSON"""
        findings = self.get_findings()
        data = {
            'metadata': {
                'exported_at': datetime.now().isoformat(),
                'total_findings': len(findings),
                'statistics': self.get_statistics()
            },
            'findings': [asdict(f) for f in findings]
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    
    def close(self):
        """Đóng database connection"""
        if self.conn:
            self.conn.close()
