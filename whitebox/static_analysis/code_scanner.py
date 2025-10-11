"""
Code Scanner - White Box Module
Static analysis để tìm SSRF vulnerabilities trong source code
"""

import os
import re
from pathlib import Path
from typing import List, Dict, Set
import ast

class CodeScanner:
    """Scanner cho Python code"""
    
    # SSRF-prone functions
    DANGEROUS_FUNCTIONS = {
        'python': [
            'requests.get', 'requests.post', 'requests.put', 'requests.delete',
            'urllib.request.urlopen', 'urllib.request.urlretrieve',
            'httpx.get', 'httpx.post', 'httpx.Client',
            'aiohttp.request', 'aiohttp.ClientSession',
            'socket.connect', 'socket.create_connection'
        ],
        'java': [
            'HttpURLConnection', 'HttpClient', 'RestTemplate',
            'WebClient', 'OkHttpClient', 'Socket'
        ],
        'javascript': [
            'fetch', 'axios', 'http.request', 'https.request',
            'request', 'got', 'superagent', 'needle'
        ]
    }
    
    # Parameter patterns
    URL_PARAMETER_PATTERNS = [
        r'(url|uri|link|callback|webhook|redirect|target|destination|host|proxy|fetch)[\s]*=',
        r'request\.(args|form|json|data)\[[\'"](url|uri|callback|webhook)[\'"]',
        r'@RequestParam.*\b(url|uri|callback)\b',
        r'req\.(query|body|params)\.(url|uri|callback)'
    ]
    
    def __init__(self, source_path: str):
        self.source_path = Path(source_path)
        self.findings = []
    
    def scan_directory(self, extensions: List[str] = ['.py', '.java', '.js']) -> List[Dict]:
        """Scan toàn bộ directory"""
        print(f"[*] Scanning {self.source_path}...")
        
        files = []
        for ext in extensions:
            files.extend(self.source_path.rglob(f'*{ext}'))
        
        print(f"[*] Found {len(files)} files to scan")
        
        for file_path in files:
            self._scan_file(file_path)
        
        return self.findings
    
    def _scan_file(self, file_path: Path):
        """Scan một file cụ thể"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Detect language
            ext = file_path.suffix
            if ext == '.py':
                self._scan_python(file_path, content)
            elif ext == '.java':
                self._scan_java(file_path, content)
            elif ext == '.js':
                self._scan_javascript(file_path, content)
        
        except Exception as e:
            print(f"[!] Error scanning {file_path}: {e}")
    
    def _scan_python(self, file_path: Path, content: str):
        """Scan Python code"""
        lines = content.split('\n')
        
        # Pattern 1: requests.get/post with user input
        for i, line in enumerate(lines, 1):
            # Check for dangerous functions
            for func in self.DANGEROUS_FUNCTIONS['python']:
                if func in line:
                    # Check if using user input
                    context = self._get_context(lines, i, window=5)
                    
                    has_user_input = any(
                        pattern in context
                        for pattern in ['request.args', 'request.form', 'request.json', 'request.data', 'input(']
                    )
                    
                    has_validation = any(
                        keyword in context
                        for keyword in ['whitelist', 'validate', 'sanitize', 'allowed_urls', 'check_url']
                    )
                    
                    if has_user_input and not has_validation:
                        self.findings.append({
                            'file': str(file_path),
                            'line': i,
                            'code': line.strip(),
                            'function': func,
                            'severity': 'CRITICAL',
                            'category': 'SSRF',
                            'description': f'Potential SSRF: {func} with user input without validation',
                            'cwe': 'CWE-918'
                        })
        
        # Pattern 2: AST analysis
        try:
            tree = ast.parse(content)
            visitor = SSRFVisitor(file_path)
            visitor.visit(tree)
            self.findings.extend(visitor.findings)
        except:
            pass
    
    def _scan_java(self, file_path: Path, content: str):
        """Scan Java code"""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for HTTP client usage
            if any(func in line for func in self.DANGEROUS_FUNCTIONS['java']):
                # Check for @RequestParam or similar
                context = self._get_context(lines, i, window=10)
                
                if any(pattern in context for pattern in ['@RequestParam', '@PathVariable', 'request.getParameter']):
                    # Check for validation
                    has_validation = any(
                        keyword in context
                        for keyword in ['validate', 'isValid', 'whitelist', 'URLValidator']
                    )
                    
                    if not has_validation:
                        self.findings.append({
                            'file': str(file_path),
                            'line': i,
                            'code': line.strip(),
                            'severity': 'CRITICAL',
                            'category': 'SSRF',
                            'description': 'Potential SSRF: HTTP client with user-controlled URL',
                            'cwe': 'CWE-918'
                        })
    
    def _scan_javascript(self, file_path: Path, content: str):
        """Scan JavaScript/Node.js code"""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            if any(func in line for func in self.DANGEROUS_FUNCTIONS['javascript']):
                context = self._get_context(lines, i, window=5)
                
                # Check for req.query, req.body, req.params
                has_user_input = any(
                    pattern in context
                    for pattern in ['req.query', 'req.body', 'req.params', 'request.query']
                )
                
                has_validation = 'validate' in context or 'whitelist' in context
                
                if has_user_input and not has_validation:
                    self.findings.append({
                        'file': str(file_path),
                        'line': i,
                        'code': line.strip(),
                        'severity': 'CRITICAL',
                        'category': 'SSRF',
                        'description': 'Potential SSRF: HTTP request with user input',
                        'cwe': 'CWE-918'
                    })
    
    def _get_context(self, lines: List[str], line_num: int, window: int = 5) -> str:
        """Lấy context xung quanh một line"""
        start = max(0, line_num - window - 1)
        end = min(len(lines), line_num + window)
        return '\n'.join(lines[start:end])
    
    def get_statistics(self) -> Dict:
        """Lấy statistics"""
        by_severity = {}
        by_file = {}
        
        for finding in self.findings:
            # By severity
            severity = finding['severity']
            by_severity[severity] = by_severity.get(severity, 0) + 1
            
            # By file
            file_name = finding['file']
            by_file[file_name] = by_file.get(file_name, 0) + 1
        
        return {
            'total_findings': len(self.findings),
            'by_severity': by_severity,
            'by_file': by_file,
            'critical_files': [f for f, count in by_file.items() if count > 0]
        }
    
    def export_report(self, output_file: str):
        """Export findings to file"""
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("# SSRF Static Analysis Report\n\n")
            
            stats = self.get_statistics()
            f.write(f"## Summary\n")
            f.write(f"- Total Findings: {stats['total_findings']}\n")
            f.write(f"- By Severity: {stats['by_severity']}\n\n")
            
            f.write("## Findings\n\n")
            for i, finding in enumerate(self.findings, 1):
                f.write(f"### {i}. {finding['description']}\n")
                f.write(f"- **File**: `{finding['file']}`\n")
                f.write(f"- **Line**: {finding['line']}\n")
                f.write(f"- **Severity**: {finding['severity']}\n")
                f.write(f"- **Code**: `{finding['code']}`\n")
                f.write(f"- **CWE**: {finding['cwe']}\n\n")

class SSRFVisitor(ast.NodeVisitor):
    """AST Visitor để detect SSRF patterns"""
    
    def __init__(self, file_path: Path):
        self.file_path = file_path
        self.findings = []
        self.user_input_vars = set()
    
    def visit_Assign(self, node):
        """Track variables được gán từ user input"""
        # Check if right side is request.args.get() etc.
        if isinstance(node.value, ast.Call):
            if hasattr(node.value.func, 'attr'):
                if node.value.func.attr in ['get', 'getlist']:
                    # This might be request.args.get()
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            self.user_input_vars.add(target.id)
        
        self.generic_visit(node)
    
    def visit_Call(self, node):
        """Check function calls"""
        # Check if calling requests.get() with user-controlled variable
        if hasattr(node.func, 'attr'):
            if node.func.attr in ['get', 'post', 'put', 'delete']:
                # Check arguments
                for arg in node.args:
                    if isinstance(arg, ast.Name):
                        if arg.id in self.user_input_vars:
                            self.findings.append({
                                'file': str(self.file_path),
                                'line': node.lineno,
                                'code': ast.unparse(node) if hasattr(ast, 'unparse') else 'N/A',
                                'severity': 'CRITICAL',
                                'category': 'SSRF',
                                'description': f'SSRF: Using user input variable "{arg.id}" in HTTP request',
                                'cwe': 'CWE-918'
                            })
        
        self.generic_visit(node)

if __name__ == "__main__":
    # Test
    scanner = CodeScanner(".")
    findings = scanner.scan_directory()
    
    print(f"\n[+] Found {len(findings)} potential SSRF vulnerabilities:")
    for finding in findings:
        print(f"  [{finding['severity']}] {finding['file']}:{finding['line']}")
        print(f"      {finding['description']}")
    
    scanner.export_report("ssrf_scan_report.md")
