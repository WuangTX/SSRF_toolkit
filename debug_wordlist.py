#!/usr/bin/env python3
"""
Debug script để tìm hiểu tại sao /api/inventory/6/m không xuất hiện trong wordlist results
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blackbox.reconnaissance.endpoint_discovery_v2 import EndpointDiscoveryV2

def debug_wordlist():
    """Debug wordlist để xem có /api/inventory/6/m không"""
    
    target = "https://quangtx.io.vn"
    discovery = EndpointDiscoveryV2(target)
    
    # Lấy wordlist
    wordlist = discovery._get_default_wordlist()
    
    print(f"[*] Total wordlist paths: {len(wordlist)}")
    print(f"[*] Looking for '/api/inventory/6/m' in wordlist...")
    
    target_path = '/api/inventory/6/m'
    if target_path in wordlist:
        index = wordlist.index(target_path)
        print(f"[+] Found '{target_path}' at index {index}")
        
        # Kiểm tra các paths xung quanh
        print(f"[*] Context around index {index}:")
        start = max(0, index - 3)
        end = min(len(wordlist), index + 4)
        for i in range(start, end):
            marker = " --> " if i == index else "     "
            print(f"{marker}{i:3d}: {wordlist[i]}")
    else:
        print(f"[-] NOT found '{target_path}' in wordlist")
        
        # Tìm các paths tương tự
        similar_paths = [path for path in wordlist if '/api/inventory/6/' in path]
        print(f"[*] Similar paths found: {similar_paths}")
        
        # Kiểm tra xem có /api/inventory/6/ nào không
        inventory6_paths = [path for path in wordlist if path.startswith('/api/inventory/6')]
        print(f"[*] All /api/inventory/6* paths: {inventory6_paths}")
    
    # Test trực tiếp endpoint này
    print(f"\n[*] Testing '{target_path}' directly...")
    test_url = f"{target}{target_path}"
    result = discovery._test_endpoint(test_url, source='debug')
    
    if result:
        print(f"[+] Direct test SUCCESS:")
        print(f"    URL: {result.url}")
        print(f"    Method: {result.method}")
        print(f"    Status: {result.status_code}")
        print(f"    SSRF: {result.ssrf_potential}")
        print(f"    Severity: {result.severity}")
    else:
        print(f"[-] Direct test FAILED")

if __name__ == "__main__":
    debug_wordlist()