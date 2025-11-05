#!/usr/bin/env python3
"""
Test endpoint discovery với wordlist được cải thiện
Tập trung vào việc tìm endpoint /api/inventory/6/m trên quangtx.io.vn
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blackbox.reconnaissance.endpoint_discovery_v2 import EndpointDiscoveryV2
import time

def test_improved_wordlist():
    """Test wordlist discovery với cải thiện"""
    print("=" * 60)
    print("TESTING IMPROVED WORDLIST FOR ENDPOINT DISCOVERY")
    print("=" * 60)
    
    target = "https://quangtx.io.vn"
    
    print(f"[*] Target: {target}")
    print(f"[*] Looking for: /api/inventory/6/m")
    print()
    
    # Initialize discovery
    discovery = EndpointDiscoveryV2(target)
    
    # Check if the target endpoint specifically exists first
    print("[*] Testing known endpoint directly...")
    test_url = f"{target}/api/inventory/6/m"
    result = discovery._test_endpoint(test_url, source='manual')
    if result:
        print(f"[+] FOUND: {test_url}")
        print(f"    Method: {result.method}")
        print(f"    Status: {result.status_code}")
        print(f"    SSRF Potential: {result.ssrf_potential}")
        print(f"    Severity: {result.severity}")
    else:
        print(f"[-] Not found: {test_url}")
    print()
    
    # Test wordlist discovery
    print("[*] Running wordlist discovery...")
    start_time = time.time()
    
    # Chỉ test wordlist thôi để nhanh
    wordlist_results = discovery.discover_from_wordlist()
    
    end_time = time.time()
    duration = end_time - start_time
    
    print(f"[*] Wordlist discovery completed in {duration:.2f} seconds")
    print(f"[*] Found {len(wordlist_results)} endpoints")
    print()
    
    # Check if we found the target endpoint
    target_found = False
    for result in wordlist_results:
        if "/api/inventory/6/m" in result.url:
            target_found = True
            print(f"[+] TARGET FOUND: {result.url}")
            print(f"    Method: {result.method}")
            print(f"    Status: {result.status_code}")
            print(f"    SSRF Potential: {result.ssrf_potential}")
            print(f"    Severity: {result.severity}")
            break
    
    if not target_found:
        print("[-] Target endpoint /api/inventory/6/m NOT found in wordlist results")
    
    # Show all found endpoints
    if wordlist_results:
        print("\n[*] All discovered endpoints:")
        for i, result in enumerate(wordlist_results, 1):
            print(f"  {i:2d}. {result.url}")
            print(f"      Method: {result.method}")
            print(f"      Status: {result.status_code}")
            print(f"      SSRF: {result.ssrf_potential}")
            print(f"      Severity: {result.severity}")
            print()
    
    # Test một số endpoints có thể có SSRF
    print("[*] Testing potential SSRF endpoints manually...")
    test_endpoints = [
        "/api/inventory/6/m",
        "/api/inventory/6/s", 
        "/api/inventory/6/l",
        "/api/inventory/1/m",
        "/api/inventory",
        "/inventory"
    ]
    
    found_endpoints = []
    for endpoint in test_endpoints:
        test_url = f"{target}{endpoint}"
        result = discovery._test_endpoint(test_url, source='manual')
        if result:
            found_endpoints.append(result)
            print(f"[+] Found: {endpoint} (Status: {result.status_code})")
    
    if found_endpoints:
        print(f"\n[+] Manual testing found {len(found_endpoints)} endpoints")
        for result in found_endpoints:
            print(f"  - {result.url} (Status: {result.status_code}, SSRF: {result.ssrf_potential})")
    else:
        print("\n[-] Manual testing found no endpoints")

if __name__ == "__main__":
    test_improved_wordlist()