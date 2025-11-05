#!/usr/bin/env python3
"""
Debug discovery process để xem tại sao /api/inventory/6/m bị mất
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blackbox.reconnaissance.endpoint_discovery_v2 import EndpointDiscoveryV2

def debug_discovery():
    """Debug discovery process step by step"""
    
    target = "https://quangtx.io.vn"
    discovery = EndpointDiscoveryV2(target)
    
    # Chỉ test một số paths quan trọng
    test_paths = [
        '/api/inventory/6/s',
        '/api/inventory/6/m', 
        '/api/inventory/6/l',
        '/api/inventory/6'
    ]
    
    print(f"[*] Testing specific paths on {target}")
    print(f"[*] Target paths: {test_paths}")
    print()
    
    results = []
    for path in test_paths:
        test_url = f"{target}{path}"
        print(f"[*] Testing: {test_url}")
        
        result = discovery._test_endpoint(test_url, source='debug')
        if result:
            results.append(result)
            print(f"[+] SUCCESS: {result.url} (Status: {result.status_code}, SSRF: {result.ssrf_potential})")
        else:
            print(f"[-] FAILED: {test_url}")
        print()
    
    print(f"[*] Total successful results: {len(results)}")
    
    # Test deduplication process
    print(f"\n[*] Testing deduplication...")
    print(f"[*] Before deduplication: {len(results)} results")
    
    if hasattr(discovery, '_deduplicate_results'):
        deduplicated = discovery._deduplicate_results(results)
        print(f"[*] After deduplication: {len(deduplicated)} results")
        
        target_found = any('/api/inventory/6/m' in r.url for r in deduplicated)
        print(f"[*] Target /api/inventory/6/m found after deduplication: {target_found}")
        
        print(f"\n[*] Deduplicated results:")
        for i, result in enumerate(deduplicated, 1):
            print(f"  {i:2d}. {result.url} (Status: {result.status_code})")
    else:
        print(f"[-] No _deduplicate_results method found")
    
    # Chạy discovery bình thường và xem kết quả
    print(f"\n[*] Running normal wordlist discovery...")
    wordlist_results = discovery.discover_from_wordlist()
    
    target_found_in_normal = any('/api/inventory/6/m' in r.url for r in wordlist_results)
    print(f"[*] Target /api/inventory/6/m found in normal discovery: {target_found_in_normal}")
    
    print(f"[*] Found {len(wordlist_results)} endpoints in normal discovery")
    
    # Tìm endpoints có inventory/6
    inventory6_results = [r for r in wordlist_results if '/inventory/6' in r.url]
    print(f"\n[*] Endpoints with '/inventory/6': {len(inventory6_results)}")
    for result in inventory6_results:
        print(f"  - {result.url} (Status: {result.status_code})")

if __name__ == "__main__":
    debug_discovery()