#!/usr/bin/env python3
"""
Test stability của endpoint /api/inventory/6/m
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from blackbox.reconnaissance.endpoint_discovery_v2 import EndpointDiscoveryV2
import time

def test_endpoint_stability():
    """Test endpoint stability"""
    
    target = "https://quangtx.io.vn"
    discovery = EndpointDiscoveryV2(target)
    
    test_endpoints = [
        "/api/inventory/6",
        "/api/inventory/6/s", 
        "/api/inventory/6/m",
        "/api/inventory/6/l"
    ]
    
    print(f"[*] Testing endpoint stability...")
    print(f"[*] Target: {target}")
    print(f"[*] Test endpoints: {test_endpoints}")
    print()
    
    for endpoint in test_endpoints:
        print(f"[*] Testing {endpoint}")
        
        success_count = 0
        total_tests = 5
        
        for i in range(total_tests):
            test_url = f"{target}{endpoint}"
            result = discovery._test_endpoint(test_url, source='stability_test')
            
            if result and result.status_code == 200:
                success_count += 1
                print(f"  Test {i+1}: SUCCESS (Status: {result.status_code})")
            else:
                status = result.status_code if result else "No response"
                print(f"  Test {i+1}: FAILED (Status: {status})")
            
            # Small delay between tests
            time.sleep(0.5)
        
        success_rate = (success_count / total_tests) * 100
        print(f"  Success rate: {success_count}/{total_tests} ({success_rate}%)")
        print()
    
    # Test với wordlist method để so sánh
    print("[*] Testing with discover_from_wordlist() method...")
    
    # Tạo custom wordlist chỉ có các endpoints này
    custom_wordlist = test_endpoints
    
    # Ghi đè wordlist method temporarily
    original_method = discovery._get_default_wordlist
    discovery._get_default_wordlist = lambda: custom_wordlist
    
    try:
        results = discovery.discover_from_wordlist()
        print(f"[*] Wordlist method found {len(results)} endpoints:")
        
        for result in results:
            print(f"  - {result.url} (Status: {result.status_code})")
        
        # Check if target endpoint found
        target_found = any('/api/inventory/6/m' in r.url for r in results)
        print(f"\n[*] Target /api/inventory/6/m found: {target_found}")
        
    finally:
        # Restore original method
        discovery._get_default_wordlist = original_method

if __name__ == "__main__":
    test_endpoint_stability()