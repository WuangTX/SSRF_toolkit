#!/usr/bin/env python3
"""
Quick test for EndpointDiscoveryV2 to debug issues
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from blackbox.reconnaissance.endpoint_discovery_v2 import EndpointDiscoveryV2
import json

def test_quangtx():
    """Test với quangtx.io.vn"""
    print('🧪 Testing EndpointDiscoveryV2 với quangtx.io.vn...')
    
    discovery = EndpointDiscoveryV2(
        'https://quangtx.io.vn', 
        timeout=5, 
        max_workers=2, 
        rate_limit=1.0
    )
    
    try:
        # Test individual methods first
        print('\n1️⃣ Testing wordlist discovery...')
        wordlist_results = discovery.discover_from_wordlist()
        print(f'Wordlist: {len(wordlist_results)} endpoints')
        
        print('\n2️⃣ Testing sitemap discovery...')
        sitemap_results = discovery.discover_from_sitemap()
        print(f'Sitemap: {len(sitemap_results)} endpoints')
        
        print('\n3️⃣ Testing robots discovery...')
        robots_results = discovery.discover_from_robots()
        print(f'Robots: {len(robots_results)} endpoints')
        
        # Skip JS for now to avoid errors
        print('\n4️⃣ Skipping JavaScript discovery...')
        
        # Combine results manually
        all_results = []
        all_results.extend(wordlist_results)
        all_results.extend(sitemap_results) 
        all_results.extend(robots_results)
        
        unique_results = discovery._deduplicate_results(all_results)
        
        print(f'\n📊 Final Results: {len(unique_results)} unique endpoints')
        
        for result in unique_results:
            print(f'✅ {result.url} [{result.status_code}] - {result.severity} ({result.source})')
            if result.accepts_post:
                print(f'   POST support: ✅')
            if result.ssrf_potential != 'unknown':
                print(f'   SSRF potential: {result.ssrf_potential}')
        
        # Get summary
        summary = discovery.get_summary()
        print(f'\n📈 Summary:')
        print(f'Total endpoints: {summary["total_endpoints"]}')
        print(f'Severity breakdown: {json.dumps(summary["severity_breakdown"], indent=2)}')
        
        return unique_results
        
    except Exception as e:
        print(f'❌ Error: {str(e)}')
        import traceback
        traceback.print_exc()
        return []

if __name__ == "__main__":
    results = test_quangtx()
    print(f"\n🎉 Test completed! Found {len(results)} endpoints")