#!/usr/bin/env python3
"""
Test script for Enhanced Endpoint Discovery V2
"""

from blackbox.reconnaissance.endpoint_discovery_v2 import EndpointDiscoveryV2
import json
import sys

def test_comprehensive_discovery():
    """Test comprehensive endpoint discovery"""
    print('🧪 Testing Enhanced Endpoint Discovery V2...')
    
    # Initialize discovery engine
    discovery = EndpointDiscoveryV2(
        'https://quangtx.io.vn', 
        timeout=5, 
        max_workers=3, 
        rate_limit=1.5
    )
    
    try:
        # Run comprehensive discovery
        print('\n🔍 Starting comprehensive discovery...')
        results = discovery.discover_comprehensive()
        
        # Get summary
        summary = discovery.get_summary()
        
        # Print results
        print(f'\n📊 Discovery Results Summary:')
        print(f'Target: {summary["target_url"]}')
        print(f'Total endpoints found: {summary["total_endpoints"]}')
        print(f'Backend services detected: {summary["backend_services"]}')
        
        print(f'\n🚨 Severity Breakdown:')
        for severity, count in summary["severity_breakdown"].items():
            if count > 0:
                print(f'  {severity.upper()}: {count} endpoints')
        
        print(f'\n📈 Statistics:')
        stats = summary["statistics"]
        success_rate = (stats["successful_requests"] / max(stats["total_requests"], 1)) * 100
        print(f'  Success rate: {success_rate:.1f}% ({stats["successful_requests"]}/{stats["total_requests"]})')
        print(f'  Average response time: {stats["avg_response_time"]:.3f}s')
        
        # Export results
        json_file = discovery.export_results('json', 'test_discovery_results')
        print(f'\n💾 Results exported to: {json_file}')
        
        # Show discovered endpoints
        if results:
            print(f'\n🎯 Discovered Endpoints (Top 10):')
            for i, endpoint in enumerate(results[:10]):
                print(f'{i+1:2d}. {endpoint.url}')
                print(f'     Status: {endpoint.status_code} | Severity: {endpoint.severity} | Source: {endpoint.source}')
                if endpoint.metadata:
                    print(f'     Metadata: {endpoint.metadata}')
                print()
        
        return results
        
    except Exception as e:
        print(f'❌ Error during testing: {str(e)}')
        import traceback
        traceback.print_exc()
        return []

def test_individual_methods():
    """Test individual discovery methods"""
    print('\n🔬 Testing Individual Discovery Methods...')
    
    discovery = EndpointDiscoveryV2('https://httpbin.org', timeout=3, rate_limit=1.0)
    
    # Test wordlist discovery
    print('\n1️⃣ Testing wordlist discovery...')
    wordlist_results = discovery.discover_from_wordlist()
    print(f'   Found {len(wordlist_results)} endpoints from wordlist')
    
    # Test sitemap discovery
    print('\n2️⃣ Testing sitemap discovery...')
    sitemap_results = discovery.discover_from_sitemap()
    print(f'   Found {len(sitemap_results)} endpoints from sitemap')
    
    # Test robots.txt discovery
    print('\n3️⃣ Testing robots.txt discovery...')
    robots_results = discovery.discover_from_robots()
    print(f'   Found {len(robots_results)} endpoints from robots.txt')
    
    # Test JavaScript discovery
    print('\n4️⃣ Testing JavaScript discovery...')
    try:
        js_results = discovery.discover_from_javascript()
        print(f'   Found {len(js_results)} endpoints from JavaScript')
    except Exception as e:
        print(f'   JavaScript discovery error: {str(e)}')
        js_results = []
    
    total = len(wordlist_results) + len(sitemap_results) + len(robots_results) + len(js_results)
    print(f'\n📊 Individual method results: {total} total endpoints')
    
    return {
        'wordlist': wordlist_results,
        'sitemap': sitemap_results, 
        'robots': robots_results,
        'javascript': js_results
    }

if __name__ == "__main__":
    print("🚀 Enhanced Endpoint Discovery V2 Test Suite")
    print("=" * 50)
    
    # Test comprehensive discovery
    comprehensive_results = test_comprehensive_discovery()
    
    # Test individual methods
    individual_results = test_individual_methods()
    
    print("\n✅ Testing completed!")
    print(f"Comprehensive discovery found: {len(comprehensive_results)} endpoints")
    
    individual_total = sum(len(results) for results in individual_results.values())
    print(f"Individual methods total: {individual_total} endpoints")
    
    if comprehensive_results:
        print("\n🎉 Enhanced Endpoint Discovery V2 is working correctly!")
    else:
        print("\n⚠️  No endpoints discovered - check target availability")