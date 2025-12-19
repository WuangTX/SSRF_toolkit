"""
Quick SSRF test to verify toolkit detection is working
"""
import sys
sys.path.insert(0, '.')

from blackbox.detection.external_callback import ExternalCallbackDetector
from web_ui.app import CallbackServerClient
import os

# Setup callback server client (VPS)
os.environ['CALLBACK_URL'] = 'http://40.82.145.240:8888'
callback_server = CallbackServerClient(host='40.82.145.240', port=8888)

# Create detector
detector = ExternalCallbackDetector(callback_server=callback_server)

# Add auth headers
os.environ['CUSTOM_HEADERS'] = 'Token:token=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiQURNSU4iLCJzdWIiOiJhZG1pbiIsImlhdCI6MTc2NTk0OTgxMSwiZXhwIjoxNzY2MDM2MjExfQ.P_6YkmyrdPEhkvOn4LkxmR6MaNb3s9pOw7GQCHrUUL8;Cookie:csrftoken=ewyxpUtTxvZYXTHqjGpbu8zV7AFDHaEc'

print("=" * 80)
print("🧪 Testing SSRF Detection with Updated Logic")
print("=" * 80)

target = "https://quangtx.io.vn/api/products/5/fetch_review/"

print(f"\nTarget: {target}")
print(f"Callback Server: http://40.82.145.240:8888")
print(f"Testing parameter: review_url (POST)\n")

# Test
result = detector.test_ssrf(
    target_url=target,
    parameter='review_url',
    method='POST',
    timeout=10
)

print("\n" + "=" * 80)
print("📊 Test Result")
print("=" * 80)
print(f"Vulnerable: {result['is_vulnerable']}")
print(f"Callbacks Received: {result['callbacks_received']}")

if result['is_vulnerable']:
    print("\n✅ SSRF DETECTION WORKING!")
    print("Toolkit can now detect this vulnerability in scans.")
else:
    print("\n❌ Still not detecting SSRF")
    print("Debug info:")
    print(f"Attempts: {len(result['all_attempts'])}")
    for attempt in result['all_attempts']:
        print(f"\n  Address: {attempt['address']}")
        print(f"  Callbacks: {attempt['callbacks_received']}")
        print(f"  Details: {attempt['callback_details']}")
