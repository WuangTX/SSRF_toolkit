"""
Test Burp File Upload to Graybox Scan
"""
import requests

# Read the Burp file
burp_file_path = r"C:\Users\ASUS-PRO\Documents\huhuhu1"

with open(burp_file_path, 'rb') as f:
    files = {
        'traffic_file': ('burp_export.xml', f, 'application/xml')
    }
    
    data = {
        'mode': 'graybox',
        'target': '',  # Optional
        'discover_docker': 'on',
        'ssrf_detection': ['pattern', 'parameter', 'network'],
        'confidence_threshold': 'medium'
    }
    
    print("🚀 Uploading Burp file and starting Graybox scan...")
    
    response = requests.post(
        'http://localhost:5000/api/scan/start',
        files=files,
        data=data
    )
    
    print(f"\n📊 Response Status: {response.status_code}")
    print(f"📄 Response: {response.json()}")
    
    if response.status_code == 200:
        print("\n✅ Scan started successfully!")
        print("🌐 Open http://localhost:5000/results to view progress")
    else:
        print(f"\n❌ Error: {response.json().get('error')}")
