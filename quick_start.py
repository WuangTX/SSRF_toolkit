"""
Quick Start Demo
Chạy các demos nhanh cho từng mode
"""

import sys
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

print("""
╔══════════════════════════════════════════════════════════════╗
║       🎯 MICROSERVICE SSRF PENTEST TOOLKIT - DEMO           ║
╚══════════════════════════════════════════════════════════════╝
""")

def demo_black_box():
    """Demo Black Box scanning"""
    print("\n" + "="*60)
    print("📋 DEMO 1: BLACK BOX SCANNING")
    print("="*60)
    
    from blackbox.reconnaissance.parameter_fuzzer import ParameterFuzzer
    
    print("\n🔍 Testing parameter fuzzing on local endpoint...")
    print("Target: http://localhost:8083/inventory/1/M")
    
    fuzzer = ParameterFuzzer(timeout=5)
    
    # Test một số parameters
    test_params = ['callback_url', 'url', 'webhook']
    
    print(f"\nTesting {len(test_params)} parameters...")
    
    for param in test_params:
        print(f"\n  Testing parameter: {param}")
        # Simulate test
        confidence = 0.85 if param == 'callback_url' else 0.0
        
        if confidence > 0.5:
            print(f"  ✅ VULNERABLE! Confidence: {confidence:.2f}")
        else:
            print(f"  ❌ Not vulnerable")
    
    print("\n✨ Black Box demo complete!")
    print("\nℹ️  To run full Black Box scan:")
    print("   python cli.py --mode blackbox --target http://localhost:8083/inventory/1/M")

def demo_gray_box():
    """Demo Gray Box scanning"""
    print("\n" + "="*60)
    print("📋 DEMO 2: GRAY BOX SCANNING (Docker)")
    print("="*60)
    
    from graybox.architecture.docker_inspector import DockerInspector
    
    inspector = DockerInspector()
    
    if not inspector.is_available:
        print("\n⚠️  Docker is not available!")
        print("Please start Docker to run Gray Box scan.")
        print("\nTo simulate Gray Box analysis:")
        print("   docker-compose up -d")
        print("   python cli.py --mode graybox --docker")
        return
    
    print("\n🐳 Analyzing Docker environment...")
    
    # Get networks
    networks = inspector.get_networks()
    print(f"\n✅ Found {len(networks)} Docker networks:")
    for net in networks:
        print(f"   • {net['name']} - {len(net['containers'])} containers")
    
    # Get containers
    containers = inspector.get_containers()
    print(f"\n✅ Found {len(containers)} running containers:")
    for container in containers:
        print(f"   • {container['name']} - {container['status']}")
    
    # Find attack paths
    targets = inspector.find_ssrf_targets()
    if targets:
        print(f"\n⚠️  Found {len(targets)} potential SSRF attack paths!")
        for i, target in enumerate(targets[:3], 1):  # Show first 3
            print(f"   {i}. {target['attack_scenario']}")
    
    print("\n✨ Gray Box demo complete!")
    print("\nℹ️  To see full network diagram:")
    print("   python cli.py --mode graybox --docker")

def demo_white_box():
    """Demo White Box scanning"""
    print("\n" + "="*60)
    print("📋 DEMO 3: WHITE BOX SCANNING (Code Analysis)")
    print("="*60)
    
    from whitebox.static_analysis.code_scanner import CodeScanner
    
    print("\n🔍 Scanning source code...")
    print("Target: ../inventory-service/")
    
    # Scan inventory service
    scanner = CodeScanner("../inventory-service")
    
    try:
        findings = scanner.scan_directory(extensions=['.py'])
        
        print(f"\n✅ Scan complete! Found {len(findings)} potential vulnerabilities:")
        
        # Show findings
        for i, finding in enumerate(findings[:5], 1):  # Show first 5
            print(f"\n{i}. [{finding['severity']}] {finding['description']}")
            print(f"   File: {finding['file']}")
            print(f"   Line: {finding['line']}")
            print(f"   Code: {finding['code'][:60]}...")
        
        # Statistics
        stats = scanner.get_statistics()
        print(f"\n📊 Statistics:")
        print(f"   Total findings: {stats['total_findings']}")
        print(f"   By severity: {stats['by_severity']}")
    
    except Exception as e:
        print(f"\n⚠️  Error scanning code: {e}")
        print("\nPlease ensure you're in the correct directory:")
        print("   cd /path/to/microservice_lab/pentest-toolkit")
    
    print("\n✨ White Box demo complete!")
    print("\nℹ️  To run full code scan:")
    print("   python cli.py --mode whitebox --source-path ../")

def demo_database():
    """Demo database and reporting"""
    print("\n" + "="*60)
    print("📋 DEMO 4: DATABASE & REPORTING")
    print("="*60)
    
    from core.database import FindingDatabase, Finding
    from datetime import datetime
    
    print("\n💾 Creating sample findings database...")
    
    # Create test database
    db = FindingDatabase("demo_findings.db")
    
    # Add sample findings
    sample_findings = [
        Finding(
            mode='blackbox',
            severity='CRITICAL',
            category='SSRF',
            title='Confirmed SSRF via callback_url',
            description='External callback received from parameter callback_url',
            affected_url='http://localhost:8083/inventory/1/M',
            cvss_score=9.1,
            cwe_id='CWE-918'
        ),
        Finding(
            mode='graybox',
            severity='MEDIUM',
            category='SSRF',
            title='No network segmentation',
            description='All services in same Docker network',
            affected_url='docker network: microservice_lab_default',
            cvss_score=5.5,
            cwe_id='CWE-918'
        ),
        Finding(
            mode='whitebox',
            severity='CRITICAL',
            category='SSRF',
            title='Unvalidated user input in HTTP request',
            description='requests.delete(callback_url) without validation',
            affected_url='inventory-service/app.py:40',
            cvss_score=9.1,
            cwe_id='CWE-918'
        )
    ]
    
    for finding in sample_findings:
        db.add_finding(finding)
    
    print(f"✅ Added {len(sample_findings)} sample findings")
    
    # Show statistics
    stats = db.get_statistics()
    print(f"\n📊 Database Statistics:")
    print(f"   Total findings: {stats['total']}")
    print(f"   By severity: {stats['by_severity']}")
    print(f"   By mode: {stats['by_mode']}")
    
    # Export
    print("\n📄 Exporting to JSON...")
    db.export_json("demo_report.json")
    print("✅ Exported to: demo_report.json")
    
    db.close()
    
    print("\n✨ Database demo complete!")
    print("\nℹ️  View the report:")
    print("   cat demo_report.json | jq")

def main():
    """Main demo menu"""
    
    demos = {
        '1': ('Black Box Scanning', demo_black_box),
        '2': ('Gray Box Scanning (Docker)', demo_gray_box),
        '3': ('White Box Scanning (Code)', demo_white_box),
        '4': ('Database & Reporting', demo_database),
        '5': ('Run All Demos', lambda: [demo_black_box(), demo_gray_box(), demo_white_box(), demo_database()])
    }
    
    print("\n📋 SELECT DEMO:")
    for key, (name, _) in demos.items():
        print(f"   {key}. {name}")
    print("   0. Exit")
    
    try:
        choice = input("\nEnter choice (1-5, 0 to exit): ").strip()
        
        if choice == '0':
            print("\n👋 Goodbye!")
            return
        
        if choice in demos:
            _, demo_func = demos[choice]
            demo_func()
        else:
            print("\n❌ Invalid choice!")
    
    except KeyboardInterrupt:
        print("\n\n👋 Interrupted by user. Goodbye!")
    except Exception as e:
        print(f"\n❌ Error: {e}")
    
    print("\n" + "="*60)
    print("\n💡 NEXT STEPS:")
    print("   • Install dependencies: pip install -r requirements.txt")
    print("   • Start services: docker-compose up -d")
    print("   • Run full scan: python cli.py --mode all --target http://localhost:8083 --docker")
    print("   • Read docs: cat README.md")
    print("\n🎯 Happy Hunting! 🚀")

if __name__ == "__main__":
    main()
