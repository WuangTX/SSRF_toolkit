"""
Quick start script for Web UI
"""

import subprocess
import sys
import os
from pathlib import Path

def check_dependencies():
    """Check if required packages are installed"""
    try:
        import flask
        import flask_socketio
        print("✅ Dependencies already installed")
        return True
    except ImportError:
        print("⚠️  Dependencies not found")
        return False

def install_dependencies():
    """Install required packages"""
    print("📦 Installing dependencies...")
    requirements_file = Path(__file__).parent / 'requirements.txt'
    
    try:
        subprocess.check_call([
            sys.executable, '-m', 'pip', 'install', '-r', str(requirements_file)
        ])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def start_server():
    """Start the Flask server"""
    print("\n" + "="*60)
    print("🚀 Starting Microservice SSRF Pentest Toolkit Web UI")
    print("="*60)
    print("📊 Dashboard will be available at: http://localhost:5000")
    print("Press Ctrl+C to stop the server")
    print("="*60 + "\n")
    
    app_file = Path(__file__).parent / 'app.py'
    
    try:
        subprocess.call([sys.executable, str(app_file)])
    except KeyboardInterrupt:
        print("\n\n👋 Server stopped")

def main():
    # Change to web_ui directory
    os.chdir(Path(__file__).parent)
    
    # Check and install dependencies
    if not check_dependencies():
        response = input("\n❓ Install dependencies now? (Y/n): ").strip().lower()
        if response in ['', 'y', 'yes']:
            if not install_dependencies():
                print("❌ Cannot start server without dependencies")
                sys.exit(1)
        else:
            print("❌ Dependencies required to run the server")
            sys.exit(1)
    
    # Start server
    start_server()

if __name__ == "__main__":
    main()
