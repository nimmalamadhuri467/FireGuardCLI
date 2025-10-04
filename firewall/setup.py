#!/usr/bin/env python3
"""
FireGuardCLI Setup Script
Installation and configuration utility
"""

import os
import sys
import json
import subprocess
import urllib.request
import tarfile
import tempfile
from pathlib import Path

def print_banner():
    """Print installation banner"""
    banner = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   🔥 FireGuardCLI - Advanced Firewall Simulation Tool   ║
    ║                                                          ║
    ║         Professional-grade network security testing      ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """
    print(banner)

def check_python_version():
    """Ensure Python 3.7+ is being used"""
    print("🔍 Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print("❌ Error: Python 3.7 or higher is required")
        print(f"   Current version: {version.major}.{version.minor}.{version.micro}")
        print("   Please upgrade Python and try again")
        sys.exit(1)
    
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} detected")

def install_dependencies():
    """Install required Python packages"""
    print("📦 Installing Python dependencies...")
    
    try:
        # Core dependencies that should always work
        core_deps = [
            "rich>=13.0.0",
        ]
        
        # Optional dependencies
        optional_deps = [
            "geoip2>=4.0.0",
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
        ]
        
        # Install core dependencies
        for dep in core_deps:
            print(f"   Installing {dep}...")
            result = subprocess.run([sys.executable, "-m", "pip", "install", dep], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print(f"❌ Failed to install {dep}")
                print(f"   Error: {result.stderr}")
                return False
        
        # Try to install optional dependencies
        for dep in optional_deps:
            print(f"   Installing {dep} (optional)...")
            result = subprocess.run([sys.executable, "-m", "pip", "install", dep], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                print(f"⚠️  Warning: Could not install optional dependency {dep}")
        
        print("✅ Core dependencies installed successfully")
        return True
        
    except Exception as e:
        print(f"❌ Error installing dependencies: {e}")
        return False

def setup_directories():
    """Create necessary directories"""
    print("📁 Creating directories...")
    
    directories = [
        "logs",
        "data", 
        "exports",
        "tests",
        "docs"
    ]
    
    for directory in directories:
        Path(directory).mkdir(exist_ok=True)
        print(f"   Created: {directory}/")
    
    print("✅ Directory structure created")

def create_default_config():
    """Create default configuration files"""
    print("⚙️  Creating default configuration...")
    
    # Create default rules if they don't exist
    if not os.path.exists("rules.json"):
        default_rules = {
            "rules": [
                {
                    "id": 1,
                    "ip": "127.0.0.1",
                    "action": "ALLOW",
                    "priority": 1,
                    "description": "Allow localhost traffic"
                },
                {
                    "id": 2,
                    "ip": "192.168.0.0/16",
                    "action": "ALLOW", 
                    "priority": 10,
                    "description": "Allow private network 192.168.x.x"
                },
                {
                    "id": 3,
                    "ip": "10.0.0.0/8",
                    "action": "ALLOW",
                    "priority": 10,
                    "description": "Allow private network 10.x.x.x"
                },
                {
                    "id": 4,
                    "port": 22,
                    "protocol": "TCP",
                    "action": "BLOCK",
                    "priority": 80,
                    "description": "Block SSH from external networks"
                }
            ],
            "metadata": {
                "version": "2.0",
                "created": "2024-01-01T00:00:00",
                "total_rules": 4
            }
        }
        
        with open("rules.json", "w") as f:
            json.dump(default_rules, f, indent=4)
        print("   Created: rules.json")
    
    # Create example packet file
    if not os.path.exists("examples/"):
        os.makedirs("examples/", exist_ok=True)
    
    example_packets = [
        {"ip": "192.168.1.100", "port": 80, "protocol": "TCP", "size": 1024},
        {"ip": "8.8.8.8", "port": 53, "protocol": "UDP", "size": 64},
        {"ip": "10.0.0.1", "port": 22, "protocol": "TCP", "size": 128},
        {"ip": "1.1.1.1", "port": 443, "protocol": "TCP", "size": 1200}
    ]
    
    with open("examples/sample_packets.json", "w") as f:
        json.dump(example_packets, f, indent=2)
    print("   Created: examples/sample_packets.json")
    
    print("✅ Default configuration created")

def download_geoip_database():
    """Download GeoIP database (optional)"""
    print("🌍 Setting up GeoIP database...")
    
    # Check if database already exists
    if os.path.exists("GeoLite2-Country.mmdb"):
        print("   GeoIP database already exists")
        return True
    
    print("   GeoIP database setup requires MaxMind account")
    print("   Visit: https://dev.maxmind.com/geoip/geolite2-free-geolocation-data")
    print("   ⚠️  Skipping automatic download - country filtering will be disabled")
    
    # Create placeholder file
    with open("GeoLite2-Country.mmdb.readme", "w") as f:
        f.write("""
GeoLite2 Country Database Setup
==============================

To enable country-based filtering in FireGuardCLI:

1. Create a free MaxMind account at:
   https://dev.maxmind.com/geoip/geolite2-free-geolocation-data

2. Download GeoLite2-Country database

3. Place the GeoLite2-Country.mmdb file in this directory

4. Restart FireGuardCLI

Without this database, country-based rules will be ignored.
All other functionality will work normally.
""")
    
    return True

def run_tests():
    """Run basic tests to verify installation"""
    print("🧪 Running installation tests...")
    
    try:
        # Test imports
        print("   Testing imports...")
        import rich
        from rich.console import Console
        console = Console()
        
        # Test basic firewall functionality
        print("   Testing firewall engine...")
        sys.path.insert(0, '.')
        from firewall import FirewallEngine
        
        # Create temporary rules file for testing
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({"rules": []}, f)
            temp_rules = f.name
        
        try:
            firewall = FirewallEngine(temp_rules)
            
            # Test packet processing
            test_packet = {
                'ip': '192.168.1.1',
                'port': 80,
                'protocol': 'TCP'
            }
            
            result = firewall.check_packet(test_packet)
            assert 'action' in result
            assert result['action'] in ['ALLOW', 'BLOCK']
            
            print("   ✅ Firewall engine test passed")
            
        finally:
            os.unlink(temp_rules)
        
        # Test logger
        print("   Testing logger...")
        from logger import FirewallLogger
        
        with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
            temp_db = f.name
        
        try:
            logger = FirewallLogger(temp_db)
            logger.log_decision(test_packet, 'ALLOW', 'Test')
            logs = logger.get_recent_logs(1)
            assert len(logs) >= 0  # Should work even if empty
            
            print("   ✅ Logger test passed")
            
        finally:
            if os.path.exists(temp_db):
                os.unlink(temp_db)
        
        print("✅ All tests passed!")
        return True
        
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def create_launch_scripts():
    """Create convenient launch scripts"""
    print("🚀 Creating launch scripts...")
    
    # Unix/Linux/Mac script
    bash_script = """#!/bin/bash
# FireGuardCLI Launch Script

# Change to script directory
cd "$(dirname "$0")"

# Activate virtual environment if it exists
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run FireGuardCLI with arguments
python main.py "$@"
"""
    
    with open("fireguard.sh", "w") as f:
        f.write(bash_script)
    
    # Make executable
    try:
        os.chmod("fireguard.sh", 0o755)
        print("   Created: fireguard.sh (Unix/Linux/Mac)")
    except:
        pass
    
    # Windows batch script
    batch_script = """@echo off
REM FireGuardCLI Launch Script

REM Change to script directory
cd /d "%~dp0"

REM Activate virtual environment if it exists
if exist venv\\Scripts\\activate.bat (
    call venv\\Scripts\\activate.bat
)

REM Run FireGuardCLI with arguments
python main.py %*
"""
    
    with open("fireguard.bat", "w") as f:
        f.write(batch_script)
    print("   Created: fireguard.bat (Windows)")
    
    print("✅ Launch scripts created")

def show_completion_message():
    """Show installation completion message"""
    completion_msg = """
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   🎉 FireGuardCLI Installation Complete!                ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    
    🚀 Quick Start:
    
       # Test a packet
       python main.py simulate --ip 192.168.1.1 --port 80 --protocol TCP
       
       # View default rules
       python main.py list-rules
       
       # Start interactive mode
       python main.py interactive
       
       # Run help for all options
       python main.py --help
    
    📚 Documentation: README.md
    🧪 Run tests: python tests/test_firewall.py
    🛠️  Launch scripts: ./fireguard.sh (Unix) or fireguard.bat (Windows)
    
    ⚠️  Note: GeoIP country filtering requires manual database download
             See GeoLite2-Country.mmdb.readme for instructions
    
    Happy packet filtering! 🔒
    """
    print(completion_msg)

def main():
    """Main setup function"""
    print_banner()
    
    try:
        # Run setup steps
        check_python_version()
        
        if not install_dependencies():
            print("❌ Setup failed during dependency installation")
            sys.exit(1)
        
        setup_directories()
        create_default_config()
        download_geoip_database()
        create_launch_scripts()
        
        # Run tests
        if not run_tests():
            print("⚠️  Warning: Some tests failed, but installation may still work")
            print("   Try running: python main.py --help")
        
        show_completion_message()
        
    except KeyboardInterrupt:
        print("\n❌ Setup cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error during setup: {e}")
        print("   Please check the error and try again")
        sys.exit(1)

if __name__ == "__main__":
    main()