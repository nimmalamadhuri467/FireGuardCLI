
🔥 FireGuardCLI - Advanced Firewall Simulation Tool
A comprehensive command-line based firewall simulator that demonstrates packet filtering, rule management, and network security concepts. Perfect for learning cybersecurity fundamentals and testing firewall configurations.
🌟 Features
Core Functionality

Packet Simulation: Test individual packets or bulk traffic simulation
Rule Management: Add, delete, modify firewall rules with priority system
Multiple Actions: ALLOW/BLOCK decisions with detailed reasoning
Protocol Support: TCP, UDP, ICMP traffic filtering
Network Support: IP addresses, CIDR ranges, and wildcard matching

Advanced Features

Rate Limiting: Per-IP packet rate controls
GeoIP Filtering: Block/allow traffic by country
Real-time Logging: SQLite database + file logging
Statistics Dashboard: Comprehensive traffic analysis
Interactive Mode: Live firewall testing environment
Import/Export: JSON-based rule configuration
Audit Trail: Complete history of rule changes

User Interface

Rich CLI: Colorized output with tables and progress bars
Multiple Modes: Command-line arguments or interactive shell
Bulk Operations: Process hundreds of packets efficiently
Export Tools: Generate reports in JSON/CSV formats

📦 Installation
Prerequisites
bash# Python 3.7 or higher required
python --version

# Install required packages
pip install rich argparse sqlite3
pip install geoip2  # Optional: for country-based filtering
Download GeoIP Database (Optional)
For country-based filtering, download the GeoLite2 database:
bash# Download from MaxMind (requires free account)
wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_KEY&suffix=tar.gz
Quick Setup
bash# Clone or download the project
git clone https://github.com/yourusername/FireGuardCLI.git
cd FireGuardCLI

# Make main script executable
chmod +x main.py

# Run initial setup (creates default rules)
python main.py list-rules
🚀 Quick Start
Basic Commands
bash# Test a single packet
python main.py simulate --ip 192.168.1.100 --port 80 --protocol TCP

# Add a blocking rule
python main.py add-rule --ip 10.0.0.1 --port 22 --protocol TCP --action BLOCK --description "Block SSH"

# List all rules
python main.py list-rules

# View recent activity
python main.py logs --tail 20

# Show statistics
python main.py stats --period day








