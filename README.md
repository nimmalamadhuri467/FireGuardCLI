# FireGuardCLI

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

# Start interactive mode
python main.py interactive
Example Session
bash$ python main.py simulate --ip 192.168.1.1 --port 80 --protocol TCP --verbose

🔥 FireGuardCLI - Advanced Firewall Simulation Tool

✅ ALLOW - 192.168.1.1:80/TCP
  Reason: Allow private network 192.168.x.x
  Matched Rule: Rule #2
  Packet Size: 64 bytes
  Processing Time: 0.0023s

$ python main.py add-rule --ip 10.0.0.0/8 --action BLOCK --priority 50 --description "Block internal network"
✅ Rule added successfully with ID: 13

$ python main.py bulk-simulate --random --count 100
Simulating 100 packets...
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric                ┃ Count                 ┃ Percentage            ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━┩
│ Total Packets         │ 100                   │ 100%                  │
│ Allowed               │ 67                    │ 67.0%                 │
│ Blocked               │ 33                    │ 33.0%                 │
└───────────────────────┴───────────────────────┴───────────────────────┘
📖 Detailed Usage
Command Reference
Packet Simulation
bash# Single packet test
python main.py simulate --ip <IP> --port <PORT> --protocol <TCP|UDP|ICMP> [options]

# Options:
--verbose, -v          # Show detailed output
--size <bytes>         # Packet size (default: 64)

# Examples:
python main.py simulate --ip 8.8.8.8 --port 53 --protocol UDP
python main.py simulate --ip 192.168.1.1 --port 443 --protocol TCP --verbose
Bulk Simulation
bash# Random packet generation
python main.py bulk-simulate --random --count <number>

# From file
python main.py bulk-simulate --file packets.json

# Example packet file format:
[
    {"ip": "192.168.1.1", "port": 80, "protocol": "TCP", "size": 1024},
    {"ip": "10.0.0.1", "port": 22, "protocol": "TCP", "size": 64}
]
Rule Management
bash# Add rules
python main.py add-rule [options]

# Required:
--action <ALLOW|BLOCK>

# Optional filters:
--ip <ip/cidr>         # IP address or CIDR range
--port <port>          # Port number (1-65535)
--protocol <protocol>  # TCP, UDP, ICMP, or ANY
--country <code>       # Two-letter country code
--priority <1-1000>    # Rule priority (lower = higher priority)
--description <text>   # Human-readable description
--rate-limit <pps>     # Packets per second limit

# Examples:
python main.py add-rule --ip 192.168.0.0/16 --action ALLOW --description "Private network"
python main.py add-rule --port 22 --action BLOCK --description "Block SSH globally"
python main.py add-rule --country CN --action BLOCK --description "Block China traffic"
python main.py add-rule --ip 8.8.8.8 --port 53 --protocol UDP --action ALLOW --rate-limit 100
Rule Viewing and Management
bash# List all rules
python main.py list-rules [--action <ALLOW|BLOCK>] [--export <file>]

# Delete rule
python main.py delete-rule --id <rule_id>

# Import/export rules
python main.py import-rules --file rules.json [--merge]
python main.py list-rules --export backup_rules.json
Logging and Statistics
bash# View logs
python main.py logs [options]
--tail <count>         # Number of recent entries (default: 50)
--action <ALLOW|BLOCK> # Filter by action
--ip <address>         # Filter by IP address

# Statistics
python main.py stats [--period <hour|day|week>]

# Example output:
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Metric                        ┃ Value                           ┃
┡━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Total Packets                 │ 1,234                           │
│ Allowed Packets               │ 856                             │
│ Blocked Packets               │ 378                             │
│ Unique Ips                    │ 45                              │
│ Allow Rate                    │ 69.4%                           │
│ Block Rate                    │ 30.6%                           │
│ Avg Processing Time           │ 0.0034s                         │
└───────────────────────────────┴─────────────────────────────────┘
Interactive Mode
bashpython main.py interactive

# Interactive commands:
FireGuard> simulate 192.168.1.1 80 TCP
FireGuard> list-rules
FireGuard> stats
FireGuard> logs
FireGuard> help
FireGuard> quit
🏗️ Project Structure
FireGuardCLI/
│
├── main.py                    # Entry point and CLI interface
├── firewall.py                # Core firewall engine and rules
├── logger.py                  # Logging and statistics module
├── rules.json                 # Default firewall rules
├── tests/
│   ├── test_firewall.py       # Comprehensive test suite
│   └── __init__.py
├── docs/
│   ├── architecture.md        # System architecture
│   ├── examples.md            # Usage examples
│   └── screenshots/           # Demo screenshots
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── LICENSE                    # MIT License






