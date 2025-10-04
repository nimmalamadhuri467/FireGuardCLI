
# FireGuardCLI 🚀

A **command-line firewall simulator** for learning packet filtering, rule management, and network security concepts. Perfect for cybersecurity beginners and testing firewall configurations.

## 🌟 Features

### Core Functionality

* **Packet Simulation:** Test single packets or bulk traffic.
* **Rule Management:** Add, delete, modify rules with priority system.
* **Actions:** ALLOW/BLOCK decisions with detailed reasoning.
* **Protocol Support:** TCP, UDP, ICMP.
* **Network Support:** IPs, CIDR ranges, and wildcards.

### Advanced Features

* **Rate Limiting:** Per-IP packet rate control.
* **GeoIP Filtering:** Allow/block traffic by country.
* **Real-time Logging:** SQLite + file logging.
* **Statistics Dashboard:** Traffic analysis with summaries.
* **Interactive Mode:** Live firewall testing environment.
* **Import/Export:** JSON-based rule configuration.
* **Audit Trail:** Complete history of rule changes.

### User Interface

* **Rich CLI:** Colorized tables and progress bars.
* **Multiple Modes:** Command-line or interactive shell.
* **Bulk Operations:** Handle hundreds of packets efficiently.
* **Export Tools:** Generate JSON/CSV reports.

## 📦 Installation

### Prerequisites

```bash
# Python 3.7+
python --version

# Install required packages
pip install rich argparse sqlite3
pip install geoip2   # Optional: for country filtering
```

### Optional GeoIP Setup

```bash
# Download GeoLite2 Country database from MaxMind
wget https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=YOUR_KEY&suffix=tar.gz
```

### Quick Setup

```bash
git clone https://github.com/yourusername/FireGuardCLI.git
cd FireGuardCLI
chmod +x main.py
python main.py list-rules   # Initialize default rules
```
## 🚀 Quick Start

### Single Packet Simulation

```bash
python main.py simulate --ip 192.168.1.100 --port 80 --protocol TCP
python main.py simulate --ip 192.168.1.1 --port 443 --protocol TCP --verbose
```

### Rule Management

```bash
# Add rule
python main.py add-rule --ip 10.0.0.1 --port 22 --protocol TCP --action BLOCK --description "Block SSH"

# List rules
python main.py list-rules

# Delete rule
python main.py delete-rule --id 13

# Import/Export rules
python main.py import-rules --file rules.json --merge
python main.py list-rules --export backup_rules.json
```

### Logs & Statistics

```bash
# View logs
python main.py logs --tail 20

# Show stats
python main.py stats --period day
```

### Interactive Mode

```bash
python main.py interactive

# Example commands:
FireGuard> simulate 192.168.1.1 80 TCP
FireGuard> list-rules
FireGuard> stats
FireGuard> logs
FireGuard> help
FireGuard> quit

## 🏗️ Project Structure

```
FireGuardCLI/
├── main.py                # CLI entry point
├── firewall.py            # Firewall engine & rules
├── logger.py              # Logging & stats
├── rules.json             # Default rules
├── tests/
│   └── test_firewall.py   # Test suite
├── docs/
│   ├── architecture.md
│   ├── examples.md
│   └── screenshots/
├── requirements.txt
├── README.md
└── LICENSE






