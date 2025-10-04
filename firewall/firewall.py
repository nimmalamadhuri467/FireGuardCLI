"""
FireGuardCLI: Core Firewall Engine
Handles rule management, packet matching, and decision making
"""

import json
import time
import ipaddress
import re
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
import geoip2.database
import geoip2.errors

class RateLimiter:
    """Simple rate limiter for tracking packet rates"""
    
    def __init__(self):
        self.counters = {}  # {ip: [(timestamp, count), ...]}
        self.cleanup_interval = 60  # seconds
        self.last_cleanup = time.time()
    
    def check_rate(self, ip: str, limit: int, window: int = 60) -> bool:
        """Check if IP is within rate limit"""
        now = time.time()
        
        # Cleanup old entries periodically
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(now, window)
            self.last_cleanup = now
        
        # Initialize or get existing counter
        if ip not in self.counters:
            self.counters[ip] = []
        
        # Remove old entries for this IP
        self.counters[ip] = [
            (ts, count) for ts, count in self.counters[ip]
            if now - ts < window
        ]
        
        # Count packets in the current window
        current_count = sum(count for _, count in self.counters[ip])
        
        if current_count >= limit:
            return False
        
        # Add current packet
        self.counters[ip].append((now, 1))
        return True
    
    def _cleanup_old_entries(self, now: float, window: int):
        """Remove old entries to prevent memory leak"""
        for ip in list(self.counters.keys()):
            self.counters[ip] = [
                (ts, count) for ts, count in self.counters[ip]
                if now - ts < window
            ]
            if not self.counters[ip]:
                del self.counters[ip]

class GeoIPHandler:
    """Handle GeoIP lookups for country-based filtering"""
    
    def __init__(self, db_path: str = "GeoLite2-Country.mmdb"):
        self.db_path = db_path
        self.reader = None
        self._initialize_reader()
    
    def _initialize_reader(self):
        """Initialize GeoIP2 reader"""
        try:
            self.reader = geoip2.database.Reader(self.db_path)
        except (FileNotFoundError, geoip2.errors.GeoIP2Error):
            self.reader = None
    
    def get_country(self, ip: str) -> Optional[str]:
        """Get country code for IP address"""
        if not self.reader:
            return None
        
        try:
            response = self.reader.country(ip)
            return response.country.iso_code
        except (geoip2.errors.GeoIP2Error, ValueError):
            return None
    
    def __del__(self):
        """Cleanup reader on destruction"""
        if self.reader:
            self.reader.close()

class FirewallRule:
    """Represents a single firewall rule"""
    
    def __init__(self, rule_data: Dict[str, Any], rule_id: int = None):
        self.id = rule_id
        self.ip = rule_data.get('ip')
        self.ip_network = None
        self.port = rule_data.get('port')
        self.protocol = rule_data.get('protocol', 'ANY').upper()
        self.action = rule_data.get('action', 'BLOCK').upper()
        self.priority = rule_data.get('priority', 100)
        self.description = rule_data.get('description', '')
        self.country = rule_data.get('country')
        self.rate_limit = rule_data.get('rate_limit')
        self.created_at = rule_data.get('created_at', datetime.now().isoformat())
        
        # Parse IP/CIDR if provided
        if self.ip:
            try:
                self.ip_network = ipaddress.ip_network(self.ip, strict=False)
            except ValueError:
                # If not a valid network, treat as single IP
                try:
                    self.ip_network = ipaddress.ip_network(f"{self.ip}/32", strict=False)
                except ValueError:
                    self.ip_network = None
    
    def matches_packet(self, packet: Dict[str, Any]) -> bool:
        """Check if this rule matches the given packet"""
        
        # Check IP match
        if self.ip and self.ip_network:
            try:
                packet_ip = ipaddress.ip_address(packet['ip'])
                if packet_ip not in self.ip_network:
                    return False
            except ValueError:
                if self.ip != packet['ip']:
                    return False
        
        # Check port match
        if self.port and self.port != packet.get('port'):
            return False
        
        # Check protocol match
        if self.protocol and self.protocol != 'ANY' and self.protocol != packet.get('protocol', '').upper():
            return False
        
        return True
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary representation"""
        return {
            'id': self.id,
            'ip': self.ip,
            'port': self.port,
            'protocol': self.protocol,
            'action': self.action,
            'priority': self.priority,
            'description': self.description,
            'country': self.country,
            'rate_limit': self.rate_limit,
            'created_at': self.created_at
        }

class FirewallEngine:
    """Main firewall engine for processing packets and managing rules"""
    
    def __init__(self, rules_file: str = "rules.json"):
        self.rules_file = rules_file
        self.rules: List[FirewallRule] = []
        self.next_rule_id = 1
        self.rate_limiter = RateLimiter()
        self.geoip = GeoIPHandler()
        self.stats = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_blocked': 0,
            'rules_matched': 0,
            'last_reset': datetime.now().isoformat()
        }
        
        self.load_rules()
    
    def load_rules(self):
        """Load rules from JSON file"""
        try:
            with open(self.rules_file, 'r') as f:
                data = json.load(f)
            
            self.rules = []
            
            # Handle legacy format (whitelist/blacklist)
            if 'whitelist' in data or 'blacklist' in data:
                self._convert_legacy_rules(data)
            else:
                # Handle new format
                rules_data = data.get('rules', [])
                for rule_data in rules_data:
                    rule = FirewallRule(rule_data, rule_data.get('id'))
                    self.rules.append(rule)
                    if rule.id and rule.id >= self.next_rule_id:
                        self.next_rule_id = rule.id + 1
            
            # Sort rules by priority
            self.rules.sort(key=lambda r: r.priority)
            
        except FileNotFoundError:
            # Create default rules file
            self._create_default_rules()
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in rules file: {e}")
    
    def _convert_legacy_rules(self, data: Dict[str, Any]):
        """Convert legacy rule format to new format"""
        
        # Convert whitelist
        for rule in data.get('whitelist', []):
            firewall_rule = FirewallRule({
                'ip': rule['ip'],
                'port': int(rule['port']),
                'protocol': rule['protocol'],
                'action': 'ALLOW',
                'priority': 50,
                'description': 'Converted from legacy whitelist'
            }, self.next_rule_id)
            self.rules.append(firewall_rule)
            self.next_rule_id += 1
        
        # Convert blacklist
        for rule in data.get('blacklist', []):
            firewall_rule = FirewallRule({
                'ip': rule['ip'],
                'port': int(rule['port']),
                'protocol': rule['protocol'],
                'action': 'BLOCK',
                'priority': 50,
                'description': 'Converted from legacy blacklist'
            }, self.next_rule_id)
            self.rules.append(firewall_rule)
            self.next_rule_id += 1
        
        # Convert IP blacklists
        for ip in data.get('blacklist_ip', []):
            firewall_rule = FirewallRule({
                'ip': ip,
                'action': 'BLOCK',
                'priority': 10,
                'description': 'Converted from legacy IP blacklist'
            }, self.next_rule_id)
            self.rules.append(firewall_rule)
            self.next_rule_id += 1
        
        # Convert country blacklists
        for country in data.get('blacklist_country', []):
            firewall_rule = FirewallRule({
                'country': country,
                'action': 'BLOCK',
                'priority': 20,
                'description': f'Block traffic from {country}'
            }, self.next_rule_id)
            self.rules.append(firewall_rule)
            self.next_rule_id += 1
        
        # Save converted rules
        self.save_rules()
    
    def _create_default_rules(self):
        """Create default rules file"""
        default_rules = [
            {
                'ip': '127.0.0.1',
                'action': 'ALLOW',
                'priority': 1,
                'description': 'Allow localhost traffic'
            },
            {
                'ip': '192.168.0.0/16',
                'action': 'ALLOW',
                'priority': 10,
                'description': 'Allow private network 192.168.x.x'
            },
            {
                'ip': '10.0.0.0/8',
                'action': 'ALLOW',
                'priority': 10,
                'description': 'Allow private network 10.x.x.x'
            },
            {
                'port': 22,
                'protocol': 'TCP',
                'action': 'BLOCK',
                'priority': 90,
                'description': 'Block SSH from external networks'
            }
        ]
        
        for i, rule_data in enumerate(default_rules):
            rule = FirewallRule(rule_data, i + 1)
            self.rules.append(rule)
        
        self.next_rule_id = len(default_rules) + 1
        self.save_rules()
    
    def save_rules(self):
        """Save rules to JSON file"""
        data = {
            'rules': [rule.to_dict() for rule in self.rules],
            'metadata': {
                'version': '2.0',
                'created': datetime.now().isoformat(),
                'total_rules': len(self.rules)
            }
        }
        
        with open(self.rules_file, 'w') as f:
            json.dump(data, f, indent=4)
    
    def add_rule(self, rule_data: Dict[str, Any]) -> int:
        """Add a new rule"""
        # Validate rule data
        if not rule_data.get('action') in ['ALLOW', 'BLOCK']:
            raise ValueError("Action must be ALLOW or BLOCK")
        
        # Create rule with new ID
        rule = FirewallRule(rule_data, self.next_rule_id)
        self.rules.append(rule)
        self.next_rule_id += 1
        
        # Sort by priority and save
        self.rules.sort(key=lambda r: r.priority)
        self.save_rules()
        
        return rule.id
    
    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule by ID"""
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                del self.rules[i]
                self.save_rules()
                return True
        return False
    
    def get_rules(self, action_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all rules, optionally filtered by action"""
        rules = self.rules
        
        if action_filter:
            rules = [r for r in rules if r.action == action_filter.upper()]
        
        return [rule.to_dict() for rule in rules]
    
    def check_packet(self, packet: Dict[str, Any]) -> Dict[str, Any]:
        """Check a packet against all rules and return decision"""
        start_time = time.time()
        self.stats['packets_processed'] += 1
        
        # Validate packet format
        required_fields = ['ip', 'port', 'protocol']
        for field in required_fields:
            if field not in packet:
                return {
                    'action': 'BLOCK',
                    'reason': f'Invalid packet: missing {field}',
                    'processing_time': time.time() - start_time
                }
        
        # Check country-based rules first
        country = self.geoip.get_country(packet['ip'])
        if country:
            packet['country'] = country
        
        # Check each rule in priority order
        for rule in self.rules:
            # Check country match
            if rule.country and country and rule.country.upper() == country.upper():
                self.stats['rules_matched'] += 1
                if rule.action == 'ALLOW':
                    self.stats['packets_allowed'] += 1
                else:
                    self.stats['packets_blocked'] += 1
                
                return {
                    'action': rule.action,
                    'reason': f'Country rule: {rule.description or f"Rule #{rule.id}"}',
                    'matched_rule': rule.to_dict(),
                    'processing_time': time.time() - start_time
                }
            
            # Check packet-level match
            if rule.matches_packet(packet):
                self.stats['rules_matched'] += 1
                
                # Check rate limiting if specified
                if rule.rate_limit and rule.action == 'ALLOW':
                    if not self.rate_limiter.check_rate(packet['ip'], rule.rate_limit):
                        self.stats['packets_blocked'] += 1
                        return {
                            'action': 'BLOCK',
                            'reason': f'Rate limit exceeded ({rule.rate_limit} pps)',
                            'matched_rule': rule.to_dict(),
                            'processing_time': time.time() - start_time
                        }
                
                if rule.action == 'ALLOW':
                    self.stats['packets_allowed'] += 1
                else:
                    self.stats['packets_blocked'] += 1
                
                return {
                    'action': rule.action,
                    'reason': rule.description or f"Matched rule #{rule.id}",
                    'matched_rule': rule.to_dict(),
                    'processing_time': time.time() - start_time
                }
        
        # Default policy: BLOCK
        self.stats['packets_blocked'] += 1
        return {
            'action': 'BLOCK',
            'reason': 'No matching rule (default deny)',
            'processing_time': time.time() - start_time
        }
    
    def import_rules(self, file_path: str, merge: bool = False):
        """Import rules from JSON file"""
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        if not merge:
            self.rules = []
            self.next_rule_id = 1
        
        # Handle different formats
        if 'rules' in data:
            # New format
            for rule_data in data['rules']:
                if not merge or not any(r.id == rule_data.get('id') for r in self.rules):
                    rule = FirewallRule(rule_data, rule_data.get('id', self.next_rule_id))
                    self.rules.append(rule)
                    if rule.id >= self.next_rule_id:
                        self.next_rule_id = rule.id + 1
        else:
            # Legacy format
            self._convert_legacy_rules(data)
        
        self.rules.sort(key=lambda r: r.priority)
        self.save_rules()
    
    def export_rules(self, file_path: str):
        """Export rules to JSON file"""
        data = {
            'rules': [rule.to_dict() for rule in self.rules],
            'metadata': {
                'version': '2.0',
                'exported': datetime.now().isoformat(),
                'total_rules': len(self.rules)
            }
        }
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
    
    def reset_rules(self):
        """Reset all rules and statistics"""
        self.rules = []
        self.next_rule_id = 1
        self.stats = {
            'packets_processed': 0,
            'packets_allowed': 0,
            'packets_blocked': 0,
            'rules_matched': 0,
            'last_reset': datetime.now().isoformat()
        }
        self._create_default_rules()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get firewall statistics"""
        stats = self.stats.copy()
        stats.update({
            'total_rules': len(self.rules),
            'allow_rules': len([r for r in self.rules if r.action == 'ALLOW']),
            'block_rules': len([r for r in self.rules if r.action == 'BLOCK']),
            'uptime': str(datetime.now() - datetime.fromisoformat(self.stats['last_reset'])).split('.')[0]
        })
        
        if stats['packets_processed'] > 0:
            stats['allow_rate'] = f"{(stats['packets_allowed'] / stats['packets_processed']) * 100:.1f}%"
            stats['block_rate'] = f"{(stats['packets_blocked'] / stats['packets_processed']) * 100:.1f}%"
            stats['match_rate'] = f"{(stats['rules_matched'] / stats['packets_processed']) * 100:.1f}%"
        
        return stats
    
    def validate_rule(self, rule_data: Dict[str, Any]) -> List[str]:
        """Validate rule data and return list of errors"""
        errors = []
        
        # Check required fields
        if 'action' not in rule_data or rule_data['action'] not in ['ALLOW', 'BLOCK']:
            errors.append("Action must be ALLOW or BLOCK")
        
        # Validate IP/CIDR
        if 'ip' in rule_data and rule_data['ip']:
            try:
                ipaddress.ip_network(rule_data['ip'], strict=False)
            except ValueError:
                try:
                    ipaddress.ip_address(rule_data['ip'])
                except ValueError:
                    errors.append(f"Invalid IP address or CIDR: {rule_data['ip']}")
        
        # Validate port
        if 'port' in rule_data and rule_data['port']:
            try:
                port = int(rule_data['port'])
                if not 1 <= port <= 65535:
                    errors.append("Port must be between 1 and 65535")
            except (ValueError, TypeError):
                errors.append("Port must be a valid integer")
        
        # Validate protocol
        if 'protocol' in rule_data and rule_data['protocol']:
            valid_protocols = ['TCP', 'UDP', 'ICMP', 'ANY']
            if rule_data['protocol'].upper() not in valid_protocols:
                errors.append(f"Protocol must be one of: {', '.join(valid_protocols)}")
        
        # Validate priority
        if 'priority' in rule_data and rule_data['priority']:
            try:
                priority = int(rule_data['priority'])
                if not 1 <= priority <= 1000:
                    errors.append("Priority must be between 1 and 1000")
            except (ValueError, TypeError):
                errors.append("Priority must be a valid integer")
        
        # Validate rate limit
        if 'rate_limit' in rule_data and rule_data['rate_limit']:
            try:
                rate_limit = int(rule_data['rate_limit'])
                if rate_limit < 1:
                    errors.append("Rate limit must be positive")
            except (ValueError, TypeError):
                errors.append("Rate limit must be a valid integer")
        
        return errors
    
    def search_rules(self, query: str) -> List[Dict[str, Any]]:
        """Search rules by IP, description, or other criteria"""
        results = []
        query = query.lower()
        
        for rule in self.rules:
            rule_dict = rule.to_dict()
            
            # Search in various fields
            search_fields = [
                str(rule_dict.get('ip', '')),
                str(rule_dict.get('port', '')),
                rule_dict.get('protocol', ''),
                rule_dict.get('action', ''),
                rule_dict.get('description', ''),
                rule_dict.get('country', '')
            ]
            
            if any(query in field.lower() for field in search_fields):
                results.append(rule_dict)
        
        return results