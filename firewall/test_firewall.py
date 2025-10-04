#!/usr/bin/env python3
"""
FireGuardCLI: Unit Tests
Comprehensive test suite for firewall functionality
"""

import unittest
import tempfile
import os
import json
import sqlite3
from unittest.mock import patch, MagicMock
import sys
sys.path.append('..')

from firewall import FirewallEngine, FirewallRule, RateLimiter, GeoIPHandler
from logger import FirewallLogger

class TestFirewallRule(unittest.TestCase):
    """Test FirewallRule class functionality"""
    
    def test_rule_creation_basic(self):
        """Test basic rule creation"""
        rule_data = {
            'ip': '192.168.1.1',
            'port': 80,
            'protocol': 'TCP',
            'action': 'ALLOW',
            'description': 'Test rule'
        }
        
        rule = FirewallRule(rule_data, 1)
        
        self.assertEqual(rule.id, 1)
        self.assertEqual(rule.ip, '192.168.1.1')
        self.assertEqual(rule.port, 80)
        self.assertEqual(rule.protocol, 'TCP')
        self.assertEqual(rule.action, 'ALLOW')
        self.assertEqual(rule.description, 'Test rule')
    
    def test_rule_cidr_parsing(self):
        """Test CIDR network parsing"""
        rule_data = {
            'ip': '192.168.0.0/24',
            'action': 'BLOCK'
        }
        
        rule = FirewallRule(rule_data, 1)
        self.assertIsNotNone(rule.ip_network)
        
        # Test packet matching within CIDR
        packet = {'ip': '192.168.0.100', 'port': 80, 'protocol': 'TCP'}
        self.assertTrue(rule.matches_packet(packet))
        
        # Test packet outside CIDR
        packet = {'ip': '192.168.1.100', 'port': 80, 'protocol': 'TCP'}
        self.assertFalse(rule.matches_packet(packet))
    
    def test_rule_matching(self):
        """Test packet matching logic"""
        rule_data = {
            'ip': '192.168.1.1',
            'port': 80,
            'protocol': 'TCP',
            'action': 'ALLOW'
        }
        
        rule = FirewallRule(rule_data, 1)
        
        # Exact match
        packet = {'ip': '192.168.1.1', 'port': 80, 'protocol': 'TCP'}
        self.assertTrue(rule.matches_packet(packet))
        
        # Different IP
        packet = {'ip': '192.168.1.2', 'port': 80, 'protocol': 'TCP'}
        self.assertFalse(rule.matches_packet(packet))
        
        # Different port
        packet = {'ip': '192.168.1.1', 'port': 443, 'protocol': 'TCP'}
        self.assertFalse(rule.matches_packet(packet))
        
        # Different protocol
        packet = {'ip': '192.168.1.1', 'port': 80, 'protocol': 'UDP'}
        self.assertFalse(rule.matches_packet(packet))
    
    def test_wildcard_matching(self):
        """Test wildcard matching (ANY protocol)"""
        rule_data = {
            'ip': '192.168.1.1',
            'protocol': 'ANY',
            'action': 'ALLOW'
        }
        
        rule = FirewallRule(rule_data, 1)
        
        # Should match any protocol
        packet = {'ip': '192.168.1.1', 'port': 80, 'protocol': 'TCP'}
        self.assertTrue(rule.matches_packet(packet))
        
        packet = {'ip': '192.168.1.1', 'port': 53, 'protocol': 'UDP'}
        self.assertTrue(rule.matches_packet(packet))

class TestRateLimiter(unittest.TestCase):
    """Test RateLimiter functionality"""
    
    def setUp(self):
        self.rate_limiter = RateLimiter()
    
    def test_rate_limiting(self):
        """Test basic rate limiting"""
        ip = '192.168.1.1'
        limit = 5
        
        # Should allow first 5 packets
        for i in range(5):
            self.assertTrue(self.rate_limiter.check_rate(ip, limit))
        
        # Should block 6th packet
        self.assertFalse(self.rate_limiter.check_rate(ip, limit))
    
    def test_different_ips(self):
        """Test rate limiting for different IPs"""
        limit = 5
        
        # Fill up limit for first IP
        for i in range(5):
            self.assertTrue(self.rate_limiter.check_rate('192.168.1.1', limit))
        
        # Second IP should still work
        self.assertTrue(self.rate_limiter.check_rate('192.168.1.2', limit))
    
    @patch('time.time')
    def test_time_window_reset(self, mock_time):
        """Test that rate limits reset after time window"""
        ip = '192.168.1.1'
        limit = 5
        
        # Start at time 0
        mock_time.return_value = 0
        
        # Fill up the limit
        for i in range(5):
            self.assertTrue(self.rate_limiter.check_rate(ip, limit))
        
        # Should be blocked
        self.assertFalse(self.rate_limiter.check_rate(ip, limit))
        
        # Move time forward 61 seconds (past window)
        mock_time.return_value = 61
        
        # Should work again
        self.assertTrue(self.rate_limiter.check_rate(ip, limit))

class TestFirewallEngine(unittest.TestCase):
    """Test FirewallEngine functionality"""
    
    def setUp(self):
        # Create temporary rules file
        self.temp_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.rules_file = self.temp_file.name
        self.temp_file.close()
        
        # Create test firewall
        self.firewall = FirewallEngine(self.rules_file)
    
    def tearDown(self):
        # Cleanup temporary file
        if os.path.exists(self.rules_file):
            os.unlink(self.rules_file)
    
    def test_default_rules_creation(self):
        """Test that default rules are created"""
        self.assertGreater(len(self.firewall.rules), 0)
        
        # Check that localhost is allowed
        localhost_rules = [r for r in self.firewall.rules if r.ip == '127.0.0.1']
        self.assertGreater(len(localhost_rules), 0)
    
    def test_add_rule(self):
        """Test adding new rules"""
        initial_count = len(self.firewall.rules)
        
        rule_data = {
            'ip': '10.0.0.1',
            'port': 22,
            'protocol': 'TCP',
            'action': 'BLOCK',
            'description': 'Block SSH from specific IP'
        }
        
        rule_id = self.firewall.add_rule(rule_data)
        
        self.assertEqual(len(self.firewall.rules), initial_count + 1)
        self.assertIsInstance(rule_id, int)
        
        # Verify rule was added correctly
        added_rule = next((r for r in self.firewall.rules if r.id == rule_id), None)
        self.assertIsNotNone(added_rule)
        self.assertEqual(added_rule.ip, '10.0.0.1')
        self.assertEqual(added_rule.action, 'BLOCK')
    
    def test_delete_rule(self):
        """Test deleting rules"""
        # Add a rule first
        rule_data = {
            'ip': '10.0.0.1',
            'action': 'BLOCK'
        }
        rule_id = self.firewall.add_rule(rule_data)
        initial_count = len(self.firewall.rules)
        
        # Delete the rule
        success = self.firewall.delete_rule(rule_id)
        self.assertTrue(success)
        self.assertEqual(len(self.firewall.rules), initial_count - 1)
        
        # Try to delete non-existent rule
        success = self.firewall.delete_rule(99999)
        self.assertFalse(success)
    
    def test_packet_checking_allow(self):
        """Test packet checking - ALLOW case"""
        # Add an ALLOW rule
        rule_data = {
            'ip': '192.168.1.100',
            'port': 80,
            'protocol': 'TCP',
            'action': 'ALLOW',
            'priority': 1
        }
        self.firewall.add_rule(rule_data)
        
        # Test matching packet
        packet = {
            'ip': '192.168.1.100',
            'port': 80,
            'protocol': 'TCP'
        }
        
        result = self.firewall.check_packet(packet)
        self.assertEqual(result['action'], 'ALLOW')
        self.assertIn('matched_rule', result)
    
    def test_packet_checking_block(self):
        """Test packet checking - BLOCK case"""
        # Add a BLOCK rule
        rule_data = {
            'ip': '10.0.0.1',
            'port': 22,
            'protocol': 'TCP',
            'action': 'BLOCK',
            'priority': 1
        }
        self.firewall.add_rule(rule_data)
        
        # Test matching packet
        packet = {
            'ip': '10.0.0.1',
            'port': 22,
            'protocol': 'TCP'
        }
        
        result = self.firewall.check_packet(packet)
        self.assertEqual(result['action'], 'BLOCK')
    
    def test_packet_checking_default_deny(self):
        """Test default deny behavior"""
        # Clear all rules
        self.firewall.rules = []
        
        # Test random packet
        packet = {
            'ip': '203.0.113.1',
            'port': 12345,
            'protocol': 'TCP'
        }
        
        result = self.firewall.check_packet(packet)
        self.assertEqual(result['action'], 'BLOCK')
        self.assertIn('default deny', result['reason'].lower())
    
    def test_rule_priority(self):
        """Test rule priority handling"""
        # Add high priority BLOCK rule
        block_rule = {
            'ip': '192.168.1.100',
            'action': 'BLOCK',
            'priority': 10
        }
        self.firewall.add_rule(block_rule)
        
        # Add low priority ALLOW rule
        allow_rule = {
            'ip': '192.168.1.100',
            'action': 'ALLOW',
            'priority': 90
        }
        self.firewall.add_rule(allow_rule)
        
        # Test packet - should match high priority BLOCK rule
        packet = {
            'ip': '192.168.1.100',
            'port': 80,
            'protocol': 'TCP'
        }
        
        result = self.firewall.check_packet(packet)
        self.assertEqual(result['action'], 'BLOCK')
    
    def test_invalid_packet(self):
        """Test handling of invalid packets"""
        # Missing required fields
        invalid_packets = [
            {'ip': '192.168.1.1', 'port': 80},  # Missing protocol
            {'port': 80, 'protocol': 'TCP'},     # Missing IP
            {'ip': '192.168.1.1', 'protocol': 'TCP'}  # Missing port
        ]
        
        for packet in invalid_packets:
            result = self.firewall.check_packet(packet)
            self.assertEqual(result['action'], 'BLOCK')
            self.assertIn('Invalid packet', result['reason'])
    
    def test_rule_validation(self):
        """Test rule validation"""
        # Valid rule
        valid_rule = {
            'ip': '192.168.1.1',
            'port': 80,
            'protocol': 'TCP',
            'action': 'ALLOW'
        }
        errors = self.firewall.validate_rule(valid_rule)
        self.assertEqual(len(errors), 0)
        
        # Invalid action
        invalid_rule = {
            'action': 'INVALID_ACTION'
        }
        errors = self.firewall.validate_rule(invalid_rule)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any('Action must be' in error for error in errors))
        
        # Invalid IP
        invalid_rule = {
            'ip': 'invalid_ip',
            'action': 'ALLOW'
        }
        errors = self.firewall.validate_rule(invalid_rule)
        self.assertGreater(len(errors), 0)
        
        # Invalid port
        invalid_rule = {
            'port': 70000,  # Port too high
            'action': 'ALLOW'
        }
        errors = self.firewall.validate_rule(invalid_rule)
        self.assertGreater(len(errors), 0)
    
    def test_import_export_rules(self):
        """Test rule import/export functionality"""
        # Create temporary export file
        export_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        export_path = export_file.name
        export_file.close()
        
        try:
            # Export current rules
            self.firewall.export_rules(export_path)
            
            # Clear rules and import
            original_count = len(self.firewall.rules)
            self.firewall.rules = []
            self.firewall.import_rules(export_path)
            
            # Should have same number of rules
            self.assertEqual(len(self.firewall.rules), original_count)
            
        finally:
            if os.path.exists(export_path):
                os.unlink(export_path)

class TestFirewallLogger(unittest.TestCase):
    """Test FirewallLogger functionality"""
    
    def setUp(self):
        # Create temporary database
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.temp_db.name
        self.temp_db.close()
        
        # Create temporary log file
        self.temp_log = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
        self.log_path = self.temp_log.name
        self.temp_log.close()
        
        self.logger = FirewallLogger(self.db_path, self.log_path)
    
    def tearDown(self):
        # Cleanup temporary files
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
        if os.path.exists(self.log_path):
            os.unlink(self.log_path)
    
    def test_database_setup(self):
        """Test database initialization"""
        self.assertIsNotNone(self.logger.conn)
        
        # Check that tables exist
        cursor = self.logger.conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
        tables = [row[0] for row in cursor.fetchall()]
        
        expected_tables = ['packet_logs', 'rule_changes', 'system_events', 'daily_stats']
        for table in expected_tables:
            self.assertIn(table, tables)
    
    def test_log_decision(self):
        """Test logging firewall decisions"""
        packet = {
            'ip': '192.168.1.1',
            'port': 80,
            'protocol': 'TCP'
        }
        
        self.logger.log_decision(packet, 'ALLOW', 'Test rule', 1, 0.001)
        
        # Check database entry
        cursor = self.logger.conn.execute(
            'SELECT * FROM packet_logs WHERE ip = ?', ('192.168.1.1',)
        )
        row = cursor.fetchone()
        
        self.assertIsNotNone(row)
        self.assertEqual(row[2], 80)  # port
        self.assertEqual(row[3], 'TCP')  # protocol
        self.assertEqual(row[4], 'ALLOW')  # action
    
    def test_get_recent_logs(self):
        """Test retrieving recent logs"""
        # Add some test logs
        packets = [
            {'ip': '192.168.1.1', 'port': 80, 'protocol': 'TCP'},
            {'ip': '192.168.1.2', 'port': 443, 'protocol': 'TCP'},
            {'ip': '10.0.0.1', 'port': 22, 'protocol': 'TCP'}
        ]
        
        for packet in packets:
            self.logger.log_decision(packet, 'ALLOW', 'Test')
        
        logs = self.logger.get_recent_logs(count=5)
        self.assertEqual(len(logs), 3)
        
        # Test filtering
        logs = self.logger.get_recent_logs(count=5, action_filter='ALLOW')
        self.assertEqual(len(logs), 3)
        
        logs = self.logger.get_recent_logs(count=5, ip_filter='192.168.1.1')
        self.assertEqual(len(logs), 1)
    
    def test_statistics(self):
        """Test statistics generation"""
        # Add some test data
        packets = [
            ({'ip': '192.168.1.1', 'port': 80, 'protocol': 'TCP'}, 'ALLOW'),
            ({'ip': '192.168.1.2', 'port': 80, 'protocol': 'TCP'}, 'ALLOW'),
            ({'ip': '10.0.0.1', 'port': 22, 'protocol': 'TCP'}, 'BLOCK'),
        ]
        
        for packet, action in packets:
            self.logger.log_decision(packet, action, 'Test')
        
        stats = self.logger.get_stats('day')
        
        self.assertEqual(stats['total_packets'], 3)
        self.assertEqual(stats['allowed_packets'], 2)
        self.assertEqual(stats['blocked_packets'], 1)
        self.assertEqual(stats['unique_ips'], 3)

class TestIntegration(unittest.TestCase):
    """Integration tests combining multiple components"""
    
    def setUp(self):
        # Create temporary files
        self.temp_rules = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json')
        self.rules_file = self.temp_rules.name
        self.temp_rules.close()
        
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_file = self.temp_db.name
        self.temp_db.close()
        
        self.temp_log = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
        self.log_file = self.temp_log.name
        self.temp_log.close()
        
        self.firewall = FirewallEngine(self.rules_file)
        self.logger = FirewallLogger(self.db_file, self.log_file)
    
    def tearDown(self):
        # Cleanup
        for file_path in [self.rules_file, self.db_file, self.log_file]:
            if os.path.exists(file_path):
                os.unlink(file_path)
    
    def test_full_workflow(self):
        """Test complete firewall workflow"""
        # Add a rule
        rule_data = {
            'ip': '192.168.1.100',
            'port': 80,
            'protocol': 'TCP',
            'action': 'ALLOW',
            'description': 'Test web server'
        }
        rule_id = self.firewall.add_rule(rule_data)
        self.logger.log_rule_change('ADD', rule_id, rule_data)
        
        # Test packet processing
        packet = {
            'ip': '192.168.1.100',
            'port': 80,
            'protocol': 'TCP'
        }
        
        result = self.firewall.check_packet(packet)
        self.logger.log_decision(packet, result['action'], result['reason'])
        
        self.assertEqual(result['action'], 'ALLOW')
        
        # Check logs were created
        logs = self.logger.get_recent_logs(count=1)
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]['action'], 'ALLOW')
        
        # Check statistics
        stats = self.logger.get_stats('day')
        self.assertEqual(stats['total_packets'], 1)
        self.assertEqual(stats['allowed_packets'], 1)

def run_tests():
    """Run all tests with detailed output"""
    # Create test suite
    test_suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestFirewallRule,
        TestRateLimiter,
        TestFirewallEngine,
        TestFirewallLogger,
        TestIntegration
    ]
    
    for test_class in test_classes:
        tests = unittest.TestLoader().loadTestsFromTestCase(test_class)
        test_suite.addTests(tests)
    
    # Run tests with verbose output
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(test_suite)
    
    # Return success status
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    exit(0 if success else 1)