"""
FireGuardCLI: Logging Module
Handles logging of firewall decisions, statistics, and audit trail
"""

import json
import sqlite3
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from pathlib import Path

class FirewallLogger:
    """Enhanced logging system for firewall operations"""
    
    def __init__(self, db_path: str = "firewall_logs.db", log_file: str = "firewall.log"):
        self.db_path = db_path
        self.log_file = log_file
        
        # Setup file logger
        self.setup_file_logger()
        
        # Setup database
        self.setup_database()
    
    def setup_file_logger(self):
        """Setup file-based logging"""
        # Create logs directory if it doesn't exist
        log_dir = Path(self.log_file).parent
        log_dir.mkdir(exist_ok=True)
        
        # Configure logger
        self.file_logger = logging.getLogger('firewall')
        self.file_logger.setLevel(logging.INFO)
        
        # Remove existing handlers to avoid duplicates
        for handler in self.file_logger.handlers[:]:
            self.file_logger.removeHandler(handler)
        
        # File handler with rotation
        handler = logging.FileHandler(self.log_file)
        formatter = logging.Formatter(
            '%(asctime)s | %(levelname)s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        self.file_logger.addHandler(handler)
        
        # Console handler for errors
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.ERROR)
        console_handler.setFormatter(formatter)
        self.file_logger.addHandler(console_handler)
    
    def setup_database(self):
        """Setup SQLite database for structured logging"""
        try:
            self.conn = sqlite3.connect(self.db_path)
            self.conn.execute('PRAGMA journal_mode=WAL')  # Better concurrency
            
            # Create tables
            self.conn.executescript('''
                CREATE TABLE IF NOT EXISTS packet_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT,
                    rule_id INTEGER,
                    packet_size INTEGER,
                    processing_time REAL,
                    country TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS rule_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    rule_id INTEGER,
                    rule_data TEXT,
                    user_info TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS system_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'INFO',
                    details TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                CREATE TABLE IF NOT EXISTS daily_stats (
                    date TEXT PRIMARY KEY,
                    total_packets INTEGER DEFAULT 0,
                    allowed_packets INTEGER DEFAULT 0,
                    blocked_packets INTEGER DEFAULT 0,
                    unique_ips INTEGER DEFAULT 0,
                    top_blocked_ips TEXT,
                    top_allowed_ports TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Create indexes for better performance
                CREATE INDEX IF NOT EXISTS idx_packet_logs_timestamp ON packet_logs(timestamp);
                CREATE INDEX IF NOT EXISTS idx_packet_logs_ip ON packet_logs(ip);
                CREATE INDEX IF NOT EXISTS idx_packet_logs_action ON packet_logs(action);
                CREATE INDEX IF NOT EXISTS idx_rule_changes_timestamp ON rule_changes(timestamp);
                CREATE INDEX IF NOT EXISTS idx_system_events_timestamp ON system_events(timestamp);
            ''')
            
            self.conn.commit()
            
        except sqlite3.Error as e:
            self.file_logger.error(f"Database setup error: {e}")
            # Fallback to file-only logging
            self.conn = None
    
    def log_decision(self, packet: Dict[str, Any], action: str, reason: str = "", 
                    rule_id: Optional[int] = None, processing_time: float = 0.0):
        """Log a firewall decision"""
        timestamp = datetime.now().isoformat()
        
        # Log to file
        log_message = (
            f"DECISION | {action} | {packet['ip']}:{packet['port']}/{packet['protocol']} | "
            f"{reason} | {processing_time:.4f}s"
        )
        
        if action == 'ALLOW':
            self.file_logger.info(log_message)
        else:
            self.file_logger.warning(log_message)
        
        # Log to database
        if self.conn:
            try:
                self.conn.execute('''
                    INSERT INTO packet_logs 
                    (timestamp, ip, port, protocol, action, reason, rule_id, packet_size, processing_time, country)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    timestamp,
                    packet['ip'],
                    packet['port'],
                    packet['protocol'],
                    action,
                    reason,
                    rule_id,
                    packet.get('size', 64),
                    processing_time,
                    packet.get('country')
                ))
                self.conn.commit()
                
                # Update daily stats
                self._update_daily_stats(packet, action)
                
            except sqlite3.Error as e:
                self.file_logger.error(f"Database logging error: {e}")
    
    def log_rule_change(self, operation: str, rule_id: Optional[int] = None, 
                       rule_data: Optional[Dict[str, Any]] = None, user_info: str = "system"):
        """Log rule management operations"""
        timestamp = datetime.now().isoformat()
        
        # Log to file
        log_message = f"RULE_CHANGE | {operation} | Rule ID: {rule_id} | User: {user_info}"
        self.file_logger.info(log_message)
        
        # Log to database
        if self.conn:
            try:
                self.conn.execute('''
                    INSERT INTO rule_changes (timestamp, operation, rule_id, rule_data, user_info)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    timestamp,
                    operation,
                    rule_id,
                    json.dumps(rule_data) if rule_data else None,
                    user_info
                ))
                self.conn.commit()
            except sqlite3.Error as e:
                self.file_logger.error(f"Database rule logging error: {e}")
    
    def log_system_event(self, event_type: str, description: str, 
                        severity: str = "INFO", details: Optional[Dict[str, Any]] = None):
        """Log system events"""
        timestamp = datetime.now().isoformat()
        
        # Log to file
        log_message = f"SYSTEM | {severity} | {event_type} | {description}"
        
        if severity == "ERROR":
            self.file_logger.error(log_message)
        elif severity == "WARNING":
            self.file_logger.warning(log_message)
        else:
            self.file_logger.info(log_message)
        
        # Log to database
        if self.conn:
            try:
                self.conn.execute('''
                    INSERT INTO system_events (timestamp, event_type, description, severity, details)
                    VALUES (?, ?, ?, ?, ?)
                ''', (
                    timestamp,
                    event_type,
                    description,
                    severity,
                    json.dumps(details) if details else None
                ))
                self.conn.commit()
            except sqlite3.Error as e:
                self.file_logger.error(f"Database system logging error: {e}")
    
    def _update_daily_stats(self, packet: Dict[str, Any], action: str):
        """Update daily statistics"""
        if not self.conn:
            return
        
        today = datetime.now().date().isoformat()
        
        try:
            # Get or create daily stats
            cursor = self.conn.execute('SELECT * FROM daily_stats WHERE date = ?', (today,))
            row = cursor.fetchone()
            
            if row:
                # Update existing stats
                total_packets = row[1] + 1
                allowed_packets = row[2] + (1 if action == 'ALLOW' else 0)
                blocked_packets = row[3] + (1 if action == 'BLOCK' else 0)
                
                self.conn.execute('''
                    UPDATE daily_stats 
                    SET total_packets = ?, allowed_packets = ?, blocked_packets = ?, updated_at = CURRENT_TIMESTAMP
                    WHERE date = ?
                ''', (total_packets, allowed_packets, blocked_packets, today))
            else:
                # Create new daily stats
                allowed_packets = 1 if action == 'ALLOW' else 0
                blocked_packets = 1 if action == 'BLOCK' else 0
                
                self.conn.execute('''
                    INSERT INTO daily_stats (date, total_packets, allowed_packets, blocked_packets)
                    VALUES (?, 1, ?, ?)
                ''', (today, allowed_packets, blocked_packets))
            
            self.conn.commit()
            
        except sqlite3.Error as e:
            self.file_logger.error(f"Daily stats update error: {e}")
    
    def get_recent_logs(self, count: int = 50, action_filter: Optional[str] = None, 
                       ip_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get recent log entries"""
        if not self.conn:
            return []
        
        query = 'SELECT * FROM packet_logs WHERE 1=1'
        params = []
        
        if action_filter:
            query += ' AND action = ?'
            params.append(action_filter.upper())
        
        if ip_filter:
            query += ' AND ip = ?'
            params.append(ip_filter)
        
        query += ' ORDER BY created_at DESC LIMIT ?'
        params.append(count)
        
        try:
            cursor = self.conn.execute(query, params)
            rows = cursor.fetchall()
            
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
            
        except sqlite3.Error as e:
            self.file_logger.error(f"Error retrieving logs: {e}")
            return []
    
    def get_stats(self, period: str = 'day') -> Dict[str, Any]:
        """Get statistics for specified period"""
        if not self.conn:
            return {}
        
        # Calculate date range
        now = datetime.now()
        if period == 'hour':
            start_time = now - timedelta(hours=1)
        elif period == 'week':
            start_time = now - timedelta(weeks=1)
        else:  # day
            start_time = now - timedelta(days=1)
        
        start_iso = start_time.isoformat()
        
        try:
            # Basic packet stats
            cursor = self.conn.execute('''
                SELECT 
                    COUNT(*) as total_packets,
                    SUM(CASE WHEN action = 'ALLOW' THEN 1 ELSE 0 END) as allowed_packets,
                    SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked_packets,
                    COUNT(DISTINCT ip) as unique_ips,
                    AVG(processing_time) as avg_processing_time
                FROM packet_logs 
                WHERE timestamp >= ?
            ''', (start_iso,))
            
            row = cursor.fetchone()
            stats = {
                'period': period,
                'total_packets': row[0] or 0,
                'allowed_packets': row[1] or 0,
                'blocked_packets': row[2] or 0,
                'unique_ips': row[3] or 0,
                'avg_processing_time': f"{(row[4] or 0):.4f}s"
            }
            
            # Top blocked IPs
            cursor = self.conn.execute('''
                SELECT ip, COUNT(*) as count 
                FROM packet_logs 
                WHERE timestamp >= ? AND action = 'BLOCK'
                GROUP BY ip 
                ORDER BY count DESC 
                LIMIT 5
            ''', (start_iso,))
            
            stats['top_blocked_ips'] = [{'ip': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            # Top ports
            cursor = self.conn.execute('''
                SELECT port, COUNT(*) as count 
                FROM packet_logs 
                WHERE timestamp >= ?
                GROUP BY port 
                ORDER BY count DESC 
                LIMIT 5
            ''', (start_iso,))
            
            stats['top_ports'] = [{'port': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            # Protocol distribution
            cursor = self.conn.execute('''
                SELECT protocol, COUNT(*) as count 
                FROM packet_logs 
                WHERE timestamp >= ?
                GROUP BY protocol 
                ORDER BY count DESC
            ''', (start_iso,))
            
            stats['protocol_distribution'] = [{'protocol': row[0], 'count': row[1]} for row in cursor.fetchall()]
            
            return stats
            
        except sqlite3.Error as e:
            self.file_logger.error(f"Error retrieving stats: {e}")
            return {}
    
    def export_logs(self, file_path: str, start_date: Optional[str] = None, 
                   end_date: Optional[str] = None, format_type: str = 'json'):
        """Export logs to file"""
        if not self.conn:
            raise ValueError("Database not available for export")
        
        query = 'SELECT * FROM packet_logs WHERE 1=1'
        params = []
        
        if start_date:
            query += ' AND timestamp >= ?'
            params.append(start_date)
        
        if end_date:
            query += ' AND timestamp <= ?'
            params.append(end_date)
        
        query += ' ORDER BY timestamp'
        
        try:
            cursor = self.conn.execute(query, params)
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            
            data = [dict(zip(columns, row)) for row in rows]
            
            if format_type.lower() == 'json':
                with open(file_path, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            elif format_type.lower() == 'csv':
                import csv
                with open(file_path, 'w', newline='') as f:
                    if data:
                        writer = csv.DictWriter(f, fieldnames=columns)
                        writer.writeheader()
                        writer.writerows(data)
            else:
                raise ValueError("Unsupported format. Use 'json' or 'csv'")
                
        except sqlite3.Error as e:
            self.file_logger.error(f"Export error: {e}")
            raise
    
    def clear_logs(self, older_than_days: Optional[int] = None):
        """Clear logs, optionally keeping recent entries"""
        if not self.conn:
            return
        
        try:
            if older_than_days:
                cutoff_date = (datetime.now() - timedelta(days=older_than_days)).isoformat()
                
                # Clear old packet logs
                self.conn.execute('DELETE FROM packet_logs WHERE timestamp < ?', (cutoff_date,))
                self.conn.execute('DELETE FROM rule_changes WHERE timestamp < ?', (cutoff_date,))
                self.conn.execute('DELETE FROM system_events WHERE timestamp < ?', (cutoff_date,))
                
                deleted_count = self.conn.total_changes
                self.log_system_event(
                    'LOG_CLEANUP',
                    f'Cleared {deleted_count} log entries older than {older_than_days} days'
                )
            else:
                # Clear all logs
                self.conn.execute('DELETE FROM packet_logs')
                self.conn.execute('DELETE FROM rule_changes') 
                self.conn.execute('DELETE FROM system_events')
                self.conn.execute('DELETE FROM daily_stats')
                
                self.log_system_event('LOG_RESET', 'All logs cleared')
            
            self.conn.commit()
            
            # Vacuum database to reclaim space
            self.conn.execute('VACUUM')
            
        except sqlite3.Error as e:
            self.file_logger.error(f"Error clearing logs: {e}")
    
    def get_audit_trail(self, count: int = 100) -> List[Dict[str, Any]]:
        """Get audit trail of rule changes and system events"""
        if not self.conn:
            return []
        
        try:
            # Combine rule changes and system events
            cursor = self.conn.execute('''
                SELECT 'RULE_CHANGE' as type, timestamp, operation as event, rule_data as details, user_info
                FROM rule_changes
                UNION ALL
                SELECT 'SYSTEM_EVENT' as type, timestamp, event_type as event, details, 'system' as user_info
                FROM system_events
                ORDER BY timestamp DESC
                LIMIT ?
            ''', (count,))
            
            rows = cursor.fetchall()
            columns = [desc[0] for desc in cursor.description]
            return [dict(zip(columns, row)) for row in rows]
            
        except sqlite3.Error as e:
            self.file_logger.error(f"Error retrieving audit trail: {e}")
            return []
    
    def __del__(self):
        """Cleanup database connection"""
        if hasattr(self, 'conn') and self.conn:
            self.conn.close()