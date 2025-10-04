#!/usr/bin/env python3
"""
FireGuardCLI: Advanced Firewall Simulation Tool
Entry point for the command-line interface
"""

import argparse
import sys
from rich.console import Console
from rich.table import Table
from rich import print as rprint
from firewall import FirewallEngine
from logger import FirewallLogger

console = Console()

def create_parser():
    """Create and configure argument parser"""
    parser = argparse.ArgumentParser(
        description="FireGuardCLI - Advanced Firewall Simulation Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py simulate --ip 192.168.1.1 --port 80 --protocol TCP
  python main.py add-rule --ip 10.0.0.1 --port 22 --protocol TCP --action BLOCK
  python main.py list-rules
  python main.py delete-rule --id 2
  python main.py bulk-simulate --count 100
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Simulate command
    simulate_parser = subparsers.add_parser('simulate', help='Simulate a packet')
    simulate_parser.add_argument('--ip', required=True, help='Source IP address')
    simulate_parser.add_argument('--port', type=int, required=True, help='Destination port')
    simulate_parser.add_argument('--protocol', required=True, choices=['TCP', 'UDP', 'ICMP'], 
                               help='Protocol type')
    simulate_parser.add_argument('--size', type=int, default=64, help='Packet size in bytes')
    simulate_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')
    
    # Bulk simulate command
    bulk_parser = subparsers.add_parser('bulk-simulate', help='Simulate multiple packets')
    bulk_parser.add_argument('--count', type=int, default=10, help='Number of packets to simulate')
    bulk_parser.add_argument('--file', help='Load packets from JSON file')
    bulk_parser.add_argument('--random', action='store_true', help='Generate random packets')
    
    # Add rule command
    add_parser = subparsers.add_parser('add-rule', help='Add a new rule')
    add_parser.add_argument('--ip', help='IP address or CIDR (e.g., 192.168.1.0/24)')
    add_parser.add_argument('--port', type=int, help='Port number')
    add_parser.add_argument('--protocol', choices=['TCP', 'UDP', 'ICMP', 'ANY'], help='Protocol')
    add_parser.add_argument('--action', required=True, choices=['ALLOW', 'BLOCK'], help='Action to take')
    add_parser.add_argument('--priority', type=int, default=100, help='Rule priority (lower = higher priority)')
    add_parser.add_argument('--description', help='Rule description')
    add_parser.add_argument('--country', help='Block/allow by country code (e.g., US, CN)')
    add_parser.add_argument('--rate-limit', type=int, help='Rate limit (packets per second)')
    
    # Delete rule command
    delete_parser = subparsers.add_parser('delete-rule', help='Delete a rule')
    delete_parser.add_argument('--id', type=int, required=True, help='Rule ID to delete')
    
    # List rules command
    list_parser = subparsers.add_parser('list-rules', help='List all rules')
    list_parser.add_argument('--action', choices=['ALLOW', 'BLOCK'], help='Filter by action')
    list_parser.add_argument('--export', help='Export rules to file')
    
    # Import rules command
    import_parser = subparsers.add_parser('import-rules', help='Import rules from file')
    import_parser.add_argument('--file', required=True, help='JSON file to import')
    import_parser.add_argument('--merge', action='store_true', help='Merge with existing rules')
    
    # Stats command
    stats_parser = subparsers.add_parser('stats', help='Show firewall statistics')
    stats_parser.add_argument('--period', choices=['hour', 'day', 'week'], default='day', 
                            help='Time period for stats')
    
    # Log command
    log_parser = subparsers.add_parser('logs', help='View firewall logs')
    log_parser.add_argument('--tail', type=int, default=50, help='Number of recent entries to show')
    log_parser.add_argument('--action', choices=['ALLOW', 'BLOCK'], help='Filter by action')
    log_parser.add_argument('--ip', help='Filter by IP address')
    
    # Reset command
    reset_parser = subparsers.add_parser('reset', help='Reset rules and logs')
    reset_parser.add_argument('--confirm', action='store_true', help='Confirm reset')
    
    # Interactive mode
    interactive_parser = subparsers.add_parser('interactive', help='Start interactive mode')
    
    return parser

def display_packet_result(packet, result, rule=None, verbose=False):
    """Display packet simulation result with rich formatting"""
    if result['action'] == 'ALLOW':
        color = "green"
        symbol = "✅"
    else:
        color = "red"
        symbol = "❌"
    
    rprint(f"\n{symbol} [bold {color}]{result['action']}[/bold {color}] - "
           f"{packet['ip']}:{packet['port']}/{packet['protocol']}")
    
    if verbose:
        console.print(f"  Reason: {result.get('reason', 'No matching rule')}")
        if rule:
            console.print(f"  Matched Rule: {rule.get('description', f'Rule #{rule.get('id')}')}")
        console.print(f"  Packet Size: {packet.get('size', 64)} bytes")
        console.print(f"  Processing Time: {result.get('processing_time', 0):.4f}s")

def handle_simulate(args, firewall, logger):
    """Handle packet simulation"""
    packet = {
        'ip': args.ip,
        'port': args.port,
        'protocol': args.protocol,
        'size': args.size
    }
    
    result = firewall.check_packet(packet)
    matched_rule = result.get('matched_rule')
    
    display_packet_result(packet, result, matched_rule, args.verbose)
    
    # Log the decision
    logger.log_decision(packet, result['action'], result.get('reason', ''))

def handle_bulk_simulate(args, firewall, logger):
    """Handle bulk packet simulation"""
    import random
    import json
    
    packets = []
    
    if args.file:
        try:
            with open(args.file, 'r') as f:
                packets = json.load(f)
        except Exception as e:
            console.print(f"[red]Error loading file: {e}[/red]")
            return
    elif args.random:
        # Generate random packets
        ips = ['192.168.1.' + str(random.randint(1, 254)) for _ in range(10)]
        ips.extend(['10.0.0.' + str(random.randint(1, 254)) for _ in range(5)])
        ips.extend(['8.8.8.8', '1.1.1.1', '208.67.222.222'])
        
        ports = [22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3389, 5432]
        protocols = ['TCP', 'UDP']
        
        for _ in range(args.count):
            packets.append({
                'ip': random.choice(ips),
                'port': random.choice(ports),
                'protocol': random.choice(protocols),
                'size': random.randint(32, 1500)
            })
    else:
        console.print("[red]Please specify --file or --random for bulk simulation[/red]")
        return
    
    console.print(f"\n[bold cyan]Simulating {len(packets)} packets...[/bold cyan]")
    
    allowed = 0
    blocked = 0
    
    with console.status("[bold green]Processing packets...") as status:
        for i, packet in enumerate(packets):
            result = firewall.check_packet(packet)
            
            if result['action'] == 'ALLOW':
                allowed += 1
            else:
                blocked += 1
            
            logger.log_decision(packet, result['action'], result.get('reason', ''))
            status.update(f"[bold green]Processed {i+1}/{len(packets)} packets...")
    
    # Display summary
    table = Table(title="Bulk Simulation Results")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="magenta")
    table.add_column("Percentage", style="green")
    
    total = len(packets)
    table.add_row("Total Packets", str(total), "100%")
    table.add_row("Allowed", str(allowed), f"{(allowed/total)*100:.1f}%")
    table.add_row("Blocked", str(blocked), f"{(blocked/total)*100:.1f}%")
    
    console.print(table)

def handle_add_rule(args, firewall):
    """Handle adding a new rule"""
    rule = {
        'ip': args.ip,
        'port': args.port,
        'protocol': args.protocol,
        'action': args.action,
        'priority': args.priority,
        'description': args.description,
        'country': args.country,
        'rate_limit': args.rate_limit
    }
    
    try:
        rule_id = firewall.add_rule(rule)
        console.print(f"[green]✅ Rule added successfully with ID: {rule_id}[/green]")
    except Exception as e:
        console.print(f"[red]❌ Error adding rule: {e}[/red]")

def handle_delete_rule(args, firewall):
    """Handle deleting a rule"""
    try:
        if firewall.delete_rule(args.id):
            console.print(f"[green]✅ Rule {args.id} deleted successfully[/green]")
        else:
            console.print(f"[red]❌ Rule {args.id} not found[/red]")
    except Exception as e:
        console.print(f"[red]❌ Error deleting rule: {e}[/red]")

def handle_list_rules(args, firewall):
    """Handle listing rules"""
    rules = firewall.get_rules(action_filter=args.action)
    
    if not rules:
        console.print("[yellow]No rules found[/yellow]")
        return
    
    table = Table(title="Firewall Rules")
    table.add_column("ID", style="cyan")
    table.add_column("IP/CIDR", style="blue")
    table.add_column("Port", style="magenta")
    table.add_column("Protocol", style="yellow")
    table.add_column("Action", style="green")
    table.add_column("Priority", style="red")
    table.add_column("Description")
    
    for rule in rules:
        action_color = "green" if rule['action'] == 'ALLOW' else "red"
        table.add_row(
            str(rule.get('id', '')),
            rule.get('ip', 'ANY'),
            str(rule.get('port', 'ANY')),
            rule.get('protocol', 'ANY'),
            f"[{action_color}]{rule['action']}[/{action_color}]",
            str(rule.get('priority', 100)),
            rule.get('description', '')
        )
    
    console.print(table)
    
    if args.export:
        try:
            firewall.export_rules(args.export)
            console.print(f"[green]✅ Rules exported to {args.export}[/green]")
        except Exception as e:
            console.print(f"[red]❌ Error exporting rules: {e}[/red]")

def handle_stats(args, firewall, logger):
    """Handle showing statistics"""
    stats = logger.get_stats(period=args.period)
    
    table = Table(title=f"Firewall Statistics ({args.period})")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")
    
    for key, value in stats.items():
        table.add_row(key.replace('_', ' ').title(), str(value))
    
    console.print(table)

def handle_logs(args, logger):
    """Handle showing logs"""
    logs = logger.get_recent_logs(
        count=args.tail,
        action_filter=args.action,
        ip_filter=args.ip
    )
    
    if not logs:
        console.print("[yellow]No logs found[/yellow]")
        return
    
    table = Table(title="Recent Firewall Logs")
    table.add_column("Timestamp", style="cyan")
    table.add_column("IP", style="blue")
    table.add_column("Port", style="magenta")
    table.add_column("Protocol", style="yellow")
    table.add_column("Action", style="green")
    table.add_column("Reason")
    
    for log in logs:
        action_color = "green" if log['action'] == 'ALLOW' else "red"
        table.add_row(
            log['timestamp'],
            log['ip'],
            str(log['port']),
            log['protocol'],
            f"[{action_color}]{log['action']}[/{action_color}]",
            log.get('reason', '')
        )
    
    console.print(table)

def interactive_mode(firewall, logger):
    """Start interactive mode"""
    console.print("\n[bold cyan]🔥 FireGuardCLI Interactive Mode[/bold cyan]")
    console.print("Type 'help' for commands or 'quit' to exit\n")
    
    while True:
        try:
            cmd = console.input("[bold green]FireGuard> [/bold green]").strip()
            
            if not cmd:
                continue
                
            if cmd.lower() in ['quit', 'exit']:
                break
            elif cmd.lower() == 'help':
                console.print("""
Available commands:
  simulate <ip> <port> <protocol>     - Test a packet
  add-rule                           - Add a new rule (guided setup)
  block <ip> [port] [protocol]       - Quick block rule
  allow <ip> [port] [protocol]       - Quick allow rule
  delete <rule_id>                   - Delete rule by ID
  list-rules [allow|block]           - Show all rules (optional filter)
  search <query>                     - Search rules by IP/description
  stats [hour|day|week]              - Show statistics
  logs [count]                       - Show recent logs
  export <filename>                  - Export rules to file
  reset                              - Reset all rules (dangerous!)
  clear                              - Clear screen
  help                               - Show this help
  quit                               - Exit interactive mode

Examples:
  simulate 192.168.1.1 80 TCP
  block 10.0.0.1 22 TCP
  allow 8.8.8.8 53 UDP
  stats day
  logs 20
                """)
            elif cmd.startswith('simulate'):
                parts = cmd.split()
                if len(parts) >= 4:
                    try:
                        packet = {
                            'ip': parts[1],
                            'port': int(parts[2]),
                            'protocol': parts[3].upper(),
                            'size': 64
                        }
                        result = firewall.check_packet(packet)
                        display_packet_result(packet, result, verbose=True)
                        logger.log_decision(packet, result['action'], result.get('reason', ''))
                    except ValueError:
                        console.print("[red]Error: Port must be a number[/red]")
                else:
                    console.print("[red]Usage: simulate <ip> <port> <protocol>[/red]")
            
            elif cmd.startswith('block'):
                parts = cmd.split()
                if len(parts) >= 2:
                    try:
                        rule_data = {
                            'ip': parts[1],
                            'port': int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None,
                            'protocol': parts[3].upper() if len(parts) > 3 else None,
                            'action': 'BLOCK',
                            'priority': 50,
                            'description': f'Interactive block: {parts[1]}'
                        }
                        rule_id = firewall.add_rule(rule_data)
                        console.print(f"[green]✅ Block rule added with ID: {rule_id}[/green]")
                        logger.log_rule_change('ADD', rule_id, rule_data, 'interactive')
                    except Exception as e:
                        console.print(f"[red]❌ Error: {e}[/red]")
                else:
                    console.print("[red]Usage: block <ip> [port] [protocol][/red]")
            
            elif cmd.startswith('allow'):
                parts = cmd.split()
                if len(parts) >= 2:
                    try:
                        rule_data = {
                            'ip': parts[1],
                            'port': int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else None,
                            'protocol': parts[3].upper() if len(parts) > 3 else None,
                            'action': 'ALLOW',
                            'priority': 50,
                            'description': f'Interactive allow: {parts[1]}'
                        }
                        rule_id = firewall.add_rule(rule_data)
                        console.print(f"[green]✅ Allow rule added with ID: {rule_id}[/green]")
                        logger.log_rule_change('ADD', rule_id, rule_data, 'interactive')
                    except Exception as e:
                        console.print(f"[red]❌ Error: {e}[/red]")
                else:
                    console.print("[red]Usage: allow <ip> [port] [protocol][/red]")
            
            elif cmd.startswith('delete'):
                parts = cmd.split()
                if len(parts) >= 2:
                    try:
                        rule_id = int(parts[1])
                        if firewall.delete_rule(rule_id):
                            console.print(f"[green]✅ Rule {rule_id} deleted[/green]")
                            logger.log_rule_change('DELETE', rule_id, None, 'interactive')
                        else:
                            console.print(f"[red]❌ Rule {rule_id} not found[/red]")
                    except ValueError:
                        console.print("[red]Error: Rule ID must be a number[/red]")
                else:
                    console.print("[red]Usage: delete <rule_id>[/red]")
            
            elif cmd.startswith('list-rules'):
                parts = cmd.split()
                action_filter = parts[1].upper() if len(parts) > 1 and parts[1].upper() in ['ALLOW', 'BLOCK'] else None
                handle_list_rules(argparse.Namespace(action=action_filter, export=None), firewall)
            
            elif cmd.startswith('search'):
                parts = cmd.split(maxsplit=1)
                if len(parts) >= 2:
                    query = parts[1]
                    results = firewall.search_rules(query)
                    if results:
                        console.print(f"\n[cyan]Found {len(results)} rules matching '{query}':[/cyan]")
                        table = Table()
                        table.add_column("ID", style="cyan")
                        table.add_column("IP/CIDR", style="blue") 
                        table.add_column("Port", style="magenta")
                        table.add_column("Protocol", style="yellow")
                        table.add_column("Action", style="green")
                        table.add_column("Description")
                        
                        for rule in results:
                            action_color = "green" if rule['action'] == 'ALLOW' else "red"
                            table.add_row(
                                str(rule.get('id', '')),
                                rule.get('ip', 'ANY'),
                                str(rule.get('port', 'ANY')),
                                rule.get('protocol', 'ANY'),
                                f"[{action_color}]{rule['action']}[/{action_color}]",
                                rule.get('description', '')
                            )
                        console.print(table)
                    else:
                        console.print(f"[yellow]No rules found matching '{query}'[/yellow]")
                else:
                    console.print("[red]Usage: search <query>[/red]")
            
            elif cmd.startswith('stats'):
                parts = cmd.split()
                period = parts[1] if len(parts) > 1 and parts[1] in ['hour', 'day', 'week'] else 'day'
                handle_stats(argparse.Namespace(period=period), firewall, logger)
            
            elif cmd.startswith('logs'):
                parts = cmd.split()
                count = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 10
                handle_logs(argparse.Namespace(tail=count, action=None, ip=None), logger)
            
            elif cmd.startswith('export'):
                parts = cmd.split()
                if len(parts) >= 2:
                    try:
                        firewall.export_rules(parts[1])
                        console.print(f"[green]✅ Rules exported to {parts[1]}[/green]")
                    except Exception as e:
                        console.print(f"[red]❌ Export error: {e}[/red]")
                else:
                    console.print("[red]Usage: export <filename>[/red]")
            
            elif cmd == 'add-rule':
                # Guided rule creation
                console.print("\n[cyan]🔧 Interactive Rule Creator[/cyan]")
                try:
                    ip = console.input("IP address or CIDR (or press Enter for ANY): ").strip()
                    ip = ip if ip else None
                    
                    port_input = console.input("Port number (or press Enter for ANY): ").strip()
                    port = int(port_input) if port_input.isdigit() else None
                    
                    protocol = console.input("Protocol [TCP/UDP/ICMP/ANY] (default: ANY): ").strip().upper()
                    protocol = protocol if protocol in ['TCP', 'UDP', 'ICMP', 'ANY'] else 'ANY'
                    
                    action = console.input("Action [ALLOW/BLOCK]: ").strip().upper()
                    if action not in ['ALLOW', 'BLOCK']:
                        console.print("[red]❌ Action must be ALLOW or BLOCK[/red]")
                        continue
                    
                    priority_input = console.input("Priority [1-1000] (default: 100): ").strip()
                    priority = int(priority_input) if priority_input.isdigit() else 100
                    
                    description = console.input("Description (optional): ").strip()
                    description = description if description else f"Interactive {action.lower()} rule"
                    
                    rule_data = {
                        'ip': ip,
                        'port': port,
                        'protocol': protocol if protocol != 'ANY' else None,
                        'action': action,
                        'priority': priority,
                        'description': description
                    }
                    
                    rule_id = firewall.add_rule(rule_data)
                    console.print(f"[green]✅ Rule added successfully with ID: {rule_id}[/green]")
                    logger.log_rule_change('ADD', rule_id, rule_data, 'interactive')
                    
                except KeyboardInterrupt:
                    console.print("\n[yellow]Rule creation cancelled[/yellow]")
                except Exception as e:
                    console.print(f"[red]❌ Error creating rule: {e}[/red]")
            
            elif cmd == 'reset':
                confirm = console.input("[red]⚠️  Reset ALL rules? Type 'yes' to confirm: [/red]")
                if confirm.lower() == 'yes':
                    firewall.reset_rules()
                    logger.clear_logs()
                    console.print("[green]✅ Rules and logs reset[/green]")
                else:
                    console.print("[yellow]Reset cancelled[/yellow]")
            
            elif cmd == 'clear':
                os.system('cls' if os.name == 'nt' else 'clear')
                console.print("[bold cyan]🔥 FireGuardCLI Interactive Mode[/bold cyan]")
            
            elif cmd == 'list-rules':
                handle_list_rules(argparse.Namespace(action=None, export=None), firewall)
            elif cmd == 'stats':
                handle_stats(argparse.Namespace(period='day'), firewall, logger)
            elif cmd == 'logs':
                handle_logs(argparse.Namespace(tail=10, action=None, ip=None), logger)
            else:
                console.print(f"[red]Unknown command: {cmd}[/red]")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
    
    console.print("\n[yellow]Goodbye! 👋[/yellow]")

def main():
    """Main entry point"""
    parser = create_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Initialize firewall and logger
    firewall = FirewallEngine()
    logger = FirewallLogger()
    
    console.print("[bold cyan]🔥 FireGuardCLI - Advanced Firewall Simulation Tool[/bold cyan]\n")
    
    try:
        if args.command == 'simulate':
            handle_simulate(args, firewall, logger)
        elif args.command == 'bulk-simulate':
            handle_bulk_simulate(args, firewall, logger)
        elif args.command == 'add-rule':
            handle_add_rule(args, firewall)
        elif args.command == 'delete-rule':
            handle_delete_rule(args, firewall)
        elif args.command == 'list-rules':
            handle_list_rules(args, firewall)
        elif args.command == 'import-rules':
            try:
                firewall.import_rules(args.file, merge=args.merge)
                console.print(f"[green]✅ Rules imported from {args.file}[/green]")
            except Exception as e:
                console.print(f"[red]❌ Error importing rules: {e}[/red]")
        elif args.command == 'stats':
            handle_stats(args, firewall, logger)
        elif args.command == 'logs':
            handle_logs(args, logger)
        elif args.command == 'reset':
            if args.confirm:
                firewall.reset_rules()
                logger.clear_logs()
                console.print("[green]✅ Rules and logs reset successfully[/green]")
            else:
                console.print("[red]Please use --confirm to reset[/red]")
        elif args.command == 'interactive':
            interactive_mode(firewall, logger)
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Operation cancelled[/yellow]")
    except Exception as e:
        console.print(f"[red]❌ Error: {e}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()