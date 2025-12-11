#!/usr/bin/env python3
"""
SecureNet DC - Attack Simulation Toolkit
CPEG 460 Bonus Project

Unified interface for all attack simulations.
Provides easy-to-use API for launching and managing attacks.

WARNING: For educational use only in controlled environments.
"""

import sys
import os
import logging
import threading
import time

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('attack_toolkit')

# Import attack modules
try:
    from .syn_flood import SYNFlood
    from .icmp_flood import ICMPFlood
    from .udp_flood import UDPFlood
    from .slowloris import Slowloris
    from .dns_amplification import DNSAmplification
except ImportError:
    from syn_flood import SYNFlood
    from icmp_flood import ICMPFlood
    from udp_flood import UDPFlood
    from slowloris import Slowloris
    from dns_amplification import DNSAmplification


class AttackToolkit:
    """
    Unified Attack Simulation Toolkit.

    Provides a single interface for launching various types of
    DDoS attacks for educational and testing purposes.
    """

    ATTACK_TYPES = {
        'syn_flood': {
            'class': SYNFlood,
            'description': 'TCP SYN Flood - Exhausts server connection resources',
            'default_duration': 30,
            'default_rate': 100
        },
        'icmp_flood': {
            'class': ICMPFlood,
            'description': 'ICMP Flood (Ping Flood) - Bandwidth exhaustion',
            'default_duration': 30,
            'default_rate': 50
        },
        'udp_flood': {
            'class': UDPFlood,
            'description': 'UDP Flood - Volumetric bandwidth attack',
            'default_duration': 30,
            'default_rate': 200
        },
        'slowloris': {
            'class': Slowloris,
            'description': 'Slowloris - Slow HTTP connection exhaustion',
            'default_duration': 60,
            'default_rate': 50  # connections
        },
        'dns_amplification': {
            'class': DNSAmplification,
            'description': 'DNS Amplification - Reflection/amplification attack',
            'default_duration': 30,
            'default_rate': 50
        }
    }

    def __init__(self, safe_mode=True):
        """
        Initialize Attack Toolkit.

        Args:
            safe_mode: Limit attack intensity (default: True)
        """
        self.safe_mode = safe_mode
        self.active_attacks = {}
        self.attack_history = []

        logger.info("Attack Toolkit initialized")
        if safe_mode:
            logger.info("Safe mode ENABLED - Attack intensity limited")
        else:
            logger.warning("Safe mode DISABLED - Use with caution!")

    def list_attacks(self):
        """
        List available attack types.

        Returns:
            dict: Available attacks with descriptions
        """
        return {
            name: info['description']
            for name, info in self.ATTACK_TYPES.items()
        }

    def launch_attack(self, attack_type, target_ip, **kwargs):
        """
        Launch an attack.

        Args:
            attack_type: Type of attack (syn_flood, icmp_flood, etc.)
            target_ip: Target IP address
            **kwargs: Attack-specific parameters

        Returns:
            str: Attack ID for tracking
        """
        if attack_type not in self.ATTACK_TYPES:
            raise ValueError(f"Unknown attack type: {attack_type}. "
                           f"Available: {list(self.ATTACK_TYPES.keys())}")

        attack_info = self.ATTACK_TYPES[attack_type]
        attack_class = attack_info['class']

        # Get parameters with defaults
        duration = kwargs.get('duration', attack_info['default_duration'])
        rate = kwargs.get('rate', attack_info['default_rate'])
        target_port = kwargs.get('port', 80)

        # Create attack instance
        if attack_type == 'slowloris':
            attack = attack_class(target_ip, target_port, self.safe_mode)
        elif attack_type == 'dns_amplification':
            dns_server = kwargs.get('dns_server', '10.0.1.2')
            attack = attack_class(target_ip, dns_server, self.safe_mode)
        elif attack_type in ['syn_flood']:
            attack = attack_class(target_ip, target_port, self.safe_mode)
        else:
            attack = attack_class(target_ip, self.safe_mode)

        # Generate attack ID
        attack_id = f"{attack_type}_{int(time.time())}"

        # Start attack in background thread
        def run_attack():
            try:
                if attack_type == 'slowloris':
                    stats = attack.start(duration=duration, connections=rate)
                else:
                    stats = attack.start(duration=duration, pps=rate)

                stats['attack_id'] = attack_id
                self.attack_history.append(stats)

            finally:
                if attack_id in self.active_attacks:
                    del self.active_attacks[attack_id]

        thread = threading.Thread(target=run_attack)
        thread.daemon = True
        thread.start()

        self.active_attacks[attack_id] = {
            'attack': attack,
            'thread': thread,
            'type': attack_type,
            'target': target_ip,
            'start_time': time.time()
        }

        logger.info(f"Launched attack {attack_id}: {attack_type} -> {target_ip}")
        return attack_id

    def stop_attack(self, attack_id):
        """
        Stop a running attack.

        Args:
            attack_id: ID of attack to stop

        Returns:
            bool: True if stopped, False if not found
        """
        if attack_id not in self.active_attacks:
            return False

        self.active_attacks[attack_id]['attack'].stop()
        logger.info(f"Stopped attack {attack_id}")
        return True

    def stop_all_attacks(self):
        """Stop all running attacks."""
        for attack_id in list(self.active_attacks.keys()):
            self.stop_attack(attack_id)
        logger.info("All attacks stopped")

    def get_active_attacks(self):
        """
        Get list of active attacks.

        Returns:
            list: Active attack information
        """
        active = []
        for attack_id, info in self.active_attacks.items():
            active.append({
                'attack_id': attack_id,
                'type': info['type'],
                'target': info['target'],
                'running_time': time.time() - info['start_time']
            })
        return active

    def get_attack_history(self, limit=10):
        """
        Get attack history.

        Args:
            limit: Maximum number of entries to return

        Returns:
            list: Recent attack statistics
        """
        return self.attack_history[-limit:]

    def run_interactive(self):
        """Run interactive attack console."""
        print("\n" + "=" * 60)
        print("  SecureNet DC - Attack Simulation Toolkit")
        print("  EDUCATIONAL USE ONLY")
        print("=" * 60)

        if self.safe_mode:
            print("\n[SAFE MODE] Attack intensity is limited")
        else:
            print("\n[WARNING] Safe mode disabled - attacks at full intensity")

        print("\nAvailable attacks:")
        for name, desc in self.list_attacks().items():
            print(f"  {name}: {desc}")

        print("\nCommands:")
        print("  launch <type> <target_ip> [duration] [rate] - Launch attack")
        print("  stop <attack_id> - Stop an attack")
        print("  stopall - Stop all attacks")
        print("  list - List active attacks")
        print("  history - Show attack history")
        print("  quit - Exit toolkit")
        print()

        while True:
            try:
                cmd = input("attack> ").strip().split()

                if not cmd:
                    continue

                if cmd[0] == 'quit' or cmd[0] == 'exit':
                    self.stop_all_attacks()
                    break

                elif cmd[0] == 'launch':
                    if len(cmd) < 3:
                        print("Usage: launch <type> <target_ip> [duration] [rate]")
                        continue

                    attack_type = cmd[1]
                    target_ip = cmd[2]
                    duration = int(cmd[3]) if len(cmd) > 3 else None
                    rate = int(cmd[4]) if len(cmd) > 4 else None

                    kwargs = {}
                    if duration:
                        kwargs['duration'] = duration
                    if rate:
                        kwargs['rate'] = rate

                    try:
                        attack_id = self.launch_attack(attack_type, target_ip, **kwargs)
                        print(f"Attack launched: {attack_id}")
                    except ValueError as e:
                        print(f"Error: {e}")

                elif cmd[0] == 'stop':
                    if len(cmd) < 2:
                        print("Usage: stop <attack_id>")
                        continue

                    if self.stop_attack(cmd[1]):
                        print(f"Stopped: {cmd[1]}")
                    else:
                        print(f"Attack not found: {cmd[1]}")

                elif cmd[0] == 'stopall':
                    self.stop_all_attacks()
                    print("All attacks stopped")

                elif cmd[0] == 'list':
                    active = self.get_active_attacks()
                    if active:
                        print("Active attacks:")
                        for a in active:
                            print(f"  {a['attack_id']}: {a['type']} -> {a['target']} "
                                  f"({a['running_time']:.0f}s)")
                    else:
                        print("No active attacks")

                elif cmd[0] == 'history':
                    history = self.get_attack_history()
                    if history:
                        print("Recent attacks:")
                        for h in history:
                            print(f"  {h.get('attack_type', 'unknown')}: "
                                  f"{h.get('target', 'unknown')} "
                                  f"({h.get('duration', 0):.1f}s, "
                                  f"{h.get('packets_sent', 0)} packets)")
                    else:
                        print("No attack history")

                else:
                    print(f"Unknown command: {cmd[0]}")

            except KeyboardInterrupt:
                print("\n\nInterrupted. Stopping all attacks...")
                self.stop_all_attacks()
                break
            except Exception as e:
                print(f"Error: {e}")


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description='SecureNet DC Attack Simulation Toolkit'
    )
    parser.add_argument('--unsafe', action='store_true',
                       help='Disable safe mode')
    parser.add_argument('--interactive', '-i', action='store_true',
                       help='Run interactive console')
    parser.add_argument('--attack', '-a', choices=list(AttackToolkit.ATTACK_TYPES.keys()),
                       help='Attack type to launch')
    parser.add_argument('--target', '-t', help='Target IP address')
    parser.add_argument('--duration', '-d', type=int, default=30,
                       help='Attack duration in seconds')
    parser.add_argument('--rate', '-r', type=int,
                       help='Attack rate (pps or connections)')

    args = parser.parse_args()

    toolkit = AttackToolkit(safe_mode=not args.unsafe)

    if args.interactive or (not args.attack and not args.target):
        toolkit.run_interactive()
    elif args.attack and args.target:
        kwargs = {'duration': args.duration}
        if args.rate:
            kwargs['rate'] = args.rate

        try:
            attack_id = toolkit.launch_attack(args.attack, args.target, **kwargs)
            print(f"Attack {attack_id} launched. Press Ctrl+C to stop.")

            # Wait for attack to complete or interrupt
            while toolkit.get_active_attacks():
                time.sleep(1)

        except KeyboardInterrupt:
            print("\nStopping attack...")
            toolkit.stop_all_attacks()
    else:
        parser.print_help()


if __name__ == '__main__':
    main()
