#!/usr/bin/env python3
"""
SecureNet DC - Integrated Demo Runner
=====================================
Runs Mininet + Attack Simulator in ONE process for proper namespace access.

Usage:
    sudo python3 scripts/run_demo.py                  # Interactive mode
    sudo python3 scripts/run_demo.py --auto           # Auto-run demo
    sudo python3 scripts/run_demo.py --attack icmp    # Run specific attack

This script MUST run as root and from the securenet_dc directory.
"""

import subprocess
import time
import threading
import sys
import os
import argparse
import signal

# Check if we can import mininet
try:
    from mininet.net import Mininet
    from mininet.nodelib import LinuxBridge
    from mininet.topolib import TreeTopo
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    # Import our Fat-Tree topology
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from topology.dynamic_topology import FatTreeTopo
except ImportError as e:
    print(f"[!] Import error: {e}")
    print("[!] Mininet not installed. Install with: sudo apt install mininet")
    sys.exit(1)

# ============== COLORS ==============
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
BOLD = '\033[1m'
NC = '\033[0m'  # No Color

# ============== GLOBAL STATE ==============
net = None
stats_proc = None
dashboard_proc = None
running = True
attack_stats = {
    'total_attacks': 0,
    'packets_sent': 0,
    'current_attack': None
}

# ============== UTILITY FUNCTIONS ==============

def print_banner():
    """Print the demo banner"""
    print(f"{RED}")
    print("=" * 70)
    print("  ____                           _   _        _     ____   ____ ")
    print(" / ___|  ___  ___ _   _ _ __ ___| \\ | | ___  | |_  |  _ \\ / ___|")
    print(" \\___ \\ / _ \\/ __| | | | '__/ _ \\  \\| |/ _ \\ | __| | | | | |    ")
    print("  ___) |  __/ (__| |_| | | |  __/ |\\  |  __/ | |_  | |_| | |___ ")
    print(" |____/ \\___|\\___|\\__,_|_|  \\___|_| \\_|\\___|  \\__| |____/ \\____|")
    print("")
    print("         INTEGRATED DEMO RUNNER - WSL2 Linux Bridge Mode")
    print("=" * 70)
    print(f"{NC}")


def print_status():
    """Print current network and attack status"""
    print(f"\n{CYAN}{'=' * 60}{NC}")
    print(f"{CYAN}CURRENT STATUS{NC}")
    print(f"{CYAN}{'=' * 60}{NC}")

    if net:
        print(f"  {GREEN}Network:{NC} Running")
        print(f"  {GREEN}Switches:{NC} {[s.name for s in net.switches]}")
        print(f"  {GREEN}Hosts:{NC} {[h.name for h in net.hosts]}")
        for h in net.hosts:
            print(f"    - {h.name}: {h.IP()}")
    else:
        print(f"  {RED}Network:{NC} Not running")

    print(f"\n  {YELLOW}Attack Stats:{NC}")
    print(f"    Total Attacks: {attack_stats['total_attacks']}")
    print(f"    Est. Packets: {attack_stats['packets_sent']:,}")
    print(f"    Current: {attack_stats['current_attack'] or 'None'}")
    print(f"{CYAN}{'=' * 60}{NC}")


def cleanup():
    """Clean up all resources"""
    global net, stats_proc, dashboard_proc, running
    running = False

    print(f"\n{YELLOW}[*] Cleaning up...{NC}")

    if net:
        try:
            net.stop()
        except:
            pass

    if stats_proc:
        try:
            stats_proc.terminate()
        except:
            pass

    if dashboard_proc:
        try:
            dashboard_proc.terminate()
        except:
            pass

    # Clean up mininet
    subprocess.run(['mn', '-c'], capture_output=True, timeout=10)
    print(f"{GREEN}[+] Cleanup complete{NC}")


def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    print(f"\n{YELLOW}[!] Interrupt received{NC}")
    cleanup()
    sys.exit(0)


# ============== SERVICE MANAGEMENT ==============

def start_stats_collector():
    """Start the stats collector service"""
    global stats_proc

    print(f"{YELLOW}[*] Starting Stats Collector...{NC}")

    # Check if already running
    result = subprocess.run(['pgrep', '-f', 'network_stats_collector'], capture_output=True)
    if result.returncode == 0:
        print(f"{GREEN}[+] Stats Collector already running{NC}")
        return True

    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        venv_python = os.path.join(os.path.dirname(script_dir), 'venv', 'bin', 'python3')

        if os.path.exists(venv_python):
            python_cmd = venv_python
        else:
            python_cmd = 'python3'

        stats_script = os.path.join(script_dir, 'network_stats_collector.py')

        stats_proc = subprocess.Popen(
            [python_cmd, stats_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(script_dir)
        )
        time.sleep(2)
        print(f"{GREEN}[+] Stats Collector started on port 8080{NC}")
        return True
    except Exception as e:
        print(f"{RED}[!] Failed to start Stats Collector: {e}{NC}")
        return False


def start_dashboard():
    """Start the web dashboard"""
    global dashboard_proc

    print(f"{YELLOW}[*] Starting Dashboard...{NC}")

    # Check if already running
    result = subprocess.run(['pgrep', '-f', 'dashboard/app.py'], capture_output=True)
    if result.returncode == 0:
        print(f"{GREEN}[+] Dashboard already running{NC}")
        return True

    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        base_dir = os.path.dirname(script_dir)
        venv_python = os.path.join(base_dir, 'venv', 'bin', 'python3')

        if os.path.exists(venv_python):
            python_cmd = venv_python
        else:
            python_cmd = 'python3'

        dashboard_script = os.path.join(base_dir, 'dashboard', 'app.py')

        dashboard_proc = subprocess.Popen(
            [python_cmd, dashboard_script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=base_dir
        )
        time.sleep(2)
        print(f"{GREEN}[+] Dashboard started on port 5000{NC}")
        return True
    except Exception as e:
        print(f"{RED}[!] Failed to start Dashboard: {e}{NC}")
        return False


def start_network():
    """Start Mininet network with Linux bridges - LARGER TOPOLOGY"""
    global net

    print(f"\n{YELLOW}[*] Creating Mininet network...{NC}")

    # Clean up first
    subprocess.run(['mn', '-c'], capture_output=True, timeout=10)
    time.sleep(1)

    try:
        setLogLevel('warning')

        # Create Fat-Tree k=4 topology: 20 switches, 16 hosts
        # Or fallback to tree topology if Fat-Tree fails
        try:
            print(f"{YELLOW}[*] Creating Fat-Tree k=4 topology (20 switches, 16 hosts)...{NC}")
            topo = FatTreeTopo(k=4)
            topo_name = "Fat-Tree k=4"
        except Exception as e:
            print(f"{YELLOW}[*] Fat-Tree failed ({e}), using tree topology...{NC}")
            topo = TreeTopo(depth=2, fanout=3)
            topo_name = "tree,depth=2,fanout=3"

        net = Mininet(topo=topo, controller=None, switch=LinuxBridge)

        print(f"{YELLOW}[*] Starting network...{NC}")
        net.start()

        print(f"\n{GREEN}[+] Network Started Successfully!{NC}")
        print(f"{GREEN}    Topology: {topo_name}{NC}")
        print(f"{GREEN}    Switches: {len(net.switches)}{NC}")
        print(f"{GREEN}    Hosts: {len(net.hosts)}{NC}")

        # Show host IPs with roles
        print(f"\n{CYAN}Host Configuration:{NC}")
        print(f"    {CYAN}{'Host':<6} {'IP':<15} {'Role':<20}{NC}")
        print(f"    {'-'*45}")
        host_roles = {
            'h1': 'Web Server', 'h2': 'Web Server', 'h3': 'Web Server', 'h4': 'Web Server',
            'h5': 'Database', 'h6': 'Database',
            'h7': 'Client', 'h8': 'Client', 'h9': 'Client', 'h10': 'Client', 'h11': 'Client', 'h12': 'Client',
            'h13': f'{RED}Attacker{NC}', 'h14': 'IDS Monitor',
            'h15': 'Streaming', 'h16': 'Streaming'
        }
        for h in net.hosts:
            role = host_roles.get(h.name, 'General')
            print(f"    {h.name:<6} {h.IP():<15} {role}")

        # Test connectivity
        print(f"\n{YELLOW}[*] Testing connectivity...{NC}")
        net.pingAll()

        return True

    except Exception as e:
        print(f"{RED}[!] Failed to start network: {e}{NC}")
        return False


# ============== ATTACK FUNCTIONS ==============

def run_icmp_flood(attacker='h13', target='h1', count=5000, background=True):
    """Run ICMP flood attack - default attacker is h13"""
    global attack_stats

    if not net:
        print(f"{RED}[!] Network not running{NC}")
        return False

    try:
        src = net.get(attacker)
        dst = net.get(target)
        target_ip = dst.IP()

        print(f"\n{RED}{'=' * 60}{NC}")
        print(f"{RED}  ██████╗ ██████╗  ██████╗ ███████╗    █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗{NC}")
        print(f"{RED}  ██╔══██╗██╔══██╗██╔═══██╗██╔════╝   ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝{NC}")
        print(f"{RED}  ██║  ██║██║  ██║██║   ██║███████╗   ███████║   ██║      ██║   ███████║██║     █████╔╝ {NC}")
        print(f"{RED}  ██║  ██║██║  ██║██║   ██║╚════██║   ██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ {NC}")
        print(f"{RED}  ██████╔╝██████╔╝╚██████╔╝███████║   ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗{NC}")
        print(f"{RED}  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{NC}")
        print(f"{RED}{'=' * 60}{NC}")
        print(f"{RED}  ICMP FLOOD ATTACK{NC}")
        print(f"{RED}{'=' * 60}{NC}")
        print(f"  {YELLOW}Attacker:{NC} {attacker} ({src.IP()})")
        print(f"  {YELLOW}Target:{NC}   {target} ({target_ip})")
        print(f"  {YELLOW}Packets:{NC}  {count:,}")
        print(f"{RED}{'=' * 60}{NC}")

        attack_stats['current_attack'] = f'ICMP Flood: {attacker} -> {target}'
        attack_stats['total_attacks'] += 1
        attack_stats['packets_sent'] += count

        cmd = f'ping -f -c {count} {target_ip}'
        if background:
            src.cmd(cmd + ' &')
            print(f"{GREEN}[+] Attack launched in background!{NC}")
            print(f"{YELLOW}[*] Watch the dashboard for detection...{NC}")
        else:
            output = src.cmd(cmd)
            print(f"{CYAN}{output}{NC}")

        return True

    except Exception as e:
        print(f"{RED}[!] Attack failed: {e}{NC}")
        return False


def run_syn_flood(attacker='h8', target='h1', count=3000, port=80):
    """Run SYN flood attack using hping3 - default attacker is h8"""
    global attack_stats

    if not net:
        print(f"{RED}[!] Network not running{NC}")
        return False

    try:
        src = net.get(attacker)
        dst = net.get(target)
        target_ip = dst.IP()

        print(f"\n{RED}{'=' * 60}{NC}")
        print(f"{RED}  SYN FLOOD ATTACK{NC}")
        print(f"{RED}{'=' * 60}{NC}")
        print(f"  {YELLOW}Attacker:{NC} {attacker} ({src.IP()})")
        print(f"  {YELLOW}Target:{NC}   {target} ({target_ip}:{port})")
        print(f"  {YELLOW}Packets:{NC}  {count:,}")
        print(f"{RED}{'=' * 60}{NC}")

        attack_stats['current_attack'] = f'SYN Flood: {attacker} -> {target}:{port}'
        attack_stats['total_attacks'] += 1
        attack_stats['packets_sent'] += count

        # Try hping3 first, fallback to ping flood
        result = src.cmd('which hping3')
        if 'hping3' in result:
            cmd = f'hping3 -S -p {port} --flood -c {count} {target_ip}'
        else:
            print(f"{YELLOW}[!] hping3 not found, using ping flood as fallback{NC}")
            cmd = f'ping -f -s 1400 -c {count} {target_ip}'

        src.cmd(cmd + ' &')
        print(f"{GREEN}[+] Attack launched!{NC}")
        print(f"{YELLOW}[*] Watch the dashboard for detection...{NC}")
        return True

    except Exception as e:
        print(f"{RED}[!] Attack failed: {e}{NC}")
        return False


def run_udp_flood(attacker='h7', target='h2', count=3000, port=53):
    """Run UDP flood attack - default attacker is h7"""
    global attack_stats

    if not net:
        print(f"{RED}[!] Network not running{NC}")
        return False

    try:
        src = net.get(attacker)
        dst = net.get(target)
        target_ip = dst.IP()

        print(f"\n{RED}{'=' * 60}{NC}")
        print(f"{RED}  UDP FLOOD ATTACK{NC}")
        print(f"{RED}{'=' * 60}{NC}")
        print(f"  {YELLOW}Attacker:{NC} {attacker} ({src.IP()})")
        print(f"  {YELLOW}Target:{NC}   {target} ({target_ip}:{port})")
        print(f"  {YELLOW}Packets:{NC}  {count:,}")
        print(f"{RED}{'=' * 60}{NC}")

        attack_stats['current_attack'] = f'UDP Flood: {attacker} -> {target}:{port}'
        attack_stats['total_attacks'] += 1
        attack_stats['packets_sent'] += count

        # Try hping3 first
        result = src.cmd('which hping3')
        if 'hping3' in result:
            cmd = f'hping3 --udp -p {port} --flood -c {count} {target_ip}'
        else:
            print(f"{YELLOW}[!] hping3 not found, using ping flood as fallback{NC}")
            cmd = f'ping -f -s 1400 -c {count} {target_ip}'

        src.cmd(cmd + ' &')
        print(f"{GREEN}[+] Attack launched!{NC}")
        print(f"{YELLOW}[*] Watch the dashboard for detection...{NC}")
        return True

    except Exception as e:
        print(f"{RED}[!] Attack failed: {e}{NC}")
        return False


def run_ping_of_death(attacker='h9', target='h1', count=1000):
    """Run oversized ping attack - default attacker is h9"""
    global attack_stats

    if not net:
        print(f"{RED}[!] Network not running{NC}")
        return False

    try:
        src = net.get(attacker)
        dst = net.get(target)
        target_ip = dst.IP()

        print(f"\n{RED}{'=' * 60}{NC}")
        print(f"{RED}  PING OF DEATH ATTACK{NC}")
        print(f"{RED}{'=' * 60}{NC}")
        print(f"  {YELLOW}Attacker:{NC} {attacker} ({src.IP()})")
        print(f"  {YELLOW}Target:{NC}   {target} ({target_ip})")
        print(f"  {YELLOW}Packets:{NC}  {count:,}")
        print(f"  {YELLOW}Size:{NC}     65507 bytes (max)")
        print(f"{RED}{'=' * 60}{NC}")

        attack_stats['current_attack'] = f'Ping of Death: {attacker} -> {target}'
        attack_stats['total_attacks'] += 1
        attack_stats['packets_sent'] += count

        cmd = f'ping -s 65507 -f -c {count} {target_ip}'
        src.cmd(cmd + ' &')
        print(f"{GREEN}[+] Attack launched!{NC}")
        print(f"{YELLOW}[*] Watch the dashboard for detection...{NC}")
        return True

    except Exception as e:
        print(f"{RED}[!] Attack failed: {e}{NC}")
        return False


def run_multi_attack():
    """Run COORDINATED attacks from multiple attacker hosts"""
    global attack_stats

    if not net:
        print(f"{RED}[!] Network not running{NC}")
        return False

    print(f"\n{RED}{'=' * 60}{NC}")
    print(f"{RED}  ███╗   ███╗██╗   ██╗██╗  ████████╗██╗       █████╗ ████████╗████████╗ █████╗  ██████╗██╗  ██╗{NC}")
    print(f"{RED}  ████╗ ████║██║   ██║██║  ╚══██╔══╝██║      ██╔══██╗╚══██╔══╝╚══██╔══╝██╔══██╗██╔════╝██║ ██╔╝{NC}")
    print(f"{RED}  ██╔████╔██║██║   ██║██║     ██║   ██║█████╗███████║   ██║      ██║   ███████║██║     █████╔╝ {NC}")
    print(f"{RED}  ██║╚██╔╝██║██║   ██║██║     ██║   ██║╚════╝██╔══██║   ██║      ██║   ██╔══██║██║     ██╔═██╗ {NC}")
    print(f"{RED}  ██║ ╚═╝ ██║╚██████╔╝███████╗██║   ██║      ██║  ██║   ██║      ██║   ██║  ██║╚██████╗██║  ██╗{NC}")
    print(f"{RED}  ╚═╝     ╚═╝ ╚═════╝ ╚══════╝╚═╝   ╚═╝      ╚═╝  ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝{NC}")
    print(f"{RED}{'=' * 60}{NC}")
    print(f"{RED}  COORDINATED MULTI-VECTOR DDOS ATTACK{NC}")
    print(f"{RED}{'=' * 60}{NC}")
    print(f"  {YELLOW}Attack 1:{NC} h7 -> h1 (ICMP Flood)")
    print(f"  {YELLOW}Attack 2:{NC} h8 -> h2 (ICMP Flood)")
    print(f"  {YELLOW}Attack 3:{NC} h9 -> h3 (Large Ping)")
    print(f"{RED}{'=' * 60}{NC}")

    # Get all hosts
    h1, h2, h3, h7, h8, h9 = net.get('h1', 'h2', 'h3', 'h7', 'h8', 'h9')

    # Launch coordinated attacks from multiple attackers
    print(f"{YELLOW}[*] Launching attack from h7...{NC}")
    h7.cmd(f'ping -f -c 5000 {h1.IP()} &')
    time.sleep(0.5)

    print(f"{YELLOW}[*] Launching attack from h8...{NC}")
    h8.cmd(f'ping -f -c 5000 {h2.IP()} &')
    time.sleep(0.5)

    print(f"{YELLOW}[*] Launching attack from h9...{NC}")
    h9.cmd(f'ping -s 65507 -c 1000 {h3.IP()} &')

    attack_stats['current_attack'] = 'Multi-Vector DDoS Attack'
    attack_stats['total_attacks'] += 3
    attack_stats['packets_sent'] += 11000

    print(f"\n{GREEN}[+] All attacks launched!{NC}")
    print(f"{YELLOW}[*] Watch the dashboard for detection...{NC}")
    return True


def run_scenario_demo():
    """Run a COMPLETE PRESENTATION demo scenario"""
    global attack_stats

    if not net:
        print(f"{RED}[!] Network not running{NC}")
        return False

    print(f"\n{BOLD}{CYAN}{'=' * 70}{NC}")
    print(f"{BOLD}{CYAN}   ____  _____ __  __  ___    ____   ____ _____ _   _    _    ____  ___ {NC}")
    print(f"{BOLD}{CYAN}  |  _ \\| ____|  \\/  |/ _ \\  / ___| / ___| ____| \\ | |  / \\  |  _ \\|_ _|{NC}")
    print(f"{BOLD}{CYAN}  | | | |  _| | |\\/| | | | | \\___ \\| |   |  _| |  \\| | / _ \\ | |_) || | {NC}")
    print(f"{BOLD}{CYAN}  | |_| | |___| |  | | |_| |  ___) | |___| |___| |\\  |/ ___ \\|  _ < | | {NC}")
    print(f"{BOLD}{CYAN}  |____/|_____|_|  |_|\\___/  |____/ \\____|_____|_| \\_/_/   \\_\\_| \\_\\___|{NC}")
    print(f"{BOLD}{CYAN}{'=' * 70}{NC}")
    print(f"\n{BOLD}SecureNet DC - DDoS Detection Demo{NC}")
    print(f"\nThis demo will showcase:")
    print(f"  {GREEN}Phase 1:{NC} Normal traffic baseline")
    print(f"  {YELLOW}Phase 2:{NC} Single attacker detection")
    print(f"  {RED}Phase 3:{NC} Coordinated multi-vector attack")
    print(f"  {CYAN}Phase 4:{NC} Defense and blocking demonstration")
    print(f"{BOLD}{CYAN}{'=' * 70}{NC}")
    print(f"\n{YELLOW}>>> Open the dashboard at http://localhost:5000{NC}")
    print(f"{YELLOW}>>> API endpoint: http://localhost:8080/securenet/ddos/alerts{NC}\n")

    input(f"{CYAN}Press Enter to start the demo...{NC}")

    # Get hosts
    h1, h2, h3, h4, h5, h6, h7, h8, h9 = net.get('h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'h8', 'h9')

    # Phase 1: Normal traffic
    print(f"\n{GREEN}{'=' * 50}{NC}")
    print(f"{GREEN}[PHASE 1/4] NORMAL TRAFFIC BASELINE{NC}")
    print(f"{GREEN}{'=' * 50}{NC}")
    print(f"Generating normal ping traffic between hosts...")
    h1.cmd(f'ping -c 30 {h2.IP()} &')
    h3.cmd(f'ping -c 30 {h7.IP()} &')
    h4.cmd(f'ping -c 30 {h5.IP()} &')
    print(f"{GREEN}[+] Normal traffic flowing...{NC}")
    time.sleep(8)

    # Phase 2: Single attacker
    print(f"\n{YELLOW}{'=' * 50}{NC}")
    print(f"{YELLOW}[PHASE 2/4] SINGLE ATTACKER - h9 -> h1{NC}")
    print(f"{YELLOW}{'=' * 50}{NC}")
    print(f"Launching ICMP flood attack from h9 ({h9.IP()}) to h1 ({h1.IP()})...")
    h9.cmd(f'ping -f -c 10000 {h1.IP()} &')
    attack_stats['total_attacks'] += 1
    attack_stats['packets_sent'] += 10000
    print(f"{RED}[!] Attack in progress - watch the dashboard!{NC}")
    time.sleep(12)

    # Phase 3: Multi-attack
    print(f"\n{RED}{'=' * 50}{NC}")
    print(f"{RED}[PHASE 3/4] COORDINATED MULTI-VECTOR ATTACK{NC}")
    print(f"{RED}{'=' * 50}{NC}")
    print(f"Launching coordinated attacks from h7, h8, h9...")
    h7.cmd(f'ping -f -c 5000 {h1.IP()} &')
    time.sleep(0.3)
    h8.cmd(f'ping -f -c 5000 {h2.IP()} &')
    time.sleep(0.3)
    h9.cmd(f'ping -s 65507 -c 1000 {h3.IP()} &')
    attack_stats['total_attacks'] += 3
    attack_stats['packets_sent'] += 11000
    print(f"{RED}[!] Multiple attacks in progress!{NC}")
    time.sleep(12)

    # Phase 4: Results
    print(f"\n{CYAN}{'=' * 50}{NC}")
    print(f"{CYAN}[PHASE 4/4] DEFENSE RESULTS{NC}")
    print(f"{CYAN}{'=' * 50}{NC}")

    # Query the API for alerts
    try:
        import urllib.request
        import json
        response = urllib.request.urlopen('http://localhost:8080/securenet/ddos/alerts', timeout=5)
        data = json.loads(response.read().decode())

        print(f"\n{GREEN}Detection Summary:{NC}")
        print(f"  Total Attacks Detected: {data.get('total_attacks', 0)}")
        print(f"  Currently Blocked: {data.get('currently_blocked', 0)}")

        if data.get('blocked_ips'):
            print(f"\n{YELLOW}Blocked Attackers:{NC}")
            for ip in data['blocked_ips']:
                print(f"  {RED}✘{NC} {ip}")

        if data.get('alerts'):
            print(f"\n{RED}Recent Alerts:{NC}")
            for alert in data['alerts'][:5]:
                print(f"  [{alert.get('timestamp', '')}] {alert.get('attack_type', '')} from {alert.get('src_ip', '')}")

    except Exception as e:
        print(f"{YELLOW}[*] Could not fetch API data: {e}{NC}")

    print(f"\n{GREEN}{'=' * 50}{NC}")
    print(f"{GREEN}DEMO COMPLETE!{NC}")
    print(f"{GREEN}{'=' * 50}{NC}")
    print(f"\n{CYAN}The dashboard shows real-time attack detection and blocking.{NC}")
    print(f"{CYAN}Attackers (h7, h8, h9) have been identified and blocked.{NC}")

    attack_stats['current_attack'] = None
    return True


# ============== INTERACTIVE MENU ==============

def interactive_menu():
    """Run interactive attack menu"""
    global running

    while running:
        print(f"\n{CYAN}{'=' * 60}{NC}")
        print(f"{CYAN}  SECURENET DC - ATTACK CONTROL CENTER{NC}")
        print(f"{CYAN}{'=' * 60}{NC}")
        print(f"  {BOLD}Network:{NC} 4 switches, 9 hosts (h1-h9)")
        print(f"  {BOLD}Any host can attack any other - detection is automatic{NC}")
        print(f"{CYAN}{'-' * 60}{NC}")
        print(f"  {RED}[1]{NC} ICMP Flood Attack")
        print(f"  {RED}[2]{NC} SYN Flood Attack")
        print(f"  {RED}[3]{NC} UDP Flood Attack")
        print(f"  {RED}[4]{NC} Ping of Death")
        print(f"  {RED}[5]{NC} Multi-Vector Attack (3 hosts)")
        print(f"  {YELLOW}[6]{NC} Run Full Demo Scenario")
        print(f"{CYAN}{'-' * 60}{NC}")
        print(f"  {GREEN}[7]{NC} Test Connectivity (pingall)")
        print(f"  {GREEN}[8]{NC} Show Network Status")
        print(f"  {GREEN}[9]{NC} Open Mininet CLI")
        print(f"  {BOLD}[0]{NC} Exit")
        print(f"{CYAN}{'=' * 60}{NC}")

        try:
            choice = input(f"{YELLOW}Select option: {NC}").strip()
        except EOFError:
            break

        if choice == '0':
            break
        elif choice == '1':
            attacker = input("Attacker host [h9]: ").strip() or 'h9'
            target = input("Target host [h1]: ").strip() or 'h1'
            count = int(input("Packet count [5000]: ").strip() or '5000')
            run_icmp_flood(attacker, target, count)
        elif choice == '2':
            attacker = input("Attacker host [h8]: ").strip() or 'h8'
            target = input("Target host [h1]: ").strip() or 'h1'
            count = int(input("Packet count [3000]: ").strip() or '3000')
            run_syn_flood(attacker, target, count)
        elif choice == '3':
            attacker = input("Attacker host [h7]: ").strip() or 'h7'
            target = input("Target host [h2]: ").strip() or 'h2'
            count = int(input("Packet count [3000]: ").strip() or '3000')
            run_udp_flood(attacker, target, count)
        elif choice == '4':
            attacker = input("Attacker host [h9]: ").strip() or 'h9'
            target = input("Target host [h1]: ").strip() or 'h1'
            count = int(input("Packet count [1000]: ").strip() or '1000')
            run_ping_of_death(attacker, target, count)
        elif choice == '5':
            run_multi_attack()
        elif choice == '6':
            run_scenario_demo()
        elif choice == '7':
            if net:
                print(f"\n{YELLOW}[*] Running pingall...{NC}")
                net.pingAll()
            else:
                print(f"{RED}[!] Network not running{NC}")
        elif choice == '8':
            print_status()
        elif choice == '9':
            if net:
                print(f"\n{YELLOW}[*] Opening Mininet CLI (type 'exit' to return)...{NC}")
                CLI(net)
            else:
                print(f"{RED}[!] Network not running{NC}")


def auto_demo():
    """Run automated demo"""
    print(f"\n{BOLD}{GREEN}Starting Automated Demo...{NC}")
    print(f"{YELLOW}Press Ctrl+C to stop{NC}\n")

    h1, h2, h3, h4 = net.get('h1', 'h2', 'h3', 'h4')

    wave = 1
    try:
        while running:
            print(f"\n{CYAN}[Wave {wave}] Launching attack...{NC}")

            # Alternate attack types
            if wave % 3 == 1:
                run_icmp_flood('h4', 'h1', 5000)
            elif wave % 3 == 2:
                run_multi_attack()
            else:
                run_ping_of_death('h4', 'h1', 1000)

            print(f"{YELLOW}[*] Waiting 15s before next wave...{NC}")
            time.sleep(15)
            wave += 1

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[*] Stopping auto demo{NC}")


# ============== MAIN ==============

def main():
    global running

    parser = argparse.ArgumentParser(
        description='SecureNet DC - Integrated Demo Runner',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('--auto', action='store_true',
                       help='Run automated continuous demo')
    parser.add_argument('--attack', '-a',
                       choices=['icmp', 'syn', 'udp', 'pod', 'multi', 'demo'],
                       help='Run specific attack immediately')
    parser.add_argument('--cli', action='store_true',
                       help='Open Mininet CLI after starting')
    parser.add_argument('--no-services', action='store_true',
                       help='Skip starting stats collector and dashboard')

    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root{NC}")
        print(f"{YELLOW}    Run with: sudo python3 scripts/run_demo.py{NC}")
        sys.exit(1)

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print_banner()

    # Start services
    if not args.no_services:
        start_stats_collector()
        start_dashboard()

    # Start network
    if not start_network():
        print(f"{RED}[!] Failed to start network{NC}")
        cleanup()
        sys.exit(1)

    # Get WSL IP for display
    try:
        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True)
        wsl_ip = result.stdout.strip().split()[0]
    except:
        wsl_ip = 'localhost'

    print(f"\n{GREEN}{'=' * 60}{NC}")
    print(f"{GREEN}SYSTEM READY!{NC}")
    print(f"{GREEN}{'=' * 60}{NC}")
    print(f"  {CYAN}Dashboard:{NC}     http://{wsl_ip}:5000")
    print(f"  {CYAN}Stats API:{NC}     http://{wsl_ip}:8080/securenet/status")
    print(f"  {CYAN}DDoS Alerts:{NC}   http://{wsl_ip}:8080/securenet/ddos/alerts")
    print(f"{GREEN}{'=' * 60}{NC}")

    # Run appropriate mode
    try:
        if args.attack:
            if args.attack == 'icmp':
                run_icmp_flood()
            elif args.attack == 'syn':
                run_syn_flood()
            elif args.attack == 'udp':
                run_udp_flood()
            elif args.attack == 'pod':
                run_ping_of_death()
            elif args.attack == 'multi':
                run_multi_attack()
            elif args.attack == 'demo':
                run_scenario_demo()

            # Keep network running
            print(f"\n{YELLOW}Attack launched. Press Ctrl+C to exit.{NC}")
            while running:
                time.sleep(1)

        elif args.cli:
            print(f"\n{YELLOW}[*] Opening Mininet CLI...{NC}")
            CLI(net)

        elif args.auto:
            auto_demo()

        else:
            interactive_menu()

    except KeyboardInterrupt:
        pass
    finally:
        cleanup()


if __name__ == '__main__':
    main()
