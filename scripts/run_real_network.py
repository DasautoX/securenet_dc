#!/usr/bin/env python3
"""
SecureNet DC - Real Virtual Network Runner
Creates a real virtual network using Mininet with Linux bridges.
Generates continuous traffic for dashboard visualization.
Works in WSL2!
"""

import time
import signal
import sys
import threading
import random
from mininet.net import Mininet
from mininet.node import Controller
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.link import TCLink

class DataCenterTopo(Topo):
    """Simple data center topology for demo."""
    def build(self):
        # Create switches (Linux bridges)
        core = self.addSwitch('s1')
        agg1 = self.addSwitch('s2')
        agg2 = self.addSwitch('s3')
        edge1 = self.addSwitch('s4')
        edge2 = self.addSwitch('s5')

        # Create hosts
        h1 = self.addHost('h1', ip='10.0.1.1/24')
        h2 = self.addHost('h2', ip='10.0.1.2/24')
        h3 = self.addHost('h3', ip='10.0.2.1/24')
        h4 = self.addHost('h4', ip='10.0.2.2/24')
        h5 = self.addHost('h5', ip='10.0.3.1/24')
        h6 = self.addHost('h6', ip='10.0.3.2/24')

        # Core to aggregation
        self.addLink(core, agg1)
        self.addLink(core, agg2)

        # Aggregation to edge
        self.addLink(agg1, edge1)
        self.addLink(agg1, edge2)
        self.addLink(agg2, edge1)
        self.addLink(agg2, edge2)

        # Edge to hosts
        self.addLink(edge1, h1)
        self.addLink(edge1, h2)
        self.addLink(edge1, h3)
        self.addLink(edge2, h4)
        self.addLink(edge2, h5)
        self.addLink(edge2, h6)

def generate_traffic(net, stop_event):
    """Generate continuous traffic between hosts."""
    info('*** Traffic generator started\n')
    hosts = net.hosts

    while not stop_event.is_set():
        try:
            if len(hosts) >= 2:
                # Random ping between hosts
                h1 = random.choice(hosts)
                h2 = random.choice([h for h in hosts if h != h1])
                h1.cmd(f'ping -c 1 -W 1 {h2.IP()} > /dev/null 2>&1 &')

                # Sometimes do iperf for more traffic
                if random.random() < 0.1:
                    h1.cmd(f'iperf -c {h2.IP()} -t 1 -i 1 > /dev/null 2>&1 &')

            time.sleep(0.5)
        except Exception as e:
            if not stop_event.is_set():
                info(f'Traffic generator error: {e}\n')
            break

    info('*** Traffic generator stopped\n')

def main():
    setLogLevel('info')

    info('='*60 + '\n')
    info('SecureNet DC - Real Virtual Network\n')
    info('='*60 + '\n')

    # Create topology
    info('*** Creating Data Center topology\n')
    topo = DataCenterTopo()

    # Create network with Linux bridge switches (works in WSL2!)
    net = Mininet(
        topo=topo,
        switch='lxbr',  # Linux bridge - works in WSL2!
        controller=None,  # No controller needed for Linux bridges
        autoSetMacs=True
    )

    stop_event = threading.Event()

    def cleanup(sig=None, frame=None):
        info('\n*** Stopping network\n')
        stop_event.set()
        try:
            net.stop()
        except:
            pass
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    info('*** Starting network\n')
    net.start()

    info('*** Network topology:\n')
    info(f'    Switches: {len(net.switches)}\n')
    info(f'    Hosts: {len(net.hosts)}\n')
    for h in net.hosts:
        info(f'    - {h.name}: {h.IP()}\n')

    # Run initial ping test
    info('\n*** Running initial connectivity test\n')
    net.pingAll(timeout=2)

    # Start traffic generator
    info('\n*** Starting continuous traffic generator\n')
    traffic_thread = threading.Thread(
        target=generate_traffic,
        args=(net, stop_event),
        daemon=True
    )
    traffic_thread.start()

    info('\n' + '='*60 + '\n')
    info('Network is running with REAL traffic!\n')
    info('Run the stats collector to see data in dashboard:\n')
    info('  python scripts/network_stats_collector.py\n')
    info('='*60 + '\n')
    info('Press Ctrl+C to stop\n\n')

    # Keep running
    while True:
        time.sleep(5)
        # Periodic ping to show activity
        if net.hosts:
            h1 = net.hosts[0]
            h2 = net.hosts[-1]
            result = h1.cmd(f'ping -c 1 -W 1 {h2.IP()}')
            if '1 received' in result:
                info(f'[{time.strftime("%H:%M:%S")}] Traffic flowing: {h1.name} -> {h2.name} OK\n')

if __name__ == '__main__':
    main()
