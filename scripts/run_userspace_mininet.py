#!/usr/bin/env python3
"""
SecureNet DC - User-Space Mininet Runner
Uses user-space switches instead of OVS kernel switches.
This works in WSL2 where OVS kernel module has issues.
"""

import time
import signal
import sys
import threading
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, UserSwitch, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
from mininet.cli import CLI


class TreeTopo(Topo):
    """Simple tree topology for testing."""
    def build(self, depth=2, fanout=2):
        self.hostNum = 1
        self.switchNum = 1
        self.addTree(depth, fanout, None)

    def addTree(self, depth, fanout, parent):
        switch = self.addSwitch('s%d' % self.switchNum)
        self.switchNum += 1

        if parent:
            self.addLink(switch, parent)

        if depth > 1:
            for i in range(fanout):
                self.addTree(depth - 1, fanout, switch)
        else:
            for i in range(fanout):
                host = self.addHost('h%d' % self.hostNum)
                self.hostNum += 1
                self.addLink(host, switch)


def generate_traffic(net, stop_event):
    """Generate continuous traffic to keep stats updating."""
    info('*** Traffic generator started\n')
    hosts = net.hosts
    while not stop_event.is_set():
        try:
            if len(hosts) >= 2:
                # Ping between random hosts
                h1, h2 = hosts[0], hosts[-1]
                h1.cmd('ping -c 1 -W 1 %s &' % h2.IP())
            time.sleep(2)
        except Exception as e:
            if not stop_event.is_set():
                error('Traffic generator error: %s\n' % e)
            break
    info('*** Traffic generator stopped\n')


def main():
    setLogLevel('info')

    # Try OVS first with user-space datapath, fall back to UserSwitch
    info('*** Creating topology\n')
    topo = TreeTopo(depth=2, fanout=2)

    # Try different switch configurations
    switch_configs = [
        # Option 1: OVS with user-space datapath (no kernel module needed)
        ('OVS-UserSpace', lambda: OVSSwitch, {'datapath': 'user'}),
        # Option 2: Pure user-space switch (reference implementation)
        ('UserSwitch', lambda: UserSwitch, {}),
    ]

    net = None
    for name, switch_cls, switch_opts in switch_configs:
        try:
            info('*** Trying %s configuration\n' % name)

            net = Mininet(
                topo=topo,
                controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
                switch=switch_cls(),
                autoSetMacs=True,
                waitConnected=True
            )

            # Configure switches
            for switch in net.switches:
                for opt, val in switch_opts.items():
                    if hasattr(switch, opt):
                        setattr(switch, opt, val)

            info('*** Starting network with %s\n' % name)
            net.start()

            # Wait for controller connection
            info('*** Waiting for switches to connect to controller...\n')
            time.sleep(3)

            # Check if switches connected
            connected = True
            for switch in net.switches:
                if hasattr(switch, 'connected') and not switch.connected():
                    connected = False
                    break

            if connected:
                info('*** %s configuration successful!\n' % name)
                break
            else:
                info('*** %s: Switches not connected, trying next option\n' % name)
                net.stop()
                net = None

        except Exception as e:
            error('*** %s failed: %s\n' % (name, e))
            if net:
                try:
                    net.stop()
                except:
                    pass
                net = None
            continue

    if not net:
        error('*** All switch configurations failed!\n')
        error('*** Falling back to simple OVS with default settings\n')

        try:
            net = Mininet(
                topo=topo,
                controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
                switch=OVSSwitch,
                autoSetMacs=True
            )
            net.start()
        except Exception as e:
            error('*** Final fallback failed: %s\n' % e)
            sys.exit(1)

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

    info('*** Network started with %d switches and %d hosts\n' %
         (len(net.switches), len(net.hosts)))
    info('*** Switches connected to controller at 127.0.0.1:6653\n')

    # Run initial ping test
    info('*** Running initial connectivity test\n')
    net.pingAll(timeout=2)

    # Start traffic generator thread
    traffic_thread = threading.Thread(target=generate_traffic, args=(net, stop_event), daemon=True)
    traffic_thread.start()

    info('*** Network running. Dashboard should show REAL data now.\n')
    info('*** Press Ctrl+C to stop or type CLI commands:\n')

    # Enter CLI for interactive use
    CLI(net)

    # Cleanup on CLI exit
    cleanup()


if __name__ == '__main__':
    main()
