#!/usr/bin/env python3
"""
SecureNet DC - Mininet Runner
Keeps the network alive for dashboard monitoring
"""

import time
import signal
import sys
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.link import TCLink

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

def main():
    setLogLevel('info')

    # Create topology
    topo = TreeTopo(depth=2, fanout=2)

    # Create network with remote controller
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        switch=OVSKernelSwitch,
        autoSetMacs=True
    )

    # Set OpenFlow 1.3
    for switch in net.switches:
        switch.cmd('ovs-vsctl set bridge', switch.name, 'protocols=OpenFlow13')

    def cleanup(sig, frame):
        info('\n*** Stopping network\n')
        net.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    info('*** Starting network\n')
    net.start()

    info('*** Network started with %d switches and %d hosts\n' %
         (len(net.switches), len(net.hosts)))
    info('*** Switches connected to controller at 127.0.0.1:6653\n')
    info('*** Press Ctrl+C to stop\n')

    # Run a quick ping to establish flows
    info('*** Running initial ping test\n')
    net.pingAll(timeout=1)

    # Keep network alive
    info('*** Network running. Dashboard should now show real data.\n')
    while True:
        time.sleep(5)
        # Periodically generate some traffic to keep stats updating
        net.ping([net.hosts[0], net.hosts[-1]], timeout=1)

if __name__ == '__main__':
    main()
