#!/usr/bin/env python3
"""
SecureNet DC - Fat-Tree Data Center Topology
CPEG 460 Bonus Project

This module creates a k=4 Fat-Tree topology representing an enterprise
data center with:
- 4 Core switches
- 8 Aggregation switches (2 per pod)
- 8 Edge/ToR switches (2 per pod)
- 16 Hosts organized into functional groups

The topology supports OpenFlow 1.3 and connects to a remote SDN controller.
"""

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import Controller, RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error
from mininet.link import TCLink
import sys
import os

# Add parent directory to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from topology.network_config import NetworkConfig
except ImportError:
    from network_config import NetworkConfig


class FatTreeDataCenter(Topo):
    """
    Fat-Tree (Clos) topology for data center networks.

    With k=4:
    - (k/2)^2 = 4 core switches
    - k pods, each with k/2=2 aggregation and k/2=2 edge switches
    - Each edge switch connects to k/2=2 hosts
    - Total: 4 core + 8 agg + 8 edge = 20 switches, 16 hosts

    This provides full bisection bandwidth and multiple paths for redundancy.
    """

    def __init__(self, k=4, **opts):
        """
        Initialize Fat-Tree topology.

        Args:
            k: Fat-tree parameter (must be even). Default is 4.
        """
        self.k = k
        self.pod_count = k
        self.core_count = (k // 2) ** 2
        self.agg_per_pod = k // 2
        self.edge_per_pod = k // 2
        self.hosts_per_edge = k // 2

        # Storage for created nodes
        self.core_switches = []
        self.agg_switches = []
        self.edge_switches = []
        self.hosts_list = []

        # Call parent constructor
        Topo.__init__(self, **opts)

    def build(self):
        """Build the Fat-Tree topology."""
        info('*** Building Fat-Tree Data Center Topology\n')
        info(f'*** k={self.k}: {self.core_count} core, '
             f'{self.pod_count * self.agg_per_pod} agg, '
             f'{self.pod_count * self.edge_per_pod} edge switches\n')

        self._create_core_switches()
        self._create_pods()
        self._connect_pods_to_core()

        info(f'*** Topology complete: {len(self.switches())} switches, '
             f'{len(self.hosts())} hosts\n')

    def _create_core_switches(self):
        """Create core layer switches."""
        info('*** Creating core switches\n')
        for i in range(self.core_count):
            # DPID format: 01XXYY where XX=01 (core), YY=switch number
            dpid = f'00000000000001{i+1:02d}'
            switch = self.addSwitch(
                f'c{i+1}',
                dpid=dpid,
                protocols=NetworkConfig.OPENFLOW_VERSION
            )
            self.core_switches.append(switch)
            info(f'    Core switch c{i+1} (dpid={dpid})\n')

    def _create_pods(self):
        """Create pod structures with aggregation, edge switches, and hosts."""
        info('*** Creating pods\n')

        host_counter = 1
        config = NetworkConfig

        for pod in range(self.pod_count):
            info(f'  * Pod {pod}\n')
            pod_agg = []
            pod_edge = []

            # Create aggregation switches for this pod
            for agg in range(self.agg_per_pod):
                agg_num = pod * self.agg_per_pod + agg + 1
                dpid = f'00000000000002{agg_num:02d}'
                switch = self.addSwitch(
                    f'a{agg_num}',
                    dpid=dpid,
                    protocols=NetworkConfig.OPENFLOW_VERSION
                )
                pod_agg.append(switch)
                self.agg_switches.append(switch)
                info(f'    Aggregation switch a{agg_num}\n')

            # Create edge switches for this pod
            for edge in range(self.edge_per_pod):
                edge_num = pod * self.edge_per_pod + edge + 1
                dpid = f'00000000000003{edge_num:02d}'
                switch = self.addSwitch(
                    f'e{edge_num}',
                    dpid=dpid,
                    protocols=NetworkConfig.OPENFLOW_VERSION
                )
                pod_edge.append(switch)
                self.edge_switches.append(switch)
                info(f'    Edge switch e{edge_num}\n')

            # Connect aggregation to edge (full mesh within pod)
            for agg_sw in pod_agg:
                for edge_sw in pod_edge:
                    self.addLink(
                        agg_sw, edge_sw,
                        bw=config.AGG_LINK_BW,
                        delay=config.AGG_LINK_DELAY
                    )

            # Create hosts and connect to edge switches
            for edge_idx, edge_sw in enumerate(pod_edge):
                for h in range(self.hosts_per_edge):
                    hostname = f'h{host_counter}'
                    ip = config.get_host_ip(hostname)

                    if ip:
                        host = self.addHost(
                            hostname,
                            ip=f'{ip}/24'
                        )
                    else:
                        # Fallback IP scheme if not in config
                        ip = f'10.{pod}.{edge_idx}.{h+1}'
                        host = self.addHost(
                            hostname,
                            ip=f'{ip}/24'
                        )

                    self.hosts_list.append(host)
                    self.addLink(
                        host, edge_sw,
                        bw=config.EDGE_LINK_BW,
                        delay=config.EDGE_LINK_DELAY
                    )
                    info(f'    Host {hostname} ({ip}) -> {edge_sw}\n')
                    host_counter += 1

    def _connect_pods_to_core(self):
        """Connect aggregation switches to core switches."""
        info('*** Connecting pods to core\n')
        config = NetworkConfig

        # Each aggregation switch at index i in its pod connects to
        # core switches [i*(k/2), i*(k/2) + k/2)
        for pod in range(self.pod_count):
            for agg in range(self.agg_per_pod):
                agg_sw = self.agg_switches[pod * self.agg_per_pod + agg]

                # Determine which core switches this agg connects to
                core_start = agg * (self.k // 2)
                for c in range(self.k // 2):
                    core_idx = core_start + c
                    if core_idx < len(self.core_switches):
                        core_sw = self.core_switches[core_idx]
                        self.addLink(
                            agg_sw, core_sw,
                            bw=config.CORE_LINK_BW,
                            delay=config.CORE_LINK_DELAY
                        )
                        info(f'    {agg_sw} <-> {core_sw}\n')


def create_network(remote_controller=True, controller_ip='127.0.0.1',
                   controller_port=6653):
    """
    Create and return the Mininet network with Fat-Tree topology.

    Args:
        remote_controller: If True, use remote SDN controller
        controller_ip: IP address of remote controller
        controller_port: Port of remote controller

    Returns:
        Mininet network object
    """
    setLogLevel('info')

    info('\n')
    info('=' * 60 + '\n')
    info('  SecureNet DC - Fat-Tree Data Center\n')
    info('  CPEG 460 Bonus Project\n')
    info('=' * 60 + '\n\n')

    # Create topology
    topo = FatTreeDataCenter(k=NetworkConfig.FAT_TREE_K)

    # Create network
    if remote_controller:
        info(f'*** Using remote controller at {controller_ip}:{controller_port}\n')
        net = Mininet(
            topo=topo,
            controller=lambda name: RemoteController(
                name,
                ip=controller_ip,
                port=controller_port
            ),
            switch=OVSKernelSwitch,
            link=TCLink,
            autoSetMacs=True
        )
    else:
        info('*** Using default controller\n')
        net = Mininet(
            topo=topo,
            controller=Controller,
            switch=OVSKernelSwitch,
            link=TCLink,
            autoSetMacs=True
        )

    return net


def configure_qos(net):
    """
    Configure QoS queues on all switches.

    This sets up HTB (Hierarchical Token Bucket) queues for
    traffic prioritization.
    """
    info('\n*** Configuring QoS queues on switches\n')

    config = NetworkConfig

    for switch in net.switches:
        for intf in switch.intfList():
            if intf.name != 'lo' and intf.link:
                # Create QoS configuration for this interface
                queues_str = ' '.join([
                    f'queues:{qid}=@q{qid}'
                    for qid in config.QOS_QUEUES.keys()
                ])

                queue_defs = ' '.join([
                    f'-- --id=@q{qid} create Queue '
                    f'other-config:min-rate={q["min_rate"]} '
                    f'other-config:max-rate={q["max_rate"]}'
                    for qid, q in config.QOS_QUEUES.items()
                ])

                cmd = (
                    f'ovs-vsctl -- set Port {intf.name} qos=@newqos '
                    f'-- --id=@newqos create QoS type=linux-htb '
                    f'other-config:max-rate=100000000 '
                    f'{queues_str} {queue_defs}'
                )

                try:
                    switch.cmd(cmd)
                    info(f'    QoS configured on {intf.name}\n')
                except Exception as e:
                    error(f'    Error configuring QoS on {intf.name}: {e}\n')


def start_host_services(net):
    """
    Start services on hosts based on their roles.
    """
    info('\n*** Starting host services\n')

    config = NetworkConfig

    # Start web servers on h1-h4
    for i in range(1, 5):
        host = net.get(f'h{i}')
        if host:
            host.cmd('python3 -m http.server 80 &')
            info(f'    h{i}: HTTP server started on port 80\n')

    # Start iperf servers for testing
    for i in range(5, 7):
        host = net.get(f'h{i}')
        if host:
            host.cmd('iperf3 -s -D')
            info(f'    h{i}: iperf3 server started\n')

    # Video streaming placeholder on h15-h16
    for i in range(15, 17):
        host = net.get(f'h{i}')
        if host:
            # Using iperf UDP as video stream simulator
            host.cmd('iperf3 -s -D')
            info(f'    h{i}: Streaming server (iperf3) started\n')


def print_network_info(net):
    """Print detailed network information."""
    info('\n')
    info('=' * 60 + '\n')
    info('  Network Information\n')
    info('=' * 60 + '\n')

    info('\n*** Switches:\n')
    for sw in net.switches:
        info(f'    {sw.name}: dpid={sw.dpid}\n')

    info('\n*** Hosts:\n')
    config = NetworkConfig
    for host in net.hosts:
        group = config.get_host_group(host.name)
        ip = host.IP()
        info(f'    {host.name}: {ip} ({group})\n')

    info('\n*** Host Groups:\n')
    for group_name, group in config.HOST_GROUPS.items():
        info(f'    {group_name}: {group["description"]}\n')
        for hostname in group['hosts']:
            info(f'        - {hostname} ({config.get_host_ip(hostname)})\n')

    info('\n')


def run_interactive():
    """Run the network in interactive mode with CLI."""
    net = create_network(remote_controller=False)

    try:
        net.start()
        print_network_info(net)

        info('*** Testing connectivity\n')
        net.pingAll()

        info('\n*** Starting CLI\n')
        info('*** Type "help" for available commands\n')
        info('*** Type "exit" or Ctrl+D to quit\n\n')

        CLI(net)

    finally:
        info('*** Stopping network\n')
        net.stop()


def run_with_controller(controller_ip='127.0.0.1', controller_port=6653,
                        enable_qos=True, start_services=True):
    """
    Run the network with remote SDN controller.

    Args:
        controller_ip: IP of the SDN controller
        controller_port: Port of the SDN controller
        enable_qos: Whether to configure QoS queues
        start_services: Whether to start host services
    """
    net = create_network(
        remote_controller=True,
        controller_ip=controller_ip,
        controller_port=controller_port
    )

    try:
        net.start()
        print_network_info(net)

        if enable_qos:
            configure_qos(net)

        if start_services:
            start_host_services(net)

        info('*** Testing connectivity\n')
        net.pingAll()

        info('\n*** Starting CLI\n')
        info('*** Controller should be running at '
             f'{controller_ip}:{controller_port}\n')
        info('*** Type "exit" or Ctrl+D to quit\n\n')

        CLI(net)

    finally:
        info('*** Stopping network\n')
        net.stop()


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(
        description='SecureNet DC - Fat-Tree Data Center Topology'
    )
    parser.add_argument(
        '--remote', '-r',
        action='store_true',
        help='Use remote SDN controller'
    )
    parser.add_argument(
        '--controller-ip', '-c',
        default='127.0.0.1',
        help='Remote controller IP (default: 127.0.0.1)'
    )
    parser.add_argument(
        '--controller-port', '-p',
        type=int,
        default=6653,
        help='Remote controller port (default: 6653)'
    )
    parser.add_argument(
        '--no-qos',
        action='store_true',
        help='Disable QoS configuration'
    )
    parser.add_argument(
        '--no-services',
        action='store_true',
        help='Do not start host services'
    )

    args = parser.parse_args()

    if args.remote:
        run_with_controller(
            controller_ip=args.controller_ip,
            controller_port=args.controller_port,
            enable_qos=not args.no_qos,
            start_services=not args.no_services
        )
    else:
        run_interactive()
