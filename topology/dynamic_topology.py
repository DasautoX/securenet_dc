#!/usr/bin/env python3
"""
SecureNet DC - Dynamic Topology Generator
==========================================
Creates configurable network topologies with variable size.

Supported topologies:
- tree: Standard tree topology (configurable depth and fanout)
- fat_tree: Data center fat-tree topology (k-ary)
- linear: Simple linear chain
- mesh: Full mesh (for small networks)
- custom: Define your own parameters

Usage in run_demo.py:
    from topology.dynamic_topology import create_topology
    topo = create_topology('fat_tree', k=4)  # 20 switches, 16 hosts
    net = Mininet(topo=topo, ...)

Command line:
    sudo python3 topology/dynamic_topology.py --type fat_tree --k 4
    sudo python3 topology/dynamic_topology.py --type tree --depth 3 --fanout 3
"""

import argparse
import sys

try:
    from mininet.topo import Topo
    from mininet.net import Mininet
    from mininet.nodelib import LinuxBridge
    from mininet.cli import CLI
    from mininet.log import setLogLevel
except ImportError:
    print("[!] Mininet not installed")
    sys.exit(1)


class DynamicTreeTopo(Topo):
    """
    Dynamic tree topology with configurable depth and fanout.

    depth=2, fanout=2: 3 switches, 4 hosts (default)
    depth=3, fanout=2: 7 switches, 8 hosts
    depth=2, fanout=3: 4 switches, 9 hosts
    depth=3, fanout=3: 13 switches, 27 hosts
    """

    def build(self, depth=2, fanout=2):
        self.host_count = 0
        self.switch_count = 0
        self.host_ip_base = 1

        # Build tree recursively
        self._add_tree(depth, fanout, None)

        print(f"[Topology] Tree: depth={depth}, fanout={fanout}")
        print(f"           Switches: {self.switch_count}, Hosts: {self.host_count}")

    def _add_tree(self, depth, fanout, parent):
        """Recursively build tree structure"""
        self.switch_count += 1
        switch_name = f's{self.switch_count}'
        self.addSwitch(switch_name)

        if parent:
            self.addLink(parent, switch_name)

        if depth == 1:
            # Leaf level - add hosts
            for i in range(fanout):
                self.host_count += 1
                host_name = f'h{self.host_count}'
                host_ip = f'10.0.0.{self.host_ip_base}'
                self.host_ip_base += 1
                self.addHost(host_name, ip=host_ip)
                self.addLink(switch_name, host_name)
        else:
            # Internal node - add child switches
            for i in range(fanout):
                self._add_tree(depth - 1, fanout, switch_name)


class FatTreeTopo(Topo):
    """
    Fat-tree data center topology.

    k=4: 20 switches (4 core, 8 aggregation, 8 edge), 16 hosts
    k=6: 45 switches, 54 hosts
    k=8: 80 switches, 128 hosts

    Structure:
    - k pods
    - Each pod has k/2 aggregation switches and k/2 edge switches
    - Each edge switch connects to k/2 hosts
    - k^2/4 core switches
    """

    def build(self, k=4):
        if k % 2 != 0:
            raise ValueError("k must be even for fat-tree topology")

        self.k = k
        self.core_switches = []
        self.agg_switches = []
        self.edge_switches = []
        self.hosts = []
        self.host_count = 0

        # Create core switches: (k/2)^2 total
        num_core = (k // 2) ** 2
        for i in range(num_core):
            sw = self.addSwitch(f'c{i+1}')  # c1, c2, ...
            self.core_switches.append(sw)

        # Create pods
        for pod in range(k):
            pod_agg = []
            pod_edge = []

            # Aggregation switches for this pod
            for i in range(k // 2):
                sw_id = pod * (k // 2) + i + 1
                sw = self.addSwitch(f'a{sw_id}')  # a1, a2, ...
                pod_agg.append(sw)
                self.agg_switches.append(sw)

            # Edge switches for this pod
            for i in range(k // 2):
                sw_id = pod * (k // 2) + i + 1
                sw = self.addSwitch(f'e{sw_id}')  # e1, e2, ...
                pod_edge.append(sw)
                self.edge_switches.append(sw)

            # Connect aggregation to edge (within pod)
            for agg in pod_agg:
                for edge in pod_edge:
                    self.addLink(agg, edge)

            # Connect hosts to edge switches
            for edge_idx, edge in enumerate(pod_edge):
                for h in range(k // 2):
                    self.host_count += 1
                    host_name = f'h{self.host_count}'
                    # IP scheme: 10.pod.edge.host
                    host_ip = f'10.{pod}.{edge_idx}.{h+1}'
                    self.addHost(host_name, ip=host_ip)
                    self.hosts.append(host_name)
                    self.addLink(edge, host_name)

            # Connect aggregation to core
            for agg_idx, agg in enumerate(pod_agg):
                # Each agg switch connects to k/2 core switches
                for core_idx in range(k // 2):
                    core_sw = self.core_switches[agg_idx * (k // 2) + core_idx]
                    self.addLink(agg, core_sw)

        print(f"[Topology] Fat-Tree: k={k}")
        print(f"           Core: {len(self.core_switches)}, Agg: {len(self.agg_switches)}, Edge: {len(self.edge_switches)}")
        print(f"           Total Switches: {len(self.core_switches) + len(self.agg_switches) + len(self.edge_switches)}")
        print(f"           Hosts: {self.host_count}")


class LinearTopo(Topo):
    """
    Simple linear topology with configurable number of hosts.

    n=4: 3 switches, 4 hosts
    n=8: 7 switches, 8 hosts

    h1 -- s1 -- s2 -- s3 -- ... -- sN -- hN
           |    |    |
          h2   h3   h4
    """

    def build(self, n=4):
        prev_switch = None

        for i in range(n):
            host_name = f'h{i+1}'
            host_ip = f'10.0.0.{i+1}'
            self.addHost(host_name, ip=host_ip)

            if i < n - 1:  # Not the last host
                switch_name = f's{i+1}'
                self.addSwitch(switch_name)
                self.addLink(host_name, switch_name)

                if prev_switch:
                    self.addLink(prev_switch, switch_name)
                prev_switch = switch_name
            else:  # Last host connects to last switch
                self.addLink(host_name, prev_switch)

        print(f"[Topology] Linear: {n} hosts, {n-1} switches")


class SpineLeafTopo(Topo):
    """
    Modern data center spine-leaf topology.

    spine=2, leaf=4, hosts_per_leaf=4: 6 switches, 16 hosts

    All spine switches connect to all leaf switches.
    Each leaf switch connects to a set of hosts.
    """

    def build(self, spine_count=2, leaf_count=4, hosts_per_leaf=4):
        spine_switches = []
        leaf_switches = []
        host_count = 0

        # Create spine switches
        for i in range(spine_count):
            sw = self.addSwitch(f'spine{i+1}')
            spine_switches.append(sw)

        # Create leaf switches and hosts
        for i in range(leaf_count):
            leaf_sw = self.addSwitch(f'leaf{i+1}')
            leaf_switches.append(leaf_sw)

            # Connect leaf to all spines
            for spine in spine_switches:
                self.addLink(leaf_sw, spine)

            # Add hosts to this leaf
            for h in range(hosts_per_leaf):
                host_count += 1
                host_name = f'h{host_count}'
                host_ip = f'10.{i}.0.{h+1}'
                self.addHost(host_name, ip=host_ip)
                self.addLink(host_name, leaf_sw)

        print(f"[Topology] Spine-Leaf: {spine_count} spine, {leaf_count} leaf")
        print(f"           Switches: {spine_count + leaf_count}, Hosts: {host_count}")


class DataCenterTopo(Topo):
    """
    Enterprise data center topology with different zones.

    Zones:
    - Web servers (DMZ)
    - Application servers
    - Database servers
    - Management

    Each zone has its own edge switch.
    """

    def build(self, web_hosts=4, app_hosts=4, db_hosts=2, mgmt_hosts=2):
        # Core switch
        core = self.addSwitch('core1')

        # Distribution switches
        dist1 = self.addSwitch('dist1')
        dist2 = self.addSwitch('dist2')
        self.addLink(core, dist1)
        self.addLink(core, dist2)
        self.addLink(dist1, dist2)  # Redundancy

        # Zone switches
        web_sw = self.addSwitch('web_sw')
        app_sw = self.addSwitch('app_sw')
        db_sw = self.addSwitch('db_sw')
        mgmt_sw = self.addSwitch('mgmt_sw')

        self.addLink(dist1, web_sw)
        self.addLink(dist1, app_sw)
        self.addLink(dist2, db_sw)
        self.addLink(dist2, mgmt_sw)

        host_count = 0

        # Web servers (DMZ)
        for i in range(web_hosts):
            host_count += 1
            h = self.addHost(f'web{i+1}', ip=f'10.1.0.{i+1}')
            self.addLink(h, web_sw)

        # App servers
        for i in range(app_hosts):
            host_count += 1
            h = self.addHost(f'app{i+1}', ip=f'10.2.0.{i+1}')
            self.addLink(h, app_sw)

        # Database servers
        for i in range(db_hosts):
            host_count += 1
            h = self.addHost(f'db{i+1}', ip=f'10.3.0.{i+1}')
            self.addLink(h, db_sw)

        # Management hosts (including attacker for demo)
        for i in range(mgmt_hosts):
            host_count += 1
            h = self.addHost(f'mgmt{i+1}', ip=f'10.4.0.{i+1}')
            self.addLink(h, mgmt_sw)

        print(f"[Topology] DataCenter: 7 switches, {host_count} hosts")
        print(f"           Zones: Web({web_hosts}), App({app_hosts}), DB({db_hosts}), Mgmt({mgmt_hosts})")


def create_topology(topo_type='tree', **kwargs):
    """
    Factory function to create topology by type.

    Args:
        topo_type: 'tree', 'fat_tree', 'linear', 'spine_leaf', 'datacenter'
        **kwargs: Topology-specific parameters

    Returns:
        Topo object ready to use with Mininet
    """
    if topo_type == 'tree':
        depth = kwargs.get('depth', 2)
        fanout = kwargs.get('fanout', 2)
        return DynamicTreeTopo(depth=depth, fanout=fanout)

    elif topo_type == 'fat_tree':
        k = kwargs.get('k', 4)
        return FatTreeTopo(k=k)

    elif topo_type == 'linear':
        n = kwargs.get('n', 4)
        return LinearTopo(n=n)

    elif topo_type == 'spine_leaf':
        spine = kwargs.get('spine', 2)
        leaf = kwargs.get('leaf', 4)
        hosts_per_leaf = kwargs.get('hosts_per_leaf', 4)
        return SpineLeafTopo(spine_count=spine, leaf_count=leaf, hosts_per_leaf=hosts_per_leaf)

    elif topo_type == 'datacenter':
        web = kwargs.get('web', 4)
        app = kwargs.get('app', 4)
        db = kwargs.get('db', 2)
        mgmt = kwargs.get('mgmt', 2)
        return DataCenterTopo(web_hosts=web, app_hosts=app, db_hosts=db, mgmt_hosts=mgmt)

    else:
        raise ValueError(f"Unknown topology type: {topo_type}")


def get_topology_info(topo_type, **kwargs):
    """Get info about a topology without creating it."""
    info = {
        'tree': {
            'description': 'Hierarchical tree topology',
            'params': ['depth', 'fanout'],
            'default': {'depth': 2, 'fanout': 2},
            'examples': [
                {'depth': 2, 'fanout': 2, 'switches': 3, 'hosts': 4},
                {'depth': 3, 'fanout': 2, 'switches': 7, 'hosts': 8},
                {'depth': 2, 'fanout': 4, 'switches': 5, 'hosts': 16},
            ]
        },
        'fat_tree': {
            'description': 'Data center fat-tree (Clos) topology',
            'params': ['k'],
            'default': {'k': 4},
            'examples': [
                {'k': 4, 'switches': 20, 'hosts': 16},
                {'k': 6, 'switches': 45, 'hosts': 54},
                {'k': 8, 'switches': 80, 'hosts': 128},
            ]
        },
        'spine_leaf': {
            'description': 'Modern spine-leaf data center topology',
            'params': ['spine', 'leaf', 'hosts_per_leaf'],
            'default': {'spine': 2, 'leaf': 4, 'hosts_per_leaf': 4},
            'examples': [
                {'spine': 2, 'leaf': 4, 'hosts_per_leaf': 4, 'switches': 6, 'hosts': 16},
                {'spine': 4, 'leaf': 8, 'hosts_per_leaf': 4, 'switches': 12, 'hosts': 32},
            ]
        },
        'datacenter': {
            'description': 'Enterprise DC with zone segmentation',
            'params': ['web', 'app', 'db', 'mgmt'],
            'default': {'web': 4, 'app': 4, 'db': 2, 'mgmt': 2},
            'examples': [
                {'web': 4, 'app': 4, 'db': 2, 'mgmt': 2, 'switches': 7, 'hosts': 12},
            ]
        },
        'linear': {
            'description': 'Simple linear chain topology',
            'params': ['n'],
            'default': {'n': 4},
            'examples': [
                {'n': 4, 'switches': 3, 'hosts': 4},
                {'n': 8, 'switches': 7, 'hosts': 8},
            ]
        }
    }
    return info.get(topo_type, {})


def main():
    parser = argparse.ArgumentParser(
        description='SecureNet DC - Dynamic Topology Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --type tree --depth 2 --fanout 2    # 3 switches, 4 hosts
  %(prog)s --type tree --depth 3 --fanout 3    # 13 switches, 27 hosts
  %(prog)s --type fat_tree --k 4               # 20 switches, 16 hosts
  %(prog)s --type fat_tree --k 6               # 45 switches, 54 hosts
  %(prog)s --type spine_leaf                   # 6 switches, 16 hosts
  %(prog)s --type datacenter                   # 7 switches, 12 hosts
  %(prog)s --list                              # Show available topologies
        """
    )
    parser.add_argument('--type', '-t', default='tree',
                       choices=['tree', 'fat_tree', 'linear', 'spine_leaf', 'datacenter'],
                       help='Topology type')
    parser.add_argument('--depth', type=int, default=2, help='Tree depth')
    parser.add_argument('--fanout', type=int, default=2, help='Tree fanout')
    parser.add_argument('--k', type=int, default=4, help='Fat-tree k parameter')
    parser.add_argument('--n', type=int, default=4, help='Linear topology host count')
    parser.add_argument('--spine', type=int, default=2, help='Spine switch count')
    parser.add_argument('--leaf', type=int, default=4, help='Leaf switch count')
    parser.add_argument('--hosts-per-leaf', type=int, default=4, help='Hosts per leaf')
    parser.add_argument('--web', type=int, default=4, help='Web server count')
    parser.add_argument('--app', type=int, default=4, help='App server count')
    parser.add_argument('--db', type=int, default=2, help='DB server count')
    parser.add_argument('--mgmt', type=int, default=2, help='Management host count')
    parser.add_argument('--list', '-l', action='store_true', help='List available topologies')
    parser.add_argument('--cli', action='store_true', help='Start Mininet CLI')

    args = parser.parse_args()

    if args.list:
        print("\n" + "=" * 60)
        print("Available Topologies:")
        print("=" * 60)
        for topo_type in ['tree', 'fat_tree', 'spine_leaf', 'datacenter', 'linear']:
            info = get_topology_info(topo_type)
            print(f"\n{topo_type}:")
            print(f"  {info['description']}")
            print(f"  Parameters: {', '.join(info['params'])}")
            print(f"  Examples:")
            for ex in info['examples']:
                print(f"    {ex}")
        print("\n" + "=" * 60)
        return

    setLogLevel('warning')

    # Build kwargs based on topology type
    kwargs = {}
    if args.type == 'tree':
        kwargs = {'depth': args.depth, 'fanout': args.fanout}
    elif args.type == 'fat_tree':
        kwargs = {'k': args.k}
    elif args.type == 'linear':
        kwargs = {'n': args.n}
    elif args.type == 'spine_leaf':
        kwargs = {'spine': args.spine, 'leaf': args.leaf, 'hosts_per_leaf': args.hosts_per_leaf}
    elif args.type == 'datacenter':
        kwargs = {'web': args.web, 'app': args.app, 'db': args.db, 'mgmt': args.mgmt}

    print("=" * 60)
    print("SecureNet DC - Dynamic Topology Generator")
    print("=" * 60)

    topo = create_topology(args.type, **kwargs)

    print("\nCreating Mininet network...")
    net = Mininet(topo=topo, controller=None, switch=LinuxBridge)
    net.start()

    print(f"\nNetwork started successfully!")
    print(f"Switches: {[s.name for s in net.switches]}")
    print(f"Hosts: {[h.name for h in net.hosts]}")

    print("\nTesting connectivity...")
    net.pingAll()

    if args.cli:
        print("\nStarting CLI (type 'exit' to quit)...")
        CLI(net)

    net.stop()
    print("\nNetwork stopped.")


if __name__ == '__main__':
    main()
