#!/usr/bin/env python3
"""
SecureNet DC - Lab Experiment Runner
CPEG 460 Bonus Project

Simplified runner for the student lab experiment.
Starts the network in a guided mode for following lab instructions.
"""

import os
import sys
import time
import argparse

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from mininet.log import setLogLevel, info
from mininet.cli import CLI


def print_banner():
    """Print experiment banner."""
    print("\n" + "=" * 70)
    print("  SecureNet DC - Lab Experiment")
    print("  Building and Defending a Software-Defined Data Center Network")
    print("  CPEG 460 - Computer Networks")
    print("=" * 70)


def print_lab_menu():
    """Print lab part menu."""
    print("\n*** Lab Parts ***")
    print("  1. Topology Exploration")
    print("  2. SDN Controller Basics")
    print("  3. Load Balancer Testing")
    print("  4. DDoS Attack and Defense")
    print("  5. QoS Configuration")
    print("  6. Performance Analysis")
    print("  7. Full Interactive Mode")
    print("  0. Exit")


def run_part1_topology(net):
    """Part 1: Topology Exploration."""
    print("\n" + "=" * 50)
    print("  Part 1: Topology Exploration")
    print("=" * 50)

    print("\n*** Network Information ***")
    print(f"Switches: {len(net.switches)}")
    print(f"Hosts: {len(net.hosts)}")

    print("\n*** Switch List ***")
    for sw in net.switches:
        print(f"  {sw.name} (dpid: {sw.dpid})")

    print("\n*** Host List ***")
    for host in net.hosts:
        print(f"  {host.name}: {host.IP()}")

    print("\n*** Testing Connectivity ***")
    net.pingAll()

    print("\n*** Instructions ***")
    print("1. Use 'nodes' to see all network nodes")
    print("2. Use 'net' to see network connections")
    print("3. Use 'dump' to see detailed node info")
    print("4. Use 'pingall' to test connectivity")
    print("\nType 'exit' to return to menu\n")

    CLI(net)


def run_part2_controller(net):
    """Part 2: SDN Controller Basics."""
    print("\n" + "=" * 50)
    print("  Part 2: SDN Controller Basics")
    print("=" * 50)

    print("\n*** Instructions ***")
    print("1. Check flow tables: sh ovs-ofctl dump-flows s1")
    print("2. Watch packet-in events in controller terminal")
    print("3. Generate traffic: h1 ping h16")
    print("4. Observe new flow rules being installed")
    print("\nType 'exit' to return to menu\n")

    CLI(net)


def run_part3_loadbalancer(net):
    """Part 3: Load Balancer Testing."""
    print("\n" + "=" * 50)
    print("  Part 3: Load Balancer Testing")
    print("=" * 50)

    print("\n*** Load Balancer Configuration ***")
    print("VIP: 10.0.0.100")
    print("Server Pool: h1 (10.0.1.1), h2 (10.0.1.2), h3 (10.0.1.3), h4 (10.0.1.4)")

    print("\n*** Starting Web Servers ***")
    for i in range(1, 5):
        net.get(f'h{i}').cmd('python3 -m http.server 80 &')
        print(f"  h{i}: Web server started")

    print("\n*** Instructions ***")
    print("1. From a client, access the VIP:")
    print("   h7 curl http://10.0.0.100/")
    print("2. Run multiple requests and observe distribution:")
    print("   h7 for i in $(seq 1 10); do curl -s http://10.0.0.100/ | head -1; done")
    print("3. Check controller logs for load balancing decisions")
    print("\nType 'exit' to return to menu\n")

    CLI(net)


def run_part4_ddos(net):
    """Part 4: DDoS Attack and Defense."""
    print("\n" + "=" * 50)
    print("  Part 4: DDoS Attack and Defense")
    print("=" * 50)

    print("\n*** Attack Simulation Setup ***")
    print("Attacker: h13 (10.0.4.1)")
    print("Target: h1 (10.0.1.1)")

    print("\n*** Instructions ***")
    print("1. Generate baseline traffic:")
    print("   h7 ping h1")
    print("")
    print("2. Launch SYN flood attack from h13:")
    print("   h13 python3 ../attacks/syn_flood.py 10.0.1.1 80 30")
    print("")
    print("3. Observe in controller logs:")
    print("   - Attack detection message")
    print("   - Block rule installation")
    print("")
    print("4. Verify blocking:")
    print("   h13 ping h1  (should fail)")
    print("   h7 ping h1   (should succeed)")
    print("")
    print("5. Check blocked hosts via REST API:")
    print("   curl http://localhost:8080/securenet/ddos/blocked")
    print("\nType 'exit' to return to menu\n")

    CLI(net)


def run_part5_qos(net):
    """Part 5: QoS Configuration."""
    print("\n" + "=" * 50)
    print("  Part 5: QoS Configuration")
    print("=" * 50)

    print("\n*** QoS Queue Configuration ***")
    print("Queue 0 (Critical): 50% min bandwidth - SSH, DNS")
    print("Queue 1 (Real-time): 30% min bandwidth - Video, Streaming")
    print("Queue 2 (Interactive): 15% min bandwidth - HTTP/HTTPS")
    print("Queue 3 (Bulk): 5% min bandwidth - FTP, General")

    print("\n*** Instructions ***")
    print("1. Start iperf server on h15 (streaming):")
    print("   h15 iperf3 -s &")
    print("")
    print("2. Start iperf server on h5 (bulk):")
    print("   h5 iperf3 -s -p 5002 &")
    print("")
    print("3. Generate competing traffic:")
    print("   h7 iperf3 -c 10.0.5.1 -u -b 50M -t 30 &")
    print("   h8 iperf3 -c 10.0.2.1 -p 5002 -t 30 &")
    print("")
    print("4. Observe that streaming (h15) gets priority")
    print("\nType 'exit' to return to menu\n")

    CLI(net)


def run_part6_performance(net):
    """Part 6: Performance Analysis."""
    print("\n" + "=" * 50)
    print("  Part 6: Performance Analysis")
    print("=" * 50)

    print("\n*** Running Automated Benchmarks ***")

    # Import analyzer
    sys.path.insert(0, os.path.join(PROJECT_ROOT, 'analysis'))
    from performance_analyzer import PerformanceAnalyzer
    from graph_generator import GraphGenerator

    analyzer = PerformanceAnalyzer(net)

    # Run benchmarks
    print("\n*** Throughput Test: h7 -> h1 ***")
    result = analyzer.measure_throughput('h7', 'h1')
    print(f"Result: {result.get('throughput_mbps', 0):.1f} Mbps")

    print("\n*** Latency Test: h7 -> h1 ***")
    result = analyzer.measure_latency('h7', 'h1')
    print(f"Result: {result.get('avg_ms', 0):.2f} ms avg")

    print("\n*** Latency Test: h7 -> h16 (cross-pod) ***")
    result = analyzer.measure_latency('h7', 'h16')
    print(f"Result: {result.get('avg_ms', 0):.2f} ms avg")

    # Generate graphs
    print("\n*** Generating Performance Graphs ***")
    generator = GraphGenerator(os.path.join(PROJECT_ROOT, 'docs', 'images'))
    graphs = generator.generate_all_sample_graphs()
    print(f"Generated {len(graphs)} graphs")

    print("\n*** Instructions ***")
    print("1. Export results: analyzer.export_results('results.json')")
    print("2. View graphs in docs/images/")
    print("3. Compare intra-pod vs inter-pod latency")
    print("\nType 'exit' to return to menu\n")

    CLI(net)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='SecureNet DC Lab Experiment')
    parser.add_argument('--part', type=int, default=0,
                       help='Jump directly to lab part (1-6)')
    args = parser.parse_args()

    # Check root
    if os.geteuid() != 0:
        print("\nError: This script must be run as root (sudo)")
        sys.exit(1)

    print_banner()
    setLogLevel('info')

    # Create network
    from topology.fat_tree_datacenter import create_network

    print("\n*** Creating Network ***")
    net = create_network(remote_controller=False)
    net.start()

    print("\n*** Network Ready ***")

    try:
        if args.part > 0:
            # Jump to specific part
            parts = {
                1: run_part1_topology,
                2: run_part2_controller,
                3: run_part3_loadbalancer,
                4: run_part4_ddos,
                5: run_part5_qos,
                6: run_part6_performance,
            }
            if args.part in parts:
                parts[args.part](net)
            return

        # Interactive menu
        while True:
            print_lab_menu()
            choice = input("\nSelect part (0-7): ").strip()

            if choice == '0':
                break
            elif choice == '1':
                run_part1_topology(net)
            elif choice == '2':
                run_part2_controller(net)
            elif choice == '3':
                run_part3_loadbalancer(net)
            elif choice == '4':
                run_part4_ddos(net)
            elif choice == '5':
                run_part5_qos(net)
            elif choice == '6':
                run_part6_performance(net)
            elif choice == '7':
                print("\n*** Full Interactive Mode ***")
                print("Type 'exit' to return to menu\n")
                CLI(net)
            else:
                print("Invalid choice")

    finally:
        print("\n*** Stopping Network ***")
        net.stop()


if __name__ == '__main__':
    main()
