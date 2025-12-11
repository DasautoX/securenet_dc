#!/usr/bin/env python3
"""
SecureNet DC - Performance Analyzer
CPEG 460 Bonus Project

Automated performance benchmarking and analysis tools.
Measures:
- Throughput (iperf3)
- Latency (ping)
- Jitter (UDP mode)
- Packet loss
"""

import subprocess
import re
import time
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class PerformanceAnalyzer:
    """
    Network Performance Analysis Tool.

    Provides automated benchmarking capabilities for measuring
    network performance metrics.
    """

    def __init__(self, net=None):
        """
        Initialize Performance Analyzer.

        Args:
            net: Mininet network object (optional)
        """
        self.net = net
        self.results = []
        self.current_test = None

    def set_network(self, net):
        """Set the Mininet network object."""
        self.net = net

    def measure_throughput(self, src_host, dst_host, duration=10, port=5201):
        """
        Measure TCP throughput using iperf3.

        Args:
            src_host: Source host (Mininet host or name)
            dst_host: Destination host (Mininet host or name)
            duration: Test duration in seconds
            port: iperf3 port

        Returns:
            dict: Throughput results
        """
        src = self._get_host(src_host)
        dst = self._get_host(dst_host)

        if not src or not dst:
            return {'error': 'Invalid hosts'}

        dst_ip = dst.IP()

        logger.info(f"Measuring throughput: {src.name} -> {dst.name}")

        # Start iperf server
        dst.cmd(f'iperf3 -s -p {port} -D')
        time.sleep(0.5)

        # Run iperf client
        output = src.cmd(f'iperf3 -c {dst_ip} -t {duration} -p {port} -f m')

        # Stop server
        dst.cmd('pkill iperf3')

        # Parse results
        result = self._parse_iperf_output(output)
        result['src'] = src.name
        result['dst'] = dst.name
        result['type'] = 'throughput'
        result['timestamp'] = datetime.now().isoformat()

        self.results.append(result)
        return result

    def measure_latency(self, src_host, dst_host, count=20):
        """
        Measure RTT latency using ping.

        Args:
            src_host: Source host
            dst_host: Destination host
            count: Number of ping packets

        Returns:
            dict: Latency results
        """
        src = self._get_host(src_host)
        dst = self._get_host(dst_host)

        if not src or not dst:
            return {'error': 'Invalid hosts'}

        dst_ip = dst.IP()

        logger.info(f"Measuring latency: {src.name} -> {dst.name}")

        output = src.cmd(f'ping -c {count} {dst_ip}')

        # Parse results
        result = self._parse_ping_output(output)
        result['src'] = src.name
        result['dst'] = dst.name
        result['type'] = 'latency'
        result['timestamp'] = datetime.now().isoformat()

        self.results.append(result)
        return result

    def measure_jitter(self, src_host, dst_host, duration=10, bandwidth='1M', port=5202):
        """
        Measure jitter using iperf3 UDP mode.

        Args:
            src_host: Source host
            dst_host: Destination host
            duration: Test duration
            bandwidth: Target bandwidth
            port: iperf3 port

        Returns:
            dict: Jitter results
        """
        src = self._get_host(src_host)
        dst = self._get_host(dst_host)

        if not src or not dst:
            return {'error': 'Invalid hosts'}

        dst_ip = dst.IP()

        logger.info(f"Measuring jitter: {src.name} -> {dst.name}")

        # Start iperf server
        dst.cmd(f'iperf3 -s -p {port} -D')
        time.sleep(0.5)

        # Run iperf client in UDP mode
        output = src.cmd(f'iperf3 -c {dst_ip} -u -b {bandwidth} -t {duration} -p {port}')

        # Stop server
        dst.cmd('pkill iperf3')

        # Parse results
        result = self._parse_iperf_udp_output(output)
        result['src'] = src.name
        result['dst'] = dst.name
        result['type'] = 'jitter'
        result['timestamp'] = datetime.now().isoformat()

        self.results.append(result)
        return result

    def measure_packet_loss(self, src_host, dst_host, count=100, size=64):
        """
        Measure packet loss using ping.

        Args:
            src_host: Source host
            dst_host: Destination host
            count: Number of packets
            size: Packet size

        Returns:
            dict: Packet loss results
        """
        src = self._get_host(src_host)
        dst = self._get_host(dst_host)

        if not src or not dst:
            return {'error': 'Invalid hosts'}

        dst_ip = dst.IP()

        logger.info(f"Measuring packet loss: {src.name} -> {dst.name}")

        output = src.cmd(f'ping -c {count} -s {size} {dst_ip}')

        # Parse results
        result = self._parse_ping_output(output)
        result['src'] = src.name
        result['dst'] = dst.name
        result['type'] = 'packet_loss'
        result['timestamp'] = datetime.now().isoformat()

        self.results.append(result)
        return result

    def run_full_benchmark(self, host_pairs=None):
        """
        Run comprehensive benchmark on host pairs.

        Args:
            host_pairs: List of (src, dst) tuples. If None, uses defaults.

        Returns:
            dict: Complete benchmark results
        """
        if host_pairs is None:
            # Default test pairs
            host_pairs = [
                ('h7', 'h1'),   # Client to web server (same pod)
                ('h7', 'h4'),   # Client to web server (cross pod)
                ('h7', 'h15'),  # Client to streaming server
                ('h8', 'h5'),   # Client to DB server
            ]

        benchmark_results = {
            'timestamp': datetime.now().isoformat(),
            'tests': []
        }

        for src, dst in host_pairs:
            logger.info(f"\n=== Benchmarking {src} <-> {dst} ===")

            test_result = {
                'pair': f'{src}->{dst}',
                'throughput': self.measure_throughput(src, dst),
                'latency': self.measure_latency(src, dst),
                'jitter': self.measure_jitter(src, dst),
                'packet_loss': self.measure_packet_loss(src, dst)
            }

            benchmark_results['tests'].append(test_result)

        return benchmark_results

    def compare_with_without_qos(self, src_host, dst_host, duration=10):
        """
        Compare performance with and without QoS.

        Note: This requires ability to toggle QoS on controller.

        Args:
            src_host: Source host
            dst_host: Destination host
            duration: Test duration

        Returns:
            dict: Comparison results
        """
        results = {
            'pair': f'{src_host}->{dst_host}',
            'with_qos': {},
            'without_qos': {},
            'improvement': {}
        }

        # Measure with current (QoS) settings
        logger.info("Measuring with QoS enabled...")
        results['with_qos']['throughput'] = self.measure_throughput(src_host, dst_host, duration)
        results['with_qos']['latency'] = self.measure_latency(src_host, dst_host)

        # Note: Toggling QoS would require controller API call
        # For now, just store current results
        logger.info("QoS comparison complete")

        return results

    def _get_host(self, host):
        """Get Mininet host object."""
        if isinstance(host, str):
            if self.net:
                return self.net.get(host)
            return None
        return host

    def _parse_iperf_output(self, output):
        """Parse iperf3 TCP output."""
        result = {
            'throughput_mbps': 0,
            'transfer_mb': 0,
            'retransmits': 0
        }

        # Look for summary line
        match = re.search(r'\[SUM\].*?(\d+\.?\d*)\s*MBytes\s+(\d+\.?\d*)\s*Mbits/sec', output)
        if match:
            result['transfer_mb'] = float(match.group(1))
            result['throughput_mbps'] = float(match.group(2))
        else:
            # Try single stream format
            match = re.search(r'(\d+\.?\d*)\s*MBytes\s+(\d+\.?\d*)\s*Mbits/sec.*receiver', output)
            if match:
                result['transfer_mb'] = float(match.group(1))
                result['throughput_mbps'] = float(match.group(2))

        # Look for retransmits
        match = re.search(r'(\d+)\s+Retr', output)
        if match:
            result['retransmits'] = int(match.group(1))

        return result

    def _parse_iperf_udp_output(self, output):
        """Parse iperf3 UDP output for jitter."""
        result = {
            'jitter_ms': 0,
            'loss_percent': 0,
            'packets_sent': 0,
            'packets_lost': 0
        }

        # Look for jitter
        match = re.search(r'(\d+\.?\d*)\s*ms\s+(\d+)/(\d+)\s+\((\d+\.?\d*)%\)', output)
        if match:
            result['jitter_ms'] = float(match.group(1))
            result['packets_lost'] = int(match.group(2))
            result['packets_sent'] = int(match.group(3))
            result['loss_percent'] = float(match.group(4))

        return result

    def _parse_ping_output(self, output):
        """Parse ping output."""
        result = {
            'min_ms': 0,
            'avg_ms': 0,
            'max_ms': 0,
            'mdev_ms': 0,
            'loss_percent': 0,
            'packets_sent': 0,
            'packets_received': 0
        }

        # Parse RTT stats
        match = re.search(r'rtt min/avg/max/mdev = ([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', output)
        if match:
            result['min_ms'] = float(match.group(1))
            result['avg_ms'] = float(match.group(2))
            result['max_ms'] = float(match.group(3))
            result['mdev_ms'] = float(match.group(4))

        # Parse packet loss
        match = re.search(r'(\d+) packets transmitted, (\d+) received.*?(\d+)% packet loss', output)
        if match:
            result['packets_sent'] = int(match.group(1))
            result['packets_received'] = int(match.group(2))
            result['loss_percent'] = float(match.group(3))

        return result

    def export_results(self, filename='benchmark_results.json'):
        """Export results to JSON file."""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        logger.info(f"Results exported to {filename}")

    def get_summary(self):
        """Get summary of all test results."""
        if not self.results:
            return "No results available"

        summary = {
            'total_tests': len(self.results),
            'throughput_tests': [],
            'latency_tests': [],
            'avg_throughput': 0,
            'avg_latency': 0
        }

        for r in self.results:
            if r.get('type') == 'throughput':
                summary['throughput_tests'].append(r.get('throughput_mbps', 0))
            elif r.get('type') == 'latency':
                summary['latency_tests'].append(r.get('avg_ms', 0))

        if summary['throughput_tests']:
            summary['avg_throughput'] = sum(summary['throughput_tests']) / len(summary['throughput_tests'])
        if summary['latency_tests']:
            summary['avg_latency'] = sum(summary['latency_tests']) / len(summary['latency_tests'])

        return summary
