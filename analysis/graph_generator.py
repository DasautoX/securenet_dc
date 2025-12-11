#!/usr/bin/env python3
"""
SecureNet DC - Graph Generator
CPEG 460 Bonus Project

Generates performance visualization graphs using matplotlib.
"""

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
import json
import os
from datetime import datetime

# Use non-interactive backend for server environments
plt.switch_backend('Agg')


class GraphGenerator:
    """
    Performance Graph Generator.

    Creates visualizations for network performance data.
    """

    # Color scheme matching dashboard
    COLORS = {
        'primary': '#58a6ff',
        'success': '#3fb950',
        'warning': '#d29922',
        'danger': '#f85149',
        'purple': '#a371f7',
        'gray': '#8b949e',
        'bg': '#0d1117',
        'panel': '#161b22'
    }

    def __init__(self, output_dir='graphs'):
        """
        Initialize Graph Generator.

        Args:
            output_dir: Directory to save graphs
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

        # Set style
        plt.style.use('dark_background')
        plt.rcParams['figure.facecolor'] = self.COLORS['bg']
        plt.rcParams['axes.facecolor'] = self.COLORS['panel']
        plt.rcParams['axes.edgecolor'] = self.COLORS['gray']
        plt.rcParams['text.color'] = '#c9d1d9'
        plt.rcParams['axes.labelcolor'] = '#c9d1d9'
        plt.rcParams['xtick.color'] = '#c9d1d9'
        plt.rcParams['ytick.color'] = '#c9d1d9'

    def plot_throughput_comparison(self, data, title='Throughput Comparison'):
        """
        Create throughput comparison bar chart.

        Args:
            data: Dict with 'labels' and 'values' keys
            title: Chart title

        Returns:
            str: Path to saved figure
        """
        fig, ax = plt.subplots(figsize=(10, 6))

        labels = data.get('labels', [])
        values = data.get('values', [])

        bars = ax.bar(labels, values, color=self.COLORS['primary'], edgecolor=self.COLORS['gray'])

        # Add value labels on bars
        for bar, val in zip(bars, values):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1,
                   f'{val:.1f}', ha='center', va='bottom', fontsize=10)

        ax.set_xlabel('Host Pair')
        ax.set_ylabel('Throughput (Mbps)')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_ylim(0, max(values) * 1.2 if values else 100)

        plt.tight_layout()

        filename = os.path.join(self.output_dir, 'throughput_comparison.png')
        plt.savefig(filename, dpi=150, facecolor=self.COLORS['bg'])
        plt.close()

        return filename

    def plot_latency_distribution(self, data, title='Latency Distribution'):
        """
        Create latency distribution chart.

        Args:
            data: Dict with 'labels', 'avg', 'min', 'max' keys
            title: Chart title

        Returns:
            str: Path to saved figure
        """
        fig, ax = plt.subplots(figsize=(10, 6))

        labels = data.get('labels', [])
        avg = data.get('avg', [])
        min_vals = data.get('min', [])
        max_vals = data.get('max', [])

        x = np.arange(len(labels))
        width = 0.6

        # Error bars showing min/max range
        error_low = [a - m for a, m in zip(avg, min_vals)]
        error_high = [m - a for a, m in zip(avg, max_vals)]

        bars = ax.bar(x, avg, width, color=self.COLORS['success'],
                     yerr=[error_low, error_high], capsize=5,
                     error_kw={'ecolor': self.COLORS['warning']})

        ax.set_xlabel('Host Pair')
        ax.set_ylabel('Latency (ms)')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(labels)

        plt.tight_layout()

        filename = os.path.join(self.output_dir, 'latency_distribution.png')
        plt.savefig(filename, dpi=150, facecolor=self.COLORS['bg'])
        plt.close()

        return filename

    def plot_qos_comparison(self, data, title='QoS Impact on Traffic Classes'):
        """
        Create QoS comparison chart showing impact on different traffic types.

        Args:
            data: Dict with traffic class data
            title: Chart title

        Returns:
            str: Path to saved figure
        """
        fig, ax = plt.subplots(figsize=(12, 6))

        classes = ['Critical', 'Real-time', 'Interactive', 'Bulk']
        without_qos = data.get('without_qos', [80, 75, 70, 65])
        with_qos = data.get('with_qos', [95, 90, 80, 50])

        x = np.arange(len(classes))
        width = 0.35

        bars1 = ax.bar(x - width/2, without_qos, width, label='Without QoS',
                      color=self.COLORS['gray'])
        bars2 = ax.bar(x + width/2, with_qos, width, label='With QoS',
                      color=self.COLORS['primary'])

        ax.set_xlabel('Traffic Class')
        ax.set_ylabel('Throughput (Mbps)')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(classes)
        ax.legend()
        ax.set_ylim(0, 110)

        # Add value labels
        for bars in [bars1, bars2]:
            for bar in bars:
                height = bar.get_height()
                ax.text(bar.get_x() + bar.get_width()/2, height + 1,
                       f'{height:.0f}', ha='center', va='bottom', fontsize=9)

        plt.tight_layout()

        filename = os.path.join(self.output_dir, 'qos_comparison.png')
        plt.savefig(filename, dpi=150, facecolor=self.COLORS['bg'])
        plt.close()

        return filename

    def plot_attack_timeline(self, events, title='DDoS Attack Timeline'):
        """
        Create attack detection timeline visualization.

        Args:
            events: List of attack events with timestamps
            title: Chart title

        Returns:
            str: Path to saved figure
        """
        fig, ax = plt.subplots(figsize=(14, 6))

        if not events:
            events = [
                {'time': 0, 'type': 'normal', 'pps': 50},
                {'time': 5, 'type': 'normal', 'pps': 60},
                {'time': 10, 'type': 'attack_start', 'pps': 500},
                {'time': 12, 'type': 'detected', 'pps': 800},
                {'time': 13, 'type': 'mitigated', 'pps': 100},
                {'time': 20, 'type': 'normal', 'pps': 55},
            ]

        times = [e['time'] for e in events]
        pps = [e['pps'] for e in events]

        # Plot traffic line
        ax.plot(times, pps, color=self.COLORS['primary'], linewidth=2, marker='o')

        # Fill area under curve
        ax.fill_between(times, pps, alpha=0.3, color=self.COLORS['primary'])

        # Mark attack events
        for event in events:
            if event['type'] == 'attack_start':
                ax.axvline(x=event['time'], color=self.COLORS['danger'],
                          linestyle='--', alpha=0.7, label='Attack Start')
                ax.annotate('Attack!', xy=(event['time'], event['pps']),
                           xytext=(event['time']+1, event['pps']+100),
                           fontsize=10, color=self.COLORS['danger'],
                           arrowprops=dict(arrowstyle='->', color=self.COLORS['danger']))
            elif event['type'] == 'detected':
                ax.axvline(x=event['time'], color=self.COLORS['warning'],
                          linestyle='--', alpha=0.7)
                ax.annotate('Detected', xy=(event['time'], event['pps']),
                           xytext=(event['time']+1, event['pps']-100),
                           fontsize=10, color=self.COLORS['warning'])
            elif event['type'] == 'mitigated':
                ax.axvline(x=event['time'], color=self.COLORS['success'],
                          linestyle='--', alpha=0.7)
                ax.annotate('Mitigated', xy=(event['time'], event['pps']),
                           xytext=(event['time']+1, event['pps']+50),
                           fontsize=10, color=self.COLORS['success'])

        ax.set_xlabel('Time (seconds)')
        ax.set_ylabel('Packets per Second')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.set_ylim(0, max(pps) * 1.3)

        plt.tight_layout()

        filename = os.path.join(self.output_dir, 'attack_timeline.png')
        plt.savefig(filename, dpi=150, facecolor=self.COLORS['bg'])
        plt.close()

        return filename

    def plot_load_balancer_distribution(self, data, title='Load Balancer Distribution'):
        """
        Create pie chart showing request distribution across servers.

        Args:
            data: Dict with server IPs and request counts
            title: Chart title

        Returns:
            str: Path to saved figure
        """
        fig, ax = plt.subplots(figsize=(8, 8))

        servers = list(data.keys())
        requests = list(data.values())

        colors = [self.COLORS['primary'], self.COLORS['success'],
                 self.COLORS['warning'], self.COLORS['purple']]

        wedges, texts, autotexts = ax.pie(requests, labels=servers,
                                          autopct='%1.1f%%', colors=colors[:len(servers)],
                                          textprops={'color': '#c9d1d9'})

        ax.set_title(title, fontsize=14, fontweight='bold')

        plt.tight_layout()

        filename = os.path.join(self.output_dir, 'lb_distribution.png')
        plt.savefig(filename, dpi=150, facecolor=self.COLORS['bg'])
        plt.close()

        return filename

    def plot_bandwidth_over_time(self, data, title='Bandwidth Over Time'):
        """
        Create line chart showing bandwidth changes over time.

        Args:
            data: Dict with 'time', 'rx', 'tx' arrays
            title: Chart title

        Returns:
            str: Path to saved figure
        """
        fig, ax = plt.subplots(figsize=(12, 6))

        times = data.get('time', list(range(60)))
        rx = data.get('rx', [np.random.uniform(30, 60) for _ in range(60)])
        tx = data.get('tx', [np.random.uniform(20, 50) for _ in range(60)])

        ax.plot(times, rx, color=self.COLORS['success'], label='RX', linewidth=2)
        ax.plot(times, tx, color=self.COLORS['primary'], label='TX', linewidth=2)

        ax.fill_between(times, rx, alpha=0.2, color=self.COLORS['success'])
        ax.fill_between(times, tx, alpha=0.2, color=self.COLORS['primary'])

        ax.set_xlabel('Time (seconds)')
        ax.set_ylabel('Bandwidth (Mbps)')
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.legend(loc='upper right')
        ax.grid(True, alpha=0.3)

        plt.tight_layout()

        filename = os.path.join(self.output_dir, 'bandwidth_time.png')
        plt.savefig(filename, dpi=150, facecolor=self.COLORS['bg'])
        plt.close()

        return filename

    def generate_all_sample_graphs(self):
        """
        Generate all sample graphs with demo data.

        Returns:
            list: Paths to all generated graphs
        """
        graphs = []

        # Throughput comparison
        throughput_data = {
            'labels': ['h7->h1', 'h7->h4', 'h8->h5', 'h9->h15'],
            'values': [94.2, 87.5, 91.3, 89.8]
        }
        graphs.append(self.plot_throughput_comparison(throughput_data))

        # Latency distribution
        latency_data = {
            'labels': ['h7->h1', 'h7->h4', 'h8->h5', 'h9->h15'],
            'avg': [2.3, 4.1, 3.2, 3.8],
            'min': [1.8, 3.2, 2.5, 3.0],
            'max': [3.1, 5.5, 4.2, 4.9]
        }
        graphs.append(self.plot_latency_distribution(latency_data))

        # QoS comparison
        qos_data = {
            'without_qos': [75, 72, 68, 62],
            'with_qos': [95, 88, 78, 45]
        }
        graphs.append(self.plot_qos_comparison(qos_data))

        # Attack timeline
        graphs.append(self.plot_attack_timeline(None))

        # Load balancer distribution
        lb_data = {
            '10.0.1.1': 245,
            '10.0.1.2': 238,
            '10.0.1.3': 251,
            '10.0.1.4': 242
        }
        graphs.append(self.plot_load_balancer_distribution(lb_data))

        # Bandwidth over time
        graphs.append(self.plot_bandwidth_over_time({}))

        print(f"Generated {len(graphs)} graphs in {self.output_dir}/")
        return graphs


if __name__ == '__main__':
    generator = GraphGenerator()
    generator.generate_all_sample_graphs()
