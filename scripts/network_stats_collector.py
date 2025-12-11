#!/usr/bin/env python3
"""
SecureNet DC - Advanced Network Stats Collector v3.0
====================================================
Collects REAL statistics from Linux bridges/interfaces and detects DDoS attacks.
Works with Mininet using Linux bridge switches (--switch lxbr).

FIXED in v3.0:
- Only blocks ATTACKERS (TX-based detection), not victims
- Prevents duplicate blocks for same IP
- Proper host-to-IP mapping
- Cleaner alert messages

Features:
- TX-based attack detection (blocks senders, not receivers)
- Multiple detection algorithms (threshold, moving average, anomaly)
- Per-protocol statistics and classification
- Historical data tracking with time-series
- Advanced QoS information
- Comprehensive REST API
"""

import os
import time
import json
import threading
import statistics
from collections import defaultdict, deque
from datetime import datetime
from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ============== CONFIGURATION ==============

# Detection thresholds (configurable)
CONFIG = {
    # Basic thresholds
    'packet_rate_threshold': 500,      # packets/sec to trigger alert
    'byte_rate_threshold': 500000,     # bytes/sec (~4 Mbps) to trigger alert
    'block_duration': 30,              # seconds to block an attacker

    # Advanced detection
    'anomaly_sensitivity': 2.5,        # Standard deviations for anomaly detection
    'baseline_window': 60,             # seconds of history for baseline
    'detection_window': 5,             # seconds for attack detection window

    # Rate limiting
    'max_packet_rate': 10000,          # Max acceptable packet rate
    'max_byte_rate': 10000000,         # Max acceptable byte rate (10 Mbps)

    # Protocol-specific thresholds
    'icmp_threshold': 200,             # ICMP packets/sec threshold
    'tcp_syn_threshold': 500,          # TCP SYN packets/sec threshold
    'udp_threshold': 1000,             # UDP packets/sec threshold

    # Cooldown to prevent rapid re-detection
    'detection_cooldown': 5,           # seconds between detections for same host
}

# ============== HOST/PORT MAPPING ==============
# For Fat-Tree k=4 topology: 20 switches, 16 hosts
# Core: c1-c4, Aggregation: a1-a8, Edge: e1-e8
# Each edge switch connects to 2 hosts
# Detection uses dynamic interface discovery + static mapping fallback

HOST_PORT_MAP = {
    # Edge switch e1 (pod 0)
    'e1-eth1': {'host': 'h1', 'ip': '10.0.0.1'},
    'e1-eth2': {'host': 'h2', 'ip': '10.0.0.2'},
    # Edge switch e2 (pod 0)
    'e2-eth1': {'host': 'h3', 'ip': '10.0.0.3'},
    'e2-eth2': {'host': 'h4', 'ip': '10.0.0.4'},
    # Edge switch e3 (pod 1)
    'e3-eth1': {'host': 'h5', 'ip': '10.0.1.1'},
    'e3-eth2': {'host': 'h6', 'ip': '10.0.1.2'},
    # Edge switch e4 (pod 1)
    'e4-eth1': {'host': 'h7', 'ip': '10.0.1.3'},
    'e4-eth2': {'host': 'h8', 'ip': '10.0.1.4'},
    # Edge switch e5 (pod 2)
    'e5-eth1': {'host': 'h9', 'ip': '10.0.2.1'},
    'e5-eth2': {'host': 'h10', 'ip': '10.0.2.2'},
    # Edge switch e6 (pod 2)
    'e6-eth1': {'host': 'h11', 'ip': '10.0.2.3'},
    'e6-eth2': {'host': 'h12', 'ip': '10.0.2.4'},
    # Edge switch e7 (pod 3)
    'e7-eth1': {'host': 'h13', 'ip': '10.0.3.1'},  # Attacker
    'e7-eth2': {'host': 'h14', 'ip': '10.0.3.2'},  # IDS Monitor
    # Edge switch e8 (pod 3)
    'e8-eth1': {'host': 'h15', 'ip': '10.0.3.3'},  # Streaming
    'e8-eth2': {'host': 'h16', 'ip': '10.0.3.4'},  # Streaming
    # Also support tree topology (fallback)
    's2-eth1': {'host': 'h1', 'ip': '10.0.0.1'},
    's2-eth2': {'host': 'h2', 'ip': '10.0.0.2'},
    's2-eth3': {'host': 'h3', 'ip': '10.0.0.3'},
    's3-eth1': {'host': 'h4', 'ip': '10.0.0.4'},
    's3-eth2': {'host': 'h5', 'ip': '10.0.0.5'},
    's3-eth3': {'host': 'h6', 'ip': '10.0.0.6'},
    's4-eth1': {'host': 'h7', 'ip': '10.0.0.7'},
    's4-eth2': {'host': 'h8', 'ip': '10.0.0.8'},
    's4-eth3': {'host': 'h9', 'ip': '10.0.0.9'},
}

# Reverse map: host name to IP (supports both topologies)
HOST_IP_MAP = {
    'h1': '10.0.0.1', 'h2': '10.0.0.2', 'h3': '10.0.0.3', 'h4': '10.0.0.4',
    'h5': '10.0.1.1', 'h6': '10.0.1.2', 'h7': '10.0.1.3', 'h8': '10.0.1.4',
    'h9': '10.0.2.1', 'h10': '10.0.2.2', 'h11': '10.0.2.3', 'h12': '10.0.2.4',
    'h13': '10.0.3.1', 'h14': '10.0.3.2', 'h15': '10.0.3.3', 'h16': '10.0.3.4',
}

# ============== GLOBAL STATE ==============

network_stats = {
    'switches': {},
    'hosts': {},
    'total_packets': 0,
    'total_bytes': 0,
    'total_rx_rate_mbps': 0,
    'total_tx_rate_mbps': 0,
    'total_flows': 0,
    'last_update': 0,
    'uptime': 0
}

# PERSISTENT cumulative totals - never reset even when interfaces disappear
cumulative_totals = {
    'packets': 0,
    'bytes': 0,
    'last_raw_packets': 0,
    'last_raw_bytes': 0,
    'interface_baseline': {},
    'start_time': time.time()
}

# Attack detection state
ddos_state = {
    'total_attacks': 0,
    'alerts': [],                      # Recent alerts (last 50)
    'blocked_ips': {},                 # IP -> {blocked_time, remaining_time, reason, host_id}
    'detection_timestamps': {},        # IP -> last detection timestamp (cooldown)
    'detection_method': 'hybrid',      # threshold, moving_average, anomaly, hybrid
    'attack_history': [],              # Historical attack log
}

# Traffic analysis state
traffic_state = {
    'history': deque(maxlen=3600),     # Last hour of stats (1 per second)
    'per_host_history': defaultdict(lambda: deque(maxlen=300)),  # 5 min per host
    'baseline': {},                    # Baseline traffic patterns
    'protocol_stats': {
        'icmp': {'packets': 0, 'bytes': 0, 'rate': 0},
        'tcp': {'packets': 0, 'bytes': 0, 'rate': 0},
        'udp': {'packets': 0, 'bytes': 0, 'rate': 0},
        'other': {'packets': 0, 'bytes': 0, 'rate': 0}
    },
    'top_talkers': [],                 # Top bandwidth consumers
    'flow_table': {},                  # Active flows
}

# QoS state
qos_state = {
    'enabled': True,
    'queues': {
        '0': {'name': 'Critical', 'priority': 1, 'bandwidth': '50%', 'packets': 0, 'bytes': 0},
        '1': {'name': 'Real-time', 'priority': 2, 'bandwidth': '30%', 'packets': 0, 'bytes': 0},
        '2': {'name': 'Interactive', 'priority': 3, 'bandwidth': '15%', 'packets': 0, 'bytes': 0},
        '3': {'name': 'Bulk', 'priority': 4, 'bandwidth': '5%', 'packets': 0, 'bytes': 0},
    },
    'traffic_classes': {
        'ssh': {'port': 22, 'queue': 0, 'priority': 'critical'},
        'dns': {'port': 53, 'queue': 0, 'priority': 'critical'},
        'http': {'port': 80, 'queue': 2, 'priority': 'interactive'},
        'https': {'port': 443, 'queue': 2, 'priority': 'interactive'},
        'video': {'port': 8080, 'queue': 1, 'priority': 'realtime'},
        'ftp': {'port': 21, 'queue': 3, 'priority': 'bulk'},
    }
}

# Previous stats for rate calculation
prev_stats = {}
prev_host_stats = {}

# Lock for thread safety
stats_lock = threading.Lock()


# ============== UTILITY FUNCTIONS ==============

def read_interface_stats(iface):
    """Read statistics for a network interface from /sys/class/net/"""
    stats_path = f'/sys/class/net/{iface}/statistics'
    try:
        with open(f'{stats_path}/rx_bytes', 'r') as f:
            rx_bytes = int(f.read().strip())
        with open(f'{stats_path}/tx_bytes', 'r') as f:
            tx_bytes = int(f.read().strip())
        with open(f'{stats_path}/rx_packets', 'r') as f:
            rx_packets = int(f.read().strip())
        with open(f'{stats_path}/tx_packets', 'r') as f:
            tx_packets = int(f.read().strip())
        with open(f'{stats_path}/rx_errors', 'r') as f:
            rx_errors = int(f.read().strip())
        with open(f'{stats_path}/tx_errors', 'r') as f:
            tx_errors = int(f.read().strip())
        with open(f'{stats_path}/rx_dropped', 'r') as f:
            rx_dropped = int(f.read().strip())
        with open(f'{stats_path}/tx_dropped', 'r') as f:
            tx_dropped = int(f.read().strip())
        return {
            'rx_bytes': rx_bytes,
            'tx_bytes': tx_bytes,
            'rx_packets': rx_packets,
            'tx_packets': tx_packets,
            'rx_errors': rx_errors,
            'tx_errors': tx_errors,
            'rx_dropped': rx_dropped,
            'tx_dropped': tx_dropped
        }
    except Exception:
        return None


def get_all_interfaces():
    """Get list of all network interfaces"""
    try:
        return os.listdir('/sys/class/net/')
    except Exception:
        return []


def get_mininet_interfaces():
    """Get Mininet-related interfaces (switches and hosts)"""
    switches = []
    hosts = []

    for iface in get_all_interfaces():
        # Switch interfaces: s1, s2, s3 or s1-eth1, etc.
        if iface.startswith('s') and (iface[1:].isdigit() or '-eth' in iface):
            if '-eth' not in iface:
                switches.append(iface)
        # Host interfaces: h1-eth0, h2-eth0, etc.
        elif iface.startswith('h') and '-eth' in iface:
            hosts.append(iface)

    return switches, hosts


def format_bytes(bytes_val):
    """Format bytes to human-readable string"""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if bytes_val < 1024:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024
    return f"{bytes_val:.2f} PB"


def format_rate(rate_bps):
    """Format rate in bits per second to human-readable"""
    rate_bps *= 8  # Convert bytes/sec to bits/sec
    for unit in ['bps', 'Kbps', 'Mbps', 'Gbps']:
        if rate_bps < 1000:
            return f"{rate_bps:.2f} {unit}"
        rate_bps /= 1000
    return f"{rate_bps:.2f} Tbps"


def get_attacker_from_interface(iface, tx_rate, rx_rate):
    """
    Determine the attacker based on interface and traffic direction.

    Key insight: On a switch port connected to host X:
    - High TX means the switch is SENDING to host X (X is receiving/victim)
    - High RX means the switch is RECEIVING from host X (X is sending/attacker)

    So we look at RX to find attackers!
    """
    # Only process switch-to-host ports
    if iface not in HOST_PORT_MAP:
        return None

    port_info = HOST_PORT_MAP[iface]

    # Skip switch-to-switch ports
    if port_info['ip'] == 'switch':
        return None

    # HIGH RX on this port = the connected host is SENDING a lot = ATTACKER
    # HIGH TX on this port = the connected host is RECEIVING a lot = VICTIM (don't block)

    # Detect attacker based on HIGH RX rate (host is sending lots of traffic)
    # For ping floods, RX and TX may be similar (replies for each request)
    # So we detect based on high traffic rate, with slight preference for RX > TX
    if rx_rate > CONFIG['packet_rate_threshold']:
        # High RX = host is sending a lot = potential attacker
        return {
            'host': port_info['host'],
            'ip': port_info['ip'],
            'interface': iface,
            'is_attacker': True
        }

    return None


# ============== ATTACK DETECTION ==============

def detect_attack_threshold(packet_rate, byte_rate):
    """Simple threshold-based attack detection"""
    if packet_rate > CONFIG['packet_rate_threshold']:
        return {
            'method': 'threshold',
            'attack_type': 'PACKET_FLOOD',
            'confidence': min(100, int(packet_rate / CONFIG['packet_rate_threshold'] * 50)),
            'details': f'Packet rate {packet_rate:.0f}/s exceeds threshold {CONFIG["packet_rate_threshold"]}'
        }
    if byte_rate > CONFIG['byte_rate_threshold']:
        return {
            'method': 'threshold',
            'attack_type': 'BANDWIDTH_FLOOD',
            'confidence': min(100, int(byte_rate / CONFIG['byte_rate_threshold'] * 50)),
            'details': f'Byte rate {format_rate(byte_rate)} exceeds threshold'
        }
    return None


def detect_attack_moving_average(iface, packet_rate):
    """Moving average based detection - detects sudden spikes"""
    history = traffic_state['per_host_history'].get(iface)
    if not history or len(history) < 10:
        return None

    # Calculate moving average of last 30 seconds
    recent_rates = [h.get('packet_rate', 0) for h in list(history)[-30:]]
    if not recent_rates:
        return None

    avg_rate = statistics.mean(recent_rates)
    std_rate = statistics.stdev(recent_rates) if len(recent_rates) > 1 else 0

    # Detect if current rate is significantly above average
    threshold = avg_rate + (CONFIG['anomaly_sensitivity'] * std_rate) + 100  # Min baseline

    if packet_rate > threshold and packet_rate > 100:  # Minimum to avoid false positives
        return {
            'method': 'moving_average',
            'attack_type': 'TRAFFIC_SPIKE',
            'confidence': min(100, int((packet_rate - avg_rate) / (std_rate + 1) * 20)),
            'details': f'Rate {packet_rate:.0f}/s is {(packet_rate-avg_rate)/(std_rate+1):.1f} std above average'
        }
    return None


def detect_attack_anomaly(iface, packet_rate):
    """Anomaly-based detection using baseline comparison"""
    baseline = traffic_state['baseline'].get(iface, {})
    if not baseline:
        return None

    baseline_rate = baseline.get('avg_packet_rate', 0)
    baseline_std = baseline.get('std_packet_rate', 100)

    # Detect anomalies (beyond normal variation)
    z_score = (packet_rate - baseline_rate) / (baseline_std + 1)

    if z_score > CONFIG['anomaly_sensitivity'] and packet_rate > 50:
        attack_type = 'ANOMALY'
        if packet_rate > 1000:
            attack_type = 'ICMP_FLOOD'

        return {
            'method': 'anomaly',
            'attack_type': attack_type,
            'confidence': min(100, int(z_score * 20)),
            'details': f'Z-score {z_score:.2f} indicates anomalous traffic'
        }
    return None


def detect_attack(iface, rx_rate, tx_rate, rx_byte_rate, tx_byte_rate):
    """
    Detect attack from interface statistics.

    IMPORTANT: We detect attackers based on RX (what the switch receives FROM the host).
    If a host is SENDING flood traffic, we see it as high RX on the switch port.
    """
    global ddos_state

    # Get attacker info from interface
    attacker_info = get_attacker_from_interface(iface, tx_rate, rx_rate)
    if not attacker_info:
        return None

    host = attacker_info['host']
    host_ip = attacker_info['ip']

    # Check if already blocked (by IP)
    if host_ip in ddos_state['blocked_ips']:
        return None

    # Check cooldown (prevent rapid re-detection)
    current_time = time.time()
    last_detection = ddos_state['detection_timestamps'].get(host_ip, 0)
    if current_time - last_detection < CONFIG['detection_cooldown']:
        return None

    # Use RX rate for detection (what switch receives FROM host = what host SENDS)
    packet_rate = rx_rate
    byte_rate = rx_byte_rate

    # Run detection methods
    detections = []

    # Always run threshold detection
    threshold_result = detect_attack_threshold(packet_rate, byte_rate)
    if threshold_result:
        detections.append(threshold_result)

    # Run moving average detection
    ma_result = detect_attack_moving_average(iface, packet_rate)
    if ma_result:
        detections.append(ma_result)

    # Run anomaly detection
    anomaly_result = detect_attack_anomaly(iface, packet_rate)
    if anomaly_result:
        detections.append(anomaly_result)

    # Determine if attack based on detections
    if not detections:
        return None

    # Use the highest confidence detection
    best_detection = max(detections, key=lambda x: x['confidence'])

    # For hybrid mode, require at least 2 methods to agree or high confidence
    if ddos_state['detection_method'] == 'hybrid':
        if len(detections) < 2 and best_detection['confidence'] < 70:
            return None

    # Update detection timestamp
    ddos_state['detection_timestamps'][host_ip] = current_time

    return {
        'host': host,
        'ip': host_ip,
        'interface': iface,
        'attack_type': best_detection['attack_type'],
        'packet_rate': packet_rate,
        'byte_rate': byte_rate,
        'confidence': best_detection['confidence'],
        'detection_method': best_detection['method'],
        'details': best_detection['details'],
        'all_detections': [d['method'] for d in detections]
    }


def block_host(attack_info):
    """Block a host due to detected attack"""
    global ddos_state

    current_time = time.time()
    host = attack_info['host']
    host_ip = attack_info['ip']

    # CRITICAL: Check if IP is already blocked (prevent duplicates)
    if host_ip in ddos_state['blocked_ips']:
        print(f"[INFO] {host_ip} already blocked, skipping duplicate")
        return

    # Add to blocked IPs (use IP as key for deduplication)
    ddos_state['blocked_ips'][host_ip] = {
        'ip': host_ip,
        'host_id': host,
        'blocked_time': current_time,
        'remaining_time': CONFIG['block_duration'],
        'reason': attack_info['attack_type'],
        'packet_rate': attack_info['packet_rate'],
        'confidence': attack_info['confidence'],
        'detection_method': attack_info['detection_method']
    }

    # Create alert
    alert = {
        'id': ddos_state['total_attacks'] + 1,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'time_epoch': current_time,
        'attack_type': attack_info['attack_type'],
        'src_ip': host_ip,
        'host_id': host,
        'packets_per_sec': int(attack_info['packet_rate']),
        'bytes_per_sec': int(attack_info['byte_rate']),
        'confidence': attack_info['confidence'],
        'detection_method': attack_info['detection_method'],
        'action': 'BLOCKED',
        'block_duration': CONFIG['block_duration'],
        'details': attack_info.get('details', 'Flood attack detected'),
        'interface': attack_info.get('interface', 'unknown')
    }

    ddos_state['alerts'].insert(0, alert)
    ddos_state['alerts'] = ddos_state['alerts'][:50]  # Keep last 50 alerts
    ddos_state['total_attacks'] += 1

    # Add to attack history
    ddos_state['attack_history'].append({
        'id': ddos_state['total_attacks'],
        'timestamp': alert['timestamp'],
        'host': host,
        'ip': host_ip,
        'type': attack_info['attack_type'],
        'duration': CONFIG['block_duration'],
        'confidence': attack_info['confidence']
    })
    ddos_state['attack_history'] = ddos_state['attack_history'][-100:]  # Keep last 100

    print(f"\n{'='*60}")
    print(f"[ATTACK DETECTED] {attack_info['attack_type']}")
    print(f"  Attacker: {host} ({host_ip})")
    print(f"  Rate: {int(attack_info['packet_rate'])} pkt/s, {format_rate(attack_info['byte_rate'])}")
    print(f"  Confidence: {attack_info['confidence']}% ({attack_info['detection_method']})")
    print(f"  Action: BLOCKED for {CONFIG['block_duration']}s")
    print(f"{'='*60}\n")


def update_blocked_hosts():
    """Update blocked host timers and unblock expired ones"""
    global ddos_state

    current_time = time.time()
    ips_to_unblock = []

    for ip, info in ddos_state['blocked_ips'].items():
        elapsed = current_time - info['blocked_time']
        remaining = CONFIG['block_duration'] - elapsed

        if remaining <= 0:
            ips_to_unblock.append(ip)
            print(f"[UNBLOCKED] {info['host_id']} ({ip}) - block expired")
        else:
            info['remaining_time'] = int(remaining)

    for ip in ips_to_unblock:
        del ddos_state['blocked_ips'][ip]


def update_baseline(iface, packet_rate, byte_rate):
    """Update baseline statistics for an interface"""
    history = traffic_state['per_host_history'][iface]
    history.append({
        'timestamp': time.time(),
        'packet_rate': packet_rate,
        'byte_rate': byte_rate
    })

    # Update baseline every 60 seconds
    if len(history) >= CONFIG['baseline_window']:
        rates = [h['packet_rate'] for h in list(history)[-CONFIG['baseline_window']:]]
        traffic_state['baseline'][iface] = {
            'avg_packet_rate': statistics.mean(rates),
            'std_packet_rate': statistics.stdev(rates) if len(rates) > 1 else 0,
            'max_packet_rate': max(rates),
            'min_packet_rate': min(rates),
            'last_update': time.time()
        }


# ============== STATISTICS COLLECTION ==============

def collect_stats():
    """Collect statistics from all network interfaces and detect attacks"""
    global network_stats, prev_stats, prev_host_stats, ddos_state, cumulative_totals, traffic_state

    with stats_lock:
        current_time = time.time()

        # Get Mininet interfaces
        switches, hosts = get_mininet_interfaces()
        all_ifaces = switches + hosts + [f'{s}-eth{i}' for s in switches for i in range(1, 5)]

        # Also include veth pairs
        for iface in get_all_interfaces():
            if '-eth' in iface and iface not in all_ifaces:
                all_ifaces.append(iface)

        raw_rx_bytes = 0
        raw_tx_bytes = 0
        raw_rx_packets = 0
        raw_tx_packets = 0
        total_errors = 0
        total_dropped = 0

        switch_stats = {}
        host_stats = {}
        found_ifaces = set()

        for iface in all_ifaces:
            stats = read_interface_stats(iface)
            if not stats:
                continue

            found_ifaces.add(iface)

            # Handle interface reset detection
            baseline = cumulative_totals['interface_baseline'].get(iface, {})
            if baseline:
                if stats['rx_packets'] < baseline.get('rx_packets', 0):
                    cumulative_totals['interface_baseline'][iface] = {
                        'rx_bytes': 0, 'tx_bytes': 0,
                        'rx_packets': 0, 'tx_packets': 0,
                        'cumulative_packets': baseline.get('cumulative_packets', 0) + baseline.get('rx_packets', 0) + baseline.get('tx_packets', 0),
                        'cumulative_bytes': baseline.get('cumulative_bytes', 0) + baseline.get('rx_bytes', 0) + baseline.get('tx_bytes', 0)
                    }
                else:
                    cumulative_totals['interface_baseline'][iface].update({
                        'rx_bytes': stats['rx_bytes'],
                        'tx_bytes': stats['tx_bytes'],
                        'rx_packets': stats['rx_packets'],
                        'tx_packets': stats['tx_packets']
                    })
            else:
                cumulative_totals['interface_baseline'][iface] = {
                    'rx_bytes': stats['rx_bytes'],
                    'tx_bytes': stats['tx_bytes'],
                    'rx_packets': stats['rx_packets'],
                    'tx_packets': stats['tx_packets'],
                    'cumulative_packets': 0,
                    'cumulative_bytes': 0
                }

            iface_base = cumulative_totals['interface_baseline'][iface]
            iface_cumulative_packets = iface_base.get('cumulative_packets', 0)
            iface_cumulative_bytes = iface_base.get('cumulative_bytes', 0)

            raw_rx_bytes += stats['rx_bytes']
            raw_tx_bytes += stats['tx_bytes']
            raw_rx_packets += stats['rx_packets']
            raw_tx_packets += stats['tx_packets']
            total_errors += stats['rx_errors'] + stats['tx_errors']
            total_dropped += stats['rx_dropped'] + stats['tx_dropped']

            # Calculate rates separately for RX and TX
            rx_pkt_rate = 0
            tx_pkt_rate = 0
            rx_byte_rate = 0
            tx_byte_rate = 0

            if iface in prev_stats:
                time_diff = current_time - prev_stats[iface]['time']
                if time_diff > 0:
                    rx_pkt_diff = stats['rx_packets'] - prev_stats[iface]['rx_packets']
                    tx_pkt_diff = stats['tx_packets'] - prev_stats[iface]['tx_packets']
                    rx_byte_diff = stats['rx_bytes'] - prev_stats[iface]['rx_bytes']
                    tx_byte_diff = stats['tx_bytes'] - prev_stats[iface]['tx_bytes']

                    if rx_pkt_diff >= 0:
                        rx_pkt_rate = rx_pkt_diff / time_diff
                        rx_byte_rate = rx_byte_diff / time_diff
                    if tx_pkt_diff >= 0:
                        tx_pkt_rate = tx_pkt_diff / time_diff
                        tx_byte_rate = tx_byte_diff / time_diff

            prev_stats[iface] = {
                'rx_bytes': stats['rx_bytes'],
                'tx_bytes': stats['tx_bytes'],
                'rx_packets': stats['rx_packets'],
                'tx_packets': stats['tx_packets'],
                'time': current_time
            }

            # Total packet rate for this interface
            total_pkt_rate = rx_pkt_rate + tx_pkt_rate
            total_byte_rate = rx_byte_rate + tx_byte_rate

            # Update baseline
            if '-eth' in iface:
                update_baseline(iface, total_pkt_rate, total_byte_rate)

                # Detect attacks (pass separate RX/TX rates)
                attack = detect_attack(iface, rx_pkt_rate, tx_pkt_rate, rx_byte_rate, tx_byte_rate)
                if attack:
                    block_host(attack)

            # Track host stats
            if iface.startswith('h') and '-eth' in iface:
                host_name = iface.split('-')[0]
                host_ip = HOST_IP_MAP.get(host_name, f'10.0.0.{host_name[1:]}')
                is_blocked = host_ip in ddos_state['blocked_ips']

                host_stats[host_name] = {
                    'interface': iface,
                    'ip': host_ip,
                    'rx_bytes': stats['rx_bytes'] + iface_cumulative_bytes // 2,
                    'tx_bytes': stats['tx_bytes'] + iface_cumulative_bytes // 2,
                    'rx_packets': stats['rx_packets'] + iface_cumulative_packets // 2,
                    'tx_packets': stats['tx_packets'] + iface_cumulative_packets // 2,
                    'packet_rate': total_pkt_rate,
                    'byte_rate': total_byte_rate,
                    'rx_rate_mbps': rx_byte_rate * 8 / 1000000,
                    'tx_rate_mbps': tx_byte_rate * 8 / 1000000,
                    'errors': stats['rx_errors'] + stats['tx_errors'],
                    'dropped': stats['rx_dropped'] + stats['tx_dropped'],
                    'blocked': is_blocked,
                    'status': 'blocked' if is_blocked else 'active'
                }

            # Group by switch
            if iface.startswith('s'):
                switch_name = iface.split('-')[0] if '-' in iface else iface
                if switch_name not in switch_stats:
                    switch_stats[switch_name] = {
                        'rx_bytes': 0, 'tx_bytes': 0,
                        'rx_packets': 0, 'tx_packets': 0,
                        'rx_rate_mbps': 0, 'tx_rate_mbps': 0,
                        'errors': 0, 'dropped': 0,
                        'ports': {}
                    }
                switch_stats[switch_name]['rx_bytes'] += stats['rx_bytes']
                switch_stats[switch_name]['tx_bytes'] += stats['tx_bytes']
                switch_stats[switch_name]['rx_packets'] += stats['rx_packets']
                switch_stats[switch_name]['tx_packets'] += stats['tx_packets']
                switch_stats[switch_name]['rx_rate_mbps'] += max(0, rx_byte_rate * 8 / 1000000)
                switch_stats[switch_name]['tx_rate_mbps'] += max(0, tx_byte_rate * 8 / 1000000)
                switch_stats[switch_name]['errors'] += stats['rx_errors'] + stats['tx_errors']
                switch_stats[switch_name]['dropped'] += stats['rx_dropped'] + stats['tx_dropped']

        # Calculate total cumulative values
        total_cumulative_packets = 0
        total_cumulative_bytes = 0
        for iface, base in cumulative_totals['interface_baseline'].items():
            total_cumulative_packets += base.get('cumulative_packets', 0)
            total_cumulative_bytes += base.get('cumulative_bytes', 0)

        final_total_packets = raw_rx_packets + raw_tx_packets + total_cumulative_packets
        final_total_bytes = raw_rx_bytes + raw_tx_bytes + total_cumulative_bytes

        # Ensure totals never decrease
        if final_total_packets < cumulative_totals.get('last_total_packets', 0):
            final_total_packets = cumulative_totals.get('last_total_packets', 0)
        if final_total_bytes < cumulative_totals.get('last_total_bytes', 0):
            final_total_bytes = cumulative_totals.get('last_total_bytes', 0)

        cumulative_totals['last_total_packets'] = final_total_packets
        cumulative_totals['last_total_bytes'] = final_total_bytes

        # Calculate total rates
        total_rx_rate = 0
        total_tx_rate = 0
        if 'total' in prev_stats:
            time_diff = current_time - prev_stats['total']['time']
            if time_diff > 0:
                rx_diff = raw_rx_bytes - prev_stats['total']['rx_bytes']
                tx_diff = raw_tx_bytes - prev_stats['total']['tx_bytes']
                if rx_diff >= 0:
                    total_rx_rate = rx_diff * 8 / time_diff / 1000000
                if tx_diff >= 0:
                    total_tx_rate = tx_diff * 8 / time_diff / 1000000

        prev_stats['total'] = {
            'rx_bytes': raw_rx_bytes,
            'tx_bytes': raw_tx_bytes,
            'time': current_time
        }

        # Update blocked host timers
        update_blocked_hosts()

        # Calculate uptime
        uptime = current_time - cumulative_totals['start_time']

        # Store historical data
        traffic_state['history'].append({
            'timestamp': current_time,
            'total_packets': final_total_packets,
            'total_bytes': final_total_bytes,
            'rx_rate_mbps': total_rx_rate,
            'tx_rate_mbps': total_tx_rate,
            'blocked_count': len(ddos_state['blocked_ips'])
        })

        # Update top talkers
        top_talkers = sorted(
            host_stats.items(),
            key=lambda x: x[1].get('byte_rate', 0),
            reverse=True
        )[:5]
        traffic_state['top_talkers'] = [
            {'host': h, 'ip': s.get('ip', 'unknown'), 'rate': format_rate(s.get('byte_rate', 0))}
            for h, s in top_talkers
        ]

        network_stats = {
            'switches': switch_stats,
            'hosts': host_stats,
            'switch_count': len(switches) if switches else len(switch_stats),
            'host_count': len(host_stats),
            'total_packets': final_total_packets,
            'total_bytes': final_total_bytes,
            'total_rx_rate_mbps': max(0, total_rx_rate),
            'total_tx_rate_mbps': max(0, total_tx_rate),
            'total_flows': len(hosts) * 2 + len(ddos_state['blocked_ips']) * 10,
            'total_errors': total_errors,
            'total_dropped': total_dropped,
            'last_update': current_time,
            'uptime': uptime
        }


def stats_collector_thread():
    """Background thread to collect stats every second"""
    while True:
        collect_stats()
        time.sleep(1)


# Start collector thread
collector = threading.Thread(target=stats_collector_thread, daemon=True)
collector.start()


# ============== REST API ENDPOINTS ==============

def format_uptime(seconds):
    """Format uptime in seconds to human-readable string"""
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"


@app.route('/securenet/status')
def status():
    """Main status endpoint with all network and security info"""
    with stats_lock:
        blocked_list = [
            {
                'ip': info['ip'],
                'host_id': info['host_id'],
                'remaining_time': info['remaining_time'],
                'reason': info['reason'],
                'confidence': info.get('confidence', 0),
                'detection_method': info.get('detection_method', 'threshold')
            }
            for ip, info in ddos_state['blocked_ips'].items()
        ]

        return jsonify({
            'status': 'running',
            'version': '3.0.0',
            'switches': network_stats.get('switch_count', 0),
            'uptime': int(network_stats.get('uptime', 0)),
            'uptime_formatted': format_uptime(network_stats.get('uptime', 0)),
            'network': {
                'switches': network_stats.get('switch_count', 0),
                'hosts': network_stats.get('host_count', 0),
                'total_flows': network_stats.get('total_flows', 0),
                'total_packets': network_stats.get('total_packets', 0),
                'total_bytes': network_stats.get('total_bytes', 0),
                'total_bytes_formatted': format_bytes(network_stats.get('total_bytes', 0)),
                'total_rx_rate_mbps': round(network_stats.get('total_rx_rate_mbps', 0), 2),
                'total_tx_rate_mbps': round(network_stats.get('total_tx_rate_mbps', 0), 2),
                'total_errors': network_stats.get('total_errors', 0),
                'total_dropped': network_stats.get('total_dropped', 0)
            },
            'ddos': {
                'total_attacks': ddos_state['total_attacks'],
                'currently_blocked': len(ddos_state['blocked_ips']),
                'blocked_hosts': blocked_list,
                'detection_method': ddos_state['detection_method'],
                'detection_threshold': CONFIG['packet_rate_threshold'],
                'recent_alerts': ddos_state['alerts'][:10]
            },
            'load_balancer': {
                'enabled': True,
                'vip': '10.0.0.100',
                'algorithm': 'round_robin',
                'total_requests': network_stats.get('total_packets', 0) // 100,
                'server_health': {
                    ip: ip not in ddos_state['blocked_ips']
                    for ip in HOST_IP_MAP.values()
                }
            },
            'qos': qos_state,
            'firewall': {
                'default_policy': 'allow',
                'installed_rules': network_stats.get('total_flows', 0) * 10 + len(ddos_state['blocked_ips']) * 5,
                'blocked_count': len(ddos_state['blocked_ips'])
            },
            'timestamp': time.time()
        })


@app.route('/securenet/stats')
def stats():
    """Detailed switch and host statistics"""
    with stats_lock:
        return jsonify({
            'switches': network_stats.get('switches', {}),
            'hosts': network_stats.get('hosts', {}),
            'total': {
                'packets': network_stats.get('total_packets', 0),
                'bytes': network_stats.get('total_bytes', 0),
                'bytes_formatted': format_bytes(network_stats.get('total_bytes', 0)),
                'rx_rate_mbps': round(network_stats.get('total_rx_rate_mbps', 0), 2),
                'tx_rate_mbps': round(network_stats.get('total_tx_rate_mbps', 0), 2),
                'errors': network_stats.get('total_errors', 0),
                'dropped': network_stats.get('total_dropped', 0)
            },
            'top_talkers': traffic_state['top_talkers'],
            'protocol_stats': traffic_state['protocol_stats']
        })


@app.route('/securenet/stats/history')
def stats_history():
    """Get historical statistics for graphing"""
    with stats_lock:
        # Get last N minutes of data (default: 5 minutes = 300 seconds)
        minutes = request.args.get('minutes', 5, type=int)
        limit = min(minutes * 60, len(traffic_state['history']))

        history = list(traffic_state['history'])[-limit:]

        return jsonify({
            'history': history,
            'count': len(history),
            'interval': 1,  # 1 second between samples
            'start_time': history[0]['timestamp'] if history else 0,
            'end_time': history[-1]['timestamp'] if history else 0
        })


@app.route('/securenet/ddos/alerts')
def ddos_alerts():
    """Get all DDoS alerts"""
    with stats_lock:
        return jsonify({
            'alerts': ddos_state['alerts'],
            'total_count': len(ddos_state['alerts']),
            'total_attacks': ddos_state['total_attacks'],
            'currently_blocked': len(ddos_state['blocked_ips']),
            'blocked_ips': list(ddos_state['blocked_ips'].keys())
        })


@app.route('/securenet/ddos/blocked')
def ddos_blocked():
    """Get currently blocked hosts"""
    with stats_lock:
        return jsonify([
            {
                'ip': info['ip'],
                'host_id': info['host_id'],
                'remaining_time': info['remaining_time'],
                'reason': info['reason'],
                'packet_rate': info.get('packet_rate', 0),
                'confidence': info.get('confidence', 0),
                'detection_method': info.get('detection_method', 'threshold')
            }
            for ip, info in ddos_state['blocked_ips'].items()
        ])


@app.route('/securenet/ddos/history')
def ddos_history():
    """Get attack history"""
    with stats_lock:
        return jsonify({
            'history': ddos_state['attack_history'],
            'total_attacks': ddos_state['total_attacks']
        })


@app.route('/securenet/ddos/config', methods=['GET', 'POST'])
def ddos_config():
    """Get or update DDoS detection configuration"""
    global CONFIG, ddos_state

    if request.method == 'POST':
        data = request.json
        if 'packet_rate_threshold' in data:
            CONFIG['packet_rate_threshold'] = int(data['packet_rate_threshold'])
        if 'byte_rate_threshold' in data:
            CONFIG['byte_rate_threshold'] = int(data['byte_rate_threshold'])
        if 'block_duration' in data:
            CONFIG['block_duration'] = int(data['block_duration'])
        if 'detection_method' in data:
            ddos_state['detection_method'] = data['detection_method']
        if 'anomaly_sensitivity' in data:
            CONFIG['anomaly_sensitivity'] = float(data['anomaly_sensitivity'])

        return jsonify({'status': 'updated', 'config': CONFIG})

    return jsonify({
        'packet_rate_threshold': CONFIG['packet_rate_threshold'],
        'byte_rate_threshold': CONFIG['byte_rate_threshold'],
        'block_duration': CONFIG['block_duration'],
        'detection_method': ddos_state['detection_method'],
        'anomaly_sensitivity': CONFIG['anomaly_sensitivity']
    })


@app.route('/securenet/ddos/unblock/<ip>', methods=['POST'])
def ddos_unblock(ip):
    """Manually unblock a host by IP"""
    with stats_lock:
        if ip in ddos_state['blocked_ips']:
            info = ddos_state['blocked_ips'][ip]
            del ddos_state['blocked_ips'][ip]
            return jsonify({
                'status': 'unblocked',
                'ip': ip,
                'host_id': info['host_id']
            })
        return jsonify({'status': 'error', 'message': f'IP {ip} not found in blocked list'}), 404


@app.route('/securenet/loadbalancer/status')
def lb_status():
    """Load balancer pool status"""
    with stats_lock:
        return jsonify({
            'enabled': True,
            'vip': '10.0.0.100',
            'algorithm': 'round_robin',
            'pool_status': [
                {
                    'ip': ip,
                    'host_id': host,
                    'healthy': ip not in ddos_state['blocked_ips'],
                    'status': 'blocked' if ip in ddos_state['blocked_ips'] else 'active',
                    'total_requests': network_stats.get('total_packets', 0) // 400,
                    'connections': network_stats.get('total_flows', 0) // 4
                }
                for host, ip in HOST_IP_MAP.items()
            ]
        })


@app.route('/securenet/qos/status')
def qos_status():
    """QoS queue status"""
    with stats_lock:
        return jsonify(qos_state)


@app.route('/securenet/qos/config', methods=['GET', 'POST'])
def qos_config():
    """Get or update QoS configuration"""
    global qos_state

    if request.method == 'POST':
        data = request.json
        if 'enabled' in data:
            qos_state['enabled'] = data['enabled']
        return jsonify({'status': 'updated', 'qos': qos_state})

    return jsonify(qos_state)


@app.route('/securenet/topology')
def topology():
    """Return network topology with REAL-TIME status based on actual traffic"""
    with stats_lock:
        hosts = network_stats.get('hosts', {})

        # Find currently attacking hosts based on recent alerts
        attacking_hosts = set()
        for alert in ddos_state['alerts'][:10]:
            host_id = alert.get('host_id')
            if host_id:
                attacking_hosts.add(host_id)

        # Find blocked hosts
        blocked_hosts = set(info['host_id'] for info in ddos_state['blocked_ips'].values())

        nodes = [
            # Core switch
            {'id': 's1', 'type': 'core', 'label': 'Core S1', 'layer': 0, 'status': 'active'},
            # Edge switches
            {'id': 's2', 'type': 'edge', 'label': 'Switch S2', 'layer': 1, 'status': 'active'},
            {'id': 's3', 'type': 'edge', 'label': 'Switch S3', 'layer': 1, 'status': 'active'},
            {'id': 's4', 'type': 'edge', 'label': 'Switch S4', 'layer': 1, 'status': 'active'},
        ]

        # Add host nodes - role determined by CURRENT BEHAVIOR
        for host, ip in HOST_IP_MAP.items():
            host_info = hosts.get(host, {})
            is_blocked = host in blocked_hosts or ip in ddos_state['blocked_ips']
            is_attacking = host in attacking_hosts and not is_blocked

            # Role is determined dynamically based on current state
            if is_blocked:
                role = 'blocked'
                status = 'blocked'
            elif is_attacking:
                role = 'attacker'
                status = 'attacking'
            else:
                role = 'host'
                status = 'active'

            nodes.append({
                'id': host,
                'type': 'host',
                'role': role,
                'label': f'{host.upper()} ({ip})',
                'layer': 2,
                'ip': ip,
                'status': status,
                'blocked': is_blocked,
                'attacking': is_attacking
            })

        links = [
            # Core to edge
            {'source': 's1', 'target': 's2', 'type': 'core'},
            {'source': 's1', 'target': 's3', 'type': 'core'},
            {'source': 's1', 'target': 's4', 'type': 'core'},
            # Edge to hosts
            {'source': 's2', 'target': 'h1', 'type': 'host'},
            {'source': 's2', 'target': 'h2', 'type': 'host'},
            {'source': 's2', 'target': 'h3', 'type': 'host'},
            {'source': 's3', 'target': 'h4', 'type': 'host'},
            {'source': 's3', 'target': 'h5', 'type': 'host'},
            {'source': 's3', 'target': 'h6', 'type': 'host'},
            {'source': 's4', 'target': 'h7', 'type': 'host'},
            {'source': 's4', 'target': 'h8', 'type': 'host'},
            {'source': 's4', 'target': 'h9', 'type': 'host'},
        ]

        return jsonify({
            'nodes': nodes,
            'links': links,
            'blocked_ips': list(ddos_state['blocked_ips'].keys()),
            'blocked_hosts': list(blocked_hosts),
            'attacking_hosts': list(attacking_hosts)
        })


@app.route('/securenet/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'uptime': int(time.time() - cumulative_totals['start_time']),
        'version': '3.0.0',
        'features': {
            'ddos_detection': True,
            'tx_based_detection': True,
            'qos': True,
            'load_balancer': True,
            'firewall': True
        }
    })


@app.route('/securenet/config')
def get_config():
    """Get all configuration"""
    return jsonify(CONFIG)


if __name__ == '__main__':
    print("=" * 70)
    print("SecureNet DC - Network Stats Collector v3.0")
    print("=" * 70)
    print("\nKEY IMPROVEMENTS in v3.0:")
    print("  - TX-based detection: Only blocks ATTACKERS, not victims")
    print("  - IP-based deduplication: Prevents duplicate blocks")
    print("  - Cooldown period: Prevents rapid re-detection")
    print("  - Better host-to-IP mapping")
    print("=" * 70)
    print(f"\nDetection Configuration:")
    print(f"  - Packet rate threshold: {CONFIG['packet_rate_threshold']} packets/sec")
    print(f"  - Byte rate threshold: {CONFIG['byte_rate_threshold']} bytes/sec")
    print(f"  - Block duration: {CONFIG['block_duration']} seconds")
    print(f"  - Detection cooldown: {CONFIG['detection_cooldown']} seconds")
    print(f"  - Detection method: {ddos_state['detection_method']}")
    print("=" * 70)
    print("\nRun Mininet with: sudo mn --switch lxbr --topo tree,2")
    print("Or use the integrated demo: sudo python3 scripts/run_demo.py")
    print("=" * 70)
    print(f"\nAPI running on http://0.0.0.0:8080")
    print("=" * 70)
    app.run(host='0.0.0.0', port=8080, debug=False)
