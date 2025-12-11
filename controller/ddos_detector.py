"""
SecureNet DC - DDoS Detection Engine
CPEG 460 Bonus Project

Real-time DDoS attack detection using packet rate analysis.
Supports detection of:
- SYN Flood attacks
- ICMP Flood attacks
- UDP Flood attacks
- Slowloris attacks
"""

import time
from collections import defaultdict
from threading import RLock
import logging

logger = logging.getLogger(__name__)


class DDoSDetector:
    """
    DDoS Attack Detection Engine.

    Monitors traffic patterns per source IP and detects anomalies
    that indicate potential DDoS attacks.
    """

    def __init__(self, config):
        """
        Initialize the DDoS detector.

        Args:
            config: NetworkConfig class with DDOS_THRESHOLDS
        """
        self.config = config
        self.thresholds = config.DDOS_THRESHOLDS

        # Traffic counters: {timestamp: {src_ip: {packet_type: count}}}
        self.traffic_stats = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))

        # Blocked hosts: {src_ip: unblock_timestamp}
        self.blocked_hosts = {}

        # Alert history for dashboard
        self.alerts = []
        self.max_alerts = 100

        # Thread safety (RLock for nested calls)
        self.lock = RLock()

        # Statistics
        self.total_attacks_detected = 0
        self.attacks_by_type = defaultdict(int)

        logger.info("DDoS Detector initialized")
        logger.info(f"Thresholds: SYN={self.thresholds['syn_flood']}, "
                   f"ICMP={self.thresholds['icmp_flood']}, "
                   f"UDP={self.thresholds['udp_flood']}")

    def record_packet(self, src_ip, packet_type='normal', dst_port=None):
        """
        Record a packet for traffic analysis.

        Args:
            src_ip: Source IP address
            packet_type: Type of packet ('syn', 'icmp', 'udp', 'http', 'normal')
            dst_port: Destination port (for HTTP-based attacks)
        """
        current_time = int(time.time())

        with self.lock:
            self.traffic_stats[current_time][src_ip]['total'] += 1
            self.traffic_stats[current_time][src_ip][packet_type] += 1

            # Track incomplete HTTP connections for Slowloris
            if packet_type == 'http_incomplete':
                self.traffic_stats[current_time][src_ip]['slowloris'] += 1

            # Clean old data (keep only detection window)
            self._cleanup_old_stats(current_time)

    def check_for_attack(self, src_ip):
        """
        Check if the given source IP is conducting an attack.

        Args:
            src_ip: Source IP to check

        Returns:
            tuple: (attack_detected, attack_type, packet_count) or (False, None, 0)
        """
        if self.is_blocked(src_ip):
            return True, 'BLOCKED', 0

        current_time = int(time.time())
        window = self.thresholds['detection_window']

        with self.lock:
            # Aggregate packet counts over detection window
            stats = defaultdict(int)
            for t in range(current_time - window, current_time + 1):
                if t in self.traffic_stats and src_ip in self.traffic_stats[t]:
                    for ptype, count in self.traffic_stats[t][src_ip].items():
                        stats[ptype] += count

            # Check SYN flood
            if stats['syn'] > self.thresholds['syn_flood']:
                return True, 'SYN_FLOOD', stats['syn']

            # Check ICMP flood
            if stats['icmp'] > self.thresholds['icmp_flood']:
                return True, 'ICMP_FLOOD', stats['icmp']

            # Check UDP flood
            if stats['udp'] > self.thresholds['udp_flood']:
                return True, 'UDP_FLOOD', stats['udp']

            # Check Slowloris
            if stats['slowloris'] > self.thresholds['slowloris']:
                return True, 'SLOWLORIS', stats['slowloris']

            # Check total packet rate
            if stats['total'] > self.thresholds['total_pps']:
                return True, 'VOLUMETRIC', stats['total']

        return False, None, 0

    def block_host(self, src_ip, attack_type, packet_count):
        """
        Block a host identified as an attacker.

        Args:
            src_ip: IP address to block
            attack_type: Type of attack detected
            packet_count: Number of malicious packets

        Returns:
            bool: True if newly blocked, False if already blocked
        """
        if self.is_blocked(src_ip):
            return False

        block_duration = self.thresholds['block_duration']
        unblock_time = time.time() + block_duration

        with self.lock:
            self.blocked_hosts[src_ip] = unblock_time
            self.total_attacks_detected += 1
            self.attacks_by_type[attack_type] += 1

            # Create alert
            alert = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip': src_ip,
                'attack_type': attack_type,
                'packet_count': packet_count,
                'action': 'BLOCKED',
                'duration': block_duration
            }
            self.alerts.append(alert)
            if len(self.alerts) > self.max_alerts:
                self.alerts.pop(0)

            logger.warning(f"[ATTACK DETECTED] {attack_type} from {src_ip} "
                         f"({packet_count} packets) - BLOCKED for {block_duration}s")

        return True

    def is_blocked(self, src_ip):
        """
        Check if an IP is currently blocked.

        Args:
            src_ip: IP address to check

        Returns:
            bool: True if blocked, False otherwise
        """
        with self.lock:
            if src_ip in self.blocked_hosts:
                if time.time() < self.blocked_hosts[src_ip]:
                    return True
                else:
                    # Block expired
                    del self.blocked_hosts[src_ip]
                    logger.info(f"[UNBLOCK] {src_ip} - Block expired")

                    # Add unblock alert
                    alert = {
                        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                        'src_ip': src_ip,
                        'attack_type': 'N/A',
                        'packet_count': 0,
                        'action': 'UNBLOCKED',
                        'duration': 0
                    }
                    self.alerts.append(alert)
        return False

    def unblock_host(self, src_ip):
        """
        Manually unblock a host.

        Args:
            src_ip: IP address to unblock

        Returns:
            bool: True if unblocked, False if not found
        """
        with self.lock:
            if src_ip in self.blocked_hosts:
                del self.blocked_hosts[src_ip]
                logger.info(f"[MANUAL UNBLOCK] {src_ip}")
                return True
        return False

    def get_blocked_hosts(self):
        """
        Get list of currently blocked hosts with remaining time.

        Returns:
            list: List of dicts with 'ip' and 'remaining_time' keys
        """
        current_time = time.time()
        result = []

        with self.lock:
            for ip, unblock_time in list(self.blocked_hosts.items()):
                remaining = max(0, int(unblock_time - current_time))
                if remaining > 0:
                    result.append({
                        'ip': ip,
                        'remaining_time': remaining
                    })
                else:
                    del self.blocked_hosts[ip]

        return result

    def get_alerts(self, limit=20):
        """
        Get recent alerts.

        Args:
            limit: Maximum number of alerts to return

        Returns:
            list: Recent alerts (newest first)
        """
        with self.lock:
            return list(reversed(self.alerts[-limit:]))

    def get_statistics(self):
        """
        Get detection statistics.

        Returns:
            dict: Statistics about detected attacks
        """
        with self.lock:
            return {
                'total_attacks': self.total_attacks_detected,
                'attacks_by_type': dict(self.attacks_by_type),
                'currently_blocked': len(self.blocked_hosts),
                'blocked_hosts': self.get_blocked_hosts()
            }

    def get_traffic_stats(self, src_ip=None):
        """
        Get current traffic statistics.

        Args:
            src_ip: Optional specific IP to get stats for

        Returns:
            dict: Traffic statistics
        """
        current_time = int(time.time())
        window = self.thresholds['detection_window']

        with self.lock:
            if src_ip:
                stats = defaultdict(int)
                for t in range(current_time - window, current_time + 1):
                    if t in self.traffic_stats and src_ip in self.traffic_stats[t]:
                        for ptype, count in self.traffic_stats[t][src_ip].items():
                            stats[ptype] += count
                return dict(stats)
            else:
                # Aggregate all traffic
                all_stats = defaultdict(lambda: defaultdict(int))
                for t in range(current_time - window, current_time + 1):
                    for ip, ip_stats in self.traffic_stats.get(t, {}).items():
                        for ptype, count in ip_stats.items():
                            all_stats[ip][ptype] += count
                return {ip: dict(stats) for ip, stats in all_stats.items()}

    def _cleanup_old_stats(self, current_time):
        """Remove statistics older than detection window."""
        window = self.thresholds['detection_window']
        cutoff = current_time - window - 1

        old_times = [t for t in self.traffic_stats.keys() if t < cutoff]
        for t in old_times:
            del self.traffic_stats[t]

    def analyze_packet(self, pkt_ipv4, pkt_tcp=None, pkt_udp=None, pkt_icmp=None):
        """
        Analyze a packet and determine if it's part of an attack.

        Args:
            pkt_ipv4: IPv4 packet object
            pkt_tcp: TCP packet object (if applicable)
            pkt_udp: UDP packet object (if applicable)
            pkt_icmp: ICMP packet object (if applicable)

        Returns:
            tuple: (should_block, attack_type, packet_count)
        """
        src_ip = str(pkt_ipv4.src)

        # Determine packet type
        if pkt_tcp:
            # Check for SYN without ACK (SYN flood indicator)
            if pkt_tcp.bits & 0x02 and not (pkt_tcp.bits & 0x10):
                self.record_packet(src_ip, 'syn')
            else:
                self.record_packet(src_ip, 'tcp')
        elif pkt_udp:
            self.record_packet(src_ip, 'udp')
        elif pkt_icmp:
            self.record_packet(src_ip, 'icmp')
        else:
            self.record_packet(src_ip, 'normal')

        # Check for attack
        is_attack, attack_type, count = self.check_for_attack(src_ip)

        if is_attack and attack_type != 'BLOCKED':
            # New attack detected
            self.block_host(src_ip, attack_type, count)
            return True, attack_type, count

        return is_attack, attack_type, count
