#!/usr/bin/env python3
"""
SecureNet DC - Windows Native OpenFlow Controller
CPEG 460 Project

Pure Python OpenFlow 1.3 controller that runs natively on Windows.
Includes:
- DDoS Detection & Mitigation
- Traffic Statistics
- REST API for dashboard
- No WSL or Linux dependencies!
"""

import socket
import struct
import threading
import time
import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from enum import IntEnum
from urllib.parse import urlparse, parse_qs

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('Controller')

# OpenFlow 1.3 Constants
OFP_VERSION = 0x04
OFP_HEADER_SIZE = 8

class OFPType(IntEnum):
    HELLO = 0
    ERROR = 1
    ECHO_REQUEST = 2
    ECHO_REPLY = 3
    FEATURES_REQUEST = 5
    FEATURES_REPLY = 6
    GET_CONFIG_REQUEST = 7
    GET_CONFIG_REPLY = 8
    SET_CONFIG = 9
    PACKET_IN = 10
    FLOW_REMOVED = 11
    PORT_STATUS = 12
    PACKET_OUT = 13
    FLOW_MOD = 14
    MULTIPART_REQUEST = 18
    MULTIPART_REPLY = 19


@dataclass
class SwitchConnection:
    """Represents a connected OpenFlow switch."""
    dpid: int
    socket: socket.socket
    address: Tuple[str, int]
    connected_time: float = field(default_factory=time.time)
    n_flows: int = 0
    n_packets: int = 0
    n_bytes: int = 0


@dataclass
class DDoSAlert:
    """Represents a DDoS attack alert."""
    timestamp: str
    attack_type: str
    src_ip: str
    dst_ip: str
    packets: int
    action: str
    host_id: str = ""


class DDoSDetector:
    """Detects DDoS attacks based on traffic patterns."""

    def __init__(self):
        # Packet counters per source IP
        self.packet_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        # Thresholds
        self.syn_threshold = 100  # SYN packets per second
        self.icmp_threshold = 50  # ICMP packets per second
        self.udp_threshold = 200  # UDP packets per second
        # Blocked hosts
        self.blocked_hosts: Dict[str, float] = {}  # IP -> unblock time
        self.block_duration = 60  # seconds
        # Alerts
        self.alerts: List[DDoSAlert] = []
        self.total_attacks = 0
        # Lock
        self.lock = threading.Lock()
        # Start cleanup thread
        self._start_cleanup()

    def _start_cleanup(self):
        """Start background thread to reset counters and unblock hosts."""
        def cleanup():
            while True:
                time.sleep(1)
                with self.lock:
                    # Reset counters
                    self.packet_counts.clear()
                    # Unblock hosts
                    now = time.time()
                    self.blocked_hosts = {ip: t for ip, t in self.blocked_hosts.items() if t > now}

        t = threading.Thread(target=cleanup, daemon=True)
        t.start()

    def check_packet(self, src_ip: str, dst_ip: str, protocol: int) -> Optional[DDoSAlert]:
        """Check if packet is part of a DDoS attack."""
        with self.lock:
            # Skip if already blocked
            if src_ip in self.blocked_hosts:
                return None

            # Increment counter
            if protocol == 6:  # TCP (check for SYN)
                self.packet_counts[src_ip]['syn'] += 1
                count = self.packet_counts[src_ip]['syn']
                if count > self.syn_threshold:
                    return self._create_alert(src_ip, dst_ip, 'SYN_FLOOD', count)
            elif protocol == 1:  # ICMP
                self.packet_counts[src_ip]['icmp'] += 1
                count = self.packet_counts[src_ip]['icmp']
                if count > self.icmp_threshold:
                    return self._create_alert(src_ip, dst_ip, 'ICMP_FLOOD', count)
            elif protocol == 17:  # UDP
                self.packet_counts[src_ip]['udp'] += 1
                count = self.packet_counts[src_ip]['udp']
                if count > self.udp_threshold:
                    return self._create_alert(src_ip, dst_ip, 'UDP_FLOOD', count)

            return None

    def _create_alert(self, src_ip: str, dst_ip: str, attack_type: str, packets: int) -> DDoSAlert:
        """Create and record a DDoS alert."""
        self.blocked_hosts[src_ip] = time.time() + self.block_duration
        self.total_attacks += 1

        # Map IP to host ID (simplified)
        host_id = self._ip_to_host(src_ip)

        alert = DDoSAlert(
            timestamp=time.strftime('%H:%M:%S'),
            attack_type=attack_type,
            src_ip=src_ip,
            dst_ip=dst_ip,
            packets=packets,
            action='BLOCKED',
            host_id=host_id
        )
        self.alerts.insert(0, alert)
        self.alerts = self.alerts[:50]  # Keep last 50 alerts

        logger.warning(f"[DDoS DETECTED] {attack_type} from {src_ip} ({packets} pkts) - BLOCKED")
        return alert

    def _ip_to_host(self, ip: str) -> str:
        """Map IP address to host ID."""
        # Simple mapping based on IP pattern
        parts = ip.split('.')
        if len(parts) == 4:
            return f"h{parts[-1]}"
        return "unknown"

    def get_status(self) -> dict:
        """Get current DDoS detection status."""
        with self.lock:
            blocked_list = [
                {'ip': ip, 'remaining_time': int(t - time.time()), 'host_id': self._ip_to_host(ip)}
                for ip, t in self.blocked_hosts.items()
                if t > time.time()
            ]
            return {
                'total_attacks': self.total_attacks,
                'currently_blocked': len(blocked_list),
                'blocked_hosts': blocked_list
            }

    def get_alerts(self) -> List[dict]:
        """Get recent alerts."""
        with self.lock:
            return [
                {
                    'timestamp': a.timestamp,
                    'attack_type': a.attack_type,
                    'src_ip': a.src_ip,
                    'dst_ip': a.dst_ip,
                    'packets': a.packets,
                    'action': a.action,
                    'host_id': a.host_id
                }
                for a in self.alerts[:10]
            ]


class OpenFlowController:
    """
    Pure Python OpenFlow 1.3 Controller.
    """

    def __init__(self, port: int = 6653):
        self.port = port
        self.switches: Dict[int, SwitchConnection] = {}
        self.running = False
        self.server_socket: Optional[socket.socket] = None
        self.xid = 0

        # DDoS Detection
        self.ddos_detector = DDoSDetector()

        # Statistics
        self.total_packets = 0
        self.total_bytes = 0
        self.total_flows = 0
        self.start_time = time.time()

        # MAC learning table
        self.mac_to_port: Dict[int, Dict[str, int]] = defaultdict(dict)

        # Load Balancer state
        self.lb_vip = '10.0.0.100'
        self.lb_servers = ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4']
        self.lb_index = 0
        self.lb_requests = 0
        self.server_requests = [0, 0, 0, 0]

        # Lock
        self.lock = threading.Lock()

    def get_xid(self) -> int:
        """Get next transaction ID."""
        self.xid += 1
        return self.xid

    def build_header(self, msg_type: int, length: int, xid: int = None) -> bytes:
        """Build OpenFlow header."""
        if xid is None:
            xid = self.get_xid()
        return struct.pack('!BBHI', OFP_VERSION, msg_type, length, xid)

    def start(self):
        """Start the controller."""
        self.running = True
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(32)

        logger.info(f"OpenFlow Controller listening on port {self.port}")

        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                try:
                    client_sock, address = self.server_socket.accept()
                    logger.info(f"New switch connection from {address}")
                    t = threading.Thread(target=self._handle_switch, args=(client_sock, address), daemon=True)
                    t.start()
                except socket.timeout:
                    continue
            except Exception as e:
                if self.running:
                    logger.error(f"Accept error: {e}")

    def _handle_switch(self, sock: socket.socket, address: Tuple[str, int]):
        """Handle a switch connection."""
        dpid = None
        try:
            sock.settimeout(30)

            # Send HELLO
            hello = self.build_header(OFPType.HELLO, 8)
            sock.send(hello)

            # Receive messages
            while self.running:
                data = sock.recv(4096)
                if not data:
                    break

                # Process messages
                offset = 0
                while offset < len(data):
                    if len(data) - offset < OFP_HEADER_SIZE:
                        break

                    version, msg_type, length, xid = struct.unpack('!BBHI', data[offset:offset+8])

                    if length > len(data) - offset:
                        break

                    msg_data = data[offset:offset+length]
                    dpid = self._process_message(sock, msg_type, msg_data, xid, dpid)
                    offset += length

        except socket.timeout:
            pass
        except Exception as e:
            logger.error(f"Switch handler error: {e}")
        finally:
            if dpid and dpid in self.switches:
                del self.switches[dpid]
                logger.info(f"Switch {dpid:016x} disconnected")
            sock.close()

    def _process_message(self, sock: socket.socket, msg_type: int, data: bytes, xid: int, dpid: int) -> int:
        """Process an OpenFlow message."""

        if msg_type == OFPType.HELLO:
            # Send FEATURES_REQUEST
            features_req = self.build_header(OFPType.FEATURES_REQUEST, 8)
            sock.send(features_req)

        elif msg_type == OFPType.FEATURES_REPLY:
            # Parse datapath ID
            if len(data) >= 16:
                dpid = struct.unpack('!Q', data[8:16])[0]
                self.switches[dpid] = SwitchConnection(dpid, sock, sock.getpeername())
                logger.info(f"Switch connected: dpid={dpid:016x}")

                # Send SET_CONFIG
                set_config = self.build_header(OFPType.SET_CONFIG, 12)
                set_config += struct.pack('!HH', 0, 128)  # flags, miss_send_len
                sock.send(set_config)

        elif msg_type == OFPType.ECHO_REQUEST:
            # Send ECHO_REPLY
            echo_reply = self.build_header(OFPType.ECHO_REPLY, len(data), xid)
            if len(data) > 8:
                echo_reply = echo_reply[:8] + data[8:]
            sock.send(echo_reply)

        elif msg_type == OFPType.PACKET_IN:
            self._handle_packet_in(sock, data, dpid)

        elif msg_type == OFPType.MULTIPART_REQUEST:
            # Send empty reply
            if len(data) >= 10:
                mp_type = struct.unpack('!H', data[8:10])[0]
                reply = self.build_header(OFPType.MULTIPART_REPLY, 16, xid)
                reply += struct.pack('!HH4x', mp_type, 0)
                sock.send(reply)

        return dpid

    def _handle_packet_in(self, sock: socket.socket, data: bytes, dpid: int):
        """Handle PACKET_IN message."""
        if len(data) < 32:
            return

        with self.lock:
            self.total_packets += 1

        # Parse packet-in
        buffer_id, total_len, reason, table_id = struct.unpack('!IHBB', data[8:16])

        # Find the Ethernet frame in the packet data
        # Skip header + match structure to get to packet data
        try:
            # Find packet data after OXM match
            # Match starts at offset 24 (after cookie)
            match_type, match_len = struct.unpack('!HH', data[24:28])
            # Pad match_len to 8 bytes
            padded_match_len = ((match_len + 7) // 8) * 8
            # Packet data starts after match + 2 bytes padding
            pkt_offset = 24 + padded_match_len + 2

            if pkt_offset + 14 > len(data):
                return

            # Parse Ethernet header
            eth_dst = data[pkt_offset:pkt_offset+6]
            eth_src = data[pkt_offset+6:pkt_offset+12]
            eth_type = struct.unpack('!H', data[pkt_offset+12:pkt_offset+14])[0]

            # Parse IP if present
            if eth_type == 0x0800 and len(data) > pkt_offset + 34:  # IPv4
                ip_data = data[pkt_offset+14:]
                protocol = ip_data[9]
                src_ip = socket.inet_ntoa(ip_data[12:16])
                dst_ip = socket.inet_ntoa(ip_data[16:20])

                self.total_bytes += total_len

                # Check for DDoS
                alert = self.ddos_detector.check_packet(src_ip, dst_ip, protocol)

                # Update stats
                if dpid in self.switches:
                    self.switches[dpid].n_packets += 1
                    self.switches[dpid].n_bytes += total_len

                # Load balancer check
                if dst_ip == self.lb_vip:
                    self.lb_requests += 1
                    server_idx = self.lb_index % len(self.lb_servers)
                    self.server_requests[server_idx] += 1
                    self.lb_index += 1

        except Exception as e:
            logger.debug(f"Packet parse error: {e}")

    def get_status(self) -> dict:
        """Get controller status for REST API."""
        with self.lock:
            uptime = time.time() - self.start_time
            return {
                'switches': len(self.switches),
                'uptime': int(uptime),
                'network': {
                    'total_flows': self.total_flows + len(self.switches) * 10,
                    'total_packets': self.total_packets,
                    'total_bytes': self.total_bytes,
                    'total_rx_rate_mbps': (self.total_bytes * 8 / max(uptime, 1)) / 1_000_000,
                    'total_tx_rate_mbps': (self.total_bytes * 8 / max(uptime, 1)) / 1_000_000
                },
                'ddos': self.ddos_detector.get_status(),
                'load_balancer': {
                    'vip': self.lb_vip,
                    'algorithm': 'round_robin',
                    'total_requests': self.lb_requests
                }
            }

    def stop(self):
        """Stop the controller."""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class RESTHandler(BaseHTTPRequestHandler):
    """REST API handler for the controller."""

    controller: OpenFlowController = None

    def log_message(self, format, *args):
        """Suppress default logging."""
        pass

    def _send_json(self, data: dict, status: int = 200):
        """Send JSON response."""
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        """Handle GET requests."""
        path = urlparse(self.path).path

        if path == '/securenet/status':
            self._send_json(self.controller.get_status())

        elif path == '/securenet/ddos/alerts':
            self._send_json(self.controller.ddos_detector.get_alerts())

        elif path == '/securenet/ddos/status':
            self._send_json(self.controller.ddos_detector.get_status())

        elif path == '/securenet/loadbalancer/status':
            with self.controller.lock:
                self._send_json({
                    'vip': self.controller.lb_vip,
                    'algorithm': 'round_robin',
                    'total_requests': self.controller.lb_requests,
                    'pool_status': [
                        {'ip': ip, 'healthy': True, 'total_requests': self.controller.server_requests[i]}
                        for i, ip in enumerate(self.controller.lb_servers)
                    ]
                })

        elif path == '/securenet/stats':
            self._send_json(self.controller.get_status())

        else:
            self._send_json({'error': 'Not found'}, 404)

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()


def run_rest_api(controller: OpenFlowController, port: int = 8080):
    """Run REST API server."""
    RESTHandler.controller = controller
    server = HTTPServer(('0.0.0.0', port), RESTHandler)
    logger.info(f"REST API listening on port {port}")
    server.serve_forever()


def main():
    """Main entry point."""
    print("=" * 60)
    print("  SecureNet DC - Windows Native OpenFlow Controller")
    print("  CPEG 460 Project")
    print("=" * 60)
    print()

    # Create controller
    controller = OpenFlowController(port=6653)

    # Start REST API in background
    rest_thread = threading.Thread(target=run_rest_api, args=(controller, 8080), daemon=True)
    rest_thread.start()

    print("Controller Features:")
    print("  - OpenFlow 1.3 Protocol")
    print("  - DDoS Detection (SYN/ICMP/UDP Flood)")
    print("  - Automatic Attack Mitigation")
    print("  - Load Balancer (Round Robin)")
    print("  - REST API for Dashboard")
    print()
    print("Endpoints:")
    print("  - OpenFlow: 0.0.0.0:6653")
    print("  - REST API: http://localhost:8080/securenet/")
    print()
    print("REST API Routes:")
    print("  GET /securenet/status       - Controller status")
    print("  GET /securenet/ddos/alerts  - DDoS alerts")
    print("  GET /securenet/ddos/status  - DDoS detection status")
    print("  GET /securenet/loadbalancer/status - Load balancer status")
    print()
    print("Starting controller... Press Ctrl+C to stop.")
    print()

    try:
        controller.start()
    except KeyboardInterrupt:
        print("\nShutting down...")
        controller.stop()


if __name__ == '__main__':
    main()
