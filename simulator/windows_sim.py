#!/usr/bin/env python3
"""
SecureNet DC - Windows Native Network Simulator
CPEG 460 Project

Pure Python OpenFlow switch simulator that connects to Ryu controller.
No WSL or Linux required - runs 100% on Windows!

This simulator:
1. Creates virtual OpenFlow switches that connect to the controller
2. Simulates hosts generating traffic (packet-in events)
3. Simulates DDoS attacks (flood of packet-in events)
4. All using real OpenFlow protocol messages
"""

import socket
import struct
import threading
import time
import random
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional
from enum import IntEnum

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('WindowsSim')

# OpenFlow 1.3 Constants
OFP_VERSION = 0x04  # OpenFlow 1.3
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

class OFPPacketInReason(IntEnum):
    NO_MATCH = 0
    ACTION = 1
    INVALID_TTL = 2

@dataclass
class VirtualHost:
    """Represents a virtual host in the network."""
    name: str
    ip: str
    mac: str
    switch_id: int
    port: int
    role: str = "normal"  # normal, attacker, server, ids

@dataclass
class VirtualSwitch:
    """Represents a virtual OpenFlow switch."""
    dpid: int
    name: str
    n_ports: int
    socket: Optional[socket.socket] = None
    connected: bool = False
    xid: int = 0

class OpenFlowSwitch:
    """
    Simulates an OpenFlow 1.3 switch that connects to a controller.
    """

    def __init__(self, dpid: int, name: str, n_ports: int = 8):
        self.dpid = dpid
        self.name = name
        self.n_ports = n_ports
        self.sock: Optional[socket.socket] = None
        self.connected = False
        self.xid = 0
        self.running = False
        self.flow_table: List[dict] = []

    def get_xid(self) -> int:
        """Get next transaction ID."""
        self.xid += 1
        return self.xid

    def build_header(self, msg_type: int, length: int, xid: int = None) -> bytes:
        """Build OpenFlow header."""
        if xid is None:
            xid = self.get_xid()
        return struct.pack('!BBHI', OFP_VERSION, msg_type, length, xid)

    def build_hello(self) -> bytes:
        """Build HELLO message."""
        return self.build_header(OFPType.HELLO, 8)

    def build_features_reply(self, xid: int) -> bytes:
        """Build FEATURES_REPLY message."""
        # OpenFlow 1.3 features reply
        # Header (8) + datapath_id (8) + n_buffers (4) + n_tables (1) +
        # auxiliary_id (1) + pad (2) + capabilities (4) + reserved (4) = 32 bytes
        header = self.build_header(OFPType.FEATURES_REPLY, 32, xid)
        body = struct.pack('!QI2BHI4x',
            self.dpid,      # datapath_id
            256,            # n_buffers
            254,            # n_tables
            0,              # auxiliary_id
            0,              # pad
            0x0000004f      # capabilities (flow stats, table stats, port stats, etc.)
        )
        return header + body

    def build_echo_reply(self, xid: int, data: bytes = b'') -> bytes:
        """Build ECHO_REPLY message."""
        length = 8 + len(data)
        header = self.build_header(OFPType.ECHO_REPLY, length, xid)
        return header + data

    def build_packet_in(self, buffer_id: int, in_port: int, reason: int,
                        eth_src: str, eth_dst: str, eth_type: int,
                        src_ip: str = None, dst_ip: str = None,
                        ip_proto: int = None, src_port: int = None, dst_port: int = None) -> bytes:
        """Build PACKET_IN message with Ethernet frame."""

        # Build Ethernet frame
        eth_frame = self._build_ethernet_frame(eth_src, eth_dst, eth_type,
                                                src_ip, dst_ip, ip_proto, src_port, dst_port)

        # OXM match for in_port
        # OXM header: class (2) + field (1) + hasmask (1 bit) + length (7 bits)
        oxm_in_port = struct.pack('!HBB', 0x8000, 0x00, 4) + struct.pack('!I', in_port)  # IN_PORT

        match_length = 4 + len(oxm_in_port)  # type (2) + length (2) + oxm fields
        # Pad to 8-byte boundary
        match_pad = (8 - (match_length % 8)) % 8

        match = struct.pack('!HH', 1, match_length) + oxm_in_port + (b'\x00' * match_pad)

        # Packet-in body
        # buffer_id (4) + total_len (2) + reason (1) + table_id (1) + cookie (8) + match + pad (2) + data
        total_len = len(eth_frame)

        body = struct.pack('!IHBB',
            buffer_id,
            total_len,
            reason,
            0  # table_id
        )
        body += struct.pack('!Q', 0)  # cookie
        body += match
        body += struct.pack('!H', 0)  # pad
        body += eth_frame

        length = 8 + len(body)
        header = self.build_header(OFPType.PACKET_IN, length)

        return header + body

    def _build_ethernet_frame(self, eth_src: str, eth_dst: str, eth_type: int,
                               src_ip: str = None, dst_ip: str = None,
                               ip_proto: int = None, src_port: int = None, dst_port: int = None) -> bytes:
        """Build an Ethernet frame with optional IP/TCP/UDP headers."""

        # Convert MAC addresses
        src_mac = bytes.fromhex(eth_src.replace(':', ''))
        dst_mac = bytes.fromhex(eth_dst.replace(':', ''))

        frame = dst_mac + src_mac + struct.pack('!H', eth_type)

        if eth_type == 0x0800 and src_ip and dst_ip:  # IPv4
            # IP header (20 bytes minimum)
            ip_header = self._build_ip_header(src_ip, dst_ip, ip_proto or 6)
            frame += ip_header

            if ip_proto == 6 and src_port and dst_port:  # TCP
                tcp_header = self._build_tcp_header(src_port, dst_port)
                frame += tcp_header
            elif ip_proto == 17 and src_port and dst_port:  # UDP
                udp_header = self._build_udp_header(src_port, dst_port)
                frame += udp_header
            elif ip_proto == 1:  # ICMP
                icmp_header = self._build_icmp_header()
                frame += icmp_header

        return frame

    def _build_ip_header(self, src_ip: str, dst_ip: str, protocol: int) -> bytes:
        """Build IPv4 header."""
        version_ihl = (4 << 4) | 5  # IPv4, 5 words (20 bytes)
        tos = 0
        total_length = 40  # IP header + TCP/UDP header
        identification = random.randint(0, 65535)
        flags_fragment = 0x4000  # Don't fragment
        ttl = 64
        checksum = 0  # Would need to calculate

        src = socket.inet_aton(src_ip)
        dst = socket.inet_aton(dst_ip)

        return struct.pack('!BBHHHBBH4s4s',
            version_ihl, tos, total_length, identification,
            flags_fragment, ttl, protocol, checksum, src, dst)

    def _build_tcp_header(self, src_port: int, dst_port: int, flags: int = 0x02) -> bytes:
        """Build TCP header. Default flags = SYN."""
        seq = random.randint(0, 2**32-1)
        ack = 0
        data_offset = 5 << 4  # 5 words (20 bytes)
        window = 65535
        checksum = 0
        urgent = 0

        return struct.pack('!HHIIBBHHH',
            src_port, dst_port, seq, ack,
            data_offset, flags, window, checksum, urgent)

    def _build_udp_header(self, src_port: int, dst_port: int) -> bytes:
        """Build UDP header."""
        length = 8
        checksum = 0
        return struct.pack('!HHHH', src_port, dst_port, length, checksum)

    def _build_icmp_header(self, icmp_type: int = 8, code: int = 0) -> bytes:
        """Build ICMP header (echo request by default)."""
        checksum = 0
        identifier = random.randint(0, 65535)
        sequence = random.randint(0, 65535)
        return struct.pack('!BBHHH', icmp_type, code, checksum, identifier, sequence)

    def connect(self, controller_ip: str = '127.0.0.1', controller_port: int = 6653) -> bool:
        """Connect to the OpenFlow controller."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(10)
            self.sock.connect((controller_ip, controller_port))
            self.connected = True
            logger.info(f"Switch {self.name} (dpid={self.dpid}) connected to controller")
            return True
        except Exception as e:
            logger.error(f"Switch {self.name} failed to connect: {e}")
            return False

    def handshake(self) -> bool:
        """Perform OpenFlow handshake."""
        try:
            # Send HELLO
            self.sock.send(self.build_hello())
            logger.debug(f"{self.name}: Sent HELLO")

            # Receive and process messages
            self.running = True
            while self.running:
                data = self.sock.recv(4096)
                if not data:
                    break
                self._process_message(data)

        except socket.timeout:
            pass
        except Exception as e:
            logger.error(f"{self.name} handshake error: {e}")
            return False
        return True

    def _process_message(self, data: bytes):
        """Process received OpenFlow message."""
        if len(data) < OFP_HEADER_SIZE:
            return

        version, msg_type, length, xid = struct.unpack('!BBHI', data[:8])

        if msg_type == OFPType.HELLO:
            logger.debug(f"{self.name}: Received HELLO")

        elif msg_type == OFPType.FEATURES_REQUEST:
            logger.debug(f"{self.name}: Received FEATURES_REQUEST, sending reply")
            self.sock.send(self.build_features_reply(xid))

        elif msg_type == OFPType.ECHO_REQUEST:
            echo_data = data[8:length] if length > 8 else b''
            self.sock.send(self.build_echo_reply(xid, echo_data))

        elif msg_type == OFPType.SET_CONFIG:
            logger.debug(f"{self.name}: Received SET_CONFIG")

        elif msg_type == OFPType.FLOW_MOD:
            logger.debug(f"{self.name}: Received FLOW_MOD")

        elif msg_type == OFPType.PACKET_OUT:
            logger.debug(f"{self.name}: Received PACKET_OUT")

        elif msg_type == OFPType.MULTIPART_REQUEST:
            # Send empty multipart reply
            self._send_multipart_reply(xid, data[8:])

    def _send_multipart_reply(self, xid: int, request_data: bytes):
        """Send multipart reply."""
        if len(request_data) >= 2:
            mp_type = struct.unpack('!H', request_data[:2])[0]
            # Send empty reply for most types
            header = self.build_header(OFPType.MULTIPART_REPLY, 16, xid)
            body = struct.pack('!HH4x', mp_type, 0)  # type, flags, pad
            self.sock.send(header + body)

    def send_packet_in(self, in_port: int, eth_src: str, eth_dst: str, eth_type: int,
                       src_ip: str = None, dst_ip: str = None, ip_proto: int = None,
                       src_port: int = None, dst_port: int = None):
        """Send a packet-in event to the controller."""
        if not self.connected or not self.sock:
            return

        buffer_id = random.randint(1, 2**31)
        pkt_in = self.build_packet_in(
            buffer_id, in_port, OFPPacketInReason.NO_MATCH,
            eth_src, eth_dst, eth_type,
            src_ip, dst_ip, ip_proto, src_port, dst_port
        )
        try:
            self.sock.send(pkt_in)
        except Exception as e:
            logger.error(f"{self.name} send_packet_in error: {e}")

    def disconnect(self):
        """Disconnect from controller."""
        self.running = False
        self.connected = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
        logger.info(f"Switch {self.name} disconnected")


class NetworkSimulator:
    """
    Main network simulator that creates switches, hosts, and generates traffic.
    """

    def __init__(self, controller_ip: str = '127.0.0.1', controller_port: int = 6653):
        self.controller_ip = controller_ip
        self.controller_port = controller_port
        self.switches: Dict[int, OpenFlowSwitch] = {}
        self.hosts: Dict[str, VirtualHost] = {}
        self.running = False
        self.traffic_thread: Optional[threading.Thread] = None
        self.attack_threads: List[threading.Thread] = []

    def create_fattree_topology(self, k: int = 4):
        """Create a Fat-Tree topology with k pods."""
        logger.info(f"Creating Fat-Tree topology with k={k}")

        # Core switches: (k/2)^2
        n_core = (k // 2) ** 2
        for i in range(n_core):
            dpid = 0x100 + i
            sw = OpenFlowSwitch(dpid, f"core_{i+1}", n_ports=k)
            self.switches[dpid] = sw

        # Aggregation and Edge switches: k pods * k switches per pod
        for pod in range(k):
            # Aggregation switches
            for agg in range(k // 2):
                dpid = 0x200 + pod * (k // 2) + agg
                sw = OpenFlowSwitch(dpid, f"agg_{pod}_{agg}", n_ports=k)
                self.switches[dpid] = sw

            # Edge switches
            for edge in range(k // 2):
                dpid = 0x300 + pod * (k // 2) + edge
                sw = OpenFlowSwitch(dpid, f"edge_{pod}_{edge}", n_ports=k)
                self.switches[dpid] = sw

        # Create hosts: k^3/4 hosts
        n_hosts = (k ** 3) // 4
        host_roles = ['web', 'web', 'web', 'web', 'db', 'db',
                      'client', 'client', 'client', 'client', 'client', 'client',
                      'attacker', 'ids', 'streaming', 'streaming']

        for i in range(min(n_hosts, 16)):
            pod = i // (k // 2)
            edge = i % (k // 2)
            port = (i % 2) + 1

            host = VirtualHost(
                name=f"h{i+1}",
                ip=f"10.0.{pod}.{i+1}",
                mac=f"00:00:00:00:{pod:02x}:{i+1:02x}",
                switch_id=0x300 + pod * (k // 2) + edge,
                port=port,
                role=host_roles[i] if i < len(host_roles) else 'client'
            )
            self.hosts[host.name] = host

        logger.info(f"Created {len(self.switches)} switches and {len(self.hosts)} hosts")

    def connect_all(self) -> bool:
        """Connect all switches to the controller."""
        logger.info("Connecting switches to controller...")
        threads = []

        for dpid, switch in self.switches.items():
            if switch.connect(self.controller_ip, self.controller_port):
                t = threading.Thread(target=switch.handshake, daemon=True)
                t.start()
                threads.append(t)
                time.sleep(0.1)  # Stagger connections

        # Wait for handshakes
        time.sleep(2)
        connected = sum(1 for sw in self.switches.values() if sw.connected)
        logger.info(f"Connected {connected}/{len(self.switches)} switches")
        return connected > 0

    def start_normal_traffic(self, packets_per_second: int = 10):
        """Start generating normal background traffic."""
        self.running = True

        def traffic_generator():
            while self.running:
                # Pick random source and destination hosts
                src_host = random.choice(list(self.hosts.values()))
                dst_host = random.choice([h for h in self.hosts.values() if h.name != src_host.name])

                # Get the switch
                switch = self.switches.get(src_host.switch_id)
                if switch and switch.connected:
                    # Generate random traffic type
                    traffic_type = random.choice(['http', 'https', 'dns', 'icmp'])

                    if traffic_type == 'http':
                        switch.send_packet_in(
                            src_host.port, src_host.mac, dst_host.mac, 0x0800,
                            src_host.ip, dst_host.ip, 6, random.randint(1024, 65535), 80
                        )
                    elif traffic_type == 'https':
                        switch.send_packet_in(
                            src_host.port, src_host.mac, dst_host.mac, 0x0800,
                            src_host.ip, dst_host.ip, 6, random.randint(1024, 65535), 443
                        )
                    elif traffic_type == 'dns':
                        switch.send_packet_in(
                            src_host.port, src_host.mac, dst_host.mac, 0x0800,
                            src_host.ip, dst_host.ip, 17, random.randint(1024, 65535), 53
                        )
                    elif traffic_type == 'icmp':
                        switch.send_packet_in(
                            src_host.port, src_host.mac, dst_host.mac, 0x0800,
                            src_host.ip, dst_host.ip, 1
                        )

                time.sleep(1.0 / packets_per_second)

        self.traffic_thread = threading.Thread(target=traffic_generator, daemon=True)
        self.traffic_thread.start()
        logger.info(f"Started normal traffic generation ({packets_per_second} pps)")

    def launch_syn_flood(self, attacker: str, target: str, duration: int = 10, pps: int = 100):
        """Launch a SYN flood attack from attacker to target."""
        attacker_host = self.hosts.get(attacker)
        target_host = self.hosts.get(target)

        if not attacker_host or not target_host:
            logger.error(f"Invalid attacker or target host")
            return

        logger.warning(f"[ATTACK] SYN FLOOD: {attacker} -> {target} for {duration}s at {pps} pps")

        def syn_flood():
            switch = self.switches.get(attacker_host.switch_id)
            end_time = time.time() + duration

            while time.time() < end_time and self.running:
                if switch and switch.connected:
                    # Send SYN packet (TCP flags = 0x02)
                    switch.send_packet_in(
                        attacker_host.port, attacker_host.mac, target_host.mac, 0x0800,
                        attacker_host.ip, target_host.ip, 6,  # TCP
                        random.randint(1024, 65535), 80
                    )
                time.sleep(1.0 / pps)

            logger.info(f"[ATTACK END] SYN FLOOD from {attacker} completed")

        t = threading.Thread(target=syn_flood, daemon=True)
        t.start()
        self.attack_threads.append(t)

    def launch_icmp_flood(self, attacker: str, target: str, duration: int = 10, pps: int = 50):
        """Launch an ICMP flood attack."""
        attacker_host = self.hosts.get(attacker)
        target_host = self.hosts.get(target)

        if not attacker_host or not target_host:
            logger.error(f"Invalid attacker or target host")
            return

        logger.warning(f"[ATTACK] ICMP FLOOD: {attacker} -> {target} for {duration}s at {pps} pps")

        def icmp_flood():
            switch = self.switches.get(attacker_host.switch_id)
            end_time = time.time() + duration

            while time.time() < end_time and self.running:
                if switch and switch.connected:
                    switch.send_packet_in(
                        attacker_host.port, attacker_host.mac, target_host.mac, 0x0800,
                        attacker_host.ip, target_host.ip, 1  # ICMP
                    )
                time.sleep(1.0 / pps)

            logger.info(f"[ATTACK END] ICMP FLOOD from {attacker} completed")

        t = threading.Thread(target=icmp_flood, daemon=True)
        t.start()
        self.attack_threads.append(t)

    def launch_udp_flood(self, attacker: str, target: str, duration: int = 10, pps: int = 200):
        """Launch a UDP flood attack."""
        attacker_host = self.hosts.get(attacker)
        target_host = self.hosts.get(target)

        if not attacker_host or not target_host:
            logger.error(f"Invalid attacker or target host")
            return

        logger.warning(f"[ATTACK] UDP FLOOD: {attacker} -> {target} for {duration}s at {pps} pps")

        def udp_flood():
            switch = self.switches.get(attacker_host.switch_id)
            end_time = time.time() + duration

            while time.time() < end_time and self.running:
                if switch and switch.connected:
                    switch.send_packet_in(
                        attacker_host.port, attacker_host.mac, target_host.mac, 0x0800,
                        attacker_host.ip, target_host.ip, 17,  # UDP
                        random.randint(1024, 65535), random.randint(1, 65535)
                    )
                time.sleep(1.0 / pps)

            logger.info(f"[ATTACK END] UDP FLOOD from {attacker} completed")

        t = threading.Thread(target=udp_flood, daemon=True)
        t.start()
        self.attack_threads.append(t)

    def stop(self):
        """Stop the simulator."""
        logger.info("Stopping simulator...")
        self.running = False

        for switch in self.switches.values():
            switch.disconnect()

        logger.info("Simulator stopped")


def main():
    """Main entry point for the Windows simulator."""
    print("=" * 60)
    print("  SecureNet DC - Windows Native Network Simulator")
    print("  CPEG 460 Project")
    print("=" * 60)
    print()

    # Create simulator
    sim = NetworkSimulator()

    # Create Fat-Tree topology
    sim.create_fattree_topology(k=4)

    # Connect to controller
    print("\nConnecting to controller at 127.0.0.1:6653...")
    print("Make sure the Ryu controller is running!")
    print()

    if not sim.connect_all():
        print("Failed to connect to controller. Is it running?")
        print("Start controller with: ryu-manager controller/securenet_controller.py")
        return

    # Start normal traffic
    sim.start_normal_traffic(packets_per_second=20)

    print("\n" + "=" * 60)
    print("  Simulator Running - Interactive Mode")
    print("=" * 60)
    print("\nCommands:")
    print("  syn <attacker> <target> [duration] [pps] - Launch SYN flood")
    print("  icmp <attacker> <target> [duration] [pps] - Launch ICMP flood")
    print("  udp <attacker> <target> [duration] [pps] - Launch UDP flood")
    print("  hosts - List all hosts")
    print("  status - Show simulator status")
    print("  quit - Stop simulator")
    print()
    print("Example: syn h13 h1 10 100")
    print("         (SYN flood from h13 to h1 for 10 seconds at 100 pps)")
    print()

    try:
        while True:
            cmd = input("sim> ").strip().lower().split()
            if not cmd:
                continue

            if cmd[0] == 'quit' or cmd[0] == 'exit':
                break

            elif cmd[0] == 'hosts':
                print("\nHosts:")
                for name, host in sorted(sim.hosts.items()):
                    print(f"  {name}: IP={host.ip}, Role={host.role}, Switch=0x{host.switch_id:x}")
                print()

            elif cmd[0] == 'status':
                connected = sum(1 for sw in sim.switches.values() if sw.connected)
                print(f"\nSwitches: {connected}/{len(sim.switches)} connected")
                print(f"Hosts: {len(sim.hosts)}")
                print(f"Traffic: {'Running' if sim.running else 'Stopped'}")
                print()

            elif cmd[0] == 'syn' and len(cmd) >= 3:
                attacker = cmd[1]
                target = cmd[2]
                duration = int(cmd[3]) if len(cmd) > 3 else 10
                pps = int(cmd[4]) if len(cmd) > 4 else 100
                sim.launch_syn_flood(attacker, target, duration, pps)

            elif cmd[0] == 'icmp' and len(cmd) >= 3:
                attacker = cmd[1]
                target = cmd[2]
                duration = int(cmd[3]) if len(cmd) > 3 else 10
                pps = int(cmd[4]) if len(cmd) > 4 else 50
                sim.launch_icmp_flood(attacker, target, duration, pps)

            elif cmd[0] == 'udp' and len(cmd) >= 3:
                attacker = cmd[1]
                target = cmd[2]
                duration = int(cmd[3]) if len(cmd) > 3 else 10
                pps = int(cmd[4]) if len(cmd) > 4 else 200
                sim.launch_udp_flood(attacker, target, duration, pps)

            elif cmd[0] == 'help':
                print("\nCommands:")
                print("  syn <attacker> <target> [duration] [pps]")
                print("  icmp <attacker> <target> [duration] [pps]")
                print("  udp <attacker> <target> [duration] [pps]")
                print("  hosts - List hosts")
                print("  status - Show status")
                print("  quit - Exit")
                print()

            else:
                print("Unknown command. Type 'help' for commands.")

    except KeyboardInterrupt:
        print("\nInterrupted")

    finally:
        sim.stop()
        print("Goodbye!")


if __name__ == '__main__':
    main()
