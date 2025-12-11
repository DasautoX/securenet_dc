"""
SecureNet DC - Load Balancer Module
CPEG 460 Bonus Project

VIP-based load balancing across server pools using OpenFlow.
Supports:
- Round-robin distribution
- Weighted round-robin
- Least connections
- Health checking
"""

import time
import logging
from collections import defaultdict
from threading import Lock, Thread

logger = logging.getLogger(__name__)


class LoadBalancer:
    """
    SDN-based Load Balancer using Virtual IP (VIP).

    Distributes incoming traffic across a pool of backend servers
    by rewriting destination IP/MAC addresses via OpenFlow rules.
    """

    def __init__(self, config):
        """
        Initialize Load Balancer.

        Args:
            config: NetworkConfig class with LOAD_BALANCER settings
        """
        self.config = config.LOAD_BALANCER
        self.enabled = self.config['enabled']

        self.vip = self.config['virtual_ip']
        self.vmac = self.config['virtual_mac']
        self.server_pool = list(self.config['server_pool'])
        self.algorithm = self.config['algorithm']
        self.weights = list(self.config.get('weights', [1] * len(self.server_pool)))
        self.service_port = self.config['service_port']

        # Server state tracking
        self.server_index = 0
        self.weighted_index = 0
        self.weight_counter = 0
        self.connections = defaultdict(int)  # For least_conn
        self.server_health = {ip: True for ip in self.server_pool}

        # Server MAC addresses (to be populated)
        self.server_macs = {}

        # Statistics
        self.stats = {
            'total_requests': 0,
            'requests_per_server': defaultdict(int),
            'active_connections': defaultdict(int)
        }

        # Flow tracking: {(client_ip, client_port): server_ip}
        self.flow_mapping = {}

        # Thread safety
        self.lock = Lock()

        # Health checking
        self.health_check_interval = self.config.get('health_check_interval', 5)
        self.health_thread = None
        self.running = False

        logger.info(f"Load Balancer initialized: VIP={self.vip}, "
                   f"Algorithm={self.algorithm}")
        logger.info(f"Server pool: {self.server_pool}")

    def start_health_checks(self, net=None):
        """
        Start background health checking thread.

        Args:
            net: Mininet network object (for ping-based health checks)
        """
        self.running = True
        self.health_thread = Thread(target=self._health_check_loop, args=(net,))
        self.health_thread.daemon = True
        self.health_thread.start()
        logger.info("Health checking started")

    def stop_health_checks(self):
        """Stop health checking thread."""
        self.running = False
        if self.health_thread:
            self.health_thread.join(timeout=2)
        logger.info("Health checking stopped")

    def _health_check_loop(self, net):
        """Background health check loop."""
        while self.running:
            for server_ip in self.server_pool:
                # Simple health check - in production would ping or HTTP check
                # For simulation, servers are always healthy unless manually marked
                pass
            time.sleep(self.health_check_interval)

    def select_server(self, client_ip=None, client_port=None):
        """
        Select a backend server based on the configured algorithm.

        Args:
            client_ip: Client IP address
            client_port: Client source port

        Returns:
            str: Selected server IP address, or None if no healthy servers
        """
        if not self.enabled:
            return None

        with self.lock:
            # Check for existing flow mapping (connection affinity)
            if client_ip and client_port:
                flow_key = (client_ip, client_port)
                if flow_key in self.flow_mapping:
                    return self.flow_mapping[flow_key]

            # Get healthy servers
            healthy_servers = [ip for ip in self.server_pool
                            if self.server_health.get(ip, False)]

            if not healthy_servers:
                logger.warning("No healthy servers available!")
                return None

            # Select server based on algorithm
            if self.algorithm == 'round_robin':
                server = self._round_robin(healthy_servers)
            elif self.algorithm == 'weighted':
                server = self._weighted_round_robin(healthy_servers)
            elif self.algorithm == 'least_conn':
                server = self._least_connections(healthy_servers)
            else:
                server = self._round_robin(healthy_servers)

            # Record the mapping
            if client_ip and client_port:
                flow_key = (client_ip, client_port)
                self.flow_mapping[flow_key] = server

            # Update statistics
            self.stats['total_requests'] += 1
            self.stats['requests_per_server'][server] += 1
            self.stats['active_connections'][server] += 1

            logger.debug(f"Load balancer: {client_ip}:{client_port} -> {server}")

            return server

    def _round_robin(self, servers):
        """Simple round-robin selection."""
        server = servers[self.server_index % len(servers)]
        self.server_index = (self.server_index + 1) % len(servers)
        return server

    def _weighted_round_robin(self, servers):
        """Weighted round-robin selection."""
        # Build weighted list
        weighted_servers = []
        for i, server in enumerate(servers):
            weight = self.weights[self.server_pool.index(server)]
            weighted_servers.extend([server] * weight)

        if not weighted_servers:
            return servers[0]

        server = weighted_servers[self.weighted_index % len(weighted_servers)]
        self.weighted_index = (self.weighted_index + 1) % len(weighted_servers)
        return server

    def _least_connections(self, servers):
        """Select server with least active connections."""
        min_conn = float('inf')
        selected = servers[0]

        for server in servers:
            conn = self.stats['active_connections'][server]
            if conn < min_conn:
                min_conn = conn
                selected = server

        return selected

    def release_connection(self, client_ip, client_port):
        """
        Release a connection when it's closed.

        Args:
            client_ip: Client IP address
            client_port: Client source port
        """
        with self.lock:
            flow_key = (client_ip, client_port)
            if flow_key in self.flow_mapping:
                server = self.flow_mapping[flow_key]
                self.stats['active_connections'][server] = max(
                    0, self.stats['active_connections'][server] - 1
                )
                del self.flow_mapping[flow_key]

    def set_server_health(self, server_ip, healthy):
        """
        Set health status of a server.

        Args:
            server_ip: Server IP address
            healthy: Boolean health status
        """
        with self.lock:
            old_status = self.server_health.get(server_ip, True)
            self.server_health[server_ip] = healthy

            if old_status != healthy:
                status = "UP" if healthy else "DOWN"
                logger.warning(f"Server {server_ip} is now {status}")

    def add_server(self, server_ip, weight=1):
        """
        Add a server to the pool.

        Args:
            server_ip: Server IP address
            weight: Server weight for weighted algorithm
        """
        with self.lock:
            if server_ip not in self.server_pool:
                self.server_pool.append(server_ip)
                self.weights.append(weight)
                self.server_health[server_ip] = True
                logger.info(f"Added server {server_ip} to pool (weight={weight})")

    def remove_server(self, server_ip):
        """
        Remove a server from the pool.

        Args:
            server_ip: Server IP address
        """
        with self.lock:
            if server_ip in self.server_pool:
                idx = self.server_pool.index(server_ip)
                self.server_pool.remove(server_ip)
                self.weights.pop(idx)
                self.server_health.pop(server_ip, None)
                logger.info(f"Removed server {server_ip} from pool")

    def register_server_mac(self, server_ip, mac):
        """
        Register MAC address for a server.

        Args:
            server_ip: Server IP address
            mac: MAC address
        """
        self.server_macs[server_ip] = mac
        logger.debug(f"Registered MAC {mac} for server {server_ip}")

    def get_server_mac(self, server_ip):
        """Get MAC address for a server."""
        return self.server_macs.get(server_ip)

    def get_flow_actions(self, parser, client_ip, client_port, in_port):
        """
        Get OpenFlow actions for load balancing.

        Args:
            parser: OpenFlow parser
            client_ip: Client IP address
            client_port: Client source port
            in_port: Input port

        Returns:
            tuple: (actions, selected_server) or (None, None) if disabled
        """
        if not self.enabled:
            return None, None

        server_ip = self.select_server(client_ip, client_port)
        if not server_ip:
            return None, None

        server_mac = self.get_server_mac(server_ip)

        actions = []

        # Rewrite destination IP to selected server
        actions.append(parser.OFPActionSetField(ipv4_dst=server_ip))

        # Rewrite destination MAC if known
        if server_mac:
            actions.append(parser.OFPActionSetField(eth_dst=server_mac))

        return actions, server_ip

    def get_reverse_flow_actions(self, parser, server_ip, client_ip):
        """
        Get OpenFlow actions for reverse flow (server -> client).

        Args:
            parser: OpenFlow parser
            server_ip: Server IP address
            client_ip: Client IP address

        Returns:
            list: OpenFlow actions
        """
        actions = []

        # Rewrite source IP to VIP
        actions.append(parser.OFPActionSetField(ipv4_src=self.vip))

        # Rewrite source MAC to virtual MAC
        actions.append(parser.OFPActionSetField(eth_src=self.vmac))

        return actions

    def handle_arp_request(self, parser, ofproto, datapath, in_port, pkt_arp):
        """
        Handle ARP request for the VIP.

        Args:
            parser: OpenFlow parser
            ofproto: OpenFlow protocol
            datapath: OpenFlow datapath
            in_port: Input port
            pkt_arp: ARP packet

        Returns:
            bool: True if ARP was handled, False otherwise
        """
        if str(pkt_arp.dst_ip) != self.vip:
            return False

        # Create ARP reply
        from ryu.lib.packet import packet, ethernet, arp

        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(
            ethertype=0x0806,
            dst=pkt_arp.src_mac,
            src=self.vmac
        ))
        pkt.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY,
            src_mac=self.vmac,
            src_ip=self.vip,
            dst_mac=pkt_arp.src_mac,
            dst_ip=pkt_arp.src_ip
        ))
        pkt.serialize()

        # Send ARP reply
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=ofproto.OFPP_CONTROLLER,
            actions=actions,
            data=pkt.data
        )
        datapath.send_msg(out)

        logger.debug(f"Sent ARP reply for VIP {self.vip}")
        return True

    def get_statistics(self):
        """
        Get load balancer statistics.

        Returns:
            dict: Load balancer statistics
        """
        with self.lock:
            return {
                'enabled': self.enabled,
                'vip': self.vip,
                'algorithm': self.algorithm,
                'total_requests': self.stats['total_requests'],
                'requests_per_server': dict(self.stats['requests_per_server']),
                'active_connections': dict(self.stats['active_connections']),
                'server_pool': self.server_pool,
                'server_health': dict(self.server_health),
                'weights': self.weights
            }

    def get_pool_status(self):
        """
        Get status of all servers in the pool.

        Returns:
            list: List of server status dicts
        """
        with self.lock:
            status = []
            for i, server in enumerate(self.server_pool):
                status.append({
                    'ip': server,
                    'healthy': self.server_health.get(server, False),
                    'weight': self.weights[i],
                    'connections': self.stats['active_connections'][server],
                    'total_requests': self.stats['requests_per_server'][server]
                })
            return status
