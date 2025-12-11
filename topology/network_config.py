"""
SecureNet DC - Network Configuration
CPEG 460 Bonus Project

Centralized configuration for the entire network.
"""


class NetworkConfig:
    """
    Central configuration class for SecureNet DC.
    Modify these values to customize the network behavior.
    """

    # ===========================================
    # TOPOLOGY CONFIGURATION
    # ===========================================

    # Fat-Tree parameter (k=4 gives us a manageable size)
    FAT_TREE_K = 4

    # Link properties
    CORE_LINK_BW = 1000      # Mbps - Core to Aggregation
    AGG_LINK_BW = 100        # Mbps - Aggregation to Edge
    EDGE_LINK_BW = 100       # Mbps - Edge to Host

    CORE_LINK_DELAY = '1ms'
    AGG_LINK_DELAY = '2ms'
    EDGE_LINK_DELAY = '1ms'

    # ===========================================
    # HOST CONFIGURATION
    # ===========================================

    # Host groups and their IP ranges
    HOST_GROUPS = {
        'web_servers': {
            'hosts': ['h1', 'h2', 'h3', 'h4'],
            'ip_base': '10.0.1.',
            'gateway': '10.0.1.254',
            'description': 'Web Server Pool (Load Balanced)'
        },
        'db_servers': {
            'hosts': ['h5', 'h6'],
            'ip_base': '10.0.2.',
            'gateway': '10.0.2.254',
            'description': 'Database Servers'
        },
        'clients': {
            'hosts': ['h7', 'h8', 'h9', 'h10', 'h11', 'h12'],
            'ip_base': '10.0.3.',
            'gateway': '10.0.3.254',
            'description': 'Client Hosts'
        },
        'security': {
            'hosts': ['h13', 'h14'],
            'ip_base': '10.0.4.',
            'gateway': '10.0.4.254',
            'description': 'Attacker (h13) and IDS Monitor (h14)'
        },
        'streaming': {
            'hosts': ['h15', 'h16'],
            'ip_base': '10.0.5.',
            'gateway': '10.0.5.254',
            'description': 'Video Streaming Servers'
        }
    }

    # ===========================================
    # SDN CONTROLLER CONFIGURATION
    # ===========================================

    CONTROLLER_IP = '127.0.0.1'
    CONTROLLER_PORT = 6653
    OPENFLOW_VERSION = 'OpenFlow13'

    # ===========================================
    # DDOS DETECTION THRESHOLDS
    # ===========================================

    DDOS_THRESHOLDS = {
        'syn_flood': 100,       # SYN packets/sec from single IP
        'icmp_flood': 50,       # ICMP packets/sec from single IP
        'udp_flood': 200,       # UDP packets/sec from single IP
        'slowloris': 20,        # Incomplete HTTP connections
        'total_pps': 500,       # Total packets/sec from single IP
        'detection_window': 5,  # Seconds to analyze
        'block_duration': 120   # Seconds to block attacker
    }

    # ===========================================
    # QOS CONFIGURATION
    # ===========================================

    QOS_QUEUES = {
        0: {
            'name': 'critical',
            'min_rate': 50_000_000,   # 50 Mbps minimum
            'max_rate': 100_000_000,  # 100 Mbps maximum
            'priority': 1,
            'ports': [22, 53]         # SSH, DNS
        },
        1: {
            'name': 'realtime',
            'min_rate': 30_000_000,   # 30 Mbps minimum
            'max_rate': 80_000_000,   # 80 Mbps maximum
            'priority': 2,
            'ports': [554, 1935, 5001, 8554]  # RTSP, RTMP, iperf UDP
        },
        2: {
            'name': 'interactive',
            'min_rate': 15_000_000,   # 15 Mbps minimum
            'max_rate': 50_000_000,   # 50 Mbps maximum
            'priority': 3,
            'ports': [80, 443, 8080]  # HTTP, HTTPS
        },
        3: {
            'name': 'bulk',
            'min_rate': 5_000_000,    # 5 Mbps minimum
            'max_rate': 20_000_000,   # 20 Mbps maximum
            'priority': 4,
            'ports': [21, 5002]       # FTP, iperf TCP
        }
    }

    # Traffic classification rules
    TRAFFIC_CLASSES = {
        'critical': {'tcp_ports': [22, 53], 'udp_ports': [53], 'queue': 0},
        'realtime': {'tcp_ports': [554, 1935], 'udp_ports': [5001, 8554], 'queue': 1},
        'interactive': {'tcp_ports': [80, 443, 8080], 'udp_ports': [], 'queue': 2},
        'bulk': {'tcp_ports': [21, 5002], 'udp_ports': [], 'queue': 3}
    }

    # ===========================================
    # LOAD BALANCER CONFIGURATION
    # ===========================================

    LOAD_BALANCER = {
        'enabled': True,
        'virtual_ip': '10.0.0.100',
        'virtual_mac': '00:00:00:00:00:64',
        'server_pool': ['10.0.1.1', '10.0.1.2', '10.0.1.3', '10.0.1.4'],
        'algorithm': 'round_robin',  # round_robin, weighted, least_conn
        'weights': [1, 1, 1, 1],     # For weighted algorithm
        'health_check_interval': 5,   # Seconds
        'health_check_timeout': 2,    # Seconds
        'service_port': 80
    }

    # ===========================================
    # FIREWALL RULES
    # ===========================================

    FIREWALL_ZONES = {
        'dmz': {
            'subnets': ['10.0.1.0/24', '10.0.5.0/24'],
            'allowed_inbound': [80, 443, 554],
            'description': 'Web and Streaming servers'
        },
        'internal': {
            'subnets': ['10.0.2.0/24', '10.0.3.0/24'],
            'allowed_inbound': [],  # No direct inbound from outside
            'description': 'Database and Client networks'
        },
        'security': {
            'subnets': ['10.0.4.0/24'],
            'allowed_inbound': [],
            'description': 'Security testing zone'
        }
    }

    # Default firewall policy
    FIREWALL_DEFAULT_POLICY = 'allow'  # 'allow' or 'deny'

    # ===========================================
    # DASHBOARD CONFIGURATION
    # ===========================================

    DASHBOARD = {
        'host': '0.0.0.0',
        'port': 5000,
        'debug': False,
        'update_interval': 1000,  # ms - WebSocket update frequency
        'history_length': 60      # Seconds of history to keep
    }

    # ===========================================
    # STATISTICS COLLECTION
    # ===========================================

    STATS = {
        'poll_interval': 5,       # Seconds between stats requests
        'flow_stats': True,
        'port_stats': True,
        'table_stats': True,
        'aggregate_stats': True
    }

    # ===========================================
    # ATTACK SIMULATION (SAFE DEFAULTS)
    # ===========================================

    ATTACK_CONFIG = {
        'safe_mode': True,        # Limit attack intensity
        'max_pps': 1000,          # Maximum packets per second in safe mode
        'default_duration': 30,   # Default attack duration in seconds
        'target_hosts': ['h1', 'h2'],  # Default targets (web servers)
    }

    @classmethod
    def get_host_ip(cls, hostname):
        """Get IP address for a hostname."""
        for group_name, group in cls.HOST_GROUPS.items():
            if hostname in group['hosts']:
                idx = group['hosts'].index(hostname) + 1
                return f"{group['ip_base']}{idx}"
        return None

    @classmethod
    def get_host_group(cls, hostname):
        """Get the group name for a hostname."""
        for group_name, group in cls.HOST_GROUPS.items():
            if hostname in group['hosts']:
                return group_name
        return None

    @classmethod
    def get_all_hosts(cls):
        """Get list of all hostnames."""
        hosts = []
        for group in cls.HOST_GROUPS.values():
            hosts.extend(group['hosts'])
        return hosts

    @classmethod
    def get_traffic_class(cls, port, protocol='tcp'):
        """Determine traffic class based on port and protocol."""
        port_key = f'{protocol}_ports'
        for class_name, rules in cls.TRAFFIC_CLASSES.items():
            if port in rules.get(port_key, []):
                return class_name, rules['queue']
        return 'bulk', 3  # Default to bulk
