"""
SecureNet DC - SDN Firewall Module
CPEG 460 Bonus Project

Zone-based firewall using OpenFlow rules.
Supports:
- Zone-based access control
- Port filtering
- IP whitelist/blacklist
- Dynamic rule insertion
"""

import logging
from collections import defaultdict
import ipaddress

logger = logging.getLogger(__name__)


class SDNFirewall:
    """
    SDN-based Firewall using OpenFlow.

    Implements zone-based security with configurable rules
    that are enforced at the switch level.
    """

    def __init__(self, config):
        """
        Initialize SDN Firewall.

        Args:
            config: NetworkConfig class with FIREWALL_ZONES
        """
        self.config = config
        self.zones = config.FIREWALL_ZONES
        self.default_policy = config.FIREWALL_DEFAULT_POLICY

        # Dynamic rules
        self.whitelist = set()
        self.blacklist = set()
        self.port_rules = defaultdict(list)  # {port: [allow/deny rules]}

        # Rule tracking
        self.installed_rules = []
        self.rule_stats = defaultdict(lambda: {'matches': 0, 'bytes': 0})

        # Zone membership cache
        self.ip_to_zone = {}
        self._build_zone_cache()

        logger.info(f"SDN Firewall initialized (default policy: {self.default_policy})")
        for zone_name, zone in self.zones.items():
            logger.info(f"  Zone '{zone_name}': {zone['subnets']}")

    def _build_zone_cache(self):
        """Build IP to zone mapping cache."""
        for zone_name, zone in self.zones.items():
            for subnet_str in zone['subnets']:
                try:
                    network = ipaddress.ip_network(subnet_str, strict=False)
                    # Store network object for faster lookup
                    for ip in network.hosts():
                        self.ip_to_zone[str(ip)] = zone_name
                except ValueError as e:
                    logger.error(f"Invalid subnet {subnet_str}: {e}")

    def get_zone(self, ip_address):
        """
        Get the zone for an IP address.

        Args:
            ip_address: IP address to lookup

        Returns:
            str: Zone name or None if not found
        """
        # Check cache first
        if ip_address in self.ip_to_zone:
            return self.ip_to_zone[ip_address]

        # Check subnets
        try:
            ip = ipaddress.ip_address(ip_address)
            for zone_name, zone in self.zones.items():
                for subnet_str in zone['subnets']:
                    network = ipaddress.ip_network(subnet_str, strict=False)
                    if ip in network:
                        self.ip_to_zone[ip_address] = zone_name
                        return zone_name
        except ValueError:
            pass

        return None

    def check_access(self, src_ip, dst_ip, dst_port, protocol='tcp'):
        """
        Check if traffic should be allowed.

        Args:
            src_ip: Source IP address
            dst_ip: Destination IP address
            dst_port: Destination port
            protocol: 'tcp' or 'udp'

        Returns:
            tuple: (allowed, reason)
        """
        # Check blacklist first
        if src_ip in self.blacklist:
            return False, 'BLACKLISTED'

        # Check whitelist
        if src_ip in self.whitelist:
            return True, 'WHITELISTED'

        # Get zones
        src_zone = self.get_zone(src_ip)
        dst_zone = self.get_zone(dst_ip)

        # Same zone - usually allowed
        if src_zone == dst_zone and src_zone is not None:
            return True, 'SAME_ZONE'

        # Check destination zone rules
        if dst_zone:
            zone_config = self.zones.get(dst_zone, {})
            allowed_ports = zone_config.get('allowed_inbound', [])

            if dst_port in allowed_ports:
                return True, f'ALLOWED_PORT_{dst_port}'
            elif allowed_ports:  # Zone has rules but port not in list
                return False, f'PORT_{dst_port}_NOT_ALLOWED'

        # Check custom port rules
        port_rules = self.port_rules.get(dst_port, [])
        for rule in port_rules:
            if self._match_rule(rule, src_ip, dst_ip):
                return rule['action'] == 'allow', rule.get('reason', 'CUSTOM_RULE')

        # Default policy
        if self.default_policy == 'allow':
            return True, 'DEFAULT_ALLOW'
        else:
            return False, 'DEFAULT_DENY'

    def _match_rule(self, rule, src_ip, dst_ip):
        """Check if a rule matches the given IPs."""
        src_match = rule.get('src_ip', 'any')
        dst_match = rule.get('dst_ip', 'any')

        if src_match != 'any':
            try:
                network = ipaddress.ip_network(src_match, strict=False)
                if ipaddress.ip_address(src_ip) not in network:
                    return False
            except ValueError:
                if src_ip != src_match:
                    return False

        if dst_match != 'any':
            try:
                network = ipaddress.ip_network(dst_match, strict=False)
                if ipaddress.ip_address(dst_ip) not in network:
                    return False
            except ValueError:
                if dst_ip != dst_match:
                    return False

        return True

    def add_to_blacklist(self, ip_address, reason='manual'):
        """
        Add an IP to the blacklist.

        Args:
            ip_address: IP to blacklist
            reason: Reason for blacklisting
        """
        self.blacklist.add(ip_address)
        # Remove from whitelist if present
        self.whitelist.discard(ip_address)
        logger.warning(f"Blacklisted {ip_address}: {reason}")

    def remove_from_blacklist(self, ip_address):
        """Remove an IP from the blacklist."""
        self.blacklist.discard(ip_address)
        logger.info(f"Removed {ip_address} from blacklist")

    def add_to_whitelist(self, ip_address, reason='manual'):
        """
        Add an IP to the whitelist.

        Args:
            ip_address: IP to whitelist
            reason: Reason for whitelisting
        """
        self.whitelist.add(ip_address)
        # Remove from blacklist if present
        self.blacklist.discard(ip_address)
        logger.info(f"Whitelisted {ip_address}: {reason}")

    def remove_from_whitelist(self, ip_address):
        """Remove an IP from the whitelist."""
        self.whitelist.discard(ip_address)
        logger.info(f"Removed {ip_address} from whitelist")

    def add_port_rule(self, port, action, src_ip='any', dst_ip='any',
                      protocol='tcp', reason='custom'):
        """
        Add a custom port rule.

        Args:
            port: Port number
            action: 'allow' or 'deny'
            src_ip: Source IP or 'any'
            dst_ip: Destination IP or 'any'
            protocol: 'tcp' or 'udp'
            reason: Reason for the rule
        """
        rule = {
            'port': port,
            'action': action,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol,
            'reason': reason
        }
        self.port_rules[port].append(rule)
        logger.info(f"Added port rule: {action} {protocol}/{port} "
                   f"from {src_ip} to {dst_ip}")

    def install_default_rules(self, datapath):
        """
        Install default firewall rules on a switch.

        Args:
            datapath: OpenFlow datapath
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        logger.info(f"Installing firewall rules on switch {datapath.id}")

        # Priority levels:
        # 1000+ : Security (blacklist, block rules)
        # 500-999: Zone rules
        # 100-499: Port rules
        # 1-99: Default rules
        # 0: Table-miss

        # Install blacklist rules (will be added dynamically)

        # Install zone-based rules
        for zone_name, zone in self.zones.items():
            for subnet in zone['subnets']:
                # Allow inbound to permitted ports
                for port in zone.get('allowed_inbound', []):
                    # TCP rule
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=6,
                        ipv4_dst=(subnet.split('/')[0], '255.255.255.0'),
                        tcp_dst=port
                    )
                    actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
                    self._add_flow(datapath, 500, match, actions,
                                 f"zone_{zone_name}_tcp_{port}")

                    # UDP rule
                    match = parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=17,
                        ipv4_dst=(subnet.split('/')[0], '255.255.255.0'),
                        udp_dst=port
                    )
                    self._add_flow(datapath, 500, match, actions,
                                 f"zone_{zone_name}_udp_{port}")

        # Default policy
        if self.default_policy == 'deny':
            # Drop all IP traffic by default
            match = parser.OFPMatch(eth_type=0x0800)
            actions = []  # Empty = drop
            self._add_flow(datapath, 1, match, actions, "default_deny")
            logger.info("  Default policy: DENY")
        else:
            # Allow all (normal forwarding)
            match = parser.OFPMatch(eth_type=0x0800)
            actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
            self._add_flow(datapath, 1, match, actions, "default_allow")
            logger.info("  Default policy: ALLOW")

        # Always allow ARP
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, 100, match, actions, "allow_arp")

    def install_block_rule(self, datapath, src_ip, timeout=0):
        """
        Install a rule to block a specific IP.

        Args:
            datapath: OpenFlow datapath
            src_ip: IP address to block
            timeout: Hard timeout in seconds (0 = permanent)
        """
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip
        )
        actions = []  # Drop

        self._add_flow(datapath, 1000, match, actions,
                      f"block_{src_ip}", hard_timeout=timeout)

        logger.warning(f"Installed block rule for {src_ip} on switch {datapath.id}")

    def remove_block_rule(self, datapath, src_ip):
        """
        Remove a block rule for an IP.

        Args:
            datapath: OpenFlow datapath
            src_ip: IP address to unblock
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=src_ip
        )

        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            match=match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY
        )
        datapath.send_msg(mod)

        logger.info(f"Removed block rule for {src_ip} on switch {datapath.id}")

    def _add_flow(self, datapath, priority, match, actions, rule_name,
                  idle_timeout=0, hard_timeout=0):
        """Add a flow entry to the switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(
            ofproto.OFPIT_APPLY_ACTIONS, actions
        )]

        mod = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(mod)

        self.installed_rules.append({
            'switch': datapath.id,
            'name': rule_name,
            'priority': priority
        })

    def get_statistics(self):
        """
        Get firewall statistics.

        Returns:
            dict: Firewall statistics
        """
        return {
            'default_policy': self.default_policy,
            'blacklist': list(self.blacklist),
            'whitelist': list(self.whitelist),
            'zones': {name: zone['description']
                     for name, zone in self.zones.items()},
            'installed_rules': len(self.installed_rules),
            'rule_stats': dict(self.rule_stats)
        }
