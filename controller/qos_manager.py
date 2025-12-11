"""
SecureNet DC - QoS Traffic Manager
CPEG 460 Bonus Project

Quality of Service implementation using OpenFlow meters and queues.
Supports:
- Traffic classification by port/protocol
- 4-tier priority system
- Bandwidth guarantees
- DSCP marking
"""

import logging
from collections import defaultdict

logger = logging.getLogger(__name__)


class QoSManager:
    """
    QoS Traffic Manager for SDN-based traffic engineering.

    Classifies traffic into priority levels and applies appropriate
    QoS policies using OpenFlow actions.
    """

    # DSCP values for each priority class
    DSCP_VALUES = {
        0: 46,  # Critical - EF (Expedited Forwarding)
        1: 34,  # Real-time - AF41 (Assured Forwarding 41)
        2: 26,  # Interactive - AF31
        3: 0    # Bulk - Best Effort
    }

    def __init__(self, config, datapath=None):
        """
        Initialize QoS Manager.

        Args:
            config: NetworkConfig class with QOS_QUEUES and TRAFFIC_CLASSES
            datapath: OpenFlow datapath (can be set later)
        """
        self.config = config
        self.datapath = datapath
        self.queues = config.QOS_QUEUES
        self.traffic_classes = config.TRAFFIC_CLASSES

        # Traffic statistics per class
        self.class_stats = defaultdict(lambda: {
            'packets': 0,
            'bytes': 0
        })

        # Flow tracking
        self.qos_flows = {}

        logger.info("QoS Manager initialized")
        for qid, q in self.queues.items():
            logger.info(f"  Queue {qid} ({q['name']}): "
                       f"min={q['min_rate']/1e6:.0f}Mbps, "
                       f"max={q['max_rate']/1e6:.0f}Mbps")

    def set_datapath(self, datapath):
        """Set the OpenFlow datapath."""
        self.datapath = datapath

    def classify_traffic(self, dst_port, protocol='tcp'):
        """
        Classify traffic based on destination port and protocol.

        Args:
            dst_port: Destination port number
            protocol: 'tcp' or 'udp'

        Returns:
            tuple: (class_name, queue_id, dscp_value)
        """
        port_key = f'{protocol}_ports'

        for class_name, rules in self.traffic_classes.items():
            if dst_port in rules.get(port_key, []):
                queue_id = rules['queue']
                dscp = self.DSCP_VALUES.get(queue_id, 0)
                return class_name, queue_id, dscp

        # Default to bulk class
        return 'bulk', 3, self.DSCP_VALUES[3]

    def get_qos_actions(self, parser, dst_port, protocol='tcp', out_port=None):
        """
        Get OpenFlow actions for QoS treatment.

        Args:
            parser: OpenFlow parser
            dst_port: Destination port for classification
            protocol: 'tcp' or 'udp'
            out_port: Output port (if known)

        Returns:
            list: OpenFlow actions including queue assignment and DSCP marking
        """
        class_name, queue_id, dscp = self.classify_traffic(dst_port, protocol)

        actions = []

        # Set DSCP value (IP ToS field)
        # DSCP is stored in the upper 6 bits of the ToS byte
        tos = dscp << 2
        actions.append(parser.OFPActionSetField(ip_dscp=dscp))

        # Set output queue for bandwidth management
        actions.append(parser.OFPActionSetQueue(queue_id))

        # Add output action if port specified
        if out_port is not None:
            actions.append(parser.OFPActionOutput(out_port))

        # Update statistics
        self.class_stats[class_name]['packets'] += 1

        logger.debug(f"QoS: port {dst_port}/{protocol} -> {class_name} "
                    f"(queue={queue_id}, dscp={dscp})")

        return actions, class_name, queue_id

    def install_qos_rules(self, datapath):
        """
        Install proactive QoS flow rules on a switch.

        Args:
            datapath: OpenFlow datapath
        """
        if datapath is None:
            logger.error("Cannot install QoS rules: datapath is None")
            return

        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        logger.info(f"Installing QoS rules on switch {datapath.id}")

        # Install rules for each traffic class
        for class_name, rules in self.traffic_classes.items():
            queue_id = rules['queue']
            dscp = self.DSCP_VALUES[queue_id]
            priority = 100 + (3 - queue_id) * 10  # Higher queue = higher priority

            # TCP port rules
            for port in rules.get('tcp_ports', []):
                # Destination port match
                match = parser.OFPMatch(
                    eth_type=0x0800,  # IPv4
                    ip_proto=6,        # TCP
                    tcp_dst=port
                )
                actions = [
                    parser.OFPActionSetField(ip_dscp=dscp),
                    parser.OFPActionSetQueue(queue_id),
                    parser.OFPActionOutput(ofproto.OFPP_NORMAL)
                ]
                self._add_flow(datapath, priority, match, actions)

                # Source port match (for return traffic)
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=6,
                    tcp_src=port
                )
                self._add_flow(datapath, priority, match, actions)

                logger.info(f"  {class_name}: TCP port {port} -> queue {queue_id}")

            # UDP port rules
            for port in rules.get('udp_ports', []):
                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=17,       # UDP
                    udp_dst=port
                )
                actions = [
                    parser.OFPActionSetField(ip_dscp=dscp),
                    parser.OFPActionSetQueue(queue_id),
                    parser.OFPActionOutput(ofproto.OFPP_NORMAL)
                ]
                self._add_flow(datapath, priority, match, actions)

                match = parser.OFPMatch(
                    eth_type=0x0800,
                    ip_proto=17,
                    udp_src=port
                )
                self._add_flow(datapath, priority, match, actions)

                logger.info(f"  {class_name}: UDP port {port} -> queue {queue_id}")

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0,
                  hard_timeout=0):
        """
        Add a flow entry to the switch.

        Args:
            datapath: OpenFlow datapath
            priority: Flow priority
            match: Match fields
            actions: Actions to apply
            idle_timeout: Idle timeout in seconds
            hard_timeout: Hard timeout in seconds
        """
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

    def get_statistics(self):
        """
        Get QoS statistics.

        Returns:
            dict: Statistics per traffic class
        """
        stats = {
            'class_stats': dict(self.class_stats),
            'queues': {}
        }

        for qid, q in self.queues.items():
            stats['queues'][qid] = {
                'name': q['name'],
                'min_rate_mbps': q['min_rate'] / 1e6,
                'max_rate_mbps': q['max_rate'] / 1e6,
                'priority': q['priority'],
                'dscp': self.DSCP_VALUES[qid]
            }

        return stats

    def get_queue_for_port(self, port, protocol='tcp'):
        """
        Get queue ID for a given port/protocol combination.

        Args:
            port: Port number
            protocol: 'tcp' or 'udp'

        Returns:
            int: Queue ID
        """
        _, queue_id, _ = self.classify_traffic(port, protocol)
        return queue_id

    def update_class_stats(self, class_name, packets=1, bytes_count=0):
        """
        Update traffic statistics for a class.

        Args:
            class_name: Traffic class name
            packets: Number of packets
            bytes_count: Number of bytes
        """
        self.class_stats[class_name]['packets'] += packets
        self.class_stats[class_name]['bytes'] += bytes_count

    def configure_ovs_queues(self, switch, interface):
        """
        Generate OVS commands to configure QoS queues.

        Args:
            switch: Switch node
            interface: Interface name

        Returns:
            str: OVS command to execute
        """
        queue_defs = []
        queue_refs = []

        for qid, q in self.queues.items():
            queue_refs.append(f'queues:{qid}=@q{qid}')
            queue_defs.append(
                f'-- --id=@q{qid} create Queue '
                f'other-config:min-rate={q["min_rate"]} '
                f'other-config:max-rate={q["max_rate"]}'
            )

        cmd = (
            f'ovs-vsctl -- set Port {interface} qos=@newqos '
            f'-- --id=@newqos create QoS type=linux-htb '
            f'other-config:max-rate=100000000 '
            f'{" ".join(queue_refs)} {" ".join(queue_defs)}'
        )

        return cmd
