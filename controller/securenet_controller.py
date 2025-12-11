#!/usr/bin/env python3
"""
SecureNet DC - Main SDN Controller
CPEG 460 Bonus Project

Integrated Ryu SDN controller with:
- L2 Learning Switch
- DDoS Detection & Mitigation
- QoS Traffic Engineering
- Load Balancing
- Firewall
- Statistics Collection
- REST API
"""

try:
    from ryu.base import app_manager
    from ryu.controller import ofp_event
    from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
    from ryu.controller.handler import set_ev_cls
    from ryu.ofproto import ofproto_v1_3
    from ryu.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
    from ryu.lib import hub
    from ryu.app.wsgi import ControllerBase, WSGIApplication, route
except ImportError:
    # Use os-ken (Python 3.12+ compatible fork of Ryu)
    from os_ken.base import app_manager
    from os_ken.controller import ofp_event
    from os_ken.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
    from os_ken.controller.handler import set_ev_cls
    from os_ken.ofproto import ofproto_v1_3
    from os_ken.lib.packet import packet, ethernet, arp, ipv4, tcp, udp, icmp
    from os_ken.lib import hub
    from os_ken.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import json
import logging
import sys
import os

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from topology.network_config import NetworkConfig
    from controller.ddos_detector import DDoSDetector
    from controller.qos_manager import QoSManager
    from controller.load_balancer import LoadBalancer
    from controller.firewall import SDNFirewall
    from controller.stats_collector import StatsCollector
except ImportError:
    # Fallback for direct execution
    from network_config import NetworkConfig
    from ddos_detector import DDoSDetector
    from qos_manager import QoSManager
    from load_balancer import LoadBalancer
    from firewall import SDNFirewall
    from stats_collector import StatsCollector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('securenet')

# REST API instance name
SECURENET_INSTANCE = 'securenet_api'


class SecureNetController(app_manager.RyuApp):
    """
    Main SecureNet DC SDN Controller.

    Integrates all security and traffic engineering modules
    into a single cohesive controller application.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SecureNetController, self).__init__(*args, **kwargs)

        # L2 Learning switch state
        self.mac_to_port = {}

        # Configuration
        self.config = NetworkConfig

        # Initialize modules
        self.ddos_detector = DDoSDetector(NetworkConfig)
        self.qos_manager = QoSManager(NetworkConfig)
        self.load_balancer = LoadBalancer(NetworkConfig)
        self.firewall = SDNFirewall(NetworkConfig)
        self.stats_collector = StatsCollector(NetworkConfig)

        # Datapath tracking
        self.datapaths = {}

        # Register REST API
        wsgi = kwargs['wsgi']
        wsgi.register(SecureNetAPI, {SECURENET_INSTANCE: self})

        # Start statistics polling
        self.stats_collector.start_polling()

        logger.info("=" * 60)
        logger.info("  SecureNet DC Controller Started")
        logger.info("=" * 60)
        logger.info(f"  DDoS Detection: ENABLED")
        logger.info(f"  QoS Management: ENABLED")
        logger.info(f"  Load Balancer: {'ENABLED' if self.load_balancer.enabled else 'DISABLED'}")
        logger.info(f"  Firewall: ENABLED (policy: {self.firewall.default_policy})")
        logger.info(f"  REST API: http://0.0.0.0:8080/securenet/")
        logger.info("=" * 60)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """Handle new switch connection."""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        logger.info(f"Switch connected: dpid={dpid}")

        # Store datapath
        self.datapaths[dpid] = datapath

        # Register with stats collector
        self.stats_collector.register_datapath(datapath)

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            ofproto.OFPP_CONTROLLER,
            ofproto.OFPCML_NO_BUFFER
        )]
        self._add_flow(datapath, 0, match, actions)

        # Install ARP handling
        match = parser.OFPMatch(eth_type=0x0806)
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        self._add_flow(datapath, 100, match, actions)

        # Install firewall rules
        self.firewall.install_default_rules(datapath)

        # Install QoS rules
        self.qos_manager.install_qos_rules(datapath)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER])
    def state_change_handler(self, ev):
        """Handle switch disconnection."""
        datapath = ev.datapath
        dpid = datapath.id

        if ev.state == MAIN_DISPATCHER:
            pass  # Already handled in switch_features_handler
        else:
            # Switch disconnected
            if dpid in self.datapaths:
                logger.warning(f"Switch disconnected: dpid={dpid}")
                del self.datapaths[dpid]
                self.stats_collector.unregister_datapath(dpid)
                if dpid in self.mac_to_port:
                    del self.mac_to_port[dpid]

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        """Handle packets sent to controller."""
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        # Parse packet
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        # Learn MAC address
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Handle ARP
        pkt_arp = pkt.get_protocol(arp.arp)
        if pkt_arp:
            self._handle_arp(datapath, in_port, pkt_arp, eth)
            return

        # Handle IPv4
        pkt_ipv4 = pkt.get_protocol(ipv4.ipv4)
        if pkt_ipv4:
            self._handle_ipv4(ev, datapath, in_port, pkt, eth, pkt_ipv4)
            return

        # Default L2 forwarding for other traffic
        self._l2_forward(datapath, msg, in_port, dst, src)

    def _handle_arp(self, datapath, in_port, pkt_arp, eth):
        """Handle ARP packets."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Check if ARP is for load balancer VIP
        if self.load_balancer.enabled:
            if self.load_balancer.handle_arp_request(
                    parser, ofproto, datapath, in_port, pkt_arp):
                return

        # Otherwise flood ARP
        actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=ofproto.OFP_NO_BUFFER,
            in_port=in_port,
            actions=actions,
            data=eth
        )
        datapath.send_msg(out)

    def _handle_ipv4(self, ev, datapath, in_port, pkt, eth, pkt_ipv4):
        """Handle IPv4 packets with full security pipeline."""
        msg = ev.msg
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        src_ip = str(pkt_ipv4.src)
        dst_ip = str(pkt_ipv4.dst)

        # Get L4 protocol info
        pkt_tcp = pkt.get_protocol(tcp.tcp)
        pkt_udp = pkt.get_protocol(udp.udp)
        pkt_icmp = pkt.get_protocol(icmp.icmp)

        dst_port = 0
        src_port = 0
        protocol = 'ip'

        if pkt_tcp:
            dst_port = pkt_tcp.dst_port
            src_port = pkt_tcp.src_port
            protocol = 'tcp'
        elif pkt_udp:
            dst_port = pkt_udp.dst_port
            src_port = pkt_udp.src_port
            protocol = 'udp'
        elif pkt_icmp:
            protocol = 'icmp'

        # ===== STAGE 1: DDoS Detection =====
        is_attack, attack_type, count = self.ddos_detector.analyze_packet(
            pkt_ipv4, pkt_tcp, pkt_udp, pkt_icmp
        )

        if is_attack:
            if attack_type != 'BLOCKED':
                # Install block rule on all switches
                for dp in self.datapaths.values():
                    self.firewall.install_block_rule(
                        dp, src_ip,
                        timeout=self.config.DDOS_THRESHOLDS['block_duration']
                    )
                # Add to firewall blacklist
                self.firewall.add_to_blacklist(src_ip, attack_type)

            logger.warning(f"[BLOCKED] {attack_type} from {src_ip}")
            return  # Drop packet

        # ===== STAGE 2: Firewall Check =====
        allowed, reason = self.firewall.check_access(
            src_ip, dst_ip, dst_port, protocol
        )

        if not allowed:
            logger.debug(f"Firewall blocked: {src_ip} -> {dst_ip}:{dst_port} ({reason})")
            return  # Drop packet

        # ===== STAGE 3: Load Balancer =====
        lb_actions = []
        selected_server = None

        if self.load_balancer.enabled and dst_ip == self.load_balancer.vip:
            lb_actions, selected_server = self.load_balancer.get_flow_actions(
                parser, src_ip, src_port, in_port
            )

            if selected_server:
                logger.debug(f"Load balancer: {src_ip}:{src_port} -> {selected_server}")
                dst_ip = selected_server

        # ===== STAGE 4: Determine Output Port =====
        dst_mac = eth.dst

        if dpid in self.mac_to_port and dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD

        # ===== STAGE 5: Build Actions with QoS =====
        actions = []

        # Add load balancer actions (IP rewrite)
        if lb_actions:
            actions.extend(lb_actions)

        # Add QoS actions
        if dst_port > 0:
            qos_actions, class_name, queue_id = self.qos_manager.get_qos_actions(
                parser, dst_port, protocol, out_port=None
            )
            actions.extend(qos_actions[:-1])  # Exclude output action from QoS

        # Add output action
        actions.append(parser.OFPActionOutput(out_port))

        # ===== STAGE 6: Install Flow Rule =====
        if out_port != ofproto.OFPP_FLOOD:
            # Install bidirectional flow rules
            if pkt_tcp:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ip_proto=6,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    tcp_src=src_port,
                    tcp_dst=dst_port
                )
            elif pkt_udp:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ip_proto=17,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip,
                    udp_src=src_port,
                    udp_dst=dst_port
                )
            else:
                match = parser.OFPMatch(
                    in_port=in_port,
                    eth_type=0x0800,
                    ipv4_src=src_ip,
                    ipv4_dst=dst_ip
                )

            self._add_flow(datapath, 10, match, actions,
                          idle_timeout=30, hard_timeout=60)

        # ===== STAGE 7: Send Packet Out =====
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _l2_forward(self, datapath, msg, in_port, dst, src):
        """Basic L2 forwarding."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        if dst in self.mac_to_port.get(dpid, {}):
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self._add_flow(datapath, 5, match, actions,
                          idle_timeout=60, hard_timeout=120)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions,
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

    # ===== Statistics Event Handlers =====

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Handle flow statistics reply."""
        self.stats_collector.handle_flow_stats_reply(ev)

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Handle port statistics reply."""
        self.stats_collector.handle_port_stats_reply(ev)

    @set_ev_cls(ofp_event.EventOFPTableStatsReply, MAIN_DISPATCHER)
    def table_stats_reply_handler(self, ev):
        """Handle table statistics reply."""
        self.stats_collector.handle_table_stats_reply(ev)

    @set_ev_cls(ofp_event.EventOFPAggregateStatsReply, MAIN_DISPATCHER)
    def aggregate_stats_reply_handler(self, ev):
        """Handle aggregate statistics reply."""
        self.stats_collector.handle_aggregate_stats_reply(ev)


class SecureNetAPI(ControllerBase):
    """
    REST API for SecureNet DC Controller.

    Endpoints:
    - GET /securenet/status - Overall status
    - GET /securenet/ddos/alerts - DDoS alerts
    - GET /securenet/ddos/blocked - Blocked hosts
    - POST /securenet/ddos/unblock - Unblock a host
    - GET /securenet/loadbalancer/status - Load balancer status
    - GET /securenet/qos/status - QoS status
    - GET /securenet/firewall/status - Firewall status
    - GET /securenet/stats - Network statistics
    """

    def __init__(self, req, link, data, **config):
        super(SecureNetAPI, self).__init__(req, link, data, **config)
        self.controller = data[SECURENET_INSTANCE]

    @route('securenet', '/securenet/status', methods=['GET'])
    def get_status(self, req, **kwargs):
        """Get overall controller status."""
        status = {
            'status': 'running',
            'switches': len(self.controller.datapaths),
            'ddos': self.controller.ddos_detector.get_statistics(),
            'load_balancer': self.controller.load_balancer.get_statistics(),
            'qos': self.controller.qos_manager.get_statistics(),
            'firewall': self.controller.firewall.get_statistics(),
            'network': self.controller.stats_collector.get_network_summary()
        }
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(status, indent=2)
        )

    @route('securenet', '/securenet/ddos/alerts', methods=['GET'])
    def get_ddos_alerts(self, req, **kwargs):
        """Get DDoS alerts."""
        alerts = self.controller.ddos_detector.get_alerts()
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(alerts, indent=2)
        )

    @route('securenet', '/securenet/ddos/blocked', methods=['GET'])
    def get_blocked_hosts(self, req, **kwargs):
        """Get list of blocked hosts."""
        blocked = self.controller.ddos_detector.get_blocked_hosts()
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(blocked, indent=2)
        )

    @route('securenet', '/securenet/ddos/unblock', methods=['POST'])
    def unblock_host(self, req, **kwargs):
        """Unblock a host."""
        try:
            body = json.loads(req.body)
            ip = body.get('ip')

            if not ip:
                return Response(status=400, charset='utf-8', body='Missing "ip" field')

            success = self.controller.ddos_detector.unblock_host(ip)
            self.controller.firewall.remove_from_blacklist(ip)

            # Remove block rules from switches
            for datapath in self.controller.datapaths.values():
                self.controller.firewall.remove_block_rule(datapath, ip)

            return Response(
                content_type='application/json',
                charset='utf-8',
                body=json.dumps({'success': success, 'ip': ip})
            )
        except Exception as e:
            return Response(status=500, charset='utf-8', body=str(e))

    @route('securenet', '/securenet/loadbalancer/status', methods=['GET'])
    def get_lb_status(self, req, **kwargs):
        """Get load balancer status."""
        status = self.controller.load_balancer.get_statistics()
        status['pool_status'] = self.controller.load_balancer.get_pool_status()
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(status, indent=2)
        )

    @route('securenet', '/securenet/qos/status', methods=['GET'])
    def get_qos_status(self, req, **kwargs):
        """Get QoS status."""
        status = self.controller.qos_manager.get_statistics()
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(status, indent=2)
        )

    @route('securenet', '/securenet/firewall/status', methods=['GET'])
    def get_firewall_status(self, req, **kwargs):
        """Get firewall status."""
        status = self.controller.firewall.get_statistics()
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(status, indent=2)
        )

    @route('securenet', '/securenet/stats', methods=['GET'])
    def get_stats(self, req, **kwargs):
        """Get network statistics."""
        stats = self.controller.stats_collector.get_all_statistics()
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(stats, indent=2, default=str)
        )

    @route('securenet', '/securenet/stats/ports', methods=['GET'])
    def get_port_stats(self, req, **kwargs):
        """Get port statistics."""
        stats = self.controller.stats_collector.get_port_stats()
        return Response(
            content_type='application/json',
            charset='utf-8',
            body=json.dumps(stats, indent=2, default=str)
        )


# Entry point for ryu-manager or osken-manager
try:
    app_manager.require_app('ryu.app.rest_topology')
except:
    app_manager.require_app('os_ken.app.rest_topology')
