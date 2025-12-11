"""
SecureNet DC - Statistics Collector Module
CPEG 460 Bonus Project

Collects and aggregates switch statistics using OpenFlow.
Supports:
- Flow statistics
- Port statistics
- Table statistics
- Aggregate statistics
"""

import time
import logging
from collections import defaultdict
from threading import Thread, RLock

logger = logging.getLogger(__name__)


class StatsCollector:
    """
    OpenFlow Statistics Collector.

    Periodically polls switches for statistics and maintains
    historical data for analysis and visualization.
    """

    def __init__(self, config):
        """
        Initialize Statistics Collector.

        Args:
            config: NetworkConfig class with STATS settings
        """
        self.config = config.STATS
        self.poll_interval = self.config['poll_interval']

        # Storage for statistics
        self.flow_stats = defaultdict(dict)      # {dpid: {flow_id: stats}}
        self.port_stats = defaultdict(dict)      # {dpid: {port_no: stats}}
        self.table_stats = defaultdict(dict)     # {dpid: {table_id: stats}}
        self.aggregate_stats = defaultdict(dict) # {dpid: stats}

        # Historical data (for graphs)
        self.history_length = 60  # seconds
        self.bandwidth_history = defaultdict(lambda: defaultdict(list))
        self.packet_history = defaultdict(lambda: defaultdict(list))

        # Datapaths
        self.datapaths = {}

        # Thread control
        self.running = False
        self.poll_thread = None
        self.lock = RLock()  # Use RLock to prevent deadlock in nested calls

        # Callbacks for dashboard updates
        self.callbacks = []

        logger.info("Statistics Collector initialized "
                   f"(poll_interval={self.poll_interval}s)")

    def register_datapath(self, datapath):
        """
        Register a switch for statistics collection.

        Args:
            datapath: OpenFlow datapath
        """
        self.datapaths[datapath.id] = datapath
        logger.info(f"Registered switch {datapath.id} for stats collection")

    def unregister_datapath(self, dpid):
        """
        Unregister a switch.

        Args:
            dpid: Datapath ID
        """
        if dpid in self.datapaths:
            del self.datapaths[dpid]
            logger.info(f"Unregistered switch {dpid} from stats collection")

    def start_polling(self):
        """Start the statistics polling thread."""
        if self.running:
            return

        self.running = True
        self.poll_thread = Thread(target=self._polling_loop)
        self.poll_thread.daemon = True
        self.poll_thread.start()
        logger.info("Statistics polling started")

    def stop_polling(self):
        """Stop the statistics polling thread."""
        self.running = False
        if self.poll_thread:
            self.poll_thread.join(timeout=2)
        logger.info("Statistics polling stopped")

    def _polling_loop(self):
        """Main polling loop."""
        while self.running:
            try:
                self._request_all_stats()
            except Exception as e:
                logger.error(f"Error in polling loop: {e}")

            time.sleep(self.poll_interval)

    def _request_all_stats(self):
        """Request statistics from all registered switches."""
        for dpid, datapath in list(self.datapaths.items()):
            try:
                if self.config.get('flow_stats', True):
                    self._request_flow_stats(datapath)

                if self.config.get('port_stats', True):
                    self._request_port_stats(datapath)

                if self.config.get('table_stats', True):
                    self._request_table_stats(datapath)

                if self.config.get('aggregate_stats', True):
                    self._request_aggregate_stats(datapath)

            except Exception as e:
                logger.error(f"Error requesting stats from switch {dpid}: {e}")

    def _request_flow_stats(self, datapath):
        """Request flow statistics from a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _request_port_stats(self, datapath):
        """Request port statistics from a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _request_table_stats(self, datapath):
        """Request table statistics from a switch."""
        parser = datapath.ofproto_parser

        req = parser.OFPTableStatsRequest(datapath)
        datapath.send_msg(req)

    def _request_aggregate_stats(self, datapath):
        """Request aggregate statistics from a switch."""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        req = parser.OFPAggregateStatsRequest(
            datapath, 0, ofproto.OFPTT_ALL, ofproto.OFPP_ANY,
            ofproto.OFPG_ANY, 0, 0, match
        )
        datapath.send_msg(req)

    def handle_flow_stats_reply(self, ev):
        """
        Handle flow statistics reply.

        Args:
            ev: OpenFlow event
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        with self.lock:
            self.flow_stats[dpid] = {}

            for stat in body:
                flow_id = (stat.match.get('in_port', 0),
                          stat.match.get('eth_dst', ''),
                          stat.match.get('eth_src', ''))

                self.flow_stats[dpid][flow_id] = {
                    'packet_count': stat.packet_count,
                    'byte_count': stat.byte_count,
                    'duration_sec': stat.duration_sec,
                    'priority': stat.priority,
                    'table_id': stat.table_id
                }

        self._notify_callbacks('flow_stats', dpid)

    def handle_port_stats_reply(self, ev):
        """
        Handle port statistics reply.

        Args:
            ev: OpenFlow event
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        current_time = time.time()

        with self.lock:
            old_stats = self.port_stats.get(dpid, {})

            for stat in body:
                port_no = stat.port_no

                # Calculate bandwidth (bytes since last poll)
                old_rx = old_stats.get(port_no, {}).get('rx_bytes', 0)
                old_tx = old_stats.get(port_no, {}).get('tx_bytes', 0)

                rx_rate = (stat.rx_bytes - old_rx) / self.poll_interval if old_rx else 0
                tx_rate = (stat.tx_bytes - old_tx) / self.poll_interval if old_tx else 0

                self.port_stats[dpid][port_no] = {
                    'rx_packets': stat.rx_packets,
                    'tx_packets': stat.tx_packets,
                    'rx_bytes': stat.rx_bytes,
                    'tx_bytes': stat.tx_bytes,
                    'rx_dropped': stat.rx_dropped,
                    'tx_dropped': stat.tx_dropped,
                    'rx_errors': stat.rx_errors,
                    'tx_errors': stat.tx_errors,
                    'rx_rate_bps': rx_rate * 8,
                    'tx_rate_bps': tx_rate * 8,
                    'timestamp': current_time
                }

                # Update history
                self.bandwidth_history[dpid][port_no].append({
                    'time': current_time,
                    'rx': rx_rate * 8,
                    'tx': tx_rate * 8
                })

                # Trim history
                cutoff = current_time - self.history_length
                self.bandwidth_history[dpid][port_no] = [
                    h for h in self.bandwidth_history[dpid][port_no]
                    if h['time'] > cutoff
                ]

        self._notify_callbacks('port_stats', dpid)

    def handle_table_stats_reply(self, ev):
        """
        Handle table statistics reply.

        Args:
            ev: OpenFlow event
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        with self.lock:
            for stat in body:
                self.table_stats[dpid][stat.table_id] = {
                    'active_count': stat.active_count,
                    'lookup_count': stat.lookup_count,
                    'matched_count': stat.matched_count
                }

        self._notify_callbacks('table_stats', dpid)

    def handle_aggregate_stats_reply(self, ev):
        """
        Handle aggregate statistics reply.

        Args:
            ev: OpenFlow event
        """
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        with self.lock:
            self.aggregate_stats[dpid] = {
                'packet_count': body.packet_count,
                'byte_count': body.byte_count,
                'flow_count': body.flow_count
            }

        self._notify_callbacks('aggregate_stats', dpid)

    def register_callback(self, callback):
        """
        Register a callback for statistics updates.

        Args:
            callback: Function to call with (stat_type, dpid) args
        """
        self.callbacks.append(callback)

    def _notify_callbacks(self, stat_type, dpid):
        """Notify all registered callbacks."""
        for callback in self.callbacks:
            try:
                callback(stat_type, dpid)
            except Exception as e:
                logger.error(f"Error in stats callback: {e}")

    def get_port_stats(self, dpid=None, port_no=None):
        """
        Get port statistics.

        Args:
            dpid: Optional datapath ID filter
            port_no: Optional port number filter

        Returns:
            dict: Port statistics
        """
        with self.lock:
            if dpid is not None:
                if port_no is not None:
                    return self.port_stats.get(dpid, {}).get(port_no, {})
                return dict(self.port_stats.get(dpid, {}))
            return {d: dict(p) for d, p in self.port_stats.items()}

    def get_flow_stats(self, dpid=None):
        """
        Get flow statistics.

        Args:
            dpid: Optional datapath ID filter

        Returns:
            dict: Flow statistics
        """
        with self.lock:
            if dpid is not None:
                return dict(self.flow_stats.get(dpid, {}))
            return {d: dict(f) for d, f in self.flow_stats.items()}

    def get_bandwidth_history(self, dpid, port_no):
        """
        Get bandwidth history for a port.

        Args:
            dpid: Datapath ID
            port_no: Port number

        Returns:
            list: Bandwidth history entries
        """
        with self.lock:
            return list(self.bandwidth_history[dpid][port_no])

    def get_network_summary(self):
        """
        Get summary of network statistics.

        Returns:
            dict: Network summary
        """
        with self.lock:
            total_flows = 0
            total_packets = 0
            total_bytes = 0

            for dpid, stats in self.aggregate_stats.items():
                total_flows += stats.get('flow_count', 0)
                total_packets += stats.get('packet_count', 0)
                total_bytes += stats.get('byte_count', 0)

            total_rx_rate = 0
            total_tx_rate = 0

            for dpid, ports in self.port_stats.items():
                for port_no, stats in ports.items():
                    total_rx_rate += stats.get('rx_rate_bps', 0)
                    total_tx_rate += stats.get('tx_rate_bps', 0)

            return {
                'switches': len(self.datapaths),
                'total_flows': total_flows,
                'total_packets': total_packets,
                'total_bytes': total_bytes,
                'total_rx_rate_mbps': total_rx_rate / 1e6,
                'total_tx_rate_mbps': total_tx_rate / 1e6
            }

    def get_all_statistics(self):
        """
        Get all collected statistics.

        Returns:
            dict: All statistics
        """
        with self.lock:
            return {
                'flow_stats': {d: dict(f) for d, f in self.flow_stats.items()},
                'port_stats': {d: dict(p) for d, p in self.port_stats.items()},
                'table_stats': {d: dict(t) for d, t in self.table_stats.items()},
                'aggregate_stats': dict(self.aggregate_stats),
                'summary': self.get_network_summary()
            }
