#!/usr/bin/env python3
"""
SecureNet DC - Real-Time Monitoring Dashboard
CPEG 460 Bonus Project

Flask-based web dashboard with:
- Live network topology visualization (D3.js)
- Real-time traffic graphs
- DDoS attack alerts
- QoS statistics
- Load balancer status
"""

from flask import Flask, render_template, jsonify, request
from flask_socketio import SocketIO, emit
from flask_cors import CORS
import json
import time
import threading
import logging
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('dashboard')

app = Flask(__name__)
app.config['SECRET_KEY'] = 'securenet_dc_secret'
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Controller API URL (localhost when running in WSL)
CONTROLLER_API = 'http://127.0.0.1:8080/securenet'

# Dashboard state
dashboard_state = {
    'connected_clients': 0,
    'last_update': 0,
    'topology': None,
    'stats': None,
    'alerts': []
}

# Simulation mode - False to use REAL data from controller
# Set to True only if controller is not available
SIMULATION_MODE = False
import random

# Persistent simulation state (accumulating values)
sim_state = {
    'total_packets': 0,
    'total_bytes': 0,
    'total_requests': 0,
    'attack_count': 0,
    'attacks': [],
    'blocked': [],
    'server_requests': [0, 0, 0, 0],
    'active_attacker': None  # Track which node is attacking
}

def generate_simulation_data():
    """Generate realistic simulated network data with accumulating values."""
    # Accumulate traffic (add random increment each second)
    sim_state['total_packets'] += random.randint(500, 2000)
    sim_state['total_bytes'] += random.randint(50000, 200000)

    # Current rates (instantaneous, can fluctuate)
    rx_rate = random.uniform(20, 80)
    tx_rate = random.uniform(20, 80)

    # Randomly trigger DDoS attacks (10% chance per update)
    attacks = sim_state['attacks']
    blocked = sim_state['blocked']

    # Map attacker IPs to host IDs for topology highlighting
    attacker_map = {
        '10.0.3.13': 'h13',  # Attacker host
        '10.0.2.7': 'h7',
        '10.0.1.99': 'h4',
        '10.0.4.50': 'h14'   # IDS host (compromised scenario)
    }

    # Chance of new attack
    if random.random() < 0.12:  # 12% chance of attack
        attack_types = ['SYN_FLOOD', 'ICMP_FLOOD', 'UDP_FLOOD']
        attacker_ip = random.choice(list(attacker_map.keys()))
        new_attack = {
            'timestamp': time.strftime('%H:%M:%S'),
            'attack_type': random.choice(attack_types),
            'src_ip': attacker_ip,
            'host_id': attacker_map[attacker_ip],
            'packets': random.randint(100, 500),
            'action': 'BLOCKED'
        }
        attacks.insert(0, new_attack)
        attacks = attacks[:10]  # Keep last 10
        sim_state['attack_count'] += 1
        sim_state['active_attacker'] = attacker_map[attacker_ip]

        # Add to blocked hosts
        if attacker_ip not in [b['ip'] for b in blocked]:
            blocked.append({
                'ip': attacker_ip,
                'host_id': attacker_map[attacker_ip],
                'remaining_time': random.randint(30, 60)
            })
    else:
        # Clear active attacker after a bit
        if random.random() < 0.3:
            sim_state['active_attacker'] = None

    # Decrease block timers
    for host in blocked[:]:
        host['remaining_time'] -= 1
        if host['remaining_time'] <= 0:
            blocked.remove(host)

    sim_state['attacks'] = attacks
    sim_state['blocked'] = blocked

    # Accumulate load balancer requests
    sim_state['total_requests'] += random.randint(5, 20)
    for i in range(4):
        sim_state['server_requests'][i] += random.randint(1, 5)

    return {
        'status': {
            'switches': 20,  # Fat-tree k=4 has 20 switches
            'network': {
                'total_flows': 50 + len(blocked) * 10 + sim_state['attack_count'],
                'total_packets': sim_state['total_packets'],
                'total_bytes': sim_state['total_bytes'],
                'total_rx_rate_mbps': rx_rate,
                'total_tx_rate_mbps': tx_rate
            },
            'ddos': {
                'total_attacks': sim_state['attack_count'],
                'currently_blocked': len(blocked),
                'blocked_hosts': blocked
            },
            'load_balancer': {
                'vip': '10.0.0.100',
                'algorithm': 'round_robin',
                'total_requests': sim_state['total_requests']
            }
        },
        'alerts': attacks,
        'lb_status': {
            'pool_status': [
                {'ip': '10.0.1.1', 'healthy': True, 'total_requests': sim_state['server_requests'][0]},
                {'ip': '10.0.1.2', 'healthy': True, 'total_requests': sim_state['server_requests'][1]},
                {'ip': '10.0.1.3', 'healthy': random.random() > 0.05, 'total_requests': sim_state['server_requests'][2]},
                {'ip': '10.0.1.4', 'healthy': True, 'total_requests': sim_state['server_requests'][3]}
            ]
        },
        'active_attacker': sim_state['active_attacker'],  # For topology highlighting
        'blocked_hosts_ids': [b['host_id'] for b in blocked],  # For topology highlighting
        'timestamp': time.time()
    }


def fetch_controller_data(endpoint):
    """Fetch data from the SDN controller REST API."""
    try:
        response = requests.get(f"{CONTROLLER_API}/{endpoint}", timeout=2)
        if response.status_code == 200:
            return response.json()
    except Exception as e:
        logger.debug(f"Failed to fetch {endpoint}: {e}")
    return None


def background_updater():
    """Background thread to fetch and broadcast updates."""
    while True:
        try:
            if SIMULATION_MODE:
                # Use simulated data for demo
                sim_data = generate_simulation_data()
                dashboard_state['stats'] = sim_data['status']
                dashboard_state['alerts'] = sim_data['alerts']
                dashboard_state['last_update'] = time.time()

                # Broadcast to connected clients
                if dashboard_state['connected_clients'] > 0:
                    socketio.emit('stats_update', sim_data)
            else:
                # Fetch all data from controller
                status = fetch_controller_data('status')
                alerts = fetch_controller_data('ddos/alerts')
                lb_status = fetch_controller_data('loadbalancer/status')
                stats = fetch_controller_data('stats')

                # Update dashboard state
                dashboard_state['stats'] = status
                dashboard_state['alerts'] = alerts or []
                dashboard_state['last_update'] = time.time()

                # Broadcast to connected clients
                if dashboard_state['connected_clients'] > 0:
                    socketio.emit('stats_update', {
                        'status': status,
                        'alerts': alerts,
                        'lb_status': lb_status,
                        'network_stats': stats,
                        'timestamp': time.time()
                    })

        except Exception as e:
            logger.error(f"Background updater error: {e}")

        time.sleep(1)  # Update every second


# Start background thread
updater_thread = threading.Thread(target=background_updater, daemon=True)
updater_thread.start()


# ===== Routes =====

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')


@app.route('/api/status')
def api_status():
    """Get current dashboard status."""
    return jsonify({
        'status': 'running',
        'connected_clients': dashboard_state['connected_clients'],
        'last_update': dashboard_state['last_update'],
        'controller_data': dashboard_state['stats']
    })


@app.route('/api/topology')
def api_topology():
    """Get network topology data - LARGER tree,depth=2,fanout=3 topology."""
    # Try to fetch from stats collector first for real-time status
    try:
        response = requests.get(f"{CONTROLLER_API}/topology", timeout=2)
        if response.status_code == 200:
            return jsonify(response.json())
    except:
        pass

    # Fallback: Static topology (tree,depth=2,fanout=3 = 4 switches, 9 hosts)
    # All hosts start as normal - roles assigned dynamically based on behavior
    topology = {
        'nodes': [
            # Switches
            {'id': 's1', 'type': 'core', 'label': 'Core S1', 'layer': 0},
            {'id': 's2', 'type': 'edge', 'label': 'Switch S2', 'layer': 1},
            {'id': 's3', 'type': 'edge', 'label': 'Switch S3', 'layer': 1},
            {'id': 's4', 'type': 'edge', 'label': 'Switch S4', 'layer': 1},
            # All hosts - roles determined by real-time behavior
            {'id': 'h1', 'type': 'host', 'role': 'host', 'label': 'H1 (10.0.0.1)', 'layer': 2, 'ip': '10.0.0.1'},
            {'id': 'h2', 'type': 'host', 'role': 'host', 'label': 'H2 (10.0.0.2)', 'layer': 2, 'ip': '10.0.0.2'},
            {'id': 'h3', 'type': 'host', 'role': 'host', 'label': 'H3 (10.0.0.3)', 'layer': 2, 'ip': '10.0.0.3'},
            {'id': 'h4', 'type': 'host', 'role': 'host', 'label': 'H4 (10.0.0.4)', 'layer': 2, 'ip': '10.0.0.4'},
            {'id': 'h5', 'type': 'host', 'role': 'host', 'label': 'H5 (10.0.0.5)', 'layer': 2, 'ip': '10.0.0.5'},
            {'id': 'h6', 'type': 'host', 'role': 'host', 'label': 'H6 (10.0.0.6)', 'layer': 2, 'ip': '10.0.0.6'},
            {'id': 'h7', 'type': 'host', 'role': 'host', 'label': 'H7 (10.0.0.7)', 'layer': 2, 'ip': '10.0.0.7'},
            {'id': 'h8', 'type': 'host', 'role': 'host', 'label': 'H8 (10.0.0.8)', 'layer': 2, 'ip': '10.0.0.8'},
            {'id': 'h9', 'type': 'host', 'role': 'host', 'label': 'H9 (10.0.0.9)', 'layer': 2, 'ip': '10.0.0.9'},
        ],
        'links': [
            {'source': 's1', 'target': 's2', 'type': 'core'},
            {'source': 's1', 'target': 's3', 'type': 'core'},
            {'source': 's1', 'target': 's4', 'type': 'core'},
            {'source': 's2', 'target': 'h1', 'type': 'host'},
            {'source': 's2', 'target': 'h2', 'type': 'host'},
            {'source': 's2', 'target': 'h3', 'type': 'host'},
            {'source': 's3', 'target': 'h4', 'type': 'host'},
            {'source': 's3', 'target': 'h5', 'type': 'host'},
            {'source': 's3', 'target': 'h6', 'type': 'host'},
            {'source': 's4', 'target': 'h7', 'type': 'host'},
            {'source': 's4', 'target': 'h8', 'type': 'host'},
            {'source': 's4', 'target': 'h9', 'type': 'host'},
        ],
        'blocked_hosts': [],
        'attacking_hosts': []
    }
    return jsonify(topology)


@app.route('/api/alerts')
def api_alerts():
    """Get recent alerts."""
    return jsonify(dashboard_state['alerts'])


@app.route('/api/loadbalancer')
def api_loadbalancer():
    """Get load balancer status."""
    return jsonify(fetch_controller_data('loadbalancer/status') or {})


@app.route('/api/qos')
def api_qos():
    """Get QoS status."""
    return jsonify(fetch_controller_data('qos/status') or {})


# ===== WebSocket Events =====

@socketio.on('connect')
def handle_connect():
    """Handle client connection."""
    dashboard_state['connected_clients'] += 1
    logger.info(f"Client connected. Total: {dashboard_state['connected_clients']}")
    emit('connected', {'status': 'ok'})


@socketio.on('disconnect')
def handle_disconnect():
    """Handle client disconnection."""
    dashboard_state['connected_clients'] -= 1
    logger.info(f"Client disconnected. Total: {dashboard_state['connected_clients']}")


@socketio.on('request_update')
def handle_request_update():
    """Handle manual update request."""
    emit('stats_update', {
        'status': dashboard_state['stats'],
        'alerts': dashboard_state['alerts'],
        'timestamp': time.time()
    })


def run_dashboard(host='0.0.0.0', port=5000, debug=False):
    """Run the dashboard server."""
    logger.info(f"Starting SecureNet DC Dashboard on http://{host}:{port}")
    socketio.run(app, host=host, port=port, debug=debug, allow_unsafe_werkzeug=True)


if __name__ == '__main__':
    run_dashboard(debug=True)
