/**
 * SecureNet DC - Dashboard JavaScript
 * CPEG 460 Bonus Project
 *
 * Handles D3.js topology visualization and real-time updates
 */

// Global state
let socket = null;
let topology = null;
let simulation = null;

// Initialize on page load
document.addEventListener('DOMContentLoaded', () => {
    initWebSocket();
    loadTopology();
    startPeriodicUpdates();
});

/**
 * Initialize WebSocket connection
 */
function initWebSocket() {
    socket = io();

    socket.on('connect', () => {
        console.log('Connected to dashboard server');
        updateControllerStatus('Connected', true);
    });

    socket.on('disconnect', () => {
        console.log('Disconnected from dashboard server');
        updateControllerStatus('Disconnected', false);
    });

    socket.on('stats_update', (data) => {
        updateDashboard(data);
    });

    socket.on('connected', (data) => {
        console.log('WebSocket connected:', data);
    });
}

/**
 * Update controller status display
 */
function updateControllerStatus(status, connected) {
    const elem = document.getElementById('controller-status');
    elem.textContent = status;
    elem.style.color = connected ? '#3fb950' : '#f85149';
}

/**
 * Load and render network topology
 */
async function loadTopology() {
    try {
        const response = await fetch('/api/topology');
        topology = await response.json();
        renderTopology();
    } catch (error) {
        console.error('Failed to load topology:', error);
    }
}

/**
 * Render network topology using fixed hierarchical layout
 * Supports tree,depth=2,fanout=3 topology (4 switches, 9 hosts)
 */
function renderTopology() {
    const container = document.getElementById('topology-container');
    const width = container.clientWidth || 800;
    const height = container.clientHeight || 450;

    // Clear existing
    d3.select('#topology-container').selectAll('*').remove();

    // Create SVG
    const svg = d3.select('#topology-container')
        .append('svg')
        .attr('width', width)
        .attr('height', height);

    // Add defs for gradients and filters
    const defs = svg.append('defs');

    // Glow filter for attacking nodes
    const glowFilter = defs.append('filter')
        .attr('id', 'glow')
        .attr('x', '-50%')
        .attr('y', '-50%')
        .attr('width', '200%')
        .attr('height', '200%');
    glowFilter.append('feGaussianBlur')
        .attr('stdDeviation', '4')
        .attr('result', 'coloredBlur');
    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Add zoom behavior
    const g = svg.append('g');
    svg.call(d3.zoom()
        .extent([[0, 0], [width, height]])
        .scaleExtent([0.5, 3])
        .on('zoom', (event) => {
            g.attr('transform', event.transform);
        }));

    // Calculate fixed positions for tree topology
    const layerY = {
        0: 50,   // Core switch (s1)
        1: 160,  // Edge switches (s2, s3, s4)
        2: 320   // Hosts (h1-h9)
    };

    // Position nodes by layer
    const nodePositions = {};

    // Core switch (s1) - center top
    const cores = topology.nodes.filter(n => n.type === 'core');
    cores.forEach((node, i) => {
        node.x = width / 2;
        node.y = layerY[0];
        nodePositions[node.id] = { x: node.x, y: node.y };
    });

    // Edge switches (s2, s3, s4) - spread horizontally into 3 columns
    const edges = topology.nodes.filter(n => n.type === 'edge');
    const edgeCount = edges.length || 3;
    edges.forEach((node, i) => {
        node.x = width * (0.17 + i * 0.33);
        node.y = layerY[1];
        nodePositions[node.id] = { x: node.x, y: node.y };
    });

    // Hosts - 3 under each edge switch
    const hosts = topology.nodes.filter(n => n.type === 'host');
    const hostsPerEdge = 3;
    hosts.forEach((node, i) => {
        const edgeIdx = Math.floor(i / hostsPerEdge);
        const hostInEdge = i % hostsPerEdge;
        const baseX = width * (0.17 + edgeIdx * 0.33);
        node.x = baseX + (hostInEdge - 1) * 70;
        node.y = layerY[2];
        nodePositions[node.id] = { x: node.x, y: node.y };
    });

    // Draw links
    g.append('g')
        .selectAll('line')
        .data(topology.links)
        .join('line')
        .attr('class', d => `link ${d.type}`)
        .attr('x1', d => nodePositions[d.source.id || d.source]?.x || 0)
        .attr('y1', d => nodePositions[d.source.id || d.source]?.y || 0)
        .attr('x2', d => nodePositions[d.target.id || d.target]?.x || 0)
        .attr('y2', d => nodePositions[d.target.id || d.target]?.y || 0);

    // Draw nodes
    const node = g.append('g')
        .selectAll('g')
        .data(topology.nodes)
        .join('g')
        .attr('class', d => {
            let cls = `node ${d.type}`;
            if (d.role) cls += ` ${d.role}`;
            if (d.blocked) cls += ' blocked';
            if (d.attacking) cls += ' attacking';
            return cls;
        })
        .attr('id', d => `node-${d.id}`)
        .attr('transform', d => `translate(${d.x},${d.y})`);

    // Node circles
    node.append('circle')
        .attr('r', d => {
            if (d.type === 'core') return 20;
            if (d.type === 'edge') return 14;
            return 10;
        })
        .attr('filter', d => (d.attacking && !d.blocked) ? 'url(#glow)' : null)
        .on('mouseover', showTooltip)
        .on('mouseout', hideTooltip);

    // Add X mark for blocked hosts
    node.filter(d => d.blocked)
        .append('text')
        .attr('class', 'blocked-mark')
        .attr('dy', 5)
        .attr('text-anchor', 'middle')
        .style('font-size', '16px')
        .style('font-weight', 'bold')
        .style('fill', '#fff')
        .text('✕');

    // Node labels
    node.append('text')
        .attr('dy', d => {
            if (d.type === 'host') return 25;
            return 35;
        })
        .attr('class', 'node-label')
        .text(d => d.label);

    // Status badges - only show for attacking/blocked (dynamic, not pre-assigned)
    node.filter(d => d.type === 'host' && (d.attacking || d.blocked))
        .append('text')
        .attr('dy', -18)
        .attr('class', 'status-badge')
        .style('font-size', '10px')
        .style('font-weight', 'bold')
        .style('fill', d => {
            if (d.blocked) return '#f85149';
            if (d.attacking) return '#ff6b6b';
            return '#8b949e';
        })
        .text(d => {
            if (d.blocked) return 'BLOCKED';
            if (d.attacking) return 'ATTACKING';
            return '';
        });
}

/**
 * Drag handlers for nodes
 */
function dragStarted(event, d) {
    if (!event.active) simulation.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
}

function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
}

function dragEnded(event, d) {
    if (!event.active) simulation.alphaTarget(0);
    d.fx = null;
    d.fy = null;
}

/**
 * Tooltip functions
 */
function showTooltip(event, d) {
    // Could add tooltip element here
    console.log('Node:', d);
}

function hideTooltip() {
    // Hide tooltip
}

/**
 * Reset topology view
 */
function resetTopology() {
    if (topology) {
        renderTopology();
    }
}

/**
 * Update dashboard with new data
 */
function updateDashboard(data) {
    // Update timestamp
    const now = new Date();
    document.getElementById('last-update').textContent = now.toLocaleTimeString();

    if (data.status) {
        // Update switch count
        document.getElementById('switch-count').textContent = data.status.switches || 0;

        // Update flow count
        if (data.status.network) {
            document.getElementById('flow-count').textContent = data.status.network.total_flows || 0;
            document.getElementById('total-packets').textContent = formatNumber(data.status.network.total_packets || 0);
            document.getElementById('total-bytes').textContent = formatBytes(data.status.network.total_bytes || 0);
            document.getElementById('rx-rate').textContent = (data.status.network.total_rx_rate_mbps || 0).toFixed(1) + ' Mbps';
            document.getElementById('tx-rate').textContent = (data.status.network.total_tx_rate_mbps || 0).toFixed(1) + ' Mbps';
        }

        // Update DDoS stats
        if (data.status.ddos) {
            document.getElementById('attacks-detected').textContent = data.status.ddos.total_attacks || 0;
            document.getElementById('hosts-blocked').textContent = data.status.ddos.currently_blocked || 0;
            updateBlockedHosts(data.status.ddos.blocked_hosts || []);
        }

        // Update Load Balancer
        if (data.status.load_balancer) {
            document.getElementById('lb-vip').textContent = data.status.load_balancer.vip || '10.0.0.100';
            document.getElementById('lb-algorithm').textContent = data.status.load_balancer.algorithm || 'round_robin';
            document.getElementById('lb-requests').textContent = data.status.load_balancer.total_requests || 0;
            updateServerPool(data.lb_status);
        }
    }

    // Update alerts
    if (data.alerts) {
        updateAlerts(data.alerts.alerts || data.alerts);
    }

    // Update topology highlighting for attackers
    // Handle both old format (active_attacker) and new format (attacking_hosts array)
    let attackingHosts = data.attacking_hosts || [];
    if (data.active_attacker && !attackingHosts.includes(data.active_attacker)) {
        attackingHosts = [data.active_attacker, ...attackingHosts];
    }

    let blockedHosts = data.blocked_hosts || data.blocked_hosts_ids || [];
    if (data.status?.ddos?.blocked_hosts) {
        blockedHosts = data.status.ddos.blocked_hosts.map(h => h.host_id);
    }

    updateTopologyHighlights(attackingHosts, blockedHosts);

    // Reload topology if needed to get fresh status
    if (data.status?.ddos?.currently_blocked > 0 || attackingHosts.length > 0) {
        // Refresh topology data for real-time status
        refreshTopologyData();
    }
}

/**
 * Refresh topology data from API
 */
async function refreshTopologyData() {
    try {
        const response = await fetch('/api/topology');
        const data = await response.json();
        if (data.nodes) {
            topology = data;
            // Update nodes with current status without re-rendering
            data.nodes.forEach(node => {
                const nodeElem = d3.select(`#node-${node.id}`);
                if (!nodeElem.empty()) {
                    nodeElem.classed('blocked', node.blocked || false);
                    nodeElem.classed('attacking', node.attacking || false);
                }
            });

            if (data.attacking_hosts) {
                updateTopologyHighlights(data.attacking_hosts, data.blocked_hosts || []);
            }
        }
    } catch (error) {
        console.debug('Topology refresh error:', error);
    }
}

/**
 * Highlight attacker nodes in topology with animations
 */
function updateTopologyHighlights(attackingHosts, blockedHosts) {
    // Reset all nodes
    d3.selectAll('.node')
        .classed('attacking', false)
        .classed('blocked', false);

    d3.selectAll('.node circle')
        .attr('filter', null);

    // Remove existing X marks
    d3.selectAll('.blocked-mark').remove();

    // Highlight attacking hosts (pulsing red glow)
    if (attackingHosts && attackingHosts.length > 0) {
        attackingHosts.forEach(hostId => {
            const node = d3.select(`#node-${hostId}`);
            if (!node.empty()) {
                node.classed('attacking', true);
                node.select('circle').attr('filter', 'url(#glow)');
            }
        });
    }

    // Mark blocked hosts with X
    if (blockedHosts && blockedHosts.length > 0) {
        blockedHosts.forEach(hostId => {
            const node = d3.select(`#node-${hostId}`);
            if (!node.empty()) {
                node.classed('blocked', true);
                node.classed('attacking', false);
                node.select('circle').attr('filter', null);

                // Add X mark if not exists
                if (node.select('.blocked-mark').empty()) {
                    node.append('text')
                        .attr('class', 'blocked-mark')
                        .attr('dy', 5)
                        .attr('text-anchor', 'middle')
                        .style('font-size', '16px')
                        .style('font-weight', 'bold')
                        .style('fill', '#fff')
                        .text('✕');
                }
            }
        });
    }
}

/**
 * Update blocked hosts list
 */
function updateBlockedHosts(hosts) {
    const list = document.getElementById('blocked-list');
    list.innerHTML = '';

    if (!hosts || hosts.length === 0) {
        list.innerHTML = '<li style="color: var(--text-secondary);">No blocked hosts</li>';
        return;
    }

    hosts.forEach(host => {
        const li = document.createElement('li');
        li.innerHTML = `
            <span class="ip">${host.ip}</span>
            <span class="time">${host.remaining_time}s</span>
        `;
        list.appendChild(li);
    });
}

/**
 * Update server pool display
 */
function updateServerPool(lbStatus) {
    const pool = document.getElementById('server-pool');
    pool.innerHTML = '';

    if (!lbStatus || !lbStatus.pool_status) {
        return;
    }

    lbStatus.pool_status.forEach(server => {
        const div = document.createElement('div');
        div.className = 'server-item';
        div.innerHTML = `
            <span class="server-status ${server.healthy ? 'healthy' : 'unhealthy'}"></span>
            <span class="server-ip">${server.ip}</span>
            <span class="server-requests">${server.total_requests} req</span>
        `;
        pool.appendChild(div);
    });
}

/**
 * Update alerts display
 */
function updateAlerts(alerts) {
    const container = document.getElementById('alerts-container');
    const countElem = document.getElementById('alert-count');

    countElem.textContent = alerts.length;

    container.innerHTML = '';

    if (!alerts || alerts.length === 0) {
        container.innerHTML = '<div style="color: var(--text-secondary); text-align: center; padding: 20px;">No alerts</div>';
        return;
    }

    alerts.slice(0, 10).forEach(alert => {
        const div = document.createElement('div');
        div.className = 'alert-item';
        div.innerHTML = `
            <span class="alert-time">${alert.timestamp}</span>
            <span class="alert-type">${alert.attack_type}</span>
            <span class="alert-source">${alert.src_ip}</span>
            <span class="alert-action">${alert.action}</span>
        `;
        container.appendChild(div);
    });
}

/**
 * Start periodic data updates
 */
function startPeriodicUpdates() {
    // Request update every 2 seconds if WebSocket isn't working
    setInterval(() => {
        if (socket && socket.connected) {
            socket.emit('request_update');
        }
    }, 2000);

    // Also poll REST API directly as fallback (works even if WebSocket fails)
    setInterval(async () => {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            if (data.controller_data) {
                // Transform to expected format
                updateDashboard({
                    status: data.controller_data,
                    alerts: data.controller_data.ddos?.blocked_hosts || [],
                    lb_status: {
                        pool_status: Object.entries(data.controller_data.load_balancer?.requests_per_server || {}).map(([ip, requests]) => ({
                            ip: ip,
                            healthy: data.controller_data.load_balancer?.server_health?.[ip] ?? true,
                            total_requests: requests
                        }))
                    },
                    timestamp: data.last_update
                });
                console.log('REST API update:', data.controller_data.network);
            }
        } catch (error) {
            console.error('REST API fetch failed:', error);
        }
    }, 1000);  // Poll every second
}

/**
 * Format large numbers
 */
function formatNumber(num) {
    if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
    if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
    return num.toString();
}

/**
 * Format bytes to human readable
 */
function formatBytes(bytes) {
    if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(1) + ' GB';
    if (bytes >= 1048576) return (bytes / 1048576).toFixed(1) + ' MB';
    if (bytes >= 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return bytes + ' B';
}

// Handle window resize
window.addEventListener('resize', () => {
    if (topology) {
        renderTopology();
    }
});
