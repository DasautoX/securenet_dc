#!/bin/bash
# SecureNet DC - Stop Full SDN Services

echo "Stopping SecureNet DC Full SDN services..."

# Stop Ryu
if [ -f /tmp/ryu.pid ]; then
    kill $(cat /tmp/ryu.pid) 2>/dev/null
    rm /tmp/ryu.pid
fi
pkill -9 -f "ryu-manager" 2>/dev/null

# Stop Dashboard
if [ -f /tmp/dashboard.pid ]; then
    kill $(cat /tmp/dashboard.pid) 2>/dev/null
    rm /tmp/dashboard.pid
fi
pkill -9 -f "python.*app.py" 2>/dev/null

# Stop Stats Collector
pkill -9 -f "network_stats_collector" 2>/dev/null

# Clean Mininet
mn -c 2>/dev/null

# Clean OVS bridges
for br in $(ovs-vsctl list-br 2>/dev/null); do
    ovs-vsctl del-br $br 2>/dev/null
done

echo "All services stopped."
