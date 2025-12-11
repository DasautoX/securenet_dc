#!/bin/bash
# SecureNet DC - Full SDN Version Startup Script
# Run this in a VM with OVS + Ryu installed
# Usage: ./scripts/start_full_sdn.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${BLUE}"
    echo "========================================================"
    echo "  SecureNet DC - Full SDN Version"
    echo "  Open vSwitch + Ryu Controller + Mininet"
    echo "========================================================"
    echo -e "${NC}"
}

check_requirements() {
    echo -e "${YELLOW}[*] Checking requirements...${NC}"

    # Check if running as root (needed for Mininet)
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[!] Please run as root (sudo)${NC}"
        exit 1
    fi

    # Check OVS
    if ! command -v ovs-vsctl &> /dev/null; then
        echo -e "${RED}[!] Open vSwitch not installed${NC}"
        echo "    Run: sudo apt install openvswitch-switch openvswitch-common"
        exit 1
    fi

    # Check Ryu
    if ! command -v ryu-manager &> /dev/null; then
        echo -e "${RED}[!] Ryu not installed${NC}"
        echo "    Run: pip install ryu eventlet"
        exit 1
    fi

    # Check Mininet
    if ! command -v mn &> /dev/null; then
        echo -e "${RED}[!] Mininet not installed${NC}"
        echo "    Run: sudo apt install mininet"
        exit 1
    fi

    # Check OVS is running
    if ! systemctl is-active --quiet openvswitch-switch; then
        echo -e "${YELLOW}[*] Starting OVS service...${NC}"
        systemctl start openvswitch-switch
    fi

    echo -e "${GREEN}[+] All requirements met${NC}"
}

cleanup() {
    echo -e "${YELLOW}[*] Cleaning up previous instances...${NC}"

    # Kill existing processes
    pkill -9 -f "ryu-manager" 2>/dev/null || true
    pkill -9 -f "network_stats_collector" 2>/dev/null || true
    pkill -9 -f "python.*app.py" 2>/dev/null || true

    # Clean Mininet
    mn -c 2>/dev/null || true

    # Clean OVS bridges
    for br in $(ovs-vsctl list-br 2>/dev/null); do
        ovs-vsctl del-br $br 2>/dev/null || true
    done

    sleep 2
    echo -e "${GREEN}[+] Cleanup complete${NC}"
}

start_ryu_controller() {
    echo -e "${YELLOW}[*] Starting Ryu SDN Controller...${NC}"

    cd "$PROJECT_DIR"

    # Activate virtual environment if it exists
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi

    # Start Ryu in background
    ryu-manager controller/securenet_controller.py \
        --observe-links \
        --wsapi-host 0.0.0.0 \
        --wsapi-port 8080 \
        > /tmp/ryu.log 2>&1 &

    RYU_PID=$!
    echo $RYU_PID > /tmp/ryu.pid

    # Wait for controller to start
    sleep 3

    if kill -0 $RYU_PID 2>/dev/null; then
        echo -e "${GREEN}[+] Ryu Controller started (PID: $RYU_PID)${NC}"
        echo "    Logs: /tmp/ryu.log"
        echo "    OpenFlow: 0.0.0.0:6653"
        echo "    REST API: 0.0.0.0:8080"
    else
        echo -e "${RED}[!] Failed to start Ryu Controller${NC}"
        cat /tmp/ryu.log
        exit 1
    fi
}

start_dashboard() {
    echo -e "${YELLOW}[*] Starting Web Dashboard...${NC}"

    cd "$PROJECT_DIR"

    # Activate virtual environment if it exists
    if [ -f "venv/bin/activate" ]; then
        source venv/bin/activate
    fi

    # Start dashboard in background
    python3 dashboard/app.py > /tmp/dashboard.log 2>&1 &

    DASH_PID=$!
    echo $DASH_PID > /tmp/dashboard.pid

    sleep 2

    if kill -0 $DASH_PID 2>/dev/null; then
        echo -e "${GREEN}[+] Dashboard started (PID: $DASH_PID)${NC}"
        echo "    URL: http://localhost:5000"
        echo "    Logs: /tmp/dashboard.log"
    else
        echo -e "${RED}[!] Failed to start Dashboard${NC}"
        cat /tmp/dashboard.log
    fi
}

start_mininet() {
    echo -e "${YELLOW}[*] Starting Mininet with OVS (OpenFlow 1.3)...${NC}"

    # Create network with OVS switches connected to remote controller
    mn --controller=remote,ip=127.0.0.1,port=6653 \
       --switch ovsk,protocols=OpenFlow13 \
       --topo tree,depth=2,fanout=2 \
       --mac \
       > /tmp/mininet.log 2>&1 &

    MN_PID=$!
    echo $MN_PID > /tmp/mininet.pid

    sleep 5

    if kill -0 $MN_PID 2>/dev/null; then
        echo -e "${GREEN}[+] Mininet started (PID: $MN_PID)${NC}"
        echo "    Topology: tree,depth=2,fanout=2"
        echo "    Switches: 3 (s1=core, s2/s3=edge)"
        echo "    Hosts: 4 (h1-h4)"
    else
        echo -e "${RED}[!] Failed to start Mininet${NC}"
        cat /tmp/mininet.log
    fi
}

show_status() {
    echo ""
    echo -e "${BLUE}========================================================"
    echo "  SecureNet DC - Full SDN Mode Running"
    echo "========================================================${NC}"
    echo ""
    echo -e "${GREEN}Services:${NC}"
    echo "  • Ryu Controller:  http://localhost:8080 (REST API)"
    echo "  • Web Dashboard:   http://localhost:5000"
    echo "  • OpenFlow:        localhost:6653"
    echo ""
    echo -e "${GREEN}Logs:${NC}"
    echo "  • Ryu:       /tmp/ryu.log"
    echo "  • Dashboard: /tmp/dashboard.log"
    echo "  • Mininet:   /tmp/mininet.log"
    echo ""
    echo -e "${GREEN}PIDs:${NC}"
    [ -f /tmp/ryu.pid ] && echo "  • Ryu:       $(cat /tmp/ryu.pid)"
    [ -f /tmp/dashboard.pid ] && echo "  • Dashboard: $(cat /tmp/dashboard.pid)"
    [ -f /tmp/mininet.pid ] && echo "  • Mininet:   $(cat /tmp/mininet.pid)"
    echo ""
    echo -e "${YELLOW}To run an attack demo:${NC}"
    echo "  1. Open a new terminal"
    echo "  2. Run: sudo python3 $PROJECT_DIR/scripts/attack_simulator.py"
    echo ""
    echo -e "${YELLOW}Or manually in Mininet CLI:${NC}"
    echo "  mininet> h4 ping -f 10.0.0.1"
    echo ""
    echo -e "${YELLOW}To stop all services:${NC}"
    echo "  sudo $SCRIPT_DIR/stop_full_sdn.sh"
    echo "  or: sudo mn -c && pkill ryu-manager && pkill -f app.py"
    echo ""
}

show_flows() {
    echo -e "${YELLOW}[*] Current OpenFlow rules:${NC}"
    sleep 3  # Wait for switches to connect
    for sw in s1 s2 s3; do
        echo ""
        echo "Switch $sw:"
        ovs-ofctl dump-flows $sw -O OpenFlow13 2>/dev/null || echo "  (not connected yet)"
    done
}

# Main execution
print_banner

case "${1:-start}" in
    start)
        check_requirements
        cleanup
        start_ryu_controller
        start_dashboard
        start_mininet
        show_status
        ;;
    stop)
        cleanup
        echo -e "${GREEN}[+] All services stopped${NC}"
        ;;
    status)
        show_status
        ;;
    flows)
        show_flows
        ;;
    *)
        echo "Usage: $0 {start|stop|status|flows}"
        exit 1
        ;;
esac
