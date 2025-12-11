#!/bin/bash
#
# SecureNet DC - Start All Services
# CPEG 460 Project
#
# This script starts the controller, dashboard, and opens Mininet
# Run from ~/securenet_dc directory
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "============================================================"
echo "  SecureNet DC - Starting All Services"
echo "============================================================"
echo ""

# Check if venv exists
if [ ! -f "venv/bin/activate" ]; then
    echo "[ERROR] Virtual environment not found!"
    echo "Run: python3.11 -m venv venv --system-site-packages"
    exit 1
fi

# Activate virtual environment
source venv/bin/activate

# Kill any existing processes
echo "[*] Stopping any existing services..."
pkill -f "ryu-manager" 2>/dev/null || true
pkill -f "dashboard/app.py" 2>/dev/null || true
sleep 1

# Start Controller
echo "[*] Starting Ryu Controller..."
ryu-manager controller/securenet_controller.py \
    --observe-links \
    --wsapi-host 0.0.0.0 \
    --wsapi-port 8080 \
    > /tmp/controller.log 2>&1 &
CONTROLLER_PID=$!
echo "    Controller PID: $CONTROLLER_PID"
sleep 2

# Check if controller started
if ! kill -0 $CONTROLLER_PID 2>/dev/null; then
    echo "[ERROR] Controller failed to start!"
    cat /tmp/controller.log
    exit 1
fi

# Start Dashboard
echo "[*] Starting Dashboard..."
python dashboard/app.py > /tmp/dashboard.log 2>&1 &
DASHBOARD_PID=$!
echo "    Dashboard PID: $DASHBOARD_PID"
sleep 2

# Check if dashboard started
if ! kill -0 $DASHBOARD_PID 2>/dev/null; then
    echo "[ERROR] Dashboard failed to start!"
    cat /tmp/dashboard.log
    exit 1
fi

# Get WSL IP for browser access
WSL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo "============================================================"
echo "  SecureNet DC - Services Running"
echo "============================================================"
echo ""
echo "  Controller: http://localhost:8080/securenet/"
echo "  Dashboard:  http://localhost:5000"
echo ""
echo "  From Windows browser: http://$WSL_IP:5000"
echo ""
echo "============================================================"
echo ""
echo "Now run Mininet in another terminal:"
echo ""
echo "  sudo mn --controller=remote,ip=127.0.0.1,port=6653 --topo=tree,2"
echo ""
echo "Or use the Fat-Tree topology:"
echo ""
echo "  sudo mn --custom topology/datacenter_topo.py --topo=fattree \\"
echo "          --controller=remote,ip=127.0.0.1,port=6653"
echo ""
echo "Press Ctrl+C to stop all services..."
echo ""

# Wait and cleanup
cleanup() {
    echo ""
    echo "[*] Stopping services..."
    kill $CONTROLLER_PID 2>/dev/null || true
    kill $DASHBOARD_PID 2>/dev/null || true
    echo "[*] Done."
    exit 0
}

trap cleanup SIGINT SIGTERM

# Keep script running
wait
