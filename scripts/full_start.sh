#!/bin/bash
# SecureNet DC - Full Stack Startup Script
# Ensures proper startup sequence

echo "==========================================="
echo "  SecureNet DC - Full Stack Startup"
echo "==========================================="

# Step 1: Clean up
echo ""
echo "[1/5] Cleaning up old processes..."
sudo pkill -9 -f ryu-manager 2>/dev/null
sudo pkill -9 -f "python.*app.py" 2>/dev/null
sudo mn -c 2>/dev/null
sleep 1

# Step 2: Start Open vSwitch
echo "[2/5] Starting Open vSwitch..."
sudo service openvswitch-switch restart
sleep 2

# Step 3: Start Ryu Controller
echo "[3/5] Starting Ryu Controller..."
cd ~/securenet_dc
source venv/bin/activate
ryu-manager controller/securenet_controller.py --observe-links --wsapi-host 0.0.0.0 2>&1 &
CONTROLLER_PID=$!
echo "    Controller PID: $CONTROLLER_PID"

# Wait for controller to be ready (check port 6653)
echo "    Waiting for controller to be ready..."
for i in {1..15}; do
    if ss -tln | grep -q ':6653'; then
        echo "    Controller ready on port 6653!"
        break
    fi
    sleep 1
done

# Additional wait for WSAPI
sleep 2

# Verify controller is running
if ! kill -0 $CONTROLLER_PID 2>/dev/null; then
    echo "ERROR: Controller failed to start!"
    exit 1
fi

# Step 4: Start Mininet
echo "[4/5] Starting Mininet..."
sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch ovsk,protocols=OpenFlow13 --topo tree,2 2>&1 &
MININET_PID=$!

# Wait for mininet to initialize
sleep 5

# Step 5: Start Dashboard
echo "[5/5] Starting Dashboard..."
python dashboard/app.py 2>&1 &
DASHBOARD_PID=$!

echo ""
echo "==========================================="
echo "  All services started!"
echo "==========================================="
echo ""
echo "  Controller PID: $CONTROLLER_PID"
echo "  Dashboard PID:  $DASHBOARD_PID"
echo ""
echo "  Dashboard URL: http://localhost:5000"
echo "  Controller API: http://localhost:8080/securenet/status"
echo ""
echo "Press Ctrl+C to stop all services..."

# Keep running and wait for signals
trap "sudo pkill -9 -f ryu; sudo pkill -9 -f 'python.*app.py'; sudo mn -c; exit" SIGINT SIGTERM
wait
