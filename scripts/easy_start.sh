#!/bin/bash
# SecureNet DC - Easy One-Click Start
# Just run: ./scripts/easy_start.sh

echo "=============================================="
echo "  SecureNet DC - Starting Dashboard"
echo "=============================================="

# Go to project directory
cd ~/securenet_dc

# Kill any existing processes
echo "[1/3] Cleaning up old processes..."
pkill -f "python.*app.py" 2>/dev/null
pkill -f "ryu-manager" 2>/dev/null
sudo mn -c 2>/dev/null
sleep 1

# Activate virtual environment
echo "[2/3] Activating environment..."
source venv/bin/activate

# Start dashboard
echo "[3/3] Starting dashboard..."
echo ""
echo "=============================================="
echo "  Dashboard running at:"
echo "  http://localhost:5000"
echo ""
echo "  Or from Windows browser:"
WSL_IP=$(hostname -I | awk '{print $1}')
echo "  http://$WSL_IP:5000"
echo "=============================================="
echo ""
echo "Press Ctrl+C to stop"
echo ""

python dashboard/app.py
