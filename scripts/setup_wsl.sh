#!/bin/bash
#
# SecureNet DC - WSL Setup Script
# CPEG 460 Project
#
# This script sets up the complete environment in WSL
#

set -e

echo "============================================================"
echo "  SecureNet DC - WSL Environment Setup"
echo "============================================================"
echo ""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"
echo "[*] Project directory: $PROJECT_DIR"
echo ""

# Check Python version
echo "[*] Checking Python version..."
if command -v python3.11 &> /dev/null; then
    PYTHON=python3.11
    echo "    Found Python 3.11"
elif command -v python3 &> /dev/null; then
    PYTHON=python3
    PY_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
    echo "    Found Python $PY_VERSION"
else
    echo "[ERROR] Python not found!"
    exit 1
fi

# Create virtual environment
echo ""
echo "[*] Creating virtual environment..."
if [ -d "venv" ]; then
    echo "    Removing old venv..."
    rm -rf venv
fi
$PYTHON -m venv venv --system-site-packages
echo "    Created venv"

# Activate and install dependencies
echo ""
echo "[*] Installing dependencies..."
source venv/bin/activate

pip install --quiet setuptools==57.5.0
echo "    Installed setuptools"

pip install --quiet --no-build-isolation ryu
echo "    Installed Ryu SDN Framework"

pip install --quiet flask flask-socketio flask-cors requests
echo "    Installed Flask and dashboard dependencies"

# Apply eventlet patch
echo ""
echo "[*] Applying eventlet compatibility patch..."
WSGI_FILE="venv/lib/$PYTHON/site-packages/ryu/app/wsgi.py"
if [ -f "$WSGI_FILE" ]; then
    sed -i "s/from eventlet.wsgi import ALREADY_HANDLED/ALREADY_HANDLED = b''/" "$WSGI_FILE"
    echo "    Patch applied"
else
    # Try alternate path
    WSGI_FILE=$(find venv -name "wsgi.py" -path "*/ryu/app/*" 2>/dev/null | head -1)
    if [ -n "$WSGI_FILE" ]; then
        sed -i "s/from eventlet.wsgi import ALREADY_HANDLED/ALREADY_HANDLED = b''/" "$WSGI_FILE"
        echo "    Patch applied to $WSGI_FILE"
    else
        echo "    [WARNING] Could not find wsgi.py to patch"
    fi
fi

# Make scripts executable
echo ""
echo "[*] Making scripts executable..."
chmod +x scripts/*.sh 2>/dev/null || true
echo "    Done"

# Verify installation
echo ""
echo "[*] Verifying installation..."
source venv/bin/activate
if python -c "import ryu; print(f'    Ryu version: {ryu.__version__}')" 2>/dev/null; then
    echo "    Ryu: OK"
else
    echo "    [WARNING] Ryu import failed"
fi

if python -c "import flask; print(f'    Flask version: {flask.__version__}')" 2>/dev/null; then
    echo "    Flask: OK"
else
    echo "    [WARNING] Flask import failed"
fi

echo ""
echo "============================================================"
echo "  Setup Complete!"
echo "============================================================"
echo ""
echo "To start the project:"
echo ""
echo "  cd $PROJECT_DIR"
echo "  ./scripts/start_all.sh"
echo ""
echo "Or manually:"
echo ""
echo "  Terminal 1: source venv/bin/activate && ryu-manager controller/securenet_controller.py"
echo "  Terminal 2: source venv/bin/activate && python dashboard/app.py"
echo "  Terminal 3: sudo mn --controller=remote,ip=127.0.0.1,port=6653 --topo=tree,2"
echo ""
echo "Dashboard: http://localhost:5000"
echo ""
