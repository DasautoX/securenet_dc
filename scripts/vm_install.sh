#!/bin/bash
# SecureNet DC - Full SDN VM Auto-Installer
# Usage: curl -sSL <raw_url> | sudo bash
# Or: wget -qO- <raw_url> | sudo bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}"
echo "========================================================"
echo "  SecureNet DC - Full SDN Auto-Installer"
echo "  This will install OVS + Ryu + Mininet + Dashboard"
echo "========================================================"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Please run as root: sudo bash $0${NC}"
    exit 1
fi

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    echo -e "${RED}[!] Cannot detect OS${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Detected: $OS $VERSION${NC}"

# Check supported OS
if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
    echo -e "${RED}[!] Only Ubuntu/Debian supported${NC}"
    exit 1
fi

# Get the actual user (not root)
ACTUAL_USER=${SUDO_USER:-$USER}
ACTUAL_HOME=$(eval echo ~$ACTUAL_USER)

echo -e "${YELLOW}[*] Installing for user: $ACTUAL_USER${NC}"
echo -e "${YELLOW}[*] Home directory: $ACTUAL_HOME${NC}"

# Update system
echo -e "${YELLOW}[1/7] Updating system packages...${NC}"
apt update && apt upgrade -y

# Install dependencies
echo -e "${YELLOW}[2/7] Installing dependencies...${NC}"
apt install -y \
    python3 python3-pip python3-venv \
    git curl wget \
    openvswitch-switch openvswitch-common \
    mininet \
    iperf iperf3 hping3 nmap \
    net-tools iproute2 \
    tcpdump wireshark-common

# Start and enable OVS
echo -e "${YELLOW}[3/7] Configuring Open vSwitch...${NC}"
systemctl enable openvswitch-switch
systemctl start openvswitch-switch
sleep 2

# Verify OVS
if ovs-vsctl show > /dev/null 2>&1; then
    echo -e "${GREEN}[+] OVS is running${NC}"
    ovs-vsctl --version | head -1
else
    echo -e "${RED}[!] OVS failed to start${NC}"
    exit 1
fi

# Clone or update SecureNet DC
echo -e "${YELLOW}[4/7] Setting up SecureNet DC...${NC}"
INSTALL_DIR="$ACTUAL_HOME/securenet_dc"

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[*] Updating existing installation...${NC}"
    cd "$INSTALL_DIR"
    sudo -u $ACTUAL_USER git pull || true
else
    echo -e "${YELLOW}[*] Cloning SecureNet DC...${NC}"
    sudo -u $ACTUAL_USER git clone https://github.com/DasautoX/securenet_dc.git "$INSTALL_DIR" || {
        echo -e "${YELLOW}[*] Git clone failed, creating directory...${NC}"
        sudo -u $ACTUAL_USER mkdir -p "$INSTALL_DIR"
    }
fi

cd "$INSTALL_DIR"

# Create Python virtual environment
echo -e "${YELLOW}[5/7] Setting up Python environment...${NC}"
sudo -u $ACTUAL_USER python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install \
    flask \
    flask-cors \
    flask-socketio \
    ryu \
    eventlet \
    requests \
    webob \
    routes

# Fix eventlet compatibility if needed
pip install eventlet==0.33.3 dnspython==2.3.0 2>/dev/null || true

# Make scripts executable
echo -e "${YELLOW}[6/7] Configuring scripts...${NC}"
chmod +x scripts/*.sh scripts/*.py 2>/dev/null || true

# Test Mininet with OVS
echo -e "${YELLOW}[7/7] Testing Mininet with OVS...${NC}"
mn -c 2>/dev/null || true
timeout 30 mn --test pingall --switch ovsk --topo single,3 || {
    echo -e "${YELLOW}[!] Mininet test had issues, but continuing...${NC}"
}

# Create convenient aliases
echo -e "${YELLOW}[*] Creating convenience aliases...${NC}"
cat >> "$ACTUAL_HOME/.bashrc" << 'EOF'

# SecureNet DC aliases
alias securenet-start='cd ~/securenet_dc && sudo ./scripts/start_full_sdn.sh'
alias securenet-stop='cd ~/securenet_dc && sudo ./scripts/stop_full_sdn.sh'
alias securenet-status='cd ~/securenet_dc && sudo ./scripts/start_full_sdn.sh status'
alias securenet-attack='cd ~/securenet_dc && source venv/bin/activate && sudo python3 scripts/attack_simulator.py'
EOF

# Print success message
echo ""
echo -e "${GREEN}========================================================"
echo "  Installation Complete!"
echo "========================================================${NC}"
echo ""
echo -e "${BLUE}SecureNet DC installed to: $INSTALL_DIR${NC}"
echo ""
echo -e "${GREEN}Quick Start:${NC}"
echo "  cd ~/securenet_dc"
echo "  sudo ./scripts/start_full_sdn.sh"
echo ""
echo -e "${GREEN}Or use aliases (after reloading shell):${NC}"
echo "  securenet-start   - Start all services"
echo "  securenet-stop    - Stop all services"
echo "  securenet-attack  - Run attack simulator"
echo ""
echo -e "${GREEN}Access Dashboard:${NC}"
IP=$(hostname -I | awk '{print $1}')
echo "  http://$IP:5000"
echo ""
echo -e "${GREEN}Manual Start (3 terminals):${NC}"
echo "  Terminal 1: ryu-manager controller/securenet_controller.py --observe-links"
echo "  Terminal 2: python3 dashboard/app.py"
echo "  Terminal 3: sudo mn --controller=remote --switch ovsk,protocols=OpenFlow13 --topo tree,2"
echo ""
echo -e "${YELLOW}Reload your shell to use aliases:${NC}"
echo "  source ~/.bashrc"
echo ""
