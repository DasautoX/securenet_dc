#!/bin/bash
# SecureNet DC - Setup Script for WSL2/Ubuntu
# CPEG 460 Bonus Project

echo "=============================================="
echo "  SecureNet DC - Installation Script"
echo "  CPEG 460 Bonus Project"
echo "=============================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Please run as root (use sudo)${NC}"
    exit 1
fi

echo -e "\n${YELLOW}[1/6] Updating system packages...${NC}"
apt-get update -y

echo -e "\n${YELLOW}[2/6] Installing Mininet...${NC}"
apt-get install -y mininet

echo -e "\n${YELLOW}[3/6] Installing Open vSwitch...${NC}"
apt-get install -y openvswitch-switch openvswitch-common

echo -e "\n${YELLOW}[4/6] Installing network tools...${NC}"
apt-get install -y iperf iperf3 hping3 tcpdump wireshark tshark net-tools

echo -e "\n${YELLOW}[5/6] Installing Python dependencies...${NC}"
apt-get install -y python3-pip python3-dev

# Install Python packages
pip3 install -r requirements.txt

echo -e "\n${YELLOW}[6/6] Configuring Open vSwitch...${NC}"
# Start OVS service
service openvswitch-switch start

# Create OVS database if it doesn't exist
if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Start OVS database server
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
    --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
    --pidfile --detach 2>/dev/null || true

# Initialize OVS
ovs-vsctl --no-wait init 2>/dev/null || true

echo -e "\n${GREEN}=============================================="
echo "  System Dependencies Installed!"
echo "=============================================="
echo -e "${NC}"
echo ""
echo "Next step: Run the WSL setup script to configure Python environment:"
echo ""
echo "  ./scripts/setup_wsl.sh"
echo ""
echo "This will:"
echo "  - Create Python virtual environment"
echo "  - Install Ryu SDN Framework"
echo "  - Install Flask dependencies"
echo "  - Apply eventlet compatibility patch"
echo ""
echo "After setup, start the project with:"
echo ""
echo "  ./scripts/start_all.sh"
echo ""
echo "Then in another terminal:"
echo ""
echo "  sudo mn --controller=remote,ip=127.0.0.1,port=6653 --topo=tree,2"
echo ""
