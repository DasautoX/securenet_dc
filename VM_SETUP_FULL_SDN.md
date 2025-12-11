# SecureNet DC - Full SDN Version (VM Setup)

This guide sets up the **complete SDN experience** with Open vSwitch + Ryu Controller.

## Why a VM?

WSL2 has a limitation: Open vSwitch (OVS) kernel modules don't work properly,
preventing OpenFlow communication between switches and the SDN controller.

A proper Linux VM provides:
- Full OVS support with kernel datapath
- OpenFlow 1.3 protocol support
- Real SDN flow programming
- QoS queue management
- Dynamic firewall rules

## Quick Comparison

| Feature | WSL2 Version | VM Version |
|---------|--------------|------------|
| Real traffic | Yes | Yes |
| Attack detection | Yes | Yes |
| OpenFlow | No | Yes |
| Flow rules | No | Yes |
| QoS queues | No | Yes |
| Dynamic blocking | Simulated | Real |
| Setup complexity | Easy | Medium |

## VM Setup Options

### Option A: VirtualBox (Recommended for Windows)

1. Download VirtualBox: https://www.virtualbox.org/
2. Download Ubuntu 22.04 Server ISO: https://ubuntu.com/download/server
3. Create VM:
   - RAM: 4GB minimum
   - CPU: 2 cores
   - Disk: 20GB
   - Network: NAT + Host-Only Adapter

### Option B: VMware Workstation Player (Free)

1. Download: https://www.vmware.com/products/workstation-player.html
2. Same Ubuntu ISO
3. Similar VM specs

## Installation Script

After Ubuntu is installed, run this script:

```bash
#!/bin/bash
# SecureNet DC - Full SDN Installation Script

echo "=========================================="
echo "SecureNet DC - Full SDN Version Installer"
echo "=========================================="

# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y \
    python3 python3-pip python3-venv \
    git curl wget \
    openvswitch-switch openvswitch-common \
    mininet \
    iperf iperf3 hping3 nmap \
    net-tools iproute2

# Start OVS
sudo systemctl enable openvswitch-switch
sudo systemctl start openvswitch-switch

# Verify OVS is working
sudo ovs-vsctl show
echo "OVS Version: $(sudo ovs-vsctl --version | head -1)"

# Clone or copy SecureNet DC
cd ~
if [ ! -d "securenet_dc" ]; then
    mkdir securenet_dc
    echo "Copy your securenet_dc files here"
fi

cd securenet_dc

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python dependencies
pip install --upgrade pip
pip install flask flask-cors flask-socketio ryu eventlet requests

# Test Mininet with OVS
echo ""
echo "Testing Mininet with OVS..."
sudo mn --test pingall --switch ovsk --topo tree,2

echo ""
echo "=========================================="
echo "Installation Complete!"
echo "=========================================="
echo ""
echo "To start SecureNet DC Full SDN:"
echo "  cd ~/securenet_dc"
echo "  ./scripts/start_full_sdn.sh"
```

## Directory Structure

```
securenet_dc/
├── controller/
│   └── securenet_controller.py    # Ryu SDN Controller
├── dashboard/
│   └── app.py                     # Web Dashboard
├── scripts/
│   ├── start_full_sdn.sh          # Full SDN startup
│   └── attack_simulator.py        # Attack tools
└── VM_SETUP_FULL_SDN.md           # This file
```

## Running the Full SDN Version

### Terminal 1: Start Ryu Controller
```bash
cd ~/securenet_dc
source venv/bin/activate
ryu-manager controller/securenet_controller.py --observe-links --wsapi-host 0.0.0.0
```

### Terminal 2: Start Dashboard
```bash
cd ~/securenet_dc
source venv/bin/activate
python dashboard/app.py
```

### Terminal 3: Start Mininet with OVS
```bash
sudo mn --controller=remote,ip=127.0.0.1,port=6653 \
        --switch ovsk,protocols=OpenFlow13 \
        --topo tree,2
```

### Terminal 4: Run Attack
```bash
# In Mininet CLI:
h4 ping -f 10.0.0.1
```

## Full SDN Features

### 1. Flow Rules
The Ryu controller can install OpenFlow rules:
```python
# Block traffic from attacker
match = parser.OFPMatch(eth_src=attacker_mac)
actions = []  # Drop
self.add_flow(datapath, priority=100, match=match, actions=actions)
```

### 2. QoS Queues
```bash
# Create QoS queues on OVS
sudo ovs-vsctl set port s1-eth1 qos=@newqos -- \
    --id=@newqos create qos type=linux-htb queues=0=@q0,1=@q1 -- \
    --id=@q0 create queue other-config:min-rate=1000000 -- \
    --id=@q1 create queue other-config:min-rate=5000000
```

### 3. Real Traffic Blocking
When an attack is detected, the controller installs a flow rule that
actually drops packets at the switch level - not just monitoring.

## Access from Windows Host

1. Get VM IP: `ip addr show`
2. In Windows browser: `http://<VM_IP>:5000`

## Troubleshooting

### OVS not starting
```bash
sudo systemctl status openvswitch-switch
sudo journalctl -u openvswitch-switch
```

### Controller not connecting
```bash
# Check if controller is listening
netstat -tlnp | grep 6653

# Check OVS controller setting
sudo ovs-vsctl show
```

### Mininet cleanup
```bash
sudo mn -c
```
