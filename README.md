# SecureNet DC

## A Software-Defined Data Center with Intelligent Traffic Engineering, Real-Time DDoS Defense, and Performance Analytics

**CPEG 460 - Computer Networks | Bonus Project | Fall 2025**

---

## Overview

SecureNet DC is a comprehensive network emulation project that demonstrates advanced Software-Defined Networking (SDN) concepts using Mininet. This project showcases enterprise-grade data center networking with security, QoS, and monitoring capabilities.

### Key Features

- **Fat-Tree Data Center Topology**: Industry-standard k=4 fat-tree with 20 switches and 16 hosts
- **Intelligent SDN Controller**: Custom Ryu controller with 6 integrated modules
- **DDoS Detection & Mitigation**: Real-time attack detection with automatic blocking
- **QoS Traffic Engineering**: 4-tier priority system with bandwidth guarantees
- **Load Balancing**: VIP-based distribution across server pools
- **Real-Time Dashboard**: D3.js visualization with WebSocket updates
- **Attack Simulation Toolkit**: Educational tools for security testing
- **Performance Analysis**: Automated benchmarking and graph generation

---

## Architecture

```
                     +------------------------------------------+
                     |        SDN CONTROLLER (Ryu)              |
                     |  +----------+ +----------+ +----------+  |
                     |  |  DDoS    | |   QoS    | |   Load   |  |
                     |  | Detector | | Manager  | | Balancer |  |
                     |  +----------+ +----------+ +----------+  |
                     |  +----------+ +----------+ +----------+  |
                     |  | Firewall | |  Stats   | |   REST   |  |
                     |  |  Rules   | |Collector | |   API    |  |
                     |  +----------+ +----------+ +----------+  |
                     +---------------------|--------------------+
                                           | OpenFlow 1.3
                     +------------------------------------------+
                     |           FAT-TREE DATA CENTER           |
                     |    [Core]       c1    c2    c3    c4     |
                     |    [Agg]     a1  a2  a3  a4  a5  a6  a7  a8  |
                     |    [Edge]    e1  e2  e3  e4  e5  e6  e7  e8  |
                     |    [Hosts]        h1 - h16               |
                     +------------------------------------------+
```

---

## Two Running Modes

SecureNet DC supports two deployment modes:

| Feature | WSL2 Mode (Quick Demo) | VM Mode (Full SDN) |
|---------|------------------------|-------------------|
| Real traffic | Yes | Yes |
| Attack detection | Yes | Yes |
| OpenFlow flows | No | Yes |
| Flow-based blocking | No | Yes |
| QoS queues | No | Yes |
| Dynamic blocking | Interface-based | OpenFlow rules |
| Setup complexity | Easy | Medium |
| Performance | Best for demos | Production-ready |

---

## Mode 1: WSL2 Quick Demo (Recommended for Windows)

This mode uses Linux bridges for WSL2 compatibility. Perfect for demonstrations with real traffic and attack detection.

### Prerequisites

- **Windows 10/11 with WSL2**
- **Ubuntu 20.04+** distribution in WSL2
- **Python 3.11** (recommended)
- Root/sudo access

### Quick Start (One-Click)

**Just double-click `START_SECURENET.bat` from Windows!**

This automatically:
1. Syncs files to WSL2
2. Starts the Stats Collector (DDoS detection)
3. Starts the Web Dashboard
4. Starts Mininet with Linux bridges

### Manual Installation

```bash
# 1. Open WSL Ubuntu terminal
wsl

# 2. Navigate to project directory
cd ~/securenet_dc

# 3. Run automated setup script
chmod +x scripts/setup_wsl.sh
./scripts/setup_wsl.sh
```

### Manual Running (3 terminals)

```bash
# TERMINAL 1: Stats Collector (attack detection)
cd ~/securenet_dc
source venv/bin/activate
python3 scripts/network_stats_collector.py

# TERMINAL 2: Dashboard
cd ~/securenet_dc
source venv/bin/activate
python3 dashboard/app.py

# TERMINAL 3: Mininet with Linux bridges
sudo mn --switch lxbr --topo tree,2
```

### Running Attack Demo

In the Mininet CLI:
```bash
# ICMP Flood attack from h4 to h1
mininet> h4 ping -f -c 5000 10.0.0.1

# Watch the dashboard - attack will be detected!
```

### Accessing the Dashboard

- **From WSL**: http://localhost:5000
- **From Windows Browser**: http://<WSL_IP>:5000

Get your WSL IP:
```bash
hostname -I | awk '{print $1}'
```

---

## Mode 2: Full SDN with VM (Complete Experience)

For the complete SDN experience with OpenFlow, flow rules, and real packet blocking, use a proper Linux VM.

**Why a VM?** WSL2 lacks OVS kernel modules, preventing OpenFlow communication between switches and the Ryu controller.

### VM Setup

See [VM_SETUP_FULL_SDN.md](VM_SETUP_FULL_SDN.md) for complete instructions.

Quick summary:
1. Create Ubuntu 22.04 VM (VirtualBox/VMware)
2. Run the installation script from VM_SETUP_FULL_SDN.md
3. Start services with `sudo ./scripts/start_full_sdn.sh`

### Running Full SDN Mode (in VM)

```bash
# One command to start everything:
sudo ./scripts/start_full_sdn.sh

# Or manually in 3 terminals:

# TERMINAL 1: Ryu Controller
ryu-manager controller/securenet_controller.py --observe-links --wsapi-host 0.0.0.0

# TERMINAL 2: Dashboard
python3 dashboard/app.py

# TERMINAL 3: Mininet with OVS
sudo mn --controller=remote,ip=127.0.0.1,port=6653 \
        --switch ovsk,protocols=OpenFlow13 \
        --topo tree,depth=2,fanout=2
```

---

## Project Structure

```
securenet_dc/
├── START_SECURENET.bat     # One-click Windows launcher (WSL2 mode)
├── VM_SETUP_FULL_SDN.md    # VM setup guide for full SDN mode
├── topology/               # Network topology definitions
│   ├── fat_tree_datacenter.py
│   ├── datacenter_topo.py  # Mininet custom topology
│   └── network_config.py
├── controller/             # SDN controller (Ryu) - VM mode
│   ├── securenet_controller.py
│   ├── ddos_detector.py
│   ├── qos_manager.py
│   ├── load_balancer.py
│   ├── firewall.py
│   └── stats_collector.py
├── attacks/                # Attack simulation tools
│   ├── attack_toolkit.py
│   ├── syn_flood.py
│   ├── icmp_flood.py
│   ├── udp_flood.py
│   └── slowloris.py
├── dashboard/              # Web monitoring interface
│   ├── app.py
│   ├── templates/
│   └── static/
├── simulator/              # Windows native attempt (experimental)
│   ├── windows_sim.py
│   └── windows_controller.py
├── analysis/               # Performance tools
│   ├── performance_analyzer.py
│   └── graph_generator.py
├── scripts/                # Runner scripts
│   ├── setup_wsl.sh        # WSL environment setup
│   ├── start_full_sdn.sh   # Full SDN startup (VM mode)
│   ├── stop_full_sdn.sh    # Stop Full SDN services
│   ├── network_stats_collector.py  # Stats + DDoS detection (WSL2 mode)
│   ├── attack_simulator.py # Attack generator
│   ├── run_demo.py         # Integrated demo runner
│   ├── start_all.sh        # Start all services
│   └── run_attacks.sh      # Attack reference
└── docs/                   # Documentation
    ├── project_report.tex
    ├── lab_document.tex
    └── solution_report.tex
```

---

## Host Configuration

| Host | IP Address | Role |
|------|------------|------|
| h1-h4 | 10.0.1.1-4 | Web Server Pool |
| h5-h6 | 10.0.2.1-2 | Database Servers |
| h7-h12 | 10.0.3.1-6 | Client Hosts |
| h13 | 10.0.4.1 | Attacker Host |
| h14 | 10.0.4.2 | IDS Monitor |
| h15-h16 | 10.0.5.1-2 | Video Streaming |

---

## Features in Detail

### 1. DDoS Detection

The controller monitors traffic patterns and detects:
- **SYN Flood**: TCP SYN without ACK > 100 pps
- **ICMP Flood**: Ping packets > 50 pps
- **UDP Flood**: UDP traffic > 200 pps
- **Slowloris**: Incomplete HTTP connections

When an attack is detected, the attacker's IP is automatically blocked for 120 seconds.

### 2. QoS Traffic Engineering

Traffic is classified into 4 priority levels:
- **Critical (50%)**: SSH, DNS
- **Real-time (30%)**: Video streaming
- **Interactive (15%)**: HTTP/HTTPS
- **Bulk (5%)**: FTP, general transfers

### 3. Load Balancing

Requests to the Virtual IP (10.0.0.100) are distributed across the web server pool using:
- Round-robin (default)
- Weighted round-robin
- Least connections

### 4. Real-Time Dashboard

Access at `http://localhost:5000` to see:
- Live network topology
- Bandwidth graphs
- Attack alerts
- Blocked hosts
- QoS statistics

---

## Attack Simulation (In Mininet CLI)

```bash
# ICMP Flood (simple, no extra tools)
mininet> h1 ping -f -c 1000 10.0.0.2

# SYN Flood (requires hping3)
mininet> h1 hping3 -S --flood -p 80 10.0.0.2

# UDP Flood
mininet> h1 hping3 --udp --flood -p 53 10.0.0.2

# Normal traffic test
mininet> pingall
```

---

## Development Journey

During development, we explored running the project natively on Windows using pure Python OpenFlow simulators (`simulator/` folder). However, this approach had limitations:
- Windows lacks Linux network namespaces
- No Open vSwitch kernel modules on Windows
- Couldn't provide real packet forwarding

The final solution uses **WSL2**, providing the best of both worlds:
- Full Linux kernel functionality
- Native Mininet support
- Dashboard accessible from Windows browser

---

## Demonstration

For the professor demo:

1. **Topology Creation**: 20 switches, 16 hosts connected
2. **Connectivity Test**: `pingall` succeeds
3. **Load Balancing**: Traffic distributed across servers
4. **DDoS Defense**: Attack detected and blocked automatically
5. **QoS Enforcement**: Priority traffic gets bandwidth guarantees
6. **Live Dashboard**: Real-time visualization
7. **Wireshark Analysis**: OpenFlow and attack packet captures
8. **Performance Graphs**: Throughput and latency comparisons

---

## Author

**CPEG 460 - Computer Networks**
**Fall 2025**
**Dr. Mohammad Shaqfeh**

---

## License

This project is for educational purposes only. The attack simulation tools should only be used in controlled environments for learning.
