#!/bin/bash
#
# SecureNet DC - Attack Simulation Script
# CPEG 460 Project
#
# Run this inside Mininet or as standalone
#

echo "============================================================"
echo "  SecureNet DC - Attack Simulation"
echo "============================================================"
echo ""
echo "This script provides attack commands for Mininet."
echo ""
echo "USAGE (inside Mininet):"
echo ""
echo "  # ICMP Flood (Ping Flood)"
echo "  mininet> h13 ping -f -c 1000 10.0.0.1"
echo ""
echo "  # SYN Flood (requires hping3)"
echo "  mininet> h13 hping3 -S --flood -p 80 10.0.0.1"
echo ""
echo "  # UDP Flood (requires hping3)"
echo "  mininet> h13 hping3 --udp --flood -p 53 10.0.0.1"
echo ""
echo "  # Slow attack for visibility"
echo "  mininet> h13 ping -i 0.01 10.0.0.1"
echo ""
echo "  # Test normal traffic"
echo "  mininet> pingall"
echo "  mininet> iperf h1 h2"
echo ""
echo "============================================================"
echo ""

# Check if we're being sourced or run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "Run these commands inside Mininet CLI."
    echo ""
    echo "To start Mininet:"
    echo "  sudo mn --controller=remote,ip=127.0.0.1,port=6653 --topo=tree,2"
    echo ""
fi
