#!/usr/bin/env python3
"""
SecureNet DC - Full Project Runner
CPEG 460 Bonus Project

Starts the complete SecureNet DC environment:
1. SDN Controller (Ryu)
2. Network Topology (Mininet)
3. Web Dashboard (Flask)
"""

import os
import sys
import time
import subprocess
import threading
import signal

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from mininet.log import setLogLevel, info

# Global process handles
processes = []


def signal_handler(sig, frame):
    """Handle Ctrl+C to cleanup processes."""
    print("\n\n*** Shutting down SecureNet DC ***")
    for name, proc in processes:
        print(f"Stopping {name}...")
        proc.terminate()
        proc.wait(timeout=5)
    print("Shutdown complete.")
    sys.exit(0)


def start_controller():
    """Start the Ryu SDN controller."""
    controller_path = os.path.join(PROJECT_ROOT, 'controller', 'securenet_controller.py')

    print("\n*** Starting SDN Controller ***")
    print(f"Controller: {controller_path}")

    # Try to find ryu-manager, osken-manager, or use python -m
    import shutil
    ryu_manager = shutil.which('ryu-manager') or shutil.which('osken-manager')

    if not ryu_manager:
        # Check venv for ryu-manager or osken-manager
        venv_ryu = os.path.join(PROJECT_ROOT, 'venv', 'bin', 'ryu-manager')
        venv_osken = os.path.join(PROJECT_ROOT, 'venv', 'bin', 'osken-manager')
        if os.path.exists(venv_ryu):
            ryu_manager = venv_ryu
        elif os.path.exists(venv_osken):
            ryu_manager = venv_osken

    if ryu_manager:
        cmd = [ryu_manager, controller_path]
    else:
        # Use python -m to run os_ken or ryu manager
        python_path = sys.executable
        # Try os_ken first (Python 3.12+), then ryu
        try:
            import os_ken
            cmd = [python_path, '-m', 'os_ken.cmd.manager', controller_path]
        except ImportError:
            try:
                import ryu
                cmd = [python_path, '-m', 'ryu.cmd.manager', controller_path]
            except ImportError:
                print("ERROR: Neither os-ken nor ryu is installed.")
                print("Install with: pip install os-ken (Python 3.12+) or pip install ryu")
                sys.exit(1)

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=PROJECT_ROOT
    )
    processes.append(('Controller', proc))

    # Wait for controller to start
    time.sleep(3)
    return proc


def start_dashboard():
    """Start the web dashboard."""
    dashboard_path = os.path.join(PROJECT_ROOT, 'dashboard', 'app.py')

    print("\n*** Starting Web Dashboard ***")
    print(f"Dashboard: http://localhost:5000")

    # Try venv python first, then system python
    venv_python = os.path.join(PROJECT_ROOT, 'venv', 'bin', 'python')
    python_cmd = venv_python if os.path.exists(venv_python) else 'python3'

    proc = subprocess.Popen(
        [python_cmd, dashboard_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        cwd=PROJECT_ROOT
    )
    processes.append(('Dashboard', proc))

    # Wait for dashboard to start
    time.sleep(2)
    return proc


def start_network():
    """Start the Mininet network."""
    from topology.fat_tree_datacenter import run_with_controller

    print("\n*** Starting Network Topology ***")

    run_with_controller(
        controller_ip='127.0.0.1',
        controller_port=6653,
        enable_qos=True,
        start_services=True
    )


def main():
    """Main entry point."""
    print("=" * 60)
    print("  SecureNet DC - Full Project Runner")
    print("  CPEG 460 Bonus Project")
    print("=" * 60)

    # Check root
    if os.geteuid() != 0:
        print("\nError: This script must be run as root (sudo)")
        print("Usage: sudo python3 run_project.py")
        sys.exit(1)

    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    setLogLevel('info')

    # Start components
    print("\n*** Starting SecureNet DC Components ***\n")

    # 1. Start controller
    start_controller()

    # 2. Start dashboard
    start_dashboard()

    # 3. Start network (this blocks until exit)
    print("\n" + "=" * 60)
    print("  All components started!")
    print("  - Controller: Running on port 6653")
    print("  - Dashboard: http://localhost:5000")
    print("  - REST API: http://localhost:8080/securenet/status")
    print("=" * 60)
    print("\n*** Starting Mininet CLI ***")
    print("*** Type 'exit' to stop the network ***\n")

    start_network()

    # Cleanup
    signal_handler(None, None)


if __name__ == '__main__':
    main()
