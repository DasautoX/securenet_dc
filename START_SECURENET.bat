@echo off
REM SecureNet DC v2.0 - Easy Windows Launcher (Integrated Mode)
REM Double-click this file to start the project

echo.
echo ====================================================================
echo   SecureNet DC v2.0 - Advanced SDN Monitoring with DDoS Defense
echo   Using Linux Bridges - Compatible with WSL2
echo ====================================================================
echo.

REM Check if Windows Terminal is available
where wt >nul 2>nul
if %ERRORLEVEL% neq 0 (
    echo [WARNING] Windows Terminal not found.
    echo Opening with regular WSL...
    echo.
    echo Run this command in WSL:
    echo   cd ~/securenet_dc
    echo   sudo python3 scripts/run_demo.py
    echo.
    wsl
    exit /b
)

REM Sync files to WSL first
echo [1/3] Syncing files to WSL...
wsl -e bash -c "mkdir -p ~/securenet_dc && cp -r /mnt/c/Users/ayman/CPEG460/project/securenet_dc/* ~/securenet_dc/ 2>/dev/null; chmod +x ~/securenet_dc/scripts/*.sh ~/securenet_dc/scripts/*.py 2>/dev/null"
echo       Done.
echo.

REM Clean up old processes
echo [2/3] Cleaning up old processes...
wsl -e bash -c "pkill -9 -f 'network_stats_collector' 2>/dev/null; pkill -9 -f 'python.*app.py' 2>/dev/null; pkill -9 -f 'run_demo' 2>/dev/null; sudo mn -c 2>/dev/null"
timeout /t 2 /nobreak >nul
echo       Done.
echo.

REM Get WSL IP
for /f "tokens=*" %%i in ('wsl -e bash -c "hostname -I 2>/dev/null | awk '{print $1}'"') do set WSL_IP=%%i

echo [3/3] Starting SecureNet DC...
echo.

REM Launch Windows Terminal with tabs (no profile specified for compatibility)
wt -w 0 new-tab --title "SecureNet Demo" wsl -e bash -c "cd ~/securenet_dc && echo 'Starting SecureNet DC Integrated Demo...' && echo '' && sudo python3 scripts/run_demo.py" ; new-tab --title "Stats Collector" wsl -e bash -c "sleep 2 && cd ~/securenet_dc && source venv/bin/activate && echo 'Starting Stats Collector...' && python3 scripts/network_stats_collector.py" ; new-tab --title "Dashboard" wsl -e bash -c "sleep 4 && cd ~/securenet_dc && source venv/bin/activate && echo 'Starting Dashboard...' && python3 dashboard/app.py"

echo.
echo ====================================================================
echo   ACCESS POINTS:
echo   Dashboard:        http://%WSL_IP%:5000
echo   Stats API:        http://%WSL_IP%:8080/securenet/status
echo   Health Check:     http://%WSL_IP%:8080/securenet/health
echo   DDoS Alerts:      http://%WSL_IP%:8080/securenet/ddos/alerts
echo.
echo   From Windows browser, use the WSL IP above.
echo   From WSL, use http://localhost:5000
echo ====================================================================
echo.
echo   Windows Terminal opened with 3 tabs:
echo   Tab 1: Integrated Demo (Mininet + Attack Control)
echo   Tab 2: Stats Collector (port 8080)
echo   Tab 3: Dashboard (port 5000)
echo.
echo ====================================================================
echo   USAGE IN TAB 1 (Integrated Demo):
echo.
echo   The demo runner provides an interactive menu:
echo     1. ICMP Flood Attack
echo     2. SYN Flood Attack
echo     3. UDP Flood Attack
echo     4. Ping of Death
echo     5. Multi-Vector Attack
echo     6. Run Demo Scenario (recommended for presentation)
echo     7. Test Connectivity
echo     8. Show Status
echo     9. Open Mininet CLI
echo     0. Exit
echo.
echo   Or run with arguments:
echo     sudo python3 scripts/run_demo.py --auto      # Auto demo
echo     sudo python3 scripts/run_demo.py --attack demo  # Demo scenario
echo     sudo python3 scripts/run_demo.py --cli      # Mininet CLI
echo ====================================================================
echo.
echo Press any key to close this window...
pause >nul
