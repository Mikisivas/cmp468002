@echo off
title IfeSentinel - Demo menu
cd /d "%~dp0"
set PY=python
%PY% --version >nul 2>&1 || set PY=py
%PY% --version >nul 2>&1 || goto nopython
if not exist venv\Scripts\activate.bat (
  echo  Setup has not been done yet. Double-click 1_SETUP.bat first.
  pause
  exit /b 1
)
call venv\Scripts\activate.bat
:menu
echo.
echo ===================== IfeSentinel demo menu =====================
echo  1. Ransomware on REGISTRY-SRV (canary trip)
echo  2. Quiet ransomware on BURSARY-PC1
echo  3. Restore REGISTRY-SRV
echo  4. Restore BURSARY-PC1
echo  5. Power cut on CSE-LAB-07
echo  6. CSE-LAB-07 power back
echo  7. Show agent status
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py attack --agent REGISTRY-SRV
if "%c%"=="2" python main.py stealth --agent BURSARY-PC1
if "%c%"=="3" python main.py restore --agent REGISTRY-SRV
if "%c%"=="4" python main.py restore --agent BURSARY-PC1
if "%c%"=="5" python main.py outage --agent CSE-LAB-07
if "%c%"=="6" python main.py reconnect --agent CSE-LAB-07
if "%c%"=="7" python main.py status
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
