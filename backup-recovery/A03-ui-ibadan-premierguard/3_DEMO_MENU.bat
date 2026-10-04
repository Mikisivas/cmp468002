@echo off
title PremierGuard - Demo menu
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
echo ===================== PremierGuard demo menu =====================
echo  1. Stop the student portal (outage)
echo  2. Quiet ransomware on CSV files
echo  3. Loud ransomware (.locked + note)
echo  4. Snapshot now
echo  5. Restore newest good snapshot
echo  6. Verify Merkle roots and chunks
echo  7. List snapshots
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py outage
if "%c%"=="2" python main.py stealth
if "%c%"=="3" python main.py attack
if "%c%"=="4" python main.py snapshot
if "%c%"=="5" python main.py restore
if "%c%"=="6" python main.py verify
if "%c%"=="7" python main.py list
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
