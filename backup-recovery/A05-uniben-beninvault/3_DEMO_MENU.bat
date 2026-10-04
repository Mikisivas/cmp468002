@echo off
title BeninVault - Demo menu
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
echo ===================== BeninVault demo menu =====================
echo  1. Stop the student portal (outage)
echo  2. Quiet ransomware on CSV files
echo  3. Loud ransomware (.locked + note)
echo  4. Back up now
echo  5. Restore newest good backup
echo  6. Lose site A (Ugbowo ICT Centre burns)
echo  7. Scrub and rebuild shards
echo  8. Show SLA uptime
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py outage
if "%c%"=="2" python main.py stealth
if "%c%"=="3" python main.py attack
if "%c%"=="4" python main.py backup
if "%c%"=="5" python main.py restore
if "%c%"=="6" python main.py lose-site A
if "%c%"=="7" python main.py scrub
if "%c%"=="8" python main.py sla
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
