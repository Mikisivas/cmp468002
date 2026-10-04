@echo off
title YolaShield - Demo menu
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
echo ===================== YolaShield demo menu =====================
echo  1. Six simulated USSD calls through the gateway (start 2_START.bat first)
echo  2. Seal pending reports into a block
echo  3. Verify the ledger
echo  4. Insider edits a sealed report in the database
echo  5. Show LGA risk levels
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py demo-calls
if "%c%"=="2" python main.py seal
if "%c%"=="3" python main.py verify
if "%c%"=="4" python main.py tamper
if "%c%"=="5" python main.py risk
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
