@echo off
title LafiaAlert - Demo menu
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
echo ===================== LafiaAlert demo menu =====================
echo  1. Send 10 demo SMS through the signed webhook (start 2_START.bat first)
echo  2. Show today's spike test per LGA
echo  3. Retrain the classifier
echo  4. Classify one message
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py demo-feed
if "%c%"=="2" python main.py spikes
if "%c%"=="3" python main.py train
if "%c%"=="4" python main.py classify "an kai hari a giza yanzu da bindigogi"
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
