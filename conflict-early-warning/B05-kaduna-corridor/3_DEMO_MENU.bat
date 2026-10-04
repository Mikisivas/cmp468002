@echo off
title KadunaCorridor - Demo menu
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
echo ===================== KadunaCorridor demo menu =====================
echo  1. An attack and two reprisals in Sanga
echo  2. Show the 7-day forecast
echo  3. Refit the model
echo  4. List retaliation chains
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py flare --lga Sanga
if "%c%"=="2" python main.py forecast
if "%c%"=="3" python main.py fit
if "%c%"=="4" python main.py chains
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
