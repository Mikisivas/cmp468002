@echo off
title NigerBasinWatch - Demo menu
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
echo ===================== NigerBasinWatch demo menu =====================
echo  1. New satellite week: northern drought
echo  2. Recompute the 8-week calendar
echo  3. Validate TPI against incidents
echo  4. Verify dataset fingerprints
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py drought
if "%c%"=="2" python main.py forecast
if "%c%"=="3" python main.py validate
if "%c%"=="4" python main.py verify-data
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
