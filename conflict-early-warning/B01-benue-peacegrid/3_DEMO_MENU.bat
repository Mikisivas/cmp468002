@echo off
title BenuePeaceGrid - Demo menu
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
echo ===================== BenuePeaceGrid demo menu =====================
echo  1. Live feed: herds move, two drift into Guma farms (start 2_START.bat first)
echo  2. Rescore all cells
echo  3. Show top 15 cells
echo  4. Show AHP weights and consistency
echo  5. Run the back-test
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py simulate --steps 30 --interval 2
if "%c%"=="2" python main.py score
if "%c%"=="3" python main.py top
if "%c%"=="4" python main.py ahp
if "%c%"=="5" python main.py backtest
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
