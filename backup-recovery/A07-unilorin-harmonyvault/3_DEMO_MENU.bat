@echo off
title HarmonyVault - Demo menu
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
echo ===================== HarmonyVault demo menu =====================
echo  1. Intruder edits a honey file
echo  2. Quiet ransomware
echo  3. Loud ransomware
echo  4. Commit a backup now
echo  5. Restore the latest clean commit
echo  6. Verify the whole signed history
echo  7. Show commit log
echo  8. Stop the portal (outage)
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py peek-honey
if "%c%"=="2" python main.py stealth
if "%c%"=="3" python main.py attack
if "%c%"=="4" python main.py commit
if "%c%"=="5" python main.py restore
if "%c%"=="6" python main.py verify
if "%c%"=="7" python main.py log
if "%c%"=="8" python main.py outage
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
