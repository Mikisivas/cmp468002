@echo off
title KanoShield - Demo menu
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
echo ===================== KanoShield demo menu =====================
echo  1. Show admin authenticator code
echo  2. Show second admin code
echo  3. Try to delete backup 1 (WORM lock)
echo  4. Quiet ransomware
echo  5. Loud ransomware
echo  6. Seal a backup now
echo  7. Verify the vault
echo  8. Stop the portal (outage)
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py code --user ictdirector
if "%c%"=="2" python main.py code --user deputyregistrar
if "%c%"=="3" python main.py try-delete --id 1
if "%c%"=="4" python main.py stealth
if "%c%"=="5" python main.py attack
if "%c%"=="6" python main.py backup
if "%c%"=="7" python main.py verify
if "%c%"=="8" python main.py outage
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
