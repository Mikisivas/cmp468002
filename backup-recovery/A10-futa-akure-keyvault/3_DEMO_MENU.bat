@echo off
title AkureKeyVault - Demo menu
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
echo ===================== AkureKeyVault demo menu =====================
echo  1. Show the demo custodian shares
echo  2. Quiet ransomware
echo  3. Loud ransomware
echo  4. Back up now
echo  5. Restore with Registrar + Bursar shares
echo  6. Restore with Bursar + ICT Director shares
echo  7. Rotate the recovery key
echo  8. Crypto-shred backup 1
echo  9. Verify copies
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py shares
if "%c%"=="2" python main.py stealth
if "%c%"=="3" python main.py attack
if "%c%"=="4" python main.py backup
if "%c%"=="5" python main.py restore
if "%c%"=="6" python main.py restore --custodians bursar,ict_director
if "%c%"=="7" python main.py rotate
if "%c%"=="8" python main.py shred --id 1
if "%c%"=="9" python main.py verify
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
