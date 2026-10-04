@echo off
title SahelStore - Demo menu
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
echo ===================== SahelStore demo menu =====================
echo  1. Mains power cut, battery 35%
echo  2. Battery critical 12%
echo  3. Mains power back
echo  4. Quiet ransomware
echo  5. Loud ransomware
echo  6. Snapshot now
echo  7. Restore from local store
echo  8. Server room flooded (delete local store)
echo  9. Restore from offsite mirror
echo  10. Show status
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py power-cut
if "%c%"=="2" python main.py battery-critical
if "%c%"=="3" python main.py power-back
if "%c%"=="4" python main.py stealth
if "%c%"=="5" python main.py attack
if "%c%"=="6" python main.py snapshot
if "%c%"=="7" python main.py restore
if "%c%"=="8" python main.py lose-local
if "%c%"=="9" python main.py restore-offsite
if "%c%"=="10" python main.py status
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
