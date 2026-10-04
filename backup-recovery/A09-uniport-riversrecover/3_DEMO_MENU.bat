@echo off
title RiversRecover - Demo menu
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
echo ===================== RiversRecover demo menu =====================
echo  1. Normal registry activity
echo  2. Insider changes grades to A
echo  3. Insider deletes current results
echo  4. Ransomware encrypts the database file
echo  5. Recover to now (after ransomware)
echo  6. Unfreeze the database
echo  7. Ship journal now
echo  8. Verify recovery store
echo  9. Show status
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
if "%c%"=="1" python main.py normal-activity
if "%c%"=="2" python main.py grade-tamper
if "%c%"=="3" python main.py mass-delete
if "%c%"=="4" python main.py ransomware
if "%c%"=="5" python main.py recover
if "%c%"=="6" python main.py unfreeze
if "%c%"=="7" python main.py ship
if "%c%"=="8" python main.py verify
if "%c%"=="9" python main.py status
goto menu

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
