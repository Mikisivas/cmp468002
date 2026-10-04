@echo off
title AkureKeyVault - Setup
cd /d "%~dp0"
set PY=python
%PY% --version >nul 2>&1 || set PY=py
%PY% --version >nul 2>&1 || goto nopython
echo ============================================================
echo  AkureKeyVault setup. Takes 2 to 5 minutes. Keep internet ON for the first run.
echo ============================================================
if not exist venv\Scripts\activate.bat %PY% -m venv venv || goto failed
call venv\Scripts\activate.bat
echo Installing packages...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt || goto failed
python main.py setup || goto failed
echo.
echo ============================================================
echo  SETUP COMPLETE. Next: double-click 2_START.bat
echo  operator / ChangeMe@468 (auditor / ChangeMe@468 is read-only). Demo custodian shares are printed by setup and stored in data/shares_to_print/.
echo ============================================================
pause
exit /b 0
:failed
echo  Something failed above. Read the last lines, fix it, then run this file again.
pause
exit /b 1

:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
