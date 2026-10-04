"""Writes Windows .bat launchers, a Linux/macOS run.sh and README.md for one system folder.
Usage: python gen_launchers.py reports/build/specs/A01.json  (set "folder" to the full path of the project folder first)"""
import json
import os
import sys

NOPY = r"""
:nopython
echo.
echo  ERROR: Python was not found on this computer.
echo  Install Python 3.10 or newer from https://www.python.org/downloads/
echo  On the FIRST installer screen tick "Add python.exe to PATH", then run this file again.
pause
exit /b 1
"""
HEAD = """@echo off
title {name} - {what}
cd /d "%~dp0"
set PY=python
%PY% --version >nul 2>&1 || set PY=py
%PY% --version >nul 2>&1 || goto nopython
"""
NEEDVENV = """if not exist venv\\Scripts\\activate.bat (
  echo  Setup has not been done yet. Double-click 1_SETUP.bat first.
  pause
  exit /b 1
)
call venv\\Scripts\\activate.bat
"""


def write(folder, name, text, crlf=True):
    with open(os.path.join(folder, name), "w", newline="\r\n" if crlf else "\n") as fh:
        fh.write(text)


def main(spec_path):
    s = json.load(open(spec_path))
    f = s["folder"]
    setup = HEAD.format(name=s["name"], what="Setup") + f"""echo ============================================================
echo  {s['name']} setup. Takes 2 to 5 minutes. Keep internet ON for the first run.
echo ============================================================
if not exist venv\\Scripts\\activate.bat %PY% -m venv venv || goto failed
call venv\\Scripts\\activate.bat
echo Installing packages...
python -m pip install --upgrade pip >nul
python -m pip install -r requirements.txt || goto failed
python main.py setup || goto failed
echo.
echo ============================================================
echo  SETUP COMPLETE. Next: double-click 2_START.bat
echo  {s['login']}
echo ============================================================
pause
exit /b 0
:failed
echo  Something failed above. Read the last lines, fix it, then run this file again.
pause
exit /b 1
""" + NOPY
    write(f, "1_SETUP.bat", setup)
    start = HEAD.format(name=s["name"], what="Running (keep this window open)") + NEEDVENV + f"""echo Starting {s['name']}. Your browser opens in a few seconds.
echo KEEP THIS WINDOW OPEN. Closing it stops the system.
start "" cmd /c "timeout /t 4 >nul & start {s['url']}"
python main.py serve
pause
exit /b 0
""" + NOPY
    write(f, "2_START.bat", start)
    menu_lines = "\n".join(f"echo  {i + 1}. {label}" for i, (label, _) in enumerate(s["demo"]))
    ifs = "\n".join(f'if "%c%"=="{i + 1}" python main.py {cmd}' for i, (_, cmd) in enumerate(s["demo"]))
    demo = HEAD.format(name=s["name"], what="Demo menu") + NEEDVENV + f""":menu
echo.
echo ===================== {s['name']} demo menu =====================
{menu_lines}
echo  0. Exit
set /p c=Type a number and press Enter:
if "%c%"=="0" exit /b 0
{ifs}
goto menu
""" + NOPY
    write(f, "3_DEMO_MENU.bat", demo)
    test = HEAD.format(name=s["name"], what="Self test") + NEEDVENV + """echo Running the automatic test suite. It resets the demo data first.
python selftest.py
pause
exit /b 0
""" + NOPY
    write(f, "4_SELFTEST.bat", test)
    sh = f"""#!/usr/bin/env sh
# Linux/macOS helper. First run: sh run.sh setup   Then: sh run.sh serve   Demo: sh run.sh <command>
cd "$(dirname "$0")"
if [ ! -d venv ]; then python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt; fi
. venv/bin/activate
if [ "$1" = "selftest" ]; then python selftest.py; else python main.py "$@"; fi
"""
    write(f, "run.sh", sh, crlf=False)

    demo_rows = "\n".join(f"| {i + 1} | {say} | `python main.py {cmd}` | {see} |"
                          for i, (say, cmd, see) in enumerate(s["script"]))
    design = "\n".join(f"- {d}" for d in s["design"])
    cmds = "\n".join(f"| `python main.py {c}` | {t} |" for c, t in s["commands"])
    readme = f"""# {s['name']}: {s['title']}

{s['intro']}

Built for: **{s['institution']}**. Project folder: `{os.path.basename(f)}`.

Default login after setup: {s['login']}

## What makes this design different

{design}

## Part A. Install on a Windows computer (about 10 minutes)

1. Install Python 3.10 or newer from https://www.python.org/downloads/ and tick **Add python.exe to PATH**.
2. Copy this whole folder to the computer, for example `C:\\CMP468\\{os.path.basename(f)}`.
3. Double-click **1_SETUP.bat**. It creates a private Python environment, installs the packages and
   prepares the demo data.
4. Double-click **2_START.bat**. Your browser opens {s['url']} . Keep the black window open.
5. Double-click **3_DEMO_MENU.bat** for the defence demonstration.
6. Double-click **4_SELFTEST.bat** to run the automatic tests. It prints PASS or FAIL for each test and saves
   the numbers to `results/selftest.json`.

Linux or macOS: `sh run.sh setup`, then `sh run.sh serve`, and `sh run.sh selftest`.

## Part B. Defence demonstration script

| # | Say this | Run this (or use 3_DEMO_MENU.bat) | What the panel sees |
|---|----------|-----------------------------------|---------------------|
{demo_rows}

## All commands

| Command | What it does |
|---------|--------------|
{cmds}
| `python selftest.py` | Full automatic test. Resets the demo data first. |

## Files

{s['files']}

{s.get('extra', '')}

## Troubleshooting

- "python is not recognized": reinstall Python and tick Add python.exe to PATH.
- Port already in use: another copy is running. Close the other black window, or change `"port"` in
  `config.json`.
- Start again from zero: `python main.py reset`, then run 1_SETUP.bat again.
"""
    write(f, "README.md", readme, crlf=False)


if __name__ == "__main__":
    main(sys.argv[1])
