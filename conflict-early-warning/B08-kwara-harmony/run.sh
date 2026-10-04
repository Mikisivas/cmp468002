#!/usr/bin/env sh
# Linux/macOS helper. First run: sh run.sh setup   Then: sh run.sh serve   Demo: sh run.sh <command>
cd "$(dirname "$0")"
if [ ! -d venv ]; then python3 -m venv venv && . venv/bin/activate && pip install -r requirements.txt; fi
. venv/bin/activate
if [ "$1" = "selftest" ]; then python selftest.py; else python main.py "$@"; fi
