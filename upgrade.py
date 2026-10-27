#!/usr/bin/env python3
"""Stable user command; implementation lives in core/."""
from pathlib import Path
import runpy
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'core'))

if __name__ == '__main__':
    runpy.run_path(str(ROOT / 'core/upgrade_cli.py'), run_name='__main__')
