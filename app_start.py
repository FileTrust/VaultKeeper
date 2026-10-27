#!/usr/bin/env python3
"""Frozen standard-library service entrypoint; lock before reading app code."""
from pathlib import Path
import runpy
import sys
from ft_update_bootstrap import enter
ROOT=Path(__file__).resolve().parent
enter(ROOT)
sys.argv=[str(ROOT/'vaultkeeper.py'),*sys.argv[1:]]
runpy.run_path(str(ROOT/'vaultkeeper.py'),run_name='__main__')
