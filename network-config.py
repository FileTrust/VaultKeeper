#!/usr/bin/env python3
"""Inspect and explicitly apply FileTrust network settings while stopped."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT/'core'))
from ft_network_config import cli
if __name__=='__main__':
    arguments=sys.argv[1:]
    if not any(a=='--home' or a.startswith('--home=') for a in arguments): arguments += ['--home','/var/lib/filetrust-vaultkeeper']
    raise SystemExit(cli(ROOT,arguments))
