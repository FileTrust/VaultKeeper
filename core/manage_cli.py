#!/usr/bin/env python3
"""Node controls. Restart never cleans, resets, rebuilds or regenerates setup."""
import argparse,json,os,subprocess
from pathlib import Path
UNIT='filetrust-vaultkeeper.service'
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['start','stop','restart','status','logs','doctor','repair','configure','update','uninstall']);p.add_argument('arguments',nargs=argparse.REMAINDER);a=p.parse_args();root=Path(__file__).resolve().parents[1]
    if a.command in {'start','stop','restart','status'}:return subprocess.call(['systemctl',a.command,UNIT,*a.arguments])
    if a.command=='logs':return subprocess.call(['journalctl','-u',UNIT,'-f',*a.arguments])
    python=str(root/'.venv/bin/python') if (root/'.venv/bin/python').exists() else __import__('sys').executable
    target={'doctor':('vaultkeeper.py',['doctor']),'repair':('vaultkeeper.py',['repair']),'configure':('vaultkeeper.py',['configure']),'update':('upgrade.py',a.arguments or ['status']),'uninstall':('uninstall.py',a.arguments)}[a.command]
    return subprocess.call([python,str(root/target[0]),*target[1]])
if __name__=='__main__':raise SystemExit(main())
