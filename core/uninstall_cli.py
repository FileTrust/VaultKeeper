#!/usr/bin/env python3
"""Remove the standard application; retain custody/storage by default."""
import argparse,fcntl,json,os,shutil,subprocess,sys
from pathlib import Path
UNIT_DIR=Path('/etc/systemd/system')
APP=Path('/opt/filetrust-vaultkeeper');STATE=Path('/var/lib/filetrust-vaultkeeper');CREDENTIALS=Path('/etc/filetrust-vaultkeeper');UNIT='filetrust-vaultkeeper.service'
def uninstall(purge=False):
    if os.geteuid()!=0:raise PermissionError('Run this uninstaller with sudo')
    if purge:
        if not sys.stdin.isatty():raise ValueError('Purge requires a terminal confirmation')
        print('Retire network obligations and back up custody first. This deletes the standard wallet, unlock credential, state and profiles. External storage is always kept.')
        if input('Type DELETE to purge standard node state: ')!='DELETE':raise ValueError('Cancelled')
    from ft_update_bootstrap import initialize
    if APP.is_symlink():raise ValueError("Refusing a symlink application path")
    APP.mkdir(mode=0o755,parents=True,exist_ok=True)
    control=initialize(APP)
    with (control/'update.lock').open('rb') as update,(control/'run.lock').open('rb') as run:
        try:fcntl.flock(update,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Wait for the current installation/update') from None
        loaded=subprocess.check_output(['systemctl','show',UNIT,'--property=LoadState','--value'],text=True).strip()
        if loaded!='not-found':subprocess.run(['systemctl','disable','--now',UNIT],check=True)
        try:fcntl.flock(run,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('A manual process still uses this application') from None
        lock_path=STATE/'.run.lock'
        with lock_path.open('rb') if lock_path.exists() else open('/dev/null','rb') as node:
            try:fcntl.flock(node,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('A node/worker still uses this identity') from None
            # Fixed paths, no arbitrary rm target from an unprivileged config.
            for path in (APP,STATE,CREDENTIALS):
                if path.is_symlink():raise ValueError('Refusing a symlink installation path')
            if purge and STATE.exists():
                if os.path.ismount(STATE) or any(os.path.ismount(path) for path in STATE.rglob('*') if path.is_dir() and not path.is_symlink()):raise ValueError('Unmount external storage before purging standard state, or use keep-data uninstall')
            if APP.exists():shutil.rmtree(APP)
            (UNIT_DIR/UNIT).unlink(missing_ok=True)
            drop=(UNIT_DIR/(UNIT+'.d')/'application-updates.conf');drop.unlink(missing_ok=True)
            if purge:
                if STATE.exists():
                    # Never follow a custom storage link; external storage is kept.
                    shutil.rmtree(STATE)
                if CREDENTIALS.exists():shutil.rmtree(CREDENTIALS)
            subprocess.run(['systemctl','daemon-reload'],check=True)
    print('Application removed. '+('Standard node state purged.' if purge else 'Wallet, state, profiles and unlock credential kept.'))
    print('External storage, source clone, shared tools and inactive ftvaultkeeper account are kept.')
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--purge',action='store_true');a=p.parse_args()
    try:uninstall(a.purge)
    except (ValueError,PermissionError) as exc:print(str(exc));raise SystemExit(1)
