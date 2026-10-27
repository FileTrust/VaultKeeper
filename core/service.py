"""Standard one-node systemd unit; installation enables but never starts it."""
from pathlib import Path
import json,os,pwd,subprocess,sys
HOME=Path('/var/lib/filetrust-vaultkeeper');CREDENTIALS=Path('/etc/filetrust-vaultkeeper');APP=Path('/opt/filetrust-vaultkeeper');UNIT='filetrust-vaultkeeper.service'
def unit(state,credential,storage):
    for value in (state,credential,storage,APP,sys.executable):
        if any(char in str(value) for char in '\n\r\t %\\"'):raise ValueError('Service paths cannot contain whitespace or systemd expansions')
    return f'''[Unit]
Description=FileTrust Vaultkeeper node
Wants=network-online.target
After=network-online.target
StartLimitIntervalSec=0
[Service]
Type=simple
User=ftvaultkeeper
Group=ftvaultkeeper
WorkingDirectory={state}
LoadCredential=unlock.key:{credential}
RuntimeDirectory=filetrust-vaultkeeper
RuntimeDirectoryMode=0700
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=TMPDIR=/run/filetrust-vaultkeeper
ExecStart={sys.executable} {APP}/app_start.py --home {state} run
Restart=on-failure
RestartSec=15
UMask=0077
LimitCORE=0
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths={state} {storage}
RestrictSUIDSGID=yes
CapabilityBoundingSet=
KillMode=mixed
TimeoutStopSec=infinity
SendSIGKILL=no
[Install]
WantedBy=multi-user.target
'''
def install_service(state,credential,storage):
    if os.geteuid()!=0 or not Path('/run/systemd/system').is_dir():raise ValueError('System service installation needs root and systemd')
    if state!=HOME or credential!=CREDENTIALS/'unlock.key':raise ValueError('Automatic service installation uses the standard state/credential paths only')
    try:account=pwd.getpwnam('ftvaultkeeper')
    except KeyError:
        subprocess.run(['useradd','--system','--home-dir',str(state),'--shell','/usr/sbin/nologin','ftvaultkeeper'],check=True);account=pwd.getpwnam('ftvaultkeeper')
    record={'schema':1,'state':str(state),'storage':str(storage),'storage_device':storage.stat().st_dev,'storage_inode':storage.stat().st_ino}
    from vault import write_private
    write_private(CREDENTIALS/'installation.json',json.dumps(record).encode())
    # Do not descend into operator data outside these explicitly chosen node paths.
    for base in {state,storage}:
        for path in [base,*base.rglob('*')]:
            if path.is_symlink():raise ValueError('Node state cannot contain symbolic links during initial ownership setup')
            os.chown(path,account.pw_uid,account.pw_gid)
    from ft_update_bootstrap import initialize
    initialize(APP)
    Path('/etc/systemd/system/'+UNIT).write_text(unit(state,credential,storage))
    subprocess.run(['systemctl','daemon-reload'],check=True);subprocess.run(['systemctl','enable',UNIT],check=True)
