"""Container entrypoint. Reuse node behavior; keep custody in named volumes."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import signal
import sys
import time

APP=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(APP))  # Root startup/update helpers sit beside core/.
STATE=Path('/var/lib/filetrust-vaultkeeper')
CREDENTIAL=Path('/etc/filetrust-vaultkeeper/unlock.key')
RUNTIME=Path(os.environ.get('RUNTIME_DIRECTORY','/run/filetrust-vaultkeeper'))


def health():
    """Worker startup health; proof/admission readiness is reported in node logs."""
    try:
        started=json.loads((RUNTIME/'container-start.json').read_text())
        status=json.loads((STATE/'.filetrust-node-health.json').read_text())
        if status['pid']!=started['pid'] or status['ready_at']<started['started_at']:
            return False
        if status['version']!=(APP/'VERSION').read_text().strip():return False
        os.kill(status['pid'],0)
        return True
    except (OSError,ValueError,KeyError,TypeError):return False


def config_import(stream):
    from config_layout import organized
    from vault import load_wallet,write_private
    data=stream.read(1024*1024+1)
    if len(data)>1024*1024:raise ValueError('Configuration exceeds 1 MiB')
    config=json.loads(data)
    if not isinstance(config,dict):raise ValueError('Configuration must be a JSON object')
    if any(str(name).lower() in {'private_key','vk_private_key','wallet_private_key','peer_key','mnemonic','seed_phrase'} for name in config):
        raise ValueError('Private keys belong in the protected wallet, not configuration')
    config=organized(config,STATE)
    wallet=load_wallet(STATE/'wallet.json',CREDENTIAL)
    if config.get('address','').lower()!=wallet['address'].lower():raise ValueError('Configuration must preserve this node wallet address')
    if not Path(config['storage_path']).resolve().is_relative_to(STATE.resolve()):
        raise ValueError('Docker storage must stay inside the persistent node volume')
    if config['storage_capacity_bytes']<=0 or not 1<=config['port']<=65535:raise ValueError('Invalid capacity or port')
    with (STATE/'.run.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Stop the node before changing configuration') from None
        write_private(STATE/'config.json',json.dumps(config,indent=2).encode())
    print('Configuration saved. Startup verifies network and contract settings.',flush=True)


def main(arguments=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['install','run','doctor','repair','configure','config','import-config','check','health','idle','network-config'])
    parser.add_argument('arguments',nargs=argparse.REMAINDER)
    args=parser.parse_args(arguments)
    if args.command=='network-config':
        from ft_network_config import cli
        return cli(APP,[*args.arguments,'--home',str(STATE)])
    if args.command=='health':return 0 if health() else 1
    if args.command=='idle':
        signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
        while True:signal.pause()
    if args.command=='config':
        print((STATE/'config.json').read_text());return 0
    if args.command=='import-config':config_import(sys.stdin);return 0
    if args.command=='run':
        from vault import write_private
        write_private(RUNTIME/'container-start.json',json.dumps({'pid':os.getpid(),'started_at':time.time()}).encode())
        os.execv(sys.executable,[sys.executable,str(APP/'app_start.py'),'run'])
    # Optional private-repository access exists only in this temporary tool
    # container's RAM filesystem; it never enters image layers or Docker Env.
    token=RUNTIME/'github-token'
    if token.exists():
        from vault import private_file
        raw=private_file(token,8192).decode().strip()
        if not raw or any(char.isspace() for char in raw):raise ValueError('Invalid GitHub credential')
        os.environ['GH_TOKEN']=raw
    if args.command=='check':
        from ft_updates import cli
        sys.argv=[str(APP/'update.py'),*args.arguments]
        return cli(APP)
    import node
    parsed=node.parser().parse_args([args.command,*args.arguments])
    if args.command=='install' and parsed.service:raise ValueError('Docker manages this node; --service is for native installation')
    if args.command in {'install','doctor'}:
        getattr(node,args.command)(parsed)
        return 0
    os.execv(sys.executable,[sys.executable,str(APP/'vaultkeeper.py'),args.command,*args.arguments])


if __name__=='__main__':
    try:raise SystemExit(main())
    except (Exception,KeyboardInterrupt) as error:
        print('Container command stopped: '+(str(error) if isinstance(error,(ValueError,PermissionError)) else type(error).__name__),file=sys.stderr)
        raise SystemExit(1)
