#!/usr/bin/env python3
"""Install one Vaultkeeper: compile verified source, download public setup only."""
from pathlib import Path
import argparse,base64,fcntl,getpass,json,os,platform,resource,signal,subprocess,sys,tempfile,threading,time
HERE=Path(__file__).resolve().parents[1]
if __name__=='__main__' and 'run' in sys.argv[1:]:
    from ft_update_bootstrap import enter
    enter(HERE)
from eth_account import Account
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from web3 import Web3
from vk_http import session as http_session
from artifact_store import GitHubRelease,verify_manifest,destination,installed,extract
from network import CONFIG_URL,fetch,config_from_payload,check_network,write_abis
from vault import write_private,save_wallet,load_wallet
from release import ARTIFACT_TAG
from settings import complete
from config_layout import organized

STOP=threading.Event()
def say(message):
    if len(sys.argv)>1 and 'run' in sys.argv[1:]:
        from console_color import paint
        message=paint(message)
    print(message,flush=True)
def private_dir(path):
    path=Path(path)
    if path.is_symlink():raise ValueError('Private directories cannot be symbolic links')
    path.mkdir(parents=True,exist_ok=True,mode=0o700);path.chmod(0o700)

def release_manifest(state,tag=ARTIFACT_TAG):
    folder=Path(state)/'releases'/tag
    manifest=verify_manifest((folder/'manifest.json').read_bytes(),(folder/'manifest.sig').read_bytes(),HERE/'release-key.pub')
    if manifest['version']!=tag:raise ValueError('Artifact release selector mismatch')
    return manifest

def prepare_release(state,profiles,tag=ARTIFACT_TAG,progress=say,allow_repair=True):
    source=json.loads((HERE/'update-source.json').read_text())
    remote=GitHubRelease(source['repository'],tag)
    manifest,raw,signature=remote.manifest(HERE/'release-key.pub')
    if manifest['version']!=tag:raise ValueError('Artifact release version mismatch')
    selected={f'partition-{int(size)}' for size in profiles}
    bundles=[row for row in manifest['bundles'] if row['id'] in selected]
    if len(bundles)!=len(selected):raise ValueError('Profile not in signed release')
    required=sum(row['size']+sum(file['size'] for file in row['files'].values()) for row in bundles if not installed(destination(state/'artifacts',row),row))
    import shutil
    if shutil.disk_usage(state).free < required+128*1024*1024:raise ValueError('Not enough free space for downloads and extraction')
    for index,bundle in enumerate(bundles,1):
        target=destination(state/'artifacts',bundle)
        progress(f'Artifact {index}/{len(bundles)}: {bundle["id"]}')
        if installed(target,bundle):progress('Already installed; verified')
        else:
            if target.exists() and not allow_repair:raise ValueError('An existing bundle is damaged; stop the node and repair it before preparing an update')
            extract(remote.download(bundle,state/'downloads',progress),target,bundle)
    folder=state/'releases'/tag;folder.mkdir(parents=True,exist_ok=True)
    write_private(folder/'manifest.json',raw);write_private(folder/'manifest.sig',signature)
    return manifest

def setup_wallet(state,credential):
    path=state/'wallet.json'
    if path.exists():return load_wallet(path,credential)
    choice=input('Do you have a wallet private key? [y/N]: ').strip().lower()
    if choice not in {'','n','no','y','yes'}:raise ValueError('Answer yes or no')
    if choice in {'y','yes'}:
        if not sys.stdin.isatty():raise ValueError('Import requires a terminal to keep the key hidden')
        try:account=Account.from_key(getpass.getpass('Wallet private key (hidden): ').strip())
        except Exception:raise ValueError('Invalid wallet private key') from None
    else:account=Account.create()
    peer=Ed25519PrivateKey.generate()
    encoded=b'\x08\x01\x12\x40'+peer.private_bytes_raw()+peer.public_key().public_bytes_raw()
    wallet={'address':account.address,'private_key':account.key.hex(),'peer_key':base64.b64encode(encoded).decode()}
    save_wallet(path,wallet,credential);return wallet

def installation_capacity(requested_gib,existing,requested_capacity=None,requested_bytes=None):
    from capacity_input import parse_capacity
    supplied=[requested_gib is not None,requested_capacity is not None,requested_bytes is not None]
    if sum(supplied)>1:raise ValueError('Use one storage capacity option')
    requested=None
    if requested_gib is not None:requested=parse_capacity(requested_gib)
    elif requested_capacity is not None:requested=parse_capacity(requested_capacity)
    elif requested_bytes is not None:requested=parse_capacity(requested_bytes,'b')
    if 'storage_capacity_bytes' in existing:
        capacity=existing['storage_capacity_bytes']
        if requested is not None and requested!=capacity:
            raise ValueError('Existing storage allocation differs; installation will not silently resize it')
        return capacity
    if requested is None:
        if not sys.stdin.isatty():raise ValueError('Specify --capacity, --capacity-gib or --storage-capacity-bytes for noninteractive installation')
        while requested is None:
            try:requested=parse_capacity(input('Storage capacity (examples: 200 MiB, 100 GiB; bare numbers mean GiB): '))
            except ValueError as exc:say(str(exc))
    say('Node storage allocation: '+str(requested)+' bytes')
    return requested


def check_install_port(port):
    """Fail before large downloads when another node already owns this port."""
    import socket
    if not 1<=port<=65535:raise ValueError('Choose a TCP port from 1 to 65535')
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        try:listener.bind(('0.0.0.0',port))
        except OSError as exc:
            raise ValueError(f'TCP port {port} is unavailable. Choose a free port with --port; existing nodes are not stopped.') from exc


def install(args):
    state=args.home.resolve();credential=args.key_file.resolve()
    if platform.system()!='Linux' or platform.machine()!='x86_64':raise ValueError('This release supports Linux x86_64')
    say('[1/8] Checking private state and installation locks');private_dir(state)
    from ft_update_install import update_lock
    with update_lock(HERE), (state/'.run.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Stop the node before installing') from None
        existing=json.loads((state/'config.json').read_text()) if (state/'config.json').exists() else {}
        if existing:existing=complete(existing)
        args.config_url=args.config_url or existing.get('network_config_url') or CONFIG_URL
        capacity=installation_capacity(args.capacity_gib,existing,args.capacity,args.storage_capacity_bytes)
        profile=int(existing.get('profile','partition-'+str(args.profile)).split('-')[-1])
        if existing and profile!=args.profile:raise ValueError('An installed profile cannot be changed implicitly; keep its original profile')
        selected=set(existing.get('download_profiles',[]))|set(args.download_profile or [])|{profile}
        # Persist selection before network/download work so retries cannot expand it.
        selection=state/'installation-selection.json'
        if selection.exists():selected.update(json.loads(selection.read_text())['profiles'])
        write_private(selection,json.dumps({'profiles':sorted(selected)}).encode())
        check_install_port(existing.get('port',args.port))
        say('[2/8] Checking Go and compiling the shipped runtime source')
        from go_build import build_runtime
        build_runtime(HERE,progress=say)
        say('[3/8] Downloading signed public artifacts (resume supported)')
        manifest=prepare_release(state,selected)
        bundle=next(row for row in manifest['bundles'] if row['id']==f'partition-{profile}')
        say('[4/8] Verifying network, profile, contract code and wiring')
        payload=fetch(args.config_url);cfg=config_from_payload(payload,bundle,args.rpc_url)
        cfg.update(existing)
        w3=Web3(Web3.HTTPProvider(cfg['rpc_url'],request_kwargs={'timeout':30},session=http_session()))
        check_network(w3,cfg,manifest,payload)
        say('[5/8] Preparing protected wallet and stable peer identity')
        if not credential.exists():
            if (state/'wallet.json').exists():raise ValueError('Restore the original unlock key; do not replace it')
            private_dir(credential.parent);write_private(credential,os.urandom(32))
        wallet=setup_wallet(state,credential)
        storage=Path(existing.get('storage_path') or args.storage_path or state/'storage').expanduser().resolve()
        if storage==state or (not storage.is_relative_to(state) and (len(storage.parts)<3 or storage.parts[1] not in {'srv','mnt','media','home'} or os.path.ismount(storage))):raise ValueError('Choose a dedicated storage subdirectory')
        if storage.exists() and not existing and any(storage.iterdir()):raise ValueError('For a new node choose an empty storage directory')
        private_dir(storage)
        cfg.update(address=wallet['address'],storage_path=str(storage),storage_capacity_bytes=capacity,
                   port=existing.get('port',args.port),advertise_ip=existing.get('advertise_ip',args.advertise_ip),
                   storage_fee=existing.get('storage_fee',args.storage_fee),stake_wei=existing.get('stake_wei',args.stake_wei),
                   network_config_url=args.config_url,download_profiles=sorted(selected),transaction_log_path=str(state/'logs/transactions.jsonl'))
        cfg=organized(cfg,state)
        if cfg['storage_capacity_bytes']<=0 or not 1<=cfg['port']<=65535 or cfg['storage_fee']<0 or cfg['stake_wei']<0:raise ValueError('Invalid capacity, port, storage fee or stake')
        say('[6/8] Saving settings and network ABIs; keeping existing state')
        write_abis(payload,state/'contracts');write_private(state/'network-config-active.json',json.dumps(payload).encode());cfg['network_config_snapshot']=str(state/'network-config-active.json');write_private(state/'config.json',json.dumps(cfg,indent=2).encode())
        say('[7/8] Preparing reboot service')
        if args.service:
            from service import install_service
            install_service(state,credential,storage)
        say('[8/8] Installation complete')
        say('Wallet address: '+wallet['address']);say('Fund the wallet, review storage/fees/stake, then start the service. Installation does not register or start the node.')

def configure(args):
    """Expand an existing config while stopped; never create or unlock an identity."""
    from ft_update_install import update_lock
    state=args.home.resolve();path=state/'config.json'
    if path.is_symlink():raise ValueError('Configuration cannot be a symbolic link')
    with update_lock(HERE), (state/'.run.lock').open('a') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Stop the node before changing configuration') from None
        try:fcntl.flock(int(os.environ['FILETRUST_RUN_LOCK_FD']),fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Another process uses this application') from None
        info=path.stat();cfg=organized(json.loads(path.read_text()),state)
        write_private(path,json.dumps(cfg,indent=2).encode())
        if os.geteuid()==0:os.chown(path,info.st_uid,info.st_gid)
        say('Configuration expanded: '+str(path)+'; existing settings and identity retained')

def doctor(args):
    state=args.home.resolve();cfg=organized(json.loads((state/'config.json').read_text()),state);manifest=release_manifest(state)
    wallet=load_wallet(state/'wallet.json',args.key_file)
    if Account.from_key(wallet['private_key']).address.lower()!=cfg['address'].lower():raise ValueError('Wallet address mismatch')
    profile=next(row for row in manifest['bundles'] if row['id']==cfg['profile']);runtime=None
    for bundle in (profile,):
        say('Checking '+bundle['id'])
        if not installed(destination(state/'artifacts',bundle),bundle,progress=say):raise ValueError('Missing or changed files; run repair. Setup generation is never attempted')
    from go_build import built_runtime
    runtime=built_runtime(HERE)
    say('Checking network and deployed contracts; waiting for RPC responses')
    snapshot=Path(cfg.get('network_config_snapshot') or state/'network-config-active.json')
    payload=json.loads(snapshot.read_text()) if snapshot.is_file() else fetch(cfg['network_config_url'])
    binding=check_network(Web3(Web3.HTTPProvider(cfg['rpc_url'],request_kwargs={'timeout':30},session=http_session())),cfg,manifest,payload)
    from network import verify_local_abis
    verify_local_abis(cfg,binding)
    if not snapshot.exists():write_private(snapshot,json.dumps(payload).encode())
    return cfg,wallet,profile,runtime

def run(args):
    resource.setrlimit(resource.RLIMIT_CORE,(0,0));os.umask(0o077)
    state=args.home.resolve();lock=(state/'.run.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    os.set_inheritable(lock.fileno(),True);os.environ['FILETRUST_GUARDIAN_STATE_LOCK_FD']=str(lock.fileno())
    cfg,wallet,profile,runtime=doctor(args)
    from commands import build_commands
    from ft_update_bootstrap import child_lock_options,ready
    from ft_updates import start_watcher
    signal.signal(signal.SIGTERM,lambda *_:STOP.set());signal.signal(signal.SIGINT,lambda *_:STOP.set())
    start_watcher(HERE,state_dir=state/'updates',log=say,stop=STOP)
    runtime_dir=os.environ.get('RUNTIME_DIRECTORY')
    if not runtime_dir:
        runtime_dir='/run/user/'+str(os.getuid())
        if not Path(runtime_dir).is_dir():raise ValueError('Run through systemd or provide a private tmpfs RUNTIME_DIRECTORY')
    with tempfile.TemporaryDirectory(prefix='vaultkeeper-',dir=runtime_dir) as temporary:
        run_dir=Path(temporary);write_private(run_dir/'signing.key',(wallet['private_key']+'\n').encode());write_private(run_dir/'peer.key',base64.b64decode(wallet['peer_key'],validate=True));wallet.clear()
        cfg['profile_path']=str(destination(state/'artifacts',profile));server,proof,environment=build_commands(cfg,state,runtime,run_dir)
        environment['FILETRUST_VK_SUPERVISOR_PID']=str(os.getpid())
        from supervisor import run_workers
        private_dir(state/'logs')
        try:
            run_workers(cfg,state,runtime,server,proof,environment,STOP,child_lock_options(),
                        lambda:None,say,on_started=lambda:ready(HERE,state))
        finally:
            (state/'.filetrust-node-health.json').unlink(missing_ok=True)

def parser():
    p=argparse.ArgumentParser(prog="vaultkeeper.py",description=__doc__);p.add_argument('--home',type=Path,default=Path('/var/lib/filetrust-vaultkeeper'));p.add_argument('--key-file',type=Path,default=Path('/etc/filetrust-vaultkeeper/unlock.key'))
    s=p.add_subparsers(dest='command',required=True);setup=s.add_parser('install')
    setup.add_argument('--profile',type=int,choices=(128,256,512,1024),default=512);setup.add_argument('--download-profile',type=int,action='append',choices=(128,256,512,1024))
    setup.add_argument('--config-url',default=None);setup.add_argument('--rpc-url',default='https://rpc.filetrust.io');capacity_options=setup.add_mutually_exclusive_group();capacity_options.add_argument('--capacity-gib');capacity_options.add_argument('--capacity');capacity_options.add_argument('--storage-capacity-bytes',type=int);setup.add_argument('--storage-path',type=Path)
    setup.add_argument('--port',type=int,default=4101);setup.add_argument('--advertise-ip',default='auto');setup.add_argument('--storage-fee',type=int,default=6121);setup.add_argument('--stake-wei',type=int,default=0);setup.add_argument('--service',action='store_true')
    for name in ('run','doctor','repair','configure'):s.add_parser(name)
    return p
if __name__=='__main__':
    args=parser().parse_args()
    try:
        if args.command=='install':install(args)
        elif args.command=='run':run(args)
        elif args.command=='doctor':doctor(args);say('Vaultkeeper checks passed')
        elif args.command=='configure':configure(args)
        else:
            from ft_update_install import update_lock
            with update_lock(HERE), (args.home/'.run.lock').open('a') as lock:
                try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise ValueError('Stop the node before repairing artifacts') from None
                from go_build import build_runtime
                try:fcntl.flock(int(os.environ['FILETRUST_RUN_LOCK_FD']),fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:raise ValueError('Another node uses this application; stop it before repair') from None
                build_runtime(HERE,repair=True)
                cfg=json.loads((args.home/'config.json').read_text());prepare_release(args.home,cfg['download_profiles'])
    except (Exception,KeyboardInterrupt) as exc:
        # Transport exceptions may include URLs; custody exceptions may contain secrets.
        say('Vaultkeeper stopped: '+(str(exc) if isinstance(exc,(ValueError,PermissionError)) else type(exc).__name__));raise SystemExit(1)
