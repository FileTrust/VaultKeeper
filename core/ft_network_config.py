"""Network settings: daily notices and explicit, stopped-node activation.

Vendored unchanged into independent packages. No code download, key handling,
proof lock, contract deployment or automatic node restart is performed here.
"""
from __future__ import annotations
import argparse, contextlib, fcntl, hashlib, ipaddress, json, os, random, re, shutil, tempfile, time
from pathlib import Path
from urllib.parse import urlsplit
import urllib.request
try:
    from .ft_network_http import _HTTPHandler, _HTTPSHandler
except ImportError:
    from ft_network_http import _HTTPHandler, _HTTPSHandler

URL = 'https://config.filetrust.io/v1/network-config'
LIMIT = 32 * 1024 * 1024
CONTRACTS = {
 'guardian_registry':'GuardianRegistry', 'vault_keeper_registry':'VaultKeeperRegistry',
 'network_directory_reader':'NetworkDirectoryReader', 'acl':'AccessControlFT',
 'dv':'DataVault', 'dkg':'DKG', 'telg':'TElG', 'telg_v2':'TElGv2',
 'zkdkg_coordinator_v2':'ZkDkgCoordinatorV2', 'guardian_share_proof':'GuardianShareProof',
 'zkdkg_dispute_manager':'ZkDkgDisputeManager', 'reputation_manager':'ReputationManager',
 'staking_manager':'StakingManager', 'reward_manager':'RewardManager',
 'file_registration':'FileRegistrationSC', 'vk_escrow':'VKEscrow',
 'storageproof':'StorageProofSC', 'capacity_proof':'CapacityProofSC',
 'capacity_certification':'CapacityCertificationSC', 'capacity_incremental_batch':'CapacityIncrementalBatchSC',
 'partition_snapshot_proof':'PartitionSnapshotProofSC', 'storage_receipt_dispute':'StorageReceiptDispute',
 'storage_registration_timeout':'StorageRegistrationTimeout', 'deletion_release':'DeletionReleaseSC',
 'zkdkg_share_verifier':'ShareVerifier', 'v2_pre_partial_verifier':'V2PrePartialVerifier',
 'share_possession_verifier':'SharePossessionVerifier',
}

G_PREFIXES={'guardian_registry','vault_keeper_registry','acl','dv','telg_v2','zkdkg_coordinator_v2','guardian_share_proof','zkdkg_dispute_manager','reputation_manager','staking_manager','reward_manager','file_registration','zkdkg_share_verifier','v2_pre_partial_verifier','share_possession_verifier'}
VK_PREFIXES={'vault_keeper_registry','acl','file_registration','vk_escrow','capacity_proof','capacity_certification','capacity_incremental_batch','partition_snapshot_proof','storageproof','storage_receipt_dispute','deletion_release'}

def product(app):
    try:return read(Path(app)/'update-source.json')['product']
    except (OSError,ValueError,KeyError):return None

def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
def digest(value): return hashlib.sha256(canonical(value)).hexdigest()
def read(path): return json.loads(Path(path).read_text())
def atomic(path, value):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink(): raise ValueError('Settings cannot be symbolic links')
    info=path.stat() if path.exists() else None
    fd,tmp=tempfile.mkstemp(prefix='.settings-',dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as out:
            out.write(canonical(value)+b'\n');out.flush();os.fsync(out.fileno())
        if info and os.geteuid()==0: os.chown(tmp,info.st_uid,info.st_gid)
        os.replace(tmp,path)
        fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
    finally: Path(tmp).unlink(missing_ok=True)

def https(value):
    if any(c.isspace() or ord(c)<32 or c in '\"\\' for c in str(value)): raise ValueError('Invalid service URL characters')
    p=urlsplit(str(value))
    if p.scheme!='https' or not p.hostname or p.username or p.password or p.fragment:
        raise ValueError('Network services require HTTPS without credentials')
    try: ipaddress.ip_address(p.hostname)
    except ValueError: pass
    else: raise ValueError('Use DNS names for network services')
    return str(value)

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self,*args,**kwargs): raise ValueError('Configuration redirects are not accepted')

def fetch(url):
    request=urllib.request.Request(https(url),headers={'Accept':'application/json','User-Agent':'FileTrust-network-settings/1'})
    with urllib.request.build_opener(_HTTPHandler(),_HTTPSHandler(),NoRedirect()).open(request,timeout=30) as response:
        if response.status!=200: raise ValueError('Configuration service unavailable')
        data=response.read(LIMIT+1)
    if len(data)>LIMIT: raise ValueError('Configuration payload exceeds limit')
    payload=json.loads(data)
    if not isinstance(payload,dict) or not isinstance(payload.get('network'),dict) or not isinstance(payload.get('deployed_addresses'),dict):
        raise ValueError('Invalid network configuration')
    return payload

def rpc(url,method,params):
    request=urllib.request.Request(url,data=canonical({'jsonrpc':'2.0','id':1,'method':method,'params':params}),headers={'Content-Type':'application/json','User-Agent':'FileTrust-network-settings/1'})
    # Operators may retain a local RPC. The config download and proposed public
    # endpoint still require verified HTTPS; credentials never enter notices.
    with urllib.request.build_opener(_HTTPHandler(),_HTTPSHandler(),NoRedirect()).open(request,timeout=30) as response: data=json.loads(response.read(2*1024*1024))
    if 'error' in data or 'result' not in data: raise ValueError('RPC validation failed')
    return data['result']

def address(value):
    return isinstance(value,str) and re.fullmatch(r'0x[0-9a-fA-F]{40}',value) and int(value[2:],16)!=0

def projection(home,cfg,payload,initial=False,entity=None):
    """Only network-owned fields; never return custody or operator settings."""
    home=Path(home);deployed=payload['deployed_addresses'];network=payload['network']
    chain=int(deployed['chainId']);actual=chain if initial else int(rpc(cfg['rpc_url'],'eth_chainId',[]),16)
    if chain<=0 or chain!=actual or (not initial and cfg.get('chain_id') and int(cfg['chain_id'])!=chain):
        raise ValueError('Network chain mismatch')
    proposed_rpc=https(network['rpc_url'])
    if int(rpc(proposed_rpc,'eth_chainId',[]),16)!=chain: raise ValueError('Proposed RPC chain mismatch')
    fields={'rpc_url':proposed_rpc};abis={};current_abis={};targets={};old_addresses={}
    if 'chain_id' in cfg: fields['chain_id']=chain
    for prefix,name in CONTRACTS.items():
        if entity in {'g','guardians'} and prefix not in G_PREFIXES: continue
        if entity in {'vk','vaultkeeper'} and prefix not in VK_PREFIXES: continue
        key=prefix+'_address'
        if key not in cfg: continue
        value=(deployed.get('contracts') or {}).get(name) or (deployed.get('appConfig') or {}).get(key) or (deployed.get('env') or {}).get(prefix.upper()+'_ADDRESS')
        if not value and not cfg[key]: continue
        if not address(value): raise ValueError('Missing required deployed contract: '+name)
        artifact=(payload.get('artifact_files') or {}).get(name+'.json')
        if not isinstance(artifact,dict) or not isinstance(artifact.get('abi'),list) or not artifact['abi']:
            raise ValueError('Missing contract ABI: '+name)
        for item in artifact['abi']:
            if not isinstance(item,dict) or item.get('type') not in {'function','constructor','event','error','fallback','receive'}:
                raise ValueError('Invalid ABI structure: '+name)
        code=rpc(proposed_rpc,'eth_getCode',[value,'latest'])
        if code in ('0x','0x0',''): raise ValueError('Contract code missing: '+name)
        fields[key]=value
        jsonkey=prefix+'_json'
        if jsonkey in cfg:
            source=Path(cfg[jsonkey]);source=source if source.is_absolute() else home/source
            if not source.is_file() and not Path(cfg[jsonkey]).is_absolute(): source=home/'core'/cfg[jsonkey]
            current_abis[name]=read(source).get('abi') if source.is_file() else None
            targets[jsonkey]=name+'.json';abis[name]={'abi':artifact['abi']}
        old_addresses[key]=cfg[key]
    if 'abi_path' in cfg and 'VaultKeeperRegistry' in abis: targets['abi_path']='VaultKeeperRegistry.json'
    if not targets: raise ValueError('No supported contract ABI settings')
    # Keep user-selected Discovery peers unless management was explicitly enabled.
    if cfg.get('network_config_manage_discovery') and 'discovery_urls' in cfg:
        peers=network.get('discovery_urls')
        if not isinstance(peers,list) or not peers: raise ValueError('Missing Discovery endpoints')
        fields['discovery_urls']=[https(value) for value in peers]
    if 'price_url' in cfg and network.get('ftu_price_url'):
        fields['price_url']=https(network['ftu_price_url'])
    if cfg.get('storageproof_rpc_url')==cfg.get('rpc_url'):
        fields['storageproof_rpc_url']=proposed_rpc
    protocol=[]
    required=('zk_block_size','zk_tree_depth','storageproof_deadline_count','storageproof_challenge_count','storageproof_partition_max_sectors','storageproof_proof_period_seconds','su_to_wei_rate','filetrust_fixed_gas_price_wei','fixed_gas_price_wei')
    advertised=deployed.get('appConfig') or {}
    economics=deployed.get('economics') or {}
    advertised={**advertised}
    if 'suToWeiRate' in economics:advertised['su_to_wei_rate']=economics['suToWeiRate']
    if 'fixedGasPriceWei' in economics:
        advertised['fixed_gas_price_wei']=economics['fixedGasPriceWei'];advertised['filetrust_fixed_gas_price_wei']=economics['fixedGasPriceWei']
    for key in required:
        if key not in cfg or key not in advertised:continue
        value=advertised[key]
        if int(cfg[key])!=int(value):
            fields[key]=str(value) if isinstance(cfg[key],str) else int(value)
            protocol.append('protocol:'+key)
    changes=[key for key,value in fields.items() if cfg.get(key)!=value and not (key.endswith('_address') and str(cfg.get(key,'')).lower()==value.lower())]
    changes += protocol
    changes += ['ABI:'+name for name,value in abis.items() if current_abis.get(name)!=value['abi']]
    result={'chain_id':chain,'fields':fields,'abis':abis,'targets':targets,'changes':sorted(changes)}
    return result

@contextlib.contextmanager
def locked(path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    if path.is_symlink(): raise ValueError('Lock cannot be a symbolic link')
    inherited=os.environ.get('FILETRUST_NETWORK_INSTALL_LOCK_FD')
    if inherited and path.name=='run.lock' and path.parent.name=='.filetrust-updates':
        fd=int(inherited)
        if os.fstat(fd).st_ino!=path.stat().st_ino or os.fstat(fd).st_dev!=path.stat().st_dev: raise ValueError('Invalid installer lock')
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        yield
        return
    with path.open('rb' if path.exists() else 'a') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise ValueError('Node or settings operation is running; stop it first') from None
        yield

def status(home):
    try: return read(Path(home)/'.network-updates/status.json')
    except (OSError,ValueError): return {'state':'unchecked'}

def policy(app,home,cfg,candidate,payload,initial=False):
    """Public proof packages supply their existing signed binding validator."""
    plugin=Path(app)/'network_config_policy.py'
    if not plugin.exists(): plugin=Path(app)/'core/network_config_policy.py'
    if plugin.exists():
        import importlib.util
        spec=importlib.util.spec_from_file_location('_filetrust_network_policy',plugin);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        module.validate(Path(app),Path(home),cfg,candidate,payload)
    elif not initial:
        if any(key.startswith('protocol:') for key in candidate['changes']): raise ValueError('Protocol settings require a compatible application/artifact release')
        # Internal/factory nodes have no signed package binding. A changed
        # runtime or ABI requires an application compatibility review first.
        for prefix,name in CONTRACTS.items():
            key=prefix+'_address'
            if key not in candidate['fields']: continue
            if 'ABI:'+name in candidate['changes']: raise ValueError('ABI compatibility requires an application update: '+name)
            if key in candidate['changes']:
                old=rpc(cfg['rpc_url'],'eth_getCode',[cfg[key],'latest']);new=rpc(candidate['fields']['rpc_url'],'eth_getCode',[candidate['fields'][key],'latest'])
                if old in ('0x','0x0','') or old.lower()!=new.lower(): raise ValueError('Contract compatibility requires an application update: '+name)

def check(app,home=None,force=False,initial=False):
    app=Path(app);home=Path(home or app);directory=home/'.network-updates';directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    if directory.is_symlink(): raise ValueError('Settings state cannot be a symbolic link')
    directory.chmod(0o700)
    with locked(directory/'check.lock'):
        previous=status(home)
        if not force and previous.get('next_check',0)>time.time(): return previous
        try:
            cfg=read(home/'config.json');payload=fetch(cfg.get('network_config_url') or URL);candidate=projection(home,cfg,payload,initial,product(app))
            reason=''
            try: policy(app,home,cfg,candidate,payload,initial)
            except ValueError as exc: reason=str(exc)
            # Full bootstrap is public, but restrict permissions like other state.
            atomic(directory/'pending.json',{'candidate':candidate,'payload':payload,'base_sha256':digest(cfg)})
            result={'state':'blocked' if reason else ('available' if candidate['changes'] else 'current'),'changes':candidate['changes'],'content_sha256':digest(candidate),'reason':reason,'checked_at':time.time(),'next_check':time.time()+86400+random.uniform(0,3600)}
        except Exception:
            result={**previous,'state':'unavailable','checked_at':time.time(),'next_check':time.time()+3600+random.uniform(0,600),'message':'Network settings check unavailable; saved settings retained.'}
        atomic(directory/'status.json',result);return result

def notify(app,home=None,log=print):
    home=Path(home or app)
    try:
        previous=status(home);result=check(app,home)
        marker=(result.get('state'),result.get('content_sha256'))
        if marker!=(previous.get('state'),previous.get('content_sha256')):
            if result['state'] in {'available','blocked'}:
                log('Network settings changed: '+', '.join(result['changes'])+'. '+('Requires a compatible application/artifact release; saved settings retained.' if result['state']=='blocked' else 'Review with network-config.py status; applying is manual.'))
            elif result['state']=='unavailable': log(result['message'])
        return result
    except Exception: return {'state':'unavailable'}

def apply(app,home=None,initial=False,gui=False):
    app=Path(app);home=Path(home or app);directory=home/'.network-updates'
    # Both locks are separate from proof/transfer locks. Running applications
    # retain their lifecycle locks and make explicit application fail closed.
    with (contextlib.nullcontext() if gui or os.environ.get('FILETRUST_CONTAINER')=='1' else locked(app/'.filetrust-updates/run.lock')),locked(home/'.run.lock'),locked(directory/'check.lock'):
        cfg=read(home/'config.json');pending=read(directory/'pending.json')
        if pending['base_sha256']!=digest(cfg): raise ValueError('Settings changed after check; check again')
        candidate=projection(home,cfg,pending['payload'],initial,product(app));policy(app,home,cfg,candidate,pending['payload'],initial)
        if not candidate['changes']: return []
        generation=directory/'generations'/digest(candidate);generation.mkdir(parents=True,exist_ok=True,mode=0o700)
        # Retain auxiliary verifier ABIs used by factory node launchers.
        for key in candidate['targets']:
            source=Path(cfg[key]);source=source if source.is_absolute() else home/source
            if not source.is_file() and not Path(cfg[key]).is_absolute(): source=home/'core'/cfg[key]
            if source.is_file():
                for old in source.parent.glob('*.json'):
                    try: artifact=read(old)
                    except (OSError,ValueError): continue
                    if isinstance(artifact,dict) and isinstance(artifact.get('abi'),list): atomic(generation/old.name,{'abi':artifact['abi']})
        for name,artifact in candidate['abis'].items(): atomic(generation/(name+'.json'),artifact)
        new={**cfg,**candidate['fields']}
        if 'profile' in cfg and (app/'core/network_config_policy.py').is_file():
            atomic(generation/'network-config.json',pending['payload'])
            new['network_config_snapshot']=str((generation/'network-config.json').resolve())
        for key,name in candidate['targets'].items(): new[key]=str((generation/name).resolve())
        owner=(home/'config.json').stat()
        if os.geteuid()==0:
            for p in [directory,*directory.rglob('*')]:
                if not p.is_symlink(): os.chown(p,owner.st_uid,owner.st_gid)
        # Generation files are complete/fsynced before a single config pointer
        # switch. A crash exposes either all old or all new contract files.
        atomic(directory/'rollback.json',{'config':cfg,'activated_sha256':digest(new)})
        atomic(home/'config.json',new)
        atomic(directory/'status.json',{'state':'applied','changes':candidate['changes'],'checked_at':time.time(),'restart_required':True})
        return candidate['changes']

def rollback(app,home=None):
    app=Path(app);home=Path(home or app);directory=home/'.network-updates'
    with locked(app/'.filetrust-updates/run.lock'),locked(home/'.run.lock'),locked(directory/'check.lock'):
        old=read(directory/'rollback.json')
        if digest(read(home/'config.json'))!=old['activated_sha256']: raise ValueError('Settings changed since activation; review before rollback')
        atomic(home/'config.json',old['config']);atomic(directory/'status.json',{'state':'rolled_back','restart_required':True})

def watch(app,home):
    """Persistent notices for the original detached VK fleet launcher."""
    import signal,threading
    app=Path(app);home=Path(home)
    with locked(home/'.network-updates/watcher.lock'):
        from ft_update_bootstrap import enter
        enter(app)
        stop=threading.Event()
        signal.signal(signal.SIGTERM,lambda *_:stop.set())
        signal.signal(signal.SIGINT,lambda *_:stop.set())
        from ft_updates import start_watcher
        start_watcher(app,network_home=home,stop=stop,log=lambda text:print(text,flush=True))
        while not stop.wait(30):
            alive=False
            for proc in Path('/proc').iterdir():
                if not proc.name.isdigit():continue
                try:
                    args=(proc/'cmdline').read_bytes().split(b'\0')
                    if args and Path(os.fsdecode(args[0])).name=='vaultmesh' and (proc/'cwd').resolve().is_relative_to(app):alive=True;break
                except OSError:pass
            if not alive:return


def cli(app,argv=None):
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('command',choices=['check','status','apply','rollback','bootstrap','watch']);p.add_argument('--home',type=Path);a=p.parse_args(argv);home=a.home or Path(app)
    try:
        if a.command=='watch':watch(app,home);return 0
        if a.command=='status': result=status(home)
        elif a.command in {'check','bootstrap'}:
            result=check(app,home,force=True,initial=a.command=='bootstrap')
            if a.command=='bootstrap':
                if result['state'] not in {'available','current'}: raise ValueError('Current network settings could not be validated; retry installation')
                result={'state':'installed','changes':apply(app,home,initial=True)}
        elif a.command=='apply': result={'state':'applied','changes':apply(app,home),'restart_required':True}
        else: rollback(app,home);result=status(home)
        print(json.dumps(result,indent=2));return 1 if result['state'] in {'unavailable','blocked'} else 0
    except Exception as exc:
        print('Network settings operation stopped: '+(str(exc) if isinstance(exc,ValueError) else type(exc).__name__));return 1
