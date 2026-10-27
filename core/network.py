"""HTTPS bootstrap checked against the independently signed artifact release."""
import hashlib
import json
from pathlib import Path
from urllib.parse import urlparse
import requests
from web3 import Web3
from vk_http import session as http_session

CONFIG_URL='https://config.filetrust.io/v1/network-config'
PRICE_URL='https://price.filetrust.io'
SETTINGS=('zk_block_size','zk_tree_depth','storageproof_deadline_count','storageproof_challenge_count','storageproof_partition_max_sectors','storageproof_proof_period_seconds','su_to_wei_rate','fixed_gas_price_wei')
CONTRACTS={'vault_keeper_registry':'VaultKeeperRegistry','acl':'AccessControlFT','file_registration':'FileRegistrationSC','vk_escrow':'VKEscrow','capacity_proof':'CapacityProofSC','capacity_certification':'CapacityCertificationSC','capacity_incremental_batch':'CapacityIncrementalBatchSC','partition_snapshot_proof':'PartitionSnapshotProofSC','storageproof':'StorageProofSC','storage_receipt_dispute':'StorageReceiptDispute','deletion_release':'DeletionReleaseSC'}

def https(url):
    p=urlparse(url)
    if p.scheme!='https' or not p.hostname or p.username or p.password:raise ValueError('Use an HTTPS endpoint without embedded credentials')
    return url

def fetch(url):
    with http_session() as client, client.get(https(url),headers={'User-Agent':'FileTrust-Vaultkeeper/1'},timeout=(15,30),stream=True,allow_redirects=False) as r:
        r.raise_for_status()
        if r.status_code!=200:raise ValueError('Bootstrap redirects are not accepted')
        data=bytearray()
        for chunk in r.iter_content(65536):
            data.extend(chunk)
            if len(data)>16*1024*1024:raise ValueError('Bootstrap response too large')
        return json.loads(data)

def abi_hash(abi):return hashlib.sha256(json.dumps(abi,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def config_from_payload(payload,profile,rpc=None):
    deployed=payload['deployed_addresses']; app=deployed['appConfig']; params=profile['params']
    if int(app['zk_block_size'])!=profile['block_size'] or int(app['zk_tree_depth'])!=params['zk_tree_depth']:raise ValueError('Selected profile does not match the deployed network; choose its approved profile')
    cfg={key:app[key] for key in ('storageproof_deadline_count','storageproof_challenge_count','storageproof_partition_max_sectors','storageproof_proof_period_seconds','zk_block_size','zk_tree_depth')}
    if int(cfg['storageproof_challenge_count'])!=4 or int(cfg['storageproof_partition_max_sectors'])!=16 or int(cfg['storageproof_deadline_count'])<=0:raise ValueError('Unsupported network proof dimensions')
    cfg.update(rpc_url=https(rpc or payload['network']['rpc_url']),chain_id=int(deployed['chainId']),price_url=PRICE_URL,
               discovery_urls=[https(url) for url in payload['network'].get('discovery_urls',[])],profile=profile['id'])
    for prefix,name in CONTRACTS.items():
        address=app.get(prefix+'_address') or deployed['contracts'].get(name)
        if not Web3.is_address(address or ''):raise ValueError('Missing deployed contract: '+name)
        cfg[prefix+'_address']=Web3.to_checksum_address(address)
    cfg['su_to_wei_rate']=int(deployed['economics']['suToWeiRate'])
    cfg['fixed_gas_price_wei']=int(deployed['economics']['fixedGasPriceWei'])
    return cfg

def check_network(w3,cfg,manifest,payload):
    binding=manifest['networks'].get(str(w3.eth.chain_id))
    if not binding or int(cfg['chain_id'])!=int(w3.eth.chain_id):raise ValueError('Chain is not approved by this signed artifact release')
    approved=binding['profiles'].get(cfg['profile'])
    if not approved or approved['zk_block_size']!=int(cfg['zk_block_size']) or approved['zk_tree_depth']!=int(cfg['zk_tree_depth']):raise ValueError('Proof profile is not approved for this chain')
    if set(binding.get('settings',{}))!=set(SETTINGS) or any(int(cfg[key])!=int(binding['settings'][key]) for key in SETTINGS):raise ValueError('Network proof or fee settings differ from the signed release')
    artifacts=payload['artifact_files']
    for name,row in binding['contracts'].items():
        if name in CONTRACTS.values():
            prefix=next(key for key,value in CONTRACTS.items() if value==name)
            if cfg.get(prefix+'_address','').lower()!=row['address'].lower():raise ValueError('Contract address mismatch: '+name)
        code=bytes(w3.eth.get_code(row['address']))
        if not code or hashlib.sha256(code).hexdigest()!=row['code_sha256']:raise ValueError('Contract runtime mismatch: '+name)
        if 'abi_sha256' in row and abi_hash(artifacts[name+'.json']['abi'])!=row['abi_sha256']:raise ValueError('Contract ABI mismatch: '+name)
    for edge in binding['wiring']:
        owner=binding['contracts'][edge['from']]['address']; target=binding['contracts'][edge['to']]['address']
        raw=bytes(w3.eth.call({'to':owner,'data':Web3.keccak(text=edge['getter']+'()')[:4]}))
        if len(raw)!=32 or Web3.to_checksum_address(raw[-20:]).lower()!=target.lower():raise ValueError('Contract wiring mismatch: '+edge['getter'])
    return binding

def write_abis(payload,directory):
    directory.mkdir(parents=True,exist_ok=True)
    for name in CONTRACTS.values():
        abi=payload['artifact_files'][name+'.json']['abi']
        (directory/(name+'.json')).write_text(json.dumps({'abi':abi}))


def verify_local_abis(cfg,binding):
    """Verify the ABI files actually passed to workers, not only the bootstrap copy."""
    for prefix,name in CONTRACTS.items():
        path=Path(cfg[prefix+'_json'])
        if path.is_symlink() or not path.is_file() or path.stat().st_size>16*1024*1024:
            raise ValueError('Missing or unsafe contract description file: '+prefix+'_json')
        try:abi=json.loads(path.read_text())['abi']
        except (OSError,ValueError,KeyError,TypeError):
            raise ValueError('Invalid contract description file: '+prefix+'_json') from None
        expected=binding['contracts'].get(name,{}).get('abi_sha256')
        if not expected or abi_hash(abi)!=expected:
            raise ValueError('Local contract ABI differs from signed deployment: '+prefix+'_json')
