"""Ordinary escrow claims using the node's existing protected wallet and ABI."""
import argparse
import json
from pathlib import Path

from web3 import Web3
from vault import load_wallet, private_file
from vk_chain import ResilientReadHTTPProvider, _sp_send_tx
from escrow_evidence import claim_call, find_historical_manifest


def claim_credentials(w3, account, escrow, credentials, context):
    secrets = [Web3.to_bytes(hexstr=credentials[name]) for name in
               ('nullifier', 'secret', 'regNullifier', 'regSecret', 'linkNonce')]
    if any(len(word) != 32 for word in secrets):
        raise ValueError('Escrow secrets must be bytes32')
    manifest = credentials.get('historicalManifest')
    if manifest is None:
        manifest = find_historical_manifest(w3, escrow, secrets, context.get('storage', ''), context.get('file_registration_json'))
    call = claim_call(escrow, secrets, manifest)
    # Existing sender locking, pending nonce, gas estimation, receipt and revert
    # handling are shared with the node's normal transaction path.
    return _sp_send_tx(w3, account, call, context=context)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--home', type=Path, default=Path('/var/lib/filetrust-vaultkeeper'))
    p.add_argument('--key-file', type=Path, default=Path('/etc/filetrust-vaultkeeper/unlock.key'))
    p.add_argument('credential', type=Path)
    a = p.parse_args(argv)
    cfg = json.loads((a.home / 'config.json').read_text())
    storage = Path(cfg['storage_path']).resolve()
    credential = a.credential.resolve()
    if not credential.is_relative_to(storage / 'payment'):
        raise ValueError('Select credentials from this node storage/payment directory')
    wallet = load_wallet(a.home / 'wallet.json', a.key_file)
    w3 = Web3(ResilientReadHTTPProvider(cfg['rpc_url']))
    account = w3.eth.account.from_key(wallet['private_key'])
    wallet.clear()
    if account.address.lower() != cfg['address'].lower():
        raise ValueError('Wallet address mismatch')
    if int(w3.eth.chain_id) != int(cfg['chain_id']):
        raise ValueError('Network chain ID mismatch')
    artifact = json.loads(Path(cfg['vk_escrow_json']).read_text())
    escrow = w3.eth.contract(address=Web3.to_checksum_address(cfg['vk_escrow_address']),
                            abi=artifact if isinstance(artifact, list) else artifact['abi'])
    context = {**cfg, 'storage': str(storage),
               'filetrust_fixed_gas_price_wei': cfg['fixed_gas_price_wei']}
    tx = claim_credentials(w3, account, escrow,
                           json.loads(private_file(credential)), context)
    print(json.dumps({'ok': True, 'transaction': tx}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


def start_claim_worker(cfg, environment, stop, log):
    """Retry ordinary matured claims while the existing node owns its unlocked key.

    Uses the same protected credentials and transaction sender as the manual
    command. Proof scheduling remains in the native worker. Errors never grant
    entitlement or mark a payment successful locally.
    """
    import threading
    signing_file = environment.get('VK_PRIVATE_KEY_FILE')
    if not signing_file or not cfg.get('vk_escrow_address'):
        return None
    w3 = Web3(ResilientReadHTTPProvider(cfg['rpc_url']))
    account = w3.eth.account.from_key(private_file(Path(signing_file)).decode('ascii').strip())
    if account.address.lower() != cfg['address'].lower():
        raise ValueError('Claim worker wallet address mismatch')
    try:
        initial_chain_id = int(w3.eth.chain_id)
    except Exception:
        initial_chain_id = None  # RPC interruption must not stop the storage workers.
    if initial_chain_id is not None and initial_chain_id != int(cfg['chain_id']):
        raise ValueError('Claim worker network chain ID mismatch')
    artifact = json.loads(Path(cfg['vk_escrow_json']).read_text())
    escrow = w3.eth.contract(address=Web3.to_checksum_address(cfg['vk_escrow_address']),
        abi=artifact if isinstance(artifact,list) else artifact['abi'])
    context = {**cfg, 'storage': cfg['storage_path'],
        'filetrust_fixed_gas_price_wei': cfg['fixed_gas_price_wei']}
    def loop():
        while not stop.is_set():
            try:
                if int(w3.eth.chain_id) != int(cfg['chain_id']):
                    raise ValueError('Claim worker network chain ID mismatch')
            except Exception as error:
                log('Escrow network check deferred; will retry ('+type(error).__name__+')')
                stop.wait(max(1,int(cfg.get('storageproof_proof_poll_seconds',60))))
                continue
            for path in sorted((Path(cfg['storage_path'])/'payment').glob('*.json')):
                if stop.is_set():break
                try:
                    credentials = json.loads(private_file(path))
                    if not credentials.get('nullifier') or not credentials.get('secret'):continue
                    if int(escrow.functions.claimableAmount(
                            Web3.to_bytes(hexstr=credentials['nullifier']),
                            Web3.to_bytes(hexstr=credentials['secret'])).call()) <= 0:continue
                    tx = claim_credentials(w3,account,escrow,credentials,context)
                    log('Escrow payment accepted: '+str(tx))
                except Exception as error:
                    # No secrets, calldata or signer material in this operational message.
                    log('Escrow claim deferred; will retry ('+type(error).__name__+')')
            stop.wait(max(1,int(cfg.get('storageproof_proof_poll_seconds',60))))
    thread=threading.Thread(target=loop,name='escrow-claims',daemon=True)
    thread.start()
    return thread
