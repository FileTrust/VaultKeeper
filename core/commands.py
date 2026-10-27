"""One-node commands; never invoke compiler, setup, fleet or cleanup tools."""
from pathlib import Path
import os,shlex,sys
from settings import flags, COMMON, SERVER, PROOF

def build_commands(cfg,state,runtime,run_dir):
    from config_layout import organized
    cfg=organized(cfg,state)
    state=Path(state);runtime=Path(runtime);run_dir=Path(run_dir)
    binary=str(runtime/'vaultmesh');contracts=state/'contracts';storage=str(Path(cfg['storage_path']))
    tx_log=Path(cfg.get('transaction_log_path') or state/'logs/transactions.jsonl').resolve()
    if not tx_log.is_relative_to(state.resolve()):raise ValueError('transaction_log_path must stay inside the node state directory')
    helper=shlex.join([sys.executable,str(Path(__file__).resolve().parent/'vk_chain.py')])
    wrapper=shlex.quote(str(runtime/'partition_prover_wrapper.sh'))
    common=[binary,'--storage',storage,'--rpc-url',cfg['rpc_url'],'--chain-id',str(cfg['chain_id']),
            '--vk-private-key-file',str(run_dir/'signing.key'),'--zk-block-size',str(cfg['zk_block_size']),
            '--zk-tree-depth',str(cfg['zk_tree_depth']),'--capacity-bytes',str(cfg['storage_capacity_bytes']),
            '--storage-proof-contract',cfg['storageproof_address'],'--capacity-proof-contract',cfg['capacity_proof_address'],
            '--file-registration-contract',cfg['file_registration_address'],'--deletion-release-contract',cfg['deletion_release_address'],
            '--vk-registry-contract',cfg['vault_keeper_registry_address'],'--vk-registry-abi',str(cfg['vault_keeper_registry_json']),
            '--transaction-log-path',str(tx_log),'--fixed-gas-price-wei',str(cfg['fixed_gas_price_wei']),'--chain-proof-cmd',helper,'--resume-capacity',
            '--deadline-count',str(cfg['storageproof_deadline_count']),'--partition-max-sectors',str(cfg.get('storageproof_partition_max_sectors',16)),
            '--challenge-count',str(cfg.get('storageproof_challenge_count',4)),
            '--proof-period-seconds',str(cfg['storageproof_proof_period_seconds']),
            '--partition-prover-cmd',wrapper,'--zk-prover-cmd',shlex.quote(str(runtime/'prover_wrapper.sh')),
            '--deterministic-challenge',*flags(cfg,COMMON)]
    server=[*common,'--mode','server','--listen',f'/ip4/0.0.0.0/tcp/{cfg["port"]}',
            '--acl-address',cfg['acl_address'],'--vk-escrow-contract',cfg['vk_escrow_address'],
            '--advertise-ip',cfg.get('advertise_ip','auto'),'--storage-fee',str(cfg['storage_fee']),
            '--su-to-wei-rate',str(cfg['su_to_wei_rate']),'--stake-wei',str(cfg.get('stake_wei',0)),*flags(cfg,SERVER)]
    if cfg['discovery_enabled'] and cfg.get('discovery_urls'):server+=['--discovery',','.join(cfg['discovery_urls'])]
    proof=[*common,'--mode','proof-daemon',*flags(cfg,PROOF)]
    environment={key:value for key,value in os.environ.items() if key not in {'GH_TOKEN','GITHUB_TOKEN','VK_PRIVATE_KEY','PRIVATE_KEY'}}
    environment.update(FILETRUST_VK_IDENTITY_KEY_FILE=str(run_dir/'peer.key'),VK_PRIVATE_KEY_FILE=str(run_dir/'signing.key'),
                       FILETRUST_ZK_PARTITION_PROFILE=cfg['profile'],FILETRUST_ZK_PROFILE=cfg['profile'],
                       FILETRUST_ZK_PARTITION_KEYS_DIR=str(cfg['profile_path']),FILETRUST_ZK_PROVER_RUN_DIR=str(run_dir/'prover'),
                       FILETRUST_ZK_PROVER_DEBUG_DIR=str(run_dir/'prover/debug'),
                       FILETRUST_ZK_PARTITION_PROVER_SOCKET=str(run_dir/'prover.sock'),
                       FILETRUST_ZK_PARTITION_PROVER_LOG=str(state/'logs/prover.log'),FILETRUST_ZK_CONFIG=str(state/'config.json'),
                       FILETRUST_ZK_PERSISTENT_PROVER_ENABLED='1' if cfg['storageproof_persistent_prover_enabled'] else '0',
                       FILETRUST_ZK_PERSISTENT_START_TIMEOUT_SECONDS=str(cfg['storageproof_persistent_prover_start_timeout_seconds']),
                       FILETRUST_ZK_PERSISTENT_REQUEST_TIMEOUT_SECONDS=str(cfg['storageproof_persistent_prover_request_timeout_seconds']),
                       FILETRUST_ZK_PROVER_NICE=str(cfg['storageproof_prover_nice']),
                       FILETRUST_ZK_PROVER_IO_PRIORITY=cfg['storageproof_prover_io_priority'],
                       STORAGEPROOF_CONFIRMATIONS=str(cfg['storageproof_confirmations']),LOG_ETH_CALLS=str(cfg['log_eth_calls']).lower(),
                       STORAGEPROOF_CONFIG=str(state/'config.json'),VK_CONFIG=str(state/'config.json'),
                       TRANSACTION_LOG_PATH=str(tx_log),RPC_URL=cfg['rpc_url'],STORAGEPROOF_ADDRESS=cfg['storageproof_address'],
                       STORAGEPROOF_JSON=str(cfg['storageproof_json']),VK_ADDRESS=cfg['address'],
                       CAPACITY_PROOF_ADDRESS=cfg['capacity_proof_address'],CAPACITY_PROOF_JSON=str(cfg['capacity_proof_json']),
                       PARTITION_SNAPSHOT_PROOF_ADDRESS=cfg['partition_snapshot_proof_address'],PARTITION_SNAPSHOT_PROOF_JSON=str(cfg['partition_snapshot_proof_json']),
                       FILETRUST_PROOF_HOST_LOCK_PATH=str(state/'.proof-work.lock'),FILETRUST_PROOF_JOB_VK_IDENTITY=cfg['address'])
    environment.update(STORAGE_RECEIPT_DISPUTE_ADDRESS=cfg['storage_receipt_dispute_address'],STORAGE_RECEIPT_DISPUTE_JSON=str(cfg['storage_receipt_dispute_json']))
    return server,proof,environment
