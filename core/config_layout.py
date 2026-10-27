"""Human-readable JSON sections, matching the DO/REQ configuration convention."""
from pathlib import Path
from settings import complete
from network import CONTRACTS

SECTIONS = [
    ('HOW TO USE THIS FILE', 'Stop the service before editing. Sizes ending in _bytes are bytes; 1 GiB is 1073741824 bytes. Sections marked DO NOT CHANGE must match the network.', []),
    ('NODE IDENTITY  DO NOT CHANGE', 'The public wallet address must match the encrypted wallet. Private keys are stored separately, not in this config.', ['address']),
    ('STORAGE ALLOCATION', 'storage_capacity_bytes is the capacity this node provides. Set during installation; keep extra disk space for proofs, downloads and logs. Changing this value does not move or delete stored data.', ['storage_capacity_bytes','storage_path','capacity_slot_size_bytes','admission_margin_bytes','sync_admission_to_registry','filesystem_reserve_bytes']),
    ('NETWORK AND DISCOVERY', 'RPC and network configuration endpoints, public TCP port and discovery services. Automatic address discovery checks public reachability.', ['rpc_url','network_config_url','price_url','port','advertise_ip','discovery_enabled','discovery_urls','discovery_ttl_seconds','discovery_heartbeat_seconds','public_addr_check_seconds','public_addr_full_check_seconds','public_addr_min_change_seconds','public_addr_helpers','public_addr_port_mapping','reach_helper']),
    ('STORAGE FEES AND STAKE', 'storage_fee is SU per GB per day. stake_wei is the registration stake in wei. Review network requirements before registration.', ['storage_fee','stake_wei','max_service_days']),
    ('TRANSFER LIMITS', 'Upload/download concurrency, queue limits and partial-upload retention. Defaults limit resource use; raise only with sufficient resources.', ['piece_block_size','max_piece_size_bytes','max_concurrent_uploads','max_concurrent_downloads','max_queued_transfers','max_transfers_per_peer','max_temporary_upload_bytes','transfer_queue_wait_seconds','transfer_retry_after_seconds','partial_upload_ttl_seconds','completed_transfer_ttl_seconds']),
    ('QUOTE LIMITS', 'Limits and timing for reserved capacity and transfer quotes.', ['quote_reservation_quantum_bytes','max_outstanding_quote_reservations','max_outstanding_quotes_per_identity','max_open_quotes_per_file','max_unused_quotes_per_file','unused_quote_window_seconds','quote_hold_gas','quote_reservation_reconcile_seconds','quote_transfer_min_bytes_per_second','quote_transfer_recovery_grace_seconds']),
    ('SECTOR POLICY', 'Local sector packing, lifetime and expiration extension policy.', ['sector_max_pieces','sector_lifetime_days','allow_sector_extend','sector_max_expiration_extension_seconds','sector_allow_large_expiration_mixing']),
    ('CAPACITY PROOF SCHEDULING', 'Batch timing and pending-mutation thresholds. These tune scheduling, not the network proof requirements.', []),
    ('PROOF WORKERS AND TIMEOUTS', 'Worker maximum 0 uses available CPUs. startup_timeout_sec 0 waits for server startup without a fixed cutoff. Native capacity progress reports readiness to accept pieces separately. Prover nice is 0–19; I/O priority is low or normal.', ['proof_background_min_workers','proof_background_max_workers','proof_background_busy_cpu_percent','proof_deadline_conservative_bound_seconds','storageproof_proof_poll_seconds','storageproof_chain_command_timeout_seconds','storageproof_staleness_threshold_rounds','storageproof_confirmations','storageproof_persistent_prover_enabled','storageproof_persistent_prover_start_timeout_seconds','storageproof_persistent_prover_request_timeout_seconds','storageproof_prover_nice','storageproof_prover_io_priority','startup_timeout_sec']),
    ('LOG FILES', 'Log rotation limits. log_eth_calls enables detailed chain-read logging and may produce large logs. transaction_log_path must stay inside the node state directory.', ['transaction_log_path','log_max_mb','log_keep_days','log_max_total_mb','log_eth_calls']),
    ('NETWORK PROOF PARAMETERS  DO NOT CHANGE', 'These values come from the approved signed deployment and proof bundles. Changing them arbitrarily stops startup.', ['chain_id','profile','zk_block_size','zk_tree_depth','storageproof_deadline_count','storageproof_challenge_count','storageproof_partition_max_sectors','storageproof_proof_period_seconds','download_profiles','su_to_wei_rate','fixed_gas_price_wei']),
    ('CONTRACT ADDRESSES  DO NOT CHANGE', 'Active contract addresses must match the approved signed network deployment.', [prefix+'_address' for prefix in CONTRACTS]),
    ('CONTRACT DESCRIPTION FILES  DO NOT CHANGE', 'Paths to contract ABI JSON files. The node reads these files and checks their ABIs against the signed deployment.', [prefix+'_json' for prefix in CONTRACTS]),
]


def organized(config, state):
    cfg = complete(config)
    for prefix,name in CONTRACTS.items():
        key=prefix+'_json'
        cfg.setdefault(key, str(Path(state).resolve()/'contracts'/(name+'.json')))
        if not isinstance(cfg[key],str) or not cfg[key]:raise ValueError('Contract JSON path must be nonempty text: '+key)
        if not Path(cfg[key]).is_absolute():cfg[key]=str(Path(state).resolve()/cfg[key])
    cfg.setdefault('transaction_log_path',str(Path(state).resolve()/'logs/transactions.jsonl'))
    result={}
    for title,help_text,names in SECTIONS:
        names=list(names)
        if title=='CAPACITY PROOF SCHEDULING':
            names=[name for name in cfg if name.startswith('capacity_proof_') and not name.endswith(('_address','_json'))]
        result['## '+title]=help_text
        for name in names:
            if name in cfg:result[name]=cfg.pop(name)
    # Preserve additional user help and any future recognized fields.
    for name,value in cfg.items():
        if name not in result:result[name]=value
    return result
