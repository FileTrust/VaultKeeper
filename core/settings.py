"""Explicit operator settings and their native runtime destinations.

Network-controlled values remain in the signed deployment binding. Identity,
program paths and setup-generation commands are not operator tuning options.
"""
from copy import deepcopy

# (default, native flag). These settings apply to both cooperating workers.
COMMON = {
    'capacity_slot_size_bytes': (0, 'capacity-slot-size-bytes'),
    'admission_margin_bytes': (100 * 1024 * 1024, 'admission-margin-bytes'),
    'sync_admission_to_registry': (True, 'sync-admission-to-registry'),
    'capacity_proof_debounce_seconds': (1800, 'capacity-proof-debounce-seconds'),
    'capacity_proof_max_batch_seconds': (1800, 'capacity-proof-max-batch-seconds'),
    'capacity_proof_max_pending_mutations': (64, 'capacity-proof-max-pending-mutations'),
    'capacity_proof_max_pending_bytes': (1073741824, 'capacity-proof-max-pending-bytes'),
    'capacity_proof_max_divergence_bytes': (536870912, 'capacity-proof-max-divergence-bytes'),
    'capacity_proof_max_touched_partitions': (16, 'capacity-proof-max-touched-partitions'),
    'capacity_proof_max_oldest_mutation_seconds': (1800, 'capacity-proof-max-oldest-mutation-seconds'),
    'capacity_proof_max_queue_depth': (8, 'capacity-proof-max-queue-depth'),
    'capacity_proof_max_consecutive_failed_epochs': (3, 'capacity-proof-max-consecutive-failed-epochs'),
    'capacity_proof_submission_safety_seconds': (120, 'capacity-proof-submission-safety-seconds'),
    'proof_background_min_workers': (1, 'proof-background-min-workers'),
    'proof_background_max_workers': (0, 'proof-background-max-workers'),
    'proof_background_busy_cpu_percent': (20, 'proof-background-busy-cpu-percent'),
    'proof_deadline_conservative_bound_seconds': (1800, 'proof-deadline-conservative-bound-seconds'),
    'storageproof_chain_command_timeout_seconds': (180, 'chain-command-timeout-seconds'),
    'log_max_mb': (50, 'log-max-mb'),
    'log_keep_days': (14, 'log-keep-days'),
    'log_max_total_mb': (1000, 'log-max-total-mb'),
}
SERVER = {
    'quote_reservation_quantum_bytes': (65536, 'quote-reservation-quantum-bytes'),
    'max_outstanding_quote_reservations': (64, 'max-outstanding-quote-reservations'),
    'max_outstanding_quotes_per_identity': (4, 'max-outstanding-quotes-per-identity'),
    'max_open_quotes_per_file': (2, 'max-open-quotes-per-file'),
    'max_unused_quotes_per_file': (3, 'max-unused-quotes-per-file'),
    'unused_quote_window_seconds': (86400, 'unused-quote-window-seconds'),
    'quote_hold_gas': (400000, 'quote-hold-gas'),
    'quote_reservation_reconcile_seconds': (15, 'quote-reservation-reconcile-seconds'),
    'quote_transfer_min_bytes_per_second': (65536, 'quote-transfer-min-bytes-per-second'),
    'quote_transfer_recovery_grace_seconds': (600, 'quote-transfer-recovery-grace-seconds'),
    'filesystem_reserve_bytes': (0, 'filesystem-reserve-bytes'),
    'public_addr_check_seconds': (300, 'public-addr-check-seconds'),
    'public_addr_full_check_seconds': (3600, 'public-addr-full-check-seconds'),
    'public_addr_min_change_seconds': (600, 'public-addr-min-change-seconds'),
    'public_addr_helpers': (3, 'public-addr-helpers'),
    'public_addr_port_mapping': (True, 'public-addr-port-mapping'),
    'reach_helper': (True, 'reach-helper'),
    'piece_block_size': (65536, 'piece-block-size'),
    'max_piece_size_bytes': (2 * 1024**3, 'max-piece-size-bytes'),
    'max_concurrent_uploads': (4, 'max-concurrent-uploads'),
    'max_concurrent_downloads': (8, 'max-concurrent-downloads'),
    'max_queued_transfers': (32, 'max-queued-transfers'),
    'max_transfers_per_peer': (4, 'max-transfers-per-peer'),
    'max_temporary_upload_bytes': (0, 'max-temporary-upload-bytes'),
    'transfer_queue_wait_seconds': (2, 'transfer-queue-wait-seconds'),
    'transfer_retry_after_seconds': (5, 'transfer-retry-after-seconds'),
    'partial_upload_ttl_seconds': (86400, 'partial-upload-ttl-seconds'),
    'completed_transfer_ttl_seconds': (604800, 'completed-transfer-ttl-seconds'),
    'sector_max_pieces': (1024, 'sector-max-pieces'),
    'sector_lifetime_days': (30, 'sector-lifetime-days'),
    'allow_sector_extend': (True, 'allow-sector-extend'),
    'sector_max_expiration_extension_seconds': (604800, 'sector-max-expiration-extension'),
    'sector_allow_large_expiration_mixing': (False, 'sector-allow-large-mixing'),
    'max_service_days': (0, 'max-service-days'),
    'discovery_ttl_seconds': (28800, 'discovery-ttl-seconds'),
    'discovery_heartbeat_seconds': (7200, 'discovery-heartbeat-seconds'),
}
PROOF = {'storageproof_proof_poll_seconds': (60, 'proof-poll-seconds')}
# Wrapper and supervisor settings are handled separately from native flags.
OTHER = {
    'discovery_enabled': True,
    'storageproof_persistent_prover_enabled': True,
    'storageproof_persistent_prover_start_timeout_seconds': 900,
    'storageproof_persistent_prover_request_timeout_seconds': 900,
    'storageproof_prover_nice': 10,
    'storageproof_prover_io_priority': 'low',
    'storageproof_staleness_threshold_rounds': 2,
    'log_eth_calls': False,
    'storageproof_confirmations': 1,
    'startup_timeout_sec': 0,
}
DEFAULTS = {**{key: row[0] for group in (COMMON, SERVER, PROOF) for key, row in group.items()}, **OTHER}
ALIASES = {'proof_poll_seconds': 'storageproof_proof_poll_seconds', 'capacity_bytes': 'storage_capacity_bytes'}
DEPLOYMENT_FIELDS = {
    'rpc_url', 'chain_id', 'price_url', 'discovery_urls', 'profile', 'profile_path',
    'zk_block_size', 'zk_tree_depth', 'storageproof_deadline_count',
    'storageproof_challenge_count', 'storageproof_partition_max_sectors',
    'storageproof_proof_period_seconds', 'su_to_wei_rate', 'fixed_gas_price_wei',
    'address', 'storage_path', 'storage_capacity_bytes', 'port', 'advertise_ip',
    'storage_fee', 'stake_wei', 'network_config_url', 'network_config_snapshot', 'network_config_manage_discovery', 'download_profiles',
    'transaction_log_path',
    'vault_keeper_registry_json','acl_json','file_registration_json','vk_escrow_json',
    'capacity_proof_json','capacity_certification_json','capacity_incremental_batch_json',
    'partition_snapshot_proof_json','storageproof_json','storage_receipt_dispute_json','deletion_release_json',
} | {name + '_address' for name in (
    'vault_keeper_registry', 'acl', 'file_registration', 'vk_escrow',
    'capacity_proof', 'capacity_certification', 'capacity_incremental_batch',
    'partition_snapshot_proof', 'storageproof', 'storage_receipt_dispute', 'deletion_release',
)}
POSITIVE = {
    'piece_block_size', 'max_concurrent_uploads', 'max_concurrent_downloads',
    'max_transfers_per_peer', 'sector_max_pieces', 'sector_lifetime_days',
    'storageproof_proof_poll_seconds', 'storageproof_chain_command_timeout_seconds',
    'storageproof_persistent_prover_start_timeout_seconds',
    'storageproof_persistent_prover_request_timeout_seconds',
    'proof_deadline_conservative_bound_seconds', 'log_max_mb', 'log_keep_days',
    'storageproof_confirmations', 'storageproof_staleness_threshold_rounds',
    'log_max_total_mb', 'discovery_ttl_seconds', 'discovery_heartbeat_seconds',
}


def complete(config):
    """Fill missing visible settings, preserving existing values and old names."""
    result = dict(config)
    for name,value in result.items():
        if name.startswith('## ') and not isinstance(value,str):
            raise ValueError('Configuration help must be text: '+name)
    for old, new in ALIASES.items():
        if old in result:
            if new in result and result[new] != result[old]:
                raise ValueError('Conflicting configuration fields: ' + old + ' and ' + new)
            result[new] = result.pop(old)
    unknown = {name for name in result if not name.startswith('## ')} - set(DEFAULTS) - DEPLOYMENT_FIELDS
    if unknown:
        raise ValueError('Unsupported configuration fields: ' + ', '.join(sorted(unknown)))
    result = {**deepcopy(DEFAULTS), **result}
    for name, default in DEFAULTS.items():
        value = result[name]
        if type(value) is not type(default):
            raise ValueError('Invalid configuration type: ' + name)
        if type(default) is int and not (0 <= value <= 2**63 - 1):
            raise ValueError('Invalid configuration range: ' + name)
        if name in POSITIVE and value == 0:
            raise ValueError('Configuration must be positive: ' + name)
    if not 1 <= result['proof_background_busy_cpu_percent'] <= 100:
        raise ValueError('proof_background_busy_cpu_percent must be between 1 and 100')
    if not 0 <= result['storageproof_prover_nice'] <= 19:
        raise ValueError('storageproof_prover_nice must be between 0 and 19')
    if result['storageproof_prover_io_priority'] not in {'low', 'normal'}:
        raise ValueError('storageproof_prover_io_priority must be low or normal')
    if (result['proof_background_max_workers'] and
            result['proof_background_max_workers'] < result['proof_background_min_workers']):
        raise ValueError('Maximum proof workers cannot be less than minimum proof workers')
    if result['discovery_enabled'] and result['discovery_heartbeat_seconds'] >= result['discovery_ttl_seconds']:
        raise ValueError('Discovery heartbeat must be shorter than record lifetime')
    if 'storage_capacity_bytes' in result and (type(result['storage_capacity_bytes']) is not int or not 0 < result['storage_capacity_bytes'] <= 2**63-1):
        raise ValueError('storage_capacity_bytes must be a positive integer number of bytes')
    return result


def flags(config, group):
    result = []
    for name, (_, flag) in group.items():
        value = config[name]
        if type(value) is bool:
            result.append('--' + flag + '=' + str(value).lower())
        else:
            result.extend(['--' + flag, str(value)])
    return result
