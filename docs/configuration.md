# Vaultkeeper configuration

The installed configuration is `/var/lib/filetrust-vaultkeeper/config.json`.
Stop the service before editing it. Configuration changes take effect on the
next start. Keep the existing wallet and unlock credential unchanged.

New installations write all operator settings explicitly, grouped by `##` section
headings with explanatory text, following DO/REQ. Capacity is requested during
first installation unless `--capacity`, `--capacity-gib` or `--storage-capacity-bytes` is supplied. Units and fractional GiB values are accepted.

The `CONTRACT ADDRESSES` section contains each active contract address. The
`CONTRACT DESCRIPTION FILES` section contains its corresponding `*_json` path.
These paths are actually used by workers/helpers, and local ABI contents are
checked against the signed deployment before the node starts. Relative ABI paths
are interpreted relative to the node state directory.

New installations write all operator settings explicitly. To expand an older,
shorter configuration after installing this code version:

```sh
sudo systemctl stop filetrust-vaultkeeper
sudo python3 /opt/filetrust-vaultkeeper/manage.py configure
sudo nano /var/lib/filetrust-vaultkeeper/config.json
```

Expansion preserves existing values, ownership, node identity and storage. It
neither creates a wallet nor unlocks one. It refuses to run while a node is active.
`config.defaults.json` lists the tuning defaults; it is not a replacement for the
installed config, which also contains the node and network-specific values.
Unknown fields and invalid types are rejected instead of silently ignored.

## Node and network values

`storage_capacity_bytes`, `storage_path`, `port`, `advertise_ip`, `storage_fee` and
`stake_wei` identify the local storage allocation, endpoint and financial policy.
Changing declared capacity or relocating storage on an established node requires
planning for existing network duties; editing JSON does not move stored pieces.
`transaction_log_path` must stay inside the node state directory.

`rpc_url`, `network_config_url`, `discovery_urls` and `price_url` describe network
services. The native node uses RPC and discovery; price_url records the price
service and does not change on-chain fee conversion.

Chain ID, proof dimensions, proof period, contract addresses and fee conversion
remain visible but must match the approved signed deployment. A mismatch stops
startup. `address` must match the encrypted wallet. Native program locations,
proof-file paths and ABI paths are managed by the installation. Setup generation,
forced capacity rebuilds and secret keys are not configurable command arguments.

## Tuning defaults

Boolean values must be JSON `true` or `false`; numeric settings require integers.
Worker maximum 0 uses available CPUs. Capacity slot size 0 uses automatic slots.
Native capacity-batch thresholds of 0 select their built-in fallback values.
Some native limits similarly interpret 0 as automatic/unlimited: retain the
provided defaults unless the corresponding behavior is intended.

### Shared worker settings

| Setting | Default | Meaning |
|---|---|---|
| `capacity_slot_size_bytes` | `0` | maximum bytes per stable capacity slot/sector (0 = automatic bounded rolling slots) |
| `admission_margin_bytes` | `104857600` | bytes subtracted from fresh certified free capacity after live reservations (0 = 100 MiB) |
| `sync_admission_to_registry` | `true` | publish admission open/closed status to VaultKeeperRegistry |
| `capacity_proof_debounce_seconds` | `1800` | quiet/idle delay before opportunistically closing a capacity batch |
| `capacity_proof_max_batch_seconds` | `1800` | maximum continuous capacity batch window |
| `capacity_proof_max_pending_mutations` | `64` | pending mutation count service objective |
| `capacity_proof_max_pending_bytes` | `1073741824` | pending changed-byte service objective |
| `capacity_proof_max_divergence_bytes` | `536870912` | maximum live-versus-proved capacity divergence |
| `capacity_proof_max_touched_partitions` | `16` | touched partition threshold for closing a batch |
| `capacity_proof_max_oldest_mutation_seconds` | `1800` | maximum age of the oldest unproved mutation |
| `capacity_proof_max_queue_depth` | `8` | proof queue depth that forces capacity batch closure |
| `capacity_proof_max_consecutive_failed_epochs` | `3` | failed epoch service objective |
| `capacity_proof_submission_safety_seconds` | `120` | reserved chain submission/confirmation time in freshness calculations |
| `proof_background_min_workers` | `1` | minimum background proof/cache workers while foreground traffic is active |
| `proof_background_max_workers` | `0` | maximum background proof/cache workers while idle (0 = available CPUs) |
| `proof_background_busy_cpu_percent` | `20` | average CPU share per background worker while foreground traffic is active |
| `proof_deadline_conservative_bound_seconds` | `1800` | cold bound assumed for one protected storage-deadline proof before measured history calibrates it down |
| `storageproof_chain_command_timeout_seconds` | `180` | maximum seconds for one StorageProof chain helper call |
| `log_max_mb` | `50` | rotate a log once it reaches this size |
| `log_keep_days` | `14` | delete gzipped logs older than this |
| `log_max_total_mb` | `1000` | cap the whole log folder at this size |

### Storage server settings

| Setting | Default | Meaning |
|---|---|---|
| `quote_reservation_quantum_bytes` | `65536` | privacy-preserving byte quantum for authoritative quote capacity reservations |
| `max_outstanding_quote_reservations` | `64` | maximum globally outstanding durable quote reservations |
| `max_outstanding_quotes_per_identity` | `4` | maximum outstanding durable quotes per remote identity |
| `max_open_quotes_per_file` | `2` | maximum outstanding durable quotes for one file |
| `max_unused_quotes_per_file` | `3` | unused (never paid and sent) quotes one file may leave within the window before it is refused |
| `unused_quote_window_seconds` | `86400` | window over which unused quotes per file are counted |
| `quote_hold_gas` | `400000` | gas of the keeper's hold and release transactions, charged at --fixed-gas-price-wei inside every quoted price (0 = no hold fee) |
| `quote_reservation_reconcile_seconds` | `15` | seconds between authoritative quote reservation reconciliation scans |
| `quote_transfer_min_bytes_per_second` | `65536` | minimum sustained transfer rate used to derive signed registration deadlines |
| `quote_transfer_recovery_grace_seconds` | `600` | additional signed recovery time for a resumable transfer |
| `filesystem_reserve_bytes` | `0` | hard unsellable filesystem reserve (0 derives proof/upload workspace safely) |
| `public_addr_check_seconds` | `300` | auto address: seconds between light checks for a new address |
| `public_addr_full_check_seconds` | `3600` | auto address: seconds between full proofs of the published address |
| `public_addr_min_change_seconds` | `600` | auto address: minimum seconds between two published changes (each is an on-chain update) |
| `public_addr_helpers` | `3` | auto address: independent keepers asked to call this keeper back |
| `public_addr_port_mapping` | `true` | auto address: ask a home router (UPnP / NAT-PMP) to open the listen port |
| `reach_helper` | `true` | call other keepers back at their own address when they ask, so they can prove it |
| `piece_block_size` | `65536` | piece Merkle block size in bytes |
| `max_piece_size_bytes` | `2147483648` | maximum accepted piece size in bytes (0 = unlimited) |
| `max_concurrent_uploads` | `4` | maximum simultaneous upload handlers |
| `max_concurrent_downloads` | `8` | maximum simultaneous download handlers |
| `max_queued_transfers` | `32` | maximum upload/download requests waiting for admission |
| `max_transfers_per_peer` | `4` | maximum simultaneous admitted transfers per remote peer or wallet |
| `max_temporary_upload_bytes` | `0` | maximum bytes reserved by resumable partial uploads (0 = derive from declared capacity) |
| `transfer_queue_wait_seconds` | `2` | seconds a transfer may wait for admission before receiving busy |
| `transfer_retry_after_seconds` | `5` | retry delay returned when transfer admission is busy |
| `partial_upload_ttl_seconds` | `86400` | retention for incomplete resumable uploads |
| `completed_transfer_ttl_seconds` | `604800` | retention for completed transfer responses used by idempotent resume |
| `sector_max_pieces` | `1024` | maximum piece roots per local VK sector |
| `sector_lifetime_days` | `30` | default local VK sector lifetime |
| `allow_sector_extend` | `true` | allow open sector expiration extension to cover a piece serviceEnd |
| `sector_max_expiration_extension_seconds` | `604800` | max seconds to extend an open sector expiration for a new piece (0 = default 7 days) |
| `sector_allow_large_expiration_mixing` | `false` | allow placing pieces in sectors whose expiration bucket is much larger than the piece needs |
| `max_service_days` | `0` | maximum service duration VK accepts in days (0 = unlimited); registered in VaultKeeperRegistry |
| `discovery_ttl_seconds` | `28800` | seconds before a discovery record expires |
| `discovery_heartbeat_seconds` | `7200` | seconds between discovery heartbeats |

### Proof worker settings

| Setting | Default | Meaning |
|---|---|---|
| `storageproof_proof_poll_seconds` | `60` | proof daemon poll interval in seconds |

### Supervisor, wrapper and chain-helper settings

| Setting | Default | Meaning |
|---|---|---|
| `discovery_enabled` | `true` | Publish and refresh the node discovery record. |
| `storageproof_persistent_prover_enabled` | `true` | Reuse a persistent prover process instead of starting one per request. |
| `storageproof_persistent_prover_start_timeout_seconds` | `900` | Maximum wait for persistent prover startup, in seconds. |
| `storageproof_persistent_prover_request_timeout_seconds` | `900` | Maximum wait for one persistent prover request, in seconds. |
| `storageproof_prover_nice` | `10` | CPU scheduling nice value: 0–19. |
| `storageproof_prover_io_priority` | `"low"` | I/O priority: low or normal. |
| `storageproof_staleness_threshold_rounds` | `2` | Proof-staleness threshold read by the chain helper. |
| `log_eth_calls` | `false` | Enable read-only eth_call logging in the chain helper; can produce large logs. |
| `storageproof_confirmations` | `1` | Confirmation count used by the chain helper. |
| `startup_timeout_sec` | `0` | Wait for native server startup. 0 waits without a time limit; positive values are seconds. Admission readiness is reported separately by native capacity progress. |

The legacy public field `proof_poll_seconds` is migrated to `storageproof_proof_poll_seconds`. Conflicting values are rejected.

Old `capacity_bytes` is migrated to `storage_capacity_bytes` without changing the allocation. Conflicting aliases are rejected. Reinstallation preserves the existing capacity and rejects a different `--capacity-gib` value rather than silently resizing the node.

The prover is warmed before starting the server; the proof worker starts after native server startup. The supervisor reports piece readiness only after native capacity progress reports admission open. The update health marker separately confirms that both workers have started; it is not proof of open storage admission. Initialization output is forwarded to the systemd journal and retained in the node log files.
