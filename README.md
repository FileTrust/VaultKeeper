# FileTrust Vaultkeeper

FileTrust Vaultkeeper is the storage-node application for the FileTrust network.
It stores encrypted data pieces and submits the proofs required by the network.
Each installation operates an independent node with its own wallet, identity,
storage directory and proof worker.

## Choose an installation method

- **Native:** `sudo bash install.sh` installs the node as a system service.
- **Docker:** `./docker.sh install` builds and sets up the same application in a container.

Both methods preserve node data during a normal restart or application update.
See [Docker installation and controls](docs/docker.md) for prerequisites, start,
stop, restart, settings, updates and uninstall. The native steps follow below.

## Native installation environment

The installer supports x86_64 Linux systems with `apt` and `systemd`, including
Debian 12/13 and Ubuntu 22.04/24.04. Python **3.10 through 3.14** is supported.
The installer uses the system Python to create a private application environment;
it does not replace the system Python. It installs Python prerequisites and a
checksum-verified Go compiler when needed, then compiles the included native
programs locally.

Other Linux distributions may require changes to dependency installation and
service configuration. ARM, native Windows and native macOS installation paths
are not included in this installer. Platform compatibility should be verified
before operating a node on a different environment.

### Node resources

| Resource | Requirement |
|---|---|
| Storage | Persistent disk capacity allocated to the node, plus application files, proof parameters, download cache and working space |
| Build space | Allow at least 3 GiB for the compiler, downloaded dependencies and build cache, in addition to node storage |
| Proof parameters | Download only the required profiles; all four profiles together occupy approximately 2.7 GiB extracted, with additional space needed for ZIP downloads |
| Network | Continuous internet access, access to the blockchain RPC and network configuration service, and an externally reachable TCP port (default `4101`) |
| Permissions | Administrator access during installation and service management |

The storage allocation is configured with `--capacity` (for example, `200 MiB` or `100 GiB`); it is separate from
space used by the application and proof processing. CPU, memory and proof
workspace needs depend on the active proof profile and concurrent workload.

## Features

- Local compilation of the included node and proof-worker source.
- Signed proof-parameter downloads with checksum verification and download resume.
- Wallet creation or import, encrypted key storage and automatic service startup.
- Service controls that preserve node identity, storage and protocol state.
- Signed update notifications, staged installation and code recovery.

## 1. Download and install

```sh
git clone https://github.com/FileTrust/VaultKeeper.git
cd VaultKeeper
sudo bash install.sh
```

First-time setup asks how much storage the node should provide. Enter a size
with units, such as `200 MiB` or `100 GiB`. Alternatively, specify `--capacity`. Profile `512` and port `4101`
are defaults; select the profile approved by the network. For example:

```sh
sudo bash install.sh --profile 512 --capacity "100 GiB"
```

Supported profile sizes are `128`, `256`, `512` and `1024`. The active profile
must match the network's approved configuration. The installer checks this;
supported sizes are not interchangeable on every deployment.

If another node already uses TCP port `4101`, select a free port, for example
`sudo bash install.sh --port 4201`. Installation checks the port before compiling
or downloading proof parameters; it never stops another node to free a port.

Installation prompts for an existing wallet private key or creates a new wallet.
Private-key input is hidden. The installer shows each stage, download progress
and verification results. If interrupted, rerun the same command: downloads
resume and existing identity, settings and selected profiles are retained.

Proof parameters are downloaded and verified against signed manifests. The
application does not generate new setup keys or deploy contracts.

For repositories or artifact downloads requiring authentication, see
[repository access](docs/release-notes.md#repository-access).

### Installation settings

Installation options:

| Option | Purpose |
|---|---|
| `--profile` | Active proof profile: `128`, `256`, `512` or `1024` |
| `--capacity` | Storage allocation with units, such as `200 MiB` or `100 GiB` |
| `--capacity-gib` | Storage allocation in GiB; decimals are accepted |
| `--storage-capacity-bytes` | Exact storage allocation in bytes |
| `--storage-path` | Dedicated directory for stored pieces |
| `--port` | Public node TCP port; default `4101` |
| `--advertise-ip` | Public address; default `auto` checks reachability |
| `--rpc-url` | Blockchain RPC; default `https://rpc.filetrust.io` |
| `--config-url` | Network configuration; default `https://config.filetrust.io/v1/network-config` |
| `--storage-fee` | Storage fee, in SU per GB per day |
| `--stake-wei` | Stake amount in wei, according to network requirements |
| `--download-profile` | Cache an additional profile; repeat for more profiles |

A new dedicated storage directory must be empty. The installer keeps existing
node storage when resuming installation. Network identity, contracts and profile
compatibility are checked against the signed release binding. Changing the RPC
address alone does not switch the node to a different blockchain deployment.
Price information uses `https://price.filetrust.io`; fee conversion uses the
on-chain network configuration.

## Configuration

The node configuration is stored at `/var/lib/filetrust-vaultkeeper/config.json`.
It uses the same `##` section headings and help text as the DO/REQ configuration.
`storage_capacity_bytes` sets the node storage allocation in bytes (1 GiB =
1073741824 bytes). Contract addresses and their `*_json` file paths are shown in
separate sections marked DO NOT CHANGE.

It includes explicit transfer limits, capacity-proof scheduling, proof-worker
settings, discovery settings and logging controls, alongside local node and
validated network settings. Defaults are listed in [config.defaults.json](config.defaults.json).
A complete layout is shown in [config.example.json](config.example.json); the
installer fills the actual identity and network values.

Stop the node before editing configuration. For an older installation, the
`manage.py configure` command expands the config after the updated application
code is installed. Existing settings and node identity are preserved.
See the [configuration reference](docs/configuration.md) for every tuning field,
its default and how it is applied.

## 2. Prepare and start the node

Before starting:

1. Fund the wallet address displayed by the installer for transaction fees and
   any stake required by the network.
2. Review the storage capacity, fee and stake settings.
3. Make the selected TCP port reachable through your firewall and router.
4. Back up the node identity and unlock credential as described below.

Installation enables startup at reboot but does not start or register the node
immediately. Complete the steps above before starting it or rebooting the host.
Registration and network operations can spend transaction fees and stake.

```sh
sudo systemctl start filetrust-vaultkeeper
```

## 3. Manage the service

| Action | Command |
|---|---|
| Start | `sudo systemctl start filetrust-vaultkeeper` |
| Check status | `sudo systemctl status filetrust-vaultkeeper` |
| Stop | `sudo systemctl stop filetrust-vaultkeeper` |
| Restart | `sudo systemctl restart filetrust-vaultkeeper` |
| View live logs | `sudo journalctl --output=cat -u filetrust-vaultkeeper -f` |

Service logs include prover warm-up, server initialization, proof progress and errors.
The `Vaultkeeper ready: admission open, accepting pieces` message confirms native
admission has opened. Either cooperating worker can publish this transition.
`FileTrust VK started` and an active systemd service confirm process startup;
Wait for the readiness message before treating the node as available for new pieces.

Logs show node activity and errors. Press **Ctrl+C** to leave the log view;
this does not stop the node.

In a colour-capable terminal, success messages are green, warnings yellow and
errors red. Progress stays plain. This uses standard terminal colours and needs
no additional packages or fonts. Set `VK_LOG_COLOR=never` (or `NO_COLOR`) in the
service environment for plain output. Colours are recorded when messages are
emitted; changing the viewing command does not colour older plain messages.

Restart preserves the wallet, peer identity, stored pieces, proof parameters and
protocol state. Stopping refuses new work and waits for active transfers and
proof work to finish. Allow time for a graceful stop. On-chain proof deadlines
continue during downtime, so plan maintenance accordingly.

The `manage.py` command is an alternative to systemctl. For example:
`sudo python3 /opt/filetrust-vaultkeeper/manage.py status`.
It also provides `logs`, `doctor`, `repair`, `update` and `uninstall` shortcuts.

During startup, the journal shows proof-file checks, storage preparation in MiB,
and the number of initial proofs confirmed on-chain. Storage preparation and
confirmed proofs are separate stages; 100% prepared storage does not mean the
node is ready. Long calculations show elapsed time without an estimated percentage.
The node reports readiness only when native admission opens.

Full worker output, including internal coordination and prover details, remains
in `/var/lib/filetrust-vaultkeeper/logs/server.log`, `proof.log` and `prover.log`.
Normal journal output summarizes this activity; genuine failures remain visible.

## 4. Backups and key protection

| Location | Contents |
|---|---|
| `/opt/filetrust-vaultkeeper` | Installed application, local programs and build cache |
| `/var/lib/filetrust-vaultkeeper` | Wallet, peer identity, configuration, protocol state and proof files |
| `/etc/filetrust-vaultkeeper` | Unlock credential and installation record |
| Configured storage directory | Stored pieces |

**Back up the node state, its matching unlock credential and stored pieces.**
A wallet-only backup cannot restore the peer identity or storage/protocol state.
Stop the node gracefully before making a consistent backup. Keep backups private.

Wallet and peer private keys are encrypted at rest. A separate OS credential
allows the service to unlock them automatically after reboot. Decrypted keys
use private RAM files rather than command arguments. This protects stored keys;
an administrator controlling the host can still access a running node.

## 5. Check or repair an installation

Check local files, identity and network compatibility:

```sh
sudo python3 /opt/filetrust-vaultkeeper/manage.py doctor
```

To repair local programs or downloaded proof files, stop the node first:

```sh
sudo systemctl stop filetrust-vaultkeeper
sudo python3 /opt/filetrust-vaultkeeper/manage.py repair
sudo python3 /opt/filetrust-vaultkeeper/manage.py doctor
sudo systemctl start filetrust-vaultkeeper
```

Repair rebuilds local programs when required and downloads verified proof files.
It preserves identity, stored pieces and protocol state.

## 6. Update the application

The node checks for signed releases at startup and approximately daily in the
background. It reports available updates; it does not install them automatically.
Failed checks do not interrupt node work.

Check for a release:

```sh
sudo /opt/filetrust-vaultkeeper/.venv/bin/python /opt/filetrust-vaultkeeper/update.py --check
```

Prepare the update, then apply it during a suitable maintenance window:

```sh
sudo /opt/filetrust-vaultkeeper/.venv/bin/python /opt/filetrust-vaultkeeper/upgrade.py prepare
sudo /opt/filetrust-vaultkeeper/.venv/bin/python /opt/filetrust-vaultkeeper/upgrade.py apply --service
```

Preparation verifies the release, builds the new programs and stages dependencies
and proof files before stopping the service. Applying stops the node gracefully
and restarts it if it was running beforehand. Failed readiness checks restore
the previous code and environment. Code rollback does not roll back user data.

Use `upgrade.py status` to inspect update state. Recovery commands are documented
in [release and recovery notes](docs/release-notes.md).

## 7. Uninstall

Remove the application while keeping node data for recovery or reinstallation:

```sh
sudo python3 /opt/filetrust-vaultkeeper/uninstall.py
```

To also delete the standard node state and unlock credential:

```sh
sudo python3 /opt/filetrust-vaultkeeper/uninstall.py --purge
```

Purge requires typing `DELETE`. Retire network duties and make required backups
first. Uninstall does not withdraw stake or deregister the node.
External storage is always kept, including with purge. Unmount any active mounts
inside the standard state directory before purging it.

The inactive service account and the source clone are kept. After a successful
purge, you can remove the account with `sudo userdel ftvaultkeeper` and delete
the source clone. Review external storage separately before deleting any data.
Shared Python and Git installations are kept for other applications.

## License and credits

See [LICENSE](LICENSE), [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)
and [licenses/](licenses/). Native runtime source is included under `runtime/`;
Python application modules are included in this repository. Retain the
corresponding source and dependency versions when redistributing binaries.

## Registry heartbeat

The running node sends a registry heartbeat every 30 minutes at a stable wallet/chain-specific slot. Failed sends retry after 60 seconds using the same saved signed transaction, so timeouts or restarts do not allocate another pending heartbeat. The existing account transaction lock coordinates this with normal node transactions. No new contract deployment is needed.

Explorer displays Participation (Enabled/Disabled/Suspended where supported) separately from Heartbeat (Fresh/Stale). Fresh means the registry timestamp is no older than 45 minutes. Neither a fresh heartbeat nor a Discovery announcement changes suspension, participation or admission.

VK Discovery announcements now default to every 2 hours, with a separate wallet-specific slot. They renew the signed address record; unchanged endpoints do not require a blockchain transaction. The record lifetime remains 8 hours. Existing explicit `discovery_heartbeat_seconds` settings are preserved; use `7200` for the new 2-hour interval when updating an existing installation.

## Network settings updates

Code releases and network settings are checked separately. The node checks for
network changes daily alongside code update checks. Checks only notify; they
never change contracts, ABIs, storage allocation, identities or running work.
A normal restart uses the saved settings.

```sh
python3 network-config.py check
python3 network-config.py status
```

Review the reported changes. Stop the node normally before applying:

```sh
python3 network-config.py apply
# Start the node again using its usual service or launcher command.
```

Use the installed application's Python environment and the account that owns its
settings (or sudo where required). Public Guardian and Vaultkeeper commands use
their installed state directories by default; `--home PATH` selects another node.
Application and proof-artifact compatibility checks remain mandatory. If a change
requires a new application or signed artifact release, install that release first.
To undo the last settings activation while stopped:

```sh
python3 network-config.py rollback
```

Previous settings and ABI generations are retained in the node's private
`.network-updates` directory. Wallets, transport keys, shares, pieces and capacity
state are preserved. Failed checks keep the last working settings. User-selected
Discovery peers remain unchanged; `network_config_manage_discovery: true` opts
into managing that list from the network service.

For Docker: `./docker.sh network-config check`, `./docker.sh network-config status`; stop with `./docker.sh stop`, apply with `./docker.sh network-config apply`, then `./docker.sh start`. State stays in the persistent node volume.
