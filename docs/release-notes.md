# Release, repository access and recovery notes

This document records deployment-specific details separately from the user guide.
Documentation changes do not change a release's approved network or establish a
production security certification.

## Repository access

If the repository requires access, authenticate with an account that can read it:

```sh
gh auth login
gh repo clone FileTrust/VaultKeeper
cd FileTrust-Vaultkeeper
export GH_TOKEN="$(gh auth token)"
sudo --preserve-env=GH_TOKEN bash install.sh
unset GH_TOKEN
```

Add the desired profile, capacity and other installation options to the command.
Public repositories and public release artifacts need no GitHub credential.
A complete installer ZIP is also supported; code-only update ZIPs are not installers.

For authenticated update checks by the service, run `update.py --authorize-service`
with sudo using the application's virtual-environment Python. Supply a read-only
repository token when prompted. This stores a systemd credential and takes effect
at the next planned restart. Your interactive GitHub login is not automatically
saved as a service credential.

## Published deployment binding

The published 0.2.0 release uses artifact set
`vaultkeeper-test-2026-10-21.1`. That existing signed binding targets chain ID
31338 and profile 512. Its parameters also archive profiles 128, 256 and 1024
for compatible deployments. A production chain requires its own approved signed
binding covering chain identity, contracts, code hashes, ABIs and profile
parameters. Changing README text or an RPC URL does not replace that binding.

The old artifact manifest retains a precompiled runtime bundle for older clients;
0.2.0 compiles locally and does not download or execute that bundle. The Go pin
is defined in the shipped builder. The 0.2.0 pin is Go 1.26.10.

## Upgrade compatibility

For the one-time 0.1 to 0.2 layout/local-build transition, stop the node gracefully
and use the full installer with the original profile and matching credentials.
The old flat-code updater cannot prepare the new build layout. Node state and
storage stay in their configured locations. Compatible later releases use the
signed prepare/apply procedure in the README.

## Recovery

Run these commands with `/opt/filetrust-vaultkeeper/.venv/bin/python` and the
absolute path to `/opt/filetrust-vaultkeeper/upgrade.py`:

- `status`: inspect update state.
- `recover`: recover an interrupted update.
- `rollback`: restore the previous code/environment.
- `cancel --service`: cancel pending managed maintenance.

If application imports are damaged, the frozen standard-library helper supports:

```sh
sudo python3 /opt/filetrust-vaultkeeper/ft_update_bootstrap.py --recover
```

It also supports `--rollback`. Startup and trust files have protected paths and
require a separate reviewed bootstrap/key-rotation procedure. Breaking data,
setup or contract changes require an explicit migration procedure.

## Version 0.2.1

Operator tuning values are now explicit in the installed configuration and wired
to the native workers, prover wrappers and chain helper. `manage.py configure`
expands an older config while the service is stopped. Existing values, identity,
credential and storage are preserved.

The server now receives the same proof dimensions and prover commands required
for its capacity initialization. The visible `startup_timeout_sec` replaces a
fixed 60-second cutoff; its default 0 waits for readiness without a time limit.
The Python layout uses `core/` for implementation and stable root command launchers.
The proof parameter release and approved network binding are unchanged.

## Version 0.2.2

Generated configuration now follows the DO/REQ convention: named `##` sections
and explanatory text inside valid JSON. `storage_capacity_bytes` is the visible
allocation field; the earlier `capacity_bytes` name is migrated without changing
the value. First-time setup asks for capacity in GiB unless `--capacity-gib` is
supplied. Reinstallation preserves the existing capacity.

Contract addresses and corresponding `*_json` paths are explicit. The runtime
uses configured registry/helper ABI paths and verifies local contract ABI contents
against the signed deployment. A complete layout example is included as
`config.example.json`.

## Version 0.2.3

Capacity input accepts units (for example `200 MiB`) and fractional GiB.
`--storage-capacity-bytes` accepts VK's exact original byte allocation. The
default `capacity_slot_size_bytes` is restored to 0 (automatic), matching VK.
Existing explicit allocations and slot settings are preserved.

Persistent prover warm-up precedes server startup; the proof worker starts after
the server startup message. The native capacity-progress admission-open message
controls readiness. Native initialization/proof output is also forwarded to the
service journal. Native node/prover source and proof parameters are unchanged.
