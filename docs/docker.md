# Run Vaultkeeper with Docker

Docker is an alternative to the native installer in this same repository.
It supplies Python and dependencies and compiles the included Go programs on
this machine during image building. It downloads signed proof parameters during
node setup; it never generates setup keys or deploys contracts.

## Requirements

Use an x86_64 Linux host with Docker Engine and its Compose plugin (v2 or later).
Install Docker using the instructions for the host distribution:
https://docs.docker.com/engine/install/

No host Python or Go installation is needed. The current image targets Linux
amd64 and uses Linux host networking for the node's public TCP port. Windows,
macOS, ARM and rootless Docker networking are not validated by this package.
The host still needs sufficient memory, disk space and a reachable node port as
listed in the main README. Docker does not remove router or firewall requirements.

If Docker commands require administrator access on this host, run the commands
below with `sudo`. Docker daemon access is administrator-level access.

## Install

Docker packaging currently lives on `feature/docker-installation`; the native
release remains available on `main`. The command below selects the Docker branch.

```sh
git clone --branch feature/docker-installation https://github.com/FileTrust/VaultKeeper.git
cd VaultKeeper
./docker.sh install
```

Setup asks for the node's storage allocation and whether to import a wallet or
create a new one. Private-key input is hidden. Compilation and signed downloads
show progress. Interrupted downloads can resume by rerunning the same command.
Installation does not register or start the node.

Options match native setup, for example:

```sh
./docker.sh install --capacity "100 GiB" --port 4101
```

If another node uses port 4101, choose a free port. A port conflict is reported during setup, before
proof-parameter downloads. Fund the displayed wallet and review settings before
starting. Each Docker project is one independent node. It does not use a native
installation's wallet, settings or storage.

For private repositories, existing `gh auth login` access is used automatically.
Alternatively provide `GH_TOKEN` or `FILETRUST_GITHUB_TOKEN_FILE` to the wrapper.
With sudo, explicitly preserve only the required environment variable.
The wrapper sends this credential over stdin into a temporary setup container's
RAM filesystem. It is not an image build argument or container environment
variable and is removed with the temporary container. The running node is not
automatically given an administrator GitHub credential.

## Start, stop and observe

```sh
./docker.sh start
./docker.sh logs
./docker.sh status
./docker.sh stop
./docker.sh restart
```

Logs show preparation, real proof confirmations and the admission-open message.
Docker health means that the application workers have started; it is not a
claim that all capacity proofs are confirmed. Readiness to accept pieces is
reported separately in the node logs.

The wrapper waits for graceful shutdown without a forced-kill timeout when
stopping the node. A restart preserves the wallet, peer identity, settings,
stored pieces, proof parameters and protocol journals. Docker can automatically
start the node after a host reboot when the Docker service starts.

## Settings and maintenance

```sh
./docker.sh config > node-settings.json
./docker.sh stop
# Edit node-settings.json with a text editor.
./docker.sh config import node-settings.json
./docker.sh start
./docker.sh doctor
```

The configuration has the same categorized settings as a native node. Import
preserves the wallet address, requires the node to be stopped and keeps storage
inside the managed persistent volume. Startup still verifies network bindings
and contracts. Remove exported configuration files when no longer needed.

`./docker.sh repair` rechecks/downloads proof files while the node is stopped.
`./docker.sh check` checks signed update information. Private release checks need
GitHub access; failure does not stop node work.

## Update or return to the previous image

```sh
git pull --ff-only
./docker.sh update
./docker.sh logs
```

Review the intended Git release before rebuilding. The image is built before
the running node is stopped. A build failure leaves the existing node running.
The previous image is retained, and the node's previous running/stopped state
is preserved during replacement. Monitor logs/status to verify the new image.

```sh
./docker.sh rollback
```

Rollback restores the previous application image, not older copies of node data.
Use compatible releases and retain backups before upgrades that change data
formats. Docker images are rebuilt from the operator-selected Git source; this
is not an automatically installed signed image-update service. Signed release
notices remain available. The native in-place updater is not used inside the
read-only application image.

## Data, backups and uninstall

Docker manages two named volumes: `<project>_state` and `<project>_credentials`.
Together they contain the encrypted wallet, matching unlock credential, settings,
pieces, proof files and journals. They stay when a container is replaced or when
the source clone is deleted. Back up both volumes together while the node is
stopped; restoring only the wallet does not restore stored pieces or peer state.
Docker administrator/root access can read these volumes, as host administrator
access can read a native node's files.

```sh
./docker.sh uninstall
```

This removes the container and keeps its data for reinstalling later.

```sh
./docker.sh uninstall --purge
```

This additionally deletes both managed node volumes after a terminal `DELETE`
confirmation. Retire network obligations and save backups first. It affects only
this Docker project. Native installations, the source clone and image/build
cache are retained. Shared Docker images/caches are not automatically pruned.

The default project is `filetrust-vaultkeeper`. To operate another independent
node, consistently set `FILETRUST_DOCKER_PROJECT` to another name and select a
different free TCP port. Do not change the project name accidentally: another
name means different wallet/data volumes.
