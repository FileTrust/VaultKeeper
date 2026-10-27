#!/usr/bin/env bash
# BEGIN FILETRUST INSTALL BANNER — from root singature.txt
filetrust_install_banner() {
  local banner_dir banner_version='unknown' banner_line
  banner_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
  if [[ -r "$banner_dir/VERSION" ]]; then
    IFS= read -r banner_version < "$banner_dir/VERSION" || [[ -n $banner_version ]]
    banner_version=${banner_version%$'\r'}
  fi
  cat <<'FILETRUST_BANNER_TOP'
███████╗██╗██╗     ███████╗████████╗██████╗ ██╗   ██╗███████╗████████╗
██╔════╝██║██║     ██╔════╝╚══██╔══╝██╔══██╗██║   ██║██╔════╝╚══██╔══╝
█████╗  ██║██║     █████╗     ██║   ██████╔╝██║   ██║███████╗   ██║
██╔══╝  ██║██║     ██╔══╝     ██║   ██╔══██╗██║   ██║╚════██║   ██║
██║     ██║███████╗███████╗   ██║   ██║  ██║╚██████╔╝███████║   ██║
╚═╝     ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝


Author: Ali Farahpoor
Company: Electra Sphere Innovations (ElectraSI.es)
Location: Barcelona, Spain
Contact: support@filetrust.io

FILETRUST_BANNER_TOP
  printf 'Version: %s %s\n' 'Vaultkeeper' "$banner_version"
  cat <<'FILETRUST_BANNER_BOTTOM'
Release Date: 25 October 2026

Documentation: https://docs.filetrust.io
Website: https://www.filetrust.io
FILETRUST_BANNER_BOTTOM
  printf '\n'
}
if [[ ${1:-help} == install ]]; then
  filetrust_install_banner
fi
unset -f filetrust_install_banner
# END FILETRUST INSTALL BANNER
set +x
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command_name=${1:-help}
[[ $# -eq 0 ]] || shift
if [[ $command_name == help || $command_name == --help ]]; then
  echo 'Usage: ./docker.sh install [settings] | start | stop | restart | status | logs | doctor | repair | check | config [import FILE] | update | rollback | uninstall [--purge]'
  echo 'Docker Engine with its Compose plugin on x86_64 Linux is required. Native installation: sudo bash install.sh'
  exit 0
fi
command -v docker >/dev/null || { echo 'Install Docker Engine and its Compose plugin: https://docs.docker.com/engine/install/' >&2; exit 1; }
docker compose version >/dev/null || { echo 'The Docker Compose plugin is required.' >&2; exit 1; }
daemon_platform=$(docker info --format '{{.OSType}}/{{.Architecture}}') || { echo 'Cannot access Docker. Start the Docker service or use an account with Docker access.' >&2; exit 1; }
[[ $daemon_platform =~ ^linux/(x86_64|amd64)$ ]] || { echo 'This package currently supports Linux amd64 Docker hosts.' >&2; exit 1; }
export FILETRUST_DOCKER_PROJECT=${FILETRUST_DOCKER_PROJECT:-filetrust-vaultkeeper}
[[ ${#FILETRUST_DOCKER_PROJECT} -le 64 && $FILETRUST_DOCKER_PROJECT =~ ^[a-z0-9][a-z0-9_-]*$ ]] || { echo 'Invalid Docker project name' >&2; exit 1; }
compose=(docker compose --project-name "$FILETRUST_DOCKER_PROJECT" --project-directory "$root" -f "$root/compose.yaml")
image="filetrust-vaultkeeper:$FILETRUST_DOCKER_PROJECT"
previous="$image-previous"
tool_container=''
cleanup() { if [[ -n $tool_container ]]; then docker rm -f "$tool_container" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT
build_image() {
  local flags=()
  if [[ -n ${FILETRUST_DOCKER_BUILD_NETWORK:-} ]]; then
    [[ $FILETRUST_DOCKER_BUILD_NETWORK == host || $FILETRUST_DOCKER_BUILD_NETWORK == default ]] || { echo 'Invalid build network' >&2; exit 1; }
    flags+=(--network "$FILETRUST_DOCKER_BUILD_NETWORK")
    [[ $FILETRUST_DOCKER_BUILD_NETWORK != host ]] || flags+=(--allow network.host)
  fi
  docker build --target runtime --tag "$image" "${flags[@]}" "$root"
}
container_id() { "${compose[@]}" ps --all -q node; }
stop_node() {
  local cid; cid=$(container_id)
  if [[ -n $cid ]]; then
    echo 'Stopping Vaultkeeper; waiting for active work to finish...'
    docker stop --timeout -1 "$cid" >/dev/null
  fi
}
require_stopped() {
  local cid; cid=$(container_id)
  [[ -z $cid || $(docker inspect --format '{{.State.Running}}' "$cid") != true ]] || { echo 'Stop the node before running this command.' >&2; exit 1; }
}
run_tool() {
  local token='' flags=(-i)
  [[ ! -t 0 || ! -t 1 ]] || flags+=(-t)
  tool_container=$("${compose[@]}" run --detach --no-deps setup idle)
  # Credentials go over stdin into a mode-0600 file on container tmpfs.
  # No secret is passed as an argument, image build input or container Env.
  if [[ -n ${FILETRUST_GITHUB_TOKEN_FILE:-} ]]; then token=$(cat -- "$FILETRUST_GITHUB_TOKEN_FILE")
  elif [[ -n ${GH_TOKEN:-${GITHUB_TOKEN:-}} ]]; then token=${GH_TOKEN:-$GITHUB_TOKEN}
  elif command -v gh >/dev/null; then token=$(gh auth token 2>/dev/null || true)
  fi
  if [[ -n $token ]]; then
    printf '%s' "$token" | docker exec -i "$tool_container" python -c 'import sys; sys.path.insert(0,"/opt/filetrust-vaultkeeper/core"); from vault import write_private; from pathlib import Path; data=sys.stdin.buffer.read(8193); assert 0<len(data)<=8192; write_private(Path("/run/filetrust-vaultkeeper/github-token"),data)'
    unset token
  fi
  docker exec "${flags[@]}" "$tool_container" python /opt/filetrust-vaultkeeper/core/container_cli.py "$@"
  docker rm -f "$tool_container" >/dev/null
  tool_container=''
}
case "$command_name" in
  install) require_stopped; build_image; run_tool install "$@" ;;
  start) "${compose[@]}" up -d --no-build node ;;
  stop) stop_node ;;
  restart) stop_node; "${compose[@]}" up -d --no-build node ;;
  status) "${compose[@]}" ps --all node ;;
  logs) "${compose[@]}" logs --follow --tail 80 node "$@" ;;
  network-config) run_tool network-config "$@" ;;
  doctor|check) run_tool "$command_name" "$@" ;;
  repair|configure) require_stopped; run_tool "$command_name" "$@" ;;
  config)
    if [[ ${1:-} == import && $# -eq 2 ]]; then require_stopped; run_tool import-config < "$2"
    elif [[ $# -eq 0 ]]; then run_tool config
    else echo 'Usage: ./docker.sh config [import FILE]' >&2; exit 1; fi ;;
  update)
    cid=$(container_id); [[ -n $cid ]] || { echo 'Install the node first.' >&2; exit 1; }
    old_image=$(docker inspect --format '{{.Image}}' "$cid")
    was_running=$(docker inspect --format '{{.State.Running}}' "$cid")
    echo 'Building the currently checked-out source. Review/pull the intended Git release before this command.'
    build_image
    docker tag "$old_image" "$previous"
    stop_node
    "${compose[@]}" create --force-recreate --no-build node
    if [[ $was_running == true ]]; then "${compose[@]}" up -d --no-build node; fi
    echo 'Image replaced; wallet and node volumes preserved. Use logs/status to check startup. Previous image: ./docker.sh rollback' ;;
  rollback)
    docker image inspect "$previous" >/dev/null
    cid=$(container_id); was_running=false
    if [[ -n $cid ]]; then was_running=$(docker inspect --format '{{.State.Running}}' "$cid"); fi
    stop_node; docker tag "$previous" "$image"
    "${compose[@]}" create --force-recreate --no-build node
    if [[ $was_running == true ]]; then "${compose[@]}" up -d --no-build node; fi
    echo 'Previous application image restored. Node data was preserved.' ;;
  uninstall)
    [[ $# -eq 0 || ( $# -eq 1 && $1 == --purge ) ]] || { echo 'Usage: ./docker.sh uninstall [--purge]' >&2; exit 1; }
    if [[ ${1:-} == --purge ]]; then
      [[ -t 0 ]] || { echo 'Purge requires a terminal confirmation.' >&2; exit 1; }
      echo 'This permanently deletes this Docker node wallet, unlock credential, stored pieces, proof files and state. Retire obligations and back up first.'
      read -r -p 'Type DELETE to remove all node data: ' answer
      [[ $answer == DELETE ]] || { echo 'Cancelled.'; exit 1; }
    fi
    stop_node
    "${compose[@]}" down --timeout -1
    if [[ ${1:-} == --purge ]]; then
      docker volume rm "${FILETRUST_DOCKER_PROJECT}_state" "${FILETRUST_DOCKER_PROJECT}_credentials"
      echo 'Docker node and all its managed data removed.'
    else echo 'Docker node removed. Wallet, storage and settings kept; reinstall/start reuses them.'; fi
    echo 'Source clone and build images are kept. Native installations are unchanged.' ;;
  *) echo "Unknown command: $command_name" >&2; exit 1 ;;
esac
