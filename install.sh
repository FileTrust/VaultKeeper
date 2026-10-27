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
filetrust_install_banner
unset -f filetrust_install_banner
# END FILETRUST INSTALL BANNER
set -euo pipefail
source_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
[[ $EUID -eq 0 ]] || { echo 'Run sudo bash install.sh'; exit 1; }
[[ $(uname -s) == Linux && $(uname -m) == x86_64 && -d /run/systemd/system ]] || { echo 'Linux x86_64 with systemd is required'; exit 1; }
command -v apt-get >/dev/null || { echo 'Automatic dependencies support Debian/Ubuntu'; exit 1; }
if systemctl is-active --quiet filetrust-vaultkeeper; then echo 'Stop the node after its work finishes before installation'; exit 1; fi
echo '[Setup] Installing Python and HTTPS prerequisites; Go is verified/installed privately by the local build stage; no circuit setup generation'
apt-get update
apt-get install -y python3 python3-venv ca-certificates util-linux procps
python3 -c 'import sys,ssl,venv; raise SystemExit(not ((3, 10) <= sys.version_info[:2] <= (3, 14)))' || { echo 'Python 3.10 through 3.14 is supported. Install a supported Python and its venv package; do not replace the system Python.'; exit 1; }
echo "[Setup] Using $(python3 --version); creating an application-only virtual environment"
app=/opt/filetrust-vaultkeeper
install -d -m 0755 "$app" "$app/.filetrust-updates"
touch "$app/.filetrust-updates/run.lock" "$app/.filetrust-updates/update.lock"
chmod 0644 "$app/.filetrust-updates/"*.lock
exec 9< "$app/.filetrust-updates/update.lock"; flock -n 9 || { echo 'An installer or update is running'; exit 1; }
exec 8< "$app/.filetrust-updates/run.lock"; flock -n 8 || { echo 'A node worker still uses this app'; exit 1; }
if [[ "$source_dir" != "$app" ]]; then
  for name in vaultkeeper.py app_start.py manage.py uninstall.py update.py upgrade.py ft_update_bootstrap.py release-key.pub update-root.json update-source.json VERSION requirements.txt config.defaults.json config.example.json README.md LICENSE THIRD-PARTY-NOTICES.md; do install -m 0644 "$source_dir/$name" "$app/$name"; done
  rm -rf -- "$app/runtime" "$app/licenses" "$app/core" "$app/docs"
  cp -a "$source_dir/core" "$source_dir/runtime" "$source_dir/licenses" "$source_dir/docs" "$app/"
  # Normalize copies from Windows/shared drives before the service uses them.
  if find "$app/core" "$app/runtime" "$app/licenses" "$app/docs" -type l -print -quit | grep -q .; then echo 'Source symlinks are not accepted'; exit 1; fi
  find "$app/core" "$app/runtime" "$app/licenses" "$app/docs" -type d -name __pycache__ -prune -exec rm -rf -- {} +
  chown -R root:root "$app/core" "$app/runtime" "$app/licenses" "$app/docs"
  find "$app/core" "$app/runtime" "$app/licenses" "$app/docs" -type d -exec chmod 0755 {} +
  find "$app/core" "$app/runtime" "$app/licenses" "$app/docs" -type f -exec chmod 0644 {} +
  # Remove only the known obsolete 0.1 code modules, never node data.
  for name in artifact_store commands network vault release service update_artifacts ft_updates ft_update_install ft_update_service; do rm -f -- "$app/$name.py"; done
fi
if [[ ! -x "$app/.venv/bin/python" ]]; then python3 -m venv "$app/.venv"; fi
env -u GH_TOKEN -u GITHUB_TOKEN -u PYTHONPATH -u PYTHONHOME -u PIP_CONFIG_FILE "$app/.venv/bin/python" -m pip --isolated install --disable-pip-version-check -r "$app/requirements.txt"
"$app/.venv/bin/python" -m pip check
flock -u 8; flock -u 9
exec "$app/.venv/bin/python" "$app/vaultkeeper.py" install --service "$@"
