#!/usr/bin/env bash
# FileTrust partition ZK prover client and persistent-service supervisor.
set -euo pipefail
umask 077

if ! command -v flock >/dev/null 2>&1; then
  echo "persistent partition prover requires flock" >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=prover_priority.sh
source "$SCRIPT_DIR/prover_priority.sh"
filetrust_apply_prover_priority

KEYS_DIR="${FILETRUST_ZK_KEYS_DIR:-$SCRIPT_DIR/keys}"
PROFILE="${FILETRUST_ZK_PARTITION_PROFILE:-${FILETRUST_ZK_PROFILE:-partition_128b_d28_n16_m4}}"
if [[ -n "$PROFILE" ]]; then
  PARTITION_KEYS_DIR="${FILETRUST_ZK_PARTITION_KEYS_DIR:-$SCRIPT_DIR/keys/profiles/$PROFILE/partition}"
else
  PARTITION_KEYS_DIR="${FILETRUST_ZK_PARTITION_KEYS_DIR:-$KEYS_DIR/partition}"
fi
CONFIG_ARGS=()
if [[ -n "${FILETRUST_ZK_CONFIG:-}" ]]; then
  CONFIG_ARGS=(--config "$FILETRUST_ZK_CONFIG")
fi

PERSISTENT_ENABLED="${FILETRUST_ZK_PERSISTENT_PROVER_ENABLED:-1}"
PROFILE_SAFE="$(printf '%s' "${PROFILE:-default}" | tr -c 'A-Za-z0-9_.-' '_')"
RUN_DIR="${FILETRUST_ZK_PROVER_RUN_DIR:-$SCRIPT_DIR/run}"
SOCKET_PATH="${FILETRUST_ZK_PARTITION_PROVER_SOCKET:-$RUN_DIR/partition-$PROFILE_SAFE.sock}"
PID_FILE="${SOCKET_PATH}.pid"
SERVICE_LOG="${FILETRUST_ZK_PARTITION_PROVER_LOG:-${SOCKET_PATH}.log}"
START_LOCK="${SOCKET_PATH}.start.lock"
START_TIMEOUT="${FILETRUST_ZK_PERSISTENT_START_TIMEOUT_SECONDS:-900}"
REQUEST_TIMEOUT="${FILETRUST_ZK_PERSISTENT_REQUEST_TIMEOUT_SECONDS:-900}"
INSTANCE_LOCK="$RUN_DIR/partition-$PROFILE_SAFE.instance.lock"

DEBUG_DIR="${FILETRUST_ZK_PROVER_DEBUG_DIR:-$RUN_DIR/debug}"
mkdir -p "$DEBUG_DIR"
chmod 0700 "$DEBUG_DIR"
REQUEST_DIR="$(mktemp -d "$DEBUG_DIR/request.XXXXXXXX")"
trap 'rm -rf -- "$REQUEST_DIR"' EXIT
REQ_FILE="$REQUEST_DIR/input.json"
RAW_OUT="$REQUEST_DIR/stdout.log"
RAW_ERR="$REQUEST_DIR/stderr.log"
JSON_OUT="$REQUEST_DIR/result.json"

service_pid() {
  [[ -f "$PID_FILE" ]] || return 1
  local pid
  pid="$(tr -dc '0-9' < "$PID_FILE")"
  [[ -n "$pid" ]] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  local args
  args="$(ps -p "$pid" -o args= 2>/dev/null || true)"
  [[ "$args" == *"storageproof-prover"* && "$args" == *"$SOCKET_PATH"* ]] || return 1
  printf '%s' "$pid"
}

stop_service_locked() {
  local pid=""
  pid="$(service_pid || true)"
  if [[ -n "$pid" ]]; then
    kill -TERM "$pid" 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.1
    done
  fi
  rm -f "$PID_FILE"
  if [[ -S "$SOCKET_PATH" ]]; then
    rm -f "$SOCKET_PATH"
  elif [[ -e "$SOCKET_PATH" ]]; then
    echo "refusing to remove non-socket path: $SOCKET_PATH" >&2
    return 1
  fi
}

start_service_locked() {
  local pid=""
  pid="$(service_pid || true)"
  if [[ -n "$pid" && -S "$SOCKET_PATH" ]]; then
    return 0
  fi
  if [[ -n "$pid" ]]; then
    stop_service_locked
  elif [[ -S "$SOCKET_PATH" ]]; then
    rm -f "$SOCKET_PATH"
  elif [[ -e "$SOCKET_PATH" ]]; then
    echo "refusing to replace non-socket path: $SOCKET_PATH" >&2
    return 1
  fi

  local -a command=(
    "$SCRIPT_DIR/storageproof-prover"
    --mode partition-serve
    --keys "$KEYS_DIR"
    --partition-keys "$PARTITION_KEYS_DIR"
    --socket "$SOCKET_PATH"
    "${CONFIG_ARGS[@]}"
  )
  mkdir -p "$(dirname "$INSTANCE_LOCK")"
  touch "$INSTANCE_LOCK"
  chmod 0600 "$INSTANCE_LOCK"
  local -a singleton_command=(
    flock --nonblock --no-fork --conflict-exit-code 73 "$INSTANCE_LOCK"
    "${command[@]}"
  )
  touch "$SERVICE_LOG"
  chmod 0600 "$SERVICE_LOG"
  # The daemon must not inherit the startup lock: interrupted startup must
  # release it so the shutdown wrapper can acquire it and stop the service.
  if command -v setsid >/dev/null 2>&1; then
    nohup setsid env NO_COLOR=1 "${singleton_command[@]}" >> "$SERVICE_LOG" 2>&1 < /dev/null 9>&- &
  else
    nohup env NO_COLOR=1 "${singleton_command[@]}" >> "$SERVICE_LOG" 2>&1 < /dev/null 9>&- &
  fi
  pid=$!
  printf '%s\n' "$pid" > "$PID_FILE"
  chmod 0600 "$PID_FILE"

  local checks=$((START_TIMEOUT * 10))
  for ((i=0; i<checks; i++)); do
    if [[ -S "$SOCKET_PATH" ]] && kill -0 "$pid" 2>/dev/null; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "persistent partition prover exited during startup; log=$SERVICE_LOG" >&2
      tail -n 40 "$SERVICE_LOG" >&2 || true
      return 1
    fi
    sleep 0.1
  done
  echo "persistent partition prover startup timed out after ${START_TIMEOUT}s; log=$SERVICE_LOG" >&2
  return 1
}

ensure_service() {
  local action="${1:-start}"
  mkdir -p "$RUN_DIR" "$(dirname "$SOCKET_PATH")"
  chmod 0700 "$RUN_DIR"
  exec 9>"$START_LOCK"
  chmod 0600 "$START_LOCK"
  flock -x 9
  if [[ "$action" == "restart" ]]; then
    stop_service_locked
  fi
  start_service_locked
  flock -u 9
}

send_service_request() {
  python3 - "$SOCKET_PATH" "$REQ_FILE" "$RAW_OUT" "$REQUEST_TIMEOUT" <<'PY'
import socket
import sys
from pathlib import Path

socket_path, request_path, output_path, request_timeout = sys.argv[1:]
payload = Path(request_path).read_bytes()
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.settimeout(10)
sock.connect(socket_path)
sock.settimeout(float(request_timeout))
sock.sendall(payload)
sock.shutdown(socket.SHUT_WR)
chunks = []
while True:
    chunk = sock.recv(65536)
    if not chunk:
        break
    chunks.append(chunk)
sock.close()
response = b"".join(chunks)
if not response:
    raise RuntimeError("persistent partition prover returned an empty response")
Path(output_path).write_bytes(response)
PY
}

case "${1:-}" in
  --start-service)
    ensure_service start
    exit 0
    ;;
  --restart-service)
    ensure_service restart
    exit 0
    ;;
  --stop-service)
    mkdir -p "$RUN_DIR" "$(dirname "$SOCKET_PATH")"
    exec 9>"$START_LOCK"
    chmod 0600 "$START_LOCK"
    flock -x 9
    stop_service_locked
    flock -u 9
    exit 0
    ;;
esac

# Capture stdin before starting or contacting the service. The request contains
# commitments and paths, never private challenged block contents.
cat > "$REQ_FILE"
: > "$RAW_ERR"
: > "$RAW_OUT"
: > "$JSON_OUT"
chmod 0600 "$REQ_FILE" "$RAW_ERR" "$RAW_OUT" "$JSON_OUT"

if [[ "$PERSISTENT_ENABLED" == "1" || "$PERSISTENT_ENABLED" == "true" ]]; then
  ensure_service start
  set +e
  send_service_request 2> "$RAW_ERR"
  CODE=$?
  set -e
  if [[ $CODE -ne 0 ]]; then
    ensure_service restart
    set +e
    send_service_request 2>> "$RAW_ERR"
    CODE=$?
    set -e
  fi
else
  set +e
  NO_COLOR=1 "$SCRIPT_DIR/storageproof-prover" \
    --mode partition-prove \
    --keys "$KEYS_DIR" \
    --partition-keys "$PARTITION_KEYS_DIR" \
    "${CONFIG_ARGS[@]}" \
    < "$REQ_FILE" \
    > "$RAW_OUT" \
    2> >(tee "$RAW_ERR" >&2)
  CODE=$?
  set -e
fi

python3 - "$RAW_OUT" "$RAW_ERR" "$JSON_OUT" "$CODE" <<'PY'
import json
import re
import sys
from pathlib import Path

raw_out = Path(sys.argv[1])
raw_err = Path(sys.argv[2])
json_out = Path(sys.argv[3])
code = int(sys.argv[4])

ansi = re.compile(r"\x1b\[[0-9;]*m")
text = ansi.sub("", raw_out.read_text(errors="replace"))
err = ansi.sub("", raw_err.read_text(errors="replace"))

candidates = [line.strip() for line in text.splitlines() if line.strip().startswith("{") and line.strip().endswith("}")]
for candidate in reversed(candidates):
    try:
        parsed = json.loads(candidate)
        json_out.write_text(candidate + "\n")
        print(candidate)
        sys.exit(0 if code == 0 else code)
    except Exception:
        pass

message = err.strip() or text.strip() or f"partition prover exited {code} with no JSON output"
print(json.dumps({"ok": False, "err": message}))
sys.exit(1)
PY
