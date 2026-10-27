#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KEYS_DIR="${FILETRUST_ZK_KEYS_DIR:-$SCRIPT_DIR/keys}"

# shellcheck source=prover_priority.sh
source "$SCRIPT_DIR/prover_priority.sh"
filetrust_apply_prover_priority

DEBUG_DIR="$SCRIPT_DIR/debug"
mkdir -p "$DEBUG_DIR"

REQ_FILE="$DEBUG_DIR/last_prover_input.json"
RAW_OUT="$DEBUG_DIR/last_prover_raw_stdout.log"
RAW_ERR="$DEBUG_DIR/last_prover_raw_stderr.log"
JSON_OUT="$DEBUG_DIR/last_prover_json.log"

cat > "$REQ_FILE"

set +e
NO_COLOR=1 "$SCRIPT_DIR/storageproof-prover" --mode prove --keys "$KEYS_DIR" \
  < "$REQ_FILE" \
  > "$RAW_OUT" \
  2> "$RAW_ERR"
CODE=$?
set -e

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

candidates = []
for line in text.splitlines():
    s = line.strip()
    if s.startswith("{") and s.endswith("}"):
        candidates.append(s)

for s in reversed(candidates):
    try:
        json.loads(s)
        json_out.write_text(s + "\n")
        print(s)
        sys.exit(0 if code == 0 else code)
    except Exception:
        pass

msg = err.strip() or text.strip() or f"prover exited with code {code} and no JSON output"
print(json.dumps({"ok": False, "err": msg}))
sys.exit(1)
PY
