#!/usr/bin/env bash
# Shared, best-effort process-priority policy for FileTrust ZK provers.
#
# A positive nice value and the lowest best-effort I/O priority allow proofs to
# continue making progress while foreground VK traffic receives preference.
# Missing or unsupported priority tools must never prevent a proof from running.

filetrust_validate_prover_priority() {
  local nice_value="${FILETRUST_ZK_PROVER_NICE:-10}"
  local io_priority="${FILETRUST_ZK_PROVER_IO_PRIORITY:-low}"

  if [[ ! "$nice_value" =~ ^[0-9]{1,2}$ ]]; then
    echo "invalid FILETRUST_ZK_PROVER_NICE=$nice_value; expected an integer from 0 to 19" >&2
    return 2
  fi
  # Force decimal interpretation so a direct value such as 08 is not treated
  # as invalid octal by Bash arithmetic.
  if (( 10#$nice_value > 19 )); then
    echo "invalid FILETRUST_ZK_PROVER_NICE=$nice_value; expected an integer from 0 to 19" >&2
    return 2
  fi
  case "$io_priority" in
    low|normal) ;;
    *)
      echo "invalid FILETRUST_ZK_PROVER_IO_PRIORITY=$io_priority; expected low or normal" >&2
      return 2
      ;;
  esac
}

filetrust_apply_prover_priority() {
  filetrust_validate_prover_priority || return $?

  local nice_value="${FILETRUST_ZK_PROVER_NICE:-10}"
  local io_priority="${FILETRUST_ZK_PROVER_IO_PRIORITY:-low}"
  local target_pid="${BASHPID:-$$}"
  local nice_decimal=$((10#$nice_value))

  if (( nice_decimal > 0 )); then
    if command -v renice >/dev/null 2>&1; then
      if ! renice -n "$nice_decimal" -p "$target_pid" >/dev/null 2>&1; then
        echo "[zk-priority] warning: could not set CPU nice=$nice_decimal; continuing" >&2
      fi
    else
      echo "[zk-priority] warning: renice is unavailable; continuing with inherited CPU priority" >&2
    fi
  fi

  if [[ "$io_priority" == "low" ]]; then
    if command -v ionice >/dev/null 2>&1; then
      # Best-effort class, lowest priority. Unlike the idle class, this still
      # guarantees progress while the host has continuous foreground I/O.
      if ! ionice -c 2 -n 7 -p "$target_pid" >/dev/null 2>&1; then
        echo "[zk-priority] warning: could not set low I/O priority; continuing" >&2
      fi
    else
      echo "[zk-priority] warning: ionice is unavailable; continuing with inherited I/O priority" >&2
    fi
  fi
}
