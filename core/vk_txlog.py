"""Transaction-only JSONL logging for Vault Keeper tools."""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

_CALL_LOGGER_INSTALLED = False
_ORIGINAL_CONTRACT_FUNCTION_CALL = None


def _json_default(value: Any) -> Any:
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if hasattr(value, "hex"):
        return value.hex()
    return str(value)


def _iso_ts() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def repo_root() -> Path:
    here = Path(__file__).resolve().parents[1]
    return next(
        (
            path
            for path in (here, *here.parents)
            if (path / "App").is_dir() and (path / "Blockchain").is_dir()
        ),
        here.parents[2],
    )


def default_log_path() -> Path:
    """Where this VK's transaction record lives: inside the VK, not in reports/.

    It used to default to reports/transaction_logs/, which only made sense
    because the test dashboard read from there. A Vault Keeper has to be able
    to run on a machine of its own, so its records belong under App/VK/log/.
    """
    return Path(__file__).resolve().parents[1] / "log" / "vk_transactions.jsonl"


def calls_log_path(context: Any = None) -> Path:
    """Companion file for read-only eth_call records.

    These are ~99.5% of the volume and carry no transaction hash, gas or cost.
    Keeping them beside the real transactions is what grew one of these files
    to 600 MB. They go to their own file, and only when asked for.
    """
    tx_path = context_log_path(context)
    return tx_path.with_name(tx_path.name.replace("transactions", "calls"))


def calls_logging_enabled(context: Any = None) -> bool:
    """Read-call logging is opt-in: set log_eth_calls true to debug."""
    value = _context_get(context, "log_eth_calls", _context_get(context, "LOG_ETH_CALLS", False))
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def resolve_log_path(value: Any = "") -> Path:
    raw_text = str(value or "").strip()
    if not raw_text:
        return default_log_path()
    raw = Path(raw_text).expanduser()
    if raw.is_absolute():
        text = raw.as_posix()
        marker = "/FileTrust/"
        if marker in text:
            configured_root = Path(text.split(marker, 1)[0] + "/FileTrust")
            local_root = repo_root()
            try:
                if configured_root.resolve() != local_root.resolve():
                    return local_root / text.split(marker, 1)[1]
            except OSError:
                return local_root / text.split(marker, 1)[1]
        return raw
    return (Path(__file__).resolve().parents[1] / raw).resolve()


def append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, default=_json_default, separators=(",", ":")) + "\n")


def _context_get(context: Any, key: str, default: Any = "") -> Any:
    if isinstance(context, dict):
        return context.get(key, context.get(key.lower(), default))
    if hasattr(context, key):
        return getattr(context, key)
    if hasattr(context, key.lower()):
        return getattr(context, key.lower())
    return default


def context_log_path(context: Any = None) -> Path:
    return resolve_log_path(_context_get(context, "transaction_log_path", _context_get(context, "TRANSACTION_LOG_PATH", "")))


def _chain_id(context: Any, w3: Any = None) -> str:
    if w3 is not None:
        try:
            return str(w3.eth.chain_id)
        except Exception:
            pass
    return str(_context_get(context, "chain_id", _context_get(context, "CHAIN_ID", "")) or "")


def _rpc_url(context: Any) -> str:
    return str(_context_get(context, "rpc_url", _context_get(context, "RPC_URL", "")) or "")


def _base(
    context: Any,
    *,
    tag: str,
    transaction_kind: str,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    status: str,
    w3: Any = None,
) -> dict[str, Any]:
    return {
        "tag": tag,
        "facility": "vault_keeper",
        "source": "VK",
        "transaction_kind": transaction_kind,
        "network": "",
        "chain_id": _chain_id(context, w3),
        "timestamp": _iso_ts(),
        "rpc_url": _rpc_url(context),
        "actor_address": actor_address or "",
        "contract_name": contract_name or "",
        "function_name": function_name or "",
        "contract_address": contract_address or "",
        "to_address": contract_address or "",
        "value_wei": "0",
        "transaction_hash": "",
        "block_number": "",
        "status": status,
        "gas_used": "0",
        "gas_price_wei": "0",
        "effective_gas_price_wei": "0",
        "total_cost_wei": "0",
        "total_cost_eth": "0",
    }


def function_name(fn: Any, fallback: str = "") -> str:
    return str(getattr(fn, "fn_name", "") or getattr(fn, "function_identifier", "") or fallback or "")


def contract_address(fn: Any, fallback: str = "") -> str:
    return str(getattr(fn, "address", "") or fallback or "")


def contract_name_for_address(context: Any, address: str, fallback: str = "contract") -> str:
    target = str(address or "").lower()
    known = {
        "VaultKeeperRegistry": _context_get(context, "vault_keeper_registry_address", _context_get(context, "VK_REGISTRY_CONTRACT", "")),
        "AccessControlFT": _context_get(context, "acl_address", ""),
        "StorageProofSC": _context_get(context, "storageproof_address", _context_get(context, "STORAGEPROOF_ADDRESS", "")),
        "FileRegistrationSC": _context_get(context, "file_registration_address", ""),
        "VKEscrow": _context_get(context, "vk_escrow_address", ""),
    }
    for name, known_address in known.items():
        if str(known_address or "").lower() == target:
            return name
    return fallback


def log_eth_call(
    context: Any,
    *,
    contract_name: str,
    function_name: str,
    contract_address: str = "",
    actor_address: str = "",
    status: str,
    error: str = "",
    w3: Any = None,
    **details: Any,
) -> None:
    payload = _base(
        context,
        tag=f"vk:{contract_name}.{function_name}",
        transaction_kind="eth_call",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=status,
        w3=w3,
    )
    payload.update({key: value for key, value in details.items() if value is not None})
    if error:
        payload["error"] = str(error)
    if not calls_logging_enabled(context):
        return
    append_jsonl(calls_log_path(context), payload)


def log_contract_transaction(
    context: Any,
    w3: Any,
    *,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    tx: dict[str, Any],
    tx_hash: Any,
    receipt: Any,
    **details: Any,
) -> None:
    gas_used = int(receipt.get("gasUsed", 0) or 0)
    gas_price = int(tx.get("gasPrice", 0) or 0)
    effective_gas_price = int(receipt.get("effectiveGasPrice", gas_price) or gas_price)
    total_cost_wei = gas_used * effective_gas_price
    payload = _base(
        context,
        tag=f"vk:{contract_name}.{function_name}",
        transaction_kind="contract_transaction",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=str(receipt.get("status", "")),
        w3=w3,
    )
    payload.update(
        {
            "to_address": str(tx.get("to", "") or contract_address or ""),
            "value_wei": str(int(tx.get("value", 0) or 0)),
            "transaction_hash": tx_hash.hex() if hasattr(tx_hash, "hex") else str(tx_hash),
            "block_number": str(receipt.get("blockNumber", "")),
            "gas_used": str(gas_used),
            "gas_price_wei": str(gas_price),
            "effective_gas_price_wei": str(effective_gas_price),
            "total_cost_wei": str(total_cost_wei),
            "total_cost_eth": str(w3.from_wei(total_cost_wei, "ether")),
        }
    )
    payload.update({key: value for key, value in details.items() if value is not None})
    append_jsonl(context_log_path(context), payload)


def log_contract_transaction_attempt(
    context: Any,
    *,
    actor_address: str,
    contract_name: str,
    function_name: str,
    contract_address: str,
    status: str,
    error: str = "",
    **details: Any,
) -> None:
    payload = _base(
        context,
        tag=f"vk:{contract_name}.{function_name}",
        transaction_kind="contract_transaction_attempt",
        actor_address=actor_address,
        contract_name=contract_name,
        function_name=function_name,
        contract_address=contract_address,
        status=status,
    )
    payload.update({key: value for key, value in details.items() if value is not None})
    if error:
        payload["error"] = str(error)
    append_jsonl(context_log_path(context), payload)


def install_contract_call_logger(context: Any) -> None:
    global _CALL_LOGGER_INSTALLED, _ORIGINAL_CONTRACT_FUNCTION_CALL
    if _CALL_LOGGER_INSTALLED:
        return
    try:
        from web3.contract.contract import ContractFunction
    except Exception:
        return

    original_call = ContractFunction.call
    _ORIGINAL_CONTRACT_FUNCTION_CALL = original_call

    def logged_call(self, *args, **kwargs):
        fn_name = function_name(self)
        contract_addr = contract_address(self)
        c_name = contract_name_for_address(context, contract_addr)
        actor_address = ""
        tx_params = kwargs.get("transaction")
        if isinstance(tx_params, dict):
            actor_address = str(tx_params.get("from", "") or "")
        try:
            result = original_call(self, *args, **kwargs)
            details: dict[str, Any] = {}
            if isinstance(result, (list, tuple)):
                details["result_count"] = len(result)
            log_eth_call(
                context,
                contract_name=c_name,
                function_name=fn_name,
                contract_address=contract_addr,
                actor_address=actor_address,
                status="success",
                **details,
            )
            return result
        except Exception as exc:
            log_eth_call(
                context,
                contract_name=c_name,
                function_name=fn_name,
                contract_address=contract_addr,
                actor_address=actor_address,
                status="failed",
                error=str(exc),
            )
            raise

    ContractFunction.call = logged_call
    _CALL_LOGGER_INSTALLED = True
