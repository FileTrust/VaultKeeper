from __future__ import annotations


import argparse


import contextlib


import fcntl


import json


import os


import random


import re


import shlex


import shutil


import signal


import subprocess


import sys


import tempfile


import threading


import time


from pathlib import Path


from typing import Any, Optional


import requests


from web3 import Web3


from web3.providers.rpc import HTTPProvider


from vk_http import session as http_session


import vk_txlog as TX


from vk_secret_files import signing_key_args, read_private_key, write_private_text


_SAFE_RPC_PREFIXES = (
    "eth_get", "eth_call", "eth_estimateGas", "eth_blockNumber",
    "eth_chainId", "eth_gasPrice", "eth_maxPriorityFeePerGas",
    "eth_feeHistory", "net_", "web3_",
)


_NOT_YET_VISIBLE = (
    "tx not found",
    "not found: hash",
    "failed to get receipts from comet block",
    "failed to get rpc block",
    "failed to fetch header by number",
    "is not ready",
    "height is not available",
    "requested block height is bigger",
)


def _chain_not_yet_visible(response: dict) -> bool:
    error = response.get("error")
    if not isinstance(error, dict):
        return False
    message = str(error.get("message", "")).lower()
    if "reverted" in message or "invalid" in message:
        return False
    return any(marker in message for marker in _NOT_YET_VISIBLE)


class ResilientReadHTTPProvider(HTTPProvider):
    """Retry VK blockchain reads, but never transaction submission."""

    def __init__(self, endpoint_uri: str):
        session = http_session()
        super().__init__(
            endpoint_uri=endpoint_uri,
            request_kwargs={"timeout": 30},
            session=session,
            # The read-only retry loop below owns retries. Web3's default
            # allowlist also retries eth_sendRawTransaction after transport errors.
            exception_retry_configuration=None,
        )

    def make_request(self, method, params):
        if not str(method).startswith(_SAFE_RPC_PREFIXES):
            return super().make_request(method, params)
        last_error = None
        for attempt in range(4):
            try:
                response = super().make_request(method, params)
                if isinstance(response, dict) and _chain_not_yet_visible(response):
                    # Committed but not readable yet: a Cosmos EVM node indexes a
                    # block just after committing it, and answers reads issued in
                    # between with an error instead of silence. That is a wait,
                    # not a failure, so fall through to the retry below. A revert
                    # or a bad argument is a real answer and returns at once.
                    last_error = ConnectionError(
                        f"JSON-RPC {method} not yet available: "
                        f"{response['error'].get('message', '')}"
                    )
                elif isinstance(response, dict) and (
                    response.get("error") is not None
                    or ("result" in response and response.get("result") is not None)
                ):
                    return response
                last_error = ConnectionError(
                    f"JSON-RPC {method} returned no usable result"
                )
            except (
                requests.RequestException, ConnectionError, ConnectionResetError,
                TimeoutError, OSError,
            ) as exc:
                last_error = exc
            if attempt < 3:
                delay = min(2.0, 0.25 * (2**attempt))
                time.sleep(delay + random.uniform(0.0, min(0.1, delay / 4)))
        raise last_error or ConnectionError(f"JSON-RPC {method} failed")


@contextlib.contextmanager
def account_transaction_lock(address: str):
    """Serialize transactions for one signer across VK processes on this host."""
    normalized = str(address or "").strip().lower().removeprefix("0x")
    if not normalized or any(ch not in "0123456789abcdef" for ch in normalized):
        raise ValueError(f"invalid transaction signer address: {address!r}")
    lock_dir = Path(
        os.getenv("FILETRUST_CHAIN_TX_LOCK_DIR")
        or (Path(tempfile.gettempdir()) / "filetrust-chain-tx-locks")
    )
    lock_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_path = lock_dir / f"{normalized}.lock"
    with lock_path.open("a+b") as lock_file:
        wait_started = time.monotonic()
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        waited = time.monotonic() - wait_started
        if waited >= 0.25:
            print(
                f"[chain-tx] account={normalized} waited={waited:.3f}s for signer lock",
                file=sys.stderr,
                flush=True,
            )
        try:
            yield
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def _sp_fail(msg: str, code: int = 1) -> None:
    print(json.dumps({"ok": False, "err": msg}))
    raise SystemExit(code)


def _sp_load_config() -> dict:
    config_path = os.getenv("STORAGEPROOF_CONFIG") or os.getenv("VK_CONFIG") or ""
    cfg: dict = {}
    if config_path and Path(config_path).is_file():
        cfg = json.loads(Path(config_path).read_text(encoding="utf-8"))

    def get(*names: str, default: str = "") -> str:
        for n in names:
            if os.getenv(n):
                return os.getenv(n)  # type: ignore[return-value]
            if n in cfg and cfg[n] not in (None, ""):
                return cfg[n]
            low = n.lower()
            if low in cfg and cfg[low] not in (None, ""):
                return cfg[low]
        return default

    return {
        "rpc_url":        get("RPC_URL"),
        "address":        get("STORAGEPROOF_ADDRESS"),
        "json":           get("STORAGEPROOF_JSON"),
        "capacity_proof_address": get(
            "CAPACITY_PROOF_ADDRESS", "capacity_proof_address"
        ),
        "capacity_proof_json": get(
            "CAPACITY_PROOF_JSON", "capacity_proof_json",
            default="../../Blockchain/artifacts/contracts/CapacityProofSC.sol/CapacityProofSC.json",
        ),
        "partition_snapshot_proof_address": get(
            "PARTITION_SNAPSHOT_PROOF_ADDRESS", "partition_snapshot_proof_address"
        ),
        "partition_snapshot_proof_json": get(
            "PARTITION_SNAPSHOT_PROOF_JSON", "partition_snapshot_proof_json",
            default="../../Blockchain/artifacts/contracts/PartitionSnapshotProofSC.sol/PartitionSnapshotProofSC.json",
        ),
        "storage_receipt_dispute_address": get(
            "STORAGE_RECEIPT_DISPUTE_ADDRESS", "storage_receipt_dispute_address"
        ),
        "storageproof_staleness_threshold_rounds": int(
            get(
                "STORAGEPROOF_STALENESS_THRESHOLD_ROUNDS",
                "storageproof_staleness_threshold_rounds",
                default="2",
            )
            or 2
        ),
        "filetrust_fixed_gas_price_wei": int(get(
            "FILETRUST_FIXED_GAS_PRICE_WEI", "filetrust_fixed_gas_price_wei", "fixed_gas_price_wei",
            default="1000000",
        )),
        "vk_private_key": read_private_key(get("VK_PRIVATE_KEY_FILE")) if get("VK_PRIVATE_KEY_FILE") else get("VK_PRIVATE_KEY", "PRIVATE_KEY"),
        "vk_address":     get("VK_ADDRESS"),
        "confirmations":  int(get("STORAGEPROOF_CONFIRMATIONS", "storageproof_confirmations", default="1") or 1),
        "transaction_log_path": get("TRANSACTION_LOG_PATH", default=str(TX.default_log_path())),
        "log_eth_calls": str(get("LOG_ETH_CALLS", "log_eth_calls", default="false")).lower() in {"true", "1", "yes", "on"},
    }


def _sp_load_contract(
    w3: Web3,
    address: str,
    artifact_path: str,
    *,
    address_label: str = "STORAGEPROOF_ADDRESS",
    json_label: str = "STORAGEPROOF_JSON",
):
    if not address:
        _sp_fail(f"missing {address_label}")
    if not artifact_path:
        _sp_fail(f"missing {json_label}")
    artifact = json.loads(Path(artifact_path).read_text(encoding="utf-8"))
    abi = artifact["abi"] if isinstance(artifact, dict) and "abi" in artifact else artifact
    return w3.eth.contract(address=w3.to_checksum_address(address), abi=abi)


def _sp_load_partition_snapshot_contract(w3: Web3, storage_contract, cfg: dict):
    configured = str(cfg.get("partition_snapshot_proof_address") or "").strip()
    try:
        linked = Web3.to_checksum_address(
            storage_contract.functions.partitionSnapshotProof().call()
        )
    except Exception as exc:
        _sp_fail(f"StorageProofSC partitionSnapshotProof() lookup failed: {exc}")
    if int(linked, 16) == 0:
        _sp_fail("StorageProofSC partitionSnapshotProof() is not configured")
    if configured:
        configured = Web3.to_checksum_address(configured)
        if configured.lower() != linked.lower():
            _sp_fail(
                "PARTITION_SNAPSHOT_PROOF_ADDRESS does not match "
                f"StorageProofSC link: configured={configured} linked={linked}"
            )
    address = configured or linked
    try:
        code = bytes(w3.eth.get_code(address))
    except Exception as exc:
        _sp_fail(f"cannot read PartitionSnapshotProofSC bytecode at {address}: {exc}")
    if not code:
        _sp_fail(f"PartitionSnapshotProofSC address has no deployed code: {address}")
    contract = _sp_load_contract(
        w3,
        address,
        str(cfg.get("partition_snapshot_proof_json") or ""),
        address_label="PARTITION_SNAPSHOT_PROOF_ADDRESS",
        json_label="PARTITION_SNAPSHOT_PROOF_JSON",
    )
    required = (
        "getFrozenPartitionSnapshotStatus",
        "freezePartitionSnapshot",
        "sealPartitionSnapshot",
        "reanchorFrozenPartitionSnapshot",
        "computeFrozenPartitionDetSeed",
        "expectedFrozenPartitionPublicInputs",
        "submitFrozenPartitionZkProof",
        "abandonFrozenPartitionSnapshot",
    )
    missing = []
    for name in required:
        try:
            getattr(contract.functions, name)
        except Exception:
            missing.append(name)
    if missing:
        _sp_fail(
            "PARTITION_SNAPSHOT_PROOF_JSON ABI is incompatible; missing: "
            + ", ".join(missing)
        )
    return contract


def _sp_load_capacity_proof_contract(w3: Web3, storage_contract, cfg: dict):
    """Load the one CapacityProofSC that StorageProofSC is immutably wired to.

    Refusing a configured/linked address mismatch prevents a VK from declaring
    or advancing capacity on a different ledger than the one used by partition
    registration and admission.
    """
    configured = str(cfg.get("capacity_proof_address") or "").strip()
    try:
        linked = Web3.to_checksum_address(storage_contract.functions.capacityProof().call())
    except Exception as exc:
        _sp_fail(f"StorageProofSC capacityProof() lookup failed: {exc}")
    if int(linked, 16) == 0:
        _sp_fail("StorageProofSC capacityProof() is not configured")
    if configured:
        configured = Web3.to_checksum_address(configured)
        if configured.lower() != linked.lower():
            _sp_fail(
                "CAPACITY_PROOF_ADDRESS does not match StorageProofSC link: "
                f"configured={configured} linked={linked}"
            )
    address = configured or linked
    try:
        code = bytes(w3.eth.get_code(address))
    except Exception as exc:
        _sp_fail(f"cannot read CapacityProofSC bytecode at {address}: {exc}")
    if not code:
        _sp_fail(f"CapacityProofSC address has no deployed code: {address}")
    contract = _sp_load_contract(
        w3,
        address,
        str(cfg.get("capacity_proof_json") or ""),
        address_label="CAPACITY_PROOF_ADDRESS",
        json_label="CAPACITY_PROOF_JSON",
    )
    required = (
        "declareCapacity",
        "beginProofEpoch",
        "abortProofEpoch",
        "getActiveProofEpoch",
        "capacityAccountingOf",
        "maxProofAgeSeconds",
        "maxManifestOverheadBytes",
    )
    missing = []
    for name in required:
        try:
            getattr(contract.functions, name)
        except Exception:
            missing.append(name)
    if missing:
        _sp_fail("CAPACITY_PROOF_JSON ABI is incompatible; missing: " + ", ".join(missing))
    return contract


def _sp_send_tx(w3: Web3, account, fn, value: int = 0, context: dict | None = None,
                explicit_nonce: int | None = None, caller_holds_lock: bool = False) -> str:
    ctx = context or {}
    from_addr = account.address if hasattr(account, "address") else str(account)
    fn_name = TX.function_name(fn, "storageProofTx")
    contract_addr = TX.contract_address(fn)
    gas = 1_200_000
    try:
        # A.2.5: when the Go caller already holds the sender-wide account transaction flock
        # (and has reserved+journalled the exact nonce), do NOT re-acquire it here — that would
        # deadlock against the caller — and use the explicit reserved nonce instead of pending.
        caller_holds_lock = caller_holds_lock or bool(ctx.get("_caller_holds_account_lock"))
        _tx_lock = contextlib.nullcontext() if caller_holds_lock else account_transaction_lock(from_addr)
        with _tx_lock:
            try:
                gas = fn.estimate_gas({"from": from_addr, "value": value})
                TX.log_eth_call(
                    ctx,
                    contract_name="eth",
                    function_name="estimateGas",
                    contract_address=contract_addr,
                    actor_address=from_addr,
                    status="success",
                    gas_estimate=gas,
                    target_function=fn_name,
                    w3=w3,
                )
            except Exception as exc:
                TX.log_eth_call(
                    ctx,
                    contract_name="eth",
                    function_name="estimateGas",
                    contract_address=contract_addr,
                    actor_address=from_addr,
                    status="failed",
                    error=str(exc),
                    target_function=fn_name,
                    w3=w3,
                )
                # Some RPC estimators probe generated Groth16 verifiers with too
                # little gas. The pairing precompile then reports ProofInvalid
                # even though the proof is valid. Simulate once with a generous,
                # block-bounded limit before using a fallback; genuine reverts
                # still fail closed and are never submitted blindly.
                block_gas_limit = int(w3.eth.get_block("latest").gasLimit)
                fallback_limit = min(8_000_000, max(0, block_gas_limit - 100_000))
                if fallback_limit <= 80_000:
                    raise
                try:
                    fn.call({
                        "from": from_addr,
                        "value": value,
                        "gas": fallback_limit,
                    })
                except Exception:
                    raise exc
                gas = fallback_limit - 80_000

            gas_price = int(ctx.get("filetrust_fixed_gas_price_wei", 1_000_000))
            if hasattr(account, "sign_transaction"):
                if explicit_nonce is not None:
                    # Use EXACTLY the reserved nonce; reject a stale one rather than
                    # silently substituting another (which would break the durable lineage).
                    confirmed = w3.eth.get_transaction_count(from_addr, "latest")
                    if int(explicit_nonce) < int(confirmed):
                        raise Exception(
                            f"explicit sender nonce {explicit_nonce} is stale "
                            f"(already consumed; confirmed={confirmed}); refusing to substitute"
                        )
                    nonce = int(explicit_nonce)
                else:
                    nonce = w3.eth.get_transaction_count(from_addr, "pending")
                # Echo the exact nonce used back through the caller's context (not the local
                # `ctx = context or {}`, which may be a fresh dict when context is empty).
                if context is not None:
                    context["_sender_nonce_used"] = int(nonce)
                TX.log_eth_call(
                    ctx,
                    contract_name="eth",
                    function_name="getTransactionCount",
                    actor_address=from_addr,
                    status="success",
                    nonce=nonce,
                    target_function=fn_name,
                    w3=w3,
                )
                TX.log_eth_call(
                    ctx,
                    contract_name="eth",
                    function_name="gasPrice",
                    actor_address=from_addr,
                    status="success",
                    result=gas_price,
                    target_function=fn_name,
                    w3=w3,
                )
                tx = fn.build_transaction({
                    "from":     from_addr,
                    "nonce":    nonce,
                    "gas":      gas + 80_000,
                    "gasPrice": gas_price,
                    "value":    value,
                })
                signed = account.sign_transaction(tx)
                tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
            else:
                tx = {
                    "from": from_addr,
                    "to": contract_addr,
                    "gas": gas + 80_000,
                    "gasPrice": gas_price,
                    "value": value,
                }
                tx_hash = fn.transact({
                    "from": from_addr,
                    "gas": gas + 80_000,
                    "gasPrice": gas_price,
                    "value": value,
                })
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    except Exception as exc:
        TX.log_contract_transaction_attempt(
            ctx,
            actor_address=from_addr,
            contract_name=TX.contract_name_for_address(ctx, contract_addr, "StorageProofSC"),
            function_name=fn_name,
            contract_address=contract_addr,
            status="failed",
            error=str(exc),
            gas_limit=gas + 80_000,
            value_wei=value,
        )
        raise
    TX.log_contract_transaction(
        ctx,
        w3,
        actor_address=from_addr,
        contract_name=TX.contract_name_for_address(ctx, contract_addr, "StorageProofSC"),
        function_name=fn_name,
        contract_address=contract_addr,
        tx=tx,
        tx_hash=tx_hash,
        receipt=receipt,
    )
    if int(receipt.status) != 1:
        _sp_fail(f"tx failed: {tx_hash.hex()}")
    return tx_hash.hex()


def _sp_bytes32(value: str, label: str) -> bytes:
    s = str(value or "").strip()
    if not s:
        _sp_fail(f"missing {label}")
    if not s.startswith("0x"):
        s = "0x" + s
    b = Web3.to_bytes(hexstr=s)
    if len(b) != 32:
        _sp_fail(f"{label} must be bytes32, got {len(b)} bytes")
    return b


def _sp_sector_id_bytes(sector_id: str) -> bytes:
    return Web3.keccak(text=str(sector_id))


def _sp_split_public_inputs(raw) -> list[str]:
    return [str(int(x)) for x in raw]


def _sp_as_proof_bytes(proof_value) -> bytes:
    if isinstance(proof_value, str):
        s = proof_value.strip()
        if not s.startswith("0x"):
            s = "0x" + s
        return Web3.to_bytes(hexstr=s)
    _sp_fail("proof must be hex string produced by the ZK prover")
    return b""


def _sp_open_challenge(w3: Web3, account, contract, req: dict, context: dict) -> None:
    sector        = req.get("sector") or {}
    sector_id     = sector.get("sectorId")
    sector_root   = _sp_bytes32(sector.get("sectorRoot"), "sectorRoot")
    expiration    = int(sector.get("expiration") or 0)
    block_count   = int(sector.get("sectorBlockCount") or len(sector.get("pieceRoots") or []))
    challenge_count = int(req.get("challengeCount") or sector.get("challengeCount") or 4)
    round_id      = int(req.get("round") or contract.functions.currentRound().call())
    sid           = _sp_sector_id_bytes(sector_id)

    tx_reg = _sp_send_tx(
        w3, account,
        contract.functions.registerOrUpdateSector(sid, sector_root, expiration, block_count, challenge_count),
        context=context,
    )

    from_addr  = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    sector_key = contract.functions.sectorKeyOf(from_addr, sid).call()

    try:
        c = contract.functions.challenges(sector_key, int(round_id)).call()
        exists = bool(c[4])
    except Exception:
        exists = False

    tx_open = ""
    if not exists:
        tx_open = _sp_send_tx(w3, account, contract.functions.openChallenge(sid, int(round_id)), context=context)

    c             = contract.functions.challenges(sector_key, int(round_id)).call()
    seed          = c[0]
    public_inputs = contract.functions.expectedPublicInputs(sector_key, int(round_id)).call()
    indexes       = [int(x) for x in public_inputs[7:]]

    print(json.dumps({
        "ok":               True,
        "round":            int(round_id),
        "challengeSeed":    Web3.to_hex(seed),
        "challengeIndexes": indexes,
        "publicInputs":     _sp_split_public_inputs(public_inputs),
        "registerTx":       tx_reg,
        "openTx":           tx_open,
    }))


def _sp_submit_proof(w3: Web3, account, contract, req: dict, context: dict) -> None:
    sector      = req.get("sector") or {}
    proof_obj   = req.get("proof") or {}
    challenge   = req.get("challenge") or {}
    sid         = _sp_sector_id_bytes(sector.get("sectorId"))
    round_id    = int(req.get("round") or challenge.get("round") or proof_obj.get("round") or 0)
    if round_id <= 0:
        _sp_fail("missing round for submit_proof")
    proof_bytes   = _sp_as_proof_bytes(proof_obj.get("proof"))
    public_inputs = [int(x) for x in proof_obj.get("publicInputs") or []]
    if not public_inputs:
        _sp_fail("missing publicInputs in proof result")
    tx_submit = _sp_send_tx(
        w3, account,
        contract.functions.submitZkSectorProof(sid, int(round_id), proof_bytes, public_inputs),
        context=context,
    )
    print(json.dumps({"ok": True, "round": round_id, "submitTx": tx_submit}))


def _sp_build_partition_arrays(w3: Web3, sectors: list) -> tuple:
    """Extract on-chain arrays from a list of SectorMeta dicts."""
    sector_ids, sector_roots, block_counts, piece_commits = [], [], [], []
    for i, s in enumerate(sectors):
        sector_ids.append(_sp_sector_id_bytes(s["sectorId"]))
        sector_roots.append(_sp_bytes32(s["sectorRoot"], f"sectorRoot[{i}]"))
        block_counts.append(int(s["sectorBlockCount"]))
        pc = s.get("zkPieceCommitment") or ""
        if not pc:
            _sp_fail(f"sector {s.get('sectorId')} missing zkPieceCommitment — recompute sector root")
        piece_commits.append(_sp_bytes32(pc, f"pieceCommitment[{i}]"))
    return sector_ids, sector_roots, block_counts, piece_commits


def _sp_register_partition(w3: Web3, account, contract, partition: dict, challenge_count: int, context: dict) -> tuple[bytes, str, int]:
    """Register/update a partition and return its canonical content version."""
    dl_idx     = int(partition.get("deadlineIndex", 0))
    pt_idx     = int(partition.get("partitionIndex", 0))
    sectors    = partition.get("sectors") or []
    expiration = int(partition.get("expiration") or 0)
    sids, sroots, bcounts, pcommits = _sp_build_partition_arrays(w3, sectors)
    try:
        fn = contract.functions.registerOrUpdatePartitionV2(
            dl_idx, pt_idx, sids, sroots, bcounts, pcommits, expiration, challenge_count,
        )
    except Exception:
        # Compatibility for obligations created by a pre-snapshot deployment.
        # New deployments always expose V2; the read below still provides the
        # canonical version after the legacy transaction.
        fn = contract.functions.registerOrUpdatePartition(
            dl_idx, pt_idx, sids, sroots, bcounts, pcommits, expiration, challenge_count,
        )
    tx_hash = _sp_send_tx(w3, account, fn, context=context)
    from_addr = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    p_key = contract.functions.partitionKeyOf(from_addr, dl_idx, pt_idx).call()
    _, content_version, _, _ = contract.functions.getPartitionVersionStatus(p_key).call()
    return p_key, tx_hash, int(content_version)


def _sp_register_partition_only(w3: Web3, account, contract, req: dict, context: dict) -> None:
    partition       = req.get("partition") or {}
    challenge_count = int(req.get("challengeCount") or contract.functions.partitionCircuitChallenges().call())
    pKey, tx_hash, content_version = _sp_register_partition(w3, account, contract, partition, challenge_count, context)
    print(json.dumps({
        "ok":           True,
        "partitionKey": Web3.to_hex(pKey),
        "contentVersion": content_version,
        "registerTx":   tx_hash,
    }))


def _sp_deactivate_partition(w3: Web3, account, contract, req: dict, context: dict) -> None:
    dl_idx = int(req.get("deadlineIndex", 0))
    pt_idx = int(req.get("partitionIndex", 0))
    tx_hash = _sp_send_tx(
        w3, account,
        contract.functions.deactivatePartition(dl_idx, pt_idx),
        context=context,
    )
    from_addr = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    pKey = contract.functions.partitionKeyOf(from_addr, dl_idx, pt_idx).call()
    print(json.dumps({
        "ok":           True,
        "partitionKey": Web3.to_hex(pKey),
        "registerTx":   tx_hash,
    }))


_SP_PARTITION_STATIC_FIELD_INDEX = {
    "vk": 0,
    "partitionKey": 1,
    "deadlineIndex": 2,
    "partitionIndex": 3,
    "partitionKind": 4,
    "committedBytes": 5,
    "expiration": 6,
    "registeredAt": 7,
    "updatedAt": 8,
    "lastProofRound": 9,
    "challengeCount": 10,
    "active": 11,
    "contentHash": 12,
    "contentVersion": 13,
    "lastProvenContentHash": 14,
    "challengeAnchor": 15,
    "anchorBlock": 16,
}


def _sp_partition_static_field(partition_info, name: str):
    try:
        return partition_info[name]
    except Exception:
        pass
    try:
        return getattr(partition_info, name)
    except Exception:
        pass
    idx = _SP_PARTITION_STATIC_FIELD_INDEX[name]
    if idx >= len(partition_info):
        _sp_fail(f"StorageProof partitions() response missing {name}")
    return partition_info[idx]


def _sp_list_active_capacity_partitions(w3: Web3, account, contract, req: dict, context: dict) -> None:
    from_addr = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    out = []
    for p_key in contract.functions.getVkPartitionKeys(from_addr).call():
        info = contract.functions.partitions(p_key).call()
        active = bool(_sp_partition_static_field(info, "active"))
        kind = int(_sp_partition_static_field(info, "partitionKind"))
        if not active or kind != 2:
            continue
        out.append({
            "partitionKey":   Web3.to_hex(p_key),
            "deadlineIndex":  int(_sp_partition_static_field(info, "deadlineIndex")),
            "partitionIndex": int(_sp_partition_static_field(info, "partitionIndex")),
            "partitionKind":  kind,
            "active":         active,
            "committedBytes": int(_sp_partition_static_field(info, "committedBytes")),
            "contentHash":    Web3.to_hex(_sp_partition_static_field(info, "contentHash")),
            "contentVersion": int(_sp_partition_static_field(info, "contentVersion")),
            "challengeCount": int(_sp_partition_static_field(info, "challengeCount")),
        })
    print(json.dumps({
        "ok":                 True,
        "capacityPartitions": out,
    }))


def _sp_list_active_data_partitions(w3: Web3, account, contract, req: dict, context: dict) -> None:
    from_addr = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    out = []
    for p_key in contract.functions.getVkPartitionKeys(from_addr).call():
        info = contract.functions.partitions(p_key).call()
        active = bool(_sp_partition_static_field(info, "active"))
        kind = int(_sp_partition_static_field(info, "partitionKind"))
        if not active or kind != 1:
            continue
        out.append({
            "partitionKey":   Web3.to_hex(p_key),
            "deadlineIndex":  int(_sp_partition_static_field(info, "deadlineIndex")),
            "partitionIndex": int(_sp_partition_static_field(info, "partitionIndex")),
            "partitionKind":  kind,
            "active":         active,
            "committedBytes": int(_sp_partition_static_field(info, "committedBytes")),
            "contentHash":    Web3.to_hex(_sp_partition_static_field(info, "contentHash")),
            "contentVersion": int(_sp_partition_static_field(info, "contentVersion")),
            "challengeCount": int(_sp_partition_static_field(info, "challengeCount")),
        })
    print(json.dumps({
        "ok":             True,
        "dataPartitions": out,
    }))


def _sp_data_lifecycle_guard_status(w3: Web3, account, contract, req: dict, context: dict) -> None:
    file_registration = contract.functions.fileRegistration().call()
    required = bool(contract.functions.dataLifecycleGuardRequired().call())
    print(json.dumps({
        "ok":                True,
        "fileRegistration":  w3.to_checksum_address(file_registration),
        "dataGuardRequired": required,
    }))


def _sp_partition_version_status(w3: Web3, account, contract, req: dict, context: dict) -> None:
    partition = req.get("partition") or {}
    dl_idx = int(partition.get("deadlineIndex", 0))
    pt_idx = int(partition.get("partitionIndex", 0))
    from_addr = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    # Every value in this response must describe the same chain state. Without
    # a pinned block, a proof or partition update mined between these calls can
    # create an impossible mixed response and incorrectly close admission.
    requested_block = int(req.get("blockNumber") or 0)
    latest = w3.eth.get_block(requested_block if requested_block > 0 else "latest")
    snapshot_block = int(latest["number"])
    p_key = contract.functions.partitionKeyOf(from_addr, dl_idx, pt_idx).call(
        block_identifier=snapshot_block,
    )
    content_hash, content_version, last_proven_hash, current_proven = (
        contract.functions.getPartitionVersionStatus(p_key).call(
            block_identifier=snapshot_block,
        )
    )
    _, active, last_proof_round, registered_at = (
        contract.functions.getPartitionProofStatus(p_key).call(
            block_identifier=snapshot_block,
        )
    )
    partition_info = contract.functions.partitions(p_key).call(
        block_identifier=snapshot_block,
    )
    chain_timestamp = int(latest["timestamp"])
    current_round = int(contract.functions.currentRound().call(
        block_identifier=snapshot_block,
    ))
    proof_period_seconds = int(contract.functions.proofPeriodSeconds().call(
        block_identifier=snapshot_block,
    ))
    print(json.dumps({
        "ok": True,
        "blockNumber": snapshot_block,
        "partitionKey": Web3.to_hex(p_key),
        "contentHash": Web3.to_hex(content_hash),
        "contentVersion": int(content_version),
        "lastProvenContentHash": Web3.to_hex(last_proven_hash),
        "currentContentProven": bool(current_proven),
        "partitionActive": bool(active),
        "lastProofRound": int(last_proof_round),
        "registeredAt": int(registered_at),
        "chainTimestamp": chain_timestamp,
        "currentRound": current_round,
        "proofPeriodSeconds": proof_period_seconds,
        "partitionChallengeCount": int(_sp_partition_static_field(partition_info, "challengeCount")),
    }))


def _sp_partition_health_snapshot(w3: Web3, account, contract, req: dict, context: dict) -> None:
    """Read all local partition obligations and W10 policy from one block."""
    requested_block = int(req.get("blockNumber") or 0)
    block = w3.eth.get_block(requested_block if requested_block > 0 else "latest")
    snapshot_block = int(block["number"])
    chain_timestamp = int(block["timestamp"])
    dispute_address = str(context.get("storage_receipt_dispute_address") or "").strip()
    from_addr = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    partition_specs = []
    for partition in req.get("partitions") or []:
        dl_idx = int(partition.get("deadlineIndex", 0))
        pt_idx = int(partition.get("partitionIndex", 0))
        kind = str(partition.get("partitionKind") or "")
        # StorageProofSC computes this as
        # keccak256(abi.encodePacked(address,uint8,uint8)). Deriving it locally
        # removes another RPC call per partition.
        p_key = Web3.solidity_keccak(
            ["address", "uint8", "uint8"], [from_addr, dl_idx, pt_idx]
        )
        partition_specs.append((kind, dl_idx, pt_idx, p_key))

    selector = Web3.keccak(text="stalenessThreshold()")[:4]
    try:
        # One pinned JSON-RPC batch replaces three serial HTTP round trips per
        # partition. web3.py keeps request order and applies each ABI decoder.
        with w3.batch_requests() as batch:
            batch.add(contract.functions.proofPeriodSeconds().call(
                block_identifier=snapshot_block,
            ))
            if dispute_address:
                batch.add(w3.eth.call(
                    {"to": w3.to_checksum_address(dispute_address), "data": selector},
                    block_identifier=snapshot_block,
                ))
            for _, _, _, p_key in partition_specs:
                batch.add(contract.functions.getPartitionVersionStatus(p_key).call(
                    block_identifier=snapshot_block,
                ))
                batch.add(contract.functions.getPartitionProofStatus(p_key).call(
                    block_identifier=snapshot_block,
                ))
                batch.add(contract.functions.partitions(p_key).call(
                    block_identifier=snapshot_block,
                ))
            batch_results = batch.execute()
    except Exception as batch_exc:
        # JSON-RPC batching is standard and supported by FileTrust's Hardhat and
        # Cosmos-EVM endpoints, but an operator's reverse proxy may disable it.
        # Preserve correctness and availability with pinned serial reads; the
        # warning makes the scaling degradation visible instead of silently
        # changing proof-health semantics.
        print(
            f"[storageproof] pinned health batch unavailable at block {snapshot_block}; "
            f"falling back to serial RPC: {batch_exc}",
            file=sys.stderr,
            flush=True,
        )
        try:
            batch_results = [contract.functions.proofPeriodSeconds().call(
                block_identifier=snapshot_block,
            )]
            if dispute_address:
                batch_results.append(w3.eth.call(
                    {"to": w3.to_checksum_address(dispute_address), "data": selector},
                    block_identifier=snapshot_block,
                ))
            for _, _, _, p_key in partition_specs:
                batch_results.append(contract.functions.getPartitionVersionStatus(p_key).call(
                    block_identifier=snapshot_block,
                ))
                batch_results.append(contract.functions.getPartitionProofStatus(p_key).call(
                    block_identifier=snapshot_block,
                ))
                batch_results.append(contract.functions.partitions(p_key).call(
                    block_identifier=snapshot_block,
                ))
        except Exception as serial_exc:
            _sp_fail(
                f"cannot read pinned partition health at block {snapshot_block}: "
                f"batch={batch_exc}; serial={serial_exc}"
            )

    cursor = 0
    proof_period_seconds = int(batch_results[cursor])
    cursor += 1
    threshold = int(context.get("storageproof_staleness_threshold_rounds") or 0)
    if dispute_address:
        threshold = int.from_bytes(bytes(batch_results[cursor]), byteorder="big")
        cursor += 1
    if proof_period_seconds < 1:
        _sp_fail("storage proof period must be positive")
    if threshold < 1:
        _sp_fail("storage proof staleness threshold must be at least one round")
    current_round = chain_timestamp // proof_period_seconds

    statuses = []
    for kind, dl_idx, pt_idx, p_key in partition_specs:
        content_hash, content_version, last_proven_hash, current_proven = batch_results[cursor]
        _, active, last_proof_round, registered_at = batch_results[cursor + 1]
        partition_info = batch_results[cursor + 2]
        cursor += 3
        statuses.append({
            "blockNumber": snapshot_block,
            "partitionKey": Web3.to_hex(p_key),
            "partitionKind": kind,
            "deadlineIndex": dl_idx,
            "partitionIndex": pt_idx,
            "contentHash": Web3.to_hex(content_hash),
            "contentVersion": int(content_version),
            "lastProvenContentHash": Web3.to_hex(last_proven_hash),
            "currentContentProven": bool(current_proven),
            "partitionActive": bool(active),
            "lastProofRound": int(last_proof_round),
            "registeredAt": int(registered_at),
            "chainTimestamp": chain_timestamp,
            "currentRound": current_round,
            "proofPeriodSeconds": proof_period_seconds,
            "partitionChallengeCount": int(_sp_partition_static_field(partition_info, "challengeCount")),
        })
    print(json.dumps({
        "ok": True,
        "blockNumber": snapshot_block,
        "stalenessThreshold": threshold,
        "partitionStatuses": statuses,
    }))


def _sp_proof_clock_status(w3: Web3, account, contract, req: dict, context: dict) -> None:
    """Return one chain-authoritative snapshot for round/deadline scheduling."""
    latest = w3.eth.get_block("latest")
    snapshot_block = int(latest["number"])
    print(json.dumps({
        "ok": True,
        "blockNumber": snapshot_block,
        "chainTimestamp": int(latest["timestamp"]),
        "currentRound": int(contract.functions.currentRound().call(
            block_identifier=snapshot_block,
        )),
        "proofPeriodSeconds": int(contract.functions.proofPeriodSeconds().call(
            block_identifier=snapshot_block,
        )),
    }))


def _sp_partition_challenge_status(w3: Web3, account, contract, req: dict, context: dict) -> None:
    """Read legacy challenge timing without opening or changing a challenge."""
    partition = req.get("partition") or {}
    dl_idx = int(partition.get("deadlineIndex", 0))
    pt_idx = int(partition.get("partitionIndex", 0))
    latest = w3.eth.get_block("latest")
    snapshot_block = int(latest["number"])
    current_round = int(contract.functions.currentRound().call(
        block_identifier=snapshot_block,
    ))
    round_id = int(req.get("round") or current_round)
    from_addr = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    p_key = contract.functions.partitionKeyOf(from_addr, dl_idx, pt_idx).call(
        block_identifier=snapshot_block,
    )
    challenge = contract.functions.partitionChallenges(p_key, round_id).call(
        block_identifier=snapshot_block,
    )
    chain_timestamp = int(latest["timestamp"])
    print(json.dumps({
        "ok": True,
        "blockNumber": snapshot_block,
        "partitionKey": Web3.to_hex(p_key),
        "round": round_id,
        "currentRound": current_round,
        "challengeExists": bool(challenge[4]),
        "challengeDeadline": int(challenge[1]),
        "challengeProven": bool(challenge[5]),
        "chainTimestamp": chain_timestamp,
    }))


def _sp_open_partition_challenge(w3: Web3, account, contract, req: dict, context: dict) -> None:
    partition       = req.get("partition") or {}
    challenge_count = int(req.get("challengeCount") or contract.functions.partitionCircuitChallenges().call())
    round_id        = int(req.get("round") or contract.functions.currentRound().call())

    pKey, _, _ = _sp_register_partition(w3, account, contract, partition, challenge_count, context)

    try:
        c      = contract.functions.partitionChallenges(pKey, round_id).call()
        exists = bool(c[4])
    except Exception:
        exists = False

    tx_open = ""
    if not exists:
        tx_open = _sp_send_tx(w3, account, contract.functions.openPartitionChallenge(pKey, round_id), context=context)

    c             = contract.functions.partitionChallenges(pKey, round_id).call()
    seed          = c[0]
    public_inputs = contract.functions.expectedPartitionPublicInputs(pKey, round_id).call()

    print(json.dumps({
        "ok":            True,
        "partitionKey":  Web3.to_hex(pKey),
        "round":         round_id,
        "challengeSeed": Web3.to_hex(seed),
        "publicInputs":  _sp_split_public_inputs(public_inputs),
        "openTx":        tx_open,
    }))


def _sp_get_partition_challenge_deterministic(w3: Web3, account, contract, req: dict, context: dict) -> None:
    partition       = req.get("partition") or {}
    challenge_count = int(req.get("challengeCount") or contract.functions.partitionCircuitChallenges().call())
    round_id        = int(req.get("round") or contract.functions.currentRound().call())

    # Register/update refreshes the challengeAnchor for deterministic seed derivation.
    pKey, _, _    = _sp_register_partition(w3, account, contract, partition, challenge_count, context)
    det_seed      = contract.functions.computePartitionDetSeed(pKey, round_id).call()
    public_inputs = contract.functions.expectedPartitionPublicInputsDeterministic(pKey, round_id).call()

    print(json.dumps({
        "ok":            True,
        "partitionKey":  Web3.to_hex(pKey),
        "round":         round_id,
        "challengeSeed": Web3.to_hex(det_seed),
        "publicInputs":  _sp_split_public_inputs(public_inputs),
    }))


def _sp_exact_partition_proof_exists(contract, p_key, round_id: int) -> tuple[bool, str]:
    """Check the chain's exact (partition, round, current-content) proof key.

    This is only an optimization. StorageProofSC independently enforces
    idempotency, and older deployed contracts are still handled by the VK's
    post-error exact-state verification.
    """
    try:
        content_hash, _, last_proven_hash, current_proven = (
            contract.functions.getPartitionVersionStatus(p_key).call()
        )
        if not bool(current_proven) or bytes(content_hash) != bytes(last_proven_hash):
            return False, Web3.to_hex(content_hash)
        proven = bool(
            contract.functions.isPartitionContentProven(
                p_key, int(round_id), content_hash,
            ).call()
        )
        return proven, Web3.to_hex(content_hash)
    except Exception:
        return False, ""


def _sp_submit_partition_proof(w3: Web3, account, contract, req: dict, context: dict) -> None:
    p_challenge   = req.get("partitionChallenge") or {}
    proof_obj     = req.get("proof") or {}
    pKey          = _sp_bytes32(p_challenge.get("partitionKey"), "partitionKey")
    round_id      = int(req.get("round") or p_challenge.get("round") or 0)
    if round_id <= 0:
        _sp_fail("missing round for submit_partition_proof")
    proof_bytes   = _sp_as_proof_bytes(proof_obj.get("proof"))
    public_inputs = [int(x) for x in proof_obj.get("publicInputs") or []]
    if not public_inputs:
        _sp_fail("missing publicInputs in proof result")
    already_proven, content_hash = _sp_exact_partition_proof_exists(contract, pKey, round_id)
    if already_proven:
        print(json.dumps({
            "ok": True, "round": round_id, "submitTx": "",
            "alreadyProven": True, "contentHash": content_hash,
        }))
        return
    tx_submit = _sp_send_tx(
        w3, account,
        contract.functions.submitPartitionZkProof(pKey, round_id, proof_bytes, public_inputs),
        context=context,
    )
    print(json.dumps({"ok": True, "round": round_id, "submitTx": tx_submit}))


def _sp_submit_partition_proof_deterministic(w3: Web3, account, contract, req: dict, context: dict) -> None:
    p_challenge   = req.get("partitionChallenge") or {}
    proof_obj     = req.get("proof") or {}
    pKey          = _sp_bytes32(p_challenge.get("partitionKey"), "partitionKey")
    round_id      = int(req.get("round") or p_challenge.get("round") or 0)
    if round_id <= 0:
        _sp_fail("missing round for submit_partition_proof_deterministic")
    proof_bytes   = _sp_as_proof_bytes(proof_obj.get("proof"))
    public_inputs = [int(x) for x in proof_obj.get("publicInputs") or []]
    if not public_inputs:
        _sp_fail("missing publicInputs in proof result")
    already_proven, content_hash = _sp_exact_partition_proof_exists(contract, pKey, round_id)
    if already_proven:
        print(json.dumps({
            "ok": True, "round": round_id, "submitTx": "",
            "alreadyProven": True, "contentHash": content_hash,
        }))
        return
    tx_submit = _sp_send_tx(
        w3, account,
        contract.functions.submitPartitionZkProofDeterministic(pKey, round_id, proof_bytes, public_inputs),
        context=context,
    )
    print(json.dumps({"ok": True, "round": round_id, "submitTx": tx_submit}))


def _sp_snapshot_partition_key(w3: Web3, account, contract, req: dict) -> bytes:
    raw = str(req.get("partitionKey") or "").strip()
    if raw:
        return _sp_bytes32(raw, "partitionKey")
    partition = req.get("partition") or {}
    dl_idx = int(partition.get("deadlineIndex", 0))
    pt_idx = int(partition.get("partitionIndex", 0))
    from_addr = w3.to_checksum_address(
        account.address if hasattr(account, "address") else str(account)
    )
    return contract.functions.partitionKeyOf(from_addr, dl_idx, pt_idx).call()


def _sp_frozen_snapshot_dict(contract, p_key: bytes) -> dict:
    raw = contract.functions.getFrozenPartitionSnapshotStatus(p_key).call()
    if len(raw) < 11:
        _sp_fail("StorageProof frozen snapshot status is incomplete")
    return {
        "snapshotExists": bool(raw[0]),
        "proofEpochId": int(raw[1]),
        "contentVersion": int(raw[2]),
        "contentHash": Web3.to_hex(raw[3]),
        "round": int(raw[4]),
        "anchorBlock": int(raw[5]),
        "challengeSeed": Web3.to_hex(raw[6]),
        "snapshotDeadline": int(raw[7]),
        "snapshotProven": bool(raw[8]),
        "snapshotCurrent": bool(raw[9]),
        "snapshotNonce": int(raw[10]),
    }


def _sp_print_frozen_snapshot(contract, p_key: bytes, **extra) -> None:
    out = {
        "ok": True,
        "partitionKey": Web3.to_hex(p_key),
        **_sp_frozen_snapshot_dict(contract, p_key),
        **extra,
    }
    print(json.dumps(out))


def _sp_frozen_partition_snapshot_status(w3: Web3, account, storage_contract, snapshot_contract, req: dict, context: dict) -> None:
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    _sp_print_frozen_snapshot(snapshot_contract, p_key)


def _sp_freeze_partition_snapshot(w3: Web3, account, storage_contract, snapshot_contract, req: dict, context: dict) -> None:
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    proof_epoch_id = int(req.get("proofEpochId") or 0)
    round_id = int(req.get("round") or storage_contract.functions.currentRound().call())
    if proof_epoch_id <= 0:
        _sp_fail("proofEpochId is required for frozen partition snapshots")
    status = _sp_frozen_snapshot_dict(snapshot_contract, p_key)
    tx_hash = ""
    if status["snapshotExists"]:
        if status["proofEpochId"] != proof_epoch_id or status["round"] != round_id:
            _sp_fail(
                "a different frozen snapshot already exists: "
                f"epoch={status['proofEpochId']} round={status['round']} "
                f"requestedEpoch={proof_epoch_id} requestedRound={round_id}"
            )
    else:
        explicit_nonce = int(req["senderTxNonce"]) if req.get("hasSenderTxNonce") else None
        caller_holds_lock = bool(req.get("callerHoldsAccountLock"))
        tx_hash = _sp_send_tx(
            w3, account,
            snapshot_contract.functions.freezePartitionSnapshot(
                p_key, proof_epoch_id, round_id
            ),
            context=context,
            explicit_nonce=explicit_nonce,
            caller_holds_lock=caller_holds_lock,
        )
    _sp_print_frozen_snapshot(
        snapshot_contract, p_key, openTx=tx_hash,
        senderNonce=int(context.get("_sender_nonce_used", 0)),
    )


def _sp_seal_partition_snapshot(w3: Web3, account, storage_contract, snapshot_contract, req: dict, context: dict) -> None:
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    expected_version = int(req.get("contentVersion") or 0)
    status = _sp_frozen_snapshot_dict(snapshot_contract, p_key)
    if not status["snapshotExists"]:
        _sp_fail("no frozen partition snapshot exists")
    if expected_version and status["contentVersion"] != expected_version:
        _sp_fail(
            f"frozen snapshot version mismatch: chain={status['contentVersion']} requested={expected_version}"
        )
    tx_hash = ""
    if int(status["challengeSeed"], 16) == 0:
        tx_hash = _sp_send_tx(
            w3, account, snapshot_contract.functions.sealPartitionSnapshot(p_key), context=context,
        )
    _sp_print_frozen_snapshot(snapshot_contract, p_key, openTx=tx_hash)


def _sp_reanchor_frozen_partition_snapshot(
    w3: Web3,
    account,
    storage_contract,
    snapshot_contract,
    req: dict,
    context: dict,
) -> None:
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    expected_epoch = int(req.get("proofEpochId") or 0)
    expected_version = int(req.get("contentVersion") or 0)
    expected_round = int(req.get("round") or 0)
    expected_hash = str(req.get("contentHash") or "").strip()
    expected_nonce = int(req.get("snapshotNonce") or 0)
    if expected_epoch <= 0 or expected_version <= 0 or expected_round <= 0:
        _sp_fail("proofEpochId, contentVersion, and round are required to reanchor a snapshot")
    if not expected_hash or expected_nonce <= 0:
        _sp_fail("contentHash and snapshotNonce are required to reanchor a snapshot")
    status = _sp_frozen_snapshot_dict(snapshot_contract, p_key)
    if not status["snapshotExists"]:
        _sp_fail("no frozen partition snapshot exists")
    if (
        status["proofEpochId"] != expected_epoch
        or status["contentVersion"] != expected_version
        or status["round"] != expected_round
        or status["contentHash"].lower() != expected_hash.lower()
        or status["snapshotNonce"] != expected_nonce
    ):
        _sp_fail(
            "refuse to reanchor a different snapshot: "
            f"chainEpoch={status['proofEpochId']} chainVersion={status['contentVersion']} "
            f"chainRound={status['round']} chainNonce={status['snapshotNonce']}"
        )
    tx_hash = _sp_send_tx(
        w3,
        account,
        snapshot_contract.functions.reanchorFrozenPartitionSnapshot(
            p_key, expected_version, expected_round,
            expected_epoch, Web3.to_bytes(hexstr=expected_hash), expected_nonce,
        ),
        context=context,
    )
    _sp_print_frozen_snapshot(snapshot_contract, p_key, openTx=tx_hash)


def _sp_expected_frozen_partition_public_inputs(w3: Web3, account, storage_contract, snapshot_contract, req: dict, context: dict) -> None:
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    proof_epoch_id = int(req.get("proofEpochId") or 0)
    content_version = int(req.get("contentVersion") or 0)
    round_id = int(req.get("round") or 0)
    if proof_epoch_id <= 0 or content_version <= 0 or round_id <= 0:
        _sp_fail("proofEpochId, contentVersion, and round are required for frozen partition inputs")
    status = _sp_frozen_snapshot_dict(snapshot_contract, p_key)
    if (
        not status["snapshotExists"]
        or status["proofEpochId"] != proof_epoch_id
        or status["contentVersion"] != content_version
        or status["round"] != round_id
    ):
        _sp_fail("requested frozen partition generation does not exist")
    seed = snapshot_contract.functions.computeFrozenPartitionDetSeed(
        p_key, content_version, round_id,
    ).call()
    public_inputs = snapshot_contract.functions.expectedFrozenPartitionPublicInputs(
        p_key, content_version, round_id,
    ).call()
    print(json.dumps({
        "ok": True,
        "partitionKey": Web3.to_hex(p_key),
        "proofEpochId": proof_epoch_id,
        "contentVersion": content_version,
        "round": round_id,
        "challengeSeed": Web3.to_hex(seed),
        "publicInputs": _sp_split_public_inputs(public_inputs),
    }))


def _sp_submit_frozen_partition_zk_proof(w3: Web3, account, storage_contract, snapshot_contract, req: dict, context: dict) -> None:
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    proof_epoch_id = int(req.get("proofEpochId") or 0)
    content_version = int(req.get("contentVersion") or 0)
    round_id = int(req.get("round") or 0)
    proof_obj = req.get("proof") or {}
    proof_bytes = _sp_as_proof_bytes(proof_obj.get("proof"))
    public_inputs = [int(x) for x in proof_obj.get("publicInputs") or []]
    content_hash = str(req.get("contentHash") or "").strip()
    snapshot_nonce = int(req.get("snapshotNonce") or 0)
    if proof_epoch_id <= 0 or content_version <= 0 or round_id <= 0 or not public_inputs:
        _sp_fail("proofEpochId, contentVersion, round, and publicInputs are required for frozen proof submission")
    if not content_hash or snapshot_nonce <= 0:
        _sp_fail("contentHash and snapshotNonce are required for frozen proof submission")
    status = _sp_frozen_snapshot_dict(snapshot_contract, p_key)
    if (
        status["snapshotProven"]
        and status["proofEpochId"] == proof_epoch_id
        and status["contentVersion"] == content_version
        and status["round"] == round_id
    ):
        print(json.dumps({
            "ok": True, "partitionKey": Web3.to_hex(p_key),
            "proofEpochId": proof_epoch_id,
            "contentVersion": content_version, "round": round_id,
            "snapshotNonce": snapshot_nonce,
            "submitTx": "", "alreadyProven": True,
        }))
        return
    tx_hash = _sp_send_tx(
        w3, account,
        snapshot_contract.functions.submitFrozenPartitionZkProof(
            p_key, content_version, proof_epoch_id, round_id,
            Web3.to_bytes(hexstr=content_hash), snapshot_nonce,
            proof_bytes, public_inputs,
        ),
        context=context,
    )
    print(json.dumps({
        "ok": True, "partitionKey": Web3.to_hex(p_key),
        "proofEpochId": proof_epoch_id,
        "contentVersion": content_version, "round": round_id,
        "snapshotNonce": snapshot_nonce,
        "submitTx": tx_hash,
    }))


def _sp_abandon_frozen_partition_snapshot(w3: Web3, account, storage_contract, snapshot_contract, req: dict, context: dict) -> None:
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    expected_epoch = int(req.get("proofEpochId") or 0)
    expected_version = int(req.get("contentVersion") or 0)
    expected_hash = str(req.get("contentHash") or "").strip()
    expected_nonce = int(req.get("snapshotNonce") or 0)
    status = _sp_frozen_snapshot_dict(snapshot_contract, p_key)
    tx_hash = ""
    if status["snapshotExists"]:
        if expected_epoch <= 0 or expected_version <= 0 or not expected_hash or expected_nonce <= 0:
            _sp_fail(
                "proofEpochId, contentVersion, contentHash, and snapshotNonce are required "
                "to abandon a frozen snapshot"
            )
        if status["proofEpochId"] != expected_epoch:
            _sp_fail(
                f"refuse to abandon epoch {status['proofEpochId']} as requested epoch {expected_epoch}"
            )
        if status["contentVersion"] != expected_version:
            _sp_fail(
                f"refuse to abandon version {status['contentVersion']} as requested version {expected_version}"
            )
        if status["contentHash"].lower() != expected_hash.lower():
            _sp_fail("refuse to abandon a snapshot with a different content hash")
        if status["snapshotNonce"] != expected_nonce:
            _sp_fail(
                f"refuse to abandon snapshot generation {status['snapshotNonce']} "
                f"as requested generation {expected_nonce}"
            )
        tx_hash = _sp_send_tx(
            w3, account,
            snapshot_contract.functions.abandonFrozenPartitionSnapshot(
                p_key, expected_version, expected_epoch,
                Web3.to_bytes(hexstr=expected_hash), expected_nonce,
            ),
            context=context,
        )
    print(json.dumps({
        "ok": True, "partitionKey": Web3.to_hex(p_key),
        "proofEpochId": expected_epoch,
        "contentVersion": expected_version,
        "snapshotNonce": expected_nonce, "registerTx": tx_hash,
    }))


def _sp_capacity_proof_status(w3: Web3, account, capacity_contract, req: dict, context: dict) -> None:
    vk = w3.to_checksum_address(
        account.address if hasattr(account, "address") else str(account)
    )
    epoch = capacity_contract.functions.getActiveProofEpoch(vk).call()
    if len(epoch) < 8:
        _sp_fail("CapacityProof epoch status is incomplete")
    accounting = capacity_contract.functions.capacityAccountingOf(vk).call()
    if len(accounting) < 10:
        _sp_fail("CapacityProof accounting status is incomplete")
    checkpoint = capacity_contract.functions.capacityCheckpointOf(vk).call()
    if len(checkpoint) < 8:
        _sp_fail("CapacityProof checkpoint status is incomplete")
    print(json.dumps({
        "ok": True,
        "proofEpochId": int(epoch[0]),
        "round": int(epoch[1]),
        "epochCutoffNonce": int(epoch[2]),
        "epochExpectedPartitions": int(epoch[3]),
        "epochProvenPartitions": int(epoch[4]),
        "epochExpectedBytes": int(epoch[5]),
        "epochActive": bool(epoch[6]),
        "epochInvalidated": bool(epoch[7]),
        "declaredCapacityBytes": int(accounting[0]),
        "registeredFreeBytes": int(accounting[1]),
        "registeredDataBytes": int(accounting[2]),
        "provedFreeBytes": int(accounting[3]),
        "provedDataBytes": int(accounting[4]),
        "quoteReservedBytes": int(accounting[5]),
        "allocatedStoredBytes": int(accounting[6]),
        "conservativeFreeBytes": int(accounting[7]),
        "lastCapacityProofAt": int(accounting[8]),
        "capacityProofFresh": bool(accounting[9]),
        "capacityProofSequence": int(checkpoint[4]),
        "provedBackingBytes": int(checkpoint[3]),
        "checkpointFreeBytes": int(checkpoint[0]),
        "checkpointDataBytes": int(checkpoint[1]),
        "checkpointProofRound": int(checkpoint[5]),
        "checkpointProofAt": int(checkpoint[6]),
        "maxProofAgeSeconds": int(capacity_contract.functions.maxProofAgeSeconds().call()),
        "maxManifestOverheadBytes": int(
            capacity_contract.functions.maxManifestOverheadBytes().call()
        ),
    }))


def _sp_capacity_epoch_exclusion_status(
    w3: Web3, account, storage_contract, capacity_contract, req: dict, context: dict
) -> None:
    vk = w3.to_checksum_address(
        account.address if hasattr(account, "address") else str(account)
    )
    epoch_id = int(req.get("proofEpochId") or 0)
    if epoch_id <= 0:
        _sp_fail("proofEpochId is required for capacity epoch exclusion status")
    p_key = _sp_snapshot_partition_key(w3, account, storage_contract, req)
    exclusion = capacity_contract.functions.getProofEpochExclusion(
        vk, epoch_id, p_key
    ).call()
    if len(exclusion) < 4:
        _sp_fail("capacity epoch exclusion status is incomplete")
    print(json.dumps({
        "ok": True,
        "partitionKey": Web3.to_hex(p_key),
        "proofEpochId": epoch_id,
        "epochVersionExcluded": bool(exclusion[0]),
        "contentVersion": int(exclusion[1]),
        "contentHash": Web3.to_hex(exclusion[2]),
        "excludedBytes": int(exclusion[3]),
    }))


def _sp_begin_capacity_proof_epoch(w3: Web3, account, capacity_contract, req: dict, context: dict) -> None:
    vk = w3.to_checksum_address(
        account.address if hasattr(account, "address") else str(account)
    )
    epoch_id = int(req.get("proofEpochId") or 0)
    round_id = int(req.get("round") or 0)
    batch_mode = int(req.get("batchMode") or 0)
    if epoch_id <= 0 or round_id <= 0:
        _sp_fail("proofEpochId and round are required to begin a capacity proof epoch")
    if batch_mode < 2 or batch_mode > 7:
        _sp_fail(f"full capacity proof epoch requires batchMode 2..7, got {batch_mode}")
    before = capacity_contract.functions.getActiveProofEpoch(vk).call()
    if bool(before[6]):
        if int(before[0]) != epoch_id or int(before[1]) != round_id:
            _sp_fail(
                f"different capacity epoch already active: epoch={before[0]} round={before[1]}"
            )
        print(json.dumps({
            "ok": True,
            "proofEpochId": epoch_id,
            "round": round_id,
            "batchMode": batch_mode,
            "alreadyActive": True,
        }))
        return
    if int(before[0]) >= epoch_id:
        _sp_fail(f"capacity epoch id {epoch_id} is not newer than chain epoch {before[0]}")
    tx_hash = _sp_send_tx(
        w3, account,
        capacity_contract.functions.beginProofEpoch(epoch_id, round_id, batch_mode),
        context=context,
    )
    print(json.dumps({
        "ok": True,
        "proofEpochId": epoch_id,
        "round": round_id,
        "batchMode": batch_mode,
        "openTx": tx_hash,
    }))


def _sp_abort_capacity_proof_epoch(w3: Web3, account, capacity_contract, req: dict, context: dict) -> None:
    vk = w3.to_checksum_address(
        account.address if hasattr(account, "address") else str(account)
    )
    epoch_id = int(req.get("proofEpochId") or 0)
    if epoch_id <= 0:
        _sp_fail("proofEpochId is required to abort a capacity proof epoch")
    status = capacity_contract.functions.getActiveProofEpoch(vk).call()
    if int(status[0]) != epoch_id:
        _sp_fail(f"capacity epoch mismatch: chain={status[0]} requested={epoch_id}")
    tx_hash = ""
    if bool(status[6]):
        tx_hash = _sp_send_tx(
            w3, account, capacity_contract.functions.abortProofEpoch(epoch_id), context=context
        )
    print(json.dumps({"ok": True, "proofEpochId": epoch_id, "registerTx": tx_hash}))


def _sp_capacity_incremental_batch_members(
    w3: Web3, account, contract, snapshot_contract, req: dict, context: dict
) -> None:
    """CHAIN-AUTHORITATIVE member enumeration (recovery uses this when local records are gone).
    Mirrors CapacityIncrementalBatchSC.selectedMemberKeys/selectedMember. `frozen` is reported False
    to match the D.3 adapter: the recovery only parses a member when it is frozen, and the contract's
    own abandon precondition (a live selected snapshot) is the real guard, so an empty/false-frozen
    member set lets recovery proceed straight to the guarded abandon."""
    vk = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    ib = _sp_load_incremental_batch_contract(w3, snapshot_contract, context)
    want = int(req.get("proofEpochID") or req.get("proofEpochId") or 0)
    active_batch = int(ib.functions.activeBatchIdOf(vk).call())
    batch_id = want or active_batch
    members = []
    if batch_id:
        for key in ib.functions.selectedMemberKeys(batch_id).call():
            exists, accepted = ib.functions.selectedMemberAccepted(batch_id, key).call()
            if not exists:
                continue
            members.append({"key": Web3.to_hex(key), "accepted": bool(accepted), "frozen": False})
    print(json.dumps({
        "ok": True,
        "incrementalBatchId": batch_id,
        "incrementalBatchActive": bool(active_batch and active_batch == batch_id),
        "members": members,
    }))


def _sp_abandon_incremental_batch(
    w3: Web3, account, contract, snapshot_contract, req: dict, context: dict
) -> None:
    """Safe abandon of a stuck incremental batch via PartitionSnapshotProofSC.abandonIncrementalBatch.
    The contract refuses while any selected-but-unaccepted member still holds a live frozen snapshot,
    so this is not a force-unlock; a revert surfaces as an error for the caller to retry."""
    reason = int(req.get("abandonReason") or req.get("reason") or 0)
    if reason < 1 or reason > 4:
        _sp_fail("abandon_incremental_batch requires reason 1..4")
    vk = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    ib = _sp_load_incremental_batch_contract(w3, snapshot_contract, context)
    active_batch = int(ib.functions.activeBatchIdOf(vk).call())
    if active_batch == 0:
        print(json.dumps({"ok": True, "batchActive": False, "registerTx": ""}))
        return
    tx_hash = _sp_send_tx(
        w3, account, snapshot_contract.functions.abandonIncrementalBatch(reason), context=context
    )
    print(json.dumps({
        "ok": True, "batchId": active_batch, "batchActive": False, "registerTx": tx_hash,
    }))


def _sp_load_incremental_batch_contract(w3: Web3, snapshot_contract, cfg: dict):
    address = snapshot_contract.functions.incrementalBatch().call()
    base = str(cfg.get("partition_snapshot_proof_json") or cfg.get("capacity_proof_json") or "")
    path = str(Path(base).parent / "CapacityIncrementalBatchSC.json")
    return _sp_load_contract(
        w3, address, path,
        address_label="INCREMENTAL_BATCH_ADDRESS", json_label="INCREMENTAL_BATCH_JSON",
    )


def _sp_load_certification_contract(w3: Web3, capacity_contract, cfg: dict):
    address = capacity_contract.functions.certificationContract().call()
    path = str(Path(str(cfg.get("capacity_proof_json") or "")).parent / "CapacityCertificationSC.json")
    return _sp_load_contract(
        w3, address, path,
        address_label="CERTIFICATION_ADDRESS", json_label="CERTIFICATION_JSON",
    )


def _sp_capacity_incremental_batch_status(
    w3: Web3, account, contract, snapshot_contract, req: dict, context: dict
) -> None:
    """Batch membership counts/bytes + the capacity epoch/accounting fields the binary
    also parses out of this response (same shape as capacity_proof_status)."""
    vk = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    ib = _sp_load_incremental_batch_contract(w3, snapshot_contract, context)
    want = int(req.get("proofEpochID") or req.get("proofEpochId") or 0)
    active_batch = int(ib.functions.activeBatchIdOf(vk).call())
    batch_id = want or active_batch
    target_round = cutoff_nonce = 0
    selected = accepted = selected_bytes = accepted_bytes = 0
    batch_active = batch_complete = False
    if batch_id:
        batch = ib.functions.batches(batch_id).call()
        target_round = int(batch[2])
        cutoff_nonce = int(batch[3])
        selected = int(batch[5])
        accepted = int(batch[6])
        selected_bytes = int(batch[7])
        accepted_bytes = int(batch[8])
        batch_active = bool(batch[9])
        batch_complete = bool(batch[10])
    capacity = _sp_load_capacity_proof_contract(w3, contract, context)
    epoch = capacity.functions.getActiveProofEpoch(vk).call()
    acct = capacity.functions.capacityAccountingOf(vk).call()
    checkpoint = capacity.functions.capacityCheckpointOf(vk).call()
    if len(checkpoint) < 8:
        _sp_fail("CapacityProof checkpoint status is incomplete")
    print(json.dumps({
        "ok": True,
        "incrementalBatchId": batch_id,
        "incrementalBatchActive": bool(active_batch == batch_id and batch_active),
        "incrementalBatchComplete": batch_complete,
        "incrementalSelectedPartitions": selected,
        "incrementalAcceptedPartitions": accepted,
        "incrementalSelectedBytes": selected_bytes,
        "incrementalAcceptedBytes": accepted_bytes,
        "round": target_round,
        "epochCutoffNonce": cutoff_nonce,
        "proofEpochId": int(epoch[0]),
        "epochActive": bool(epoch[6]),
        "declaredCapacityBytes": int(acct[0]),
        "registeredFreeBytes": int(acct[1]),
        "registeredDataBytes": int(acct[2]),
        "provedFreeBytes": int(acct[3]),
        "provedDataBytes": int(acct[4]),
        "quoteReservedBytes": int(acct[5]),
        "allocatedStoredBytes": int(acct[6]),
        "conservativeFreeBytes": int(acct[7]),
        "lastCapacityProofAt": int(acct[8]),
        "capacityProofFresh": bool(acct[9]),
        # Keep this response ledger-compatible with capacity_proof_status.
        # The Go scheduler validates durable full-baseline provenance even
        # while an incremental campaign owns the proof lane. Omitting these
        # fields made their zero-value decode look like a corrupt baseline.
        "capacityProofSequence": int(checkpoint[4]),
        "provedBackingBytes": int(checkpoint[3]),
        "checkpointFreeBytes": int(checkpoint[0]),
        "checkpointDataBytes": int(checkpoint[1]),
        "checkpointProofRound": int(checkpoint[5]),
        "checkpointProofAt": int(checkpoint[6]),
        "maxProofAgeSeconds": int(capacity.functions.maxProofAgeSeconds().call()),
        "maxManifestOverheadBytes": int(capacity.functions.maxManifestOverheadBytes().call()),
    }))


def _sp_open_capacity_incremental_batch(
    w3: Web3, account, contract, snapshot_contract, req: dict, context: dict
) -> None:
    """Opens an incremental batch on CapacityIncrementalBatchSC over the exact selected
    membership. Converts logical 'kind:dl:pt' keys to on-chain partition keys via partitionKeyOf."""
    vk = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    target_round = int(req.get("round") or 0)
    raw_keys = req.get("partitionKeys") or []
    if target_round <= 0 or not raw_keys:
        _sp_fail("open_capacity_incremental_batch requires round and exact membership")
    chain_keys = []
    for raw in raw_keys:
        s = str(raw).strip()
        if s.startswith("0x") and len(s) == 66:
            chain_keys.append(Web3.to_bytes(hexstr=s))
            continue
        parts = s.replace("dl", "").replace("pt", "").split(":")
        if len(parts) != 3:
            _sp_fail(f"unparseable selection key: {s}")
        dl_idx, pt_idx = int(parts[1]), int(parts[2])
        chain_keys.append(contract.functions.partitionKeyOf(vk, dl_idx, pt_idx).call())
    ib = _sp_load_incremental_batch_contract(w3, snapshot_contract, context)
    open_tx = _sp_send_tx(w3, account, ib.functions.openBatch(target_round, chain_keys), context=context)
    batch_id = int(ib.functions.activeBatchIdOf(vk).call())
    batch = ib.functions.batches(batch_id).call()
    print(json.dumps({
        "ok": True, "openTx": open_tx, "round": target_round,
        "incrementalBatchId": batch_id, "incrementalBatchActive": batch_id != 0,
        "incrementalBatchComplete": False,
        "incrementalSelectedPartitions": int(batch[5]),
        "incrementalAcceptedPartitions": int(batch[6]),
        "incrementalSelectedBytes": int(batch[7]),
        "incrementalAcceptedBytes": int(batch[8]),
    }))


def _sp_certified_capacity_admission_status(
    w3: Web3, account, capacity_contract, req: dict, context: dict
) -> None:
    """Certified free/data capacity for the admission gate."""
    vk = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    cert = _sp_load_certification_contract(w3, capacity_contract, context)
    block = w3.eth.block_number
    acct = capacity_contract.functions.capacityAccountingOf(vk).call(block_identifier=block)
    ring_free = int(cert.functions.certifiedFree(vk).call(block_identifier=block))
    # G.5's fresh certified value is clamped only by the allocation ledger. Quote reservations
    # and the admission margin are applied later when safeAllocatable is computed; using
    # conservativeFreeCapacity here would incorrectly mix in the full-sweep checkpoint.
    ledger_free = max(0, int(acct[0]) - int(acct[6]))
    chain_ts = int(w3.eth.get_block(block)["timestamp"])
    print(json.dumps({
        "ok": True,
        "freshCertifiedFreeCapacity": min(ring_free, ledger_free),
        "ringCertifiedFreeCapacity": ring_free,
        "allocatedStoredBytes": int(acct[6]),
        "certifiedDataBytes": int(cert.functions.certifiedData(vk).call(block_identifier=block)),
        "expiredCertifiedBytes": 0,
        "certificationObservationBlock": int(block),
        "certificationChainTimestamp": chain_ts,
    }))


def _sp_capacity_incremental_selection_snapshot(
    w3: Web3, account, contract, snapshot_contract, req: dict, context: dict
) -> None:
    """Per-partition pinned identity + certification for the incremental selection view.
    Canonical hash comes from the contract's certificationIdentityHash (not the simulator's sha256)."""
    vk = w3.to_checksum_address(account.address if hasattr(account, "address") else str(account))
    capacity = _sp_load_capacity_proof_contract(w3, contract, context)
    cert = _sp_load_certification_contract(w3, capacity, context)
    requested_block = int(req.get("blockNumber") or 0)
    block_info = w3.eth.get_block(requested_block if requested_block > 0 else "latest")
    block = int(block_info["number"])
    current_slot = int(cert.functions.currentCertificationSlot().call(block_identifier=block))
    entries = []
    for meta in req.get("partitions", []) or []:
        dl_idx = int(meta.get("deadlineIndex", 0) or 0)
        pt_idx = int(meta.get("partitionIndex", 0) or 0)
        p_key = contract.functions.partitionKeyOf(vk, dl_idx, pt_idx).call(block_identifier=block)
        info = contract.functions.partitions(p_key).call(block_identifier=block)
        active = bool(_sp_partition_static_field(info, "active"))
        kind = int(_sp_partition_static_field(info, "partitionKind"))
        content_version = int(_sp_partition_static_field(info, "contentVersion"))
        content_hash = _sp_partition_static_field(info, "contentHash")
        committed = int(_sp_partition_static_field(info, "committedBytes"))
        challenge_count = int(_sp_partition_static_field(info, "challengeCount"))
        canonical = cert.functions.certificationIdentityHash(
            p_key, kind, active, content_version, content_hash, committed
        ).call(block_identifier=block)
        rec = cert.functions.partitionCertifications(p_key).call(
            block_identifier=block,
        )  # (vk, provedAt, expirySlot, bytes, kind, idHash)
        cert_expiry = int(rec[2]); cert_bytes = int(rec[3]); proved_at = int(rec[1]); cert_id_hash = rec[5]
        exists = cert_expiry > 0
        logical = ("capacity" if kind == 2 else "data") + f":{dl_idx}:{pt_idx}"
        entries.append({
            "identity": {
                "partitionKey": logical, "vk": vk,
                "kind": "capacity" if kind == 2 else "data",
                "active": active, "contentVersion": content_version,
                "contentHash": Web3.to_hex(content_hash), "committedBytes": committed,
                "registeredAt": int(_sp_partition_static_field(info, "registeredAt")),
            },
            "certification": {
                "exists": exists,
                "vk": w3.to_checksum_address(rec[0]) if exists else "",
                "provedAt": proved_at, "certifiedExpirySlot": cert_expiry,
                "certifiedBytes": cert_bytes,
                "certifiedKind": (
                    "capacity" if (int(rec[4]) if exists else kind) == 2 else "data"
                ),
                "certifiedIdentityHash": Web3.to_hex(cert_id_hash),
            },
            "canonicalIdentityHash": Web3.to_hex(canonical),
            "chainPartitionKey": Web3.to_hex(p_key),
            "challengeCount": challenge_count,
        })
    active_capacity_keys = []
    for p_key in contract.functions.getVkPartitionKeys(vk).call(block_identifier=block):
        info = contract.functions.partitions(p_key).call(block_identifier=block)
        if (bool(_sp_partition_static_field(info, "active")) and
                int(_sp_partition_static_field(info, "partitionKind")) == 2):
            active_capacity_keys.append(Web3.to_hex(p_key))
    print(json.dumps({
        "ok": True, "blockNumber": int(block),
        "currentCertificationSlot": current_slot,
        "capacitySelectionEntries": entries,
        "activeCapacityPartitionKeys": sorted(active_capacity_keys),
    }))


def run_storageproof_client_mode() -> int:
    try:
        req = json.loads(sys.stdin.read() or "{}")
    except Exception as exc:
        _sp_fail(f"invalid stdin json: {exc}")
    cfg = _sp_load_config()
    # Go serializes transaction-producing chain commands with the same sender flock used by
    # this client. Reuse that ownership instead of recursively locking in the child process.
    cfg["_caller_holds_account_lock"] = bool(req.get("callerHoldsAccountLock"))
    TX.install_contract_call_logger(cfg)
    if not cfg["rpc_url"]:
        _sp_fail("missing RPC_URL")
    if not cfg["vk_private_key"] and not cfg["vk_address"]:
        _sp_fail("missing VK_PRIVATE_KEY or VK_ADDRESS")
    w3 = Web3(ResilientReadHTTPProvider(cfg["rpc_url"]))
    if not w3.is_connected():
        _sp_fail(f"cannot connect to RPC {cfg['rpc_url']}")
    account = (
        w3.eth.account.from_key(cfg["vk_private_key"])
        if cfg["vk_private_key"]
        else w3.to_checksum_address(cfg["vk_address"])
    )
    action   = str(req.get("action") or "").strip()
    contract = _sp_load_contract(w3, cfg["address"], cfg["json"])
    snapshot_actions = {
        "frozen_partition_snapshot_status",
        "freeze_partition_snapshot",
        "seal_partition_snapshot",
        "reanchor_frozen_partition_snapshot",
        "expected_frozen_partition_public_inputs",
        "submit_frozen_partition_zk_proof",
        "abandon_frozen_partition_snapshot",
        "capacity_incremental_batch_members",
        "abandon_incremental_batch",
        "capacity_incremental_batch_status",
        "open_capacity_incremental_batch",
        "capacity_incremental_selection_snapshot",
    }
    capacity_actions = {
        "capacity_proof_status",
        "capacity_epoch_exclusion_status",
        "begin_capacity_proof_epoch",
        "abort_capacity_proof_epoch",
        "declare_capacity",
        "certified_capacity_admission_status",
    }
    snapshot_contract = (
        _sp_load_partition_snapshot_contract(w3, contract, cfg)
        if action in snapshot_actions
        else None
    )
    capacity_contract = (
        _sp_load_capacity_proof_contract(w3, contract, cfg)
        if action in capacity_actions
        else None
    )
    if action == "open_challenge":
        _sp_open_challenge(w3, account, contract, req, cfg)
    elif action == "submit_proof":
        _sp_submit_proof(w3, account, contract, req, cfg)
    elif action == "open_partition_challenge":
        _sp_open_partition_challenge(w3, account, contract, req, cfg)
    elif action == "register_partition":
        _sp_register_partition_only(w3, account, contract, req, cfg)
    elif action == "deactivate_partition":
        _sp_deactivate_partition(w3, account, contract, req, cfg)
    elif action == "list_active_capacity_partitions":
        _sp_list_active_capacity_partitions(w3, account, contract, req, cfg)
    elif action == "list_active_data_partitions":
        _sp_list_active_data_partitions(w3, account, contract, req, cfg)
    elif action == "data_lifecycle_guard_status":
        _sp_data_lifecycle_guard_status(w3, account, contract, req, cfg)
    elif action == "partition_version_status":
        _sp_partition_version_status(w3, account, contract, req, cfg)
    elif action == "partition_health_snapshot":
        _sp_partition_health_snapshot(w3, account, contract, req, cfg)
    elif action == "proof_clock_status":
        _sp_proof_clock_status(w3, account, contract, req, cfg)
    elif action == "partition_challenge_status":
        _sp_partition_challenge_status(w3, account, contract, req, cfg)
    elif action == "submit_partition_proof":
        _sp_submit_partition_proof(w3, account, contract, req, cfg)
    elif action == "get_partition_challenge_deterministic":
        _sp_get_partition_challenge_deterministic(w3, account, contract, req, cfg)
    elif action == "submit_partition_proof_deterministic":
        _sp_submit_partition_proof_deterministic(w3, account, contract, req, cfg)
    elif action == "frozen_partition_snapshot_status":
        _sp_frozen_partition_snapshot_status(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "freeze_partition_snapshot":
        _sp_freeze_partition_snapshot(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "seal_partition_snapshot":
        _sp_seal_partition_snapshot(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "reanchor_frozen_partition_snapshot":
        _sp_reanchor_frozen_partition_snapshot(
            w3, account, contract, snapshot_contract, req, cfg
        )
    elif action == "expected_frozen_partition_public_inputs":
        _sp_expected_frozen_partition_public_inputs(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "submit_frozen_partition_zk_proof":
        _sp_submit_frozen_partition_zk_proof(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "abandon_frozen_partition_snapshot":
        _sp_abandon_frozen_partition_snapshot(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "capacity_incremental_batch_members":
        _sp_capacity_incremental_batch_members(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "abandon_incremental_batch":
        _sp_abandon_incremental_batch(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "capacity_incremental_batch_status":
        _sp_capacity_incremental_batch_status(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "open_capacity_incremental_batch":
        _sp_open_capacity_incremental_batch(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "capacity_incremental_selection_snapshot":
        _sp_capacity_incremental_selection_snapshot(w3, account, contract, snapshot_contract, req, cfg)
    elif action == "certified_capacity_admission_status":
        _sp_certified_capacity_admission_status(w3, account, capacity_contract, req, cfg)
    elif action == "capacity_proof_status":
        _sp_capacity_proof_status(w3, account, capacity_contract, req, cfg)
    elif action == "capacity_epoch_exclusion_status":
        _sp_capacity_epoch_exclusion_status(
            w3, account, contract, capacity_contract, req, cfg
        )
    elif action == "begin_capacity_proof_epoch":
        _sp_begin_capacity_proof_epoch(w3, account, capacity_contract, req, cfg)
    elif action == "abort_capacity_proof_epoch":
        _sp_abort_capacity_proof_epoch(w3, account, capacity_contract, req, cfg)
    elif action == "declare_capacity":
        total_bytes = int(req.get("totalCapacityBytes") or 0)
        _sp_send_tx(w3, account, capacity_contract.functions.declareCapacity(total_bytes), context=cfg)
        print(json.dumps({"ok": True}))
    elif action == "update_capacity_usage":
        _sp_fail(
            "update_capacity_usage was removed: CapacityProofSC derives usage "
            "from verified StorageProof partition registration"
        )
    else:
        _sp_fail(f"unsupported action: {action}")
    return 0



if __name__ == "__main__":
    raise SystemExit(run_storageproof_client_mode())
