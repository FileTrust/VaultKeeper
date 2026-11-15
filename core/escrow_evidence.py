"""Select an escrow evidence ABI and estimate its actual transaction.

A historical manifest is an untrusted witness, never an acceptance certificate.
Only VKEscrow and the bound on-chain receipt determine entitlement.
"""

FIELDS = (
    'deadline', 'partition', 'kind', 'sectorIds', 'sectorRoots',
    'sectorBlockCounts', 'pieceCommitments', 'committedBytes',
    'expiration', 'challengeCount', 'contentVersion',
)


def manifest_tuple(manifest):
    if not isinstance(manifest, dict) or set(manifest) != set(FIELDS):
        raise ValueError('Historical manifest must contain exactly the canonical fields')
    value = dict(manifest)
    for name, bits in (('deadline', 8), ('partition', 8), ('kind', 8),
                       ('committedBytes', 64), ('expiration', 64),
                       ('challengeCount', 16), ('contentVersion', 64)):
        number = value[name]
        if isinstance(number, bool) or not isinstance(number, int) or not 0 <= number < 2**bits:
            raise ValueError(f'Invalid unsigned {bits}-bit {name}')
    k = len(value['sectorRoots'])
    if not 0 < k <= 255:
        raise ValueError('Invalid real manifest length')
    for name in ('sectorIds', 'sectorRoots', 'pieceCommitments'):
        if not isinstance(value[name], list) or len(value[name]) != k:
            raise ValueError('Manifest arrays must have the same real length')
        for word in value[name]:
            if not isinstance(word, str) or not word.startswith('0x') or len(word) != 66:
                raise ValueError('Manifest identifiers must be bytes32 hex strings')
            bytes.fromhex(word[2:])
    if not isinstance(value['sectorBlockCounts'], list) or len(value['sectorBlockCounts']) != k:
        raise ValueError('Manifest arrays must have the same real length')
    if any(isinstance(n, bool) or not isinstance(n, int) or not 0 < n < 2**32
           for n in value['sectorBlockCounts']):
        raise ValueError('Invalid sector block count')
    return tuple(value[name] for name in FIELDS)


def claim_call(contract, secrets, manifest=None):
    if len(secrets) != 5:
        raise ValueError('Five original escrow linkage secrets are required')
    if manifest is None:
        return contract.functions.claimEscrow(*secrets)
    return contract.functions.claimEscrowWithHistoricalProof(*secrets, manifest_tuple(manifest))


def estimated_transaction(call, *, sender, nonce, gas_price):
    transaction = {'from': sender, 'nonce': nonce, 'gasPrice': gas_price}
    transaction['gas'] = call.estimate_gas(transaction)
    return call.build_transaction(transaction)


def evidence_directory(storage, chain_id, escrow_address):
    from pathlib import Path
    return Path(storage) / 'escrow-evidence' / f'{int(chain_id)}-{escrow_address.lower()}'


def _save_private_json(path, value):
    import json
    import os
    import tempfile
    from pathlib import Path
    folder = path.parent
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists() and json.loads(path.read_text()) == value:
        return
    fd, temporary = tempfile.mkstemp(dir=folder)
    try:
        with os.fdopen(fd, 'w') as target:
            os.fchmod(target.fileno(), 0o600)
            json.dump(value, target)
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(directory_fd)
        finally: os.close(directory_fd)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _manifest_hash(manifest):
    from eth_abi import encode
    from web3 import Web3
    values = manifest_tuple(manifest)
    encoded_values = list(values[:-1])
    for i in (3, 4, 6):
        encoded_values[i] = [Web3.to_bytes(hexstr=x) for x in encoded_values[i]]
    return Web3.keccak(encode(['uint8','uint8','uint8','bytes32[]','bytes32[]',
        'uint32[]','bytes32[]','uint64','uint64','uint16'], encoded_values))


def archive_current_manifest(w3, storage_contract, key, context):
    """Archive exact chain metadata at one block; local timestamps are not evidence."""
    import json
    from web3 import Web3
    if not context.get('storage') or not context.get('vk_escrow_address'):
        return None
    block = w3.eth.block_number
    info = storage_contract.functions.partitions(key).call(block_identifier=block)
    if int(info[4]) != 1 or not bool(info[11]):
        return None  # capacity receipts are not file-payment witnesses
    folder = evidence_directory(context['storage'], w3.eth.chain_id, context['vk_escrow_address'])
    path = folder / f'{Web3.to_hex(key)}-{int(info[13])}.json'
    if path.exists():
        cached = json.loads(path.read_text())
        if cached.get('contentVersion') == int(info[13]) and bytes(_manifest_hash(cached)) == bytes(info[12]):
            return cached  # Still authenticated against this block; avoid four repeated RPCs.
    arrays = [getattr(storage_contract.functions, method)(key).call(block_identifier=block)
              for method in ('getPartitionSectorIds', 'getPartitionSectorRoots',
                             'getPartitionBlockCounts', 'getPartitionPieceCommitments')]
    manifest = dict(zip(FIELDS, (int(info[2]), int(info[3]), int(info[4]),
        [Web3.to_hex(x) for x in arrays[0]], [Web3.to_hex(x) for x in arrays[1]],
        list(arrays[2]), [Web3.to_hex(x) for x in arrays[3]],
        int(info[5]), int(info[6]), int(info[10]), int(info[13]))))
    digest = _manifest_hash(manifest)
    if bytes(digest) != bytes(info[12]):
        raise ValueError('Manifest does not match authenticated partition content hash')
    _save_private_json(path, manifest)
    return manifest


def find_historical_manifest(w3, escrow, secrets, storage, registration_abi_path=None):
    """Select only a witness the actual escrow accepts; the chain remains authority."""
    import json
    from pathlib import Path
    from web3 import Web3
    artifact = json.loads(Path(registration_abi_path or Path(__file__).parent / 'contracts/FileRegistrationSC.json').read_text())
    registration = w3.eth.contract(address=escrow.functions.fileRegistration().call(),
        abi=artifact if isinstance(artifact, list) else artifact['abi'])
    rc = Web3.keccak(secrets[2] + secrets[3])
    ch = registration.functions.registrationCommitmentToCommitmentHash(rc).call()
    record = registration.functions.fileRecords(ch).call()
    try:
        claim_call(escrow, secrets).estimate_gas({'from': record[2]})
        return None
    except Exception:
        pass
    folder = evidence_directory(storage, w3.eth.chain_id, escrow.address)
    for path in sorted(folder.glob('*.json')):
        manifest = json.loads(path.read_text())
        values = manifest_tuple(manifest)
        if not any(Web3.to_bytes(hexstr=root) == bytes(record[0]) and
                   Web3.to_bytes(hexstr=piece) == bytes(record[1])
                   for root, piece in zip(values[4], values[6])):
            continue
        try:
            claim_call(escrow, secrets, manifest).estimate_gas({'from': record[2]})
            return manifest
        except Exception:
            continue
    return None


def terminal_proof_requirements(w3, storage_contract, snapshot, entries, context, vk, block, timestamp):
    """Read-only, pinned evidence for EXISTING exact incremental audit selection.

    Never changes authority, rounds, fees or acceptance time. On-chain admission
    and the Snapshot verifier remain authoritative. A current or historical
    qualifying receipt suppresses further proof work even before payment retries.
    """
    import json
    from pathlib import Path
    from web3 import Web3
    folder = Path(context['storage']) / 'payment'
    if not folder.exists():
        return {}
    abi_path = context.get('vk_escrow_json') or Path(context['capacity_proof_json']).parent / 'VKEscrow.json'
    artifact = json.loads(Path(abi_path).read_text())
    escrow = w3.eth.contract(address=Web3.to_checksum_address(context['vk_escrow_address']),
        abi=artifact if isinstance(artifact, list) else artifact['abi'])
    artifact = json.loads(Path(context.get('file_registration_json') or Path(abi_path).parent / 'FileRegistrationSC.json').read_text())
    registration = w3.eth.contract(address=escrow.functions.fileRegistration().call(block_identifier=block),
        abi=artifact if isinstance(artifact, list) else artifact['abi'])
    required, manifests, receipts = {}, {}, {}
    archive = evidence_directory(context['storage'], w3.eth.chain_id, escrow.address)
    historical = None
    def call(function):
        return function.call(block_identifier=block)
    def historical_qualifies(root, piece, cutoff):
        nonlocal historical
        if historical is None:
            historical = [json.loads(path.read_text()) for path in sorted(archive.glob('*.json'))]
        for manifest in historical:
            values = manifest_tuple(manifest)
            if manifest['kind'] != 1 or not any(Web3.to_bytes(hexstr=r) == root and
                Web3.to_bytes(hexstr=p) == piece for r,p in zip(values[4],values[6])):
                continue
            key = call(storage_contract.functions.partitionKeyOf(vk, manifest['deadline'], manifest['partition']))
            identity = (bytes(key), manifest['contentVersion'])
            if identity not in receipts:
                receipts[identity] = call(snapshot.functions.acceptedVersionReceipts(key, manifest['contentVersion']))
            rec = receipts[identity]
            if int(rec[0]) and int(rec[5]) and int(rec[3]) >= cutoff and bytes(rec[4]) == bytes(_manifest_hash(manifest)):
                return True
        return False
    for path in sorted(folder.glob('*.json')):
        credential = json.loads(path.read_text())
        # Quote-only records may not yet contain the DO's linkage secrets.
        if not all(credential.get(name) for name in ('nullifier','secret','regNullifier','regSecret','linkNonce')):
            continue
        secrets = [Web3.to_bytes(hexstr=credential[name]) for name in
                   ('nullifier','secret','regNullifier','regSecret','linkNonce')]
        if any(len(word) != 32 for word in secrets):
            raise ValueError('Invalid local escrow credential')
        pc = Web3.keccak(secrets[0]+secrets[1]); rec = call(escrow.functions.escrows(pc))
        cutoff = int(rec[2])
        if not rec[5] or int(rec[0]) <= int(rec[7]) or cutoff > timestamp:
            continue
        rc = Web3.keccak(secrets[2]+secrets[3])
        if bytes(rec[4]) != bytes(Web3.keccak(pc+rc+secrets[4])):
            raise ValueError('Local escrow registration link mismatch')
        ch = call(registration.functions.registrationCommitmentToCommitmentHash(rc))
        if not any(ch) or call(registration.functions.expiredRegistrationCommitments(rc)) or call(registration.functions.expiredCommitmentHashes(ch)) or call(registration.functions.isDeletionConfirmed(ch)):
            continue
        record = call(registration.functions.fileRecords(ch))
        if record[2].lower() != vk.lower() or int(record[5]) < cutoff:
            continue
        root, piece = bytes(record[0]), bytes(record[1])
        if historical_qualifies(root, piece, cutoff):
            continue
        for entry in entries:
            identity = entry['identity']
            if not identity['active'] or identity['kind'] != 'data' or identity['vk'].lower() != vk.lower():
                continue
            key = Web3.to_bytes(hexstr=entry['chainPartitionKey'])
            if key not in manifests:
                roots = call(storage_contract.functions.getPartitionSectorRoots(key))
                pieces = call(storage_contract.functions.getPartitionPieceCommitments(key))
                manifests[key] = list(zip(map(bytes, roots), map(bytes, pieces)))
            if (root, piece) not in manifests[key]:
                continue
            # A current accepted Snapshot is already enough; a recurring proof is not.
            status = call(snapshot.functions.getCurrentPartitionProofStatus(key))
            if status[0] and int(status[4]) >= cutoff:
                continue
            logical = identity['partitionKey']
            required[logical] = min(cutoff, required.get(logical, cutoff))
    return required
