"""Owner-only signing-key delivery, without secret process arguments."""
import os
import re
import stat
import tempfile
from pathlib import Path


def write_private_text(path, text):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.secret-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def signing_key_args(directory, key, chain_id):
    if not key:
        return []
    if not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', key):
        raise ValueError('Invalid VK signing key')
    path = Path(directory).resolve() / 'signing.key'
    write_private_text(path, key + '\n')
    return ['--vk-private-key-file', str(path), '--chain-id', str(int(chain_id))] if chain_id else []


def read_private_key(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'r', encoding='ascii') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_uid != os.geteuid() or info.st_size > 128:
            raise ValueError('VK signing key must be an owner-only regular file')
        key = stream.read(128).strip()
    if not re.fullmatch(r'(?:0x)?[0-9a-fA-F]{64}', key):
        raise ValueError('Invalid VK signing key file')
    return key
