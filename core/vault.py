"""Encrypted wallet/peer identity; automatic unlock uses a separate OS credential."""
import base64,json,os,stat,tempfile
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
FORMAT='filetrust-vaultkeeper-aesgcm-v1'

def private_file(path,limit=65536,*,systemd_credential=False):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        owner_only=not info.st_mode&0o077 and (os.geteuid()==0 or info.st_uid==os.geteuid())
        # systemd may expose credentials as root-owned 0440 files to the
        # service group. Only the credential reader opts into this exception.
        managed=systemd_credential and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o440
        if not stat.S_ISREG(info.st_mode) or not (owner_only or managed) or info.st_size>limit:raise ValueError('Expected an owner-only credential file')
        return stream.read(limit+1)

def key(path):
    directory=os.environ.get('CREDENTIALS_DIRECTORY')
    if directory:
        folder=Path(directory)
        if not folder.is_absolute() or '..' in folder.parts or not folder.is_relative_to('/run/credentials'):
            raise ValueError('Unexpected systemd credential directory')
        info=folder.lstat()
        # systemd 249 uses a service-owned 0500 directory and 0400 key;
        # newer versions may use a root-owned directory and a 0440 key.
        if not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0,os.geteuid()} or info.st_mode&0o022:
            raise ValueError('Expected a protected systemd credential directory')
    raw=private_file(Path(directory)/'unlock.key' if directory else Path(path),33,systemd_credential=bool(directory))
    if len(raw)!=32:raise ValueError('Unlock credential must contain exactly 32 bytes')
    return raw

def write_private(path,data):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd,'wb') as target:
            os.fchmod(target.fileno(),0o600);target.write(data);target.flush();os.fsync(target.fileno())
        os.replace(tmp,path)
    finally:Path(tmp).unlink(missing_ok=True)

def save_wallet(path,value,credential):
    nonce=os.urandom(12);data=AESGCM(key(credential)).encrypt(nonce,json.dumps(value).encode(),FORMAT.encode())
    write_private(path,json.dumps({'format':FORMAT,'nonce':base64.b64encode(nonce).decode(),'ciphertext':base64.b64encode(data).decode()}).encode())

def load_wallet(path,credential):
    try:
        raw=private_file(path)
    except (OSError,ValueError):
        raise ValueError('Cannot read encrypted wallet; check its ownership and owner-only permissions') from None
    try:
        row=json.loads(raw)
        if row['format']!=FORMAT:raise ValueError()
        nonce=base64.b64decode(row['nonce'],validate=True)
        ciphertext=base64.b64decode(row['ciphertext'],validate=True)
    except (ValueError,KeyError,TypeError):
        raise ValueError('Encrypted wallet format is invalid; restore its backup') from None
    try:
        unlock=key(credential)
    except (OSError,ValueError):
        raise ValueError('Cannot read unlock credential; check the systemd credential and owner-only file permissions') from None
    try:
        return json.loads(AESGCM(unlock).decrypt(nonce,ciphertext,FORMAT.encode()))
    except Exception:
        raise ValueError('Cannot unlock wallet; restore the matching wallet and unlock credential backup') from None
