import os
import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def seal(plain, target):
    if os.environ.get("FISTPUMPD_NO_SEAL") or not Path("/dev/tpmrm0").exists():
        return False
    result = subprocess.run(["systemd-creds", "encrypt", "--with-key=tpm2", "--tpm2-pcrs=7", "--name=fistpumpd", "-", str(target)],
                            input=plain, capture_output=True, check=False)
    return result.returncode == 0


def unseal(source):
    result = subprocess.run(["systemd-creds", "decrypt", "--name=fistpumpd", str(source), "-"], capture_output=True, check=True)
    return result.stdout


def write_private(path, data):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(data)


def load_key(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    sealed, plain = directory / "sign.key.cred", directory / "sign.key"
    if sealed.exists():
        raw = unseal(sealed)
    elif plain.exists():
        raw = plain.read_bytes()
    else:
        key = ed25519.Ed25519PrivateKey.generate()
        raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
        if not seal(raw, sealed):
            write_private(plain, raw)
    return ed25519.Ed25519PrivateKey.from_private_bytes(raw)


def public_hex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
