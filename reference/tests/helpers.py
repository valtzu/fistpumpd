import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from fistpumpd import chain


class Node:
    def __init__(self, name):
        self.name = name
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        self.record = {"sign_pub": self.public, "tls_fp": hashlib.sha256(f"{name}-tls".encode()).hexdigest(), "ek_hash": hashlib.sha256(f"{name}-ek".encode()).hexdigest(), "addr": f"{name}.test:7000"}


def build_key():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "build")])
    now = datetime.datetime(2026, 1, 1)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256())
    )
    return key, certificate.public_bytes(serialization.Encoding.PEM)


def admit_entry(log, node, roles, signers, founder=False, extra=None):
    body = {"node": node.record, "roles": roles, "facts": {}, "policy": {}}
    if founder:
        body["founder"] = True
    body.update(extra or {})
    entry = {"index": len(log), "prev": log.head, "type": "admit", "body": body}
    entry["sigs"] = {str(log.slot_of(s.public) if not founder else 0): chain.sign(s.key, entry) for s in signers}
    return entry


def sign_by(log, entry, signers):
    entry["sigs"] = {str(log.slot_of(s.public)): chain.sign(s.key, entry) for s in signers}
    return entry
