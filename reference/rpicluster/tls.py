import datetime
import hashlib
import os
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def fingerprint(certificate_der):
    return hashlib.sha256(certificate_der).hexdigest()


def create(directory, name="rpi-cluster-member"):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    key_path, cert_path = directory / "tls.key", directory / "tls.crt"
    if not key_path.exists() or not cert_path.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256())
        )
        descriptor = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    return key_path, cert_path, fingerprint(certificate.public_bytes(serialization.Encoding.DER))
