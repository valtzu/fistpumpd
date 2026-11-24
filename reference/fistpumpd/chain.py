import base64
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509 import load_pem_x509_certificate

from . import canonical

ZERO = "0" * 64
TYPES = ("admit", "evict", "topology", "reset")


class ChainError(ValueError):
    pass


def quorum(members):
    if members < 1:
        raise ChainError("a quorum needs members")
    faulty = (members - 1) // 3
    return (members + faulty + 2) // 2


def entry_hash(entry):
    core = {key: entry[key] for key in ("index", "prev", "type", "body")}
    return hashlib.sha256(canonical.dumps(core)).hexdigest()


def sign(private_key, entry):
    return private_key.sign(bytes.fromhex(entry_hash(entry))).hex()


def verify_member(public_hex, entry, signature_hex):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
            bytes.fromhex(signature_hex), bytes.fromhex(entry_hash(entry))
        )
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_message(public_hex, message, signature_hex):
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(bytes.fromhex(signature_hex), message)
    except (InvalidSignature, ValueError):
        return False
    return True


def verify_build(certificate_pem, entry):
    signature = entry.get("build_sig")
    if not certificate_pem or not isinstance(signature, str):
        return False
    key = load_pem_x509_certificate(certificate_pem if isinstance(certificate_pem, bytes) else certificate_pem.encode()).public_key()
    digest = bytes.fromhex(entry_hash(entry))
    try:
        data = base64.b64decode(signature, validate=True)
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(data, digest, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(data, digest, ec.ECDSA(hashes.SHA256()))
        else:
            return False
    except (InvalidSignature, ValueError):
        return False
    return True


def sign_build(private_key, entry):
    digest = bytes.fromhex(entry_hash(entry))
    if isinstance(private_key, rsa.RSAPrivateKey):
        signature = private_key.sign(digest, padding.PKCS1v15(), hashes.SHA256())
    else:
        signature = private_key.sign(digest, ec.ECDSA(hashes.SHA256()))
    return base64.b64encode(signature).decode()


def node_record(node):
    required = ("sign_pub", "tls_fp", "ek_hash")
    if not isinstance(node, dict) or any(not isinstance(node.get(key), str) or not node[key] for key in required):
        raise ChainError("a node record has sign_pub, tls_fp and ek_hash")
    return node


class Chain:
    def __init__(self, build_certificate=None):
        self.build_certificate = build_certificate
        self.entries = []
        self.members = {}
        self.topology = None

    def __len__(self):
        return len(self.entries)

    @property
    def head(self):
        return entry_hash(self.entries[-1]) if self.entries else ZERO

    def active(self):
        return [self.members[slot] for slot in sorted(self.members) if self.members[slot]["status"] == "active"]

    def member(self, slot):
        found = self.members.get(slot)
        return found if found and found["status"] == "active" else None

    def slot_of(self, sign_pub):
        for member in self.active():
            if member["node"]["sign_pub"] == sign_pub:
                return member["slot"]
        return None

    def rank_of(self, slot):
        return [member["slot"] for member in self.active()].index(slot)

    def check(self, entry):
        if not isinstance(entry, dict) or entry.get("type") not in TYPES:
            raise ChainError("unknown entry type")
        if entry.get("index") != len(self.entries):
            raise ChainError(f"index {entry.get('index')} is not the next one ({len(self.entries)})")
        if entry.get("prev") != self.head:
            raise ChainError("prev does not match the head")
        if not isinstance(entry.get("body"), dict):
            raise ChainError("body is an object")
        getattr(self, "check_" + entry["type"])(entry)

    def append(self, entry):
        self.check(entry)
        getattr(self, "apply_" + entry["type"])(entry)
        self.entries.append(entry)

    def signers(self, entry, excluded=()):
        valid = set()
        for key, signature in (entry.get("sigs") or {}).items():
            member = self.member(int(key)) if str(key).isdigit() else None
            if member and member["slot"] not in excluded and verify_member(member["node"]["sign_pub"], entry, signature):
                valid.add(member["slot"])
        return valid

    def require_quorum(self, entry, excluded=()):
        needed = quorum(len(self.active()))
        got = self.signers(entry, excluded)
        if len(got) < needed:
            raise ChainError(f"{len(got)} valid signatures, {needed} needed")

    def check_admit(self, entry):
        body = entry["body"]
        node = node_record(body.get("node"))
        if not isinstance(body.get("roles"), list):
            raise ChainError("roles is a list")
        for member in self.active():
            if member["node"]["sign_pub"] == node["sign_pub"] or member["node"]["ek_hash"] == node["ek_hash"]:
                raise ChainError("node is already a member")
        if not self.entries:
            if not body.get("founder"):
                raise ChainError("the first entry admits a founder")
            if not verify_member(node["sign_pub"], entry, (entry.get("sigs") or {}).get("0", "")):
                raise ChainError("founder signature is invalid")
            return
        if body.get("founder"):
            raise ChainError("only the first entry is a founder")
        if not self.active():
            raise ChainError("no members, a reset is needed")
        self.require_quorum(entry)

    def apply_admit(self, entry):
        body = entry["body"]
        self.members[entry["index"]] = {
            "slot": entry["index"],
            "node": body["node"],
            "roles": body["roles"],
            "facts": body.get("facts", {}),
            "policy": body.get("policy", {}),
            "pcr1": body.get("pcr1"),
            "status": "active",
            "since": entry["index"],
        }
        if body.get("topology"):
            self.topology = body["topology"]

    def check_evict(self, entry):
        slot = entry["body"].get("slot")
        if not isinstance(slot, int) or not self.member(slot):
            raise ChainError("evict names an active member")
        if len(self.active()) < 2:
            raise ChainError("the last member is removed by a reset")
        self.require_quorum(entry, excluded=(slot,))

    def apply_evict(self, entry):
        self.members[entry["body"]["slot"]]["status"] = "evicted"

    def check_topology(self, entry):
        version, digest = entry["body"].get("version"), entry["body"].get("digest")
        current = (self.topology or {}).get("version", 0)
        if not isinstance(version, int) or version <= current or not isinstance(digest, str):
            raise ChainError(f"topology version must be above {current}")
        self.require_quorum(entry)

    def apply_topology(self, entry):
        self.topology = {"version": entry["body"]["version"], "digest": entry["body"]["digest"]}

    def check_reset(self, entry):
        slots = entry["body"].get("members")
        if not isinstance(slots, list) or not slots or any(not isinstance(s, int) or s not in self.members for s in slots):
            raise ChainError("reset names known members")
        if not verify_build(self.build_certificate, entry):
            raise ChainError("reset is not signed by the build key")

    def apply_reset(self, entry):
        keep = set(entry["body"]["members"])
        for slot, member in self.members.items():
            member["status"] = "active" if slot in keep else "evicted"

    def to_lines(self):
        return [canonical.dumps(entry).decode() for entry in self.entries]

    @classmethod
    def from_lines(cls, lines, build_certificate=None):
        import json

        chain = cls(build_certificate)
        for line in lines:
            if line.strip():
                chain.append(json.loads(line))
        return chain
