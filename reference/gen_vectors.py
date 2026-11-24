import base64
import datetime
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID

from fistpumpd import apply, canonical, chain, member, policy, selector, topology


def key(seed):
    private = ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
    public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return private, public


def record(index):
    _, public = key(index + 1)
    return {"sign_pub": public, "tls_fp": f"{index:02x}" * 32, "ek_hash": f"{index + 16:02x}" * 32, "addr": f"10.0.0.{index + 1}:17947"}


def build_chain():
    log = chain.Chain()
    privates = [key(i + 1)[0] for i in range(4)]
    founder = {"index": 0, "prev": chain.ZERO, "type": "admit", "body": {"node": record(0), "roles": ["server", "ingress"], "facts": {"arch": "arm64", "memory-gib": 8}, "founder": True,
               "topology": {"version": 1, "digest": "aa" * 32}, "policy": {}}}
    founder["sigs"] = {"0": chain.sign(privates[0], founder)}
    log.append(founder)
    for index in range(1, 4):
        entry = {"index": index, "prev": log.head, "type": "admit", "body": {"node": record(index), "roles": ["server"] if index < 3 else ["agent", "ingress"],
                 "facts": {"arch": "arm64", "memory-gib": 8}, "topology": {"version": 1, "digest": "aa" * 32}, "policy": {"image": "30"}, "pcr1": "bb" * 32, "sponsor": 0}}
        needed = chain.quorum(index)
        entry["sigs"] = {str(slot): chain.sign(privates[slot], entry) for slot in range(needed)}
        log.append(entry)
    evict = {"index": 4, "prev": log.head, "type": "evict", "body": {"slot": 3, "reason": "failed attestation"}}
    evict["sigs"] = {str(slot): chain.sign(privates[slot], evict) for slot in (0, 1, 2)}
    log.append(evict)
    adopted = {"index": 5, "prev": log.head, "type": "topology", "body": {"version": 2, "digest": "cc" * 32}}
    adopted["sigs"] = {str(slot): chain.sign(privates[slot], adopted) for slot in (0, 1)}
    log.append(adopted)
    return log, privates


def canonical_cases():
    values = [
        {}, [], {"b": 1, "a": 2}, {"k": "äö € \U0001f600"}, {"k": "quote\" back\\slash\nnewline\ttab\u0001ctl\u007fdel"},
        {"nested": {"z": [1, 2, {"y": None, "x": True}], "a": False}}, {"n": -5, "big": 9007199254740993, "zero": 0},
        {"html": "<a href='x'>&</a>"}, {"slash": "a/b"}, [{"b": "x"}, {"a": "y"}], {"": "empty key"},
    ]
    return [{"value": value, "canonical": canonical.dumps(value).decode(), "sha256": canonical.digest(value)} for value in values]


def selector_cases():
    cases = [
        ({"memory-gib": ">=4"}, {"memory-gib": 8}), ({"memory-gib": ">=4"}, {"memory-gib": 2}), ({"memory-gib": ">=4"}, {"memory-gib": "8"}),
        ({"arch": ["arm64", "amd64"]}, {"arch": "amd64"}), ({"arch": ["arm64", "amd64"]}, {"arch": "riscv"}), ({"board": "!=pi3"}, {"board": "pi4"}),
        ({"board": "!=pi3"}, {"board": "pi3"}), ({"tpm": True}, {"tpm": True}), ({"tpm": True}, {"tpm": False}), ({"disk-gib": ">=1"}, {}),
        ({}, {}), ({"memory-gib": "<4"}, {"memory-gib": 2}), ({"memory-gib": ">4"}, {"memory-gib": 4}), ({"memory-gib": "<=4"}, {"memory-gib": 4}),
        ({"cpu-count": 4}, {"cpu-count": 4}), ({"cpu-count": 4}, {"cpu-count": 8}), ({"arch": "arm64"}, {"arch": "arm64"}), ({"memory-gib": ">=4"}, {"memory-gib": "lots"}),
    ]
    return [{"selector": s, "facts": f, "match": selector.matches(s, f)} for s, f in cases]


TOPOLOGY = {
    "version": 7,
    "roles": [
        {"name": "server", "selector": {"arch": "arm64", "memory-gib": ">=4"}, "min": 3, "max": 5, "conflicts": ["agent"]},
        {"name": "agent", "selector": {"arch": "arm64"}, "conflicts": ["server"]},
        {"name": "ingress", "selector": {}},
        {"name": "data", "selector": {"disk-gib": ">=500"}, "max": 1, "conflicts": ["agent"]},
    ],
    "vips": {"server": ["192.168.1.20", "192.168.1.21", "192.168.1.22"], "ingress": ["192.168.1.30", "192.168.1.31"]},
}


def topology_cases():
    parsed = topology.parse(TOPOLOGY)
    big = {"arch": "arm64", "memory-gib": 8, "disk-gib": 900}
    small = {"arch": "arm64", "memory-gib": 2, "disk-gib": 32}
    cases = []
    for facts, held in [(big, []), (big, [["server"]] * 5), (small, []), (big, [["server", "data"]]), ({"arch": "riscv"}, []), (big, [["server"]] * 2)]:
        members = [{"roles": roles} for roles in held]
        cases.append({"facts": facts, "held": held, "roles": topology.select_roles(parsed, facts, members), "unmet": topology.unmet(parsed, members)})
    invalid = [
        {"version": 0, "roles": [{"name": "a"}]}, {"version": 1, "roles": []}, {"version": 1, "roles": [{"name": "a"}, {"name": "a"}]},
        {"version": 1, "roles": [{"name": "a", "conflicts": ["b"]}]}, {"version": 1, "roles": [{"name": "a", "min": 3, "max": 2}]}, {"version": 1, "roles": [{"name": "a", "extra": 1}]},
    ]
    return {"document": TOPOLOGY, "digest": parsed["digest"], "cases": cases, "invalid": invalid}


def policy_cases():
    document = {
        "firmware": [{"pcr0": "a" * 64}, {"pcr0": "A" * 64}], "secure_boot": {"pcr7": "e" * 64}, "secure_boot_all": [{"pcr7": "d" * 64}],
        "versions": [{"version": "30", "pcr11": "f" * 64}, {"version": "31", "pcr11": "9" * 64}],
        "peripheral_firmware": [{"pcr2": "c" * 64}], "eeprom_configuration": [{"pcr3": "b" * 64}],
    }
    good = {"0": "a" * 64, "1": "1" * 64, "2": "c" * 64, "3": "b" * 64, "7": "e" * 64, "11": "f" * 64}
    pol = policy.Policy(document)
    cases = []
    for pcrs in [good, dict(good, **{"11": "9" * 64}), dict(good, **{"7": "d" * 64}), dict(good, **{"0": "0" * 64}), dict(good, **{"11": "7" * 64}), {k: v for k, v in good.items() if k != "2"}]:
        try:
            image = pol.check(pcrs)
            cases.append({"pcrs": pcrs, "ok": True, "image": image})
        except policy.PolicyError as error:
            cases.append({"pcrs": pcrs, "ok": False, "error": str(error)})
    empty = policy.Policy({})
    return {"document": document, "cases": cases, "empty_error": _error(empty, good), "allowed": {str(k): v for k, v in pol.allowed.items()}}


def _error(pol, pcrs):
    try:
        pol.check(pcrs)
    except policy.PolicyError as error:
        return str(error)


def apply_cases(log):
    parsed = topology.parse(TOPOLOGY)
    genesis = {"min_members": 2}
    cases = []
    for slot in (0, 1, 2):
        plan = apply.plan(log, slot, parsed, genesis, "eth0")
        cases.append({"slot": slot, "plan": plan, "keepalived": apply.render_keepalived(plan["keepalived"]), "k3s": apply.render_k3s(plan["k3s"])})
    return {"genesis": genesis, "cases": cases, "priorities": [[rank, count, index, apply.priority(rank, count, index)] for count in (1, 2, 3, 7, 40, 200) for rank in range(min(count, 5)) for index in range(3)]}


def reset_case(log, privates):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "build")])
    now = datetime.datetime(2026, 1, 1)
    certificate = x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(private.public_key()).serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=3650)).sign(private, hashes.SHA256())
    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
    entry = {"index": len(log), "prev": log.head, "type": "reset", "body": {"members": [0, 1], "reason": "lost quorum"}}
    entry["build_sig"] = chain.sign_build(private, entry)
    forged = dict(entry, build_sig=base64.b64encode(b"x" * 256).decode())
    return {"certificate": pem, "entry": entry, "forged": forged}


def main():
    log, privates = build_chain()
    tampered = [json.loads(line) for line in log.to_lines()]
    tampered[2]["body"]["roles"] = ["agent"]
    state = {"head": log.head, "members": {str(slot): {"status": m["status"], "roles": m["roles"]} for slot, m in log.members.items()}, "topology": log.topology,
             "active": [m["slot"] for m in log.active()]}
    document = {
        "canonical": canonical_cases(),
        "quorum": [[n, chain.quorum(n)] for n in range(1, 13)],
        "selector": selector_cases(),
        "topology": topology_cases(),
        "policy": policy_cases(),
        "chain": {"seeds": [i + 1 for i in range(4)], "entries": log.entries, "state": state, "tampered": tampered},
        "apply": apply_cases(log),
        "reset": reset_case(log, privates),
        "token_request": [member.token_request("server", "ab" * 20, 3).decode()],
    }
    Path(sys.argv[1] if len(sys.argv) > 1 else "testdata/vectors.json").write_text(json.dumps(document, indent=1, sort_keys=True) + "\n")


main()
