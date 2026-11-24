import copy
import threading
import time

from . import attest, canonical, chain, topology as topologies

VOTE_LOCK_SECONDS = 300
MAX_ROUNDS = 5


def token_request(kind, nonce, slot):
    return f"fistpumpd token {kind} {nonce} {slot}".encode()


class Refused(Exception):
    def __init__(self, reason, pending=None):
        super().__init__(reason)
        self.reason = reason
        self.pending = pending


class TransportError(Exception):
    pass


class Superseded(Exception):
    pass


class Member:
    def __init__(self, key, record, log, store, topology, policy, verifier, transport, build_certificate=None,
                 observer=None, clock=time.time, on_change=None, tpm=None, tokens=None):
        self.key = key
        self.record = record
        self.tpm = tpm
        self.tokens = tokens
        self.challenges = {}
        self.mutex = threading.RLock()
        self.log = log
        self.store = store
        self.topology = topology
        self.policy = policy
        self.verifier = verifier
        self.transport = transport
        self.observer = observer
        self.clock = clock
        self.on_change = on_change or (lambda member: None)
        self.votes = store.load_votes()

    @property
    def slot(self):
        return self.log.slot_of(self.record["sign_pub"])

    def sign(self, entry):
        return chain.sign(self.key, entry)

    def peers(self):
        return [m for m in self.log.active() if m["node"]["sign_pub"] != self.record["sign_pub"]]

    def call(self, member, method, payload):
        return self.transport.call(member["node"]["addr"], method, payload)

    def handle(self, method, payload):
        if method.startswith("attest_") and self.tpm is not None:
            return attest.serve(self.tpm, method, payload)
        handler = getattr(self, "on_" + method, None)
        if handler is None:
            raise Refused(f"unknown method {method}")
        return handler(payload)

    def on_token_challenge(self, payload):
        nonce = attest.new_nonce()
        now = self.clock()
        self.challenges = {k: v for k, v in self.challenges.items() if now - v < 60}
        self.challenges[nonce] = now
        return {"nonce": nonce}

    def on_token(self, payload):
        kind, nonce = payload.get("kind"), payload.get("nonce")
        slot = payload.get("slot")
        if self.tokens is None or kind not in ("server", "agent") or self.challenges.pop(nonce, None) is None:
            raise Refused("no such challenge")
        requester = self.log.member(slot) if isinstance(slot, int) else None
        if requester is None or not chain.verify_message(requester["node"]["sign_pub"], token_request(kind, nonce, slot), payload.get("sig", "")):
            raise Refused("not an active member")
        allowed = {"server": ("server",), "agent": ("server", "agent")}[kind]
        if not any(role in allowed for role in requester["roles"]):
            raise Refused("this member's roles do not allow that token")
        value = self.tokens.get(kind)
        if value is None:
            raise Refused("this member has no such token")
        return {"token": value}

    def fetch_token(self, kind):
        for member in self.peers():
            try:
                nonce = self.call(member, "token_challenge", {})["nonce"]
                signature = self.key.sign(token_request(kind, nonce, self.slot)).hex()
                return self.call(member, "token", {"kind": kind, "nonce": nonce, "slot": self.slot, "sig": signature})["token"]
            except (TransportError, Refused):
                continue
        return None

    def on_hello(self, payload):
        return {"sign_pub": self.record["sign_pub"], "length": len(self.log), "head": self.log.head}

    def on_log(self, payload):
        start = int(payload.get("from", 0))
        return {"entries": self.log.entries[start:]}

    def on_commit(self, payload):
        self.accept(payload["entry"])
        return {"length": len(self.log)}

    def accept(self, entry):
        if entry["index"] > len(self.log):
            self.catch_up()
        with self.mutex:
            if entry["index"] != len(self.log):
                return
            self.log.append(entry)
            self.store.append(canonical.dumps(entry).decode())
            self.votes = {k: v for k, v in self.votes.items() if int(k) > entry["index"]}
            self.store.save_votes(self.votes)
        self.on_change(self)

    def catch_up(self):
        for member in self.peers():
            try:
                entries = self.call(member, "log", {"from": len(self.log)})["entries"]
            except (TransportError, Refused):
                continue
            for entry in entries:
                if entry["index"] == len(self.log):
                    self.accept(entry)
            if entries:
                return

    def lock(self, entry):
        key = str(entry["index"])
        digest = chain.entry_hash(entry)
        with self.mutex:
            held = self.votes.get(key)
            if held and held["hash"] != digest:
                if self.clock() - held["time"] < VOTE_LOCK_SECONDS:
                    raise Refused("already voted for another entry at this index", pending=held["entry"])
            self.votes[key] = {"hash": digest, "time": self.clock(), "entry": entry}
            self.store.save_votes(self.votes)

    def shape(self, entry):
        if entry.get("index") != len(self.log) or entry.get("prev") != self.log.head:
            self.catch_up()
        if entry.get("index") != len(self.log):
            raise Refused(f"index {entry.get('index')} is not the next one ({len(self.log)})")
        if entry.get("prev") != self.log.head:
            raise Refused("prev does not match the head")
        if entry.get("type") not in ("admit", "evict", "topology"):
            raise Refused("this entry type is not voted on")

    def on_propose(self, payload):
        entry = payload["entry"]
        proposal = {key: entry[key] for key in ("index", "prev", "type", "body")}
        self.shape(proposal)
        getattr(self, "validate_" + proposal["type"])(proposal)
        self.lock(proposal)
        return {"sig": self.sign(proposal), "slot": self.slot}

    def validate_admit(self, entry):
        body = entry["body"]
        node = chain.node_record(body.get("node"))
        if not isinstance(node.get("addr"), str) or not isinstance(body.get("facts"), dict):
            raise Refused("a join carries an address and facts")
        for member in self.log.active():
            if member["node"]["sign_pub"] == node["sign_pub"] or member["node"]["ek_hash"] == node["ek_hash"]:
                raise Refused("node is already a member")
        claimed = body.get("topology") or {}
        if claimed.get("version") != self.topology["version"] or claimed.get("digest") != self.topology["digest"]:
            raise Refused("another topology is in force here")
        expected = topologies.select_roles(self.topology, body["facts"], self.log.active())
        if body["roles"] != expected:
            raise Refused(f"roles should be {expected}")
        if not expected and self.topology["unmatched"] == "refuse":
            raise Refused("no role matches this node")
        pcrs = self.attest_joiner(entry)
        try:
            image = self.policy.check(pcrs)
        except Exception as error:
            raise Refused(str(error)) from None
        if body.get("policy", {}).get("image") != image or body.get("pcr1") != pcrs.get("1"):
            raise Refused("the entry does not describe what the node reports")

    def attest_joiner(self, entry):
        node = entry["body"]["node"]
        nonce = attest.new_nonce()
        try:
            prover = self.transport.prover(node["addr"], node["tls_fp"])
            return attest.attest(prover, self.verifier, node["ek_hash"], nonce, node["sign_pub"], node["tls_fp"])
        except (attest.AttestationError, TransportError) as error:
            raise Refused(f"attestation failed: {error}") from None

    def validate_evict(self, entry):
        slot = entry["body"].get("slot")
        if not self.log.member(slot):
            raise Refused("not an active member")
        if self.observer is None or self.observer.healthy(self.log.member(slot)):
            raise Refused("this member sees it as healthy")

    def validate_topology(self, entry):
        body = entry["body"]
        current = (self.log.topology or {}).get("version", 0)
        if body.get("version") != self.topology["version"] or body.get("digest") != self.topology["digest"]:
            raise Refused("this is not the topology in force here")
        if body["version"] <= current:
            raise Refused(f"topology version must be above {current}")

    def drive(self, entry):
        proposal = {key: entry[key] for key in ("index", "prev", "type", "body")}
        try:
            signatures = {str(self.slot): self.sign_after_check(proposal)}
        except Refused as refusal:
            if refusal.pending:
                self.finish(refusal.pending)
                raise Superseded() from None
            raise
        needed = chain.quorum(len(self.log.active()))
        excluded = proposal["body"].get("slot") if proposal["type"] == "evict" else None
        for member in self.peers():
            if len(signatures) >= needed:
                break
            if member["slot"] == excluded:
                continue
            try:
                reply = self.call(member, "propose", {"entry": proposal})
            except Refused as refusal:
                if refusal.pending:
                    self.finish(refusal.pending)
                    raise Superseded() from None
                continue
            except TransportError:
                continue
            signatures[str(member["slot"])] = reply["sig"]
        if len(signatures) < needed:
            raise Refused(f"{len(signatures)} of {needed} signatures")
        signed = dict(proposal, sigs=signatures)
        self.commit(signed)
        return signed

    def sign_after_check(self, proposal):
        self.shape(proposal)
        getattr(self, "validate_" + proposal["type"])(proposal)
        self.lock(proposal)
        return self.sign(proposal)

    def finish(self, pending):
        self.catch_up()
        if pending["index"] < len(self.log):
            return None
        try:
            return self.drive(pending)
        except Superseded:
            return None

    def commit(self, entry):
        audience = self.peers()
        self.accept(entry)
        for member in audience:
            try:
                self.call(member, "commit", {"entry": entry})
            except (TransportError, Refused):
                continue
        joiner = entry["body"].get("node", {}).get("addr") if entry["type"] == "admit" else None
        if joiner:
            try:
                self.transport.call(joiner, "commit", {"entry": entry})
            except (TransportError, Refused):
                pass

    def on_join(self, payload):
        node, facts = payload["node"], payload["facts"]
        pcrs = None
        probe = {"body": {"node": node}}
        try:
            pcrs = self.attest_joiner(probe)
        except Refused as refusal:
            raise Refused(refusal.reason) from None
        image = None
        try:
            image = self.policy.check(pcrs)
        except Exception as error:
            raise Refused(str(error)) from None
        roles = topologies.select_roles(self.topology, facts, self.log.active())
        body = {
            "node": node,
            "roles": roles,
            "facts": facts,
            "topology": {"version": self.topology["version"], "digest": self.topology["digest"]},
            "policy": {"image": image},
            "pcr1": pcrs.get("1"),
            "sponsor": self.slot,
        }
        return {"entry": self.run("admit", body)}

    def run(self, kind, body):
        for _ in range(MAX_ROUNDS):
            self.catch_up()
            entry = {"index": len(self.log), "prev": self.log.head, "type": kind, "body": body}
            try:
                return self.drive(entry)
            except Superseded:
                continue
        raise Refused("too many competing entries")

    def propose_evict(self, slot, reason):
        return self.run("evict", {"slot": slot, "reason": reason})

    def propose_topology(self):
        return self.run("topology", {"version": self.topology["version"], "digest": self.topology["digest"]})

    def snapshot(self):
        return copy.deepcopy({"slot": self.slot, "members": self.log.active(), "head": self.log.head})


def found(key, record, facts, store, topology, policy, verifier, transport, build_certificate=None, **kwargs):
    log = chain.Chain(build_certificate)
    body = {"node": record, "roles": topologies.select_roles(topology, facts, []), "facts": facts, "founder": True,
            "topology": {"version": topology["version"], "digest": topology["digest"]}, "policy": {}}
    entry = {"index": 0, "prev": chain.ZERO, "type": "admit", "body": body}
    entry["sigs"] = {"0": chain.sign(key, entry)}
    log.append(entry)
    store.append(canonical.dumps(entry).decode())
    return Member(key, record, log, store, topology, policy, verifier, transport, build_certificate, **kwargs)


def restore(key, record, store, topology, policy, verifier, transport, build_certificate=None, **kwargs):
    log = chain.Chain.from_lines(store.load_lines(), build_certificate)
    return Member(key, record, log, store, topology, policy, verifier, transport, build_certificate, **kwargs)
