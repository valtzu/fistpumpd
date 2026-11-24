from . import attest, chain
from .member import Member, Refused, TransportError


class Candidate:
    def __init__(self, key, record, facts, tpm, store, topology, policy, verifier, transport, build_certificate=None, **kwargs):
        self.key = key
        self.record = record
        self.facts = facts
        self.tpm = tpm
        self.store = store
        self.topology = topology
        self.policy = policy
        self.verifier = verifier
        self.transport = transport
        self.build_certificate = build_certificate
        self.kwargs = kwargs

    def handle(self, method, payload):
        if method.startswith("attest_"):
            return attest.serve(self.tpm, method, payload)
        if method == "commit":
            return {"length": 0}
        raise Refused(f"unknown method {method}")

    def join(self, seeds):
        refusal = None
        for address in seeds:
            try:
                self.transport.call(address, "join", {"node": self.record, "facts": self.facts})
                entries = self.transport.call(address, "log", {"from": 0})["entries"]
            except TransportError:
                continue
            except Refused as error:
                refusal = error
                continue
            log = chain.Chain.from_lines([canonical_line(entry) for entry in entries], self.build_certificate)
            if log.slot_of(self.record["sign_pub"]) is None:
                raise Refused("the log does not contain this node")
            for entry in entries:
                self.store.append(canonical_line(entry))
            return Member(self.key, self.record, log, self.store, self.topology, self.policy, self.verifier,
                          self.transport, self.build_certificate, tpm=self.tpm, **self.kwargs)
        if refusal:
            raise refusal
        raise TransportError("no seed answered")


def canonical_line(entry):
    from . import canonical

    return canonical.dumps(entry).decode()
