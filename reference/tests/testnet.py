from fistpumpd import attest, member as members, policy as policy_module, store, topology

from tests import helpers

GOOD = {"0": "a" * 64, "1": "b" * 64, "2": "c" * 64, "3": "d" * 64, "7": "e" * 64, "11": "f" * 64}
DOCUMENT = {
    "firmware": [{"pcr0": GOOD["0"]}],
    "secure_boot": {"pcr7": GOOD["7"]},
    "versions": [{"version": "30", "pcr11": GOOD["11"], "channel": "canary"}],
    "peripheral_firmware": [{"pcr2": GOOD["2"]}],
    "eeprom_configuration": [{"pcr3": GOOD["3"]}],
}
TOPOLOGY = topology.parse({
    "version": 1,
    "roles": [
        {"name": "server", "selector": {"memory-gib": ">=4"}, "min": 3, "max": 3, "conflicts": ["agent"]},
        {"name": "agent", "selector": {}, "conflicts": ["server"]},
    ],
})
BIG = {"memory-gib": 8, "arch": "arm64"}


class Network:
    def __init__(self):
        self.nodes = {}
        self.down = set()

    def register(self, address, node):
        self.nodes[address] = node

    def view(self):
        return View(self)


class View:
    def __init__(self, network):
        self.network = network

    def call(self, address, method, payload):
        if address in self.network.down or address not in self.network.nodes:
            raise members.TransportError(address)
        return self.network.nodes[address].handle(method, payload)

    def prover(self, address, fingerprint):
        return attest.RemoteProver(lambda method, payload: self.call(address, method, payload))


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def candidate(network, name, pcrs=None, facts=None, topology_in_force=TOPOLOGY, tpm=None, clock=None):
    from fistpumpd.candidate import Candidate

    node = helpers.Node(name)
    node.record["ek_hash"] = None
    fake = tpm or attest.FakeTpm(pcrs or GOOD)
    node.record["ek_hash"] = attest.ek_hash(fake.hello())
    kwargs = {"clock": clock} if clock else {}
    found = Candidate(node.key, node.record, facts or BIG, fake, store.MemoryStore(), topology_in_force,
                      policies(), attest.FakeVerifier(), network.view(), **kwargs)
    found.name = name
    network.register(node.record["addr"], found)
    return found


def policies():
    return policy_module.Policy(DOCUMENT)


def make_founder(network, name="n0", **kwargs):
    first = candidate(network, name, **kwargs)
    founder = members.found(first.key, first.record, first.facts, first.store, first.topology, first.policy,
                            first.verifier, first.transport, tpm=first.tpm, **first.kwargs)
    network.register(first.record["addr"], founder)
    return founder


def make_cluster(network, count, **kwargs):
    founder = make_founder(network, **kwargs)
    nodes = [founder]
    for index in range(1, count):
        joiner = candidate(network, f"n{index}", **kwargs)
        nodes.append(admitted(network, joiner, nodes[0]))
    return nodes


def admitted(network, joiner, sponsor):
    member = joiner.join([sponsor.record["addr"]])
    network.register(joiner.record["addr"], member)
    return member
