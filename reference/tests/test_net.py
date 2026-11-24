import tempfile
import unittest

from rpicluster import attest, member as members, net, policy as policy_module, store, tls, topology
from rpicluster.candidate import Candidate
from tests import helpers, testnet


def free_port():
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Live:
    def __init__(self, name, address_book):
        self.directory = tempfile.mkdtemp()
        self.key_path, self.cert_path, self.fp = tls.create(self.directory)
        self.node = helpers.Node(name)
        self.node.record["tls_fp"] = self.fp
        self.tpm = attest.FakeTpm(testnet.GOOD)
        self.node.record["ek_hash"] = attest.ek_hash(self.tpm.hello())
        self.transport = net.HttpsTransport(address_book)
        self.server = None

        self.node.record["addr"] = f"127.0.0.1:{free_port()}"

    def serve(self, node):
        self.server = net.Server(node, self.node.record["addr"], self.cert_path, self.key_path).start()


class OverTlsTest(unittest.TestCase):
    def test_three_nodes_over_real_tls(self):
        pins = {}
        lookup = lambda address: pins.get(address)
        live = [Live(f"t{i}", lookup) for i in range(3)]
        policy = policy_module.Policy(testnet.DOCUMENT)
        servers = []
        try:
            first = live[0]
            founder = members.found(first.node.key, first.node.record, testnet.BIG, store.MemoryStore(), testnet.TOPOLOGY, policy,
                                    attest.FakeVerifier(), first.transport, tpm=first.tpm)
            first.serve(founder)
            pins[first.node.record["addr"]] = first.fp
            servers.append(first)
            joined = [founder]
            for item in live[1:]:
                candidate = Candidate(item.node.key, item.node.record, testnet.BIG, item.tpm, store.MemoryStore(), testnet.TOPOLOGY,
                                      policy, attest.FakeVerifier(), item.transport)
                item.serve(candidate)
                member = candidate.join([first.node.record["addr"]])
                item.server.stop()
                item.serve(member)
                pins[item.node.record["addr"]] = item.fp
                servers.append(item)
                joined.append(member)
            self.assertEqual(len(joined[0].log), 3)
        finally:
            for item in live:
                if item.server:
                    item.server.stop()

    def test_wrong_certificate_is_rejected(self):
        a = Live("a", None)
        node = type("Node", (), {"handle": lambda self, m, p: {"ok": True}})()
        a.serve(node)
        try:
            transport = net.HttpsTransport()
            self.assertEqual(transport.call(a.node.record["addr"], "x", {}), {"ok": True})
            with self.assertRaisesRegex(members.TransportError, "pinned"):
                transport.call(a.node.record["addr"], "x", {}, fingerprint="0" * 64)
        finally:
            a.server.stop()

    def test_refusal_travels_with_its_reason(self):
        class Refusing:
            def handle(self, method, payload):
                raise members.Refused("no", pending={"index": 3})

        a = Live("r", None)
        a.serve(Refusing())
        try:
            with self.assertRaises(members.Refused) as caught:
                net.HttpsTransport().call(a.node.record["addr"], "x", {})
            self.assertEqual(caught.exception.pending, {"index": 3})
        finally:
            a.server.stop()


if __name__ == "__main__":
    unittest.main()
