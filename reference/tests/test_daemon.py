import json
import os
import re
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

from fistpumpd import apply, attest, daemon, genesis, member as members
from tests import testnet

os.environ["FISTPUMPD_NO_SEAL"] = "1"
TOPOLOGY = {
    "version": 1,
    "roles": [
        {"name": "server", "selector": {"memory-gib": ">=4"}, "min": 3, "max": 3, "conflicts": ["agent"]},
        {"name": "agent", "selector": {}, "conflicts": ["server"]},
        {"name": "ingress", "selector": {}},
    ],
    "vips": {"server": ["10.9.0.20", "10.9.0.21", "10.9.0.22"], "ingress": ["10.9.0.30"]},
}


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Recording(apply.Host):
    def __init__(self):
        self.calls = []
        super().__init__(run=lambda *arguments: self.calls.append(arguments))


class Rig:
    def __init__(self, count, facts=None, topology=None, pcrs=None, tpm_factory=None, verifier=None, document=None):
        self.directory = tempfile.mkdtemp()
        self.ports = [(free_port(), free_port(socket.SOCK_DGRAM)) for _ in range(count)]
        self.topology = topology or TOPOLOGY
        self.facts = facts or testnet.BIG
        self.pcrs = pcrs
        self.tpm_factory = tpm_factory
        self.verifier = verifier or attest.FakeVerifier()
        self.document = document or testnet.DOCUMENT
        self.daemons = [None] * count
        self.threads = [None] * count
        self.hosts = [Recording() for _ in range(count)]

    def start(self, index, pcrs=None):
        root = Path(self.directory) / f"n{index}"
        for name in ("state", "run", "root", "credstore"):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / "topology.json").write_text(json.dumps(self.topology))
        document = genesis.parse({"min_members": 2, "founder_wait": 1, "attest_interval": 1, "evict_after": 2, "join_retry": 1, "port": self.ports[index][0],
                                  "discovery_port": self.ports[index][1]})
        targets = [("127.0.0.1", udp) for i, (_, udp) in enumerate(self.ports) if i != index]
        paths = {"state": root / "state", "run": root / "run", "root": root / "root", "credstore": root / "credstore",
                 "topology": root / "topology.json"}
        tpm = self.tpm_factory(index) if self.tpm_factory else attest.FakeTpm(pcrs or testnet.GOOD)
        instance = daemon.Daemon(paths, document, tpm, self.verifier, f"127.0.0.1:{self.ports[index][0]}", facts=self.facts,
                                 host=self.hosts[index], discovery_targets=targets, policy_loader=lambda: self.document,
                                 seal=False)
        instance.record_tpm = tpm
        thread = threading.Thread(target=instance.run, daemon=True)
        thread.start()
        self.daemons[index] = instance
        self.threads[index] = thread
        return instance

    def wait(self, condition, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if condition():
                return True
            time.sleep(0.2)
        return False

    def stop(self):
        for instance in self.daemons:
            if instance:
                instance.stop()


class DaemonTest(unittest.TestCase):
    def test_three_nodes_form_a_cluster_without_a_server(self):
        rig = Rig(3)
        try:
            rig.start(0)
            self.assertTrue(rig.wait(lambda: rig.daemons[0].member is not None))
            self.assertEqual(rig.daemons[0].member.slot, 0)
            self.assertFalse((Path(rig.daemons[0].paths["run"]) / "k3s-ready").exists())
            rig.start(1)
            rig.start(2)
            self.assertTrue(rig.wait(lambda: all(d.member is not None and len(d.member.log) == 3 for d in rig.daemons)))
            heads = {d.member.log.head for d in rig.daemons}
            self.assertEqual(len(heads), 1)
            self.assertTrue(rig.wait(lambda: all((Path(d.paths["run"]) / "k3s-ready").exists() for d in rig.daemons)))
            first = (Path(rig.daemons[0].paths["root"]) / "etc/rancher/k3s/config.yaml.d/10-role.yaml").read_text()
            second = (Path(rig.daemons[1].paths["root"]) / "etc/rancher/k3s/config.yaml.d/10-role.yaml").read_text()
            self.assertIn("cluster-init: true", first)
            self.assertIn("server: https://10.9.0.20:6443", second)
            self.assertTrue(rig.wait(lambda: all(d.tokens.get("server") for d in rig.daemons)))
            self.assertEqual({d.tokens.get("server") for d in rig.daemons}, {rig.daemons[0].tokens.get("server")})
            best = {}
            for d in rig.daemons:
                text = (Path(d.paths["run"]) / "keepalived.conf").read_text()
                for name, priority in re.findall(r"vrrp_instance (SERVER\d) \{.*?priority (\d+)", text, re.S):
                    best[name] = max(best.get(name, (0, None)), (int(priority), d.member.slot))
            winners = [slot for _, slot in best.values()]
            self.assertEqual(sorted(winners), [0, 1, 2])
        finally:
            rig.stop()

    def test_a_new_topology_is_adopted_through_the_log(self):
        rig = Rig(2)
        try:
            rig.start(0)
            rig.start(1)
            self.assertTrue(rig.wait(lambda: all(d.member is not None and len(d.member.log) == 2 for d in rig.daemons)))
            newer = dict(TOPOLOGY, version=2, roles=[{"name": "server", "selector": {}, "max": 5}, {"name": "agent", "selector": {}, "conflicts": ["server"]}])
            for d in rig.daemons:
                Path(d.paths["topology"]).write_text(json.dumps(newer))
            self.assertTrue(rig.wait(lambda: all((d.member.log.topology or {}).get("version") == 2 for d in rig.daemons)))
        finally:
            rig.stop()

    def test_two_nodes_booting_together_found_one_cluster(self):
        rig = Rig(2)
        try:
            rig.start(0)
            rig.start(1)
            self.assertTrue(rig.wait(lambda: all(d.member is not None and len(d.member.log) == 2 for d in rig.daemons)))
            self.assertEqual(len({d.member.log.head for d in rig.daemons}), 1)
        finally:
            rig.stop()

    def test_a_node_with_unknown_firmware_stays_out(self):
        rig = Rig(2)
        try:
            rig.start(0)
            self.assertTrue(rig.wait(lambda: rig.daemons[0].member is not None))
            rig.start(1, pcrs=dict(testnet.GOOD, **{"11": "9" * 64}))
            time.sleep(8)
            self.assertIsNone(rig.daemons[1].member)
            self.assertEqual(len(rig.daemons[0].member.log), 1)
            self.assertIn("PCR 11", rig.daemons[1].status.get("error", ""))
        finally:
            rig.stop()

    def test_restart_keeps_membership(self):
        rig = Rig(2)
        try:
            rig.start(0)
            rig.start(1)
            self.assertTrue(rig.wait(lambda: all(d.member is not None and len(d.member.log) == 2 for d in rig.daemons)))
            first_head = rig.daemons[1].member.log.head
            slot = rig.daemons[1].member.slot
            rig.daemons[1].stop()
            rig.daemons[1] = None
            replacement = rig.start(1)
            self.assertTrue(rig.wait(lambda: replacement.member is not None))
            self.assertEqual(replacement.member.log.head, first_head)
            self.assertEqual(replacement.member.slot, slot)
        finally:
            rig.stop()


if __name__ == "__main__":
    unittest.main()
