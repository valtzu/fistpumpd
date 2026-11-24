import tempfile
import unittest
from pathlib import Path

from fistpumpd import apply, chain, topology
from tests import helpers, testnet

GENESIS = {"min_members": 2}
TOPOLOGY = topology.parse({
    "version": 1,
    "roles": [
        {"name": "server", "selector": {}, "max": 3, "conflicts": ["agent"]},
        {"name": "agent", "selector": {}, "conflicts": ["server"]},
        {"name": "ingress", "selector": {}},
    ],
    "vips": {"server": ["192.168.1.20", "192.168.1.21", "192.168.1.22"], "ingress": ["192.168.1.30", "192.168.1.31"]},
})


def chain_with(role_sets):
    log = chain.Chain()
    nodes = [helpers.Node(f"n{i}") for i in range(len(role_sets))]
    log.append(helpers.admit_entry(log, nodes[0], role_sets[0], [nodes[0]], founder=True))
    for index in range(1, len(role_sets)):
        needed = chain.quorum(index)
        log.append(helpers.admit_entry(log, nodes[index], role_sets[index], nodes[:needed]))
    return log, nodes


class PlanTest(unittest.TestCase):
    def test_priorities_rotate_equally_over_three_servers(self):
        log, _ = chain_with([["server", "ingress"]] * 3)
        masters = {}
        for slot in range(3):
            plan = apply.plan(log, slot, TOPOLOGY, GENESIS, "eth0")
            for instance in plan["keepalived"]["instances"]:
                if instance["name"].startswith("SERVER"):
                    masters.setdefault(instance["name"], []).append((instance["priority"], slot))
        winners = [max(entries)[1] for entries in masters.values()]
        self.assertEqual(sorted(winners), [0, 1, 2])
        for entries in masters.values():
            self.assertEqual(len({priority for priority, _ in entries}), 3)

    def test_no_names_are_involved(self):
        log, _ = chain_with([["server"]] * 2)
        plan = apply.plan(log, 1, TOPOLOGY, GENESIS, "eth0")
        self.assertEqual([i["name"] for i in plan["keepalived"]["instances"]], ["SERVER1", "SERVER2", "SERVER3"])

    def test_agents_hold_no_server_vips(self):
        log, _ = chain_with([["server"], ["agent", "ingress"]])
        plan = apply.plan(log, 1, TOPOLOGY, GENESIS, "eth0")
        self.assertEqual([i["name"] for i in plan["keepalived"]["instances"]], ["INGRESS1", "INGRESS2"])

    def test_lone_node_does_not_start_k3s(self):
        log, _ = chain_with([["server"]])
        plan = apply.plan(log, 0, TOPOLOGY, GENESIS, "eth0")
        self.assertFalse(plan["start_k3s"])
        self.assertTrue(plan["creates_tokens"])

    def test_second_member_releases_cluster_init(self):
        log, _ = chain_with([["server"], ["server"]])
        first = apply.plan(log, 0, TOPOLOGY, GENESIS, "eth0")
        second = apply.plan(log, 1, TOPOLOGY, GENESIS, "eth0")
        self.assertTrue(first["start_k3s"] and second["start_k3s"])
        self.assertTrue(first["k3s"]["cluster-init"])
        self.assertEqual(second["k3s"]["server"], "https://192.168.1.20:6443")
        self.assertEqual(second["needs_tokens"], ["server", "agent"])

    def test_only_the_first_server_ever_inits(self):
        log, nodes = chain_with([["server"], ["server"], ["server"]])
        entry = {"index": len(log), "prev": log.head, "type": "evict", "body": {"slot": 0}}
        log.append(helpers.sign_by(log, entry, nodes[1:]))
        plan = apply.plan(log, 1, TOPOLOGY, GENESIS, "eth0")
        self.assertNotIn("cluster-init", plan["k3s"])

    def test_agent_joins_through_the_vip(self):
        log, _ = chain_with([["server"], ["server"], ["agent"]])
        plan = apply.plan(log, 2, TOPOLOGY, GENESIS, "eth0")
        self.assertEqual(plan["k3s"], {"server": "https://192.168.1.20:6443"})
        self.assertEqual(plan["needs_tokens"], ["agent"])

    def test_priority_range_stays_valid_for_many_nodes(self):
        for count in (1, 2, 3, 7, 40, 200):
            for rank in range(count):
                for index in range(3):
                    self.assertTrue(1 <= apply.priority(rank, count, index) <= 100)


class RenderTest(unittest.TestCase):
    def test_keepalived_text(self):
        log, _ = chain_with([["server", "ingress"]] * 2)
        text = apply.render_keepalived(apply.plan(log, 0, TOPOLOGY, GENESIS, "eth0")["keepalived"])
        self.assertIn("vrrp_instance SERVER1", text)
        self.assertIn("virtual_ipaddress {\n        192.168.1.20/24", text)
        self.assertIn("track_script {\n        chk_server", text)

    def test_k3s_text(self):
        self.assertEqual(apply.render_k3s({"cluster-init": True, "tls-san": ["a", "b"]}), "cluster-init: true\ntls-san+:\n  - a\n  - b\n")


class ApplyTest(unittest.TestCase):
    class Recording(apply.Host):
        def __init__(self):
            self.calls = []
            super().__init__(run=lambda *arguments: self.calls.append(arguments))

    def test_writes_once_and_signals_only_on_change(self):
        log, _ = chain_with([["server", "ingress"]] * 2)
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as run:
            host = self.Recording()
            settings = apply.plan(log, 0, TOPOLOGY, GENESIS, "eth0")
            apply.apply(settings, root, run, host)
            first = list(host.calls)
            self.assertIn(("systemctl", "reload-or-restart", "keepalived.service"), first)
            self.assertIn(("systemctl", "start", "--no-block", "k3s.service"), first)
            self.assertIn(("hostnamectl", "tags", "server", "ingress"), first)
            apply.apply(settings, root, run, host)
            self.assertEqual(host.calls, first)
            self.assertTrue((Path(root) / "etc/rancher/k3s/config.yaml.d/10-role.yaml").exists())

    def test_role_change_removes_old_marker(self):
        log, _ = chain_with([["server", "ingress"]] * 2)
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as run:
            host = self.Recording()
            apply.apply(apply.plan(log, 0, TOPOLOGY, GENESIS, "eth0"), root, run, host)
            settings = apply.plan(log, 0, TOPOLOGY, GENESIS, "eth0")
            settings["roles"] = ["agent"]
            apply.apply(settings, root, run, host)
            self.assertFalse((Path(root) / "etc/node-role.d/server.conf").exists())
            self.assertTrue((Path(root) / "etc/node-role.d/agent.conf").exists())


if __name__ == "__main__":
    unittest.main()
