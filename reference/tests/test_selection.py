import unittest

from fistpumpd import selector, topology

TOPOLOGY = topology.parse({
    "version": 7,
    "roles": [
        {"name": "server", "selector": {"arch": "arm64", "memory-gib": ">=4"}, "min": 3, "max": 5, "conflicts": ["agent"]},
        {"name": "agent", "selector": {"arch": "arm64"}, "conflicts": ["server"]},
        {"name": "ingress", "selector": {}},
        {"name": "data", "selector": {"disk-gib": ">=500"}, "max": 1, "conflicts": ["agent"]},
    ],
})
BIG = {"arch": "arm64", "memory-gib": 8, "disk-gib": 900}
SMALL = {"arch": "arm64", "memory-gib": 2, "disk-gib": 32}


def holding(*role_sets):
    return [{"roles": roles} for roles in role_sets]


class SelectorTest(unittest.TestCase):
    def test_comparisons(self):
        self.assertTrue(selector.matches({"memory-gib": ">=4"}, {"memory-gib": 8}))
        self.assertFalse(selector.matches({"memory-gib": ">=4"}, {"memory-gib": 2}))
        self.assertTrue(selector.matches({"arch": ["arm64", "amd64"]}, {"arch": "amd64"}))
        self.assertTrue(selector.matches({"board": "!=pi3"}, {"board": "pi4"}))
        self.assertTrue(selector.matches({"tpm": True}, {"tpm": True}))
        self.assertFalse(selector.matches({"tpm": True}, {"tpm": False}))

    def test_missing_fact_never_matches(self):
        self.assertFalse(selector.matches({"disk-gib": ">=1"}, {}))

    def test_empty_selector_matches_all(self):
        self.assertTrue(selector.matches({}, {}))

    def test_validate_rejects_bad_operand(self):
        with self.assertRaises(selector.SelectorError):
            selector.validate({"memory-gib": ">=lots"})


class RoleSelectionTest(unittest.TestCase):
    def test_first_nodes_become_servers_with_ingress(self):
        self.assertEqual(topology.select_roles(TOPOLOGY, BIG, []), ["server", "ingress", "data"])

    def test_server_cap_sends_later_nodes_to_agent(self):
        members = holding(*[["server"]] * 5)
        self.assertEqual(topology.select_roles(TOPOLOGY, BIG, members), ["agent", "ingress"])

    def test_small_node_is_agent(self):
        self.assertEqual(topology.select_roles(TOPOLOGY, SMALL, []), ["agent", "ingress"])

    def test_data_goes_to_one_node(self):
        members = holding(["server", "data"])
        self.assertEqual(topology.select_roles(TOPOLOGY, BIG, members), ["server", "ingress"])

    def test_conflicts_are_symmetric(self):
        reversed_order = topology.parse({
            "version": 1,
            "roles": [{"name": "agent", "selector": {}}, {"name": "server", "selector": {}, "conflicts": ["agent"]}],
        })
        self.assertEqual(topology.select_roles(reversed_order, {}, []), ["agent"])

    def test_no_match_is_empty(self):
        self.assertEqual(topology.select_roles(TOPOLOGY, {"arch": "riscv"}, []), ["ingress"])

    def test_unmet_minimum(self):
        self.assertEqual(topology.unmet(TOPOLOGY, holding(["server"])), {"server": 2})
        self.assertEqual(topology.unmet(TOPOLOGY, holding(["server"], ["server"], ["server"])), {})

    def test_digest_changes_with_content(self):
        other = topology.parse({"version": 7, "roles": [{"name": "server", "selector": {}}]})
        self.assertNotEqual(other["digest"], TOPOLOGY["digest"])

    def test_bad_topologies(self):
        for document in (
            {"version": 0, "roles": [{"name": "a"}]},
            {"version": 1, "roles": []},
            {"version": 1, "roles": [{"name": "a"}, {"name": "a"}]},
            {"version": 1, "roles": [{"name": "a", "conflicts": ["b"]}]},
            {"version": 1, "roles": [{"name": "a", "min": 3, "max": 2}]},
            {"version": 1, "roles": [{"name": "a", "extra": 1}]},
        ):
            with self.assertRaises(topology.TopologyError, msg=document):
                topology.parse(document)


if __name__ == "__main__":
    unittest.main()
