import unittest

from fistpumpd import attest, chain, member as members
from tests import helpers, testnet


class AdmissionTest(unittest.TestCase):
    def setUp(self):
        self.network = testnet.Network()

    def test_three_nodes_get_slots_and_roles_in_order(self):
        nodes = testnet.make_cluster(self.network, 3)
        for node in nodes:
            self.assertEqual(len(node.log), 3)
            self.assertEqual(node.log.head, nodes[0].log.head)
        self.assertEqual([m["roles"] for m in nodes[0].log.active()], [["server"], ["server"], ["server"]])
        self.assertEqual([n.slot for n in nodes], [0, 1, 2])

    def test_server_cap_turns_the_fourth_into_an_agent(self):
        nodes = testnet.make_cluster(self.network, 4)
        self.assertEqual(nodes[3].log.member(3)["roles"], ["agent"])

    def test_small_node_is_an_agent(self):
        founder = testnet.make_founder(self.network)
        small = testnet.candidate(self.network, "small", facts={"memory-gib": 2})
        member = testnet.admitted(self.network, small, founder)
        self.assertEqual(member.log.member(1)["roles"], ["agent"])

    def test_unknown_firmware_is_refused(self):
        founder = testnet.make_founder(self.network)
        bad = dict(testnet.GOOD, **{"11": "9" * 64})
        stranger = testnet.candidate(self.network, "stranger", pcrs=bad)
        with self.assertRaisesRegex(members.Refused, "PCR 11"):
            stranger.join([founder.record["addr"]])
        self.assertEqual(len(founder.log), 1)

    def test_lying_about_the_endorsement_key_is_refused(self):
        founder = testnet.make_founder(self.network)
        stranger = testnet.candidate(self.network, "liar")
        stranger.record["ek_hash"] = "1" * 64
        with self.assertRaisesRegex(members.Refused, "endorsement key"):
            stranger.join([founder.record["addr"]])

    def test_pcr_values_forged_without_the_attestation_key_are_refused(self):
        founder = testnet.make_founder(self.network)
        stranger = testnet.candidate(self.network, "forger", pcrs=dict(testnet.GOOD, **{"0": "1" * 64}))
        genuine = stranger.tpm.quote

        def forged(qualifying):
            quote = genuine(qualifying)
            quote["pcrs"] = dict(testnet.GOOD)
            return quote

        stranger.tpm.quote = forged
        with self.assertRaisesRegex(members.Refused, "signature"):
            stranger.join([founder.record["addr"]])

    def test_every_member_holds_the_same_chain(self):
        nodes = testnet.make_cluster(self.network, 5)
        heads = {n.log.head for n in nodes}
        self.assertEqual(len(heads), 1)

    def test_a_late_joiner_replays_the_whole_history(self):
        nodes = testnet.make_cluster(self.network, 4)
        late = testnet.candidate(self.network, "late")
        member = testnet.admitted(self.network, late, nodes[2])
        self.assertEqual(len(member.log), 5)
        self.assertEqual(member.log.head, nodes[0].log.head)

    def test_quorum_survives_one_node_down(self):
        nodes = testnet.make_cluster(self.network, 4)
        self.network.down.add(nodes[3].record["addr"])
        joiner = testnet.candidate(self.network, "n4")
        member = testnet.admitted(self.network, joiner, nodes[0])
        self.assertEqual(len(member.log.active()), 5)

    def test_no_quorum_means_no_admission(self):
        nodes = testnet.make_cluster(self.network, 3)
        for node in nodes[1:]:
            self.network.down.add(node.record["addr"])
        joiner = testnet.candidate(self.network, "n3")
        with self.assertRaisesRegex(members.Refused, "signatures"):
            joiner.join([nodes[0].record["addr"]])
        self.assertEqual(len(nodes[0].log), 3)

    def test_a_node_already_in_cannot_join_twice(self):
        nodes = testnet.make_cluster(self.network, 3)
        again = testnet.candidate(self.network, "again", tpm=nodes[1].tpm)
        again.record["sign_pub"] = nodes[1].record["sign_pub"]
        with self.assertRaises(members.Refused):
            again.join([nodes[0].record["addr"]])


class ConcurrencyTest(unittest.TestCase):
    def setUp(self):
        self.network = testnet.Network()

    def test_two_sponsors_for_one_index_end_in_one_order(self):
        nodes = testnet.make_cluster(self.network, 3)
        first = testnet.candidate(self.network, "x")
        second = testnet.candidate(self.network, "y")
        a = nodes[0].handle("join", {"node": first.record, "facts": first.facts})
        b = nodes[1].handle("join", {"node": second.record, "facts": second.facts})
        for node in nodes:
            node.catch_up()
        self.assertEqual(len({n.log.head for n in nodes}), 1)
        self.assertEqual(len(nodes[0].log), 5)
        self.assertNotEqual(a["entry"]["index"], b["entry"]["index"])

    def test_a_stale_lock_is_finished_by_the_next_sponsor(self):
        nodes = testnet.make_cluster(self.network, 3)
        first = testnet.candidate(self.network, "x")
        second = testnet.candidate(self.network, "y")
        original = nodes[0].commit
        nodes[0].commit = lambda entry: (_ for _ in ()).throw(members.TransportError("crashed before commit"))
        with self.assertRaises(members.TransportError):
            nodes[0].handle("join", {"node": first.record, "facts": first.facts})
        nodes[0].commit = original
        self.assertEqual(len(nodes[0].log), 3)
        b = nodes[1].handle("join", {"node": second.record, "facts": second.facts})
        for node in nodes:
            node.catch_up()
        self.assertEqual(len(nodes[1].log), 5)
        slots = sorted(m["node"]["addr"] for m in nodes[1].log.active())
        self.assertIn(first.record["addr"], slots)
        self.assertIn(second.record["addr"], slots)

    def test_votes_survive_a_restart(self):
        nodes = testnet.make_cluster(self.network, 3)
        joiner = testnet.candidate(self.network, "x")
        nodes[0].handle("join", {"node": joiner.record, "facts": joiner.facts})
        self.assertEqual(nodes[1].store.load_votes(), nodes[1].votes)


class LockExpiryTest(unittest.TestCase):
    def test_a_lock_expires(self):
        network = testnet.Network()
        clock = testnet.Clock()
        nodes = testnet.make_cluster(network, 3)
        for node in nodes:
            node.clock = clock
        entry = {"index": 3, "prev": nodes[0].log.head, "type": "admit", "body": {}}
        nodes[1].votes["3"] = {"hash": "ab" * 32, "time": clock.now, "entry": entry}
        proposal = dict(entry, body={"x": 1})
        with self.assertRaisesRegex(members.Refused, "already voted"):
            nodes[1].lock(proposal)
        clock.now += members.VOTE_LOCK_SECONDS + 1
        nodes[1].lock(proposal)


class EvictionTest(unittest.TestCase):
    class Watching:
        def __init__(self, failing):
            self.failing = failing

        def healthy(self, member):
            return member["slot"] not in self.failing

    def test_members_that_see_the_failure_evict(self):
        network = testnet.Network()
        nodes = testnet.make_cluster(network, 4)
        for node in nodes:
            node.observer = self.Watching({3})
        nodes[0].propose_evict(3, "attestation failed")
        self.assertEqual([m["slot"] for m in nodes[1].log.active()], [0, 1, 2])

    def test_a_member_that_sees_it_healthy_does_not_sign(self):
        network = testnet.Network()
        nodes = testnet.make_cluster(network, 4)
        nodes[0].observer = self.Watching({3})
        for node in nodes[1:]:
            node.observer = self.Watching(set())
        with self.assertRaisesRegex(members.Refused, "signatures"):
            nodes[0].propose_evict(3, "suspicion")
        self.assertEqual(len(nodes[0].log.active()), 4)


class TopologyTest(unittest.TestCase):
    def test_adopting_a_new_topology_is_logged(self):
        from fistpumpd import topology

        network = testnet.Network()
        nodes = testnet.make_cluster(network, 3)
        newer = topology.parse({"version": 2, "roles": testnet.TOPOLOGY["roles"] and [
            {"name": "server", "selector": {}, "max": 3}, {"name": "agent", "selector": {}, "conflicts": ["server"]}]})
        for node in nodes:
            node.topology = newer
        nodes[1].propose_topology()
        self.assertEqual(nodes[0].log.topology["version"], 2)

    def test_a_node_with_an_older_topology_refuses_to_sign(self):
        from fistpumpd import topology

        network = testnet.Network()
        nodes = testnet.make_cluster(network, 3)
        newer = topology.parse({"version": 2, "roles": [{"name": "server", "selector": {}}]})
        nodes[0].topology = newer
        with self.assertRaisesRegex(members.Refused, "signatures"):
            nodes[0].propose_topology()


if __name__ == "__main__":
    unittest.main()


class TokenTest(unittest.TestCase):
    class Tokens:
        def __init__(self, values):
            self.values = values

        def get(self, kind):
            return self.values.get(kind)

    def test_members_fetch_tokens_by_role(self):
        network = testnet.Network()
        nodes = testnet.make_cluster(network, 4)
        nodes[0].tokens = self.Tokens({"server": "s3cret", "agent": "a9ent"})
        self.assertEqual(nodes[1].fetch_token("server"), "s3cret")
        self.assertEqual(nodes[3].fetch_token("agent"), "a9ent")
        self.assertIsNone(nodes[3].fetch_token("server"))

    def test_a_replayed_request_gets_nothing(self):
        network = testnet.Network()
        nodes = testnet.make_cluster(network, 3)
        nodes[0].tokens = self.Tokens({"server": "s3cret"})
        nonce = nodes[0].handle("token_challenge", {})["nonce"]
        signature = nodes[1].key.sign(members.token_request("server", nonce, 1)).hex()
        request = {"kind": "server", "nonce": nonce, "slot": 1, "sig": signature}
        self.assertEqual(nodes[0].handle("token", request)["token"], "s3cret")
        with self.assertRaises(members.Refused):
            nodes[0].handle("token", request)

    def test_an_outsider_gets_nothing(self):
        network = testnet.Network()
        nodes = testnet.make_cluster(network, 3)
        nodes[0].tokens = self.Tokens({"server": "s3cret"})
        outsider = helpers.Node("out")
        nonce = nodes[0].handle("token_challenge", {})["nonce"]
        signature = outsider.key.sign(members.token_request("server", nonce, 1)).hex()
        with self.assertRaises(members.Refused):
            nodes[0].handle("token", {"kind": "server", "nonce": nonce, "slot": 1, "sig": signature})


class ResetOverTheWireTest(unittest.TestCase):
    def test_a_build_signed_reset_reaches_every_member(self):
        key, certificate = helpers.build_key()
        network = testnet.Network()
        nodes = testnet.make_cluster(network, 4)
        for node in nodes:
            node.log.build_certificate = certificate
        entry = {"index": len(nodes[0].log), "prev": nodes[0].log.head, "type": "reset", "body": {"members": [0, 1], "reason": "lost two"}}
        entry["build_sig"] = chain.sign_build(key, entry)
        nodes[0].commit(entry)
        self.assertEqual([m["slot"] for m in nodes[3].log.active()], [0, 1])
        self.assertEqual(len(nodes[2].log), 5)
