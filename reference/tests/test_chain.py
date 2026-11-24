import unittest

from fistpumpd import chain
from tests import helpers


def cluster_of(count, certificate=None):
    log = chain.Chain(certificate)
    nodes = [helpers.Node(f"n{i}") for i in range(count)]
    log.append(helpers.admit_entry(log, nodes[0], ["server"], [nodes[0]], founder=True))
    for joiner in range(1, count):
        voters = nodes[:joiner]
        needed = chain.quorum(joiner)
        log.append(helpers.admit_entry(log, nodes[joiner], ["agent"], voters[:needed]))
    return log, nodes


class QuorumTest(unittest.TestCase):
    def test_thresholds(self):
        self.assertEqual([chain.quorum(n) for n in range(1, 9)], [1, 2, 2, 3, 4, 4, 5, 6])


class AdmitTest(unittest.TestCase):
    def test_founder_then_members_get_slots_by_index(self):
        log, nodes = cluster_of(4)
        self.assertEqual([m["slot"] for m in log.active()], [0, 1, 2, 3])
        self.assertEqual(log.slot_of(nodes[2].public), 2)
        self.assertEqual(log.rank_of(3), 3)

    def test_second_member_needs_both(self):
        log, nodes = cluster_of(1)
        joiner = helpers.Node("j")
        with self.assertRaisesRegex(chain.ChainError, "0 valid signatures"):
            log.append(helpers.admit_entry(log, joiner, [], []))

    def test_joiner_cannot_sign_its_own_admission(self):
        log, nodes = cluster_of(1)
        joiner = helpers.Node("j")
        entry = helpers.admit_entry(log, joiner, [], [])
        entry["sigs"] = {"1": chain.sign(joiner.key, entry)}
        with self.assertRaises(chain.ChainError):
            log.append(entry)

    def test_forged_signature_is_rejected(self):
        log, nodes = cluster_of(1)
        joiner, stranger = helpers.Node("j"), helpers.Node("s")
        entry = helpers.admit_entry(log, joiner, [], [])
        entry["sigs"] = {"0": chain.sign(stranger.key, entry)}
        with self.assertRaises(chain.ChainError):
            log.append(entry)

    def test_wrong_index_and_prev(self):
        log, nodes = cluster_of(2)
        joiner = helpers.Node("j")
        entry = helpers.admit_entry(log, joiner, [], nodes)
        entry["index"] = 7
        with self.assertRaisesRegex(chain.ChainError, "next one"):
            log.append(entry)
        entry = helpers.admit_entry(log, joiner, [], nodes)
        entry["prev"] = "f" * 64
        with self.assertRaisesRegex(chain.ChainError, "prev"):
            log.append(entry)

    def test_a_second_founder_is_refused(self):
        log, nodes = cluster_of(1)
        other = helpers.Node("o")
        entry = helpers.admit_entry(log, other, [], [], founder=True)
        with self.assertRaises(chain.ChainError):
            log.append(entry)

    def test_same_node_twice_is_refused(self):
        log, nodes = cluster_of(2)
        entry = helpers.admit_entry(log, nodes[1], [], nodes)
        with self.assertRaisesRegex(chain.ChainError, "already a member"):
            log.append(entry)

    def test_tampering_with_history_is_detected_on_replay(self):
        log, nodes = cluster_of(3)
        lines = log.to_lines()
        tampered = lines[1].replace('"agent"', '"server"')
        with self.assertRaises(chain.ChainError):
            chain.Chain.from_lines([lines[0], tampered, lines[2]])

    def test_replay_roundtrip(self):
        log, nodes = cluster_of(5)
        again = chain.Chain.from_lines(log.to_lines())
        self.assertEqual(again.head, log.head)
        self.assertEqual(len(again.active()), 5)


class EvictTest(unittest.TestCase):
    def test_evict_needs_quorum_without_the_target(self):
        log, nodes = cluster_of(4)
        entry = {"index": len(log), "prev": log.head, "type": "evict", "body": {"slot": 3, "reason": "failed attestation"}}
        helpers.sign_by(log, entry, [nodes[0], nodes[1]])
        with self.assertRaisesRegex(chain.ChainError, "2 valid"):
            log.append(entry)
        helpers.sign_by(log, entry, [nodes[0], nodes[1], nodes[2]])
        log.append(entry)
        self.assertEqual([m["slot"] for m in log.active()], [0, 1, 2])

    def test_target_signature_does_not_count(self):
        log, nodes = cluster_of(3)
        entry = {"index": len(log), "prev": log.head, "type": "evict", "body": {"slot": 2}}
        helpers.sign_by(log, entry, [nodes[0], nodes[2]])
        with self.assertRaises(chain.ChainError):
            log.append(entry)

    def test_evicted_slot_is_not_reused(self):
        log, nodes = cluster_of(4)
        entry = {"index": len(log), "prev": log.head, "type": "evict", "body": {"slot": 1}}
        log.append(helpers.sign_by(log, entry, [nodes[0], nodes[2], nodes[3]]))
        joiner = helpers.Node("late")
        log.append(helpers.admit_entry(log, joiner, [], [nodes[0], nodes[2], nodes[3]]))
        self.assertEqual(log.slot_of(joiner.public), 5)

    def test_last_member_cannot_be_evicted(self):
        log, nodes = cluster_of(1)
        entry = {"index": 1, "prev": log.head, "type": "evict", "body": {"slot": 0}}
        with self.assertRaises(chain.ChainError):
            log.append(helpers.sign_by(log, entry, [nodes[0]]))


class TopologyEntryTest(unittest.TestCase):
    def test_version_only_goes_up(self):
        log, nodes = cluster_of(3)
        entry = {"index": len(log), "prev": log.head, "type": "topology", "body": {"version": 2, "digest": "ab"}}
        log.append(helpers.sign_by(log, entry, nodes[:2]))
        again = {"index": len(log), "prev": log.head, "type": "topology", "body": {"version": 2, "digest": "cd"}}
        with self.assertRaisesRegex(chain.ChainError, "above 2"):
            log.append(helpers.sign_by(log, again, nodes[:2]))
        self.assertEqual(log.topology["version"], 2)


class ResetTest(unittest.TestCase):
    def test_reset_needs_the_build_key(self):
        key, certificate = helpers.build_key()
        log, nodes = cluster_of(4, certificate)
        entry = {"index": len(log), "prev": log.head, "type": "reset", "body": {"members": [0], "reason": "lost quorum"}}
        with self.assertRaisesRegex(chain.ChainError, "build key"):
            log.append(entry)
        other, _ = helpers.build_key()
        entry["build_sig"] = chain.sign_build(other, entry)
        with self.assertRaises(chain.ChainError):
            log.append(entry)
        entry["build_sig"] = chain.sign_build(key, entry)
        log.append(entry)
        self.assertEqual([m["slot"] for m in log.active()], [0])

    def test_after_reset_the_survivor_can_admit_alone(self):
        key, certificate = helpers.build_key()
        log, nodes = cluster_of(4, certificate)
        entry = {"index": len(log), "prev": log.head, "type": "reset", "body": {"members": [0]}}
        entry["build_sig"] = chain.sign_build(key, entry)
        log.append(entry)
        joiner = helpers.Node("new")
        log.append(helpers.admit_entry(log, joiner, [], [nodes[0]]))
        self.assertEqual(len(log.active()), 2)


if __name__ == "__main__":
    unittest.main()
