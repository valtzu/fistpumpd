import json
import os
import tempfile
import unittest
from pathlib import Path

from fistpumpd import facts, genesis, identity


def fake_root(tmp, memory_kib=8 * 1024 * 1024, disks=None, usr_source="/dev/mmcblk0p2", model="Raspberry Pi 4 Model B Rev 1.5"):
    root = Path(tmp)
    (root / "proc/self").mkdir(parents=True)
    (root / "proc/meminfo").write_text(f"MemTotal:       {memory_kib} kB\n")
    (root / "proc/device-tree").mkdir(parents=True)
    (root / "proc/device-tree/model").write_text(model + "\0")
    (root / "proc/self/mountinfo").write_text(f"36 35 8:2 / /usr ro,relatime - ext4 {usr_source} ro\n")
    for name, gib in (disks or {"mmcblk0": 32, "sda": 900}).items():
        (root / "sys/block" / name).mkdir(parents=True)
        (root / "sys/block" / name / "size").write_text(str(gib * 1024 ** 3 // 512))
    (root / "dev").mkdir()
    (root / "dev/tpmrm0").write_text("")
    return root


class FactsTest(unittest.TestCase):
    def test_collects(self):
        with tempfile.TemporaryDirectory() as tmp:
            found = facts.collect(fake_root(tmp))
        self.assertEqual(found["memory-gib"], 8)
        self.assertEqual(found["disk-gib"], 900)
        self.assertEqual(found["board"], "raspberry-pi-4-model-b-rev-1-5")
        self.assertTrue(found["tpm"])

    def test_root_disk_is_not_counted_as_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            found = facts.collect(fake_root(tmp, disks={"sda": 240}, usr_source="/dev/sda2"))
        self.assertEqual(found["disk-gib"], 0)

    def test_virtual_devices_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            found = facts.collect(fake_root(tmp, disks={"mmcblk0": 32, "zram0": 4, "loop0": 1}))
        self.assertEqual(found["disk-gib"], 0)


class GenesisTest(unittest.TestCase):
    def test_a_lone_node_is_not_a_cluster(self):
        with self.assertRaises(genesis.GenesisError):
            genesis.parse({"min_members": 1})

    def test_defaults(self):
        self.assertEqual(genesis.parse({})["min_members"], 2)

    def test_policy_urls_are_https(self):
        with self.assertRaises(genesis.GenesisError):
            genesis.parse({"policy_urls": ["http://x"]})


class IdentityTest(unittest.TestCase):
    def test_key_persists(self):
        os.environ["FISTPUMPD_NO_SEAL"] = "1"
        with tempfile.TemporaryDirectory() as tmp:
            first = identity.public_hex(identity.load_key(tmp))
            second = identity.public_hex(identity.load_key(tmp))
            self.assertEqual(first, second)
            self.assertEqual(oct((Path(tmp) / "sign.key").stat().st_mode & 0o777), "0o600")


if __name__ == "__main__":
    unittest.main()
