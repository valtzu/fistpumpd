import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from rpicluster import discovery, policy as policy_module, policysource


def make_signing_key():
    home = tempfile.mkdtemp()
    environment = dict(os.environ, GNUPGHOME=home)
    subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key", "updates@test", "default", "default", "never"],
                   env=environment, capture_output=True, check=True)
    keyring = Path(home) / "ring.gpg"
    export = subprocess.run(["gpg", "--export", "updates@test"], env=environment, capture_output=True, check=True).stdout
    keyring.write_bytes(export)
    return home, keyring


def sign(home, data):
    return subprocess.run(["gpg", "--batch", "--detach-sign", "--local-user", "updates@test"], input=data,
                          env=dict(os.environ, GNUPGHOME=home), capture_output=True, check=True).stdout


class FakeBucket:
    def __init__(self, files):
        self.files = files

    def __call__(self, url, timeout=0):
        import io

        name = url.rsplit("/", 1)[1]
        if name not in self.files:
            raise OSError("404")
        return io.BytesIO(self.files[name])


class PolicySourceTest(unittest.TestCase):
    def setUp(self):
        self.home, self.keyring = make_signing_key()
        self.versions = json.dumps({"versions": [{"version": "1", "pcr11": "a" * 64}], "secure_boot": {"pcr7": "b" * 64},
                                    "firmware": [{"pcr0": "c" * 64}]}).encode()
        self.sums = f"{hashlib.sha256(self.versions).hexdigest()}  versions.json\n".encode()

    def bucket(self, **changes):
        files = {"SHA256SUMS": self.sums, "SHA256SUMS.gpg": sign(self.home, self.sums), "versions.json": self.versions}
        files.update(changes)
        return FakeBucket(files)

    def test_signed_policy_is_accepted(self):
        document = policysource.fetch_one("https://x/canary", self.keyring, self.bucket())
        self.assertEqual(document["versions"][0]["version"], "1")

    def test_tampered_versions_are_refused(self):
        with self.assertRaisesRegex(policysource.PolicySourceError, "checksum"):
            policysource.fetch_one("https://x/c", self.keyring, self.bucket(**{"versions.json": self.versions + b" "}))

    def test_wrong_signature_is_refused(self):
        other_home, _ = make_signing_key()
        with self.assertRaisesRegex(policysource.PolicySourceError, "not signed"):
            policysource.fetch_one("https://x/c", self.keyring, self.bucket(**{"SHA256SUMS.gpg": sign(other_home, self.sums)}))

    def test_cache_is_used_when_the_bucket_is_down(self):
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "policy.json"
            policysource.refresh(["https://x/c"], self.keyring, cache, self.bucket())
            again = policysource.refresh(["https://x/c"], self.keyring, cache, FakeBucket({}))
        self.assertEqual(again["versions"][0]["pcr11"], "a" * 64)

    def test_merged_policy_accepts_both_channels(self):
        merged = policysource.merge([
            {"versions": [{"pcr11": "1" * 64}], "secure_boot": {"pcr7": "7" * 64}, "firmware": [{"pcr0": "0" * 64}]},
            {"versions": [{"pcr11": "2" * 64}], "secure_boot": {"pcr7": "7" * 64}, "firmware": [{"pcr0": "0" * 64}]},
        ])
        policy = policy_module.Policy(merged)
        self.assertEqual(policy.allowed[11], ["1" * 64, "2" * 64])
        self.assertEqual(policy.allowed[7], ["7" * 64])


class DiscoveryTest(unittest.TestCase):
    def test_probe_finds_responders(self):
        responder = discovery.Responder(0, {"addr": "10.0.0.5:17947", "role": "member"}, bind="127.0.0.1").start()
        try:
            found = discovery.probe([("127.0.0.1", responder.port)], wait=1.5, bind="127.0.0.1")
        finally:
            responder.stop()
        self.assertEqual(found[0]["addr"], "10.0.0.5:17947")


if __name__ == "__main__":
    unittest.main()
