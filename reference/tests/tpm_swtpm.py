import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, "/work")
from fistpumpd import attest, tpm


class SwtpmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.mkdtemp()
        cls.process = subprocess.Popen(
            ["swtpm", "socket", "--tpmstate", f"dir={cls.directory}", "--tpm2", "--ctrl", f"type=tcp,port=2322",
             "--server", "type=tcp,port=2321", "--flags", "not-need-init,startup-clear"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.5)
        cls.environment = {"TPM2TOOLS_TCTI": "swtpm:host=127.0.0.1,port=2321"}

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()

    def test_attestation_roundtrip(self):
        prover = tpm.TpmProver(self.environment)
        verifier = tpm.TpmVerifier()
        ek_hash = attest.ek_hash(prover.hello())
        pcrs = attest.attest(prover, verifier, ek_hash, attest.new_nonce(), "ab" * 32, "cd" * 32)
        self.assertEqual(sorted(pcrs), ["0", "1", "11", "2", "3", "7"])
        self.assertEqual(len(pcrs["0"]), 64)

    def test_a_forged_pcr_value_is_detected(self):
        prover = tpm.TpmProver(self.environment)
        verifier = tpm.TpmVerifier()
        hello = prover.hello()
        qualifying = attest.binding(attest.new_nonce(), "ab" * 32, "cd" * 32)
        quote = prover.quote(qualifying)
        quote["pcrs"]["7"] = "11" * 32
        with self.assertRaises(attest.AttestationError):
            verifier.check_quote(hello, quote, qualifying)

    def test_a_wrong_nonce_is_detected(self):
        prover = tpm.TpmProver(self.environment)
        verifier = tpm.TpmVerifier()
        hello = prover.hello()
        quote = prover.quote("00" * 20)
        with self.assertRaises(attest.AttestationError):
            verifier.check_quote(hello, quote, "11" * 20)

    def test_credential_proves_the_key_pair(self):
        prover = tpm.TpmProver(self.environment)
        verifier = tpm.TpmVerifier()
        hello = prover.hello()
        blob, secret = verifier.challenge(hello)
        self.assertEqual(prover.answer(blob), secret)


if __name__ == "__main__":
    unittest.main()
