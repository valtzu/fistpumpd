import os
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, "/work")
os.environ["RPI_CLUSTER_NO_SEAL"] = "1"
from rpicluster import tpm
from tests.test_daemon import Rig

ZERO = "0" * 64
DOCUMENT = {
    "firmware": [{"pcr0": ZERO}],
    "secure_boot": {"pcr7": ZERO},
    "versions": [{"version": "1", "pcr11": ZERO, "channel": "canary"}],
    "peripheral_firmware": [{"pcr2": ZERO}],
    "eeprom_configuration": [{"pcr3": ZERO}],
}


class ThreeRealTpmsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.processes = []
        cls.ports = []
        for index in range(3):
            directory = tempfile.mkdtemp()
            data, control = 2321 + index * 10, 2322 + index * 10
            cls.processes.append(subprocess.Popen(
                ["swtpm", "socket", "--tpmstate", f"dir={directory}", "--tpm2", "--ctrl", f"type=tcp,port={control}",
                 "--server", f"type=tcp,port={data}", "--flags", "not-need-init,startup-clear"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
            cls.ports.append(data)
        time.sleep(2)

    @classmethod
    def tearDownClass(cls):
        for process in cls.processes:
            process.terminate()

    def test_cluster_forms_with_real_attestation(self):
        rig = Rig(3, tpm_factory=lambda i: tpm.TpmProver({"TPM2TOOLS_TCTI": f"swtpm:host=127.0.0.1,port={self.ports[i]}"}),
                  verifier=tpm.TpmVerifier(), document=DOCUMENT)
        try:
            rig.start(0)
            self.assertTrue(rig.wait(lambda: rig.daemons[0].member is not None, 120))
            rig.start(1)
            self.assertTrue(rig.wait(lambda: rig.daemons[1].member is not None, 180))
            rig.start(2)
            self.assertTrue(rig.wait(lambda: rig.daemons[2].member is not None and len(rig.daemons[2].member.log) == 3, 240))
            self.assertEqual(len({d.member.log.head for d in rig.daemons}), 3 - 2)
            hashes = {m["node"]["ek_hash"] for m in rig.daemons[0].member.log.active()}
            self.assertEqual(len(hashes), 3)
        finally:
            rig.stop()


if __name__ == "__main__":
    unittest.main()
