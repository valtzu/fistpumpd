import os
import secrets
import subprocess
from pathlib import Path

KINDS = ("server", "agent")
CREDSTORE = Path("/var/lib/credstore.encrypted")
CREDENTIAL_NAMES = {"server": "k3s.token", "agent": "k3s-agent.token"}


class Tokens:
    def __init__(self, directory, credstore=CREDSTORE, seal=True):
        self.directory = Path(directory)
        self.credstore = Path(credstore)
        self.seal = seal and Path("/dev/tpmrm0").exists() and not os.environ.get("FISTPUMPD_NO_SEAL")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path(self, kind):
        return self.directory / f"{kind}.token"

    def get(self, kind):
        try:
            value = self.path(kind).read_text().strip()
        except OSError:
            return None
        return value or None

    def put(self, kind, value):
        descriptor = os.open(self.path(kind), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(value + "\n")

    def create(self):
        for kind in KINDS:
            if self.get(kind) is None:
                self.put(kind, secrets.token_hex(32))

    def install_credentials(self, kinds):
        self.credstore.mkdir(parents=True, exist_ok=True, mode=0o755)
        for kind in kinds:
            value = self.get(kind)
            if value is None:
                continue
            target = self.credstore / CREDENTIAL_NAMES[kind]
            if self.seal:
                result = subprocess.run(["systemd-creds", "encrypt", "--with-key=tpm2", "--tpm2-pcrs=7", f"--name={CREDENTIAL_NAMES[kind]}", "-", str(target)],
                                        input=value.encode(), capture_output=True, check=False)
                if result.returncode != 0:
                    raise OSError(f"systemd-creds: {result.stderr.decode().strip()}")
            else:
                target.write_text(value + "\n")
