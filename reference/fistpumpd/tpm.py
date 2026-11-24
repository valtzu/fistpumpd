import base64
import hashlib
import os
import secrets
import subprocess
import tempfile
from pathlib import Path

from .attest import AttestationError

EK_HANDLE = "0x81010001"
AK_HANDLE = "0x81010002"
BANK = "sha256"
SELECTION = (0, 1, 2, 3, 7, 11)
PCR_LIST = BANK + ":" + ",".join(str(n) for n in SELECTION)
DIGEST_BYTES = 32


def run(*command, env=None, input_bytes=None):
    result = subprocess.run(command, capture_output=True, input=input_bytes, env=env, check=False, timeout=60)
    if result.returncode != 0:
        raise AttestationError(f"{command[0]}: {result.stderr.decode(errors='replace').strip()[-300:]}")
    return result.stdout


class TpmProver:
    def __init__(self, environment=None):
        self.environment = dict(os.environ, **(environment or {}))

    def tpm(self, *command, **kwargs):
        return run(*command, env=self.environment, **kwargs)

    def prepare(self, work):
        self.flush()

        def create_ek():
            self.tpm("tpm2_createek", "-c", str(work / "ek.ctx"), "-G", "ecc")
            self.tpm("tpm2_evictcontrol", "-C", "o", "-c", str(work / "ek.ctx"), EK_HANDLE)
            self.flush()

        def create_ak():
            self.tpm("tpm2_createak", "-C", EK_HANDLE, "-c", str(work / "ak.ctx"), "-G", "ecc", "-g", BANK, "-s", "ecdsa")
            self.tpm("tpm2_evictcontrol", "-C", "o", "-c", str(work / "ak.ctx"), AK_HANDLE)
            self.flush()

        self.ensure_persistent(work, EK_HANDLE, create_ek)
        self.ensure_persistent(work, AK_HANDLE, create_ak)

    def ensure_persistent(self, work, handle, create):
        try:
            self.tpm("tpm2_readpublic", "-c", handle, "-o", str(work / "probe.pub"))
            return
        except AttestationError:
            pass
        create()

    def flush(self):
        for option in ("-t", "-l", "-s"):
            try:
                self.tpm("tpm2_flushcontext", option)
            except AttestationError:
                pass

    def hello(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            self.prepare(work)
            self.tpm("tpm2_readpublic", "-c", EK_HANDLE, "-o", str(work / "ek.pub"))
            self.tpm("tpm2_readpublic", "-c", AK_HANDLE, "-o", str(work / "ak.pub"), "-n", str(work / "ak.name"))
            return {
                "ek_pub": base64.b64encode((work / "ek.pub").read_bytes()).decode(),
                "ak_pub": base64.b64encode((work / "ak.pub").read_bytes()).decode(),
                "ak_name": (work / "ak.name").read_bytes().hex(),
            }

    def answer(self, challenge):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            self.prepare(work)
            (work / "cred.blob").write_bytes(base64.b64decode(challenge))
            session = str(work / "session.ctx")
            self.tpm("tpm2_startauthsession", "--policy-session", "-S", session)
            try:
                self.tpm("tpm2_policysecret", "-S", session, "-c", "e")
                self.tpm("tpm2_activatecredential", "-c", AK_HANDLE, "-C", EK_HANDLE, "-i", str(work / "cred.blob"),
                         "-o", str(work / "secret.out"), "-P", f"session:{session}")
            finally:
                try:
                    self.tpm("tpm2_flushcontext", session)
                except AttestationError:
                    pass
            return (work / "secret.out").read_bytes().hex()

    def quote(self, qualifying):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            self.prepare(work)
            for _ in range(3):
                self.tpm("tpm2_pcrread", PCR_LIST, "-o", str(work / "before.pcrs"))
                self.tpm("tpm2_quote", "-c", AK_HANDLE, "-l", PCR_LIST, "-q", qualifying, "-m", str(work / "quote.msg"),
                         "-s", str(work / "quote.sig"), "-g", BANK)
                self.tpm("tpm2_pcrread", PCR_LIST, "-o", str(work / "quote.pcrs"))
                if (work / "before.pcrs").read_bytes() == (work / "quote.pcrs").read_bytes():
                    break
            else:
                raise AttestationError("the PCRs keep changing")
            raw = (work / "quote.pcrs").read_bytes()
            if len(raw) != DIGEST_BYTES * len(SELECTION):
                raise AttestationError("unexpected PCR data length")
            pcrs = {str(n): raw[i * DIGEST_BYTES:(i + 1) * DIGEST_BYTES].hex() for i, n in enumerate(SELECTION)}
            return {
                "pcrs": pcrs,
                "message": base64.b64encode((work / "quote.msg").read_bytes()).decode(),
                "signature": base64.b64encode((work / "quote.sig").read_bytes()).decode(),
            }


class TpmVerifier:
    def challenge(self, hello):
        secret = secrets.token_bytes(DIGEST_BYTES)
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "ek.pub").write_bytes(base64.b64decode(hello["ek_pub"]))
            (work / "secret").write_bytes(secret)
            run("tpm2_makecredential", "-T", "none", "-e", str(work / "ek.pub"), "-s", str(work / "secret"),
                "-n", hello["ak_name"], "-o", str(work / "cred.blob"))
            return base64.b64encode((work / "cred.blob").read_bytes()).decode(), secret.hex()

    def check_quote(self, hello, quote, qualifying):
        pcrs = quote["pcrs"]
        try:
            raw = b"".join(bytes.fromhex(pcrs[str(n)]) for n in SELECTION)
        except (KeyError, ValueError):
            raise AttestationError("the quote lacks some of the PCRs") from None
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "ak.pub").write_bytes(base64.b64decode(hello["ak_pub"]))
            (work / "quote.msg").write_bytes(base64.b64decode(quote["message"]))
            (work / "quote.sig").write_bytes(base64.b64decode(quote["signature"]))
            (work / "quote.pcrs").write_bytes(raw)
            run("tpm2_checkquote", "-u", str(work / "ak.pub"), "-m", str(work / "quote.msg"), "-s", str(work / "quote.sig"),
                "-f", str(work / "quote.pcrs"), "-l", PCR_LIST, "-g", BANK, "-q", qualifying)
        return {str(n): pcrs[str(n)].lower() for n in SELECTION}
