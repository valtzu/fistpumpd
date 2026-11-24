import base64
import hashlib
import hmac
import os
import secrets


class AttestationError(Exception):
    pass


def binding(nonce, sign_pub, tls_fp):
    return hashlib.sha256(bytes.fromhex(nonce) + bytes.fromhex(sign_pub) + bytes.fromhex(tls_fp)).hexdigest()


def new_nonce():
    return secrets.token_hex(20)


def ek_hash(hello):
    return hashlib.sha256(base64.b64decode(hello["ek_pub"])).hexdigest()


class FakeTpm:
    def __init__(self, pcrs, tpm_key=None):
        self.pcrs = {str(k): v for k, v in pcrs.items()}
        self.tpm_key = tpm_key or os.urandom(32)
        self.ek = os.urandom(32)
        self.ak = hmac.new(self.tpm_key, b"ak", "sha256").digest()

    def hello(self):
        return {
            "ek_pub": base64.b64encode(self.ek).decode(),
            "ak_pub": base64.b64encode(self.ak).decode(),
            "ak_name": hashlib.sha256(self.ak).hexdigest(),
        }

    def answer(self, challenge):
        return hmac.new(self.ek, base64.b64decode(challenge), "sha256").hexdigest()

    def quote(self, qualifying):
        pcrs = {k: v for k, v in self.pcrs.items() if int(k) in (0, 1, 2, 3, 7, 11)}
        message = repr(sorted(pcrs.items())) + qualifying
        return {"pcrs": pcrs, "message": message, "signature": hmac.new(self.ak, message.encode(), "sha256").hexdigest()}


class FakeVerifier:
    def challenge(self, hello):
        blob = base64.b64encode(os.urandom(16)).decode()
        ek = base64.b64decode(hello["ek_pub"])
        return blob, hmac.new(ek, base64.b64decode(blob), "sha256").hexdigest()

    def check_quote(self, hello, quote, qualifying):
        ak = base64.b64decode(hello["ak_pub"])
        message = repr(sorted(quote["pcrs"].items())) + qualifying
        expected = hmac.new(ak, message.encode(), "sha256").hexdigest()
        if quote.get("message") != message or not hmac.compare_digest(expected, quote.get("signature", "")):
            raise AttestationError("quote signature does not match the attestation key")
        return quote["pcrs"]


def attest(prover, verifier, expected_ek_hash, nonce, sign_pub, tls_fp):
    hello = prover.hello()
    if ek_hash(hello) != expected_ek_hash:
        raise AttestationError("the endorsement key is not the one in the join request")
    blob, secret = verifier.challenge(hello)
    if not hmac.compare_digest(prover.answer(blob), secret):
        raise AttestationError("the attestation key is not bound to the endorsement key")
    qualifying = binding(nonce, sign_pub, tls_fp)
    return verifier.check_quote(hello, prover.quote(qualifying), qualifying)


class RemoteProver:
    def __init__(self, call):
        self.call = call

    def hello(self):
        return self.call("attest_hello", {})

    def answer(self, challenge):
        return self.call("attest_answer", {"challenge": challenge})["secret"]

    def quote(self, qualifying):
        return self.call("attest_quote", {"qualifying": qualifying})


def serve(tpm, method, payload):
    if method == "attest_hello":
        return tpm.hello()
    if method == "attest_answer":
        return {"secret": tpm.answer(payload["challenge"])}
    if method == "attest_quote":
        return tpm.quote(payload["qualifying"])
    return None
