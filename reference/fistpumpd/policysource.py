import hashlib
import json
import subprocess
import tempfile
import urllib.request
from pathlib import Path

SECTIONS = ("firmware", "peripheral_firmware", "eeprom_configuration", "versions")


class PolicySourceError(Exception):
    pass


def download(url, opener=urllib.request.urlopen):
    try:
        with opener(url, timeout=30) as response:
            return response.read(16 * 1024 * 1024)
    except OSError as error:
        raise PolicySourceError(f"{url}: {error}") from None


def verify_signature(sums, signature, keyring):
    with tempfile.TemporaryDirectory() as directory:
        work = Path(directory)
        (work / "sums").write_bytes(sums)
        (work / "sums.gpg").write_bytes(signature)
        result = subprocess.run(
            ["gpg", "--batch", "--no-default-keyring", "--keyring", str(keyring), "--trust-model", "always",
             "--verify", str(work / "sums.gpg"), str(work / "sums")],
            capture_output=True, check=False, env={"GNUPGHOME": str(work)},
        )
    if result.returncode != 0:
        raise PolicySourceError("SHA256SUMS is not signed by the update key")


def checksum_of(sums, name):
    for line in sums.decode().splitlines():
        digest, _, filename = line.strip().partition(" ")
        if filename.strip().lstrip("*") == name:
            return digest
    raise PolicySourceError(f"SHA256SUMS does not list {name}")


def fetch_one(base, keyring, opener=urllib.request.urlopen):
    base = base.rstrip("/")
    sums = download(f"{base}/SHA256SUMS", opener)
    verify_signature(sums, download(f"{base}/SHA256SUMS.gpg", opener), keyring)
    document = download(f"{base}/versions.json", opener)
    if hashlib.sha256(document).hexdigest() != checksum_of(sums, "versions.json"):
        raise PolicySourceError(f"{base}/versions.json does not match its signed checksum")
    return json.loads(document)


def merge(documents):
    merged = {section: [] for section in SECTIONS}
    merged["secure_boot_all"] = []
    for document in documents:
        for section in SECTIONS:
            for entry in document.get(section, []):
                if entry not in merged[section]:
                    merged[section].append(entry)
        boot = document.get("secure_boot")
        if boot and boot not in merged["secure_boot_all"]:
            merged["secure_boot_all"].append(boot)
    return merged


def refresh(urls, keyring, cache, opener=urllib.request.urlopen):
    cache = Path(cache)
    documents, errors = [], []
    for url in urls:
        try:
            documents.append(fetch_one(url, keyring, opener))
        except (PolicySourceError, ValueError) as error:
            errors.append(str(error))
    if documents:
        cache.parent.mkdir(parents=True, exist_ok=True)
        merged = merge(documents)
        temporary = cache.with_suffix(".new")
        temporary.write_text(json.dumps(merged))
        temporary.replace(cache)
        return merged
    if cache.exists():
        return json.loads(cache.read_text())
    raise PolicySourceError("; ".join(errors) or "no policy source")
