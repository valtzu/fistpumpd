import json
import re
from pathlib import Path

DEFAULT_PORT = 17947
DISCOVERY_PORT = 17946


class GenesisError(ValueError):
    pass


def load(path):
    try:
        document = json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise GenesisError(f"{path}: {error}") from None
    return parse(document)


def parse(document):
    if not isinstance(document, dict):
        raise GenesisError("genesis is an object")
    minimum = document.get("min_members", 2)
    if not isinstance(minimum, int) or minimum < 2:
        raise GenesisError("min_members is at least 2: a lone node never starts a cluster")
    urls = document.get("policy_urls", [])
    if not isinstance(urls, list) or any(not isinstance(u, str) or not re.match(r"^https://", u) for u in urls):
        raise GenesisError("policy_urls are https URLs")
    return {
        "min_members": minimum,
        "port": int(document.get("port", DEFAULT_PORT)),
        "discovery_port": int(document.get("discovery_port", DISCOVERY_PORT)),
        "policy_urls": urls,
        "seeds": [str(s) for s in document.get("seeds", [])],
        "founder_wait": float(document.get("founder_wait", 20)),
        "evict_after": float(document.get("evict_after", 300)),
        "attest_interval": float(document.get("attest_interval", 30)),
        "join_retry": float(document.get("join_retry", 10)),
    }
