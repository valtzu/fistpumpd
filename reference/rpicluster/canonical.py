import hashlib
import json


def dumps(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def digest(value):
    return hashlib.sha256(dumps(value)).hexdigest()
