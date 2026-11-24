import json
import os
import tempfile
from pathlib import Path


class MemoryStore:
    def __init__(self):
        self.lines = []
        self.votes = {}

    def append(self, line):
        self.lines.append(line)

    def load_lines(self):
        return list(self.lines)

    def save_votes(self, votes):
        self.votes = json.loads(json.dumps(votes))

    def load_votes(self):
        return json.loads(json.dumps(self.votes))


class DirectoryStore:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def append(self, line):
        with open(self.directory / "log.jsonl", "a") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def load_lines(self):
        try:
            return (self.directory / "log.jsonl").read_text().splitlines()
        except FileNotFoundError:
            return []

    def save_votes(self, votes):
        descriptor, name = tempfile.mkstemp(dir=self.directory, prefix="votes-")
        with os.fdopen(descriptor, "w") as handle:
            json.dump(votes, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(name, self.directory / "votes.json")

    def load_votes(self):
        try:
            return json.loads((self.directory / "votes.json").read_text())
        except (FileNotFoundError, ValueError):
            return {}
