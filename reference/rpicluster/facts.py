import os
import platform
from pathlib import Path

ARCHITECTURES = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "amd64", "amd64": "amd64"}
GIB = 1024 ** 3


def read(path, default=""):
    try:
        return Path(path).read_text().strip("\0\n ")
    except OSError:
        return default


def memory_gib(root):
    for line in read(root / "proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            return round(int(line.split()[1]) * 1024 / GIB)
    return 0


def disks(root):
    found = {}
    block = root / "sys/block"
    if not block.is_dir():
        return found
    for entry in sorted(block.iterdir()):
        if entry.name.startswith(("loop", "ram", "zram", "dm-", "md", "nbd", "sr")):
            continue
        sectors = read(entry / "size", "0")
        found[entry.name] = int(sectors) * 512 if sectors.isdigit() else 0
    return found


def root_disk(root):
    for line in read(root / "proc/self/mountinfo").splitlines():
        fields = line.split()
        if len(fields) > 9 and fields[4] == "/usr":
            source = fields[fields.index("-") + 2] if "-" in fields else ""
            name = source.removeprefix("/dev/")
            for disk in disks(root):
                if name == disk or name.startswith(disk):
                    return disk
    return None


def board(root):
    model = read(root / "proc/device-tree/model").lower()
    return "-".join("".join(c if c.isalnum() else " " for c in model).split()) or "unknown"


def collect(root="/"):
    root = Path(root)
    present = disks(root)
    system = root_disk(root)
    others = [size for name, size in present.items() if name != system]
    return {
        "arch": ARCHITECTURES.get(platform.machine(), platform.machine()),
        "memory-gib": memory_gib(root),
        "disk-gib": round(max(others, default=0) / GIB),
        "cpu-count": os.cpu_count() or 0,
        "board": board(root),
        "tpm": (root / "dev/tpmrm0").exists(),
    }
