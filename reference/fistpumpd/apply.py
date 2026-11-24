import json
import os
import subprocess
from pathlib import Path

API_PORT = 6443
CHECKS = {
    "server": 'script "/usr/bin/curl --silent --insecure --max-time 2 --output /dev/null https://127.0.0.1:6443/livez"',
    "ingress": 'script "/usr/bin/curl --silent --max-time 2 --output /dev/null http://127.0.0.1:80/"',
}
GLOBALS = """global_defs {
    enable_script_security
    script_user nobody
}
"""


def holders(log, role):
    return [m["slot"] for m in log.active() if role in m["roles"]]


def priority(rank, count, index):
    step = max(1, min(10, 90 // max(count, 1)))
    return max(1, 100 - ((rank - index) % max(count, 1)) * step)


def first_server_slot(log):
    slots = [slot for slot, member in log.members.items() if "server" in member["roles"]]
    return min(slots) if slots else None


def plan(log, slot, topology, genesis, interface):
    me = log.member(slot)
    roles = me["roles"]
    active = log.active()
    vips = topology.get("vips", {})
    instances = []
    for group_index, (role, addresses) in enumerate(sorted(vips.items())):
        if role not in roles or role not in CHECKS:
            continue
        group = holders(log, role)
        rank = group.index(slot)
        for index, address in enumerate(addresses):
            instances.append({
                "name": f"{role.upper()}{index + 1}",
                "router_id": 60 + 10 * group_index + index,
                "address": address,
                "priority": priority(rank, len(group), index),
                "check": role,
            })
    api = (vips.get("server") or [None])[0]
    init = first_server_slot(log)
    is_server = "server" in roles
    is_agent = "agent" in roles and not is_server
    ready = len(active) >= genesis["min_members"]
    k3s = {}
    if is_server:
        k3s["tls-san"] = list(vips.get("server", []))
        if slot == init:
            k3s["cluster-init"] = True
        elif api:
            k3s["server"] = f"https://{api}:{API_PORT}"
    elif is_agent and api:
        k3s["server"] = f"https://{api}:{API_PORT}"
    start_k3s = (is_server or is_agent) and ready and (slot == init or api is not None)
    return {
        "slot": slot,
        "rank": log.rank_of(slot),
        "members": len(active),
        "roles": roles,
        "topology": (log.topology or {}).get("version"),
        "keepalived": {"interface": interface, "instances": instances},
        "k3s": k3s,
        "start_k3s": start_k3s,
        "creates_tokens": is_server and slot == init,
        "needs_tokens": [kind for kind, wanted in (("server", is_server and slot != init), ("agent", is_agent or (is_server and slot != init))) if wanted],
    }


def render_keepalived(settings):
    lines = [GLOBALS]
    for kind in sorted({instance["check"] for instance in settings["instances"]}):
        lines.append(f"vrrp_script chk_{kind} {{\n    {CHECKS[kind]}\n    interval 2\n    fall 2\n    rise 2\n}}\n")
    for instance in settings["instances"]:
        lines.append(
            f"vrrp_instance {instance['name']} {{\n"
            f"    interface {settings['interface']}\n"
            "    state BACKUP\n"
            f"    virtual_router_id {instance['router_id']}\n"
            "    advert_int 1\n"
            "    preempt_delay 60\n"
            f"    priority {instance['priority']}\n"
            f"    virtual_ipaddress {{\n        {instance['address']}/24\n    }}\n"
            f"    track_script {{\n        chk_{instance['check']}\n    }}\n"
            "}\n"
        )
    return "\n".join(lines)


APPENDED = ("tls-san",)


def render_k3s(settings):
    lines = []
    for key, value in settings.items():
        if isinstance(value, list):
            if value:
                lines.append(f"{key}+:" if key in APPENDED else f"{key}:")
                lines.extend(f"  - {item}" for item in value)
        elif isinstance(value, bool):
            lines.append(f"{key}: {str(value).lower()}")
        else:
            lines.append(f"{key}: {value}")
    return "\n".join(lines) + "\n" if lines else ""


def write_if_changed(path, content, mode=0o644):
    path = Path(path)
    try:
        if path.read_text() == content:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".new")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(content)
    os.replace(temporary, path)
    return True


def remove(path):
    try:
        Path(path).unlink()
        return True
    except FileNotFoundError:
        return False


class Host:
    def __init__(self, run=None):
        self.run = run or self.systemctl

    def systemctl(self, *arguments):
        subprocess.run(arguments, capture_output=True, check=False, timeout=120)


def apply(settings, root="/", run_directory="/run/fistpumpd", host=None):
    host = host or Host()
    root = Path(root)
    changed = []
    state = json.dumps({key: settings[key] for key in ("slot", "rank", "members", "roles", "topology", "start_k3s")}, sort_keys=True)
    write_if_changed(Path(run_directory) / "state.json", state + "\n")

    for role_file in (root / "etc/node-role.d").glob("*.conf") if (root / "etc/node-role.d").is_dir() else []:
        if role_file.stem not in settings["roles"]:
            role_file.unlink()
    for role in settings["roles"]:
        if write_if_changed(root / "etc/node-role.d" / f"{role}.conf", f"ROLE={role}\n"):
            changed.append("roles")
    if "roles" in changed:
        host.run("hostnamectl", "tags", *settings["roles"])
        host.run("systemctl", "start", "systemd-sysupdate-auto-enable.service")

    keepalived = settings["keepalived"]
    config = Path(run_directory) / "keepalived.conf"
    if keepalived["instances"]:
        if write_if_changed(config, render_keepalived(keepalived)):
            host.run("systemctl", "reload-or-restart", "keepalived.service")
    elif remove(config):
        host.run("systemctl", "stop", "keepalived.service")

    dropin = root / "etc/rancher/k3s/config.yaml.d/10-role.yaml"
    if settings["k3s"]:
        write_if_changed(dropin, render_k3s(settings["k3s"]))
    else:
        remove(dropin)

    ready = Path(run_directory) / "k3s-ready"
    if settings["start_k3s"]:
        if write_if_changed(ready, "ready\n"):
            host.run("systemctl", "start", "--no-block", "k3s.service")
    else:
        remove(ready)
    return changed
