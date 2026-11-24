import argparse
import json
import logging
import os
import re
import signal
import subprocess
import sys
from pathlib import Path

from . import daemon, genesis, net, policysource, tpm

RUN = "/run/fistpumpd"
STATE = "/var/lib/fistpumpd"
GENESIS = "/usr/lib/fistpumpd/genesis.json"
TOPOLOGIES = ("/etc/fistpumpd/topology.json", "/usr/lib/fistpumpd/topology.json")
KEYRINGS = ("/usr/lib/systemd/import-pubring.pgp", "/usr/lib/systemd/import-pubring.gpg")
BUILD_CERTIFICATE = "/usr/lib/verity.d/mkosi.crt"


def default_route():
    output = subprocess.run(["ip", "-4", "-o", "route", "get", "1.1.1.1"], capture_output=True, text=True, check=False).stdout
    device, source = re.search(r"dev (\S+)", output), re.search(r"src (\S+)", output)
    return (device.group(1) if device else "eth0"), (source.group(1) if source else None)


def run_daemon(arguments):
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    document = genesis.load(arguments.genesis)
    interface, source = default_route()
    if source is None:
        sys.exit("no default route yet")
    keyring = next((k for k in KEYRINGS if Path(k).exists()), KEYRINGS[0])
    certificate = Path(BUILD_CERTIFICATE).read_bytes() if Path(BUILD_CERTIFICATE).exists() else None
    cache = Path(arguments.state) / "policy.json"
    instance = daemon.Daemon(
        {"state": arguments.state, "run": RUN, "topology": arguments.topology},
        document, tpm.TpmProver(), tpm.TpmVerifier(), f"{source}:{document['port']}", build_certificate=certificate,
        policy_loader=lambda: policysource.refresh(document["policy_urls"], keyring, cache), interface=interface,
    )
    signal.signal(signal.SIGTERM, lambda *_: instance.stop())
    instance.run()


def control(arguments):
    client = net.ControlClient(f"{RUN}/control.sock")
    return client.call(arguments.command, {"slot": getattr(arguments, "slot", None), "reason": getattr(arguments, "reason", "")})


def reset_sign(arguments):
    from cryptography.hazmat.primitives import serialization

    from . import chain

    document = json.loads(Path(arguments.log).read_text())
    entries = document["entries"] if isinstance(document, dict) else document
    log = chain.Chain(Path(arguments.certificate).read_bytes())
    for entry in entries:
        log.append(entry)
    keep = [int(slot) for slot in arguments.keep.split(",")]
    entry = {"index": len(log), "prev": log.head, "type": "reset", "body": {"members": keep, "reason": arguments.reason}}
    key = serialization.load_pem_private_key(Path(arguments.key).read_bytes(), None)
    entry["build_sig"] = chain.sign_build(key, entry)
    log.check(entry)
    print(json.dumps(entry, sort_keys=True))


def submit(arguments):
    entry = json.loads(Path(arguments.file).read_text())
    return net.ControlClient(f"{RUN}/control.sock").call("submit", {"entry": entry})


def show_status(reply):
    status = reply["status"]
    print(f"phase {status.get('phase')}  slot {reply['slot']}  topology v{reply['topology']}  log length {reply['length']}")
    for member in reply["members"]:
        node = member["node"]
        print(f"  slot {member['slot']:<3} {node['addr']:<22} roles {','.join(member['roles']) or '-':<24} {'failing' if str(member['slot']) in reply['failing'] else 'ok'}")


def main():
    parser = argparse.ArgumentParser(prog="fistpumpd")
    parser.add_argument("--state", default=STATE)
    parser.add_argument("--genesis", default=GENESIS)
    parser.add_argument("--topology", default=next((t for t in TOPOLOGIES if Path(t).exists()), TOPOLOGIES[0]))
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("daemon")
    commands.add_parser("status")
    commands.add_parser("log")
    evict = commands.add_parser("evict")
    evict.add_argument("slot", type=int)
    evict.add_argument("--reason", default="operator request")
    signing = commands.add_parser("reset-sign", help="offline: sign a reset entry with the build key")
    signing.add_argument("--log", required=True)
    signing.add_argument("--key", required=True)
    signing.add_argument("--certificate", required=True)
    signing.add_argument("--keep", required=True, help="comma-separated slots that stay")
    signing.add_argument("--reason", default="operator reset")
    send = commands.add_parser("submit", help="hand a signed entry to the local member")
    send.add_argument("file")
    arguments = parser.parse_args()
    if arguments.command == "daemon":
        return run_daemon(arguments)
    if arguments.command == "reset-sign":
        return reset_sign(arguments)
    if arguments.command == "submit":
        try:
            print(json.dumps(submit(arguments)))
        except (net.TransportError, net.Refused) as error:
            sys.exit(f"fistpumpd: {error}")
        return
    try:
        reply = control(arguments)
    except (net.TransportError, net.Refused) as error:
        sys.exit(f"fistpumpd: {error}")
    if arguments.command == "status":
        show_status(reply)
    else:
        print(json.dumps(reply, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
