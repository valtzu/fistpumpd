import hashlib
import json
import logging
import os
import random
import threading
import time
from pathlib import Path

from . import apply, attest, canonical, chain, discovery, facts as fact_source, genesis as genesis_module
from . import identity, member as members, net, policy as policy_module, policysource, store as stores, tls, tokens as token_store
from . import topology as topologies
from .candidate import Candidate

log = logging.getLogger("rpi-cluster")
POLICY_MAX_AGE = 3600


class Switch:
    def __init__(self, target):
        self.target = target

    def handle(self, method, payload):
        return self.target.handle(method, payload)


class ControlSwitch:
    def __init__(self, daemon):
        self.daemon = daemon

    def handle(self, method, payload):
        return self.daemon.control(method, payload)


class Observer:
    def __init__(self, daemon):
        self.daemon = daemon

    def healthy(self, record):
        return self.daemon.attest_member(record)


class Daemon:
    def __init__(self, paths, genesis, tpm, verifier, address, facts=None, host=None, discovery_targets=None,
                 build_certificate=None, policy_loader=None, clock=time.time, interface="eth0", seal=True):
        self.paths = paths
        self.genesis = genesis
        self.tpm = tpm
        self.verifier = verifier
        self.address = address
        self.facts = facts if facts is not None else fact_source.collect()
        self.host = host
        self.targets = discovery_targets or [("255.255.255.255", genesis["discovery_port"])]
        self.build_certificate = build_certificate
        self.policy_loader = policy_loader
        self.clock = clock
        self.interface = interface
        self.key = identity.load_key(Path(paths["state"]) / "identity")
        key_path, cert_path, fingerprint = tls.create(Path(paths["state"]) / "identity")
        ek = attest.ek_hash(tpm.hello())
        self.record = {"sign_pub": identity.public_hex(self.key), "tls_fp": fingerprint, "ek_hash": ek, "addr": address}
        self.tls_paths = (cert_path, key_path)
        self.store = stores.DirectoryStore(Path(paths["state"]) / "log")
        self.tokens = token_store.Tokens(Path(paths["state"]) / "tokens", credstore=paths.get("credstore", token_store.CREDSTORE), seal=seal)
        self.transport = net.HttpsTransport(self.pin)
        self.switch = Switch(None)
        self.member = None
        self.policy = None
        self.policy_time = 0.0
        self.policy_error = None
        self.topology = None
        self.failing = {}
        self.stop_event = threading.Event()
        self.servers = []
        self.serving = False
        self.state_lock = threading.Lock()
        self.status = {"phase": "starting"}

    def pin(self, address):
        if self.member is None:
            return None
        for record in self.member.log.active():
            if record["node"]["addr"] == address:
                return record["node"]["tls_fp"]
        return None

    def load_topology(self):
        document = json.loads(Path(self.paths["topology"]).read_text())
        self.topology = topologies.parse(document)

    def load_policy(self, force=False):
        if self.policy and not force and self.clock() - self.policy_time < POLICY_MAX_AGE:
            return self.policy
        try:
            document = self.policy_loader()
            self.policy = policy_module.Policy(document)
            self.policy_time = self.clock()
            self.policy_error = None
        except Exception as error:
            self.policy_error = str(error)
            log.warning("policy refresh failed: %s", error)
            if self.policy is None:
                self.policy = policy_module.Policy({})
        if self.member:
            self.member.policy = self.policy
        return self.policy

    def info(self):
        member = self.member
        first = member.log.entries[0] if member and member.log.entries else None
        return {
            "role": "member" if member else "candidate",
            "addr": self.address,
            "ek_hash": self.record["ek_hash"],
            "genesis": chain.entry_hash(first) if first else None,
            "length": len(member.log) if member else 0,
        }

    def serve(self, target):
        self.switch.target = target
        if not self.serving:
            self.serving = True
            cert, key = self.tls_paths
            host, port = net.split(self.address)
            bind = f"0.0.0.0:{port}" if host not in ("127.0.0.1", "::1") else self.address
            self.servers.append(net.Server(self.switch, bind, cert, key).start())
            self.servers.append(discovery.Responder(self.genesis["discovery_port"], self.info, bind="127.0.0.1" if host == "127.0.0.1" else "0.0.0.0").start())

    def start_member(self):
        lines = self.store.load_lines()
        if lines:
            member = members.restore(self.key, self.record, self.store, self.topology, self.policy, self.verifier, self.transport,
                                     self.build_certificate, observer=Observer(self), clock=self.clock, on_change=self.changed,
                                     tpm=self.tpm, tokens=self.tokens)
            if member.slot is None:
                self.status = {"phase": "evicted"}
                return None
            return member
        return None

    def become(self, member):
        member.observer = Observer(self)
        member.on_change = self.changed
        member.tokens = self.tokens
        self.member = member
        self.serve(member)
        self.status = {"phase": "member", "slot": member.slot}
        self.changed(member)

    def candidate(self):
        return Candidate(self.key, self.record, self.facts, self.tpm, self.store, self.topology, self.policy, self.verifier,
                         self.transport, self.build_certificate, observer=Observer(self), clock=self.clock, on_change=self.changed,
                         tokens=self.tokens)

    def join_or_found(self):
        candidate = self.candidate()
        self.serve(candidate)
        started = self.clock()
        while not self.stop_event.is_set():
            self.load_policy()
            replies = discovery.probe(self.targets, wait=3.0, bind="127.0.0.1" if net.split(self.address)[0] == "127.0.0.1" else "0.0.0.0")
            seeds = [r["addr"] for r in replies if r.get("role") == "member"] + self.genesis["seeds"]
            if seeds:
                try:
                    return candidate.join(seeds)
                except (members.Refused, members.TransportError) as error:
                    self.status = {"phase": "joining", "error": str(error)}
                    log.warning("join refused: %s", error)
                    self.stop_event.wait(self.genesis["join_retry"])
                    continue
            others = [r["ek_hash"] for r in replies if r.get("role") == "candidate" and r.get("addr") != self.address]
            if self.clock() - started >= self.genesis["founder_wait"] and self.record["ek_hash"] <= min(others, default=self.record["ek_hash"]):
                log.info("no cluster found, founding one")
                return members.found(self.key, self.record, self.facts, self.store, self.topology, self.policy, self.verifier,
                                     self.transport, self.build_certificate, observer=Observer(self), clock=self.clock,
                                     on_change=self.changed, tpm=self.tpm, tokens=self.tokens)
            self.status = {"phase": "waiting", "candidates": len(others)}
            self.stop_event.wait(2)
        return None

    def attest_member(self, record):
        node = record["node"]
        try:
            prover = self.transport.prover(node["addr"], node["tls_fp"])
            pcrs = attest.attest(prover, self.verifier, node["ek_hash"], attest.new_nonce(), node["sign_pub"], node["tls_fp"])
            self.load_policy()
            self.policy.check(pcrs)
            return record.get("pcr1") in (None, pcrs.get("1"))
        except Exception as error:
            log.info("slot %s failed attestation: %s", record["slot"], error)
            return False

    def changed(self, member):
        with self.state_lock:
            if member.slot is None or member.log.member(member.slot) is None:
                self.status = {"phase": "evicted"}
                return
            settings = apply.plan(member.log, member.slot, self.topology, self.genesis, self.interface)
            self.settings = settings
            if settings["creates_tokens"]:
                self.tokens.create()
            self.install_tokens(member, settings)
            apply.apply(settings, self.paths.get("root", "/"), self.paths["run"], self.host)

    def install_tokens(self, member, settings):
        for kind in settings["needs_tokens"]:
            if self.tokens.get(kind) is None:
                value = member.fetch_token(kind)
                if value:
                    self.tokens.put(kind, value)
        wanted = ("server", "agent") if "server" in settings["roles"] else ("agent",)
        try:
            self.tokens.install_credentials(wanted)
        except OSError as error:
            log.warning("could not install credentials: %s", error)

    def housekeeping(self):
        member = self.member
        member.catch_up()
        if member.log.member(member.slot) is None:
            self.status = {"phase": "evicted"}
            self.stop_event.set()
            return
        self.load_policy()
        self.reload_topology(member)
        self.changed(member)
        self.adopt_topology(member)
        self.check_peers(member)
        self.status = {"phase": "member", "slot": member.slot, "members": len(member.log.active()), "length": len(member.log),
                       "policy_error": self.policy_error}

    def reload_topology(self, member):
        try:
            newest = topologies.parse(json.loads(Path(self.paths["topology"]).read_text()))
        except (OSError, ValueError, topologies.TopologyError) as error:
            log.warning("topology not reloaded: %s", error)
            return
        if newest["version"] >= self.topology["version"] and newest["digest"] != self.topology["digest"]:
            self.topology = newest
            member.topology = newest

    def adopt_topology(self, member):
        current = (member.log.topology or {}).get("version", 0)
        if self.topology["version"] > current:
            self.stop_event.wait(member.log.rank_of(member.slot) * 2 + random.random())
            member.catch_up()
            if self.topology["version"] > (member.log.topology or {}).get("version", 0):
                try:
                    member.propose_topology()
                except (members.Refused, members.TransportError) as error:
                    log.info("topology adoption not agreed yet: %s", error)

    def check_peers(self, member):
        now = self.clock()
        peers = member.peers()
        for peer in peers:
            if self.attest_member(peer):
                self.failing.pop(peer["slot"], None)
            else:
                self.failing.setdefault(peer["slot"], now)
        for slot in list(self.failing):
            if member.log.member(slot) is None:
                del self.failing[slot]
        for slot, since in list(self.failing.items()):
            if now - since >= self.genesis["evict_after"]:
                self.stop_event.wait(member.log.rank_of(member.slot) * 2 + random.random())
                try:
                    member.propose_evict(slot, f"failed attestation for {int(now - since)} s")
                except (members.Refused, members.TransportError) as error:
                    log.info("eviction of slot %s not agreed: %s", slot, error)

    def control(self, method, payload):
        if method == "status":
            member = self.member
            return {"status": self.status, "slot": member.slot if member else None,
                    "members": member.log.active() if member else [], "head": member.log.head if member else None,
                    "length": len(member.log) if member else 0, "failing": {str(k): v for k, v in self.failing.items()},
                    "settings": getattr(self, "settings", None), "topology": self.topology["version"]}
        if method == "log":
            return {"entries": self.member.log.entries if self.member else []}
        if method == "evict":
            if self.member is None:
                raise members.Refused("this node is not a member")
            entry = self.member.propose_evict(int(payload["slot"]), str(payload.get("reason", "operator request")))
            return {"entry": entry}
        if method == "submit":
            if self.member is None:
                raise members.Refused("this node is not a member")
            try:
                self.member.commit(payload["entry"])
            except chain.ChainError as error:
                raise members.Refused(str(error)) from None
            return {"length": len(self.member.log)}
        raise members.Refused(f"unknown control method {method}")

    def run(self):
        control = net.ControlServer(ControlSwitch(self), Path(self.paths["run"]) / "control.sock").start()
        self.servers.append(control)
        self.load_topology()
        self.load_policy(force=True)
        member = self.start_member()
        if member is None and self.status.get("phase") != "evicted":
            member = self.join_or_found()
        if member is None:
            return
        if member.log.member(member.slot) is None:
            self.status = {"phase": "evicted"}
            return
        if self.member is None:
            self.become(member)
        while not self.stop_event.is_set():
            try:
                self.housekeeping()
            except Exception:
                log.exception("housekeeping failed")
            self.stop_event.wait(self.genesis["attest_interval"])

    def stop(self):
        self.stop_event.set()
        for server in self.servers:
            server.stop()
