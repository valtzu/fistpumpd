# Protocol

The design of fistpumpd: a signed, quorum-agreed admission log for a small cluster. The Go code in `cluster/` implements it, and `testdata/vectors.json` pins the wire format: canonical encoding, hashes, signatures, quorum sizes, role selection, policy checks and the generated configuration. The vectors were produced by the Python prototype this was ported from, which is no longer kept. Another implementation must reproduce them.

## Problem

Provisioning depended on one machine, the attestation server: its UI approved nodes, its Keylime verifier attested them, and `roles.yaml` held the topology. That made it a central authority and a single point of failure, let admissions run in parallel (two nodes could both become the first and run `cluster-init`), and left hostnames hardcoded where an order or a rank was needed (`@rpi-N priority` in `keepalived.conf`, which silently fell back to "highest IP wins every VIP" for any other name).

## Goals

1. No central authority at run time. The image build key stays the root of trust (intentional).
2. Admissions happen one at a time, in one agreed order.
3. History is readable by anyone and cannot be rewritten.
4. The topology (which roles exist and how nodes get them) is signed at build time and versioned separately from the OS. It fixes no number of nodes.
5. `cluster-init` only happens once a second node is in the network.
6. No node names anywhere. A node's rank comes from the log.
7. Nodes attest each other, with a quorum.

Not goals: public participation, tokens, mining, tolerating a malicious build key, or tolerating a hostile majority of members.

## Not a blockchain

A permissioned, hash-chained, quorum-signed log. No proof of work or stake. The consensus is small: a member signs at most one entry per index (a persistent vote lock), and an entry needs `quorum(n)` signatures from the `n` active members, so two different entries cannot both reach quorum. `quorum(n) = ceil((n + f + 1) / 2)` with `f = floor((n - 1) / 3)`: 1, 2, 2, 3, 4, 4, 5 for n = 1 to 7. With fewer than four members `f` is zero, so a cluster of up to three members tolerates crashes, not a malicious member.

## Artifacts

| Artifact | Content | Signed by | Delivered as |
|---|---|---|---|
| Genesis | quorum parameters, minimum member count, policy URLs | the image (dm-verity signed `/usr`) | `/usr/lib/fistpumpd/genesis.json` |
| Topology | role definitions, selectors, VIP lists, version | build key (signed confext) | `topology/` project, sysupdate component `topology`, default copy in the image |
| Policy | accepted PCR values per image, firmware and boot chain | update key (gpg over `SHA256SUMS`) | `versions.json` as published today |

The topology and the policy are fetched and verified by each node itself. The policy loader (`policysource.go`) checks the gpg signature of `SHA256SUMS`, then the checksum of `versions.json`, merges every configured channel, and falls back to the last good copy when the bucket is down.

## The log

`cluster/chain.go`. Each entry is `{index, prev, type, body, sigs}`. Its hash is the SHA-256 of the canonical JSON of the first four fields, and every signature (Ed25519, keyed by the signer's slot) covers that hash. Types:

- `admit`: node record (`sign_pub`, `tls_fp`, `ek_hash`, `addr`), roles, facts, topology version and digest, the image the node runs, its PCR 1. Index 0 is the founder, signed by itself. All others need a quorum.
- `evict`: a slot and a reason. The target's own signature does not count.
- `topology`: a new topology version and digest. Versions only go up.
- `reset`: a set of surviving slots, signed by the build key instead of members (recovery, below).

The index of an `admit` is the node's **slot**. Slots are never reused. `Chain` replays and verifies everything from entry 0, so any node (or the UI) can check the whole history from the entries alone.

## Admission

`member.go`, `candidate.go`.

1. A new node (candidate) asks a member to sponsor it (`join`): its node record, facts and address.
2. The sponsor attests it, runs the role selection, and builds an `admit` proposal for the next index.
3. Each voter re-validates the proposal itself: index and `prev`, the node is new, its own topology matches the proposal's, its own role selection gives the same roles, and a **fresh attestation** of the candidate passes the policy. Then it records a vote lock and signs.
4. With a quorum of signatures the sponsor appends the entry and pushes it to every member and the candidate. The candidate fetches the whole log, verifies it, finds itself in it and becomes a member.

If a sponsor dies after collecting some signatures, members that already voted answer later proposals for the same index with the pending entry. The next sponsor finishes it first, then proposes its own. Vote locks expire after five minutes, which trades strict safety for liveness when a candidate disappears mid-admission.

### Attestation

`attest.go`, `tpm.go`. The verifier never trusts the candidate's claims:

1. EK to AK binding: the verifier makes a credential for the candidate's EK and AK name (`tpm2_makecredential`), and the candidate proves both keys sit in one TPM by activating it (`tpm2_activatecredential`).
2. A quote over PCRs 0, 1, 2, 3, 7 and 11 whose qualifying data is the hash of a fresh nonce, the candidate's log signing key and its TLS fingerprint. That binds the keys to the measured boot state.
3. The PCR values are checked against the policy (PCR 0, 7 and 11 always, 2 and 3 when the policy lists values). PCR 1 identifies the board and is pinned in the `admit` entry; later attestations must match it.

As with Keylime today, EK certificates are not checked: the trust is in the measured software and in first sight of the EK.

## Role selection

`topology.go`, `selector.go`. The topology does not list nodes. It lists roles in priority order:

```json
{"name": "server", "selector": {"arch": "arm64", "memory-gib": ">=4"}, "min": 3, "max": 5, "conflicts": ["agent"]}
```

- **Facts** (`facts.go`) are collected by the attested node software: `arch`, `memory-gib`, `disk-gib` (largest disk that is not the OS disk), `cpu-count`, `board`, `tpm`. Voters recompute the selection from the facts in the proposal; the facts come from software whose measurement was just verified.
- **Selector**: equality, `>=`, `<=`, `>`, `<`, `!=`, or a list meaning any of. A missing fact never matches.
- **Coexistence**: roles may share a node unless one lists the other under `conflicts` (symmetric).
- **Demand**: `max` caps a role; no `max` means every matching node gets it. `min` is not a gate: it reports roles with too few holders (`unmet`) and nothing more.

The first matching, non-conflicting, uncapped roles are granted. Roles are fixed at admission. Changing a rule does not strip running nodes of roles; moving a node is an `evict` and a new admission.

## What a member does with the log

`apply.go`. On every change, from the log alone:

- **Roles**: markers in `/etc/node-role.d/`, machine tags (which make sysupdate enable the `k3s-server` or `k3s-agent` component).
- **keepalived**: `/run/fistpumpd/keepalived.conf` is generated. For each VIP of a role the node holds, priority is `100 - ((rank - index) mod n) * step`, where `rank` is the node's position among the holders of that role and `n` their number. VIPs are spread evenly over any set of nodes and no name is involved. Health gates (`chk_apiserver`, `chk_ingress`) stay.
- **k3s**: `/etc/rancher/k3s/config.yaml.d/10-role.yaml` with `tls-san+` for the server VIPs, `cluster-init` on the first server ever admitted, and `server: https://<first VIP>:6443` for everyone else. `/run/fistpumpd/k3s-ready` is created once the log holds the genesis minimum of members. The base image's `k3s.service` drop-in requires that file, so a lone node never starts a cluster.
- **Tokens**: the init node creates the server and agent tokens. Others fetch them from a member over pinned TLS with a challenge response signed by their log key; servers get both, agents only the agent token. They are stored with `systemd-creds` sealed to the TPM.

## Network

`net.go`. Members speak JSON RPC over TLS 1.3 on port 17947. Each member has a self-signed certificate whose fingerprint is in its `admit` entry, and clients pin it. The first contact of a candidate with a seed is unpinned, which is acceptable because the log is self-verifying and no secret crosses that connection. Log entries are public by design, so the port is not firewalled.

Discovery (`discovery.go`) is a UDP broadcast on 17946 where members and candidates answer with their address. A candidate that finds a member joins. If it finds none, it waits `founder_wait` seconds and, if its EK hash is the lowest among the candidates it heard, founds the log. Two nodes booting together elect one founder; a node that boots later finds that member and joins. A fork (two logs with different entry 0) cannot be merged. It is not repaired but it is visible, and a lone founder never starts k3s, so no second cluster results.

## Failure handling

- Every member attests one peer at a time every `attest_interval` seconds. A peer that fails for `evict_after` seconds is proposed for eviction by the observers. A voter signs an `evict` only if its own fresh attestation of the target fails now.
- A node whose slot is not active stops. Rejoining is manual (wipe `/var/lib/fistpumpd`).
- **Lost quorum**: `fistpumpd reset-sign` creates a `reset` entry offline with the build key (`--log` is the log from a surviving member, `--keep` the slots that stay). `fistpumpd submit` hands it to a member, which applies and pushes it. Members not in `--keep` are evicted.
- Topology changes: a node that finds a higher topology version than the log's proposes a `topology` entry; the quorum signs only if it has the same topology locally.

## Operating it

```
fistpumpd status            # members, roles, failing peers
fistpumpd log               # the verified log as JSON
fistpumpd evict SLOT        # propose an eviction
./publish topology-canary     # after `mkosi build` in topology/
./publish topology-promote
```

The attestation UI gains a read-only `Cluster log` page (set `cluster_members` in `ui/config.yaml`) that fetches a member's log and verifies every entry before showing it.

## Tests

`make test` runs everything except the swtpm tests (about a minute, with the race detector). `make test-tpm` runs the swtpm tests, which need `swtpm` and `tpm2-tools` (the Makefile uses a container).

## Known limits

- **Member addresses** are fixed at admission. A node whose address changes stays in the log under the old one until it is evicted and re-admitted. An `address` entry would fix that.
- **Quorum arithmetic** gives no Byzantine tolerance below four members, and a two-member cluster stops when either member does.
- **Vote lock expiry** (five minutes) can in theory let two entries reach quorum if a partition and a vanished candidate coincide.
- **Image key** compromise is out of scope: the build key signs the genesis, topology and reset entries.
- **Legacy path**: the Keylime payload flow (`node-role`, `apply-payload`, role confext images, `roles.yaml`) and the approval UI's approve action are still in the tree for images without genesis. They can go once nodes run the new image.
- **Hardware**: the TPM code runs against `swtpm`, not a real SLB9670 on a Pi 4. The discovery broadcast and keepalived interaction are untested on a real network.
- **Rollout**: the k3s sysexts need a rebuild (`K3S_SYSEXT_REV` is bumped) so servers load the agent token, and nodes on an image built before this change do not take part in the log.
