# Protocol

This document describes how fistpumpd members agree on the membership of a cluster: the log, the consensus rule, admission and attestation, role selection, and the network and failure behavior. For what the daemon is for and how to run it, see the [README](../README.md).

Membership is a hash-chained log that members extend by quorum. A machine is admitted only after the members have checked its TPM, and every member derives its own configuration from the log. The only trusted party is the build key that signs the OS image and the topology.

## Consensus

An entry needs `quorum(n)` signatures from the `n` active members, where `quorum(n) = ceil((n + f + 1) / 2)` and `f = floor((n - 1) / 3)`: 1, 2, 2, 3, 4, 4, 5 for n = 1 to 7. A member records a vote lock for each index before it signs, so two different entries cannot both reach quorum. With fewer than four members `f` is zero: the cluster then tolerates crashes, not a malicious member.

There is no leader election or gossip layer. The member that receives a join request sponsors it: it proposes the next entry and collects signatures. If two sponsors race for one index, the members that already voted answer the second with the pending entry, and the second sponsor finishes it before proposing its own.

## Trusted inputs

| Input | Content | Trusted because |
|---|---|---|
| Genesis (`/usr/lib/fistpumpd/genesis.json`) | minimum member count, ports, policy URLs, timings | it is part of the signed OS image |
| Topology (`/etc/fistpumpd/topology.json`, else `/usr/lib/fistpumpd/topology.json`) | roles, selectors, floating addresses, a version | it ships in the signed image or in a signed confext |
| Build certificate (`/usr/lib/verity.d/mkosi.crt`) | the public key of the build key | it is part of the signed OS image |
| Policy | the PCR values that are accepted | gpg signature over `SHA256SUMS`, checked against `/usr/lib/systemd/import-pubring.pgp` |

The policy is a JSON document that each node fetches from the configured URLs, checks (signature of `SHA256SUMS`, then the checksum of `versions.json`), merges across URLs, and caches. It lists accepted values per PCR:

| PCR | Source in the document |
|---|---|
| 0 | `firmware[].pcr0` |
| 2 | `peripheral_firmware[].pcr2` (optional) |
| 3 | `eeprom_configuration[].pcr3` (optional) |
| 7 | `secure_boot.pcr7` and `secure_boot_all[].pcr7` |
| 11 | `versions[].pcr11` (the OS image) |

PCR 0, 7 and 11 must have at least one accepted value. PCR 2 and 3 are checked when the policy lists values for them. PCR 1 identifies the board and is pinned in the admission entry instead.

## The log

Each entry is `{index, prev, type, body, sigs}`. Its hash is the SHA-256 of the canonical JSON of `index`, `prev`, `type` and `body`. Every signature (Ed25519, keyed by the signer's slot) covers that hash.

Canonical JSON: keys sorted by code point, no whitespace, strings in UTF-8 with only `"`, `\` and control characters escaped (short forms for `\n \r \t \b \f`, `\u00xx` otherwise), integers only.

Entry types:

- `admit`: the node record (`sign_pub`, `tls_fp`, `ek_hash`, `addr`), its roles, the facts it reported, the topology version and digest, the image it runs, and its PCR 1. Index 0 is the founder and signs itself. Every other admission needs a quorum.
- `evict`: a slot and a reason. The target's own signature does not count.
- `topology`: a new topology version and digest. Versions only go up.
- `reset`: the slots that survive, signed by the build key instead of members (recovery, below).

The index of an `admit` entry is the node's **slot**. Slots are never reused. A node can replay the whole log and check every signature, so it needs to trust nothing but its genesis and the build certificate.

## Admission

1. A new node (the candidate) asks a member to sponsor it, sending its node record and its facts.
2. The sponsor attests the candidate, runs the role selection, and proposes an `admit` entry for the next index.
3. Each voter validates the proposal itself: the index and `prev` fit, the node is new, the voter's topology is the one in the proposal, the voter's own role selection gives the same roles, and a fresh attestation of the candidate passes the policy. Then it records a vote lock and signs.
4. With a quorum of signatures the sponsor appends the entry and pushes it to the members and to the candidate. The candidate fetches the whole log, verifies it, finds itself in it, and becomes a member.

Vote locks expire after five minutes. That trades strict safety for liveness in one case: a sponsor and a candidate vanish after some members have voted.

### Attestation

The verifier does not trust the candidate's claims:

1. **Key binding.** The verifier makes a credential for the candidate's endorsement key and attestation key name (`tpm2_makecredential`). The candidate proves that both keys sit in one TPM by activating it (`tpm2_activatecredential`).
2. **Quote.** The candidate signs a quote over PCRs 0, 1, 2, 3, 7 and 11. Its qualifying data is the hash of a fresh nonce, the candidate's log signing key and its TLS certificate fingerprint. That ties the keys to the measured boot state.
3. **Policy.** The PCR values are checked against the policy.

Endorsement key certificates are not checked: the trust is in the measured software and in the first sight of the key.

## Role selection

The topology lists roles in priority order:

```json
{"name": "server", "selector": {"arch": "arm64", "memory-gib": ">=4"}, "min": 3, "max": 5, "conflicts": ["agent"]}
```

- **Facts** are collected by the node software that was just attested: `arch`, `memory-gib`, `disk-gib` (the largest disk that is not the OS disk), `cpu-count`, `board`, `tpm`. Voters recompute the selection from the facts in the proposal.
- **Selector**: equality, `>=`, `<=`, `>`, `<`, `!=`, or a list meaning any of. A missing fact never matches.
- **Coexistence**: roles may share a node unless one lists the other under `conflicts` (symmetric).
- **Demand**: `max` caps a role. Without `max`, every matching node gets it. `min` gates nothing: it only reports roles with too few holders.

The node gets the first matching, non-conflicting, uncapped roles. Roles are fixed at admission. Changing a rule does not take roles from running nodes. Moving a node means evicting it and admitting it again. The topology can also set `unmatched` to `refuse` to turn away nodes that match no role.

`vips` in the topology lists the floating addresses for each role.

## What a member configures

On every change of the log, from the log alone:

- **Roles**: markers in `/etc/machine-role.d/` and machine tags (`hostnamectl tags`).
- **Files**: the topology's `files` list. Each entry has an absolute `path`, an optional octal `mode`, an optional `roles` list (the file is written only on a node that holds one of them) and a `template`, a string or a list of lines joined with newlines. The text is Go `text/template`, rendered from the log alone, so every member that sees the same log renders the same text. A file whose text is empty is removed. `reload` names a unit that gets `systemctl reload-or-restart` when the text changes, `start` a unit that gets `systemctl start --no-block`, and `stop` a unit that is stopped when the file is removed. Paths under `/run/fistpumpd/` are in the daemon's run directory.

Template values:

| Value | Meaning |
|---|---|
| `.Slot`, `.Rank`, `.Members`, `.MinMembers`, `.Roles`, `.Topology`, `.Interface` | the node's slot and rank, the number of active members, the genesis minimum, the node's roles, the topology version and the network interface |
| `.Holds "role"` | whether this node holds the role |
| `.RankIn "role"`, `.Count "role"` | this node's position among the holders of the role, and how many hold it |
| `.IsFirst "role"` | whether this node is the first member ever admitted to the role |
| `.Vips "group"`, `.VipGroups` | the addresses of a floating address group, and the sorted group names |
| `priority rank count index` | the priority `100 - ((rank - index) mod count) * step`, where `step = max(1, min(10, 90 / count))`, which spreads floating addresses evenly over any set of nodes |
| `add`, `mul`, `upper`, `join`, `dict` | helpers; `and`, `or`, `index`, `ge` and the other built-ins work too |

- **Tokens**: for k3s, the first server creates the server and agent tokens. The other members fetch them from a member over pinned TLS, with a challenge signed by their log key. Servers get both tokens, agents only the agent token. They are stored with `systemd-creds`, sealed to the TPM.

## Read API

A member serves a read-only, Kubernetes-style HTTP API on `api_port` (genesis, default 17948), from its copy of the log, so `kubectl` can list the members and the roles without a cluster. It is enabled when the file named by `api_client_ca` (default `/etc/fistpumpd/api-client-ca.pem`) exists. Clients authenticate with a certificate that the CA signed, over TLS 1.3 with the member's own certificate.

The group is `cluster.fistpumpd.example/v1alpha1`:

- `machines`: one per active member, named `slot-N`. The facts and the roles (`role.fistpumpd.example/<role>`) are labels. `status` has the phase (`Running`, or `Failed` while attestation fails), the address, the roles and the image.
- `machinesets`: one per role of the topology, named after the role. `spec.replicas` is `min`, `spec.maxReplicas` is `max`, and `status` has the number of holders and the number of healthy holders.

`get` and `list` work, and the Table format that `kubectl get` asks for is served. Any other verb is refused.

```
kubectl --server=https://<member>:17948 --insecure-skip-tls-verify \
  --client-certificate=client.pem --client-key=client-key.pem \
  get machines
```

## Network

Members speak JSON RPC over TLS 1.3 on port 17947 (`POST /rpc/<method>`). Each member has a self-signed certificate whose fingerprint is in its `admit` entry, and clients pin it. A candidate's first contact with a seed is unpinned. That is acceptable because the log is self-verifying and no secret crosses that connection. The log is public by design.

Discovery is a UDP broadcast on port 17946 that members and candidates answer with their address. A candidate that finds a member joins. If it finds none, it waits `founder_wait` seconds and, if its endorsement key hash is the lowest among the candidates it heard, it founds the log. Two nodes booting together elect one founder, and a node that boots later finds that member and joins. Two logs with different first entries cannot be merged. This is visible, and a lone founder never starts k3s.

A local control socket at `/run/fistpumpd/control.sock` serves the CLI.

## Failure handling

- Every member attests one peer at a time every `attest_interval` seconds. A peer that fails for `evict_after` seconds is proposed for eviction. A voter signs an `evict` only if its own fresh attestation of the target fails at that moment.
- A node whose slot is not active stops. Rejoining is manual: remove `/var/lib/fistpumpd`.
- **Lost quorum**: `fistpumpd reset-sign` creates a `reset` entry offline with the build key, given a log from a surviving member and the slots to keep. `fistpumpd submit` hands it to a member, which applies and pushes it. Members not kept are evicted.
- **Topology change**: a node that finds a higher topology version than the log's proposes a `topology` entry. The quorum signs it only if the members hold the same topology.

## Operating

```
fistpumpd daemon                     # run the member
fistpumpd status                     # members, roles, failing peers
fistpumpd log                        # the log as JSON
fistpumpd evict SLOT [--reason TEXT] # propose an eviction
fistpumpd verify [--certificate F] < log.json   # check a log from outside
fistpumpd reset-sign --log F --key F --certificate F --keep SLOTS
fistpumpd submit FILE
```

## Tests

`make test` runs everything except the TPM tests (about a minute, with the race detector). `make test-tpm` runs them against `swtpm` (it needs `swtpm` and `tpm2-tools`; the Makefile uses a container): real attestation, and three daemons forming a cluster through real quote checks.

`testdata/vectors.json` pins the wire format: canonical encoding and hashes, a signed chain with an eviction and a topology entry, quorum sizes, selector and role selection cases, policy checks, generated keepalived and k3s text, and a build-signed reset. Another implementation must reproduce them.

## Limits

- Member addresses are fixed at admission. A node whose address changes must be evicted and admitted again.
- Below four members the cluster tolerates crashes, not a malicious member. A two-member cluster stops when either member does.
- Vote lock expiry (five minutes) can in theory let two entries reach quorum when a partition and a vanished candidate coincide.
- The TPM code is tested against `swtpm`, not against physical TPMs. Discovery and keepalived behavior are untested on a real network.
- The build key signs the genesis, the topology and the reset entries. Its compromise is out of scope.
