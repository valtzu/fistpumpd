# fistpumpd

A membership daemon for small clusters of machines that have a TPM 2.0 and measured boot. The members keep a shared, signed log of who is in the cluster and what each one does. A new machine is admitted only after the existing members have checked its TPM and agreed to let it in. There is no central server and no node names to maintain.

It was written to bring up a k3s cluster on Raspberry Pi 4 boards that boot a signed image, but the machinery is general: it decides *who* is a member and *which roles* they get, and writes out the local configuration that follows from that.

## What you get

- **No coordinator.** Members agree by quorum. The only trusted party is the key that signs your OS image and your topology.
- **Hardware-backed admission.** A node joins only if its TPM proves that it runs software your policy accepts. Members keep attesting each other afterwards, and a peer that stops passing is voted out.
- **One order, readable history.** Admissions are serialized and every entry is hash-chained and signed, so the whole history can be read and verified by anyone, including tools outside the cluster.
- **No fixed size.** Roles are assigned by rules over what each node reports about itself (memory, disk, architecture, board), in the manner of a `nodeSelector`. Some roles may share a node and some may not.
- **No names.** A node's rank comes from the log, so anything that needs an order (floating address priorities, who initializes the cluster) works for any set of machines.
- **No split start.** A lone node never starts the cluster. The first member waits until a second one has been admitted, so two nodes that boot together cannot both initialize their own cluster.

## How it works, briefly

Every node runs `fistpumpd daemon`. On boot it looks for members on the local network. If it finds one it asks to join, and the members verify the TPM quote and the software measurements it presents, pick its roles from the topology, and sign its admission. If it finds none, it waits briefly and, if it is the only candidate, founds a new log.

Once admitted, a node derives its configuration from the log alone:

- role markers and machine tags,
- configuration files rendered from templates in the signed topology, for any service: the templates see the members, their roles, the floating addresses and the node's rank, so f.e. [keepalived](https://www.keepalived.org/) priorities spread the floating addresses evenly and [k3s](https://k3s.io/) gets `cluster-init` on the first server and a join address for the rest,
- the k3s tokens, which the first server creates and the others fetch from a member over pinned TLS.

The protocol itself is described in [docs/protocol.md](docs/protocol.md).

## Requirements

- Linux with systemd. The daemon runs as root.
- A TPM 2.0 and the [tpm2-tools](https://github.com/tpm2-software/tpm2-tools) commands (`tpm2_quote`, `tpm2_makecredential`, and so on).
- Measured boot, and a way to publish a signed policy of accepted PCR values (see the protocol document for the format).
- `gpg` to check that policy, and `systemd-creds` if you want secrets sealed to the TPM.
- To build it: Go 1.24 or later. The binary has no dependencies beyond the standard library.

## Install

Releases carry static binaries for `linux/amd64` and `linux/arm64`, and a `SHA256SUMS` file:

```
curl -fLO https://github.com/valtzu/fistpumpd/releases/download/0.1.0/fistpumpd-arm64
curl -fLO https://github.com/valtzu/fistpumpd/releases/download/0.1.0/SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
install -m 0755 fistpumpd-arm64 /usr/bin/fistpumpd
```

Then run `fistpumpd daemon` from a unit that starts after the network and the TPM are up.

## Configuration

Two files, both meant to ship in your signed OS image (or a signed extension of it).

`/usr/lib/fistpumpd/genesis.json` holds the cluster-wide settings:

```json
{
  "min_members": 2,
  "port": 17947,
  "discovery_port": 17946,
  "policy_urls": ["https://example.org/updates/stable", "https://example.org/updates/canary"]
}
```

`/etc/fistpumpd/topology.json` (or `/usr/lib/fistpumpd/topology.json`) describes the roles and the floating addresses:

```json
{
  "version": 1,
  "roles": [
    {"name": "server", "selector": {"arch": "arm64", "memory-gib": ">=4"}, "min": 3, "max": 3, "conflicts": ["agent"]},
    {"name": "agent", "selector": {"arch": "arm64"}, "conflicts": ["server"]},
    {"name": "ingress", "selector": {}}
  ],
  "vips": {
    "server": ["192.168.1.20", "192.168.1.21", "192.168.1.22"],
    "ingress": ["192.168.1.30", "192.168.1.31"]
  }
}
```

A node takes every role whose selector matches, which no earlier role it already got conflicts with, and whose `max` is not reached. Bumping `version` and shipping the new file moves the cluster to the new rules: the members record the change in the log.

## Usage

```
fistpumpd daemon                     # run the member
fistpumpd status                     # members, roles, failing peers
fistpumpd log                        # the log as JSON
fistpumpd evict SLOT [--reason TEXT] # propose removing a member
fistpumpd verify < log.json          # check a log from outside the cluster
fistpumpd version
```

If the cluster loses its quorum, `fistpumpd reset-sign` (offline, with the build key) and `fistpumpd submit` recover it. See the protocol document.

## Building and testing

```
make image        # test container with Go, swtpm and tpm2-tools
make test         # unit and simulation tests, with the race detector
make test-tpm     # real TPM attestation against a software TPM (swtpm)
make build        # out/fistpumpd-amd64 and out/fistpumpd-arm64, static
```

`testdata/vectors.json` holds fixed test vectors that pin the wire format; another implementation should reproduce them.

## Status

Version 0.1.0 is early. It is tested against software TPMs and a simulated network, not yet against physical TPMs and real network conditions. Below four members a cluster tolerates crashes but not a malicious member, and member addresses are fixed once admitted. The protocol document lists the limits.

## License

MIT. See [LICENSE](LICENSE).
