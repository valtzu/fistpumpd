# fistpumpd

Cluster membership for a small fleet of machines with TPM 2.0 and measured boot: a signed, hash-chained admission log that the members agree on by quorum. Nodes attest each other with TPM quotes, get their roles from a signed topology, and derive keepalived priorities and k3s settings from the log alone. There is no central server and no node names.

- [docs/protocol.md](docs/protocol.md): the design and the wire format.
- `cluster/`: the implementation (Go, standard library only).
- `cmd/fistpumpd/`: the daemon and the CLI (`daemon`, `status`, `log`, `evict`, `verify`, `reset-sign`, `submit`).
- `testdata/vectors.json`: fixed test vectors (canonical encoding and hashes, a signed chain, role selection, policy checks, generated configuration) that pin the wire format. The Go tests check them.

```
make image        # test container with Go, swtpm and tpm2-tools
make test
make test-tpm     # real TPM attestation against swtpm
make build        # out/fistpumpd-arm64 and out/fistpumpd-amd64 (static)
```
