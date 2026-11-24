# Design for 0.2.0: configuration without built-in k3s and keepalived

Status: proposal. Nothing here is implemented in 0.1.x.

## Goal

The daemon decides who is a member and which roles they hold. What a role writes to disk is not its business. Today it writes keepalived and k3s files itself. In 0.2.0 the signed topology carries that, so any service can be provisioned.

Kept as they are: machine tags, role markers, and the systemd ordering. The role marker directory is renamed to `/etc/machine-role.d/`, so that it is not mistaken for a Kubernetes node.

## Files in the topology

A role lists files to write:

```json
{"name": "server", "selector": {"arch": "arm64"}, "max": 3,
 "files": [{"path": "/run/fistpumpd/keepalived.conf", "mode": "0644",
            "template": "…", "reload": "keepalived.service"}]}
```

- Templates use Go `text/template`. They see only values derived from the log, so every member renders the same text.
- A file is rewritten when its rendered text changes, then the `reload` unit gets `systemctl reload-or-restart`.
- Templates come from the signed topology, so a quorum agrees on them. Rendering is covered by the test vectors.

Template values:

| Value | Meaning |
|---|---|
| `.Self` | slot, rank in each role, facts |
| `.Members` | all active members with address, roles and slot |
| `.Holders "role"` | members that hold the role, in rank order |
| `.First "role"` | whether this node is the first member ever admitted to the role |
| `.Vip "name"` | the address of a floating address |
| `.Secret "name"` | a shared secret, see below |

## Secrets

A role declares `secrets: ["name"]`. The first holder generates a random value. The other holders fetch it from a member over the pinned TLS connection, with a challenge signed by their log key. Each node stores it sealed with `systemd-creds` and PCR 7. A template reads it through `.Secret`.

## Readiness

A role declares `ready_after_members: N`. The daemon creates `/run/fistpumpd/ready/<role>` once the log holds N members. A unit can require that file.

## Floating addresses

A group in `vips` gets a `source`:

- `static`: the list in the topology, as today.
- `range` or `cidr`: the daemon picks addresses from the log, by slot and group index. It checks with ARP that an address is free before a member takes it.
- `dhcp`: each address has a fixed MAC derived from the group and the index. The interface with that MAC exists only on the keepalived MASTER, and a DHCP client runs on it. The router's reservation for that MAC fixes the address.

For `dhcp`, the group has a `name` that the router's DNS resolves. Configuration refers to the name, so no member needs the address before it holds the lease. If a configuration needs the address itself, a `vip` log entry records the leased address, signed by a quorum, and `.Vip` reads it.

## Compatibility

This changes the topology schema and the role marker path, so it is breaking: the minor version goes up. Members of 0.1.x and 0.2.0 do not mix in one cluster.
