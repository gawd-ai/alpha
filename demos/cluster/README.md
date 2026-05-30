# Cluster demo — three Sanctums you drive by hand

A hands-on runbook: stand up **three real Alpha nodes** (`alpha node` processes), form a **dynamic
many-to-many mesh** from one seed, watch the graph converge, get the nodes **cross-executing** each
other's creatures, and **attach an AI** to each — all through the shipped control surfaces (the shell,
the HTTP API, and MCP). This is the operator-facing counterpart to the in-process
[`federation`](../federation/) demo: here the nodes are separate processes (or separate machines) you
actually log into.

Clustering is real `alpha node`: nodes gossip membership over the existing ed25519-authenticated TCP
transport, so the mesh self-completes — no node is pre-configured with every peer. See the
[operator quickstart](../../docs/quickstart/operator.md) for the single-node basics.

## Run it (all on loopback)

```sh
cd demos/cluster
./00-build.sh          # build alpha (release)
./01-boot.sh           # boot 3 nodes A,B,C (each: cluster port + HTTP/MCP port)
./02-join.sh           # introduce B and C to A; gossip forms the full mesh
./03-graph.sh poll     # watch each node's view converge to the full 3-node mesh
./04-cross-run.sh      # author a creature on A, run it from B over the mesh
./05-connect-ai.sh     # the .mcp.json per node + a live MCP read of the graph
./09-teardown.sh       # stop all three
```

Each step prints what it did and what to run next. Node logs/pids/pubkeys land in `./run/`.

## Run it across three real machines

Every script reads hosts/ports from the environment (see [`env.sh`](env.sh)). On three boxes, point the
`*_HOST` vars at each box's reachable address and supply your own keys/seeds:

```sh
# one shell, driving three hosts:
A_HOST=10.0.0.1 B_HOST=10.0.0.2 C_HOST=10.0.0.3 \
A_KEY=… B_KEY=… C_KEY=… ./01-boot.sh   # (boot each node on its own host; then ./02-join.sh, …)
```

(`01-boot.sh` backgrounds local processes; for genuinely separate hosts, run the per-node boot on each
host and run `02`–`05` from wherever can reach all three.)

## What each step proves

| Step | Surface | What it demonstrates |
|---|---|---|
| 01 | CLI flags | an `alpha node` process joins a cluster: `--node-id --cluster-listen --seed --cluster-key` |
| 02 | HTTP `POST /api/cluster/connect` | the operator/AI-gated **join**; gossip propagates it |
| 03 | HTTP `GET /api/cluster` | the **observable graph** + many-to-many convergence (also on the `/api/ws` sense stream) |
| 04 | HTTP `POST /api/author/critter` + `POST /api/send {node}` | **cross-execution**: author on A, run it from B over the mesh |
| 05 | MCP (`alpha mcp`) | **connect an AI** to each node — read the graph, drive the node, cross-execute |

## Posture (honest)

- The nodes boot with **`--allow-ai`** because they're headless — a remote curl/MCP caller is the
  operator. On a node you sit at, keep the gate **off** and use the REPL (`allow-ai on` when you want
  to hand control to an AI). The gate is the same allow-AI gate the control plane describes.
- Clustering trust is **transitive**: the first join is operator-gated, then gossip propagates
  membership across the authenticated mesh. The ed25519 peer handshake is unchanged; signed membership
  + UDP/mDNS LAN discovery are next steps (see the
  [identity, transport, and clustering design note](../../docs/design/identity-transport-clustering.md)).
  Demo seeds in `env.sh` are fixed/insecure — generate real keys for anything real.
- **The Bearer API key is the real admission boundary here.** With `--allow-ai` on, the key is the
  *only* gate on `POST /api/cluster/connect`, and since a join is gossiped into every node's handshake
  allowlist, holding any one node's key is effectively cluster-wide admission authority. For anything
  real: use strong, distinct per-node keys (not `demo-key-*`), bind `--listen` to a trusted interface,
  and/or keep `--allow-ai` off and join from the local REPL.
