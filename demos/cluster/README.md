# Cluster demo — three Sanctums you drive by hand

A hands-on runbook: stand up **three real Sanctum nodes** across **both poles** — node **A** is the
**Ω server** (`omega serve`, a federation/gateway Sanctum and the mesh anchor), nodes **B** and **C**
are **α operators** (`alpha node`) — form a **dynamic many-to-many mesh** from one seed, watch the
graph converge, get the nodes **cross-executing** each other's creatures, and prove that one
pre-admitted remote MCP hub can read a specific operator's graph over a **real MCP-over-mesh hop** —
all through the shipped control surfaces (the shell, the HTTP/WS API, and MCP). This is the
operator-facing counterpart to the in-process [`federation`](../federation/) demo: here the nodes are
separate processes (or separate machines) you actually log into.

Both poles boot the **same** control plane, gossip, and ed25519-authenticated TCP transport — only the
binary+subcommand differs. Nodes gossip membership over the transport, so the mesh self-completes — no
node is pre-configured with every peer. See the [operator quickstart](../../docs/quickstart/operator.md)
for the single-node basics.

A runs the `omega-federator` (that's what makes it the Ω server), but this cluster declares a **single
Realm** and configures no peer Realm, so A's federator is **present but idle** — the federator's
cross-Realm job (pull anti-entropy, signed reputation, Omega-addressed routing) is what the
[`federation`](../federation/) demo narrates.

## Run it (all on loopback)

```sh
cd demos/cluster
./00-build.sh          # build alpha + omega (release)
./01-boot.sh           # boot 3 nodes: A = omega serve, B/C = alpha node (cluster + HTTP/WS ports)
./02-join.sh           # introduce B and C to A; gossip forms the full mesh
./03-graph.sh poll     # fail unless every node sees both expected peers connected
./04-cross-run.sh      # author on B; require A's cross-node reply to be exactly "olleh"
./05-connect-ai.sh     # pre-admit a hub, then read B's live graph through remote MCP over the mesh
./09-teardown.sh       # stop all three
```

Each step prints what it did and what to run next. For the local launcher, node logs, PID records,
pubkeys, and process-local ControlCore ids land in `./run/`. The runbook needs Linux `/proc`, `flock`,
`curl`, and `jq`; MCP remains newline-delimited JSON-RPC on stdio and does not consume an HTTP port.

The authoritative local `tools/local-validation.sh` gate runs the same behavioral Steps 01–05 through
[`ci-smoke.sh`](ci-smoke.sh), using the debug `alpha` and `omega` binaries produced by its existing
workspace build. The wrapper never invokes Cargo, requires a fresh absolute `ALPHA_CLUSTER_RUN`
directory, and guarantees bounded Step 09 teardown on success, failure, or signal. Hosted CI keeps
only short sanity coverage.

The lifecycle helpers require Linux `/proc` plus `flock`. Boot and teardown hold one stable
`run/.lifecycle.lock`, so concurrent commands cannot unlink or replace one another's PID records.
Each record binds a PID to the kernel boot id and `/proc/<pid>/stat` start time; a stale, reused, or
unverifiable identity is never signalled. Partial boot rolls back only children started by that boot,
and teardown uses bounded TERM-then-KILL waits, retaining the record if death cannot be proved.

## Run it across three real machines

`01-boot.sh` is intentionally a **local process launcher**; setting three remote `*_HOST` values does
not make Bash remote-exec. On separate boxes, first build/install the same candidate, then boot A with
`omega serve` and B/C with `alpha node` on their respective hosts, using the same flags Step 01 shows:

```sh
# host A (advertise 10.0.0.1:9101 to peers; bind addresses may differ by deployment)
export A_SEED=your-64-hex-seed A_KEY=your-strong-api-key
omega serve --node-id A --realm crew --cluster-listen 0.0.0.0:9101 \
  --cluster-key "$A_SEED" --listen 0.0.0.0:7101 --api-key "$A_KEY" --allow-ai --headless

# host B (host C is the same shape with C / 9103 / 7103 / C-seed)
export B_SEED=your-64-hex-seed B_KEY=your-strong-api-key A_PUB=copy-from-A-boot-log
alpha node --node-id B --cluster-listen 0.0.0.0:9102 --cluster-key "$B_SEED" \
  --seed "A@10.0.0.1:9101#$A_PUB" \
  --listen 0.0.0.0:7102 --api-key "$B_KEY" --allow-ai --headless
```

Those logs remain on the machines that own the processes; this directory cannot capture remote PID
ownership or stop those processes. From a fourth driver, export reachable `A_HOST/B_HOST/C_HOST`, API
and cluster ports/keys, plus `A_PUB`, `B_PUB`, and `C_PUB` copied from the current boot logs. Step 05
also needs `B_CONTROL_ID`, copied from B's current `ControlCore on Role::CONTROL (id=...)` line; that id
is process-local and must be refreshed after every B restart. Set `MCP_HUB_HOST` to a literal IP the
mesh can reach (its `MCP_HUB_CPORT` is a cluster port), then run Steps 02–05 on the driver. Stop each
remote service on its owning host; `09-teardown.sh` only owns local children recorded by Step 01.

## What each step proves

| Step | Surface | What it demonstrates |
|---|---|---|
| 01 | CLI flags | both poles join one mesh: A `omega serve`, B/C `alpha node` — `--node-id --cluster-listen --seed --cluster-key` |
| 02 | HTTP `POST /api/cluster/connect` | the operator/AI-gated **join**; gossip propagates it |
| 03 | HTTP `GET /api/cluster` | the **observable graph** + an exact fail-closed assertion that A sees B/C, B sees A/C, and C sees A/B connected (events also appear on `/api/ws`, on the same HTTP/WS API port) |
| 04 | HTTP `POST /api/author/critter` + `POST /api/send {node}` | **cross-execution between the poles**: author on B (α operator), run it from A (Ω server), and parse/assert the exact `olleh` reply |
| 05 | MCP (`alpha mcp`) | pre-admit a stable hub identity, route `alpha_cluster` to B's actual ControlCore over authenticated GAWD mesh traffic, and assert B's live graph; the printed MCP-host entry reuses that admitted identity |

## Posture (honest)

- The nodes boot with **`--allow-ai`** because they're headless and this demo deliberately chooses a
  remote-mutation posture: A admits peers and sends, B authors, and C is available for the same
  operator-driven exercises. On a node you sit at, keep the gate **off** and use the REPL
  (`allow-ai on` when you choose to hand control to an AI). In Step 05, the remote hub does **not**
  receive `--allow-ai`: the target B owns the gate; the hub cannot grant itself permission.
- **Authoring is the α seat.** The Ω server (`omega serve`) has no authoring organ, so creatures are
  authored on the `alpha node` operators (B/C) and run from anywhere on the mesh — including A.
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
