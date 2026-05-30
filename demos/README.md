# Demos

Runnable, narrated Alpha walkthroughs of the GAWD substrate against **live kernels** — the
substrate's most striking properties, out of `#[test]` and into your terminal. Each demo drives only
the public APIs an operator would use; there is no demo-only back door into the kernel, and each one
rides code paths the integration tests prove.

| Demo | Run | What it shows | Proven in |
|---|---|---|---|
| [**walkthrough**](walkthrough/) | `cargo run -p walkthrough` | **One node's loop.** An AI authors a creature from an English request → compiles → ed25519-signs → admits → hot-loads → runs it (native *and* critter tiers), then a running self **migrates between two Sanctums** with cryptographic continuity. | `m3_authoring_loop.rs`, `abode_migrate_local.rs` |
| [**federation**](federation/) | `cargo run -p federation` | **Many nodes, many Realms.** Several Sanctums across 2–3 Realms wired over real ed25519-authenticated TCP (loopback): a within-Realm cross-node fetch, then cross-Realm pull anti-entropy, **signed reputation**, **quarantine** propagation, and **Omega-addressed routing** (Loop 5, Acculturate). | `omega_federation_cross_node.rs`, `m2_two_node.rs`, `distributor_cross_node.rs` |
| [**cluster**](cluster/) | `cd demos/cluster && ./00-build.sh && ./01-boot.sh …` | **Three real `alpha node` processes** (the deployable thing, not one process) form a **dynamic many-to-many mesh** from one seed via gossip, then **cross-execute** over it and **attach an AI** to each — driven entirely through the shell + HTTP API + MCP. The operator-facing counterpart to `federation`. | `cluster_gossip_mesh.rs`, `m2_two_node.rs` |

## Notes

- **walkthrough** is the fastest way to "get" Alpha's slice of the GAWD substrate. Its authoring step
  shells out to a real `cargo build`, so the *first* run is slow (a minute or two while the dependency
  cache warms); later runs finish in seconds. It is gated in CI so it can never silently rot.
- **federation** is configurable: `cargo run -p federation -- --realms 3 --sanctums 2`
  (each bounded to `1..=3`, default `2 2`, so the loopback mesh stays reliable). With one Realm or one
  Sanctum it gracefully narrates what to add to see the next layer.
- **cluster** is the real-deployment shape: separate `alpha node` *processes* you drive by hand (or
  across real machines via `*_HOST` env vars — see [`cluster/env.sh`](cluster/env.sh)). Each step is a
  numbered `.sh` you run yourself; node logs/keys land in `cluster/run/`. Nodes boot `--allow-ai`
  (headless, so a curl/MCP caller is the operator) — on a node you sit at, keep the gate off and use
  the REPL.

For driving a *single* live node interactively — boot `alpha node`, author live, watch the sense-tape,
then scale up to these demos — see the [operator quickstart](../docs/quickstart/operator.md). To write
your own creature, see the per-tier [quickstarts](../docs/quickstart/).
