# Demos

Runnable, narrated Alpha walkthroughs of the GAWD substrate against **live kernels** — the
substrate's most striking properties, out of `#[test]` and into your terminal. Each demo drives only
the public APIs an operator would use; there is no demo-only back door into the kernel, and each one
rides code paths the integration tests prove.

| Demo | Run | What it shows | Proven in |
|---|---|---|---|
| [**walkthrough**](walkthrough/) | `cargo run -p walkthrough` | **One node's loop.** An AI authors a creature from an English request → compiles → ed25519-signs → admits → hot-loads → runs it (native *and* critter tiers), then a running self **migrates between two Sanctums** with cryptographic continuity. | `m3_authoring_loop.rs`, `abode_migrate_local.rs` |
| [**federation**](federation/) | `cargo run -p federation` | **Many nodes, many Realms.** Several Sanctums across 2–3 Realms wired over real ed25519-authenticated TCP (loopback): a within-Realm cross-node fetch, then cross-Realm pull anti-entropy, **signed reputation**, **quarantine** propagation, and **Omega-addressed routing** (Loop 5, Acculturate). | `omega_federation_cross_node.rs`, `m2_two_node.rs`, `distributor_cross_node.rs` |
| [**distribute**](distribute/) | `cargo run -p distribute` | **Cross-node artifact transfer.** Two Sanctums over ed25519-authenticated TCP (loopback): A publishes a creature into its registry; B pulls it in **bounded, resumable GX chunks** and admits + runs it with a single `registry fetch-load` command — the cross-node ship loop the substrate used to hand-script, with per-chunk *and* whole-file SHA-256 integrity (a tampered fetch is refused at admission). | `m2_two_node.rs` |
| [**bestiary-live**](bestiary-live/) | `… cargo run -p bestiary-live --features openai` | **A real model into a durable Bestiary.** A live LLM authors a creature from English (bounded compile-error retry, sandboxed critter tier), which is signed, hot-loaded, run, then **published into a durable, replicated, AI-curated Bestiary** — with a **verifiable entry proof**, recovery across a store restart, and a second node converging via the monotonic lattice. **Opt-in / key-gated.** | `agent_mind_authoring_loop.rs`, `bestiary_durable_local.rs`, `bestiary_replication_cross_node.rs` |
| [**cluster**](cluster/) | `cd demos/cluster && ./00-build.sh && ./01-boot.sh …` | **Three real Sanctum processes across both poles** (the deployable thing, not one process): node A an **`omega serve`** server, B/C **`alpha node`** operators. They form a **dynamic many-to-many mesh** from one seed via gossip, then **cross-execute** over it (author on an α operator, run from the Ω server) and **attach an AI** to each — driven entirely through the shell + HTTP API + MCP. The operator-facing counterpart to `federation`. | `cluster_gossip_mesh.rs`, `omega_serve_federation.rs`, `m2_two_node.rs` |

## Notes

- **walkthrough** is the fastest way to "get" Alpha's slice of the GAWD substrate. Its authoring step
  shells out to a real `cargo build`, so the *first* run is slow (a minute or two while the dependency
  cache warms); later runs finish in seconds. It is gated in CI so it can never silently rot.
- **federation** is configurable: `cargo run -p federation -- --realms 3 --sanctums 2`
  (each bounded to `1..=3`, default `2 2`, so the loopback mesh stays reliable). With one Realm or one
  Sanctum it gracefully narrates what to add to see the next layer. Set **`ALPHA_DURABLE_BESTIARY=1`**
  to run the whole scenario on the on-disk `bestiary-daemon` instead of the in-memory stub — the
  fastest way to watch federation drive a *durable* registry (hermetic, no model needed). Each Realm
  gateway in the demo is the in-process equivalent of an **`omega serve`** server: it binds its
  `omega-federator` through `omega::serve::boot_federator`, the same recipe the binary runs, so the demo
  and the deployed server cannot drift.
- **distribute** is hermetic (no model, no network beyond loopback): it boots two real Sanctums and
  shows the `registry fetch-load` verb pulling an artifact cross-node in windowed GX chunks, re-requesting
  only the missing chunks on a stall (resume without restart) and re-verifying at admission.
- **bestiary-live** is **opt-in and key-gated**: it needs a model and the `openai` feature. Set
  `ALPHA_LLM_MODEL` (and `ALPHA_LLM_BASE_URL` / `ALPHA_LLM_API_KEY`, or point at a local Ollama /
  LM-Studio) and run `cargo run -p bestiary-live --features openai`. With `ALPHA_LLM_MODEL` unset it
  prints a hint and exits 0, so CI never makes a network call. `ALPHA_LLM_MAX_ATTEMPTS` (default 3)
  bounds the author → build retry loop.
- **cluster** is the real-deployment shape: separate Sanctum *processes* across both poles — node A an
  `omega serve` server (the mesh anchor + an idle federator, since the cluster is single-Realm), B/C
  `alpha node` operators — that you drive by hand (or across real machines via `*_HOST` env vars — see
  [`cluster/env.sh`](cluster/env.sh)). Authoring is the α seat, so creatures are authored on B/C and run
  from anywhere, including A. Each step is a numbered `.sh` you run yourself; node logs/keys land in
  `cluster/run/`. Nodes boot `--allow-ai` (headless, so a curl/MCP caller is the operator) — on a node
  you sit at, keep the gate off and use the REPL.

For driving a *single* live node interactively — boot `alpha node`, author live, watch the sense-tape,
then scale up to these demos — see the [operator quickstart](../docs/quickstart/operator.md). To write
your own creature, see the per-tier [quickstarts](../docs/quickstart/).
