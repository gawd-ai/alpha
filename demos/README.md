# Demos

Runnable, narrated Alpha walkthroughs of the GAWD substrate against **live kernels** — the
substrate's most striking properties, out of `#[test]` and into your terminal. Each demo drives only
the public APIs an operator would use; there is no demo-only back door into the kernel, and each one
rides code paths the integration tests prove.

`alpha demo list` is the authoritative registry — every demo below appears there. Single-process
demos launch with `alpha demo run <name>`; the multi-process **cluster** runbook is listed tagged
`(manual runbook)` and `alpha demo run cluster` prints its step sequence rather than launching it.

| Demo | Run | What it shows | Proven in |
|---|---|---|---|
| [**walkthrough**](walkthrough/) | `cargo run -p walkthrough` | **One node's loop.** A deterministic reference authoring agent turns an English request into a creature → compiles → ed25519-signs → admits → hot-loads → runs it (native *and* critter tiers), then a running self performs a signed **two-body hand-off inside one Sanctum**. The separate integration proof covers the cross-Sanctum transport variant. | `m3_authoring_loop.rs`, `critter_examples.rs`, `abode_migrate_local.rs`, `abode_migrate_cross_node.rs` |
| [**federation**](federation/) | `cargo run -p federation` | **Many nodes, many Realms.** Several Sanctums across 2–3 Realms wired over real ed25519-authenticated TCP (loopback): a within-Realm cross-node fetch, then cross-Realm pull anti-entropy, **signed reputation**, **quarantine** propagation, and **Omega-addressed routing** (Loop 5, Acculturate). | `omega_federation_cross_node.rs`, `m2_two_node.rs`, `distributor_cross_node.rs` |
| [**dialogue**](dialogue/) | `cargo run -p dialogue` | **Two reference agents conversing across a Realm boundary.** Two Sanctums in two Realms over real ed25519-authenticated TCP (loopback): a `dialogue-initiator` on one Realm holds a **multi-turn conversation** with a **stateful reference responder** on the other, each turn a SEER `dialogue` Query routed across the boundary by the **Omega gateway** — application traffic crossing the mesh, not just catalogue federation. Replace the reference agents with model-backed ones for the v0.5.0 composition. | `dialogue_seam.rs`, `omega_app_routing_cross_node.rs`, `distributor_cross_realm.rs` |
| [**distribute**](distribute/) | `cargo run -p distribute` | **Cross-node artifact transfer.** Two Sanctums over ed25519-authenticated TCP (loopback): A publishes a creature; B performs a loss-free pull in **bounded GX chunks**, then admits + runs it with one `registry fetch-load` command. Per-chunk and whole-file SHA-256 integrity, missing-chunk retry, and tamper refusal are separately pinned by tests. | `m2_two_node.rs`, `fetch_load_verb.rs`, `gawdxfer/src/tests.rs`, `function_jobs_cross_realm_process.rs` |
| [**bestiary-live**](bestiary-live/) | `alpha demo run bestiary-live` | **A real model into a durable Bestiary.** A live LLM authors a sandboxed critter with bounded compile-error retry; Alpha signs, hot-loads, runs, and publishes it using the safe deterministic curator. The demo verifies an `EntryProof`, replays the signed journal through a fresh store handle, and exercises store-level monotonic convergence. Cross-node `PushEntries` replication and optional AI curation are separate injectable/tested seams. **Opt-in / key-gated; the runner enables `openai`.** | `agent_mind_authoring_loop.rs`, `bestiary_durable_local.rs`, `bestiary_replication_cross_node.rs` |
| [**cluster**](cluster/) | `cd demos/cluster && ./00-build.sh && ./01-boot.sh …` | **Three real Sanctum processes across both poles** (the deployable thing, not one process): node A an **`omega serve`** server, B/C **`alpha node`** operators. They form a **dynamic many-to-many mesh** from one seed via gossip, then **cross-execute** over it (author on an α operator, run from the Ω server) and prove a pre-admitted remote MCP hub can read B's live graph — all through fail-closed shell + HTTP + MCP steps. | `cluster_gossip_mesh.rs`, `omega_serve_federation.rs`, `m2_two_node.rs` |

## Notes

- **walkthrough** is the fastest way to "get" Alpha's slice of the GAWD substrate. Its deterministic
  reference authoring step shells out to a real `cargo build`, so the *first* run is slow (a minute or two while the dependency
  cache warms); later runs finish in seconds. It is gated in CI so it can never silently rot.
- **federation** is configurable: `cargo run -p federation -- --realms 3 --sanctums 2`
  (each bounded to `1..=3`, default `2 2`, so the loopback mesh stays reliable). With one Realm or one
  Sanctum it gracefully narrates what to add to see the next layer. Set **`ALPHA_DURABLE_BESTIARY=1`**
  to run the whole scenario on the on-disk `bestiary-daemon` instead of the in-memory stub — the
  fastest way to watch federation drive a *durable* registry (hermetic, no model needed). These are
  minimal demo Sanctums rather than full `alpha node` / `omega serve` compositions; each Realm
  gateway binds its `omega-federator` through `omega::serve::boot_federator`, the same organ recipe
  the server uses.
- **dialogue** is hermetic (no model, no network beyond loopback): it boots two real Sanctums in two
  Realms and runs a live reference-agent conversation across the boundary. Where `federation` moves
  catalogue + trust state between Realms, `dialogue` moves *application* traffic — a multi-turn SEER
  `dialogue` exchange — through the Omega gateway, with the answering agent holding state across turns.
  Replace the reference agents with LLM-backed ones and it is the v0.5.0 "AIs across the mesh" story.
- **distribute** is hermetic (no model, no network beyond loopback): it boots two real Sanctums and
  shows the loss-free `registry fetch-load` path pulling an artifact cross-node in bounded, windowed
  GX chunks and verifying per-chunk/whole-file GX integrity before admission. Missing-chunk
  re-request and tamper refusal are protocol
  guarantees exercised by the cited contract/process tests, not faults injected by this narrated run.
- **bestiary-live** is **opt-in and key-gated**: it needs a model and the `openai` feature. Set
  `ALPHA_LLM_MODEL` (and `ALPHA_LLM_BASE_URL` / `ALPHA_LLM_API_KEY`, or point at a local Ollama /
  LM-Studio) and run `cargo run -p bestiary-live --features openai`. With `ALPHA_LLM_MODEL` unset it
  prints a hint and exits 0, so CI never makes a network call. `ALPHA_LLM_MAX_ATTEMPTS` (default 3)
  is restricted to `1..=5`; `ALPHA_LLM_TIMEOUT_SECS` (default 60) is restricted to `1..=90`.
- **cluster** is the real-deployment shape: separate Sanctum *processes* across both poles — node A an
  `omega serve` server (the mesh anchor + an idle federator, since the cluster is single-Realm), B/C
  `alpha node` operators — that you drive by hand (or across real machines via `*_HOST` env vars — see
  [`cluster/env.sh`](cluster/env.sh)). Authoring is the α seat, so creatures are authored on B/C and run
  from anywhere, including A. Each step is a numbered `.sh` you run yourself; node logs, PID records,
  and public keys land in `cluster/run/`. Nodes boot `--allow-ai` (headless, so a curl/MCP caller is
  the operator) — on a node you sit at, keep the gate off and use the REPL.

For driving a *single* live node interactively — boot `alpha node`, author live, watch the sense-tape,
then scale up to these demos — see the [operator quickstart](../docs/quickstart/operator.md). To write
your own creature, see the per-tier [quickstarts](../docs/quickstart/).
