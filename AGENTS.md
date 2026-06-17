# AGENTS.md — orientation for AI agents (and humans in a hurry)

You are reading the source of **Alpha**, the first public open-source substrate for **GAWD**. This
file is the fast, machine-first map: the mental model, where things live, how to run it, and the
invariants you must not break. Deeper prose is in [`docs/`](docs/); this is the index you read first.
The main crate is named `alpha` because it is the first door into the larger GAWD cosmology.
Use **Alpha** for this repository, source release, binary, and current substrate implementation; use
**GAWD** for the company's overall goal and system universe, the cosmology, and names that must remain
stable across GAWD systems, such as the `gawd_creature_v1` wire ABI. Rule of thumb: commands, crates,
release notes, and runtime UI in this repo say Alpha; cross-system contracts, realm-scale concepts,
and the broader objective say GAWD.

> Alpha is GPL-3.0-or-later. Linking a creature against the SDK/engine surface makes it a derivative
> work. See [`LICENSE`](LICENSE) and [`SECURITY.md`](SECURITY.md) before publishing creatures.

## Mental model (read this once)

A **daemon** is a unit of capability — code that does one thing. It runs inside a **Sanctum** (a
single node: a server, a robot, a satellite, an edge box) whose whole job is to **load, supervise,
place, and unload** creatures at runtime. Sanctums advertise their **embodiment** (hardware, sensors,
links, location) so work is matched to them. Sanctums federate into a **Realm** (a trust domain);
Realms federate into the **Omega** (the global graph + registry). Work — and the creatures that do
it — is **distributed** across this graph **by AI**, placed where it best runs.

The vocabulary is a cosmology on purpose (Aether, Sanctum, Abode, Realm, Omega, creature). It is
load-bearing, not decoration — each term maps to a precise engineering concept. The dictionary is
[`docs/CONCEPTS.md`](docs/CONCEPTS.md).

## The one architectural principle

**The substrate ships *sockets*; operators inject *models*** (inversion of control). The kernel
(`cosmos/sanctum/`) is model-free and tier-blind: it does lifecycle, routing, and admission *mechanism* — it
never decides what to trust, what is "fit", or what to kill. Those are **creatures** bound into
sockets (a `Role`) or fed by signals (a `Topic`). When you wonder "where does policy X live?" — the
answer is almost always "an injected creature, not the substrate."

The two contracts that make this work:
- **In motion:** the [`aether::Envelope`](cosmos/aether/src/lib.rs) — one typed message, one `Router`.
- **At rest / in transit:** the [`sigil::Manifest`](cosmos/sigil/src/lib.rs) — the sole
  metadata + permission source for a creature.

## Repository map

Three creature buckets + the spine. **Crate naming follows one rule: coin what's ours, keep the
world's names literal.** The spine carries coined cosmology names (`aether`, `sanctum`, `sigil`,
`anima`, `forge`) — each a precise concept, globally unique without a vendor prefix; the type inside
keeps its plain label (`sigil::Manifest`, like `aether::Envelope`). A crate that fronts an **external
standard** keeps that standard's name literal — `surface-mcp` / `surface-http` / `transport-tcp` keep
`mcp` / `http` / `tcp` (the MCP hub is the `alpha mcp` subcommand + the `surface-mcp` creature, with
no `gawd-`-prefixed crate). Creature crates keep descriptive seam names
(`policy-signed`, `scorer-latency`) — self-describing in a `use`, a lockfile, or a stack trace, where
a folder can't help.

The tree mirrors the cosmology: **`alpha` (α) and `omega` (Ω) are the two poles at the root that hold
the whole system** — `alpha` the front door + local operator (client), `omega` the federation apex /
mesh (server) — and the cosmology *between* them lives under `cosmos/`, their common library. Beneath
both sits `foundation/` — shared GAWD foundations Alpha *consumes but does not own* (cross-system
contracts/tools, `gawd`-prefixed, destined to externalize into their own repos); **not** part of the
cosmology, so beside it, not within it (filing one under `cosmos/` would falsely claim it is Alpha's
interior). `demos/` and `docs/` stay at the root. (The memory-safety harnesses live with the tests they
drive, in `cosmos/sanctum/tests/memcheck/` — not a root `ci/` dir; the real CI is `.github/workflows/`.)

| Path | What it is |
|---|---|
| `alpha/` | **The α pole — the front door + local operator (client).** One of the two root poles (with `omega/`) that hold the system. `alpha node` / `alpha mcp` / `alpha http` dispatch in-process (the node daemon + MCP-hub composition roots live here); `alpha demo [list\|run <name>]` is a managed runner that *spawns* a demo from the external `demos/demos.json` registry, not linked in. `alpha` = α, `omega` = Ω; the cosmology is between them, only stimuli in / products out. |
| `omega/` | **The Ω pole — the federation apex / mesh side (server), dual to the α door.** Where `alpha` is the local operator, `omega` is the network graph of Realms. Now a **lib+bin**: `omega serve` boots a dedicated federation/gateway Sanctum (transport mesh + registry + `omega-federator` on `Role::OMEGA_GATEWAY` + an optional control plane), headless, no authoring/REPL — the dual of `alpha node`. A root crate like `alpha`, not a `cosmos/` vocabulary noun; it consumes the cosmology and the kernel the way `alpha` does. The frozen Ω **wire contract** (`GATEWAY_ROLE`, the `deferred` shape, the reserved `OmegaServices` seam) lives in the lean `cosmos/omega-contract` leaf — re-exported here so `omega::deferred` still resolves — so a stub gateway can parse it without pulling this server's kernel deps. Its gateway/federator *creatures* live in `cosmos/creatures/`. |
| `demos/` | Narrated, runnable demos (`walkthrough`, `federation`, `distribute`, `bestiary-live`, `dialogue`; the `cluster/` dir is a multi-process runbook — listed in the registry tagged `(manual runbook)`, run by hand rather than launched by the runner). The registry of what `alpha demo` knows is [`demos/demos.json`](demos/demos.json), and `alpha demo list` is authoritative. The fastest way to *see* Alpha. Stay at the root, alongside the door they exercise. |
| `foundation/` | **Shared GAWD foundations** — cross-system contracts/tools Alpha *consumes but does not own* (`gawd`-prefixed, destined to externalize into their own repos). Beside the cosmology, not within it. A new crate lands here (not `cosmos/`) when another GAWD system would want the *exact same* crate and it will carry its own version/repo/maybe binary. |
| `foundation/gawdxfer/` | **The GX bulk-transfer contract** shared by GAWD systems: chunked/resumable init, chunk, ack, progress, resume, status, completion, binary chunk framing, chunk math, and streaming SHA-256 helpers. Transport-neutral; Alpha and `sctl` adapt this instead of inventing local xfer protocols. |
| `cosmos/` | **Everything between α and Ω** — the interior the front door opens onto: the whole spine, the concept crates, the control core, and every creature. |
| `cosmos/{sigil,aether,anima,sanctum,forge}/` | **The spine**: contract → bus → per-tier loaders → kernel → authoring SDK. |
| `cosmos/{abode,seer,realm}/` | **First-class concept crates**: the distributed-self snapshot contract (`abode`), the consult-and-reconcile primitive (`seer`), and the trust-domain (`realm`). They live alongside `aether` so federation authority has a home that already exists. `realm` owns the realm-gateway seam *and* its routing mechanism (`realm::serve`). (**Ω** lived here too as `cosmos/omega`; it was promoted to the root as the system's second pole — see `omega/` above. `omega` still owns the gateway socket + `deferred` wire contract + reserved `OmegaServices`.) |
| `cosmos/omni/` | **The spine-only control core** every surface drives over the bus (`run_verb` + `ControlCore`). |
| `cosmos/creatures/` | **Production-capable reference organs** — the real substrate creatures (the daemon boots several), plus the loadable surfaces (`surface-http`, `surface-mcp`). Indexed by [`cosmos/creatures/README.md`](cosmos/creatures/README.md). Reads as a reduction gradient ↓. |
| `cosmos/creatures/prototypes/<seam>/` | **Operator-replaceable injected models** — the reference strategies that fill the IoC sockets (the "model" in *fabric, not model*), grouped by socket (`policies/`, `scorers/`, `distributors/`, `reputation/`, `merge/`, `gateways/`, `responders/`, `dialogue/`, `critters/`, + `monitor/`). These are reference strategies, not disposable demo material. Legend: [`cosmos/creatures/prototypes/README.md`](cosmos/creatures/prototypes/README.md). |
| `cosmos/creatures/prototypes/fixtures/` | **Test-only creatures** the kernel test suite dlopens (walking skeleton + fault specimens) — the most reduced prototype, nested deepest. Not shipped. |

The three creature tiers (`abi.backend`): **`daemon`** (native `.so`), **`beast`** (WASM, wasmtime),
**`critter`** (Rhai script). All load through the same `Kernel::load` path, differing only by backend.

## Build · run · test

```sh
cargo run -p walkthrough          # the whole loop, narrated — start here
cargo run -p federation           # many Sanctums × Realms over ed25519 TCP (loopback)
cargo build --locked --workspace
CARGO_BUILD_JOBS=2 cargo test --locked --workspace -- --test-threads=1   # CI uses this cap
cargo run -p alpha -- node              # boot a live node + REPL (add --minimal for a bare kernel)
cargo run -p omega -- serve --node-id Ω --cluster-listen 127.0.0.1:9100   # boot the Ω federation/gateway server (headless)
cargo doc --workspace --no-deps --open # browse the API — every crate has //! docs
```

A **Sanctum** is the kernel (`sanctum`) run as a process; both poles realize one — `alpha node` is the
operator/authoring seat (REPL + authoring organs), `omega serve` the headless federation/gateway server
(`omega-federator` on `Role::OMEGA_GATEWAY`, no authoring). They compose the same kernel + control core
and differ in posture, not mechanism. `demos/cluster/` is the runbook that stands up both on one mesh
(A `omega serve`, B/C `alpha node`); `demos/federation/`'s in-process gateways bind their federator via
the same `omega::serve::boot_federator` recipe `omega serve` uses.

The composed end-to-end loops live in `cosmos/sanctum/tests/`. The `panic-daemon` "failures" in a test run
are **expected** — it is the fault-isolation specimen proving a panicking creature doesn't crash
the node. Toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml).

## Before you author or modify a creature

- **What it may listen to / emit:** the pub/sub + consult contract — [`docs/TOPICS.md`](docs/TOPICS.md).
- **The manifest it must carry:** fields + a minimal valid manifest per tier — [`cosmos/sigil/README.md`](cosmos/sigil/README.md); validate against the machine-readable [`cosmos/sigil/manifest.schema.json`](cosmos/sigil/manifest.schema.json) (JSON Schema, drift-guarded against the Rust type).
- **Where a new creature goes** (`cosmos/creatures/` vs `cosmos/creatures/prototypes/<seam>/` vs `cosmos/creatures/prototypes/fixtures/`):
  the placement rule in [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Load-bearing invariants — DO NOT break these

1. **No `#[global_allocator]` in any workspace member.** The native FFI seam does `Box::from_raw` on
   the host side over memory the creature allocated inside its `.so`; this is only sound while both
   sides share one allocator. jemalloc/mimalloc/etc. silently risk UB on every native unload.
   (`Cargo.toml` workspace invariant.)
2. **Never set `panic = "abort"`.** `std::panic::catch_unwind` at every creature boundary is the R9
   fabric-integrity floor — a panicking creature is caught and routed to unload, not allowed to crash
   the node. `abort` would make those catches impossible. (`Cargo.toml [profile.release]`.)
3. **Manifest signing order: set `content_address` *before* signing.** `Manifest::signing_payload`
   clears only `provenance.signature` — the content address rides *inside* the signature. Sign a
   manifest whose `content_address` is unset/stale and verification fails. (`sigil` signing.)
4. **Manifest field order is part of the signed wire.** Appending new *optional* fields is additive;
   **reordering or renaming** an existing field invalidates signed manifests in flight. Treat it as a
   wire-format change, lockstep with the `signing_payload_hash_is_locked_to_a_known_fixture` tripwire.
5. **The `daemon` tier is trusted-by-admission.** The fabric cannot fully contain malicious in-process
   native code, so foreign/mobile code never arrives as a `daemon` — only as a `beast` (WASM) or
   `critter` (script). Don't route untrusted code through the native tier.
6. **Keep the kernel model-free.** New "should we trust / promote / kill / place this?" logic belongs
   in an injected creature, never in `cosmos/sanctum/`. Adding such a decision to the substrate is the most
   common way to break the architecture.

## Deeper docs

[`docs/VISION.md`](docs/VISION.md) · [`docs/CONCEPTS.md`](docs/CONCEPTS.md) (glossary) ·
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) · [`docs/TOPICS.md`](docs/TOPICS.md) ·
[`docs/ROADMAP.md`](docs/ROADMAP.md) · [`docs/design/`](docs/design/) (how Alpha works by subsystem — the
*why* behind every hard-to-reverse call) · [`CONTRIBUTING.md`](CONTRIBUTING.md).
