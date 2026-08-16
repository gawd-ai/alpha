# Contributing to Alpha

> Alpha is pre-1.0: the two contracts — `Manifest` + `Envelope` — plus
> `Creature` + `declare_creature!` are the public baseline you build against.
> Minor releases may still change contracts when correctness, security, or the
> operating model requires it. Check [`CHANGELOG.md`](CHANGELOG.md) before
> assuming a contract is final.

## Toolchain

- Rust **1.97.1** (pinned by `rust-toolchain.toml`), **edition 2021**.
- Build the two entry points: `cargo build --locked -p alpha -p omega`; the complete workspace gate
  runs once in constrained CI.
- Run a node: `cargo run -p alpha -- node` (REPL — see [README](README.md)).
- Native creatures are `cdylib` crates (`crate-type = ["cdylib"]`).
- Beast (wasm) creatures target `wasm32-unknown-unknown` and are built explicitly
  (excluded from the workspace). The beast tier is exercised by an inline WAT module in
  `cosmos/sanctum/tests/m0_integration.rs` (the `wat` crate compiles it for `WasmEngine`); no standalone
  wasm guest crate ships yet.
- Critter (script) creatures are UTF-8 Rhai source artifacts. They are not Cargo crates; the
  `build-critter` organ validates and signs the source, and `ScriptEngine` loads it by bytes.

> **Workspace invariant:** no member may set a custom
> `#[global_allocator]`. The native FFI seam currently does `Box::from_raw` on
> the host side over memory the creature allocated inside its `.so` (the
> vtable). This is only sound while both sides share one allocator. The
> constraint is documented at the top of the root `Cargo.toml`. Lifting it
> requires a future ABI extension (`gawd_creature_v1_destroy` or a `vtable_drop`
> slot in `CreatureVTableV1`).

## Layout

`cosmos/sigil/` (at-rest contract) · `cosmos/aether/` (bus spine) ·
`cosmos/anima/` (per-tier loaders) · `cosmos/sanctum/` (kernel library) ·
`alpha/` (the α front door — `alpha node`/`mcp`/`http`/`demo`) · `cosmos/forge/` (authoring surface) ·
`cosmos/creatures/*` (production-capable reference organs) · `cosmos/creatures/prototypes/*` (injected reference models +
critter script references) · `cosmos/creatures/prototypes/fixtures/*` (test-only creatures) ·
`foundation/gawdxfer/` (the shared GX bulk-transfer contract) · `foundation/gawdfn/` (the shared
typed-Function + durable-Job contract — both foundations sit beside the cosmology, not within it).
Full detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). For a fast machine-first map (and the
load-bearing invariants), see [`AGENTS.md`](AGENTS.md). Before authoring a creature, read the two
contracts it builds against: the pub/sub + consult surface in [`docs/TOPICS.md`](docs/TOPICS.md) and
the manifest fields + minimal examples in [`cosmos/sigil/README.md`](cosmos/sigil/README.md).

**Where a new creature goes.** A production-capable organ — a real consumer of a substrate primitive,
the kind an operator could actually run — lives in `cosmos/creatures/`. An operator-replaceable
reference strategy (an admission policy, fitness scorer, reputation weigher, merge lattice, gateway,
or critter script reference) lives in `cosmos/creatures/prototypes/`. A creature that exists only to
be exercised by the kernel test suite (a fault specimen or a walking-skeleton stub) lives in
`cosmos/creatures/prototypes/fixtures/`.

**Where a shared foundation crate goes.** `cosmos/` is Alpha's *own* interior — the cosmology. A crate
that another GAWD system would want *verbatim* — a cross-system contract or tool, `gawd`-prefixed, that
will carry its own version (eventually its own repo, maybe its own binary) — lives in `foundation/`,
beside the cosmology rather than inside it; filing shared infra under `cosmos/` would falsely claim
Alpha owns it. `foundation/gawdxfer` is the GX bulk-transfer contract shared with `sctl`;
`foundation/gawdfn` is the typed-Function + durable-Job contract shared across GAWD systems. An
Alpha-internal seam that is *not* cross-system — e.g. `cosmos/mind` (the injected-model seam) — stays
in `cosmos/`.

## Release packaging

The public release is **source-first**: every workspace crate sets `publish.workspace = true` and so
inherits `publish = false` from the root manifest — nothing goes to a package registry; you clone and
build from this repository. Keep that invariant when adding a crate (set `publish.workspace = true`):
on Alpha the distributable unit is the **creature** (a signed `gawd_creature_v1` artifact), published
and fetched by content address over the bus, not a Rust package. The release checklist lives in
[`RELEASE.md`](RELEASE.md).

## Add a creature (native daemon)

A creature is a `cdylib` crate that exports one POD-only `extern "C"`
constructor via `forge::declare_creature!`. The kernel loads it via
`NativeEngine`.

1. **New crate** under `cosmos/creatures/<name>/`, with:
   ```toml
   [lib]
   crate-type = ["cdylib"]

   [dependencies]
   aether         = { path = "../../aether" }
   sigil  = { path = "../../sigil" }
   forge       = { path = "../../forge" }
   ```
2. **Implement `aether::Creature + Default`** on your type, then declare it:
   ```rust
   use forge::prelude::*;

   #[derive(Default)]
   pub struct MyDaemon;

   impl Creature for MyDaemon {
       fn bind(&mut self, _ctx: CreatureCtx) {
           // Hold onto _ctx.bus if you'll emit envelopes later.
       }

       fn handle(&mut self, env: Envelope) -> Outcome {
           // Do work; return a reply or further dispatches.
           Outcome::reply(&env, b"ok".to_vec())
       }

       fn shutdown(&mut self, _deadline: Deadline) {
           // Clean up. The SDK joins managed-spawn threads after this returns.
       }
   }

   forge::declare_creature!(MyDaemon);
   ```
3. **Spawn threads only via `forge::spawn`.** The managed-spawn registry
   (`forge::managed`) records every thread the creature spawns and joins
   them in `shutdown` before the host `dlclose`s the library. Raw
   `std::thread::spawn` is invisible to the SDK; the kernel's thread-count
   guard will refuse `dlclose` and the library will leak (bounded, not UAF).
   `cosmos/creatures/prototypes/fixtures/welbehaved-thread-daemon` is the reference; the misbehavior
   specimens (`panic-daemon`, `runaway-thread-daemon`) document what the fabric
   contains rather than allows.
4. **Add the crate to the workspace `members`** in the root `Cargo.toml`.
5. **Author a manifest** (a JSON file) declaring `name`, `version`, `abi`,
   `entrypoints`, `capabilities`, `requirements`, `provenance`, and
   `provides`. The `Manifest` type (in `sigil`) is the schema; see the
   `Manifest::new(…)` builder used throughout `cosmos/sanctum/tests/` for the field shape.

To smoke-test:
```
cargo build -p my-daemon
cargo run -p alpha -- node
alpha> load cosmos/creatures/my-daemon/manifest.json target/debug/libmy_daemon.so
alpha> send <id> hello world
```

## Add a beast (wasm)

The shipped beast ABI is intentionally minimal and SDK-free today: a module exports
`memory`, `alloc(len) -> ptr`, and `handle(ptr, len) -> i64` where the return packs
`(out_ptr << 32) | out_len`. The host writes the envelope payload into linear memory
and reads the returned bytes back. There are no host imports yet; that is why `net`
and `fs` are closed by construction.

1. Build a `wasm32-unknown-unknown` artifact that exports the minimal guest ABI above.
2. Author a manifest with `abi.backend = "beast"` and `abi_tag = "gawd_creature_v1"`.
3. Load it as bytes (`Artifact::Bytes`) or via a registry fetch. The beast tests show
   the current contract with inline WAT in `cosmos/sanctum/tests/m0_integration.rs` and
   `cosmos/sanctum/tests/m4_capability_sandbox.rs`; no standalone wasm guest crate ships yet.

`forge::declare_creature!` is the native daemon FFI surface. A future wasm SDK adapter
can wrap the minimal guest ABI, but that wrapper is not in-tree today.

## Add a critter (script)

A critter is the cheapest creature tier: one Rhai source file that defines
`fn handle(env)`. It is loaded as UTF-8 source bytes with `abi.backend = "critter"` and
`abi_tag = "gawd_critter_v1"`; there is no `Cargo.toml`, `.so`, or wasm artifact.

1. Write a Rhai `handle` function. `env.payload` is a `Blob`; `env.text` is the payload as lossy
   UTF-8 (the engine has no Blob→String builtin, so string-oriented critters read this); `env.schema`,
   `env.from`, `env.to`, and optional `env.corr` are also available. Return a `Blob` or string to reply, return
   `()` for no reply, or call `emit("creature:N", bytes)` / `emit("role:R", bytes)` /
   `emit("topic:T", bytes)` / `emit("intent:X", bytes)` / `emit("kernel", bytes)` for extra
   capability-gated dispatches. Local variables have a fresh scope per envelope; bounded
   `mem_get` / `mem_set` / `mem_del` state survives for the loaded instance. `emit` payloads must be
   **Blobs** and still pass the `calls` gate. Pure `json_parse` / `json_stringify` helpers support
   value-only JSON under byte, depth, node, and structural caps; `function_call_verify` validates a
   typed Function call's signed dispatch and its authenticated local `env.from` / `env.to` route.
   These helpers add no I/O or key authority. The engine caps expression-nesting depth, pinned
   identically across debug/release builds, so it won't surprise you between profiles.
2. Author a manifest stub with the same fields the native authoring path uses. `build-critter`
   fills `abi`, `provenance`, `content_address`, and the ed25519 signature.
3. Validate/sign through `cosmos/creatures/build-critter` or through `alpha> author --critter <request>`.
   The compile gate rejects syntax errors, missing `handle`, Rhai `import`, and runtime `eval` before
   anything is signed.

Start from [`docs/quickstart/critter.md`](docs/quickstart/critter.md) (one of the per-tier
[quickstarts](docs/quickstart)); the worked set is in
[`cosmos/creatures/prototypes/critters/`](cosmos/creatures/prototypes/critters) (each compiled + run by `cosmos/sanctum/tests/critter_examples.rs`),
with `cosmos/creatures/prototypes/critters/echo-critter/echo.rhai` the reference and `cosmos/sanctum/tests/critter_tier.rs` the
end-to-end pattern.

## Add an injected model (`cosmos/creatures/prototypes/*`)

Models — placement resolvers, admission policies, fitness scorers — are *not*
substrate; they belong in `cosmos/creatures/prototypes/*` (or in `cosmos/creatures/*` when they're real
shipped consumers of a substrate primitive, like the requirements-matching distributor and
advertiser). The substrate ships the *socket* and the *mechanism*; a model fills
the socket via `Role`-binding (`bind <role> <id>` at the REPL, or programmatically
via `Router::bind_role`). **The substrate never substitutes a model of its own.**

- `cosmos/creatures/prototypes/distributors/distributor-roundrobin` — a minimal round-robin
  distributor reference, bound to `Role::DISTRIBUTOR`. The requirements-matching Distributor
  (`cosmos/creatures/distributor-requirements`) ships alongside; both are creatures, the
  operator picks one with `bind_role` (IoC composability).
- `cosmos/creatures/prototypes/policies/policy-dev` — permissive admission policy (admits everything).
- `cosmos/creatures/prototypes/policies/policy-signed` — admission policy requiring an Abode-signed manifest.
- `cosmos/creatures/prototypes/policies/policy-budget` — admission policy consuming the `BudgetSignal`.

When you write a new model, decide between `cosmos/creatures/prototypes/`
(operator-replaceable reference strategy) and `cosmos/creatures/` (real consumer of a substrate
primitive); either way, call out in its README that it is an injected model, not substrate.

## Tests

- **Unit tests** live next to the code they test; run a focused crate with `cargo test -p <crate>`.
- **Full suite:** do not duplicate it locally. It runs once on the exact release candidate in
  constrained CI. Iterate with
  `CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 cargo test -p <crate> -- --test-threads=1`;
  `.cargo/config.toml` also defaults forgotten invocations to one build job and one libtest thread.
- **Disk courtesy:** CI runs the full suite once per candidate; focused package tests are the local
  iteration loop. The workspace profiles retain line tables but disable full
  debug/incremental artifact graphs. Cargo does not garbage-collect old target variants; inspect
  `target/` and use `cargo clean -p <exact-package>` when generated package artifacts must be
  reclaimed. Never clean runtime state, journals, keys, or fixtures as build output. Do not launch a
  Cargo command while another agent or shell is compiling the same workspace; wait for and reuse the
  existing result instead of repeating the gate.
  Cargo-backed authoring tests and demos share `target/gawd-build-cache`; while no authoring build is
  active, `cargo clean --target-dir target/gawd-build-cache` reclaims exactly that generated cache.
- **CPU courtesy:** budget/fuel tests should prove the trap with the smallest useful cap and bounded
  work. If a test intentionally spins, keep the loop short, serialize it with a harness-local lock
  when nearby tests may also spin, and make long-lived thread specimens sleep/yield between polls.
- **Integration tests** live in `cosmos/sanctum/tests/*.rs` and exercise composed
  paths through the kernel. Patterns to follow:
  - native-lifecycle changes → an `m1_*`-style reload-loop test (see
    `cosmos/sanctum/tests/m1_reload_loop.rs`)
  - cross-node changes → an `m2_*`-style two-Sanctum test (see
    `cosmos/sanctum/tests/m2_two_node.rs`; it binds ephemeral loopback ports)
  - authoring-loop changes → an `m3_*`-style test (see
    `cosmos/sanctum/tests/m3_authoring_loop.rs`)
  - capability-gate changes → an `m4_*`-style test (see
    `cosmos/sanctum/tests/m4_capability_sandbox.rs`)
  - composed-loop changes → a `v01_end_to_end`-style wrap test (see
    `cosmos/sanctum/tests/v01_end_to_end.rs`; static ports 19_910 / 19_911)
- **Port allocation** for cross-node tests: prefer ephemeral loopback ports for new tests. Static
  allocations still in tree: `v01_end_to_end` uses `19_910 / 19_911`;
  `distributor_cross_node` uses `19_920 / 19_921`; `realm_local_route` uses
  `19_930 / 19_931`
  (the `omega_stub_route` test is in-process, no ports); `19_940 / 19_941`
  is deliberately left as an unused gap;
  `v02_end_to_end` uses `19_950 / 19_951`;
  `abode_migrate_cross_node` uses
  `19_955 / 19_956` and `abode_restore_admission_rejected` uses
  `19_957 / 19_958` (`abode_migrate_local` is in-process — one Sanctum,
  two migrator creatures — so it uses no ports);
  `omega_federation_cross_node` uses `19_960 / 19_961` (
  `omega_admission_gate_holds` is in-process — the T2 property is about the
  admission gate, not the wire — so it uses no ports); `seer_steer_abort_cross_node`
  uses `19_970 / 19_971`. Pick from the next free range and document the choice.

## Conventions

- Match the style of the surrounding code.
- Record significant or hard-to-reverse decisions in the relevant
  [design note](docs/design/) so the reasoning travels with the code.
- Keep "fabric, not model" structural: if a change adds a *strategy* to the
  kernel, surface a *socket* in the kernel and put the strategy in a
  creature instead (see [inversion of control](docs/design/inversion-of-control.md)).
- New shipped behavior needs a test that fails before and passes after; for
  cross-node and lifecycle changes, see the patterns above.
