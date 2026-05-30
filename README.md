# Alpha

[![CI](https://github.com/gawd-ai/alpha/actions/workflows/ci.yml/badge.svg)](https://github.com/gawd-ai/alpha/actions/workflows/ci.yml)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg)](LICENSE)
![status: pre-1.0](https://img.shields.io/badge/status-pre--1.0-orange.svg)

A running AI writes a new capability in Rust, the runtime compiles and ed25519-signs it and hot-loads
it into a live node, and then that **running self relocates to another machine mid-flight — its state
cryptographically intact**. One command watches it happen; two tests prove it over real TCP.

**Alpha** is the first public open-source substrate for **GAWD**: **General Autonomous World
Demiurge**, the larger goal of AI-authored capability that can make, move, govern, and retire its own
work. Alpha is still a work distributor, but it is more than a dispatcher: the unit of progress isn't
a chat turn — it's a new piece of *running, shareable* work: code an AI authors, admits, runs,
distributes across machines, and retires on its own initiative. The primary operator is an AI; humans
supervise.

That is why the main crate and binary are named `alpha`: this release is the first door into the
larger GAWD cosmology.

**Naming seam:** use **Alpha** for this repository, source release, binary, and current substrate
implementation. Use **GAWD** for the company's overall goal and system universe, the cosmology
(Sanctum, Realm, Omega), and names that must remain stable across GAWD systems, such as the
`gawd_creature_v1` wire ABI. Rule of thumb: commands, crates, release notes, and runtime UI in this
repo say Alpha; cross-system contracts, realm-scale concepts, and the broader objective say GAWD.

```sh
cargo run -p walkthrough      # the whole loop, narrated, in your terminal
```

The demo authors a string-reversing creature from an English request, compiles + signs it, admits it
through the kernel's gate, hot-loads it, runs it, then migrates a running self between two Sanctums —
driving the **same** admission → engine → router path the test suite uses, no mocks. The first run
shells out to a real `cargo build` to compile the authored creature, so on a cold cache it takes a
minute or two; later runs are seconds.

> **It's not slideware — the claims point at tests you can run.** A creature authored on node A ships
> to node B over ed25519-authenticated TCP, B verifies provenance + integrity *before* running it, and
> a running self relocates between hosts and stays authoritative there:
> [`abode_migrate_cross_node.rs`](cosmos/sanctum/tests/abode_migrate_cross_node.rs) and
> [`distributor_cross_node.rs`](cosmos/sanctum/tests/distributor_cross_node.rs).
>
> **What's real vs. not-yet (we'd rather you knew):** the shipped reference authoring creature is a
> deterministic *template matcher* (`agent-templated`), not an LLM — it proves the author → compile →
> sign → admit → load *seam*, and an LLM-backed author binds the exact same `AUTHORING` socket but is
> not yet wired in-tree. Native creatures are *trusted-by-admission* (in-process; run untrusted code in
> the sandboxed WASM `beast` tier or the metered, sandboxed script `critter` tier). Alpha is **pre-1.0
> with no external security audit** — see [`SECURITY.md`](SECURITY.md).

## The five governing loops are alive

Alpha's behavior is five anti-entropy loops — all ordinary bus traffic, each realized by an *injected*
creature (the substrate ships the socket and the sense stream; the model is a creature). Every row is
a claim you can click through to tested code:

| Loop | Cycle | Realized by | Proven in |
|---|---|---|---|
| **1 Sense → act** | proprioception → reason → motor act | the kernel's sense streams + control surface | [`v01_end_to_end.rs`](cosmos/sanctum/tests/v01_end_to_end.rs) |
| **2 Author → select → promote** | variation → fitness → heredity | `fitness-selector` (signs a promotion from an injected criterion) | [`fitness_selection_local.rs`](cosmos/sanctum/tests/fitness_selection_local.rs) |
| **3 Distribute** | intent → match requirements ↔ embodiment → place | `distributor-requirements` (capability-addressed routing) | [`distributor_cross_node.rs`](cosmos/sanctum/tests/distributor_cross_node.rs) |
| **4 Defend** | observe → self/non-self → contain / quarantine | `immune-response` (trust-gated, reversible quarantine) | [`immune_response_local.rs`](cosmos/sanctum/tests/immune_response_local.rs) |
| **5 Acculturate** | observe peers → adopt better models | `omega-federator` (cross-Realm pull + signed reputation) | [`omega_federation_cross_node.rs`](cosmos/sanctum/tests/omega_federation_cross_node.rs) |

The composed tests `cosmos/sanctum/tests/v0{1,2,3}_end_to_end.rs` stitch the whole loop together. All three
runtime tiers are real (native `daemon` + WASM `beast` + script `critter`); the substrate ships
*sockets and mechanisms* only — every *model* (placement, policy, fitness, consensus) is an injected
creature it can re-author.

## Self-hosting: the AI can re-author the substrate it runs on

The substrate's *own* infrastructure — transport, registry, the authoring agent, the admission policy,
the placement distributor — is itself a set of creatures, hot-swappable like any other.
[`hot_swap_organ.rs`](cosmos/sanctum/tests/hot_swap_organ.rs) swaps a bound infrastructure organ mid-traffic
without tearing down the bus. An AI improves the system it runs on, not just the work running on it.

## Workspace map

The root holds just the **α** door (`alpha/`) and the support dirs (`demos/`, `docs/`);
everything between α and **Ω** lives under `cosmos/`, so the cosmology is legible from `ls`.

| Path | What it is |
|---|---|
| `cosmos/sigil/` | The at-rest contract: `name / version / abi / entrypoints / capabilities / requirements / provenance / content_address / provides`. The **sole** metadata source. |
| `cosmos/aether/` | The bus spine: typed `Envelope` (carrying trust primitives), `Address` (`Creature / Node / Kernel / Topic / Intent / Role`, plus the `Realm` / `Omega` federation grain), sharded `Router`, the `Creature` seam, `BusHandle`, the journal, the `seer` Query/Answer primitive, and the `abode` snapshot types. |
| `cosmos/anima/` | The per-tier loaders: `NativeEngine` (libloading + safe-unload), `WasmEngine` (real wasmtime — fuel + linear-memory limiter), `ScriptEngine` (the `critter` tier — a sandboxed Rhai interpreter metered by an operation budget). |
| `cosmos/sanctum/` | **The kernel library** — three jobs, model-free: lifecycle (load/unload/reload), routing (the bus), admission (mechanism here, policy injected). Tier-blind. |
| `cosmos/forge/` | The creature-authoring surface: `declare_creature!` (one POD-only `extern "C"` entry), `NativeBus`, the managed `spawn` (thread-join discipline), the prelude. |
| `cosmos/abode/` · `cosmos/seer/` · `cosmos/realm/` · `cosmos/omega/` | First-class **concept crates** that live alongside `aether`: `abode` (snapshot/continuity), `seer` (Query/Answer), and the federation pair `realm` (trust domain) + `omega` (**= Ω**). `realm`/`omega` own their gateway seam — the Role + wire contract their injected gateway creatures fulfill. |
| `alpha/` · `cosmos/omni/` | **`alpha`** is the **α** front door: the single binary, dispatching in-process to `alpha node` (the sanctum daemon — REPL + optional HTTP/WS + cluster), `alpha mcp` (the MCP control-hub), and `alpha http` (the HTTP/WS plane); `alpha demo` is a managed runner that launches the external demos listed in `demos/demos.json` (not linked in). **`omni`** is the spine-only control core every surface drives over the bus (`run_verb` + `ControlCore` on `Role::CONTROL`). |
| `cosmos/creatures/*` | Creatures — the substrate's **production-capable reference organs**: the author/transport/registry loop (`build-cargo`, `build-critter`, `agent-templated`, `agent-curious`, `transport-tcp`, `registry-mem`), the loadable control surfaces (`surface-http`, `surface-mcp`), the Distributor (`distributor-requirements` + `embodiment-advertiser`), the distributed self (`abode-migrator`, `abode-reconciler`), federation (`omega-federator`), evolution (`fitness-selector`, `immune-response`), and verifiable randomness (`verifiable-die`). |
| `cosmos/creatures/prototypes/*` | **Injected reference-strategy models, NOT substrate** — operator-replaceable strategies the tests bind into the sockets: distributors (`distributor-roundrobin`, `reputation-roundrobin`), admission policies (`policy-dev / -signed / -budget / -abode-allowlist / -prefer-promoted / -quarantine-*`), fitness scorers (`scorer-success-rate / -latency / -roundrobin`), federation gateways (`realm-gateway`, `omega-gateway`), a merge lattice (`merge-lww-map`), the `monitor`, and the critter (Rhai) script prototypes (`critters/*`, `echo-critter`). |
| `cosmos/creatures/prototypes/fixtures/*` | **Test-only creatures**, loaded by the kernel test suite — the walking-skeleton stubs (`echo-daemon{,-v2}`, `loopback-gateway`) and the misbehavior/control specimens (`panic-daemon`, `runaway-thread-daemon`, `welbehaved-thread-daemon`). Not built into any deployment. |
| `cosmos/sanctum/tests/memcheck/` | Memory-safety harnesses (ASan / Miri / Valgrind) over the unsafe native-load path, beside the `sanctum` tests they drive. Run by hand, not by CI. |

The **beast (WASM)** and **critter (script)** tiers are real: integration tests compile and run
WebAssembly inline via `WasmEngine`, and the critter tests load signed Rhai source through
`ScriptEngine`, both through the same `Kernel::load` path as native and differing only by
`abi.backend`. The full per-creature table is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Build & run

```sh
# See the whole loop, narrated, in your terminal — the fastest way to "get" Alpha.
cargo run -p walkthrough

# See many Sanctums across 2–3 Realms federate over real ed25519-authenticated TCP (loopback).
cargo run -p federation        # --realms 3 --sanctums 2 for a bigger mesh

# Build the whole workspace against locked deps.
cargo build --locked --workspace

# Run the test suite with polite parallelism (the composed end-to-end loops
# live in cosmos/sanctum/tests/). CI uses the same cap.
CARGO_BUILD_JOBS=2 cargo test --locked --workspace -- --test-threads=1

# Run a Sanctum node — boots the three engines, wires its own organs, and drops into the REPL.
cargo run -p alpha -- node        # add --minimal for a bare kernel with nothing bound

# Browse the full API — every crate carries //! crate-level docs.
cargo doc --workspace --no-deps --open
```

## Release/install posture

This first public release is **source-first**. Clone the repo and build the `alpha` front door (and
the demos) from the workspace; `sigil` is the only crate currently packaged for crates.io, because
it is the standalone at-rest contract. The other workspace crates are intentionally unpublished while
the node/MCP/control surfaces settle before 1.0.

By default the node **self-hosts its own organs** (the authoring agent, the build creature, the
registry, and a `monitor` watching the sense streams). The REPL exposes the kernel's control
surface — every command goes through the same admission → engine → router path the integration
tests use:

```
alpha> author <request>                       # AI authors → compiles → signs → admits → hot-loads a creature
alpha> author --critter <request>             # AI authors → signs → admits → hot-loads a script creature
alpha> load <manifest-path> <artifact-path>   # admit + load a creature from disk
alpha> send <id> <text>                       # route an Envelope to a Creature
alpha> intent <outcome> <text>                # route to whoever is bound to the Intent socket
alpha> bind <role> <id>                       # plug a creature into a Role socket
alpha> unload <id>                            # safe-unload via deregister → drain → engine::unload
alpha> list | status | journal                # introspect: loaded creatures, role bindings, the bus journal
alpha> quit                                   # shutdown_all on the way out
```

So `author write a daemon that reverses a string` makes the substrate write, compile, sign, admit,
and hot-load that creature live — then `list` shows it sitting alongside the node's own organs. The
[operator quickstart](docs/quickstart/operator.md) walks this end to end — boot, author live, watch the
sense-tape, then scale up to the federation demo.

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml) (stable, edition 2021). See
[`CONTRIBUTING.md`](CONTRIBUTING.md) for how to author a creature.

> **Platform:** the native (`daemon`) tier uses `dlopen`/`.so` loading and is developed on Linux
> (x86-64; the valgrind/ASan helpers in `cosmos/sanctum/tests/memcheck/` assume it). The WASM (`beast`) tier is
> platform-independent. macOS/Windows support for the native tier is untested.

## Drive a node remotely — HTTP API + MCP

The REPL is the local human seat. A node can also expose an authenticated **HTTP + WebSocket**
control plane, and an AI assistant can drive it over **MCP** — both are loadable surface creatures
driving `Role::CONTROL` over the bus (see [the bus & control design note](docs/design/bus-and-control.md)):

```bash
# Build the one binary from this source release: `alpha`, the α front door.
cargo build --release -p alpha

# Serve the HTTP/WS control plane (the loadable `surface-http` creature). `alpha node
# --listen` keeps the local REPL too; `alpha http --listen` is the headless sibling.
cargo run -p alpha -- node --listen 127.0.0.1:7777
#   --headless        API only, no REPL        --allow-ai   open the gate at boot
#   --api-key <key>   set the key (else SANCTUM_API_KEY, else auto-generated + printed once)

curl -s localhost:7777/api/health                                  # public liveness
curl -s -H "Authorization: Bearer $KEY" localhost:7777/api/status  # auth'd; shows the allow-AI gate
```

Register the MCP hub with any host. `alpha mcp` **is itself a headless Alpha Sanctum** participating
in the GAWD fabric — not a REST proxy: its `surface-mcp` creature owns stdio, and each tool call
becomes a `Verb` envelope on the node's own bus. The default is a self-contained hub; `--target
<node@control-id> --seed …` joins the mesh to front a peer node instead.

```json
{ "mcpServers": { "alpha": {
    "command": "/abs/path/to/target/release/alpha",
    "args": ["mcp"] } } }
```

**Human and AI co-drive the *same* node, safely:** the allow-AI gate is **off by default**, so a
remote AI's mutating tools (`alpha_author`, `alpha_send`, …) return `ai-not-allowed` until a human grants
it at the REPL with `allow-ai on`. HTTP reads still require the Bearer key; MCP read-only tools
require access to the spawned hub and, in remote mode, its mesh identity. Neither read path is
blocked by the allow-AI gate. The AI announces its activity, which shows on the operator's sense-tape
and `/api/ws` stream — so a human can watch and `allow-ai off` to revoke mid-flight. This surface can
author and hot-load native code; see [`SECURITY.md`](SECURITY.md).

**Cluster many nodes.** Give `alpha node` a `--cluster-listen` address and it joins a **dynamic
many-to-many mesh**: nodes gossip membership over the authenticated transport, so the mesh
self-completes from one `--seed` (or a runtime `cluster join`) — no node is pre-configured with every
peer (see [the identity, transport & clustering design note](docs/design/identity-transport-clustering.md)). `cluster` reads the graph,
`send <node-id>:<id>` runs a creature on a peer over the mesh, and an AI can drive it all over MCP
(`alpha_cluster`). The hands-on three-node runbook — boot, join, observe, cross-execute, attach an AI —
is [`demos/cluster/`](demos/cluster/).

## Vocabulary

Four terms carry the rest; the full glossary is in [`docs/CONCEPTS.md`](docs/CONCEPTS.md).

- **Creature** — a hot-loadable unit of capability. Three tiers: a native `daemon` (in-process,
  trusted-by-admission), a WASM `beast` (sandboxed — where untrusted/mobile code runs), and a script
  `critter` (a sandboxed Rhai interpreter metered by an operation budget — cheap, portable, authored
  with no compiler).
- **Sanctum** — a node: any compute host (server, robot, satellite, edge device) that loads and
  supervises creatures.
- **Abode** — a portable per-identity *self*: state that can migrate / fork / merge between Sanctums.
- **Realm / Omega** — Sanctums federate into a Realm (a trust domain); Realms into the Omega
  (the global graph + registry).

## Documentation

Browsing as an AI agent? Start at **[AGENTS.md](AGENTS.md)** — the machine-first map: mental model,
repository layout, run/test commands, and the load-bearing invariants.

| Doc | What |
|---|---|
| [AGENTS.md](AGENTS.md) | AI-agent orientation: the fast map + invariants you must not break |
| [Quickstarts](docs/quickstart/) | Run a node as the operator, and write your first creature on each tier (critter / daemon / beast) |
| [Topics & SEER](docs/TOPICS.md) | The pub/sub + consult contract — what a creature may listen to and emit |
| [Demos](demos/) | Narrated, runnable walkthroughs — one node's whole loop, and a multi-Realm federation over TCP |
| [Vision](docs/VISION.md) | The thesis and why now |
| [Concepts](docs/CONCEPTS.md) | Cosmology + glossary |
| [Design notes](docs/design/) | How Alpha works, by subsystem — the mechanism and the reasoning that shapes it |
| [Roadmap](docs/ROADMAP.md) | Alpha's next substrate steps toward GAWD |
| [Architecture](docs/ARCHITECTURE.md) | As-built engineering truth |
| [Changelog](CHANGELOG.md) | What shipped, by version |
| [Release](RELEASE.md) | Release checklist and tag/publish procedure |

## Design principles

The four load-bearing decisions that shape the substrate — the full reasoning is in the
[design notes](docs/design/):

- **One substrate, three tiers** — native / WASM / script load through one `Kernel::load` path, differing only by `abi.backend` ([substrate](docs/design/substrate.md)).
- **Safe native hot-unload** — kernel-driven `deregister → drain → engine::unload`, proven over a 1000-cycle RSS-stable, ASan-clean reload loop ([substrate](docs/design/substrate.md)).
- **Proof of trust** — the trust primitives ride structurally on every envelope; concrete trust *models* are injected, never baked in ([addressing, placement & federation](docs/design/addressing-placement-federation.md)).
- **Inversion of control** — the kernel ships *sockets and mechanisms*; every *model* (placement, policy, fitness, consensus) is an injected creature. This is the thesis — *fabric, not model* ([inversion of control](docs/design/inversion-of-control.md)).

## License

Alpha is licensed under the **GNU General Public License v3.0 or later** (`GPL-3.0-or-later`). See
[`LICENSE`](LICENSE) for the full text. Contributions are accepted under the same license; please
read [`CONTRIBUTING.md`](CONTRIBUTING.md) and the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

**For creature authors:** the SDK and contracts (`forge`, `aether`, `sigil`) are GPL-3.0-or-later,
so a native creature that links them is a derivative work and, when distributed, must use compatible
terms.

## Community

Source, issues, and discussion: <https://github.com/gawd-ai/alpha>.
