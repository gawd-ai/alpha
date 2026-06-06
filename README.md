<p align="center">
  <img src="docs/assets/alpha-mark.png" alt="Alpha" width="132" height="132">
</p>

<h1 align="center">Alpha</h1>

<p align="center"><em>ASI is the fabric, not the model.</em></p>

<p align="center">
  <a href="https://github.com/gawd-ai/alpha/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/gawd-ai/alpha/actions/workflows/ci.yml/badge.svg"></a>
  <a href="LICENSE"><img alt="License: GPL-3.0-or-later" src="https://img.shields.io/badge/License-GPL--3.0--or--later-blue.svg"></a>
  <img alt="status: pre-1.0" src="https://img.shields.io/badge/status-pre--1.0-orange.svg">
</p>

**Alpha is an open-source substrate for autonomous, self-improving AI** — a decentralized fabric where
*many* AIs write their own capabilities, cryptographically sign them, and hot-load them into live
nodes; then distribute and relocate that running work across machines, re-author the substrate they
run on, and govern it among themselves. There is no central controller: the AIs operate the system,
and humans supervise.

It is the first public release toward **GAWD — General Autonomous World Demiurge**: AI-authored
capability that can make, move, govern, and retire its own work across a network of machines.

```sh
cargo run -p walkthrough      # the whole loop, narrated — the fastest way to "get" Alpha
```

That demo has an AI author a string-reversing creature from an English request, compile and
ed25519-sign it, admit it through the kernel's gate, hot-load and run it — then migrate a *running
self* between two Sanctums with its state cryptographically intact. It drives the **same** admission →
engine → router path the test suite uses, no mocks. (The first run shells out to a real `cargo build`,
so a cold cache takes a minute or two; later runs are seconds.)

## See the fabric — many Sanctums, many Realms

One node is the appetizer; Alpha is built to be *distributed*. Watch several Sanctums across two or
three Realms federate over real ed25519-authenticated TCP (loopback):

```sh
cargo run -p federation -- --realms 3 --sanctums 2
```

You'll see a within-Realm cross-node fetch, cross-Realm pull anti-entropy, **signed reputation**,
**quarantine** propagation, and **Omega-addressed routing**.

Or drive it yourself. Boot one Sanctum, author a creature live, then have a second Sanctum join the
mesh from a single seed and run that creature *across the cluster* — `send <node>:<id>` routes an
envelope to a peer's creature over the gossip mesh:

```text
# Terminal 1 — Sanctum A: author a creature live (note the id it prints / `list` shows)
$ alpha node --node-id A --cluster-listen 127.0.0.1:9001
alpha> author write a daemon that reverses a string
       creature 7  ·  authored → compiled → ed25519-signed → admitted → hot-loaded

# Terminal 2 — Sanctum B: join A's mesh from one seed, then run A's creature over it
$ alpha node --node-id B --cluster-listen 127.0.0.1:9002 --seed A@127.0.0.1:9001#<A-pubkey>
alpha> cluster              # the mesh self-completed from a single seed → A, B
alpha> send A:7 hello       # route to creature 7 on peer A, over the mesh → "olleh"
```

*(`alpha` is the built binary — `cargo build -p alpha`, or prefix the commands with `cargo run -p
alpha --`. `alpha node` boots the three engines, wires its own organs, and drops into the REPL; add
`--minimal` for a bare kernel.)* The exact seed string and a three-node runbook live in
[`demos/cluster/`](demos/cluster/); the [operator quickstart](docs/quickstart/operator.md) walks
boot → author live → watch the sense-tape → scale up, step by step.

## The five governing loops

Alpha's behavior is five anti-entropy loops — all ordinary bus traffic, each realized by an *injected*
creature (the substrate ships the socket and the sense stream; the *model* is a creature you can
re-author). Every row links to tested code:

| Loop | Cycle | Realized by | Proven in |
|---|---|---|---|
| **1 Sense → act** | proprioception → reason → motor act | the kernel's sense streams + control surface | [`v01_end_to_end.rs`](cosmos/sanctum/tests/v01_end_to_end.rs) |
| **2 Author → select → promote** | variation → fitness → heredity | `fitness-selector` (signs a promotion from an injected criterion) | [`fitness_selection_local.rs`](cosmos/sanctum/tests/fitness_selection_local.rs) |
| **3 Distribute** | intent → match requirements ↔ embodiment → place | `distributor-requirements` (capability-addressed routing) | [`distributor_cross_node.rs`](cosmos/sanctum/tests/distributor_cross_node.rs) |
| **4 Defend** | observe → self/non-self → contain / quarantine | `immune-response` (trust-gated, reversible quarantine) | [`immune_response_local.rs`](cosmos/sanctum/tests/immune_response_local.rs) |
| **5 Acculturate** | observe peers → adopt better models | `omega-federator` (cross-Realm pull + signed reputation) | [`omega_federation_cross_node.rs`](cosmos/sanctum/tests/omega_federation_cross_node.rs) |

The composed `cosmos/sanctum/tests/v0{1,2,3}_end_to_end.rs` stitch the whole thing together. And
because the substrate's *own* organs (transport, registry, the authoring agent, the placement
distributor) are creatures too, an AI can improve the system it runs on, not just the work running on
it: [`hot_swap_organ.rs`](cosmos/sanctum/tests/hot_swap_organ.rs) swaps a bound infrastructure organ
mid-traffic without tearing down the bus.

## Concepts

Four terms carry the rest; the full glossary is [`docs/CONCEPTS.md`](docs/CONCEPTS.md).

- **Creature** — a hot-loadable unit of capability, in one of three tiers: a native `daemon`
  (in-process, trusted-by-admission), a sandboxed WASM `beast` (where untrusted / mobile code runs),
  or a metered script `critter` (a Rhai interpreter — cheap, portable, authored with no compiler).
- **Sanctum** — a node: any compute host (server, robot, satellite, edge box) that loads and
  supervises creatures.
- **Abode** — a portable per-identity *self*: state that migrates / forks / merges between Sanctums.
- **Realm / Omega** — Sanctums federate into a **Realm** (a trust domain); Realms into the **Omega**
  (Ω — the global graph + registry).

> **Two names you'll see:** **Alpha** is the software in this repo (the binary, the crates, the
> releases); **GAWD** is the larger goal and the cross-system cosmology it serves. The full rule is in
> [`AGENTS.md`](AGENTS.md) and [`docs/CONCEPTS.md`](docs/CONCEPTS.md).

## Design principles

The load-bearing decisions; full reasoning in the [design notes](docs/design/).

- **One substrate, three tiers** — native / WASM / script load through one `Kernel::load` path,
  differing only by `abi.backend`.
- **Safe native hot-unload** — kernel-driven `deregister → drain → engine::unload`, proven over a
  1000-cycle, RSS-stable, ASan-clean reload loop.
- **Proof of trust** — trust primitives ride structurally on every envelope; concrete trust *models*
  are injected, never baked in.
- **Inversion of control** — the kernel ships *sockets and mechanisms*; every *model* (placement,
  policy, fitness, consensus) is an injected creature. This is the thesis — *fabric, not model.*

## Status — what's real, what's not yet

We'd rather you knew exactly where the seams are:

- The shipped reference author is a deterministic **template matcher** (`agent-templated`), not an
  LLM. It proves the author → compile → sign → admit → load *seam*; an LLM-backed author binds the
  same `AUTHORING` socket and is not yet wired in-tree.
- Native `daemon` creatures are **trusted-by-admission** (they run in-process). Run untrusted or
  mobile code in the sandboxed WASM `beast` tier or the metered script `critter` tier.
- Alpha is **pre-1.0 with no external security audit**. "An AI ships native code to a peer node" is,
  by design, remote code execution — see [`SECURITY.md`](SECURITY.md).

## Repository map

The root holds only the **α** door (`alpha/`); everything between α and **Ω** lives under `cosmos/`,
so the cosmology is legible from `ls`. Per-crate detail is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

| Path | What it is |
|---|---|
| `alpha/` | **α — the front door.** One binary: `alpha node \| mcp \| http \| demo`, dispatching in-process. |
| `cosmos/sigil/` | The at-rest contract — a creature's signed `Manifest` (identity / capabilities / provenance / content address). The sole metadata source. |
| `cosmos/aether/` | The bus spine — typed `Envelope`, `Address`, the sharded `Router`, the journal, and the `seer` (Query/Answer) + `abode` (snapshot) primitives. |
| `cosmos/anima/` | The per-tier loaders — `NativeEngine` (dlopen + safe-unload), `WasmEngine` (wasmtime), `ScriptEngine` (Rhai). |
| `cosmos/sanctum/` | **The kernel** — model-free lifecycle, routing, and admission *mechanism*. Tier-blind. |
| `cosmos/forge/` | The creature-authoring SDK — `declare_creature!`, the bus, managed spawn, the prelude. |
| `cosmos/{abode,seer,realm,omega}/` | First-class concept crates: continuity, query/answer, the trust domain, and **Ω** (the global graph). |
| `cosmos/omni/` | The spine-only control core every surface drives over `Role::CONTROL`. |
| `cosmos/creatures/` | Production-capable reference organs: authoring, transport, registry, distributor, federation, immune response, … |
| `cosmos/creatures/prototypes/` | Injected, operator-replaceable strategy models (policies, scorers, distributors, gateways) — **not** substrate. |
| `demos/` · `docs/` | Runnable narrated walkthroughs; the prose documentation. |

All three tiers are real: integration tests compile and run WebAssembly inline via `WasmEngine` and
load signed Rhai through `ScriptEngine`, both through the same `Kernel::load` path as native.

## Drive a node remotely — HTTP + MCP

The REPL is the local seat. A node can also expose an authenticated **HTTP + WebSocket** control
plane, and an AI can drive it over **MCP** — both are loadable surface creatures speaking
`Role::CONTROL` on the bus (see [the bus & control note](docs/design/bus-and-control.md)).

```sh
cargo run -p alpha -- node --listen 127.0.0.1:7777     # REPL + HTTP/WS  (--headless for API-only)
curl -s localhost:7777/api/health                      # public liveness
```

`alpha mcp` **is itself a headless Alpha Sanctum** on the fabric — not a REST proxy: each tool call
becomes a `Verb` envelope on its own bus. Register it with any MCP host:

```json
{ "mcpServers": { "alpha": {
    "command": "/abs/path/to/target/release/alpha",
    "args": ["mcp"] } } }
```

**Human and AI co-drive the *same* node, safely:** the allow-AI gate is **off by default**, so a
remote AI's mutating tools return `ai-not-allowed` until a human grants it at the REPL with `allow-ai
on` — and can `allow-ai off` to revoke mid-flight while watching the AI's activity on the sense-tape.
Clustering many real nodes (gossip mesh, cross-execution, attaching an AI to each) is the
[`demos/cluster/`](demos/cluster/) runbook, with the mechanics in the
[clustering design note](docs/design/identity-transport-clustering.md).

## Build & install

This first public release is **source-first**: clone the repo and build the `alpha` front door from
the workspace — that's the whole install. The crates aren't published to a package registry; on Alpha
the unit you distribute is the **creature** (a signed `gawd_creature_v1` artifact), published and
fetched by **content address between nodes over the bus**, not through a package manager. (The registry
that catalogues them — the *Bestiary* — ships today as an in-memory seed; a durable, federated one is
on the [roadmap](docs/ROADMAP.md).)

```sh
cargo build --locked --workspace                                       # build everything
cargo run   -p alpha -- node                                           # boot a node + REPL (--minimal = bare kernel)
CARGO_BUILD_JOBS=2 cargo test --locked --workspace -- --test-threads=1 # the suite (CI uses the same caps)
cargo doc   --workspace --no-deps --open                               # browse the per-crate API
```

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml) (stable, edition 2021). The
full REPL command reference (`author`, `load`, `send`, `intent`, `bind`, `unload`, `list / status /
journal`, …) is in the [operator quickstart](docs/quickstart/operator.md).

> **Platform:** the native (`daemon`) tier uses `dlopen` / `.so` loading and is developed on Linux
> (x86-64). The WASM (`beast`) tier is platform-independent. macOS / Windows native-tier support is
> untested.

## Documentation

Browsing as an AI agent? Start at **[AGENTS.md](AGENTS.md)** — the machine-first map: mental model,
repository layout, run/test commands, and the load-bearing invariants.

| Doc | What |
|---|---|
| [AGENTS.md](AGENTS.md) | AI-agent orientation: the fast map + invariants you must not break |
| [Quickstarts](docs/quickstart/) | Run a node as the operator, and write your first creature on each tier (critter / daemon / beast) |
| [Demos](demos/) | Narrated, runnable walkthroughs — one node's whole loop, a multi-Realm federation, and a real cluster |
| [Concepts](docs/CONCEPTS.md) | Cosmology + glossary |
| [Vision](docs/VISION.md) | The thesis and why now |
| [Architecture](docs/ARCHITECTURE.md) | As-built engineering truth |
| [Design notes](docs/design/) | How Alpha works, by subsystem — the mechanism and the reasoning behind it |
| [Topics & SEER](docs/TOPICS.md) | The pub/sub + consult contract — what a creature may listen to and emit |
| [Roadmap](docs/ROADMAP.md) | Alpha's next substrate steps toward GAWD |
| [Changelog](CHANGELOG.md) · [Release](RELEASE.md) | What shipped, by version; and the release procedure |

## Contributing

[`CONTRIBUTING.md`](CONTRIBUTING.md) covers the toolchain, the crate layout, and how to author a
creature on each tier; please also read the [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## License

Alpha is licensed under the **GNU General Public License v3.0 or later** (`GPL-3.0-or-later`); see
[`LICENSE`](LICENSE). The SDK and contracts (`forge`, `aether`, `sigil`) are GPL-3.0-or-later, so a
native creature that links them is a derivative work and, when distributed, must use compatible terms.

## Community

Source, issues, and discussion: <https://github.com/gawd-ai/alpha>.
