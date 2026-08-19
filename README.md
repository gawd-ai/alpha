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

**Alpha is an AI-first operating system for building a distributed computing fabric for ASI.** AIs write
their own capabilities, cryptographically sign them, and hot-load them into live nodes — then distribute
that running work across machines, federate it between networks, and govern it among themselves. There
is no central controller: the AIs operate the system; humans supervise.

It runs as two binaries, two poles:

- **`alpha`** — the **control surface**. The shell an AI (or you) uses to author, sign, hot-load, and
  drive *creatures*. One bus contract (`Role::CONTROL`) behind three faces: a REPL, HTTP/WS, and MCP.
- **`omega`** — the **fabric**. A headless server that meshes nodes into **Realms** and federates
  across them. Every peer link is mutually-authenticated ed25519 over TCP.

This is the first public release toward **GAWD — General Autonomous World Demiurge**.

## Quickstart

Five rungs, each building on the last. Every command is real — the same admission → engine → router
path the test suite drives, no mocks.

### 1. Get it and build

```sh
git clone https://github.com/gawd-ai/alpha && cd alpha
cargo build --release -p alpha -p omega        # → target/release/{alpha,omega}
```

In a hurry? `cargo run -p walkthrough` narrates the whole loop in one process: a reference author
creates a creature from an English request, compiles and ed25519-signs it, hot-loads and runs it, then
performs a signed local hand-off of a *running self* between two bodies inside one Sanctum with its
state intact. The cross-Sanctum transport variant is integration-test-proven rather than simulated by
the narrated demo. (The authoring step shells out to a real `cargo build`, so a cold cache takes a
minute; later runs are seconds.)

Alpha v0.5.0 includes a credential-free regression mode:

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 cargo run --locked -p dialogue -- --fixture
```

It exercises the whole composition with strict scripted Models, but it is regression evidence only.
Product acceptance requires a fresh `--live` run on the exact clean release commit: a Builder,
Reviewer, and Contract Tester make four signer-verified causal decisions across two Realms, producing
one novel bounded `affine_i32_v1` program. The same live Builder confirms a tiny source-free record for
each tier; host validation and audited templates—not model-supplied source—lower it into Rust, no-import
WAT, and Rhai. Three builders sign and durably publish the results, and six Jobs execute the three
distinct backend `FunctionId`s locally and cross-Realm using the Contract Tester's chosen inputs.

The live run must retain sanitized configurations, seven exact provider calls and provider-reported
receipts, four signed turns, decisions, lowered sources, artifacts, Bestiary proofs, six complete
signed Job event/grant/call/deployment/result bundles, and exact
commit/binary/toolchain identity in a hash-indexed evidence directory. An operator-controlled key
signs a seal outside that directory. Release validation is local: first run the exhaustive
credential-free `tools/local-validation.sh` gate with an external `--output-dir` on the frozen exact
commit; its handoff contains the validation report and copied candidate binary. Push that unchanged
commit and require its short hosted sanity check to pass, then run `tools/v05-live-acceptance.sh`
locally with that absolute `--validation-report` and a new absolute `--output-dir`. It validates the
handoff before loading provider/operator keys, invokes the
copied binary's standalone `dialogue verify-live` path with independently pinned trust/freshness
inputs, encrypts raw prompt-bearing evidence, and creates a disclosure-safe pack containing the local
validation report, exact binary, signed seal and index, acceptance manifest, six-field verifier
report, README, and hashes. GitHub receives neither those keys nor raw evidence; hosted sanity is
required merge/tag hygiene but is not the authoritative validation gate.
Provider receipts are traceability metadata, not cryptographic proof of model weights,
and the retained binary identity is not a reproducible-build proof. This is constrained typed
synthesis and a bounded three-mind fan-out/fan-in, not arbitrary-code generation, general agency,
broadcast/group chat, consensus, or a three-process deployment proof. See
[the release gate](RELEASE.md#local-v050-live-acceptance-gate),
[the demo instructions](demos/README.md#notes), and
[TRD-007](docs/trd/TRD-007-cross-mesh-model-collaboration.md). The exact v0.5.0 source candidate
deliberately carries pending TRD/ADR status: exact-commit validation, hosted sanity, live acceptance,
and external retention must succeed before its tag, and a later post-tag documentation commit links
the acceptance record and advances status. Its final
version/changelog metadata is already present before exhaustive local validation and the retained
live run; changing tracked metadata after proof would create an unproved commit.

### 2. Run a node, author a creature

Boot a node and you land in its REPL. A fresh `alpha node` self-hosts its own organs — an authoring
agent, the build creatures, an in-memory registry, a sense monitor — so it can write and run code
immediately:

```text
$ alpha node
alpha> author --critter reverse a string        # script tier: a sandboxed Rhai creature, no compiler
       ✓ authored → signed → admitted → hot-loaded critter as id=7
alpha> send 7 hello
       reply: olleh
```

That is one node authoring and running its own capability. Now make it a **fabric**: stand up an
`omega` node and connect this alpha to it. The first link is mutual — there is **no TOFU**, so each end
must already hold the other's pubkey (every node prints its own `node pubkey = …` at boot).

```sh
# Terminal 1 — alpha operator + HTTP/WS control surface (note its pubkey and ControlCore id):
alpha node --node-id op --cluster-listen 127.0.0.1:9302 --listen 127.0.0.1:7302

# Terminal 2 — an omega fabric node, seeded to your alpha so it can authenticate the first hop:
omega serve --node-id fab --realm crew --cluster-listen 127.0.0.1:9301 \
    --seed op@127.0.0.1:9302#<op-pub>
```

```text
# back at the alpha REPL — admit the fabric node (now A holds B's key too), then check the graph:
alpha> cluster join fab@127.0.0.1:9301#<fab-pub>
alpha> cluster
       op ── fab   (connected)
```

A lone `alpha node` already authors and runs creatures by itself, and alpha nodes can form an
authenticated Realm mesh directly. `omega serve` is the headless gateway/federation pole; with one
Realm it can act as a mesh anchor, and it earns its cross-Realm role in rung 3.

Typed Functions and durable Jobs are an explicit composition because a node cannot guess an Abode
root, operational keys, trust policy, or durable custody directory. Start the bounded reference
fillings with `alpha node --functions /secure/alpha/function-runtime.json`; the file references
separate protected operational-key files and contains only public proof material: the root-signed
Home authority plus exact operational-identity pins. The Abode root private key is never accepted by
this boot path. Ordinary `alpha node` and `omega serve` leave the Function sockets unbound. See
[`docs/design/functions-and-jobs.md`](docs/design/functions-and-jobs.md#normal-boot-posture-and-the-reference-opt-in).
The runtime canonicalizes and exclusively locks that state tree for its process lifetime before
opening seeds or stores. TRD-006 is Met for v0.4.4 through a suite-compositional proof: the in-process
custody suite proves the optional root-declared KMS rewrap chain, while the real two-process harness
uses boot-attested TCP/Omega, explicit signed deployment of the checked-in typed critter, changed-id
remote executor recovery through `NodeRole`, blocking-parent progress and Steer, typed causal-child
execution, fenced Home migration on the legacy no-rewrap branch, faulted GX gap retry, dual hard
restart, and terminal recovery. It deliberately does not claim crash-resume inside an unfinished GX
transfer; hard cuts occur at durable protocol boundaries.

### 3. Mesh more omegas across Realms

A **Realm** is one mesh of nodes. To federate *across* Realms — across servers, sites, organizations —
run one `omega` gateway per Realm. Each declares its own Realm (`--realm`) and maps the others to their
gateways (`--peer-realm <realm>=<node>`); seed the gateways with each other and they form the
inter-Realm mesh:

```sh
# Realm "crew" gateway (one host):
omega serve --node-id crew-gw --realm crew --cluster-listen 0.0.0.0:9101 \
    --peer-realm ops=ops-gw  --seed ops-gw@<ops-host>:9102#<ops-pub> --pull-interval 30

# Realm "ops" gateway (another host):
omega serve --node-id ops-gw  --realm ops  --cluster-listen 0.0.0.0:9102 \
    --peer-realm crew=crew-gw --seed crew-gw@<crew-host>:9101#<crew-pub> --pull-interval 30
```

The gateways exchange catalogues by pull anti-entropy, federate signed reputation and quarantine, and
route Omega-addressed traffic between Realms. `--pull-interval <seconds>` makes a gateway
**self-reconciling** — it pokes its own anti-entropy on that cadence instead of waiting for an operator
(omit it and the gateway stays poke-driven; the substrate ships no clock). Authoring stays on the
**alpha** seat: operators join a Realm's gateway, author there, and the federation carries it across.
Pin a stable identity for scripted seeds with `--cluster-key <64-hex>`.

See the whole cross-Realm story two ways — in one process, and as real separate processes:

```sh
cargo run -p federation                          # 2 Realms × 2 Sanctums, real TCP on loopback
cargo run -p federation -- --realms 3 --sanctums 2
```

The [`demos/cluster/`](demos/cluster/) runbook stands up the same shape as separate processes — an
`omega serve` anchor plus `alpha node` operators — forms the mesh, and cross-executes between nodes.

### 4. Drive it over MCP

An AI drives a node over **MCP**. `alpha mcp` is itself a headless Alpha Sanctum on the bus — not a
REST proxy: each tool call becomes a `Verb` envelope on `Role::CONTROL`. Register it with any MCP host:

```json
{ "mcpServers": { "alpha": {
    "command": "/abs/path/to/target/release/alpha",
    "args": ["mcp", "--allow-ai"] } } }
```

That spawns a self-contained, **headless** hub with mutating tools enabled at boot. Omit `--allow-ai`
for a read-only session; there is no REPL inside the MCP process and no MCP tool that can change its
gate later. To instead drive a node already running on a mesh, the target must have booted a control
surface (`--listen`) and printed its process-local `ControlCore` id. First pre-admit the hub's stable
identity at that mesh (there is no TOFU), then point it at that control creature. The hub needs
its own identity seed and listener as well as the peer seed:

```text
alpha> cluster join hub@127.0.0.1:9190#<hub-pub-derived-from-hub-seed>
```

```sh
alpha mcp --node-id hub --listen 127.0.0.1:9190 \
    --cluster-key <hub-ed25519-seed> \
    --target op@<control-id> --seed op@127.0.0.1:9302#<op-pub>
```

The [`demos/cluster/`](demos/cluster/) Step 05 shows the complete fail-closed pre-admission and remote
`alpha_cluster` check with a fixed demo identity. Generate fresh keys outside a demo.

Tools: `alpha_author`, `alpha_author_critter`, `alpha_send`, `alpha_cluster`, `alpha_status`,
`alpha_list`, `alpha_registry_*`, and the rest of the REPL surface. In remote mode the **target node**
owns the allow-AI gate: grant it at that node's REPL, or boot a headless target with `--allow-ai`.
Passing `--allow-ai` to the remote hub does not change the target's gate.

### 5. Drive it over HTTP

Any node can expose an authenticated HTTP-REST + WebSocket control plane — the same `Role::CONTROL`
surface, for web clients and scripts. (`omega serve` takes the same `--listen` / `--api-key`.)

```sh
alpha node --listen 127.0.0.1:7777 --api-key secret
# For API-only mutation, add both --headless and --allow-ai (there is then no REPL).

curl -s localhost:7777/api/health                                          # public liveness
curl -s -H "Authorization: Bearer secret" localhost:7777/api/cluster       # the mesh graph
curl -s -H "Authorization: Bearer secret" -X POST localhost:7777/api/author/critter \
     -H 'Content-Type: application/json' -d '{"request":"reverse a string"}'   # → {"creature_id":N,…}
curl -s -H "Authorization: Bearer secret" -X POST localhost:7777/api/send \
     -H 'Content-Type: application/json' -d '{"id":N,"text":"hello"}'          # → {"reply":"olleh"}
```

`GET /api/health` is public; everything else needs the Bearer key. A remote caller's **mutating** verbs
(author, send, cluster connect) stay blocked by the **allow-AI gate** — off by default. On an
interactive `alpha node`, a human flips `allow-ai on|off` at the REPL and watches the AI on the
sense-tape. A headless `alpha http`, `alpha node --headless`, or `omega serve` has no REPL: enable
mutation explicitly with `--allow-ai` at boot, and restart without it to close the gate. The remote
surface itself can never grant permission.

## Creatures — the unit of work

A **creature** is a hot-loadable unit of capability. Artifact-backed creatures in all three tiers
load through the *same* `Kernel::load` path, differing only by `abi.backend`:

| Tier | What it is | Author it with |
|---|---|---|
| **`critter`** | A metered **Rhai script** — cheap, portable, authored with no compiler. | `author --critter <request>` ([quickstart](docs/quickstart/critter.md)) |
| **`daemon`** | A **native** in-process creature (`dlopen` + safe hot-unload), trusted by admission. | `author <request>` → real `cargo build` ([quickstart](docs/quickstart/daemon.md)) |
| **`beast`** | A sandboxed **WASM** creature — where untrusted or mobile code runs. | compile a guest that exports the [minimal beast ABI](docs/quickstart/beast.md) |

The bundled reference author is a deterministic template matcher (it keys on `reverse` / `uppercase`),
which proves the author → compile → sign → admit → load *seam* with no network. A real model-backed
author (`agent-mind`) binds the same `AUTHORING` socket — build with `--features openai`, select a model
at the surface, and a live LLM writes the source. The model is *injected*; the fabric ships only the
socket. To author your own on any tier, see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## How work distributes — the five governing loops

Alpha's behavior is five anti-entropy loops — all ordinary bus traffic, each realized by an *injected*
creature (the substrate ships the socket and the sense stream; the *model* is a creature you can
re-author). Every row links to tested code:

| Loop | Cycle | Realized by | Proven in |
|---|---|---|---|
| **1 Sense → act** | proprioception → reason → motor act | the kernel's sense streams + control surface | [`v01_end_to_end.rs`](cosmos/sanctum/tests/v01_end_to_end.rs) |
| **2 Author → select → promote** | variation → fitness → heredity | `fitness-selector` (signs a promotion from an injected criterion) | [`fitness_selection_local.rs`](cosmos/sanctum/tests/fitness_selection_local.rs) |
| **3 Distribute** | intent → match requirements ↔ embodiment → place | `distributor-requirements` (capability-addressed routing) | [`distributor_cross_node.rs`](cosmos/sanctum/tests/distributor_cross_node.rs) |
| **4 Defend** | observe → self/non-self → contain / quarantine | `immune-response` (reversible local quarantine; injected trust gates inbound peer notices) | [`immune_response_local.rs`](cosmos/sanctum/tests/immune_response_local.rs) |
| **5 Acculturate** | observe peers → adopt better models | `omega-federator` (cross-Realm pull + signed reputation) | [`omega_federation_cross_node.rs`](cosmos/sanctum/tests/omega_federation_cross_node.rs) |

The composed `cosmos/sanctum/tests/v0{1,2,3}_end_to_end.rs` stitch the whole thing together. And
because the substrate's *own* organs (transport, registry, the authoring agent, the placement
distributor) are creatures too, an AI can improve the system it runs on, not just the work running on
it: [`hot_swap_organ.rs`](cosmos/sanctum/tests/hot_swap_organ.rs) swaps a bound infrastructure organ
mid-traffic without tearing down the bus.

## Concepts

Four terms carry the rest; the full glossary is [`docs/CONCEPTS.md`](docs/CONCEPTS.md).

- **Creature** — a hot-loadable unit of capability, in one of three tiers (above).
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

- **One substrate, three artifact tiers** — native / WASM / script artifacts load through one
  `Kernel::load` path, differing only by `abi.backend`; trusted compiled-in organs use the privileged
  instance-loading seam and then share the same lifecycle.
- **Safe native hot-unload** — kernel-driven `deregister → drain → engine::unload`, proven over a
  1000-cycle, RSS-stable, ASan-clean reload loop.
- **Proof of trust** — trust primitives ride structurally on every envelope; concrete trust *models*
  are injected, never baked in.
- **Inversion of control** — the kernel ships *sockets and mechanisms*; every *model* (placement,
  policy, fitness, consensus) is an injected creature. This is the thesis — *fabric, not model.*

## Status — what's real, what's not yet

We'd rather you knew exactly where the seams are:

- The **default** reference author is a deterministic **template matcher** (`agent-templated`) —
  hermetic, no network — which proves the author → compile → sign → admit → load *seam*. A real
  **model-backed author** (`agent-mind`) now binds the same `AUTHORING` socket: build with `--features
  openai`, select a model at the operator surface, and a live LLM writes the source.
- Native `daemon` creatures are **trusted-by-admission** (they run in-process). Run untrusted or
  mobile code in the sandboxed WASM `beast` tier or the metered script `critter` tier.
- Alpha is **pre-1.0 with no external security audit**. "An AI ships native code to a peer node" is,
  by design, remote code execution — see [`SECURITY.md`](SECURITY.md).

## Repository map

The root holds the two poles — the **α** door (`alpha/`) and the **Ω** server (`omega/`); everything
*between* them lives under `cosmos/`, so the cosmology is legible from `ls`. Per-crate detail is in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

| Path | What it is |
|---|---|
| `alpha/` | **α — the front door (client).** One binary: `alpha node \| mcp \| http \| demo`, dispatching in-process. |
| `omega/` | **Ω — the federation/gateway server.** One binary: `omega serve` boots a headless gateway Sanctum (transport mesh + registry + `omega-federator` on `Role::OMEGA_GATEWAY`), the dual of `alpha node`. |
| `foundation/{gawdxfer,gawdfn}/` | Shared GAWD contracts Alpha consumes: GX bulk transfer and typed Function/durable Job identities, wires, and proof verification. |
| `cosmos/sigil/` | The at-rest contract — a creature's signed `Manifest` (identity / capabilities / provenance / content address). The sole metadata source. |
| `cosmos/aether/` | The bus spine — typed `Envelope`, `Address`, bounded Router tables, and the bounded metadata journal. `seer` and `abode` are separate first-class concept crates. |
| `cosmos/anima/` | The per-tier loaders — `NativeEngine` (dlopen + safe-unload), `WasmEngine` (wasmtime), `ScriptEngine` (Rhai). |
| `cosmos/sanctum/` | **The kernel** — model-free lifecycle, routing, and admission *mechanism*. Tier-blind. |
| `cosmos/forge/` | The creature-authoring SDK — `declare_creature!`, the bus, managed spawn, the prelude. |
| `cosmos/{abode,seer,realm,bestiary,mind,omega-contract}/` | First-class concept/leaf crates: continuity, query/answer, the trust domain, the durable registry, model injection, and the lean **Ω** wire contract (`omega.deferred` + `GATEWAY_ROLE`; re-exported by the `omega` server). |
| `cosmos/omni/` | The spine-only control core every surface drives over `Role::CONTROL`. |
| `cosmos/creatures/` | Production-capable reference organs: authoring, transport, registry, distributor, federation, Function/Job execution and custody, immune response, … |
| `cosmos/creatures/prototypes/` | Injected, operator-replaceable strategy models (policies, scorers, distributors, gateways) — **not** substrate. |
| `demos/` · `docs/` | Runnable narrated walkthroughs; the prose documentation. |

All three artifact tiers are real: integration tests compile and run WebAssembly inline via
`WasmEngine` and load signed Rhai through `ScriptEngine`, both through the same `Kernel::load` path
as artifact-backed native creatures.

## Build, test, and platform

This first public release is **source-first**: clone the repo and build from the workspace — that's the
whole install. The crates aren't published to a package registry; on Alpha the unit you distribute is
the **creature** (a signed artifact; daemon/beast use `gawd_creature_v1`, critter uses
`gawd_critter_v1`), published and fetched by **content address
between nodes over the bus**, not through a package manager. (The registry that catalogues them — the
*Bestiary* — ships in two forms: an in-memory seed (`registry-mem`) and a **durable, federated,
curator-injected** one (`bestiary-daemon`) — a realm-hashed signed-log store with verifiable entry
proofs and monotonic-lattice replication. Its curator may be deterministic or model-backed; both
fillings use `Role::REGISTRY`.)

```sh
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 cargo build --locked -p alpha -p omega
cargo run   -p alpha -- node                                           # boot a node + REPL (--minimal = bare kernel)
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 cargo test --locked -p sanctum --lib -- --test-threads=1
CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 cargo doc --locked -p sanctum --no-deps --open
```

Use focused package tests while iterating. After freezing the exact candidate, run the authoritative
full workspace gate once locally with `tools/local-validation.sh --exact-commit <40-hex-sha>`.
Hosted GitHub CI is deliberately a short credential-free sanity check, not a second exhaustive run.
Workspace Cargo config defaults to one build job and one libtest
thread. The development/test profiles keep only line-table debug information, disable incremental
artifacts, and use one codegen unit to keep repeat builds responsive and reduce generated volume.
Cargo does not garbage-collect stale target variants; inspect before cleaning, and use the exact
authoring-cache command `cargo clean --target-dir target/gawd-build-cache` only while no authoring
build is active. That generated cache also contains build-cargo's isolated `.cargo-home`, so authored
registry downloads and unpacked dependency sources are covered by the same finite budget and cleanup.
Every Alpha process using that directory takes its retained `.alpha-build-cargo.lock`; contention
polls without spinning and consumes the build timeout, so two local nodes do not compile there at
once. Cargo's own locks still protect cache integrity, but are not the concurrency/resource boundary.
The isolation does not inherit `~/.cargo` configuration, credentials, or warmed registries:
operators that require source replacement, offline builds, or authenticated/private registries must
provision equivalent config/cache inside the budgeted home and inject credentials explicitly.
After a candidate is frozen, an intentional workspace-wide reclaim of generated debug/test output is
`cargo clean --locked --profile dev --dry-run`, followed by the same command without `--dry-run` only
after confirming no Cargo process is active. It leaves `target/release` and all runtime state,
journals, keys, fixtures, and source untouched.

The toolchain is pinned in [`rust-toolchain.toml`](rust-toolchain.toml) (Rust 1.97.1, edition 2021). The
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
| [Demos](demos/) | Narrated, runnable apps — local authoring/hand-off, federation, GX transfer, cross-Realm model collaboration into a typed capability, opt-in live-model Bestiary, and a real cluster runbook |
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
