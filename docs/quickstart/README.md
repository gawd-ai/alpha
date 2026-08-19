# Quickstarts

Short, task-oriented guides. Two kinds: **run the system** (drive a live node as the operator), and
**write a creature** (author one on each runtime tier).

## Run the system

| Quickstart | Reach for it when… |
|---|---|
| [operator](./operator.md) | you want to **boot a node and play with it** — author code live, watch the sense-tape, then scale up to a small federation of Realms |

The two fastest narrated demos it builds toward live in [`demos/`](../../demos/):
`cargo run -p walkthrough` (one node's whole loop) and `cargo run -p federation`
(many Sanctums across 2–3 Realms over real TCP). `alpha demo list` shows the complete six-entry
registry, including GX transfer, dialogue, the opt-in live-model demo, and the manual cluster runbook.
The v0.5.0 `dialogue --fixture` path is an all-tier regression, not product acceptance.
Acceptance requires a fresh retained three-role live run: four signer-verified causal decisions
approve one bounded affine IR, host validation/trusted lowering produces all three backend Functions,
six Jobs run, and a private evidence directory plus external operator seal bind the exact commit.
The frozen commit first passes the exhaustive local `tools/local-validation.sh` gate and produces its
report plus copied-binary handoff. Push the unchanged commit and require short hosted sanity to pass;
the local `tools/v05-live-acceptance.sh` ceremony then consumes that absolute validation report,
runs the packaged binary's offline verifier, encrypts the raw bundle, and produces a disclosure-safe
pack containing the validation report, exact binary, signed seal/index, acceptance manifest,
six-field verifier report, README, and hashes. The release
operator moves those exact objects
directly to immutable supported-lifetime storage and appends the externally signed acceptance record
before tagging. Hosted CI is required merge/tag hygiene, not the authoritative validation gate, and
receives no keys or raw evidence. See the operator guide for the complete ceremony.
Driving a node *remotely* is in the README quickstart —
[*Drive it over MCP*](../../README.md#4-drive-it-over-mcp) and
[*Drive it over HTTP*](../../README.md#5-drive-it-over-http).

## Write a creature

Artifact-backed creatures in all three tiers load through the *same* `Kernel::load` path and differ
only by `abi.backend`; pick the tier by how much power vs. containment you need:

| Quickstart | Tier | Reach for it when… | Authoring cost |
|---|---|---|---|
| [critter](./critter.md) | script (Rhai) | you want the cheapest creature, or to author live | none — a script string; instant |
| [daemon](./daemon.md) | native (`.so`) | you need full Rust / threads / state and trust the code | a `cargo build` (cdylib) |
| [beast](./beast.md) | WASM (wasmtime) | you need portability or hard sandboxing (byte-exact memory) | in-process WAT → WASM via `BuildBeast`, or an external guest toolchain |

For the deeper "add a creature to the tree" mechanics (crate layout, manifests, tests), see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

> These are deliberately light. When a topic earns thorough documentation it graduates to its own folder
> under `docs/`; until then, the quickstart here is the entry point.
