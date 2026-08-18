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
After exact push CI, the protected release workflow runs the packaged binary's offline verifier,
encrypts the raw bundle, attests a disclosure-safe pack, and uploads 90-day staging artifacts. The
release operator must then promote those exact objects to immutable supported-lifetime storage and
append the externally signed acceptance record before tagging. See the operator guide for the
distinction between this ceremony and local exploration.
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
