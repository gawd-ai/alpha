# Quickstarts

Short, task-oriented guides. Two kinds: **run the system** (drive a live node as the operator), and
**write a creature** (author one on each runtime tier).

## Run the system

| Quickstart | Reach for it when… |
|---|---|
| [operator](./operator.md) | you want to **boot a node and play with it** — author code live, watch the sense-tape, then scale up to a small federation of Realms |

The runnable, narrated demos it builds toward live in [`demos/`](../../demos/):
`cargo run -p walkthrough` (one node's whole loop) and `cargo run -p federation`
(many Sanctums across 2–3 Realms over real TCP). Driving a node *remotely* over the HTTP API or MCP is
in the README's [*Drive a node remotely*](../../README.md) section.

## Write a creature

All three tiers load through the *same* `Kernel::load` path and differ only by `abi.backend`; pick the
tier by how much power vs. containment you need:

| Quickstart | Tier | Reach for it when… | Authoring cost |
|---|---|---|---|
| [critter](./critter.md) | script (Rhai) | you want the cheapest creature, or to author live | none — a script string; instant |
| [daemon](./daemon.md) | native (`.so`) | you need full Rust / threads / state and trust the code | a `cargo build` (cdylib) |
| [beast](./beast.md) | WASM (wasmtime) | you need portability or hard sandboxing (byte-exact memory) | compile a guest to `.wasm` |

For the deeper "add a creature to the tree" mechanics (crate layout, manifests, tests), see
[`CONTRIBUTING.md`](../../CONTRIBUTING.md).

> These are deliberately light. When a topic earns thorough documentation it graduates to its own folder
> under `docs/`; until then, the quickstart here is the entry point.
