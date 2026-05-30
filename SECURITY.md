# Security Policy

## Project maturity — read this first

Alpha is a **pre-1.0 research substrate** at walking-skeleton maturity. It is built around a
deliberate, explicit security model (below), but it has **not** been through an external audit and
is **not** hardened for hostile production deployment. Treat it accordingly:

- Run **untrusted or foreign code only in a sandboxed tier**: `beast` (WASM) when you need byte-exact
  memory limits, or `critter` (script) when Rhai's structural memory caps are enough. The substrate
  can verify and policy-gate a native artifact, but native is not a sandbox; do not configure policy
  to admit foreign native artifacts unless you are willing to trust them as host code.
- The native `daemon` tier is **trusted-by-admission**: in-process native code cannot be fully
  contained, so you load only native creatures you vouch for. This is a stated limit, not a bug.
- The `critter` (script) tier is a **sandboxed Rhai interpreter**: contained by
  construction (no filesystem/network/clock/rand; one capability-gated `emit`) and metered by a
  per-envelope **operation budget** (`cpu_ms`). One honest limit: `mem_bytes` is **best-effort**
  (Rhai structural caps), not the byte-exact memory limiter the `beast` tier has — a critter that
  must be memory-capped exactly should run as a beast.

## The control plane (HTTP/WS + MCP surfaces)

`alpha node` can expose an HTTP + WebSocket control plane (`--listen`, the loadable `surface-http`
creature), and `alpha mcp` runs the MCP control-hub; both drive the node's `Role::CONTROL` over the bus.
This surface **can author and hot-load native code**, so treat it as privileged:

- **Off by default.** No API exists unless you pass `--listen <addr>` (which has no default). Bind a
  **localhost** address (e.g. `127.0.0.1:7777`) to keep it host-local; exposing it beyond the host
  means binding a routable address explicitly or fronting it with a reverse proxy — there is **no TLS
  termination in `alpha node`** (a reverse proxy's job).
- **Bearer auth, constant-time compare.** One key, from `--api-key` / `SANCTUM_API_KEY` /
  auto-generated + printed once at boot. There is **no per-identity or per-role auth** — one key, one
  trust level. Only `GET /api/health` is unauthenticated; `/api/ws` uses `?token=` because browser
  WebSocket upgrades cannot set `Authorization`.
- **Allow-AI gate, off by default.** A remote front-end (MCP/HTTP) cannot run a *mutating* verb until
  a human grants it at the local REPL (`allow-ai on`) or at boot (`--allow-ai`). Read-only HTTP verbs
  still require the Bearer key; read-only MCP tools require access to the spawned hub and, in remote
  mode, its mesh identity. Neither read path is blocked by the allow-AI gate; the local REPL is never
  gated; the gate is node-level, not per-creature.
- **DEV posture is disclosed, not assumed away.** The boot banner, the MCP `serverInfo`/instructions,
  and this file all state that the bundled dev policy admits everything and the bus signer is a stub.
  This is a single-node developer surface, not a hardened multi-tenant deployment.

## Supported versions

| Version | Supported          |
|---------|--------------------|
| 0.4.x   | :white_check_mark: |
| < 0.4   | :x:                |

Only the latest minor release receives security fixes while the project is pre-1.0.

## Reporting a vulnerability

**Please do not open a public issue for a security vulnerability.**

Report it privately by email to **hello@gawd.ai**. Include:

- a description of the issue and the component (`aether`, `sanctum`, `anima`, a transport or
  registry creature, …);
- steps to reproduce, ideally a minimal test or envelope/manifest that triggers it;
- the impact you believe it has against the model below.

You can expect an acknowledgement within a few days. Coordinated disclosure is appreciated — we will
work with you on a fix and a disclosure timeline before any public write-up.

## The security model (what counts as a vulnerability)

Alpha's substrate "takes no side among the players" — it does not adjudicate whether creatures lie,
collude, or act at random; that is left to selection (the immune loop). **But the board must not be
flippable.** Two bounds are mandatory and always-on:

- **The fabric-integrity floor (R9).** No creature may crash, hang, OOM, deadlock, or corrupt the
  kernel, the bus, or another creature's isolation *through the fabric's own surfaces*. Enforced by
  construction: bounded inboxes with backpressure, no-trust parsing of every envelope/manifest
  (malformed input errors, never panics the kernel), and creature-fault isolation (a panic in
  `handle` is caught at the boundary and routed to that creature's unload, never fatal to the node).
- **The life-safety floor.** The substrate must not be hostile to human/earthly life.

A reproducible way to make the **kernel or bus** panic, hang, leak unboundedly, or violate another
creature's isolation from *within the fabric's surfaces* (a crafted envelope, manifest, or a
sandboxed beast escaping its limits) is a **vulnerability** — report it.

What is **out of scope** (by design, not by oversight):
- A native `daemon` doing harm — native is trusted-by-admission (see above).
- Creatures deceiving or out-competing each other at the application level — that is the arms race
  the immune and selection loops exist for, not a fabric flaw.

The model is specified in the design notes: the capability & sandbox model in
[the substrate note](docs/design/substrate.md), and the proof-of-trust primitives and
taking-no-side stance in [the addressing, placement & federation note](docs/design/addressing-placement-federation.md).
