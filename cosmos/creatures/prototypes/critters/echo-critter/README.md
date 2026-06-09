# echo-critter — reference critter (script tier)

The script-tier reference creature: the [`Backend::Critter`] analog of the native
[`echo-daemon`](../../fixtures/echo-daemon) and the WASM reverse-beast. It is a single Rhai source file
([`echo.rhai`](./echo.rhai)) — **not** a Cargo crate, because a critter ships as UTF-8 source text,
not a compiled artifact. There is nothing to build.

```rhai
fn handle(env) { env.payload }
```

## Loading one

A critter is admitted and run through the *same* `Kernel::load` path as every other tier; only the
manifest's `abi.backend` (and the `gawd_critter_v1` ABI tag) select the Rhai engine. In a test or a
host, load it directly from bytes:

```rust
let src = std::fs::read("cosmos/creatures/prototypes/critters/echo-critter/echo.rhai")?;
kernel.load(critter_manifest(), Artifact::Bytes(src))?;
```

Or author one live (no cargo) through `Role::BUILD` with the `build-critter` creature — see
`walkthrough` for the narrated author → sign → load → run loop.

## The contract

`fn handle(env)` receives a map (`env.payload` Blob, `env.text` a bounded lossy UTF-8 preview,
`env.text_truncated` when that preview clipped the body, `env.schema`, `env.from`, `env.corr`) and:

- **returns a Blob or string** (or any other non-unit value, best-effort stringified) → the engine
  replies to the envelope's reply target;
- **returns `()`** → no reply;
- **calls `emit(addr, bytes)`** → an extra, capability-gated dispatch the kernel routes, where
  `addr` is `creature:N` / `role:R` / `topic:T` / `intent:X` / `kernel`.

## Containment & budget

(For the tiers, the capability model, and limits-as-gradients see
[the substrate design note](../../../../../docs/design/substrate.md) and
[CONCEPTS](../../../../../docs/CONCEPTS.md).)

The engine is **bare by construction**: no filesystem, network, clock (`no_time`), process, or rand —
the only host function is `emit`, and its dispatches still pass the router's `calls` gate. The script
is **metered**: `capabilities.cpu_ms` becomes an operation budget (the critter analog of wasm fuel),
refilled per envelope from a live ceiling a `KernelControl::ExtendBudget` grant can lift; a breach is
a structured `Hard`/`Fuel` budget signal, never a hang or a panic. `mem_bytes` maps to best-effort
structural caps (string/array/map size), **not** the byte-exact limiter the beast tier has.
