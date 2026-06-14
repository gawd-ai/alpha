# Write your first daemon (native tier)

A **daemon** is a native Rust creature compiled to a `cdylib` (`.so`) and `dlopen`'d into the node. It
is the most capable tier (full Rust, real threads) and the fastest — and, by the same token, the least
contained: native code runs **in-process**, so the daemon tier is **trusted-by-admission** (you load
only native creatures you vouch for). Reach for `critter` or `beast` when you need to run code you don't
fully trust.

## 1. The contract

Write a Rust type, `impl Creature` for it, derive `Default`, and call `declare_creature!` — the
macro hides the entire POD-only `extern "C"` FFI seam. This is the whole of `cosmos/creatures/prototypes/fixtures/echo-daemon`:

```rust
use forge::prelude::*;

#[derive(Default)]
pub struct EchoDaemon;

impl Creature for EchoDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {}            // wire-up; keep a NativeBus handle here if you emit

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)                 // or Outcome::send(Dispatch…) / Outcome::none()
    }
}

forge::declare_creature!(EchoDaemon);
```

Unlike a critter, a daemon **may hold state** across envelopes (`&mut self`) and spawn threads (use the
SDK's managed `spawn` so they join cleanly on unload).

## 2. Build + load it

It's a normal crate with `crate-type = ["cdylib"]` depending on `forge`; `cargo build` produces a
`.so`. Then hand the daemon a manifest (`backend = "daemon"`, `abi_tag = "gawd_creature_v1"`) + the `.so`:

```
alpha> load path/to/manifest.json target/debug/libmycreature.so
loaded id=5
alpha> send 5 hello
reply: olleh
```

The crate scaffolding (Cargo.toml, the manifest fields, the build invocation) is in
[`CONTRIBUTING.md` → "Add a creature (native daemon)"](../../CONTRIBUTING.md). For the **live** path,
`alpha> author <request>` has an agent write a daemon, then `cargo build` + sign + admit + hot-load
it (a cold build takes a minute or two — prefer `author --critter` for an instant creature). The
default agent is a keyword template matcher (a request containing `reverse`); build with
`--features openai` and select a model for free-form English authoring.

## 3. Containment

Native is **not a sandbox** — there is no fuel or memory cap on a daemon (those are the `beast`/`critter`
tiers). The kernel still gives you orderly lifecycle (load → drain → unload), `catch_unwind` at the FFI
boundary so a panicking `handle` unloads rather than crashes the node, and the `calls` capability gate on
anything it emits. But you are trusting the code itself. See [`SECURITY.md`](../../SECURITY.md) and
[the substrate design note](../design/substrate.md) for the capability model.

## Next

What your creature may listen to and emit is the [Topics & SEER contract](../TOPICS.md); the full
manifest field set (and a minimal valid manifest per tier) is in [sigil](../../cosmos/sigil/README.md).
