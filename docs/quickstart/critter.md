# Write your first critter (script tier)

A **critter** is the cheapest GAWD creature: a single [Rhai](https://rhai.rs) script, no compiler, no
crate. It loads through the same `Kernel::load` path as a native `daemon` or a WASM `beast`,
runs metered + sandboxed, and is the natural target for live authoring. This is the five-minute version;
the worked set with explanations is in [`cosmos/creatures/prototypes/critters`](../../cosmos/creatures/prototypes/critters).

## 1. The contract

Define `fn handle(env)`. It gets a map and returns a reply:

```rhai
fn handle(env) {
    // env.payload — request bytes (a Blob)
    // env.text    — payload as lossy UTF-8 (there is no Blob→String builtin; use this for strings)
    // env.schema  — the request's schema tag (a string)
    // env.from    — sender address string, e.g. "creature:7" (echo-able to emit)
    // env.corr    — int correlation id (only on correlated requests)
    env.text.to_upper()        // return a Blob/string to reply; return () for no reply
}
```

That's a complete request→reply creature. To send elsewhere instead of (or as well as) replying, call
`emit(addr, blob)` where `addr` is `creature:N` / `role:R` / `topic:T` / `intent:X` / `kernel` — each
`emit` passes the kernel's `calls` capability gate.

## 2. Two ways to run it

**Author it live (no files).** Start the daemon and ask for one in plain language — an agent picks a
template, `build-critter` signs it (no cargo), and it hot-loads:

```
$ cargo run -p alpha -- node
alpha> author --critter uppercase the message
✓ authored → signed → admitted → hot-loaded critter as id=7 (no compiler). Try: send 7 <text>
alpha> send 7 hello, world!
reply: HELLO, WORLD!
```

**Load a `.rhai` you wrote.** Save your script, hand the daemon a manifest + the source bytes:

```
alpha> load path/to/manifest.json path/to/mycritter.rhai
loaded id=8
alpha> send 8 hello
```

(A test or host can skip the manifest file: `kernel.load(critter_manifest("x"), Artifact::Bytes(src))`
— see [`cosmos/sanctum/tests/critter_examples.rs`](../../cosmos/sanctum/tests/critter_examples.rs).)

## 3. Three things that will bite you

1. **Stateless per envelope.** Each call gets a fresh scope — no state survives between messages.
2. **`emit` payloads are Blobs**, and `emit` is `calls`-gated — the script never holds bus authority.
3. **No in-script JSON.** Use `split` + an object map instead. (The interpreter caps expression-nesting
   depth, but the cap is high and pinned identically in debug and release; `rot13` assigns step by step
   for readability and metering, not because the one-liner would be rejected.)

## 4. Containment

The engine is bare by construction: no filesystem, network, clock, process, or rand. `cpu_ms` becomes
an operation budget (the critter analog of WASM fuel); a breach is a structured budget signal, never a
hang. `mem_bytes` maps to best-effort structural caps. See [the substrate design note](../design/substrate.md).

## Next

What your creature may listen to and emit is the [Topics & SEER contract](../TOPICS.md); the full
manifest field set (and a minimal valid manifest per tier) is in [sigil](../../cosmos/sigil/README.md).
