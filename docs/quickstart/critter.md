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
    // env.text    — bounded lossy UTF-8 preview (use env.payload for full bytes)
    // env.text_truncated — true when env.text clipped the payload
    // env.schema  — the request's schema tag (a string)
    // env.from    — sender address string, e.g. "creature:7" (echo-able to emit)
    // env.to      — this envelope's local destination address
    // env.corr    — int correlation id (only on correlated requests)
    env.text.to_upper()        // return a Blob/string to reply; return () for no reply
}
```

That's a complete request→reply creature. To send elsewhere instead of (or as well as) replying, call
`emit(addr, blob)` where `addr` is `creature:N` / `role:R` / `topic:T` / `intent:X` / `kernel` — each
`emit` passes the kernel's `calls` capability gate.

Typed JSON protocols use two pure helpers: `json_parse(text)` returns Rhai maps/arrays/scalars and
`json_stringify(value)` returns deterministic compact JSON text. For example, a Function critter can
first require `function_call_verify(env.text, env.from, env.to)`, then parse `env.text`, compute a
value, copy `message["call"].attempt` into its result, and stringify a `gawd.function.call.v1` reply.
The verifier checks the Home grant, executor dispatch signature, and exact local route; it exposes no
key or policy authority. See
[`typed-add-one`](../../cosmos/creatures/prototypes/critters/typed-add-one).
That checked-in source is also the typed causal-child target in the real two-process TRD-006 proof; it
is signed, loaded through `Kernel::load`, independently measured, registered, and invoked through the
ordinary `ScriptEngine`. The proof's parent progress and Steer outcome come from a separate blocking
daemon fixture, not from this critter.

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

## 3. Four things that will bite you

1. **Fresh scope, explicit memory.** Local variables reset each call. Use bounded `mem_get`,
   `mem_set`, and `mem_del` for state that survives for this loaded instance; it is dropped on unload.
2. **`emit` payloads are Blobs**, and `emit` is `calls`-gated — the script never holds bus authority.
3. **`env.text` is a preview.** It is bounded by the declared/default memory cap and a 1 MiB ceiling;
   check `env.text_truncated` when partial text is not acceptable.
4. **JSON is bounded and value-only.** `json_parse` / `json_stringify` accept JSON-compatible values,
   not Blobs or host objects. Each conversion is capped by `mem_bytes` (or the default structural
   cap), a 1 MiB ceiling, 64 nesting levels, and 65,536 values. An over-cap or invalid conversion is a
   script error and emits no partial reply.

## 4. Containment

The engine is bare by construction: no filesystem, network, script-visible clock, process, or rand.
`cpu_ms` becomes an operation budget (the critter analog of WASM fuel), and `wall_ms` a live
progress-hook deadline; a breach is a structured budget signal, never a hang. `mem_bytes` maps to
best-effort structural caps. The JSON helpers only transform bounded in-memory values; they add no
ambient authority. See [the substrate design note](../design/substrate.md).

## Next

What your creature may listen to and emit is the [Topics & SEER contract](../TOPICS.md); the full
manifest field set (and a minimal valid manifest per tier) is in [sigil](../../cosmos/sigil/README.md).
