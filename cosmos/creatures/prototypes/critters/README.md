# Critter examples — the no-compiler on-ramp

Critters are the **script tier**: a creature that ships as a single Rhai source file, runs
on a metered + sandboxed interpreter, and loads through the *same* `Kernel::load` path as a native
`daemon` or a WASM `beast` — with **no build step**. They are the cheapest way to get a working
creature, and the natural target for live authoring (`author --critter …`).

These are worked examples, in rough order of difficulty. Each is one `.rhai` file plus a short README;
every one is compiled + run by [`sanctum/tests/critter_examples.rs`](../../../sanctum/tests/critter_examples.rs),
so this directory doubles as the proof that the Rhai builtins they use actually exist.

| critter | shows | reply |
|---|---|---|
| [`echo-critter`](./echo-critter) | the reference — `env.payload` returned unchanged (start here) | the input, verbatim |
| [`uppercase`](./uppercase) | `env.text` + a string return | upper-cased text |
| [`rot13`](./rot13) | byte arithmetic on `env.payload`; metering-friendly bounded loop | the cipher (its own inverse) |
| [`contains`](./contains) | a stateless predicate over `env.text` + `env.schema` | `"yes"` / `"no"` |
| [`kv-extract`](./kv-extract) | `split` + an object map + the `in` operator | one value by key |
| [`route-by-prefix`](./route-by-prefix) | `emit` — the one outward authority — + the `calls` gate | `()` (re-routes instead) |

The reference echo critter is [`echo-critter`](./echo-critter) above; start there.

## The contract

`fn handle(env)` receives a map and returns a reply:

- `env.payload` — the request bytes (a **Blob**).
- `env.text` — a bounded **lossy UTF-8** preview of the payload (the engine has no Blob→String builtin,
  so this is how a critter does string work; use `env.payload` for full bytes).
- `env.text_truncated` — `true` when `env.text` clipped the payload at the declared/default memory cap
  or the 1 MiB text ceiling.
- `env.schema` — the request's schema tag (a string).
- `env.from` — the sender as an address string (e.g. `"creature:7"`), echo-able straight back to `emit`.
- `env.corr` — an int correlation id, present only on correlated requests.

Return a **Blob or string** to reply; return **`()`** for no reply; call **`emit(addr, blob)`** to send
an extra, capability-gated dispatch (`addr` is `creature:N` / `role:R` / `topic:T` / `intent:X` / `kernel`).

## Three gotchas (learned the hard way)

1. **Stateless per envelope.** Each `handle` call gets a fresh scope — a critter cannot accumulate
   state across messages. Need memory? That's a `daemon`/`beast` concern. (`contains` leans into this.)
2. **`emit` payloads must be Blobs**, and every `emit` still passes the kernel's `calls` gate — a
   critter never holds bus authority itself, it parks dispatches the kernel chooses to route.
   (`route-by-prefix` is the demonstration.)
3. **`env.text` is not the full payload contract.** It is capped before the script runs; string
   critters should check `env.text_truncated` when a partial body would be wrong.
4. **No in-script JSON.** There's no JSON parser in the sandbox — use `split` + a map (`kv-extract`
   shows this). The interpreter *does* cap expression-nesting depth, but the cap is high and **pinned
   identically in debug and release** so a critter that compiles in one profile compiles in the other;
   `rot13` splits its arithmetic into single-op statements for readability and metering granularity,
   not because the one-liner would be rejected.

## Run them

```
cargo test -p sanctum --test critter_examples
```

Or load one live in the daemon: `alpha node` → `load <manifest> <artifact>` (see each critter's README),
or have an agent author the equivalent with `author --critter "…"`.
