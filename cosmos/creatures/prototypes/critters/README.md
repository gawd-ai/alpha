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
| [`typed-add-one`](./typed-add-one) | bounded JSON + a typed FunctionResultV1 that preserves AttemptId | `{ "answer": n + 1 }` |

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
- `env.to` — this envelope's local destination, used with `env.from` by proof-bound adapters.
- `env.corr` — an int correlation id, present only on correlated requests.

Return a **Blob or string** to reply; return **`()`** for no reply; call **`emit(addr, blob)`** to send
an extra, capability-gated dispatch (`addr` is `creature:N` / `role:R` / `topic:T` / `intent:X` / `kernel`).
`json_parse(text)` and `json_stringify(value)` provide deterministic, value-only JSON conversion for
typed protocols without adding an authority-bearing host service.
`function_call_verify(text, env.from, env.to)` verifies the Home grant, executor dispatch signature,
and exact local executor/target route before a critter accepts a typed Function call.

## Four gotchas (learned the hard way)

1. **Fresh scope, explicit memory.** Each `handle` call gets fresh local variables. Bounded
   `mem_get` / `mem_set` / `mem_del` state survives for the loaded instance and is dropped on unload;
   `contains` simply chooses to remain stateless.
2. **`emit` payloads must be Blobs**, and every `emit` still passes the kernel's `calls` gate — a
   critter never holds bus authority itself, it parks dispatches the kernel chooses to route.
   (`route-by-prefix` is the demonstration.)
3. **`env.text` is not the full payload contract.** It is capped before the script runs; string
   critters should check `env.text_truncated` when a partial body would be wrong.
4. **JSON is deliberately finite.** `json_parse` / `json_stringify` reject non-JSON Rhai types and
   conversions beyond the effective structural/message cap, 64 nesting levels, or 65,536 values.
   The author gate and runtime register the same helpers. (`kv-extract` still demonstrates when a
   tiny text grammar is cheaper than JSON.)

## Run them

```
cargo test -p sanctum --test critter_examples
```

Or load one live in the daemon: `alpha node` → `load <manifest> <artifact>` (see each critter's README),
or have an agent author the equivalent with `author --critter "…"`.
