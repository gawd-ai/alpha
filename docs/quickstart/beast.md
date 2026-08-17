# Write your first beast (WASM tier)

A **beast** is a WebAssembly creature run on `wasmtime`. It is the **portable, sandboxed** tier: the
right choice for foreign or cross-Realm code, and the only tier with a **byte-exact** linear-memory cap
(plus a fuel/CPU budget). The trade-off is the lowest-level authoring contract of the three tiers — you
speak a small ABI directly. For most work, prefer `critter` (instant) or `daemon` (full Rust); reach for
a beast when you specifically need portability or hard sandboxing.

> **No standalone beast crate ships.** Unlike `echo-daemon`/`echo-critter`, the reference beast is the
> small WAT module compiled inline (via the `wat` crate) in the integration test —
> [`cosmos/sanctum/tests/m0_integration.rs`](../../cosmos/sanctum/tests/m0_integration.rs). That test is the runnable
> reference for this quickstart.

## 1. The ABI

A beast module must export these three things (`cosmos/anima/src/wasm.rs`):

- `memory` — its linear memory.
- `alloc(len: i32) -> i32` — return a pointer to `len` writable bytes (the host writes the request there).
- `handle(ptr: i32, len: i32) -> i64` — read the request bytes at `[ptr, ptr+len)`, write the reply into
  memory, and return the reply as a **packed `i64`: `(out_ptr << 32) | out_len`**.

Manifest: `backend = "beast"` (wasm), `abi_tag = "gawd_creature_v1"` (the same tag native daemons use — the
tier is selected by `backend`, not the tag).

## 2. The reference beast (reverses its payload), in WAT

```wat
(module
  (memory (export "memory") 1)
  (global $bump (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $p i32)
    (local.set $p (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.get $p))
  (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
    (local $out_ptr i32) (local $i i32)
    (local.set $out_ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.set $i (i32.const 0))
    (block $done (loop $copy
      (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
      (i32.store8 (i32.add (local.get $out_ptr) (local.get $i))
        (i32.load8_u (i32.sub (i32.add (local.get $ptr) (local.get $len))
                              (i32.add (local.get $i) (i32.const 1)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $copy)))
    (i64.or (i64.shl (i64.extend_i32_u (local.get $out_ptr)) (i64.const 32))
            (i64.extend_i32_u (local.get $len)))))
```

You normally won't hand-write WAT — compile a guest in any language that targets WASM (Rust with
`--target wasm32-unknown-unknown`, AssemblyScript, …) and export those three symbols. Hand-written WAT is
just the smallest way to *see* the contract.

## 3. Load it

`wat`/your toolchain produces a `.wasm`; load it like any creature:

```
alpha> load path/to/beast-manifest.json path/to/mybeast.wasm
loaded id=9
alpha> send 9 hello
reply: olleh
```

## 4. Containment

The strongest of the three tiers: a per-handle **fuel** budget (`cpu_ms`) and a **byte-exact** linear
memory cap (`mem_bytes`) — a grow past the cap traps and is classified as a budget breach, never silently
swallowed. A workload that must be memory-capped *exactly* belongs here, not in a critter (whose
`mem_bytes` is best-effort). See [the substrate design note](../design/substrate.md) for the tiers and
the capability model.

## Next

What your creature may listen to and emit is the [Topics & SEER contract](../TOPICS.md); the full
manifest field set (and a minimal valid manifest per tier) is in [sigil](../../cosmos/sigil/README.md).
