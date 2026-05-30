# The substrate: creatures, the ABI, and the tiers

A sanctum's unit of capability is a **creature** — a loadable, addressable, evictable thing that
holds a body of behavior. Everything that does work in GAWD is a creature: a policy, a gateway, a
distributor, an authoring agent, an echo. A creature is admitted from a signed manifest, bound to
the bus (`aether`), driven by one drain thread, and unloaded on demand. The substrate is the
machinery that loads, runs, contains, and tears down creatures — and it does so across three
execution tiers behind one path.

## Three tiers, one load path

A creature runs in one of three tiers, selected by a single manifest field (`abi.backend`). The
kernel holds one `Engine` per tier and keys it by that field, so every tier loads through the *same*
`Kernel::load` → `Engine::load` → `bind` → `handle` → `unload` lifecycle. The tiers differ only in
what executes the bytes and in how much they confine by nature.

- **daemon** — a native `.so`, loaded via `dlopen`. The trusted, local, performance core: full host
  access, native speed, the richest expressiveness. A daemon is **trusted-by-admission** — the
  substrate cannot fully contain malicious in-process native code, so foreign or mobile code never
  arrives as a daemon. You load native code you vouch for.

- **beast** — WASM, run on `wasmtime`. Portable bytecode that runs unchanged on a server, an ARM
  robot, or a satellite. A beast is **isolated by construction**: it has no host imports, so it
  reaches no filesystem, network, or syscall — it sees only bytes in its own linear memory. This is
  the home of untrusted, mobile, foreign code. An artifact arriving over the wire lands as a beast.

- **critter** — a Rhai script, run by a metered, sandboxed interpreter. The cheapest, most ephemeral
  tier: no compile step, portable source text, sub-millisecond authoring. Ideal for high-variation
  experiments and glue. A critter is **contained by construction** like a beast — the bare engine
  reaches nothing — at the cost of tree-walked interpretation, so hot paths stay native or WASM.

The tiers are concentric in confinement (daemon ⊃ beast ⊃ critter) but the substrate does **not**
pick a tier *for* the operator to enforce containment. Which tier to use, and whether to sandbox at
all, is the operator's self-determined call. The same declared capabilities can ship as a daemon or
a beast; the tier is the containment choice, the manifest is the description.

## The ABI

A native creature and the host meet at a single C boundary, and **only POD crosses** it — integers,
raw pointers, and a vtable of `extern "C"` function pointers. No Rust trait object, `Box<dyn _>`, or
non-`repr(C)` type ever crosses. Envelopes and dispatches cross as serialized bytes (pointer + len),
so the creature holds no Rust pointer into host types and the host holds only an opaque vtable into
the creature. That bytes-only seam is exactly what makes unload clean: run the creature's `destroy`,
then `dlclose`, with nothing dangling across the boundary.

**The ABI tag** is `gawd_creature_v1` for native and beast; the critter tier carries its own tag,
`gawd_critter_v1`, because a Rhai bump that changes operation accounting (and thus determinism and
content-addressing) would bump it to `v2` independently. A manifest declares its tag in `abi.abi_tag`,
and a mismatch is rejected at load — before any symbol is called or any source is parsed.

**The native constructor** is one exported symbol, `gawd_creature_v1` — `extern "C" fn() -> *mut
CreatureVTableV1`. The loader looks it up, calls it (inside `catch_unwind`, because a panic across
the C ABI is undefined behavior), null-checks the returned vtable, and wraps it. The vtable is POD:

```
#[repr(C)] struct CreatureVTableV1 {
    data:     *mut c_void,                                          // creature's erased state
    bind:     extern "C" fn(data, ctx: *const BindCtxFfi),          // hand over id + manifest + send
    handle:   extern "C" fn(data, env_ptr, env_len) -> i32,         // one envelope in, rc out
    shutdown: extern "C" fn(data, deadline_ms),                     // drain within a deadline
    destroy:  extern "C" fn(data),                                  // free creature state
}
```

A creature's only outward authority is a `send` callback handed to it at `bind` inside `BindCtxFfi`
— there is no ambient global. The creature serializes a `Dispatch` and calls `send`; the host
deserializes it and routes it through the one gated bus path. Distinct `RC_*` return codes carry the
failure shape back (backpressure, no-such-creature, denied, …) so a creature can act on each, and
`RC_PANIC` lets the host detect that a creature unwound inside its own glue and pull it off the bus
rather than treat the call as success.

Authors never write the vtable. They write a Rust type, `impl Creature for It`, and call
`forge::declare_creature!(It)` once; the macro emits the constructor and the glue that bridges the C
boundary to the typed `bind`/`handle`/`shutdown`. **Every glue function catches panics** before
returning across `extern "C"` — the fabric-integrity floor for the FFI seam. A beast or critter
needs no such macro: a beast exports `memory` + `alloc` + `handle`, and a critter defines
`fn handle(env)` in source.

## The signed manifest

A creature at rest or in transit is described by a **manifest** — the sole metadata and permission
source. There is no parallel permission system, no sidecar policy file, no env-var override at admit.
The manifest carries:

- **identity** — `name`, `version`, and the `abi` block (backend, abi_tag, and an opaque, open-ended
  `target` the substrate assigns no meaning to — an injected matcher weighs it against a node's
  advertised embodiment).
- **`entrypoints`** — typed descriptors an authoring agent generates against.
- **`capabilities`** — `fs`, `net`, `cpu_ms`, `mem_bytes`, and `calls` (the bus-level send
  allowlist), plus an opt-in `budget_warn_at` advisory threshold.
- **`requirements`** — what a host must offer (accelerators, sensors, memory, connectivity,
  jurisdiction) for placement.
- **`provides`** — which inversion-of-control roles the creature can fill, for binding into a socket.
- **`provenance`** — the author's Abode key, source and build hashes, an optional Realm assertion,
  and the signature.
- **`content_address`** — a portable `sha256:` identity for *this manifest*.

**What the manifest binds.** The `content_address` is a hash over the whole manifest body with the
volatile fields (the signature and the address itself) cleared — so two creatures with identical
artifact bytes but different capabilities, provides, entrypoints, or requirements get **distinct**
addresses. The address names "what manifest is this," not "what bytes ran"; without that, federation
cannot tell a benign manifest from a hostile one carrying the same payload. The **signature** commits
to the manifest with only its own signature field cleared — which means the `content_address` rides
*inside* the signed bytes. An author therefore sets the content address **before** signing, or a
receiver recomputing the signing payload sees a different (or absent) address and the signature
mismatches. A declared Realm rides inside the signed payload too, so a peer can refuse manifests that
don't claim the Realm it expects.

Field order is part of the signed wire format: serde emits struct fields in declaration order, so
appending an optional field is additive but reordering or renaming one invalidates signed manifests
in flight. Byte-stability tripwire tests lock both the signing payload and the identity payload to
known fixtures to catch silent drift.

Verification is a **mechanism** the substrate ships (ed25519 over the signing payload); *which* keys
are trust roots is an injected policy, never defined in the contract. Admission gathers evidence —
signature validity, content-address self-consistency, structural validity — and an injected `Policy`
decides whether to admit. Parsing never panics on hostile input: malformed bytes become a structured
error.

## Safe unload

Unloading a native `.so` while any function pointer, `&'static`, or spawned thread originating from
it is still live is undefined behavior — Rust's guarantees stop at the `dlopen` boundary. The
substrate solves this per tier, and the discipline is the load-bearing part of the native story.

**The drop order is fixed and singular.** `Engine::unload` runs `shutdown` within a deadline, then
drops the **instance** (the native `destroy` runs while the library is still mapped), then drops the
**resources** (`dlclose` runs **last**). The same order is encoded structurally: `LoadedModule`
declares `instance` before `resources`, and struct fields drop in declaration order, so even an
implicit drop tears down in the right sequence. When a native artifact arrived as in-memory bytes,
the resources also hold a tempfile guard that unlinks the spilled `.so` *after* the library unmaps —
declared after the library, so it drops second.

**Creatures do no self-teardown.** The kernel owns the drain. Unload deregisters the creature from
the router (no new envelopes reach it), the drain thread reads the disconnect, the creature's
`shutdown` runs, and then the kernel drives the drop sequence. This inverts the naive
"creature cleans up after itself" model: the substrate, not the creature, decides when teardown
happens.

**The thread-join barrier is in the SDK.** A native creature that spawns a thread must use
`forge::spawn`, which registers the thread into the creature's managed set. The SDK's `shutdown`
joins every registered thread **before** returning to the host — so the drain proceeds to `dlclose`
only after every disciplined thread is reaped. A thread that outlives `dlclose` would dereference
now-unmapped code through a dangling vtable: the canonical native-unload use-after-free. The SDK
ships a *discipline*, not a contract — `forge::spawn` is the right path; a raw `std::thread::spawn`
is documented as "you're on your own."

**The kernel's thread-count guard is the floor.** A creature that bypasses the discipline (a raw or
detached thread) is caught by a `/proc/self/task` snapshot diff — tids before `bind` versus after
`shutdown`. When the guard fires, the kernel **leaks the resources**: it `Box::leak`s the `Library`
so the `.so` stays mapped, the runaway thread keeps dereferencing live code, and the proprioception
bus publishes `unload_leaked_resources`. This is a **bounded leak — one library per misbehavior, and
never a use-after-free.** A healthy creature beside the offender keeps serving and unloads normally.

**The unload deadline is real.** `Kernel::unload` waits on a per-drain signal channel; on timeout it
abandons the drain detached and returns `UnloadTimeout`. The substrate never hangs on a misbehaving
creature — the thread-count guard's bounded leak is the safety net for the abandoned drain. Creatures
unload in reverse-chronological order so a still-running neighbor's threads aren't misread as leaked.

**Beast and critter unload trivially.** A beast's unload drops the `wasmtime` store; linear memory,
tables, and instances all vanish atomically — there is no native UB class. A critter's teardown drops
the Rhai engine, AST, scope, and outbox together. The same kernel drop ordering applies, but the
hard problem only exists for native.

## Capabilities and the sandbox

GAWD's stance on containment is deliberate: the substrate **does not impose** a sandbox or a
capability cage. Its job is to make strong containment *available and effective*; whether and how
tightly to use it is the operator's choice and responsibility. Freedom is the default; defense is
chosen, and — when it proves out — promoted into shared instinct by the collective. A cage imposed
once is studied once; an immune system the mesh evolves keeps adapting. The architectural correlate:
the substrate ships the *mechanism* (the gate, the evidence, the signal); every *model* of trust or
response is an injected creature, swappable per operator and per Realm.

The capability vocabulary is the manifest's `capabilities` block, declared once by the author.
Enforcement is per tier:

| Field | Beast | Critter | Daemon |
|---|---|---|---|
| `fs`, `net` | Closed by construction — no host imports, no FS or net to reach. | Closed by construction — the bare engine reaches nothing; `import` and `eval` are removed. | Trusted-by-admission. The declarations are evidence an injected policy reads at admit; OS-level confinement is the operator's deployment seam. |
| `cpu_ms` | `wasmtime` fuel, refilled per envelope. | A Rhai **operation budget** (`set_max_operations`), refilled per envelope. | Read at admit; not metered at runtime. |
| `mem_bytes` | A custom `ResourceLimiter` refuses growth past the cap — byte-exact. | Rhai's structural caps (string/array/map size) — **best-effort counts, not bytes**, with an always-on backstop. | Read at admit; the operator's OS-level seam. |
| `calls` | Router-side allowlist at the one bus choke point; a disallowed envelope is never delivered. Empty = unrestricted. | Same router gate. | Same router gate. |

**Beast and critter have teeth.** A beast that declares a host import fails to instantiate, so
`net:none` and `fs:[]` are properties of the loader, not runtime checks. Its `cpu_ms` is real fuel
and its `mem_bytes` is a real byte-exact cap. A critter is contained the same way — its one host
function, `emit`, only parks a dispatch the kernel routes through the gated bus path; it holds no bus
authority itself, and `no_module` plus a disabled `eval` make it exactly its signed, static source.
Its `cpu_ms` is a real operation budget; its `mem_bytes` is honestly best-effort (structural counts,
with a bounded default backstop so one bulk-allocating builtin can't OOM the host).

**The daemon stays honest about its limits.** The substrate does not pretend to confine in-process
native code mid-flight. The capability declarations are evidence an injected admission policy reads —
a policy can demand `net:none` and refuse any daemon that declares otherwise, or compose
signed-provenance + net-restriction + author-allowlist + any custom rule. OS-level confinement
(bwrap, firejail, seccomp, cgroups) is the operator's deployment decision, applied to the sanctum
process, not a per-creature cage the kernel fakes.

**Budgets are observed, never judged, by the substrate.** When an engine detects pressure — fuel or
operation exhaustion, a refused grow, a crossed warning threshold — it surfaces a `BudgetSignal`
(`Hard` on a terminal breach, `Warn` alongside an otherwise-successful reply) on the creature's
outcome. The kernel publishes it as an event on the proprioception topic; it **never** decides that a
breach is fatal. An **injected** policy creature subscribes, parses the signal, and decides: unload,
observe, demote, escalate to a human, or grant grace. The kill rule, the grace period, the
escalation — all live outside the kernel. Swap the rule by swapping the creature; no kernel rebuild.

**The control surface is one socket.** The kernel address is a live destination served by a
dispatcher that drains kernel-addressed envelopes and executes `KernelControl` ops. `Unload` runs
the same safe-unload path any explicit unload uses. `ExtendBudget` lifts a creature's live per-handle
fuel or operation ceiling — a lock-free atomic the engine shares with the running instance, read
fresh each `handle`, so a granted lift takes effect on the very next envelope without reaching into a
creature on its own drain thread. A native creature exposes no such ceiling, so a grant to it is an
honest no-op the kernel reports rather than a silent lie. The control enum is tagged so future ops
land additively; a malformed payload is skipped, never a panic.
