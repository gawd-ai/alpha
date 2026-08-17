# The substrate: creatures, the ABI, and the tiers

A sanctum's unit of capability is a **creature** — a loadable, addressable, evictable thing that
holds a body of behavior. Everything that does work in GAWD is a creature: a policy, a gateway, a
distributor, an authoring agent, an echo. A creature is admitted from a manifest plus the evidence
available at its load boundary (signature requirements are injected policy), bound to the bus
(`aether`), driven by one drain thread, and unloaded on demand. The substrate is the
machinery that loads, runs, contains, and tears down creatures — and it does so across three
execution tiers behind one path.

## Three tiers, one load path

A creature runs in one of three tiers, selected by a single manifest field (`abi.backend`). The
kernel holds one `Engine` per tier and keys it by that field, so every tier loads through the *same*
`Kernel::load` → `Engine::load` → `bind` → `handle` → `unload` lifecycle. The tiers differ only in
what executes the bytes and in how much they confine by nature.

- **daemon** — a native `.so`, loaded via `dlopen`. The trusted, local, performance core: full host
  access, native speed, the richest expressiveness. A daemon is **trusted-by-admission** — the
  substrate cannot fully contain malicious in-process native code, so an operator **must not admit**
  foreign or mobile code as a daemon. The wire preserves a manifest's declared tier; it does not
  rewrite an unsafe native artifact into a safer backend. Load native code only when you vouch for it.

- **beast** — WASM, run on `wasmtime`. Portable bytecode that runs unchanged on a server, an ARM
  robot, or a satellite. A beast is **isolated by construction**: it has no host imports, so it
  reaches no filesystem, network, or syscall — it sees only bytes in its own linear memory. This is
  the required home for untrusted, mobile, foreign compiled code; admission policy must enforce that
  posture because fetch/load preserves the manifest backend.

- **critter** — a Rhai script, run by a metered, sandboxed interpreter. The cheapest, most ephemeral
  tier: no compile step, portable source text, sub-millisecond authoring. Ideal for high-variation
  experiments and glue. A critter is **contained by construction** like a beast — the bare engine
  reaches nothing — at the cost of tree-walked interpretation, so hot paths stay native or WASM.

The tiers are concentric in confinement (daemon ⊃ beast ⊃ critter) but the substrate does **not**
pick a tier *for* the operator to enforce containment. Which tier to use, and whether to sandbox at
all, is the operator's self-determined call. The same declared capabilities can ship as a daemon or
a beast; the tier is the containment choice, the manifest is the description.

Alpha builds Wasmtime with default features off and only its `cranelift` + `runtime` surfaces. In
particular, the optional `parallel-compilation`/Rayon pool is absent, so a module compile cannot fan
out behind Cargo's one-job resource boundary. The engine still spells
`Config::parallel_compilation(false)` through a compatibility seam: if another dependency ever
unifies that optional Wasmtime feature, the inherent setter takes over and disables the pool before
engine construction. A source/lockfile guard fails CI if the lean declaration or no-Rayon invariant
drifts.

Artifacts that a tier must materialize as bytes are capped at 128 MiB at the `anima::Artifact`
reader boundary. That covers beast/critter path loads, in-memory artifact loads before WASM
compile or Rhai UTF-8 parsing, and wire-shipped native `.so` bytes. A beast/critter path is opened
once into bounded bytes before admission; its engine receives those same bytes, not a pathname it
can reopen later.

Every native load likewise uses one retained stage. A local source path is opened once and streamed
with O(1) memory while hashing each written chunk; native `Artifact::Bytes` uses the same primitive
after its 128 MiB cap. On Linux/Android the stage is an anonymous memfd. Alpha closes the duplicate
writer, applies the kernel's write/grow/shrink/further-seal seals, re-hashes the sealed bytes and
requires that digest to equal the streaming digest, then admits and `dlopen`s a process-unique
spelling of its retained `/proc/self/fd` capability. The unique spelling prevents loader pathname
cache collisions when the kernel reuses a numeric fd; it is made only from kernel-resolved `.` and
`..` components, not a mutable symlink. Seal or `/proc` capability failure is fail-closed. The memfd
stays retained through `dlclose`, and the deliberate native leak path retains it with the library.

Other platforms use a 128-bit OS-random, `create_new` private directory and read-only staged file.
Unix fallbacks set directory mode 0700 and file mode 0400; non-Unix targets make no ACL-hardening
claim. This closes the ordinary operator source-path swap because the source is no longer reopened,
but it is explicitly not Linux-equivalent immutability: the same OS identity may be able to restore
write permission between admission and load. The fallback is defense in depth, not a containment
boundary against code already running as the node's user.

Staging has a real native compatibility cost. The loaded object's pathname—and therefore ELF
`$ORIGIN`—is the descriptor pseudo-directory on Linux/Android or the random staging directory on
other targets, never the operator's source directory. Alpha does not copy adjacent private libraries
there. A daemon whose `DT_NEEDED` entries depend on
`$ORIGIN`/sibling `.so` files will therefore fail to load unless those dependencies are available by
another reviewed loader path (for example a system/absolute rpath), or are linked into the daemon.
Code that inspects its own module pathname or relies on pathname-based `dlopen` coalescing likewise
sees a unique staged path. Staging copies the artifact once when the capability is prepared; sealed
stage clones may be reused safely across reloads. Non-Linux fallbacks require the platform temporary
directory to permit executable mappings (`noexec` can reject a load); hardened Linux memfd execution
policy can also reject loading. These tradeoffs are intentional: exact admitted-byte identity takes
priority over preserving mutable source-path behavior.

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
rejects oversized serialized dispatch bytes before building a slice or deserializing, then routes
valid dispatches through the one gated bus path. Distinct `RC_*` return codes carry the failure shape
back (backpressure, no-such-creature, denied, …) so a creature can act on each, and `RC_PANIC` lets
the host detect that a creature unwound inside its own glue and pull it off the bus rather than treat
the call as success.

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
- **`entrypoints`** — named descriptors an authoring agent generates against. Each retains its
  signed human-readable `signature` and may add an optional machine-readable
  `gawdfn::EntrypointContractV1` (bounded input/output JSON Schema, media types, and controls). `None`
  elides from legacy manifests byte-for-byte.
- **`capabilities`** — `fs`, `net`, `cpu_ms`, `mem_bytes`, optional `wall_ms`, and `calls` (the
  bus-level send allowlist), plus an opt-in `budget_warn_at` advisory threshold.
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

**A typed Function is one of these entrypoints, not a fourth tier or another exported symbol.** Its
immutable identity is the signed manifest content address plus entrypoint name. An executor carries a
`gawd.function.call.v1` envelope to the already-loaded creature and multiplexes the entrypoint through
the same `handle` call shown above. Explicit deployment records where that immutable definition is
live; an asynchronous Job records the resolved deployment pin before execution. The kernel, engines,
and `gawd_creature_v1` ABI are unchanged. See
[`functions-and-jobs.md`](functions-and-jobs.md).

Verification is a **mechanism** the substrate ships (ed25519 over the signing payload); *which* keys
are trust roots is an injected policy, never defined in the contract. Admission gathers evidence —
signature validity, content-address self-consistency, structural validity — and an injected `Policy`
decides whether to admit. Parsing never panics on hostile input: malformed bytes become a structured
error. Manifest JSON and retained metadata are size-bounded before admission or registry retention,
so malformed manifests cannot become an unbounded memory or durable-journal amplifier.

## Safe unload

Unloading a native `.so` while any function pointer, `&'static`, or spawned thread originating from
it is still live is undefined behavior — Rust's guarantees stop at the `dlopen` boundary. The
substrate solves this per tier, and the discipline is the load-bearing part of the native story.

**The drop order is fixed and singular.** `Engine::unload` runs `shutdown` within a deadline, then
drops the **instance** (the native `destroy` runs while the library is still mapped), then drops the
**resources** (`dlclose` runs **last**). The same order is encoded structurally: `LoadedModule`
declares `instance` before `resources`, and struct fields drop in declaration order, so even an
implicit drop tears down in the right sequence. Native resources also hold the staged-artifact guard
declared after the library, so it drops second. On Linux/Android that guard retains the sealed memfd
through `dlclose` and closes it afterward; each newly prepared stage receives a process-unique
`/proc/self/fd` spelling. On fallback platforms it unlinks the exact `.so` and removes its private,
OS-random per-stage directory after the library unmaps; those files are opened with `create_new`.
Thus independently prepared same-content stages never alias a mutable path or truncate one another.

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
ships a *discipline*, not a contract — `forge::spawn` is the compatible fire-and-report helper,
`forge::try_spawn` returns OS spawn errors to authors that must fail synchronously, and a raw
`std::thread::spawn` is documented as "you're on your own."

**The kernel's thread-count guard is the floor.** A creature that bypasses the discipline (a raw or
detached thread) is caught by a `/proc/self/task` snapshot diff — tids before `bind` versus after
`shutdown`. When the guard fires, the kernel **leaks the resources**: it `Box::leak`s the `Library`
and its stage guard, so both the mapping and exact staged artifact remain, the runaway thread keeps
dereferencing live code, and the proprioception bus publishes `unload_leaked_resources`. This is a
**bounded leak—one library plus one staged artifact per misbehavior, and never a use-after-free.** A
healthy creature beside the offender keeps serving and unloads normally.

**The unload deadline is real.** `Kernel::unload` waits on a per-drain signal channel; on timeout it
abandons the drain detached and returns `UnloadTimeout`. The substrate never hangs on a misbehaving
creature — the thread-count guard's bounded leak is the safety net for the abandoned drain. Creatures
unload in reverse-chronological order so a still-running neighbor's threads aren't misread as leaked.

**Off-drain workers honor the same floor.** A creature whose `handle` must do something slow — a
model call in `agent-mind`, say — runs that work on a self-owned worker thread and emits the reply
through its captured bus, so the drain thread is never blocked. `agent-mind` caps the in-flight model
worker set by default (`DEFAULT_MAX_IN_FLIGHT_MODEL_REQUESTS`), with `0` as the explicit lab/demo
opt-out for deployments that accept unbounded blocking model calls. Its `shutdown` sets a stop flag
(which suppresses a stopped worker's reply) and joins, **deadline-bounded by polling** so it returns
inside the kernel's unload budget; a worker still blocked in its call at the deadline is detached.
This is sound only for an **in-process** creature — the one place an emitting worker is safe, since
there is no `.so` FFI bus shim on that path — where a detached worker returns into no unmapped code:
it finishes its now-stopped call, drops its reply, and exits. The residual is a bounded, in-process
thread that lingers for the call's duration — never a use-after-free, the same floor a `.so` leak
converges on. (Clamping the call's *own* timeout low enough to fit a 1 s deadline would make a real
model call impossible, so the call timeout stays generous and the **join** is what's bounded.) When a
worker is still blocked at the deadline, the thread-count guard logs its generic "leaking resources"
line for the detached tid — but for an in-process creature the resources it would leak are empty, so
that diagnostic is conservative (no library is actually leaked); detach is the *expected*
in-flight-unload path under this no-clamp choice, not a fault.

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
| `wall_ms` | An opt-in per-envelope **wall-clock** cap, enforced by one engine-global `wasmtime` epoch ticker; an exceeded deadline traps as a `Hard` `Wall` signal. | An opt-in live per-envelope deadline sampled by Rhai's progress hook; expiry terminates with a `Hard` `Wall` signal. | Read at admit; not metered at runtime. |
| `mem_bytes` | A custom `ResourceLimiter` refuses growth past the cap — byte-exact. | Rhai's structural caps (string/array/map size) — **best-effort counts, not bytes**, with an always-on backstop. | Read at admit; the operator's OS-level seam. |
| `calls` | Router-side allowlist at the one bus choke point; a disallowed envelope is never delivered. Empty = unrestricted. | Same router gate. | Same router gate. |

**Beast and critter have teeth.** A beast that declares a host import fails to instantiate, so
`net:none` and `fs:[]` are properties of the loader, not runtime checks. Its `cpu_ms` is real fuel
and its `mem_bytes` is a real byte-exact cap. A critter is contained the same way — its one host
function with an outward effect, `emit`, only parks a dispatch the kernel routes through the gated bus
path; its bounded `mem_*` host functions retain only instance-local values. It holds no bus authority
itself, and `no_module` plus a disabled `eval` make it exactly its signed, static source. Its `cpu_ms`
is a real operation budget; its `mem_bytes` is honestly best-effort (structural counts, with a bounded
default backstop so one bulk-allocating builtin can't OOM the host). The loader also keeps the
convenience string view honest: `env.text` is a lossy UTF-8 preview capped by the effective memory cap
and a 1 MiB ceiling, while `env.payload` remains the full byte-exact `Blob`.

**The metered tiers also bound wall time.** `capabilities.wall_ms` is an opt-in per-envelope ceiling on
*elapsed* time — the backstop for work that consumes little fuel but still blocks or spins. It is
enforced for beasts through `wasmtime`'s **epoch interruption**: the engine enables epoch interruption once, a
single engine-global ticker thread advances the epoch on a fixed cadence (a weak engine handle, so the
ticker never keeps the engine alive), and each `handle` arms a per-store deadline of `ceil(wall_ms /
tick)` epochs; an exceeded deadline surfaces as a trap and becomes a `Hard` `BudgetSignal { kind:
Wall }` — the same apoptosis path a fuel breach takes. Two honesty notes: like fuel, the deadline is
checked at instrumentation points the compiler weaves into the wasm code, so it bounds time spent *in*
the beast (a beast has no host imports, so there is nothing external to block inside); and the cap is
**fail-closed** — if the ticker thread ever fails to spawn, the engine logs the degradation and
*refuses to load* any beast that declares `wall_ms`, rather than silently ignore the cap. A beast with
no `wall_ms` runs under an effectively unlimited deadline, exactly as `cpu_ms == 0` means unlimited
fuel. A critter reads the same live ceiling on each handle and samples its deadline from Rhai's
progress hook; it terminates as `Hard`/`Wall` after the bounded sampling interval. Native remains
trusted-by-admission and does not meter wall time.

**The daemon stays honest about its limits.** The substrate does not pretend to confine in-process
native code mid-flight. The capability declarations are evidence an injected admission policy reads —
a policy can demand `net:none` and refuse any daemon that declares otherwise, or compose
signed-provenance + net-restriction + author-allowlist + any custom rule. OS-level confinement
(bwrap, firejail, seccomp, cgroups) is the operator's deployment decision, applied to the sanctum
process, not a per-creature cage the kernel fakes.

**A model-backed author is contained by the route, not the prompt.** `agent-mind` is the first place a
real model decides what native code gets compiled and admitted — and it is prompt-injectable (both the
request and the compiler `prev_error` fed back on retry are influenceable). The reference `build-cargo`
emits a native `Backend::Daemon` by default — a *trusted-by-admission* creature signed with the
operator's own Abode key — and under the dev posture (an allow-all verifier) that signature is not
load-bearing. So containment lives where it can be enforced, the **route + admission layer, not the
prompt**: default a model-author path to the sandboxed `critter` tier (concentric confinement:
daemon ⊃ beast ⊃ critter), or gate model-authored native artifacts behind a model-author-specific
admission policy. The system prompt's tier preference is advisory. For audit, the author emits one
structured line per completion (authored-source `sha256`, model label, token usage). The honest
containment boundary is the operator's tier choice + admission policy — the daemon's
trusted-by-admission limit above, now with an untrusted author on the other side of it.

**Budgets are observed, never judged, by the substrate.** When an engine detects pressure — fuel or
operation exhaustion, a refused grow, a crossed warning threshold — it surfaces a `BudgetSignal`
(`Hard` on a terminal breach, `Warn` alongside an otherwise-successful reply) on the creature's
outcome. The kernel publishes it as an event on the proprioception topic; it **never** decides that a
breach is fatal. An **injected** policy creature subscribes, parses the signal, and decides: unload,
observe, demote, escalate to a human, or grant grace. The kill rule, the grace period, the
escalation — all live outside the kernel. Swap the rule by swapping the creature; no kernel rebuild.

**The control surface is one socket.** The kernel address is a live destination served by a
dispatcher that drains kernel-addressed envelopes and executes `KernelControl` ops. `Unload` runs
the same safe-unload path any explicit unload uses. `ExtendBudget` lifts enforceable per-handle
ceilings through lock-free cells shared with the running engine: beasts support fuel, memory, and
wall; critters support operation budget (reported as fuel) and wall, while their structural memory
caps stay fixed at load. The next handle sees the lift without the kernel reaching into the drain
thread. Native exposes no budget control, and any unsupported dimension is reported
`Unenforceable` rather than silently accepted. The control enum is tagged so future ops land
additively; a malformed payload is skipped, never a panic.

## Bounded growth and the `0 = unbounded` escape-hatch convention

Every in-memory table that a peer or a config could otherwise grow without limit is **bounded by a
finite default** — the kernel's per-creature inboxes, the history journal, the topic-subscription
table, the reference registry's entry/byte caps, the advertiser's offer table, the realm-gateway's
mapping table, the dialogue initiator's parked-conversation table. This is the R9 fabric-integrity
floor in practice: the kernel bounds the *table*, not the *traffic*, and a flood sheds via
backpressure or drop-oldest rather than OOM.

For the cases where a lab or demo workload genuinely wants no cap, those bounds expose **one uniform
opt-out**: a `with_max_*` / `*_and_limit` builder where **`0` selects the explicit unbounded opt-out**.
The convention, applied identically everywhere:

- The default is always a **finite** value; `0` is never the default and must be selected explicitly.
- `0` means *unbounded* and is documented, on every such knob, with the canonical phrase: *"`0`
  selects the explicit unbounded opt-out (lab/demo workloads only); production deployments MUST set a
  finite cap."*
- The opt-out is kept (the demos and test fixtures rely on it knowingly), not removed — removing it
  would trade a documented, opt-in escape hatch for friction with no safety gain, since the default is
  already finite.

A new creature author bounding any retained collection reaches for this same `with_max_*(0) =
unbounded` shape and the same doc phrasing, so an operator learns the rule once and an unbounded
opt-out is one phrase to grep for in review. (See `Router::with_max_topics`,
`RegistryMem::with_max_entries`, `EmbodimentAdvertiser::with_max_offers`,
`RealmGateway::with_many_and_limit`, `DialogueInitiator::with_max_pending`.)
