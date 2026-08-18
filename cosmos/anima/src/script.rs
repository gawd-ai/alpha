//! The critter (script) tier — a real, metered, sandboxed Rhai interpreter.
//!
//! The third creature tier: cheaper and more ephemeral than a native `daemon` or a WASM
//! `beast` — ideal for high-variation experiments and glue. Like the beast, it is **contained by
//! construction**: a freshly built [`rhai::Engine`] reaches nothing (no filesystem, network, clock,
//! process, or rand — Rhai has no such builtins, and the `no_time` feature strips even
//! `timestamp()`). We compile Rhai with `no_module` and additionally turn off runtime code-gen
//! (`disable_symbol("eval")`) so a critter is exactly its signed, static source. Its only outward host
//! function is `emit`, whose effect is a [`Dispatch`] the kernel routes through the one
//! capability-gated bus path; `mem_get` / `mem_set` / `mem_del` expose only bounded, instance-local
//! memory. The pure `json_parse` / `json_stringify` helpers only transform bounded values in memory;
//! they confer no authority. So `net:none` / `fs:[]` hold for a critter the same way they hold for a
//! beast — properties of the loader, not runtime checks — and the router's `calls` gate applies
//! unchanged at its single choke point.
//!
//! Enforcement is the interpreter-limit mechanism, wired to the
//! same budget-gradient surface as the beast: `capabilities.cpu_ms` becomes an
//! **operation budget** (`set_max_operations`, the analog of wasm fuel) refilled per envelope from a
//! live [`BudgetControl`] ceiling, so a `KernelControl::ExtendBudget` grant lifts a running critter
//! exactly as it lifts a beast. A budget breach is a structured `Hard`/`Fuel` [`BudgetSignal`], not
//! a hang or a panic; a successful handle that crossed `budget_warn_at` rides a `Warn` alongside its
//! reply. `mem_bytes` maps to Rhai's *structural* caps (string / array / map size), which are
//! **always installed** — a bounded [`DEFAULT_STRUCTURAL_CAP`] backstop when `mem_bytes` is unset
//! (so one bulk-allocating builtin can't OOM the host past the op budget's reach), tightened to the
//! declared value when set. A structural breach surfaces as a best-effort `Hard`/`Memory`
//! [`BudgetSignal`] — **not** the byte-exact `ResourceLimiter` the beast tier has. `wall_ms` is a
//! live per-envelope cap sampled by the interpreter progress hook and surfaces as `Hard`/`Wall`.
//!
//! The artifact is UTF-8 Rhai **source text** (deterministic bytes, content-addressable, no
//! interpreter-version serialization lock-in). A critter defines `fn handle(env)`; its return value
//! becomes a reply to the envelope's reply target, and it may `emit(addr, bytes)` additional
//! dispatches.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aether::{
    Address, BudgetSignal, BudgetVector, Creature, CreatureCtx, CreatureId, Dispatch, Envelope,
    Intent, LimitKind, Outcome, Role, Topic,
};
use gawdfn::{FunctionCallMessageV1, FunctionId, Validate, MAX_JOB_MESSAGE_BYTES, SCHEMA_CALL_V1};
use rhai::{Blob, Dynamic, Engine as RhaiEngine, EvalAltResult, Map as RhaiMap, Scope, AST};
use serde_json::Value as JsonValue;
use sigil::{Backend, Manifest};

use crate::{Artifact, BudgetControl, Engine, EngineError, LoadedModule};

/// The compatibility tag a critter manifest must declare, distinct from native/beast's
/// `"gawd_creature_v1"` (`aether::ffi::ABI_TAG`). A manifest carrying any other tag is rejected at load
/// with [`EngineError::AbiMismatch`] before the source is parsed — the same guard native applies. If
/// a future Rhai bump changes operation accounting (and thus the determinism / content-address
/// contract), this tag bumps to `gawd_critter_v2`.
pub const CRITTER_ABI_TAG: &str = "gawd_critter_v1";

/// The entrypoint a critter script must define: `fn handle(env)`. The kernel always drives this one
/// function (multi-entrypoint dispatch is deferred).
const HANDLE_FN: &str = "handle";

/// Default interpreter operations granted per declared `cpu_ms`. The critter analog of the beast's
/// [`DEFAULT_FUEL_PER_MS`](crate::wasm::DEFAULT_FUEL_PER_MS) — deliberately modest, because Rhai is a
/// tree-walking interpreter and the operation counter is a budget dial, not a wall-clock guarantee.
/// This keeps budget traps cheap in the public test suite while leaving ordinary glue scripts plenty
/// of headroom. A per-engine tuning knob is deferred; `cpu_ms` is the per-creature dial
/// today (`cpu_ms == 0` ⇒ unbounded).
pub const DEFAULT_OPS_PER_MS: u64 = 10_000;

/// The structural-size backstop installed when a critter declares no `mem_bytes`. Rhai reads a `0`
/// cap as "unlimited", which would let a single bulk-allocating builtin (`pad`, string `*`, array
/// `+`) allocate host memory proportional to a *script-supplied* integer in **one** tracked
/// operation — outside the operation budget's reach. This element / char / entry ceiling
/// bounds any single allocation while leaving ample room for ordinary glue. It is a *count*, not a
/// byte size (Rhai's caps are structural); an operator who needs a tighter or looser ceiling sets
/// `mem_bytes`. A per-engine knob is deferred. NB: distinct from `cpu_ms == 0`, which is
/// the deliberate CPU opt-out — there is no "unlimited structural memory" opt-out by construction.
pub const DEFAULT_STRUCTURAL_CAP: u64 = 1024 * 1024;

/// Maximum bytes copied into a critter's convenience `env.text` view. `env.payload` remains the full
/// byte-exact [`Blob`]; this cap only bounds the extra host-side lossy UTF-8 string the loader builds
/// before the script runs. The effective cap is `min(mem_bytes-or-default, MAX_ENV_TEXT_BYTES)`, so a
/// tight declared memory budget also tightens the text view.
pub const MAX_ENV_TEXT_BYTES: usize = 1024 * 1024;

/// Maximum number of keys a critter's persistent memory (`mem_set`) holds at once. At capacity a
/// *new* key is refused while an *existing* one can still be overwritten — the same refuse-new
/// posture `registry-mem` takes, so a runaway script cannot grow host memory without bound through
/// the memory surface. The per-creature analog of a registry's `max_entries`. (Each stored value is
/// separately bounded by the engine's structural caps — `mem_bytes` / [`DEFAULT_STRUCTURAL_CAP`] —
/// at the moment the script builds it, so the whole surface is bounded by entries × value-size.)
pub const MAX_PERSIST_ENTRIES: usize = 256;

/// Maximum byte length of a persistent-memory key. A longer key is refused by `mem_set` rather than
/// retained, so a script can't grow the keyspace's memory through pathological key strings.
pub const MAX_PERSIST_KEY_BYTES: usize = 256;

/// Maximum parse-time expression nesting depth (global scope, then function body). Rhai's *default*
/// caps are **profile-dependent** — halved in debug builds (function-body depth 16 debug vs 32
/// release) to keep the parser's own recursion off a smaller test stack. Left unset, a critter could
/// compile under `--release` yet be rejected under `cargo test`/debug, and the loader
/// ([`ScriptEngine`]) and the author gate (`build-critter`) could disagree on what is valid. We pin
/// both engines to Rhai's documented **non-debug** defaults so the depth limit is identical across
/// build profiles and across the two engines. (Bounding parse depth also caps parser stack use.)
pub const MAX_EXPR_DEPTH: usize = 64;
pub const MAX_FN_EXPR_DEPTH: usize = 32;

/// Hard byte ceiling for either side of one pure JSON conversion. The effective ceiling is the
/// lower of this value and the critter's declared/default structural cap. JSON helpers execute as a
/// host call (one interpreter operation), so they need their own byte/work bounds rather than
/// relying on Rhai fuel alone.
pub const MAX_JSON_BYTES: usize = 1024 * 1024;

/// Maximum total values (objects, arrays, and leaves) traversed by one JSON helper call. This caps
/// host-side work even for compact inputs such as deeply populated arrays.
pub const MAX_JSON_NODES: usize = 65_536;

/// Maximum JSON container nesting. Kept explicit and profile-independent just like the Rhai parser
/// depth caps; it also keeps conversion recursion safely shallow.
pub const MAX_JSON_DEPTH: usize = 64;

/// The critter (script) engine. A unit struct on purpose: it carries no per-engine configuration, so
/// every existing `Arc::new(ScriptEngine)` construction site stays untouched (the operation-budget
/// rate is the module constant `DEFAULT_OPS_PER_MS`).
pub struct ScriptEngine;

impl Engine for ScriptEngine {
    fn backend(&self) -> Backend {
        Backend::Critter
    }

    fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        // A non-critter manifest mis-routed here is a routing bug — surface it precisely
        // (discoverability), the way native/beast do, not as an "unsupported tier" condition.
        if manifest.abi.backend != Backend::Critter {
            return Err(EngineError::WrongBackend {
                engine: Backend::Critter,
                manifest: manifest.abi.backend,
            });
        }
        // Guard the entry boundary before parsing a byte (mirrors `native.rs`): a critter declares
        // its own ABI tag, so a daemon/beast artifact mis-tagged as a critter is rejected cleanly.
        if manifest.abi.abi_tag != CRITTER_ABI_TAG {
            return Err(EngineError::AbiMismatch {
                expected: CRITTER_ABI_TAG.to_string(),
                got: manifest.abi.abi_tag.clone(),
            });
        }
        let function_bindings = ContractedFunctionBindings::from_manifest(manifest)?;
        let src = String::from_utf8(artifact.read_bytes()?)
            .map_err(|e| EngineError::Load(format!("critter source is not valid UTF-8: {e}")))?;

        // `cpu_ms == 0` ⇒ 0 ops ⇒ Rhai's "unlimited" sentinel (`set_max_operations(0)`), the same
        // operator opt-out the beast's `cpu_ms == 0` ⇒ unbounded-fuel gives.
        let ops_cap = budget_to_ops(manifest.capabilities.cpu_ms, DEFAULT_OPS_PER_MS);
        // The critter enforces fuel (ops) and wall (the `on_progress` watchdog below) live; its
        // `mem_bytes` maps to Rhai *structural* caps installed once at load (Rhai has no live
        // structural setter), so a mem lift is honestly reported unenforceable by the kernel rather
        // than silently dropped.
        let budget = BudgetControl::new(ops_cap, 0, manifest.capabilities.wall_ms.unwrap_or(0))
            .enforcing(true, false, true);

        // Per-handle observability shared with the running instance: `outbox` collects the dispatches
        // the script `emit`s (the kernel sends them, so its `calls` gate and local-FIFO ordering
        // both apply); `ops_observed` is written by the progress hook so a handle can report
        // `consumed` for the budget vector.
        let outbox: Arc<Mutex<Vec<Dispatch>>> = Arc::new(Mutex::new(Vec::new()));
        let ops_observed = Arc::new(AtomicU64::new(0));
        // The current handle's wall deadline (`None` = no wall cap this handle), shared with the
        // `on_progress` watchdog below; `handle` arms it each call from the live wall cell.
        let wall_deadline: Arc<Mutex<Option<std::time::Instant>>> = Arc::new(Mutex::new(None));

        let mut engine = RhaiEngine::new();
        // Runtime `eval(string)` is dynamic code-gen. It is *not* a sandbox escape — the inner script
        // shares this engine's op budget and gains no host fn beyond `emit` — but it defeats
        // build-critter's "all code is static, present, and signed" compile gate and is an audit
        // surprise. Disable it (Rhai's own hardening recommendation) so a critter is exactly its
        // signed source; build-critter disables it at the compile gate too, so authored `eval` fails
        // fast rather than loading and then mis-behaving.
        engine.disable_symbol("eval");
        // `mem_bytes` → Rhai's *structural* caps (string / array / map size). These are ALWAYS
        // installed: Rhai treats a `0` cap as "unlimited", and several stdlib builtins (`pad`, string
        // `*`, array `+`) allocate proportional to a *script-supplied* integer in ONE tracked
        // operation — so without a cap a single op could allocate unbounded host memory that
        // `set_max_operations` never catches. We install a bounded default backstop when `mem_bytes`
        // is unset, tightened to the declared value when set. NOT byte-exact (counts, not bytes) —
        // best-effort. (Distinct from `cpu_ms == 0`, which IS the CPU opt-out.)
        let mem_cap = if manifest.capabilities.mem_bytes > 0 {
            manifest.capabilities.mem_bytes
        } else {
            DEFAULT_STRUCTURAL_CAP
        };
        let cap = usize::try_from(mem_cap).unwrap_or(usize::MAX);
        engine.set_max_string_size(cap);
        engine.set_max_array_size(cap);
        engine.set_max_map_size(cap);
        register_json_helpers(&mut engine, cap.min(MAX_JSON_BYTES));
        register_function_helpers(&mut engine);
        // Pin parse-time expression depth so it does not silently differ between debug and release (or
        // from `build-critter`'s author gate). See [`MAX_EXPR_DEPTH`].
        engine.set_max_expr_depths(MAX_EXPR_DEPTH, MAX_FN_EXPR_DEPTH);
        // A script's `print`/`debug` are diagnostics, not authority: route them to stderr (never the
        // daemon's stdout, which would corrupt a protocol stream), and never to the bus.
        engine.on_print(|s| eprintln!("[critter] {s}"));
        engine.on_debug(|s, src, pos| eprintln!("[critter] {s} (src={src:?} pos={pos:?})"));
        // Operation observer: record the running count so a handle can fill `BudgetVector.consumed`.
        // Always returns `None` — the *enforcement* is `set_max_operations` (→ `ErrorTooManyOperations`),
        // this hook only measures.
        {
            let obs = ops_observed.clone();
            let deadline = wall_deadline.clone();
            engine.on_progress(move |ops| {
                obs.store(ops, Ordering::Relaxed);
                // Wall watchdog: terminate the script if the per-handle wall deadline has passed.
                // Sampled ~every 256 ops so the clock read never dominates a hot loop (enforcement
                // slack is bounded by those ops). When there is no wall cap this handle the deadline
                // is `None` and no clock is read. A termination here surfaces as `ErrorTerminated`,
                // which `handle` maps to a Hard/Wall breach (distinct from a Fuel op-budget trap).
                if ops & 0xff == 0 {
                    if let Ok(guard) = deadline.lock() {
                        if let Some(dl) = *guard {
                            if std::time::Instant::now() >= dl {
                                return Some(rhai::Dynamic::UNIT);
                            }
                        }
                    }
                }
                None
            });
        }
        // The critter's one outward effect. It builds a `Dispatch` and parks it in the outbox; the
        // kernel routes it through the same gated bus path every tier uses — the script never holds
        // bus authority itself. An unroutable address string is an honest error to the author.
        {
            let ob = outbox.clone();
            engine.register_fn(
                "emit",
                move |to: rhai::ImmutableString, payload: Blob| -> Result<(), Box<EvalAltResult>> {
                    let addr =
                        parse_address(to.as_str()).ok_or_else(|| -> Box<EvalAltResult> {
                            format!(
                                "emit: unroutable address `{to}` \
                             (expected creature:N / role:R / topic:T / intent:X / kernel)"
                            )
                            .into()
                        })?;
                    if let Ok(mut guard) = ob.lock() {
                        guard.push(Dispatch::to(addr, payload));
                    }
                    Ok(())
                },
            );
        }
        // Persistent per-creature memory. Every other critter state is per-call — a fresh `Scope`
        // each `handle` (see below) — so until now the critter was the one tier with *no* carried
        // state, where a daemon has struct fields and a beast has linear memory. This is that carried
        // state: a small key→value store, reached through three host fns (`mem_get`/`mem_set`/`mem_del`,
        // the same registered-host-fn shape as `emit`, because Rhai script functions can't see the
        // parent scope). It SURVIVES across `handle` calls for the instance's lifetime and is dropped
        // on unload — NOT durable across a reload (a reloaded critter starts empty, matching "a critter
        // is exactly its signed source"). Bounded: at most [`MAX_PERSIST_ENTRIES`] keys (refuse-new at
        // capacity, like `registry-mem`), keys up to [`MAX_PERSIST_KEY_BYTES`]; each value is already
        // structurally size-capped by the engine at the moment the script builds it.
        let persist: Arc<Mutex<HashMap<String, Dynamic>>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let store = persist.clone();
            engine.register_fn("mem_get", move |key: rhai::ImmutableString| -> Dynamic {
                store
                    .lock()
                    .ok()
                    .and_then(|g| g.get(key.as_str()).cloned())
                    .unwrap_or(Dynamic::UNIT)
            });
        }
        {
            let store = persist.clone();
            engine.register_fn(
                "mem_set",
                move |key: rhai::ImmutableString,
                      value: Dynamic|
                      -> Result<(), Box<EvalAltResult>> {
                    if key.len() > MAX_PERSIST_KEY_BYTES {
                        return Err(
                            format!("mem_set: key exceeds {MAX_PERSIST_KEY_BYTES} bytes").into()
                        );
                    }
                    let mut g = store
                        .lock()
                        .map_err(|_| -> Box<EvalAltResult> { "mem_set: memory poisoned".into() })?;
                    // Refuse-new at capacity; overwriting an existing key always succeeds.
                    if !g.contains_key(key.as_str()) && g.len() >= MAX_PERSIST_ENTRIES {
                        return Err(format!(
                            "mem_set: memory at capacity ({MAX_PERSIST_ENTRIES} keys); \
                             delete a key before adding a new one"
                        )
                        .into());
                    }
                    g.insert(key.to_string(), value);
                    Ok(())
                },
            );
        }
        {
            let store = persist.clone();
            engine.register_fn("mem_del", move |key: rhai::ImmutableString| {
                if let Ok(mut g) = store.lock() {
                    g.remove(key.as_str());
                }
            });
        }

        // Seed the static cap; `handle` re-seeds from the live atomic each call so an `ExtendBudget`
        // grant takes effect on the next handle, mirroring the beast at `wasm.rs`.
        engine.set_max_operations(ops_cap);

        let ast = engine
            .compile(&src)
            .map_err(|e| EngineError::Load(format!("critter compile error: {e}")))?;
        // Fail at load, not on the first envelope, if the contract entrypoint is missing
        // (discoverability). `params` arity is only retained under Rhai's `metadata` feature, so we
        // check the name only; a wrong arity surfaces as a structured runtime error on `handle`.
        if !ast.iter_functions().any(|f| f.name == HANDLE_FN) {
            return Err(EngineError::Load(format!(
                "critter must define `fn {HANDLE_FN}(env)`; none found in the script"
            )));
        }

        let instance = ScriptInstance {
            engine,
            ast,
            me: None,
            function_bindings,
            live_ops_cap: budget.cell(),
            live_wall_ms_cap: budget.wall_cell(),
            wall_deadline,
            ops_observed,
            outbox,
            mem_cap,
            // `t.min(100)`: a malformed `budget_warn_at > 100` clamps to 100 (the engine never trusts
            // a declared input), matching the beast's clamp.
            budget_warn_at: manifest.capabilities.budget_warn_at.map(|t| t.min(100)),
            envelopes_handled: 0,
        };
        Ok(LoadedModule::new(Box::new(instance), Box::new(())).with_budget(budget))
    }
}

/// A loaded critter: a configured (sandboxed, metered) Rhai engine + the compiled script, plus the
/// per-handle observability the engine's host fns write to. Lives on one creature drain thread, so
/// it only needs to be `Send` — which Rhai's types are under the `sync` feature.
struct ScriptInstance {
    engine: RhaiEngine,
    ast: AST,
    me: Option<CreatureId>,
    /// Manifest-derived identities for contracted typed-Function entrypoints. Absent for ordinary
    /// critters, whose payload-in/reply-out behavior remains unchanged.
    function_bindings: Option<ContractedFunctionBindings>,
    /// The live per-handle operation ceiling, shared with the kernel via [`BudgetControl`]. Read
    /// fresh each `handle` so a granted `ExtendBudget` lifts the next call.
    live_ops_cap: Arc<AtomicU64>,
    /// The live per-handle wall-clock ceiling (ms; `0` = unlimited), shared with the kernel via
    /// [`BudgetControl`]. Read fresh each `handle` to arm [`Self::wall_deadline`]; a granted
    /// `ExtendBudget` wall lift takes effect on the next call.
    live_wall_ms_cap: Arc<AtomicU64>,
    /// The current handle's absolute wall deadline (`None` = no cap this handle), read by the
    /// engine's `on_progress` watchdog and re-armed by `handle`.
    wall_deadline: Arc<Mutex<Option<std::time::Instant>>>,
    /// Written by the engine's progress hook every operation; read after a handle to report
    /// `consumed`.
    ops_observed: Arc<AtomicU64>,
    /// Dispatches the script `emit`ted during the current handle, in push order (the local-delivery
    /// FIFO contract on [`Outcome`] holds, since the kernel drains this in order).
    outbox: Arc<Mutex<Vec<Dispatch>>>,
    /// The effective structural-size cap installed on the engine (the declared `mem_bytes`, or
    /// [`DEFAULT_STRUCTURAL_CAP`] when unset). Reported as the `limit` of a `Memory` breach signal.
    mem_cap: u64,
    /// Declared `Warn` threshold (percent of the op budget), clamped to `0..=100`.
    budget_warn_at: Option<u8>,
    envelopes_handled: u64,
}

impl Creature for ScriptInstance {
    fn bind(&mut self, ctx: CreatureCtx) {
        // A critter's only outward authority is the `emit` host fn (whose dispatches the kernel
        // routes); it needs no direct bus handle. Keep its identity for diagnostics.
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // A contracted typed-Function critter must not be allowed to interpret a validly shaped
        // call for another immutable function. Bind identity at load from the manifest and
        // enforce it before Rhai runs. The script's existing `function_call_verify` remains the
        // grant/signature/route gate; keeping those checks there avoids verifying every signature
        // twice while this host guard closes the manifest-identity gap independently of script
        // control flow.
        if let Some(bindings) = &self.function_bindings {
            if let Err(error) = bindings.verify_identity(&env) {
                eprintln!(
                    "anima(critter): contracted Function refused envelope from {:?} (seq={}): {error}",
                    env.header.from, env.header.seq
                );
                return Outcome::none();
            }
        }
        // Refill the operation budget to the *live* per-envelope ceiling BEFORE running:
        // this reads the shared atomic, so a granted `ExtendBudget` takes effect here; absent a grant
        // it equals the `cpu_ms`-derived cap seeded at load.
        let ops_cap = self.live_ops_cap.load(Ordering::Relaxed);
        self.engine.set_max_operations(ops_cap);
        self.ops_observed.store(0, Ordering::Relaxed);
        // Arm the per-handle wall deadline from the *live* wall cell (`0` = no cap), read fresh so a
        // granted `ExtendBudget` wall lift takes effect here. The `on_progress` watchdog enforces it.
        let wall_cap_ms = self.live_wall_ms_cap.load(Ordering::Relaxed);
        if let Ok(mut g) = self.wall_deadline.lock() {
            *g = (wall_cap_ms > 0)
                .then(|| std::time::Instant::now() + std::time::Duration::from_millis(wall_cap_ms));
        }
        if let Ok(mut guard) = self.outbox.lock() {
            guard.clear();
        }
        self.envelopes_handled = self.envelopes_handled.saturating_add(1);

        let env_value = marshal_env(&env, self.mem_cap);
        let started = std::time::Instant::now();
        let mut scope = Scope::new();
        let result = self.engine.call_fn::<Dynamic>(&mut scope, &self.ast, HANDLE_FN, (env_value,));
        let wall_ms_elapsed = started.elapsed().as_millis() as u64;
        let consumed = self.ops_observed.load(Ordering::Relaxed);

        match result {
            Ok(ret) => {
                // The script's emitted dispatches (kernel-routed, gated), then its return value as a
                // reply to the envelope's reply target. A `()` return means "no reply" (the script
                // used `emit` instead).
                let mut dispatches = self.drain_outbox();
                if let Some(bytes) = dynamic_to_payload(&ret) {
                    dispatches.push(Dispatch::reply_to_env(&env, bytes));
                }
                let dispatches_this_envelope = dispatches.len() as u32;
                let mut outcome = Outcome { dispatches, budget_signal: None };
                // The first/only `Warn` a critter emits: a *successful* handle whose op
                // consumption crossed the declared threshold rides a `Warn` alongside the reply
                // (`budget_signal` is metadata, not a discriminant).
                if let Some(threshold) = self.budget_warn_at {
                    if ops_cap > 0 && crossed(consumed, ops_cap, threshold) {
                        outcome.budget_signal = Some(BudgetSignal::warn(
                            LimitKind::Fuel,
                            BudgetVector {
                                consumed,
                                limit: ops_cap,
                                dispatches_this_envelope,
                                wall_ms_elapsed,
                                envelopes_since_load: self.envelopes_handled,
                            },
                        ));
                    }
                }
                outcome
            }
            Err(err) => match &*err {
                // The operation budget ran out: a structured `Hard`/`Fuel` breach, no reply, no
                // partial sends — exactly what the apoptosis chain observes for a beast fuel trap.
                EvalAltResult::ErrorTooManyOperations(_) => {
                    let vector = BudgetVector {
                        // On a too-many-ops trap the observed count is ≈ the cap; guarantee it is
                        // non-zero so a `Hard`/`Fuel` signal always reports work consumed.
                        consumed: if consumed > 0 { consumed } else { ops_cap.max(1) },
                        limit: ops_cap,
                        dispatches_this_envelope: 0,
                        wall_ms_elapsed,
                        envelopes_since_load: self.envelopes_handled,
                    };
                    Outcome::budget_signal(BudgetSignal::hard(LimitKind::Fuel, vector))
                }
                // The wall watchdog (`on_progress`) terminated the handle: the per-envelope wall-clock
                // cap was exceeded. The critter analog of a beast's `Wall` epoch trap — a structured
                // `Hard`/`Wall` breach, no reply, no partial sends.
                EvalAltResult::ErrorTerminated(_, _) => {
                    let vector = BudgetVector {
                        consumed: wall_ms_elapsed.max(1),
                        limit: self.live_wall_ms_cap.load(Ordering::Relaxed),
                        dispatches_this_envelope: 0,
                        wall_ms_elapsed,
                        envelopes_since_load: self.envelopes_handled,
                    };
                    Outcome::budget_signal(BudgetSignal::hard(LimitKind::Wall, vector))
                }
                // A structural-size cap breach (`mem_bytes` → string/array/map size, or the always-on
                // default backstop): the critter analog of the beast's memory trap. Best-effort
                // `Hard`/`Memory` — Rhai's caps are counts, not bytes, so we report the cap as the
                // limit rather than an exact byte tally — so an injected budget policy observes the
                // Memory dimension for a critter the same way it does for a beast.
                EvalAltResult::ErrorDataTooLarge(..) => {
                    let vector = BudgetVector {
                        // No byte/element count is recoverable from the error; report the cap that was
                        // breached so the signal is non-zero and self-describing.
                        consumed: self.mem_cap,
                        limit: self.mem_cap,
                        dispatches_this_envelope: 0,
                        wall_ms_elapsed,
                        envelopes_since_load: self.envelopes_handled,
                    };
                    Outcome::budget_signal(BudgetSignal::hard(LimitKind::Memory, vector))
                }
                // Any other script error (type error, bad index, missing/!1-arity `handle`, an
                // `emit` to an unroutable address, …) is hostile-or-buggy input: no reply, no partial
                // sends, never a host crash (R9). Surface the reason so the operator isn't left
                // guessing why the critter went silent (the beast tier does the same).
                other => {
                    eprintln!(
                        "anima(critter): script errored on envelope from {:?} (seq={}); \
                         no reply: {other}",
                        env.header.from, env.header.seq
                    );
                    Outcome::none()
                }
            },
        }
    }
}

/// Immutable Function identities derived from one loaded critter manifest.
///
/// Multiple contracted entrypoints remain legal: they share the manifest content address and are
/// distinguished by entrypoint name. A critter with no contracted `gawd.function.call.v1`
/// entrypoint does not get this guard, preserving the general script ABI exactly.
struct ContractedFunctionBindings {
    expected: Vec<FunctionId>,
}

impl ContractedFunctionBindings {
    fn from_manifest(manifest: &Manifest) -> Result<Option<Self>, EngineError> {
        let entrypoints = manifest
            .entrypoints
            .iter()
            .filter(|entrypoint| {
                entrypoint.signature == SCHEMA_CALL_V1 && entrypoint.contract.is_some()
            })
            .collect::<Vec<_>>();
        if entrypoints.is_empty() {
            return Ok(None);
        }

        let content_address = manifest.content_address.clone().ok_or_else(|| {
            EngineError::Load(
                "a contracted Function critter manifest must carry a content address".into(),
            )
        })?;
        if content_address != manifest.compute_content_address() {
            return Err(EngineError::Load(
                "contracted Function critter manifest content address is stale".into(),
            ));
        }

        let mut expected = Vec::with_capacity(entrypoints.len());
        for entrypoint in entrypoints {
            let function = FunctionId {
                manifest_content_address: content_address.clone(),
                entrypoint: entrypoint.name.clone(),
            };
            function.validate().map_err(|error| {
                EngineError::Load(format!("contracted critter FunctionId: {error}"))
            })?;
            expected.push(function);
        }
        Ok(Some(Self { expected }))
    }

    fn verify_identity(&self, env: &Envelope) -> Result<(), String> {
        if env.header.schema != SCHEMA_CALL_V1 {
            return Err(format!(
                "expected schema `{SCHEMA_CALL_V1}`, received `{}`",
                env.header.schema
            ));
        }
        if env.payload.len() > MAX_JOB_MESSAGE_BYTES {
            return Err(format!(
                "Function call is {} bytes, exceeds {MAX_JOB_MESSAGE_BYTES}",
                env.payload.len()
            ));
        }
        let message = serde_json::from_slice::<FunctionCallMessageV1>(&env.payload)
            .map_err(|error| format!("invalid Function call JSON: {error}"))?;
        let FunctionCallMessageV1::Call { call } = message else {
            return Err("expected a Function call operation".into());
        };
        if self.expected.iter().any(|expected| expected == &call.function) {
            return Ok(());
        }
        Err(format!(
            "call targets {}#{}, which is not declared by the loaded manifest",
            call.function.manifest_content_address, call.function.entrypoint
        ))
    }
}

impl ScriptInstance {
    fn drain_outbox(&self) -> Vec<Dispatch> {
        match self.outbox.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(_) => Vec::new(),
        }
    }
}

/// Register the critter's two pure JSON bridge functions. They intentionally accept/return text
/// rather than blobs: typed application protocols are UTF-8 JSON, while byte-exact opaque payloads
/// remain available as `env.payload`. Neither helper reaches an ambient service or retains state.
fn register_json_helpers(engine: &mut RhaiEngine, byte_cap: usize) {
    engine.register_fn(
        "json_parse",
        move |text: rhai::ImmutableString| -> Result<Dynamic, Box<EvalAltResult>> {
            parse_json(text.as_str(), byte_cap)
                .map_err(|error| format!("json_parse: {error}").into())
        },
    );
    engine.register_fn(
        "json_stringify",
        move |value: Dynamic| -> Result<String, Box<EvalAltResult>> {
            stringify_json(&value, byte_cap)
                .map_err(|error| format!("json_stringify: {error}").into())
        },
    );
}

/// Register the proof-bearing Function call gate used by critter adapters. It is pure verification:
/// no key, bus, clock, store, or policy authority enters the script. A call is exposed as valid only
/// when its exact Home-signed grant verifies and the authenticated local envelope route matches the
/// grant-pinned executor and target CreatureIds.
fn register_function_helpers(engine: &mut RhaiEngine) {
    engine.register_fn(
        "function_call_verify",
        |text: rhai::ImmutableString,
         from: rhai::ImmutableString,
         to: rhai::ImmutableString|
         -> Result<bool, Box<EvalAltResult>> {
            verify_function_call_route(text.as_str(), from.as_str(), to.as_str())
                .map_err(|error| format!("function_call_verify: {error}").into())
        },
    );
}

fn verify_function_call_route(text: &str, from: &str, to: &str) -> Result<bool, String> {
    if text.len() > MAX_JOB_MESSAGE_BYTES {
        return Err(format!("input is {} bytes, exceeds {MAX_JOB_MESSAGE_BYTES}", text.len()));
    }
    let message = serde_json::from_str::<FunctionCallMessageV1>(text)
        .map_err(|error| format!("invalid Function call JSON: {error}"))?;
    let FunctionCallMessageV1::Call { call } = message else {
        return Ok(false);
    };
    call.validate().map_err(|error| error.to_string())?;
    Ok(from == format!("creature:{}", call.executor_dispatch.payload.executor_creature)
        && to == format!("creature:{}", call.executor_dispatch.payload.target_creature))
}

fn parse_json(text: &str, byte_cap: usize) -> Result<Dynamic, String> {
    if text.len() > byte_cap {
        return Err(format!("input is {} bytes, exceeds {byte_cap}", text.len()));
    }
    let value = serde_json::from_str::<JsonValue>(text)
        .map_err(|error| format!("invalid JSON: {error}"))?;
    let mut nodes = 0;
    validate_json_value(&value, 0, &mut nodes)?;
    rhai::serde::to_dynamic(value)
        .map_err(|error| format!("cannot represent JSON in Rhai: {error}"))
}

fn stringify_json(value: &Dynamic, byte_cap: usize) -> Result<String, String> {
    let mut nodes = 0;
    validate_dynamic_json(value, byte_cap, 0, &mut nodes)?;
    let value = rhai::serde::from_dynamic::<JsonValue>(value)
        .map_err(|error| format!("value is not JSON-compatible: {error}"))?;
    let encoded =
        serde_json::to_string(&value).map_err(|error| format!("JSON encoding failed: {error}"))?;
    if encoded.len() > byte_cap {
        return Err(format!("output is {} bytes, exceeds {byte_cap}", encoded.len()));
    }
    Ok(encoded)
}

fn count_json_node(depth: usize, nodes: &mut usize) -> Result<(), String> {
    if depth > MAX_JSON_DEPTH {
        return Err(format!("nesting exceeds {MAX_JSON_DEPTH} levels"));
    }
    *nodes = nodes.saturating_add(1);
    if *nodes > MAX_JSON_NODES {
        return Err(format!("value count exceeds {MAX_JSON_NODES}"));
    }
    Ok(())
}

fn validate_json_value(value: &JsonValue, depth: usize, nodes: &mut usize) -> Result<(), String> {
    count_json_node(depth, nodes)?;
    match value {
        JsonValue::Null | JsonValue::Bool(_) | JsonValue::String(_) => Ok(()),
        JsonValue::Number(number) => {
            // Rhai's integer is i64. Refuse a JSON u64 that would otherwise become an opaque custom
            // Dynamic (or lose precision as f64); floating-point JSON remains supported.
            if number.as_i64().is_none() && number.as_u64().is_some() {
                Err("integer is outside Rhai's signed 64-bit range".into())
            } else if number.as_f64().is_some_and(f64::is_finite) {
                Ok(())
            } else {
                Err("number is outside Rhai's finite numeric range".into())
            }
        }
        JsonValue::Array(values) => {
            for value in values {
                validate_json_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
        JsonValue::Object(values) => {
            for value in values.values() {
                validate_json_value(value, depth + 1, nodes)?;
            }
            Ok(())
        }
    }
}

fn validate_dynamic_json(
    value: &Dynamic,
    byte_cap: usize,
    depth: usize,
    nodes: &mut usize,
) -> Result<(), String> {
    count_json_node(depth, nodes)?;
    // Shared Dynamics can be cyclic. JSON cannot, so refusing them before descending both preserves
    // JSON semantics and prevents a hostile value from making host-side traversal recurse forever.
    if value.is_shared() {
        return Err("shared/cyclic values are not JSON-compatible".into());
    }
    if value.is_unit() || value.is_bool() || value.is_int() {
        return Ok(());
    }
    if value.is_float() {
        return value
            .as_float()
            .map_err(|actual| format!("expected float, got {actual}"))
            .and_then(|number| {
                number
                    .is_finite()
                    .then_some(())
                    .ok_or_else(|| "non-finite floats are not JSON-compatible".into())
            });
    }
    if value.is_string() {
        let string = value
            .as_immutable_string_ref()
            .map_err(|actual| format!("expected string, got {actual}"))?;
        return (string.len() <= byte_cap)
            .then_some(())
            .ok_or_else(|| format!("string is {} bytes, exceeds {byte_cap}", string.len()));
    }
    if value.is_array() {
        let values =
            value.as_array_ref().map_err(|actual| format!("expected array, got {actual}"))?;
        for value in values.iter() {
            validate_dynamic_json(value, byte_cap, depth + 1, nodes)?;
        }
        return Ok(());
    }
    if value.is_map() {
        let values = value.as_map_ref().map_err(|actual| format!("expected map, got {actual}"))?;
        for (key, value) in values.iter() {
            if key.len() > byte_cap {
                return Err(format!("object key is {} bytes, exceeds {byte_cap}", key.len()));
            }
            validate_dynamic_json(value, byte_cap, depth + 1, nodes)?;
        }
        return Ok(());
    }
    Err(format!("Rhai type `{}` is not JSON-compatible", value.type_name()))
}

/// `cpu_ms` → operation budget. `0` ⇒ `0`, which is Rhai's "unlimited" sentinel for
/// `set_max_operations` (operator opt-out, mirroring the beast's unbounded-fuel default).
fn budget_to_ops(cpu_ms: u64, ops_per_ms: u64) -> u64 {
    cpu_ms.saturating_mul(ops_per_ms)
}

/// Whether `consumed` crossed `threshold_pct` of `limit`. `limit == 0` (no cap) never crosses.
/// Integer-exact via `u128` widening (no float). Identical in spirit to the beast's `crossed`.
fn crossed(consumed: u64, limit: u64, threshold_pct: u8) -> bool {
    if limit == 0 {
        return false;
    }
    (consumed as u128).saturating_mul(100) >= (limit as u128).saturating_mul(threshold_pct as u128)
}

/// Marshal an [`Envelope`] into the Rhai value a critter's `handle(env)` receives: an object map with
/// `payload` (a Blob), `text` (a bounded lossy UTF-8 view of the payload — Rhai has no Blob→String
/// builtin, so this is how a critter does string work), `text_truncated` (whether that view clipped
/// the original bytes), `schema` (string), `from` (an address string the critter can echo back to
/// `emit`), `to` (the local destination), and `corr` (int, when present).
fn marshal_env(env: &Envelope, mem_cap: u64) -> Dynamic {
    let mut m = RhaiMap::new();
    m.insert("payload".into(), Dynamic::from_blob(env.payload.clone()));
    // `text` is the payload decoded as lossy UTF-8 (invalid bytes → U+FFFD), but bounded before the
    // script sees it. The full byte payload stays available in `env.payload`; string-oriented
    // critters (`contains`, `kv-extract`) read `env.text` and can check `env.text_truncated` when a
    // complete text body matters.
    let (text, text_truncated) = bounded_lossy_text(&env.payload, text_preview_cap(mem_cap));
    m.insert("text".into(), text.into());
    m.insert("text_truncated".into(), text_truncated.into());
    m.insert("schema".into(), env.header.schema.clone().into());
    m.insert("from".into(), addr_to_string(&env.header.from).into());
    m.insert("to".into(), addr_to_string(&env.header.to).into());
    if let Some(corr) = env.header.corr {
        // Rhai's INT is i64; a corr above i64::MAX is exposed to the script as a wrapped negative.
        // Reply correlation is unaffected (`Dispatch::reply_to_env` copies the original u64), so this
        // only touches a script that reads `env.corr` itself — and corr is a small monotonic counter.
        m.insert("corr".into(), (corr as i64).into());
    }
    Dynamic::from_map(m)
}

fn text_preview_cap(mem_cap: u64) -> usize {
    usize::try_from(mem_cap.min(MAX_ENV_TEXT_BYTES as u64)).unwrap_or(MAX_ENV_TEXT_BYTES)
}

fn bounded_lossy_text(bytes: &[u8], max_bytes: usize) -> (String, bool) {
    let prefix = utf8_boundary_prefix(bytes, max_bytes);
    let truncated = prefix.len() < bytes.len();
    (String::from_utf8_lossy(prefix).into_owned(), truncated)
}

fn utf8_boundary_prefix(bytes: &[u8], max_bytes: usize) -> &[u8] {
    let mut end = max_bytes.min(bytes.len());
    if end == bytes.len() {
        return &bytes[..end];
    }
    while end > 0 && is_utf8_continuation(bytes[end]) {
        end -= 1;
    }
    &bytes[..end]
}

fn is_utf8_continuation(byte: u8) -> bool {
    byte & 0b1100_0000 == 0b1000_0000
}

/// A critter's return value → reply payload bytes. A Blob is taken verbatim; a string is its UTF-8
/// bytes; unit (`()`) means "no reply"; anything else is best-effort stringified.
fn dynamic_to_payload(value: &Dynamic) -> Option<Vec<u8>> {
    if value.is_unit() {
        None
    } else if value.is_blob() {
        value.clone().into_blob().ok()
    } else if value.is_string() {
        value.clone().into_string().ok().map(String::into_bytes)
    } else {
        Some(value.to_string().into_bytes())
    }
}

/// Render an [`Address`] to the same string vocabulary the router's `caps_allow` uses, so a critter
/// can read `env.from` and pass it straight back to `emit`. Federation wrappers (rare for a local
/// critter) fall back to a debug form.
fn addr_to_string(addr: &Address) -> String {
    match addr {
        Address::Creature(id) => format!("creature:{}", id.0),
        Address::Node(_, id) => format!("creature:{}", id.0),
        Address::Kernel => "kernel".to_string(),
        Address::Topic(t) => format!("topic:{}", t.0),
        Address::Role(r) => format!("role:{}", r.0),
        Address::Intent(i) => format!("intent:{}", i.outcome),
        other => format!("{other:?}"),
    }
}

/// Parse the address vocabulary a critter's `emit` accepts — the inverse of [`addr_to_string`] and
/// the same forms the `calls` capability gate matches (`router::caps_allow`). `None` for anything
/// unrecognized, so `emit` can return an honest error to the author.
fn parse_address(s: &str) -> Option<Address> {
    let s = s.trim();
    if s == "kernel" {
        return Some(Address::Kernel);
    }
    let (kind, rest) = s.split_once(':')?;
    match kind {
        "creature" => rest.parse::<u64>().ok().map(|n| Address::Creature(CreatureId(n))),
        "role" if !rest.is_empty() => Some(Address::Role(Role::new(rest))),
        "topic" if !rest.is_empty() => Some(Address::Topic(Topic::new(rest))),
        "intent" if !rest.is_empty() => {
            Some(Address::Intent(Intent { outcome: rest.to_string(), requirements: Vec::new() }))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_string_roundtrips_the_caps_vocabulary() {
        for s in ["kernel", "creature:7", "role:build", "topic:fitness", "intent:reverse-string"] {
            let addr = parse_address(s).expect("parses");
            assert_eq!(addr_to_string(&addr), s, "round-trip for {s}");
        }
    }

    #[test]
    fn parse_address_rejects_garbage() {
        for s in ["", "creature:", "creature:notanumber", "weird:x", "role:", "no-colon"] {
            assert!(parse_address(s).is_none(), "`{s}` must not parse");
        }
    }

    #[test]
    fn budget_to_ops_zero_cpu_is_unlimited_sentinel() {
        assert_eq!(budget_to_ops(0, DEFAULT_OPS_PER_MS), 0, "cpu_ms=0 ⇒ Rhai-unlimited (0)");
        assert_eq!(budget_to_ops(2, 1_000), 2_000);
        assert_eq!(budget_to_ops(u64::MAX, 1_000), u64::MAX, "saturates, never overflows");
    }

    #[test]
    fn text_preview_cap_uses_lower_of_mem_cap_and_hard_ceiling() {
        assert_eq!(text_preview_cap(64), 64);
        assert_eq!(text_preview_cap(MAX_ENV_TEXT_BYTES as u64 + 1), MAX_ENV_TEXT_BYTES);
    }

    #[test]
    fn bounded_lossy_text_marks_truncation_and_keeps_utf8_boundary() {
        let (text, truncated) = bounded_lossy_text("ééé".as_bytes(), 5);
        assert!(truncated);
        assert_eq!(text, "éé");
    }

    #[test]
    fn crossed_matches_threshold_arithmetic() {
        assert!(!crossed(50, 0, 90), "no cap never crosses");
        assert!(!crossed(89, 100, 90));
        assert!(crossed(90, 100, 90));
        assert!(crossed(100, 100, 0), "threshold 0 always crosses a capped, used budget");
    }

    #[test]
    fn json_helpers_roundtrip_a_typed_call_and_preserve_the_attempt() {
        let mut c = critter(
            r#"
            fn handle(env) {
                let message = json_parse(env.text);
                let invocation = message["call"];
                let result = #{
                    operation: "result",
                    result: #{
                        attempt: invocation.attempt,
                        outcome: #{
                            Ok: #{
                                kind: "inline",
                                value: #{ answer: invocation.input.value.value + 1 }
                            }
                        }
                    }
                };
                json_stringify(result)
            }
            "#,
        );
        let request = br#"{"operation":"call","call":{"attempt":{"job":"job-dynamic","number":7},"function":{"manifest_content_address":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","entrypoint":"add_one"},"input":{"kind":"inline","value":{"value":41}}}}"#;
        let first = reply_text(&c.handle(mem_env(request)));
        let second = reply_text(&c.handle(mem_env(request)));
        assert_eq!(first, second, "same in-memory value has deterministic JSON bytes");
        assert_eq!(
            first,
            r#"{"operation":"result","result":{"attempt":{"job":"job-dynamic","number":7},"outcome":{"Ok":{"kind":"inline","value":{"answer":42}}}}}"#,
            "object keys serialize in deterministic lexical order"
        );
        assert_eq!(
            serde_json::from_str::<JsonValue>(&first).expect("valid result JSON"),
            serde_json::json!({
                "operation": "result",
                "result": {
                    "attempt": { "job": "job-dynamic", "number": 7 },
                    "outcome": {
                        "Ok": { "kind": "inline", "value": { "answer": 42 } }
                    }
                }
            }),
            "the script copies the dynamic AttemptId verbatim into FunctionResultV1"
        );
    }

    #[test]
    fn json_helpers_enforce_bytes_depth_nodes_and_numeric_domain() {
        assert!(parse_json("{}", 1).unwrap_err().contains("exceeds"));
        assert!(parse_json("18446744073709551615", 64).unwrap_err().contains("signed 64-bit"));

        let mut nested = JsonValue::Null;
        for _ in 0..=MAX_JSON_DEPTH {
            nested = JsonValue::Array(vec![nested]);
        }
        let mut nodes = 0;
        assert!(validate_json_value(&nested, 0, &mut nodes).unwrap_err().contains("nesting"));

        let many = JsonValue::Array(vec![JsonValue::Null; MAX_JSON_NODES]);
        let mut nodes = 0;
        assert!(validate_json_value(&many, 0, &mut nodes).unwrap_err().contains("value count"));
    }

    #[test]
    fn json_stringify_rejects_non_json_rhai_values_and_oversized_output() {
        assert!(stringify_json(&Dynamic::from_blob(vec![1, 2, 3]), 64)
            .unwrap_err()
            .contains("not JSON-compatible"));
        assert!(stringify_json(&Dynamic::from("too long"), 4).unwrap_err().contains("exceeds"));
        assert!(stringify_json(&Dynamic::from_float(f64::NAN), 64)
            .unwrap_err()
            .contains("non-finite"));
    }

    // ---- persistent critter memory (Tier-1 #2) -----------------------------------------------

    /// Load a critter from source with an unbounded op budget (these tests exercise memory, not the
    /// CPU dial), returning its drivable instance.
    fn critter(src: &str) -> Box<dyn Creature> {
        let mut manifest = Manifest::new("mem-critter", "0.1.0", Backend::Critter, CRITTER_ABI_TAG);
        manifest.capabilities.cpu_ms = 0; // unbounded ops — don't let the budget interrupt a fill loop
        ScriptEngine
            .load(&Artifact::Bytes(src.as_bytes().to_vec()), &manifest)
            .expect("critter loads")
            .instance
    }

    fn mem_env(payload: &[u8]) -> Envelope {
        Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: Some(Address::Creature(CreatureId(1))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(9),
                commitment: None,
                schema: "text".into(),
                origin: None,
            },
            payload: payload.to_vec(),
        }
    }

    fn reply_text(out: &Outcome) -> String {
        let d = out.dispatches.last().expect("a reply dispatch");
        String::from_utf8(d.payload.clone()).expect("utf8 reply")
    }

    #[test]
    fn persistent_memory_survives_across_handle_calls() {
        // The counter lives only in the persistent store — a fresh Scope each call would lose it.
        let mut c = critter(
            r#"
            fn handle(env) {
                let n = mem_get("count");
                if type_of(n) == "()" { n = 0; }
                n += 1;
                mem_set("count", n);
                n.to_string()
            }
            "#,
        );
        assert_eq!(reply_text(&c.handle(mem_env(b""))), "1");
        assert_eq!(reply_text(&c.handle(mem_env(b""))), "2");
        assert_eq!(
            reply_text(&c.handle(mem_env(b""))),
            "3",
            "the counter accumulates across handle calls — state carried, not reset"
        );
    }

    #[test]
    fn persistent_memory_is_capped_refuse_new_at_capacity() {
        // The script adds distinct keys until `mem_set` refuses, then reports how many it stored —
        // exactly MAX_PERSIST_ENTRIES. Refuse-new at capacity, never unbounded growth.
        let mut c = critter(
            r#"
            fn handle(env) {
                let added = 0;
                for i in 0..100000 {
                    try {
                        mem_set("k" + i, i);
                        added += 1;
                    } catch (e) {
                        break;
                    }
                }
                added.to_string()
            }
            "#,
        );
        assert_eq!(
            reply_text(&c.handle(mem_env(b""))),
            MAX_PERSIST_ENTRIES.to_string(),
            "memory holds at most MAX_PERSIST_ENTRIES keys (refuse-new at capacity)"
        );
    }

    #[test]
    fn overwriting_an_existing_key_at_capacity_is_allowed() {
        // Refuse-NEW, not refuse-write: at capacity, re-setting an EXISTING key must still succeed.
        let mut c = critter(
            r#"
            fn handle(env) {
                for i in 0..100000 {
                    try { mem_set("k" + i, i); } catch (e) { break; }
                }
                mem_set("k0", 999);   // overwrite an existing key — must NOT throw
                mem_get("k0").to_string()
            }
            "#,
        );
        assert_eq!(
            reply_text(&c.handle(mem_env(b""))),
            "999",
            "an existing key stays overwritable even at capacity"
        );
    }

    #[test]
    fn mem_set_rejects_an_over_long_key() {
        // Keys are capped at MAX_PERSIST_KEY_BYTES so a hostile critter can't pile unbounded bytes
        // into the key namespace. An over-cap key throws (caught here); a normal key still stores.
        let over = MAX_PERSIST_KEY_BYTES + 1;
        let mut c = critter(&format!(
            r#"
            fn handle(env) {{
                let long_key = "";
                for i in 0..{over} {{ long_key += "k"; }}
                let rejected = false;
                try {{ mem_set(long_key, 1); }} catch (e) {{ rejected = true; }}
                mem_set("ok", 2);                       // a normal-length key still works
                rejected.to_string() + ":" + mem_get("ok").to_string()
            }}
            "#,
        ));
        assert_eq!(
            reply_text(&c.handle(mem_env(b""))),
            "true:2",
            "an over-cap key is refused while a normal-length key still stores"
        );
    }

    #[test]
    fn mem_del_frees_a_slot_and_get_returns_unit_for_absent() {
        let mut c = critter(
            r#"
            fn handle(env) {
                mem_set("a", 1);
                mem_del("a");
                let v = mem_get("a");
                type_of(v)        // "()" once deleted
            }
            "#,
        );
        assert_eq!(
            reply_text(&c.handle(mem_env(b""))),
            "()",
            "a deleted (or never-set) key reads back as unit"
        );
    }
}
