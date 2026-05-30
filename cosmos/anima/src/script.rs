//! The critter (script) tier — a real, metered, sandboxed Rhai interpreter.
//!
//! The third creature tier: cheaper and more ephemeral than a native `daemon` or a WASM
//! `beast` — ideal for high-variation experiments and glue. Like the beast, it is **contained by
//! construction**: a freshly built [`rhai::Engine`] reaches nothing (no filesystem, network, clock,
//! process, or rand — Rhai has no such builtins, and the `no_time` feature strips even
//! `timestamp()`). We compile Rhai with `no_module` and additionally turn off runtime code-gen
//! (`disable_symbol("eval")`) so a critter is exactly its signed, static source; the only host
//! function we register is `emit`, whose effect is a [`Dispatch`] the kernel routes through the one
//! capability-gated bus path. So `net:none` / `fs:[]` hold for a critter the same way they hold for a
//! beast — properties of the loader, not runtime checks — and the router's `calls` gate
//! applies unchanged at its single choke point.
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
//! [`BudgetSignal`] — **not** the byte-exact `ResourceLimiter` the beast tier has; `Wall`
//! stays reserved.
//!
//! The artifact is UTF-8 Rhai **source text** (deterministic bytes, content-addressable, no
//! interpreter-version serialization lock-in). A critter defines `fn handle(env)`; its return value
//! becomes a reply to the envelope's reply target, and it may `emit(addr, bytes)` additional
//! dispatches.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aether::{
    Address, BudgetSignal, BudgetVector, Creature, CreatureCtx, CreatureId, Dispatch, Envelope,
    Intent, LimitKind, Outcome, Role, Topic,
};
use rhai::{Blob, Dynamic, Engine as RhaiEngine, EvalAltResult, Map as RhaiMap, Scope, AST};
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

/// Maximum parse-time expression nesting depth (global scope, then function body). Rhai's *default*
/// caps are **profile-dependent** — halved in debug builds (function-body depth 16 debug vs 32
/// release) to keep the parser's own recursion off a smaller test stack. Left unset, a critter could
/// compile under `--release` yet be rejected under `cargo test`/debug, and the loader
/// ([`ScriptEngine`]) and the author gate (`build-critter`) could disagree on what is valid. We pin
/// both engines to Rhai's documented **non-debug** defaults so the depth limit is identical across
/// build profiles and across the two engines. (Bounding parse depth also caps parser stack use.)
pub const MAX_EXPR_DEPTH: usize = 64;
pub const MAX_FN_EXPR_DEPTH: usize = 32;

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
        let src = String::from_utf8(artifact.read_bytes()?)
            .map_err(|e| EngineError::Load(format!("critter source is not valid UTF-8: {e}")))?;

        // `cpu_ms == 0` ⇒ 0 ops ⇒ Rhai's "unlimited" sentinel (`set_max_operations(0)`), the same
        // operator opt-out the beast's `cpu_ms == 0` ⇒ unbounded-fuel gives.
        let ops_cap = budget_to_ops(manifest.capabilities.cpu_ms, DEFAULT_OPS_PER_MS);
        let budget = BudgetControl::new(ops_cap);

        // Per-handle observability shared with the running instance: `outbox` collects the dispatches
        // the script `emit`s (the kernel sends them, so its `calls` gate and local-FIFO ordering
        // both apply); `ops_observed` is written by the progress hook so a handle can report
        // `consumed` for the budget vector.
        let outbox: Arc<Mutex<Vec<Dispatch>>> = Arc::new(Mutex::new(Vec::new()));
        let ops_observed = Arc::new(AtomicU64::new(0));

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
            engine.on_progress(move |ops| {
                obs.store(ops, Ordering::Relaxed);
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
            live_ops_cap: budget.cell(),
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
    /// The live per-handle operation ceiling, shared with the kernel via [`BudgetControl`]. Read
    /// fresh each `handle` so a granted `ExtendBudget` lifts the next call.
    live_ops_cap: Arc<AtomicU64>,
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
        // Refill the operation budget to the *live* per-envelope ceiling BEFORE running:
        // this reads the shared atomic, so a granted `ExtendBudget` takes effect here; absent a grant
        // it equals the `cpu_ms`-derived cap seeded at load.
        let ops_cap = self.live_ops_cap.load(Ordering::Relaxed);
        self.engine.set_max_operations(ops_cap);
        self.ops_observed.store(0, Ordering::Relaxed);
        if let Ok(mut guard) = self.outbox.lock() {
            guard.clear();
        }
        self.envelopes_handled = self.envelopes_handled.saturating_add(1);

        let env_value = marshal_env(&env);
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
                // `ErrorTerminated` is matched alongside defensively (a future
                // progress-hook abort path); today the hook only measures and never terminates.
                EvalAltResult::ErrorTooManyOperations(_) | EvalAltResult::ErrorTerminated(_, _) => {
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

impl ScriptInstance {
    fn drain_outbox(&self) -> Vec<Dispatch> {
        match self.outbox.lock() {
            Ok(mut guard) => std::mem::take(&mut *guard),
            Err(_) => Vec::new(),
        }
    }
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
/// `payload` (a Blob), `text` (the payload as a lossy UTF-8 string — Rhai has no Blob→String builtin,
/// so this is the only way a critter does string work), `schema` (string), `from` (an address string
/// the critter can echo back to `emit`), and `corr` (int, when present).
fn marshal_env(env: &Envelope) -> Dynamic {
    let mut m = RhaiMap::new();
    m.insert("payload".into(), Dynamic::from_blob(env.payload.clone()));
    // `text` is the payload decoded as lossy UTF-8 (invalid bytes → U+FFFD). The critter engine
    // exposes no Blob→String conversion, so string-oriented critters (`contains`, `kv-extract`) read
    // `env.text`; byte-oriented ones (`reverse`, `uppercase`, `rot13`) stay on `env.payload`.
    m.insert("text".into(), String::from_utf8_lossy(&env.payload).into_owned().into());
    m.insert("schema".into(), env.header.schema.clone().into());
    m.insert("from".into(), addr_to_string(&env.header.from).into());
    if let Some(corr) = env.header.corr {
        // Rhai's INT is i64; a corr above i64::MAX is exposed to the script as a wrapped negative.
        // Reply correlation is unaffected (`Dispatch::reply_to_env` copies the original u64), so this
        // only touches a script that reads `env.corr` itself — and corr is a small monotonic counter.
        m.insert("corr".into(), (corr as i64).into());
    }
    Dynamic::from_map(m)
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
    fn crossed_matches_threshold_arithmetic() {
        assert!(!crossed(50, 0, 90), "no cap never crosses");
        assert!(!crossed(89, 100, 90));
        assert!(crossed(90, 100, 90));
        assert!(crossed(100, 100, 0), "threshold 0 always crosses a capped, used budget");
    }
}
