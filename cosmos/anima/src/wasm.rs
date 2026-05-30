//! The beast (WASM) tier: real `wasmtime`. First-class alongside native (**R3**).
//!
//! The host marshals an envelope's **payload** into the guest's linear memory, calls the guest, and
//! reads the result back — the guest sees only bytes in its own memory, never a host pointer, which
//! is exactly why a beast is a safe citizen and the home of untrusted code. The minimal guest ABI:
//! `memory` + `alloc(len) -> ptr` + `handle(ptr, len) -> i64` (packed `ptr<<32 | len`). The full
//! envelope-into-wasm + host imports land later; this is enough to prove the tier end-to-end.
//!
//! **Capability & sandbox enforcement.** The manifest's [`Capabilities`] become real for the
//! beast tier here:
//! - `cpu_ms` → wasmtime fuel via [`WasmEngine::fuel_per_ms`]: cpu-budget exhaustion produces a
//!   `Trap::OutOfFuel` → a `Hard`-level [`BudgetSignal`] of [`LimitKind::Fuel`] on the outcome.
//! - `mem_bytes` → a custom `ResourceLimiter` capping linear-memory growth; a refused grow
//!   produces a typed sentinel error → trap → a `Hard`-level [`BudgetSignal`] of
//!   [`LimitKind::Memory`].
//! - `net` and `fs` → currently *closed by construction* (the beast has no host imports at all).
//!   The day a host import lands in a richer guest ABI, it'll be gated on the capability declared
//!   here — the seam is the existing import vocabulary, not a new manifest field.
//!
//! The kernel observes a `budget_signal` outcome and publishes a `BudgetSignalEvent` proprio
//! event. What happens *next* (kill, demote tier, raise the budget, grant grace) lives in an
//! injected policy creature, never in the substrate.
//!
//! A successful handle that crosses `budget_warn_at` emits a `Warn` signal, and the
//! live per-handle fuel ceiling is exposed through [`BudgetControl`] so an injected policy can grant
//! `KernelControl::ExtendBudget`; the next handle reads the lifted ceiling. The [`BudgetVector`] is
//! filled best-effort with the scalars wasmtime exposes cheaply (`consumed`, `limit`); fields a
//! richer engine would measure (wall ms, dispatches-this-envelope) stay at zero.

use aether::{
    ffi::ABI_TAG, BudgetSignal, BudgetVector, Creature, CreatureCtx, Envelope, LimitKind, Outcome,
};
use sigil::{Backend, Manifest};
use wasmtime::{
    Config as WtConfig, Engine as WtEngine, Instance, Memory, Module, ResourceLimiter, Store, Trap,
    TypedFunc,
};

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::{Artifact, BudgetControl, Engine, EngineError, LoadedModule};

/// Sentinel error wrapped inside wasmtime's `anyhow::Error` chain to mark a grow that the
/// limiter refused for budget reasons. We use a typed marker (not a magic string) so
/// `diagnose_trap` can downcast cleanly and tell budget-grow-refusals apart from other
/// memory-related traps.
#[derive(Debug)]
struct BudgetMemoryRefused;

impl std::fmt::Display for BudgetMemoryRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("memory grow refused by M4 budget")
    }
}

impl std::error::Error for BudgetMemoryRefused {}

/// Default fuel cost per declared millisecond. Wasmtime fuel is per-instruction, not per-second;
/// this constant is the operator-visible "how generous is each ms" knob, configurable on the
/// engine. The value is intentionally a round-million — generous enough that small busy-loops
/// terminate in a tight number of ms, tight enough that a `loop { nop }` runs out fast. Operators
/// who profile their workloads tune this for their fleet.
pub const DEFAULT_FUEL_PER_MS: u64 = 1_000_000;

pub struct WasmEngine {
    engine: WtEngine,
    fuel_per_ms: u64,
}

impl WasmEngine {
    /// Constructs with `DEFAULT_FUEL_PER_MS` and `consume_fuel(true)` on the wasmtime config.
    /// `consume_fuel` must be set at engine build time (not per-store), so we enable it whether or
    /// not any given creature declares `cpu_ms`. A creature with `cpu_ms == 0` simply gets `u64::MAX`
    /// fuel on its store — effectively unlimited.
    pub fn new() -> Self {
        let mut cfg = WtConfig::new();
        cfg.consume_fuel(true);
        let engine = WtEngine::new(&cfg).expect(
            "wasmtime config is fixed and valid; failure here is a bug in this constructor",
        );
        WasmEngine { engine, fuel_per_ms: DEFAULT_FUEL_PER_MS }
    }

    /// Override the fuel-per-ms factor (see `DEFAULT_FUEL_PER_MS`). Operator-tunable.
    pub fn with_fuel_per_ms(mut self, fuel_per_ms: u64) -> Self {
        self.fuel_per_ms = fuel_per_ms.max(1);
        self
    }
}

impl Default for WasmEngine {
    fn default() -> Self {
        WasmEngine::new()
    }
}

/// What rides inside `Store<T>`. Holds the resource-limiter and (later) any host-import state.
/// Keeping a typed struct (vs `()`) gives `Store::limiter`'s closure something to project from.
struct StoreData {
    limits: BudgetLimits,
}

/// The `ResourceLimiter`. `mem_bytes == 0` means "unlimited" (the default); otherwise refuse
/// any grow past the cap by returning [`BudgetMemoryRefused`] as an `Err`, which wasmtime
/// surfaces as a trap. We deliberately do NOT use wasmtime's bundled `StoreLimits`: that one
/// emits a generic `anyhow!("forcing trap when growing memory…")` string we'd have to brittle-
/// match. A typed sentinel error is the durable seam.
struct BudgetLimits {
    mem_bytes: u64,
}

impl ResourceLimiter for BudgetLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        if self.mem_bytes == 0 {
            return Ok(true); // unlimited (the default)
        }
        if (desired as u64) > self.mem_bytes {
            // Refuse-as-trap: returning Err short-circuits the grow into a trap whose error chain
            // contains our typed sentinel, which `diagnose_trap` keys off to classify as a Memory
            // budget breach. (Returning `Ok(false)` would silently report -1 to the wasm program,
            // which the guest could swallow — exactly the wrong shape for a budget gate.)
            Err(BudgetMemoryRefused.into())
        } else {
            Ok(true)
        }
    }

    fn table_growing(
        &mut self,
        _current: usize,
        _desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        // Tables aren't budgeted — they're tiny and operator-tunable later if needed.
        Ok(true)
    }
}

impl Engine for WasmEngine {
    fn backend(&self) -> Backend {
        Backend::Beast
    }

    fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        if manifest.abi.backend != Backend::Beast {
            return Err(EngineError::WrongBackend {
                engine: Backend::Beast,
                manifest: manifest.abi.backend,
            });
        }
        if manifest.abi.abi_tag != ABI_TAG {
            return Err(EngineError::AbiMismatch {
                expected: ABI_TAG.to_string(),
                got: manifest.abi.abi_tag.clone(),
            });
        }
        let bytes = artifact.read_bytes()?;
        let module = Module::new(&self.engine, &bytes)
            .map_err(|e| EngineError::Load(format!("wasm compile: {e}")))?;

        // Per-store budget limiter. `mem_bytes == 0` = unlimited; otherwise a grow past the cap
        // returns our typed sentinel error → wasmtime trap → `diagnose_trap` classifies it as
        // `BudgetBreach::Memory`. The wasm program can't quietly swallow this (vs. spec's silent
        // -1 on memory.grow failure) — that's exactly the shape the budget-kill needs.
        let limits = BudgetLimits { mem_bytes: manifest.capabilities.mem_bytes };

        let mut store = Store::new(&self.engine, StoreData { limits });
        store.limiter(|d: &mut StoreData| &mut d.limits as &mut dyn ResourceLimiter);

        // cpu_ms → fuel. Always set (the engine is built with consume_fuel=true). `cpu_ms == 0`
        // means "no budget" → effectively unlimited fuel.
        let fuel = budget_to_fuel(manifest.capabilities.cpu_ms, self.fuel_per_ms);
        store.set_fuel(fuel).map_err(|e| EngineError::Load(format!("wasm set_fuel: {e}")))?;

        let instance = Instance::new(&mut store, &module, &[])
            .map_err(|e| EngineError::Load(format!("wasm instantiate: {e}")))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or_else(|| EngineError::Load("wasm export `memory` missing".into()))?;
        let alloc = instance
            .get_typed_func::<(i32,), i32>(&mut store, "alloc")
            .map_err(|e| EngineError::Load(format!("wasm export `alloc`: {e}")))?;
        let handle = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "handle")
            .map_err(|e| EngineError::Load(format!("wasm export `handle`: {e}")))?;
        let cpu_ms = manifest.capabilities.cpu_ms;
        let mem_bytes_cap = manifest.capabilities.mem_bytes;
        // Clamp the operator-declared warn threshold to [0, 100]; values >100 (a malformed
        // manifest) collapse to "always warn" rather than refusing the load. Admission could
        // also reject them, but engine-side clamp is the floor — never trust the input.
        let budget_warn_at = manifest.capabilities.budget_warn_at.map(|p| p.min(100));
        // The per-handle fuel ceiling is *live*: a shared atomic the instance reads
        // each handle and the kernel can lift on a grant (`ExtendBudget`). Seeded with the declared
        // budget (`fuel` above), so behaviour is identical until a grant raises it.
        let budget = BudgetControl::new(fuel);
        let inst = WasmInstance {
            store,
            memory,
            alloc,
            handle,
            cpu_ms,
            mem_bytes_cap,
            envelopes_handled: 0,
            budget_warn_at,
            live_fuel_cap: budget.cell(),
        };
        Ok(LoadedModule::new(Box::new(inst), Box::new(())).with_budget(budget))
    }
}

/// Map `cpu_ms` to a wasmtime fuel quota. `cpu_ms == 0` (the unset default) means "no budget" →
/// `u64::MAX` (effectively unlimited). Otherwise multiply, **saturating** so an oversize ms doesn't
/// silently wrap to a tiny budget.
fn budget_to_fuel(cpu_ms: u64, fuel_per_ms: u64) -> u64 {
    if cpu_ms == 0 {
        u64::MAX
    } else {
        cpu_ms.saturating_mul(fuel_per_ms)
    }
}

/// True iff `consumed * 100 >= limit * threshold_pct` without overflowing.
/// Uses `u128` for the multiplication: `limit` (u64) × `threshold` (≤100) cannot overflow u128.
/// Guards against `limit == 0` (no cap declared) — never crosses; returns false.
fn crossed(consumed: u64, limit: u64, threshold_pct: u8) -> bool {
    if limit == 0 {
        return false;
    }
    let lhs = (consumed as u128).saturating_mul(100);
    let rhs = (limit as u128).saturating_mul(threshold_pct as u128);
    lhs >= rhs
}

/// Inspect a wasmtime error to extract a [`LimitKind`], if any.
/// - `OutOfFuel` is unambiguous (`cpu_ms`).
/// - Our `BudgetMemoryRefused` sentinel is the durable seam for `mem_bytes` — present in the error
///   chain because our `BudgetLimits` returned it; matched here by `downcast_ref`.
/// - `AllocationTooLarge` covers the case where the guest's initial-allocation is itself larger
///   than what the limiter is willing to allow.
///
/// Anything else (StackOverflow, UnreachableCodeReached, …) is a "creature bug" trap, classified
/// as `None` so the kernel's existing no-reply path picks it up — not a budget breach.
fn diagnose_trap(err: &wasmtime::Error) -> Option<LimitKind> {
    if err.chain().any(|c| c.downcast_ref::<BudgetMemoryRefused>().is_some()) {
        return Some(LimitKind::Memory);
    }
    match err.downcast_ref::<Trap>()? {
        Trap::OutOfFuel => Some(LimitKind::Fuel),
        Trap::AllocationTooLarge => Some(LimitKind::Memory),
        _ => None,
    }
}

struct WasmInstance {
    store: Store<StoreData>,
    memory: Memory,
    alloc: TypedFunc<(i32,), i32>,
    handle: TypedFunc<(i32, i32), i64>,
    /// The operator-declared CPU budget (ms). The *actual* per-handle fuel ceiling
    /// lives in [`Self::live_fuel_cap`] (which a grant can lift); `cpu_ms` is kept only as the
    /// "was a CPU cap declared?" marker that gates fuel-Warn applicability (`cpu_ms > 0`) — a
    /// creature with no declared cap is never "near" a limit.
    cpu_ms: u64,
    /// Cached for the [`BudgetVector::limit`] field on a Memory-kind signal. The cap also lives in
    /// `BudgetLimits` inside the store, but reading it through `store.data()` would borrow `store`
    /// during the breach-classification path we want unencumbered.
    mem_bytes_cap: u64,
    /// **[`BudgetVector::envelopes_since_load`].** Bumped on entry to each
    /// `handle`; a policy creature reading the breach vector can weigh first-call behavior
    /// differently from 100th-call behavior without per-creature bookkeeping of its own.
    envelopes_handled: u64,
    /// **Operator-declared advisory threshold.** `Some(p)` with `p ∈ 0..=100`
    /// asks the engine to emit a `BudgetSignal::warn(...)` after a successful handle when the
    /// consumed fraction of the relevant cap crosses `p%`. `None` (the default) disables the check
    /// entirely — zero overhead, zero behaviour change.
    /// Checked per-dimension: fuel uses `cpu_ms`, memory uses `mem_bytes_cap`; dimensions with
    /// no cap (`0`) are skipped (you can't be "near" a non-existent limit). Clamped on load to
    /// [0, 100] so a malformed >100 value never multiplies past `u64`.
    budget_warn_at: Option<u8>,
    /// **The live per-handle fuel ceiling.** Read fresh on every `handle` (replacing the
    /// fixed `budget_to_fuel(cpu_ms, …)`), so a `KernelControl::ExtendBudget` grant — which writes
    /// this atomic through the [`BudgetControl`] the kernel holds — lifts the budget for the
    /// creature's *next* handle without touching the instance on its drain thread. Seeded at load to
    /// the declared budget, so an ungranted creature behaves exactly as before.
    live_fuel_cap: Arc<AtomicU64>,
}

impl Creature for WasmInstance {
    fn bind(&mut self, _ctx: CreatureCtx) {
        // The beast is a pure function of its payload; it needs no bus authority. (Host imports
        // for proactive sends land with the later guest ABI.)
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Refill fuel to the *live* per-envelope ceiling BEFORE running. This reads the
        // shared atomic so a granted `ExtendBudget` takes effect here; absent a grant it equals the
        // declared `budget_to_fuel(cpu_ms, fuel_per_ms)` seeded at load. See `live_fuel_cap` doc.
        let fuel = self.live_fuel_cap.load(Ordering::Relaxed);
        if let Err(e) = self.store.set_fuel(fuel) {
            // Fuel can't be set (engine config disagrees with the store). Effectively unreachable
            // (fuel consumption is enabled at store construction), but if it ever happened we'd
            // silently return "no reply"; surface it instead. Not a budget breach — a
            // misconfiguration, not a runtime breach. (T17)
            eprintln!("anima(wasm): set_fuel({fuel}) failed: {e}; returning no reply");
            return Outcome::none();
        }
        self.envelopes_handled = self.envelopes_handled.saturating_add(1);
        let started = std::time::Instant::now();
        let result = self.run(&env.payload);
        let wall_ms_elapsed = started.elapsed().as_millis() as u64;
        match result {
            Ok(out) => {
                // **Engine-emitted Warn.** After a
                // *successful* handle (no trap), if the operator opted in via `budget_warn_at`,
                // check whether the consumed fraction crossed the declared threshold on any
                // capped dimension. If yes, attach a `Warn`-level signal alongside the reply.
                // This is the non-Hard `BudgetSignal` path the [`policy_budget::BudgetGraceful`]
                // creature's grace branch needs exercised by real beast execution, not just direct
                // injection.
                //
                // Fuel-first: it's the only universally-applicable kind today (`cpu_ms` is
                // checked on every wasm; `mem_bytes` only matters for grow-pressured guests).
                // Memory Warn falls through to the same branch when fuel doesn't cross but
                // memory does. We emit *one* signal per handle (the first dimension to cross);
                // an engine that wanted both could be made richer, but one-per-handle keeps the
                // bus traffic predictable.
                let signal = self.maybe_warn(fuel, wall_ms_elapsed);
                let mut outcome = Outcome::reply(&env, out);
                outcome.budget_signal = signal;
                outcome
            }
            Err(EngineError::BudgetBreach(kind)) => {
                // Build the full [`BudgetSignal`] (level=Hard, kind, vector)
                // at trap time, so the kernel's proprio event and any injected policy creature get
                // the trajectory scalars from which they can compute their own tolerance / velocity /
                // curve model. The Warn-level signal is now emitted on the success path above when
                // `budget_warn_at` is declared; Hard remains the trap-time signal.
                let vector = self.measure_vector(kind, fuel, wall_ms_elapsed);
                Outcome::budget_signal(BudgetSignal::hard(kind, vector))
            }
            Err(e) => {
                // A trapping/faulting guest (not a budget breach) produces no reply and never
                // crashes the host (R9). The kernel observes the absence and may apoptose the beast
                // via the fitness-fail path — but the classified trap reason was being DISCARDED,
                // leaving the operator no clue why a beast went silent. Surface it. The instance
                // holds no CreatureId (`bind` ignores ctx), so identify the work by the inbound
                // envelope's from/seq. (T8)
                eprintln!(
                    "anima(wasm): beast trapped on envelope from {:?} (seq={}); no reply: {e}",
                    env.header.from, env.header.seq
                );
                Outcome::none()
            }
        }
    }
}

impl WasmInstance {
    /// Decide whether to emit a `Warn`-level [`BudgetSignal`] after a successful handle. Returns
    /// `None` if no threshold is declared, no capped dimension exists, or no dimension crossed.
    /// Checks fuel first (the universal dimension), then memory; emits one signal for the first
    /// crossing. Bus volume is bounded — one Warn per handle at most.
    ///
    /// **Why no Wall here**: per-envelope wall-time isn't a substrate-enforced limit
    /// (`LimitKind::Wall` is reserved in [`aether`]). The `wall_ms_elapsed` scalar is still
    /// shipped in the vector for an injected policy that wants to read it, but the engine
    /// doesn't itself trigger Wall Warns.
    fn maybe_warn(&mut self, fuel_initial: u64, wall_ms_elapsed: u64) -> Option<BudgetSignal> {
        let threshold = self.budget_warn_at?; // `?` returns None if the operator opted out.
                                              // Fuel — only when the operator declared a CPU cap (cpu_ms > 0).
        if self.cpu_ms > 0 {
            let remaining = self.store.get_fuel().unwrap_or(fuel_initial);
            let consumed = fuel_initial.saturating_sub(remaining);
            if crossed(consumed, fuel_initial, threshold) {
                let vector = BudgetVector {
                    consumed,
                    limit: fuel_initial,
                    dispatches_this_envelope: 0,
                    wall_ms_elapsed,
                    envelopes_since_load: self.envelopes_handled,
                };
                return Some(BudgetSignal::warn(LimitKind::Fuel, vector));
            }
        }
        // Memory — only when the operator declared a memory cap. Best-effort: we measure live
        // linear-memory size after the handle returned. A creature that allocates and frees
        // within the handle window won't appear "near"; a creature that retains memory will.
        if self.mem_bytes_cap > 0 {
            let consumed = self.memory.data_size(&self.store) as u64;
            if crossed(consumed, self.mem_bytes_cap, threshold) {
                let vector = BudgetVector {
                    consumed,
                    limit: self.mem_bytes_cap,
                    dispatches_this_envelope: 0,
                    wall_ms_elapsed,
                    envelopes_since_load: self.envelopes_handled,
                };
                return Some(BudgetSignal::warn(LimitKind::Memory, vector));
            }
        }
        None
    }

    /// Fill a [`BudgetVector`] from what wasmtime exposes cheaply at trap time. Best-effort: a
    /// field the engine can't measure without extra work is zero — the *shape* is the
    /// commitment, not per-field exactitude. `dispatches_this_envelope` is always zero here
    /// because the engine can't see the dispatches list (the kernel sees that, and a richer
    /// signal-publishing path could merge it in).
    fn measure_vector(
        &mut self,
        kind: LimitKind,
        fuel_initial: u64,
        wall_ms_elapsed: u64,
    ) -> BudgetVector {
        let (consumed, limit) = match kind {
            LimitKind::Fuel => {
                let remaining = self.store.get_fuel().unwrap_or(0);
                (fuel_initial.saturating_sub(remaining), fuel_initial)
            }
            LimitKind::Memory => {
                let current = self.memory.data_size(&self.store) as u64;
                (current, self.mem_bytes_cap)
            }
            LimitKind::Wall => (wall_ms_elapsed, 0),
        };
        BudgetVector {
            consumed,
            limit,
            dispatches_this_envelope: 0,
            wall_ms_elapsed,
            envelopes_since_load: self.envelopes_handled,
        }
    }
}

impl WasmInstance {
    fn run(&mut self, input: &[u8]) -> Result<Vec<u8>, EngineError> {
        let len = input.len() as i32;
        let ptr = self.alloc.call(&mut self.store, (len,)).map_err(|e| classify(&e))?;
        self.memory
            .write(&mut self.store, ptr as usize, input)
            .map_err(|e| EngineError::Load(format!("wasm mem write: {e}")))?;
        let packed = self.handle.call(&mut self.store, (ptr, len)).map_err(|e| classify(&e))?;
        let out_ptr = ((packed >> 32) as u32) as usize;
        let out_len = ((packed & 0xffff_ffff) as u32) as usize;
        let data = self.memory.data(&self.store);
        let end = out_ptr
            .checked_add(out_len)
            .ok_or_else(|| EngineError::Load("wasm out range overflow".into()))?;
        if end > data.len() {
            return Err(EngineError::Load("wasm out range out of bounds".into()));
        }
        Ok(data[out_ptr..end].to_vec())
    }
}

/// Turn a wasmtime error into the right [`EngineError`]: a budget breach gets its own variant the
/// instance maps to `Outcome::budget_breach`; everything else surfaces as a plain `Load` error
/// (the kernel's existing "no reply / panic-isolated" path picks it up).
fn classify(err: &wasmtime::Error) -> EngineError {
    if let Some(kind) = diagnose_trap(err) {
        EngineError::BudgetBreach(kind)
    } else {
        EngineError::Load(format!("wasm trap: {err}"))
    }
}
