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
    Config as WtConfig, Engine as WtEngine, EngineWeak, Instance, Memory, Module, ResourceLimiter,
    Store, Trap, TypedFunc,
};

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

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

/// Wall-clock granularity for beast epoch interruption: the engine-global ticker advances the shared
/// epoch counter once per this interval, so a per-creature `wall_ms` cap is enforced to within one
/// tick. Fine enough to bound a runaway beast promptly; coarse enough that one thread per engine is
/// cheap. Operator-tunable per engine via [`WasmEngine::with_tick_ms`].
pub const DEFAULT_EPOCH_TICK_MS: u64 = 10;

/// Epoch deadline armed when a beast declares no `wall_ms` cap. Large enough never to trip in any
/// realistic run, small enough that `current_epoch + this` never overflows `u64`.
const UNLIMITED_EPOCH_DEADLINE: u64 = u64::MAX / 2;

pub struct WasmEngine {
    engine: WtEngine,
    fuel_per_ms: u64,
    /// The epoch ticker's cadence (ms) — also the wall-clock granularity (one tick = one interval).
    epoch_tick_ms: u64,
    /// Set on `Drop` so the engine-global epoch ticker exits its loop and is joined (no leaked thread).
    ticker_stop: Arc<AtomicBool>,
    ticker: Option<JoinHandle<()>>,
}

impl WasmEngine {
    /// Constructs with `DEFAULT_FUEL_PER_MS`, `consume_fuel(true)`, and `epoch_interruption(true)` on
    /// the wasmtime config, plus the engine-global epoch ticker at `DEFAULT_EPOCH_TICK_MS`.
    /// `consume_fuel`/`epoch_interruption` must be set at engine build time (not per-store), so they
    /// are always on. A creature with `cpu_ms == 0` gets `u64::MAX` fuel; one with `wall_ms == None`
    /// gets an effectively-unlimited epoch deadline — both effectively unlimited.
    pub fn new() -> Self {
        Self::with_tick_ms(DEFAULT_EPOCH_TICK_MS)
    }

    /// Like [`new`](WasmEngine::new) but with a custom epoch-tick granularity. A finer tick enforces
    /// `wall_ms` more precisely (and lets a test trip a wall cap fast); `tick_ms` is clamped to ≥1.
    pub fn with_tick_ms(tick_ms: u64) -> Self {
        let mut cfg = WtConfig::new();
        cfg.consume_fuel(true);
        // Wall-clock enforcement for the beast tier rides wasmtime epoch interruption — an
        // engine-build-time tunable on the shared engine. Once on, EVERY store must get an epoch
        // deadline set before a guest call (the default deadline of 0 traps immediately); we arm one
        // at load (so a wasm `start` fn doesn't trip) and refresh it per handle.
        cfg.epoch_interruption(true);
        let engine = WtEngine::new(&cfg).expect(
            "wasmtime config is fixed and valid; failure here is a bug in this constructor",
        );
        let epoch_tick_ms = tick_ms.max(1);

        // Exactly ONE engine-global ticker advances the shared epoch counter. It holds a WEAK engine
        // handle so it never keeps the engine alive (a strong clone would leak both the engine and
        // this thread); a stop flag set on `Drop` makes teardown prompt even while beasts — which
        // hold strong engine refs internally — are still loaded. N tickers would race the single
        // counter to N× the cadence, so the count is load-bearing: one, for the whole engine.
        let ticker_stop = Arc::new(AtomicBool::new(false));
        let weak: EngineWeak = engine.weak();
        let stop = ticker_stop.clone();
        let ticker = match std::thread::Builder::new().name("anima-wasm-epoch".into()).spawn(
            move || loop {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                match weak.upgrade() {
                    Some(e) => e.increment_epoch(),
                    None => break, // engine fully dropped — nothing left to tick
                }
                std::thread::sleep(Duration::from_millis(epoch_tick_ms));
            },
        ) {
            Ok(h) => Some(h),
            // **Fail loud, never silently fail open.** Without the ticker the epoch never advances, so
            // no `wall_ms` deadline can ever trip. We do NOT panic the whole engine on a transient
            // resource blip; instead we log the degradation here and `load()` refuses any beast that
            // *declares* a `wall_ms` cap (so the cap is never silently ignored). A beast with no wall
            // cap is unaffected.
            Err(e) => {
                eprintln!(
                    "anima(wasm): FAILED to spawn the engine-global epoch ticker ({e}); beast \
                     wall-clock (wall_ms) enforcement is DISABLED on this engine — load() will refuse \
                     any beast that declares a wall_ms cap rather than silently ignore it"
                );
                None
            }
        };

        WasmEngine { engine, fuel_per_ms: DEFAULT_FUEL_PER_MS, epoch_tick_ms, ticker_stop, ticker }
    }

    /// Override the fuel-per-ms factor (see `DEFAULT_FUEL_PER_MS`). Operator-tunable.
    pub fn with_fuel_per_ms(mut self, fuel_per_ms: u64) -> Self {
        self.fuel_per_ms = fuel_per_ms.max(1);
        self
    }
}

impl Drop for WasmEngine {
    fn drop(&mut self) {
        // Stop + join the engine-global epoch ticker so no thread outlives the engine.
        self.ticker_stop.store(true, Ordering::Relaxed);
        if let Some(h) = self.ticker.take() {
            let _ = h.join();
        }
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
    /// **Live** memory ceiling (bytes; `0` = unlimited). Shared with the kernel's [`BudgetControl`]
    /// so an `ExtendBudget` mem lift is observed by the very next `memory_growing` — no reach into
    /// the store on its drain thread.
    mem_bytes: Arc<AtomicU64>,
}

impl ResourceLimiter for BudgetLimits {
    fn memory_growing(
        &mut self,
        _current: usize,
        desired: usize,
        _maximum: Option<usize>,
    ) -> wasmtime::Result<bool> {
        let mem_bytes = self.mem_bytes.load(Ordering::Relaxed);
        if mem_bytes == 0 {
            return Ok(true); // unlimited (the default)
        }
        if (desired as u64) > mem_bytes {
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
        // **Fail-closed wall-clock:** if the engine's epoch ticker isn't running (its spawn failed at
        // construction — already logged), a declared `wall_ms` cap cannot be enforced. Refuse the load
        // rather than silently ignore the cap. A beast that declares no `wall_ms` loads normally.
        if manifest.capabilities.wall_ms.is_some() && self.ticker.is_none() {
            return Err(EngineError::Load(
                "beast declares a wall_ms cap but this engine's wall-clock epoch ticker is not \
                 running (its spawn failed); refusing to load rather than ignore the cap"
                    .to_string(),
            ));
        }
        let bytes = artifact.read_bytes()?;
        let module = Module::new(&self.engine, &bytes)
            .map_err(|e| EngineError::Load(format!("wasm compile: {e}")))?;

        // cpu_ms → fuel. Always set (the engine is built with consume_fuel=true). `cpu_ms == 0`
        // means "no budget" → effectively unlimited fuel.
        let fuel = budget_to_fuel(manifest.capabilities.cpu_ms, self.fuel_per_ms);
        // The live budget control owns the per-handle fuel/mem/wall ceilings the instance reads each
        // handle and the kernel lifts on an `ExtendBudget` grant. Beast enforces fuel + mem live; wall
        // is enforceable iff the engine's epoch ticker is running (a beast that *declares* a wall cap
        // with no ticker was already refused above, so this only governs a grant onto a no-wall beast).
        let budget = BudgetControl::new(
            fuel,
            manifest.capabilities.mem_bytes,
            manifest.capabilities.wall_ms.unwrap_or(0),
        )
        .enforcing(true, true, self.ticker.is_some());

        // Per-store budget limiter, reading the **live** mem cell so an `ExtendBudget` mem lift takes
        // effect on the next grow. `mem_bytes == 0` = unlimited; otherwise a grow past the cap
        // returns our typed sentinel error → wasmtime trap → `diagnose_trap` classifies it as
        // `BudgetBreach::Memory`. The wasm program can't quietly swallow this (vs. spec's silent
        // -1 on memory.grow failure) — that's exactly the shape the budget-kill needs.
        let limits = BudgetLimits { mem_bytes: budget.mem_cell() };

        let mut store = Store::new(&self.engine, StoreData { limits });
        store.limiter(|d: &mut StoreData| &mut d.limits as &mut dyn ResourceLimiter);
        store.set_fuel(fuel).map_err(|e| EngineError::Load(format!("wasm set_fuel: {e}")))?;

        // Epoch interruption is enabled engine-wide, so the store needs a non-tripping deadline for
        // instantiation (a wasm `start` function runs inside `Instance::new`). The real per-handle
        // wall deadline is armed fresh in `handle` from the creature's `wall_ms` cap.
        store.set_epoch_deadline(UNLIMITED_EPOCH_DEADLINE);

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
            // The per-handle wall ceiling is *live* too (ms; `0` = unlimited): read fresh each handle
            // from the shared cell, so an `ExtendBudget` wall lift takes effect on the next handle.
            live_wall_ms_cap: budget.wall_cell(),
            epoch_tick_ms: self.epoch_tick_ms,
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
        // An exceeded epoch deadline (the engine-global wall-clock ticker passed this store's
        // deadline) surfaces as `Trap::Interrupt` — the beast wall-clock breach (E3).
        Trap::Interrupt => Some(LimitKind::Wall),
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
    /// **The live per-envelope wall-clock cap (ms).** Read fresh on every `handle` from the shared
    /// cell the kernel lifts on an `ExtendBudget` wall grant. `n > 0` arms an epoch deadline of
    /// `ceil(n / tick)` ticks before each `handle`, so a beast that exceeds `n` ms of wall time traps
    /// with `Trap::Interrupt` → a `Hard` `Wall` budget signal. `0` (the default) → an
    /// effectively-unlimited deadline (never trips), mirroring the `cpu_ms == 0` fuel convention.
    live_wall_ms_cap: Arc<AtomicU64>,
    /// The engine-global ticker cadence (ms), cached to convert `wall_ms` to a number of epoch ticks.
    epoch_tick_ms: u64,
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
        // Arm the per-envelope wall-clock ceiling via the engine-global epoch (E3). Convert the
        // declared `wall_ms` cap to a number of ticks; `None`/`0` → an effectively-unlimited deadline
        // that never trips (mirrors the fuel `cpu_ms == 0` convention). Set fresh each handle so the
        // budget is genuinely per-envelope.
        let deadline_ticks = match self.live_wall_ms_cap.load(Ordering::Relaxed) {
            ms if ms > 0 => ms.div_ceil(self.epoch_tick_ms).max(1),
            _ => UNLIMITED_EPOCH_DEADLINE,
        };
        self.store.set_epoch_deadline(deadline_ticks);
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
    /// **Why no Wall here**: wall-clock is enforced as a *Hard* trap (an exceeded epoch deadline →
    /// `Trap::Interrupt` → `LimitKind::Wall`), not as a Warn. There is no cheap "fraction of the wall
    /// budget consumed" reading to threshold mid-handle the way fuel/memory have, so the engine emits
    /// no Wall Warn; the `wall_ms_elapsed` scalar is still shipped in every vector for a policy to read.
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
            // Wall: consumed is the ms elapsed; limit is the declared per-envelope `wall_ms` cap
            // (0 if somehow unset — a Wall trap shouldn't arise without a cap).
            LimitKind::Wall => (wall_ms_elapsed, self.live_wall_ms_cap.load(Ordering::Relaxed)),
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
