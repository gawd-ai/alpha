//! anima — the per-tier loaders behind one [`Engine`] trait.
//!
//! The kernel holds `Box<dyn Engine>` per tier and picks by one manifest field (`abi.backend`), so
//! native and beast load through the *same* path (**R1**, **R3**). Each engine produces a
//! [`LoadedModule`] — a `Box<dyn Creature>` plus the tier resources that must outlive it. The
//! **unload ordering** lives in one place: [`Engine::unload`] runs `shutdown`, then drops
//! the instance, then drops resources (native: `dlclose` **last**).

mod native;
mod script;
mod wasm;

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aether::{Creature, Deadline, LimitKind};
use sigil::{Backend, Manifest};

pub use native::NativeEngine;
pub use script::ScriptEngine;
pub use wasm::WasmEngine;

/// What to load: a path on disk (native needs this — `dlopen` takes a path) or raw bytes (a shipped
/// artifact; beasts compile straight from bytes).
///
/// `Clone` is the reload-loop requirement: the loop owns one `Artifact` spec and re-loads from it
/// every cycle without inventing a fresh `PathBuf` or copying `Vec<u8>` at the call site.
#[derive(Clone)]
pub enum Artifact {
    Path(PathBuf),
    Bytes(Vec<u8>),
}

impl Artifact {
    pub fn read_bytes(&self) -> Result<Vec<u8>, EngineError> {
        match self {
            Artifact::Path(p) => std::fs::read(p)
                .map_err(|e| EngineError::Load(format!("read {}: {e}", p.display()))),
            Artifact::Bytes(b) => Ok(b.clone()),
        }
    }
}

/// A handle to a loaded creature's **live per-handle fuel ceiling**. It exists so the
/// kernel can *lift* a creature's budget — honoring a `KernelControl::ExtendBudget` grant — **without
/// reaching into the instance running on its own drain thread**. The engine shares one end with the
/// running instance (which reads the ceiling each `handle`); the kernel keeps the other and writes to
/// it on a grant. Lock-free (`Arc<AtomicU64>`); the next handle observes the new ceiling.
///
/// The **beast (wasm)** tier (per-handle fuel) and the **critter (script)** tier (per-handle
/// operation budget) populate it, so an `ExtendBudget` grant lifts a running creature of either tier.
/// **Native** is trusted-by-admission (no metering), so its [`LoadedModule::budget`] is `None` and a
/// grant to it is an honest no-op (not a silent lie — the kernel reports it via `extend_budget`).
#[derive(Clone)]
pub struct BudgetControl {
    fuel_cap: Arc<AtomicU64>,
}

impl BudgetControl {
    /// Create a control seeded with the creature's initial per-handle fuel ceiling.
    pub fn new(initial_fuel: u64) -> Self {
        BudgetControl { fuel_cap: Arc::new(AtomicU64::new(initial_fuel)) }
    }
    /// The shared cell the running instance reads each handle. The engine passes this into the
    /// instance so both ends point at the same atomic.
    pub fn cell(&self) -> Arc<AtomicU64> {
        self.fuel_cap.clone()
    }
    /// The current per-handle fuel ceiling.
    pub fn current_fuel(&self) -> u64 {
        self.fuel_cap.load(Ordering::Relaxed)
    }
    /// Lift (or set) the per-handle fuel ceiling — the creature's **next** handle gets it.
    /// A policy grants grace by raising this after a `Warn` (or anticipating a `Hard`).
    pub fn set_fuel(&self, fuel: u64) {
        self.fuel_cap.store(fuel, Ordering::Relaxed);
    }
}

/// A loaded creature plus the tier resources that must outlive its instance.
///
/// Field order is load-bearing: `instance` is declared before `resources`, and struct fields drop
/// in declaration order — so an implicit drop tears the instance down FIRST (e.g. the native
/// `destroy` runs while the library is still mapped), then `resources` (e.g. `dlclose`). The
/// explicit [`Engine::unload`] enforces the same order around a `shutdown` call.
pub struct LoadedModule {
    pub instance: Box<dyn Creature>,
    resources: Box<dyn std::any::Any + Send>,
    /// The live budget-ceiling control: `Some` for the wasm (fuel) and critter
    /// (operation-budget) tiers, `None` for native (see [`BudgetControl`]). The kernel `take()`s this
    /// at install and keys it by `CreatureId` so a later `ExtendBudget` reaches the right creature.
    pub budget: Option<BudgetControl>,
}

impl LoadedModule {
    /// Construct from an instance and the resources that must drop after it. No budget control by
    /// default (native); the wasm and critter engines add one via [`LoadedModule::with_budget`].
    pub fn new(instance: Box<dyn Creature>, resources: Box<dyn std::any::Any + Send>) -> Self {
        LoadedModule { instance, resources, budget: None }
    }

    /// Attach a live budget-ceiling control (the wasm and critter engines).
    pub fn with_budget(mut self, budget: BudgetControl) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Split into instance + tier resources. The kernel uses this on the **leak path** (the thread-
    /// count guard): when a creature leaves threads alive across `shutdown`, the kernel drops the
    /// instance (so native `destroy` runs while the library is still mapped) but **leaks** the
    /// resources (`Box::leak` the `Library` — `dlclose` never runs, the `.so` stays mapped). This is
    /// the bounded-leak/not-UAF tradeoff: the offending creature's library never goes away, but the
    /// runaway thread continues to dereference live mapped code. Healthy creatures unload normally
    /// and free their libraries.
    pub fn into_parts(self) -> (Box<dyn Creature>, Box<dyn std::any::Any + Send>) {
        (self.instance, self.resources)
    }
}

/// One engine per tier. The kernel never inspects the artifact format — it asks the engine for the
/// manifest's `backend` to load through the one path.
pub trait Engine: Send + Sync {
    fn backend(&self) -> Backend;

    /// Load (do not yet `bind`) a creature. Pure construction; binding happens on the drain thread.
    fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedModule, EngineError>;

    /// Tear down, honoring per-tier ordering. The default is correct for every tier:
    /// `shutdown` within the deadline, then drop the instance (native `destroy` runs while the
    /// library is still mapped), then drop tier resources (native: `dlclose` **last**). Bindings
    /// drop in *reverse* declaration order, so the explicit drops here — not field order — set it.
    fn unload(&self, loaded: LoadedModule, deadline: Deadline) -> Result<(), EngineError> {
        let LoadedModule { mut instance, resources, budget } = loaded;
        instance.shutdown(deadline);
        drop(instance); // tier teardown (native: `destroy` via the still-loaded library)
        drop(resources); // tier resources (native: `dlclose`)
        drop(budget); // live-budget handle — just an Arc; order doesn't matter
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("load failed: {0}")]
    Load(String),
    #[error("abi mismatch: engine expects `{expected}`, manifest declares `{got}`")]
    AbiMismatch { expected: String, got: String },
    #[error("an engine for {engine:?} cannot load a {manifest:?} creature")]
    WrongBackend { engine: Backend, manifest: Backend },
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// The creature exhausted a declared resource budget (`cpu_ms` → fuel, `mem_bytes` →
    /// limiter). Distinct from `Load` because the engine surfaces it through
    /// [`aether::Outcome::budget_signal`] for IoC-pure observability — not a kernel-built kill.
    ///
    /// Carries just the [`LimitKind`]; the full [`aether::BudgetSignal`] (with level + vector) is
    /// constructed at the `handle` boundary where the engine has the per-envelope scalars in
    /// scope. This keeps the variant compact (the engine knows only "what kind broke," not the
    /// envelope context).
    #[error("budget breach: {0:?}")]
    BudgetBreach(LimitKind),
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil::{Abi, Backend, Manifest};
    use std::sync::{Mutex, OnceLock};

    fn manifest(backend: Backend, abi_tag: &str) -> Manifest {
        Manifest::new("t", "0.1.0", backend, abi_tag)
    }

    /// Tests that deliberately burn fuel/ops should not run in parallel under libtest's default
    /// thread pool. The invariant under test is budget classification, not scheduler pressure.
    fn budget_spin_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn engines_report_their_backends() {
        assert_eq!(NativeEngine.backend(), Backend::Daemon);
        assert_eq!(WasmEngine::new().backend(), Backend::Beast);
        assert_eq!(ScriptEngine.backend(), Backend::Critter);
    }

    // ---- critter (script) tier — the Rhai engine, mirroring the beast suite below ----

    /// Build a critter engine + manifest (correct ABI tag) + source artifact, with `cpu_ms` as the
    /// declared operation-budget dial (`0` ⇒ unbounded).
    fn critter(src: &str, cpu_ms: u64) -> (ScriptEngine, Manifest, Artifact) {
        let mut m = manifest(Backend::Critter, crate::script::CRITTER_ABI_TAG);
        m.capabilities.cpu_ms = cpu_ms;
        (ScriptEngine, m, Artifact::Bytes(src.as_bytes().to_vec()))
    }

    #[test]
    fn script_engine_loads_runs_and_echoes() {
        let (e, m, art) = critter("fn handle(env) { env.payload }", 0);
        let mut loaded = e.load(&art, &m).expect("critter loads");
        let out = loaded.instance.handle(test_envelope(b"hello critter"));
        assert_eq!(out.dispatches.len(), 1, "echo replies once");
        assert_eq!(out.dispatches[0].payload, b"hello critter", "return value → reply payload");
        assert!(out.budget_signal.is_none(), "no signal on an unbounded echo");
        e.unload(loaded, Deadline::default()).expect("critter unloads");
    }

    #[test]
    fn script_rejects_wrong_abi_tag() {
        // Right tier, wrong ABI tag → rejected before the source is parsed (mirrors native).
        let e = ScriptEngine;
        let m = manifest(Backend::Critter, "gawd_creature_v1");
        assert!(matches!(
            e.load(&Artifact::Bytes(b"fn handle(env){env.payload}".to_vec()), &m),
            Err(EngineError::AbiMismatch { .. })
        ));
    }

    #[test]
    fn script_compile_error_is_a_clean_load_error_not_a_panic() {
        let (e, m, art) = critter("fn handle(env) { this is not valid rhai", 0);
        assert!(matches!(e.load(&art, &m), Err(EngineError::Load(_))));
    }

    #[test]
    fn script_missing_handle_fn_is_a_load_error() {
        // Discoverability: a script with no `handle` fails at load, not on the first envelope.
        let (e, m, art) = critter("fn not_handle(env) { env.payload }", 0);
        assert!(matches!(e.load(&art, &m), Err(EngineError::Load(_))));
    }

    #[test]
    fn script_cpu_ms_budget_traps_with_fuel_signal_hard_and_vector_filled() {
        let _spin = budget_spin_lock().lock().unwrap_or_else(|p| p.into_inner());
        use aether::SignalLevel;
        // cpu_ms=1 → DEFAULT_OPS_PER_MS op cap; an infinite loop trips it.
        let (e, m, art) = critter("fn handle(env) { let i = 0; loop { i += 1; } }", 1);
        let mut loaded = e.load(&art, &m).expect("critter loads");
        let out = loaded.instance.handle(test_envelope(b""));
        assert!(out.dispatches.is_empty(), "spin-forever produces no reply");
        let signal =
            out.budget_signal.expect("engine must emit a BudgetSignal on the op-budget trap");
        assert_eq!(signal.level, SignalLevel::Hard);
        assert_eq!(signal.kind, LimitKind::Fuel, "op-budget breach classifies as Fuel");
        assert_eq!(
            signal.vector.limit,
            crate::script::DEFAULT_OPS_PER_MS,
            "limit reflects cpu_ms × DEFAULT_OPS_PER_MS"
        );
        assert!(signal.vector.consumed > 0, "Hard signal reports ops consumed");
        assert_eq!(signal.vector.envelopes_since_load, 1, "first envelope handled");
        e.unload(loaded, Deadline::default()).expect("critter unloads after trap");
    }

    #[test]
    fn script_cpu_ms_zero_means_unbounded_no_signal() {
        let (e, m, art) = critter("fn handle(env) { env.payload }", 0);
        let mut loaded = e.load(&art, &m).expect("critter loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        assert_eq!(out.dispatches.len(), 1);
        assert!(out.budget_signal.is_none(), "cpu_ms=0 ⇒ unbounded ⇒ no signal");
        e.unload(loaded, Deadline::default()).expect("critter unloads");
    }

    #[test]
    fn script_extend_budget_lifts_the_live_ops_cap_mid_life() {
        let _spin = budget_spin_lock().lock().unwrap_or_else(|p| p.into_inner());
        // A bounded loop that exceeds the cpu_ms=1 cap, then echoes: it traps under the
        // small cap, then *completes* after a `BudgetControl::set_fuel` grant — proving the critter's
        // live ceiling lifts exactly as the beast's fuel does, and that `Kernel::extend_budget` now
        // returns `true` for a non-wasm tier.
        let loop_iters = crate::script::DEFAULT_OPS_PER_MS + crate::script::DEFAULT_OPS_PER_MS / 2;
        let src = format!(
            "fn handle(env) {{ let i = 0; while i < {loop_iters} {{ i += 1; }} env.payload }}"
        );
        let (e, m, art) = critter(&src, 1);
        let mut loaded = e.load(&art, &m).expect("critter loads");
        let budget = loaded.budget.clone().expect("critter tier exposes a BudgetControl");
        assert_eq!(
            budget.current_fuel(),
            crate::script::DEFAULT_OPS_PER_MS,
            "seeded to cpu_ms × DEFAULT_OPS_PER_MS"
        );

        let out = loaded.instance.handle(test_envelope(b"hi"));
        assert!(out.dispatches.is_empty(), "traps under the small cap → no reply");
        assert_eq!(out.budget_signal.expect("Hard on the op trap").kind, LimitKind::Fuel);

        let raised = crate::script::DEFAULT_OPS_PER_MS * 10;
        budget.set_fuel(raised);
        assert_eq!(budget.current_fuel(), raised, "the ceiling is raised");

        let out = loaded.instance.handle(test_envelope(b"hi"));
        assert_eq!(out.dispatches.len(), 1, "with the lifted ceiling the same handle completes");
        assert_eq!(out.dispatches[0].payload, b"hi", "and echoes its payload");
        assert!(out.budget_signal.is_none(), "no breach after the grant");
        e.unload(loaded, Deadline::default()).expect("critter unloads");
    }

    #[test]
    fn script_budget_warn_at_emits_warn_alongside_reply() {
        use aether::SignalLevel;
        // Any successful handle crosses `budget_warn_at = 0` → a Warn rides alongside the reply.
        let (e, mut m, art) = critter("fn handle(env) { env.payload }", 1);
        m.capabilities.budget_warn_at = Some(0);
        let mut loaded = e.load(&art, &m).expect("critter loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        assert_eq!(out.dispatches.len(), 1, "Warn must not suppress the reply");
        let signal = out.budget_signal.expect("Warn on threshold cross");
        assert_eq!(signal.level, SignalLevel::Warn);
        assert_eq!(signal.kind, LimitKind::Fuel);
        assert_eq!(signal.vector.limit, crate::script::DEFAULT_OPS_PER_MS);
        assert!(signal.vector.consumed > 0, "an echo consumes some ops");
        e.unload(loaded, Deadline::default()).expect("critter unloads");
    }

    #[test]
    fn script_no_budget_warn_at_means_no_warn() {
        let (e, m, art) = critter("fn handle(env) { env.payload }", 1);
        let mut loaded = e.load(&art, &m).expect("loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        assert_eq!(out.dispatches.len(), 1);
        assert!(out.budget_signal.is_none(), "no opt-in, no Warn");
        e.unload(loaded, Deadline::default()).expect("unloads");
    }

    #[test]
    fn script_budget_warn_at_above_100_is_clamped() {
        // A garbage threshold > 100 clamps to 100 → a cheap handle (consumed ≪ limit) never fires.
        let (e, mut m, art) = critter("fn handle(env) { env.payload }", 1);
        m.capabilities.budget_warn_at = Some(250);
        let mut loaded = e.load(&art, &m).expect("loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        assert_eq!(out.dispatches.len(), 1);
        assert!(out.budget_signal.is_none(), "clamped to 100, threshold not crossed");
        e.unload(loaded, Deadline::default()).expect("unloads");
    }

    #[test]
    fn script_emit_sends_a_gated_dispatch_then_replies_in_push_order() {
        // The script emits to a topic, then returns a reply → two dispatches, emit first (the
        // local-delivery FIFO contract holds because the kernel drains `dispatches` in push order).
        use aether::Address;
        let src = r#"fn handle(env) { emit("topic:fitness", env.payload); env.payload }"#;
        let (e, m, art) = critter(src, 0);
        let mut loaded = e.load(&art, &m).expect("loads");
        let out = loaded.instance.handle(test_envelope(b"x"));
        assert_eq!(out.dispatches.len(), 2, "one emit + one return-reply");
        assert!(matches!(out.dispatches[0].to, Address::Topic(_)), "emit lands first (FIFO)");
        e.unload(loaded, Deadline::default()).expect("unloads");
    }

    #[test]
    fn script_emit_to_unroutable_address_is_a_clean_no_reply_not_a_panic() {
        // A bad address makes `emit` error → the whole handle errors → no reply, no *partial* sends,
        // no host crash (R9).
        let src = r#"fn handle(env) { emit("bogus-address", env.payload); env.payload }"#;
        let (e, m, art) = critter(src, 0);
        let mut loaded = e.load(&art, &m).expect("loads");
        let out = loaded.instance.handle(test_envelope(b"x"));
        assert!(out.dispatches.is_empty(), "an errored handle sends nothing");
        assert!(out.budget_signal.is_none());
        e.unload(loaded, Deadline::default()).expect("unloads");
    }

    #[test]
    fn script_is_sandboxed_no_ambient_authority() {
        // IoC + determinism tripwire: the bare engine exposes no clock/fs/net/rand. `timestamp()` is
        // removed by the `no_time` feature, so calling it is an unknown-function runtime error → no
        // reply (and never a panic). If a future contributor registers an ambient host fn, this
        // script would return a value and the assertion below would trip.
        let (e, m, art) = critter("fn handle(env) { timestamp() }", 0);
        let mut loaded = e.load(&art, &m).expect("script compiles (fn resolution is at call time)");
        let out = loaded.instance.handle(test_envelope(b""));
        assert!(out.dispatches.is_empty(), "no ambient timestamp() ⇒ runtime error ⇒ no reply");
        e.unload(loaded, Deadline::default()).expect("unloads");
    }

    #[test]
    fn script_loads_the_reference_echo_critter_from_disk() {
        // The shipped reference creature (creatures/prototypes/critters/echo-critter/echo.rhai) loads + echoes.
        let src = include_bytes!("../../creatures/prototypes/critters/echo-critter/echo.rhai");
        let mut m = manifest(Backend::Critter, crate::script::CRITTER_ABI_TAG);
        m.capabilities.cpu_ms = 0;
        let mut loaded =
            ScriptEngine.load(&Artifact::Bytes(src.to_vec()), &m).expect("echo-critter loads");
        let out = loaded.instance.handle(test_envelope(b"reference"));
        assert_eq!(out.dispatches.len(), 1);
        assert_eq!(out.dispatches[0].payload, b"reference");
        ScriptEngine.unload(loaded, Deadline::default()).expect("unloads");
    }

    #[test]
    fn script_default_structural_cap_stops_bulk_allocation_with_memory_signal() {
        use aether::SignalLevel;
        // mem_bytes unset + cpu_ms=0 (op budget unlimited): the ONLY backstop is the always-on
        // default structural cap. With the cap unset Rhai would `resize` straight to the requested
        // length; with the cap set the size is checked UP FRONT and the op errors before allocating.
        // We pad just past the default cap (not to billions) so even a hypothetical regression that
        // dropped the up-front check stays bounded — the assertion still proves the breach surfaces
        // as a Hard/Memory signal (no reply, no panic). Regression guard for the un-capped DoS.
        let requested = crate::script::DEFAULT_STRUCTURAL_CAP + 1;
        let src = format!("fn handle(env) {{ let a = []; a.pad({requested}, 0); a }}");
        let (e, m, art) = critter(&src, 0);
        let mut loaded = e.load(&art, &m).expect("critter loads");
        let out = loaded.instance.handle(test_envelope(b""));
        assert!(out.dispatches.is_empty(), "a structural-cap breach produces no reply");
        let signal = out.budget_signal.expect("structural-cap breach must emit a BudgetSignal");
        assert_eq!(signal.level, SignalLevel::Hard);
        assert_eq!(signal.kind, LimitKind::Memory, "a structural-size breach classifies as Memory");
        assert_eq!(
            signal.vector.limit,
            crate::script::DEFAULT_STRUCTURAL_CAP,
            "limit reflects the default structural backstop"
        );
        e.unload(loaded, Deadline::default()).expect("critter unloads after the structural trap");
    }

    #[test]
    fn script_declared_mem_bytes_traps_with_memory_signal() {
        // A declared mem_bytes tightens the structural cap; exceeding it is a Hard/Memory breach whose
        // limit reflects the declared value (best-effort: counts, not bytes).
        let (e, mut m, art) = critter("fn handle(env) { let a = []; a.pad(1000, 0); a }", 0);
        m.capabilities.mem_bytes = 64;
        let mut loaded = e.load(&art, &m).expect("critter loads at the declared cap");
        let out = loaded.instance.handle(test_envelope(b""));
        assert!(out.dispatches.is_empty(), "exceeding mem_bytes produces no reply");
        let signal = out.budget_signal.expect("mem_bytes breach must emit a BudgetSignal");
        assert_eq!(signal.kind, LimitKind::Memory);
        assert_eq!(signal.vector.limit, 64, "limit reflects the declared mem_bytes cap");
        e.unload(loaded, Deadline::default()).expect("critter unloads");
    }

    #[test]
    fn script_rejects_wrong_backend() {
        // A non-critter manifest mis-routed to the script engine is a routing bug — it must get a
        // precise `WrongBackend`, the same as native/wasm, not the "tier reserved" stub error.
        let e = ScriptEngine;
        let daemon = manifest(Backend::Daemon, "gawd_creature_v1");
        assert!(matches!(
            e.load(&Artifact::Bytes(vec![]), &daemon),
            Err(EngineError::WrongBackend { .. })
        ));
    }

    #[test]
    fn native_rejects_wrong_backend_and_bad_abi_tag() {
        let e = NativeEngine;
        // wrong tier
        let beast = manifest(Backend::Beast, "gawd_creature_v1");
        assert!(matches!(
            e.load(&Artifact::Path("/nonexistent.so".into()), &beast),
            Err(EngineError::WrongBackend { .. })
        ));
        // right tier, wrong abi tag → rejected before any dlopen
        let mut m = manifest(Backend::Daemon, "ancient_v0");
        m.abi = Abi { backend: Backend::Daemon, abi_tag: "ancient_v0".into(), target: vec![] };
        assert!(matches!(
            e.load(&Artifact::Path("/nonexistent.so".into()), &m),
            Err(EngineError::AbiMismatch { .. })
        ));
    }

    #[test]
    fn native_missing_file_is_a_clean_load_error_not_a_panic() {
        let e = NativeEngine;
        let m = manifest(Backend::Daemon, "gawd_creature_v1");
        assert!(matches!(
            e.load(&Artifact::Path("/no/such/path.so".into()), &m),
            Err(EngineError::Load(_))
        ));
    }

    // A minimal real WASM module: linear memory + a bump `alloc` + an identity `handle` returning the
    // packed (ptr<<32 | len). Proves the beast tier end-to-end (compile, instantiate, alloc, write
    // memory, call, read back) without the SDK. The real reversing beast (Rust→wasm) is tested with
    // the kernel in the integration suite.
    const IDENTITY_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $bump (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $len)))
            (local.get $p))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len)))))
    "#;

    fn test_envelope(payload: &[u8]) -> aether::Envelope {
        use aether::{Address, CreatureId, Header};
        aether::Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: String::new(),
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn wasm_engine_loads_runs_and_unloads_a_real_module() {
        let wasm = wat::parse_str(IDENTITY_WAT).expect("valid wat");
        let e = WasmEngine::new();
        let m = manifest(Backend::Beast, "gawd_creature_v1");
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b"hello wasm"));
        assert_eq!(out.dispatches.len(), 1);
        // identity round-trip through real linear memory proves alloc + write + call + read.
        assert_eq!(out.dispatches[0].payload, b"hello wasm");
        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }

    #[test]
    fn wasm_rejects_a_non_beast_manifest() {
        let wasm = wat::parse_str(IDENTITY_WAT).unwrap();
        let e = WasmEngine::new();
        let m = manifest(Backend::Daemon, "gawd_creature_v1");
        assert!(matches!(
            e.load(&Artifact::Bytes(wasm), &m),
            Err(EngineError::WrongBackend { .. })
        ));
    }

    #[test]
    fn wasm_rejects_bad_abi_tag_before_compiling() {
        let e = WasmEngine::new();
        let m = manifest(Backend::Beast, "ancient_wasm_v0");
        assert!(matches!(
            e.load(&Artifact::Bytes(Vec::new()), &m),
            Err(EngineError::AbiMismatch { .. })
        ));
    }

    /// `cpu_ms` budget translates to wasmtime fuel; a tight infinite loop runs out and
    /// the engine surfaces `BudgetBreach::Fuel`. The kernel sees this as a structured outcome
    /// (no panic, no host crash) — exactly what the budget-kill story needs to observe.
    ///
    /// The WAT loops forever after a single `alloc` + `memory.write` (so we pass the host's
    /// pre-handle steps cleanly). Fuel runs out *inside* `handle`, so the trap is attributed to
    /// the handle call — exactly where enforcement happens.
    const SPIN_FOREVER_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $bump (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $len)))
            (local.get $p))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (loop $spin (br $spin))
            (i64.const 0)))
    "#;

    #[test]
    fn wasm_cpu_ms_budget_traps_with_fuel_signal_hard_and_vector_filled() {
        let _spin = budget_spin_lock().lock().unwrap_or_else(|p| p.into_inner());
        use aether::{LimitKind, SignalLevel};
        let wasm = wat::parse_str(SPIN_FOREVER_WAT).expect("valid wat");
        // A tiny `cpu_ms` → small fuel quota; the infinite loop trips OutOfFuel quickly.
        let e = WasmEngine::new().with_fuel_per_ms(1_000);
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.cpu_ms = 1; // 1_000 fuel — enough to prove the trap without a long burn
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b""));
        // No reply (the trap aborted handle before it could return), and the engine surfaced a
        // **Hard, Fuel-kind** signal with the per-envelope trajectory vector — filled
        // best-effort at trap time.
        assert!(out.dispatches.is_empty(), "spin-forever produces no reply");
        let signal = out.budget_signal.expect("engine must emit a BudgetSignal on trap");
        assert_eq!(signal.level, SignalLevel::Hard, "fuel traps are terminal Hard signals");
        assert_eq!(signal.kind, LimitKind::Fuel, "OutOfFuel must classify as Fuel");
        assert_eq!(signal.vector.limit, 1_000, "limit reflects the per-envelope fuel cap");
        // The trap consumed *some* fuel before bailing — the exact number is engine-specific,
        // but the vector must show non-zero consumed at a Hard fuel signal.
        assert!(signal.vector.consumed > 0, "Hard-fuel signal must report fuel consumed");
        assert_eq!(signal.vector.envelopes_since_load, 1, "first envelope handled");
        e.unload(loaded, Deadline::default()).expect("beast unloads cleanly after trap");
    }

    #[test]
    fn wasm_cpu_ms_zero_means_unbounded_fuel_no_signal() {
        // `cpu_ms == 0` is the unset default, honored as "no budget." A non-looping beast
        // running with zero declared budget must NOT trip a signal — otherwise we'd silently break
        // every test that left capabilities at default.
        let wasm = wat::parse_str(IDENTITY_WAT).expect("valid wat");
        let e = WasmEngine::new();
        let m = manifest(Backend::Beast, "gawd_creature_v1"); // cpu_ms defaults to 0
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        assert_eq!(out.dispatches.len(), 1, "identity beast replies normally");
        assert!(out.budget_signal.is_none(), "no signal on unset cpu_ms");
        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }

    /// A guest that does a *bounded* amount of work (≈2k loop iterations) then
    /// echoes its payload. Unlike `SPIN_FOREVER_WAT` (which traps at any cap), this lets a fuel
    /// *grant* change the outcome: a small cap traps mid-loop, a raised cap lets it finish.
    const BOUNDED_LOOP_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $bump (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $len)))
            (local.get $p))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (local $i i32)
            (local.set $i (i32.const 2000))
            (block $done
              (loop $work
                (br_if $done (i32.eqz (local.get $i)))
                (local.set $i (i32.sub (local.get $i) (i32.const 1)))
                (br $work)))
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len)))))
    "#;

    /// **The live fuel-ceiling lifts mid-life.** The SAME creature with the SAME payload
    /// *traps* under a small per-handle fuel cap, then *succeeds* after a `BudgetControl::set_fuel`
    /// grant — proving the gradient flows both ways (the engine doesn't only emit Hard/Warn; a grant
    /// raises the ceiling the next handle reads). This is the engine-level proof; the kernel-level
    /// path (a `KernelControl::ExtendBudget` over the bus) is in `sanctum/tests/budget_extend_honored`.
    #[test]
    fn wasm_extend_budget_lifts_the_live_fuel_cap_mid_life() {
        let _spin = budget_spin_lock().lock().unwrap_or_else(|p| p.into_inner());
        use aether::LimitKind;
        let wasm = wat::parse_str(BOUNDED_LOOP_WAT).expect("valid wat");
        // 1k fuel: less than the bounded loop needs → traps on the first handle.
        let e = WasmEngine::new().with_fuel_per_ms(1_000);
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.cpu_ms = 1; // 1_000 fuel
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let budget = loaded.budget.clone().expect("wasm tier exposes a BudgetControl");
        assert_eq!(budget.current_fuel(), 1_000, "seeded to the declared budget");

        // Before the grant: the bounded loop runs out of fuel → Hard/Fuel signal, no reply.
        let out = loaded.instance.handle(test_envelope(b"hi"));
        assert!(out.dispatches.is_empty(), "traps under the small cap → no reply");
        let signal = out.budget_signal.expect("Hard signal on the fuel trap");
        assert_eq!(signal.kind, LimitKind::Fuel);

        // The grant: lift the per-handle fuel ceiling well past what the loop needs.
        budget.set_fuel(100_000);
        assert_eq!(budget.current_fuel(), 100_000, "the ceiling is raised");

        // After the grant: the SAME payload now completes the loop and echoes — survival via grace.
        let out = loaded.instance.handle(test_envelope(b"hi"));
        assert_eq!(out.dispatches.len(), 1, "with the lifted ceiling the same handle succeeds");
        assert_eq!(out.dispatches[0].payload, b"hi", "and echoes its payload");
        assert!(out.budget_signal.is_none(), "no breach after the grant");

        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }

    /// `mem_bytes` budget caps linear-memory growth; a `memory.grow` past the limit
    /// (with `trap_on_grow_failure(true)`) traps and the engine surfaces `BudgetBreach::Memory`.
    ///
    /// The WAT requests one page (64 KiB) at startup (the `(memory 1)` import) — so an operator
    /// setting `mem_bytes = 1` (one byte!) blocks even the initial instantiation. We exercise the
    /// growth path here: `mem_bytes` set to one page, then `handle` calls `memory.grow(1)` to
    /// request a second page → refused → trap.
    const GROW_MEM_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $bump (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $len)))
            (local.get $p))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (drop (memory.grow (i32.const 1)))
            (i64.const 0)))
    "#;

    /// **Warn emission by an engine.** When `budget_warn_at` is
    /// declared, a *successful* handle (no trap) that consumed past the threshold attaches a
    /// `Warn`-level signal to the outcome **alongside the reply**. This is the branch the
    /// `BudgetGraceful` injected policy reacts to in production — without this, every Warn path is
    /// unreachable except by direct injection.
    ///
    /// We use IDENTITY_WAT (which always succeeds) + `budget_warn_at = 0` so the threshold fires
    /// on every handle regardless of how cheap the work is. The exact-fuel-consumed value is
    /// engine-specific; the *shape* of the signal (level=Warn, kind=Fuel, non-zero consumed,
    /// limit reflects cpu_ms × fuel_per_ms) is what we lock.
    #[test]
    fn wasm_budget_warn_at_emits_warn_alongside_reply_on_successful_handle() {
        use aether::{LimitKind, SignalLevel};
        let wasm = wat::parse_str(IDENTITY_WAT).expect("valid wat");
        let e = WasmEngine::new().with_fuel_per_ms(10_000);
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.cpu_ms = 1; // 10_000 fuel quota
        m.capabilities.budget_warn_at = Some(0); // any consumption ≥ 0% → fires
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        // (a) The reply is still there — Warn does NOT replace the dispatch, it rides alongside.
        assert_eq!(out.dispatches.len(), 1, "Warn must not suppress the reply");
        // (b) The signal is Warn + Fuel + non-zero consumed + limit matches the fuel quota.
        let signal = out.budget_signal.expect("Warn must be attached on threshold cross");
        assert_eq!(signal.level, SignalLevel::Warn, "first real engine-emitted Warn");
        assert_eq!(signal.kind, LimitKind::Fuel, "fuel was the dimension checked");
        assert_eq!(signal.vector.limit, 10_000);
        assert!(signal.vector.consumed > 0, "identity handle consumes some fuel");
        assert_eq!(signal.vector.envelopes_since_load, 1);
        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }

    /// **Negative test** — without `budget_warn_at`, no Warn fires regardless of fuel use. Locks
    /// the default wire behavior for creatures that do not opt into advisory warnings.
    #[test]
    fn wasm_no_budget_warn_at_means_no_warn_emitted() {
        let wasm = wat::parse_str(IDENTITY_WAT).expect("valid wat");
        let e = WasmEngine::new().with_fuel_per_ms(10_000);
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.cpu_ms = 1; // fuel cap declared, but no opt-in
                                   // budget_warn_at omitted (None)
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        assert_eq!(out.dispatches.len(), 1);
        assert!(
            out.budget_signal.is_none(),
            "no opt-in, no Warn — default wire behavior preserved"
        );
        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }

    /// **Negative test** — a high threshold not crossed → no Warn. Confirms the threshold
    /// arithmetic doesn't fire spuriously below the cut.
    #[test]
    fn wasm_warn_threshold_not_crossed_means_no_warn() {
        let wasm = wat::parse_str(IDENTITY_WAT).expect("valid wat");
        let e = WasmEngine::new().with_fuel_per_ms(10_000_000); // very generous budget
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.cpu_ms = 1; // 10_000_000 fuel — identity handle consumes well under 1%
        m.capabilities.budget_warn_at = Some(99); // need 99% consumed to fire
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        assert_eq!(out.dispatches.len(), 1);
        assert!(out.budget_signal.is_none(), "threshold 99% not crossed by cheap handle");
        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }

    /// **Robustness** — a malformed `budget_warn_at > 100` is clamped on load (the engine never
    /// trusts inputs). 200% effectively becomes "always fires" (consumed never exceeds 200% of
    /// limit on a single handle — unless... actually 200% is unreachable in one handle, so it
    /// becomes "never fires"). Verify the clamp is to 100, meaning Warn becomes "only fires on
    /// full consumption."
    #[test]
    fn wasm_budget_warn_at_above_100_is_clamped() {
        let wasm = wat::parse_str(IDENTITY_WAT).expect("valid wat");
        let e = WasmEngine::new().with_fuel_per_ms(10_000);
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.cpu_ms = 1;
        m.capabilities.budget_warn_at = Some(250); // garbage value
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b"abc"));
        // After clamp to 100, an identity-handle's modest consumption is under 100% → no Warn.
        // Crucially: no panic, no overflow, no spurious fire.
        assert_eq!(out.dispatches.len(), 1);
        assert!(out.budget_signal.is_none(), "clamped to 100, threshold not crossed");
        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }

    #[test]
    fn wasm_mem_bytes_budget_traps_with_memory_signal_hard_and_vector_filled() {
        use aether::{LimitKind, SignalLevel};
        let wasm = wat::parse_str(GROW_MEM_WAT).expect("valid wat");
        let e = WasmEngine::new();
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        // One wasm page = 64 KiB. The module instantiates with 1 page already; setting the cap to
        // exactly one page means any grow refuses, and our typed sentinel → wasmtime trap
        // classifies as a Memory signal.
        m.capabilities.mem_bytes = 64 * 1024;
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads at cap");
        let out = loaded.instance.handle(test_envelope(b""));
        assert!(out.dispatches.is_empty(), "trapping grow produces no reply");
        let signal = out.budget_signal.expect("engine must emit a BudgetSignal on grow refusal");
        assert_eq!(signal.level, SignalLevel::Hard, "memory traps are terminal Hard signals");
        assert_eq!(signal.kind, LimitKind::Memory, "grow refusal must classify as Memory");
        assert_eq!(signal.vector.limit, 64 * 1024, "limit reflects the mem_bytes cap");
        // `consumed` for a Memory signal is current linear-memory size — must be ≤ cap (the grow
        // was refused, so we're still at the pre-grow size, which is the initial allocation).
        assert!(signal.vector.consumed <= signal.vector.limit);
        e.unload(loaded, Deadline::default()).expect("beast unloads cleanly after trap");
    }

    /// **E2 — initial-memory cap (failing-first regression).** The limiter is installed BEFORE
    /// `Instance::new`, so wasmtime routes the module's declared *initial* (minimum) linear memory
    /// through `memory_growing` at instantiation. A beast whose initial allocation exceeds its
    /// `mem_bytes` cap therefore fails the *load* — not only a later `memory.grow`. This guards the
    /// load-ordering invariant (`store.limiter(...)` before `Instance::new`) against a future refactor
    /// that moved the limiter and silently regressed initial-allocation enforcement.
    #[test]
    fn wasm_initial_memory_over_cap_fails_the_load() {
        // IDENTITY_WAT declares `(memory 1)` = one 64 KiB page as its initial allocation.
        let wasm = wat::parse_str(IDENTITY_WAT).expect("valid wat");
        let e = WasmEngine::new();
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.mem_bytes = 1024; // far below 64 KiB → the initial allocation is refused
        assert!(
            matches!(e.load(&Artifact::Bytes(wasm), &m), Err(EngineError::Load(_))),
            "an initial linear-memory allocation over the mem_bytes cap must fail the load"
        );
    }

    /// **E3 — beast wall-clock.** A spinning beast with *unlimited fuel* (`cpu_ms == 0`) but a tight
    /// `wall_ms` cap trips the engine-global epoch deadline (`Trap::Interrupt`) → a `Hard` `Wall`
    /// budget signal, riding the same gradient shape as a fuel breach. A fine tick makes it prompt.
    #[test]
    fn wasm_wall_ms_budget_traps_with_wall_signal_when_fuel_is_unlimited() {
        let _spin = budget_spin_lock().lock().unwrap_or_else(|p| p.into_inner());
        use aether::{LimitKind, SignalLevel};
        let wasm = wat::parse_str(SPIN_FOREVER_WAT).expect("valid wat");
        let e = WasmEngine::with_tick_ms(2); // 2 ms cadence
        let mut m = manifest(Backend::Beast, "gawd_creature_v1");
        m.capabilities.cpu_ms = 0; // unlimited fuel — so WALL, not fuel, is what trips
        m.capabilities.wall_ms = Some(20); // ~10 ticks at a 2 ms cadence
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b""));
        assert!(out.dispatches.is_empty(), "a wall-clock trap produces no reply");
        let signal = out.budget_signal.expect("engine must emit a BudgetSignal on the wall trap");
        assert_eq!(signal.level, SignalLevel::Hard, "wall traps are terminal Hard signals");
        assert_eq!(signal.kind, LimitKind::Wall, "an epoch-deadline trap classifies as Wall");
        assert_eq!(signal.vector.limit, 20, "limit reflects the declared wall_ms cap");
        assert!(signal.vector.consumed > 0, "the Wall vector reports ms elapsed");
        assert_eq!(signal.vector.envelopes_since_load, 1, "first envelope handled");
        e.unload(loaded, Deadline::default()).expect("beast unloads cleanly after the wall trap");
    }

    /// **E3 negative** — a quick, bounded beast with no `wall_ms` cap completes normally; the epoch
    /// deadline never trips. Locks the "wall_ms == None ⇒ unlimited" convention (mirroring cpu_ms==0).
    #[test]
    fn wasm_wall_ms_none_means_no_wall_trap() {
        let wasm = wat::parse_str(BOUNDED_LOOP_WAT).expect("valid wat");
        let e = WasmEngine::with_tick_ms(2);
        let m = manifest(Backend::Beast, "gawd_creature_v1"); // cpu_ms=0, wall_ms=None
        let mut loaded = e.load(&Artifact::Bytes(wasm), &m).expect("beast loads");
        let out = loaded.instance.handle(test_envelope(b"hi"));
        assert_eq!(out.dispatches.len(), 1, "no wall cap ⇒ the bounded loop completes and replies");
        assert_eq!(out.dispatches[0].payload, b"hi");
        assert!(out.budget_signal.is_none(), "wall_ms=None never trips a wall signal");
        e.unload(loaded, Deadline::default()).expect("beast unloads");
    }
}
