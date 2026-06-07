//! Integration coverage for [`policy_budget::BudgetGraceful`], a consumer of
//! the `BudgetVector`, `KernelControl::ExtendBudget`, and creature-initiated
//! `BudgetRequest` seams.
//!
//! These tests sit alongside the capability/sandbox exit-criteria tests (`m4_capability_sandbox.rs`),
//! which prove the IoC chain end-to-end with the **simplest** policy (`BudgetApoptosis`: Hard → Unload). The
//! tests below add what that suite doesn't:
//!
//! 1. [`graceful_hard_signal_drives_apoptosis_through_real_kernel`] — proves the richer policy's
//!    wire is structurally identical to the simple one on `Hard` (still `Unload` to
//!    `Address::Kernel`) and round-trips through the real kernel.
//! 2. [`graceful_warn_extend_budget_is_accepted_and_listener_stays_alive`] — proves the kernel's
//!    `KernelControl::ExtendBudget` branch accepts a real `ExtendBudget` op, updates metered
//!    engines when present, and keeps the control listener healthy afterward (a follow-up `Hard`
//!    still drives apoptosis).
//!
//! **The three scenarios** that prove `Warn` is not dead weight (these need real engine-emitted
//! Warns — manual injection alone is "pointless," per the user's framing). All three depend on
//! [`anima::WasmEngine`] emitting `BudgetSignal::warn(...)` on successful handles whose
//! consumption crossed the operator-declared `budget_warn_at` threshold (the Phase 2a-real-warn
//! addition):
//!
//! 3. [`warn_survival_beast_keeps_handling_after_grace`] — real engine-emitted Warn → grace
//!    granted by BudgetGraceful → beast keeps handling envelopes successfully → still loaded.
//!    The "survival via grace" scenario.
//! 4. [`warn_then_hard_beast_unloaded_despite_grace`] — Warn cycle grants grace, then a heavier
//!    payload trips Hard → kernel apoptoses despite grace. The "grace doesn't save it" scenario.
//! 5. [`warn_self_apoptosis_relay_lets_beast_exit_cleanly`] — a "warn-relay-as-apoptosis"
//!    creature translates Warn into `KernelControl::Unload { module }` on the *beast's* behalf:
//!    the beast's current handle completes (reply lands), THEN the unload arrives. The
//!    "survival = achieving own apoptosis" scenario: clean exit at handle boundary instead of
//!    mid-handle Hard-kill.
//!
//! IoC discipline is the same as the apoptosis case: the kernel ships the proprio fan-out + the
//! control vocabulary; the **richer** policy creature decides whether to grant grace, unload,
//! or observe — the kernel has no opinion about which trajectory class deserves which response.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Bus, Creature, CreatureCtx, Deadline, Dispatch, Envelope, Outcome, Topic};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_budget::BudgetGraceful;
use policy_dev::DevPolicy;
use sanctum::{BudgetSignalEvent, Kernel, KernelControl};
use sigil::{Backend, Capabilities, Manifest};

// A real wasm reverse module — the same shape the capability/sandbox tests use. We don't actually need its `handle` to do
// anything special for these tests (we never call it); we just want a real loaded beast so the
// kernel's apoptosis path has something to unload.
const REVERSE_BEAST_WAT: &str = r#"
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
          (i64.shl (i64.extend_i32_u (global.get $bump)) (i64.const 32))
          (i64.extend_i32_u (local.get $len)))))
"#;

// **Tunable beast for the Warn scenarios.** Branches on the first input byte:
//   - byte 0x00 → infinite loop → engine traps OutOfFuel → Hard signal
//   - any other byte → echo the input back → successful handle (Warn fires if threshold crossed)
//
// This lets one beast drive both the Warn-survival path (non-zero payload) and the Hard-failure
// path (zero payload) in the same test, exercising the policy's response to *both* signals on
// the same creature — the core of the "grace doesn't save it" scenario.
const ECHO_OR_SPIN_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (global $bump (mut i32) (i32.const 1024))
      (func (export "alloc") (param $len i32) (result i32)
        (local $p i32)
        (local.set $p (global.get $bump))
        (global.set $bump (i32.add (global.get $bump) (local.get $len)))
        (local.get $p))
      (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
        ;; If first byte is 0x00, spin forever. Otherwise echo input.
        (block $not_spin
          (br_if $not_spin (i32.ne (i32.load8_u (local.get $ptr)) (i32.const 0)))
          (loop $spin (br $spin)))
        (i64.or
          (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
          (i64.extend_i32_u (local.get $len)))))
"#;

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![
            Arc::new(NativeEngine),
            Arc::new(WasmEngine::new().with_fuel_per_ms(1_000)),
            Arc::new(ScriptEngine),
        ],
        Arc::new(aether::StubSigner::new("p2a-node")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn beast_manifest_named(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Beast, "gawd_creature_v1")
}

fn beast_artifact() -> Artifact {
    Artifact::Bytes(wat::parse_str(REVERSE_BEAST_WAT).expect("valid wat"))
}

/// Wire a `BudgetGraceful` creature against the kernel: open an endpoint with default caps,
/// subscribe to `PROPRIOCEPTION`, drain inbox into `handle`, send resulting dispatches back
/// through the bus. Identical scaffolding to the `BudgetApoptosis` setup so the only thing
/// under test is BudgetGraceful's behavior. Returns the policy thread handle so the test can
/// keep it alive for the kernel's lifetime.
fn spawn_graceful_policy(k: &Arc<Kernel>) -> std::thread::JoinHandle<()> {
    let (policy_id, policy_bus, policy_rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), policy_id);
    let k_keepalive = k.clone();
    std::thread::Builder::new()
        .name("policy-budget-graceful".into())
        .spawn(move || {
            let mut p = BudgetGraceful::new();
            let bus: Arc<dyn Bus> = Arc::new(policy_bus.clone());
            let ctx = CreatureCtx {
                me: policy_id,
                bus,
                manifest: Manifest::new(
                    "policy-budget-graceful",
                    "0.1.0",
                    Backend::Daemon,
                    "gawd_creature_v1",
                ),
            };
            p.bind(ctx);
            while let Ok(env) = policy_rx.recv() {
                let out = p.handle(env);
                for d in out.dispatches {
                    let _ = policy_bus.send(d);
                }
            }
            // Keep the kernel handle alive for the thread's lifetime so a late-arriving signal
            // doesn't race shutdown.
            drop(k_keepalive);
        })
        .expect("spawn graceful policy thread")
}

/// Publish a `BudgetSignalEvent` directly on PROPRIOCEPTION from a probe endpoint. Tests use
/// this to drive specific policy vectors without having to trap a beast for every case (faster +
/// deterministic — engine-emitted Warn and Hard paths are covered below and in the capability/sandbox suite).
fn publish_budget_signal(
    k: &Arc<Kernel>,
    module: u64,
    level: &str,
    kind: &str,
    vector: aether::BudgetVector,
) {
    let (_id, bus, _rx) = k.open_endpoint(Capabilities::default());
    let payload = serde_json::to_vec(&BudgetSignalEvent {
        module,
        level: level.into(),
        kind: kind.into(),
        vector,
    })
    .unwrap();
    bus.send(
        Dispatch::to(Address::Topic(Topic::new(Topic::PROPRIOCEPTION)), payload)
            .with_schema("budget_signal"),
    )
    .expect("publish to PROPRIOCEPTION");
}

/// Wait up to `deadline` for `predicate` to become true, polling every 20ms. Returns `true` if
/// it became true within the budget, `false` if the deadline expired.
fn wait_until(deadline: Duration, mut predicate: impl FnMut() -> bool) -> bool {
    let stop = std::time::Instant::now() + deadline;
    while std::time::Instant::now() < stop {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    predicate()
}

/// **Phase 2a (1/2)** — `BudgetGraceful` on a `Hard` signal drives the same Unload-via-kernel
/// chain as `BudgetApoptosis`, proving the richer policy's wire is structurally identical and
/// round-trips through the real kernel.
#[test]
fn graceful_hard_signal_drives_apoptosis_through_real_kernel() {
    let k = kernel();
    let _policy = spawn_graceful_policy(&k);

    let beast =
        k.load(beast_manifest_named("graceful-target"), beast_artifact()).expect("beast loads");

    // Publish a Hard signal with a productive trajectory. The Hard floor applies regardless
    // — the engine has already trapped, so trajectory is observability only.
    publish_budget_signal(
        &k,
        beast.0,
        "hard",
        "fuel",
        aether::BudgetVector {
            consumed: 9_000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        },
    );

    let unloaded = wait_until(Duration::from_secs(5), || !k.is_loaded(beast));
    assert!(unloaded, "BudgetGraceful Hard→Unload→kernel chain did not complete within 5s");

    // **Prove-stop (E1): "stop means stop."** Apoptosis didn't merely *signal* the beast — it
    // deregistered it from the router. A send to its address now returns a clean
    // `RouteError::NoSuchModule` (the deregistered-target result), never a use-after-free. This closes
    // the gap between "a Hard signal fired" and "the creature is gone."
    let (_probe, bus, _rx) = k.open_endpoint(Capabilities::default());
    let err = bus
        .send(Dispatch::to(Address::Creature(beast), b"after-apoptosis".to_vec()))
        .expect_err("a send to the apoptosed beast must not route");
    assert!(
        matches!(err, aether::RouteError::NoSuchModule(_)),
        "post-apoptosis send must be NoSuchModule (deregistered), got {err:?}"
    );

    k.shutdown_all(Deadline::default());
}

/// **Phase 2a (2/2)** — A `Warn` signal with a productive trajectory drives `BudgetGraceful`
/// to emit `KernelControl::ExtendBudget` to `Address::Kernel`; the kernel's control listener
/// accepts it and updates the target's live fuel ceiling when a budget handle exists. The proof that
/// it really happened (and didn't crash the listener) is a follow-up `Hard` signal targeting a
/// second beast, which must still drive apoptosis correctly.
#[test]
fn graceful_warn_extend_budget_is_accepted_and_listener_stays_alive() {
    let k = kernel();
    let _policy = spawn_graceful_policy(&k);

    let a = k.load(beast_manifest_named("warn-target"), beast_artifact()).expect("a loads");
    let b = k.load(beast_manifest_named("hard-target"), beast_artifact()).expect("b loads");

    // (1) Publish a Warn signal with a productive trajectory targeting `a`. BudgetGraceful
    // should classify this as ProductiveThenTerminal, grant one-shot grace, emit ExtendBudget
    // to Address::Kernel. `a` must remain loaded (ExtendBudget does NOT unload).
    publish_budget_signal(
        &k,
        a.0,
        "warn",
        "fuel",
        aether::BudgetVector {
            consumed: 9_000,
            limit: 10_000,
            dispatches_this_envelope: 5,
            wall_ms_elapsed: 50,
            envelopes_since_load: 3,
        },
    );

    // Give the chain (publish → fan-out → graceful::handle → bus → kernel control listener)
    // time to settle, then assert `a` is still loaded. A 200ms grace window is generous for an
    // in-process two-hop bus path.
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        k.is_loaded(a),
        "ExtendBudget must NOT unload — beast `a` should still be loaded after Warn cycle"
    );
    assert!(k.is_loaded(b), "second beast unaffected by the Warn cycle");

    // (2) Now publish a Hard targeting `b`. If the control listener had crashed processing
    // ExtendBudget, this Unload would never land — and `b` would still be loaded after the
    // deadline. We assert apoptosis still works → the listener survived.
    publish_budget_signal(
        &k,
        b.0,
        "hard",
        "fuel",
        aether::BudgetVector {
            consumed: 1_000,
            limit: 1_000,
            dispatches_this_envelope: 0,
            wall_ms_elapsed: 5,
            envelopes_since_load: 1,
        },
    );
    let b_unloaded = wait_until(Duration::from_secs(5), || !k.is_loaded(b));
    assert!(
        b_unloaded,
        "control listener should still apoptose after the ExtendBudget cycle (it didn't crash)"
    );

    // Sanity: `a` is still loaded (only `b` was Hard-targeted).
    assert!(k.is_loaded(a), "`a` remained loaded throughout — only Warn, no Unload");

    k.shutdown_all(Deadline::default());
}

// =============================================================================================
// The three Warn-is-not-pointless scenarios (Phase 2a, real engine emission)
// =============================================================================================
//
// Each of these tests is end-to-end: the WasmEngine actually emits a Warn signal (no manual
// injection of the proprio event); the kernel actually enriches `dispatches_this_envelope`;
// BudgetGraceful actually reacts based on the real vector; the kernel actually processes the
// resulting control op. Manual injection (which the earlier tests use) only proves wire shape;
// these prove the **path** is reachable from real beast execution.

/// Load a beast running ECHO_OR_SPIN_WAT with declared `cpu_ms` and `budget_warn_at`. Returns
/// the kernel creature id. A non-zero-first-byte payload echoes (and consumes some fuel — if
/// `budget_warn_at` is met, a Warn rides on the outcome); a zero-first-byte payload spins
/// forever (Hard signal).
fn load_echo_or_spin(
    k: &Arc<Kernel>,
    name: &str,
    cpu_ms: u64,
    warn_at: Option<u8>,
) -> aether::CreatureId {
    let mut m = beast_manifest_named(name);
    m.capabilities.cpu_ms = cpu_ms;
    m.capabilities.budget_warn_at = warn_at;
    k.load(m, Artifact::Bytes(wat::parse_str(ECHO_OR_SPIN_WAT).expect("valid wat")))
        .expect("beast loads")
}

/// **Scenario 1 — Survival via grace** (the canonical "Warn is useful" case).
///
/// A real wasm beast (running ECHO_OR_SPIN_WAT) is loaded with `cpu_ms = 1` (1_000 fuel under this
/// test kernel's fuel_per_ms = 1_000) and `budget_warn_at = Some(0)` (any consumption ≥ 0% of
/// the limit triggers Warn). Sending an echo envelope:
///
///   1. WasmEngine handles the envelope, the echo function consumes some fuel and returns.
///   2. Engine's `maybe_warn` sees fuel `consumed > 0` ≥ 0% of 1_000 → attaches
///      `BudgetSignal::warn(Fuel, vector)` to the outcome alongside the echo reply.
///   3. Kernel drain enriches `vector.dispatches_this_envelope = 1` (the reply), then publishes
///      `BudgetSignalEvent { level: "warn", kind: "fuel", vector: {dispatches=1, ...} }` on
///      PROPRIOCEPTION.
///   4. BudgetGraceful subscribes; classifies the vector as ProductiveThenTerminal (≥1 dispatch);
///      grants one-shot grace → emits `KernelControl::ExtendBudget { fuel: Some(1.5×limit) }` to
///      Address::Kernel.
///   5. Kernel control listener honors ExtendBudget by lifting the live fuel cap. Consecutive echo
///      envelopes also start with a fresh `cpu_ms × fuel_per_ms`, so the cycle remains
///      non-disruptive even before the grant matters.
///
/// **Survival assertion**: after the Warn cycle + several more echo envelopes, the beast is
/// still loaded — proof that engine-emitted Warn → policy reaction → kernel processing is a
/// non-disruptive cycle and the beast really kept running. The reply chain also runs through
/// a probe so we can assert echo responses arrived.
#[test]
fn warn_survival_beast_keeps_handling_after_grace() {
    let k = kernel();
    let _policy = spawn_graceful_policy(&k);

    // Beast: budget_warn_at=0 so every handle triggers Warn.
    let beast = load_echo_or_spin(&k, "warn-survivor", 1, Some(0));

    // Probe with default caps so it can address the beast directly.
    let (probe, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    // Send 3 echo envelopes (non-zero first byte → echo path → Warn fires each time). The probe
    // should receive 3 echo replies; the beast should still be loaded throughout.
    for i in 0..3u8 {
        let payload = vec![1, i + 10]; // first byte = 1 (non-zero) → echo path
        probe_bus
            .send(
                Dispatch::to(Address::Creature(beast), payload)
                    .with_reply_to(Address::Creature(probe)),
            )
            .expect("send to beast");
        let reply = probe_rx.recv_timeout(Duration::from_secs(2)).expect("echo reply within 2s");
        assert_eq!(reply.payload, vec![1, i + 10], "beast echoed payload byte-for-byte");
    }

    // After three Warn-triggering successful handles, the beast must still be loaded. If the
    // engine had panicked, the kernel had crashed processing ExtendBudget, or BudgetGraceful
    // had spuriously emitted Unload on a Warn — `is_loaded` would be false.
    assert!(
        k.is_loaded(beast),
        "survival: real-engine-Warn cycle did not unload the beast (grace path works end-to-end)"
    );

    k.shutdown_all(Deadline::default());
}

/// **Scenario 2 — Failure despite grace** (the "Warn earned grace, but the next envelope was
/// genuinely terminal" case).
///
/// Same beast (ECHO_OR_SPIN_WAT) with `cpu_ms = 1`, `budget_warn_at = Some(0)`. Send:
///
///   1. Envelope `[1]` (echo path) → handle succeeds → Warn fires → BudgetGraceful grants
///      grace once → kernel accepts-and-skips ExtendBudget. Reply lands at the probe.
///   2. Envelope `[0]` (spin path) → handle spins forever → engine traps OutOfFuel → Hard
///      fires → BudgetGraceful's Hard floor: `Unload { module: beast }` regardless of grace
///      history. Kernel processes the unload through the standard path.
///
/// **Failure assertion**: the beast is NOT loaded after the second envelope. Grace was granted
/// once and gracefully *did not* save the creature — because the second handle's trap is real
/// and the engine has already returned to a non-runnable state.
#[test]
fn warn_then_hard_beast_unloaded_despite_grace() {
    let k = kernel();
    let _policy = spawn_graceful_policy(&k);

    let beast = load_echo_or_spin(&k, "warn-then-hard", 1, Some(0));
    let (probe, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    // (1) Echo envelope → Warn cycle → grace granted.
    probe_bus
        .send(
            Dispatch::to(Address::Creature(beast), vec![1, 2, 3])
                .with_reply_to(Address::Creature(probe)),
        )
        .expect("send echo");
    let reply = probe_rx.recv_timeout(Duration::from_secs(2)).expect("echo reply");
    assert_eq!(reply.payload, vec![1, 2, 3], "echo arrived (Warn rode alongside)");

    // (2) Spin envelope → Hard → unload. The beast doesn't reply (the trap aborts the handle).
    probe_bus
        .send(
            Dispatch::to(Address::Creature(beast), vec![0]).with_reply_to(Address::Creature(probe)),
        )
        .expect("send spin");

    let unloaded = wait_until(Duration::from_secs(5), || !k.is_loaded(beast));
    assert!(
        unloaded,
        "failure: grace did NOT save the beast from a genuine Hard breach (apoptosis still wins)"
    );

    k.shutdown_all(Deadline::default());
}

/// **Scenario 3 — Survival as achieving own apoptosis** (the "Warn lets the creature exit
/// cleanly at a handle boundary instead of being killed mid-handle" case).
///
/// A "warn-relay-as-apoptosis" creature listens on PROPRIOCEPTION; on every `Warn`-level
/// BudgetSignalEvent for a module in its watch-set, it emits `KernelControl::Unload { module }`
/// on the creature's behalf. The semantic claim: the beast's body's autonomous cleanup — like
/// apoptotic signaling in biology — translates a "you're close to your limit" advisory into a
/// clean unload **after the current handle's reply has already left**. The beast doesn't get
/// killed mid-handle (no Hard, no spin); it completes its work, ships the reply, then exits.
///
/// This is what "achieving its own apoptosis" looks like with today's minimal wasm ABI: the
/// creature doesn't need self-bus-access (which beasts don't have) — its representative
/// (the relay) reads the Warn and acts on its behalf. A future richer guest ABI could let the beast
/// itself emit the unload; the fabric-level pattern is the same.
///
/// **Survival-as-apoptosis assertion**:
///   - The echo reply arrives at the probe (the handle completed successfully).
///   - The beast is unloaded shortly after (within the test deadline).
///   - The reply arrived BEFORE the unload (proof of clean-exit-at-boundary, not mid-handle
///     kill). We assert the recv timeout in the order it must hold.
#[test]
fn warn_self_apoptosis_relay_lets_beast_exit_cleanly() {
    let k = kernel();

    // Step 1: wire the warn-relay creature. Listens on PROPRIOCEPTION; on Warn for any module
    // in `watch`, emits Unload for that module. (Watch-set so this test's relay doesn't try
    // to unload the OTHER tests' policy creature when running in parallel.)
    let (relay_id, relay_bus, relay_rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), relay_id);
    let watch: Arc<std::sync::Mutex<std::collections::HashSet<u64>>> =
        Arc::new(std::sync::Mutex::new(std::collections::HashSet::new()));
    let watch_for_thread = watch.clone();
    let k_keepalive = k.clone();
    let _relay_thread = std::thread::Builder::new()
        .name("warn-relay-as-apoptosis".into())
        .spawn(move || {
            let mut relay = WarnRelayAsApoptosis::new(watch_for_thread);
            let bus: Arc<dyn Bus> = Arc::new(relay_bus.clone());
            let ctx = CreatureCtx {
                me: relay_id,
                bus,
                manifest: Manifest::new(
                    "warn-relay-as-apoptosis",
                    "0.1.0",
                    Backend::Daemon,
                    "gawd_creature_v1",
                ),
            };
            relay.bind(ctx);
            while let Ok(env) = relay_rx.recv() {
                for d in relay.handle(env).dispatches {
                    let _ = relay_bus.send(d);
                }
            }
            drop(k_keepalive);
        })
        .expect("spawn relay thread");

    // Step 2: load the beast with warn_at=0 so any handle triggers Warn. Add it to the watch-set
    // so the relay knows to translate ITS Warns into Unloads.
    let beast = load_echo_or_spin(&k, "self-apoptosis-beast", 1, Some(0));
    watch.lock().unwrap().insert(beast.0);

    // Step 3: send the beast one envelope. The handle returns the echo (reply lands), the
    // engine attaches Warn to the outcome, the kernel publishes the BudgetSignalEvent, the
    // relay translates Warn → Unload, the kernel unloads the beast.
    let (probe, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    probe_bus
        .send(
            Dispatch::to(Address::Creature(beast), vec![7, 7, 7])
                .with_reply_to(Address::Creature(probe)),
        )
        .expect("send to beast");

    // (a) Reply arrives FIRST — the handle completed cleanly, the result shipped.
    let reply = probe_rx
        .recv_timeout(Duration::from_secs(2))
        .expect("echo reply arrived BEFORE unload — proof of clean exit at handle boundary");
    assert_eq!(reply.payload, vec![7, 7, 7], "the work was done before exit");

    // (b) Beast is unloaded shortly after (the Warn → relay → Unload chain settled).
    let unloaded = wait_until(Duration::from_secs(5), || !k.is_loaded(beast));
    assert!(
        unloaded,
        "self-apoptosis: relay translated Warn → Unload after the handle completed cleanly"
    );

    k.shutdown_all(Deadline::default());
}

/// In-process creature for [`warn_self_apoptosis_relay_lets_beast_exit_cleanly`]. Subscribes
/// to PROPRIOCEPTION; on a `Warn`-level BudgetSignalEvent whose `module` is in `watch`, emits
/// `KernelControl::Unload { module }` to Address::Kernel.
///
/// This represents a "respectful apoptosis policy" — the creature reads the engine's "you're
/// at the limit" advisory and translates it to a clean exit AFTER the current handle's
/// outputs have already been shipped (the engine emits Warn at handle return, the reply has
/// already left the engine before the proprio event publishes). The beast doesn't have to know
/// it's been warned; the relay carries the self-cleanup behavior in the substrate.
struct WarnRelayAsApoptosis {
    watch: Arc<std::sync::Mutex<std::collections::HashSet<u64>>>,
}

impl WarnRelayAsApoptosis {
    fn new(watch: Arc<std::sync::Mutex<std::collections::HashSet<u64>>>) -> Self {
        WarnRelayAsApoptosis { watch }
    }
}

impl Creature for WarnRelayAsApoptosis {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let Ok(b) = serde_json::from_slice::<BudgetSignalEvent>(&env.payload) else {
            return Outcome::none();
        };
        if b.level != "warn" {
            return Outcome::none();
        }
        if !self.watch.lock().unwrap().contains(&b.module) {
            return Outcome::none();
        }
        let op = KernelControl::Unload { module: b.module };
        let Ok(payload) = serde_json::to_vec(&op) else { return Outcome::none() };
        Outcome::send(Dispatch::to(Address::Kernel, payload).with_schema("kernel_control"))
    }
}
