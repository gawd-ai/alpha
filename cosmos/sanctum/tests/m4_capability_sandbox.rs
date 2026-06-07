//! Capability & sandbox. The exit-criteria suite.
//!
//! Exit criteria:
//! (a) creature sandboxed with `net:none` attempting egress is blocked + observable.
//! (b) budget-exceeding creature terminated + unloaded cleanly.
//! (c) per-tier enforcers: native (process-level sandbox, trusted-by-admission),
//!     wasm (host-import gating + fuel/memory metering), and script via the Rhai tier.
//! (d) tier-as-containment proven: same `capabilities` block runs unconfined as a native daemon
//!     **and** contained as a WASM beast — operator's call, one manifest body.
//! (e) required-provenance policy (injected) rejects tampered/unsigned.
//!
//! IoC discipline: the *mechanism* lives in the substrate (wasmtime fuel, the
//! `BudgetSignalEvent` proprio event with level/kind/vector, the `Capabilities.calls` gate at the
//! router choke point); the *decision* (when to apoptose, which authors to trust, which sandbox
//! prefix to apply) lives in an injected creature. The kernel ships sockets, never a model of
//! trust or apoptosis.
//!
//! The signal shape is level/kind/vector; engines emit `Warn`, `Hard`,
//! and honor grace via `KernelControl::ExtendBudget`.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Creature, Deadline, Dispatch, RouteError, StubSigner, StubVerifier};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

mod support;
use support::native_cdylib;

// A reverse-beast bytecode shape — a real wasm module that we want to load and route to.
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
        (local $out_ptr i32)
        (local $i i32)
        (local.set $out_ptr (global.get $bump))
        (global.set $bump (i32.add (global.get $bump) (local.get $len)))
        (local.set $i (i32.const 0))
        (block $done
          (loop $copy
            (br_if $done (i32.ge_u (local.get $i) (local.get $len)))
            (i32.store8
              (i32.add (local.get $out_ptr) (local.get $i))
              (i32.load8_u (i32.sub (i32.add (local.get $ptr) (local.get $len))
                                    (i32.add (local.get $i) (i32.const 1)))))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $copy)))
        (i64.or
          (i64.shl (i64.extend_i32_u (local.get $out_ptr)) (i64.const 32))
          (i64.extend_i32_u (local.get $len)))))
"#;

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![
            Arc::new(NativeEngine),
            Arc::new(WasmEngine::new().with_fuel_per_ms(1_000)),
            Arc::new(ScriptEngine),
        ],
        Arc::new(StubSigner::new("m4-node")),
        Arc::new(StubVerifier),
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

/// **`Capabilities.calls` at admit-and-route grain.**
///
/// The router unit tests in `aether` prove the gate's *function*; this test proves the integration
/// path: a real Beast is loaded by the kernel with restricted `calls`, an open endpoint is the
/// declared destination, and a routed envelope to an *undeclared* sibling fails with
/// [`RouteError::Denied`] at the one bus-level choke point.
#[test]
fn capabilities_calls_gate_is_enforced_at_admit_and_route() {
    let k = kernel();

    // A second beast that exists solely to be a routable-but-disallowed destination. The
    // `calls`-restricted sender (the probe endpoint, below) will be denied addressing this one.
    let forbidden = k.load(beast_manifest_named("forbidden-sink"), beast_artifact()).unwrap();

    // A third beast that the probe IS allowed to call.
    let allowed = k.load(beast_manifest_named("allowed-sink"), beast_artifact()).unwrap();

    // Open a probe endpoint with caps that allowlist *only* the allowed sink. The router's
    // `caps_allow` resolves `Address::Creature(id)` to `"creature:<id>"`, so we declare the same shape.
    let caps =
        Capabilities { calls: vec![format!("creature:{}", allowed.0)], ..Capabilities::default() };
    let (probe, bus, rx) = k.open_endpoint(caps);

    // Allowed: passes the gate, the beast runs, the reply lands in the probe's inbox.
    bus.send(
        Dispatch::to(Address::Creature(allowed), b"abc".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .expect("allowed send must pass the call-gate");
    let env = rx.recv_timeout(Duration::from_secs(2)).expect("allowed reply arrives");
    assert_eq!(env.payload, b"cba", "the allowed beast reverses as expected");

    // Disallowed: the kernel's `route` returns Denied at admit-and-route level. The forbidden
    // beast never sees the envelope — the gate is *before* delivery, not a beast-side check.
    let err = bus
        .send(Dispatch::to(Address::Creature(forbidden), b"sneak".to_vec()))
        .expect_err("disallowed destination must be denied");
    assert!(
        matches!(err, RouteError::Denied { from } if from == probe),
        "disallowed destination must be Denied with the sender's id, got {err:?}"
    );

    k.shutdown_all(Deadline::default());
}

/// **Empty `calls` is opt-in unrestricted (the default holds).**
///
/// The call-gate is *opt-in*: empty `calls` means "this creature has not asked for restriction,"
/// which is the dev default. Capability enforcement must not change that — an operator
/// who doesn't fill `calls` is choosing the unconfined path knowingly, never silently restricted.
#[test]
fn empty_calls_means_unrestricted_dev_default() {
    let k = kernel();
    let sink_a = k.load(beast_manifest_named("sink-a"), beast_artifact()).unwrap();
    let sink_b = k.load(beast_manifest_named("sink-b"), beast_artifact()).unwrap();
    // Capabilities::default() has empty `calls` — the unrestricted dev shape.
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    for sink in [sink_a, sink_b] {
        bus.send(
            Dispatch::to(Address::Creature(sink), b"abc".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .expect("empty calls means unrestricted — both sinks must be addressable");
        let env = rx.recv_timeout(Duration::from_secs(2)).expect("reply arrives");
        assert_eq!(env.payload, b"cba");
    }
    k.shutdown_all(Deadline::default());
}

// Daemon path is referenced by later tests (tier-as-containment proof) — keep this here so the
// helper compiles standalone now, and the (d) test can use it without re-introducing it.
#[allow(dead_code)]
fn require_echo_daemon() -> std::path::PathBuf {
    native_cdylib("echo_daemon")
}

/// **Exit criterion (e) — required-provenance policy rejects tampered/unsigned.**
///
/// `SignedPolicy` already demonstrates the *gate*; this test closes the loop by binding
/// it as the default policy and confirming that an unsigned manifest is refused
/// at admission *before any engine touches it*. The other side of the gate (tampered artifact
/// bytes) is exhaustively covered by the `m2_integrity` suite — this test doesn't duplicate that work;
/// it asserts the *same mechanism* applies under a capability-enforcing kernel construction.
///
/// It reuses the admission gate literally: same policy crate, same evidence shape, same admission seam —
/// capability/sandbox enforcement layers *on top* of the admission gate, not in place of it.
#[test]
fn signed_policy_under_m4_kernel_rejects_unsigned_manifest_at_admission() {
    use aether::Ed25519Verifier;
    use policy_signed::SignedPolicy;

    let k = sanctum::Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("signed-m4-node")),
        Arc::new(Ed25519Verifier),
        // `any_signed_author()` is the right shape: integrity ON, but no Abode-key allowlist —
        // this isolates the test to "is signature required at all," not "is the right key trusted."
        Arc::new(SignedPolicy::any_signed_author()),
        128,
    );

    // An *unsigned* manifest — provenance.signature absent. SignedPolicy must reject before the
    // engine ever sees the bytes.
    let unsigned = beast_manifest_named("unsigned-beast");
    let err = k
        .load(unsigned, beast_artifact())
        .expect_err("SignedPolicy must reject an unsigned manifest");
    assert!(
        matches!(&err, sanctum::KernelError::AdmissionRejected(msg) if msg.contains("unsigned")),
        "expected an admission rejection naming the missing signature, got {err:?}"
    );

    k.shutdown_all(Deadline::default());
}

// A WAT module that loops forever in `handle` — used by the (b) test to provoke a fuel breach.
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

/// **Exit criterion (d) — tier-as-containment proven.**
///
/// The **same `capabilities` block** ships as both a native daemon (no in-process containment;
/// trusted-by-admission) and a WASM beast (closed-imports containment by construction). The
/// operator picks the tier per workload via `abi.backend` — *one manifest body modulo the tier
/// field, two different containment profiles*. The reversing capability runs in both and produces
/// the same result for the same input.
///
/// What this test proves:
/// 1. A capabilities block declared once is byte-identical in both manifest variants — the
///    operator authors capability intent once.
/// 2. Both tiers load and route through the same `Kernel::load` / `Router::route` path (R3/R4).
/// 3. Same input, same output — the *capability* is the same; the *containment* is the operator's
///    choice. (Tier-choice IS containment.)
///
/// The capability we encode is deliberately conservative: `net = None`, `cpu_ms = 100`, no fs
/// access — the kind of bound an operator who *wants* the beast tier would declare anyway. The
/// daemon variant runs unconfined-in-process at runtime (the operator's choice); the beast variant
/// is closed-import-locked by the loader.
#[test]
fn tier_as_containment_same_caps_run_as_daemon_or_beast() {
    use sigil::{Backend, NetCapability};

    let k = kernel();
    let daemon_path = require_echo_daemon();

    // The single capability declaration shared by both tier variants. This is the "authored once"
    // surface; the only thing that differs between the two manifests below is `abi.backend`.
    let shared_caps = Capabilities {
        fs: vec![],
        net: NetCapability::None,
        cpu_ms: 100,
        mem_bytes: 4 * 1024 * 1024, // 4 MiB — plenty for the reverse beast
        calls: vec![],
        budget_warn_at: None,
        wall_ms: None,
    };

    // Daemon variant — same caps, native tier. The .so was built at workspace `cargo build` time.
    let mut as_daemon =
        Manifest::new("reverser-as-daemon", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    as_daemon.capabilities = shared_caps.clone();

    // Beast variant — same caps, beast tier. The wasm bytes are the reverse-beast (compiled
    // here from WAT so the test is self-contained).
    let mut as_beast =
        Manifest::new("reverser-as-beast", "0.1.0", Backend::Beast, "gawd_creature_v1");
    as_beast.capabilities = shared_caps.clone();

    // (1) The capabilities block is *byte-identical* in both manifests — the operator authored
    // capability intent once, separately from the containment-tier choice.
    assert_eq!(
        as_daemon.capabilities, as_beast.capabilities,
        "the authored capability is one declaration, regardless of tier — that's the discipline"
    );

    // (2) Both load through the same `Kernel::load` path; only `abi.backend` changes.
    let daemon_id = k.load(as_daemon, Artifact::Path(daemon_path)).expect("daemon variant loads");
    let beast_id = k.load(as_beast, beast_artifact()).expect("beast variant loads");

    // (3) Both reverse "abc" → "cba". Same input, same output — the *capability* the operator
    // declared runs identically in either containment profile.
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    for id in [daemon_id, beast_id] {
        bus.send(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .expect("send to reverser variant");
        let env = rx.recv_timeout(Duration::from_secs(2)).expect("reply arrives");
        assert_eq!(env.payload, b"cba", "tier {id:?} did not reverse — capability is not the same");
    }

    k.shutdown_all(Deadline::default());
}

/// **Exit criterion (a) — WASM: `net:none` is enforced by construction.**
///
/// The beast tier exposes **no host imports** — a guest can't `socket()`, `connect()`, or
/// touch the file system because there's no host function to call. A beast that *declares* a
/// host import in its wasm module fails to instantiate with a structured engine error, never an
/// undefined-symbol crash. The signal that should hit the operator's eye: a wasm load error that
/// names the missing import.
///
/// This is the honest line for the beast tier: enforcement isn't a runtime check, it's a
/// *property of the loader*. The day a host import lands in a richer guest ABI, it'll be gated
/// on `manifest.capabilities.net` — the seam is the import name, not a new manifest field.
#[test]
fn wasm_beast_attempting_host_import_fails_to_load_net_none_by_construction() {
    // A WAT module that *declares* a host import the beast tier doesn't provide. Wasmtime's
    // `Instance::new` fails at instantiation because no host functions are linked.
    const NEEDS_NET_WAT: &str = r#"
        (module
          (import "host" "net_send" (func $net_send (param i32 i32) (result i32)))
          (memory (export "memory") 1)
          (func (export "alloc") (param $len i32) (result i32) (i32.const 0))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (drop (call $net_send (local.get $ptr) (local.get $len)))
            (i64.const 0)))
    "#;
    let wasm = wat::parse_str(NEEDS_NET_WAT).expect("valid wat");
    let k = kernel();
    let m = beast_manifest_named("netty-beast");
    let err = k.load(m, Artifact::Bytes(wasm)).expect_err("must fail; net is not granted");
    // The error surface is a structured kernel error — never a host crash, never UB. R9.
    let msg = format!("{err}");
    assert!(
        msg.contains("instantiate") || msg.contains("import"),
        "expected an instantiate/import-related error message, got {msg:?}"
    );
}

/// **Exit criterion (a) — native: an injected policy can enforce `net:none`.**
///
/// Native creatures are "trusted-by-admission": the substrate doesn't pretend to
/// confine in-process native code at runtime. What it ships is the evidence + the socket — an
/// operator who wants `net:none` for native writes (or binds) a policy creature that rejects
/// at admission any manifest with `capabilities.net != None`. The kernel honors the policy
/// without baking the rule in.
///
/// This test uses an in-test policy (the simplest possible NetNone enforcer) to prove the
/// admission seam works end-to-end. A production deployment would ship this rule inside a
/// composed policy creature (signed + net-none + …).
#[test]
fn native_admission_policy_can_demand_net_none_via_capabilities_evidence() {
    use sigil::NetCapability;

    struct NetNoneOnly;
    impl sanctum::Policy for NetNoneOnly {
        fn admit(&self, manifest: &sigil::Manifest, _e: &sanctum::Admission) -> Result<(), String> {
            // Read the manifest's declared net capability — the manifest is the SOLE
            // metadata source (R6), so the policy reads from there, not from a side channel.
            if manifest.capabilities.net != NetCapability::None {
                return Err(format!(
                    "net-none policy rejects manifest declaring net={:?}",
                    manifest.capabilities.net
                ));
            }
            Ok(())
        }
    }

    let k = sanctum::Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("netnone-node")),
        Arc::new(StubVerifier),
        Arc::new(NetNoneOnly),
        128,
    );

    // A `net:any` creature: the manifest declares it wants the network. Policy rejects.
    let mut wants_net = beast_manifest_named("wants-net");
    wants_net.capabilities.net = NetCapability::Any;
    let err = k
        .load(wants_net, beast_artifact())
        .expect_err("net-none policy must reject a net:any creature");
    assert!(
        matches!(&err, sanctum::KernelError::AdmissionRejected(msg) if msg.contains("net-none")),
        "expected a policy-shaped admission rejection, got {err:?}"
    );

    // The same creature with `net:None` (the dev default) is admitted.
    let mut ok_creature = beast_manifest_named("net-none-ok");
    ok_creature.capabilities.net = NetCapability::None;
    let _id = k.load(ok_creature, beast_artifact()).expect("net:none creature admitted");

    k.shutdown_all(Deadline::default());
}

/// **Exit criterion (b) — budget-exceeding creature terminated + unloaded cleanly.**
///
/// The IoC-pure chain (signal shape — level/kind/vector):
/// 1. A beast with `cpu_ms = 1` is loaded; its handler spins forever.
/// 2. We send it one envelope → wasmtime runs out of fuel → engine surfaces a
///    `BudgetSignal { level: Hard, kind: Fuel, vector: <measured> }` on the outcome.
/// 3. The kernel's drain publishes a `BudgetSignalEvent { module, level: "hard", kind: "fuel",
///    vector }` proprio event with the per-envelope trajectory scalars filled best-effort.
/// 4. An injected `BudgetApoptosis` creature subscribes to PROPRIOCEPTION and (because it sees
///    `level == "hard"`) sends back a `KernelControl::Unload { module }` envelope addressed to
///    `Address::Kernel`. The richer-policy contract is exactly the same; this example just
///    happens to be the simplest possible (kill on every Hard, ignore Warn).
/// 5. The kernel's control listener dispatches the unload through the unload path
///    (deregister → drain-stop → engine-unload).
/// 6. We poll `Kernel::is_loaded` to confirm the offender is gone.
///
/// What the kernel does NOT do: decide that a Hard signal should be fatal. That decision lives
/// entirely in the example policy creature, swap-able for any other (grace via ExtendBudget,
/// demote-to-beast, escalate to a human). The kernel ships the signal + the
/// socket, never the model.
#[test]
fn budget_breach_via_injected_policy_drives_kernel_to_apoptose_the_offender() {
    use aether::Topic;
    use policy_budget::BudgetApoptosis;

    let k = kernel();

    // (1) Load a beast with a tight cpu_ms budget. This test kernel deliberately uses a low
    // fuel-per-ms factor so the intentional spin traps quickly on a developer workstation.
    let mut greedy = beast_manifest_named("greedy-spin");
    greedy.capabilities.cpu_ms = 1;
    let wasm_bytes = wat::parse_str(SPIN_FOREVER_WAT).expect("valid wat");
    let greedy_id = k.load(greedy, Artifact::Bytes(wasm_bytes)).expect("beast loads");

    // (2) Install the injected budget-apoptosis policy. Open an endpoint for it on the bus, build a
    // drain thread manually so we drive its handle without going through Kernel::load (the policy
    // isn't an artifact-bytes creature — it's an in-process example, no admission needed).
    //
    // Subscribe it to PROPRIOCEPTION so the kernel's BudgetSignalEvent fan-out reaches it.
    let (policy_id, policy_bus, policy_rx) = k.open_endpoint(Default::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), policy_id);
    let policy_kernel_handle = k.clone();
    let _policy_thread = std::thread::Builder::new()
        .name("policy-budget-apoptosis".into())
        .spawn(move || {
            let mut p = BudgetApoptosis::new();
            // The policy needs a `CreatureCtx` for `bind` — we hand it a minimal one. The policy
            // ignores it (it has no own state to stash), but binding is part of the contract.
            use aether::{Bus, CreatureCtx};
            use sigil::Manifest;
            // CreatureCtx wants `Arc<dyn Bus>`; wrap the BusHandle into an Arc and let coercion do
            // the rest. `BusHandle: Bus + Clone`, so the wrapped clone is a valid trait object.
            let bus: std::sync::Arc<dyn Bus> = std::sync::Arc::new(policy_bus.clone());
            let ctx = CreatureCtx {
                me: policy_id,
                bus,
                manifest: Manifest::new(
                    "policy-budget",
                    "0.1.0",
                    sigil::Backend::Daemon,
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
            // Keep the kernel handle alive for the thread's lifetime so unload arrives even if the
            // outer test scope races to drop. The handle's drop is harmless (Arc).
            drop(policy_kernel_handle);
        })
        .expect("spawn policy thread");

    // (3) Send the greedy beast one envelope. The kernel's drain handles it → engine traps on
    // fuel → publishes `BudgetSignalEvent { level: "hard", kind: "fuel", vector }` → the policy
    // receives the proprio event and sends `KernelControl::Unload { greedy_id }` to
    // `Address::Kernel` → kernel's control listener calls `unload`. We then poll `is_loaded`
    // until it returns false.
    let (probe, probe_bus, _probe_rx) = k.open_endpoint(Capabilities::default());
    probe_bus
        .send(
            Dispatch::to(Address::Creature(greedy_id), b"go".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .expect("send to greedy beast");

    // (4) Wait for apoptosis. Generous timeout (5s) so a slow CI host has room; in practice the
    // round-trip is single-digit ms. We do NOT assert *which* thread did the unload — the IoC
    // contract is that the kernel acts on the control envelope, not who sent it.
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut unloaded = false;
    while std::time::Instant::now() < deadline {
        if !k.is_loaded(greedy_id) {
            unloaded = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        unloaded,
        "budget breach → injected policy → kernel control → unload chain did not complete within 5s"
    );

    // **The IoC proof.** The kernel didn't decide to kill the beast; the *injected* creature did,
    // and the kernel honored it through the same unload path normal `Kernel::unload` uses.
    k.shutdown_all(Deadline::default());
}
