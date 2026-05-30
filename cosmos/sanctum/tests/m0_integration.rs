//! Walking-skeleton exit-criteria suite — the integration proof that all R1–R9 integration
//! risks are crossed once, end-to-end, through the same kernel API. Criterion #9 (REPL control
//! loop) is exercised in `alpha/tests/node_repl.rs`; #10 (Miri-friendly revocation) lives in the
//! `aether` unit tests; #11 (fabric-integrity floor: bounded
//! queues + no-panic parsing + creature-fault isolation) is covered by aether + sanctum unit
//! tests and is referenced in #18.

use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Deadline, Dispatch, Intent, NodeId, Role, RouteError, StubSigner, StubVerifier, Topic,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use distributor_roundrobin::RoundRobinDistributor;
use loopback_gateway::LoopbackGateway;
use policy_dev::DevPolicy;
use sanctum::{Kernel, Proprioception};
use sigil::{Backend, Capabilities, Manifest};

mod support;
use support::native_cdylib;

// A real wasm "beast" that reverses its input bytes. Memory + bump alloc + a tight byte-copy loop
// returning `(out_ptr << 32) | len`. Compiled to wasm here via `wat::parse_str` — same bytecode
// wasmtime executes.
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

fn echo_daemon_path() -> std::path::PathBuf {
    native_cdylib("echo_daemon")
}

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn daemon_manifest() -> Manifest {
    Manifest::new("echo-daemon", "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

fn beast_manifest() -> Manifest {
    Manifest::new("echo-beast", "0.1.0", Backend::Beast, "gawd_creature_v1")
}

fn beast_artifact() -> Artifact {
    Artifact::Bytes(wat::parse_str(REVERSE_BEAST_WAT).expect("valid wat"))
}

#[test]
fn c1_c2_both_tiers_load_and_reverse_through_one_path() {
    let k = kernel();
    let daemon_path = echo_daemon_path();

    // C1: same Kernel::load path; only `abi.backend` differs.
    let daemon_id = k.load(daemon_manifest(), Artifact::Path(daemon_path)).expect("daemon loads");
    let beast_id = k.load(beast_manifest(), beast_artifact()).expect("beast loads");

    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    // C2: reverse "abc" → "cba" through BOTH tiers; reply envelopes carry fabric-set fields.
    for id in [daemon_id, beast_id] {
        bus.send(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .unwrap();
        let env = rx.recv_timeout(Duration::from_secs(2)).expect("reply arrives");
        assert_eq!(env.payload, b"cba", "tier {id:?} did not reverse");
        assert!(matches!(env.header.from, Address::Creature(_)), "from sealed by the bus");
        assert!(!env.header.sig.is_empty(), "sig present (R5)");
        assert!(env.header.stamp > 0, "router-set logical time");
    }
    k.shutdown_all(Deadline::default());
}

#[test]
fn c3_stamp_is_logical_and_sig_present_on_every_envelope() {
    let k = kernel();
    let beast_id = k.load(beast_manifest(), beast_artifact()).unwrap();
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    let mut prev_stamp = 0u64;
    for i in 0..3 {
        let payload = format!("p{i}").into_bytes();
        bus.send(
            Dispatch::to(Address::Creature(beast_id), payload)
                .with_reply_to(Address::Creature(probe)),
        )
        .unwrap();
        let env = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        // R5: stamp advances per change-of-state, NOT a wall clock.
        assert!(env.header.stamp > prev_stamp, "stamp must advance on every routed envelope");
        prev_stamp = env.header.stamp;
        assert!(!env.header.sig.is_empty(), "sig must be present on every envelope (R5)");
    }
    k.shutdown_all(Deadline::default());
}

#[test]
fn c4_node_address_round_trips_real_bytes_through_the_gateway() {
    let k = kernel();
    let daemon_id =
        k.load(daemon_manifest(), Artifact::Path(echo_daemon_path())).expect("daemon loads");

    // Bind the loopback gateway to the transport role.
    let gw = LoopbackGateway::new().unwrap();
    let gw_id = k
        .load_instance(
            Manifest::new("loopback-gateway", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(gw),
        )
        .unwrap();
    k.bind_role(Role::new(Role::TRANSPORT), gw_id);

    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    // Node-addressed → gateway → real Unix socketpair (bytes!) → deserialize → re-route to
    // Creature(target). Echo replies to reply_to (the probe) DIRECTLY — not via the gateway (R8).
    bus.send(
        Dispatch::to(Address::Node(NodeId("self".into()), daemon_id), b"abc".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .unwrap();
    let env = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(env.payload, b"cba", "node→gateway→echo round-trip must reverse the payload");
    k.shutdown_all(Deadline::default());
}

#[test]
fn c5_intent_routes_via_bound_resolver_and_reply_to_finds_the_original() {
    let k = kernel();
    let daemon_id =
        k.load(daemon_manifest(), Artifact::Path(echo_daemon_path())).expect("daemon loads");

    // Inject the example round-robin distributor into the Distributor socket.
    let distributor = RoundRobinDistributor::with_targets(vec![daemon_id]);
    let distributor_id = k
        .load_instance(
            Manifest::new("distributor-roundrobin", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(distributor),
        )
        .unwrap();
    k.bind_role(Role::new(Role::DISTRIBUTOR), distributor_id);

    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(
            Address::Intent(Intent { outcome: "reverse".into(), requirements: vec![] }),
            b"abc".to_vec(),
        )
        .with_reply_to(Address::Creature(probe))
        .with_corr(42),
    )
    .unwrap();
    let env = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(env.payload, b"cba", "intent → distributor → echo → original requester");
    assert_eq!(env.header.corr, Some(42), "corr preserved end-to-end (fire-and-correlate)");
    k.shutdown_all(Deadline::default());
}

#[test]
fn c5b_no_resolver_bound_yields_structured_no_provider() {
    let k = kernel();
    let (_probe, bus, _rx) = k.open_endpoint(Capabilities::default());
    let err = bus
        .send(Dispatch::to(
            Address::Intent(Intent { outcome: "x".into(), requirements: vec![] }),
            vec![],
        ))
        .unwrap_err();
    // The fabric supplies no model when nothing is bound — a clean error, never a default behavior.
    assert!(matches!(err, RouteError::NoProvider(_)));
}

#[test]
fn c6_kernel_driven_unload_for_both_tiers_yields_no_such_module() {
    let k = kernel();
    let daemon_id =
        k.load(daemon_manifest(), Artifact::Path(echo_daemon_path())).expect("daemon loads");
    let beast_id = k.load(beast_manifest(), beast_artifact()).expect("beast loads");

    let (_probe, bus, _rx) = k.open_endpoint(Capabilities::default());

    k.unload(daemon_id, Deadline::default()).unwrap();
    k.unload(beast_id, Deadline::default()).unwrap();

    for id in [daemon_id, beast_id] {
        let err = bus.send(Dispatch::to(Address::Creature(id), b"x".to_vec())).unwrap_err();
        assert!(
            matches!(err, RouteError::NoSuchModule(_)),
            "post-unload routing must be a structured error, never UB (R2)"
        );
    }
}

#[test]
fn c7_admission_runs_the_mechanism_and_consults_the_injected_policy() {
    // Deny-policy: same kernel construction, different injected model. The fabric is unchanged.
    struct Deny;
    impl sanctum::Policy for Deny {
        fn admit(&self, _m: &Manifest, _e: &sanctum::Admission) -> Result<(), String> {
            Err("denied for the test".into())
        }
    }
    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("n")),
        Arc::new(StubVerifier),
        Arc::new(Deny),
        128,
    );
    let err = k.load(beast_manifest(), beast_artifact()).unwrap_err();
    assert!(matches!(err, sanctum::KernelError::AdmissionRejected(_)));
}

#[test]
fn c8_proprioception_carries_a_loaded_event_for_both_tiers() {
    let k = kernel();
    let (sub, _b, rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), sub);

    let _daemon_id =
        k.load(daemon_manifest(), Artifact::Path(echo_daemon_path())).expect("daemon loads");
    let _beast_id = k.load(beast_manifest(), beast_artifact()).expect("beast loads");

    // Drain up to a handful of events looking for two `loaded` ones (one per tier).
    let mut loaded_events = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline && loaded_events < 2 {
        if let Ok(env) = rx.recv_timeout(Duration::from_millis(200)) {
            if let Ok(p) = serde_json::from_slice::<Proprioception>(&env.payload) {
                if p.event == "loaded" {
                    loaded_events += 1;
                }
            }
        }
    }
    assert_eq!(loaded_events, 2, "both tiers publish a `loaded` proprioception event");
    k.shutdown_all(Deadline::default());
}

// Criterion #6/#11 is also covered by aether::tests::deregister_makes_routing_fail_cleanly_not_ub,
// which is intentionally pure-logic (no threads, no FFI) → Miri-compatible. Run criterion #10 with:
//   cargo +nightly miri test -p aether deregister_makes_routing_fail_cleanly_not_ub
// (the R7 verification split is recorded in #18).
