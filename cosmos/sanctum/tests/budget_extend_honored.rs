//! **`ExtendBudget` is honored over the bus** (the cap-lifting seam).
//! The full gradient loop, through the real kernel:
//!
//! 1. A wasm beast with a small per-handle fuel cap runs a bounded loop that needs more fuel than
//!    the cap → it **traps**, and the kernel publishes a `Hard`/`Fuel` `BudgetSignalEvent` on
//!    `Topic::PROPRIOCEPTION` (observed by a subscribed probe). No reply.
//! 2. A `KernelControl::ExtendBudget { module, fuel: Some(big) }` is sent to `Address::Kernel` — the
//!    grant an injected policy (`cosmos/creatures/prototypes/policies/policy-budget`'s `BudgetGraceful`) would issue.
//! 3. The **same** payload is sent again → the beast now **completes** and replies. The grant lifted
//!    the live fuel ceiling the engine reads each handle. Survival via grace, end to end.
//!
//! The control listener honors `ExtendBudget` by live-lifting the cap; this test is the proof.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{Address, Deadline, Dispatch, Ed25519Verifier, InboxReceiver, StubSigner, Topic};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use sanctum::{BudgetSignalEvent, Kernel, KernelControl};
use sha2::{Digest, Sha256};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};

fn slow_factor() -> u64 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}
fn scaled(d: Duration) -> Duration {
    d * (slow_factor() as u32)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// A bounded-work beast: ~2k loop iterations then echo the payload. A small fuel cap traps it; a
/// lifted cap lets it finish — exactly the difference `ExtendBudget` must make.
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

fn recv_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<Vec<u8>> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env.payload),
            _ => continue,
        }
    }
    None
}

/// Wait for a `budget_signal` proprio event naming `module` at the given `level`.
fn recv_budget_signal(rx: &InboxReceiver, module: u64, level: &str, budget: Duration) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.schema == "budget_signal" => {
                if let Ok(ev) = serde_json::from_slice::<BudgetSignalEvent>(&env.payload) {
                    if ev.module == module && ev.level == level {
                        return true;
                    }
                }
            }
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    false
}

#[test]
fn extend_budget_over_the_bus_lifts_a_trapping_beasts_fuel_so_it_survives() {
    let node_key = Ed25519KeyMaterial::from_seed([0xE4u8; 32]).unwrap();
    // 1k fuel per ms → a cpu_ms=1 beast gets 1k fuel, less than the bounded loop needs.
    let k = Kernel::new(
        vec![
            Arc::new(NativeEngine),
            Arc::new(WasmEngine::new().with_fuel_per_ms(1_000)),
            Arc::new(ScriptEngine),
        ],
        Arc::new(StubSigner::new("v04-budget")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![node_key.public_hex().to_string()])),
        128,
    );

    // Build + sign the beast manifest (build_hash must match the artifact bytes for admission).
    let wasm = wat::parse_str(BOUNDED_LOOP_WAT).expect("valid wat");
    let mut m = Manifest::new("bounded-beast", "0.1.0", Backend::Beast, "gawd_creature_v1");
    m.capabilities.cpu_ms = 1; // 1_000 fuel
    m.provenance.author = Some(node_key.public_hex().to_string());
    m.provenance.build_hash = Some(sha256_hex(&wasm));
    m.provenance.signature = Some(node_key.sign(&m.signing_payload()));
    let beast_id = k.load(m, Artifact::Bytes(wasm)).expect("beast admits + loads");

    // A probe that observes proprioception (to see the Hard breach) and drives the beast.
    let (probe_id, probe, rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), probe_id);

    // ----- 1. Under the small cap, the bounded loop traps → Hard/Fuel signal, no reply ------------
    probe
        .send(
            Dispatch::to(Address::Creature(beast_id), b"survive-me".to_vec())
                .with_corr(1)
                .with_reply_to(Address::Creature(probe_id)),
        )
        .expect("send to beast");
    assert!(
        recv_budget_signal(&rx, beast_id.0, "hard", scaled(Duration::from_secs(3))),
        "the beast must trap on fuel under the small cap (Hard/Fuel on PROPRIOCEPTION)"
    );

    // ----- 2. The grant: ExtendBudget over the bus, to the kernel ---------------------------------
    let grant = KernelControl::ExtendBudget {
        module: beast_id.0,
        fuel: Some(100_000),
        mem_bytes: None,
        wall_ms: None,
    };
    probe
        .send(
            Dispatch::to(Address::Kernel, serde_json::to_vec(&grant).unwrap())
                .with_schema("kernel_control"),
        )
        .expect("send ExtendBudget to the kernel");

    // ----- 3. The SAME payload now completes — the lifted ceiling took effect ---------------------
    // Retry: the control op is async (it hops through the kernel's control listener); a couple of
    // sends bracket the moment the new ceiling lands. The beast is idempotent (pure echo after the
    // loop), so repeated sends are harmless.
    let mut survived = None;
    let deadline = Instant::now() + scaled(Duration::from_secs(4));
    let mut corr = 1u64;
    while survived.is_none() && Instant::now() < deadline {
        corr += 1;
        probe
            .send(
                Dispatch::to(Address::Creature(beast_id), b"survive-me".to_vec())
                    .with_corr(corr)
                    .with_reply_to(Address::Creature(probe_id)),
            )
            .expect("re-send to beast");
        survived = recv_corr(&rx, corr, Duration::from_millis(500));
    }
    assert_eq!(
        survived.as_deref(),
        Some(b"survive-me".as_slice()),
        "after the ExtendBudget grant the same handle completes and echoes — survival via grace"
    );

    k.shutdown_all(Deadline::from_millis(1000));
}
