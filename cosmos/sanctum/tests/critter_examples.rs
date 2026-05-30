//! The worked critter (Rhai) examples, proven end-to-end through the real kernel.
//!
//! Each `creatures/prototypes/critters/<name>/<name>.rhai` is the cheap, no-compiler on-ramp to authoring (the
//! sibling of the reference `echo-critter`). This suite is ALSO the compile+run proof of every Rhai
//! builtin the examples use — `to_upper`, `.contains`, `.split`, object maps, the `in` operator, blob
//! ops, and `emit` — plus the `env.text` marshalling. If the engine surface ever drifts, one of these
//! trips here rather than silently in a user's first critter.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, CreatureId, Deadline, Dispatch, StubSigner, StubVerifier, Topic};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

const CRITTER_ABI_TAG: &str = "gawd_critter_v1";

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("critter-examples-node")),
        Arc::new(StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn critter_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Critter, CRITTER_ABI_TAG)
}

/// A manifest with a real (finite, non-sentinel) CPU budget. `cpu_ms == 0` is the "unlimited"
/// opt-out; a positive value installs an actual operation ceiling (`cpu_ms * 10_000` ops).
fn critter_manifest_metered(name: &str, cpu_ms: u64) -> Manifest {
    let mut m = critter_manifest(name);
    m.capabilities.cpu_ms = cpu_ms;
    m
}

fn load(k: &Arc<Kernel>, name: &str, src: &[u8]) -> CreatureId {
    k.load(critter_manifest(name), Artifact::Bytes(src.to_vec()))
        .unwrap_or_else(|e| panic!("critter `{name}` must load through the real ScriptEngine: {e}"))
}

/// Send `payload` (with a `schema` tag the critter may read) and return the reply bytes.
fn ask(k: &Arc<Kernel>, target: CreatureId, payload: &[u8], schema: &str) -> Vec<u8> {
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(Address::Creature(target), payload.to_vec())
            .with_reply_to(Address::Creature(probe))
            .with_schema(schema),
    )
    .expect("send to critter");
    rx.recv_timeout(Duration::from_secs(2)).expect("critter reply arrives").payload
}

#[test]
fn uppercase_critter_uppercases_text() {
    let k = kernel();
    let id = load(
        &k,
        "uppercase",
        include_bytes!("../../creatures/prototypes/critters/uppercase/uppercase.rhai"),
    );
    assert_eq!(ask(&k, id, b"hello, world!", ""), b"HELLO, WORLD!");
    k.shutdown_all(Deadline::default());
}

#[test]
fn rot13_critter_is_its_own_inverse() {
    let k = kernel();
    let id =
        load(&k, "rot13", include_bytes!("../../creatures/prototypes/critters/rot13/rot13.rhai"));
    let once = ask(&k, id, b"Hello", "");
    assert_eq!(once, b"Uryyb");
    // The defining property: rot13 ∘ rot13 = identity. Re-feeding the ciphertext recovers the input.
    assert_eq!(ask(&k, id, &once, ""), b"Hello", "rot13 applied twice is identity");
    k.shutdown_all(Deadline::default());
}

#[test]
fn contains_critter_is_a_stateless_predicate() {
    let k = kernel();
    let id = load(
        &k,
        "contains",
        include_bytes!("../../creatures/prototypes/critters/contains/contains.rhai"),
    );
    assert_eq!(ask(&k, id, b"hello world", "world"), b"yes");
    assert_eq!(ask(&k, id, b"hello world", "xyz"), b"no");
    k.shutdown_all(Deadline::default());
}

#[test]
fn kv_extract_critter_selects_one_value_by_key() {
    let k = kernel();
    let id = load(
        &k,
        "kv-extract",
        include_bytes!("../../creatures/prototypes/critters/kv-extract/kv-extract.rhai"),
    );
    assert_eq!(ask(&k, id, b"a=1;b=2;c=3", "b"), b"2");
    assert_eq!(ask(&k, id, b"a=1;b=2;c=3", "missing"), b"", "absent key replies empty");
    k.shutdown_all(Deadline::default());
}

#[test]
fn route_by_prefix_critter_emits_to_the_prefixed_address() {
    let k = kernel();
    let id = load(
        &k,
        "route-by-prefix",
        include_bytes!("../../creatures/prototypes/critters/route-by-prefix/route-by-prefix.rhai"),
    );

    // A probe subscribed to FITNESS receives the payload the critter re-emits there (first byte 'l').
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::FITNESS), probe);
    bus.send(Dispatch::to(Address::Creature(id), b"log:hi".to_vec())).expect("send to critter");
    let got = rx.recv_timeout(Duration::from_secs(2)).expect("the emit lands on topic:fitness");
    assert_eq!(got.payload, b"log:hi");

    k.shutdown_all(Deadline::default());
}

/// Locks gotcha #2 from the critters README: `emit`'s payload MUST be a Blob. A critter that hands
/// `emit` a *string* hits no matching overload, so `handle` script-errors and produces **no reply**;
/// the identical critter handing `emit` a Blob succeeds and the `handle` return value comes back. The
/// reply-presence is the signal (we deliberately do NOT subscribe to FITNESS — a failed handle also
/// publishes a fitness event there, which would mask the test). If `emit` ever accepted strings, the
/// string case below would start replying and trip here, rather than silently in a user's first
/// critter. (`from_secs(2)` is the ample-success window; the failure case must out-wait it to be sure
/// the absence of a reply is the script error, not a slow one.)
#[test]
fn emit_requires_a_blob_payload_not_a_string() {
    let k = kernel();
    // Same shape, only the emit payload type differs: env.payload is a Blob, env.text is a String.
    let blob_ok = br#"fn handle(env) { emit("topic:fitness", env.payload); "ok" }"#;
    let str_bad = br#"fn handle(env) { emit("topic:fitness", env.text); "ok" }"#;
    let ok_id = load(&k, "emit-blob-ok", blob_ok);
    let bad_id = load(&k, "emit-string-bad", str_bad);

    // Positive control: a Blob payload is accepted, so the handle returns and we get "ok" back.
    assert_eq!(ask(&k, ok_id, b"x", ""), b"ok", "emit() must accept a Blob payload");

    // The string payload makes emit() (and thus handle) error ⇒ no reply ever arrives.
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(Address::Creature(bad_id), b"x".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .expect("send to critter");
    assert!(
        rx.recv_timeout(Duration::from_secs(2)).is_err(),
        "a string `emit` payload must script-error, producing no reply"
    );

    k.shutdown_all(Deadline::default());
}

/// The shipped examples advertise themselves as "metering-friendly". Prove `rot13` runs correctly
/// under a *real* finite operation budget (`cpu_ms = 10` ⇒ 100k ops), not just the `cpu_ms == 0`
/// unlimited opt-out the other cases use — the on-ramp's metered posture, demonstrated.
#[test]
fn rot13_runs_under_a_real_cpu_budget() {
    let k = kernel();
    let id = k
        .load(
            critter_manifest_metered("rot13-metered", 10),
            Artifact::Bytes(
                include_bytes!("../../creatures/prototypes/critters/rot13/rot13.rhai").to_vec(),
            ),
        )
        .expect("metered critter loads");
    assert_eq!(ask(&k, id, b"Hello", ""), b"Uryyb", "rot13 stays within a 100k-op budget");
    k.shutdown_all(Deadline::default());
}
