//! The worked critter (Rhai) examples, proven end-to-end through the real kernel.
//!
//! Each `creatures/prototypes/critters/<name>/<name>.rhai` is the cheap, no-compiler on-ramp to authoring (the
//! sibling of the reference `echo-critter`). This suite is ALSO the compile+run proof of every Rhai
//! builtin the examples use — `to_upper`, `.contains`, `.split`, object maps, the `in` operator, blob
//! ops, `emit`, and bounded JSON conversion — plus the `env.text` marshalling. If the engine surface
//! ever drifts, one of these trips here rather than silently in a user's first critter.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, CreatureId, Deadline, Dispatch, StubSigner, StubVerifier, Topic};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine, CRITTER_ABI_TAG};
use gawdfn::{
    canonical_hash, AbodeKeyBindingV1, AttemptId, AuthoritySigner, DeliveryModeV1, DeploymentId,
    DeploymentReceiptV1, Ed25519SeedSigner, ExecutionGrantV1, ExecutorDispatchV1,
    FunctionCallMessageV1, FunctionCallV1, FunctionId, HomeAuthorityV1, HomeId, JobId,
    OperationalCapabilityV1, OperationalKeyGrantV1, SignedRecordV1, Validate, ValueRefV1,
    SCHEMA_CALL_V1, SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1,
};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

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

fn signed_add_one_call(
    executor_route: CreatureId,
    target: CreatureId,
) -> (AttemptId, FunctionCallMessageV1) {
    let root = Ed25519SeedSigner::from_seed([81; 32]).expect("root seed");
    let operational = Ed25519SeedSigner::from_seed([82; 32]).expect("operational seed");
    let executor = Ed25519SeedSigner::from_seed([83; 32]).expect("executor seed");
    let home = HomeId::new(root.public_key());
    let authority = HomeAuthorityV1 {
        abode: SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            AbodeKeyBindingV1 {
                abode: home.clone(),
                root_public_key: root.public_key().into(),
                issued_at_unix_ms: None,
            },
            &root,
        )
        .expect("Abode root binding"),
        operational: SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            OperationalKeyGrantV1 {
                home: home.clone(),
                epoch: 1,
                operational_public_key: operational.public_key().into(),
                valid_from_unix_ms: None,
                expires_at_unix_ms: None,
                capabilities: vec![OperationalCapabilityV1::JobHome],
                evidence: vec![],
            },
            &root,
        )
        .expect("operational Home grant"),
        prepared: None,
    };
    let function = FunctionId {
        manifest_content_address: format!("sha256:{}", "a".repeat(64)),
        entrypoint: "add_one".into(),
    };
    let attempt = AttemptId { home: home.clone(), job: JobId::new("job-from-executor"), number: 7 };
    let deployment = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentReceiptV1 {
            deployment: DeploymentId::new("typed-add-one-critter-test"),
            function: function.clone(),
            artifact_hash: format!("sha256:{}", "b".repeat(64)),
            realm: "test-realm".into(),
            node: "test-node".into(),
            executor: executor.public_key().into(),
            executor_creature: executor_route.0.to_string(),
            creature: target.0.to_string(),
            evidence: vec![],
            registered_at_unix_ms: None,
        },
        &executor,
    )
    .expect("executor-signed deployment");
    let input = ValueRefV1::Inline { value: serde_json::json!({ "value": 41 }) };
    let grant = SignedRecordV1::sign(
        SCHEMA_EXECUTE_V1,
        ExecutionGrantV1 {
            attempt: attempt.clone(),
            request_hash: format!("sha256:{}", "c".repeat(64)),
            home_epoch: 1,
            home_route_sequence: 1,
            home_realm: "test-realm".into(),
            home_node: "home-node".into(),
            home_coordinator: "1".into(),
            owner: home,
            authority,
            function: function.clone(),
            deployment,
            input: input.clone(),
            delivery: DeliveryModeV1::AtMostOnce,
            grant_sequence: 1,
            issued_at_unix_ms: None,
            deadline_unix_ms: None,
        },
        &operational,
    )
    .expect("Home-signed execution grant");
    let executor_dispatch = SignedRecordV1::sign(
        SCHEMA_CALL_V1,
        ExecutorDispatchV1 {
            attempt: attempt.clone(),
            grant_hash: canonical_hash(&grant).expect("grant hash"),
            deployment: grant.payload.deployment.payload.deployment.clone(),
            executor_creature: executor_route.0.to_string(),
            target_creature: target.0.to_string(),
        },
        &executor,
    )
    .expect("current executor route proof");
    (
        attempt.clone(),
        FunctionCallMessageV1::Call {
            call: Box::new(FunctionCallV1 {
                attempt,
                function,
                input,
                grant: Box::new(grant),
                executor_dispatch,
            }),
        },
    )
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

#[test]
fn typed_add_one_critter_returns_a_valid_result_for_the_dynamic_attempt() {
    let k = kernel();
    let id = load(
        &k,
        "typed-add-one",
        include_bytes!("../../creatures/prototypes/critters/typed-add-one/typed-add-one.rhai"),
    );
    let (executor_route, bus, rx) = k.open_endpoint(Capabilities::default());
    let (attempt, message) = signed_add_one_call(executor_route, id);
    bus.send(
        Dispatch::to(Address::Creature(id), aether::wire::to_bytes(&message))
            .with_reply_to(Address::Creature(executor_route))
            .with_schema(SCHEMA_CALL_V1),
    )
    .expect("executor sends proof-bearing call");
    let reply =
        rx.recv_timeout(Duration::from_secs(2)).expect("valid proof-bearing call replies").payload;
    let result = serde_json::from_slice::<FunctionCallMessageV1>(&reply).expect("typed JSON reply");
    result.validate().expect("reply satisfies the frozen Function call contract");
    match result {
        FunctionCallMessageV1::Result { result } => {
            assert_eq!(
                result.attempt, attempt,
                "AttemptId is copied, never invented by the script"
            );
            assert_eq!(
                result.outcome,
                Ok(ValueRefV1::Inline { value: serde_json::json!({ "answer": 42 }) })
            );
        }
        other => panic!("expected FunctionResultV1, got {other:?}"),
    }

    let (forged_sender, forged_bus, forged_rx) = k.open_endpoint(Capabilities::default());
    forged_bus
        .send(
            Dispatch::to(Address::Creature(id), aether::wire::to_bytes(&message))
                .with_reply_to(Address::Creature(forged_sender))
                .with_schema(SCHEMA_CALL_V1),
        )
        .expect("deliver wrong-sender specimen");
    assert!(
        forged_rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "a valid captured call arriving from another creature is not exposed to the script"
    );

    let mut tampered = message;
    let FunctionCallMessageV1::Call { call } = &mut tampered else {
        unreachable!("fixture is a call")
    };
    call.grant.payload.input = ValueRefV1::Inline { value: serde_json::json!({ "value": 99 }) };
    bus.send(
        Dispatch::to(Address::Creature(id), aether::wire::to_bytes(&tampered))
            .with_reply_to(Address::Creature(executor_route))
            .with_schema(SCHEMA_CALL_V1),
    )
    .expect("deliver tampered-grant specimen");
    assert!(
        rx.recv_timeout(Duration::from_millis(500)).is_err(),
        "a grant whose signed payload was altered is not exposed to the script"
    );
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
