//! The model-backed authoring loop, end-to-end — hermetic (no network).
//!
//! `agent-mind` binds `Role::AUTHORING` exactly like `agent-templated`, but asks an injected
//! [`mind::Model`] for the source + manifest stub. These tests use the zero-dep [`mind::FakeModel`] /
//! [`mind::SlowModel`] so the full author → build → admit → load → run loop (and the off-drain-worker
//! shutdown contract) is provable offline, with the same kernel admission gates the real path uses.
//!
//! Coverage:
//! - **happy path** — `loop_reverse_authored_built_loaded_run_correct` (FakeModel always-good).
//! - **compile-error retry via the real `prev_error` prompt path** —
//!   `loop_compile_error_recovers_via_prev_error_then_builds` (FakeModel broken→fixed).
//! - **model error → structured Failed, node survives** — `backend_error_yields_failed_reply`.
//! - **off-drain emit delivers when the worker completes** — `offdrain_emit_delivers_reply`.
//! - **in-flight unload is bounded + drops the reply, no thread leak** —
//!   `inflight_unload_is_bounded_and_drops_reply` (SlowModel, the load-bearing shutdown test).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, Bus, BusHandle, CreatureId, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier,
    InboxReceiver, Role,
};
use agent_mind::{AgentMind, DOUBLE_SIGNED_CRITTER_REQUEST_V1};
use agent_templated::{AuthoringReply, AuthoringRequest, AuthoringResponse};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use build_cargo::{BuildCargo, BuildConfig, BuildErrorKind, BuildOp, BuildReply, Sandbox};
use build_critter::{BuildCritter, BuildCritterOp};
use gawdfn::{
    canonical_hash, sha256_digest, AbodeKeyBindingV1, AttemptId, AuthoritySigner, DeliveryModeV1,
    DeploymentId, DeploymentReceiptV1, Ed25519SeedSigner, EffectClassV1, ExecutionGrantV1,
    ExecutorDispatchV1, FunctionCallMessageV1, FunctionCallV1, FunctionId, HomeAuthorityV1, HomeId,
    JobId, OperationalCapabilityV1, OperationalKeyGrantV1, SchemaRefV1, SignedRecordV1, Validate,
    ValueRefV1, SCHEMA_CALL_V1, SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1,
};
use mind::{FakeModel, Model, SlowModel};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
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

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

/// Share one canonical authoring cache across Omni, demos, and every Cargo-backed authoring proof.
/// build-cargo materializes a process-unique work dir + per-build cargo crate name, so sharing is
/// collision-safe; the repository's serial defaults avoid lock contention.
fn shared_build_cache() -> PathBuf {
    workspace_root().join("target").join("gawd-build-cache")
}

struct World {
    kernel: Arc<Kernel>,
    agent_id: aether::CreatureId,
    /// build-critter, addressed by id (the no-cargo script-tier builder).
    critter_build_id: aether::CreatureId,
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
}

fn build_world(model: Arc<dyn Model>) -> World {
    let abode = Ed25519KeyMaterial::from_seed([23u8; 32]).expect("ed25519 from seed");
    let author_label = abode.public_hex().to_string();

    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(abode.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![author_label.clone()])),
        128,
    );

    // agent-mind on Role::AUTHORING — the model-backed author under test.
    let agent_id = kernel
        .load_instance(signed_boot_manifest("agent-mind", &abode), Box::new(AgentMind::new(model)))
        .expect("agent-mind admits");
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);

    // build-cargo on Role::BUILD — compiles + signs the authored daemon source.
    let mut build_cfg = BuildConfig::with_workspace_root(
        workspace_root().join("cosmos"),
        abode.clone(),
        author_label.clone(),
    );
    build_cfg.target_dir = shared_build_cache();
    build_cfg.sandbox = Sandbox::None;
    build_cfg.cargo_timeout = scaled(Duration::from_secs(300));
    let build_id = kernel
        .load_instance(
            signed_boot_manifest("build-cargo", &abode),
            Box::new(BuildCargo::new(build_cfg)),
        )
        .expect("build-cargo admits");
    kernel.bind_role(Role::new(Role::BUILD), build_id);

    // build-critter — the no-cargo script-tier builder, addressed by id (the sandboxed safe-tier path).
    let critter_build_id = kernel
        .load_instance(
            signed_boot_manifest("build-critter", &abode),
            Box::new(BuildCritter::new(abode.clone(), author_label)),
        )
        .expect("build-critter admits");

    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    World { kernel, agent_id, critter_build_id, probe_bus, probe_rx }
}

fn signed_boot_manifest(name: &str, abode: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(abode.public_hex().to_string());
    m.provenance.signature = Some(abode.sign(&m.signing_payload()));
    m
}

/// Send an `AuthoringRequest` to `Role::AUTHORING` and wait for the (off-drain) reply.
fn author(world: &World, req: AuthoringRequest, corr: u64) -> AuthoringReply {
    let payload = serde_json::to_vec(&req).expect("serialize AuthoringRequest");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("send to authoring");
    let env = recv_with_corr(&world.probe_rx, corr, scaled(Duration::from_secs(5)))
        .expect("authoring reply");
    serde_json::from_slice(&env.payload).expect("deserialize AuthoringReply")
}

fn author_ok(world: &World, req: AuthoringRequest, corr: u64) -> AuthoringResponse {
    match author(world, req, corr) {
        AuthoringReply::Authored(r) => r,
        AuthoringReply::Failed(e) => panic!("authoring failed: {e:?}"),
    }
}

fn build(world: &World, resp: &AuthoringResponse, corr: u64) -> BuildReply {
    let op = BuildOp::Build {
        crate_name: resp.crate_name.clone(),
        crate_version: resp.crate_version.clone(),
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
        deps: resp.deps.clone(),
    };
    let payload = serde_json::to_vec(&op).expect("serialize BuildOp");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::BUILD)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("send to build");
    let env = recv_with_corr(&world.probe_rx, corr, scaled(Duration::from_secs(360)))
        .expect("build reply");
    serde_json::from_slice(&env.payload).expect("deserialize BuildReply")
}

fn recv_with_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<aether::Envelope> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn count_threads() -> usize {
    std::fs::read_dir("/proc/self/task").map(|d| d.count()).unwrap_or(0)
}

// =================================================================================================
// (1) happy path: model authors a reverse daemon, built, loaded, correct output.
// =================================================================================================

#[test]
fn loop_reverse_authored_built_loaded_run_correct() {
    let world = build_world(Arc::new(FakeModel::always_good()));

    let resp = author_ok(
        &world,
        AuthoringRequest {
            request: "write a daemon that reverses a string".into(),
            ..Default::default()
        },
        1,
    );
    assert_eq!(resp.crate_name, "reverse-daemon");
    assert_eq!(resp.template, "agent-mind", "the model-backed author labels its output");

    let (manifest, artifact) = match build(&world, &resp, 2) {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => {
            panic!("expected Built, got Failed({kind:?}): {message}\n--- stderr ---\n{stderr}")
        }
    };
    assert!(manifest.provenance.signature.is_some(), "build creature signs");

    let id =
        world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("authored creature loads");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(3),
        )
        .expect("send to authored creature");
    let echo = recv_with_corr(&world.probe_rx, 3, scaled(Duration::from_secs(5)))
        .expect("authored replies");
    assert_eq!(echo.payload, b"cba", "model-authored reverse-daemon reverses bytes");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (1b) the sandboxed critter (script) tier: a critter request routes the model to Rhai output, which
//      build-critter validates + signs (no cargo) and the ScriptEngine loads + runs. This is the
//      "safe tier" opt-in — proving it actually works with the model author, not just agent-templated.
// =================================================================================================

#[test]
fn loop_critter_authored_built_loaded_run_correct() {
    let world = build_world(Arc::new(FakeModel::always_good()));

    let resp = author_ok(
        &world,
        AuthoringRequest { request: "reverse the bytes as a critter".into(), ..Default::default() },
        1,
    );
    assert_eq!(resp.template, "agent-mind-critter", "a critter request authors the script tier");
    assert!(resp.source.contains("fn handle(env)"), "model authored Rhai, not Rust");

    let op = BuildCritterOp::Author {
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
    };
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(world.critter_build_id), op.to_bytes())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(2),
        )
        .expect("send to build-critter");
    let env = recv_with_corr(&world.probe_rx, 2, scaled(Duration::from_secs(10)))
        .expect("build-critter reply");
    let (manifest, artifact) = match serde_json::from_slice::<BuildReply>(&env.payload).unwrap() {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, .. } => {
            panic!("critter build failed ({kind:?}): {message}")
        }
    };

    let id = world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("critter loads");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(3),
        )
        .expect("send to authored critter");
    let echo = recv_with_corr(&world.probe_rx, 3, scaled(Duration::from_secs(5)))
        .expect("authored critter replies");
    assert_eq!(echo.payload, b"cba", "model-authored reverse-critter reverses bytes");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (1c) typed Function critter: prose → exact contract → signed Rhai → proof-bearing calls. The
//      wrong-sender probe demonstrates that the authored source actually invokes route verification;
//      the two valid calls prove signed FunctionResultV1 output and exact AttemptId continuation.
// =================================================================================================

#[test]
fn loop_typed_function_critter_authored_signed_and_doubles_exactly() {
    let world = build_world(Arc::new(FakeModel::always_good()));

    let response = author_ok(
        &world,
        AuthoringRequest { request: DOUBLE_SIGNED_CRITTER_REQUEST_V1.into(), ..Default::default() },
        10,
    );
    assert_eq!(response.template, "agent-mind-function-critter");
    assert_eq!(response.crate_name, "double-int-critter");

    let op = BuildCritterOp::Author {
        source: response.source.clone(),
        manifest_stub: response.manifest_stub.clone(),
    };
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(world.critter_build_id), op.to_bytes())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(11),
        )
        .expect("send typed source to build-critter");
    let env = recv_with_corr(&world.probe_rx, 11, scaled(Duration::from_secs(10)))
        .expect("typed build-critter reply");
    let (manifest, artifact) = match serde_json::from_slice::<BuildReply>(&env.payload).unwrap() {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, .. } => {
            panic!("typed critter build failed ({kind:?}): {message}")
        }
    };
    assert_eq!(manifest.abi.backend, Backend::Critter);
    assert!(manifest.provenance.signature.is_some(), "build-critter signs the typed artifact");
    let entrypoint = manifest.entrypoints.first().expect("one typed entrypoint");
    assert_eq!(manifest.entrypoints.len(), 1);
    assert_eq!(entrypoint.name, "double_signed");
    assert_eq!(entrypoint.signature, SCHEMA_CALL_V1);
    let contract = entrypoint.contract.as_ref().expect("machine-readable Function contract");
    assert_eq!(contract.effect, EffectClassV1::Idempotent);
    assert_eq!(contract.controls, Default::default(), "all Function controls remain false");
    assert_eq!(
        contract.input_schema,
        SchemaRefV1::Inline {
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "value": { "type": "integer", "minimum": -1_000_000, "maximum": 1_000_000 }
                },
                "required": ["value"],
                "additionalProperties": false
            })
        }
    );
    assert_eq!(
        contract.output_schema,
        SchemaRefV1::Inline {
            schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "doubled": { "type": "integer", "minimum": -2_000_000, "maximum": 2_000_000 }
                },
                "required": ["doubled"],
                "additionalProperties": false
            })
        }
    );

    let manifest_content_address =
        manifest.content_address.clone().expect("build-critter assigns the Function identity");
    let artifact_hash = sha256_digest(&artifact);
    let target = world
        .kernel
        .load(manifest, Artifact::Bytes(artifact))
        .expect("signed typed critter loads through ScriptEngine");
    let function = FunctionId { manifest_content_address, entrypoint: "double_signed".into() };

    // Pin a valid call to the real executor endpoint, then send it from a different endpoint. The
    // authored script must produce no result because function_call_verify binds the envelope route.
    let (_wrong_id, wrong_bus, wrong_rx) = world.kernel.open_endpoint(Capabilities::default());
    let (route_attempt, route_call) =
        signed_double_call(function.clone(), 21, 1, world.probe_bus.id(), target, &artifact_hash);
    wrong_bus
        .emit(
            Dispatch::to(
                Address::Creature(target),
                serde_json::to_vec(&route_call).expect("serialize typed call"),
            )
            .with_schema(SCHEMA_CALL_V1)
            .with_reply_to(Address::Creature(wrong_bus.id()))
            .with_corr(12),
        )
        .expect("send deliberately misrouted typed call");
    assert!(
        recv_with_corr(&wrong_rx, 12, scaled(Duration::from_millis(250))).is_none(),
        "a valid proof on the wrong local executor route must not reach Function code"
    );

    // Reuse the exact signed call from its pinned executor route: the result must now be accepted,
    // proving the negative above was route verification rather than a malformed proof.
    emit_function_call(&world.probe_bus, target, 13, &route_call);
    assert_double_result(
        recv_with_corr(&world.probe_rx, 13, scaled(Duration::from_secs(5)))
            .expect("21 call result"),
        &route_attempt,
        42,
    );

    let (_extra_attempt, extra_property_call) = signed_double_call_with_input(
        function.clone(),
        serde_json::json!({"value": 21, "extra": true}),
        3,
        world.probe_bus.id(),
        target,
        &artifact_hash,
    );
    emit_function_call(&world.probe_bus, target, 15, &extra_property_call);
    assert!(
        recv_with_corr(&world.probe_rx, 15, scaled(Duration::from_millis(250))).is_none(),
        "additionalProperties:false must be enforced by the canonical Function adapter"
    );

    let (_float_attempt, float_call) = signed_double_call_with_input(
        function.clone(),
        serde_json::json!({"value": 21.5}),
        4,
        world.probe_bus.id(),
        target,
        &artifact_hash,
    );
    emit_function_call(&world.probe_bus, target, 16, &float_call);
    assert!(
        recv_with_corr(&world.probe_rx, 16, scaled(Duration::from_millis(250))).is_none(),
        "the declared integer schema must reject a signed float input"
    );

    let (negative_attempt, negative_call) =
        signed_double_call(function, -21, 2, world.probe_bus.id(), target, &artifact_hash);
    emit_function_call(&world.probe_bus, target, 14, &negative_call);
    assert_double_result(
        recv_with_corr(&world.probe_rx, 14, scaled(Duration::from_secs(5)))
            .expect("-21 call result"),
        &negative_attempt,
        -42,
    );

    world.kernel.shutdown_all(Deadline::default());
}

fn signed_double_call(
    function: FunctionId,
    value: i64,
    attempt_number: u8,
    executor_route: CreatureId,
    target: CreatureId,
    artifact_hash: &str,
) -> (AttemptId, FunctionCallMessageV1) {
    signed_double_call_with_input(
        function,
        serde_json::json!({ "value": value }),
        attempt_number,
        executor_route,
        target,
        artifact_hash,
    )
}

fn signed_double_call_with_input(
    function: FunctionId,
    input_value: serde_json::Value,
    attempt_number: u8,
    executor_route: CreatureId,
    target: CreatureId,
    artifact_hash: &str,
) -> (AttemptId, FunctionCallMessageV1) {
    let root = Ed25519SeedSigner::from_seed([81; 32]).expect("root signer");
    let operational = Ed25519SeedSigner::from_seed([82; 32]).expect("operational signer");
    let executor = Ed25519SeedSigner::from_seed([83; 32]).expect("executor signer");
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
        .expect("root self-binding"),
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
        .expect("root grants the Home operational key"),
        prepared: None,
    };
    let attempt = AttemptId {
        home: home.clone(),
        job: JobId::new(format!("agent-mind-double-{attempt_number}")),
        number: attempt_number,
    };
    let deployment = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentReceiptV1 {
            deployment: DeploymentId::new(format!("agent-mind-double-{attempt_number}")),
            function: function.clone(),
            artifact_hash: artifact_hash.to_string(),
            realm: "local-test".into(),
            node: "agent-mind-test".into(),
            executor: executor.public_key().into(),
            executor_creature: executor_route.0.to_string(),
            creature: target.0.to_string(),
            evidence: vec![],
            registered_at_unix_ms: None,
        },
        &executor,
    )
    .expect("executor deployment receipt");
    let input = ValueRefV1::Inline { value: input_value };
    let grant = SignedRecordV1::sign(
        SCHEMA_EXECUTE_V1,
        ExecutionGrantV1 {
            attempt: attempt.clone(),
            request_hash: sha256_digest(format!("double-request-{attempt_number}").as_bytes()),
            home_epoch: 1,
            home_route_sequence: 1,
            home_realm: "local-test".into(),
            home_node: "agent-mind-test".into(),
            home_coordinator: executor_route.0.to_string(),
            owner: home,
            authority,
            function: function.clone(),
            deployment,
            input: input.clone(),
            delivery: DeliveryModeV1::AtLeastOnce { max_attempts: 3 },
            grant_sequence: 1,
            issued_at_unix_ms: None,
            deadline_unix_ms: None,
        },
        &operational,
    )
    .expect("Home execution grant");
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
    .expect("executor route dispatch");
    let call = FunctionCallV1 {
        attempt: attempt.clone(),
        function,
        input,
        grant: Box::new(grant),
        executor_dispatch,
    };
    call.validate().expect("constructed Function call proof verifies");
    (attempt, FunctionCallMessageV1::Call { call: Box::new(call) })
}

fn emit_function_call(
    bus: &BusHandle,
    target: CreatureId,
    corr: u64,
    call: &FunctionCallMessageV1,
) {
    bus.emit(
        Dispatch::to(
            Address::Creature(target),
            serde_json::to_vec(call).expect("serialize typed call"),
        )
        .with_schema(SCHEMA_CALL_V1)
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(corr),
    )
    .expect("send proof-bearing typed call");
}

fn assert_double_result(env: aether::Envelope, expected_attempt: &AttemptId, expected: i64) {
    assert_eq!(env.header.schema, SCHEMA_CALL_V1);
    let message: FunctionCallMessageV1 =
        serde_json::from_slice(&env.payload).expect("valid FunctionResultV1 JSON");
    let FunctionCallMessageV1::Result { result } = message else {
        panic!("expected FunctionResultV1, got {message:?}")
    };
    assert_eq!(&result.attempt, expected_attempt, "the exact AttemptId is propagated");
    assert_eq!(
        result.outcome,
        Ok(ValueRefV1::Inline { value: serde_json::json!({ "doubled": expected }) })
    );
}

// =================================================================================================
// (2) compile-error retry via the real prev_error prompt path: broken → fixed.
// =================================================================================================

#[test]
fn loop_compile_error_recovers_via_prev_error_then_builds() {
    let world = build_world(Arc::new(FakeModel::broken_then_fixed()));

    // First attempt (no prev_error) → the fake returns intentionally broken source → Compile failure.
    let broken = author_ok(
        &world,
        AuthoringRequest {
            request: "write a daemon that reverses a string".into(),
            ..Default::default()
        },
        1,
    );
    let stderr = match build(&world, &broken, 2) {
        BuildReply::Failed { kind: BuildErrorKind::Compile, stderr, .. } => stderr,
        BuildReply::Failed { kind, message, .. } => {
            panic!("expected Compile, got {kind:?}: {message}")
        }
        BuildReply::Built { .. } => panic!("broken source must not Build"),
    };
    assert!(!stderr.is_empty(), "compile failure carries stderr substance");

    // Second attempt WITH the real prev_error → the fake (keying on the retry marker the prompt
    // builder injects) returns the fixed source → Build succeeds.
    let fixed = author_ok(
        &world,
        AuthoringRequest {
            request: "write a daemon that reverses a string".into(),
            prev_error: Some(stderr),
        },
        3,
    );
    let (manifest, artifact) = match build(&world, &fixed, 4) {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => {
            panic!("recovery expected Built, got Failed({kind:?}): {message}\n{stderr}")
        }
    };
    let id = world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("recovered build loads");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"xyz".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(5),
        )
        .expect("send to recovered creature");
    let echo = recv_with_corr(&world.probe_rx, 5, scaled(Duration::from_secs(5)))
        .expect("recovered replies");
    assert_eq!(echo.payload, b"zyx");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (3) model error → structured Failed reply, node survives.
// =================================================================================================

#[test]
fn backend_error_yields_failed_reply() {
    let world = build_world(Arc::new(FakeModel::erroring()));

    match author(&world, AuthoringRequest { request: "reverse".into(), ..Default::default() }, 1) {
        AuthoringReply::Failed(_) => {}
        AuthoringReply::Authored(r) => panic!("expected Failed, got Authored({})", r.crate_name),
    }
    // The node survived: the agent is still bound and answers again (another Failed), no crash.
    match author(
        &world,
        AuthoringRequest { request: "reverse again".into(), ..Default::default() },
        2,
    ) {
        AuthoringReply::Failed(_) => {}
        other => panic!("expected a second Failed, got {other:?}"),
    }

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (4a) off-drain emit delivers the reply once the (slow) worker completes in time.
// =================================================================================================

#[test]
fn offdrain_emit_delivers_reply() {
    let slow = Arc::new(SlowModel::new());
    let world = build_world(slow.clone());

    let payload =
        serde_json::to_vec(&AuthoringRequest { request: "reverse".into(), ..Default::default() })
            .unwrap();
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(1),
        )
        .expect("send to authoring");

    // The worker is provably in-flight (blocked in the model) — handle has already returned.
    wait_until(|| slow.has_entered(), Duration::from_secs(2));
    assert!(slow.has_entered(), "worker entered the model call off-drain");

    // Release in time → the worker emits the reply through the captured bus.
    slow.release();
    let env = recv_with_corr(&world.probe_rx, 1, scaled(Duration::from_secs(5)))
        .expect("off-drain worker delivered the reply");
    match serde_json::from_slice::<AuthoringReply>(&env.payload).unwrap() {
        AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
        other => panic!("expected Authored, got {other:?}"),
    }

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (4b) in-flight unload is bounded, drops the reply cleanly, and leaks no thread (the load-bearing
//      shutdown test the instant-fake happy path does NOT cover).
// =================================================================================================

#[test]
fn inflight_unload_is_bounded_and_drops_reply() {
    let slow = Arc::new(SlowModel::new());
    let world = build_world(slow.clone());

    #[cfg(target_os = "linux")]
    let before = count_threads();

    let payload =
        serde_json::to_vec(&AuthoringRequest { request: "reverse".into(), ..Default::default() })
            .unwrap();
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(1),
        )
        .expect("send to authoring");
    wait_until(|| slow.has_entered(), Duration::from_secs(2));
    assert!(slow.has_entered() && !slow.has_finished(), "worker is provably still in-flight");

    // Unload with a short deadline while the worker is blocked: shutdown must return promptly
    // (deadline-bounded polling join), detaching the straggler rather than hanging.
    let t = Instant::now();
    let _ = world.kernel.unload(
        world.agent_id,
        Deadline::from_millis(scaled(Duration::from_millis(300)).as_millis() as u64),
    );
    let elapsed = t.elapsed();
    assert!(
        elapsed < scaled(Duration::from_secs(3)),
        "in-flight unload must be bounded, took {elapsed:?}"
    );

    // Release the straggler. Because shutdown set `stop`, the worker drops its reply on return —
    // and even an emit would be a clean NoSuchModule (agent-mind is in-process; no unmapped code).
    slow.release();
    wait_until(|| slow.has_finished(), Duration::from_secs(2));
    assert!(slow.has_finished(), "the detached worker finished cleanly after release");

    // No reply was delivered for corr=1 (the stopped worker dropped it).
    assert!(
        recv_with_corr(&world.probe_rx, 1, Duration::from_millis(300)).is_none(),
        "a stopped worker must not deliver its reply"
    );

    // The detached worker thread does not persist (it ran to completion and exited).
    #[cfg(target_os = "linux")]
    {
        std::thread::sleep(Duration::from_millis(200));
        let after = count_threads();
        assert!(after <= before, "worker thread must not leak (before={before}, after={after})");
    }

    world.kernel.shutdown_all(Deadline::default());
}

fn wait_until(mut cond: impl FnMut() -> bool, budget: Duration) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
