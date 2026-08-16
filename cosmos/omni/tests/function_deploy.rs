//! Function deployment is a three-party proof: caller authorization, privileged post-load
//! registration, and an executor-authored durable receipt. These tests exercise the real Kernel
//! load path and make rollback/ambiguity behavior explicit at the control boundary.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, Outcome, Role,
    StubSigner, StubVerifier,
};
use anima::{Artifact, Engine, EngineError, LoadedModule, ScriptEngine};
use gawdfn::{
    derive_deployment_id, sha256_digest, verify_deployment_receipt, verify_deployment_registration,
    AuthoritySigner, DeploymentId, DeploymentListV1, DeploymentReceiptV1, DeploymentRequestV1,
    Ed25519SeedSigner, EffectClassV1, EntrypointContractV1, FunctionDeployMessageV1, FunctionId,
    FunctionSelectorV1, HomeId, ProtocolErrorV1, ResolutionReceiptV1, SchemaRefV1, SignedRecordV1,
    UndeployReceiptV1, UndeployRequestV1, FUNCTION_EXECUTOR_ROLE, SCHEMA_FUNCTION_DEPLOY_V1,
};
use omni::{run_verb, AiControl, Verb, VerbCtx, VerbResult};
use sanctum::Kernel;
use serde_json::json;
use sigil::{Backend, Capabilities, Entrypoint, Manifest};

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let suffix = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("omni-function-deploy-{tag}-{}-{suffix}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Copy)]
enum ExecutorMode {
    Register,
    WrongExecutorCreature,
    ExplicitError,
    UnexpectedReply,
}

struct TestExecutor {
    signer: Arc<Ed25519SeedSigner>,
    mode: ExecutorMode,
    me: Option<CreatureId>,
}

impl TestExecutor {
    fn protocol_error(code: &str, message: &str) -> FunctionDeployMessageV1 {
        FunctionDeployMessageV1::Error {
            error: ProtocolErrorV1 { code: code.into(), message: message.into(), retryable: false },
        }
    }
}

impl Creature for TestExecutor {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA_FUNCTION_DEPLOY_V1 {
            return Outcome::none();
        }
        let Ok(FunctionDeployMessageV1::Register { request }) =
            serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
        else {
            return Outcome::none();
        };

        let response = match self.mode {
            ExecutorMode::ExplicitError => {
                Self::protocol_error("registration_refused", "injected admission refused")
            }
            ExecutorMode::UnexpectedReply => FunctionDeployMessageV1::Deployments {
                list: DeploymentListV1 { deployments: Vec::new() },
            },
            ExecutorMode::Register | ExecutorMode::WrongExecutorCreature => {
                if let Err(error) = verify_deployment_registration(&request) {
                    Self::protocol_error("invalid_registration", &error.to_string())
                } else {
                    let registration = &request.payload;
                    let authorization = &registration.authorization.payload;
                    let receipt = DeploymentReceiptV1 {
                        deployment: registration.deployment.clone(),
                        function: registration.function.clone(),
                        artifact_hash: registration.artifact_hash.clone(),
                        realm: authorization.target_realm.clone(),
                        node: authorization.target_node.clone().expect("test pins a node"),
                        executor: self.signer.public_key().into(),
                        executor_creature: if matches!(
                            self.mode,
                            ExecutorMode::WrongExecutorCreature
                        ) {
                            "999999".into()
                        } else {
                            self.me.expect("bound before handle").0.to_string()
                        },
                        creature: registration.target_creature.clone(),
                        evidence: Vec::new(),
                        registered_at_unix_ms: None,
                    };
                    FunctionDeployMessageV1::Registered {
                        receipt: SignedRecordV1::sign(
                            SCHEMA_FUNCTION_DEPLOY_V1,
                            receipt,
                            self.signer.as_ref(),
                        )
                        .unwrap(),
                    }
                }
            }
        };

        Outcome::send(
            Dispatch::reply_to_env(&env, serde_json::to_vec(&response).unwrap())
                .with_schema(SCHEMA_FUNCTION_DEPLOY_V1),
        )
    }
}

struct Exercise {
    kernel: Arc<Kernel>,
    executor: CreatureId,
    result: VerbResult,
}

fn exercise(
    mode: ExecutorMode,
    forge_same_corr_reply: bool,
    mismatched_manifest_build_hash: bool,
) -> Exercise {
    let files = TempDir::new("case");
    let manifest_path = files.0.join("typed-critter.manifest.json");
    let artifact_path = files.0.join("typed-critter.rhai");
    exercise_with_artifact(
        mode,
        forge_same_corr_reply,
        mismatched_manifest_build_hash,
        Arc::new(ScriptEngine),
        Backend::Critter,
        "gawd_critter_v1",
        b"fn handle(env) { env.payload }",
        &manifest_path,
        &artifact_path,
    )
}

#[allow(clippy::too_many_arguments)]
fn exercise_with_artifact(
    mode: ExecutorMode,
    forge_same_corr_reply: bool,
    mismatched_manifest_build_hash: bool,
    engine: Arc<dyn Engine>,
    backend: Backend,
    abi_tag: &str,
    artifact: &[u8],
    manifest_path: &std::path::Path,
    artifact_path: &std::path::Path,
) -> Exercise {
    let kernel = Kernel::new(
        vec![engine],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        64,
    );

    let executor_signer = Arc::new(Ed25519SeedSigner::from_seed([91; 32]).unwrap());
    let executor = kernel
        .load_instance(
            Manifest::new("function-executor-test", "1.0.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(TestExecutor { signer: executor_signer, mode, me: None }),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_EXECUTOR_ROLE), executor);

    let artifact_hash = sha256_digest(artifact);
    let mut manifest = Manifest::new("typed-target", "1.0.0", backend, abi_tag);
    manifest.entrypoints.push(Entrypoint {
        name: "run".into(),
        signature: "gawd.function.call.v1".into(),
        contract: Some(EntrypointContractV1 {
            description: "echo one typed value".into(),
            input_schema: SchemaRefV1::Inline { schema: json!({"type": "object"}) },
            output_schema: SchemaRefV1::Inline { schema: json!({"type": "object"}) },
            error_schema: None,
            effect: EffectClassV1::Idempotent,
            controls: Default::default(),
        }),
    });
    manifest.provenance.build_hash = artifact_hash.strip_prefix("sha256:").map(str::to_owned);
    if mismatched_manifest_build_hash {
        manifest.provenance.build_hash = Some("0".repeat(64));
    }
    manifest.content_address = Some(manifest.compute_content_address());

    std::fs::write(manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    std::fs::write(artifact_path, artifact).unwrap();

    let function = FunctionId {
        manifest_content_address: manifest.content_address.clone().unwrap(),
        entrypoint: "run".into(),
    };
    let selector = FunctionSelectorV1::Id { function: function.clone() };
    let home_signer = Ed25519SeedSigner::from_seed([92; 32]).unwrap();
    let home = HomeId::new(home_signer.public_key());
    let request = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRequestV1 {
            requested_by: home,
            function: selector.clone(),
            target_realm: "realm-a".into(),
            target_node: Some("node-a".into()),
            evidence: Vec::new(),
            requested_at_unix_ms: None,
        },
        &home_signer,
    )
    .unwrap();
    let resolver_signer = Ed25519SeedSigner::from_seed([93; 32]).unwrap();
    let resolution = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        ResolutionReceiptV1 {
            selector,
            function,
            artifact_hash,
            resolved_at_unix_ms: None,
            evidence: Vec::new(),
        },
        &resolver_signer,
    )
    .unwrap();
    let deployer = Ed25519SeedSigner::from_seed([94; 32]).unwrap();

    let (probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    if forge_same_corr_reply {
        let (_attacker_id, attacker_bus, _attacker_rx) =
            kernel.open_endpoint(Capabilities::default());
        let forged = SelfContainedError::message();
        attacker_bus
            .send(
                Dispatch::to(Address::Creature(probe_id), serde_json::to_vec(&forged).unwrap())
                    .with_schema(SCHEMA_FUNCTION_DEPLOY_V1)
                    .with_corr(1),
            )
            .unwrap();
    }

    let ai = AiControl::new(true);
    let result = {
        let mut ctx = VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, None, &ai, false);
        ctx.set_function_deployer(&deployer);
        run_verb(
            Verb::FunctionDeploy {
                request,
                resolution,
                manifest_path: manifest_path.to_string_lossy().into_owned(),
                artifact_path: artifact_path.to_string_lossy().into_owned(),
            },
            &mut ctx,
            &mut |_| {},
        )
    };
    if forge_same_corr_reply {
        // Let the authenticated executor finish its already-routed request before the temporary
        // probe is dropped. Its reply is intentionally too late to replace the rejected forgery.
        let _ = probe_rx.recv_timeout(std::time::Duration::from_millis(250));
    }

    Exercise { kernel, executor, result }
}

struct SelfContainedError;

impl SelfContainedError {
    fn message() -> FunctionDeployMessageV1 {
        FunctionDeployMessageV1::Error {
            error: ProtocolErrorV1 {
                code: "forged_refusal".into(),
                message: "not the role provider".into(),
                retryable: false,
            },
        }
    }
}

#[test]
fn deploy_loads_then_accepts_an_executor_signed_exact_receipt() {
    let Exercise { kernel, executor, result } = exercise(ExecutorMode::Register, false, false);
    assert!(result.ok, "deployment succeeds: {:?}", result.json);
    assert_eq!(kernel.loaded_count(), 2, "executor plus deployed target remain loaded");

    let receipt: SignedRecordV1<DeploymentReceiptV1> =
        serde_json::from_value(result.json["deployment"].clone()).unwrap();
    verify_deployment_receipt(&receipt).unwrap();
    assert_eq!(receipt.payload.executor_creature, executor.0.to_string());
    assert!(kernel
        .is_loaded(CreatureId(result.json["creature_id"].as_u64().expect("loaded creature id"))));

    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn explicit_executor_error_rolls_back_the_loaded_target() {
    let Exercise { kernel, result, .. } = exercise(ExecutorMode::ExplicitError, false, false);
    assert!(!result.ok, "executor refusal is surfaced: {:?}", result.json);
    assert_eq!(result.json["stage"], "register");
    assert_eq!(result.json["rolled_back"], true);
    assert_eq!(kernel.loaded_count(), 1, "only the executor remains after rollback");

    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn unexpected_executor_reply_is_indeterminate_and_retains_target() {
    let Exercise { kernel, result, .. } = exercise(ExecutorMode::UnexpectedReply, false, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "deployment-registration-indeterminate");
    assert_eq!(result.json["loaded_instance_retained"], true);
    assert_eq!(kernel.loaded_count(), 2, "ambiguous registration never unloads the target");

    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn receipt_cannot_claim_a_different_executor_creature() {
    let Exercise { kernel, result, .. } =
        exercise(ExecutorMode::WrongExecutorCreature, false, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "deployment-registration-indeterminate");
    assert_eq!(result.json["loaded_instance_retained"], true);
    assert_eq!(kernel.loaded_count(), 2, "mismatched receipt leaves registration ambiguous");

    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn forged_same_correlation_refusal_cannot_trigger_rollback() {
    let Exercise { kernel, executor, result } = exercise(ExecutorMode::Register, true, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "deployment-registration-indeterminate");
    assert_eq!(result.json["loaded_instance_retained"], true);
    let detail = result.json["detail"].as_str().unwrap_or_default();
    assert!(detail.contains("rejected reply from"), "origin failure: {detail}");
    assert!(detail.contains(&executor.0.to_string()), "expected provider is named: {detail}");
    assert_eq!(kernel.loaded_count(), 2, "untrusted refusal cannot cause target unload");

    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn manifest_build_hash_must_bind_the_supplied_artifact_before_load() {
    let Exercise { kernel, result, .. } = exercise(ExecutorMode::Register, false, true);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "invalid-function-contract");
    assert_eq!(result.json["field"], "manifest");
    assert!(result.json["detail"].as_str().unwrap_or_default().contains("provenance.build_hash"));
    assert_eq!(kernel.loaded_count(), 1, "the target is rejected before Kernel load");

    kernel.shutdown_all(Deadline::from_millis(500));
}

struct SwapSourceEngine {
    source: std::path::PathBuf,
    replacement: std::path::PathBuf,
    observed: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Engine for SwapSourceEngine {
    fn backend(&self) -> Backend {
        Backend::Daemon
    }

    fn load(&self, artifact: &Artifact, _manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        #[cfg(target_os = "windows")]
        std::fs::remove_file(&self.source)
            .map_err(|error| EngineError::Load(format!("remove source before swap: {error}")))?;
        std::fs::rename(&self.replacement, &self.source)
            .map_err(|error| EngineError::Load(format!("swap source after admission: {error}")))?;
        *self.observed.lock().unwrap_or_else(|poison| poison.into_inner()) =
            Some(artifact.read_bytes()?);
        Ok(LoadedModule::new(Box::new(LoadedNoop), Box::new(())))
    }
}

struct LoadedNoop;

impl Creature for LoadedNoop {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

#[test]
fn permissive_policy_source_swap_keeps_function_receipt_on_prepared_bytes() {
    let files = TempDir::new("source-swap");
    let manifest_path = files.0.join("native.manifest.json");
    let source = files.0.join("native.so");
    let replacement = files.0.join("replacement.so");
    let v1 = b"native-function-v1";
    let v2 = b"native-function-v2";
    std::fs::write(&replacement, v2).unwrap();
    let observed = Arc::new(Mutex::new(None));
    let engine =
        SwapSourceEngine { source: source.clone(), replacement, observed: observed.clone() };

    let Exercise { kernel, result, .. } = exercise_with_artifact(
        ExecutorMode::Register,
        false,
        false,
        Arc::new(engine),
        Backend::Daemon,
        "gawd_creature_v1",
        v1,
        &manifest_path,
        &source,
    );

    assert!(result.ok, "deployment succeeds from the exact prepared v1: {:?}", result.json);
    assert_eq!(std::fs::read(&source).unwrap(), v2, "engine hook replaced the source path");
    assert_eq!(
        observed.lock().unwrap_or_else(|poison| poison.into_inner()).as_deref(),
        Some(v1.as_slice()),
        "the engine consumes the prepared v1 capability, not replaced source v2"
    );
    let target = CreatureId(result.json["creature_id"].as_u64().unwrap());
    let identity = kernel.loaded_manifest_identity(target).unwrap();
    let v1_hash = sha256_digest(v1);
    assert_eq!(
        identity.artifact_sha256.as_deref(),
        v1_hash.strip_prefix("sha256:"),
        "Kernel identity and the deployment receipt remain pinned to v1"
    );
    assert_eq!(result.json["deployment"]["payload"]["artifact_hash"], v1_hash);

    kernel.shutdown_all(Deadline::from_millis(500));
}

#[derive(Clone, Copy)]
enum UndeployMode {
    Acknowledge,
    Refuse,
    WrongDeployment,
    WrongSigner,
    UnexpectedReply,
}

struct UndeployExecutor {
    mode: UndeployMode,
    retirement_stage: Arc<AtomicU64>,
    signer: Arc<Ed25519SeedSigner>,
    me: Option<CreatureId>,
}

impl Creature for UndeployExecutor {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA_FUNCTION_DEPLOY_V1 {
            return Outcome::none();
        }
        let Ok(FunctionDeployMessageV1::Undeploy { request }) =
            serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
        else {
            return Outcome::none();
        };
        let sign_acknowledgement =
            |deployment: DeploymentId, signer: &dyn AuthoritySigner| -> FunctionDeployMessageV1 {
                let receipt = SignedRecordV1::sign(
                    SCHEMA_FUNCTION_DEPLOY_V1,
                    UndeployReceiptV1 {
                        deployment,
                        executor: signer.public_key().into(),
                        executor_creature: self.me.expect("executor is bound").0.to_string(),
                    },
                    signer,
                )
                .unwrap();
                FunctionDeployMessageV1::Undeployed { receipt }
            };
        let reply = match self.mode {
            UndeployMode::Acknowledge => {
                // Models the real executor's append+fsync boundary: the stage changes before its
                // acknowledgement is put on the bus. The target asserts shutdown sees this fact.
                self.retirement_stage.store(1, Ordering::SeqCst);
                sign_acknowledgement(request.payload.deployment, self.signer.as_ref())
            }
            UndeployMode::Refuse => FunctionDeployMessageV1::Error {
                error: ProtocolErrorV1 {
                    code: "deployment_busy".into(),
                    message: "a nonterminal attempt still holds the deployment".into(),
                    retryable: true,
                },
            },
            UndeployMode::WrongDeployment => {
                self.retirement_stage.store(1, Ordering::SeqCst);
                sign_acknowledgement(
                    DeploymentId::new(format!("sha256:{}", "f".repeat(64))),
                    self.signer.as_ref(),
                )
            }
            UndeployMode::WrongSigner => {
                self.retirement_stage.store(1, Ordering::SeqCst);
                let other = Ed25519SeedSigner::from_seed([103; 32]).unwrap();
                sign_acknowledgement(request.payload.deployment, &other)
            }
            UndeployMode::UnexpectedReply => {
                self.retirement_stage.store(1, Ordering::SeqCst);
                FunctionDeployMessageV1::Deployments {
                    list: DeploymentListV1 { deployments: Vec::new() },
                }
            }
        };
        Outcome::send(
            Dispatch::reply_to_env(&env, serde_json::to_vec(&reply).unwrap())
                .with_schema(SCHEMA_FUNCTION_DEPLOY_V1),
        )
    }
}

struct RetirementTarget {
    retirement_stage: Arc<AtomicU64>,
    slow_shutdown: bool,
}

struct RetirementEngine {
    retirement_stage: Arc<AtomicU64>,
    slow_shutdown: bool,
}

impl Engine for RetirementEngine {
    fn backend(&self) -> Backend {
        Backend::Daemon
    }

    fn load(
        &self,
        _artifact: &Artifact,
        _manifest: &Manifest,
    ) -> Result<LoadedModule, EngineError> {
        Ok(LoadedModule::new(
            Box::new(RetirementTarget {
                retirement_stage: self.retirement_stage.clone(),
                slow_shutdown: self.slow_shutdown,
            }),
            Box::new(()),
        ))
    }
}

impl Creature for RetirementTarget {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        if self.retirement_stage.compare_exchange(1, 2, Ordering::SeqCst, Ordering::SeqCst).is_err()
        {
            self.retirement_stage.store(99, Ordering::SeqCst);
        }
        if self.slow_shutdown {
            std::thread::sleep(std::time::Duration::from_millis(1_250));
        }
    }
}

struct UndeployExercise {
    kernel: Arc<Kernel>,
    target: CreatureId,
    executor: CreatureId,
    stage: Arc<AtomicU64>,
    result: VerbResult,
}

fn exercise_undeploy(
    mode: UndeployMode,
    stale_target_identity: bool,
    receipt_executor_override: Option<u64>,
    forge_same_corr_reply: bool,
    slow_shutdown: bool,
) -> UndeployExercise {
    let stage = Arc::new(AtomicU64::new(0));
    let kernel = Kernel::new(
        vec![Arc::new(RetirementEngine { retirement_stage: stage.clone(), slow_shutdown })],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        64,
    );
    let executor_signer = Arc::new(Ed25519SeedSigner::from_seed([101; 32]).unwrap());
    let executor = kernel
        .load_instance(
            Manifest::new("function-executor-test", "1.0.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(UndeployExecutor {
                mode,
                retirement_stage: stage.clone(),
                signer: executor_signer.clone(),
                me: None,
            }),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_EXECUTOR_ROLE), executor);

    let artifact = b"retirement-target-test-artifact".to_vec();
    let artifact_hash = sha256_digest(&artifact);
    let artifact_raw_hash = artifact_hash.strip_prefix("sha256:").unwrap().to_string();
    let mut live_manifest =
        Manifest::new("retirement-target", "1.0.0", Backend::Daemon, "gawd_creature_v1");
    live_manifest.provenance.build_hash = Some(artifact_raw_hash.clone());
    live_manifest.content_address = Some(live_manifest.compute_content_address());
    let live_content_address = live_manifest.content_address.clone().unwrap();
    let target = kernel.load(live_manifest, Artifact::Bytes(artifact)).unwrap();

    let receipt_function = FunctionId {
        manifest_content_address: if stale_target_identity {
            format!("sha256:{}", "b".repeat(64))
        } else {
            live_content_address
        },
        entrypoint: "run".into(),
    };
    let deployment_id = derive_deployment_id(
        &receipt_function,
        &artifact_hash,
        "realm-a",
        "node-a",
        &target.0.to_string(),
    )
    .unwrap();
    let receipt = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentReceiptV1 {
            deployment: deployment_id.clone(),
            function: receipt_function,
            artifact_hash,
            realm: "realm-a".into(),
            node: "node-a".into(),
            executor: executor_signer.public_key().into(),
            executor_creature: receipt_executor_override.unwrap_or(executor.0).to_string(),
            creature: target.0.to_string(),
            evidence: Vec::new(),
            registered_at_unix_ms: None,
        },
        executor_signer.as_ref(),
    )
    .unwrap();
    let requester = Ed25519SeedSigner::from_seed([102; 32]).unwrap();
    let request = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        UndeployRequestV1 {
            requested_by: HomeId::new(requester.public_key()),
            deployment: deployment_id,
            reason: Some("operator retired the exact deployment".into()),
        },
        &requester,
    )
    .unwrap();

    let (probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    if forge_same_corr_reply {
        let (_attacker_id, attacker_bus, _attacker_rx) =
            kernel.open_endpoint(Capabilities::default());
        let forged = FunctionDeployMessageV1::Undeployed {
            receipt: SignedRecordV1::sign(
                SCHEMA_FUNCTION_DEPLOY_V1,
                UndeployReceiptV1 {
                    deployment: request.payload.deployment.clone(),
                    executor: executor_signer.public_key().into(),
                    executor_creature: executor.0.to_string(),
                },
                executor_signer.as_ref(),
            )
            .unwrap(),
        };
        attacker_bus
            .send(
                Dispatch::to(Address::Creature(probe_id), serde_json::to_vec(&forged).unwrap())
                    .with_schema(SCHEMA_FUNCTION_DEPLOY_V1)
                    .with_corr(1),
            )
            .unwrap();
    }
    let ai = AiControl::new(true);
    let result = {
        let mut ctx = VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, None, &ai, false);
        run_verb(Verb::FunctionUndeploy { request, deployment: receipt }, &mut ctx, &mut |_| {})
    };
    if forge_same_corr_reply {
        let _ = probe_rx.recv_timeout(std::time::Duration::from_millis(250));
    }
    UndeployExercise { kernel, target, executor, stage, result }
}

#[test]
fn undeploy_confirms_executor_tombstone_before_unloading_exact_target() {
    let UndeployExercise { kernel, target, executor, stage, result } =
        exercise_undeploy(UndeployMode::Acknowledge, false, None, false, false);
    assert!(result.ok, "retirement succeeds: {:?}", result.json);
    assert_eq!(result.json["durable_tombstone"], true);
    assert_eq!(result.json["target_status"], "unloaded");
    let acknowledgement: SignedRecordV1<UndeployReceiptV1> =
        serde_json::from_value(result.json["undeploy_receipt"].clone()).unwrap();
    gawdfn::verify_undeploy_receipt(&acknowledgement).unwrap();
    assert_eq!(acknowledgement.payload.executor_creature, executor.0.to_string());
    assert_eq!(stage.load(Ordering::SeqCst), 2, "target shutdown followed durable acknowledgement");
    assert!(!kernel.is_loaded(target));
    assert!(kernel.is_loaded(executor));
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn undeploy_refusal_retains_the_loaded_target() {
    let UndeployExercise { kernel, target, stage, result, .. } =
        exercise_undeploy(UndeployMode::Refuse, false, None, false, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "deployment_busy");
    assert_eq!(result.json["durable_tombstone"], false);
    assert_eq!(result.json["loaded_instance_retained"], true);
    assert!(kernel.is_loaded(target));
    assert_eq!(stage.load(Ordering::SeqCst), 0);
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn forged_or_indeterminate_undeploy_reply_never_triggers_unload() {
    let UndeployExercise { kernel, target, result, .. } =
        exercise_undeploy(UndeployMode::Acknowledge, false, None, true, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "undeploy-outcome-indeterminate");
    assert_eq!(result.json["kernel_unload_attempted"], false);
    assert_eq!(result.json["loaded_instance_retained"], true);
    assert!(kernel.is_loaded(target), "an unauthenticated response cannot retire the target");
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn wrong_undeploy_acknowledgement_retains_the_loaded_target() {
    let UndeployExercise { kernel, target, result, .. } =
        exercise_undeploy(UndeployMode::WrongDeployment, false, None, false, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "undeploy-outcome-indeterminate");
    assert_eq!(result.json["kernel_unload_attempted"], false);
    assert!(kernel.is_loaded(target));
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn unexpected_undeploy_reply_retains_the_loaded_target() {
    let UndeployExercise { kernel, target, result, .. } =
        exercise_undeploy(UndeployMode::UnexpectedReply, false, None, false, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "undeploy-outcome-indeterminate");
    assert_eq!(result.json["kernel_unload_attempted"], false);
    assert!(kernel.is_loaded(target));
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn recovered_executor_rebinds_a_stale_receipt_route_with_a_signed_current_ack() {
    let UndeployExercise { kernel, target, result, .. } =
        exercise_undeploy(UndeployMode::Acknowledge, false, Some(999_999), false, false);
    assert!(result.ok, "stable executor continuity survives route restart: {:?}", result.json);
    assert_eq!(result.json["target_status"], "unloaded");
    assert!(!kernel.is_loaded(target));
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn undeploy_acknowledgement_must_use_the_deployment_pinned_stable_executor_key() {
    let UndeployExercise { kernel, target, result, .. } =
        exercise_undeploy(UndeployMode::WrongSigner, false, None, false, false);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "undeploy-outcome-indeterminate");
    assert!(result.json["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("different stable executor"));
    assert!(kernel.is_loaded(target), "a different executor key cannot authorize unload");
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn stale_or_reused_numeric_target_is_tombstoned_without_unsafe_unload() {
    let UndeployExercise { kernel, target, result, .. } =
        exercise_undeploy(UndeployMode::Acknowledge, true, None, false, false);
    assert!(result.ok, "durable retirement itself succeeded: {:?}", result.json);
    assert_eq!(result.json["durable_tombstone"], true);
    assert_eq!(result.json["target_status"], "identity_mismatch");
    assert_eq!(result.json["unsafe_unload_prevented"], true);
    assert_eq!(result.json["kernel_unload_attempted"], false);
    assert!(kernel.is_loaded(target), "the different occupant is not touched");
    kernel.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn unload_timeout_reports_a_tombstoned_safe_orphan() {
    let UndeployExercise { kernel, target, result, .. } =
        exercise_undeploy(UndeployMode::Acknowledge, false, None, false, true);
    assert!(!result.ok);
    assert_eq!(result.json["error"], "function-unload-incomplete");
    assert_eq!(result.json["durable_tombstone"], true);
    assert_eq!(result.json["retirement_state"], "tombstoned_safe_orphan");
    assert_eq!(result.json["target_routable"], false);
    assert!(!kernel.is_loaded(target), "a timed-out drain is already off the bus");
    std::thread::sleep(std::time::Duration::from_millis(300));
    kernel.shutdown_all(Deadline::from_millis(500));
}
