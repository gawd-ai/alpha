//! Composed delivery-behaviour proof for typed Functions and durable Jobs.
//!
//! All state transitions under test cross the real Kernel bus. The fixture constructs trust keys,
//! a signed resolution, and an already-loaded target deployment, but never calls Home or executor
//! state methods to advance a Job.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    Outcome, Role, StubSigner, StubVerifier,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use function_executor::{
    DeploymentAdmission, DeploymentLiveness, ExecutorConfig, FunctionExecutor, StringAddressing,
};
use function_home::{FunctionHome, FunctionMetadata, FunctionTrust, HomeConfig};
use gawdfn::{
    canonical_hash, derive_deployment_id, verify_job_control_acceptance, AbodeKeyBindingV1,
    AttemptId, AuthoritySigner, BlobAvailability, BlobRefV1, ContractError, ControlDispositionV1,
    ControlId, DeliveryModeV1, DeploymentReceiptV1, DeploymentRegistrationV1, DeploymentRequestV1,
    Ed25519SeedSigner, EffectClassV1, EntrypointContractV1, EventPageV1, EventQueryRelayV1,
    EventQueryV1, ExecuteMessageV1, ExecutionControlV1, ExecutionGrantV1, ExecutionReceiptV1,
    ExecutionStageV1, FunctionAlias, FunctionDeployMessageV1, FunctionId, FunctionResultV1,
    FunctionSelectorV1, HomeAuthorityV1, HomeId, JobAccessV1, JobControlKindV1, JobControlV1,
    JobEventKindV1, JobGetRelayV1, JobGetV1, JobHandleV1, JobMessageV1, JobSnapshotV1, JobStateV1,
    JobSubmitV1, OperationalCapabilityV1, OperationalKeyGrantV1, PlacementDecisionV1,
    PolicyMessageV1, ResolutionReceiptV1, RetryDecisionV1, RetryQuestionV1, SchemaRefV1,
    SignedRecordV1, UndeployRequestV1, ValueRefV1, FUNCTION_EXECUTOR_ROLE, FUNCTION_HOME_ROLE,
    FUNCTION_POLICY_ROLE, SCHEMA_CALL_V1, SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1,
    SCHEMA_HOME_V1, SCHEMA_JOB_V1, SCHEMA_POLICY_V1,
};
use sanctum::{Admission, Kernel, Policy};
use serde::Serialize;
use serde_json::json;
use sigil::{Backend, Capabilities, Entrypoint, Manifest};

struct AdmitFixture;

impl Policy for AdmitFixture {
    fn admit(&self, _manifest: &Manifest, _evidence: &Admission) -> Result<(), String> {
        Ok(())
    }
}

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("function-job-behaviors")),
        Arc::new(StubVerifier),
        Arc::new(AdmitFixture),
        512,
    )
}

fn boot_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

fn role(name: &str) -> Address {
    Address::Role(Role::new(name))
}

fn recv_corr(rx: &InboxReceiver, corr: u64, schema: &str) -> Envelope {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if let Ok(env) = rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            if env.header.corr == Some(corr) && env.header.schema == schema {
                return env;
            }
        }
    }
    panic!("no {schema} reply for correlation {corr}");
}

fn send_rpc<T: Serialize>(
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    corr: u64,
    to: Address,
    schema: &str,
    message: &T,
) -> Envelope {
    bus.send(
        Dispatch::to(to, aether::wire::to_bytes(message))
            .with_schema(schema)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(corr),
    )
    .expect("request routes through the real bus");
    recv_corr(rx, corr, schema)
}

struct KernelLiveness(Weak<Kernel>);

impl DeploymentLiveness for KernelLiveness {
    fn target_is_live(
        &self,
        target: CreatureId,
        deployment: &DeploymentReceiptV1,
    ) -> Result<bool, String> {
        let kernel = self.0.upgrade().ok_or_else(|| "Kernel roster is unavailable".to_string())?;
        let Some(identity) = kernel.loaded_manifest_identity(target) else {
            return Ok(false);
        };
        Ok(identity.manifest_content_address.as_deref()
            == Some(deployment.function.manifest_content_address.as_str())
            && identity.artifact_build_hash.as_deref().and_then(normalize_sha256).as_deref()
                == Some(deployment.artifact_hash.as_str()))
    }
}

fn normalize_sha256(value: &str) -> Option<String> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    (raw.len() == 64
        && raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| format!("sha256:{raw}"))
}

struct OwnerAdmission(String);

impl DeploymentAdmission for OwnerAdmission {
    fn register(&self, request: &SignedRecordV1<DeploymentRegistrationV1>) -> Result<(), String> {
        (request.signer == self.0)
            .then_some(())
            .ok_or_else(|| "deployer is not the local Abode".into())
    }

    fn undeploy(
        &self,
        request: &SignedRecordV1<UndeployRequestV1>,
        _deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (request.signer == self.0)
            .then_some(())
            .ok_or_else(|| "undeployer is not the local Abode".into())
    }
}

struct IdempotentMetadata;

impl FunctionMetadata for IdempotentMetadata {
    fn effect(&self, _function: &gawdfn::ResolvedFunctionV1) -> EffectClassV1 {
        EffectClassV1::Idempotent
    }
}

struct InlineOnly;

impl BlobAvailability for InlineOnly {
    fn verify_available(&self, _blob: &BlobRefV1) -> Result<(), ContractError> {
        Err(ContractError::Invalid("fixture has no external blob store".into()))
    }
}

struct PinnedTrust {
    resolver: String,
    executor: String,
    policy: String,
}

impl FunctionTrust for PinnedTrust {
    fn allow_resolution(
        &self,
        resolution: &SignedRecordV1<ResolutionReceiptV1>,
    ) -> Result<(), String> {
        (resolution.signer == self.resolver)
            .then_some(())
            .ok_or_else(|| "untrusted resolver".into())
    }

    fn allow_deployment(
        &self,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (deployment.signer == self.executor)
            .then_some(())
            .ok_or_else(|| "untrusted executor deployment".into())
    }

    fn allow_executor_receipt(
        &self,
        receipt: &SignedRecordV1<ExecutionReceiptV1>,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (receipt.signer == self.executor && deployment.signer == self.executor)
            .then_some(())
            .ok_or_else(|| "untrusted executor receipt".into())
    }

    fn allow_placement_decision(
        &self,
        decision: &SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "untrusted placement policy".into())
    }

    fn allow_retry_decision(
        &self,
        decision: &SignedRecordV1<RetryDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "untrusted retry policy".into())
    }
}

#[derive(Clone)]
struct CapturedControl {
    from: Address,
    attempt: AttemptId,
    endorsed: SignedRecordV1<ExecutionControlV1>,
}

/// A cooperative typed target. Parent calls remain live after reporting progress, child calls
/// finish immediately, and retry calls fail their first numbered attempt then succeed their second.
struct CooperativeTarget {
    function: FunctionId,
    calls: Arc<Mutex<Vec<AttemptId>>>,
    controls: Arc<Mutex<Vec<CapturedControl>>>,
}

impl Creature for CooperativeTarget {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if let Ok(call) = forge::function::parse_call_for(&env, &self.function) {
            self.calls
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(call.attempt.clone());
            let ValueRefV1::Inline { value } = &call.input else {
                return Outcome::none();
            };
            let mode = value.get("mode").and_then(serde_json::Value::as_str).unwrap_or_default();
            let dispatch = match mode {
                "parent" => forge::function::progress(
                    &env,
                    call.attempt,
                    1,
                    ValueRefV1::Inline { value: json!({"phase": "ready"}) },
                ),
                "child" => forge::function::reply(
                    &env,
                    FunctionResultV1 {
                        attempt: call.attempt,
                        outcome: Ok(ValueRefV1::Inline { value: json!({"child": "complete"}) }),
                    },
                ),
                "retry" if call.attempt.number == 1 => forge::function::reply(
                    &env,
                    FunctionResultV1 {
                        attempt: call.attempt,
                        outcome: Err(ValueRefV1::Inline {
                            value: json!({"kind": "transient", "attempt": 1}),
                        }),
                    },
                ),
                "retry" => forge::function::reply(
                    &env,
                    FunctionResultV1 {
                        attempt: call.attempt,
                        outcome: Ok(ValueRefV1::Inline {
                            value: json!({"attempt": 2, "status": "recovered"}),
                        }),
                    },
                ),
                _ => return Outcome::none(),
            };
            return dispatch.map_or_else(|_| Outcome::none(), Outcome::send);
        }

        let Ok((attempt, endorsed)) = forge::function::parse_control(&env) else {
            return Outcome::none();
        };
        self.controls.lock().unwrap_or_else(|poison| poison.into_inner()).push(CapturedControl {
            from: env.header.from.clone(),
            attempt: attempt.clone(),
            endorsed,
        });
        let Ok(ack) = forge::function::control_result(
            &env,
            ControlDispositionV1::Applied,
            Some("pace accepted".into()),
        ) else {
            return Outcome::none();
        };
        let Ok(result) = forge::function::reply(
            &env,
            FunctionResultV1 {
                attempt,
                outcome: Ok(ValueRefV1::Inline { value: json!({"steered": true}) }),
            },
        ) else {
            return Outcome::none();
        };
        let mut outcome = Outcome::send(ack);
        outcome.push(result);
        outcome
    }
}

struct CapturingExecutor {
    inner: FunctionExecutor,
    grants: Arc<Mutex<Vec<SignedRecordV1<ExecutionGrantV1>>>>,
}

impl Creature for CapturingExecutor {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.inner.bind(ctx);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema == SCHEMA_EXECUTE_V1 {
            if let Ok(ExecuteMessageV1::Grant { grant }) =
                serde_json::from_slice::<ExecuteMessageV1>(&env.payload)
            {
                self.grants.lock().unwrap_or_else(|poison| poison.into_inner()).push(*grant);
            }
        }
        self.inner.handle(env)
    }

    fn shutdown(&mut self, deadline: Deadline) {
        self.inner.shutdown(deadline);
    }
}

/// This policy intentionally treats the target's first error as retryable. That choice is model
/// policy, not executor or Home mechanism, and its signed decision is retained for the assertions.
struct RetryOncePolicy {
    signer: Arc<Ed25519SeedSigner>,
    retries: Arc<Mutex<Vec<SignedRecordV1<RetryDecisionV1>>>>,
}

impl Creature for RetryOncePolicy {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA_POLICY_V1 {
            return Outcome::none();
        }
        let Ok(message) = serde_json::from_slice::<PolicyMessageV1>(&env.payload) else {
            return Outcome::none();
        };
        let response = match message {
            PolicyMessageV1::SelectDeployment { question } => {
                let Ok(question_hash) = canonical_hash(&question) else {
                    return Outcome::none();
                };
                let Some(selected) = question.payload.candidates.first() else {
                    return Outcome::none();
                };
                let Ok(decision) = SignedRecordV1::sign(
                    SCHEMA_POLICY_V1,
                    PlacementDecisionV1 {
                        job: question.payload.job.clone(),
                        question_hash,
                        selected: selected.payload.deployment.clone(),
                        evidence: vec![],
                    },
                    self.signer.as_ref(),
                ) else {
                    return Outcome::none();
                };
                PolicyMessageV1::DeploymentSelected { decision: Box::new(decision) }
            }
            PolicyMessageV1::DecideRetry { question } => {
                let Ok(question_hash) = canonical_hash(&question) else {
                    return Outcome::none();
                };
                let RetryQuestionV1 { snapshot, failed_attempt, candidates, .. } = question.payload;
                let Some(deployment) = candidates.first() else {
                    return Outcome::none();
                };
                let payload = RetryDecisionV1::Retry {
                    question_hash,
                    job: snapshot.spec.handle,
                    failed_attempt: failed_attempt.clone(),
                    next_attempt: AttemptId {
                        home: failed_attempt.home.clone(),
                        job: failed_attempt.job.clone(),
                        number: failed_attempt.number.saturating_add(1),
                    },
                    deployment: Box::new(deployment.clone()),
                    not_before_unix_ms: None,
                };
                let Ok(decision) =
                    SignedRecordV1::sign(SCHEMA_POLICY_V1, payload, self.signer.as_ref())
                else {
                    return Outcome::none();
                };
                self.retries
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(decision.clone());
                PolicyMessageV1::RetryDecided { decision: Box::new(decision) }
            }
            PolicyMessageV1::DeploymentSelected { .. }
            | PolicyMessageV1::RetryDecided { .. }
            | PolicyMessageV1::Error { .. } => return Outcome::none(),
        };
        Outcome::send(
            Dispatch::reply_to_env(&env, aether::wire::to_bytes(&response))
                .with_schema(SCHEMA_POLICY_V1),
        )
    }
}

struct Harness {
    root: PathBuf,
    node: Arc<Kernel>,
    abode: Arc<Ed25519SeedSigner>,
    controller: Arc<Ed25519SeedSigner>,
    executor: Arc<Ed25519SeedSigner>,
    policy: Arc<Ed25519SeedSigner>,
    home: HomeId,
    selector: FunctionSelectorV1,
    resolution: SignedRecordV1<ResolutionReceiptV1>,
    deployment: SignedRecordV1<DeploymentReceiptV1>,
    target_id: CreatureId,
    executor_id: CreatureId,
    home_id: CreatureId,
    probe_id: CreatureId,
    bus: aether::BusHandle,
    rx: InboxReceiver,
    calls: Arc<Mutex<Vec<AttemptId>>>,
    controls: Arc<Mutex<Vec<CapturedControl>>>,
    grants: Arc<Mutex<Vec<SignedRecordV1<ExecutionGrantV1>>>>,
    retry_decisions: Arc<Mutex<Vec<SignedRecordV1<RetryDecisionV1>>>>,
}

impl Harness {
    fn new() -> Self {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        let root = std::env::temp_dir()
            .join(format!("alpha-function-job-behaviors-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create test state root");

        let abode = Arc::new(Ed25519SeedSigner::from_seed([71; 32]).expect("abode key"));
        let controller = Arc::new(Ed25519SeedSigner::from_seed([72; 32]).expect("controller key"));
        let operational =
            Arc::new(Ed25519SeedSigner::from_seed([73; 32]).expect("operational key"));
        let resolver = Arc::new(Ed25519SeedSigner::from_seed([74; 32]).expect("resolver key"));
        let executor = Arc::new(Ed25519SeedSigner::from_seed([75; 32]).expect("executor key"));
        let policy = Arc::new(Ed25519SeedSigner::from_seed([76; 32]).expect("policy key"));
        let home = HomeId::new(abode.public_key());
        let authority = home_authority(&home, abode.as_ref(), operational.as_ref());

        let artifact_hash_raw = "d".repeat(64);
        let mut target_manifest = boot_manifest("cooperative-function-target");
        target_manifest.provenance.build_hash = Some(artifact_hash_raw.clone());
        target_manifest.entrypoints.push(Entrypoint {
            name: "cooperate".into(),
            signature: SCHEMA_CALL_V1.into(),
            contract: Some(EntrypointContractV1 {
                description: "Exercise progress, controls, children, and retries".into(),
                input_schema: SchemaRefV1::Inline {
                    schema: json!({"type":"object", "required":["mode"]}),
                },
                output_schema: SchemaRefV1::Inline { schema: json!({"type":"object"}) },
                error_schema: Some(SchemaRefV1::Inline { schema: json!({"type":"object"}) }),
                effect: EffectClassV1::Idempotent,
                controls: Default::default(),
            }),
        });
        let manifest_content_address = target_manifest.compute_content_address();
        target_manifest.content_address = Some(manifest_content_address.clone());
        target_manifest.validate().expect("typed target manifest");
        let function = FunctionId { manifest_content_address, entrypoint: "cooperate".into() };
        let selector = FunctionSelectorV1::Alias {
            alias: FunctionAlias {
                realm: "local".into(),
                name: "cooperative-function-target".into(),
                version: "0.1.0".into(),
                entrypoint: "cooperate".into(),
            },
        };
        let resolution = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            ResolutionReceiptV1 {
                selector: selector.clone(),
                function: function.clone(),
                artifact_hash: format!("sha256:{artifact_hash_raw}"),
                resolved_at_unix_ms: None,
                evidence: vec![],
            },
            resolver.as_ref(),
        )
        .expect("signed resolution fixture");

        let calls = Arc::new(Mutex::new(Vec::new()));
        let controls = Arc::new(Mutex::new(Vec::new()));
        let grants = Arc::new(Mutex::new(Vec::new()));
        let retry_decisions = Arc::new(Mutex::new(Vec::new()));
        let node = kernel();
        let target_id = node
            .load_instance(
                target_manifest,
                Box::new(CooperativeTarget {
                    function: function.clone(),
                    calls: calls.clone(),
                    controls: controls.clone(),
                }),
            )
            .expect("target loads");

        let liveness = Arc::new(KernelLiveness(Arc::downgrade(&node)));
        let inner = FunctionExecutor::open_with_liveness(
            ExecutorConfig::new(root.join("executor"), executor.public_key()),
            executor.clone(),
            Arc::new(StringAddressing),
            Arc::new(OwnerAdmission(home.to_string())),
            liveness,
        )
        .expect("executor opens");
        let executor_id = node
            .load_instance(
                boot_manifest("function-executor"),
                Box::new(CapturingExecutor { inner, grants: grants.clone() }),
            )
            .expect("executor loads");
        node.bind_role(Role::new(FUNCTION_EXECUTOR_ROLE), executor_id);

        let home_creature = FunctionHome::open(
            HomeConfig::for_creature(root.join("home"), home.clone(), authority)
                .with_location("local", "local"),
            operational.clone(),
            Arc::new(IdempotentMetadata),
            Arc::new(PinnedTrust {
                resolver: resolver.public_key().into(),
                executor: executor.public_key().into(),
                policy: policy.public_key().into(),
            }),
            Arc::new(InlineOnly),
        )
        .expect("Home opens");
        let home_id = node
            .load_instance(boot_manifest("function-home"), Box::new(home_creature))
            .expect("Home loads");
        node.bind_role(Role::new(FUNCTION_HOME_ROLE), home_id);

        let policy_id = node
            .load_instance(
                boot_manifest("retry-once-policy"),
                Box::new(RetryOncePolicy {
                    signer: policy.clone(),
                    retries: retry_decisions.clone(),
                }),
            )
            .expect("policy loads");
        node.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy_id);
        let (probe_id, bus, rx) = node.open_endpoint(Capabilities::default());

        let authorization = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentRequestV1 {
                requested_by: home.clone(),
                function: selector.clone(),
                target_realm: "local".into(),
                target_node: Some("local".into()),
                evidence: vec![],
                requested_at_unix_ms: None,
            },
            abode.as_ref(),
        )
        .expect("deployment authorization");
        let registration = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentRegistrationV1 {
                authorization,
                resolution: resolution.clone(),
                deployment: derive_deployment_id(
                    &function,
                    &resolution.payload.artifact_hash,
                    "local",
                    "local",
                    &target_id.0.to_string(),
                )
                .expect("deployment identity"),
                function: function.clone(),
                artifact_hash: resolution.payload.artifact_hash.clone(),
                target_creature: target_id.0.to_string(),
                evidence: vec![],
            },
            abode.as_ref(),
        )
        .expect("deployment registration");
        let env = send_rpc(
            &bus,
            &rx,
            1,
            role(FUNCTION_EXECUTOR_ROLE),
            SCHEMA_FUNCTION_DEPLOY_V1,
            &FunctionDeployMessageV1::Register { request: Box::new(registration) },
        );
        let deployment = match serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
            .expect("deployment response")
        {
            FunctionDeployMessageV1::Registered { receipt } => receipt,
            other => panic!("expected Registered, got {other:?}"),
        };
        gawdfn::verify_deployment_receipt(&deployment).expect("valid deployment receipt");

        Self {
            root,
            node,
            abode,
            controller,
            executor,
            policy,
            home,
            selector,
            resolution,
            deployment,
            target_id,
            executor_id,
            home_id,
            probe_id,
            bus,
            rx,
            calls,
            controls,
            grants,
            retry_decisions,
        }
    }

    fn submit(
        &self,
        corr: u64,
        key: &str,
        mode: &str,
        delivery: DeliveryModeV1,
        access: JobAccessV1,
    ) -> (JobHandleV1, SignedRecordV1<gawdfn::JobEventV1>) {
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobSubmitV1 {
                home: self.home.clone(),
                caller_idempotency_key: key.into(),
                function: self.selector.clone(),
                input: ValueRefV1::Inline { value: json!({"mode": mode}) },
                delivery,
                allow_duplicate_effects: false,
                parent: None,
                causal: vec![],
                access,
                evidence: vec![],
                result_recipients: vec![],
                submitted_at_unix_ms: None,
            },
            self.abode.as_ref(),
        )
        .expect("signed submission");
        let env = send_rpc(
            &self.bus,
            &self.rx,
            corr,
            role(FUNCTION_HOME_ROLE),
            SCHEMA_JOB_V1,
            &JobMessageV1::Submit {
                request: Box::new(request),
                resolution: Box::new(self.resolution.clone()),
                deployment: Box::new(self.deployment.clone()),
            },
        );
        match serde_json::from_slice::<JobMessageV1>(&env.payload).expect("submission response") {
            JobMessageV1::Accepted { handle, request_hash, submitted } => {
                gawdfn::verify_job_acceptance(&handle, &request_hash, &submitted)
                    .expect("durable acceptance proof");
                (handle, *submitted)
            }
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    fn events(&self, handle: &JobHandleV1, corr: u64) -> EventPageV1 {
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryV1 {
                handle: handle.clone(),
                after_sequence: None,
                limit: 128,
                nonce: format!("events-{corr}"),
            },
            self.abode.as_ref(),
        )
        .expect("event query");
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryRelayV1 {
                caller,
                reply_to: serde_json::to_string(&Address::Creature(self.bus.id())).unwrap(),
            },
            self.abode.as_ref(),
        )
        .expect("event query relay");
        let env = send_rpc(
            &self.bus,
            &self.rx,
            corr,
            role(FUNCTION_HOME_ROLE),
            SCHEMA_JOB_V1,
            &JobMessageV1::Events { request: Box::new(request.clone()) },
        );
        match serde_json::from_slice::<JobMessageV1>(&env.payload).expect("event response") {
            JobMessageV1::EventPage { response } => {
                gawdfn::verify_event_page_response_for(&response, &request)
                    .expect("event response binds exact relay");
                response.payload.page
            }
            other => panic!("expected EventPage, got {other:?}"),
        }
    }

    fn snapshot(&self, handle: &JobHandleV1, corr: u64) -> SignedRecordV1<JobSnapshotV1> {
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetV1 { handle: handle.clone(), nonce: format!("read-{corr}") },
            self.abode.as_ref(),
        )
        .expect("snapshot query");
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetRelayV1 {
                caller,
                reply_to: serde_json::to_string(&Address::Creature(self.bus.id())).unwrap(),
            },
            self.abode.as_ref(),
        )
        .expect("snapshot query relay");
        let env = send_rpc(
            &self.bus,
            &self.rx,
            corr,
            role(FUNCTION_HOME_ROLE),
            SCHEMA_JOB_V1,
            &JobMessageV1::Get { request: Box::new(request.clone()) },
        );
        match serde_json::from_slice::<JobMessageV1>(&env.payload).expect("snapshot response") {
            JobMessageV1::Snapshot { response } => {
                gawdfn::verify_job_snapshot_response_for(&response, &request)
                    .expect("snapshot response binds exact relay");
                *response.payload.snapshot
            }
            other => panic!("expected Snapshot, got {other:?}"),
        }
    }

    fn wait_for<F>(&self, handle: &JobHandleV1, corr: &mut u64, predicate: F) -> EventPageV1
    where
        F: Fn(&EventPageV1) -> bool,
    {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let page = self.events(handle, *corr);
            *corr += 1;
            if predicate(&page) {
                return page;
            }
            assert!(Instant::now() < deadline, "timed out waiting for durable Job event");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn finish(self) {
        self.node.shutdown_all(Deadline::from_millis(500));
        let root = self.root.clone();
        drop(self);
        std::fs::remove_dir_all(root).expect("remove test state root");
    }
}

fn home_authority(
    home: &HomeId,
    abode: &Ed25519SeedSigner,
    operational: &Ed25519SeedSigner,
) -> HomeAuthorityV1 {
    let abode_binding = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        AbodeKeyBindingV1 {
            abode: home.clone(),
            root_public_key: abode.public_key().into(),
            issued_at_unix_ms: None,
        },
        abode,
    )
    .expect("root self-binding");
    let operational = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        OperationalKeyGrantV1 {
            home: home.clone(),
            epoch: 1,
            operational_public_key: operational.public_key().into(),
            valid_from_unix_ms: None,
            expires_at_unix_ms: None,
            capabilities: vec![
                OperationalCapabilityV1::JobHome,
                OperationalCapabilityV1::JobControl,
            ],
            evidence: vec![],
        },
        abode,
    )
    .expect("root grants operational authority");
    HomeAuthorityV1 { abode: abode_binding, operational, prepared: None }
}

fn find_grant(
    grants: &[SignedRecordV1<ExecutionGrantV1>],
    attempt: &AttemptId,
) -> SignedRecordV1<ExecutionGrantV1> {
    grants
        .iter()
        .find(|grant| &grant.payload.attempt == attempt)
        .cloned()
        .unwrap_or_else(|| panic!("missing grant for {attempt:?}"))
}

#[test]
fn progress_steer_and_causal_child_are_durable_and_proof_bound() {
    let harness = Harness::new();
    let access = JobAccessV1 {
        readers: vec![],
        controllers: vec![HomeId::new(harness.controller.public_key())],
    };
    let (parent, submitted) =
        harness.submit(10, "parent-job", "parent", DeliveryModeV1::AtMostOnce, access);
    let mut corr = 100;
    let parent_events = harness.wait_for(&parent, &mut corr, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
    });
    let progress = parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        .expect("durable progress event")
        .clone();
    let (parent_attempt, progress_sequence) = match &progress.payload.kind {
        JobEventKindV1::Progress { attempt, sequence, progress } => {
            assert_eq!(progress, &ValueRefV1::Inline { value: json!({"phase": "ready"}) });
            (attempt.clone(), *sequence)
        }
        _ => unreachable!(),
    };
    assert_eq!(progress_sequence, 1);
    let grants = harness.grants.lock().unwrap_or_else(|poison| poison.into_inner()).clone();
    let parent_grant = find_grant(&grants, &parent_attempt);
    gawdfn::verify_job_event_with_grant(&progress, &parent_grant)
        .expect("progress embeds the exact executor-authenticated foreign receipt");
    let progress_receipt = progress.payload.foreign_receipt.as_deref().expect("foreign receipt");
    assert_eq!(progress_receipt.signer, harness.executor.public_key());
    assert!(matches!(
        progress_receipt.payload.stage,
        ExecutionStageV1::Progress { sequence: 1, .. }
    ));

    let progress_hash = canonical_hash(&progress).expect("parent event hash");
    let child_submit = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSubmitV1 {
            home: harness.home.clone(),
            caller_idempotency_key: "child-job".into(),
            function: harness.selector.clone(),
            input: ValueRefV1::Inline { value: json!({"mode": "child"}) },
            delivery: DeliveryModeV1::AtMostOnce,
            allow_duplicate_effects: false,
            parent: Some(parent.clone()),
            causal: vec![gawdfn::CausalLinkV1 {
                job: parent.clone(),
                relation: "spawned_by".into(),
                receipt_hash: Some(progress_hash.clone()),
            }],
            access: JobAccessV1::default(),
            evidence: vec![],
            result_recipients: vec![],
            submitted_at_unix_ms: None,
        },
        harness.controller.as_ref(),
    )
    .expect("controller-authorized child submission");
    let child_request_hash = child_submit.payload.request_hash().expect("child request hash");
    let spawn = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            handle: parent.clone(),
            expected_home_epoch: 1,
            control: ControlId::new("spawn-child-1"),
            issued_at_unix_ms: None,
            kind: JobControlKindV1::ProposeChild {
                parent_attempt: parent_attempt.clone(),
                parent_event_hash: progress_hash,
                spawn_key: "spawn-1".into(),
                child_request_hash,
                submit: Box::new(child_submit),
                resolution: Box::new(harness.resolution.clone()),
                deployment: Box::new(harness.deployment.clone()),
            },
        },
        harness.controller.as_ref(),
    )
    .expect("controller-authorized child proposal");
    let spawn_message = JobMessageV1::Control { request: Box::new(spawn.clone()) };
    let first_spawn_env = send_rpc(
        &harness.bus,
        &harness.rx,
        11,
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &spawn_message,
    );
    let spawned = match serde_json::from_slice::<JobMessageV1>(&first_spawn_env.payload)
        .expect("spawn response")
    {
        JobMessageV1::ControlAccepted { request_hash, event } => {
            verify_job_control_acceptance(&spawn, &request_hash, &event)
                .expect("child acceptance binds the exact signed proposal");
            *event
        }
        other => panic!("expected child event, got {other:?}"),
    };
    let child = match &spawned.payload.kind {
        JobEventKindV1::ChildSpawned { parent_attempt: recorded, child, root, .. } => {
            assert_eq!(recorded, &parent_attempt);
            assert_eq!(root, &parent);
            child.clone()
        }
        other => panic!("expected ChildSpawned, got {other:?}"),
    };
    let duplicate_spawn_env = send_rpc(
        &harness.bus,
        &harness.rx,
        12,
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &spawn_message,
    );
    let duplicate_spawn = match serde_json::from_slice::<JobMessageV1>(&duplicate_spawn_env.payload)
        .expect("spawn replay response")
    {
        JobMessageV1::ControlAccepted { request_hash, event } => {
            verify_job_control_acceptance(&spawn, &request_hash, &event)
                .expect("child replay binds the same signed proposal");
            *event
        }
        other => panic!("expected replayed child event, got {other:?}"),
    };
    assert_eq!(duplicate_spawn, spawned, "spawn replay returns the exact durable edge");

    let child_events = harness.wait_for(&child, &mut corr, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
    });
    let child_submitted = child_events.events.first().expect("child Submitted event");
    assert_eq!(child_submitted.payload.state_after, JobStateV1::Queued);
    let JobEventKindV1::Submitted { spec } = &child_submitted.payload.kind else {
        panic!("child ledger must begin with Submitted")
    };
    assert_eq!(spec.root, parent);
    assert_eq!(spec.parent.as_ref(), Some(&parent));
    assert!(child_events.events.iter().any(|event| {
        matches!(
            &event.payload.kind,
            JobEventKindV1::DispatchGranted { attempt, .. }
                if attempt.job == child.job && attempt.number == 1
        )
    }));

    let steer = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            handle: parent.clone(),
            expected_home_epoch: 1,
            control: ControlId::new("steer-parent-1"),
            issued_at_unix_ms: None,
            kind: JobControlKindV1::Steer {
                value: ValueRefV1::Inline { value: json!({"pace": "fast"}) },
            },
        },
        harness.controller.as_ref(),
    )
    .expect("controller-signed steer");
    let steer_env = send_rpc(
        &harness.bus,
        &harness.rx,
        13,
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &JobMessageV1::Control { request: Box::new(steer.clone()) },
    );
    let issued =
        match serde_json::from_slice::<JobMessageV1>(&steer_env.payload).expect("steer response") {
            JobMessageV1::ControlAccepted { request_hash, event } => {
                verify_job_control_acceptance(&steer, &request_hash, &event)
                    .expect("steer acceptance binds the exact signed request");
                *event
            }
            other => panic!("expected durable control event, got {other:?}"),
        };
    assert!(matches!(
        &issued.payload.kind,
        JobEventKindV1::ControlRequested { request, attempt: Some(selected) }
            if request.as_ref() == &steer && selected == &parent_attempt
    ));

    let terminal = harness.wait_for(&parent, &mut corr, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
    });
    let queued = terminal
        .events
        .iter()
        .find(|event| {
            matches!(
                &event.payload.kind,
                JobEventKindV1::ControlQueued { control, attempt }
                    if control.as_str() == "steer-parent-1" && attempt == &parent_attempt
            )
        })
        .expect("Home persists executor queued intent receipt");
    let acknowledged = terminal
        .events
        .iter()
        .find(|event| {
            matches!(
                &event.payload.kind,
                JobEventKindV1::ControlAcknowledged { control, attempt, disposition }
                    if control.as_str() == "steer-parent-1"
                        && attempt == &parent_attempt
                        && *disposition == ControlDispositionV1::Applied
            )
        })
        .expect("Home persists cooperative target outcome");
    gawdfn::verify_job_event_with_grant(queued, &parent_grant)
        .expect("queued intent receipt binds the parent grant");
    gawdfn::verify_job_event_with_grant(acknowledged, &parent_grant)
        .expect("control outcome binds the parent grant");
    assert!(matches!(
        acknowledged.payload.foreign_receipt.as_deref().map(|receipt| &receipt.payload.stage),
        Some(ExecutionStageV1::ControlAcknowledged {
            disposition: ControlDispositionV1::Applied,
            ..
        })
    ));

    let controls = harness.controls.lock().unwrap_or_else(|poison| poison.into_inner()).clone();
    assert_eq!(controls.len(), 1);
    let captured = &controls[0];
    assert_eq!(captured.from, Address::Creature(harness.executor_id));
    assert_eq!(captured.attempt, parent_attempt);
    assert_eq!(captured.endorsed.payload.caller_request, steer);
    assert_eq!(captured.endorsed.payload.home_sequence, issued.payload.sequence);
    gawdfn::verify_execution_control(&captured.endorsed)
        .expect("target received an exact Home-endorsed control");

    let journal = harness.node.router().journal_snapshot();
    let accepted_stamp = journal
        .iter()
        .find(|entry| {
            entry.from == Address::Creature(harness.home_id)
                && entry.to == Address::Creature(harness.probe_id)
                && entry.corr == Some(10)
        })
        .expect("Accepted journal entry")
        .stamp;
    let parent_call_stamp = journal
        .iter()
        .filter(|entry| {
            entry.from == Address::Creature(harness.executor_id)
                && entry.to == Address::Creature(harness.target_id)
        })
        .map(|entry| entry.stamp)
        .min()
        .expect("parent call journal entry");
    assert!(accepted_stamp < parent_call_stamp, "Accepted precedes the parent call");
    let issued_stamp = journal
        .iter()
        .find(|entry| {
            entry.from == Address::Creature(harness.home_id)
                && entry.to == Address::Creature(harness.probe_id)
                && entry.corr == Some(13)
        })
        .expect("durable control response")
        .stamp;
    let forwarded_stamp = journal
        .iter()
        .filter(|entry| {
            entry.from == Address::Creature(harness.home_id)
                && entry.to == Address::Creature(harness.executor_id)
        })
        .map(|entry| entry.stamp)
        .filter(|stamp| *stamp > issued_stamp)
        .min()
        .expect("endorsed control journal entry");
    assert!(issued_stamp < forwarded_stamp, "Home persisted/replied before forwarding steer");
    assert_eq!(submitted.payload.sequence, 1);

    harness.finish();
}

#[test]
fn signed_policy_retry_creates_attributable_second_run_and_terminal_result() {
    let harness = Harness::new();
    let (handle, _submitted) = harness.submit(
        20,
        "retry-job",
        "retry",
        DeliveryModeV1::AtLeastOnce { max_attempts: 2 },
        JobAccessV1::default(),
    );
    let mut corr = 500;
    let events = harness.wait_for(&handle, &mut corr, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
    });

    let attempts = harness
        .calls
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .iter()
        .filter(|attempt| attempt.job == handle.job)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        attempts,
        vec![
            AttemptId { home: handle.home.clone(), job: handle.job.clone(), number: 1 },
            AttemptId { home: handle.home.clone(), job: handle.job.clone(), number: 2 },
        ],
        "the target observes two separately attributable runs"
    );
    assert!(events.events.iter().any(|event| {
        matches!(
            &event.payload.kind,
            JobEventKindV1::AttemptFailed { attempt, retryable: false, .. }
                if attempt.number == 1
        ) && event.payload.state_after == JobStateV1::RetryPending
    }));
    assert!(events.events.iter().any(|event| {
        matches!(
            &event.payload.kind,
            JobEventKindV1::RetryScheduled { next_attempt, .. }
                if next_attempt.number == 2
        )
    }));
    assert!(events.events.iter().any(|event| {
        matches!(
            &event.payload.kind,
            JobEventKindV1::DispatchGranted { attempt, .. } if attempt.number == 2
        )
    }));
    let terminal = events.events.last().expect("terminal event");
    assert!(matches!(
        &terminal.payload.kind,
        JobEventKindV1::Succeeded { attempt, result }
            if attempt.number == 2
                && result == &ValueRefV1::Inline {
                    value: json!({"attempt": 2, "status": "recovered"})
                }
    ));
    assert_eq!(terminal.payload.state_after, JobStateV1::Succeeded);

    let decisions =
        harness.retry_decisions.lock().unwrap_or_else(|poison| poison.into_inner()).clone();
    assert_eq!(decisions.len(), 1, "one policy decision authorizes the bounded retry");
    let decision = &decisions[0];
    assert!(decision.verify());
    assert_eq!(decision.signer, harness.policy.public_key());
    match &decision.payload {
        RetryDecisionV1::Retry { next_attempt, deployment, .. } => {
            assert_eq!(
                next_attempt,
                &AttemptId { home: handle.home.clone(), job: handle.job.clone(), number: 2 }
            );
            assert_eq!(deployment.as_ref(), &harness.deployment);
        }
        other => panic!("expected signed Retry, got {other:?}"),
    }

    let grants = harness.grants.lock().unwrap_or_else(|poison| poison.into_inner()).clone();
    let attempt_one = AttemptId { home: handle.home.clone(), job: handle.job.clone(), number: 1 };
    let attempt_two = AttemptId { home: handle.home.clone(), job: handle.job.clone(), number: 2 };
    let grant_one = find_grant(&grants, &attempt_one);
    let grant_two = find_grant(&grants, &attempt_two);
    gawdfn::verify_execution_grant(&grant_one).expect("first attempt grant");
    gawdfn::verify_execution_grant(&grant_two).expect("second attempt grant");
    assert!(grant_one.payload.grant_sequence < grant_two.payload.grant_sequence);
    gawdfn::verify_job_event_with_grant(terminal, &grant_two)
        .expect("terminal receipt binds the exact second grant");

    let snapshot = harness.snapshot(&handle, corr);
    gawdfn::verify_job_snapshot(&snapshot).expect("durable terminal snapshot");
    assert_eq!(snapshot.payload.current_attempt, Some(attempt_two));
    assert_eq!(snapshot.payload.state, JobStateV1::Succeeded);

    let journal = harness.node.router().journal_snapshot();
    let accepted_stamp = journal
        .iter()
        .find(|entry| {
            entry.from == Address::Creature(harness.home_id)
                && entry.to == Address::Creature(harness.probe_id)
                && entry.corr == Some(20)
        })
        .expect("Accepted journal entry")
        .stamp;
    let first_call_stamp = journal
        .iter()
        .filter(|entry| {
            entry.from == Address::Creature(harness.executor_id)
                && entry.to == Address::Creature(harness.target_id)
        })
        .map(|entry| entry.stamp)
        .min()
        .expect("first retry run");
    assert!(accepted_stamp < first_call_stamp, "Accepted precedes the first retry run");

    harness.finish();
}
