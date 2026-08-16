//! Composed local proof for typed functions and durable jobs.
//!
//! This deliberately crosses the dynamic seams instead of calling organ methods directly:
//! resolver, executor registry, home, placement policy, and the typed target are ordinary
//! creatures on one real Kernel. The only fixture-specific pieces are injected trust/catalog
//! models and deterministic test keys.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    Outcome, RealmId, Role, StubSigner, StubVerifier,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine, CRITTER_ABI_TAG};
use bestiary::CatalogEntry;
use function_executor::{
    DeploymentAdmission, DeploymentLiveness, ExecutorConfig, FunctionExecutor, StringAddressing,
};
use function_home::{FunctionHome, FunctionMetadata, FunctionTrust, HomeConfig};
use function_resolver::{FunctionCatalog, FunctionResolver};
use gawdfn::{
    derive_deployment_id, AbodeKeyBindingV1, AuthoritySigner, BlobAvailability, BlobRefV1,
    ContractError, DeliveryModeV1, DeploymentListV1, DeploymentQueryV1, DeploymentReceiptV1,
    DeploymentRegistrationV1, DeploymentRequestV1, Ed25519SeedSigner, EffectClassV1,
    EntrypointContractV1, EventPageV1, EventQueryRelayV1, EventQueryV1, ExecuteMessageV1,
    ExecutionReceiptV1, ExecutionStageV1, FunctionAlias, FunctionCallMessageV1, FunctionCallV1,
    FunctionDeployMessageV1, FunctionId, FunctionSelectorV1, HomeAuthorityV1, HomeId, JobAccessV1,
    JobGetRelayV1, JobGetV1, JobHandleV1, JobMessageV1, JobSnapshotV1, JobStateV1, JobSubmitV1,
    OperationalCapabilityV1, OperationalKeyGrantV1, PlacementDecisionV1, ResolutionReceiptV1,
    ResolveRequestV1, ResolvedFunctionV1, RetryDecisionV1, SchemaRefV1, SignedRecordV1,
    UndeployRequestV1, Validate, ValueRefV1, FUNCTION_EXECUTOR_ROLE, FUNCTION_HOME_ROLE,
    FUNCTION_POLICY_ROLE, FUNCTION_RESOLVER_ROLE, SCHEMA_CALL_V1, SCHEMA_EXECUTE_V1,
    SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1, SCHEMA_JOB_V1,
};
use policy_job_basic::{BasicJobPolicy, BasicPolicyCaps};
use sanctum::{Admission, Kernel, Policy};
use serde::Serialize;
use serde_json::json;
use sigil::{Backend, Capabilities, Entrypoint, Manifest};

const TYPED_ADD_ONE_SOURCE: &[u8] =
    include_bytes!("../../creatures/prototypes/critters/typed-add-one/typed-add-one.rhai");

struct AdmitBootCreatures;

impl Policy for AdmitBootCreatures {
    fn admit(&self, _manifest: &Manifest, _evidence: &Admission) -> Result<(), String> {
        Ok(())
    }
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

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("function-jobs-e2e")),
        Arc::new(StubVerifier),
        Arc::new(AdmitBootCreatures),
        256,
    )
}

fn boot_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

fn role(name: &str) -> Address {
    Address::Role(Role::new(name))
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
    recv_corr(rx, corr, schema, Duration::from_secs(3))
}

fn recv_corr(rx: &InboxReceiver, corr: u64, schema: &str, budget: Duration) -> Envelope {
    let deadline = Instant::now() + budget;
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

#[derive(Clone)]
struct StaticCatalog(Vec<CatalogEntry>);

impl FunctionCatalog for StaticCatalog {
    fn candidates(&self, _request: &ResolveRequestV1) -> Result<Vec<CatalogEntry>, String> {
        Ok(self.0.clone())
    }
}

struct IdempotentMetadata;

impl FunctionMetadata for IdempotentMetadata {
    fn effect(&self, _function: &ResolvedFunctionV1) -> EffectClassV1 {
        EffectClassV1::Idempotent
    }
}

/// The test makes the trust roots explicit. A valid signature from any other key is still refused.
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
            .ok_or_else(|| "resolver key is not trusted".into())
    }

    fn allow_deployment(
        &self,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (deployment.signer == self.executor)
            .then_some(())
            .ok_or_else(|| "executor key is not trusted".into())
    }

    fn allow_executor_receipt(
        &self,
        receipt: &SignedRecordV1<ExecutionReceiptV1>,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (receipt.signer == self.executor && deployment.signer == self.executor)
            .then_some(())
            .ok_or_else(|| "execution receipt is not from the pinned executor".into())
    }

    fn allow_placement_decision(
        &self,
        decision: &SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "placement policy key is not trusted".into())
    }

    fn allow_retry_decision(
        &self,
        decision: &SignedRecordV1<RetryDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "retry policy key is not trusted".into())
    }
}

struct InlineOnly;

impl BlobAvailability for InlineOnly {
    fn verify_available(&self, _blob: &BlobRefV1) -> Result<(), ContractError> {
        Err(ContractError::Invalid("this fixture intentionally has no external blob store".into()))
    }
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

struct Noop;

impl Creature for Noop {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

/// Observability filling around the real executor. It does not alter routing or execution; it only
/// retains the authority-bearing grant so the restart half can replay the exact signed bytes.
struct CapturingExecutor {
    inner: FunctionExecutor,
    grants: Arc<Mutex<Vec<SignedRecordV1<gawdfn::ExecutionGrantV1>>>>,
    calls: Arc<Mutex<Vec<FunctionCallV1>>>,
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
                self.grants.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(*grant);
            }
        }
        let outcome = self.inner.handle(env);
        for dispatch in &outcome.dispatches {
            if dispatch.schema != SCHEMA_CALL_V1 {
                continue;
            }
            if let Ok(FunctionCallMessageV1::Call { call }) =
                serde_json::from_slice::<FunctionCallMessageV1>(&dispatch.payload)
            {
                self.calls.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(*call);
            }
        }
        outcome
    }

    fn shutdown(&mut self, deadline: Deadline) {
        self.inner.shutdown(deadline);
    }
}

struct Fixture {
    root: PathBuf,
    abode: Arc<Ed25519SeedSigner>,
    operational: Arc<Ed25519SeedSigner>,
    resolver: Arc<Ed25519SeedSigner>,
    executor: Arc<Ed25519SeedSigner>,
    policy: Arc<Ed25519SeedSigner>,
    home: HomeId,
    authority: HomeAuthorityV1,
    alias: FunctionAlias,
    target_manifest: Manifest,
    function: FunctionId,
    artifact_hash_raw: String,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        let root = std::env::temp_dir()
            .join(format!("alpha-function-jobs-e2e-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create isolated state root");

        let abode = Arc::new(Ed25519SeedSigner::from_seed([61; 32]).expect("abode key"));
        let operational =
            Arc::new(Ed25519SeedSigner::from_seed([62; 32]).expect("operational key"));
        let resolver = Arc::new(Ed25519SeedSigner::from_seed([63; 32]).expect("resolver key"));
        let executor = Arc::new(Ed25519SeedSigner::from_seed([64; 32]).expect("executor key"));
        let policy = Arc::new(Ed25519SeedSigner::from_seed([65; 32]).expect("policy key"));
        let home = HomeId::new(abode.public_key());
        let abode_binding = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            AbodeKeyBindingV1 {
                abode: home.clone(),
                root_public_key: abode.public_key().into(),
                issued_at_unix_ms: None,
            },
            abode.as_ref(),
        )
        .expect("root self-binding");
        let operational_grant = SignedRecordV1::sign(
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
            abode.as_ref(),
        )
        .expect("root grants an epoch key without exporting the root private key");
        let authority = HomeAuthorityV1 {
            abode: abode_binding,
            operational: operational_grant,
            prepared: None,
        };

        let artifact_hash = gawdfn::sha256_digest(TYPED_ADD_ONE_SOURCE);
        let artifact_hash_raw = artifact_hash
            .strip_prefix("sha256:")
            .expect("gawdfn digest is canonically prefixed")
            .to_string();
        let mut target_manifest =
            Manifest::new("typed-add-one", "0.1.0", Backend::Critter, CRITTER_ABI_TAG);
        // Function identity includes the exact artifact digest. Set it before computing the manifest
        // content address, matching the same ordering required before manifest signing.
        target_manifest.provenance.build_hash = Some(artifact_hash_raw.clone());
        target_manifest.entrypoints.push(Entrypoint {
            name: "add_one".into(),
            signature: SCHEMA_CALL_V1.into(),
            contract: Some(EntrypointContractV1 {
                description: "Add one to an integer".into(),
                input_schema: SchemaRefV1::Inline {
                    schema: json!({
                        "type": "object",
                        "required": ["value"],
                        "properties": { "value": { "type": "integer" } }
                    }),
                },
                output_schema: SchemaRefV1::Inline {
                    schema: json!({
                        "type": "object",
                        "required": ["answer"],
                        "properties": { "answer": { "type": "integer" } }
                    }),
                },
                error_schema: None,
                effect: EffectClassV1::Idempotent,
                controls: Default::default(),
            }),
        });
        let manifest_content_address = target_manifest.compute_content_address();
        target_manifest.content_address = Some(manifest_content_address.clone());
        target_manifest.validate().expect("typed manifest is valid");
        let function = FunctionId { manifest_content_address, entrypoint: "add_one".into() };

        Self {
            root,
            abode,
            operational,
            resolver,
            executor,
            policy,
            home,
            authority,
            alias: FunctionAlias {
                realm: "local".into(),
                name: "typed-add-one".into(),
                version: "0.1.0".into(),
                entrypoint: "add_one".into(),
            },
            target_manifest,
            function,
            artifact_hash_raw,
        }
    }

    fn executor_config(&self) -> ExecutorConfig {
        ExecutorConfig::new(self.root.join("executor"), self.executor.public_key())
    }

    fn home_config(&self) -> HomeConfig {
        HomeConfig::for_creature(self.root.join("home"), self.home.clone(), self.authority.clone())
            .with_location("local", "local")
    }

    fn trust(&self) -> Arc<dyn FunctionTrust> {
        Arc::new(PinnedTrust {
            resolver: self.resolver.public_key().into(),
            executor: self.executor.public_key().into(),
            policy: self.policy.public_key().into(),
        })
    }

    fn open_executor(&self, liveness: Arc<dyn DeploymentLiveness>) -> FunctionExecutor {
        FunctionExecutor::open_with_liveness(
            self.executor_config(),
            self.executor.clone(),
            Arc::new(StringAddressing),
            Arc::new(OwnerAdmission(self.home.to_string())),
            liveness,
        )
        .expect("executor opens or recovers")
    }

    fn open_home(&self) -> FunctionHome {
        FunctionHome::open(
            self.home_config(),
            self.operational.clone(),
            Arc::new(IdempotentMetadata),
            self.trust(),
            Arc::new(InlineOnly),
        )
        .expect("home opens or recovers")
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn catalog(fixture: &Fixture) -> StaticCatalog {
    StaticCatalog(vec![CatalogEntry {
        artifact_hash: fixture.artifact_hash_raw.clone(),
        realm: RealmId("local".into()),
        manifest: fixture.target_manifest.clone(),
        reputation: None,
        quarantine: None,
    }])
}

fn load_target(kernel: &Kernel, fixture: &Fixture) -> aether::CreatureId {
    kernel
        .load(fixture.target_manifest.clone(), Artifact::Bytes(TYPED_ADD_ONE_SOURCE.to_vec()))
        .expect("typed critter loads through Kernel admission and ScriptEngine")
}

fn load_executor(
    kernel: &Arc<Kernel>,
    fixture: &Fixture,
    grants: Arc<Mutex<Vec<SignedRecordV1<gawdfn::ExecutionGrantV1>>>>,
    calls: Arc<Mutex<Vec<FunctionCallV1>>>,
) -> aether::CreatureId {
    let liveness = Arc::new(KernelLiveness(Arc::downgrade(kernel)));
    let id = kernel
        .load_instance(
            boot_manifest("function-executor"),
            Box::new(CapturingExecutor { inner: fixture.open_executor(liveness), grants, calls }),
        )
        .expect("executor loads");
    kernel.bind_role(Role::new(FUNCTION_EXECUTOR_ROLE), id);
    id
}

fn load_home(kernel: &Kernel, fixture: &Fixture) -> aether::CreatureId {
    let id = kernel
        .load_instance(boot_manifest("function-home"), Box::new(fixture.open_home()))
        .expect("home loads");
    kernel.bind_role(Role::new(FUNCTION_HOME_ROLE), id);
    id
}

#[test]
fn deployment_liveness_rejects_artifact_mismatch_and_reused_id_with_wrong_manifest() {
    let fixture = Fixture::new();
    let first = kernel();
    let target = load_target(&first, &fixture);
    let receipt = DeploymentReceiptV1 {
        deployment: derive_deployment_id(
            &fixture.function,
            &format!("sha256:{}", fixture.artifact_hash_raw),
            "local",
            "local",
            &target.0.to_string(),
        )
        .unwrap(),
        function: fixture.function.clone(),
        artifact_hash: format!("sha256:{}", fixture.artifact_hash_raw),
        realm: "local".into(),
        node: "local".into(),
        executor: fixture.executor.public_key().to_string(),
        executor_creature: "2".into(),
        creature: target.0.to_string(),
        evidence: vec![],
        registered_at_unix_ms: None,
    };
    let first_liveness = KernelLiveness(Arc::downgrade(&first));
    assert!(first_liveness.target_is_live(target, &receipt).unwrap());

    let mut artifact_mismatch = receipt.clone();
    artifact_mismatch.artifact_hash = format!("sha256:{}", "c".repeat(64));
    assert!(!first_liveness.target_is_live(target, &artifact_mismatch).unwrap());

    first.shutdown_all(Deadline::from_millis(500));
    drop(first_liveness);
    drop(first);

    // A fresh Kernel reuses its first process-local id. Even when the artifact build hash is the
    // same, a different manifest identity must not satisfy the durable deployment receipt.
    let second = kernel();
    let mut wrong_manifest = boot_manifest("different-function-at-reused-id");
    wrong_manifest.provenance.build_hash = Some(fixture.artifact_hash_raw.clone());
    wrong_manifest.content_address = Some(wrong_manifest.compute_content_address());
    wrong_manifest.validate().unwrap();
    let reused = second.load_instance(wrong_manifest, Box::new(Noop)).unwrap();
    assert_eq!(reused, target, "fresh Kernels reuse process-local CreatureIds");
    let second_liveness = KernelLiveness(Arc::downgrade(&second));
    assert!(!second_liveness.target_is_live(reused, &receipt).unwrap());
    second.shutdown_all(Deadline::from_millis(500));
}

fn read_snapshot(
    fixture: &Fixture,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    handle: &JobHandleV1,
    corr: u64,
) -> SignedRecordV1<JobSnapshotV1> {
    let caller = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetV1 { handle: handle.clone(), nonce: format!("read-{corr}") },
        fixture.abode.as_ref(),
    )
    .expect("signed read");
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetRelayV1 {
            caller,
            reply_to: serde_json::to_string(&Address::Creature(bus.id()))
                .expect("canonical read reply route"),
        },
        fixture.abode.as_ref(),
    )
    .expect("caller-bound read relay");
    let env = send_rpc(
        bus,
        rx,
        corr,
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &JobMessageV1::Get { request: Box::new(request.clone()) },
    );
    match serde_json::from_slice::<JobMessageV1>(&env.payload).expect("job reply") {
        JobMessageV1::Snapshot { response } => {
            gawdfn::verify_job_snapshot_response_for(&response, &request)
                .expect("snapshot binds the exact signed read and return route");
            *response.payload.snapshot
        }
        other => panic!("expected job snapshot, got {other:?}"),
    }
}

fn wait_for_success(
    fixture: &Fixture,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    handle: &JobHandleV1,
    next_corr: &mut u64,
) -> SignedRecordV1<JobSnapshotV1> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let snapshot = read_snapshot(fixture, bus, rx, handle, *next_corr);
        *next_corr += 1;
        if snapshot.payload.state == JobStateV1::Succeeded {
            return snapshot;
        }
        assert!(
            !snapshot.payload.state.is_terminal(),
            "job terminated unexpectedly as {:?}",
            snapshot.payload.state
        );
        assert!(Instant::now() < deadline, "job did not reach Succeeded");
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_events(
    fixture: &Fixture,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    handle: &JobHandleV1,
    corr: u64,
) -> EventPageV1 {
    let caller = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EventQueryV1 {
            handle: handle.clone(),
            after_sequence: None,
            limit: 64,
            nonce: format!("events-{corr}"),
        },
        fixture.abode.as_ref(),
    )
    .expect("signed event query");
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EventQueryRelayV1 {
            caller,
            reply_to: serde_json::to_string(&Address::Creature(bus.id()))
                .expect("canonical event reply route"),
        },
        fixture.abode.as_ref(),
    )
    .expect("caller-bound event relay");
    let env = send_rpc(
        bus,
        rx,
        corr,
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &JobMessageV1::Events { request: Box::new(request.clone()) },
    );
    match serde_json::from_slice::<JobMessageV1>(&env.payload).expect("event reply") {
        JobMessageV1::EventPage { response } => {
            gawdfn::verify_event_page_response_for(&response, &request)
                .expect("event page binds the exact signed query and return route");
            response.payload.page
        }
        other => panic!("expected event page, got {other:?}"),
    }
}

fn lookup_deployment(
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    function: &FunctionId,
    corr: u64,
) -> DeploymentListV1 {
    let env = send_rpc(
        bus,
        rx,
        corr,
        role(FUNCTION_EXECUTOR_ROLE),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &FunctionDeployMessageV1::Lookup {
            query: DeploymentQueryV1 {
                function: Some(function.clone()),
                realm: Some("local".into()),
                node: Some("local".into()),
                limit: 8,
            },
        },
    );
    match serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
        .expect("deployment lookup reply")
    {
        FunctionDeployMessageV1::Deployments { list } => list,
        other => panic!("expected deployment list, got {other:?}"),
    }
}

#[test]
fn home_replays_grant_to_current_executor_role_after_creature_id_changes() {
    let fixture = Fixture::new();
    let first = kernel();
    let captured_grants = Arc::new(Mutex::new(Vec::new()));
    let captured_calls = Arc::new(Mutex::new(Vec::new()));

    let target_id = load_target(&first, &fixture);
    assert_eq!(target_id, CreatureId(1));
    let old_executor = first
        .load_instance(
            boot_manifest("function-executor"),
            Box::new(CapturingExecutor {
                inner: fixture.open_executor(Arc::new(KernelLiveness(Arc::downgrade(&first)))),
                grants: captured_grants.clone(),
                calls: captured_calls.clone(),
            }),
        )
        .expect("original executor loads without occupying its role");
    assert_eq!(old_executor, CreatureId(2));
    let (_first_probe, first_bus, first_rx) = first.open_endpoint(Capabilities::default());

    let selector = FunctionSelectorV1::Alias { alias: fixture.alias.clone() };
    let resolution = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        ResolutionReceiptV1 {
            selector: selector.clone(),
            function: fixture.function.clone(),
            artifact_hash: format!("sha256:{}", fixture.artifact_hash_raw),
            resolved_at_unix_ms: None,
            evidence: vec![],
        },
        fixture.resolver.as_ref(),
    )
    .expect("resolver-signed exact function pin");
    let deployment_authorization = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRequestV1 {
            requested_by: fixture.home.clone(),
            function: selector.clone(),
            target_realm: "local".into(),
            target_node: Some("local".into()),
            evidence: vec![],
            requested_at_unix_ms: None,
        },
        fixture.abode.as_ref(),
    )
    .expect("deployment authorization");
    let deployment_id = derive_deployment_id(
        &fixture.function,
        &resolution.payload.artifact_hash,
        "local",
        "local",
        &target_id.0.to_string(),
    )
    .expect("deterministic deployment id");
    let registration = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRegistrationV1 {
            authorization: deployment_authorization,
            resolution: resolution.clone(),
            deployment: deployment_id,
            function: fixture.function.clone(),
            artifact_hash: resolution.payload.artifact_hash.clone(),
            target_creature: target_id.0.to_string(),
            evidence: vec![],
        },
        fixture.abode.as_ref(),
    )
    .expect("signed deployment registration");
    let registered = send_rpc(
        &first_bus,
        &first_rx,
        1,
        Address::Creature(old_executor),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &FunctionDeployMessageV1::Register { request: Box::new(registration) },
    );
    let deployment = match serde_json::from_slice::<FunctionDeployMessageV1>(&registered.payload)
        .expect("deployment response")
    {
        FunctionDeployMessageV1::Registered { receipt } => receipt,
        other => panic!("expected registered deployment, got {other:?}"),
    };
    assert_eq!(deployment.payload.executor_creature, old_executor.0.to_string());

    // Retire the process-local route without tombstoning the durable deployment. A supervisor may
    // restart the stable executor organ; its stable signing key and journal, not this number, are
    // the authority continuity proof.
    first.unload(old_executor, Deadline::from_millis(500)).expect("old executor unloads");
    assert!(!first.router().is_registered(old_executor));

    let policy_id = first
        .load_instance(
            boot_manifest("policy-job-basic"),
            Box::new(
                BasicJobPolicy::new(fixture.policy.clone(), BasicPolicyCaps::default())
                    .expect("policy config"),
            ),
        )
        .expect("policy loads");
    assert_eq!(policy_id, CreatureId(4), "the endpoint deliberately occupies id 3");
    first.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy_id);
    let home_id = load_home(&first, &fixture);
    assert_eq!(home_id, CreatureId(5));

    let submit = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSubmitV1 {
            home: fixture.home.clone(),
            caller_idempotency_key: "lost-first-grant".into(),
            function: selector,
            input: ValueRefV1::Inline { value: json!({ "value": 41 }) },
            delivery: DeliveryModeV1::AtMostOnce,
            allow_duplicate_effects: false,
            parent: None,
            causal: vec![],
            access: JobAccessV1::default(),
            evidence: vec![],
            result_recipients: vec![],
            submitted_at_unix_ms: None,
        },
        fixture.abode.as_ref(),
    )
    .expect("owner-signed job");
    let accepted = send_rpc(
        &first_bus,
        &first_rx,
        2,
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &JobMessageV1::Submit {
            request: Box::new(submit),
            resolution: Box::new(resolution),
            deployment: Box::new(deployment.clone()),
        },
    );
    let handle = match serde_json::from_slice::<JobMessageV1>(&accepted.payload)
        .expect("accepted response")
    {
        JobMessageV1::Accepted { handle, .. } => handle,
        other => panic!("expected Accepted, got {other:?}"),
    };

    let deadline = Instant::now() + Duration::from_secs(3);
    let mut corr = 10;
    loop {
        let snapshot = read_snapshot(&fixture, &first_bus, &first_rx, &handle, corr);
        corr += 1;
        if snapshot.payload.state == JobStateV1::Dispatching {
            break;
        }
        assert_eq!(snapshot.payload.state, JobStateV1::Queued);
        assert!(Instant::now() < deadline, "policy did not durably issue the first grant");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(captured_grants.lock().unwrap().is_empty(), "unbound stale id saw no grant");
    assert!(first
        .router()
        .journal_snapshot()
        .iter()
        .all(|env| env.to != Address::Creature(target_id)));

    first.shutdown_all(Deadline::from_millis(500));
    drop(first_bus);
    drop(first_rx);
    drop(first);

    // Preserve the target's exact deployment id, deliberately occupy the old executor id with a
    // different creature, then recover the same stable executor at a new route. Loading Home last
    // causes its bind-time recovery to replay the exact durable grant through the current role.
    let restarted = kernel();
    let restarted_target = load_target(&restarted, &fixture);
    assert_eq!(restarted_target, target_id);
    let stale_id_occupant = restarted
        .load_instance(boot_manifest("unrelated-at-stale-executor-id"), Box::new(Noop))
        .expect("dummy load perturbs executor id");
    assert_eq!(stale_id_occupant, old_executor);
    let current_executor =
        load_executor(&restarted, &fixture, captured_grants.clone(), captured_calls.clone());
    assert_ne!(current_executor, old_executor);
    let (_probe, bus, rx) = restarted.open_endpoint(Capabilities::default());
    let restarted_home = load_home(&restarted, &fixture);
    assert_eq!(restarted_home, home_id, "Home callback route remains stable in this proof");

    let mut next_corr = 100;
    let succeeded = wait_for_success(&fixture, &bus, &rx, &handle, &mut next_corr);
    assert_eq!(
        succeeded.payload.result,
        Some(ValueRefV1::Inline { value: json!({ "answer": 42 }) })
    );
    let journal = restarted.router().journal_snapshot();
    journal
        .iter()
        .find(|env| {
            env.from == Address::Creature(current_executor)
                && env.to == Address::Creature(restarted_target)
        })
        .expect("replayed grant reached the current role and crossed the typed call boundary");
    let call = captured_calls
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .first()
        .cloned()
        .expect("executor witness captured the typed call wire");
    call.validate().expect("typed target authority chain validates");
    gawdfn::verify_executor_dispatch(&call.executor_dispatch, &call.grant)
        .expect("current executor route is stable-key signed and grant-bound");
    assert_eq!(call.grant.payload.deployment.payload.executor_creature, old_executor.0.to_string());
    assert_eq!(call.executor_dispatch.payload.executor_creature, current_executor.0.to_string());
    assert_eq!(call.executor_dispatch.signer, fixture.executor.public_key());
    assert_eq!(call.executor_dispatch.payload.target_creature, target_id.0.to_string());
    assert_eq!(
        captured_grants.lock().unwrap().len(),
        1,
        "the current role receives one bind-time exact grant replay"
    );

    restarted.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn typed_job_is_accepted_dispatched_completed_and_deduplicated_across_restart() {
    let fixture = Fixture::new();
    let node = kernel();
    let captured_grants = Arc::new(Mutex::new(Vec::new()));
    let captured_calls = Arc::new(Mutex::new(Vec::new()));

    let target_id = load_target(&node, &fixture);
    let executor_id =
        load_executor(&node, &fixture, captured_grants.clone(), captured_calls.clone());
    let home_id = load_home(&node, &fixture);
    let resolver_id = node
        .load_instance(
            boot_manifest("function-resolver"),
            Box::new(FunctionResolver::new(fixture.resolver.clone(), Arc::new(catalog(&fixture)))),
        )
        .expect("resolver loads");
    node.bind_role(Role::new(FUNCTION_RESOLVER_ROLE), resolver_id);
    let policy_id = node
        .load_instance(
            boot_manifest("policy-job-basic"),
            Box::new(
                BasicJobPolicy::new(fixture.policy.clone(), BasicPolicyCaps::default())
                    .expect("policy config"),
            ),
        )
        .expect("job policy loads");
    node.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy_id);
    let (probe_id, bus, rx) = node.open_endpoint(Capabilities::default());

    let selector = FunctionSelectorV1::Alias { alias: fixture.alias.clone() };
    let resolve_request = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        ResolveRequestV1 {
            requested_by: fixture.home.clone(),
            selector: selector.clone(),
            evidence: vec![],
        },
        fixture.abode.as_ref(),
    )
    .expect("signed resolve request");
    let resolved_env = send_rpc(
        &bus,
        &rx,
        1,
        role(FUNCTION_RESOLVER_ROLE),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &FunctionDeployMessageV1::Resolve { request: resolve_request },
    );
    let resolution = match serde_json::from_slice::<FunctionDeployMessageV1>(&resolved_env.payload)
        .expect("resolver reply")
    {
        FunctionDeployMessageV1::Resolved { receipt } => receipt,
        other => panic!("expected resolution, got {other:?}"),
    };
    assert!(resolution.verify());
    assert_eq!(resolution.signer, fixture.resolver.public_key());
    assert_eq!(resolution.payload.function, fixture.function);

    // The target is already loaded through Kernel admission. The deployer now binds the signed
    // resolution's exact manifest/artifact claim and the live CreatureId into the durable registry.
    let deployment_authorization = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRequestV1 {
            requested_by: fixture.home.clone(),
            function: selector.clone(),
            target_realm: "local".into(),
            target_node: Some("local".into()),
            evidence: vec![],
            requested_at_unix_ms: None,
        },
        fixture.abode.as_ref(),
    )
    .expect("signed deployment authorization");
    let registration = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRegistrationV1 {
            authorization: deployment_authorization,
            resolution: resolution.clone(),
            deployment: derive_deployment_id(
                &fixture.function,
                &resolution.payload.artifact_hash,
                "local",
                "local",
                &target_id.0.to_string(),
            )
            .expect("deterministic deployment identity"),
            function: fixture.function.clone(),
            artifact_hash: resolution.payload.artifact_hash.clone(),
            target_creature: target_id.0.to_string(),
            evidence: vec![],
        },
        fixture.abode.as_ref(),
    )
    .expect("signed registration");
    let deployed_env = send_rpc(
        &bus,
        &rx,
        2,
        role(FUNCTION_EXECUTOR_ROLE),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &FunctionDeployMessageV1::Register { request: Box::new(registration) },
    );
    let deployment = match serde_json::from_slice::<FunctionDeployMessageV1>(&deployed_env.payload)
        .expect("registration reply")
    {
        FunctionDeployMessageV1::Registered { receipt } => receipt,
        other => panic!("expected registered deployment, got {other:?}"),
    };
    gawdfn::verify_deployment_receipt(&deployment).expect("executor-bound deployment receipt");
    assert_eq!(deployment.payload.creature, target_id.0.to_string());
    assert_eq!(deployment.payload.executor_creature, executor_id.0.to_string());
    assert_eq!(
        lookup_deployment(&bus, &rx, &fixture.function, 3).deployments,
        vec![deployment.clone()]
    );

    let submit = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSubmitV1 {
            home: fixture.home.clone(),
            caller_idempotency_key: "one-logical-call".into(),
            function: selector,
            input: ValueRefV1::Inline { value: json!({ "value": 41 }) },
            delivery: DeliveryModeV1::AtMostOnce,
            allow_duplicate_effects: false,
            parent: None,
            causal: vec![],
            access: JobAccessV1::default(),
            evidence: vec![],
            result_recipients: vec![],
            submitted_at_unix_ms: None,
        },
        fixture.abode.as_ref(),
    )
    .expect("owner-signed submit");
    let submit_message = JobMessageV1::Submit {
        request: Box::new(submit),
        resolution: Box::new(resolution),
        deployment: Box::new(deployment.clone()),
    };

    // Home durably accepts first, then consults the injected policy. No test code calls
    // issue_grant/claim/call/result: every later transition is an asynchronous bus dispatch.
    let accepted_env =
        send_rpc(&bus, &rx, 4, role(FUNCTION_HOME_ROLE), SCHEMA_JOB_V1, &submit_message);
    let (handle, request_hash, submitted) = match serde_json::from_slice::<JobMessageV1>(
        &accepted_env.payload,
    )
    .expect("accepted reply")
    {
        JobMessageV1::Accepted { handle, request_hash, submitted } => {
            (handle, request_hash, submitted)
        }
        other => panic!("expected Accepted, got {other:?}"),
    };
    assert_eq!(request_hash.len(), "sha256:".len() + 64);
    gawdfn::verify_job_acceptance(&handle, &request_hash, &submitted)
        .expect("Accepted carries the exact fsynced, root-authorized Submitted event");

    // Redelivery of the exact signed Submit is the same logical job. Depending on scheduling this
    // may also redeliver the same placement/grant; executor claim dedup must still protect target.
    let duplicate_env =
        send_rpc(&bus, &rx, 5, role(FUNCTION_HOME_ROLE), SCHEMA_JOB_V1, &submit_message);
    match serde_json::from_slice::<JobMessageV1>(&duplicate_env.payload).expect("duplicate reply") {
        JobMessageV1::Accepted {
            handle: duplicate,
            request_hash: duplicate_hash,
            submitted: duplicate_submitted,
        } => {
            assert_eq!(duplicate, handle);
            assert_eq!(duplicate_hash, request_hash);
            assert_eq!(duplicate_submitted, submitted);
            gawdfn::verify_job_acceptance(&duplicate, &duplicate_hash, &duplicate_submitted)
                .expect("duplicate returns the same acceptance proof");
        }
        other => panic!("duplicate submit was not idempotently accepted: {other:?}"),
    }

    let mut next_corr = 10;
    let succeeded = wait_for_success(&fixture, &bus, &rx, &handle, &mut next_corr);
    gawdfn::verify_job_snapshot(&succeeded).expect("snapshot chains to the Abode root");
    assert_eq!(succeeded.signer, fixture.operational.public_key());
    assert_eq!(
        succeeded.payload.result,
        Some(ValueRefV1::Inline { value: json!({ "answer": 42 }) })
    );

    let events = read_events(&fixture, &bus, &rx, &handle, next_corr);
    events.validate().expect("bounded signed event page");
    for event in &events.events {
        gawdfn::verify_job_event(event).expect("event chains to the Abode root");
    }
    assert_eq!(events.events.first(), Some(submitted.as_ref()));
    assert_eq!(events.events.first().map(|event| event.payload.sequence), Some(1));
    assert!(matches!(
        events.events.first().map(|event| &event.payload.kind),
        Some(gawdfn::JobEventKindV1::Submitted { .. })
    ));
    assert!(events
        .events
        .iter()
        .any(|event| matches!(event.payload.kind, gawdfn::JobEventKindV1::DispatchGranted { .. })));
    assert!(events
        .events
        .iter()
        .any(|event| matches!(event.payload.kind, gawdfn::JobEventKindV1::Claimed { .. })));
    assert!(events
        .events
        .iter()
        .any(|event| matches!(event.payload.kind, gawdfn::JobEventKindV1::Started { .. })));
    let terminal_event = events.events.last().expect("terminal event");
    assert!(matches!(terminal_event.payload.kind, gawdfn::JobEventKindV1::Succeeded { .. }));
    assert_eq!(terminal_event.payload.state_after, JobStateV1::Succeeded);

    // The bus journal gives an independent causal tripwire: Accepted was routed before a typed
    // call and before the executor's terminal receipt, even though different drain threads run.
    let journal = node.router().journal_snapshot();
    let accepted_stamp = journal
        .iter()
        .find(|env| {
            env.from == Address::Creature(home_id)
                && env.to == Address::Creature(probe_id)
                && env.corr == Some(4)
        })
        .map(|env| env.stamp)
        .expect("Accepted is observable in the kernel journal");
    let call_stamp = journal
        .iter()
        .find(|env| {
            env.from == Address::Creature(executor_id) && env.to == Address::Creature(target_id)
        })
        .map(|env| env.stamp)
        .expect("typed call is observable in the kernel journal");
    assert_eq!(
        journal
            .iter()
            .filter(|env| {
                env.from == Address::Creature(executor_id) && env.to == Address::Creature(target_id)
            })
            .count(),
        1,
        "one logical Submit crosses the critter effect boundary once"
    );
    let grant = captured_grants
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .first()
        .cloned()
        .expect("Home emitted a signed execution grant");
    assert!(accepted_stamp < call_stamp, "Accepted must precede execution in bus order");
    gawdfn::verify_execution_grant(&grant).expect("captured grant is authority-bound");
    assert_eq!(grant.payload.request_hash, request_hash);
    assert_eq!(grant.payload.attempt.job, handle.job);
    assert_eq!(grant.payload.deployment, deployment);
    gawdfn::verify_job_event_with_grant(terminal_event, &grant)
        .expect("terminal Home event preserves the exact executor-signed receipt and grant hash");
    let terminal_receipt = terminal_event
        .payload
        .foreign_receipt
        .as_deref()
        .expect("receipt-derived terminal event exposes foreign provenance");
    assert_eq!(terminal_receipt.signer, fixture.executor.public_key());
    assert_eq!(
        terminal_receipt.payload.attempt, grant.payload.attempt,
        "the Rhai target copied the executor's dynamic AttemptId into FunctionResultV1"
    );
    assert!(matches!(terminal_receipt.payload.stage, ExecutionStageV1::Succeeded { .. }));

    node.shutdown_all(Deadline::from_millis(500));
    drop(bus);
    drop(rx);
    drop(node);

    // Rebuild a fresh Kernel over the same durable Home + executor roots. The registry and signed
    // terminal ledger recover; replaying the captured grant returns the existing terminal receipt
    // and never emits another gawd.function.call.v1 invocation.
    let restarted = kernel();
    let restarted_target = load_target(&restarted, &fixture);
    assert_eq!(restarted_target.0.to_string(), deployment.payload.creature);
    let restarted_executor =
        load_executor(&restarted, &fixture, captured_grants.clone(), captured_calls.clone());
    assert_eq!(restarted_executor, executor_id);
    let _restarted_home = load_home(&restarted, &fixture);
    let (_probe, restarted_bus, restarted_rx) = restarted.open_endpoint(Capabilities::default());

    let durable = lookup_deployment(&restarted_bus, &restarted_rx, &fixture.function, 100);
    assert_eq!(durable.deployments, vec![deployment]);
    let recovered = read_snapshot(&fixture, &restarted_bus, &restarted_rx, &handle, 101);
    gawdfn::verify_job_snapshot(&recovered).expect("recovered snapshot keeps its authority proof");
    assert_eq!(recovered.payload.state, JobStateV1::Succeeded);
    assert_eq!(recovered.payload.last_sequence, terminal_event.payload.sequence);

    let calls_before = captured_calls.lock().unwrap().len();
    restarted_bus
        .send(
            Dispatch::to(
                role(FUNCTION_EXECUTOR_ROLE),
                aether::wire::to_bytes(&ExecuteMessageV1::Grant { grant: Box::new(grant.clone()) }),
            )
            .with_schema(SCHEMA_EXECUTE_V1),
        )
        .expect("duplicate grant routes to current executor role");
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        captured_calls.lock().unwrap().len(),
        calls_before,
        "deduplicated terminal grant emits no typed call"
    );
    assert_eq!(
        restarted
            .router()
            .journal_snapshot()
            .iter()
            .filter(|env| {
                env.from == Address::Creature(restarted_executor)
                    && env.to == Address::Creature(restarted_target)
            })
            .count(),
        0,
        "restart + grant replay must not cross the function effect boundary again"
    );

    restarted.shutdown_all(Deadline::from_millis(500));
}
