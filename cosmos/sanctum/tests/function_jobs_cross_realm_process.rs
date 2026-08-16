//! Cross-Realm Function execution, Home movement, and recovery across real OS processes.
//!
//! The parent test self-spawns this integration-test binary twice: node A owns the source Home,
//! injected Job policy, and GX source, while node B owns the blocking typed parent target, a real
//! signed-artifact `typed-add-one` Rhai critter, the executor, and custody destination. A explicitly
//! registers both deployments through B's durable executor. A real submitted parent Job reaches B
//! through the changed-ID executor's `NodeRole`; its target remains running while custody is
//! Prepared and Staged. Application messages cross authenticated `transport-tcp` and
//! `omega-federator`; checkpoint and referenced dependency bytes cross only the raw
//! `transport.gx.chunk` lane. A one-shot drop and one-shot payload corruption leave exact gaps which
//! B re-requests before committing the verified bytes to its distinct durable store.
//!
//! The full lifecycle path also preserves an executor-authenticated Progress event byte-for-byte
//! across movement, sends the same root-signed causal child proposal twice from A over Omega/TCP,
//! and proves one inherited child ledger, one measured-artifact critter invocation, and one terminal
//! proof. A cross-Realm Steer is durably queued while the parent is blocked and receives the
//! target's honest `TooLate` outcome after release.
//!
//! Crash cuts are deliberately placed only after a durable deployment registration and after a
//! durable custody Stage plus executor receipt. The receipt's push is suppressed, both processes
//! are hard-killed, and the activated moved Home recovers that exact proof by querying the reopened
//! executor without executing the target twice. This proves hard process restart at committed
//! protocol boundaries. It does **not** claim crash-resume inside an in-progress GX transfer:
//! `ChunkAssembler` retains its gap bitmap in memory, so persistent mid-transfer resume remains a
//! separate product seam.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aether::{
    Address, BusHandle, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Ed25519Signer,
    Envelope, InboxReceiver, NodeId, Outcome, RealmId, Role,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine, CRITTER_ABI_TAG};
use function_executor::{
    DeploymentAdmission, DeploymentLiveness, ExecutorConfig, FunctionExecutor, StringAddressing,
};
use function_home::{
    FunctionHome, FunctionMetadata, FunctionTrust, HomeConfig, HomeCustodyDestination,
};
use gawdfn::{
    canonical_hash, derive_deployment_id, verify_custody_staged, verify_deployment_receipt,
    verify_event_page_response_for, verify_execution_receipt, verify_home_custody_status,
    verify_home_lease, verify_job_acceptance, verify_job_control_acceptance, verify_job_event,
    verify_job_event_with_grant, verify_job_snapshot_response_for, AbodeKeyBindingV1,
    AuthoritySigner, BlobAvailability, BlobRefV1, CheckpointBlobStore, ControlDispositionV1,
    ControlId, CustodyGrantV1, CustodyPreparedV1, CustodyStagedV1, DeliveryModeV1,
    DeploymentQueryV1, DeploymentReceiptV1, DeploymentRegistrationV1, DeploymentRequestV1,
    Ed25519SeedSigner, EffectClassV1, EntrypointContractV1, EventPageV1, EventQueryRelayV1,
    EventQueryV1, ExecuteMessageV1, ExecutionGrantV1, ExecutionReceiptV1, ExecutionStageV1,
    FunctionAlias, FunctionCallMessageV1, FunctionDeployMessageV1, FunctionId, FunctionResultV1,
    FunctionSelectorV1, HandoffId, HomeAuthorityV1, HomeCheckpointV1, HomeCustodyPhaseV1,
    HomeCustodyStatusV1, HomeId, HomeMessageV1, JobAccessV1, JobControlKindV1, JobControlV1,
    JobEventKindV1, JobGetRelayV1, JobGetV1, JobHandleV1, JobMessageV1, JobSnapshotV1, JobStateV1,
    JobSubmitV1, OperationalCapabilityV1, OperationalKeyGrantV1, PlacementDecisionV1,
    ResolutionReceiptV1, ResolvedFunctionV1, RetryDecisionV1, SchemaRefV1, SignedRecordV1,
    UndeployRequestV1, ValueRefV1, FUNCTION_EXECUTOR_ROLE, FUNCTION_POLICY_ROLE, SCHEMA_CALL_V1,
    SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1, SCHEMA_JOB_V1,
};
use job_blob_fs::{BlobCaps, FsJobBlobStore};
use omega_federator::{FederatorConfig, OmegaFederator};
use policy_job_basic::{BasicJobPolicy, BasicPolicyCaps};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Entrypoint, Manifest};
use transport_tcp::{PeerConfig, TransportConfig, TransportTcp};

const NODE_A: &str = "function-process-origin-A";
const NODE_B: &str = "function-process-compute-B";
const REALM_A: &str = "process-origin";
const REALM_B: &str = "process-compute";
const CONTROL_PREFIX: &str = "@@gawd-process-control@@";
const MAX_CONTROL_BYTES: usize = 1024 * 1024;
const CONTROL_TIMEOUT: Duration = Duration::from_secs(15);
const RPC_TIMEOUT: Duration = Duration::from_secs(8);
const PING_SCHEMA: &str = "test.function-process.ping.v1";
const GX_CONTROL_SCHEMA: &str = "test.function-process.gx.v1";
const CHECKPOINT_CHUNK_SIZE: u32 = gawdxfer::MIN_CHUNK_SIZE;
const GX_WINDOW: usize = 8;
const TYPED_ADD_ONE_SOURCE: &[u8] =
    include_bytes!("../../creatures/prototypes/critters/typed-add-one/typed-add-one.rhai");

const NODE_A_SEED: [u8; 32] = [0x71; 32];
const NODE_B_SEED: [u8; 32] = [0x72; 32];
const ROOT_SEED: [u8; 32] = [0x73; 32];
const SOURCE_SEED: [u8; 32] = [0x74; 32];
const DESTINATION_SEED: [u8; 32] = [0x75; 32];
const RESOLVER_SEED: [u8; 32] = [0x76; 32];
const EXECUTOR_SEED: [u8; 32] = [0x77; 32];
const POLICY_SEED: [u8; 32] = [0x78; 32];

fn slow_factor() -> u32 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .filter(|value| *value >= 1)
        .unwrap_or(1)
}

fn scaled(duration: Duration) -> Duration {
    duration * slow_factor()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PublicFixture {
    node_a_public: String,
    node_b_public: String,
    root_public: String,
    resolver_public: String,
    executor_public: String,
    policy_public: String,
    home: HomeId,
    source_authority: HomeAuthorityV1,
    destination_authority: HomeAuthorityV1,
    alias: FunctionAlias,
    function: FunctionId,
    artifact_hash: String,
    target_manifest: Manifest,
    typed_alias: FunctionAlias,
    typed_function: FunctionId,
    typed_artifact_hash: String,
    typed_target_manifest: Manifest,
    job_input: BlobRefV1,
}

impl PublicFixture {
    fn create() -> Self {
        let node_a = Ed25519KeyMaterial::from_seed(NODE_A_SEED).expect("node A key");
        let node_b = Ed25519KeyMaterial::from_seed(NODE_B_SEED).expect("node B key");
        let root = Ed25519SeedSigner::from_seed(ROOT_SEED).expect("root key");
        let source = Ed25519SeedSigner::from_seed(SOURCE_SEED).expect("source key");
        let destination = Ed25519SeedSigner::from_seed(DESTINATION_SEED).expect("destination key");
        let resolver = Ed25519SeedSigner::from_seed(RESOLVER_SEED).expect("resolver key");
        let executor = Ed25519SeedSigner::from_seed(EXECUTOR_SEED).expect("executor key");
        let policy = Ed25519SeedSigner::from_seed(POLICY_SEED).expect("policy key");
        let home = HomeId::new(root.public_key());
        let source_authority = authority(&root, &source, &home, 1);
        let destination_authority = authority(&root, &destination, &home, 2);

        let artifact_raw = "e".repeat(64);
        let artifact_hash = format!("sha256:{artifact_raw}");
        let alias = FunctionAlias {
            realm: REALM_B.into(),
            name: "process-blocking-add-one".into(),
            version: "0.1.0".into(),
            entrypoint: "run".into(),
        };
        let mut target_manifest =
            Manifest::new("process-blocking-add-one", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        target_manifest.provenance.author = Some(node_b.public_hex().to_string());
        target_manifest.provenance.build_hash = Some(artifact_raw);
        target_manifest.entrypoints.push(Entrypoint {
            name: "run".into(),
            signature: SCHEMA_CALL_V1.into(),
            contract: Some(EntrypointContractV1 {
                description: "Blocking target used to prove running custody overlap".into(),
                input_schema: SchemaRefV1::Inline { schema: json!({"type":"object"}) },
                output_schema: SchemaRefV1::Inline { schema: json!({"type":"object"}) },
                error_schema: None,
                effect: EffectClassV1::Idempotent,
                controls: Default::default(),
            }),
        });
        let manifest_content_address = target_manifest.compute_content_address();
        target_manifest.content_address = Some(manifest_content_address.clone());
        target_manifest.provenance.signature =
            Some(node_b.sign(&target_manifest.signing_payload()));
        target_manifest.validate().expect("target manifest");

        let typed_artifact_hash = gawdfn::sha256_digest(TYPED_ADD_ONE_SOURCE);
        let typed_artifact_hash_raw = typed_artifact_hash
            .strip_prefix("sha256:")
            .expect("typed critter digest is canonically prefixed")
            .to_string();
        let typed_alias = FunctionAlias {
            realm: REALM_B.into(),
            name: "typed-add-one".into(),
            version: "0.1.0".into(),
            entrypoint: "add_one".into(),
        };
        let mut typed_target_manifest =
            Manifest::new("typed-add-one", "0.1.0", Backend::Critter, CRITTER_ABI_TAG);
        typed_target_manifest.provenance.author = Some(node_b.public_hex().to_string());
        typed_target_manifest.provenance.build_hash = Some(typed_artifact_hash_raw);
        typed_target_manifest.entrypoints.push(Entrypoint {
            name: "add_one".into(),
            signature: SCHEMA_CALL_V1.into(),
            contract: Some(EntrypointContractV1 {
                description: "Add one to an integer through the real Rhai critter tier".into(),
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
        let typed_manifest_content_address = typed_target_manifest.compute_content_address();
        typed_target_manifest.content_address = Some(typed_manifest_content_address.clone());
        typed_target_manifest.provenance.signature =
            Some(node_b.sign(&typed_target_manifest.signing_payload()));
        typed_target_manifest.validate().expect("typed critter manifest");
        let typed_function = FunctionId {
            manifest_content_address: typed_manifest_content_address,
            entrypoint: "add_one".into(),
        };
        let dependency_bytes = vec![0x5a; 24 * 1024];
        let job_input = BlobRefV1 {
            digest: format!("sha256:{}", gawdxfer::hash_bytes(&dependency_bytes)),
            size: dependency_bytes.len() as u64,
            media_type: "application/vnd.gawd.process-dependency".into(),
        };

        Self {
            node_a_public: node_a.public_hex().to_string(),
            node_b_public: node_b.public_hex().to_string(),
            root_public: root.public_key().into(),
            resolver_public: resolver.public_key().into(),
            executor_public: executor.public_key().into(),
            policy_public: policy.public_key().into(),
            home,
            source_authority,
            destination_authority,
            alias,
            function: FunctionId { manifest_content_address, entrypoint: "run".into() },
            artifact_hash,
            target_manifest,
            typed_alias,
            typed_function,
            typed_artifact_hash,
            typed_target_manifest,
            job_input,
        }
    }

    fn load(root: &Path) -> Result<Self, String> {
        let bytes =
            fs::read(root.join("fixture-public.json")).map_err(|error| error.to_string())?;
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }

    fn trust(&self) -> Arc<dyn FunctionTrust> {
        Arc::new(PinnedTrust {
            resolver: self.resolver_public.clone(),
            executor: self.executor_public.clone(),
            policy: self.policy_public.clone(),
        })
    }

    fn resolution(&self) -> SignedRecordV1<ResolutionReceiptV1> {
        let resolver = Ed25519SeedSigner::from_seed(RESOLVER_SEED).expect("resolver key");
        SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            ResolutionReceiptV1 {
                selector: FunctionSelectorV1::Alias { alias: self.alias.clone() },
                function: self.function.clone(),
                artifact_hash: self.artifact_hash.clone(),
                resolved_at_unix_ms: None,
                evidence: vec![],
            },
            &resolver,
        )
        .expect("resolution fixture")
    }

    fn typed_resolution(&self) -> SignedRecordV1<ResolutionReceiptV1> {
        let resolver = Ed25519SeedSigner::from_seed(RESOLVER_SEED).expect("resolver key");
        SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            ResolutionReceiptV1 {
                selector: FunctionSelectorV1::Alias { alias: self.typed_alias.clone() },
                function: self.typed_function.clone(),
                artifact_hash: self.typed_artifact_hash.clone(),
                resolved_at_unix_ms: None,
                evidence: vec![],
            },
            &resolver,
        )
        .expect("typed resolution fixture")
    }
}

fn authority(
    root: &Ed25519SeedSigner,
    operational: &Ed25519SeedSigner,
    home: &HomeId,
    epoch: u64,
) -> HomeAuthorityV1 {
    let abode = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        AbodeKeyBindingV1 {
            abode: home.clone(),
            root_public_key: root.public_key().into(),
            issued_at_unix_ms: None,
        },
        root,
    )
    .expect("abode binding");
    let operational = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        OperationalKeyGrantV1 {
            home: home.clone(),
            epoch,
            operational_public_key: operational.public_key().into(),
            valid_from_unix_ms: None,
            expires_at_unix_ms: None,
            capabilities: vec![
                OperationalCapabilityV1::JobHome,
                OperationalCapabilityV1::JobControl,
                OperationalCapabilityV1::Custody,
                OperationalCapabilityV1::Locate,
            ],
            evidence: vec![],
        },
        root,
    )
    .expect("operational grant");
    HomeAuthorityV1 { abode, operational, prepared: None }
}

fn signed_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut manifest = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    manifest.provenance.author = Some(key.public_hex().to_string());
    manifest.provenance.signature = Some(key.sign(&manifest.signing_payload()));
    manifest
}

fn normalize_sha256(value: &str) -> Option<String> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    (raw.len() == 64
        && raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| format!("sha256:{raw}"))
}

struct KernelLiveness {
    kernel: Weak<Kernel>,
    blocking_fixture: CreatureId,
}

impl DeploymentLiveness for KernelLiveness {
    fn target_is_live(
        &self,
        target: CreatureId,
        deployment: &DeploymentReceiptV1,
    ) -> Result<bool, String> {
        let kernel =
            self.kernel.upgrade().ok_or_else(|| "Kernel roster unavailable".to_string())?;
        let Some(identity) = kernel.loaded_manifest_identity(target) else {
            return Ok(false);
        };
        if identity.manifest_content_address.as_deref()
            != Some(deployment.function.manifest_content_address.as_str())
        {
            return Ok(false);
        }
        if let Some(measured) = identity.artifact_sha256.as_deref().and_then(normalize_sha256) {
            return Ok(measured == deployment.artifact_hash);
        }

        // The blocking parent is deliberately an in-process test fixture so it can expose a gate
        // across the process-control channel. It is the sole no-artifact exception; every dynamic
        // target, including the typed critter, must match Kernel-measured artifact bytes above.
        Ok(target == self.blocking_fixture
            && identity.artifact_build_hash.as_deref().and_then(normalize_sha256).as_deref()
                == Some(deployment.artifact_hash.as_str()))
    }
}

struct OwnerAdmission(String);

impl DeploymentAdmission for OwnerAdmission {
    fn register(&self, request: &SignedRecordV1<DeploymentRegistrationV1>) -> Result<(), String> {
        (request.signer == self.0)
            .then_some(())
            .ok_or_else(|| "deployment was not authorized by the owning Abode".into())
    }

    fn undeploy(
        &self,
        request: &SignedRecordV1<UndeployRequestV1>,
        _deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (request.signer == self.0)
            .then_some(())
            .ok_or_else(|| "undeploy was not authorized by the owning Abode".into())
    }
}

struct IdempotentMetadata;

impl FunctionMetadata for IdempotentMetadata {
    fn effect(&self, _function: &ResolvedFunctionV1) -> EffectClassV1 {
        EffectClassV1::Idempotent
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
            .ok_or_else(|| "resolution signer is not pinned".into())
    }

    fn allow_deployment(
        &self,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (deployment.signer == self.executor)
            .then_some(())
            .ok_or_else(|| "deployment signer is not pinned".into())
    }

    fn allow_executor_receipt(
        &self,
        receipt: &SignedRecordV1<gawdfn::ExecutionReceiptV1>,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (receipt.signer == self.executor && deployment.signer == self.executor)
            .then_some(())
            .ok_or_else(|| "execution signer is not pinned".into())
    }

    fn allow_placement_decision(
        &self,
        decision: &SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "placement signer is not pinned".into())
    }

    fn allow_retry_decision(
        &self,
        decision: &SignedRecordV1<RetryDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "retry signer is not pinned".into())
    }
}

struct NoopCreature;

impl Creature for NoopCreature {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

const MAX_TEST_INVOCATIONS: usize = 8;

#[derive(Clone)]
struct DurableInvocationCounter {
    path: PathBuf,
    lock: Arc<Mutex<()>>,
}

impl DurableInvocationCounter {
    fn new(path: PathBuf) -> Self {
        Self { path, lock: Arc::new(Mutex::new(())) }
    }

    fn count(&self) -> Result<usize, String> {
        let _guard = self.lock.lock().unwrap_or_else(|poison| poison.into_inner());
        self.count_locked()
    }

    fn record(&self) -> Result<usize, String> {
        let _guard = self.lock.lock().unwrap_or_else(|poison| poison.into_inner());
        let prior = self.count_locked()?;
        if prior >= MAX_TEST_INVOCATIONS {
            return Err("test target invocation cap reached".into());
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|error| error.to_string())?;
        file.write_all(b"call\n").map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        Ok(prior + 1)
    }

    fn count_locked(&self) -> Result<usize, String> {
        let bytes = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(error) => return Err(error.to_string()),
        };
        if bytes.len() > MAX_TEST_INVOCATIONS * b"call\n".len()
            || !bytes.chunks_exact(b"call\n".len()).all(|chunk| chunk == b"call\n")
            || !bytes.chunks_exact(b"call\n".len()).remainder().is_empty()
        {
            return Err("durable invocation counter is malformed or over cap".into());
        }
        Ok(bytes.len() / b"call\n".len())
    }
}

#[derive(Default)]
struct TargetGate {
    entered: bool,
    release: bool,
    complete_after_control: bool,
    executor_route: Option<String>,
}

fn child_input() -> ValueRefV1 {
    ValueRefV1::Inline { value: json!({"value": 7}) }
}

struct ProofTarget {
    function: FunctionId,
    input: ValueRefV1,
    gate: Arc<(Mutex<TargetGate>, Condvar)>,
    invocations: DurableInvocationCounter,
    pending_completion: Option<(Envelope, FunctionResultV1)>,
    bus: Option<Arc<dyn aether::Bus>>,
}

impl Creature for ProofTarget {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.bus = Some(ctx.bus);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if let Ok(call) = forge::function::parse_call_for(&env, &self.function) {
            if call.input != self.input || self.invocations.record().is_err() {
                return Outcome::none();
            }
            let Ok(progress) = forge::function::progress(
                &env,
                call.attempt.clone(),
                1,
                ValueRefV1::Inline { value: json!({"phase": "remote-ready", "realm": REALM_B}) },
            ) else {
                return Outcome::none();
            };
            let Some(bus) = self.bus.as_ref() else {
                return Outcome::none();
            };
            if bus.emit(progress).is_err() {
                return Outcome::none();
            }
            let (lock, ready) = &*self.gate;
            let mut gate = lock.lock().unwrap_or_else(|poison| poison.into_inner());
            gate.entered = true;
            gate.executor_route = Some(call.executor_dispatch.payload.executor_creature.clone());
            ready.notify_all();
            let deadline = Instant::now() + scaled(Duration::from_secs(45));
            while !gate.release && Instant::now() < deadline {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let (next, _) = ready
                    .wait_timeout(gate, remaining.min(Duration::from_millis(200)))
                    .unwrap_or_else(|poison| poison.into_inner());
                gate = next;
            }
            let result = FunctionResultV1 {
                attempt: call.attempt,
                outcome: Ok(ValueRefV1::Inline { value: json!({"answer": 42}) }),
            };
            if gate.complete_after_control {
                drop(gate);
                self.pending_completion = Some((env, result));
                return Outcome::none();
            }
            drop(gate);
            return forge::function::reply(&env, result)
                .map(Outcome::send)
                .unwrap_or_else(|_| Outcome::none());
        }

        if forge::function::parse_control(&env).is_err() {
            return Outcome::none();
        }
        let Ok(acknowledgement) = forge::function::control_result(
            &env,
            ControlDispositionV1::TooLate,
            Some("blocking call already completed before queued steer was observed".into()),
        ) else {
            return Outcome::none();
        };
        let mut outcome = Outcome::send(acknowledgement);
        if let Some((request, result)) = self.pending_completion.take() {
            let Ok(completion) = forge::function::reply(&request, result) else {
                return Outcome::none();
            };
            outcome.push(completion);
        }
        outcome
    }
}

struct CapturingExecutor {
    inner: FunctionExecutor,
    child_invocations: DurableInvocationCounter,
    grant: Arc<Mutex<Option<SignedRecordV1<ExecutionGrantV1>>>>,
    child_grant: Arc<Mutex<Option<SignedRecordV1<ExecutionGrantV1>>>>,
    grant_receiver: Arc<Mutex<Option<CreatureId>>>,
    terminal: Arc<Mutex<Option<SignedRecordV1<ExecutionReceiptV1>>>>,
    child_terminal: Arc<Mutex<Option<SignedRecordV1<ExecutionReceiptV1>>>>,
    terminal_push_suppressed: Arc<AtomicBool>,
    query_count: Arc<AtomicUsize>,
    me: Option<CreatureId>,
}

impl Creature for CapturingExecutor {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
        self.inner.bind(ctx);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema == SCHEMA_EXECUTE_V1 {
            match serde_json::from_slice::<ExecuteMessageV1>(&env.payload) {
                Ok(ExecuteMessageV1::Grant { grant }) => {
                    if grant.payload.input == child_input() {
                        *self.child_grant.lock().unwrap_or_else(|poison| poison.into_inner()) =
                            Some(*grant);
                    } else {
                        *self.grant.lock().unwrap_or_else(|poison| poison.into_inner()) =
                            Some(*grant);
                    }
                    *self.grant_receiver.lock().unwrap_or_else(|poison| poison.into_inner()) =
                        self.me;
                }
                Ok(ExecuteMessageV1::Query { .. }) => {
                    self.query_count.fetch_add(1, Ordering::SeqCst);
                }
                _ => {}
            }
        }
        let terminal_attempt = (env.header.schema == SCHEMA_CALL_V1)
            .then(|| serde_json::from_slice::<FunctionCallMessageV1>(&env.payload).ok())
            .flatten()
            .and_then(|message| match message {
                FunctionCallMessageV1::Result { result } => Some(result.attempt),
                _ => None,
            });
        let outcome = self.inner.handle(env);
        let Some(attempt) = terminal_attempt else { return outcome };
        let receipt = outcome.dispatches.iter().find_map(|dispatch| {
            if dispatch.schema != SCHEMA_EXECUTE_V1 {
                return None;
            }
            match serde_json::from_slice::<ExecuteMessageV1>(&dispatch.payload).ok()? {
                ExecuteMessageV1::Receipt { receipt } if receipt.payload.attempt == attempt => {
                    Some(*receipt)
                }
                _ => None,
            }
        });
        if let Some(receipt) = receipt {
            let is_parent = matches!(
                &receipt.payload.stage,
                ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value },
                } if value == &json!({"answer": 42})
            );
            if is_parent {
                *self.terminal.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(receipt);
                self.terminal_push_suppressed.store(true, Ordering::SeqCst);
                // The executor has already fsynced the receipt. Suppress only the parent's
                // best-effort push; a causal child's terminal remains normally deliverable.
                Outcome::none()
            } else {
                if matches!(
                    &receipt.payload.stage,
                    ExecutionStageV1::Succeeded {
                        result: ValueRefV1::Inline { value },
                    } if value == &json!({"answer": 8})
                ) && self.child_invocations.record().is_err()
                {
                    return Outcome::none();
                }
                *self.child_terminal.lock().unwrap_or_else(|poison| poison.into_inner()) =
                    Some(receipt);
                outcome
            }
        } else {
            outcome
        }
    }

    fn shutdown(&mut self, deadline: Deadline) {
        self.inner.shutdown(deadline);
    }
}

struct PingCreature;

impl Creature for PingCreature {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != PING_SCHEMA {
            return Outcome::none();
        }
        Outcome::send(Dispatch::reply_to_env(&env, b"pong".to_vec()).with_schema(PING_SCHEMA))
    }
}

struct SharedHome(Arc<Mutex<FunctionHome>>);

impl Creature for SharedHome {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner()).bind(ctx);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        self.0.lock().unwrap_or_else(|poison| poison.into_inner()).handle(env)
    }
}

#[derive(Clone, Debug, Default)]
struct FaultPlan {
    drop_once: Option<u32>,
    tamper_once: Option<u32>,
    dropped: bool,
    tampered: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum GxRequest {
    Plan { blob: BlobRefV1, chunk_size: u32 },
    Chunk { blob: BlobRefV1, transfer_id: String, chunk_size: u32, chunk_index: u32 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum GxReply {
    Plan {
        transfer_id: String,
        file_size: u64,
        file_hash: String,
        chunk_size: u32,
        total_chunks: u32,
    },
    Served {
        chunk_index: u32,
        disposition: String,
    },
    Error {
        message: String,
    },
}

struct CheckpointGxSource {
    store: Arc<FsJobBlobStore>,
    faults: Arc<Mutex<FaultPlan>>,
}

impl CheckpointGxSource {
    fn plan(
        &self,
        blob: &BlobRefV1,
        chunk_size: u32,
    ) -> Result<(Vec<u8>, gawdxfer::TransferPlan), String> {
        let bytes = self.store.get_checkpoint(blob).map_err(|error| error.to_string())?;
        let digest = blob.digest.strip_prefix("sha256:").unwrap_or(&blob.digest);
        let transfer_id = format!("checkpoint-{digest}");
        let plan = gawdxfer::TransferPlan::from_bytes(transfer_id, &bytes, chunk_size)
            .map_err(|error| error.to_string())?;
        if format!("sha256:{}", plan.file_hash) != blob.digest || plan.file_size != blob.size {
            return Err("GX plan differs from the requested content address".into());
        }
        Ok((bytes, plan))
    }

    fn reply(env: &Envelope, reply: GxReply) -> Dispatch {
        Dispatch::reply_to_env(env, aether::wire::to_bytes(&reply)).with_schema(GX_CONTROL_SCHEMA)
    }
}

impl Creature for CheckpointGxSource {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != GX_CONTROL_SCHEMA {
            return Outcome::none();
        }
        let Ok(request) = serde_json::from_slice::<GxRequest>(&env.payload) else {
            return Outcome::send(Self::reply(
                &env,
                GxReply::Error { message: "invalid GX request".into() },
            ));
        };
        match request {
            GxRequest::Plan { blob, chunk_size } => match self.plan(&blob, chunk_size) {
                Ok((_bytes, plan)) => Outcome::send(Self::reply(
                    &env,
                    GxReply::Plan {
                        transfer_id: plan.transfer_id,
                        file_size: plan.file_size,
                        file_hash: plan.file_hash,
                        chunk_size: plan.chunk_size,
                        total_chunks: plan.total_chunks,
                    },
                )),
                Err(message) => Outcome::send(Self::reply(&env, GxReply::Error { message })),
            },
            GxRequest::Chunk { blob, transfer_id, chunk_size, chunk_index } => {
                let Ok((bytes, plan)) = self.plan(&blob, chunk_size) else {
                    return Outcome::send(Self::reply(
                        &env,
                        GxReply::Error { message: "checkpoint bytes unavailable".into() },
                    ));
                };
                if plan.transfer_id != transfer_id || chunk_index >= plan.total_chunks {
                    return Outcome::send(Self::reply(
                        &env,
                        GxReply::Error {
                            message: "GX chunk request does not match its plan".into(),
                        },
                    ));
                }

                let disposition = {
                    let mut faults =
                        self.faults.lock().unwrap_or_else(|poison| poison.into_inner());
                    if faults.drop_once == Some(chunk_index) && !faults.dropped {
                        faults.dropped = true;
                        "dropped"
                    } else if faults.tamper_once == Some(chunk_index) && !faults.tampered {
                        faults.tampered = true;
                        "tampered"
                    } else {
                        "sent"
                    }
                };
                let reply = Self::reply(
                    &env,
                    GxReply::Served { chunk_index, disposition: disposition.into() },
                );
                if disposition == "dropped" {
                    return Outcome::send(reply);
                }

                let Some(target) = env.header.reply_to.clone() else {
                    return Outcome::send(Self::reply(
                        &env,
                        GxReply::Error { message: "GX request omitted its receiver route".into() },
                    ));
                };
                let frame = if disposition == "tampered" {
                    let Ok((header, payload)) = plan.chunk(&bytes, chunk_index) else {
                        return Outcome::send(Self::reply(
                            &env,
                            GxReply::Error { message: "GX chunk bounds failed".into() },
                        ));
                    };
                    let mut corrupted = payload.to_vec();
                    if let Some(first) = corrupted.first_mut() {
                        *first ^= 0x80;
                    }
                    match gawdxfer::encode_binary_frame(&header, &corrupted) {
                        Ok(frame) => frame,
                        Err(error) => {
                            return Outcome::send(Self::reply(
                                &env,
                                GxReply::Error { message: error.to_string() },
                            ));
                        }
                    }
                } else {
                    match plan.encode_chunk(&bytes, chunk_index) {
                        Ok(frame) => frame,
                        Err(error) => {
                            return Outcome::send(Self::reply(
                                &env,
                                GxReply::Error { message: error.to_string() },
                            ));
                        }
                    }
                };
                Outcome {
                    dispatches: vec![
                        Dispatch::to(target, frame)
                            .with_schema(gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA)
                            .with_corr(env.header.corr.unwrap_or_default()),
                        reply,
                    ],
                    budget_signal: None,
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn base_node(
    node_id: &str,
    realm: &str,
    port: u16,
    node_key: &Ed25519KeyMaterial,
    peer_node: &str,
    peer_realm: &str,
    peer_port: u16,
    peer_public: &str,
    dials: bool,
) -> Arc<Kernel> {
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(node_key.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![node_key.public_hex().to_string()])),
        256,
    );
    kernel.set_node_identity(node_key.public_hex().to_string());
    let transport = TransportTcp::new(TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(node_id.into()),
        listen_addr: format!("127.0.0.1:{port}"),
        peers: vec![PeerConfig {
            node_id: NodeId(peer_node.into()),
            pubkey_hex: peer_public.into(),
            dial_addr: dials.then(|| format!("127.0.0.1:{peer_port}")),
        }],
    });
    let transport_id = kernel
        .load_transport_instance(signed_manifest("transport-tcp", node_key), Box::new(transport))
        .expect("load attesting transport");
    kernel.bind_role(Role::new(Role::TRANSPORT), transport_id);
    let registry_id = kernel
        .load_instance(signed_manifest("registry-mem", node_key), Box::new(RegistryMem::new()))
        .expect("load registry");
    kernel.bind_role(Role::new(Role::REGISTRY), registry_id);
    let mut realm_to_peer = HashMap::new();
    realm_to_peer.insert(RealmId::new(peer_realm), NodeId(peer_node.into()));
    let federator = OmegaFederator::new(FederatorConfig {
        self_node: NodeId(node_id.into()),
        self_realm: RealmId::new(realm),
        local_registry: registry_id,
        abode_key: node_key.clone(),
        realm_to_peer,
        weigher: Box::new(RoundRobinReputation::new()),
    });
    let federator_id = kernel
        .load_instance(signed_manifest("omega-federator", node_key), Box::new(federator))
        .expect("load omega federator");
    kernel.bind_role(Role::new(Role::OMEGA_GATEWAY), federator_id);
    kernel
}

fn remote_node(realm: &str, node: &str, creature: CreatureId) -> Address {
    Address::Omega {
        realm: RealmId::new(realm),
        target: Box::new(Address::Node(NodeId(node.into()), creature)),
    }
}

fn remote_executor() -> Address {
    Address::Omega {
        realm: RealmId::new(REALM_B),
        target: Box::new(Address::NodeRole(
            NodeId(NODE_B.into()),
            Role::new(FUNCTION_EXECUTOR_ROLE),
        )),
    }
}

fn recv_corr(
    rx: &InboxReceiver,
    corr: u64,
    schema: &str,
    timeout: Duration,
) -> Result<Envelope, String> {
    let deadline = Instant::now() + scaled(timeout);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == schema => {
                return Ok(env);
            }
            Ok(_) => {}
            Err(_) => {}
        }
    }
    Err(format!("no `{schema}` response for correlation {corr}"))
}

fn rpc<T: Serialize>(
    bus: &BusHandle,
    rx: &InboxReceiver,
    corr: u64,
    target: Address,
    schema: &str,
    message: &T,
) -> Result<Envelope, String> {
    bus.send(
        Dispatch::to(target, aether::wire::to_bytes(message))
            .with_schema(schema)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(corr),
    )
    .map_err(|error| error.to_string())?;
    recv_corr(rx, corr, schema, RPC_TIMEOUT)
}

struct NodeAState {
    kernel: Arc<Kernel>,
    bus: BusHandle,
    rx: InboxReceiver,
    corr: u64,
    source_home: Arc<Mutex<FunctionHome>>,
    checkpoint_store: Arc<FsJobBlobStore>,
    source: CreatureId,
    gx_source: CreatureId,
    ping: CreatureId,
    faults: Arc<Mutex<FaultPlan>>,
    public: PublicFixture,
}

impl NodeAState {
    fn boot(root: &Path, port_a: u16, port_b: u16, public: PublicFixture) -> Self {
        let node_key = Ed25519KeyMaterial::from_seed(NODE_A_SEED).expect("node A key");
        let kernel = base_node(
            NODE_A,
            REALM_A,
            port_a,
            &node_key,
            NODE_B,
            REALM_B,
            port_b,
            &public.node_b_public,
            true,
        );
        let checkpoint_store = Arc::new(
            FsJobBlobStore::open(root.join("checkpoint-store-a"), BlobCaps::default())
                .expect("source checkpoint store"),
        );
        let policy_signer = Arc::new(
            Ed25519SeedSigner::from_seed(POLICY_SEED).expect("job policy operational key"),
        );
        let policy = kernel
            .load_instance(
                signed_manifest("policy-job-basic-process", &node_key),
                Box::new(
                    BasicJobPolicy::new(policy_signer, BasicPolicyCaps::default())
                        .expect("open job policy"),
                ),
            )
            .expect("load job policy");
        kernel.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy);
        let source_signer =
            Arc::new(Ed25519SeedSigner::from_seed(SOURCE_SEED).expect("source operational key"));
        let source_home = Arc::new(Mutex::new(
            FunctionHome::open_with_checkpoint_store(
                HomeConfig::for_creature(
                    root.join("home-source"),
                    public.home.clone(),
                    public.source_authority.clone(),
                )
                .with_location(REALM_A, NODE_A),
                source_signer,
                Arc::new(IdempotentMetadata),
                public.trust(),
                checkpoint_store.clone(),
                checkpoint_store.clone(),
            )
            .expect("source Home"),
        ));
        let source = kernel
            .load_instance(
                signed_manifest("function-home-source-process", &node_key),
                Box::new(SharedHome(source_home.clone())),
            )
            .expect("load source Home");
        let faults = Arc::new(Mutex::new(FaultPlan::default()));
        let gx_source = kernel
            .load_instance(
                signed_manifest("checkpoint-gx-source-process", &node_key),
                Box::new(CheckpointGxSource {
                    store: checkpoint_store.clone(),
                    faults: faults.clone(),
                }),
            )
            .expect("load GX source");
        let ping = kernel
            .load_instance(signed_manifest("ping-process-a", &node_key), Box::new(PingCreature))
            .expect("load ping A");
        let (_probe, bus, rx) = kernel.open_endpoint(Capabilities::default());
        Self {
            kernel,
            bus,
            rx,
            corr: 1,
            source_home,
            checkpoint_store,
            source,
            gx_source,
            ping,
            faults,
            public,
        }
    }

    fn next_corr(&mut self) -> u64 {
        let corr = self.corr;
        self.corr = self.corr.saturating_add(1);
        corr
    }

    fn ping_b(&mut self, target: CreatureId) -> Result<(), String> {
        let corr = self.next_corr();
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            remote_node(REALM_B, NODE_B, target),
            PING_SCHEMA,
            &json!({"ping": true}),
        )?;
        (env.payload == b"pong")
            .then_some(())
            .ok_or_else(|| "remote ping returned the wrong payload".into())
    }

    fn register_deployment(
        &mut self,
        target: CreatureId,
        alias: FunctionAlias,
        function: FunctionId,
        artifact_hash: String,
        resolution: SignedRecordV1<ResolutionReceiptV1>,
    ) -> Result<FunctionDeployMessageV1, String> {
        let root = Ed25519SeedSigner::from_seed(ROOT_SEED).map_err(|error| error.to_string())?;
        let authorization = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentRequestV1 {
                requested_by: self.public.home.clone(),
                function: FunctionSelectorV1::Alias { alias },
                target_realm: REALM_B.into(),
                target_node: Some(NODE_B.into()),
                evidence: vec![],
                requested_at_unix_ms: None,
            },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let deployment =
            derive_deployment_id(&function, &artifact_hash, REALM_B, NODE_B, &target.0.to_string())
                .map_err(|error| error.to_string())?;
        let registration = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentRegistrationV1 {
                authorization,
                resolution,
                deployment,
                function,
                artifact_hash,
                target_creature: target.0.to_string(),
                evidence: vec![],
            },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let corr = self.next_corr();
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            remote_executor(),
            SCHEMA_FUNCTION_DEPLOY_V1,
            &FunctionDeployMessageV1::Register { request: Box::new(registration) },
        )?;
        serde_json::from_slice(&env.payload).map_err(|error| error.to_string())
    }

    fn register_b(&mut self, target: CreatureId) -> Result<FunctionDeployMessageV1, String> {
        self.register_deployment(
            target,
            self.public.alias.clone(),
            self.public.function.clone(),
            self.public.artifact_hash.clone(),
            self.public.resolution(),
        )
    }

    fn register_typed_b(&mut self, target: CreatureId) -> Result<FunctionDeployMessageV1, String> {
        self.register_deployment(
            target,
            self.public.typed_alias.clone(),
            self.public.typed_function.clone(),
            self.public.typed_artifact_hash.clone(),
            self.public.typed_resolution(),
        )
    }

    fn lookup_function(&mut self, function: FunctionId) -> Result<FunctionDeployMessageV1, String> {
        let corr = self.next_corr();
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            remote_executor(),
            SCHEMA_FUNCTION_DEPLOY_V1,
            &FunctionDeployMessageV1::Lookup {
                query: DeploymentQueryV1 {
                    function: Some(function),
                    realm: Some(REALM_B.into()),
                    node: Some(NODE_B.into()),
                    limit: 8,
                },
            },
        )?;
        serde_json::from_slice(&env.payload).map_err(|error| error.to_string())
    }

    fn lookup_b(&mut self) -> Result<FunctionDeployMessageV1, String> {
        self.lookup_function(self.public.function.clone())
    }

    fn lookup_typed_b(&mut self) -> Result<FunctionDeployMessageV1, String> {
        self.lookup_function(self.public.typed_function.clone())
    }

    fn submit_job(
        &mut self,
        deployment: SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<JobMessageV1, String> {
        let root = Ed25519SeedSigner::from_seed(ROOT_SEED).map_err(|error| error.to_string())?;
        let dependency_bytes = vec![0x5a; 24 * 1024];
        let dependency = self
            .checkpoint_store
            .put_checkpoint("application/vnd.gawd.process-dependency", &dependency_bytes)
            .map_err(|error| error.to_string())?;
        if dependency != self.public.job_input {
            return Err("source store changed the deterministic Job input content address".into());
        }
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobSubmitV1 {
                home: self.public.home.clone(),
                caller_idempotency_key: "process-gx-checkpoint".into(),
                function: FunctionSelectorV1::Alias { alias: self.public.alias.clone() },
                input: ValueRefV1::Blob { blob: dependency },
                delivery: DeliveryModeV1::AtMostOnce,
                allow_duplicate_effects: false,
                parent: None,
                causal: vec![],
                access: JobAccessV1::default(),
                evidence: vec![],
                result_recipients: vec![],
                submitted_at_unix_ms: None,
            },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let corr = self.next_corr();
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            Address::Creature(self.source),
            SCHEMA_JOB_V1,
            &JobMessageV1::Submit {
                request: Box::new(request),
                resolution: Box::new(self.public.resolution()),
                deployment: Box::new(deployment),
            },
        )?;
        serde_json::from_slice(&env.payload).map_err(|error| error.to_string())
    }

    fn create_checkpoint(&self) -> Result<(SignedRecordV1<HomeCheckpointV1>, BlobRefV1), String> {
        let home = self.source_home.lock().unwrap_or_else(|poison| poison.into_inner());
        let checkpoint = home.create_checkpoint(None).map_err(|error| error.to_string())?;
        Ok((checkpoint, self.public.job_input.clone()))
    }

    fn prepare(
        &self,
        checkpoint: SignedRecordV1<HomeCheckpointV1>,
    ) -> Result<SignedRecordV1<CustodyPreparedV1>, String> {
        let root = Ed25519SeedSigner::from_seed(ROOT_SEED).map_err(|error| error.to_string())?;
        let grant = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyGrantV1 {
                home: self.public.home.clone(),
                handoff: HandoffId::new("process-gx-handoff"),
                from_epoch: 1,
                to_epoch: 2,
                source_authority: self.public.source_authority.clone(),
                source_realm: REALM_A.into(),
                source_node: NODE_A.into(),
                destination_realm: REALM_B.into(),
                destination_node: NODE_B.into(),
                checkpoint_hash: canonical_hash(&checkpoint).map_err(|error| error.to_string())?,
                source_log_root: checkpoint.payload.log_root.clone(),
                destination_operational_key: self.public.destination_authority.operational.clone(),
                evidence: vec![],
                issued_at_unix_ms: None,
                destination_rewrap: None,
            },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let home = self.source_home.lock().unwrap_or_else(|poison| poison.into_inner());
        home.prepare_handoff(grant, checkpoint)
            .map(|prepared| prepared.prepared)
            .map_err(|error| error.to_string())
    }

    fn home_rpc(
        &mut self,
        destination: CreatureId,
        message: &HomeMessageV1,
    ) -> Result<HomeMessageV1, String> {
        let corr = self.next_corr();
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            remote_node(REALM_B, NODE_B, destination),
            SCHEMA_HOME_V1,
            message,
        )?;
        serde_json::from_slice(&env.payload).map_err(|error| error.to_string())
    }

    fn source_status(&self) -> Result<SignedRecordV1<HomeCustodyStatusV1>, String> {
        self.source_home
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .signed_custody_status()
            .map_err(|error| error.to_string())
    }

    fn read_job(
        &mut self,
        destination: Option<CreatureId>,
        handle: &JobHandleV1,
    ) -> Result<JobMessageV1, String> {
        let corr = self.next_corr();
        let target = destination.map_or(Address::Creature(self.source), |destination| {
            remote_node(REALM_B, NODE_B, destination)
        });
        let signed_reply_to = destination.map_or(Address::Creature(self.bus.id()), |_| {
            Address::Node(NodeId(NODE_A.into()), self.bus.id())
        });
        let root = Ed25519SeedSigner::from_seed(ROOT_SEED).map_err(|error| error.to_string())?;
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetV1 { handle: handle.clone(), nonce: format!("process-get-{corr}") },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetRelayV1 {
                caller,
                reply_to: serde_json::to_string(&signed_reply_to)
                    .map_err(|error| error.to_string())?,
            },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            target,
            SCHEMA_JOB_V1,
            &JobMessageV1::Get { request: Box::new(request.clone()) },
        )?;
        let message = serde_json::from_slice::<JobMessageV1>(&env.payload)
            .map_err(|error| error.to_string())?;
        if let JobMessageV1::Snapshot { response } = &message {
            verify_job_snapshot_response_for(response, &request)
                .map_err(|error| error.to_string())?;
        }
        Ok(message)
    }

    fn read_events(
        &mut self,
        destination: Option<CreatureId>,
        handle: &JobHandleV1,
    ) -> Result<JobMessageV1, String> {
        let corr = self.next_corr();
        let target = destination.map_or(Address::Creature(self.source), |destination| {
            remote_node(REALM_B, NODE_B, destination)
        });
        let signed_reply_to = destination.map_or(Address::Creature(self.bus.id()), |_| {
            Address::Node(NodeId(NODE_A.into()), self.bus.id())
        });
        let root = Ed25519SeedSigner::from_seed(ROOT_SEED).map_err(|error| error.to_string())?;
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryV1 {
                handle: handle.clone(),
                after_sequence: None,
                limit: 64,
                nonce: format!("process-events-{corr}"),
            },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryRelayV1 {
                caller,
                reply_to: serde_json::to_string(&signed_reply_to)
                    .map_err(|error| error.to_string())?,
            },
            &root,
        )
        .map_err(|error| error.to_string())?;
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            target,
            SCHEMA_JOB_V1,
            &JobMessageV1::Events { request: Box::new(request.clone()) },
        )?;
        let message = serde_json::from_slice::<JobMessageV1>(&env.payload)
            .map_err(|error| error.to_string())?;
        if let JobMessageV1::EventPage { response } = &message {
            verify_event_page_response_for(response, &request)
                .map_err(|error| error.to_string())?;
        }
        Ok(message)
    }

    fn control_job(
        &mut self,
        destination: CreatureId,
        request: SignedRecordV1<JobControlV1>,
    ) -> Result<JobMessageV1, String> {
        let corr = self.next_corr();
        let target = remote_node(REALM_B, NODE_B, destination);
        let env = rpc(
            &self.bus,
            &self.rx,
            corr,
            target.clone(),
            SCHEMA_JOB_V1,
            &JobMessageV1::Control { request: Box::new(request) },
        )?;
        if !self.kernel.router().journal_snapshot().iter().any(|entry| {
            entry.from == Address::Creature(self.bus.id())
                && entry.to == target
                && entry.corr == Some(corr)
        }) {
            return Err("causal control did not enter A's explicit Omega application route".into());
        }
        serde_json::from_slice(&env.payload).map_err(|error| error.to_string())
    }
}

struct NodeBState {
    kernel: Arc<Kernel>,
    bus: BusHandle,
    rx: InboxReceiver,
    corr: u64,
    checkpoint_store: Arc<FsJobBlobStore>,
    target: CreatureId,
    typed_target: CreatureId,
    executor: CreatureId,
    ping: CreatureId,
    destination: CreatureId,
    gate: Arc<(Mutex<TargetGate>, Condvar)>,
    invocations: DurableInvocationCounter,
    child_invocations: DurableInvocationCounter,
    grant: Arc<Mutex<Option<SignedRecordV1<ExecutionGrantV1>>>>,
    child_grant: Arc<Mutex<Option<SignedRecordV1<ExecutionGrantV1>>>>,
    grant_receiver: Arc<Mutex<Option<CreatureId>>>,
    terminal: Arc<Mutex<Option<SignedRecordV1<ExecutionReceiptV1>>>>,
    child_terminal: Arc<Mutex<Option<SignedRecordV1<ExecutionReceiptV1>>>>,
    terminal_push_suppressed: Arc<AtomicBool>,
    query_count: Arc<AtomicUsize>,
}

impl NodeBState {
    fn boot(root: &Path, port_a: u16, port_b: u16, generation: u32, public: PublicFixture) -> Self {
        let node_key = Ed25519KeyMaterial::from_seed(NODE_B_SEED).expect("node B key");
        let kernel = base_node(
            NODE_B,
            REALM_B,
            port_b,
            &node_key,
            NODE_A,
            REALM_A,
            port_a,
            &public.node_a_public,
            false,
        );
        let gate = Arc::new((Mutex::new(TargetGate::default()), Condvar::new()));
        let invocations = DurableInvocationCounter::new(root.join("target-invocations.log"));
        let child_invocations =
            DurableInvocationCounter::new(root.join("typed-target-invocations.log"));
        let target = kernel
            .load_instance(
                public.target_manifest.clone(),
                Box::new(ProofTarget {
                    function: public.function.clone(),
                    input: ValueRefV1::Blob { blob: public.job_input.clone() },
                    gate: gate.clone(),
                    invocations: invocations.clone(),
                    pending_completion: None,
                    bus: None,
                }),
            )
            .expect("load blocking parent target");
        let typed_target = kernel
            .load(
                public.typed_target_manifest.clone(),
                Artifact::Bytes(TYPED_ADD_ONE_SOURCE.to_vec()),
            )
            .expect("load signed typed-add-one artifact through the ScriptEngine");
        if generation >= 2 {
            kernel
                .load_instance(
                    signed_manifest("executor-id-filler-process", &node_key),
                    Box::new(NoopCreature),
                )
                .expect("load executor ID filler");
        }
        let executor_signer = Arc::new(
            Ed25519SeedSigner::from_seed(EXECUTOR_SEED).expect("executor operational key"),
        );
        let grant = Arc::new(Mutex::new(None));
        let child_grant = Arc::new(Mutex::new(None));
        let grant_receiver = Arc::new(Mutex::new(None));
        let terminal = Arc::new(Mutex::new(None));
        let child_terminal = Arc::new(Mutex::new(None));
        let terminal_push_suppressed = Arc::new(AtomicBool::new(false));
        let query_count = Arc::new(AtomicUsize::new(0));
        let executor = kernel
            .load_instance(
                signed_manifest("function-executor-process", &node_key),
                Box::new(CapturingExecutor {
                    inner: FunctionExecutor::open_with_liveness(
                        ExecutorConfig::new(
                            root.join("executor-b"),
                            public.executor_public.clone(),
                        )
                        .with_location(REALM_B, NODE_B, "auto"),
                        executor_signer,
                        Arc::new(StringAddressing),
                        Arc::new(OwnerAdmission(public.root_public.clone())),
                        Arc::new(KernelLiveness {
                            kernel: Arc::downgrade(&kernel),
                            blocking_fixture: target,
                        }),
                    )
                    .expect("open executor"),
                    child_invocations: child_invocations.clone(),
                    grant: grant.clone(),
                    child_grant: child_grant.clone(),
                    grant_receiver: grant_receiver.clone(),
                    terminal: terminal.clone(),
                    child_terminal: child_terminal.clone(),
                    terminal_push_suppressed: terminal_push_suppressed.clone(),
                    query_count: query_count.clone(),
                    me: None,
                }),
            )
            .expect("load executor");
        kernel.bind_remote_role(Role::new(FUNCTION_EXECUTOR_ROLE), executor);
        let policy_signer = Arc::new(
            Ed25519SeedSigner::from_seed(POLICY_SEED).expect("job policy operational key"),
        );
        let policy = kernel
            .load_instance(
                signed_manifest("policy-job-basic-destination-process", &node_key),
                Box::new(
                    BasicJobPolicy::new(policy_signer, BasicPolicyCaps::default())
                        .expect("open destination job policy"),
                ),
            )
            .expect("load destination job policy");
        kernel.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy);
        let ping = kernel
            .load_instance(signed_manifest("ping-process-b", &node_key), Box::new(PingCreature))
            .expect("load ping B");
        let checkpoint_store = Arc::new(
            FsJobBlobStore::open(root.join("checkpoint-store-b"), BlobCaps::default())
                .expect("destination checkpoint store"),
        );
        let destination_signer = Arc::new(
            Ed25519SeedSigner::from_seed(DESTINATION_SEED).expect("destination operational key"),
        );
        let mut destination_config = HomeConfig::for_creature(
            root.join("home-destination"),
            public.home.clone(),
            public.destination_authority.clone(),
        )
        .with_location(REALM_B, NODE_B);
        destination_config.epoch = 2;
        let destination = kernel
            .load_instance(
                signed_manifest("function-home-destination-process", &node_key),
                Box::new(
                    HomeCustodyDestination::new(
                        destination_config,
                        destination_signer,
                        Arc::new(IdempotentMetadata),
                        public.trust(),
                        checkpoint_store.clone(),
                        checkpoint_store.clone(),
                    )
                    .expect("open destination Home"),
                ),
            )
            .expect("load destination Home");
        let (_probe, bus, rx) = kernel.open_endpoint(Capabilities::default());
        Self {
            kernel,
            bus,
            rx,
            corr: 10_000,
            checkpoint_store,
            target,
            typed_target,
            executor,
            ping,
            destination,
            gate,
            invocations,
            child_invocations,
            grant,
            child_grant,
            grant_receiver,
            terminal,
            child_terminal,
            terminal_push_suppressed,
            query_count,
        }
    }

    fn next_corr(&mut self) -> u64 {
        let corr = self.corr;
        self.corr = self.corr.saturating_add(1);
        corr
    }

    fn execution_status(&self) -> Result<ExecutionStatus, String> {
        let gate = self.gate.0.lock().unwrap_or_else(|poison| poison.into_inner());
        Ok(ExecutionStatus {
            entered: gate.entered,
            released: gate.release,
            invocations: self.invocations.count()?,
            child_invocations: self.child_invocations.count()?,
            executor_route: gate.executor_route.clone(),
            grant: self.grant.lock().unwrap_or_else(|poison| poison.into_inner()).clone(),
            child_grant: self
                .child_grant
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone(),
            grant_receiver: *self
                .grant_receiver
                .lock()
                .unwrap_or_else(|poison| poison.into_inner()),
            terminal: self.terminal.lock().unwrap_or_else(|poison| poison.into_inner()).clone(),
            child_terminal: self
                .child_terminal
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone(),
            terminal_push_suppressed: self.terminal_push_suppressed.load(Ordering::SeqCst),
            query_count: self.query_count.load(Ordering::SeqCst),
        })
    }

    fn release_target(&self) {
        let mut gate = self.gate.0.lock().unwrap_or_else(|poison| poison.into_inner());
        gate.release = true;
        self.gate.1.notify_all();
    }

    fn release_target_after_control(&self) {
        let mut gate = self.gate.0.lock().unwrap_or_else(|poison| poison.into_inner());
        gate.complete_after_control = true;
        gate.release = true;
        self.gate.1.notify_all();
    }

    fn pull_checkpoint(
        &mut self,
        source: CreatureId,
        blob: &BlobRefV1,
        require_gaps: bool,
    ) -> Result<PullReport, String> {
        let plan_corr = self.next_corr();
        let plan_env = rpc(
            &self.bus,
            &self.rx,
            plan_corr,
            remote_node(REALM_A, NODE_A, source),
            GX_CONTROL_SCHEMA,
            &GxRequest::Plan { blob: blob.clone(), chunk_size: CHECKPOINT_CHUNK_SIZE },
        )?;
        let plan_reply = serde_json::from_slice::<GxReply>(&plan_env.payload)
            .map_err(|error| error.to_string())?;
        let GxReply::Plan { transfer_id, file_size, file_hash, chunk_size, total_chunks } =
            plan_reply
        else {
            return Err(format!("GX source did not return a transfer plan: {plan_reply:?}"));
        };
        let plan =
            gawdxfer::TransferPlan::new(transfer_id.clone(), file_size, file_hash, chunk_size)
                .map_err(|error| error.to_string())?;
        if plan.total_chunks != total_chunks
            || format!("sha256:{}", plan.file_hash) != blob.digest
            || plan.file_size != blob.size
        {
            return Err("GX source returned a plan inconsistent with the signed checkpoint".into());
        }
        let mut assembler = gawdxfer::ChunkAssembler::with_max_file_size(plan, blob.size)
            .map_err(|error| error.to_string())?;
        let chunk_corr = self.next_corr();
        let target = remote_node(REALM_A, NODE_A, source);

        for chunk_index in 0..total_chunks {
            self.bus
                .send(
                    Dispatch::to(
                        target.clone(),
                        aether::wire::to_bytes(&GxRequest::Chunk {
                            blob: blob.clone(),
                            transfer_id: transfer_id.clone(),
                            chunk_size,
                            chunk_index,
                        }),
                    )
                    .with_schema(GX_CONTROL_SCHEMA)
                    .with_reply_to(Address::Creature(self.bus.id()))
                    .with_corr(chunk_corr),
                )
                .map_err(|error| error.to_string())?;
        }
        receive_gx_pass(&self.rx, chunk_corr, total_chunks, &mut assembler)?;
        let first_missing = assembler.missing_chunks();
        if require_gaps && first_missing.is_empty() {
            return Err("faulted GX pass unexpectedly had no gaps".into());
        }

        for batch in first_missing.chunks(GX_WINDOW) {
            for &chunk_index in batch {
                self.bus
                    .send(
                        Dispatch::to(
                            target.clone(),
                            aether::wire::to_bytes(&GxRequest::Chunk {
                                blob: blob.clone(),
                                transfer_id: transfer_id.clone(),
                                chunk_size,
                                chunk_index,
                            }),
                        )
                        .with_schema(GX_CONTROL_SCHEMA)
                        .with_reply_to(Address::Creature(self.bus.id()))
                        .with_corr(chunk_corr),
                    )
                    .map_err(|error| error.to_string())?;
            }
            receive_gx_pass(
                &self.rx,
                chunk_corr,
                u32::try_from(batch.len()).map_err(|_| "GX resume batch overflow")?,
                &mut assembler,
            )?;
        }
        if !assembler.is_complete() {
            return Err(format!("GX resume left gaps: {:?}", assembler.missing_chunks()));
        }
        let bytes = assembler.finish().map_err(|error| error.to_string())?;
        let transferred = self
            .checkpoint_store
            .put_checkpoint(&blob.media_type, &bytes)
            .map_err(|error| error.to_string())?;
        if &transferred != blob {
            return Err("destination CAS changed the checkpoint content address".into());
        }
        self.checkpoint_store.verify_available(blob).map_err(|error| error.to_string())?;
        Ok(PullReport { transferred, first_missing, total_chunks })
    }
}

fn receive_gx_pass(
    rx: &InboxReceiver,
    corr: u64,
    expected_acks: u32,
    assembler: &mut gawdxfer::ChunkAssembler,
) -> Result<(), String> {
    let deadline = Instant::now() + scaled(RPC_TIMEOUT);
    let mut acknowledgements = 0_u32;
    while acknowledgements < expected_acks && Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let env = rx
            .recv_timeout(remaining.min(Duration::from_millis(100)))
            .map_err(|error| error.to_string())?;
        if env.header.corr != Some(corr) {
            continue;
        }
        if env.header.schema == gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA {
            assembler.accept_binary_frame(&env.payload).map_err(|error| error.to_string())?;
        } else if env.header.schema == GX_CONTROL_SCHEMA {
            match serde_json::from_slice::<GxReply>(&env.payload)
                .map_err(|error| error.to_string())?
            {
                GxReply::Served { .. } => acknowledgements = acknowledgements.saturating_add(1),
                GxReply::Error { message } => return Err(message),
                GxReply::Plan { .. } => {}
            }
        }
    }
    if acknowledgements != expected_acks {
        return Err(format!("received {acknowledgements} of {expected_acks} GX acknowledgements"));
    }
    while let Ok(env) = rx.try_recv() {
        if env.header.corr == Some(corr) && env.header.schema == gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA
        {
            assembler.accept_binary_frame(&env.payload).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeDescription {
    side: String,
    generation: u32,
    pid: u32,
    source: Option<CreatureId>,
    gx_source: Option<CreatureId>,
    target: Option<CreatureId>,
    typed_target: Option<CreatureId>,
    typed_artifact_sha256: Option<String>,
    executor: Option<CreatureId>,
    ping: CreatureId,
    destination: Option<CreatureId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PullReport {
    transferred: BlobRefV1,
    first_missing: Vec<u32>,
    total_chunks: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct ExecutionStatus {
    entered: bool,
    released: bool,
    invocations: usize,
    child_invocations: usize,
    executor_route: Option<String>,
    grant: Option<SignedRecordV1<ExecutionGrantV1>>,
    child_grant: Option<SignedRecordV1<ExecutionGrantV1>>,
    grant_receiver: Option<CreatureId>,
    terminal: Option<SignedRecordV1<ExecutionReceiptV1>>,
    child_terminal: Option<SignedRecordV1<ExecutionReceiptV1>>,
    terminal_push_suppressed: bool,
    query_count: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ControlRequest {
    Describe,
    PingB { target: CreatureId },
    RegisterB { target: CreatureId },
    RegisterTypedB { target: CreatureId },
    LookupB,
    LookupTypedB,
    SubmitJob { deployment: SignedRecordV1<DeploymentReceiptV1> },
    CreateCheckpoint,
    ReadJob { destination: Option<CreatureId>, handle: JobHandleV1 },
    ReadEvents { destination: Option<CreatureId>, handle: JobHandleV1 },
    ControlJobB { destination: CreatureId, request: SignedRecordV1<JobControlV1> },
    Prepare { checkpoint: SignedRecordV1<HomeCheckpointV1> },
    StageB { destination: CreatureId, prepared: SignedRecordV1<CustodyPreparedV1> },
    ActivateB { destination: CreatureId, staged: SignedRecordV1<CustodyStagedV1> },
    ConfigureFaults { drop_once: u32, tamper_once: u32 },
    PullCheckpoint { source: CreatureId, blob: BlobRefV1, require_gaps: bool },
    SourceStatus,
    ExecutionStatus,
    ReleaseTarget,
    ReleaseTargetAfterControl,
    Shutdown,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum ControlResponse {
    Description {
        node: NodeDescription,
    },
    Pong,
    Deployment {
        message: FunctionDeployMessageV1,
    },
    Job {
        message: JobMessageV1,
    },
    Checkpoint {
        checkpoint: SignedRecordV1<HomeCheckpointV1>,
        checkpoint_chunks: u32,
        dependency: BlobRefV1,
        dependency_chunks: u32,
    },
    Prepared {
        prepared: SignedRecordV1<CustodyPreparedV1>,
    },
    Home {
        message: HomeMessageV1,
    },
    FaultsConfigured,
    Pulled {
        report: PullReport,
    },
    SourceStatus {
        status: SignedRecordV1<HomeCustodyStatusV1>,
    },
    ExecutionStatus {
        status: Box<ExecutionStatus>,
    },
    TargetReleased,
    Bye,
    Error {
        message: String,
    },
}

enum ChildNode {
    A(Box<NodeAState>),
    B(Box<NodeBState>),
}

impl ChildNode {
    fn description(&self, generation: u32) -> NodeDescription {
        match self {
            Self::A(node) => NodeDescription {
                side: "a".into(),
                generation,
                pid: std::process::id(),
                source: Some(node.source),
                gx_source: Some(node.gx_source),
                target: None,
                typed_target: None,
                typed_artifact_sha256: None,
                executor: None,
                ping: node.ping,
                destination: None,
            },
            Self::B(node) => NodeDescription {
                side: "b".into(),
                generation,
                pid: std::process::id(),
                source: None,
                gx_source: None,
                target: Some(node.target),
                typed_target: Some(node.typed_target),
                typed_artifact_sha256: node
                    .kernel
                    .loaded_manifest_identity(node.typed_target)
                    .and_then(|identity| identity.artifact_sha256),
                executor: Some(node.executor),
                ping: node.ping,
                destination: Some(node.destination),
            },
        }
    }

    fn handle(&mut self, request: ControlRequest, generation: u32) -> ControlResponse {
        let result = match request {
            ControlRequest::Describe => {
                return ControlResponse::Description { node: self.description(generation) };
            }
            ControlRequest::PingB { target } => match self {
                Self::A(node) => node.ping_b(target).map(|()| ControlResponse::Pong),
                Self::B(_) => Err("PingB belongs to node A".into()),
            },
            ControlRequest::RegisterB { target } => match self {
                Self::A(node) => {
                    node.register_b(target).map(|message| ControlResponse::Deployment { message })
                }
                Self::B(_) => Err("RegisterB belongs to node A".into()),
            },
            ControlRequest::RegisterTypedB { target } => match self {
                Self::A(node) => node
                    .register_typed_b(target)
                    .map(|message| ControlResponse::Deployment { message }),
                Self::B(_) => Err("RegisterTypedB belongs to node A".into()),
            },
            ControlRequest::LookupB => match self {
                Self::A(node) => {
                    node.lookup_b().map(|message| ControlResponse::Deployment { message })
                }
                Self::B(_) => Err("LookupB belongs to node A".into()),
            },
            ControlRequest::LookupTypedB => match self {
                Self::A(node) => {
                    node.lookup_typed_b().map(|message| ControlResponse::Deployment { message })
                }
                Self::B(_) => Err("LookupTypedB belongs to node A".into()),
            },
            ControlRequest::SubmitJob { deployment } => match self {
                Self::A(node) => {
                    node.submit_job(deployment).map(|message| ControlResponse::Job { message })
                }
                Self::B(_) => Err("SubmitJob belongs to node A".into()),
            },
            ControlRequest::CreateCheckpoint => match self {
                Self::A(node) => node.create_checkpoint().and_then(|(checkpoint, dependency)| {
                    let bytes = node
                        .checkpoint_store
                        .get_checkpoint(&checkpoint.payload.state)
                        .map_err(|error| error.to_string())?;
                    let checkpoint_plan = gawdxfer::TransferPlan::from_bytes(
                        "checkpoint-shape",
                        &bytes,
                        CHECKPOINT_CHUNK_SIZE,
                    )
                    .map_err(|error| error.to_string())?;
                    let dependency_bytes = node
                        .checkpoint_store
                        .get_checkpoint(&dependency)
                        .map_err(|error| error.to_string())?;
                    let dependency_plan = gawdxfer::TransferPlan::from_bytes(
                        "dependency-shape",
                        &dependency_bytes,
                        CHECKPOINT_CHUNK_SIZE,
                    )
                    .map_err(|error| error.to_string())?;
                    Ok(ControlResponse::Checkpoint {
                        checkpoint,
                        checkpoint_chunks: checkpoint_plan.total_chunks,
                        dependency,
                        dependency_chunks: dependency_plan.total_chunks,
                    })
                }),
                Self::B(_) => Err("CreateCheckpoint belongs to node A".into()),
            },
            ControlRequest::ReadJob { destination, handle } => match self {
                Self::A(node) => node
                    .read_job(destination, &handle)
                    .map(|message| ControlResponse::Job { message }),
                Self::B(_) => Err("ReadJob belongs to node A".into()),
            },
            ControlRequest::ReadEvents { destination, handle } => match self {
                Self::A(node) => node
                    .read_events(destination, &handle)
                    .map(|message| ControlResponse::Job { message }),
                Self::B(_) => Err("ReadEvents belongs to node A".into()),
            },
            ControlRequest::ControlJobB { destination, request } => match self {
                Self::A(node) => node
                    .control_job(destination, request)
                    .map(|message| ControlResponse::Job { message }),
                Self::B(_) => Err("ControlJobB belongs to node A".into()),
            },
            ControlRequest::Prepare { checkpoint } => match self {
                Self::A(node) => {
                    node.prepare(checkpoint).map(|prepared| ControlResponse::Prepared { prepared })
                }
                Self::B(_) => Err("Prepare belongs to node A".into()),
            },
            ControlRequest::StageB { destination, prepared } => match self {
                Self::A(node) => node
                    .home_rpc(destination, &HomeMessageV1::Stage { prepared: Box::new(prepared) })
                    .map(|message| ControlResponse::Home { message }),
                Self::B(_) => Err("StageB belongs to node A".into()),
            },
            ControlRequest::ActivateB { destination, staged } => match self {
                Self::A(node) => node
                    .home_rpc(destination, &HomeMessageV1::Activate { staged: Box::new(staged) })
                    .map(|message| ControlResponse::Home { message }),
                Self::B(_) => Err("ActivateB belongs to node A".into()),
            },
            ControlRequest::ConfigureFaults { drop_once, tamper_once } => match self {
                Self::A(node) => {
                    *node.faults.lock().unwrap_or_else(|poison| poison.into_inner()) = FaultPlan {
                        drop_once: Some(drop_once),
                        tamper_once: Some(tamper_once),
                        dropped: false,
                        tampered: false,
                    };
                    Ok(ControlResponse::FaultsConfigured)
                }
                Self::B(_) => Err("ConfigureFaults belongs to node A".into()),
            },
            ControlRequest::PullCheckpoint { source, blob, require_gaps } => match self {
                Self::B(node) => node
                    .pull_checkpoint(source, &blob, require_gaps)
                    .map(|report| ControlResponse::Pulled { report }),
                Self::A(_) => Err("PullCheckpoint belongs to node B".into()),
            },
            ControlRequest::SourceStatus => match self {
                Self::A(node) => {
                    node.source_status().map(|status| ControlResponse::SourceStatus { status })
                }
                Self::B(_) => Err("SourceStatus belongs to node A".into()),
            },
            ControlRequest::ExecutionStatus => match self {
                Self::B(node) => node
                    .execution_status()
                    .map(|status| ControlResponse::ExecutionStatus { status: Box::new(status) }),
                Self::A(_) => Err("ExecutionStatus belongs to node B".into()),
            },
            ControlRequest::ReleaseTarget => match self {
                Self::B(node) => {
                    node.release_target();
                    Ok(ControlResponse::TargetReleased)
                }
                Self::A(_) => Err("ReleaseTarget belongs to node B".into()),
            },
            ControlRequest::ReleaseTargetAfterControl => match self {
                Self::B(node) => {
                    node.release_target_after_control();
                    Ok(ControlResponse::TargetReleased)
                }
                Self::A(_) => Err("ReleaseTargetAfterControl belongs to node B".into()),
            },
            ControlRequest::Shutdown => return ControlResponse::Bye,
        };
        result.unwrap_or_else(|message| ControlResponse::Error { message })
    }

    fn shutdown(&self) {
        match self {
            Self::A(node) => node.kernel.shutdown_all(Deadline::from_millis(1500)),
            Self::B(node) => node.kernel.shutdown_all(Deadline::from_millis(1500)),
        }
    }
}

fn child_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("child environment omitted `{name}`"))
}

#[test]
#[ignore = "subprocess entrypoint; run by process proof parent"]
fn process_node_child() {
    let side = child_env("GAWD_PROCESS_NODE_SIDE");
    let root = PathBuf::from(child_env("GAWD_PROCESS_ROOT"));
    let port_a = child_env("GAWD_PROCESS_PORT_A").parse::<u16>().expect("port A");
    let port_b = child_env("GAWD_PROCESS_PORT_B").parse::<u16>().expect("port B");
    let generation = child_env("GAWD_PROCESS_GENERATION").parse::<u32>().expect("generation");
    let control_port = child_env("GAWD_PROCESS_CONTROL_PORT").parse::<u16>().expect("control port");
    let public = PublicFixture::load(&root).expect("public fixture");
    eprintln!("process-proof child {side} generation {generation} booting");
    let mut node = match side.as_str() {
        "a" => ChildNode::A(Box::new(NodeAState::boot(&root, port_a, port_b, public))),
        "b" => ChildNode::B(Box::new(NodeBState::boot(&root, port_a, port_b, generation, public))),
        _ => panic!("unknown process node side `{side}`"),
    };
    eprintln!("process-proof child {side} generation {generation} control-ready");

    let control = TcpListener::bind(("127.0.0.1", control_port)).expect("bind child control");
    let (stream, _) = control.accept().expect("accept parent control");
    stream
        .set_read_timeout(Some(scaled(CONTROL_TIMEOUT)))
        .expect("bound child control read timeout");
    stream
        .set_write_timeout(Some(scaled(CONTROL_TIMEOUT)))
        .expect("bound child control write timeout");
    let mut input = BufReader::new(stream.try_clone().expect("clone child control stream"));
    let mut output = BufWriter::new(stream);
    loop {
        let mut line = String::new();
        let read = input.read_line(&mut line).expect("read parent control request");
        if read == 0 {
            node.shutdown();
            return;
        }
        let response = if line.len() > MAX_CONTROL_BYTES {
            ControlResponse::Error { message: "control request exceeds byte cap".into() }
        } else {
            match serde_json::from_str::<ControlRequest>(line.trim_end()) {
                Ok(ControlRequest::Shutdown) => {
                    node.shutdown();
                    ControlResponse::Bye
                }
                Ok(request) => node.handle(request, generation),
                Err(error) => ControlResponse::Error { message: error.to_string() },
            }
        };
        let encoded = serde_json::to_string(&response).expect("encode child control response");
        assert!(encoded.len() <= MAX_CONTROL_BYTES, "control response exceeds byte cap");
        writeln!(output, "{CONTROL_PREFIX}{encoded}").expect("write child control response");
        output.flush().expect("flush child control response");
        if matches!(response, ControlResponse::Bye) {
            return;
        }
    }
}

struct NodeChild {
    side: &'static str,
    child: Child,
    input: BufWriter<TcpStream>,
    responses: BufReader<TcpStream>,
    log_path: PathBuf,
}

impl NodeChild {
    fn spawn(side: &'static str, generation: u32, root: &Path, port_a: u16, port_b: u16) -> Self {
        let control_port = free_loopback_port();
        let log_path = root.join(format!("node-{side}-generation-{generation}.stderr.log"));
        let log = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&log_path)
            .expect("open child stderr log");
        let mut child = Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--ignored", "--exact", "process_node_child", "--nocapture", "--test-threads=1"])
            .env("GAWD_PROCESS_NODE_SIDE", side)
            .env("GAWD_PROCESS_ROOT", root)
            .env("GAWD_PROCESS_PORT_A", port_a.to_string())
            .env("GAWD_PROCESS_PORT_B", port_b.to_string())
            .env("GAWD_PROCESS_GENERATION", generation.to_string())
            .env("GAWD_PROCESS_CONTROL_PORT", control_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log))
            .spawn()
            .unwrap_or_else(|error| panic!("spawn node {side}: {error}"));
        let deadline = Instant::now() + scaled(CONTROL_TIMEOUT);
        let stream = loop {
            match TcpStream::connect(("127.0.0.1", control_port)) {
                Ok(stream) => break stream,
                Err(error) => {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            let stderr = fs::read_to_string(&log_path).unwrap_or_default();
                            panic!("node {side} exited during boot with {status}: {error}; stderr:\n{stderr}");
                        }
                        Ok(None) => {}
                        Err(poll_error) => {
                            let _ = child.kill();
                            let _ = child.wait();
                            let stderr = fs::read_to_string(&log_path).unwrap_or_default();
                            panic!(
                                "could not poll starting node {side}: {poll_error}; last connect error: {error}; stderr:\n{stderr}"
                            );
                        }
                    }
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        let stderr = fs::read_to_string(&log_path).unwrap_or_default();
                        panic!(
                            "node {side} control did not become ready: {error}; stderr:\n{stderr}"
                        );
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        stream
            .set_read_timeout(Some(scaled(CONTROL_TIMEOUT)))
            .expect("parent control read timeout");
        stream
            .set_write_timeout(Some(scaled(CONTROL_TIMEOUT)))
            .expect("parent control write timeout");
        let input = BufWriter::new(stream.try_clone().expect("clone parent control stream"));
        let responses = BufReader::new(stream);
        Self { side, child, input, responses, log_path }
    }

    fn request(&mut self, request: &ControlRequest) -> ControlResponse {
        let encoded = serde_json::to_string(request).expect("encode parent control request");
        assert!(encoded.len() <= MAX_CONTROL_BYTES, "control request exceeds byte cap");
        writeln!(self.input, "{encoded}").expect("write parent control request");
        self.input.flush().expect("flush parent control request");
        let mut line = String::new();
        self.responses.read_line(&mut line).unwrap_or_else(|error| {
            panic!(
                "node {} did not answer control request: {error}; stderr:\n{}",
                self.side,
                self.log_contents()
            )
        });
        let encoded = line
            .trim_end()
            .strip_prefix(CONTROL_PREFIX)
            .unwrap_or_else(|| panic!("node {} returned malformed control framing", self.side));
        serde_json::from_str(encoded).expect("decode child control response")
    }

    fn description(&mut self) -> NodeDescription {
        match self.request(&ControlRequest::Describe) {
            ControlResponse::Description { node } => node,
            other => panic!("node {} did not describe itself: {other:?}", self.side),
        }
    }

    fn hard_kill(&mut self) {
        if self.child.try_wait().expect("poll child before kill").is_none() {
            self.child.kill().expect("hard-kill child");
        }
        self.child.wait().expect("reap hard-killed child");
    }

    fn graceful_shutdown(&mut self) {
        if self.child.try_wait().expect("poll child before shutdown").is_some() {
            return;
        }
        assert!(matches!(self.request(&ControlRequest::Shutdown), ControlResponse::Bye));
        let deadline = Instant::now() + scaled(Duration::from_secs(5));
        loop {
            if self.child.try_wait().expect("poll child shutdown").is_some() {
                return;
            }
            if Instant::now() >= deadline {
                self.hard_kill();
                panic!("node {} did not exit after graceful shutdown", self.side);
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn log_contents(&self) -> String {
        fs::read_to_string(&self.log_path).unwrap_or_else(|error| format!("<unreadable: {error}>"))
    }
}

impl Drop for NodeChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn free_loopback_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .expect("reserve loopback port")
        .local_addr()
        .expect("reserved loopback address")
        .port()
}

fn free_loopback_pair() -> (u16, u16) {
    let a = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port A");
    let b = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port B");
    let ports = (
        a.local_addr().expect("port A address").port(),
        b.local_addr().expect("port B address").port(),
    );
    drop((a, b));
    ports
}

fn unique_root() -> PathBuf {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).expect("system clock").as_nanos();
    let root = std::env::temp_dir()
        .join(format!("alpha-function-process-gx-{}-{unique}", std::process::id()));
    fs::create_dir_all(&root).expect("create process proof root");
    root
}

fn await_application_route(a: &mut NodeChild, b_ping: CreatureId) {
    let deadline = Instant::now() + scaled(Duration::from_secs(20));
    loop {
        if matches!(a.request(&ControlRequest::PingB { target: b_ping }), ControlResponse::Pong) {
            return;
        }
        assert!(Instant::now() < deadline, "authenticated Omega application route did not recover");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn response_deployment(response: ControlResponse) -> FunctionDeployMessageV1 {
    match response {
        ControlResponse::Deployment { message } => message,
        ControlResponse::Error { message } => panic!("deployment control failed: {message}"),
        other => panic!("unexpected deployment control response: {other:?}"),
    }
}

fn execution_status(node: &mut NodeChild) -> ExecutionStatus {
    match node.request(&ControlRequest::ExecutionStatus) {
        ControlResponse::ExecutionStatus { status } => *status,
        ControlResponse::Error { message } => panic!("execution status failed: {message}"),
        other => panic!("unexpected execution status response: {other:?}"),
    }
}

fn wait_for_target_entry(node: &mut NodeChild) -> ExecutionStatus {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    loop {
        let status = execution_status(node);
        if status.entered {
            return status;
        }
        assert!(Instant::now() < deadline, "proof-valid target was never invoked");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_terminal(node: &mut NodeChild) -> ExecutionStatus {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    loop {
        let status = execution_status(node);
        if status.terminal.is_some() {
            return status;
        }
        assert!(Instant::now() < deadline, "executor did not durably record the terminal receipt");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_child_grant(node: &mut NodeChild) -> ExecutionStatus {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    loop {
        let status = execution_status(node);
        if status.child_grant.is_some() {
            return status;
        }
        assert!(Instant::now() < deadline, "executor did not receive the causal child Grant");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_child_terminal(node: &mut NodeChild) -> ExecutionStatus {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    loop {
        let status = execution_status(node);
        if status.child_terminal.is_some() {
            return status;
        }
        assert!(Instant::now() < deadline, "executor did not durably record the child terminal");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_job_state(
    node: &mut NodeChild,
    destination: Option<CreatureId>,
    handle: &JobHandleV1,
    expected: JobStateV1,
) -> SignedRecordV1<JobSnapshotV1> {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    loop {
        let last =
            match node.request(&ControlRequest::ReadJob { destination, handle: handle.clone() }) {
                ControlResponse::Job { message: JobMessageV1::Snapshot { response } } => {
                    let snapshot = *response.payload.snapshot;
                    if snapshot.payload.state == expected {
                        return snapshot;
                    }
                    format!("snapshot state {:?}", snapshot.payload.state)
                }
                ControlResponse::Job { message: JobMessageV1::Error { error } } => {
                    format!("{}: {}", error.code, error.message)
                }
                ControlResponse::Error { message } => message,
                other => format!("unexpected response {other:?}"),
            };
        assert!(Instant::now() < deadline, "Job did not reach {expected:?}; last response: {last}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_event_page(
    node: &mut NodeChild,
    destination: Option<CreatureId>,
    handle: &JobHandleV1,
    ready: impl Fn(&EventPageV1) -> bool,
) -> EventPageV1 {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    loop {
        let last = match node
            .request(&ControlRequest::ReadEvents { destination, handle: handle.clone() })
        {
            ControlResponse::Job { message: JobMessageV1::EventPage { response } } => {
                let page = response.payload.page;
                if ready(&page) {
                    return page;
                }
                format!(
                    "event high-water mark {:?}",
                    page.events.last().map(|event| event.payload.sequence)
                )
            }
            ControlResponse::Job { message: JobMessageV1::Error { error } } => {
                format!("{}: {}", error.code, error.message)
            }
            ControlResponse::Error { message } => message,
            other => format!("unexpected response {other:?}"),
        };
        assert!(Instant::now() < deadline, "event predicate was not satisfied; last: {last}");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn accepted_control_event(
    response: ControlResponse,
    request: &SignedRecordV1<JobControlV1>,
) -> SignedRecordV1<gawdfn::JobEventV1> {
    let ControlResponse::Job { message: JobMessageV1::ControlAccepted { request_hash, event } } =
        response
    else {
        panic!("Home did not accept the causal control: {response:?}")
    };
    verify_job_control_acceptance(request, &request_hash, &event)
        .expect("causal control acceptance proof");
    *event
}

struct RootCleanup(PathBuf);

impl Drop for RootCleanup {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct StagedProcessScenario {
    root: PathBuf,
    public: PublicFixture,
    port_a: u16,
    port_b: u16,
    a: NodeChild,
    b: NodeChild,
    a1: NodeDescription,
    b2: NodeDescription,
    handle: JobHandleV1,
    grant: SignedRecordV1<ExecutionGrantV1>,
    typed_deployment: SignedRecordV1<DeploymentReceiptV1>,
    progress: SignedRecordV1<gawdfn::JobEventV1>,
    prepared: SignedRecordV1<CustodyPreparedV1>,
    staged: SignedRecordV1<CustodyStagedV1>,
    cleanup: RootCleanup,
}

fn stage_running_process_scenario() -> StagedProcessScenario {
    let root = unique_root();
    let cleanup = RootCleanup(root.clone());
    let public = PublicFixture::create();
    let public_bytes = serde_json::to_vec_pretty(&public).expect("encode public fixture");
    fs::write(root.join("fixture-public.json"), public_bytes).expect("write public fixture");
    let (port_a, port_b) = free_loopback_pair();

    let mut b = NodeChild::spawn("b", 1, &root, port_a, port_b);
    let b1 = b.description();
    let mut a = NodeChild::spawn("a", 1, &root, port_a, port_b);
    let a1 = a.description();
    assert_ne!(a1.pid, b1.pid, "the two Sanctums must be distinct OS processes");
    await_application_route(&mut a, b1.ping);

    let target = b1.target.expect("B target ID");
    let typed_target = b1.typed_target.expect("B typed critter target ID");
    let measured_typed_artifact = b1
        .typed_artifact_sha256
        .as_deref()
        .and_then(normalize_sha256)
        .expect("B reports the independently measured typed critter artifact hash");
    assert_eq!(
        measured_typed_artifact, public.typed_artifact_hash,
        "the loaded critter bytes must match the signed deployment artifact pin"
    );
    let first_executor = b1.executor.expect("B executor ID");
    let registered = response_deployment(a.request(&ControlRequest::RegisterB { target }));
    let FunctionDeployMessageV1::Registered { receipt: deployment } = registered else {
        panic!("remote executor did not register the deployment: {registered:?}")
    };
    verify_deployment_receipt(&deployment).expect("deployment receipt");
    assert_eq!(deployment.payload.creature, target.0.to_string());
    assert_eq!(deployment.payload.executor_creature, first_executor.0.to_string());
    let typed_registered =
        response_deployment(a.request(&ControlRequest::RegisterTypedB { target: typed_target }));
    let FunctionDeployMessageV1::Registered { receipt: typed_deployment } = typed_registered else {
        panic!("remote executor did not register the typed critter: {typed_registered:?}")
    };
    verify_deployment_receipt(&typed_deployment).expect("typed critter deployment receipt");
    assert_eq!(typed_deployment.payload.function, public.typed_function);
    assert_eq!(typed_deployment.payload.artifact_hash, measured_typed_artifact);
    assert_eq!(typed_deployment.payload.creature, typed_target.0.to_string());
    assert_eq!(typed_deployment.payload.executor_creature, first_executor.0.to_string());

    // Hard cut 1: both registrations are fsynced. Generation 2 inserts a filler after the stable
    // parent and critter targets and before the executor, forcing a new process-local executor ID
    // without changing either signed target pin or durable registration.
    b.hard_kill();
    let mut b = NodeChild::spawn("b", 2, &root, port_a, port_b);
    let b2 = b.description();
    assert_ne!(b1.pid, b2.pid, "B restart must create a new OS process");
    assert_eq!(b2.target, Some(target), "filler must not change the target ID");
    assert_eq!(
        b2.typed_target,
        Some(typed_target),
        "filler must not change the typed critter target ID"
    );
    assert_eq!(
        b2.typed_artifact_sha256.as_deref().and_then(normalize_sha256),
        Some(public.typed_artifact_hash.clone()),
        "B must remeasure the same checked-in critter bytes after hard restart"
    );
    assert_ne!(b2.executor, Some(first_executor), "filler must change executor ID");
    await_application_route(&mut a, b2.ping);

    let looked_up = response_deployment(a.request(&ControlRequest::LookupB));
    let FunctionDeployMessageV1::Deployments { list } = looked_up else {
        panic!("restarted executor did not answer lookup: {looked_up:?}")
    };
    assert_eq!(list.deployments, vec![deployment.clone()]);
    assert_eq!(
        list.deployments[0].payload.executor_creature,
        first_executor.0.to_string(),
        "the immutable receipt remains audit history while NodeRole reaches the new executor"
    );
    let typed_looked_up = response_deployment(a.request(&ControlRequest::LookupTypedB));
    let FunctionDeployMessageV1::Deployments { list: typed_list } = typed_looked_up else {
        panic!("restarted executor did not answer typed lookup: {typed_looked_up:?}")
    };
    assert_eq!(
        typed_list.deployments,
        vec![typed_deployment.clone()],
        "the measured critter registration must reopen durably after the hard cut"
    );

    // Submit through the bound source Home creature. Its durable acceptance drives the real basic
    // policy socket, which selects the immutable deployment and dispatches a signed Grant through
    // Omega(NodeRole) to B's changed-ID executor.
    let submit_response = a.request(&ControlRequest::SubmitJob { deployment: deployment.clone() });
    let ControlResponse::Job {
        message: JobMessageV1::Accepted { handle, request_hash, submitted },
    } = submit_response
    else {
        panic!("source Home did not durably accept the Job: {submit_response:?}")
    };
    verify_job_acceptance(&handle, &request_hash, &submitted).expect("Job acceptance proof");
    let live_executor = b2.executor.expect("changed executor ID");
    let running_target = wait_for_target_entry(&mut b);
    assert_eq!(running_target.invocations, 1, "target must execute exactly once");
    assert_eq!(running_target.grant_receiver, Some(live_executor));
    assert_eq!(running_target.executor_route, Some(live_executor.0.to_string()));
    let grant = running_target.grant.clone().expect("executor captured the exact Grant");
    assert_eq!(grant.payload.deployment, deployment);
    assert_eq!(grant.payload.input, ValueRefV1::Blob { blob: public.job_input.clone() });
    let running = wait_for_job_state(&mut a, None, &handle, JobStateV1::Running);
    assert_eq!(running.payload.home_epoch, 1);
    assert_eq!(running.payload.spec.input, ValueRefV1::Blob { blob: public.job_input.clone() });

    let parent_events = wait_for_event_page(&mut a, None, &handle, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
    });
    for event in &parent_events.events {
        verify_job_event(event).expect("source Home event proof");
    }
    let dispatch = parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::DispatchGranted { .. }))
        .expect("injected policy must leave a durable DispatchGranted event");
    let JobEventKindV1::DispatchGranted { grant_hash, attempt } = &dispatch.payload.kind else {
        unreachable!()
    };
    assert_eq!(grant_hash, &canonical_hash(&grant).expect("Grant hash"));
    assert_eq!(attempt, &grant.payload.attempt);
    let progress = parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        .cloned()
        .expect("source Home must durably retain executor-authenticated progress");
    verify_job_event_with_grant(&progress, &grant).expect("source progress proof");
    let JobEventKindV1::Progress { attempt, sequence, progress: value } = &progress.payload.kind
    else {
        unreachable!()
    };
    assert_eq!(attempt, &grant.payload.attempt);
    assert_eq!(*sequence, 1);
    assert_eq!(
        value,
        &ValueRefV1::Inline { value: json!({"phase": "remote-ready", "realm": REALM_B}) }
    );
    let progress_receipt =
        progress.payload.foreign_receipt.as_deref().expect("progress retains the executor receipt");
    verify_execution_receipt(progress_receipt, &grant).expect("executor progress receipt");
    assert_eq!(progress_receipt.signer, public.executor_public);

    let checkpoint_response = a.request(&ControlRequest::CreateCheckpoint);
    let ControlResponse::Checkpoint {
        checkpoint,
        checkpoint_chunks,
        dependency,
        dependency_chunks,
    } = checkpoint_response
    else {
        panic!("source failed to create checkpoint: {checkpoint_response:?}")
    };
    assert!(checkpoint_chunks >= 1, "checkpoint must have at least one GX chunk");
    assert!(dependency_chunks >= 3, "fault proof needs at least three dependency chunks");
    let prepared_response = a.request(&ControlRequest::Prepare { checkpoint: checkpoint.clone() });
    let ControlResponse::Prepared { prepared } = prepared_response else {
        panic!("source failed to prepare custody: {prepared_response:?}")
    };
    let destination = b2.destination.expect("B destination ID");

    let pretransfer =
        a.request(&ControlRequest::StageB { destination, prepared: prepared.clone() });
    let ControlResponse::Home { message: HomeMessageV1::Error { error } } = pretransfer else {
        panic!("Stage unexpectedly succeeded before GX bytes were available: {pretransfer:?}")
    };
    assert!(
        error.message.contains("checkpoint bytes unavailable"),
        "pre-transfer refusal must name the missing checkpoint, got: {}",
        error.message
    );

    let gx_source = a1.gx_source.expect("A GX source ID");
    let checkpoint_pull = b.request(&ControlRequest::PullCheckpoint {
        source: gx_source,
        blob: checkpoint.payload.state.clone(),
        require_gaps: false,
    });
    let ControlResponse::Pulled { report: checkpoint_report } = checkpoint_pull else {
        panic!(
            "destination checkpoint GX pull failed: {checkpoint_pull:?}; B stderr:\n{}",
            b.log_contents()
        )
    };
    assert_eq!(checkpoint_report.transferred, checkpoint.payload.state);
    assert!(checkpoint_report.first_missing.is_empty());
    assert_eq!(checkpoint_report.total_chunks, checkpoint_chunks);

    let missing_dependency =
        a.request(&ControlRequest::StageB { destination, prepared: prepared.clone() });
    let ControlResponse::Home { message: HomeMessageV1::Error { error } } = missing_dependency
    else {
        panic!("Stage unexpectedly succeeded without its referenced value: {missing_dependency:?}")
    };
    assert!(
        error.message.contains("dependency is unavailable"),
        "archive-only refusal must name the missing dependency, got: {}",
        error.message
    );

    assert!(matches!(
        a.request(&ControlRequest::ConfigureFaults { drop_once: 1, tamper_once: 2 }),
        ControlResponse::FaultsConfigured
    ));
    let dependency_pull = b.request(&ControlRequest::PullCheckpoint {
        source: gx_source,
        blob: dependency.clone(),
        require_gaps: true,
    });
    let ControlResponse::Pulled { report: dependency_report } = dependency_pull else {
        panic!(
            "destination dependency GX pull failed: {dependency_pull:?}; B stderr:\n{}",
            b.log_contents()
        )
    };
    assert_eq!(dependency_report.transferred, dependency);
    assert_eq!(dependency_report.first_missing, vec![1, 2]);
    assert_eq!(dependency_report.total_chunks, dependency_chunks);

    let staged_response =
        a.request(&ControlRequest::StageB { destination, prepared: prepared.clone() });
    let ControlResponse::Home { message: HomeMessageV1::Staged { staged } } = staged_response
    else {
        panic!("destination did not Stage after verified GX commit: {staged_response:?}")
    };
    let staged = *staged;
    verify_custody_staged(&staged).expect("staged proof");

    let staged_execution = execution_status(&mut b);
    assert!(staged_execution.entered && !staged_execution.released);
    assert_eq!(staged_execution.invocations, 1);
    assert_eq!(staged_execution.child_invocations, 0);
    assert!(staged_execution.terminal.is_none());
    assert_eq!(
        staged.payload.prepared.payload.checkpoint.payload.high_water_mark,
        checkpoint.payload.high_water_mark,
        "Stage must preserve the checkpoint of the genuinely Running Job"
    );

    StagedProcessScenario {
        root,
        public,
        port_a,
        port_b,
        a,
        b,
        a1,
        b2,
        handle,
        grant,
        typed_deployment,
        progress,
        prepared,
        staged,
        cleanup,
    }
}

#[test]
fn two_process_restart_and_faulted_gx_resume_before_custody_stage() {
    if std::env::var_os("GAWD_PROCESS_NODE_SIDE").is_some() {
        return;
    }
    let StagedProcessScenario {
        root,
        public,
        port_a,
        port_b,
        mut a,
        mut b,
        a1,
        b2,
        handle,
        grant,
        typed_deployment: _typed_deployment,
        progress,
        prepared,
        staged,
        cleanup: _cleanup,
    } = stage_running_process_scenario();

    assert!(matches!(b.request(&ControlRequest::ReleaseTarget), ControlResponse::TargetReleased));
    let terminal_status = wait_for_terminal(&mut b);
    assert_eq!(terminal_status.invocations, 1);
    assert_eq!(terminal_status.child_invocations, 0);
    assert!(terminal_status.terminal_push_suppressed);
    let terminal = terminal_status.terminal.expect("durable terminal receipt");
    verify_execution_receipt(&terminal, &grant).expect("terminal executor proof");
    assert!(matches!(
        &terminal.payload.stage,
        ExecutionStageV1::Succeeded {
            result: ValueRefV1::Inline { value },
        } if value == &json!({"answer": 42})
    ));

    // Hard cut 2: Stage is fsynced and both GX objects are fully committed. Kill both Sanctums;
    // we intentionally do not kill inside a transfer because this proof uses ChunkAssembler's
    // in-memory gap bitmap.
    b.hard_kill();
    a.hard_kill();
    let mut b = NodeChild::spawn("b", 2, &root, port_a, port_b);
    let b3 = b.description();
    let mut a = NodeChild::spawn("a", 2, &root, port_a, port_b);
    let a2 = a.description();
    assert_ne!(b2.pid, b3.pid, "second B restart must create a new OS process");
    assert_ne!(a1.pid, a2.pid, "A restart must create a new OS process");
    assert_eq!(b3.target, b2.target);
    assert_eq!(b3.typed_target, b2.typed_target);
    assert_eq!(b3.typed_artifact_sha256, b2.typed_artifact_sha256);
    assert_eq!(b3.executor, b2.executor);
    assert_eq!(b3.destination, b2.destination);
    assert_eq!(a2.source, a1.source, "source coordinator route must reopen stably");
    assert_eq!(a2.gx_source, a1.gx_source, "GX source route must reopen stably");
    await_application_route(&mut a, b3.ping);

    let source_status = a.request(&ControlRequest::SourceStatus);
    let ControlResponse::SourceStatus { status } = source_status else {
        panic!("reopened source did not return custody status: {source_status:?}")
    };
    verify_home_custody_status(&status).expect("reopened source custody status");
    let HomeCustodyPhaseV1::Frozen { prepared: recovered, redirect: None } = status.payload.state
    else {
        panic!("reopened source was not frozen before activation: {:?}", status.payload.state)
    };
    assert_eq!(*recovered, prepared, "source must recover the exact Prepared proof");

    let replay = a.request(&ControlRequest::StageB {
        destination: b3.destination.expect("reopened destination ID"),
        prepared: prepared.clone(),
    });
    let ControlResponse::Home { message: HomeMessageV1::Staged { staged: replayed } } = replay
    else {
        panic!("reopened destination did not replay Stage: {replay:?}")
    };
    assert_eq!(*replayed, staged, "Stage replay must recover the exact durable proof");
    let activated = a.request(&ControlRequest::ActivateB {
        destination: b3.destination.expect("reopened destination ID"),
        staged,
    });
    let ControlResponse::Home { message: HomeMessageV1::Activated { lease } } = activated else {
        panic!("reopened destination did not activate: {activated:?}")
    };
    verify_home_lease(&lease).expect("activated Home lease");
    assert_eq!(lease.payload.realm, REALM_B);
    assert_eq!(lease.payload.node, NODE_B);

    let destination = b3.destination.expect("active destination ID");
    let succeeded = wait_for_job_state(&mut a, Some(destination), &handle, JobStateV1::Succeeded);
    assert_eq!(succeeded.payload.home_epoch, 2);
    assert_eq!(succeeded.payload.result, Some(ValueRefV1::Inline { value: json!({"answer": 42}) }));
    assert_eq!(succeeded.payload.spec.input, ValueRefV1::Blob { blob: public.job_input.clone() });

    let events_response = a.request(&ControlRequest::ReadEvents {
        destination: Some(destination),
        handle: handle.clone(),
    });
    let ControlResponse::Job { message: JobMessageV1::EventPage { response } } = events_response
    else {
        panic!("moved Home did not return its event proof chain: {events_response:?}")
    };
    let EventPageV1 { events, .. } = response.payload.page;
    for event in &events {
        verify_job_event(event).expect("moved Home event proof");
    }
    let moved_progress = events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        .expect("moved Home retains source progress");
    assert_eq!(moved_progress, &progress);
    assert_eq!(
        serde_json::to_vec(moved_progress).expect("encode moved progress"),
        serde_json::to_vec(&progress).expect("encode source progress"),
        "custody movement must preserve the exact signed progress bytes"
    );
    let terminal_event = events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
        .expect("moved Home must durably reconcile the terminal event");
    verify_job_event_with_grant(terminal_event, &grant).expect("terminal Home event proof");
    let recovered_terminal = terminal_event
        .payload
        .foreign_receipt
        .as_deref()
        .expect("terminal Home event retains the foreign executor proof");
    assert_eq!(
        recovered_terminal, &terminal,
        "moved Home must recover the exact pre-crash terminal receipt"
    );

    let recovered_execution = execution_status(&mut b);
    assert_eq!(recovered_execution.invocations, 1, "recovery must not invoke the target again");
    assert_eq!(recovered_execution.child_invocations, 0);
    assert!(
        recovered_execution.query_count >= 1,
        "activated moved Home must Query the reopened executor for the lost push"
    );
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(execution_status(&mut b).invocations, 1, "terminal reconciliation is not execution");

    b.graceful_shutdown();
    a.graceful_shutdown();
}

#[test]
fn two_process_moved_home_deduplicates_causal_child_and_recovers_parent_terminal() {
    if std::env::var_os("GAWD_PROCESS_NODE_SIDE").is_some() {
        return;
    }
    let StagedProcessScenario {
        root,
        public,
        port_a,
        port_b,
        mut a,
        mut b,
        a1,
        b2,
        handle,
        grant,
        typed_deployment,
        progress,
        prepared,
        staged,
        cleanup: _cleanup,
    } = stage_running_process_scenario();
    let destination = b2.destination.expect("staged destination ID");

    // Activate while the parent target remains blocked. This makes the imported epoch-1 Progress
    // available to the authoritative epoch-2 Home while the parent is still legally able to spawn
    // a causal child; no timing race with terminal reconciliation is involved.
    let activated = a.request(&ControlRequest::ActivateB { destination, staged: staged.clone() });
    let ControlResponse::Home { message: HomeMessageV1::Activated { lease } } = activated else {
        panic!("destination did not activate while the parent was Running: {activated:?}")
    };
    verify_home_lease(&lease).expect("active destination lease");
    assert_eq!(lease.payload.realm, REALM_B);
    assert_eq!(lease.payload.node, NODE_B);
    let routed_destination = CreatureId(
        lease.payload.coordinator.parse().expect("lease coordinator is a numeric creature route"),
    );
    assert_eq!(routed_destination, destination);
    let destination = routed_destination;

    let moved_parent_events = wait_for_event_page(&mut a, Some(destination), &handle, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
    });
    for event in &moved_parent_events.events {
        verify_job_event(event).expect("moved parent event proof");
    }
    let moved_progress = moved_parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        .expect("active moved Home retains parent Progress");
    assert_eq!(moved_progress, &progress);
    assert_eq!(
        serde_json::to_vec(moved_progress).expect("encode moved Progress"),
        serde_json::to_vec(&progress).expect("encode source Progress"),
        "Stage/Activate must preserve the signed Progress bytes exactly"
    );
    let JobEventKindV1::Progress { attempt: parent_attempt, .. } = &progress.payload.kind else {
        unreachable!()
    };
    let progress_hash = canonical_hash(&progress).expect("Progress event hash");

    let root_signer = Ed25519SeedSigner::from_seed(ROOT_SEED).expect("root key");
    let steer = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            handle: handle.clone(),
            expected_home_epoch: 2,
            control: ControlId::new("process-cross-realm-parent-steer"),
            issued_at_unix_ms: None,
            kind: JobControlKindV1::Steer {
                value: ValueRefV1::Inline { value: json!({"pace": "finish"}) },
            },
        },
        &root_signer,
    )
    .expect("sign moved-Home steer");
    let steer_requested = accepted_control_event(
        a.request(&ControlRequest::ControlJobB { destination, request: steer.clone() }),
        &steer,
    );
    assert!(matches!(
        &steer_requested.payload.kind,
        JobEventKindV1::ControlRequested { request, attempt: Some(selected) }
            if request.as_ref() == &steer && selected == parent_attempt
    ));
    let parent_with_queued_steer =
        wait_for_event_page(&mut a, Some(destination), &handle, |page| {
            page.events.iter().any(|event| {
                matches!(
                    &event.payload.kind,
                    JobEventKindV1::ControlQueued { control, attempt }
                        if control == &steer.payload.control && attempt == parent_attempt
                )
            })
        });
    let steer_queued = parent_with_queued_steer
        .events
        .iter()
        .find(|event| {
            matches!(
                &event.payload.kind,
                JobEventKindV1::ControlQueued { control, attempt }
                    if control == &steer.payload.control && attempt == parent_attempt
            )
        })
        .expect("moved Home durably records the cross-Realm queued steer");
    verify_job_event_with_grant(steer_queued, &grant).expect("queued steer Home proof");
    let queued_receipt = steer_queued
        .payload
        .foreign_receipt
        .as_deref()
        .expect("queued steer retains the executor receipt");
    verify_execution_receipt(queued_receipt, &grant).expect("queued steer executor proof");
    assert!(matches!(
        &queued_receipt.payload.stage,
        ExecutionStageV1::ControlQueued { control } if control == &steer.payload.control
    ));

    let child_submit = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSubmitV1 {
            home: public.home.clone(),
            caller_idempotency_key: "process-cross-realm-child".into(),
            function: FunctionSelectorV1::Alias { alias: public.typed_alias.clone() },
            input: child_input(),
            delivery: DeliveryModeV1::AtMostOnce,
            allow_duplicate_effects: false,
            parent: Some(handle.clone()),
            causal: vec![gawdfn::CausalLinkV1 {
                job: handle.clone(),
                relation: "spawned_by_progress".into(),
                receipt_hash: Some(progress_hash.clone()),
            }],
            access: JobAccessV1::default(),
            evidence: vec![],
            result_recipients: vec![],
            submitted_at_unix_ms: None,
        },
        &root_signer,
    )
    .expect("sign child submission");
    let child_request_hash = child_submit.payload.request_hash().expect("child request hash");
    let spawn = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            handle: handle.clone(),
            expected_home_epoch: 2,
            control: ControlId::new("process-spawn-cross-realm-child"),
            issued_at_unix_ms: None,
            kind: JobControlKindV1::ProposeChild {
                parent_attempt: parent_attempt.clone(),
                parent_event_hash: progress_hash.clone(),
                spawn_key: "process-remote-progress-child".into(),
                child_request_hash: child_request_hash.clone(),
                submit: Box::new(child_submit),
                resolution: Box::new(public.typed_resolution()),
                deployment: Box::new(typed_deployment.clone()),
            },
        },
        &root_signer,
    )
    .expect("sign causal child proposal");

    let spawned = accepted_control_event(
        a.request(&ControlRequest::ControlJobB { destination, request: spawn.clone() }),
        &spawn,
    );
    let child = match &spawned.payload.kind {
        JobEventKindV1::ChildSpawned {
            parent_attempt: recorded_attempt,
            parent_event_hash,
            spawn_key,
            child,
            root,
            child_request_hash: recorded_request_hash,
        } => {
            assert_eq!(recorded_attempt, parent_attempt);
            assert_eq!(parent_event_hash, &progress_hash);
            assert_eq!(spawn_key, "process-remote-progress-child");
            assert_eq!(root, &handle);
            assert_eq!(recorded_request_hash, &child_request_hash);
            child.clone()
        }
        other => panic!("expected durable ChildSpawned edge, got {other:?}"),
    };
    let replayed = accepted_control_event(
        a.request(&ControlRequest::ControlJobB { destination, request: spawn.clone() }),
        &spawn,
    );
    assert_eq!(
        replayed, spawned,
        "duplicate ProposeChild must return the exact durable causal edge"
    );

    // The child Grant reaches the changed-ID executor and the independently loaded Rhai target
    // while the in-process parent remains blocked. The duplicate proposal must not create a second
    // child execution.
    let queued_child = wait_for_child_grant(&mut b);
    assert_eq!(queued_child.invocations, 1);
    assert!(queued_child.child_invocations <= 1);
    let child_grant = queued_child.child_grant.expect("captured child Grant");
    assert_eq!(child_grant.payload.home_epoch, 2);
    assert_eq!(child_grant.payload.home_realm, REALM_B);
    assert_eq!(child_grant.payload.home_node, NODE_B);
    assert_eq!(child_grant.payload.home_coordinator, destination.0.to_string());
    assert_eq!(child_grant.payload.input, child_input());
    assert_eq!(child_grant.payload.deployment, typed_deployment);
    assert_eq!(child_grant.payload.function, public.typed_function);

    let completed_child = wait_for_child_terminal(&mut b);
    assert_eq!(completed_child.invocations, 1, "blocked parent executes exactly once");
    assert_eq!(
        completed_child.child_invocations, 1,
        "the measured-artifact Rhai critter executes the causal child exactly once"
    );
    assert!(completed_child.terminal.is_none(), "the parent remains blocked");
    assert_eq!(completed_child.grant_receiver, b2.executor);
    let child_terminal = completed_child.child_terminal.expect("durable child terminal");
    verify_execution_receipt(&child_terminal, &child_grant).expect("child terminal executor proof");
    assert!(matches!(
        &child_terminal.payload.stage,
        ExecutionStageV1::Succeeded {
            result: ValueRefV1::Inline { value },
        } if value == &json!({"answer": 8})
    ));

    let child_succeeded =
        wait_for_job_state(&mut a, Some(destination), &child, JobStateV1::Succeeded);
    assert_eq!(child_succeeded.payload.home_epoch, 2);
    assert_eq!(child_succeeded.payload.spec.root, handle);
    assert_eq!(child_succeeded.payload.spec.parent.as_ref(), Some(&handle));
    assert_eq!(child_succeeded.payload.spec.input, child_input());
    assert_eq!(
        child_succeeded.payload.result,
        Some(ValueRefV1::Inline { value: json!({"answer": 8}) })
    );

    assert!(matches!(
        b.request(&ControlRequest::ReleaseTargetAfterControl),
        ControlResponse::TargetReleased
    ));
    let terminal_status = wait_for_terminal(&mut b);
    let parent_terminal = terminal_status.terminal.expect("durable parent terminal");
    verify_execution_receipt(&parent_terminal, &grant).expect("parent terminal executor proof");
    assert!(terminal_status.terminal_push_suppressed);
    let parent_with_steer_outcome =
        wait_for_event_page(&mut a, Some(destination), &handle, |page| {
            page.events.iter().any(|event| {
                matches!(
                    &event.payload.kind,
                    JobEventKindV1::ControlAcknowledged {
                        control,
                        attempt,
                        disposition: ControlDispositionV1::TooLate,
                    } if control == &steer.payload.control && attempt == parent_attempt
                )
            })
        });
    let steer_acknowledged = parent_with_steer_outcome
        .events
        .iter()
        .find(|event| {
            matches!(
                &event.payload.kind,
                JobEventKindV1::ControlAcknowledged {
                    control,
                    attempt,
                    disposition: ControlDispositionV1::TooLate,
                } if control == &steer.payload.control && attempt == parent_attempt
            )
        })
        .cloned()
        .expect("moved Home durably records the target's honest late steer outcome");
    verify_job_event_with_grant(&steer_acknowledged, &grant)
        .expect("acknowledged steer Home proof");
    let acknowledged_receipt = steer_acknowledged
        .payload
        .foreign_receipt
        .as_deref()
        .expect("acknowledged steer retains the executor receipt");
    verify_execution_receipt(acknowledged_receipt, &grant)
        .expect("acknowledged steer executor proof");
    assert!(matches!(
        &acknowledged_receipt.payload.stage,
        ExecutionStageV1::ControlAcknowledged {
            control,
            disposition: ControlDispositionV1::TooLate,
            detail: Some(detail),
        } if control == &steer.payload.control && detail.contains("already completed")
    ));

    let child_events = wait_for_event_page(&mut a, Some(destination), &child, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
    });
    for event in &child_events.events {
        verify_job_event(event).expect("child event proof");
    }
    let submitted = child_events.events.first().expect("child Submitted event");
    let JobEventKindV1::Submitted { spec } = &submitted.payload.kind else {
        panic!("child ledger must begin with Submitted")
    };
    assert_eq!(spec.root, handle);
    assert_eq!(spec.parent.as_ref(), Some(&handle));
    assert_eq!(spec.causal.len(), 1);
    assert_eq!(spec.causal[0].job, handle);
    assert_eq!(spec.causal[0].relation, "spawned_by_progress");
    assert_eq!(spec.causal[0].receipt_hash.as_ref(), Some(&progress_hash));
    assert_eq!(
        child_events
            .events
            .iter()
            .filter(|event| matches!(event.payload.kind, JobEventKindV1::DispatchGranted { .. }))
            .count(),
        1,
        "duplicate ProposeChild must persist one child dispatch"
    );
    assert_eq!(
        child_events
            .events
            .iter()
            .filter(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
            .count(),
        1,
        "causal child must persist one terminal"
    );
    let child_dispatch = child_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::DispatchGranted { .. }))
        .expect("child dispatch event");
    let JobEventKindV1::DispatchGranted { grant_hash, attempt } = &child_dispatch.payload.kind
    else {
        unreachable!()
    };
    assert_eq!(attempt, &child_grant.payload.attempt);
    assert_eq!(grant_hash, &canonical_hash(&child_grant).expect("child Grant hash"));
    let child_terminal_event = child_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
        .expect("child terminal Home event");
    verify_job_event_with_grant(child_terminal_event, &child_grant)
        .expect("child terminal Home proof");
    assert_eq!(
        child_terminal_event.payload.foreign_receipt.as_deref(),
        Some(&child_terminal),
        "active Home must retain the exact child executor receipt"
    );

    // Ensure the reverse activation notification is durable at A before the crash. The parent is
    // still Running at Home because only its executor receipt exists; its push was intentionally
    // suppressed after fsync.
    let redirect_deadline = Instant::now() + scaled(Duration::from_secs(10));
    loop {
        let status_response = a.request(&ControlRequest::SourceStatus);
        let ControlResponse::SourceStatus { status } = status_response else {
            panic!("source custody status failed: {status_response:?}")
        };
        verify_home_custody_status(&status).expect("source custody status proof");
        if matches!(
            &status.payload.state,
            HomeCustodyPhaseV1::Frozen { prepared: observed, redirect: Some(observed_lease) }
                if **observed == prepared && **observed_lease == *lease
        ) {
            break;
        }
        assert!(Instant::now() < redirect_deadline, "source did not persist activation redirect");
        std::thread::sleep(Duration::from_millis(20));
    }
    let parent_before_cut =
        wait_for_job_state(&mut a, Some(destination), &handle, JobStateV1::Running);
    assert_eq!(parent_before_cut.payload.home_epoch, 2);

    // Hard cut after the active Home has the child terminal and the executor has the parent's lost
    // terminal. Reopen both processes from the same stores; active-Home recovery must Query that
    // exact parent fact and must not replay either invocation.
    b.hard_kill();
    a.hard_kill();
    let mut b = NodeChild::spawn("b", 2, &root, port_a, port_b);
    let b3 = b.description();
    let mut a = NodeChild::spawn("a", 2, &root, port_a, port_b);
    let a2 = a.description();
    assert_ne!(b2.pid, b3.pid, "B active-Home reopen must use a new PID");
    assert_ne!(a1.pid, a2.pid, "A frozen-Home reopen must use a new PID");
    assert_eq!(b3.target, b2.target);
    assert_eq!(b3.typed_target, b2.typed_target);
    assert_eq!(b3.typed_artifact_sha256, b2.typed_artifact_sha256);
    assert_eq!(b3.executor, b2.executor);
    assert_eq!(b3.destination, b2.destination);
    assert_eq!(a2.source, a1.source);
    await_application_route(&mut a, b3.ping);

    let recovered_parent =
        wait_for_job_state(&mut a, Some(destination), &handle, JobStateV1::Succeeded);
    assert_eq!(recovered_parent.payload.home_epoch, 2);
    assert_eq!(
        recovered_parent.payload.result,
        Some(ValueRefV1::Inline { value: json!({"answer": 42}) })
    );
    let recovered_child =
        wait_for_job_state(&mut a, Some(destination), &child, JobStateV1::Succeeded);
    assert_eq!(recovered_child, child_succeeded, "child snapshot must reopen exactly");

    let reopened_parent_events = wait_for_event_page(&mut a, Some(destination), &handle, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
    });
    let reopened_progress = reopened_parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        .expect("reopened active Home retains Progress");
    assert_eq!(reopened_progress, &progress);
    assert_eq!(
        serde_json::to_vec(reopened_progress).expect("encode reopened Progress"),
        serde_json::to_vec(&progress).expect("encode original Progress"),
        "active-Home reopen must preserve the signed Progress bytes exactly"
    );
    let recovered_terminal_event = reopened_parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
        .expect("reopened active Home reconciles parent terminal");
    verify_job_event_with_grant(recovered_terminal_event, &grant)
        .expect("reconciled parent Home proof");
    assert_eq!(
        recovered_terminal_event.payload.foreign_receipt.as_deref(),
        Some(&parent_terminal),
        "recovery must retain the exact pre-crash parent receipt"
    );
    assert!(
        reopened_parent_events.events.iter().any(|event| event == &steer_acknowledged),
        "the exact durable cross-Realm steer outcome must survive both hard restarts"
    );

    let reopened_child_events = wait_for_event_page(&mut a, Some(destination), &child, |page| {
        page.events
            .iter()
            .any(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
    });
    assert_eq!(
        reopened_child_events, child_events,
        "causal child ledger must reopen without reconstruction"
    );
    let recovered_execution = execution_status(&mut b);
    assert_eq!(recovered_execution.invocations, 1);
    assert_eq!(recovered_execution.child_invocations, 1);
    assert!(
        recovered_execution.query_count >= 1,
        "reopened active Home must Query the executor for the lost parent terminal"
    );
    std::thread::sleep(Duration::from_millis(100));
    let stable_counts = execution_status(&mut b);
    assert_eq!(stable_counts.invocations, 1);
    assert_eq!(stable_counts.child_invocations, 1);

    b.graceful_shutdown();
    a.graceful_shutdown();
}
