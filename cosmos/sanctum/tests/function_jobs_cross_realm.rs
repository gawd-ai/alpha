//! Typed Function execution and live Home custody across two authenticated Realms.
//!
//! Two distinct Sanctums run in Realms `origin` and `compute` over authenticated
//! `transport-tcp`, with `omega-federator` as each Realm gateway. The caller and epoch-1 Home live
//! on A; the durable executor, typed target, locator, and epoch-2 Home endpoint live on B. The
//! checkpoint blob is copied from the source CAS into the destination CAS in-process, standing in
//! for a completed GX transfer. One Home-addressed sealed value exists in both CAS stores; the
//! root-declared source inventory, destination KMS request/receipt, and the custody
//! grant/checkpoint/prepared/staged/activated proofs themselves cross the real Omega/TCP path.
//! Before Submit, B reopens its stable-key executor at a changed CreatureId while an inert filler
//! occupies the stale id; A's Home grant must therefore traverse the authenticated remote role.
//! The Forge-verified target reports durable progress back across the mesh before that running Job
//! migrates. After activation, A sends the same causal-child proposal twice to B's epoch-2 Home;
//! the Home atomically deduplicates the edge and the child is dispatched to completion on B.
//!
//! The test performs a full Kernel/store reopen on both sides. It is deliberately one OS-process
//! harness, not a claim that process-kill/GX fault injection is already covered.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aether::{
    Address, BusHandle, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Ed25519Signer,
    Envelope, InboxReceiver, NodeId, Outcome, RealmId, Role,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use function_executor::{
    DeploymentAdmission, DeploymentLiveness, ExecutorConfig, FunctionExecutor, StringAddressing,
};
use function_home::{
    CustodyKeyRewrapper, FunctionHome, FunctionMetadata, FunctionTrust, HomeConfig,
    HomeCustodyDestination,
};
use function_locator::{FunctionLocator, LocatorCaps};
use gawdfn::{
    canonical_hash, derive_deployment_id, is_home_lease_coordinator_revision,
    verify_custody_prepared, verify_custody_rewrap_receipt, verify_custody_staged,
    verify_deployment_receipt, verify_event_page_response_for, verify_execution_receipt,
    verify_home_custody_status, verify_home_lease, verify_job_acceptance,
    verify_job_control_acceptance, verify_job_event, verify_job_event_with_grant,
    verify_job_snapshot, verify_job_snapshot_response_for, AbodeKeyBindingV1, AuthoritySigner,
    BlobRefV1, CheckpointBlobStore, ControlId, CustodyGrantV1, CustodyRewrapEntryV1,
    CustodyRewrapReceiptV1, CustodyRewrapRequestV1, CustodyRewrapRequirementV1,
    CustodyRewrapSourceV1, DeliveryModeV1, DeploymentQueryV1, DeploymentReceiptV1,
    DeploymentRegistrationV1, DeploymentRequestV1, Ed25519SeedSigner, EffectClassV1,
    EntrypointContractV1, EventPageV1, EventQueryRelayV1, EventQueryV1, ExecuteMessageV1,
    ExecutionGrantV1, ExecutionReceiptV1, ExecutionStageV1, FunctionAlias, FunctionCallMessageV1,
    FunctionId, FunctionResultV1, FunctionSelectorV1, HandoffId, HomeAuthorityV1,
    HomeCustodyPhaseV1, HomeId, HomeLocateV1, HomeMessageV1, JobAccessV1, JobControlKindV1,
    JobControlV1, JobEventKindV1, JobGetRelayV1, JobGetV1, JobHandleV1, JobMessageV1,
    JobSnapshotV1, JobStateV1, JobSubmitV1, LocateMessageV1, OperationalCapabilityV1,
    OperationalKeyGrantV1, PlacementDecisionV1, RecipientKeyBindingV1, RecipientKeyWrapV1,
    ResolutionReceiptV1, ResolvedFunctionV1, RetryDecisionV1, SchemaRefV1, SealedValueV1,
    SignedRecordV1, UndeployRequestV1, ValueRefV1, FUNCTION_LOCATOR_ROLE, FUNCTION_POLICY_ROLE,
    SCHEMA_CALL_V1, SCHEMA_CUSTODY_REWRAP_V1, SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1,
    SCHEMA_HOME_V1, SCHEMA_JOB_V1, SCHEMA_LOCATE_V1,
};
use job_blob_fs::{BlobCaps, FsJobBlobStore};
use omega_federator::{FederatorConfig, OmegaFederator};
use policy_job_basic::{BasicJobPolicy, BasicPolicyCaps};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use serde::Serialize;
use serde_json::json;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Entrypoint, Manifest};
use transport_tcp::{PeerConfig, TransportConfig, TransportTcp};

const PORT_A: u16 = 19_966;
const PORT_B: u16 = 19_967;
const NODE_A: &str = "function-origin-A";
const NODE_B: &str = "function-compute-B";
const REALM_A: &str = "origin";
const REALM_B: &str = "compute";

fn slow_factor() -> u64 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value >= 1)
        .unwrap_or(1)
}

fn scaled(duration: Duration) -> Duration {
    duration * (slow_factor() as u32)
}

fn normalize_sha256(value: &str) -> Option<String> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    (raw.len() == 64
        && raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| format!("sha256:{raw}"))
}

fn remote_b(creature: CreatureId) -> Address {
    Address::Omega {
        realm: RealmId::new(REALM_B),
        target: Box::new(Address::Node(NodeId(NODE_B.into()), creature)),
    }
}

fn remote_b_role(role: &'static str) -> Address {
    Address::Omega {
        realm: RealmId::new(REALM_B),
        target: Box::new(Address::NodeRole(NodeId(NODE_B.into()), Role::new(role))),
    }
}

fn signed_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut manifest = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    manifest.provenance.author = Some(key.public_hex().to_string());
    manifest.provenance.signature = Some(key.sign(&manifest.signing_payload()));
    manifest
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
    panic!("no {schema} response for correlation {corr}");
}

fn rpc<T: Serialize>(
    bus: &BusHandle,
    rx: &InboxReceiver,
    corr: u64,
    target: Address,
    schema: &str,
    message: &T,
) -> Envelope {
    bus.send(
        Dispatch::to(target, aether::wire::to_bytes(message))
            .with_schema(schema)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(corr),
    )
    .expect("request enters the real bus");
    recv_corr(rx, corr, schema, scaled(Duration::from_secs(8)))
}

/// Wait for the complete application route, not merely transport's one-shot handshake event.
/// Every attempt has a fresh correlation, so a late reply cannot satisfy a later operation.
fn await_remote_route(
    bus: &BusHandle,
    rx: &InboxReceiver,
    locator: CreatureId,
    home: &HomeId,
    mut corr: u64,
) -> u64 {
    let deadline = Instant::now() + scaled(Duration::from_secs(10));
    while Instant::now() < deadline {
        let message = LocateMessageV1::Locate {
            query: HomeLocateV1 { home: home.clone(), minimum_epoch: None },
        };
        bus.send(
            Dispatch::to(remote_b(locator), aether::wire::to_bytes(&message))
                .with_schema(SCHEMA_LOCATE_V1)
                .with_reply_to(Address::Creature(bus.id()))
                .with_corr(corr),
        )
        .expect("readiness probe enters the local bus");
        let remaining_total = deadline.saturating_duration_since(Instant::now());
        let attempt_deadline =
            Instant::now() + scaled(Duration::from_millis(350)).min(remaining_total);
        while Instant::now() < attempt_deadline {
            let remaining = attempt_deadline.saturating_duration_since(Instant::now());
            if let Ok(env) = rx.recv_timeout(remaining.min(Duration::from_millis(50))) {
                if env.header.corr == Some(corr)
                    && env.header.schema == SCHEMA_LOCATE_V1
                    && serde_json::from_slice::<LocateMessageV1>(&env.payload).is_ok()
                {
                    return corr.saturating_add(1);
                }
            }
        }
        corr = corr.saturating_add(1);
        std::thread::sleep(Duration::from_millis(20));
    }
    panic!("authenticated Omega application route to Realm B did not become ready");
}

struct KernelLiveness(Weak<Kernel>);

impl DeploymentLiveness for KernelLiveness {
    fn target_is_live(
        &self,
        target: CreatureId,
        deployment: &DeploymentReceiptV1,
    ) -> Result<bool, String> {
        let kernel = self.0.upgrade().ok_or_else(|| "Kernel roster unavailable".to_string())?;
        let Some(identity) = kernel.loaded_manifest_identity(target) else {
            return Ok(false);
        };
        Ok(identity.manifest_content_address.as_deref()
            == Some(deployment.function.manifest_content_address.as_str())
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
        receipt: &SignedRecordV1<ExecutionReceiptV1>,
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

#[derive(Default)]
struct TargetGate {
    entered: bool,
    release: bool,
}

fn child_input() -> ValueRefV1 {
    ValueRefV1::Inline { value: json!({"kind": "child", "value": 7}) }
}

struct BlockingAddOne {
    function: FunctionId,
    sealed_input: ValueRefV1,
    gate: Arc<(Mutex<TargetGate>, Condvar)>,
    calls: Arc<AtomicUsize>,
    child_calls: Arc<AtomicUsize>,
    executor_routes: Arc<Mutex<Vec<String>>>,
    me: Option<CreatureId>,
    bus: Option<Arc<dyn aether::Bus>>,
}

impl Creature for BlockingAddOne {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
        self.bus = Some(ctx.bus);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if self.me.map(Address::Creature).as_ref() != Some(&env.header.to) {
            return Outcome::none();
        }
        let Ok(call) = forge::function::parse_call_for(&env, &self.function) else {
            return Outcome::none();
        };
        self.executor_routes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(call.executor_dispatch.payload.executor_creature.clone());
        if call.input == child_input() {
            self.child_calls.fetch_add(1, Ordering::SeqCst);
            let result = FunctionResultV1 {
                attempt: call.attempt,
                outcome: Ok(ValueRefV1::Inline {
                    value: json!({"answer": 8, "child": "complete"}),
                }),
            };
            return forge::function::reply(&env, result)
                .map(Outcome::send)
                .unwrap_or_else(|_| Outcome::none());
        }
        // The deterministic fixture stands in for target-side decryption: it recognizes only the
        // exact sealed descriptor whose data-key envelope the custody adapter rewrapped.
        if call.input != self.sealed_input {
            return Outcome::none();
        }
        let value = 41;
        self.calls.fetch_add(1, Ordering::SeqCst);
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
        ready.notify_all();
        let deadline = Instant::now() + scaled(Duration::from_secs(15));
        while !gate.release && Instant::now() < deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let (next, _) = ready
                .wait_timeout(gate, remaining.min(Duration::from_millis(200)))
                .unwrap_or_else(|poison| poison.into_inner());
            gate = next;
        }
        drop(gate);
        let result = FunctionResultV1 {
            attempt: call.attempt,
            outcome: Ok(ValueRefV1::Inline { value: json!({"answer": value + 1}) }),
        };
        forge::function::reply(&env, result).map(Outcome::send).unwrap_or_else(|_| Outcome::none())
    }
}

struct CapturingExecutor {
    inner: FunctionExecutor,
    grants: Arc<Mutex<Vec<SignedRecordV1<ExecutionGrantV1>>>>,
    grant_receivers: Arc<Mutex<Vec<CreatureId>>>,
    queries: Arc<Mutex<Vec<CreatureId>>>,
    remote_lookups: Arc<Mutex<Vec<CreatureId>>>,
    terminal_recorded: Arc<AtomicBool>,
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
                    self.grants.lock().unwrap_or_else(|poison| poison.into_inner()).push(*grant);
                    self.grant_receivers
                        .lock()
                        .unwrap_or_else(|poison| poison.into_inner())
                        .push(self.me.expect("executor must be bound before handling Grant"));
                }
                Ok(ExecuteMessageV1::Query { .. }) => {
                    let target = self.me.expect("executor must be bound before handling Query");
                    // The moved Home is local to B after activation, so recovery uses the local role.
                    // A separate Lookup assertion below proves inbound NodeRole resolution rewrites
                    // to this exact changed CreatureId before transport delivers it.
                    if env.header.to == Address::Role(Role::new(gawdfn::FUNCTION_EXECUTOR_ROLE))
                        || env.header.to == Address::Creature(target)
                    {
                        self.queries
                            .lock()
                            .unwrap_or_else(|poison| poison.into_inner())
                            .push(target);
                    }
                }
                _ => {}
            }
        }
        if env.header.schema == SCHEMA_FUNCTION_DEPLOY_V1
            && matches!(
                serde_json::from_slice::<gawdfn::FunctionDeployMessageV1>(&env.payload),
                Ok(gawdfn::FunctionDeployMessageV1::Lookup { .. })
            )
        {
            let target = self.me.expect("executor must be bound before handling Lookup");
            if env.header.to == Address::Creature(target) {
                self.remote_lookups
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .push(target);
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
        let is_parent_terminal = terminal_attempt.is_some_and(|attempt| {
            self.grants
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .first()
                .is_some_and(|grant| grant.payload.attempt == attempt)
        });
        if is_parent_terminal {
            self.terminal_recorded.store(true, Ordering::SeqCst);
            // Lose the parent push after the executor has durably recorded it. The reopened Home
            // must pull this exact receipt from the changed, role-selected executor incarnation.
            // Later child terminals still reach the active epoch-2 Home normally.
            return Outcome::none();
        }
        outcome
    }

    fn shutdown(&mut self, deadline: Deadline) {
        self.inner.shutdown(deadline);
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

struct InertRouteFiller;

impl Creature for InertRouteFiller {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

fn recipient_binding(
    root: &Ed25519SeedSigner,
    proof: &Ed25519SeedSigner,
    encryption_byte: u8,
) -> SignedRecordV1<RecipientKeyBindingV1> {
    SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        RecipientKeyBindingV1 {
            abode: HomeId::new(root.public_key()),
            signing_public_key: proof.public_key().into(),
            encryption_public_key: format!("{encryption_byte:02x}").repeat(32),
            suite: "hpke-x25519".into(),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
        },
        root,
    )
    .unwrap()
}

type RewrapCall = (SignedRecordV1<CustodyRewrapRequestV1>, Vec<CustodyRewrapSourceV1>);

struct TestRewrapper {
    binding: SignedRecordV1<RecipientKeyBindingV1>,
    proof: Option<Arc<Ed25519SeedSigner>>,
    calls: Arc<Mutex<Vec<RewrapCall>>>,
}

impl CustodyKeyRewrapper for TestRewrapper {
    fn current_binding(&self) -> Result<SignedRecordV1<RecipientKeyBindingV1>, String> {
        Ok(self.binding.clone())
    }

    fn rewrap(
        &self,
        request: &SignedRecordV1<CustodyRewrapRequestV1>,
        inventory: &[CustodyRewrapSourceV1],
    ) -> Result<SignedRecordV1<CustodyRewrapReceiptV1>, String> {
        self.calls
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push((request.clone(), inventory.to_vec()));
        let proof =
            self.proof.as_deref().ok_or_else(|| "source test adapter cannot rewrap".to_string())?;
        let destination_binding_hash =
            canonical_hash(&self.binding).map_err(|error| error.to_string())?;
        let entries = inventory
            .iter()
            .enumerate()
            .map(|(index, source)| {
                Ok(CustodyRewrapEntryV1 {
                    sealed_value_hash: source.sealed_value_hash.clone(),
                    ciphertext: source.ciphertext.clone(),
                    source_wrap_hash: canonical_hash(&source.source_wrap)
                        .map_err(|error| error.to_string())?,
                    destination_wrap: RecipientKeyWrapV1 {
                        recipient: source.source_wrap.recipient.clone(),
                        binding_hash: destination_binding_hash.clone(),
                        encapsulated_key: format!("destination-encapsulated-{index}"),
                        wrapped_data_key: format!("destination-wrapped-key-{index}"),
                    },
                })
            })
            .collect::<Result<Vec<_>, String>>()?;
        SignedRecordV1::sign(
            SCHEMA_CUSTODY_REWRAP_V1,
            CustodyRewrapReceiptV1 {
                request: Box::new(request.clone()),
                entries,
                evidence: vec![],
            },
            proof,
        )
        .map_err(|error| error.to_string())
    }
}

struct Fixture {
    root_dir: PathBuf,
    node_a_key: Ed25519KeyMaterial,
    node_b_key: Ed25519KeyMaterial,
    root: Arc<Ed25519SeedSigner>,
    source_key: Arc<Ed25519SeedSigner>,
    destination_key: Arc<Ed25519SeedSigner>,
    destination_proof_key: Arc<Ed25519SeedSigner>,
    resolver_key: Arc<Ed25519SeedSigner>,
    executor_key: Arc<Ed25519SeedSigner>,
    policy_key: Arc<Ed25519SeedSigner>,
    home: HomeId,
    source_authority: HomeAuthorityV1,
    destination_authority: HomeAuthorityV1,
    source_binding: SignedRecordV1<RecipientKeyBindingV1>,
    destination_binding: SignedRecordV1<RecipientKeyBindingV1>,
    alias: FunctionAlias,
    function: FunctionId,
    artifact_hash: String,
    target_manifest: Manifest,
    gate: Arc<(Mutex<TargetGate>, Condvar)>,
    calls: Arc<AtomicUsize>,
    child_calls: Arc<AtomicUsize>,
    target_executor_routes: Arc<Mutex<Vec<String>>>,
    grants: Arc<Mutex<Vec<SignedRecordV1<ExecutionGrantV1>>>>,
    grant_receivers: Arc<Mutex<Vec<CreatureId>>>,
    executor_queries: Arc<Mutex<Vec<CreatureId>>>,
    remote_executor_lookups: Arc<Mutex<Vec<CreatureId>>>,
    terminal_recorded: Arc<AtomicBool>,
    rewrap_calls: Arc<Mutex<Vec<RewrapCall>>>,
}

impl Fixture {
    fn new() -> Self {
        let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root_dir = std::env::temp_dir()
            .join(format!("alpha-function-cross-realm-{}-{unique}", std::process::id()));
        std::fs::create_dir_all(&root_dir).unwrap();
        let node_a_key = Ed25519KeyMaterial::from_seed([0x6a; 32]).unwrap();
        let node_b_key = Ed25519KeyMaterial::from_seed([0x6b; 32]).unwrap();
        let root = Arc::new(Ed25519SeedSigner::from_seed([101; 32]).unwrap());
        let source_key = Arc::new(Ed25519SeedSigner::from_seed([102; 32]).unwrap());
        let destination_key = Arc::new(Ed25519SeedSigner::from_seed([103; 32]).unwrap());
        let source_proof_key = Arc::new(Ed25519SeedSigner::from_seed([107; 32]).unwrap());
        let destination_proof_key = Arc::new(Ed25519SeedSigner::from_seed([108; 32]).unwrap());
        let resolver_key = Arc::new(Ed25519SeedSigner::from_seed([104; 32]).unwrap());
        let executor_key = Arc::new(Ed25519SeedSigner::from_seed([105; 32]).unwrap());
        let policy_key = Arc::new(Ed25519SeedSigner::from_seed([106; 32]).unwrap());
        let home = HomeId::new(root.public_key());
        let source_authority = authority(root.as_ref(), source_key.as_ref(), &home, 1);
        let destination_authority = authority(root.as_ref(), destination_key.as_ref(), &home, 2);
        let source_binding = recipient_binding(root.as_ref(), source_proof_key.as_ref(), 0x41);
        let destination_binding =
            recipient_binding(root.as_ref(), destination_proof_key.as_ref(), 0x42);

        let artifact_raw = "d".repeat(64);
        let artifact_hash = format!("sha256:{artifact_raw}");
        let alias = FunctionAlias {
            realm: REALM_B.into(),
            name: "remote-add-one".into(),
            version: "0.1.0".into(),
            entrypoint: "add_one".into(),
        };
        let mut target_manifest =
            Manifest::new("remote-add-one", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        target_manifest.provenance.author = Some(node_b_key.public_hex().to_string());
        target_manifest.provenance.build_hash = Some(artifact_raw);
        target_manifest.entrypoints.push(Entrypoint {
            name: "add_one".into(),
            signature: SCHEMA_CALL_V1.into(),
            contract: Some(EntrypointContractV1 {
                description: "Add one on the remote Realm".into(),
                input_schema: SchemaRefV1::Inline {
                    schema: json!({"type":"object","required":["value"]}),
                },
                output_schema: SchemaRefV1::Inline {
                    schema: json!({"type":"object","required":["answer"]}),
                },
                error_schema: None,
                effect: EffectClassV1::Idempotent,
                controls: Default::default(),
            }),
        });
        let manifest_content_address = target_manifest.compute_content_address();
        target_manifest.content_address = Some(manifest_content_address.clone());
        target_manifest.provenance.signature =
            Some(node_b_key.sign(&target_manifest.signing_payload()));
        target_manifest.validate().unwrap();
        let function = FunctionId { manifest_content_address, entrypoint: "add_one".into() };

        Self {
            root_dir,
            node_a_key,
            node_b_key,
            root,
            source_key,
            destination_key,
            destination_proof_key,
            resolver_key,
            executor_key,
            policy_key,
            home,
            source_authority,
            destination_authority,
            source_binding,
            destination_binding,
            alias,
            function,
            artifact_hash,
            target_manifest,
            gate: Arc::new((Mutex::new(TargetGate::default()), Condvar::new())),
            calls: Arc::new(AtomicUsize::new(0)),
            child_calls: Arc::new(AtomicUsize::new(0)),
            target_executor_routes: Arc::new(Mutex::new(Vec::new())),
            grants: Arc::new(Mutex::new(Vec::new())),
            grant_receivers: Arc::new(Mutex::new(Vec::new())),
            executor_queries: Arc::new(Mutex::new(Vec::new())),
            remote_executor_lookups: Arc::new(Mutex::new(Vec::new())),
            terminal_recorded: Arc::new(AtomicBool::new(false)),
            rewrap_calls: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn trust(&self) -> Arc<dyn FunctionTrust> {
        Arc::new(PinnedTrust {
            resolver: self.resolver_key.public_key().into(),
            executor: self.executor_key.public_key().into(),
            policy: self.policy_key.public_key().into(),
        })
    }

    fn checkpoint_store(&self, side: &str) -> Arc<FsJobBlobStore> {
        Arc::new(
            FsJobBlobStore::open(
                self.root_dir.join(format!("gx-prestaged-blobs-{side}")),
                BlobCaps::default(),
            )
            .unwrap(),
        )
    }

    fn sealed_input(&self, ciphertext: BlobRefV1) -> ValueRefV1 {
        ValueRefV1::Sealed {
            sealed: Box::new(SealedValueV1 {
                ciphertext,
                suite: "hpke-x25519".into(),
                plaintext_digest: None,
                recipients: vec![RecipientKeyWrapV1 {
                    recipient: self.home.clone(),
                    binding_hash: canonical_hash(&self.source_binding).unwrap(),
                    encapsulated_key: "source-encapsulated".into(),
                    wrapped_data_key: "source-wrapped-data-key".into(),
                }],
            }),
        }
    }

    fn rewrap_inventory(&self, ciphertext: BlobRefV1) -> Vec<CustodyRewrapSourceV1> {
        let ValueRefV1::Sealed { sealed } = self.sealed_input(ciphertext) else {
            unreachable!("fixture always constructs a sealed value")
        };
        vec![CustodyRewrapSourceV1 {
            sealed_value_hash: canonical_hash(sealed.as_ref()).unwrap(),
            ciphertext: sealed.ciphertext.clone(),
            source_wrap: sealed.recipients[0].clone(),
        }]
    }

    fn rewrap_requirement(&self) -> CustodyRewrapRequirementV1 {
        CustodyRewrapRequirementV1 {
            source_binding: Box::new(self.source_binding.clone()),
            destination_binding: Box::new(self.destination_binding.clone()),
            evidence: vec![],
        }
    }

    fn source_home(&self, values: Arc<FsJobBlobStore>) -> FunctionHome {
        FunctionHome::open_with_checkpoint_store_and_rewrapper(
            HomeConfig::for_creature(
                self.root_dir.join("home-source"),
                self.home.clone(),
                self.source_authority.clone(),
            )
            .with_location(REALM_A, NODE_A),
            self.source_key.clone(),
            Arc::new(IdempotentMetadata),
            self.trust(),
            values.clone(),
            values,
            Arc::new(TestRewrapper {
                binding: self.source_binding.clone(),
                proof: None,
                calls: Arc::new(Mutex::new(Vec::new())),
            }),
        )
        .unwrap()
    }

    fn destination_config(&self) -> HomeConfig {
        let mut config = HomeConfig::for_creature(
            self.root_dir.join("home-destination"),
            self.home.clone(),
            self.destination_authority.clone(),
        )
        .with_location(REALM_B, NODE_B);
        config.epoch = 2;
        config
    }

    fn executor(&self, kernel: &Arc<Kernel>) -> FunctionExecutor {
        FunctionExecutor::open_with_liveness(
            ExecutorConfig::new(self.root_dir.join("executor"), self.executor_key.public_key())
                .with_location(REALM_B, NODE_B, "auto"),
            self.executor_key.clone(),
            Arc::new(StringAddressing),
            Arc::new(OwnerAdmission(self.root.public_key().into())),
            Arc::new(KernelLiveness(Arc::downgrade(kernel))),
        )
        .unwrap()
    }

    fn resolution(&self) -> SignedRecordV1<ResolutionReceiptV1> {
        SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            ResolutionReceiptV1 {
                selector: FunctionSelectorV1::Alias { alias: self.alias.clone() },
                function: self.function.clone(),
                artifact_hash: self.artifact_hash.clone(),
                resolved_at_unix_ms: None,
                evidence: vec![],
            },
            self.resolver_key.as_ref(),
        )
        .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root_dir);
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
    .unwrap();
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
    .unwrap();
    HomeAuthorityV1 { abode, operational, prepared: None }
}

#[allow(clippy::too_many_arguments)] // mesh fixture keeps every authenticated endpoint explicit
fn base_node(
    node_id: &str,
    realm: &str,
    port: u16,
    node_key: &Ed25519KeyMaterial,
    peer_node: &str,
    peer_realm: &str,
    peer_port: u16,
    peer_key: &Ed25519KeyMaterial,
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
            pubkey_hex: peer_key.public_hex().to_string(),
            dial_addr: dials.then(|| format!("127.0.0.1:{peer_port}")),
        }],
    });
    let transport_id = kernel
        .load_transport_instance(signed_manifest("transport-tcp", node_key), Box::new(transport))
        .unwrap();
    kernel.bind_role(Role::new(Role::TRANSPORT), transport_id);
    let registry_id = kernel
        .load_instance(signed_manifest("registry-mem", node_key), Box::new(RegistryMem::new()))
        .unwrap();
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
        .unwrap();
    kernel.bind_role(Role::new(Role::OMEGA_GATEWAY), federator_id);
    kernel
}

struct NodeA {
    kernel: Arc<Kernel>,
    locator: CreatureId,
    source: CreatureId,
    source_home: Arc<Mutex<FunctionHome>>,
    checkpoint_store: Arc<FsJobBlobStore>,
    ciphertext: BlobRefV1,
}

fn boot_a(fixture: &Fixture) -> NodeA {
    let kernel = base_node(
        NODE_A,
        REALM_A,
        PORT_A,
        &fixture.node_a_key,
        NODE_B,
        REALM_B,
        PORT_B,
        &fixture.node_b_key,
        true,
    );
    let locator = kernel
        .load_instance(
            signed_manifest("function-locator", &fixture.node_a_key),
            Box::new(
                FunctionLocator::open(fixture.root_dir.join("locator-a"), LocatorCaps::default())
                    .unwrap(),
            ),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_LOCATOR_ROLE), locator);
    let policy = kernel
        .load_instance(
            signed_manifest("policy-job-basic", &fixture.node_a_key),
            Box::new(
                BasicJobPolicy::new(fixture.policy_key.clone(), BasicPolicyCaps::default())
                    .unwrap(),
            ),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy);
    let checkpoint_store = fixture.checkpoint_store("source");
    let ciphertext = checkpoint_store
        .put_ref("application/vnd.gawd.test-ciphertext", b"cross-realm sealed value")
        .unwrap();
    let source_home = Arc::new(Mutex::new(fixture.source_home(checkpoint_store.clone())));
    let source = kernel
        .load_instance(
            signed_manifest("function-home-source", &fixture.node_a_key),
            Box::new(SharedHome(source_home.clone())),
        )
        .unwrap();
    NodeA { kernel, locator, source, source_home, checkpoint_store, ciphertext }
}

struct NodeB {
    kernel: Arc<Kernel>,
    target: CreatureId,
    restart_filler: Option<CreatureId>,
    executor: CreatureId,
    locator: CreatureId,
    destination: CreatureId,
    checkpoint_store: Arc<FsJobBlobStore>,
    ciphertext: BlobRefV1,
    gate: Arc<(Mutex<TargetGate>, Condvar)>,
}

impl Drop for NodeB {
    fn drop(&mut self) {
        // Failed assertions after the typed call begins must not leave its worker parked while
        // Kernel teardown tries to drain creatures.
        let (lock, ready) = &*self.gate;
        let mut gate = lock.lock().unwrap_or_else(|poison| poison.into_inner());
        if gate.entered {
            gate.release = true;
            ready.notify_all();
        }
    }
}

fn boot_b(fixture: &Fixture, restart: bool) -> NodeB {
    let kernel = base_node(
        NODE_B,
        REALM_B,
        PORT_B,
        &fixture.node_b_key,
        NODE_A,
        REALM_A,
        PORT_A,
        &fixture.node_a_key,
        false,
    );
    let values = fixture.checkpoint_store("destination");
    let ciphertext = values
        .put_ref("application/vnd.gawd.test-ciphertext", b"cross-realm sealed value")
        .unwrap();
    let target = kernel
        .load_instance(
            fixture.target_manifest.clone(),
            Box::new(BlockingAddOne {
                function: fixture.function.clone(),
                sealed_input: fixture.sealed_input(ciphertext.clone()),
                gate: fixture.gate.clone(),
                calls: fixture.calls.clone(),
                child_calls: fixture.child_calls.clone(),
                executor_routes: fixture.target_executor_routes.clone(),
                me: None,
                bus: None,
            }),
        )
        .unwrap();
    let restart_filler = restart
        .then(|| {
            kernel.load_instance(
                signed_manifest("restart-route-filler", &fixture.node_b_key),
                Box::new(InertRouteFiller),
            )
        })
        .transpose()
        .unwrap();
    let executor = kernel
        .load_instance(
            signed_manifest("function-executor", &fixture.node_b_key),
            Box::new(CapturingExecutor {
                inner: fixture.executor(&kernel),
                grants: fixture.grants.clone(),
                grant_receivers: fixture.grant_receivers.clone(),
                queries: fixture.executor_queries.clone(),
                remote_lookups: fixture.remote_executor_lookups.clone(),
                terminal_recorded: fixture.terminal_recorded.clone(),
                me: None,
            }),
        )
        .unwrap();
    kernel.bind_remote_role(Role::new(gawdfn::FUNCTION_EXECUTOR_ROLE), executor);
    let locator = kernel
        .load_instance(
            signed_manifest("function-locator", &fixture.node_b_key),
            Box::new(
                FunctionLocator::open(fixture.root_dir.join("locator-b"), LocatorCaps::default())
                    .unwrap(),
            ),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_LOCATOR_ROLE), locator);
    let destination = kernel
        .load_instance(
            signed_manifest("function-home-destination", &fixture.node_b_key),
            Box::new(
                HomeCustodyDestination::new_with_rewrapper(
                    fixture.destination_config(),
                    fixture.destination_key.clone(),
                    Arc::new(IdempotentMetadata),
                    fixture.trust(),
                    values.clone(),
                    values.clone(),
                    Arc::new(TestRewrapper {
                        binding: fixture.destination_binding.clone(),
                        proof: Some(fixture.destination_proof_key.clone()),
                        calls: fixture.rewrap_calls.clone(),
                    }),
                )
                .unwrap(),
            ),
        )
        .unwrap();
    let policy = kernel
        .load_instance(
            signed_manifest("policy-job-basic", &fixture.node_b_key),
            Box::new(
                BasicJobPolicy::new(fixture.policy_key.clone(), BasicPolicyCaps::default())
                    .unwrap(),
            ),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy);
    NodeB {
        kernel,
        target,
        restart_filler,
        executor,
        locator,
        destination,
        checkpoint_store: values,
        ciphertext,
        gate: fixture.gate.clone(),
    }
}

fn signed_reply_to(bus: &BusHandle, target: &Address) -> Address {
    // A remote Home sees the transport-rewritten return route. Signing that stable Node address up
    // front keeps the relay proof byte-identical across the authenticated hop; a local Home sees
    // the probe's Creature address directly.
    if matches!(target, Address::Node(..) | Address::Realm { .. } | Address::Omega { .. }) {
        Address::Node(NodeId(NODE_A.into()), bus.id())
    } else {
        Address::Creature(bus.id())
    }
}

fn read_job(
    fixture: &Fixture,
    bus: &BusHandle,
    rx: &InboxReceiver,
    target: Address,
    handle: &JobHandleV1,
    corr: u64,
) -> JobMessageV1 {
    let signed_reply_to = signed_reply_to(bus, &target);
    let caller = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetV1 { handle: handle.clone(), nonce: format!("read-{corr}") },
        fixture.root.as_ref(),
    )
    .unwrap();
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetRelayV1 { caller, reply_to: serde_json::to_string(&signed_reply_to).unwrap() },
        fixture.root.as_ref(),
    )
    .unwrap();
    let env = rpc(
        bus,
        rx,
        corr,
        target,
        SCHEMA_JOB_V1,
        &JobMessageV1::Get { request: Box::new(request.clone()) },
    );
    let message: JobMessageV1 = serde_json::from_slice(&env.payload).unwrap();
    if let JobMessageV1::Snapshot { response } = &message {
        verify_job_snapshot_response_for(response, &request).unwrap();
    }
    message
}

fn read_events(
    fixture: &Fixture,
    bus: &BusHandle,
    rx: &InboxReceiver,
    target: Address,
    handle: &JobHandleV1,
    corr: u64,
) -> EventPageV1 {
    let signed_reply_to = signed_reply_to(bus, &target);
    let caller = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EventQueryV1 {
            handle: handle.clone(),
            after_sequence: None,
            limit: 64,
            nonce: format!("events-{corr}"),
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EventQueryRelayV1 { caller, reply_to: serde_json::to_string(&signed_reply_to).unwrap() },
        fixture.root.as_ref(),
    )
    .unwrap();
    let env = rpc(
        bus,
        rx,
        corr,
        target,
        SCHEMA_JOB_V1,
        &JobMessageV1::Events { request: Box::new(request.clone()) },
    );
    let JobMessageV1::EventPage { response } =
        serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap()
    else {
        panic!("Home did not return its durable event chain")
    };
    verify_event_page_response_for(&response, &request).unwrap();
    response.payload.page
}

fn wait_for_events<F>(
    fixture: &Fixture,
    bus: &BusHandle,
    rx: &InboxReceiver,
    target: Address,
    handle: &JobHandleV1,
    corr: &mut u64,
    predicate: F,
) -> EventPageV1
where
    F: Fn(&EventPageV1) -> bool,
{
    let deadline = Instant::now() + scaled(Duration::from_secs(8));
    loop {
        let page = read_events(fixture, bus, rx, target.clone(), handle, *corr);
        *corr += 1;
        if predicate(&page) {
            return page;
        }
        assert!(Instant::now() < deadline, "durable Job event did not arrive");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn wait_for_state(
    fixture: &Fixture,
    bus: &BusHandle,
    rx: &InboxReceiver,
    target: Address,
    handle: &JobHandleV1,
    expected: JobStateV1,
    corr: &mut u64,
) -> SignedRecordV1<JobSnapshotV1> {
    let deadline = Instant::now() + scaled(Duration::from_secs(8));
    loop {
        let message = read_job(fixture, bus, rx, target.clone(), handle, *corr);
        *corr += 1;
        let last_response = match message {
            JobMessageV1::Snapshot { response } => {
                let snapshot = response.payload.snapshot;
                if snapshot.payload.state == expected {
                    return *snapshot;
                }
                format!("snapshot in {:?}", snapshot.payload.state)
            }
            JobMessageV1::Error { error } => {
                format!("error {}: {}", error.code, error.message)
            }
            _ => "unexpected response operation".into(),
        };
        assert!(
            Instant::now() < deadline,
            "job did not reach {expected:?}; last response was {last_response}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn locate(
    bus: &BusHandle,
    rx: &InboxReceiver,
    target: Address,
    home: &HomeId,
    corr: u64,
) -> LocateMessageV1 {
    let env = rpc(
        bus,
        rx,
        corr,
        target,
        SCHEMA_LOCATE_V1,
        &LocateMessageV1::Locate {
            query: HomeLocateV1 { home: home.clone(), minimum_epoch: Some(2) },
        },
    );
    serde_json::from_slice(&env.payload).unwrap()
}

#[test]
fn remote_sealed_job_rewraps_migrates_home_and_recovers_after_mesh_reopen() {
    let fixture = Fixture::new();

    // B listens first; A then dials it. B is restarted once after durable deployment registration so
    // the source Home must discover a changed executor route before it can issue the first grant.
    let initial_b = boot_b(&fixture, false);
    let first_a = boot_a(&fixture);
    assert_eq!(
        first_a.ciphertext, initial_b.ciphertext,
        "the completed GX stand-in must preserve the sealed ciphertext address"
    );
    let sealed_input = fixture.sealed_input(first_a.ciphertext.clone());
    let rewrap_inventory = fixture.rewrap_inventory(first_a.ciphertext.clone());
    let (_probe, bus, rx) = first_a.kernel.open_endpoint(Capabilities::default());
    // A peer handshake event does not itself prove the Omega application path is routable. Drive a
    // harmless locator round-trip before sending authority-bearing deployment messages.
    let mut corr = await_remote_route(&bus, &rx, initial_b.locator, &fixture.home, 1);

    // Register the already-admitted typed target with B's executor from A, crossing Omega/TCP.
    let resolution = fixture.resolution();
    let selector = FunctionSelectorV1::Alias { alias: fixture.alias.clone() };
    let authorization = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRequestV1 {
            requested_by: fixture.home.clone(),
            function: selector.clone(),
            target_realm: REALM_B.into(),
            target_node: Some(NODE_B.into()),
            evidence: vec![],
            requested_at_unix_ms: None,
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let deployment_id = derive_deployment_id(
        &fixture.function,
        &fixture.artifact_hash,
        REALM_B,
        NODE_B,
        &initial_b.target.0.to_string(),
    )
    .unwrap();
    let registration = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRegistrationV1 {
            authorization,
            resolution: resolution.clone(),
            deployment: deployment_id,
            function: fixture.function.clone(),
            artifact_hash: fixture.artifact_hash.clone(),
            target_creature: initial_b.target.0.to_string(),
            evidence: vec![],
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b(initial_b.executor),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &gawdfn::FunctionDeployMessageV1::Register { request: Box::new(registration) },
    );
    corr += 1;
    let gawdfn::FunctionDeployMessageV1::Registered { receipt: deployment } =
        serde_json::from_slice::<gawdfn::FunctionDeployMessageV1>(&env.payload).unwrap()
    else {
        panic!("remote executor did not register the deployment")
    };
    verify_deployment_receipt(&deployment).unwrap();
    assert_eq!(deployment.payload.realm, REALM_B);
    assert_eq!(deployment.payload.node, NODE_B);
    assert_eq!(deployment.payload.executor_creature, initial_b.executor.0.to_string());
    assert_eq!(deployment.payload.creature, initial_b.target.0.to_string());

    // Reopen B alone with a filler at the old executor id. The target stays at its signed deployment
    // pin, while the stable-key executor reopens its registration at a different process-local id.
    let stale_executor = initial_b.executor;
    let stable_target = initial_b.target;
    initial_b.kernel.shutdown_all(Deadline::from_millis(1500));
    drop(initial_b);
    std::thread::sleep(scaled(Duration::from_millis(150)));
    let first_b = boot_b(&fixture, true);
    assert_eq!(first_b.ciphertext, rewrap_inventory[0].ciphertext);
    assert_eq!(first_b.target, stable_target, "the signed deployment target must stay pinned");
    assert_eq!(
        first_b.restart_filler,
        Some(stale_executor),
        "the stale executor id must resolve to an inert creature"
    );
    assert_ne!(first_b.executor, stale_executor, "the stable executor must reopen at a new id");
    corr += 100;
    corr = await_remote_route(&bus, &rx, first_b.locator, &fixture.home, corr);

    // This probe traverses Omega(NodeRole), not a numeric route, and proves the restarted executor
    // recovered the exact durable registration before the source Home submits work to it.
    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b_role(gawdfn::FUNCTION_EXECUTOR_ROLE),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &gawdfn::FunctionDeployMessageV1::Lookup {
            query: DeploymentQueryV1 {
                function: Some(fixture.function.clone()),
                realm: Some(REALM_B.into()),
                node: Some(NODE_B.into()),
                limit: 8,
            },
        },
    );
    corr += 1;
    let gawdfn::FunctionDeployMessageV1::Deployments { list } =
        serde_json::from_slice::<gawdfn::FunctionDeployMessageV1>(&env.payload).unwrap()
    else {
        panic!("changed-id executor did not answer the remote-role lookup")
    };
    assert_eq!(list.deployments, vec![deployment.clone()]);
    assert_eq!(
        fixture
            .remote_executor_lookups
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_slice(),
        &[first_b.executor],
        "inbound NodeRole must resolve to the changed executor, not the stale numeric id"
    );

    let submit = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSubmitV1 {
            home: fixture.home.clone(),
            caller_idempotency_key: "cross-realm-logical-call".into(),
            function: selector.clone(),
            input: sealed_input.clone(),
            delivery: DeliveryModeV1::AtMostOnce,
            allow_duplicate_effects: false,
            parent: None,
            causal: vec![],
            access: JobAccessV1::default(),
            evidence: vec![],
            result_recipients: vec![],
            submitted_at_unix_ms: None,
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let env = rpc(
        &bus,
        &rx,
        corr,
        Address::Creature(first_a.source),
        SCHEMA_JOB_V1,
        &JobMessageV1::Submit {
            request: Box::new(submit),
            resolution: Box::new(resolution.clone()),
            deployment: Box::new(deployment.clone()),
        },
    );
    corr += 1;
    let JobMessageV1::Accepted { handle, request_hash, submitted } =
        serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap()
    else {
        panic!("source Home did not durably accept")
    };
    verify_job_acceptance(&handle, &request_hash, &submitted).unwrap();
    assert_eq!(submitted.payload.sequence, 1);
    assert_eq!(submitted.payload.state_after, JobStateV1::Queued);

    // The target stays blocked after the executor's durable Claimed/Started facts. This makes the
    // Home handoff overlap a genuinely remote running attempt instead of a fabricated receipt.
    {
        let (lock, ready) = &*fixture.gate;
        let gate = lock.lock().unwrap_or_else(|poison| poison.into_inner());
        let (gate, _) = ready
            .wait_timeout_while(gate, scaled(Duration::from_secs(8)), |state| !state.entered)
            .unwrap_or_else(|poison| poison.into_inner());
        assert!(gate.entered, "typed target in Realm B was never called");
    }
    assert_eq!(
        fixture.grant_receivers.lock().unwrap_or_else(|poison| poison.into_inner()).as_slice(),
        &[first_b.executor],
        "A's source Home grant must traverse the remote role to the changed executor"
    );
    assert_eq!(
        fixture
            .target_executor_routes
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_slice(),
        &[first_b.executor.0.to_string()],
        "Forge-verified dispatch must bind the changed executor route"
    );
    let running = wait_for_state(
        &fixture,
        &bus,
        &rx,
        Address::Creature(first_a.source),
        &handle,
        JobStateV1::Running,
        &mut corr,
    );
    verify_job_snapshot(&running).unwrap();
    assert_eq!(running.payload.home_epoch, 1);

    // The Forge-verified target emits through its bound real Bus while its typed parent call remains
    // blocked. B's executor accepts the observation only from the grant-pinned target, signs it,
    // and sends it over Omega/TCP to the epoch-1 Home before that Home checkpoints its ledger.
    let parent_events = wait_for_events(
        &fixture,
        &bus,
        &rx,
        Address::Creature(first_a.source),
        &handle,
        &mut corr,
        |page| {
            page.events
                .iter()
                .any(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        },
    );
    for event in &parent_events.events {
        verify_job_event(event).unwrap();
    }
    let progress = parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        .cloned()
        .expect("source Home must durably retain remote target progress");
    let parent_attempt = match &progress.payload.kind {
        JobEventKindV1::Progress { attempt, sequence, progress: value } => {
            assert_eq!(*sequence, 1);
            assert_eq!(
                value,
                &ValueRefV1::Inline { value: json!({"phase": "remote-ready", "realm": REALM_B}) }
            );
            attempt.clone()
        }
        _ => unreachable!(),
    };
    let parent_grant = fixture
        .grants
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .iter()
        .find(|grant| grant.payload.attempt == parent_attempt)
        .cloned()
        .expect("changed-id executor must capture the exact parent grant");
    assert_eq!(parent_grant.payload.home_epoch, 1);
    assert_eq!(parent_grant.payload.deployment, deployment);
    verify_job_event_with_grant(&progress, &parent_grant).unwrap();
    let progress_receipt = progress.payload.foreign_receipt.as_deref().unwrap();
    verify_execution_receipt(progress_receipt, &parent_grant).unwrap();
    assert_eq!(progress_receipt.signer, fixture.executor_key.public_key());
    assert!(matches!(
        &progress_receipt.payload.stage,
        ExecutionStageV1::Progress {
            sequence: 1,
            progress: ValueRefV1::Inline { value },
        } if value == &json!({"phase": "remote-ready", "realm": REALM_B})
    ));
    let source_home_route = Address::Omega {
        realm: RealmId::new(REALM_A),
        target: Box::new(Address::Node(NodeId(NODE_A.into()), first_a.source)),
    };
    let b_journal = first_b.kernel.router().journal_snapshot();
    assert!(
        b_journal.iter().any(|entry| {
            entry.from == Address::Creature(first_b.target)
                && entry.to == Address::Creature(first_b.executor)
        }),
        "progress must enter the executor from the exact Forge-verified target route"
    );
    assert!(
        b_journal.iter().any(|entry| {
            entry.from == Address::Creature(first_b.executor) && entry.to == source_home_route
        }),
        "executor observations must leave B on the authenticated Omega route to the source Home"
    );

    // The source exports a signed archive into its injected checkpoint store. Copying the exact
    // bytes into B's separate CAS models a completed, verified GX transfer; it does not model GX.
    let checkpoint = first_a
        .source_home
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .create_checkpoint(None)
        .unwrap();
    let checkpoint_bytes =
        first_a.checkpoint_store.get_checkpoint(&checkpoint.payload.state).unwrap();
    let transferred = first_b
        .checkpoint_store
        .put_checkpoint(&checkpoint.payload.state.media_type, &checkpoint_bytes)
        .unwrap();
    assert_eq!(
        transferred, checkpoint.payload.state,
        "the completed GX stand-in must preserve the exact content address"
    );
    let custody_grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyGrantV1 {
            home: fixture.home.clone(),
            handoff: HandoffId::new("cross-realm-live-handoff"),
            from_epoch: 1,
            to_epoch: 2,
            source_authority: fixture.source_authority.clone(),
            source_realm: REALM_A.into(),
            source_node: NODE_A.into(),
            destination_realm: REALM_B.into(),
            destination_node: NODE_B.into(),
            checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
            source_log_root: checkpoint.payload.log_root.clone(),
            destination_operational_key: fixture.destination_authority.operational.clone(),
            evidence: vec![],
            issued_at_unix_ms: None,
            destination_rewrap: Some(fixture.rewrap_requirement()),
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let env = rpc(
        &bus,
        &rx,
        corr,
        Address::Creature(first_a.source),
        SCHEMA_HOME_V1,
        &HomeMessageV1::Prepare {
            grant: Box::new(custody_grant),
            checkpoint: Box::new(checkpoint),
        },
    );
    corr += 1;
    let HomeMessageV1::Prepared { prepared } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("source did not return its fsynced Prepared proof")
    };
    verify_custody_prepared(&prepared).unwrap();
    assert_eq!(prepared.payload.source_coordinator, first_a.source.0.to_string());
    assert_eq!(prepared.payload.rewrap_item_count, Some(1));
    assert_eq!(
        prepared.payload.rewrap_inventory_hash,
        Some(gawdfn::custody_rewrap_inventory_hash(&rewrap_inventory).unwrap())
    );

    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b(first_b.destination),
        SCHEMA_HOME_V1,
        &HomeMessageV1::Stage { prepared: prepared.clone() },
    );
    corr += 1;
    let staged_reply = serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap();
    let HomeMessageV1::Staged { staged } = staged_reply else {
        panic!("destination did not return its durable staging proof: {staged_reply:?}")
    };
    verify_custody_staged(&staged).unwrap();
    assert_eq!(staged.payload.destination_coordinator, first_b.destination.0.to_string());
    let rewrap_receipt = staged
        .payload
        .rewrap_receipt
        .as_deref()
        .cloned()
        .expect("Stage must carry the exact destination KMS proof");
    verify_custody_rewrap_receipt(&rewrap_receipt, &prepared).unwrap();
    assert_eq!(rewrap_receipt.payload.entries.len(), 1);
    assert_eq!(
        rewrap_receipt.payload.entries[0].destination_wrap.binding_hash,
        canonical_hash(&fixture.destination_binding).unwrap()
    );
    assert_eq!(
        *fixture.rewrap_calls.lock().unwrap_or_else(|poison| poison.into_inner()),
        vec![((*rewrap_receipt.payload.request).clone(), rewrap_inventory.clone())],
        "the destination adapter must receive the exact source-frozen inventory once"
    );

    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b(first_b.destination),
        SCHEMA_HOME_V1,
        &HomeMessageV1::Activate { staged: staged.clone() },
    );
    corr += 1;
    let HomeMessageV1::Activated { lease } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("destination did not activate")
    };
    let lease = *lease;
    verify_home_lease(&lease).unwrap();
    assert_eq!(lease.payload.realm, REALM_B);
    assert_eq!(lease.payload.node, NODE_B);
    assert_eq!(lease.payload.coordinator, first_b.destination.0.to_string());
    assert_eq!(lease.payload.epoch, 2);

    // The activated endpoint is already the stable address carried by the lease and serves the
    // imported running Job. Its local locator learned exactly that signed lease.
    let moved_running = wait_for_state(
        &fixture,
        &bus,
        &rx,
        remote_b(first_b.destination),
        &handle,
        JobStateV1::Running,
        &mut corr,
    );
    assert_eq!(moved_running.payload.home_epoch, 2);
    verify_job_snapshot(&moved_running).unwrap();
    match locate(&bus, &rx, remote_b(first_b.locator), &fixture.home, corr) {
        LocateMessageV1::Location { location } => assert_eq!(location.lease, lease),
        other => panic!("B locator did not follow activated lease: {other:?}"),
    }
    corr += 1;

    // Destination activation notifies the frozen source over the reverse Omega route. Poll its
    // independently signed custody status until that redirect is durable.
    let redirect_deadline = Instant::now() + scaled(Duration::from_secs(5));
    loop {
        let env = rpc(
            &bus,
            &rx,
            corr,
            Address::Creature(first_a.source),
            SCHEMA_HOME_V1,
            &HomeMessageV1::Status { home: fixture.home.clone() },
        );
        corr += 1;
        if let HomeMessageV1::StatusResult { status } =
            serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
        {
            verify_home_custody_status(&status).unwrap();
            if matches!(
                &status.payload.state,
                HomeCustodyPhaseV1::Frozen { redirect: Some(observed), .. }
                    if **observed == lease
            ) {
                break;
            }
        }
        assert!(Instant::now() < redirect_deadline, "source redirect was not recorded");
        std::thread::sleep(Duration::from_millis(20));
    }

    // The imported ledger contains the exact epoch-1 progress proof, not a destination-authored
    // reconstruction. Use that durable event as the causal receipt for an epoch-2 child proposal.
    let moved_parent_events =
        read_events(&fixture, &bus, &rx, remote_b(first_b.destination), &handle, corr);
    corr += 1;
    for event in &moved_parent_events.events {
        verify_job_event(event).unwrap();
    }
    let moved_progress = moved_parent_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Progress { .. }))
        .expect("migrated Home must retain the source-authored progress event");
    assert_eq!(moved_progress, &progress);
    let progress_hash = canonical_hash(moved_progress).unwrap();

    let child_submit = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSubmitV1 {
            home: fixture.home.clone(),
            caller_idempotency_key: "cross-realm-child".into(),
            function: selector.clone(),
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
        fixture.root.as_ref(),
    )
    .unwrap();
    let child_request_hash = child_submit.payload.request_hash().unwrap();
    let spawn = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            handle: handle.clone(),
            expected_home_epoch: 2,
            control: ControlId::new("spawn-cross-realm-child"),
            issued_at_unix_ms: None,
            kind: JobControlKindV1::ProposeChild {
                parent_attempt: parent_attempt.clone(),
                parent_event_hash: progress_hash.clone(),
                spawn_key: "remote-progress-child".into(),
                child_request_hash: child_request_hash.clone(),
                submit: Box::new(child_submit),
                resolution: Box::new(resolution.clone()),
                deployment: Box::new(deployment.clone()),
            },
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let spawn_message = JobMessageV1::Control { request: Box::new(spawn.clone()) };
    let first_spawn_corr = corr;
    let env = rpc(&bus, &rx, corr, remote_b(first_b.destination), SCHEMA_JOB_V1, &spawn_message);
    corr += 1;
    let spawned = match serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap() {
        JobMessageV1::ControlAccepted { request_hash, event } => {
            verify_job_control_acceptance(&spawn, &request_hash, &event).unwrap();
            *event
        }
        other => panic!("destination Home did not atomically accept the child: {other:?}"),
    };
    let child = match &spawned.payload.kind {
        JobEventKindV1::ChildSpawned {
            parent_attempt: recorded_attempt,
            parent_event_hash,
            spawn_key,
            child,
            root,
            child_request_hash: recorded_request_hash,
        } => {
            assert_eq!(recorded_attempt, &parent_attempt);
            assert_eq!(parent_event_hash, &progress_hash);
            assert_eq!(spawn_key, "remote-progress-child");
            assert_eq!(root, &handle);
            assert_eq!(recorded_request_hash, &child_request_hash);
            child.clone()
        }
        other => panic!("expected ChildSpawned, got {other:?}"),
    };

    let replay_spawn_corr = corr;
    let env = rpc(&bus, &rx, corr, remote_b(first_b.destination), SCHEMA_JOB_V1, &spawn_message);
    corr += 1;
    let replayed = match serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap() {
        JobMessageV1::ControlAccepted { request_hash, event } => {
            verify_job_control_acceptance(&spawn, &request_hash, &event).unwrap();
            *event
        }
        other => panic!("destination Home did not deduplicate the child: {other:?}"),
    };
    assert_eq!(replayed, spawned, "spawn replay must return the exact durable causal edge");
    let proposal_target = remote_b(first_b.destination);
    let a_journal = first_a.kernel.router().journal_snapshot();
    for proposal_corr in [first_spawn_corr, replay_spawn_corr] {
        assert!(
            a_journal.iter().any(|entry| {
                entry.from == Address::Creature(bus.id())
                    && entry.to == proposal_target
                    && entry.corr == Some(proposal_corr)
            }),
            "each child proposal must leave A on its explicit Omega/TCP route"
        );
    }

    // Release the parent only after both cross-Realm proposals have returned. The target then
    // finishes the parent, accepts the child's distinct Forge-verified dispatch, and reports the
    // child terminal normally to the active epoch-2 Home.
    {
        let (lock, ready) = &*fixture.gate;
        let mut gate = lock.lock().unwrap_or_else(|poison| poison.into_inner());
        gate.release = true;
        ready.notify_all();
    }
    let child_succeeded = wait_for_state(
        &fixture,
        &bus,
        &rx,
        remote_b(first_b.destination),
        &child,
        JobStateV1::Succeeded,
        &mut corr,
    );
    verify_job_snapshot(&child_succeeded).unwrap();
    assert_eq!(child_succeeded.payload.home_epoch, 2);
    assert_eq!(child_succeeded.payload.spec.root, handle);
    assert_eq!(child_succeeded.payload.spec.parent.as_ref(), Some(&handle));
    assert_eq!(child_succeeded.payload.spec.input, child_input());
    assert_eq!(
        child_succeeded.payload.result,
        Some(ValueRefV1::Inline { value: json!({"answer": 8, "child": "complete"}) })
    );
    let child_events =
        read_events(&fixture, &bus, &rx, remote_b(first_b.destination), &child, corr);
    corr += 1;
    for event in &child_events.events {
        verify_job_event(event).unwrap();
    }
    let child_submitted = child_events.events.first().expect("child Submitted event");
    let JobEventKindV1::Submitted { spec: child_spec } = &child_submitted.payload.kind else {
        panic!("child ledger must begin atomically with Submitted")
    };
    assert_eq!(child_spec.root, handle);
    assert_eq!(child_spec.parent.as_ref(), Some(&handle));
    assert_eq!(child_spec.causal.len(), 1);
    assert_eq!(child_spec.causal[0].job, handle);
    assert_eq!(child_spec.causal[0].relation, "spawned_by_progress");
    assert_eq!(child_spec.causal[0].receipt_hash.as_ref(), Some(&progress_hash));
    let child_attempt = child_events
        .events
        .iter()
        .find_map(|event| match &event.payload.kind {
            JobEventKindV1::DispatchGranted { attempt, .. } => Some(attempt.clone()),
            _ => None,
        })
        .expect("epoch-2 Home must durably grant the child dispatch");
    let child_grant = fixture
        .grants
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .iter()
        .find(|grant| grant.payload.attempt == child_attempt)
        .cloned()
        .expect("changed-id executor must capture the exact child grant");
    assert_eq!(child_grant.payload.home_epoch, 2);
    assert_eq!(child_grant.payload.home_realm, REALM_B);
    assert_eq!(child_grant.payload.home_node, NODE_B);
    assert_eq!(child_grant.payload.home_coordinator, first_b.destination.0.to_string());
    assert_eq!(child_grant.payload.deployment, deployment);
    let child_terminal = child_events
        .events
        .iter()
        .find(|event| matches!(event.payload.kind, JobEventKindV1::Succeeded { .. }))
        .expect("child must durably complete at the epoch-2 Home");
    verify_job_event_with_grant(child_terminal, &child_grant).unwrap();
    let child_receipt = child_terminal.payload.foreign_receipt.as_deref().unwrap();
    verify_execution_receipt(child_receipt, &child_grant).unwrap();
    assert_eq!(child_receipt.signer, fixture.executor_key.public_key());
    assert!(matches!(
        &child_receipt.payload.stage,
        ExecutionStageV1::Succeeded {
            result: ValueRefV1::Inline { value },
        } if value == &json!({"answer": 8, "child": "complete"})
    ));
    assert_eq!(fixture.child_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        fixture.grant_receivers.lock().unwrap_or_else(|poison| poison.into_inner()).as_slice(),
        &[first_b.executor, first_b.executor],
        "both the remote parent grant and local epoch-2 child grant reach the live executor"
    );

    // The executor commits the parent terminal receipt, then the fixture loses its immediate push.
    // Recovery must pull that durable fact from the changed executor route.
    let terminal_deadline = Instant::now() + scaled(Duration::from_secs(5));
    while !fixture.terminal_recorded.load(Ordering::SeqCst) {
        assert!(Instant::now() < terminal_deadline, "executor did not durably record result");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1);

    // Close both Sanctums and every endpoint, then rebuild them over the same authenticated peer
    // identities and durable stores. This is a full Kernel/store reopen, not merely reconstructing
    // the organ value in place.
    drop(bus);
    drop(rx);
    first_a.kernel.shutdown_all(Deadline::from_millis(1500));
    first_b.kernel.shutdown_all(Deadline::from_millis(1500));
    let old_ids = (
        first_a.source,
        first_a.locator,
        first_b.target,
        first_b.executor,
        first_b.locator,
        first_b.destination,
    );
    drop(first_a);
    drop(first_b);
    fixture.executor_queries.lock().unwrap_or_else(|poison| poison.into_inner()).clear();
    fixture.remote_executor_lookups.lock().unwrap_or_else(|poison| poison.into_inner()).clear();
    std::thread::sleep(scaled(Duration::from_millis(150)));

    let second_b = boot_b(&fixture, true);
    let second_a = boot_a(&fixture);
    assert_eq!(second_a.ciphertext, rewrap_inventory[0].ciphertext);
    assert_eq!(second_b.ciphertext, rewrap_inventory[0].ciphertext);
    assert_eq!(
        old_ids,
        (
            second_a.source,
            second_a.locator,
            second_b.target,
            second_b.executor,
            second_b.locator,
            second_b.destination,
        ),
        "the later full reopen must preserve the already-shifted live layout"
    );
    assert_eq!(
        second_b.restart_filler,
        Some(stale_executor),
        "the stale pre-Submit executor route must remain occupied by the inert creature"
    );
    let (_probe, bus, rx) = second_a.kernel.open_endpoint(Capabilities::default());
    corr += 100;
    corr = await_remote_route(&bus, &rx, second_b.locator, &fixture.home, corr);

    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b(second_b.destination),
        SCHEMA_HOME_V1,
        &HomeMessageV1::Status { home: fixture.home.clone() },
    );
    corr += 1;
    let HomeMessageV1::StatusResult { status } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("reopened destination did not answer custody status")
    };
    verify_home_custody_status(&status).unwrap();
    assert!(matches!(
        status.payload.state,
        HomeCustodyPhaseV1::Active { staged: Some(ref staged), .. }
            if staged.payload.rewrap_receipt.as_deref() == Some(&rewrap_receipt)
    ));
    assert_eq!(
        fixture.rewrap_calls.lock().unwrap_or_else(|poison| poison.into_inner()).len(),
        1,
        "reopen must recover the durable receipt without repeating KMS work"
    );

    // Executor registration survived reopen and is still advertised only because the exact target
    // manifest/build identity is loaded at the same route.
    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b_role(gawdfn::FUNCTION_EXECUTOR_ROLE),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &gawdfn::FunctionDeployMessageV1::Lookup {
            query: DeploymentQueryV1 {
                function: Some(fixture.function.clone()),
                realm: Some(REALM_B.into()),
                node: Some(NODE_B.into()),
                limit: 8,
            },
        },
    );
    corr += 1;
    let gawdfn::FunctionDeployMessageV1::Deployments { list } =
        serde_json::from_slice::<gawdfn::FunctionDeployMessageV1>(&env.payload).unwrap()
    else {
        panic!("reopened executor did not answer lookup")
    };
    assert_eq!(list.deployments, vec![deployment.clone()]);
    assert_eq!(
        fixture
            .remote_executor_lookups
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_slice(),
        &[second_b.executor],
        "inbound NodeRole must resolve to the changed executor, not the stale numeric id"
    );

    // The cold destination replays activation idempotently. Opening the imported Home immediately
    // emits a Query to the recovered executor; that pull reconciles the terminal receipt which was
    // originally addressed to the now-frozen epoch-1 source.
    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b(second_b.destination),
        SCHEMA_HOME_V1,
        &HomeMessageV1::Activate { staged },
    );
    corr += 1;
    let HomeMessageV1::Activated { lease: reopened_lease } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("reopened destination did not replay activation")
    };
    let reopened_lease = *reopened_lease;
    verify_home_lease(&reopened_lease).unwrap();
    assert!(
        is_home_lease_coordinator_revision(&lease.payload, &reopened_lease.payload),
        "restart may revise only the process-local coordinator route"
    );
    assert_eq!(reopened_lease.payload.coordinator, second_b.destination.0.to_string());

    let succeeded = wait_for_state(
        &fixture,
        &bus,
        &rx,
        remote_b(second_b.destination),
        &handle,
        JobStateV1::Succeeded,
        &mut corr,
    );
    verify_job_snapshot(&succeeded).unwrap();
    assert_eq!(succeeded.payload.home_epoch, 2);
    assert_eq!(succeeded.payload.spec.input, sealed_input);
    assert_eq!(succeeded.payload.result, Some(ValueRefV1::Inline { value: json!({"answer": 42}) }));
    assert_eq!(fixture.calls.load(Ordering::SeqCst), 1, "reopen must not invoke again");
    assert_eq!(
        fixture.child_calls.load(Ordering::SeqCst),
        1,
        "reopen must not replay the already-terminal causal child"
    );
    let executor_queries =
        fixture.executor_queries.lock().unwrap_or_else(|poison| poison.into_inner());
    assert!(
        executor_queries.contains(&second_b.executor),
        "destination recovery Query must reach the changed live executor role"
    );
    assert!(
        !executor_queries.contains(&stale_executor),
        "destination recovery must not query the stale numeric executor route"
    );

    let caller = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EventQueryV1 {
            handle: handle.clone(),
            after_sequence: None,
            limit: 64,
            nonce: format!("events-{corr}"),
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EventQueryRelayV1 {
            caller,
            reply_to: serde_json::to_string(&Address::Node(NodeId(NODE_A.into()), bus.id()))
                .unwrap(),
        },
        fixture.root.as_ref(),
    )
    .unwrap();
    let env = rpc(
        &bus,
        &rx,
        corr,
        remote_b(second_b.destination),
        SCHEMA_JOB_V1,
        &JobMessageV1::Events { request: Box::new(request.clone()) },
    );
    corr += 1;
    let JobMessageV1::EventPage { response } =
        serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap()
    else {
        panic!("moved Home did not return its event chain")
    };
    verify_event_page_response_for(&response, &request).unwrap();
    let EventPageV1 { events, .. } = response.payload.page;
    for event in &events {
        verify_job_event(event).unwrap();
    }
    let terminal = events
        .iter()
        .find(|event| matches!(event.payload.kind, gawdfn::JobEventKindV1::Succeeded { .. }))
        .expect("terminal Home event retains executor provenance");
    let grant = fixture
        .grants
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .first()
        .cloned()
        .expect("executor observed the exact remote grant");
    verify_job_event_with_grant(terminal, &grant).unwrap();
    let foreign = terminal.payload.foreign_receipt.as_deref().unwrap();
    verify_execution_receipt(foreign, &grant).unwrap();
    assert_eq!(foreign.signer, fixture.executor_key.public_key());
    assert!(matches!(
        foreign.payload.stage,
        ExecutionStageV1::Succeeded {
            result: ValueRefV1::Inline { ref value }
        } if value == &json!({"answer": 42})
    ));

    // Both durable locator views and the frozen source converge on the exact root-authorized
    // epoch-2 lease after reopen.
    for target in [Address::Creature(second_a.locator), remote_b(second_b.locator)] {
        let deadline = Instant::now() + scaled(Duration::from_secs(5));
        loop {
            let located = locate(&bus, &rx, target.clone(), &fixture.home, corr);
            corr += 1;
            if matches!(
                located,
                LocateMessageV1::Location { ref location }
                    if location.lease == reopened_lease
            ) {
                break;
            }
            assert!(Instant::now() < deadline, "locator did not converge on refreshed Home lease");
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    let redirect_deadline = Instant::now() + scaled(Duration::from_secs(5));
    loop {
        let env = rpc(
            &bus,
            &rx,
            corr,
            Address::Creature(second_a.source),
            SCHEMA_HOME_V1,
            &HomeMessageV1::Status { home: fixture.home.clone() },
        );
        corr += 1;
        if let HomeMessageV1::StatusResult { status } =
            serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
        {
            verify_home_custody_status(&status).unwrap();
            if matches!(
                status.payload.state,
                HomeCustodyPhaseV1::Frozen { redirect: Some(ref observed), .. }
                    if **observed == reopened_lease
            ) {
                break;
            }
        }
        assert!(
            Instant::now() < redirect_deadline,
            "reopened source did not converge on refreshed Home redirect"
        );
        std::thread::sleep(Duration::from_millis(20));
    }

    drop(bus);
    drop(rx);
    second_a.kernel.shutdown_all(Deadline::from_millis(1500));
    second_b.kernel.shutdown_all(Deadline::from_millis(1500));
}
