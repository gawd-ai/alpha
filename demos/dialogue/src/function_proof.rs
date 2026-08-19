//! The v0.5 candidate's execution cut after dialogue: publish one approved capability implemented
//! by all three engines, then execute each backend-specific [`FunctionId`] in a local compute world
//! and an authenticated cross-Realm world. Fixture mode regresses this mechanism; only a retained,
//! operator-sealed live run contributes product-acceptance evidence.
//!
//! This is intentionally demo-local orchestration over production organs. The exhaustive Function
//! restart/custody/control matrices remain in `sanctum` integration tests; this module proves only
//! the new conjunction from constrained model decisions and trusted lowering to a running, durable
//! typed capability. It does not claim arbitrary code synthesis or general agency.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Ed25519Signer, Envelope,
    InboxReceiver, NodeId, Outcome, RealmId, Role, Topic,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use bestiary::CatalogEntry;
use function_executor::{
    DeploymentAdmission, DeploymentLiveness, ExecutorConfig, FunctionExecutor, StringAddressing,
};
use function_home::{FunctionHome, FunctionMetadata, FunctionTrust, HomeConfig};
use function_resolver::{FunctionCatalog, FunctionResolver};
use gawdfn::{
    canonical_hash, derive_deployment_id, derive_job_id, verify_deployment_receipt,
    verify_event_page_response_for, verify_execution_grant, verify_execution_receipt,
    verify_job_acceptance, verify_job_event, verify_job_event_with_grant, verify_job_snapshot,
    verify_job_snapshot_response_for, AbodeKeyBindingV1, AuthoritySigner, BlobAvailability,
    BlobRefV1, ContractError, DeliveryModeV1, DeploymentReceiptV1, DeploymentRegistrationV1,
    DeploymentRequestV1, Ed25519SeedSigner, EffectClassV1, EntrypointContractV1, EventQueryRelayV1,
    EventQueryV1, EvidenceRefV1, ExecuteMessageV1, ExecutionGrantV1, ExecutionReceiptV1,
    FunctionAlias, FunctionCallMessageV1, FunctionCallV1, FunctionControlsV1,
    FunctionDeployMessageV1, FunctionId, FunctionSelectorV1, HomeAuthorityV1, HomeId, JobAccessV1,
    JobEventKindV1, JobEventV1, JobGetRelayV1, JobGetV1, JobHandleV1, JobMessageV1, JobSnapshotV1,
    JobStateV1, JobSubmitV1, OperationalCapabilityV1, OperationalKeyGrantV1, PlacementDecisionV1,
    ResolutionReceiptV1, ResolveRequestV1, ResolvedFunctionV1, RetryDecisionV1, SchemaRefV1,
    SignedRecordV1, UndeployRequestV1, Validate, ValueRefV1, FUNCTION_EXECUTOR_ROLE,
    FUNCTION_HOME_ROLE, FUNCTION_POLICY_ROLE, FUNCTION_RESOLVER_ROLE, SCHEMA_CALL_V1,
    SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1, SCHEMA_JOB_V1,
};
use omega_federator::{FederatorConfig, OmegaFederator};
use policy_job_basic::{BasicJobPolicy, BasicPolicyCaps};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

use crate::decisions::{evaluate_affine, FinalCapabilitySpecV1};

const REALM_A: &str = "reviewers";
const REALM_B: &str = "builders";
const NODE_A: &str = "reviewer-home";
const NODE_B: &str = "builder-executor";
const MESH_BIND_ATTEMPTS: usize = 3;
pub const EXECUTION_PROOF_BUNDLE_SCHEMA_V1: &str = "gawd.dialogue.execution-proof-bundle.v1";
const COMPLETE_SUCCESS_EVENT_COUNT: usize = 5;

type PeerProbe = (aether::BusHandle, InboxReceiver);
type MeshKernel = (Arc<Kernel>, Option<PeerProbe>);
type ReadyMesh = (Arc<Kernel>, Arc<Kernel>, aether::BusHandle, InboxReceiver);

/// The exact published object shared by both proof worlds.
#[derive(Clone)]
pub(crate) struct PublishedCapability {
    pub manifest: Manifest,
    pub artifact: Vec<u8>,
    pub artifact_hash: String,
    /// Exact trusted-lowered source bytes supplied to the tier builder. The approved model record
    /// contains no source. Native and beast builds transform these bytes; a critter's artifact is
    /// the source itself.
    pub source: Vec<u8>,
    pub source_hash: String,
    /// One signed dialogue approval authorizes every member of the three-tier suite. It is carried
    /// through the existing advisory evidence fields, never treated as authority by itself.
    pub approval_digest: String,
}

#[derive(Clone, Debug)]
pub(crate) struct TierJobProof {
    pub function: FunctionId,
    pub local: JobHandleV1,
    pub local_receipt: SignedRecordV1<ExecutionReceiptV1>,
    pub local_input: i32,
    pub local_result: i32,
    pub local_proof: RetainedJobProofV1,
    pub remote: JobHandleV1,
    pub remote_receipt: SignedRecordV1<ExecutionReceiptV1>,
    pub remote_input: i32,
    pub remote_result: i32,
    pub remote_proof: RetainedJobProofV1,
}

/// Offline-verifiable evidence assembled exclusively from existing `gawdfn` wire records.
///
/// The duplicated named records must be byte-equal to their entries in `complete_home_events`.
/// Keeping them named makes the acceptance, authorization, and terminal facts discoverable while
/// the complete contiguous event log plus terminal snapshot proves there was exactly one attempt.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedJobProofV1 {
    pub schema: String,
    pub submission: SignedRecordV1<JobSubmitV1>,
    pub acceptance: SignedRecordV1<JobEventV1>,
    pub deployment: SignedRecordV1<DeploymentReceiptV1>,
    pub dispatch_authorization: SignedRecordV1<JobEventV1>,
    pub grant: SignedRecordV1<ExecutionGrantV1>,
    pub function_call: FunctionCallV1,
    pub terminal_home_event: SignedRecordV1<JobEventV1>,
    pub terminal_receipt: SignedRecordV1<ExecutionReceiptV1>,
    pub terminal_snapshot: SignedRecordV1<JobSnapshotV1>,
    pub complete_home_events: Vec<SignedRecordV1<JobEventV1>>,
}

struct VerifiedJob {
    handle: JobHandleV1,
    receipt: SignedRecordV1<ExecutionReceiptV1>,
    input: i32,
    result: i32,
    proof: RetainedJobProofV1,
}

impl RetainedJobProofV1 {
    /// Reverify the complete portable chain without trusting the live process that assembled it.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema != EXECUTION_PROOF_BUNDLE_SCHEMA_V1 {
            return Err("execution proof bundle has an unknown schema".into());
        }

        self.submission.validate().map_err(|error| error.to_string())?;
        if self.submission.schema != SCHEMA_JOB_V1
            || !self.submission.verify()
            || self.submission.signer != self.submission.payload.home.as_str()
        {
            return Err("Job submission is not signed by its named Home root".into());
        }
        let request_hash = self.submission.payload.request_hash().map_err(|e| e.to_string())?;
        let expected_handle = JobHandleV1 {
            home: self.submission.payload.home.clone(),
            job: derive_job_id(
                &self.submission.payload.home,
                &self.submission.payload.caller_idempotency_key,
            )
            .map_err(|error| error.to_string())?,
        };

        verify_job_acceptance(&expected_handle, &request_hash, &self.acceptance)
            .map_err(|error| error.to_string())?;
        let accepted_spec = match &self.acceptance.payload.kind {
            JobEventKindV1::Submitted { spec } => spec.as_ref(),
            _ => return Err("retained Job acceptance is not a Submitted event".into()),
        };
        if accepted_spec.function.resolution.is_none() {
            return Err("retained Job acceptance omitted its signed resolution proof".into());
        }
        if accepted_spec.handle != expected_handle
            || accepted_spec.root != expected_handle
            || accepted_spec.caller_idempotency_key
                != self.submission.payload.caller_idempotency_key
            || accepted_spec.request_hash != request_hash
            || accepted_spec.function.requested != self.submission.payload.function
            || accepted_spec.input != self.submission.payload.input
            || accepted_spec.delivery != self.submission.payload.delivery
            || accepted_spec.allow_duplicate_effects
                != self.submission.payload.allow_duplicate_effects
            || accepted_spec.parent != self.submission.payload.parent
            || accepted_spec.causal != self.submission.payload.causal
            || accepted_spec.access != self.submission.payload.access
            || accepted_spec.evidence != self.submission.payload.evidence
            || accepted_spec.result_recipients != self.submission.payload.result_recipients
        {
            return Err("Home acceptance changed the exact signed Job submission".into());
        }

        verify_deployment_receipt(&self.deployment).map_err(|error| error.to_string())?;
        if accepted_spec.deployment != self.deployment
            || accepted_spec.function.function != self.deployment.payload.function
            || accepted_spec.function.artifact_hash != self.deployment.payload.artifact_hash
        {
            return Err("accepted Job is not bound to the retained deployment receipt".into());
        }

        verify_execution_grant(&self.grant).map_err(|error| error.to_string())?;
        if self.grant.signer != self.acceptance.signer
            || self.grant.payload.authority != self.acceptance.payload.authority
            || self.grant.payload.home_epoch != self.acceptance.payload.home_epoch
            || self.grant.payload.attempt.home != expected_handle.home
            || self.grant.payload.attempt.job != expected_handle.job
            || self.grant.payload.attempt.number != 1
            || self.grant.payload.owner != expected_handle.home
            || self.grant.payload.request_hash != request_hash
            || self.grant.payload.function != accepted_spec.function.function
            || self.grant.payload.deployment != self.deployment
            || self.grant.payload.input != accepted_spec.input
            || self.grant.payload.delivery != accepted_spec.delivery
        {
            return Err(
                "execution grant changed its accepted Job, Home, Function, or deployment".into()
            );
        }

        verify_job_event(&self.dispatch_authorization).map_err(|error| error.to_string())?;
        let grant_hash = canonical_hash(&self.grant).map_err(|error| error.to_string())?;
        if self.dispatch_authorization.signer != self.grant.signer
            || self.dispatch_authorization.payload.authority != self.grant.payload.authority
            || self.dispatch_authorization.payload.home_epoch != self.grant.payload.home_epoch
            || self.dispatch_authorization.payload.handle != expected_handle
            || self.dispatch_authorization.payload.state_after != JobStateV1::Dispatching
            || !matches!(
                &self.dispatch_authorization.payload.kind,
                JobEventKindV1::DispatchGranted {
                    grant_hash: authorized_hash,
                    attempt,
                } if authorized_hash == &grant_hash && attempt == &self.grant.payload.attempt
            )
        {
            return Err("DispatchGranted event does not authorize the exact signed grant".into());
        }

        self.function_call.validate().map_err(|error| error.to_string())?;
        if self.function_call.grant.as_ref() != &self.grant
            || self.function_call.attempt != self.grant.payload.attempt
            || self.function_call.function != self.grant.payload.function
            || self.function_call.input != self.grant.payload.input
            || self.function_call.executor_dispatch.payload.executor_creature
                != self.deployment.payload.executor_creature
            || self.function_call.executor_dispatch.payload.target_creature
                != self.deployment.payload.creature
        {
            return Err(
                "typed Function call changed the exact grant or signed executor route".into()
            );
        }

        verify_execution_receipt(&self.terminal_receipt, &self.grant)
            .map_err(|error| error.to_string())?;
        verify_job_event_with_grant(&self.terminal_home_event, &self.grant)
            .map_err(|error| error.to_string())?;
        let terminal_result = match &self.terminal_home_event.payload.kind {
            JobEventKindV1::Succeeded { attempt, result }
                if attempt == &self.grant.payload.attempt =>
            {
                result
            }
            _ => return Err("retained terminal Home event is not the granted success".into()),
        };
        let terminal_foreign_receipt = self
            .terminal_home_event
            .payload
            .foreign_receipt
            .as_deref()
            .ok_or_else(|| "terminal Home event omitted its executor receipt".to_string())?;
        let receipt_result = match &self.terminal_receipt.payload.stage {
            gawdfn::ExecutionStageV1::Succeeded { result } => result,
            _ => return Err("retained terminal executor receipt is not Succeeded".into()),
        };
        if terminal_foreign_receipt != &self.terminal_receipt
            || terminal_result != receipt_result
            || self.terminal_home_event.payload.state_after != JobStateV1::Succeeded
        {
            return Err("terminal Home event and executor receipt are not byte-exact peers".into());
        }

        verify_job_snapshot(&self.terminal_snapshot).map_err(|error| error.to_string())?;
        if self.terminal_snapshot.payload.spec != *accepted_spec
            || self.terminal_snapshot.payload.state != JobStateV1::Succeeded
            || self.terminal_snapshot.payload.cancel_requested
            || self.terminal_snapshot.payload.current_attempt.as_ref()
                != Some(&self.grant.payload.attempt)
            || self.terminal_snapshot.payload.result.as_ref() != Some(terminal_result)
            || self.terminal_snapshot.payload.error.is_some()
            || self.terminal_snapshot.payload.home_epoch != self.grant.payload.home_epoch
            || self.terminal_snapshot.payload.authority != self.grant.payload.authority
        {
            return Err("terminal snapshot changed the accepted Job, attempt, or result".into());
        }

        validate_complete_success_events(
            &self.complete_home_events,
            &expected_handle,
            &self.grant,
            self.terminal_snapshot.payload.last_sequence,
        )?;
        if self.complete_home_events.first() != Some(&self.acceptance)
            || self.complete_home_events.get(1) != Some(&self.dispatch_authorization)
            || self.complete_home_events.last() != Some(&self.terminal_home_event)
        {
            return Err("named proof records diverged from the complete Home event log".into());
        }

        // Parsing the application values is deliberately last: all authority and lineage checks
        // above must stand independently of a convenient scalar summary.
        exact_inline_i32(&self.submission.payload.input, "value")?;
        exact_inline_i32(terminal_result, "result")?;
        Ok(())
    }

    pub fn validate_topology(
        &self,
        expected_home_realm: &str,
        expected_home_node: &str,
        expected_deployment_realm: &str,
        expected_deployment_node: &str,
    ) -> Result<(), String> {
        self.validate()?;
        if self.grant.payload.home_realm != expected_home_realm
            || self.grant.payload.home_node != expected_home_node
            || self.deployment.payload.realm != expected_deployment_realm
            || self.deployment.payload.node != expected_deployment_node
        {
            return Err(
                "signed Home/deployment topology differs from the required proof world".into()
            );
        }
        Ok(())
    }

    pub fn input_i32(&self) -> Result<i32, String> {
        exact_inline_i32(&self.submission.payload.input, "value")
    }

    pub fn result_i32(&self) -> Result<i32, String> {
        let result = match &self.terminal_receipt.payload.stage {
            gawdfn::ExecutionStageV1::Succeeded { result } => result,
            _ => return Err("retained terminal executor receipt is not Succeeded".into()),
        };
        exact_inline_i32(result, "result")
    }

    pub fn attempt_count(&self) -> u8 {
        self.complete_home_events
            .iter()
            .filter(|event| matches!(event.payload.kind, JobEventKindV1::DispatchGranted { .. }))
            .count()
            .try_into()
            .unwrap_or(u8::MAX)
    }
}

fn validate_complete_success_events(
    events: &[SignedRecordV1<JobEventV1>],
    handle: &JobHandleV1,
    grant: &SignedRecordV1<ExecutionGrantV1>,
    last_sequence: u64,
) -> Result<(), String> {
    if events.len() != COMPLETE_SUCCESS_EVENT_COUNT {
        return Err(format!(
            "complete one-attempt proof requires {COMPLETE_SUCCESS_EVENT_COUNT} Home events; found {}",
            events.len()
        ));
    }
    validate_complete_sequence_window(
        &events.iter().map(|event| event.payload.sequence).collect::<Vec<_>>(),
        last_sequence,
    )?;
    let expected_states = [
        JobStateV1::Queued,
        JobStateV1::Dispatching,
        JobStateV1::Dispatching,
        JobStateV1::Running,
        JobStateV1::Succeeded,
    ];
    for (index, event) in events.iter().enumerate() {
        verify_job_event(event).map_err(|error| error.to_string())?;
        if &event.payload.handle != handle
            || event.payload.home_epoch != grant.payload.home_epoch
            || event.payload.authority != grant.payload.authority
            || event.signer != grant.signer
            || event.payload.cancel_requested
            || event.payload.state_after != expected_states[index]
        {
            return Err(
                "complete Home event log changed handle, authority, lifecycle state, or cancellation state"
                    .into()
            );
        }
        match (index, &event.payload.kind) {
            (0, JobEventKindV1::Submitted { .. }) => {
                if event.payload.foreign_receipt.is_some() {
                    return Err("Submitted event unexpectedly carries an executor receipt".into());
                }
            }
            (1, JobEventKindV1::DispatchGranted { attempt, .. })
                if attempt == &grant.payload.attempt =>
            {
                if event.payload.foreign_receipt.is_some() {
                    return Err("DispatchGranted unexpectedly carries an executor receipt".into());
                }
            }
            (2, JobEventKindV1::Claimed { attempt, executor })
                if attempt == &grant.payload.attempt
                    && executor == &grant.payload.deployment.payload.executor =>
            {
                validate_event_receipt(event, grant, 1)?;
            }
            (3, JobEventKindV1::Started { attempt }) if attempt == &grant.payload.attempt => {
                validate_event_receipt(event, grant, 2)?;
            }
            (4, JobEventKindV1::Succeeded { attempt, .. })
                if attempt == &grant.payload.attempt =>
            {
                validate_event_receipt(event, grant, 3)?;
            }
            _ => {
                return Err(
                    "complete Home event log is not Submitted→DispatchGranted→Claimed→Started→Succeeded"
                        .into(),
                )
            }
        }
    }
    Ok(())
}

fn validate_event_receipt(
    event: &SignedRecordV1<JobEventV1>,
    grant: &SignedRecordV1<ExecutionGrantV1>,
    expected_sequence: u64,
) -> Result<(), String> {
    verify_job_event_with_grant(event, grant).map_err(|error| error.to_string())?;
    let receipt = event
        .payload
        .foreign_receipt
        .as_deref()
        .ok_or_else(|| "executor-derived Home event omitted its exact receipt".to_string())?;
    if receipt.payload.sequence != expected_sequence {
        return Err("executor receipt sequence is not the exact one-attempt 1→2→3 chain".into());
    }
    Ok(())
}

fn validate_complete_sequence_window(sequences: &[u64], last_sequence: u64) -> Result<(), String> {
    if sequences.is_empty()
        || sequences.last().copied() != Some(last_sequence)
        || sequences
            .iter()
            .copied()
            .enumerate()
            .any(|(index, observed)| observed != index as u64 + 1)
    {
        return Err("Home event proof is not one complete contiguous 1..=last_sequence log".into());
    }
    Ok(())
}

fn exact_inline_i32(value: &ValueRefV1, key: &str) -> Result<i32, String> {
    match value {
        ValueRefV1::Inline { value } => value
            .as_object()
            .filter(|object| object.len() == 1)
            .and_then(|object| object.get(key))
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| format!("retained value is not the exact {{{key}: i32}} shape")),
        _ => Err("retained proof unexpectedly refers to an external value".into()),
    }
}

#[derive(Clone)]
struct StaticCatalog(Vec<CatalogEntry>);

impl FunctionCatalog for StaticCatalog {
    fn candidates(&self, _request: &ResolveRequestV1) -> Result<Vec<CatalogEntry>, String> {
        Ok(self.0.clone())
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
        let Some(deployment_hash) = normalize_sha256(&deployment.artifact_hash) else {
            return Ok(false);
        };
        let Some(loaded_hash) = identity.artifact_sha256.as_deref().and_then(normalize_sha256)
        else {
            return Ok(false);
        };
        Ok(identity.manifest_content_address.as_deref()
            == Some(deployment.function.manifest_content_address.as_str())
            && loaded_hash == deployment_hash)
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
            .ok_or_else(|| "deployment is not authorized by this Home's Abode".into())
    }

    fn undeploy(
        &self,
        request: &SignedRecordV1<UndeployRequestV1>,
        _deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        (request.signer == self.0)
            .then_some(())
            .ok_or_else(|| "undeploy is not authorized by this Home's Abode".into())
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
            .ok_or_else(|| "execution receipt is not from the pinned executor".into())
    }

    fn allow_placement_decision(
        &self,
        decision: &SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "placement decision is not from the pinned policy".into())
    }

    fn allow_retry_decision(
        &self,
        decision: &SignedRecordV1<RetryDecisionV1>,
    ) -> Result<(), String> {
        (decision.signer == self.policy)
            .then_some(())
            .ok_or_else(|| "retry decision is not from the pinned policy".into())
    }
}

struct InlineOnly;

impl BlobAvailability for InlineOnly {
    fn verify_available(&self, _blob: &BlobRefV1) -> Result<(), ContractError> {
        Err(ContractError::Invalid("this acceptance proof permits inline values only".into()))
    }
}

/// Adds only observability around the production executor. Routing, durable claiming, typed call,
/// and receipt construction remain owned by [`FunctionExecutor`].
struct CapturingExecutor {
    inner: FunctionExecutor,
    capture: Arc<Mutex<ExecutionCapture>>,
}

#[derive(Default)]
struct ExecutionCapture {
    grants: Vec<SignedRecordV1<ExecutionGrantV1>>,
    calls: Vec<FunctionCallV1>,
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
                self.capture
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .grants
                    .push(*grant);
            }
        }
        let outcome = self.inner.handle(env);
        let calls = outcome
            .dispatches
            .iter()
            .filter(|dispatch| dispatch.schema == SCHEMA_CALL_V1)
            .filter_map(|dispatch| {
                match serde_json::from_slice::<FunctionCallMessageV1>(&dispatch.payload) {
                    Ok(FunctionCallMessageV1::Call { call }) => Some(*call),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        if !calls.is_empty() {
            self.capture.lock().unwrap_or_else(|poison| poison.into_inner()).calls.extend(calls);
        }
        outcome
    }

    fn shutdown(&mut self, deadline: Deadline) {
        self.inner.shutdown(deadline);
    }
}

struct Authorities {
    root: Arc<Ed25519SeedSigner>,
    operational: Arc<Ed25519SeedSigner>,
    resolver: Arc<Ed25519SeedSigner>,
    executor: Arc<Ed25519SeedSigner>,
    policy: Arc<Ed25519SeedSigner>,
    home: HomeId,
    authority: HomeAuthorityV1,
}

impl Authorities {
    fn generate() -> Result<Self, String> {
        let root = fresh_authority_signer("Function Home root")?;
        let operational = fresh_authority_signer("Function Home operational")?;
        let resolver = fresh_authority_signer("Function resolver")?;
        let executor = fresh_authority_signer("Function executor")?;
        let policy = fresh_authority_signer("Function policy")?;
        let home = HomeId::new(root.public_key());
        let abode = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            AbodeKeyBindingV1 {
                abode: home.clone(),
                root_public_key: root.public_key().into(),
                issued_at_unix_ms: None,
            },
            root.as_ref(),
        )
        .map_err(|e| e.to_string())?;
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
            root.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        Ok(Self {
            root,
            operational,
            resolver,
            executor,
            policy,
            home,
            authority: HomeAuthorityV1 { abode, operational: operational_grant, prepared: None },
        })
    }

    fn trust(&self) -> Arc<dyn FunctionTrust> {
        Arc::new(PinnedTrust {
            resolver: self.resolver.public_key().into(),
            executor: self.executor.public_key().into(),
            policy: self.policy.public_key().into(),
        })
    }
}

fn fresh_authority_signer(label: &str) -> Result<Arc<Ed25519SeedSigner>, String> {
    let (_, seed) = Ed25519KeyMaterial::generate()
        .map_err(|error| format!("could not generate {label} identity: {error}"))?;
    Ed25519SeedSigner::from_seed(seed)
        .map(Arc::new)
        .map_err(|error| format!("could not construct {label} signer: {error}"))
}

fn fresh_node_key(label: &str) -> Result<Ed25519KeyMaterial, String> {
    Ed25519KeyMaterial::generate()
        .map(|(key, _)| key)
        .map_err(|error| format!("could not generate {label} identity: {error}"))
}

fn signed_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut manifest = Manifest::new(name, "0.1.0", sigil::Backend::Daemon, "gawd_creature_v1");
    manifest.provenance.author = Some(key.public_hex().to_string());
    manifest.content_address = Some(manifest.compute_content_address());
    manifest.provenance.signature = Some(key.sign(&manifest.signing_payload()));
    manifest
}

fn kernel(node_key: &Ed25519KeyMaterial, artifact_author: &str) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(node_key.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![
            node_key.public_hex().to_string(),
            artifact_author.to_string(),
        ])),
        256,
    )
}

#[allow(clippy::too_many_arguments)]
fn mesh_kernel(
    node: &str,
    realm: &str,
    port: u16,
    key: &Ed25519KeyMaterial,
    peer_node: &str,
    peer_realm: &str,
    peer_port: u16,
    peer_key: &Ed25519KeyMaterial,
    dials: bool,
    artifact_author: &str,
) -> Result<MeshKernel, String> {
    let kernel = kernel(key, artifact_author);
    kernel.set_node_identity(key.public_hex().to_string());
    let peer_probe = if dials {
        let (_probe, bus, rx) = kernel.open_endpoint(Capabilities::default());
        kernel.router().subscribe(Topic::new(Topic::PROPRIOCEPTION), bus.id());
        Some((bus, rx))
    } else {
        None
    };
    let transport = TransportTcp::new(TransportConfig {
        self_key: key.clone(),
        self_node: NodeId(node.into()),
        listen_addr: format!("127.0.0.1:{port}"),
        peers: vec![PeerConfig {
            node_id: NodeId(peer_node.into()),
            pubkey_hex: peer_key.public_hex().to_string(),
            dial_addr: dials.then(|| format!("127.0.0.1:{peer_port}")),
        }],
    });
    let transport_id = kernel
        .load_transport_instance(signed_manifest("transport-tcp", key), Box::new(transport))
        .map_err(|e| e.to_string())?;
    kernel.bind_role(Role::new(Role::TRANSPORT), transport_id);
    let registry_id = kernel
        .load_instance(signed_manifest("registry-mem", key), Box::new(RegistryMem::new()))
        .map_err(|e| e.to_string())?;
    kernel.bind_role(Role::new(Role::REGISTRY), registry_id);
    let mut realm_to_peer = HashMap::new();
    realm_to_peer.insert(RealmId::new(peer_realm), NodeId(peer_node.into()));
    let federator = OmegaFederator::new(FederatorConfig {
        self_node: NodeId(node.into()),
        self_realm: RealmId::new(realm),
        local_registry: registry_id,
        abode_key: key.clone(),
        realm_to_peer,
        weigher: Box::new(RoundRobinReputation::new()),
    });
    let federator_id = kernel
        .load_instance(signed_manifest("omega-federator", key), Box::new(federator))
        .map_err(|e| e.to_string())?;
    kernel.bind_role(Role::new(Role::OMEGA_GATEWAY), federator_id);
    Ok((kernel, peer_probe))
}

fn role(name: &str) -> Address {
    Address::Role(Role::new(name))
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
    budget: Duration,
) -> Result<Envelope, String> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == schema => {
                return Ok(env);
            }
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(format!(
                    "response inbox disconnected while waiting for {schema} correlation {corr}"
                ));
            }
        }
    }
    Err(format!("no {schema} response for correlation {corr}"))
}

fn rpc<T: Serialize>(
    bus: &aether::BusHandle,
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
    .map_err(|e| e.to_string())?;
    recv_corr(rx, corr, schema, Duration::from_secs(8))
}

fn catalog(capabilities: &[PublishedCapability]) -> StaticCatalog {
    StaticCatalog(
        capabilities
            .iter()
            .map(|capability| CatalogEntry {
                artifact_hash: capability.artifact_hash.clone(),
                realm: RealmId::new(REALM_B),
                manifest: capability.manifest.clone(),
                reputation: None,
                quarantine: None,
            })
            .collect(),
    )
}

fn function_id(
    capability: &PublishedCapability,
    spec: &FinalCapabilitySpecV1,
) -> Result<FunctionId, String> {
    let manifest_content_address = capability
        .manifest
        .content_address
        .clone()
        .ok_or_else(|| "published manifest has no content address".to_string())?;
    Ok(FunctionId { manifest_content_address, entrypoint: spec.entrypoint.clone() })
}

fn alias(capability: &PublishedCapability, spec: &FinalCapabilitySpecV1) -> FunctionAlias {
    FunctionAlias {
        realm: REALM_B.into(),
        name: capability.manifest.name.clone(),
        version: capability.manifest.version.clone(),
        entrypoint: spec.entrypoint.clone(),
    }
}

fn expected_contract(spec: &FinalCapabilitySpecV1) -> Result<EntrypointContractV1, String> {
    let endpoint_a = evaluate_affine(spec.input_min, spec.multiplier, spec.addend)
        .map_err(|error| error.to_string())?;
    let endpoint_b = evaluate_affine(spec.input_max, spec.multiplier, spec.addend)
        .map_err(|error| error.to_string())?;
    let output_min = endpoint_a.min(endpoint_b);
    let output_max = endpoint_a.max(endpoint_b);
    Ok(EntrypointContractV1 {
        description: spec.description.clone(),
        input_schema: SchemaRefV1::Inline {
            schema: json!({
                "type": "object",
                "properties": {
                    "value": {
                        "type": "integer",
                        "minimum": spec.input_min,
                        "maximum": spec.input_max
                    }
                },
                "required": ["value"],
                "additionalProperties": false
            }),
        },
        output_schema: SchemaRefV1::Inline {
            schema: json!({
                "type": "object",
                "properties": {
                    "result": {
                        "type": "integer",
                        "minimum": output_min,
                        "maximum": output_max
                    }
                },
                "required": ["result"],
                "additionalProperties": false
            }),
        },
        error_schema: None,
        effect: EffectClassV1::Idempotent,
        controls: FunctionControlsV1::default(),
    })
}

fn approval_evidence(capability: &PublishedCapability) -> Vec<EvidenceRefV1> {
    vec![EvidenceRefV1 {
        kind: "dialogue_approval".into(),
        digest: capability.approval_digest.clone(),
        issuer: None,
        locator: None,
    }]
}

fn load_executor(
    kernel: &Arc<Kernel>,
    node_key: &Ed25519KeyMaterial,
    authorities: &Authorities,
    root: PathBuf,
    remote: bool,
    capture: Arc<Mutex<ExecutionCapture>>,
) -> Result<CreatureId, String> {
    let inner = FunctionExecutor::open_with_liveness(
        ExecutorConfig::new(root, authorities.executor.public_key()).with_location(
            REALM_B,
            NODE_B,
            "v0.5-acceptance",
        ),
        authorities.executor.clone(),
        Arc::new(StringAddressing),
        Arc::new(OwnerAdmission(authorities.home.to_string())),
        Arc::new(KernelLiveness(Arc::downgrade(kernel))),
    )
    .map_err(|e| e.to_string())?;
    let id = kernel
        .load_instance(
            signed_manifest("function-executor", node_key),
            Box::new(CapturingExecutor { inner, capture }),
        )
        .map_err(|e| e.to_string())?;
    if remote {
        kernel.bind_remote_role(Role::new(FUNCTION_EXECUTOR_ROLE), id);
    } else {
        kernel.bind_role(Role::new(FUNCTION_EXECUTOR_ROLE), id);
    }
    Ok(id)
}

fn load_home(
    kernel: &Kernel,
    node_key: &Ed25519KeyMaterial,
    authorities: &Authorities,
    root: PathBuf,
    realm: &str,
    node: &str,
) -> Result<CreatureId, String> {
    let home = FunctionHome::open(
        HomeConfig::for_creature(root, authorities.home.clone(), authorities.authority.clone())
            .with_location(realm, node),
        authorities.operational.clone(),
        Arc::new(IdempotentMetadata),
        authorities.trust(),
        Arc::new(InlineOnly),
    )
    .map_err(|e| e.to_string())?;
    let id = kernel
        .load_instance(signed_manifest("function-home", node_key), Box::new(home))
        .map_err(|e| e.to_string())?;
    kernel.bind_role(Role::new(FUNCTION_HOME_ROLE), id);
    Ok(id)
}

fn load_resolver_and_policy(
    kernel: &Kernel,
    node_key: &Ed25519KeyMaterial,
    authorities: &Authorities,
    capabilities: &[PublishedCapability],
) -> Result<(), String> {
    let resolver = kernel
        .load_instance(
            signed_manifest("function-resolver", node_key),
            Box::new(FunctionResolver::new(
                authorities.resolver.clone(),
                Arc::new(catalog(capabilities)),
            )),
        )
        .map_err(|e| e.to_string())?;
    kernel.bind_role(Role::new(FUNCTION_RESOLVER_ROLE), resolver);
    let policy = kernel
        .load_instance(
            signed_manifest("policy-job-basic", node_key),
            Box::new(
                BasicJobPolicy::new(authorities.policy.clone(), BasicPolicyCaps::default())
                    .map_err(|e| e.to_string())?,
            ),
        )
        .map_err(|e| e.to_string())?;
    kernel.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy);
    Ok(())
}

fn resolve(
    authorities: &Authorities,
    capability: &PublishedCapability,
    spec: &FinalCapabilitySpecV1,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    corr: u64,
) -> Result<SignedRecordV1<ResolutionReceiptV1>, String> {
    let request = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        ResolveRequestV1 {
            requested_by: authorities.home.clone(),
            selector: FunctionSelectorV1::Alias { alias: alias(capability, spec) },
            evidence: approval_evidence(capability),
        },
        authorities.root.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    let env = rpc(
        bus,
        rx,
        corr,
        role(FUNCTION_RESOLVER_ROLE),
        SCHEMA_FUNCTION_DEPLOY_V1,
        &FunctionDeployMessageV1::Resolve { request },
    )?;
    match serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
        .map_err(|e| e.to_string())?
    {
        FunctionDeployMessageV1::Resolved { receipt } => {
            if !receipt.verify() || receipt.signer != authorities.resolver.public_key() {
                return Err("resolver returned an invalid or unpinned receipt".into());
            }
            let expected_selector = FunctionSelectorV1::Alias { alias: alias(capability, spec) };
            if receipt.payload.selector != expected_selector
                || receipt.payload.function != function_id(capability, spec)?
                || receipt.payload.artifact_hash
                    != normalize_sha256(&capability.artifact_hash)
                        .ok_or_else(|| "published artifact hash is malformed".to_string())?
                || receipt.payload.evidence != approval_evidence(capability)
            {
                return Err("resolver changed the approved selector or published identity".into());
            }
            Ok(receipt)
        }
        other => Err(format!("resolver returned {other:?}")),
    }
}

#[allow(clippy::too_many_arguments)]
fn register(
    authorities: &Authorities,
    capability: &PublishedCapability,
    spec: &FinalCapabilitySpecV1,
    resolution: &SignedRecordV1<ResolutionReceiptV1>,
    target_id: CreatureId,
    executor_id: CreatureId,
    executor_route: Address,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    corr: u64,
) -> Result<SignedRecordV1<DeploymentReceiptV1>, String> {
    let selector = FunctionSelectorV1::Alias { alias: alias(capability, spec) };
    let authorization = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRequestV1 {
            requested_by: authorities.home.clone(),
            function: selector,
            target_realm: REALM_B.into(),
            target_node: Some(NODE_B.into()),
            evidence: approval_evidence(capability),
            requested_at_unix_ms: None,
        },
        authorities.root.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    let function = function_id(capability, spec)?;
    let expected_deployment = derive_deployment_id(
        &function,
        &resolution.payload.artifact_hash,
        REALM_B,
        NODE_B,
        &target_id.0.to_string(),
    )
    .map_err(|e| e.to_string())?;
    let registration = SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentRegistrationV1 {
            authorization,
            resolution: resolution.clone(),
            deployment: expected_deployment.clone(),
            function,
            artifact_hash: resolution.payload.artifact_hash.clone(),
            target_creature: target_id.0.to_string(),
            evidence: approval_evidence(capability),
        },
        authorities.root.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    let env = rpc(
        bus,
        rx,
        corr,
        executor_route,
        SCHEMA_FUNCTION_DEPLOY_V1,
        &FunctionDeployMessageV1::Register { request: Box::new(registration) },
    )?;
    match serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
        .map_err(|e| e.to_string())?
    {
        FunctionDeployMessageV1::Registered { receipt } => {
            verify_deployment_receipt(&receipt).map_err(|e| e.to_string())?;
            if receipt.signer != authorities.executor.public_key()
                || receipt.payload.deployment != expected_deployment
                || receipt.payload.function != function_id(capability, spec)?
                || receipt.payload.artifact_hash != resolution.payload.artifact_hash
                || receipt.payload.realm != REALM_B
                || receipt.payload.node != NODE_B
                || receipt.payload.executor != authorities.executor.public_key()
                || receipt.payload.executor_creature != executor_id.0.to_string()
                || receipt.payload.creature != target_id.0.to_string()
                || receipt.payload.evidence != approval_evidence(capability)
            {
                return Err("deployment receipt changed the exact published target".into());
            }
            Ok(receipt)
        }
        other => Err(format!("executor registration returned {other:?}")),
    }
}

struct JobProofContext<'a> {
    authorities: &'a Authorities,
    capability: &'a PublishedCapability,
    spec: &'a FinalCapabilitySpecV1,
    bus: &'a aether::BusHandle,
    rx: &'a InboxReceiver,
    capture: &'a Arc<Mutex<ExecutionCapture>>,
}

fn submit_and_verify(
    context: JobProofContext<'_>,
    resolution: SignedRecordV1<ResolutionReceiptV1>,
    deployment: SignedRecordV1<DeploymentReceiptV1>,
    input: i32,
    expected: i32,
    idempotency_key: &str,
    corr_base: u64,
) -> Result<VerifiedJob, String> {
    let JobProofContext { authorities, capability, spec, bus, rx, capture } = context;
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSubmitV1 {
            home: authorities.home.clone(),
            caller_idempotency_key: idempotency_key.into(),
            function: FunctionSelectorV1::Alias { alias: alias(capability, spec) },
            input: ValueRefV1::Inline { value: json!({"value": input}) },
            delivery: DeliveryModeV1::AtMostOnce,
            allow_duplicate_effects: false,
            parent: None,
            causal: vec![],
            access: JobAccessV1::default(),
            evidence: approval_evidence(capability),
            result_recipients: vec![],
            submitted_at_unix_ms: None,
        },
        authorities.root.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    let expected_request_hash = request.payload.request_hash().map_err(|e| e.to_string())?;
    let expected_handle = JobHandleV1 {
        home: authorities.home.clone(),
        job: derive_job_id(&authorities.home, idempotency_key).map_err(|e| e.to_string())?,
    };
    let expected_deployment = deployment.clone();
    let message = JobMessageV1::Submit {
        request: Box::new(request.clone()),
        resolution: Box::new(resolution),
        deployment: Box::new(deployment.clone()),
    };
    let first = rpc(bus, rx, corr_base, role(FUNCTION_HOME_ROLE), SCHEMA_JOB_V1, &message)?;
    let (handle, request_hash, submitted) =
        match serde_json::from_slice::<JobMessageV1>(&first.payload).map_err(|e| e.to_string())? {
            JobMessageV1::Accepted { handle, request_hash, submitted } => {
                (handle, request_hash, submitted)
            }
            other => return Err(format!("Home returned {other:?} instead of Accepted")),
        };
    verify_job_acceptance(&handle, &request_hash, &submitted).map_err(|e| e.to_string())?;
    let submitted_spec = match &submitted.payload.kind {
        gawdfn::JobEventKindV1::Submitted { spec } => spec,
        _ => return Err("Home acceptance proof is not a Submitted event".into()),
    };
    if handle != expected_handle
        || request_hash != expected_request_hash
        || submitted.signer != authorities.operational.public_key()
        || submitted.payload.handle != expected_handle
        || submitted_spec.request_hash != expected_request_hash
        || submitted_spec.evidence != approval_evidence(capability)
    {
        return Err("Home acceptance did not bind the exact signed submission".into());
    }

    // Redeliver the exact signed request. At-most-once means the same durable acceptance and one
    // effect-boundary crossing, not a promise that the network sends only once.
    let duplicate = rpc(
        bus,
        rx,
        corr_base.saturating_add(1),
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &message,
    )?;
    match serde_json::from_slice::<JobMessageV1>(&duplicate.payload).map_err(|e| e.to_string())? {
        JobMessageV1::Accepted {
            handle: duplicate_handle,
            request_hash: duplicate_hash,
            submitted: duplicate_submitted,
        } if duplicate_handle == handle
            && duplicate_hash == request_hash
            && duplicate_submitted == submitted => {}
        other => return Err(format!("duplicate Submit was not byte-stably accepted: {other:?}")),
    }

    let snapshot = wait_for_success(authorities, bus, rx, &handle, corr_base.saturating_add(100))?;
    verify_job_snapshot(&snapshot).map_err(|e| e.to_string())?;
    let observed_result = match snapshot.payload.result.as_ref() {
        Some(ValueRefV1::Inline { value }) => value
            .as_object()
            .filter(|object| object.len() == 1)
            .and_then(|object| object.get("result"))
            .and_then(serde_json::Value::as_i64)
            .and_then(|value| i32::try_from(value).ok())
            .ok_or_else(|| "terminal result is not the exact {result: i32} shape".to_string())?,
        _ => return Err("terminal result is not an inline value".into()),
    };
    if snapshot.signer != authorities.operational.public_key() || observed_result != expected {
        return Err(format!("unexpected terminal snapshot: {snapshot:?}"));
    }

    let events = read_events(authorities, bus, rx, &handle, corr_base.saturating_add(500))?;
    let dispatches = events
        .iter()
        .filter(|event| {
            matches!(event.payload.kind, gawdfn::JobEventKindV1::DispatchGranted { .. })
        })
        .count();
    let successes = events
        .iter()
        .filter(|event| matches!(event.payload.kind, gawdfn::JobEventKindV1::Succeeded { .. }))
        .count();
    if dispatches != 1 || successes != 1 {
        return Err(format!(
            "expected one successful attempt, observed {dispatches} grants and {successes} successes"
        ));
    }
    let terminal = events
        .iter()
        .find(|event| matches!(event.payload.kind, gawdfn::JobEventKindV1::Succeeded { .. }))
        .ok_or_else(|| "Home returned no successful terminal Job event".to_string())?;
    let receipt = terminal
        .payload
        .foreign_receipt
        .as_deref()
        .ok_or_else(|| "terminal event carries no executor receipt".to_string())?;
    if receipt.signer != authorities.executor.public_key() {
        return Err("terminal receipt is not from the pinned executor".into());
    }
    let captured = capture.lock().unwrap_or_else(|poison| poison.into_inner());
    let matching_grants = captured
        .grants
        .iter()
        .filter(|grant| grant.payload.attempt == receipt.payload.attempt)
        .collect::<Vec<_>>();
    let matching_calls = captured
        .calls
        .iter()
        .filter(|call| call.attempt == receipt.payload.attempt)
        .collect::<Vec<_>>();
    if matching_grants.len() != 1 || matching_calls.len() != 1 {
        return Err(format!(
            "terminal attempt requires one captured grant and Function call; observed {} grants and {} calls",
            matching_grants.len(),
            matching_calls.len()
        ));
    }
    let grant = (*matching_grants[0]).clone();
    let function_call = (*matching_calls[0]).clone();
    drop(captured);
    verify_execution_grant(&grant).map_err(|e| e.to_string())?;
    let grant_hash = canonical_hash(&grant).map_err(|e| e.to_string())?;
    let dispatch = events
        .iter()
        .find(|event| {
            matches!(
                &event.payload.kind,
                gawdfn::JobEventKindV1::DispatchGranted {
                    grant_hash: event_grant_hash,
                    attempt,
                } if event_grant_hash == &grant_hash && attempt == &grant.payload.attempt
            )
        })
        .ok_or_else(|| "signed grant has no exact DispatchGranted event".to_string())?;
    if grant.payload.request_hash != request_hash
        || grant.payload.attempt.home != handle.home
        || grant.payload.attempt.job != handle.job
        || grant.payload.function != function_id(capability, spec)?
        || grant.payload.deployment != expected_deployment
        || dispatch.payload.handle != handle
    {
        return Err("execution grant is not bound to the accepted Job and deployment".into());
    }
    verify_execution_receipt(receipt, &grant).map_err(|e| e.to_string())?;
    verify_job_event_with_grant(terminal, &grant).map_err(|e| e.to_string())?;
    let dispatch_authorization = dispatch.clone();
    let terminal_home_event = terminal.clone();
    let terminal_receipt = receipt.clone();
    let proof = RetainedJobProofV1 {
        schema: EXECUTION_PROOF_BUNDLE_SCHEMA_V1.into(),
        submission: request,
        acceptance: *submitted,
        deployment,
        dispatch_authorization,
        grant,
        function_call,
        terminal_home_event,
        terminal_receipt: terminal_receipt.clone(),
        terminal_snapshot: snapshot,
        complete_home_events: events,
    };
    proof.validate()?;
    Ok(VerifiedJob { handle, receipt: terminal_receipt, input, result: observed_result, proof })
}

fn read_snapshot(
    authorities: &Authorities,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    handle: &JobHandleV1,
    corr: u64,
) -> Result<SignedRecordV1<JobSnapshotV1>, String> {
    let caller = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetV1 { handle: handle.clone(), nonce: format!("v05-read-{corr}") },
        authorities.root.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetRelayV1 {
            caller,
            reply_to: serde_json::to_string(&Address::Creature(bus.id()))
                .map_err(|e| e.to_string())?,
        },
        authorities.root.as_ref(),
    )
    .map_err(|e| e.to_string())?;
    let env = rpc(
        bus,
        rx,
        corr,
        role(FUNCTION_HOME_ROLE),
        SCHEMA_JOB_V1,
        &JobMessageV1::Get { request: Box::new(request.clone()) },
    )?;
    match serde_json::from_slice::<JobMessageV1>(&env.payload).map_err(|e| e.to_string())? {
        JobMessageV1::Snapshot { response } => {
            verify_job_snapshot_response_for(&response, &request).map_err(|e| e.to_string())?;
            Ok(*response.payload.snapshot)
        }
        other => Err(format!("Home returned {other:?} instead of Snapshot")),
    }
}

fn wait_for_success(
    authorities: &Authorities,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    handle: &JobHandleV1,
    mut corr: u64,
) -> Result<SignedRecordV1<JobSnapshotV1>, String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        let snapshot = read_snapshot(authorities, bus, rx, handle, corr)?;
        corr = corr.saturating_add(1);
        if snapshot.payload.state == JobStateV1::Succeeded {
            return Ok(snapshot);
        }
        if snapshot.payload.state.is_terminal() {
            return Err(format!("Job terminated as {:?}", snapshot.payload.state));
        }
        if Instant::now() >= deadline {
            return Err("Job did not reach Succeeded before the bounded deadline".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn read_events(
    authorities: &Authorities,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    handle: &JobHandleV1,
    corr: u64,
) -> Result<Vec<SignedRecordV1<gawdfn::JobEventV1>>, String> {
    let mut after_sequence = None;
    let mut events = Vec::new();
    let mut page_index = 0_u64;
    loop {
        if page_index >= 64 {
            return Err("Job event pagination exceeded the bounded 64-page proof window".into());
        }
        let page_corr = corr.saturating_add(page_index);
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryV1 {
                handle: handle.clone(),
                after_sequence,
                limit: 64,
                nonce: format!("v05-events-{page_corr}"),
            },
            authorities.root.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryRelayV1 {
                caller,
                reply_to: serde_json::to_string(&Address::Creature(bus.id()))
                    .map_err(|e| e.to_string())?,
            },
            authorities.root.as_ref(),
        )
        .map_err(|e| e.to_string())?;
        let env = rpc(
            bus,
            rx,
            page_corr,
            role(FUNCTION_HOME_ROLE),
            SCHEMA_JOB_V1,
            &JobMessageV1::Events { request: Box::new(request.clone()) },
        )?;
        let page = match serde_json::from_slice::<JobMessageV1>(&env.payload)
            .map_err(|e| e.to_string())?
        {
            JobMessageV1::EventPage { response } => {
                verify_event_page_response_for(&response, &request).map_err(|e| e.to_string())?;
                response.payload.page
            }
            other => return Err(format!("Home returned {other:?} instead of EventPage")),
        };
        for event in &page.events {
            verify_job_event(event).map_err(|e| e.to_string())?;
        }
        let next = page.next_after_sequence;
        events.extend(page.events);
        match next {
            Some(sequence) if after_sequence.is_none_or(|previous| sequence > previous) => {
                after_sequence = Some(sequence);
                page_index = page_index.saturating_add(1);
            }
            Some(_) => return Err("Job event pagination did not advance".into()),
            None => return Ok(events),
        }
    }
}

fn await_remote_executor(
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    function: &FunctionId,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut corr = 10_000;
    while Instant::now() < deadline {
        let message = FunctionDeployMessageV1::Lookup {
            query: gawdfn::DeploymentQueryV1 {
                function: Some(function.clone()),
                realm: Some(REALM_B.into()),
                node: Some(NODE_B.into()),
                limit: 8,
            },
        };
        let _ = bus.send(
            Dispatch::to(remote_executor(), aether::wire::to_bytes(&message))
                .with_schema(SCHEMA_FUNCTION_DEPLOY_V1)
                .with_reply_to(Address::Creature(bus.id()))
                .with_corr(corr),
        );
        if let Ok(env) = recv_corr(rx, corr, SCHEMA_FUNCTION_DEPLOY_V1, Duration::from_millis(350))
        {
            if matches!(
                serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload),
                Ok(FunctionDeployMessageV1::Deployments { .. })
            ) {
                return Ok(());
            }
        }
        corr = corr.saturating_add(1);
        std::thread::sleep(Duration::from_millis(20));
    }
    Err("authenticated Omega/NodeRole route to the executor did not become ready".into())
}

fn assert_one_target_call(
    kernel: &Kernel,
    executor: CreatureId,
    target: CreatureId,
) -> Result<(), String> {
    let calls = kernel
        .router()
        .journal_snapshot()
        .iter()
        .filter(|entry| entry.to == Address::Creature(target))
        .map(|entry| entry.from.clone())
        .collect::<Vec<_>>();
    if calls.len() != 1 || calls[0] != Address::Creature(executor) {
        return Err(format!(
            "expected exactly one executor-to-target Function delivery and no shortcut, observed {calls:?}"
        ));
    }
    Ok(())
}

fn free_ports() -> Result<(u16, u16), String> {
    let a = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let b = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let pa = a.local_addr().map_err(|e| e.to_string())?.port();
    let pb = b.local_addr().map_err(|e| e.to_string())?.port();
    drop((a, b));
    Ok((pa, pb))
}

fn wait_for_peer(rx: &InboxReceiver, peer: &str) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.schema == "peer_event" => {
                if let Ok(event) = serde_json::from_slice::<PeerEvent>(&env.payload) {
                    if event.peer == peer && event.event == "peer_connected" {
                        return Ok(());
                    }
                }
            }
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err("peer-event inbox disconnected before Function mesh readiness".into())
            }
        }
    }
    Err(format!("authenticated Function transport to {peer} did not become ready"))
}

fn open_remote_mesh(
    key_a: &Ed25519KeyMaterial,
    key_b: &Ed25519KeyMaterial,
    artifact_author: &str,
) -> Result<ReadyMesh, String> {
    let mut last_error = None;
    for _ in 0..MESH_BIND_ATTEMPTS {
        let (port_a, port_b) = match free_ports() {
            Ok(ports) => ports,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        // B listens first; A then dials. Both are attesting transports and both have an Omega
        // gateway. If another process wins either ephemeral port, tear down the partial topology
        // and try a fresh pair before any durable Job state is created.
        let b = match mesh_kernel(
            NODE_B,
            REALM_B,
            port_b,
            key_b,
            NODE_A,
            REALM_A,
            port_a,
            key_a,
            false,
            artifact_author,
        ) {
            Ok((kernel, _)) => kernel,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let (a, peer_probe) = match mesh_kernel(
            NODE_A,
            REALM_A,
            port_a,
            key_a,
            NODE_B,
            REALM_B,
            port_b,
            key_b,
            true,
            artifact_author,
        ) {
            Ok(pair) => pair,
            Err(error) => {
                b.shutdown_all(Deadline::from_millis(1500));
                drop(b);
                last_error = Some(error);
                continue;
            }
        };
        let Some((bus, rx)) = peer_probe else {
            a.shutdown_all(Deadline::from_millis(1500));
            drop(a);
            b.shutdown_all(Deadline::from_millis(1500));
            drop(b);
            last_error = Some("dialing Function mesh omitted its readiness probe".into());
            continue;
        };
        match wait_for_peer(&rx, NODE_B) {
            Ok(()) => return Ok((a, b, bus, rx)),
            Err(error) => {
                a.shutdown_all(Deadline::from_millis(1500));
                drop(a);
                b.shutdown_all(Deadline::from_millis(1500));
                drop(b);
                last_error = Some(error);
            }
        }
    }
    Err(format!(
        "could not claim a fresh Function mesh port pair after {MESH_BIND_ATTEMPTS} attempts: {}",
        last_error.unwrap_or_else(|| "no bind attempt completed".into())
    ))
}

/// Execute both required worlds sequentially, with isolated durable state and fresh Kernels.
pub(crate) fn prove_all_tiers(
    root: &Path,
    capabilities: &[PublishedCapability],
    artifact_author: &str,
    spec: &FinalCapabilitySpecV1,
) -> Result<Vec<TierJobProof>, String> {
    spec.validate().map_err(|error| error.to_string())?;
    validate_suite(capabilities, spec)?;
    let local = prove_local(root.join("function-local"), capabilities, artifact_author, spec)?;
    let remote = prove_remote(root.join("function-remote"), capabilities, artifact_author, spec)?;
    if local.len() != remote.len() || local.len() != capabilities.len() {
        return Err("the local and remote worlds did not prove every approved tier".into());
    }
    local
        .into_iter()
        .zip(remote)
        .map(|((local_function, local), (remote_function, remote))| {
            if local_function != remote_function {
                return Err("a tier changed FunctionId between isolated worlds".into());
            }
            if local.input != spec.local_input || remote.input != spec.remote_input {
                return Err("a Job changed the Contract Tester's approved input".into());
            }
            local.proof.validate_topology(REALM_B, NODE_B, REALM_B, NODE_B)?;
            remote.proof.validate_topology(REALM_A, NODE_A, REALM_B, NODE_B)?;
            if local.proof.grant.payload.function != local_function
                || remote.proof.grant.payload.function != remote_function
                || local.proof.input_i32()? != local.input
                || remote.proof.input_i32()? != remote.input
                || local.proof.result_i32()? != local.result
                || remote.proof.result_i32()? != remote.result
                || local.proof.attempt_count() != 1
                || remote.proof.attempt_count() != 1
            {
                return Err(
                    "retained proof summary changed FunctionId, scalar result, or attempt count"
                        .into(),
                );
            }
            Ok(TierJobProof {
                function: local_function,
                local: local.handle,
                local_receipt: local.receipt,
                local_input: local.input,
                local_result: local.result,
                local_proof: local.proof,
                remote: remote.handle,
                remote_receipt: remote.receipt,
                remote_input: remote.input,
                remote_result: remote.result,
                remote_proof: remote.proof,
            })
        })
        .collect()
}

fn validate_suite(
    capabilities: &[PublishedCapability],
    spec: &FinalCapabilitySpecV1,
) -> Result<(), String> {
    if capabilities.len() != 3 {
        return Err(format!(
            "the v0.5 suite requires daemon, beast, and critter; received {} artifacts",
            capabilities.len()
        ));
    }
    let mut backends = BTreeSet::new();
    let mut functions = BTreeSet::new();
    let mut names = BTreeSet::new();
    let exact_contract = expected_contract(spec)?;
    let approval = capabilities[0].approval_digest.as_str();
    for capability in capabilities {
        capability.manifest.validate().map_err(|e| e.to_string())?;
        backends.insert(format!("{:?}", capability.manifest.abi.backend));
        names.insert(capability.manifest.name.clone());
        functions.insert(function_id(capability, spec)?);
        if capability.approval_digest != approval {
            return Err("the three artifacts do not continue one dialogue approval".into());
        }
        if capability.manifest.entrypoints.len() != 1 {
            return Err(format!(
                "{} does not expose exactly one approved entrypoint",
                capability.manifest.name
            ));
        }
        let entrypoint = &capability.manifest.entrypoints[0];
        if entrypoint.name != spec.entrypoint {
            return Err(format!(
                "{} changed approved entrypoint {}",
                capability.manifest.name, spec.entrypoint
            ));
        }
        if entrypoint.signature != gawdfn::SCHEMA_CALL_V1 {
            return Err(format!("{} changed the Function wire schema", capability.manifest.name));
        }
        if entrypoint.contract.as_ref() != Some(&exact_contract) {
            return Err(format!(
                "{} does not expose the exact approved description, shape, and bounds",
                capability.manifest.name
            ));
        }
    }
    let expected_backends = BTreeSet::from([
        format!("{:?}", Backend::Daemon),
        format!("{:?}", Backend::Beast),
        format!("{:?}", Backend::Critter),
    ]);
    if backends != expected_backends || names.len() != 3 || functions.len() != 3 {
        return Err(
            "suite tiers, aliases, and immutable FunctionIds must be pairwise distinct".into()
        );
    }
    Ok(())
}

fn prove_local(
    root: PathBuf,
    capabilities: &[PublishedCapability],
    artifact_author: &str,
    spec: &FinalCapabilitySpecV1,
) -> Result<Vec<(FunctionId, VerifiedJob)>, String> {
    let authorities = Authorities::generate()?;
    let node_key = fresh_node_key("local Function node")?;
    let node = kernel(&node_key, artifact_author);
    let result = (|| {
        let targets = capabilities
            .iter()
            .map(|capability| {
                node.load(capability.manifest.clone(), Artifact::Bytes(capability.artifact.clone()))
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let capture = Arc::new(Mutex::new(ExecutionCapture::default()));
        let executor = load_executor(
            &node,
            &node_key,
            &authorities,
            root.join("executor"),
            false,
            capture.clone(),
        )?;
        load_home(&node, &node_key, &authorities, root.join("home"), REALM_B, NODE_B)?;
        load_resolver_and_policy(&node, &node_key, &authorities, capabilities)?;
        let (_probe, bus, rx) = node.open_endpoint(Capabilities::default());
        let mut proofs = Vec::with_capacity(capabilities.len());
        for (index, (capability, target)) in capabilities.iter().zip(targets).enumerate() {
            let corr = 1_000 + (index as u64) * 10;
            let resolution = resolve(&authorities, capability, spec, &bus, &rx, corr)?;
            let deployment = register(
                &authorities,
                capability,
                spec,
                &resolution,
                target,
                executor,
                role(FUNCTION_EXECUTOR_ROLE),
                &bus,
                &rx,
                corr + 1,
            )?;
            let handle = submit_and_verify(
                JobProofContext {
                    authorities: &authorities,
                    capability,
                    spec,
                    bus: &bus,
                    rx: &rx,
                    capture: &capture,
                },
                resolution,
                deployment,
                spec.local_input,
                evaluate_affine(spec.local_input, spec.multiplier, spec.addend)
                    .map_err(|error| error.to_string())?,
                &format!("v05-local-{}", capability.manifest.name),
                10_000 + (index as u64) * 1_000,
            )?;
            assert_one_target_call(&node, executor, target)?;
            proofs.push((function_id(capability, spec)?, handle));
        }
        Ok(proofs)
    })();
    node.shutdown_all(Deadline::from_millis(1500));
    drop(node);
    result
}

fn prove_remote(
    root: PathBuf,
    capabilities: &[PublishedCapability],
    artifact_author: &str,
    spec: &FinalCapabilitySpecV1,
) -> Result<Vec<(FunctionId, VerifiedJob)>, String> {
    let authorities = Authorities::generate()?;
    let key_a = fresh_node_key("reviewer-home Function node")?;
    let key_b = fresh_node_key("builder-executor Function node")?;
    let (a, b, bus, rx) = open_remote_mesh(&key_a, &key_b, artifact_author)?;
    let result = (|| {
        let targets = capabilities
            .iter()
            .map(|capability| {
                b.load(capability.manifest.clone(), Artifact::Bytes(capability.artifact.clone()))
                    .map_err(|e| e.to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        let capture = Arc::new(Mutex::new(ExecutionCapture::default()));
        let executor =
            load_executor(&b, &key_b, &authorities, root.join("executor"), true, capture.clone())?;
        load_home(&a, &key_a, &authorities, root.join("home"), REALM_A, NODE_A)?;
        load_resolver_and_policy(&a, &key_a, &authorities, capabilities)?;
        await_remote_executor(&bus, &rx, &function_id(&capabilities[0], spec)?)?;
        let mut proofs = Vec::with_capacity(capabilities.len());
        for (index, (capability, target)) in capabilities.iter().zip(targets).enumerate() {
            let corr = 2_000 + (index as u64) * 10;
            let resolution = resolve(&authorities, capability, spec, &bus, &rx, corr)?;
            let deployment = register(
                &authorities,
                capability,
                spec,
                &resolution,
                target,
                executor,
                remote_executor(),
                &bus,
                &rx,
                corr + 1,
            )?;
            let handle = submit_and_verify(
                JobProofContext {
                    authorities: &authorities,
                    capability,
                    spec,
                    bus: &bus,
                    rx: &rx,
                    capture: &capture,
                },
                resolution,
                deployment,
                spec.remote_input,
                evaluate_affine(spec.remote_input, spec.multiplier, spec.addend)
                    .map_err(|error| error.to_string())?,
                &format!("v05-cross-realm-{}", capability.manifest.name),
                20_000 + (index as u64) * 1_000,
            )?;
            assert_one_target_call(&b, executor, target)?;
            proofs.push((function_id(capability, spec)?, handle));
        }
        Ok(proofs)
    })();
    a.shutdown_all(Deadline::from_millis(1500));
    drop(a);
    b.shutdown_all(Deadline::from_millis(1500));
    drop(b);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dynamic_spec() -> FinalCapabilitySpecV1 {
        let mut spec = FinalCapabilitySpecV1 {
            schema: crate::decisions::FINAL_CAPABILITY_SCHEMA_V1.into(),
            name: "Triple minus five".into(),
            slug: "triple-minus-five".into(),
            entrypoint: "triple_minus_five".into(),
            description: "Triples a bounded signed value and subtracts five.".into(),
            input_min: -9,
            input_max: 11,
            multiplier: 3,
            addend: -5,
            local_input: 4,
            remote_input: -4,
            semantic_digest: String::new(),
        };
        spec.semantic_digest = spec.computed_semantic_digest().expect("valid semantic digest");
        spec.validate().expect("valid dynamic spec");
        spec
    }

    #[test]
    fn exact_contract_tracks_dynamic_shape_description_and_bounds() {
        let spec = dynamic_spec();
        let contract = expected_contract(&spec).expect("contract");
        assert_eq!(contract.description, spec.description);
        assert_eq!(
            contract.input_schema,
            SchemaRefV1::Inline {
                schema: json!({
                    "type": "object",
                    "properties": {
                        "value": { "type": "integer", "minimum": -9, "maximum": 11 }
                    },
                    "required": ["value"],
                    "additionalProperties": false
                })
            }
        );
        assert_eq!(
            contract.output_schema,
            SchemaRefV1::Inline {
                schema: json!({
                    "type": "object",
                    "properties": {
                        "result": { "type": "integer", "minimum": -32, "maximum": 28 }
                    },
                    "required": ["result"],
                    "additionalProperties": false
                })
            }
        );
        assert_eq!(contract.effect, EffectClassV1::Idempotent);
        assert_eq!(contract.controls, FunctionControlsV1::default());
    }

    #[test]
    fn retained_event_window_must_be_complete_contiguous_and_terminal() {
        assert!(validate_complete_sequence_window(&[1, 2, 3, 4, 5], 5).is_ok());
        assert!(validate_complete_sequence_window(&[1, 2, 4, 5], 5).is_err());
        assert!(validate_complete_sequence_window(&[1, 2, 3, 4], 5).is_err());
        assert!(validate_complete_sequence_window(&[1, 2, 3, 4, 5], 4).is_err());
        assert!(validate_complete_sequence_window(&[], 0).is_err());
    }
}
