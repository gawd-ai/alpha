//! Durable Realm-local attempt executor for asynchronous function jobs.
//!
//! A grant is durably claimed before the function call is emitted. Re-delivery of the same grant
//! returns its existing receipt without invoking the function again. At-least-once creates a new
//! numbered attempt at the home; one `AttemptId` is never executed twice.
//! A composition-injected, model-free liveness view also proves that the process-local target id is
//! currently occupied by the deployment's exact manifest and artifact before registration,
//! active lookup, first claim, and the Started/call gate.

#![forbid(unsafe_code)]

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, NodeId, Outcome, RealmId, Role,
};
use function_home::{JournalCaps, JournalError, SignedJournal};
use gawdfn::{
    canonical_hash, derive_deployment_id, verify_execution_grant, verify_execution_query,
    AttemptId, AuthoritySigner, ControlDispositionV1, DeploymentId, DeploymentListV1,
    DeploymentQueryV1, DeploymentReceiptV1, DeploymentRegistrationV1, ExecuteMessageV1,
    ExecutionControlV1, ExecutionGrantV1, ExecutionQueryV1, ExecutionReceiptV1, ExecutionStageV1,
    ExecutorControlDispatchV1, ExecutorDispatchV1, FunctionCallMessageV1, FunctionCallV1,
    FunctionControlV1, FunctionDeployMessageV1, FunctionResultV1, ProtocolErrorV1, SignedRecordV1,
    UndeployReceiptV1, UndeployRequestV1, Validate, MAX_ATTEMPT_OBSERVATIONS,
    MAX_EXECUTOR_RECOVERY_DISPATCHES, MAX_JOB_CONTROLS, MAX_JOB_MESSAGE_BYTES, SCHEMA_CALL_V1,
    SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use thiserror::Error;

pub const DEFAULT_MAX_EXECUTOR_ATTEMPTS: usize = 16_384;
pub const DEFAULT_MAX_DEPLOYMENTS: usize = 4_096;
const EXECUTOR_CHAIN_SCHEMA: &str = "gawd.function.executor.journal.v1";
const EXECUTOR_RECOVERY_POKE_SCHEMA: &str = "gawd.function.executor.recovery-poke.v1";
const EXECUTOR_RECOVERY_POKE_PAYLOAD: &[u8] = b"continue";
const EXECUTOR_RECOVERY_INDETERMINATE_REASON: &str =
    "executor recovered a claimed attempt with unknown call outcome";
const EXECUTOR_RECOVERY_FAILURE_KIND: &str = "executor_recovery_ambiguity";

type ControlKey = (gawdfn::HomeId, gawdfn::JobId, u8, gawdfn::ControlId);
type AttemptKey = (gawdfn::HomeId, gawdfn::JobId, u8);

pub trait ExecutionAddressing: Send + Sync {
    fn function_target(&self, grant: &ExecutionGrantV1) -> Result<Address, String>;
    fn home_target(&self, grant: &ExecutionGrantV1) -> Result<Address, String>;
    fn query_home_target(
        &self,
        grant: &ExecutionGrantV1,
        query: &ExecutionQueryV1,
    ) -> Result<Address, String>;
    fn control_home_target(
        &self,
        grant: &ExecutionGrantV1,
        control: &ExecutionControlV1,
    ) -> Result<Address, String>;
}

/// Admission remains injected: valid signatures/evidence are facts, not trust decisions.
pub trait DeploymentAdmission: Send + Sync {
    fn register(&self, request: &SignedRecordV1<DeploymentRegistrationV1>) -> Result<(), String>;
    fn undeploy(
        &self,
        request: &SignedRecordV1<UndeployRequestV1>,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String>;
}

/// Mechanism-only view of whether an exact local deployment target is currently routable and still
/// has the deployment's immutable manifest content address and artifact hash.
///
/// The executor deliberately does not depend on `sanctum`: a composition root injects its local
/// roster view. Returning `false` or refusing the lookup both fail closed before a first claim or
/// call is emitted. This is a liveness fact, not placement or trust policy.
pub trait DeploymentLiveness: Send + Sync {
    fn target_is_live(
        &self,
        target: CreatureId,
        deployment: &DeploymentReceiptV1,
    ) -> Result<bool, String>;
}

/// Fail-closed default used when a composition has not supplied a local roster view.
pub struct UnavailableDeploymentLiveness;

impl DeploymentLiveness for UnavailableDeploymentLiveness {
    fn target_is_live(
        &self,
        _target: CreatureId,
        _deployment: &DeploymentReceiptV1,
    ) -> Result<bool, String> {
        Err("deployment liveness is not configured".into())
    }
}

/// Explicit parser for `creature:<u64>`, raw `<u64>`, and `role:<name>` deployment addresses.
pub struct StringAddressing;

impl ExecutionAddressing for StringAddressing {
    fn function_target(&self, grant: &ExecutionGrantV1) -> Result<Address, String> {
        parse_address(&grant.deployment.payload.creature)
    }
    fn home_target(&self, grant: &ExecutionGrantV1) -> Result<Address, String> {
        let coordinator = parse_address(&grant.home_coordinator)?;
        routed_address(
            &grant.deployment.payload.realm,
            &grant.deployment.payload.node,
            &grant.home_realm,
            &grant.home_node,
            coordinator,
        )
    }
    fn query_home_target(
        &self,
        grant: &ExecutionGrantV1,
        query: &ExecutionQueryV1,
    ) -> Result<Address, String> {
        let coordinator = parse_address(&query.home_coordinator)?;
        routed_address(
            &grant.deployment.payload.realm,
            &grant.deployment.payload.node,
            &query.home_realm,
            &query.home_node,
            coordinator,
        )
    }
    fn control_home_target(
        &self,
        grant: &ExecutionGrantV1,
        control: &ExecutionControlV1,
    ) -> Result<Address, String> {
        let coordinator = parse_address(&control.home_coordinator)?;
        routed_address(
            &grant.deployment.payload.realm,
            &grant.deployment.payload.node,
            &control.home_realm,
            &control.home_node,
            coordinator,
        )
    }
}

#[derive(Clone)]
pub struct ExecutorConfig {
    pub root: PathBuf,
    pub executor: String,
    pub max_attempts: usize,
    pub realm: String,
    pub node: String,
    pub executor_creature: String,
    pub max_deployments: usize,
    pub journal_caps: JournalCaps,
}

impl ExecutorConfig {
    pub fn new(root: impl Into<PathBuf>, executor: impl Into<String>) -> Self {
        Self {
            root: root.into(),
            executor: executor.into(),
            max_attempts: DEFAULT_MAX_EXECUTOR_ATTEMPTS,
            realm: "local".into(),
            node: "local".into(),
            executor_creature: "auto".into(),
            max_deployments: DEFAULT_MAX_DEPLOYMENTS,
            journal_caps: JournalCaps::default(),
        }
    }

    pub fn with_location(
        mut self,
        realm: impl Into<String>,
        node: impl Into<String>,
        executor_creature: impl Into<String>,
    ) -> Self {
        self.realm = realm.into();
        self.node = node.into();
        self.executor_creature = executor_creature.into();
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExecutorLedgerRecord {
    Register {
        request: Box<SignedRecordV1<DeploymentRegistrationV1>>,
        receipt: SignedRecordV1<DeploymentReceiptV1>,
    },
    Undeploy {
        request: SignedRecordV1<UndeployRequestV1>,
        deployment: DeploymentId,
    },
    Claim {
        grant: Box<SignedRecordV1<ExecutionGrantV1>>,
        receipt: SignedRecordV1<ExecutionReceiptV1>,
    },
    Refuse {
        grant: Box<SignedRecordV1<ExecutionGrantV1>>,
        receipt: SignedRecordV1<ExecutionReceiptV1>,
    },
    Control {
        request: Box<SignedRecordV1<ExecutionControlV1>>,
        receipt: SignedRecordV1<ExecutionReceiptV1>,
    },
    HomeFence {
        query: Box<SignedRecordV1<ExecutionQueryV1>>,
    },
    Receipt {
        receipt: SignedRecordV1<ExecutionReceiptV1>,
    },
}

#[derive(Debug, Clone)]
struct AttemptRecord {
    grant: SignedRecordV1<ExecutionGrantV1>,
    grant_hash: String,
    receipts: Vec<SignedRecordV1<ExecutionReceiptV1>>,
    receipt_recovery_ordinals: Vec<u64>,
    observation_count: usize,
    highest_progress_sequence: u64,
    highest_checkpoint_sequence: u64,
    progress_receipts: BTreeMap<u64, usize>,
    checkpoint_receipts: BTreeMap<u64, usize>,
    control_count: usize,
    terminal: bool,
}

#[derive(Debug, Clone)]
struct HomeFence {
    epoch: u64,
    route_sequence: u64,
    operational_signer: String,
    authority_hash: String,
    home_realm: String,
    home_node: String,
    home_coordinator: String,
}

#[derive(Debug, Clone)]
struct ControlRecord {
    request_hash: String,
    request: SignedRecordV1<ExecutionControlV1>,
    queued: SignedRecordV1<ExecutionReceiptV1>,
    acknowledged: Option<SignedRecordV1<ExecutionReceiptV1>>,
}

#[derive(Default)]
struct ExecutorState {
    attempts: BTreeMap<AttemptKey, AttemptRecord>,
    deployments: BTreeMap<DeploymentId, SignedRecordV1<DeploymentReceiptV1>>,
    deployment_tombstones: std::collections::BTreeSet<DeploymentId>,
    home_fences: BTreeMap<gawdfn::HomeId, HomeFence>,
    controls: BTreeMap<ControlKey, ControlRecord>,
    next_receipt_recovery_ordinal: u64,
    nonterminal_attempts: usize,
    unacknowledged_controls: usize,
}

#[derive(Default)]
struct ExecutorRecoverySweep {
    receipt_high_water_ordinal: u64,
    receipts_remaining: usize,
    receipt_after: Option<(AttemptKey, u64)>,
    active: bool,
}

#[derive(Clone)]
enum AttemptRecoveryWork {
    Resume(Box<AttemptResumeRecovery>),
    Receipt(Box<AttemptReceiptRecovery>),
}

#[derive(Clone)]
struct AttemptResumeRecovery {
    grant: SignedRecordV1<ExecutionGrantV1>,
    claimed: SignedRecordV1<ExecutionReceiptV1>,
}

#[derive(Clone)]
struct AttemptReceiptRecovery {
    grant: SignedRecordV1<ExecutionGrantV1>,
    receipt: SignedRecordV1<ExecutionReceiptV1>,
    control: Option<SignedRecordV1<ExecutionControlV1>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    Claimed {
        receipts: Vec<SignedRecordV1<ExecutionReceiptV1>>,
        call: FunctionCallV1,
        target: Address,
    },
    Duplicate {
        receipt: SignedRecordV1<ExecutionReceiptV1>,
    },
    Terminal {
        receipt: SignedRecordV1<ExecutionReceiptV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordOutcome {
    Recorded(SignedRecordV1<ExecutionReceiptV1>),
    Duplicate(SignedRecordV1<ExecutionReceiptV1>),
}

#[derive(Debug, Error)]
pub enum ExecutorError {
    #[error("executor configuration is invalid: {0}")]
    Configuration(String),
    #[error("invalid execution message: {0}")]
    Invalid(String),
    #[error("execution message is unauthorized: {0}")]
    Unauthorized(String),
    #[error("attempt was not found")]
    NotFound,
    #[error("attempt conflict: {0}")]
    Conflict(String),
    #[error("executor capacity reached")]
    Capacity,
    #[error("attempt is terminal")]
    Terminal,
    #[error("cannot resolve execution address: {0}")]
    Address(String),
    #[error("deployment target is not live: {0}")]
    TargetUnavailable(String),
    #[error("deployment liveness check failed: {0}")]
    Liveness(String),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("signing failed: {0}")]
    Signing(String),
}

pub struct FunctionExecutor {
    config: ExecutorConfig,
    signer: Arc<dyn AuthoritySigner>,
    addressing: Arc<dyn ExecutionAddressing>,
    admission: Arc<dyn DeploymentAdmission>,
    liveness: Arc<dyn DeploymentLiveness>,
    journal: SignedJournal<ExecutorLedgerRecord>,
    state: Mutex<ExecutorState>,
    recovery_sweep: Mutex<ExecutorRecoverySweep>,
    me: Option<CreatureId>,
}

impl FunctionExecutor {
    pub fn open(
        config: ExecutorConfig,
        signer: Arc<dyn AuthoritySigner>,
        addressing: Arc<dyn ExecutionAddressing>,
        admission: Arc<dyn DeploymentAdmission>,
    ) -> Result<Self, ExecutorError> {
        Self::open_with_liveness(
            config,
            signer,
            addressing,
            admission,
            Arc::new(UnavailableDeploymentLiveness),
        )
    }

    pub fn open_with_liveness(
        config: ExecutorConfig,
        signer: Arc<dyn AuthoritySigner>,
        addressing: Arc<dyn ExecutionAddressing>,
        admission: Arc<dyn DeploymentAdmission>,
        liveness: Arc<dyn DeploymentLiveness>,
    ) -> Result<Self, ExecutorError> {
        if config.executor.trim().is_empty()
            || config.max_attempts == 0
            || config.max_deployments == 0
            || config.realm.trim().is_empty()
            || config.node.trim().is_empty()
            || config.executor_creature.trim().is_empty()
        {
            return Err(ExecutorError::Configuration(
                "executor and max_attempts must be non-empty/non-zero".into(),
            ));
        }
        if signer.public_key() != config.executor {
            return Err(ExecutorError::Configuration(
                "executor identity must equal the injected signer public key".into(),
            ));
        }
        let journal = SignedJournal::open_with_schema(
            &config.root,
            "function-executor",
            EXECUTOR_CHAIN_SCHEMA,
            signer.clone(),
            config.journal_caps,
        )?;
        let mut state = ExecutorState::default();
        for record in journal.records() {
            apply_record(&config, signer.public_key(), &mut state, &record.payload.event)?;
        }
        validate_reservation_counters(&state)?;
        if journal.remaining_records()? < durable_record_reservations(&state) {
            return Err(ExecutorError::Capacity);
        }
        if state.attempts.len() > config.max_attempts {
            return Err(ExecutorError::Capacity);
        }
        if state.deployments.len() > config.max_deployments {
            return Err(ExecutorError::Capacity);
        }
        // A recovered nonterminal claim is ambiguous: the durable claim precedes the call, but a
        // crash can occur on either side of emitting that call. Never redispatch the same AttemptId.
        // At-most-once becomes indeterminate; at-least-once reports a retryable failed attempt so
        // the home/policy may mint a new numbered grant. A queued cooperative control does not
        // relax this crash fence: after restart it remains audit evidence but cannot prove that the
        // base call or control was not already observed by the old process.
        let unfinished: Vec<_> = state
            .attempts
            .values()
            .filter(|attempt| {
                !attempt.terminal
                    && !matches!(
                        attempt.receipts.last().map(|receipt| &receipt.payload.stage),
                        Some(ExecutionStageV1::Claimed)
                    )
            })
            .map(|attempt| {
                (
                    attempt.grant.clone(),
                    attempt.grant.payload.delivery.clone(),
                    attempt.receipts.len() as u64 + 1,
                )
            })
            .collect();
        for (grant, delivery, sequence) in unfinished {
            let reservation_after = durable_record_reservations(&state).saturating_sub(1);
            ensure_append_capacity(&journal, reservation_after)?;
            let stage = match delivery {
                gawdfn::DeliveryModeV1::AtMostOnce => ExecutionStageV1::Indeterminate {
                    reason: EXECUTOR_RECOVERY_INDETERMINATE_REASON.into(),
                    execution_may_have_occurred: true,
                },
                gawdfn::DeliveryModeV1::AtLeastOnce { .. } => ExecutionStageV1::Failed {
                    error: gawdfn::ValueRefV1::Inline {
                        value: serde_json::json!({
                            "kind": EXECUTOR_RECOVERY_FAILURE_KIND,
                            "execution_may_have_occurred": true
                        }),
                    },
                    retryable: true,
                },
            };
            let receipt = SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: canonical_hash(&grant).map_err(invalid)?,
                    executor: config.executor.clone(),
                    sequence,
                    observed_at_unix_ms: None,
                    stage,
                },
                signer.as_ref(),
            )
            .map_err(|error| ExecutorError::Signing(error.to_string()))?;
            let record = ExecutorLedgerRecord::Receipt { receipt };
            validate_record(&config, signer.public_key(), &record)?;
            journal.append(record.clone())?;
            apply_record(&config, signer.public_key(), &mut state, &record)?;
        }
        validate_reservation_counters(&state)?;
        if journal.remaining_records()? < durable_record_reservations(&state) {
            return Err(ExecutorError::Capacity);
        }
        Ok(Self {
            config,
            signer,
            addressing,
            admission,
            liveness,
            journal,
            state: Mutex::new(state),
            recovery_sweep: Mutex::new(ExecutorRecoverySweep::default()),
            me: None,
        })
    }

    /// Once an append crosses a durability boundary and then fails, this process no longer knows
    /// which signed prefix is authoritative. Every executor capability stays inert until reopen
    /// replays the on-disk chain and establishes a fresh healthy journal instance.
    fn ensure_operational(&self) -> Result<(), ExecutorError> {
        self.journal.ensure_healthy()?;
        Ok(())
    }

    fn lock_healthy_state(&self) -> Result<MutexGuard<'_, ExecutorState>, ExecutorError> {
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        self.ensure_operational()?;
        Ok(state)
    }

    pub fn register(
        &self,
        request: SignedRecordV1<DeploymentRegistrationV1>,
    ) -> Result<SignedRecordV1<DeploymentReceiptV1>, ExecutorError> {
        let mut state = self.lock_healthy_state()?;
        gawdfn::verify_deployment_registration(&request)
            .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
        if request.payload.authorization.payload.target_realm != self.config.realm
            || request.payload.authorization.payload.target_node.as_deref()
                != Some(self.config.node.as_str())
        {
            return Err(ExecutorError::Unauthorized(
                "deployment authorization targets a different Realm/node".into(),
            ));
        }
        if !positive_creature_id(&request.payload.target_creature) {
            return Err(ExecutorError::Invalid(
                "deployment target must be one exact positive numeric CreatureId".into(),
            ));
        }
        let expected_deployment = derive_deployment_id(
            &request.payload.function,
            &request.payload.artifact_hash,
            &self.config.realm,
            &self.config.node,
            &request.payload.target_creature,
        )
        .map_err(invalid)?;
        if request.payload.deployment != expected_deployment {
            return Err(ExecutorError::Invalid(
                "DeploymentId is not derived from the immutable function/location/target pin"
                    .into(),
            ));
        }
        self.admission.register(&request).map_err(|reason| {
            ExecutorError::Unauthorized(format!("registration refused: {reason}"))
        })?;
        let registration = &request.payload;
        let receipt_payload = DeploymentReceiptV1 {
            deployment: registration.deployment.clone(),
            function: registration.function.clone(),
            artifact_hash: registration.artifact_hash.clone(),
            realm: self.config.realm.clone(),
            node: self.config.node.clone(),
            executor: self.config.executor.clone(),
            executor_creature: self.config.executor_creature.clone(),
            creature: registration.target_creature.clone(),
            evidence: registration.evidence.clone(),
            registered_at_unix_ms: None,
        };
        if self.config.executor_creature == "auto" {
            return Err(ExecutorError::Configuration(
                "executor must be bound before registering a deployment".into(),
            ));
        }
        let target_id = CreatureId(
            registration
                .target_creature
                .parse::<u64>()
                .map_err(|_| ExecutorError::Invalid("deployment target is not numeric".into()))?,
        );
        self.require_live_target(target_id, &receipt_payload)?;
        let receipt =
            SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, receipt_payload, self.signer.as_ref())
                .map_err(|error| ExecutorError::Signing(error.to_string()))?;
        gawdfn::verify_deployment_receipt(&receipt).map_err(invalid)?;
        if state.deployment_tombstones.contains(&registration.deployment) {
            return Err(ExecutorError::Conflict(
                "a tombstoned DeploymentId cannot be resurrected".into(),
            ));
        }
        if let Some(existing) = state.deployments.get(&registration.deployment) {
            if existing.payload == receipt.payload {
                return Ok(existing.clone());
            }
            if !same_deployment_binding(&existing.payload, &receipt.payload) {
                return Err(ExecutorError::Conflict(
                    "DeploymentId is already registered with different contents".into(),
                ));
            }
        }
        if state.deployments.len() >= self.config.max_deployments {
            return Err(ExecutorError::Capacity);
        }
        ensure_append_capacity(&self.journal, durable_record_reservations(&state))?;
        let record =
            ExecutorLedgerRecord::Register { request: Box::new(request), receipt: receipt.clone() };
        validate_record(&self.config, self.signer.public_key(), &record)?;
        self.journal.append(record.clone())?;
        apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
        Ok(receipt)
    }

    /// Return only durable registrations whose exact target identity is live now.
    ///
    /// Stale rows remain in the signed journal for audit/reconciliation but are never advertised as
    /// active. A liveness-provider refusal is treated as not live.
    pub fn deployments(
        &self,
        query: &DeploymentQueryV1,
    ) -> Result<DeploymentListV1, ExecutorError> {
        let state = self.lock_healthy_state()?;
        query.validate().map_err(invalid)?;
        let deployments = state
            .deployments
            .values()
            .filter(|receipt| {
                query.function.as_ref().is_none_or(|function| &receipt.payload.function == function)
                    && query.realm.as_ref().is_none_or(|realm| &receipt.payload.realm == realm)
                    && query.node.as_ref().is_none_or(|node| &receipt.payload.node == node)
                    && self.deployment_is_live(&receipt.payload)
            })
            .take(usize::from(query.limit))
            .cloned()
            .collect();
        Ok(DeploymentListV1 { deployments })
    }

    pub fn undeploy(
        &self,
        request: SignedRecordV1<UndeployRequestV1>,
    ) -> Result<SignedRecordV1<UndeployReceiptV1>, ExecutorError> {
        let mut state = self.lock_healthy_state()?;
        request.validate().map_err(invalid)?;
        if request.schema != SCHEMA_FUNCTION_DEPLOY_V1
            || !request.verify()
            || request.signer != request.payload.requested_by.as_str()
        {
            return Err(ExecutorError::Unauthorized("invalid undeploy authorization".into()));
        }
        let id = request.payload.deployment.clone();
        // A retry after a lost acknowledgement or executor restart re-attests the already-durable
        // tombstone with this process's current route. The stable executor signing key, not the old
        // process-local CreatureId, carries continuity.
        if state.deployment_tombstones.contains(&id) {
            return self.sign_undeploy_receipt(id);
        }
        let deployment = state.deployments.get(&id).cloned().ok_or(ExecutorError::NotFound)?;
        self.admission
            .undeploy(&request, &deployment)
            .map_err(|reason| ExecutorError::Unauthorized(format!("undeploy refused: {reason}")))?;
        if state.attempts.values().any(|attempt| {
            !attempt.terminal
                && attempt.grant.payload.deployment.payload.deployment == request.payload.deployment
        }) {
            return Err(ExecutorError::Conflict(
                "deployment has a nonterminal claimed attempt".into(),
            ));
        }
        ensure_append_capacity(&self.journal, durable_record_reservations(&state))?;
        let record = ExecutorLedgerRecord::Undeploy { request, deployment: id.clone() };
        validate_record(&self.config, self.signer.public_key(), &record)?;
        self.journal.append(record.clone())?;
        apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
        // Signing happens only after append/fsync + state application. If signing ever fails, the
        // caller receives no acknowledgement and a retry takes the tombstone branch above.
        self.sign_undeploy_receipt(id)
    }

    fn sign_undeploy_receipt(
        &self,
        deployment: DeploymentId,
    ) -> Result<SignedRecordV1<UndeployReceiptV1>, ExecutorError> {
        self.ensure_operational()?;
        if !positive_creature_id(&self.config.executor_creature) {
            return Err(ExecutorError::Configuration(
                "executor must be bound before acknowledging an undeploy".into(),
            ));
        }
        let receipt = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            UndeployReceiptV1 {
                deployment,
                executor: self.config.executor.clone(),
                executor_creature: self.config.executor_creature.clone(),
            },
            self.signer.as_ref(),
        )
        .map_err(|error| ExecutorError::Signing(error.to_string()))?;
        gawdfn::verify_undeploy_receipt(&receipt).map_err(invalid)?;
        Ok(receipt)
    }

    pub fn claim(
        &self,
        grant: SignedRecordV1<ExecutionGrantV1>,
    ) -> Result<ClaimOutcome, ExecutorError> {
        let mut state = self.lock_healthy_state()?;
        grant.validate().map_err(invalid)?;
        verify_execution_grant(&grant)
            .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
        if gawdfn::verify_deployment_receipt(&grant.payload.deployment).is_err() {
            return Err(ExecutorError::Unauthorized("invalid deployment receipt signature".into()));
        }
        if grant.payload.deployment.payload.executor != self.config.executor {
            return Err(ExecutorError::Invalid(format!(
                "grant targets executor `{}`, this executor is `{}`",
                grant.payload.deployment.payload.executor, self.config.executor
            )));
        }
        let key = attempt_key(&grant.payload.attempt);
        let grant_hash = canonical_hash(&grant).map_err(invalid)?;
        validate_home_fence(&state, &grant)?;
        if let Some(existing) = state.attempts.get(&key) {
            if existing.grant_hash != grant_hash {
                return Err(ExecutorError::Conflict(
                    "different grant for an already-claimed AttemptId".into(),
                ));
            }
            let receipt =
                existing.receipts.last().cloned().ok_or_else(|| {
                    ExecutorError::Conflict("claimed attempt has no receipt".into())
                })?;
            if !existing.terminal && receipt.payload.stage == ExecutionStageV1::Claimed {
                // Recovery after the durable claim but before the durable Started gate. The call
                // cannot have been emitted by this implementation, so it is safe to continue once.
                let (target_id, target) = self.exact_local_target(&grant.payload)?;
                if let Err(error) =
                    self.require_live_target(target_id, &grant.payload.deployment.payload)
                {
                    ensure_append_capacity(
                        &self.journal,
                        durable_record_reservations(&state).saturating_sub(1),
                    )?;
                    let failed = self.sign_liveness_refusal(&grant, 2, error)?;
                    let record = ExecutorLedgerRecord::Receipt { receipt: failed.clone() };
                    validate_record(&self.config, self.signer.public_key(), &record)?;
                    self.journal.append(record.clone())?;
                    apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
                    return Ok(ClaimOutcome::Terminal { receipt: failed });
                }
                let claimed = receipt;
                ensure_append_capacity(&self.journal, durable_record_reservations(&state))?;
                let started = self.sign_receipt(
                    &grant,
                    2,
                    grant.payload.issued_at_unix_ms,
                    ExecutionStageV1::Started,
                )?;
                let record = ExecutorLedgerRecord::Receipt { receipt: started.clone() };
                validate_record(&self.config, self.signer.public_key(), &record)?;
                self.journal.append(record.clone())?;
                apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
                return Ok(ClaimOutcome::Claimed {
                    receipts: vec![claimed, started],
                    call: self.function_call(&grant)?,
                    target,
                });
            }
            return Ok(if existing.terminal {
                ClaimOutcome::Terminal { receipt }
            } else {
                ClaimOutcome::Duplicate { receipt }
            });
        }
        if state.attempts.len() >= self.config.max_attempts {
            return Err(ExecutorError::Capacity);
        }
        let registered =
            state.deployments.get(&grant.payload.deployment.payload.deployment).ok_or_else(
                || ExecutorError::Unauthorized("grant deployment is not registered".into()),
            )?;
        if canonical_hash(registered).map_err(invalid)?
            != canonical_hash(&grant.payload.deployment).map_err(invalid)?
        {
            return Err(ExecutorError::Unauthorized(
                "grant deployment differs from the durable registry pin".into(),
            ));
        }
        let (target_id, target) = self.exact_local_target(&grant.payload)?;
        // Check before committing the first claim. A stale durable deployment must not turn into a
        // claimed attempt merely because its old CreatureId still parses.
        if let Err(error) = self.require_live_target(target_id, &grant.payload.deployment.payload) {
            ensure_append_capacity(&self.journal, durable_record_reservations(&state))?;
            let failed = self.sign_liveness_refusal(&grant, 1, error)?;
            let record =
                ExecutorLedgerRecord::Refuse { grant: Box::new(grant), receipt: failed.clone() };
            validate_record(&self.config, self.signer.public_key(), &record)?;
            self.journal.append(record.clone())?;
            apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
            return Ok(ClaimOutcome::Terminal { receipt: failed });
        }
        ensure_append_capacity(
            &self.journal,
            durable_record_reservations(&state).saturating_add(2),
        )?;
        let receipt = self.sign_receipt(
            &grant,
            1,
            grant.payload.issued_at_unix_ms,
            ExecutionStageV1::Claimed,
        )?;
        let record = ExecutorLedgerRecord::Claim {
            grant: Box::new(grant.clone()),
            receipt: receipt.clone(),
        };
        validate_record(&self.config, self.signer.public_key(), &record)?;
        self.journal.append(record.clone())?;
        apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
        // Recheck immediately before crossing the durable Started/call gate. An unload racing the
        // first check leaves a replayable Claimed record, never a falsely Started one.
        if let Err(error) = self.require_live_target(target_id, &grant.payload.deployment.payload) {
            ensure_append_capacity(
                &self.journal,
                durable_record_reservations(&state).saturating_sub(1),
            )?;
            let failed = self.sign_liveness_refusal(&grant, 2, error)?;
            let failed_record = ExecutorLedgerRecord::Receipt { receipt: failed.clone() };
            validate_record(&self.config, self.signer.public_key(), &failed_record)?;
            self.journal.append(failed_record.clone())?;
            apply_record(&self.config, self.signer.public_key(), &mut state, &failed_record)?;
            return Ok(ClaimOutcome::Terminal { receipt: failed });
        }
        ensure_append_capacity(&self.journal, durable_record_reservations(&state))?;
        let started = self.sign_receipt(
            &grant,
            2,
            grant.payload.issued_at_unix_ms,
            ExecutionStageV1::Started,
        )?;
        let started_record = ExecutorLedgerRecord::Receipt { receipt: started.clone() };
        validate_record(&self.config, self.signer.public_key(), &started_record)?;
        self.journal.append(started_record.clone())?;
        apply_record(&self.config, self.signer.public_key(), &mut state, &started_record)?;
        Ok(ClaimOutcome::Claimed {
            receipts: vec![receipt, started],
            call: self.function_call(&grant)?,
            target,
        })
    }

    fn function_call(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
    ) -> Result<FunctionCallV1, ExecutorError> {
        self.ensure_operational()?;
        let dispatch = ExecutorDispatchV1 {
            attempt: grant.payload.attempt.clone(),
            grant_hash: canonical_hash(grant).map_err(invalid)?,
            deployment: grant.payload.deployment.payload.deployment.clone(),
            executor_creature: self.config.executor_creature.clone(),
            target_creature: grant.payload.deployment.payload.creature.clone(),
        };
        let executor_dispatch =
            SignedRecordV1::sign(SCHEMA_CALL_V1, dispatch, self.signer.as_ref())
                .map_err(|error| ExecutorError::Signing(error.to_string()))?;
        let call = FunctionCallV1 {
            attempt: grant.payload.attempt.clone(),
            function: grant.payload.function.clone(),
            input: grant.payload.input.clone(),
            grant: Box::new(grant.clone()),
            executor_dispatch,
        };
        call.validate().map_err(invalid)?;
        Ok(call)
    }

    fn function_control(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
        endorsement: &SignedRecordV1<ExecutionControlV1>,
    ) -> Result<FunctionControlV1, ExecutorError> {
        self.ensure_operational()?;
        let dispatch = ExecutorControlDispatchV1 {
            attempt: grant.payload.attempt.clone(),
            grant_hash: canonical_hash(grant).map_err(invalid)?,
            control_hash: canonical_hash(endorsement).map_err(invalid)?,
            deployment: grant.payload.deployment.payload.deployment.clone(),
            executor_creature: self.config.executor_creature.clone(),
            target_creature: grant.payload.deployment.payload.creature.clone(),
        };
        let executor_dispatch =
            SignedRecordV1::sign(SCHEMA_CALL_V1, dispatch, self.signer.as_ref())
                .map_err(|error| ExecutorError::Signing(error.to_string()))?;
        let control = FunctionControlV1 {
            attempt: grant.payload.attempt.clone(),
            endorsement: Box::new(endorsement.clone()),
            grant: Box::new(grant.clone()),
            executor_dispatch,
        };
        control.validate().map_err(invalid)?;
        Ok(control)
    }

    fn live_control_target(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
    ) -> Result<Address, ExecutorError> {
        self.live_attempt_target(grant, false)
    }

    fn live_control_forward_target(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
    ) -> Result<Address, ExecutorError> {
        self.live_attempt_target(grant, true)
    }

    fn live_attempt_target(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
        require_nonterminal: bool,
    ) -> Result<Address, ExecutorError> {
        {
            let state = self.lock_healthy_state()?;
            if require_nonterminal {
                let attempt = state
                    .attempts
                    .get(&attempt_key(&grant.payload.attempt))
                    .ok_or(ExecutorError::NotFound)?;
                if attempt.terminal {
                    return Err(ExecutorError::Terminal);
                }
            }
            let deployment = state
                .deployments
                .get(&grant.payload.deployment.payload.deployment)
                .ok_or_else(|| {
                    ExecutorError::Unauthorized(
                        "control grant deployment is no longer registered".into(),
                    )
                })?;
            if state.deployment_tombstones.contains(&grant.payload.deployment.payload.deployment)
                || canonical_hash(deployment).map_err(invalid)?
                    != canonical_hash(&grant.payload.deployment).map_err(invalid)?
            {
                return Err(ExecutorError::Unauthorized(
                    "control grant differs from the exact live deployment registration".into(),
                ));
            }
        }
        let (target_id, target) = self.exact_local_target(&grant.payload)?;
        self.require_live_target(target_id, &grant.payload.deployment.payload)?;
        Ok(target)
    }

    fn exact_local_target(
        &self,
        grant: &ExecutionGrantV1,
    ) -> Result<(CreatureId, Address), ExecutorError> {
        let raw = &grant.deployment.payload.creature;
        let id = raw.parse::<u64>().map_err(|_| {
            ExecutorError::Address(format!("deployment target `{raw}` is not a numeric CreatureId"))
        })?;
        if id == 0 || id.to_string() != *raw {
            return Err(ExecutorError::Address(format!(
                "deployment target `{raw}` is not one canonical positive CreatureId"
            )));
        }
        let target_id = CreatureId(id);
        let target = self.addressing.function_target(grant).map_err(ExecutorError::Address)?;
        if target != Address::Creature(target_id) {
            return Err(ExecutorError::Address(format!(
                "deployment target `{raw}` resolved to `{target:?}` instead of its exact local CreatureId"
            )));
        }
        Ok((target_id, target))
    }

    fn require_live_target(
        &self,
        target: CreatureId,
        deployment: &DeploymentReceiptV1,
    ) -> Result<(), ExecutorError> {
        match self.liveness.target_is_live(target, deployment) {
            Ok(true) => Ok(()),
            Ok(false) => Err(ExecutorError::TargetUnavailable(target.0.to_string())),
            Err(reason) => Err(ExecutorError::Liveness(reason)),
        }
    }

    fn deployment_is_live(&self, deployment: &DeploymentReceiptV1) -> bool {
        let raw = &deployment.creature;
        let Ok(id) = raw.parse::<u64>() else { return false };
        if id == 0 || id.to_string() != *raw {
            return false;
        }
        self.liveness.target_is_live(CreatureId(id), deployment).is_ok_and(|live| live)
    }

    fn sign_liveness_refusal(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
        sequence: u64,
        error: ExecutorError,
    ) -> Result<SignedRecordV1<ExecutionReceiptV1>, ExecutorError> {
        let (kind, reason) = match error {
            ExecutorError::TargetUnavailable(reason) => ("deployment_target_unavailable", reason),
            ExecutorError::Liveness(reason) => ("deployment_liveness_unavailable", reason),
            other => return Err(other),
        };
        let reason: String = reason.chars().take(gawdfn::MAX_REASON_BYTES / 4).collect();
        self.sign_receipt(
            grant,
            sequence,
            grant.payload.issued_at_unix_ms,
            ExecutionStageV1::Failed {
                error: gawdfn::ValueRefV1::Inline {
                    value: serde_json::json!({
                        "kind": kind,
                        "reason": reason,
                        "execution_may_have_occurred": false
                    }),
                },
                retryable: true,
            },
        )
    }

    /// Persist progress/checkpoint/terminal state before emitting it to the job home.
    pub fn record_stage(
        &self,
        attempt: &AttemptId,
        stage: ExecutionStageV1,
        observed_at_unix_ms: Option<u64>,
    ) -> Result<RecordOutcome, ExecutorError> {
        let mut state = self.lock_healthy_state()?;
        stage.validate().map_err(invalid)?;
        let key = attempt_key(attempt);
        let current = state.attempts.get(&key).ok_or(ExecutorError::NotFound)?;
        let observation_sequence = match &stage {
            ExecutionStageV1::Progress { sequence, .. } => Some(("progress", *sequence)),
            ExecutionStageV1::Checkpoint { sequence, .. } => Some(("checkpoint", *sequence)),
            _ => None,
        };
        if let Some((kind, sequence)) = observation_sequence {
            let highest = match kind {
                "progress" => current.highest_progress_sequence,
                "checkpoint" => current.highest_checkpoint_sequence,
                _ => {
                    return Err(ExecutorError::Conflict(
                        "validated observation kind is not progress/checkpoint".into(),
                    ));
                }
            };
            let existing_index = match kind {
                "progress" => current.progress_receipts.get(&sequence),
                "checkpoint" => current.checkpoint_receipts.get(&sequence),
                _ => {
                    return Err(ExecutorError::Conflict(
                        "validated observation index kind is not progress/checkpoint".into(),
                    ));
                }
            };
            if let Some(existing) = existing_index.and_then(|index| current.receipts.get(*index)) {
                return if existing.payload.stage == stage {
                    Ok(RecordOutcome::Duplicate(existing.clone()))
                } else {
                    Err(ExecutorError::Conflict(format!(
                        "{kind} sequence {sequence} changed contents"
                    )))
                };
            }
            if sequence <= highest {
                return Err(ExecutorError::Conflict(format!(
                    "{kind} sequence {sequence} is not newer than {highest}"
                )));
            }
            if current.observation_count >= MAX_ATTEMPT_OBSERVATIONS {
                return Err(ExecutorError::Capacity);
            }
        }
        if let ExecutionStageV1::ControlAcknowledged { control, .. } = &stage {
            let control_key =
                (attempt.home.clone(), attempt.job.clone(), attempt.number, control.clone());
            let queued = state.controls.get(&control_key).ok_or_else(|| {
                ExecutorError::Conflict(format!(
                    "control `{}` was not durably queued",
                    control.as_str()
                ))
            })?;
            if let Some(existing) = &queued.acknowledged {
                return if existing.payload.stage == stage {
                    Ok(RecordOutcome::Duplicate(existing.clone()))
                } else {
                    Err(ExecutorError::Conflict(format!(
                        "control `{}` received divergent acknowledgments",
                        control.as_str()
                    )))
                };
            }
        }
        let control_acknowledgment = matches!(&stage, ExecutionStageV1::ControlAcknowledged { .. });
        if current.terminal && !control_acknowledgment {
            if let Some(last) = current.receipts.last() {
                if last.payload.stage == stage {
                    return Ok(RecordOutcome::Duplicate(last.clone()));
                }
            }
            return Err(ExecutorError::Terminal);
        }
        let consumes_attempt_reservation = usize::from(!current.terminal && stage_terminal(&stage));
        let consumes_control_reservation = match &stage {
            ExecutionStageV1::ControlAcknowledged { control, .. } => usize::from(
                state
                    .controls
                    .get(&(
                        attempt.home.clone(),
                        attempt.job.clone(),
                        attempt.number,
                        control.clone(),
                    ))
                    .is_some_and(|pending| pending.acknowledged.is_none()),
            ),
            _ => 0,
        };
        ensure_append_capacity(
            &self.journal,
            durable_record_reservations(&state)
                .saturating_sub(consumes_attempt_reservation + consumes_control_reservation),
        )?;
        let next_sequence = current.receipts.len() as u64 + 1;
        let grant = current.grant.clone();
        let receipt = self.sign_receipt(&grant, next_sequence, observed_at_unix_ms, stage)?;
        let record = ExecutorLedgerRecord::Receipt { receipt: receipt.clone() };
        validate_record(&self.config, self.signer.public_key(), &record)?;
        self.journal.append(record.clone())?;
        apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
        Ok(RecordOutcome::Recorded(receipt))
    }

    fn record_control_queued(
        &self,
        attempt: &AttemptId,
        request: SignedRecordV1<ExecutionControlV1>,
    ) -> Result<RecordOutcome, ExecutorError> {
        let mut state = self.lock_healthy_state()?;
        gawdfn::verify_execution_control(&request)
            .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
        if &request.payload.attempt != attempt {
            return Err(ExecutorError::Unauthorized(
                "control endorsement names a different attempt".into(),
            ));
        }
        let control = request.payload.caller_request.payload.control.clone();
        let request_hash = canonical_hash(&request).map_err(invalid)?;
        let key = (attempt.home.clone(), attempt.job.clone(), attempt.number, control.clone());
        validate_control_fence(&state, &request)?;
        let current = state.attempts.get(&attempt_key(attempt)).ok_or(ExecutorError::NotFound)?;
        if request.payload.grant_hash != current.grant_hash
            || request.payload.caller_request.payload.handle.home != current.grant.payload.owner
        {
            return Err(ExecutorError::Unauthorized(
                "control endorsement does not name the exact accepted attempt grant".into(),
            ));
        }
        let current_terminal = current.terminal;
        let current_grant = current.grant.clone();
        let next_sequence = current.receipts.len() as u64 + 1;
        if let Some(existing) = state.controls.get(&key).cloned() {
            if existing.request_hash != request_hash
                && !same_control_intent(&existing.request, &request)
            {
                return Err(ExecutorError::Conflict(format!(
                    "control `{}` was replayed with different signed contents",
                    control.as_str()
                )));
            }
            if existing.request_hash == request_hash {
                let latest =
                    existing.acknowledged.clone().unwrap_or_else(|| existing.queued.clone());
                return Ok(RecordOutcome::Duplicate(latest));
            }
            let queued = existing.queued.clone();
            let latest = existing.acknowledged.clone().unwrap_or_else(|| queued.clone());
            // A newer Home may continue the same durable accepted intent after custody moves.
            // Persist the current signed return route and advance the fence in this same record;
            // the original queued receipt/control count remain unchanged. Route changes never
            // borrow a terminal/control reservation or become process-local state.
            ensure_append_capacity(&self.journal, durable_record_reservations(&state))?;
            let record =
                ExecutorLedgerRecord::Control { request: Box::new(request), receipt: queued };
            validate_record(&self.config, self.signer.public_key(), &record)?;
            self.journal.append(record.clone())?;
            apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
            return Ok(RecordOutcome::Duplicate(latest));
        }
        if current.control_count >= MAX_JOB_CONTROLS {
            return Err(ExecutorError::Capacity);
        }
        if current_terminal {
            return Err(ExecutorError::Terminal);
        }
        ensure_append_capacity(
            &self.journal,
            durable_record_reservations(&state).saturating_add(1),
        )?;
        let receipt = self.sign_receipt(
            &current_grant,
            next_sequence,
            request.payload.caller_request.payload.issued_at_unix_ms,
            ExecutionStageV1::ControlQueued { control },
        )?;
        let record =
            ExecutorLedgerRecord::Control { request: Box::new(request), receipt: receipt.clone() };
        validate_record(&self.config, self.signer.public_key(), &record)?;
        self.journal.append(record.clone())?;
        apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
        Ok(RecordOutcome::Recorded(receipt))
    }

    pub fn latest(
        &self,
        attempt: &AttemptId,
    ) -> Result<SignedRecordV1<ExecutionReceiptV1>, ExecutorError> {
        self.lock_healthy_state()?
            .attempts
            .get(&attempt_key(attempt))
            .and_then(|record| record.receipts.last())
            .cloned()
            .ok_or(ExecutorError::NotFound)
    }

    /// Start one finite recovery sweep over the current durable receipt high-water mark.
    ///
    /// Receipts are replayed in per-attempt sequence order so a Home can deduplicate an already
    /// observed prefix without seeing a gap. A Claimed-only attempt may durably cross its Started
    /// gate and emit its first call; a Started attempt was already terminalized during reopen and
    /// never regains a call or queued control command. A self-addressed private continuation drains
    /// only the captured prefix in bounded Outcomes, never retries pending work awaiting an ack.
    pub fn recovery_dispatches(&self) -> Outcome {
        let state = match self.lock_healthy_state() {
            Ok(state) => state,
            Err(_) => return Outcome::none(),
        };
        let receipts_remaining =
            state.attempts.values().map(|attempt| attempt.receipts.len()).sum();
        let mut sweep = self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner());
        *sweep = ExecutorRecoverySweep {
            receipt_high_water_ordinal: state.next_receipt_recovery_ordinal,
            receipts_remaining,
            receipt_after: None,
            active: receipts_remaining != 0,
        };
        drop(sweep);
        drop(state);
        self.continue_recovery_sweep()
    }

    fn continue_recovery_sweep(&self) -> Outcome {
        if self.ensure_operational().is_err() {
            return Outcome::none();
        }
        let mut outcome = Outcome::none();
        loop {
            let receipts_remaining = self
                .recovery_sweep
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .receipts_remaining;
            if receipts_remaining == 0 {
                break;
            }
            // A receipt may carry its queued control command; a Claimed-only recovery can emit
            // Claimed + Started + the call. Reserving three slots keeps every Outcome bounded.
            if MAX_EXECUTOR_RECOVERY_DISPATCHES - outcome.dispatches.len() < 3 {
                break;
            }
            let work = match self.take_next_receipt_recovery() {
                Ok(Some(work)) => work,
                Ok(None) => break,
                Err(_) => return Outcome::none(),
            };
            outcome.dispatches.extend(self.dispatch_attempt_recovery(work));
            if self.ensure_operational().is_err() {
                return Outcome::none();
            }
        }

        let has_more = {
            let mut sweep = self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner());
            let has_more = sweep.receipts_remaining != 0;
            sweep.active = has_more;
            has_more
        };
        if has_more {
            if let Some(poke) = self.recovery_poke_dispatch() {
                outcome.push(poke);
            }
        }
        if self.ensure_operational().is_err() {
            Outcome::none()
        } else {
            outcome
        }
    }

    fn take_next_receipt_recovery(&self) -> Result<Option<AttemptRecoveryWork>, ExecutorError> {
        let state = self.lock_healthy_state()?;
        let mut sweep = self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner());
        if !sweep.active || sweep.receipts_remaining == 0 {
            return Ok(None);
        }
        let after = sweep.receipt_after.clone();
        let lower = after
            .as_ref()
            .map(|(key, _)| std::ops::Bound::Included(key.clone()))
            .unwrap_or(std::ops::Bound::Unbounded);
        let mut next = None;
        'attempts: for (key, attempt) in state.attempts.range((lower, std::ops::Bound::Unbounded)) {
            for (index, (receipt, ordinal)) in
                attempt.receipts.iter().zip(&attempt.receipt_recovery_ordinals).enumerate()
            {
                if *ordinal > sweep.receipt_high_water_ordinal
                    || after.as_ref().is_some_and(|(after_key, after_sequence)| {
                        key < after_key
                            || (key == after_key && receipt.payload.sequence <= *after_sequence)
                    })
                {
                    continue;
                }
                let work = if index + 1 == attempt.receipts.len()
                    && !attempt.terminal
                    && matches!(receipt.payload.stage, ExecutionStageV1::Claimed)
                {
                    AttemptRecoveryWork::Resume(Box::new(AttemptResumeRecovery {
                        grant: attempt.grant.clone(),
                        claimed: receipt.clone(),
                    }))
                } else {
                    let control = match &receipt.payload.stage {
                        ExecutionStageV1::ControlQueued { control } if !attempt.terminal => state
                            .controls
                            .get(&(key.0.clone(), key.1.clone(), key.2, control.clone()))
                            .filter(|pending| pending.acknowledged.is_none())
                            .map(|pending| pending.request.clone()),
                        _ => None,
                    };
                    AttemptRecoveryWork::Receipt(Box::new(AttemptReceiptRecovery {
                        grant: attempt.grant.clone(),
                        receipt: receipt.clone(),
                        control,
                    }))
                };
                next = Some((key.clone(), receipt.payload.sequence, work));
                break 'attempts;
            }
        }
        let Some((key, sequence, work)) = next else {
            sweep.receipts_remaining = 0;
            return Ok(None);
        };
        sweep.receipt_after = Some((key, sequence));
        sweep.receipts_remaining -= 1;
        Ok(Some(work))
    }

    fn dispatch_attempt_recovery(&self, work: AttemptRecoveryWork) -> Vec<Dispatch> {
        let grant = match &work {
            AttemptRecoveryWork::Resume(work) => &work.grant,
            AttemptRecoveryWork::Receipt(work) => &work.grant,
        }
        .clone();
        let Ok(home) = self.recovery_home_target(&grant) else {
            return Vec::new();
        };
        match work {
            AttemptRecoveryWork::Resume(work) => {
                let AttemptResumeRecovery { grant, claimed } = *work;
                match self.claim(grant) {
                    Ok(ClaimOutcome::Claimed { receipts, call, target }) => {
                        let mut dispatches = receipts
                            .into_iter()
                            .map(|receipt| execute_receipt_to(home.clone(), receipt))
                            .collect::<Vec<_>>();
                        dispatches.push(
                            Dispatch::to(
                                target,
                                aether::wire::to_bytes(&FunctionCallMessageV1::Call {
                                    call: Box::new(call),
                                }),
                            )
                            .with_schema(SCHEMA_CALL_V1),
                        );
                        dispatches
                    }
                    Ok(ClaimOutcome::Duplicate { receipt }) => {
                        if receipt.payload.sequence > claimed.payload.sequence {
                            vec![
                                execute_receipt_to(home.clone(), claimed),
                                execute_receipt_to(home, receipt),
                            ]
                        } else {
                            vec![execute_receipt_to(home, receipt)]
                        }
                    }
                    Ok(ClaimOutcome::Terminal { receipt }) => {
                        vec![
                            execute_receipt_to(home.clone(), claimed),
                            execute_receipt_to(home, receipt),
                        ]
                    }
                    Err(_) => Vec::new(),
                }
            }
            AttemptRecoveryWork::Receipt(work) => {
                let mut dispatches = vec![execute_receipt_to(home, work.receipt)];
                if let Some(control) = work.control {
                    if let Ok(target) = self.live_control_forward_target(&grant) {
                        if let Ok(command) = self.function_control(&grant, &control) {
                            dispatches.push(
                                Dispatch::to(
                                    target,
                                    aether::wire::to_bytes(&FunctionCallMessageV1::Control {
                                        control: Box::new(command),
                                    }),
                                )
                                .with_schema(SCHEMA_CALL_V1),
                            );
                        }
                    }
                }
                dispatches
            }
        }
    }

    fn recovery_home_target(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
    ) -> Result<Address, ExecutorError> {
        let state = self.lock_healthy_state()?;
        let fence = state.home_fences.get(&grant.payload.attempt.home).cloned();
        drop(state);
        if let Some(fence) = fence {
            if fence.epoch > grant.payload.home_epoch
                || (fence.epoch == grant.payload.home_epoch
                    && fence.route_sequence >= grant.payload.home_route_sequence)
            {
                let coordinator =
                    parse_address(&fence.home_coordinator).map_err(ExecutorError::Address)?;
                return routed_address(
                    &self.config.realm,
                    &self.config.node,
                    &fence.home_realm,
                    &fence.home_node,
                    coordinator,
                )
                .map_err(ExecutorError::Address);
            }
        }
        self.addressing.home_target(&grant.payload).map_err(ExecutorError::Address)
    }

    fn recovery_poke_dispatch(&self) -> Option<Dispatch> {
        let me = self.me?;
        Some(
            Dispatch::to(Address::Creature(me), EXECUTOR_RECOVERY_POKE_PAYLOAD.to_vec())
                .with_schema(EXECUTOR_RECOVERY_POKE_SCHEMA),
        )
    }

    fn is_authenticated_recovery_poke(&self, env: &Envelope) -> bool {
        let Some(me) = self.me else { return false };
        let self_address = Address::Creature(me);
        env.header.schema == EXECUTOR_RECOVERY_POKE_SCHEMA
            && env.header.origin.is_none()
            && env.header.from == self_address
            && env.header.to == self_address
            && env.payload == EXECUTOR_RECOVERY_POKE_PAYLOAD
    }

    /// Reconcile one exact attempt only for its current root-authorized Home. The signed query
    /// advances the executor's durable epoch fence when custody has moved and supplies the sole
    /// reply route; an Envelope `reply_to` is never a receipt capability.
    pub fn query(
        &self,
        request: SignedRecordV1<ExecutionQueryV1>,
    ) -> Result<(SignedRecordV1<ExecutionReceiptV1>, Address), ExecutorError> {
        let mut state = self.lock_healthy_state()?;
        verify_execution_query(&request)
            .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
        let (grant, receipt, grant_hash) = state
            .attempts
            .get(&attempt_key(&request.payload.attempt))
            .and_then(|record| {
                record
                    .receipts
                    .last()
                    .cloned()
                    .map(|receipt| (record.grant.clone(), receipt, record.grant_hash.clone()))
            })
            .ok_or(ExecutorError::NotFound)?;
        if request.payload.grant_hash != grant_hash
            || request.payload.attempt != grant.payload.attempt
            || request.payload.attempt.home != grant.payload.owner
        {
            return Err(ExecutorError::Unauthorized(
                "execution query does not name the exact accepted Home grant".into(),
            ));
        }
        validate_query_fence(&state, &request)?;
        let target = self
            .addressing
            .query_home_target(&grant.payload, &request.payload)
            .map_err(ExecutorError::Address)?;
        let needs_fence =
            state.home_fences.get(&request.payload.attempt.home).is_none_or(|fence| {
                fence.epoch < request.payload.home_epoch
                    || (fence.epoch == request.payload.home_epoch
                        && fence.route_sequence < request.payload.home_route_sequence)
            });
        if needs_fence {
            // A changed return route is authoritative only after its signed fence record is
            // durable. At exact capacity the Home must increase the cap/reopen and retry; neither
            // terminal state nor a signed one-shot request permits an in-memory route exception.
            ensure_append_capacity(&self.journal, durable_record_reservations(&state))?;
            let record = ExecutorLedgerRecord::HomeFence { query: Box::new(request) };
            validate_record(&self.config, self.signer.public_key(), &record)?;
            self.journal.append(record.clone())?;
            apply_record(&self.config, self.signer.public_key(), &mut state, &record)?;
        }
        Ok((receipt, target))
    }

    pub fn grant(
        &self,
        attempt: &AttemptId,
    ) -> Result<SignedRecordV1<ExecutionGrantV1>, ExecutorError> {
        self.lock_healthy_state()?
            .attempts
            .get(&attempt_key(attempt))
            .map(|record| record.grant.clone())
            .ok_or(ExecutorError::NotFound)
    }

    fn sign_receipt(
        &self,
        grant: &SignedRecordV1<ExecutionGrantV1>,
        sequence: u64,
        observed_at_unix_ms: Option<u64>,
        stage: ExecutionStageV1,
    ) -> Result<SignedRecordV1<ExecutionReceiptV1>, ExecutorError> {
        self.ensure_operational()?;
        let receipt = ExecutionReceiptV1 {
            attempt: grant.payload.attempt.clone(),
            grant_hash: canonical_hash(grant).map_err(invalid)?,
            executor: self.config.executor.clone(),
            sequence,
            observed_at_unix_ms,
            stage,
        };
        receipt.validate().map_err(invalid)?;
        SignedRecordV1::sign(SCHEMA_EXECUTE_V1, receipt, self.signer.as_ref())
            .map_err(|error| ExecutorError::Signing(error.to_string()))
    }

    fn result(
        &self,
        env: &Envelope,
        result: FunctionResultV1,
    ) -> Result<(SignedRecordV1<ExecutionReceiptV1>, Address), ExecutorError> {
        self.ensure_operational()?;
        result.validate().map_err(invalid)?;
        let grant = self.grant(&result.attempt)?;
        let expected_target = self.live_control_target(&grant)?;
        if env.header.from != expected_target {
            return Err(ExecutorError::Unauthorized(
                "function result sender does not match the pinned target".into(),
            ));
        }
        let stage = match result.outcome {
            Ok(value) => ExecutionStageV1::Succeeded { result: value },
            Err(error) => ExecutionStageV1::Failed { error, retryable: false },
        };
        let receipt = match self.record_stage(&result.attempt, stage, None)? {
            RecordOutcome::Recorded(receipt) | RecordOutcome::Duplicate(receipt) => receipt,
        };
        let home = self.recovery_home_target(&grant)?;
        Ok((receipt, home))
    }
}

impl Creature for FunctionExecutor {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
        self.config.executor_creature = ctx.me.0.to_string();
        for dispatch in self.recovery_dispatches().dispatches {
            let _ = ctx.bus.emit(dispatch);
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema == EXECUTOR_RECOVERY_POKE_SCHEMA {
            return if self.is_authenticated_recovery_poke(&env) {
                self.continue_recovery_sweep()
            } else {
                Outcome::none()
            };
        }
        if self.ensure_operational().is_err() {
            return Outcome::none();
        }
        if env.payload.len() > MAX_JOB_MESSAGE_BYTES {
            return Outcome::none();
        }
        let outcome = match env.header.schema.as_str() {
            SCHEMA_FUNCTION_DEPLOY_V1 => {
                let Ok(message) = serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
                else {
                    return Outcome::none();
                };
                let response = match message {
                    FunctionDeployMessageV1::Register { request } => {
                        match self.register(*request) {
                            Ok(receipt) => FunctionDeployMessageV1::Registered { receipt },
                            Err(error) => deploy_error(error),
                        }
                    }
                    FunctionDeployMessageV1::Lookup { query } => match self.deployments(&query) {
                        Ok(list) => FunctionDeployMessageV1::Deployments { list },
                        Err(error) => deploy_error(error),
                    },
                    FunctionDeployMessageV1::Undeploy { request } => match self.undeploy(request) {
                        Ok(receipt) => FunctionDeployMessageV1::Undeployed { receipt },
                        Err(error) => deploy_error(error),
                    },
                    FunctionDeployMessageV1::Resolve { .. }
                    | FunctionDeployMessageV1::Resolved { .. }
                    | FunctionDeployMessageV1::Registered { .. }
                    | FunctionDeployMessageV1::Deployments { .. }
                    | FunctionDeployMessageV1::Undeployed { .. }
                    | FunctionDeployMessageV1::Error { .. } => return Outcome::none(),
                };
                Outcome::send(
                    Dispatch::reply_to_env(&env, aether::wire::to_bytes(&response))
                        .with_schema(SCHEMA_FUNCTION_DEPLOY_V1),
                )
            }
            SCHEMA_EXECUTE_V1 => {
                let Ok(message) = serde_json::from_slice::<ExecuteMessageV1>(&env.payload) else {
                    return Outcome::none();
                };
                match message {
                    ExecuteMessageV1::Grant { grant } => {
                        let grant = *grant;
                        let claim = self.claim(grant.clone());
                        let home = match self.recovery_home_target(&grant) {
                            Ok(home) => home,
                            Err(_) => return Outcome::none(),
                        };
                        match claim {
                            Ok(ClaimOutcome::Claimed { receipts, call, target }) => {
                                let mut outcome = Outcome::none();
                                for receipt in receipts {
                                    outcome.push(execute_receipt_to(home.clone(), receipt));
                                }
                                outcome.push(
                                    Dispatch::to(
                                        target,
                                        aether::wire::to_bytes(&FunctionCallMessageV1::Call {
                                            call: Box::new(call),
                                        }),
                                    )
                                    .with_schema(SCHEMA_CALL_V1),
                                );
                                outcome
                            }
                            Ok(ClaimOutcome::Duplicate { receipt })
                            | Ok(ClaimOutcome::Terminal { receipt }) => {
                                Outcome::send(execute_receipt_to(home, receipt))
                            }
                            Err(error) => Outcome::send(execute_error_to(home, error)),
                        }
                    }
                    ExecuteMessageV1::Query { request } => match self.query(*request) {
                        Ok((receipt, target)) => Outcome::send(
                            Dispatch::to(
                                target,
                                aether::wire::to_bytes(&ExecuteMessageV1::Receipt {
                                    receipt: Box::new(receipt),
                                }),
                            )
                            .with_schema(SCHEMA_EXECUTE_V1),
                        ),
                        // An unauthenticated/invalid query supplies no trusted error route.
                        Err(_) => Outcome::none(),
                    },
                    ExecuteMessageV1::Control { request } => self.on_control(&env, *request),
                    ExecuteMessageV1::Receipt { .. } | ExecuteMessageV1::Error { .. } => {
                        Outcome::none()
                    }
                }
            }
            SCHEMA_CALL_V1 => {
                let Ok(message) = serde_json::from_slice::<FunctionCallMessageV1>(&env.payload)
                else {
                    return Outcome::none();
                };
                match message {
                    FunctionCallMessageV1::Result { result } => match self.result(&env, result) {
                        Ok((receipt, home)) => Outcome::send(
                            Dispatch::to(
                                home,
                                aether::wire::to_bytes(&ExecuteMessageV1::Receipt {
                                    receipt: Box::new(receipt),
                                }),
                            )
                            .with_schema(SCHEMA_EXECUTE_V1),
                        ),
                        Err(_) => Outcome::none(),
                    },
                    FunctionCallMessageV1::Progress { attempt, sequence, progress } => self
                        .on_function_observation(
                            &env,
                            attempt,
                            ExecutionStageV1::Progress { sequence, progress },
                        ),
                    FunctionCallMessageV1::Checkpoint { attempt, sequence, checkpoint } => self
                        .on_function_observation(
                            &env,
                            attempt,
                            ExecutionStageV1::Checkpoint { sequence, checkpoint },
                        ),
                    FunctionCallMessageV1::ControlResult {
                        attempt,
                        control,
                        disposition,
                        detail,
                    } => self.on_control_result(&env, attempt, control, disposition, detail),
                    FunctionCallMessageV1::Call { .. } | FunctionCallMessageV1::Control { .. } => {
                        Outcome::none()
                    }
                }
            }
            _ => Outcome::none(),
        };
        if self.ensure_operational().is_err() {
            Outcome::none()
        } else {
            outcome
        }
    }
}

impl FunctionExecutor {
    fn on_function_observation(
        &self,
        env: &Envelope,
        attempt: AttemptId,
        stage: ExecutionStageV1,
    ) -> Outcome {
        if self.ensure_operational().is_err() {
            return Outcome::none();
        }
        let grant = match self.grant(&attempt) {
            Ok(grant) => grant,
            Err(_) => return Outcome::none(),
        };
        let expected_target = match self.live_control_target(&grant) {
            Ok(target) => target,
            Err(_) => return Outcome::none(),
        };
        if env.header.from != expected_target {
            return Outcome::none();
        }
        let receipt = match self.record_stage(&attempt, stage, None) {
            Ok(RecordOutcome::Recorded(receipt) | RecordOutcome::Duplicate(receipt)) => receipt,
            Err(_) => return Outcome::none(),
        };
        let home = match self.recovery_home_target(&grant) {
            Ok(home) => home,
            Err(_) => return Outcome::none(),
        };
        Outcome::send(
            Dispatch::to(
                home,
                aether::wire::to_bytes(&ExecuteMessageV1::Receipt { receipt: Box::new(receipt) }),
            )
            .with_schema(SCHEMA_EXECUTE_V1),
        )
    }

    fn on_control(&self, env: &Envelope, request: SignedRecordV1<ExecutionControlV1>) -> Outcome {
        if self.ensure_operational().is_err() {
            return Outcome::none();
        }
        if gawdfn::verify_execution_control(&request).is_err() {
            return Outcome::send(reply_execute_error(
                env,
                ExecutorError::Unauthorized("invalid control signature".into()),
            ));
        }
        let attempt = request.payload.attempt.clone();
        let grant = match self.grant(&attempt) {
            Ok(grant) => grant,
            Err(error) => return Outcome::send(reply_execute_error(env, error)),
        };
        if grant.payload.owner != request.payload.caller_request.payload.handle.home
            || canonical_hash(&grant).ok().as_deref() != Some(request.payload.grant_hash.as_str())
        {
            return Outcome::send(reply_execute_error(
                env,
                ExecutorError::Unauthorized(
                    "control endorsement does not match the exact accepted attempt grant".into(),
                ),
            ));
        }
        let (receipt, should_forward) = match self.record_control_queued(&attempt, request.clone())
        {
            Ok(RecordOutcome::Recorded(receipt)) => {
                let pending =
                    matches!(receipt.payload.stage, ExecutionStageV1::ControlQueued { .. });
                (receipt, pending)
            }
            Ok(RecordOutcome::Duplicate(receipt)) => {
                let pending =
                    matches!(receipt.payload.stage, ExecutionStageV1::ControlQueued { .. });
                (receipt, pending)
            }
            Err(error) => return Outcome::send(reply_execute_error(env, error)),
        };
        if self.ensure_operational().is_err() {
            return Outcome::none();
        }
        let terminal = match self.lock_healthy_state().and_then(|state| {
            state
                .attempts
                .get(&attempt_key(&attempt))
                .map(|record| record.terminal)
                .ok_or(ExecutorError::NotFound)
        }) {
            Ok(terminal) => terminal,
            Err(_) => return Outcome::none(),
        };
        let home = match if terminal {
            self.addressing
                .control_home_target(&grant.payload, &request.payload)
                .map_err(ExecutorError::Address)
        } else {
            self.recovery_home_target(&grant)
        } {
            Ok(home) => home,
            Err(_) => return Outcome::none(),
        };
        let mut outcome = Outcome::send(execute_receipt_to(home, receipt));
        if should_forward && !terminal {
            if let (Ok(target), Ok(control)) =
                (self.live_control_forward_target(&grant), self.function_control(&grant, &request))
            {
                outcome.push(
                    Dispatch::to(
                        target,
                        aether::wire::to_bytes(&FunctionCallMessageV1::Control {
                            control: Box::new(control),
                        }),
                    )
                    .with_schema(SCHEMA_CALL_V1),
                );
            }
        }
        if self.ensure_operational().is_err() {
            Outcome::none()
        } else {
            outcome
        }
    }

    fn on_control_result(
        &self,
        env: &Envelope,
        attempt: AttemptId,
        control: gawdfn::ControlId,
        disposition: ControlDispositionV1,
        detail: Option<String>,
    ) -> Outcome {
        if self.ensure_operational().is_err() {
            return Outcome::none();
        }
        let pending = {
            let state = match self.lock_healthy_state() {
                Ok(state) => state,
                Err(_) => return Outcome::none(),
            };
            state
                .controls
                .get(&(attempt.home.clone(), attempt.job.clone(), attempt.number, control.clone()))
                .map(|record| record.request.clone())
        };
        let Some(_pending) = pending else {
            return Outcome::none();
        };
        let grant = match self.grant(&attempt) {
            Ok(grant) => grant,
            Err(_) => return Outcome::none(),
        };
        let expected_target = match self.live_control_target(&grant) {
            Ok(target) => target,
            Err(_) => return Outcome::none(),
        };
        if env.header.from != expected_target {
            return Outcome::none();
        }
        let receipt = match self.record_stage(
            &attempt,
            ExecutionStageV1::ControlAcknowledged { control, disposition, detail },
            None,
        ) {
            Ok(RecordOutcome::Recorded(receipt) | RecordOutcome::Duplicate(receipt)) => receipt,
            Err(_) => return Outcome::none(),
        };
        let home = match self.recovery_home_target(&grant) {
            Ok(home) => home,
            Err(_) => return Outcome::none(),
        };
        Outcome::send(
            Dispatch::to(
                home,
                aether::wire::to_bytes(&ExecuteMessageV1::Receipt { receipt: Box::new(receipt) }),
            )
            .with_schema(SCHEMA_EXECUTE_V1),
        )
    }
}

fn apply_record(
    config: &ExecutorConfig,
    journal_signer: &str,
    state: &mut ExecutorState,
    record: &ExecutorLedgerRecord,
) -> Result<(), ExecutorError> {
    validate_record(config, journal_signer, record)?;
    match record {
        ExecutorLedgerRecord::Register { receipt, .. } => {
            let id = receipt.payload.deployment.clone();
            if state.deployment_tombstones.contains(&id) {
                return Err(ExecutorError::Conflict("registration follows tombstone".into()));
            }
            if let Some(existing) = state.deployments.insert(id, receipt.clone()) {
                if !same_deployment_binding(&existing.payload, &receipt.payload) {
                    return Err(ExecutorError::Conflict(
                        "conflicting persisted deployment registration".into(),
                    ));
                }
            }
        }
        ExecutorLedgerRecord::Undeploy { deployment, .. } => {
            if state.deployments.remove(deployment).is_none()
                && !state.deployment_tombstones.contains(deployment)
            {
                return Err(ExecutorError::Conflict("undeploy precedes registration".into()));
            }
            state.deployment_tombstones.insert(deployment.clone());
        }
        ExecutorLedgerRecord::Claim { grant, receipt }
        | ExecutorLedgerRecord::Refuse { grant, receipt } => {
            let registered =
                state.deployments.get(&grant.payload.deployment.payload.deployment).ok_or_else(
                    || ExecutorError::Unauthorized("claim precedes deployment registration".into()),
                )?;
            if canonical_hash(registered).map_err(invalid)?
                != canonical_hash(&grant.payload.deployment).map_err(invalid)?
            {
                return Err(ExecutorError::Conflict(
                    "claim deployment differs from registry".into(),
                ));
            }
            let key = attempt_key(&grant.payload.attempt);
            let hash = canonical_hash(grant).map_err(invalid)?;
            if let Some(existing) = state.attempts.get(&key) {
                if existing.grant_hash != hash {
                    return Err(ExecutorError::Conflict("two grants for one AttemptId".into()));
                }
                return Ok(());
            }
            advance_home_fence(state, grant)?;
            state.next_receipt_recovery_ordinal = state
                .next_receipt_recovery_ordinal
                .checked_add(1)
                .ok_or(ExecutorError::Capacity)?;
            let receipt_recovery_ordinal = state.next_receipt_recovery_ordinal;
            let mut progress_receipts = BTreeMap::new();
            let mut checkpoint_receipts = BTreeMap::new();
            match &receipt.payload.stage {
                ExecutionStageV1::Progress { sequence, .. } => {
                    progress_receipts.insert(*sequence, 0);
                }
                ExecutionStageV1::Checkpoint { sequence, .. } => {
                    checkpoint_receipts.insert(*sequence, 0);
                }
                _ => {}
            }
            let terminal = stage_terminal(&receipt.payload.stage);
            if !terminal {
                state.nonterminal_attempts =
                    state.nonterminal_attempts.checked_add(1).ok_or(ExecutorError::Capacity)?;
            }
            state.attempts.insert(
                key,
                AttemptRecord {
                    grant: (**grant).clone(),
                    grant_hash: hash,
                    receipts: vec![receipt.clone()],
                    receipt_recovery_ordinals: vec![receipt_recovery_ordinal],
                    observation_count: usize::from(is_observation(&receipt.payload.stage)),
                    highest_progress_sequence: progress_sequence(&receipt.payload.stage),
                    highest_checkpoint_sequence: checkpoint_sequence(&receipt.payload.stage),
                    progress_receipts,
                    checkpoint_receipts,
                    control_count: 0,
                    terminal,
                },
            );
        }
        ExecutorLedgerRecord::Control { request, receipt } => {
            let control = request.payload.caller_request.payload.control.clone();
            let key = (
                receipt.payload.attempt.home.clone(),
                receipt.payload.attempt.job.clone(),
                receipt.payload.attempt.number,
                control,
            );
            let request_hash = canonical_hash(request).map_err(invalid)?;
            validate_control_fence(state, request)?;
            if let Some(existing) = state.controls.get(&key) {
                if existing.request_hash == request_hash {
                    return Ok(());
                }
                if !same_control_intent(&existing.request, request) {
                    return Err(ExecutorError::Conflict(
                        "persisted ControlId has divergent signed requests".into(),
                    ));
                }
                if existing.queued != *receipt {
                    return Err(ExecutorError::Conflict(
                        "re-endorsed control changed its original queued receipt".into(),
                    ));
                }
                advance_control_fence(state, request)?;
                let existing = state.controls.get_mut(&key).ok_or_else(|| {
                    ExecutorError::Conflict(
                        "control disappeared during current endorsement update".into(),
                    )
                })?;
                existing.request_hash = request_hash;
                existing.request = (**request).clone();
                return Ok(());
            }
            let attempt = state
                .attempts
                .get(&attempt_key(&receipt.payload.attempt))
                .ok_or(ExecutorError::NotFound)?;
            gawdfn::verify_execution_receipt(receipt, &attempt.grant)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            if attempt.grant_hash != request.payload.grant_hash
                || attempt.grant.payload.owner != request.payload.caller_request.payload.handle.home
                || request.payload.attempt != receipt.payload.attempt
            {
                return Err(ExecutorError::Unauthorized(
                    "persisted control does not match the exact accepted attempt grant".into(),
                ));
            }
            let expected = attempt.receipts.len() as u64 + 1;
            if receipt.payload.sequence != expected || attempt.terminal {
                return Err(ExecutorError::Conflict(
                    "persisted control receipt is out of sequence or terminal".into(),
                ));
            }
            if attempt.control_count >= MAX_JOB_CONTROLS {
                return Err(ExecutorError::Capacity);
            }
            advance_control_fence(state, request)?;
            let attempt = state
                .attempts
                .get_mut(&attempt_key(&receipt.payload.attempt))
                .ok_or_else(|| {
                    ExecutorError::Conflict(
                        "attempt disappeared during control fence advancement".into(),
                    )
                })?;
            attempt.receipts.push(receipt.clone());
            attempt.control_count += 1;
            state.next_receipt_recovery_ordinal = state
                .next_receipt_recovery_ordinal
                .checked_add(1)
                .ok_or(ExecutorError::Capacity)?;
            let receipt_recovery_ordinal = state.next_receipt_recovery_ordinal;
            state
                .attempts
                .get_mut(&attempt_key(&receipt.payload.attempt))
                .ok_or_else(|| {
                    ExecutorError::Conflict(
                        "control attempt disappeared while recording recovery order".into(),
                    )
                })?
                .receipt_recovery_ordinals
                .push(receipt_recovery_ordinal);
            state.unacknowledged_controls =
                state.unacknowledged_controls.checked_add(1).ok_or(ExecutorError::Capacity)?;
            state.controls.insert(
                key,
                ControlRecord {
                    request_hash,
                    request: (**request).clone(),
                    queued: receipt.clone(),
                    acknowledged: None,
                },
            );
        }
        ExecutorLedgerRecord::HomeFence { query } => {
            let attempt = state
                .attempts
                .get(&attempt_key(&query.payload.attempt))
                .ok_or(ExecutorError::NotFound)?;
            if attempt.grant_hash != query.payload.grant_hash
                || attempt.grant.payload.owner != query.payload.attempt.home
            {
                return Err(ExecutorError::Unauthorized(
                    "persisted query fence does not name its exact accepted grant".into(),
                ));
            }
            advance_query_fence(state, query)?;
        }
        ExecutorLedgerRecord::Receipt { receipt } => {
            let acknowledged_control =
                if let ExecutionStageV1::ControlAcknowledged { control, .. } =
                    &receipt.payload.stage
                {
                    let key = (
                        receipt.payload.attempt.home.clone(),
                        receipt.payload.attempt.job.clone(),
                        receipt.payload.attempt.number,
                        control.clone(),
                    );
                    if !state.controls.contains_key(&key) {
                        return Err(ExecutorError::Conflict(
                            "control acknowledgment precedes durable forwarding".into(),
                        ));
                    }
                    Some(key)
                } else {
                    None
                };
            let consumes_control_reservation = acknowledged_control.as_ref().is_some_and(|key| {
                state.controls.get(key).is_some_and(|control| control.acknowledged.is_none())
            });
            let attempt = state
                .attempts
                .get_mut(&attempt_key(&receipt.payload.attempt))
                .ok_or(ExecutorError::NotFound)?;
            gawdfn::verify_execution_receipt(receipt, &attempt.grant)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            let expected = attempt.receipts.len() as u64 + 1;
            if receipt.payload.sequence != expected {
                return Err(ExecutorError::Conflict(format!(
                    "receipt sequence {} is not next after {}",
                    receipt.payload.sequence,
                    expected - 1
                )));
            }
            let terminal_before = attempt.terminal;
            if terminal_before
                && !matches!(&receipt.payload.stage, ExecutionStageV1::ControlAcknowledged { .. })
            {
                return Err(ExecutorError::Terminal);
            }
            if is_observation(&receipt.payload.stage)
                && attempt.observation_count >= MAX_ATTEMPT_OBSERVATIONS
            {
                return Err(ExecutorError::Capacity);
            }
            let receipt_index = attempt.receipts.len();
            if let ExecutionStageV1::Progress { sequence, .. } = &receipt.payload.stage {
                if *sequence <= attempt.highest_progress_sequence {
                    return Err(ExecutorError::Conflict(
                        "persisted progress sequence is not monotonic".into(),
                    ));
                }
                attempt.highest_progress_sequence = *sequence;
                attempt.progress_receipts.insert(*sequence, receipt_index);
            }
            if let ExecutionStageV1::Checkpoint { sequence, .. } = &receipt.payload.stage {
                if *sequence <= attempt.highest_checkpoint_sequence {
                    return Err(ExecutorError::Conflict(
                        "persisted checkpoint sequence is not monotonic".into(),
                    ));
                }
                attempt.highest_checkpoint_sequence = *sequence;
                attempt.checkpoint_receipts.insert(*sequence, receipt_index);
            }
            if is_observation(&receipt.payload.stage) {
                attempt.observation_count += 1;
            }
            attempt.terminal = terminal_before || stage_terminal(&receipt.payload.stage);
            let became_terminal = !terminal_before && attempt.terminal;
            attempt.receipts.push(receipt.clone());
            state.next_receipt_recovery_ordinal = state
                .next_receipt_recovery_ordinal
                .checked_add(1)
                .ok_or(ExecutorError::Capacity)?;
            let receipt_recovery_ordinal = state.next_receipt_recovery_ordinal;
            state
                .attempts
                .get_mut(&attempt_key(&receipt.payload.attempt))
                .ok_or_else(|| {
                    ExecutorError::Conflict(
                        "receipt attempt disappeared while recording recovery order".into(),
                    )
                })?
                .receipt_recovery_ordinals
                .push(receipt_recovery_ordinal);
            if became_terminal {
                state.nonterminal_attempts =
                    state.nonterminal_attempts.checked_sub(1).ok_or_else(|| {
                        ExecutorError::Conflict("nonterminal reservation underflow".into())
                    })?;
            }
            if consumes_control_reservation {
                state.unacknowledged_controls =
                    state.unacknowledged_controls.checked_sub(1).ok_or_else(|| {
                        ExecutorError::Conflict("control reservation underflow".into())
                    })?;
            }
            if let Some(key) = acknowledged_control {
                state
                    .controls
                    .get_mut(&key)
                    .ok_or_else(|| {
                        ExecutorError::Conflict(
                            "control disappeared while applying its acknowledgment".into(),
                        )
                    })?
                    .acknowledged = Some(receipt.clone());
            }
        }
    }
    Ok(())
}

fn validate_record(
    config: &ExecutorConfig,
    journal_signer: &str,
    record: &ExecutorLedgerRecord,
) -> Result<(), ExecutorError> {
    match record {
        ExecutorLedgerRecord::Register { request, receipt } => {
            gawdfn::verify_deployment_registration(request)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            if request.payload.authorization.payload.target_realm != config.realm
                || request.payload.authorization.payload.target_node.as_deref()
                    != Some(config.node.as_str())
            {
                return Err(ExecutorError::Unauthorized(
                    "persisted registration authorization targets another Realm/node".into(),
                ));
            }
            let expected_deployment = derive_deployment_id(
                &request.payload.function,
                &request.payload.artifact_hash,
                &config.realm,
                &config.node,
                &request.payload.target_creature,
            )
            .map_err(invalid)?;
            if request.payload.deployment != expected_deployment {
                return Err(ExecutorError::Invalid(
                    "persisted DeploymentId is not derived from its exact binding".into(),
                ));
            }
            gawdfn::verify_deployment_receipt(receipt)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            if receipt.signer != journal_signer
                || receipt.payload.executor != config.executor
                || receipt.payload.realm != config.realm
                || receipt.payload.node != config.node
                || receipt.payload.deployment != request.payload.deployment
                || receipt.payload.function != request.payload.function
                || receipt.payload.artifact_hash != request.payload.artifact_hash
                || receipt.payload.creature != request.payload.target_creature
                || !positive_creature_id(&receipt.payload.executor_creature)
                || !positive_creature_id(&receipt.payload.creature)
            {
                return Err(ExecutorError::Conflict(
                    "deployment receipt does not match registration/executor".into(),
                ));
            }
        }
        ExecutorLedgerRecord::Undeploy { request, deployment } => {
            request.validate().map_err(invalid)?;
            if request.schema != SCHEMA_FUNCTION_DEPLOY_V1
                || !request.verify()
                || request.signer != request.payload.requested_by.as_str()
                || &request.payload.deployment != deployment
            {
                return Err(ExecutorError::Unauthorized(
                    "persisted undeploy authorization is invalid".into(),
                ));
            }
        }
        ExecutorLedgerRecord::Claim { grant, receipt } => {
            verify_execution_grant(grant)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            if grant.payload.deployment.payload.executor != config.executor {
                return Err(ExecutorError::Invalid(
                    "persisted grant targets another executor".into(),
                ));
            }
            validate_receipt(config, journal_signer, receipt)?;
            gawdfn::verify_execution_receipt(receipt, grant)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            if receipt.payload.attempt != grant.payload.attempt
                || receipt.payload.sequence != 1
                || receipt.payload.stage != ExecutionStageV1::Claimed
            {
                return Err(ExecutorError::Conflict("claim receipt does not match grant".into()));
            }
        }
        ExecutorLedgerRecord::Refuse { grant, receipt } => {
            verify_execution_grant(grant)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            if grant.payload.deployment.payload.executor != config.executor {
                return Err(ExecutorError::Invalid(
                    "persisted refusal grant targets another executor".into(),
                ));
            }
            validate_receipt(config, journal_signer, receipt)?;
            gawdfn::verify_execution_receipt(receipt, grant)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            let valid_refusal = matches!(
                &receipt.payload.stage,
                ExecutionStageV1::Failed {
                    error: gawdfn::ValueRefV1::Inline { value },
                    retryable: true,
                } if value.get("execution_may_have_occurred") == Some(&serde_json::Value::Bool(false))
                    && matches!(
                        value.get("kind").and_then(serde_json::Value::as_str),
                        Some("deployment_target_unavailable" | "deployment_liveness_unavailable")
                    )
            );
            if receipt.payload.attempt != grant.payload.attempt
                || receipt.payload.sequence != 1
                || !valid_refusal
            {
                return Err(ExecutorError::Conflict(
                    "pre-execution refusal receipt does not match grant".into(),
                ));
            }
        }
        ExecutorLedgerRecord::Control { request, receipt } => {
            gawdfn::verify_execution_control(request)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
            validate_receipt(config, journal_signer, receipt)?;
            if !matches!(
                &receipt.payload.stage,
                ExecutionStageV1::ControlQueued { control }
                    if control == &request.payload.caller_request.payload.control
                        && receipt.payload.attempt == request.payload.attempt
            ) {
                return Err(ExecutorError::Conflict(
                    "control queued receipt does not match the signed request/attempt".into(),
                ));
            }
        }
        ExecutorLedgerRecord::HomeFence { query } => {
            verify_execution_query(query)
                .map_err(|error| ExecutorError::Unauthorized(error.to_string()))?;
        }
        ExecutorLedgerRecord::Receipt { receipt } => {
            validate_receipt(config, journal_signer, receipt)?
        }
    }
    Ok(())
}

fn validate_receipt(
    config: &ExecutorConfig,
    journal_signer: &str,
    receipt: &SignedRecordV1<ExecutionReceiptV1>,
) -> Result<(), ExecutorError> {
    receipt.validate().map_err(invalid)?;
    if receipt.schema != SCHEMA_EXECUTE_V1
        || receipt.signer != journal_signer
        || receipt.payload.executor != config.executor
        || !receipt.verify()
    {
        return Err(ExecutorError::Unauthorized("persisted receipt signature is invalid".into()));
    }
    Ok(())
}

fn stage_terminal(stage: &ExecutionStageV1) -> bool {
    matches!(
        stage,
        ExecutionStageV1::Succeeded { .. }
            | ExecutionStageV1::Failed { .. }
            | ExecutionStageV1::Cancelled { .. }
            | ExecutionStageV1::Indeterminate { .. }
    )
}

fn is_observation(stage: &ExecutionStageV1) -> bool {
    matches!(stage, ExecutionStageV1::Progress { .. } | ExecutionStageV1::Checkpoint { .. })
}

fn progress_sequence(stage: &ExecutionStageV1) -> u64 {
    match stage {
        ExecutionStageV1::Progress { sequence, .. } => *sequence,
        _ => 0,
    }
}

fn checkpoint_sequence(stage: &ExecutionStageV1) -> u64 {
    match stage {
        ExecutionStageV1::Checkpoint { sequence, .. } => *sequence,
        _ => 0,
    }
}

fn durable_record_reservations(state: &ExecutorState) -> usize {
    state.nonterminal_attempts.saturating_add(state.unacknowledged_controls)
}

fn validate_reservation_counters(state: &ExecutorState) -> Result<(), ExecutorError> {
    let nonterminal = state.attempts.values().filter(|attempt| !attempt.terminal).count();
    let unacknowledged =
        state.controls.values().filter(|control| control.acknowledged.is_none()).count();
    let receipts = state.attempts.values().try_fold(0usize, |total, attempt| {
        if attempt.receipts.len() != attempt.receipt_recovery_ordinals.len() {
            return Err(ExecutorError::Conflict(
                "receipt recovery ordinals diverged from retained receipts".into(),
            ));
        }
        total.checked_add(attempt.receipts.len()).ok_or(ExecutorError::Capacity)
    })?;
    if state.nonterminal_attempts != nonterminal
        || state.unacknowledged_controls != unacknowledged
        || u64::try_from(receipts).ok() != Some(state.next_receipt_recovery_ordinal)
    {
        return Err(ExecutorError::Conflict(
            "executor durable-record reservation counters diverged from recovered state".into(),
        ));
    }
    Ok(())
}

fn ensure_append_capacity(
    journal: &SignedJournal<ExecutorLedgerRecord>,
    reservation_after_append: usize,
) -> Result<(), ExecutorError> {
    let remaining = journal.remaining_records()?;
    if remaining <= reservation_after_append {
        Err(ExecutorError::Capacity)
    } else {
        Ok(())
    }
}

fn attempt_key(attempt: &AttemptId) -> (gawdfn::HomeId, gawdfn::JobId, u8) {
    (attempt.home.clone(), attempt.job.clone(), attempt.number)
}

fn validate_home_fence(
    state: &ExecutorState,
    grant: &SignedRecordV1<ExecutionGrantV1>,
) -> Result<(), ExecutorError> {
    let Some(fence) = state.home_fences.get(&grant.payload.owner) else {
        return Ok(());
    };
    let authority_hash = canonical_hash(&grant.payload.authority).map_err(invalid)?;
    if grant.payload.home_epoch < fence.epoch {
        return Err(ExecutorError::Unauthorized(format!(
            "stale Home epoch {} is fenced by epoch {}",
            grant.payload.home_epoch, fence.epoch
        )));
    }
    if grant.payload.home_epoch == fence.epoch
        && (grant.signer != fence.operational_signer || authority_hash != fence.authority_hash)
    {
        return Err(ExecutorError::Unauthorized(
            "same Home epoch presented divergent operational authority".into(),
        ));
    }
    if grant.payload.home_epoch == fence.epoch
        && (grant.payload.home_route_sequence < fence.route_sequence
            || (grant.payload.home_route_sequence == fence.route_sequence
                && (grant.payload.home_realm != fence.home_realm
                    || grant.payload.home_node != fence.home_node
                    || grant.payload.home_coordinator != fence.home_coordinator)))
    {
        return Err(ExecutorError::Unauthorized(
            "stale or divergent same-revision Home return route".into(),
        ));
    }
    Ok(())
}

fn advance_home_fence(
    state: &mut ExecutorState,
    grant: &SignedRecordV1<ExecutionGrantV1>,
) -> Result<(), ExecutorError> {
    validate_home_fence(state, grant)?;
    let authority_hash = canonical_hash(&grant.payload.authority).map_err(invalid)?;
    let next = HomeFence {
        epoch: grant.payload.home_epoch,
        route_sequence: grant.payload.home_route_sequence,
        operational_signer: grant.signer.clone(),
        authority_hash,
        home_realm: grant.payload.home_realm.clone(),
        home_node: grant.payload.home_node.clone(),
        home_coordinator: grant.payload.home_coordinator.clone(),
    };
    match state.home_fences.get(&grant.payload.owner) {
        Some(existing)
            if existing.epoch > next.epoch
                || (existing.epoch == next.epoch
                    && existing.route_sequence >= next.route_sequence) => {}
        _ => {
            state.home_fences.insert(grant.payload.owner.clone(), next);
        }
    }
    Ok(())
}

fn validate_control_fence(
    state: &ExecutorState,
    control: &SignedRecordV1<ExecutionControlV1>,
) -> Result<(), ExecutorError> {
    let home = &control.payload.attempt.home;
    let Some(fence) = state.home_fences.get(home) else {
        return Ok(());
    };
    let authority_hash = canonical_hash(&control.payload.authority).map_err(invalid)?;
    if control.payload.home_epoch < fence.epoch {
        return Err(ExecutorError::Unauthorized(format!(
            "stale control Home epoch {} is fenced by epoch {}",
            control.payload.home_epoch, fence.epoch
        )));
    }
    if control.payload.home_epoch == fence.epoch
        && (control.signer != fence.operational_signer || authority_hash != fence.authority_hash)
    {
        return Err(ExecutorError::Unauthorized(
            "same control Home epoch presented divergent operational authority".into(),
        ));
    }
    if control.payload.home_epoch == fence.epoch
        && (control.payload.home_route_sequence < fence.route_sequence
            || (control.payload.home_route_sequence == fence.route_sequence
                && (control.payload.home_realm != fence.home_realm
                    || control.payload.home_node != fence.home_node
                    || control.payload.home_coordinator != fence.home_coordinator)))
    {
        return Err(ExecutorError::Unauthorized(
            "stale or divergent same-revision control return route".into(),
        ));
    }
    Ok(())
}

fn advance_control_fence(
    state: &mut ExecutorState,
    control: &SignedRecordV1<ExecutionControlV1>,
) -> Result<(), ExecutorError> {
    validate_control_fence(state, control)?;
    let authority_hash = canonical_hash(&control.payload.authority).map_err(invalid)?;
    let next = HomeFence {
        epoch: control.payload.home_epoch,
        route_sequence: control.payload.home_route_sequence,
        operational_signer: control.signer.clone(),
        authority_hash,
        home_realm: control.payload.home_realm.clone(),
        home_node: control.payload.home_node.clone(),
        home_coordinator: control.payload.home_coordinator.clone(),
    };
    match state.home_fences.get(&control.payload.attempt.home) {
        Some(existing)
            if existing.epoch > next.epoch
                || (existing.epoch == next.epoch
                    && existing.route_sequence >= next.route_sequence) => {}
        _ => {
            state.home_fences.insert(control.payload.attempt.home.clone(), next);
        }
    }
    Ok(())
}

fn same_control_intent(
    left: &SignedRecordV1<ExecutionControlV1>,
    right: &SignedRecordV1<ExecutionControlV1>,
) -> bool {
    left.payload.caller_request == right.payload.caller_request
        && left.payload.accepted_event == right.payload.accepted_event
        && left.payload.attempt == right.payload.attempt
        && left.payload.grant_hash == right.payload.grant_hash
}

fn validate_query_fence(
    state: &ExecutorState,
    query: &SignedRecordV1<ExecutionQueryV1>,
) -> Result<(), ExecutorError> {
    let Some(fence) = state.home_fences.get(&query.payload.attempt.home) else {
        return Ok(());
    };
    let authority_hash = canonical_hash(&query.payload.authority).map_err(invalid)?;
    if query.payload.home_epoch < fence.epoch {
        return Err(ExecutorError::Unauthorized(format!(
            "stale query Home epoch {} is fenced by epoch {}",
            query.payload.home_epoch, fence.epoch
        )));
    }
    if query.payload.home_epoch == fence.epoch
        && (query.signer != fence.operational_signer || authority_hash != fence.authority_hash)
    {
        return Err(ExecutorError::Unauthorized(
            "same query Home epoch presented divergent operational authority".into(),
        ));
    }
    if query.payload.home_epoch == fence.epoch
        && (query.payload.home_route_sequence < fence.route_sequence
            || (query.payload.home_route_sequence == fence.route_sequence
                && (query.payload.home_realm != fence.home_realm
                    || query.payload.home_node != fence.home_node
                    || query.payload.home_coordinator != fence.home_coordinator)))
    {
        return Err(ExecutorError::Unauthorized(
            "stale or divergent same-revision query return route".into(),
        ));
    }
    Ok(())
}

fn advance_query_fence(
    state: &mut ExecutorState,
    query: &SignedRecordV1<ExecutionQueryV1>,
) -> Result<(), ExecutorError> {
    validate_query_fence(state, query)?;
    let authority_hash = canonical_hash(&query.payload.authority).map_err(invalid)?;
    let next = HomeFence {
        epoch: query.payload.home_epoch,
        route_sequence: query.payload.home_route_sequence,
        operational_signer: query.signer.clone(),
        authority_hash,
        home_realm: query.payload.home_realm.clone(),
        home_node: query.payload.home_node.clone(),
        home_coordinator: query.payload.home_coordinator.clone(),
    };
    match state.home_fences.get(&query.payload.attempt.home) {
        Some(existing)
            if existing.epoch > next.epoch
                || (existing.epoch == next.epoch
                    && existing.route_sequence >= next.route_sequence) => {}
        _ => {
            state.home_fences.insert(query.payload.attempt.home.clone(), next);
        }
    }
    Ok(())
}

fn same_deployment_binding(left: &DeploymentReceiptV1, right: &DeploymentReceiptV1) -> bool {
    left.deployment == right.deployment
        && left.function == right.function
        && left.artifact_hash == right.artifact_hash
        && left.realm == right.realm
        && left.node == right.node
        && left.executor == right.executor
        && left.executor_creature == right.executor_creature
        && left.creature == right.creature
        && left.evidence == right.evidence
}

fn positive_creature_id(value: &str) -> bool {
    value.parse::<u64>().is_ok_and(|id| id > 0 && id.to_string() == value)
}

fn routed_address(
    local_realm: &str,
    local_node: &str,
    target_realm: &str,
    target_node: &str,
    target: Address,
) -> Result<Address, String> {
    if target_realm == local_realm && target_node == local_node {
        return Ok(target);
    }
    let node_target = match target {
        Address::Creature(creature) => Address::Node(NodeId(target_node.to_string()), creature),
        Address::Role(role) if target_realm != local_realm => Address::Role(role),
        Address::Role(_) => {
            return Err("a role address cannot select one remote node inside the same Realm".into());
        }
        _ => return Err("home coordinator must be a creature or role address".into()),
    };
    if target_realm == local_realm {
        Ok(node_target)
    } else {
        Ok(Address::Omega { realm: RealmId::new(target_realm), target: Box::new(node_target) })
    }
}

fn parse_address(value: &str) -> Result<Address, String> {
    if let Some(role) = value.strip_prefix("role:") {
        if role.trim().is_empty() {
            return Err("empty role address".into());
        }
        return Ok(Address::Role(Role::new(role)));
    }
    let raw = value.strip_prefix("creature:").unwrap_or(value);
    raw.parse::<u64>()
        .map(|id| Address::Creature(CreatureId(id)))
        .map_err(|_| format!("`{value}` is not creature:<u64>, <u64>, or role:<name>"))
}

fn execute_receipt_to(target: Address, receipt: SignedRecordV1<ExecutionReceiptV1>) -> Dispatch {
    Dispatch::to(
        target,
        aether::wire::to_bytes(&ExecuteMessageV1::Receipt { receipt: Box::new(receipt) }),
    )
    .with_schema(SCHEMA_EXECUTE_V1)
}

fn execute_error_to(target: Address, error: ExecutorError) -> Dispatch {
    Dispatch::to(target, aether::wire::to_bytes(&execute_error_message(error)))
        .with_schema(SCHEMA_EXECUTE_V1)
}

fn reply_execute_error(env: &Envelope, error: ExecutorError) -> Dispatch {
    Dispatch::reply_to_env(env, aether::wire::to_bytes(&execute_error_message(error)))
        .with_schema(SCHEMA_EXECUTE_V1)
}

fn execute_error_message(error: ExecutorError) -> ExecuteMessageV1 {
    let retryable = matches!(
        error,
        ExecutorError::Capacity
            | ExecutorError::Journal(_)
            | ExecutorError::TargetUnavailable(_)
            | ExecutorError::Liveness(_)
    );
    let code = match &error {
        ExecutorError::Unauthorized(_) => "unauthorized",
        ExecutorError::NotFound => "not_found",
        ExecutorError::Conflict(_) => "conflict",
        ExecutorError::Capacity => "capacity",
        ExecutorError::Journal(_) => "storage",
        ExecutorError::Terminal => "terminal",
        ExecutorError::TargetUnavailable(_) => "target_unavailable",
        ExecutorError::Liveness(_) => "liveness_unavailable",
        ExecutorError::Configuration(_)
        | ExecutorError::Invalid(_)
        | ExecutorError::Address(_)
        | ExecutorError::Signing(_) => "invalid",
    };
    let message = bound_reason(error.to_string());
    ExecuteMessageV1::Error { error: ProtocolErrorV1 { code: code.into(), message, retryable } }
}

fn deploy_error(error: ExecutorError) -> FunctionDeployMessageV1 {
    let retryable = matches!(
        error,
        ExecutorError::Capacity
            | ExecutorError::Journal(_)
            | ExecutorError::TargetUnavailable(_)
            | ExecutorError::Liveness(_)
    );
    let code = match &error {
        ExecutorError::Unauthorized(_) => "unauthorized",
        ExecutorError::NotFound => "not_found",
        ExecutorError::Conflict(_) => "conflict",
        ExecutorError::Capacity => "capacity",
        ExecutorError::Journal(_) => "storage",
        ExecutorError::Terminal => "terminal",
        ExecutorError::TargetUnavailable(_) => "target_unavailable",
        ExecutorError::Liveness(_) => "liveness_unavailable",
        ExecutorError::Configuration(_)
        | ExecutorError::Invalid(_)
        | ExecutorError::Address(_)
        | ExecutorError::Signing(_) => "invalid",
    };
    let message = bound_reason(error.to_string());
    FunctionDeployMessageV1::Error {
        error: ProtocolErrorV1 { code: code.into(), message, retryable },
    }
}

fn invalid(error: impl std::fmt::Display) -> ExecutorError {
    ExecutorError::Invalid(error.to_string())
}

fn bound_reason(mut reason: String) -> String {
    if reason.len() > gawdfn::MAX_REASON_BYTES {
        let mut end = gawdfn::MAX_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use gawdfn::{
        AbodeKeyBindingV1, BlobRefV1, ControlId, CustodyGrantV1, CustodyPreparedV1, DeliveryModeV1,
        DeploymentRequestV1, Ed25519SeedSigner, ExecutionControlV1, FunctionAlias, FunctionId,
        FunctionSelectorV1, HandoffId, HomeAuthorityV1, HomeCheckpointV1, HomeId, JobControlKindV1,
        JobControlV1, JobEventKindV1, JobEventV1, JobHandleV1, JobId, JobStateV1,
        OperationalCapabilityV1, OperationalKeyGrantV1, ResolutionReceiptV1, ValueRefV1,
        SCHEMA_HOME_V1,
    };
    use serde_json::json;
    use std::collections::VecDeque;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct AllowAdmission;

    impl DeploymentAdmission for AllowAdmission {
        fn register(
            &self,
            _request: &SignedRecordV1<DeploymentRegistrationV1>,
        ) -> Result<(), String> {
            Ok(())
        }

        fn undeploy(
            &self,
            _request: &SignedRecordV1<UndeployRequestV1>,
            _deployment: &SignedRecordV1<DeploymentReceiptV1>,
        ) -> Result<(), String> {
            Ok(())
        }
    }

    struct AlwaysLive;

    impl DeploymentLiveness for AlwaysLive {
        fn target_is_live(
            &self,
            _target: CreatureId,
            _deployment: &DeploymentReceiptV1,
        ) -> Result<bool, String> {
            Ok(true)
        }
    }

    struct SequenceLiveness(Mutex<VecDeque<Result<bool, String>>>);

    impl SequenceLiveness {
        fn new(answers: impl IntoIterator<Item = Result<bool, String>>) -> Self {
            Self(Mutex::new(answers.into_iter().collect()))
        }
    }

    impl DeploymentLiveness for SequenceLiveness {
        fn target_is_live(
            &self,
            _target: CreatureId,
            _deployment: &DeploymentReceiptV1,
        ) -> Result<bool, String> {
            self.0
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .pop_front()
                .unwrap_or_else(|| Err("unexpected extra liveness check".into()))
        }
    }

    struct Fixture {
        root: PathBuf,
        owner: Arc<Ed25519SeedSigner>,
        operational: Arc<Ed25519SeedSigner>,
        resolver: Ed25519SeedSigner,
        executor: Arc<Ed25519SeedSigner>,
        authority: HomeAuthorityV1,
        selector: FunctionSelectorV1,
        function: FunctionId,
        artifact: String,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let root = std::env::temp_dir()
                .join(format!("alpha-function-executor-{name}-{}-{nonce}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            let owner = Arc::new(Ed25519SeedSigner::from_seed([21; 32]).unwrap());
            let operational = Arc::new(Ed25519SeedSigner::from_seed([22; 32]).unwrap());
            let resolver = Ed25519SeedSigner::from_seed([23; 32]).unwrap();
            let executor = Arc::new(Ed25519SeedSigner::from_seed([24; 32]).unwrap());
            let home = HomeId::new(owner.public_key());
            let authority = authority(&owner, &operational, home, 1);
            let selector = FunctionSelectorV1::Alias {
                alias: FunctionAlias {
                    realm: "realm-a".into(),
                    name: "worker".into(),
                    version: "1.0.0".into(),
                    entrypoint: "run".into(),
                },
            };
            Self {
                root,
                owner,
                operational,
                resolver,
                executor,
                authority,
                selector,
                function: FunctionId {
                    manifest_content_address: hash('a'),
                    entrypoint: "run".into(),
                },
                artifact: hash('b'),
            }
        }

        fn config(&self) -> ExecutorConfig {
            ExecutorConfig::new(&self.root, self.executor.public_key())
                .with_location("realm-a", "node-a", "9")
        }

        fn open(&self) -> FunctionExecutor {
            self.open_with_liveness(Arc::new(AlwaysLive))
        }

        fn open_with_liveness(&self, liveness: Arc<dyn DeploymentLiveness>) -> FunctionExecutor {
            FunctionExecutor::open_with_liveness(
                self.config(),
                self.executor.clone(),
                Arc::new(StringAddressing),
                Arc::new(AllowAdmission),
                liveness,
            )
            .unwrap()
        }

        fn registration(
            &self,
            target_realm: &str,
            target_node: Option<&str>,
        ) -> SignedRecordV1<DeploymentRegistrationV1> {
            let authorization = SignedRecordV1::sign(
                SCHEMA_FUNCTION_DEPLOY_V1,
                DeploymentRequestV1 {
                    requested_by: HomeId::new(self.owner.public_key()),
                    function: self.selector.clone(),
                    target_realm: target_realm.into(),
                    target_node: target_node.map(str::to_string),
                    evidence: vec![],
                    requested_at_unix_ms: None,
                },
                self.owner.as_ref(),
            )
            .unwrap();
            let resolution = SignedRecordV1::sign(
                SCHEMA_FUNCTION_DEPLOY_V1,
                ResolutionReceiptV1 {
                    selector: self.selector.clone(),
                    function: self.function.clone(),
                    artifact_hash: self.artifact.clone(),
                    resolved_at_unix_ms: None,
                    evidence: vec![],
                },
                &self.resolver,
            )
            .unwrap();
            let deployment = derive_deployment_id(
                &self.function,
                &self.artifact,
                target_realm,
                target_node.unwrap_or("node-a"),
                "11",
            )
            .unwrap();
            SignedRecordV1::sign(
                SCHEMA_FUNCTION_DEPLOY_V1,
                DeploymentRegistrationV1 {
                    authorization,
                    resolution,
                    deployment,
                    function: self.function.clone(),
                    artifact_hash: self.artifact.clone(),
                    target_creature: "11".into(),
                    evidence: vec![],
                },
                self.owner.as_ref(),
            )
            .unwrap()
        }

        fn grant(
            &self,
            deployment: SignedRecordV1<DeploymentReceiptV1>,
            job: &str,
            delivery: DeliveryModeV1,
        ) -> SignedRecordV1<ExecutionGrantV1> {
            self.grant_with_authority(
                deployment,
                job,
                delivery,
                self.authority.clone(),
                self.operational.as_ref(),
                1,
            )
        }

        fn grant_with_authority(
            &self,
            deployment: SignedRecordV1<DeploymentReceiptV1>,
            job: &str,
            delivery: DeliveryModeV1,
            authority: HomeAuthorityV1,
            signer: &Ed25519SeedSigner,
            epoch: u64,
        ) -> SignedRecordV1<ExecutionGrantV1> {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionGrantV1 {
                    attempt: AttemptId {
                        home: HomeId::new(self.owner.public_key()),
                        job: JobId::new(job),
                        number: 1,
                    },
                    request_hash: hash('c'),
                    home_epoch: epoch,
                    home_route_sequence: epoch,
                    home_realm: "realm-a".into(),
                    home_node: "home-node".into(),
                    home_coordinator: "7".into(),
                    owner: HomeId::new(self.owner.public_key()),
                    authority,
                    function: self.function.clone(),
                    deployment,
                    input: ValueRefV1::Inline { value: json!({"x": 1}) },
                    delivery,
                    grant_sequence: epoch,
                    issued_at_unix_ms: None,
                    deadline_unix_ms: None,
                },
                signer,
            )
            .unwrap()
        }

        fn control(
            &self,
            grant: &SignedRecordV1<ExecutionGrantV1>,
            control: impl Into<String>,
            sequence: u64,
            kind: JobControlKindV1,
        ) -> SignedRecordV1<ExecutionControlV1> {
            let caller_request = SignedRecordV1::sign(
                gawdfn::SCHEMA_JOB_V1,
                JobControlV1 {
                    handle: JobHandleV1 {
                        home: grant.payload.attempt.home.clone(),
                        job: grant.payload.attempt.job.clone(),
                    },
                    expected_home_epoch: grant.payload.home_epoch,
                    control: ControlId::new(control),
                    issued_at_unix_ms: None,
                    kind,
                },
                self.owner.as_ref(),
            )
            .unwrap();
            let accepted_event = SignedRecordV1::sign(
                gawdfn::SCHEMA_JOB_V1,
                JobEventV1 {
                    handle: caller_request.payload.handle.clone(),
                    home_epoch: grant.payload.home_epoch,
                    authority: grant.payload.authority.clone(),
                    sequence,
                    occurred_at_unix_ms: None,
                    state_after: JobStateV1::Running,
                    cancel_requested: matches!(
                        caller_request.payload.kind,
                        JobControlKindV1::Cancel { .. }
                    ),
                    kind: JobEventKindV1::ControlRequested {
                        request: Box::new(caller_request.clone()),
                        attempt: Some(grant.payload.attempt.clone()),
                    },
                    foreign_receipt: None,
                },
                self.operational.as_ref(),
            )
            .unwrap();
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionControlV1 {
                    caller_request,
                    accepted_event: Box::new(accepted_event),
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: canonical_hash(grant).unwrap(),
                    home_epoch: grant.payload.home_epoch,
                    home_route_sequence: grant.payload.home_route_sequence,
                    home_sequence: sequence,
                    home_realm: grant.payload.home_realm.clone(),
                    home_node: grant.payload.home_node.clone(),
                    home_coordinator: grant.payload.home_coordinator.clone(),
                    authority: grant.payload.authority.clone(),
                },
                self.operational.as_ref(),
            )
            .unwrap()
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn authority(
        owner: &Ed25519SeedSigner,
        operational: &Ed25519SeedSigner,
        home: HomeId,
        epoch: u64,
    ) -> HomeAuthorityV1 {
        let abode = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            AbodeKeyBindingV1 {
                abode: home.clone(),
                root_public_key: owner.public_key().into(),
                issued_at_unix_ms: None,
            },
            owner,
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
            owner,
        )
        .unwrap();
        let mut result = HomeAuthorityV1 { abode, operational, prepared: None };
        if epoch == 2 {
            let source = Ed25519SeedSigner::from_seed([0x6f; 32]).unwrap();
            let checkpoint = SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                HomeCheckpointV1 {
                    home: home.clone(),
                    epoch: 1,
                    high_water_mark: 1,
                    log_root: hash('d'),
                    state: BlobRefV1 {
                        digest: hash('e'),
                        size: 1,
                        media_type: "application/octet-stream".into(),
                    },
                    created_at_unix_ms: None,
                },
                &source,
            )
            .unwrap();
            let grant = SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                CustodyGrantV1 {
                    home: home.clone(),
                    handoff: HandoffId::new("executor-epoch-fence"),
                    from_epoch: 1,
                    to_epoch: 2,
                    source_authority: authority(owner, &source, home.clone(), 1),
                    source_realm: "realm-a".into(),
                    source_node: "source-node".into(),
                    destination_realm: "realm-a".into(),
                    destination_node: "home-node".into(),
                    checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
                    source_log_root: checkpoint.payload.log_root.clone(),
                    destination_operational_key: result.operational.clone(),
                    evidence: vec![],
                    issued_at_unix_ms: None,
                    destination_rewrap: None,
                },
                owner,
            )
            .unwrap();
            let prepared = SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                CustodyPreparedV1 {
                    grant: Box::new(grant.clone()),
                    checkpoint: Box::new(checkpoint.clone()),
                    grant_hash: canonical_hash(&grant).unwrap(),
                    checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
                    source_log_root: checkpoint.payload.log_root.clone(),
                    source_coordinator: "source-home".into(),
                    rewrap_inventory_hash: None,
                    rewrap_item_count: None,
                },
                &source,
            )
            .unwrap();
            result.prepared = Some(Box::new(prepared));
        }
        result
    }

    fn moved_authority(
        fixture: &Fixture,
        next_operational: &Ed25519SeedSigner,
        handoff: &str,
    ) -> HomeAuthorityV1 {
        let home = HomeId::new(fixture.owner.public_key());
        let mut next = authority(fixture.owner.as_ref(), next_operational, home.clone(), 2);
        let checkpoint = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            HomeCheckpointV1 {
                home: home.clone(),
                epoch: 1,
                high_water_mark: 3,
                log_root: hash('f'),
                state: BlobRefV1 {
                    digest: hash('e'),
                    size: 1,
                    media_type: "application/octet-stream".into(),
                },
                created_at_unix_ms: None,
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        let grant = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyGrantV1 {
                home,
                handoff: HandoffId::new(handoff),
                from_epoch: 1,
                to_epoch: 2,
                source_authority: fixture.authority.clone(),
                source_realm: "realm-a".into(),
                source_node: "home-node".into(),
                destination_realm: "realm-a".into(),
                destination_node: "home-node".into(),
                checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
                source_log_root: checkpoint.payload.log_root.clone(),
                destination_operational_key: next.operational.clone(),
                evidence: vec![],
                issued_at_unix_ms: None,
                destination_rewrap: None,
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let prepared = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyPreparedV1 {
                grant_hash: canonical_hash(&grant).unwrap(),
                checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
                source_log_root: checkpoint.payload.log_root.clone(),
                source_coordinator: "7".into(),
                grant: Box::new(grant),
                checkpoint: Box::new(checkpoint),
                rewrap_inventory_hash: None,
                rewrap_item_count: None,
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        next.prepared = Some(Box::new(prepared));
        next
    }

    fn hash(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    #[test]
    fn bounded_protocol_reason_preserves_utf8_boundaries() {
        let bounded = bound_reason("€".repeat(gawdfn::MAX_REASON_BYTES));
        assert!(bounded.len() <= gawdfn::MAX_REASON_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
    }

    #[test]
    fn registration_rejects_authorization_for_another_location() {
        let fixture = Fixture::new("registration-location");
        let executor = fixture.open();
        assert!(matches!(
            executor.register(fixture.registration("realm-a", Some("node-b"))),
            Err(ExecutorError::Unauthorized(_))
        ));
        assert!(matches!(
            executor.register(fixture.registration("realm-a", None)),
            Err(ExecutorError::Unauthorized(_))
        ));
        let mut role_target = fixture.registration("realm-a", Some("node-a")).payload;
        role_target.target_creature = "role:worker".into();
        let role_target =
            SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, role_target, fixture.owner.as_ref())
                .unwrap();
        assert!(matches!(
            executor.register(role_target),
            Err(ExecutorError::Invalid(_) | ExecutorError::Unauthorized(_))
        ));

        let mut noncanonical = fixture.registration("realm-a", Some("node-a")).payload;
        noncanonical.target_creature = "01".into();
        noncanonical.deployment = derive_deployment_id(
            &noncanonical.function,
            &noncanonical.artifact_hash,
            "realm-a",
            "node-a",
            "01",
        )
        .unwrap();
        let noncanonical =
            SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, noncanonical, fixture.owner.as_ref())
                .unwrap();
        assert!(matches!(
            executor.register(noncanonical),
            Err(ExecutorError::Invalid(reason) | ExecutorError::Unauthorized(reason))
                if reason.contains("canonical decimal form of a positive CreatureId")
                    || reason.contains("exact positive numeric CreatureId")
        ));
    }

    #[test]
    fn durable_undeploy_retry_rebinds_the_current_executor_route_after_restart() {
        let fixture = Fixture::new("undeploy-restart-route");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let request = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            UndeployRequestV1 {
                requested_by: HomeId::new(fixture.owner.public_key()),
                deployment: deployment.payload.deployment.clone(),
                reason: Some("retire exact deployment".into()),
            },
            fixture.owner.as_ref(),
        )
        .unwrap();

        let first = executor.undeploy(request.clone()).unwrap();
        gawdfn::verify_undeploy_receipt(&first).unwrap();
        assert_eq!(first.payload.executor, fixture.executor.public_key());
        assert_eq!(first.payload.executor_creature, "9");
        drop(executor);

        let reopened = FunctionExecutor::open_with_liveness(
            ExecutorConfig::new(&fixture.root, fixture.executor.public_key())
                .with_location("realm-a", "node-a", "17"),
            fixture.executor.clone(),
            Arc::new(StringAddressing),
            Arc::new(AllowAdmission),
            Arc::new(AlwaysLive),
        )
        .unwrap();
        let rebound = reopened.undeploy(request).unwrap();
        gawdfn::verify_undeploy_receipt(&rebound).unwrap();
        assert_eq!(rebound.payload.deployment, first.payload.deployment);
        assert_eq!(rebound.payload.executor, first.payload.executor);
        assert_eq!(rebound.payload.executor_creature, "17");
        assert!(
            reopened
                .deployments(&DeploymentQueryV1 {
                    function: None,
                    realm: Some("realm-a".into()),
                    node: Some("node-a".into()),
                    limit: 8,
                })
                .unwrap()
                .deployments
                .is_empty(),
            "re-attestation does not resurrect the tombstoned deployment"
        );
    }

    #[test]
    fn unloaded_target_is_omitted_and_durably_refused_before_call() {
        let fixture = Fixture::new("target-unloaded");
        let executor = fixture.open_with_liveness(Arc::new(SequenceLiveness::new([
            Ok(true),
            Ok(false),
            Ok(false),
        ])));
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        assert!(
            executor
                .deployments(&DeploymentQueryV1 {
                    function: Some(fixture.function.clone()),
                    realm: Some("realm-a".into()),
                    node: Some("node-a".into()),
                    limit: 8,
                })
                .unwrap()
                .deployments
                .is_empty(),
            "lookup must not advertise an identity-stale durable row as active"
        );
        let grant = fixture.grant(deployment, "job-unloaded", DeliveryModeV1::AtMostOnce);
        let ClaimOutcome::Terminal { receipt } = executor.claim(grant.clone()).unwrap() else {
            panic!("an unloaded target produces a durable terminal refusal")
        };
        gawdfn::verify_execution_receipt(&receipt, &grant).unwrap();
        assert_eq!(receipt.payload.sequence, 1);
        assert!(matches!(
            &receipt.payload.stage,
            ExecutionStageV1::Failed {
                error: gawdfn::ValueRefV1::Inline { value },
                retryable: true,
            } if value["kind"] == "deployment_target_unavailable"
                && value["execution_may_have_occurred"] == false
        ));
        assert_eq!(executor.latest(&grant.payload.attempt).unwrap(), receipt);
        drop(executor);
        let recovered =
            fixture.open_with_liveness(Arc::new(SequenceLiveness::new(std::iter::empty::<
                Result<bool, String>,
            >())));
        assert!(matches!(
            recovered.claim(grant).unwrap(),
            ClaimOutcome::Terminal { receipt: replayed } if replayed == receipt
        ));
    }

    #[test]
    fn missing_liveness_provider_fails_closed() {
        let fixture = Fixture::new("liveness-refusal");
        let executor = FunctionExecutor::open(
            fixture.config(),
            fixture.executor.clone(),
            Arc::new(StringAddressing),
            Arc::new(AllowAdmission),
        )
        .unwrap();
        assert!(matches!(
            executor.register(fixture.registration("realm-a", Some("node-a"))),
            Err(ExecutorError::Liveness(reason)) if reason.contains("not configured")
        ));
    }

    #[test]
    fn claimed_replay_rechecks_liveness_before_the_first_call() {
        let fixture = Fixture::new("claimed-liveness-replay");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-replay", DeliveryModeV1::AtMostOnce);
        let claimed = executor.sign_receipt(&grant, 1, None, ExecutionStageV1::Claimed).unwrap();
        let record =
            ExecutorLedgerRecord::Claim { grant: Box::new(grant.clone()), receipt: claimed };
        validate_record(&executor.config, executor.signer.public_key(), &record).unwrap();
        executor.journal.append(record).unwrap();
        drop(executor); // crash after Claim fsync, before the Started/call gate

        let recovered = fixture.open_with_liveness(Arc::new(SequenceLiveness::new([Ok(true)])));
        let recovery = recovered.recovery_dispatches();
        assert_eq!(recovery.dispatches.len(), 3);
        let stages = recovery.dispatches[..2]
            .iter()
            .map(|dispatch| {
                let message: ExecuteMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
                let ExecuteMessageV1::Receipt { receipt } = message else {
                    panic!("Claimed resume emits receipts before the call")
                };
                receipt.payload.stage
            })
            .collect::<Vec<_>>();
        assert_eq!(stages, vec![ExecutionStageV1::Claimed, ExecutionStageV1::Started]);
        assert_eq!(recovery.dispatches[2].schema, SCHEMA_CALL_V1);

        // Once Started is durable, an exact grant replay returns the receipt and never consults
        // liveness or emits another call.
        assert!(matches!(recovered.claim(grant).unwrap(), ClaimOutcome::Duplicate { .. }));
    }

    #[test]
    fn claimed_startup_resume_refuses_a_reused_target_without_emitting_a_call() {
        let fixture = Fixture::new("claimed-reused-target");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-reused-resume", DeliveryModeV1::AtMostOnce);
        let claimed = executor.sign_receipt(&grant, 1, None, ExecutionStageV1::Claimed).unwrap();
        let record = ExecutorLedgerRecord::Claim {
            grant: Box::new(grant.clone()),
            receipt: claimed.clone(),
        };
        validate_record(&executor.config, executor.signer.public_key(), &record).unwrap();
        executor.journal.append(record).unwrap();
        drop(executor);

        let recovered = fixture.open_with_liveness(Arc::new(SequenceLiveness::new([Ok(false)])));
        let recovery = recovered.recovery_dispatches();
        assert_eq!(recovery.dispatches.len(), 2);
        assert!(recovery.dispatches.iter().all(|dispatch| dispatch.schema == SCHEMA_EXECUTE_V1));
        let messages = recovery
            .dispatches
            .iter()
            .map(|dispatch| serde_json::from_slice::<ExecuteMessageV1>(&dispatch.payload).unwrap())
            .collect::<Vec<_>>();
        assert!(matches!(
            &messages[0],
            ExecuteMessageV1::Receipt { receipt } if **receipt == claimed
        ));
        assert!(matches!(
            &messages[1],
            ExecuteMessageV1::Receipt { receipt }
                if matches!(receipt.payload.stage, ExecutionStageV1::Failed { .. })
        ));
    }

    #[test]
    fn claim_deduplicates_exact_grant_and_rejects_changed_body() {
        let fixture = Fixture::new("claim-dedup");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-a", DeliveryModeV1::AtMostOnce);
        let ClaimOutcome::Claimed { receipts, .. } = executor.claim(grant.clone()).unwrap() else {
            panic!("first grant claims");
        };
        assert_eq!(receipts.len(), 2);
        assert!(matches!(executor.claim(grant.clone()).unwrap(), ClaimOutcome::Duplicate { .. }));
        let mut changed = grant.payload.clone();
        changed.grant_sequence += 1;
        let changed =
            SignedRecordV1::sign(SCHEMA_EXECUTE_V1, changed, fixture.operational.as_ref()).unwrap();
        assert!(matches!(executor.claim(changed), Err(ExecutorError::Conflict(_))));
    }

    #[test]
    fn restart_classifies_started_attempt_by_delivery_mode() {
        let fixture = Fixture::new("restart");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let at_most = fixture.grant(deployment.clone(), "job-at-most", DeliveryModeV1::AtMostOnce);
        let at_most_attempt = at_most.payload.attempt.clone();
        executor.claim(at_most).unwrap();
        drop(executor);
        let executor = fixture.open();
        assert!(matches!(
            executor.latest(&at_most_attempt).unwrap().payload.stage,
            ExecutionStageV1::Indeterminate { .. }
        ));
        let at_least = fixture.grant(
            deployment,
            "job-at-least",
            DeliveryModeV1::AtLeastOnce { max_attempts: 2 },
        );
        let at_least_attempt = at_least.payload.attempt.clone();
        executor.claim(at_least).unwrap();
        drop(executor);
        let executor = fixture.open();
        assert!(matches!(
            executor.latest(&at_least_attempt).unwrap().payload.stage,
            ExecutionStageV1::Failed { retryable: true, .. }
        ));
    }

    #[test]
    fn recovered_home_epoch_fence_rejects_stale_grants() {
        let fixture = Fixture::new("epoch-fence");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        executor
            .claim(fixture.grant(deployment.clone(), "job-epoch-one", DeliveryModeV1::AtMostOnce))
            .unwrap();
        let next_operational = Ed25519SeedSigner::from_seed([25; 32]).unwrap();
        let mut next_authority = authority(
            fixture.owner.as_ref(),
            &next_operational,
            HomeId::new(fixture.owner.public_key()),
            2,
        );
        let home = HomeId::new(fixture.owner.public_key());
        let checkpoint = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            HomeCheckpointV1 {
                home: home.clone(),
                epoch: 1,
                high_water_mark: 1,
                log_root: hash('d'),
                state: BlobRefV1 {
                    digest: hash('e'),
                    size: 1,
                    media_type: "application/octet-stream".into(),
                },
                created_at_unix_ms: None,
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        let custody_grant = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyGrantV1 {
                home,
                handoff: HandoffId::new("executor-epoch-fence"),
                from_epoch: 1,
                to_epoch: 2,
                source_authority: fixture.authority.clone(),
                source_realm: "realm-a".into(),
                source_node: "home-node".into(),
                destination_realm: "realm-a".into(),
                destination_node: "home-node".into(),
                checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
                source_log_root: checkpoint.payload.log_root.clone(),
                destination_operational_key: next_authority.operational.clone(),
                evidence: vec![],
                issued_at_unix_ms: None,
                destination_rewrap: None,
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let prepared = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyPreparedV1 {
                grant_hash: canonical_hash(&custody_grant).unwrap(),
                checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
                source_log_root: checkpoint.payload.log_root.clone(),
                source_coordinator: "7".into(),
                grant: Box::new(custody_grant),
                checkpoint: Box::new(checkpoint),
                rewrap_inventory_hash: None,
                rewrap_item_count: None,
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        next_authority.prepared = Some(Box::new(prepared));
        executor
            .claim(fixture.grant_with_authority(
                deployment.clone(),
                "job-epoch-two",
                DeliveryModeV1::AtMostOnce,
                next_authority,
                &next_operational,
                2,
            ))
            .unwrap();
        drop(executor);
        let recovered = fixture.open();
        let stale = fixture.grant(deployment, "job-stale", DeliveryModeV1::AtMostOnce);
        assert!(matches!(recovered.claim(stale), Err(ExecutorError::Unauthorized(_))));
    }

    #[test]
    fn same_epoch_newer_grant_route_receives_refusal_and_claim_receipts() {
        use aether::Header;

        let fixture = Fixture::new("same-epoch-grant-route");
        let mut executor = fixture.open_with_liveness(Arc::new(SequenceLiveness::new([
            Ok(true), // registration
            Ok(true),
            Ok(true),  // route-one seed claim
            Ok(false), // route-two refusal
            Ok(true),
            Ok(true), // route-three claim and Started gate
        ])));
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        executor
            .claim(fixture.grant(deployment.clone(), "route-one-seed", DeliveryModeV1::AtMostOnce))
            .unwrap();

        let grant_at = |job: &str, route_sequence: u64, coordinator: &str| {
            let mut payload =
                fixture.grant(deployment.clone(), job, DeliveryModeV1::AtMostOnce).payload;
            payload.home_route_sequence = route_sequence;
            payload.home_coordinator = coordinator.into();
            SignedRecordV1::sign(SCHEMA_EXECUTE_V1, payload, fixture.operational.as_ref()).unwrap()
        };
        let envelope = |grant| Envelope {
            header: Header {
                from: Address::Creature(CreatureId(7)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_EXECUTE_V1.into(),
                origin: None,
            },
            payload: aether::wire::to_bytes(&ExecuteMessageV1::Grant { grant: Box::new(grant) }),
        };

        let refused = executor.handle(envelope(grant_at("route-two", 2, "8")));
        assert_eq!(refused.dispatches.len(), 1);
        assert_eq!(
            refused.dispatches[0].to,
            Address::Node(NodeId("home-node".into()), CreatureId(8))
        );
        let refusal: ExecuteMessageV1 =
            serde_json::from_slice(&refused.dispatches[0].payload).unwrap();
        assert!(matches!(
            refusal,
            ExecuteMessageV1::Receipt { receipt }
                if matches!(receipt.payload.stage, ExecutionStageV1::Failed { .. })
        ));

        let claimed = executor.handle(envelope(grant_at("route-three", 3, "9")));
        assert_eq!(claimed.dispatches.len(), 3);
        assert!(claimed.dispatches[..2].iter().all(|dispatch| {
            dispatch.schema == SCHEMA_EXECUTE_V1
                && dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(9))
        }));
        assert_eq!(claimed.dispatches[2].schema, SCHEMA_CALL_V1);
        assert_eq!(claimed.dispatches[2].to, Address::Creature(CreatureId(11)));
        let stages = claimed.dispatches[..2]
            .iter()
            .map(|dispatch| {
                let message: ExecuteMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
                let ExecuteMessageV1::Receipt { receipt } = message else {
                    panic!("claim dispatches begin with executor receipts")
                };
                receipt.payload.stage
            })
            .collect::<Vec<_>>();
        assert_eq!(stages, vec![ExecutionStageV1::Claimed, ExecutionStageV1::Started]);

        let state = executor.state.lock().unwrap_or_else(|poison| poison.into_inner());
        let fence = state.home_fences.get(&HomeId::new(fixture.owner.public_key())).unwrap();
        assert_eq!((fence.epoch, fence.route_sequence), (1, 3));
        assert_eq!(fence.home_coordinator, "9");
    }

    #[test]
    fn moved_home_reendorses_one_accepted_pending_control_and_fences_stale_replay() {
        let fixture = Fixture::new("moved-pending-control");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-moved-control", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let accepted = fixture.control(
            &grant,
            "move-control",
            3,
            JobControlKindV1::Steer { value: ValueRefV1::Inline { value: json!({"speed": 2}) } },
        );
        let RecordOutcome::Recorded(queued) =
            executor.record_control_queued(&attempt, accepted.clone()).unwrap()
        else {
            panic!("epoch-one control is durably queued")
        };

        let next_operational = Ed25519SeedSigner::from_seed([26; 32]).unwrap();
        let next_authority = moved_authority(&fixture, &next_operational, "pending-control-move");
        let mut continued = accepted.payload.clone();
        continued.home_epoch = 2;
        continued.home_realm = "realm-a".into();
        continued.home_node = "home-node".into();
        continued.home_coordinator = "8".into();
        continued.authority = next_authority;
        let continued =
            SignedRecordV1::sign(SCHEMA_EXECUTE_V1, continued, &next_operational).unwrap();
        gawdfn::verify_execution_control(&continued).unwrap();
        assert_eq!(
            continued.payload.accepted_event, accepted.payload.accepted_event,
            "the moved Home continues the exact old durable acceptance proof"
        );
        assert!(matches!(
            executor.record_control_queued(&attempt, continued.clone()).unwrap(),
            RecordOutcome::Duplicate(receipt) if receipt == queued
        ));
        assert!(matches!(
            executor.record_control_queued(&attempt, accepted.clone()),
            Err(ExecutorError::Unauthorized(_))
        ));
        {
            let state = executor.state.lock().unwrap_or_else(|p| p.into_inner());
            assert_eq!(state.home_fences.get(&attempt.home).unwrap().epoch, 2);
            assert_eq!(state.attempts.get(&attempt_key(&attempt)).unwrap().control_count, 1);
        }
        drop(executor);

        let recovered = fixture.open();
        assert!(matches!(
            recovered.record_control_queued(&attempt, accepted),
            Err(ExecutorError::Unauthorized(_))
        ));
        let replay = recovered.recovery_dispatches();
        assert_eq!(replay.dispatches.len(), 4);
        assert!(replay.dispatches.iter().all(|dispatch| {
            dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(8))
                && dispatch.schema == SCHEMA_EXECUTE_V1
        }));
        let receipts = replay
            .dispatches
            .iter()
            .map(|dispatch| {
                let message: ExecuteMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
                let ExecuteMessageV1::Receipt { receipt } = message else {
                    panic!("restart recovery emits only durable receipt history")
                };
                *receipt
            })
            .collect::<Vec<_>>();
        assert_eq!(
            receipts.iter().map(|receipt| receipt.payload.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3, 4]
        );
        assert_eq!(receipts[2], queued);
        assert!(matches!(receipts[3].payload.stage, ExecutionStageV1::Indeterminate { .. }));
    }

    #[test]
    fn uncertain_moved_control_append_blocks_stale_duplicate_until_reopen_recovers_fence() {
        use aether::Header;
        use function_home::{inject_durability_fault, DurabilityFaultPoint};

        let fixture = Fixture::new("moved-control-uncertain");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-moved-uncertain", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let accepted = fixture.control(
            &grant,
            "uncertain-move",
            3,
            JobControlKindV1::Steer { value: ValueRefV1::Inline { value: json!({"speed": 2}) } },
        );
        executor.record_control_queued(&attempt, accepted.clone()).unwrap();

        let next_operational = Ed25519SeedSigner::from_seed([27; 32]).unwrap();
        let mut moved = accepted.payload.clone();
        moved.home_epoch = 2;
        moved.home_route_sequence = 2;
        moved.home_coordinator = "8".into();
        moved.authority = moved_authority(&fixture, &next_operational, "uncertain-control-move");
        let moved = SignedRecordV1::sign(SCHEMA_EXECUTE_V1, moved, &next_operational).unwrap();

        let fault = inject_durability_fault(DurabilityFaultPoint::AfterLogSync, 0);
        assert!(matches!(
            executor.record_control_queued(&attempt, moved),
            Err(ExecutorError::Journal(JournalError::Io(_)))
        ));
        drop(fault);
        assert!(matches!(
            executor.record_control_queued(&attempt, accepted.clone()),
            Err(ExecutorError::Journal(JournalError::Uncertain))
        ));
        assert!(matches!(
            executor.latest(&attempt),
            Err(ExecutorError::Journal(JournalError::Uncertain))
        ));
        assert!(matches!(
            executor.deployments(&DeploymentQueryV1 {
                function: None,
                realm: None,
                node: None,
                limit: 1,
            }),
            Err(ExecutorError::Journal(JournalError::Uncertain))
        ));
        assert!(executor.recovery_dispatches().dispatches.is_empty());
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(7)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_EXECUTE_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        assert!(executor.on_control(&env, accepted.clone()).dispatches.is_empty());
        drop(executor);

        let reopened = fixture.open();
        {
            let state = reopened.state.lock().unwrap_or_else(|poison| poison.into_inner());
            let fence = state.home_fences.get(&attempt.home).unwrap();
            assert_eq!((fence.epoch, fence.route_sequence), (2, 2));
        }
        assert!(matches!(
            reopened.record_control_queued(&attempt, accepted),
            Err(ExecutorError::Unauthorized(_))
        ));
        let recovery = reopened.recovery_dispatches();
        assert!(recovery.dispatches.iter().all(|dispatch| {
            dispatch.schema == SCHEMA_EXECUTE_V1
                && dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(8))
        }));
    }

    #[test]
    fn moved_home_query_rebinds_all_later_and_restart_receipts_without_route_rollback() {
        use aether::Header;

        let fixture = Fixture::new("moved-result-route");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-moved-result", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();

        let next_operational = Ed25519SeedSigner::from_seed([28; 32]).unwrap();
        let next_authority = moved_authority(&fixture, &next_operational, "result-route-move");
        let query_for = |route_sequence, coordinator: &str, id: &str| {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionQueryV1 {
                    attempt: attempt.clone(),
                    grant_hash: canonical_hash(&grant).unwrap(),
                    home_epoch: 2,
                    home_route_sequence: route_sequence,
                    home_realm: "realm-a".into(),
                    home_node: "home-node".into(),
                    home_coordinator: coordinator.into(),
                    authority: next_authority.clone(),
                    query: ControlId::new(id),
                },
                &next_operational,
            )
            .unwrap()
        };
        let (_, query_target) = executor.query(query_for(2, "8", "move-current")).unwrap();
        assert_eq!(query_target, Address::Node(NodeId("home-node".into()), CreatureId(8)));
        assert!(matches!(
            executor.query(query_for(1, "8", "move-stale")),
            Err(ExecutorError::Unauthorized(_))
        ));
        assert!(matches!(
            executor.query(query_for(2, "7", "move-divergent")),
            Err(ExecutorError::Unauthorized(_))
        ));

        let target = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        let (_, result_target) = executor
            .result(
                &target,
                FunctionResultV1 {
                    attempt: attempt.clone(),
                    outcome: Ok(ValueRefV1::Inline { value: json!({"done": true}) }),
                },
            )
            .unwrap();
        assert_eq!(result_target, Address::Node(NodeId("home-node".into()), CreatureId(8)));
        drop(executor);

        let reopened = fixture.open();
        let recovery = reopened.recovery_dispatches();
        assert!(!recovery.dispatches.is_empty());
        assert!(recovery.dispatches.iter().all(|dispatch| {
            dispatch.schema == SCHEMA_EXECUTE_V1
                && dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(8))
        }));
        let sequences = recovery
            .dispatches
            .iter()
            .map(|dispatch| {
                let message: ExecuteMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
                let ExecuteMessageV1::Receipt { receipt } = message else {
                    panic!("terminal restart recovery is receipt-only")
                };
                receipt.payload.sequence
            })
            .collect::<Vec<_>>();
        assert!(sequences.windows(2).all(|pair| pair[0] < pair[1]));
    }

    #[test]
    fn progress_sequences_and_control_ids_are_deduplicated() {
        let fixture = Fixture::new("progress-control-dedup");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-controls", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();

        let progress = ExecutionStageV1::Progress {
            sequence: 2,
            progress: ValueRefV1::Inline { value: json!({"step": 2}) },
        };
        assert!(matches!(
            executor.record_stage(&attempt, progress.clone(), None).unwrap(),
            RecordOutcome::Recorded(_)
        ));
        assert!(matches!(
            executor.record_stage(&attempt, progress, None).unwrap(),
            RecordOutcome::Duplicate(_)
        ));
        assert!(matches!(
            executor.record_stage(
                &attempt,
                ExecutionStageV1::Progress {
                    sequence: 1,
                    progress: ValueRefV1::Inline { value: json!({"step": 1}) },
                },
                None,
            ),
            Err(ExecutorError::Conflict(_))
        ));

        let endorsed = fixture.control(
            &grant,
            "control-a",
            1,
            JobControlKindV1::Steer { value: ValueRefV1::Inline { value: json!({"speed": 1}) } },
        );
        assert!(matches!(
            executor.record_control_queued(&attempt, endorsed.clone()).unwrap(),
            RecordOutcome::Recorded(_)
        ));
        assert!(matches!(
            executor.record_control_queued(&attempt, endorsed).unwrap(),
            RecordOutcome::Duplicate(_)
        ));

        let changed = fixture.control(
            &grant,
            "control-a",
            2,
            JobControlKindV1::Steer { value: ValueRefV1::Inline { value: json!({"speed": 2}) } },
        );
        assert!(matches!(
            executor.record_control_queued(&attempt, changed),
            Err(ExecutorError::Conflict(_))
        ));
    }

    #[test]
    fn observation_cap_and_indexes_survive_restart_while_terminal_capacity_is_reserved() {
        let fixture = Fixture::new("observation-cap");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-observations", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant).unwrap();

        for sequence in 1..=MAX_ATTEMPT_OBSERVATIONS as u64 {
            assert!(matches!(
                executor
                    .record_stage(
                        &attempt,
                        ExecutionStageV1::Progress {
                            sequence,
                            progress: ValueRefV1::Inline { value: json!({"step": sequence}) },
                        },
                        None,
                    )
                    .unwrap(),
                RecordOutcome::Recorded(_)
            ));
        }
        assert!(matches!(
            executor.record_stage(
                &attempt,
                ExecutionStageV1::Progress {
                    sequence: MAX_ATTEMPT_OBSERVATIONS as u64 + 1,
                    progress: ValueRefV1::Inline { value: json!({"overflow": true}) },
                },
                None,
            ),
            Err(ExecutorError::Capacity)
        ));
        assert!(matches!(
            executor
                .record_stage(
                    &attempt,
                    ExecutionStageV1::Progress {
                        sequence: MAX_ATTEMPT_OBSERVATIONS as u64,
                        progress: ValueRefV1::Inline {
                            value: json!({"step": MAX_ATTEMPT_OBSERVATIONS as u64}),
                        },
                    },
                    None,
                )
                .unwrap(),
            RecordOutcome::Duplicate(_)
        ));
        assert!(matches!(
            executor.record_stage(
                &attempt,
                ExecutionStageV1::Checkpoint {
                    sequence: 1,
                    checkpoint: ValueRefV1::Inline { value: json!({"too_late": true}) },
                },
                None,
            ),
            Err(ExecutorError::Capacity)
        ));
        assert!(matches!(
            executor
                .record_stage(
                    &attempt,
                    ExecutionStageV1::Succeeded {
                        result: ValueRefV1::Inline { value: json!({"done": true}) },
                    },
                    None,
                )
                .unwrap(),
            RecordOutcome::Recorded(_)
        ));
        drop(executor);
        let recovered = fixture.open();
        let state = recovered.state.lock().unwrap_or_else(|poison| poison.into_inner());
        let recovered_attempt = state.attempts.get(&attempt_key(&attempt)).unwrap();
        assert_eq!(recovered_attempt.observation_count, MAX_ATTEMPT_OBSERVATIONS);
        assert_eq!(recovered_attempt.highest_progress_sequence, MAX_ATTEMPT_OBSERVATIONS as u64);
        assert_eq!(recovered_attempt.progress_receipts.len(), MAX_ATTEMPT_OBSERVATIONS);
        assert!(matches!(
            recovered_attempt.receipts.last().unwrap().payload.stage,
            ExecutionStageV1::Succeeded { .. }
        ));
    }

    #[test]
    fn journal_capacity_reserves_terminal_and_control_ack_slots_across_reopen() {
        let fixture = Fixture::new("journal-reservations");
        let mut config = fixture.config();
        config.journal_caps.max_records = 8;
        let open = || {
            FunctionExecutor::open_with_liveness(
                config.clone(),
                fixture.executor.clone(),
                Arc::new(StringAddressing),
                Arc::new(AllowAdmission),
                Arc::new(AlwaysLive),
            )
            .unwrap()
        };
        let executor = open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-reserved", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let control_id = ControlId::new("reserved-ack");
        executor
            .record_control_queued(
                &attempt,
                fixture.control(
                    &grant,
                    control_id.as_str(),
                    3,
                    JobControlKindV1::Steer {
                        value: ValueRefV1::Inline { value: json!({"speed": 1}) },
                    },
                ),
            )
            .unwrap();
        for sequence in 1..=2 {
            executor
                .record_stage(
                    &attempt,
                    ExecutionStageV1::Progress {
                        sequence,
                        progress: ValueRefV1::Inline { value: json!({"step": sequence}) },
                    },
                    None,
                )
                .unwrap();
        }
        assert!(matches!(
            executor.record_stage(
                &attempt,
                ExecutionStageV1::Progress {
                    sequence: 3,
                    progress: ValueRefV1::Inline { value: json!({"step": 3}) },
                },
                None,
            ),
            Err(ExecutorError::Capacity)
        ));
        executor
            .record_stage(
                &attempt,
                ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value: json!({"done": true}) },
                },
                None,
            )
            .unwrap();
        executor
            .record_stage(
                &attempt,
                ExecutionStageV1::ControlAcknowledged {
                    control: control_id,
                    disposition: ControlDispositionV1::Applied,
                    detail: None,
                },
                None,
            )
            .unwrap();
        assert_eq!(executor.journal.remaining_records().unwrap(), 0);
        {
            let state = executor.state.lock().unwrap_or_else(|poison| poison.into_inner());
            assert_eq!((state.nonterminal_attempts, state.unacknowledged_controls), (0, 0));
            validate_reservation_counters(&state).unwrap();
        }
        drop(executor);

        let reopened = open();
        assert_eq!(reopened.journal.remaining_records().unwrap(), 0);
        let recovery = reopened.recovery_dispatches();
        assert_eq!(recovery.dispatches.len(), 7);
        let sequences = recovery
            .dispatches
            .iter()
            .map(|dispatch| {
                let message: ExecuteMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
                let ExecuteMessageV1::Receipt { receipt } = message else {
                    panic!("full terminal history replays durable receipts only")
                };
                receipt.payload.sequence
            })
            .collect::<Vec<_>>();
        assert_eq!(sequences, (1..=7).collect::<Vec<_>>());
        let next_operational = Ed25519SeedSigner::from_seed([36; 32]).unwrap();
        let query = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionQueryV1 {
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                home_epoch: 2,
                home_route_sequence: 2,
                home_realm: "realm-a".into(),
                home_node: "home-node".into(),
                home_coordinator: "8".into(),
                authority: moved_authority(&fixture, &next_operational, "full-reservation-pull"),
                query: ControlId::new("full-reservation-pull"),
            },
            &next_operational,
        )
        .unwrap();
        assert!(matches!(reopened.query(query), Err(ExecutorError::Capacity)));
    }

    #[test]
    fn reopen_rejects_a_cap_below_recovered_durable_reservations() {
        let fixture = Fixture::new("journal-reservation-shrink");
        let open = |max_records| {
            let mut config = fixture.config();
            config.journal_caps.max_records = max_records;
            FunctionExecutor::open_with_liveness(
                config,
                fixture.executor.clone(),
                Arc::new(StringAddressing),
                Arc::new(AllowAdmission),
                Arc::new(AlwaysLive),
            )
        };
        let executor = open(10).unwrap();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-cap-shrink", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        executor
            .record_control_queued(
                &attempt,
                fixture.control(
                    &grant,
                    "cap-shrink-pending",
                    3,
                    JobControlKindV1::Cancel { reason: "stop".into() },
                ),
            )
            .unwrap();
        assert_eq!(executor.journal.remaining_records().unwrap(), 6);
        drop(executor);

        assert!(matches!(open(5), Err(ExecutorError::Capacity)));
        let recovered = open(6).unwrap();
        assert_eq!(recovered.journal.remaining_records().unwrap(), 1);
        let state = recovered.state.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!((state.nonterminal_attempts, state.unacknowledged_controls), (0, 1));
        validate_reservation_counters(&state).unwrap();
    }

    #[test]
    fn full_terminal_journal_requires_capacity_before_persisting_a_new_query_route() {
        let fixture = Fixture::new("full-terminal-query-route");
        let open = |max_records| {
            let mut config = fixture.config();
            config.journal_caps.max_records = max_records;
            FunctionExecutor::open_with_liveness(
                config,
                fixture.executor.clone(),
                Arc::new(StringAddressing),
                Arc::new(AllowAdmission),
                Arc::new(AlwaysLive),
            )
            .unwrap()
        };
        let executor = open(4);
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-full-query", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let RecordOutcome::Recorded(terminal) = executor
            .record_stage(
                &attempt,
                ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value: json!({"done": true}) },
                },
                None,
            )
            .unwrap()
        else {
            panic!("terminal result consumes the attempt's reserved record")
        };
        assert_eq!(executor.journal.remaining_records().unwrap(), 0);
        drop(executor); // terminal callback may have been lost before reaching the moved Home

        let reopened = open(4);
        assert_eq!(reopened.recovery_dispatches().dispatches.len(), 3);
        let next_operational = Ed25519SeedSigner::from_seed([30; 32]).unwrap();
        let request = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionQueryV1 {
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                home_epoch: 2,
                home_route_sequence: 2,
                home_realm: "realm-a".into(),
                home_node: "home-node".into(),
                home_coordinator: "8".into(),
                authority: moved_authority(&fixture, &next_operational, "full-query-move"),
                query: ControlId::new("recover-full-terminal"),
            },
            &next_operational,
        )
        .unwrap();
        assert!(matches!(reopened.query(request.clone()), Err(ExecutorError::Capacity)));
        assert_eq!(reopened.journal.remaining_records().unwrap(), 0);
        {
            let state = reopened.state.lock().unwrap_or_else(|poison| poison.into_inner());
            let fence = state.home_fences.get(&attempt.home).unwrap();
            assert_eq!((fence.epoch, fence.route_sequence), (1, 1));
        }
        drop(reopened);

        let expanded = open(5);
        let (recovered, target) = expanded.query(request.clone()).unwrap();
        assert_eq!(recovered, terminal);
        assert_eq!(target, Address::Node(NodeId("home-node".into()), CreatureId(8)));
        assert_eq!(expanded.journal.remaining_records().unwrap(), 0);
        let recovery = expanded.recovery_dispatches();
        assert_eq!(recovery.dispatches.len(), 3);
        assert!(recovery.dispatches.iter().all(|dispatch| {
            dispatch.schema == SCHEMA_EXECUTE_V1
                && dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(8))
        }));
        drop(expanded);

        let restarted_again = open(5);
        let restarted_recovery = restarted_again.recovery_dispatches();
        assert_eq!(restarted_recovery.dispatches.len(), 3);
        assert!(restarted_recovery.dispatches.iter().all(|dispatch| {
            dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(8))
        }));
        let (replayed, replay_target) = restarted_again.query(request).unwrap();
        assert_eq!(replayed, terminal);
        assert_eq!(replay_target, target);
    }

    #[test]
    fn exact_cap_query_stays_blocked_after_same_home_callbacks_consume_the_last_slot() {
        let fixture = Fixture::new("same-home-query-reservation");
        let mut config = fixture.config();
        config.journal_caps.max_records = 7;
        let open = || {
            FunctionExecutor::open_with_liveness(
                config.clone(),
                fixture.executor.clone(),
                Arc::new(StringAddressing),
                Arc::new(AllowAdmission),
                Arc::new(AlwaysLive),
            )
            .unwrap()
        };
        let executor = open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let terminal_grant =
            fixture.grant(deployment.clone(), "job-terminal-query", DeliveryModeV1::AtMostOnce);
        let terminal_attempt = terminal_grant.payload.attempt.clone();
        executor.claim(terminal_grant.clone()).unwrap();
        let RecordOutcome::Recorded(terminal_receipt) = executor
            .record_stage(
                &terminal_attempt,
                ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value: json!({"done": "a"}) },
                },
                None,
            )
            .unwrap()
        else {
            panic!("first attempt becomes terminal")
        };
        let pending_grant =
            fixture.grant(deployment, "job-pending-same-home", DeliveryModeV1::AtMostOnce);
        let pending_attempt = pending_grant.payload.attempt.clone();
        executor.claim(pending_grant).unwrap();
        assert_eq!(executor.journal.remaining_records().unwrap(), 1);

        let next_operational = Ed25519SeedSigner::from_seed([32; 32]).unwrap();
        let request = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionQueryV1 {
                attempt: terminal_attempt.clone(),
                grant_hash: canonical_hash(&terminal_grant).unwrap(),
                home_epoch: 2,
                home_route_sequence: 2,
                home_realm: "realm-a".into(),
                home_node: "home-node".into(),
                home_coordinator: "8".into(),
                authority: moved_authority(&fixture, &next_operational, "same-home-query-move"),
                query: ControlId::new("same-home-capacity"),
            },
            &next_operational,
        )
        .unwrap();
        assert!(matches!(executor.query(request.clone()), Err(ExecutorError::Capacity)));
        assert_eq!(executor.journal.remaining_records().unwrap(), 1);

        executor
            .record_stage(
                &pending_attempt,
                ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value: json!({"done": "b"}) },
                },
                None,
            )
            .unwrap();
        assert_eq!(executor.journal.remaining_records().unwrap(), 0);
        assert!(matches!(executor.query(request.clone()), Err(ExecutorError::Capacity)));
        assert_eq!(executor.latest(&terminal_attempt).unwrap(), terminal_receipt);
        {
            let state = executor.state.lock().unwrap_or_else(|poison| poison.into_inner());
            let fence = state.home_fences.get(&terminal_attempt.home).unwrap();
            assert_eq!((fence.epoch, fence.route_sequence), (1, 1));
        }
        drop(executor);

        let reopened = open();
        assert_eq!(reopened.recovery_dispatches().dispatches.len(), 6);
        assert!(matches!(reopened.query(request), Err(ExecutorError::Capacity)));
        assert_eq!(reopened.journal.remaining_records().unwrap(), 0);
    }

    #[test]
    fn another_home_reservation_still_protects_the_global_route_append_capacity() {
        let fixture = Fixture::new("other-home-query-reservation");
        let mut config = fixture.config();
        config.journal_caps.max_records = 7;
        let executor = FunctionExecutor::open_with_liveness(
            config,
            fixture.executor.clone(),
            Arc::new(StringAddressing),
            Arc::new(AllowAdmission),
            Arc::new(AlwaysLive),
        )
        .unwrap();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let terminal_grant =
            fixture.grant(deployment.clone(), "job-home-a-terminal", DeliveryModeV1::AtMostOnce);
        let terminal_attempt = terminal_grant.payload.attempt.clone();
        executor.claim(terminal_grant.clone()).unwrap();
        executor
            .record_stage(
                &terminal_attempt,
                ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value: json!({"done": true}) },
                },
                None,
            )
            .unwrap();

        let other_owner = Ed25519SeedSigner::from_seed([33; 32]).unwrap();
        let other_operational = Ed25519SeedSigner::from_seed([34; 32]).unwrap();
        let other_home = HomeId::new(other_owner.public_key());
        let mut other_payload =
            fixture.grant(deployment, "job-home-b-pending", DeliveryModeV1::AtMostOnce).payload;
        other_payload.attempt.home = other_home.clone();
        other_payload.owner = other_home.clone();
        other_payload.authority =
            authority(&other_owner, &other_operational, other_home.clone(), 1);
        other_payload.home_coordinator = "17".into();
        let other_grant =
            SignedRecordV1::sign(SCHEMA_EXECUTE_V1, other_payload, &other_operational).unwrap();
        executor.claim(other_grant).unwrap();
        assert_eq!(executor.journal.remaining_records().unwrap(), 1);

        let next_operational = Ed25519SeedSigner::from_seed([35; 32]).unwrap();
        let request = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionQueryV1 {
                attempt: terminal_attempt.clone(),
                grant_hash: canonical_hash(&terminal_grant).unwrap(),
                home_epoch: 2,
                home_route_sequence: 2,
                home_realm: "realm-a".into(),
                home_node: "home-node".into(),
                home_coordinator: "8".into(),
                authority: moved_authority(&fixture, &next_operational, "other-home-query-move"),
                query: ControlId::new("other-home-capacity"),
            },
            &next_operational,
        )
        .unwrap();
        assert!(matches!(executor.query(request), Err(ExecutorError::Capacity)));
        assert_eq!(executor.journal.remaining_records().unwrap(), 1);
        let state = executor.state.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!((state.nonterminal_attempts, state.unacknowledged_controls), (1, 0));
        assert!(state.home_fences.contains_key(&other_home));
    }

    #[test]
    fn unique_control_cap_recovers_accepts_exact_retries_and_records_acknowledgments() {
        let fixture = Fixture::new("control-cap");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-control-cap", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let request_for = |index: usize| {
            fixture.control(
                &grant,
                format!("control-{index}"),
                index as u64 + 1,
                JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"value": index}) },
                },
            )
        };
        let mut retained = None;
        for index in 0..MAX_JOB_CONTROLS {
            let request = request_for(index);
            executor.record_control_queued(&attempt, request.clone()).unwrap();
            if index + 1 == MAX_JOB_CONTROLS {
                retained = Some(request);
            }
        }
        let retained = retained.unwrap();
        assert!(matches!(
            executor.record_control_queued(&attempt, retained.clone()).unwrap(),
            RecordOutcome::Duplicate(_)
        ));
        assert!(matches!(
            executor.record_control_queued(&attempt, request_for(MAX_JOB_CONTROLS)),
            Err(ExecutorError::Capacity)
        ));
        let control = retained.payload.caller_request.payload.control.clone();
        let acknowledgment = match executor
            .record_stage(
                &attempt,
                ExecutionStageV1::ControlAcknowledged {
                    control: control.clone(),
                    disposition: ControlDispositionV1::Applied,
                    detail: None,
                },
                None,
            )
            .unwrap()
        {
            RecordOutcome::Recorded(receipt) => receipt,
            other => panic!("expected recorded acknowledgment, got {other:?}"),
        };
        assert!(matches!(
            executor.record_control_queued(&attempt, retained.clone()).unwrap(),
            RecordOutcome::Duplicate(receipt) if receipt == acknowledgment
        ));
        drop(executor);

        let executor = fixture.open();
        assert_eq!(
            executor
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .attempts
                .get(&attempt_key(&attempt))
                .unwrap()
                .control_count,
            MAX_JOB_CONTROLS
        );
        assert!(matches!(
            executor.record_control_queued(&attempt, retained).unwrap(),
            RecordOutcome::Duplicate(receipt) if receipt == acknowledgment
        ));
        assert!(matches!(
            executor.record_control_queued(&attempt, request_for(MAX_JOB_CONTROLS + 1)),
            Err(ExecutorError::Capacity)
        ));
    }

    #[test]
    fn control_result_requires_exact_pending_attempt_control_and_target_sender() {
        use aether::Header;

        let fixture = Fixture::new("control-result-binding");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let control = ControlId::new("same-id-across-jobs");
        let mut attempts = Vec::new();
        for (sequence, job) in [(1, "job-a"), (2, "job-b")] {
            let grant = fixture.grant(deployment.clone(), job, DeliveryModeV1::AtMostOnce);
            let attempt = grant.payload.attempt.clone();
            executor.claim(grant.clone()).unwrap();
            let endorsed = fixture.control(
                &grant,
                control.as_str(),
                sequence,
                JobControlKindV1::Cancel { reason: "stop".into() },
            );
            executor.record_control_queued(&attempt, endorsed).unwrap();
            attempts.push(attempt);
        }

        let envelope_from = |from| Envelope {
            header: Header {
                from,
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: vec![],
        };

        let forged = executor.on_control_result(
            &envelope_from(Address::Creature(CreatureId(12))),
            attempts[0].clone(),
            control.clone(),
            ControlDispositionV1::Rejected,
            None,
        );
        assert!(forged.dispatches.is_empty(), "a non-target sender is ignored");

        let result = executor.on_control_result(
            &envelope_from(Address::Creature(CreatureId(11))),
            attempts[0].clone(),
            control,
            ControlDispositionV1::Rejected,
            None,
        );
        assert_eq!(result.dispatches.len(), 1);
        assert!(matches!(
            executor.latest(&attempts[0]).unwrap().payload.stage,
            ExecutionStageV1::ControlAcknowledged { .. }
        ));
        assert!(matches!(
            executor.latest(&attempts[1]).unwrap().payload.stage,
            ExecutionStageV1::ControlQueued { .. }
        ));
    }

    #[test]
    fn queued_control_restart_terminalizes_base_call_and_never_reforwards_command() {
        use aether::Header;

        let fixture = Fixture::new("control-crash-windows");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-control-crash", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let control_id = ControlId::new("durable-control");
        let endorsed = fixture.control(
            &grant,
            control_id.as_str(),
            3,
            JobControlKindV1::Cancel { reason: "stop".into() },
        );

        let RecordOutcome::Recorded(queued) =
            executor.record_control_queued(&attempt, endorsed.clone()).unwrap()
        else {
            panic!("first control intent is durable")
        };
        assert!(matches!(&queued.payload.stage, ExecutionStageV1::ControlQueued { .. }));
        drop(executor); // crash after executor journal fsync, before target send

        let recovered = fixture.open();
        let replay = recovered.recovery_dispatches();
        assert_eq!(replay.dispatches.len(), 4);
        assert!(replay.dispatches.iter().all(|dispatch| dispatch.schema == SCHEMA_EXECUTE_V1));
        let receipts = replay
            .dispatches
            .iter()
            .map(|dispatch| {
                let message: ExecuteMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
                let ExecuteMessageV1::Receipt { receipt } = message else {
                    panic!("ambiguous restart must not replay a function command")
                };
                *receipt
            })
            .collect::<Vec<_>>();
        assert_eq!(receipts[2], queued);
        assert!(matches!(receipts[3].payload.stage, ExecutionStageV1::Indeterminate { .. }));

        let target_env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        let sent = recovered.on_control_result(
            &target_env,
            attempt.clone(),
            control_id,
            ControlDispositionV1::Applied,
            Some("stopped".into()),
        );
        assert_eq!(sent.dispatches.len(), 1);
        let acknowledged = recovered.latest(&attempt).unwrap();
        assert!(matches!(
            &acknowledged.payload.stage,
            ExecutionStageV1::ControlAcknowledged {
                disposition: ControlDispositionV1::Applied,
                ..
            }
        ));
        drop(recovered); // crash after late ack fsync, before/while returning it to Home

        let reopened = fixture.open();
        let disposition_replay = reopened.recovery_dispatches();
        assert_eq!(disposition_replay.dispatches.len(), 5);
        assert!(disposition_replay
            .dispatches
            .iter()
            .all(|dispatch| dispatch.schema == SCHEMA_EXECUTE_V1));
        let last: ExecuteMessageV1 =
            serde_json::from_slice(&disposition_replay.dispatches.last().unwrap().payload).unwrap();
        assert!(matches!(
            last,
            ExecuteMessageV1::Receipt { receipt } if *receipt == acknowledged
        ));
    }

    #[test]
    fn terminal_control_replays_never_reforward_or_fabricate_a_disposition() {
        use aether::Header;

        let fixture = Fixture::new("terminal-control-replay");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-terminal-control", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let control_id = ControlId::new("terminal-pending");
        let exact = fixture.control(
            &grant,
            control_id.as_str(),
            3,
            JobControlKindV1::Cancel { reason: "stop".into() },
        );
        let RecordOutcome::Recorded(queued) =
            executor.record_control_queued(&attempt, exact.clone()).unwrap()
        else {
            panic!("control is durably queued before the crash")
        };
        drop(executor);

        let mut recovered = fixture.open();
        assert!(matches!(
            recovered.latest(&attempt).unwrap().payload.stage,
            ExecutionStageV1::Indeterminate { .. }
        ));
        let envelope = |request| Envelope {
            header: Header {
                from: Address::Creature(CreatureId(7)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_EXECUTE_V1.into(),
                origin: None,
            },
            payload: aether::wire::to_bytes(&ExecuteMessageV1::Control {
                request: Box::new(request),
            }),
        };
        let receipt_from = |outcome: &Outcome| {
            assert_eq!(outcome.dispatches.len(), 1, "terminal replay is receipt-only");
            assert_eq!(outcome.dispatches[0].schema, SCHEMA_EXECUTE_V1);
            let message: ExecuteMessageV1 =
                serde_json::from_slice(&outcome.dispatches[0].payload).unwrap();
            let ExecuteMessageV1::Receipt { receipt } = message else {
                panic!("terminal control replay returns its durable receipt")
            };
            *receipt
        };

        let exact_replay = recovered.handle(envelope(exact.clone()));
        assert_eq!(
            exact_replay.dispatches[0].to,
            Address::Node(NodeId("home-node".into()), CreatureId(7))
        );
        assert_eq!(receipt_from(&exact_replay), queued);

        let next_operational = Ed25519SeedSigner::from_seed([29; 32]).unwrap();
        let mut moved_payload = exact.payload.clone();
        moved_payload.home_epoch = 2;
        moved_payload.home_route_sequence = 2;
        moved_payload.home_coordinator = "8".into();
        moved_payload.authority =
            moved_authority(&fixture, &next_operational, "terminal-control-move");
        let moved =
            SignedRecordV1::sign(SCHEMA_EXECUTE_V1, moved_payload, &next_operational).unwrap();
        let moved_replay = recovered.handle(envelope(moved.clone()));
        assert_eq!(
            moved_replay.dispatches[0].to,
            Address::Node(NodeId("home-node".into()), CreatureId(8))
        );
        assert_eq!(receipt_from(&moved_replay), queued);
        let moved_duplicate = recovered.handle(envelope(moved));
        assert_eq!(
            moved_duplicate.dispatches[0].to,
            Address::Node(NodeId("home-node".into()), CreatureId(8))
        );
        assert_eq!(receipt_from(&moved_duplicate), queued);
        {
            let state = recovered.state.lock().unwrap_or_else(|poison| poison.into_inner());
            assert_eq!(state.unacknowledged_controls, 1);
            assert!(state.controls.values().all(|control| control.acknowledged.is_none()));
            let fence = state.home_fences.get(&attempt.home).unwrap();
            assert_eq!((fence.epoch, fence.route_sequence), (2, 2));
        }

        let target = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        let late = recovered.on_control_result(
            &target,
            attempt.clone(),
            control_id,
            ControlDispositionV1::Applied,
            Some("target-confirmed".into()),
        );
        assert_eq!(late.dispatches[0].to, Address::Node(NodeId("home-node".into()), CreatureId(8)));
        let acknowledged = receipt_from(&late);
        assert!(matches!(
            acknowledged.payload.stage,
            ExecutionStageV1::ControlAcknowledged {
                disposition: ControlDispositionV1::Applied,
                ..
            }
        ));
        assert_eq!(
            recovered
                .state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .unacknowledged_controls,
            0
        );
        drop(recovered);

        let reopened = fixture.open();
        assert_eq!(reopened.latest(&attempt).unwrap(), acknowledged);
        assert!(reopened.recovery_dispatches().dispatches.iter().all(|dispatch| {
            dispatch.schema == SCHEMA_EXECUTE_V1
                && dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(8))
        }));
    }

    #[test]
    fn full_terminal_journal_requires_cap_growth_before_moved_control_ack_replay() {
        use aether::Header;

        let fixture = Fixture::new("full-terminal-control-route");
        let open = |max_records| {
            let mut config = fixture.config();
            config.journal_caps.max_records = max_records;
            FunctionExecutor::open_with_liveness(
                config,
                fixture.executor.clone(),
                Arc::new(StringAddressing),
                Arc::new(AllowAdmission),
                Arc::new(AlwaysLive),
            )
            .unwrap()
        };
        let executor = open(6);
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-full-control", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let control_id = ControlId::new("full-pending");
        let original = fixture.control(
            &grant,
            control_id.as_str(),
            3,
            JobControlKindV1::Cancel { reason: "stop".into() },
        );
        let RecordOutcome::Recorded(queued) =
            executor.record_control_queued(&attempt, original.clone()).unwrap()
        else {
            panic!("control queue consumes a normal append while retaining its ack reservation")
        };
        drop(executor);

        let next_operational = Ed25519SeedSigner::from_seed([31; 32]).unwrap();
        let mut moved_payload = original.payload.clone();
        moved_payload.home_epoch = 2;
        moved_payload.home_route_sequence = 2;
        moved_payload.home_coordinator = "8".into();
        moved_payload.authority = moved_authority(&fixture, &next_operational, "full-control-move");
        let moved =
            SignedRecordV1::sign(SCHEMA_EXECUTE_V1, moved_payload, &next_operational).unwrap();
        let envelope = |request| Envelope {
            header: Header {
                from: Address::Creature(CreatureId(8)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_EXECUTE_V1.into(),
                origin: None,
            },
            payload: aether::wire::to_bytes(&ExecuteMessageV1::Control {
                request: Box::new(request),
            }),
        };
        let receipt_from = |outcome: &Outcome| {
            assert_eq!(outcome.dispatches.len(), 1, "terminal control replay is receipt-only");
            let message: ExecuteMessageV1 =
                serde_json::from_slice(&outcome.dispatches[0].payload).unwrap();
            let ExecuteMessageV1::Receipt { receipt } = message else {
                panic!("terminal control replay returns a receipt")
            };
            *receipt
        };

        let mut recovered = open(6);
        assert_eq!(recovered.journal.remaining_records().unwrap(), 1);
        let blocked = recovered.handle(envelope(moved.clone()));
        assert_eq!(blocked.dispatches.len(), 1);
        assert!(blocked.dispatches.iter().all(|dispatch| dispatch.schema != SCHEMA_CALL_V1));
        let blocked_message: ExecuteMessageV1 =
            serde_json::from_slice(&blocked.dispatches[0].payload).unwrap();
        assert!(matches!(
            blocked_message,
            ExecuteMessageV1::Error { error } if error.code == "capacity"
        ));
        assert_eq!(recovered.journal.remaining_records().unwrap(), 1);
        {
            let state = recovered.state.lock().unwrap_or_else(|poison| poison.into_inner());
            assert_eq!((state.nonterminal_attempts, state.unacknowledged_controls), (0, 1));
            assert_eq!(state.controls.values().next().unwrap().queued, queued);
            let fence = state.home_fences.get(&attempt.home).unwrap();
            assert_eq!((fence.epoch, fence.route_sequence), (1, 1));
        }

        let target = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        let late = recovered.on_control_result(
            &target,
            attempt.clone(),
            control_id,
            ControlDispositionV1::Applied,
            Some("target-confirmed".into()),
        );
        assert_eq!(late.dispatches[0].to, Address::Node(NodeId("home-node".into()), CreatureId(7)));
        let real_ack = receipt_from(&late);
        assert!(matches!(
            real_ack.payload.stage,
            ExecutionStageV1::ControlAcknowledged {
                disposition: ControlDispositionV1::Applied,
                ..
            }
        ));
        assert_eq!(recovered.journal.remaining_records().unwrap(), 0);
        drop(recovered); // the real ack's first response may also have been lost

        let mut reopened = open(6);
        let still_blocked = reopened.handle(envelope(moved.clone()));
        let still_blocked_message: ExecuteMessageV1 =
            serde_json::from_slice(&still_blocked.dispatches[0].payload).unwrap();
        assert!(matches!(
            still_blocked_message,
            ExecuteMessageV1::Error { error } if error.code == "capacity"
        ));
        drop(reopened);

        let mut expanded = open(7);
        let ack_replay = expanded.handle(envelope(moved));
        assert_eq!(
            ack_replay.dispatches[0].to,
            Address::Node(NodeId("home-node".into()), CreatureId(8))
        );
        assert_eq!(receipt_from(&ack_replay), real_ack);
        assert_eq!(expanded.journal.remaining_records().unwrap(), 0);
        let recovery = expanded.recovery_dispatches();
        assert_eq!(recovery.dispatches.len(), 5);
        assert!(recovery.dispatches.iter().all(|dispatch| {
            dispatch.schema == SCHEMA_EXECUTE_V1
                && dispatch.to == Address::Node(NodeId("home-node".into()), CreatureId(8))
        }));
        let state = expanded.state.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!((state.nonterminal_attempts, state.unacknowledged_controls), (0, 0));
    }

    #[test]
    fn restart_replays_control_receipts_by_sequence_before_synthesized_terminal() {
        let fixture = Fixture::new("control-receipt-order");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-control-order", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        for (event_sequence, id) in [(3, "z-first"), (4, "a-second")] {
            executor
                .record_control_queued(
                    &attempt,
                    fixture.control(
                        &grant,
                        id,
                        event_sequence,
                        JobControlKindV1::Steer {
                            value: ValueRefV1::Inline { value: json!({"id": id}) },
                        },
                    ),
                )
                .unwrap();
        }
        for id in ["a-second", "z-first"] {
            executor
                .record_stage(
                    &attempt,
                    ExecutionStageV1::ControlAcknowledged {
                        control: ControlId::new(id),
                        disposition: ControlDispositionV1::Applied,
                        detail: None,
                    },
                    None,
                )
                .unwrap();
        }
        drop(executor); // both acknowledgments are durable but neither send is assumed delivered

        let reopened = fixture.open();
        let recovery = reopened.recovery_dispatches();
        assert_eq!(recovery.dispatches.len(), 7);
        assert!(recovery.dispatches.iter().all(|dispatch| dispatch.schema == SCHEMA_EXECUTE_V1));
        let receipts = recovery
            .dispatches
            .iter()
            .map(|dispatch| {
                let message: ExecuteMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
                let ExecuteMessageV1::Receipt { receipt } = message else {
                    panic!("acknowledged controls never regain a target command after restart")
                };
                *receipt
            })
            .collect::<Vec<_>>();
        assert_eq!(
            receipts.iter().map(|receipt| receipt.payload.sequence).collect::<Vec<_>>(),
            (1..=7).collect::<Vec<_>>()
        );
        assert!(matches!(
            &receipts[2].payload.stage,
            ExecutionStageV1::ControlQueued { control } if control.as_str() == "z-first"
        ));
        assert!(matches!(
            &receipts[3].payload.stage,
            ExecutionStageV1::ControlQueued { control } if control.as_str() == "a-second"
        ));
        assert!(matches!(
            &receipts[4].payload.stage,
            ExecutionStageV1::ControlAcknowledged { control, .. }
                if control.as_str() == "a-second"
        ));
        assert!(matches!(
            &receipts[5].payload.stage,
            ExecutionStageV1::ControlAcknowledged { control, .. }
                if control.as_str() == "z-first"
        ));
        assert!(matches!(receipts[6].payload.stage, ExecutionStageV1::Indeterminate { .. }));
    }

    #[test]
    fn control_forwarding_rechecks_reused_target_liveness_on_recovery() {
        use aether::Header;

        let fixture = Fixture::new("control-reused-target");
        let executor = fixture.open_with_liveness(Arc::new(SequenceLiveness::new([
            Ok(true),
            Ok(true),
            Ok(true),
            Ok(false),
            Ok(true),
        ])));
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-reused-target", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let control = fixture.control(
            &grant,
            "recheck-target",
            3,
            JobControlKindV1::Cancel { reason: "stop".into() },
        );
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(7)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_EXECUTE_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        let initial = executor.on_control(&env, control);
        assert_eq!(
            initial.dispatches.len(),
            1,
            "a reused/nonmatching target receives no control after the queue fsync"
        );
        assert_eq!(
            initial.dispatches[0].to,
            Address::Node(NodeId("home-node".into()), CreatureId(7))
        );

        let recovery = executor.recovery_dispatches();
        assert_eq!(recovery.dispatches.len(), 4);
        assert_eq!(recovery.dispatches[3].to, Address::Creature(CreatureId(11)));
        let command: FunctionCallMessageV1 =
            serde_json::from_slice(&recovery.dispatches[3].payload).unwrap();
        assert!(matches!(
            command,
            FunctionCallMessageV1::Control { control }
                if control.attempt == attempt && *control.grant == grant
        ));
    }

    #[test]
    fn every_inbound_function_observation_rechecks_restarted_registry_and_live_binding() {
        use aether::Header;

        let fixture = Fixture::new("inbound-live-binding");
        let executor = fixture.open();
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        drop(executor);

        let executor = fixture.open_with_liveness(Arc::new(SequenceLiveness::new(
            [Ok(true), Ok(true)]
                .into_iter()
                .chain(std::iter::repeat_n(Ok(false), 4))
                .chain(std::iter::repeat_n(Ok(true), 4)),
        )));
        let grant = fixture.grant(deployment, "job-inbound-live", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        let control_id = ControlId::new("live-control-result");
        let control = fixture.control(
            &grant,
            control_id.as_str(),
            3,
            JobControlKindV1::Steer { value: ValueRefV1::Inline { value: json!({"speed": 3}) } },
        );
        let RecordOutcome::Recorded(baseline) =
            executor.record_control_queued(&attempt, control).unwrap()
        else {
            panic!("control queue establishes the no-append baseline")
        };
        let target = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        assert!(matches!(
            executor.result(
                &target,
                FunctionResultV1 {
                    attempt: attempt.clone(),
                    outcome: Ok(ValueRefV1::Inline { value: json!({"done": true}) }),
                },
            ),
            Err(ExecutorError::TargetUnavailable(_))
        ));
        assert!(executor
            .on_function_observation(
                &target,
                attempt.clone(),
                ExecutionStageV1::Progress {
                    sequence: 1,
                    progress: ValueRefV1::Inline { value: json!({"step": 1}) },
                },
            )
            .dispatches
            .is_empty());
        assert!(executor
            .on_function_observation(
                &target,
                attempt.clone(),
                ExecutionStageV1::Checkpoint {
                    sequence: 1,
                    checkpoint: ValueRefV1::Inline { value: json!({"at": 1}) },
                },
            )
            .dispatches
            .is_empty());
        assert!(executor
            .on_control_result(
                &target,
                attempt.clone(),
                control_id.clone(),
                ControlDispositionV1::Applied,
                None,
            )
            .dispatches
            .is_empty());
        assert_eq!(executor.latest(&attempt).unwrap(), baseline);

        assert_eq!(
            executor
                .on_function_observation(
                    &target,
                    attempt.clone(),
                    ExecutionStageV1::Progress {
                        sequence: 1,
                        progress: ValueRefV1::Inline { value: json!({"step": 1}) },
                    },
                )
                .dispatches
                .len(),
            1
        );
        assert_eq!(
            executor
                .on_function_observation(
                    &target,
                    attempt.clone(),
                    ExecutionStageV1::Checkpoint {
                        sequence: 1,
                        checkpoint: ValueRefV1::Inline { value: json!({"at": 1}) },
                    },
                )
                .dispatches
                .len(),
            1
        );
        assert_eq!(
            executor
                .on_control_result(
                    &target,
                    attempt.clone(),
                    control_id,
                    ControlDispositionV1::Applied,
                    None,
                )
                .dispatches
                .len(),
            1
        );
        assert!(executor
            .result(
                &target,
                FunctionResultV1 {
                    attempt: attempt.clone(),
                    outcome: Ok(ValueRefV1::Inline { value: json!({"done": true}) }),
                },
            )
            .is_ok());
        assert!(matches!(
            executor.latest(&attempt).unwrap().payload.stage,
            ExecutionStageV1::Succeeded { .. }
        ));
    }

    #[test]
    fn control_recovery_is_bounded_and_authenticated_self_pokes_finish_one_sweep() {
        use aether::{Header, Origin};

        let fixture = Fixture::new("control-recovery-cap");
        let mut executor = fixture.open();
        executor.me = Some(CreatureId(9));
        let deployment =
            executor.register(fixture.registration("realm-a", Some("node-a"))).unwrap();
        let grant = fixture.grant(deployment, "job-recovery-cap", DeliveryModeV1::AtMostOnce);
        let attempt = grant.payload.attempt.clone();
        executor.claim(grant.clone()).unwrap();
        for index in 0..40_u64 {
            let control = fixture.control(
                &grant,
                format!("recovery-{index:02}"),
                index + 3,
                JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"index": index}) },
                },
            );
            executor.record_control_queued(&attempt, control).unwrap();
        }

        let control_ids = |outcome: &Outcome| {
            outcome
                .dispatches
                .iter()
                .filter(|dispatch| dispatch.schema == SCHEMA_CALL_V1)
                .filter_map(|dispatch| {
                    let message =
                        serde_json::from_slice::<FunctionCallMessageV1>(&dispatch.payload).ok()?;
                    let FunctionCallMessageV1::Control { control } = message else {
                        return None;
                    };
                    Some(
                        control
                            .endorsement
                            .payload
                            .caller_request
                            .payload
                            .control
                            .as_str()
                            .to_string(),
                    )
                })
                .collect::<std::collections::BTreeSet<_>>()
        };
        let mut next = executor.recovery_dispatches();
        assert!(next.dispatches.len() <= MAX_EXECUTOR_RECOVERY_DISPATCHES + 1);
        let mut seen = control_ids(&next);
        let mut continuations = 0;
        while next
            .dispatches
            .iter()
            .any(|dispatch| dispatch.schema == EXECUTOR_RECOVERY_POKE_SCHEMA)
        {
            continuations += 1;
            assert!(continuations < 10, "one finite snapshot must drain promptly");
            let self_address = Address::Creature(CreatureId(9));
            let envelope = |from, origin| Envelope {
                header: Header {
                    from,
                    to: self_address.clone(),
                    reply_to: None,
                    seq: 1,
                    causal: vec![],
                    stamp: 1,
                    sig: "test".into(),
                    corr: None,
                    commitment: None,
                    schema: EXECUTOR_RECOVERY_POKE_SCHEMA.into(),
                    origin,
                },
                payload: EXECUTOR_RECOVERY_POKE_PAYLOAD.to_vec(),
            };
            assert!(executor
                .handle(envelope(Address::Creature(CreatureId(8)), None))
                .dispatches
                .is_empty());
            assert!(executor
                .handle(
                    envelope(self_address.clone(), Some(Origin::node(NodeId("remote".into()))),)
                )
                .dispatches
                .is_empty());
            next = executor.handle(envelope(self_address.clone(), None));
            assert!(next.dispatches.len() <= MAX_EXECUTOR_RECOVERY_DISPATCHES + 1);
            seen.extend(control_ids(&next));
        }
        assert_eq!(seen.len(), 40);
        let stale = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(9)),
                to: Address::Creature(CreatureId(9)),
                reply_to: None,
                seq: 2,
                causal: vec![],
                stamp: 2,
                sig: "test".into(),
                corr: None,
                commitment: None,
                schema: EXECUTOR_RECOVERY_POKE_SCHEMA.into(),
                origin: None,
            },
            payload: EXECUTOR_RECOVERY_POKE_PAYLOAD.to_vec(),
        };
        assert!(executor.handle(stale).dispatches.is_empty());
    }
}
