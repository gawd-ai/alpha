//! Durable single-authority home ledger for asynchronous function jobs.
//!
//! The Home is the sole writer of Job intent, causal edges, attempt grants, commands, and verified
//! executor observations. It persists signed hash-chained Job and custody journals, fails closed on
//! corrupt, uncertain, or frozen authority state, and moves write authority only through the fenced
//! handoff protocol. Placement and retry decisions remain injected policy; blob storage, trust,
//! retention, and workflow are not chosen here.

#![forbid(unsafe_code)]

mod custody;
mod custody_bus;
mod journal;

pub use custody::{
    activate_staged_handoff, destination_custody_status, stage_handoff,
    stage_handoff_with_rewrapper, HomeCustodyStatus, PreparedHandoff,
};
pub use custody_bus::HomeCustodyDestination;
#[cfg(any(test, feature = "durability-test-hooks"))]
#[doc(hidden)]
pub use journal::{inject_durability_fault, DurabilityFaultGuard, DurabilityFaultPoint};
pub use journal::{ChainEntry, JournalAuthority, JournalCaps, JournalError, SignedJournal};

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, NodeId, Outcome, RealmId, Role,
};
use gawdfn::{
    canonical_hash, derive_job_id, AttemptId, AuthoritySigner, ControlId, CustodyRewrapReceiptV1,
    CustodyRewrapRequestV1, CustodyRewrapSourceV1, DeliveryModeV1, DeploymentReceiptV1,
    EffectClassV1, EventPageResponseV1, EventPageV1, EventQueryRelayV1, EventQueryV1,
    ExecuteMessageV1, ExecutionControlV1, ExecutionGrantV1, ExecutionQueryV1, ExecutionReceiptV1,
    ExecutionStageV1, HomeAuthorityV1, HomeId, HomeMessageV1, JobAccessV1, JobControlKindV1,
    JobControlV1, JobEventKindV1, JobEventV1, JobGetRelayV1, JobHandleV1, JobId, JobMessageV1,
    JobSnapshotResponseV1, JobSnapshotV1, JobSpecV1, JobStateV1, LocateMessageV1,
    OperationalCapabilityV1, PlacementDecisionV1, PlacementQuestionV1, PolicyMessageV1,
    ProtocolErrorV1, RecipientKeyBindingV1, ResolutionReceiptV1, ResolvedFunctionV1,
    RetryDecisionV1, RetryQuestionV1, SignedRecordV1, Validate, ValueRefV1, FUNCTION_EXECUTOR_ROLE,
    FUNCTION_LOCATOR_ROLE, FUNCTION_POLICY_ROLE, MAX_ATTEMPT_OBSERVATIONS, MAX_EVENT_PAGE_ITEMS,
    MAX_HOME_RECOVERY_DISPATCHES, MAX_JOB_CONTROLS, MAX_JOB_MESSAGE_BYTES,
    MAX_PRIVATE_READ_MESSAGE_BYTES, SCHEMA_EXECUTE_V1, SCHEMA_HOME_V1, SCHEMA_JOB_V1,
    SCHEMA_LOCATE_V1, SCHEMA_POLICY_V1,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use thiserror::Error;

pub const DEFAULT_MAX_HOME_JOBS: usize = 16_384;
pub const DEFAULT_MAX_HOME_CHECKPOINT_BYTES: usize = 64 * 1024 * 1024;
const HOME_RECOVERY_POKE_SCHEMA: &str = "gawd.internal.function.home.recovery.v1";
const HOME_RECOVERY_POKE_PAYLOAD: &[u8] = b"continue-v1";
const HOME_RECOVERY_PLACEMENT: u8 = 0;
const HOME_RECOVERY_RETRY: u8 = 1;
const HOME_RECOVERY_ATTEMPT: u8 = 2;
const HOME_RECOVERY_CONTROL: u8 = 3;

/// Alias/artifact knowledge is injected. The home owns the pinning invariant, not discovery
/// strategy: it accepts only the immutable result returned here.
pub trait FunctionMetadata: Send + Sync {
    fn effect(&self, function: &ResolvedFunctionV1) -> EffectClassV1;
}

/// Trust is injected separately from structural and cryptographic verification. Evidence remains
/// data for this policy; the home never treats a merely well-formed signature as admission.
pub trait FunctionTrust: Send + Sync {
    fn allow_resolution(
        &self,
        resolution: &SignedRecordV1<ResolutionReceiptV1>,
    ) -> Result<(), String>;
    fn allow_deployment(
        &self,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String>;
    fn allow_executor_receipt(
        &self,
        receipt: &SignedRecordV1<ExecutionReceiptV1>,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String>;
    fn allow_placement_decision(
        &self,
        decision: &SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<(), String>;
    fn allow_retry_decision(
        &self,
        decision: &SignedRecordV1<RetryDecisionV1>,
    ) -> Result<(), String>;

    /// Admit a route-binding relay for a signed caller read. The default permits a caller to bind
    /// its own route; compositions may additionally pin a local control relay key.
    fn allow_read_relay(&self, relay: &str, caller: &str) -> Result<(), String> {
        if relay == caller {
            Ok(())
        } else {
            Err("job read relay is not the caller or an injected trust anchor".into())
        }
    }
}

/// Destination-local KMS/enclave seam for Home custody key rotation.
///
/// Only root-signed public bindings, ciphertext envelopes, and signed public proofs cross this
/// boundary. Private recipient and proof keys remain owned by the injected implementation.
pub trait CustodyKeyRewrapper: Send + Sync {
    /// Return the exact root-signed recipient binding currently served by this adapter.
    /// It must remain stable for the lifetime of the Home instance.
    fn current_binding(&self) -> Result<SignedRecordV1<RecipientKeyBindingV1>, String>;

    /// Rewrap the exact source-frozen inventory named by `request` and return one aggregate proof.
    ///
    /// This operation must be idempotent by the complete signed `request`: a crash can occur after
    /// adapter success but before the Home fsyncs `StagingReceipt`. Repeating the exact request must
    /// safely re-attest the same semantic destination wraps (and normally the exact same receipt),
    /// never consume a one-shot key transition or create an untracked independent rotation.
    fn rewrap(
        &self,
        request: &SignedRecordV1<CustodyRewrapRequestV1>,
        inventory: &[CustodyRewrapSourceV1],
    ) -> Result<SignedRecordV1<CustodyRewrapReceiptV1>, String>;
}

pub(crate) struct UnavailableCustodyKeyRewrapper;

impl CustodyKeyRewrapper for UnavailableCustodyKeyRewrapper {
    fn current_binding(&self) -> Result<SignedRecordV1<RecipientKeyBindingV1>, String> {
        Err("no custody key rewrapper is configured".into())
    }

    fn rewrap(
        &self,
        _request: &SignedRecordV1<CustodyRewrapRequestV1>,
        _inventory: &[CustodyRewrapSourceV1],
    ) -> Result<SignedRecordV1<CustodyRewrapReceiptV1>, String> {
        Err("no custody key rewrapper is configured".into())
    }
}

#[derive(Clone)]
pub struct HomeConfig {
    pub root: PathBuf,
    pub home: HomeId,
    pub epoch: u64,
    pub coordinator: String,
    pub realm: String,
    pub node: String,
    pub authority: HomeAuthorityV1,
    /// Root-authorized prior epoch keys accepted only while replaying a migrated ledger.
    pub historical_authorities: Vec<HomeAuthorityV1>,
    pub max_jobs: usize,
    pub max_checkpoint_bytes: usize,
    pub journal_caps: JournalCaps,
}

impl HomeConfig {
    pub fn new(
        root: impl Into<PathBuf>,
        home: HomeId,
        coordinator: impl Into<String>,
        authority: HomeAuthorityV1,
    ) -> Self {
        Self {
            root: root.into(),
            home,
            epoch: 1,
            coordinator: coordinator.into(),
            realm: "local".into(),
            node: "local".into(),
            authority,
            historical_authorities: Vec::new(),
            max_jobs: DEFAULT_MAX_HOME_JOBS,
            max_checkpoint_bytes: DEFAULT_MAX_HOME_CHECKPOINT_BYTES,
            journal_caps: JournalCaps::default(),
        }
    }

    pub fn with_location(mut self, realm: impl Into<String>, node: impl Into<String>) -> Self {
        self.realm = realm.into();
        self.node = node.into();
        self
    }

    /// Configuration for a Home loaded as a Creature. `bind` replaces the sentinel with the live
    /// `CreatureId`, avoiding a boot-time ID prediction cycle.
    pub fn for_creature(
        root: impl Into<PathBuf>,
        home: HomeId,
        authority: HomeAuthorityV1,
    ) -> Self {
        Self::new(root, home, "auto", authority)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HomeLedgerRecord {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant: Option<SignedRecordV1<ExecutionGrantV1>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<SignedRecordV1<ExecutionReceiptV1>>,
    events: Vec<SignedRecordV1<JobEventV1>>,
}

#[derive(Debug, Clone)]
struct JobRecord {
    snapshot: JobSnapshotV1,
    events: Vec<SignedRecordV1<JobEventV1>>,
}

#[derive(Debug, Clone)]
struct ChildSpawnRecord {
    parent_event_hash: String,
    child_request_hash: String,
    child: JobHandleV1,
    root: JobHandleV1,
    event: SignedRecordV1<JobEventV1>,
}

#[derive(Debug, Clone)]
struct ForwardedControlRecord {
    attempt: AttemptId,
    queued_receipt_hash: Option<String>,
    acknowledged_receipt_hash: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct HomeRecoveryKey {
    job: JobId,
    kind: u8,
    sequence: u64,
}

#[derive(Default)]
struct HomeRecoverySweep {
    cursor: Option<HomeRecoveryKey>,
    high_water: Option<HomeRecoveryKey>,
    remaining: usize,
}

struct HomeState {
    jobs: BTreeMap<JobId, JobRecord>,
    request_hashes: BTreeMap<JobId, String>,
    grants: BTreeMap<(JobId, u8), SignedRecordV1<ExecutionGrantV1>>,
    receipts: BTreeMap<(JobId, u8, u64), String>,
    highest_receipt_sequences: BTreeMap<(JobId, u8), u64>,
    observation_counts: BTreeMap<(JobId, u8), usize>,
    highest_progress_sequences: BTreeMap<(JobId, u8), u64>,
    highest_checkpoint_sequences: BTreeMap<(JobId, u8), u64>,
    controls: BTreeMap<(JobId, String), String>,
    control_counts: BTreeMap<JobId, usize>,
    forwarded_controls: BTreeMap<(JobId, String), ForwardedControlRecord>,
    child_spawns: BTreeMap<(JobId, u8, String), ChildSpawnRecord>,
    nonterminal_jobs: usize,
    unacknowledged_forwarded_controls: usize,
    next_grant_sequence: u64,
    custody: custody::CustodyState,
}

impl HomeState {
    fn new(custody: custody::CustodyState) -> Self {
        Self {
            jobs: BTreeMap::new(),
            request_hashes: BTreeMap::new(),
            grants: BTreeMap::new(),
            receipts: BTreeMap::new(),
            highest_receipt_sequences: BTreeMap::new(),
            observation_counts: BTreeMap::new(),
            highest_progress_sequences: BTreeMap::new(),
            highest_checkpoint_sequences: BTreeMap::new(),
            controls: BTreeMap::new(),
            control_counts: BTreeMap::new(),
            forwarded_controls: BTreeMap::new(),
            child_spawns: BTreeMap::new(),
            nonterminal_jobs: 0,
            unacknowledged_forwarded_controls: 0,
            next_grant_sequence: 1,
            custody,
        }
    }

    fn empty_for_replay() -> Self {
        Self::new(custody::CustodyState::unfenced_for_replay())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    Accepted { handle: JobHandleV1, request_hash: String, submitted: SignedRecordV1<JobEventV1> },
    Existing { handle: JobHandleV1, request_hash: String, submitted: SignedRecordV1<JobEventV1> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyReceiptOutcome {
    Applied(SignedRecordV1<JobEventV1>),
    Duplicate(SignedRecordV1<JobEventV1>),
}

struct PreparedSubmission {
    handle: JobHandleV1,
    request_hash: String,
    spec: JobSpecV1,
}

#[derive(Debug, Error)]
pub enum HomeError {
    #[error("home configuration is invalid: {0}")]
    Configuration(String),
    #[error("invalid request: {0}")]
    Invalid(String),
    #[error("request is not authorized: {0}")]
    Unauthorized(String),
    #[error("job `{0}` was not found")]
    NotFound(String),
    #[error("idempotency conflict for job `{0}`")]
    Conflict(String),
    #[error("job state conflict: {0}")]
    State(String),
    #[error("home capacity reached: {0}")]
    Capacity(String),
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error("signing failed: {0}")]
    Signing(String),
}

pub struct FunctionHome {
    config: HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    metadata: Arc<dyn FunctionMetadata>,
    trust: Arc<dyn FunctionTrust>,
    blobs: Arc<dyn gawdfn::BlobAvailability>,
    journal: SignedJournal<HomeLedgerRecord>,
    custody_journal: SignedJournal<custody::CustodyLedgerRecord>,
    checkpoint_blobs: Arc<dyn gawdfn::CheckpointBlobStore>,
    rewrapper: Arc<dyn CustodyKeyRewrapper>,
    current_recipient_binding: Mutex<Option<SignedRecordV1<RecipientKeyBindingV1>>>,
    state: Mutex<HomeState>,
    recovery_sweep: Mutex<HomeRecoverySweep>,
    operational_failure: Mutex<Option<String>>,
    me: Option<CreatureId>,
}

impl FunctionHome {
    pub fn open(
        config: HomeConfig,
        signer: Arc<dyn AuthoritySigner>,
        metadata: Arc<dyn FunctionMetadata>,
        trust: Arc<dyn FunctionTrust>,
        blobs: Arc<dyn gawdfn::BlobAvailability>,
    ) -> Result<Self, HomeError> {
        Self::open_with_checkpoint_store(
            config,
            signer,
            metadata,
            trust,
            blobs,
            Arc::new(custody::UnavailableCheckpointStore),
        )
    }

    pub fn open_with_checkpoint_store(
        config: HomeConfig,
        signer: Arc<dyn AuthoritySigner>,
        metadata: Arc<dyn FunctionMetadata>,
        trust: Arc<dyn FunctionTrust>,
        blobs: Arc<dyn gawdfn::BlobAvailability>,
        checkpoint_blobs: Arc<dyn gawdfn::CheckpointBlobStore>,
    ) -> Result<Self, HomeError> {
        Self::open_with_checkpoint_store_and_rewrapper(
            config,
            signer,
            metadata,
            trust,
            blobs,
            checkpoint_blobs,
            Arc::new(UnavailableCustodyKeyRewrapper),
        )
    }

    /// Open a Home with an injected destination-local KMS/enclave rewrap implementation.
    pub fn open_with_checkpoint_store_and_rewrapper(
        mut config: HomeConfig,
        signer: Arc<dyn AuthoritySigner>,
        metadata: Arc<dyn FunctionMetadata>,
        trust: Arc<dyn FunctionTrust>,
        blobs: Arc<dyn gawdfn::BlobAvailability>,
        checkpoint_blobs: Arc<dyn gawdfn::CheckpointBlobStore>,
        rewrapper: Arc<dyn CustodyKeyRewrapper>,
    ) -> Result<Self, HomeError> {
        custody::merge_imported_authorities(&mut config)?;
        custody::merge_current_authority(&mut config)?;
        config.home.validate().map_err(invalid)?;
        if config.epoch == 0
            || config.max_jobs == 0
            || config.max_checkpoint_bytes == 0
            || config.coordinator.trim().is_empty()
            || config.realm.trim().is_empty()
            || config.node.trim().is_empty()
        {
            return Err(HomeError::Configuration(
                "epoch, max_jobs, and coordinator must be non-zero/non-empty".into(),
            ));
        }
        config
            .authority
            .verify(&config.home, config.epoch, OperationalCapabilityV1::JobHome)
            .map_err(|error| HomeError::Configuration(error.to_string()))?;
        config
            .authority
            .verify(&config.home, config.epoch, OperationalCapabilityV1::JobControl)
            .map_err(|error| HomeError::Configuration(error.to_string()))?;
        if config.authority.operational.payload.operational_public_key != signer.public_key() {
            return Err(HomeError::Configuration(
                "current authority does not grant the injected operational signer".into(),
            ));
        }
        let mut authorized_epochs = BTreeMap::<String, u64>::new();
        authorized_epochs.insert(signer.public_key().to_string(), config.epoch);
        for authority in &config.historical_authorities {
            let epoch = authority.operational.payload.epoch;
            if epoch >= config.epoch {
                return Err(HomeError::Configuration(
                    "historical authority epoch must precede the current epoch".into(),
                ));
            }
            authority
                .verify(&config.home, epoch, OperationalCapabilityV1::JobHome)
                .map_err(|error| HomeError::Configuration(error.to_string()))?;
            if authorized_epochs
                .insert(authority.operational.payload.operational_public_key.clone(), epoch)
                .is_some()
            {
                return Err(HomeError::Configuration(
                    "one operational key is granted for multiple epochs".into(),
                ));
            }
        }
        let chain_authority =
            Arc::new(move |candidate: &str, entry: &ChainEntry<HomeLedgerRecord>| {
                let Some(epoch) = authorized_epochs.get(candidate).copied() else { return false };
                !entry.event.events.is_empty()
                    && entry.event.events.iter().all(|event| event.payload.home_epoch == epoch)
                    && entry
                        .event
                        .grant
                        .as_ref()
                        .is_none_or(|grant| grant.payload.home_epoch == epoch)
            });
        let journal = SignedJournal::open_with_authority(
            &config.root,
            "function-home",
            "gawd.function.home.journal.v1",
            signer.clone(),
            config.journal_caps,
            chain_authority,
        )?;
        let (custody_journal, custody) =
            custody::open_or_initialize_custody(&config, signer.clone(), journal.is_empty())?;
        let mut state = HomeState::new(custody);
        journal.with_snapshot(|records, _| {
            for record in records {
                apply_ledger_record(&config, &mut state, &record.payload.event)?;
            }
            Ok::<_, HomeError>(())
        })??;
        let reservations = home_reservations(&state)?;
        if journal.remaining_records()? < reservations {
            return Err(HomeError::Capacity(format!(
                "recovered Home requires {reservations} terminal/control-ack slots beyond the configured journal cap"
            )));
        }
        if state.jobs.len() > config.max_jobs {
            return Err(HomeError::Capacity("recovered jobs exceed configured cap".into()));
        }
        if let Some(coordinator) = state.custody.active_coordinator() {
            // The custody journal, not process configuration, owns the current route revision.
            // Bind may durably advance it, but open must never sign a same-sequence divergent hint.
            config.coordinator = coordinator.to_string();
        }
        let overlay_binding =
            custody::active_overlay_recipient_binding(&config, checkpoint_blobs.as_ref(), &state)?;
        let direct_constraint = if overlay_binding.is_none() {
            journal.with_snapshot(|records, _| {
                custody::durable_direct_recipient_constraint(&config.home, records)
            })??
        } else {
            None
        };
        let current_recipient_binding = if overlay_binding.is_some() || direct_constraint.is_some()
        {
            let binding = rewrapper.current_binding().map_err(|error| {
                HomeError::State(format!("custody key rewrapper unavailable: {error}"))
            })?;
            custody::verify_current_recipient_binding(&config, &binding)?;
            if let Some(required) = overlay_binding {
                if binding != required {
                    return Err(HomeError::Unauthorized(
                        "custody rewrapper binding differs from the effective checkpoint overlay"
                            .into(),
                    ));
                }
            } else if let Some((required_hash, required_suite)) = direct_constraint {
                if canonical_hash(&binding).map_err(invalid)? != required_hash
                    || binding.payload.suite != required_suite
                {
                    return Err(HomeError::Unauthorized(
                        "custody rewrapper binding differs from durable direct Home envelopes"
                            .into(),
                    ));
                }
            }
            Some(binding)
        } else {
            None
        };
        Ok(Self {
            config,
            signer,
            metadata,
            trust,
            blobs,
            journal,
            custody_journal,
            checkpoint_blobs,
            rewrapper,
            current_recipient_binding: Mutex::new(current_recipient_binding),
            state: Mutex::new(state),
            recovery_sweep: Mutex::new(HomeRecoverySweep::default()),
            operational_failure: Mutex::new(None),
            me: None,
        })
    }

    pub(crate) fn bind_runtime(&mut self, ctx: CreatureCtx, emit_recovery: bool) -> Outcome {
        self.me = Some(ctx.me);
        let coordinator = ctx.me.0.to_string();
        if let Err(error) = self.refresh_runtime_route(&coordinator) {
            *self.operational_failure.lock().unwrap_or_else(|poison| poison.into_inner()) =
                Some(error.to_string());
            return Outcome::none();
        }
        self.config.coordinator = coordinator;
        let recovery = self.recovery_dispatches();
        if emit_recovery {
            for dispatch in recovery.dispatches.iter().cloned() {
                let _ = ctx.bus.emit(dispatch);
            }
        }
        recovery
    }

    fn ensure_authoritative_state(&self, state: &HomeState) -> Result<(), HomeError> {
        if let Some(error) =
            self.operational_failure.lock().unwrap_or_else(|poison| poison.into_inner()).as_ref()
        {
            return Err(HomeError::State(format!("Home runtime is inert: {error}")));
        }
        self.journal.ensure_healthy()?;
        self.custody_journal.ensure_healthy()?;
        state.custody.ensure_writable()
    }

    /// Gate every path that can sign, dispatch, consult policy, or return an authoritative
    /// duplicate. A frozen source or uncertain journal prefix becomes inert until audited reopen.
    fn ensure_operational_write_authority(&self) -> Result<(), HomeError> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)
    }

    pub fn submit(
        &self,
        request: SignedRecordV1<gawdfn::JobSubmitV1>,
        resolution: SignedRecordV1<ResolutionReceiptV1>,
        deployment: SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<SubmitOutcome, HomeError> {
        self.ensure_operational_write_authority()?;
        if request.payload.parent.is_some() || !request.payload.causal.is_empty() {
            return Err(HomeError::Invalid(
                "direct Submit cannot assert parent/causal edges; use atomic ProposeChild".into(),
            ));
        }
        let (handle, request_hash) = self.validate_job_request(&request)?;
        {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_authoritative_state(&state)?;
            if let Some(existing_hash) = state.request_hashes.get(&handle.job) {
                return if existing_hash == &request_hash {
                    Ok(SubmitOutcome::Existing {
                        submitted: submitted_event(&state, &handle.job)?,
                        handle,
                        request_hash,
                    })
                } else {
                    Err(HomeError::Conflict(handle.job.to_string()))
                };
            }
        }
        let prepared = self.prepare_submission(request, resolution, deployment)?;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        if let Some(existing_hash) = state.request_hashes.get(&prepared.handle.job) {
            return if existing_hash == &request_hash {
                Ok(SubmitOutcome::Existing {
                    submitted: submitted_event(&state, &prepared.handle.job)?,
                    handle: prepared.handle,
                    request_hash,
                })
            } else {
                Err(HomeError::Conflict(prepared.handle.job.to_string()))
            };
        }
        if state.jobs.len() >= self.config.max_jobs {
            return Err(HomeError::Capacity(format!(
                "{} jobs reaches cap {}",
                state.jobs.len(),
                self.config.max_jobs
            )));
        }
        let event = self.sign_event(
            &state,
            &prepared.handle,
            JobStateV1::Queued,
            false,
            prepared.spec.accepted_at_unix_ms,
            JobEventKindV1::Submitted { spec: Box::new(prepared.spec) },
        )?;
        self.persist_and_apply(
            &mut state,
            HomeLedgerRecord { grant: None, receipt: None, events: vec![event.clone()] },
        )?;
        Ok(SubmitOutcome::Accepted {
            handle: prepared.handle,
            request_hash: prepared.request_hash,
            submitted: event,
        })
    }

    fn validate_job_request(
        &self,
        request: &SignedRecordV1<gawdfn::JobSubmitV1>,
    ) -> Result<(JobHandleV1, String), HomeError> {
        self.validate_job_request_signed_by(request, self.config.home.as_str())
    }

    fn validate_job_request_signed_by(
        &self,
        request: &SignedRecordV1<gawdfn::JobSubmitV1>,
        authorized_signer: &str,
    ) -> Result<(JobHandleV1, String), HomeError> {
        request.validate().map_err(invalid)?;
        self.require_value(&request.payload.input)?;
        if request.schema != SCHEMA_JOB_V1 || !request.verify() {
            return Err(HomeError::Unauthorized("invalid job-submission signature".into()));
        }
        if request.payload.home != self.config.home || request.signer != authorized_signer {
            return Err(HomeError::Unauthorized(
                "submission is not signed by the authority that approved this operation".into(),
            ));
        }
        let job = derive_job_id(&request.payload.home, &request.payload.caller_idempotency_key)
            .map_err(invalid)?;
        let request_hash = request.payload.request_hash().map_err(invalid)?;
        Ok((JobHandleV1 { home: self.config.home.clone(), job }, request_hash))
    }

    fn prepare_submission(
        &self,
        request: SignedRecordV1<gawdfn::JobSubmitV1>,
        resolution: SignedRecordV1<ResolutionReceiptV1>,
        deployment: SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<PreparedSubmission, HomeError> {
        self.prepare_submission_signed_by(
            request,
            resolution,
            deployment,
            self.config.home.as_str(),
        )
    }

    fn prepare_submission_signed_by(
        &self,
        request: SignedRecordV1<gawdfn::JobSubmitV1>,
        resolution: SignedRecordV1<ResolutionReceiptV1>,
        deployment: SignedRecordV1<DeploymentReceiptV1>,
        authorized_signer: &str,
    ) -> Result<PreparedSubmission, HomeError> {
        let (handle, request_hash) =
            self.validate_job_request_signed_by(&request, authorized_signer)?;
        resolution.validate().map_err(invalid)?;
        deployment.validate().map_err(invalid)?;
        if !resolution.verify() || gawdfn::verify_deployment_receipt(&deployment).is_err() {
            return Err(HomeError::Unauthorized(
                "resolution/deployment receipt signature is invalid".into(),
            ));
        }
        self.trust
            .allow_resolution(&resolution)
            .map_err(|reason| HomeError::Unauthorized(format!("resolution refused: {reason}")))?;
        self.trust
            .allow_deployment(&deployment)
            .map_err(|reason| HomeError::Unauthorized(format!("deployment refused: {reason}")))?;
        if resolution.payload.selector != request.payload.function
            || resolution.payload.function != deployment.payload.function
            || resolution.payload.artifact_hash != deployment.payload.artifact_hash
        {
            return Err(HomeError::Invalid(
                "submission, resolution, and deployment pins do not match".into(),
            ));
        }
        let resolved = ResolvedFunctionV1 {
            requested: request.payload.function.clone(),
            function: resolution.payload.function.clone(),
            artifact_hash: resolution.payload.artifact_hash.clone(),
            resolution: Some(resolution),
        };
        resolved.validate().map_err(invalid)?;
        if matches!(request.payload.delivery, DeliveryModeV1::AtLeastOnce { .. })
            && !request.payload.allow_duplicate_effects
            && !matches!(
                self.metadata.effect(&resolved),
                EffectClassV1::ReadOnly | EffectClassV1::Idempotent
            )
        {
            return Err(HomeError::Invalid(
                "at-least-once for an unknown/non-idempotent function requires allow_duplicate_effects"
                    .into(),
            ));
        }
        let spec = JobSpecV1 {
            handle: handle.clone(),
            root: request.payload.parent.clone().unwrap_or_else(|| handle.clone()),
            caller_idempotency_key: request.payload.caller_idempotency_key,
            request_hash: request_hash.clone(),
            function: resolved,
            deployment,
            input: request.payload.input,
            delivery: request.payload.delivery,
            allow_duplicate_effects: request.payload.allow_duplicate_effects,
            parent: request.payload.parent,
            causal: request.payload.causal,
            access: request.payload.access,
            evidence: request.payload.evidence,
            result_recipients: request.payload.result_recipients,
            accepted_at_unix_ms: request.payload.submitted_at_unix_ms,
        };
        spec.validate().map_err(invalid)?;
        Ok(PreparedSubmission { handle, request_hash, spec })
    }

    /// Build the bounded placement question for a queued job. The reference Home exposes only the
    /// exact deployment accepted into the immutable JobSpec; broader candidate discovery remains a
    /// separate resolver/registry concern and cannot silently change this pin.
    pub fn placement_question(
        &self,
        handle: &JobHandleV1,
    ) -> Result<Option<SignedRecordV1<PlacementQuestionV1>>, HomeError> {
        self.ensure_operational_write_authority()?;
        if handle.home != self.config.home {
            return Err(HomeError::NotFound(handle.job.to_string()));
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        let job = state
            .jobs
            .get(&handle.job)
            .ok_or_else(|| HomeError::NotFound(handle.job.to_string()))?;
        if job.snapshot.state != JobStateV1::Queued {
            return Ok(None);
        }
        let question = PlacementQuestionV1 {
            job: handle.clone(),
            home_epoch: self.config.epoch,
            authority: self.config.authority.clone(),
            function: job.snapshot.spec.function.function.clone(),
            candidates: vec![job.snapshot.spec.deployment.clone()],
            evidence: job.snapshot.spec.evidence.clone(),
        };
        question.validate().map_err(invalid)?;
        let question = SignedRecordV1::sign(SCHEMA_POLICY_V1, question, self.signer.as_ref())
            .map_err(signing)?;
        gawdfn::verify_placement_question(&question).map_err(invalid)?;
        Ok(Some(question))
    }

    /// Reconstruct the exact signed retry question from durable job/event state. Ed25519 signing
    /// is deterministic, so a restart produces the same signed record and canonical hash for the
    /// same outstanding failure; no transport correlation is needed as authority.
    pub fn retry_question(
        &self,
        handle: &JobHandleV1,
        failed_attempt: &AttemptId,
    ) -> Result<SignedRecordV1<RetryQuestionV1>, HomeError> {
        self.ensure_operational_write_authority()?;
        if handle.home != self.config.home
            || failed_attempt.home != handle.home
            || failed_attempt.job != handle.job
        {
            return Err(HomeError::NotFound(handle.job.to_string()));
        }
        let (mut snapshot, failure, retryable, candidates, evidence) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_authoritative_state(&state)?;
            let job = state
                .jobs
                .get(&handle.job)
                .ok_or_else(|| HomeError::NotFound(handle.job.to_string()))?;
            if job.snapshot.state != JobStateV1::RetryPending
                || job.snapshot.current_attempt.as_ref() != Some(failed_attempt)
            {
                return Err(HomeError::State(
                    "job has no outstanding retry question for that failed attempt".into(),
                ));
            }
            let Some((_, failure, retryable)) = job
                .events
                .iter()
                .rev()
                .filter_map(|event| retry_failure(&event.payload.kind))
                .find(|(attempt, _, _)| attempt == failed_attempt)
            else {
                return Err(HomeError::State(
                    "durable failed-attempt event is unavailable for retry policy".into(),
                ));
            };
            (
                job.snapshot.clone(),
                failure,
                retryable,
                vec![job.snapshot.spec.deployment.clone()],
                job.snapshot.spec.evidence.clone(),
            )
        };
        snapshot.home_epoch = self.config.epoch;
        snapshot.authority = self.config.authority.clone();
        let question = RetryQuestionV1 {
            snapshot,
            failed_attempt: failed_attempt.clone(),
            failure,
            executor_retryable_hint: retryable,
            candidates,
            evidence,
        };
        question.validate().map_err(invalid)?;
        let question = SignedRecordV1::sign(SCHEMA_POLICY_V1, question, self.signer.as_ref())
            .map_err(signing)?;
        gawdfn::verify_retry_question(&question).map_err(invalid)?;
        Ok(question)
    }

    /// Admit a signed policy response and durably mint (or idempotently recover) the first exact
    /// grant. Signature validity is only a fact: `FunctionTrust` decides whether this policy signer
    /// is authoritative for the Home.
    pub fn apply_placement_decision(
        &self,
        decision: SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<SignedRecordV1<ExecutionGrantV1>, HomeError> {
        self.ensure_operational_write_authority()?;
        decision.validate().map_err(invalid)?;
        if decision.schema != SCHEMA_POLICY_V1 || !decision.verify() {
            return Err(HomeError::Unauthorized("placement decision signature is invalid".into()));
        }
        let expected_question = self
            .placement_question(&decision.payload.job)?
            .ok_or_else(|| HomeError::State("job has no outstanding placement question".into()))?;
        let expected_hash = canonical_hash(&expected_question).map_err(invalid)?;
        if decision.payload.question_hash != expected_hash {
            return Err(HomeError::Unauthorized(
                "placement decision does not bind the exact outstanding signed question".into(),
            ));
        }
        self.trust.allow_placement_decision(&decision).map_err(|reason| {
            HomeError::Unauthorized(format!("placement decision refused: {reason}"))
        })?;
        if decision.payload.job.home != self.config.home {
            return Err(HomeError::NotFound(decision.payload.job.job.to_string()));
        }
        let (deployment, existing) = {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_authoritative_state(&state)?;
            let job = state
                .jobs
                .get(&decision.payload.job.job)
                .ok_or_else(|| HomeError::NotFound(decision.payload.job.job.to_string()))?;
            if job.snapshot.state.is_terminal() || job.snapshot.cancel_requested {
                return Err(HomeError::State(
                    "placement decision arrived after the job stopped dispatching".into(),
                ));
            }
            if decision.payload.selected != job.snapshot.spec.deployment.payload.deployment {
                return Err(HomeError::Unauthorized(
                    "placement decision selected a deployment outside the accepted candidate set"
                        .into(),
                ));
            }
            let existing = job.snapshot.current_attempt.as_ref().and_then(|attempt| {
                state.grants.get(&(attempt.job.clone(), attempt.number)).cloned()
            });
            (job.snapshot.spec.deployment.clone(), existing)
        };
        if let Some(grant) = existing {
            return Ok(grant);
        }
        self.issue_grant(&decision.payload.job.job, deployment, None, None)
    }

    /// Apply a correlated retry policy decision. A retry stays bounded by the caller's delivery
    /// mode and may only reuse the exact accepted deployment in this reference slice.
    pub fn apply_retry_decision(
        &self,
        decision: SignedRecordV1<RetryDecisionV1>,
    ) -> Result<Option<SignedRecordV1<ExecutionGrantV1>>, HomeError> {
        self.ensure_operational_write_authority()?;
        decision.validate().map_err(invalid)?;
        if decision.schema != SCHEMA_POLICY_V1 || !decision.verify() {
            return Err(HomeError::Unauthorized("retry decision signature is invalid".into()));
        }
        let (handle, failed_attempt, question_hash) = match &decision.payload {
            RetryDecisionV1::Retry { question_hash, job, failed_attempt, .. }
            | RetryDecisionV1::Stop { question_hash, job, failed_attempt, .. } => {
                (job.clone(), failed_attempt.clone(), question_hash.clone())
            }
        };
        if handle.home != self.config.home {
            return Err(HomeError::NotFound(handle.job.to_string()));
        }
        let expected_question = self.retry_question(&handle, &failed_attempt)?;
        let expected_hash = canonical_hash(&expected_question).map_err(invalid)?;
        if question_hash != expected_hash {
            return Err(HomeError::Unauthorized(
                "retry decision does not bind the exact outstanding signed question".into(),
            ));
        }
        self.trust.allow_retry_decision(&decision).map_err(|reason| {
            HomeError::Unauthorized(format!("retry decision refused: {reason}"))
        })?;
        match decision.payload {
            RetryDecisionV1::Retry {
                job,
                failed_attempt,
                next_attempt,
                deployment,
                not_before_unix_ms,
                ..
            } => {
                let job_id = &job.job;
                if next_attempt.home != self.config.home
                    || next_attempt.job != *job_id
                    || failed_attempt.home != self.config.home
                    || failed_attempt.job != *job_id
                {
                    return Err(HomeError::Conflict("retry decision names a different job".into()));
                }
                let deployment = *deployment;
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                self.ensure_authoritative_state(&state)?;
                let job = state
                    .jobs
                    .get(job_id)
                    .ok_or_else(|| HomeError::NotFound(job_id.to_string()))?;
                if canonical_hash(&deployment).map_err(invalid)?
                    != canonical_hash(&job.snapshot.spec.deployment).map_err(invalid)?
                {
                    return Err(HomeError::Unauthorized(
                        "retry selected a deployment outside the admitted candidate set".into(),
                    ));
                }
                if let Some(existing) =
                    state.grants.get(&(job_id.clone(), next_attempt.number)).cloned()
                {
                    return Ok(Some(existing));
                }
                if job.snapshot.state != JobStateV1::RetryPending {
                    return Err(HomeError::State(
                        "retry decision requires retry_pending state".into(),
                    ));
                }
                let Some(current_failed_attempt) = &job.snapshot.current_attempt else {
                    return Err(HomeError::State("retry has no failed attempt".into()));
                };
                if current_failed_attempt != &failed_attempt
                    || next_attempt.number != current_failed_attempt.number.saturating_add(1)
                    || next_attempt.number > job.snapshot.spec.delivery.max_attempts()
                {
                    return Err(HomeError::State(
                        "retry decision violates the numbered attempt bound".into(),
                    ));
                }
                let already_scheduled = job.events.iter().any(|event| {
                    matches!(
                        &event.payload.kind,
                        JobEventKindV1::RetryScheduled { next_attempt: existing, .. }
                            if existing == &next_attempt
                    )
                });
                if !already_scheduled {
                    let handle = job.snapshot.spec.handle.clone();
                    let cancel_requested = job.snapshot.cancel_requested;
                    let event = self.sign_event(
                        &state,
                        &handle,
                        JobStateV1::RetryPending,
                        cancel_requested,
                        None,
                        JobEventKindV1::RetryScheduled { next_attempt, not_before_unix_ms },
                    )?;
                    self.persist_and_apply(
                        &mut state,
                        HomeLedgerRecord { grant: None, receipt: None, events: vec![event] },
                    )?;
                }
                drop(state);
                self.issue_grant(job_id, deployment, None, None).map(Some)
            }
            RetryDecisionV1::Stop { job, failed_attempt, terminal_state, reason, .. } => {
                let job_id = &job.job;
                let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
                self.ensure_authoritative_state(&state)?;
                let job = state
                    .jobs
                    .get(job_id)
                    .ok_or_else(|| HomeError::NotFound(job_id.to_string()))?;
                if job.snapshot.state.is_terminal() {
                    return Ok(None);
                }
                if job.snapshot.state != JobStateV1::RetryPending {
                    return Err(HomeError::State("retry stop requires retry_pending state".into()));
                }
                if job.snapshot.current_attempt.as_ref() != Some(&failed_attempt) {
                    return Err(HomeError::Conflict(
                        "retry stop does not bind the current failed attempt".into(),
                    ));
                }
                let kind = match terminal_state {
                    JobStateV1::Failed => JobEventKindV1::Failed {
                        error: ValueRefV1::Inline {
                            value: serde_json::json!({"kind": "policy_stopped_retry", "reason": reason}),
                        },
                    },
                    JobStateV1::Cancelled => JobEventKindV1::Cancelled { reason },
                    JobStateV1::Indeterminate => JobEventKindV1::Indeterminate {
                        attempt: job.snapshot.current_attempt.clone().ok_or_else(|| {
                            HomeError::State(
                                "indeterminate retry stop has no current attempt".into(),
                            )
                        })?,
                        reason,
                        execution_may_have_occurred: false,
                    },
                    _ => return Err(HomeError::Invalid(
                        "retry policy cannot synthesize success or another non-failure terminal"
                            .into(),
                    )),
                };
                let event = self.sign_event(
                    &state,
                    &job.snapshot.spec.handle,
                    terminal_state,
                    job.snapshot.cancel_requested,
                    None,
                    kind,
                )?;
                self.persist_and_apply(
                    &mut state,
                    HomeLedgerRecord { grant: None, receipt: None, events: vec![event] },
                )?;
                Ok(None)
            }
        }
    }

    fn executor_target(&self, deployment: &DeploymentReceiptV1) -> Address {
        // CreatureIds are process-local routes, not durable executor identity. The operator's
        // current role binding selects the live executor at every locality grain; that executor
        // still must hold the receipt-pinned stable key and exact durable deployment or it refuses
        // the grant. A remote role is scoped to the exact deployment node and must have been
        // explicitly exposed by that host, so this is discovery without ambient Realm authority.
        if deployment.realm == self.config.realm && deployment.node == self.config.node {
            return Address::Role(Role::new(FUNCTION_EXECUTOR_ROLE));
        }
        let target =
            Address::NodeRole(NodeId(deployment.node.clone()), Role::new(FUNCTION_EXECUTOR_ROLE));
        if deployment.realm == self.config.realm {
            target
        } else {
            Address::Omega { realm: RealmId::new(&deployment.realm), target: Box::new(target) }
        }
    }

    /// Durably grant one exact attempt. The returned record is what the caller routes to
    /// `FUNCTION_EXECUTOR_ROLE` under `SCHEMA_EXECUTE_V1`.
    pub fn issue_grant(
        &self,
        job: &JobId,
        deployment: SignedRecordV1<DeploymentReceiptV1>,
        issued_at_unix_ms: Option<u64>,
        deadline_unix_ms: Option<u64>,
    ) -> Result<SignedRecordV1<ExecutionGrantV1>, HomeError> {
        self.ensure_operational_write_authority()?;
        deployment.validate().map_err(invalid)?;
        if gawdfn::verify_deployment_receipt(&deployment).is_err() {
            return Err(HomeError::Unauthorized("deployment receipt signature is invalid".into()));
        }
        self.trust
            .allow_deployment(&deployment)
            .map_err(|reason| HomeError::Unauthorized(format!("deployment refused: {reason}")))?;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        let record = state.jobs.get(job).ok_or_else(|| HomeError::NotFound(job.to_string()))?;
        if record.snapshot.state.is_terminal() || record.snapshot.cancel_requested {
            return Err(HomeError::State("terminal/cancel-requested job cannot dispatch".into()));
        }
        if !matches!(record.snapshot.state, JobStateV1::Queued | JobStateV1::RetryPending) {
            return Err(HomeError::State(format!(
                "job is {:?}, expected queued or retry_pending",
                record.snapshot.state
            )));
        }
        if deployment.payload.function != record.snapshot.spec.function.function {
            return Err(HomeError::Invalid("deployment does not pin the job function".into()));
        }
        if canonical_hash(&deployment).map_err(invalid)?
            != canonical_hash(&record.snapshot.spec.deployment).map_err(invalid)?
        {
            return Err(HomeError::Unauthorized(
                "alternate deployment requires an explicit signed placement decision".into(),
            ));
        }
        let number = record
            .snapshot
            .current_attempt
            .as_ref()
            .map_or(1, |attempt| attempt.number.saturating_add(1));
        if number == 0 || number > record.snapshot.spec.delivery.max_attempts() {
            return Err(HomeError::State("delivery attempt bound exhausted".into()));
        }
        let attempt = AttemptId { home: self.config.home.clone(), job: job.clone(), number };
        let grant = ExecutionGrantV1 {
            attempt: attempt.clone(),
            request_hash: record.snapshot.spec.request_hash.clone(),
            home_epoch: self.config.epoch,
            home_route_sequence: state.custody.active_route_sequence()?,
            home_realm: self.config.realm.clone(),
            home_node: self.config.node.clone(),
            home_coordinator: self.config.coordinator.clone(),
            owner: self.config.home.clone(),
            authority: self.config.authority.clone(),
            function: record.snapshot.spec.function.function.clone(),
            deployment,
            input: record.snapshot.spec.input.clone(),
            delivery: record.snapshot.spec.delivery.clone(),
            grant_sequence: state.next_grant_sequence,
            issued_at_unix_ms,
            deadline_unix_ms,
        };
        grant.validate().map_err(invalid)?;
        let signed_grant = SignedRecordV1::sign(SCHEMA_EXECUTE_V1, grant, self.signer.as_ref())
            .map_err(signing)?;
        let grant_hash = canonical_hash(&signed_grant).map_err(invalid)?;
        let handle = record.snapshot.spec.handle.clone();
        let event = self.sign_event(
            &state,
            &handle,
            JobStateV1::Dispatching,
            false,
            issued_at_unix_ms,
            JobEventKindV1::DispatchGranted { grant_hash, attempt },
        )?;
        self.persist_and_apply(
            &mut state,
            HomeLedgerRecord {
                grant: Some(signed_grant.clone()),
                receipt: None,
                events: vec![event],
            },
        )?;
        Ok(signed_grant)
    }

    pub fn apply_executor_receipt(
        &self,
        receipt: SignedRecordV1<ExecutionReceiptV1>,
    ) -> Result<ApplyReceiptOutcome, HomeError> {
        self.ensure_operational_write_authority()?;
        receipt.validate().map_err(invalid)?;
        let key = (
            receipt.payload.attempt.job.clone(),
            receipt.payload.attempt.number,
            receipt.payload.sequence,
        );
        let receipt_hash = canonical_hash(&receipt).map_err(invalid)?;
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        if let Some(existing) = state.receipts.get(&key) {
            if existing == &receipt_hash {
                let event = state
                    .jobs
                    .get(&receipt.payload.attempt.job)
                    .and_then(|job| {
                        job.events.iter().find(|event| {
                            event
                                .payload
                                .foreign_receipt
                                .as_deref()
                                .and_then(|foreign| canonical_hash(foreign).ok())
                                .is_some_and(|hash| hash == receipt_hash)
                        })
                    })
                    .cloned()
                    .ok_or_else(|| HomeError::State("receipt dedup state is incomplete".into()))?;
                return Ok(ApplyReceiptOutcome::Duplicate(event));
            }
            return Err(HomeError::Conflict(format!(
                "{} attempt {} receipt sequence {}",
                receipt.payload.attempt.job,
                receipt.payload.attempt.number,
                receipt.payload.sequence
            )));
        }
        let attempt_key = (receipt.payload.attempt.job.clone(), receipt.payload.attempt.number);
        let grant = state
            .grants
            .get(&attempt_key)
            .ok_or_else(|| HomeError::State("receipt has no durable attempt grant".into()))?;
        gawdfn::verify_execution_receipt(&receipt, grant)
            .map_err(|error| HomeError::Unauthorized(error.to_string()))?;
        self.trust.allow_executor_receipt(&receipt, &grant.payload.deployment).map_err(
            |reason| HomeError::Unauthorized(format!("executor receipt refused: {reason}")),
        )?;
        let job = state
            .jobs
            .get(&receipt.payload.attempt.job)
            .ok_or_else(|| HomeError::NotFound(receipt.payload.attempt.job.to_string()))?;
        let last_for_attempt =
            state.highest_receipt_sequences.get(&attempt_key).copied().unwrap_or(0);
        if receipt.payload.sequence == last_for_attempt {
            return Err(HomeError::State(format!(
                "receipt sequence {} matches the high-water mark but has no retained identity",
                receipt.payload.sequence
            )));
        }
        let late = receipt.payload.sequence < last_for_attempt || job.snapshot.state.is_terminal();
        let (state_after, cancel_requested, kind) = if late {
            self.require_receipt_values(&receipt.payload.stage)?;
            (
                job.snapshot.state,
                job.snapshot.cancel_requested,
                JobEventKindV1::LateReceipt {
                    attempt: receipt.payload.attempt.clone(),
                    observed: receipt.payload.stage.clone(),
                },
            )
        } else {
            self.event_from_receipt(&job.snapshot, &receipt.payload)?
        };
        let event = self.sign_event_with_receipt(
            &state,
            &job.snapshot.spec.handle,
            state_after,
            cancel_requested,
            receipt.payload.observed_at_unix_ms,
            kind,
            Some(receipt.clone()),
        )?;
        self.persist_and_apply(
            &mut state,
            HomeLedgerRecord { grant: None, receipt: Some(receipt), events: vec![event.clone()] },
        )?;
        Ok(ApplyReceiptOutcome::Applied(event))
    }

    pub fn control(
        &self,
        request: SignedRecordV1<JobControlV1>,
    ) -> Result<SignedRecordV1<JobEventV1>, HomeError> {
        self.ensure_operational_write_authority()?;
        if matches!(request.payload.kind, JobControlKindV1::ProposeChild { .. }) {
            return self.propose_child(request);
        }
        request.validate().map_err(invalid)?;
        if let JobControlKindV1::Steer { value } = &request.payload.kind {
            self.require_value(value)?;
        }
        if request.schema != SCHEMA_JOB_V1 || !request.verify() {
            return Err(HomeError::Unauthorized("invalid job control signature".into()));
        }
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        let job = state
            .jobs
            .get(&request.payload.handle.job)
            .ok_or_else(|| HomeError::NotFound(request.payload.handle.job.to_string()))?;
        if request.payload.handle.home != self.config.home
            || request.payload.expected_home_epoch != self.config.epoch
        {
            return Err(HomeError::State("control names the wrong home epoch".into()));
        }
        let owner = request.signer == self.config.home.as_str();
        let controller =
            job.snapshot.spec.access.controllers.iter().any(|id| id.as_str() == request.signer);
        if !owner && !controller {
            return Err(HomeError::Unauthorized("signer is not owner or controller".into()));
        }
        if matches!(request.payload.kind, JobControlKindV1::AccessUpdate { .. }) && !owner {
            return Err(HomeError::Unauthorized("only the owner may update access".into()));
        }
        let control_key = (request.payload.handle.job.clone(), request.payload.control.0.clone());
        let control_hash = canonical_hash(&request).map_err(invalid)?;
        if let Some(existing_hash) = state.controls.get(&control_key) {
            if existing_hash != &control_hash {
                return Err(HomeError::Conflict(format!(
                    "control `{}` changed after durable acceptance for job `{}`",
                    request.payload.control, request.payload.handle.job
                )));
            }
            return job
                .events
                .iter()
                .find(|event| {
                    matches!(
                        &event.payload.kind,
                        JobEventKindV1::ControlRequested { request: durable, .. }
                            if durable.payload.control == request.payload.control
                    ) || matches!(
                        &event.payload.kind,
                        JobEventKindV1::AccessUpdated { control, request_hash, .. }
                            if control == &request.payload.control && request_hash == &control_hash
                    )
                })
                .cloned()
                .ok_or_else(|| HomeError::State("control dedup state is incomplete".into()));
        }
        if state.control_counts.get(&request.payload.handle.job).copied().unwrap_or(0)
            >= MAX_JOB_CONTROLS
        {
            return Err(HomeError::Capacity(format!("job controls exceed {MAX_JOB_CONTROLS}")));
        }
        if job.snapshot.state.is_terminal() {
            return Err(HomeError::State("control arrived after terminal state".into()));
        }
        if matches!(request.payload.kind, JobControlKindV1::Steer { .. })
            && (!matches!(job.snapshot.state, JobStateV1::Dispatching | JobStateV1::Running)
                || job.snapshot.current_attempt.is_none())
        {
            return Err(HomeError::State(
                "steer requires an active dispatching or running attempt".into(),
            ));
        }
        let handle = job.snapshot.spec.handle.clone();
        let selected_attempt = job.snapshot.current_attempt.clone();
        let mut state_after = job.snapshot.state;
        let mut cancel_requested = job.snapshot.cancel_requested;
        let kind = match &request.payload.kind {
            JobControlKindV1::Cancel { .. } => {
                cancel_requested = true;
                if matches!(
                    job.snapshot.state,
                    JobStateV1::Queued | JobStateV1::Blocked | JobStateV1::RetryPending
                ) {
                    state_after = JobStateV1::Cancelled;
                }
                JobEventKindV1::ControlRequested {
                    request: Box::new(request.clone()),
                    attempt: selected_attempt.clone(),
                }
            }
            JobControlKindV1::AccessUpdate {
                add_readers,
                remove_readers,
                add_controllers,
                remove_controllers,
            } => {
                let access = update_access(
                    &job.snapshot.spec.access,
                    add_readers,
                    remove_readers,
                    add_controllers,
                    remove_controllers,
                )?;
                JobEventKindV1::AccessUpdated {
                    control: request.payload.control.clone(),
                    request_hash: control_hash,
                    access,
                }
            }
            _ => JobEventKindV1::ControlRequested {
                request: Box::new(request.clone()),
                attempt: selected_attempt,
            },
        };
        let event = self.sign_event(
            &state,
            &handle,
            state_after,
            cancel_requested,
            request.payload.issued_at_unix_ms,
            kind,
        )?;
        self.persist_and_apply(
            &mut state,
            HomeLedgerRecord { grant: None, receipt: None, events: vec![event.clone()] },
        )?;
        Ok(event)
    }

    /// Atomically bind a causal spawn to its parent event and create the child submission. The
    /// child caller idempotency key derives the child JobId; `(parent attempt, spawn_key)` is the
    /// durable dedup key. The child submission must carry the same authorized owner/controller
    /// signature as the outer proposal, so spawning never requires exporting the Abode root key to
    /// a Function. A replay with changed parent/request material is a conflict.
    fn propose_child(
        &self,
        request: SignedRecordV1<JobControlV1>,
    ) -> Result<SignedRecordV1<JobEventV1>, HomeError> {
        request.validate().map_err(invalid)?;
        if request.schema != SCHEMA_JOB_V1 || !request.verify() {
            return Err(HomeError::Unauthorized("invalid causal child control signature".into()));
        }
        let (
            parent_attempt,
            parent_event_hash,
            spawn_key,
            child_request_hash,
            submit,
            resolution,
            deployment,
        ) = match request.payload.kind.clone() {
            JobControlKindV1::ProposeChild {
                parent_attempt,
                parent_event_hash,
                spawn_key,
                child_request_hash,
                submit,
                resolution,
                deployment,
            } => (
                parent_attempt,
                parent_event_hash,
                spawn_key,
                child_request_hash,
                *submit,
                *resolution,
                *deployment,
            ),
            _ => return Err(HomeError::Invalid("control is not a child proposal".into())),
        };
        if submit.signer != request.signer {
            return Err(HomeError::Unauthorized(
                "child submission and causal proposal must have the same signer".into(),
            ));
        }

        // Authenticate the owner/controller before consulting injected trust or blob stores. The
        // state is checked again below after those calls so a concurrent access update cannot race
        // an accepted child into existence.
        {
            let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            self.ensure_authoritative_state(&state)?;
            if request.payload.handle.home != self.config.home
                || request.payload.expected_home_epoch != self.config.epoch
            {
                return Err(HomeError::State("child proposal names the wrong home epoch".into()));
            }
            let parent = state
                .jobs
                .get(&request.payload.handle.job)
                .ok_or_else(|| HomeError::NotFound(request.payload.handle.job.to_string()))?;
            let owner = request.signer == self.config.home.as_str();
            let controller = parent
                .snapshot
                .spec
                .access
                .controllers
                .iter()
                .any(|id| id.as_str() == request.signer);
            if !owner && !controller {
                return Err(HomeError::Unauthorized("signer is not owner or controller".into()));
            }
        }

        let mut prepared =
            self.prepare_submission_signed_by(submit, resolution, deployment, &request.signer)?;
        if prepared.request_hash != child_request_hash {
            return Err(HomeError::Conflict(
                "child request hash changed for the proposed spawn".into(),
            ));
        }
        if prepared.spec.parent.as_ref() != Some(&request.payload.handle) {
            return Err(HomeError::Invalid(
                "atomic child submission must name the controlled job as parent".into(),
            ));
        }
        if prepared.handle == request.payload.handle {
            return Err(HomeError::Conflict("a job cannot spawn itself".into()));
        }

        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        if request.payload.handle.home != self.config.home
            || request.payload.expected_home_epoch != self.config.epoch
        {
            return Err(HomeError::State("child proposal names the wrong home epoch".into()));
        }
        let parent = state
            .jobs
            .get(&request.payload.handle.job)
            .ok_or_else(|| HomeError::NotFound(request.payload.handle.job.to_string()))?;
        let owner = request.signer == self.config.home.as_str();
        let controller =
            parent.snapshot.spec.access.controllers.iter().any(|id| id.as_str() == request.signer);
        if !owner && !controller {
            return Err(HomeError::Unauthorized("signer is not owner or controller".into()));
        }
        if parent.snapshot.spec.handle.home != prepared.handle.home
            || parent.snapshot.spec.root.home != prepared.handle.home
        {
            return Err(HomeError::Invalid(
                "child, parent, and workflow root must remain in one Home".into(),
            ));
        }
        prepared.spec.root = parent.snapshot.spec.root.clone();
        prepared.spec.validate().map_err(invalid)?;
        if parent.snapshot.state.is_terminal() {
            return Err(HomeError::State(
                "child proposal arrived after terminal parent state".into(),
            ));
        }
        let parent_event_exists = parent.events.iter().any(|event| {
            event_attempt(&event.payload.kind) == Some(&parent_attempt)
                && canonical_hash(event).is_ok_and(|hash| hash == parent_event_hash)
        });
        if !parent_event_exists {
            return Err(HomeError::Unauthorized(
                "parent event hash does not name an event for the proposed attempt".into(),
            ));
        }
        let spawn_key_tuple =
            (parent_attempt.job.clone(), parent_attempt.number, spawn_key.clone());
        if let Some(existing) = state.child_spawns.get(&spawn_key_tuple) {
            return if existing.parent_event_hash == parent_event_hash
                && existing.child_request_hash == child_request_hash
                && existing.child == prepared.handle
                && existing.root == prepared.spec.root
            {
                Ok(existing.event.clone())
            } else {
                Err(HomeError::Conflict(format!(
                    "child spawn `{spawn_key}` changed after durable acceptance"
                )))
            };
        }
        if state.control_counts.get(&request.payload.handle.job).copied().unwrap_or(0)
            >= MAX_JOB_CONTROLS
        {
            return Err(HomeError::Capacity(format!("job controls exceed {MAX_JOB_CONTROLS}")));
        }
        if state.jobs.contains_key(&prepared.handle.job) {
            return Err(HomeError::Conflict(format!(
                "child job `{}` already exists outside this spawn",
                prepared.handle.job
            )));
        }
        if state.jobs.len() >= self.config.max_jobs {
            return Err(HomeError::Capacity(format!(
                "{} jobs reaches cap {}",
                state.jobs.len(),
                self.config.max_jobs
            )));
        }
        let parent_state = parent.snapshot.state;
        let parent_cancel_requested = parent.snapshot.cancel_requested;
        let parent_handle = parent.snapshot.spec.handle.clone();
        let parent_event = self.sign_event(
            &state,
            &parent_handle,
            parent_state,
            parent_cancel_requested,
            request.payload.issued_at_unix_ms,
            JobEventKindV1::ChildSpawned {
                parent_attempt,
                parent_event_hash,
                spawn_key,
                child: prepared.handle.clone(),
                root: prepared.spec.root.clone(),
                child_request_hash,
            },
        )?;
        let child_event = self.sign_event(
            &state,
            &prepared.handle,
            JobStateV1::Queued,
            false,
            prepared.spec.accepted_at_unix_ms,
            JobEventKindV1::Submitted { spec: Box::new(prepared.spec) },
        )?;
        self.persist_and_apply(
            &mut state,
            HomeLedgerRecord {
                grant: None,
                receipt: None,
                events: vec![parent_event.clone(), child_event],
            },
        )?;
        Ok(parent_event)
    }

    pub fn get(&self, job: &JobId) -> Result<JobSnapshotV1, HomeError> {
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        self.snapshot_from_state(&state, job)
    }

    fn snapshot_from_state(
        &self,
        state: &HomeState,
        job: &JobId,
    ) -> Result<JobSnapshotV1, HomeError> {
        let mut snapshot = state
            .jobs
            .get(job)
            .map(|record| record.snapshot.clone())
            .ok_or_else(|| HomeError::NotFound(job.to_string()))?;
        // A snapshot is a present-tense assertion by the active Home. Historical events retain
        // their original epoch proofs independently.
        snapshot.home_epoch = self.config.epoch;
        snapshot.authority = self.config.authority.clone();
        Ok(snapshot)
    }

    #[cfg(test)]
    fn authorize_get(
        &self,
        env: &Envelope,
        request: &SignedRecordV1<JobGetRelayV1>,
    ) -> Result<JobHandleV1, HomeError> {
        gawdfn::verify_job_get_relay(request)
            .map_err(|error| HomeError::Unauthorized(error.to_string()))?;
        self.require_read_route(env, &request.payload.reply_to)?;
        self.trust
            .allow_read_relay(&request.signer, &request.payload.caller.signer)
            .map_err(HomeError::Unauthorized)?;
        self.authorize_reader(
            &request.payload.caller.payload.handle,
            &request.payload.caller.signer,
        )?;
        Ok(request.payload.caller.payload.handle.clone())
    }

    fn require_read_route(&self, env: &Envelope, expected: &str) -> Result<(), HomeError> {
        let actual = env.header.reply_to.as_ref().ok_or_else(|| {
            HomeError::Unauthorized("private job read has no return route".into())
        })?;
        let actual = serde_json::to_string(actual).map_err(|error| invalid(error.to_string()))?;
        if actual == expected {
            Ok(())
        } else {
            Err(HomeError::Unauthorized(
                "private job read return route differs from its signed relay endorsement".into(),
            ))
        }
    }

    #[cfg(test)]
    fn authorize_reader(&self, handle: &JobHandleV1, signer: &str) -> Result<(), HomeError> {
        if handle.home != self.config.home {
            return Err(HomeError::NotFound(handle.job.to_string()));
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.authorize_reader_from_state(&state, handle, signer)
    }

    fn authorize_reader_from_state(
        &self,
        state: &HomeState,
        handle: &JobHandleV1,
        signer: &str,
    ) -> Result<(), HomeError> {
        if handle.home != self.config.home {
            return Err(HomeError::NotFound(handle.job.to_string()));
        }
        let job = state
            .jobs
            .get(&handle.job)
            .ok_or_else(|| HomeError::NotFound(handle.job.to_string()))?;
        let allowed = signer == self.config.home.as_str()
            || job.snapshot.spec.access.readers.iter().any(|id| id.as_str() == signer)
            || job.snapshot.spec.access.controllers.iter().any(|id| id.as_str() == signer);
        if allowed {
            Ok(())
        } else {
            Err(HomeError::Unauthorized("signer is not a job reader".into()))
        }
    }

    pub fn events(&self, query: &EventQueryV1) -> Result<EventPageV1, HomeError> {
        query.validate().map_err(invalid)?;
        if query.handle.home != self.config.home {
            return Err(HomeError::NotFound(query.handle.job.to_string()));
        }
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        self.events_from_state(&state, query)
    }

    fn events_from_state(
        &self,
        state: &HomeState,
        query: &EventQueryV1,
    ) -> Result<EventPageV1, HomeError> {
        let job = state
            .jobs
            .get(&query.handle.job)
            .ok_or_else(|| HomeError::NotFound(query.handle.job.to_string()))?;
        let after = query.after_sequence.unwrap_or(0);
        let limit = usize::from(query.limit).min(MAX_EVENT_PAGE_ITEMS);
        let mut eligible = job.events.iter().filter(|event| event.payload.sequence > after);
        let sizing_page = EventPageV1 {
            handle: query.handle.clone(),
            events: Vec::new(),
            next_after_sequence: None,
        };
        let sizing_response = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventPageResponseV1 {
                request_hash: format!("sha256:{}", "0".repeat(64)),
                home_epoch: self.config.epoch,
                authority: self.config.authority.clone(),
                page: sizing_page,
            },
            self.signer.as_ref(),
        )
        .map_err(signing)?;
        let base_bytes =
            serde_json::to_vec(&JobMessageV1::EventPage { response: Box::new(sizing_response) })
                .map_err(|error| HomeError::Invalid(error.to_string()))?
                .len();
        // A populated `next_after_sequence` is at most a u64 plus its fixed JSON key. Reserve a
        // little more than that so the final signed wrapper is guaranteed to remain in-bounds.
        let mut encoded_bytes = base_bytes.saturating_add(64);
        let mut events = Vec::new();
        let mut more = false;
        for event in eligible.by_ref().take(limit) {
            let event_bytes = serde_json::to_vec(event)
                .map_err(|error| HomeError::Invalid(error.to_string()))?
                .len();
            let separator = usize::from(!events.is_empty());
            if encoded_bytes.saturating_add(separator).saturating_add(event_bytes)
                > MAX_PRIVATE_READ_MESSAGE_BYTES
            {
                more = true;
                break;
            }
            encoded_bytes += separator + event_bytes;
            events.push(event.clone());
        }
        if !more {
            more = eligible.next().is_some();
        }
        if events.is_empty() && more {
            return Err(HomeError::Capacity(
                "one validated job event cannot fit the bounded event-page response".into(),
            ));
        }
        let next_after_sequence =
            if more { events.last().map(|event| event.payload.sequence) } else { None };
        let page = EventPageV1 { handle: query.handle.clone(), events, next_after_sequence };
        page.validate().map_err(invalid)?;
        Ok(page)
    }

    fn event_from_receipt(
        &self,
        snapshot: &JobSnapshotV1,
        receipt: &ExecutionReceiptV1,
    ) -> Result<(JobStateV1, bool, JobEventKindV1), HomeError> {
        self.require_receipt_values(&receipt.stage)?;
        if let ExecutionStageV1::Succeeded { result } = &receipt.stage {
            require_result_recipient_wraps(result, &snapshot.spec.result_recipients)?;
        }
        let attempt = receipt.attempt.clone();
        let cancel = snapshot.cancel_requested;
        Ok(match &receipt.stage {
            ExecutionStageV1::Claimed => (
                JobStateV1::Dispatching,
                cancel,
                JobEventKindV1::Claimed { attempt, executor: receipt.executor.clone() },
            ),
            ExecutionStageV1::Started => {
                (JobStateV1::Running, cancel, JobEventKindV1::Started { attempt })
            }
            ExecutionStageV1::Progress { sequence, progress } => (
                snapshot.state,
                cancel,
                JobEventKindV1::Progress {
                    attempt,
                    sequence: *sequence,
                    progress: progress.clone(),
                },
            ),
            ExecutionStageV1::Checkpoint { sequence, checkpoint } => (
                snapshot.state,
                cancel,
                JobEventKindV1::Checkpoint {
                    attempt,
                    sequence: *sequence,
                    checkpoint: checkpoint.clone(),
                },
            ),
            ExecutionStageV1::Succeeded { result } => (
                JobStateV1::Succeeded,
                cancel,
                JobEventKindV1::Succeeded { attempt, result: result.clone() },
            ),
            ExecutionStageV1::Failed { error, retryable } => {
                let bounded = receipt.attempt.number < snapshot.spec.delivery.max_attempts();
                let retry =
                    bounded && matches!(snapshot.spec.delivery, DeliveryModeV1::AtLeastOnce { .. });
                (
                    if retry { JobStateV1::RetryPending } else { JobStateV1::Failed },
                    cancel,
                    JobEventKindV1::AttemptFailed {
                        attempt,
                        error: error.clone(),
                        retryable: *retryable,
                    },
                )
            }
            ExecutionStageV1::Cancelled { reason } => {
                (JobStateV1::Cancelled, true, JobEventKindV1::Cancelled { reason: reason.clone() })
            }
            ExecutionStageV1::Indeterminate { reason, execution_may_have_occurred } => {
                let retry = matches!(snapshot.spec.delivery, DeliveryModeV1::AtLeastOnce { .. })
                    && receipt.attempt.number < snapshot.spec.delivery.max_attempts();
                (
                    if retry {
                        JobStateV1::RetryPending
                    } else if matches!(snapshot.spec.delivery, DeliveryModeV1::AtMostOnce) {
                        JobStateV1::Indeterminate
                    } else {
                        JobStateV1::Failed
                    },
                    cancel,
                    JobEventKindV1::Indeterminate {
                        attempt,
                        reason: reason.clone(),
                        execution_may_have_occurred: *execution_may_have_occurred,
                    },
                )
            }
            ExecutionStageV1::ControlAcknowledged { control, disposition, .. } => (
                snapshot.state,
                cancel,
                JobEventKindV1::ControlAcknowledged {
                    control: control.clone(),
                    attempt,
                    disposition: *disposition,
                },
            ),
            ExecutionStageV1::ControlQueued { control } => (
                snapshot.state,
                cancel,
                JobEventKindV1::ControlQueued { control: control.clone(), attempt },
            ),
        })
    }

    fn require_receipt_values(&self, stage: &ExecutionStageV1) -> Result<(), HomeError> {
        match stage {
            ExecutionStageV1::Progress { progress, .. } => self.require_value(progress)?,
            ExecutionStageV1::Checkpoint { checkpoint, .. } => self.require_value(checkpoint)?,
            ExecutionStageV1::Succeeded { result } => self.require_value(result)?,
            ExecutionStageV1::Failed { error, .. } => self.require_value(error)?,
            _ => {}
        }
        Ok(())
    }

    fn sign_event(
        &self,
        state: &HomeState,
        handle: &JobHandleV1,
        state_after: JobStateV1,
        cancel_requested: bool,
        occurred_at_unix_ms: Option<u64>,
        kind: JobEventKindV1,
    ) -> Result<SignedRecordV1<JobEventV1>, HomeError> {
        self.sign_event_with_receipt(
            state,
            handle,
            state_after,
            cancel_requested,
            occurred_at_unix_ms,
            kind,
            None,
        )
    }

    // These arguments are the exact signed event fields. Keeping them visible at each call site
    // makes foreign-receipt binding auditable instead of hiding it behind a mutable builder.
    #[allow(clippy::too_many_arguments)]
    fn sign_event_with_receipt(
        &self,
        state: &HomeState,
        handle: &JobHandleV1,
        state_after: JobStateV1,
        cancel_requested: bool,
        occurred_at_unix_ms: Option<u64>,
        kind: JobEventKindV1,
        foreign_receipt: Option<SignedRecordV1<ExecutionReceiptV1>>,
    ) -> Result<SignedRecordV1<JobEventV1>, HomeError> {
        self.ensure_authoritative_state(state)?;
        let sequence = state.jobs.get(&handle.job).map_or(1, |job| job.snapshot.last_sequence + 1);
        let event = JobEventV1 {
            handle: handle.clone(),
            home_epoch: self.config.epoch,
            authority: self.config.authority.clone(),
            sequence,
            occurred_at_unix_ms,
            state_after,
            cancel_requested,
            kind,
            foreign_receipt: foreign_receipt.map(Box::new),
        };
        event.validate().map_err(invalid)?;
        SignedRecordV1::sign(SCHEMA_JOB_V1, event, self.signer.as_ref()).map_err(signing)
    }

    fn persist_and_apply(
        &self,
        state: &mut HomeState,
        record: HomeLedgerRecord,
    ) -> Result<(), HomeError> {
        self.ensure_authoritative_state(state)?;
        validate_ledger_record(&record, &self.config)?;
        // Validate against a bounded shadow containing only the jobs and indexes this one record
        // can touch. This keeps the append boundary transactional without cloning global retained
        // history for every progress event.
        preflight_ledger_transition(&self.config, state, &record)?;
        let reserved_after = home_reservations_after(state, &record)?;
        let remaining = self.journal.remaining_records()?;
        if remaining <= reserved_after {
            return Err(HomeError::Capacity(format!(
                "Home journal must preserve {reserved_after} terminal/control-ack record slots"
            )));
        }
        self.journal.append(record.clone())?;
        // The mutex remains held between preflight and this application, so the same transition
        // cannot become invalid. Any error here is an internal invariant defect, not input that can
        // cross the fsync boundary.
        apply_ledger_record(&self.config, state, &record)
    }

    fn require_value(&self, value: &ValueRefV1) -> Result<(), HomeError> {
        value
            .verify_available(self.blobs.as_ref())
            .map_err(|reason| HomeError::Invalid(format!("job blob unavailable: {reason}")))?;
        let ValueRefV1::Sealed { sealed } = value else { return Ok(()) };
        let mut home_wraps =
            sealed.recipients.iter().filter(|wrap| wrap.recipient == self.config.home);
        let Some(home_wrap) = home_wraps.next() else { return Ok(()) };
        if home_wraps.next().is_some() {
            return Err(HomeError::Invalid(
                "sealed value carries multiple envelopes for its Home".into(),
            ));
        }
        let binding = self.current_recipient_binding()?;
        if sealed.suite != binding.payload.suite
            || home_wrap.binding_hash != canonical_hash(&binding).map_err(invalid)?
        {
            return Err(HomeError::Unauthorized(
                "sealed value Home envelope does not use the current recipient binding".into(),
            ));
        }
        Ok(())
    }

    fn current_recipient_binding(
        &self,
    ) -> Result<SignedRecordV1<RecipientKeyBindingV1>, HomeError> {
        let mut cached =
            self.current_recipient_binding.lock().unwrap_or_else(|poison| poison.into_inner());
        if let Some(binding) = cached.as_ref() {
            return Ok(binding.clone());
        }
        let binding = self.rewrapper.current_binding().map_err(|error| {
            HomeError::State(format!("custody key rewrapper unavailable: {error}"))
        })?;
        custody::verify_current_recipient_binding(&self.config, &binding)?;
        *cached = Some(binding.clone());
        Ok(binding)
    }

    /// Build the executor-facing endorsement only after the caller control event is durable.
    pub fn endorsed_control(
        &self,
        caller_request: SignedRecordV1<JobControlV1>,
        durable_event: &SignedRecordV1<JobEventV1>,
    ) -> Result<Option<(SignedRecordV1<ExecutionControlV1>, Address)>, HomeError> {
        self.ensure_operational_write_authority()?;
        let (durable_request, attempt) = match &durable_event.payload.kind {
            JobEventKindV1::ControlRequested { request, attempt } => {
                (request.as_ref(), attempt.as_ref())
            }
            _ => return Ok(None),
        };
        if durable_request != &caller_request {
            return Err(HomeError::Conflict(
                "durable control event does not contain the exact signed caller request".into(),
            ));
        }
        let Some(attempt) = attempt else { return Ok(None) };
        let state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.ensure_authoritative_state(&state)?;
        state
            .jobs
            .get(&caller_request.payload.handle.job)
            .ok_or_else(|| HomeError::NotFound(caller_request.payload.handle.job.to_string()))?;
        let grant = state
            .grants
            .get(&(attempt.job.clone(), attempt.number))
            .ok_or_else(|| HomeError::State("controlled attempt has no durable grant".into()))?;
        let endorsed = self.sign_control_endorsement(
            caller_request,
            durable_event,
            grant,
            state.custody.active_route_sequence()?,
        )?;
        Ok(Some((endorsed, self.executor_target(&grant.payload.deployment.payload))))
    }

    fn sign_control_endorsement(
        &self,
        caller_request: SignedRecordV1<JobControlV1>,
        durable_event: &SignedRecordV1<JobEventV1>,
        grant: &SignedRecordV1<ExecutionGrantV1>,
        home_route_sequence: u64,
    ) -> Result<SignedRecordV1<ExecutionControlV1>, HomeError> {
        let endorsed = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionControlV1 {
                caller_request,
                accepted_event: Box::new(durable_event.clone()),
                attempt: grant.payload.attempt.clone(),
                grant_hash: canonical_hash(grant).map_err(invalid)?,
                home_epoch: self.config.epoch,
                home_route_sequence,
                home_sequence: durable_event.payload.sequence,
                home_realm: self.config.realm.clone(),
                home_node: self.config.node.clone(),
                home_coordinator: self.config.coordinator.clone(),
                authority: self.config.authority.clone(),
            },
            self.signer.as_ref(),
        )
        .map_err(signing)?;
        gawdfn::verify_execution_control(&endorsed).map_err(invalid)?;
        Ok(endorsed)
    }

    fn append_policy_question(&self, outcome: &mut Outcome, handle: &JobHandleV1) {
        let Ok(Some(question)) = self.placement_question(handle) else {
            return;
        };
        outcome.push(
            Dispatch::to(
                Address::Role(Role::new(FUNCTION_POLICY_ROLE)),
                aether::wire::to_bytes(&PolicyMessageV1::SelectDeployment {
                    question: Box::new(question),
                }),
            )
            .with_schema(SCHEMA_POLICY_V1),
        );
    }

    fn append_retry_question(&self, outcome: &mut Outcome, event: &SignedRecordV1<JobEventV1>) {
        if event.payload.state_after != JobStateV1::RetryPending {
            return;
        }
        let Some((attempt, error, retryable)) = retry_failure(&event.payload.kind) else {
            return;
        };
        let Ok(corr) = retry_correlation(&attempt) else {
            return;
        };
        let _ = (error, retryable);
        let handle = JobHandleV1 { home: attempt.home.clone(), job: attempt.job.clone() };
        let Ok(question) = self.retry_question(&handle, &attempt) else { return };
        outcome.push(
            Dispatch::to(
                Address::Role(Role::new(FUNCTION_POLICY_ROLE)),
                aether::wire::to_bytes(&PolicyMessageV1::DecideRetry {
                    question: Box::new(question),
                }),
            )
            .with_schema(SCHEMA_POLICY_V1)
            .with_corr(corr),
        );
    }

    fn for_each_recovery_key(&self, state: &HomeState, mut visit: impl FnMut(HomeRecoveryKey)) {
        for (job_id, job) in &state.jobs {
            match job.snapshot.state {
                JobStateV1::Queued => visit(HomeRecoveryKey {
                    job: job_id.clone(),
                    kind: HOME_RECOVERY_PLACEMENT,
                    sequence: 0,
                }),
                JobStateV1::RetryPending => visit(HomeRecoveryKey {
                    job: job_id.clone(),
                    kind: HOME_RECOVERY_RETRY,
                    sequence: 0,
                }),
                JobStateV1::Dispatching | JobStateV1::Running => {
                    let Some(attempt) = &job.snapshot.current_attempt else { continue };
                    if !state.grants.contains_key(&(attempt.job.clone(), attempt.number)) {
                        continue;
                    }
                    visit(HomeRecoveryKey {
                        job: job_id.clone(),
                        kind: HOME_RECOVERY_ATTEMPT,
                        sequence: 0,
                    });
                    for event in &job.events {
                        let JobEventKindV1::ControlRequested {
                            request,
                            attempt: Some(control_attempt),
                        } = &event.payload.kind
                        else {
                            continue;
                        };
                        let control_key = (
                            request.payload.handle.job.clone(),
                            request.payload.control.as_str().to_string(),
                        );
                        if control_attempt == attempt
                            && state
                                .forwarded_controls
                                .get(&control_key)
                                .is_some_and(|control| control.acknowledged_receipt_hash.is_none())
                        {
                            visit(HomeRecoveryKey {
                                job: job_id.clone(),
                                kind: HOME_RECOVERY_CONTROL,
                                sequence: event.payload.sequence,
                            });
                        }
                    }
                }
                JobStateV1::Blocked
                | JobStateV1::Succeeded
                | JobStateV1::Failed
                | JobStateV1::Cancelled
                | JobStateV1::Indeterminate => {}
            }
        }
    }

    fn recovery_dispatch_for_key(
        &self,
        state: &HomeState,
        key: &HomeRecoveryKey,
    ) -> Option<Dispatch> {
        let job = state.jobs.get(&key.job)?;
        match key.kind {
            HOME_RECOVERY_PLACEMENT if job.snapshot.state == JobStateV1::Queued => {
                let question = PlacementQuestionV1 {
                    job: job.snapshot.spec.handle.clone(),
                    home_epoch: self.config.epoch,
                    authority: self.config.authority.clone(),
                    function: job.snapshot.spec.function.function.clone(),
                    candidates: vec![job.snapshot.spec.deployment.clone()],
                    evidence: job.snapshot.spec.evidence.clone(),
                };
                let question =
                    SignedRecordV1::sign(SCHEMA_POLICY_V1, question, self.signer.as_ref()).ok()?;
                gawdfn::verify_placement_question(&question).ok()?;
                Some(
                    Dispatch::to(
                        Address::Role(Role::new(FUNCTION_POLICY_ROLE)),
                        aether::wire::to_bytes(&PolicyMessageV1::SelectDeployment {
                            question: Box::new(question),
                        }),
                    )
                    .with_schema(SCHEMA_POLICY_V1),
                )
            }
            HOME_RECOVERY_RETRY if job.snapshot.state == JobStateV1::RetryPending => {
                let (attempt, error, retryable) =
                    job.events.iter().rev().find_map(|event| retry_failure(&event.payload.kind))?;
                let correlation = retry_correlation(&attempt).ok()?;
                let mut snapshot = job.snapshot.clone();
                snapshot.home_epoch = self.config.epoch;
                snapshot.authority = self.config.authority.clone();
                let question = RetryQuestionV1 {
                    snapshot,
                    failed_attempt: attempt,
                    failure: error,
                    executor_retryable_hint: retryable,
                    candidates: vec![job.snapshot.spec.deployment.clone()],
                    evidence: job.snapshot.spec.evidence.clone(),
                };
                let question =
                    SignedRecordV1::sign(SCHEMA_POLICY_V1, question, self.signer.as_ref()).ok()?;
                gawdfn::verify_retry_question(&question).ok()?;
                Some(
                    Dispatch::to(
                        Address::Role(Role::new(FUNCTION_POLICY_ROLE)),
                        aether::wire::to_bytes(&PolicyMessageV1::DecideRetry {
                            question: Box::new(question),
                        }),
                    )
                    .with_schema(SCHEMA_POLICY_V1)
                    .with_corr(correlation),
                )
            }
            HOME_RECOVERY_ATTEMPT
                if matches!(job.snapshot.state, JobStateV1::Dispatching | JobStateV1::Running) =>
            {
                let attempt = job.snapshot.current_attempt.as_ref()?;
                let grant = state.grants.get(&(attempt.job.clone(), attempt.number))?;
                let target = self.executor_target(&grant.payload.deployment.payload);
                let route_sequence = state.custody.active_route_sequence().ok()?;
                if self.config.epoch == grant.payload.home_epoch
                    && route_sequence == grant.payload.home_route_sequence
                {
                    Some(
                        Dispatch::to(
                            target,
                            aether::wire::to_bytes(&ExecuteMessageV1::Grant {
                                grant: Box::new(grant.clone()),
                            }),
                        )
                        .with_schema(SCHEMA_EXECUTE_V1),
                    )
                } else if self.config.epoch > grant.payload.home_epoch
                    || (self.config.epoch == grant.payload.home_epoch
                        && route_sequence > grant.payload.home_route_sequence)
                {
                    let request = SignedRecordV1::sign(
                        SCHEMA_EXECUTE_V1,
                        ExecutionQueryV1 {
                            attempt: attempt.clone(),
                            grant_hash: canonical_hash(grant).ok()?,
                            home_epoch: self.config.epoch,
                            home_route_sequence: route_sequence,
                            home_realm: self.config.realm.clone(),
                            home_node: self.config.node.clone(),
                            home_coordinator: self.config.coordinator.clone(),
                            authority: self.config.authority.clone(),
                            query: ControlId::new(format!(
                                "reconcile-{}-{}-{}",
                                self.config.epoch, attempt.job, attempt.number
                            )),
                        },
                        self.signer.as_ref(),
                    )
                    .ok()?;
                    Some(
                        Dispatch::to(
                            target,
                            aether::wire::to_bytes(&ExecuteMessageV1::Query {
                                request: Box::new(request),
                            }),
                        )
                        .with_schema(SCHEMA_EXECUTE_V1),
                    )
                } else {
                    None
                }
            }
            HOME_RECOVERY_CONTROL
                if matches!(job.snapshot.state, JobStateV1::Dispatching | JobStateV1::Running) =>
            {
                let attempt = job.snapshot.current_attempt.as_ref()?;
                let grant = state.grants.get(&(attempt.job.clone(), attempt.number))?;
                let target = self.executor_target(&grant.payload.deployment.payload);
                let event =
                    job.events.iter().find(|event| event.payload.sequence == key.sequence)?;
                let JobEventKindV1::ControlRequested { request, attempt: Some(control_attempt) } =
                    &event.payload.kind
                else {
                    return None;
                };
                let control_key = (
                    request.payload.handle.job.clone(),
                    request.payload.control.as_str().to_string(),
                );
                if control_attempt != attempt
                    || state
                        .forwarded_controls
                        .get(&control_key)
                        .is_none_or(|control| control.acknowledged_receipt_hash.is_some())
                {
                    return None;
                }
                let endorsed = self
                    .sign_control_endorsement(
                        (**request).clone(),
                        event,
                        grant,
                        state.custody.active_route_sequence().ok()?,
                    )
                    .ok()?;
                Some(
                    Dispatch::to(
                        target,
                        aether::wire::to_bytes(&ExecuteMessageV1::Control {
                            request: Box::new(endorsed),
                        }),
                    )
                    .with_schema(SCHEMA_EXECUTE_V1),
                )
            }
            _ => None,
        }
    }

    fn begin_recovery_sweep(&self) {
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if self.ensure_authoritative_state(&state).is_err() {
            *self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner()) =
                HomeRecoverySweep::default();
            return;
        }
        let mut remaining = 0usize;
        let mut high_water = None;
        self.for_each_recovery_key(&state, |key| {
            remaining = remaining.saturating_add(1);
            high_water = Some(key);
        });
        *self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner()) =
            HomeRecoverySweep { cursor: None, high_water, remaining };
    }

    fn continue_recovery_sweep(&self) -> Outcome {
        let mut outcome = Outcome::none();
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if self.ensure_authoritative_state(&state).is_err() {
            *self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner()) =
                HomeRecoverySweep::default();
            return outcome;
        }
        let mut sweep = self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner());
        if sweep.remaining == 0 {
            return outcome;
        }
        let Some(high_water) = sweep.high_water.clone() else {
            sweep.remaining = 0;
            return outcome;
        };
        let limit = sweep.remaining.min(MAX_HOME_RECOVERY_DISPATCHES);
        let cursor = sweep.cursor.clone();
        let mut keys = Vec::with_capacity(limit.saturating_add(1));
        self.for_each_recovery_key(&state, |key| {
            if cursor.as_ref().is_none_or(|cursor| key > *cursor)
                && key <= high_water
                && keys.len() <= limit
            {
                keys.push(key);
            }
        });
        let has_more = keys.len() > limit;
        keys.truncate(limit);
        if keys.is_empty() {
            sweep.remaining = 0;
            return outcome;
        }
        sweep.cursor = keys.last().cloned();
        sweep.remaining = sweep.remaining.saturating_sub(keys.len());
        if !has_more {
            sweep.remaining = 0;
        }
        let should_continue = sweep.remaining > 0;
        for key in &keys {
            if let Some(dispatch) = self.recovery_dispatch_for_key(&state, key) {
                outcome.push(dispatch);
            }
        }
        drop(sweep);
        drop(state);
        if should_continue {
            if let Some(me) = self.me {
                outcome.push(
                    Dispatch::to(Address::Creature(me), HOME_RECOVERY_POKE_PAYLOAD.to_vec())
                        .with_schema(HOME_RECOVERY_POKE_SCHEMA),
                );
            }
        }
        outcome
    }

    /// Rebuild one finite batch of durable best-effort work. The first call captures one sweep;
    /// subsequent authenticated self-pokes visit its unseen tail exactly once rather than retrying
    /// unacknowledged work forever.
    pub fn recovery_dispatches(&self) -> Outcome {
        let active =
            self.recovery_sweep.lock().unwrap_or_else(|poison| poison.into_inner()).remaining > 0;
        if !active {
            self.begin_recovery_sweep();
        }
        self.continue_recovery_sweep()
    }

    fn is_authenticated_recovery_poke(&self, env: &Envelope) -> bool {
        let Some(me) = self.me else { return false };
        env.header.origin.is_none()
            && env.header.from == Address::Creature(me)
            && env.header.to == Address::Creature(me)
            && env.payload == HOME_RECOVERY_POKE_PAYLOAD
    }

    fn grant_dispatch(&self, grant: SignedRecordV1<ExecutionGrantV1>) -> Option<Dispatch> {
        self.ensure_operational_write_authority().ok()?;
        let target = self.executor_target(&grant.payload.deployment.payload);
        Some(
            Dispatch::to(
                target,
                aether::wire::to_bytes(&ExecuteMessageV1::Grant { grant: Box::new(grant) }),
            )
            .with_schema(SCHEMA_EXECUTE_V1),
        )
    }

    fn handle_submit_message(
        &self,
        env: &Envelope,
        request: SignedRecordV1<gawdfn::JobSubmitV1>,
        resolution: SignedRecordV1<ResolutionReceiptV1>,
        deployment: SignedRecordV1<DeploymentReceiptV1>,
    ) -> Outcome {
        let result = self.submit(request, resolution, deployment);
        let (response, handle) = match result {
            Ok(SubmitOutcome::Accepted { handle, request_hash, submitted })
            | Ok(SubmitOutcome::Existing { handle, request_hash, submitted }) => (
                JobMessageV1::Accepted {
                    handle: handle.clone(),
                    request_hash,
                    submitted: Box::new(submitted),
                },
                Some(handle),
            ),
            Err(error) => (job_error(error), None),
        };
        // Dispatch order is intentional: durable acceptance is independently observable before
        // any best-effort policy consult. If the role is absent, the job simply remains Queued.
        let mut outcome = reply(env, SCHEMA_JOB_V1, &response);
        if let Some(handle) = handle {
            self.append_policy_question(&mut outcome, &handle);
        }
        outcome
    }

    fn handle_get_message(
        &self,
        env: &Envelope,
        request: SignedRecordV1<JobGetRelayV1>,
    ) -> JobMessageV1 {
        let response = (|| -> Result<JobMessageV1, HomeError> {
            gawdfn::verify_job_get_relay(&request)
                .map_err(|error| HomeError::Unauthorized(error.to_string()))?;
            self.require_read_route(env, &request.payload.reply_to)?;
            self.trust
                .allow_read_relay(&request.signer, &request.payload.caller.signer)
                .map_err(HomeError::Unauthorized)?;
            let request_hash = canonical_hash(&request).map_err(invalid)?;
            let handle = &request.payload.caller.payload.handle;
            let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
            self.ensure_authoritative_state(&state)?;
            self.authorize_reader_from_state(&state, handle, &request.payload.caller.signer)?;
            let snapshot = self.snapshot_from_state(&state, &handle.job)?;
            let snapshot = SignedRecordV1::sign(SCHEMA_JOB_V1, snapshot, self.signer.as_ref())
                .map_err(signing)?;
            let response = SignedRecordV1::sign(
                SCHEMA_JOB_V1,
                JobSnapshotResponseV1 { request_hash, snapshot: Box::new(snapshot) },
                self.signer.as_ref(),
            )
            .map_err(signing)?;
            Ok(bounded_private_read_response(JobMessageV1::Snapshot {
                response: Box::new(response),
            }))
        })();
        response.unwrap_or_else(job_error)
    }

    fn handle_events_message(
        &self,
        env: &Envelope,
        request: SignedRecordV1<EventQueryRelayV1>,
    ) -> JobMessageV1 {
        let response = (|| -> Result<JobMessageV1, HomeError> {
            gawdfn::verify_event_query_relay(&request)
                .map_err(|error| HomeError::Unauthorized(error.to_string()))?;
            self.require_read_route(env, &request.payload.reply_to)?;
            self.trust
                .allow_read_relay(&request.signer, &request.payload.caller.signer)
                .map_err(HomeError::Unauthorized)?;
            let request_hash = canonical_hash(&request).map_err(invalid)?;
            let query = &request.payload.caller.payload;
            query.validate().map_err(invalid)?;
            let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
            self.ensure_authoritative_state(&state)?;
            self.authorize_reader_from_state(
                &state,
                &query.handle,
                &request.payload.caller.signer,
            )?;
            let page = self.events_from_state(&state, query)?;
            let response = SignedRecordV1::sign(
                SCHEMA_JOB_V1,
                EventPageResponseV1 {
                    request_hash,
                    home_epoch: self.config.epoch,
                    authority: self.config.authority.clone(),
                    page,
                },
                self.signer.as_ref(),
            )
            .map_err(signing)?;
            Ok(bounded_private_read_response(JobMessageV1::EventPage {
                response: Box::new(response),
            }))
        })();
        response.unwrap_or_else(job_error)
    }

    fn handle_policy_message(&self, _env: &Envelope, message: PolicyMessageV1) -> Outcome {
        match message {
            PolicyMessageV1::DeploymentSelected { decision } => {
                let Ok(grant) = self.apply_placement_decision(*decision) else {
                    return Outcome::none();
                };
                self.grant_dispatch(grant).map_or_else(Outcome::none, Outcome::send)
            }
            PolicyMessageV1::RetryDecided { decision } => {
                let Ok(grant) = self.apply_retry_decision(*decision) else {
                    return Outcome::none();
                };
                grant
                    .and_then(|grant| self.grant_dispatch(grant))
                    .map_or_else(Outcome::none, Outcome::send)
            }
            PolicyMessageV1::SelectDeployment { .. }
            | PolicyMessageV1::DecideRetry { .. }
            | PolicyMessageV1::Error { .. } => Outcome::none(),
        }
    }

    fn handle_home_message(&self, env: &Envelope, message: HomeMessageV1) -> Outcome {
        match message {
            HomeMessageV1::Prepare { grant, checkpoint } => {
                match self.prepare_handoff(*grant, *checkpoint) {
                    Ok(prepared) => reply(
                        env,
                        SCHEMA_HOME_V1,
                        &HomeMessageV1::Prepared { prepared: Box::new(prepared.prepared) },
                    ),
                    Err(error) => reply_home_error(env, error),
                }
            }
            HomeMessageV1::Activated { lease } => {
                let lease = *lease;
                if let Err(error) = self.record_handoff_redirect(lease.clone()) {
                    return reply_home_error(env, error);
                }
                let status = match self.signed_custody_status() {
                    Ok(status) => status,
                    Err(error) => return reply_home_error(env, error),
                };
                let mut outcome = reply(
                    env,
                    SCHEMA_HOME_V1,
                    &HomeMessageV1::StatusResult { status: Box::new(status) },
                );
                outcome.push(
                    Dispatch::to(
                        Address::Role(Role::new(FUNCTION_LOCATOR_ROLE)),
                        aether::wire::to_bytes(&LocateMessageV1::Announce { lease }),
                    )
                    .with_schema(SCHEMA_LOCATE_V1),
                );
                outcome
            }
            HomeMessageV1::Status { home } if home == self.config.home => {
                match self.signed_custody_status() {
                    Ok(status) => reply(
                        env,
                        SCHEMA_HOME_V1,
                        &HomeMessageV1::StatusResult { status: Box::new(status) },
                    ),
                    Err(error) => reply_home_error(env, error),
                }
            }
            HomeMessageV1::Status { .. } => reply(
                env,
                SCHEMA_HOME_V1,
                &HomeMessageV1::Error {
                    error: ProtocolErrorV1 {
                        code: "not_found".into(),
                        message: "Home status request names another Home".into(),
                        retryable: false,
                    },
                },
            ),
            HomeMessageV1::Prepared { .. }
            | HomeMessageV1::Stage { .. }
            | HomeMessageV1::Staged { .. }
            | HomeMessageV1::Activate { .. }
            | HomeMessageV1::StatusResult { .. }
            | HomeMessageV1::Error { .. } => Outcome::none(),
        }
    }
}

impl Creature for FunctionHome {
    fn bind(&mut self, ctx: CreatureCtx) {
        // Re-emit only durable socket questions/queries after restart. This is mechanism, not a
        // scheduler: policy/executor creatures decide what happens, and failed best-effort sends
        // leave the ledger unchanged for an explicit later recovery poke.
        let _ = self.bind_runtime(ctx, true);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.payload.len() > MAX_JOB_MESSAGE_BYTES {
            return Outcome::none();
        }
        if env.header.schema == HOME_RECOVERY_POKE_SCHEMA {
            return if self.is_authenticated_recovery_poke(&env) {
                self.continue_recovery_sweep()
            } else {
                Outcome::none()
            };
        }
        match env.header.schema.as_str() {
            SCHEMA_JOB_V1 => {
                let Ok(message) = serde_json::from_slice::<JobMessageV1>(&env.payload) else {
                    return Outcome::none();
                };
                let response = match message {
                    JobMessageV1::Submit { request, resolution, deployment } => {
                        return self.handle_submit_message(
                            &env,
                            *request,
                            *resolution,
                            *deployment,
                        );
                    }
                    JobMessageV1::Get { request } => self.handle_get_message(&env, *request),
                    JobMessageV1::Events { request } => self.handle_events_message(&env, *request),
                    JobMessageV1::Control { request } => {
                        let request_hash = match canonical_hash(request.as_ref()) {
                            Ok(hash) => hash,
                            Err(error) => {
                                return reply(&env, SCHEMA_JOB_V1, &job_error(invalid(error)))
                            }
                        };
                        let request_for_forward = (*request).clone();
                        match self.control(*request) {
                            Ok(event) => {
                                let child = match &event.payload.kind {
                                    JobEventKindV1::ChildSpawned { child, .. } => {
                                        Some(child.clone())
                                    }
                                    _ => None,
                                };
                                let forward = self
                                    .endorsed_control(request_for_forward, &event)
                                    .ok()
                                    .flatten();
                                let mut outcome = reply(
                                    &env,
                                    SCHEMA_JOB_V1,
                                    &JobMessageV1::ControlAccepted {
                                        request_hash,
                                        event: Box::new(event),
                                    },
                                );
                                if let Some((request, target)) = forward {
                                    outcome.push(
                                        Dispatch::to(
                                            target,
                                            aether::wire::to_bytes(&ExecuteMessageV1::Control {
                                                request: Box::new(request),
                                            }),
                                        )
                                        .with_schema(SCHEMA_EXECUTE_V1),
                                    );
                                }
                                if let Some(child) = child {
                                    self.append_policy_question(&mut outcome, &child);
                                }
                                return outcome;
                            }
                            Err(error) => job_error(error),
                        }
                    }
                    JobMessageV1::Accepted { .. }
                    | JobMessageV1::Snapshot { .. }
                    | JobMessageV1::EventPage { .. }
                    | JobMessageV1::ControlAccepted { .. }
                    | JobMessageV1::Event { .. }
                    | JobMessageV1::Error { .. } => return Outcome::none(),
                };
                reply(&env, SCHEMA_JOB_V1, &response)
            }
            SCHEMA_EXECUTE_V1 => {
                let Ok(ExecuteMessageV1::Receipt { receipt }) =
                    serde_json::from_slice::<ExecuteMessageV1>(&env.payload)
                else {
                    return Outcome::none();
                };
                let (response, retry_event) = match self.apply_executor_receipt(*receipt) {
                    Ok(ApplyReceiptOutcome::Applied(event))
                    | Ok(ApplyReceiptOutcome::Duplicate(event)) => {
                        (JobMessageV1::Event { event: Box::new(event.clone()) }, Some(event))
                    }
                    Err(error) => (job_error(error), None),
                };
                let mut outcome = reply(&env, SCHEMA_JOB_V1, &response);
                if let Some(event) = retry_event {
                    self.append_retry_question(&mut outcome, &event);
                }
                outcome
            }
            SCHEMA_POLICY_V1 => {
                let Ok(message) = serde_json::from_slice::<PolicyMessageV1>(&env.payload) else {
                    return Outcome::none();
                };
                self.handle_policy_message(&env, message)
            }
            SCHEMA_HOME_V1 => {
                let Ok(message) = serde_json::from_slice::<HomeMessageV1>(&env.payload) else {
                    return reply(
                        &env,
                        SCHEMA_HOME_V1,
                        &HomeMessageV1::Error {
                            error: ProtocolErrorV1 {
                                code: "invalid_message".into(),
                                message: "cannot decode Home custody message".into(),
                                retryable: false,
                            },
                        },
                    );
                };
                self.handle_home_message(&env, message)
            }
            _ => Outcome::none(),
        }
    }
}

fn preflight_ledger_transition(
    config: &HomeConfig,
    state: &HomeState,
    record: &HomeLedgerRecord,
) -> Result<(), HomeError> {
    let mut shadow = HomeState::new(state.custody.clone());
    shadow.next_grant_sequence = state.next_grant_sequence;
    shadow.nonterminal_jobs = state.nonterminal_jobs;
    shadow.unacknowledged_forwarded_controls = state.unacknowledged_forwarded_controls;

    let mut jobs = BTreeSet::new();
    for event in &record.events {
        jobs.insert(event.payload.handle.job.clone());
        match &event.payload.kind {
            JobEventKindV1::Submitted { spec } => {
                if let Some(parent) = &spec.parent {
                    jobs.insert(parent.job.clone());
                }
            }
            JobEventKindV1::ChildSpawned { parent_attempt, child, .. } => {
                jobs.insert(parent_attempt.job.clone());
                jobs.insert(child.job.clone());
            }
            _ => {}
        }
    }
    if let Some(grant) = &record.grant {
        jobs.insert(grant.payload.attempt.job.clone());
        let key = (grant.payload.attempt.job.clone(), grant.payload.attempt.number);
        if let Some(existing) = state.grants.get(&key) {
            shadow.grants.insert(key, existing.clone());
        }
    }
    if let Some(receipt) = &record.receipt {
        jobs.insert(receipt.payload.attempt.job.clone());
        let attempt_key = (receipt.payload.attempt.job.clone(), receipt.payload.attempt.number);
        if let Some(existing) = state.grants.get(&attempt_key) {
            shadow.grants.insert(attempt_key.clone(), existing.clone());
        }
        if let Some(count) = state.observation_counts.get(&attempt_key) {
            shadow.observation_counts.insert(attempt_key.clone(), *count);
        }
        if let Some(sequence) = state.highest_receipt_sequences.get(&attempt_key) {
            shadow.highest_receipt_sequences.insert(attempt_key.clone(), *sequence);
        }
        if let Some(sequence) = state.highest_progress_sequences.get(&attempt_key) {
            shadow.highest_progress_sequences.insert(attempt_key.clone(), *sequence);
        }
        if let Some(sequence) = state.highest_checkpoint_sequences.get(&attempt_key) {
            shadow.highest_checkpoint_sequences.insert(attempt_key, *sequence);
        }
        let receipt_key = (
            receipt.payload.attempt.job.clone(),
            receipt.payload.attempt.number,
            receipt.payload.sequence,
        );
        if let Some(hash) = state.receipts.get(&receipt_key) {
            shadow.receipts.insert(receipt_key, hash.clone());
        }
        if let ExecutionStageV1::ControlQueued { control }
        | ExecutionStageV1::ControlAcknowledged { control, .. } = &receipt.payload.stage
        {
            let control_key = (receipt.payload.attempt.job.clone(), control.as_str().to_string());
            if let Some(existing) = state.forwarded_controls.get(&control_key) {
                shadow.forwarded_controls.insert(control_key.clone(), existing.clone());
            }
            if let Some(hash) = state.controls.get(&control_key) {
                shadow.controls.insert(control_key, hash.clone());
            }
        }
    }

    for job in jobs {
        if let Some(existing) = state.jobs.get(&job) {
            shadow.jobs.insert(
                job.clone(),
                JobRecord { snapshot: existing.snapshot.clone(), events: Vec::new() },
            );
        }
        if let Some(hash) = state.request_hashes.get(&job) {
            shadow.request_hashes.insert(job, hash.clone());
        }
    }
    for event in &record.events {
        let job = event.payload.handle.job.clone();
        if let Some(count) = state.control_counts.get(&job) {
            shadow.control_counts.insert(job.clone(), *count);
        }
        let control_key = match &event.payload.kind {
            JobEventKindV1::AccessUpdated { control, .. } => Some((job.clone(), control.0.clone())),
            JobEventKindV1::ControlRequested { request, .. } => {
                Some((job.clone(), request.payload.control.0.clone()))
            }
            _ => None,
        };
        if let Some(key) = control_key {
            if let Some(hash) = state.controls.get(&key) {
                shadow.controls.insert(key.clone(), hash.clone());
            }
            if let Some(existing) = state.forwarded_controls.get(&key) {
                shadow.forwarded_controls.insert(key, existing.clone());
            }
        }
        if let JobEventKindV1::ChildSpawned { parent_attempt, spawn_key, .. } = &event.payload.kind
        {
            let key = (parent_attempt.job.clone(), parent_attempt.number, spawn_key.clone());
            if let Some(existing) = state.child_spawns.get(&key) {
                shadow.child_spawns.insert(key, existing.clone());
            }
        }
    }
    apply_ledger_record(config, &mut shadow, record)
}

fn home_reservations_after(
    state: &HomeState,
    record: &HomeLedgerRecord,
) -> Result<usize, HomeError> {
    let mut jobs = state.nonterminal_jobs;
    let mut controls = state.unacknowledged_forwarded_controls;
    for event in &record.events {
        match &event.payload.kind {
            JobEventKindV1::Submitted { .. } => {
                jobs = jobs.checked_add(1).ok_or_else(|| {
                    HomeError::Capacity("nonterminal Job reservation count overflowed".into())
                })?;
            }
            JobEventKindV1::ControlRequested { request, attempt: Some(_) } => {
                let key = (
                    event.payload.handle.job.clone(),
                    request.payload.control.as_str().to_string(),
                );
                if !state.forwarded_controls.contains_key(&key) {
                    controls = controls.checked_add(1).ok_or_else(|| {
                        HomeError::Capacity(
                            "unacknowledged control reservation count overflowed".into(),
                        )
                    })?;
                }
            }
            _ => {}
        }
        if event.payload.state_after.is_terminal()
            && state
                .jobs
                .get(&event.payload.handle.job)
                .is_some_and(|job| !job.snapshot.state.is_terminal())
        {
            jobs = jobs.checked_sub(1).ok_or_else(|| {
                HomeError::State("nonterminal Job reservation count underflowed".into())
            })?;
        }
    }
    if let Some(receipt) = &record.receipt {
        if let ExecutionStageV1::ControlAcknowledged { control, .. } = &receipt.payload.stage {
            let key = (receipt.payload.attempt.job.clone(), control.as_str().to_string());
            if state
                .forwarded_controls
                .get(&key)
                .is_some_and(|retained| retained.acknowledged_receipt_hash.is_none())
            {
                controls = controls.checked_sub(1).ok_or_else(|| {
                    HomeError::State("control-ack reservation count underflowed".into())
                })?;
            }
        }
    }
    jobs.checked_add(controls)
        .ok_or_else(|| HomeError::Capacity("Home safety reservation count overflowed".into()))
}

fn home_reservations(state: &HomeState) -> Result<usize, HomeError> {
    state
        .nonterminal_jobs
        .checked_add(state.unacknowledged_forwarded_controls)
        .ok_or_else(|| HomeError::Capacity("Home safety reservation count overflowed".into()))
}

fn apply_ledger_record(
    config: &HomeConfig,
    state: &mut HomeState,
    record: &HomeLedgerRecord,
) -> Result<(), HomeError> {
    validate_ledger_record(record, config)?;
    if let Some(grant) = &record.grant {
        if grant.payload.owner != config.home
            || !authorized_operational(config, grant.payload.home_epoch, &grant.signer)
        {
            return Err(HomeError::State("grant belongs to an unauthorized home epoch".into()));
        }
        let key = (grant.payload.attempt.job.clone(), grant.payload.attempt.number);
        if let Some(existing) = state.grants.get(&key) {
            if canonical_hash(existing).map_err(invalid)?
                != canonical_hash(grant).map_err(invalid)?
            {
                return Err(HomeError::Conflict("two grants for one attempt".into()));
            }
        } else {
            state.grants.insert(key, grant.clone());
        }
        state.next_grant_sequence = state.next_grant_sequence.max(grant.payload.grant_sequence + 1);
    }
    if let Some(receipt) = &record.receipt {
        let attempt_key = (receipt.payload.attempt.job.clone(), receipt.payload.attempt.number);
        let grant = state
            .grants
            .get(&attempt_key)
            .ok_or_else(|| HomeError::State("persisted receipt has no grant".into()))?;
        gawdfn::verify_execution_receipt(receipt, grant)
            .map_err(|error| HomeError::Unauthorized(error.to_string()))?;
        let highest_receipt =
            state.highest_receipt_sequences.get(&attempt_key).copied().unwrap_or(0);
        if receipt.payload.sequence == highest_receipt {
            return Err(HomeError::State(format!(
                "persisted receipt sequence {} matches an unindexed high-water mark",
                receipt.payload.sequence
            )));
        }
        let late = receipt.payload.sequence < highest_receipt;
        let observation = matches!(
            receipt.payload.stage,
            ExecutionStageV1::Progress { .. } | ExecutionStageV1::Checkpoint { .. }
        );
        if observation
            && state.observation_counts.get(&attempt_key).copied().unwrap_or(0)
                >= MAX_ATTEMPT_OBSERVATIONS
        {
            return Err(HomeError::Capacity(format!(
                "attempt observations exceed {MAX_ATTEMPT_OBSERVATIONS}"
            )));
        }
        if !late {
            match &receipt.payload.stage {
                ExecutionStageV1::Progress { sequence, .. } => {
                    let highest =
                        state.highest_progress_sequences.get(&attempt_key).copied().unwrap_or(0);
                    if *sequence <= highest {
                        return Err(HomeError::State(format!(
                            "persisted progress sequence {sequence} is not newer than {highest}"
                        )));
                    }
                }
                ExecutionStageV1::Checkpoint { sequence, .. } => {
                    let highest =
                        state.highest_checkpoint_sequences.get(&attempt_key).copied().unwrap_or(0);
                    if *sequence <= highest {
                        return Err(HomeError::State(format!(
                            "persisted checkpoint sequence {sequence} is not newer than {highest}"
                        )));
                    }
                }
                _ => {}
            }
        }
        let hash = canonical_hash(receipt).map_err(invalid)?;
        index_home_control_receipt(state, receipt, &hash)?;
        let key = (
            receipt.payload.attempt.job.clone(),
            receipt.payload.attempt.number,
            receipt.payload.sequence,
        );
        if state.receipts.insert(key, hash.clone()).is_some_and(|old| old != hash) {
            return Err(HomeError::Conflict("conflicting persisted executor receipt".into()));
        }
        state
            .highest_receipt_sequences
            .insert(attempt_key.clone(), highest_receipt.max(receipt.payload.sequence));
        match &receipt.payload.stage {
            ExecutionStageV1::Progress { sequence, .. } => {
                let highest =
                    state.highest_progress_sequences.get(&attempt_key).copied().unwrap_or(0);
                state
                    .highest_progress_sequences
                    .insert(attempt_key.clone(), highest.max(*sequence));
            }
            ExecutionStageV1::Checkpoint { sequence, .. } => {
                let highest =
                    state.highest_checkpoint_sequences.get(&attempt_key).copied().unwrap_or(0);
                state
                    .highest_checkpoint_sequences
                    .insert(attempt_key.clone(), highest.max(*sequence));
            }
            _ => {}
        }
        if observation {
            *state.observation_counts.entry(attempt_key).or_default() += 1;
        }
    }
    for event in &record.events {
        apply_job_event(config, state, event)?;
    }
    Ok(())
}

fn validate_ledger_record(record: &HomeLedgerRecord, config: &HomeConfig) -> Result<(), HomeError> {
    if record.events.is_empty() {
        return Err(HomeError::State("ledger record has no public event".into()));
    }
    for event in &record.events {
        if gawdfn::verify_job_event(event).is_err()
            || !authorized_operational(config, event.payload.home_epoch, &event.signer)
        {
            return Err(HomeError::Unauthorized("persisted job event signature is invalid".into()));
        }
    }
    if let Some(grant) = &record.grant {
        grant.validate().map_err(invalid)?;
        if grant.schema != SCHEMA_EXECUTE_V1 || gawdfn::verify_execution_grant(grant).is_err() {
            return Err(HomeError::Unauthorized("persisted grant signature is invalid".into()));
        }
        let grant_hash = canonical_hash(grant).map_err(invalid)?;
        let matching = record.events.iter().filter(|event| {
            matches!(
                &event.payload.kind,
                JobEventKindV1::DispatchGranted { grant_hash: event_hash, attempt }
                    if event_hash == &grant_hash && attempt == &grant.payload.attempt
            )
        });
        if matching.count() != 1 {
            return Err(HomeError::State(
                "persisted grant is not bound to one exact DispatchGranted event".into(),
            ));
        }
    }
    if let Some(receipt) = &record.receipt {
        receipt.validate().map_err(invalid)?;
        if receipt.schema != SCHEMA_EXECUTE_V1 || !receipt.verify() {
            return Err(HomeError::Unauthorized("persisted receipt signature is invalid".into()));
        }
        let receipt_hash = canonical_hash(receipt).map_err(invalid)?;
        let matching = record.events.iter().filter(|event| {
            event
                .payload
                .foreign_receipt
                .as_deref()
                .and_then(|foreign| canonical_hash(foreign).ok())
                .is_some_and(|hash| hash == receipt_hash)
        });
        if matching.count() != 1 {
            return Err(HomeError::State(
                "persisted receipt is not bound to one exact public foreign receipt".into(),
            ));
        }
    } else if record.events.iter().any(|event| event.payload.foreign_receipt.is_some()) {
        return Err(HomeError::State(
            "public foreign receipt has no matching private ledger receipt".into(),
        ));
    }
    for (index, event) in record.events.iter().enumerate() {
        let JobEventKindV1::ChildSpawned { child, root, child_request_hash, .. } =
            &event.payload.kind
        else {
            continue;
        };
        let linked = record.events.iter().skip(index + 1).any(|candidate| {
            let JobEventKindV1::Submitted { spec } = &candidate.payload.kind else {
                return false;
            };
            candidate.payload.handle == *child
                && spec.handle == *child
                && spec.parent.as_ref() == Some(&event.payload.handle)
                && spec.root == *root
                && spec.request_hash == *child_request_hash
        });
        if !linked {
            return Err(HomeError::State(
                "ChildSpawned is not atomically followed by its exact child Submitted event".into(),
            ));
        }
    }
    Ok(())
}

fn authorized_operational(config: &HomeConfig, epoch: u64, signer: &str) -> bool {
    std::iter::once(&config.authority).chain(config.historical_authorities.iter()).any(
        |authority| {
            authority.operational.payload.epoch == epoch
                && authority.operational.payload.operational_public_key == signer
                && authority.verify(&config.home, epoch, OperationalCapabilityV1::JobHome).is_ok()
        },
    )
}

fn apply_job_event(
    config: &HomeConfig,
    state: &mut HomeState,
    event: &SignedRecordV1<JobEventV1>,
) -> Result<(), HomeError> {
    if event.payload.handle.home != config.home
        || !authorized_operational(config, event.payload.home_epoch, &event.signer)
    {
        return Err(HomeError::State("event belongs to another home epoch".into()));
    }
    let job_id = event.payload.handle.job.clone();
    if let JobEventKindV1::Submitted { spec } = &event.payload.kind {
        if event.payload.sequence != 1 || event.payload.state_after != JobStateV1::Queued {
            return Err(HomeError::State("submitted must be queued sequence 1".into()));
        }
        if state.jobs.contains_key(&job_id) {
            return Err(HomeError::Conflict(job_id.to_string()));
        }
        if let Some(parent) = &spec.parent {
            let parent_job = state.jobs.get(&parent.job).ok_or_else(|| {
                HomeError::State("child submission precedes its durable parent".into())
            })?;
            if parent.home != config.home
                || spec.root != parent_job.snapshot.spec.root
                || spec.root.home != config.home
            {
                return Err(HomeError::State(
                    "child submission does not inherit its parent's immutable root".into(),
                ));
            }
        } else if spec.root != spec.handle {
            return Err(HomeError::State(
                "root submission does not self-identify its immutable root".into(),
            ));
        }
        state.nonterminal_jobs = state.nonterminal_jobs.checked_add(1).ok_or_else(|| {
            HomeError::Capacity("nonterminal Job reservation count overflowed".into())
        })?;
        let snapshot = JobSnapshotV1 {
            spec: (**spec).clone(),
            state: JobStateV1::Queued,
            cancel_requested: event.payload.cancel_requested,
            home_epoch: event.payload.home_epoch,
            authority: event.payload.authority.clone(),
            last_sequence: 1,
            current_attempt: None,
            result: None,
            error: None,
        };
        state.request_hashes.insert(job_id.clone(), snapshot.spec.request_hash.clone());
        state.jobs.insert(job_id, JobRecord { snapshot, events: vec![event.clone()] });
        return Ok(());
    }
    let record = state
        .jobs
        .get_mut(&job_id)
        .ok_or_else(|| HomeError::State("event precedes submission".into()))?;
    if event.payload.sequence != record.snapshot.last_sequence + 1 {
        return Err(HomeError::State("job event sequence is not monotonic".into()));
    }
    if let JobEventKindV1::Succeeded { result, .. } = &event.payload.kind {
        require_result_recipient_wraps(result, &record.snapshot.spec.result_recipients)?;
    }
    let late_fact = record.snapshot.state == event.payload.state_after
        && matches!(event.payload.kind, JobEventKindV1::LateReceipt { .. });
    if !late_fact && !transition_allowed(record.snapshot.state, event.payload.state_after) {
        return Err(HomeError::State(format!(
            "invalid transition {:?} -> {:?}",
            record.snapshot.state, event.payload.state_after
        )));
    }
    let was_nonterminal = !record.snapshot.state.is_terminal();
    record.snapshot.state = event.payload.state_after;
    record.snapshot.home_epoch = event.payload.home_epoch;
    record.snapshot.authority = event.payload.authority.clone();
    record.snapshot.cancel_requested = event.payload.cancel_requested;
    record.snapshot.last_sequence = event.payload.sequence;
    match &event.payload.kind {
        JobEventKindV1::DispatchGranted { attempt, .. }
        | JobEventKindV1::Claimed { attempt, .. }
        | JobEventKindV1::Started { attempt }
        | JobEventKindV1::Progress { attempt, .. }
        | JobEventKindV1::Checkpoint { attempt, .. }
        | JobEventKindV1::AttemptFailed { attempt, .. }
        | JobEventKindV1::Succeeded { attempt, .. }
        | JobEventKindV1::Indeterminate { attempt, .. } => {
            record.snapshot.current_attempt = Some(attempt.clone());
        }
        _ => {}
    }
    match &event.payload.kind {
        JobEventKindV1::Succeeded { result, .. } => record.snapshot.result = Some(result.clone()),
        JobEventKindV1::AttemptFailed { error, .. } | JobEventKindV1::Failed { error } => {
            record.snapshot.error = Some(error.clone());
        }
        JobEventKindV1::AccessUpdated { control, request_hash, access } => {
            record.snapshot.spec.access = access.clone();
            let key = (job_id.clone(), control.0.clone());
            index_home_control(
                &mut state.controls,
                &mut state.control_counts,
                key,
                request_hash.clone(),
            )?;
        }
        JobEventKindV1::ControlRequested { request, attempt } => {
            let hash = canonical_hash(request).map_err(invalid)?;
            let key = (job_id.clone(), request.payload.control.0.clone());
            index_home_control(&mut state.controls, &mut state.control_counts, key.clone(), hash)?;
            if let Some(attempt) = attempt {
                if attempt.home != config.home || attempt.job != job_id {
                    return Err(HomeError::State(
                        "forwarded control attempt belongs to another Job/Home".into(),
                    ));
                }
                match state.forwarded_controls.entry(key) {
                    std::collections::btree_map::Entry::Vacant(entry) => {
                        entry.insert(ForwardedControlRecord {
                            attempt: attempt.clone(),
                            queued_receipt_hash: None,
                            acknowledged_receipt_hash: None,
                        });
                        state.unacknowledged_forwarded_controls = state
                            .unacknowledged_forwarded_controls
                            .checked_add(1)
                            .ok_or_else(|| {
                                HomeError::Capacity(
                                    "unacknowledged control reservation count overflowed".into(),
                                )
                            })?;
                    }
                    std::collections::btree_map::Entry::Occupied(entry)
                        if &entry.get().attempt == attempt => {}
                    std::collections::btree_map::Entry::Occupied(_) => {
                        return Err(HomeError::Conflict(
                            "durable control was rebound to another execution attempt".into(),
                        ));
                    }
                }
            }
        }
        JobEventKindV1::ChildSpawned {
            parent_attempt,
            parent_event_hash,
            spawn_key,
            child,
            root,
            child_request_hash,
        } => {
            if root != &record.snapshot.spec.root || child.home != config.home {
                return Err(HomeError::State(
                    "ChildSpawned does not inherit the durable parent workflow root".into(),
                ));
            }
            let key = (parent_attempt.job.clone(), parent_attempt.number, spawn_key.clone());
            let spawn = ChildSpawnRecord {
                parent_event_hash: parent_event_hash.clone(),
                child_request_hash: child_request_hash.clone(),
                child: child.clone(),
                root: root.clone(),
                event: event.clone(),
            };
            if let Some(existing) = state.child_spawns.get(&key) {
                if existing.parent_event_hash != spawn.parent_event_hash
                    || existing.child_request_hash != spawn.child_request_hash
                    || existing.child != spawn.child
                    || existing.root != spawn.root
                {
                    return Err(HomeError::Conflict(
                        "conflicting persisted causal child spawn".into(),
                    ));
                }
            } else {
                let count = state.control_counts.get(&job_id).copied().unwrap_or(0);
                if count >= MAX_JOB_CONTROLS {
                    return Err(HomeError::Capacity(format!(
                        "job controls exceed {MAX_JOB_CONTROLS}"
                    )));
                }
                state.child_spawns.insert(key, spawn);
                state.control_counts.insert(job_id.clone(), count + 1);
            }
        }
        _ => {}
    }
    record.events.push(event.clone());
    if was_nonterminal && event.payload.state_after.is_terminal() {
        state.nonterminal_jobs = state.nonterminal_jobs.checked_sub(1).ok_or_else(|| {
            HomeError::State("nonterminal Job reservation count underflowed".into())
        })?;
    }
    Ok(())
}

fn index_home_control(
    controls: &mut BTreeMap<(JobId, String), String>,
    control_counts: &mut BTreeMap<JobId, usize>,
    key: (JobId, String),
    request_hash: String,
) -> Result<(), HomeError> {
    if let Some(existing) = controls.get(&key) {
        return if existing == &request_hash {
            Ok(())
        } else {
            Err(HomeError::Conflict("control request hash changed during ledger replay".into()))
        };
    }
    let count = control_counts.get(&key.0).copied().unwrap_or(0);
    if count >= MAX_JOB_CONTROLS {
        return Err(HomeError::Capacity(format!("job controls exceed {MAX_JOB_CONTROLS}")));
    }
    control_counts.insert(key.0.clone(), count + 1);
    controls.insert(key, request_hash);
    Ok(())
}

fn index_home_control_receipt(
    state: &mut HomeState,
    receipt: &SignedRecordV1<ExecutionReceiptV1>,
    receipt_hash: &str,
) -> Result<(), HomeError> {
    let (control, acknowledged) = match &receipt.payload.stage {
        ExecutionStageV1::ControlQueued { control } => (control, false),
        ExecutionStageV1::ControlAcknowledged { control, .. } => (control, true),
        _ => return Ok(()),
    };
    let key = (receipt.payload.attempt.job.clone(), control.as_str().to_string());
    let retained = state.forwarded_controls.get_mut(&key).ok_or_else(|| {
        HomeError::State(format!(
            "executor control receipt `{}` has no durable forwarded Home control",
            control.as_str()
        ))
    })?;
    if retained.attempt != receipt.payload.attempt {
        return Err(HomeError::State(format!(
            "executor control receipt `{}` belongs to a different attempt",
            control.as_str()
        )));
    }
    let slot = if acknowledged {
        &mut retained.acknowledged_receipt_hash
    } else {
        &mut retained.queued_receipt_hash
    };
    if let Some(existing) = slot {
        return if existing == receipt_hash {
            Ok(())
        } else {
            Err(HomeError::Conflict(format!(
                "executor control receipt `{}` changed after Home retention",
                control.as_str()
            )))
        };
    }
    *slot = Some(receipt_hash.to_string());
    if acknowledged {
        state.unacknowledged_forwarded_controls = state
            .unacknowledged_forwarded_controls
            .checked_sub(1)
            .ok_or_else(|| HomeError::State("control-ack reservation count underflowed".into()))?;
    }
    Ok(())
}

/// `result_recipients` is the one v1 declaration that makes key-wrap presence contextual. Inputs
/// may be end-to-end sealed for arbitrary principals and the Home is not required to decrypt them.
/// A requested result recipient, however, must receive an inline, signed key wrap in a sealed
/// terminal result; a plain/blob result or a wrap set for different recipients is not fulfillment.
fn require_result_recipient_wraps(
    result: &ValueRefV1,
    required: &[HomeId],
) -> Result<(), HomeError> {
    if required.is_empty() {
        return Ok(());
    }
    let ValueRefV1::Sealed { sealed } = result else {
        return Err(HomeError::Invalid(
            "job requested result recipients but executor returned an unsealed result".into(),
        ));
    };
    for recipient in required {
        if !sealed.recipients.iter().any(|wrap| &wrap.recipient == recipient) {
            return Err(HomeError::Invalid(format!(
                "sealed result omits the required key envelope for recipient `{recipient}`"
            )));
        }
    }
    Ok(())
}

fn event_attempt(kind: &JobEventKindV1) -> Option<&AttemptId> {
    match kind {
        JobEventKindV1::DispatchGranted { attempt, .. }
        | JobEventKindV1::Claimed { attempt, .. }
        | JobEventKindV1::Started { attempt }
        | JobEventKindV1::Progress { attempt, .. }
        | JobEventKindV1::Checkpoint { attempt, .. }
        | JobEventKindV1::ControlQueued { attempt, .. }
        | JobEventKindV1::ControlAcknowledged { attempt, .. }
        | JobEventKindV1::AttemptFailed { attempt, .. }
        | JobEventKindV1::Succeeded { attempt, .. } => Some(attempt),
        JobEventKindV1::Indeterminate { attempt, .. }
        | JobEventKindV1::LateReceipt { attempt, .. } => Some(attempt),
        JobEventKindV1::ChildSpawned { parent_attempt, .. } => Some(parent_attempt),
        _ => None,
    }
}

fn retry_correlation(attempt: &AttemptId) -> Result<u64, HomeError> {
    let digest = canonical_hash(&serde_json::json!({
        "domain": "gawd.function.retry.correlation.v1",
        "attempt": attempt,
    }))
    .map_err(invalid)?;
    let hex = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| HomeError::Invalid("canonical retry hash is not SHA-256".into()))?;
    u64::from_str_radix(&hex[..16], 16).map(|value| value.max(1)).map_err(invalid)
}

fn retry_failure(kind: &JobEventKindV1) -> Option<(AttemptId, ValueRefV1, bool)> {
    match kind {
        JobEventKindV1::AttemptFailed { attempt, error, retryable } => {
            Some((attempt.clone(), error.clone(), *retryable))
        }
        JobEventKindV1::Indeterminate { attempt, reason, execution_may_have_occurred } => Some((
            attempt.clone(),
            ValueRefV1::Inline {
                value: serde_json::json!({
                    "kind": "executor_recovery_ambiguity",
                    "reason": reason,
                    "execution_may_have_occurred": execution_may_have_occurred,
                }),
            },
            true,
        )),
        _ => None,
    }
}

fn transition_allowed(from: JobStateV1, to: JobStateV1) -> bool {
    if from.is_terminal() {
        return false;
    }
    from == to
        || matches!(
            (from, to),
            (
                JobStateV1::Queued,
                JobStateV1::Blocked
                    | JobStateV1::Dispatching
                    | JobStateV1::Cancelled
                    | JobStateV1::Failed
            ) | (
                JobStateV1::Blocked,
                JobStateV1::Queued | JobStateV1::Cancelled | JobStateV1::Failed
            ) | (
                JobStateV1::Dispatching,
                JobStateV1::Running
                    | JobStateV1::RetryPending
                    | JobStateV1::Succeeded
                    | JobStateV1::Failed
                    | JobStateV1::Cancelled
                    | JobStateV1::Indeterminate
            ) | (
                JobStateV1::Running,
                JobStateV1::RetryPending
                    | JobStateV1::Succeeded
                    | JobStateV1::Failed
                    | JobStateV1::Cancelled
                    | JobStateV1::Indeterminate
            ) | (
                JobStateV1::RetryPending,
                JobStateV1::Dispatching
                    | JobStateV1::Cancelled
                    | JobStateV1::Failed
                    | JobStateV1::Indeterminate
            )
        )
}

fn update_access(
    current: &JobAccessV1,
    add_readers: &[HomeId],
    remove_readers: &[HomeId],
    add_controllers: &[HomeId],
    remove_controllers: &[HomeId],
) -> Result<JobAccessV1, HomeError> {
    let mut readers: BTreeSet<_> = current.readers.iter().cloned().collect();
    let mut controllers: BTreeSet<_> = current.controllers.iter().cloned().collect();
    for id in remove_readers {
        readers.remove(id);
    }
    for id in remove_controllers {
        controllers.remove(id);
    }
    readers.extend(add_readers.iter().cloned());
    controllers.extend(add_controllers.iter().cloned());
    let access = JobAccessV1 {
        readers: readers.into_iter().collect(),
        controllers: controllers.into_iter().collect(),
    };
    access.validate().map_err(invalid)?;
    Ok(access)
}

fn submitted_event(
    state: &HomeState,
    job: &JobId,
) -> Result<SignedRecordV1<JobEventV1>, HomeError> {
    state
        .jobs
        .get(job)
        .and_then(|record| record.events.first())
        .filter(|event| matches!(event.payload.kind, JobEventKindV1::Submitted { .. }))
        .cloned()
        .ok_or_else(|| HomeError::State("accepted job has no durable Submitted proof".into()))
}

fn reply<T: Serialize>(env: &Envelope, schema: &str, message: &T) -> Outcome {
    Outcome::send(Dispatch::reply_to_env(env, aether::wire::to_bytes(message)).with_schema(schema))
}

fn protocol_error(code: &str, message: String, retryable: bool) -> JobMessageV1 {
    JobMessageV1::Error {
        error: ProtocolErrorV1 { code: code.into(), message: bound(message), retryable },
    }
}

fn bounded_private_read_response(message: JobMessageV1) -> JobMessageV1 {
    match serde_json::to_vec(&message) {
        Ok(encoded) if encoded.len() <= MAX_PRIVATE_READ_MESSAGE_BYTES => message,
        Ok(encoded) => protocol_error(
            "capacity",
            format!(
                "private read response is {} bytes, exceeds reserved proof-bearing limit {}",
                encoded.len(),
                MAX_PRIVATE_READ_MESSAGE_BYTES
            ),
            true,
        ),
        Err(error) => protocol_error("encoding_failed", error.to_string(), false),
    }
}

fn job_error(error: HomeError) -> JobMessageV1 {
    let retryable = matches!(error, HomeError::Journal(_) | HomeError::Capacity(_));
    let code = match &error {
        HomeError::Unauthorized(_) => "unauthorized",
        HomeError::NotFound(_) => "not_found",
        HomeError::Conflict(_) => "conflict",
        HomeError::Capacity(_) => "capacity",
        HomeError::Journal(_) => "storage",
        HomeError::Configuration(_)
        | HomeError::Invalid(_)
        | HomeError::State(_)
        | HomeError::Signing(_) => "invalid",
    };
    protocol_error(code, error.to_string(), retryable)
}

fn reply_home_error(env: &Envelope, error: HomeError) -> Outcome {
    let retryable = matches!(error, HomeError::Journal(_) | HomeError::Capacity(_));
    let code = match &error {
        HomeError::Unauthorized(_) => "unauthorized",
        HomeError::NotFound(_) => "not_found",
        HomeError::Conflict(_) => "conflict",
        HomeError::Capacity(_) => "capacity",
        HomeError::Journal(_) => "storage",
        HomeError::Configuration(_)
        | HomeError::Invalid(_)
        | HomeError::State(_)
        | HomeError::Signing(_) => "invalid",
    };
    reply(
        env,
        SCHEMA_HOME_V1,
        &HomeMessageV1::Error {
            error: ProtocolErrorV1 {
                code: code.into(),
                message: bound(error.to_string()),
                retryable,
            },
        },
    )
}

fn bound(mut value: String) -> String {
    if value.len() > gawdfn::MAX_REASON_BYTES {
        let mut end = gawdfn::MAX_REASON_BYTES;
        while !value.is_char_boundary(end) {
            end -= 1;
        }
        value.truncate(end);
    }
    value
}

fn invalid(error: impl std::fmt::Display) -> HomeError {
    HomeError::Invalid(error.to_string())
}

fn signing(error: impl std::fmt::Display) -> HomeError {
    HomeError::Signing(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gawdfn::{
        AbodeKeyBindingV1, CausalLinkV1, ControlId, CustodyGrantV1, CustodyRewrapEntryV1,
        CustodyRewrapRequirementV1, DeploymentId, Ed25519SeedSigner, FunctionAlias, FunctionId,
        HandoffId, JobAccessV1, JobGetV1, JobSubmitV1, OperationalKeyGrantV1, RecipientKeyWrapV1,
        ResolutionReceiptV1, SealedValueV1, SCHEMA_CUSTODY_REWRAP_V1, SCHEMA_FUNCTION_DEPLOY_V1,
        SCHEMA_HOME_V1,
    };
    use job_blob_fs::{BlobCaps, FsJobBlobStore};
    use serde_json::json;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct Metadata;
    impl FunctionMetadata for Metadata {
        fn effect(&self, _function: &ResolvedFunctionV1) -> EffectClassV1 {
            EffectClassV1::Idempotent
        }
    }

    struct AllowTrust;
    impl FunctionTrust for AllowTrust {
        fn allow_resolution(&self, _: &SignedRecordV1<ResolutionReceiptV1>) -> Result<(), String> {
            Ok(())
        }
        fn allow_deployment(&self, _: &SignedRecordV1<DeploymentReceiptV1>) -> Result<(), String> {
            Ok(())
        }
        fn allow_executor_receipt(
            &self,
            _: &SignedRecordV1<ExecutionReceiptV1>,
            _: &SignedRecordV1<DeploymentReceiptV1>,
        ) -> Result<(), String> {
            Ok(())
        }
        fn allow_placement_decision(
            &self,
            _: &SignedRecordV1<PlacementDecisionV1>,
        ) -> Result<(), String> {
            Ok(())
        }
        fn allow_retry_decision(&self, _: &SignedRecordV1<RetryDecisionV1>) -> Result<(), String> {
            Ok(())
        }
        fn allow_read_relay(&self, _: &str, _: &str) -> Result<(), String> {
            Ok(())
        }
    }

    struct AllowBlobs;
    impl gawdfn::BlobAvailability for AllowBlobs {
        fn verify_available(&self, _: &gawdfn::BlobRefV1) -> Result<(), gawdfn::ContractError> {
            Ok(())
        }
    }

    struct TestRewrapper {
        binding: SignedRecordV1<RecipientKeyBindingV1>,
        proof: Arc<Ed25519SeedSigner>,
        mode: AtomicUsize,
        calls: AtomicUsize,
        requests: Mutex<Vec<(SignedRecordV1<CustodyRewrapRequestV1>, Vec<CustodyRewrapSourceV1>)>>,
    }

    impl TestRewrapper {
        fn new(
            binding: SignedRecordV1<RecipientKeyBindingV1>,
            proof: Arc<Ed25519SeedSigner>,
        ) -> Self {
            Self {
                binding,
                proof,
                mode: AtomicUsize::new(0),
                calls: AtomicUsize::new(0),
                requests: Mutex::new(Vec::new()),
            }
        }
    }

    impl CustodyKeyRewrapper for TestRewrapper {
        fn current_binding(&self) -> Result<SignedRecordV1<RecipientKeyBindingV1>, String> {
            if self.mode.load(Ordering::SeqCst) == 1 {
                Err("binding unavailable".into())
            } else {
                Ok(self.binding.clone())
            }
        }

        fn rewrap(
            &self,
            request: &SignedRecordV1<CustodyRewrapRequestV1>,
            inventory: &[CustodyRewrapSourceV1],
        ) -> Result<SignedRecordV1<CustodyRewrapReceiptV1>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.requests
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push((request.clone(), inventory.to_vec()));
            if self.mode.load(Ordering::SeqCst) == 2 {
                return Err("rewrap refused".into());
            }
            let destination_binding_hash =
                canonical_hash(&self.binding).map_err(|error| error.to_string())?;
            let entries = inventory
                .iter()
                .enumerate()
                .map(|(index, source)| CustodyRewrapEntryV1 {
                    sealed_value_hash: source.sealed_value_hash.clone(),
                    ciphertext: source.ciphertext.clone(),
                    source_wrap_hash: canonical_hash(&source.source_wrap).unwrap(),
                    destination_wrap: RecipientKeyWrapV1 {
                        recipient: self.binding.payload.abode.clone(),
                        binding_hash: destination_binding_hash.clone(),
                        encapsulated_key: format!("destination-encapsulated-{index}"),
                        wrapped_data_key: format!("destination-wrapped-{index}"),
                    },
                })
                .collect();
            let signer = if self.mode.load(Ordering::SeqCst) == 3 {
                Arc::new(Ed25519SeedSigner::from_seed([0x7f; 32]).unwrap())
            } else {
                self.proof.clone()
            };
            SignedRecordV1::sign(
                SCHEMA_CUSTODY_REWRAP_V1,
                CustodyRewrapReceiptV1 {
                    request: Box::new(request.clone()),
                    entries,
                    evidence: vec![],
                },
                signer.as_ref(),
            )
            .map_err(|error| error.to_string())
        }
    }

    struct CountingAuthoritySigner {
        inner: Arc<Ed25519SeedSigner>,
        calls: AtomicUsize,
    }

    impl AuthoritySigner for CountingAuthoritySigner {
        fn public_key(&self) -> &str {
            self.inner.public_key()
        }

        fn sign(&self, message: &[u8]) -> Result<String, gawdfn::ContractError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.inner.sign(message)
        }
    }

    struct Fixture {
        root: PathBuf,
        owner: Arc<Ed25519SeedSigner>,
        operational: Arc<Ed25519SeedSigner>,
        resolver: Ed25519SeedSigner,
        executor: Ed25519SeedSigner,
        authority: HomeAuthorityV1,
        function: FunctionId,
        artifact: String,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let root = std::env::temp_dir()
                .join(format!("alpha-function-home-{name}-{}-{n}", std::process::id()));
            fs::create_dir_all(&root).unwrap();
            let owner = Arc::new(Ed25519SeedSigner::from_seed([1; 32]).unwrap());
            let operational = Arc::new(Ed25519SeedSigner::from_seed([2; 32]).unwrap());
            let home = HomeId::new(owner.public_key());
            let abode = SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                AbodeKeyBindingV1 {
                    abode: home.clone(),
                    root_public_key: owner.public_key().into(),
                    issued_at_unix_ms: None,
                },
                owner.as_ref(),
            )
            .unwrap();
            let grant = SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                OperationalKeyGrantV1 {
                    home,
                    epoch: 1,
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
                owner.as_ref(),
            )
            .unwrap();
            Self {
                root,
                owner,
                operational,
                resolver: Ed25519SeedSigner::from_seed([3; 32]).unwrap(),
                executor: Ed25519SeedSigner::from_seed([5; 32]).unwrap(),
                authority: HomeAuthorityV1 { abode, operational: grant, prepared: None },
                function: FunctionId {
                    manifest_content_address: hash('a'),
                    entrypoint: "compute".into(),
                },
                artifact: hash('b'),
            }
        }

        fn config(&self) -> HomeConfig {
            HomeConfig::new(
                &self.root,
                HomeId::new(self.owner.public_key()),
                "creature:7",
                self.authority.clone(),
            )
        }

        fn open(&self) -> FunctionHome {
            FunctionHome::open(
                self.config(),
                self.operational.clone(),
                Arc::new(Metadata),
                Arc::new(AllowTrust),
                Arc::new(AllowBlobs),
            )
            .unwrap()
        }

        fn open_with_store(&self, store: Arc<FsJobBlobStore>) -> FunctionHome {
            FunctionHome::open_with_checkpoint_store(
                self.config(),
                self.operational.clone(),
                Arc::new(Metadata),
                Arc::new(AllowTrust),
                store.clone(),
                store,
            )
            .unwrap()
        }

        fn submission(
            &self,
            key: &str,
            input: serde_json::Value,
            mode: DeliveryModeV1,
        ) -> (
            SignedRecordV1<JobSubmitV1>,
            SignedRecordV1<ResolutionReceiptV1>,
            SignedRecordV1<DeploymentReceiptV1>,
        ) {
            let alias = FunctionAlias {
                realm: "r".into(),
                name: "worker".into(),
                version: "1.0.0".into(),
                entrypoint: "compute".into(),
            };
            let selector = gawdfn::FunctionSelectorV1::Alias { alias };
            let request = SignedRecordV1::sign(
                SCHEMA_JOB_V1,
                JobSubmitV1 {
                    home: HomeId::new(self.owner.public_key()),
                    caller_idempotency_key: key.into(),
                    function: selector.clone(),
                    input: ValueRefV1::Inline { value: input },
                    delivery: mode,
                    allow_duplicate_effects: false,
                    parent: None,
                    causal: vec![],
                    access: JobAccessV1::default(),
                    evidence: vec![],
                    result_recipients: vec![],
                    submitted_at_unix_ms: Some(10),
                },
                self.owner.as_ref(),
            )
            .unwrap();
            let resolution = SignedRecordV1::sign(
                SCHEMA_FUNCTION_DEPLOY_V1,
                ResolutionReceiptV1 {
                    selector,
                    function: self.function.clone(),
                    artifact_hash: self.artifact.clone(),
                    resolved_at_unix_ms: Some(9),
                    evidence: vec![],
                },
                &self.resolver,
            )
            .unwrap();
            let deployment = SignedRecordV1::sign(
                SCHEMA_FUNCTION_DEPLOY_V1,
                DeploymentReceiptV1 {
                    deployment: DeploymentId::new("deploy-1"),
                    function: self.function.clone(),
                    artifact_hash: self.artifact.clone(),
                    realm: "r".into(),
                    node: "n".into(),
                    executor: self.executor.public_key().into(),
                    executor_creature: "9".into(),
                    creature: "11".into(),
                    registered_at_unix_ms: Some(8),
                    evidence: vec![],
                },
                &self.executor,
            )
            .unwrap();
            (request, resolution, deployment)
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn hash(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    fn recipient_binding(
        fixture: &Fixture,
        proof: &Ed25519SeedSigner,
        encryption_byte: u8,
    ) -> SignedRecordV1<RecipientKeyBindingV1> {
        SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            RecipientKeyBindingV1 {
                abode: HomeId::new(fixture.owner.public_key()),
                signing_public_key: proof.public_key().into(),
                encryption_public_key: format!("{encryption_byte:02x}").repeat(32),
                suite: "hpke-x25519".into(),
                issued_at_unix_ms: None,
                expires_at_unix_ms: None,
            },
            fixture.owner.as_ref(),
        )
        .unwrap()
    }

    fn sealed_for_binding(
        home: &HomeId,
        binding: &SignedRecordV1<RecipientKeyBindingV1>,
        ciphertext: gawdfn::BlobRefV1,
        tag: &str,
    ) -> ValueRefV1 {
        ValueRefV1::Sealed {
            sealed: Box::new(SealedValueV1 {
                ciphertext,
                suite: binding.payload.suite.clone(),
                plaintext_digest: None,
                recipients: vec![RecipientKeyWrapV1 {
                    recipient: home.clone(),
                    binding_hash: canonical_hash(binding).unwrap(),
                    encapsulated_key: format!("encapsulated-{tag}"),
                    wrapped_data_key: format!("wrapped-{tag}"),
                }],
            }),
        }
    }

    fn custody_rewrap_grant(
        fixture: &Fixture,
        source: HomeAuthorityV1,
        destination: &HomeConfig,
        checkpoint: &SignedRecordV1<gawdfn::HomeCheckpointV1>,
        handoff: &str,
        source_location: (&str, &str),
        bindings: (SignedRecordV1<RecipientKeyBindingV1>, SignedRecordV1<RecipientKeyBindingV1>),
    ) -> SignedRecordV1<CustodyGrantV1> {
        let mut payload = custody_grant(
            fixture,
            source,
            destination,
            checkpoint,
            handoff,
            source_location.0,
            source_location.1,
        )
        .payload;
        payload.destination_rewrap = Some(CustodyRewrapRequirementV1 {
            source_binding: Box::new(bindings.0),
            destination_binding: Box::new(bindings.1),
            evidence: vec![],
        });
        SignedRecordV1::sign(SCHEMA_HOME_V1, payload, fixture.owner.as_ref()).unwrap()
    }

    fn test_envelope(schema: &str, payload: Vec<u8>, reply_to: Option<Address>) -> Envelope {
        Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(76)),
                to: Address::Creature(CreatureId(75)),
                reply_to,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: Some(1),
                commitment: None,
                schema: schema.into(),
                origin: None,
            },
            payload,
        }
    }

    fn signed_read_requests(
        fixture: &Fixture,
        handle: &JobHandleV1,
        nonce: &str,
        reply_to: &Address,
    ) -> (SignedRecordV1<JobGetRelayV1>, SignedRecordV1<EventQueryRelayV1>) {
        let route = serde_json::to_string(reply_to).unwrap();
        let get = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetV1 { handle: handle.clone(), nonce: format!("get-{nonce}") },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let get = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetRelayV1 { caller: get, reply_to: route.clone() },
            fixture.operational.as_ref(),
        )
        .unwrap();
        let events = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryV1 {
                handle: handle.clone(),
                after_sequence: None,
                limit: 16,
                nonce: format!("events-{nonce}"),
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let events = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryRelayV1 { caller: events, reply_to: route },
            fixture.operational.as_ref(),
        )
        .unwrap();
        (get, events)
    }

    fn fail_retryable_job(
        fixture: &Fixture,
        home: &FunctionHome,
        key: &str,
    ) -> (JobHandleV1, AttemptId) {
        let (request, resolution, deployment) =
            fixture.submission(key, json!({}), DeliveryModeV1::AtLeastOnce { max_attempts: 2 });
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new retry job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let attempt = grant.payload.attempt.clone();
        let failed = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                executor: fixture.executor.public_key().into(),
                sequence: 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::Failed {
                    error: ValueRefV1::Inline { value: json!({"error": key}) },
                    retryable: true,
                },
            },
            &fixture.executor,
        )
        .unwrap();
        home.apply_executor_receipt(failed).unwrap();
        (handle, attempt)
    }

    fn spawn_child(
        fixture: &Fixture,
        home: &FunctionHome,
        parent: &JobHandleV1,
        parent_attempt: &AttemptId,
        key: &str,
    ) -> (JobHandleV1, SignedRecordV1<JobEventV1>, SignedRecordV1<JobEventV1>) {
        let parent_page = home
            .events(&EventQueryV1 {
                handle: parent.clone(),
                after_sequence: None,
                limit: 64,
                nonce: "parent-events".into(),
            })
            .unwrap();
        let parent_event = parent_page
            .events
            .iter()
            .find(|event| event_attempt(&event.payload.kind) == Some(parent_attempt))
            .unwrap();
        let parent_event_hash = canonical_hash(parent_event).unwrap();
        let (request, resolution, deployment) =
            fixture.submission(key, json!({"child": key}), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        payload.parent = Some(parent.clone());
        let request = SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap();
        let child_request_hash = request.payload.request_hash().unwrap();
        let control = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: parent.clone(),
                expected_home_epoch: 1,
                control: ControlId::new(format!("spawn-{key}")),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::ProposeChild {
                    parent_attempt: parent_attempt.clone(),
                    parent_event_hash,
                    spawn_key: key.into(),
                    child_request_hash,
                    submit: Box::new(request),
                    resolution: Box::new(resolution),
                    deployment: Box::new(deployment),
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let spawned = home.control(control).unwrap();
        let JobEventKindV1::ChildSpawned { child, .. } = &spawned.payload.kind else {
            panic!("expected child spawn")
        };
        let child = child.clone();
        let submitted = home
            .events(&EventQueryV1 {
                handle: child.clone(),
                after_sequence: None,
                limit: 2,
                nonce: "child-events".into(),
            })
            .unwrap()
            .events
            .into_iter()
            .next()
            .unwrap();
        (child, spawned, submitted)
    }

    fn authority_for(fixture: &Fixture, signer: &Ed25519SeedSigner, epoch: u64) -> HomeAuthorityV1 {
        HomeAuthorityV1 {
            abode: fixture.authority.abode.clone(),
            operational: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                OperationalKeyGrantV1 {
                    home: HomeId::new(fixture.owner.public_key()),
                    epoch,
                    operational_public_key: signer.public_key().into(),
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
                fixture.owner.as_ref(),
            )
            .unwrap(),
            prepared: None,
        }
    }

    fn destination_config(
        fixture: &Fixture,
        root: PathBuf,
        signer: &Ed25519SeedSigner,
        epoch: u64,
        realm: &str,
        node: &str,
    ) -> HomeConfig {
        let mut config = HomeConfig::new(
            root,
            HomeId::new(fixture.owner.public_key()),
            format!("home-{epoch}"),
            authority_for(fixture, signer, epoch),
        )
        .with_location(realm, node);
        config.epoch = epoch;
        config
    }

    fn custody_grant(
        fixture: &Fixture,
        source: HomeAuthorityV1,
        destination: &HomeConfig,
        checkpoint: &SignedRecordV1<gawdfn::HomeCheckpointV1>,
        handoff: &str,
        source_realm: &str,
        source_node: &str,
    ) -> SignedRecordV1<CustodyGrantV1> {
        SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyGrantV1 {
                home: HomeId::new(fixture.owner.public_key()),
                handoff: HandoffId::new(handoff),
                from_epoch: checkpoint.payload.epoch,
                to_epoch: destination.epoch,
                source_authority: source,
                source_realm: source_realm.into(),
                source_node: source_node.into(),
                destination_realm: destination.realm.clone(),
                destination_node: destination.node.clone(),
                checkpoint_hash: canonical_hash(checkpoint).unwrap(),
                source_log_root: checkpoint.payload.log_root.clone(),
                destination_operational_key: destination.authority.operational.clone(),
                evidence: vec![],
                issued_at_unix_ms: None,
                destination_rewrap: None,
            },
            fixture.owner.as_ref(),
        )
        .unwrap()
    }

    fn prepared_transfer(
        fixture: &Fixture,
        destination_seed: u8,
        suffix: &str,
    ) -> (Arc<FsJobBlobStore>, HomeConfig, Arc<Ed25519SeedSigner>, PreparedHandoff) {
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join(format!("blobs-{suffix}")), BlobCaps::default())
                .unwrap(),
        );
        let source = fixture.open_with_store(store.clone());
        let checkpoint = source.create_checkpoint(None).unwrap();
        let destination_signer =
            Arc::new(Ed25519SeedSigner::from_seed([destination_seed; 32]).unwrap());
        let destination = destination_config(
            fixture,
            fixture.root.join(format!("destination-{suffix}")),
            destination_signer.as_ref(),
            2,
            "realm-b",
            &format!("node-{suffix}"),
        );
        let grant = custody_grant(
            fixture,
            fixture.authority.clone(),
            &destination,
            &checkpoint,
            &format!("handoff-{suffix}"),
            "local",
            "local",
        );
        let prepared = source.prepare_handoff(grant, checkpoint).unwrap();
        (store, destination, destination_signer, prepared)
    }

    fn prepared_rewrap_transfer(
        fixture: &Fixture,
        suffix: &str,
    ) -> (
        Arc<FsJobBlobStore>,
        HomeConfig,
        Arc<Ed25519SeedSigner>,
        PreparedHandoff,
        Arc<TestRewrapper>,
    ) {
        let store = Arc::new(
            FsJobBlobStore::open(
                fixture.root.join(format!("rewrap-transfer-{suffix}")),
                BlobCaps::default(),
            )
            .unwrap(),
        );
        let source_proof = Arc::new(Ed25519SeedSigner::from_seed([0x71; 32]).unwrap());
        let destination_proof = Arc::new(Ed25519SeedSigner::from_seed([0x72; 32]).unwrap());
        let source_binding = recipient_binding(fixture, source_proof.as_ref(), 0x73);
        let destination_binding = recipient_binding(fixture, destination_proof.as_ref(), 0x74);
        let source = FunctionHome::open_with_checkpoint_store_and_rewrapper(
            fixture.config(),
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
            Arc::new(TestRewrapper::new(source_binding.clone(), source_proof)),
        )
        .unwrap();
        let blob = store.put_ref("application/octet-stream", suffix.as_bytes()).unwrap();
        let (request, resolution, deployment) =
            fixture.submission(suffix, json!(null), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        payload.input = sealed_for_binding(&fixture.config().home, &source_binding, blob, suffix);
        source
            .submit(
                SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap(),
                resolution,
                deployment,
            )
            .unwrap();
        let destination_signer = Arc::new(Ed25519SeedSigner::from_seed([0x75; 32]).unwrap());
        let destination = destination_config(
            fixture,
            fixture.root.join(format!("rewrap-destination-{suffix}")),
            destination_signer.as_ref(),
            2,
            "realm-b",
            suffix,
        );
        let checkpoint = source.create_checkpoint(None).unwrap();
        let grant = custody_rewrap_grant(
            fixture,
            fixture.authority.clone(),
            &destination,
            &checkpoint,
            &format!("rewrap-{suffix}"),
            ("local", "local"),
            (source_binding, destination_binding.clone()),
        );
        let prepared = source.prepare_handoff(grant, checkpoint).unwrap();
        let adapter = Arc::new(TestRewrapper::new(destination_binding, destination_proof));
        (store, destination, destination_signer, prepared, adapter)
    }

    #[test]
    fn submit_is_idempotent_conflict_detecting_and_recoverable() {
        let fixture = Fixture::new("submit");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("same-key", json!({"x": 1}), DeliveryModeV1::AtMostOnce);
        let first = home.submit(request.clone(), resolution.clone(), deployment.clone()).unwrap();
        assert!(matches!(first, SubmitOutcome::Accepted { .. }));
        assert!(matches!(
            home.submit(request, resolution, deployment).unwrap(),
            SubmitOutcome::Existing { .. }
        ));
        let (different, resolution, deployment) =
            fixture.submission("same-key", json!({"x": 2}), DeliveryModeV1::AtMostOnce);
        assert!(matches!(
            home.submit(different, resolution, deployment),
            Err(HomeError::Conflict(_))
        ));
        let job = derive_job_id(&HomeId::new(fixture.owner.public_key()), "same-key").unwrap();
        drop(home);
        let recovered = fixture.open();
        assert_eq!(recovered.get(&job).unwrap().state, JobStateV1::Queued);
    }

    #[test]
    fn grant_and_out_of_order_terminal_receipt_remain_monotonic() {
        let fixture = Fixture::new("receipt");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("job", json!({"x": 1}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, Some(20), None).unwrap();
        assert!(gawdfn::verify_execution_grant(&grant).is_ok());
        let grant_hash = canonical_hash(&grant).unwrap();
        // A terminal sequence 2 can arrive before the claim receipt over a distributed route. It
        // closes the job; the later lower receipt is retained as audit evidence without reopening.
        let terminal = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: grant.payload.attempt.clone(),
                grant_hash: grant_hash.clone(),
                executor: fixture.executor.public_key().into(),
                sequence: 2,
                observed_at_unix_ms: Some(30),
                stage: ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value: json!({"answer": 42}) },
                },
            },
            &fixture.executor,
        )
        .unwrap();
        home.apply_executor_receipt(terminal.clone()).unwrap();
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Succeeded);
        let late = home
            .apply_executor_receipt(
                SignedRecordV1::sign(
                    SCHEMA_EXECUTE_V1,
                    ExecutionReceiptV1 {
                        attempt: grant.payload.attempt,
                        grant_hash,
                        executor: fixture.executor.public_key().into(),
                        sequence: 1,
                        observed_at_unix_ms: Some(21),
                        stage: ExecutionStageV1::Claimed,
                    },
                    &fixture.executor,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            late,
            ApplyReceiptOutcome::Applied(event)
                if matches!(event.payload.kind, JobEventKindV1::LateReceipt { .. })
        ));
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Succeeded);
        assert!(matches!(
            home.apply_executor_receipt(terminal),
            Ok(ApplyReceiptOutcome::Duplicate(_))
        ));
    }

    #[test]
    fn observation_cap_high_water_and_preflight_survive_recovery_without_blocking_terminal() {
        let fixture = Fixture::new("observation-cap");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("job", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let grant_hash = canonical_hash(&grant).unwrap();
        let observation = |receipt_sequence: u64, progress_sequence: u64| {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: grant_hash.clone(),
                    executor: fixture.executor.public_key().into(),
                    sequence: receipt_sequence,
                    observed_at_unix_ms: None,
                    stage: ExecutionStageV1::Progress {
                        sequence: progress_sequence,
                        progress: ValueRefV1::Inline { value: json!({"step": progress_sequence}) },
                    },
                },
                &fixture.executor,
            )
            .unwrap()
        };

        home.apply_executor_receipt(observation(1, 1)).unwrap();
        let log_path = fixture.root.join("function-home.jsonl");
        let bytes_before = fs::read(&log_path).unwrap();
        let tip_before = home.journal.tip_hash();
        let records_before = home.journal.len();
        let out_of_order_receipt = observation(2, 2);
        let snapshot = home.get(&handle.job).unwrap();
        let out_of_order_event = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobEventV1 {
                handle: handle.clone(),
                home_epoch: 1,
                authority: fixture.authority.clone(),
                sequence: snapshot.last_sequence + 2,
                occurred_at_unix_ms: None,
                state_after: snapshot.state,
                cancel_requested: snapshot.cancel_requested,
                kind: JobEventKindV1::Progress {
                    attempt: grant.payload.attempt.clone(),
                    sequence: 2,
                    progress: ValueRefV1::Inline { value: json!({"step": 2}) },
                },
                foreign_receipt: Some(Box::new(out_of_order_receipt.clone())),
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        let mut state = home.state.lock().unwrap_or_else(|poison| poison.into_inner());
        assert!(matches!(
            home.persist_and_apply(
                &mut state,
                HomeLedgerRecord {
                    grant: None,
                    receipt: Some(out_of_order_receipt),
                    events: vec![out_of_order_event],
                },
            ),
            Err(HomeError::State(reason)) if reason.contains("event sequence")
        ));
        drop(state);
        assert_eq!(fs::read(&log_path).unwrap(), bytes_before);
        assert_eq!(home.journal.tip_hash(), tip_before);
        assert_eq!(home.journal.len(), records_before);
        drop(home);

        let home = fixture.open();
        assert!(matches!(
            home.apply_executor_receipt(observation(2, 1)),
            Err(HomeError::State(reason)) if reason.contains("progress sequence")
        ));
        for sequence in 2..=MAX_ATTEMPT_OBSERVATIONS as u64 {
            home.apply_executor_receipt(observation(sequence, sequence)).unwrap();
        }
        assert!(matches!(
            home.apply_executor_receipt(observation(
                MAX_ATTEMPT_OBSERVATIONS as u64 + 1,
                MAX_ATTEMPT_OBSERVATIONS as u64 + 1,
            )),
            Err(HomeError::Capacity(_))
        ));
        drop(home);

        let home = fixture.open();
        assert!(matches!(
            home.apply_executor_receipt(observation(
                MAX_ATTEMPT_OBSERVATIONS as u64 + 1,
                MAX_ATTEMPT_OBSERVATIONS as u64 + 1,
            )),
            Err(HomeError::Capacity(_))
        ));
        let terminal = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: grant.payload.attempt,
                grant_hash,
                executor: fixture.executor.public_key().into(),
                sequence: MAX_ATTEMPT_OBSERVATIONS as u64 + 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::Succeeded {
                    result: ValueRefV1::Inline { value: json!({"done": true}) },
                },
            },
            &fixture.executor,
        )
        .unwrap();
        home.apply_executor_receipt(terminal).unwrap();
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Succeeded);
    }

    #[test]
    fn home_journal_reserves_terminal_and_control_ack_slots_under_progress_pressure() {
        let fixture = Fixture::new("home-record-reservations");
        let mut config = fixture.config();
        config.journal_caps.max_records = 7;
        let home = FunctionHome::open(
            config,
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            Arc::new(AllowBlobs),
        )
        .unwrap();
        let (request, resolution, deployment) =
            fixture.submission("reserved", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let control = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: handle.clone(),
                expected_home_epoch: 1,
                control: ControlId::new("reserved-ack"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"direction": "left"}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        home.control(control.clone()).unwrap();
        let receipt = |sequence, stage| {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: canonical_hash(&grant).unwrap(),
                    executor: fixture.executor.public_key().into(),
                    sequence,
                    observed_at_unix_ms: None,
                    stage,
                },
                &fixture.executor,
            )
            .unwrap()
        };
        let queued = receipt(
            1,
            ExecutionStageV1::ControlQueued { control: control.payload.control.clone() },
        );
        home.apply_executor_receipt(queued).unwrap();
        home.apply_executor_receipt(receipt(
            2,
            ExecutionStageV1::Progress {
                sequence: 1,
                progress: ValueRefV1::Inline { value: json!({"pct": 10}) },
            },
        ))
        .unwrap();
        assert!(matches!(
            home.apply_executor_receipt(receipt(
                3,
                ExecutionStageV1::Progress {
                    sequence: 2,
                    progress: ValueRefV1::Inline { value: json!({"pct": 20}) },
                },
            )),
            Err(HomeError::Capacity(_))
        ));
        let acknowledged = receipt(
            4,
            ExecutionStageV1::ControlAcknowledged {
                control: control.payload.control,
                disposition: gawdfn::ControlDispositionV1::Applied,
                detail: None,
            },
        );
        home.apply_executor_receipt(acknowledged.clone()).unwrap();
        home.apply_executor_receipt(receipt(
            5,
            ExecutionStageV1::Succeeded {
                result: ValueRefV1::Inline { value: json!({"ok": true}) },
            },
        ))
        .unwrap();
        assert_eq!(home.journal.len(), 7);
        drop(home);

        let reopened = fixture.open();
        assert_eq!(reopened.get(&handle.job).unwrap().state, JobStateV1::Succeeded);
        assert_eq!(reopened.state.lock().unwrap().nonterminal_jobs, 0);
        assert_eq!(reopened.state.lock().unwrap().unacknowledged_forwarded_controls, 0);
        assert!(matches!(
            reopened.apply_executor_receipt(acknowledged).unwrap(),
            ApplyReceiptOutcome::Duplicate(_)
        ));
    }

    #[test]
    fn event_pages_are_byte_bounded_and_resume_at_the_first_omitted_large_event() {
        let fixture = Fixture::new("event-page-bytes");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("job", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let grant_hash = canonical_hash(&grant).unwrap();
        for sequence in 1..=24_u64 {
            let receipt = SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: grant_hash.clone(),
                    executor: fixture.executor.public_key().into(),
                    sequence,
                    observed_at_unix_ms: None,
                    stage: ExecutionStageV1::Progress {
                        sequence,
                        progress: ValueRefV1::Inline {
                            value: json!({
                                "sequence": sequence,
                                "padding": "x".repeat(gawdfn::MAX_PROGRESS_BYTES - 1024),
                            }),
                        },
                    },
                },
                &fixture.executor,
            )
            .unwrap();
            home.apply_executor_receipt(receipt).unwrap();
        }

        let query = EventQueryV1 {
            handle: handle.clone(),
            after_sequence: None,
            limit: MAX_EVENT_PAGE_ITEMS as u16,
            nonce: "large-page-1".into(),
        };
        let page = home.events(&query).unwrap();
        assert!(!page.events.is_empty());
        assert!(page.events.len() < 26, "byte pressure, not item count, must split the page");
        let cursor = page.next_after_sequence.expect("large retained history has another page");
        assert_eq!(cursor, page.events.last().unwrap().payload.sequence);
        let response = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventPageResponseV1 {
                request_hash: hash('9'),
                home_epoch: 1,
                authority: fixture.authority.clone(),
                page,
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        let encoded =
            serde_json::to_vec(&JobMessageV1::EventPage { response: Box::new(response) }).unwrap();
        assert!(encoded.len() <= MAX_PRIVATE_READ_MESSAGE_BYTES);

        let resumed = home
            .events(&EventQueryV1 {
                handle,
                after_sequence: Some(cursor),
                limit: MAX_EVENT_PAGE_ITEMS as u16,
                nonce: "large-page-2".into(),
            })
            .unwrap();
        assert_eq!(resumed.events.first().unwrap().payload.sequence, cursor + 1);
    }

    #[test]
    fn declared_result_recipients_require_matching_sealed_key_envelopes() {
        let fixture = Fixture::new("result-recipient-wraps");
        let home = fixture.open();
        let required_signer = Ed25519SeedSigner::from_seed([90; 32]).unwrap();
        let other_signer = Ed25519SeedSigner::from_seed([91; 32]).unwrap();
        let required = HomeId::new(required_signer.public_key());
        let (request, resolution, deployment) =
            fixture.submission("sealed-result", json!({}), DeliveryModeV1::AtMostOnce);
        let mut request_payload = request.payload;
        request_payload.result_recipients = vec![required.clone()];
        let request =
            SignedRecordV1::sign(SCHEMA_JOB_V1, request_payload, fixture.owner.as_ref()).unwrap();
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let receipt = |result: ValueRefV1| {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: canonical_hash(&grant).unwrap(),
                    executor: fixture.executor.public_key().into(),
                    sequence: 1,
                    observed_at_unix_ms: None,
                    stage: ExecutionStageV1::Succeeded { result },
                },
                &fixture.executor,
            )
            .unwrap()
        };
        assert!(matches!(
            home.apply_executor_receipt(receipt(ValueRefV1::Inline { value: json!({"x": 1}) })),
            Err(HomeError::Invalid(_))
        ));

        let sealed_for = |recipient: HomeId| ValueRefV1::Sealed {
            sealed: Box::new(SealedValueV1 {
                ciphertext: gawdfn::BlobRefV1 {
                    digest: hash('9'),
                    size: 128,
                    media_type: "application/octet-stream".into(),
                },
                suite: "hpke-x25519".into(),
                plaintext_digest: None,
                recipients: vec![RecipientKeyWrapV1 {
                    recipient,
                    binding_hash: hash('8'),
                    encapsulated_key: "encapsulated-key".into(),
                    wrapped_data_key: "wrapped-data-key".into(),
                }],
            }),
        };
        assert!(matches!(
            home.apply_executor_receipt(receipt(sealed_for(HomeId::new(
                other_signer.public_key()
            )))),
            Err(HomeError::Invalid(_))
        ));
        home.apply_executor_receipt(receipt(sealed_for(required))).unwrap();
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Succeeded);
        drop(home);
        assert_eq!(fixture.open().get(&handle.job).unwrap().state, JobStateV1::Succeeded);
    }

    #[test]
    fn duplicate_receipt_returns_its_exact_foreign_provenance_event() {
        let fixture = Fixture::new("receipt-dedup");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("job", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let receipt = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: grant.payload.attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                executor: fixture.executor.public_key().into(),
                sequence: 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::Claimed,
            },
            &fixture.executor,
        )
        .unwrap();
        home.apply_executor_receipt(receipt.clone()).unwrap();
        let steer = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle,
                expected_home_epoch: 1,
                control: ControlId::new("after-claim"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"pace": "slow"}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        home.control(steer).unwrap();
        let ApplyReceiptOutcome::Duplicate(event) =
            home.apply_executor_receipt(receipt.clone()).unwrap()
        else {
            panic!("duplicate")
        };
        assert_eq!(
            canonical_hash(event.payload.foreign_receipt.as_deref().unwrap()).unwrap(),
            canonical_hash(&receipt).unwrap()
        );
    }

    #[test]
    fn unseen_lower_control_ack_is_retained_as_late_audit_without_reopening_terminal_state() {
        let fixture = Fixture::new("late-control-ack");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("late-ack", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let control = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: handle.clone(),
                expected_home_epoch: 1,
                control: ControlId::new("ack-before-terminal-send"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"mode": "safe"}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        home.control(control.clone()).unwrap();
        let receipt = |sequence, stage| {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: canonical_hash(&grant).unwrap(),
                    executor: fixture.executor.public_key().into(),
                    sequence,
                    observed_at_unix_ms: None,
                    stage,
                },
                &fixture.executor,
            )
            .unwrap()
        };
        home.apply_executor_receipt(receipt(
            1,
            ExecutionStageV1::ControlQueued { control: control.payload.control.clone() },
        ))
        .unwrap();
        home.apply_executor_receipt(receipt(
            3,
            ExecutionStageV1::Succeeded {
                result: ValueRefV1::Inline { value: json!({"done": true}) },
            },
        ))
        .unwrap();
        let ack = receipt(
            2,
            ExecutionStageV1::ControlAcknowledged {
                control: control.payload.control,
                disposition: gawdfn::ControlDispositionV1::Applied,
                detail: None,
            },
        );
        let ApplyReceiptOutcome::Applied(late) = home.apply_executor_receipt(ack.clone()).unwrap()
        else {
            panic!("previously unseen lower ack must be durably retained")
        };
        assert_eq!(late.payload.state_after, JobStateV1::Succeeded);
        assert!(matches!(
            late.payload.kind,
            JobEventKindV1::LateReceipt {
                observed: ExecutionStageV1::ControlAcknowledged { .. },
                ..
            }
        ));
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Succeeded);
        assert_eq!(
            home.state.lock().unwrap().highest_receipt_sequences.get(&(handle.job.clone(), 1)),
            Some(&3)
        );
        drop(home);
        let reopened = fixture.open();
        assert!(matches!(
            reopened.apply_executor_receipt(ack).unwrap(),
            ApplyReceiptOutcome::Duplicate(_)
        ));
        assert_eq!(reopened.get(&handle.job).unwrap().state, JobStateV1::Succeeded);
    }

    #[test]
    fn at_least_once_indeterminate_preserves_receipt_then_can_cancel_retry() {
        let fixture = Fixture::new("indeterminate");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("job", json!({}), DeliveryModeV1::AtLeastOnce { max_attempts: 2 });
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let receipt = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: grant.payload.attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                executor: fixture.executor.public_key().into(),
                sequence: 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::Indeterminate {
                    reason: "crash after effect boundary".into(),
                    execution_may_have_occurred: true,
                },
            },
            &fixture.executor,
        )
        .unwrap();
        let ApplyReceiptOutcome::Applied(event) =
            home.apply_executor_receipt(receipt.clone()).unwrap()
        else {
            panic!("applied")
        };
        assert_eq!(event.payload.state_after, JobStateV1::RetryPending);
        assert!(matches!(
            event.payload.kind,
            JobEventKindV1::Indeterminate { execution_may_have_occurred: true, .. }
        ));
        gawdfn::verify_job_event_with_grant(&event, &grant).unwrap();
        let mut tampered_payload = event.payload.clone();
        let JobEventKindV1::Indeterminate { execution_may_have_occurred, .. } =
            &mut tampered_payload.kind
        else {
            panic!("indeterminate event")
        };
        *execution_may_have_occurred = false;
        let tampered =
            SignedRecordV1::sign(SCHEMA_JOB_V1, tampered_payload, fixture.operational.as_ref())
                .unwrap();
        assert!(gawdfn::verify_job_event_with_grant(&tampered, &grant).is_err());
        assert_eq!(
            canonical_hash(event.payload.foreign_receipt.as_deref().unwrap()).unwrap(),
            canonical_hash(&receipt).unwrap()
        );

        let cancel = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: handle.clone(),
                expected_home_epoch: 1,
                control: ControlId::new("cancel-retry"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Cancel { reason: "enough".into() },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        assert_eq!(home.control(cancel).unwrap().payload.state_after, JobStateV1::Cancelled);
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Cancelled);
    }

    #[test]
    fn recovery_reissues_queued_retry_and_live_grant_rails() {
        let fixture = Fixture::new("recovery-dispatch");
        let home = fixture.open();

        let (request, resolution, deployment) =
            fixture.submission("queued", json!({}), DeliveryModeV1::AtMostOnce);
        home.submit(request, resolution, deployment).unwrap();

        let (request, resolution, deployment) =
            fixture.submission("live", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle: live, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new live job")
        };
        home.issue_grant(&live.job, deployment, None, None).unwrap();

        let (request, resolution, deployment) =
            fixture.submission("retry", json!({}), DeliveryModeV1::AtLeastOnce { max_attempts: 2 });
        let SubmitOutcome::Accepted { handle: retry, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new retry job")
        };
        let grant = home.issue_grant(&retry.job, deployment, None, None).unwrap();
        let failed = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: grant.payload.attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                executor: fixture.executor.public_key().into(),
                sequence: 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::Failed {
                    error: ValueRefV1::Inline { value: json!({"error": "retry"}) },
                    retryable: true,
                },
            },
            &fixture.executor,
        )
        .unwrap();
        home.apply_executor_receipt(failed).unwrap();
        drop(home);

        let recovered = fixture.open();
        let outcome = recovered.recovery_dispatches();
        assert_eq!(outcome.dispatches.len(), 3);
        let mut placement = 0;
        let mut retry_questions = 0;
        let mut execution_resumes = 0;
        for dispatch in outcome.dispatches {
            match dispatch.schema.as_str() {
                SCHEMA_POLICY_V1 => {
                    let message: PolicyMessageV1 =
                        serde_json::from_slice(&dispatch.payload).unwrap();
                    match message {
                        PolicyMessageV1::SelectDeployment { .. } => placement += 1,
                        PolicyMessageV1::DecideRetry { .. } => retry_questions += 1,
                        _ => panic!("unexpected policy recovery message"),
                    }
                }
                SCHEMA_EXECUTE_V1 => {
                    let message: ExecuteMessageV1 =
                        serde_json::from_slice(&dispatch.payload).unwrap();
                    assert!(matches!(message, ExecuteMessageV1::Grant { .. }));
                    execution_resumes += 1;
                }
                other => panic!("unexpected recovery schema {other}"),
            }
        }
        assert_eq!((placement, retry_questions, execution_resumes), (1, 1, 1));
    }

    #[test]
    fn home_recovery_sweep_is_bounded_self_poked_and_rejects_remote_same_id_pokes() {
        let fixture = Fixture::new("bounded-home-recovery");
        let mut home = fixture.open();
        for index in 0..(MAX_HOME_RECOVERY_DISPATCHES + 6) {
            let (request, resolution, deployment) = fixture.submission(
                &format!("queued-{index}"),
                json!({}),
                DeliveryModeV1::AtMostOnce,
            );
            home.submit(request, resolution, deployment).unwrap();
        }
        let me = CreatureId(75);
        home.me = Some(me);
        let first = home.recovery_dispatches();
        assert_eq!(first.dispatches.len(), MAX_HOME_RECOVERY_DISPATCHES + 1);
        assert_eq!(
            first
                .dispatches
                .iter()
                .filter(|dispatch| dispatch.schema == HOME_RECOVERY_POKE_SCHEMA)
                .count(),
            1
        );

        let remote_forgery = Envelope {
            header: aether::Header {
                from: Address::Creature(me),
                to: Address::Creature(me),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "remote".into(),
                corr: None,
                commitment: None,
                schema: HOME_RECOVERY_POKE_SCHEMA.into(),
                origin: Some(aether::Origin::node(NodeId("remote-node".into()))),
            },
            payload: HOME_RECOVERY_POKE_PAYLOAD.to_vec(),
        };
        assert!(home.handle(remote_forgery).dispatches.is_empty());
        let wrong_local_sender = Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(74)),
                to: Address::Creature(me),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "local".into(),
                corr: None,
                commitment: None,
                schema: HOME_RECOVERY_POKE_SCHEMA.into(),
                origin: None,
            },
            payload: HOME_RECOVERY_POKE_PAYLOAD.to_vec(),
        };
        assert!(home.handle(wrong_local_sender).dispatches.is_empty());

        let valid_poke = Envelope {
            header: aether::Header {
                from: Address::Creature(me),
                to: Address::Creature(me),
                reply_to: None,
                seq: 2,
                causal: vec![],
                stamp: 2,
                sig: "local".into(),
                corr: None,
                commitment: None,
                schema: HOME_RECOVERY_POKE_SCHEMA.into(),
                origin: None,
            },
            payload: HOME_RECOVERY_POKE_PAYLOAD.to_vec(),
        };
        let tail = home.handle(valid_poke);
        assert_eq!(tail.dispatches.len(), 6);
        assert!(tail
            .dispatches
            .iter()
            .all(|dispatch| dispatch.schema != HOME_RECOVERY_POKE_SCHEMA));

        let mut recovered = BTreeSet::new();
        for dispatch in first.dispatches.iter().chain(&tail.dispatches) {
            if dispatch.schema != SCHEMA_POLICY_V1 {
                continue;
            }
            let PolicyMessageV1::SelectDeployment { question } =
                serde_json::from_slice::<PolicyMessageV1>(&dispatch.payload).unwrap()
            else {
                panic!("queued recovery emitted the wrong policy work")
            };
            recovered.insert(question.payload.job.job);
        }
        assert_eq!(recovered.len(), MAX_HOME_RECOVERY_DISPATCHES + 6);
    }

    #[test]
    fn executor_route_refresh_uses_exact_node_scoped_roles_at_every_remote_grain() {
        let fixture = Fixture::new("executor-route-grains");
        let home = fixture.open();
        let (_, _, mut deployment) =
            fixture.submission("route", json!({}), DeliveryModeV1::AtMostOnce);

        deployment.payload.realm = "local".into();
        deployment.payload.node = "local".into();
        assert_eq!(
            home.executor_target(&deployment.payload),
            Address::Role(Role::new(FUNCTION_EXECUTOR_ROLE)),
            "same-Sanctum recovery follows the current admitted role binding"
        );

        deployment.payload.node = "peer".into();
        assert_eq!(
            home.executor_target(&deployment.payload),
            Address::NodeRole(NodeId("peer".into()), Role::new(FUNCTION_EXECUTOR_ROLE)),
            "same-Realm execution follows the exact peer's explicitly exposed current role"
        );

        deployment.payload.realm = "other".into();
        assert_eq!(
            home.executor_target(&deployment.payload),
            Address::Omega {
                realm: RealmId::new("other"),
                target: Box::new(Address::NodeRole(
                    NodeId("peer".into()),
                    Role::new(FUNCTION_EXECUTOR_ROLE),
                )),
            },
            "Omega carries the exact gateway node and unresolved executor role"
        );
    }

    #[test]
    fn genesis_route_revision_is_durable_and_recovery_queries_the_current_coordinator() {
        let fixture = Fixture::new("genesis-route-revision");
        let mut home = fixture.open();
        home.refresh_runtime_route("99").unwrap();
        home.config.coordinator = "99".into();
        let (request, resolution, deployment) =
            fixture.submission("running", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        assert_eq!(grant.payload.home_route_sequence, 2);
        assert_eq!(grant.payload.home_coordinator, "99");
        drop(home);

        let mut reopened = fixture.open();
        assert_eq!(reopened.state.lock().unwrap().custody.active_route_sequence().unwrap(), 2);
        reopened.refresh_runtime_route("100").unwrap();
        reopened.config.coordinator = "100".into();
        let recovery = reopened.recovery_dispatches();
        let query = recovery
            .dispatches
            .iter()
            .find_map(|dispatch| {
                let ExecuteMessageV1::Query { request } =
                    serde_json::from_slice::<ExecuteMessageV1>(&dispatch.payload).ok()?
                else {
                    return None;
                };
                Some(request)
            })
            .expect("same-epoch route revision reconciles through a signed current query");
        assert_eq!(query.payload.home_route_sequence, 3);
        assert_eq!(query.payload.home_coordinator, "100");

        let control = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle,
                expected_home_epoch: 1,
                control: ControlId::new("after-route-rebind"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"route": 3}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let event = reopened.control(control.clone()).unwrap();
        let (endorsed, _) = reopened.endorsed_control(control, &event).unwrap().unwrap();
        assert_eq!(endorsed.payload.home_route_sequence, 3);
        assert_eq!(endorsed.payload.home_coordinator, "100");
    }

    #[test]
    fn custody_route_revision_preserves_frozen_and_prepared_reservations() {
        let fixture = Fixture::new("custody-route-reservation");
        let mut source_config = fixture.config();
        source_config.journal_caps.max_records = 3;
        let source_authority = source_config.authority.clone();
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("blobs"), BlobCaps::default()).unwrap(),
        );
        let source = FunctionHome::open_with_checkpoint_store(
            source_config,
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
        )
        .unwrap();

        assert!(matches!(source.refresh_runtime_route("99"), Err(HomeError::Capacity(_))));
        assert_eq!(source.custody_journal.len(), 1);

        let checkpoint = source.create_checkpoint(None).unwrap();
        let destination_signer = Ed25519SeedSigner::from_seed([59; 32]).unwrap();
        let destination = destination_config(
            &fixture,
            fixture.root.join("destination"),
            &destination_signer,
            2,
            "realm-b",
            "node-b",
        );
        let grant = custody_grant(
            &fixture,
            source_authority,
            &destination,
            &checkpoint,
            "reserved-handoff",
            "local",
            "local",
        );
        source.prepare_handoff(grant, checkpoint).unwrap();
        assert_eq!(
            source.custody_journal.len(),
            3,
            "the final two custody slots remain available for Frozen and Prepared"
        );
    }

    #[test]
    fn recovery_reemits_exact_signed_control_after_home_append_before_send() {
        let fixture = Fixture::new("control-recovery");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("controlled", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new controlled job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let attempt = grant.payload.attempt.clone();
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle,
                expected_home_epoch: 1,
                control: ControlId::new("recover-exact-control"),
                issued_at_unix_ms: Some(31),
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"pace": "slow"}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let durable = home.control(caller.clone()).unwrap();
        assert!(matches!(
            &durable.payload.kind,
            JobEventKindV1::ControlRequested {
                request,
                attempt: Some(selected),
            } if request.as_ref() == &caller && selected == &attempt
        ));
        drop(home); // crash after Home journal fsync, before executor send

        let recovered = fixture.open();
        let recovery = recovered.recovery_dispatches();
        let controls: Vec<_> = recovery
            .dispatches
            .iter()
            .filter_map(|dispatch| {
                let message = serde_json::from_slice::<ExecuteMessageV1>(&dispatch.payload).ok()?;
                match message {
                    ExecuteMessageV1::Control { request } => Some(*request),
                    _ => None,
                }
            })
            .collect();
        assert_eq!(controls.len(), 1);
        let endorsed = &controls[0];
        gawdfn::verify_execution_control(endorsed).unwrap();
        assert_eq!(endorsed.payload.caller_request, caller);
        assert_eq!(endorsed.payload.attempt, attempt);
        assert_eq!(endorsed.payload.home_sequence, durable.payload.sequence);

        let queued = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                executor: fixture.executor.public_key().into(),
                sequence: 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::ControlQueued {
                    control: endorsed.payload.caller_request.payload.control.clone(),
                },
            },
            &fixture.executor,
        )
        .unwrap();
        recovered.apply_executor_receipt(queued).unwrap();
        let acknowledged = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                executor: fixture.executor.public_key().into(),
                sequence: 2,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::ControlAcknowledged {
                    control: endorsed.payload.caller_request.payload.control.clone(),
                    disposition: gawdfn::ControlDispositionV1::Applied,
                    detail: Some("pace applied".into()),
                },
            },
            &fixture.executor,
        )
        .unwrap();
        let ApplyReceiptOutcome::Applied(event) =
            recovered.apply_executor_receipt(acknowledged).unwrap()
        else {
            panic!("terminal control disposition applied")
        };
        assert!(matches!(
            event.payload.kind,
            JobEventKindV1::ControlAcknowledged {
                attempt: acknowledged_attempt,
                disposition: gawdfn::ControlDispositionV1::Applied,
                ..
            } if acknowledged_attempt == attempt
        ));
        drop(recovered);

        let reopened = fixture.open();
        assert!(reopened.recovery_dispatches().dispatches.iter().all(|dispatch| {
            !matches!(
                serde_json::from_slice::<ExecuteMessageV1>(&dispatch.payload),
                Ok(ExecuteMessageV1::Control { .. })
            )
        }));
    }

    #[test]
    fn moved_home_reendorses_pending_control_with_current_route_and_old_acceptance_proof() {
        let fixture = Fixture::new("moved-control-recovery");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("moved-control-blobs"), BlobCaps::default())
                .unwrap(),
        );
        let source = fixture.open_with_store(store.clone());
        let (request, resolution, deployment) =
            fixture.submission("moved-controlled", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            source.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new controlled job")
        };
        let grant = source.issue_grant(&handle.job, deployment, None, None).unwrap();
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle,
                expected_home_epoch: 1,
                control: ControlId::new("move-pending"),
                issued_at_unix_ms: Some(41),
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"pace": "slow"}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let accepted = source.control(caller.clone()).unwrap();
        let checkpoint = source.create_checkpoint(Some(42)).unwrap();
        let destination_signer = Arc::new(Ed25519SeedSigner::from_seed([84; 32]).unwrap());
        let destination = destination_config(
            &fixture,
            fixture.root.join("moved-control-e2"),
            destination_signer.as_ref(),
            2,
            "realm-b",
            "node-b",
        );
        let custody = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &destination,
            &checkpoint,
            "moved-control-e1-e2",
            "local",
            "local",
        );
        let prepared = source.prepare_handoff(custody, checkpoint).unwrap();
        let staged = stage_handoff(
            &destination,
            destination_signer.clone(),
            store.as_ref(),
            prepared.prepared,
        )
        .unwrap();
        activate_staged_handoff(&destination, destination_signer.clone(), store.as_ref(), staged)
            .unwrap();
        let destination_home = FunctionHome::open_with_checkpoint_store(
            destination,
            destination_signer,
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
        )
        .unwrap();
        let controls: Vec<_> = destination_home
            .recovery_dispatches()
            .dispatches
            .into_iter()
            .filter_map(|dispatch| {
                let message = serde_json::from_slice::<ExecuteMessageV1>(&dispatch.payload).ok()?;
                let ExecuteMessageV1::Control { request } = message else {
                    return None;
                };
                Some(*request)
            })
            .collect();
        assert_eq!(controls.len(), 1);
        let continued = &controls[0];
        gawdfn::verify_execution_control(continued).unwrap();
        assert_eq!(continued.payload.home_epoch, 2);
        assert_eq!(continued.payload.home_realm, "realm-b");
        assert_eq!(continued.payload.home_node, "node-b");
        assert_eq!(continued.payload.home_coordinator, "home-2");
        assert_eq!(continued.payload.caller_request, caller);
        assert_eq!(*continued.payload.accepted_event, accepted);
        assert_eq!(continued.payload.grant_hash, canonical_hash(&grant).unwrap());
        assert_eq!(continued.payload.attempt, grant.payload.attempt);
    }

    #[test]
    fn retry_stop_rejects_altered_question_cross_job_replay_and_terminal_replay() {
        let fixture = Fixture::new("retry-policy-proof-binding");
        let home = fixture.open();
        let policy = Ed25519SeedSigner::from_seed([71; 32]).unwrap();
        let (first, first_attempt) = fail_retryable_job(&fixture, &home, "first");
        let (second, second_attempt) = fail_retryable_job(&fixture, &home, "second");

        let first_question = home.retry_question(&first, &first_attempt).unwrap();
        let mut altered_payload = first_question.payload.clone();
        altered_payload.evidence.push(gawdfn::EvidenceRefV1 {
            kind: "untrusted-score".into(),
            digest: hash('e'),
            issuer: None,
            locator: None,
        });
        let altered_question =
            SignedRecordV1::sign(SCHEMA_POLICY_V1, altered_payload, fixture.operational.as_ref())
                .unwrap();
        let altered_decision = SignedRecordV1::sign(
            SCHEMA_POLICY_V1,
            RetryDecisionV1::Stop {
                question_hash: canonical_hash(&altered_question).unwrap(),
                job: first.clone(),
                failed_attempt: first_attempt.clone(),
                terminal_state: JobStateV1::Failed,
                reason: "altered evidence".into(),
            },
            &policy,
        )
        .unwrap();
        assert!(matches!(
            home.apply_retry_decision(altered_decision),
            Err(HomeError::Unauthorized(_))
        ));

        let cross_job = SignedRecordV1::sign(
            SCHEMA_POLICY_V1,
            RetryDecisionV1::Stop {
                question_hash: canonical_hash(&first_question).unwrap(),
                job: second,
                failed_attempt: second_attempt,
                terminal_state: JobStateV1::Failed,
                reason: "wrong job".into(),
            },
            &policy,
        )
        .unwrap();
        assert!(matches!(home.apply_retry_decision(cross_job), Err(HomeError::Unauthorized(_))));

        let correct = SignedRecordV1::sign(
            SCHEMA_POLICY_V1,
            RetryDecisionV1::Stop {
                question_hash: canonical_hash(&first_question).unwrap(),
                job: first.clone(),
                failed_attempt: first_attempt,
                terminal_state: JobStateV1::Failed,
                reason: "bounded stop".into(),
            },
            &policy,
        )
        .unwrap();
        home.apply_retry_decision(correct.clone()).unwrap();
        assert_eq!(home.get(&first.job).unwrap().state, JobStateV1::Failed);
        assert!(matches!(home.apply_retry_decision(correct), Err(HomeError::State(_))));
    }

    #[test]
    fn signed_reads_enforce_owner_and_delegates() {
        let fixture = Fixture::new("reads");
        let mut home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("job", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment).unwrap()
        else {
            panic!()
        };
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetV1 { handle: handle.clone(), nonce: "read-1".into() },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let reply_to = Address::Creature(CreatureId(77));
        let route = serde_json::to_string(&reply_to).unwrap();
        let get = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetRelayV1 { caller, reply_to: route.clone() },
            fixture.operational.as_ref(),
        )
        .unwrap();
        let env = Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(76)),
                to: Address::Creature(CreatureId(75)),
                reply_to: Some(reply_to.clone()),
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: Some(1),
                commitment: None,
                schema: SCHEMA_JOB_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        assert_eq!(home.authorize_get(&env, &get).unwrap(), handle);
        let mut good_env = env.clone();
        good_env.payload =
            aether::wire::to_bytes(&JobMessageV1::Get { request: Box::new(get.clone()) });
        let good = home.handle(good_env);
        let JobMessageV1::Snapshot { response } =
            serde_json::from_slice::<JobMessageV1>(&good.dispatches[0].payload).unwrap()
        else {
            panic!("authorized private read did not return a snapshot")
        };
        gawdfn::verify_job_snapshot_response_for(&response, &get).unwrap();

        let mut redirected_env = env.clone();
        redirected_env.header.reply_to = Some(Address::Creature(CreatureId(99)));
        redirected_env.payload =
            aether::wire::to_bytes(&JobMessageV1::Get { request: Box::new(get.clone()) });
        let redirected = home.handle(redirected_env);
        assert!(matches!(
            serde_json::from_slice::<JobMessageV1>(&redirected.dispatches[0].payload).unwrap(),
            JobMessageV1::Error { .. }
        ));
        let stranger = Ed25519SeedSigner::from_seed([99; 32]).unwrap();
        let denied_caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetV1 { handle, nonce: "read-2".into() },
            &stranger,
        )
        .unwrap();
        let denied = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetRelayV1 { caller: denied_caller, reply_to: route },
            &stranger,
        )
        .unwrap();
        assert!(matches!(home.authorize_get(&env, &denied), Err(HomeError::Unauthorized(_))));

        let stolen_route = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobGetRelayV1 {
                caller: get.payload.caller.clone(),
                reply_to: serde_json::to_string(&Address::Creature(CreatureId(99))).unwrap(),
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        assert!(matches!(home.authorize_get(&env, &stolen_route), Err(HomeError::Unauthorized(_))));
    }

    #[test]
    fn home_addressed_values_require_one_stable_current_recipient_binding() {
        let fixture = Fixture::new("recipient-binding");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("binding-blobs"), BlobCaps::default()).unwrap(),
        );
        let proof = Arc::new(Ed25519SeedSigner::from_seed([0x31; 32]).unwrap());
        let binding = recipient_binding(&fixture, proof.as_ref(), 0x41);
        let adapter = Arc::new(TestRewrapper::new(binding.clone(), proof));
        let home = FunctionHome::open_with_checkpoint_store_and_rewrapper(
            fixture.config(),
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
            adapter.clone(),
        )
        .unwrap();
        let ciphertext = store.put_ref("application/octet-stream", b"binding-one").unwrap();
        let (request, resolution, deployment) =
            fixture.submission("binding-one", json!(null), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        payload.input = sealed_for_binding(&fixture.config().home, &binding, ciphertext, "one");
        let exact = SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap();
        home.submit(exact, resolution, deployment).unwrap();

        let ciphertext = store.put_ref("application/octet-stream", b"ambiguous").unwrap();
        let (request, resolution, deployment) =
            fixture.submission("ambiguous", json!(null), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        let mut ambiguous =
            sealed_for_binding(&fixture.config().home, &binding, ciphertext, "ambiguous");
        let ValueRefV1::Sealed { sealed } = &mut ambiguous else { unreachable!() };
        sealed.recipients.push(sealed.recipients[0].clone());
        payload.input = ambiguous;
        let ambiguous =
            SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap();
        assert!(matches!(
            home.submit(ambiguous, resolution, deployment),
            Err(HomeError::Invalid(_))
        ));
        drop(home);

        // Durable B1-addressed data pins restart to B1 even without a custody overlay.
        FunctionHome::open_with_checkpoint_store_and_rewrapper(
            fixture.config(),
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
            adapter,
        )
        .unwrap();
        let wrong_proof = Arc::new(Ed25519SeedSigner::from_seed([0x32; 32]).unwrap());
        let wrong_binding = recipient_binding(&fixture, wrong_proof.as_ref(), 0x42);
        let wrong_adapter = Arc::new(TestRewrapper::new(wrong_binding, wrong_proof));
        assert!(matches!(
            FunctionHome::open_with_checkpoint_store_and_rewrapper(
                fixture.config(),
                fixture.operational.clone(),
                Arc::new(Metadata),
                Arc::new(AllowTrust),
                store.clone(),
                store,
                wrong_adapter,
            ),
            Err(HomeError::Unauthorized(_))
        ));
    }

    #[test]
    fn custody_freezes_source_stages_then_activates_and_recovers_idempotently() {
        let fixture = Fixture::new("custody");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("blobs"), BlobCaps::default()).unwrap(),
        );
        let home = fixture.open_with_store(store.clone());
        let (request, resolution, deployment) =
            fixture.submission("portable-job", json!({"work": "kept"}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, request_hash, submitted } =
            home.submit(request, resolution, deployment).unwrap()
        else {
            panic!("new job")
        };
        gawdfn::verify_job_acceptance(&handle, &request_hash, &submitted).unwrap();

        let checkpoint = home.create_checkpoint(Some(40)).unwrap();
        let archive_bytes = store.get_ref(&checkpoint.payload.state).unwrap();
        let archive_text = String::from_utf8(archive_bytes).unwrap();
        assert!(!archive_text.contains("private_key"));
        assert!(!archive_text.contains("seed"));
        assert!(!archive_text.contains("rewrap_overlay"));

        let destination_signer = Arc::new(Ed25519SeedSigner::from_seed([6; 32]).unwrap());
        let destination = destination_config(
            &fixture,
            fixture.root.join("destination-e2"),
            destination_signer.as_ref(),
            2,
            "realm-b",
            "node-b",
        );
        let grant = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &destination,
            &checkpoint,
            "handoff-e1-e2",
            "local",
            "local",
        );
        let prepared = home.prepare_handoff(grant.clone(), checkpoint.clone()).unwrap();
        assert_eq!(prepared.grant, grant);
        assert!(matches!(home.custody_status(), HomeCustodyStatus::Frozen { epoch: 1, .. }));
        assert!(matches!(home.create_checkpoint(None), Err(HomeError::State(_))));
        // Same request is safe after the irreversible fence; a changed one is not.
        home.prepare_handoff(prepared.grant.clone(), prepared.checkpoint.clone()).unwrap();

        let staged = stage_handoff(
            &destination,
            destination_signer.clone(),
            store.as_ref(),
            prepared.prepared.clone(),
        )
        .unwrap();
        let staged_open = FunctionHome::open_with_checkpoint_store(
            destination.clone(),
            destination_signer.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
        );
        assert!(matches!(staged_open, Err(HomeError::State(_))));

        let lease = activate_staged_handoff(
            &destination,
            destination_signer.clone(),
            store.as_ref(),
            staged.clone(),
        )
        .unwrap();
        gawdfn::verify_home_lease(&lease).unwrap();
        assert_eq!(
            lease,
            activate_staged_handoff(
                &destination,
                destination_signer.clone(),
                store.as_ref(),
                staged,
            )
            .unwrap()
        );
        let destination_home = FunctionHome::open_with_checkpoint_store(
            destination.clone(),
            destination_signer,
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
        )
        .unwrap();
        let imported = destination_home.get(&handle.job).unwrap();
        assert_eq!(imported.state, JobStateV1::Queued);
        assert_eq!(imported.home_epoch, 2);

        home.record_handoff_redirect(lease.clone()).unwrap();
        home.record_handoff_redirect(lease).unwrap();
        drop(home);
        let recovered_source = fixture.open_with_store(store);
        assert!(matches!(
            recovered_source.custody_status(),
            HomeCustodyStatus::Frozen { redirect: Some(_), .. }
        ));
        assert!(matches!(recovered_source.create_checkpoint(None), Err(HomeError::State(_))));
    }

    #[test]
    fn frozen_source_is_inert_for_exact_duplicates_recovery_and_private_reads() {
        let fixture = Fixture::new("frozen-inert");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("blobs"), BlobCaps::default()).unwrap(),
        );
        let counting = Arc::new(CountingAuthoritySigner {
            inner: fixture.operational.clone(),
            calls: AtomicUsize::new(0),
        });
        let mut source = FunctionHome::open_with_checkpoint_store(
            fixture.config(),
            counting.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
        )
        .unwrap();
        let (request, resolution, deployment) =
            fixture.submission("frozen-job", json!({"work": true}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            source.submit(request.clone(), resolution.clone(), deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = source.issue_grant(&handle.job, deployment.clone(), None, None).unwrap();
        let control = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: handle.clone(),
                expected_home_epoch: 1,
                control: ControlId::new("pending-before-freeze"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"pace": "slow"}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let accepted_control = source.control(control.clone()).unwrap();
        let queued = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: grant.payload.attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                executor: fixture.executor.public_key().into(),
                sequence: 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::ControlQueued { control: control.payload.control.clone() },
            },
            &fixture.executor,
        )
        .unwrap();
        source.apply_executor_receipt(queued.clone()).unwrap();

        let checkpoint = source.create_checkpoint(None).unwrap();
        let destination_signer = Arc::new(Ed25519SeedSigner::from_seed([42; 32]).unwrap());
        let destination = destination_config(
            &fixture,
            fixture.root.join("destination"),
            destination_signer.as_ref(),
            2,
            "realm-b",
            "node-b",
        );
        let custody = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &destination,
            &checkpoint,
            "frozen-inert-handoff",
            "local",
            "local",
        );
        let prepared = source.prepare_handoff(custody, checkpoint).unwrap();
        let calls_at_freeze = counting.calls.load(Ordering::SeqCst);

        assert!(matches!(
            source.submit(request.clone(), resolution.clone(), deployment.clone()),
            Err(HomeError::State(_))
        ));
        assert!(matches!(source.control(control.clone()), Err(HomeError::State(_))));
        assert!(matches!(source.apply_executor_receipt(queued.clone()), Err(HomeError::State(_))));
        assert!(matches!(
            source.endorsed_control(control.clone(), &accepted_control),
            Err(HomeError::State(_))
        ));
        assert!(source.recovery_dispatches().dispatches.is_empty());

        let submit_outcome = source.handle(test_envelope(
            SCHEMA_JOB_V1,
            aether::wire::to_bytes(&JobMessageV1::Submit {
                request: Box::new(request),
                resolution: Box::new(resolution),
                deployment: Box::new(deployment),
            }),
            None,
        ));
        let control_outcome = source.handle(test_envelope(
            SCHEMA_JOB_V1,
            aether::wire::to_bytes(&JobMessageV1::Control { request: Box::new(control.clone()) }),
            None,
        ));
        let receipt_outcome = source.handle(test_envelope(
            SCHEMA_EXECUTE_V1,
            aether::wire::to_bytes(&ExecuteMessageV1::Receipt { receipt: Box::new(queued) }),
            None,
        ));
        for outcome in [&submit_outcome, &control_outcome, &receipt_outcome] {
            assert_eq!(outcome.dispatches.len(), 1);
            assert!(matches!(
                serde_json::from_slice::<JobMessageV1>(&outcome.dispatches[0].payload).unwrap(),
                JobMessageV1::Error { .. }
            ));
            assert!(outcome.dispatches.iter().all(|dispatch| dispatch.schema != SCHEMA_EXECUTE_V1
                && dispatch.schema != SCHEMA_POLICY_V1));
        }

        let reply_to = Address::Creature(CreatureId(77));
        let (get, events) = signed_read_requests(&fixture, &handle, "frozen", &reply_to);
        let frozen_get = source.handle(test_envelope(
            SCHEMA_JOB_V1,
            aether::wire::to_bytes(&JobMessageV1::Get { request: Box::new(get.clone()) }),
            Some(reply_to.clone()),
        ));
        let frozen_events = source.handle(test_envelope(
            SCHEMA_JOB_V1,
            aether::wire::to_bytes(&JobMessageV1::Events { request: Box::new(events.clone()) }),
            Some(reply_to.clone()),
        ));
        for outcome in [&frozen_get, &frozen_events] {
            assert!(matches!(
                serde_json::from_slice::<JobMessageV1>(&outcome.dispatches[0].payload).unwrap(),
                JobMessageV1::Error { .. }
            ));
        }
        assert_eq!(counting.calls.load(Ordering::SeqCst), calls_at_freeze);

        let staged = stage_handoff(
            &destination,
            destination_signer.clone(),
            store.as_ref(),
            prepared.prepared,
        )
        .unwrap();
        let lease = activate_staged_handoff(
            &destination,
            destination_signer.clone(),
            store.as_ref(),
            staged,
        )
        .unwrap();
        let mut destination_home = FunctionHome::open_with_checkpoint_store(
            destination,
            destination_signer,
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
        )
        .unwrap();
        source.record_handoff_redirect(lease).unwrap();
        let calls_at_redirect = counting.calls.load(Ordering::SeqCst);
        let retired_get = source.handle(test_envelope(
            SCHEMA_JOB_V1,
            aether::wire::to_bytes(&JobMessageV1::Get { request: Box::new(get.clone()) }),
            Some(reply_to.clone()),
        ));
        assert!(matches!(
            serde_json::from_slice::<JobMessageV1>(&retired_get.dispatches[0].payload).unwrap(),
            JobMessageV1::Error { .. }
        ));
        assert_eq!(counting.calls.load(Ordering::SeqCst), calls_at_redirect);

        let destination_get = destination_home.handle(test_envelope(
            SCHEMA_JOB_V1,
            aether::wire::to_bytes(&JobMessageV1::Get { request: Box::new(get) }),
            Some(reply_to.clone()),
        ));
        let destination_events = destination_home.handle(test_envelope(
            SCHEMA_JOB_V1,
            aether::wire::to_bytes(&JobMessageV1::Events { request: Box::new(events) }),
            Some(reply_to),
        ));
        assert!(matches!(
            serde_json::from_slice::<JobMessageV1>(&destination_get.dispatches[0].payload).unwrap(),
            JobMessageV1::Snapshot { .. }
        ));
        assert!(matches!(
            serde_json::from_slice::<JobMessageV1>(&destination_events.dispatches[0].payload)
                .unwrap(),
            JobMessageV1::EventPage { .. }
        ));
    }

    #[test]
    fn custody_requires_every_referenced_ciphertext_before_destination_stage() {
        let fixture = Fixture::new("custody-missing-blob");
        let source_store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("source-blobs"), BlobCaps::default()).unwrap(),
        );
        let input = source_store.put_ref("application/octet-stream", b"required input").unwrap();
        let home = fixture.open_with_store(source_store.clone());
        let (request, resolution, deployment) =
            fixture.submission("blob-job", json!(null), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        payload.input = ValueRefV1::Sealed {
            sealed: Box::new(SealedValueV1 {
                ciphertext: input.clone(),
                suite: "hpke-x25519".into(),
                plaintext_digest: None,
                recipients: vec![RecipientKeyWrapV1 {
                    // End-to-end recipient: this test exercises ciphertext durability, not a
                    // destination-local Home key declaration.
                    recipient: HomeId::new(
                        Ed25519SeedSigner::from_seed([0x6f; 32]).unwrap().public_key(),
                    ),
                    binding_hash: hash('7'),
                    encapsulated_key: "encapsulated-key".into(),
                    wrapped_data_key: "wrapped-data-key".into(),
                }],
            }),
        };
        let request = SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap();
        home.submit(request, resolution, deployment).unwrap();
        let checkpoint = home.create_checkpoint(None).unwrap();
        let destination_signer = Arc::new(Ed25519SeedSigner::from_seed([7; 32]).unwrap());
        let destination = destination_config(
            &fixture,
            fixture.root.join("missing-destination"),
            destination_signer.as_ref(),
            2,
            "realm-b",
            "node-missing",
        );
        let grant = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &destination,
            &checkpoint,
            "handoff-missing",
            "local",
            "local",
        );
        let prepared = home.prepare_handoff(grant, checkpoint.clone()).unwrap();

        // Transfer only the checkpoint archive, intentionally omitting its accepted input blob.
        let destination_store =
            FsJobBlobStore::open(fixture.root.join("destination-blobs"), BlobCaps::default())
                .unwrap();
        let bytes = source_store.get_ref(&checkpoint.payload.state).unwrap();
        assert_eq!(
            destination_store.put_ref(checkpoint.payload.state.media_type.clone(), &bytes).unwrap(),
            checkpoint.payload.state
        );
        assert!(matches!(
            stage_handoff(
                &destination,
                destination_signer.clone(),
                &destination_store,
                prepared.prepared.clone(),
            ),
            Err(HomeError::Invalid(_))
        ));
        let ciphertext = source_store.get_ref(&input).unwrap();
        assert_eq!(
            destination_store.put_ref(input.media_type.clone(), &ciphertext).unwrap(),
            input
        );
        stage_handoff(&destination, destination_signer, &destination_store, prepared.prepared)
            .unwrap();
    }

    #[test]
    fn custody_carries_complete_authority_history_across_multiple_hops() {
        let fixture = Fixture::new("custody-multihop");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("blobs"), BlobCaps::default()).unwrap(),
        );
        let source = fixture.open_with_store(store.clone());
        let (request, resolution, deployment) =
            fixture.submission("multihop-job", json!({"hop": 1}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            source.submit(request, resolution, deployment).unwrap()
        else {
            panic!("new job")
        };

        let e2_signer = Arc::new(Ed25519SeedSigner::from_seed([10; 32]).unwrap());
        let e2_config = destination_config(
            &fixture,
            fixture.root.join("home-e2"),
            e2_signer.as_ref(),
            2,
            "realm-b",
            "node-b",
        );
        let checkpoint1 = source.create_checkpoint(None).unwrap();
        let grant1 = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &e2_config,
            &checkpoint1,
            "handoff-1-2",
            "local",
            "local",
        );
        let prepared1 = source.prepare_handoff(grant1, checkpoint1).unwrap();
        let staged1 =
            stage_handoff(&e2_config, e2_signer.clone(), store.as_ref(), prepared1.prepared)
                .unwrap();
        activate_staged_handoff(&e2_config, e2_signer.clone(), store.as_ref(), staged1).unwrap();
        let e2_home = FunctionHome::open_with_checkpoint_store(
            e2_config.clone(),
            e2_signer.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
        )
        .unwrap();
        // Add an e2-signed record so the next destination must replay both historical epochs.
        let update = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: handle.clone(),
                expected_home_epoch: 2,
                control: ControlId::new("e2-record"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::AccessUpdate {
                    add_readers: vec![],
                    remove_readers: vec![],
                    add_controllers: vec![],
                    remove_controllers: vec![],
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        e2_home.control(update).unwrap();

        let e3_signer = Arc::new(Ed25519SeedSigner::from_seed([11; 32]).unwrap());
        let e3_config = destination_config(
            &fixture,
            fixture.root.join("home-e3"),
            e3_signer.as_ref(),
            3,
            "realm-c",
            "node-c",
        );
        let checkpoint2 = e2_home.create_checkpoint(None).unwrap();
        let grant2 = custody_grant(
            &fixture,
            e2_home.config.authority.clone(),
            &e3_config,
            &checkpoint2,
            "handoff-2-3",
            "realm-b",
            "node-b",
        );
        let prepared2 = e2_home.prepare_handoff(grant2, checkpoint2).unwrap();
        let staged2 =
            stage_handoff(&e3_config, e3_signer.clone(), store.as_ref(), prepared2.prepared)
                .unwrap();
        activate_staged_handoff(&e3_config, e3_signer.clone(), store.as_ref(), staged2).unwrap();
        let e3_home = FunctionHome::open_with_checkpoint_store(
            e3_config,
            e3_signer,
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
        )
        .unwrap();
        assert_eq!(e3_home.get(&handle.job).unwrap().home_epoch, 3);
        let page = e3_home
            .events(&EventQueryV1 {
                handle,
                after_sequence: None,
                limit: 10,
                nonce: "epoch-three-events".into(),
            })
            .unwrap();
        assert_eq!(page.events.len(), 2);
        assert_eq!(page.events[0].payload.home_epoch, 1);
        assert_eq!(page.events[1].payload.home_epoch, 2);
        page.validate().unwrap();
    }

    #[test]
    fn custody_rewrap_overlay_covers_old_and_new_values_across_two_hops() {
        let fixture = Fixture::new("custody-rewrap-multihop");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("rewrap-blobs"), BlobCaps::default()).unwrap(),
        );
        let e1_proof = Arc::new(Ed25519SeedSigner::from_seed([0x51; 32]).unwrap());
        let e2_proof = Arc::new(Ed25519SeedSigner::from_seed([0x52; 32]).unwrap());
        let e3_proof = Arc::new(Ed25519SeedSigner::from_seed([0x53; 32]).unwrap());
        let e1_binding = recipient_binding(&fixture, e1_proof.as_ref(), 0x61);
        let e2_binding = recipient_binding(&fixture, e2_proof.as_ref(), 0x62);
        let e3_binding = recipient_binding(&fixture, e3_proof.as_ref(), 0x63);
        let source = FunctionHome::open_with_checkpoint_store_and_rewrapper(
            fixture.config(),
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
            Arc::new(TestRewrapper::new(e1_binding.clone(), e1_proof)),
        )
        .unwrap();
        let old_blob = store.put_ref("application/octet-stream", b"epoch-one").unwrap();
        let (request, resolution, deployment) =
            fixture.submission("epoch-one", json!(null), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        payload.input =
            sealed_for_binding(&fixture.config().home, &e1_binding, old_blob, "epoch-one");
        source
            .submit(
                SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap(),
                resolution,
                deployment,
            )
            .unwrap();

        let e2_signer = Arc::new(Ed25519SeedSigner::from_seed([0x54; 32]).unwrap());
        let e2_config = destination_config(
            &fixture,
            fixture.root.join("rewrap-e2"),
            e2_signer.as_ref(),
            2,
            "realm-b",
            "node-b",
        );
        let checkpoint1 = source.create_checkpoint(None).unwrap();
        let grant1 = custody_rewrap_grant(
            &fixture,
            fixture.authority.clone(),
            &e2_config,
            &checkpoint1,
            "rewrap-1-2",
            ("local", "local"),
            (e1_binding, e2_binding.clone()),
        );
        let prepared1 = source.prepare_handoff(grant1, checkpoint1).unwrap();
        assert_eq!(prepared1.prepared.payload.rewrap_item_count, Some(1));
        let e2_adapter = Arc::new(TestRewrapper::new(e2_binding.clone(), e2_proof.clone()));
        let staged1 = stage_handoff_with_rewrapper(
            &e2_config,
            e2_signer.clone(),
            store.as_ref(),
            prepared1.prepared,
            e2_adapter.clone(),
        )
        .unwrap();
        gawdfn::verify_custody_staged(&staged1).unwrap();
        assert_eq!(e2_adapter.calls.load(Ordering::SeqCst), 1);
        let captured_request =
            e2_adapter.requests.lock().unwrap_or_else(|poison| poison.into_inner())[0].0.clone();
        assert_eq!(
            staged1.payload.rewrap_receipt.as_ref().unwrap().payload.request.as_ref(),
            &captured_request
        );
        let e2_overlay = staged1.clone();
        activate_staged_handoff(&e2_config, e2_signer.clone(), store.as_ref(), staged1).unwrap();

        let mismatched = Arc::new(TestRewrapper::new(e3_binding.clone(), e3_proof.clone()));
        assert!(matches!(
            FunctionHome::open_with_checkpoint_store_and_rewrapper(
                e2_config.clone(),
                e2_signer.clone(),
                Arc::new(Metadata),
                Arc::new(AllowTrust),
                store.clone(),
                store.clone(),
                mismatched,
            ),
            Err(HomeError::Unauthorized(_))
        ));
        let e2_home = FunctionHome::open_with_checkpoint_store_and_rewrapper(
            e2_config.clone(),
            e2_signer.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store.clone(),
            e2_adapter,
        )
        .unwrap();
        let new_blob = store.put_ref("application/octet-stream", b"epoch-two").unwrap();
        let (request, resolution, deployment) =
            fixture.submission("epoch-two", json!(null), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        payload.input =
            sealed_for_binding(&fixture.config().home, &e2_binding, new_blob, "epoch-two");
        e2_home
            .submit(
                SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap(),
                resolution,
                deployment,
            )
            .unwrap();

        let checkpoint2 = e2_home.create_checkpoint(None).unwrap();
        let archive2 = store.get_ref(&checkpoint2.payload.state).unwrap();
        assert!(String::from_utf8(archive2.clone()).unwrap().contains("rewrap_overlay"));

        // A root-valid alternate e1->e2 fork is not a valid overlay for the archive's exact e2
        // authority lineage.
        let mut alternate_grant_payload = e2_overlay.payload.prepared.payload.grant.payload.clone();
        alternate_grant_payload.handoff = HandoffId::new("alternate-rewrap-1-2");
        let alternate_grant =
            SignedRecordV1::sign(SCHEMA_HOME_V1, alternate_grant_payload, fixture.owner.as_ref())
                .unwrap();
        let original_prepared = e2_overlay.payload.prepared.as_ref();
        let alternate_prepared = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            gawdfn::CustodyPreparedV1 {
                grant: Box::new(alternate_grant.clone()),
                checkpoint: original_prepared.payload.checkpoint.clone(),
                grant_hash: canonical_hash(&alternate_grant).unwrap(),
                checkpoint_hash: original_prepared.payload.checkpoint_hash.clone(),
                source_log_root: original_prepared.payload.source_log_root.clone(),
                source_coordinator: original_prepared.payload.source_coordinator.clone(),
                rewrap_inventory_hash: original_prepared.payload.rewrap_inventory_hash.clone(),
                rewrap_item_count: original_prepared.payload.rewrap_item_count,
            },
            fixture.operational.as_ref(),
        )
        .unwrap();
        let requirement = alternate_grant.payload.destination_rewrap.as_ref().unwrap();
        let alternate_request = SignedRecordV1::sign(
            SCHEMA_CUSTODY_REWRAP_V1,
            CustodyRewrapRequestV1 {
                home: fixture.config().home,
                handoff: alternate_grant.payload.handoff.clone(),
                prepared_hash: canonical_hash(&alternate_prepared).unwrap(),
                grant_hash: canonical_hash(&alternate_grant).unwrap(),
                checkpoint_hash: alternate_prepared.payload.checkpoint_hash.clone(),
                requirement_hash: canonical_hash(requirement).unwrap(),
                inventory_hash: alternate_prepared.payload.rewrap_inventory_hash.clone().unwrap(),
                item_count: alternate_prepared.payload.rewrap_item_count.unwrap(),
            },
            e2_signer.as_ref(),
        )
        .unwrap();
        let alternate_receipt = SignedRecordV1::sign(
            SCHEMA_CUSTODY_REWRAP_V1,
            CustodyRewrapReceiptV1 {
                request: Box::new(alternate_request),
                entries: e2_overlay
                    .payload
                    .rewrap_receipt
                    .as_ref()
                    .unwrap()
                    .payload
                    .entries
                    .clone(),
                evidence: vec![],
            },
            e2_proof.as_ref(),
        )
        .unwrap();
        let alternate_staged = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            gawdfn::CustodyStagedV1 {
                prepared: Box::new(alternate_prepared.clone()),
                prepared_hash: canonical_hash(&alternate_prepared).unwrap(),
                grant_hash: alternate_prepared.payload.grant_hash.clone(),
                checkpoint_hash: alternate_prepared.payload.checkpoint_hash.clone(),
                destination_realm: e2_config.realm.clone(),
                destination_node: e2_config.node.clone(),
                destination_coordinator: e2_config.coordinator.clone(),
                rewrap_receipt: Some(Box::new(alternate_receipt)),
            },
            e2_signer.as_ref(),
        )
        .unwrap();
        gawdfn::verify_custody_staged(&alternate_staged).unwrap();
        let mut alternate_archive: serde_json::Value = serde_json::from_slice(&archive2).unwrap();
        alternate_archive["rewrap_overlay"] = serde_json::to_value(alternate_staged).unwrap();
        let alternate_bytes = gawdfn::canonical_json_bytes(&alternate_archive).unwrap();
        let alternate_blob =
            store.put_ref(checkpoint2.payload.state.media_type.clone(), &alternate_bytes).unwrap();
        let mut alternate_checkpoint_payload = checkpoint2.payload.clone();
        alternate_checkpoint_payload.state = alternate_blob;
        let alternate_checkpoint =
            SignedRecordV1::sign(SCHEMA_HOME_V1, alternate_checkpoint_payload, e2_signer.as_ref())
                .unwrap();
        let e3_signer = Arc::new(Ed25519SeedSigner::from_seed([0x55; 32]).unwrap());
        let e3_config = destination_config(
            &fixture,
            fixture.root.join("rewrap-e3"),
            e3_signer.as_ref(),
            3,
            "realm-c",
            "node-c",
        );
        let alternate_handoff = custody_rewrap_grant(
            &fixture,
            e2_home.config.authority.clone(),
            &e3_config,
            &alternate_checkpoint,
            "alternate-rewrap-2-3",
            ("realm-b", "node-b"),
            (e2_binding.clone(), e3_binding.clone()),
        );
        assert!(matches!(
            e2_home.prepare_handoff(alternate_handoff, alternate_checkpoint),
            Err(HomeError::Unauthorized(_))
        ));
        let grant2 = custody_rewrap_grant(
            &fixture,
            e2_home.config.authority.clone(),
            &e3_config,
            &checkpoint2,
            "rewrap-2-3",
            ("realm-b", "node-b"),
            (e2_binding.clone(), e3_binding.clone()),
        );
        let prepared2 = e2_home.prepare_handoff(grant2, checkpoint2).unwrap();
        assert_eq!(prepared2.prepared.payload.rewrap_item_count, Some(2));
        let e3_adapter = Arc::new(TestRewrapper::new(e3_binding, e3_proof));
        let staged2 = stage_handoff_with_rewrapper(
            &e3_config,
            e3_signer.clone(),
            store.as_ref(),
            prepared2.prepared,
            e3_adapter.clone(),
        )
        .unwrap();
        let captured = e3_adapter.requests.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(captured[0].1.len(), 2);
        let e2_hash = canonical_hash(&e2_binding).unwrap();
        assert!(captured[0].1.iter().all(|item| item.source_wrap.binding_hash == e2_hash));
        drop(captured);
        activate_staged_handoff(&e3_config, e3_signer.clone(), store.as_ref(), staged2).unwrap();
        FunctionHome::open_with_checkpoint_store_and_rewrapper(
            e3_config,
            e3_signer,
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
            e3_adapter,
        )
        .unwrap();
    }

    #[test]
    fn custody_recovery_fails_closed_on_a_torn_fence_record() {
        use std::io::Write as _;

        let fixture = Fixture::new("custody-corrupt");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("blobs"), BlobCaps::default()).unwrap(),
        );
        let home = fixture.open_with_store(store.clone());
        let checkpoint = home.create_checkpoint(None).unwrap();
        let destination_signer = Ed25519SeedSigner::from_seed([8; 32]).unwrap();
        let destination = destination_config(
            &fixture,
            fixture.root.join("never-used"),
            &destination_signer,
            2,
            "realm-b",
            "node-b",
        );
        let grant = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &destination,
            &checkpoint,
            "handoff-corrupt",
            "local",
            "local",
        );
        home.prepare_handoff(grant, checkpoint).unwrap();
        drop(home);
        std::fs::OpenOptions::new()
            .append(true)
            .open(fixture.root.join("function-home-custody.jsonl"))
            .unwrap()
            .write_all(b"{")
            .unwrap();
        let reopened = FunctionHome::open_with_checkpoint_store(
            fixture.config(),
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
        );
        assert!(matches!(reopened, Err(HomeError::Journal(JournalError::Corrupt(_)))));
    }

    #[test]
    fn uncertain_job_append_blocks_duplicates_reads_recovery_and_stale_prefix_handoff() {
        use crate::journal::{inject_durability_fault, DurabilityFaultPoint};

        let fixture = Fixture::new("job-append-uncertain");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("blobs"), BlobCaps::default()).unwrap(),
        );
        let home = fixture.open_with_store(store.clone());
        let (first_request, first_resolution, first_deployment) =
            fixture.submission("first", json!({}), DeliveryModeV1::AtMostOnce);
        home.submit(first_request.clone(), first_resolution.clone(), first_deployment.clone())
            .unwrap();
        let stale_checkpoint = home.create_checkpoint(None).unwrap();
        let destination_signer = Ed25519SeedSigner::from_seed([55; 32]).unwrap();
        let destination = destination_config(
            &fixture,
            fixture.root.join("destination"),
            &destination_signer,
            2,
            "realm-b",
            "node-b",
        );
        let stale_grant = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &destination,
            &stale_checkpoint,
            "stale-prefix",
            "local",
            "local",
        );

        let (second_request, second_resolution, second_deployment) =
            fixture.submission("second", json!({}), DeliveryModeV1::AtMostOnce);
        let fault = inject_durability_fault(DurabilityFaultPoint::AfterLogSync, 0);
        assert!(matches!(
            home.submit(
                second_request.clone(),
                second_resolution.clone(),
                second_deployment.clone(),
            ),
            Err(HomeError::Journal(JournalError::Io(_)))
        ));
        drop(fault);

        assert!(matches!(
            home.submit(first_request, first_resolution, first_deployment),
            Err(HomeError::Journal(JournalError::Uncertain))
        ));
        assert!(matches!(
            home.get(&derive_job_id(&fixture.config().home, "first").unwrap()),
            Err(HomeError::Journal(JournalError::Uncertain))
        ));
        assert!(home.recovery_dispatches().dispatches.is_empty());
        assert!(matches!(
            home.create_checkpoint(None),
            Err(HomeError::Journal(JournalError::Uncertain))
        ));
        assert!(matches!(
            home.prepare_handoff(stale_grant, stale_checkpoint),
            Err(HomeError::Journal(JournalError::Uncertain))
        ));
        drop(home);

        let reopened = fixture.open_with_store(store);
        let SubmitOutcome::Existing { handle, .. } =
            reopened.submit(second_request, second_resolution, second_deployment).unwrap()
        else {
            panic!("durable uncertain append was not recovered")
        };
        assert_eq!(reopened.get(&handle.job).unwrap().state, JobStateV1::Queued);
        let recovered_checkpoint = reopened.create_checkpoint(None).unwrap();
        assert_eq!(
            recovered_checkpoint.payload.high_water_mark, 2,
            "reopened checkpoint includes the post-fsync uncertain Submitted record"
        );
        let recovered_grant = custody_grant(
            &fixture,
            fixture.authority.clone(),
            &destination,
            &recovered_checkpoint,
            "recovered-prefix",
            "local",
            "local",
        );
        reopened.prepare_handoff(recovered_grant, recovered_checkpoint).unwrap();
    }

    #[test]
    fn checkpoint_encoding_refuses_the_cap_before_materializing_the_archive() {
        let fixture = Fixture::new("checkpoint-encode-cap");
        let store = Arc::new(
            FsJobBlobStore::open(fixture.root.join("checkpoint-cap-blobs"), BlobCaps::default())
                .unwrap(),
        );
        let mut config = fixture.config();
        config.max_checkpoint_bytes = 128;
        let home = FunctionHome::open_with_checkpoint_store(
            config,
            fixture.operational.clone(),
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
        )
        .unwrap();

        assert!(matches!(home.create_checkpoint(None), Err(HomeError::Capacity(_))));
    }

    #[test]
    fn reopen_refuses_caps_that_discard_recovered_home_or_custody_reservations() {
        let custody_fixture = Fixture::new("custody-shrunk-cap");
        drop(custody_fixture.open());
        let mut custody_config = custody_fixture.config();
        custody_config.journal_caps.max_records = 2;
        assert!(matches!(
            FunctionHome::open(
                custody_config,
                custody_fixture.operational.clone(),
                Arc::new(Metadata),
                Arc::new(AllowTrust),
                Arc::new(AllowBlobs),
            ),
            Err(HomeError::Capacity(_))
        ));

        let home_fixture = Fixture::new("home-shrunk-cap");
        let home = home_fixture.open();
        for key in ["pending-a", "pending-b", "pending-c"] {
            let (request, resolution, deployment) =
                home_fixture.submission(key, json!({}), DeliveryModeV1::AtMostOnce);
            home.submit(request, resolution, deployment).unwrap();
        }
        drop(home);
        let mut home_config = home_fixture.config();
        // The custody journal still has three free safety slots, but the three pending Jobs would
        // have only one terminal slot after this operator cap reduction.
        home_config.journal_caps.max_records = 4;
        assert!(matches!(
            FunctionHome::open(
                home_config,
                home_fixture.operational.clone(),
                Arc::new(Metadata),
                Arc::new(AllowTrust),
                Arc::new(AllowBlobs),
            ),
            Err(HomeError::Capacity(_))
        ));
    }

    #[test]
    fn custody_fence_append_uncertainty_closes_writes_and_reopens_at_the_persisted_cut() {
        use crate::journal::{inject_durability_fault, DurabilityFaultPoint};

        let cuts = [
            (DurabilityFaultPoint::BeforeLogWrite, false),
            (DurabilityFaultPoint::AfterLogWrite, true),
            (DurabilityFaultPoint::AfterLogSync, true),
            (DurabilityFaultPoint::AfterAtomicTempSync, true),
            (DurabilityFaultPoint::BeforeAtomicRename, true),
            (DurabilityFaultPoint::BeforeAtomicDirSync, true),
            (DurabilityFaultPoint::AfterAtomicDirSync, true),
        ];
        for (index, (cut, fence_visible_on_reopen)) in cuts.into_iter().enumerate() {
            let fixture = Fixture::new(&format!("fence-cut-{index}"));
            let store = Arc::new(
                FsJobBlobStore::open(fixture.root.join("blobs"), BlobCaps::default()).unwrap(),
            );
            let home = fixture.open_with_store(store.clone());
            let checkpoint = home.create_checkpoint(None).unwrap();
            let destination_signer = Ed25519SeedSigner::from_seed([20 + index as u8; 32]).unwrap();
            let destination = destination_config(
                &fixture,
                fixture.root.join("destination"),
                &destination_signer,
                2,
                "realm-b",
                "node-b",
            );
            let grant = custody_grant(
                &fixture,
                fixture.authority.clone(),
                &destination,
                &checkpoint,
                &format!("fence-cut-{index}"),
                "local",
                "local",
            );

            let fault = inject_durability_fault(cut, 0);
            assert!(matches!(
                home.prepare_handoff(grant, checkpoint),
                Err(HomeError::Journal(JournalError::Io(_)))
            ));
            drop(fault);
            // Even when the filesystem cannot say whether Frozen survived, this process must not
            // keep writing via the independent Job journal and cannot emit a Prepared proof.
            assert!(matches!(
                home.create_checkpoint(None),
                Err(HomeError::State(_)) | Err(HomeError::Journal(JournalError::Uncertain))
            ));
            assert!(matches!(
                home.signed_custody_status(),
                Err(HomeError::State(_)) | Err(HomeError::Journal(JournalError::Uncertain))
            ));
            drop(home);

            let reopened = fixture.open_with_store(store);
            assert_eq!(
                matches!(reopened.custody_status(), HomeCustodyStatus::Frozen { .. }),
                fence_visible_on_reopen,
                "cut {cut:?}"
            );
        }
    }

    #[test]
    fn custody_stage_retries_metadata_marker_snapshot_and_receipt_cuts() {
        use crate::journal::{inject_durability_fault, DurabilityFaultPoint};

        let cuts = [
            // Imported public authority history was renamed but its parent fsync failed.
            (DurabilityFaultPoint::BeforeAtomicDirSync, 0),
            // Destination Staged marker log fsynced before its head hint.
            (DurabilityFaultPoint::AfterLogSync, 0),
            // Installed Home snapshot log renamed before its parent fsync.
            (DurabilityFaultPoint::BeforeAtomicDirSync, 2),
            // Signed staging receipt log fsynced before its head hint.
            (DurabilityFaultPoint::AfterLogSync, 1),
        ];
        for (index, (cut, matches_to_skip)) in cuts.into_iter().enumerate() {
            let fixture = Fixture::new(&format!("stage-cut-{index}"));
            let (store, destination, signer, prepared) =
                prepared_transfer(&fixture, 40 + index as u8, &format!("stage-{index}"));
            let fault = inject_durability_fault(cut, matches_to_skip);
            assert!(stage_handoff(
                &destination,
                signer.clone(),
                store.as_ref(),
                prepared.prepared.clone(),
            )
            .is_err());
            drop(fault);

            // No cut before the receipt can make the destination writable. A complete receipt is
            // still Staged, never Active, until exact activation is durably appended.
            assert!(FunctionHome::open_with_checkpoint_store(
                destination.clone(),
                signer.clone(),
                Arc::new(Metadata),
                Arc::new(AllowTrust),
                store.clone(),
                store.clone(),
            )
            .is_err());
            let staged =
                stage_handoff(&destination, signer.clone(), store.as_ref(), prepared.prepared)
                    .unwrap();
            let status = destination_custody_status(&destination, signer).unwrap();
            gawdfn::verify_home_custody_status(&status).unwrap();
            assert!(matches!(status.payload.state, gawdfn::HomeCustodyPhaseV1::Staged { .. }));
            assert_eq!(
                canonical_hash(&staged).unwrap(),
                canonical_hash(match &status.payload.state {
                    gawdfn::HomeCustodyPhaseV1::Staged { staged } => staged.as_ref(),
                    _ => unreachable!(),
                })
                .unwrap()
            );
        }
    }

    #[test]
    fn custody_rewrap_failures_never_persist_a_receipt_and_uncertain_retry_is_exact() {
        use crate::journal::{inject_durability_fault, DurabilityFaultPoint};

        let unavailable = Fixture::new("rewrap-unavailable");
        let (store, destination, signer, prepared, adapter) =
            prepared_rewrap_transfer(&unavailable, "unavailable");
        assert!(matches!(
            stage_handoff(&destination, signer.clone(), store.as_ref(), prepared.prepared.clone(),),
            Err(HomeError::State(_))
        ));
        assert!(destination_custody_status(&destination, signer.clone()).is_err());
        stage_handoff_with_rewrapper(
            &destination,
            signer,
            store.as_ref(),
            prepared.prepared,
            adapter,
        )
        .unwrap();

        for (suffix, mode) in [("adapter-error", 2), ("wrong-proof", 3)] {
            let fixture = Fixture::new(suffix);
            let (store, destination, signer, prepared, adapter) =
                prepared_rewrap_transfer(&fixture, suffix);
            adapter.mode.store(mode, Ordering::SeqCst);
            assert!(stage_handoff_with_rewrapper(
                &destination,
                signer.clone(),
                store.as_ref(),
                prepared.prepared.clone(),
                adapter.clone(),
            )
            .is_err());
            assert!(matches!(
                destination_custody_status(&destination, signer.clone()),
                Err(HomeError::State(_))
            ));
            adapter.mode.store(0, Ordering::SeqCst);
            let staged = stage_handoff_with_rewrapper(
                &destination,
                signer,
                store.as_ref(),
                prepared.prepared,
                adapter,
            )
            .unwrap();
            gawdfn::verify_custody_staged(&staged).unwrap();
        }

        // Adapter success precedes the receipt append. A cut before that append must replay the
        // exact signed request and inventory; the seam's idempotency contract makes that safe.
        let fixture = Fixture::new("rewrap-before-receipt-append");
        let (store, destination, signer, prepared, adapter) =
            prepared_rewrap_transfer(&fixture, "before-receipt-append");
        let fault = inject_durability_fault(DurabilityFaultPoint::BeforeLogWrite, 1);
        assert!(matches!(
            stage_handoff_with_rewrapper(
                &destination,
                signer.clone(),
                store.as_ref(),
                prepared.prepared.clone(),
                adapter.clone(),
            ),
            Err(HomeError::Journal(JournalError::Io(_)))
        ));
        drop(fault);
        let staged = stage_handoff_with_rewrapper(
            &destination,
            signer,
            store.as_ref(),
            prepared.prepared,
            adapter.clone(),
        )
        .unwrap();
        gawdfn::verify_custody_staged(&staged).unwrap();
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 2);
        let requests = adapter.requests.lock().unwrap_or_else(|poison| poison.into_inner());
        assert_eq!(requests.len(), 2);
        assert_eq!(
            gawdfn::canonical_json_bytes(&requests[0]).unwrap(),
            gawdfn::canonical_json_bytes(&requests[1]).unwrap(),
            "pre-receipt retry changed the exact adapter request or inventory"
        );
        drop(requests);

        let fixture = Fixture::new("rewrap-receipt-uncertain");
        let (store, destination, signer, prepared, adapter) =
            prepared_rewrap_transfer(&fixture, "receipt-uncertain");
        let fault = inject_durability_fault(DurabilityFaultPoint::AfterLogSync, 1);
        assert!(matches!(
            stage_handoff_with_rewrapper(
                &destination,
                signer.clone(),
                store.as_ref(),
                prepared.prepared.clone(),
                adapter.clone(),
            ),
            Err(HomeError::Journal(JournalError::Io(_)))
        ));
        drop(fault);
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
        let staged = stage_handoff_with_rewrapper(
            &destination,
            signer.clone(),
            store.as_ref(),
            prepared.prepared,
            adapter.clone(),
        )
        .unwrap();
        assert_eq!(adapter.calls.load(Ordering::SeqCst), 1);
        activate_staged_handoff(&destination, signer.clone(), store.as_ref(), staged).unwrap();
        FunctionHome::open_with_checkpoint_store_and_rewrapper(
            destination,
            signer,
            Arc::new(Metadata),
            Arc::new(AllowTrust),
            store.clone(),
            store,
            adapter,
        )
        .unwrap();
    }

    #[test]
    fn custody_stage_rejects_the_wrong_destination_key_and_stale_epoch() {
        let fixture = Fixture::new("stage-key-epoch");
        let (store, destination, _signer, prepared) =
            prepared_transfer(&fixture, 52, "stage-key-epoch");
        let wrong_signer = Arc::new(Ed25519SeedSigner::from_seed([53; 32]).unwrap());
        assert!(matches!(
            stage_handoff(&destination, wrong_signer, store.as_ref(), prepared.prepared.clone(),),
            Err(HomeError::Unauthorized(_))
        ));

        let mut stale_destination = destination;
        stale_destination.epoch = 3;
        let configured_signer = Arc::new(Ed25519SeedSigner::from_seed([52; 32]).unwrap());
        assert!(matches!(
            stage_handoff(&stale_destination, configured_signer, store.as_ref(), prepared.prepared,),
            Err(HomeError::Unauthorized(_))
        ));
    }

    #[test]
    fn custody_activation_append_cuts_never_return_a_lease_early() {
        use crate::journal::{inject_durability_fault, DurabilityFaultPoint};

        let cuts = [
            DurabilityFaultPoint::BeforeLogWrite,
            DurabilityFaultPoint::AfterLogWrite,
            DurabilityFaultPoint::AfterLogSync,
            DurabilityFaultPoint::AfterAtomicTempSync,
            DurabilityFaultPoint::BeforeAtomicRename,
            DurabilityFaultPoint::BeforeAtomicDirSync,
            DurabilityFaultPoint::AfterAtomicDirSync,
        ];
        for (index, cut) in cuts.into_iter().enumerate() {
            let fixture = Fixture::new(&format!("activate-cut-{index}"));
            let (store, destination, signer, prepared) =
                prepared_transfer(&fixture, 60 + index as u8, &format!("activate-{index}"));
            let staged =
                stage_handoff(&destination, signer.clone(), store.as_ref(), prepared.prepared)
                    .unwrap();
            let fault = inject_durability_fault(cut, 0);
            assert!(matches!(
                activate_staged_handoff(
                    &destination,
                    signer.clone(),
                    store.as_ref(),
                    staged.clone(),
                ),
                Err(HomeError::Journal(JournalError::Io(_)))
            ));
            drop(fault);

            // Recovery sees either the exact Staged prefix or the exact Activated continuation.
            // In both cases retry is deterministic and is the first call allowed to return a lease.
            let lease =
                activate_staged_handoff(&destination, signer, store.as_ref(), staged).unwrap();
            gawdfn::verify_home_lease(&lease).unwrap();
            assert_eq!(lease.payload.epoch, 2);
        }
    }

    #[test]
    fn queued_cancel_is_terminal_and_direct_causal_claims_are_rejected() {
        let fixture = Fixture::new("cancel-causal");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("queued-cancel", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment).unwrap()
        else {
            panic!("new job")
        };
        let steer = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: handle.clone(),
                expected_home_epoch: 1,
                control: ControlId::new("steer-before-dispatch"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Steer {
                    value: ValueRefV1::Inline { value: json!({"speed": 2}) },
                },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        assert!(matches!(home.control(steer), Err(HomeError::State(_))));
        assert_eq!(
            home.events(&EventQueryV1 {
                handle: handle.clone(),
                after_sequence: None,
                limit: 64,
                nonce: "steer-before-dispatch".into(),
            })
            .unwrap()
            .events
            .len(),
            1,
            "rejected Steer must not become durable"
        );
        let control = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: handle.clone(),
                expected_home_epoch: 1,
                control: ControlId::new("cancel-before-dispatch"),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Cancel { reason: "stop".into() },
            },
            fixture.owner.as_ref(),
        )
        .unwrap();
        let event = home.control(control).unwrap();
        assert_eq!(event.payload.state_after, JobStateV1::Cancelled);
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Cancelled);

        let (request, resolution, deployment) =
            fixture.submission("forged-child", json!({}), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        payload.parent = Some(handle);
        let request = SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap();
        assert!(matches!(home.submit(request, resolution, deployment), Err(HomeError::Invalid(_))));

        let (request, resolution, deployment) =
            fixture.submission("forged-causal", json!({}), DeliveryModeV1::AtMostOnce);
        let mut payload = request.payload;
        let self_job = derive_job_id(&payload.home, &payload.caller_idempotency_key).unwrap();
        payload.causal = vec![CausalLinkV1 {
            job: JobHandleV1 { home: payload.home.clone(), job: self_job },
            relation: "depends_on".into(),
            receipt_hash: None,
        }];
        let request = SignedRecordV1::sign(SCHEMA_JOB_V1, payload, fixture.owner.as_ref()).unwrap();
        assert!(matches!(home.submit(request, resolution, deployment), Err(HomeError::Invalid(_))));
    }

    #[test]
    fn control_ids_are_scoped_per_job_and_divergent_same_job_replay_conflicts() {
        let fixture = Fixture::new("control-scope");
        let home = fixture.open();
        let mut handles = Vec::new();
        for key in ["control-a", "control-b"] {
            let (request, resolution, deployment) =
                fixture.submission(key, json!({}), DeliveryModeV1::AtMostOnce);
            let SubmitOutcome::Accepted { handle, .. } =
                home.submit(request, resolution, deployment.clone()).unwrap()
            else {
                panic!("new job")
            };
            let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
            let claimed = SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: canonical_hash(&grant).unwrap(),
                    executor: fixture.executor.public_key().into(),
                    sequence: 1,
                    observed_at_unix_ms: None,
                    stage: ExecutionStageV1::Claimed,
                },
                &fixture.executor,
            )
            .unwrap();
            home.apply_executor_receipt(claimed).unwrap();
            handles.push(handle);
        }
        let request_for = |handle: &JobHandleV1, value: i64| {
            SignedRecordV1::sign(
                SCHEMA_JOB_V1,
                JobControlV1 {
                    handle: handle.clone(),
                    expected_home_epoch: 1,
                    control: ControlId::new("same-control-id"),
                    issued_at_unix_ms: None,
                    kind: JobControlKindV1::Steer {
                        value: ValueRefV1::Inline { value: json!({"value": value}) },
                    },
                },
                fixture.owner.as_ref(),
            )
            .unwrap()
        };
        let first = request_for(&handles[0], 1);
        let first_event = home.control(first.clone()).unwrap();
        assert_eq!(home.control(first).unwrap(), first_event);
        home.control(request_for(&handles[1], 2)).unwrap();
        assert!(matches!(home.control(request_for(&handles[0], 3)), Err(HomeError::Conflict(_))));
    }

    #[test]
    fn unique_control_cap_recovers_accepts_exact_retries_and_leaves_ack_capacity() {
        let fixture = Fixture::new("control-cap");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("controlled", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let request_for = |index: usize| {
            SignedRecordV1::sign(
                SCHEMA_JOB_V1,
                JobControlV1 {
                    handle: handle.clone(),
                    expected_home_epoch: 1,
                    control: ControlId::new(format!("control-{index}")),
                    issued_at_unix_ms: None,
                    kind: JobControlKindV1::Steer {
                        value: ValueRefV1::Inline { value: json!({"value": index}) },
                    },
                },
                fixture.owner.as_ref(),
            )
            .unwrap()
        };
        let mut retained = None;
        for index in 0..MAX_JOB_CONTROLS {
            let request = request_for(index);
            let event = home.control(request.clone()).unwrap();
            if index + 1 == MAX_JOB_CONTROLS {
                retained = Some((request, event));
            }
        }
        let (retained_request, retained_event) = retained.unwrap();
        assert_eq!(home.control(retained_request.clone()).unwrap(), retained_event);
        assert!(matches!(home.control(request_for(MAX_JOB_CONTROLS)), Err(HomeError::Capacity(_))));

        let grant_hash = canonical_hash(&grant).unwrap();
        let unknown_receipt = |stage| {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: grant_hash.clone(),
                    executor: fixture.executor.public_key().into(),
                    sequence: 1,
                    observed_at_unix_ms: None,
                    stage,
                },
                &fixture.executor,
            )
            .unwrap()
        };
        let log_path = fixture.root.join("function-home.jsonl");
        let bytes_before_unknown = fs::read(&log_path).unwrap();
        let tip_before_unknown = home.journal.tip_hash();
        for stage in [
            ExecutionStageV1::ControlQueued { control: ControlId::new("unknown-queued") },
            ExecutionStageV1::ControlAcknowledged {
                control: ControlId::new("unknown-ack"),
                disposition: gawdfn::ControlDispositionV1::Applied,
                detail: None,
            },
        ] {
            assert!(matches!(
                home.apply_executor_receipt(unknown_receipt(stage)),
                Err(HomeError::State(_))
            ));
            assert_eq!(fs::read(&log_path).unwrap(), bytes_before_unknown);
            assert_eq!(home.journal.tip_hash(), tip_before_unknown);
        }

        let acknowledgment = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionReceiptV1 {
                attempt: grant.payload.attempt.clone(),
                grant_hash,
                executor: fixture.executor.public_key().into(),
                sequence: 1,
                observed_at_unix_ms: None,
                stage: ExecutionStageV1::ControlAcknowledged {
                    control: retained_request.payload.control.clone(),
                    disposition: gawdfn::ControlDispositionV1::Applied,
                    detail: None,
                },
            },
            &fixture.executor,
        )
        .unwrap();
        let acknowledgment_hash = canonical_hash(&acknowledgment).unwrap();
        home.apply_executor_receipt(acknowledgment).unwrap();
        let retained_key =
            (handle.job.clone(), retained_request.payload.control.as_str().to_string());
        assert_eq!(
            home.state
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .forwarded_controls
                .get(&retained_key)
                .and_then(|control| control.acknowledged_receipt_hash.as_deref()),
            Some(acknowledgment_hash.as_str())
        );
        drop(home);

        let home = fixture.open();
        {
            let state = home.state.lock().unwrap_or_else(|poison| poison.into_inner());
            assert_eq!(state.control_counts.get(&handle.job), Some(&MAX_JOB_CONTROLS));
            assert_eq!(
                state
                    .forwarded_controls
                    .get(&retained_key)
                    .and_then(|control| control.acknowledged_receipt_hash.as_deref()),
                Some(acknowledgment_hash.as_str())
            );
        }
        assert_eq!(home.control(retained_request).unwrap(), retained_event);
        assert!(matches!(
            home.control(request_for(MAX_JOB_CONTROLS + 1)),
            Err(HomeError::Capacity(_))
        ));
    }

    #[test]
    fn protocol_error_bounding_preserves_utf8_boundaries() {
        let bounded = bound("🦀".repeat(gawdfn::MAX_REASON_BYTES));
        assert!(bounded.len() <= gawdfn::MAX_REASON_BYTES);
        assert!(std::str::from_utf8(bounded.as_bytes()).is_ok());
    }

    #[test]
    fn grandchild_inherits_root_and_atomic_replay_rejects_lineage_tamper() {
        let fixture = Fixture::new("lineage");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("root", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle: root, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new root")
        };
        let root_grant = home.issue_grant(&root.job, deployment, None, None).unwrap();
        let (child, _, _) =
            spawn_child(&fixture, &home, &root, &root_grant.payload.attempt, "child");
        assert_eq!(home.get(&child.job).unwrap().spec.root, root);

        let child_deployment = home.get(&child.job).unwrap().spec.deployment;
        let child_grant = home.issue_grant(&child.job, child_deployment, None, None).unwrap();
        let (grandchild, spawned, submitted) =
            spawn_child(&fixture, &home, &child, &child_grant.payload.attempt, "grandchild");
        assert_eq!(home.get(&grandchild.job).unwrap().spec.root, root);

        let mut tampered_payload = submitted.payload.clone();
        let JobEventKindV1::Submitted { spec } = &mut tampered_payload.kind else {
            panic!("submitted")
        };
        spec.root = child.clone();
        let tampered =
            SignedRecordV1::sign(SCHEMA_JOB_V1, tampered_payload, fixture.operational.as_ref())
                .unwrap();
        let record =
            HomeLedgerRecord { grant: None, receipt: None, events: vec![spawned, tampered] };
        assert!(validate_ledger_record(&record, &fixture.config()).is_err());
    }

    #[test]
    fn terminal_jobs_retain_exact_late_receipts_without_reopening() {
        let fixture = Fixture::new("late-receipt");
        let home = fixture.open();
        let (request, resolution, deployment) =
            fixture.submission("late", json!({}), DeliveryModeV1::AtMostOnce);
        let SubmitOutcome::Accepted { handle, .. } =
            home.submit(request, resolution, deployment.clone()).unwrap()
        else {
            panic!("new job")
        };
        let grant = home.issue_grant(&handle.job, deployment, None, None).unwrap();
        let receipt = |sequence, stage| {
            SignedRecordV1::sign(
                SCHEMA_EXECUTE_V1,
                ExecutionReceiptV1 {
                    attempt: grant.payload.attempt.clone(),
                    grant_hash: canonical_hash(&grant).unwrap(),
                    executor: fixture.executor.public_key().into(),
                    sequence,
                    observed_at_unix_ms: None,
                    stage,
                },
                &fixture.executor,
            )
            .unwrap()
        };
        let ambiguous = receipt(
            1,
            ExecutionStageV1::Indeterminate {
                reason: "lost boundary acknowledgement".into(),
                execution_may_have_occurred: true,
            },
        );
        home.apply_executor_receipt(ambiguous.clone()).unwrap();
        assert_eq!(home.get(&handle.job).unwrap().state, JobStateV1::Indeterminate);

        let succeeded = receipt(
            2,
            ExecutionStageV1::Succeeded {
                result: ValueRefV1::Inline { value: json!({"too_late": true}) },
            },
        );
        let ApplyReceiptOutcome::Applied(late) =
            home.apply_executor_receipt(succeeded.clone()).unwrap()
        else {
            panic!("late receipt applied")
        };
        assert!(matches!(late.payload.kind, JobEventKindV1::LateReceipt { .. }));
        gawdfn::verify_job_event_with_grant(&late, &grant).unwrap();
        let snapshot = home.get(&handle.job).unwrap();
        assert_eq!(snapshot.state, JobStateV1::Indeterminate);
        assert!(snapshot.result.is_none());

        let mismatched_record =
            HomeLedgerRecord { grant: None, receipt: Some(ambiguous), events: vec![late] };
        assert!(matches!(
            validate_ledger_record(&mismatched_record, &fixture.config()),
            Err(HomeError::State(_))
        ));
    }
}
