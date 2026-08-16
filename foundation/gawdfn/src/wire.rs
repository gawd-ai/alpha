//! Versioned application messages carried through `aether::Envelope`.

use serde::{Deserialize, Serialize};

use crate::{
    canonical_hash, validate_causal_links, validate_ed25519_public_key, validate_expiry,
    validate_optional_text, validate_sha256, validate_text, validate_vec, AbodeKeyBindingV1,
    AttemptId, BlobRefV1, CausalLinkV1, ContractError, ControlId, DeploymentId, EvidenceRefV1,
    FunctionId, FunctionSelectorV1, HandoffId, HomeId, JobAccessV1, JobHandleV1,
    OperationalCapabilityV1, OperationalKeyGrantV1, RecipientKeyBindingV1, RecipientKeyWrapV1,
    ResolvedFunctionV1, SignedRecordV1, Validate, ValueRefV1, MAX_CUSTODY_REWRAP_ITEMS,
    MAX_ERROR_BYTES, MAX_EVENT_PAGE_ITEMS, MAX_EVIDENCE_REFS, MAX_IDEMPOTENCY_KEY_BYTES,
    MAX_ID_BYTES, MAX_JOB_ATTEMPTS, MAX_JOB_MESSAGE_BYTES, MAX_NAME_BYTES, MAX_PROGRESS_BYTES,
    MAX_REASON_BYTES, MAX_RESULT_RECIPIENTS,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DeliveryModeV1 {
    AtMostOnce,
    AtLeastOnce { max_attempts: u8 },
}

impl DeliveryModeV1 {
    pub fn max_attempts(&self) -> u8 {
        match self {
            Self::AtMostOnce => 1,
            Self::AtLeastOnce { max_attempts } => *max_attempts,
        }
    }
}

impl Validate for DeliveryModeV1 {
    fn validate(&self) -> Result<(), ContractError> {
        let attempts = self.max_attempts();
        if attempts == 0 || attempts > MAX_JOB_ATTEMPTS {
            return Err(ContractError::Invalid(format!(
                "delivery attempts must be in 1..={MAX_JOB_ATTEMPTS}"
            )));
        }
        Ok(())
    }
}

/// Caller-authored request. A signed outer record provides authorization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSubmitV1 {
    pub home: HomeId,
    pub caller_idempotency_key: String,
    pub function: FunctionSelectorV1,
    pub input: ValueRefV1,
    pub delivery: DeliveryModeV1,
    #[serde(default)]
    pub allow_duplicate_effects: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<JobHandleV1>,
    #[serde(default)]
    pub causal: Vec<CausalLinkV1>,
    #[serde(default)]
    pub access: JobAccessV1,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
    #[serde(default)]
    pub result_recipients: Vec<HomeId>,
    /// Optional signed observation only; job ordering is epoch/sequence based.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub submitted_at_unix_ms: Option<u64>,
}

impl JobSubmitV1 {
    pub fn request_hash(&self) -> Result<String, ContractError> {
        self.validate()?;
        canonical_hash(self)
    }
}

impl Validate for JobSubmitV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        validate_text(
            "caller_idempotency_key",
            &self.caller_idempotency_key,
            MAX_IDEMPOTENCY_KEY_BYTES,
        )?;
        self.function.validate()?;
        self.input.validate()?;
        self.delivery.validate()?;
        if let Some(parent) = &self.parent {
            parent.validate()?;
        }
        validate_causal_links(&self.causal)?;
        self.access.validate()?;
        validate_vec("job evidence", &self.evidence, MAX_EVIDENCE_REFS)?;
        validate_vec("result recipients", &self.result_recipients, MAX_RESULT_RECIPIENTS)?;
        ensure_message_bound(self)
    }
}

/// Immutable accepted job specification. Alias resolution has already been pinned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSpecV1 {
    pub handle: JobHandleV1,
    /// Immutable workflow root. A root job names itself; every descendant inherits this exact
    /// handle from its parent rather than recomputing lineage from mutable orchestration state.
    pub root: JobHandleV1,
    pub caller_idempotency_key: String,
    pub request_hash: String,
    pub function: ResolvedFunctionV1,
    /// Exact post-load deployment selected before acceptance. Later attempts may carry a different
    /// receipt only when policy explicitly moves the same immutable `FunctionId`.
    pub deployment: SignedRecordV1<DeploymentReceiptV1>,
    pub input: ValueRefV1,
    pub delivery: DeliveryModeV1,
    pub allow_duplicate_effects: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<JobHandleV1>,
    #[serde(default)]
    pub causal: Vec<CausalLinkV1>,
    #[serde(default)]
    pub access: JobAccessV1,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
    #[serde(default)]
    pub result_recipients: Vec<HomeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accepted_at_unix_ms: Option<u64>,
}

impl Validate for JobSpecV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.handle.validate()?;
        self.root.validate()?;
        if self.root.home != self.handle.home {
            return Err(ContractError::Invalid(
                "job root and handle must belong to the same Home".into(),
            ));
        }
        validate_text(
            "caller_idempotency_key",
            &self.caller_idempotency_key,
            MAX_IDEMPOTENCY_KEY_BYTES,
        )?;
        validate_sha256("request_hash", &self.request_hash)?;
        self.function.validate()?;
        verify_deployment_receipt(&self.deployment)?;
        if self.deployment.payload.function != self.function.function
            || self.deployment.payload.artifact_hash != self.function.artifact_hash
        {
            return Err(ContractError::Invalid(
                "accepted deployment does not match the resolved function/artifact".into(),
            ));
        }
        self.input.validate()?;
        self.delivery.validate()?;
        if let Some(parent) = &self.parent {
            parent.validate()?;
            if parent.home != self.handle.home || self.root == self.handle {
                return Err(ContractError::Invalid(
                    "child parent/root must share its Home and root cannot be the child".into(),
                ));
            }
        } else if self.root != self.handle {
            return Err(ContractError::Invalid(
                "a root job must name itself as its immutable workflow root".into(),
            ));
        }
        validate_causal_links(&self.causal)?;
        self.access.validate()?;
        validate_vec("job evidence", &self.evidence, MAX_EVIDENCE_REFS)?;
        validate_vec("result recipients", &self.result_recipients, MAX_RESULT_RECIPIENTS)?;
        ensure_message_bound(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobStateV1 {
    Queued,
    Blocked,
    Dispatching,
    Running,
    RetryPending,
    Succeeded,
    Failed,
    Cancelled,
    Indeterminate,
}

impl JobStateV1 {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled | Self::Indeterminate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRequestV1 {
    pub requested_by: HomeId,
    pub function: FunctionSelectorV1,
    pub target_realm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node: Option<String>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolveRequestV1 {
    pub requested_by: HomeId,
    pub selector: FunctionSelectorV1,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for ResolveRequestV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.requested_by.validate()?;
        self.selector.validate()?;
        validate_vec("resolution evidence", &self.evidence, MAX_EVIDENCE_REFS)
    }
}

impl Validate for DeploymentRequestV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.requested_by.validate()?;
        self.function.validate()?;
        validate_text("target_realm", &self.target_realm, MAX_ID_BYTES)?;
        validate_optional_text("target_node", self.target_node.as_deref(), MAX_ID_BYTES)?;
        validate_vec("deployment evidence", &self.evidence, MAX_EVIDENCE_REFS)?;
        ensure_message_bound(self)
    }
}

/// Post-load registration request. ControlCore/deployer signs the loaded identities; the executor
/// independently durably registers them and returns its own [`DeploymentReceiptV1`]. No component
/// shares the executor's private key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentRegistrationV1 {
    pub authorization: SignedRecordV1<DeploymentRequestV1>,
    pub resolution: SignedRecordV1<crate::ResolutionReceiptV1>,
    pub deployment: DeploymentId,
    pub function: FunctionId,
    pub artifact_hash: String,
    pub target_creature: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for DeploymentRegistrationV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.authorization.validate()?;
        if self.authorization.schema != crate::SCHEMA_FUNCTION_DEPLOY_V1
            || !self.authorization.verify()
            || self.authorization.signer != self.authorization.payload.requested_by.0
        {
            return Err(ContractError::Crypto(
                "deployment registration authorization signature is invalid".into(),
            ));
        }
        self.resolution.validate()?;
        if self.resolution.schema != crate::SCHEMA_FUNCTION_DEPLOY_V1 || !self.resolution.verify() {
            return Err(ContractError::Crypto(
                "deployment registration resolution signature is invalid".into(),
            ));
        }
        if self.authorization.payload.function != self.resolution.payload.selector
            || self.resolution.payload.function != self.function
            || self.resolution.payload.artifact_hash != self.artifact_hash
        {
            return Err(ContractError::Invalid(
                "deployment authorization, resolution, function, and artifact do not match".into(),
            ));
        }
        self.deployment.validate()?;
        self.function.validate()?;
        validate_sha256("artifact_hash", &self.artifact_hash)?;
        validate_creature_id("registration.target_creature", &self.target_creature)?;
        validate_vec("registration evidence", &self.evidence, MAX_EVIDENCE_REFS)
    }
}

pub fn verify_deployment_registration(
    record: &SignedRecordV1<DeploymentRegistrationV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_FUNCTION_DEPLOY_V1 || !record.verify() {
        return Err(ContractError::Crypto(
            "deployment registration request signature is invalid".into(),
        ));
    }
    Ok(())
}

/// Exact live target. This is separate from immutable [`FunctionId`] definition identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentReceiptV1 {
    pub deployment: DeploymentId,
    pub function: FunctionId,
    pub artifact_hash: String,
    pub realm: String,
    pub node: String,
    /// Lowercase-hex Ed25519 public key of the executor that signs this receipt and later facts.
    pub executor: String,
    /// Routable executor creature identity on `node`; separate from its signing key.
    pub executor_creature: String,
    /// Routable loaded target creature identity on `node`.
    pub creature: String,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registered_at_unix_ms: Option<u64>,
}

impl Validate for DeploymentReceiptV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.deployment.validate()?;
        self.function.validate()?;
        validate_sha256("artifact_hash", &self.artifact_hash)?;
        validate_text("deployment.realm", &self.realm, MAX_ID_BYTES)?;
        validate_text("deployment.node", &self.node, MAX_ID_BYTES)?;
        validate_ed25519_public_key("deployment.executor", &self.executor)?;
        validate_creature_id("deployment.executor_creature", &self.executor_creature)?;
        validate_creature_id("deployment.creature", &self.creature)?;
        validate_vec("deployment evidence", &self.evidence, MAX_EVIDENCE_REFS)
    }
}

/// Verify that a deployment receipt was signed by the executor identity it binds.
pub fn verify_deployment_receipt(
    record: &SignedRecordV1<DeploymentReceiptV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_FUNCTION_DEPLOY_V1 {
        return Err(ContractError::Invalid(format!(
            "deployment receipt schema is `{}`, expected `{}`",
            record.schema,
            crate::SCHEMA_FUNCTION_DEPLOY_V1
        )));
    }
    if !record.verify() {
        return Err(ContractError::Crypto("invalid deployment receipt signature".into()));
    }
    if record.signer != record.payload.executor {
        return Err(ContractError::Invalid(
            "deployment receipt signer does not match its executor identity".into(),
        ));
    }
    Ok(())
}

pub type DeploymentPinV1 = DeploymentReceiptV1;

fn validate_creature_id(label: &str, value: &str) -> Result<(), ContractError> {
    validate_text(label, value, MAX_ID_BYTES)?;
    let parsed = value.parse::<u64>().map_err(|_| {
        ContractError::Invalid(format!("{label} must be a positive numeric CreatureId"))
    })?;
    if parsed == 0 || parsed.to_string() != value {
        return Err(ContractError::Invalid(format!(
            "{label} must be the canonical decimal form of a positive CreatureId"
        )));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndeployRequestV1 {
    pub requested_by: HomeId,
    pub deployment: DeploymentId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Validate for UndeployRequestV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.requested_by.validate()?;
        self.deployment.validate()?;
        validate_optional_text("undeploy reason", self.reason.as_deref(), MAX_REASON_BYTES)
    }
}

/// Executor-signed acknowledgement that a deployment tombstone is durable.
///
/// `executor` is the stable operational signing identity already pinned by the deployment receipt;
/// `executor_creature` is the current process-local route that emitted this acknowledgement. The
/// split lets a recovered executor re-attest the same durable tombstone after its CreatureId changes
/// without treating the old route as authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UndeployReceiptV1 {
    pub deployment: DeploymentId,
    pub executor: String,
    pub executor_creature: String,
}

impl Validate for UndeployReceiptV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.deployment.validate()?;
        validate_ed25519_public_key("undeploy.executor", &self.executor)?;
        validate_creature_id("undeploy.executor_creature", &self.executor_creature)
    }
}

/// Verify a durable undeploy acknowledgement against the stable executor identity it names.
pub fn verify_undeploy_receipt(
    record: &SignedRecordV1<UndeployReceiptV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_FUNCTION_DEPLOY_V1 {
        return Err(ContractError::Invalid(format!(
            "undeploy receipt schema is `{}`, expected `{}`",
            record.schema,
            crate::SCHEMA_FUNCTION_DEPLOY_V1
        )));
    }
    if !record.verify() {
        return Err(ContractError::Crypto("invalid undeploy receipt signature".into()));
    }
    if record.signer != record.payload.executor {
        return Err(ContractError::Invalid(
            "undeploy receipt signer does not match its executor identity".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentQueryV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    pub limit: u16,
}

impl Validate for DeploymentQueryV1 {
    fn validate(&self) -> Result<(), ContractError> {
        if let Some(function) = &self.function {
            function.validate()?;
        }
        validate_optional_text("deployment query realm", self.realm.as_deref(), MAX_ID_BYTES)?;
        validate_optional_text("deployment query node", self.node.as_deref(), MAX_ID_BYTES)?;
        if self.limit == 0 || usize::from(self.limit) > MAX_EVENT_PAGE_ITEMS {
            return Err(ContractError::Invalid(format!(
                "deployment query limit must be in 1..={MAX_EVENT_PAGE_ITEMS}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentListV1 {
    pub deployments: Vec<SignedRecordV1<DeploymentReceiptV1>>,
}

impl Validate for DeploymentListV1 {
    fn validate(&self) -> Result<(), ContractError> {
        if self.deployments.len() > MAX_EVENT_PAGE_ITEMS {
            return Err(ContractError::Limit(format!(
                "deployment list has {} items, exceeds {MAX_EVENT_PAGE_ITEMS}",
                self.deployments.len()
            )));
        }
        for deployment in &self.deployments {
            verify_deployment_receipt(deployment)?;
        }
        ensure_message_bound(self)
    }
}

/// Durable execution permission for one numbered attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionGrantV1 {
    pub attempt: AttemptId,
    /// Exact accepted submission identity carried through every execution fact.
    pub request_hash: String,
    pub home_epoch: u64,
    /// Monotonic active-lease route revision within `home_epoch` (genesis is 1).
    pub home_route_sequence: u64,
    /// Authenticated return-route hint. A later locator lease may supersede it after custody moves.
    pub home_realm: String,
    pub home_node: String,
    pub home_coordinator: String,
    pub owner: HomeId,
    /// Root-to-epoch proof chain for the operational key signing this grant.
    pub authority: HomeAuthorityV1,
    pub function: FunctionId,
    pub deployment: SignedRecordV1<DeploymentReceiptV1>,
    pub input: ValueRefV1,
    pub delivery: DeliveryModeV1,
    pub grant_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_unix_ms: Option<u64>,
}

impl Validate for ExecutionGrantV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        validate_sha256("execution grant request_hash", &self.request_hash)?;
        if self.home_epoch == 0 || self.home_route_sequence == 0 || self.grant_sequence == 0 {
            return Err(ContractError::Invalid(
                "home epoch, route sequence, and grant sequence must be non-zero".into(),
            ));
        }
        validate_text("home_realm", &self.home_realm, MAX_ID_BYTES)?;
        validate_text("home_node", &self.home_node, MAX_ID_BYTES)?;
        validate_text("home_coordinator", &self.home_coordinator, MAX_ID_BYTES)?;
        self.owner.validate()?;
        if self.attempt.home != self.owner {
            return Err(ContractError::Invalid(
                "execution attempt does not belong to the granting Home".into(),
            ));
        }
        self.authority.verify(&self.owner, self.home_epoch, OperationalCapabilityV1::JobHome)?;
        if self.home_epoch > 1 {
            let prepared = self.authority.prepared.as_ref().ok_or_else(|| {
                ContractError::Invalid(
                    "moved execution grant authority omits its Prepared proof".into(),
                )
            })?;
            let custody = &prepared.payload.grant.payload;
            if self.home_realm != custody.destination_realm
                || self.home_node != custody.destination_node
            {
                return Err(ContractError::Invalid(
                    "execution grant location does not match its custody proof".into(),
                ));
            }
        }
        self.function.validate()?;
        verify_deployment_receipt(&self.deployment)?;
        if self.deployment.payload.function != self.function {
            return Err(ContractError::Invalid(
                "deployment receipt does not pin the granted function".into(),
            ));
        }
        self.input.validate()?;
        self.delivery.validate()?;
        if matches!((self.issued_at_unix_ms, self.deadline_unix_ms), (Some(issued), Some(deadline)) if deadline <= issued)
        {
            return Err(ContractError::Invalid(
                "execution deadline must be later than issue time".into(),
            ));
        }
        ensure_message_bound(self)
    }
}

/// Current-Home-authorized reconciliation request for one exact durable attempt. Replies follow
/// this signed route rather than the transport envelope's caller-chosen `reply_to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionQueryV1 {
    pub attempt: AttemptId,
    pub grant_hash: String,
    pub home_epoch: u64,
    /// Monotonic active-lease route revision within `home_epoch` (genesis is 1).
    pub home_route_sequence: u64,
    pub home_realm: String,
    pub home_node: String,
    pub home_coordinator: String,
    pub authority: HomeAuthorityV1,
    pub query: ControlId,
}

impl Validate for ExecutionQueryV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        validate_sha256("execution query grant_hash", &self.grant_hash)?;
        if self.home_epoch == 0 || self.home_route_sequence == 0 {
            return Err(ContractError::Invalid(
                "execution query Home epoch and route sequence must be non-zero".into(),
            ));
        }
        validate_text("query home_realm", &self.home_realm, MAX_ID_BYTES)?;
        validate_text("query home_node", &self.home_node, MAX_ID_BYTES)?;
        validate_text("query home_coordinator", &self.home_coordinator, MAX_ID_BYTES)?;
        self.authority.verify(
            &self.attempt.home,
            self.home_epoch,
            OperationalCapabilityV1::JobHome,
        )?;
        if self.home_epoch > 1 {
            let prepared = self.authority.prepared.as_ref().ok_or_else(|| {
                ContractError::Invalid(
                    "moved execution query authority omits its Prepared proof".into(),
                )
            })?;
            let custody = &prepared.payload.grant.payload;
            if self.home_realm != custody.destination_realm
                || self.home_node != custody.destination_node
            {
                return Err(ContractError::Invalid(
                    "execution query location does not match its custody proof".into(),
                ));
            }
        }
        self.query.validate()?;
        ensure_message_bound(self)
    }
}

pub fn verify_execution_query(
    record: &SignedRecordV1<ExecutionQueryV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_EXECUTE_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid execution query signature".into()));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "execution query signer is not the active root-authorized Home key".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum ExecutionStageV1 {
    Claimed,
    Started,
    Progress {
        sequence: u64,
        progress: ValueRefV1,
    },
    Checkpoint {
        sequence: u64,
        checkpoint: ValueRefV1,
    },
    Succeeded {
        result: ValueRefV1,
    },
    Failed {
        error: ValueRefV1,
        retryable: bool,
    },
    /// The executor cannot prove whether the attempt crossed its effect boundary. At-most-once
    /// homes must terminally preserve this ambiguity and must not issue another attempt.
    Indeterminate {
        reason: String,
        execution_may_have_occurred: bool,
    },
    Cancelled {
        reason: String,
    },
    /// Durable executor intent only: the command is queued for delivery to the target, but no
    /// claim is made that a best-effort send happened or that the target applied it.
    ControlQueued {
        control: ControlId,
    },
    ControlAcknowledged {
        control: ControlId,
        disposition: ControlDispositionV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

impl Validate for ExecutionStageV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Claimed | Self::Started => Ok(()),
            Self::Progress { sequence, progress } => {
                if *sequence == 0 {
                    return Err(ContractError::Invalid(
                        "progress sequence must be non-zero".into(),
                    ));
                }
                progress.validate_with_limit(MAX_PROGRESS_BYTES)
            }
            Self::Checkpoint { sequence, checkpoint } => {
                if *sequence == 0 {
                    return Err(ContractError::Invalid(
                        "checkpoint sequence must be non-zero".into(),
                    ));
                }
                checkpoint.validate()
            }
            Self::Succeeded { result } => result.validate(),
            Self::Failed { error, .. } => error.validate_with_limit(MAX_ERROR_BYTES),
            Self::Indeterminate { reason, .. } => {
                validate_text("indeterminate reason", reason, MAX_REASON_BYTES)
            }
            Self::Cancelled { reason } => validate_text("cancel reason", reason, MAX_REASON_BYTES),
            Self::ControlQueued { control } => control.validate(),
            Self::ControlAcknowledged { control, detail, .. } => {
                control.validate()?;
                validate_optional_text("control detail", detail.as_deref(), MAX_REASON_BYTES)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionReceiptV1 {
    pub attempt: AttemptId,
    /// Canonical hash of the complete signed grant this fact continues.
    pub grant_hash: String,
    pub executor: String,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_unix_ms: Option<u64>,
    pub stage: ExecutionStageV1,
}

impl Validate for ExecutionReceiptV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        validate_sha256("execution receipt grant_hash", &self.grant_hash)?;
        validate_ed25519_public_key("executor", &self.executor)?;
        if self.sequence == 0 {
            return Err(ContractError::Invalid(
                "execution receipt sequence must be non-zero".into(),
            ));
        }
        self.stage.validate()?;
        ensure_message_bound(self)
    }
}

/// Verify an execution fact against the exact accepted, Home-signed attempt grant.
pub fn verify_execution_receipt(
    record: &SignedRecordV1<ExecutionReceiptV1>,
    grant: &SignedRecordV1<ExecutionGrantV1>,
) -> Result<(), ContractError> {
    verify_execution_grant(grant)?;
    record.validate()?;
    if record.schema != crate::SCHEMA_EXECUTE_V1 {
        return Err(ContractError::Invalid(format!(
            "execution receipt schema is `{}`, expected `{}`",
            record.schema,
            crate::SCHEMA_EXECUTE_V1
        )));
    }
    if !record.verify() {
        return Err(ContractError::Crypto("invalid execution receipt signature".into()));
    }
    if record.payload.attempt != grant.payload.attempt
        || record.payload.grant_hash != canonical_hash(grant)?
    {
        return Err(ContractError::Invalid(
            "execution receipt does not continue the exact signed grant".into(),
        ));
    }
    if record.signer != grant.payload.deployment.payload.executor
        || record.payload.executor != grant.payload.deployment.payload.executor
    {
        return Err(ContractError::Invalid(
            "execution receipt signer does not match the pinned executor".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlDispositionV1 {
    Applied,
    Rejected,
    Unsupported,
    TooLate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum JobControlKindV1 {
    Steer {
        value: ValueRefV1,
    },
    Cancel {
        reason: String,
    },
    AccessUpdate {
        #[serde(default)]
        add_readers: Vec<HomeId>,
        #[serde(default)]
        remove_readers: Vec<HomeId>,
        #[serde(default)]
        add_controllers: Vec<HomeId>,
        #[serde(default)]
        remove_controllers: Vec<HomeId>,
    },
    ProposeChild {
        parent_attempt: AttemptId,
        parent_event_hash: String,
        spawn_key: String,
        child_request_hash: String,
        submit: Box<SignedRecordV1<JobSubmitV1>>,
        resolution: Box<SignedRecordV1<crate::ResolutionReceiptV1>>,
        deployment: Box<SignedRecordV1<DeploymentReceiptV1>>,
    },
}

impl Validate for JobControlKindV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Steer { value } => value.validate(),
            Self::Cancel { reason } => validate_text("cancel reason", reason, MAX_REASON_BYTES),
            Self::AccessUpdate {
                add_readers,
                remove_readers,
                add_controllers,
                remove_controllers,
            } => {
                validate_vec("add_readers", add_readers, crate::MAX_JOB_DELEGATES)?;
                validate_vec("remove_readers", remove_readers, crate::MAX_JOB_DELEGATES)?;
                validate_vec("add_controllers", add_controllers, crate::MAX_JOB_DELEGATES)?;
                validate_vec("remove_controllers", remove_controllers, crate::MAX_JOB_DELEGATES)
            }
            Self::ProposeChild {
                parent_attempt,
                parent_event_hash,
                spawn_key,
                child_request_hash,
                submit,
                resolution,
                deployment,
            } => {
                parent_attempt.validate()?;
                validate_sha256("parent_event_hash", parent_event_hash)?;
                validate_text("spawn_key", spawn_key, MAX_IDEMPOTENCY_KEY_BYTES)?;
                validate_sha256("child_request_hash", child_request_hash)?;
                submit.validate()?;
                if submit.schema != crate::SCHEMA_JOB_V1 || !submit.verify() {
                    return Err(ContractError::Crypto(
                        "child submission signature is invalid".into(),
                    ));
                }
                if submit.payload.request_hash()? != *child_request_hash {
                    return Err(ContractError::Invalid(
                        "child request hash does not match the signed submission".into(),
                    ));
                }
                resolution.validate()?;
                if resolution.schema != crate::SCHEMA_FUNCTION_DEPLOY_V1 || !resolution.verify() {
                    return Err(ContractError::Crypto(
                        "child resolution receipt signature is invalid".into(),
                    ));
                }
                verify_deployment_receipt(deployment)?;
                if resolution.payload.selector != submit.payload.function
                    || resolution.payload.function != deployment.payload.function
                    || resolution.payload.artifact_hash != deployment.payload.artifact_hash
                {
                    return Err(ContractError::Invalid(
                        "child submission, resolution, and deployment pins do not match".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobControlV1 {
    pub handle: JobHandleV1,
    pub expected_home_epoch: u64,
    pub control: ControlId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ms: Option<u64>,
    pub kind: JobControlKindV1,
}

/// Home-endorsed control forwarding. The original caller signature remains nested and attributable;
/// the accepted event proves when the command became durable, while the outer signature proves the
/// currently active Home is continuing that exact intent after any custody move.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionControlV1 {
    pub caller_request: SignedRecordV1<JobControlV1>,
    /// Exact Home-signed `ControlRequested` event that made `caller_request` and the selected
    /// attempt durable. This remains the old epoch's independently verifiable acceptance proof
    /// when a newer Home re-endorses an unacknowledged control after custody moves.
    pub accepted_event: Box<SignedRecordV1<JobEventV1>>,
    /// Exact attempt selected when the Home durably accepted the control. `(attempt, ControlId)`
    /// is the target's stable replay/deduplication key.
    pub attempt: AttemptId,
    /// Canonical hash of the exact original execution grant for `attempt`.
    pub grant_hash: String,
    /// Current Home authority and authenticated return-route hint. These may be newer than the
    /// accepted event and original attempt grant after custody moves.
    pub home_epoch: u64,
    /// Monotonic active-lease route revision within `home_epoch` (genesis is 1).
    pub home_route_sequence: u64,
    pub home_sequence: u64,
    pub home_realm: String,
    pub home_node: String,
    pub home_coordinator: String,
    pub authority: HomeAuthorityV1,
}

impl Validate for ExecutionControlV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.caller_request.validate()?;
        if self.caller_request.schema != crate::SCHEMA_JOB_V1 || !self.caller_request.verify() {
            return Err(ContractError::Crypto(
                "execution control contains an invalid caller request signature".into(),
            ));
        }
        if self.home_epoch == 0 || self.home_route_sequence == 0 || self.home_sequence == 0 {
            return Err(ContractError::Invalid(
                "execution control home epoch/route/event sequences must be non-zero".into(),
            ));
        }
        validate_sha256("execution control grant_hash", &self.grant_hash)?;
        validate_text("control home_realm", &self.home_realm, MAX_ID_BYTES)?;
        validate_text("control home_node", &self.home_node, MAX_ID_BYTES)?;
        validate_text("control home_coordinator", &self.home_coordinator, MAX_ID_BYTES)?;
        verify_job_event(&self.accepted_event)?;
        let (accepted_request, accepted_attempt) = match &self.accepted_event.payload.kind {
            JobEventKindV1::ControlRequested { request, attempt: Some(attempt) } => {
                (request.as_ref(), attempt)
            }
            _ => {
                return Err(ContractError::Invalid(
                    "execution control acceptance proof is not a delivered ControlRequested event"
                        .into(),
                ));
            }
        };
        if accepted_request != &self.caller_request
            || accepted_attempt != &self.attempt
            || self.accepted_event.payload.handle != self.caller_request.payload.handle
            || self.accepted_event.payload.home_epoch
                != self.caller_request.payload.expected_home_epoch
            || self.accepted_event.payload.sequence != self.home_sequence
        {
            return Err(ContractError::Invalid(
                "execution control does not exactly continue its durable accepted event".into(),
            ));
        }
        if self.caller_request.payload.expected_home_epoch > self.home_epoch {
            return Err(ContractError::Invalid(
                "caller control expects an epoch newer than the endorsing Home".into(),
            ));
        }
        if self.attempt.home != self.caller_request.payload.handle.home
            || self.attempt.job != self.caller_request.payload.handle.job
        {
            return Err(ContractError::Invalid(
                "execution control attempt does not belong to the controlled Job".into(),
            ));
        }
        self.attempt.validate()?;
        self.authority.verify(
            &self.caller_request.payload.handle.home,
            self.home_epoch,
            OperationalCapabilityV1::JobControl,
        )?;
        if self.home_epoch > 1 {
            let prepared = self.authority.prepared.as_ref().ok_or_else(|| {
                ContractError::Invalid(
                    "moved execution control authority omits its Prepared proof".into(),
                )
            })?;
            let custody = &prepared.payload.grant.payload;
            if self.home_realm != custody.destination_realm
                || self.home_node != custody.destination_node
            {
                return Err(ContractError::Invalid(
                    "execution control location does not match its custody proof".into(),
                ));
            }
        }
        ensure_message_bound(self)
    }
}

impl Validate for JobControlV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.handle.validate()?;
        if self.expected_home_epoch == 0 {
            return Err(ContractError::Invalid("expected home epoch must be non-zero".into()));
        }
        self.control.validate()?;
        self.kind.validate()?;
        if let JobControlKindV1::ProposeChild { parent_attempt, .. } = &self.kind {
            if parent_attempt.home != self.handle.home || parent_attempt.job != self.handle.job {
                return Err(ContractError::Invalid(
                    "child proposal parent attempt does not belong to controlled job".into(),
                ));
            }
        }
        ensure_message_bound(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum JobEventKindV1 {
    Submitted {
        spec: Box<JobSpecV1>,
    },
    Blocked {
        reason: String,
    },
    DispatchGranted {
        grant_hash: String,
        attempt: AttemptId,
    },
    Claimed {
        attempt: AttemptId,
        executor: String,
    },
    Started {
        attempt: AttemptId,
    },
    Progress {
        attempt: AttemptId,
        sequence: u64,
        progress: ValueRefV1,
    },
    Checkpoint {
        attempt: AttemptId,
        sequence: u64,
        checkpoint: ValueRefV1,
    },
    /// The complete signed caller request is retained so a recovering Home can reproduce the
    /// exact attributable endorsement. `attempt` is the immutable delivery selection; `None`
    /// means the Job had no live attempt when the request became durable.
    ControlRequested {
        request: Box<SignedRecordV1<JobControlV1>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attempt: Option<AttemptId>,
    },
    ControlQueued {
        control: ControlId,
        attempt: AttemptId,
    },
    ControlAcknowledged {
        control: ControlId,
        attempt: AttemptId,
        disposition: ControlDispositionV1,
    },
    AttemptFailed {
        attempt: AttemptId,
        error: ValueRefV1,
        retryable: bool,
    },
    RetryScheduled {
        next_attempt: AttemptId,
        /// Advisory policy hint, not an authority or ordering input.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_before_unix_ms: Option<u64>,
    },
    Succeeded {
        attempt: AttemptId,
        result: ValueRefV1,
    },
    Failed {
        error: ValueRefV1,
    },
    Cancelled {
        reason: String,
    },
    Indeterminate {
        attempt: AttemptId,
        reason: String,
        execution_may_have_occurred: bool,
    },
    /// A valid executor fact observed after the Job was already terminal. It never reopens or
    /// rewrites the terminal result; the exact foreign receipt remains attached to the event.
    LateReceipt {
        attempt: AttemptId,
        observed: ExecutionStageV1,
    },
    AccessUpdated {
        control: ControlId,
        request_hash: String,
        access: JobAccessV1,
    },
    /// Atomic parent-ledger receipt for `(parent attempt, spawn_key)` deduplication.
    ChildSpawned {
        parent_attempt: AttemptId,
        parent_event_hash: String,
        spawn_key: String,
        child: JobHandleV1,
        root: JobHandleV1,
        child_request_hash: String,
    },
    CustodyPrepared {
        handoff: HandoffId,
        next_epoch: u64,
    },
    CustodyActivated {
        handoff: HandoffId,
    },
}

impl Validate for JobEventKindV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Submitted { spec } => spec.validate(),
            Self::Blocked { reason } | Self::Cancelled { reason } => {
                validate_text("job event reason", reason, MAX_REASON_BYTES)
            }
            Self::Indeterminate { attempt, reason, .. } => {
                attempt.validate()?;
                validate_text("job event reason", reason, MAX_REASON_BYTES)
            }
            Self::LateReceipt { attempt, observed } => {
                attempt.validate()?;
                observed.validate()
            }
            Self::DispatchGranted { grant_hash, attempt } => {
                validate_sha256("grant_hash", grant_hash)?;
                attempt.validate()
            }
            Self::Claimed { attempt, executor } => {
                attempt.validate()?;
                validate_text("executor", executor, MAX_ID_BYTES)
            }
            Self::Started { attempt } => attempt.validate(),
            Self::Progress { attempt, sequence, progress } => {
                attempt.validate()?;
                if *sequence == 0 {
                    return Err(ContractError::Invalid(
                        "progress sequence must be non-zero".into(),
                    ));
                }
                progress.validate_with_limit(MAX_PROGRESS_BYTES)
            }
            Self::Checkpoint { attempt, sequence, checkpoint } => {
                attempt.validate()?;
                if *sequence == 0 {
                    return Err(ContractError::Invalid(
                        "checkpoint sequence must be non-zero".into(),
                    ));
                }
                checkpoint.validate()
            }
            Self::ControlRequested { request, attempt } => {
                request.validate()?;
                if request.schema != crate::SCHEMA_JOB_V1 || !request.verify() {
                    return Err(ContractError::Crypto(
                        "job control event contains an invalid caller signature".into(),
                    ));
                }
                if let Some(attempt) = attempt {
                    attempt.validate()?;
                    if attempt.home != request.payload.handle.home
                        || attempt.job != request.payload.handle.job
                    {
                        return Err(ContractError::Invalid(
                            "job control event attempt belongs to another Job".into(),
                        ));
                    }
                }
                Ok(())
            }
            Self::ControlQueued { control, attempt } => {
                control.validate()?;
                attempt.validate()
            }
            Self::ControlAcknowledged { control, attempt, .. } => {
                control.validate()?;
                attempt.validate()
            }
            Self::AttemptFailed { attempt, error, .. } => {
                attempt.validate()?;
                error.validate_with_limit(MAX_ERROR_BYTES)
            }
            Self::RetryScheduled { next_attempt, .. } => next_attempt.validate(),
            Self::Succeeded { attempt, result } => {
                attempt.validate()?;
                result.validate()
            }
            Self::Failed { error } => error.validate_with_limit(MAX_ERROR_BYTES),
            Self::AccessUpdated { control, request_hash, access } => {
                control.validate()?;
                validate_sha256("access control request_hash", request_hash)?;
                access.validate()
            }
            Self::ChildSpawned {
                parent_attempt,
                parent_event_hash,
                spawn_key,
                child,
                root,
                child_request_hash,
            } => {
                parent_attempt.validate()?;
                validate_sha256("parent_event_hash", parent_event_hash)?;
                validate_text("spawn_key", spawn_key, MAX_IDEMPOTENCY_KEY_BYTES)?;
                child.validate()?;
                root.validate()?;
                if child.home != root.home
                    || parent_attempt.home != root.home
                    || parent_attempt.job == child.job
                {
                    return Err(ContractError::Invalid(
                        "child/root Homes must match and a child cannot equal its parent".into(),
                    ));
                }
                validate_sha256("child_request_hash", child_request_hash)
            }
            Self::CustodyPrepared { handoff, next_epoch } => {
                handoff.validate()?;
                if *next_epoch == 0 {
                    return Err(ContractError::Invalid("next epoch must be non-zero".into()));
                }
                Ok(())
            }
            Self::CustodyActivated { handoff } => handoff.validate(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobEventV1 {
    pub handle: JobHandleV1,
    pub home_epoch: u64,
    /// Root-to-epoch proof for the signer of this independently portable event.
    pub authority: HomeAuthorityV1,
    pub sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub occurred_at_unix_ms: Option<u64>,
    pub state_after: JobStateV1,
    #[serde(default)]
    pub cancel_requested: bool,
    pub kind: JobEventKindV1,
    /// Verbatim foreign executor provenance when this Home event normalizes an execution fact.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub foreign_receipt: Option<Box<SignedRecordV1<ExecutionReceiptV1>>>,
}

impl Validate for JobEventV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.handle.validate()?;
        if self.home_epoch == 0 || self.sequence == 0 {
            return Err(ContractError::Invalid(
                "home epoch and event sequence must be non-zero".into(),
            ));
        }
        self.authority.verify(
            &self.handle.home,
            self.home_epoch,
            OperationalCapabilityV1::JobHome,
        )?;
        self.kind.validate()?;
        match &self.kind {
            JobEventKindV1::Submitted { spec } if spec.handle != self.handle => {
                return Err(ContractError::Invalid(
                    "Submitted event handle does not match its accepted specification".into(),
                ));
            }
            JobEventKindV1::ChildSpawned { parent_attempt, child, root, .. }
                if parent_attempt.home != self.handle.home
                    || parent_attempt.job != self.handle.job
                    || child.home != self.handle.home
                    || root.home != self.handle.home =>
            {
                return Err(ContractError::Invalid(
                    "ChildSpawned parent/child/root do not share the event lineage".into(),
                ));
            }
            _ => {}
        }
        if matches!(self.kind, JobEventKindV1::LateReceipt { .. }) && self.foreign_receipt.is_none()
        {
            return Err(ContractError::Invalid(
                "LateReceipt event omits its exact foreign receipt".into(),
            ));
        }
        if let Some(receipt) = &self.foreign_receipt {
            receipt.validate()?;
            if receipt.schema != crate::SCHEMA_EXECUTE_V1
                || !receipt.verify()
                || receipt.signer != receipt.payload.executor
                || receipt.payload.attempt.home != self.handle.home
                || receipt.payload.attempt.job != self.handle.job
                || !receipt_matches_event(&receipt.payload, &self.kind)
            {
                return Err(ContractError::Invalid(
                    "foreign execution receipt does not exactly match the Home event".into(),
                ));
            }
        }
        ensure_message_bound(self)
    }
}

/// Verify an independently transported event all the way to its Abode root, rather than trusting
/// the hop-by-hop Envelope origin or a bare operational-key signature.
pub fn verify_job_event(record: &SignedRecordV1<JobEventV1>) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_JOB_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid job-event signature".into()));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "job-event signer is not the root-authorized Home epoch key".into(),
        ));
    }
    Ok(())
}

/// Verify that a Home's control acknowledgement answers one exact signed caller request and that
/// its signed durable event is the event shape that request can produce. The outer
/// [`JobMessageV1::ControlAccepted`] rides an authenticated Aether reply; this check prevents a
/// valid event or response for another control from being accepted merely because it came from the
/// current Home role.
pub fn verify_job_control_acceptance(
    request: &SignedRecordV1<JobControlV1>,
    request_hash: &str,
    event: &SignedRecordV1<JobEventV1>,
) -> Result<(), ContractError> {
    request.validate()?;
    if request.schema != crate::SCHEMA_JOB_V1 || !request.verify() {
        return Err(ContractError::Crypto("invalid job-control request signature".into()));
    }
    let expected_hash = crate::canonical_hash(request)?;
    if request_hash != expected_hash {
        return Err(ContractError::Invalid(
            "job-control acknowledgement does not bind the exact signed request".into(),
        ));
    }
    verify_job_event(event)?;
    if event.payload.handle != request.payload.handle
        || event.payload.home_epoch != request.payload.expected_home_epoch
    {
        return Err(ContractError::Invalid(
            "job-control acknowledgement event belongs to another handle or Home epoch".into(),
        ));
    }

    let matches_request = match (&request.payload.kind, &event.payload.kind) {
        (
            JobControlKindV1::Steer { .. },
            JobEventKindV1::ControlRequested { request: durable, attempt: Some(_) },
        ) => durable.as_ref() == request,
        (
            JobControlKindV1::Cancel { .. },
            JobEventKindV1::ControlRequested { request: durable, .. },
        ) => durable.as_ref() == request,
        (
            JobControlKindV1::AccessUpdate { .. },
            JobEventKindV1::AccessUpdated { control, request_hash: durable_hash, .. },
        ) => control == &request.payload.control && durable_hash == request_hash,
        (
            JobControlKindV1::ProposeChild {
                parent_attempt,
                parent_event_hash,
                spawn_key,
                child_request_hash,
                submit,
                ..
            },
            JobEventKindV1::ChildSpawned {
                parent_attempt: durable_attempt,
                parent_event_hash: durable_event_hash,
                spawn_key: durable_spawn_key,
                child,
                child_request_hash: durable_child_hash,
                ..
            },
        ) => {
            let expected_child =
                crate::derive_job_id(&submit.payload.home, &submit.payload.caller_idempotency_key)
                    .map(|job| JobHandleV1 { home: submit.payload.home.clone(), job })?;
            durable_attempt == parent_attempt
                && durable_event_hash == parent_event_hash
                && durable_spawn_key == spawn_key
                && durable_child_hash == child_request_hash
                && child == &expected_child
        }
        _ => false,
    };
    if !matches_request {
        return Err(ContractError::Invalid(
            "job-control acknowledgement event does not prove the requested control".into(),
        ));
    }
    Ok(())
}

/// Additionally bind a receipt-derived public event to the exact signed attempt grant.
pub fn verify_job_event_with_grant(
    record: &SignedRecordV1<JobEventV1>,
    grant: &SignedRecordV1<ExecutionGrantV1>,
) -> Result<(), ContractError> {
    verify_job_event(record)?;
    let receipt = record.payload.foreign_receipt.as_deref().ok_or_else(|| {
        ContractError::Invalid("job event does not carry a foreign execution receipt".into())
    })?;
    verify_execution_receipt(receipt, grant)
}

fn receipt_matches_event(receipt: &ExecutionReceiptV1, event: &JobEventKindV1) -> bool {
    match (&receipt.stage, event) {
        (ExecutionStageV1::Claimed, JobEventKindV1::Claimed { attempt, executor }) => {
            attempt == &receipt.attempt && executor == &receipt.executor
        }
        (ExecutionStageV1::Started, JobEventKindV1::Started { attempt }) => {
            attempt == &receipt.attempt
        }
        (
            ExecutionStageV1::Progress { sequence: left_sequence, progress: left },
            JobEventKindV1::Progress { attempt, sequence: right_sequence, progress: right },
        ) => attempt == &receipt.attempt && left_sequence == right_sequence && left == right,
        (
            ExecutionStageV1::Checkpoint { sequence: left_sequence, checkpoint: left },
            JobEventKindV1::Checkpoint { attempt, sequence: right_sequence, checkpoint: right },
        ) => attempt == &receipt.attempt && left_sequence == right_sequence && left == right,
        (
            ExecutionStageV1::Succeeded { result: left },
            JobEventKindV1::Succeeded { attempt, result: right },
        ) => attempt == &receipt.attempt && left == right,
        (
            ExecutionStageV1::Failed { error: left, retryable: left_retryable },
            JobEventKindV1::AttemptFailed { attempt, error: right, retryable: right_retryable },
        ) => attempt == &receipt.attempt && left == right && left_retryable == right_retryable,
        (
            ExecutionStageV1::Indeterminate { reason: left, execution_may_have_occurred: left_may },
            JobEventKindV1::Indeterminate {
                attempt,
                reason: right,
                execution_may_have_occurred: right_may,
            },
        ) => attempt == &receipt.attempt && left == right && left_may == right_may,
        (observed, JobEventKindV1::LateReceipt { attempt, observed: event_observed }) => {
            attempt == &receipt.attempt && observed == event_observed
        }
        (
            ExecutionStageV1::Cancelled { reason: left },
            JobEventKindV1::Cancelled { reason: right },
        ) => left == right,
        (
            ExecutionStageV1::ControlQueued { control: left },
            JobEventKindV1::ControlQueued { control: right, attempt },
        ) => attempt == &receipt.attempt && left == right,
        (
            ExecutionStageV1::ControlAcknowledged {
                control: left,
                disposition: left_disposition,
                ..
            },
            JobEventKindV1::ControlAcknowledged {
                control: right,
                attempt,
                disposition: right_disposition,
            },
        ) => attempt == &receipt.attempt && left == right && left_disposition == right_disposition,
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSnapshotV1 {
    pub spec: JobSpecV1,
    pub state: JobStateV1,
    pub cancel_requested: bool,
    pub home_epoch: u64,
    /// Root-to-epoch proof for the active Home signer asserting this snapshot.
    pub authority: HomeAuthorityV1,
    pub last_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_attempt: Option<AttemptId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<ValueRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ValueRefV1>,
}

impl Validate for JobSnapshotV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.spec.validate()?;
        if self.home_epoch == 0 || self.last_sequence == 0 {
            return Err(ContractError::Invalid(
                "home epoch and last sequence must be non-zero".into(),
            ));
        }
        self.authority.verify(
            &self.spec.handle.home,
            self.home_epoch,
            OperationalCapabilityV1::JobHome,
        )?;
        if let Some(attempt) = &self.current_attempt {
            attempt.validate()?;
            if attempt.home != self.spec.handle.home || attempt.job != self.spec.handle.job {
                return Err(ContractError::Invalid(
                    "snapshot current attempt belongs to a different Job handle".into(),
                ));
            }
        }
        if let Some(result) = &self.result {
            result.validate()?;
        }
        if let Some(error) = &self.error {
            error.validate_with_limit(MAX_ERROR_BYTES)?;
        }
        ensure_message_bound(self)
    }
}

pub fn verify_job_snapshot(record: &SignedRecordV1<JobSnapshotV1>) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_JOB_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid job-snapshot signature".into()));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "job-snapshot signer is not the root-authorized active Home key".into(),
        ));
    }
    Ok(())
}

/// Stable-executor-signed proof of the executor's current process-local dispatch route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorDispatchV1 {
    pub attempt: AttemptId,
    pub grant_hash: String,
    pub deployment: DeploymentId,
    /// Current process-local executor route; re-attested after restart by the stable executor key.
    pub executor_creature: String,
    pub target_creature: String,
}

/// Stable-executor-signed current route for one cooperative control. This is distinct from a call
/// dispatch because it binds the exact current Home endorsement as well as the immutable grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutorControlDispatchV1 {
    pub attempt: AttemptId,
    pub grant_hash: String,
    pub control_hash: String,
    pub deployment: DeploymentId,
    /// Current process-local executor route; re-attested after restart by the stable executor key.
    pub executor_creature: String,
    pub target_creature: String,
}

impl Validate for ExecutorControlDispatchV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        validate_sha256("executor control dispatch grant_hash", &self.grant_hash)?;
        validate_sha256("executor control dispatch control_hash", &self.control_hash)?;
        self.deployment.validate()?;
        validate_creature_id("executor control dispatch route", &self.executor_creature)?;
        validate_creature_id("executor control dispatch target", &self.target_creature)
    }
}

pub fn verify_executor_control_dispatch(
    record: &SignedRecordV1<ExecutorControlDispatchV1>,
    control: &SignedRecordV1<ExecutionControlV1>,
    grant: &SignedRecordV1<ExecutionGrantV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    verify_execution_control(control)?;
    verify_execution_grant(grant)?;
    if record.schema != crate::SCHEMA_CALL_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid executor control dispatch signature".into()));
    }
    let grant_hash = canonical_hash(grant)?;
    if record.signer != grant.payload.deployment.payload.executor
        || record.payload.attempt != grant.payload.attempt
        || record.payload.attempt != control.payload.attempt
        || record.payload.grant_hash != grant_hash
        || control.payload.grant_hash != grant_hash
        || record.payload.control_hash != canonical_hash(control)?
        || record.payload.deployment != grant.payload.deployment.payload.deployment
        || record.payload.target_creature != grant.payload.deployment.payload.creature
    {
        return Err(ContractError::Invalid(
            "executor control dispatch does not continue its exact grant and Home endorsement"
                .into(),
        ));
    }
    Ok(())
}

impl Validate for ExecutorDispatchV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        validate_sha256("executor dispatch grant_hash", &self.grant_hash)?;
        self.deployment.validate()?;
        validate_creature_id("executor dispatch route", &self.executor_creature)?;
        validate_creature_id("executor dispatch target", &self.target_creature)
    }
}

pub fn verify_executor_dispatch(
    record: &SignedRecordV1<ExecutorDispatchV1>,
    grant: &SignedRecordV1<ExecutionGrantV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    verify_execution_grant(grant)?;
    if record.schema != crate::SCHEMA_CALL_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid executor dispatch signature".into()));
    }
    if record.signer != grant.payload.deployment.payload.executor
        || record.payload.attempt != grant.payload.attempt
        || record.payload.grant_hash != canonical_hash(grant)?
        || record.payload.deployment != grant.payload.deployment.payload.deployment
        || record.payload.target_creature != grant.payload.deployment.payload.creature
    {
        return Err(ContractError::Invalid(
            "executor dispatch does not continue its exact deployment grant".into(),
        ));
    }
    Ok(())
}

/// Actual typed call proxied by an executor into a creature's single `handle` ABI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCallV1 {
    pub attempt: AttemptId,
    pub function: FunctionId,
    pub input: ValueRefV1,
    /// Exact Home-signed permission already durably claimed by the executor. The target adapter
    /// verifies this proof and binds the fabric sender/recipient to its deployment routes before
    /// allowing application code to observe the call.
    pub grant: Box<SignedRecordV1<ExecutionGrantV1>>,
    /// Stable-executor-signed current route. Deployment receipts remain immutable historical load
    /// facts even when the executor creature obtains a new process-local id after restart.
    pub executor_dispatch: SignedRecordV1<ExecutorDispatchV1>,
}

/// Proof-bearing cooperative control delivered through the same creature `handle` ABI as calls.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionControlV1 {
    pub attempt: AttemptId,
    pub endorsement: Box<SignedRecordV1<ExecutionControlV1>>,
    pub grant: Box<SignedRecordV1<ExecutionGrantV1>>,
    pub executor_dispatch: SignedRecordV1<ExecutorControlDispatchV1>,
}

impl Validate for FunctionControlV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        verify_execution_control(&self.endorsement)?;
        verify_execution_grant(&self.grant)?;
        verify_executor_control_dispatch(&self.executor_dispatch, &self.endorsement, &self.grant)?;
        if self.attempt != self.endorsement.payload.attempt
            || self.attempt != self.grant.payload.attempt
        {
            return Err(ContractError::Invalid(
                "function control does not name its exact endorsed and granted attempt".into(),
            ));
        }
        ensure_message_bound(self)
    }
}

impl Validate for FunctionCallV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        self.function.validate()?;
        self.input.validate()?;
        verify_execution_grant(&self.grant)?;
        verify_executor_dispatch(&self.executor_dispatch, &self.grant)?;
        if self.attempt != self.grant.payload.attempt
            || self.function != self.grant.payload.function
            || self.input != self.grant.payload.input
        {
            return Err(ContractError::Invalid(
                "function call does not exactly continue its signed execution grant".into(),
            ));
        }
        ensure_message_bound(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionResultV1 {
    pub attempt: AttemptId,
    pub outcome: Result<ValueRefV1, ValueRefV1>,
}

impl Validate for FunctionResultV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.attempt.validate()?;
        match &self.outcome {
            Ok(result) => result.validate()?,
            Err(error) => error.validate_with_limit(MAX_ERROR_BYTES)?,
        }
        ensure_message_bound(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeCheckpointV1 {
    pub home: HomeId,
    pub epoch: u64,
    pub high_water_mark: u64,
    pub log_root: String,
    pub state: BlobRefV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix_ms: Option<u64>,
}

impl Validate for HomeCheckpointV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        if self.epoch == 0 {
            return Err(ContractError::Invalid("home epoch must be non-zero".into()));
        }
        validate_sha256("log_root", &self.log_root)?;
        self.state.validate()
    }
}

/// Root-bound source and destination data-key identities for an explicitly requested custody
/// rewrap. The private encryption and proof-signing keys remain behind the injected KMS/enclave
/// adapter; this contract carries only their public bindings and bounded policy evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRewrapRequirementV1 {
    pub source_binding: Box<SignedRecordV1<RecipientKeyBindingV1>>,
    pub destination_binding: Box<SignedRecordV1<RecipientKeyBindingV1>>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for CustodyRewrapRequirementV1 {
    fn validate(&self) -> Result<(), ContractError> {
        verify_recipient_key_binding(&self.source_binding)?;
        verify_recipient_key_binding(&self.destination_binding)?;
        let source = &self.source_binding.payload;
        let destination = &self.destination_binding.payload;
        if source.abode != destination.abode {
            return Err(ContractError::Invalid(
                "custody rewrap key bindings must name the same Abode".into(),
            ));
        }
        if source.suite != destination.suite {
            return Err(ContractError::Invalid(
                "custody rewrap v1 requires the same source and destination key suite".into(),
            ));
        }
        if source.encryption_public_key == destination.encryption_public_key
            || canonical_hash(self.source_binding.as_ref())?
                == canonical_hash(self.destination_binding.as_ref())?
        {
            return Err(ContractError::Invalid(
                "custody rewrap must rotate to a distinct destination encryption binding".into(),
            ));
        }
        validate_vec("custody rewrap evidence", &self.evidence, MAX_EVIDENCE_REFS)?;
        ensure_message_bound(self)
    }
}

/// Verify that a recipient-key binding is an exact root-domain statement by the named Abode.
pub fn verify_recipient_key_binding(
    record: &SignedRecordV1<RecipientKeyBindingV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_HOME_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid recipient-key-binding signature".into()));
    }
    if record.signer != record.payload.abode.0 {
        return Err(ContractError::Invalid(
            "recipient-key binding must be signed by the named Abode root".into(),
        ));
    }
    Ok(())
}

/// Portable public input to an injected rewrap adapter. The source wrap remains ciphertext; no
/// private key or decrypted data key enters the function contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRewrapSourceV1 {
    /// Canonical hash of the complete sealed value found in the frozen checkpoint.
    pub sealed_value_hash: String,
    pub ciphertext: BlobRefV1,
    /// The exact source-Home envelope selected from that sealed value.
    pub source_wrap: RecipientKeyWrapV1,
}

impl Validate for CustodyRewrapSourceV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_sha256("rewrap sealed_value_hash", &self.sealed_value_hash)?;
        self.ciphertext.validate()?;
        self.source_wrap.validate()
    }
}

#[derive(Serialize)]
struct CustodyRewrapInventoryCommitmentV1 {
    sealed_value_hash: String,
    ciphertext: BlobRefV1,
    source_wrap_hash: String,
}

#[derive(Serialize)]
struct CustodyRewrapInventoryHashV1 {
    schema: &'static str,
    purpose: &'static str,
    items: Vec<CustodyRewrapInventoryCommitmentV1>,
}

fn validate_rewrap_item_order<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> Result<(), ContractError> {
    let mut previous: Option<&str> = None;
    for name in names {
        if previous.is_some_and(|prior| prior >= name) {
            return Err(ContractError::Invalid(
                "custody rewrap items must be strictly ordered by unique sealed_value_hash".into(),
            ));
        }
        previous = Some(name);
    }
    Ok(())
}

fn rewrap_inventory_hash(
    items: Vec<CustodyRewrapInventoryCommitmentV1>,
) -> Result<String, ContractError> {
    canonical_hash(&CustodyRewrapInventoryHashV1 {
        schema: crate::SCHEMA_CUSTODY_REWRAP_V1,
        purpose: "source_inventory",
        items,
    })
}

/// Compute the canonical, schema-domain-separated commitment to a bounded source inventory.
/// Items must be strictly ordered and unique so all implementations produce the same commitment.
pub fn custody_rewrap_inventory_hash(
    inventory: &[CustodyRewrapSourceV1],
) -> Result<String, ContractError> {
    if inventory.len() > MAX_CUSTODY_REWRAP_ITEMS {
        return Err(ContractError::Limit(format!(
            "custody rewrap inventory has {} items, exceeds {MAX_CUSTODY_REWRAP_ITEMS}",
            inventory.len()
        )));
    }
    validate_rewrap_item_order(inventory.iter().map(|item| item.sealed_value_hash.as_str()))?;
    let mut commitments = Vec::with_capacity(inventory.len());
    for source in inventory {
        source.validate()?;
        commitments.push(CustodyRewrapInventoryCommitmentV1 {
            sealed_value_hash: source.sealed_value_hash.clone(),
            ciphertext: source.ciphertext.clone(),
            source_wrap_hash: canonical_hash(&source.source_wrap)?,
        });
    }
    rewrap_inventory_hash(commitments)
}

/// Validate that a source inventory is exactly addressed to the declared source binding, then
/// return its canonical commitment for inclusion in a source-signed Prepared proof.
pub fn verify_custody_rewrap_inventory(
    home: &HomeId,
    requirement: &CustodyRewrapRequirementV1,
    inventory: &[CustodyRewrapSourceV1],
) -> Result<String, ContractError> {
    requirement.validate()?;
    if &requirement.source_binding.payload.abode != home
        || &requirement.destination_binding.payload.abode != home
    {
        return Err(ContractError::Invalid(
            "custody rewrap inventory and bindings do not name the granted Home".into(),
        ));
    }
    let source_binding_hash = canonical_hash(requirement.source_binding.as_ref())?;
    for source in inventory {
        if &source.source_wrap.recipient != home
            || source.source_wrap.binding_hash != source_binding_hash
        {
            return Err(ContractError::Invalid(
                "custody rewrap source envelope does not use the exact declared source binding"
                    .into(),
            ));
        }
    }
    custody_rewrap_inventory_hash(inventory)
}

/// Owner-authorized transfer from one single-writer epoch to the next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyGrantV1 {
    pub home: HomeId,
    pub handoff: HandoffId,
    pub from_epoch: u64,
    pub to_epoch: u64,
    /// Root-proven source epoch key authorized to freeze and sign the checkpoint.
    pub source_authority: HomeAuthorityV1,
    pub source_realm: String,
    pub source_node: String,
    pub destination_realm: String,
    pub destination_node: String,
    /// Canonical hash of the complete signed [`HomeCheckpointV1`] record.
    pub checkpoint_hash: String,
    /// Exact hash-chain tip committed inside that checkpoint.
    pub source_log_root: String,
    pub destination_operational_key: SignedRecordV1<OperationalKeyGrantV1>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ms: Option<u64>,
    /// Optional explicit requirement to preserve Home decryption capability at the destination.
    /// `None` deliberately makes no decryption or destination-envelope claim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_rewrap: Option<CustodyRewrapRequirementV1>,
}

impl Validate for CustodyGrantV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        self.handoff.validate()?;
        if self.from_epoch == 0 || self.to_epoch != self.from_epoch.saturating_add(1) {
            return Err(ContractError::Invalid(
                "custody grant must advance exactly one non-zero epoch".into(),
            ));
        }
        self.source_authority.verify(
            &self.home,
            self.from_epoch,
            OperationalCapabilityV1::Custody,
        )?;
        validate_text("source_realm", &self.source_realm, MAX_ID_BYTES)?;
        validate_text("source_node", &self.source_node, MAX_ID_BYTES)?;
        validate_text("destination_realm", &self.destination_realm, MAX_ID_BYTES)?;
        validate_text("destination_node", &self.destination_node, MAX_ID_BYTES)?;
        validate_sha256("checkpoint_hash", &self.checkpoint_hash)?;
        validate_sha256("source_log_root", &self.source_log_root)?;
        self.destination_operational_key.validate()?;
        if self.destination_operational_key.schema != crate::SCHEMA_HOME_V1
            || !self.destination_operational_key.verify()
            || self.destination_operational_key.signer != self.home.0
        {
            return Err(ContractError::Crypto(
                "destination operational key is not signed by the Abode root".into(),
            ));
        }
        let key = &self.destination_operational_key.payload;
        if key.home != self.home || key.epoch != self.to_epoch {
            return Err(ContractError::Invalid(
                "destination operational key does not match home/epoch".into(),
            ));
        }
        for required in [
            OperationalCapabilityV1::JobHome,
            OperationalCapabilityV1::JobControl,
            OperationalCapabilityV1::Custody,
            OperationalCapabilityV1::Locate,
        ] {
            if !key.capabilities.contains(&required) {
                return Err(ContractError::Invalid(format!(
                    "destination operational key lacks required `{required:?}` capability"
                )));
            }
        }
        validate_vec("custody evidence", &self.evidence, MAX_EVIDENCE_REFS)?;
        if let Some(requirement) = &self.destination_rewrap {
            requirement.validate()?;
            let source = &requirement.source_binding.payload;
            let destination = &requirement.destination_binding.payload;
            if source.abode != self.home || destination.abode != self.home {
                return Err(ContractError::Invalid(
                    "custody rewrap bindings do not name the granted Home".into(),
                ));
            }
            let source_operational =
                &self.source_authority.operational.payload.operational_public_key;
            let destination_operational =
                &self.destination_operational_key.payload.operational_public_key;
            for proof_signer in [&source.signing_public_key, &destination.signing_public_key] {
                for encryption_key in
                    [&source.encryption_public_key, &destination.encryption_public_key]
                {
                    if proof_signer == encryption_key {
                        return Err(ContractError::Invalid(
                            "custody rewrap proof-signing and encryption keys must be separate"
                                .into(),
                        ));
                    }
                }
                if proof_signer == &self.home.0
                    || proof_signer == source_operational
                    || proof_signer == destination_operational
                {
                    return Err(ContractError::Invalid(
                        "custody rewrap proof keys must be separate from root and epoch authority keys"
                            .into(),
                    ));
                }
            }
            for encryption_key in
                [&source.encryption_public_key, &destination.encryption_public_key]
            {
                if encryption_key == &self.home.0
                    || encryption_key == source_operational
                    || encryption_key == destination_operational
                {
                    return Err(ContractError::Invalid(
                        "custody rewrap encryption keys must be separate from root and epoch authority keys"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Verify the root authorization of an epoch-fenced custody transition.
pub fn verify_custody_grant(record: &SignedRecordV1<CustodyGrantV1>) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_HOME_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid custody-grant signature".into()));
    }
    if record.signer != record.payload.home.0 {
        return Err(ContractError::Invalid(
            "custody grant must be signed by the owning Abode root".into(),
        ));
    }
    Ok(())
}

/// Verify the source epoch's signed checkpoint and its exact handoff hash/tip binding.
pub fn verify_handoff_checkpoint(
    grant: &SignedRecordV1<CustodyGrantV1>,
    checkpoint: &SignedRecordV1<HomeCheckpointV1>,
) -> Result<(), ContractError> {
    verify_custody_grant(grant)?;
    checkpoint.validate()?;
    if checkpoint.schema != crate::SCHEMA_HOME_V1 || !checkpoint.verify() {
        return Err(ContractError::Crypto("invalid handoff checkpoint signature".into()));
    }
    let source_key = &grant.payload.source_authority.operational.payload.operational_public_key;
    if checkpoint.signer != *source_key
        || checkpoint.payload.home != grant.payload.home
        || checkpoint.payload.epoch != grant.payload.from_epoch
        || checkpoint.payload.log_root != grant.payload.source_log_root
        || canonical_hash(checkpoint)? != grant.payload.checkpoint_hash
    {
        return Err(ContractError::Invalid(
            "handoff checkpoint does not match source authority/home/epoch/hash-chain tip".into(),
        ));
    }
    Ok(())
}

/// Source-epoch proof that the exact custody fence was durably prepared.
///
/// This record is signed only after the source Home has fsynced its irreversible Frozen marker.
/// Embedding the exact grant and checkpoint makes the proof independently verifiable after it
/// crosses Realm boundaries; no hop-local envelope identity is promoted into authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyPreparedV1 {
    pub grant: Box<SignedRecordV1<CustodyGrantV1>>,
    pub checkpoint: Box<SignedRecordV1<HomeCheckpointV1>>,
    pub grant_hash: String,
    pub checkpoint_hash: String,
    pub source_log_root: String,
    /// Numeric source Home creature identity when one is available. It is a signed return route,
    /// not custody authority; non-creature compositions may use another bounded identifier.
    pub source_coordinator: String,
    /// Source-frozen commitment to every unique checkpoint sealed value addressed to this Home.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrap_inventory_hash: Option<String>,
    /// Exact number of unique entries in `rewrap_inventory_hash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrap_item_count: Option<u32>,
}

impl Validate for CustodyPreparedV1 {
    fn validate(&self) -> Result<(), ContractError> {
        verify_handoff_checkpoint(&self.grant, &self.checkpoint)?;
        validate_sha256("prepared grant_hash", &self.grant_hash)?;
        validate_sha256("prepared checkpoint_hash", &self.checkpoint_hash)?;
        validate_sha256("prepared source_log_root", &self.source_log_root)?;
        validate_text("prepared source_coordinator", &self.source_coordinator, MAX_ID_BYTES)?;
        if canonical_hash(self.grant.as_ref())? != self.grant_hash
            || canonical_hash(self.checkpoint.as_ref())? != self.checkpoint_hash
            || self.source_log_root != self.grant.payload.source_log_root
            || self.source_log_root != self.checkpoint.payload.log_root
        {
            return Err(ContractError::Invalid(
                "prepared proof does not bind its exact grant/checkpoint/log root".into(),
            ));
        }
        match (
            &self.grant.payload.destination_rewrap,
            &self.rewrap_inventory_hash,
            self.rewrap_item_count,
        ) {
            (None, None, None) => {}
            (Some(_), Some(inventory_hash), Some(item_count)) => {
                validate_sha256("prepared rewrap_inventory_hash", inventory_hash)?;
                if usize::try_from(item_count)
                    .map_or(true, |count| count > MAX_CUSTODY_REWRAP_ITEMS)
                {
                    return Err(ContractError::Limit(format!(
                        "prepared custody rewrap has {item_count} items, exceeds {MAX_CUSTODY_REWRAP_ITEMS}"
                    )));
                }
            }
            _ => {
                return Err(ContractError::Invalid(
                    "prepared custody rewrap inventory fields must be present exactly when the grant declares rewrap"
                        .into(),
                ));
            }
        }
        ensure_message_bound(self)
    }
}

/// Verify a source-fsynced custody preparation proof and its root-authorized epoch signer.
pub fn verify_custody_prepared(
    record: &SignedRecordV1<CustodyPreparedV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_HOME_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid custody-prepared signature".into()));
    }
    let source_key =
        &record.payload.grant.payload.source_authority.operational.payload.operational_public_key;
    if &record.signer != source_key {
        return Err(ContractError::Invalid(
            "custody-prepared signer is not the root-authorized source epoch key".into(),
        ));
    }
    Ok(())
}

/// Destination-epoch request for the injected KMS/enclave adapter to rewrap one exact,
/// source-frozen inventory. This request contains commitments only; private key operations stay
/// behind the adapter boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRewrapRequestV1 {
    pub home: HomeId,
    pub handoff: HandoffId,
    pub prepared_hash: String,
    pub grant_hash: String,
    pub checkpoint_hash: String,
    pub requirement_hash: String,
    pub inventory_hash: String,
    pub item_count: u32,
}

impl Validate for CustodyRewrapRequestV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        self.handoff.validate()?;
        validate_sha256("rewrap request prepared_hash", &self.prepared_hash)?;
        validate_sha256("rewrap request grant_hash", &self.grant_hash)?;
        validate_sha256("rewrap request checkpoint_hash", &self.checkpoint_hash)?;
        validate_sha256("rewrap request requirement_hash", &self.requirement_hash)?;
        validate_sha256("rewrap request inventory_hash", &self.inventory_hash)?;
        if usize::try_from(self.item_count).map_or(true, |count| count > MAX_CUSTODY_REWRAP_ITEMS) {
            return Err(ContractError::Limit(format!(
                "custody rewrap request has {} items, exceeds {MAX_CUSTODY_REWRAP_ITEMS}",
                self.item_count
            )));
        }
        ensure_message_bound(self)
    }
}

/// Verify the destination operational signer's exact request for a source-signed inventory.
pub fn verify_custody_rewrap_request(
    record: &SignedRecordV1<CustodyRewrapRequestV1>,
    prepared: &SignedRecordV1<CustodyPreparedV1>,
) -> Result<(), ContractError> {
    verify_custody_prepared(prepared)?;
    record.validate()?;
    if record.schema != crate::SCHEMA_CUSTODY_REWRAP_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid custody-rewrap-request signature".into()));
    }
    let grant = &prepared.payload.grant;
    let requirement = grant.payload.destination_rewrap.as_ref().ok_or_else(|| {
        ContractError::Invalid(
            "custody rewrap request has no declaration in the exact custody grant".into(),
        )
    })?;
    let destination_key = &grant.payload.destination_operational_key.payload.operational_public_key;
    let prepared_inventory_hash =
        prepared.payload.rewrap_inventory_hash.as_ref().ok_or_else(|| {
            ContractError::Invalid("prepared proof omits its declared rewrap inventory hash".into())
        })?;
    let prepared_item_count = prepared.payload.rewrap_item_count.ok_or_else(|| {
        ContractError::Invalid("prepared proof omits its declared rewrap item count".into())
    })?;
    let request = &record.payload;
    if &record.signer != destination_key
        || request.home != grant.payload.home
        || request.handoff != grant.payload.handoff
        || request.prepared_hash != canonical_hash(prepared)?
        || request.grant_hash != prepared.payload.grant_hash
        || request.checkpoint_hash != prepared.payload.checkpoint_hash
        || request.requirement_hash != canonical_hash(requirement)?
        || &request.inventory_hash != prepared_inventory_hash
        || request.item_count != prepared_item_count
    {
        return Err(ContractError::Invalid(
            "custody rewrap request does not exactly bind the Prepared proof, grant, requirement, and inventory"
                .into(),
        ));
    }
    Ok(())
}

/// One exact destination envelope and the source-inventory commitment it replaces.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRewrapEntryV1 {
    pub sealed_value_hash: String,
    pub ciphertext: BlobRefV1,
    pub source_wrap_hash: String,
    pub destination_wrap: RecipientKeyWrapV1,
}

impl Validate for CustodyRewrapEntryV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_sha256("rewrap entry sealed_value_hash", &self.sealed_value_hash)?;
        self.ciphertext.validate()?;
        validate_sha256("rewrap entry source_wrap_hash", &self.source_wrap_hash)?;
        self.destination_wrap.validate()
    }
}

/// Aggregate KMS/enclave proof that every item in the exact source-frozen inventory received a
/// destination-local envelope. The outer record is signed by the destination binding's dedicated
/// proof key, not by a root or operational authority key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRewrapReceiptV1 {
    pub request: Box<SignedRecordV1<CustodyRewrapRequestV1>>,
    pub entries: Vec<CustodyRewrapEntryV1>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for CustodyRewrapReceiptV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.request.validate()?;
        if self.entries.len() > MAX_CUSTODY_REWRAP_ITEMS {
            return Err(ContractError::Limit(format!(
                "custody rewrap receipt has {} entries, exceeds {MAX_CUSTODY_REWRAP_ITEMS}",
                self.entries.len()
            )));
        }
        validate_rewrap_item_order(
            self.entries.iter().map(|entry| entry.sealed_value_hash.as_str()),
        )?;
        let mut commitments = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            entry.validate()?;
            commitments.push(CustodyRewrapInventoryCommitmentV1 {
                sealed_value_hash: entry.sealed_value_hash.clone(),
                ciphertext: entry.ciphertext.clone(),
                source_wrap_hash: entry.source_wrap_hash.clone(),
            });
        }
        let entry_count = u32::try_from(self.entries.len()).map_err(|_| {
            ContractError::Limit("custody rewrap receipt item count does not fit u32".into())
        })?;
        if self.request.payload.item_count != entry_count
            || self.request.payload.inventory_hash != rewrap_inventory_hash(commitments)?
        {
            return Err(ContractError::Invalid(
                "custody rewrap receipt entries do not exactly cover the requested inventory"
                    .into(),
            ));
        }
        validate_vec("custody rewrap receipt evidence", &self.evidence, MAX_EVIDENCE_REFS)?;
        ensure_message_bound(self)
    }
}

/// Verify the complete root grant -> source Prepared -> destination request -> KMS receipt chain.
pub fn verify_custody_rewrap_receipt(
    record: &SignedRecordV1<CustodyRewrapReceiptV1>,
    prepared: &SignedRecordV1<CustodyPreparedV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    verify_custody_rewrap_request(&record.payload.request, prepared)?;
    if record.schema != crate::SCHEMA_CUSTODY_REWRAP_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid custody-rewrap-receipt signature".into()));
    }
    let grant = &prepared.payload.grant;
    let requirement = grant.payload.destination_rewrap.as_ref().ok_or_else(|| {
        ContractError::Invalid(
            "custody rewrap receipt has no declaration in the exact custody grant".into(),
        )
    })?;
    let destination_binding_hash = canonical_hash(requirement.destination_binding.as_ref())?;
    if record.signer != requirement.destination_binding.payload.signing_public_key {
        return Err(ContractError::Invalid(
            "custody rewrap receipt is not signed by the declared destination proof key".into(),
        ));
    }
    for entry in &record.payload.entries {
        if entry.destination_wrap.recipient != grant.payload.home
            || entry.destination_wrap.binding_hash != destination_binding_hash
        {
            return Err(ContractError::Invalid(
                "custody rewrap receipt entry does not use the exact destination binding".into(),
            ));
        }
    }
    Ok(())
}

/// Destination proof that the exact prepared archive and all referenced blobs were durably staged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyStagedV1 {
    pub prepared: Box<SignedRecordV1<CustodyPreparedV1>>,
    pub prepared_hash: String,
    pub grant_hash: String,
    pub checkpoint_hash: String,
    pub destination_realm: String,
    pub destination_node: String,
    pub destination_coordinator: String,
    /// Required aggregate proof exactly when the root grant declared destination rewrap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rewrap_receipt: Option<Box<SignedRecordV1<CustodyRewrapReceiptV1>>>,
}

impl Validate for CustodyStagedV1 {
    fn validate(&self) -> Result<(), ContractError> {
        verify_custody_prepared(&self.prepared)?;
        validate_sha256("staged prepared_hash", &self.prepared_hash)?;
        validate_sha256("staged grant_hash", &self.grant_hash)?;
        validate_sha256("staged checkpoint_hash", &self.checkpoint_hash)?;
        validate_text("staged destination_realm", &self.destination_realm, MAX_ID_BYTES)?;
        validate_text("staged destination_node", &self.destination_node, MAX_ID_BYTES)?;
        validate_text(
            "staged destination_coordinator",
            &self.destination_coordinator,
            MAX_ID_BYTES,
        )?;
        let grant = &self.prepared.payload.grant;
        if canonical_hash(self.prepared.as_ref())? != self.prepared_hash
            || self.prepared.payload.grant_hash != self.grant_hash
            || self.prepared.payload.checkpoint_hash != self.checkpoint_hash
            || grant.payload.destination_realm != self.destination_realm
            || grant.payload.destination_node != self.destination_node
        {
            return Err(ContractError::Invalid(
                "staging receipt does not bind the prepared proof, hashes, and destination".into(),
            ));
        }
        match (&self.prepared.payload.grant.payload.destination_rewrap, &self.rewrap_receipt) {
            (None, None) => {}
            (Some(_), Some(receipt)) => {
                verify_custody_rewrap_receipt(receipt, &self.prepared)?;
            }
            _ => {
                return Err(ContractError::Invalid(
                    "staging rewrap receipt must be present exactly when the custody grant declares rewrap"
                        .into(),
                ));
            }
        }
        ensure_message_bound(self)
    }
}

/// Verify a staging receipt and prove its signer is the root-authorized destination epoch key.
pub fn verify_custody_staged(
    record: &SignedRecordV1<CustodyStagedV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_HOME_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid custody-staged signature".into()));
    }
    let destination_key = &record
        .payload
        .prepared
        .payload
        .grant
        .payload
        .destination_operational_key
        .payload
        .operational_public_key;
    if &record.signer != destination_key {
        return Err(ContractError::Invalid(
            "custody-staged signer is not the root-authorized destination epoch key".into(),
        ));
    }
    Ok(())
}

/// Bounded proof that an epoch operational key descends from the Abode root.
///
/// Evidence referenced by the grant remains policy input. Only these signatures, the exact home,
/// monotone epoch, and an explicit capability establish protocol authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeAuthorityV1 {
    pub abode: SignedRecordV1<AbodeKeyBindingV1>,
    pub operational: SignedRecordV1<OperationalKeyGrantV1>,
    /// Source-fsynced custody proof for a moved epoch. Genesis epoch 1 omits it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prepared: Option<Box<SignedRecordV1<CustodyPreparedV1>>>,
}

impl HomeAuthorityV1 {
    pub fn verify(
        &self,
        home: &HomeId,
        epoch: u64,
        capability: OperationalCapabilityV1,
    ) -> Result<(), ContractError> {
        self.validate()?;
        let binding = &self.abode.payload;
        if &binding.abode != home || binding.root_public_key != home.0 {
            return Err(ContractError::Invalid(
                "Abode binding does not self-bind the requested home/root key".into(),
            ));
        }
        let grant = &self.operational.payload;
        if &grant.home != home || grant.epoch != epoch {
            return Err(ContractError::Invalid(
                "operational grant does not match requested home/epoch".into(),
            ));
        }
        if !grant.capabilities.contains(&capability) {
            return Err(ContractError::Invalid(format!(
                "operational grant lacks required `{capability:?}` capability"
            )));
        }
        Ok(())
    }
}

impl Validate for HomeAuthorityV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.abode.validate()?;
        self.operational.validate()?;
        if self.abode.schema != crate::SCHEMA_HOME_V1
            || self.operational.schema != crate::SCHEMA_HOME_V1
        {
            return Err(ContractError::Invalid(format!(
                "home authority records must both use `{}`",
                crate::SCHEMA_HOME_V1
            )));
        }
        if !self.abode.verify() || !self.operational.verify() {
            return Err(ContractError::Crypto(
                "home authority chain contains an invalid signature".into(),
            ));
        }
        let binding = &self.abode.payload;
        if self.abode.signer != binding.root_public_key
            || binding.abode.0 != binding.root_public_key
        {
            return Err(ContractError::Invalid(
                "Abode key binding must be self-signed by the Abode root".into(),
            ));
        }
        if self.operational.signer != binding.root_public_key {
            return Err(ContractError::Invalid(
                "operational key grant must be signed by the bound Abode root".into(),
            ));
        }
        let grant = &self.operational.payload;
        match (grant.epoch, &self.prepared) {
            (1, None) => {}
            (1, Some(_)) => {
                return Err(ContractError::Invalid(
                    "genesis Home authority must not carry a custody proof".into(),
                ));
            }
            (_, Some(prepared)) => {
                verify_custody_prepared(prepared)?;
                let custody = &prepared.payload.grant.payload;
                if custody.home != grant.home
                    || custody.to_epoch != grant.epoch
                    || custody.destination_operational_key != self.operational
                    || custody.source_authority.abode != self.abode
                {
                    return Err(ContractError::Invalid(
                        "Home authority does not continue its exact source-fsynced custody proof"
                            .into(),
                    ));
                }
            }
            (_, None) => {
                return Err(ContractError::Invalid(
                    "moved Home authority requires a source-fsynced custody proof".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeLeaseV1 {
    pub home: HomeId,
    pub epoch: u64,
    /// Claimed monotonic revision within the epoch. It may advance only to refresh the coordinator
    /// while every authority/custody/location binding remains identical.
    pub lease_sequence: u64,
    pub realm: String,
    pub node: String,
    pub coordinator: String,
    /// Root-authorized epoch key chain. The signed outer lease must use this operational key.
    pub authority: HomeAuthorityV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<HandoffId>,
    /// Exact root-signed custody proof for a moved (epoch > 1) location. Genesis leases have no
    /// handoff and no custody grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custody_grant: Option<Box<SignedRecordV1<CustodyGrantV1>>>,
    /// Canonical hash of the complete signed checkpoint record for this lease.
    pub checkpoint_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}

impl Validate for HomeLeaseV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        if self.epoch == 0 || self.lease_sequence == 0 {
            return Err(ContractError::Invalid(
                "home epoch and lease sequence must be non-zero".into(),
            ));
        }
        validate_text("home realm", &self.realm, MAX_ID_BYTES)?;
        validate_text("home node", &self.node, MAX_ID_BYTES)?;
        validate_text("home coordinator", &self.coordinator, MAX_ID_BYTES)?;
        self.authority.verify(&self.home, self.epoch, OperationalCapabilityV1::Locate)?;
        match (&self.handoff, &self.custody_grant) {
            (None, None) if self.epoch == 1 => {}
            (Some(handoff), Some(grant)) => {
                handoff.validate()?;
                verify_custody_grant(grant)?;
                if grant.payload.home != self.home
                    || grant.payload.to_epoch != self.epoch
                    || &grant.payload.handoff != handoff
                    || grant.payload.destination_realm != self.realm
                    || grant.payload.destination_node != self.node
                    || grant.payload.destination_operational_key != self.authority.operational
                    || grant.payload.source_authority.abode != self.authority.abode
                    || grant.payload.checkpoint_hash != self.checkpoint_hash
                    || self
                        .authority
                        .prepared
                        .as_ref()
                        .is_none_or(|prepared| prepared.payload.grant.as_ref() != grant.as_ref())
                {
                    return Err(ContractError::Invalid(
                        "home lease does not match its exact root-signed custody grant".into(),
                    ));
                }
            }
            _ => {
                return Err(ContractError::Invalid(
                    "genesis leases omit custody proof; moved leases require handoff and grant"
                        .into(),
                ));
            }
        }
        validate_sha256("checkpoint_hash", &self.checkpoint_hash)?;
        validate_expiry(self.issued_at_unix_ms, self.expires_at_unix_ms)
    }
}

/// Verify both a lease record signature and its embedded root-to-epoch authority chain.
pub fn verify_home_lease(record: &SignedRecordV1<HomeLeaseV1>) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_LOCATE_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid home lease signature".into()));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "home lease signer is not the authorized epoch operational key".into(),
        ));
    }
    Ok(())
}

/// Return whether `next` is the one same-epoch lease revision that may supersede `current`.
///
/// A restarted Home may have a new process-local coordinator, so that routing hint and a strictly
/// increasing sequence are mutable. Every authority-bearing or custody-bearing field remains
/// byte-for-byte fixed, as do the signed time observations. Callers must verify both outer records
/// before using this structural predicate.
pub fn is_home_lease_coordinator_revision(current: &HomeLeaseV1, next: &HomeLeaseV1) -> bool {
    next.lease_sequence > current.lease_sequence
        && next.home == current.home
        && next.epoch == current.epoch
        && next.realm == current.realm
        && next.node == current.node
        && next.authority == current.authority
        && next.handoff == current.handoff
        && next.custody_grant == current.custody_grant
        && next.checkpoint_hash == current.checkpoint_hash
        && next.issued_at_unix_ms == current.issued_at_unix_ms
        && next.expires_at_unix_ms == current.expires_at_unix_ms
}

/// Proof-bearing custody phase returned by the Home status protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum HomeCustodyPhaseV1 {
    /// Genesis has neither proof. A moved active Home carries both its staging receipt and lease.
    Active {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        staged: Option<Box<SignedRecordV1<CustodyStagedV1>>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        lease: Option<Box<SignedRecordV1<HomeLeaseV1>>>,
    },
    Frozen {
        prepared: Box<SignedRecordV1<CustodyPreparedV1>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        redirect: Option<Box<SignedRecordV1<HomeLeaseV1>>>,
    },
    Staged {
        staged: Box<SignedRecordV1<CustodyStagedV1>>,
    },
}

/// Signed, self-contained custody status fact. It is safe to cache but is not a policy decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeCustodyStatusV1 {
    pub home: HomeId,
    pub epoch: u64,
    pub authority: HomeAuthorityV1,
    pub state: HomeCustodyPhaseV1,
}

impl Validate for HomeCustodyStatusV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        if self.epoch == 0 {
            return Err(ContractError::Invalid("custody status epoch must be non-zero".into()));
        }
        self.authority.verify(&self.home, self.epoch, OperationalCapabilityV1::Custody)?;
        match &self.state {
            HomeCustodyPhaseV1::Active { staged: None, lease: None } if self.epoch == 1 => {}
            HomeCustodyPhaseV1::Active { staged: Some(staged), lease: Some(lease) } => {
                verify_custody_staged(staged)?;
                verify_home_lease(lease)?;
                let grant = &staged.payload.prepared.payload.grant.payload;
                if self.home != grant.home
                    || self.epoch != grant.to_epoch
                    || self.authority.operational != grant.destination_operational_key
                    || lease.payload.home != self.home
                    || lease.payload.epoch != self.epoch
                    || lease.payload.handoff.as_ref() != Some(&grant.handoff)
                    || lease.payload.checkpoint_hash != staged.payload.checkpoint_hash
                {
                    return Err(ContractError::Invalid(
                        "active custody status does not match its staged proof and lease".into(),
                    ));
                }
            }
            HomeCustodyPhaseV1::Frozen { prepared, redirect } => {
                verify_custody_prepared(prepared)?;
                let grant = &prepared.payload.grant.payload;
                if self.home != grant.home
                    || self.epoch != grant.from_epoch
                    || self.authority != grant.source_authority
                {
                    return Err(ContractError::Invalid(
                        "frozen custody status does not match its prepared proof".into(),
                    ));
                }
                if let Some(redirect) = redirect {
                    verify_home_lease(redirect)?;
                    if redirect.payload.home != self.home
                        || redirect.payload.epoch != grant.to_epoch
                        || redirect.payload.handoff.as_ref() != Some(&grant.handoff)
                        || redirect.payload.checkpoint_hash != prepared.payload.checkpoint_hash
                    {
                        return Err(ContractError::Invalid(
                            "frozen custody redirect does not match its prepared proof".into(),
                        ));
                    }
                }
            }
            HomeCustodyPhaseV1::Staged { staged } => {
                verify_custody_staged(staged)?;
                let grant = &staged.payload.prepared.payload.grant.payload;
                if self.home != grant.home
                    || self.epoch != grant.to_epoch
                    || self.authority.operational != grant.destination_operational_key
                {
                    return Err(ContractError::Invalid(
                        "staged custody status does not match its staging receipt".into(),
                    ));
                }
            }
            _ => {
                return Err(ContractError::Invalid(
                    "active genesis omits custody proofs; moved active status requires both".into(),
                ));
            }
        }
        ensure_message_bound(self)
    }
}

pub fn verify_home_custody_status(
    record: &SignedRecordV1<HomeCustodyStatusV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_HOME_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid home-custody status signature".into()));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "home-custody status signer is not its root-authorized epoch key".into(),
        ));
    }
    Ok(())
}

/// Verify an execution grant and prove its signer is the root-authorized home epoch key.
pub fn verify_execution_grant(
    record: &SignedRecordV1<ExecutionGrantV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_EXECUTE_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid execution grant signature".into()));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "execution grant signer is not the authorized epoch operational key".into(),
        ));
    }
    Ok(())
}

/// Verify the active Home endorsement without discarding the original caller provenance.
pub fn verify_execution_control(
    record: &SignedRecordV1<ExecutionControlV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_EXECUTE_V1 || !record.verify() {
        return Err(ContractError::Crypto(
            "invalid home-endorsed execution-control signature".into(),
        ));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "execution-control signer is not the authorized home epoch key".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeLocateV1 {
    pub home: HomeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_epoch: Option<u64>,
}

impl Validate for HomeLocateV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        if self.minimum_epoch == Some(0) {
            return Err(ContractError::Invalid("minimum epoch must be non-zero".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HomeLocationV1 {
    pub lease: SignedRecordV1<HomeLeaseV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at_unix_ms: Option<u64>,
}

impl Validate for HomeLocationV1 {
    fn validate(&self) -> Result<(), ContractError> {
        verify_home_lease(&self.lease)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventQueryV1 {
    pub handle: JobHandleV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_sequence: Option<u64>,
    pub limit: u16,
    /// Caller-selected nonce makes a signed page request independently attributable.
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobGetV1 {
    pub handle: JobHandleV1,
    /// Caller-selected nonce makes a signed read request independently attributable.
    pub nonce: String,
}

impl Validate for JobGetV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.handle.validate()?;
        validate_text("job read nonce", &self.nonce, MAX_ID_BYTES)
    }
}

impl Validate for EventQueryV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.handle.validate()?;
        validate_text("job event-read nonce", &self.nonce, MAX_ID_BYTES)?;
        if self.limit == 0 || usize::from(self.limit) > MAX_EVENT_PAGE_ITEMS {
            return Err(ContractError::Invalid(format!(
                "event query limit must be in 1..={MAX_EVENT_PAGE_ITEMS}"
            )));
        }
        Ok(())
    }
}

/// Trusted-relay endorsement binding an authorized caller's signed read to one exact Aether return
/// route. A relay is an injected trust decision; a captured caller request alone is not a bearer
/// capability for redirecting private job state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobGetRelayV1 {
    pub caller: SignedRecordV1<JobGetV1>,
    pub reply_to: String,
}

impl Validate for JobGetRelayV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.caller.validate()?;
        if self.caller.schema != crate::SCHEMA_JOB_V1 || !self.caller.verify() {
            return Err(ContractError::Crypto("invalid relayed job-read caller signature".into()));
        }
        validate_text("job read reply_to", &self.reply_to, MAX_ID_BYTES)?;
        ensure_message_bound(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventQueryRelayV1 {
    pub caller: SignedRecordV1<EventQueryV1>,
    pub reply_to: String,
}

impl Validate for EventQueryRelayV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.caller.validate()?;
        if self.caller.schema != crate::SCHEMA_JOB_V1 || !self.caller.verify() {
            return Err(ContractError::Crypto(
                "invalid relayed job-event-read caller signature".into(),
            ));
        }
        validate_text("job event read reply_to", &self.reply_to, MAX_ID_BYTES)?;
        ensure_message_bound(self)
    }
}

pub fn verify_job_get_relay(record: &SignedRecordV1<JobGetRelayV1>) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_JOB_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid job-read relay signature".into()));
    }
    Ok(())
}

pub fn verify_event_query_relay(
    record: &SignedRecordV1<EventQueryRelayV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_JOB_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid event-read relay signature".into()));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPageV1 {
    pub handle: JobHandleV1,
    pub events: Vec<SignedRecordV1<JobEventV1>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_after_sequence: Option<u64>,
}

impl Validate for EventPageV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.handle.validate()?;
        if self.events.len() > MAX_EVENT_PAGE_ITEMS {
            return Err(ContractError::Limit(format!(
                "event page has {} items, exceeds {MAX_EVENT_PAGE_ITEMS}",
                self.events.len()
            )));
        }
        for event in &self.events {
            verify_job_event(event)?;
            if event.payload.handle != self.handle {
                return Err(ContractError::Invalid(
                    "event page contains an event for a different job".into(),
                ));
            }
        }
        ensure_message_bound(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobSnapshotResponseV1 {
    /// Canonical hash of the complete signed relay request this response answers.
    pub request_hash: String,
    pub snapshot: Box<SignedRecordV1<JobSnapshotV1>>,
}

impl Validate for JobSnapshotResponseV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_sha256("job snapshot response request_hash", &self.request_hash)?;
        verify_job_snapshot(&self.snapshot)?;
        ensure_message_bound(self)
    }
}

pub fn verify_job_snapshot_response(
    record: &SignedRecordV1<JobSnapshotResponseV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_JOB_V1
        || !record.verify()
        || record.signer != record.payload.snapshot.signer
    {
        return Err(ContractError::Crypto("invalid job snapshot response signature".into()));
    }
    Ok(())
}

/// Verify a snapshot response and bind it to the complete signed relay request that elicited it.
///
/// The outer relay signature covers both the caller's independently signed request and the exact
/// Aether return route. Comparing its canonical hash here prevents a correctly signed response for
/// one route/nonce from being accepted for another read.
pub fn verify_job_snapshot_response_for(
    record: &SignedRecordV1<JobSnapshotResponseV1>,
    request: &SignedRecordV1<JobGetRelayV1>,
) -> Result<(), ContractError> {
    verify_job_get_relay(request)?;
    verify_job_snapshot_response(record)?;
    if record.payload.request_hash != crate::canonical_hash(request)? {
        return Err(ContractError::Invalid(
            "job snapshot response does not bind the exact signed relay request".into(),
        ));
    }
    if record.payload.snapshot.payload.spec.handle != request.payload.caller.payload.handle {
        return Err(ContractError::Invalid(
            "job snapshot response belongs to a different Job handle".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventPageResponseV1 {
    /// Canonical hash of the complete signed relay request this response answers.
    pub request_hash: String,
    pub home_epoch: u64,
    pub authority: HomeAuthorityV1,
    pub page: EventPageV1,
}

impl Validate for EventPageResponseV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_sha256("event page response request_hash", &self.request_hash)?;
        self.authority.verify(
            &self.page.handle.home,
            self.home_epoch,
            OperationalCapabilityV1::JobHome,
        )?;
        self.page.validate()?;
        ensure_message_bound(self)
    }
}

pub fn verify_event_page_response(
    record: &SignedRecordV1<EventPageResponseV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_JOB_V1
        || !record.verify()
        || record.signer != record.payload.authority.operational.payload.operational_public_key
    {
        return Err(ContractError::Crypto("invalid event page response signature".into()));
    }
    Ok(())
}

/// Verify an event-page response against the complete signed relay request it answers.
pub fn verify_event_page_response_for(
    record: &SignedRecordV1<EventPageResponseV1>,
    request: &SignedRecordV1<EventQueryRelayV1>,
) -> Result<(), ContractError> {
    verify_event_query_relay(request)?;
    verify_event_page_response(record)?;
    if record.payload.request_hash != crate::canonical_hash(request)? {
        return Err(ContractError::Invalid(
            "event page response does not bind the exact signed relay request".into(),
        ));
    }
    if record.payload.page.handle != request.payload.caller.payload.handle {
        return Err(ContractError::Invalid(
            "event page response belongs to a different Job handle".into(),
        ));
    }
    let query = &request.payload.caller.payload;
    if record.payload.page.events.len() > usize::from(query.limit) {
        return Err(ContractError::Limit(format!(
            "event page has {} items, exceeds requested limit {}",
            record.payload.page.events.len(),
            query.limit
        )));
    }
    let mut previous = query.after_sequence.unwrap_or(0);
    for event in &record.payload.page.events {
        let expected = previous.checked_add(1).ok_or_else(|| {
            ContractError::Invalid("event page continues beyond the sequence domain".into())
        })?;
        if event.payload.sequence != expected {
            return Err(ContractError::Invalid(format!(
                "event page sequence {} is not the next sequence after {previous}",
                event.payload.sequence
            )));
        }
        previous = event.payload.sequence;
    }
    match record.payload.page.next_after_sequence {
        Some(cursor) if record.payload.page.events.is_empty() => {
            return Err(ContractError::Invalid(format!(
                "empty event page carries continuation cursor {cursor}"
            )));
        }
        Some(cursor) if cursor != previous => {
            return Err(ContractError::Invalid(format!(
                "event page continuation cursor {cursor} does not name its last event {previous}"
            )));
        }
        _ => {}
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtocolErrorV1 {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub retryable: bool,
}

/// Policy question: select one exact live deployment from a bounded candidate set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementQuestionV1 {
    pub job: JobHandleV1,
    pub home_epoch: u64,
    /// Root-to-epoch proof for the Home key signing this exact policy question.
    pub authority: HomeAuthorityV1,
    pub function: FunctionId,
    pub candidates: Vec<SignedRecordV1<DeploymentReceiptV1>>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for PlacementQuestionV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.job.validate()?;
        if self.home_epoch == 0 {
            return Err(ContractError::Invalid(
                "placement-question Home epoch must be non-zero".into(),
            ));
        }
        self.authority.verify(&self.job.home, self.home_epoch, OperationalCapabilityV1::JobHome)?;
        self.function.validate()?;
        if self.candidates.is_empty() || self.candidates.len() > MAX_EVENT_PAGE_ITEMS {
            return Err(ContractError::Limit(format!(
                "placement candidates must contain 1..={MAX_EVENT_PAGE_ITEMS} records"
            )));
        }
        for candidate in &self.candidates {
            verify_deployment_receipt(candidate)?;
            if candidate.payload.function != self.function {
                return Err(ContractError::Invalid(
                    "placement candidate pins a different function".into(),
                ));
            }
        }
        validate_vec("placement evidence", &self.evidence, MAX_EVIDENCE_REFS)
    }
}

/// Verify that a placement question was signed by the exact root-authorized Home epoch key it
/// carries. A transport sender or correlation id is never policy authority.
pub fn verify_placement_question(
    record: &SignedRecordV1<PlacementQuestionV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_POLICY_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid placement-question signature".into()));
    }
    if record.signer != record.payload.authority.operational.payload.operational_public_key {
        return Err(ContractError::Invalid(
            "placement-question signer is not the root-authorized Home epoch key".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementDecisionV1 {
    pub job: JobHandleV1,
    /// Canonical hash of the complete signed placement question, including its Home signature.
    pub question_hash: String,
    pub selected: DeploymentId,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for PlacementDecisionV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.job.validate()?;
        validate_sha256("placement decision question_hash", &self.question_hash)?;
        self.selected.validate()?;
        validate_vec("placement decision evidence", &self.evidence, MAX_EVIDENCE_REFS)
    }
}

/// Policy question after one terminal attempt receipt. The policy chooses retry versus stop; the
/// contract does not encode scoring, backoff, trust, or retention criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryQuestionV1 {
    pub snapshot: JobSnapshotV1,
    pub failed_attempt: AttemptId,
    pub failure: ValueRefV1,
    pub executor_retryable_hint: bool,
    pub candidates: Vec<SignedRecordV1<DeploymentReceiptV1>>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for RetryQuestionV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.snapshot.validate()?;
        self.failed_attempt.validate()?;
        if self.snapshot.state != JobStateV1::RetryPending {
            return Err(ContractError::Invalid(
                "retry question snapshot must be retry_pending".into(),
            ));
        }
        if self.failed_attempt.home != self.snapshot.spec.handle.home
            || self.failed_attempt.job != self.snapshot.spec.handle.job
            || self.snapshot.current_attempt.as_ref() != Some(&self.failed_attempt)
        {
            return Err(ContractError::Invalid(
                "retry question failed attempt does not match the snapshot's current job attempt"
                    .into(),
            ));
        }
        self.failure.validate_with_limit(MAX_ERROR_BYTES)?;
        if self.candidates.len() > MAX_EVENT_PAGE_ITEMS {
            return Err(ContractError::Limit(format!(
                "retry candidates exceed {MAX_EVENT_PAGE_ITEMS}"
            )));
        }
        for candidate in &self.candidates {
            verify_deployment_receipt(candidate)?;
            if candidate.payload.function != self.snapshot.spec.function.function {
                return Err(ContractError::Invalid(
                    "retry candidate pins a different immutable function".into(),
                ));
            }
        }
        validate_vec("retry evidence", &self.evidence, MAX_EVIDENCE_REFS)
    }
}

/// Verify that a retry question was signed by the exact root-authorized Home epoch key asserted
/// by its durable snapshot.
pub fn verify_retry_question(
    record: &SignedRecordV1<RetryQuestionV1>,
) -> Result<(), ContractError> {
    record.validate()?;
    if record.schema != crate::SCHEMA_POLICY_V1 || !record.verify() {
        return Err(ContractError::Crypto("invalid retry-question signature".into()));
    }
    if record.signer != record.payload.snapshot.authority.operational.payload.operational_public_key
    {
        return Err(ContractError::Invalid(
            "retry-question signer is not the root-authorized Home epoch key".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RetryDecisionV1 {
    Retry {
        /// Canonical hash of the complete signed retry question.
        question_hash: String,
        job: JobHandleV1,
        failed_attempt: AttemptId,
        next_attempt: AttemptId,
        deployment: Box<SignedRecordV1<DeploymentReceiptV1>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        not_before_unix_ms: Option<u64>,
    },
    Stop {
        /// Canonical hash of the complete signed retry question.
        question_hash: String,
        /// Explicit binding prevents a Stop response being applied to a job selected by corr.
        job: JobHandleV1,
        failed_attempt: AttemptId,
        terminal_state: JobStateV1,
        reason: String,
    },
}

impl Validate for RetryDecisionV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Retry {
                question_hash, job, failed_attempt, next_attempt, deployment, ..
            } => {
                validate_sha256("retry decision question_hash", question_hash)?;
                job.validate()?;
                failed_attempt.validate()?;
                next_attempt.validate()?;
                if failed_attempt.home != job.home
                    || failed_attempt.job != job.job
                    || next_attempt.home != job.home
                    || next_attempt.job != job.job
                    || next_attempt.number != failed_attempt.number.saturating_add(1)
                {
                    return Err(ContractError::Invalid(
                        "retry decision attempt lineage does not match its explicit job".into(),
                    ));
                }
                verify_deployment_receipt(deployment)
            }
            Self::Stop { question_hash, job, failed_attempt, terminal_state, reason } => {
                validate_sha256("retry decision question_hash", question_hash)?;
                job.validate()?;
                failed_attempt.validate()?;
                if failed_attempt.home != job.home || failed_attempt.job != job.job {
                    return Err(ContractError::Invalid(
                        "retry stop failed attempt does not belong to its explicit job".into(),
                    ));
                }
                if !terminal_state.is_terminal() {
                    return Err(ContractError::Invalid(
                        "retry stop decision must name a terminal state".into(),
                    ));
                }
                validate_text("retry stop reason", reason, MAX_REASON_BYTES)
            }
        }
    }
}

impl Validate for ProtocolErrorV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text("error code", &self.code, MAX_NAME_BYTES)?;
        validate_text("error message", &self.message, MAX_REASON_BYTES)
    }
}

// Application union types keep each Envelope schema stable while operations grow additively.

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum FunctionDeployMessageV1 {
    Resolve { request: SignedRecordV1<ResolveRequestV1> },
    Resolved { receipt: SignedRecordV1<crate::ResolutionReceiptV1> },
    Register { request: Box<SignedRecordV1<DeploymentRegistrationV1>> },
    Registered { receipt: SignedRecordV1<DeploymentReceiptV1> },
    Lookup { query: DeploymentQueryV1 },
    Deployments { list: DeploymentListV1 },
    Undeploy { request: SignedRecordV1<UndeployRequestV1> },
    Undeployed { receipt: SignedRecordV1<UndeployReceiptV1> },
    Error { error: ProtocolErrorV1 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum JobMessageV1 {
    Submit {
        request: Box<SignedRecordV1<JobSubmitV1>>,
        resolution: Box<SignedRecordV1<crate::ResolutionReceiptV1>>,
        deployment: Box<SignedRecordV1<DeploymentReceiptV1>>,
    },
    Accepted {
        handle: JobHandleV1,
        request_hash: String,
        /// The exact fsynced Submitted event; this is the durable acceptance proof.
        submitted: Box<SignedRecordV1<JobEventV1>>,
    },
    Get {
        request: Box<SignedRecordV1<JobGetRelayV1>>,
    },
    Snapshot {
        response: Box<SignedRecordV1<JobSnapshotResponseV1>>,
    },
    Events {
        request: Box<SignedRecordV1<EventQueryRelayV1>>,
    },
    EventPage {
        response: Box<SignedRecordV1<EventPageResponseV1>>,
    },
    Control {
        request: Box<SignedRecordV1<JobControlV1>>,
    },
    ControlAccepted {
        /// Canonical hash of the complete signed [`JobControlV1`] request.
        request_hash: String,
        /// The exact durable Home-signed event produced (or recovered by idempotent replay).
        event: Box<SignedRecordV1<JobEventV1>>,
    },
    Event {
        event: Box<SignedRecordV1<JobEventV1>>,
    },
    Error {
        error: ProtocolErrorV1,
    },
}

pub fn verify_job_acceptance(
    handle: &JobHandleV1,
    request_hash: &str,
    submitted: &SignedRecordV1<JobEventV1>,
) -> Result<(), ContractError> {
    handle.validate()?;
    validate_sha256("accepted request_hash", request_hash)?;
    verify_job_event(submitted)?;
    let JobEventKindV1::Submitted { spec } = &submitted.payload.kind else {
        return Err(ContractError::Invalid("job acceptance proof is not a Submitted event".into()));
    };
    if &submitted.payload.handle != handle
        || &spec.handle != handle
        || spec.request_hash != request_hash
        || submitted.payload.sequence != 1
        || submitted.payload.state_after != JobStateV1::Queued
    {
        return Err(ContractError::Invalid(
            "job acceptance proof does not match handle/request/state".into(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ExecuteMessageV1 {
    Grant { grant: Box<SignedRecordV1<ExecutionGrantV1>> },
    Receipt { receipt: Box<SignedRecordV1<ExecutionReceiptV1>> },
    Query { request: Box<SignedRecordV1<ExecutionQueryV1>> },
    Control { request: Box<SignedRecordV1<ExecutionControlV1>> },
    Error { error: ProtocolErrorV1 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum FunctionCallMessageV1 {
    Call {
        call: Box<FunctionCallV1>,
    },
    Result {
        result: FunctionResultV1,
    },
    /// Cooperative target observation. The executor authenticates the envelope sender against the
    /// pinned deployment, persists an executor-signed receipt, then forwards it to the Home.
    Progress {
        attempt: AttemptId,
        sequence: u64,
        progress: ValueRefV1,
    },
    /// Cooperative resumability material, subject to the same target authentication as progress.
    Checkpoint {
        attempt: AttemptId,
        sequence: u64,
        checkpoint: ValueRefV1,
    },
    Control {
        control: Box<FunctionControlV1>,
    },
    ControlResult {
        attempt: AttemptId,
        control: ControlId,
        disposition: ControlDispositionV1,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        detail: Option<String>,
    },
}

impl Validate for FunctionCallMessageV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Call { call } => call.validate()?,
            Self::Result { result } => result.validate()?,
            Self::Progress { attempt, sequence, progress } => {
                attempt.validate()?;
                if *sequence == 0 {
                    return Err(ContractError::Invalid(
                        "function progress sequence must be non-zero".into(),
                    ));
                }
                progress.validate_with_limit(MAX_PROGRESS_BYTES)?;
            }
            Self::Checkpoint { attempt, sequence, checkpoint } => {
                attempt.validate()?;
                if *sequence == 0 {
                    return Err(ContractError::Invalid(
                        "function checkpoint sequence must be non-zero".into(),
                    ));
                }
                checkpoint.validate()?;
            }
            Self::Control { control } => control.validate()?,
            Self::ControlResult { attempt, control, detail, .. } => {
                attempt.validate()?;
                control.validate()?;
                validate_optional_text(
                    "function control result detail",
                    detail.as_deref(),
                    MAX_REASON_BYTES,
                )?;
            }
        }
        ensure_message_bound(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum HomeMessageV1 {
    Prepare {
        grant: Box<SignedRecordV1<CustodyGrantV1>>,
        checkpoint: Box<SignedRecordV1<HomeCheckpointV1>>,
    },
    Prepared {
        prepared: Box<SignedRecordV1<CustodyPreparedV1>>,
    },
    Stage {
        prepared: Box<SignedRecordV1<CustodyPreparedV1>>,
    },
    Staged {
        staged: Box<SignedRecordV1<CustodyStagedV1>>,
    },
    Activate {
        staged: Box<SignedRecordV1<CustodyStagedV1>>,
    },
    Activated {
        lease: Box<SignedRecordV1<HomeLeaseV1>>,
    },
    Status {
        home: HomeId,
    },
    StatusResult {
        status: Box<SignedRecordV1<HomeCustodyStatusV1>>,
    },
    Error {
        error: ProtocolErrorV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum LocateMessageV1 {
    Locate { query: HomeLocateV1 },
    Announce { lease: SignedRecordV1<HomeLeaseV1> },
    Location { location: HomeLocationV1 },
    NotFound { home: HomeId },
    Conflict { home: HomeId, epoch: u64, leases: Vec<SignedRecordV1<HomeLeaseV1>> },
    Error { error: ProtocolErrorV1 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PolicyMessageV1 {
    SelectDeployment { question: Box<SignedRecordV1<PlacementQuestionV1>> },
    DeploymentSelected { decision: Box<SignedRecordV1<PlacementDecisionV1>> },
    DecideRetry { question: Box<SignedRecordV1<RetryQuestionV1>> },
    RetryDecided { decision: Box<SignedRecordV1<RetryDecisionV1>> },
    Error { error: ProtocolErrorV1 },
}

impl<T: Serialize + Validate> Validate for SignedRecordV1<T> {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text("signed record schema", &self.schema, MAX_ID_BYTES)?;
        validate_text("signed record signer", &self.signer, crate::MAX_PUBLIC_KEY_BYTES)?;
        validate_text("signed record signature", &self.signature, crate::MAX_SIGNATURE_BYTES)?;
        self.payload.validate()?;
        ensure_message_bound(self)
    }
}

fn ensure_message_bound<T: Serialize>(value: &T) -> Result<(), ContractError> {
    let len = crate::canonical_json_bytes(value)?.len();
    if len > MAX_JOB_MESSAGE_BYTES {
        Err(ContractError::Limit(format!(
            "wire message is {len} bytes, exceeds {MAX_JOB_MESSAGE_BYTES}"
        )))
    } else {
        Ok(())
    }
}
