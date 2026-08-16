//! `policy-job-basic` — a deliberately dull reference filling for the Function policy socket.
//!
//! It chooses a cryptographically intact exact-function deployment by stable lexical order and
//! retries only when the caller selected at-least-once, the executor marked the failure retryable,
//! the attempt budget remains, and another valid candidate exists. Evidence is preserved by the
//! contract but ignored here: a smarter AI/reputation creature can replace this model on the same
//! role and wire. It signs no answer until the exact question is signed by its root-authorized Home
//! epoch key, and every answer hash-binds that complete signed question.

#![forbid(unsafe_code)]

use std::sync::Arc;

use aether::{Creature, CreatureCtx, Dispatch, Envelope, Outcome};
use gawdfn::{
    canonical_hash, verify_placement_question, verify_retry_question, AttemptId, AuthoritySigner,
    DeliveryModeV1, JobHandleV1, JobStateV1, PlacementDecisionV1, PlacementQuestionV1,
    PolicyMessageV1, ProtocolErrorV1, RetryDecisionV1, RetryQuestionV1, SignedRecordV1, Validate,
    MAX_JOB_MESSAGE_BYTES, MAX_REASON_BYTES, SCHEMA_POLICY_V1,
};
use thiserror::Error;

pub const DEFAULT_MAX_POLICY_CANDIDATES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BasicPolicyCaps {
    pub max_candidates: usize,
}

impl Default for BasicPolicyCaps {
    fn default() -> Self {
        Self { max_candidates: DEFAULT_MAX_POLICY_CANDIDATES }
    }
}

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid policy question: {0}")]
    Invalid(String),
    #[error("policy candidate limit exceeded: {actual} > {limit}")]
    CandidateLimit { actual: usize, limit: usize },
    #[error("no cryptographically valid exact-function deployment candidate")]
    NoCandidate,
    #[error("cannot sign policy decision: {0}")]
    Signing(String),
}

pub struct BasicJobPolicy {
    signer: Arc<dyn AuthoritySigner>,
    caps: BasicPolicyCaps,
}

impl BasicJobPolicy {
    pub fn new(
        signer: Arc<dyn AuthoritySigner>,
        caps: BasicPolicyCaps,
    ) -> Result<Self, PolicyError> {
        if caps.max_candidates == 0 {
            return Err(PolicyError::Invalid("max_candidates must be non-zero".into()));
        }
        Ok(Self { signer, caps })
    }

    pub fn select(
        &self,
        question: SignedRecordV1<PlacementQuestionV1>,
    ) -> Result<SignedRecordV1<PlacementDecisionV1>, PolicyError> {
        verify_placement_question(&question).map_err(invalid)?;
        self.check_count(question.payload.candidates.len())?;
        let question_hash = canonical_hash(&question).map_err(invalid)?;
        let selected =
            choose_candidate(&question.payload.candidates).ok_or(PolicyError::NoCandidate)?;
        let decision = PlacementDecisionV1 {
            job: question.payload.job,
            question_hash,
            selected: selected.payload.deployment.clone(),
            // Input evidence is not automatically promoted into an authority-bearing decision.
            evidence: vec![],
        };
        SignedRecordV1::sign(SCHEMA_POLICY_V1, decision, self.signer.as_ref())
            .map_err(|error| PolicyError::Signing(error.to_string()))
    }

    pub fn decide_retry(
        &self,
        question: SignedRecordV1<RetryQuestionV1>,
    ) -> Result<SignedRecordV1<RetryDecisionV1>, PolicyError> {
        verify_retry_question(&question).map_err(invalid)?;
        self.check_count(question.payload.candidates.len())?;
        let question_hash = canonical_hash(&question).map_err(invalid)?;
        let payload = &question.payload;
        let job = payload.snapshot.spec.handle.clone();
        let failed_attempt = payload.failed_attempt.clone();
        let decision = if payload.snapshot.cancel_requested {
            stop(
                question_hash,
                job,
                failed_attempt,
                JobStateV1::Cancelled,
                "cancellation is already requested",
            )
        } else if payload.snapshot.state.is_terminal() {
            stop(
                question_hash,
                job,
                failed_attempt,
                payload.snapshot.state,
                "job is already terminal",
            )
        } else {
            match payload.snapshot.spec.delivery {
                DeliveryModeV1::AtMostOnce => stop(
                    question_hash,
                    job,
                    failed_attempt,
                    JobStateV1::Failed,
                    "at-most-once does not authorize another attempt",
                ),
                DeliveryModeV1::AtLeastOnce { .. } if !payload.executor_retryable_hint => stop(
                    question_hash,
                    job,
                    failed_attempt,
                    JobStateV1::Failed,
                    "executor classified the failure as non-retryable",
                ),
                DeliveryModeV1::AtLeastOnce { max_attempts }
                    if payload.failed_attempt.number >= max_attempts =>
                {
                    stop(
                        question_hash,
                        job,
                        failed_attempt,
                        JobStateV1::Failed,
                        "at-least-once attempt budget is exhausted",
                    )
                }
                DeliveryModeV1::AtLeastOnce { .. } => {
                    let selected =
                        choose_candidate(&payload.candidates).ok_or(PolicyError::NoCandidate)?;
                    RetryDecisionV1::Retry {
                        question_hash,
                        job,
                        failed_attempt: failed_attempt.clone(),
                        next_attempt: AttemptId {
                            home: failed_attempt.home,
                            job: failed_attempt.job,
                            number: failed_attempt.number.saturating_add(1),
                        },
                        deployment: Box::new(selected.clone()),
                        not_before_unix_ms: None,
                    }
                }
            }
        };
        decision.validate().map_err(invalid)?;
        SignedRecordV1::sign(SCHEMA_POLICY_V1, decision, self.signer.as_ref())
            .map_err(|error| PolicyError::Signing(error.to_string()))
    }

    fn check_count(&self, actual: usize) -> Result<(), PolicyError> {
        if actual > self.caps.max_candidates {
            Err(PolicyError::CandidateLimit { actual, limit: self.caps.max_candidates })
        } else {
            Ok(())
        }
    }
}

impl Creature for BasicJobPolicy {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA_POLICY_V1 || env.payload.len() > MAX_JOB_MESSAGE_BYTES {
            return Outcome::none();
        }
        let message = match serde_json::from_slice::<PolicyMessageV1>(&env.payload) {
            Ok(message) => message,
            Err(_) => {
                return reply(&env, policy_error("invalid_message", "cannot decode policy message"))
            }
        };
        let response = match message {
            PolicyMessageV1::SelectDeployment { question } => match self.select(*question) {
                Ok(decision) => {
                    PolicyMessageV1::DeploymentSelected { decision: Box::new(decision) }
                }
                Err(error) => policy_error("selection_rejected", &error.to_string()),
            },
            PolicyMessageV1::DecideRetry { question } => match self.decide_retry(*question) {
                Ok(decision) => PolicyMessageV1::RetryDecided { decision: Box::new(decision) },
                Err(error) => policy_error("retry_rejected", &error.to_string()),
            },
            PolicyMessageV1::DeploymentSelected { .. }
            | PolicyMessageV1::RetryDecided { .. }
            | PolicyMessageV1::Error { .. } => return Outcome::none(),
        };
        reply(&env, response)
    }
}

fn choose_candidate(
    candidates: &[SignedRecordV1<gawdfn::DeploymentReceiptV1>],
) -> Option<&SignedRecordV1<gawdfn::DeploymentReceiptV1>> {
    candidates
        .iter()
        .filter(|candidate| gawdfn::verify_deployment_receipt(candidate).is_ok())
        .min_by_key(|candidate| {
            let payload = &candidate.payload;
            (
                payload.realm.as_str(),
                payload.node.as_str(),
                payload.executor.as_str(),
                payload.creature.as_str(),
                payload.deployment.as_str(),
            )
        })
}

fn stop(
    question_hash: String,
    job: JobHandleV1,
    failed_attempt: AttemptId,
    state: JobStateV1,
    reason: &str,
) -> RetryDecisionV1 {
    RetryDecisionV1::Stop {
        question_hash,
        job,
        failed_attempt,
        terminal_state: state,
        reason: reason.to_string(),
    }
}

fn invalid(error: gawdfn::ContractError) -> PolicyError {
    PolicyError::Invalid(error.to_string())
}

fn policy_error(code: &str, reason: &str) -> PolicyMessageV1 {
    let mut message = reason.to_string();
    if message.len() > MAX_REASON_BYTES {
        let mut end = MAX_REASON_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    PolicyMessageV1::Error {
        error: ProtocolErrorV1 { code: code.to_string(), message, retryable: false },
    }
}

fn reply(env: &Envelope, message: PolicyMessageV1) -> Outcome {
    let payload = serde_json::to_vec(&message).unwrap_or_default();
    Outcome::send(Dispatch::reply_to_env(env, payload).with_schema(SCHEMA_POLICY_V1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use gawdfn::{
        AbodeKeyBindingV1, AuthoritySigner, DeploymentId, DeploymentReceiptV1, Ed25519SeedSigner,
        FunctionId, FunctionSelectorV1, HomeAuthorityV1, HomeId, JobAccessV1, JobHandleV1, JobId,
        JobSnapshotV1, JobSpecV1, OperationalCapabilityV1, OperationalKeyGrantV1,
        ResolvedFunctionV1, ValueRefV1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1,
    };
    use serde_json::json;

    fn hash(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    fn signed_deployment(
        signer: &Ed25519SeedSigner,
        function: &FunctionId,
        deployment: &str,
        node: &str,
    ) -> SignedRecordV1<DeploymentReceiptV1> {
        SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentReceiptV1 {
                deployment: DeploymentId::new(deployment),
                function: function.clone(),
                artifact_hash: hash('b'),
                realm: "realm-a".into(),
                node: node.into(),
                executor: signer.public_key().to_string(),
                executor_creature: "7".into(),
                creature: "42".into(),
                evidence: vec![],
                registered_at_unix_ms: None,
            },
            signer,
        )
        .unwrap()
    }

    fn fixture(
    ) -> (Arc<Ed25519SeedSigner>, FunctionId, JobHandleV1, SignedRecordV1<DeploymentReceiptV1>)
    {
        let signer = Arc::new(Ed25519SeedSigner::from_seed([21; 32]).unwrap());
        let home_root = Ed25519SeedSigner::from_seed([22; 32]).unwrap();
        let function = FunctionId { manifest_content_address: hash('a'), entrypoint: "run".into() };
        let job = JobHandleV1 { home: HomeId::new(home_root.public_key()), job: JobId::new("job") };
        let deployment = signed_deployment(&signer, &function, "dep-1", "node-a");
        (signer, function, job, deployment)
    }

    #[test]
    fn selection_is_stable_and_ignores_inert_evidence() {
        let (signer, function, job, dep_b) = fixture();
        let dep_a = signed_deployment(&signer, &function, "dep-2", "node-0");
        let policy = BasicJobPolicy::new(signer, BasicPolicyCaps::default()).unwrap();
        let home_signer = Ed25519SeedSigner::from_seed([23; 32]).unwrap();
        let question = SignedRecordV1::sign(
            SCHEMA_POLICY_V1,
            PlacementQuestionV1 {
                home_epoch: 1,
                authority: snapshot_authority(&job.home),
                job,
                function,
                candidates: vec![dep_b, dep_a.clone()],
                evidence: vec![],
            },
            &home_signer,
        )
        .unwrap();
        let question_hash = canonical_hash(&question).unwrap();
        let decision = policy.select(question).unwrap();
        assert!(decision.verify());
        assert_eq!(decision.payload.question_hash, question_hash);
        assert_eq!(decision.payload.selected, dep_a.payload.deployment);
        assert!(decision.payload.evidence.is_empty());
    }

    #[test]
    fn refuses_unsigned_wrong_home_and_tampered_questions_instead_of_signing_oracle_output() {
        let (policy_signer, function, job, deployment) = fixture();
        let policy = BasicJobPolicy::new(policy_signer, BasicPolicyCaps::default()).unwrap();
        let home_signer = Ed25519SeedSigner::from_seed([23; 32]).unwrap();
        let attacker = Ed25519SeedSigner::from_seed([99; 32]).unwrap();
        let payload = PlacementQuestionV1 {
            home_epoch: 1,
            authority: snapshot_authority(&job.home),
            job,
            function,
            candidates: vec![deployment],
            evidence: vec![],
        };

        let wrong_signer =
            SignedRecordV1::sign(SCHEMA_POLICY_V1, payload.clone(), &attacker).unwrap();
        assert!(matches!(policy.select(wrong_signer), Err(PolicyError::Invalid(_))));

        let mut tampered = SignedRecordV1::sign(SCHEMA_POLICY_V1, payload, &home_signer).unwrap();
        tampered.payload.evidence.push(gawdfn::EvidenceRefV1 {
            kind: "post-signature-score".into(),
            digest: hash('f'),
            issuer: None,
            locator: None,
        });
        assert!(matches!(policy.select(tampered), Err(PolicyError::Invalid(_))));
    }

    #[test]
    fn at_most_once_never_retries() {
        let (signer, function, job, deployment) = fixture();
        let policy = BasicJobPolicy::new(signer, BasicPolicyCaps::default()).unwrap();
        let snapshot = snapshot(job, function, deployment.clone(), DeliveryModeV1::AtMostOnce);
        let home_signer = Ed25519SeedSigner::from_seed([23; 32]).unwrap();
        let decision = policy
            .decide_retry(
                SignedRecordV1::sign(
                    SCHEMA_POLICY_V1,
                    RetryQuestionV1 {
                        failed_attempt: AttemptId {
                            home: snapshot.spec.handle.home.clone(),
                            job: JobId::new("job"),
                            number: 1,
                        },
                        snapshot,
                        failure: ValueRefV1::Inline { value: json!({"error":"lost"}) },
                        executor_retryable_hint: true,
                        candidates: vec![deployment],
                        evidence: vec![],
                    },
                    &home_signer,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            decision.payload,
            RetryDecisionV1::Stop {
                job,
                failed_attempt,
                terminal_state: JobStateV1::Failed,
                ..
            } if job.job == failed_attempt.job && job.home == failed_attempt.home
        ));
    }

    #[test]
    fn at_least_once_advances_an_attributable_attempt() {
        let (signer, function, job, deployment) = fixture();
        let policy = BasicJobPolicy::new(signer, BasicPolicyCaps::default()).unwrap();
        let snapshot = snapshot(
            job,
            function,
            deployment.clone(),
            DeliveryModeV1::AtLeastOnce { max_attempts: 3 },
        );
        let home_signer = Ed25519SeedSigner::from_seed([23; 32]).unwrap();
        let decision = policy
            .decide_retry(
                SignedRecordV1::sign(
                    SCHEMA_POLICY_V1,
                    RetryQuestionV1 {
                        failed_attempt: AttemptId {
                            home: snapshot.spec.handle.home.clone(),
                            job: JobId::new("job"),
                            number: 1,
                        },
                        snapshot,
                        failure: ValueRefV1::Inline { value: json!({"error":"temporary"}) },
                        executor_retryable_hint: true,
                        candidates: vec![deployment],
                        evidence: vec![],
                    },
                    &home_signer,
                )
                .unwrap(),
            )
            .unwrap();
        assert!(matches!(
            decision.payload,
            RetryDecisionV1::Retry { next_attempt: AttemptId { number: 2, .. }, .. }
        ));
    }

    fn snapshot(
        handle: JobHandleV1,
        function: FunctionId,
        deployment: SignedRecordV1<DeploymentReceiptV1>,
        delivery: DeliveryModeV1,
    ) -> JobSnapshotV1 {
        let authority = snapshot_authority(&handle.home);
        let attempt_home = handle.home.clone();
        JobSnapshotV1 {
            spec: JobSpecV1 {
                root: handle.clone(),
                handle,
                caller_idempotency_key: "key".into(),
                request_hash: hash('c'),
                function: ResolvedFunctionV1 {
                    requested: FunctionSelectorV1::Id { function: function.clone() },
                    function,
                    artifact_hash: hash('b'),
                    resolution: None,
                },
                deployment,
                input: ValueRefV1::Inline { value: json!({}) },
                delivery,
                allow_duplicate_effects: false,
                parent: None,
                causal: vec![],
                access: JobAccessV1::default(),
                evidence: vec![],
                result_recipients: vec![],
                accepted_at_unix_ms: None,
            },
            state: JobStateV1::RetryPending,
            cancel_requested: false,
            home_epoch: 1,
            last_sequence: 1,
            current_attempt: Some(AttemptId {
                home: attempt_home,
                job: JobId::new("job"),
                number: 1,
            }),
            result: None,
            error: None,
            authority,
        }
    }

    fn snapshot_authority(home: &HomeId) -> HomeAuthorityV1 {
        let root = Ed25519SeedSigner::from_seed([22; 32]).unwrap();
        let operational = Ed25519SeedSigner::from_seed([23; 32]).unwrap();
        assert_eq!(home.as_str(), root.public_key());
        let abode = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            AbodeKeyBindingV1 {
                abode: home.clone(),
                root_public_key: root.public_key().into(),
                issued_at_unix_ms: None,
            },
            &root,
        )
        .unwrap();
        let operational = SignedRecordV1::sign(
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
        .unwrap();
        HomeAuthorityV1 { abode, operational, prepared: None }
    }
}
