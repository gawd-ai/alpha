//! Strict, model-authored decisions for the three-mind collaboration proof.
//!
//! Models choose a small semantic contract, not executable source.  Each turn is bounded,
//! canonically hashed, and linked to the exact validated predecessors.  A trusted adapter can
//! later lower [`FinalCapabilitySpecV1`] into the native, Wasm, and Rhai implementations.

use std::error::Error;
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub const CHALLENGE_SCHEMA_V1: &str = "alpha.dialogue.challenge.v1";
pub const BUILDER_DRAFT_SCHEMA_V1: &str = "alpha.dialogue.builder-draft.v1";
pub const REVIEWER_DECISION_SCHEMA_V1: &str = "alpha.dialogue.reviewer-decision.v1";
pub const CONTRACT_TEST_PLAN_SCHEMA_V1: &str = "alpha.dialogue.contract-test-plan.v1";
pub const FINAL_APPROVAL_SCHEMA_V1: &str = "alpha.dialogue.final-approval.v1";
pub const FINAL_CAPABILITY_SCHEMA_V1: &str = "alpha.capability.affine-i32.v1";
pub const SEMANTIC_TRUTH_TABLE_SCHEMA_V1: &str = "alpha.capability.affine-i32.truth-table.v1";
pub const AFFINE_I32_KIND_V1: &str = "affine_i32_v1";

pub const CHALLENGE_OBJECTIVE_V1: &str = "Propose one novel bounded affine i32 capability for equivalent native, WebAssembly, and Rhai execution.";
pub const MAX_DECISION_JSON_BYTES: usize = 16 * 1024;
pub const MAX_DECISION_PROMPT_BYTES: usize = 64 * 1024;
pub const MIN_CHALLENGE_NONCE_BYTES: usize = 16;
pub const MAX_CHALLENGE_NONCE_BYTES: usize = 128;
pub const MAX_CAPABILITY_NAME_BYTES: usize = 64;
pub const MAX_CAPABILITY_SLUG_BYTES: usize = 48;
pub const MAX_ENTRYPOINT_BYTES: usize = 64;
pub const MAX_DESCRIPTION_BYTES: usize = 256;
pub const INPUT_FLOOR: i32 = -1_000_000;
pub const INPUT_CEILING: i32 = 1_000_000;
pub const MAX_DOMAIN_POINTS: usize = 257;
pub const MIN_MULTIPLIER: i32 = -16;
pub const MAX_MULTIPLIER: i32 = 16;
pub const MIN_ADDEND: i32 = -1_000_000;
pub const MAX_ADDEND: i32 = 1_000_000;
/// `input`, plus an operator and literal for each non-identity affine operation.
pub const MAX_SEMANTIC_NODES: usize = 5;
pub const PREDECESSOR_COUNT: usize = 4;
pub const CONTRACT_CASE_COUNT: usize = 5;

/// A bounded validation/decoding failure. Messages are intended for an operator or model retry,
/// and deliberately contain no provider secret or executable source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionError(String);

impl DecisionError {
    fn invalid(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for DecisionError {}

pub type DecisionResult<T> = Result<T, DecisionError>;

/// A caller-originated, nonce-bound problem statement. All constraints other than the nonce are
/// frozen so a challenge cannot smuggle a preferred answer or generated implementation to a model.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeV1 {
    pub schema: String,
    pub challenge_nonce: String,
    pub objective: String,
    pub capability_kind: String,
    pub input_floor: i32,
    pub input_ceiling: i32,
    pub max_domain_points: usize,
    pub min_multiplier: i32,
    pub max_multiplier: i32,
    pub min_addend: i32,
    pub max_addend: i32,
    pub max_semantic_nodes: usize,
}

impl ChallengeV1 {
    pub fn new(challenge_nonce: impl Into<String>) -> Self {
        Self {
            schema: CHALLENGE_SCHEMA_V1.into(),
            challenge_nonce: challenge_nonce.into(),
            objective: CHALLENGE_OBJECTIVE_V1.into(),
            capability_kind: AFFINE_I32_KIND_V1.into(),
            input_floor: INPUT_FLOOR,
            input_ceiling: INPUT_CEILING,
            max_domain_points: MAX_DOMAIN_POINTS,
            min_multiplier: MIN_MULTIPLIER,
            max_multiplier: MAX_MULTIPLIER,
            min_addend: MIN_ADDEND,
            max_addend: MAX_ADDEND,
            max_semantic_nodes: MAX_SEMANTIC_NODES,
        }
    }

    #[cfg(test)]
    pub fn decode_json(bytes: &[u8]) -> DecisionResult<Self> {
        decode_record(bytes, "challenge")
    }

    pub fn validate(&self) -> DecisionResult<()> {
        exact("challenge schema", &self.schema, CHALLENGE_SCHEMA_V1)?;
        validate_nonce(&self.challenge_nonce)?;
        exact("challenge objective", &self.objective, CHALLENGE_OBJECTIVE_V1)?;
        exact("capability kind", &self.capability_kind, AFFINE_I32_KIND_V1)?;
        if self.input_floor != INPUT_FLOOR
            || self.input_ceiling != INPUT_CEILING
            || self.max_domain_points != MAX_DOMAIN_POINTS
            || self.min_multiplier != MIN_MULTIPLIER
            || self.max_multiplier != MAX_MULTIPLIER
            || self.min_addend != MIN_ADDEND
            || self.max_addend != MAX_ADDEND
            || self.max_semantic_nodes != MAX_SEMANTIC_NODES
        {
            return Err(DecisionError::invalid(
                "challenge constraints differ from the frozen affine_i32_v1 limits",
            ));
        }
        ensure_record_size("challenge", self)
    }

    /// Freshness is intentionally supplied by the composition root, which owns durable run state.
    /// A nonce-bound challenge is fresh iff its canonical hash is absent from that state.
    #[cfg(test)]
    pub fn validate_fresh(&self, prior_challenge_hashes: &[String]) -> DecisionResult<()> {
        self.validate()?;
        let own_hash = self.hash()?;
        if prior_challenge_hashes.iter().any(|prior| prior == &own_hash) {
            return Err(DecisionError::invalid("challenge was already used"));
        }
        Ok(())
    }

    pub fn hash(&self) -> DecisionResult<String> {
        self.validate()?;
        canonical_hash(self)
    }
}

/// The Builder's semantic proposal. It contains no Rust, WAT, Rhai, or other executable text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuilderDraftV1 {
    pub schema: String,
    pub challenge_hash: String,
    pub name: String,
    pub slug: String,
    pub entrypoint: String,
    pub description: String,
    pub input_min: i32,
    pub input_max: i32,
    pub multiplier: i32,
    pub addend: i32,
}

impl BuilderDraftV1 {
    pub fn decode_json(bytes: &[u8]) -> DecisionResult<Self> {
        decode_record(bytes, "builder draft")
    }

    pub fn validate(&self, challenge: &ChallengeV1) -> DecisionResult<()> {
        challenge.validate()?;
        exact("builder draft schema", &self.schema, BUILDER_DRAFT_SCHEMA_V1)?;
        exact("builder challenge hash", &self.challenge_hash, &challenge.hash()?)?;
        validate_capability_identity(self)?;
        validate_domain(self.input_min, self.input_max, true)?;
        validate_affine(self.multiplier, self.addend, self.input_min, self.input_max)?;
        if affine_semantic_node_count(self.multiplier, self.addend) > challenge.max_semantic_nodes {
            return Err(DecisionError::invalid("builder proposal exceeds the semantic node cap"));
        }
        ensure_record_size("builder draft", self)
    }

    pub fn hash(&self, challenge: &ChallengeV1) -> DecisionResult<String> {
        self.validate(challenge)?;
        canonical_hash(self)
    }
}

/// The Reviewer has no advisory-only output: accepting this record changes both admitted domain
/// boundaries while retaining enough signed range for meaningful boundary/interior tests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewerDecisionV1 {
    pub schema: String,
    pub challenge_hash: String,
    pub draft_hash: String,
    pub admitted_input_min: i32,
    pub admitted_input_max: i32,
}

impl ReviewerDecisionV1 {
    pub fn decode_json(bytes: &[u8]) -> DecisionResult<Self> {
        decode_record(bytes, "reviewer decision")
    }

    pub fn validate(&self, challenge: &ChallengeV1, draft: &BuilderDraftV1) -> DecisionResult<()> {
        draft.validate(challenge)?;
        exact("reviewer schema", &self.schema, REVIEWER_DECISION_SCHEMA_V1)?;
        exact("reviewer challenge hash", &self.challenge_hash, &challenge.hash()?)?;
        exact("reviewer draft hash", &self.draft_hash, &draft.hash(challenge)?)?;
        validate_domain(self.admitted_input_min, self.admitted_input_max, false)?;
        if self.admitted_input_min <= draft.input_min || self.admitted_input_max >= draft.input_max
        {
            return Err(DecisionError::invalid(
                "reviewer must materially narrow both domain boundaries",
            ));
        }
        validate_affine(
            draft.multiplier,
            draft.addend,
            self.admitted_input_min,
            self.admitted_input_max,
        )?;
        ensure_record_size("reviewer decision", self)
    }

    pub fn hash(&self, challenge: &ChallengeV1, draft: &BuilderDraftV1) -> DecisionResult<String> {
        self.validate(challenge, draft)?;
        canonical_hash(self)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContractCaseKindV1 {
    LowerBoundary,
    RemoteNegativeInterior,
    Zero,
    LocalPositiveInterior,
    UpperBoundary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractCaseV1 {
    pub kind: ContractCaseKindV1,
    pub input: i32,
    pub expected_output: i32,
}

/// The Contract Tester's contribution selects the values used by the actual local and cross-Realm
/// jobs. Expected values are untrusted claims and are recomputed by the host during validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractTestPlanV1 {
    pub schema: String,
    pub challenge_hash: String,
    pub draft_hash: String,
    pub review_hash: String,
    pub local_input: i32,
    pub remote_input: i32,
    pub cases: Vec<ContractCaseV1>,
}

impl ContractTestPlanV1 {
    pub fn decode_json(bytes: &[u8]) -> DecisionResult<Self> {
        decode_record(bytes, "contract test plan")
    }

    pub fn validate(
        &self,
        challenge: &ChallengeV1,
        draft: &BuilderDraftV1,
        review: &ReviewerDecisionV1,
    ) -> DecisionResult<()> {
        review.validate(challenge, draft)?;
        exact("contract plan schema", &self.schema, CONTRACT_TEST_PLAN_SCHEMA_V1)?;
        exact("contract plan challenge hash", &self.challenge_hash, &challenge.hash()?)?;
        exact("contract plan draft hash", &self.draft_hash, &draft.hash(challenge)?)?;
        exact("contract plan review hash", &self.review_hash, &review.hash(challenge, draft)?)?;

        let minimum = review.admitted_input_min;
        let maximum = review.admitted_input_max;
        if self.remote_input <= minimum || self.remote_input >= 0 {
            return Err(DecisionError::invalid(
                "remote input must be chosen from the negative interior",
            ));
        }
        if self.local_input <= 0 || self.local_input >= maximum {
            return Err(DecisionError::invalid(
                "local input must be chosen from the positive interior",
            ));
        }
        if self.cases.len() != CONTRACT_CASE_COUNT {
            return Err(DecisionError::invalid(format!(
                "contract plan must contain exactly {CONTRACT_CASE_COUNT} ordered cases"
            )));
        }

        let required = [
            (ContractCaseKindV1::LowerBoundary, minimum),
            (ContractCaseKindV1::RemoteNegativeInterior, self.remote_input),
            (ContractCaseKindV1::Zero, 0),
            (ContractCaseKindV1::LocalPositiveInterior, self.local_input),
            (ContractCaseKindV1::UpperBoundary, maximum),
        ];
        for (index, (case, (kind, input))) in self.cases.iter().zip(required).enumerate() {
            if case.kind != kind || case.input != input {
                return Err(DecisionError::invalid(format!(
                    "contract case {index} is missing, reordered, or bound to the wrong input"
                )));
            }
            let expected = evaluate_affine(input, draft.multiplier, draft.addend)?;
            if case.expected_output != expected {
                return Err(DecisionError::invalid(format!(
                    "contract case {index} expected output was not host-derived"
                )));
            }
        }
        ensure_record_size("contract test plan", self)
    }

    pub fn hash(
        &self,
        challenge: &ChallengeV1,
        draft: &BuilderDraftV1,
        review: &ReviewerDecisionV1,
    ) -> DecisionResult<String> {
        self.validate(challenge, draft, review)?;
        canonical_hash(self)
    }
}

/// The exact, normalized capability that an authoring adapter may lower into all three engines.
/// Its semantic digest intentionally excludes names, descriptions, challenge nonces, and test-run
/// choices; it identifies the complete admitted input/output truth table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalCapabilitySpecV1 {
    pub schema: String,
    pub name: String,
    pub slug: String,
    pub entrypoint: String,
    pub description: String,
    pub input_min: i32,
    pub input_max: i32,
    pub multiplier: i32,
    pub addend: i32,
    pub local_input: i32,
    pub remote_input: i32,
    pub semantic_digest: String,
}

impl FinalCapabilitySpecV1 {
    pub fn from_chain(
        challenge: &ChallengeV1,
        draft: &BuilderDraftV1,
        review: &ReviewerDecisionV1,
        plan: &ContractTestPlanV1,
    ) -> DecisionResult<Self> {
        plan.validate(challenge, draft, review)?;
        let mut spec = Self {
            schema: FINAL_CAPABILITY_SCHEMA_V1.into(),
            name: draft.name.clone(),
            slug: draft.slug.clone(),
            entrypoint: draft.entrypoint.clone(),
            description: draft.description.clone(),
            input_min: review.admitted_input_min,
            input_max: review.admitted_input_max,
            multiplier: draft.multiplier,
            addend: draft.addend,
            local_input: plan.local_input,
            remote_input: plan.remote_input,
            semantic_digest: String::new(),
        };
        spec.semantic_digest = spec.computed_semantic_digest()?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> DecisionResult<()> {
        self.validate_without_digest()?;
        exact(
            "semantic truth-table digest",
            &self.semantic_digest,
            &self.computed_semantic_digest()?,
        )?;
        ensure_record_size("final capability", self)
    }

    fn validate_without_digest(&self) -> DecisionResult<()> {
        exact("final capability schema", &self.schema, FINAL_CAPABILITY_SCHEMA_V1)?;
        validate_text("capability name", &self.name, MAX_CAPABILITY_NAME_BYTES)?;
        validate_slug(&self.slug)?;
        validate_entrypoint(&self.entrypoint)?;
        validate_text("capability description", &self.description, MAX_DESCRIPTION_BYTES)?;
        reject_legacy_double_identity(&self.slug, &self.entrypoint)?;
        validate_domain(self.input_min, self.input_max, false)?;
        validate_affine(self.multiplier, self.addend, self.input_min, self.input_max)?;
        if self.remote_input <= self.input_min || self.remote_input >= 0 {
            return Err(DecisionError::invalid(
                "final capability remote input is outside the negative interior",
            ));
        }
        if self.local_input <= 0 || self.local_input >= self.input_max {
            return Err(DecisionError::invalid(
                "final capability local input is outside the positive interior",
            ));
        }
        Ok(())
    }

    pub fn truth_table(&self) -> DecisionResult<SemanticTruthTableV1> {
        self.validate_without_digest()?;
        let mut points = Vec::with_capacity(domain_points(self.input_min, self.input_max)?);
        for input in self.input_min..=self.input_max {
            points.push(SemanticTruthPointV1 {
                input,
                output: evaluate_affine(input, self.multiplier, self.addend)?,
            });
        }
        Ok(SemanticTruthTableV1 {
            schema: SEMANTIC_TRUTH_TABLE_SCHEMA_V1.into(),
            capability_kind: AFFINE_I32_KIND_V1.into(),
            input_min: self.input_min,
            input_max: self.input_max,
            points,
        })
    }

    pub fn computed_semantic_digest(&self) -> DecisionResult<String> {
        canonical_hash(&self.truth_table()?)
    }

    /// Product/live acceptance passes the fixture and prior-live semantic digests here. Matching
    /// one fails closed even if a model changed names, descriptions, nonces, or test inputs.
    pub fn reject_forbidden_semantics(&self, forbidden_digests: &[String]) -> DecisionResult<()> {
        self.validate()?;
        if forbidden_digests.iter().any(|digest| digest == &self.semantic_digest) {
            return Err(DecisionError::invalid(
                "capability semantic digest matches a fixture or previously admitted capability",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTruthTableV1 {
    pub schema: String,
    pub capability_kind: String,
    pub input_min: i32,
    pub input_max: i32,
    pub points: Vec<SemanticTruthPointV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTruthPointV1 {
    pub input: i32,
    pub output: i32,
}

/// The Builder's final turn. Fixed-position predecessor hashes make omission and reordering
/// detectable, while exact projection prevents a last-turn mutation of any reviewed/tested field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalApprovalV1 {
    pub schema: String,
    pub predecessor_hashes: [String; PREDECESSOR_COUNT],
    pub normalized_spec: FinalCapabilitySpecV1,
}

impl FinalApprovalV1 {
    pub fn from_chain(
        challenge: &ChallengeV1,
        draft: &BuilderDraftV1,
        review: &ReviewerDecisionV1,
        plan: &ContractTestPlanV1,
    ) -> DecisionResult<Self> {
        let normalized_spec = FinalCapabilitySpecV1::from_chain(challenge, draft, review, plan)?;
        Ok(Self {
            schema: FINAL_APPROVAL_SCHEMA_V1.into(),
            predecessor_hashes: predecessor_hashes(challenge, draft, review, plan)?,
            normalized_spec,
        })
    }

    pub fn decode_json(bytes: &[u8]) -> DecisionResult<Self> {
        decode_record(bytes, "final approval")
    }

    pub fn validate(
        &self,
        challenge: &ChallengeV1,
        draft: &BuilderDraftV1,
        review: &ReviewerDecisionV1,
        plan: &ContractTestPlanV1,
    ) -> DecisionResult<()> {
        plan.validate(challenge, draft, review)?;
        exact("final approval schema", &self.schema, FINAL_APPROVAL_SCHEMA_V1)?;
        if self.predecessor_hashes != predecessor_hashes(challenge, draft, review, plan)? {
            return Err(DecisionError::invalid(
                "final predecessor hashes are wrong, missing, or reordered",
            ));
        }
        let expected = FinalCapabilitySpecV1::from_chain(challenge, draft, review, plan)?;
        if self.normalized_spec != expected {
            return Err(DecisionError::invalid(
                "final capability is not the exact normalized draft/review/test projection",
            ));
        }
        self.normalized_spec.validate()?;
        ensure_record_size("final approval", self)
    }

    pub fn validate_with_forbidden_semantics(
        &self,
        challenge: &ChallengeV1,
        draft: &BuilderDraftV1,
        review: &ReviewerDecisionV1,
        plan: &ContractTestPlanV1,
        forbidden_digests: &[String],
    ) -> DecisionResult<()> {
        self.validate(challenge, draft, review, plan)?;
        self.normalized_spec.reject_forbidden_semantics(forbidden_digests)
    }

    pub fn hash(
        &self,
        challenge: &ChallengeV1,
        draft: &BuilderDraftV1,
        review: &ReviewerDecisionV1,
        plan: &ContractTestPlanV1,
    ) -> DecisionResult<String> {
        self.validate(challenge, draft, review, plan)?;
        canonical_hash(self)
    }
}

pub fn builder_prompt(challenge: &ChallengeV1) -> DecisionResult<String> {
    challenge.validate()?;
    let instructions = format!(
        "Propose one novel affine_i32_v1 semantic contract. Return only one BuilderDraftV1 JSON object of at most {MAX_DECISION_JSON_BYTES} bytes with exactly these fields: schema, challenge_hash, name, slug, entrypoint, description, input_min, input_max, multiplier, addend. Set schema to {BUILDER_DRAFT_SCHEMA_V1} and challenge_hash to {}. Do not emit source code or an implementation. Choose the identity, bounded zero-crossing draft domain, multiplier, and addend; the proposal must not be constant, identity, pure negation, or signed doubling.",
        challenge.hash()?
    );
    decision_prompt("BUILDER", &instructions, &[("CHALLENGE", canonical_json(challenge)?)])
}

pub fn reviewer_prompt(challenge: &ChallengeV1, draft: &BuilderDraftV1) -> DecisionResult<String> {
    draft.validate(challenge)?;
    let instructions = format!(
        "Return only one ReviewerDecisionV1 JSON object of at most {MAX_DECISION_JSON_BYTES} bytes with exactly these fields: schema, challenge_hash, draft_hash, admitted_input_min, admitted_input_max. Set schema to {REVIEWER_DECISION_SCHEMA_V1}, challenge_hash to {}, and draft_hash to {}. Do not emit source code or an implementation. Materially narrow both admitted-domain boundaries while preserving negative interior, zero, and positive interior values.",
        challenge.hash()?,
        draft.hash(challenge)?
    );
    decision_prompt(
        "REVIEWER",
        &instructions,
        &[("CHALLENGE", canonical_json(challenge)?), ("BUILDER_DRAFT", canonical_json(draft)?)],
    )
}

pub fn contract_tester_prompt(
    challenge: &ChallengeV1,
    draft: &BuilderDraftV1,
    review: &ReviewerDecisionV1,
) -> DecisionResult<String> {
    review.validate(challenge, draft)?;
    let instructions = format!(
        "Return only one ContractTestPlanV1 JSON object of at most {MAX_DECISION_JSON_BYTES} bytes with exactly these fields: schema, challenge_hash, draft_hash, review_hash, local_input, remote_input, cases. Set schema to {CONTRACT_TEST_PLAN_SCHEMA_V1}, challenge_hash to {}, draft_hash to {}, and review_hash to {}. Every case has exactly kind, input, expected_output. Do not emit source code or an implementation. Choose one negative-interior remote input and one positive-interior local input; provide exactly the ordered lower_boundary, remote_negative_interior, zero, local_positive_interior, and upper_boundary cases. Compute claimed outputs yourself; the host will recompute all of them.",
        challenge.hash()?,
        draft.hash(challenge)?,
        review.hash(challenge, draft)?
    );
    decision_prompt(
        "CONTRACT_TESTER",
        &instructions,
        &[
            ("CHALLENGE", canonical_json(challenge)?),
            ("BUILDER_DRAFT", canonical_json(draft)?),
            ("REVIEWER_DECISION", canonical_json(review)?),
        ],
    )
}

pub fn final_approval_prompt(
    challenge: &ChallengeV1,
    draft: &BuilderDraftV1,
    review: &ReviewerDecisionV1,
    plan: &ContractTestPlanV1,
) -> DecisionResult<String> {
    plan.validate(challenge, draft, review)?;
    let hashes = predecessor_hashes(challenge, draft, review, plan)?;
    let semantic_digest =
        FinalCapabilitySpecV1::from_chain(challenge, draft, review, plan)?.semantic_digest;
    let instructions = format!(
        "Return only one FinalApprovalV1 JSON object of at most {MAX_DECISION_JSON_BYTES} bytes with exactly these fields: schema, predecessor_hashes, normalized_spec. Set schema to {FINAL_APPROVAL_SCHEMA_V1}. Set predecessor_hashes, in causal order, to [{:?}, {:?}, {:?}, {:?}]. normalized_spec has exactly schema, name, slug, entrypoint, description, input_min, input_max, multiplier, addend, local_input, remote_input, semantic_digest; set its schema to {FINAL_CAPABILITY_SCHEMA_V1} and its host-derived semantic_digest to {semantic_digest}. Do not emit source code or an implementation. Project every other normalized field exactly from the decisions; do not invent or revise one.",
        hashes[0], hashes[1], hashes[2], hashes[3]
    );
    decision_prompt(
        "BUILDER_FINAL",
        &instructions,
        &[
            ("CHALLENGE", canonical_json(challenge)?),
            ("BUILDER_DRAFT", canonical_json(draft)?),
            ("REVIEWER_DECISION", canonical_json(review)?),
            ("CONTRACT_TEST_PLAN", canonical_json(plan)?),
        ],
    )
}

pub fn evaluate_affine(input: i32, multiplier: i32, addend: i32) -> DecisionResult<i32> {
    input
        .checked_mul(multiplier)
        .and_then(|product| product.checked_add(addend))
        .ok_or_else(|| DecisionError::invalid("affine i32 evaluation overflowed"))
}

pub fn affine_semantic_node_count(multiplier: i32, addend: i32) -> usize {
    let multiply_nodes = usize::from(multiplier != 1) * 2;
    let add_nodes = usize::from(addend != 0) * 2;
    1 + multiply_nodes + add_nodes
}

pub fn canonical_json<T: Serialize>(value: &T) -> DecisionResult<Vec<u8>> {
    gawdfn::canonical_json_bytes(value)
        .map_err(|error| DecisionError::invalid(format!("canonical JSON failed: {error}")))
}

pub fn canonical_hash<T: Serialize>(value: &T) -> DecisionResult<String> {
    gawdfn::canonical_hash(value)
        .map_err(|error| DecisionError::invalid(format!("canonical hash failed: {error}")))
}

fn predecessor_hashes(
    challenge: &ChallengeV1,
    draft: &BuilderDraftV1,
    review: &ReviewerDecisionV1,
    plan: &ContractTestPlanV1,
) -> DecisionResult<[String; PREDECESSOR_COUNT]> {
    Ok([
        challenge.hash()?,
        draft.hash(challenge)?,
        review.hash(challenge, draft)?,
        plan.hash(challenge, draft, review)?,
    ])
}

fn validate_capability_identity(draft: &BuilderDraftV1) -> DecisionResult<()> {
    validate_text("capability name", &draft.name, MAX_CAPABILITY_NAME_BYTES)?;
    validate_slug(&draft.slug)?;
    validate_entrypoint(&draft.entrypoint)?;
    validate_text("capability description", &draft.description, MAX_DESCRIPTION_BYTES)?;
    reject_legacy_double_identity(&draft.slug, &draft.entrypoint)
}

fn reject_legacy_double_identity(slug: &str, entrypoint: &str) -> DecisionResult<()> {
    let normalized_slug: String =
        slug.chars().filter(|character| character.is_ascii_alphanumeric()).collect();
    let normalized_entrypoint: String =
        entrypoint.chars().filter(|character| character.is_ascii_alphanumeric()).collect();
    if normalized_slug == "doublesigned" || normalized_entrypoint == "doublesigned" {
        return Err(DecisionError::invalid(
            "the legacy double_signed identity is not a novel capability",
        ));
    }
    Ok(())
}

fn validate_affine(
    multiplier: i32,
    addend: i32,
    input_min: i32,
    input_max: i32,
) -> DecisionResult<()> {
    if !(MIN_MULTIPLIER..=MAX_MULTIPLIER).contains(&multiplier) {
        return Err(DecisionError::invalid(format!(
            "multiplier must be in {MIN_MULTIPLIER}..={MAX_MULTIPLIER}"
        )));
    }
    if !(MIN_ADDEND..=MAX_ADDEND).contains(&addend) {
        return Err(DecisionError::invalid(format!(
            "addend must be in {MIN_ADDEND}..={MAX_ADDEND}"
        )));
    }
    match (multiplier, addend) {
        (0, _) => return Err(DecisionError::invalid("constant semantics are forbidden")),
        (1, 0) => return Err(DecisionError::invalid("identity semantics are forbidden")),
        (-1, 0) => return Err(DecisionError::invalid("pure negation semantics are forbidden")),
        (2, 0) => {
            return Err(DecisionError::invalid("double_signed-equivalent semantics are forbidden"))
        }
        _ => {}
    }
    if affine_semantic_node_count(multiplier, addend) > MAX_SEMANTIC_NODES {
        return Err(DecisionError::invalid("affine semantics exceed the node cap"));
    }
    for input in input_min..=input_max {
        evaluate_affine(input, multiplier, addend)?;
    }
    Ok(())
}

fn validate_domain(input_min: i32, input_max: i32, draft: bool) -> DecisionResult<()> {
    if input_min < INPUT_FLOOR || input_max > INPUT_CEILING {
        return Err(DecisionError::invalid(format!(
            "input domain must remain within {INPUT_FLOOR}..={INPUT_CEILING}"
        )));
    }
    let points = domain_points(input_min, input_max)?;
    if points > MAX_DOMAIN_POINTS {
        return Err(DecisionError::invalid(format!(
            "input domain contains {points} points; cap is {MAX_DOMAIN_POINTS}"
        )));
    }
    let required_interior = if draft { 3 } else { 2 };
    if input_min > -required_interior || input_max < required_interior {
        return Err(DecisionError::invalid(format!(
            "input domain must cross zero with at least {required_interior} values of headroom on each side"
        )));
    }
    Ok(())
}

fn domain_points(input_min: i32, input_max: i32) -> DecisionResult<usize> {
    if input_min > input_max {
        return Err(DecisionError::invalid("input domain minimum exceeds maximum"));
    }
    let points = i64::from(input_max) - i64::from(input_min) + 1;
    usize::try_from(points).map_err(|_| DecisionError::invalid("input domain width overflowed"))
}

fn validate_nonce(value: &str) -> DecisionResult<()> {
    let length = value.len();
    if !(MIN_CHALLENGE_NONCE_BYTES..=MAX_CHALLENGE_NONCE_BYTES).contains(&length) {
        return Err(DecisionError::invalid(format!(
            "challenge nonce must be {MIN_CHALLENGE_NONCE_BYTES}..={MAX_CHALLENGE_NONCE_BYTES} bytes"
        )));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(DecisionError::invalid("challenge nonce contains a forbidden character"));
    }
    Ok(())
}

fn validate_slug(value: &str) -> DecisionResult<()> {
    validate_text("capability slug", value, MAX_CAPABILITY_SLUG_BYTES)?;
    let bytes = value.as_bytes();
    if bytes.len() < 3
        || !bytes.first().is_some_and(u8::is_ascii_lowercase)
        || !bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        || value.contains("--")
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
    {
        return Err(DecisionError::invalid(
            "capability slug must be 3..=48 bytes of lowercase ASCII, digits, or interior hyphens",
        ));
    }
    Ok(())
}

fn validate_entrypoint(value: &str) -> DecisionResult<()> {
    validate_text("entrypoint", value, MAX_ENTRYPOINT_BYTES)?;
    let bytes = value.as_bytes();
    if !bytes.first().is_some_and(u8::is_ascii_lowercase)
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return Err(DecisionError::invalid(
            "entrypoint must start with lowercase ASCII and contain only lowercase ASCII, digits, or underscores",
        ));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, maximum: usize) -> DecisionResult<()> {
    if value.is_empty() || value.len() > maximum || value.trim() != value {
        return Err(DecisionError::invalid(format!(
            "{label} must be non-empty, trimmed, and at most {maximum} bytes"
        )));
    }
    let normalized = value.to_ascii_lowercase();
    if !value.bytes().all(|byte| byte == b' ' || byte.is_ascii_graphic())
        || value.chars().any(|character| matches!(character, '{' | '}' | '`'))
        || normalized.contains("fn ")
        || normalized.contains("(module")
        || normalized.contains("gawd_creature_v1")
        || normalized.contains("extern \"")
    {
        return Err(DecisionError::invalid(format!(
            "{label} must be one-line prose, not generated implementation text"
        )));
    }
    Ok(())
}

fn exact(label: &str, actual: &str, expected: &str) -> DecisionResult<()> {
    if actual != expected {
        return Err(DecisionError::invalid(format!("{label} does not match")));
    }
    Ok(())
}

fn decode_record<T: DeserializeOwned>(bytes: &[u8], label: &str) -> DecisionResult<T> {
    if bytes.is_empty() || bytes.len() > MAX_DECISION_JSON_BYTES {
        return Err(DecisionError::invalid(format!(
            "{label} JSON must be 1..={MAX_DECISION_JSON_BYTES} bytes"
        )));
    }
    serde_json::from_slice(bytes)
        .map_err(|error| DecisionError::invalid(format!("invalid {label} JSON: {error}")))
}

fn ensure_record_size<T: Serialize>(label: &str, value: &T) -> DecisionResult<()> {
    let length = canonical_json(value)?.len();
    if length > MAX_DECISION_JSON_BYTES {
        return Err(DecisionError::invalid(format!(
            "canonical {label} is {length} bytes; cap is {MAX_DECISION_JSON_BYTES}"
        )));
    }
    Ok(())
}

fn decision_prompt(
    role: &str,
    instructions: &str,
    records: &[(&str, Vec<u8>)],
) -> DecisionResult<String> {
    let mut prompt = format!("ALPHA_THREE_MIND_DECISION_V1\nROLE:{role}\n{instructions}\n");
    for (label, bytes) in records {
        if bytes.len() > MAX_DECISION_JSON_BYTES {
            return Err(DecisionError::invalid(format!(
                "{label} predecessor exceeds the decision cap"
            )));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| DecisionError::invalid(format!("{label} is not UTF-8 JSON")))?;
        prompt.push_str(label);
        prompt.push(':');
        prompt.push_str(&bytes.len().to_string());
        prompt.push('\n');
        prompt.push_str(text);
        prompt.push('\n');
    }
    if prompt.len() > MAX_DECISION_PROMPT_BYTES {
        return Err(DecisionError::invalid(format!(
            "decision prompt exceeds the {MAX_DECISION_PROMPT_BYTES}-byte cap"
        )));
    }
    Ok(prompt)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        challenge: ChallengeV1,
        draft: BuilderDraftV1,
        review: ReviewerDecisionV1,
        plan: ContractTestPlanV1,
        approval: FinalApprovalV1,
    }

    fn case(kind: ContractCaseKindV1, input: i32, multiplier: i32, addend: i32) -> ContractCaseV1 {
        ContractCaseV1 {
            kind,
            input,
            expected_output: evaluate_affine(input, multiplier, addend).unwrap(),
        }
    }

    fn fixture() -> Fixture {
        let challenge = ChallengeV1::new("fixture-challenge-00000001");
        let draft = BuilderDraftV1 {
            schema: BUILDER_DRAFT_SCHEMA_V1.into(),
            challenge_hash: challenge.hash().unwrap(),
            name: "Offset Tripler".into(),
            slug: "offset-tripler".into(),
            entrypoint: "offset_triple".into(),
            description: "Triples a signed value and subtracts five.".into(),
            input_min: -8,
            input_max: 8,
            multiplier: 3,
            addend: -5,
        };
        let review = ReviewerDecisionV1 {
            schema: REVIEWER_DECISION_SCHEMA_V1.into(),
            challenge_hash: challenge.hash().unwrap(),
            draft_hash: draft.hash(&challenge).unwrap(),
            admitted_input_min: -6,
            admitted_input_max: 6,
        };
        let remote_input = -2;
        let local_input = 3;
        let plan = ContractTestPlanV1 {
            schema: CONTRACT_TEST_PLAN_SCHEMA_V1.into(),
            challenge_hash: challenge.hash().unwrap(),
            draft_hash: draft.hash(&challenge).unwrap(),
            review_hash: review.hash(&challenge, &draft).unwrap(),
            local_input,
            remote_input,
            cases: vec![
                case(ContractCaseKindV1::LowerBoundary, -6, 3, -5),
                case(ContractCaseKindV1::RemoteNegativeInterior, remote_input, 3, -5),
                case(ContractCaseKindV1::Zero, 0, 3, -5),
                case(ContractCaseKindV1::LocalPositiveInterior, local_input, 3, -5),
                case(ContractCaseKindV1::UpperBoundary, 6, 3, -5),
            ],
        };
        let approval = FinalApprovalV1::from_chain(&challenge, &draft, &review, &plan).unwrap();
        Fixture { challenge, draft, review, plan, approval }
    }

    #[test]
    fn valid_chain_is_strictly_linked_and_canonically_stable() {
        let fixture = fixture();
        fixture
            .approval
            .validate(&fixture.challenge, &fixture.draft, &fixture.review, &fixture.plan)
            .unwrap();

        let encoded = serde_json::to_vec_pretty(&fixture.approval).unwrap();
        let decoded = FinalApprovalV1::decode_json(&encoded).unwrap();
        assert_eq!(decoded, fixture.approval);
        assert_eq!(
            decoded
                .hash(&fixture.challenge, &fixture.draft, &fixture.review, &fixture.plan)
                .unwrap(),
            fixture
                .approval
                .hash(&fixture.challenge, &fixture.draft, &fixture.review, &fixture.plan)
                .unwrap()
        );
    }

    #[test]
    fn challenge_is_fixed_bounded_and_has_an_external_freshness_hook() {
        let challenge = ChallengeV1::new("fresh-challenge-00000001");
        challenge.validate_fresh(&[]).unwrap();
        assert!(challenge.validate_fresh(&[challenge.hash().unwrap()]).is_err());

        let mut changed = challenge.clone();
        changed.objective.push_str(" Prefer multiplier three.");
        assert!(changed.validate().is_err());
        let mut short_nonce = challenge;
        short_nonce.challenge_nonce = "reused".into();
        assert!(short_nonce.validate().is_err());
    }

    #[test]
    fn decoding_rejects_unknown_fields_missing_fields_and_oversized_records() {
        let fixture = fixture();
        let mut draft = serde_json::to_value(&fixture.draft).unwrap();
        draft.as_object_mut().unwrap().insert("source".into(), "fn handle() {}".into());
        assert!(BuilderDraftV1::decode_json(&serde_json::to_vec(&draft).unwrap()).is_err());

        draft.as_object_mut().unwrap().remove("multiplier");
        assert!(BuilderDraftV1::decode_json(&serde_json::to_vec(&draft).unwrap()).is_err());
        assert!(ChallengeV1::decode_json(&vec![b' '; MAX_DECISION_JSON_BYTES + 1]).is_err());
    }

    #[test]
    fn draft_rejects_trivial_legacy_unbounded_and_wrongly_linked_semantics() {
        let fixture = fixture();
        for (multiplier, addend) in [(0, 7), (1, 0), (-1, 0), (2, 0)] {
            let mut draft = fixture.draft.clone();
            draft.multiplier = multiplier;
            draft.addend = addend;
            assert!(draft.validate(&fixture.challenge).is_err(), "{multiplier}x+{addend}");
        }

        let mut legacy_identity = fixture.draft.clone();
        legacy_identity.slug = "double-signed".into();
        assert!(legacy_identity.validate(&fixture.challenge).is_err());
        let mut source_smuggling = fixture.draft.clone();
        source_smuggling.description = "fn handle attempts to smuggle implementation text".into();
        assert!(source_smuggling.validate(&fixture.challenge).is_err());
        let mut too_wide = fixture.draft.clone();
        too_wide.input_min = -129;
        too_wide.input_max = 128;
        assert!(too_wide.validate(&fixture.challenge).is_err());
        let mut wrong_hash = fixture.draft;
        wrong_hash.challenge_hash = gawdfn::sha256_digest(b"wrong");
        assert!(wrong_hash.validate(&fixture.challenge).is_err());
    }

    #[test]
    fn affine_evaluation_and_node_accounting_fail_closed() {
        assert_eq!(affine_semantic_node_count(1, 4), 3);
        assert_eq!(affine_semantic_node_count(3, 0), 3);
        assert_eq!(affine_semantic_node_count(3, -5), 5);
        assert_eq!(evaluate_affine(7, 3, -5).unwrap(), 16);
        assert!(evaluate_affine(i32::MAX, 2, 0).is_err());
        assert!(evaluate_affine(i32::MIN, 1, -1).is_err());
    }

    #[test]
    fn reviewer_must_make_a_material_two_sided_change() {
        let fixture = fixture();
        let mut decorative = fixture.review.clone();
        decorative.admitted_input_min = fixture.draft.input_min;
        assert!(decorative.validate(&fixture.challenge, &fixture.draft).is_err());

        let mut one_sided = fixture.review.clone();
        one_sided.admitted_input_max = fixture.draft.input_max;
        assert!(one_sided.validate(&fixture.challenge, &fixture.draft).is_err());

        let mut loses_interior = fixture.review;
        loses_interior.admitted_input_min = -1;
        assert!(loses_interior.validate(&fixture.challenge, &fixture.draft).is_err());
    }

    #[test]
    fn tester_must_choose_runtime_inputs_and_exact_host_checked_cases() {
        let fixture = fixture();
        let mut wrong_output = fixture.plan.clone();
        wrong_output.cases[2].expected_output += 1;
        assert!(wrong_output
            .validate(&fixture.challenge, &fixture.draft, &fixture.review)
            .is_err());

        let mut reordered = fixture.plan.clone();
        reordered.cases.swap(0, 1);
        assert!(reordered.validate(&fixture.challenge, &fixture.draft, &fixture.review).is_err());

        let mut missing = fixture.plan.clone();
        missing.cases.pop();
        assert!(missing.validate(&fixture.challenge, &fixture.draft, &fixture.review).is_err());

        let mut decorative = fixture.plan;
        decorative.local_input = fixture.review.admitted_input_max;
        assert!(decorative.validate(&fixture.challenge, &fixture.draft, &fixture.review).is_err());
    }

    #[test]
    fn final_rejects_wrong_reordered_missing_links_and_projection_mutation() {
        let fixture = fixture();
        let mut wrong = fixture.approval.clone();
        wrong.predecessor_hashes[0] = gawdfn::sha256_digest(b"wrong");
        assert!(wrong
            .validate(&fixture.challenge, &fixture.draft, &fixture.review, &fixture.plan)
            .is_err());

        let mut reordered = fixture.approval.clone();
        reordered.predecessor_hashes.swap(1, 2);
        assert!(reordered
            .validate(&fixture.challenge, &fixture.draft, &fixture.review, &fixture.plan)
            .is_err());

        let mut missing = serde_json::to_value(&fixture.approval).unwrap();
        missing["predecessor_hashes"].as_array_mut().unwrap().pop();
        assert!(FinalApprovalV1::decode_json(&serde_json::to_vec(&missing).unwrap()).is_err());

        let mut mutation = fixture.approval;
        mutation.normalized_spec.local_input -= 1;
        assert!(mutation
            .validate(&fixture.challenge, &fixture.draft, &fixture.review, &fixture.plan)
            .is_err());
    }

    #[test]
    fn semantic_digest_excludes_names_nonces_and_test_choices() {
        let first = fixture();
        let challenge = ChallengeV1::new("another-challenge-0000001");
        challenge.validate().unwrap();
        let mut draft = first.draft.clone();
        draft.challenge_hash = challenge.hash().unwrap();
        draft.name = "Three Then Less".into();
        draft.slug = "three-then-less".into();
        draft.entrypoint = "three_then_less".into();
        draft.description = "Applies a bounded signed affine transform.".into();
        let review = ReviewerDecisionV1 {
            schema: REVIEWER_DECISION_SCHEMA_V1.into(),
            challenge_hash: challenge.hash().unwrap(),
            draft_hash: draft.hash(&challenge).unwrap(),
            admitted_input_min: first.review.admitted_input_min,
            admitted_input_max: first.review.admitted_input_max,
        };
        let mut plan = first.plan.clone();
        plan.challenge_hash = challenge.hash().unwrap();
        plan.draft_hash = draft.hash(&challenge).unwrap();
        plan.review_hash = review.hash(&challenge, &draft).unwrap();
        plan.local_input = 2;
        plan.remote_input = -3;
        plan.cases[1] = case(ContractCaseKindV1::RemoteNegativeInterior, -3, 3, -5);
        plan.cases[3] = case(ContractCaseKindV1::LocalPositiveInterior, 2, 3, -5);
        let second = FinalCapabilitySpecV1::from_chain(&challenge, &draft, &review, &plan).unwrap();

        assert_ne!(first.challenge.hash().unwrap(), challenge.hash().unwrap());
        assert_eq!(first.approval.normalized_spec.semantic_digest, second.semantic_digest);
    }

    #[test]
    fn fixture_digest_rejection_cannot_be_evaded_with_cosmetic_changes() {
        let fixture = fixture();
        let forbidden = vec![fixture.approval.normalized_spec.semantic_digest.clone()];
        assert!(fixture
            .approval
            .validate_with_forbidden_semantics(
                &fixture.challenge,
                &fixture.draft,
                &fixture.review,
                &fixture.plan,
                &forbidden,
            )
            .is_err());
        fixture
            .approval
            .validate_with_forbidden_semantics(
                &fixture.challenge,
                &fixture.draft,
                &fixture.review,
                &fixture.plan,
                &[gawdfn::sha256_digest(b"different")],
            )
            .unwrap();
    }

    #[test]
    fn prompts_are_bounded_self_delimiting_and_do_not_embed_future_answers_or_source() {
        let fixture = fixture();
        let prompts = [
            builder_prompt(&fixture.challenge).unwrap(),
            reviewer_prompt(&fixture.challenge, &fixture.draft).unwrap(),
            contract_tester_prompt(&fixture.challenge, &fixture.draft, &fixture.review).unwrap(),
            final_approval_prompt(
                &fixture.challenge,
                &fixture.draft,
                &fixture.review,
                &fixture.plan,
            )
            .unwrap(),
        ];
        for prompt in &prompts {
            assert!(prompt.len() <= MAX_DECISION_PROMPT_BYTES);
            assert!(!prompt.contains("fn handle"));
            assert!(!prompt.contains("gawd_creature_v1"));
            assert!(!prompt.contains("(module"));
        }

        let draft_json = String::from_utf8(canonical_json(&fixture.draft).unwrap()).unwrap();
        let review_json = String::from_utf8(canonical_json(&fixture.review).unwrap()).unwrap();
        let plan_json = String::from_utf8(canonical_json(&fixture.plan).unwrap()).unwrap();
        let approval_json = String::from_utf8(canonical_json(&fixture.approval).unwrap()).unwrap();
        assert!(!prompts[0].contains(&draft_json));
        assert!(!prompts[1].contains(&review_json));
        assert!(!prompts[2].contains(&plan_json));
        assert!(!prompts[3].contains(&approval_json));

        let challenge_json = canonical_json(&fixture.challenge).unwrap();
        assert!(prompts[0].contains(&format!("CHALLENGE:{}\n", challenge_json.len())));
    }

    #[test]
    fn canonical_hash_ignores_object_key_order_but_not_array_order() {
        let fixture = fixture();
        let normal = fixture.challenge.hash().unwrap();
        let shuffled = format!(
            "{{\"max_semantic_nodes\":5,\"max_addend\":1000000,\"min_addend\":-1000000,\"max_multiplier\":16,\"min_multiplier\":-16,\"max_domain_points\":257,\"input_ceiling\":1000000,\"input_floor\":-1000000,\"capability_kind\":\"affine_i32_v1\",\"objective\":{},\"challenge_nonce\":\"fixture-challenge-00000001\",\"schema\":\"alpha.dialogue.challenge.v1\"}}",
            serde_json::to_string(CHALLENGE_OBJECTIVE_V1).unwrap()
        );
        let decoded = ChallengeV1::decode_json(shuffled.as_bytes()).unwrap();
        assert_eq!(decoded.hash().unwrap(), normal);
    }
}
