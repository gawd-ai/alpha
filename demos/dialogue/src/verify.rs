//! Independent, offline verification of one retained live dialogue acceptance bundle.
//!
//! This path consumes only the packaged candidate binary, an operator-pinned candidate commit and
//! evidence-seal key, the signed seal, and the sealed evidence directory. It does not consult a
//! provider, a Bestiary store, a running Sanctum, Git, or any private key.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use agent_mind::{
    AffineI32SpecV1, ApprovedImplementationV1, ApprovedProgramKindV1, ApprovedTier,
    ApprovedTypedProfile, APPROVED_IMPLEMENTATION_V1,
};
use bestiary::EntryProof;
use gawdfn::{
    DeliveryModeV1, EvidenceRefV1, ExecutionReceiptV1, FunctionAlias, FunctionId,
    FunctionSelectorV1, JobStateV1, SignedRecordV1,
};
use mind::Prompt;
use seer::topics::dialogue::{AnswerBody, Provenance};
use serde::de::DeserializeOwned;
use serde::Serialize;
use sigil::{Backend, Ed25519Verifier, Manifest, Verifier};

use crate::decisions::{
    builder_prompt, contract_tester_prompt, final_approval_prompt, reviewer_prompt, BuilderDraftV1,
    ChallengeV1, ContractTestPlanV1, FinalApprovalV1, FinalCapabilitySpecV1, ReviewerDecisionV1,
    FINAL_CAPABILITY_SCHEMA_V1,
};
use crate::evidence::{
    prompt_sha256, read_secure_signed_evidence_seal, secure_external_file_sha256,
    CollaborationApprovalSummaryV1, EngineRunSummaryV1, EngineTierV1, EvidenceDirectory,
    EvidenceReferenceV1, FinalRunSummaryV1, ModelCallOutcomeV1, ModelCallRecordV1,
    ModelReplayEntryV1, VerifiedEvidenceDirectory, VerifiedSignedDialogueTurnV1,
};
use crate::function_proof::RetainedJobProofV1;
use crate::ExecutionResultEvidenceV1;

const FINAL_SUMMARY_FILE: &str = "final-run-summary.v1.json";
const APPROVAL_SUMMARY_FILE: &str = "collaboration-approval.v1.json";
const MODEL_CALLS_FILE: &str = "model-calls.v1.json";
const MODEL_REPLAY_FILE: &str = "model-replay.v1.json";
const SIGNED_TURNS_FILE: &str = "signed-dialogue-turns.v1.json";
const CHALLENGE_FILE: &str = "challenge.v1.json";
const DRAFT_FILE: &str = "builder-draft.v1.json";
const REVIEW_FILE: &str = "reviewer-decision.v1.json";
const TEST_PLAN_FILE: &str = "contract-test-plan.v1.json";
const FINAL_APPROVAL_FILE: &str = "final-approval.v1.json";
const APPROVED_PROFILE_FILE: &str = "approved-profile.v1.json";

const FIXTURE_SEMANTIC_INPUT_MIN: i32 = -64;
const FIXTURE_SEMANTIC_INPUT_MAX: i32 = 64;
const FIXTURE_SEMANTIC_MULTIPLIER: i32 = 3;
const FIXTURE_SEMANTIC_ADDEND: i32 = -5;

const BUILDER_INSTRUCTIONS: &str = "You are Alpha's Builder mind. Follow the requested strict JSON schema exactly. On the first turn originate a novel bounded affine capability; on the final turn integrate the exact validated Reviewer and Contract Tester records. Never emit source code, dependencies, capabilities, prose, Markdown, or fields outside the requested record.";
const REVIEWER_INSTRUCTIONS: &str = "You are Alpha's Reviewer mind. Return only the requested strict JSON record. Make a material safety decision by narrowing both bounds of the Builder's exact candidate domain; do not emit source, prose, or advisory-only commentary.";
const CONTRACT_TESTER_INSTRUCTIONS: &str = "You are Alpha's Contract Tester mind. Return only the requested strict JSON record. Choose the actual local and cross-Realm inputs and the exact ordered boundary/interior cases from the validated Builder and Reviewer records; do not emit source or prose.";

/// All external trust and identity inputs required by the offline verifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfflineVerificationInputs {
    pub expected_seal_signer_public_key: String,
    pub candidate_sha: String,
    pub packaged_binary_path: PathBuf,
    pub evidence_dir: PathBuf,
    pub signed_seal_path: PathBuf,
    pub forbidden_prior_semantic_digests: Vec<String>,
}

/// Deliberately compact, secret-free success output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedLiveEvidence {
    pub index_sha256: String,
    pub semantic_sha256: String,
    pub binary_sha256: String,
    pub builder_model: String,
    pub reviewer_model: String,
    pub contract_tester_model: String,
}

struct VerifiedModelLabels {
    builder: String,
    reviewer: String,
    contract_tester: String,
}

#[derive(Clone, Copy)]
struct TierSpec {
    label: &'static str,
    summary_tier: EngineTierV1,
    approved_tier: ApprovedTier,
    backend: Backend,
}

const TIERS: [TierSpec; 3] = [
    TierSpec {
        label: "daemon",
        summary_tier: EngineTierV1::Daemon,
        approved_tier: ApprovedTier::Daemon,
        backend: Backend::Daemon,
    },
    TierSpec {
        label: "beast",
        summary_tier: EngineTierV1::Beast,
        approved_tier: ApprovedTier::Beast,
        backend: Backend::Beast,
    },
    TierSpec {
        label: "critter",
        summary_tier: EngineTierV1::Critter,
        approved_tier: ApprovedTier::Critter,
        backend: Backend::Critter,
    },
];

struct DecisionEvidence {
    challenge: ChallengeV1,
    draft: BuilderDraftV1,
    review: ReviewerDecisionV1,
    plan: ContractTestPlanV1,
    approval: FinalApprovalV1,
    profile: ApprovedTypedProfile,
    approval_digest: String,
}

struct TierEvidence {
    function: FunctionId,
    alias: FunctionAlias,
    artifact_hash: String,
    manifest_author: String,
    bestiary_attester: String,
    local_result_hash: String,
    remote_result_hash: String,
    job_handles: [String; 2],
}

/// Verify one sealed live run without consulting live services or mutable source state.
pub fn verify_live_evidence(
    inputs: &OfflineVerificationInputs,
) -> Result<VerifiedLiveEvidence, String> {
    validate_public_key(&inputs.expected_seal_signer_public_key)?;
    validate_candidate_sha(&inputs.candidate_sha)?;
    let forbidden = normalized_forbidden_semantics(&inputs.forbidden_prior_semantic_digests)?;

    // Trust policy comes before crypto mechanism: never spend verification on a self-named key
    // until it equals the operator's pin.
    let signed = read_secure_signed_evidence_seal(&inputs.signed_seal_path)
        .map_err(|error| format!("signed evidence seal was refused: {error}"))?;
    if signed.signer_public_key != inputs.expected_seal_signer_public_key {
        return Err("signed evidence seal does not use the operator-pinned public key".into());
    }
    signed
        .verify_signature(&Ed25519Verifier)
        .map_err(|error| format!("signed evidence seal was refused: {error}"))?;
    require_seal_sibling_path(
        &inputs.evidence_dir,
        &inputs.signed_seal_path,
        &signed.seal.index_sha256,
    )?;

    let verified = EvidenceDirectory::verify(&inputs.evidence_dir, &signed.seal)
        .map_err(|error| format!("sealed evidence directory was refused: {error}"))?;
    require_exact_file_set(&verified)?;

    let summary: FinalRunSummaryV1 = read_json(&verified, FINAL_SUMMARY_FILE)?;
    summary.validate().map_err(|error| format!("final run summary was refused: {error}"))?;
    verify_source_identity(&summary, inputs)?;
    verify_top_level_references(&verified, &summary)?;

    let approval_summary: CollaborationApprovalSummaryV1 =
        read_json(&verified, APPROVAL_SUMMARY_FILE)?;
    approval_summary
        .validate()
        .map_err(|error| format!("collaboration approval summary was refused: {error}"))?;
    require_index_digest(&verified, APPROVAL_SUMMARY_FILE, &summary.approval_summary_sha256)?;

    let decisions = verify_decision_chain(&verified, &summary, &approval_summary, &forbidden)?;
    let turns = verify_signed_turns(&verified, &decisions, &approval_summary)?;
    let model_labels = verify_model_calls_and_replay(&verified, &decisions, &turns)?;

    let mut tier_evidence = Vec::with_capacity(TIERS.len());
    for tier in TIERS {
        let run = summary
            .engine_runs
            .iter()
            .find(|run| run.tier == tier.summary_tier)
            .ok_or_else(|| format!("final summary omitted the {} engine", tier.label))?;
        tier_evidence.push(verify_tier(
            &verified,
            tier,
            run,
            &decisions.profile,
            &decisions.approval_digest,
        )?);
    }
    verify_cross_tier_invariants(&summary, &tier_evidence, &turns)?;

    Ok(VerifiedLiveEvidence {
        index_sha256: verified.index_sha256().to_string(),
        semantic_sha256: bare_digest(&decisions.approval.normalized_spec.semantic_digest)?,
        binary_sha256: summary.source.binary_sha256,
        builder_model: model_labels.builder,
        reviewer_model: model_labels.reviewer,
        contract_tester_model: model_labels.contract_tester,
    })
}

fn verify_source_identity(
    summary: &FinalRunSummaryV1,
    inputs: &OfflineVerificationInputs,
) -> Result<(), String> {
    summary.source.validate().map_err(|error| error.to_string())?;
    summary.source.require_matching_build_commit().map_err(|error| error.to_string())?;
    if !summary.source.worktree_clean
        || summary.source.git_commit != inputs.candidate_sha
        || summary.source.binary_build_commit.as_deref() != Some(inputs.candidate_sha.as_str())
    {
        return Err("final summary is not bound to the pinned clean candidate/build commit".into());
    }
    let packaged_hash = secure_external_file_sha256(&inputs.packaged_binary_path)
        .map_err(|error| format!("packaged candidate binary was refused: {error}"))?;
    if packaged_hash != summary.source.binary_sha256 {
        return Err("packaged candidate binary hash differs from retained source identity".into());
    }
    Ok(())
}

fn verify_top_level_references(
    verified: &VerifiedEvidenceDirectory,
    summary: &FinalRunSummaryV1,
) -> Result<(), String> {
    if summary.topology.authoring_realm != "builders"
        || summary.topology.authoring_node != "builder-agent"
        || summary.topology.execution_realm != "builders"
        || summary.topology.execution_node != "builder-executor"
    {
        return Err("final summary changed the required authoring/execution topology".into());
    }
    for (reference, expected_file) in [
        (&summary.model_calls, MODEL_CALLS_FILE),
        (&summary.replay_entries, MODEL_REPLAY_FILE),
        (&summary.signed_dialogue_turns, SIGNED_TURNS_FILE),
    ] {
        require_reference(verified, reference, expected_file)?;
    }
    let names = [
        summary.model_calls.file.as_str(),
        summary.replay_entries.file.as_str(),
        summary.signed_dialogue_turns.file.as_str(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let digests = [
        summary.model_calls.sha256.as_str(),
        summary.replay_entries.sha256.as_str(),
        summary.signed_dialogue_turns.sha256.as_str(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    if names.len() != 3 || digests.len() != 3 {
        return Err("final summary top-level evidence references are not unique".into());
    }
    Ok(())
}

fn verify_decision_chain(
    verified: &VerifiedEvidenceDirectory,
    summary: &FinalRunSummaryV1,
    approval_summary: &CollaborationApprovalSummaryV1,
    forbidden: &[String],
) -> Result<DecisionEvidence, String> {
    let challenge: ChallengeV1 = read_json(verified, CHALLENGE_FILE)?;
    let draft: BuilderDraftV1 = read_json(verified, DRAFT_FILE)?;
    let review: ReviewerDecisionV1 = read_json(verified, REVIEW_FILE)?;
    let plan: ContractTestPlanV1 = read_json(verified, TEST_PLAN_FILE)?;
    let approval: FinalApprovalV1 = read_json(verified, FINAL_APPROVAL_FILE)?;
    let approved_profile: FinalCapabilitySpecV1 = read_json(verified, APPROVED_PROFILE_FILE)?;

    challenge.validate().map_err(|error| error.to_string())?;
    let nonce = challenge
        .challenge_nonce
        .strip_prefix("live:")
        .ok_or_else(|| "retained challenge is not a live-run challenge".to_string())?;
    validate_public_key(nonce).map_err(|_| "live challenge nonce is malformed".to_string())?;
    draft.validate(&challenge).map_err(|error| error.to_string())?;
    review.validate(&challenge, &draft).map_err(|error| error.to_string())?;
    plan.validate(&challenge, &draft, &review).map_err(|error| error.to_string())?;
    approval
        .validate_with_forbidden_semantics(&challenge, &draft, &review, &plan, forbidden)
        .map_err(|error| error.to_string())?;
    if approved_profile != approval.normalized_spec {
        return Err("approved profile file differs from the exact final approval projection".into());
    }

    let challenge_digest = bare_digest(&challenge.hash().map_err(|error| error.to_string())?)?;
    let approval_digest =
        approval.hash(&challenge, &draft, &review, &plan).map_err(|error| error.to_string())?;
    if summary.run_id != challenge.challenge_nonce
        || summary.challenge_sha256 != challenge_digest
        || approval_summary.challenge_sha256 != challenge_digest
        || approval_summary.approval_payload_sha256 != bare_digest(&approval_digest)?
        || approval_summary.approved_profile_schema != FINAL_CAPABILITY_SCHEMA_V1
        || approval_summary.semantic_sha256
            != bare_digest(&approval.normalized_spec.semantic_digest)?
    {
        return Err("summary hashes do not bind the exact validated decision chain".into());
    }

    let spec = agent_profile_spec(&approval.normalized_spec);
    let profile_digest = ApprovedTypedProfile::canonical_digest(&spec)
        .map_err(|error| format!("approved profile was refused: {error}"))?;
    let semantic_digest = ApprovedTypedProfile::canonical_semantic_digest(&spec)
        .map_err(|error| format!("approved profile was refused: {error}"))?;
    if profile_digest != format!("sha256:{}", approval_summary.approved_profile_sha256)
        || semantic_digest != approval.normalized_spec.semantic_digest
    {
        return Err("AgentMind profile hashes differ from the approved decision hashes".into());
    }
    let profile = ApprovedTypedProfile::from_approved(spec, &profile_digest)
        .map_err(|error| format!("approved profile was refused: {error}"))?;

    Ok(DecisionEvidence { challenge, draft, review, plan, approval, profile, approval_digest })
}

fn verify_signed_turns(
    verified: &VerifiedEvidenceDirectory,
    decisions: &DecisionEvidence,
    approval_summary: &CollaborationApprovalSummaryV1,
) -> Result<Vec<VerifiedSignedDialogueTurnV1>, String> {
    let turns: Vec<VerifiedSignedDialogueTurnV1> = read_json(verified, SIGNED_TURNS_FILE)?;
    if turns.len() != 4 || approval_summary.contributors.len() != 3 {
        return Err("live evidence requires exactly four turns and three contributors".into());
    }
    let prompts = [
        builder_prompt(&decisions.challenge).map_err(|error| error.to_string())?,
        reviewer_prompt(&decisions.challenge, &decisions.draft)
            .map_err(|error| error.to_string())?,
        contract_tester_prompt(&decisions.challenge, &decisions.draft, &decisions.review)
            .map_err(|error| error.to_string())?,
        final_approval_prompt(
            &decisions.challenge,
            &decisions.draft,
            &decisions.review,
            &decisions.plan,
        )
        .map_err(|error| error.to_string())?,
    ];
    let expected_roles = ["builder", "reviewer", "contract-tester", "builder"];
    let expected_corr = [900_000, 910_000, 920_000, 900_001];
    let signer_keys = [
        approval_summary.contributors[0].signer_public_key.as_str(),
        approval_summary.contributors[1].signer_public_key.as_str(),
        approval_summary.contributors[2].signer_public_key.as_str(),
        approval_summary.contributors[0].signer_public_key.as_str(),
    ];
    if signer_keys[..3].iter().copied().collect::<BTreeSet<_>>().len() != 3 {
        return Err("Builder, Reviewer, and Contract Tester signer keys are not distinct".into());
    }
    let mut hashes = Vec::with_capacity(4);
    for index in 0..4 {
        let turn = &turns[index];
        turn.validate().map_err(|error| error.to_string())?;
        if turn.turn_ordinal != index as u64
            || turn.role != expected_roles[index]
            || turn.correlation_id != expected_corr[index]
            || turn.prompt_sha256 != hash_bytes(prompts[index].as_bytes())
            || turn.causal_predecessor_turn_sha256 != hashes
            || turn.pinned_signer_public_key != signer_keys[index]
        {
            return Err(format!("signed dialogue turn {index} changed identity or causal order"));
        }
        validate_public_key(signer_keys[index])?;
        let answer: AnswerBody = serde_json::from_str(&turn.signed_answer_body_utf8)
            .map_err(|_| format!("signed dialogue turn {index} is not an AnswerBody"))?;
        if answer.signer_pubkey.as_deref() != Some(signer_keys[index]) {
            return Err(format!(
                "signed dialogue turn {index} is not bound to its pinned role key"
            ));
        }
        if aether::wire::to_bytes(&answer) != turn.signed_answer_body_utf8.as_bytes()
            || turn.reply_sha256 != hash_bytes(answer.reply.as_bytes())
        {
            return Err(format!("signed dialogue turn {index} changed its exact answer bytes"));
        }
        match answer.verify_provenance(turn.correlation_id, &prompts[index], &Ed25519Verifier) {
            Provenance::Verified(key) if key == signer_keys[index] => {}
            _ => return Err(format!("signed dialogue turn {index} signature did not verify")),
        }
        verify_turn_reply(index, &answer.reply, decisions)?;
        hashes.push(hash_json(turn)?);
    }

    let expected_contributors = ["builder", "reviewer", "contract-tester"];
    for index in 0..3 {
        let contributor = &approval_summary.contributors[index];
        if contributor.role != expected_contributors[index]
            || contributor.signed_turn_sha256 != hashes[index]
            || contributor.signer_public_key != turns[index].pinned_signer_public_key
        {
            return Err(
                "approval contributor bindings differ from the first three signed turns".into()
            );
        }
    }
    if approval_summary.final_builder_turn_sha256 != hashes[3]
        || turns[3].pinned_signer_public_key != turns[0].pinned_signer_public_key
    {
        return Err(
            "final Builder turn is not bound to the originating Builder and approval".into()
        );
    }
    Ok(turns)
}

fn verify_turn_reply(
    index: usize,
    reply: &str,
    decisions: &DecisionEvidence,
) -> Result<(), String> {
    let equal = match index {
        0 => serde_json::from_str::<BuilderDraftV1>(reply)
            .map(|value| value == decisions.draft)
            .unwrap_or(false),
        1 => serde_json::from_str::<ReviewerDecisionV1>(reply)
            .map(|value| value == decisions.review)
            .unwrap_or(false),
        2 => serde_json::from_str::<ContractTestPlanV1>(reply)
            .map(|value| value == decisions.plan)
            .unwrap_or(false),
        3 => serde_json::from_str::<FinalApprovalV1>(reply)
            .map(|value| value == decisions.approval)
            .unwrap_or(false),
        _ => false,
    };
    if !equal {
        return Err(format!("signed dialogue reply {index} differs from its retained decision"));
    }
    Ok(())
}

fn verify_model_calls_and_replay(
    verified: &VerifiedEvidenceDirectory,
    decisions: &DecisionEvidence,
    turns: &[VerifiedSignedDialogueTurnV1],
) -> Result<VerifiedModelLabels, String> {
    let calls: Vec<ModelCallRecordV1> = read_json(verified, MODEL_CALLS_FILE)?;
    let replay: Vec<ModelReplayEntryV1> = read_json(verified, MODEL_REPLAY_FILE)?;
    if calls.len() != 7 || replay.len() != 7 {
        return Err("live evidence requires exactly seven model calls and replay entries".into());
    }
    let expected_roles = [
        ("builder", 0),
        ("reviewer", 0),
        ("contract-tester", 0),
        ("builder", 1),
        ("builder", 2),
        ("builder", 3),
        ("builder", 4),
    ];
    let dialogue_systems = [
        BUILDER_INSTRUCTIONS,
        REVIEWER_INSTRUCTIONS,
        CONTRACT_TESTER_INSTRUCTIONS,
        BUILDER_INSTRUCTIONS,
    ];
    let dialogue_prompts = [
        builder_prompt(&decisions.challenge).map_err(|error| error.to_string())?,
        reviewer_prompt(&decisions.challenge, &decisions.draft)
            .map_err(|error| error.to_string())?,
        contract_tester_prompt(&decisions.challenge, &decisions.draft, &decisions.review)
            .map_err(|error| error.to_string())?,
        final_approval_prompt(
            &decisions.challenge,
            &decisions.draft,
            &decisions.review,
            &decisions.plan,
        )
        .map_err(|error| error.to_string())?,
    ];
    let mut response_ids = BTreeSet::new();
    for index in 0..7 {
        let call = &calls[index];
        let entry = &replay[index];
        call.validate().map_err(|error| error.to_string())?;
        entry.validate().map_err(|error| error.to_string())?;
        if call.global_ordinal != index as u64
            || entry.global_ordinal != index as u64
            || call.role != expected_roles[index].0
            || entry.role != expected_roles[index].0
            || call.role_ordinal != expected_roles[index].1
            || entry.role_ordinal != expected_roles[index].1
        {
            return Err(format!(
                "model call {index} is missing, reordered, or assigned to the wrong role"
            ));
        }
        let prompt = Prompt {
            system_prompt: entry.prompt.system_prompt.clone(),
            user_prompt: entry.prompt.user_prompt.clone(),
            max_tokens: entry.prompt.max_tokens,
            temperature: f32::from_bits(entry.prompt.temperature_bits),
        };
        if prompt_sha256(&prompt).map_err(|error| error.to_string())? != entry.prompt.sha256
            || call.prompt.sha256 != entry.prompt.sha256
            || call.prompt.system_prompt_bytes != entry.prompt.system_prompt.len() as u64
            || call.prompt.user_prompt_bytes != entry.prompt.user_prompt.len() as u64
            || call.prompt.max_tokens != entry.prompt.max_tokens
            || call.prompt.temperature_bits != entry.prompt.temperature_bits
        {
            return Err(format!("model call {index} differs from its exact replay prompt"));
        }
        if index < 4 {
            if entry.prompt.system_prompt != dialogue_systems[index]
                || entry.prompt.user_prompt != dialogue_prompts[index]
                || entry.prompt.max_tokens != 4096
                || entry.prompt.temperature_bits != 0.2_f32.to_bits()
                || entry.completion.content != signed_turn_answer(&turns[index])?.reply
            {
                return Err(format!("dialogue model replay {index} differs from the signed turn"));
            }
        } else {
            let tier = TIERS[index - 4];
            verify_authoring_replay(entry, &decisions.profile, tier.approved_tier)?;
        }
        let ModelCallOutcomeV1::Completed {
            completion_sha256,
            completion_bytes,
            responding_model,
            usage,
            provider_receipt: Some(receipt),
        } = &call.outcome
        else {
            return Err(format!("model call {index} was not completed with a provider receipt"));
        };
        if completion_sha256 != &entry.completion.sha256
            || *completion_bytes != entry.completion.content.len() as u64
            || responding_model != &entry.completion.model
            || usage != &entry.completion.usage
            || entry.completion.provider.as_ref() != Some(receipt)
        {
            return Err(format!("model call {index} differs from its exact replay completion"));
        }
        let response_id = receipt
            .response_id
            .as_deref()
            .ok_or_else(|| format!("model call {index} omitted its provider response id"))?;
        if !response_ids.insert(response_id)
            || receipt.reported_model.as_deref() != Some(responding_model.as_str())
            || receipt.finish_reason.as_deref() != Some("stop")
            || receipt.store_requested
            || call.config.timeout_ms == 0
            || !live_origin_is_confidential_or_loopback(
                call.config
                    .endpoint_origin
                    .as_deref()
                    .ok_or_else(|| format!("model call {index} omitted its endpoint origin"))?,
            )
        {
            return Err(format!(
                "model call {index} has invalid live provider receipt/configuration"
            ));
        }
        if call.config.provider != "openai-compatible" {
            return Err(format!(
                "model call {index} does not identify the live OpenAI-compatible provider seam"
            ));
        }
    }
    if [3, 4, 5, 6].into_iter().any(|index| calls[index].config != calls[0].config) {
        return Err(
            "Builder dialogue and authoring calls changed their pinned model configuration".into(),
        );
    }
    Ok(VerifiedModelLabels {
        builder: calls[0].config.requested_model.clone(),
        reviewer: calls[1].config.requested_model.clone(),
        contract_tester: calls[2].config.requested_model.clone(),
    })
}

fn signed_turn_answer(turn: &VerifiedSignedDialogueTurnV1) -> Result<AnswerBody, String> {
    serde_json::from_str(&turn.signed_answer_body_utf8)
        .map_err(|_| "signed dialogue turn is not an AnswerBody".to_string())
}

fn verify_authoring_replay(
    entry: &ModelReplayEntryV1,
    profile: &ApprovedTypedProfile,
    tier: ApprovedTier,
) -> Result<(), String> {
    if entry.prompt.system_prompt != approved_system_prompt(tier)
        || entry.prompt.user_prompt != approved_user_prompt(profile, tier)
        || entry.prompt.max_tokens != 512
        || entry.prompt.temperature_bits != 0.0_f32.to_bits()
    {
        return Err(format!(
            "{} authoring replay changed its exact approved prompt",
            tier.as_str()
        ));
    }
    let implementation: ApprovedImplementationV1 = serde_json::from_str(&entry.completion.content)
        .map_err(|_| {
            format!(
                "{} authoring completion is not the bounded implementation record",
                tier.as_str()
            )
        })?;
    if implementation != profile.implementation(tier)
        || implementation.schema != APPROVED_IMPLEMENTATION_V1
    {
        return Err(format!(
            "{} authoring completion differs from the approved profile",
            tier.as_str()
        ));
    }
    Ok(())
}

fn verify_tier(
    verified: &VerifiedEvidenceDirectory,
    tier: TierSpec,
    run: &EngineRunSummaryV1,
    profile: &ApprovedTypedProfile,
    approval_digest: &str,
) -> Result<TierEvidence, String> {
    let source_file = tier_file(tier.label, "source", "bin");
    let manifest_file = tier_file(tier.label, "manifest", "json");
    let artifact_file = tier_file(tier.label, "artifact", "bin");
    let entry_proof_file = tier_file(tier.label, "entry-proof", "json");
    for (file, digest) in [
        (source_file.as_str(), run.source_sha256.as_str()),
        (manifest_file.as_str(), run.manifest_sha256.as_str()),
        (artifact_file.as_str(), run.artifact_sha256.as_str()),
        (entry_proof_file.as_str(), run.entry_proof_sha256.as_str()),
    ] {
        require_index_digest(verified, file, digest)?;
    }
    let source = verified.read(&source_file).map_err(|error| error.to_string())?;
    let manifest_bytes = verified.read(&manifest_file).map_err(|error| error.to_string())?;
    let artifact = verified.read(&artifact_file).map_err(|error| error.to_string())?;
    let entry_proof_bytes = verified.read(&entry_proof_file).map_err(|error| error.to_string())?;
    let manifest = strict_manifest(&manifest_bytes)?;
    let entry_proof: EntryProof = strict_json(&entry_proof_bytes, "Bestiary EntryProof")?;

    verify_manifest_and_artifact(tier, profile, &manifest, &source, &artifact)?;
    let artifact_hash = hash_bytes(&artifact);
    let content_address = manifest
        .content_address
        .as_deref()
        .ok_or_else(|| format!("{} manifest omitted its content address", tier.label))?;
    validate_public_key(&entry_proof.attester)?;
    if !entry_proof.verify(&Ed25519Verifier)
        || entry_proof.realm != aether::RealmId::new("builders")
        || entry_proof.artifact_hash != artifact_hash
        || entry_proof.manifest_hash != content_address
    {
        return Err(format!(
            "{} Bestiary EntryProof did not bind the exact published entry",
            tier.label
        ));
    }
    let function: FunctionId = serde_json::from_str(&run.function_id)
        .map_err(|_| format!("{} summary FunctionId is malformed", tier.label))?;
    if function.manifest_content_address != content_address
        || function.entrypoint != profile.spec().entrypoint
    {
        return Err(format!("{} FunctionId differs from its manifest/profile", tier.label));
    }
    let alias = FunctionAlias {
        realm: "builders".into(),
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        entrypoint: profile.spec().entrypoint.clone(),
    };
    let local = verify_execution(
        verified,
        tier,
        run,
        "local",
        &function,
        &alias,
        &artifact_hash,
        profile.spec().local_input,
        profile.evaluate(profile.spec().local_input).map_err(|error| error.to_string())?,
        approval_digest,
    )?;
    let remote = verify_execution(
        verified,
        tier,
        run,
        "remote",
        &function,
        &alias,
        &artifact_hash,
        profile.spec().remote_input,
        profile.evaluate(profile.spec().remote_input).map_err(|error| error.to_string())?,
        approval_digest,
    )?;
    let manifest_author = manifest
        .provenance
        .author
        .clone()
        .ok_or_else(|| format!("{} manifest omitted its author", tier.label))?;
    Ok(TierEvidence {
        function,
        alias,
        artifact_hash,
        manifest_author,
        bestiary_attester: entry_proof.attester,
        local_result_hash: local.0,
        remote_result_hash: remote.0,
        job_handles: [local.1, remote.1],
    })
}

#[allow(clippy::too_many_arguments)]
fn verify_execution(
    verified: &VerifiedEvidenceDirectory,
    tier: TierSpec,
    run: &EngineRunSummaryV1,
    world: &str,
    function: &FunctionId,
    expected_alias: &FunctionAlias,
    artifact_hash: &str,
    expected_input: i32,
    expected_result: i32,
    approval_digest: &str,
) -> Result<(String, String), String> {
    let (result_file, proof_file, receipt_file, summary_result_hash, summary_receipt_hash) =
        if world == "local" {
            (
                tier_file(tier.label, "local-result", "json"),
                tier_file(tier.label, "local-execution-proof", "json"),
                tier_file(tier.label, "local-receipt", "json"),
                &run.local_result_sha256,
                &run.local_job_receipt_sha256,
            )
        } else {
            (
                tier_file(tier.label, "remote-result", "json"),
                tier_file(tier.label, "cross-realm-execution-proof", "json"),
                tier_file(tier.label, "remote-receipt", "json"),
                &run.cross_realm_result_sha256,
                &run.cross_realm_job_receipt_sha256,
            )
        };
    require_index_digest(verified, &result_file, summary_result_hash)?;
    require_index_digest(verified, &receipt_file, summary_receipt_hash)?;
    let result_bytes = verified.read(&result_file).map_err(|error| error.to_string())?;
    let proof_bytes = verified.read(&proof_file).map_err(|error| error.to_string())?;
    let receipt_bytes = verified.read(&receipt_file).map_err(|error| error.to_string())?;
    let result: ExecutionResultEvidenceV1 = strict_json(&result_bytes, "execution result")?;
    if result.execution_proof.file != proof_file
        || result.terminal_receipt.file != receipt_file
        || result.execution_proof.sha256 != index_digest(verified, &proof_file)?
        || result.terminal_receipt.sha256 != index_digest(verified, &receipt_file)?
    {
        return Err(format!(
            "{} {world} result references do not uniquely match sealed files",
            tier.label
        ));
    }
    result.verify_files(&proof_bytes, &receipt_bytes)?;
    let proof: RetainedJobProofV1 = strict_json(&proof_bytes, "execution proof bundle")?;
    let receipt: SignedRecordV1<ExecutionReceiptV1> =
        strict_json(&receipt_bytes, "terminal execution receipt")?;
    proof.validate()?;
    if world == "local" {
        proof.validate_topology("builders", "builder-executor", "builders", "builder-executor")?;
    } else {
        proof.validate_topology("reviewers", "reviewer-home", "builders", "builder-executor")?;
    }
    let accepted_spec = match &proof.acceptance.payload.kind {
        gawdfn::JobEventKindV1::Submitted { spec } => spec.as_ref(),
        _ => return Err(format!("{} {world} proof acceptance is not Submitted", tier.label)),
    };
    let expected_selector = FunctionSelectorV1::Alias { alias: expected_alias.clone() };
    if &proof.grant.payload.function != function
        || &proof.deployment.payload.function != function
        || proof.submission.payload.function != expected_selector
        || accepted_spec.function.requested != expected_selector
        || proof.deployment.payload.artifact_hash != artifact_hash
        || proof.input_i32()? != expected_input
        || proof.result_i32()? != expected_result
        || proof.attempt_count() != 1
        || receipt != proof.terminal_receipt
        || proof.submission.payload.delivery != DeliveryModeV1::AtMostOnce
        || proof.submission.payload.allow_duplicate_effects
        || proof.complete_home_events[2].payload.state_after != JobStateV1::Dispatching
        || proof.complete_home_events[3].payload.state_after != JobStateV1::Running
        || !exact_approval_evidence(&proof.submission.payload.evidence, approval_digest)
        || !exact_approval_evidence(&proof.deployment.payload.evidence, approval_digest)
    {
        return Err(format!(
            "{} {world} proof changed its Function, result, attempt, or approval",
            tier.label
        ));
    }
    if !exact_approval_evidence(&accepted_spec.evidence, approval_digest) {
        return Err(format!(
            "{} {world} accepted Job omitted the exact approval evidence",
            tier.label
        ));
    }
    let handle =
        format!("{}:{}", proof.grant.payload.attempt.home, proof.grant.payload.attempt.job);
    Ok((hash_bytes(&result_bytes), handle))
}

fn verify_manifest_and_artifact(
    tier: TierSpec,
    profile: &ApprovedTypedProfile,
    manifest: &Manifest,
    source: &[u8],
    artifact: &[u8],
) -> Result<(), String> {
    manifest.validate().map_err(|error| error.to_string())?;
    let stub = profile.manifest_stub(tier.approved_tier);
    if manifest.name != stub.name
        || manifest.version != stub.version
        || manifest.entrypoints != stub.entrypoints
        || manifest.capabilities != stub.capabilities
        || manifest.provides != stub.provides
        || manifest.requirements != Default::default()
        || manifest.abi.backend != tier.backend
        || manifest.provenance.realm.is_some()
    {
        return Err(format!(
            "{} manifest differs from the trusted approved-profile stub",
            tier.label
        ));
    }
    match tier.backend {
        Backend::Daemon => {
            if manifest.abi.abi_tag != aether::ffi::ABI_TAG
                || manifest.abi.target.len() != 1
                || manifest.abi.target.first().map(String::as_str)
                    != Some("x86_64-unknown-linux-gnu")
                || !is_x86_64_shared_elf(artifact)
            {
                return Err("daemon artifact/manifest has the wrong native ABI or target".into());
            }
        }
        Backend::Beast => {
            if manifest.abi.abi_tag != aether::ffi::ABI_TAG
                || manifest.abi.target.len() != 1
                || manifest.abi.target.first().map(String::as_str) != Some("wasm32-unknown-unknown")
                || wat::parse_bytes(source)
                    .map_err(|_| "trusted beast source is not valid WAT".to_string())?
                    .as_ref()
                    != artifact
            {
                return Err("beast artifact differs from the exact WAT source or ABI".into());
            }
        }
        Backend::Critter => {
            if manifest.abi.abi_tag != anima::CRITTER_ABI_TAG
                || !manifest.abi.target.is_empty()
                || source != artifact
            {
                return Err("critter artifact differs from the identity source or ABI".into());
            }
        }
    }
    let expected_source = profile.rendered_source(tier.approved_tier);
    if source != expected_source.as_bytes() {
        return Err(format!("{} source differs from the audited trusted lowering", tier.label));
    }
    let source_hash = hash_bytes(source);
    let artifact_hash = hash_bytes(artifact);
    let computed_content_address = manifest.compute_content_address();
    if manifest.provenance.source_hash.as_deref() != Some(source_hash.as_str())
        || manifest.provenance.build_hash.as_deref() != Some(artifact_hash.as_str())
        || manifest.content_address.as_deref() != Some(computed_content_address.as_str())
    {
        return Err(format!("{} manifest provenance hashes are stale", tier.label));
    }
    let author = manifest
        .provenance
        .author
        .as_deref()
        .ok_or_else(|| format!("{} manifest omitted its author", tier.label))?;
    let signature = manifest
        .provenance
        .signature
        .as_deref()
        .ok_or_else(|| format!("{} manifest omitted its signature", tier.label))?;
    validate_public_key(author)?;
    if !Ed25519Verifier.verify(author, &manifest.signing_payload(), signature) {
        return Err(format!("{} manifest signature did not verify", tier.label));
    }
    Ok(())
}

fn verify_cross_tier_invariants(
    summary: &FinalRunSummaryV1,
    tiers: &[TierEvidence],
    turns: &[VerifiedSignedDialogueTurnV1],
) -> Result<(), String> {
    if tiers.len() != 3 || turns.len() != 4 {
        return Err("offline verification requires exactly three tier proofs".into());
    }
    let functions = tiers
        .iter()
        .map(|tier| {
            serde_json::to_string(&tier.function)
                .map_err(|_| "verified FunctionId could not be serialized".to_string())
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let aliases = tiers.iter().map(|tier| &tier.alias).collect::<BTreeSet<_>>();
    let artifacts = tiers.iter().map(|tier| tier.artifact_hash.as_str()).collect::<BTreeSet<_>>();
    let authors = tiers.iter().map(|tier| tier.manifest_author.as_str()).collect::<BTreeSet<_>>();
    let attesters =
        tiers.iter().map(|tier| tier.bestiary_attester.as_str()).collect::<BTreeSet<_>>();
    let separated_identities = [
        turns[0].pinned_signer_public_key.as_str(),
        turns[1].pinned_signer_public_key.as_str(),
        turns[2].pinned_signer_public_key.as_str(),
        tiers[0].manifest_author.as_str(),
        tiers[0].bestiary_attester.as_str(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let jobs = tiers
        .iter()
        .flat_map(|tier| tier.job_handles.iter().map(String::as_str))
        .collect::<BTreeSet<_>>();
    let observed_results = tiers
        .iter()
        .flat_map(|tier| [&tier.local_result_hash, &tier.remote_result_hash])
        .cloned()
        .collect::<BTreeSet<_>>();
    let summary_results = summary
        .engine_runs
        .iter()
        .flat_map(|run| [&run.local_result_sha256, &run.cross_realm_result_sha256])
        .cloned()
        .collect::<BTreeSet<_>>();
    let summary_sources =
        summary.engine_runs.iter().map(|run| run.source_sha256.as_str()).collect::<BTreeSet<_>>();
    let summary_manifests =
        summary.engine_runs.iter().map(|run| run.manifest_sha256.as_str()).collect::<BTreeSet<_>>();
    let summary_artifacts =
        summary.engine_runs.iter().map(|run| run.artifact_sha256.as_str()).collect::<BTreeSet<_>>();
    let summary_entry_proofs = summary
        .engine_runs
        .iter()
        .map(|run| run.entry_proof_sha256.as_str())
        .collect::<BTreeSet<_>>();
    let summary_receipts = summary
        .engine_runs
        .iter()
        .flat_map(|run| [&run.local_job_receipt_sha256, &run.cross_realm_job_receipt_sha256])
        .collect::<BTreeSet<_>>();
    if functions.len() != 3
        || aliases.len() != 3
        || artifacts.len() != 3
        || authors.len() != 1
        || attesters.len() != 1
        || authors == attesters
        || separated_identities.len() != 5
        || jobs.len() != 6
        || observed_results.len() != 6
        || summary_results.len() != 6
        || summary_sources.len() != 3
        || summary_manifests.len() != 3
        || summary_artifacts.len() != 3
        || summary_entry_proofs.len() != 3
        || summary_receipts.len() != 6
        || observed_results != summary_results
    {
        return Err(
            "three-tier/six-result identities are not distinct and exactly summary-anchored".into(),
        );
    }
    Ok(())
}

fn exact_approval_evidence(evidence: &[EvidenceRefV1], approval_digest: &str) -> bool {
    evidence
        == [EvidenceRefV1 {
            kind: "dialogue_approval".into(),
            digest: approval_digest.into(),
            issuer: None,
            locator: None,
        }]
}

fn normalized_forbidden_semantics(values: &[String]) -> Result<Vec<String>, String> {
    let mut forbidden = values
        .iter()
        .map(|value| normalize_digest(value, "forbidden prior semantic digest"))
        .collect::<Result<Vec<_>, _>>()?;
    forbidden.push(fixture_semantic_digest()?);
    forbidden.sort();
    forbidden.dedup();
    Ok(forbidden)
}

fn fixture_semantic_digest() -> Result<String, String> {
    let spec = AffineI32SpecV1 {
        kind: ApprovedProgramKindV1::AffineI32V1,
        slug: "fixture-semantic".into(),
        name: "Fixture semantic".into(),
        entrypoint: "fixture_semantic".into(),
        description: "Fixture semantic digest sentinel.".into(),
        input_min: FIXTURE_SEMANTIC_INPUT_MIN,
        input_max: FIXTURE_SEMANTIC_INPUT_MAX,
        multiplier: FIXTURE_SEMANTIC_MULTIPLIER,
        addend: FIXTURE_SEMANTIC_ADDEND,
        local_input: 17,
        remote_input: -19,
    };
    ApprovedTypedProfile::canonical_semantic_digest(&spec).map_err(|error| error.to_string())
}

fn agent_profile_spec(spec: &FinalCapabilitySpecV1) -> AffineI32SpecV1 {
    AffineI32SpecV1 {
        kind: ApprovedProgramKindV1::AffineI32V1,
        slug: spec.slug.clone(),
        name: spec.name.clone(),
        entrypoint: spec.entrypoint.clone(),
        description: spec.description.clone(),
        input_min: spec.input_min,
        input_max: spec.input_max,
        multiplier: spec.multiplier,
        addend: spec.addend,
        local_input: spec.local_input,
        remote_input: spec.remote_input,
    }
}

fn expected_payload_files() -> BTreeSet<String> {
    let mut files = [
        FINAL_SUMMARY_FILE,
        APPROVAL_SUMMARY_FILE,
        MODEL_CALLS_FILE,
        MODEL_REPLAY_FILE,
        SIGNED_TURNS_FILE,
        CHALLENGE_FILE,
        DRAFT_FILE,
        REVIEW_FILE,
        TEST_PLAN_FILE,
        FINAL_APPROVAL_FILE,
        APPROVED_PROFILE_FILE,
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    for tier in TIERS {
        for (kind, extension) in [
            ("source", "bin"),
            ("manifest", "json"),
            ("artifact", "bin"),
            ("entry-proof", "json"),
            ("local-receipt", "json"),
            ("remote-receipt", "json"),
            ("local-execution-proof", "json"),
            ("cross-realm-execution-proof", "json"),
            ("local-result", "json"),
            ("remote-result", "json"),
        ] {
            files.insert(tier_file(tier.label, kind, extension));
        }
    }
    files
}

fn require_exact_file_set(verified: &VerifiedEvidenceDirectory) -> Result<(), String> {
    let expected = expected_payload_files();
    let observed =
        verified.index().files.iter().map(|record| record.file.clone()).collect::<BTreeSet<_>>();
    if expected.len() != 41
        || observed != expected
        || verified.index().files.len() != expected.len()
    {
        return Err("sealed evidence payload is not the exact 41-file live bundle".into());
    }
    Ok(())
}

fn require_seal_sibling_path(
    evidence_dir: &Path,
    seal_path: &Path,
    index_sha256: &str,
) -> Result<(), String> {
    let expected_name = format!("evidence-seal-{index_sha256}.v1.json");
    if evidence_dir.parent() != seal_path.parent()
        || seal_path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str())
    {
        return Err("signed seal is not the exact index-derived evidence-directory sibling".into());
    }
    Ok(())
}

fn require_reference(
    verified: &VerifiedEvidenceDirectory,
    reference: &EvidenceReferenceV1,
    expected_file: &str,
) -> Result<(), String> {
    if reference.file != expected_file {
        return Err(format!("summary reference for {expected_file} changed its exact filename"));
    }
    require_index_digest(verified, expected_file, &reference.sha256)
}

fn require_index_digest(
    verified: &VerifiedEvidenceDirectory,
    file: &str,
    expected: &str,
) -> Result<(), String> {
    if index_digest(verified, file)? != expected {
        return Err(format!("summary digest for {file} differs from the sealed index"));
    }
    Ok(())
}

fn index_digest(verified: &VerifiedEvidenceDirectory, file: &str) -> Result<String, String> {
    verified
        .index()
        .files
        .iter()
        .find(|record| record.file == file)
        .map(|record| record.sha256.clone())
        .ok_or_else(|| format!("sealed index omitted required file {file}"))
}

fn read_json<T: DeserializeOwned + Serialize>(
    verified: &VerifiedEvidenceDirectory,
    file: &str,
) -> Result<T, String> {
    let bytes = verified.read(file).map_err(|error| error.to_string())?;
    strict_json(&bytes, file)
}

fn strict_json<T: DeserializeOwned + Serialize>(bytes: &[u8], label: &str) -> Result<T, String> {
    let raw: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|_| format!("{label} is not valid bounded JSON"))?;
    let value: T = serde_json::from_value(raw.clone())
        .map_err(|_| format!("{label} does not match its required schema"))?;
    let normalized =
        serde_json::to_value(&value).map_err(|_| format!("{label} could not be normalized"))?;
    if normalized != raw {
        return Err(format!("{label} contains unknown or non-schema fields"));
    }
    Ok(value)
}

fn strict_manifest(bytes: &[u8]) -> Result<Manifest, String> {
    let raw: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| "manifest is not valid bounded JSON".to_string())?;
    let manifest = Manifest::parse(bytes).map_err(|error| error.to_string())?;
    if serde_json::to_value(&manifest).map_err(|error| error.to_string())? != raw {
        return Err("manifest contains unknown or non-schema fields".into());
    }
    Ok(manifest)
}

fn tier_file(tier: &str, kind: &str, extension: &str) -> String {
    format!("{tier}-{kind}.v1.{extension}")
}

fn hash_bytes(bytes: &[u8]) -> String {
    gawdfn::sha256_digest(bytes)
        .strip_prefix("sha256:")
        .expect("sha256_digest always prefixes its digest")
        .to_string()
}

fn hash_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value).map(|bytes| hash_bytes(&bytes)).map_err(|error| error.to_string())
}

fn normalize_digest(value: &str, label: &str) -> Result<String, String> {
    let bare = value.strip_prefix("sha256:").unwrap_or(value);
    validate_bare_digest(bare, label)?;
    Ok(format!("sha256:{bare}"))
}

fn bare_digest(value: &str) -> Result<String, String> {
    let bare = value.strip_prefix("sha256:").unwrap_or(value);
    validate_bare_digest(bare, "digest")?;
    Ok(bare.to_string())
}

fn validate_bare_digest(value: &str, label: &str) -> Result<(), String> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{label} must be a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn validate_public_key(value: &str) -> Result<(), String> {
    validate_bare_digest(value, "Ed25519 public key")
}

fn validate_candidate_sha(value: &str) -> Result<(), String> {
    if !matches!(value.len(), 40 | 64)
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("candidate SHA must be an exact lowercase Git object id".into());
    }
    Ok(())
}

fn live_origin_is_confidential_or_loopback(origin: &str) -> bool {
    origin.starts_with("https://")
        || origin == "http://localhost"
        || origin.starts_with("http://localhost:")
        || origin == "http://127.0.0.1"
        || origin.starts_with("http://127.0.0.1:")
        || origin == "http://[::1]"
        || origin.starts_with("http://[::1]:")
}

fn approved_user_prompt(profile: &ApprovedTypedProfile, tier: ApprovedTier) -> String {
    format!(
        "{}\n\nAPPROVED PROFILE (canonical JSON; semantic source of truth):\n{}\nAPPROVED PROFILE DIGEST: {}\nREQUESTED TIER: {}",
        profile.request(tier),
        profile.canonical_spec(),
        profile.digest(),
        tier.as_str()
    )
}

fn approved_system_prompt(tier: ApprovedTier) -> String {
    let boundary = match tier {
        ApprovedTier::Daemon => "Alpha's trusted renderer will produce native Rust that binds its signed manifest identity, verifies the authenticated Function call before decoding, uses checked i32 arithmetic, and continues the exact AttemptId.",
        ApprovedTier::Beast => "Alpha's trusted renderer will produce a closed no-import/no-start core-WASM module. WasmEngine authenticates the Function proof, route, identity, and AttemptId before/after the payload-only guest call.",
        ApprovedTier::Critter => "Alpha's trusted renderer will produce Rhai that verifies the Function proof and exact route before parsing and continues the exact AttemptId in its result.",
    };
    format!(
        "You are the Builder model confirming one causally approved bounded capability for Alpha's {} tier.\n\
The canonical approved profile and its sha256 digest are in the user message. Treat them as immutable.\n\
Return exactly one JSON object and no Markdown, prose, source code, dependencies, manifest, or authority.\n\
The object has exactly four fields: `schema`, `profile_digest`, `tier`, and `program`.\n\
`schema` must be `{APPROVED_IMPLEMENTATION_V1}`; `profile_digest` and `tier` must bind the request.\n\
`program` has exactly `kind`, `multiplier`, and `addend` and must faithfully restate the approved affine_i32_v1 program.\n\
Do not invent values, fields, code, capabilities, controls, or an alternate implementation. {boundary}",
        tier.as_str()
    )
}

fn is_x86_64_shared_elf(bytes: &[u8]) -> bool {
    bytes.len() >= 20
        && &bytes[..4] == b"\x7fELF"
        && bytes[4] == 2
        && bytes[5] == 1
        && bytes[16..18] == [3, 0]
        && bytes[18..20] == [0x3e, 0]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_profile() -> ApprovedTypedProfile {
        let spec = AffineI32SpecV1 {
            kind: ApprovedProgramKindV1::AffineI32V1,
            slug: "triple-minus-five".into(),
            name: "Triple Minus Five".into(),
            entrypoint: "triple_minus_five".into(),
            description: "Multiply a bounded signed integer by three, then subtract five.".into(),
            input_min: -64,
            input_max: 64,
            multiplier: 3,
            addend: -5,
            local_input: 17,
            remote_input: -19,
        };
        let digest = ApprovedTypedProfile::canonical_digest(&spec).unwrap();
        ApprovedTypedProfile::from_approved(spec, &digest).unwrap()
    }

    #[test]
    fn fixture_semantic_is_always_forbidden_and_inputs_normalize() {
        let extra = "11".repeat(32);
        let forbidden = normalized_forbidden_semantics(std::slice::from_ref(&extra)).unwrap();
        assert!(forbidden.contains(&format!("sha256:{extra}")));
        assert!(forbidden.contains(&fixture_semantic_digest().unwrap()));
        assert_eq!(forbidden.len(), 2);
    }

    #[test]
    fn trusted_lowering_is_exact_and_a_source_tamper_changes_it() {
        let profile = fixture_profile();
        for tier in ApprovedTier::ALL {
            let expected = profile.rendered_source(tier);
            assert!(!expected.is_empty());
            let mut tampered = expected.into_bytes();
            tampered[0] ^= 1;
            assert_ne!(tampered, profile.rendered_source(tier).as_bytes());
        }
    }

    #[test]
    fn answer_signature_rejects_exact_reply_tamper() {
        let key = sigil::Ed25519KeyMaterial::from_seed([0x51; 32]).unwrap();
        let signer = aether::Ed25519Signer::new(key);
        let mut answer = AnswerBody::signed(7, "exact prompt", "exact reply", &signer);
        assert!(matches!(
            answer.verify_provenance(7, "exact prompt", &Ed25519Verifier),
            Provenance::Verified(_)
        ));
        answer.reply.push('!');
        assert_eq!(
            answer.verify_provenance(7, "exact prompt", &Ed25519Verifier),
            Provenance::Invalid
        );
    }

    #[test]
    fn exact_payload_inventory_is_complete_and_unique() {
        let files = expected_payload_files();
        assert_eq!(files.len(), 41);
        assert!(files.contains("daemon-local-execution-proof.v1.json"));
        assert!(files.contains("critter-remote-result.v1.json"));
    }

    #[test]
    fn success_report_contract_binds_digests_and_role_model_labels() {
        let report = VerifiedLiveEvidence {
            index_sha256: "11".repeat(32),
            semantic_sha256: "22".repeat(32),
            binary_sha256: "33".repeat(32),
            builder_model: "builder-model".into(),
            reviewer_model: "reviewer-model".into(),
            contract_tester_model: "tester-model".into(),
        };
        assert_eq!(
            serde_json::to_value(report).unwrap(),
            serde_json::json!({
                "index_sha256": "11".repeat(32),
                "semantic_sha256": "22".repeat(32),
                "binary_sha256": "33".repeat(32),
                "builder_model": "builder-model",
                "reviewer_model": "reviewer-model",
                "contract_tester_model": "tester-model",
            })
        );
    }
}
