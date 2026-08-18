//! Three model-backed, independently signing dialogue peers collaborate over the existing
//! SEER/Omega/transport path. The builder's same injected model then confirms the approved bounded
//! IR, and trusted AgentMind lowerers render it for the daemon, beast, and critter builders. The
//! four-turn chain has both fan-out and fan-in: the builder draft reaches the reviewer and contract
//! tester, the review reaches the tester and builder, and the final approval requires the exact
//! canonical projection and fixed-order hashes of every validated predecessor.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::RecvTimeoutError;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use aether::{
    Address, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier, InboxReceiver, NodeId, RealmId,
    Role, Signer, Topic,
};
use agent_mind::{
    AffineI32SpecV1, AgentMind, ApprovedProgramKindV1, ApprovedTier, ApprovedTypedProfile,
};
use agent_templated::{AuthoringReply, AuthoringRequest};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use build_beast::{BuildBeast, BuildBeastOp};
use build_cargo::{BuildCargo, BuildConfig, BuildOp, BuildReply, ManifestStub, Sandbox};
use build_critter::{BuildCritter, BuildCritterOp};
use dialogue_initiator::{
    DialogueFailed, DialogueInitiator, VerifiedDialogueTurn, VerifiedTurnSink, FAILED_SCHEMA,
    RESULT_SCHEMA, START_SCHEMA,
};
use dialogue_responder::{DialogueMind, MAX_MODEL_OUTPUT_BYTES};
use mind::{Completion, Model, ModelError, Prompt};
use omega_federator::{FederatorConfig, OmegaFederator};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest, Verifier};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

use crate::decisions::{
    builder_prompt, contract_tester_prompt, evaluate_affine, final_approval_prompt,
    reviewer_prompt, BuilderDraftV1, ChallengeV1, ContractCaseKindV1, ContractCaseV1,
    ContractTestPlanV1, FinalApprovalV1, FinalCapabilitySpecV1, ReviewerDecisionV1,
    BUILDER_DRAFT_SCHEMA_V1, CONTRACT_TEST_PLAN_SCHEMA_V1, REVIEWER_DECISION_SCHEMA_V1,
};
use crate::evidence::{
    ModelCallJournal, ModelCallOutcomeV1, ModelCallRecordV1, ModelReplayEntryV1, RecordedModel,
    RecordingModel, SanitizedModelConfigV1,
};
use crate::function_proof::PublishedCapability;

const REALM_A: &str = "reviewers";
const REALM_B: &str = "builders";
const NODE_A: &str = "reviewer-agent";
const NODE_B: &str = "builder-agent";
const REVIEWER_ROLE: &str = "v05-dialogue-reviewer";
const BUILDER_ROLE: &str = "v05-dialogue-builder";
const CONTRACT_TESTER_ROLE: &str = "v05-dialogue-contract-tester";

const BUILDER_INSTRUCTIONS: &str = "You are Alpha's Builder mind. Follow the requested strict JSON schema exactly. On the first turn originate a novel bounded affine capability; on the final turn integrate the exact validated Reviewer and Contract Tester records. Never emit source code, dependencies, capabilities, prose, Markdown, or fields outside the requested record.";
const REVIEWER_INSTRUCTIONS: &str = "You are Alpha's Reviewer mind. Return only the requested strict JSON record. Make a material safety decision by narrowing both bounds of the Builder's exact candidate domain; do not emit source, prose, or advisory-only commentary.";
const CONTRACT_TESTER_INSTRUCTIONS: &str = "You are Alpha's Contract Tester mind. Return only the requested strict JSON record. Choose the actual local and cross-Realm inputs and the exact ordered boundary/interior cases from the validated Builder and Reviewer records; do not emit source or prose.";
const MAX_COLLABORATION_CONTRIBUTION_BYTES: usize = crate::decisions::MAX_DECISION_JSON_BYTES;
const MESH_BIND_ATTEMPTS: usize = 3;
#[cfg(feature = "openai")]
const MAX_MODEL_NAME_BYTES: usize = 256;
#[cfg(feature = "openai")]
const MAX_MODEL_BASE_URL_BYTES: usize = 2048;
#[cfg(feature = "openai")]
const MAX_API_KEY_BYTES: usize = 16 * 1024;
// OpenAiModel may spend up to ten seconds connecting before its configured read timeout begins.
// Five more seconds cover worker scheduling and the signed reply's trip back through the fabric.
const MODEL_CALL_MARGIN: Duration = Duration::from_secs(15);

const FIXTURE_CHALLENGE_NONCE: &str = "fixture-v1-three-mind-affine-0001";

#[derive(Clone)]
struct FixtureChain {
    draft: BuilderDraftV1,
    review: ReviewerDecisionV1,
    test_plan: ContractTestPlanV1,
    approval: FinalApprovalV1,
}

fn fixture_chain(challenge: &ChallengeV1) -> Result<FixtureChain, String> {
    let draft = BuilderDraftV1 {
        schema: BUILDER_DRAFT_SCHEMA_V1.into(),
        challenge_hash: challenge.hash().map_err(|error| error.to_string())?,
        name: "Triple Minus Five".into(),
        slug: "triple-minus-five".into(),
        entrypoint: "triple_minus_five".into(),
        description: "Multiply a bounded signed integer by three, then subtract five.".into(),
        input_min: -128,
        input_max: 128,
        multiplier: 3,
        addend: -5,
    };
    draft.validate(challenge).map_err(|error| error.to_string())?;
    let review = ReviewerDecisionV1 {
        schema: REVIEWER_DECISION_SCHEMA_V1.into(),
        challenge_hash: challenge.hash().map_err(|error| error.to_string())?,
        draft_hash: draft.hash(challenge).map_err(|error| error.to_string())?,
        admitted_input_min: -64,
        admitted_input_max: 64,
    };
    review.validate(challenge, &draft).map_err(|error| error.to_string())?;
    let local_input = 17;
    let remote_input = -19;
    let cases = [
        (ContractCaseKindV1::LowerBoundary, review.admitted_input_min),
        (ContractCaseKindV1::RemoteNegativeInterior, remote_input),
        (ContractCaseKindV1::Zero, 0),
        (ContractCaseKindV1::LocalPositiveInterior, local_input),
        (ContractCaseKindV1::UpperBoundary, review.admitted_input_max),
    ]
    .into_iter()
    .map(|(kind, input)| {
        Ok(ContractCaseV1 {
            kind,
            input,
            expected_output: evaluate_affine(input, draft.multiplier, draft.addend)
                .map_err(|error| error.to_string())?,
        })
    })
    .collect::<Result<Vec<_>, String>>()?;
    let test_plan = ContractTestPlanV1 {
        schema: CONTRACT_TEST_PLAN_SCHEMA_V1.into(),
        challenge_hash: challenge.hash().map_err(|error| error.to_string())?,
        draft_hash: draft.hash(challenge).map_err(|error| error.to_string())?,
        review_hash: review.hash(challenge, &draft).map_err(|error| error.to_string())?,
        local_input,
        remote_input,
        cases,
    };
    test_plan.validate(challenge, &draft, &review).map_err(|error| error.to_string())?;
    let approval = FinalApprovalV1::from_chain(challenge, &draft, &review, &test_plan)
        .map_err(|error| error.to_string())?;
    Ok(FixtureChain { draft, review, test_plan, approval })
}

/// Evidence retained only long enough to make the hermetic causal assertions. No transcript is
/// persisted to disk.
#[derive(Default)]
struct ScriptedEvidence {
    builder_dialogue_prompts: Mutex<Vec<String>>,
    builder_author_prompts: Mutex<Vec<String>>,
    reviewer_prompts: Mutex<Vec<String>>,
    contract_tester_prompts: Mutex<Vec<String>>,
}

struct ScriptedBuilder {
    dialogue_calls: AtomicUsize,
    evidence: Arc<ScriptedEvidence>,
    draft_prompt: String,
    draft_reply: String,
    approval_prompt: String,
    approval_reply: String,
    approved_profile: Arc<Mutex<Option<ApprovedTypedProfile>>>,
}

impl ScriptedBuilder {
    fn new(
        evidence: Arc<ScriptedEvidence>,
        draft_prompt: String,
        draft_reply: String,
        approval_prompt: String,
        approval_reply: String,
        approved_profile: Arc<Mutex<Option<ApprovedTypedProfile>>>,
    ) -> Self {
        Self {
            dialogue_calls: AtomicUsize::new(0),
            evidence,
            draft_prompt,
            draft_reply,
            approval_prompt,
            approval_reply,
            approved_profile,
        }
    }
}

impl Model for ScriptedBuilder {
    fn complete(&self, request: Prompt) -> Result<Completion, ModelError> {
        let call = self.dialogue_calls.fetch_add(1, Ordering::SeqCst);
        if call >= 2 {
            self.evidence
                .builder_author_prompts
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .push(request.user_prompt.clone());
            let profile = self
                .approved_profile
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .clone()
                .ok_or_else(|| {
                    ModelError::Decode("approved profile was not installed before authoring".into())
                })?;
            for tier in ApprovedTier::ALL {
                if request.user_prompt.starts_with(&profile.request(tier)) {
                    return Ok(Completion {
                        content: profile.implementation_json(tier),
                        model: "fixture-builder".into(),
                        usage: None,
                        provider: None,
                    });
                }
            }
            return Err(ModelError::Decode(
                "fixture builder received an unknown approved-profile selector".into(),
            ));
        }

        self.evidence
            .builder_dialogue_prompts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(request.user_prompt.clone());
        let content = match call {
            0 if request.user_prompt == self.draft_prompt => self.draft_reply.clone(),
            1 if request.user_prompt == self.approval_prompt => self.approval_reply.clone(),
            _ => {
                return Err(ModelError::Decode(
                    "builder did not receive the exact causally prior contribution".into(),
                ))
            }
        };
        Ok(Completion { content, model: "fixture-builder".into(), usage: None, provider: None })
    }

    fn describe(&self) -> String {
        "fixture-builder".into()
    }
}

struct ScriptedReviewer {
    evidence: Arc<ScriptedEvidence>,
    expected_prompt: String,
    response: String,
}

impl Model for ScriptedReviewer {
    fn complete(&self, request: Prompt) -> Result<Completion, ModelError> {
        self.evidence
            .reviewer_prompts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(request.user_prompt.clone());
        if request.user_prompt != self.expected_prompt {
            return Err(ModelError::Decode(
                "reviewer did not receive the exact bytes from the signer-verified builder turn"
                    .into(),
            ));
        }
        Ok(Completion {
            content: self.response.clone(),
            model: "fixture-reviewer".into(),
            usage: None,
            provider: None,
        })
    }

    fn describe(&self) -> String {
        "fixture-reviewer".into()
    }
}

struct ScriptedContractTester {
    evidence: Arc<ScriptedEvidence>,
    expected_prompt: String,
    response: String,
}

impl Model for ScriptedContractTester {
    fn complete(&self, request: Prompt) -> Result<Completion, ModelError> {
        self.evidence
            .contract_tester_prompts
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(request.user_prompt.clone());
        if request.user_prompt != self.expected_prompt {
            return Err(ModelError::Decode(
                "contract tester did not receive the exact draft and critique".into(),
            ));
        }
        Ok(Completion {
            content: self.response.clone(),
            model: "fixture-contract-tester".into(),
            usage: None,
            provider: None,
        })
    }

    fn describe(&self) -> String {
        "fixture-contract-tester".into()
    }
}

struct Models {
    builder: Arc<dyn Model>,
    reviewer: Arc<dyn Model>,
    contract_tester: Arc<dyn Model>,
    scripted: Option<Arc<ScriptedEvidence>>,
    fixture: Option<FixtureChain>,
    fixture_profile: Option<Arc<Mutex<Option<ApprovedTypedProfile>>>>,
    model_calls: Arc<ModelCallJournal>,
    builder_timeout: Duration,
    reviewer_timeout: Duration,
    contract_tester_timeout: Duration,
}

fn validate_contribution(label: &str, value: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        return Err(format!("{label} contribution is empty"));
    }
    if value.len() > MAX_COLLABORATION_CONTRIBUTION_BYTES {
        return Err(format!(
            "{label} contribution is {} bytes, exceeds {}",
            value.len(),
            MAX_COLLABORATION_CONTRIBUTION_BYTES
        ));
    }
    Ok(())
}

fn model_wait(timeout: Duration) -> Duration {
    timeout.saturating_add(MODEL_CALL_MARGIN)
}

fn replay_prompt(entry: &ModelReplayEntryV1) -> Prompt {
    Prompt {
        system_prompt: entry.prompt.system_prompt.clone(),
        user_prompt: entry.prompt.user_prompt.clone(),
        max_tokens: entry.prompt.max_tokens,
        temperature: f32::from_bits(entry.prompt.temperature_bits),
    }
}

fn verify_model_replay(entries: &[ModelReplayEntryV1]) -> Result<(), String> {
    let builder = RecordedModel::new(
        "builder",
        entries.iter().filter(|entry| entry.role == "builder").cloned(),
    )
    .map_err(|error| error.to_string())?;
    let reviewer = RecordedModel::new(
        "reviewer",
        entries.iter().filter(|entry| entry.role == "reviewer").cloned(),
    )
    .map_err(|error| error.to_string())?;
    let contract_tester = RecordedModel::new(
        "contract-tester",
        entries.iter().filter(|entry| entry.role == "contract-tester").cloned(),
    )
    .map_err(|error| error.to_string())?;
    let mut ordered = entries.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|entry| entry.global_ordinal);
    for entry in ordered {
        let completion = match entry.role.as_str() {
            "builder" => builder.complete(replay_prompt(entry)),
            "reviewer" => reviewer.complete(replay_prompt(entry)),
            "contract-tester" => contract_tester.complete(replay_prompt(entry)),
            role => return Err(format!("recorded an unknown model role {role:?}")),
        }
        .map_err(|error| format!("recorded model replay failed: {error}"))?;
        if completion.content != entry.completion.content
            || completion.model != entry.completion.model
            || completion.usage != entry.completion.usage
        {
            return Err("recorded model replay changed completion content or metadata".into());
        }
    }
    builder.assert_exhausted().map_err(|error| error.to_string())?;
    reviewer.assert_exhausted().map_err(|error| error.to_string())?;
    contract_tester.assert_exhausted().map_err(|error| error.to_string())?;
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

fn validate_live_model_origin(config: &SanitizedModelConfigV1) -> Result<(), String> {
    let origin = config
        .endpoint_origin
        .as_deref()
        .ok_or_else(|| "live model configuration omitted its endpoint origin".to_string())?;
    if !live_origin_is_confidential_or_loopback(origin) {
        return Err(format!("live model endpoint {origin} is neither HTTPS nor exact loopback"));
    }
    Ok(())
}

fn validate_model_call_evidence(records: &[ModelCallRecordV1], live: bool) -> Result<(), String> {
    let expected_roles = [("builder", 5_usize), ("reviewer", 1), ("contract-tester", 1)];
    if records.len() != 7
        || expected_roles.iter().any(|(role, count)| {
            records.iter().filter(|record| record.role == *role).count() != *count
        })
    {
        return Err("model evidence did not contain exactly five Builder, one Reviewer, and one Contract Tester calls".into());
    }
    if records.iter().enumerate().any(|(ordinal, record)| {
        record.global_ordinal != ordinal as u64
            || !matches!(record.outcome, ModelCallOutcomeV1::Completed { .. })
    }) {
        return Err("model evidence contained a failed, missing, or reordered call".into());
    }
    if !live {
        return Ok(());
    }

    let mut response_ids = std::collections::BTreeSet::new();
    for record in records {
        validate_live_model_origin(&record.config)?;
        let ModelCallOutcomeV1::Completed { provider_receipt: Some(receipt), .. } = &record.outcome
        else {
            return Err("live model call omitted provider-reported receipt metadata".into());
        };
        let response_id = receipt
            .response_id
            .as_deref()
            .ok_or_else(|| "live provider omitted its response id".to_string())?;
        if !response_ids.insert(response_id) {
            return Err("live provider reused a response id across distinct model calls".into());
        }
        if receipt.reported_model.is_none() {
            return Err("live provider omitted its reported model id".into());
        }
        if receipt.finish_reason.as_deref() != Some("stop") {
            return Err("live model completion did not report terminal finish_reason=stop".into());
        }
        if receipt.store_requested {
            return Err("live model call unexpectedly requested provider-side storage".into());
        }
    }
    Ok(())
}

fn models(live: bool, challenge: &ChallengeV1) -> Result<Models, String> {
    if live {
        return live_models();
    }
    let fixture = fixture_chain(challenge)?;
    let evidence = Arc::new(ScriptedEvidence::default());
    let model_calls = Arc::new(ModelCallJournal::new());
    let approved_profile = Arc::new(Mutex::new(None));
    let draft_prompt = builder_prompt(challenge).map_err(|error| error.to_string())?;
    let draft_reply = serde_json::to_string(&fixture.draft).map_err(|error| error.to_string())?;
    let reviewer_expected =
        reviewer_prompt(challenge, &fixture.draft).map_err(|error| error.to_string())?;
    let reviewer_response =
        serde_json::to_string(&fixture.review).map_err(|error| error.to_string())?;
    let tester_expected = contract_tester_prompt(challenge, &fixture.draft, &fixture.review)
        .map_err(|error| error.to_string())?;
    let tester_response =
        serde_json::to_string(&fixture.test_plan).map_err(|error| error.to_string())?;
    let approval_prompt =
        final_approval_prompt(challenge, &fixture.draft, &fixture.review, &fixture.test_plan)
            .map_err(|error| error.to_string())?;
    let approval_reply =
        serde_json::to_string(&fixture.approval).map_err(|error| error.to_string())?;
    let builder: Arc<dyn Model> = Arc::new(ScriptedBuilder::new(
        evidence.clone(),
        draft_prompt,
        draft_reply,
        approval_prompt,
        approval_reply,
        approved_profile.clone(),
    ));
    let reviewer: Arc<dyn Model> = Arc::new(ScriptedReviewer {
        evidence: evidence.clone(),
        expected_prompt: reviewer_expected,
        response: reviewer_response,
    });
    let contract_tester: Arc<dyn Model> = Arc::new(ScriptedContractTester {
        evidence: evidence.clone(),
        expected_prompt: tester_expected,
        response: tester_response,
    });
    Ok(Models {
        builder: Arc::new(
            RecordingModel::new(
                "builder",
                SanitizedModelConfigV1::fixture("alpha-fixture", "fixture-builder")
                    .map_err(|error| error.to_string())?,
                builder,
                model_calls.clone(),
            )
            .map_err(|error| error.to_string())?,
        ),
        reviewer: Arc::new(
            RecordingModel::new(
                "reviewer",
                SanitizedModelConfigV1::fixture("alpha-fixture", "fixture-reviewer")
                    .map_err(|error| error.to_string())?,
                reviewer,
                model_calls.clone(),
            )
            .map_err(|error| error.to_string())?,
        ),
        contract_tester: Arc::new(
            RecordingModel::new(
                "contract-tester",
                SanitizedModelConfigV1::fixture("alpha-fixture", "fixture-contract-tester")
                    .map_err(|error| error.to_string())?,
                contract_tester,
                model_calls.clone(),
            )
            .map_err(|error| error.to_string())?,
        ),
        scripted: Some(evidence),
        fixture: Some(fixture),
        fixture_profile: Some(approved_profile),
        model_calls,
        builder_timeout: Duration::from_secs(5),
        reviewer_timeout: Duration::from_secs(5),
        contract_tester_timeout: Duration::from_secs(5),
    })
}

#[cfg(feature = "openai")]
fn live_models() -> Result<Models, String> {
    use mind::OpenAiModel;

    let builder = model_config("BUILDER")?;
    let reviewer = model_config("REVIEWER")?;
    let contract_tester = model_config("CONTRACT_TESTER")?;
    let builder_timeout = builder.timeout;
    let reviewer_timeout = reviewer.timeout;
    let contract_tester_timeout = contract_tester.timeout;
    let model_calls = Arc::new(ModelCallJournal::new());
    let builder_config = SanitizedModelConfigV1::from_model_config("openai-compatible", &builder)
        .map_err(|error| error.to_string())?;
    let reviewer_config = SanitizedModelConfigV1::from_model_config("openai-compatible", &reviewer)
        .map_err(|error| error.to_string())?;
    let contract_tester_config =
        SanitizedModelConfigV1::from_model_config("openai-compatible", &contract_tester)
            .map_err(|error| error.to_string())?;
    // Validate the release-evidence confidentiality posture before constructing an HTTP model.
    // The same check runs again over retained call records, but that post-call audit is too late to
    // prevent a misconfigured cleartext endpoint from receiving the prompts.
    validate_live_model_origin(&builder_config)?;
    validate_live_model_origin(&reviewer_config)?;
    validate_live_model_origin(&contract_tester_config)?;
    Ok(Models {
        builder: Arc::new(
            RecordingModel::new(
                "builder",
                builder_config,
                Arc::new(OpenAiModel::new(builder)),
                model_calls.clone(),
            )
            .map_err(|error| error.to_string())?,
        ),
        reviewer: Arc::new(
            RecordingModel::new(
                "reviewer",
                reviewer_config,
                Arc::new(OpenAiModel::new(reviewer)),
                model_calls.clone(),
            )
            .map_err(|error| error.to_string())?,
        ),
        contract_tester: Arc::new(
            RecordingModel::new(
                "contract-tester",
                contract_tester_config,
                Arc::new(OpenAiModel::new(contract_tester)),
                model_calls.clone(),
            )
            .map_err(|error| error.to_string())?,
        ),
        scripted: None,
        fixture: None,
        fixture_profile: None,
        model_calls,
        builder_timeout,
        reviewer_timeout,
        contract_tester_timeout,
    })
}

/// Validate every live-provider configuration and private key file before the caller consumes a
/// create-new evidence path. The configurations are parsed again when the models are constructed;
/// that second pass closes the preflight/use race and still occurs before any provider call.
#[cfg(feature = "openai")]
pub(crate) fn preflight_live_configuration() -> Result<(), String> {
    for (role, provider) in
        [("BUILDER", "builder"), ("REVIEWER", "reviewer"), ("CONTRACT_TESTER", "contract-tester")]
    {
        let config = model_config(role)?;
        let sanitized = SanitizedModelConfigV1::from_model_config(provider, &config)
            .map_err(|error| error.to_string())?;
        validate_live_model_origin(&sanitized)?;
    }
    Ok(())
}

#[cfg(not(feature = "openai"))]
pub(crate) fn preflight_live_configuration() -> Result<(), String> {
    Err("--live requires rebuilding dialogue with `--features openai`".into())
}

#[cfg(not(feature = "openai"))]
fn live_models() -> Result<Models, String> {
    Err("--live requires rebuilding dialogue with `--features openai`".into())
}

#[cfg(feature = "openai")]
fn model_config(role: &str) -> Result<mind::ModelConfig, String> {
    let prefix = format!("ALPHA_DIALOGUE_{role}");
    let model = std::env::var(format!("{prefix}_MODEL"))
        .map_err(|_| format!("{prefix}_MODEL is required in --live mode"))?;
    let base_url = std::env::var(format!("{prefix}_BASE_URL"))
        .unwrap_or_else(|_| "http://localhost:11434/v1".into());
    if model.trim().is_empty() || model.len() > MAX_MODEL_NAME_BYTES {
        return Err(format!("{prefix}_MODEL must contain 1..={MAX_MODEL_NAME_BYTES} bytes"));
    }
    if base_url.trim().is_empty() || base_url.len() > MAX_MODEL_BASE_URL_BYTES {
        return Err(format!("{prefix}_BASE_URL must contain 1..={MAX_MODEL_BASE_URL_BYTES} bytes"));
    }
    if base_url.trim() != base_url
        || (!base_url.starts_with("https://") && !base_url.starts_with("http://"))
        || base_url.contains('@')
    {
        return Err(format!(
            "{prefix}_BASE_URL must use a lowercase HTTP(S) scheme, contain no surrounding whitespace, and contain no URL user-info"
        ));
    }
    let api_key_file_var = format!("{prefix}_API_KEY_FILE");
    let api_key = match std::env::var(&api_key_file_var) {
        Ok(path) => read_private_api_key_file(&prefix, Path::new(&path))?,
        Err(std::env::VarError::NotPresent) => {
            let api_key_var = format!("{prefix}_API_KEY");
            match std::env::var(&api_key_var) {
                Ok(key) if key.len() > MAX_API_KEY_BYTES => {
                    return Err(format!("{prefix}_API_KEY exceeds {MAX_API_KEY_BYTES} bytes"))
                }
                Ok(key) if key.is_empty() => None,
                Ok(key) => Some(key),
                Err(std::env::VarError::NotPresent) => None,
                Err(std::env::VarError::NotUnicode(_)) => {
                    return Err(format!("{prefix}_API_KEY must be UTF-8"))
                }
            }
        }
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{prefix}_API_KEY_FILE must be UTF-8"))
        }
    };
    let timeout_secs = std::env::var(format!("{prefix}_TIMEOUT_SECS"))
        .ok()
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|_| format!("{prefix}_TIMEOUT_SECS must be an integer in 1..=120"))
        })
        .transpose()?
        .unwrap_or(60);
    if !(1..=120).contains(&timeout_secs) {
        return Err(format!("{prefix}_TIMEOUT_SECS must be in 1..=120"));
    }
    Ok(mind::ModelConfig { base_url, model, api_key, timeout: Duration::from_secs(timeout_secs) })
}

#[cfg(feature = "openai")]
fn read_private_api_key_file(prefix: &str, path: &Path) -> Result<Option<String>, String> {
    use std::fs::File;
    use std::io::Read;

    if !path.is_absolute()
        || path.components().any(|component| {
            !matches!(component, std::path::Component::RootDir | std::path::Component::Normal(_))
        })
    {
        return Err(format!("{prefix}_API_KEY_FILE must be an absolute normalized path"));
    }
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        format!("cannot resolve {prefix}_API_KEY_FILE {}: {error}", path.display())
    })?;
    if canonical != path {
        return Err(format!(
            "{prefix}_API_KEY_FILE {} contains a symlink or noncanonical component",
            path.display()
        ));
    }
    let before = std::fs::metadata(path).map_err(|error| {
        format!("cannot inspect {prefix}_API_KEY_FILE {}: {error}", path.display())
    })?;
    if !before.is_file() {
        return Err(format!("{prefix}_API_KEY_FILE {} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "{prefix}_API_KEY_FILE {} must not grant group or other permissions",
                path.display()
            ));
        }
    }

    let mut file = File::open(path).map_err(|error| {
        format!("cannot open {prefix}_API_KEY_FILE {}: {error}", path.display())
    })?;
    let opened = file
        .metadata()
        .map_err(|error| format!("cannot inspect opened {prefix}_API_KEY_FILE: {error}"))?;
    if !opened.is_file() {
        return Err(format!("opened {prefix}_API_KEY_FILE is not a regular file"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(format!("{prefix}_API_KEY_FILE changed while it was opened"));
        }
    }
    let mut bytes = Vec::new();
    (&mut file).take(MAX_API_KEY_BYTES as u64 + 1).read_to_end(&mut bytes).map_err(|error| {
        format!("cannot read {prefix}_API_KEY_FILE {}: {error}", path.display())
    })?;
    if bytes.len() > MAX_API_KEY_BYTES {
        return Err(format!("{prefix}_API_KEY_FILE exceeds {MAX_API_KEY_BYTES} bytes"));
    }
    let after = file
        .metadata()
        .map_err(|error| format!("cannot recheck {prefix}_API_KEY_FILE: {error}"))?;
    if opened.len() != after.len() {
        return Err(format!("{prefix}_API_KEY_FILE changed while it was read"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.dev() != after.dev() || opened.ino() != after.ino() {
            return Err(format!("{prefix}_API_KEY_FILE changed while it was read"));
        }
    }
    let key = String::from_utf8(bytes)
        .map_err(|_| format!("{prefix}_API_KEY_FILE is not UTF-8"))?
        .trim()
        .to_string();
    if key.is_empty() {
        return Err(format!("{prefix}_API_KEY_FILE is empty"));
    }
    Ok(Some(key))
}

fn signed_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut manifest = Manifest::new(name, "0.1.0", sigil::Backend::Daemon, "gawd_creature_v1");
    manifest.provenance.author = Some(key.public_hex().to_string());
    manifest.content_address = Some(manifest.compute_content_address());
    manifest.provenance.signature = Some(key.sign(&manifest.signing_payload()));
    manifest
}

fn workspace_root() -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(std::path::PathBuf::from)
        .unwrap_or(manifest_dir)
}

fn kernel(key: &Ed25519KeyMaterial) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(key.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![key.public_hex().to_string()])),
        256,
    )
}

#[allow(clippy::too_many_arguments)]
fn install_mesh(
    kernel: &Arc<Kernel>,
    node: &str,
    realm: &str,
    port: u16,
    key: &Ed25519KeyMaterial,
    peer_node: &str,
    peer_realm: &str,
    peer_port: u16,
    peer_key: &Ed25519KeyMaterial,
    dials: bool,
) -> Result<(), String> {
    kernel.set_node_identity(key.public_hex().to_string());
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
    Ok(())
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
                return Err("peer-event inbox disconnected before readiness".into())
            }
        }
    }
    Err(format!("authenticated transport to {peer} did not become ready"))
}

fn free_ports() -> Result<(u16, u16), String> {
    let a = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let b = std::net::TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let a_port = a.local_addr().map_err(|e| e.to_string())?.port();
    let b_port = b.local_addr().map_err(|e| e.to_string())?.port();
    drop((a, b));
    Ok((a_port, b_port))
}

fn open_mesh(
    key_a: &Ed25519KeyMaterial,
    key_b: &Ed25519KeyMaterial,
) -> Result<(Arc<Kernel>, Arc<Kernel>, aether::BusHandle, InboxReceiver), String> {
    let mut last_error = None;
    for _ in 0..MESH_BIND_ATTEMPTS {
        let (port_a, port_b) = match free_ports() {
            Ok(ports) => ports,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let b = kernel(key_b);
        if let Err(error) =
            install_mesh(&b, NODE_B, REALM_B, port_b, key_b, NODE_A, REALM_A, port_a, key_a, false)
        {
            b.shutdown_all(Deadline::from_millis(1500));
            drop(b);
            last_error = Some(error);
            continue;
        }

        let a = kernel(key_a);
        // Subscribe on the sender before its transport can install. Peer events are live fan-out,
        // not replay, and sender-side readiness proves A has its writer before the first one-shot
        // dialogue.
        let (_probe, bus, rx) = a.open_endpoint(Capabilities::default());
        a.router().subscribe(Topic::new(Topic::PROPRIOCEPTION), bus.id());
        if let Err(error) =
            install_mesh(&a, NODE_A, REALM_A, port_a, key_a, NODE_B, REALM_B, port_b, key_b, true)
        {
            a.shutdown_all(Deadline::from_millis(1500));
            drop(a);
            b.shutdown_all(Deadline::from_millis(1500));
            drop(b);
            last_error = Some(error);
            continue;
        }
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
        "could not claim a fresh collaboration mesh port pair after {MESH_BIND_ATTEMPTS} attempts: {}",
        last_error.unwrap_or_else(|| "no bind attempt completed".into())
    ))
}

fn say(
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    initiator: aether::CreatureId,
    corr: u64,
    prompt: &str,
    budget: Duration,
) -> Result<String, String> {
    if prompt.len() > MAX_MODEL_OUTPUT_BYTES {
        return Err(format!(
            "dialogue prompt is {} bytes, exceeds {}",
            prompt.len(),
            MAX_MODEL_OUTPUT_BYTES
        ));
    }
    bus.send(
        Dispatch::to(Address::Creature(initiator), prompt.as_bytes().to_vec())
            .with_schema(START_SCHEMA)
            .with_corr(corr)
            .with_reply_to(Address::Creature(bus.id())),
    )
    .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env)
                if env.header.from == Address::Creature(initiator)
                    && env.header.corr == Some(corr) =>
            {
                if env.header.schema == RESULT_SCHEMA {
                    return String::from_utf8(env.payload)
                        .map_err(|_| "dialogue result was not UTF-8".into());
                }
                if env.header.schema == FAILED_SCHEMA {
                    let failure = DialogueFailed::parse(&env.payload).map_err(|e| e.to_string())?;
                    return Err(format!("dialogue failed: {}", failure.reason));
                }
            }
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err("dialogue result inbox disconnected before a terminal reply".into())
            }
        }
    }
    Err("dialogue did not produce a terminal result before the bounded demo deadline".into())
}

fn recv_schema(
    rx: &InboxReceiver,
    expected_from: aether::CreatureId,
    corr: u64,
    schema: &str,
    budget: Duration,
) -> Result<aether::Envelope, String> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(env)
                if env.header.from == Address::Creature(expected_from)
                    && env.header.corr == Some(corr)
                    && env.header.schema == schema =>
            {
                return Ok(env);
            }
            Ok(_) | Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => {
                return Err(format!(
                    "reply inbox disconnected while waiting for {schema} correlation {corr}"
                ));
            }
        }
    }
    Err(format!("no {schema} reply for correlation {corr}"))
}

#[derive(Clone, Copy, Debug)]
enum BuildTier {
    Daemon,
    Beast,
    Critter,
}

impl BuildTier {
    const ALL: [Self; 3] = [Self::Daemon, Self::Beast, Self::Critter];

    fn backend(self) -> Backend {
        match self {
            Self::Daemon => Backend::Daemon,
            Self::Beast => Backend::Beast,
            Self::Critter => Backend::Critter,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Daemon => "BuildCargo",
            Self::Beast => "BuildBeast",
            Self::Critter => "BuildCritter",
        }
    }

    fn approved_tier(self) -> ApprovedTier {
        match self {
            Self::Daemon => ApprovedTier::Daemon,
            Self::Beast => ApprovedTier::Beast,
            Self::Critter => ApprovedTier::Critter,
        }
    }
}

struct Builders {
    daemon: aether::CreatureId,
    beast: aether::CreatureId,
    critter: aether::CreatureId,
}

impl Builders {
    fn id(&self, tier: BuildTier) -> aether::CreatureId {
        match tier {
            BuildTier::Daemon => self.daemon,
            BuildTier::Beast => self.beast,
            BuildTier::Critter => self.critter,
        }
    }
}

fn install_authoring(
    kernel: &Kernel,
    root: &Path,
    node_key: &Ed25519KeyMaterial,
    builder_model: Arc<dyn Model>,
    approved_profile: ApprovedTypedProfile,
    build_key: &Ed25519KeyMaterial,
) -> Result<(aether::CreatureId, Builders), String> {
    let author = kernel
        .load_instance(
            signed_manifest("agent-mind", node_key),
            Box::new(
                AgentMind::approved_only(builder_model, approved_profile)
                    .with_max_in_flight_model_requests(1),
            ),
        )
        .map_err(|error| error.to_string())?;

    let mut cargo_config = BuildConfig::with_workspace_root(
        workspace_root().join("cosmos"),
        build_key.clone(),
        build_key.public_hex(),
    );
    cargo_config.work_root = root.join("native-authoring-work");
    cargo_config.target_dir = workspace_root().join("target").join("gawd-build-cache");
    cargo_config.max_target_bytes = 2 * 1024 * 1024 * 1024;
    cargo_config.cargo_timeout = Duration::from_secs(300);
    cargo_config.cargo_jobs = 1;
    cargo_config.cargo_codegen_units = 1;
    cargo_config.sandbox = Sandbox::None;
    let daemon = kernel
        .load_instance(
            signed_manifest("build-cargo", node_key),
            Box::new(BuildCargo::new(cargo_config)),
        )
        .map_err(|error| error.to_string())?;
    let beast = kernel
        .load_instance(
            signed_manifest("build-beast", node_key),
            Box::new(BuildBeast::new(build_key.clone(), build_key.public_hex())),
        )
        .map_err(|error| error.to_string())?;
    let critter = kernel
        .load_instance(
            signed_manifest("build-critter", node_key),
            Box::new(BuildCritter::new(build_key.clone(), build_key.public_hex())),
        )
        .map_err(|error| error.to_string())?;
    Ok((author, Builders { daemon, beast, critter }))
}

fn build_operation(
    tier: BuildTier,
    source: String,
    stub: ManifestStub,
    crate_name: String,
    crate_version: String,
    deps: Vec<build_cargo::CargoDep>,
) -> Vec<u8> {
    match tier {
        BuildTier::Daemon => aether::wire::to_bytes(&BuildOp::Build {
            crate_name,
            crate_version,
            source,
            manifest_stub: stub,
            deps,
        }),
        BuildTier::Beast => BuildBeastOp::Author { source, manifest_stub: stub }.to_bytes(),
        BuildTier::Critter => BuildCritterOp::Author { source, manifest_stub: stub }.to_bytes(),
    }
}

fn hash_hex(bytes: &[u8]) -> String {
    gawdfn::sha256_digest(bytes)
        .strip_prefix("sha256:")
        .expect("sha256_digest always prefixes its digest")
        .to_string()
}

fn validate_built_capability(
    tier: BuildTier,
    expected_source: String,
    expected_stub: ManifestStub,
    build_key: &Ed25519KeyMaterial,
    approval_digest: &str,
    manifest: Manifest,
    artifact: Vec<u8>,
) -> Result<PublishedCapability, String> {
    let label = tier.label();
    let source = expected_source.into_bytes();
    if manifest.name != expected_stub.name
        || manifest.version != expected_stub.version
        || manifest.entrypoints != expected_stub.entrypoints
        || manifest.capabilities != expected_stub.capabilities
        || manifest.provides != expected_stub.provides
        || manifest.requirements != Default::default()
        || manifest.abi.backend != tier.backend()
    {
        return Err(format!("{label} changed the exact approved manifest stub"));
    }
    match tier {
        BuildTier::Daemon => {
            if manifest.abi.abi_tag != aether::ffi::ABI_TAG
                || manifest.abi.target.len() != 1
                || manifest.abi.target.first().map(String::as_str)
                    != Some("x86_64-unknown-linux-gnu")
            {
                return Err("BuildCargo emitted the wrong native ABI/target".into());
            }
        }
        BuildTier::Beast => {
            if manifest.abi.abi_tag != aether::ffi::ABI_TAG
                || manifest.abi.target.len() != 1
                || manifest.abi.target.first().map(String::as_str) != Some("wasm32-unknown-unknown")
            {
                return Err("BuildBeast emitted the wrong WASM ABI/target".into());
            }
            let expected_artifact = wat::parse_bytes(&source)
                .map_err(|error| format!("canonical beast WAT stopped compiling: {error}"))?;
            if expected_artifact.as_ref() != artifact.as_slice() {
                return Err("BuildBeast substituted bytes for the exact canonical WAT".into());
            }
        }
        BuildTier::Critter => {
            if manifest.abi.abi_tag != anima::CRITTER_ABI_TAG || !manifest.abi.target.is_empty() {
                return Err("BuildCritter emitted the wrong Rhai ABI/target".into());
            }
        }
    }
    if manifest.provenance.author.as_deref() != Some(build_key.public_hex())
        || manifest.provenance.realm.is_some()
    {
        return Err(format!("{label} did not preserve the pinned build identity"));
    }
    let source_hash = hash_hex(&source);
    let artifact_hash = hash_hex(&artifact);
    if manifest.provenance.source_hash.as_deref() != Some(source_hash.as_str())
        || manifest.provenance.build_hash.as_deref() != Some(artifact_hash.as_str())
    {
        return Err(format!("{label} provenance does not bind the exact source/artifact bytes"));
    }
    if tier.backend() == Backend::Critter && artifact != source {
        return Err("BuildCritter changed the canonical Rhai source artifact".into());
    }
    let address = manifest
        .content_address
        .as_deref()
        .ok_or_else(|| format!("{label} omitted content_address"))?;
    if address != manifest.compute_content_address() {
        return Err(format!("{label} emitted a stale content address"));
    }
    let signature = manifest
        .provenance
        .signature
        .as_deref()
        .ok_or_else(|| format!("{label} omitted its manifest signature"))?;
    if !sigil::Ed25519Verifier.verify(
        build_key.public_hex(),
        &manifest.signing_payload(),
        signature,
    ) {
        return Err(format!("{label} manifest signature did not verify"));
    }
    manifest.validate().map_err(|error| error.to_string())?;
    Ok(PublishedCapability {
        manifest,
        artifact,
        artifact_hash,
        source,
        source_hash,
        approval_digest: approval_digest.to_string(),
    })
}

#[allow(clippy::too_many_arguments)]
fn author_one(
    author: aether::CreatureId,
    builders: &Builders,
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    tier: BuildTier,
    request_text: String,
    ordinal: u64,
    builder_timeout: Duration,
    build_key: &Ed25519KeyMaterial,
    approval_digest: &str,
) -> Result<PublishedCapability, String> {
    let author_corr = 20_000 + ordinal;
    let request = AuthoringRequest { request: request_text, prev_error: None };
    bus.send(
        Dispatch::to(
            Address::Creature(author),
            serde_json::to_vec(&request).map_err(|error| error.to_string())?,
        )
        .with_schema("authoring.request")
        .with_corr(author_corr)
        .with_reply_to(Address::Creature(bus.id())),
    )
    .map_err(|error| error.to_string())?;
    let authored =
        recv_schema(rx, author, author_corr, "authoring.reply", model_wait(builder_timeout))?;
    let response = match serde_json::from_slice::<AuthoringReply>(&authored.payload)
        .map_err(|error| error.to_string())?
    {
        AuthoringReply::Authored(response) => response,
        AuthoringReply::Failed(error) => {
            return Err(format!("AgentMind refused the exact {tier:?} request: {error}"))
        }
    };
    let expected_source = response.source.clone();
    let expected_stub = response.manifest_stub.clone();
    let build_payload = build_operation(
        tier,
        response.source,
        response.manifest_stub,
        response.crate_name,
        response.crate_version,
        response.deps,
    );
    let builder = builders.id(tier);
    let build_corr = 21_000 + ordinal;
    bus.send(
        Dispatch::to(Address::Creature(builder), build_payload)
            .with_schema("build.op")
            .with_corr(build_corr)
            .with_reply_to(Address::Creature(bus.id())),
    )
    .map_err(|error| error.to_string())?;
    let budget = if matches!(tier, BuildTier::Daemon) {
        Duration::from_secs(305)
    } else {
        Duration::from_secs(8)
    };
    let built = recv_schema(rx, builder, build_corr, "build.reply", budget)?;
    match serde_json::from_slice::<BuildReply>(&built.payload).map_err(|error| error.to_string())? {
        BuildReply::Built { manifest, artifact } => validate_built_capability(
            tier,
            expected_source,
            expected_stub,
            build_key,
            approval_digest,
            manifest,
            artifact,
        ),
        BuildReply::Failed { kind, message, stderr, .. } => Err(format!(
            "{} failed its single deterministic build ({kind:?}): {message}\n{stderr}",
            tier.label()
        )),
    }
}

struct AuthorSuiteRequest<'a> {
    root: &'a Path,
    node_key: &'a Ed25519KeyMaterial,
    approved_profile: ApprovedTypedProfile,
    builder_timeout: Duration,
    build_key: &'a Ed25519KeyMaterial,
    approval_digest: &'a str,
}

fn author_suite(
    kernel: &Kernel,
    builder_model: Arc<dyn Model>,
    request: AuthorSuiteRequest<'_>,
) -> Result<Vec<PublishedCapability>, String> {
    let (author, builders) = install_authoring(
        kernel,
        request.root,
        request.node_key,
        builder_model,
        request.approved_profile.clone(),
        request.build_key,
    )?;
    let (_probe, bus, rx) = kernel.open_endpoint(Capabilities::default());
    BuildTier::ALL
        .into_iter()
        .enumerate()
        .map(|(index, tier)| {
            author_one(
                author,
                &builders,
                &bus,
                &rx,
                tier,
                request.approved_profile.request(tier.approved_tier()),
                index as u64 + 1,
                request.builder_timeout,
                request.build_key,
                request.approval_digest,
            )
        })
        .collect()
}

fn approved_profile(spec: &FinalCapabilitySpecV1) -> Result<ApprovedTypedProfile, String> {
    spec.validate().map_err(|error| error.to_string())?;
    let candidate = AffineI32SpecV1 {
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
    };
    let semantic =
        ApprovedTypedProfile::canonical_semantic_digest(&candidate).map_err(|e| e.to_string())?;
    if semantic != spec.semantic_digest {
        return Err("AgentMind and dialogue computed different semantic truth-table digests".into());
    }
    let digest = ApprovedTypedProfile::canonical_digest(&candidate).map_err(|e| e.to_string())?;
    ApprovedTypedProfile::from_approved(candidate, &digest).map_err(|e| e.to_string())
}

fn collaboration_challenge(live: bool) -> Result<ChallengeV1, String> {
    let challenge = if live {
        let (nonce, _) = Ed25519KeyMaterial::generate().map_err(|error| error.to_string())?;
        ChallengeV1::new(format!("live:{}", nonce.public_hex()))
    } else {
        ChallengeV1::new(FIXTURE_CHALLENGE_NONCE)
    };
    challenge.validate().map_err(|error| error.to_string())?;
    Ok(challenge)
}

fn run_key(live: bool, fixture_seed: u8) -> Result<Ed25519KeyMaterial, String> {
    if live {
        Ed25519KeyMaterial::generate().map(|(key, _)| key)
    } else {
        Ed25519KeyMaterial::from_seed([fixture_seed; 32])
    }
}

#[derive(Default)]
struct VerifiedTurnJournal(Mutex<Vec<VerifiedDialogueTurn>>);

impl VerifiedTurnSink for VerifiedTurnJournal {
    fn record_verified_turn(&self, turn: VerifiedDialogueTurn) -> Result<(), String> {
        let mut turns = self.0.lock().unwrap_or_else(|poison| poison.into_inner());
        if turns.len() >= 4 {
            return Err("three-mind proof attempted to retain more than four dialogue turns".into());
        }
        turns.push(turn);
        Ok(())
    }
}

pub(crate) struct CollaborationOutput {
    pub capabilities: Vec<PublishedCapability>,
    pub challenge: ChallengeV1,
    pub draft: BuilderDraftV1,
    pub review: ReviewerDecisionV1,
    pub test_plan: ContractTestPlanV1,
    pub approval: FinalApprovalV1,
    pub profile_digest: String,
    pub verified_turns: Vec<VerifiedDialogueTurn>,
    pub builder_signer: String,
    pub reviewer_signer: String,
    pub contract_tester_signer: String,
    pub model_calls: Vec<ModelCallRecordV1>,
    pub replay_entries: Vec<ModelReplayEntryV1>,
}

fn verify_fixture_evidence(
    evidence: &ScriptedEvidence,
    challenge: &ChallengeV1,
    fixture: &FixtureChain,
    profile: &ApprovedTypedProfile,
) -> Result<(), String> {
    let builder =
        evidence.builder_dialogue_prompts.lock().unwrap_or_else(|poison| poison.into_inner());
    let reviewer = evidence.reviewer_prompts.lock().unwrap_or_else(|poison| poison.into_inner());
    let contract_tester =
        evidence.contract_tester_prompts.lock().unwrap_or_else(|poison| poison.into_inner());
    let author =
        evidence.builder_author_prompts.lock().unwrap_or_else(|poison| poison.into_inner());
    let expected_authoring = ApprovedTier::ALL.map(|tier| profile.request(tier));
    if builder.len() != 2
        || reviewer.len() != 1
        || contract_tester.len() != 1
        || author.len() != 3
        || !author.iter().zip(expected_authoring).all(|(observed, selector)| {
            observed.starts_with(&selector)
                && observed.contains(profile.canonical_spec())
                && observed.contains(profile.digest())
        })
        || builder[0] != builder_prompt(challenge).map_err(|error| error.to_string())?
        || reviewer[0]
            != reviewer_prompt(challenge, &fixture.draft).map_err(|error| error.to_string())?
        || contract_tester[0]
            != contract_tester_prompt(challenge, &fixture.draft, &fixture.review)
                .map_err(|error| error.to_string())?
        || builder[1]
            != final_approval_prompt(challenge, &fixture.draft, &fixture.review, &fixture.test_plan)
                .map_err(|error| error.to_string())?
    {
        return Err(
            "fixture models did not observe the exact causal four-turn/authoring chain".into()
        );
    }
    Ok(())
}

/// Run the collaboration and author/build half of the acceptance scenario.
pub(crate) fn collaborate_and_build(
    root: &Path,
    live: bool,
    forbidden_semantics: &[String],
) -> Result<CollaborationOutput, String> {
    let challenge = collaboration_challenge(live)?;
    let models = models(live, &challenge)?;
    if Arc::ptr_eq(&models.builder, &models.reviewer)
        || Arc::ptr_eq(&models.builder, &models.contract_tester)
        || Arc::ptr_eq(&models.reviewer, &models.contract_tester)
    {
        return Err(
            "builder, reviewer, and contract tester must use distinct Model injections".into()
        );
    }
    let dialogue_roles = [REVIEWER_ROLE, BUILDER_ROLE, CONTRACT_TESTER_ROLE];
    if dialogue_roles.iter().collect::<std::collections::BTreeSet<_>>().len()
        != dialogue_roles.len()
    {
        return Err("builder, reviewer, and contract tester roles must be pairwise distinct".into());
    }
    let key_a = run_key(live, 0x11)?;
    let key_b = run_key(live, 0x22)?;
    let reviewer_agent_key = run_key(live, 0x31)?;
    let builder_agent_key = run_key(live, 0x32)?;
    let build_key = run_key(live, 0x33)?;
    let contract_tester_agent_key = run_key(live, 0x34)?;
    let reviewer_signer = Arc::new(Ed25519Signer::new(reviewer_agent_key));
    let builder_signer = Arc::new(Ed25519Signer::new(builder_agent_key));
    let contract_tester_signer = Arc::new(Ed25519Signer::new(contract_tester_agent_key));
    let signing_identities = [
        key_a.public_hex().to_string(),
        key_b.public_hex().to_string(),
        reviewer_signer.public_key(),
        builder_signer.public_key(),
        contract_tester_signer.public_key(),
        build_key.public_hex().to_string(),
    ];
    if signing_identities.iter().collect::<std::collections::BTreeSet<_>>().len()
        != signing_identities.len()
    {
        return Err(
            "transport, agent, and build signing identities must be pairwise distinct".into()
        );
    }

    let turns = Arc::new(VerifiedTurnJournal::default());
    let (a, b, bus, rx) = open_mesh(&key_a, &key_b)?;
    let builder_id = b
        .load_instance(
            signed_manifest("dialogue-builder", &key_b),
            Box::new(
                DialogueMind::new(
                    models.builder.clone(),
                    builder_signer.clone(),
                    BUILDER_INSTRUCTIONS,
                )
                .map_err(|e| e.to_string())?
                .with_max_in_flight_model_requests(1),
            ),
        )
        .map_err(|e| e.to_string())?;
    b.bind_remote_role(Role::new(BUILDER_ROLE), builder_id);
    let contract_tester_id = b
        .load_instance(
            signed_manifest("dialogue-contract-tester", &key_b),
            Box::new(
                DialogueMind::new(
                    models.contract_tester.clone(),
                    contract_tester_signer.clone(),
                    CONTRACT_TESTER_INSTRUCTIONS,
                )
                .map_err(|e| e.to_string())?
                .with_max_in_flight_model_requests(1),
            ),
        )
        .map_err(|e| e.to_string())?;
    b.bind_remote_role(Role::new(CONTRACT_TESTER_ROLE), contract_tester_id);

    let result = (|| {
        let reviewer_id = a
            .load_instance(
                signed_manifest("dialogue-reviewer", &key_a),
                Box::new(
                    DialogueMind::new(
                        models.reviewer.clone(),
                        reviewer_signer.clone(),
                        REVIEWER_INSTRUCTIONS,
                    )
                    .map_err(|e| e.to_string())?
                    .with_max_in_flight_model_requests(1),
                ),
            )
            .map_err(|e| e.to_string())?;
        a.bind_role(Role::new(REVIEWER_ROLE), reviewer_id);

        let remote_builder = Address::Omega {
            realm: RealmId::new(REALM_B),
            target: Box::new(Address::NodeRole(NodeId(NODE_B.into()), Role::new(BUILDER_ROLE))),
        };
        let remote_contract_tester = Address::Omega {
            realm: RealmId::new(REALM_B),
            target: Box::new(Address::NodeRole(
                NodeId(NODE_B.into()),
                Role::new(CONTRACT_TESTER_ROLE),
            )),
        };
        let builder_initiator = a
            .load_instance(
                signed_manifest("builder-dialogue-initiator", &key_a),
                Box::new(
                    DialogueInitiator::new(remote_builder)
                        .with_verifier(Arc::new(Ed25519Verifier))
                        .with_expected_signer(builder_signer.public_key())
                        .with_verified_turn_sink(turns.clone())
                        .with_max_pending(1)
                        .with_corr_seed(900_000),
                ),
            )
            .map_err(|e| e.to_string())?;
        let reviewer_initiator = a
            .load_instance(
                signed_manifest("reviewer-dialogue-initiator", &key_a),
                Box::new(
                    DialogueInitiator::new(role(REVIEWER_ROLE))
                        .with_verifier(Arc::new(Ed25519Verifier))
                        .with_expected_signer(reviewer_signer.public_key())
                        .with_verified_turn_sink(turns.clone())
                        .with_max_pending(1)
                        .with_corr_seed(910_000),
                ),
            )
            .map_err(|e| e.to_string())?;
        let contract_tester_initiator = a
            .load_instance(
                signed_manifest("contract-tester-dialogue-initiator", &key_a),
                Box::new(
                    DialogueInitiator::new(remote_contract_tester)
                        .with_verifier(Arc::new(Ed25519Verifier))
                        .with_expected_signer(contract_tester_signer.public_key())
                        .with_verified_turn_sink(turns.clone())
                        .with_max_pending(1)
                        .with_corr_seed(920_000),
                ),
            )
            .map_err(|e| e.to_string())?;

        let draft_prompt = builder_prompt(&challenge).map_err(|error| error.to_string())?;
        let draft_text = say(
            &bus,
            &rx,
            builder_initiator,
            1,
            &draft_prompt,
            model_wait(models.builder_timeout),
        )?;
        validate_contribution("builder draft", &draft_text)?;
        let draft = BuilderDraftV1::decode_json(draft_text.as_bytes())
            .and_then(|draft| {
                draft.validate(&challenge)?;
                Ok(draft)
            })
            .map_err(|error| format!("Builder draft was refused: {error}"))?;

        let critique_prompt = reviewer_prompt(&challenge, &draft).map_err(|e| e.to_string())?;
        let critique_text = say(
            &bus,
            &rx,
            reviewer_initiator,
            2,
            &critique_prompt,
            model_wait(models.reviewer_timeout),
        )?;
        validate_contribution("reviewer decision", &critique_text)?;
        let review = ReviewerDecisionV1::decode_json(critique_text.as_bytes())
            .and_then(|review| {
                review.validate(&challenge, &draft)?;
                Ok(review)
            })
            .map_err(|error| format!("Reviewer decision was refused: {error}"))?;

        let contract_test_prompt =
            contract_tester_prompt(&challenge, &draft, &review).map_err(|e| e.to_string())?;
        let test_plan_text = say(
            &bus,
            &rx,
            contract_tester_initiator,
            3,
            &contract_test_prompt,
            model_wait(models.contract_tester_timeout),
        )?;
        validate_contribution("contract tester plan", &test_plan_text)?;
        let test_plan = ContractTestPlanV1::decode_json(test_plan_text.as_bytes())
            .and_then(|plan| {
                plan.validate(&challenge, &draft, &review)?;
                Ok(plan)
            })
            .map_err(|error| format!("Contract Tester plan was refused: {error}"))?;

        let approval_prompt = final_approval_prompt(&challenge, &draft, &review, &test_plan)
            .map_err(|error| error.to_string())?;
        let approval_text = say(
            &bus,
            &rx,
            builder_initiator,
            4,
            &approval_prompt,
            model_wait(models.builder_timeout),
        )?;
        validate_contribution("builder approval", &approval_text)?;
        let approval = FinalApprovalV1::decode_json(approval_text.as_bytes())
            .map_err(|error| format!("Builder final approval was refused: {error}"))?;
        if live {
            let fixture_challenge = ChallengeV1::new(FIXTURE_CHALLENGE_NONCE);
            let fixture = fixture_chain(&fixture_challenge)?;
            let mut forbidden = Vec::with_capacity(forbidden_semantics.len() + 1);
            forbidden.push(fixture.approval.normalized_spec.semantic_digest);
            forbidden.extend(forbidden_semantics.iter().cloned());
            approval
                .validate_with_forbidden_semantics(
                    &challenge, &draft, &review, &test_plan, &forbidden,
                )
                .map_err(|error| format!("Builder final approval was refused: {error}"))?;
        } else {
            approval
                .validate(&challenge, &draft, &review, &test_plan)
                .map_err(|error| format!("Builder final approval was refused: {error}"))?;
        }
        let profile = approved_profile(&approval.normalized_spec)?;
        let approval_digest = approval
            .hash(&challenge, &draft, &review, &test_plan)
            .map_err(|error| error.to_string())?;
        if let Some(slot) = &models.fixture_profile {
            *slot.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(profile.clone());
        }

        let capabilities = author_suite(
            &b,
            models.builder.clone(),
            AuthorSuiteRequest {
                root,
                node_key: &key_b,
                approved_profile: profile.clone(),
                builder_timeout: models.builder_timeout,
                build_key: &build_key,
                approval_digest: &approval_digest,
            },
        )?;
        if let (Some(evidence), Some(fixture)) = (&models.scripted, &models.fixture) {
            if draft != fixture.draft
                || review != fixture.review
                || test_plan != fixture.test_plan
                || approval != fixture.approval
            {
                return Err("fixture decisions drifted from the reviewed regression fixture".into());
            }
            verify_fixture_evidence(evidence, &challenge, fixture, &profile)?;
        }
        let verified_turns = turns.0.lock().unwrap_or_else(|poison| poison.into_inner()).clone();
        let expected_turns = [
            (900_000, draft_prompt.as_str(), draft_text.as_str()),
            (910_000, critique_prompt.as_str(), critique_text.as_str()),
            (920_000, contract_test_prompt.as_str(), test_plan_text.as_str()),
            (900_001, approval_prompt.as_str(), approval_text.as_str()),
        ];
        if verified_turns.len() != expected_turns.len()
            || !verified_turns.iter().zip(expected_turns).all(|(turn, expected)| {
                turn.corr == expected.0
                    && turn.query_id == 1
                    && turn.prompt == expected.1
                    && turn.answer.reply == expected.2
            })
        {
            return Err("verified turn journal did not preserve the exact four-turn chain".into());
        }
        let model_calls = models.model_calls.records().map_err(|error| error.to_string())?;
        let replay_entries =
            models.model_calls.replay_entries().map_err(|error| error.to_string())?;
        validate_model_call_evidence(&model_calls, live)?;
        verify_model_replay(&replay_entries)?;
        Ok(CollaborationOutput {
            capabilities,
            challenge: challenge.clone(),
            draft,
            review,
            test_plan,
            approval,
            profile_digest: profile.digest().to_string(),
            verified_turns,
            builder_signer: builder_signer.public_key(),
            reviewer_signer: reviewer_signer.public_key(),
            contract_tester_signer: contract_tester_signer.public_key(),
            model_calls,
            replay_entries,
        })
    })();
    a.shutdown_all(Deadline::from_millis(1500));
    drop(a);
    b.shutdown_all(Deadline::from_millis(1500));
    result
}

fn role(name: &str) -> Address {
    Address::Role(Role::new(name))
}

#[cfg(test)]
mod tests {
    use agent_mind::{ApprovedTier, APPROVED_IMPLEMENTATION_V1};

    use super::{
        approved_profile, fixture_chain, validate_live_model_origin, ChallengeV1,
        SanitizedModelConfigV1, FIXTURE_CHALLENGE_NONCE,
    };
    #[cfg(feature = "openai")]
    use super::{model_config, read_private_api_key_file};

    #[test]
    fn fixture_chain_lowers_to_one_dynamic_three_tier_profile() {
        let challenge = ChallengeV1::new(FIXTURE_CHALLENGE_NONCE);
        let fixture = fixture_chain(&challenge).expect("valid regression fixture");
        let profile = approved_profile(&fixture.approval.normalized_spec)
            .expect("approved decision lowers to AgentMind's profile");

        assert_eq!(profile.spec().multiplier, 3);
        assert_eq!(profile.spec().addend, -5);
        assert_eq!(profile.evaluate(profile.spec().local_input).unwrap(), 46);
        assert_eq!(profile.evaluate(profile.spec().remote_input).unwrap(), -62);
        assert_eq!(profile.semantic_digest(), fixture.approval.normalized_spec.semantic_digest);
        for tier in ApprovedTier::ALL {
            let record = profile.implementation(tier);
            assert_eq!(record.schema, APPROVED_IMPLEMENTATION_V1);
            assert_eq!(record.profile_digest, profile.digest());
            assert_eq!(record.tier, tier);
            let json = profile.implementation_json(tier);
            assert!(!json.contains("fn handle"));
            assert!(!json.contains("(module"));
        }
    }

    #[test]
    fn live_model_origin_is_rejected_before_any_provider_call() {
        let config = |origin: &str| SanitizedModelConfigV1 {
            provider: "openai-compatible".into(),
            requested_model: "model-v1".into(),
            endpoint_origin: Some(origin.into()),
            timeout_ms: 60_000,
        };

        for origin in [
            "https://provider.example",
            "http://localhost:11434",
            "http://127.0.0.1:11434",
            "http://[::1]:11434",
        ] {
            validate_live_model_origin(&config(origin)).expect("confidential or loopback origin");
        }
        for origin in ["http://provider.example", "http://127.0.0.2:11434"] {
            assert!(validate_live_model_origin(&config(origin)).is_err());
        }
    }

    #[cfg(all(feature = "openai", unix))]
    #[test]
    fn live_api_key_file_must_be_private_regular_and_canonical() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::time::{SystemTime, UNIX_EPOCH};

        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let root = std::env::temp_dir()
            .join(format!("alpha-dialogue-api-key-{}-{nonce}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let key = root.join("key");
        std::fs::write(&key, b"secret\n").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_private_api_key_file("ALPHA_DIALOGUE_TEST", &key).unwrap().as_deref(),
            Some("secret")
        );

        let role = "FILE_PRECEDENCE_TEST";
        let prefix = format!("ALPHA_DIALOGUE_{role}");
        std::env::set_var(format!("{prefix}_MODEL"), "model-v1");
        std::env::set_var(format!("{prefix}_BASE_URL"), "http://localhost:11434/v1");
        std::env::set_var(format!("{prefix}_API_KEY_FILE"), &key);
        std::env::set_var(format!("{prefix}_API_KEY"), "x".repeat(8 * 1024));
        assert_eq!(model_config(role).unwrap().api_key.as_deref(), Some("secret"));
        for suffix in ["MODEL", "BASE_URL", "API_KEY_FILE", "API_KEY"] {
            std::env::remove_var(format!("{prefix}_{suffix}"));
        }

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_api_key_file("ALPHA_DIALOGUE_TEST", &key).is_err());
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = root.join("key-link");
        symlink(&key, &link).unwrap();
        assert!(read_private_api_key_file("ALPHA_DIALOGUE_TEST", &link).is_err());
        std::fs::remove_file(link).unwrap();
        std::fs::remove_file(key).unwrap();
        std::fs::remove_dir(root).unwrap();
    }
}
