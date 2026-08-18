//! Construction-time approved capability profiles for model-backed authoring.
//!
//! This is deliberately **not** a new fabric or authoring wire contract. A composition root obtains
//! an approved structured specification through its own signed workflow, verifies the canonical
//! digest, and injects the resulting [`ApprovedTypedProfile`] into `AgentMind`. The existing
//! `AuthoringRequest::request` string then carries only an exact, digest-bound tier selector.
//!
//! Native code is trusted by admission, so an approved profile never accepts model-authored Rust,
//! WAT, or Rhai. The model confirms a tiny typed implementation record and this module renders all
//! executable bytes from audited templates. Only validated ASCII identifiers and decimal `i32`
//! literals enter those templates.

use build_cargo::ManifestStub;
use gawdfn::{
    canonical_hash, canonical_json_bytes, EffectClassV1, EntrypointContractV1, FunctionControlsV1,
    SchemaRefV1, Validate, SCHEMA_CALL_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sigil::{Capabilities, Entrypoint};

/// Reserved first-line marker for approved-profile authoring selectors.
pub const APPROVED_TYPED_REQUEST_V1: &str = "ALPHA_APPROVED_TYPED_V1";
/// Schema discriminator in the model's small, non-executable implementation record.
pub const APPROVED_IMPLEMENTATION_V1: &str = "alpha.approved_implementation.v1";
/// Domain separator for the name/test-independent semantic truth-table digest.
pub const AFFINE_I32_TRUTH_TABLE_V1: &str = "alpha.capability.affine-i32.truth-table.v1";

/// Profile JSON retained in prompts and hashed for approval is intentionally small.
pub const MAX_APPROVED_PROFILE_BYTES: usize = 16 * 1024;
/// A bounded domain makes exhaustive checked evaluation a construction-time proof, not sampling.
pub const MAX_AFFINE_DOMAIN_VALUES: u32 = 257;
pub const MAX_PROFILE_SLUG_BYTES: usize = 96;
pub const MAX_PROFILE_NAME_BYTES: usize = 128;
pub const MAX_PROFILE_ENTRYPOINT_BYTES: usize = 128;
pub const MAX_PROFILE_DESCRIPTION_BYTES: usize = 1024;
/// Coefficient limits mirror the signed collaboration challenge, preventing a composition root
/// from constructing a broader executable family than the reviewed decision protocol admits.
pub const MIN_AFFINE_MULTIPLIER: i32 = -16;
pub const MAX_AFFINE_MULTIPLIER: i32 = 16;
pub const MIN_AFFINE_ADDEND: i32 = -1_000_000;
pub const MAX_AFFINE_ADDEND: i32 = 1_000_000;

/// The only executable program family admitted by this first dynamic profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovedProgramKindV1 {
    AffineI32V1,
}

/// A model-originated, bounded `i32` affine Function specification.
///
/// Its application shape is fixed in v1: `{ "value": i32 } -> { "result": i32 }`. Keeping the
/// shape fixed leaves the native, WASM, and Rhai renderers compact enough to audit. New shapes are
/// new tagged program variants, not unchecked strings interpreted by these renderers.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffineI32SpecV1 {
    pub kind: ApprovedProgramKindV1,
    /// Lowercase manifest/Cargo stem. Tier suffixes are added by the trusted profile.
    pub slug: String,
    /// Human-facing capability name retained in the approved spec and prompt.
    pub name: String,
    /// Typed Function entrypoint advertised by every tier manifest.
    pub entrypoint: String,
    pub description: String,
    pub input_min: i32,
    pub input_max: i32,
    pub multiplier: i32,
    pub addend: i32,
    /// Positive/negative, distinct acceptance vectors chosen during collaboration.
    pub local_input: i32,
    pub remote_input: i32,
}

/// The three existing Alpha creature backends targeted by one approved profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovedTier {
    Daemon,
    Beast,
    Critter,
}

impl ApprovedTier {
    pub const ALL: [Self; 3] = [Self::Daemon, Self::Beast, Self::Critter];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Daemon => "daemon",
            Self::Beast => "beast",
            Self::Critter => "critter",
        }
    }
}

/// The only model reply accepted for an approved profile.
///
/// This is an internal model-completion contract, not an Envelope or AUTHORING wire type. Strict
/// unknown-field rejection prevents a completion from smuggling source, dependencies, authority,
/// or an alternate program beside the reviewed fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedImplementationV1 {
    pub schema: String,
    pub profile_digest: String,
    pub tier: ApprovedTier,
    pub program: AffineI32ProgramV1,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffineI32ProgramV1 {
    pub kind: ApprovedProgramKindV1,
    pub multiplier: i32,
    pub addend: i32,
}

/// Canonical semantic preimage shared with collaboration/evaluation code. It intentionally excludes
/// presentation, identity, and selected test-vector fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticTruthTableV1 {
    pub schema: String,
    pub capability_kind: ApprovedProgramKindV1,
    pub input_min: i32,
    pub input_max: i32,
    pub points: Vec<AffineI32TruthPointV1>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AffineI32TruthPointV1 {
    pub input: i32,
    pub output: i32,
}

/// A validated, immutable construction-time authoring profile.
#[derive(Clone, Debug)]
pub struct ApprovedTypedProfile {
    spec: AffineI32SpecV1,
    digest: String,
    canonical_spec: String,
    semantic_digest: String,
    output_min: i32,
    output_max: i32,
}

/// A fail-closed profile construction or model-confirmation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileError {
    message: String,
}

impl ProfileError {
    fn new(message: impl Into<String>) -> Self {
        Self { message: message.into() }
    }
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ProfileError {}

impl ApprovedTypedProfile {
    /// Validate `spec`, recompute its canonical digest, and require the signer-approved digest.
    pub fn from_approved(
        spec: AffineI32SpecV1,
        approved_digest: &str,
    ) -> Result<Self, ProfileError> {
        let analysis = analyze_spec(&spec)?;
        if approved_digest != analysis.digest {
            return Err(ProfileError::new(format!(
                "approved profile digest mismatch: received `{approved_digest}`, computed `{}`",
                analysis.digest
            )));
        }
        Ok(Self {
            spec,
            digest: analysis.digest,
            canonical_spec: analysis.canonical_spec,
            semantic_digest: analysis.semantic_digest,
            output_min: analysis.output_min,
            output_max: analysis.output_max,
        })
    }

    /// Validate and hash a candidate spec before a collaboration signs or approves it.
    pub fn canonical_digest(spec: &AffineI32SpecV1) -> Result<String, ProfileError> {
        Ok(analyze_spec(spec)?.digest)
    }

    /// Hash only the exhaustive input/output truth table. Human names, entrypoint, description,
    /// and selected local/remote test vectors deliberately do not affect semantic novelty.
    pub fn canonical_semantic_digest(spec: &AffineI32SpecV1) -> Result<String, ProfileError> {
        Ok(analyze_spec(spec)?.semantic_digest)
    }

    /// Return the exact canonical semantic preimage so callers never duplicate its field set.
    pub fn semantic_truth_table(
        spec: &AffineI32SpecV1,
    ) -> Result<SemanticTruthTableV1, ProfileError> {
        Ok(analyze_spec(spec)?.semantic_truth_table)
    }

    pub fn spec(&self) -> &AffineI32SpecV1 {
        &self.spec
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn canonical_spec(&self) -> &str {
        &self.canonical_spec
    }

    pub fn semantic_digest(&self) -> &str {
        &self.semantic_digest
    }

    pub fn output_bounds(&self) -> (i32, i32) {
        (self.output_min, self.output_max)
    }

    /// Checked execution used by the acceptance harness to derive expected outputs.
    pub fn evaluate(&self, input: i32) -> Result<i32, ProfileError> {
        if !(self.spec.input_min..=self.spec.input_max).contains(&input) {
            return Err(ProfileError::new(format!(
                "input {input} is outside approved bounds {}..={}",
                self.spec.input_min, self.spec.input_max
            )));
        }
        checked_affine(&self.spec, input).ok_or_else(|| {
            ProfileError::new(format!("approved affine program overflowed for input {input}"))
        })
    }

    /// Exact selector carried through the existing free-form `AuthoringRequest::request` field.
    pub fn request(&self, tier: ApprovedTier) -> String {
        format!("{APPROVED_TYPED_REQUEST_V1}\nprofile={}\ntier={}", self.digest, tier.as_str())
    }

    pub(crate) fn tier_for_request(&self, request: &str) -> Option<ApprovedTier> {
        ApprovedTier::ALL.into_iter().find(|tier| request == self.request(*tier))
    }

    /// Exact strict record a conforming model returns. Primarily useful to hermetic fixture models.
    pub fn implementation(&self, tier: ApprovedTier) -> ApprovedImplementationV1 {
        ApprovedImplementationV1 {
            schema: APPROVED_IMPLEMENTATION_V1.to_string(),
            profile_digest: self.digest.clone(),
            tier,
            program: AffineI32ProgramV1 {
                kind: self.spec.kind,
                multiplier: self.spec.multiplier,
                addend: self.spec.addend,
            },
        }
    }

    /// Infallible serialization of the strict plain-data implementation record for hermetic model
    /// fixtures. Product models receive the prompt and must originate their own equivalent record.
    pub fn implementation_json(&self, tier: ApprovedTier) -> String {
        serde_json::to_string(&self.implementation(tier))
            .expect("approved implementation serialization is infallible for plain data")
    }

    pub(crate) fn verify_implementation(
        &self,
        tier: ApprovedTier,
        implementation: &ApprovedImplementationV1,
    ) -> Result<(), ProfileError> {
        if implementation.schema != APPROVED_IMPLEMENTATION_V1 {
            return Err(ProfileError::new(format!(
                "implementation schema must be `{APPROVED_IMPLEMENTATION_V1}`"
            )));
        }
        if implementation.profile_digest != self.digest {
            return Err(ProfileError::new(
                "implementation does not bind the exact approved profile digest",
            ));
        }
        if implementation.tier != tier {
            return Err(ProfileError::new(
                "implementation tier does not match the approved authoring request",
            ));
        }
        let expected = self.implementation(tier);
        if implementation.program != expected.program {
            return Err(ProfileError::new(
                "implementation program differs from the approved affine program",
            ));
        }
        Ok(())
    }

    /// The exact no-authority manifest half shared semantically by all three rendered sources.
    pub fn manifest_stub(&self, tier: ApprovedTier) -> ManifestStub {
        ManifestStub {
            name: format!("{}-{}", self.spec.slug, tier.as_str()),
            version: "0.1.0".to_string(),
            entrypoints: vec![Entrypoint {
                name: self.spec.entrypoint.clone(),
                signature: SCHEMA_CALL_V1.to_string(),
                contract: Some(self.contract()),
            }],
            capabilities: Capabilities::default(),
            provides: vec![],
        }
    }

    pub fn contract(&self) -> EntrypointContractV1 {
        EntrypointContractV1 {
            description: self.spec.description.clone(),
            input_schema: SchemaRefV1::Inline {
                schema: json!({
                    "type": "object",
                    "properties": {
                        "value": {
                            "type": "integer",
                            "minimum": self.spec.input_min,
                            "maximum": self.spec.input_max
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
                            "minimum": self.output_min,
                            "maximum": self.output_max
                        }
                    },
                    "required": ["result"],
                    "additionalProperties": false
                }),
            },
            error_schema: None,
            effect: EffectClassV1::Idempotent,
            controls: FunctionControlsV1::default(),
        }
    }

    /// Render the exact audited executable source for one tier from this validated profile.
    ///
    /// This is public so an offline evidence verifier can independently reproduce and compare the
    /// retained source bytes. No model-controlled source crosses this boundary; only already-
    /// validated ASCII identifiers and decimal `i32` literals are inserted.
    pub fn rendered_source(&self, tier: ApprovedTier) -> String {
        match tier {
            ApprovedTier::Daemon => self.render_daemon(),
            ApprovedTier::Beast => self.render_beast(),
            ApprovedTier::Critter => self.render_critter(),
        }
    }

    fn render_daemon(&self) -> String {
        render(
            DAEMON_TEMPLATE,
            &[
                ("__ENTRYPOINT__", &self.spec.entrypoint),
                ("__INPUT_MIN__", &self.spec.input_min.to_string()),
                ("__INPUT_MAX__", &self.spec.input_max.to_string()),
                ("__MULTIPLIER__", &self.spec.multiplier.to_string()),
                ("__ADDEND__", &self.spec.addend.to_string()),
                ("__OUTPUT_MIN__", &self.output_min.to_string()),
                ("__OUTPUT_MAX__", &self.output_max.to_string()),
            ],
        )
    }

    fn render_critter(&self) -> String {
        render(
            CRITTER_TEMPLATE,
            &[
                ("__ENTRYPOINT__", &self.spec.entrypoint),
                ("__INPUT_MIN__", &self.spec.input_min.to_string()),
                ("__INPUT_MAX__", &self.spec.input_max.to_string()),
                ("__MULTIPLIER__", &self.spec.multiplier.to_string()),
                ("__ADDEND__", &self.spec.addend.to_string()),
                ("__OUTPUT_MIN__", &self.output_min.to_string()),
                ("__OUTPUT_MAX__", &self.output_max.to_string()),
            ],
        )
    }

    fn render_beast(&self) -> String {
        let max_magnitude =
            self.spec.input_min.unsigned_abs().max(self.spec.input_max.unsigned_abs());
        render(
            BEAST_TEMPLATE,
            &[
                ("__MAX_MAGNITUDE__", &max_magnitude.to_string()),
                ("__INPUT_MIN__", &self.spec.input_min.to_string()),
                ("__INPUT_MAX__", &self.spec.input_max.to_string()),
                ("__MULTIPLIER__", &self.spec.multiplier.to_string()),
                ("__ADDEND__", &self.spec.addend.to_string()),
                ("__OUTPUT_MIN__", &self.output_min.to_string()),
                ("__OUTPUT_MAX__", &self.output_max.to_string()),
            ],
        )
    }
}

/// A request in the reserved namespace that does not exactly match the injected profile must never
/// fall through to general native authoring.
pub(crate) fn is_reserved_request(request: &str) -> bool {
    request.trim_start().starts_with(APPROVED_TYPED_REQUEST_V1)
}

struct Analysis {
    digest: String,
    canonical_spec: String,
    semantic_digest: String,
    semantic_truth_table: SemanticTruthTableV1,
    output_min: i32,
    output_max: i32,
}

fn analyze_spec(spec: &AffineI32SpecV1) -> Result<Analysis, ProfileError> {
    if spec.kind != ApprovedProgramKindV1::AffineI32V1 {
        return Err(ProfileError::new("unsupported approved program kind"));
    }
    validate_slug(&spec.slug)?;
    validate_printable_ascii("name", &spec.name, MAX_PROFILE_NAME_BYTES)?;
    validate_identifier(&spec.entrypoint)?;
    validate_printable_ascii("description", &spec.description, MAX_PROFILE_DESCRIPTION_BYTES)?;

    if spec.input_min >= 0 || spec.input_max <= 0 {
        return Err(ProfileError::new(
            "approved affine input domain must contain both negative and positive values",
        ));
    }
    let domain = i64::from(spec.input_max) - i64::from(spec.input_min) + 1;
    if !(1..=i64::from(MAX_AFFINE_DOMAIN_VALUES)).contains(&domain) {
        return Err(ProfileError::new(format!(
            "approved affine domain has {domain} values; limit is {MAX_AFFINE_DOMAIN_VALUES}"
        )));
    }
    if !(MIN_AFFINE_MULTIPLIER..=MAX_AFFINE_MULTIPLIER).contains(&spec.multiplier) {
        return Err(ProfileError::new(format!(
            "multiplier must be in {MIN_AFFINE_MULTIPLIER}..={MAX_AFFINE_MULTIPLIER}"
        )));
    }
    if !(MIN_AFFINE_ADDEND..=MAX_AFFINE_ADDEND).contains(&spec.addend) {
        return Err(ProfileError::new(format!(
            "addend must be in {MIN_AFFINE_ADDEND}..={MAX_AFFINE_ADDEND}"
        )));
    }
    if spec.multiplier == 0
        || (spec.multiplier == 1 && spec.addend == 0)
        || (spec.multiplier == -1 && spec.addend == 0)
    {
        return Err(ProfileError::new(
            "approved affine program must be non-constant and not canonical identity or negation",
        ));
    }
    if spec.multiplier == 2 && spec.addend == 0 {
        return Err(ProfileError::new(
            "the legacy double_signed semantics are not a novel approved capability",
        ));
    }
    for (label, input) in [("local_input", spec.local_input), ("remote_input", spec.remote_input)] {
        if !(spec.input_min..=spec.input_max).contains(&input) {
            return Err(ProfileError::new(format!(
                "{label} {input} is outside approved bounds {}..={}",
                spec.input_min, spec.input_max
            )));
        }
    }
    if spec.local_input == 0
        || spec.remote_input == 0
        || spec.local_input.signum() == spec.remote_input.signum()
    {
        return Err(ProfileError::new(
            "local_input and remote_input must be distinct nonzero vectors on opposite sides of zero",
        ));
    }

    let mut output_min = i32::MAX;
    let mut output_max = i32::MIN;
    let mut points = Vec::with_capacity(domain as usize);
    for input in spec.input_min..=spec.input_max {
        let output = checked_affine(spec, input).ok_or_else(|| {
            ProfileError::new(format!("affine program overflows i32 for approved input {input}"))
        })?;
        output_min = output_min.min(output);
        output_max = output_max.max(output);
        points.push(AffineI32TruthPointV1 { input, output });
    }

    let contract = EntrypointContractV1 {
        description: spec.description.clone(),
        input_schema: SchemaRefV1::Inline {
            schema: json!({
                "type": "object",
                "properties": { "value": {
                    "type": "integer", "minimum": spec.input_min, "maximum": spec.input_max
                }},
                "required": ["value"],
                "additionalProperties": false
            }),
        },
        output_schema: SchemaRefV1::Inline {
            schema: json!({
                "type": "object",
                "properties": { "result": {
                    "type": "integer", "minimum": output_min, "maximum": output_max
                }},
                "required": ["result"],
                "additionalProperties": false
            }),
        },
        error_schema: None,
        effect: EffectClassV1::Idempotent,
        controls: FunctionControlsV1::default(),
    };
    contract
        .validate()
        .map_err(|error| ProfileError::new(format!("derived Function contract: {error}")))?;

    let canonical = canonical_json_bytes(spec)
        .map_err(|error| ProfileError::new(format!("canonical approved profile: {error}")))?;
    if canonical.len() > MAX_APPROVED_PROFILE_BYTES {
        return Err(ProfileError::new(format!(
            "canonical approved profile is {} bytes; limit is {MAX_APPROVED_PROFILE_BYTES}",
            canonical.len()
        )));
    }
    let canonical_spec = String::from_utf8(canonical)
        .map_err(|_| ProfileError::new("canonical approved profile is not UTF-8"))?;
    let digest = canonical_hash(spec)
        .map_err(|error| ProfileError::new(format!("hash approved profile: {error}")))?;
    let semantic_truth_table = SemanticTruthTableV1 {
        schema: AFFINE_I32_TRUTH_TABLE_V1.to_string(),
        capability_kind: spec.kind,
        input_min: spec.input_min,
        input_max: spec.input_max,
        points,
    };
    let semantic_digest = canonical_hash(&semantic_truth_table)
        .map_err(|error| ProfileError::new(format!("hash affine truth table: {error}")))?;
    Ok(Analysis {
        digest,
        canonical_spec,
        semantic_digest,
        semantic_truth_table,
        output_min,
        output_max,
    })
}

fn checked_affine(spec: &AffineI32SpecV1, input: i32) -> Option<i32> {
    input.checked_mul(spec.multiplier)?.checked_add(spec.addend)
}

fn validate_slug(slug: &str) -> Result<(), ProfileError> {
    if slug.is_empty() || slug.len() > MAX_PROFILE_SLUG_BYTES {
        return Err(ProfileError::new(format!(
            "slug must contain 1..={MAX_PROFILE_SLUG_BYTES} bytes"
        )));
    }
    let mut bytes = slug.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(ProfileError::new(
            "slug must start with a lowercase ASCII letter and contain only lowercase letters, digits, or `-`",
        ));
    }
    if slug.ends_with('-') || slug.contains("--") {
        return Err(ProfileError::new("slug must not end in `-` or contain consecutive `-`"));
    }
    // Longest suffix is `-critter`; keep the derived manifest name within sigil's 128-byte cap.
    if slug.len() + "-critter".len() > sigil::MAX_MANIFEST_NAME_BYTES {
        return Err(ProfileError::new("tier-suffixed slug exceeds manifest name limit"));
    }
    Ok(())
}

fn validate_identifier(value: &str) -> Result<(), ProfileError> {
    if value.is_empty() || value.len() > MAX_PROFILE_ENTRYPOINT_BYTES {
        return Err(ProfileError::new(format!(
            "entrypoint must contain 1..={MAX_PROFILE_ENTRYPOINT_BYTES} bytes"
        )));
    }
    let mut bytes = value.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_')
        || !bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        return Err(ProfileError::new("entrypoint must be a lowercase ASCII identifier"));
    }
    Ok(())
}

fn validate_printable_ascii(label: &str, value: &str, max: usize) -> Result<(), ProfileError> {
    if value.is_empty() || value.len() > max || value.trim() != value {
        return Err(ProfileError::new(format!(
            "{label} must contain 1..={max} bytes with no surrounding whitespace"
        )));
    }
    if !value.bytes().all(|byte| byte == b' ' || byte.is_ascii_graphic()) {
        return Err(ProfileError::new(format!("{label} must contain printable ASCII only")));
    }
    Ok(())
}

fn render(template: &str, replacements: &[(&str, &str)]) -> String {
    let mut rendered = template.to_string();
    for (marker, value) in replacements {
        rendered = rendered.replace(marker, value);
    }
    rendered
}

const DAEMON_TEMPLATE: &str = r#"use forge::prelude::*;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct ApprovedAffineDaemon {
    manifest_content_address: Option<String>,
}

impl Creature for ApprovedAffineDaemon {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.manifest_content_address = ctx.manifest.content_address;
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        let Some(manifest_content_address) = self.manifest_content_address.as_deref() else {
            return Outcome::none();
        };
        let Ok(call) = forge::function::parse_call(&env) else {
            return Outcome::none();
        };
        if call.function.manifest_content_address != manifest_content_address
            || call.function.entrypoint != "__ENTRYPOINT__"
        {
            return Outcome::none();
        }
        let Ok(mut input) = forge::function::from_inline::<BTreeMap<String, i32>>(&call.input)
        else {
            return Outcome::none();
        };
        if input.len() != 1 {
            return Outcome::none();
        }
        let Some(value) = input.remove("value") else {
            return Outcome::none();
        };
        if !(__INPUT_MIN__..=__INPUT_MAX__).contains(&value) {
            return Outcome::none();
        }
        let Some(result) = value
            .checked_mul(__MULTIPLIER__)
            .and_then(|value| value.checked_add(__ADDEND__))
        else {
            return Outcome::none();
        };
        if !(__OUTPUT_MIN__..=__OUTPUT_MAX__).contains(&result) {
            return Outcome::none();
        }
        let output = BTreeMap::from([("result", result)]);
        forge::function::success(&env, call.attempt, &output)
            .map(Outcome::send)
            .unwrap_or_else(|_| Outcome::none())
    }
}

forge::declare_creature!(ApprovedAffineDaemon);
"#;

const CRITTER_TEMPLATE: &str = r#"fn handle(env) {
    if env.schema != "gawd.function.call.v1" || env.text_truncated {
        return ();
    }
    if !function_call_verify(env.text, env.from, env.to) {
        return ();
    }
    let message = json_parse(env.text);
    if message.operation != "call" {
        return ();
    }
    let invocation = message["call"];
    if invocation.function.entrypoint != "__ENTRYPOINT__" || invocation.input.kind != "inline" {
        return ();
    }
    let input = invocation.input.value;
    if type_of(input) != "map" || input.len() != 1 || !input.contains("value") {
        return ();
    }
    let value = input.value;
    if type_of(value) != "i64" || value < __INPUT_MIN__ || value > __INPUT_MAX__ {
        return ();
    }
    let result = value * __MULTIPLIER__ + __ADDEND__;
    if result < __OUTPUT_MIN__ || result > __OUTPUT_MAX__ {
        return ();
    }
    json_stringify(#{
        operation: "result",
        result: #{
            attempt: invocation.attempt,
            outcome: #{ Ok: #{ kind: "inline", value: #{ result: result } } }
        }
    })
}
"#;

// This renderer accepts only canonical application JSON produced by WasmEngine's typed host
// adapter. The host authenticates the grant, route, FunctionId, and AttemptId; the guest sees only
// `{ "value": i32 }` and returns `{ "result": i32 }`.
const BEAST_TEMPLATE: &str = r#"(module
  (memory (export "memory") 1)

  (func (export "alloc") (param $len i32) (result i32)
    (i32.const 1024))

  (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
    (local $cursor i32)
    (local $end i32)
    (local $digit i32)
    (local $value i32)
    (local $sign i32)
    (local $result i32)
    (local $magnitude i32)
    (local $digits i32)
    (local $out i32)

    (if (i32.lt_u (local.get $len) (i32.const 11))
      (then (return (i64.const 0))))
    (if (i32.gt_u (local.get $len) (i32.const 18))
      (then (return (i64.const 0))))
    (if (i64.ne
          (i64.load (local.get $ptr))
          (i64.const 0x2265756c6176227b))
      (then (return (i64.const 0))))
    (if (i32.ne (i32.load8_u offset=8 (local.get $ptr)) (i32.const 58))
      (then (return (i64.const 0))))

    (local.set $end
      (i32.add (local.get $ptr) (i32.sub (local.get $len) (i32.const 1))))
    (if (i32.ne (i32.load8_u (local.get $end)) (i32.const 125))
      (then (return (i64.const 0))))
    (local.set $cursor (i32.add (local.get $ptr) (i32.const 9)))
    (local.set $sign (i32.const 1))
    (if (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 45))
      (then
        (local.set $sign (i32.const -1))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))))
    (if (i32.ge_u (local.get $cursor) (local.get $end))
      (then (return (i64.const 0))))
    (if (i32.and
          (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 48))
          (i32.lt_u (i32.add (local.get $cursor) (i32.const 1)) (local.get $end)))
      (then (return (i64.const 0))))

    (block $digits_done
      (loop $parse_digit
        (br_if $digits_done (i32.ge_u (local.get $cursor) (local.get $end)))
        (local.set $digit (i32.load8_u (local.get $cursor)))
        (if (i32.or
              (i32.lt_u (local.get $digit) (i32.const 48))
              (i32.gt_u (local.get $digit) (i32.const 57)))
          (then (return (i64.const 0))))
        (local.set $value
          (i32.add
            (i32.mul (local.get $value) (i32.const 10))
            (i32.sub (local.get $digit) (i32.const 48))))
        (if (i32.gt_u (local.get $value) (i32.const __MAX_MAGNITUDE__))
          (then (return (i64.const 0))))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))
        (br $parse_digit)))

    (if (i32.eq (local.get $sign) (i32.const -1))
      (then (local.set $value (i32.sub (i32.const 0) (local.get $value)))))
    (if (i32.or
          (i32.lt_s (local.get $value) (i32.const __INPUT_MIN__))
          (i32.gt_s (local.get $value) (i32.const __INPUT_MAX__)))
      (then (return (i64.const 0))))
    (local.set $result
      (i32.add
        (i32.mul (local.get $value) (i32.const __MULTIPLIER__))
        (i32.const __ADDEND__)))
    (if (i32.or
          (i32.lt_s (local.get $result) (i32.const __OUTPUT_MIN__))
          (i32.gt_s (local.get $result) (i32.const __OUTPUT_MAX__)))
      (then (return (i64.const 0))))

    (i64.store (i32.const 4096) (i64.const 0x746c75736572227b))
    (i32.store offset=8 (i32.const 4096) (i32.const 0x00003a22))
    (local.set $out (i32.const 4106))
    (if (i32.lt_s (local.get $result) (i32.const 0))
      (then
        (i32.store8 (local.get $out) (i32.const 45))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (local.set $magnitude (i32.sub (i32.const 0) (local.get $result))))
      (else (local.set $magnitude (local.get $result))))

    (loop $write_reverse
      (i32.store8
        (i32.add (i32.const 4200) (local.get $digits))
        (i32.add
          (i32.const 48)
          (i32.rem_u (local.get $magnitude) (i32.const 10))))
      (local.set $digits (i32.add (local.get $digits) (i32.const 1)))
      (local.set $magnitude (i32.div_u (local.get $magnitude) (i32.const 10)))
      (br_if $write_reverse (i32.ne (local.get $magnitude) (i32.const 0))))

    (block $copy_done
      (loop $copy_digit
        (br_if $copy_done (i32.eqz (local.get $digits)))
        (local.set $digits (i32.sub (local.get $digits) (i32.const 1)))
        (i32.store8
          (local.get $out)
          (i32.load8_u (i32.add (i32.const 4200) (local.get $digits))))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (br $copy_digit)))
    (i32.store8 (local.get $out) (i32.const 125))
    (local.set $out (i32.add (local.get $out) (i32.const 1)))

    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 4096)) (i64.const 32))
      (i64.extend_i32_u (i32.sub (local.get $out) (i32.const 4096))))))
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> AffineI32SpecV1 {
        AffineI32SpecV1 {
            kind: ApprovedProgramKindV1::AffineI32V1,
            slug: "triple-minus-five".into(),
            name: "Triple minus five".into(),
            entrypoint: "triple_minus_five".into(),
            description: "Multiply a bounded integer by three, then subtract five.".into(),
            input_min: -128,
            input_max: 128,
            multiplier: 3,
            addend: -5,
            local_input: 21,
            remote_input: -21,
        }
    }

    fn profile() -> ApprovedTypedProfile {
        let spec = spec();
        let digest = ApprovedTypedProfile::canonical_digest(&spec).expect("valid profile digest");
        ApprovedTypedProfile::from_approved(spec, &digest).expect("approved profile")
    }

    #[test]
    fn canonical_digest_is_order_independent_and_binds_every_semantic_field() {
        let first = serde_json::to_string(&spec()).unwrap();
        let reordered = r#"{"remote_input":-21,"local_input":21,"addend":-5,"multiplier":3,"input_max":128,"input_min":-128,"description":"Multiply a bounded integer by three, then subtract five.","entrypoint":"triple_minus_five","name":"Triple minus five","slug":"triple-minus-five","kind":"affine_i32_v1"}"#;
        let a: AffineI32SpecV1 = serde_json::from_str(&first).unwrap();
        let b: AffineI32SpecV1 = serde_json::from_str(reordered).unwrap();
        assert_eq!(a, b);
        assert_eq!(
            ApprovedTypedProfile::canonical_digest(&a).unwrap(),
            ApprovedTypedProfile::canonical_digest(&b).unwrap()
        );
        let mut drifted = b;
        drifted.addend = -4;
        assert_ne!(
            ApprovedTypedProfile::canonical_digest(&a).unwrap(),
            ApprovedTypedProfile::canonical_digest(&drifted).unwrap()
        );
    }

    #[test]
    fn strict_spec_and_implementation_reject_unknown_fields() {
        let mut value = serde_json::to_value(spec()).unwrap();
        value["hidden_source"] = json!("arbitrary Rust");
        assert!(serde_json::from_value::<AffineI32SpecV1>(value).is_err());

        let p = profile();
        let mut implementation =
            serde_json::to_value(p.implementation(ApprovedTier::Daemon)).unwrap();
        implementation["deps"] = json!(["ambient"]);
        assert!(serde_json::from_value::<ApprovedImplementationV1>(implementation).is_err());
        let mut nested = serde_json::to_value(p.implementation(ApprovedTier::Daemon)).unwrap();
        nested["program"]["source"] = json!("unsafe");
        assert!(serde_json::from_value::<ApprovedImplementationV1>(nested).is_err());
    }

    #[test]
    fn validation_rejects_unbounded_injectable_trivial_or_legacy_profiles() {
        let cases = [
            ("slug", {
                let mut s = spec();
                s.slug = "Bad; source".into();
                s
            }),
            ("entrypoint", {
                let mut s = spec();
                s.entrypoint = "bad\"entry".into();
                s
            }),
            ("ASCII", {
                let mut s = spec();
                s.description = "not printable\nsource".into();
                s
            }),
            ("negative and positive", {
                let mut s = spec();
                s.input_min = 0;
                s
            }),
            ("limit", {
                let mut s = spec();
                s.input_min = -128;
                s.input_max = 129;
                s
            }),
            ("non-constant", {
                let mut s = spec();
                s.multiplier = 0;
                s
            }),
            ("non-constant", {
                let mut s = spec();
                s.multiplier = 1;
                s.addend = 0;
                s
            }),
            ("negation", {
                let mut s = spec();
                s.multiplier = -1;
                s.addend = 0;
                s
            }),
            ("double_signed", {
                let mut s = spec();
                s.multiplier = 2;
                s.addend = 0;
                s
            }),
            ("opposite sides", {
                let mut s = spec();
                s.remote_input = 22;
                s
            }),
            ("multiplier", {
                let mut s = spec();
                s.multiplier = i32::MAX;
                s
            }),
            ("addend", {
                let mut s = spec();
                s.addend = MAX_AFFINE_ADDEND + 1;
                s
            }),
        ];
        for (needle, invalid) in cases {
            let error = ApprovedTypedProfile::canonical_digest(&invalid).unwrap_err();
            assert!(error.to_string().contains(needle), "{needle}: {error}");
        }
    }

    #[test]
    fn approval_digest_must_match_and_evaluation_is_checked_and_bounded() {
        let s = spec();
        assert!(ApprovedTypedProfile::from_approved(s, "sha256:wrong").is_err());
        let p = profile();
        assert_eq!(p.output_bounds(), (-389, 379));
        assert_eq!(p.evaluate(21).unwrap(), 58);
        assert_eq!(p.evaluate(-21).unwrap(), -68);
        assert!(p.evaluate(129).is_err());
    }

    #[test]
    fn semantic_digest_is_the_public_truth_table_and_excludes_identity_and_test_choices() {
        let original = spec();
        let truth = ApprovedTypedProfile::semantic_truth_table(&original).unwrap();
        assert_eq!(truth.schema, AFFINE_I32_TRUTH_TABLE_V1);
        assert_eq!(truth.capability_kind, ApprovedProgramKindV1::AffineI32V1);
        assert_eq!(truth.input_min, -128);
        assert_eq!(truth.input_max, 128);
        assert_eq!(truth.points.len(), 257);
        assert_eq!(truth.points.first().unwrap().input, -128);
        assert_eq!(truth.points.first().unwrap().output, -389);
        assert_eq!(truth.points.last().unwrap().input, 128);
        assert_eq!(truth.points.last().unwrap().output, 379);
        assert_eq!(
            ApprovedTypedProfile::canonical_semantic_digest(&original).unwrap(),
            canonical_hash(&truth).unwrap()
        );

        let mut renamed = original.clone();
        renamed.slug = "same-program-new-name".into();
        renamed.name = "Same program, renamed".into();
        renamed.entrypoint = "same_program_new_name".into();
        renamed.description = "The same approved arithmetic with different presentation.".into();
        renamed.local_input = 7;
        renamed.remote_input = -9;
        assert_ne!(
            ApprovedTypedProfile::canonical_digest(&original).unwrap(),
            ApprovedTypedProfile::canonical_digest(&renamed).unwrap()
        );
        assert_eq!(
            ApprovedTypedProfile::canonical_semantic_digest(&original).unwrap(),
            ApprovedTypedProfile::canonical_semantic_digest(&renamed).unwrap()
        );

        let mut changed = original.clone();
        changed.addend = -6;
        assert_ne!(
            ApprovedTypedProfile::canonical_semantic_digest(&original).unwrap(),
            ApprovedTypedProfile::canonical_semantic_digest(&changed).unwrap()
        );
    }

    #[test]
    fn requests_are_exact_distinct_digest_bound_reserved_selectors() {
        let p = profile();
        let requests = ApprovedTier::ALL.map(|tier| p.request(tier));
        assert_eq!(requests.iter().collect::<std::collections::BTreeSet<_>>().len(), 3);
        for (tier, request) in ApprovedTier::ALL.into_iter().zip(&requests) {
            assert!(request.starts_with(APPROVED_TYPED_REQUEST_V1));
            assert!(request.contains(p.digest()));
            assert_eq!(p.tier_for_request(request), Some(tier));
            assert!(is_reserved_request(&format!("  {request}")));
        }
        assert_eq!(p.tier_for_request(&format!("{}x", requests[0])), None);
    }

    #[test]
    fn manifests_are_one_exact_contract_with_no_authority() {
        let p = profile();
        let expected = p.contract();
        let mut names = std::collections::BTreeSet::new();
        for tier in ApprovedTier::ALL {
            let stub = p.manifest_stub(tier);
            names.insert(stub.name.clone());
            assert_eq!(stub.version, "0.1.0");
            assert_eq!(stub.entrypoints.len(), 1);
            assert_eq!(stub.entrypoints[0].name, "triple_minus_five");
            assert_eq!(stub.entrypoints[0].signature, SCHEMA_CALL_V1);
            assert_eq!(stub.entrypoints[0].contract.as_ref(), Some(&expected));
            assert_eq!(stub.capabilities, Capabilities::default());
            assert!(stub.provides.is_empty());
        }
        assert_eq!(names.len(), 3);
    }

    #[test]
    fn strict_implementation_binds_profile_tier_and_program() {
        let p = profile();
        let good = p.implementation(ApprovedTier::Beast);
        assert_eq!(
            serde_json::from_str::<ApprovedImplementationV1>(
                &p.implementation_json(ApprovedTier::Beast)
            )
            .unwrap(),
            good
        );
        p.verify_implementation(ApprovedTier::Beast, &good).unwrap();
        let mut wrong = good.clone();
        wrong.profile_digest.push('0');
        assert!(p.verify_implementation(ApprovedTier::Beast, &wrong).is_err());
        let mut wrong = good.clone();
        wrong.tier = ApprovedTier::Daemon;
        assert!(p.verify_implementation(ApprovedTier::Beast, &wrong).is_err());
        let mut wrong = good;
        wrong.program.addend += 1;
        assert!(p.verify_implementation(ApprovedTier::Beast, &wrong).is_err());
    }

    #[test]
    fn trusted_renderers_embed_only_validated_semantics_and_security_skeletons() {
        let p = profile();
        let native = p.rendered_source(ApprovedTier::Daemon);
        for required in [
            "forge::function::parse_call(&env)",
            "call.function.manifest_content_address != manifest_content_address",
            "call.function.entrypoint != \"triple_minus_five\"",
            ".checked_mul(3)",
            "value.checked_add(-5)",
            "forge::function::success(&env, call.attempt, &output)",
        ] {
            assert!(native.contains(required), "native missing {required}");
        }
        assert!(!native.contains("double_signed"));
        assert!(!native.contains("__"));

        let critter = p.rendered_source(ApprovedTier::Critter);
        for required in [
            "function_call_verify(env.text, env.from, env.to)",
            "invocation.function.entrypoint != \"triple_minus_five\"",
            "let result = value * 3 + -5;",
            "attempt: invocation.attempt",
        ] {
            assert!(critter.contains(required), "critter missing {required}");
        }
        assert!(!critter.contains("__"));

        let beast = p.rendered_source(ApprovedTier::Beast);
        for required in [
            "(memory (export \"memory\") 1)",
            "(func (export \"alloc\")",
            "(func (export \"handle\")",
            "(i32.mul (local.get $value) (i32.const 3))",
            "(i32.const -5)",
            "0x746c75736572227b",
        ] {
            assert!(beast.contains(required), "beast missing {required}");
        }
        assert!(!beast.contains("(import "));
        assert!(!beast.contains("(start "));
        assert!(!beast.contains("__"));
    }
}
