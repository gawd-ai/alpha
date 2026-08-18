//! Durable, replayable evidence for the live three-mind collaboration proof.
//!
//! This module deliberately has no knowledge of the dialogue composition root.  It supplies the
//! bounded records and secure directory primitive that `collaboration` can wire in once the live
//! decision protocol is ready.  Provider credentials are never accepted by an evidence schema:
//! [`SanitizedModelConfigV1::from_model_config`] reads the requested model, timeout, and only the
//! parsed origin of `ModelConfig::base_url`. User-info, path, query, fragment, and API credentials
//! are never retained.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aether::Signer;
use mind::{Completion, Model, ModelConfig, ModelError, Prompt, ProviderReceipt, TokenUsage};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::{Ed25519KeyMaterial, Verifier};

pub const MAX_EVIDENCE_CALLS: usize = 256;
pub const MAX_ROLE_BYTES: usize = 96;
pub const MAX_MODEL_LABEL_BYTES: usize = 512;
pub const MAX_PROVIDER_LABEL_BYTES: usize = 128;
pub const MAX_ENDPOINT_ORIGIN_BYTES: usize = 512;
pub const MAX_PROMPT_PART_BYTES: usize = 256 * 1024;
pub const MAX_COMPLETION_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_REPLAY_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_SIGNED_TURN_BYTES: usize = 256 * 1024;
pub const MAX_EVIDENCE_FILES: usize = 512;
pub const MAX_EVIDENCE_FILE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_EVIDENCE_TOTAL_BYTES: u64 = 512 * 1024 * 1024;
pub const MAX_EVIDENCE_SIGNER_BYTES: usize = 1_024;
pub const MAX_EVIDENCE_SIGNATURE_BYTES: usize = 4_096;
pub const MAX_SOURCE_TOOL_OUTPUT_BYTES: usize = 16 * 1_024;
/// Year 9999-12-31T23:59:59.999Z. Readings outside the JSON evidence domain are omitted.
pub const MAX_UNIX_TIMESTAMP_MS: u64 = 253_402_300_799_999;
/// Evidence is for bounded calls. Longer monotonic observations are honestly represented as absent.
pub const MAX_MODEL_CALL_DURATION_MS: u64 = 7 * 24 * 60 * 60 * 1_000;
pub const EVIDENCE_INDEX_FILE: &str = "evidence-index.v1.json";

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
pub enum EvidenceError {
    Invalid(String),
    UnsafePath(PathBuf),
    ReuseRefused(PathBuf),
    SymlinkRefused(PathBuf),
    NotRegular(PathBuf),
    PermissionMismatch { path: PathBuf, expected: u32, actual: u32 },
    CapExceeded(&'static str),
    InFlightCalls(usize),
    MissingReplay { role: String, ordinal: u64, prompt_sha256: String },
    UnusedReplay(usize),
    HashMismatch { path: PathBuf, expected: String, actual: String },
    Io { operation: &'static str, path: PathBuf, source: std::io::Error },
    Json(serde_json::Error),
}

impl std::fmt::Display for EvidenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(message) => write!(f, "invalid evidence: {message}"),
            Self::UnsafePath(path) => {
                write!(f, "evidence path is not an absolute, symlink-free leaf: {}", path.display())
            }
            Self::ReuseRefused(path) => {
                write!(f, "refusing to reuse evidence path: {}", path.display())
            }
            Self::SymlinkRefused(path) => {
                write!(f, "refusing to follow evidence symlink: {}", path.display())
            }
            Self::NotRegular(path) => {
                write!(f, "evidence entry is not a regular file: {}", path.display())
            }
            Self::PermissionMismatch { path, expected, actual } => write!(
                f,
                "evidence permissions for {} are {actual:o}, expected {expected:o}",
                path.display()
            ),
            Self::CapExceeded(name) => write!(f, "evidence cap exceeded: {name}"),
            Self::InFlightCalls(count) => {
                write!(f, "cannot snapshot evidence while {count} model calls are in flight")
            }
            Self::MissingReplay { role, ordinal, prompt_sha256 } => write!(
                f,
                "no replay entry for role {role:?}, ordinal {ordinal}, prompt {prompt_sha256}"
            ),
            Self::UnusedReplay(count) => write!(f, "{count} replay entries were not consumed"),
            Self::HashMismatch { path, expected, actual } => write!(
                f,
                "evidence hash mismatch for {}: expected {expected}, got {actual}",
                path.display()
            ),
            Self::Io { operation, path, source } => {
                write!(f, "could not {operation} {}: {source}", path.display())
            }
            Self::Json(source) => write!(f, "could not encode/decode evidence JSON: {source}"),
        }
    }
}

impl std::error::Error for EvidenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Json(source) => Some(source),
            _ => None,
        }
    }
}

impl From<serde_json::Error> for EvidenceError {
    fn from(source: serde_json::Error) -> Self {
        Self::Json(source)
    }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> EvidenceError {
    EvidenceError::Io { operation, path: path.to_path_buf(), source }
}

fn sha256(bytes: &[u8]) -> String {
    gawdfn::sha256_digest(bytes)
        .strip_prefix("sha256:")
        .expect("gawdfn::sha256_digest always prefixes its digest")
        .to_string()
}

fn push_framed(target: &mut Vec<u8>, bytes: &[u8]) {
    target.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    target.extend_from_slice(bytes);
}

/// Hash every field in a prompt, including the exact floating-point bit pattern.
pub fn prompt_sha256(prompt: &Prompt) -> Result<String, EvidenceError> {
    validate_prompt(prompt)?;
    let mut framed = Vec::with_capacity(
        64 + prompt.system_prompt.len().saturating_add(prompt.user_prompt.len()),
    );
    push_framed(&mut framed, b"alpha.model-prompt.v1");
    push_framed(&mut framed, prompt.system_prompt.as_bytes());
    push_framed(&mut framed, prompt.user_prompt.as_bytes());
    framed.extend_from_slice(&prompt.max_tokens.to_be_bytes());
    framed.extend_from_slice(&prompt.temperature.to_bits().to_be_bytes());
    Ok(sha256(&framed))
}

/// Hash the complete successful model response, not just its text.
pub fn completion_sha256(completion: &Completion) -> Result<String, EvidenceError> {
    validate_completion(completion)?;
    let mut framed =
        Vec::with_capacity(64 + completion.content.len().saturating_add(completion.model.len()));
    push_framed(&mut framed, b"alpha.model-completion.v1");
    push_framed(&mut framed, completion.content.as_bytes());
    push_framed(&mut framed, completion.model.as_bytes());
    match &completion.usage {
        Some(usage) => {
            framed.push(1);
            framed.extend_from_slice(&usage.prompt_tokens.to_be_bytes());
            framed.extend_from_slice(&usage.completion_tokens.to_be_bytes());
            framed.extend_from_slice(&usage.total_tokens.to_be_bytes());
        }
        None => framed.push(0),
    }
    match &completion.provider {
        Some(receipt) => {
            framed.push(1);
            for value in [
                receipt.response_id.as_deref(),
                receipt.request_id.as_deref(),
                receipt.reported_model.as_deref(),
                receipt.finish_reason.as_deref(),
            ] {
                match value {
                    Some(value) => {
                        framed.push(1);
                        push_framed(&mut framed, value.as_bytes());
                    }
                    None => framed.push(0),
                }
            }
            framed.push(u8::from(receipt.store_requested));
        }
        None => framed.push(0),
    }
    Ok(sha256(&framed))
}

fn validate_prompt(prompt: &Prompt) -> Result<(), EvidenceError> {
    if prompt.system_prompt.len() > MAX_PROMPT_PART_BYTES {
        return Err(EvidenceError::CapExceeded("model system prompt bytes"));
    }
    if prompt.user_prompt.len() > MAX_PROMPT_PART_BYTES {
        return Err(EvidenceError::CapExceeded("model user prompt bytes"));
    }
    if !prompt.temperature.is_finite() {
        return Err(EvidenceError::Invalid("model temperature must be finite".into()));
    }
    Ok(())
}

fn validate_completion(completion: &Completion) -> Result<(), EvidenceError> {
    if completion.content.len() > MAX_COMPLETION_BYTES {
        return Err(EvidenceError::CapExceeded("model completion bytes"));
    }
    validate_bounded_text("responding model", &completion.model, MAX_MODEL_LABEL_BYTES)?;
    if let Some(receipt) = &completion.provider {
        ProviderReceiptMetadataV1::from_provider_receipt(receipt)?.validate()?;
    }
    Ok(())
}

fn validate_bounded_text(
    label: &'static str,
    value: &str,
    max_bytes: usize,
) -> Result<(), EvidenceError> {
    if value.is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(EvidenceError::Invalid(format!(
            "{label} must be non-empty, control-free, and at most {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn validate_digest(label: &'static str, value: &str) -> Result<(), EvidenceError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(EvidenceError::Invalid(format!("{label} must be a lowercase SHA-256 digest")));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelCallSchemaV1 {
    #[serde(rename = "alpha.model-call.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ModelReplaySchemaV1 {
    #[serde(rename = "alpha.model-replay.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerifiedDialogueTurnSchemaV1 {
    #[serde(rename = "alpha.verified-dialogue-turn.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum CollaborationApprovalSchemaV1 {
    #[serde(rename = "alpha.collaboration-approval.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum FinalRunSummarySchemaV1 {
    #[serde(rename = "alpha.model-collaboration-run.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceIndexSchemaV1 {
    #[serde(rename = "alpha.evidence-index.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EvidenceSealSchemaV1 {
    #[serde(rename = "alpha.evidence-seal.v1")]
    V1,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum SignedEvidenceSealSchemaV1 {
    #[serde(rename = "alpha.signed-evidence-seal.v1")]
    V1,
}

fn invalid_endpoint() -> EvidenceError {
    // Never echo the source URL: rejected URLs may contain credentials.
    EvidenceError::Invalid(
        "model endpoint must be an absolute HTTP(S) URL with a valid host".into(),
    )
}

fn parse_port(port: &str) -> Result<u16, EvidenceError> {
    if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_endpoint());
    }
    let port = port.parse::<u16>().map_err(|_| invalid_endpoint())?;
    if port == 0 {
        return Err(invalid_endpoint());
    }
    Ok(port)
}

fn normalize_dns_or_ipv4_host(host: &str) -> Result<String, EvidenceError> {
    if host.is_empty() || host.len() > 253 || !host.is_ascii() {
        return Err(invalid_endpoint());
    }
    if host.bytes().all(|byte| byte.is_ascii_digit() || byte == b'.') {
        return host
            .parse::<std::net::Ipv4Addr>()
            .map(|address| address.to_string())
            .map_err(|_| invalid_endpoint());
    }
    for label in host.split('.') {
        if label.is_empty()
            || label.len() > 63
            || !label.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || label.starts_with('-')
            || label.ends_with('-')
        {
            return Err(invalid_endpoint());
        }
    }
    Ok(host.to_ascii_lowercase())
}

/// Parse a base URL but retain only its normalized origin. The parser accepts HTTP(S), DNS/IPv4,
/// and bracketed IPv6. It deliberately rejects ambiguous URL forms instead of trying to repair
/// them; the source URL is never included in an error.
fn endpoint_origin(base_url: &str) -> Result<String, EvidenceError> {
    const MAX_BASE_URL_BYTES: usize = 8 * 1024;

    if base_url.is_empty()
        || base_url.len() > MAX_BASE_URL_BYTES
        || !base_url.is_ascii()
        || base_url.bytes().any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        || base_url.contains('\\')
    {
        return Err(invalid_endpoint());
    }
    let (scheme, remainder) = base_url.split_once("://").ok_or_else(invalid_endpoint)?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(invalid_endpoint());
    }
    let authority_end = remainder.find(['/', '?', '#']).unwrap_or(remainder.len());
    let authority = &remainder[..authority_end];
    if authority.is_empty() || authority.matches('@').count() > 1 {
        return Err(invalid_endpoint());
    }
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, host_port)| host_port);
    if host_port.is_empty() {
        return Err(invalid_endpoint());
    }

    let (host, port) = if let Some(bracketed) = host_port.strip_prefix('[') {
        let close = bracketed.find(']').ok_or_else(invalid_endpoint)?;
        let address = &bracketed[..close];
        let tail = &bracketed[close + 1..];
        let address =
            address.parse::<std::net::Ipv6Addr>().map_err(|_| invalid_endpoint())?.to_string();
        let port = if tail.is_empty() {
            None
        } else {
            Some(parse_port(tail.strip_prefix(':').ok_or_else(invalid_endpoint)?)?)
        };
        (format!("[{address}]"), port)
    } else {
        if host_port.contains(['[', ']']) || host_port.matches(':').count() > 1 {
            return Err(invalid_endpoint());
        }
        let (host, port) = match host_port.rsplit_once(':') {
            Some((host, port)) => (host, Some(parse_port(port)?)),
            None => (host_port, None),
        };
        (normalize_dns_or_ipv4_host(host)?, port)
    };
    let origin = match port {
        Some(port) => format!("{scheme}://{host}:{port}"),
        None => format!("{scheme}://{host}"),
    };
    if origin.len() > MAX_ENDPOINT_ORIGIN_BYTES {
        return Err(invalid_endpoint());
    }
    Ok(origin)
}

/// The only model configuration allowed into evidence. Credentials and the raw endpoint are
/// absent by construction. `endpoint_origin` contains only normalized scheme, host, and optional
/// port; user-info, path, query, and fragment are discarded by a strict parser.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SanitizedModelConfigV1 {
    pub provider: String,
    pub requested_model: String,
    pub endpoint_origin: Option<String>,
    pub timeout_ms: u64,
}

impl SanitizedModelConfigV1 {
    // Kept available in credential-free builds so evidence/config tests exercise the identical
    // sanitizer; the production call site is feature-gated with the HTTP adapter.
    #[allow(dead_code)]
    pub fn from_model_config(
        provider: impl Into<String>,
        config: &ModelConfig,
    ) -> Result<Self, EvidenceError> {
        let timeout_ms = u64::try_from(config.timeout.as_millis())
            .map_err(|_| EvidenceError::CapExceeded("model timeout milliseconds"))?;
        let sanitized = Self {
            provider: provider.into(),
            requested_model: config.model.clone(),
            endpoint_origin: Some(endpoint_origin(&config.base_url)?),
            timeout_ms,
        };
        sanitized.validate()?;
        Ok(sanitized)
    }

    pub fn fixture(
        provider: impl Into<String>,
        model: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let sanitized = Self {
            provider: provider.into(),
            requested_model: model.into(),
            endpoint_origin: None,
            timeout_ms: 0,
        };
        sanitized.validate()?;
        Ok(sanitized)
    }

    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_bounded_text("provider", &self.provider, MAX_PROVIDER_LABEL_BYTES)?;
        validate_bounded_text("requested model", &self.requested_model, MAX_MODEL_LABEL_BYTES)?;
        if let Some(origin) = &self.endpoint_origin {
            if endpoint_origin(origin)? != *origin {
                return Err(EvidenceError::Invalid(
                    "model endpoint origin is not in canonical form".into(),
                ));
            }
        }
        Ok(())
    }
}

/// Provider-reported receipt metadata retained without headers, URLs, or arbitrary response bodies.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProviderReceiptMetadataV1 {
    pub response_id: Option<String>,
    pub request_id: Option<String>,
    pub reported_model: Option<String>,
    pub finish_reason: Option<String>,
    pub store_requested: bool,
}

impl ProviderReceiptMetadataV1 {
    fn from_provider_receipt(receipt: &ProviderReceipt) -> Result<Self, EvidenceError> {
        let evidence = Self {
            response_id: receipt.response_id.clone(),
            request_id: receipt.request_id.clone(),
            reported_model: receipt.reported_model.clone(),
            finish_reason: receipt.finish_reason.clone(),
            store_requested: receipt.store_requested,
        };
        evidence.validate()?;
        Ok(evidence)
    }

    fn to_provider_receipt(&self) -> Result<ProviderReceipt, EvidenceError> {
        self.validate()?;
        Ok(ProviderReceipt {
            response_id: self.response_id.clone(),
            request_id: self.request_id.clone(),
            reported_model: self.reported_model.clone(),
            finish_reason: self.finish_reason.clone(),
            store_requested: self.store_requested,
        })
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        for (label, id) in [
            ("provider response id", self.response_id.as_deref()),
            ("provider request id", self.request_id.as_deref()),
            ("provider reported model", self.reported_model.as_deref()),
            ("provider finish reason", self.finish_reason.as_deref()),
        ] {
            if let Some(id) = id {
                validate_bounded_text(label, id, 1024)?;
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PromptFingerprintV1 {
    pub sha256: String,
    pub system_prompt_bytes: u64,
    pub user_prompt_bytes: u64,
    pub max_tokens: u32,
    pub temperature_bits: u32,
}

impl PromptFingerprintV1 {
    fn from_prompt(prompt: &Prompt) -> Result<Self, EvidenceError> {
        Ok(Self {
            sha256: prompt_sha256(prompt)?,
            system_prompt_bytes: prompt.system_prompt.len() as u64,
            user_prompt_bytes: prompt.user_prompt.len() as u64,
            max_tokens: prompt.max_tokens,
            temperature_bits: prompt.temperature.to_bits(),
        })
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        validate_digest("prompt sha256", &self.sha256)?;
        if self.system_prompt_bytes > MAX_PROMPT_PART_BYTES as u64
            || self.user_prompt_bytes > MAX_PROMPT_PART_BYTES as u64
        {
            return Err(EvidenceError::CapExceeded("recorded prompt bytes"));
        }
        if !f32::from_bits(self.temperature_bits).is_finite() {
            return Err(EvidenceError::Invalid("recorded temperature must be finite".into()));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ModelCallErrorClassV1 {
    Transport,
    Http,
    Decode,
    Config,
    EvidenceCap,
    Panic,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ModelCallOutcomeV1 {
    Completed {
        completion_sha256: String,
        completion_bytes: u64,
        responding_model: String,
        usage: Option<TokenUsage>,
        provider_receipt: Option<ProviderReceiptMetadataV1>,
    },
    Failed {
        class: ModelCallErrorClassV1,
        http_status: Option<u16>,
    },
}

fn bounded_unix_ms(reading: SystemTime) -> Option<u64> {
    let millis = reading.duration_since(UNIX_EPOCH).ok()?.as_millis();
    u64::try_from(millis).ok().filter(|millis| *millis <= MAX_UNIX_TIMESTAMP_MS)
}

fn bounded_duration_ms(duration: Duration) -> Option<u64> {
    let millis = u64::try_from(duration.as_millis()).ok()?;
    (millis <= MAX_MODEL_CALL_DURATION_MS).then_some(millis)
}

/// Bounded clock observations for one call. Unix readings are independent wall-clock samples and
/// may be absent outside the evidence domain. Duration comes from a monotonic clock and is not
/// inferred from wall time. A wall-clock regression is reported rather than repaired.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelCallTimingV1 {
    pub started_unix_ms: Option<u64>,
    pub finished_unix_ms: Option<u64>,
    pub monotonic_duration_ms: Option<u64>,
    pub wall_clock_regressed: bool,
}

impl ModelCallTimingV1 {
    fn from_observations(
        started: SystemTime,
        finished: SystemTime,
        monotonic_duration: Duration,
    ) -> Self {
        Self {
            started_unix_ms: bounded_unix_ms(started),
            finished_unix_ms: bounded_unix_ms(finished),
            monotonic_duration_ms: bounded_duration_ms(monotonic_duration),
            wall_clock_regressed: finished.duration_since(started).is_err(),
        }
    }

    fn validate(&self) -> Result<(), EvidenceError> {
        for reading in [self.started_unix_ms, self.finished_unix_ms].into_iter().flatten() {
            if reading > MAX_UNIX_TIMESTAMP_MS {
                return Err(EvidenceError::CapExceeded("model call Unix timestamp"));
            }
        }
        if self.monotonic_duration_ms.is_some_and(|duration| duration > MAX_MODEL_CALL_DURATION_MS)
        {
            return Err(EvidenceError::CapExceeded("model call monotonic duration"));
        }
        if let (Some(started), Some(finished)) = (self.started_unix_ms, self.finished_unix_ms) {
            if (finished < started && !self.wall_clock_regressed)
                || (finished > started && self.wall_clock_regressed)
            {
                return Err(EvidenceError::Invalid(
                    "model call wall-clock regression flag contradicts timestamps".into(),
                ));
            }
        }
        Ok(())
    }
}

struct CallClock {
    wall: SystemTime,
    monotonic: Instant,
}

impl CallClock {
    fn start() -> Self {
        Self { wall: SystemTime::now(), monotonic: Instant::now() }
    }

    fn finish(self) -> ModelCallTimingV1 {
        let monotonic_duration = self.monotonic.elapsed();
        let finished = SystemTime::now();
        ModelCallTimingV1::from_observations(self.wall, finished, monotonic_duration)
    }
}

/// A sanitized, bounded audit record.  Prompts and replies are represented by exact hashes and byte
/// counts; replay content is kept in the separately versioned [`ModelReplayEntryV1`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelCallRecordV1 {
    pub schema: ModelCallSchemaV1,
    pub global_ordinal: u64,
    pub role: String,
    pub role_ordinal: u64,
    pub config: SanitizedModelConfigV1,
    pub prompt: PromptFingerprintV1,
    pub timing: ModelCallTimingV1,
    pub outcome: ModelCallOutcomeV1,
}

impl ModelCallRecordV1 {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_bounded_text("model role", &self.role, MAX_ROLE_BYTES)?;
        self.config.validate()?;
        self.prompt.validate()?;
        self.timing.validate()?;
        if let ModelCallOutcomeV1::Completed {
            completion_sha256,
            completion_bytes,
            responding_model,
            provider_receipt,
            ..
        } = &self.outcome
        {
            validate_digest("completion sha256", completion_sha256)?;
            if *completion_bytes > MAX_COMPLETION_BYTES as u64 {
                return Err(EvidenceError::CapExceeded("recorded completion bytes"));
            }
            validate_bounded_text("responding model", responding_model, MAX_MODEL_LABEL_BYTES)?;
            if let Some(receipt) = provider_receipt {
                receipt.validate()?;
            }
        }
        Ok(())
    }
}

/// Exact prompt material retained for deterministic replay. Strings preserve their UTF-8 bytes;
/// `temperature_bits` preserves even floating-point representations that compare equal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayPromptV1 {
    pub system_prompt: String,
    pub user_prompt: String,
    pub max_tokens: u32,
    pub temperature_bits: u32,
    pub sha256: String,
}

impl ReplayPromptV1 {
    fn from_prompt(prompt: &Prompt) -> Result<Self, EvidenceError> {
        validate_prompt(prompt)?;
        Ok(Self {
            system_prompt: prompt.system_prompt.clone(),
            user_prompt: prompt.user_prompt.clone(),
            max_tokens: prompt.max_tokens,
            temperature_bits: prompt.temperature.to_bits(),
            sha256: prompt_sha256(prompt)?,
        })
    }

    fn to_prompt(&self) -> Result<Prompt, EvidenceError> {
        validate_digest("replay prompt sha256", &self.sha256)?;
        let prompt = Prompt {
            system_prompt: self.system_prompt.clone(),
            user_prompt: self.user_prompt.clone(),
            max_tokens: self.max_tokens,
            temperature: f32::from_bits(self.temperature_bits),
        };
        let actual = prompt_sha256(&prompt)?;
        if actual != self.sha256 {
            return Err(EvidenceError::Invalid(
                "replay prompt hash does not match retained prompt bytes and parameters".into(),
            ));
        }
        Ok(prompt)
    }

    fn retained_bytes(&self) -> usize {
        self.system_prompt.len().saturating_add(self.user_prompt.len())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReplayCompletionV1 {
    pub content: String,
    pub model: String,
    pub usage: Option<TokenUsage>,
    pub provider: Option<ProviderReceiptMetadataV1>,
    pub sha256: String,
}

impl ReplayCompletionV1 {
    fn from_completion(completion: &Completion) -> Result<Self, EvidenceError> {
        Ok(Self {
            content: completion.content.clone(),
            model: completion.model.clone(),
            usage: completion.usage.clone(),
            provider: completion
                .provider
                .as_ref()
                .map(ProviderReceiptMetadataV1::from_provider_receipt)
                .transpose()?,
            sha256: completion_sha256(completion)?,
        })
    }

    fn to_completion(&self) -> Result<Completion, EvidenceError> {
        let completion = Completion {
            content: self.content.clone(),
            model: self.model.clone(),
            usage: self.usage.clone(),
            provider: self
                .provider
                .as_ref()
                .map(ProviderReceiptMetadataV1::to_provider_receipt)
                .transpose()?,
        };
        let actual = completion_sha256(&completion)?;
        if actual != self.sha256 {
            return Err(EvidenceError::Invalid(
                "replay completion hash does not match content".into(),
            ));
        }
        Ok(completion)
    }
}

/// Raw completion content needed for hermetic replay.  It is separate from the public model-call
/// audit record so callers can retain or encrypt replay material under a different policy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ModelReplayEntryV1 {
    pub schema: ModelReplaySchemaV1,
    pub global_ordinal: u64,
    pub role: String,
    pub role_ordinal: u64,
    pub prompt: ReplayPromptV1,
    pub completion: ReplayCompletionV1,
}

impl ModelReplayEntryV1 {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_bounded_text("replay role", &self.role, MAX_ROLE_BYTES)?;
        self.prompt.to_prompt()?;
        self.completion.to_completion()?;
        Ok(())
    }

    fn retained_bytes(&self) -> usize {
        self.role
            .len()
            .saturating_add(self.prompt.retained_bytes())
            .saturating_add(self.completion.content.len())
            .saturating_add(self.completion.model.len())
    }
}

#[derive(Debug, Clone)]
struct CallReservation {
    global_ordinal: u64,
    role_ordinal: u64,
}

#[derive(Default)]
struct JournalState {
    next_global_ordinal: u64,
    next_role_ordinal: BTreeMap<String, u64>,
    reserved_calls: usize,
    in_flight: usize,
    replay_bytes: usize,
    calls: Vec<ModelCallRecordV1>,
    replays: Vec<ModelReplayEntryV1>,
}

/// Shared journal for all three role-specific recording wrappers.
#[derive(Default)]
pub struct ModelCallJournal {
    state: Mutex<JournalState>,
}

impl ModelCallJournal {
    pub fn new() -> Self {
        Self::default()
    }

    fn reserve(&self, role: &str) -> Result<CallReservation, EvidenceError> {
        validate_bounded_text("model role", role, MAX_ROLE_BYTES)?;
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if state.reserved_calls >= MAX_EVIDENCE_CALLS {
            return Err(EvidenceError::CapExceeded("recorded model calls"));
        }
        let global_ordinal = state.next_global_ordinal;
        state.next_global_ordinal = state
            .next_global_ordinal
            .checked_add(1)
            .ok_or(EvidenceError::CapExceeded("global model call ordinal"))?;
        let role_ordinal = *state.next_role_ordinal.get(role).unwrap_or(&0);
        state.next_role_ordinal.insert(
            role.to_string(),
            role_ordinal
                .checked_add(1)
                .ok_or(EvidenceError::CapExceeded("role model call ordinal"))?,
        );
        state.reserved_calls += 1;
        state.in_flight += 1;
        Ok(CallReservation { global_ordinal, role_ordinal })
    }

    fn finish_failure(&self, record: ModelCallRecordV1) {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        state.calls.push(record);
    }

    fn finish_success(
        &self,
        mut record: ModelCallRecordV1,
        replay: ModelReplayEntryV1,
    ) -> Result<(), EvidenceError> {
        let retained = replay.retained_bytes();
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        state.in_flight = state.in_flight.saturating_sub(1);
        if state.replay_bytes.saturating_add(retained) > MAX_REPLAY_BYTES {
            record.outcome = ModelCallOutcomeV1::Failed {
                class: ModelCallErrorClassV1::EvidenceCap,
                http_status: None,
            };
            state.calls.push(record);
            return Err(EvidenceError::CapExceeded("retained model replay bytes"));
        }
        state.replay_bytes += retained;
        state.calls.push(record);
        state.replays.push(replay);
        Ok(())
    }

    pub fn records(&self) -> Result<Vec<ModelCallRecordV1>, EvidenceError> {
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if state.in_flight != 0 {
            return Err(EvidenceError::InFlightCalls(state.in_flight));
        }
        let mut records = state.calls.clone();
        records.sort_by_key(|record| record.global_ordinal);
        for record in &records {
            record.validate()?;
        }
        Ok(records)
    }

    pub fn replay_entries(&self) -> Result<Vec<ModelReplayEntryV1>, EvidenceError> {
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if state.in_flight != 0 {
            return Err(EvidenceError::InFlightCalls(state.in_flight));
        }
        let mut entries = state.replays.clone();
        entries.sort_by_key(|entry| entry.global_ordinal);
        for entry in &entries {
            entry.validate()?;
        }
        Ok(entries)
    }
}

/// A `mind::Model` decorator that emits bounded evidence without changing model semantics.
pub struct RecordingModel {
    role: String,
    config: SanitizedModelConfigV1,
    inner: Arc<dyn Model>,
    journal: Arc<ModelCallJournal>,
}

impl RecordingModel {
    pub fn new(
        role: impl Into<String>,
        config: SanitizedModelConfigV1,
        inner: Arc<dyn Model>,
        journal: Arc<ModelCallJournal>,
    ) -> Result<Self, EvidenceError> {
        let role = role.into();
        validate_bounded_text("model role", &role, MAX_ROLE_BYTES)?;
        config.validate()?;
        Ok(Self { role, config, inner, journal })
    }

    fn base_record(
        &self,
        reservation: &CallReservation,
        prompt: &Prompt,
        timing: &ModelCallTimingV1,
        outcome: ModelCallOutcomeV1,
    ) -> Result<ModelCallRecordV1, EvidenceError> {
        Ok(ModelCallRecordV1 {
            schema: ModelCallSchemaV1::V1,
            global_ordinal: reservation.global_ordinal,
            role: self.role.clone(),
            role_ordinal: reservation.role_ordinal,
            config: self.config.clone(),
            prompt: PromptFingerprintV1::from_prompt(prompt)?,
            timing: timing.clone(),
            outcome,
        })
    }
}

impl Model for RecordingModel {
    fn complete(&self, request: Prompt) -> Result<Completion, ModelError> {
        validate_prompt(&request).map_err(evidence_model_error)?;
        let reservation = self.journal.reserve(&self.role).map_err(evidence_model_error)?;
        let clock = CallClock::start();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.inner.complete(request.clone())
        }));
        let timing = clock.finish();

        match result {
            Ok(Ok(completion)) => {
                if let Err(error) = validate_completion(&completion) {
                    let record = self
                        .base_record(
                            &reservation,
                            &request,
                            &timing,
                            ModelCallOutcomeV1::Failed {
                                class: ModelCallErrorClassV1::EvidenceCap,
                                http_status: None,
                            },
                        )
                        .map_err(evidence_model_error)?;
                    self.journal.finish_failure(record);
                    return Err(evidence_model_error(error));
                }
                let provider_receipt = completion
                    .provider
                    .as_ref()
                    .map(ProviderReceiptMetadataV1::from_provider_receipt)
                    .transpose()
                    .map_err(evidence_model_error)?;
                if let Some(receipt) = &provider_receipt {
                    if let Err(error) = receipt.validate() {
                        let record = self
                            .base_record(
                                &reservation,
                                &request,
                                &timing,
                                ModelCallOutcomeV1::Failed {
                                    class: ModelCallErrorClassV1::EvidenceCap,
                                    http_status: None,
                                },
                            )
                            .map_err(evidence_model_error)?;
                        self.journal.finish_failure(record);
                        return Err(evidence_model_error(error));
                    }
                }
                let completion_hash =
                    completion_sha256(&completion).map_err(evidence_model_error)?;
                let record = self
                    .base_record(
                        &reservation,
                        &request,
                        &timing,
                        ModelCallOutcomeV1::Completed {
                            completion_sha256: completion_hash,
                            completion_bytes: completion.content.len() as u64,
                            responding_model: completion.model.clone(),
                            usage: completion.usage.clone(),
                            provider_receipt,
                        },
                    )
                    .map_err(evidence_model_error)?;
                let replay = ModelReplayEntryV1 {
                    schema: ModelReplaySchemaV1::V1,
                    global_ordinal: reservation.global_ordinal,
                    role: self.role.clone(),
                    role_ordinal: reservation.role_ordinal,
                    prompt: ReplayPromptV1::from_prompt(&request).map_err(evidence_model_error)?,
                    completion: ReplayCompletionV1::from_completion(&completion)
                        .map_err(evidence_model_error)?,
                };
                self.journal.finish_success(record, replay).map_err(evidence_model_error)?;
                Ok(completion)
            }
            Ok(Err(error)) => {
                let (class, http_status) = model_error_metadata(&error);
                let record = self
                    .base_record(
                        &reservation,
                        &request,
                        &timing,
                        ModelCallOutcomeV1::Failed { class, http_status },
                    )
                    .map_err(evidence_model_error)?;
                self.journal.finish_failure(record);
                Err(error)
            }
            Err(payload) => {
                if let Ok(record) = self.base_record(
                    &reservation,
                    &request,
                    &timing,
                    ModelCallOutcomeV1::Failed {
                        class: ModelCallErrorClassV1::Panic,
                        http_status: None,
                    },
                ) {
                    self.journal.finish_failure(record);
                }
                std::panic::resume_unwind(payload)
            }
        }
    }

    fn describe(&self) -> String {
        self.inner.describe()
    }
}

fn evidence_model_error(error: EvidenceError) -> ModelError {
    ModelError::Config(format!("evidence recording rejected the call: {error}"))
}

fn model_error_metadata(error: &ModelError) -> (ModelCallErrorClassV1, Option<u16>) {
    match error {
        ModelError::Transport(_) => (ModelCallErrorClassV1::Transport, None),
        ModelError::Http { status, .. } => (ModelCallErrorClassV1::Http, Some(*status)),
        ModelError::Decode(_) => (ModelCallErrorClassV1::Decode, None),
        ModelError::Config(_) => (ModelCallErrorClassV1::Config, None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ReplayKey {
    role: String,
    role_ordinal: u64,
    prompt_sha256: String,
}

struct RecordedTurn {
    prompt: ReplayPromptV1,
    completion: ReplayCompletionV1,
}

/// A one-shot, fail-closed replay model.  Any role, ordinal, prompt, or ordering drift is rejected.
pub struct RecordedModel {
    role: String,
    next_ordinal: AtomicU64,
    entries: Mutex<BTreeMap<ReplayKey, RecordedTurn>>,
}

impl RecordedModel {
    pub fn new(
        role: impl Into<String>,
        entries: impl IntoIterator<Item = ModelReplayEntryV1>,
    ) -> Result<Self, EvidenceError> {
        let role = role.into();
        validate_bounded_text("replay role", &role, MAX_ROLE_BYTES)?;
        let mut keyed = BTreeMap::new();
        for entry in entries {
            entry.validate()?;
            if entry.role != role {
                return Err(EvidenceError::Invalid(format!(
                    "replay entry role {:?} does not match model role {:?}",
                    entry.role, role
                )));
            }
            let key = ReplayKey {
                role: entry.role,
                role_ordinal: entry.role_ordinal,
                prompt_sha256: entry.prompt.sha256.clone(),
            };
            let turn = RecordedTurn { prompt: entry.prompt, completion: entry.completion };
            if keyed.insert(key, turn).is_some() {
                return Err(EvidenceError::Invalid("duplicate replay key".into()));
            }
        }
        if keyed.len() > MAX_EVIDENCE_CALLS {
            return Err(EvidenceError::CapExceeded("replay entries"));
        }
        Ok(Self { role, next_ordinal: AtomicU64::new(0), entries: Mutex::new(keyed) })
    }

    pub fn assert_exhausted(&self) -> Result<(), EvidenceError> {
        let remaining = self.entries.lock().unwrap_or_else(|poison| poison.into_inner()).len();
        if remaining == 0 {
            Ok(())
        } else {
            Err(EvidenceError::UnusedReplay(remaining))
        }
    }
}

impl Model for RecordedModel {
    fn complete(&self, request: Prompt) -> Result<Completion, ModelError> {
        let prompt_sha256 = prompt_sha256(&request).map_err(evidence_model_error)?;
        let role_ordinal = self.next_ordinal.fetch_add(1, Ordering::SeqCst);
        let key = ReplayKey {
            role: self.role.clone(),
            role_ordinal,
            prompt_sha256: prompt_sha256.clone(),
        };
        let turn = self
            .entries
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .remove(&key)
            .ok_or_else(|| {
                evidence_model_error(EvidenceError::MissingReplay {
                    role: self.role.clone(),
                    ordinal: role_ordinal,
                    prompt_sha256,
                })
            })?;
        let retained_prompt = turn.prompt.to_prompt().map_err(evidence_model_error)?;
        if retained_prompt.system_prompt.as_bytes() != request.system_prompt.as_bytes()
            || retained_prompt.user_prompt.as_bytes() != request.user_prompt.as_bytes()
            || retained_prompt.max_tokens != request.max_tokens
            || retained_prompt.temperature.to_bits() != request.temperature.to_bits()
        {
            return Err(evidence_model_error(EvidenceError::Invalid(
                "replay request does not exactly match retained prompt bytes and parameters".into(),
            )));
        }
        turn.completion.to_completion().map_err(evidence_model_error)
    }

    fn describe(&self) -> String {
        format!("recorded:{}", self.role)
    }
}

// ---- Collaboration and run records ----------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VerifiedSignedDialogueTurnV1 {
    pub schema: VerifiedDialogueTurnSchemaV1,
    pub turn_ordinal: u64,
    pub role: String,
    pub correlation_id: u64,
    pub prompt_sha256: String,
    pub reply_sha256: String,
    pub signed_answer_body_utf8: String,
    pub signed_answer_body_sha256: String,
    pub pinned_signer_public_key: String,
    pub causal_predecessor_turn_sha256: Vec<String>,
}

impl VerifiedSignedDialogueTurnV1 {
    /// Construct a record only after the dialogue initiator has verified the signed answer against
    /// `pinned_signer_public_key` and the exact prompt represented by `prompt_sha256`.
    #[allow(clippy::too_many_arguments)]
    pub fn from_verified_answer(
        turn_ordinal: u64,
        role: impl Into<String>,
        correlation_id: u64,
        prompt_sha256: impl Into<String>,
        reply_sha256: impl Into<String>,
        signed_answer_body_utf8: impl Into<String>,
        pinned_signer_public_key: impl Into<String>,
        causal_predecessor_turn_sha256: Vec<String>,
    ) -> Result<Self, EvidenceError> {
        let signed_answer_body_utf8 = signed_answer_body_utf8.into();
        let record = Self {
            schema: VerifiedDialogueTurnSchemaV1::V1,
            turn_ordinal,
            role: role.into(),
            correlation_id,
            prompt_sha256: prompt_sha256.into(),
            reply_sha256: reply_sha256.into(),
            signed_answer_body_sha256: sha256(signed_answer_body_utf8.as_bytes()),
            signed_answer_body_utf8,
            pinned_signer_public_key: pinned_signer_public_key.into(),
            causal_predecessor_turn_sha256,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_bounded_text("dialogue role", &self.role, MAX_ROLE_BYTES)?;
        validate_digest("dialogue prompt sha256", &self.prompt_sha256)?;
        validate_digest("dialogue reply sha256", &self.reply_sha256)?;
        validate_digest("signed answer sha256", &self.signed_answer_body_sha256)?;
        if self.signed_answer_body_utf8.len() > MAX_SIGNED_TURN_BYTES {
            return Err(EvidenceError::CapExceeded("signed dialogue turn bytes"));
        }
        if sha256(self.signed_answer_body_utf8.as_bytes()) != self.signed_answer_body_sha256 {
            return Err(EvidenceError::Invalid(
                "signed answer body hash does not match bytes".into(),
            ));
        }
        validate_bounded_text("pinned signer public key", &self.pinned_signer_public_key, 1024)?;
        if self.causal_predecessor_turn_sha256.len() > 16 {
            return Err(EvidenceError::CapExceeded("dialogue causal predecessors"));
        }
        for digest in &self.causal_predecessor_turn_sha256 {
            validate_digest("causal predecessor sha256", digest)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovalContributorV1 {
    pub role: String,
    pub signer_public_key: String,
    pub signed_turn_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CollaborationApprovalSummaryV1 {
    pub schema: CollaborationApprovalSchemaV1,
    pub challenge_sha256: String,
    pub approved_profile_schema: String,
    pub approved_profile_sha256: String,
    pub semantic_sha256: String,
    pub approval_payload_sha256: String,
    pub contributors: Vec<ApprovalContributorV1>,
    pub final_builder_turn_sha256: String,
}

impl CollaborationApprovalSummaryV1 {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        for (label, digest) in [
            ("challenge sha256", self.challenge_sha256.as_str()),
            ("approved profile sha256", self.approved_profile_sha256.as_str()),
            ("semantic sha256", self.semantic_sha256.as_str()),
            ("approval payload sha256", self.approval_payload_sha256.as_str()),
            ("final builder turn sha256", self.final_builder_turn_sha256.as_str()),
        ] {
            validate_digest(label, digest)?;
        }
        validate_bounded_text("approved profile schema", &self.approved_profile_schema, 128)?;
        if self.contributors.len() != 3 {
            return Err(EvidenceError::Invalid(
                "approval must contain exactly builder, reviewer, and contract-tester contributors"
                    .into(),
            ));
        }
        let mut roles = BTreeSet::new();
        let mut signers = BTreeSet::new();
        for contributor in &self.contributors {
            validate_bounded_text("approval contributor role", &contributor.role, MAX_ROLE_BYTES)?;
            validate_bounded_text(
                "approval contributor signer",
                &contributor.signer_public_key,
                1024,
            )?;
            validate_digest("approval contributor turn sha256", &contributor.signed_turn_sha256)?;
            if !roles.insert(&contributor.role) || !signers.insert(&contributor.signer_public_key) {
                return Err(EvidenceError::Invalid(
                    "approval contributor roles and signer keys must be distinct".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EngineTierV1 {
    Daemon,
    Beast,
    Critter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentityV1 {
    pub git_commit: String,
    pub worktree_clean: bool,
    /// Candidate commit embedded when this binary was compiled. Live release evidence requires
    /// `ALPHA_DIALOGUE_BUILD_COMMIT` at build time and exact equality with `git_commit`; the field
    /// remains optional so ordinary fixture/test builds do not pretend to carry provenance.
    pub binary_build_commit: Option<String>,
    pub binary_sha256: String,
    pub toolchain: String,
}

impl SourceIdentityV1 {
    /// Derive the exact source/runtime identity used for a retained live proof.
    ///
    /// `repo_root` must be the absolute, canonical top level of a Git worktree. The worktree must
    /// have no tracked, staged, untracked, or submodule changes, and `HEAD` must resolve to the
    /// same exact commit before and after the cleanliness observation. The executable is hashed in
    /// a streaming pass, so deriving this identity does not buffer the binary in memory.
    pub fn derive_clean(repo_root: impl AsRef<Path>) -> Result<Self, EvidenceError> {
        let repo_root = repo_root.as_ref();
        ensure_existing_directory_no_symlink(repo_root, None)?;

        let prefix =
            git_stdout(repo_root, &["rev-parse", "--show-prefix"], MAX_SOURCE_TOOL_OUTPUT_BYTES)?;
        if !trim_ascii_whitespace(&prefix).is_empty() {
            return Err(EvidenceError::Invalid(
                "source identity requires the exact Git worktree root".into(),
            ));
        }

        let commit_before = exact_git_commit(repo_root)?;
        let status = git_stdout(
            repo_root,
            &["status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"],
            MAX_SOURCE_TOOL_OUTPUT_BYTES,
        )?;
        if !status.is_empty() {
            return Err(EvidenceError::Invalid(
                "source identity requires a clean Git worktree".into(),
            ));
        }
        let commit_after = exact_git_commit(repo_root)?;
        if commit_before != commit_after {
            return Err(EvidenceError::Invalid(
                "Git HEAD changed while source identity was derived".into(),
            ));
        }

        let binary_path = std::env::current_exe().map_err(|error| {
            io_error("resolve the current executable for source identity", Path::new("."), error)
        })?;
        let binary_sha256 = streaming_regular_file_sha256(&binary_path)?;
        let toolchain = rustc_identity()?;
        let final_status = git_stdout(
            repo_root,
            &["status", "--porcelain=v1", "--untracked-files=normal", "--ignore-submodules=none"],
            MAX_SOURCE_TOOL_OUTPUT_BYTES,
        )?;
        if !final_status.is_empty() || exact_git_commit(repo_root)? != commit_before {
            return Err(EvidenceError::Invalid(
                "Git source changed while source identity was derived".into(),
            ));
        }
        let binary_build_commit = option_env!("ALPHA_DIALOGUE_BUILD_COMMIT").map(str::to_string);
        let identity = Self {
            git_commit: commit_before,
            worktree_clean: true,
            binary_build_commit,
            binary_sha256,
            toolchain,
        };
        identity.validate()?;
        Ok(identity)
    }

    /// Require the binary's compile-time candidate binding to equal the clean runtime checkout.
    /// This catches stale/local binaries. An external build-provenance attestation over the binary
    /// hash is still required to make that compile-time claim independently trustworthy.
    pub fn require_matching_build_commit(&self) -> Result<(), EvidenceError> {
        let embedded = self.binary_build_commit.as_deref().ok_or_else(|| {
            EvidenceError::Invalid(
                "live evidence binary was not built with ALPHA_DIALOGUE_BUILD_COMMIT".into(),
            )
        })?;
        if embedded != self.git_commit {
            return Err(EvidenceError::Invalid(
                "live evidence binary build commit differs from the clean runtime checkout".into(),
            ));
        }
        Ok(())
    }

    pub fn validate(&self) -> Result<(), EvidenceError> {
        if (self.git_commit.len() != 40 && self.git_commit.len() != 64)
            || !self
                .git_commit
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(EvidenceError::Invalid(
                "git commit must be an exact lowercase Git object id".into(),
            ));
        }
        if !self.worktree_clean {
            return Err(EvidenceError::Invalid(
                "retained source identity must describe a clean worktree".into(),
            ));
        }
        if let Some(commit) = &self.binary_build_commit {
            if (commit.len() != 40 && commit.len() != 64)
                || !commit
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            {
                return Err(EvidenceError::Invalid(
                    "binary build commit must be an exact lowercase Git object id".into(),
                ));
            }
        }
        validate_digest("binary sha256", &self.binary_sha256)?;
        validate_bounded_text("toolchain", &self.toolchain, 512)
    }
}

fn exact_git_commit(repo_root: &Path) -> Result<String, EvidenceError> {
    let output = git_stdout(
        repo_root,
        &["rev-parse", "--verify", "HEAD^{commit}"],
        MAX_SOURCE_TOOL_OUTPUT_BYTES,
    )?;
    let commit = std::str::from_utf8(trim_ascii_whitespace(&output))
        .map_err(|_| EvidenceError::Invalid("Git returned a non-UTF-8 commit id".into()))?
        .to_string();
    if (commit.len() != 40 && commit.len() != 64)
        || !commit.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(EvidenceError::Invalid(
            "Git did not resolve HEAD to an exact lowercase commit id".into(),
        ));
    }
    Ok(commit)
}

fn git_stdout(repo_root: &Path, args: &[&str], cap: usize) -> Result<Vec<u8>, EvidenceError> {
    let mut command = Command::new("git");
    command.arg("-C").arg(repo_root).args(args);
    bounded_command_stdout(&mut command, "run Git for source identity", cap)
}

fn rustc_identity() -> Result<String, EvidenceError> {
    let mut command = Command::new("rustc");
    command.arg("-vV");
    let output = bounded_command_stdout(
        &mut command,
        "run rustc for source identity",
        MAX_SOURCE_TOOL_OUTPUT_BYTES,
    )?;
    let output = std::str::from_utf8(&output)
        .map_err(|_| EvidenceError::Invalid("rustc returned non-UTF-8 identity output".into()))?;
    let identity = output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("; ");
    validate_bounded_text("toolchain", &identity, 512)?;
    Ok(identity)
}

fn bounded_command_stdout(
    command: &mut Command,
    operation: &'static str,
    cap: usize,
) -> Result<Vec<u8>, EvidenceError> {
    command.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child = command.spawn().map_err(|error| io_error(operation, Path::new("."), error))?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        EvidenceError::Invalid("source identity command did not expose stdout".into())
    })?;
    let mut bytes = Vec::with_capacity(cap.min(4 * 1024));
    let read_result = (&mut stdout).take((cap as u64).saturating_add(1)).read_to_end(&mut bytes);
    drop(stdout);
    if let Err(error) = read_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(io_error(operation, Path::new("."), error));
    }
    if bytes.len() > cap {
        let _ = child.kill();
        let _ = child.wait();
        return Err(EvidenceError::CapExceeded("source identity command output"));
    }
    let status = child
        .wait()
        .map_err(|error| io_error("wait for source identity command", Path::new("."), error))?;
    if !status.success() {
        return Err(EvidenceError::Invalid(format!(
            "source identity command failed with status {status}"
        )));
    }
    Ok(bytes)
}

fn trim_ascii_whitespace(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[1..];
    }
    while bytes.last().is_some_and(u8::is_ascii_whitespace) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

fn streaming_regular_file_sha256(path: &Path) -> Result<String, EvidenceError> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| io_error("canonicalize source executable", path, error))?;
    let before = ensure_regular_file_no_symlink(&canonical, None)?;
    let mut file = File::open(&canonical)
        .map_err(|error| io_error("open source executable", &canonical, error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error("stat opened source executable", &canonical, error))?;
    if !same_file(&before, &opened) {
        return Err(EvidenceError::SymlinkRefused(canonical));
    }

    let mut hasher = Sha256::new();
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|error| io_error("hash source executable", &canonical, error))?;
        if read == 0 {
            break;
        }
        hasher.update(&chunk[..read]);
    }
    let after_open = file
        .metadata()
        .map_err(|error| io_error("re-stat opened source executable", &canonical, error))?;
    let after_path = fs::symlink_metadata(&canonical)
        .map_err(|error| io_error("re-stat source executable path", &canonical, error))?;
    if !same_file(&opened, &after_open)
        || !same_file(&opened, &after_path)
        || opened.len() != after_open.len()
        || opened.modified().ok() != after_open.modified().ok()
    {
        return Err(EvidenceError::Invalid("source executable changed while it was hashed".into()));
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TopologySummaryV1 {
    pub authoring_realm: String,
    pub authoring_node: String,
    pub execution_realm: String,
    pub execution_node: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EngineRunSummaryV1 {
    pub tier: EngineTierV1,
    pub source_sha256: String,
    pub manifest_sha256: String,
    pub artifact_sha256: String,
    pub entry_proof_sha256: String,
    pub function_id: String,
    pub local_job_receipt_sha256: String,
    pub cross_realm_job_receipt_sha256: String,
    pub local_result_sha256: String,
    pub cross_realm_result_sha256: String,
}

impl EngineRunSummaryV1 {
    fn validate(&self) -> Result<(), EvidenceError> {
        for (label, digest) in [
            ("source sha256", self.source_sha256.as_str()),
            ("manifest sha256", self.manifest_sha256.as_str()),
            ("artifact sha256", self.artifact_sha256.as_str()),
            ("entry proof sha256", self.entry_proof_sha256.as_str()),
            ("local job receipt sha256", self.local_job_receipt_sha256.as_str()),
            ("cross-realm job receipt sha256", self.cross_realm_job_receipt_sha256.as_str()),
            ("local result sha256", self.local_result_sha256.as_str()),
            ("cross-realm result sha256", self.cross_realm_result_sha256.as_str()),
        ] {
            validate_digest(label, digest)?;
        }
        validate_bounded_text("function id", &self.function_id, 1024)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceReferenceV1 {
    pub file: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FinalRunSummaryV1 {
    pub schema: FinalRunSummarySchemaV1,
    pub run_id: String,
    pub challenge_sha256: String,
    pub approval_summary_sha256: String,
    pub source: SourceIdentityV1,
    pub topology: TopologySummaryV1,
    pub model_calls: EvidenceReferenceV1,
    pub replay_entries: EvidenceReferenceV1,
    pub signed_dialogue_turns: EvidenceReferenceV1,
    pub engine_runs: Vec<EngineRunSummaryV1>,
}

impl FinalRunSummaryV1 {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        validate_bounded_text("run id", &self.run_id, 256)?;
        validate_digest("run challenge sha256", &self.challenge_sha256)?;
        validate_digest("run approval sha256", &self.approval_summary_sha256)?;
        self.source.validate()?;
        for value in [
            &self.topology.authoring_realm,
            &self.topology.authoring_node,
            &self.topology.execution_realm,
            &self.topology.execution_node,
        ] {
            validate_bounded_text("topology id", value, 256)?;
        }
        for reference in [&self.model_calls, &self.replay_entries, &self.signed_dialogue_turns] {
            validate_file_name(&reference.file)?;
            validate_digest("evidence reference sha256", &reference.sha256)?;
        }
        if self.engine_runs.len() != 3 {
            return Err(EvidenceError::Invalid(
                "final run must contain exactly daemon, beast, and critter summaries".into(),
            ));
        }
        let tiers: BTreeSet<_> = self.engine_runs.iter().map(|run| run.tier).collect();
        if tiers
            != BTreeSet::from([EngineTierV1::Daemon, EngineTierV1::Beast, EngineTierV1::Critter])
        {
            return Err(EvidenceError::Invalid(
                "final run must contain one summary for each engine tier".into(),
            ));
        }
        for run in &self.engine_runs {
            run.validate()?;
        }
        Ok(())
    }
}

// ---- Secure persistent directory ------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceFileRecordV1 {
    pub file: String,
    pub bytes: u64,
    pub sha256: String,
}

impl EvidenceFileRecordV1 {
    fn validate(&self) -> Result<(), EvidenceError> {
        validate_file_name(&self.file)?;
        validate_digest("evidence file sha256", &self.sha256)?;
        if self.bytes > MAX_EVIDENCE_FILE_BYTES as u64 {
            return Err(EvidenceError::CapExceeded("evidence file bytes"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceIndexV1 {
    pub schema: EvidenceIndexSchemaV1,
    pub files: Vec<EvidenceFileRecordV1>,
}

impl EvidenceIndexV1 {
    fn validate(&self) -> Result<(), EvidenceError> {
        if self.files.len() > MAX_EVIDENCE_FILES {
            return Err(EvidenceError::CapExceeded("evidence file count"));
        }
        let mut names = BTreeSet::new();
        let mut total = 0_u64;
        for file in &self.files {
            file.validate()?;
            if file.file == EVIDENCE_INDEX_FILE || !names.insert(&file.file) {
                return Err(EvidenceError::Invalid(
                    "duplicate or recursive evidence index entry".into(),
                ));
            }
            total = total
                .checked_add(file.bytes)
                .ok_or(EvidenceError::CapExceeded("total evidence bytes"))?;
        }
        if total > MAX_EVIDENCE_TOTAL_BYTES {
            return Err(EvidenceError::CapExceeded("total evidence bytes"));
        }
        Ok(())
    }
}

/// The index hash is the evidence bundle root.  Keep it outside the directory (for example in an
/// operator attestation); the index cannot recursively contain its own hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSealV1 {
    pub schema: EvidenceSealSchemaV1,
    pub index_file: String,
    pub index_sha256: String,
    pub index_bytes: u64,
    pub payload_files: u64,
}

impl EvidenceSealV1 {
    pub fn validate(&self) -> Result<(), EvidenceError> {
        if self.index_file != EVIDENCE_INDEX_FILE {
            return Err(EvidenceError::Invalid("unexpected evidence index filename".into()));
        }
        validate_digest("evidence index sha256", &self.index_sha256)?;
        if self.index_bytes > MAX_EVIDENCE_FILE_BYTES as u64 {
            return Err(EvidenceError::CapExceeded("evidence index bytes"));
        }
        if self.payload_files > MAX_EVIDENCE_FILES as u64 {
            return Err(EvidenceError::CapExceeded("evidence payload file count"));
        }
        Ok(())
    }
}

/// An external, signer-bound attestation over one immutable evidence bundle root.
///
/// This wrapper deliberately lives outside the indexed evidence directory: putting a signature
/// over the index inside that index would create a recursive hash. The signing payload covers the
/// wrapper schema, the complete [`EvidenceSealV1`], and the public key, in that field order. It
/// never contains or serializes private key material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedEvidenceSealV1 {
    pub schema: SignedEvidenceSealSchemaV1,
    pub seal: EvidenceSealV1,
    pub signer_public_key: String,
    pub signature: String,
}

#[derive(Serialize)]
struct EvidenceSealSigningPayloadV1<'a> {
    schema: SignedEvidenceSealSchemaV1,
    seal: &'a EvidenceSealV1,
    signer_public_key: &'a str,
}

impl SignedEvidenceSealV1 {
    /// Sign with the substrate's injected signing mechanism. Production evidence should supply an
    /// `aether::Ed25519Signer`; the abstraction remains mechanism-only like the rest of Alpha.
    #[allow(dead_code)]
    pub fn sign_with_aether(
        seal: EvidenceSealV1,
        signer: &dyn Signer,
    ) -> Result<Self, EvidenceError> {
        Self::sign_with(seal, signer.public_key(), |payload| signer.sign(payload))
    }

    /// Sign directly with shared GAWD Ed25519 key material. Only the public half enters the record.
    pub fn sign_with_ed25519(
        seal: EvidenceSealV1,
        key: &Ed25519KeyMaterial,
    ) -> Result<Self, EvidenceError> {
        Self::sign_with(seal, key.public_hex().to_string(), |payload| key.sign(payload))
    }

    fn sign_with(
        seal: EvidenceSealV1,
        signer_public_key: String,
        sign: impl FnOnce(&[u8]) -> String,
    ) -> Result<Self, EvidenceError> {
        let mut record = Self {
            schema: SignedEvidenceSealSchemaV1::V1,
            seal,
            signer_public_key,
            signature: String::new(),
        };
        record.validate_unsigned()?;
        record.signature = sign(&record.signing_payload()?);
        record.validate()?;
        Ok(record)
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, EvidenceError> {
        self.validate_unsigned()?;
        serde_json::to_vec(&EvidenceSealSigningPayloadV1 {
            schema: self.schema,
            seal: &self.seal,
            signer_public_key: &self.signer_public_key,
        })
        .map_err(EvidenceError::Json)
    }

    fn validate_unsigned(&self) -> Result<(), EvidenceError> {
        self.seal.validate()?;
        validate_bounded_text(
            "evidence seal signer public key",
            &self.signer_public_key,
            MAX_EVIDENCE_SIGNER_BYTES,
        )
    }

    pub fn validate(&self) -> Result<(), EvidenceError> {
        self.validate_unsigned()?;
        validate_bounded_text(
            "evidence seal signature",
            &self.signature,
            MAX_EVIDENCE_SIGNATURE_BYTES,
        )
    }

    /// Cryptographically verify the record with an injected root-blind verifier. Deciding whether
    /// `signer_public_key` is trusted remains operator policy, outside this evidence mechanism.
    pub fn verify_signature(&self, verifier: &dyn Verifier) -> Result<(), EvidenceError> {
        self.validate()?;
        if !verifier.verify(&self.signer_public_key, &self.signing_payload()?, &self.signature) {
            return Err(EvidenceError::Invalid(
                "external evidence seal signature did not verify".into(),
            ));
        }
        Ok(())
    }
}

/// Read an externally retained signed seal from one exact, private path.
///
/// The seal lives outside its evidence directory, so [`EvidenceDirectory::verify`] cannot protect
/// this first read. Require an absolute canonical path, a regular non-symlink file, and mode `0600`
/// before decoding it. The caller still owns trust policy: compare `signer_public_key` with its
/// pinned key *before* calling [`SignedEvidenceSealV1::verify_signature`].
pub fn read_secure_signed_evidence_seal(
    path: impl AsRef<Path>,
) -> Result<SignedEvidenceSealV1, EvidenceError> {
    const MAX_SIGNED_SEAL_BYTES: usize = 64 * 1024;

    let bytes = read_external_regular_file(path.as_ref(), MAX_SIGNED_SEAL_BYTES, Some(0o600))?;
    let signed: SignedEvidenceSealV1 = serde_json::from_slice(&bytes)?;
    signed.validate()?;
    Ok(signed)
}

/// Hash the bytes at one exact packaged-binary path without following symlinks or accepting a file
/// that changes while it is read. The returned digest is bare lowercase SHA-256, matching evidence
/// index and [`SourceIdentityV1::binary_sha256`] fields.
pub fn secure_external_file_sha256(path: impl AsRef<Path>) -> Result<String, EvidenceError> {
    let path = path.as_ref();
    validate_exact_external_file_path(path)?;
    streaming_stable_file_sha256(path)
}

#[derive(Default)]
struct DirectoryState {
    files: BTreeMap<String, EvidenceFileRecordV1>,
    sealed: bool,
}

/// A newly-created evidence directory.  It never opens an existing path for writing.
pub struct EvidenceDirectory {
    path: PathBuf,
    state: Mutex<DirectoryState>,
}

impl EvidenceDirectory {
    pub fn create(path: impl AsRef<Path>) -> Result<Self, EvidenceError> {
        let path = path.as_ref();
        validate_new_directory_path(path)?;
        let parent = path.parent().ok_or_else(|| EvidenceError::UnsafePath(path.to_path_buf()))?;
        ensure_existing_directory_no_symlink(parent, None)?;

        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(EvidenceError::ReuseRefused(path.to_path_buf()))
            }
            Err(error) => return Err(io_error("create evidence directory", path, error)),
        }
        #[cfg(unix)]
        fs::set_permissions(path, unix_permissions(0o700))
            .map_err(|error| io_error("set evidence directory permissions", path, error))?;
        ensure_existing_directory_no_symlink(path, Some(0o700))?;
        Ok(Self { path: path.to_path_buf(), state: Mutex::new(DirectoryState::default()) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_json<T: Serialize>(
        &self,
        file: &str,
        value: &T,
    ) -> Result<EvidenceFileRecordV1, EvidenceError> {
        let mut bytes = serde_json::to_vec_pretty(value)?;
        bytes.push(b'\n');
        self.write_bytes(file, &bytes)
    }

    pub fn write_bytes(
        &self,
        file: &str,
        bytes: &[u8],
    ) -> Result<EvidenceFileRecordV1, EvidenceError> {
        validate_file_name(file)?;
        if file == EVIDENCE_INDEX_FILE {
            return Err(EvidenceError::Invalid("index filename is reserved".into()));
        }
        if bytes.len() > MAX_EVIDENCE_FILE_BYTES {
            return Err(EvidenceError::CapExceeded("evidence file bytes"));
        }
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if state.sealed || state.files.contains_key(file) {
            return Err(EvidenceError::ReuseRefused(self.path.join(file)));
        }
        if state.files.len() >= MAX_EVIDENCE_FILES {
            return Err(EvidenceError::CapExceeded("evidence file count"));
        }
        let current_total: u64 = state.files.values().map(|record| record.bytes).sum();
        if current_total.saturating_add(bytes.len() as u64) > MAX_EVIDENCE_TOTAL_BYTES {
            return Err(EvidenceError::CapExceeded("total evidence bytes"));
        }
        let record = atomic_publish_file(&self.path, file, bytes)?;
        state.files.insert(file.to_string(), record.clone());
        Ok(record)
    }

    pub fn seal(&self) -> Result<EvidenceSealV1, EvidenceError> {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        if state.sealed {
            return Err(EvidenceError::ReuseRefused(self.path.join(EVIDENCE_INDEX_FILE)));
        }
        let index = EvidenceIndexV1 {
            schema: EvidenceIndexSchemaV1::V1,
            files: state.files.values().cloned().collect(),
        };
        index.validate()?;
        let mut bytes = serde_json::to_vec_pretty(&index)?;
        bytes.push(b'\n');
        let record = atomic_publish_file(&self.path, EVIDENCE_INDEX_FILE, &bytes)?;
        state.sealed = true;
        let seal = EvidenceSealV1 {
            schema: EvidenceSealSchemaV1::V1,
            index_file: EVIDENCE_INDEX_FILE.to_string(),
            index_sha256: record.sha256,
            index_bytes: record.bytes,
            payload_files: index.files.len() as u64,
        };
        seal.validate()?;
        Ok(seal)
    }

    /// Publish a signed seal as a create-new `0600` sibling of this evidence directory.
    ///
    /// The filename is derived from the sealed index digest, so it is bounded and cannot inject a
    /// path component. Publication uses the same same-directory temporary file + no-replace hard
    /// link discipline as payload evidence. The directory is re-verified before publication.
    pub fn write_signed_seal_sibling(
        &self,
        signed: &SignedEvidenceSealV1,
    ) -> Result<PathBuf, EvidenceError> {
        signed.validate()?;
        {
            let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
            if !state.sealed {
                return Err(EvidenceError::Invalid(
                    "external evidence seal can only be written after the directory is sealed"
                        .into(),
                ));
            }
        }
        verify_evidence_directory(&self.path, &signed.seal)?;
        let parent =
            self.path.parent().ok_or_else(|| EvidenceError::UnsafePath(self.path.clone()))?;
        ensure_existing_directory_no_symlink(parent, None)?;
        let file = format!("evidence-seal-{}.v1.json", signed.seal.index_sha256);
        validate_file_name(&file)?;
        let mut bytes = serde_json::to_vec_pretty(signed)?;
        bytes.push(b'\n');
        atomic_publish_file(parent, &file, &bytes)?;
        Ok(parent.join(file))
    }

    #[allow(dead_code)]
    pub fn sign_and_write_seal_sibling(
        &self,
        seal: EvidenceSealV1,
        signer: &dyn Signer,
    ) -> Result<(PathBuf, SignedEvidenceSealV1), EvidenceError> {
        let signed = SignedEvidenceSealV1::sign_with_aether(seal, signer)?;
        let path = self.write_signed_seal_sibling(&signed)?;
        Ok((path, signed))
    }

    pub fn sign_and_write_seal_sibling_with_ed25519(
        &self,
        seal: EvidenceSealV1,
        key: &Ed25519KeyMaterial,
    ) -> Result<(PathBuf, SignedEvidenceSealV1), EvidenceError> {
        let signed = SignedEvidenceSealV1::sign_with_ed25519(seal, key)?;
        let path = self.write_signed_seal_sibling(&signed)?;
        Ok((path, signed))
    }

    pub fn verify(
        path: impl AsRef<Path>,
        seal: &EvidenceSealV1,
    ) -> Result<VerifiedEvidenceDirectory, EvidenceError> {
        verify_evidence_directory(path.as_ref(), seal)
    }
}

#[derive(Debug, Clone)]
pub struct VerifiedEvidenceDirectory {
    path: PathBuf,
    index: EvidenceIndexV1,
    index_sha256: String,
}

impl VerifiedEvidenceDirectory {
    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn index(&self) -> &EvidenceIndexV1 {
        &self.index
    }

    pub fn index_sha256(&self) -> &str {
        &self.index_sha256
    }

    pub fn read(&self, file: &str) -> Result<Vec<u8>, EvidenceError> {
        validate_file_name(file)?;
        let expected =
            self.index.files.iter().find(|record| record.file == file).ok_or_else(|| {
                EvidenceError::Invalid(format!("file {file:?} is not in evidence index"))
            })?;
        let path = self.path.join(file);
        let bytes = read_regular_file_no_symlink(&path, MAX_EVIDENCE_FILE_BYTES)?;
        verify_file_record(&path, &bytes, expected)?;
        Ok(bytes)
    }
}

fn verify_evidence_directory(
    path: &Path,
    seal: &EvidenceSealV1,
) -> Result<VerifiedEvidenceDirectory, EvidenceError> {
    seal.validate()?;
    validate_existing_directory_path(path)?;
    ensure_existing_directory_no_symlink(path, Some(0o700))?;
    let index_path = path.join(EVIDENCE_INDEX_FILE);
    let index_bytes = read_regular_file_no_symlink(&index_path, MAX_EVIDENCE_FILE_BYTES)?;
    let index_hash = sha256(&index_bytes);
    if index_hash != seal.index_sha256 {
        return Err(EvidenceError::HashMismatch {
            path: index_path,
            expected: seal.index_sha256.clone(),
            actual: index_hash,
        });
    }
    if index_bytes.len() as u64 != seal.index_bytes {
        return Err(EvidenceError::Invalid("evidence index byte count changed".into()));
    }
    let index: EvidenceIndexV1 = serde_json::from_slice(&index_bytes)?;
    index.validate()?;
    if index.files.len() as u64 != seal.payload_files {
        return Err(EvidenceError::Invalid("evidence payload file count changed".into()));
    }

    let expected_names: BTreeSet<_> = index
        .files
        .iter()
        .map(|record| record.file.as_str())
        .chain(std::iter::once(EVIDENCE_INDEX_FILE))
        .collect();
    let mut actual_names = BTreeSet::new();
    for entry in
        fs::read_dir(path).map_err(|error| io_error("read evidence directory", path, error))?
    {
        let entry =
            entry.map_err(|error| io_error("read evidence directory entry", path, error))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| EvidenceError::Invalid("evidence filename is not UTF-8".into()))?;
        actual_names.insert(name);
    }
    let actual_refs: BTreeSet<_> = actual_names.iter().map(String::as_str).collect();
    if actual_refs != expected_names {
        return Err(EvidenceError::Invalid(
            "evidence directory contains missing, unindexed, or temporary files".into(),
        ));
    }

    for expected in &index.files {
        let file_path = path.join(&expected.file);
        let bytes = read_regular_file_no_symlink(&file_path, MAX_EVIDENCE_FILE_BYTES)?;
        verify_file_record(&file_path, &bytes, expected)?;
    }
    Ok(VerifiedEvidenceDirectory {
        path: path.to_path_buf(),
        index,
        index_sha256: seal.index_sha256.clone(),
    })
}

fn verify_file_record(
    path: &Path,
    bytes: &[u8],
    expected: &EvidenceFileRecordV1,
) -> Result<(), EvidenceError> {
    if bytes.len() as u64 != expected.bytes {
        return Err(EvidenceError::Invalid(format!(
            "evidence byte count changed for {}",
            path.display()
        )));
    }
    let actual = sha256(bytes);
    if actual != expected.sha256 {
        return Err(EvidenceError::HashMismatch {
            path: path.to_path_buf(),
            expected: expected.sha256.clone(),
            actual,
        });
    }
    Ok(())
}

fn atomic_publish_file(
    directory: &Path,
    file: &str,
    bytes: &[u8],
) -> Result<EvidenceFileRecordV1, EvidenceError> {
    validate_file_name(file)?;
    let final_path = directory.join(file);
    if fs::symlink_metadata(&final_path).is_ok() {
        return Err(EvidenceError::ReuseRefused(final_path));
    }
    let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temp_name = format!(".alpha-evidence-{}-{sequence}.tmp", std::process::id());
    let temp_path = directory.join(temp_name);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|error| io_error("create temporary evidence file", &temp_path, error))?;
    let publication = (|| -> Result<(), EvidenceError> {
        temp.write_all(bytes)
            .map_err(|error| io_error("write temporary evidence file", &temp_path, error))?;
        temp.sync_all()
            .map_err(|error| io_error("sync temporary evidence file", &temp_path, error))?;
        #[cfg(unix)]
        fs::set_permissions(&temp_path, unix_permissions(0o600))
            .map_err(|error| io_error("set evidence file permissions", &temp_path, error))?;
        // A same-directory hard link is an atomic, no-replace publication: unlike rename, it never
        // overwrites an existing path, including a symlink planted by another process.
        fs::hard_link(&temp_path, &final_path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                EvidenceError::ReuseRefused(final_path.clone())
            } else {
                io_error("publish evidence file", &final_path, error)
            }
        })?;
        fs::remove_file(&temp_path)
            .map_err(|error| io_error("remove temporary evidence link", &temp_path, error))?;
        sync_directory(directory)?;
        ensure_regular_file_no_symlink(&final_path, Some(0o600))?;
        Ok(())
    })();
    if publication.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    publication?;
    Ok(EvidenceFileRecordV1 {
        file: file.to_string(),
        bytes: bytes.len() as u64,
        sha256: sha256(bytes),
    })
}

fn read_regular_file_no_symlink(path: &Path, cap: usize) -> Result<Vec<u8>, EvidenceError> {
    let before = ensure_regular_file_no_symlink(path, Some(0o600))?;
    if before.len() > cap as u64 {
        return Err(EvidenceError::CapExceeded("evidence file read bytes"));
    }
    let file = File::open(path).map_err(|error| io_error("open evidence file", path, error))?;
    let opened =
        file.metadata().map_err(|error| io_error("stat opened evidence file", path, error))?;
    if !same_file(&before, &opened) {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }
    let after = fs::symlink_metadata(path)
        .map_err(|error| io_error("re-stat evidence file", path, error))?;
    if after.file_type().is_symlink() || !same_file(&opened, &after) {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((cap as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read evidence file", path, error))?;
    if bytes.len() > cap {
        return Err(EvidenceError::CapExceeded("evidence file read bytes"));
    }
    Ok(bytes)
}

fn read_external_regular_file(
    path: &Path,
    cap: usize,
    expected_mode: Option<u32>,
) -> Result<Vec<u8>, EvidenceError> {
    validate_exact_external_file_path(path)?;
    let before = ensure_regular_file_no_symlink(path, expected_mode)?;
    if before.len() > cap as u64 {
        return Err(EvidenceError::CapExceeded("external evidence file read bytes"));
    }
    let file =
        File::open(path).map_err(|error| io_error("open external evidence file", path, error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error("stat opened external evidence file", path, error))?;
    if !same_file(&before, &opened) {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((cap as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read external evidence file", path, error))?;
    if bytes.len() > cap {
        return Err(EvidenceError::CapExceeded("external evidence file read bytes"));
    }
    ensure_file_unchanged(path, &opened, bytes.len() as u64)?;
    Ok(bytes)
}

fn streaming_stable_file_sha256(path: &Path) -> Result<String, EvidenceError> {
    let before = ensure_regular_file_no_symlink(path, None)?;
    let mut file =
        File::open(path).map_err(|error| io_error("open packaged executable", path, error))?;
    let opened = file
        .metadata()
        .map_err(|error| io_error("stat opened packaged executable", path, error))?;
    if !same_file(&before, &opened) {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }

    let mut hasher = Sha256::new();
    let mut bytes_read = 0_u64;
    let mut chunk = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|error| io_error("hash packaged executable", path, error))?;
        if read == 0 {
            break;
        }
        bytes_read = bytes_read
            .checked_add(read as u64)
            .ok_or(EvidenceError::CapExceeded("packaged executable bytes"))?;
        hasher.update(&chunk[..read]);
    }
    ensure_file_unchanged(path, &opened, bytes_read)?;
    Ok(format!("{:x}", hasher.finalize()))
}

fn validate_exact_external_file_path(path: &Path) -> Result<(), EvidenceError> {
    validate_absolute_clean_path(path)?;
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(EvidenceError::UnsafePath(path.to_path_buf()));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| io_error("canonicalize external evidence file", path, error))?;
    if canonical != path {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }
    Ok(())
}

fn ensure_file_unchanged(
    path: &Path,
    opened: &fs::Metadata,
    bytes_read: u64,
) -> Result<(), EvidenceError> {
    let after_open = File::open(path)
        .and_then(|file| file.metadata())
        .map_err(|error| io_error("re-stat opened external evidence file", path, error))?;
    let after_path = fs::symlink_metadata(path)
        .map_err(|error| io_error("re-stat external evidence file path", path, error))?;
    if after_path.file_type().is_symlink()
        || !same_file(opened, &after_open)
        || !same_file(opened, &after_path)
        || opened.len() != bytes_read
        || opened.len() != after_open.len()
        || opened.modified().ok() != after_open.modified().ok()
        || opened.modified().ok() != after_path.modified().ok()
    {
        return Err(EvidenceError::Invalid(
            "external evidence file changed while it was read".into(),
        ));
    }
    Ok(())
}

fn validate_file_name(file: &str) -> Result<(), EvidenceError> {
    if file.is_empty() || file.len() > 255 {
        return Err(EvidenceError::Invalid("evidence filename length is invalid".into()));
    }
    let path = Path::new(file);
    let mut components = path.components();
    match (components.next(), components.next()) {
        (Some(Component::Normal(_)), None) if file != "." && file != ".." => Ok(()),
        _ => Err(EvidenceError::Invalid(
            "evidence filename must be one normal path component".into(),
        )),
    }
}

fn validate_new_directory_path(path: &Path) -> Result<(), EvidenceError> {
    validate_absolute_clean_path(path)?;
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(EvidenceError::UnsafePath(path.to_path_buf()));
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Err(EvidenceError::ReuseRefused(path.to_path_buf())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(io_error("inspect prospective evidence directory", path, error)),
    }
}

fn validate_existing_directory_path(path: &Path) -> Result<(), EvidenceError> {
    validate_absolute_clean_path(path)?;
    if path.parent().is_none() || path.file_name().is_none() {
        return Err(EvidenceError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn validate_absolute_clean_path(path: &Path) -> Result<(), EvidenceError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(EvidenceError::UnsafePath(path.to_path_buf()));
    }
    let mut saw_root = false;
    for component in path.components() {
        match component {
            Component::RootDir if !saw_root => saw_root = true,
            Component::Normal(_) if saw_root => {}
            _ => return Err(EvidenceError::UnsafePath(path.to_path_buf())),
        }
    }
    Ok(())
}

fn ensure_existing_directory_no_symlink(
    path: &Path,
    expected_mode: Option<u32>,
) -> Result<fs::Metadata, EvidenceError> {
    validate_absolute_clean_path(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect evidence directory", path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }
    if !metadata.is_dir() {
        return Err(EvidenceError::NotRegular(path.to_path_buf()));
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| io_error("canonicalize evidence directory", path, error))?;
    if canonical != path {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }
    #[cfg(unix)]
    if let Some(expected) = expected_mode {
        use std::os::unix::fs::PermissionsExt;
        let actual = metadata.permissions().mode() & 0o777;
        if actual != expected {
            return Err(EvidenceError::PermissionMismatch {
                path: path.to_path_buf(),
                expected,
                actual,
            });
        }
    }
    Ok(metadata)
}

fn ensure_regular_file_no_symlink(
    path: &Path,
    expected_mode: Option<u32>,
) -> Result<fs::Metadata, EvidenceError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io_error("inspect evidence file", path, error))?;
    if metadata.file_type().is_symlink() {
        return Err(EvidenceError::SymlinkRefused(path.to_path_buf()));
    }
    if !metadata.is_file() {
        return Err(EvidenceError::NotRegular(path.to_path_buf()));
    }
    #[cfg(unix)]
    if let Some(expected) = expected_mode {
        use std::os::unix::fs::PermissionsExt;
        let actual = metadata.permissions().mode() & 0o777;
        if actual != expected {
            return Err(EvidenceError::PermissionMismatch {
                path: path.to_path_buf(),
                expected,
                actual,
            });
        }
    }
    Ok(metadata)
}

#[cfg(unix)]
fn unix_permissions(mode: u32) -> fs::Permissions {
    use std::os::unix::fs::PermissionsExt;
    fs::Permissions::from_mode(mode)
}

#[cfg(unix)]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(not(unix))]
fn same_file(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len()
        && left.created().ok() == right.created().ok()
        && left.modified().ok() == right.modified().ok()
}

fn sync_directory(path: &Path) -> Result<(), EvidenceError> {
    let directory =
        File::open(path).map_err(|error| io_error("open evidence directory", path, error))?;
    directory.sync_all().map_err(|error| io_error("sync evidence directory", path, error))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    struct CountingModel {
        calls: Arc<AtomicUsize>,
        completion: Completion,
    }

    impl Model for CountingModel {
        fn complete(&self, _request: Prompt) -> Result<Completion, ModelError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.completion.clone())
        }

        fn describe(&self) -> String {
            "counting-model".into()
        }
    }

    fn prompt(user: &str) -> Prompt {
        Prompt {
            system_prompt: "bounded system".into(),
            user_prompt: user.into(),
            max_tokens: 128,
            temperature: 0.25,
        }
    }

    fn completion(content: &str) -> Completion {
        Completion {
            content: content.into(),
            model: "provider-model-v1".into(),
            usage: Some(TokenUsage { prompt_tokens: 3, completion_tokens: 5, total_tokens: 8 }),
            provider: Some(ProviderReceipt {
                response_id: Some("response-123".into()),
                request_id: Some("request-456".into()),
                reported_model: Some("provider-model-v1".into()),
                finish_reason: Some("stop".into()),
                store_requested: false,
            }),
        }
    }

    #[test]
    fn evidence_digests_are_bare_lowercase_sha256_hex() {
        let digest = sha256(b"evidence digest format");
        assert_eq!(digest.len(), 64);
        assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert!(!digest.starts_with("sha256:"));
        validate_digest("test digest", &digest).unwrap();
    }

    #[test]
    fn replay_fails_closed_on_prompt_or_order_drift() {
        let calls = Arc::new(AtomicUsize::new(0));
        let journal = Arc::new(ModelCallJournal::new());
        let recorder = RecordingModel::new(
            "builder",
            SanitizedModelConfigV1::fixture("fixture", "fixture-v1").unwrap(),
            Arc::new(CountingModel { calls: calls.clone(), completion: completion("approved") }),
            journal.clone(),
        )
        .unwrap();
        let first = prompt("draft");
        let second = prompt("revise");
        recorder.complete(first.clone()).unwrap();
        recorder.complete(second.clone()).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let entries = journal.replay_entries().unwrap();
        assert_eq!(entries[0].prompt.system_prompt.as_bytes(), first.system_prompt.as_bytes());
        assert_eq!(entries[0].prompt.user_prompt.as_bytes(), first.user_prompt.as_bytes());
        assert_eq!(entries[0].prompt.max_tokens, first.max_tokens);
        assert_eq!(entries[0].prompt.temperature_bits, first.temperature.to_bits());
        assert_eq!(entries[0].prompt.sha256, prompt_sha256(&first).unwrap());

        let mut tampered = entries.clone();
        tampered[0].prompt.user_prompt.push('!');
        assert!(matches!(RecordedModel::new("builder", tampered), Err(EvidenceError::Invalid(_))));

        let wrong_order = RecordedModel::new("builder", entries.clone()).unwrap();
        assert!(matches!(wrong_order.complete(second.clone()), Err(ModelError::Config(_))));
        assert!(matches!(wrong_order.complete(first.clone()), Err(ModelError::Config(_))));

        let exact = RecordedModel::new("builder", entries).unwrap();
        let replayed = exact.complete(first).unwrap();
        assert_eq!(replayed.content, "approved");
        assert_eq!(
            replayed.provider.as_ref().and_then(|receipt| receipt.response_id.as_deref()),
            Some("response-123")
        );
        assert_eq!(exact.complete(second).unwrap().content, "approved");
        exact.assert_exhausted().unwrap();
        assert!(matches!(exact.complete(prompt("extra")), Err(ModelError::Config(_))));
    }

    #[test]
    fn recording_caps_reject_before_call_and_reject_oversize_reply() {
        let calls = Arc::new(AtomicUsize::new(0));
        let journal = Arc::new(ModelCallJournal::new());
        let recorder = RecordingModel::new(
            "reviewer",
            SanitizedModelConfigV1::fixture("fixture", "fixture-v1").unwrap(),
            Arc::new(CountingModel { calls: calls.clone(), completion: completion("ok") }),
            journal,
        )
        .unwrap();
        let mut too_large = prompt("x");
        too_large.user_prompt = "x".repeat(MAX_PROMPT_PART_BYTES + 1);
        assert!(matches!(recorder.complete(too_large), Err(ModelError::Config(_))));
        assert_eq!(calls.load(Ordering::SeqCst), 0);

        let reply_calls = Arc::new(AtomicUsize::new(0));
        let reply_journal = Arc::new(ModelCallJournal::new());
        let oversized_reply = "y".repeat(MAX_COMPLETION_BYTES + 1);
        let oversize = RecordingModel::new(
            "contract-tester",
            SanitizedModelConfigV1::fixture("fixture", "fixture-v1").unwrap(),
            Arc::new(CountingModel {
                calls: reply_calls.clone(),
                completion: completion(&oversized_reply),
            }),
            reply_journal.clone(),
        )
        .unwrap();
        assert!(matches!(oversize.complete(prompt("test")), Err(ModelError::Config(_))));
        assert_eq!(reply_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            reply_journal.records().unwrap()[0].outcome,
            ModelCallOutcomeV1::Failed { class: ModelCallErrorClassV1::EvidenceCap, .. }
        ));
        let timing = &reply_journal.records().unwrap()[0].timing;
        assert!(timing.monotonic_duration_ms.is_some());
        timing.validate().unwrap();
    }

    #[test]
    fn sanitized_config_serialization_never_contains_key_or_key_hash() {
        let secret = "sk-super-secret-evidence-tripwire";
        let username = "endpoint-user-tripwire";
        let path = "private-path-tripwire";
        let query = "private-query-tripwire";
        let fragment = "private-fragment-tripwire";
        let config = ModelConfig {
            base_url: format!(
                "https://{username}:{secret}@provider.invalid/{path}?token={query}#{fragment}"
            ),
            model: "model-v1".into(),
            api_key: Some(secret.into()),
            timeout: Duration::from_secs(17),
        };
        let sanitized =
            SanitizedModelConfigV1::from_model_config("openai-compatible", &config).unwrap();
        let json = serde_json::to_string(&sanitized).unwrap();
        assert!(!json.contains(secret));
        assert!(!json.contains(&sha256(secret.as_bytes())));
        assert!(!json.contains("api_key"));
        assert!(!json.contains("base_url"));
        for discarded in [username, path, query, fragment] {
            assert!(!json.contains(discarded));
        }
        assert_eq!(sanitized.endpoint_origin.as_deref(), Some("https://provider.invalid"));
        assert_eq!(sanitized.timeout_ms, 17_000);
    }

    #[test]
    fn endpoint_origin_parser_is_strict_and_never_retains_url_tail_or_userinfo() {
        let origins = [
            (
                "HTTPS://User:p%40ss@Example.COM:0443/v1?q=secret#fragment",
                "https://example.com:443",
            ),
            ("http://127.0.0.1:8080/models", "http://127.0.0.1:8080"),
            ("https://[2001:0db8::1]:8443/v1", "https://[2001:db8::1]:8443"),
            ("https://localhost", "https://localhost"),
        ];
        for (source, expected) in origins {
            assert_eq!(endpoint_origin(source).unwrap(), expected);
        }

        for rejected in [
            "ftp://provider.invalid/v1",
            "https://",
            "https://provider.invalid:0/v1",
            "https://provider.invalid:70000/v1",
            "https://bad_host.invalid/v1",
            "https://provider.invalid\\@attacker.invalid/v1",
            "https://[not-ipv6]/v1",
            "https://one@two@provider.invalid/v1",
            "https://999.999.999.999/v1",
        ] {
            let error = endpoint_origin(rejected).unwrap_err().to_string();
            assert!(!error.contains(rejected));
        }
    }

    #[test]
    fn timing_keeps_monotonic_duration_and_reports_wall_clock_regression() {
        let timing = ModelCallTimingV1::from_observations(
            UNIX_EPOCH + Duration::from_secs(2),
            UNIX_EPOCH + Duration::from_secs(1),
            Duration::from_millis(7),
        );
        assert_eq!(timing.started_unix_ms, Some(2_000));
        assert_eq!(timing.finished_unix_ms, Some(1_000));
        assert_eq!(timing.monotonic_duration_ms, Some(7));
        assert!(timing.wall_clock_regressed);
        timing.validate().unwrap();

        let out_of_domain = ModelCallTimingV1::from_observations(
            UNIX_EPOCH - Duration::from_millis(1),
            UNIX_EPOCH,
            Duration::from_millis(MAX_MODEL_CALL_DURATION_MS + 1),
        );
        assert_eq!(out_of_domain.started_unix_ms, None);
        assert_eq!(out_of_domain.finished_unix_ms, Some(0));
        assert_eq!(out_of_domain.monotonic_duration_ms, None);
        assert!(!out_of_domain.wall_clock_regressed);
        out_of_domain.validate().unwrap();
    }

    fn unique_test_path(label: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("alpha-evidence-{label}-{}-{nonce}", std::process::id()))
    }

    #[test]
    fn evidence_directory_refuses_reuse_and_symlink_ancestors() {
        let path = unique_test_path("reuse");
        let directory = EvidenceDirectory::create(&path).unwrap();
        directory.write_bytes("one.json", b"{}\n").unwrap();
        assert!(matches!(
            directory.write_bytes("one.json", b"changed\n"),
            Err(EvidenceError::ReuseRefused(_))
        ));
        assert!(matches!(EvidenceDirectory::create(&path), Err(EvidenceError::ReuseRefused(_))));
        drop(directory);
        fs::remove_file(path.join("one.json")).unwrap();
        fs::remove_dir(&path).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let outer = unique_test_path("symlink");
            let real = outer.join("real");
            let link = outer.join("link");
            fs::create_dir(&outer).unwrap();
            fs::create_dir(&real).unwrap();
            symlink(&real, &link).unwrap();
            assert!(matches!(
                EvidenceDirectory::create(link.join("bundle")),
                Err(EvidenceError::SymlinkRefused(_))
            ));
            fs::remove_file(link).unwrap();
            fs::remove_dir(real).unwrap();
            fs::remove_dir(outer).unwrap();
        }
    }

    #[test]
    fn sealed_directory_reopens_and_detects_hash_tamper() {
        let path = unique_test_path("tamper");
        let directory = EvidenceDirectory::create(&path).unwrap();
        let record = directory.write_json("calls.json", &vec!["one", "two"]).unwrap();
        let seal = directory.seal().unwrap();
        let verified = EvidenceDirectory::verify(&path, &seal).unwrap();
        assert_eq!(verified.read("calls.json").unwrap().len() as u64, record.bytes);

        let payload = path.join("calls.json");
        let mut file = OpenOptions::new().write(true).truncate(true).open(&payload).unwrap();
        file.write_all(b"tampered\n").unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            EvidenceDirectory::verify(&path, &seal),
            Err(EvidenceError::Invalid(_)) | Err(EvidenceError::HashMismatch { .. })
        ));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn signed_seal_is_external_verified_private_and_create_new() {
        let path = unique_test_path("signed-seal");
        let directory = EvidenceDirectory::create(&path).unwrap();
        directory.write_bytes("calls.json", b"{}\n").unwrap();
        let seal = directory.seal().unwrap();
        let key = Ed25519KeyMaterial::from_seed([29_u8; 32]).unwrap();
        let (seal_path, signed) =
            directory.sign_and_write_seal_sibling_with_ed25519(seal.clone(), &key).unwrap();

        assert_eq!(seal_path.parent(), path.parent());
        assert!(!seal_path.starts_with(&path));
        let retained: SignedEvidenceSealV1 =
            serde_json::from_slice(&fs::read(&seal_path).unwrap()).unwrap();
        assert_eq!(retained, signed);
        retained.verify_signature(&sigil::Ed25519Verifier).unwrap();
        EvidenceDirectory::verify(&path, &retained.seal).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&seal_path).unwrap().permissions().mode() & 0o777, 0o600);
        }

        assert!(matches!(
            directory.write_signed_seal_sibling(&signed),
            Err(EvidenceError::ReuseRefused(_))
        ));
        let mut tampered = signed.clone();
        tampered.seal.payload_files += 1;
        assert!(matches!(
            tampered.verify_signature(&sigil::Ed25519Verifier),
            Err(EvidenceError::Invalid(_))
        ));

        let aether_signer = aether::Ed25519Signer::new(key);
        let signed_via_aether =
            SignedEvidenceSealV1::sign_with_aether(seal, &aether_signer).unwrap();
        signed_via_aether.verify_signature(&sigil::Ed25519Verifier).unwrap();

        fs::remove_file(seal_path).unwrap();
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn source_identity_requires_an_exact_clean_commit() {
        let path = unique_test_path("source-identity");
        fs::create_dir(&path).unwrap();
        let run_git = |args: &[&str]| {
            let status = Command::new("git")
                .arg("-C")
                .arg(&path)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "git command failed: {args:?}");
        };
        run_git(&["init", "--quiet"]);
        fs::write(path.join("tracked.txt"), b"committed\n").unwrap();
        run_git(&["add", "tracked.txt"]);
        run_git(&[
            "-c",
            "user.name=Alpha Evidence Test",
            "-c",
            "user.email=evidence@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "--quiet",
            "--no-verify",
            "-m",
            "fixture",
        ]);

        let identity = SourceIdentityV1::derive_clean(&path).unwrap();
        identity.validate().unwrap();
        assert!(identity.worktree_clean);
        assert!(matches!(identity.git_commit.len(), 40 | 64));
        assert_eq!(identity.binary_sha256.len(), 64);
        let mut bound = identity.clone();
        bound.binary_build_commit = Some(bound.git_commit.clone());
        bound.require_matching_build_commit().unwrap();
        bound.binary_build_commit = Some("0".repeat(bound.git_commit.len()));
        assert!(matches!(bound.require_matching_build_commit(), Err(EvidenceError::Invalid(_))));

        fs::write(path.join("untracked.txt"), b"dirty\n").unwrap();
        assert!(matches!(SourceIdentityV1::derive_clean(&path), Err(EvidenceError::Invalid(_))));
        fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn strict_schema_rejects_unknown_fields() {
        let json = r#"{
            "schema":"alpha.model-call.v1",
            "global_ordinal":0,
            "role":"builder",
            "role_ordinal":0,
            "config":{"provider":"fixture","requested_model":"v1","endpoint_origin":null,"timeout_ms":0},
            "prompt":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","system_prompt_bytes":1,"user_prompt_bytes":1,"max_tokens":1,"temperature_bits":0},
            "timing":{"started_unix_ms":0,"finished_unix_ms":0,"monotonic_duration_ms":0,"wall_clock_regressed":false},
            "outcome":{"kind":"failed","class":"decode","http_status":null},
            "unexpected":true
        }"#;
        assert!(serde_json::from_str::<ModelCallRecordV1>(json).is_err());
    }
}
