//! Stable identities and value/schema/key contracts.

use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    canonical_json_bytes, sha256_digest, MAX_CAUSAL_LINKS, MAX_EVIDENCE_REFS,
    MAX_IDEMPOTENCY_KEY_BYTES, MAX_ID_BYTES, MAX_INLINE_SCHEMA_BYTES, MAX_INLINE_VALUE_BYTES,
    MAX_JOB_ATTEMPTS, MAX_JOB_DELEGATES, MAX_MEDIA_TYPE_BYTES, MAX_NAME_BYTES,
    MAX_PUBLIC_KEY_BYTES, MAX_RESULT_RECIPIENTS, MAX_VERSION_BYTES,
};

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum ContractError {
    #[error("invalid contract: {0}")]
    Invalid(String),
    #[error("contract limit exceeded: {0}")]
    Limit(String),
    #[error("contract encoding error: {0}")]
    Encoding(String),
    #[error("contract cryptography error: {0}")]
    Crypto(String),
}

/// Structural pressure validation. It deliberately does not make trust or placement decisions.
pub trait Validate {
    fn validate(&self) -> Result<(), ContractError>;
}

macro_rules! string_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Self { Self(value.into()) }
            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.0) }
        }

        impl Validate for $name {
            fn validate(&self) -> Result<(), ContractError> {
                validate_text(stringify!($name), &self.0, MAX_ID_BYTES)
            }
        }
    };
}

string_id!(/// The Abode identity that owns a job. Never a mutable node address.
    HomeId);
string_id!(/// Deterministic identity derived from a home and caller idempotency key.
    JobId);
string_id!(/// Identity of one registered live deployment.
    DeploymentId);
string_id!(/// Identity of an epoch-fenced custody handoff.
    HandoffId);
string_id!(/// Identity of a cooperative steer/cancel command.
    ControlId);

/// An immutable function definition: an exact signed manifest plus an entrypoint in it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FunctionId {
    pub manifest_content_address: String,
    pub entrypoint: String,
}

impl Validate for FunctionId {
    fn validate(&self) -> Result<(), ContractError> {
        validate_sha256("manifest_content_address", &self.manifest_content_address)?;
        validate_text("entrypoint", &self.entrypoint, MAX_NAME_BYTES)
    }
}

/// Human-facing exact-version alias. Resolution is pinned before a job is accepted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FunctionAlias {
    pub realm: String,
    pub name: String,
    pub version: String,
    pub entrypoint: String,
}

impl Validate for FunctionAlias {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text("realm", &self.realm, MAX_ID_BYTES)?;
        if self.realm.contains(':') {
            return Err(ContractError::Invalid("realm must not contain `:`".into()));
        }
        validate_text("name", &self.name, MAX_NAME_BYTES)?;
        validate_text("version", &self.version, MAX_VERSION_BYTES)?;
        validate_text("entrypoint", &self.entrypoint, MAX_NAME_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FunctionSelectorV1 {
    Id { function: FunctionId },
    Alias { alias: FunctionAlias },
}

impl Validate for FunctionSelectorV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Id { function } => function.validate(),
            Self::Alias { alias } => alias.validate(),
        }
    }
}

/// SHA-256 content reference for data moved outside an envelope (normally over GX).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobRefV1 {
    pub digest: String,
    pub size: u64,
    pub media_type: String,
}

impl Validate for BlobRefV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_sha256("blob.digest", &self.digest)?;
        validate_text("blob.media_type", &self.media_type, MAX_MEDIA_TYPE_BYTES)
    }
}

/// Bounded inline JSON or a content-addressed external value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ValueRefV1 {
    Inline {
        value: Value,
    },
    Blob {
        blob: BlobRefV1,
    },
    /// Recipient-sealed ciphertext. The Abode root signs bindings but is never an encryption key.
    Sealed {
        sealed: Box<SealedValueV1>,
    },
}

impl ValueRefV1 {
    pub fn validate_with_limit(&self, max_inline_bytes: usize) -> Result<(), ContractError> {
        match self {
            Self::Inline { value } => {
                let len = canonical_json_bytes(value)?.len();
                if len > max_inline_bytes {
                    Err(ContractError::Limit(format!(
                        "inline JSON is {len} bytes, exceeds {max_inline_bytes}"
                    )))
                } else {
                    Ok(())
                }
            }
            Self::Blob { blob } => blob.validate(),
            Self::Sealed { sealed } => sealed.validate(),
        }
    }

    /// Require every external byte reference to be durably available before accepting its owner.
    pub fn verify_available(
        &self,
        availability: &dyn BlobAvailability,
    ) -> Result<(), ContractError> {
        match self {
            Self::Inline { .. } => Ok(()),
            Self::Blob { blob } => availability.verify_available(blob),
            Self::Sealed { sealed } => availability.verify_available(&sealed.ciphertext),
        }
    }
}

/// Injected durability/proof seam for content-addressed values.
///
/// A local filesystem organ may verify bytes directly; a remote implementation may verify a signed
/// storage receipt. The Home must call this before its durable `Accepted` record. Digest strings are
/// never treated as proof that bytes exist.
pub trait BlobAvailability: Send + Sync {
    fn verify_available(&self, blob: &BlobRefV1) -> Result<(), ContractError>;
}

/// Injected, bounded byte I/O seam used for portable Home checkpoints.
///
/// Implementations must durably commit bytes before returning from `put_checkpoint` and must
/// verify the reference's digest and size on every successful read. Limits, replication, and
/// storage admission remain implementation policy; this trait carries neither filesystem details
/// nor signing/encryption keys.
pub trait CheckpointBlobStore: BlobAvailability {
    fn put_checkpoint(&self, media_type: &str, bytes: &[u8]) -> Result<BlobRefV1, ContractError>;

    fn get_checkpoint(&self, blob: &BlobRefV1) -> Result<Vec<u8>, ContractError>;
}

impl Validate for ValueRefV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.validate_with_limit(MAX_INLINE_VALUE_BYTES)
    }
}

/// JSON Schema Draft 2020-12, inline or content-addressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JsonSchemaRootV1 {
    Any,
    Object,
    Array,
    String,
    Number,
    Integer,
    Boolean,
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SchemaRefV1 {
    Inline { schema: Value },
    Blob { blob: BlobRefV1, root: JsonSchemaRootV1 },
}

impl SchemaRefV1 {
    pub fn validate_input(&self) -> Result<(), ContractError> {
        self.validate()?;
        if let Self::Inline { schema } = self {
            let object = schema.as_object().ok_or_else(|| {
                ContractError::Invalid("input JSON Schema must be an object schema".into())
            })?;
            let object_root = object.get("type").and_then(Value::as_str) == Some("object")
                || object.contains_key("$ref")
                || object.contains_key("allOf");
            if !object_root {
                return Err(ContractError::Invalid(
                    "input JSON Schema must declare an object root (`type: object`)".into(),
                ));
            }
        } else if let Self::Blob { root, .. } = self {
            if *root != JsonSchemaRootV1::Object {
                return Err(ContractError::Invalid(
                    "external input JSON Schema must declare `root: object`".into(),
                ));
            }
        }
        Ok(())
    }
}

impl Validate for SchemaRefV1 {
    fn validate(&self) -> Result<(), ContractError> {
        match self {
            Self::Inline { schema } => {
                if !schema.is_object() && !schema.is_boolean() {
                    return Err(ContractError::Invalid(
                        "JSON Schema must be an object or boolean".into(),
                    ));
                }
                let len = canonical_json_bytes(schema)?.len();
                if len > MAX_INLINE_SCHEMA_BYTES {
                    return Err(ContractError::Limit(format!(
                        "inline JSON Schema is {len} bytes, exceeds {MAX_INLINE_SCHEMA_BYTES}"
                    )));
                }
                Ok(())
            }
            Self::Blob { blob, .. } => blob.validate(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectClassV1 {
    ReadOnly,
    Idempotent,
    NonIdempotent,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionControlsV1 {
    #[serde(default)]
    pub progress: bool,
    #[serde(default)]
    pub steer: bool,
    #[serde(default)]
    pub cancel: bool,
    #[serde(default)]
    pub checkpoint: bool,
}

/// Optional structured contract appended to `sigil::Entrypoint`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrypointContractV1 {
    pub description: String,
    pub input_schema: SchemaRefV1,
    pub output_schema: SchemaRefV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_schema: Option<SchemaRefV1>,
    #[serde(default)]
    pub effect: EffectClassV1,
    #[serde(default)]
    pub controls: FunctionControlsV1,
}

impl Validate for EntrypointContractV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text(
            "entrypoint.contract.description",
            &self.description,
            MAX_INLINE_VALUE_BYTES,
        )?;
        self.input_schema.validate_input()?;
        self.output_schema.validate()?;
        if let Some(error) = &self.error_schema {
            error.validate()?;
        }
        Ok(())
    }
}

/// A bounded proof or reputation/trust input. It is evidence, never authority by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceRefV1 {
    pub kind: String,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locator: Option<String>,
}

impl Validate for EvidenceRefV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text("evidence.kind", &self.kind, MAX_NAME_BYTES)?;
        validate_sha256("evidence.digest", &self.digest)?;
        validate_optional_text("evidence.issuer", self.issuer.as_deref(), MAX_PUBLIC_KEY_BYTES)?;
        validate_optional_text("evidence.locator", self.locator.as_deref(), MAX_ID_BYTES)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceV1 {
    pub subject: String,
    pub claim: String,
    pub value: ValueRefV1,
    /// Advisory wall-clock evidence only; never grants authority or requires a synchronized clock.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}

impl Validate for EvidenceV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_text("evidence.subject", &self.subject, MAX_ID_BYTES)?;
        validate_text("evidence.claim", &self.claim, MAX_NAME_BYTES)?;
        self.value.validate()?;
        validate_expiry(self.issued_at_unix_ms, self.expires_at_unix_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolutionReceiptV1 {
    pub selector: FunctionSelectorV1,
    pub function: FunctionId,
    pub artifact_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for ResolutionReceiptV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.selector.validate()?;
        self.function.validate()?;
        if matches!(&self.selector, FunctionSelectorV1::Id { function } if function != &self.function)
        {
            return Err(ContractError::Invalid(
                "an exact FunctionId selector cannot resolve to a different function".into(),
            ));
        }
        validate_sha256("artifact_hash", &self.artifact_hash)?;
        validate_vec("resolution.evidence", &self.evidence, MAX_EVIDENCE_REFS)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedFunctionV1 {
    pub requested: FunctionSelectorV1,
    pub function: FunctionId,
    pub artifact_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolution: Option<crate::SignedRecordV1<ResolutionReceiptV1>>,
}

impl Validate for ResolvedFunctionV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.requested.validate()?;
        self.function.validate()?;
        validate_sha256("artifact_hash", &self.artifact_hash)?;
        if let Some(receipt) = &self.resolution {
            receipt.validate()?;
            if receipt.schema != crate::SCHEMA_FUNCTION_DEPLOY_V1 || !receipt.verify() {
                return Err(ContractError::Crypto(
                    "resolved function contains an invalid resolution signature".into(),
                ));
            }
            if receipt.payload.selector != self.requested
                || receipt.payload.function != self.function
                || receipt.payload.artifact_hash != self.artifact_hash
            {
                return Err(ContractError::Invalid(
                    "resolution receipt does not match resolved function".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttemptId {
    /// Stable Job-home identity. A `JobId` alone is not an authority boundary: another valid Home
    /// can copy its public bytes into a forged grant unless the Home is part of the attempt key.
    pub home: HomeId,
    pub job: JobId,
    pub number: u8,
}

impl Validate for AttemptId {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        self.job.validate()?;
        if self.number == 0 || self.number > MAX_JOB_ATTEMPTS {
            return Err(ContractError::Invalid(format!(
                "attempt number must be in 1..={MAX_JOB_ATTEMPTS}"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobHandleV1 {
    pub home: HomeId,
    pub job: JobId,
}

impl Validate for JobHandleV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        self.job.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CausalLinkV1 {
    pub job: JobHandleV1,
    pub relation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub receipt_hash: Option<String>,
}

impl Validate for CausalLinkV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.job.validate()?;
        validate_text("causal relation", &self.relation, MAX_NAME_BYTES)?;
        if let Some(hash) = &self.receipt_hash {
            validate_sha256("causal receipt_hash", hash)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobAccessV1 {
    #[serde(default)]
    pub readers: Vec<HomeId>,
    #[serde(default)]
    pub controllers: Vec<HomeId>,
}

impl Validate for JobAccessV1 {
    fn validate(&self) -> Result<(), ContractError> {
        validate_vec("readers", &self.readers, MAX_JOB_DELEGATES)?;
        validate_vec("controllers", &self.controllers, MAX_JOB_DELEGATES)?;
        reject_duplicates("readers", self.readers.iter().map(HomeId::as_str))?;
        reject_duplicates("controllers", self.controllers.iter().map(HomeId::as_str))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbodeKeyBindingV1 {
    pub abode: HomeId,
    pub root_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ms: Option<u64>,
}

impl Validate for AbodeKeyBindingV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.abode.validate()?;
        validate_text("root_public_key", &self.root_public_key, MAX_PUBLIC_KEY_BYTES)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalCapabilityV1 {
    JobHome,
    JobControl,
    Execution,
    Custody,
    Locate,
}

/// Root-authorized, epoch-scoped operational key. The root private key never appears here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationalKeyGrantV1 {
    pub home: HomeId,
    pub epoch: u64,
    pub operational_public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
    pub capabilities: Vec<OperationalCapabilityV1>,
    #[serde(default)]
    pub evidence: Vec<EvidenceRefV1>,
}

impl Validate for OperationalKeyGrantV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.home.validate()?;
        if self.epoch == 0 {
            return Err(ContractError::Invalid("operational epoch must be non-zero".into()));
        }
        validate_text(
            "operational_public_key",
            &self.operational_public_key,
            MAX_PUBLIC_KEY_BYTES,
        )?;
        validate_ed25519_public_key("operational_public_key", &self.operational_public_key)?;
        if self.capabilities.is_empty() {
            return Err(ContractError::Invalid(
                "operational key must carry at least one capability".into(),
            ));
        }
        validate_vec("operational evidence", &self.evidence, MAX_EVIDENCE_REFS)?;
        validate_expiry(self.valid_from_unix_ms, self.expires_at_unix_ms)
    }
}

/// Abode-signed binding between its signing identity and a recipient encryption key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientKeyBindingV1 {
    pub abode: HomeId,
    pub signing_public_key: String,
    pub encryption_public_key: String,
    pub suite: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix_ms: Option<u64>,
}

impl Validate for RecipientKeyBindingV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.abode.validate()?;
        validate_ed25519_public_key("signing_public_key", &self.signing_public_key)?;
        validate_x25519_public_key("encryption_public_key", &self.encryption_public_key)?;
        validate_text("encryption suite", &self.suite, MAX_NAME_BYTES)?;
        validate_expiry(self.issued_at_unix_ms, self.expires_at_unix_ms)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientKeyWrapV1 {
    pub recipient: HomeId,
    pub binding_hash: String,
    pub encapsulated_key: String,
    pub wrapped_data_key: String,
}

impl Validate for RecipientKeyWrapV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.recipient.validate()?;
        validate_sha256("binding_hash", &self.binding_hash)?;
        validate_text("encapsulated_key", &self.encapsulated_key, MAX_PUBLIC_KEY_BYTES)?;
        validate_text("wrapped_data_key", &self.wrapped_data_key, MAX_ID_BYTES * 4)
    }
}

/// Ciphertext descriptor; encryption is an adapter concern, not implemented by the contract crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedValueV1 {
    pub ciphertext: BlobRefV1,
    pub suite: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plaintext_digest: Option<String>,
    pub recipients: Vec<RecipientKeyWrapV1>,
}

impl Validate for SealedValueV1 {
    fn validate(&self) -> Result<(), ContractError> {
        self.ciphertext.validate()?;
        validate_text("sealed suite", &self.suite, MAX_NAME_BYTES)?;
        if let Some(hash) = &self.plaintext_digest {
            validate_sha256("plaintext_digest", hash)?;
        }
        validate_vec("sealed recipients", &self.recipients, MAX_RESULT_RECIPIENTS)?;
        if self.recipients.is_empty() {
            return Err(ContractError::Invalid(
                "sealed value must have at least one recipient".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn validate_text(
    label: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), ContractError> {
    if value.trim().is_empty() {
        return Err(ContractError::Invalid(format!("{label} must not be empty")));
    }
    if value.len() > max_bytes {
        return Err(ContractError::Limit(format!(
            "{label} is {} bytes, exceeds {max_bytes}",
            value.len()
        )));
    }
    Ok(())
}

pub(crate) fn validate_optional_text(
    label: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), ContractError> {
    value.map_or(Ok(()), |value| validate_text(label, value, max_bytes))
}

pub(crate) fn validate_sha256(label: &str, value: &str) -> Result<(), ContractError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(ContractError::Invalid(format!("{label} must start with `sha256:`")));
    };
    if hex.len() != 64
        || !hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::Invalid(format!(
            "{label} must contain 64 lowercase hexadecimal digits"
        )));
    }
    Ok(())
}

/// Validate the lowercase-hex 32-byte Ed25519 public-key wire representation.
pub fn validate_ed25519_public_key(label: &str, value: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::Invalid(format!(
            "{label} must be a lowercase-hex 32-byte Ed25519 public key"
        )));
    }
    Ok(())
}

pub fn validate_x25519_public_key(label: &str, value: &str) -> Result<(), ContractError> {
    if value.len() != 64
        || !value.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ContractError::Invalid(format!(
            "{label} must be a lowercase-hex 32-byte X25519 public key"
        )));
    }
    Ok(())
}

pub(crate) fn validate_vec<T: Validate>(
    label: &str,
    values: &[T],
    max_items: usize,
) -> Result<(), ContractError> {
    if values.len() > max_items {
        return Err(ContractError::Limit(format!(
            "{label} has {} items, exceeds {max_items}",
            values.len()
        )));
    }
    for value in values {
        value.validate()?;
    }
    Ok(())
}

pub(crate) fn validate_expiry(
    issued_at_unix_ms: Option<u64>,
    expires_at_unix_ms: Option<u64>,
) -> Result<(), ContractError> {
    if matches!((issued_at_unix_ms, expires_at_unix_ms), (Some(issued), Some(expiry)) if expiry <= issued)
    {
        return Err(ContractError::Invalid(
            "expiry must be later than issue/valid-from time".into(),
        ));
    }
    Ok(())
}

pub(crate) fn reject_duplicates<'a>(
    label: &str,
    values: impl Iterator<Item = &'a str>,
) -> Result<(), ContractError> {
    let mut seen = std::collections::BTreeSet::new();
    for value in values {
        if !seen.insert(value) {
            return Err(ContractError::Invalid(format!("duplicate {label} entry `{value}`")));
        }
    }
    Ok(())
}

/// Derive a stable job identity. A caller key is scoped to one home, not globally.
pub fn derive_job_id(home: &HomeId, idempotency_key: &str) -> Result<JobId, ContractError> {
    home.validate()?;
    validate_text("caller_idempotency_key", idempotency_key, MAX_IDEMPOTENCY_KEY_BYTES)?;
    let mut bytes = Vec::with_capacity(
        crate::JOB_ID_DOMAIN_V1.len() + home.0.len() + idempotency_key.len() + 16,
    );
    bytes.extend_from_slice(crate::JOB_ID_DOMAIN_V1);
    bytes.extend_from_slice(&(home.0.len() as u64).to_be_bytes());
    bytes.extend_from_slice(home.0.as_bytes());
    bytes.extend_from_slice(&(idempotency_key.len() as u64).to_be_bytes());
    bytes.extend_from_slice(idempotency_key.as_bytes());
    Ok(JobId(sha256_digest(&bytes)))
}

/// Derive a deterministic identity for one exact loaded target instance.
pub fn derive_deployment_id(
    function: &FunctionId,
    artifact_hash: &str,
    realm: &str,
    node: &str,
    target_creature: &str,
) -> Result<DeploymentId, ContractError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        domain: &'static str,
        function: &'a FunctionId,
        artifact_hash: &'a str,
        realm: &'a str,
        node: &'a str,
        target_creature: &'a str,
    }

    function.validate()?;
    validate_sha256("artifact_hash", artifact_hash)?;
    validate_text("realm", realm, MAX_ID_BYTES)?;
    validate_text("node", node, MAX_ID_BYTES)?;
    validate_text("target_creature", target_creature, MAX_ID_BYTES)?;
    let bytes = canonical_json_bytes(&Identity {
        domain: crate::DEPLOYMENT_ID_DOMAIN_V1,
        function,
        artifact_hash,
        realm,
        node,
        target_creature,
    })?;
    Ok(DeploymentId(sha256_digest(&bytes)))
}

pub(crate) fn validate_causal_links(values: &[CausalLinkV1]) -> Result<(), ContractError> {
    validate_vec("causal links", values, MAX_CAUSAL_LINKS)
}
