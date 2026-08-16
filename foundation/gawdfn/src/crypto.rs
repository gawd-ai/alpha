//! Deterministic JSON hashing and Ed25519 record signatures.

use ring::signature::{self, KeyPair};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{ContractError, MAX_JOB_MESSAGE_BYTES, MAX_PUBLIC_KEY_BYTES, MAX_SIGNATURE_BYTES};

/// Serialize as deterministic JSON. Object keys are recursively sorted before encoding.
///
/// The v1 wire deliberately permits JSON values while forbidding maps with unstable iteration
/// order in signed Rust structs. Sorting here also makes payloads produced by other languages agree.
pub fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, ContractError> {
    let value = serde_json::to_value(value)
        .map_err(|e| ContractError::Encoding(format!("cannot encode canonical JSON: {e}")))?;
    let value = sort_json(value);
    serde_json::to_vec(&value)
        .map_err(|e| ContractError::Encoding(format!("cannot encode canonical JSON: {e}")))
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let mut sorted = serde_json::Map::new();
            let mut entries: Vec<_> = values.into_iter().collect();
            entries.sort_by(|a, b| a.0.cmp(&b.0));
            for (key, value) in entries {
                sorted.insert(key, sort_json(value));
            }
            Value::Object(sorted)
        }
        other => other,
    }
}

/// `sha256:<lowercase hex>` over arbitrary bytes.
pub fn sha256_digest(bytes: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(bytes);
    format!("sha256:{}", hex_encode(hash.finalize().as_ref()))
}

/// `sha256:<lowercase hex>` over the canonical JSON representation of `value`.
pub fn canonical_hash<T: Serialize>(value: &T) -> Result<String, ContractError> {
    Ok(sha256_digest(&canonical_json_bytes(value)?))
}

/// Narrow injection seam for an Abode authority or delegated epoch signer.
///
/// Implementations own key custody. The function contract never asks for or serializes private key
/// material; the seed-backed implementation below is only a small in-memory reference/test helper.
pub trait AuthoritySigner: Send + Sync {
    fn public_key(&self) -> &str;
    fn sign(&self, payload: &[u8]) -> Result<String, ContractError>;
}

/// In-memory Ed25519 signer for tests and simple reference compositions.
pub struct Ed25519SeedSigner {
    seed: [u8; 32],
    public_key: String,
}

impl Ed25519SeedSigner {
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, ContractError> {
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&seed)
            .map_err(|_| ContractError::Crypto("invalid Ed25519 seed".into()))?;
        Ok(Self { seed, public_key: hex_encode(pair.public_key().as_ref()) })
    }
}

impl AuthoritySigner for Ed25519SeedSigner {
    fn public_key(&self) -> &str {
        &self.public_key
    }

    fn sign(&self, payload: &[u8]) -> Result<String, ContractError> {
        let pair = signature::Ed25519KeyPair::from_seed_unchecked(&self.seed)
            .map_err(|_| ContractError::Crypto("invalid Ed25519 seed".into()))?;
        Ok(hex_encode(pair.sign(payload).as_ref()))
    }
}

/// A schema/domain-separated signed application record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecordV1<T> {
    pub schema: String,
    pub signer: String,
    pub payload: T,
    pub signature: String,
}

#[derive(Serialize)]
struct RecordPayload<'a, T> {
    schema: &'a str,
    signer: &'a str,
    payload: &'a T,
}

impl<T: Serialize> SignedRecordV1<T> {
    /// Sign `schema + signer + payload`; the signature field is never self-referential.
    pub fn sign(
        schema: impl Into<String>,
        payload: T,
        signer: &dyn AuthoritySigner,
    ) -> Result<Self, ContractError> {
        let schema = schema.into();
        let signer_id = signer.public_key().to_owned();
        let bytes = canonical_json_bytes(&RecordPayload {
            schema: &schema,
            signer: &signer_id,
            payload: &payload,
        })?;
        if bytes.len() > MAX_JOB_MESSAGE_BYTES {
            return Err(ContractError::Limit(format!(
                "signed record is {} bytes, exceeds {MAX_JOB_MESSAGE_BYTES}",
                bytes.len()
            )));
        }
        let signature = signer.sign(&bytes)?;
        Ok(Self { schema, signer: signer_id, payload, signature })
    }

    pub fn signing_payload(&self) -> Result<Vec<u8>, ContractError> {
        canonical_json_bytes(&RecordPayload {
            schema: &self.schema,
            signer: &self.signer,
            payload: &self.payload,
        })
    }

    pub fn verify(&self) -> bool {
        if self.signer.len() > MAX_PUBLIC_KEY_BYTES || self.signature.len() > MAX_SIGNATURE_BYTES {
            return false;
        }
        let Ok(public_key) = hex_decode(&self.signer) else {
            return false;
        };
        let Ok(signature) = hex_decode(&self.signature) else {
            return false;
        };
        let Ok(payload) = self.signing_payload() else {
            return false;
        };
        signature::UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&payload, &signature)
            .is_ok()
    }

    pub fn encoded_len(&self) -> Result<usize, ContractError> {
        canonical_json_bytes(self).map(|bytes| bytes.len())
    }
}

impl<T: Serialize + DeserializeOwned> SignedRecordV1<T> {
    pub fn parse(bytes: &[u8]) -> Result<Self, ContractError> {
        if bytes.len() > MAX_JOB_MESSAGE_BYTES {
            return Err(ContractError::Limit(format!(
                "signed record is {} bytes, exceeds {MAX_JOB_MESSAGE_BYTES}",
                bytes.len()
            )));
        }
        serde_json::from_slice(bytes)
            .map_err(|e| ContractError::Encoding(format!("invalid signed record JSON: {e}")))
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if !value.len().is_multiple_of(2) {
        return Err(());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let hi = hex_nibble(pair[0])?;
            let lo = hex_nibble(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_nibble(value: u8) -> Result<u8, ()> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(()),
    }
}
