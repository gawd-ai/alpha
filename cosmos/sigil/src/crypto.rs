//! Real ed25519 — the **mechanism** half of the permission primitive (R5), the production
//! implementation of [`StubVerifier`](crate::StubVerifier).
//!
//! Architectural placement matters: the verifier just answers *"is this signature valid for this
//! public key over this payload?"* It does **not** decide which keys are trust roots — that is
//! injected **policy** (the kernel's `Policy::admit` gets the verified/unverified evidence and
//! makes the call). Keeping the verifier root-blind preserves the fabric-not-model stance the
//! whole substrate is built on: the kernel ships a verify mechanism, not a model of trust.
//!
//! Keys + signatures are hex-encoded strings everywhere they touch the manifest / wire / config,
//! so they survive JSON, command-line args, and human eyeballs without any base64 / binary handling.

use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};

use crate::Verifier;

/// Hex-encode bytes (lowercase, no `0x` prefix). Inline rather than pulling a `hex` crate: this is
/// trivial code, and dependency hygiene matters when the workspace already has 17 members.
pub fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(TABLE[(b >> 4) as usize] as char);
        out.push(TABLE[(b & 0xf) as usize] as char);
    }
    out
}

/// Decode a hex string. **Never panics** on hostile input (R9): malformed chars / odd length →
/// `None`.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks_exact(2) {
        let hi = hex_nibble(chunk[0])?;
        let lo = hex_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// A `serde(with = ...)` adapter that encodes a byte buffer as a single lowercase-hex JSON string
/// instead of serde's default number-per-byte array. The default renders `Vec<u8>` as
/// `[123, 8, 7, …]` — 3–4 JSON bytes and one `Number` token per payload byte, so a multi-MB
/// artifact costs seconds of parse time and ~4× the wire; a hex string is one `String` token
/// (microseconds) at 2× the wire. The single home for the byte-field codec that registry ops and
/// build artifacts both need: point a `Vec<u8>` field at it with
/// `#[serde(with = "sigil::crypto::hex_bytes")]`. **Never panics** on hostile input (R9):
/// malformed hex deserializes to a structured error.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&super::hex_encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        super::hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex in byte field"))
    }
}

/// Generate a fresh 32-byte seed from the OS RNG. Pair it with
/// [`Ed25519KeyMaterial::from_seed`] to materialize an ed25519 keypair, or use it directly for
/// non-key randomness such as API tokens and verifiable-die commitments.
pub fn fresh_seed() -> Result<[u8; 32], String> {
    use ring::rand::SecureRandom;
    let rng = SystemRandom::new();
    let mut seed = [0u8; 32];
    // The OS RNG is the root of every key/token/commitment's secrecy. If it is ever unavailable we
    // must NOT silently proceed with the all-zero (publicly-known) seed.
    rng.fill(&mut seed)
        .map_err(|_| "OS RNG (ring::SystemRandom) unavailable for seed generation".to_string())?;
    Ok(seed)
}

/// An ed25519 keypair derived from a 32-byte seed. Held as the seed (not the unwrapped private
/// key) so the same value drives reproducible test fixtures *and* production keys — operators
/// generate a fresh seed once, persist it, and the rest of the workspace consumes it.
pub struct Ed25519KeyMaterial {
    seed: [u8; 32],
    public_hex: String,
}

impl Ed25519KeyMaterial {
    /// Build from a 32-byte seed. The keypair derivation is `Ed25519KeyPair::from_seed_unchecked`,
    /// which `ring` documents as safe given a random / cryptographically generated seed (we never
    /// derive from low-entropy input in this crate).
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, String> {
        let kp =
            Ed25519KeyPair::from_seed_unchecked(&seed).map_err(|e| format!("ed25519 seed: {e}"))?;
        let public_hex = hex_encode(kp.public_key().as_ref());
        Ok(Ed25519KeyMaterial { seed, public_hex })
    }

    /// Generate a fresh keypair from the OS RNG. Returns both the material and the seed so the
    /// caller can persist the seed to disk (a node-key file, an Abode-key file).
    pub fn generate() -> Result<(Self, [u8; 32]), String> {
        let seed = fresh_seed()?;
        Self::from_seed(seed).map(|m| (m, seed))
    }

    /// The hex-encoded public key — the form that travels in manifests and the wire.
    pub fn public_hex(&self) -> &str {
        &self.public_hex
    }

    /// The raw seed (for persistence — a node's keystore writes this to disk).
    pub fn seed(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Sign a payload. Returns the hex-encoded 64-byte ed25519 signature. Re-derives the keypair
    /// on each call rather than holding a non-`Send` `Ed25519KeyPair` — ed25519 sign is microsecond-
    /// cheap and this keeps the type trivially `Send + Sync` (cloneable inside an `Arc`).
    pub fn sign(&self, payload: &[u8]) -> String {
        let kp = Ed25519KeyPair::from_seed_unchecked(&self.seed)
            .expect("seed was validated at construction");
        hex_encode(kp.sign(payload).as_ref())
    }
}

impl Clone for Ed25519KeyMaterial {
    fn clone(&self) -> Self {
        Ed25519KeyMaterial { seed: self.seed, public_hex: self.public_hex.clone() }
    }
}

/// The real ed25519 verifier: hex public key + hex signature → boolean. **Root-blind**: deciding
/// which keys to trust is the injected policy's job (see [`crate::Verifier`] docs).
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(&self, public_key: &str, payload: &[u8], signature: &str) -> bool {
        // Cheap length gate *before* allocating any decode buffer: a 32-byte key is 64 hex chars,
        // a 64-byte signature is 128. This runs on every routed envelope, so refusing an oversized
        // hostile hex string here avoids allocating a large `Vec` only to reject it (R9).
        if public_key.len() != 64 || signature.len() != 128 {
            return false;
        }
        let Some(pk) = hex_decode(public_key) else {
            return false;
        };
        let Some(sig) = hex_decode(signature) else {
            return false;
        };
        // 32-byte pubkey + 64-byte signature are the only well-formed inputs; ring will reject
        // others, but checking ourselves keeps the error path predictable.
        if pk.len() != 32 || sig.len() != 64 {
            return false;
        }
        UnparsedPublicKey::new(&ED25519, &pk).verify(payload, &sig).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trip_handles_full_byte_range() {
        let bytes: Vec<u8> = (0u8..=255).collect();
        let hex = hex_encode(&bytes);
        assert_eq!(hex.len(), 512);
        assert_eq!(hex_decode(&hex), Some(bytes));
    }

    #[test]
    fn hex_decode_rejects_hostile_input_without_panic() {
        assert_eq!(hex_decode("xyz"), None); // bad chars
        assert_eq!(hex_decode("abc"), None); // odd length
        assert_eq!(hex_decode("zz"), None);
        assert_eq!(hex_decode(""), Some(Vec::new())); // empty is well-formed
    }

    #[test]
    fn ed25519_round_trip_signs_and_verifies() {
        let m = Ed25519KeyMaterial::from_seed([7u8; 32]).unwrap();
        let payload = b"the medium is the message";
        let sig = m.sign(payload);
        let v = Ed25519Verifier;
        assert!(v.verify(m.public_hex(), payload, &sig));
    }

    #[test]
    fn ed25519_rejects_mutation_of_the_payload() {
        let m = Ed25519KeyMaterial::from_seed([7u8; 32]).unwrap();
        let sig = m.sign(b"original");
        let v = Ed25519Verifier;
        assert!(!v.verify(m.public_hex(), b"tampered", &sig));
    }

    #[test]
    fn ed25519_rejects_a_different_signers_key() {
        let a = Ed25519KeyMaterial::from_seed([1u8; 32]).unwrap();
        let b = Ed25519KeyMaterial::from_seed([2u8; 32]).unwrap();
        let payload = b"x";
        let sig_by_a = a.sign(payload);
        // b's key cannot validate a's signature
        let v = Ed25519Verifier;
        assert!(!v.verify(b.public_hex(), payload, &sig_by_a));
        // and a's own key with b's signature also fails
        let sig_by_b = b.sign(payload);
        assert!(!v.verify(a.public_hex(), payload, &sig_by_b));
    }

    #[test]
    fn ed25519_rejects_malformed_inputs_without_panic() {
        let v = Ed25519Verifier;
        assert!(!v.verify("not-hex", b"x", "also-not-hex"));
        assert!(!v.verify("0000", b"x", "0000")); // wrong lengths
    }

    #[test]
    fn deterministic_seed_yields_deterministic_pubkey() {
        // The same seed must produce the same pubkey across runs — operators persist seeds and
        // expect identity stability. ed25519's spec guarantees this; this test pins the property.
        let m1 = Ed25519KeyMaterial::from_seed([42u8; 32]).unwrap();
        let m2 = Ed25519KeyMaterial::from_seed([42u8; 32]).unwrap();
        assert_eq!(m1.public_hex(), m2.public_hex());
        // and signing is also deterministic for ed25519 (no nonce required) — same payload, same sig
        assert_eq!(m1.sign(b"x"), m2.sign(b"x"));
    }
}
