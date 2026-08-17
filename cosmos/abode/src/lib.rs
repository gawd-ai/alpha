//! **Abode snapshot/restore shape.**
//!
//! An **Abode** is the distributed *self* — a signed identity + the state and learning
//! accumulated within that self's lifetime — driving operator-agents across some number of
//! Sanctum bodies. This crate ships *the shape* of how that self is carried between bodies,
//! consumed by [`creatures/abode-migrator`](../../creatures/abode-migrator)
//! along with the integrity + signing primitives the substrate guarantees regardless of which migrator
//! creature an operator binds. The reconciler consumes the same snapshot contract for fork/merge.
//!
//! ### What rides where
//!
//! - **[`AbodeSnapshot`]** is the *envelope payload*: identity, state hash, portable state bytes,
//!   the [`Requirements`] the receiving Sanctum must satisfy to
//!   safely restore, and an optional signature over the snapshot's [`signing_payload`](AbodeSnapshot::signing_payload).
//!   Identity (`abode_key`) is the Abode's authorship key — the *self* — kept distinct from a
//!   transport key.
//! - **[`AbodeRestore`]** is the *admission op*: a structured request to restore an Abode from a
//!   snapshot. The migrator runs three substrate-shipped gates BEFORE consulting its injected
//!   restore policy: [`assert_payload_size`](AbodeSnapshot::assert_payload_size) (fabric-integrity
//!   floor — R9 — a peer cannot blast arbitrarily large snapshots into the receiver's memory);
//!   [`assert_integrity`](AbodeSnapshot::assert_integrity) (state_hash recompute — a bit-flipped
//!   snapshot is rejected before policy ever runs); [`verify_signature`](AbodeSnapshot::verify_signature)
//!   (the signature, if present, must verify under `abode_key`). Only then does the migrator
//!   ask the operator's policy "do I trust this Abode key for this body?"
//!
//! ### What this module deliberately does NOT do
//!
//! - **No built-in CRDT.** Migration uses an acknowledged hand-off — the source migrator marks its
//!   Abode `Migrated { to }` after it receives the destination ack. Because the destination becomes
//!   authoritative before that ack returns, loss or crash can leave an authority-overlap window;
//!   this is not the fenced durable-Home protocol. The reconciler adds fork + merge by injecting a
//!   merge model; this crate still carries bytes, integrity, and signatures, never a state lattice.
//! - **No checkpoint scheduler.** When to take a snapshot is injected policy on top of these
//!   types, not fabric.
//! - **No snapshot durability.** Where a snapshot persists in between hops (registry, fs, network)
//!   is the migration creature's choice — the substrate ships the bytes, not the cabinet.
//!
//! ### Wire shape notes
//!
//! `signature` and `realm` are optional and skipped when absent, so the minimal snapshot encoding
//! stays compact. The
//! `signing_payload_hash_is_locked_to_a_known_fixture` tripwire exists so later code cannot silently
//! rearrange a field and invalidate signed snapshots.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::{Ed25519KeyMaterial, Requirements, Verifier};

use aether::RealmId;

/// Default ceiling for [`AbodeSnapshot::payload_bytes`] an admission gate accepts before
/// consulting the operator policy. Bounds the fabric-integrity floor (R9): a
/// peer cannot blast arbitrarily large snapshots into the receiver's memory just by knowing a
/// migrator's address. Operators raise (or lower) the ceiling at migrator construction; this is
/// the *default* the reference [`creatures/abode-migrator`](../../creatures/abode-migrator)
/// installs when no override is supplied.
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 8 * 1024 * 1024;

/// Structured failure modes for the substrate-shipped snapshot gates. Distinct from the migrator's
/// restore policy errors (which are operator-defined strings) because these refuse a snapshot
/// *before* any policy decision: the bytes don't add up, the signature doesn't verify, the payload
/// is over the ceiling. Each variant gives the receiving migrator a structured reason for the
/// audit log + the orchestrator's reply.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotError {
    /// `state_hash` did not match `sha256(payload_bytes)`. Either the payload was tampered in
    /// flight (the integrity check) or the producer set the wrong hash
    /// (a malformed snapshot). Receiver returns this *before* running the operator's policy.
    #[error("snapshot state_hash mismatch: declared {expected}, actual {actual}")]
    IntegrityMismatch { expected: String, actual: String },
    /// `payload_bytes.len()` exceeded the receiver's accepted ceiling. Defends R9 by bounding the
    /// payload the receiver will *admit and restore into state*. (The pre-deserialization memory
    /// bound — rejecting an oversize frame before it is even parsed — is the transport-level frame
    /// cap, `transport-tcp::MAX_FRAME_BYTES`; this gate is the semantic acceptance ceiling above
    /// it.) Operator raises the ceiling at migrator construction for genuinely large Abodes.
    #[error("snapshot payload {size} bytes exceeds receiver max {max} bytes")]
    PayloadTooLarge { size: usize, max: usize },
    /// A snapshot that the receiver requires to be signed arrived with `signature: None`. The
    /// reference hand-off migrator requires signatures by default; an operator who explicitly wants
    /// unsigned snapshots (a sealed test harness, a single-tenant lab) flips the flag at
    /// construction.
    #[error("snapshot signature required but absent")]
    SignatureMissing,
    /// `signature` was present but did not verify under `abode_key`. Either the key is wrong, the
    /// payload was tampered, or a different signer produced the signature. Indistinguishable
    /// at the cryptographic level by design (the verifier is root-blind).
    #[error("snapshot signature did not verify under abode_key")]
    SignatureInvalid,
}

/// A portable snapshot of an Abode's state, signed by the Abode's authorship key. Carries enough
/// for a receiving Sanctum to admit + restore the self into a new body (Sanctum), subject to that
/// Sanctum's injected admission policy.
///
/// **`payload_bytes` is opaque to the substrate** — the snapshotting Abode chooses its encoding
/// (CBOR, bincode, Cap'n Proto, an LLM context dump, …). The fabric ships the *envelope* and the
/// *integrity hash* (`state_hash`), never a state model. Consistent with the wider IoC discipline:
/// every model is injected, including how an Abode represents itself. The reference migrator
/// (`creatures/abode-migrator`) ships its own `SCHEMA_V0_3_MAGIC` 4-byte prefix convention so later
/// migrators can dispatch by version — but the substrate doesn't know about that prefix.
///
/// **Field order is part of the signed wire format.** [`signing_payload`](Self::signing_payload)
/// serializes the struct with the `signature` field cleared; serde_json emits struct fields in
/// declaration order. Appending new fields at the end is forward-compatible (older nodes ignore
/// unknown fields via `#[serde(default)]`). **Reordering or renaming an existing field
/// invalidates every previously-signed snapshot in flight.** The tripwire test in this module
/// locks the shape from day one (same discipline as `Manifest::signing_payload_hash_is_locked_to_a_known_fixture`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbodeSnapshot {
    /// The Abode's authorship public key (the *self*-identity), encoded same as
    /// [`Provenance::author`](sigil::Provenance::author). Distinct from any Sanctum's
    /// transport key.
    pub abode_key: String,
    /// `sha256:<hex>` over the canonical encoding of `payload_bytes`. The receiver re-derives and
    /// asserts before any restore — a bit-flipped snapshot is rejected before policy ever runs.
    /// Compute via [`compute_state_hash`](Self::compute_state_hash) to keep producer and verifier
    /// on the same formula.
    pub state_hash: String,
    /// The portable state bytes. Opaque to the substrate (see struct docs).
    #[serde(default)]
    pub payload_bytes: Vec<u8>,
    /// What the receiving Sanctum must offer for the restored Abode to function. The Distributor
    /// (or the migration creature itself) matches against the candidate Sanctum's *embodiment*
    /// (the advertised resources/sensors/accelerators a node offers — see
    /// `creatures/embodiment-advertiser`) at restore time. Same shape as
    /// [`Manifest::requirements`](sigil::Manifest::requirements) so the matching language
    /// is unified across creature load and Abode restore.
    #[serde(default)]
    pub requires: Requirements,
    /// Optional Realm the snapshot was authored in (mirrors the `Provenance.realm` field).
    /// Lets a receiving Sanctum's policy refuse Abodes from un-peered Realms before doing any
    /// hash/sig work; absent → no Realm assertion was made.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<RealmId>,
    /// Hex-encoded ed25519 signature over
    /// [`signing_payload`](Self::signing_payload), produced with the private key matching
    /// `abode_key`. The substrate verifies via [`verify_signature`](Self::verify_signature); the
    /// substrate never decides *which* `abode_key` values are trusted (that's the migrator's
    /// injected restore policy — IoC).
    ///
    /// `signature: None` is elided so intentionally unsigned snapshots stay compact. The reference
    /// hand-off migrator signs by default; a test harness that wants an explicitly unsigned snapshot
    /// flips the migrator's `require_signed_snapshots` flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl AbodeSnapshot {
    /// Construct a well-formed, integrity-valid (but UNSIGNED) snapshot from raw payload bytes.
    /// Computes `state_hash` from `payload_bytes` so [`assert_integrity`](Self::assert_integrity)
    /// passes; leaves `signature: None`, `requires: default`, `realm: None`. Pair with
    /// [`sign`](Self::sign) to produce a snapshot the reference hand-off migrator's default
    /// admission gate admits.
    pub fn new(abode_key: impl Into<String>, payload_bytes: Vec<u8>) -> Self {
        let state_hash = Self::compute_state_hash(&payload_bytes);
        AbodeSnapshot {
            abode_key: abode_key.into(),
            state_hash,
            payload_bytes,
            requires: Requirements::default(),
            realm: None,
            signature: None,
        }
    }

    /// Convenience: empty-state stub used by shape-proof tests. The
    /// `state_hash` is deliberately *not* the sha256 of the empty payload — so a stub fails
    /// [`assert_integrity`](Self::assert_integrity), which is correct (stubs aren't meant to pass
    /// the gate). Use [`new`](Self::new) to construct a snapshot integrity-valid for real
    /// migration.
    ///
    /// **Test-only:** gated behind `#[cfg(test)]` so this deliberately-invalid
    /// constructor never ships in `aether`'s public API. Real producers use [`new`](Self::new)
    /// (+ [`sign`](Self::sign)); the only callers are this crate's own shape-proof tests.
    #[cfg(test)]
    pub fn stub(abode_key: impl Into<String>) -> Self {
        AbodeSnapshot {
            abode_key: abode_key.into(),
            state_hash: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .into(),
            payload_bytes: Vec::new(),
            requires: Requirements::default(),
            realm: None,
            signature: None,
        }
    }

    /// Compute the `sha256:<hex>` state hash over raw payload bytes. The same formula the
    /// receiver runs in [`assert_integrity`](Self::assert_integrity). Pure function — no struct
    /// access — so a producer can hash before constructing the snapshot.
    pub fn compute_state_hash(payload_bytes: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(payload_bytes);
        format!("sha256:{:x}", h.finalize())
    }

    /// Canonical bytes a signature commits to: the snapshot with `signature` cleared. Same
    /// discipline as [`Manifest::signing_payload`](sigil::Manifest::signing_payload) — the
    /// volatile field is removed so the signature is over a stable encoding.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.signature = None;
        aether::wire::to_bytes(&clone)
    }

    /// Sign this snapshot in place using `key`. The caller is responsible for ensuring
    /// `self.abode_key == key.public_hex()` — admission verifies the signature against the
    /// snapshot's *declared* `abode_key`, so a mismatched signing key produces a snapshot that
    /// fails [`verify_signature`](Self::verify_signature). Overwrites any prior `signature`.
    pub fn sign(&mut self, key: &Ed25519KeyMaterial) {
        let sig = key.sign(&self.signing_payload());
        self.signature = Some(sig);
    }

    /// Verify the snapshot's signature against `abode_key`.
    ///
    /// - `Ok(())` — signature present and verified.
    /// - `Err(SignatureMissing)` — no signature on the snapshot (a strict migrator policy rejects
    ///   here; a permissive one may still accept and let its own policy decide).
    /// - `Err(SignatureInvalid)` — signature present but didn't verify (wrong signer / tampered
    ///   payload / malformed key).
    pub fn verify_signature(&self, verifier: &dyn Verifier) -> Result<(), SnapshotError> {
        let sig = self.signature.as_deref().ok_or(SnapshotError::SignatureMissing)?;
        if verifier.verify(&self.abode_key, &self.signing_payload(), sig) {
            Ok(())
        } else {
            Err(SnapshotError::SignatureInvalid)
        }
    }

    /// Assert this snapshot's `state_hash` matches `sha256(payload_bytes)`. Returns
    /// [`SnapshotError::IntegrityMismatch`] with both values on disagreement — the receiver
    /// includes both in the admission audit log so a producer can see what went wrong.
    pub fn assert_integrity(&self) -> Result<(), SnapshotError> {
        let actual = Self::compute_state_hash(&self.payload_bytes);
        if actual != self.state_hash {
            return Err(SnapshotError::IntegrityMismatch {
                expected: self.state_hash.clone(),
                actual,
            });
        }
        Ok(())
    }

    /// Reject the snapshot — before it is restored into state — if `payload_bytes` is larger than
    /// `max`. The fabric-integrity floor (R9): a peer cannot have a receiver admit an enormous
    /// snapshot just because it knows the migrator's address. (The bytes are already parsed by the
    /// time this runs; the pre-parse OOM bound is the transport frame cap. This is the acceptance
    /// ceiling, checked before any restore-into-state work.)
    pub fn assert_payload_size(&self, max: usize) -> Result<(), SnapshotError> {
        if self.payload_bytes.len() > max {
            return Err(SnapshotError::PayloadTooLarge { size: self.payload_bytes.len(), max });
        }
        Ok(())
    }
}

/// The admission op the receiver runs on an incoming [`AbodeSnapshot`].
/// [`creatures/abode-migrator`](../../creatures/abode-migrator)
/// builds these from an incoming `abode.restore_request` envelope and runs the substrate-shipped
/// gates ([`assert_payload_size`](AbodeSnapshot::assert_payload_size) →
/// [`assert_integrity`](AbodeSnapshot::assert_integrity) →
/// [`verify_signature`](AbodeSnapshot::verify_signature)) before consulting the operator's injected
/// restore policy.
///
/// **No methods at this grain** — it's pure data; the gates that consume it are on
/// [`AbodeSnapshot`] (substrate-owned: integrity/size/signature) and on the migrator's restore
/// policy trait (operator-owned: which Abode keys earn restore permission, does the body satisfy
/// `snapshot.requires`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbodeRestore {
    /// The snapshot to restore.
    pub snapshot: AbodeSnapshot,
    /// Optional human-readable reason / context the requester attached. Audited by admission's
    /// policy creature.
    #[serde(default)]
    pub note: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil::Ed25519Verifier;

    #[test]
    fn snapshot_round_trips_through_json_with_realm_none() {
        // `realm: None` skips serialization, so a snapshot authored by a Sanctum that doesn't
        // participate in any Realm uses the compact minimum shape.
        let s = AbodeSnapshot::stub("abode-public-key-hex");
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: AbodeSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
        // `realm: None` is elided from the wire — keeps the surface minimal for Sanctums that
        // haven't opted into a Realm.
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("realm"));
        // `signature: None` is also elided when a snapshot is intentionally unsigned (a sealed test
        // harness, an unsigned hand-off).
        assert!(!std::str::from_utf8(&bytes).unwrap().contains("signature"));
    }

    #[test]
    fn snapshot_round_trips_with_realm_set() {
        let mut s = AbodeSnapshot::stub("key");
        s.realm = Some(RealmId::new("crew-of-the-mary-celeste"));
        s.payload_bytes = b"compressed-state-blob".to_vec();
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: AbodeSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(s, back);
        assert!(std::str::from_utf8(&bytes).unwrap().contains("crew-of-the-mary-celeste"));
    }

    #[test]
    fn restore_op_round_trips_and_note_is_optional() {
        let r = AbodeRestore { snapshot: AbodeSnapshot::stub("k"), note: None };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: AbodeRestore = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r, back);
        let r = AbodeRestore {
            snapshot: AbodeSnapshot::stub("k"),
            note: Some("scheduled drain of node A".into()),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: AbodeRestore = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r, back);
    }

    // ---- integrity, size bound, signing, signing_payload tripwire ---------

    #[test]
    fn compute_state_hash_is_sha256_over_payload_bytes() {
        // The hash formula is part of the substrate's snapshot contract — producers and receivers
        // of this shape must agree.
        // Pin against a known sha256 fixture for "hello": well-published value, easy to verify
        // independently. Format is `sha256:<hex>`.
        let h = AbodeSnapshot::compute_state_hash(b"hello");
        assert_eq!(h, "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824");
    }

    #[test]
    fn new_produces_integrity_valid_snapshot() {
        let s = AbodeSnapshot::new("abode-key", b"state-blob".to_vec());
        assert!(
            s.assert_integrity().is_ok(),
            "new() must produce a snapshot that passes integrity"
        );
        assert_eq!(s.state_hash, AbodeSnapshot::compute_state_hash(b"state-blob"));
        assert!(s.signature.is_none(), "new() returns unsigned; caller signs with .sign(&key)");
    }

    #[test]
    fn assert_integrity_detects_tampered_payload() {
        let mut s = AbodeSnapshot::new("k", b"hello".to_vec());
        s.payload_bytes = b"hellp".to_vec(); // one-byte tamper
        let err = s.assert_integrity().unwrap_err();
        match err {
            SnapshotError::IntegrityMismatch { expected, actual } => {
                assert!(expected.starts_with("sha256:"));
                assert!(actual.starts_with("sha256:"));
                assert_ne!(expected, actual, "tamper must surface as a mismatch");
            }
            other => panic!("expected IntegrityMismatch, got {other:?}"),
        }
    }

    #[test]
    fn assert_integrity_passes_on_empty_payload() {
        // The trivial case: empty payload with the sha256-of-empty state_hash.
        let s = AbodeSnapshot::new("k", Vec::new());
        assert!(s.assert_integrity().is_ok());
    }

    #[test]
    fn assert_payload_size_rejects_oversized_and_admits_under_ceiling() {
        let s = AbodeSnapshot::new("k", vec![0u8; 1024]);
        assert!(s.assert_payload_size(2048).is_ok(), "1024 bytes under 2048 ceiling: admits");
        let err = s.assert_payload_size(512).unwrap_err();
        match err {
            SnapshotError::PayloadTooLarge { size, max } => {
                assert_eq!(size, 1024);
                assert_eq!(max, 512);
            }
            other => panic!("expected PayloadTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn sign_then_verify_round_trip_succeeds_under_matching_abode_key() {
        let key = Ed25519KeyMaterial::from_seed([0x99u8; 32]).unwrap();
        let mut s = AbodeSnapshot::new(key.public_hex().to_string(), b"the-self".to_vec());
        s.sign(&key);
        assert!(s.signature.is_some());
        let v = Ed25519Verifier;
        assert!(s.verify_signature(&v).is_ok());
    }

    #[test]
    fn verify_signature_detects_tampered_payload_after_signing() {
        let key = Ed25519KeyMaterial::from_seed([0x99u8; 32]).unwrap();
        let mut s = AbodeSnapshot::new(key.public_hex().to_string(), b"original".to_vec());
        s.sign(&key);
        // Re-derive state_hash so the integrity gate would actually pass, then verify the
        // signature catches the swap (the signature was over the *original* payload's bytes).
        s.payload_bytes = b"replaced".to_vec();
        s.state_hash = AbodeSnapshot::compute_state_hash(&s.payload_bytes);
        let v = Ed25519Verifier;
        let err = s.verify_signature(&v).unwrap_err();
        assert!(matches!(err, SnapshotError::SignatureInvalid));
    }

    #[test]
    fn verify_signature_fails_when_signature_absent() {
        let s = AbodeSnapshot::new("any-key", b"x".to_vec());
        let v = Ed25519Verifier;
        let err = s.verify_signature(&v).unwrap_err();
        assert!(matches!(err, SnapshotError::SignatureMissing));
    }

    #[test]
    fn verify_signature_fails_when_signed_by_a_different_key() {
        let signer = Ed25519KeyMaterial::from_seed([0x11u8; 32]).unwrap();
        let other = Ed25519KeyMaterial::from_seed([0x22u8; 32]).unwrap();
        // Snapshot declares `other`'s pubkey but is signed by `signer` — admission's
        // verify_under(abode_key) rejects because the signature doesn't validate under the
        // declared key.
        let mut s = AbodeSnapshot::new(other.public_hex().to_string(), b"x".to_vec());
        s.sign(&signer);
        let v = Ed25519Verifier;
        let err = s.verify_signature(&v).unwrap_err();
        assert!(matches!(err, SnapshotError::SignatureInvalid));
    }

    #[test]
    fn signing_payload_excludes_the_signature_field() {
        // The substrate's signing-payload contract: the signature must not be inside the bytes it
        // signs (else a snapshot can't be re-signed without changing the hash it commits to).
        let mut s = AbodeSnapshot::new("k", b"x".to_vec());
        let before = s.signing_payload();
        s.signature = Some("dummy-sig".into());
        assert_eq!(before, s.signing_payload(), "signature must not be part of its own payload");
    }

    /// **Determinism tripwire** for `AbodeSnapshot::signing_payload`. Sibling to the manifest
    /// and envelope tripwires. A future field added in the wrong place (or whose serialization
    /// isn't byte-stable — `HashMap`, float, anything) would silently break the ability to
    /// verify signed snapshots; this test fires the alarm before that lands.
    ///
    /// To update the fixture: when a NEW field is intentionally added at the end (forward-compat),
    /// re-run with `cargo test`, copy the new hash printed in the panic message, paste here. Any
    /// change in this hash means: every signed snapshot still in flight just became
    /// unverifiable. Treat as a wire break.
    #[test]
    fn signing_payload_hash_is_locked_to_a_known_fixture() {
        let mut s = AbodeSnapshot {
            abode_key: "abcdef0123456789".into(),
            state_hash: "sha256:cafebabe".into(),
            payload_bytes: b"the self".to_vec(),
            requires: Requirements::default(),
            realm: Some(RealmId::new("crew")),
            signature: Some("must-be-stripped".into()),
        };
        let mut h = Sha256::new();
        h.update(s.signing_payload());
        let hex = format!("{:x}", h.finalize());
        const EXPECTED: &str = "535a98002a7d1a8485684f074b19cfb6f5f1c72d1fff32e147c4f1de6edd7b5e";
        // Updating: if intentional, replace EXPECTED with the value reported below.
        assert_eq!(
            hex, EXPECTED,
            "AbodeSnapshot signing_payload tripwire fired; investigate field changes (a re-order, \
             rename, or non-deterministic encoding silently breaks every signed snapshot)",
        );
        // and the sig-stripping is idempotent — clearing again produces identical bytes.
        s.signature = None;
        let mut h2 = Sha256::new();
        h2.update(s.signing_payload());
        assert_eq!(format!("{:x}", h2.finalize()), EXPECTED);
    }
}
