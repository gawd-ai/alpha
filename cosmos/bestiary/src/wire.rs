//! The registry wire vocabulary — the op/reply enums, the catalog [`Entry`], the anti-entropy
//! [`SyncEntry`], and the two optional signals ([`ReputationScore`], [`QuarantineNotice`]).
//!
//! These were extracted out of the `registry-mem` creature so both the in-memory stub and the durable
//! `bestiary-daemon` can share one wire contract. Every impl moved with its type (Rust's orphan rule:
//! an impl on a type now foreign to `registry-mem` would be illegal there). `registry-mem` re-exports
//! the lot, so `registry_mem::RegistryOp` and friends keep resolving for every existing consumer.
//!
//! ## Naming: `artifact_hash`, not `content_address`
//!
//! The `artifact_hash` field carries `sha256(artifact_bytes)` hex — exactly the value
//! `provenance.build_hash` does. It is **distinct** from [`Manifest::content_address`], which is a hash
//! over the manifest's identity-shape (name + version + capabilities + …). Confusing the two would let
//! two different creatures with the same bytes but different manifests collide on "content address."
//! The Bestiary is content-addressed *by artifact bytes*; the receiver recomputes the hash and rejects
//! a bit-flip before any load.

use serde::{Deserialize, Serialize};
use sigil::{Manifest, Verifier};

use aether::RealmId;

/// Maximum bytes retained for short registry signal key fields (`artifact_hash`, `realm`).
///
/// Artifact bytes have their own much larger cap; this limit is for metadata-only signal paths so a
/// small quarantine/reputation op cannot retain a near-artifact-sized string.
pub const MAX_REGISTRY_SIGNAL_FIELD_BYTES: usize = 512;
/// Maximum audit-reason bytes retained in one quarantine marker.
pub const MAX_QUARANTINE_REASON_BYTES: usize = 1024;
/// Maximum number of peer ids retained in one quarantine marker.
pub const MAX_QUARANTINE_ATTESTING_PEERS: usize = 64;
/// Maximum bytes retained for one quarantine attesting-peer id.
pub const MAX_QUARANTINE_ATTESTING_PEER_BYTES: usize = 256;
/// Lowercase SHA-256 hex bytes in a registry artifact key.
pub const ARTIFACT_HASH_HEX_BYTES: usize = 64;

/// Validate an artifact hash before using it as a content-addressed registry key.
#[must_use]
pub fn artifact_hash_shape_error(artifact_hash: &str) -> Option<String> {
    if artifact_hash.len() != ARTIFACT_HASH_HEX_BYTES {
        return Some(format!(
            "artifact_hash must be {ARTIFACT_HASH_HEX_BYTES} lowercase hex bytes"
        ));
    }
    if !artifact_hash.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Some("artifact_hash must be lowercase hex".to_string());
    }
    None
}

/// One catalog row.
///
/// Beyond `manifest` + `artifact`, an entry carries two *optional* signals the federation
/// mechanism populates — neither changes how an entry is keyed or fetched, and both default to
/// `None`:
///
/// - `reputation` — an aggregated fitness signal attached by [`RegistryOp::AttestFitness`]
///   (written locally by the fitness-selector, or propagated cross-Realm by the
///   omega-federator). It is a *signal an admission policy may consult*, never a gate the
///   substrate enforces (T7 / IoC).
/// - `quarantine` — a reversible defense marker attached by [`RegistryOp::MarkQuarantine`]
///   (the immune-response, or a cross-Realm `QuarantineNotice`). **Reversible by design**
///   (T5): a re-publish of the same `(realm, artifact_hash)` clears it on the in-memory stub (the
///   durable store makes quarantine sticky across federation — see the `store` module). Admission
///   reads it; the substrate enforces nothing.
#[derive(Clone, Debug)]
pub struct Entry {
    pub manifest: Manifest,
    pub artifact: Vec<u8>,
    /// Aggregated fitness/reputation signal; `None` until attested.
    pub reputation: Option<ReputationScore>,
    /// Reversible quarantine marker; `None` unless flagged.
    pub quarantine: Option<QuarantineNotice>,
}

/// A byte-light catalog row for operator/control listing. It carries the same identity and signals
/// as [`SyncEntry`] but deliberately omits artifact bytes; federation pulls still use
/// [`SyncEntry`] so anti-entropy remains self-contained.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CatalogEntry {
    pub artifact_hash: String,
    pub realm: RealmId,
    pub manifest: Manifest,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<ReputationScore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<QuarantineNotice>,
}

/// An aggregated fitness/reputation signal on an artifact. A *signal*, not a gate —
/// admission policy decides how much to credit it; the substrate enforces nothing (T7 / IoC). The
/// `attesting_realm` records which Realm's observation produced this score, so a receiver can apply
/// its own weight model to a peer's attestation (the weight model is injected — see
/// `cosmos/creatures/prototypes/reputation/reputation-roundrobin`).
///
/// **Optional promotion signature.** When `fitness-selector` promotes a creature
/// it crossed an injected threshold, it signs the *promotion claim* (`artifact_hash` + `realm` +
/// `score` + `attesting_realm`) with its Abode key and stamps `signed_by` (the pubkey) + `signature`
/// here. This makes a stored fitness score **self-verifying** — an admission policy
/// (`cosmos/creatures/prototypes/policies/policy-prefer-promoted`) re-derives the claim from the entry key + score and checks
/// the signature, so it credits only promotions whose provenance it can prove (the Baldwin effect
/// made heritable: a learned score travels as a signed, checkable fact). Both fields are
/// `None` for an *unsigned* score: a purely local attestation a test wrote, or a **peer reputation**
/// forwarded over SEER (which carries `attesting_realm` as its provenance instead — the observer
/// signed the *delta*, a different payload, verified at ingest by `omega-federator`). The
/// signature is **optional and elides from the wire when `None`**, so peer-reputation bytes
/// are unchanged.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReputationScore {
    /// The score itself. Range is the injected criterion's business (the bundled scorers work in
    /// `[0.0, 1.0]`); the registry stores whatever it's told.
    pub score: f32,
    /// The Realm whose observation produced this score. `None` for a purely local attestation
    /// (no federation provenance). The propagation test asserts this is tagged on receipt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attesting_realm: Option<RealmId>,
    /// The Abode pubkey (hex) that signed this promotion; `None` = unsigned score.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signed_by: Option<String>,
    /// ed25519 signature over [`ReputationScore::promotion_payload`]; `None` = unsigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ReputationScore {
    /// An unsigned score — peer reputation / a test attestation. A two-field literal that keeps
    /// call sites terse without `..Default`.
    pub fn unsigned(score: f32, attesting_realm: Option<RealmId>) -> Self {
        ReputationScore { score, attesting_realm, signed_by: None, signature: None }
    }

    /// Validate a complete `AttestFitness` signal before a registry filling retains or persists it.
    ///
    /// This is a shape/pressure guard only. It does not decide whether a signer is trusted, nor does
    /// it alter [`promotion_payload`](Self::promotion_payload); admission policy owns trust roots.
    pub fn attest_shape_error(&self, artifact_hash: &str, realm: &RealmId) -> Option<String> {
        if artifact_hash.len() > MAX_REGISTRY_SIGNAL_FIELD_BYTES {
            return Some(format!(
                "reputation artifact_hash too large: {} bytes exceeds {} byte limit",
                artifact_hash.len(),
                MAX_REGISTRY_SIGNAL_FIELD_BYTES
            ));
        }
        if artifact_hash.contains('\0') {
            return Some("reputation artifact_hash contains NUL byte".to_string());
        }
        if !realm.is_valid() || realm.0.contains('\0') {
            return Some("reputation realm is not a valid RealmId".to_string());
        }
        if realm.0.len() > MAX_REGISTRY_SIGNAL_FIELD_BYTES {
            return Some(format!(
                "reputation realm too large: {} bytes exceeds {} byte limit",
                realm.0.len(),
                MAX_REGISTRY_SIGNAL_FIELD_BYTES
            ));
        }
        if !self.score.is_finite() {
            return Some("reputation score is non-finite".to_string());
        }
        if let Some(attesting_realm) = &self.attesting_realm {
            if !attesting_realm.is_valid() || attesting_realm.0.contains('\0') {
                return Some("reputation attesting_realm is not a valid RealmId".to_string());
            }
            if attesting_realm.0.len() > MAX_REGISTRY_SIGNAL_FIELD_BYTES {
                return Some(format!(
                    "reputation attesting_realm too large: {} bytes exceeds {} byte limit",
                    attesting_realm.0.len(),
                    MAX_REGISTRY_SIGNAL_FIELD_BYTES
                ));
            }
        }
        match (&self.signed_by, &self.signature) {
            (None, None) => None,
            (Some(key), Some(sig)) => signed_promotion_field_shape_error("signed_by", key)
                .or_else(|| signed_promotion_field_shape_error("signature", sig)),
            _ => Some(
                "reputation promotion signature fields must be both present or both absent"
                    .to_string(),
            ),
        }
    }

    /// The canonical bytes a promotion signature commits to: the `(artifact_hash, realm, score,
    /// attesting_realm)` claim, *excluding* the signature/signer themselves (which aren't part of
    /// what's being attested). Binding `artifact_hash` + `realm` stops a signature from being
    /// replayed onto a different entry. The shared contract between the signer (the
    /// fitness-selector) and the verifier (the prefer-promoted admission policy) — both call this so
    /// the bytes are identical on each side. Deterministic: every field is a String / f32 / Option,
    /// serialized through serde_json (ryu for the float — byte-stable, the same property the
    /// manifest signing-payload tripwire relies on).
    pub fn promotion_payload(
        artifact_hash: &str,
        realm: &RealmId,
        score: f32,
        attesting_realm: Option<&RealmId>,
    ) -> Vec<u8> {
        // A tuple of borrowed primitives — no struct definition needed, order is the wire order.
        aether::wire::to_bytes(&(artifact_hash, realm, score, attesting_realm))
    }

    /// Whether this score carries a promotion signature that verifies under `signed_by` for the
    /// given `(artifact_hash, realm)` key. `None` signer/signature → `false` (an unsigned score is
    /// not a *verified* promotion; an admission policy that requires provenance treats it as
    /// un-promoted). The verifier is the injected mechanism (`Ed25519Verifier` in production); the
    /// registry owns the *payload shape*, never *which key to trust* (that's the policy — IoC).
    pub fn promotion_verifies(
        &self,
        artifact_hash: &str,
        realm: &RealmId,
        verifier: &dyn Verifier,
    ) -> bool {
        match (&self.signed_by, &self.signature) {
            (Some(key), Some(sig)) => verifier.verify(
                key,
                &Self::promotion_payload(
                    artifact_hash,
                    realm,
                    self.score,
                    self.attesting_realm.as_ref(),
                ),
                sig,
            ),
            _ => false,
        }
    }
}

fn signed_promotion_field_shape_error(field: &str, value: &str) -> Option<String> {
    if value.is_empty() {
        return Some(format!("reputation {field} is empty"));
    }
    if value.len() > MAX_REGISTRY_SIGNAL_FIELD_BYTES {
        return Some(format!(
            "reputation {field} too large: {} bytes exceeds {} byte limit",
            value.len(),
            MAX_REGISTRY_SIGNAL_FIELD_BYTES
        ));
    }
    if value.contains('\0') {
        return Some(format!("reputation {field} contains NUL byte"));
    }
    None
}

/// A reversible quarantine marker (the immune-response is the responder). **T5: reversible** —
/// a re-publish of the same `(realm, artifact_hash)` clears it on the in-memory stub. The substrate
/// never permanently blacklists; that's a policy decision (IoC). Admission may refuse a quarantined
/// entry; the substrate stores the marker and enforces nothing on its own.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct QuarantineNotice {
    /// Structured reason an admission policy / operator can audit.
    pub reason: String,
    /// The peers (node or Realm ids, operator's vocabulary) that attested this quarantine. A
    /// weight model decides whether the set is trustworthy enough to honor.
    #[serde(default)]
    pub attesting_peers: Vec<String>,
}

impl QuarantineNotice {
    /// Validate a complete `MarkQuarantine` signal before any registry filling retains or persists
    /// it. This is a shape/pressure guard only; trust and weighting remain injected policy.
    pub fn mark_shape_error(
        artifact_hash: &str,
        realm: &RealmId,
        reason: &str,
        attesting_peers: &[String],
    ) -> Option<String> {
        if artifact_hash.len() > MAX_REGISTRY_SIGNAL_FIELD_BYTES {
            return Some(format!(
                "quarantine artifact_hash too large: {} bytes exceeds {} byte limit",
                artifact_hash.len(),
                MAX_REGISTRY_SIGNAL_FIELD_BYTES
            ));
        }
        if artifact_hash.contains('\0') {
            return Some("quarantine artifact_hash contains NUL byte".to_string());
        }
        if !realm.is_valid() || realm.0.contains('\0') {
            return Some("quarantine realm is not a valid RealmId".to_string());
        }
        if realm.0.len() > MAX_REGISTRY_SIGNAL_FIELD_BYTES {
            return Some(format!(
                "quarantine realm too large: {} bytes exceeds {} byte limit",
                realm.0.len(),
                MAX_REGISTRY_SIGNAL_FIELD_BYTES
            ));
        }
        Self::notice_shape_error(reason, attesting_peers)
    }

    /// Validate the marker body independent of the registry key.
    pub fn shape_error(&self) -> Option<String> {
        Self::notice_shape_error(&self.reason, &self.attesting_peers)
    }

    fn notice_shape_error(reason: &str, attesting_peers: &[String]) -> Option<String> {
        if reason.len() > MAX_QUARANTINE_REASON_BYTES {
            return Some(format!(
                "quarantine reason too large: {} bytes exceeds {} byte limit",
                reason.len(),
                MAX_QUARANTINE_REASON_BYTES
            ));
        }
        if reason.contains('\0') {
            return Some("quarantine reason contains NUL byte".to_string());
        }
        if attesting_peers.len() > MAX_QUARANTINE_ATTESTING_PEERS {
            return Some(format!(
                "quarantine attesting_peers too large: {} peers exceeds {} peer limit",
                attesting_peers.len(),
                MAX_QUARANTINE_ATTESTING_PEERS
            ));
        }
        for peer in attesting_peers {
            if peer.contains('\0') {
                return Some("quarantine attesting_peer contains NUL byte".to_string());
            }
            if peer.len() > MAX_QUARANTINE_ATTESTING_PEER_BYTES {
                return Some(format!(
                    "quarantine attesting_peer too large: {} bytes exceeds {} byte limit",
                    peer.len(),
                    MAX_QUARANTINE_ATTESTING_PEER_BYTES
                ));
            }
        }
        None
    }
}

/// A self-contained entry digest for anti-entropy pull. Carries everything a peer
/// federator needs to merge the entry into its own registry without a follow-up fetch: the key
/// `(realm, artifact_hash)`, the full manifest + artifact bytes (admission re-verifies on load —
/// T2), and the two optional signals. The federator that pulls these re-publishes each via the
/// [`RegistryOp::Publish`] write path (with `realm: Some(..)`), so the registry keeps one ingestion
/// path.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SyncEntry {
    pub artifact_hash: String,
    pub realm: RealmId,
    pub manifest: Manifest,
    #[serde(with = "sigil::crypto::hex_bytes")]
    pub artifact: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reputation: Option<ReputationScore>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quarantine: Option<QuarantineNotice>,
}

/// What a caller asks the registry to do. Envelope payload = `serde_json::to_vec(&RegistryOp)`.
///
/// ### Realm grain
///
/// The full-artifact ops (`Publish` / `Fetch` / `FetchMetadata`) carry an optional
/// `realm: Option<RealmId>`: `None` — the field elides from the wire — operates in
/// [`RealmId::local()`]; `Some(r)` scopes to a named Realm. The store keys by
/// `(realm, artifact_hash)`, so identical bytes in two Realms are two distinct entries that never
/// collide.
///
/// The GX bulk-transfer ops keep their explicit `*InRealm` split (a separate, parallel-owned
/// shape); only these small full-artifact ops fold the Realm into one optional field.
// `Publish` carries a full `Manifest` (~½ KiB) while every other variant is small; collapsing the
// old `PublishInRealm` twin (0.4.1) left it the sole large variant. This is a deserialize-target wire
// enum — it is decoded into owned values, never copied by value on a hot path — so the size delta is
// not worth boxing the manifest through every publish handler.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RegistryOp {
    /// Publish an artifact + manifest. `realm: None` (the field elides from the wire) treats the
    /// entry as living in [`RealmId::local()`]; `Some(r)` scopes it to a named Realm.
    Publish {
        manifest: Manifest,
        #[serde(with = "sigil::crypto::hex_bytes")]
        artifact: Vec<u8>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        realm: Option<RealmId>,
    },
    /// Fetch an artifact by content-address key. `realm: None` looks in [`RealmId::local()`];
    /// `Some(r)` looks in that Realm and returns [`RegistryReply::NotFound`] if the
    /// `(realm, artifact_hash)` key is absent, even if the same hash exists in another Realm.
    Fetch {
        /// `sha256(artifact_bytes)` hex — the registry's content-address key. Equals
        /// `provenance.build_hash` for a signed manifest. **Not the same** as
        /// [`Manifest::content_address`](sigil::Manifest::content_address); see this
        /// module's docs.
        artifact_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        realm: Option<RealmId>,
    },
    /// Looks in [`RealmId::local()`] and returns a GX transfer plan plus manifest, then streams the
    /// artifact as raw `gx.chunk` frames on the transport chunk lane.
    FetchGx {
        /// `sha256(artifact_bytes)` hex — the registry's content-address key.
        artifact_hash: String,
        /// Requested GX chunk size. `None` lets the registry use the shared default. Implementations
        /// may clamp this to their artifact-shipping bounds before returning the transfer plan.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u32>,
    },
    /// Looks in [`RealmId::local()`] and returns only the GX transfer plan plus manifest. The caller
    /// then pulls individual chunks with [`FetchGxChunk`](Self::FetchGxChunk), which enables
    /// backpressure and resume without inventing another artifact transfer wire.
    FetchGxPlan {
        /// `sha256(artifact_bytes)` hex — the registry's content-address key.
        artifact_hash: String,
        /// Requested GX chunk size. `None` lets the registry use the shared default. Implementations
        /// may clamp this to their artifact-shipping bounds before returning the transfer plan.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u32>,
    },
    /// Pull one GX chunk from a prior transfer plan. Successful replies are raw
    /// `transport.gx.chunk` dispatches addressed to the requester; errors use
    /// [`RegistryReply::Error`] or [`RegistryReply::NotFound`].
    FetchGxChunk {
        /// `sha256(artifact_bytes)` hex — the registry's content-address key.
        artifact_hash: String,
        /// Transfer id returned by [`FetchGxPlan`](Self::FetchGxPlan) or
        /// [`FetchGx`](Self::FetchGx). It is echoed into the raw GX chunk frame.
        transfer_id: String,
        /// Chunk size returned by the plan. Implementations clamp this through the same GX bounds
        /// they used for the plan.
        chunk_size: u32,
        /// Zero-based chunk index to send.
        chunk_index: u32,
    },
    /// Return only catalog metadata plus artifact length — never artifact bytes; the control/operator
    /// lookup path. `realm: None` looks in [`RealmId::local()`]; `Some(r)` scopes to that Realm.
    FetchMetadata {
        /// `sha256(artifact_bytes)` hex — the registry's content-address key.
        artifact_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        realm: Option<RealmId>,
    },
    /// Realm-explicit GX fetch. See [`FetchGx`](Self::FetchGx).
    FetchGxInRealm {
        artifact_hash: String,
        realm: RealmId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u32>,
    },
    /// Realm-explicit plan-only GX fetch. See [`FetchGxPlan`](Self::FetchGxPlan).
    FetchGxPlanInRealm {
        artifact_hash: String,
        realm: RealmId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        chunk_size: Option<u32>,
    },
    /// Realm-explicit single-chunk GX pull. See [`FetchGxChunk`](Self::FetchGxChunk).
    FetchGxChunkInRealm {
        artifact_hash: String,
        realm: RealmId,
        transfer_id: String,
        chunk_size: u32,
        chunk_index: u32,
    },
    /// Attach/replace a reputation score on an existing `(realm, artifact_hash)`
    /// entry. Reply: [`RegistryReply::Attested`] on success, [`RegistryReply::NotFound`] if the
    /// entry is absent (attest the artifact you hold; the federator publishes first, then attests).
    AttestFitness {
        artifact_hash: String,
        realm: RealmId,
        score: f32,
        /// The Realm whose observation produced the score (federation provenance). Echoed onto
        /// the stored [`ReputationScore`] so a receiver can weight a peer's attestation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        attesting_realm: Option<RealmId>,
        /// Abode pubkey (hex) of a *signed promotion*; `None` for an unsigned score
        /// (peer reputation, test attestation). Elides from the wire when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signed_by: Option<String>,
        /// ed25519 signature over the promotion claim (see
        /// [`ReputationScore::promotion_payload`]); `None` for an unsigned score.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    /// Mark an existing entry quarantined (reversible — T5). Reply:
    /// [`RegistryReply::Quarantined`] on success, [`RegistryReply::NotFound`] if absent.
    MarkQuarantine {
        artifact_hash: String,
        realm: RealmId,
        reason: String,
        #[serde(default)]
        attesting_peers: Vec<String>,
    },
    /// Read-only snapshot of catalog entries for anti-entropy pull. `realm: None`
    /// returns every Realm; `Some(r)` scopes to one. Reply: [`RegistryReply::Entries`].
    ListEntries {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        realm: Option<RealmId>,
    },
    /// Read-only byte-light catalog metadata for operator/control listing. Unlike
    /// [`ListEntries`](Self::ListEntries), this does not carry artifact bytes and is not sufficient
    /// for anti-entropy merge. Reply: [`RegistryReply::Metadata`].
    ListMetadata {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        realm: Option<RealmId>,
    },
}

/// What the registry sends back. Envelope payload = `serde_json::to_vec(&RegistryReply)`.
///
/// `Published` / `Fetched` always echo the resolved `realm` — the concrete Realm the op landed in
/// ([`RealmId::local()`] when the op omitted it) — so a caller can confirm which catalog was
/// touched. Metadata fetch uses [`RegistryReply::FetchedMetadata`], whose embedded
/// [`CatalogEntry`] carries the resolved Realm.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum RegistryReply {
    /// Reply to [`RegistryOp::Publish`] — echoes the resolved Realm the entry landed in.
    Published {
        /// The artifact-bytes hash (`sha256(artifact)` hex) the registry indexed this entry under.
        /// See the field docs on [`RegistryOp::Fetch`] for the naming rationale.
        artifact_hash: String,
        realm: RealmId,
    },
    /// Reply to [`RegistryOp::Fetch`] — echoes the resolved Realm the entry was read from.
    Fetched {
        manifest: Manifest,
        #[serde(with = "sigil::crypto::hex_bytes")]
        artifact: Vec<u8>,
        realm: RealmId,
    },
    /// Reply to [`RegistryOp::FetchGx`] / [`RegistryOp::FetchGxPlan`]. Carries the manifest and
    /// transfer plan. `FetchGx` compatibility streams chunks after this reply; `FetchGxPlan`
    /// leaves chunk pacing to [`RegistryOp::FetchGxChunk`].
    FetchedGx {
        manifest: Manifest,
        artifact_hash: String,
        transfer_id: String,
        file_size: u64,
        file_hash: String,
        chunk_size: u32,
        total_chunks: u32,
    },
    /// Reply to [`RegistryOp::FetchGxInRealm`] / [`RegistryOp::FetchGxPlanInRealm`].
    FetchedGxInRealm {
        manifest: Manifest,
        artifact_hash: String,
        transfer_id: String,
        file_size: u64,
        file_hash: String,
        chunk_size: u32,
        total_chunks: u32,
        realm: RealmId,
    },
    /// Reply to [`RegistryOp::FetchMetadata`] (Realm-implicit or `realm: Some(..)`).
    FetchedMetadata {
        entry: CatalogEntry,
        artifact_len: usize,
    },
    /// Reply to [`RegistryOp::AttestFitness`] — echoes the key the score landed on.
    Attested {
        artifact_hash: String,
        realm: RealmId,
    },
    /// Reply to [`RegistryOp::MarkQuarantine`].
    Quarantined {
        artifact_hash: String,
        realm: RealmId,
    },
    /// Reply to [`RegistryOp::ListEntries`] — the catalog snapshot the puller merges.
    Entries {
        entries: Vec<SyncEntry>,
    },
    /// Reply to [`RegistryOp::ListMetadata`] — a byte-light catalog snapshot for control surfaces.
    Metadata {
        entries: Vec<CatalogEntry>,
    },
    NotFound,
    Error {
        message: String,
    },
}

impl RegistryOp {
    /// The canonical wire form of a registry operation. The creatures that emit registry RPCs
    /// (fitness-selector, immune-response, omega-federator) serialize through this rather than
    /// each re-deriving the byte form, so the op encoding has a single owner.
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

impl RegistryReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil::{Backend, Ed25519KeyMaterial, Ed25519Verifier};

    fn manifest(name: &str) -> Manifest {
        Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
    }

    /// **Signed promotion round-trip.** The promotion claim `(artifact_hash, realm, score,
    /// attesting_realm)` verifies under the signer's key for the SAME entry key, and rejects a replay
    /// onto a different artifact / realm / score — the contract `policy-prefer-promoted` checks. This
    /// test owns the wire type, so it lives with the type, not in `registry-mem`.
    #[test]
    fn signed_promotion_score_verifies_for_its_entry_and_rejects_replay() {
        let key = Ed25519KeyMaterial::from_seed([0x5A; 32]).unwrap();
        let pk = key.public_hex().to_string();
        let realm = RealmId::new("crew");
        let hash = "promoted-artifact-hash";
        let score = 0.95f32;
        let attesting = Some(RealmId::new("crew"));

        let sig =
            key.sign(&ReputationScore::promotion_payload(hash, &realm, score, attesting.as_ref()));
        let rep = ReputationScore {
            score,
            attesting_realm: attesting.clone(),
            signed_by: Some(pk),
            signature: Some(sig),
        };
        let v = Ed25519Verifier;
        assert!(rep.promotion_verifies(hash, &realm, &v), "verifies for its own entry");
        assert!(
            !rep.promotion_verifies("other-hash", &realm, &v),
            "replay onto another artifact fails"
        );
        assert!(
            !rep.promotion_verifies(hash, &RealmId::new("guests"), &v),
            "replay into another realm fails"
        );
        let mut tampered = rep.clone();
        tampered.score = 0.10;
        assert!(!tampered.promotion_verifies(hash, &realm, &v), "tampered score fails");
        assert!(!ReputationScore::unsigned(0.95, attesting).promotion_verifies(hash, &realm, &v));
    }

    #[test]
    fn artifact_hash_shape_validator_requires_lowercase_sha256_hex() {
        assert!(artifact_hash_shape_error(&"a".repeat(ARTIFACT_HASH_HEX_BYTES)).is_none());
        let err = artifact_hash_shape_error("abc").expect("short hash rejected");
        assert!(err.contains("64 lowercase hex"));
        let err =
            artifact_hash_shape_error(&"A".repeat(ARTIFACT_HASH_HEX_BYTES)).expect("case rejected");
        assert!(err.contains("lowercase hex"));
        let err = artifact_hash_shape_error("../escape").expect("path-like hash rejected");
        assert!(err.contains("64 lowercase hex"));
    }

    #[test]
    fn reputation_score_shape_validator_caps_signal_fields() {
        let rep = ReputationScore::unsigned(0.95, Some(RealmId::new("crew")));
        assert!(rep.attest_shape_error("h", &RealmId::new("crew")).is_none());

        let err = rep
            .attest_shape_error(
                &"h".repeat(MAX_REGISTRY_SIGNAL_FIELD_BYTES + 1),
                &RealmId::new("crew"),
            )
            .expect("oversized key rejected");
        assert!(err.contains("artifact_hash too large"));

        let err =
            rep.attest_shape_error("bad\0hash", &RealmId::new("crew")).expect("NUL key rejected");
        assert!(err.contains("artifact_hash contains NUL"));

        let err = rep
            .attest_shape_error("h", &RealmId::new("bad:realm"))
            .expect("invalid realm rejected");
        assert!(err.contains("realm is not a valid RealmId"));

        let err = ReputationScore::unsigned(f32::INFINITY, None)
            .attest_shape_error("h", &RealmId::new("crew"))
            .expect("non-finite score rejected");
        assert!(err.contains("non-finite"));

        let err = ReputationScore::unsigned(0.95, Some(RealmId::new("bad:realm")))
            .attest_shape_error("h", &RealmId::new("crew"))
            .expect("invalid attesting realm rejected");
        assert!(err.contains("attesting_realm"));

        let half_signed = ReputationScore {
            score: 0.95,
            attesting_realm: None,
            signed_by: Some("selector".into()),
            signature: None,
        };
        let err = half_signed
            .attest_shape_error("h", &RealmId::new("crew"))
            .expect("half-signed promotion rejected");
        assert!(err.contains("both present or both absent"));

        let bad_signed = ReputationScore {
            score: 0.95,
            attesting_realm: None,
            signed_by: Some("selector\0".into()),
            signature: Some("sig".into()),
        };
        let err = bad_signed
            .attest_shape_error("h", &RealmId::new("crew"))
            .expect("NUL signed_by rejected");
        assert!(err.contains("signed_by contains NUL"));
    }

    /// **Collapsed Realm grain + optional-field elision are locked.** The full-artifact ops carry
    /// one optional `realm` under a single stable `"op"` tag (the `*_in_realm` tags are gone in
    /// 0.4.1 — deliberately breaking): `None` elides the field, `Some(r)` adds it. The optional
    /// promotion-signature fields elide when `None`, so an unsigned `AttestFitness` carries no
    /// signature bytes.
    #[test]
    fn op_wire_tags_are_stable_and_optional_fields_elide() {
        let publish =
            RegistryOp::Publish { manifest: manifest("c"), artifact: b"a".to_vec(), realm: None };
        let json = serde_json::to_string(&publish).unwrap();
        assert!(json.contains("\"op\":\"publish\""));
        assert!(!json.contains("\"realm\""), "realm-less publish elides the Realm field");

        let in_realm = RegistryOp::Publish {
            manifest: manifest("c"),
            artifact: b"a".to_vec(),
            realm: Some(RealmId::new("crew")),
        };
        let json = serde_json::to_string(&in_realm).unwrap();
        assert!(
            json.contains("\"op\":\"publish\""),
            "realm-scoped publish keeps the 'publish' tag"
        );
        assert!(json.contains("\"realm\":\"crew\""));
        assert!(!json.contains("publish_in_realm"), "the split *_in_realm tag is gone");

        let attest = RegistryOp::AttestFitness {
            artifact_hash: "h".into(),
            realm: RealmId::new("crew"),
            score: 0.5,
            attesting_realm: None,
            signed_by: None,
            signature: None,
        };
        let json = serde_json::to_string(&attest).unwrap();
        assert!(json.contains("\"op\":\"attest_fitness\""));
        assert!(!json.contains("attesting_realm"), "None attesting_realm elides");
        assert!(!json.contains("signed_by"), "None signed_by elides");
        assert!(!json.contains("signature"), "None signature elides");

        let metadata = RegistryOp::ListMetadata { realm: Some(RealmId::new("crew")) };
        let json = serde_json::to_string(&metadata).unwrap();
        assert!(json.contains("\"op\":\"list_metadata\""));
        assert!(json.contains("\"realm\":\"crew\""));

        let fetch_metadata = RegistryOp::FetchMetadata { artifact_hash: "h".into(), realm: None };
        let json = serde_json::to_string(&fetch_metadata).unwrap();
        assert!(json.contains("\"op\":\"fetch_metadata\""));
        assert!(!json.contains("\"realm\""), "realm-less metadata fetch elides the Realm field");

        let fetch_metadata_in_realm = RegistryOp::FetchMetadata {
            artifact_hash: "h".into(),
            realm: Some(RealmId::new("crew")),
        };
        let json = serde_json::to_string(&fetch_metadata_in_realm).unwrap();
        assert!(json.contains("\"op\":\"fetch_metadata\""), "realm-scoped fetch keeps the tag");
        assert!(json.contains("\"realm\":\"crew\""));
        assert!(!json.contains("fetch_metadata_in_realm"), "the split *_in_realm tag is gone");

        let fetch_gx = RegistryOp::FetchGx { artifact_hash: "h".into(), chunk_size: None };
        let json = serde_json::to_string(&fetch_gx).unwrap();
        assert!(json.contains("\"op\":\"fetch_gx\""));
        assert!(!json.contains("chunk_size"), "None chunk_size elides");

        let fetch_gx_plan = RegistryOp::FetchGxPlan { artifact_hash: "h".into(), chunk_size: None };
        let json = serde_json::to_string(&fetch_gx_plan).unwrap();
        assert!(json.contains("\"op\":\"fetch_gx_plan\""));
        assert!(!json.contains("chunk_size"), "None chunk_size elides");

        let fetch_gx_chunk = RegistryOp::FetchGxChunk {
            artifact_hash: "h".into(),
            transfer_id: "registry.h.1.2".into(),
            chunk_size: 1024,
            chunk_index: 3,
        };
        let json = serde_json::to_string(&fetch_gx_chunk).unwrap();
        assert!(json.contains("\"op\":\"fetch_gx_chunk\""));
        assert!(json.contains("\"transfer_id\":\"registry.h.1.2\""));
        assert!(json.contains("\"chunk_index\":3"));
        assert!(!json.contains("file_hash"), "chunk pulls do not carry redundant file_hash");

        let fetch_gx_in_realm = RegistryOp::FetchGxInRealm {
            artifact_hash: "h".into(),
            realm: RealmId::new("crew"),
            chunk_size: Some(1024),
        };
        let json = serde_json::to_string(&fetch_gx_in_realm).unwrap();
        assert!(json.contains("\"op\":\"fetch_gx_in_realm\""));
        assert!(json.contains("\"chunk_size\":1024"));

        let fetch_gx_plan_in_realm = RegistryOp::FetchGxPlanInRealm {
            artifact_hash: "h".into(),
            realm: RealmId::new("crew"),
            chunk_size: Some(1024),
        };
        let json = serde_json::to_string(&fetch_gx_plan_in_realm).unwrap();
        assert!(json.contains("\"op\":\"fetch_gx_plan_in_realm\""));
        assert!(json.contains("\"realm\":\"crew\""));

        let fetch_gx_chunk_in_realm = RegistryOp::FetchGxChunkInRealm {
            artifact_hash: "h".into(),
            realm: RealmId::new("crew"),
            transfer_id: "registry.h.1.2".into(),
            chunk_size: 1024,
            chunk_index: 3,
        };
        let json = serde_json::to_string(&fetch_gx_chunk_in_realm).unwrap();
        assert!(json.contains("\"op\":\"fetch_gx_chunk_in_realm\""));
        assert!(json.contains("\"realm\":\"crew\""));
        assert!(json.contains("\"chunk_index\":3"));
        assert!(!json.contains("file_hash"), "chunk pulls do not carry redundant file_hash");
    }

    /// **`SyncEntry` round-trips** with the hex-encoded artifact bytes and elided absent signals.
    #[test]
    fn sync_entry_round_trips_with_hex_artifact_and_elided_signals() {
        let se = SyncEntry {
            artifact_hash: "abcd".into(),
            realm: RealmId::new("crew"),
            manifest: manifest("x"),
            artifact: b"some-bytes".to_vec(),
            reputation: None,
            quarantine: None,
        };
        let bytes = serde_json::to_vec(&se).unwrap();
        let json = String::from_utf8(bytes.clone()).unwrap();
        assert!(!json.contains("reputation"), "absent reputation elides");
        assert!(!json.contains("quarantine"), "absent quarantine elides");
        let back: SyncEntry = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.artifact, b"some-bytes");
        assert_eq!(back.realm, RealmId::new("crew"));
    }

    #[test]
    fn catalog_entry_omits_artifact_bytes_for_metadata_listing() {
        let entry = CatalogEntry {
            artifact_hash: "abcd".into(),
            realm: RealmId::new("crew"),
            manifest: manifest("x"),
            reputation: None,
            quarantine: None,
        };
        let reply = RegistryReply::Metadata { entries: vec![entry] };
        let json = serde_json::to_string(&reply).unwrap();
        assert!(json.contains("\"reply\":\"metadata\""));
        assert!(!json.contains("\"artifact\":"), "metadata listing must not carry artifact bytes");
    }

    #[test]
    fn quarantine_notice_shape_validator_caps_signal_fields() {
        let peers = vec!["node-A".to_string()];
        assert!(QuarantineNotice::mark_shape_error(
            "h",
            &RealmId::new("crew"),
            "apoptosis",
            &peers,
        )
        .is_none());

        let long_reason = "x".repeat(MAX_QUARANTINE_REASON_BYTES + 1);
        let err =
            QuarantineNotice::mark_shape_error("h", &RealmId::new("crew"), &long_reason, &peers)
                .expect("oversized reason rejected");
        assert!(err.contains("reason too large"));

        let long_peer = vec!["p".repeat(MAX_QUARANTINE_ATTESTING_PEER_BYTES + 1)];
        let err =
            QuarantineNotice::mark_shape_error("h", &RealmId::new("crew"), "apoptosis", &long_peer)
                .expect("oversized peer rejected");
        assert!(err.contains("attesting_peer too large"));

        let too_many_peers: Vec<String> =
            (0..=MAX_QUARANTINE_ATTESTING_PEERS).map(|i| format!("node-{i}")).collect();
        let err = QuarantineNotice::mark_shape_error(
            "h",
            &RealmId::new("crew"),
            "apoptosis",
            &too_many_peers,
        )
        .expect("oversized peer list rejected");
        assert!(err.contains("attesting_peers too large"));

        let long_hash = "h".repeat(MAX_REGISTRY_SIGNAL_FIELD_BYTES + 1);
        let err = QuarantineNotice::mark_shape_error(
            &long_hash,
            &RealmId::new("crew"),
            "apoptosis",
            &peers,
        )
        .expect("oversized key rejected");
        assert!(err.contains("artifact_hash too large"));

        let err = QuarantineNotice::mark_shape_error(
            "bad\0hash",
            &RealmId::new("crew"),
            "apoptosis",
            &peers,
        )
        .expect("NUL hash rejected");
        assert!(err.contains("artifact_hash contains NUL"));

        let err = QuarantineNotice::mark_shape_error(
            "h",
            &RealmId::new("bad:realm"),
            "apoptosis",
            &peers,
        )
        .expect("invalid realm rejected");
        assert!(err.contains("realm is not a valid RealmId"));

        let err =
            QuarantineNotice::mark_shape_error("h", &RealmId::new("crew"), "bad\0reason", &peers)
                .expect("NUL reason rejected");
        assert!(err.contains("reason contains NUL"));

        let err = QuarantineNotice::mark_shape_error(
            "h",
            &RealmId::new("crew"),
            "apoptosis",
            &["node\0A".into()],
        )
        .expect("NUL peer rejected");
        assert!(err.contains("attesting_peer contains NUL"));
    }
}
