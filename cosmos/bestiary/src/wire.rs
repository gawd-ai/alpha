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

/// A self-contained entry digest for anti-entropy pull. Carries everything a peer
/// federator needs to merge the entry into its own registry without a follow-up fetch: the key
/// `(realm, artifact_hash)`, the full manifest + artifact bytes (admission re-verifies on load —
/// T2), and the two optional signals. The federator that pulls these re-publishes each via the
/// [`RegistryOp::PublishInRealm`] write path, so the registry keeps one ingestion path.
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
/// ### Two variant families
///
/// **Realm-implicit variants** (`Publish` / `Fetch`) carry no Realm and operate in the `"local"`
/// Realm. **Realm-explicit variants** (`PublishInRealm` / `FetchInRealm`) add the Realm grain
/// explicitly. A Realm-aware caller picks the explicit variant; the wire `"op"` tag disambiguates.
///
/// Splitting into separate variants (rather than adding an optional field) is the choice that
/// honors the "zero retrofits" rule. Adding a field to a struct variant breaks every Rust struct
/// literal at compile time — even when the wire bytes stay compatible via
/// `skip_serializing_if`. Variants are forever additive.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum RegistryOp {
    /// Treats the entry as living in [`RealmId::local()`] — the Realm-implicit publish.
    Publish {
        manifest: Manifest,
        #[serde(with = "sigil::crypto::hex_bytes")]
        artifact: Vec<u8>,
    },
    /// Looks in [`RealmId::local()`].
    Fetch {
        /// `sha256(artifact_bytes)` hex — the registry's content-address key. Equals
        /// `provenance.build_hash` for a signed manifest. **Not the same** as
        /// [`Manifest::content_address`](sigil::Manifest::content_address); see this
        /// module's docs.
        artifact_hash: String,
    },
    /// Publish into a named Realm. Two creatures with identical artifact bytes in
    /// different Realms are stored under distinct `(realm, artifact_hash)` keys and do not
    /// collide.
    PublishInRealm {
        manifest: Manifest,
        #[serde(with = "sigil::crypto::hex_bytes")]
        artifact: Vec<u8>,
        realm: RealmId,
    },
    /// Fetch from a named Realm — returns [`RegistryReply::NotFound`] if the
    /// `(realm, artifact_hash)` key is absent, even if the same hash exists in another Realm.
    FetchInRealm { artifact_hash: String, realm: RealmId },
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
}

/// What the registry sends back. Envelope payload = `serde_json::to_vec(&RegistryReply)`.
///
/// The Realm-implicit reply variants (`Published` / `Fetched`) pair with the Realm-implicit ops;
/// `PublishedInRealm` / `FetchedInRealm` pair with the Realm-explicit ops. The handler responds
/// with whichever variant matches the op it received — a Realm-implicit request gets a
/// Realm-implicit reply, by construction.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "reply", rename_all = "snake_case")]
pub enum RegistryReply {
    /// Reply to [`RegistryOp::Publish`].
    Published {
        /// The artifact-bytes hash (`sha256(artifact)` hex) the registry indexed this entry under.
        /// See the field docs on [`RegistryOp::Fetch`] for the naming rationale.
        artifact_hash: String,
    },
    /// Reply to [`RegistryOp::Fetch`].
    Fetched {
        manifest: Manifest,
        #[serde(with = "sigil::crypto::hex_bytes")]
        artifact: Vec<u8>,
    },
    /// Reply to [`RegistryOp::PublishInRealm`] — echoes the Realm so the caller can
    /// confirm which catalog was touched.
    PublishedInRealm {
        artifact_hash: String,
        realm: RealmId,
    },
    /// Reply to [`RegistryOp::FetchInRealm`].
    FetchedInRealm {
        manifest: Manifest,
        #[serde(with = "sigil::crypto::hex_bytes")]
        artifact: Vec<u8>,
        realm: RealmId,
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

    /// **Wire tags + optional-field elision are locked.** The op `"op"` tags are stable and the
    /// optional promotion-signature fields elide when `None`, so an unsigned `AttestFitness` carries
    /// no signature bytes (zero-retrofit guarantee).
    #[test]
    fn op_wire_tags_are_stable_and_optional_fields_elide() {
        let publish = RegistryOp::Publish { manifest: manifest("c"), artifact: b"a".to_vec() };
        let json = serde_json::to_string(&publish).unwrap();
        assert!(json.contains("\"op\":\"publish\""));
        assert!(!json.contains("\"realm\""), "implicit publish has no Realm field");

        let in_realm = RegistryOp::PublishInRealm {
            manifest: manifest("c"),
            artifact: b"a".to_vec(),
            realm: RealmId::new("crew"),
        };
        let json = serde_json::to_string(&in_realm).unwrap();
        assert!(json.contains("\"op\":\"publish_in_realm\""));
        assert!(json.contains("\"realm\":\"crew\""));

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
}
