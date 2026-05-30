//! `registry-mem` — in-memory Bestiary seed.
//!
//! Stores `(realm, artifact_hash) → (Manifest, artifact_bytes)` in a process-local map and
//! answers `publish` / `fetch` RPCs over the bus. Bound to `Role::REGISTRY` by the operator,
//! so any creature on the local node — or, with a transport in place, on a peer node — can
//! address it.
//!
//! ### Wire shape
//!
//! Operations and replies travel as JSON in the envelope payload. The artifact bytes ride as a
//! hex-encoded string (see `sigil::crypto::hex_bytes` for the rationale).
//!
//! - `RegistryOp::Publish { manifest, artifact, realm? }` → reply `RegistryReply::Published { artifact_hash, realm }`
//! - `RegistryOp::Fetch { artifact_hash, realm? }` → reply `RegistryReply::Fetched { manifest, artifact, realm }`
//!   or `RegistryReply::NotFound`
//! - Malformed payload → reply `RegistryReply::Error { message }` (R9: never panic on hostile input)
//!
//! ### Realm grain
//!
//! Entries carry an optional `realm: Option<RealmId>`; absent (or `None`) defaults to
//! [`RealmId::local()`], so a publish/fetch call that never writes `realm` operates in the
//! `"local"` Realm. A Realm-aware operator who wants per-Realm catalogs publishes/fetches with
//! `realm: Some(...)`; the store keys by `(realm, artifact_hash)` so two creatures with identical
//! bytes in different Realms don't collide. This is the "Bestiary == the Omega view of the
//! registry" thesis: per-Realm registries first, federated to Omega.
//!
//! ## Naming: `artifact_hash`, not `content_address`
//!
//! What this field carries is `sha256(artifact_bytes)` hex — exactly the same value
//! `provenance.build_hash` does. It is **distinct** from `Manifest::content_address`, which is a
//! hash over the manifest's identity-shape (name + version + capabilities + ...). Confusing them
//! would let two different creatures with the same bytes but different manifests collide on
//! "content address". The registry
//! is content-addressed *by artifact bytes*; it lets the receiver recompute the hash and reject a
//! bit-flip before any load.
//!
//! ### What this is NOT
//!
//! Not a real Bestiary. There's no quorum, no signed-entry chain, no replication, no GC. Those
//! are Omega concerns. This
//! creature exists so the kernel's admission + transport contracts have an honest
//! "fetch a manifest+artifact and admit it" path to exercise end-to-end.

use std::collections::HashMap;
use std::sync::Mutex;

use aether::{Creature, CreatureCtx, Envelope, Outcome, RealmId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::{Manifest, Verifier};

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
///   (T5): a re-publish of the same `(realm, artifact_hash)` clears it (the substrate never
///   permanently blacklists — that's a policy decision). Admission reads it; the substrate
///   enforces nothing.
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
/// a re-publish of the same `(realm, artifact_hash)` clears it. The substrate never permanently
/// blacklists; that's a policy decision (IoC). Admission may refuse a quarantined entry; the
/// substrate stores the marker and enforces nothing on its own.
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

/// The registry creature.
pub struct RegistryMem {
    /// (realm, artifact_hash) → entry. Keying by `(RealmId, String)` is what makes the Realm grain
    /// load-bearing — two creatures with identical bytes in different Realms don't collide. Bare
    /// Mutex: registry RPC is single-creature traffic.
    entries: Mutex<HashMap<(RealmId, String), Entry>>,
    /// Maximum number of distinct catalog entries held at once. A peer that publishes an unbounded
    /// stream of distinct artifacts would otherwise grow the catalog without limit. At capacity a
    /// *new* `(realm, artifact_hash)` is refused (re-publishing an existing key still succeeds — it
    /// resets signals in place, no growth). **`0` means unbounded** (the default; preserves prior
    /// behavior). Set via [`RegistryMem::with_max_entries`].
    max_entries: usize,
}

impl Default for RegistryMem {
    fn default() -> Self {
        RegistryMem::new()
    }
}

impl RegistryMem {
    pub fn new() -> Self {
        RegistryMem { entries: Mutex::new(HashMap::new()), max_entries: 0 }
    }

    /// Cap the number of distinct catalog entries (resilience guardrail; default `0` = unbounded).
    /// At capacity a publish of a *new* key is refused rather than growing the catalog without
    /// bound; re-publishing an existing key always succeeds.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Direct (non-bus) publish into the `"local"` Realm — a convenience for in-process callers.
    /// Bus callers go through `handle` with a
    /// `RegistryOp::Publish`. Returns the `sha256(artifact)` hex the entry is indexed under.
    pub fn publish(&self, manifest: Manifest, artifact: Vec<u8>) -> String {
        self.publish_in(RealmId::local(), manifest, artifact)
    }

    /// Direct (non-bus) publish into a named Realm. Returns the artifact_hash the entry is keyed
    /// under inside that Realm.
    pub fn publish_in(&self, realm: RealmId, manifest: Manifest, artifact: Vec<u8>) -> String {
        let hash = sha256_hex(&artifact);
        let key = (realm, hash.clone());
        let mut g = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        // Catalog-pressure guard (resilience): at capacity, refuse a *new* key rather than grow the
        // catalog without bound. Re-publishing an existing key is always allowed — it resets signals
        // in place and adds no entry. `0` disables the cap. The returned hash is still the correct
        // content address of the bytes; a later fetch of a refused key simply misses.
        if self.max_entries != 0 && g.len() >= self.max_entries && !g.contains_key(&key) {
            eprintln!(
                "registry-mem: catalog at capacity ({}); refusing new artifact {hash} in realm {}",
                self.max_entries, key.0 .0
            );
            return hash;
        }
        // A (re)publish resets the reputation/quarantine signals to None. For `quarantine` this is
        // the T5 reversibility rule made concrete: re-publishing a quarantined
        // `(realm, artifact_hash)` clears the marker — the substrate never permanently blacklists.
        g.insert(key, Entry { manifest, artifact, reputation: None, quarantine: None });
        hash
    }

    /// Attach (or replace) a reputation score on an existing `(realm, artifact_hash)` entry.
    /// No-op returning `false` if the entry is absent — a reputation signal for an artifact we
    /// don't hold is dropped (the federator publishes the artifact first, then attests). Returns
    /// `true` if applied.
    pub fn attest_fitness(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        score: ReputationScore,
    ) -> bool {
        // Chokepoint defense-in-depth (T10): a non-finite score (`f32::INFINITY`/`NaN`, reachable
        // from out-of-range peer wire data) must never be stored — it poisons every downstream
        // selection / defense read. The federator guards its ingest paths too, but this
        // is the last gate before the trust store, so guard here regardless of caller. `false` maps
        // to `NotFound`, the same as "we don't hold that artifact" — both mean "not applied."
        if !score.score.is_finite() {
            eprintln!(
                "registry-mem: rejected a non-finite reputation score for {artifact_hash} \
                 in realm {} (not stored)",
                realm.0
            );
            return false;
        }
        let mut g = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        match g.get_mut(&(realm.clone(), artifact_hash.to_string())) {
            Some(entry) => {
                entry.reputation = Some(score);
                true
            }
            None => false,
        }
    }

    /// Mark an existing entry quarantined. Returns `false` if absent (you can't quarantine what
    /// you don't hold). T5: reversible — clear by re-publishing the same `(realm, artifact_hash)`.
    pub fn mark_quarantine(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        notice: QuarantineNotice,
    ) -> bool {
        let mut g = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        match g.get_mut(&(realm.clone(), artifact_hash.to_string())) {
            Some(entry) => {
                entry.quarantine = Some(notice);
                true
            }
            None => false,
        }
    }

    /// Snapshot every entry as a [`SyncEntry`] list for anti-entropy pull. If `realm` is `Some`,
    /// only that Realm's entries; `None` returns all Realms. Cloning the full set is fine at this
    /// scale (the test catalogs hold a handful of tiny artifacts); a real Bestiary would page or
    /// digest-then-fetch.
    pub fn sync_entries(&self, realm: Option<&RealmId>) -> Vec<SyncEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((r, _), _)| realm.is_none() || realm == Some(r))
            .map(|((r, hash), entry)| SyncEntry {
                artifact_hash: hash.clone(),
                realm: r.clone(),
                manifest: entry.manifest.clone(),
                artifact: entry.artifact.clone(),
                reputation: entry.reputation.clone(),
                quarantine: entry.quarantine.clone(),
            })
            .collect()
    }

    /// Realm-implicit fetch — looks in the `"local"` Realm.
    pub fn fetch(&self, artifact_hash: &str) -> Option<Entry> {
        self.fetch_in(&RealmId::local(), artifact_hash)
    }

    /// Realm-aware fetch. Returns `None` if the `(realm, artifact_hash)` key is absent —
    /// the same hash in a different Realm is a different entry by construction.
    pub fn fetch_in(&self, realm: &RealmId, artifact_hash: &str) -> Option<Entry> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(realm.clone(), artifact_hash.to_string()))
            .cloned()
    }

    pub fn len(&self) -> usize {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.lock().unwrap_or_else(|p| p.into_inner()).is_empty()
    }
}

impl Creature for RegistryMem {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reply = match serde_json::from_slice::<RegistryOp>(&env.payload) {
            // Realm-implicit: the `"local"` Realm. Reply with the matching Realm-implicit variant —
            // a Realm-implicit caller gets a Realm-implicit reply back, round-tripping the wire.
            Ok(RegistryOp::Publish { manifest, artifact }) => {
                let artifact_hash = self.publish_in(RealmId::local(), manifest, artifact);
                RegistryReply::Published { artifact_hash }
            }
            Ok(RegistryOp::Fetch { artifact_hash }) => match self
                .fetch_in(&RealmId::local(), &artifact_hash)
            {
                Some(entry) => {
                    RegistryReply::Fetched { manifest: entry.manifest, artifact: entry.artifact }
                }
                None => RegistryReply::NotFound,
            },
            // Realm-explicit. Reply with the matching Realm-explicit variant carrying the
            // resolved Realm so the caller can confirm.
            Ok(RegistryOp::PublishInRealm { manifest, artifact, realm }) => {
                let artifact_hash = self.publish_in(realm.clone(), manifest, artifact);
                RegistryReply::PublishedInRealm { artifact_hash, realm }
            }
            Ok(RegistryOp::FetchInRealm { artifact_hash, realm }) => {
                match self.fetch_in(&realm, &artifact_hash) {
                    Some(entry) => RegistryReply::FetchedInRealm {
                        manifest: entry.manifest,
                        artifact: entry.artifact,
                        realm,
                    },
                    None => RegistryReply::NotFound,
                }
            }
            // Reputation + quarantine signals + anti-entropy snapshot.
            Ok(RegistryOp::AttestFitness {
                artifact_hash,
                realm,
                score,
                attesting_realm,
                signed_by,
                signature,
            }) => {
                let applied = self.attest_fitness(
                    &realm,
                    &artifact_hash,
                    ReputationScore { score, attesting_realm, signed_by, signature },
                );
                if applied {
                    RegistryReply::Attested { artifact_hash, realm }
                } else {
                    // A reputation signal for an artifact we don't hold is dropped (the federator
                    // publishes first, then attests; a race or a stale delta lands here). Make the
                    // missed signal discoverable rather than a silent NotFound. (T8)
                    eprintln!(
                        "registry-mem: AttestFitness dropped — no entry for {artifact_hash} in realm {}",
                        realm.0
                    );
                    RegistryReply::NotFound
                }
            }
            Ok(RegistryOp::MarkQuarantine { artifact_hash, realm, reason, attesting_peers }) => {
                let applied = self.mark_quarantine(
                    &realm,
                    &artifact_hash,
                    QuarantineNotice { reason, attesting_peers },
                );
                if applied {
                    RegistryReply::Quarantined { artifact_hash, realm }
                } else {
                    eprintln!(
                        "registry-mem: MarkQuarantine dropped — no entry for {artifact_hash} in realm {}",
                        realm.0
                    );
                    RegistryReply::NotFound
                }
            }
            Ok(RegistryOp::ListEntries { realm }) => {
                RegistryReply::Entries { entries: self.sync_entries(realm.as_ref()) }
            }
            Err(e) => {
                eprintln!(
                    "registry-mem: rejected a malformed op from {:?} (corr={:?}, {} bytes): {e}",
                    env.header.from,
                    env.header.corr,
                    env.payload.len()
                );
                RegistryReply::Error { message: format!("malformed registry op: {e}") }
            }
        };
        // Reply preserves `corr` so the requester correlates the response with its request — the
        // basic fire-and-correlate discipline that lets the registry serve in-process or via the
        // transport equally well.
        let payload = reply.to_bytes();
        // Default route via the requester's reply_to/`from` (handled by the local bus / via Node
        // for cross-node). Commitment is intentionally not propagated; the registry has no
        // commit-and-reveal semantics.
        Outcome::send(aether::Dispatch::reply_to_env(&env, payload).with_schema("registry.reply"))
    }
}

/// sha256 hex of the artifact bytes — the registry's index key and also the manifest's
/// `provenance.build_hash` (so the receiving node's admission gate can recompute and verify).
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Header};
    use sigil::Backend;

    fn manifest(name: &str) -> Manifest {
        Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
    }

    fn op_env(op: RegistryOp, requester: CreatureId) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(requester),
                to: Address::Creature(CreatureId(7)),
                reply_to: Some(Address::Creature(requester)),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(42),
                commitment: None,
                schema: "registry.op".into(),
            },
            payload: serde_json::to_vec(&op).unwrap(),
        }
    }

    #[test]
    fn publish_then_fetch_returns_the_artifact_with_matching_content_address() {
        let mut r = RegistryMem::new();
        let m = manifest("c");
        let bytes = b"hello-artifact-bytes".to_vec();
        let publish_env = op_env(
            RegistryOp::Publish { manifest: m.clone(), artifact: bytes.clone() },
            CreatureId(1),
        );
        let pub_reply = r.handle(publish_env);
        assert_eq!(pub_reply.dispatches.len(), 1);
        let pub_payload = &pub_reply.dispatches[0].payload;
        let pub_reply: RegistryReply = serde_json::from_slice(pub_payload).unwrap();
        let hash = match pub_reply {
            RegistryReply::Published { artifact_hash } => artifact_hash,
            other => panic!("expected Published, got {other:?}"),
        };
        assert_eq!(hash, sha256_hex(&bytes), "artifact_hash is the artifact-bytes sha256");

        // Fetch round-trip.
        let fetch_env = op_env(RegistryOp::Fetch { artifact_hash: hash.clone() }, CreatureId(2));
        // Corr is preserved on reply.
        assert_eq!(fetch_env.header.corr, Some(42));
        let fetch_reply = r.handle(fetch_env);
        assert_eq!(fetch_reply.dispatches.len(), 1);
        assert_eq!(fetch_reply.dispatches[0].corr, Some(42)); // fire-and-correlate
        let reply: RegistryReply =
            serde_json::from_slice(&fetch_reply.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Fetched { manifest, artifact } => {
                assert_eq!(manifest, m);
                assert_eq!(artifact, bytes);
            }
            other => panic!("expected Fetched, got {other:?}"),
        }
    }

    #[test]
    fn fetch_unknown_returns_not_found() {
        let mut r = RegistryMem::new();
        let env = op_env(
            RegistryOp::Fetch { artifact_hash: "deadbeef-not-in-store".into() },
            CreatureId(1),
        );
        let reply = r.handle(env);
        let r: RegistryReply = serde_json::from_slice(&reply.dispatches[0].payload).unwrap();
        assert!(matches!(r, RegistryReply::NotFound));
    }

    /// **Realm-aware publish/fetch round-trip.** The Realm-explicit variants
    /// key entries by `(realm, artifact_hash)`, so the same hash in two Realms is two distinct
    /// entries. The reply echoes the resolved Realm so the caller can confirm.
    #[test]
    fn publish_in_realm_then_fetch_in_realm_round_trips_with_realm_echoed() {
        let mut r = RegistryMem::new();
        let m = manifest("realm-aware");
        let bytes = b"realm-scoped-artifact".to_vec();
        let realm = RealmId::new("crew");

        let publish_env = op_env(
            RegistryOp::PublishInRealm {
                manifest: m.clone(),
                artifact: bytes.clone(),
                realm: realm.clone(),
            },
            CreatureId(1),
        );
        let pub_reply: RegistryReply =
            serde_json::from_slice(&r.handle(publish_env).dispatches[0].payload).unwrap();
        match pub_reply {
            RegistryReply::PublishedInRealm { artifact_hash, realm: echoed } => {
                assert_eq!(artifact_hash, sha256_hex(&bytes));
                assert_eq!(echoed, realm, "the reply echoes the resolved Realm");
            }
            other => panic!("expected PublishedInRealm, got {other:?}"),
        }

        // Fetch from the same Realm — round-trips intact, Realm echoed.
        let fetch_env = op_env(
            RegistryOp::FetchInRealm { artifact_hash: sha256_hex(&bytes), realm: realm.clone() },
            CreatureId(2),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(fetch_env).dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::FetchedInRealm { manifest, artifact, realm: echoed } => {
                assert_eq!(manifest, m);
                assert_eq!(artifact, bytes);
                assert_eq!(echoed, realm);
            }
            other => panic!("expected FetchedInRealm, got {other:?}"),
        }
    }

    /// **Realm scoping.** Identical artifact bytes in two different Realms are two
    /// separate entries; fetching by `(realm_A, hash)` MUST NOT return the entry stored under
    /// `(realm_B, hash)`. The whole point of Realm grain: per-Realm catalogs.
    #[test]
    fn same_hash_in_two_realms_does_not_collide() {
        let mut r = RegistryMem::new();
        let m_a = manifest("a");
        let m_b = manifest("b");
        // Two manifests with DIFFERENT names but, deliberately, the SAME artifact bytes. Without
        // Realm grain they would collide (the second publish overwrites the first). With Realm
        // grain, they live in separate Realms and both remain queryable.
        let bytes = b"identical-bytes-different-meaning".to_vec();
        let hash = sha256_hex(&bytes);

        let realm_a = RealmId::new("alpha");
        let realm_b = RealmId::new("beta");

        // Publish in alpha realm.
        let env_a = op_env(
            RegistryOp::PublishInRealm {
                manifest: m_a.clone(),
                artifact: bytes.clone(),
                realm: realm_a.clone(),
            },
            CreatureId(1),
        );
        let _ = r.handle(env_a);

        // Publish (different manifest, same bytes) in beta realm.
        let env_b = op_env(
            RegistryOp::PublishInRealm {
                manifest: m_b.clone(),
                artifact: bytes.clone(),
                realm: realm_b.clone(),
            },
            CreatureId(2),
        );
        let _ = r.handle(env_b);

        assert_eq!(r.len(), 2, "two Realms, two entries — no collision");

        // Fetch from alpha — must return m_a, not m_b.
        let fetch_a = op_env(
            RegistryOp::FetchInRealm { artifact_hash: hash.clone(), realm: realm_a.clone() },
            CreatureId(3),
        );
        let reply_a: RegistryReply =
            serde_json::from_slice(&r.handle(fetch_a).dispatches[0].payload).unwrap();
        match reply_a {
            RegistryReply::FetchedInRealm { manifest, .. } => assert_eq!(manifest, m_a),
            other => panic!("expected FetchedInRealm from alpha, got {other:?}"),
        }

        // And from beta — m_b, not m_a.
        let fetch_b = op_env(
            RegistryOp::FetchInRealm { artifact_hash: hash.clone(), realm: realm_b.clone() },
            CreatureId(4),
        );
        let reply_b: RegistryReply =
            serde_json::from_slice(&r.handle(fetch_b).dispatches[0].payload).unwrap();
        match reply_b {
            RegistryReply::FetchedInRealm { manifest, .. } => assert_eq!(manifest, m_b),
            other => panic!("expected FetchedInRealm from beta, got {other:?}"),
        }
    }

    /// **Realm-implicit behavior.** A Realm-implicit Publish (no Realm field) is stored
    /// under the `"local"` Realm. A Realm-implicit Fetch finds it. An explicit `FetchInRealm` with
    /// `realm: RealmId::local()` finds the same entry (the resolution rule is "absent = local").
    /// A `FetchInRealm` with a different Realm returns NotFound — the entry is genuinely
    /// scoped to "local."
    #[test]
    fn v01_shape_publish_lands_in_local_realm_and_is_only_findable_there() {
        let mut r = RegistryMem::new();
        let m = manifest("v01-shape");
        let bytes = b"v01-bytes".to_vec();
        let hash = sha256_hex(&bytes);

        // Realm-implicit publish (no realm field).
        let env = op_env(
            RegistryOp::Publish { manifest: m.clone(), artifact: bytes.clone() },
            CreatureId(1),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        assert!(matches!(reply, RegistryReply::Published { .. }));

        // Realm-implicit fetch finds it (also implicitly local).
        let env = op_env(RegistryOp::Fetch { artifact_hash: hash.clone() }, CreatureId(2));
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        assert!(matches!(reply, RegistryReply::Fetched { .. }), "v0.1 fetch finds v0.1 publish");

        // Realm-explicit fetch with realm=local also finds it — resolution rule is consistent.
        let env = op_env(
            RegistryOp::FetchInRealm { artifact_hash: hash.clone(), realm: RealmId::local() },
            CreatureId(3),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::FetchedInRealm { manifest, .. } => assert_eq!(manifest, m),
            other => panic!("v0.2 fetch with realm=local must find a v0.1 publish, got {other:?}"),
        }

        // Realm-explicit fetch with a different realm returns NotFound — local entries stay local.
        let env = op_env(
            RegistryOp::FetchInRealm { artifact_hash: hash, realm: RealmId::new("other") },
            CreatureId(4),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        assert!(
            matches!(reply, RegistryReply::NotFound),
            "v0.1 publish does NOT leak into other Realms"
        );
    }

    /// **Wire compatibility.** A Realm-implicit op's JSON bytes carry no Realm field and
    /// deserialize cleanly. A Realm-explicit op uses a distinct `"op"` tag so a wire reader that
    /// only knows the implicit variants ignores it (it unmarshals as the implicit variant, or
    /// fails tag-matching — both are honest). This test locks the wire shape so a future refactor
    /// doesn't silently drift.
    #[test]
    fn v01_op_wire_bytes_are_unchanged_at_v02() {
        let m = manifest("compat");
        let bytes = b"a".to_vec();
        let v01_publish = RegistryOp::Publish { manifest: m.clone(), artifact: bytes.clone() };
        let json = serde_json::to_string(&v01_publish).unwrap();
        assert!(json.contains("\"op\":\"publish\""), "v0.1 op tag still 'publish'");
        assert!(!json.contains("\"realm\""), "v0.1 publish wire has no Realm field — by design");
        // The Realm-explicit variant uses a distinct op tag: 'publish_in_realm'.
        let v02_publish = RegistryOp::PublishInRealm {
            manifest: m,
            artifact: bytes,
            realm: RealmId::new("crew"),
        };
        let json = serde_json::to_string(&v02_publish).unwrap();
        assert!(json.contains("\"op\":\"publish_in_realm\""), "v0.2 op tag is 'publish_in_realm'");
        assert!(json.contains("\"realm\":\"crew\""), "v0.2 publish wire carries Realm");
    }

    /// **Reputation attestation.** AttestFitness on a held entry records the score
    /// + attesting Realm; ListEntries reflects it. Attesting an absent entry returns NotFound.
    #[test]
    fn attest_fitness_records_score_and_realm_or_not_found() {
        let mut r = RegistryMem::new();
        let m = manifest("rep");
        let bytes = b"rep-bytes".to_vec();
        let realm = RealmId::new("crew");
        let hash = r.publish_in(realm.clone(), m, bytes);

        let env = op_env(
            RegistryOp::AttestFitness {
                artifact_hash: hash.clone(),
                realm: realm.clone(),
                score: 0.95,
                attesting_realm: Some(RealmId::new("crew")),
                signed_by: None,
                signature: None,
            },
            CreatureId(1),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        assert!(matches!(reply, RegistryReply::Attested { .. }));

        let entry = r.fetch_in(&realm, &hash).unwrap();
        let rep = entry.reputation.expect("score recorded");
        assert_eq!(rep.score, 0.95);
        assert_eq!(rep.attesting_realm, Some(RealmId::new("crew")));

        // Attesting an artifact we don't hold → NotFound (federator publishes first, then attests).
        let env = op_env(
            RegistryOp::AttestFitness {
                artifact_hash: "not-held".into(),
                realm: realm.clone(),
                score: 1.0,
                attesting_realm: None,
                signed_by: None,
                signature: None,
            },
            CreatureId(1),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        assert!(matches!(reply, RegistryReply::NotFound));
    }

    /// **Signed promotion round-trip.** A fitness-selector signs the promotion claim
    /// `(artifact_hash, realm, score, attesting_realm)` with its Abode key; the stored score then
    /// verifies under that key for the SAME entry key, and fails for a tampered score or a different
    /// realm — so a signature can't be replayed onto another entry. This is the contract the
    /// `policy-prefer-promoted` admission policy checks (Baldwin: a learned score travels as a
    /// signed, checkable fact).
    #[test]
    fn signed_promotion_score_verifies_for_its_entry_and_rejects_replay() {
        use sigil::{Ed25519KeyMaterial, Ed25519Verifier};
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
            signed_by: Some(pk.clone()),
            signature: Some(sig),
        };
        let v = Ed25519Verifier;
        assert!(
            rep.promotion_verifies(hash, &realm, &v),
            "signed promotion verifies for its own entry"
        );
        // Replay onto a different artifact / realm / score must fail (the claim binds all three).
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
        // An unsigned score is never a *verified* promotion.
        assert!(!ReputationScore::unsigned(0.95, attesting).promotion_verifies(hash, &realm, &v));
    }

    /// **Quarantine is reversible (T5).** Mark quarantines; a re-publish of the same
    /// `(realm, artifact_hash)` clears it. The substrate never permanently blacklists.
    #[test]
    fn quarantine_marks_and_republish_clears_it() {
        let mut r = RegistryMem::new();
        let realm = RealmId::new("crew");
        let bytes = b"susp".to_vec();
        let hash = r.publish_in(realm.clone(), manifest("q"), bytes.clone());

        let env = op_env(
            RegistryOp::MarkQuarantine {
                artifact_hash: hash.clone(),
                realm: realm.clone(),
                reason: "apoptosis on node-A".into(),
                attesting_peers: vec!["node-A".into()],
            },
            CreatureId(1),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        assert!(matches!(reply, RegistryReply::Quarantined { .. }));
        let q = r.fetch_in(&realm, &hash).unwrap().quarantine.expect("quarantined");
        assert_eq!(q.reason, "apoptosis on node-A");
        assert_eq!(q.attesting_peers, vec!["node-A".to_string()]);

        // T5: re-publish the SAME (realm, hash) clears the quarantine.
        let _ = r.publish_in(realm.clone(), manifest("q"), bytes);
        assert!(
            r.fetch_in(&realm, &hash).unwrap().quarantine.is_none(),
            "re-publish under the same key clears quarantine (T5 reversibility)"
        );
    }

    /// **Anti-entropy snapshot.** ListEntries returns self-contained SyncEntries a
    /// peer federator can merge; realm scoping filters. This is the read side of pull-based
    /// reconciliation; the federator writes back via PublishInRealm.
    #[test]
    fn list_entries_snapshots_catalog_for_pull_with_realm_scoping() {
        let mut r = RegistryMem::new();
        r.publish_in(RealmId::new("crew"), manifest("x"), b"x-bytes".to_vec());
        r.publish_in(RealmId::new("guests"), manifest("y"), b"y-bytes".to_vec());

        // All realms.
        let env = op_env(RegistryOp::ListEntries { realm: None }, CreatureId(1));
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Entries { entries } => assert_eq!(entries.len(), 2),
            other => panic!("expected Entries, got {other:?}"),
        }

        // Scoped to one realm.
        let env =
            op_env(RegistryOp::ListEntries { realm: Some(RealmId::new("guests")) }, CreatureId(1));
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Entries { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].realm, RealmId::new("guests"));
                assert_eq!(entries[0].manifest.name, "y");
            }
            other => panic!("expected Entries, got {other:?}"),
        }
    }

    /// **Op wire tags stay distinct.** The reputation/quarantine ops use distinct `op`
    /// tags; the publish/fetch variants serialize independently. Locks the zero-retrofit guarantee.
    #[test]
    fn v03_ops_use_distinct_tags_and_dont_disturb_prior_wire() {
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
        // The optional promotion-signature fields also elide when None — so an unsigned
        // AttestFitness carries no signature bytes.
        assert!(!json.contains("signed_by"), "None signed_by elides");
        assert!(!json.contains("signature"), "None signature elides");
        let list = RegistryOp::ListEntries { realm: None };
        assert!(serde_json::to_string(&list).unwrap().contains("\"op\":\"list_entries\""));
    }

    #[test]
    fn malformed_payload_yields_error_reply_not_panic() {
        // R9: hostile input becomes a structured Error, never a panic.
        let mut r = RegistryMem::new();
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "".into(),
            },
            payload: b"{ not json".to_vec(),
        };
        let reply = r.handle(env);
        let r: RegistryReply = serde_json::from_slice(&reply.dispatches[0].payload).unwrap();
        assert!(matches!(r, RegistryReply::Error { .. }));
    }

    #[test]
    fn max_entries_refuses_new_artifact_at_capacity_but_allows_republish() {
        // Cap the catalog at 1 distinct entry. The first publish lands; a *new* artifact is refused
        // (not stored), but re-publishing an existing key still succeeds (resets signals in place,
        // no growth). `0` would be unbounded (the default).
        let r = RegistryMem::new().with_max_entries(1);
        let h1 = r.publish(manifest("a"), b"artifact-one".to_vec());
        assert!(r.fetch(&h1).is_some(), "first artifact stored under cap");

        // A second, distinct artifact at capacity is refused — the returned hash is still the
        // correct content address, but the entry was not stored, so a fetch misses.
        let h2 = r.publish(manifest("b"), b"artifact-two-distinct".to_vec());
        assert_eq!(h2, sha256_hex(b"artifact-two-distinct"), "hash is still the content address");
        assert!(r.fetch(&h2).is_none(), "new artifact refused at capacity (not stored)");
        assert!(r.fetch(&h1).is_some(), "the first artifact is untouched (refuse-new, not evict)");

        // Re-publishing the existing key is always allowed (no growth — it's the same slot).
        let h1_again = r.publish(manifest("a"), b"artifact-one".to_vec());
        assert_eq!(h1_again, h1);
        assert!(r.fetch(&h1).is_some(), "re-publish of an existing key succeeds at capacity");
    }
}
