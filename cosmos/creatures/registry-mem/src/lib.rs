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
//! - `RegistryOp::FetchMetadata { artifact_hash, realm? }` → reply
//!   `RegistryReply::FetchedMetadata { entry, artifact_len }` without artifact bytes
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
//!
//! The in-memory catalog is bounded by default ([`DEFAULT_MAX_REGISTRY_ENTRIES`]) so a peer cannot
//! grow this reference store indefinitely by publishing ever-new artifacts. At capacity, a new key is
//! refused while an existing key can still be re-published; `with_max_entries(0)` is the explicit
//! unbounded opt-out for lab or demo workloads. Published manifests are re-run through
//! `Manifest::validate`, whose metadata strings and lists are capped before the registry retains
//! them. Full-artifact anti-entropy snapshots
//! (`ListEntries`) are also source-capped by total artifact bytes so a caller cannot force the
//! registry to clone the whole catalog into one giant reply.

use std::collections::HashMap;
use std::sync::Mutex;

use aether::{Creature, CreatureCtx, Envelope, Outcome, RealmId};
use sha2::{Digest, Sha256};
use sigil::Manifest;

// The registry wire vocabulary (the op/reply enums, the catalog `Entry`, the anti-entropy
// `SyncEntry`, and the `ReputationScore` / `QuarantineNotice` signals) lives in the `bestiary`
// contract crate so the durable `bestiary-daemon` can share one wire contract with this in-memory
// stub. Re-exported here so every `registry_mem::TypeName` consumer compiles unchanged.
use bestiary::{
    registry_artifact_too_large_message, registry_op_too_large_message,
    MAX_REGISTRY_ARTIFACT_BYTES, MAX_REGISTRY_OP_BYTES,
};
pub use bestiary::{
    CatalogEntry, Entry, QuarantineNotice, RegistryOp, RegistryReply, ReputationScore, SyncEntry,
    MAX_QUARANTINE_ATTESTING_PEERS, MAX_QUARANTINE_ATTESTING_PEER_BYTES,
    MAX_QUARANTINE_REASON_BYTES, MAX_REGISTRY_SIGNAL_FIELD_BYTES,
};

/// Default maximum number of distinct `(realm, artifact_hash)` entries retained by `registry-mem`.
///
/// `0` is reserved as an explicit opt-out via [`RegistryMem::with_max_entries`].
pub const DEFAULT_MAX_REGISTRY_ENTRIES: usize = 1_024;

/// Default total artifact bytes cloned into one `ListEntries` anti-entropy snapshot.
///
/// `ListEntries` is the full-artifact replication path. The catalog entry cap bounds retained
/// state, but without a per-snapshot cap a caller could ask the registry to clone many stored
/// artifacts into one large reply. `0` via [`RegistryMem::with_max_snapshot_artifact_bytes`] is the
/// explicit opt-out for lab/demo pulls that intentionally accept larger snapshots.
pub const DEFAULT_MAX_REGISTRY_SNAPSHOT_ARTIFACT_BYTES: usize = MAX_REGISTRY_ARTIFACT_BYTES;

enum PublishResult {
    Stored(String),
    Refused { artifact_hash: String, message: String },
}

impl PublishResult {
    fn artifact_hash(self) -> String {
        match self {
            PublishResult::Stored(hash) | PublishResult::Refused { artifact_hash: hash, .. } => {
                hash
            }
        }
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
    /// resets signals in place, no growth). **`0` means unbounded** and must be selected explicitly
    /// via [`RegistryMem::with_max_entries`].
    max_entries: usize,
    /// Maximum serialized `RegistryOp` bytes this creature will decode. `0` means unbounded.
    max_op_bytes: usize,
    /// Maximum artifact bytes retained per publish. `0` means unbounded.
    max_artifact_bytes: usize,
    /// Maximum total artifact bytes cloned into one `ListEntries` reply. `0` means unbounded.
    max_snapshot_artifact_bytes: usize,
}

impl Default for RegistryMem {
    fn default() -> Self {
        RegistryMem::new()
    }
}

impl RegistryMem {
    pub fn new() -> Self {
        RegistryMem {
            entries: Mutex::new(HashMap::new()),
            max_entries: DEFAULT_MAX_REGISTRY_ENTRIES,
            max_op_bytes: MAX_REGISTRY_OP_BYTES,
            max_artifact_bytes: MAX_REGISTRY_ARTIFACT_BYTES,
            max_snapshot_artifact_bytes: DEFAULT_MAX_REGISTRY_SNAPSHOT_ARTIFACT_BYTES,
        }
    }

    /// Cap the number of distinct catalog entries.
    ///
    /// The default is [`DEFAULT_MAX_REGISTRY_ENTRIES`]. At capacity a publish of a *new* key is
    /// refused rather than growing the catalog without bound; re-publishing an existing key always
    /// succeeds. Pass `0` to opt out and make the in-memory catalog unbounded.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Cap serialized `RegistryOp` bytes before JSON decode (default [`MAX_REGISTRY_OP_BYTES`]).
    /// `0` means unbounded.
    pub fn with_max_op_bytes(mut self, max_op_bytes: usize) -> Self {
        self.max_op_bytes = max_op_bytes;
        self
    }

    /// Cap stored artifact bytes (default [`MAX_REGISTRY_ARTIFACT_BYTES`]). `0` means unbounded.
    pub fn with_max_artifact_bytes(mut self, max_artifact_bytes: usize) -> Self {
        self.max_artifact_bytes = max_artifact_bytes;
        self
    }

    /// Cap the total artifact bytes cloned into a single `ListEntries` snapshot.
    ///
    /// The default is [`DEFAULT_MAX_REGISTRY_SNAPSHOT_ARTIFACT_BYTES`]. `0` disables the cap.
    pub fn with_max_snapshot_artifact_bytes(mut self, max_snapshot_artifact_bytes: usize) -> Self {
        self.max_snapshot_artifact_bytes = max_snapshot_artifact_bytes;
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
        self.publish_in_checked(realm, manifest, artifact).artifact_hash()
    }

    fn publish_in_checked(
        &self,
        realm: RealmId,
        manifest: Manifest,
        artifact: Vec<u8>,
    ) -> PublishResult {
        let hash = sha256_hex(&artifact);
        if self.max_artifact_bytes != 0 && artifact.len() > self.max_artifact_bytes {
            let message =
                registry_artifact_too_large_message(artifact.len(), self.max_artifact_bytes);
            eprintln!("registry-mem: {message}; refusing artifact {hash} in realm {}", realm.0);
            return PublishResult::Refused { artifact_hash: hash, message };
        }
        if let Err(e) = manifest.validate() {
            let message = format!("invalid manifest: {e}");
            eprintln!("registry-mem: {message}; refusing artifact {hash} in realm {}", realm.0);
            return PublishResult::Refused { artifact_hash: hash, message };
        }
        let key = (realm, hash.clone());
        let mut g = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        // Catalog-pressure guard (resilience): at capacity, refuse a *new* key rather than grow the
        // catalog without bound. Re-publishing an existing key is always allowed — it resets signals
        // in place and adds no entry. `0` disables the cap. The returned hash is still the correct
        // content address of the bytes; a later fetch of a refused key simply misses.
        if self.max_entries != 0 && g.len() >= self.max_entries && !g.contains_key(&key) {
            let message = format!(
                "catalog at capacity ({}); refusing new artifact {hash} in realm {}",
                self.max_entries, key.0 .0
            );
            eprintln!("registry-mem: {message}");
            return PublishResult::Refused { artifact_hash: hash, message };
        }
        // A (re)publish resets the reputation/quarantine signals to None. For `quarantine` this is
        // the T5 reversibility rule made concrete: re-publishing a quarantined
        // `(realm, artifact_hash)` clears the marker — the substrate never permanently blacklists.
        g.insert(key, Entry { manifest, artifact, reputation: None, quarantine: None });
        PublishResult::Stored(hash)
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
        if let Some(message) = QuarantineNotice::mark_shape_error(
            artifact_hash,
            realm,
            &notice.reason,
            &notice.attesting_peers,
        ) {
            eprintln!(
                "registry-mem: rejected quarantine marker for {artifact_hash} in realm {}: {message}",
                realm.0
            );
            return false;
        }
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
        self.sync_entries_with_limit(realm, 0).unwrap_or_default()
    }

    fn sync_entries_checked(&self, realm: Option<&RealmId>) -> Result<Vec<SyncEntry>, String> {
        self.sync_entries_with_limit(realm, self.max_snapshot_artifact_bytes)
    }

    fn sync_entries_with_limit(
        &self,
        realm: Option<&RealmId>,
        max_snapshot_artifact_bytes: usize,
    ) -> Result<Vec<SyncEntry>, String> {
        let mut artifact_bytes = 0usize;
        let mut entries = Vec::new();
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((r, _), _)| realm.is_none() || realm == Some(r))
            .try_for_each(|((r, hash), entry)| {
                artifact_bytes = artifact_bytes.saturating_add(entry.artifact.len());
                if max_snapshot_artifact_bytes != 0 && artifact_bytes > max_snapshot_artifact_bytes
                {
                    return Err(format!(
                        "registry snapshot too large: {artifact_bytes} artifact bytes exceeds {} byte limit",
                        max_snapshot_artifact_bytes
                    ));
                }
                entries.push(SyncEntry {
                    artifact_hash: hash.clone(),
                    realm: r.clone(),
                    manifest: entry.manifest.clone(),
                    artifact: entry.artifact.clone(),
                    reputation: entry.reputation.clone(),
                    quarantine: entry.quarantine.clone(),
                });
                Ok(())
            })?;
        Ok(entries)
    }

    pub fn catalog_entries(&self, realm: Option<&RealmId>) -> Vec<CatalogEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|((r, _), _)| realm.is_none() || realm == Some(r))
            .map(|((r, hash), entry)| CatalogEntry {
                artifact_hash: hash.clone(),
                realm: r.clone(),
                manifest: entry.manifest.clone(),
                reputation: entry.reputation.clone(),
                quarantine: entry.quarantine.clone(),
            })
            .collect()
    }

    /// Realm-aware metadata fetch. Returns the byte-light catalog row and the artifact length without
    /// cloning the artifact bytes into the reply.
    pub fn fetch_metadata_in(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
    ) -> Option<(CatalogEntry, usize)> {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(&(realm.clone(), artifact_hash.to_string()))
            .map(|entry| {
                (
                    CatalogEntry {
                        artifact_hash: artifact_hash.to_string(),
                        realm: realm.clone(),
                        manifest: entry.manifest.clone(),
                        reputation: entry.reputation.clone(),
                        quarantine: entry.quarantine.clone(),
                    },
                    entry.artifact.len(),
                )
            })
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
        let reply = if self.max_op_bytes != 0 && env.payload.len() > self.max_op_bytes {
            let message = registry_op_too_large_message(env.payload.len(), self.max_op_bytes);
            eprintln!(
                "registry-mem: rejected an oversized op from {:?} (corr={:?}): {message}",
                env.header.from, env.header.corr
            );
            RegistryReply::Error { message }
        } else {
            match serde_json::from_slice::<RegistryOp>(&env.payload) {
                // Realm-implicit: the `"local"` Realm. Reply with the matching Realm-implicit variant —
                // a Realm-implicit caller gets a Realm-implicit reply back, round-tripping the wire.
                Ok(RegistryOp::Publish { manifest, artifact }) => {
                    match self.publish_in_checked(RealmId::local(), manifest, artifact) {
                        PublishResult::Stored(artifact_hash) => {
                            RegistryReply::Published { artifact_hash }
                        }
                        PublishResult::Refused { message, .. } => RegistryReply::Error { message },
                    }
                }
                Ok(RegistryOp::Fetch { artifact_hash }) => {
                    match self.fetch_in(&RealmId::local(), &artifact_hash) {
                        Some(entry) => RegistryReply::Fetched {
                            manifest: entry.manifest,
                            artifact: entry.artifact,
                        },
                        None => RegistryReply::NotFound,
                    }
                }
                Ok(RegistryOp::FetchMetadata { artifact_hash }) => {
                    match self.fetch_metadata_in(&RealmId::local(), &artifact_hash) {
                        Some((entry, artifact_len)) => {
                            RegistryReply::FetchedMetadata { entry, artifact_len }
                        }
                        None => RegistryReply::NotFound,
                    }
                }
                // Realm-explicit. Reply with the matching Realm-explicit variant carrying the
                // resolved Realm so the caller can confirm.
                Ok(RegistryOp::PublishInRealm { manifest, artifact, realm }) => {
                    match self.publish_in_checked(realm.clone(), manifest, artifact) {
                        PublishResult::Stored(artifact_hash) => {
                            RegistryReply::PublishedInRealm { artifact_hash, realm }
                        }
                        PublishResult::Refused { message, .. } => RegistryReply::Error { message },
                    }
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
                Ok(RegistryOp::FetchMetadataInRealm { artifact_hash, realm }) => {
                    match self.fetch_metadata_in(&realm, &artifact_hash) {
                        Some((entry, artifact_len)) => {
                            RegistryReply::FetchedMetadata { entry, artifact_len }
                        }
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
                Ok(RegistryOp::MarkQuarantine {
                    artifact_hash,
                    realm,
                    reason,
                    attesting_peers,
                }) => {
                    if let Some(message) = QuarantineNotice::mark_shape_error(
                        &artifact_hash,
                        &realm,
                        &reason,
                        &attesting_peers,
                    ) {
                        eprintln!(
                            "registry-mem: rejected MarkQuarantine for {artifact_hash} in realm {}: {message}",
                            realm.0
                        );
                        return Outcome::send(
                            aether::Dispatch::reply_to_env(
                                &env,
                                RegistryReply::Error { message }.to_bytes(),
                            )
                            .with_schema("registry.reply"),
                        );
                    }
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
                    match self.sync_entries_checked(realm.as_ref()) {
                        Ok(entries) => RegistryReply::Entries { entries },
                        Err(message) => {
                            eprintln!("registry-mem: {message}");
                            RegistryReply::Error { message }
                        }
                    }
                }
                Ok(RegistryOp::ListMetadata { realm }) => {
                    RegistryReply::Metadata { entries: self.catalog_entries(realm.as_ref()) }
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
    use sigil::{Backend, MAX_MANIFEST_NAME_BYTES};

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

    #[test]
    fn quarantine_marker_shape_is_capped_before_store() {
        let mut r = RegistryMem::new();
        let realm = RealmId::new("crew");
        let hash = r.publish_in(realm.clone(), manifest("q-shape"), b"q-shape".to_vec());

        let oversized_reason = "x".repeat(MAX_QUARANTINE_REASON_BYTES + 1);
        let env = op_env(
            RegistryOp::MarkQuarantine {
                artifact_hash: hash.clone(),
                realm: realm.clone(),
                reason: oversized_reason,
                attesting_peers: vec!["node-A".into()],
            },
            CreatureId(1),
        );
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("reason too large"), "{message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(
            r.fetch_in(&realm, &hash).unwrap().quarantine.is_none(),
            "oversized quarantine reason was not retained"
        );

        let direct = r.mark_quarantine(
            &realm,
            &hash,
            QuarantineNotice {
                reason: "direct".into(),
                attesting_peers: vec!["p".repeat(MAX_QUARANTINE_ATTESTING_PEER_BYTES + 1)],
            },
        );
        assert!(!direct, "direct quarantine writes reject oversized peer ids too");
        assert!(
            r.fetch_in(&realm, &hash).unwrap().quarantine.is_none(),
            "oversized direct quarantine marker was not retained"
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

    #[test]
    fn list_entries_artifact_snapshot_is_bounded_but_scoped_pulls_still_work() {
        let mut r = RegistryMem::new().with_max_snapshot_artifact_bytes(4);
        r.publish_in(RealmId::new("crew"), manifest("x"), b"xxx".to_vec());
        r.publish_in(RealmId::new("guests"), manifest("y"), b"yyy".to_vec());

        let env = op_env(RegistryOp::ListEntries { realm: None }, CreatureId(1));
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(env).dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("snapshot too large"), "{message}");
            }
            other => panic!("expected Error for over-cap snapshot, got {other:?}"),
        }

        let scoped =
            op_env(RegistryOp::ListEntries { realm: Some(RealmId::new("crew")) }, CreatureId(1));
        let reply: RegistryReply =
            serde_json::from_slice(&r.handle(scoped).dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Entries { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].realm, RealmId::new("crew"));
                assert_eq!(entries[0].artifact, b"xxx");
            }
            other => panic!("expected scoped Entries under cap, got {other:?}"),
        }

        assert_eq!(
            r.sync_entries(None).len(),
            2,
            "direct in-process snapshot helper keeps its historical unbounded behavior"
        );
    }

    #[test]
    fn list_metadata_snapshots_catalog_without_artifact_bytes() {
        let mut r = RegistryMem::new();
        r.publish_in(RealmId::new("crew"), manifest("x"), b"x-bytes".to_vec());
        r.publish_in(RealmId::new("guests"), manifest("y"), b"y-bytes".to_vec());

        let env =
            op_env(RegistryOp::ListMetadata { realm: Some(RealmId::new("guests")) }, CreatureId(1));
        let payload = r.handle(env).dispatches[0].payload.clone();
        let json = String::from_utf8(payload.clone()).unwrap();
        assert!(!json.contains("\"artifact\""), "metadata reply must not carry artifact bytes");

        match serde_json::from_slice::<RegistryReply>(&payload).unwrap() {
            RegistryReply::Metadata { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].realm, RealmId::new("guests"));
                assert_eq!(entries[0].manifest.name, "y");
                assert_eq!(entries[0].artifact_hash, sha256_hex(b"y-bytes"));
            }
            other => panic!("expected Metadata, got {other:?}"),
        }
    }

    #[test]
    fn fetch_metadata_returns_length_without_artifact_bytes() {
        let mut r = RegistryMem::new();
        let realm = RealmId::new("crew");
        let artifact = b"large-enough-to-not-inline".to_vec();
        let hash = r.publish_in(realm.clone(), manifest("meta"), artifact.clone());

        let env = op_env(
            RegistryOp::FetchMetadataInRealm { artifact_hash: hash.clone(), realm: realm.clone() },
            CreatureId(1),
        );
        let payload = r.handle(env).dispatches[0].payload.clone();
        let json = String::from_utf8(payload.clone()).unwrap();
        assert!(!json.contains("\"artifact\""), "metadata fetch must not carry artifact bytes");

        match serde_json::from_slice::<RegistryReply>(&payload).unwrap() {
            RegistryReply::FetchedMetadata { entry, artifact_len } => {
                assert_eq!(entry.realm, realm);
                assert_eq!(entry.artifact_hash, hash);
                assert_eq!(entry.manifest.name, "meta");
                assert_eq!(artifact_len, artifact.len());
            }
            other => panic!("expected FetchedMetadata, got {other:?}"),
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
        let metadata = RegistryOp::ListMetadata { realm: None };
        assert!(serde_json::to_string(&metadata).unwrap().contains("\"op\":\"list_metadata\""));
        let fetch_metadata = RegistryOp::FetchMetadata { artifact_hash: "h".into() };
        assert!(serde_json::to_string(&fetch_metadata)
            .unwrap()
            .contains("\"op\":\"fetch_metadata\""));
        let fetch_metadata_in_realm =
            RegistryOp::FetchMetadataInRealm { artifact_hash: "h".into(), realm: RealmId::local() };
        assert!(serde_json::to_string(&fetch_metadata_in_realm)
            .unwrap()
            .contains("\"op\":\"fetch_metadata_in_realm\""));
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
    fn oversized_registry_payload_is_rejected_before_json_parse() {
        let mut r = RegistryMem::new().with_max_op_bytes(8);
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
                schema: "registry.op".into(),
            },
            payload: b"{ not json".to_vec(),
        };
        let reply = r.handle(env);
        let reply: RegistryReply = serde_json::from_slice(&reply.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("too large"), "expected size error, got {message}")
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn oversized_publish_artifact_is_rejected_and_not_stored() {
        let mut r = RegistryMem::new().with_max_artifact_bytes(4);
        let bytes = b"12345".to_vec();
        let hash = sha256_hex(&bytes);

        let env = op_env(
            RegistryOp::Publish { manifest: manifest("too-big"), artifact: bytes.clone() },
            CreatureId(1),
        );
        let reply = r.handle(env);
        let reply: RegistryReply = serde_json::from_slice(&reply.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("artifact too large"), "unexpected error: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(r.fetch(&hash).is_none(), "oversized bus publish was not stored");

        let direct_hash = r.publish(manifest("direct-too-big"), bytes);
        assert_eq!(direct_hash, hash, "direct publish still reports the content address");
        assert!(r.fetch(&hash).is_none(), "oversized direct publish was not stored");
    }

    #[test]
    fn invalid_publish_manifest_is_rejected_and_not_stored() {
        let mut r = RegistryMem::new();
        let bytes = b"artifact-bytes".to_vec();
        let hash = sha256_hex(&bytes);
        let mut m = manifest("bad");
        m.name = "n".repeat(MAX_MANIFEST_NAME_BYTES + 1);

        let env = op_env(
            RegistryOp::Publish { manifest: m.clone(), artifact: bytes.clone() },
            CreatureId(1),
        );
        let reply = r.handle(env);
        let reply: RegistryReply = serde_json::from_slice(&reply.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("invalid manifest"), "unexpected error: {message}");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(r.fetch(&hash).is_none(), "invalid bus publish was not stored");

        let direct_hash = r.publish(m, bytes);
        assert_eq!(direct_hash, hash, "direct publish still reports the content address");
        assert!(r.fetch(&hash).is_none(), "invalid direct publish was not stored");
    }

    #[test]
    fn max_entries_refuses_new_artifact_at_capacity_but_allows_republish() {
        // Cap the catalog at 1 distinct entry. The first publish lands; a *new* artifact is refused
        // (not stored), but re-publishing an existing key still succeeds (resets signals in place,
        // no growth). `0` is the explicit unbounded opt-out.
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

    #[test]
    fn default_max_entries_is_bounded_and_zero_opt_out_is_unbounded() {
        let r = RegistryMem::new();

        for i in 0..DEFAULT_MAX_REGISTRY_ENTRIES {
            let bytes = format!("artifact-{i}").into_bytes();
            let h = r.publish(manifest(&format!("bounded-{i}")), bytes);
            assert!(r.fetch(&h).is_some(), "entry {i} stored under the default cap");
        }
        assert_eq!(r.len(), DEFAULT_MAX_REGISTRY_ENTRIES);

        let overflow_bytes = b"default-overflow".to_vec();
        let overflow_hash = r.publish(manifest("overflow"), overflow_bytes.clone());
        assert_eq!(overflow_hash, sha256_hex(&overflow_bytes));
        assert!(r.fetch(&overflow_hash).is_none(), "new entry refused at default capacity");
        assert_eq!(r.len(), DEFAULT_MAX_REGISTRY_ENTRIES);

        let existing_bytes = b"artifact-0".to_vec();
        let existing_hash = sha256_hex(&existing_bytes);
        let republish_hash = r.publish(manifest("bounded-0-republish"), existing_bytes);
        assert_eq!(republish_hash, existing_hash);
        assert!(r.fetch(&existing_hash).is_some(), "existing key can be re-published at capacity");
        assert_eq!(r.len(), DEFAULT_MAX_REGISTRY_ENTRIES);

        let unbounded = RegistryMem::new().with_max_entries(0);
        for i in 0..=DEFAULT_MAX_REGISTRY_ENTRIES {
            let bytes = format!("unbounded-artifact-{i}").into_bytes();
            let h = unbounded.publish(manifest(&format!("unbounded-{i}")), bytes);
            assert!(unbounded.fetch(&h).is_some(), "entry {i} stored under explicit opt-out");
        }
        assert_eq!(unbounded.len(), DEFAULT_MAX_REGISTRY_ENTRIES + 1);
    }
}
