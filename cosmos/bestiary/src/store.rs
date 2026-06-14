//! The durable store — the [`BestiaryStore`] trait and its [`FsBestiaryStore`] reference filling.
//!
//! `FsBestiaryStore` is a realm-hashed, signed-log, content-addressed on-disk Bestiary built on
//! `std::fs` alone. The shape mirrors the substrate's existing integrity discipline
//! (`abode::AbodeSnapshot`: a magic tag, a `signing_payload` with the signature cleared, a
//! determinism tripwire), applied to an append-only log.
//!
//! ## On-disk layout
//!
//! ```text
//! <root>/blobs/<artifact_hash>          content-addressed artifact bytes (deduped, atomic temp+rename)
//! <root>/log/<realm_hash>.jsonl         per-realm append-only signed LogRecord chain (one JSON/line)
//! <root>/log/<realm_hash>.head          advisory chain-tip hint {seq, hash} (truncation detector)
//! ```
//!
//! `realm_hash = sha256(realm.0.as_bytes())` hex. **A wire-sourced Realm is only ever hashed, never
//! path-joined** — [`RealmId`] permits `/` and `..`, so path-joining a peer-supplied Realm would be a
//! remote arbitrary-file-write primitive. The human Realm name is not trusted from the filename: every
//! [`LogRecord`] carries its own `realm`, and [`recover`](BestiaryStore::recover) re-derives
//! `sha256(record.realm)` and confirms it matches the file stem (a record filed under the wrong realm
//! hash is `Corrupt`). That makes a separate signed `realms.index` sidecar unnecessary — the records
//! self-describe their Realm and the filename is a validated hash, not a source of truth.
//! Artifact blobs are likewise not trusted just because their filename is a digest: every full blob
//! read is bounded by the configured artifact cap (or a stricter snapshot budget), recomputes
//! `sha256(bytes)`, and refuses a mismatch; a later publish of the same content rewrites a corrupt
//! existing blob instead of treating the path as valid dedupe. GX chunk serving uses bounded range
//! reads instead of re-reading and re-hashing the whole blob per chunk; the transfer plan still binds
//! the whole-file hash, and the receiver verifies it before admission.
//!
//! ## The self-owned journal
//!
//! Every [`LogRecord`] is signed by **this daemon's own** Abode key. `recover()` rejects any record
//! whose `author` is not us ([`StoreError::ForeignAuthor`]). The log is a self-owned journal, **not a
//! federation inbox** — peer entries arrive only via [`merge_push`](BestiaryStore::merge_push), where
//! they are verified and **re-signed under our identity** before being appended. This is at-rest
//! integrity hardening: a forged at-rest `Put` is still gated at creature LOAD by the
//! manifest-signature/calls admission gate before any `dlopen`. The journal proves "my durable record
//! is intact," nothing about peer trust.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::{Ed25519KeyMaterial, Ed25519Verifier, Manifest, RealmId, Verifier};

use crate::curator::{CurationContext, CurationDecision, Curator};
use crate::wire::{
    CatalogEntry, Entry, QuarantineNotice, ReputationScore, SyncEntry,
    MAX_QUARANTINE_ATTESTING_PEERS,
};
use crate::{registry_artifact_too_large_message, MAX_REGISTRY_ARTIFACT_BYTES};

/// Default maximum number of live `(realm, artifact_hash)` entries retained by [`FsBestiaryStore`].
///
/// `0` is reserved as an explicit opt-out via [`FsBestiaryStore::with_max_entries`].
pub const DEFAULT_MAX_BESTIARY_ENTRIES: usize = 1_024;

/// Maximum serialized bytes for one durable Bestiary log record line.
///
/// Artifact bytes live in content-addressed blobs, not in the JSONL journal. This cap is therefore
/// sized for a large manifest plus signature/chain metadata, and is enforced both when appending and
/// before `recover()` allocates a full line from disk.
pub const MAX_BESTIARY_LOG_RECORD_BYTES: usize = 4 * 1024 * 1024;

/// Maximum bytes read from the advisory `<realm_hash>.head` tip hint.
///
/// The JSONL chain is authoritative; the head file is only a crash/truncation hint containing
/// `"<next_seq> <64-byte-tip>"`, so oversized or malformed hints are ignored during recovery.
pub const MAX_BESTIARY_HEAD_BYTES: usize = 512;

/// 4-byte format tag, woven into the genesis chain root so a log can't be confused with another
/// line-oriented file and so the chain's first link is anchored to this format.
const BSTY_MAGIC: &str = "BSTY";

/// The `prev_hash` of the first record in a realm chain. Anchors the chain to the format tag.
fn genesis_prev() -> String {
    format!("{BSTY_MAGIC}:genesis:v1")
}

/// sha256 hex of bytes — the content-address formula (artifact key, realm-hash stem, record hash).
fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// The store's blob path component is a SHA-256 hex digest produced by [`sha256_hex`]. Keep that
/// contract local to the filesystem-backed store: wire payloads can be malformed, but they must
/// never become arbitrary path components or durable tombstone keys.
fn is_artifact_hash(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn invalid_artifact_hash(hash: &str) -> StoreError {
    StoreError::Integrity(format!(
        "invalid artifact_hash (len {}, expected 64 lowercase hex chars)",
        hash.len()
    ))
}

fn read_log_line_bounded<R: BufRead>(
    reader: &mut R,
    realm_hash: &str,
) -> Result<Option<String>, StoreError> {
    let mut out = Vec::new();
    loop {
        let available = reader.fill_buf().map_err(|e| StoreError::Io(e.to_string()))?;
        if available.is_empty() {
            if out.is_empty() {
                return Ok(None);
            }
            break;
        }

        let take = available.iter().position(|&b| b == b'\n').map_or(available.len(), |i| i + 1);
        if out.len().saturating_add(take) > MAX_BESTIARY_LOG_RECORD_BYTES {
            return Err(StoreError::Limit(format!(
                "{realm_hash}.jsonl log record exceeds {} byte limit",
                MAX_BESTIARY_LOG_RECORD_BYTES
            )));
        }
        let found_newline = available[..take].ends_with(b"\n");
        out.extend_from_slice(&available[..take]);
        reader.consume(take);
        if found_newline {
            break;
        }
    }

    if out.ends_with(b"\n") {
        out.pop();
        if out.ends_with(b"\r") {
            out.pop();
        }
    }
    String::from_utf8(out).map(Some).map_err(|e| {
        StoreError::Corrupt(format!("{realm_hash}.jsonl log record is not UTF-8: {e}"))
    })
}

fn encode_log_record_line(rec: &LogRecord) -> Result<Vec<u8>, StoreError> {
    let mut line = serde_json::to_vec(rec).map_err(|e| StoreError::Io(e.to_string()))?;
    line.push(b'\n');
    if line.len() > MAX_BESTIARY_LOG_RECORD_BYTES {
        return Err(StoreError::Limit(format!(
            "bestiary log record too large: {} bytes exceeds {} byte limit",
            line.len(),
            MAX_BESTIARY_LOG_RECORD_BYTES
        )));
    }
    Ok(line)
}

fn read_head_tip_bounded(path: &Path, realm_hash: &str) -> Option<String> {
    let f = File::open(path).ok()?;
    let mut bytes = Vec::new();
    let mut limited = f.take(MAX_BESTIARY_HEAD_BYTES as u64 + 1);
    if limited.read_to_end(&mut bytes).is_err() {
        return None;
    }
    if bytes.len() > MAX_BESTIARY_HEAD_BYTES {
        eprintln!(
            "bestiary: {realm_hash}.head exceeds {} byte limit (using the log)",
            MAX_BESTIARY_HEAD_BYTES
        );
        return None;
    }
    let text = String::from_utf8(bytes).ok()?;
    text.split_whitespace().nth(1).map(str::to_string)
}

/// Structured failure modes for the durable store. Distinct from a creature's admission/policy
/// errors: these refuse *before* any restore-into-catalog work — the bytes don't hash, a signature
/// doesn't verify, the chain is broken, a record is foreign-authored.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error("bestiary io error: {0}")]
    Io(String),
    /// Recomputed `sha256(artifact)` did not match the declared `artifact_hash`.
    #[error("bestiary integrity mismatch: {0}")]
    Integrity(String),
    /// A signature was present but did not verify under its declared key.
    #[error("bestiary bad signature: {0}")]
    BadSignature(String),
    /// A log record's `prev_hash`/`seq` did not chain onto the prior record (tamper / truncation).
    #[error("bestiary log chain broken: {0}")]
    ChainBroken(String),
    /// On-disk state was structurally unreadable (malformed JSON, a record filed under the wrong
    /// realm hash, …).
    #[error("bestiary corrupt on-disk state: {0}")]
    Corrupt(String),
    /// The catalog is at its `max_entries` cap and a new key was refused.
    #[error("bestiary at capacity: {0}")]
    Capacity(String),
    /// A caller asked the store to retain bytes beyond its configured bounds.
    #[error("bestiary limit exceeded: {0}")]
    Limit(String),
    /// A log record was authored by a key that is not this daemon's — the journal is self-owned, so a
    /// foreign record at rest is rejected (peer entries arrive only via verified, re-signed pushes).
    #[error("bestiary foreign-author log record: {0}")]
    ForeignAuthor(String),
}

/// A single mutation in a realm's append-only log. Each `LogOp` carries its Realm + artifact-hash key;
/// `Put` additionally carries the manifest (the artifact bytes live in the content-addressed blob
/// store, keyed by `artifact_hash`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum LogOp {
    /// Membership: this `(realm, artifact_hash)` exists, with this manifest. The manifest is boxed so
    /// the `Put` variant doesn't bloat every small `LogOp` on the stack; `Box<Manifest>` serializes
    /// byte-identically to `Manifest` (serde is transparent over `Box`), so the signed log wire is
    /// unchanged.
    Put { realm: RealmId, artifact_hash: String, manifest: Box<Manifest> },
    /// A reputation score on an existing entry.
    Attest { realm: RealmId, artifact_hash: String, score: ReputationScore },
    /// A reversible quarantine marker (sticky across federation).
    Quarantine { realm: RealmId, artifact_hash: String, notice: QuarantineNotice },
    /// Lift a quarantine (the only thing that clears it — an explicit, signed reversal).
    Unquarantine { realm: RealmId, artifact_hash: String },
    /// Permanent eviction. Federates; never silently resurrected by a later `Put`.
    Tombstone { realm: RealmId, artifact_hash: String },
}

impl LogOp {
    /// The Realm this op is about.
    pub fn realm(&self) -> &RealmId {
        match self {
            LogOp::Put { realm, .. }
            | LogOp::Attest { realm, .. }
            | LogOp::Quarantine { realm, .. }
            | LogOp::Unquarantine { realm, .. }
            | LogOp::Tombstone { realm, .. } => realm,
        }
    }
    /// The artifact-hash key this op is about.
    pub fn artifact_hash(&self) -> &str {
        match self {
            LogOp::Put { artifact_hash, .. }
            | LogOp::Attest { artifact_hash, .. }
            | LogOp::Quarantine { artifact_hash, .. }
            | LogOp::Unquarantine { artifact_hash, .. }
            | LogOp::Tombstone { artifact_hash, .. } => artifact_hash,
        }
    }
}

/// One tamper-evident record in a realm's chain. `prev_hash` commits to the prior record's
/// [`hash`](LogRecord::hash); `signature` is the daemon's Abode key over
/// [`signing_payload`](LogRecord::signing_payload) (the record with `signature` cleared).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LogRecord {
    /// Local chain position — **not** stable across compaction (a genesis rewrite renumbers it).
    pub seq: u64,
    /// The prior record's [`hash`](LogRecord::hash); the chain root is a fixed `BSTY` genesis anchor.
    pub prev_hash: String,
    /// What this record does.
    pub op: LogOp,
    /// The signer's Abode pubkey (hex). `recover` requires this to be the daemon itself.
    pub author: String,
    /// The entry's birth order — assigned once at first `Put` for a key, **never reassigned**, and
    /// preserved verbatim across compaction. Meaningless (`0`) for a `Tombstone`.
    pub first_seen: u64,
    /// ed25519 signature over [`signing_payload`](Self::signing_payload).
    pub signature: String,
}

impl LogRecord {
    /// Canonical bytes the signature commits to: the record with `signature` cleared. Same discipline
    /// as `abode::AbodeSnapshot::signing_payload`.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.signature = String::new();
        aether::wire::to_bytes(&clone)
    }

    /// The record's content hash — `sha256` over the full signed record. The next record's
    /// `prev_hash` commits to this, making the chain tamper-evident.
    pub fn hash(&self) -> String {
        sha256_hex(&aether::wire::to_bytes(self))
    }
}

/// A self-verifying entry for PUSH replication: the (optional) full [`SyncEntry`] payload plus the
/// originating daemon's signed [`LogRecord`] vouching for it. The receiver verifies both (content
/// hash + the foreign record's signature under its `author`), then merges and **re-signs under its
/// own identity** — the foreign record is never appended as-is. `sync` is `None` for a `Tombstone`
/// push (the record carries the `(realm, artifact_hash)` key; no bytes are needed to evict).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedSyncEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sync: Option<SyncEntry>,
    pub record: LogRecord,
}

/// A portable, signed attestation that an entry exists — survives compaction because it commits to
/// the compaction-stable `first_seen`, not to a chain position. An auditor verifies it against
/// `attester` without trusting the daemon. (Contrast a chain-inclusion proof, which a genesis rewrite
/// would invalidate — see the design note.)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct EntryProof {
    pub realm: RealmId,
    pub artifact_hash: String,
    /// The manifest identity (`Manifest::compute_content_address`), distinct from `artifact_hash`.
    pub manifest_hash: String,
    pub first_seen: u64,
    /// The daemon Abode pubkey (hex) that signed this attestation.
    pub attester: String,
    pub signature: String,
}

impl EntryProof {
    fn payload(
        realm: &RealmId,
        artifact_hash: &str,
        manifest_hash: &str,
        first_seen: u64,
        attester: &str,
    ) -> Vec<u8> {
        aether::wire::to_bytes(&(realm, artifact_hash, manifest_hash, first_seen, attester))
    }

    /// Whether this attestation verifies under `attester`.
    pub fn verify(&self, verifier: &dyn Verifier) -> bool {
        verifier.verify(
            &self.attester,
            &Self::payload(
                &self.realm,
                &self.artifact_hash,
                &self.manifest_hash,
                self.first_seen,
                &self.attester,
            ),
            &self.signature,
        )
    }
}

/// What a [`compact`](BestiaryStore::compact) pass did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CompactStats {
    /// Live entries scanned.
    pub scanned: usize,
    /// Entries the curator GC'd (tombstoned) this pass.
    pub gc: usize,
    /// Entries the curator quarantined this pass.
    pub quarantined: usize,
    /// Orphan blobs unlinked (not referenced by any live entry in any realm).
    pub blobs_removed: usize,
}

/// What a [`merge_push`](BestiaryStore::merge_push) did, for the daemon's `PushAck` + tests.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MergeOutcome {
    /// Membership changed (a new key landed, or a tombstone applied).
    pub membership_changed: bool,
    /// Reputation was updated (the pushed score was verified-greater than the local one).
    pub reputation_updated: bool,
    /// Quarantine was tightened (a sticky union added an attesting peer).
    pub quarantine_updated: bool,
}

/// One entry's metadata + bytes, snapshotted off the store lock so an [`AICurator`](crate::AICurator)
/// can run its (blocking) model call without blocking the catalog.
pub struct CurationSnapshot {
    pub realm: RealmId,
    pub artifact_hash: String,
    pub entry: Entry,
    pub first_seen: u64,
    pub head_first_seen: u64,
}

/// The durable Bestiary store. The `bestiary-daemon` binds an `Arc<dyn BestiaryStore>` to
/// `Role::REGISTRY`, serving every existing `RegistryOp` byte-identically while persisting,
/// replicating, and curating the catalog. `registry-mem` is the in-memory stub that fills the same
/// role; a test or demo picks one by which `Box<dyn Creature>` it loads.
pub trait BestiaryStore: Send + Sync {
    /// Publish `(realm, artifact)`; returns the `sha256(artifact)` hex key. A re-publish of an
    /// existing key preserves `first_seen` and the entry's signals (quarantine is **sticky** in the
    /// durable store, unlike the in-memory stub). A `Put` of a tombstoned key is refused (the hash is
    /// still returned, matching the stub's refuse-and-return-hash shape).
    fn put(
        &self,
        realm: &RealmId,
        manifest: Manifest,
        artifact: Vec<u8>,
    ) -> Result<String, StoreError>;
    /// Fetch the live entry for `(realm, artifact_hash)`, loading the artifact bytes from the blob
    /// store. `None` if absent or tombstoned.
    fn get(&self, realm: &RealmId, artifact_hash: &str) -> Result<Option<Entry>, StoreError>;
    /// Fetch the live entry metadata for `(realm, artifact_hash)` plus the artifact byte length.
    /// Does not read artifact bytes; it only stats the content-addressed blob to prove the stored row
    /// still has backing bytes.
    fn get_metadata(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
    ) -> Result<Option<(CatalogEntry, usize)>, StoreError>;
    /// Fetch live entry metadata for an operation that will serve artifact bytes.
    ///
    /// Unlike [`get_metadata`](BestiaryStore::get_metadata), this still avoids reading artifact
    /// bytes but enforces the configured artifact cap before advertising that the artifact is
    /// fetchable. Metadata/listing surfaces use `get_metadata`; transfer planning uses this method.
    fn get_fetch_metadata(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
    ) -> Result<Option<(CatalogEntry, usize)>, StoreError>;
    /// Read one byte range from a live artifact blob without materializing the whole artifact.
    ///
    /// This is the durable-store half of GX chunk serving. It proves the `(realm, artifact_hash)` row
    /// is live, enforces the configured artifact cap, checks the requested range against the current
    /// blob length, and reads only that range. It deliberately does not recompute the whole blob hash
    /// on every chunk; the GX plan binds the file hash and the receiver verifies the reassembled
    /// artifact before admission.
    fn get_artifact_chunk(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>, StoreError>;
    /// Snapshot live entries as [`SyncEntry`]s for anti-entropy pull. `realm: None` = all Realms.
    fn list(&self, realm: Option<&RealmId>) -> Result<Vec<SyncEntry>, StoreError>;
    /// Snapshot live entries under a total artifact-byte cap. `0` means unbounded.
    fn list_bounded(
        &self,
        realm: Option<&RealmId>,
        max_artifact_bytes: usize,
    ) -> Result<Vec<SyncEntry>, StoreError>;
    /// Snapshot live entry metadata for control/catalog listing. Does not read artifact blobs.
    fn list_metadata(&self, realm: Option<&RealmId>) -> Result<Vec<CatalogEntry>, StoreError>;
    /// Attach/replace a reputation score on an existing entry. `false` if absent/tombstoned or the
    /// score is non-finite (defense-in-depth: a non-finite score never enters the trust store).
    fn attest(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        score: ReputationScore,
    ) -> Result<bool, StoreError>;
    /// Mark an existing entry quarantined; the attesting-peer set is **accumulated** (sticky union).
    /// `false` if absent/tombstoned.
    fn quarantine(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        notice: QuarantineNotice,
    ) -> Result<bool, StoreError>;
    /// Lift a quarantine (the explicit, signed reversal — the only thing that clears it). `false` if
    /// absent or not quarantined.
    fn unquarantine(&self, realm: &RealmId, artifact_hash: &str) -> Result<bool, StoreError>;
    /// Permanently evict an entry. Federates; never silently resurrected by a later `Put`. `false` if
    /// already tombstoned.
    fn tombstone(&self, realm: &RealmId, artifact_hash: &str) -> Result<bool, StoreError>;
    /// Merge a pushed, self-verifying entry from a peer. Verifies content hash + the foreign record's
    /// signature, then merges (membership union, verified-greater reputation, sticky-union quarantine,
    /// permanent tombstone) and re-signs under our own identity. `Err` rejects a tampered push.
    fn merge_push(&self, entry: SignedSyncEntry) -> Result<MergeOutcome, StoreError>;
    /// Build the self-verifying push payload for live entries + tombstones (the PUSH replication
    /// diff). `realm: None` = all Realms.
    fn signed_entries(&self, realm: Option<&RealmId>) -> Result<Vec<SignedSyncEntry>, StoreError> {
        self.signed_entries_bounded(realm, 0, 0)
    }
    /// Build a self-verifying push payload under snapshot caps. `0` means unbounded for either cap.
    fn signed_entries_bounded(
        &self,
        realm: Option<&RealmId>,
        max_artifact_bytes: usize,
        max_entries: usize,
    ) -> Result<Vec<SignedSyncEntry>, StoreError>;
    /// Replay + verify the on-disk log at bind; returns the number of records replayed.
    fn recover(&self) -> Result<usize, StoreError>;
    /// Flush durable state (fsync) at shutdown.
    fn flush(&self) -> Result<(), StoreError>;
    /// A standalone signed [`EntryProof`]. `None` if the entry is absent/tombstoned.
    fn prove(&self, realm: &RealmId, artifact_hash: &str)
        -> Result<Option<EntryProof>, StoreError>;
    /// Snapshot live entries (with bytes) for an off-lock curator [`observe`](Curator::observe) pass.
    fn snapshot_for_curation(&self) -> Result<Vec<CurationSnapshot>, StoreError> {
        self.snapshot_for_curation_bounded(0)
    }
    /// Snapshot live entries for curation under a total artifact-byte cap. `0` means unbounded.
    fn snapshot_for_curation_bounded(
        &self,
        max_artifact_bytes: usize,
    ) -> Result<Vec<CurationSnapshot>, StoreError>;
    /// Run a GC pass: apply the curator's decision per entry, rewrite the genesis chains (preserving
    /// `first_seen`), and unlink orphan blobs (global union across all realms).
    fn compact(&self, curator: &dyn Curator) -> Result<CompactStats, StoreError>;
}

/// One live catalog row's in-memory view. The artifact bytes are not held — they live in the
/// content-addressed blob store and are loaded on `get`/`list`.
#[derive(Clone)]
struct Live {
    manifest: Manifest,
    reputation: Option<ReputationScore>,
    quarantine: Option<QuarantineNotice>,
    first_seen: u64,
}

/// A `(realm, artifact_hash) → live entry` snapshot row — a named alias so the snapshot-then-process
/// paths (`list`, `signed_entries`, `snapshot_for_curation`) don't write the nested tuple type inline.
type LiveRow = ((RealmId, String), Live);

/// A realm chain's tip: the next seq to assign and the hash of the last record (= next `prev_hash`).
#[derive(Clone)]
struct Head {
    next_seq: u64,
    tip_hash: String,
}

impl Default for Head {
    fn default() -> Self {
        Head { next_seq: 0, tip_hash: genesis_prev() }
    }
}

#[derive(Default)]
struct Inner {
    /// (realm, artifact_hash) → live entry.
    entries: HashMap<(RealmId, String), Live>,
    /// Permanently-evicted keys — refuse a `Put`, federate the eviction, never resurrect.
    tombstones: HashSet<(RealmId, String)>,
    /// realm_hash → human Realm name (rebuilt from the records, never trusted from a filename).
    realms: HashMap<String, RealmId>,
    /// realm_hash → chain tip.
    heads: HashMap<String, Head>,
    /// The next birth order to assign at a first `Put`. Monotonic; continues across restart.
    next_first_seen: u64,
}

/// The reference filling: a realm-hashed, signed-log, content-addressed on-disk Bestiary.
pub struct FsBestiaryStore {
    root: PathBuf,
    abode_key: Ed25519KeyMaterial,
    pubkey: String,
    /// Live-entry cap. A new key past it is refused; `0` means unbounded.
    max_entries: usize,
    /// `0` = unbounded; otherwise the largest artifact blob this store will retain.
    max_artifact_bytes: usize,
    /// Per-process unique suffix source for atomic temp files (no clock/rng needed).
    tmp_seq: AtomicU64,
    inner: Mutex<Inner>,
}

impl FsBestiaryStore {
    /// Open (creating if needed) a store rooted at `root`, signing its journal with `abode_key`. Does
    /// not replay — call [`recover`](BestiaryStore::recover) (the daemon does so at bind).
    pub fn new(
        root: impl Into<PathBuf>,
        abode_key: Ed25519KeyMaterial,
    ) -> Result<Self, StoreError> {
        let root = root.into();
        let pubkey = abode_key.public_hex().to_string();
        let store = FsBestiaryStore {
            root,
            abode_key,
            pubkey,
            max_entries: DEFAULT_MAX_BESTIARY_ENTRIES,
            max_artifact_bytes: MAX_REGISTRY_ARTIFACT_BYTES,
            tmp_seq: AtomicU64::new(0),
            inner: Mutex::new(Inner::default()),
        };
        fs::create_dir_all(store.blobs_dir()).map_err(|e| StoreError::Io(e.to_string()))?;
        fs::create_dir_all(store.log_dir()).map_err(|e| StoreError::Io(e.to_string()))?;
        Ok(store)
    }

    /// Cap the number of distinct catalog entries.
    ///
    /// The default is [`DEFAULT_MAX_BESTIARY_ENTRIES`]. At capacity a `Put` of a *new* key is
    /// refused; re-publishing an existing key always succeeds. Pass `0` to opt out and make the
    /// live-entry catalog unbounded.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Cap stored artifact bytes (default [`MAX_REGISTRY_ARTIFACT_BYTES`]). `0` means unbounded.
    pub fn with_max_artifact_bytes(mut self, max_artifact_bytes: usize) -> Self {
        self.max_artifact_bytes = max_artifact_bytes;
        self
    }

    /// This store's Abode pubkey (hex) — the journal author + proof attester.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    // ---- paths (a wire-sourced realm is ONLY ever hashed, never path-joined) ----

    fn blobs_dir(&self) -> PathBuf {
        self.root.join("blobs")
    }
    fn log_dir(&self) -> PathBuf {
        self.root.join("log")
    }
    fn blob_path(&self, artifact_hash: &str) -> PathBuf {
        self.blobs_dir().join(artifact_hash)
    }
    fn realm_hash(realm: &RealmId) -> String {
        sha256_hex(realm.0.as_bytes())
    }
    fn log_path(&self, realm_hash: &str) -> PathBuf {
        self.log_dir().join(format!("{realm_hash}.jsonl"))
    }
    fn head_path(&self, realm_hash: &str) -> PathBuf {
        self.log_dir().join(format!("{realm_hash}.head"))
    }

    fn unique_tmp(&self, dir: &Path, stem: &str) -> PathBuf {
        let n = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        dir.join(format!(".{stem}.{}.{n}.tmp", std::process::id()))
    }

    /// Write `bytes` atomically to `dest` (temp file in the same dir + rename), fsyncing both.
    fn atomic_write(&self, dest: &Path, bytes: &[u8]) -> Result<(), StoreError> {
        let dir = dest.parent().ok_or_else(|| StoreError::Io("no parent dir".into()))?;
        let stem = dest.file_name().and_then(|s| s.to_str()).unwrap_or("f");
        let tmp = self.unique_tmp(dir, stem);
        {
            let mut f = File::create(&tmp).map_err(|e| StoreError::Io(e.to_string()))?;
            f.write_all(bytes).map_err(|e| StoreError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| StoreError::Io(e.to_string()))?;
        }
        fs::rename(&tmp, dest).map_err(|e| StoreError::Io(e.to_string()))?;
        fsync_dir(dir);
        Ok(())
    }

    fn write_blob(&self, artifact_hash: &str, artifact: &[u8]) -> Result<(), StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Err(invalid_artifact_hash(artifact_hash));
        }
        let path = self.blob_path(artifact_hash);
        if path.exists() {
            match self.read_blob(artifact_hash) {
                Ok(_) => return Ok(()), // content-addressed dedupe: identical bytes already on disk
                Err(err) => {
                    eprintln!(
                        "bestiary: rewriting corrupt or unreadable blob {artifact_hash}: {err}"
                    );
                }
            }
        }
        self.atomic_write(&path, artifact)
    }

    fn read_blob(&self, artifact_hash: &str) -> Result<Vec<u8>, StoreError> {
        self.read_blob_bounded(artifact_hash, self.max_artifact_bytes)
    }

    fn read_blob_bounded(
        &self,
        artifact_hash: &str,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Err(invalid_artifact_hash(artifact_hash));
        }
        let path = self.blob_path(artifact_hash);
        let mut file = File::open(&path)
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}")))?;
        let mut bytes = Vec::new();
        if max_bytes == 0 {
            file.read_to_end(&mut bytes).map_err(|e| {
                StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}"))
            })?;
        } else {
            let read_limit =
                u64::try_from(max_bytes).ok().and_then(|n| n.checked_add(1)).unwrap_or(u64::MAX);
            let mut limited = file.take(read_limit);
            limited.read_to_end(&mut bytes).map_err(|e| {
                StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}"))
            })?;
            if bytes.len() > max_bytes {
                return Err(StoreError::Limit(registry_artifact_too_large_message(
                    bytes.len(),
                    max_bytes,
                )));
            }
        }
        let actual = sha256_hex(&bytes);
        if actual != artifact_hash {
            return Err(StoreError::Integrity(format!(
                "blob {artifact_hash} content hash mismatch: got {actual}"
            )));
        }
        Ok(bytes)
    }

    fn blob_len(&self, artifact_hash: &str) -> Result<usize, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Err(invalid_artifact_hash(artifact_hash));
        }
        let meta = fs::metadata(self.blob_path(artifact_hash))
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}")))?;
        usize::try_from(meta.len()).map_err(|_| {
            StoreError::Corrupt(format!("blob {artifact_hash} length does not fit usize"))
        })
    }

    fn fetchable_blob_len(&self, artifact_hash: &str) -> Result<usize, StoreError> {
        let blob_len = self.blob_len(artifact_hash)?;
        if self.max_artifact_bytes != 0 && blob_len > self.max_artifact_bytes {
            return Err(StoreError::Limit(registry_artifact_too_large_message(
                blob_len,
                self.max_artifact_bytes,
            )));
        }
        Ok(blob_len)
    }

    fn read_blob_range(
        &self,
        artifact_hash: &str,
        offset: u64,
        len: usize,
    ) -> Result<Vec<u8>, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Err(invalid_artifact_hash(artifact_hash));
        }
        let blob_len = self.fetchable_blob_len(artifact_hash)?;
        let offset_usize = usize::try_from(offset).map_err(|_| {
            StoreError::Corrupt(format!(
                "blob {artifact_hash} chunk offset {offset} does not fit usize"
            ))
        })?;
        let end = offset_usize.checked_add(len).ok_or_else(|| {
            StoreError::Corrupt(format!("blob {artifact_hash} chunk range overflows usize"))
        })?;
        if offset_usize > blob_len || end > blob_len {
            return Err(StoreError::Corrupt(format!(
                "blob {artifact_hash} chunk range {offset_usize}..{end} exceeds blob length {blob_len}"
            )));
        }
        let mut bytes = vec![0u8; len];
        if len == 0 {
            return Ok(bytes);
        }
        let mut file = File::open(self.blob_path(artifact_hash))
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}")))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} seek failed: {e}")))?;
        file.read_exact(&mut bytes)
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}")))?;
        Ok(bytes)
    }

    /// Append a record for `op`/`first_seen` to its realm chain (sign, write, advance the head).
    /// Caller holds the inner lock and has already updated the in-memory state.
    fn append(&self, inner: &mut Inner, op: LogOp, first_seen: u64) -> Result<(), StoreError> {
        let realm_hash = Self::realm_hash(op.realm());
        let head = inner.heads.entry(realm_hash.clone()).or_default().clone();
        let mut rec = LogRecord {
            seq: head.next_seq,
            prev_hash: head.tip_hash,
            op,
            author: self.pubkey.clone(),
            first_seen,
            signature: String::new(),
        };
        rec.signature = self.abode_key.sign(&rec.signing_payload());
        let rec_hash = rec.hash();

        let line = encode_log_record_line(&rec)?;
        let log_path = self.log_path(&realm_hash);
        {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            f.write_all(&line).map_err(|e| StoreError::Io(e.to_string()))?;
            f.sync_all().map_err(|e| StoreError::Io(e.to_string()))?;
        }
        let new_head = Head { next_seq: head.next_seq + 1, tip_hash: rec_hash };
        // Advisory tip hint (truncation detector) — best-effort, the jsonl is authoritative.
        let _ = self.atomic_write(
            &self.head_path(&realm_hash),
            format!("{} {}", new_head.next_seq, new_head.tip_hash).as_bytes(),
        );
        inner.heads.insert(realm_hash, new_head);
        Ok(())
    }

    /// Apply one op to the in-memory state (no log write). Shared by `recover` (replay) and, after a
    /// successful `append`, by the write paths.
    fn apply(inner: &mut Inner, op: &LogOp, first_seen: u64) {
        let realm = op.realm().clone();
        inner.realms.insert(Self::realm_hash(&realm), realm.clone());
        let key = (realm, op.artifact_hash().to_string());
        match op {
            LogOp::Put { manifest, .. } => {
                if inner.tombstones.contains(&key) {
                    return; // a tombstoned key is never resurrected by a Put
                }
                match inner.entries.get_mut(&key) {
                    Some(live) => {
                        // Re-Put: update the manifest, preserve first_seen + signals (sticky).
                        live.manifest = (**manifest).clone();
                    }
                    None => {
                        inner.entries.insert(
                            key,
                            Live {
                                manifest: (**manifest).clone(),
                                reputation: None,
                                quarantine: None,
                                first_seen,
                            },
                        );
                    }
                }
            }
            LogOp::Attest { score, .. } => {
                if let Some(live) = inner.entries.get_mut(&key) {
                    live.reputation = Some(score.clone());
                }
            }
            LogOp::Quarantine { notice, .. } => {
                if let Some(live) = inner.entries.get_mut(&key) {
                    live.quarantine = Some(notice.clone());
                }
            }
            LogOp::Unquarantine { .. } => {
                if let Some(live) = inner.entries.get_mut(&key) {
                    live.quarantine = None;
                }
            }
            LogOp::Tombstone { .. } => {
                inner.entries.remove(&key);
                inner.tombstones.insert(key);
            }
        }
    }

    fn live_entry(inner: &Inner, key: &(RealmId, String)) -> Option<Live> {
        inner.entries.get(key).cloned()
    }
}

/// Best-effort directory fsync so a rename is durable. Failure is logged, not fatal (some filesystems
/// don't support O_DIRECTORY fsync; the data write already synced).
fn fsync_dir(dir: &Path) {
    if let Ok(f) = File::open(dir) {
        let _ = f.sync_all();
    }
}

impl BestiaryStore for FsBestiaryStore {
    fn put(
        &self,
        realm: &RealmId,
        manifest: Manifest,
        artifact: Vec<u8>,
    ) -> Result<String, StoreError> {
        if self.max_artifact_bytes != 0 && artifact.len() > self.max_artifact_bytes {
            return Err(StoreError::Limit(registry_artifact_too_large_message(
                artifact.len(),
                self.max_artifact_bytes,
            )));
        }
        manifest.validate().map_err(|e| StoreError::Limit(format!("invalid manifest: {e}")))?;
        let hash = sha256_hex(&artifact);
        let key = (realm.clone(), hash.clone());
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());

        if inner.tombstones.contains(&key) {
            eprintln!("bestiary: refusing Put of tombstoned {hash} in realm {}", realm.0);
            return Ok(hash);
        }
        let is_new = !inner.entries.contains_key(&key);
        if is_new && self.max_entries != 0 && inner.entries.len() >= self.max_entries {
            // Refuse-new with a wire-honest error (matches `registry-mem`, which returns
            // `RegistryReply::Error`): the daemon maps this to a structured failure rather than a
            // false `Published`. A re-publish of an existing key never reaches here (it is not new).
            return Err(StoreError::Capacity(format!(
                "catalog at capacity ({}); refused new artifact {hash} in realm {}",
                self.max_entries, realm.0
            )));
        }

        self.write_blob(&hash, &artifact)?;
        let first_seen = if is_new {
            let fs = inner.next_first_seen;
            inner.next_first_seen += 1;
            fs
        } else {
            inner.entries.get(&key).map(|l| l.first_seen).unwrap_or(0)
        };
        let op = LogOp::Put {
            realm: realm.clone(),
            artifact_hash: hash.clone(),
            manifest: Box::new(manifest),
        };
        self.append(&mut inner, op.clone(), first_seen)?;
        Self::apply(&mut inner, &op, first_seen);
        Ok(hash)
    }

    fn get(&self, realm: &RealmId, artifact_hash: &str) -> Result<Option<Entry>, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Ok(None);
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let live = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Self::live_entry(&inner, &key)
        };
        match live {
            Some(live) => {
                let artifact = self.read_blob(artifact_hash)?;
                Ok(Some(Entry {
                    manifest: live.manifest,
                    artifact,
                    reputation: live.reputation,
                    quarantine: live.quarantine,
                }))
            }
            None => Ok(None),
        }
    }

    fn get_metadata(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
    ) -> Result<Option<(CatalogEntry, usize)>, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Ok(None);
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let live = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Self::live_entry(&inner, &key)
        };
        let Some(live) = live else {
            return Ok(None);
        };
        let artifact_len = self.blob_len(artifact_hash)?;
        Ok(Some((
            CatalogEntry {
                artifact_hash: artifact_hash.to_string(),
                realm: realm.clone(),
                manifest: live.manifest,
                reputation: live.reputation,
                quarantine: live.quarantine,
            },
            artifact_len,
        )))
    }

    fn get_fetch_metadata(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
    ) -> Result<Option<(CatalogEntry, usize)>, StoreError> {
        match self.get_metadata(realm, artifact_hash)? {
            Some((entry, _)) => {
                let artifact_len = self.fetchable_blob_len(artifact_hash)?;
                Ok(Some((entry, artifact_len)))
            }
            None => Ok(None),
        }
    }

    fn get_artifact_chunk(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        offset: u64,
        len: usize,
    ) -> Result<Option<Vec<u8>>, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Ok(None);
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let is_live = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Self::live_entry(&inner, &key).is_some()
        };
        if !is_live {
            return Ok(None);
        }
        self.read_blob_range(artifact_hash, offset, len).map(Some)
    }

    fn list(&self, realm: Option<&RealmId>) -> Result<Vec<SyncEntry>, StoreError> {
        self.list_bounded(realm, 0)
    }

    fn list_bounded(
        &self,
        realm: Option<&RealmId>,
        max_artifact_bytes: usize,
    ) -> Result<Vec<SyncEntry>, StoreError> {
        let rows: Vec<((RealmId, String), Live)> = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            inner
                .entries
                .iter()
                .filter(|((r, _), _)| realm.is_none() || realm == Some(r))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let mut artifact_bytes = 0usize;
        if max_artifact_bytes != 0 {
            for ((_, hash), _) in &rows {
                let len = self.blob_len(hash)?;
                artifact_bytes = artifact_bytes.saturating_add(len);
                if artifact_bytes > max_artifact_bytes {
                    return Err(StoreError::Limit(format!(
                        "bestiary snapshot too large: {artifact_bytes} artifact bytes exceeds {max_artifact_bytes} byte limit"
                    )));
                }
            }
        }
        let mut out = Vec::with_capacity(rows.len());
        let mut read_artifact_bytes = 0usize;
        for ((r, hash), live) in rows {
            let read_limit = max_artifact_bytes.saturating_sub(read_artifact_bytes);
            let artifact = if max_artifact_bytes == 0 {
                self.read_blob(&hash)?
            } else {
                self.read_blob_bounded(&hash, read_limit)?
            };
            if max_artifact_bytes != 0 {
                read_artifact_bytes = read_artifact_bytes.saturating_add(artifact.len());
            }
            out.push(SyncEntry {
                artifact_hash: hash,
                realm: r,
                manifest: live.manifest,
                artifact,
                reputation: live.reputation,
                quarantine: live.quarantine,
            });
        }
        Ok(out)
    }

    fn list_metadata(&self, realm: Option<&RealmId>) -> Result<Vec<CatalogEntry>, StoreError> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Ok(inner
            .entries
            .iter()
            .filter(|((r, _), _)| realm.is_none() || realm == Some(r))
            .map(|((r, hash), live)| CatalogEntry {
                artifact_hash: hash.clone(),
                realm: r.clone(),
                manifest: live.manifest.clone(),
                reputation: live.reputation.clone(),
                quarantine: live.quarantine.clone(),
            })
            .collect())
    }

    fn attest(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        score: ReputationScore,
    ) -> Result<bool, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Ok(false);
        }
        if let Some(message) = score.attest_shape_error(artifact_hash, realm) {
            eprintln!(
                "bestiary: rejected reputation signal for {artifact_hash} in realm {}: {message}",
                realm.0,
            );
            return Ok(false);
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !inner.entries.contains_key(&key) {
            return Ok(false);
        }
        let first_seen = inner.entries.get(&key).map(|l| l.first_seen).unwrap_or(0);
        let op =
            LogOp::Attest { realm: realm.clone(), artifact_hash: artifact_hash.to_string(), score };
        self.append(&mut inner, op.clone(), first_seen)?;
        Self::apply(&mut inner, &op, first_seen);
        Ok(true)
    }

    fn quarantine(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
        notice: QuarantineNotice,
    ) -> Result<bool, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Ok(false);
        }
        if let Some(message) = QuarantineNotice::mark_shape_error(
            artifact_hash,
            realm,
            &notice.reason,
            &notice.attesting_peers,
        ) {
            return Err(StoreError::Limit(message));
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let Some(live) = inner.entries.get(&key) else {
            return Ok(false);
        };
        // Sticky union: accumulate the attesting-peer set, never drop an existing signal.
        let mut merged = notice;
        if let Some(existing) = &live.quarantine {
            for p in &existing.attesting_peers {
                if !merged.attesting_peers.contains(p) {
                    if merged.attesting_peers.len() >= MAX_QUARANTINE_ATTESTING_PEERS {
                        return Err(StoreError::Limit(format!(
                            "quarantine attesting_peers too large after merge: {} peers exceeds {} peer limit",
                            merged.attesting_peers.len() + 1,
                            MAX_QUARANTINE_ATTESTING_PEERS
                        )));
                    }
                    merged.attesting_peers.push(p.clone());
                }
            }
        }
        if let Some(message) = merged.shape_error() {
            return Err(StoreError::Limit(message));
        }
        let first_seen = live.first_seen;
        let op = LogOp::Quarantine {
            realm: realm.clone(),
            artifact_hash: artifact_hash.to_string(),
            notice: merged,
        };
        self.append(&mut inner, op.clone(), first_seen)?;
        Self::apply(&mut inner, &op, first_seen);
        Ok(true)
    }

    fn unquarantine(&self, realm: &RealmId, artifact_hash: &str) -> Result<bool, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Ok(false);
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        match inner.entries.get(&key) {
            Some(live) if live.quarantine.is_some() => {
                let first_seen = live.first_seen;
                let op = LogOp::Unquarantine {
                    realm: realm.clone(),
                    artifact_hash: artifact_hash.to_string(),
                };
                self.append(&mut inner, op.clone(), first_seen)?;
                Self::apply(&mut inner, &op, first_seen);
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    fn tombstone(&self, realm: &RealmId, artifact_hash: &str) -> Result<bool, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Err(invalid_artifact_hash(artifact_hash));
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if inner.tombstones.contains(&key) {
            return Ok(false);
        }
        let op =
            LogOp::Tombstone { realm: realm.clone(), artifact_hash: artifact_hash.to_string() };
        self.append(&mut inner, op.clone(), 0)?;
        Self::apply(&mut inner, &op, 0);
        Ok(true)
    }

    fn merge_push(&self, entry: SignedSyncEntry) -> Result<MergeOutcome, StoreError> {
        let verifier = Ed25519Verifier;
        let record = &entry.record;
        // 1. The foreign record must be self-verifying under its declared author.
        if !verifier.verify(&record.author, &record.signing_payload(), &record.signature) {
            return Err(StoreError::BadSignature(format!(
                "pushed record for {} did not verify under {}",
                record.op.artifact_hash(),
                record.author
            )));
        }
        let realm = record.op.realm().clone();
        let hash = record.op.artifact_hash().to_string();
        if !is_artifact_hash(&hash) {
            return Err(invalid_artifact_hash(&hash));
        }

        match &record.op {
            LogOp::Tombstone { .. } => {
                // A tombstone push needs no bytes — it permanently evicts the key.
                let changed = self.tombstone(&realm, &hash)?;
                Ok(MergeOutcome { membership_changed: changed, ..Default::default() })
            }
            LogOp::Put { manifest, .. } => {
                let sync = entry
                    .sync
                    .ok_or_else(|| StoreError::Corrupt("Put push carried no SyncEntry".into()))?;
                if self.max_artifact_bytes != 0 && sync.artifact.len() > self.max_artifact_bytes {
                    return Err(StoreError::Limit(registry_artifact_too_large_message(
                        sync.artifact.len(),
                        self.max_artifact_bytes,
                    )));
                }
                // 2. Content integrity: the bytes must hash to the declared key, and the record + sync
                //    must agree on the key.
                if sha256_hex(&sync.artifact) != hash
                    || sync.artifact_hash != hash
                    || sync.realm != realm
                {
                    return Err(StoreError::Integrity(format!(
                        "pushed entry {hash} failed content/key integrity"
                    )));
                }
                if sync.manifest != **manifest {
                    return Err(StoreError::Integrity(format!(
                        "pushed entry {hash} manifest disagrees with its signed record"
                    )));
                }
                let mut outcome = MergeOutcome::default();
                // Membership union (re-signed under our identity inside put()). `membership_changed`
                // is true only if a *new* live key actually landed: `put` is a silent no-op for a
                // tombstoned key (a peer re-pushing something we permanently evicted), so compare the
                // live presence before AND after rather than trusting the put was applied.
                let was_present = self.get(&realm, &hash)?.is_some();
                match self.put(&realm, sync.manifest.clone(), sync.artifact.clone()) {
                    Ok(_) => {}
                    // A full catalog refuses a *new* pushed key. Lattice merge is best-effort, so
                    // skip this entry (nothing landed) rather than failing the whole push batch.
                    Err(StoreError::Capacity(msg)) => {
                        eprintln!(
                            "bestiary: dropping pushed entry {hash} in realm {}: {msg}",
                            realm.0
                        );
                        return Ok(outcome);
                    }
                    Err(e) => return Err(e),
                }
                let now_present = self.get(&realm, &hash)?.is_some();
                outcome.membership_changed = !was_present && now_present;
                // Reputation: take the verified-greater (a bare/unsigned or lesser score never clobbers).
                if let Some(incoming) = &sync.reputation {
                    if incoming.promotion_verifies(&hash, &realm, &verifier) {
                        let local = self.get(&realm, &hash)?.and_then(|e| e.reputation);
                        let local_ok = local
                            .as_ref()
                            .map(|r| r.promotion_verifies(&hash, &realm, &verifier))
                            .unwrap_or(false);
                        let take = match (&local, local_ok) {
                            (Some(l), true) => incoming.score > l.score,
                            _ => true, // no local verified score → take the verified incoming one
                        };
                        if take && self.attest(&realm, &hash, incoming.clone())? {
                            outcome.reputation_updated = true;
                        }
                    }
                }
                // Quarantine: sticky union (never cleared by a push). A shape/peer-cap rejection here
                // must not discard the membership + reputation we already persisted above: the cap
                // check returns *before* any apply, so the existing local marker is untouched. Log the
                // dropped defense signal and keep the rest of the merge — mirrors the best-effort
                // `put` Capacity skip above rather than failing the whole entry (which the daemon would
                // miscount as a generic `rejected` even though membership + reputation landed).
                if let Some(q) = &sync.quarantine {
                    match self.quarantine(&realm, &hash, q.clone()) {
                        Ok(true) => outcome.quarantine_updated = true,
                        Ok(false) => {}
                        Err(StoreError::Limit(msg)) => {
                            eprintln!(
                                "bestiary: pushed entry {hash} in realm {} merged, but its quarantine \
                                 signal was dropped over a shape cap: {msg}",
                                realm.0
                            );
                        }
                        Err(e) => return Err(e),
                    }
                }
                Ok(outcome)
            }
            other => Err(StoreError::Corrupt(format!("unexpected pushed op: {other:?}"))),
        }
    }

    fn signed_entries_bounded(
        &self,
        realm: Option<&RealmId>,
        max_artifact_bytes: usize,
        max_entries: usize,
    ) -> Result<Vec<SignedSyncEntry>, StoreError> {
        let (live_rows, tombstones): (Vec<LiveRow>, Vec<(RealmId, String)>) = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            let live = inner
                .entries
                .iter()
                .filter(|((r, _), _)| realm.is_none() || realm == Some(r))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            let tomb = inner
                .tombstones
                .iter()
                .filter(|(r, _)| realm.is_none() || realm == Some(r))
                .cloned()
                .collect();
            (live, tomb)
        };
        let total_entries = live_rows.len().saturating_add(tombstones.len());
        if max_entries != 0 && total_entries > max_entries {
            return Err(StoreError::Limit(format!(
                "bestiary push snapshot too many entries: {total_entries} entries exceeds {max_entries} entry limit"
            )));
        }
        let mut artifact_bytes = 0usize;
        if max_artifact_bytes != 0 {
            for ((_, hash), _) in &live_rows {
                let len = self.blob_len(hash)?;
                artifact_bytes = artifact_bytes.saturating_add(len);
                if artifact_bytes > max_artifact_bytes {
                    return Err(StoreError::Limit(format!(
                        "bestiary push snapshot too large: {artifact_bytes} artifact bytes exceeds {max_artifact_bytes} byte limit"
                    )));
                }
            }
        }
        let mut out = Vec::with_capacity(total_entries);
        let mut read_artifact_bytes = 0usize;
        for ((r, hash), live) in live_rows {
            let read_limit = max_artifact_bytes.saturating_sub(read_artifact_bytes);
            let artifact = if max_artifact_bytes == 0 {
                self.read_blob(&hash)?
            } else {
                self.read_blob_bounded(&hash, read_limit)?
            };
            if max_artifact_bytes != 0 {
                read_artifact_bytes = read_artifact_bytes.saturating_add(artifact.len());
            }
            let sync = SyncEntry {
                artifact_hash: hash.clone(),
                realm: r.clone(),
                manifest: live.manifest.clone(),
                artifact,
                reputation: live.reputation.clone(),
                quarantine: live.quarantine.clone(),
            };
            let record = self.sign_op(
                LogOp::Put { realm: r, artifact_hash: hash, manifest: Box::new(live.manifest) },
                live.first_seen,
            );
            out.push(SignedSyncEntry { sync: Some(sync), record });
        }
        for (r, hash) in tombstones {
            let record = self.sign_op(LogOp::Tombstone { realm: r, artifact_hash: hash }, 0);
            out.push(SignedSyncEntry { sync: None, record });
        }
        Ok(out)
    }

    fn recover(&self) -> Result<usize, StoreError> {
        let verifier = Ed25519Verifier;
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        *inner = Inner::default();
        let mut count = 0usize;
        let mut max_first_seen = 0u64;

        let dir = self.log_dir();
        let read = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => return Ok(0), // no log dir yet → empty store
        };
        // Collect+sort the jsonl files for deterministic replay order across realms.
        let mut files: Vec<(String, PathBuf)> = Vec::new();
        for ent in read {
            let ent = ent.map_err(|e| StoreError::Io(e.to_string()))?;
            let path = ent.path();
            if path.extension().and_then(|s| s.to_str()) != Some("jsonl") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or_else(|| StoreError::Corrupt("bad log filename".into()))?
                .to_string();
            files.push((stem, path));
        }
        files.sort();

        for (realm_hash, path) in files {
            let f = File::open(&path).map_err(|e| StoreError::Io(e.to_string()))?;
            let mut tip = genesis_prev();
            let mut expect_seq = 0u64;
            let mut reader = BufReader::new(f);
            while let Some(line) = read_log_line_bounded(&mut reader, &realm_hash)? {
                if line.trim().is_empty() {
                    continue;
                }
                let rec: LogRecord = serde_json::from_str(&line)
                    .map_err(|e| StoreError::Corrupt(format!("{realm_hash}.jsonl: {e}")))?;
                // Self-owned journal: a foreign-authored record is rejected outright.
                if rec.author != self.pubkey {
                    return Err(StoreError::ForeignAuthor(format!(
                        "{realm_hash}.jsonl seq {} authored by {}",
                        rec.seq, rec.author
                    )));
                }
                if !verifier.verify(&rec.author, &rec.signing_payload(), &rec.signature) {
                    return Err(StoreError::BadSignature(format!(
                        "{realm_hash}.jsonl seq {}",
                        rec.seq
                    )));
                }
                if rec.prev_hash != tip || rec.seq != expect_seq {
                    return Err(StoreError::ChainBroken(format!(
                        "{realm_hash}.jsonl seq {} (expected seq {expect_seq})",
                        rec.seq
                    )));
                }
                if !is_artifact_hash(rec.op.artifact_hash()) {
                    return Err(StoreError::Corrupt(format!(
                        "{realm_hash}.jsonl seq {} invalid artifact_hash",
                        rec.seq
                    )));
                }
                // The filename is a hash, not trusted: the record's own realm must hash to it.
                if Self::realm_hash(rec.op.realm()) != realm_hash {
                    return Err(StoreError::Corrupt(format!(
                        "{realm_hash}.jsonl seq {} realm hash mismatch",
                        rec.seq
                    )));
                }
                tip = rec.hash();
                expect_seq += 1;
                count += 1;
                max_first_seen = max_first_seen.max(rec.first_seen);
                Self::apply(&mut inner, &rec.op, rec.first_seen);
            }
            // Advisory head cross-check — a mismatch means a crash between append and head-write, or a
            // truncated tail. The jsonl chain is authoritative; warn, don't fail.
            if let Some(want) = read_head_tip_bounded(&self.head_path(&realm_hash), &realm_hash) {
                if want != tip {
                    eprintln!(
                        "bestiary: {realm_hash}.head tip {want} != replayed tip {tip} (using the log)"
                    );
                }
            }
            inner.heads.insert(realm_hash, Head { next_seq: expect_seq, tip_hash: tip });
        }
        inner.next_first_seen = max_first_seen.saturating_add(1);
        Ok(count)
    }

    fn flush(&self) -> Result<(), StoreError> {
        // Records are fsynced per append; this fsyncs the log directory so any pending rename of the
        // advisory head/genesis files is durable.
        fsync_dir(&self.log_dir());
        fsync_dir(&self.blobs_dir());
        Ok(())
    }

    fn prove(
        &self,
        realm: &RealmId,
        artifact_hash: &str,
    ) -> Result<Option<EntryProof>, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Ok(None);
        }
        let key = (realm.clone(), artifact_hash.to_string());
        let live = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Self::live_entry(&inner, &key)
        };
        let Some(live) = live else {
            return Ok(None);
        };
        let manifest_hash = live.manifest.compute_content_address();
        let payload = EntryProof::payload(
            realm,
            artifact_hash,
            &manifest_hash,
            live.first_seen,
            &self.pubkey,
        );
        let signature = self.abode_key.sign(&payload);
        Ok(Some(EntryProof {
            realm: realm.clone(),
            artifact_hash: artifact_hash.to_string(),
            manifest_hash,
            first_seen: live.first_seen,
            attester: self.pubkey.clone(),
            signature,
        }))
    }

    fn snapshot_for_curation_bounded(
        &self,
        max_artifact_bytes: usize,
    ) -> Result<Vec<CurationSnapshot>, StoreError> {
        let rows: Vec<((RealmId, String), Live)> = {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            inner.entries.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
        };
        let head_first_seen = rows.iter().map(|(_, l)| l.first_seen).max().unwrap_or(0);
        let mut artifact_bytes = 0usize;
        if max_artifact_bytes != 0 {
            for ((_, hash), _) in &rows {
                let len = self.blob_len(hash)?;
                artifact_bytes = artifact_bytes.saturating_add(len);
                if artifact_bytes > max_artifact_bytes {
                    return Err(StoreError::Limit(format!(
                        "bestiary curation snapshot too large: {artifact_bytes} artifact bytes exceeds {max_artifact_bytes} byte limit"
                    )));
                }
            }
        }
        let mut out = Vec::with_capacity(rows.len());
        let mut read_artifact_bytes = 0usize;
        for ((r, hash), live) in rows {
            let read_limit = max_artifact_bytes.saturating_sub(read_artifact_bytes);
            let artifact = if max_artifact_bytes == 0 {
                self.read_blob(&hash)?
            } else {
                self.read_blob_bounded(&hash, read_limit)?
            };
            if max_artifact_bytes != 0 {
                read_artifact_bytes = read_artifact_bytes.saturating_add(artifact.len());
            }
            out.push(CurationSnapshot {
                realm: r,
                artifact_hash: hash,
                entry: Entry {
                    manifest: live.manifest,
                    artifact,
                    reputation: live.reputation,
                    quarantine: live.quarantine,
                },
                first_seen: live.first_seen,
                head_first_seen,
            });
        }
        Ok(out)
    }

    fn compact(&self, curator: &dyn Curator) -> Result<CompactStats, StoreError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut stats = CompactStats::default();

        let head_first_seen = inner.entries.values().map(|l| l.first_seen).max().unwrap_or(0);
        // Fast metadata-only decide() pass (the byte-needing model call already ran in observe()).
        let keys: Vec<(RealmId, String)> = inner.entries.keys().cloned().collect();
        for key in keys {
            let Some(live) = inner.entries.get(&key).cloned() else { continue };
            stats.scanned += 1;
            let meta_entry = Entry {
                manifest: live.manifest.clone(),
                artifact: Vec::new(), // decide() must not need bytes (it is lock-held + fast)
                reputation: live.reputation.clone(),
                quarantine: live.quarantine.clone(),
            };
            let ctx = CurationContext {
                realm: &key.0,
                artifact_hash: &key.1,
                entry: &meta_entry,
                first_seen: live.first_seen,
                head_first_seen,
            };
            match curator.decide(&ctx) {
                CurationDecision::Keep => {}
                CurationDecision::Promote { score } | CurationDecision::Demote { score } => {
                    if let Some(l) = inner.entries.get_mut(&key) {
                        l.reputation = Some(ReputationScore::unsigned(score, None));
                    }
                }
                CurationDecision::Quarantine { reason } => {
                    if let Some(l) = inner.entries.get_mut(&key) {
                        let mut notice = l.quarantine.clone().unwrap_or(QuarantineNotice {
                            reason: reason.clone(),
                            attesting_peers: Vec::new(),
                        });
                        notice.reason = reason;
                        l.quarantine = Some(notice);
                        stats.quarantined += 1;
                    }
                }
                CurationDecision::Gc { .. } => {
                    inner.entries.remove(&key);
                    inner.tombstones.insert(key);
                    stats.gc += 1;
                }
            }
        }

        // Rewrite a fresh genesis chain per realm: a Put (+ Attest/Quarantine) per live entry and a
        // Tombstone per evicted key. first_seen is preserved verbatim; seq/prev_hash are renumbered.
        let realm_hashes: Vec<String> = inner.realms.keys().cloned().collect();
        for realm_hash in realm_hashes {
            let realm = inner.realms.get(&realm_hash).cloned();
            let Some(realm) = realm else { continue };
            let mut records: Vec<LogRecord> = Vec::new();
            let mut next_seq = 0u64;
            let mut tip = genesis_prev();

            // Live entries.
            let mut live_keys: Vec<(RealmId, String)> =
                inner.entries.keys().filter(|(r, _)| *r == realm).cloned().collect();
            live_keys.sort_by(|a, b| {
                (a.0 .0.as_str(), a.1.as_str()).cmp(&(b.0 .0.as_str(), b.1.as_str()))
            });
            for key in live_keys {
                let live = inner.entries.get(&key).cloned().expect("just listed");
                let mut ops = vec![LogOp::Put {
                    realm: realm.clone(),
                    artifact_hash: key.1.clone(),
                    manifest: Box::new(live.manifest.clone()),
                }];
                if let Some(q) = &live.quarantine {
                    ops.push(LogOp::Quarantine {
                        realm: realm.clone(),
                        artifact_hash: key.1.clone(),
                        notice: q.clone(),
                    });
                }
                if let Some(rep) = &live.reputation {
                    ops.push(LogOp::Attest {
                        realm: realm.clone(),
                        artifact_hash: key.1.clone(),
                        score: rep.clone(),
                    });
                }
                for op in ops {
                    records.push(self.build_record(next_seq, tip.clone(), op, live.first_seen));
                    tip = records.last().unwrap().hash();
                    next_seq += 1;
                }
            }
            // Tombstones (permanent — preserved across compaction so a recover keeps them dead).
            let mut tomb_keys: Vec<(RealmId, String)> =
                inner.tombstones.iter().filter(|(r, _)| *r == realm).cloned().collect();
            tomb_keys.sort_by(|a, b| {
                (a.0 .0.as_str(), a.1.as_str()).cmp(&(b.0 .0.as_str(), b.1.as_str()))
            });
            for key in tomb_keys {
                let op = LogOp::Tombstone { realm: realm.clone(), artifact_hash: key.1 };
                records.push(self.build_record(next_seq, tip.clone(), op, 0));
                tip = records.last().unwrap().hash();
                next_seq += 1;
            }

            // Atomically replace the realm chain.
            let mut buf = Vec::new();
            for rec in &records {
                buf.extend_from_slice(&encode_log_record_line(rec)?);
            }
            self.atomic_write(&self.log_path(&realm_hash), &buf)?;
            let _ = self
                .atomic_write(&self.head_path(&realm_hash), format!("{next_seq} {tip}").as_bytes());
            inner.heads.insert(realm_hash, Head { next_seq, tip_hash: tip });
        }

        // Global-union blob GC: keep only blobs referenced by some LIVE entry in ANY realm.
        let live_hashes: HashSet<String> = inner.entries.keys().map(|(_, h)| h.clone()).collect();
        if let Ok(rd) = fs::read_dir(self.blobs_dir()) {
            for ent in rd.flatten() {
                let path = ent.path();
                if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                    if name.starts_with('.') {
                        continue; // skip in-flight temp files
                    }
                    if !live_hashes.contains(name) && fs::remove_file(&path).is_ok() {
                        stats.blobs_removed += 1;
                    }
                }
            }
        }
        Ok(stats)
    }
}

impl FsBestiaryStore {
    /// Sign an op into a standalone (seq 0, genesis-rooted) record — used to build self-verifying
    /// push payloads. The seq/prev_hash are placeholders; a receiver re-signs locally on merge.
    fn sign_op(&self, op: LogOp, first_seen: u64) -> LogRecord {
        self.build_record(0, genesis_prev(), op, first_seen)
    }

    /// Build + sign a record with explicit chain coordinates (used by compaction's genesis rewrite
    /// and by [`sign_op`](Self::sign_op)).
    fn build_record(&self, seq: u64, prev_hash: String, op: LogOp, first_seen: u64) -> LogRecord {
        let mut rec = LogRecord {
            seq,
            prev_hash,
            op,
            author: self.pubkey.clone(),
            first_seen,
            signature: String::new(),
        };
        rec.signature = self.abode_key.sign(&rec.signing_payload());
        rec
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curator::DeterministicCurator;
    use sigil::{Backend, MAX_MANIFEST_NAME_BYTES};

    /// A temp directory that cleans itself up on drop (no external tempdir dep).
    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir().join(format!("bestiary-{tag}-{}-{n}", std::process::id()));
            let _ = fs::remove_dir_all(&p);
            fs::create_dir_all(&p).unwrap();
            TempRoot(p)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn key() -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([0x42; 32]).unwrap()
    }
    fn other_key() -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([0x99; 32]).unwrap()
    }
    fn manifest(name: &str) -> Manifest {
        Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
    }
    fn store(root: &TempRoot) -> FsBestiaryStore {
        FsBestiaryStore::new(&root.0, key()).unwrap()
    }

    #[test]
    fn put_get_round_trips_and_persists_across_restart() {
        let root = TempRoot::new("persist");
        let realm = RealmId::new("crew");
        let hash;
        {
            let s = store(&root);
            hash = s.put(&realm, manifest("c"), b"artifact-bytes".to_vec()).unwrap();
            assert_eq!(hash, sha256_hex(b"artifact-bytes"));
            let e = s.get(&realm, &hash).unwrap().unwrap();
            assert_eq!(e.artifact, b"artifact-bytes");
        }
        // Fresh store, same root → recover replays the journal, fetch still works.
        let s2 = store(&root);
        let replayed = s2.recover().unwrap();
        assert!(replayed >= 1, "recover replays the put");
        let e = s2.get(&realm, &hash).unwrap().unwrap();
        assert_eq!(e.manifest.name, "c");
        assert_eq!(e.artifact, b"artifact-bytes");
    }

    #[test]
    fn recover_ignores_oversized_advisory_head_hint_and_replays_log() {
        let root = TempRoot::new("head-cap");
        let realm = RealmId::new("crew");
        let s = store(&root);
        let hash = s.put(&realm, manifest("c"), b"artifact-bytes".to_vec()).unwrap();
        let realm_hash = FsBestiaryStore::realm_hash(&realm);
        fs::write(s.head_path(&realm_hash), vec![b'x'; MAX_BESTIARY_HEAD_BYTES + 1]).unwrap();

        let s2 = store(&root);
        let replayed = s2.recover().unwrap();
        assert_eq!(replayed, 1, "oversized head hint is ignored; log still replays");
        assert!(s2.get(&realm, &hash).unwrap().is_some());
    }

    #[test]
    fn metadata_list_does_not_read_artifact_blobs() {
        let root = TempRoot::new("metadata-no-blob");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("c"), b"artifact-bytes".to_vec()).unwrap();
        let (entry, artifact_len) = s.get_metadata(&realm, &hash).unwrap().unwrap();
        assert_eq!(entry.artifact_hash, hash);
        assert_eq!(entry.manifest.name, "c");
        assert_eq!(artifact_len, b"artifact-bytes".len());

        std::fs::remove_file(s.blob_path(&hash)).unwrap();

        let metadata = s.list_metadata(Some(&realm)).unwrap();
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].artifact_hash, hash);
        assert_eq!(metadata[0].manifest.name, "c");

        let missing = s
            .get_metadata(&realm, &hash)
            .expect_err("single-entry metadata fetch verifies backing blob exists");
        assert!(matches!(missing, StoreError::Corrupt(_)), "missing blob is detected: {missing:?}");

        let full = s.list(Some(&realm)).expect_err("full anti-entropy listing needs the blob");
        assert!(matches!(full, StoreError::Corrupt(_)), "missing blob is detected: {full:?}");
    }

    #[test]
    fn artifact_chunk_reads_only_requested_live_blob_range() {
        let root = TempRoot::new("artifact-chunk");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let bytes = b"artifact-bytes".to_vec();
        let hash = s.put(&realm, manifest("c"), bytes.clone()).unwrap();

        assert_eq!(s.get_artifact_chunk(&realm, &hash, 3, 5).unwrap().unwrap(), b"ifact");
        assert_eq!(
            s.get_artifact_chunk(&realm, &hash, bytes.len() as u64, 0).unwrap().unwrap(),
            Vec::<u8>::new()
        );
        assert!(
            s.get_artifact_chunk(&RealmId::new("other"), &hash, 0, 1).unwrap().is_none(),
            "chunks are served only for live rows in the requested realm"
        );
        let err = s
            .get_artifact_chunk(&realm, &hash, bytes.len() as u64, 1)
            .expect_err("out-of-range chunk is refused");
        assert!(matches!(err, StoreError::Corrupt(_)), "out-of-range chunk refused: {err:?}");
    }

    #[test]
    fn fetch_metadata_enforces_current_artifact_cap_without_hiding_catalog_metadata() {
        let root = TempRoot::new("fetch-metadata-cap");
        let realm = RealmId::new("crew");
        let bytes = b"12345";
        let hash;
        {
            let writer = store(&root);
            hash = writer.put(&realm, manifest("c"), bytes.to_vec()).unwrap();
        }

        let capped = store(&root).with_max_artifact_bytes(4);
        capped.recover().unwrap();

        let (entry, artifact_len) = capped.get_metadata(&realm, &hash).unwrap().unwrap();
        assert_eq!(entry.artifact_hash, hash);
        assert_eq!(artifact_len, bytes.len(), "catalog metadata remains byte-light and visible");

        let fetch = capped
            .get_fetch_metadata(&realm, &hash)
            .expect_err("fetch metadata refuses a blob over the current artifact cap");
        assert!(
            matches!(fetch, StoreError::Limit(_)),
            "over-cap fetch metadata refused: {fetch:?}"
        );

        let chunk = capped
            .get_artifact_chunk(&realm, &hash, 0, 1)
            .expect_err("chunk serving uses the same fetch cap");
        assert!(matches!(chunk, StoreError::Limit(_)), "over-cap chunk refused: {chunk:?}");
    }

    #[test]
    fn full_blob_reads_verify_the_content_address() {
        let root = TempRoot::new("blob-hash-read");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("c"), b"artifact-bytes".to_vec()).unwrap();

        fs::write(s.blob_path(&hash), b"corrupted-bytes").unwrap();

        let get = s.get(&realm, &hash).expect_err("corrupt blob is refused on full fetch");
        assert!(matches!(get, StoreError::Integrity(_)), "corrupt blob rejected: {get:?}");
        let list = s.list(Some(&realm)).expect_err("corrupt blob is refused on full listing");
        assert!(matches!(list, StoreError::Integrity(_)), "corrupt blob rejected: {list:?}");
    }

    #[test]
    fn full_blob_reads_are_bounded_even_for_existing_blob_paths() {
        let root = TempRoot::new("blob-read-cap");
        let s = store(&root).with_max_artifact_bytes(4);
        let bytes = b"12345";
        let hash = sha256_hex(bytes);
        fs::write(s.blob_path(&hash), bytes).unwrap();

        let err = s.read_blob(&hash).expect_err("over-cap blob read is refused");

        assert!(matches!(err, StoreError::Limit(_)), "over-cap blob rejected: {err:?}");
    }

    #[test]
    fn blob_reads_can_use_a_call_specific_cap_for_snapshots() {
        let root = TempRoot::new("blob-read-call-cap");
        let s = store(&root).with_max_artifact_bytes(0);
        let bytes = b"12345";
        let hash = sha256_hex(bytes);
        fs::write(s.blob_path(&hash), bytes).unwrap();

        let err = s.read_blob_bounded(&hash, 4).expect_err("call cap refuses this blob");
        assert!(matches!(err, StoreError::Limit(_)), "over-cap blob rejected: {err:?}");
        assert_eq!(s.read_blob_bounded(&hash, 5).unwrap(), bytes);
    }

    #[test]
    fn republish_rewrites_a_corrupt_existing_blob() {
        let root = TempRoot::new("blob-hash-heal");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let bytes = b"artifact-bytes".to_vec();
        let hash = s.put(&realm, manifest("c"), bytes.clone()).unwrap();
        fs::write(s.blob_path(&hash), b"corrupted-bytes").unwrap();

        let healed = s.put(&realm, manifest("c"), bytes.clone()).unwrap();

        assert_eq!(healed, hash);
        let entry = s.get(&realm, &hash).unwrap().expect("republished entry is readable");
        assert_eq!(entry.artifact, bytes);
    }

    #[test]
    fn list_bounded_refuses_oversized_artifact_snapshot_before_blob_read() {
        let root = TempRoot::new("list-bounded");
        let s = store(&root);
        let realm_a = RealmId::new("crew");
        let realm_b = RealmId::new("guests");
        s.put(&realm_a, manifest("a"), b"aaa".to_vec()).unwrap();
        s.put(&realm_b, manifest("b"), b"bbb".to_vec()).unwrap();

        let err = s.list_bounded(None, 4).unwrap_err();
        assert!(
            matches!(err, StoreError::Limit(_)),
            "over-cap all-realm snapshot refused: {err:?}"
        );

        let scoped = s.list_bounded(Some(&realm_a), 4).unwrap();
        assert_eq!(scoped.len(), 1);
        assert_eq!(scoped[0].realm, realm_a);
        assert_eq!(scoped[0].artifact, b"aaa");

        assert_eq!(s.list(None).unwrap().len(), 2, "unbounded list remains available to callers");
    }

    #[test]
    fn signed_entries_bounded_refuses_oversized_artifact_snapshot_before_blob_read() {
        let root = TempRoot::new("push-bounded-bytes");
        let s = store(&root);
        let realm_a = RealmId::new("crew");
        let realm_b = RealmId::new("guests");
        s.put(&realm_a, manifest("a"), b"aaa".to_vec()).unwrap();
        s.put(&realm_b, manifest("b"), b"bbb".to_vec()).unwrap();

        let err = s.signed_entries_bounded(None, 4, 0).unwrap_err();
        assert!(
            matches!(err, StoreError::Limit(_)),
            "over-cap all-realm push snapshot refused: {err:?}"
        );

        let scoped = s.signed_entries_bounded(Some(&realm_a), 4, 0).unwrap();
        assert_eq!(scoped.len(), 1);
        let sync = scoped[0].sync.as_ref().expect("live entry carries sync bytes");
        assert_eq!(sync.realm, realm_a);
        assert_eq!(sync.artifact, b"aaa");

        assert_eq!(
            s.signed_entries(None).unwrap().len(),
            2,
            "unbounded push snapshot remains available to callers"
        );
    }

    #[test]
    fn signed_entries_bounded_refuses_entry_count_before_touching_blobs() {
        let root = TempRoot::new("push-bounded-count");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let first = s.put(&realm, manifest("a"), b"aaa".to_vec()).unwrap();
        s.put(&realm, manifest("b"), b"bbb".to_vec()).unwrap();
        fs::remove_file(s.blob_path(&first)).unwrap();

        let err = s.signed_entries_bounded(None, 0, 1).unwrap_err();
        assert!(
            matches!(err, StoreError::Limit(_)),
            "entry cap must fire before blob metadata/read: {err:?}"
        );
    }

    #[test]
    fn snapshot_for_curation_bounded_refuses_oversized_artifact_snapshot_before_blob_read() {
        let root = TempRoot::new("curation-bounded");
        let s = store(&root);
        let realm_a = RealmId::new("crew");
        let realm_b = RealmId::new("guests");
        s.put(&realm_a, manifest("a"), b"aaa".to_vec()).unwrap();
        s.put(&realm_b, manifest("b"), b"bbb".to_vec()).unwrap();

        let err = match s.snapshot_for_curation_bounded(4) {
            Ok(_) => panic!("over-cap curation snapshot should fail"),
            Err(err) => err,
        };
        assert!(matches!(err, StoreError::Limit(_)), "over-cap curation snapshot refused: {err:?}");

        let snapshots = s.snapshot_for_curation_bounded(6).unwrap();
        assert_eq!(snapshots.len(), 2);
        assert!(
            snapshots.iter().any(|snap| snap.entry.artifact == b"aaa"),
            "bounded curation snapshot still carries artifact bytes under cap"
        );
    }

    #[test]
    fn filesystem_store_refuses_non_canonical_artifact_hashes() {
        let root = TempRoot::new("hash-shape");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let bad = "../escape";

        assert!(s.get(&realm, bad).unwrap().is_none(), "malformed fetch is a miss");
        assert!(s.prove(&realm, bad).unwrap().is_none(), "malformed proof request is a miss");
        assert!(!s.attest(&realm, bad, ReputationScore::unsigned(0.5, None)).unwrap());
        assert!(!s
            .quarantine(
                &realm,
                bad,
                QuarantineNotice { reason: "bad".into(), attesting_peers: Vec::new() },
            )
            .unwrap());
        assert!(matches!(s.read_blob(bad).unwrap_err(), StoreError::Integrity(_)));
        assert!(matches!(s.tombstone(&realm, bad).unwrap_err(), StoreError::Integrity(_)));
    }

    #[test]
    fn filesystem_store_rejects_oversized_artifacts_before_blob_write() {
        let root = TempRoot::new("artifact-cap");
        let s = store(&root).with_max_artifact_bytes(4);
        let realm = RealmId::new("crew");
        let bytes = b"12345".to_vec();
        let hash = sha256_hex(&bytes);

        let err = s.put(&realm, manifest("too-big"), bytes).unwrap_err();
        assert!(matches!(err, StoreError::Limit(_)), "oversized artifact rejected: {err:?}");
        assert!(s.get(&realm, &hash).unwrap().is_none(), "oversized artifact was not stored");
        assert!(!s.blob_path(&hash).exists(), "oversized artifact was not written as a blob");
    }

    #[test]
    fn filesystem_store_rejects_invalid_manifest_before_blob_or_journal_write() {
        let root = TempRoot::new("invalid-manifest");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let bytes = b"artifact-bytes".to_vec();
        let hash = sha256_hex(&bytes);
        let mut m = manifest("invalid");
        m.name = "n".repeat(MAX_MANIFEST_NAME_BYTES + 1);

        let err = s.put(&realm, m, bytes).unwrap_err();
        assert!(matches!(err, StoreError::Limit(_)), "invalid manifest rejected: {err:?}");
        assert!(s.get(&realm, &hash).unwrap().is_none(), "invalid manifest was not stored");
        assert!(!s.blob_path(&hash).exists(), "invalid manifest did not write a blob");
        assert!(
            !s.log_path(&FsBestiaryStore::realm_hash(&realm)).exists(),
            "invalid manifest was not appended to the journal"
        );
    }

    #[test]
    fn filesystem_store_refuses_oversized_log_records_before_append() {
        let root = TempRoot::new("log-record-cap");
        let s = store(&root);
        let realm = RealmId::new("r".repeat(MAX_BESTIARY_LOG_RECORD_BYTES + 1));

        let err = s.put(&realm, manifest("c"), b"artifact-bytes".to_vec()).unwrap_err();
        assert!(matches!(err, StoreError::Limit(_)), "oversized log record refused: {err:?}");
        assert!(
            !s.log_path(&FsBestiaryStore::realm_hash(&realm)).exists(),
            "oversized record was not appended to the journal"
        );
    }

    #[test]
    fn merge_push_rejects_malformed_tombstone_hashes() {
        let root_a = TempRoot::new("bad-tomb-a");
        let root_b = TempRoot::new("bad-tomb-b");
        let src = FsBestiaryStore::new(&root_a.0, key()).unwrap();
        let dst = FsBestiaryStore::new(&root_b.0, key()).unwrap();
        let realm = RealmId::new("crew");
        let bad = SignedSyncEntry {
            sync: None,
            record: src.sign_op(LogOp::Tombstone { realm, artifact_hash: "../escape".into() }, 0),
        };

        let err = dst.merge_push(bad).unwrap_err();
        assert!(matches!(err, StoreError::Integrity(_)), "malformed tombstone rejected: {err:?}");
        assert!(dst.signed_entries(None).unwrap().is_empty(), "rejected tombstone was not stored");
    }

    #[test]
    fn recover_rejects_malformed_artifact_hashes_in_the_log() {
        let root = TempRoot::new("bad-hash-log");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let realm_hash = FsBestiaryStore::realm_hash(&realm);
        let rec = s.sign_op(LogOp::Tombstone { realm, artifact_hash: "../escape".into() }, 0);
        let mut line = serde_json::to_vec(&rec).unwrap();
        line.push(b'\n');
        fs::write(s.log_path(&realm_hash), line).unwrap();

        let err = s.recover().unwrap_err();
        assert!(matches!(err, StoreError::Corrupt(_)), "bad log hash rejected: {err:?}");
    }

    #[test]
    fn recover_rejects_oversized_log_record_lines_before_json_parse() {
        let root = TempRoot::new("oversized-log-line");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let realm_hash = FsBestiaryStore::realm_hash(&realm);
        fs::write(s.log_path(&realm_hash), vec![b'x'; MAX_BESTIARY_LOG_RECORD_BYTES + 1]).unwrap();

        let err = s.recover().unwrap_err();
        assert!(matches!(err, StoreError::Limit(_)), "oversized line rejected: {err:?}");
    }

    #[test]
    fn recover_rejects_a_tampered_log() {
        let root = TempRoot::new("tamper");
        let realm = RealmId::new("crew");
        let s = store(&root);
        s.put(&realm, manifest("c"), b"bytes".to_vec()).unwrap();
        // Flip a byte in the realm's jsonl so a signature/chain check fails.
        let realm_hash = FsBestiaryStore::realm_hash(&realm);
        let path = s.log_path(&realm_hash);
        let mut txt = fs::read_to_string(&path).unwrap();
        txt = txt.replace("\"name\":\"c\"", "\"name\":\"X\"");
        fs::write(&path, txt).unwrap();
        let s2 = store(&root);
        let err = s2.recover().unwrap_err();
        assert!(
            matches!(
                err,
                StoreError::BadSignature(_) | StoreError::ChainBroken(_) | StoreError::Corrupt(_)
            ),
            "tampered log rejected, got {err:?}"
        );
    }

    #[test]
    fn recover_rejects_a_foreign_authored_log() {
        let root = TempRoot::new("foreign");
        let realm = RealmId::new("crew");
        // Write a record authored by a DIFFERENT key into the journal.
        let foreign = FsBestiaryStore::new(&root.0, other_key()).unwrap();
        foreign.put(&realm, manifest("c"), b"bytes".to_vec()).unwrap();
        // Our daemon (our key) recovers the same root → ForeignAuthor.
        let s = store(&root);
        let err = s.recover().unwrap_err();
        assert!(matches!(err, StoreError::ForeignAuthor(_)), "got {err:?}");
    }

    #[test]
    fn gc_compacts_and_a_shared_blob_across_realms_survives() {
        let root = TempRoot::new("gc");
        let s = store(&root);
        let realm_a = RealmId::new("alpha");
        let realm_b = RealmId::new("beta");
        let bytes = b"identical-bytes".to_vec();
        let hash = s.put(&realm_a, manifest("a"), bytes.clone()).unwrap();
        let _ = s.put(&realm_b, manifest("b"), bytes.clone()).unwrap();
        assert!(s.blob_path(&hash).exists());

        // GC realm A's entry by binding an aggressive curator (gap-0 keeps; force via tombstone).
        s.tombstone(&realm_a, &hash).unwrap();
        let stats = s.compact(&DeterministicCurator::default()).unwrap();
        // The blob is still referenced by realm B's live entry → survives the global-union GC.
        assert!(s.blob_path(&hash).exists(), "shared blob survives (realm B still references it)");
        assert_eq!(stats.blobs_removed, 0);
        assert!(s.get(&realm_a, &hash).unwrap().is_none(), "realm A entry is gone");
        assert!(s.get(&realm_b, &hash).unwrap().is_some(), "realm B entry survives");

        // And recover keeps the tombstone (permanent) while realm B still recovers.
        let s2 = store(&root);
        s2.recover().unwrap();
        assert!(
            s2.get(&realm_a, &hash).unwrap().is_none(),
            "tombstone is permanent across restart"
        );
        assert!(s2.get(&realm_b, &hash).unwrap().is_some());
        // A re-Put of the tombstoned key in realm A does not resurrect it.
        s2.put(&realm_a, manifest("a"), bytes).unwrap();
        assert!(
            s2.get(&realm_a, &hash).unwrap().is_none(),
            "tombstone is not resurrected by a Put"
        );
    }

    #[test]
    fn orphan_blob_is_collected_when_no_realm_references_it() {
        let root = TempRoot::new("orphan");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("c"), b"lonely-bytes".to_vec()).unwrap();
        s.tombstone(&realm, &hash).unwrap();
        let stats = s.compact(&DeterministicCurator::default()).unwrap();
        assert_eq!(stats.blobs_removed, 1, "the now-unreferenced blob is collected");
        assert!(!s.blob_path(&hash).exists());
    }

    #[test]
    fn prove_attestation_verifies_and_survives_compaction() {
        let root = TempRoot::new("prove");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("c"), b"bytes".to_vec()).unwrap();
        let proof = s.prove(&realm, &hash).unwrap().unwrap();
        assert!(proof.verify(&Ed25519Verifier), "proof verifies");
        assert_eq!(proof.attester, s.pubkey());

        // Compaction rewrites the genesis chain; the standalone attestation still verifies and the
        // re-derived proof matches (first_seen preserved).
        s.compact(&DeterministicCurator::default()).unwrap();
        let proof2 = s.prove(&realm, &hash).unwrap().unwrap();
        assert!(proof2.verify(&Ed25519Verifier));
        assert_eq!(proof.first_seen, proof2.first_seen, "first_seen preserved across compaction");
        // A tampered proof fails.
        let mut bad = proof.clone();
        bad.first_seen += 1;
        assert!(!bad.verify(&Ed25519Verifier), "tampered proof fails");
    }

    #[test]
    fn quarantine_is_sticky_and_accumulates_peers() {
        let root = TempRoot::new("quarantine");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("c"), b"susp".to_vec()).unwrap();
        s.quarantine(
            &realm,
            &hash,
            QuarantineNotice { reason: "node-A".into(), attesting_peers: vec!["node-A".into()] },
        )
        .unwrap();
        s.quarantine(
            &realm,
            &hash,
            QuarantineNotice { reason: "node-B".into(), attesting_peers: vec!["node-B".into()] },
        )
        .unwrap();
        let q = s.get(&realm, &hash).unwrap().unwrap().quarantine.unwrap();
        assert!(q.attesting_peers.contains(&"node-A".to_string()));
        assert!(q.attesting_peers.contains(&"node-B".to_string()), "peer set accumulates (sticky)");
        // A re-Put does NOT clear the quarantine (durable-store divergence from the in-memory stub).
        s.put(&realm, manifest("c"), b"susp".to_vec()).unwrap();
        assert!(
            s.get(&realm, &hash).unwrap().unwrap().quarantine.is_some(),
            "re-Put keeps quarantine"
        );
        // Only an explicit Unquarantine clears it.
        assert!(s.unquarantine(&realm, &hash).unwrap());
        assert!(s.get(&realm, &hash).unwrap().unwrap().quarantine.is_none());
    }

    #[test]
    fn quarantine_notice_shape_is_capped_before_store() {
        let root = TempRoot::new("quarantine-shape");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("q"), b"q".to_vec()).unwrap();

        let err = s
            .quarantine(
                &realm,
                &hash,
                QuarantineNotice {
                    reason: "x".repeat(crate::MAX_QUARANTINE_REASON_BYTES + 1),
                    attesting_peers: vec!["node-A".into()],
                },
            )
            .expect_err("oversized quarantine reason is rejected");
        assert!(err.to_string().contains("reason too large"), "{err}");
        assert!(
            s.get(&realm, &hash).unwrap().unwrap().quarantine.is_none(),
            "oversized marker was not retained"
        );

        let err = s
            .quarantine(
                &realm,
                &hash,
                QuarantineNotice {
                    reason: "peer-shape".into(),
                    attesting_peers: vec![
                        "p".repeat(crate::MAX_QUARANTINE_ATTESTING_PEER_BYTES + 1)
                    ],
                },
            )
            .expect_err("oversized peer id is rejected");
        assert!(err.to_string().contains("attesting_peer too large"), "{err}");
        assert!(
            s.get(&realm, &hash).unwrap().unwrap().quarantine.is_none(),
            "oversized peer id was not retained"
        );
    }

    #[test]
    fn reputation_signal_shape_is_capped_before_store() {
        let root = TempRoot::new("reputation-shape");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("rep"), b"rep".to_vec()).unwrap();

        assert!(
            !s.attest(
                &RealmId::new("bad:realm"),
                &hash,
                ReputationScore::unsigned(0.9, Some(RealmId::new("crew"))),
            )
            .unwrap(),
            "invalid reputation realm is rejected"
        );
        assert!(
            s.get(&realm, &hash).unwrap().unwrap().reputation.is_none(),
            "malformed reputation realm was not retained"
        );

        assert!(
            !s.attest(
                &realm,
                &hash,
                ReputationScore {
                    score: 0.9,
                    attesting_realm: Some(RealmId::new("crew")),
                    signed_by: Some("selector".into()),
                    signature: None,
                },
            )
            .unwrap(),
            "half-signed promotions are rejected"
        );
        assert!(
            s.get(&realm, &hash).unwrap().unwrap().reputation.is_none(),
            "half-signed reputation marker was not retained"
        );
    }

    #[test]
    fn quarantine_sticky_peer_union_is_bounded() {
        let root = TempRoot::new("quarantine-peer-cap");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let hash = s.put(&realm, manifest("q"), b"q".to_vec()).unwrap();
        let cap_peers: Vec<String> =
            (0..crate::MAX_QUARANTINE_ATTESTING_PEERS).map(|i| format!("node-{i}")).collect();

        assert!(s
            .quarantine(
                &realm,
                &hash,
                QuarantineNotice { reason: "first".into(), attesting_peers: cap_peers.clone() },
            )
            .unwrap());
        let err = s
            .quarantine(
                &realm,
                &hash,
                QuarantineNotice {
                    reason: "overflow".into(),
                    attesting_peers: vec!["new-node".into()],
                },
            )
            .expect_err("sticky union over the peer cap is rejected");
        assert!(err.to_string().contains("after merge"), "{err}");

        let q = s.get(&realm, &hash).unwrap().unwrap().quarantine.unwrap();
        assert_eq!(q.reason, "first", "rejected overflow leaves existing marker untouched");
        assert_eq!(q.attesting_peers, cap_peers);
    }

    #[test]
    fn merge_push_round_trips_and_rejects_tamper() {
        let root_a = TempRoot::new("push-a");
        let root_b = TempRoot::new("push-b");
        // Both daemons share ONE identity (a push is re-signed under the receiver's identity; here
        // the simplest valid case is the source signing under a key the receiver can verify — any
        // ed25519 key verifies; the receiver re-signs locally regardless).
        let src = FsBestiaryStore::new(&root_a.0, key()).unwrap();
        let dst = FsBestiaryStore::new(&root_b.0, key()).unwrap();
        let realm = RealmId::new("crew");
        let hash = src.put(&realm, manifest("c"), b"shared-bytes".to_vec()).unwrap();
        let pushes = src.signed_entries(Some(&realm)).unwrap();
        assert_eq!(pushes.len(), 1);

        // A genuine push merges.
        let outcome = dst.merge_push(pushes[0].clone()).unwrap();
        assert!(outcome.membership_changed);
        assert!(dst.get(&realm, &hash).unwrap().is_some(), "pushed entry landed");

        // A tampered push (bytes mutated) is rejected on content integrity.
        let mut bad = pushes[0].clone();
        if let Some(sync) = bad.sync.as_mut() {
            sync.artifact = b"different-bytes".to_vec();
        }
        let err = dst.merge_push(bad).unwrap_err();
        assert!(matches!(err, StoreError::Integrity(_)), "tampered push rejected, got {err:?}");
    }

    #[test]
    fn merge_push_drops_an_over_cap_quarantine_signal_but_keeps_the_membership() {
        // A conforming source can never produce an over-cap quarantine (its own `quarantine` gates
        // it), so this models a NON-conforming/hostile peer: take a genuine signed push (the record
        // signs the Put, not the quarantine signal) and graft an oversized quarantine reason onto its
        // SyncEntry. The membership + reputation that already landed must survive — only the malformed
        // defense signal is dropped (logged), not the whole entry.
        let root_src = TempRoot::new("merge-q-src");
        let root_dst = TempRoot::new("merge-q-dst");
        let src = FsBestiaryStore::new(&root_src.0, key()).unwrap();
        let dst = FsBestiaryStore::new(&root_dst.0, key()).unwrap();
        let realm = RealmId::new("crew");
        let hash = src.put(&realm, manifest("c"), b"shared-bytes".to_vec()).unwrap();

        let mut push = src.signed_entries(Some(&realm)).unwrap().remove(0);
        push.sync.as_mut().unwrap().quarantine = Some(QuarantineNotice {
            reason: "x".repeat(crate::MAX_QUARANTINE_REASON_BYTES + 1),
            attesting_peers: vec!["node-B".into()],
        });

        let outcome = dst.merge_push(push).expect("entry merges despite the over-cap quarantine");
        assert!(outcome.membership_changed, "membership still lands");
        let entry = dst.get(&realm, &hash).unwrap().expect("pushed entry is present");
        assert!(entry.quarantine.is_none(), "the over-cap defense signal was dropped, not applied");
    }

    #[test]
    fn tombstone_federates_via_push() {
        let root_a = TempRoot::new("tomb-a");
        let root_b = TempRoot::new("tomb-b");
        let src = FsBestiaryStore::new(&root_a.0, key()).unwrap();
        let dst = FsBestiaryStore::new(&root_b.0, key()).unwrap();
        let realm = RealmId::new("crew");
        let hash = src.put(&realm, manifest("c"), b"regretted".to_vec()).unwrap();
        // dst learns the entry, then learns the tombstone.
        for p in src.signed_entries(Some(&realm)).unwrap() {
            dst.merge_push(p).unwrap();
        }
        assert!(dst.get(&realm, &hash).unwrap().is_some());
        src.tombstone(&realm, &hash).unwrap();
        for p in src.signed_entries(Some(&realm)).unwrap() {
            dst.merge_push(p).unwrap();
        }
        assert!(dst.get(&realm, &hash).unwrap().is_none(), "tombstone federated + applied");
    }

    #[test]
    fn merge_push_to_tombstoned_key_reports_no_membership_change() {
        // A peer that never saw our tombstone re-pushes the (now permanently evicted) artifact. The
        // Put is silently refused (no resurrection), so the merge is a logical no-op and
        // `membership_changed` must be false — not true (the value a naive `!was_present` would give).
        let root = TempRoot::new("tomb-noop");
        let src_root = TempRoot::new("tomb-noop-src");
        let dst = FsBestiaryStore::new(&root.0, key()).unwrap();
        let src = FsBestiaryStore::new(&src_root.0, key()).unwrap();
        let realm = RealmId::new("crew");
        let hash = dst.put(&realm, manifest("c"), b"regretted".to_vec()).unwrap();
        dst.tombstone(&realm, &hash).unwrap();
        // The unaware peer holds the same bytes and pushes a plain Put.
        src.put(&realm, manifest("c"), b"regretted".to_vec()).unwrap();
        let push = src.signed_entries(Some(&realm)).unwrap();
        let put = push.into_iter().find(|e| e.sync.is_some()).expect("a Put push");
        let outcome = dst.merge_push(put).unwrap();
        assert!(
            !outcome.membership_changed,
            "a refused (tombstoned) push is not a membership change"
        );
        assert!(
            dst.get(&realm, &hash).unwrap().is_none(),
            "the tombstone still holds (no resurrection)"
        );
    }

    #[test]
    fn capacity_refuses_new_with_a_wire_honest_error() {
        let root = TempRoot::new("cap");
        let s = store(&root).with_max_entries(1);
        let realm = RealmId::local();
        let h1 = s.put(&realm, manifest("a"), b"one".to_vec()).unwrap();
        assert!(s.get(&realm, &h1).unwrap().is_some());
        let refused = s.put(&realm, manifest("b"), b"two".to_vec());
        assert!(
            matches!(refused, Err(StoreError::Capacity(_))),
            "a new key at capacity is a wire-honest error, not a false success: {refused:?}"
        );
        assert!(
            s.get(&realm, &sha256_hex(b"two")).unwrap().is_none(),
            "new key refused at capacity"
        );
        assert!(s.get(&realm, &h1).unwrap().is_some(), "existing entry untouched");
    }

    #[test]
    fn default_entry_cap_is_bounded_and_zero_opt_out_is_explicit() {
        let root = TempRoot::new("default-cap");
        let s = store(&root);
        assert_eq!(s.max_entries, DEFAULT_MAX_BESTIARY_ENTRIES);

        let unbounded_root = TempRoot::new("default-cap-unbounded");
        let unbounded = store(&unbounded_root).with_max_entries(0);
        assert_eq!(unbounded.max_entries, 0, "0 is the explicit unbounded opt-out");
    }

    #[test]
    fn recover_replays_existing_catalog_even_when_current_cap_is_lower() {
        let root = TempRoot::new("recover-over-cap");
        let realm = RealmId::local();
        let h1;
        let h2;
        {
            let writer = store(&root).with_max_entries(0);
            h1 = writer.put(&realm, manifest("a"), b"one".to_vec()).unwrap();
            h2 = writer.put(&realm, manifest("b"), b"two".to_vec()).unwrap();
        }

        let capped = store(&root).with_max_entries(1);
        capped.recover().unwrap();
        assert!(capped.get(&realm, &h1).unwrap().is_some(), "first entry recovered");
        assert!(
            capped.get(&realm, &h2).unwrap().is_some(),
            "recovery replays existing entries even above the current live cap"
        );

        let refused = capped.put(&realm, manifest("c"), b"three".to_vec());
        assert!(
            matches!(refused, Err(StoreError::Capacity(_))),
            "a new entry past the cap is a wire-honest Capacity error, not a false success: {refused:?}"
        );
        assert!(
            capped.get(&realm, &sha256_hex(b"three")).unwrap().is_none(),
            "new entries are still refused after over-cap recovery"
        );
    }
}
