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
//!
//! ## Resource bounds
//!
//! The default store admits at most [`DEFAULT_MAX_BESTIARY_ENTRIES`] distinct retained keys across
//! live entries **and permanent tombstones**, retains at most
//! [`DEFAULT_MAX_BESTIARY_BLOB_BYTES`] aggregate content-addressed blob bytes, and retains at most
//! [`DEFAULT_MAX_BESTIARY_LOG_BYTES`] aggregate JSONL bytes across all Realms. All three limits use
//! `0` as an explicit operator opt-out. Recovery enforces the same limits before admitting on-disk
//! state, including orphan blobs; the retained-key cap also bounds the number of physical blob
//! files so tiny artifacts cannot turn the byte budget into inode exhaustion. Compaction budgets
//! each replacement chain before growing its buffer. Atomic replacement can temporarily require
//! one additional artifact blob plus one additional rewritten Realm chain beyond the steady-state
//! aggregate caps.

use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
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

/// Default maximum number of distinct `(realm, artifact_hash)` keys retained by
/// [`FsBestiaryStore`], counting both live entries and permanent tombstones.
///
/// `0` is reserved as an explicit opt-out via [`FsBestiaryStore::with_max_entries`].
pub const DEFAULT_MAX_BESTIARY_ENTRIES: usize = 1_024;

/// Default aggregate bytes retained by unique physical content-addressed artifact blobs.
///
/// Atomic creation/replacement can transiently need one additional artifact blob while its temp
/// file is prepared. `0` is reserved as an explicit opt-out via
/// [`FsBestiaryStore::with_max_blob_bytes`].
pub const DEFAULT_MAX_BESTIARY_BLOB_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default aggregate durable JSONL bytes retained across every Realm journal.
///
/// A compaction rewrite can transiently need one additional Realm chain while its atomic temp file
/// is prepared. `0` is reserved as an explicit opt-out via
/// [`FsBestiaryStore::with_max_log_bytes`].
pub const DEFAULT_MAX_BESTIARY_LOG_BYTES: u64 = 256 * 1024 * 1024;

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

#[derive(Clone, Copy)]
enum TempDirectory {
    Blobs,
    Log,
}

/// Recognize only the exact temp basename emitted by [`FsBestiaryStore::unique_tmp`]. Keeping this
/// parser strict prevents startup cleanup from treating an arbitrary operator dotfile as ours.
fn is_owned_temp_name(name: &str, directory: TempDirectory) -> bool {
    let Some(body) = name.strip_prefix('.').and_then(|name| name.strip_suffix(".tmp")) else {
        return false;
    };
    let Some((stem_and_pid, sequence)) = body.rsplit_once('.') else { return false };
    let Some((stem, pid)) = stem_and_pid.rsplit_once('.') else { return false };
    if pid.is_empty()
        || sequence.is_empty()
        || pid.parse::<u32>().is_err()
        || sequence.parse::<u64>().is_err()
    {
        return false;
    }

    match directory {
        TempDirectory::Blobs => is_artifact_hash(stem),
        TempDirectory::Log => stem
            .strip_suffix(".jsonl")
            .or_else(|| stem.strip_suffix(".head"))
            .is_some_and(is_artifact_hash),
    }
}

/// Removes an atomic-write temp on every early return. Rename moves the inode away from `path`, so
/// disarming after a successful rename avoids an unnecessary remove attempt.
struct TempFileGuard {
    path: PathBuf,
    file: Option<File>,
    armed: bool,
}

impl TempFileGuard {
    fn new(path: PathBuf, file: File) -> Self {
        Self { path, file: Some(file), armed: true }
    }

    fn file_mut(&mut self) -> &mut File {
        self.file.as_mut().expect("atomic temp file is open")
    }

    fn close(&mut self) {
        self.file.take();
    }

    fn disarm(&mut self) {
        self.close();
        self.armed = false;
    }

    fn cleanup(&mut self) -> std::io::Result<()> {
        self.close();
        if !self.armed {
            return Ok(());
        }
        match fs::remove_file(&self.path) {
            Ok(()) => {
                self.armed = false;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.armed = false;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!(
                "bestiary: could not remove failed atomic temp {}: {error}",
                self.path.display()
            );
        }
    }
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
    /// The catalog is at its live-plus-tombstone `max_entries` cap and a new key was refused.
    #[error("bestiary at capacity: {0}")]
    Capacity(String),
    /// A caller asked the store to retain bytes beyond its configured bounds.
    #[error("bestiary limit exceeded: {0}")]
    Limit(String),
    /// A prior persistence result was uncertain. No catalog state is served or changed until a
    /// complete recovery re-establishes one authoritative chain view.
    #[error("bestiary store unhealthy; recover before use: {0}")]
    Unhealthy(String),
    /// A manifest failed structural validation (`Manifest::validate`) — a malformed shape or an
    /// over-cap metadata field, distinct from a *byte-retention* [`StoreError::Limit`].
    #[error("bestiary invalid manifest: {0}")]
    Invalid(String),
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
    /// already tombstoned. Tombstoning a live key is cardinality-neutral; a previously absent key
    /// returns [`StoreError::Capacity`] when the retained-key cap is full.
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
    /// Replay + verify the on-disk log at bind; returns the number of records replayed. Fails closed
    /// before retaining state beyond the configured distinct-key, physical-blob, or
    /// aggregate-journal cap.
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

#[derive(Clone, Default)]
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
    /// Aggregate bytes currently retained by every authoritative `<realm_hash>.jsonl` file.
    journal_bytes: u64,
    /// Aggregate bytes currently retained by unique physical content-addressed blob files,
    /// including unreferenced orphans.
    blob_bytes: u64,
    /// Number of unique physical content-addressed blob files, including unreferenced orphans.
    /// The retained-key cap also bounds this count so tiny files cannot bypass the byte budget.
    blob_count: usize,
    /// Set after a persistence result whose durable outcome cannot be inferred in-process, or when
    /// a newly opened non-empty root has not yet been recovered. Successful recovery is the only
    /// operation that clears it.
    unhealthy_reason: Option<String>,
}

/// Internal append certainty classification. Only `BeforeWrite` proves that no journal bytes were
/// attempted; callers may then roll back a blob that they know they created for this append.
enum AppendFailure {
    BeforeWrite(StoreError),
    Uncertain(StoreError),
}

impl From<StoreError> for AppendFailure {
    fn from(error: StoreError) -> Self {
        Self::BeforeWrite(error)
    }
}

impl From<AppendFailure> for StoreError {
    fn from(error: AppendFailure) -> Self {
        match error {
            AppendFailure::BeforeWrite(error) | AppendFailure::Uncertain(error) => error,
        }
    }
}

/// Atomic temp failure classification. `Cleanup` means the destination operation failed and the
/// Bestiary could not prove its newly-created temp was removed; callers must latch the store so
/// repeated requests cannot accumulate unaccounted files/inodes.
enum AtomicWriteFailure {
    Operation(StoreError),
    Cleanup { operation: String, cleanup: String },
}

impl From<StoreError> for AtomicWriteFailure {
    fn from(error: StoreError) -> Self {
        Self::Operation(error)
    }
}

impl AtomicWriteFailure {
    fn cleanup_failed(&self) -> bool {
        matches!(self, Self::Cleanup { .. })
    }
}

impl From<AtomicWriteFailure> for StoreError {
    fn from(error: AtomicWriteFailure) -> Self {
        match error {
            AtomicWriteFailure::Operation(error) => error,
            AtomicWriteFailure::Cleanup { operation, cleanup } => StoreError::Io(format!(
                "atomic write failed ({operation}) and its temp cleanup also failed ({cleanup})"
            )),
        }
    }
}

/// The reference filling: a realm-hashed, signed-log, content-addressed on-disk Bestiary.
pub struct FsBestiaryStore {
    root: PathBuf,
    abode_key: Ed25519KeyMaterial,
    pubkey: String,
    /// Retained distinct-key cap across live entries + permanent tombstones; `0` is unbounded.
    max_entries: usize,
    /// Aggregate durable JSONL byte cap across all Realms; `0` is unbounded.
    max_log_bytes: u64,
    /// Aggregate unique physical content-addressed blob byte cap; `0` is unbounded.
    max_blob_bytes: u64,
    /// `0` = unbounded; otherwise the largest artifact blob this store will retain.
    max_artifact_bytes: usize,
    /// Per-process unique suffix source for atomic temp files (no clock/rng needed).
    tmp_seq: AtomicU64,
    /// Deterministically model a full write followed by an uncertain append result.
    #[cfg(test)]
    fail_append_after_write: AtomicBool,
    /// Deterministically fail after curation has been staged but before its first replacement.
    #[cfg(test)]
    fail_compaction_after_stage: AtomicBool,
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
            max_log_bytes: DEFAULT_MAX_BESTIARY_LOG_BYTES,
            max_blob_bytes: DEFAULT_MAX_BESTIARY_BLOB_BYTES,
            max_artifact_bytes: MAX_REGISTRY_ARTIFACT_BYTES,
            tmp_seq: AtomicU64::new(0),
            #[cfg(test)]
            fail_append_after_write: AtomicBool::new(false),
            #[cfg(test)]
            fail_compaction_after_stage: AtomicBool::new(false),
            inner: Mutex::new(Inner::default()),
        };
        fs::create_dir_all(store.blobs_dir()).map_err(|e| StoreError::Io(e.to_string()))?;
        fs::create_dir_all(store.log_dir()).map_err(|e| StoreError::Io(e.to_string()))?;
        store.cleanup_stale_temps(&store.blobs_dir(), TempDirectory::Blobs)?;
        store.cleanup_stale_temps(&store.log_dir(), TempDirectory::Log)?;
        if Self::directory_has_entries(&store.blobs_dir())?
            || Self::directory_has_entries(&store.log_dir())?
        {
            store.inner.lock().unwrap_or_else(|p| p.into_inner()).unhealthy_reason = Some(
                "an existing Bestiary root must complete recovery before serving requests".into(),
            );
        }
        Ok(store)
    }

    /// Cap the number of distinct catalog entries.
    ///
    /// The default is [`DEFAULT_MAX_BESTIARY_ENTRIES`]. Live entries and permanent tombstones both
    /// consume one slot. A live-to-tombstone transition is cardinality-neutral; a `Put` or
    /// tombstone for a previously absent key is refused at capacity. The same finite value bounds
    /// unique physical blob files (including orphans) so tiny artifacts cannot exhaust inodes.
    /// Recovery enforces both bounds. Pass `0` to opt out of both counts.
    pub fn with_max_entries(mut self, max_entries: usize) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Cap aggregate durable JSONL bytes across all Realm journals.
    ///
    /// The default is [`DEFAULT_MAX_BESTIARY_LOG_BYTES`]. Append and recovery both fail closed
    /// before admitting state beyond this bound. A compaction replacement is budgeted against the
    /// other Realm logs before its buffer grows. Pass `0` to opt out.
    pub fn with_max_log_bytes(mut self, max_log_bytes: u64) -> Self {
        self.max_log_bytes = max_log_bytes;
        self
    }

    /// Cap aggregate bytes retained by unique physical content-addressed blob files.
    ///
    /// The default is [`DEFAULT_MAX_BESTIARY_BLOB_BYTES`]. Dedupe references an existing blob
    /// without charging it again. Append preflight proves the journal first, then blob growth is
    /// proved before the atomic temp is written. Recovery counts every accountable blob, including
    /// unreferenced orphans. Physical file count remains bounded by `max_entries` when it is
    /// nonzero. Pass `0` to opt out of the byte cap.
    pub fn with_max_blob_bytes(mut self, max_blob_bytes: u64) -> Self {
        self.max_blob_bytes = max_blob_bytes;
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

    fn retained_key_count(inner: &Inner) -> usize {
        inner.entries.len().saturating_add(inner.tombstones.len())
    }

    fn op_adds_retained_key(inner: &Inner, op: &LogOp) -> bool {
        match op {
            LogOp::Put { realm, artifact_hash, .. } | LogOp::Tombstone { realm, artifact_hash } => {
                let key = (realm.clone(), artifact_hash.clone());
                !inner.entries.contains_key(&key) && !inner.tombstones.contains(&key)
            }
            LogOp::Attest { .. } | LogOp::Quarantine { .. } | LogOp::Unquarantine { .. } => false,
        }
    }

    fn ensure_entry_capacity(&self, inner: &Inner, op: &LogOp) -> Result<(), StoreError> {
        if self.max_entries != 0
            && Self::op_adds_retained_key(inner, op)
            && Self::retained_key_count(inner) >= self.max_entries
        {
            return Err(StoreError::Capacity(format!(
                "catalog at retained-key capacity ({}); refused new {} in realm {}",
                self.max_entries,
                op.artifact_hash(),
                op.realm().0
            )));
        }
        Ok(())
    }

    fn checked_journal_growth(&self, current: u64, adding: u64) -> Result<u64, StoreError> {
        let prospective = current.checked_add(adding).ok_or_else(|| {
            StoreError::Limit("aggregate Bestiary journal byte count overflow".into())
        })?;
        if self.max_log_bytes != 0 && prospective > self.max_log_bytes {
            return Err(StoreError::Limit(format!(
                "aggregate Bestiary journal would retain {prospective} bytes, exceeding {} byte limit",
                self.max_log_bytes
            )));
        }
        Ok(prospective)
    }

    fn checked_blob_growth(&self, current: u64, adding: u64) -> Result<u64, StoreError> {
        let prospective = current.checked_add(adding).ok_or_else(|| {
            StoreError::Limit("aggregate Bestiary blob byte count overflow".into())
        })?;
        if self.max_blob_bytes != 0 && prospective > self.max_blob_bytes {
            return Err(StoreError::Limit(format!(
                "aggregate Bestiary blobs would retain {prospective} bytes, exceeding {} byte limit",
                self.max_blob_bytes
            )));
        }
        Ok(prospective)
    }

    fn ensure_healthy(inner: &Inner) -> Result<(), StoreError> {
        match &inner.unhealthy_reason {
            Some(reason) => Err(StoreError::Unhealthy(reason.clone())),
            None => Ok(()),
        }
    }

    fn mark_unhealthy(inner: &mut Inner, reason: impl Into<String>) {
        if inner.unhealthy_reason.is_none() {
            inner.unhealthy_reason = Some(reason.into());
        }
    }

    fn directory_has_entries(dir: &Path) -> Result<bool, StoreError> {
        fs::read_dir(dir)
            .map_err(|error| {
                StoreError::Io(format!("read Bestiary directory {}: {error}", dir.display()))
            })?
            .next()
            .transpose()
            .map(|entry| entry.is_some())
            .map_err(|error| {
                StoreError::Io(format!("read Bestiary directory {}: {error}", dir.display()))
            })
    }

    /// Account every physical blob file without reading artifact contents. Blob names are content
    /// addresses and therefore unique within the directory; all other names/inode types are
    /// unaccountable disk use and fail closed. Exact Bestiary temps were safely removed at startup.
    fn scan_blob_usage(&self) -> Result<(u64, usize), StoreError> {
        let dir = self.blobs_dir();
        let read = fs::read_dir(&dir).map_err(|error| {
            StoreError::Io(format!("read Bestiary blob directory {}: {error}", dir.display()))
        })?;
        let mut blob_bytes = 0u64;
        let mut blob_count = 0usize;
        for entry in read {
            let entry = entry.map_err(|error| {
                StoreError::Io(format!("read Bestiary blob directory {}: {error}", dir.display()))
            })?;
            let name = entry.file_name().into_string().map_err(|_| {
                StoreError::Corrupt(format!(
                    "unaccountable non-UTF-8 entry in Bestiary blob directory {}",
                    dir.display()
                ))
            })?;
            if !is_artifact_hash(&name) {
                return Err(StoreError::Corrupt(format!(
                    "unaccountable Bestiary blob-directory entry {}",
                    entry.path().display()
                )));
            }
            let metadata = fs::symlink_metadata(entry.path()).map_err(|error| {
                StoreError::Io(format!("blob {} metadata: {error}", entry.path().display()))
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(StoreError::Corrupt(format!(
                    "blob {} is not a regular non-symlink file",
                    entry.path().display()
                )));
            }
            blob_bytes = self.checked_blob_growth(blob_bytes, metadata.len())?;
            blob_count = blob_count
                .checked_add(1)
                .ok_or_else(|| StoreError::Limit("Bestiary physical blob count overflow".into()))?;
            if self.max_entries != 0 && blob_count > self.max_entries {
                return Err(StoreError::Limit(format!(
                    "Bestiary physical blobs retain {blob_count} files, exceeding the {} file limit",
                    self.max_entries
                )));
            }
        }
        Ok((blob_bytes, blob_count))
    }

    fn regular_file_len_or_zero(path: &Path) -> Result<u64, StoreError> {
        match fs::symlink_metadata(path) {
            Ok(metadata)
                if !metadata.file_type().is_symlink() && metadata.file_type().is_file() =>
            {
                Ok(metadata.len())
            }
            Ok(_) => Err(StoreError::Corrupt(format!(
                "journal path {} is not a regular non-symlink file",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
            Err(error) => {
                Err(StoreError::Io(format!("journal path {} metadata: {error}", path.display())))
            }
        }
    }

    fn cleanup_stale_temps(&self, dir: &Path, directory: TempDirectory) -> Result<(), StoreError> {
        let mut removed_any = false;
        for entry in fs::read_dir(dir).map_err(|error| StoreError::Io(error.to_string()))? {
            let entry = entry.map_err(|error| StoreError::Io(error.to_string()))?;
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if !is_owned_temp_name(&name, directory) {
                continue;
            }
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|error| {
                StoreError::Io(format!("stale temp {} metadata: {error}", path.display()))
            })?;
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(StoreError::Corrupt(format!(
                    "owned stale temp {} is not a regular non-symlink file",
                    path.display()
                )));
            }
            fs::remove_file(&path).map_err(|error| {
                StoreError::Io(format!("remove stale temp {}: {error}", path.display()))
            })?;
            removed_any = true;
        }
        if removed_any {
            fsync_dir(dir);
        }
        Ok(())
    }

    /// Write `bytes` atomically to `dest` (temp file in the same dir + rename), fsyncing both.
    fn atomic_write(&self, dest: &Path, bytes: &[u8]) -> Result<(), AtomicWriteFailure> {
        let dir = dest.parent().ok_or_else(|| StoreError::Io("no parent dir".into()))?;
        let stem = dest
            .file_name()
            .and_then(|s| s.to_str())
            .ok_or_else(|| StoreError::Io("atomic destination has no UTF-8 filename".into()))?;
        let tmp = self.unique_tmp(dir, stem);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|e| StoreError::Io(e.to_string()))?;
        let mut guard = TempFileGuard::new(tmp.clone(), file);
        if let Err(error) = guard.file_mut().write_all(bytes) {
            let operation = error.to_string();
            return Err(match guard.cleanup() {
                Ok(()) => AtomicWriteFailure::Operation(StoreError::Io(operation)),
                Err(cleanup) => {
                    AtomicWriteFailure::Cleanup { operation, cleanup: cleanup.to_string() }
                }
            });
        }
        if let Err(error) = guard.file_mut().sync_all() {
            let operation = error.to_string();
            return Err(match guard.cleanup() {
                Ok(()) => AtomicWriteFailure::Operation(StoreError::Io(operation)),
                Err(cleanup) => {
                    AtomicWriteFailure::Cleanup { operation, cleanup: cleanup.to_string() }
                }
            });
        }
        guard.close();
        if let Err(error) = fs::rename(&tmp, dest) {
            let operation = error.to_string();
            return Err(match guard.cleanup() {
                Ok(()) => AtomicWriteFailure::Operation(StoreError::Io(operation)),
                Err(cleanup) => {
                    AtomicWriteFailure::Cleanup { operation, cleanup: cleanup.to_string() }
                }
            });
        }
        guard.disarm();
        fsync_dir(dir);
        Ok(())
    }

    fn write_blob(
        &self,
        inner: &mut Inner,
        artifact_hash: &str,
        artifact: &[u8],
    ) -> Result<bool, StoreError> {
        if !is_artifact_hash(artifact_hash) {
            return Err(invalid_artifact_hash(artifact_hash));
        }
        let path = self.blob_path(artifact_hash);
        let existing_len = match fs::symlink_metadata(&path) {
            Ok(metadata)
                if !metadata.file_type().is_symlink() && metadata.file_type().is_file() =>
            {
                Some(metadata.len())
            }
            Ok(_) => {
                return Err(StoreError::Corrupt(format!(
                    "blob {artifact_hash} is not a regular non-symlink file"
                )))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => {
                return Err(StoreError::Io(format!(
                    "blob {artifact_hash} metadata failed: {error}"
                )))
            }
        };
        if existing_len.is_some() {
            match self.read_blob(artifact_hash) {
                // Content-addressed dedupe: identical bytes already on disk. `false` means an
                // append failure must never remove this pre-existing file.
                Ok(_) => return Ok(false),
                Err(err) => {
                    eprintln!(
                        "bestiary: rewriting corrupt or unreadable blob {artifact_hash}: {err}"
                    );
                }
            }
        }
        let artifact_len = u64::try_from(artifact.len())
            .map_err(|_| StoreError::Limit("artifact length does not fit u64".into()))?;
        let repairs_live_reference =
            existing_len.is_none() && inner.entries.keys().any(|(_, hash)| hash == artifact_hash);
        // A corrupt existing blob may have been externally resized. Re-scan the physical directory
        // before replacement so final accounting subtracts the actual old file rather than a stale
        // assumption. A missing blob referenced by an already-durable live row is likewise repaired
        // from a physical re-scan. These are rare repair paths; ordinary CAS dedupe never scans.
        let (current_blob_bytes, current_blob_count) =
            if existing_len.is_some() || repairs_live_reference {
                self.scan_blob_usage()?
            } else {
                (inner.blob_bytes, inner.blob_count)
            };
        let prospective_blob_count = if existing_len.is_some() {
            current_blob_count
        } else {
            current_blob_count
                .checked_add(1)
                .ok_or_else(|| StoreError::Limit("Bestiary physical blob count overflow".into()))?
        };
        if self.max_entries != 0 && prospective_blob_count > self.max_entries {
            return Err(StoreError::Limit(format!(
                "Bestiary physical blobs would retain {prospective_blob_count} files, exceeding the {} file limit",
                self.max_entries
            )));
        }
        let without_existing = current_blob_bytes
            .checked_sub(existing_len.unwrap_or(0))
            .ok_or_else(|| StoreError::Corrupt("Bestiary blob accounting underflow".into()))?;
        let prospective_blob_bytes = self.checked_blob_growth(without_existing, artifact_len)?;
        if let Err(failure) = self.atomic_write(&path, artifact) {
            let cleanup_failed = failure.cleanup_failed();
            let error = StoreError::from(failure);
            if cleanup_failed {
                Self::mark_unhealthy(inner, format!("blob atomic temp cleanup failed: {error}"));
            }
            return Err(error);
        }
        inner.blob_bytes = prospective_blob_bytes;
        inner.blob_count = prospective_blob_count;
        // A repaired blob is required by an older durable Put and must survive even if this
        // re-publication's new append later fails before writing.
        Ok(existing_len.is_none() && !repairs_live_reference)
    }

    fn rollback_new_blob(&self, inner: &mut Inner, artifact_hash: &str) -> Result<(), StoreError> {
        let path = self.blob_path(artifact_hash);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            StoreError::Io(format!("new blob {artifact_hash} rollback metadata: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(StoreError::Corrupt(format!(
                "new blob {artifact_hash} changed inode type before rollback"
            )));
        }
        fs::remove_file(&path).map_err(|error| {
            StoreError::Io(format!("rollback new blob {artifact_hash}: {error}"))
        })?;
        inner.blob_bytes = inner.blob_bytes.checked_sub(metadata.len()).ok_or_else(|| {
            StoreError::Corrupt("Bestiary blob accounting underflow during rollback".into())
        })?;
        inner.blob_count = inner.blob_count.checked_sub(1).ok_or_else(|| {
            StoreError::Corrupt("Bestiary blob count underflow during rollback".into())
        })?;
        fsync_dir(&self.blobs_dir());
        Ok(())
    }

    fn regular_blob_metadata(&self, artifact_hash: &str) -> Result<fs::Metadata, StoreError> {
        let path = self.blob_path(artifact_hash);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {error}"))
        })?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
            return Err(StoreError::Corrupt(format!(
                "blob {artifact_hash} is not a regular non-symlink file"
            )));
        }
        Ok(metadata)
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
        self.regular_blob_metadata(artifact_hash)?;
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
        let meta = self.regular_blob_metadata(artifact_hash)?;
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
        self.regular_blob_metadata(artifact_hash)?;
        let mut file = File::open(self.blob_path(artifact_hash))
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}")))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} seek failed: {e}")))?;
        file.read_exact(&mut bytes)
            .map_err(|e| StoreError::Corrupt(format!("blob {artifact_hash} unreadable: {e}")))?;
        Ok(bytes)
    }

    /// Prove the next append fits both the per-record and aggregate journal byte limits without
    /// mutating disk or chain state. Used before retaining a new artifact blob.
    fn preflight_append(
        &self,
        inner: &Inner,
        op: &LogOp,
        first_seen: u64,
    ) -> Result<(), StoreError> {
        let realm_hash = Self::realm_hash(op.realm());
        let head = inner.heads.get(&realm_hash).cloned().unwrap_or_default();
        head.next_seq
            .checked_add(1)
            .ok_or_else(|| StoreError::Limit("journal sequence exhausted".into()))?;
        let record = self.build_record(head.next_seq, head.tip_hash, op.clone(), first_seen);
        let line = encode_log_record_line(&record)?;
        let line_len = u64::try_from(line.len())
            .map_err(|_| StoreError::Limit("journal record length does not fit u64".into()))?;
        self.checked_journal_growth(inner.journal_bytes, line_len).map(|_| ())
    }

    /// Append a record for `op`/`first_seen` to its realm chain (sign, write, advance the head).
    /// Caller holds the inner lock.
    fn append(&self, inner: &mut Inner, op: LogOp, first_seen: u64) -> Result<(), AppendFailure> {
        Self::ensure_healthy(inner)?;
        let realm_hash = Self::realm_hash(op.realm());
        let head = inner.heads.entry(realm_hash.clone()).or_default().clone();
        let next_seq = head
            .next_seq
            .checked_add(1)
            .ok_or_else(|| StoreError::Limit("journal sequence exhausted".into()))?;
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
        let line_len = u64::try_from(line.len())
            .map_err(|_| StoreError::Limit("journal record length does not fit u64".into()))?;
        let new_journal_bytes = self.checked_journal_growth(inner.journal_bytes, line_len)?;
        let log_path = self.log_path(&realm_hash);
        {
            let mut f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_path)
                .map_err(|e| StoreError::Io(e.to_string()))?;
            if let Err(error) = f.write_all(&line) {
                let reason = format!(
                    "append of Realm {realm_hash} seq {} may be partially durable after write error: {error}",
                    rec.seq
                );
                Self::mark_unhealthy(inner, reason);
                return Err(AppendFailure::Uncertain(StoreError::Io(error.to_string())));
            }
            #[cfg(test)]
            if self.fail_append_after_write.swap(false, Ordering::Relaxed) {
                let reason = format!(
                    "append of Realm {realm_hash} seq {} has injected post-write uncertainty",
                    rec.seq
                );
                Self::mark_unhealthy(inner, reason.clone());
                return Err(AppendFailure::Uncertain(StoreError::Io(reason)));
            }
            if let Err(error) = f.sync_all() {
                let reason = format!(
                    "append of Realm {realm_hash} seq {} may be durable after sync error: {error}",
                    rec.seq
                );
                Self::mark_unhealthy(inner, reason);
                return Err(AppendFailure::Uncertain(StoreError::Io(error.to_string())));
            }
        }
        let new_head = Head { next_seq, tip_hash: rec_hash };
        // Advisory tip hint (truncation detector) — best-effort, the jsonl is authoritative.
        if let Err(failure) = self.atomic_write(
            &self.head_path(&realm_hash),
            format!("{} {}", new_head.next_seq, new_head.tip_hash).as_bytes(),
        ) {
            if failure.cleanup_failed() {
                let error = StoreError::from(failure);
                Self::mark_unhealthy(
                    inner,
                    format!("advisory-head atomic temp cleanup failed: {error}"),
                );
                return Err(AppendFailure::Uncertain(error));
            }
        }
        inner.heads.insert(realm_hash, new_head);
        inner.journal_bytes = new_journal_bytes;
        Ok(())
    }

    /// Encode one genesis-rewrite record directly into the bounded replacement buffer. This avoids
    /// retaining a second vector of manifest-bearing `LogRecord`s during compaction.
    fn push_compaction_record(
        &self,
        buffer: &mut Vec<u8>,
        replacement_budget: Option<u64>,
        next_seq: &mut u64,
        tip: &mut String,
        op: LogOp,
        first_seen: u64,
    ) -> Result<(), StoreError> {
        let record = self.build_record(*next_seq, tip.clone(), op, first_seen);
        let line = encode_log_record_line(&record)?;
        let line_len = u64::try_from(line.len())
            .map_err(|_| StoreError::Limit("compacted journal line does not fit u64".into()))?;
        let current = u64::try_from(buffer.len())
            .map_err(|_| StoreError::Limit("compacted journal buffer does not fit u64".into()))?;
        let prospective = current
            .checked_add(line_len)
            .ok_or_else(|| StoreError::Limit("compacted journal byte count overflow".into()))?;
        if let Some(replacement_budget) = replacement_budget {
            if prospective > replacement_budget {
                return Err(StoreError::Limit(format!(
                    "compacted Realm journal would retain {prospective} bytes, exceeding its {replacement_budget} byte aggregate-budget share"
                )));
            }
        }
        // Geometric growth avoids reallocate+copy of the full chain for every record. The logical
        // bytes are checked against the exact replacement budget before allocation; Vec may retain
        // a bounded geometric spare-capacity envelope while this one-Realm buffer is alive.
        buffer.try_reserve(line.len()).map_err(|error| {
            StoreError::Limit(format!("could not reserve compacted journal buffer: {error}"))
        })?;
        buffer.extend_from_slice(&line);
        *tip = record.hash();
        *next_seq = next_seq
            .checked_add(1)
            .ok_or_else(|| StoreError::Limit("compacted journal sequence overflow".into()))?;
        Ok(())
    }

    /// Build one Realm's canonical replacement chain under its exact share of the aggregate log
    /// budget. Callers can run this as a discardable dry pass before any durable replacement, then
    /// rebuild one Realm at a time to keep peak allocation bounded to a single chain.
    fn build_compaction_buffer(
        &self,
        inner: &Inner,
        realm: &RealmId,
        replacement_budget: Option<u64>,
    ) -> Result<(Vec<u8>, u64, String), StoreError> {
        let mut buffer = Vec::new();
        let mut next_seq = 0u64;
        let mut tip = genesis_prev();

        let mut live_keys: Vec<(RealmId, String)> =
            inner.entries.keys().filter(|(r, _)| *r == realm).cloned().collect();
        live_keys
            .sort_by(|a, b| (a.0 .0.as_str(), a.1.as_str()).cmp(&(b.0 .0.as_str(), b.1.as_str())));
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
                self.push_compaction_record(
                    &mut buffer,
                    replacement_budget,
                    &mut next_seq,
                    &mut tip,
                    op,
                    live.first_seen,
                )?;
            }
        }

        let mut tomb_keys: Vec<(RealmId, String)> =
            inner.tombstones.iter().filter(|(r, _)| *r == realm).cloned().collect();
        tomb_keys
            .sort_by(|a, b| (a.0 .0.as_str(), a.1.as_str()).cmp(&(b.0 .0.as_str(), b.1.as_str())));
        for key in tomb_keys {
            self.push_compaction_record(
                &mut buffer,
                replacement_budget,
                &mut next_seq,
                &mut tip,
                LogOp::Tombstone { realm: realm.clone(), artifact_hash: key.1 },
                0,
            )?;
        }

        Ok((buffer, next_seq, tip))
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
        manifest.validate().map_err(|e| StoreError::Invalid(e.to_string()))?;
        let hash = sha256_hex(&artifact);
        let key = (realm.clone(), hash.clone());
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        Self::ensure_healthy(&inner)?;

        if inner.tombstones.contains(&key) {
            eprintln!("bestiary: refusing Put of tombstoned {hash} in realm {}", realm.0);
            return Ok(hash);
        }
        let is_new = !inner.entries.contains_key(&key);
        if is_new && self.max_entries != 0 && Self::retained_key_count(&inner) >= self.max_entries {
            // Refuse-new with a wire-honest error (matches `registry-mem`, which returns
            // `RegistryReply::Error`): the daemon maps this to a structured failure rather than a
            // false `Published`. A re-publish of an existing key never reaches here (it is not new).
            return Err(StoreError::Capacity(format!(
                "catalog at retained-key capacity ({}); refused new artifact {hash} in realm {}",
                self.max_entries, realm.0
            )));
        }

        let (first_seen, next_first_seen) = if is_new {
            let next = inner.next_first_seen.checked_add(1).ok_or_else(|| {
                StoreError::Limit("Bestiary first_seen sequence exhausted".into())
            })?;
            (inner.next_first_seen, Some(next))
        } else {
            (inner.entries.get(&key).map(|l| l.first_seen).unwrap_or(0), None)
        };
        let op = LogOp::Put {
            realm: realm.clone(),
            artifact_hash: hash.clone(),
            manifest: Box::new(manifest),
        };
        // Prove the journal can retain this record before writing a potentially large blob. The
        // lock makes the preflight exact for this store process; append repeats the check as the
        // authoritative guard.
        self.preflight_append(&inner, &op, first_seen)?;
        let created_new_blob = self.write_blob(&mut inner, &hash, &artifact)?;
        match self.append(&mut inner, op.clone(), first_seen) {
            Ok(()) => {}
            Err(AppendFailure::BeforeWrite(error)) => {
                // This classification proves no journal write was attempted. Only a blob newly
                // created for this operation is safe to remove; deduped or repaired blobs predate
                // the failed append and remain owned by the CAS.
                if created_new_blob {
                    if let Err(cleanup_error) = self.rollback_new_blob(&mut inner, &hash) {
                        Self::mark_unhealthy(
                            &mut inner,
                            format!(
                                "append failed before write and its new blob could not be rolled back: {cleanup_error}"
                            ),
                        );
                        return Err(cleanup_error);
                    }
                }
                return Err(error);
            }
            // The record may be durable despite the reported error. Keep the blob so recovery can
            // never find a durable Put whose content was optimistically deleted; append already
            // latched the store unhealthy.
            Err(AppendFailure::Uncertain(error)) => return Err(error),
        }
        if let Some(next) = next_first_seen {
            inner.next_first_seen = next;
        }
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
            Self::ensure_healthy(&inner)?;
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
            Self::ensure_healthy(&inner)?;
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
            Self::ensure_healthy(&inner)?;
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
            Self::ensure_healthy(&inner)?;
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
        Self::ensure_healthy(&inner)?;
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
        Self::ensure_healthy(&inner)?;
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
        Self::ensure_healthy(&inner)?;
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
        Self::ensure_healthy(&inner)?;
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
        Self::ensure_healthy(&inner)?;
        if inner.tombstones.contains(&key) {
            return Ok(false);
        }
        let op =
            LogOp::Tombstone { realm: realm.clone(), artifact_hash: artifact_hash.to_string() };
        self.ensure_entry_capacity(&inner, &op)?;
        self.append(&mut inner, op.clone(), 0)?;
        Self::apply(&mut inner, &op, 0);
        Ok(true)
    }

    fn merge_push(&self, entry: SignedSyncEntry) -> Result<MergeOutcome, StoreError> {
        {
            let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
            Self::ensure_healthy(&inner)?;
        }
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
            Self::ensure_healthy(&inner)?;
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
        let mut current = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        // Enter recovery fail-closed even when an operator invokes it on a currently healthy
        // handle. Every early `?` leaves this latch in place; only the final transactional candidate
        // assignment below restores a healthy state.
        Self::mark_unhealthy(&mut current, "recovery has not completed successfully");
        // Same-instance recovery is allowed after an atomic temp cleanup failure. Re-run the exact
        // owned-name cleanup while the store lock excludes all of our writers; otherwise recovery
        // could ignore a log `.tmp`, clear the health latch, and let repeated failures accumulate
        // unaccounted files. A failed unlink returns while the latch remains set.
        self.cleanup_stale_temps(&self.blobs_dir(), TempDirectory::Blobs)?;
        self.cleanup_stale_temps(&self.log_dir(), TempDirectory::Log)?;
        // Replay into a private candidate. A late signature/chain/cap failure must not expose a
        // verified prefix through a daemon that correctly treats `recover()` as failed.
        let mut recovered = Inner::default();
        let mut count = 0usize;
        let mut max_first_seen = 0u64;
        // Count every physical content-addressed blob, not only those currently referenced by a
        // live row. Orphans can be left by an append whose durable result was uncertain and must
        // continue consuming the aggregate disk budget until compaction removes them.
        let (blob_bytes, blob_count) = self.scan_blob_usage()?;

        let dir = self.log_dir();
        let read = fs::read_dir(&dir).map_err(|error| {
            StoreError::Io(format!("read Bestiary log directory {}: {error}", dir.display()))
        })?;
        // Collect+sort the jsonl files for deterministic replay order across realms.
        let mut files: Vec<(String, PathBuf)> = Vec::new();
        let mut journal_bytes = 0u64;
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
            if !is_artifact_hash(&stem) {
                return Err(StoreError::Corrupt(format!(
                    "bad Bestiary log filename {}",
                    path.display()
                )));
            }
            let file_len = Self::regular_file_len_or_zero(&path)?;
            journal_bytes = self.checked_journal_growth(journal_bytes, file_len)?;
            // In a valid journal every Realm file contains at least one retained live/tombstone
            // key (tombstones are permanent), so a bounded catalog cannot legitimately have more
            // Realm files than retained-key slots. Enforce this while collecting paths so empty or
            // newline-only files cannot turn a byte cap into an unbounded recovery allocation.
            if self.max_entries != 0 && files.len() >= self.max_entries {
                return Err(StoreError::Capacity(format!(
                    "Bestiary journal has more Realm files than the {} retained-key limit",
                    self.max_entries
                )));
            }
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
                expect_seq = expect_seq.checked_add(1).ok_or_else(|| {
                    StoreError::Corrupt(format!("{realm_hash}.jsonl sequence overflow"))
                })?;
                count = count.checked_add(1).ok_or_else(|| {
                    StoreError::Limit("Bestiary recovery record count overflow".into())
                })?;
                max_first_seen = max_first_seen.max(rec.first_seen);
                self.ensure_entry_capacity(&recovered, &rec.op)?;
                Self::apply(&mut recovered, &rec.op, rec.first_seen);
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
            recovered.heads.insert(realm_hash, Head { next_seq: expect_seq, tip_hash: tip });
        }
        recovered.next_first_seen = max_first_seen.saturating_add(1);
        recovered.journal_bytes = journal_bytes;
        recovered.blob_bytes = blob_bytes;
        recovered.blob_count = blob_count;
        *current = recovered;
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
            Self::ensure_healthy(&inner)?;
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
            Self::ensure_healthy(&inner)?;
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
        Self::ensure_healthy(&inner)?;
        let mut durability_at_risk = false;
        let result = (|| -> Result<CompactStats, StoreError> {
            let mut stats = CompactStats::default();
            // Curate a private candidate first. A predictable cap/serialization/allocation failure
            // must leave both the live catalog and every Realm chain untouched.
            let mut candidate = inner.clone();
            let head_first_seen =
                candidate.entries.values().map(|l| l.first_seen).max().unwrap_or(0);
            // Fast metadata-only decide() pass (the byte-needing model call already ran in observe()).
            let keys: Vec<(RealmId, String)> = candidate.entries.keys().cloned().collect();
            for key in keys {
                let Some(live) = candidate.entries.get(&key).cloned() else { continue };
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
                        if let Some(l) = candidate.entries.get_mut(&key) {
                            l.reputation = Some(ReputationScore::unsigned(score, None));
                        }
                    }
                    CurationDecision::Quarantine { reason } => {
                        if let Some(l) = candidate.entries.get_mut(&key) {
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
                        candidate.entries.remove(&key);
                        candidate.tombstones.insert(key);
                        stats.gc += 1;
                    }
                }
            }

            let mut realm_hashes: Vec<String> = candidate.realms.keys().cloned().collect();
            realm_hashes.sort();

            // Discardable dry pass across every Realm. Track the planned aggregate sequentially so
            // a growth in an earlier replacement tightens every later Realm's exact budget. Peak
            // memory remains one replacement chain; no durable file or live catalog changes yet.
            let mut planned_journal_bytes = inner.journal_bytes;
            for realm_hash in &realm_hashes {
                let realm = candidate.realms.get(realm_hash).cloned();
                let Some(realm) = realm else { continue };
                let log_path = self.log_path(realm_hash);
                let old_log_bytes = Self::regular_file_len_or_zero(&log_path)?;
                let other_log_bytes = planned_journal_bytes.checked_sub(old_log_bytes).ok_or_else(
                    || {
                        StoreError::Corrupt(format!(
                            "planned journal accounting {planned_journal_bytes} bytes is smaller than {old_log_bytes} byte Realm log {realm_hash}"
                        ))
                    },
                )?;
                let replacement_budget = if self.max_log_bytes == 0 {
                    None
                } else {
                    Some(self.max_log_bytes.checked_sub(other_log_bytes).ok_or_else(|| {
                        StoreError::Limit(format!(
                            "other Realm journals retain {other_log_bytes} bytes, exceeding {} byte aggregate limit",
                            self.max_log_bytes
                        ))
                    })?)
                };
                let (buffer, _, _) =
                    self.build_compaction_buffer(&candidate, &realm, replacement_budget)?;
                let replacement_bytes = u64::try_from(buffer.len()).map_err(|_| {
                    StoreError::Limit("compacted journal buffer length does not fit u64".into())
                })?;
                planned_journal_bytes =
                    self.checked_journal_growth(other_log_bytes, replacement_bytes)?;
            }

            // All predictable work validated. From here an allocation or I/O error can leave the
            // candidate catalog ahead of disk or some Realm replacements ahead of others, so any
            // error must poison the store until recovery.
            inner.entries = candidate.entries;
            inner.tombstones = candidate.tombstones;
            durability_at_risk = true;
            #[cfg(test)]
            if self.fail_compaction_after_stage.swap(false, Ordering::Relaxed) {
                return Err(StoreError::Io(
                    "injected compaction failure after candidate staging".into(),
                ));
            }

            // Rewrite one fresh genesis chain per Realm. first_seen is preserved verbatim;
            // seq/prev_hash are renumbered. Only one replacement buffer is retained at a time.
            for realm_hash in realm_hashes {
                let realm = inner.realms.get(&realm_hash).cloned();
                let Some(realm) = realm else { continue };
                let log_path = self.log_path(&realm_hash);
                let old_log_bytes = Self::regular_file_len_or_zero(&log_path)?;
                let other_log_bytes =
                    inner.journal_bytes.checked_sub(old_log_bytes).ok_or_else(|| {
                        StoreError::Corrupt(format!(
                            "journal accounting {} bytes is smaller than {} byte Realm log {}",
                            inner.journal_bytes, old_log_bytes, realm_hash
                        ))
                    })?;
                let replacement_budget = if self.max_log_bytes == 0 {
                    None
                } else {
                    Some(self.max_log_bytes.checked_sub(other_log_bytes).ok_or_else(|| {
                        StoreError::Limit(format!(
                            "other Realm journals retain {other_log_bytes} bytes, exceeding {} byte aggregate limit",
                            self.max_log_bytes
                        ))
                    })?)
                };
                let (buffer, next_seq, tip) =
                    self.build_compaction_buffer(&inner, &realm, replacement_budget)?;
                let replacement_bytes = u64::try_from(buffer.len()).map_err(|_| {
                    StoreError::Limit("compacted journal buffer length does not fit u64".into())
                })?;
                let new_journal_bytes =
                    self.checked_journal_growth(other_log_bytes, replacement_bytes)?;
                self.atomic_write(&log_path, &buffer)?;
                if let Err(failure) = self.atomic_write(
                    &self.head_path(&realm_hash),
                    format!("{next_seq} {tip}").as_bytes(),
                ) {
                    if failure.cleanup_failed() {
                        return Err(StoreError::from(failure));
                    }
                }
                inner.heads.insert(realm_hash, Head { next_seq, tip_hash: tip });
                inner.journal_bytes = new_journal_bytes;
            }

            // Global-union blob GC: keep only blobs referenced by some LIVE entry in ANY realm.
            // Validate aggregate accounting before deleting so every decrement is exact. There can
            // be no in-flight Bestiary blob temp while this same process holds `inner`.
            let (physical_blob_bytes, physical_blob_count) = self.scan_blob_usage()?;
            if physical_blob_bytes != inner.blob_bytes || physical_blob_count != inner.blob_count {
                return Err(StoreError::Corrupt(format!(
                    "physical Bestiary blobs retain {physical_blob_count} files / {physical_blob_bytes} bytes but in-memory accounting tracks {} files / {} bytes",
                    inner.blob_count, inner.blob_bytes
                )));
            }
            let live_hashes: HashSet<String> =
                inner.entries.keys().map(|(_, h)| h.clone()).collect();
            let blob_dir = self.blobs_dir();
            let read = fs::read_dir(&blob_dir).map_err(|error| {
                StoreError::Io(format!(
                    "read Bestiary blob directory {} during GC: {error}",
                    blob_dir.display()
                ))
            })?;
            let mut removed_any = false;
            for entry in read {
                let entry = entry.map_err(|error| {
                    StoreError::Io(format!(
                        "read Bestiary blob directory {} during GC: {error}",
                        blob_dir.display()
                    ))
                })?;
                let path = entry.path();
                let name = entry.file_name().into_string().map_err(|_| {
                    StoreError::Corrupt(format!(
                        "unaccountable non-UTF-8 entry in Bestiary blob directory {}",
                        blob_dir.display()
                    ))
                })?;
                if !is_artifact_hash(&name) {
                    return Err(StoreError::Corrupt(format!(
                        "unaccountable Bestiary blob-directory entry {}",
                        path.display()
                    )));
                }
                let metadata = fs::symlink_metadata(&path).map_err(|error| {
                    StoreError::Io(format!("blob {} metadata during GC: {error}", path.display()))
                })?;
                if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                    return Err(StoreError::Corrupt(format!(
                        "blob {} is not a regular non-symlink file",
                        path.display()
                    )));
                }
                if !live_hashes.contains(&name) {
                    fs::remove_file(&path).map_err(|error| {
                        StoreError::Io(format!("remove orphan blob {}: {error}", path.display()))
                    })?;
                    inner.blob_bytes =
                        inner.blob_bytes.checked_sub(metadata.len()).ok_or_else(|| {
                            StoreError::Corrupt(
                                "Bestiary blob accounting underflow during GC".into(),
                            )
                        })?;
                    inner.blob_count = inner.blob_count.checked_sub(1).ok_or_else(|| {
                        StoreError::Corrupt("Bestiary blob count underflow during GC".into())
                    })?;
                    stats.blobs_removed += 1;
                    removed_any = true;
                }
            }
            if removed_any {
                fsync_dir(&blob_dir);
            }
            Ok(stats)
        })();
        if let Err(error) = &result {
            if durability_at_risk || matches!(error, StoreError::Corrupt(_)) {
                // Curation mutates the candidate catalog before Realm logs are replaced, and a
                // multi-Realm rewrite/GC can fail after some durable changes landed. Never continue
                // serving or append from a possibly divergent head. A pre-stage accounting
                // corruption is equally unsafe even though predictable Limit/allocation refusals
                // leave the old state operational. Only recovery may re-establish corrupt state.
                Self::mark_unhealthy(
                    &mut inner,
                    format!("compaction did not complete atomically: {error}"),
                );
            }
        }
        result
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
    fn startup_removes_only_exact_regular_owned_temps() {
        let root = TempRoot::new("stale-temps");
        let blobs = root.0.join("blobs");
        let log = root.0.join("log");
        fs::create_dir_all(&blobs).unwrap();
        fs::create_dir_all(&log).unwrap();
        let hash = "a".repeat(64);
        let blob_temp = blobs.join(format!(".{hash}.123.7.tmp"));
        let log_temp = log.join(format!(".{hash}.jsonl.123.8.tmp"));
        let unrelated = blobs.join(".operator-note");
        fs::write(&blob_temp, b"stale").unwrap();
        fs::write(&log_temp, b"stale").unwrap();
        fs::write(&unrelated, b"keep").unwrap();

        let _store = store(&root);
        assert!(!blob_temp.exists(), "owned stale blob temp removed");
        assert!(!log_temp.exists(), "owned stale log temp removed");
        assert!(unrelated.exists(), "non-Bestiary dotfile left untouched");
    }

    #[test]
    fn startup_fails_closed_on_non_regular_owned_temp() {
        let root = TempRoot::new("stale-temp-type");
        let log = root.0.join("log");
        fs::create_dir_all(root.0.join("blobs")).unwrap();
        fs::create_dir_all(&log).unwrap();
        let owned_name = format!(".{}.head.123.9.tmp", "b".repeat(64));
        fs::create_dir(log.join(owned_name)).unwrap();

        let opened = FsBestiaryStore::new(&root.0, key());
        assert!(
            matches!(opened, Err(StoreError::Corrupt(_))),
            "an owned temp with an unexpected inode type fails closed"
        );
    }

    #[test]
    fn same_instance_recovery_cleans_exact_owned_temps_before_clearing_health() {
        let root = TempRoot::new("recover-temp-cleanup");
        let store = store(&root);
        let hash = "d".repeat(64);
        let blob_temp = store.blobs_dir().join(format!(".{hash}.123.10.tmp"));
        let log_temp = store.log_dir().join(format!(".{hash}.head.123.11.tmp"));
        fs::write(&blob_temp, b"failed blob temp").unwrap();
        fs::write(&log_temp, b"failed head temp").unwrap();
        {
            let mut inner = store.inner.lock().unwrap();
            FsBestiaryStore::mark_unhealthy(&mut inner, "injected atomic temp cleanup uncertainty");
        }

        assert_eq!(store.recover().unwrap(), 0);

        assert!(!blob_temp.exists());
        assert!(!log_temp.exists());
        assert!(store.inner.lock().unwrap().unhealthy_reason.is_none());
    }

    #[test]
    fn failed_atomic_rename_removes_its_temp() {
        let root = TempRoot::new("atomic-temp-guard");
        let store = store(&root);
        let hash = "c".repeat(64);
        let destination = store.blob_path(&hash);
        fs::create_dir(&destination).unwrap();
        let expected_temp = store.blobs_dir().join(format!(".{hash}.{}.0.tmp", std::process::id()));

        let result = store.atomic_write(&destination, b"cannot replace a directory");
        assert!(matches!(result, Err(AtomicWriteFailure::Operation(StoreError::Io(_)))));
        assert!(!expected_temp.exists(), "RAII guard removed the failed atomic temp");
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
    fn republish_recreates_a_missing_live_blob_and_rebases_physical_accounting() {
        let root = TempRoot::new("blob-missing-heal");
        let s = store(&root);
        let realm = RealmId::new("crew");
        let bytes = b"artifact-bytes".to_vec();
        let hash = s.put(&realm, manifest("c"), bytes.clone()).unwrap();
        fs::remove_file(s.blob_path(&hash)).unwrap();

        let healed = s.put(&realm, manifest("c"), bytes.clone()).unwrap();

        assert_eq!(healed, hash);
        let inner = s.inner.lock().unwrap();
        assert_eq!(inner.blob_bytes, bytes.len() as u64, "repair does not double-charge bytes");
        assert_eq!(inner.blob_count, 1, "repair restores exactly one physical file");
        drop(inner);
        assert_eq!(s.get(&realm, &hash).unwrap().unwrap().artifact, bytes);
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
        assert!(matches!(err, StoreError::Invalid(_)), "invalid manifest rejected: {err:?}");
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
    fn capacity_counts_permanent_tombstones_and_live_to_tombstone_is_neutral() {
        let root = TempRoot::new("tombstone-cap");
        let s = store(&root).with_max_entries(1);
        let realm = RealmId::local();
        let live_hash = s.put(&realm, manifest("a"), b"one".to_vec()).unwrap();

        assert!(s.tombstone(&realm, &live_hash).unwrap(), "live key becomes a tombstone at cap");
        assert_eq!(
            FsBestiaryStore::retained_key_count(&s.inner.lock().unwrap()),
            1,
            "the live-to-tombstone transition consumes no new slot"
        );

        let absent_hash = sha256_hex(b"never-published");
        let refused_tombstone = s.tombstone(&realm, &absent_hash);
        assert!(
            matches!(refused_tombstone, Err(StoreError::Capacity(_))),
            "an absent key cannot create a second retained tombstone at cap: {refused_tombstone:?}"
        );
        let refused_put = s.put(&realm, manifest("b"), b"two".to_vec());
        assert!(
            matches!(refused_put, Err(StoreError::Capacity(_))),
            "the permanent tombstone continues to occupy the only retained-key slot"
        );
        assert!(!s.tombstone(&realm, &live_hash).unwrap(), "the tombstone remains idempotent");
    }

    #[test]
    fn default_entry_cap_is_bounded_and_zero_opt_out_is_explicit() {
        let root = TempRoot::new("default-cap");
        let s = store(&root);
        assert_eq!(s.max_entries, DEFAULT_MAX_BESTIARY_ENTRIES);
        assert_eq!(s.max_blob_bytes, DEFAULT_MAX_BESTIARY_BLOB_BYTES);
        assert_eq!(s.max_log_bytes, DEFAULT_MAX_BESTIARY_LOG_BYTES);

        let unbounded_root = TempRoot::new("default-cap-unbounded");
        let unbounded =
            store(&unbounded_root).with_max_entries(0).with_max_blob_bytes(0).with_max_log_bytes(0);
        assert_eq!(unbounded.max_entries, 0, "0 is the explicit unbounded opt-out");
        assert_eq!(unbounded.max_blob_bytes, 0, "blob bytes have the same explicit opt-out");
        assert_eq!(unbounded.max_log_bytes, 0, "journal bytes have the same explicit opt-out");
    }

    #[test]
    fn aggregate_blob_cap_counts_physical_content_once_across_realms() {
        let root = TempRoot::new("blob-cap-dedupe");
        let s = store(&root).with_max_blob_bytes(4);
        let realm_a = RealmId::new("a");
        let realm_b = RealmId::new("b");
        let bytes = b"same".to_vec();

        let hash = s.put(&realm_a, manifest("a"), bytes.clone()).unwrap();
        assert_eq!(s.put(&realm_b, manifest("b"), bytes).unwrap(), hash);
        {
            let inner = s.inner.lock().unwrap();
            assert_eq!(inner.blob_bytes, 4, "cross-Realm dedupe charges physical bytes once");
            assert_eq!(inner.blob_count, 1, "cross-Realm dedupe retains one physical file");
        }

        let refused_hash = sha256_hex(b"x");
        let error = s
            .put(&RealmId::new("c"), manifest("c"), b"x".to_vec())
            .expect_err("a fifth aggregate blob byte is refused before its atomic write");
        assert!(matches!(error, StoreError::Limit(_)), "aggregate blob cap is explicit: {error:?}");
        assert!(!s.blob_path(&refused_hash).exists(), "over-cap blob was never written");
    }

    #[test]
    fn recovery_counts_orphan_blob_bytes_and_reconstructs_exact_usage() {
        let root = TempRoot::new("blob-recovery-cap");
        let realm = RealmId::local();
        {
            let writer = store(&root).with_max_blob_bytes(0);
            writer.put(&realm, manifest("live"), b"four".to_vec()).unwrap();
        }
        let orphan = b"xyz";
        let orphan_hash = sha256_hex(orphan);
        fs::write(root.0.join("blobs").join(&orphan_hash), orphan).unwrap();

        let too_small = store(&root).with_max_blob_bytes(6);
        let error = too_small
            .recover()
            .expect_err("the unreferenced physical blob still consumes aggregate capacity");
        assert!(matches!(error, StoreError::Limit(_)), "orphan bytes fail closed: {error:?}");
        assert!(
            matches!(too_small.list_metadata(None), Err(StoreError::Unhealthy(_))),
            "failed recovery never enables the catalog"
        );
        drop(too_small);

        let exact = store(&root).with_max_blob_bytes(7);
        assert_eq!(exact.recover().unwrap(), 1);
        let inner = exact.inner.lock().unwrap();
        assert_eq!(inner.blob_bytes, 7);
        assert_eq!(inner.blob_count, 2);
    }

    #[test]
    fn recovery_rejects_unaccountable_or_non_regular_blob_entries() {
        let unknown_root = TempRoot::new("blob-recovery-unknown");
        fs::create_dir_all(unknown_root.0.join("blobs")).unwrap();
        fs::create_dir_all(unknown_root.0.join("log")).unwrap();
        fs::write(unknown_root.0.join("blobs").join(".operator-note"), b"not a blob").unwrap();
        let unknown = store(&unknown_root);
        assert!(
            matches!(unknown.recover(), Err(StoreError::Corrupt(_))),
            "unaccountable physical disk use fails closed"
        );

        let special_root = TempRoot::new("blob-recovery-special");
        fs::create_dir_all(special_root.0.join("blobs")).unwrap();
        fs::create_dir_all(special_root.0.join("log")).unwrap();
        fs::create_dir(special_root.0.join("blobs").join("a".repeat(64))).unwrap();
        let special = store(&special_root);
        assert!(
            matches!(special.recover(), Err(StoreError::Corrupt(_))),
            "a digest-named special inode fails closed"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;

            let symlink_root = TempRoot::new("blob-recovery-symlink");
            fs::create_dir_all(symlink_root.0.join("blobs")).unwrap();
            fs::create_dir_all(symlink_root.0.join("log")).unwrap();
            symlink(
                symlink_root.0.join("outside"),
                symlink_root.0.join("blobs").join("b".repeat(64)),
            )
            .unwrap();
            let linked = store(&symlink_root);
            assert!(
                matches!(linked.recover(), Err(StoreError::Corrupt(_))),
                "a digest-named symlink fails closed"
            );
        }
    }

    #[test]
    fn physical_blob_count_is_bounded_with_retained_keys() {
        let root = TempRoot::new("blob-file-count");
        let realm = RealmId::local();
        {
            let writer = store(&root).with_max_entries(0).with_max_blob_bytes(0);
            writer.put(&realm, manifest("live"), b"one".to_vec()).unwrap();
        }
        let orphan = b"two";
        fs::write(root.0.join("blobs").join(sha256_hex(orphan)), orphan).unwrap();

        let capped = store(&root).with_max_entries(1);
        let error = capped
            .recover()
            .expect_err("tiny orphan files cannot bypass the finite default inode bound");
        assert!(matches!(error, StoreError::Limit(_)), "physical file cap is explicit: {error:?}");
    }

    #[test]
    fn gc_decrements_aggregate_blob_bytes_and_count() {
        let root = TempRoot::new("blob-gc-accounting");
        let s = store(&root).with_max_blob_bytes(7);
        let realm = RealmId::local();
        s.put(&realm, manifest("keep"), b"one".to_vec()).unwrap();
        let removed_hash = s.put(&realm, manifest("remove"), b"four".to_vec()).unwrap();
        s.tombstone(&realm, &removed_hash).unwrap();
        assert_eq!(s.inner.lock().unwrap().blob_bytes, 7);

        let stats = s.compact(&DeterministicCurator::default()).unwrap();

        assert_eq!(stats.blobs_removed, 1);
        let inner = s.inner.lock().unwrap();
        assert_eq!(inner.blob_bytes, 3);
        assert_eq!(inner.blob_count, 1);
    }

    #[test]
    fn definitely_prewrite_append_failure_rolls_back_only_its_new_blob() {
        let root = TempRoot::new("append-prewrite-failure");
        let s = store(&root);
        let realm = RealmId::local();
        let log_path = s.log_path(&FsBestiaryStore::realm_hash(&realm));
        fs::create_dir(&log_path).unwrap();
        let bytes = b"new-blob";
        let hash = sha256_hex(bytes);

        let error = s
            .put(&realm, manifest("new"), bytes.to_vec())
            .expect_err("opening a directory as an append log fails before any write");

        assert!(matches!(error, StoreError::Io(_)), "pre-write open error is reported: {error:?}");
        assert!(!s.blob_path(&hash).exists(), "only the provably new blob was rolled back");
        let inner = s.inner.lock().unwrap();
        assert_eq!(inner.blob_bytes, 0);
        assert_eq!(inner.blob_count, 0);
        assert!(inner.unhealthy_reason.is_none(), "a proven pre-write failure is retryable");
    }

    #[test]
    fn uncertain_append_keeps_blob_and_gates_store_until_reopen_recovery() {
        let root = TempRoot::new("append-uncertain-latch");
        let realm = RealmId::local();
        let bytes = b"possibly-durable";
        let hash = sha256_hex(bytes);
        {
            let s = store(&root);
            s.fail_append_after_write.store(true, Ordering::Relaxed);
            let error = s
                .put(&realm, manifest("uncertain"), bytes.to_vec())
                .expect_err("fault is injected after the complete line write");
            assert!(matches!(error, StoreError::Io(_)));
            assert!(s.blob_path(&hash).exists(), "uncertain append never deletes its blob");
            assert!(matches!(s.get(&realm, &hash), Err(StoreError::Unhealthy(_))));
            assert!(matches!(s.signed_entries(None), Err(StoreError::Unhealthy(_))));
            assert!(matches!(
                s.compact(&DeterministicCurator::default()),
                Err(StoreError::Unhealthy(_))
            ));
            assert!(matches!(
                s.put(&realm, manifest("blocked"), b"another".to_vec()),
                Err(StoreError::Unhealthy(_))
            ));
        }

        let reopened = store(&root);
        assert!(matches!(reopened.get(&realm, &hash), Err(StoreError::Unhealthy(_))));
        assert_eq!(reopened.recover().unwrap(), 1);
        assert_eq!(reopened.get(&realm, &hash).unwrap().unwrap().artifact, bytes);
    }

    #[test]
    fn compaction_failure_after_staging_poison_latches_but_dry_run_limit_does_not() {
        let staged_root = TempRoot::new("compact-staged-latch");
        let staged = store(&staged_root);
        let realm = RealmId::local();
        let hash = staged.put(&realm, manifest("a"), b"one".to_vec()).unwrap();
        staged.fail_compaction_after_stage.store(true, Ordering::Relaxed);
        let error = staged
            .compact(&DeterministicCurator::default())
            .expect_err("fault after candidate staging is durability-uncertain");
        assert!(matches!(error, StoreError::Io(_)));
        assert!(matches!(staged.get(&realm, &hash), Err(StoreError::Unhealthy(_))));

        let dry_root = TempRoot::new("compact-dry-limit");
        let mut dry = store(&dry_root);
        let dry_hash = dry.put(&realm, manifest("b"), b"two".to_vec()).unwrap();
        dry.max_log_bytes = 1;
        let error = dry
            .compact(&DeterministicCurator::default())
            .expect_err("the dry pass proves this replacement cannot fit");
        assert!(matches!(error, StoreError::Limit(_)));
        assert!(dry.get(&realm, &dry_hash).unwrap().is_some(), "dry failure changes no state");
        assert!(dry.inner.lock().unwrap().unhealthy_reason.is_none());
    }

    #[test]
    fn recovery_rejects_a_shrunk_retained_key_cap_and_reopens_with_sufficient_capacity() {
        let root = TempRoot::new("recover-over-cap");
        let realm = RealmId::local();
        let live_then_tombstoned;
        let absent_tombstone = sha256_hex(b"never-published");
        {
            let writer = store(&root).with_max_entries(0);
            live_then_tombstoned = writer.put(&realm, manifest("a"), b"one".to_vec()).unwrap();
            writer.tombstone(&realm, &live_then_tombstoned).unwrap();
            writer.tombstone(&realm, &absent_tombstone).unwrap();
        }

        let capped = store(&root).with_max_entries(1);
        let error =
            capped.recover().expect_err("two permanent keys cannot recover through a one-key cap");
        assert!(
            matches!(error, StoreError::Capacity(_)),
            "entry-cap recovery failure is explicit: {error:?}"
        );
        assert_eq!(
            FsBestiaryStore::retained_key_count(&capped.inner.lock().unwrap()),
            0,
            "failed replay exposes no verified prefix"
        );
        drop(capped);

        let sufficient = store(&root).with_max_entries(2);
        sufficient.recover().unwrap();
        assert!(sufficient.get(&realm, &live_then_tombstoned).unwrap().is_none());
        assert!(sufficient.get(&realm, &absent_tombstone).unwrap().is_none());
        assert_eq!(FsBestiaryStore::retained_key_count(&sufficient.inner.lock().unwrap()), 2);
    }

    #[test]
    fn journal_cap_preflights_before_retaining_an_orphan_blob() {
        let root = TempRoot::new("journal-append-cap");
        let s = store(&root).with_max_log_bytes(1);
        let realm = RealmId::local();
        let bytes = b"artifact-that-must-not-be-orphaned";
        let hash = sha256_hex(bytes);

        let error = s
            .put(&realm, manifest("a"), bytes.to_vec())
            .expect_err("one byte cannot hold a signed journal record");
        assert!(matches!(error, StoreError::Limit(_)), "journal cap is explicit: {error:?}");
        assert!(!s.blob_path(&hash).exists(), "failed journal admission retained no orphan blob");
        assert!(
            !s.log_path(&FsBestiaryStore::realm_hash(&realm)).exists(),
            "failed preflight wrote no journal"
        );
    }

    #[test]
    fn recovery_enforces_the_aggregate_journal_cap_across_realms() {
        let root = TempRoot::new("journal-recovery-cap");
        let realm_a = RealmId::new("a");
        let realm_b = RealmId::new("b");
        {
            let writer = store(&root).with_max_log_bytes(0);
            writer.put(&realm_a, manifest("a"), b"one".to_vec()).unwrap();
            writer.put(&realm_b, manifest("b"), b"two".to_vec()).unwrap();
        }
        let total = [realm_a.clone(), realm_b.clone()]
            .iter()
            .map(|realm| {
                fs::metadata(
                    root.0
                        .join("log")
                        .join(format!("{}.jsonl", FsBestiaryStore::realm_hash(realm))),
                )
                .unwrap()
                .len()
            })
            .sum::<u64>();

        let too_small = store(&root).with_max_log_bytes(total - 1);
        let error = too_small
            .recover()
            .expect_err("the cap is global rather than repeated independently per Realm");
        assert!(
            matches!(error, StoreError::Limit(_)),
            "aggregate cap rejected recovery: {error:?}"
        );
        drop(too_small);

        let exact = store(&root).with_max_log_bytes(total);
        assert_eq!(exact.recover().unwrap(), 2);
        assert_eq!(exact.inner.lock().unwrap().journal_bytes, total);
    }

    #[test]
    fn compaction_rewrites_with_bounded_current_journal_accounting() {
        let root = TempRoot::new("journal-compaction-accounting");
        let s = store(&root);
        let realm = RealmId::local();
        let bytes = b"same-artifact".to_vec();
        s.put(&realm, manifest("first"), bytes.clone()).unwrap();
        s.put(&realm, manifest("replacement"), bytes).unwrap();
        let log_path = s.log_path(&FsBestiaryStore::realm_hash(&realm));
        let before = fs::metadata(&log_path).unwrap().len();

        s.compact(&DeterministicCurator::default()).unwrap();

        let after = fs::metadata(&log_path).unwrap().len();
        assert!(after < before, "genesis rewrite removed superseded history");
        assert_eq!(s.inner.lock().unwrap().journal_bytes, after);
    }
}
