//! `job-blob-fs` — the bounded reference store for opaque job value bytes.
//!
//! The function contract only names content-addressed values. It deliberately does not prescribe
//! where those bytes live. This crate is the small filesystem filling used by the reference
//! runtime: write to a same-directory temporary file, fsync it, rename it into place, fsync the
//! directory, and verify both size and SHA-256 whenever the value is read.
//!
//! Values may be ciphertext. The store never interprets, decrypts, or authorizes them; those are
//! separate policy and execution concerns.

#![forbid(unsafe_code)]

use gawdfn::{BlobRefV1, Validate};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use thiserror::Error;

/// Reference defaults are intentionally finite. Operators must opt in to larger stores.
pub const DEFAULT_MAX_BLOB_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_MAX_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
pub const DEFAULT_MAX_BLOBS: usize = 16_384;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredBlob {
    /// Lowercase SHA-256 hex without a prefix.
    pub sha256: String,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobCaps {
    pub max_blob_bytes: usize,
    pub max_total_bytes: u64,
    pub max_blobs: usize,
}

impl Default for BlobCaps {
    fn default() -> Self {
        Self {
            max_blob_bytes: DEFAULT_MAX_BLOB_BYTES,
            max_total_bytes: DEFAULT_MAX_TOTAL_BYTES,
            max_blobs: DEFAULT_MAX_BLOBS,
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BlobStoreError {
    #[error("blob store I/O error: {0}")]
    Io(String),
    #[error("blob store is corrupt: {0}")]
    Corrupt(String),
    #[error("invalid SHA-256 address `{0}`")]
    InvalidAddress(String),
    #[error("blob is too large: {actual} bytes exceeds {limit}")]
    BlobTooLarge { actual: usize, limit: usize },
    #[error("blob store entry limit reached: {limit}")]
    EntryLimit { limit: usize },
    #[error("blob store byte limit reached: adding {adding} to {current} exceeds {limit}")]
    ByteLimit { current: u64, adding: u64, limit: u64 },
    #[error("blob `{0}` not found")]
    NotFound(String),
    #[error("blob-store durability is uncertain; reopen before writing")]
    Uncertain,
}

#[derive(Debug)]
struct Index {
    sizes: HashMap<String, u64>,
    total_bytes: u64,
    orphan_entries: usize,
    orphan_bytes: u64,
    healthy: bool,
}

impl Default for Index {
    fn default() -> Self {
        Self {
            sizes: HashMap::new(),
            total_bytes: 0,
            orphan_entries: 0,
            orphan_bytes: 0,
            healthy: true,
        }
    }
}

/// A process-local handle to a filesystem CAS. One instance serializes writes; operators must not
/// open the same directory from multiple processes simultaneously.
pub struct FsJobBlobStore {
    root: PathBuf,
    caps: BlobCaps,
    index: Mutex<Index>,
    tmp_seq: AtomicU64,
}

impl FsJobBlobStore {
    /// Open an existing store or create an empty one. Recovery scans every non-temporary file and
    /// verifies that its filename equals the hash of its bytes. Any malformed or corrupt file makes
    /// the whole open fail closed; authority must not silently continue over partial job values.
    pub fn open(root: impl AsRef<Path>, caps: BlobCaps) -> Result<Self, BlobStoreError> {
        validate_caps(caps)?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(io_err)?;
        let mut index = Index::default();
        for entry in fs::read_dir(&root).map_err(io_err)? {
            let entry = entry.map_err(io_err)?;
            let ty = entry.file_type().map_err(io_err)?;
            if !ty.is_file() {
                return Err(BlobStoreError::Corrupt(format!(
                    "unexpected non-file entry `{}`",
                    entry.path().display()
                )));
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| BlobStoreError::Corrupt("non-UTF-8 filename".into()))?;
            if name.starts_with('.') && name.ends_with(".tmp") {
                // A crash before rename leaves an uncommitted value. It is safe to ignore, but not
                // delete automatically: preserving evidence keeps recovery auditable. Orphans
                // still consume the configured finite capacity so repeated crashes cannot grow an
                // allegedly bounded store without limit.
                validate_temp_name(&name)?;
                let size = entry.metadata().map_err(io_err)?.len();
                if size > caps.max_blob_bytes as u64 {
                    return Err(BlobStoreError::Corrupt(format!(
                        "temporary blob `{name}` exceeds the per-blob limit"
                    )));
                }
                index.orphan_entries = index.orphan_entries.saturating_add(1);
                index.orphan_bytes = index.orphan_bytes.checked_add(size).ok_or_else(|| {
                    BlobStoreError::Corrupt("temporary blob byte count overflow".into())
                })?;
                if index.sizes.len() + index.orphan_entries > caps.max_blobs
                    || index.total_bytes.saturating_add(index.orphan_bytes) > caps.max_total_bytes
                {
                    return Err(BlobStoreError::Corrupt(
                        "temporary crash evidence exceeds configured store capacity".into(),
                    ));
                }
                continue;
            }
            validate_hash(&name)?;
            if index.sizes.len() >= caps.max_blobs {
                return Err(BlobStoreError::Corrupt(format!(
                    "recovered entries exceed configured limit {}",
                    caps.max_blobs
                )));
            }
            let size = entry.metadata().map_err(io_err)?.len();
            if size > caps.max_blob_bytes as u64 {
                return Err(BlobStoreError::Corrupt(format!(
                    "blob `{name}` is {size} bytes, over configured per-blob limit {}",
                    caps.max_blob_bytes
                )));
            }
            let actual = hash_file(&entry.path(), caps.max_blob_bytes)?;
            if actual != name {
                return Err(BlobStoreError::Corrupt(format!("blob `{name}` hashes to `{actual}`")));
            }
            index.total_bytes = index
                .total_bytes
                .checked_add(size)
                .ok_or_else(|| BlobStoreError::Corrupt("recovered byte count overflow".into()))?;
            if index.sizes.len() + 1 + index.orphan_entries > caps.max_blobs
                || index.total_bytes.saturating_add(index.orphan_bytes) > caps.max_total_bytes
            {
                return Err(BlobStoreError::Corrupt(
                    "recovered entries/bytes exceed configured finite store limits".into(),
                ));
            }
            index.sizes.insert(name, size);
        }
        // Reopen is the only way out of an uncertain write. Re-sync the directory so a blob that is
        // visible after a failed parent fsync cannot be reported recovered before a fresh fence.
        fsync_dir(&root)?;
        Ok(Self { root, caps, index: Mutex::new(index), tmp_seq: AtomicU64::new(0) })
    }

    /// Persist bytes and return their stable address. Re-putting identical bytes is idempotent and
    /// does not consume capacity again.
    pub fn put(&self, bytes: &[u8]) -> Result<StoredBlob, BlobStoreError> {
        if bytes.len() > self.caps.max_blob_bytes {
            return Err(BlobStoreError::BlobTooLarge {
                actual: bytes.len(),
                limit: self.caps.max_blob_bytes,
            });
        }
        let sha256 = sha256_hex(bytes);
        let size = bytes.len() as u64;
        let mut index = self.index.lock().unwrap_or_else(|p| p.into_inner());
        if !index.healthy {
            return Err(BlobStoreError::Uncertain);
        }
        if let Some(existing) = index.sizes.get(&sha256) {
            if *existing != size {
                return Err(BlobStoreError::Corrupt(format!(
                    "indexed size for `{sha256}` is {existing}, expected {size}"
                )));
            }
            // Do not trust presence alone: a post-open mutation must fail before dedupe succeeds.
            let existing_bytes = self.read_verified(&sha256, *existing)?;
            if existing_bytes != bytes {
                return Err(BlobStoreError::Corrupt(format!(
                    "existing blob `{sha256}` differs from addressed bytes"
                )));
            }
            return Ok(StoredBlob { sha256, size });
        }
        if index.sizes.len() + index.orphan_entries >= self.caps.max_blobs {
            return Err(BlobStoreError::EntryLimit { limit: self.caps.max_blobs });
        }
        let occupied =
            index.total_bytes.checked_add(index.orphan_bytes).ok_or(BlobStoreError::ByteLimit {
                current: index.total_bytes,
                adding: size,
                limit: self.caps.max_total_bytes,
            })?;
        let next_occupied = occupied.checked_add(size).ok_or(BlobStoreError::ByteLimit {
            current: occupied,
            adding: size,
            limit: self.caps.max_total_bytes,
        })?;
        if next_occupied > self.caps.max_total_bytes {
            return Err(BlobStoreError::ByteLimit {
                current: occupied,
                adding: size,
                limit: self.caps.max_total_bytes,
            });
        }

        self.put_new_blob(&mut index, bytes, sha256, size, fsync_dir)
    }

    fn put_new_blob<F>(
        &self,
        index: &mut Index,
        bytes: &[u8],
        sha256: String,
        size: u64,
        sync_parent: F,
    ) -> Result<StoredBlob, BlobStoreError>
    where
        F: FnOnce(&Path) -> Result<(), BlobStoreError>,
    {
        let dest = self.root.join(&sha256);
        let (mut file, tmp) = self.create_temp(&sha256)?;
        if let Err(error) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            index.healthy = false;
            return Err(io_err(error));
        }
        drop(file);
        if let Err(error) = fs::rename(&tmp, &dest) {
            index.healthy = false;
            return Err(io_err(error));
        }
        if let Err(error) = sync_parent(&self.root) {
            index.healthy = false;
            return Err(error);
        }
        index.total_bytes = index.total_bytes.saturating_add(size);
        index.sizes.insert(sha256.clone(), size);
        Ok(StoredBlob { sha256, size })
    }

    fn create_temp(&self, sha256: &str) -> Result<(File, PathBuf), BlobStoreError> {
        // `tmp_seq` intentionally restarts when a process reopens the store. A same-pid test,
        // supervisor, or PID reuse can therefore encounter preserved crash evidence. Never
        // truncate it: create_new plus the finite store cap gives a bounded collision search.
        for _ in 0..=self.caps.max_blobs {
            let sequence = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
            let path = self.root.join(format!(".{sha256}.{}.{sequence}.tmp", std::process::id()));
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => return Ok((file, path)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(io_err(error)),
            }
        }
        Err(BlobStoreError::Corrupt(
            "temporary blob namespace exhausted within configured entry limit".into(),
        ))
    }

    /// Contract adapter used by job records. The same bytes can be referenced with distinct media
    /// types without being stored twice.
    pub fn put_ref(
        &self,
        media_type: impl Into<String>,
        bytes: &[u8],
    ) -> Result<BlobRefV1, BlobStoreError> {
        let stored = self.put(bytes)?;
        let reference = BlobRefV1 {
            digest: format!("sha256:{}", stored.sha256),
            size: stored.size,
            media_type: media_type.into(),
        };
        reference.validate().map_err(|error| BlobStoreError::Corrupt(error.to_string()))?;
        Ok(reference)
    }

    /// Fetch through the shared contract reference, checking the signed size claim as well as the
    /// content digest.
    pub fn get_ref(&self, reference: &BlobRefV1) -> Result<Vec<u8>, BlobStoreError> {
        reference.validate().map_err(|error| BlobStoreError::InvalidAddress(error.to_string()))?;
        let sha256 = reference
            .digest
            .strip_prefix("sha256:")
            .ok_or_else(|| BlobStoreError::InvalidAddress(reference.digest.clone()))?;
        let bytes = self.get(sha256)?;
        if bytes.len() as u64 != reference.size {
            return Err(BlobStoreError::Corrupt(format!(
                "blob reference size {} does not match stored size {}",
                reference.size,
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    pub fn get(&self, sha256: &str) -> Result<Vec<u8>, BlobStoreError> {
        validate_hash(sha256)?;
        let index = self.index.lock().unwrap_or_else(|p| p.into_inner());
        let size =
            *index.sizes.get(sha256).ok_or_else(|| BlobStoreError::NotFound(sha256.to_string()))?;
        self.read_verified(sha256, size)
    }

    pub fn contains(&self, sha256: &str) -> bool {
        validate_hash(sha256).is_ok()
            && self.index.lock().unwrap_or_else(|p| p.into_inner()).sizes.contains_key(sha256)
    }

    pub fn len(&self) -> usize {
        self.index.lock().unwrap_or_else(|p| p.into_inner()).sizes.len()
    }

    pub fn total_bytes(&self) -> u64 {
        self.index.lock().unwrap_or_else(|p| p.into_inner()).total_bytes
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read_verified(&self, sha256: &str, expected_size: u64) -> Result<Vec<u8>, BlobStoreError> {
        let mut file = File::open(self.root.join(sha256))
            .map_err(|e| BlobStoreError::Corrupt(format!("blob `{sha256}` unreadable: {e}")))?;
        let mut bytes = Vec::new();
        Read::by_ref(&mut file)
            .take(self.caps.max_blob_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(io_err)?;
        if bytes.len() > self.caps.max_blob_bytes {
            return Err(BlobStoreError::Corrupt(format!(
                "blob `{sha256}` grew past configured limit"
            )));
        }
        if bytes.len() as u64 != expected_size {
            return Err(BlobStoreError::Corrupt(format!(
                "blob `{sha256}` size changed: expected {expected_size}, got {}",
                bytes.len()
            )));
        }
        let actual = sha256_hex(&bytes);
        if actual != sha256 {
            return Err(BlobStoreError::Corrupt(format!("blob `{sha256}` hashes to `{actual}`")));
        }
        Ok(bytes)
    }
}

fn validate_caps(caps: BlobCaps) -> Result<(), BlobStoreError> {
    if caps.max_blob_bytes == 0 || caps.max_total_bytes == 0 || caps.max_blobs == 0 {
        return Err(BlobStoreError::Corrupt(
            "all reference blob-store limits must be non-zero".into(),
        ));
    }
    Ok(())
}

fn validate_hash(hash: &str) -> Result<(), BlobStoreError> {
    if hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) {
        Ok(())
    } else {
        Err(BlobStoreError::InvalidAddress(hash.to_string()))
    }
}

fn validate_temp_name(name: &str) -> Result<(), BlobStoreError> {
    let body = name
        .strip_prefix('.')
        .and_then(|value| value.strip_suffix(".tmp"))
        .ok_or_else(|| BlobStoreError::Corrupt(format!("malformed temporary file `{name}`")))?;
    let mut parts = body.split('.');
    let hash = parts.next().unwrap_or_default();
    let pid = parts.next().and_then(|value| value.parse::<u32>().ok());
    let sequence = parts.next().and_then(|value| value.parse::<u64>().ok());
    if parts.next().is_some() || pid.is_none_or(|pid| pid == 0) || sequence.is_none() {
        return Err(BlobStoreError::Corrupt(format!("malformed temporary file `{name}`")));
    }
    validate_hash(hash).map_err(|_| {
        BlobStoreError::Corrupt(format!("temporary file `{name}` has an invalid digest"))
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn hash_file(path: &Path, max_bytes: usize) -> Result<String, BlobStoreError> {
    let mut file = File::open(path).map_err(io_err)?;
    let mut hasher = Sha256::new();
    let mut total = 0usize;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(io_err)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n);
        if total > max_bytes {
            return Err(BlobStoreError::Corrupt(format!(
                "blob `{}` exceeds configured limit while hashing",
                path.display()
            )));
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn fsync_dir(path: &Path) -> Result<(), BlobStoreError> {
    File::open(path).and_then(|f| f.sync_all()).map_err(io_err)
}

fn io_err(err: std::io::Error) -> BlobStoreError {
    BlobStoreError::Io(err.to_string())
}

impl gawdfn::BlobAvailability for FsJobBlobStore {
    fn verify_available(&self, blob: &BlobRefV1) -> Result<(), gawdfn::ContractError> {
        self.get_ref(blob)
            .map(|_| ())
            .map_err(|error| gawdfn::ContractError::Invalid(error.to_string()))
    }
}

impl gawdfn::CheckpointBlobStore for FsJobBlobStore {
    fn put_checkpoint(
        &self,
        media_type: &str,
        bytes: &[u8],
    ) -> Result<BlobRefV1, gawdfn::ContractError> {
        self.put_ref(media_type, bytes)
            .map_err(|error| gawdfn::ContractError::Invalid(error.to_string()))
    }

    fn get_checkpoint(&self, blob: &BlobRefV1) -> Result<Vec<u8>, gawdfn::ContractError> {
        self.get_ref(blob).map_err(|error| gawdfn::ContractError::Invalid(error.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir()
                .join(format!("alpha-job-blob-{name}-{}-{nonce}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn put_is_durable_deduplicated_and_recoverable() {
        let dir = TempDir::new("roundtrip");
        let reference;
        {
            let store = FsJobBlobStore::open(&dir.0, BlobCaps::default()).unwrap();
            reference = store.put(b"opaque ciphertext").unwrap();
            assert_eq!(store.put(b"opaque ciphertext").unwrap(), reference);
            assert_eq!(store.len(), 1);
        }
        let recovered = FsJobBlobStore::open(&dir.0, BlobCaps::default()).unwrap();
        assert_eq!(recovered.get(&reference.sha256).unwrap(), b"opaque ciphertext");
        assert_eq!(recovered.total_bytes(), reference.size);
    }

    #[test]
    fn shared_blob_reference_checks_size_and_digest() {
        let dir = TempDir::new("contract-ref");
        let store = FsJobBlobStore::open(&dir.0, BlobCaps::default()).unwrap();
        let reference = store.put_ref("application/octet-stream", b"sealed").unwrap();
        assert!(reference.digest.starts_with("sha256:"));
        assert_eq!(store.get_ref(&reference).unwrap(), b"sealed");
        let mut wrong = reference;
        wrong.size += 1;
        assert!(matches!(store.get_ref(&wrong), Err(BlobStoreError::Corrupt(_))));
    }

    #[test]
    fn caps_refuse_growth_but_allow_dedup() {
        let dir = TempDir::new("caps");
        let caps = BlobCaps { max_blob_bytes: 4, max_total_bytes: 4, max_blobs: 1 };
        let store = FsJobBlobStore::open(&dir.0, caps).unwrap();
        store.put(b"1234").unwrap();
        store.put(b"1234").unwrap();
        assert!(matches!(store.put(b"x"), Err(BlobStoreError::EntryLimit { .. })));
        assert!(matches!(store.put(b"12345"), Err(BlobStoreError::BlobTooLarge { .. })));
    }

    #[test]
    fn read_and_recovery_fail_closed_on_tampering() {
        let dir = TempDir::new("tamper");
        let store = FsJobBlobStore::open(&dir.0, BlobCaps::default()).unwrap();
        let reference = store.put(b"original").unwrap();
        fs::write(dir.0.join(&reference.sha256), b"tampered").unwrap();
        assert!(matches!(store.get(&reference.sha256), Err(BlobStoreError::Corrupt(_))));
        assert!(matches!(
            FsJobBlobStore::open(&dir.0, BlobCaps::default()),
            Err(BlobStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn recovery_ignores_uncommitted_temp_but_rejects_unknown_files() {
        let dir = TempDir::new("recovery");
        let temp = format!(".{}.1.0.tmp", "a".repeat(64));
        fs::write(dir.0.join(temp), b"partial").unwrap();
        assert!(FsJobBlobStore::open(&dir.0, BlobCaps::default()).is_ok());
        fs::write(dir.0.join("README"), b"not a blob").unwrap();
        assert!(matches!(
            FsJobBlobStore::open(&dir.0, BlobCaps::default()),
            Err(BlobStoreError::InvalidAddress(_))
        ));
    }

    #[test]
    fn crash_orphans_remain_inside_finite_capacity() {
        let dir = TempDir::new("orphan-capacity");
        let temp = format!(".{}.1.0.tmp", "a".repeat(64));
        fs::write(dir.0.join(temp), b"partial").unwrap();
        let caps = BlobCaps { max_blob_bytes: 16, max_total_bytes: 16, max_blobs: 1 };
        let store = FsJobBlobStore::open(&dir.0, caps).unwrap();
        assert!(matches!(store.put(b"new"), Err(BlobStoreError::EntryLimit { .. })));

        let malformed = TempDir::new("malformed-orphan");
        fs::write(malformed.0.join(".interrupted.1.tmp"), b"partial").unwrap();
        assert!(matches!(
            FsJobBlobStore::open(&malformed.0, BlobCaps::default()),
            Err(BlobStoreError::Corrupt(_))
        ));
    }

    #[test]
    fn reopen_never_truncates_same_pid_crash_evidence_on_temp_name_collision() {
        let dir = TempDir::new("orphan-collision");
        let bytes = b"new committed bytes";
        let hash = sha256_hex(bytes);
        let orphan = dir.0.join(format!(".{hash}.{}.0.tmp", std::process::id()));
        fs::write(&orphan, b"preserved partial evidence").unwrap();
        let caps = BlobCaps { max_blob_bytes: 64, max_total_bytes: 64, max_blobs: 2 };
        let store = FsJobBlobStore::open(&dir.0, caps).unwrap();

        let stored = store.put(bytes).unwrap();
        assert_eq!(stored.sha256, hash);
        assert_eq!(fs::read(&orphan).unwrap(), b"preserved partial evidence");
        drop(store);

        let recovered = FsJobBlobStore::open(&dir.0, caps).unwrap();
        assert_eq!(recovered.get(&hash).unwrap(), bytes);
        assert!(orphan.exists());
    }

    #[test]
    fn parent_directory_sync_failure_never_reports_a_blob_committed() {
        let dir = TempDir::new("dir-sync-error");
        let store = FsJobBlobStore::open(&dir.0, BlobCaps::default()).unwrap();
        let bytes = b"ambiguous until reopen";
        let hash = sha256_hex(bytes);
        let mut index = store.index.lock().unwrap_or_else(|poison| poison.into_inner());
        let result =
            store.put_new_blob(&mut index, bytes, hash.clone(), bytes.len() as u64, |_| {
                Err(BlobStoreError::Io("injected parent-directory fsync failure".into()))
            });
        assert!(matches!(result, Err(BlobStoreError::Io(_))));
        assert!(!index.sizes.contains_key(&hash));
        drop(index);
        assert!(matches!(store.put(b"another write"), Err(BlobStoreError::Uncertain)));
        drop(store);

        // The rename is visible in this deterministic cut, so audited reopen verifies and adopts
        // it. A real power cut may instead lose it; neither case returned a false success.
        let recovered = FsJobBlobStore::open(&dir.0, BlobCaps::default()).unwrap();
        assert_eq!(recovered.get(&hash).unwrap(), bytes);
    }
}
