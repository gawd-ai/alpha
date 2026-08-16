//! Small signed append journal used by the reference home store.

use gawdfn::{canonical_hash, canonical_json_bytes, AuthoritySigner, SignedRecordV1};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use thiserror::Error;

const HOME_CHAIN_SCHEMA: &str = "gawd.function.home.journal.v1";
const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DurabilityFaultPoint {
    BeforeLogWrite,
    AfterLogWrite,
    AfterLogSync,
    AfterAtomicTempSync,
    BeforeAtomicRename,
    BeforeAtomicDirSync,
    AfterAtomicDirSync,
}

#[cfg(any(test, feature = "durability-test-hooks"))]
#[derive(Debug, Clone, Copy)]
struct InjectedFault {
    point: DurabilityFaultPoint,
    matches_to_skip: usize,
}

#[cfg(any(test, feature = "durability-test-hooks"))]
thread_local! {
    static INJECTED_FAULT: std::cell::Cell<Option<InjectedFault>> = const {
        std::cell::Cell::new(None)
    };
}

/// Scoped, current-thread fault injection used only by deterministic crash-cut tests. Production
/// durability always takes the ordinary filesystem path below.
#[cfg(any(test, feature = "durability-test-hooks"))]
pub struct DurabilityFaultGuard(Option<InjectedFault>);

#[cfg(any(test, feature = "durability-test-hooks"))]
impl Drop for DurabilityFaultGuard {
    fn drop(&mut self) {
        INJECTED_FAULT.with(|slot| slot.set(self.0));
    }
}

#[cfg(any(test, feature = "durability-test-hooks"))]
pub fn inject_durability_fault(
    point: DurabilityFaultPoint,
    matches_to_skip: usize,
) -> DurabilityFaultGuard {
    let previous = INJECTED_FAULT.with(|slot| {
        let previous = slot.get();
        slot.set(Some(InjectedFault { point, matches_to_skip }));
        previous
    });
    DurabilityFaultGuard(previous)
}

pub(super) fn check_durability_fault(point: DurabilityFaultPoint) -> Result<(), JournalError> {
    #[cfg(any(test, feature = "durability-test-hooks"))]
    {
        INJECTED_FAULT.with(|slot| {
            let Some(mut fault) = slot.get() else { return Ok(()) };
            if fault.point != point {
                return Ok(());
            }
            if fault.matches_to_skip > 0 {
                fault.matches_to_skip -= 1;
                slot.set(Some(fault));
                return Ok(());
            }
            slot.set(None);
            Err(JournalError::Io(format!("injected durability fault at {point:?}")))
        })
    }
    #[cfg(not(any(test, feature = "durability-test-hooks")))]
    {
        let _ = point;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalCaps {
    pub max_records: usize,
    pub max_record_bytes: usize,
}

impl Default for JournalCaps {
    fn default() -> Self {
        Self { max_records: 1_000_000, max_record_bytes: gawdfn::MAX_JOB_MESSAGE_BYTES }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainEntry<T> {
    pub sequence: u64,
    pub previous_hash: String,
    pub event: T,
}

/// Decides whether a correctly signed historical record belongs to this authority chain. This is
/// deliberately stronger than "any valid signature": a migratable home supplies only root-granted
/// epoch keys, while ordinary stores use the current signer alone.
pub trait JournalAuthority<T>: Send + Sync {
    fn authorize(&self, signer: &str, entry: &ChainEntry<T>) -> bool;
}

impl<T, F> JournalAuthority<T> for F
where
    F: Fn(&str, &ChainEntry<T>) -> bool + Send + Sync,
{
    fn authorize(&self, signer: &str, entry: &ChainEntry<T>) -> bool {
        self(signer, entry)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Head {
    next_sequence: u64,
    tip_hash: String,
}

type RecoveredChain<T> = (Vec<SignedRecordV1<ChainEntry<T>>>, String, Vec<Head>);

#[derive(Debug, Error)]
pub enum JournalError {
    #[error("journal I/O error: {0}")]
    Io(String),
    #[error("journal encoding error: {0}")]
    Encoding(String),
    #[error("journal is corrupt: {0}")]
    Corrupt(String),
    #[error("journal limit reached: {0}")]
    Limit(String),
    #[error("journal state is uncertain after a failed durable append; reopen before writing")]
    Uncertain,
}

struct Inner<T> {
    records: Vec<SignedRecordV1<ChainEntry<T>>>,
    tip_hash: String,
    healthy: bool,
}

/// An fsynced JSON-lines chain. Records are signed by an injected Abode/epoch authority; private
/// key bytes never enter the journal.
pub struct SignedJournal<T> {
    log_path: PathBuf,
    head_path: PathBuf,
    root: PathBuf,
    signer: Arc<dyn AuthoritySigner>,
    chain_schema: String,
    caps: JournalCaps,
    inner: Mutex<Inner<T>>,
}

impl<T> SignedJournal<T>
where
    T: Clone + Serialize + DeserializeOwned,
{
    pub fn open(
        root: impl AsRef<Path>,
        name: &str,
        signer: Arc<dyn AuthoritySigner>,
        caps: JournalCaps,
    ) -> Result<Self, JournalError> {
        Self::open_with_schema(root, name, HOME_CHAIN_SCHEMA, signer, caps)
    }

    pub fn open_with_schema(
        root: impl AsRef<Path>,
        name: &str,
        chain_schema: &str,
        signer: Arc<dyn AuthoritySigner>,
        caps: JournalCaps,
    ) -> Result<Self, JournalError> {
        let current = signer.public_key().to_string();
        Self::open_with_authority(
            root,
            name,
            chain_schema,
            signer,
            caps,
            Arc::new(move |candidate: &str, _entry: &ChainEntry<T>| candidate == current),
        )
    }

    pub fn open_with_authority(
        root: impl AsRef<Path>,
        name: &str,
        chain_schema: &str,
        signer: Arc<dyn AuthoritySigner>,
        caps: JournalCaps,
        authority: Arc<dyn JournalAuthority<T>>,
    ) -> Result<Self, JournalError> {
        if caps.max_records == 0 || caps.max_record_bytes == 0 {
            return Err(JournalError::Limit("caps must be non-zero".into()));
        }
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(JournalError::Corrupt(format!("invalid journal name `{name}`")));
        }
        if chain_schema.trim().is_empty() || chain_schema.len() > gawdfn::MAX_ID_BYTES {
            return Err(JournalError::Corrupt("invalid chain schema".into()));
        }
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(io_err)?;
        let log_path = root.join(format!("{name}.jsonl"));
        let head_path = root.join(format!("{name}.head.json"));
        let (records, tip_hash, prefix_heads) =
            recover::<T>(&log_path, chain_schema, caps, authority.as_ref())?;
        if log_path.exists() {
            // A prior writer may have returned uncertain after write but before file fsync. A
            // complete, verified record is recoverable, but it becomes durable authority only
            // after this reopen explicitly fences the log bytes.
            OpenOptions::new()
                .read(true)
                .write(true)
                .open(&log_path)
                .and_then(|file| file.sync_all())
                .map_err(io_err)?;
        }

        let expected = Head { next_sequence: records.len() as u64, tip_hash: tip_hash.clone() };
        if head_path.exists() {
            let bytes = bounded_read(&head_path, 16 * 1024)?;
            let persisted: Head = serde_json::from_slice(&bytes)
                .map_err(|e| JournalError::Corrupt(format!("invalid head: {e}")))?;
            let head_is_current = persisted == expected;
            let head_is_committed_prefix =
                prefix_heads.iter().any(|candidate| candidate == &persisted);
            if !head_is_current && !head_is_committed_prefix {
                return Err(JournalError::Corrupt(format!(
                    "head ({}, {}) is not a prefix of recovered chain ({}, {})",
                    persisted.next_sequence,
                    persisted.tip_hash,
                    expected.next_sequence,
                    expected.tip_hash
                )));
            }
            // A record is committed once its JSONL bytes fsync. A stale prefix head means a crash
            // occurred before the atomic head hint advanced; repair the hint from the chain.
            if !head_is_current {
                atomic_write(
                    &root,
                    &head_path,
                    &canonical_json_bytes(&expected).map_err(contract_err)?,
                )?;
            }
        } else if !records.is_empty() {
            // A log without a head is the legitimate first-append crash window. Its signed chain is
            // authoritative; reconstruct the truncation hint.
            atomic_write(
                &root,
                &head_path,
                &canonical_json_bytes(&expected).map_err(contract_err)?,
            )?;
        }

        // Reopening is the recovery fence after an append returned with uncertain parent-directory
        // durability. Even when the visible head is already current, sync the directory before
        // allowing a caller to treat that recovered prefix as durable or emit a receipt from it.
        File::open(&root).and_then(|directory| directory.sync_all()).map_err(io_err)?;

        Ok(Self {
            log_path,
            head_path,
            root,
            signer,
            chain_schema: chain_schema.to_string(),
            caps,
            inner: Mutex::new(Inner { records, tip_hash, healthy: true }),
        })
    }

    pub fn append(&self, event: T) -> Result<SignedRecordV1<ChainEntry<T>>, JournalError> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !inner.healthy {
            return Err(JournalError::Uncertain);
        }
        if inner.records.len() >= self.caps.max_records {
            return Err(JournalError::Limit(format!(
                "{} records exceeds {}",
                inner.records.len(),
                self.caps.max_records
            )));
        }
        let entry = ChainEntry {
            sequence: inner.records.len() as u64,
            previous_hash: inner.tip_hash.clone(),
            event,
        };
        let record = SignedRecordV1::sign(&self.chain_schema, entry, self.signer.as_ref())
            .map_err(contract_err)?;
        let mut line = canonical_json_bytes(&record).map_err(contract_err)?;
        if line.len() > self.caps.max_record_bytes {
            return Err(JournalError::Limit(format!(
                "record is {} bytes, exceeds {}",
                line.len(),
                self.caps.max_record_bytes
            )));
        }
        line.push(b'\n');
        let hash = canonical_hash(&record).map_err(contract_err)?;
        let next_head =
            Head { next_sequence: inner.records.len() as u64 + 1, tip_hash: hash.clone() };

        let durable = (|| {
            check_durability_fault(DurabilityFaultPoint::BeforeLogWrite)?;
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.log_path)
                .map_err(io_err)?;
            file.write_all(&line).map_err(io_err)?;
            check_durability_fault(DurabilityFaultPoint::AfterLogWrite)?;
            file.sync_all().map_err(io_err)?;
            check_durability_fault(DurabilityFaultPoint::AfterLogSync)?;
            atomic_write(
                &self.root,
                &self.head_path,
                &canonical_json_bytes(&next_head).map_err(contract_err)?,
            )
        })();
        if let Err(err) = durable {
            // The log append may already be durable. Continuing at the old in-memory sequence could
            // fork the chain, so force an audited reopen/recovery.
            inner.healthy = false;
            return Err(err);
        }
        inner.tip_hash = hash;
        inner.records.push(record.clone());
        Ok(record)
    }

    pub fn records(&self) -> Vec<SignedRecordV1<ChainEntry<T>>> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).records.clone()
    }

    /// Borrow one healthy, immutable chain snapshot without cloning its records.
    ///
    /// The callback runs while the journal mutex is held, so callers must keep it bounded and must
    /// not call back into this journal. Checkpoint encoding uses this cold-path seam to stream the
    /// verified records into a capped buffer instead of duplicating the complete in-memory chain.
    pub fn with_snapshot<R>(
        &self,
        inspect: impl FnOnce(&[SignedRecordV1<ChainEntry<T>>], &str) -> R,
    ) -> Result<R, JournalError> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !inner.healthy {
            return Err(JournalError::Uncertain);
        }
        Ok(inspect(&inner.records, &inner.tip_hash))
    }

    /// Fail closed after any append whose durable cut is uncertain. Only reopening and replaying
    /// the signed log establishes a new operational prefix.
    pub fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.inner.lock().unwrap_or_else(|p| p.into_inner()).healthy {
            Ok(())
        } else {
            Err(JournalError::Uncertain)
        }
    }

    /// Return the verified hash-chain tip represented by `records()`.
    pub fn tip_hash(&self) -> String {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).tip_hash.clone()
    }

    /// Install an already signed, fully verified chain without re-signing historical records.
    ///
    /// This is the only write primitive used by Home custody activation. It refuses to replace a
    /// different local chain; retrying the exact same snapshot is idempotent. The log is fsynced by
    /// atomic rename before its head hint is advanced, so a crash at either boundary recovers as a
    /// committed chain or a safely repairable stale head.
    pub fn install_snapshot(
        root: impl AsRef<Path>,
        name: &str,
        chain_schema: &str,
        records: &[SignedRecordV1<ChainEntry<T>>],
        caps: JournalCaps,
        authority: &dyn JournalAuthority<T>,
    ) -> Result<(), JournalError> {
        if caps.max_records == 0 || caps.max_record_bytes == 0 {
            return Err(JournalError::Limit("caps must be non-zero".into()));
        }
        if name.is_empty()
            || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return Err(JournalError::Corrupt(format!("invalid journal name `{name}`")));
        }
        if chain_schema.trim().is_empty() || chain_schema.len() > gawdfn::MAX_ID_BYTES {
            return Err(JournalError::Corrupt("invalid chain schema".into()));
        }
        if records.len() > caps.max_records {
            return Err(JournalError::Limit(format!(
                "snapshot has {} records, exceeds {}",
                records.len(),
                caps.max_records
            )));
        }

        let mut bytes = Vec::new();
        let mut tip = GENESIS.to_string();
        for (index, record) in records.iter().enumerate() {
            if record.schema != chain_schema
                || !record.verify()
                || !authority.authorize(&record.signer, &record.payload)
            {
                return Err(JournalError::Corrupt(format!(
                    "snapshot record {index} has an invalid or unexpected signature"
                )));
            }
            if record.payload.sequence != index as u64 || record.payload.previous_hash != tip {
                return Err(JournalError::Corrupt(format!(
                    "snapshot record {index} breaks sequence/hash chain"
                )));
            }
            let mut line = canonical_json_bytes(record).map_err(contract_err)?;
            if line.len() > caps.max_record_bytes {
                return Err(JournalError::Limit(format!(
                    "snapshot record {index} exceeds byte limit"
                )));
            }
            tip = canonical_hash(record).map_err(contract_err)?;
            line.push(b'\n');
            bytes.extend_from_slice(&line);
        }

        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(io_err)?;
        let log_path = root.join(format!("{name}.jsonl"));
        let head_path = root.join(format!("{name}.head.json"));
        if log_path.exists() {
            let max_log_bytes =
                caps.max_records.saturating_mul(caps.max_record_bytes.saturating_add(1));
            let existing = bounded_read(&log_path, max_log_bytes)?;
            if existing != bytes {
                return Err(JournalError::Corrupt(
                    "refusing to replace a different installed journal snapshot".into(),
                ));
            }
        } else {
            atomic_write(&root, &log_path, &bytes)?;
        }
        let expected = Head { next_sequence: records.len() as u64, tip_hash: tip };
        let head_bytes = canonical_json_bytes(&expected).map_err(contract_err)?;
        if head_path.exists() {
            let existing = bounded_read(&head_path, 16 * 1024)?;
            if existing != head_bytes {
                let parsed: Head = serde_json::from_slice(&existing)
                    .map_err(|e| JournalError::Corrupt(format!("invalid installed head: {e}")))?;
                let is_prefix = parsed.next_sequence <= records.len() as u64
                    && (parsed.next_sequence == 0
                        || canonical_hash(&records[parsed.next_sequence as usize - 1])
                            .map_err(contract_err)?
                            == parsed.tip_hash);
                if !is_prefix {
                    return Err(JournalError::Corrupt(
                        "installed journal head is not a committed snapshot prefix".into(),
                    ));
                }
                atomic_write(&root, &head_path, &head_bytes)?;
            }
        } else {
            atomic_write(&root, &head_path, &head_bytes)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).records.len()
    }

    /// Health-gated record capacity available to future safety-critical transitions. Callers use
    /// this while holding their organ state lock to preserve dynamic terminal/ack reservations.
    pub fn remaining_records(&self) -> Result<usize, JournalError> {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        if !inner.healthy {
            return Err(JournalError::Uncertain);
        }
        Ok(self.caps.max_records.saturating_sub(inner.records.len()))
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn recover<T>(
    path: &Path,
    expected_schema: &str,
    caps: JournalCaps,
    authority: &dyn JournalAuthority<T>,
) -> Result<RecoveredChain<T>, JournalError>
where
    T: Clone + Serialize + DeserializeOwned,
{
    if !path.exists() {
        return Ok((
            Vec::new(),
            GENESIS.to_string(),
            vec![Head { next_sequence: 0, tip_hash: GENESIS.to_string() }],
        ));
    }
    let metadata = fs::metadata(path).map_err(io_err)?;
    let max_log_bytes = caps.max_records.saturating_mul(caps.max_record_bytes.saturating_add(1));
    if metadata.len() > max_log_bytes as u64 {
        return Err(JournalError::Limit(format!(
            "journal is {} bytes, exceeds recovery limit {max_log_bytes}",
            metadata.len()
        )));
    }
    let bytes = bounded_read(path, max_log_bytes)?;
    if !bytes.is_empty() && !bytes.ends_with(b"\n") {
        return Err(JournalError::Corrupt("journal has a torn final record".into()));
    }
    let mut records = Vec::new();
    let mut tip = GENESIS.to_string();
    let mut prefix_heads = vec![Head { next_sequence: 0, tip_hash: tip.clone() }];
    for (index, line) in
        bytes.split(|byte| *byte == b'\n').filter(|line| !line.is_empty()).enumerate()
    {
        if line.len() > caps.max_record_bytes {
            return Err(JournalError::Limit(format!("record {index} exceeds byte limit")));
        }
        if records.len() >= caps.max_records {
            return Err(JournalError::Limit("record count exceeds limit".into()));
        }
        let record: SignedRecordV1<ChainEntry<T>> = serde_json::from_slice(line)
            .map_err(|e| JournalError::Corrupt(format!("record {index} is invalid JSON: {e}")))?;
        if record.schema != expected_schema {
            return Err(JournalError::Corrupt(format!("record {index} has wrong schema")));
        }
        if !record.verify() || !authority.authorize(&record.signer, &record.payload) {
            return Err(JournalError::Corrupt(format!(
                "record {index} has an invalid or unexpected signature"
            )));
        }
        if record.payload.sequence != index as u64 || record.payload.previous_hash != tip {
            return Err(JournalError::Corrupt(format!(
                "record {index} breaks sequence/hash chain"
            )));
        }
        tip = canonical_hash(&record).map_err(contract_err)?;
        records.push(record);
        prefix_heads.push(Head { next_sequence: records.len() as u64, tip_hash: tip.clone() });
    }
    Ok((records, tip, prefix_heads))
}

fn bounded_read(path: &Path, max: usize) -> Result<Vec<u8>, JournalError> {
    let mut file = File::open(path).map_err(io_err)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(max as u64 + 1).read_to_end(&mut bytes).map_err(io_err)?;
    if bytes.len() > max {
        return Err(JournalError::Limit(format!("file exceeds {max} byte limit")));
    }
    Ok(bytes)
}

fn atomic_write(root: &Path, dest: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    let stem = dest.file_name().and_then(|v| v.to_str()).unwrap_or("head");
    let tmp = root.join(format!(".{stem}.{}.tmp", std::process::id()));
    {
        let mut file = File::create(&tmp).map_err(io_err)?;
        file.write_all(bytes).map_err(io_err)?;
        file.sync_all().map_err(io_err)?;
        check_durability_fault(DurabilityFaultPoint::AfterAtomicTempSync)?;
    }
    check_durability_fault(DurabilityFaultPoint::BeforeAtomicRename)?;
    fs::rename(&tmp, dest).map_err(io_err)?;
    check_durability_fault(DurabilityFaultPoint::BeforeAtomicDirSync)?;
    File::open(root).and_then(|file| file.sync_all()).map_err(io_err)?;
    check_durability_fault(DurabilityFaultPoint::AfterAtomicDirSync)
}

fn io_err(error: std::io::Error) -> JournalError {
    JournalError::Io(error.to_string())
}

fn contract_err(error: gawdfn::ContractError) -> JournalError {
    JournalError::Encoding(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gawdfn::Ed25519SeedSigner;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Event(String);

    fn dir(name: &str) -> PathBuf {
        let n = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir()
            .join(format!("alpha-home-journal-{name}-{}-{n}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn signer() -> Arc<dyn AuthoritySigner> {
        Arc::new(Ed25519SeedSigner::from_seed([7; 32]).unwrap())
    }

    #[test]
    fn signed_chain_recovers_and_rejects_torn_tail() {
        let root = dir("recover");
        let journal = SignedJournal::open(&root, "home", signer(), JournalCaps::default()).unwrap();
        journal.append(Event("one".into())).unwrap();
        journal.append(Event("two".into())).unwrap();
        drop(journal);
        let recovered =
            SignedJournal::<Event>::open(&root, "home", signer(), JournalCaps::default()).unwrap();
        assert_eq!(recovered.len(), 2);
        drop(recovered);
        let mut file = OpenOptions::new().append(true).open(root.join("home.jsonl")).unwrap();
        file.write_all(b"{").unwrap();
        file.sync_all().unwrap();
        assert!(matches!(
            SignedJournal::<Event>::open(&root, "home", signer(), JournalCaps::default()),
            Err(JournalError::Corrupt(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn signature_or_chain_tamper_fails_closed() {
        let root = dir("tamper");
        let journal = SignedJournal::open(&root, "home", signer(), JournalCaps::default()).unwrap();
        journal.append(Event("one".into())).unwrap();
        drop(journal);
        let path = root.join("home.jsonl");
        let text = fs::read_to_string(&path).unwrap().replace("one", "two");
        fs::write(&path, text).unwrap();
        assert!(matches!(
            SignedJournal::<Event>::open(&root, "home", signer(), JournalCaps::default()),
            Err(JournalError::Corrupt(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn every_append_cut_reopens_without_inventing_or_forking_a_record() {
        let cuts = [
            (DurabilityFaultPoint::BeforeLogWrite, 0),
            (DurabilityFaultPoint::AfterLogWrite, 1),
            (DurabilityFaultPoint::AfterLogSync, 1),
            (DurabilityFaultPoint::AfterAtomicTempSync, 1),
            (DurabilityFaultPoint::BeforeAtomicRename, 1),
            (DurabilityFaultPoint::BeforeAtomicDirSync, 1),
            (DurabilityFaultPoint::AfterAtomicDirSync, 1),
        ];
        for (cut, expected_records) in cuts {
            let root = dir(&format!("cut-{cut:?}"));
            let journal =
                SignedJournal::open(&root, "home", signer(), JournalCaps::default()).unwrap();
            let fault = inject_durability_fault(cut, 0);
            assert!(matches!(journal.append(Event("one".into())), Err(JournalError::Io(_))));
            drop(fault);
            assert!(matches!(
                journal.append(Event("must-not-fork".into())),
                Err(JournalError::Uncertain)
            ));
            drop(journal);

            let recovered =
                SignedJournal::<Event>::open(&root, "home", signer(), JournalCaps::default())
                    .unwrap();
            assert_eq!(recovered.len(), expected_records, "cut {cut:?}");
            if expected_records == 1 {
                assert_eq!(recovered.records()[0].payload.event, Event("one".into()));
            }
            let _ = fs::remove_dir_all(root);
        }
    }

    #[test]
    fn wrong_authority_oversized_records_and_nonprefix_heads_fail_closed() {
        let root = dir("authority-limits-head");
        let journal = SignedJournal::open(&root, "home", signer(), JournalCaps::default()).unwrap();
        journal.append(Event("one".into())).unwrap();
        drop(journal);

        let other: Arc<dyn AuthoritySigner> =
            Arc::new(Ed25519SeedSigner::from_seed([8; 32]).unwrap());
        assert!(matches!(
            SignedJournal::<Event>::open(&root, "home", other, JournalCaps::default()),
            Err(JournalError::Corrupt(_))
        ));

        let tiny = JournalCaps { max_records: 10, max_record_bytes: 64 };
        assert!(matches!(
            SignedJournal::<Event>::open(&root, "home", signer(), tiny),
            Err(JournalError::Limit(_))
        ));

        fs::write(
            root.join("home.head.json"),
            br#"{"next_sequence":9,"tip_hash":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}"#,
        )
        .unwrap();
        assert!(matches!(
            SignedJournal::<Event>::open(&root, "home", signer(), JournalCaps::default()),
            Err(JournalError::Corrupt(_))
        ));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn append_refuses_an_oversized_record_without_creating_history() {
        let root = dir("append-limit");
        let caps = JournalCaps { max_records: 4, max_record_bytes: 256 };
        let journal = SignedJournal::open(&root, "home", signer(), caps).unwrap();
        assert!(matches!(journal.append(Event("x".repeat(1024))), Err(JournalError::Limit(_))));
        assert!(journal.is_empty());
        drop(journal);
        assert!(SignedJournal::<Event>::open(&root, "home", signer(), caps).unwrap().is_empty());
        let _ = fs::remove_dir_all(root);
    }
}
