//! `function-locator` — a finite, signed location index for migratable Job homes.
//!
//! The stable identity of a Job is `(HomeId, JobId)`; a location is only a refreshable hint. This
//! organ verifies the complete Abode-root → epoch-key authority chain embedded in every lease,
//! retains the highest epoch, and permits only a higher-sequence coordinator refresh over an
//! otherwise identical same-epoch lease. Every binding change is reported as equivocation.
//! Trust/reputation evidence is carried by the grant but deliberately not interpreted here.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use aether::{Creature, CreatureCtx, Dispatch, Envelope, Outcome};
use gawdfn::{
    canonical_json_bytes, is_home_lease_coordinator_revision, verify_home_lease, HomeId,
    HomeLeaseV1, HomeLocateV1, HomeLocationV1, LocateMessageV1, ProtocolErrorV1, SignedRecordV1,
    Validate, MAX_JOB_MESSAGE_BYTES, MAX_REASON_BYTES, SCHEMA_LOCATE_V1,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub const DEFAULT_MAX_HOMES: usize = 16_384;
pub const DEFAULT_MAX_CONFLICTS_PER_HOME: usize = 8;
pub const DEFAULT_MAX_SNAPSHOT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocatorCaps {
    pub max_homes: usize,
    pub max_conflicts_per_home: usize,
    pub max_snapshot_bytes: usize,
}

impl Default for LocatorCaps {
    fn default() -> Self {
        Self {
            max_homes: DEFAULT_MAX_HOMES,
            max_conflicts_per_home: DEFAULT_MAX_CONFLICTS_PER_HOME,
            max_snapshot_bytes: DEFAULT_MAX_SNAPSHOT_BYTES,
        }
    }
}

#[derive(Debug, Error)]
pub enum LocatorError {
    #[error("invalid home lease: {0}")]
    Invalid(String),
    #[error("locator capacity reached: {0}")]
    Limit(String),
    #[error("locator storage error: {0}")]
    Io(String),
    #[error("locator state is corrupt: {0}")]
    Corrupt(String),
    #[error("locator durability is uncertain; reopen before serving or applying leases")]
    Uncertain,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApplyOutcome {
    Added,
    Advanced,
    Duplicate,
    Stale { current_epoch: u64, current_sequence: u64 },
    Conflict { epoch: u64, leases: Vec<SignedRecordV1<HomeLeaseV1>> },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocateOutcome {
    Location(Box<SignedRecordV1<HomeLeaseV1>>),
    Conflict { epoch: u64, leases: Vec<SignedRecordV1<HomeLeaseV1>> },
    NotFound,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum LeaseState {
    Current { lease: Box<SignedRecordV1<HomeLeaseV1>> },
    Conflict { epoch: u64, leases: Vec<SignedRecordV1<HomeLeaseV1>> },
}

impl LeaseState {
    fn epoch(&self) -> u64 {
        match self {
            Self::Current { lease } => lease.payload.epoch,
            Self::Conflict { epoch, .. } => *epoch,
        }
    }

    fn leases(&self) -> Vec<SignedRecordV1<HomeLeaseV1>> {
        match self {
            Self::Current { lease } => vec![(**lease).clone()],
            Self::Conflict { leases, .. } => leases.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedEntry {
    home: HomeId,
    lease: LeaseState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PersistedState {
    version: u8,
    entries: Vec<PersistedEntry>,
}

/// Reference locator service. `open` is durable; `new` is an explicitly in-memory filling useful
/// in tests and ephemeral compositions.
pub struct FunctionLocator {
    caps: LocatorCaps,
    states: BTreeMap<HomeId, LeaseState>,
    persistence: Option<(PathBuf, PathBuf)>,
    healthy: bool,
}

impl FunctionLocator {
    pub fn new(caps: LocatorCaps) -> Result<Self, LocatorError> {
        validate_caps(caps)?;
        Ok(Self { caps, states: BTreeMap::new(), persistence: None, healthy: true })
    }

    pub fn open(root: impl AsRef<Path>, caps: LocatorCaps) -> Result<Self, LocatorError> {
        validate_caps(caps)?;
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(io_error)?;
        let path = root.join("home-leases.v1.json");
        let mut locator = Self {
            caps,
            states: BTreeMap::new(),
            persistence: Some((root.clone(), path.clone())),
            healthy: true,
        };
        if path.exists() {
            let bytes = bounded_read(&path, caps.max_snapshot_bytes)?;
            let persisted: PersistedState = serde_json::from_slice(&bytes).map_err(|error| {
                LocatorError::Corrupt(format!("invalid snapshot JSON: {error}"))
            })?;
            if persisted.version != 1 {
                return Err(LocatorError::Corrupt(format!(
                    "unsupported locator snapshot version {}",
                    persisted.version
                )));
            }
            if persisted.entries.len() > caps.max_homes {
                return Err(LocatorError::Corrupt("snapshot exceeds home limit".into()));
            }
            for entry in persisted.entries {
                if locator.states.contains_key(&entry.home) {
                    return Err(LocatorError::Corrupt(format!(
                        "duplicate snapshot entry for home {}",
                        entry.home
                    )));
                }
                validate_state(&entry.home, &entry.lease, caps)?;
                locator.states.insert(entry.home, entry.lease);
            }
        }
        // `open` is also the recovery fence after a rename-visible parent-directory fsync error.
        // Re-sync the directory before exposing the recovered location snapshot as durable state.
        File::open(&root).and_then(|directory| directory.sync_all()).map_err(io_error)?;
        Ok(locator)
    }

    pub fn apply(
        &mut self,
        lease: SignedRecordV1<HomeLeaseV1>,
    ) -> Result<ApplyOutcome, LocatorError> {
        if !self.healthy {
            return Err(LocatorError::Uncertain);
        }
        verify_home_lease(&lease).map_err(|error| LocatorError::Invalid(error.to_string()))?;
        if lease.schema != SCHEMA_LOCATE_V1 {
            return Err(LocatorError::Invalid(format!(
                "lease record schema is `{}`, expected `{SCHEMA_LOCATE_V1}`",
                lease.schema
            )));
        }
        let home = lease.payload.home.clone();
        if !self.states.contains_key(&home) && self.states.len() >= self.caps.max_homes {
            return Err(LocatorError::Limit(format!(
                "{} homes already retained (limit {})",
                self.states.len(),
                self.caps.max_homes
            )));
        }

        let mut next = self.states.clone();
        let outcome = apply_to_map(&mut next, lease, self.caps)?;
        if !matches!(outcome, ApplyOutcome::Duplicate | ApplyOutcome::Stale { .. }) {
            if let Err(error) = self.persist(&next) {
                self.healthy = false;
                return Err(error);
            }
            self.states = next;
        }
        Ok(outcome)
    }

    pub fn locate(&self, query: &HomeLocateV1) -> Result<LocateOutcome, LocatorError> {
        // A failed atomic snapshot may have renamed a newer lease into place without durably
        // fencing that rename in the parent directory. `states` deliberately remains at the last
        // confirmed snapshot, but it must not be presented as authority: only `open` re-reads and
        // re-syncs the visible snapshot, establishing which side of the write survived.
        if !self.healthy {
            return Err(LocatorError::Uncertain);
        }
        query.validate().map_err(|error| LocatorError::Invalid(error.to_string()))?;
        let Some(state) = self.states.get(&query.home) else {
            return Ok(LocateOutcome::NotFound);
        };
        if query.minimum_epoch.is_some_and(|minimum| state.epoch() < minimum) {
            return Ok(LocateOutcome::NotFound);
        }
        Ok(match state {
            LeaseState::Current { lease } => LocateOutcome::Location(lease.clone()),
            LeaseState::Conflict { epoch, leases } => {
                LocateOutcome::Conflict { epoch: *epoch, leases: leases.clone() }
            }
        })
    }

    pub fn len(&self) -> usize {
        self.states.len()
    }

    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    fn persist(&self, states: &BTreeMap<HomeId, LeaseState>) -> Result<(), LocatorError> {
        let Some((root, path)) = &self.persistence else { return Ok(()) };
        let persisted = PersistedState {
            version: 1,
            entries: states
                .iter()
                .map(|(home, lease)| PersistedEntry { home: home.clone(), lease: lease.clone() })
                .collect(),
        };
        let bytes = canonical_json_bytes(&persisted)
            .map_err(|error| LocatorError::Corrupt(error.to_string()))?;
        if bytes.len() > self.caps.max_snapshot_bytes {
            return Err(LocatorError::Limit(format!(
                "snapshot is {} bytes, exceeds {}",
                bytes.len(),
                self.caps.max_snapshot_bytes
            )));
        }
        atomic_write(root, path, &bytes)
    }
}

impl Creature for FunctionLocator {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA_LOCATE_V1 || env.payload.len() > MAX_JOB_MESSAGE_BYTES {
            return Outcome::none();
        }
        let Ok(message) = serde_json::from_slice::<LocateMessageV1>(&env.payload) else {
            return reply_error(&env, "invalid_message", "cannot decode locator message", false);
        };
        let reply = match message {
            LocateMessageV1::Announce { lease } => {
                let home = lease.payload.home.clone();
                match self.apply(lease) {
                    Ok(ApplyOutcome::Added | ApplyOutcome::Advanced | ApplyOutcome::Duplicate) => {
                        let query = HomeLocateV1 { home, minimum_epoch: None };
                        match self.locate(&query) {
                            Ok(LocateOutcome::Location(lease)) => LocateMessageV1::Location {
                                location: HomeLocationV1 {
                                    lease: *lease,
                                    observed_at_unix_ms: None,
                                },
                            },
                            Ok(LocateOutcome::Conflict { epoch, leases }) => {
                                LocateMessageV1::Conflict { home: query.home, epoch, leases }
                            }
                            _ => protocol_error(
                                "locator_state",
                                "announced lease was not retained",
                                false,
                            ),
                        }
                    }
                    Ok(ApplyOutcome::Conflict { epoch, leases }) => {
                        let home = leases
                            .first()
                            .map(|lease| lease.payload.home.clone())
                            .unwrap_or_else(|| HomeId::new("invalid"));
                        LocateMessageV1::Conflict { home, epoch, leases }
                    }
                    Ok(ApplyOutcome::Stale { .. }) => protocol_error(
                        "stale_lease",
                        "a newer home lease is already retained",
                        false,
                    ),
                    Err(error) => announce_error(&error),
                }
            }
            LocateMessageV1::Locate { query } => match self.locate(&query) {
                Ok(LocateOutcome::Location(lease)) => LocateMessageV1::Location {
                    location: HomeLocationV1 { lease: *lease, observed_at_unix_ms: None },
                },
                Ok(LocateOutcome::Conflict { epoch, leases }) => {
                    LocateMessageV1::Conflict { home: query.home, epoch, leases }
                }
                Ok(LocateOutcome::NotFound) => LocateMessageV1::NotFound { home: query.home },
                Err(error) => locate_error(&error),
            },
            LocateMessageV1::Location { .. }
            | LocateMessageV1::NotFound { .. }
            | LocateMessageV1::Conflict { .. }
            | LocateMessageV1::Error { .. } => return Outcome::none(),
        };
        let payload = encode_reply(&reply);
        Outcome::send(Dispatch::reply_to_env(&env, payload).with_schema(SCHEMA_LOCATE_V1))
    }
}

fn reply_error(env: &Envelope, code: &str, message: &str, retryable: bool) -> Outcome {
    let payload = encode_reply(&protocol_error(code, message, retryable));
    Outcome::send(Dispatch::reply_to_env(env, payload).with_schema(SCHEMA_LOCATE_V1))
}

fn announce_error(error: &LocatorError) -> LocateMessageV1 {
    match error {
        LocatorError::Uncertain | LocatorError::Io(_) | LocatorError::Corrupt(_) => {
            unavailable_error()
        }
        LocatorError::Invalid(_) => {
            protocol_error("invalid_lease", "announced lease failed validation", false)
        }
        LocatorError::Limit(_) => protocol_error(
            "locator_capacity",
            "locator capacity prevents retaining the announced lease",
            false,
        ),
    }
}

fn locate_error(error: &LocatorError) -> LocateMessageV1 {
    match error {
        LocatorError::Uncertain | LocatorError::Io(_) | LocatorError::Corrupt(_) => {
            unavailable_error()
        }
        LocatorError::Invalid(_) => {
            protocol_error("invalid_query", "location query failed validation", false)
        }
        LocatorError::Limit(_) => unavailable_error(),
    }
}

fn unavailable_error() -> LocateMessageV1 {
    protocol_error(
        "locator_unavailable",
        "locator cannot safely serve or accept leases until reopened",
        true,
    )
}

fn encode_reply(reply: &LocateMessageV1) -> Vec<u8> {
    match serde_json::to_vec(reply) {
        Ok(payload) if payload.len() <= MAX_JOB_MESSAGE_BYTES => payload,
        Ok(_) => serde_json::to_vec(&protocol_error(
            "response_too_large",
            "locator response exceeds the wire-message limit",
            false,
        ))
        .unwrap_or_default(),
        Err(_) => serde_json::to_vec(&protocol_error(
            "encoding_failure",
            "cannot encode locator reply",
            false,
        ))
        .unwrap_or_default(),
    }
}

fn protocol_error(code: &str, message: &str, retryable: bool) -> LocateMessageV1 {
    let mut message = message.to_string();
    if message.len() > MAX_REASON_BYTES {
        let mut end = MAX_REASON_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    LocateMessageV1::Error { error: ProtocolErrorV1 { code: code.to_string(), message, retryable } }
}

fn apply_to_map(
    states: &mut BTreeMap<HomeId, LeaseState>,
    lease: SignedRecordV1<HomeLeaseV1>,
    caps: LocatorCaps,
) -> Result<ApplyOutcome, LocatorError> {
    let home = lease.payload.home.clone();
    let Some(current) = states.get(&home).cloned() else {
        states.insert(home, LeaseState::Current { lease: Box::new(lease) });
        return Ok(ApplyOutcome::Added);
    };
    let current_epoch = current.epoch();
    if lease.payload.epoch > current_epoch {
        states.insert(home, LeaseState::Current { lease: Box::new(lease) });
        return Ok(ApplyOutcome::Advanced);
    }
    if lease.payload.epoch < current_epoch {
        let sequence =
            current.leases().iter().map(|lease| lease.payload.lease_sequence).max().unwrap_or(0);
        return Ok(ApplyOutcome::Stale { current_epoch, current_sequence: sequence });
    }

    match current {
        LeaseState::Current { lease: existing } => {
            if *existing == lease {
                return Ok(ApplyOutcome::Duplicate);
            }
            if is_home_lease_coordinator_revision(&existing.payload, &lease.payload) {
                states.insert(home, LeaseState::Current { lease: Box::new(lease) });
                return Ok(ApplyOutcome::Advanced);
            }
            if is_home_lease_coordinator_revision(&lease.payload, &existing.payload) {
                return Ok(ApplyOutcome::Stale {
                    current_epoch,
                    current_sequence: existing.payload.lease_sequence,
                });
            }
            let leases = vec![*existing, lease];
            states.insert(
                home,
                LeaseState::Conflict { epoch: current_epoch, leases: leases.clone() },
            );
            Ok(ApplyOutcome::Conflict { epoch: current_epoch, leases })
        }
        LeaseState::Conflict { epoch, mut leases } => {
            if leases.contains(&lease) {
                return Ok(ApplyOutcome::Conflict { epoch, leases });
            }
            if leases.len() >= caps.max_conflicts_per_home {
                return Err(LocatorError::Limit(format!(
                    "home conflict set reached {} leases",
                    caps.max_conflicts_per_home
                )));
            }
            leases.push(lease);
            states.insert(home, LeaseState::Conflict { epoch, leases: leases.clone() });
            Ok(ApplyOutcome::Conflict { epoch, leases })
        }
    }
}

fn validate_state(
    home: &HomeId,
    state: &LeaseState,
    caps: LocatorCaps,
) -> Result<(), LocatorError> {
    let leases = state.leases();
    if leases.is_empty() || leases.len() > caps.max_conflicts_per_home {
        return Err(LocatorError::Corrupt("invalid retained conflict set size".into()));
    }
    for lease in &leases {
        verify_home_lease(lease).map_err(|error| LocatorError::Corrupt(error.to_string()))?;
        if lease.schema != SCHEMA_LOCATE_V1
            || &lease.payload.home != home
            || lease.payload.epoch != state.epoch()
        {
            return Err(LocatorError::Corrupt(
                "retained lease does not match its home/epoch key".into(),
            ));
        }
    }
    match state {
        LeaseState::Current { .. } if leases.len() == 1 => Ok(()),
        LeaseState::Conflict { .. } if leases.len() >= 2 => Ok(()),
        _ => Err(LocatorError::Corrupt("invalid retained lease state".into())),
    }
}

fn validate_caps(caps: LocatorCaps) -> Result<(), LocatorError> {
    if caps.max_homes == 0 || caps.max_conflicts_per_home < 2 || caps.max_snapshot_bytes == 0 {
        return Err(LocatorError::Limit(
            "locator caps require homes > 0, conflicts >= 2, and snapshot bytes > 0".into(),
        ));
    }
    Ok(())
}

fn bounded_read(path: &Path, limit: usize) -> Result<Vec<u8>, LocatorError> {
    let mut file = File::open(path).map_err(io_error)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file).take(limit as u64 + 1).read_to_end(&mut bytes).map_err(io_error)?;
    if bytes.len() > limit {
        return Err(LocatorError::Limit(format!("snapshot exceeds {limit} bytes")));
    }
    Ok(bytes)
}

fn atomic_write(root: &Path, path: &Path, bytes: &[u8]) -> Result<(), LocatorError> {
    let tmp = root.join(format!(".home-leases.{}.tmp", std::process::id()));
    {
        let mut file = File::create(&tmp).map_err(io_error)?;
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
    }
    fs::rename(&tmp, path).map_err(io_error)?;
    #[cfg(test)]
    if FAIL_NEXT_PARENT_SYNC.with(|slot| slot.replace(false)) {
        return Err(LocatorError::Io("injected parent-directory fsync failure".into()));
    }
    File::open(root).and_then(|file| file.sync_all()).map_err(io_error)
}

fn io_error(error: std::io::Error) -> LocatorError {
    LocatorError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gawdfn::{
        canonical_hash, AbodeKeyBindingV1, AuthoritySigner, BlobRefV1, CustodyGrantV1,
        CustodyPreparedV1, Ed25519SeedSigner, HandoffId, HomeAuthorityV1, HomeCheckpointV1,
        OperationalCapabilityV1, OperationalKeyGrantV1, SCHEMA_HOME_V1,
    };
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_dir(name: &str) -> PathBuf {
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir()
            .join(format!("alpha-function-locator-{name}-{}-{nonce}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        path
    }

    fn request(message: &LocateMessageV1) -> Envelope {
        Envelope {
            header: aether::Header {
                from: aether::Address::Creature(aether::CreatureId(90)),
                to: aether::Address::Creature(aether::CreatureId(91)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: Some(7),
                commitment: None,
                schema: SCHEMA_LOCATE_V1.into(),
                origin: None,
            },
            payload: serde_json::to_vec(message).unwrap(),
        }
    }

    fn assert_unavailable(outcome: Outcome) {
        let [dispatch] = outcome.dispatches.as_slice() else {
            panic!("locator should emit exactly one bounded error reply")
        };
        assert!(dispatch.payload.len() <= MAX_JOB_MESSAGE_BYTES);
        let reply: LocateMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
        let LocateMessageV1::Error { error } = reply else {
            panic!("unhealthy locator presented authority instead of failing closed: {reply:?}")
        };
        assert_eq!(error.code, "locator_unavailable");
        assert_eq!(error.message, "locator cannot safely serve or accept leases until reopened");
        assert!(error.retryable);
    }

    fn authority(
        root: &Ed25519SeedSigner,
        operational: &Ed25519SeedSigner,
        epoch: u64,
    ) -> HomeAuthorityV1 {
        let home = HomeId::new(root.public_key());
        let abode = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            AbodeKeyBindingV1 {
                abode: home.clone(),
                root_public_key: root.public_key().to_string(),
                issued_at_unix_ms: None,
            },
            root,
        )
        .unwrap();
        let operational = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            OperationalKeyGrantV1 {
                home,
                epoch,
                operational_public_key: operational.public_key().to_string(),
                valid_from_unix_ms: None,
                expires_at_unix_ms: None,
                capabilities: vec![
                    OperationalCapabilityV1::JobHome,
                    OperationalCapabilityV1::JobControl,
                    OperationalCapabilityV1::Custody,
                    OperationalCapabilityV1::Locate,
                ],
                evidence: vec![],
            },
            root,
        )
        .unwrap();
        HomeAuthorityV1 { abode, operational, prepared: None }
    }

    fn lease(
        root: &Ed25519SeedSigner,
        operational: &Ed25519SeedSigner,
        epoch: u64,
        sequence: u64,
        node: &str,
    ) -> SignedRecordV1<HomeLeaseV1> {
        SignedRecordV1::sign(
            SCHEMA_LOCATE_V1,
            HomeLeaseV1 {
                home: HomeId::new(root.public_key()),
                epoch,
                lease_sequence: sequence,
                realm: "realm-a".into(),
                node: node.into(),
                coordinator: "function-home-1".into(),
                authority: authority(root, operational, epoch),
                handoff: None,
                custody_grant: None,
                checkpoint_hash: format!("sha256:{}", "a".repeat(64)),
                issued_at_unix_ms: None,
                expires_at_unix_ms: None,
            },
            operational,
        )
        .unwrap()
    }

    fn moved_lease(
        root: &Ed25519SeedSigner,
        source: &Ed25519SeedSigner,
        destination: &Ed25519SeedSigner,
        sequence: u64,
        node: &str,
    ) -> SignedRecordV1<HomeLeaseV1> {
        let home = HomeId::new(root.public_key());
        let handoff = HandoffId::new("handoff-1");
        let checkpoint = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            HomeCheckpointV1 {
                home: home.clone(),
                epoch: 1,
                high_water_mark: 1,
                log_root: format!("sha256:{}", "b".repeat(64)),
                state: BlobRefV1 {
                    digest: format!("sha256:{}", "c".repeat(64)),
                    size: 1,
                    media_type: "application/octet-stream".into(),
                },
                created_at_unix_ms: None,
            },
            source,
        )
        .unwrap();
        let checkpoint_hash = canonical_hash(&checkpoint).unwrap();
        let mut destination_authority = authority(root, destination, 2);
        let custody_grant = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyGrantV1 {
                home: home.clone(),
                handoff: handoff.clone(),
                from_epoch: 1,
                to_epoch: 2,
                source_authority: authority(root, source, 1),
                source_realm: "realm-a".into(),
                source_node: "node-a".into(),
                destination_realm: "realm-a".into(),
                destination_node: node.into(),
                checkpoint_hash: checkpoint_hash.clone(),
                source_log_root: format!("sha256:{}", "b".repeat(64)),
                destination_operational_key: destination_authority.operational.clone(),
                evidence: vec![],
                issued_at_unix_ms: None,
                destination_rewrap: None,
            },
            root,
        )
        .unwrap();
        let prepared = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyPreparedV1 {
                grant_hash: canonical_hash(&custody_grant).unwrap(),
                checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
                source_log_root: checkpoint.payload.log_root.clone(),
                source_coordinator: "function-home-source".into(),
                grant: Box::new(custody_grant.clone()),
                checkpoint: Box::new(checkpoint),
                rewrap_inventory_hash: None,
                rewrap_item_count: None,
            },
            source,
        )
        .unwrap();
        destination_authority.prepared = Some(Box::new(prepared));
        SignedRecordV1::sign(
            SCHEMA_LOCATE_V1,
            HomeLeaseV1 {
                home,
                epoch: 2,
                lease_sequence: sequence,
                realm: "realm-a".into(),
                node: node.into(),
                coordinator: "function-home-1".into(),
                authority: destination_authority,
                handoff: Some(handoff),
                custody_grant: Some(Box::new(custody_grant)),
                checkpoint_hash,
                issued_at_unix_ms: None,
                expires_at_unix_ms: None,
            },
            destination,
        )
        .unwrap()
    }

    #[test]
    fn highest_epoch_recovers_durably() {
        let root = Ed25519SeedSigner::from_seed([1; 32]).unwrap();
        let op1 = Ed25519SeedSigner::from_seed([2; 32]).unwrap();
        let op2 = Ed25519SeedSigner::from_seed([3; 32]).unwrap();
        let dir = test_dir("recover");
        let mut locator = FunctionLocator::open(&dir, LocatorCaps::default()).unwrap();
        let genesis = lease(&root, &op1, 1, 1, "node-a");
        assert_eq!(locator.apply(genesis.clone()).unwrap(), ApplyOutcome::Added);
        assert_eq!(locator.apply(genesis).unwrap(), ApplyOutcome::Duplicate);
        assert_eq!(
            locator.apply(moved_lease(&root, &op1, &op2, 1, "node-b")).unwrap(),
            ApplyOutcome::Advanced
        );
        assert!(matches!(
            locator.apply(lease(&root, &op1, 1, 2, "node-a")).unwrap(),
            ApplyOutcome::Stale { .. }
        ));
        drop(locator);

        let locator = FunctionLocator::open(&dir, LocatorCaps::default()).unwrap();
        let located = locator
            .locate(&HomeLocateV1 { home: HomeId::new(root.public_key()), minimum_epoch: None })
            .unwrap();
        match located {
            LocateOutcome::Location(lease) => {
                assert_eq!(lease.payload.epoch, 2);
                assert_eq!(lease.payload.node, "node-b");
            }
            other => panic!("expected location, got {other:?}"),
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn same_epoch_different_authority_is_a_conflict() {
        let root = Ed25519SeedSigner::from_seed([4; 32]).unwrap();
        let op_a = Ed25519SeedSigner::from_seed([5; 32]).unwrap();
        let op_b = Ed25519SeedSigner::from_seed([6; 32]).unwrap();
        let mut locator = FunctionLocator::new(LocatorCaps::default()).unwrap();
        locator.apply(lease(&root, &op_a, 1, 1, "node-a")).unwrap();
        let outcome = locator.apply(lease(&root, &op_b, 1, 1, "node-b")).unwrap();
        assert!(matches!(outcome, ApplyOutcome::Conflict { epoch: 1, .. }));
        assert!(matches!(
            locator
                .locate(&HomeLocateV1 { home: HomeId::new(root.public_key()), minimum_epoch: None })
                .unwrap(),
            LocateOutcome::Conflict { epoch: 1, .. }
        ));
    }

    #[test]
    fn same_binding_higher_sequence_may_refresh_only_the_coordinator() {
        let root = Ed25519SeedSigner::from_seed([14; 32]).unwrap();
        let operational = Ed25519SeedSigner::from_seed([15; 32]).unwrap();
        let mut locator = FunctionLocator::new(LocatorCaps::default()).unwrap();
        let original = lease(&root, &operational, 1, 1, "node-a");
        locator.apply(original.clone()).unwrap();

        let mut revised_payload = original.payload.clone();
        revised_payload.lease_sequence = 2;
        revised_payload.coordinator = "function-home-2".into();
        let revised =
            SignedRecordV1::sign(SCHEMA_LOCATE_V1, revised_payload, &operational).unwrap();
        assert_eq!(locator.apply(revised.clone()).unwrap(), ApplyOutcome::Advanced);
        assert!(matches!(
            locator.apply(original).unwrap(),
            ApplyOutcome::Stale { current_epoch: 1, current_sequence: 2 }
        ));
        assert!(matches!(
            locator
                .locate(&HomeLocateV1 { home: HomeId::new(root.public_key()), minimum_epoch: None })
                .unwrap(),
            LocateOutcome::Location(lease) if *lease == revised
        ));
    }

    #[test]
    fn same_signer_cannot_rewrite_a_same_epoch_location_with_a_higher_sequence() {
        let root = Ed25519SeedSigner::from_seed([12; 32]).unwrap();
        let operational = Ed25519SeedSigner::from_seed([13; 32]).unwrap();
        let dir = test_dir("same-epoch-rewrite");
        let mut locator = FunctionLocator::open(&dir, LocatorCaps::default()).unwrap();
        let original = lease(&root, &operational, 1, 1, "node-a");
        locator.apply(original.clone()).unwrap();

        let mut changed = lease(&root, &operational, 1, 2, "node-b").payload;
        changed.coordinator = "function-home-2".into();
        changed.checkpoint_hash = format!("sha256:{}", "b".repeat(64));
        let changed = SignedRecordV1::sign(SCHEMA_LOCATE_V1, changed, &operational).unwrap();
        let outcome = locator.apply(changed.clone()).unwrap();

        match outcome {
            ApplyOutcome::Conflict { epoch, leases } => {
                assert_eq!(epoch, 1);
                assert_eq!(leases, vec![original, changed]);
            }
            other => panic!("expected conflict, got {other:?}"),
        }
        drop(locator);
        let locator = FunctionLocator::open(&dir, LocatorCaps::default()).unwrap();
        assert!(matches!(
            locator
                .locate(&HomeLocateV1 { home: HomeId::new(root.public_key()), minimum_epoch: None })
                .unwrap(),
            LocateOutcome::Conflict { epoch: 1, .. }
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn forged_operational_signer_is_rejected() {
        let root = Ed25519SeedSigner::from_seed([7; 32]).unwrap();
        let authorized = Ed25519SeedSigner::from_seed([8; 32]).unwrap();
        let attacker = Ed25519SeedSigner::from_seed([9; 32]).unwrap();
        let mut record = lease(&root, &authorized, 1, 1, "node-a");
        record = SignedRecordV1::sign(SCHEMA_LOCATE_V1, record.payload, &attacker).unwrap();
        let mut locator = FunctionLocator::new(LocatorCaps::default()).unwrap();
        assert!(matches!(locator.apply(record), Err(LocatorError::Invalid(_))));
    }

    #[test]
    fn corrupt_snapshot_fails_closed() {
        let dir = test_dir("tamper");
        fs::write(dir.join("home-leases.v1.json"), b"{not-json").unwrap();
        assert!(matches!(
            FunctionLocator::open(&dir, LocatorCaps::default()),
            Err(LocatorError::Corrupt(_))
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn parent_directory_sync_failure_hides_stale_authority_until_verified_reopen() {
        let root = Ed25519SeedSigner::from_seed([10; 32]).unwrap();
        let source = Ed25519SeedSigner::from_seed([11; 32]).unwrap();
        let destination = Ed25519SeedSigner::from_seed([16; 32]).unwrap();
        let dir = test_dir("dir-sync-error");
        let mut locator = FunctionLocator::open(&dir, LocatorCaps::default()).unwrap();
        let epoch_one = lease(&root, &source, 1, 1, "node-a");
        let epoch_two = moved_lease(&root, &source, &destination, 1, "node-b");
        assert_eq!(locator.apply(epoch_one.clone()).unwrap(), ApplyOutcome::Added);

        // The epoch-two rename is visible but its parent-directory sync fails. Memory still holds
        // epoch one, so every authority-bearing path must become unavailable until reopen.
        FAIL_NEXT_PARENT_SYNC.with(|slot| slot.set(true));
        assert!(matches!(locator.apply(epoch_two.clone()), Err(LocatorError::Io(_))));
        let query = HomeLocateV1 { home: HomeId::new(root.public_key()), minimum_epoch: None };
        assert!(matches!(locator.locate(&query), Err(LocatorError::Uncertain)));
        assert_unavailable(
            locator.handle(request(&LocateMessageV1::Locate { query: query.clone() })),
        );
        assert_unavailable(
            locator.handle(request(&LocateMessageV1::Announce { lease: epoch_one })),
        );
        drop(locator);

        let reopened = FunctionLocator::open(&dir, LocatorCaps::default()).unwrap();
        let LocateOutcome::Location(recovered) = reopened.locate(&query).unwrap() else {
            panic!("verified reopen did not recover the rename-visible epoch-two lease")
        };
        assert_eq!(*recovered, epoch_two);
        assert_eq!(recovered.payload.epoch, 2);
        assert_eq!(recovered.payload.node, "node-b");
        fs::remove_dir_all(dir).unwrap();
    }
}
