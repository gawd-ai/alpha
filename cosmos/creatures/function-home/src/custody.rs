//! Crash-safe, epoch-fenced custody for the durable Home ledger.

use super::journal::{check_durability_fault, DurabilityFaultPoint};
use super::{
    apply_ledger_record, ChainEntry, CustodyKeyRewrapper, FunctionHome, HomeConfig, HomeError,
    HomeLedgerRecord, HomeState, SignedJournal, UnavailableCustodyKeyRewrapper,
};
use gawdfn::{
    canonical_hash, canonical_json_bytes, is_home_lease_coordinator_revision, verify_custody_grant,
    verify_custody_prepared, verify_custody_rewrap_inventory, verify_custody_rewrap_receipt,
    verify_custody_rewrap_request, verify_custody_staged, verify_handoff_checkpoint,
    verify_home_custody_status, verify_home_lease, verify_recipient_key_binding, AuthoritySigner,
    CheckpointBlobStore, CustodyGrantV1, CustodyPreparedV1, CustodyRewrapRequestV1,
    CustodyRewrapRequirementV1, CustodyRewrapSourceV1, CustodyStagedV1, ExecutionStageV1,
    HandoffId, HomeAuthorityV1, HomeCheckpointV1, HomeCustodyPhaseV1, HomeCustodyStatusV1, HomeId,
    HomeLeaseV1, JobControlKindV1, JobEventKindV1, OperationalCapabilityV1, RecipientKeyBindingV1,
    RecipientKeyWrapV1, SealedValueV1, SignedRecordV1, Validate, ValueRefV1,
    MAX_CUSTODY_REWRAP_ITEMS, SCHEMA_CUSTODY_REWRAP_V1, SCHEMA_HOME_V1, SCHEMA_LOCATE_V1,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;

const HOME_JOURNAL_NAME: &str = "function-home";
const HOME_JOURNAL_SCHEMA: &str = "gawd.function.home.journal.v1";
const CUSTODY_JOURNAL_NAME: &str = "function-home-custody";
const CUSTODY_JOURNAL_SCHEMA: &str = "gawd.function.home.custody.journal.v1";
const CHECKPOINT_FORMAT: &str = "gawd.function.home.checkpoint.archive.v1";
const CHECKPOINT_MEDIA_TYPE: &str = "application/vnd.gawd.function-home-checkpoint.v1+json";
const IMPORTED_AUTHORITIES_FILE: &str = "function-home.imported-authorities.json";
const CURRENT_AUTHORITY_FILE: &str = "function-home.current-authority.v1.json";
const MAX_AUTHORITY_HISTORY_BYTES: usize = 1024 * 1024;

fn require_custody_capacity<T>(
    journal: &SignedJournal<T>,
    reserved_after: usize,
    operation: &str,
) -> Result<(), HomeError>
where
    T: Clone + Serialize + serde::de::DeserializeOwned,
{
    let remaining = journal.remaining_records()?;
    if remaining <= reserved_after {
        return Err(HomeError::Capacity(format!(
            "custody journal cannot append {operation}; {reserved_after} later safety records are reserved"
        )));
    }
    Ok(())
}

/// A successfully prepared handoff. Producing this value means the source's Frozen fence is
/// already fsynced; transmitting its public fields cannot transmit the Abode root private key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedHandoff {
    pub grant: SignedRecordV1<CustodyGrantV1>,
    pub checkpoint: SignedRecordV1<HomeCheckpointV1>,
    pub prepared: SignedRecordV1<CustodyPreparedV1>,
}

/// A fsynced coordinator refresh for an already-active moved Home, plus the source return route
/// needed to replace its frozen redirect.
pub(super) struct ActiveLeaseRevision {
    pub lease: SignedRecordV1<HomeLeaseV1>,
    pub source_realm: String,
    pub source_node: String,
    pub source_coordinator: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
// Custody status is a cold-path, proof-bearing value. Keeping the complete signed redirect inline
// makes the public shape direct and avoids heap-shape differences between otherwise equal states.
#[allow(clippy::large_enum_variant)]
pub enum HomeCustodyStatus {
    Active { epoch: u64, handoff: Option<HandoffId> },
    Frozen { epoch: u64, handoff: HandoffId, redirect: Option<SignedRecordV1<HomeLeaseV1>> },
    Staged { epoch: u64, handoff: HandoffId },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HomeCheckpointArchiveV1 {
    format: String,
    home: HomeId,
    epoch: u64,
    high_water_mark: u64,
    log_root: String,
    /// Complete root-proven public operational-key history needed to replay the signed chain.
    authorities: Vec<HomeAuthorityV1>,
    records: Vec<SignedRecordV1<ChainEntry<HomeLedgerRecord>>>,
    /// Latest effective destination-envelope proof. Legacy and end-to-end-only archives omit it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rewrap_overlay: Option<Box<SignedRecordV1<CustodyStagedV1>>>,
}

struct CappedCheckpointBuffer {
    bytes: Vec<u8>,
    cap: usize,
}

impl CappedCheckpointBuffer {
    fn new(cap: usize) -> Self {
        Self { bytes: Vec::with_capacity(cap.min(64 * 1024)), cap }
    }

    fn push(&mut self, bytes: &[u8]) -> Result<(), HomeError> {
        let next = self
            .bytes
            .len()
            .checked_add(bytes.len())
            .ok_or_else(|| HomeError::Capacity("checkpoint size overflowed".into()))?;
        if next > self.cap {
            return Err(HomeError::Capacity(format!(
                "checkpoint exceeds configured cap {}",
                self.cap
            )));
        }
        self.bytes
            .try_reserve_exact(bytes.len())
            .map_err(|_| HomeError::Capacity("checkpoint buffer allocation was refused".into()))?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    fn json<T: Serialize>(&mut self, value: &T) -> Result<(), HomeError> {
        let bytes = canonical_json_bytes(value).map_err(super::invalid)?;
        self.push(&bytes)
    }

    fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// Encode the exact canonical archive wire while borrowing the journal records. Each individual
/// signed record is already bounded by the journal cap; the aggregate buffer refuses growth before
/// it crosses `max_bytes`, so checkpoint creation never materializes an unbounded archive-shaped
/// `serde_json::Value` or clones the complete chain.
fn encode_checkpoint_archive(
    config: &HomeConfig,
    records: &[SignedRecordV1<ChainEntry<HomeLedgerRecord>>],
    log_root: &str,
    rewrap_overlay: Option<&SignedRecordV1<CustodyStagedV1>>,
) -> Result<Vec<u8>, HomeError> {
    let high_water_mark = u64::try_from(records.len())
        .map_err(|_| HomeError::Capacity("checkpoint record count exceeds u64".into()))?;
    let mut out = CappedCheckpointBuffer::new(config.max_checkpoint_bytes);

    // `canonical_json_bytes` sorts object keys recursively. Keep this fixed top-level order in
    // lockstep with `HomeCheckpointArchiveV1`; nested values use the shared canonical encoder.
    out.push(br#"{"authorities":["#)?;
    for (index, authority) in
        std::iter::once(&config.authority).chain(config.historical_authorities.iter()).enumerate()
    {
        if index > 0 {
            out.push(b",")?;
        }
        out.json(authority)?;
    }
    out.push(br#"],"epoch":"#)?;
    out.json(&config.epoch)?;
    out.push(b",\"format\":")?;
    out.json(&CHECKPOINT_FORMAT)?;
    out.push(b",\"high_water_mark\":")?;
    out.json(&high_water_mark)?;
    out.push(b",\"home\":")?;
    out.json(&config.home)?;
    out.push(b",\"log_root\":")?;
    out.json(&log_root)?;
    out.push(b",\"records\":[")?;
    for (index, record) in records.iter().enumerate() {
        if index > 0 {
            out.push(b",")?;
        }
        out.json(record)?;
    }
    out.push(b"]")?;
    if let Some(overlay) = rewrap_overlay {
        out.push(b",\"rewrap_overlay\":")?;
        out.json(overlay)?;
    }
    out.push(b"}")?;
    let bytes = out.finish();
    #[cfg(test)]
    {
        let canonical = canonical_json_bytes(&HomeCheckpointArchiveV1 {
            format: CHECKPOINT_FORMAT.into(),
            home: config.home.clone(),
            epoch: config.epoch,
            high_water_mark,
            log_root: log_root.to_string(),
            authorities: std::iter::once(config.authority.clone())
                .chain(config.historical_authorities.iter().cloned())
                .collect(),
            records: records.to_vec(),
            rewrap_overlay: rewrap_overlay.cloned().map(Box::new),
        })
        .map_err(super::invalid)?;
        assert_eq!(bytes, canonical, "bounded checkpoint encoder changed canonical v1 bytes");
    }
    Ok(bytes)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ImportedAuthorityHistoryV1 {
    format: String,
    home: HomeId,
    authorities: Vec<HomeAuthorityV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub(super) enum CustodyLedgerRecord {
    Initialized { home: HomeId, epoch: u64, route_sequence: u64, coordinator: String },
    RouteRebound { route_sequence: u64, coordinator: String },
    Frozen { grant: SignedRecordV1<CustodyGrantV1>, checkpoint: SignedRecordV1<HomeCheckpointV1> },
    Prepared { prepared: SignedRecordV1<CustodyPreparedV1> },
    Staged { prepared: SignedRecordV1<CustodyPreparedV1> },
    StagingReceipt { staged: SignedRecordV1<CustodyStagedV1> },
    Activated { staged_hash: String, lease: HomeLeaseV1 },
    LeaseRebound { lease: HomeLeaseV1 },
    Redirect { lease: SignedRecordV1<HomeLeaseV1> },
}

#[derive(Debug, Clone)]
// This state is only transitioned under the Home write lock; keeping exact signed handoff proofs
// inline makes replay comparisons explicit and avoids a second owned representation.
#[allow(clippy::large_enum_variant)]
pub(super) enum CustodyState {
    Active {
        epoch: u64,
        handoff: Option<HandoffId>,
        route_sequence: u64,
        coordinator: String,
        activation: Option<(SignedRecordV1<CustodyStagedV1>, HomeLeaseV1)>,
    },
    Frozen {
        grant: SignedRecordV1<CustodyGrantV1>,
        checkpoint: SignedRecordV1<HomeCheckpointV1>,
        prepared: Option<SignedRecordV1<CustodyPreparedV1>>,
        redirect: Option<SignedRecordV1<HomeLeaseV1>>,
    },
    Staged {
        prepared: SignedRecordV1<CustodyPreparedV1>,
        staging: Option<SignedRecordV1<CustodyStagedV1>>,
    },
}

impl CustodyState {
    pub(super) fn unfenced_for_replay() -> Self {
        Self::Active {
            epoch: 1,
            handoff: None,
            route_sequence: 1,
            coordinator: String::new(),
            activation: None,
        }
    }

    pub(super) fn status(&self) -> HomeCustodyStatus {
        match self {
            Self::Active { epoch, handoff, .. } => {
                HomeCustodyStatus::Active { epoch: *epoch, handoff: handoff.clone() }
            }
            Self::Frozen { grant, redirect, .. } => HomeCustodyStatus::Frozen {
                epoch: grant.payload.from_epoch,
                handoff: grant.payload.handoff.clone(),
                redirect: redirect.clone(),
            },
            Self::Staged { prepared, .. } => HomeCustodyStatus::Staged {
                epoch: prepared.payload.grant.payload.to_epoch,
                handoff: prepared.payload.grant.payload.handoff.clone(),
            },
        }
    }

    pub(super) fn ensure_writable(&self) -> Result<(), HomeError> {
        match self {
            Self::Active { .. } => Ok(()),
            Self::Frozen { grant, .. } => Err(HomeError::State(format!(
                "home is permanently frozen for handoff `{}`; silence never thaws it",
                grant.payload.handoff
            ))),
            Self::Staged { prepared, .. } => Err(HomeError::State(format!(
                "home handoff `{}` is staged but not activated",
                prepared.payload.grant.payload.handoff
            ))),
        }
    }

    pub(super) fn active_route_sequence(&self) -> Result<u64, HomeError> {
        match self {
            Self::Active { route_sequence, .. } if *route_sequence > 0 => Ok(*route_sequence),
            Self::Active { .. } => {
                Err(HomeError::State("active Home has no durable route revision".into()))
            }
            Self::Frozen { .. } | Self::Staged { .. } => {
                Err(HomeError::State("non-active Home has no authoritative route".into()))
            }
        }
    }

    pub(super) fn active_coordinator(&self) -> Option<&str> {
        match self {
            Self::Active { coordinator, .. } => Some(coordinator),
            Self::Frozen { .. } | Self::Staged { .. } => None,
        }
    }
}

impl FunctionHome {
    pub(super) fn refresh_runtime_route(&self, coordinator: &str) -> Result<(), HomeError> {
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        self.ensure_authoritative_state(&state)?;
        let CustodyState::Active {
            epoch,
            handoff,
            route_sequence,
            coordinator: current,
            activation,
        } = &state.custody
        else {
            return Err(HomeError::State("only an active Home may refresh its route".into()));
        };
        if current == coordinator {
            return Ok(());
        }
        if activation.is_some() {
            return Err(HomeError::State(
                "moved Home bind did not durably refresh its lease before opening".into(),
            ));
        }
        let next = route_sequence
            .checked_add(1)
            .ok_or_else(|| HomeError::State("home route sequence is exhausted".into()))?;
        require_custody_capacity(&self.custody_journal, 2, "genesis route refresh")?;
        self.custody_journal.append(CustodyLedgerRecord::RouteRebound {
            route_sequence: next,
            coordinator: coordinator.to_string(),
        })?;
        state.custody = CustodyState::Active {
            epoch: *epoch,
            handoff: handoff.clone(),
            route_sequence: next,
            coordinator: coordinator.to_string(),
            activation: None,
        };
        Ok(())
    }

    /// Export a complete, signed replay archive and store it by verified content address.
    ///
    /// The write gate remains held while the journal snapshot is encoded and committed, so the
    /// returned high-water mark and hash-chain tip describe one exact source state.
    pub fn create_checkpoint(
        &self,
        created_at_unix_ms: Option<u64>,
    ) -> Result<SignedRecordV1<HomeCheckpointV1>, HomeError> {
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        self.ensure_authoritative_state(&state)?;
        let rewrap_overlay = self.checkpoint_rewrap_overlay(&state)?;
        let (bytes, high_water_mark, log_root) =
            self.journal.with_snapshot(|records, log_root| {
                let high_water_mark = u64::try_from(records.len()).map_err(|_| {
                    HomeError::Capacity("checkpoint record count exceeds u64".into())
                })?;
                let bytes = encode_checkpoint_archive(
                    &self.config,
                    records,
                    log_root,
                    rewrap_overlay.as_ref(),
                )?;
                Ok::<_, HomeError>((bytes, high_water_mark, log_root.to_string()))
            })??;
        let blob = self.checkpoint_blobs.put_checkpoint(CHECKPOINT_MEDIA_TYPE, &bytes).map_err(
            |error| HomeError::Invalid(format!("checkpoint store refused bytes: {error}")),
        )?;
        verify_blob_bytes(&blob, &bytes)?;
        self.checkpoint_blobs
            .verify_available(&blob)
            .map_err(|error| HomeError::Invalid(format!("checkpoint is not durable: {error}")))?;
        let checkpoint = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            HomeCheckpointV1 {
                home: self.config.home.clone(),
                epoch: self.config.epoch,
                high_water_mark,
                log_root,
                state: blob,
                created_at_unix_ms,
            },
            self.signer.as_ref(),
        )
        .map_err(super::signing)?;
        verify_source_checkpoint(&self.config, &checkpoint)?;
        Ok(checkpoint)
    }

    fn checkpoint_rewrap_overlay(
        &self,
        state: &HomeState,
    ) -> Result<Option<SignedRecordV1<CustodyStagedV1>>, HomeError> {
        effective_rewrap_overlay(&self.config, self.checkpoint_blobs.as_ref(), state)
    }

    /// Irreversibly fence this source after validating the root-authorized exact checkpoint.
    ///
    /// Repeating the same handoff is idempotent. Any different request after the fsynced Frozen
    /// record is rejected; no timeout or missing acknowledgement changes that state.
    pub fn prepare_handoff(
        &self,
        grant: SignedRecordV1<CustodyGrantV1>,
        checkpoint: SignedRecordV1<HomeCheckpointV1>,
    ) -> Result<PreparedHandoff, HomeError> {
        // A post-fsync append error poisons the in-memory prefix. Never compare or migrate that
        // stale view; only reopening the journals may establish which prefix is durable.
        self.journal.ensure_healthy()?;
        self.custody_journal.ensure_healthy()?;
        verify_source_handoff(&self.config, &grant, &checkpoint)?;
        let source_binding = grant
            .payload
            .destination_rewrap
            .as_ref()
            .map(|_| self.current_recipient_binding())
            .transpose()?;
        if let (Some(requirement), Some(binding)) =
            (&grant.payload.destination_rewrap, source_binding.as_ref())
        {
            if binding != requirement.source_binding.as_ref() {
                return Err(HomeError::Unauthorized(
                    "custody grant source binding is not the current Home recipient binding".into(),
                ));
            }
        }
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        self.journal.ensure_healthy()?;
        self.custody_journal.ensure_healthy()?;
        let already_frozen = match &state.custody {
            CustodyState::Frozen {
                grant: existing_grant, checkpoint: existing_checkpoint, ..
            } if canonical_hash(existing_grant).map_err(super::invalid)?
                == canonical_hash(&grant).map_err(super::invalid)?
                && canonical_hash(existing_checkpoint).map_err(super::invalid)?
                    == canonical_hash(&checkpoint).map_err(super::invalid)? =>
            {
                true
            }
            _ => {
                state.custody.ensure_writable()?;
                false
            }
        };
        if !already_frozen
            && (self.journal.len() as u64 != checkpoint.payload.high_water_mark
                || self.journal.tip_hash() != checkpoint.payload.log_root)
        {
            return Err(HomeError::Conflict(
                "checkpoint became stale before the source fence".into(),
            ));
        }
        let archive = read_archive(&self.config, self.checkpoint_blobs.as_ref(), &checkpoint)?;
        validate_archive(&self.config, &checkpoint, &archive)?;
        verify_required_blobs(self.checkpoint_blobs.as_ref(), &archive)?;
        let (rewrap_inventory_hash, rewrap_item_count) =
            if let Some(requirement) = &grant.payload.destination_rewrap {
                let (inventory, inventory_hash) = build_rewrap_inventory(&archive, requirement)?;
                let item_count = u32::try_from(inventory.len()).map_err(|_| {
                    HomeError::Capacity("custody rewrap inventory count exceeds u32".into())
                })?;
                (Some(inventory_hash), Some(item_count))
            } else {
                (None, None)
            };
        if !already_frozen {
            // This fsynced record is the irreversible source fence. The portable Prepared proof is
            // deliberately signed only after this append returns successfully.
            let frozen = CustodyState::Frozen {
                grant: grant.clone(),
                checkpoint: checkpoint.clone(),
                prepared: None,
                redirect: None,
            };
            require_custody_capacity(&self.custody_journal, 1, "source Frozen fence")?;
            if let Err(error) = self.custody_journal.append(CustodyLedgerRecord::Frozen {
                grant: grant.clone(),
                checkpoint: checkpoint.clone(),
            }) {
                // Once a fence append reaches the filesystem its persistence can be uncertain.
                // The Job journal is separate, so leaving the in-memory gate Active here would let
                // this process issue work past a possibly durable Frozen record. Freeze locally on
                // every uncertain append; restart recovery may thaw only when no fence survived,
                // and no portable Prepared proof can have been signed on this error path.
                state.custody = frozen;
                return Err(error.into());
            }
            state.custody = frozen;
        }

        if let CustodyState::Frozen { prepared: Some(prepared), .. } = &state.custody {
            if prepared.payload.rewrap_inventory_hash != rewrap_inventory_hash
                || prepared.payload.rewrap_item_count != rewrap_item_count
            {
                return Err(HomeError::Conflict(
                    "persisted Prepared proof differs from the recovered exact inventory".into(),
                ));
            }
            return Ok(PreparedHandoff { grant, checkpoint, prepared: prepared.clone() });
        }
        let prepared = SignedRecordV1::sign(
            SCHEMA_HOME_V1,
            CustodyPreparedV1 {
                grant: Box::new(grant.clone()),
                checkpoint: Box::new(checkpoint.clone()),
                grant_hash: canonical_hash(&grant).map_err(super::invalid)?,
                checkpoint_hash: canonical_hash(&checkpoint).map_err(super::invalid)?,
                source_log_root: checkpoint.payload.log_root.clone(),
                source_coordinator: self.config.coordinator.clone(),
                rewrap_inventory_hash,
                rewrap_item_count,
            },
            self.signer.as_ref(),
        )
        .map_err(super::signing)?;
        verify_custody_prepared(&prepared).map_err(super::invalid)?;
        // Persisting the public proof makes exact retries and proof-bearing status deterministic.
        require_custody_capacity(&self.custody_journal, 0, "source Prepared proof")?;
        self.custody_journal
            .append(CustodyLedgerRecord::Prepared { prepared: prepared.clone() })?;
        let CustodyState::Frozen {
            grant: frozen_grant,
            checkpoint: frozen_checkpoint,
            redirect,
            ..
        } = &state.custody
        else {
            return Err(HomeError::State("source lost its Frozen fence while preparing".into()));
        };
        state.custody = CustodyState::Frozen {
            grant: frozen_grant.clone(),
            checkpoint: frozen_checkpoint.clone(),
            prepared: Some(prepared.clone()),
            redirect: redirect.clone(),
        };
        Ok(PreparedHandoff { grant, checkpoint, prepared })
    }

    /// Store a verified destination activation lease as a read-only redirect. This never appends to
    /// the canonical Job chain and never restores source write authority.
    pub fn record_handoff_redirect(
        &self,
        lease: SignedRecordV1<HomeLeaseV1>,
    ) -> Result<(), HomeError> {
        self.journal.ensure_healthy()?;
        self.custody_journal.ensure_healthy()?;
        verify_home_lease(&lease).map_err(super::invalid)?;
        if lease.schema != SCHEMA_LOCATE_V1 {
            return Err(HomeError::Invalid("redirect lease uses the wrong schema".into()));
        }
        let mut state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        self.journal.ensure_healthy()?;
        self.custody_journal.ensure_healthy()?;
        let CustodyState::Frozen { grant, checkpoint, prepared, redirect } = &state.custody else {
            return Err(HomeError::State("only a frozen source can retain a redirect".into()));
        };
        if !redirect_matches_grant(&lease.payload, grant) {
            return Err(HomeError::Unauthorized(
                "activation lease does not match the frozen custody grant".into(),
            ));
        }
        if let Some(existing) = redirect {
            if existing == &lease {
                return Ok(());
            }
            if !is_home_lease_coordinator_revision(&existing.payload, &lease.payload) {
                return Err(HomeError::Conflict(
                    "a different redirect is already retained for this handoff".into(),
                ));
            }
        }
        let next = CustodyState::Frozen {
            grant: grant.clone(),
            checkpoint: checkpoint.clone(),
            prepared: prepared.clone(),
            redirect: Some(lease.clone()),
        };
        self.custody_journal.append(CustodyLedgerRecord::Redirect { lease })?;
        state.custody = next;
        Ok(())
    }

    pub fn custody_status(&self) -> HomeCustodyStatus {
        self.state.lock().unwrap_or_else(|poison| poison.into_inner()).custody.status()
    }

    /// Return a self-contained, current-epoch signed status fact.
    pub fn signed_custody_status(&self) -> Result<SignedRecordV1<HomeCustodyStatusV1>, HomeError> {
        let state = self.state.lock().unwrap_or_else(|poison| poison.into_inner());
        self.journal.ensure_healthy()?;
        self.custody_journal.ensure_healthy()?;
        sign_status(&self.config, self.signer.as_ref(), &state.custody)
    }
}

/// Durably stage an exact checkpoint at the destination. This method never activates the Home.
/// Retrying after either the staging fsync or journal-install fsync is idempotent.
pub fn stage_handoff(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    blobs: &dyn CheckpointBlobStore,
    prepared: SignedRecordV1<CustodyPreparedV1>,
) -> Result<SignedRecordV1<CustodyStagedV1>, HomeError> {
    stage_handoff_with_rewrapper(
        config,
        signer,
        blobs,
        prepared,
        Arc::new(UnavailableCustodyKeyRewrapper),
    )
}

/// Stage a custody handoff with an injected destination-local KMS/enclave implementation.
pub fn stage_handoff_with_rewrapper(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    blobs: &dyn CheckpointBlobStore,
    prepared: SignedRecordV1<CustodyPreparedV1>,
    rewrapper: Arc<dyn CustodyKeyRewrapper>,
) -> Result<SignedRecordV1<CustodyStagedV1>, HomeError> {
    verify_custody_prepared(&prepared).map_err(super::invalid)?;
    let grant = prepared.payload.grant.as_ref();
    let checkpoint = prepared.payload.checkpoint.as_ref();
    verify_destination_handoff(config, signer.as_ref(), grant, checkpoint)?;
    let completed_config = persist_current_authority(config, &prepared)?;
    let config = &completed_config;
    let archive = read_archive(config, blobs, checkpoint)?;
    validate_archive(config, checkpoint, &archive)?;
    verify_required_blobs(blobs, &archive)?;
    let inventory = verify_prepared_archive_rewrap(&prepared, &archive)?;
    let rewrap_request = if let Some(requirement) = grant.payload.destination_rewrap.as_ref() {
        let binding = rewrapper.current_binding().map_err(|error| {
            HomeError::State(format!("custody key rewrapper unavailable: {error}"))
        })?;
        verify_current_recipient_binding(config, &binding)?;
        if &binding != requirement.destination_binding.as_ref() {
            return Err(HomeError::Unauthorized(
                "custody rewrapper does not serve the exact destination binding".into(),
            ));
        }
        let request = SignedRecordV1::sign(
            SCHEMA_CUSTODY_REWRAP_V1,
            CustodyRewrapRequestV1 {
                home: grant.payload.home.clone(),
                handoff: grant.payload.handoff.clone(),
                prepared_hash: canonical_hash(&prepared).map_err(super::invalid)?,
                grant_hash: prepared.payload.grant_hash.clone(),
                checkpoint_hash: prepared.payload.checkpoint_hash.clone(),
                requirement_hash: canonical_hash(requirement).map_err(super::invalid)?,
                inventory_hash: prepared.payload.rewrap_inventory_hash.clone().ok_or_else(
                    || {
                        HomeError::Invalid(
                            "Prepared proof omits its declared rewrap inventory".into(),
                        )
                    },
                )?,
                item_count: prepared.payload.rewrap_item_count.ok_or_else(|| {
                    HomeError::Invalid("Prepared proof omits its declared rewrap count".into())
                })?,
            },
            signer.as_ref(),
        )
        .map_err(super::signing)?;
        verify_custody_rewrap_request(&request, &prepared).map_err(super::invalid)?;
        Some(request)
    } else {
        None
    };
    persist_imported_authorities(config, &archive.authorities)?;

    let (journal, state) = open_custody_journal(config, signer.clone(), false)?;
    match &state {
        Some(CustodyState::Staged { prepared: existing, .. })
            if same_record(existing, &prepared)? => {}
        Some(CustodyState::Active { activation: Some((staged, _)), .. })
            if same_record(staged.payload.prepared.as_ref(), &prepared)? =>
        {
            return Ok(staged.clone());
        }
        None => {
            require_custody_capacity(&journal, 4, "destination Staged marker")?;
            journal.append(CustodyLedgerRecord::Staged { prepared: prepared.clone() })?;
        }
        _ => {
            return Err(HomeError::Conflict(
                "destination contains a different custody state".into(),
            ));
        }
    }
    let authorities = authority_map(&archive.authorities, &archive.home)?;
    verify_complete_authority_lineage(&archive.authorities, &archive.home)?;
    let chain_authority = move |candidate: &str, entry: &ChainEntry<HomeLedgerRecord>| {
        authorities.get(candidate).is_some_and(|epoch| {
            !entry.event.events.is_empty()
                && entry.event.events.iter().all(|event| event.payload.home_epoch == *epoch)
                && entry.event.grant.as_ref().is_none_or(|item| item.payload.home_epoch == *epoch)
        })
    };
    SignedJournal::install_snapshot(
        &config.root,
        HOME_JOURNAL_NAME,
        HOME_JOURNAL_SCHEMA,
        &archive.records,
        config.journal_caps,
        &chain_authority,
    )?;
    if let Some(CustodyState::Staged { staging: Some(staged), .. }) = state {
        return Ok(staged);
    }
    let rewrap_receipt = if let Some(request) = rewrap_request.as_ref() {
        let receipt = rewrapper.rewrap(request, &inventory).map_err(|error| {
            HomeError::State(format!("custody key rewrapper refused inventory: {error}"))
        })?;
        if receipt.payload.request.as_ref() != request {
            return Err(HomeError::Conflict(
                "custody rewrapper receipt does not contain the exact signed request".into(),
            ));
        }
        verify_custody_rewrap_receipt(&receipt, &prepared).map_err(super::invalid)?;
        Some(Box::new(receipt))
    } else {
        None
    };
    let prepared_hash = canonical_hash(&prepared).map_err(super::invalid)?;
    let grant_hash = canonical_hash(grant).map_err(super::invalid)?;
    let checkpoint_hash = canonical_hash(checkpoint).map_err(super::invalid)?;
    let staged = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyStagedV1 {
            prepared: Box::new(prepared),
            prepared_hash,
            grant_hash,
            checkpoint_hash,
            destination_realm: config.realm.clone(),
            destination_node: config.node.clone(),
            destination_coordinator: config.coordinator.clone(),
            rewrap_receipt,
        },
        signer.as_ref(),
    )
    .map_err(super::signing)?;
    verify_custody_staged(&staged).map_err(super::invalid)?;
    // The receipt is emitted only after both the stage marker and installed Home journal fsync.
    require_custody_capacity(&journal, 3, "destination StagingReceipt")?;
    journal.append(CustodyLedgerRecord::StagingReceipt { staged: staged.clone() })?;
    Ok(staged)
}

/// Finish a previously staged install and return the destination's signed lease.
///
/// The Activated record is append+fsynced before the lease signature is produced. If the reply is
/// lost, repeating this method reconstructs and signs the exact same lease while the source remains
/// Frozen.
pub fn activate_staged_handoff(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    blobs: &dyn CheckpointBlobStore,
    staged: SignedRecordV1<CustodyStagedV1>,
) -> Result<SignedRecordV1<HomeLeaseV1>, HomeError> {
    let mut completed_config = config.clone();
    merge_current_authority(&mut completed_config)?;
    let config = &completed_config;
    verify_custody_staged(&staged).map_err(super::invalid)?;
    let (journal, state) = open_custody_journal(config, signer.clone(), false)?;
    let lease = match state {
        Some(CustodyState::Staged { prepared, staging: Some(persisted) })
            if same_record(&persisted, &staged)?
                && same_record(staged.payload.prepared.as_ref(), &prepared)? =>
        {
            let grant = prepared.payload.grant.as_ref();
            let checkpoint = prepared.payload.checkpoint.as_ref();
            verify_destination_handoff(config, signer.as_ref(), grant, checkpoint)?;
            let archive = read_archive(config, blobs, checkpoint)?;
            validate_archive(config, checkpoint, &archive)?;
            verify_required_blobs(blobs, &archive)?;
            verify_prepared_archive_rewrap(&prepared, &archive)?;
            verify_installed_archive(config, signer.clone(), &archive)?;
            let lease = destination_lease(config, grant, checkpoint)?;
            require_custody_capacity(&journal, 2, "destination Activated fence")?;
            journal.append(CustodyLedgerRecord::Activated {
                staged_hash: canonical_hash(&staged).map_err(super::invalid)?,
                lease: lease.clone(),
            })?;
            lease
        }
        Some(CustodyState::Active { activation: Some((persisted, lease)), .. })
            if same_record(&persisted, &staged)? =>
        {
            lease
        }
        Some(CustodyState::Active { activation: Some(_), .. }) => {
            return Err(HomeError::Conflict(
                "activation request names a different staging receipt".into(),
            ));
        }
        _ => {
            return Err(HomeError::State(
                "destination has no exact, receipt-bearing staged handoff to activate".into(),
            ));
        }
    };
    let signed =
        SignedRecordV1::sign(SCHEMA_LOCATE_V1, lease, signer.as_ref()).map_err(super::signing)?;
    verify_home_lease(&signed).map_err(super::invalid)?;
    Ok(signed)
}

/// Durably refresh the process-local coordinator of an already-active moved Home.
///
/// This is called from creature bind, after the live `CreatureId` is known and before the revised
/// lease is published. No authority, location, handoff, or checkpoint field may change.
pub(super) fn refresh_active_destination_lease(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
) -> Result<Option<ActiveLeaseRevision>, HomeError> {
    let (journal, state) = open_custody_journal(config, signer.clone(), false)?;
    let Some(state) = state else { return Ok(None) };
    let (staged, current) = match state {
        CustodyState::Active { activation: Some(pair), .. } => pair,
        CustodyState::Staged { .. } => return Ok(None),
        _ => {
            return Err(HomeError::State("custody destination is not an active moved Home".into()));
        }
    };
    let mut next = current.clone();
    next.lease_sequence = next
        .lease_sequence
        .checked_add(1)
        .ok_or_else(|| HomeError::State("home lease sequence is exhausted".into()))?;
    next.coordinator = config.coordinator.clone();
    next.validate().map_err(super::invalid)?;
    if !is_home_lease_coordinator_revision(&current, &next) {
        return Err(HomeError::Conflict(
            "coordinator refresh changed an immutable Home lease binding".into(),
        ));
    }
    require_custody_capacity(&journal, 2, "active lease revision")?;
    journal.append(CustodyLedgerRecord::LeaseRebound { lease: next.clone() })?;
    let lease =
        SignedRecordV1::sign(SCHEMA_LOCATE_V1, next, signer.as_ref()).map_err(super::signing)?;
    verify_home_lease(&lease).map_err(super::invalid)?;
    let prepared = &staged.payload.prepared.payload;
    let grant = &prepared.grant.payload;
    Ok(Some(ActiveLeaseRevision {
        lease,
        source_realm: grant.source_realm.clone(),
        source_node: grant.source_node.clone(),
        source_coordinator: prepared.source_coordinator.clone(),
    }))
}

/// Inspect a destination custody journal without opening the staged Home for writes.
pub fn destination_custody_status(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
) -> Result<SignedRecordV1<HomeCustodyStatusV1>, HomeError> {
    let mut completed_config = config.clone();
    merge_current_authority(&mut completed_config)?;
    let config = &completed_config;
    let (_, state) = open_custody_journal(config, signer.clone(), false)?;
    let state = state.ok_or_else(|| HomeError::State("destination has no custody state".into()))?;
    sign_status(config, signer.as_ref(), &state)
}

fn sign_status(
    config: &HomeConfig,
    signer: &dyn AuthoritySigner,
    state: &CustodyState,
) -> Result<SignedRecordV1<HomeCustodyStatusV1>, HomeError> {
    let phase = match state {
        CustodyState::Active { activation: None, .. } if config.epoch == 1 => {
            HomeCustodyPhaseV1::Active { staged: None, lease: None }
        }
        CustodyState::Active { activation: Some((staged, lease)), .. } => {
            let lease = SignedRecordV1::sign(SCHEMA_LOCATE_V1, lease.clone(), signer)
                .map_err(super::signing)?;
            verify_home_lease(&lease).map_err(super::invalid)?;
            HomeCustodyPhaseV1::Active {
                staged: Some(Box::new(staged.clone())),
                lease: Some(Box::new(lease)),
            }
        }
        CustodyState::Frozen { prepared: Some(prepared), redirect, .. } => {
            HomeCustodyPhaseV1::Frozen {
                prepared: Box::new(prepared.clone()),
                redirect: redirect.clone().map(Box::new),
            }
        }
        CustodyState::Staged { staging: Some(staged), .. } => {
            HomeCustodyPhaseV1::Staged { staged: Box::new(staged.clone()) }
        }
        CustodyState::Frozen { prepared: None, .. } => {
            return Err(HomeError::State(
                "source is fenced but its Prepared proof has not been persisted; retry Prepare"
                    .into(),
            ));
        }
        CustodyState::Staged { staging: None, .. } => {
            return Err(HomeError::State(
                "destination stage is incomplete; retry Stage before requesting status".into(),
            ));
        }
        CustodyState::Active { .. } => {
            return Err(HomeError::State(
                "non-genesis active Home is missing its activation proof".into(),
            ));
        }
    };
    let status = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        HomeCustodyStatusV1 {
            home: config.home.clone(),
            epoch: config.epoch,
            authority: config.authority.clone(),
            state: phase,
        },
        signer,
    )
    .map_err(super::signing)?;
    verify_home_custody_status(&status).map_err(super::invalid)?;
    Ok(status)
}

pub(super) fn open_or_initialize_custody(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    home_journal_empty: bool,
) -> Result<(SignedJournal<CustodyLedgerRecord>, CustodyState), HomeError> {
    let (journal, state) = open_custody_journal(config, signer, true)?;
    if let Some(state) = state {
        if matches!(state, CustodyState::Staged { .. }) {
            return Err(HomeError::State(
                "destination is staged but inactive; complete activation before opening".into(),
            ));
        }
        return Ok((journal, state));
    }
    if config.epoch != 1 || !home_journal_empty {
        return Err(HomeError::State(
            "missing custody genesis for an existing/non-genesis Home".into(),
        ));
    }
    require_custody_capacity(&journal, 2, "custody genesis")?;
    journal.append(CustodyLedgerRecord::Initialized {
        home: config.home.clone(),
        epoch: config.epoch,
        route_sequence: 1,
        coordinator: config.coordinator.clone(),
    })?;
    Ok((
        journal,
        CustodyState::Active {
            epoch: config.epoch,
            handoff: None,
            route_sequence: 1,
            coordinator: config.coordinator.clone(),
            activation: None,
        },
    ))
}

/// Merge the verified, public authority history imported with a checkpoint before the Job journal
/// is opened. This is what lets an e3 Home replay e1 and e2 signatures without caller guesswork.
pub(super) fn merge_imported_authorities(config: &mut HomeConfig) -> Result<(), HomeError> {
    let path = config.root.join(IMPORTED_AUTHORITIES_FILE);
    if !path.exists() {
        return Ok(());
    }
    let bytes = bounded_read(&path, MAX_AUTHORITY_HISTORY_BYTES)?;
    let imported: ImportedAuthorityHistoryV1 = serde_json::from_slice(&bytes).map_err(|error| {
        HomeError::Invalid(format!("imported authority history is corrupt: {error}"))
    })?;
    if imported.format != CHECKPOINT_FORMAT || imported.home != config.home {
        return Err(HomeError::Invalid(
            "imported authority history belongs to another Home/format".into(),
        ));
    }
    authority_map(&imported.authorities, &config.home)?;
    let mut by_epoch: BTreeMap<u64, HomeAuthorityV1> = config
        .historical_authorities
        .iter()
        .cloned()
        .map(|authority| (authority.operational.payload.epoch, authority))
        .collect();
    for authority in imported.authorities {
        let epoch = authority.operational.payload.epoch;
        if epoch >= config.epoch {
            return Err(HomeError::Configuration(
                "imported authority epoch is not historical at this destination".into(),
            ));
        }
        if let Some(existing) = by_epoch.get(&epoch) {
            if existing != &authority {
                return Err(HomeError::Conflict(format!(
                    "two root-proven authority chains claim imported epoch {epoch}"
                )));
            }
        } else {
            by_epoch.insert(epoch, authority);
        }
    }
    config.historical_authorities = by_epoch.into_values().collect();
    Ok(())
}

/// Recover the public source-fence proof that completes a moved Home's operational authority.
pub(super) fn merge_current_authority(config: &mut HomeConfig) -> Result<(), HomeError> {
    let path = config.root.join(CURRENT_AUTHORITY_FILE);
    if config.epoch == 1 {
        if config.authority.prepared.is_some() || path.exists() {
            return Err(HomeError::Conflict(
                "genesis Home must not carry persisted moved-epoch authority".into(),
            ));
        }
        return Ok(());
    }
    let persisted = if path.exists() {
        let bytes = bounded_read(&path, MAX_AUTHORITY_HISTORY_BYTES)?;
        Some(serde_json::from_slice::<SignedRecordV1<CustodyPreparedV1>>(&bytes).map_err(
            |error| HomeError::Invalid(format!("current authority proof is corrupt: {error}")),
        )?)
    } else {
        None
    };
    if let (Some(configured), Some(persisted)) = (&config.authority.prepared, &persisted) {
        if configured.as_ref() != persisted {
            return Err(HomeError::Conflict(
                "configured and persisted current authority proofs differ".into(),
            ));
        }
    }
    if let Some(prepared) = persisted {
        install_prepared_authority(config, prepared)?;
    } else if let Some(prepared) = config.authority.prepared.clone() {
        install_prepared_authority(config, *prepared)?;
    }
    Ok(())
}

fn persist_current_authority(
    config: &HomeConfig,
    prepared: &SignedRecordV1<CustodyPreparedV1>,
) -> Result<HomeConfig, HomeError> {
    let mut completed = config.clone();
    install_prepared_authority(&mut completed, prepared.clone())?;
    let bytes = canonical_json_bytes(prepared).map_err(super::invalid)?;
    if bytes.len() > MAX_AUTHORITY_HISTORY_BYTES {
        return Err(HomeError::Capacity(
            "current authority proof exceeds its bounded metadata cap".into(),
        ));
    }
    let path = config.root.join(CURRENT_AUTHORITY_FILE);
    if path.exists() {
        if bounded_read(&path, MAX_AUTHORITY_HISTORY_BYTES)? != bytes {
            return Err(HomeError::Conflict(
                "destination already contains a different current authority proof".into(),
            ));
        }
    } else {
        atomic_write(&config.root, &path, &bytes)?;
    }
    Ok(completed)
}

fn install_prepared_authority(
    config: &mut HomeConfig,
    prepared: SignedRecordV1<CustodyPreparedV1>,
) -> Result<(), HomeError> {
    verify_custody_prepared(&prepared).map_err(super::invalid)?;
    let grant = &prepared.payload.grant.payload;
    if grant.home != config.home
        || grant.to_epoch != config.epoch
        || grant.destination_realm != config.realm
        || grant.destination_node != config.node
        || grant.destination_operational_key != config.authority.operational
        || grant.source_authority.abode != config.authority.abode
    {
        return Err(HomeError::Unauthorized(
            "Prepared proof does not complete this exact destination authority/location".into(),
        ));
    }
    config.authority.prepared = Some(Box::new(prepared));
    for capability in [
        OperationalCapabilityV1::JobHome,
        OperationalCapabilityV1::JobControl,
        OperationalCapabilityV1::Custody,
        OperationalCapabilityV1::Locate,
    ] {
        config.authority.verify(&config.home, config.epoch, capability).map_err(super::invalid)?;
    }
    Ok(())
}

fn open_custody_journal(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    allow_initialized: bool,
) -> Result<(SignedJournal<CustodyLedgerRecord>, Option<CustodyState>), HomeError> {
    let authorized = configured_authorities(config)?;
    let journal_authorized = authorized.clone();
    let authority = Arc::new(move |candidate: &str, _entry: &ChainEntry<CustodyLedgerRecord>| {
        journal_authorized.contains_key(candidate)
    });
    let journal = SignedJournal::open_with_authority(
        &config.root,
        CUSTODY_JOURNAL_NAME,
        CUSTODY_JOURNAL_SCHEMA,
        signer,
        config.journal_caps,
        authority,
    )?;
    let mut state = None;
    journal.with_snapshot(|records, _| {
        for record in records {
            state = Some(apply_custody_record(
                config,
                state.take(),
                &record.payload.event,
                &record.signer,
                allow_initialized,
            )?);
        }
        Ok::<_, HomeError>(())
    })??;
    if let Some(recovered) = &state {
        let reservations = custody_reservations(recovered);
        if journal.remaining_records()? < reservations {
            return Err(HomeError::Capacity(format!(
                "recovered custody phase requires {reservations} safety records beyond the configured journal cap"
            )));
        }
    }
    Ok((journal, state))
}

fn custody_reservations(state: &CustodyState) -> usize {
    match state {
        // Every active Home must retain the source Frozen + Prepared tail for its next handoff.
        CustodyState::Active { .. } => 2,
        CustodyState::Frozen { prepared: None, .. } => 1,
        CustodyState::Frozen { prepared: Some(_), .. } => 0,
        // A destination first persists its receipt and activation, then remains able to hand off
        // again without sacrificing that next Frozen + Prepared safety tail.
        CustodyState::Staged { staging: None, .. } => 4,
        CustodyState::Staged { staging: Some(_), .. } => 3,
    }
}

fn apply_custody_record(
    config: &HomeConfig,
    state: Option<CustodyState>,
    record: &CustodyLedgerRecord,
    signer: &str,
    allow_initialized: bool,
) -> Result<CustodyState, HomeError> {
    if signer != config.authority.operational.payload.operational_public_key {
        return Err(HomeError::Unauthorized(
            "custody record is not signed by the configured active epoch key".into(),
        ));
    }
    match (state, record) {
        (None, CustodyLedgerRecord::Initialized { home, epoch, route_sequence, coordinator })
            if allow_initialized
                && home == &config.home
                && *epoch == 1
                && config.epoch == 1
                && *route_sequence == 1
                && !coordinator.trim().is_empty() =>
        {
            Ok(CustodyState::Active {
                epoch: *epoch,
                handoff: None,
                route_sequence: *route_sequence,
                coordinator: coordinator.clone(),
                activation: None,
            })
        }
        (
            Some(CustodyState::Active { epoch, handoff, route_sequence, activation: None, .. }),
            CustodyLedgerRecord::RouteRebound { route_sequence: next, coordinator },
        ) if epoch == 1 && *next > route_sequence && !coordinator.trim().is_empty() => {
            Ok(CustodyState::Active {
                epoch,
                handoff,
                route_sequence: *next,
                coordinator: coordinator.clone(),
                activation: None,
            })
        }
        (None, CustodyLedgerRecord::Staged { prepared }) => {
            verify_custody_prepared(prepared).map_err(super::invalid)?;
            verify_destination_handoff(
                config,
                &SignerView(signer),
                &prepared.payload.grant,
                &prepared.payload.checkpoint,
            )?;
            Ok(CustodyState::Staged { prepared: prepared.clone(), staging: None })
        }
        (
            Some(CustodyState::Active { epoch, .. }),
            CustodyLedgerRecord::Frozen { grant, checkpoint },
        ) if epoch == config.epoch => {
            verify_source_handoff(config, grant, checkpoint)?;
            Ok(CustodyState::Frozen {
                grant: grant.clone(),
                checkpoint: checkpoint.clone(),
                prepared: None,
                redirect: None,
            })
        }
        (
            Some(CustodyState::Frozen { grant, checkpoint, prepared: None, redirect }),
            CustodyLedgerRecord::Prepared { prepared },
        ) => {
            verify_custody_prepared(prepared).map_err(super::invalid)?;
            if !same_record(prepared.payload.grant.as_ref(), &grant)?
                || !same_record(prepared.payload.checkpoint.as_ref(), &checkpoint)?
            {
                return Err(HomeError::Conflict(
                    "prepared proof does not continue the exact frozen handoff".into(),
                ));
            }
            Ok(CustodyState::Frozen {
                grant,
                checkpoint,
                prepared: Some(prepared.clone()),
                redirect,
            })
        }
        (
            Some(CustodyState::Staged { prepared, staging: None }),
            CustodyLedgerRecord::StagingReceipt { staged },
        ) => {
            verify_custody_staged(staged).map_err(super::invalid)?;
            if !same_record(staged.payload.prepared.as_ref(), &prepared)? {
                return Err(HomeError::Conflict(
                    "staging receipt does not continue the exact staged handoff".into(),
                ));
            }
            Ok(CustodyState::Staged { prepared, staging: Some(staged.clone()) })
        }
        (
            Some(CustodyState::Staged { prepared, staging: Some(staged) }),
            CustodyLedgerRecord::Activated { staged_hash, lease },
        ) => {
            let grant = prepared.payload.grant.as_ref();
            let checkpoint = prepared.payload.checkpoint.as_ref();
            let mut expected = destination_lease(config, grant, checkpoint)?;
            expected.coordinator = lease.coordinator.clone();
            if staged_hash != &canonical_hash(&staged).map_err(super::invalid)?
                || lease != &expected
            {
                return Err(HomeError::Conflict(
                    "activation does not continue the exact staging receipt".into(),
                ));
            }
            Ok(CustodyState::Active {
                epoch: config.epoch,
                handoff: Some(grant.payload.handoff.clone()),
                route_sequence: lease.lease_sequence,
                coordinator: lease.coordinator.clone(),
                activation: Some((staged, lease.clone())),
            })
        }
        (
            Some(CustodyState::Active {
                epoch, handoff, activation: Some((staged, current)), ..
            }),
            CustodyLedgerRecord::LeaseRebound { lease },
        ) => {
            lease.validate().map_err(super::invalid)?;
            if !is_home_lease_coordinator_revision(&current, lease) {
                return Err(HomeError::Conflict(
                    "coordinator rebound changed an immutable Home lease binding".into(),
                ));
            }
            Ok(CustodyState::Active {
                epoch,
                handoff,
                route_sequence: lease.lease_sequence,
                coordinator: lease.coordinator.clone(),
                activation: Some((staged, lease.clone())),
            })
        }
        (
            Some(CustodyState::Frozen { grant, checkpoint, prepared, redirect }),
            CustodyLedgerRecord::Redirect { lease },
        ) => {
            verify_home_lease(lease).map_err(super::invalid)?;
            if !redirect_matches_grant(&lease.payload, &grant) {
                return Err(HomeError::Conflict("redirect does not match frozen handoff".into()));
            }
            if redirect.as_ref().is_some_and(|current| {
                current != lease
                    && !is_home_lease_coordinator_revision(&current.payload, &lease.payload)
            }) {
                return Err(HomeError::Conflict(
                    "redirect revision changed an immutable Home lease binding".into(),
                ));
            }
            Ok(CustodyState::Frozen { grant, checkpoint, prepared, redirect: Some(lease.clone()) })
        }
        _ => Err(HomeError::State("custody journal contains an invalid state transition".into())),
    }
}

fn verify_source_checkpoint(
    config: &HomeConfig,
    checkpoint: &SignedRecordV1<HomeCheckpointV1>,
) -> Result<(), HomeError> {
    checkpoint.validate().map_err(super::invalid)?;
    if checkpoint.schema != SCHEMA_HOME_V1
        || !checkpoint.verify()
        || checkpoint.signer != config.authority.operational.payload.operational_public_key
        || checkpoint.payload.home != config.home
        || checkpoint.payload.epoch != config.epoch
    {
        return Err(HomeError::Unauthorized("checkpoint is not signed by this Home epoch".into()));
    }
    config
        .authority
        .verify(&config.home, config.epoch, OperationalCapabilityV1::Custody)
        .map_err(super::invalid)
}

fn verify_source_handoff(
    config: &HomeConfig,
    grant: &SignedRecordV1<CustodyGrantV1>,
    checkpoint: &SignedRecordV1<HomeCheckpointV1>,
) -> Result<(), HomeError> {
    verify_custody_grant(grant).map_err(super::invalid)?;
    verify_handoff_checkpoint(grant, checkpoint).map_err(super::invalid)?;
    verify_source_checkpoint(config, checkpoint)?;
    if grant.payload.home != config.home
        || grant.payload.from_epoch != config.epoch
        || grant.payload.source_realm != config.realm
        || grant.payload.source_node != config.node
        || grant.payload.source_authority != config.authority
    {
        return Err(HomeError::Unauthorized(
            "custody grant does not authorize this exact source epoch/location".into(),
        ));
    }
    Ok(())
}

fn verify_destination_handoff(
    config: &HomeConfig,
    signer: &dyn AuthoritySigner,
    grant: &SignedRecordV1<CustodyGrantV1>,
    checkpoint: &SignedRecordV1<HomeCheckpointV1>,
) -> Result<(), HomeError> {
    verify_handoff_checkpoint(grant, checkpoint).map_err(super::invalid)?;
    if grant.payload.home != config.home
        || grant.payload.to_epoch != config.epoch
        || grant.payload.destination_realm != config.realm
        || grant.payload.destination_node != config.node
        || grant.payload.destination_operational_key != config.authority.operational
        || grant.payload.source_authority.abode != config.authority.abode
        || signer.public_key()
            != grant.payload.destination_operational_key.payload.operational_public_key
    {
        return Err(HomeError::Unauthorized(
            "custody grant does not authorize this exact destination epoch/location/key".into(),
        ));
    }
    Ok(())
}

pub(super) fn verify_current_recipient_binding(
    config: &HomeConfig,
    binding: &SignedRecordV1<RecipientKeyBindingV1>,
) -> Result<(), HomeError> {
    verify_recipient_key_binding(binding).map_err(super::invalid)?;
    if binding.payload.abode != config.home {
        return Err(HomeError::Unauthorized("recipient binding does not name this Home".into()));
    }
    let root = config.home.as_str();
    let signing = binding.payload.signing_public_key.as_str();
    let encryption = binding.payload.encryption_public_key.as_str();
    if signing == root || encryption == root || signing == encryption {
        return Err(HomeError::Unauthorized(
            "recipient binding reuses a root, proof, or encryption key plane".into(),
        ));
    }
    for authority in std::iter::once(&config.authority).chain(config.historical_authorities.iter())
    {
        let operational = authority.operational.payload.operational_public_key.as_str();
        if signing == operational || encryption == operational {
            return Err(HomeError::Unauthorized(
                "recipient binding reuses a Home operational authority key".into(),
            ));
        }
    }
    Ok(())
}

fn effective_rewrap_overlay(
    config: &HomeConfig,
    blobs: &dyn CheckpointBlobStore,
    state: &HomeState,
) -> Result<Option<SignedRecordV1<CustodyStagedV1>>, HomeError> {
    let CustodyState::Active { activation, .. } = &state.custody else {
        return Ok(None);
    };
    let Some((staged, _)) = activation else { return Ok(None) };
    verify_custody_staged(staged).map_err(super::invalid)?;
    if staged.payload.rewrap_receipt.is_some() {
        if config.authority.prepared.as_deref() != Some(staged.payload.prepared.as_ref()) {
            return Err(HomeError::Unauthorized(
                "active rewrap receipt is not the exact current authority lineage proof".into(),
            ));
        }
        return Ok(Some(staged.clone()));
    }
    let prior_checkpoint = staged.payload.prepared.payload.checkpoint.as_ref();
    let prior = read_archive(config, blobs, prior_checkpoint)?;
    validate_archive(config, prior_checkpoint, &prior)?;
    Ok(prior.rewrap_overlay.map(|overlay| *overlay))
}

pub(super) fn active_overlay_recipient_binding(
    config: &HomeConfig,
    blobs: &dyn CheckpointBlobStore,
    state: &HomeState,
) -> Result<Option<SignedRecordV1<RecipientKeyBindingV1>>, HomeError> {
    let Some(overlay) = effective_rewrap_overlay(config, blobs, state)? else {
        return Ok(None);
    };
    let requirement =
        overlay.payload.prepared.payload.grant.payload.destination_rewrap.as_ref().ok_or_else(
            || HomeError::Invalid("effective overlay has no rewrap declaration".into()),
        )?;
    Ok(Some(requirement.destination_binding.as_ref().clone()))
}

fn redirect_matches_grant(lease: &HomeLeaseV1, grant: &SignedRecordV1<CustodyGrantV1>) -> bool {
    let payload = &grant.payload;
    lease.home == payload.home
        && lease.epoch == payload.to_epoch
        && lease.handoff.as_ref() == Some(&payload.handoff)
        && lease.checkpoint_hash == payload.checkpoint_hash
        && lease.realm == payload.destination_realm
        && lease.node == payload.destination_node
        && lease.authority.operational == payload.destination_operational_key
        && lease.custody_grant.as_deref() == Some(grant)
}

fn destination_lease(
    config: &HomeConfig,
    grant: &SignedRecordV1<CustodyGrantV1>,
    checkpoint: &SignedRecordV1<HomeCheckpointV1>,
) -> Result<HomeLeaseV1, HomeError> {
    let lease = HomeLeaseV1 {
        home: config.home.clone(),
        epoch: config.epoch,
        lease_sequence: 1,
        realm: config.realm.clone(),
        node: config.node.clone(),
        coordinator: config.coordinator.clone(),
        authority: config.authority.clone(),
        handoff: Some(grant.payload.handoff.clone()),
        custody_grant: Some(Box::new(grant.clone())),
        checkpoint_hash: canonical_hash(checkpoint).map_err(super::invalid)?,
        issued_at_unix_ms: None,
        expires_at_unix_ms: None,
    };
    lease.validate().map_err(super::invalid)?;
    Ok(lease)
}

fn read_archive(
    config: &HomeConfig,
    blobs: &dyn CheckpointBlobStore,
    checkpoint: &SignedRecordV1<HomeCheckpointV1>,
) -> Result<HomeCheckpointArchiveV1, HomeError> {
    let bytes = blobs
        .get_checkpoint(&checkpoint.payload.state)
        .map_err(|error| HomeError::Invalid(format!("checkpoint bytes unavailable: {error}")))?;
    if bytes.len() > config.max_checkpoint_bytes {
        return Err(HomeError::Capacity(format!(
            "checkpoint is {} bytes, exceeds configured cap {}",
            bytes.len(),
            config.max_checkpoint_bytes
        )));
    }
    verify_blob_bytes(&checkpoint.payload.state, &bytes)?;
    serde_json::from_slice(&bytes)
        .map_err(|error| HomeError::Invalid(format!("checkpoint archive is invalid JSON: {error}")))
}

fn validate_archive(
    config: &HomeConfig,
    checkpoint: &SignedRecordV1<HomeCheckpointV1>,
    archive: &HomeCheckpointArchiveV1,
) -> Result<(), HomeError> {
    if archive.format != CHECKPOINT_FORMAT
        || archive.home != checkpoint.payload.home
        || archive.epoch != checkpoint.payload.epoch
        || archive.high_water_mark != checkpoint.payload.high_water_mark
        || archive.log_root != checkpoint.payload.log_root
        || archive.records.len() as u64 != archive.high_water_mark
    {
        return Err(HomeError::Conflict(
            "checkpoint archive metadata does not match its signed descriptor".into(),
        ));
    }
    let authorities = authority_map(&archive.authorities, &archive.home)?;
    verify_complete_authority_lineage(&archive.authorities, &archive.home)?;
    let mut tip =
        "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_string();
    for (index, record) in archive.records.iter().enumerate() {
        if record.schema != HOME_JOURNAL_SCHEMA
            || !record.verify()
            || record.payload.sequence != index as u64
            || record.payload.previous_hash != tip
        {
            return Err(HomeError::Unauthorized(format!(
                "checkpoint journal record {index} breaks its signed chain"
            )));
        }
        let Some(epoch) = authorities.get(&record.signer).copied() else {
            return Err(HomeError::Unauthorized(format!(
                "checkpoint journal record {index} uses an ungranted signer"
            )));
        };
        if record.payload.event.events.is_empty()
            || !record.payload.event.events.iter().all(|event| event.payload.home_epoch == epoch)
            || record
                .payload
                .event
                .grant
                .as_ref()
                .is_some_and(|item| item.payload.home_epoch != epoch)
        {
            return Err(HomeError::Unauthorized(format!(
                "checkpoint journal record {index} crosses Home authority epochs"
            )));
        }
        tip = canonical_hash(record).map_err(super::invalid)?;
    }
    if tip != archive.log_root {
        return Err(HomeError::Conflict(
            "checkpoint archive hash-chain tip does not match descriptor".into(),
        ));
    }

    let Some(current) = archive
        .authorities
        .iter()
        .find(|authority| authority.operational.payload.epoch == archive.epoch)
        .cloned()
    else {
        return Err(HomeError::Unauthorized("checkpoint omits its source epoch authority".into()));
    };
    let historical = archive
        .authorities
        .iter()
        .filter(|authority| authority.operational.payload.epoch < archive.epoch)
        .cloned()
        .collect();
    let mut replay_config = config.clone();
    replay_config.home = archive.home.clone();
    replay_config.epoch = archive.epoch;
    replay_config.authority = current;
    replay_config.historical_authorities = historical;
    let mut state = HomeState::empty_for_replay();
    for record in &archive.records {
        apply_ledger_record(&replay_config, &mut state, &record.payload.event)?;
    }
    if state.jobs.len() > config.max_jobs {
        return Err(HomeError::Capacity(
            "checkpoint contains more jobs than destination permits".into(),
        ));
    }
    verified_overlay_wraps(archive)?;
    Ok(())
}

fn verify_installed_archive(
    config: &HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    archive: &HomeCheckpointArchiveV1,
) -> Result<(), HomeError> {
    let authorized = authority_map(&archive.authorities, &archive.home)?;
    let authority = Arc::new(move |candidate: &str, entry: &ChainEntry<HomeLedgerRecord>| {
        authorized.get(candidate).is_some_and(|epoch| {
            !entry.event.events.is_empty()
                && entry.event.events.iter().all(|event| event.payload.home_epoch == *epoch)
                && entry.event.grant.as_ref().is_none_or(|item| item.payload.home_epoch == *epoch)
        })
    });
    let journal = SignedJournal::<HomeLedgerRecord>::open_with_authority(
        &config.root,
        HOME_JOURNAL_NAME,
        HOME_JOURNAL_SCHEMA,
        signer,
        config.journal_caps,
        authority,
    )?;
    if journal.len() != archive.records.len() || journal.tip_hash() != archive.log_root {
        return Err(HomeError::Conflict(
            "installed destination journal differs from staged checkpoint".into(),
        ));
    }
    Ok(())
}

fn verify_required_blobs(
    blobs: &dyn CheckpointBlobStore,
    archive: &HomeCheckpointArchiveV1,
) -> Result<(), HomeError> {
    visit_archive_values(archive, |value| {
        value.verify_available(blobs).map_err(|error| {
            HomeError::Invalid(format!("checkpoint dependency is unavailable: {error}"))
        })
    })
}

fn visit_archive_values(
    archive: &HomeCheckpointArchiveV1,
    mut visit: impl FnMut(&ValueRefV1) -> Result<(), HomeError>,
) -> Result<(), HomeError> {
    for chain in &archive.records {
        visit_ledger_record_values(&chain.payload.event, &mut visit)?;
    }
    Ok(())
}

fn visit_ledger_record_values(
    record: &HomeLedgerRecord,
    visit: &mut impl FnMut(&ValueRefV1) -> Result<(), HomeError>,
) -> Result<(), HomeError> {
    if let Some(grant) = &record.grant {
        visit(&grant.payload.input)?;
    }
    if let Some(receipt) = &record.receipt {
        match &receipt.payload.stage {
            ExecutionStageV1::Progress { progress, .. } => visit(progress)?,
            ExecutionStageV1::Checkpoint { checkpoint, .. } => visit(checkpoint)?,
            ExecutionStageV1::Succeeded { result } => visit(result)?,
            ExecutionStageV1::Failed { error, .. } => visit(error)?,
            ExecutionStageV1::Claimed
            | ExecutionStageV1::Started
            | ExecutionStageV1::Indeterminate { .. }
            | ExecutionStageV1::Cancelled { .. }
            | ExecutionStageV1::ControlQueued { .. }
            | ExecutionStageV1::ControlAcknowledged { .. } => {}
        }
    }
    for event in &record.events {
        match &event.payload.kind {
            JobEventKindV1::Submitted { spec } => visit(&spec.input)?,
            JobEventKindV1::Progress { progress, .. } => visit(progress)?,
            JobEventKindV1::Checkpoint { checkpoint, .. } => visit(checkpoint)?,
            JobEventKindV1::AttemptFailed { error, .. } | JobEventKindV1::Failed { error } => {
                visit(error)?
            }
            JobEventKindV1::Succeeded { result, .. } => visit(result)?,
            JobEventKindV1::ControlRequested { request, .. } => match &request.payload.kind {
                JobControlKindV1::Steer { value } => visit(value)?,
                JobControlKindV1::ProposeChild { submit, .. } => visit(&submit.payload.input)?,
                JobControlKindV1::Cancel { .. } | JobControlKindV1::AccessUpdate { .. } => {}
            },
            JobEventKindV1::Blocked { .. }
            | JobEventKindV1::DispatchGranted { .. }
            | JobEventKindV1::Claimed { .. }
            | JobEventKindV1::Started { .. }
            | JobEventKindV1::ControlQueued { .. }
            | JobEventKindV1::ControlAcknowledged { .. }
            | JobEventKindV1::RetryScheduled { .. }
            | JobEventKindV1::Cancelled { .. }
            | JobEventKindV1::Indeterminate { .. }
            | JobEventKindV1::LateReceipt { .. }
            | JobEventKindV1::AccessUpdated { .. }
            | JobEventKindV1::ChildSpawned { .. }
            | JobEventKindV1::CustodyPrepared { .. }
            | JobEventKindV1::CustodyActivated { .. } => {}
        }
    }
    Ok(())
}

pub(super) fn durable_direct_recipient_constraint(
    home: &HomeId,
    records: &[SignedRecordV1<ChainEntry<HomeLedgerRecord>>],
) -> Result<Option<(String, String)>, HomeError> {
    let mut binding: Option<(String, String)> = None;
    for chain in records {
        visit_ledger_record_values(&chain.payload.event, &mut |value| {
            let ValueRefV1::Sealed { sealed } = value else { return Ok(()) };
            let direct: Vec<_> =
                sealed.recipients.iter().filter(|wrap| &wrap.recipient == home).collect();
            if direct.len() > 1 {
                return Err(HomeError::Conflict(
                    "durable sealed value carries multiple direct Home envelopes".into(),
                ));
            }
            let Some(wrap) = direct.first() else { return Ok(()) };
            let candidate = (wrap.binding_hash.clone(), sealed.suite.clone());
            if binding.as_ref().is_some_and(|existing| existing != &candidate) {
                return Err(HomeError::Conflict(
                    "durable Home values use multiple recipient bindings without an overlay".into(),
                ));
            }
            binding = Some(candidate);
            Ok(())
        })?;
    }
    Ok(binding)
}

fn sealed_archive_values(
    archive: &HomeCheckpointArchiveV1,
) -> Result<BTreeMap<String, SealedValueV1>, HomeError> {
    let mut sealed_values = BTreeMap::new();
    visit_archive_values(archive, |value| {
        let ValueRefV1::Sealed { sealed } = value else { return Ok(()) };
        let sealed_hash = canonical_hash(sealed.as_ref()).map_err(super::invalid)?;
        if let Some(existing) = sealed_values.get(&sealed_hash) {
            if existing != sealed.as_ref() {
                return Err(HomeError::Conflict(
                    "checkpoint contains divergent sealed values under one canonical hash".into(),
                ));
            }
        } else {
            sealed_values.insert(sealed_hash, sealed.as_ref().clone());
        }
        Ok(())
    })?;
    Ok(sealed_values)
}

fn verified_overlay_wraps(
    archive: &HomeCheckpointArchiveV1,
) -> Result<BTreeMap<String, RecipientKeyWrapV1>, HomeError> {
    let Some(staged) = archive.rewrap_overlay.as_deref() else {
        return Ok(BTreeMap::new());
    };
    verify_custody_staged(staged).map_err(super::invalid)?;
    let grant = staged.payload.prepared.payload.grant.as_ref();
    if grant.payload.home != archive.home || grant.payload.to_epoch > archive.epoch {
        return Err(HomeError::Unauthorized(
            "checkpoint rewrap overlay is not an ancestral proof for this Home epoch".into(),
        ));
    }
    let overlay_authority = archive
        .authorities
        .iter()
        .find(|authority| authority.operational.payload.epoch == grant.payload.to_epoch)
        .ok_or_else(|| {
            HomeError::Unauthorized(
                "checkpoint rewrap overlay destination authority is absent from its lineage".into(),
            )
        })?;
    if overlay_authority.operational != grant.payload.destination_operational_key
        || overlay_authority.prepared.as_deref() != Some(staged.payload.prepared.as_ref())
    {
        return Err(HomeError::Unauthorized(
            "checkpoint rewrap overlay is not the exact Prepared proof in its authority lineage"
                .into(),
        ));
    }
    let receipt = staged.payload.rewrap_receipt.as_deref().ok_or_else(|| {
        HomeError::Invalid("checkpoint rewrap overlay omits its aggregate receipt".into())
    })?;
    let requirement = grant.payload.destination_rewrap.as_ref().ok_or_else(|| {
        HomeError::Invalid("checkpoint rewrap overlay has no root declaration".into())
    })?;
    let sealed_values = sealed_archive_values(archive)?;
    let mut wraps = BTreeMap::new();
    for entry in &receipt.payload.entries {
        let sealed = sealed_values.get(&entry.sealed_value_hash).ok_or_else(|| {
            HomeError::Conflict(
                "checkpoint rewrap overlay contains an entry absent from the archive".into(),
            )
        })?;
        if sealed.ciphertext != entry.ciphertext
            || sealed.suite != requirement.destination_binding.payload.suite
        {
            return Err(HomeError::Conflict(
                "checkpoint rewrap overlay does not match the exact sealed ciphertext and suite"
                    .into(),
            ));
        }
        if wraps.insert(entry.sealed_value_hash.clone(), entry.destination_wrap.clone()).is_some() {
            return Err(HomeError::Conflict(
                "checkpoint rewrap overlay repeats a sealed value".into(),
            ));
        }
    }
    Ok(wraps)
}

fn build_rewrap_inventory(
    archive: &HomeCheckpointArchiveV1,
    requirement: &CustodyRewrapRequirementV1,
) -> Result<(Vec<CustodyRewrapSourceV1>, String), HomeError> {
    let source_binding_hash =
        canonical_hash(requirement.source_binding.as_ref()).map_err(super::invalid)?;
    let overlay = verified_overlay_wraps(archive)?;
    let sealed_values = sealed_archive_values(archive)?;
    let mut inventory = Vec::new();
    for (sealed_value_hash, sealed) in sealed_values {
        let direct: Vec<_> =
            sealed.recipients.iter().filter(|wrap| wrap.recipient == archive.home).collect();
        if direct.len() > 1 {
            return Err(HomeError::Conflict(
                "checkpoint sealed value carries multiple direct Home envelopes".into(),
            ));
        }
        let overlay_wrap = overlay.get(&sealed_value_hash);
        if direct.is_empty() && overlay_wrap.is_none() {
            continue;
        }
        if sealed.suite != requirement.source_binding.payload.suite {
            return Err(HomeError::Conflict(
                "Home-addressed sealed value uses a different suite than the source binding".into(),
            ));
        }
        let mut effective = direct
            .first()
            .filter(|wrap| wrap.binding_hash == source_binding_hash)
            .map(|wrap| (*wrap).clone())
            .into_iter()
            .chain(overlay_wrap.filter(|wrap| wrap.binding_hash == source_binding_hash).cloned());
        let source_wrap = effective.next().ok_or_else(|| {
            HomeError::Conflict(
                "Home-addressed sealed value has no envelope for the current source binding".into(),
            )
        })?;
        if effective.next().is_some() {
            return Err(HomeError::Conflict(
                "Home-addressed sealed value has ambiguous direct and overlay source envelopes"
                    .into(),
            ));
        }
        inventory.push(CustodyRewrapSourceV1 {
            sealed_value_hash,
            ciphertext: sealed.ciphertext,
            source_wrap,
        });
        if inventory.len() > MAX_CUSTODY_REWRAP_ITEMS {
            return Err(HomeError::Capacity(format!(
                "custody rewrap inventory exceeds {MAX_CUSTODY_REWRAP_ITEMS} unique values"
            )));
        }
    }
    let inventory_hash = verify_custody_rewrap_inventory(&archive.home, requirement, &inventory)
        .map_err(super::invalid)?;
    Ok((inventory, inventory_hash))
}

fn verify_prepared_archive_rewrap(
    prepared: &SignedRecordV1<CustodyPreparedV1>,
    archive: &HomeCheckpointArchiveV1,
) -> Result<Vec<CustodyRewrapSourceV1>, HomeError> {
    let Some(requirement) = prepared.payload.grant.payload.destination_rewrap.as_ref() else {
        return Ok(Vec::new());
    };
    let (inventory, inventory_hash) = build_rewrap_inventory(archive, requirement)?;
    let item_count = u32::try_from(inventory.len())
        .map_err(|_| HomeError::Capacity("custody rewrap inventory count exceeds u32".into()))?;
    if prepared.payload.rewrap_inventory_hash.as_ref() != Some(&inventory_hash)
        || prepared.payload.rewrap_item_count != Some(item_count)
    {
        return Err(HomeError::Conflict(
            "Prepared rewrap commitment does not match the exact checkpoint inventory".into(),
        ));
    }
    Ok(inventory)
}

fn configured_authorities(config: &HomeConfig) -> Result<BTreeMap<String, u64>, HomeError> {
    authority_map(
        &std::iter::once(config.authority.clone())
            .chain(config.historical_authorities.iter().cloned())
            .collect::<Vec<_>>(),
        &config.home,
    )
}

fn authority_map(
    authorities: &[HomeAuthorityV1],
    home: &HomeId,
) -> Result<BTreeMap<String, u64>, HomeError> {
    let mut by_key = BTreeMap::new();
    let mut by_epoch = BTreeMap::new();
    for authority in authorities {
        let epoch = authority.operational.payload.epoch;
        authority.verify(home, epoch, OperationalCapabilityV1::JobHome).map_err(super::invalid)?;
        let key = authority.operational.payload.operational_public_key.clone();
        if by_key.insert(key, epoch).is_some() || by_epoch.insert(epoch, ()).is_some() {
            return Err(HomeError::Conflict(
                "checkpoint authority history contains a duplicate key/epoch".into(),
            ));
        }
    }
    Ok(by_key)
}

fn verify_complete_authority_lineage(
    authorities: &[HomeAuthorityV1],
    home: &HomeId,
) -> Result<(), HomeError> {
    let mut by_epoch = BTreeMap::new();
    for authority in authorities {
        let epoch = authority.operational.payload.epoch;
        authority.verify(home, epoch, OperationalCapabilityV1::JobHome).map_err(super::invalid)?;
        if by_epoch.insert(epoch, authority).is_some() {
            return Err(HomeError::Conflict(
                "checkpoint authority history repeats an epoch".into(),
            ));
        }
    }
    let Some((&highest_epoch, _)) = by_epoch.last_key_value() else {
        return Err(HomeError::Unauthorized("checkpoint authority history is empty".into()));
    };
    for epoch in 1..=highest_epoch {
        let authority = by_epoch.get(&epoch).ok_or_else(|| {
            HomeError::Unauthorized(
                "checkpoint authority history omits an epoch in its custody lineage".into(),
            )
        })?;
        if epoch == 1 {
            continue;
        }
        let prior = by_epoch.get(&(epoch - 1)).ok_or_else(|| {
            HomeError::Unauthorized(
                "checkpoint authority history omits an epoch in its custody lineage".into(),
            )
        })?;
        let prepared = authority.prepared.as_deref().ok_or_else(|| {
            HomeError::Unauthorized("moved checkpoint authority omits Prepared proof".into())
        })?;
        if &prepared.payload.grant.payload.source_authority != *prior {
            return Err(HomeError::Unauthorized(
                "checkpoint authorities do not form one exact custody lineage".into(),
            ));
        }
    }
    Ok(())
}

fn persist_imported_authorities(
    config: &HomeConfig,
    authorities: &[HomeAuthorityV1],
) -> Result<(), HomeError> {
    authority_map(authorities, &config.home)?;
    let record = ImportedAuthorityHistoryV1 {
        format: CHECKPOINT_FORMAT.into(),
        home: config.home.clone(),
        authorities: authorities.to_vec(),
    };
    let bytes = canonical_json_bytes(&record).map_err(super::invalid)?;
    if bytes.len() > MAX_AUTHORITY_HISTORY_BYTES {
        return Err(HomeError::Capacity(
            "imported authority history exceeds its bounded metadata cap".into(),
        ));
    }
    let path = config.root.join(IMPORTED_AUTHORITIES_FILE);
    if path.exists() {
        if bounded_read(&path, MAX_AUTHORITY_HISTORY_BYTES)? != bytes {
            return Err(HomeError::Conflict(
                "destination already contains a different imported authority history".into(),
            ));
        }
        return Ok(());
    }
    atomic_write(&config.root, &path, &bytes)
}

fn bounded_read(path: &Path, max: usize) -> Result<Vec<u8>, HomeError> {
    let mut file = File::open(path)
        .map_err(|error| HomeError::Invalid(format!("custody metadata I/O failed: {error}")))?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(max as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| HomeError::Invalid(format!("custody metadata I/O failed: {error}")))?;
    if bytes.len() > max {
        return Err(HomeError::Capacity("custody metadata exceeds its configured bound".into()));
    }
    Ok(bytes)
}

fn atomic_write(root: &Path, destination: &Path, bytes: &[u8]) -> Result<(), HomeError> {
    fs::create_dir_all(root)
        .map_err(|error| HomeError::Invalid(format!("custody metadata I/O failed: {error}")))?;
    let temporary = root.join(format!(
        ".{}.{}.tmp",
        destination.file_name().and_then(|name| name.to_str()).unwrap_or("custody"),
        std::process::id()
    ));
    {
        let mut file = File::create(&temporary)
            .map_err(|error| HomeError::Invalid(format!("custody metadata I/O failed: {error}")))?;
        file.write_all(bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| HomeError::Invalid(format!("custody metadata I/O failed: {error}")))?;
        check_durability_fault(DurabilityFaultPoint::AfterAtomicTempSync)?;
    }
    check_durability_fault(DurabilityFaultPoint::BeforeAtomicRename)?;
    fs::rename(&temporary, destination)
        .map_err(|error| HomeError::Invalid(format!("custody metadata I/O failed: {error}")))?;
    check_durability_fault(DurabilityFaultPoint::BeforeAtomicDirSync)?;
    File::open(root)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| HomeError::Invalid(format!("custody metadata I/O failed: {error}")))?;
    check_durability_fault(DurabilityFaultPoint::AfterAtomicDirSync)?;
    Ok(())
}

fn same_record<T: Serialize + Validate>(
    left: &SignedRecordV1<T>,
    right: &SignedRecordV1<T>,
) -> Result<bool, HomeError> {
    Ok(canonical_hash(left).map_err(super::invalid)?
        == canonical_hash(right).map_err(super::invalid)?)
}

fn verify_blob_bytes(blob: &gawdfn::BlobRefV1, bytes: &[u8]) -> Result<(), HomeError> {
    blob.validate().map_err(super::invalid)?;
    let actual = format!("sha256:{:x}", Sha256::digest(bytes));
    if blob.size != bytes.len() as u64 || blob.digest != actual {
        return Err(HomeError::Invalid(
            "checkpoint store returned bytes that do not match digest/size".into(),
        ));
    }
    Ok(())
}

/// Adapter used only while replaying a signed marker, where the public key is already known.
struct SignerView<'a>(&'a str);

impl AuthoritySigner for SignerView<'_> {
    fn public_key(&self) -> &str {
        self.0
    }

    fn sign(&self, _message: &[u8]) -> Result<String, gawdfn::ContractError> {
        Err(gawdfn::ContractError::Crypto("verification-only signer cannot sign".into()))
    }
}

/// Existing callers can open a non-migrating Home without accidentally gaining an implicit
/// checkpoint store. Custody calls fail explicitly until an implementation is injected.
pub(super) struct UnavailableCheckpointStore;

impl gawdfn::BlobAvailability for UnavailableCheckpointStore {
    fn verify_available(&self, _blob: &gawdfn::BlobRefV1) -> Result<(), gawdfn::ContractError> {
        Err(gawdfn::ContractError::Invalid("no checkpoint blob store is configured".into()))
    }
}

impl CheckpointBlobStore for UnavailableCheckpointStore {
    fn put_checkpoint(
        &self,
        _media_type: &str,
        _bytes: &[u8],
    ) -> Result<gawdfn::BlobRefV1, gawdfn::ContractError> {
        Err(gawdfn::ContractError::Invalid("no checkpoint blob store is configured".into()))
    }

    fn get_checkpoint(&self, _blob: &gawdfn::BlobRefV1) -> Result<Vec<u8>, gawdfn::ContractError> {
        Err(gawdfn::ContractError::Invalid("no checkpoint blob store is configured".into()))
    }
}
