//! `bestiary-daemon` — the durable Bestiary creature.
//!
//! Binds an injected [`BestiaryStore`] + [`Curator`] to `Role::REGISTRY`. It serves every existing
//! `RegistryOp` **byte-identically** to `registry-mem` (so any creature consulting REGISTRY over the
//! bus is served unchanged), while adding durability, an additive `bestiary.op` schema
//! ([`BestiaryOp`]: `ProveEntry` / `Compact` / `PushEntries`), off-drain AI curation, and
//! monotonic-lattice PUSH replication. `registry-mem` stays the in-memory stub for the same role; a
//! test or demo picks one by which `Box<dyn Creature>` it loads.
//!
//! ## Construction is injection-only
//!
//! There is no `declare_creature!` / `Default`: the store and curator are *injected* via
//! [`BestiaryDaemon::new`], so the daemon is loaded in-process (`kernel.load_instance`) like every
//! other policy-bearing organ — never shipped as a `.so` (a default store/curator would silently
//! substitute for the operator's real ones, exactly the hazard the model-author avoids).
//!
//! ## Threading (the transport-tcp discipline)
//!
//! `bind` calls [`BestiaryStore::recover`] and spawns **one** maintenance worker: it owns an
//! `AtomicBool` stop flag + a joined `JoinHandle`, captures the `Arc<dyn Bus>`, and on its own cadence
//! (a) consults the curator **off the drain thread** (the model call never blocks `handle`) then
//! compacts, and (b) PUSHes the local catalog to configured peers. `shutdown` sets stop, flushes the
//! store, and joins the worker. `handle` itself stays synchronous and fast — it touches only the store
//! (no model calls, no blocking I/O beyond the local fs the store already owns).
//!
//! ## Scoping notes (deliberate, recorded)
//!
//! - **Cross-node reputation federates over PUSH's verified-greater merge**, not a direct
//!   SEER-`Consensus` ingest. The `ReputationDelta` consensus body lives inside the `omega-federator`
//!   *creature*; a contract crate (this daemon) cannot reach it without a creature→creature edge.
//!   Hoisting it to a contract crate is deferred (the same family as the deferred policy
//!   generalization); the `omega-federator` keeps owning the cross-Realm SEER reputation path
//!   unchanged, and local reputation still flows via `AttestFitness` over REGISTRY.
//! - **The PUSH is a bounded full live-set push each cadence, not a head diff.** The lattice merge is
//!   idempotent, so a full push converges; the daemon refuses over-cap snapshots before reading blob
//!   bytes or serializing the batch. A high-volume Bestiary would diff by log head.
//! - **A refused snapshot is observable, not silent.** When the live set outgrows
//!   [`BestiaryConfig::max_snapshot_artifact_bytes`] the daemon skips that cadence's PUSH and curation
//!   `observe` pass (fail-closed) and publishes a [`MaintenanceStallEvent`] on
//!   [`Topic::PROPRIOCEPTION`], so a long-lived node that has grown past its cap surfaces a steady bus
//!   signal — for a monitor, the immune system, or an operator — rather than ceasing to replicate
//!   behind only a stderr line. Recovery is operator action: raise the cap or set it to `0`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, NodeId, Outcome,
    Topic,
};
use bestiary::{
    artifact_hash_shape_error, bestiary_op_too_large_message, registry_artifact_too_large_message,
    registry_op_too_large_message, BestiaryOp, BestiaryReply, BestiaryStore, CurationContext,
    Curator, QuarantineNotice, RegistryOp, RegistryReply, ReputationScore, BESTIARY_OP_SCHEMA,
    BESTIARY_REPLY_SCHEMA, DEFAULT_MAX_BESTIARY_ENTRIES, MAX_BESTIARY_OP_BYTES,
    MAX_REGISTRY_ARTIFACT_BYTES, MAX_REGISTRY_OP_BYTES, REGISTRY_REPLY_SCHEMA,
};
use serde::{Deserialize, Serialize};
use sigil::RealmId;

/// Default maximum number of self-verifying entries accepted in one `PushEntries` batch. A normal
/// full push can include live entries plus tombstones, so allow twice the default live catalog cap.
/// `0` in [`BestiaryConfig::max_push_entries`] means unbounded.
pub const DEFAULT_MAX_PUSH_ENTRIES: usize = DEFAULT_MAX_BESTIARY_ENTRIES * 2;

/// Default total artifact bytes read into one anti-entropy snapshot.
///
/// This mirrors `registry-mem`'s source-side snapshot cap: full fetches can still return one large
/// artifact, but a catalog-wide pull, PUSH, or curation pass cannot force the daemon to clone the
/// whole live set into one payload. `0` in [`BestiaryConfig::max_snapshot_artifact_bytes`] means
/// unbounded.
pub const DEFAULT_MAX_SNAPSHOT_ARTIFACT_BYTES: usize = MAX_REGISTRY_ARTIFACT_BYTES;

/// Default maximum replication peers retained by the daemon config.
pub const DEFAULT_MAX_REPLICATION_PEERS: usize = 1024;
/// Maximum bytes in a replication peer node id.
pub const MAX_BESTIARY_REPLICATION_NODE_ID_BYTES: usize = 256;
/// Maximum bytes in a replication Realm selector.
pub const MAX_BESTIARY_REPLICATION_REALM_BYTES: usize = sigil::MAX_MANIFEST_REALM_BYTES;

/// Schema for [`MaintenanceStallEvent`], published on [`Topic::PROPRIOCEPTION`].
pub const BESTIARY_MAINTENANCE_STALL_SCHEMA: &str = "bestiary_maintenance_stall";

/// An off-drain maintenance pass was **refused** this cadence and made no progress.
///
/// The common cause is a live set whose total artifact bytes exceed
/// [`BestiaryConfig::max_snapshot_artifact_bytes`]: the daemon refuses the snapshot *before* cloning
/// the whole catalog into one payload (the deliberate fail-closed bound), so an over-cap node skips
/// its anti-entropy PUSH and its curation `observe` pass each cadence. That stall persists — and
/// anti-entropy/GC stop converging — until the operator raises the cap or sets it to `0` to opt out.
///
/// Publishing it on the proprioception topic makes the stall **observable on the substrate's own
/// nervous system** (a monitor, an operator dashboard, the immune system) instead of being buried in
/// a stderr line a long-lived node's operator may never read. It is emitted once per refused pass
/// per cadence, so a node that has outgrown its cap surfaces a steady, visible signal rather than
/// silently ceasing to replicate.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaintenanceStallEvent {
    /// Which pass was refused: `"anti_entropy"`, `"curation"`, or `"compaction"`.
    pub stage: String,
    /// The store error that refused the pass (typically the snapshot byte/entry-cap message).
    pub reason: String,
    /// The peer this PUSH targeted, when `stage == "anti_entropy"` (`None` for catalog-wide passes).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer: Option<String>,
}

/// A peer this daemon PUSHes its catalog to.
#[derive(Clone, Debug)]
pub struct ReplicationPeer {
    /// The peer's node.
    pub node: NodeId,
    /// The peer's `bestiary-daemon` creature id on that node.
    pub daemon: CreatureId,
    /// Which Realm to push (`None` = all Realms).
    pub realm: Option<RealmId>,
}

/// Daemon configuration. Local scheduling intervals are fine in the daemon's own thread — that is how
/// `transport-tcp` polls; the "ships no clock" rule constrains the wire/contract, not local cadence.
#[derive(Clone, Debug)]
pub struct BestiaryConfig {
    /// PUSH cadence. `Duration::ZERO` disables autonomous replication (no peers / a single node).
    pub anti_entropy_interval: Duration,
    /// Curation+compaction cadence. `Duration::ZERO` disables autonomous compaction.
    pub compaction_interval: Duration,
    /// Peers to replicate to.
    pub replication_peers: Vec<ReplicationPeer>,
    /// Maximum serialized `registry.op` bytes decoded by this daemon. `0` means unbounded.
    pub max_registry_op_bytes: usize,
    /// Maximum serialized `bestiary.op` bytes decoded by this daemon. `0` means unbounded.
    pub max_bestiary_op_bytes: usize,
    /// Maximum artifact bytes retained per registry publish or pushed entry. `0` means unbounded.
    pub max_artifact_bytes: usize,
    /// Maximum total artifact bytes read into one `ListEntries` reply, autonomous PUSH batch, or
    /// curation snapshot. `0` means unbounded. When the live set exceeds this, the autonomous PUSH
    /// and curation passes are refused fail-closed and a [`MaintenanceStallEvent`] is published on
    /// [`Topic::PROPRIOCEPTION`] each cadence until an operator raises the cap or sets it to `0`.
    pub max_snapshot_artifact_bytes: usize,
    /// Maximum self-verifying entries accepted in or sent as one `PushEntries` batch. `0` means
    /// unbounded.
    pub max_push_entries: usize,
}

impl BestiaryConfig {
    /// A single-node config: no autonomous push or compaction (drive `Compact` over the bus instead).
    pub fn local() -> Self {
        BestiaryConfig {
            anti_entropy_interval: Duration::ZERO,
            compaction_interval: Duration::ZERO,
            replication_peers: Vec::new(),
            max_registry_op_bytes: MAX_REGISTRY_OP_BYTES,
            max_bestiary_op_bytes: MAX_BESTIARY_OP_BYTES,
            max_artifact_bytes: MAX_REGISTRY_ARTIFACT_BYTES,
            max_snapshot_artifact_bytes: DEFAULT_MAX_SNAPSHOT_ARTIFACT_BYTES,
            max_push_entries: DEFAULT_MAX_PUSH_ENTRIES,
        }
    }
}

fn sanitize_replication_peer_config(
    mut cfg: BestiaryConfig,
    max_replication_peers: usize,
) -> BestiaryConfig {
    cfg.replication_peers =
        retain_valid_replication_peers(cfg.replication_peers, max_replication_peers);
    cfg
}

fn retain_valid_replication_peers(
    peers: Vec<ReplicationPeer>,
    max_replication_peers: usize,
) -> Vec<ReplicationPeer> {
    let mut retained = Vec::new();
    for peer in peers {
        insert_replication_peer(&mut retained, peer, max_replication_peers);
    }
    retained
}

fn insert_replication_peer(
    retained: &mut Vec<ReplicationPeer>,
    peer: ReplicationPeer,
    max_replication_peers: usize,
) {
    if let Some(reason) = replication_peer_shape_error(&peer) {
        eprintln!("bestiary-daemon: {reason}");
        return;
    }
    if retained.iter().any(|existing| same_replication_peer(existing, &peer)) {
        return;
    }
    if max_replication_peers != 0 && retained.len() >= max_replication_peers {
        eprintln!(
            "bestiary-daemon: replication peer table at capacity ({max_replication_peers}); refusing peer {}",
            peer.node.0
        );
        return;
    }
    retained.push(peer);
}

fn replication_peer_shape_error(peer: &ReplicationPeer) -> Option<String> {
    if !node_id_shape_is_valid(&peer.node) {
        return Some(format!(
            "replication peer node must be 1..={MAX_BESTIARY_REPLICATION_NODE_ID_BYTES} ASCII [A-Za-z0-9._-] bytes"
        ));
    }
    if let Some(realm) = &peer.realm {
        if !realm.is_valid()
            || realm.0.len() > MAX_BESTIARY_REPLICATION_REALM_BYTES
            || realm.0.contains('\0')
        {
            return Some(format!(
                "replication peer realm must be valid, NUL-free, and <= {MAX_BESTIARY_REPLICATION_REALM_BYTES} bytes"
            ));
        }
    }
    None
}

fn node_id_shape_is_valid(node: &NodeId) -> bool {
    let s = node.0.as_str();
    !s.is_empty()
        && s.len() <= MAX_BESTIARY_REPLICATION_NODE_ID_BYTES
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn same_replication_peer(a: &ReplicationPeer, b: &ReplicationPeer) -> bool {
    a.node == b.node && a.daemon == b.daemon && a.realm == b.realm
}

/// The bits the maintenance worker needs — cloned out of the daemon at `bind`.
struct Shared {
    store: Arc<dyn BestiaryStore>,
    curator: Arc<dyn Curator>,
    cfg: BestiaryConfig,
    bus: Arc<dyn Bus>,
    me: CreatureId,
    stop: Arc<AtomicBool>,
}

struct GxChunkPull {
    artifact_hash: String,
    transfer_id: String,
    chunk_size: u32,
    chunk_index: u32,
}

/// The durable Bestiary creature.
pub struct BestiaryDaemon {
    store: Arc<dyn BestiaryStore>,
    curator: Arc<dyn Curator>,
    cfg: BestiaryConfig,
    stop: Arc<AtomicBool>,
    workers: Mutex<Vec<JoinHandle<()>>>,
}

impl BestiaryDaemon {
    /// Build a daemon over an injected store + curator. The store + curator carry every operator
    /// decision; the daemon is pure mechanism.
    pub fn new(
        store: Arc<dyn BestiaryStore>,
        curator: Arc<dyn Curator>,
        cfg: BestiaryConfig,
    ) -> Self {
        Self::new_with_peer_limit(store, curator, cfg, DEFAULT_MAX_REPLICATION_PEERS)
    }

    /// Build with an explicit replication-peer cap. `max_replication_peers == 0` disables the cap
    /// for lab/demo configurations.
    pub fn new_with_peer_limit(
        store: Arc<dyn BestiaryStore>,
        curator: Arc<dyn Curator>,
        cfg: BestiaryConfig,
        max_replication_peers: usize,
    ) -> Self {
        let cfg = sanitize_replication_peer_config(cfg, max_replication_peers);
        BestiaryDaemon {
            store,
            curator,
            cfg,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Mutex::new(Vec::new()),
        }
    }

    /// Number of retained replication peers after constructor sanitization.
    pub fn replication_peer_count(&self) -> usize {
        self.cfg.replication_peers.len()
    }

    // ---- registry.op (byte-identical to registry-mem) ----

    fn serve_registry(&mut self, env: &Envelope) -> Outcome {
        let reply = if self.cfg.max_registry_op_bytes != 0
            && env.payload.len() > self.cfg.max_registry_op_bytes
        {
            let message =
                registry_op_too_large_message(env.payload.len(), self.cfg.max_registry_op_bytes);
            eprintln!(
                "bestiary-daemon: rejected an oversized registry op from {:?} (corr={:?}): {message}",
                env.header.from, env.header.corr
            );
            RegistryReply::Error { message }
        } else {
            match serde_json::from_slice::<RegistryOp>(&env.payload) {
                Ok(RegistryOp::Publish { manifest, artifact, realm }) => {
                    let realm = realm.unwrap_or_else(RealmId::local);
                    if let Some(message) = self.artifact_too_large(artifact.len()) {
                        RegistryReply::Error { message }
                    } else {
                        match self.store.put(&realm, manifest, artifact) {
                            Ok(artifact_hash) => RegistryReply::Published { artifact_hash, realm },
                            Err(e) => RegistryReply::Error { message: e.to_string() },
                        }
                    }
                }
                Ok(RegistryOp::Fetch { artifact_hash, realm }) => {
                    self.fetched(&realm.unwrap_or_else(RealmId::local), &artifact_hash)
                }
                Ok(RegistryOp::FetchGx { artifact_hash, chunk_size }) => {
                    return self.fetch_gx_outcome(
                        env,
                        RealmId::local(),
                        artifact_hash,
                        chunk_size,
                        false,
                        true,
                    );
                }
                Ok(RegistryOp::FetchGxPlan { artifact_hash, chunk_size }) => {
                    return self.fetch_gx_outcome(
                        env,
                        RealmId::local(),
                        artifact_hash,
                        chunk_size,
                        false,
                        false,
                    );
                }
                Ok(RegistryOp::FetchGxChunk {
                    artifact_hash,
                    transfer_id,
                    chunk_size,
                    chunk_index,
                }) => {
                    return self.fetch_gx_chunk_outcome(
                        env,
                        RealmId::local(),
                        GxChunkPull { artifact_hash, transfer_id, chunk_size, chunk_index },
                    );
                }
                Ok(RegistryOp::FetchMetadata { artifact_hash, realm }) => {
                    self.fetched_metadata(&realm.unwrap_or_else(RealmId::local), &artifact_hash)
                }
                Ok(RegistryOp::FetchGxInRealm { artifact_hash, realm, chunk_size }) => {
                    return self.fetch_gx_outcome(
                        env,
                        realm,
                        artifact_hash,
                        chunk_size,
                        true,
                        true,
                    );
                }
                Ok(RegistryOp::FetchGxPlanInRealm { artifact_hash, realm, chunk_size }) => {
                    return self.fetch_gx_outcome(
                        env,
                        realm,
                        artifact_hash,
                        chunk_size,
                        true,
                        false,
                    );
                }
                Ok(RegistryOp::FetchGxChunkInRealm {
                    artifact_hash,
                    realm,
                    transfer_id,
                    chunk_size,
                    chunk_index,
                }) => {
                    return self.fetch_gx_chunk_outcome(
                        env,
                        realm,
                        GxChunkPull { artifact_hash, transfer_id, chunk_size, chunk_index },
                    );
                }
                Ok(RegistryOp::AttestFitness {
                    artifact_hash,
                    realm,
                    score,
                    attesting_realm,
                    signed_by,
                    signature,
                }) => {
                    let rep = ReputationScore { score, attesting_realm, signed_by, signature };
                    match self.store.attest(&realm, &artifact_hash, rep) {
                        Ok(true) => RegistryReply::Attested { artifact_hash, realm },
                        Ok(false) => {
                            eprintln!(
                            "bestiary-daemon: AttestFitness dropped — no entry for {artifact_hash} in realm {}",
                            realm.0
                        );
                            RegistryReply::NotFound
                        }
                        Err(e) => RegistryReply::Error { message: e.to_string() },
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
                            "bestiary-daemon: rejected MarkQuarantine for {artifact_hash} in realm {}: {message}",
                            realm.0
                        );
                        return Outcome::send(
                            Dispatch::reply_to_env(
                                env,
                                RegistryReply::Error { message }.to_bytes(),
                            )
                            .with_schema(REGISTRY_REPLY_SCHEMA),
                        );
                    }
                    let notice = QuarantineNotice { reason, attesting_peers };
                    match self.store.quarantine(&realm, &artifact_hash, notice) {
                        Ok(true) => RegistryReply::Quarantined { artifact_hash, realm },
                        Ok(false) => {
                            eprintln!(
                            "bestiary-daemon: MarkQuarantine dropped — no entry for {artifact_hash} in realm {}",
                            realm.0
                        );
                            RegistryReply::NotFound
                        }
                        Err(e) => RegistryReply::Error { message: e.to_string() },
                    }
                }
                Ok(RegistryOp::ListEntries { realm }) => {
                    match self
                        .store
                        .list_bounded(realm.as_ref(), self.cfg.max_snapshot_artifact_bytes)
                    {
                        Ok(entries) => RegistryReply::Entries { entries },
                        Err(e) => RegistryReply::Error { message: e.to_string() },
                    }
                }
                Ok(RegistryOp::ListMetadata { realm }) => {
                    match self.store.list_metadata(realm.as_ref()) {
                        Ok(entries) => RegistryReply::Metadata { entries },
                        Err(e) => RegistryReply::Error { message: e.to_string() },
                    }
                }
                Err(e) => {
                    eprintln!(
                    "bestiary-daemon: rejected a malformed registry op from {:?} (corr={:?}, {} bytes): {e}",
                    env.header.from,
                    env.header.corr,
                    env.payload.len()
                );
                    RegistryReply::Error { message: format!("malformed registry op: {e}") }
                }
            }
        };
        Outcome::send(
            Dispatch::reply_to_env(env, reply.to_bytes()).with_schema(REGISTRY_REPLY_SCHEMA),
        )
    }

    fn artifact_too_large(&self, len: usize) -> Option<String> {
        if self.cfg.max_artifact_bytes != 0 && len > self.cfg.max_artifact_bytes {
            Some(registry_artifact_too_large_message(len, self.cfg.max_artifact_bytes))
        } else {
            None
        }
    }

    fn fetched(&self, realm: &RealmId, artifact_hash: &str) -> RegistryReply {
        if let Some(message) = artifact_hash_shape_error(artifact_hash) {
            return RegistryReply::Error { message };
        }
        match self.store.get(realm, artifact_hash) {
            Ok(Some(entry)) => RegistryReply::Fetched {
                manifest: entry.manifest,
                artifact: entry.artifact,
                realm: realm.clone(),
            },
            Ok(None) => RegistryReply::NotFound,
            Err(e) => RegistryReply::Error { message: e.to_string() },
        }
    }

    fn fetch_gx_outcome(
        &self,
        env: &Envelope,
        realm: RealmId,
        artifact_hash: String,
        chunk_size: Option<u32>,
        include_realm: bool,
        push_chunks: bool,
    ) -> Outcome {
        if let Some(message) = artifact_hash_shape_error(&artifact_hash) {
            return Outcome::send(
                Dispatch::reply_to_env(env, RegistryReply::Error { message }.to_bytes())
                    .with_schema(REGISTRY_REPLY_SCHEMA),
            );
        }
        let chunk_size = if push_chunks {
            registry_gx_push_chunk_size(chunk_size)
        } else {
            registry_gx_chunk_size(chunk_size)
        };
        let (manifest, artifact_len, artifact) = if push_chunks {
            match self.store.get(&realm, &artifact_hash) {
                Ok(Some(entry)) => {
                    let artifact_len = entry.artifact.len();
                    (entry.manifest, artifact_len, Some(entry.artifact))
                }
                Ok(None) => {
                    return Outcome::send(
                        Dispatch::reply_to_env(env, RegistryReply::NotFound.to_bytes())
                            .with_schema(REGISTRY_REPLY_SCHEMA),
                    );
                }
                Err(e) => {
                    return Outcome::send(
                        Dispatch::reply_to_env(
                            env,
                            RegistryReply::Error { message: e.to_string() }.to_bytes(),
                        )
                        .with_schema(REGISTRY_REPLY_SCHEMA),
                    );
                }
            }
        } else {
            match self.store.get_fetch_metadata(&realm, &artifact_hash) {
                Ok(Some((entry, artifact_len))) => (entry.manifest, artifact_len, None),
                Ok(None) => {
                    return Outcome::send(
                        Dispatch::reply_to_env(env, RegistryReply::NotFound.to_bytes())
                            .with_schema(REGISTRY_REPLY_SCHEMA),
                    );
                }
                Err(e) => {
                    return Outcome::send(
                        Dispatch::reply_to_env(
                            env,
                            RegistryReply::Error { message: e.to_string() }.to_bytes(),
                        )
                        .with_schema(REGISTRY_REPLY_SCHEMA),
                    );
                }
            }
        };
        let transfer_id = registry_gx_transfer_id(&artifact_hash, chunk_size, env);
        let plan = match gawdxfer::TransferPlan::new(
            &transfer_id,
            artifact_len as u64,
            &artifact_hash,
            chunk_size,
        ) {
            Ok(plan) => plan,
            Err(e) => {
                return Outcome::send(
                    Dispatch::reply_to_env(
                        env,
                        RegistryReply::Error { message: format!("GX fetch refused: {e}") }
                            .to_bytes(),
                    )
                    .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
        };

        let reply = if include_realm {
            RegistryReply::FetchedGxInRealm {
                manifest: manifest.clone(),
                artifact_hash,
                transfer_id: plan.transfer_id.clone(),
                file_size: plan.file_size,
                file_hash: plan.file_hash.clone(),
                chunk_size: plan.chunk_size,
                total_chunks: plan.total_chunks,
                realm,
            }
        } else {
            RegistryReply::FetchedGx {
                manifest,
                artifact_hash,
                transfer_id: plan.transfer_id.clone(),
                file_size: plan.file_size,
                file_hash: plan.file_hash.clone(),
                chunk_size: plan.chunk_size,
                total_chunks: plan.total_chunks,
            }
        };

        let mut out = Outcome::send(
            Dispatch::reply_to_env(env, reply.to_bytes()).with_schema(REGISTRY_REPLY_SCHEMA),
        );
        if !push_chunks {
            return out;
        }
        let Some(artifact) = artifact else {
            return out;
        };
        let target = env.reply_target();
        for chunk_index in 0..plan.total_chunks {
            match plan.encode_chunk(&artifact, chunk_index) {
                Ok(frame) => {
                    let mut dispatch = Dispatch::to(target.clone(), frame)
                        .with_schema(gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA);
                    if let Some(corr) = env.header.corr {
                        dispatch = dispatch.with_corr(corr);
                    }
                    out.push(dispatch);
                }
                Err(e) => {
                    return Outcome::send(
                        Dispatch::reply_to_env(
                            env,
                            RegistryReply::Error {
                                message: format!("GX fetch chunk encode failed: {e}"),
                            }
                            .to_bytes(),
                        )
                        .with_schema(REGISTRY_REPLY_SCHEMA),
                    );
                }
            }
        }
        out
    }

    fn fetch_gx_chunk_outcome(&self, env: &Envelope, realm: RealmId, pull: GxChunkPull) -> Outcome {
        if let Some(message) = artifact_hash_shape_error(&pull.artifact_hash) {
            return Outcome::send(
                Dispatch::reply_to_env(env, RegistryReply::Error { message }.to_bytes())
                    .with_schema(REGISTRY_REPLY_SCHEMA),
            );
        }
        if let Some(message) = registry_gx_pull_shape_error(&pull) {
            return Outcome::send(
                Dispatch::reply_to_env(env, RegistryReply::Error { message }.to_bytes())
                    .with_schema(REGISTRY_REPLY_SCHEMA),
            );
        }
        let artifact_len = match self.store.get_fetch_metadata(&realm, &pull.artifact_hash) {
            Ok(Some((_entry, artifact_len))) => artifact_len,
            Ok(None) => {
                return Outcome::send(
                    Dispatch::reply_to_env(env, RegistryReply::NotFound.to_bytes())
                        .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
            Err(e) => {
                return Outcome::send(
                    Dispatch::reply_to_env(
                        env,
                        RegistryReply::Error { message: e.to_string() }.to_bytes(),
                    )
                    .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
        };
        let chunk_size = registry_gx_chunk_size(Some(pull.chunk_size));
        let plan = match gawdxfer::TransferPlan::new(
            pull.transfer_id,
            artifact_len as u64,
            pull.artifact_hash.clone(),
            chunk_size,
        ) {
            Ok(plan) => plan,
            Err(e) => {
                return Outcome::send(
                    Dispatch::reply_to_env(
                        env,
                        RegistryReply::Error { message: format!("GX chunk refused: {e}") }
                            .to_bytes(),
                    )
                    .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
        };
        let range = match plan.chunk_bounds(pull.chunk_index) {
            Ok(range) => range,
            Err(e) => {
                return Outcome::send(
                    Dispatch::reply_to_env(
                        env,
                        RegistryReply::Error { message: format!("GX chunk refused: {e}") }
                            .to_bytes(),
                    )
                    .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
        };
        let payload = match self.store.get_artifact_chunk(
            &realm,
            &pull.artifact_hash,
            range.start as u64,
            range.len(),
        ) {
            Ok(Some(payload)) => payload,
            Ok(None) => {
                return Outcome::send(
                    Dispatch::reply_to_env(env, RegistryReply::NotFound.to_bytes())
                        .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
            Err(e) => {
                return Outcome::send(
                    Dispatch::reply_to_env(
                        env,
                        RegistryReply::Error { message: e.to_string() }.to_bytes(),
                    )
                    .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
        };
        let header = gawdxfer::ChunkFrameHeader::new(
            plan.transfer_id.clone(),
            pull.chunk_index,
            gawdxfer::hash_bytes(&payload),
        )
        .with_total_chunks(plan.total_chunks);
        let frame = match gawdxfer::encode_binary_frame(&header, &payload) {
            Ok(frame) => frame,
            Err(e) => {
                return Outcome::send(
                    Dispatch::reply_to_env(
                        env,
                        RegistryReply::Error { message: format!("GX chunk encode failed: {e}") }
                            .to_bytes(),
                    )
                    .with_schema(REGISTRY_REPLY_SCHEMA),
                );
            }
        };
        let mut dispatch = Dispatch::to(env.reply_target(), frame)
            .with_schema(gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA);
        if let Some(corr) = env.header.corr {
            dispatch = dispatch.with_corr(corr);
        }
        Outcome::send(dispatch)
    }

    fn fetched_metadata(&self, realm: &RealmId, artifact_hash: &str) -> RegistryReply {
        if let Some(message) = artifact_hash_shape_error(artifact_hash) {
            return RegistryReply::Error { message };
        }
        match self.store.get_metadata(realm, artifact_hash) {
            Ok(Some((entry, artifact_len))) => {
                RegistryReply::FetchedMetadata { entry, artifact_len }
            }
            Ok(None) => RegistryReply::NotFound,
            Err(e) => RegistryReply::Error { message: e.to_string() },
        }
    }

    // ---- bestiary.op (the additive durable-Bestiary surface) ----

    fn serve_bestiary(&mut self, env: &Envelope) -> Outcome {
        let reply = if self.cfg.max_bestiary_op_bytes != 0
            && env.payload.len() > self.cfg.max_bestiary_op_bytes
        {
            let message =
                bestiary_op_too_large_message(env.payload.len(), self.cfg.max_bestiary_op_bytes);
            eprintln!(
                "bestiary-daemon: rejected an oversized bestiary op from {:?} (corr={:?}): {message}",
                env.header.from, env.header.corr
            );
            BestiaryReply::Error { message }
        } else {
            match serde_json::from_slice::<BestiaryOp>(&env.payload) {
                Ok(BestiaryOp::ProveEntry { artifact_hash, realm }) => {
                    match self.store.prove(&realm, &artifact_hash) {
                        Ok(Some(proof)) => BestiaryReply::EntryProof { proof },
                        Ok(None) => BestiaryReply::NotFound,
                        Err(e) => BestiaryReply::Error { message: e.to_string() },
                    }
                }
                Ok(BestiaryOp::Compact) => {
                    // Uses the curator's `decide` (fast / cache / deterministic) — the model-call
                    // `observe` pass runs only on the off-drain worker, never here on the drain thread.
                    match self.store.compact(&*self.curator) {
                        Ok(s) => BestiaryReply::Compacted {
                            scanned: s.scanned,
                            gc: s.gc,
                            quarantined: s.quarantined,
                            blobs_removed: s.blobs_removed,
                        },
                        Err(e) => BestiaryReply::Error { message: e.to_string() },
                    }
                }
                Ok(BestiaryOp::PushEntries { entries }) => {
                    if self.cfg.max_push_entries != 0 && entries.len() > self.cfg.max_push_entries {
                        BestiaryReply::Error {
                            message: bestiary_push_too_many_entries_message(
                                entries.len(),
                                self.cfg.max_push_entries,
                            ),
                        }
                    } else {
                        let (mut accepted, mut rejected) = (0usize, 0usize);
                        for entry in entries {
                            if let Some(sync) = &entry.sync {
                                if let Some(message) = self.artifact_too_large(sync.artifact.len())
                                {
                                    rejected += 1;
                                    eprintln!(
                                        "bestiary-daemon: rejected a pushed entry: {message}"
                                    );
                                    continue;
                                }
                            }
                            match self.store.merge_push(entry) {
                                Ok(_) => accepted += 1,
                                Err(e) => {
                                    rejected += 1;
                                    eprintln!("bestiary-daemon: rejected a pushed entry: {e}");
                                }
                            }
                        }
                        BestiaryReply::PushAck { accepted, rejected }
                    }
                }
                Err(e) => BestiaryReply::Error { message: format!("malformed bestiary op: {e}") },
            }
        };
        Outcome::send(
            Dispatch::reply_to_env(env, reply.to_bytes()).with_schema(BESTIARY_REPLY_SCHEMA),
        )
    }
}

fn bestiary_push_too_many_entries_message(len: usize, limit: usize) -> String {
    format!("bestiary push batch too large: {len} entries (limit {limit})")
}

impl Creature for BestiaryDaemon {
    fn bind(&mut self, ctx: CreatureCtx) {
        match self.store.recover() {
            Ok(n) => eprintln!("bestiary-daemon: recovered {n} log record(s) at bind"),
            Err(e) => eprintln!("bestiary-daemon: recover failed at bind ({e}); serving empty"),
        }
        let shared = Shared {
            store: self.store.clone(),
            curator: self.curator.clone(),
            cfg: self.cfg.clone(),
            bus: ctx.bus,
            me: ctx.me,
            stop: self.stop.clone(),
        };
        match Builder::new()
            .name("bestiary-maintenance".into())
            .spawn(move || maintenance_loop(shared))
        {
            Ok(h) => self.workers.lock().unwrap_or_else(|p| p.into_inner()).push(h),
            Err(e) => eprintln!("bestiary-daemon: failed to spawn maintenance worker: {e}"),
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema == BESTIARY_OP_SCHEMA {
            self.serve_bestiary(&env)
        } else {
            // registry.op (and anything else carrying a RegistryOp payload) — byte-identical to
            // registry-mem, including the malformed→Error path.
            self.serve_registry(&env)
        }
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        self.stop.store(true, Ordering::Relaxed);
        if let Err(e) = self.store.flush() {
            eprintln!("bestiary-daemon: flush at shutdown failed: {e}");
        }
        // The worker polls `stop` every tick, so a plain join returns within ~one poll. `_deadline`
        // is advisory (favoring a clean join — no leaked threads — over a hard cutoff).
        let handles: Vec<JoinHandle<()>> =
            self.workers.lock().unwrap_or_else(|p| p.into_inner()).drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

/// The single off-drain maintenance worker: curate+compact and PUSH on their cadences, polling `stop`.
fn maintenance_loop(shared: Shared) {
    const POLL: Duration = Duration::from_millis(50);
    let mut last_push = Instant::now();
    let mut last_compact = Instant::now();
    loop {
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(POLL);
        if shared.stop.load(Ordering::Relaxed) {
            break;
        }
        let now = Instant::now();
        if shared.cfg.compaction_interval > Duration::ZERO
            && now.duration_since(last_compact) >= shared.cfg.compaction_interval
        {
            curate_and_compact(&shared);
            last_compact = Instant::now();
        }
        if shared.cfg.anti_entropy_interval > Duration::ZERO
            && now.duration_since(last_push) >= shared.cfg.anti_entropy_interval
        {
            push_once(&shared);
            last_push = Instant::now();
        }
    }
}

/// Off-drain curation: consult the curator (its blocking model call runs here, never in `handle`),
/// then compact.
fn curate_and_compact(shared: &Shared) {
    match shared.store.snapshot_for_curation_bounded(shared.cfg.max_snapshot_artifact_bytes) {
        Ok(snaps) => {
            for snap in &snaps {
                let ctx = CurationContext {
                    realm: &snap.realm,
                    artifact_hash: &snap.artifact_hash,
                    entry: &snap.entry,
                    first_seen: snap.first_seen,
                    head_first_seen: snap.head_first_seen,
                };
                shared.curator.observe(&ctx);
            }
        }
        Err(e) => {
            let reason = e.to_string();
            eprintln!("bestiary-daemon: curation snapshot failed: {reason}");
            publish_maintenance_stall(shared, "curation", &reason, None);
        }
    }
    if let Err(e) = shared.store.compact(&*shared.curator) {
        let reason = e.to_string();
        eprintln!("bestiary-daemon: compaction failed: {reason}");
        publish_maintenance_stall(shared, "compaction", &reason, None);
    }
}

/// Surface a refused maintenance pass on the proprioception topic so the stall is observable on the
/// bus (a monitor/operator/immune creature), not only in stderr. Emitted off the drain thread, after
/// the store lock has been released by the failing call — never holds a lock across `emit`.
fn publish_maintenance_stall(shared: &Shared, stage: &str, reason: &str, peer: Option<&NodeId>) {
    let ev = MaintenanceStallEvent {
        stage: stage.to_string(),
        reason: reason.to_string(),
        peer: peer.map(|p| p.0.clone()),
    };
    let dispatch = Dispatch::to(
        Address::Topic(Topic::new(Topic::PROPRIOCEPTION)),
        aether::wire::to_bytes(&ev),
    )
    .with_schema(BESTIARY_MAINTENANCE_STALL_SCHEMA);
    // Best-effort, exactly like `transport-tcp`'s `publish_peer_event`: the stall is already on stderr
    // at the call site, so a topic with no subscriber (the common single-node case) is not worth a
    // second line every cadence.
    let _ = shared.bus.emit(dispatch);
}

/// PUSH the local catalog to every configured peer (full live set + tombstones; the merge is
/// idempotent, so a full push converges).
fn push_once(shared: &Shared) {
    for peer in &shared.cfg.replication_peers {
        let entries = match shared.store.signed_entries_bounded(
            peer.realm.as_ref(),
            shared.cfg.max_snapshot_artifact_bytes,
            shared.cfg.max_push_entries,
        ) {
            Ok(e) => e,
            Err(e) => {
                let reason = e.to_string();
                eprintln!("bestiary-daemon: bounded signed_entries for push failed: {reason}");
                publish_maintenance_stall(shared, "anti_entropy", &reason, Some(&peer.node));
                continue;
            }
        };
        if entries.is_empty() {
            continue;
        }
        let op = BestiaryOp::PushEntries { entries };
        let dispatch = Dispatch::to(Address::Node(peer.node.clone(), peer.daemon), op.to_bytes())
            .with_schema(BESTIARY_OP_SCHEMA);
        if let Err(e) = shared.bus.emit(dispatch) {
            // A peer that is briefly unreachable is normal (the next tick retries); other errors are
            // worth a line. `me` is captured for the log context.
            if !e.is_unreachable() {
                eprintln!("bestiary-daemon[{:?}]: push to {:?} failed: {e}", shared.me, peer.node);
            }
        }
    }
}

fn registry_gx_transfer_id(artifact_hash: &str, chunk_size: u32, env: &Envelope) -> String {
    let corr = env.header.corr.unwrap_or(0);
    gawdxfer::registry_transfer_id(artifact_hash, chunk_size, env.header.seq, corr)
}

fn registry_gx_chunk_size(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(gawdxfer::DEFAULT_CHUNK_SIZE)
        .clamp(gawdxfer::MIN_CHUNK_SIZE, gawdxfer::MAX_CHUNK_SIZE)
}

fn registry_gx_push_chunk_size(requested: Option<u32>) -> u32 {
    requested
        .unwrap_or(gawdxfer::DEFAULT_CHUNK_SIZE)
        .clamp(gawdxfer::DEFAULT_CHUNK_SIZE, gawdxfer::MAX_CHUNK_SIZE)
}

fn registry_gx_pull_shape_error(pull: &GxChunkPull) -> Option<String> {
    gawdxfer::registry_transfer_id_shape_error(
        &pull.transfer_id,
        &pull.artifact_hash,
        pull.chunk_size,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(node: &str, daemon: u64, realm: Option<&str>) -> ReplicationPeer {
        ReplicationPeer {
            node: NodeId(node.into()),
            daemon: CreatureId(daemon),
            realm: realm.map(RealmId::new),
        }
    }

    #[test]
    fn replication_peers_are_sanitized_deduplicated_and_bounded() {
        let oversized_node = "n".repeat(MAX_BESTIARY_REPLICATION_NODE_ID_BYTES + 1);
        let oversized_realm = "r".repeat(MAX_BESTIARY_REPLICATION_REALM_BYTES + 1);
        let cfg = BestiaryConfig {
            replication_peers: vec![
                peer("node-a", 10, Some("local")),
                peer("node-a", 10, Some("local")),
                peer("bad node", 11, Some("local")),
                peer(&oversized_node, 12, Some("local")),
                peer("node-b", 13, Some("bad:realm")),
                peer("node-c", 14, Some("bad\0realm")),
                peer("node-d", 15, Some(&oversized_realm)),
                peer("node-e", 16, None),
            ],
            ..BestiaryConfig::local()
        };

        let cfg = sanitize_replication_peer_config(cfg, 1);

        assert_eq!(cfg.replication_peers.len(), 1);
        assert_eq!(cfg.replication_peers[0].node, NodeId("node-a".into()));
        assert_eq!(cfg.replication_peers[0].daemon, CreatureId(10));
        assert_eq!(cfg.replication_peers[0].realm, Some(RealmId::new("local")));
    }

    #[test]
    fn zero_replication_peer_limit_is_explicit_unbounded_opt_out() {
        let cfg = BestiaryConfig {
            replication_peers: vec![peer("node-a", 10, None), peer("node-b", 11, None)],
            ..BestiaryConfig::local()
        };

        let cfg = sanitize_replication_peer_config(cfg, 0);

        assert_eq!(cfg.replication_peers.len(), 2);
    }

    // ---- maintenance-stall observability -------------------------------------------------------

    use std::sync::atomic::AtomicU64;

    use aether::BusError;
    use bestiary::{BestiaryStore, DeterministicCurator, FsBestiaryStore};
    use sigil::{Backend, Ed25519KeyMaterial, Manifest};

    /// A `Bus` that records every emitted dispatch — enough to observe what a maintenance pass put on
    /// the proprioception topic.
    struct CapturingBus {
        emitted: Mutex<Vec<Dispatch>>,
    }
    impl Bus for CapturingBus {
        fn emit(&self, d: Dispatch) -> Result<(), BusError> {
            self.emitted.lock().unwrap_or_else(|p| p.into_inner()).push(d);
            Ok(())
        }
        fn whoami(&self) -> CreatureId {
            CreatureId(0)
        }
    }

    /// A self-cleaning temp dir (no external tempdir dep — same approach the store tests take).
    struct TempRoot(std::path::PathBuf);
    impl TempRoot {
        fn new(tag: &str) -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let n = N.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir()
                .join(format!("bestiary-daemon-{tag}-{}-{n}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            TempRoot(dir)
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn manifest(name: &str) -> Manifest {
        Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
    }

    fn registry_env(op: RegistryOp) -> Envelope {
        Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: Some(Address::Creature(CreatureId(1))),
                seq: 9,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(42),
                commitment: None,
                schema: "registry.op".into(),
                origin: None,
            },
            payload: op.to_bytes(),
        }
    }

    #[test]
    fn gx_chunk_size_policy_preserves_small_pull_chunks_but_bounds_push() {
        let small_valid = 64 * 1024;

        assert_eq!(registry_gx_chunk_size(Some(32)), gawdxfer::MIN_CHUNK_SIZE);
        assert_eq!(registry_gx_chunk_size(Some(small_valid)), small_valid);
        assert_eq!(
            registry_gx_chunk_size(Some(gawdxfer::MAX_CHUNK_SIZE + 1)),
            gawdxfer::MAX_CHUNK_SIZE
        );

        assert_eq!(registry_gx_push_chunk_size(Some(32)), gawdxfer::DEFAULT_CHUNK_SIZE);
        assert_eq!(registry_gx_push_chunk_size(Some(small_valid)), gawdxfer::DEFAULT_CHUNK_SIZE);
        assert_eq!(
            registry_gx_push_chunk_size(Some(gawdxfer::MAX_CHUNK_SIZE + 1)),
            gawdxfer::MAX_CHUNK_SIZE
        );
    }

    #[test]
    fn registry_fetch_gx_returns_plan_then_raw_chunk_dispatches() {
        let root = TempRoot::new("fetch-gx");
        let key = Ed25519KeyMaterial::from_seed([0x43; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let m = manifest("gx");
        let bytes = b"durable-gx-artifact".repeat(16);
        let hash = store.put(&RealmId::local(), m.clone(), bytes.clone()).unwrap();
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );

        let out = daemon.serve_registry(&registry_env(RegistryOp::FetchGx {
            artifact_hash: hash.clone(),
            chunk_size: Some(32),
        }));

        assert!(out.dispatches.len() > 1, "GX fetch returns an init reply plus chunks");
        let init: RegistryReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        let (manifest, transfer_id, file_size, file_hash, chunk_size, total_chunks) = match init {
            RegistryReply::FetchedGx {
                manifest,
                artifact_hash,
                transfer_id,
                file_size,
                file_hash,
                chunk_size,
                total_chunks,
            } => {
                assert_eq!(artifact_hash, hash);
                (manifest, transfer_id, file_size, file_hash, chunk_size, total_chunks)
            }
            other => panic!("expected FetchedGx, got {other:?}"),
        };
        assert_eq!(manifest, m);
        assert_eq!(file_hash, hash, "GX plan file_hash is the registry artifact key");
        assert_eq!(
            chunk_size,
            gawdxfer::DEFAULT_CHUNK_SIZE,
            "compatibility GX push clamps tiny chunks to the default to avoid dispatch floods"
        );
        let plan = gawdxfer::TransferPlan::new(transfer_id, file_size, file_hash, chunk_size)
            .expect("valid returned plan");
        assert_eq!(plan.total_chunks, total_chunks);

        let mut assembler = gawdxfer::ChunkAssembler::new(plan).expect("assembler");
        for dispatch in &out.dispatches[1..] {
            assert_eq!(dispatch.to, Address::Creature(CreatureId(1)));
            assert_eq!(dispatch.schema, gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA);
            assert_eq!(dispatch.corr, Some(42));
            assembler.accept_binary_frame(&dispatch.payload).expect("valid gx chunk");
        }
        assert_eq!(assembler.finish().expect("complete artifact"), bytes);
    }

    #[test]
    fn registry_fetch_gx_rejects_malformed_artifact_hash_before_lookup() {
        let root = TempRoot::new("fetch-gx-shape");
        let key = Ed25519KeyMaterial::from_seed([0x45; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );
        let bad_hash = "../escape".to_string();

        for op in [
            RegistryOp::FetchGx { artifact_hash: bad_hash.clone(), chunk_size: None },
            RegistryOp::FetchGxPlan { artifact_hash: bad_hash.clone(), chunk_size: None },
            RegistryOp::FetchGxChunk {
                artifact_hash: bad_hash.clone(),
                transfer_id: format!("registry.bad.{}.9.42", gawdxfer::DEFAULT_CHUNK_SIZE),
                chunk_size: gawdxfer::DEFAULT_CHUNK_SIZE,
                chunk_index: 0,
            },
        ] {
            let out = daemon.serve_registry(&registry_env(op));
            assert_eq!(out.dispatches.len(), 1);
            let reply: RegistryReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
            match reply {
                RegistryReply::Error { message } => {
                    assert!(message.contains("artifact_hash"), "{message}");
                    assert!(message.contains("64 lowercase hex"), "{message}");
                }
                other => panic!("expected malformed GX artifact_hash error, got {other:?}"),
            }
        }
    }

    #[test]
    fn registry_legacy_fetch_rejects_malformed_artifact_hash_before_lookup() {
        let root = TempRoot::new("fetch-shape");
        let key = Ed25519KeyMaterial::from_seed([0x4B; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );
        let bad_hash = "../escape".to_string();

        for op in [
            RegistryOp::Fetch { artifact_hash: bad_hash.clone(), realm: None },
            RegistryOp::FetchMetadata { artifact_hash: bad_hash.clone(), realm: None },
            RegistryOp::Fetch {
                artifact_hash: bad_hash.clone(),
                realm: Some(RealmId::new("crew")),
            },
            RegistryOp::FetchMetadata {
                artifact_hash: bad_hash.clone(),
                realm: Some(RealmId::new("crew")),
            },
        ] {
            let out = daemon.serve_registry(&registry_env(op));
            assert_eq!(out.dispatches.len(), 1);
            let reply: RegistryReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
            match reply {
                RegistryReply::Error { message } => {
                    assert!(message.contains("artifact_hash"), "{message}");
                    assert!(message.contains("64 lowercase hex"), "{message}");
                }
                other => {
                    panic!("expected malformed artifact_hash error before lookup, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn registry_fetch_gx_chunk_rejects_malformed_transfer_id_before_lookup() {
        let root = TempRoot::new("fetch-gx-xfer-shape");
        let key = Ed25519KeyMaterial::from_seed([0x46; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );

        let out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxChunk {
            artifact_hash: "a".repeat(bestiary::ARTIFACT_HASH_HEX_BYTES),
            transfer_id: "not printable".into(),
            chunk_size: gawdxfer::DEFAULT_CHUNK_SIZE,
            chunk_index: 0,
        }));

        assert_eq!(out.dispatches.len(), 1);
        let reply: RegistryReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("transfer_id"), "{message}");
                assert!(message.contains("printable ASCII"), "{message}");
            }
            other => panic!("expected malformed GX transfer_id error before lookup, got {other:?}"),
        }
    }

    #[test]
    fn registry_fetch_gx_chunk_rejects_transfer_id_for_another_artifact_before_lookup() {
        let root = TempRoot::new("fetch-gx-xfer-artifact");
        let key = Ed25519KeyMaterial::from_seed([0x47; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );
        let artifact_hash = "a".repeat(bestiary::ARTIFACT_HASH_HEX_BYTES);
        let other_hash = "b".repeat(bestiary::ARTIFACT_HASH_HEX_BYTES);

        let out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxChunk {
            artifact_hash,
            transfer_id: format!("registry.{other_hash}.{}.9.42", gawdxfer::DEFAULT_CHUNK_SIZE),
            chunk_size: gawdxfer::DEFAULT_CHUNK_SIZE,
            chunk_index: 0,
        }));

        assert_eq!(out.dispatches.len(), 1);
        let reply: RegistryReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("transfer_id"), "{message}");
                assert!(message.contains("artifact_hash"), "{message}");
            }
            other => {
                panic!("expected artifact-bound GX transfer_id error before lookup, got {other:?}")
            }
        }
    }

    #[test]
    fn registry_fetch_gx_chunk_rejects_transfer_id_for_another_chunk_size_before_lookup() {
        let root = TempRoot::new("fetch-gx-xfer-chunk-size");
        let key = Ed25519KeyMaterial::from_seed([0x49; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );
        let artifact_hash = "a".repeat(bestiary::ARTIFACT_HASH_HEX_BYTES);

        let out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxChunk {
            artifact_hash: artifact_hash.clone(),
            transfer_id: format!("registry.{artifact_hash}.1024.9.42"),
            chunk_size: gawdxfer::DEFAULT_CHUNK_SIZE,
            chunk_index: 0,
        }));

        assert_eq!(out.dispatches.len(), 1);
        let reply: RegistryReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("transfer_id"), "{message}");
                assert!(message.contains("chunk_size"), "{message}");
            }
            other => {
                panic!(
                    "expected chunk-size-bound GX transfer_id error before lookup, got {other:?}"
                )
            }
        }
    }

    #[test]
    fn registry_fetch_gx_chunk_rejects_non_issued_transfer_id_before_lookup() {
        let root = TempRoot::new("fetch-gx-xfer-issued");
        let key = Ed25519KeyMaterial::from_seed([0x48; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );
        let artifact_hash = "a".repeat(bestiary::ARTIFACT_HASH_HEX_BYTES);

        let out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxChunk {
            artifact_hash: artifact_hash.clone(),
            transfer_id: format!("registry.{artifact_hash}.not-decimal.9.42"),
            chunk_size: gawdxfer::DEFAULT_CHUNK_SIZE,
            chunk_index: 0,
        }));

        assert_eq!(out.dispatches.len(), 1);
        let reply: RegistryReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("transfer_id"), "{message}");
                assert!(message.contains("decimal"), "{message}");
            }
            other => {
                panic!("expected non-issued GX transfer_id error before lookup, got {other:?}")
            }
        }
    }

    #[test]
    fn registry_fetch_gx_refuses_over_cap_recovered_artifact_without_hiding_metadata() {
        let root = TempRoot::new("fetch-gx-over-cap");
        let realm = RealmId::local();
        let bytes = b"12345".to_vec();
        let hash;
        {
            let key = Ed25519KeyMaterial::from_seed([0x4A; 32]).unwrap();
            let writer = FsBestiaryStore::new(&root.0, key).unwrap();
            hash = writer.put(&realm, manifest("gx-over-cap"), bytes).unwrap();
        }

        let key = Ed25519KeyMaterial::from_seed([0x4A; 32]).unwrap();
        let store = FsBestiaryStore::new(&root.0, key).unwrap().with_max_artifact_bytes(4);
        store.recover().unwrap();
        let mut daemon = BestiaryDaemon::new(
            Arc::new(store),
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );

        let metadata_out = daemon.serve_registry(&registry_env(RegistryOp::FetchMetadata {
            artifact_hash: hash.clone(),
            realm: None,
        }));
        assert_eq!(metadata_out.dispatches.len(), 1);
        let metadata: RegistryReply =
            serde_json::from_slice(&metadata_out.dispatches[0].payload).unwrap();
        match metadata {
            RegistryReply::FetchedMetadata { entry, artifact_len } => {
                assert_eq!(entry.artifact_hash, hash);
                assert_eq!(artifact_len, 5, "metadata remains a byte-light catalog lookup");
            }
            other => panic!("expected metadata lookup to remain visible, got {other:?}"),
        }

        let plan_out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxPlan {
            artifact_hash: hash.clone(),
            chunk_size: None,
        }));
        assert_eq!(plan_out.dispatches.len(), 1);
        let plan_reply: RegistryReply =
            serde_json::from_slice(&plan_out.dispatches[0].payload).unwrap();
        match plan_reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("too large"), "{message}");
                assert!(message.contains("limit 4"), "{message}");
            }
            other => panic!("expected over-cap GX plan refusal, got {other:?}"),
        }

        let chunk_size = gawdxfer::DEFAULT_CHUNK_SIZE;
        let chunk_out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxChunk {
            artifact_hash: hash.clone(),
            transfer_id: format!("registry.{hash}.{chunk_size}.9.42"),
            chunk_size,
            chunk_index: 0,
        }));
        assert_eq!(chunk_out.dispatches.len(), 1);
        let chunk_reply: RegistryReply =
            serde_json::from_slice(&chunk_out.dispatches[0].payload).unwrap();
        match chunk_reply {
            RegistryReply::Error { message } => {
                assert!(message.contains("too large"), "{message}");
                assert!(message.contains("limit 4"), "{message}");
            }
            other => panic!("expected over-cap GX chunk refusal, got {other:?}"),
        }
    }

    #[test]
    fn registry_fetch_gx_plan_then_chunk_pull_reassembles_out_of_order() {
        let root = TempRoot::new("fetch-gx-pull");
        let key = Ed25519KeyMaterial::from_seed([0x44; 32]).unwrap();
        let store = Arc::new(FsBestiaryStore::new(&root.0, key).unwrap());
        let m = manifest("gx-pull");
        let requested_chunk_size = 64 * 1024;
        let bytes = vec![0xCD; requested_chunk_size as usize + 17];
        let hash = store.put(&RealmId::local(), m.clone(), bytes.clone()).unwrap();
        let mut daemon = BestiaryDaemon::new(
            store,
            Arc::new(DeterministicCurator::default()),
            BestiaryConfig::local(),
        );

        let plan_out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxPlan {
            artifact_hash: hash.clone(),
            chunk_size: Some(requested_chunk_size),
        }));

        assert_eq!(plan_out.dispatches.len(), 1, "plan-only fetch does not push chunks");
        let init: RegistryReply = serde_json::from_slice(&plan_out.dispatches[0].payload).unwrap();
        let (transfer_id, file_size, file_hash, chunk_size, total_chunks) = match init {
            RegistryReply::FetchedGx {
                manifest,
                artifact_hash,
                transfer_id,
                file_size,
                file_hash,
                chunk_size,
                total_chunks,
            } => {
                assert_eq!(manifest, m);
                assert_eq!(artifact_hash, hash);
                (transfer_id, file_size, file_hash, chunk_size, total_chunks)
            }
            other => panic!("expected FetchedGx plan, got {other:?}"),
        };
        assert_eq!(total_chunks, 2, "fixture spans multiple GX chunks");
        assert_eq!(
            chunk_size, requested_chunk_size,
            "registry preserves valid chunk sizes below the default"
        );
        assert_eq!(file_hash, hash, "GX plan file_hash is the registry artifact key");
        let plan = gawdxfer::TransferPlan::new(
            transfer_id.clone(),
            file_size,
            file_hash.clone(),
            chunk_size,
        )
        .expect("valid returned plan");
        let mut assembler = gawdxfer::ChunkAssembler::new(plan).expect("assembler");

        for chunk_index in (0..total_chunks).rev() {
            let chunk_out = daemon.serve_registry(&registry_env(RegistryOp::FetchGxChunk {
                artifact_hash: hash.clone(),
                transfer_id: transfer_id.clone(),
                chunk_size,
                chunk_index,
            }));
            assert_eq!(chunk_out.dispatches.len(), 1, "one request returns one raw GX chunk");
            let dispatch = &chunk_out.dispatches[0];
            assert_eq!(dispatch.to, Address::Creature(CreatureId(1)));
            assert_eq!(dispatch.schema, gawdxfer::TRANSPORT_GX_CHUNK_SCHEMA);
            assert_eq!(dispatch.corr, Some(42));
            assembler.accept_binary_frame(&dispatch.payload).expect("valid gx chunk");
        }

        assert_eq!(assembler.finish().expect("complete artifact"), bytes);
    }

    /// A daemon whose live set already exceeds its snapshot cap, wired to a capturing bus. Returns the
    /// `Shared` the maintenance free-functions take plus the bus to inspect.
    fn over_cap_shared(
        root: &TempRoot,
        peers: Vec<ReplicationPeer>,
    ) -> (Shared, Arc<CapturingBus>) {
        let key = Ed25519KeyMaterial::from_seed([0x42; 32]).unwrap();
        let store = FsBestiaryStore::new(&root.0, key).unwrap();
        let realm = RealmId::new("crew");
        // Two entries, 8 artifact bytes each: a snapshot cap of 4 refuses on the first blob.
        store.put(&realm, manifest("alpha"), b"AAAAAAAA".to_vec()).unwrap();
        store.put(&realm, manifest("beta"), b"BBBBBBBB".to_vec()).unwrap();
        let cfg = BestiaryConfig {
            replication_peers: peers,
            max_snapshot_artifact_bytes: 4,
            ..BestiaryConfig::local()
        };
        let bus = Arc::new(CapturingBus { emitted: Mutex::new(Vec::new()) });
        let shared = Shared {
            store: Arc::new(store),
            curator: Arc::new(DeterministicCurator::default()),
            cfg,
            bus: bus.clone(),
            me: CreatureId(7),
            stop: Arc::new(AtomicBool::new(false)),
        };
        (shared, bus)
    }

    fn stall_events(bus: &CapturingBus) -> Vec<MaintenanceStallEvent> {
        bus.emitted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .filter(|d| {
                matches!(&d.to, Address::Topic(t) if t.0 == Topic::PROPRIOCEPTION)
                    && d.schema == BESTIARY_MAINTENANCE_STALL_SCHEMA
            })
            .map(|d| serde_json::from_slice::<MaintenanceStallEvent>(&d.payload).unwrap())
            .collect()
    }

    #[test]
    fn over_cap_push_publishes_an_observable_anti_entropy_stall() {
        let root = TempRoot::new("push-stall");
        let (shared, bus) = over_cap_shared(&root, vec![peer("node-z", 9, Some("crew"))]);

        push_once(&shared);

        let events = stall_events(&bus);
        assert_eq!(events.len(), 1, "exactly one stall signal for the one over-cap peer");
        assert_eq!(events[0].stage, "anti_entropy");
        assert_eq!(events[0].peer.as_deref(), Some("node-z"));
        assert!(!events[0].reason.is_empty(), "the refusing store error is carried for operators");
    }

    #[test]
    fn over_cap_curation_publishes_an_observable_curation_stall() {
        let root = TempRoot::new("curation-stall");
        let (shared, bus) = over_cap_shared(&root, Vec::new());

        curate_and_compact(&shared);

        let events = stall_events(&bus);
        assert!(
            events.iter().any(|e| e.stage == "curation" && e.peer.is_none()),
            "the refused curation snapshot is surfaced on the proprioception topic, got {events:?}"
        );
    }
}
