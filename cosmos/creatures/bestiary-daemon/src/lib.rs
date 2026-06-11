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

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, NodeId, Outcome,
};
use bestiary::{
    bestiary_op_too_large_message, registry_artifact_too_large_message,
    registry_op_too_large_message, BestiaryOp, BestiaryReply, BestiaryStore, CurationContext,
    Curator, QuarantineNotice, RegistryOp, RegistryReply, ReputationScore, BESTIARY_OP_SCHEMA,
    BESTIARY_REPLY_SCHEMA, DEFAULT_MAX_BESTIARY_ENTRIES, MAX_BESTIARY_OP_BYTES,
    MAX_REGISTRY_ARTIFACT_BYTES, MAX_REGISTRY_OP_BYTES, REGISTRY_REPLY_SCHEMA,
};
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
    /// curation snapshot. `0` means unbounded.
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
                Ok(RegistryOp::Publish { manifest, artifact }) => {
                    if let Some(message) = self.artifact_too_large(artifact.len()) {
                        RegistryReply::Error { message }
                    } else {
                        match self.store.put(&RealmId::local(), manifest, artifact) {
                            Ok(artifact_hash) => RegistryReply::Published { artifact_hash },
                            Err(e) => RegistryReply::Error { message: e.to_string() },
                        }
                    }
                }
                Ok(RegistryOp::Fetch { artifact_hash }) => {
                    self.fetched(&RealmId::local(), &artifact_hash)
                }
                Ok(RegistryOp::FetchMetadata { artifact_hash }) => {
                    self.fetched_metadata(&RealmId::local(), &artifact_hash)
                }
                Ok(RegistryOp::PublishInRealm { manifest, artifact, realm }) => {
                    if let Some(message) = self.artifact_too_large(artifact.len()) {
                        RegistryReply::Error { message }
                    } else {
                        match self.store.put(&realm, manifest, artifact) {
                            Ok(artifact_hash) => {
                                RegistryReply::PublishedInRealm { artifact_hash, realm }
                            }
                            Err(e) => RegistryReply::Error { message: e.to_string() },
                        }
                    }
                }
                Ok(RegistryOp::FetchInRealm { artifact_hash, realm }) => {
                    let r = realm.clone();
                    match self.store.get(&realm, &artifact_hash) {
                        Ok(Some(entry)) => RegistryReply::FetchedInRealm {
                            manifest: entry.manifest,
                            artifact: entry.artifact,
                            realm: r,
                        },
                        Ok(None) => RegistryReply::NotFound,
                        Err(e) => RegistryReply::Error { message: e.to_string() },
                    }
                }
                Ok(RegistryOp::FetchMetadataInRealm { artifact_hash, realm }) => {
                    self.fetched_metadata(&realm, &artifact_hash)
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
        match self.store.get(realm, artifact_hash) {
            Ok(Some(entry)) => {
                RegistryReply::Fetched { manifest: entry.manifest, artifact: entry.artifact }
            }
            Ok(None) => RegistryReply::NotFound,
            Err(e) => RegistryReply::Error { message: e.to_string() },
        }
    }

    fn fetched_metadata(&self, realm: &RealmId, artifact_hash: &str) -> RegistryReply {
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
        Err(e) => eprintln!("bestiary-daemon: curation snapshot failed: {e}"),
    }
    if let Err(e) = shared.store.compact(&*shared.curator) {
        eprintln!("bestiary-daemon: compaction failed: {e}");
    }
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
                eprintln!("bestiary-daemon: bounded signed_entries for push failed: {e}");
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
}
