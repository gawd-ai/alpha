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
//! - **The PUSH is a full live-set push each cadence, not a head diff.** The lattice merge is
//!   idempotent, so a full push converges; a high-volume Bestiary would diff by log head. Documented,
//!   not silently capped.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, NodeId, Outcome,
};
use bestiary::{
    BestiaryOp, BestiaryReply, BestiaryStore, CurationContext, Curator, QuarantineNotice,
    RegistryOp, RegistryReply, ReputationScore, BESTIARY_OP_SCHEMA, BESTIARY_REPLY_SCHEMA,
    REGISTRY_REPLY_SCHEMA,
};
use sigil::RealmId;

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
}

impl BestiaryConfig {
    /// A single-node config: no autonomous push or compaction (drive `Compact` over the bus instead).
    pub fn local() -> Self {
        BestiaryConfig {
            anti_entropy_interval: Duration::ZERO,
            compaction_interval: Duration::ZERO,
            replication_peers: Vec::new(),
        }
    }
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
        BestiaryDaemon {
            store,
            curator,
            cfg,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Mutex::new(Vec::new()),
        }
    }

    // ---- registry.op (byte-identical to registry-mem) ----

    fn serve_registry(&mut self, env: &Envelope) -> Outcome {
        let reply = match serde_json::from_slice::<RegistryOp>(&env.payload) {
            Ok(RegistryOp::Publish { manifest, artifact }) => {
                match self.store.put(&RealmId::local(), manifest, artifact) {
                    Ok(artifact_hash) => RegistryReply::Published { artifact_hash },
                    Err(e) => RegistryReply::Error { message: e.to_string() },
                }
            }
            Ok(RegistryOp::Fetch { artifact_hash }) => {
                self.fetched(&RealmId::local(), &artifact_hash, false)
            }
            Ok(RegistryOp::PublishInRealm { manifest, artifact, realm }) => {
                match self.store.put(&realm, manifest, artifact) {
                    Ok(artifact_hash) => RegistryReply::PublishedInRealm { artifact_hash, realm },
                    Err(e) => RegistryReply::Error { message: e.to_string() },
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
            Ok(RegistryOp::MarkQuarantine { artifact_hash, realm, reason, attesting_peers }) => {
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
            Ok(RegistryOp::ListEntries { realm }) => match self.store.list(realm.as_ref()) {
                Ok(entries) => RegistryReply::Entries { entries },
                Err(e) => RegistryReply::Error { message: e.to_string() },
            },
            Err(e) => {
                eprintln!(
                    "bestiary-daemon: rejected a malformed registry op from {:?} (corr={:?}, {} bytes): {e}",
                    env.header.from,
                    env.header.corr,
                    env.payload.len()
                );
                RegistryReply::Error { message: format!("malformed registry op: {e}") }
            }
        };
        Outcome::send(
            Dispatch::reply_to_env(env, reply.to_bytes()).with_schema(REGISTRY_REPLY_SCHEMA),
        )
    }

    fn fetched(&self, realm: &RealmId, artifact_hash: &str, _in_realm: bool) -> RegistryReply {
        match self.store.get(realm, artifact_hash) {
            Ok(Some(entry)) => {
                RegistryReply::Fetched { manifest: entry.manifest, artifact: entry.artifact }
            }
            Ok(None) => RegistryReply::NotFound,
            Err(e) => RegistryReply::Error { message: e.to_string() },
        }
    }

    // ---- bestiary.op (the additive durable-Bestiary surface) ----

    fn serve_bestiary(&mut self, env: &Envelope) -> Outcome {
        let reply = match serde_json::from_slice::<BestiaryOp>(&env.payload) {
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
                let (mut accepted, mut rejected) = (0usize, 0usize);
                for entry in entries {
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
            Err(e) => BestiaryReply::Error { message: format!("malformed bestiary op: {e}") },
        };
        Outcome::send(
            Dispatch::reply_to_env(env, reply.to_bytes()).with_schema(BESTIARY_REPLY_SCHEMA),
        )
    }
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
    match shared.store.snapshot_for_curation() {
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
        let entries = match shared.store.signed_entries(peer.realm.as_ref()) {
            Ok(e) => e,
            Err(e) => {
                eprintln!("bestiary-daemon: signed_entries for push failed: {e}");
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
