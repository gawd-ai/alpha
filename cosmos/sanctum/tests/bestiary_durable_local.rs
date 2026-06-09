//! **The durable Bestiary, in-process.**
//!
//! Boots a `bestiary-daemon` (an `FsBestiaryStore` + a `DeterministicCurator`) bound to
//! `Role::REGISTRY` on one Sanctum and drives it over the bus. Proves, end-to-end through the
//! `Creature` `bind`/`handle`/`shutdown` path:
//!
//! - publish → fetch round-trips, and **survives a restart** (drop the node, boot a fresh daemon on
//!   the same root → `recover` replays the journal → the artifact is still fetchable);
//! - a standalone `BestiaryOp::ProveEntry` attestation **verifies** and survives a compaction;
//! - the daemon answers legacy `RegistryOp`s **byte-identically** to `registry-mem` (drop-in parity).
//!
//! The store's deeper durability properties (log-tamper / foreign-author rejection, global-union GC
//! with a shared blob, sticky quarantine, push merge/tamper, tombstone federation) are unit-tested in
//! the `bestiary` crate; this suite proves the daemon wiring on top of them.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, InboxReceiver, RealmId, Role, StubSigner,
};
use anima::NativeEngine;
use bestiary::{
    BestiaryOp, BestiaryReply, BestiaryStore, DeterministicCurator, FsBestiaryStore, RegistryOp,
    RegistryReply,
};
use bestiary_daemon::{BestiaryConfig, BestiaryDaemon};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sha2::{Digest, Sha256};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

// ---- self-cleaning temp root (no external tempdir dep) ----

struct TempRoot(std::path::PathBuf);
impl TempRoot {
    fn new(tag: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("bestiary-it-{tag}-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempRoot(p)
    }
}
impl Drop for TempRoot {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn kernel(node_key: &Ed25519KeyMaterial) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine)],
        Arc::new(StubSigner::new("bestiary-local")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![node_key.public_hex().to_string()])),
        128,
    )
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Boot a single-node kernel with a durable daemon (over `root`) bound to REGISTRY. Returns the
/// kernel + the daemon's creature id.
fn boot_daemon(
    root: &std::path::Path,
    node_key: &Ed25519KeyMaterial,
    abode: Ed25519KeyMaterial,
) -> (Arc<Kernel>, CreatureId) {
    boot_daemon_with_config(root, node_key, abode, BestiaryConfig::local())
}

fn boot_daemon_with_config(
    root: &std::path::Path,
    node_key: &Ed25519KeyMaterial,
    abode: Ed25519KeyMaterial,
    cfg: BestiaryConfig,
) -> (Arc<Kernel>, CreatureId) {
    let k = kernel(node_key);
    let store = Arc::new(FsBestiaryStore::new(root, abode).unwrap());
    let curator = Arc::new(DeterministicCurator::default());
    let daemon = BestiaryDaemon::new(store, curator, cfg);
    let id = k
        .load_instance(signed_boot_manifest("bestiary-daemon", node_key), Box::new(daemon))
        .expect("daemon admits");
    k.bind_role(Role::new(Role::REGISTRY), id);
    (k, id)
}

/// Send a payload to `to` (schema `schema`, correlation `corr`) and wait for the reply addressed back
/// to `probe`, returned as raw bytes.
#[allow(clippy::too_many_arguments)] // test helper: explicit bus/rx/probe/to/schema/payload/corr/budget
fn roundtrip(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    to: Address,
    schema: &str,
    payload: Vec<u8>,
    corr: u64,
    budget: Duration,
) -> Option<Vec<u8>> {
    bus.send(
        Dispatch::to(to, payload)
            .with_schema(schema)
            .with_corr(corr)
            .with_reply_to(Address::Creature(probe)),
    )
    .ok()?;
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env.payload),
            _ => continue,
        }
    }
    None
}

fn registry_op(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    to: Address,
    op: RegistryOp,
    corr: u64,
) -> RegistryReply {
    let bytes = roundtrip(
        bus,
        rx,
        probe,
        to,
        "registry.op",
        serde_json::to_vec(&op).unwrap(),
        corr,
        Duration::from_secs(3),
    )
    .expect("registry reply");
    serde_json::from_slice(&bytes).unwrap()
}

fn bestiary_op(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    to: Address,
    op: BestiaryOp,
    corr: u64,
) -> BestiaryReply {
    let bytes =
        roundtrip(bus, rx, probe, to, "bestiary.op", op.to_bytes(), corr, Duration::from_secs(3))
            .expect("bestiary reply");
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn durable_publish_fetch_prove_and_survive_restart() {
    let root = TempRoot::new("restart");
    let node_key = Ed25519KeyMaterial::from_seed([0x11; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x22; 32]).unwrap();
    let realm = RealmId::new("crew");
    let bytes = b"durable-artifact-bytes".to_vec();
    let hash;

    {
        let (k, id) = boot_daemon(&root.0, &node_key, abode.clone());
        let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

        // Publish into a realm.
        let reply = registry_op(
            &bus,
            &rx,
            probe,
            Address::Creature(id),
            RegistryOp::PublishInRealm {
                manifest: Manifest::new("c", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                artifact: bytes.clone(),
                realm: realm.clone(),
            },
            1,
        );
        hash = match reply {
            RegistryReply::PublishedInRealm { artifact_hash, realm: echoed } => {
                assert_eq!(echoed, realm);
                artifact_hash
            }
            other => panic!("expected PublishedInRealm, got {other:?}"),
        };

        // Fetch it back.
        let reply = registry_op(
            &bus,
            &rx,
            probe,
            Address::Creature(id),
            RegistryOp::FetchInRealm { artifact_hash: hash.clone(), realm: realm.clone() },
            2,
        );
        match reply {
            RegistryReply::FetchedInRealm { artifact, .. } => assert_eq!(artifact, bytes),
            other => panic!("expected FetchedInRealm, got {other:?}"),
        }

        // Metadata fetch reports length without returning artifact bytes.
        let reply = registry_op(
            &bus,
            &rx,
            probe,
            Address::Creature(id),
            RegistryOp::FetchMetadataInRealm { artifact_hash: hash.clone(), realm: realm.clone() },
            21,
        );
        match reply {
            RegistryReply::FetchedMetadata { entry, artifact_len } => {
                assert_eq!(entry.artifact_hash, hash);
                assert_eq!(entry.realm, realm);
                assert_eq!(entry.manifest.name, "c");
                assert_eq!(artifact_len, bytes.len());
            }
            other => panic!("expected FetchedMetadata, got {other:?}"),
        }

        // Metadata listing is byte-light: it reports the catalog row without carrying artifact bytes.
        let reply = registry_op(
            &bus,
            &rx,
            probe,
            Address::Creature(id),
            RegistryOp::ListMetadata { realm: Some(realm.clone()) },
            22,
        );
        match reply {
            RegistryReply::Metadata { entries } => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].artifact_hash, hash);
                assert_eq!(entries[0].realm, realm);
                assert_eq!(entries[0].manifest.name, "c");
            }
            other => panic!("expected Metadata, got {other:?}"),
        }

        // A standalone ProveEntry attestation verifies under the daemon's abode key.
        let reply = bestiary_op(
            &bus,
            &rx,
            probe,
            Address::Creature(id),
            BestiaryOp::ProveEntry { artifact_hash: hash.clone(), realm: realm.clone() },
            3,
        );
        let proof = match reply {
            BestiaryReply::EntryProof { proof } => proof,
            other => panic!("expected EntryProof, got {other:?}"),
        };
        assert!(proof.verify(&Ed25519Verifier), "proof verifies");
        assert_eq!(proof.attester, abode.public_hex());

        // Compaction (deterministic curator keeps everything) leaves the entry intact, and the proof
        // re-derives identically (first_seen preserved).
        let reply = bestiary_op(&bus, &rx, probe, Address::Creature(id), BestiaryOp::Compact, 4);
        assert!(
            matches!(reply, BestiaryReply::Compacted { gc: 0, .. }),
            "deterministic curator GCs nothing"
        );
        let reply = bestiary_op(
            &bus,
            &rx,
            probe,
            Address::Creature(id),
            BestiaryOp::ProveEntry { artifact_hash: hash.clone(), realm: realm.clone() },
            5,
        );
        match reply {
            BestiaryReply::EntryProof { proof: p2 } => {
                assert!(p2.verify(&Ed25519Verifier));
                assert_eq!(
                    p2.first_seen, proof.first_seen,
                    "first_seen preserved across compaction"
                );
            }
            other => panic!("expected EntryProof after compaction, got {other:?}"),
        }

        k.shutdown_all(Deadline::from_millis(1500));
    }

    // Fresh node, SAME root → recover replays the journal → the artifact is still fetchable.
    let (k2, id2) = boot_daemon(&root.0, &node_key, abode);
    let (probe, bus, rx) = k2.open_endpoint(Capabilities::default());
    let reply = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id2),
        RegistryOp::FetchInRealm { artifact_hash: hash, realm },
        10,
    );
    match reply {
        RegistryReply::FetchedInRealm { artifact, manifest, .. } => {
            assert_eq!(artifact, bytes, "artifact survives restart");
            assert_eq!(manifest.name, "c");
        }
        other => panic!("after restart, fetch must still find the entry; got {other:?}"),
    }
    k2.shutdown_all(Deadline::from_millis(1500));
}

#[test]
fn daemon_answers_registry_ops_byte_identically_to_registry_mem() {
    use registry_mem::RegistryMem;

    let root = TempRoot::new("parity");
    let node_key = Ed25519KeyMaterial::from_seed([0x33; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x44; 32]).unwrap();
    let (k, id) = boot_daemon(&root.0, &node_key, abode);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    // Reference in-memory stub to compare reply *shapes* against.
    let mut stub = RegistryMem::new();
    let manifest = Manifest::new("p", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    let bytes = b"parity-bytes".to_vec();

    // Publish: both reply Published{artifact_hash=sha256(bytes)} with the identical hash.
    let daemon_reply = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::Publish { manifest: manifest.clone(), artifact: bytes.clone() },
        1,
    );
    let stub_hash = {
        use aether::Creature;
        let env = aether::Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(9)),
                to: Address::Creature(id),
                reply_to: Some(Address::Creature(CreatureId(9))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(1),
                commitment: None,
                schema: "registry.op".into(),
            },
            payload: serde_json::to_vec(&RegistryOp::Publish { manifest, artifact: bytes.clone() })
                .unwrap(),
        };
        let out = stub.handle(env);
        match serde_json::from_slice::<RegistryReply>(&out.dispatches[0].payload).unwrap() {
            RegistryReply::Published { artifact_hash } => artifact_hash,
            other => panic!("stub: {other:?}"),
        }
    };
    let hash = match daemon_reply {
        RegistryReply::Published { artifact_hash } => artifact_hash,
        other => panic!("daemon Publish reply: {other:?}"),
    };
    assert_eq!(hash, stub_hash, "daemon + stub index under the identical artifact_hash");

    // Fetch a missing key: both reply NotFound.
    let reply = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::Fetch { artifact_hash: "not-present".into() },
        2,
    );
    assert!(matches!(reply, RegistryReply::NotFound), "missing fetch is NotFound (parity)");

    // Fetch the published key: Fetched with the bytes.
    let reply = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::Fetch { artifact_hash: hash },
        3,
    );
    match reply {
        RegistryReply::Fetched { artifact, .. } => assert_eq!(artifact, bytes),
        other => panic!("expected Fetched, got {other:?}"),
    }

    // A malformed payload becomes a structured Error, never a panic (R9 parity).
    let bytes = roundtrip(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        "registry.op",
        b"{ not json".to_vec(),
        4,
        Duration::from_secs(3),
    )
    .unwrap();
    let reply: RegistryReply = serde_json::from_slice(&bytes).unwrap();
    assert!(matches!(reply, RegistryReply::Error { .. }), "malformed op → Error (parity)");

    k.shutdown_all(Deadline::from_millis(1500));
}

#[test]
fn daemon_rejects_oversized_registry_payload_before_json_parse() {
    let root = TempRoot::new("registry-op-cap");
    let node_key = Ed25519KeyMaterial::from_seed([0x55; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x56; 32]).unwrap();
    let mut cfg = BestiaryConfig::local();
    cfg.max_registry_op_bytes = 8;
    let (k, id) = boot_daemon_with_config(&root.0, &node_key, abode, cfg);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    let bytes = roundtrip(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        "registry.op",
        b"{ not json".to_vec(),
        1,
        Duration::from_secs(3),
    )
    .expect("registry reply");
    let reply: RegistryReply = serde_json::from_slice(&bytes).unwrap();
    match reply {
        RegistryReply::Error { message } => {
            assert!(message.contains("too large"), "expected size error, got {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }

    k.shutdown_all(Deadline::from_millis(1500));
}

#[test]
fn daemon_rejects_oversized_registry_publish_artifact() {
    let root = TempRoot::new("registry-artifact-cap");
    let node_key = Ed25519KeyMaterial::from_seed([0x57; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x58; 32]).unwrap();
    let mut cfg = BestiaryConfig::local();
    cfg.max_artifact_bytes = 4;
    let (k, id) = boot_daemon_with_config(&root.0, &node_key, abode, cfg);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    let realm = RealmId::new("crew");
    let bytes = b"12345".to_vec();
    let hash = sha256_hex(&bytes);

    let reply = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::PublishInRealm {
            manifest: Manifest::new("too-big", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            artifact: bytes,
            realm: realm.clone(),
        },
        1,
    );
    match reply {
        RegistryReply::Error { message } => {
            assert!(message.contains("artifact too large"), "unexpected error: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }

    let reply = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::FetchInRealm { artifact_hash: hash, realm },
        2,
    );
    assert!(matches!(reply, RegistryReply::NotFound), "oversized artifact was not stored");

    k.shutdown_all(Deadline::from_millis(1500));
}

#[test]
fn daemon_bounds_full_artifact_list_entries_snapshots() {
    let root = TempRoot::new("list-entries-cap");
    let node_key = Ed25519KeyMaterial::from_seed([0x71; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x72; 32]).unwrap();
    let mut cfg = BestiaryConfig::local();
    cfg.max_snapshot_artifact_bytes = 4;
    let (k, id) = boot_daemon_with_config(&root.0, &node_key, abode, cfg);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    let publish_a = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::PublishInRealm {
            manifest: Manifest::new("a", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            artifact: b"aaa".to_vec(),
            realm: RealmId::new("crew"),
        },
        1,
    );
    assert!(matches!(publish_a, RegistryReply::PublishedInRealm { .. }));
    let publish_b = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::PublishInRealm {
            manifest: Manifest::new("b", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            artifact: b"bbb".to_vec(),
            realm: RealmId::new("guests"),
        },
        2,
    );
    assert!(matches!(publish_b, RegistryReply::PublishedInRealm { .. }));

    let over_cap = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::ListEntries { realm: None },
        3,
    );
    match over_cap {
        RegistryReply::Error { message } => {
            assert!(message.contains("snapshot too large"), "unexpected error: {message}");
        }
        other => panic!("expected Error for over-cap ListEntries, got {other:?}"),
    }

    let scoped = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::ListEntries { realm: Some(RealmId::new("crew")) },
        4,
    );
    match scoped {
        RegistryReply::Entries { entries } => {
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].realm, RealmId::new("crew"));
            assert_eq!(entries[0].artifact, b"aaa");
        }
        other => panic!("expected scoped Entries under cap, got {other:?}"),
    }

    let metadata = registry_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        RegistryOp::ListMetadata { realm: None },
        5,
    );
    match metadata {
        RegistryReply::Metadata { entries } => assert_eq!(entries.len(), 2),
        other => panic!("expected metadata list to stay byte-light, got {other:?}"),
    }

    k.shutdown_all(Deadline::from_millis(1500));
}

#[test]
fn daemon_rejects_oversized_bestiary_payload_before_json_parse() {
    let root = TempRoot::new("bestiary-op-cap");
    let node_key = Ed25519KeyMaterial::from_seed([0x59; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x5A; 32]).unwrap();
    let mut cfg = BestiaryConfig::local();
    cfg.max_bestiary_op_bytes = 8;
    let (k, id) = boot_daemon_with_config(&root.0, &node_key, abode, cfg);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    let bytes = roundtrip(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        "bestiary.op",
        b"{ not json".to_vec(),
        1,
        Duration::from_secs(3),
    )
    .expect("bestiary reply");
    let reply: BestiaryReply = serde_json::from_slice(&bytes).unwrap();
    match reply {
        BestiaryReply::Error { message } => {
            assert!(message.contains("too large"), "expected size error, got {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }

    k.shutdown_all(Deadline::from_millis(1500));
}

#[test]
fn daemon_rejects_oversized_push_entry_artifacts() {
    let root = TempRoot::new("push-artifact-cap");
    let src_root = TempRoot::new("push-artifact-cap-src");
    let node_key = Ed25519KeyMaterial::from_seed([0x5B; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x5C; 32]).unwrap();
    let src_abode = Ed25519KeyMaterial::from_seed([0x5D; 32]).unwrap();
    let mut cfg = BestiaryConfig::local();
    cfg.max_artifact_bytes = 4;
    let (k, id) = boot_daemon_with_config(&root.0, &node_key, abode, cfg);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    let src = FsBestiaryStore::new(&src_root.0, src_abode).unwrap();
    let realm = RealmId::new("crew");
    src.put(
        &realm,
        Manifest::new("pushed-too-big", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        b"12345".to_vec(),
    )
    .unwrap();
    let entries = src.signed_entries(Some(&realm)).unwrap();

    let reply = bestiary_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        BestiaryOp::PushEntries { entries },
        1,
    );
    assert!(
        matches!(reply, BestiaryReply::PushAck { accepted: 0, rejected: 1 }),
        "oversized pushed artifact must be rejected, got {reply:?}"
    );

    k.shutdown_all(Deadline::from_millis(1500));
}

#[test]
fn daemon_rejects_oversized_push_entry_batches_before_store_merge() {
    let root = TempRoot::new("push-entry-count-cap");
    let src_root = TempRoot::new("push-entry-count-cap-src");
    let node_key = Ed25519KeyMaterial::from_seed([0x5E; 32]).unwrap();
    let abode = Ed25519KeyMaterial::from_seed([0x5F; 32]).unwrap();
    let src_abode = Ed25519KeyMaterial::from_seed([0x60; 32]).unwrap();
    let mut cfg = BestiaryConfig::local();
    cfg.max_push_entries = 1;
    let (k, id) = boot_daemon_with_config(&root.0, &node_key, abode, cfg);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    let src = FsBestiaryStore::new(&src_root.0, src_abode).unwrap();
    let realm = RealmId::new("crew");
    let h1 = src
        .put(
            &realm,
            Manifest::new("pushed-one", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            b"one".to_vec(),
        )
        .unwrap();
    let h2 = src
        .put(
            &realm,
            Manifest::new("pushed-two", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            b"two".to_vec(),
        )
        .unwrap();
    let entries = src.signed_entries(Some(&realm)).unwrap();
    assert_eq!(entries.len(), 2, "source produced a valid over-cap batch");

    let reply = bestiary_op(
        &bus,
        &rx,
        probe,
        Address::Creature(id),
        BestiaryOp::PushEntries { entries },
        1,
    );
    match reply {
        BestiaryReply::Error { message } => {
            assert!(message.contains("push batch too large"), "got: {message}");
            assert!(message.contains("2 entries"), "got: {message}");
            assert!(message.contains("limit 1"), "got: {message}");
        }
        other => panic!("expected Error, got {other:?}"),
    }

    for (corr, hash) in [(2, h1), (3, h2)] {
        let reply = registry_op(
            &bus,
            &rx,
            probe,
            Address::Creature(id),
            RegistryOp::FetchInRealm { artifact_hash: hash, realm: realm.clone() },
            corr,
        );
        assert!(matches!(reply, RegistryReply::NotFound), "over-cap batch must not merge entries");
    }

    k.shutdown_all(Deadline::from_millis(1500));
}
