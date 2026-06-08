//! **Durable Bestiary replication over `transport-tcp`.**
//!
//! Static ports `19_980 / 19_981` (one transport-tcp test per file so parallel `cargo test` doesn't
//! collide on the bind; distinct from every other cross-node suite — sanctum `19_900..19_971`, omni
//! `control_over_mesh` `19_982/19_983`, omega `19_960/19_961`). One `#[test]` to stay on one port
//! pair.
//!
//! Two Sanctums, each running `transport-tcp` (TRANSPORT) + `bestiary-daemon` (REGISTRY). A's daemon
//! is configured to PUSH-replicate to B on a short cadence; B is passive. What it proves over the wire:
//!
//! 1. **Convergence via the autonomous PUSH worker** — A publishes X; B converges to hold X.
//! 2. **A tampered push is rejected** — a hand-forged push whose bytes don't match its hash returns a
//!    `PushAck{rejected}` and never lands.
//! 3. **Sticky quarantine** — a crafted quarantine for X lands on B; A (the *unaware* peer) keeps
//!    re-pushing a plain X, and B's quarantine is **not** silently cleared.
//! 4. **Signed reputation federates** (verified-greater) — a push carrying a signed promotion score
//!    for an artifact only the source holds lands on B with the score intact.
//! 5. **Tombstone federates** — a tombstone push for that source-only artifact permanently evicts it
//!    on B (A never re-pushes it, so it stays gone).

use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, InboxReceiver, NodeId, RealmId, Role,
    StubSigner,
};
use anima::NativeEngine;
use bestiary::{
    BestiaryOp, BestiaryReply, DeterministicCurator, FsBestiaryStore, QuarantineNotice, RegistryOp,
    RegistryReply, ReputationScore, SignedSyncEntry, SyncEntry,
};
use bestiary_daemon::{BestiaryConfig, BestiaryDaemon, ReplicationPeer};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

const PORT_A: u16 = 19_980;
const PORT_B: u16 = 19_981;
const NODE_A: &str = "bsty-A";
const NODE_B: &str = "bsty-B";
const REALM: &str = "crew";

fn slow_factor() -> u64 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}
fn scaled(d: Duration) -> Duration {
    d * (slow_factor() as u32)
}

struct TempRoot(std::path::PathBuf);
impl TempRoot {
    fn new(tag: &str) -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        let n = N.fetch_add(1, Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("bsty-xnode-{tag}-{}-{n}", std::process::id()));
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
        Arc::new(StubSigner::new("bsty-xnode")),
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
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

struct Node {
    kernel: Arc<Kernel>,
    daemon_id: CreatureId,
}

#[allow(clippy::too_many_arguments)]
fn boot(
    node_id: &str,
    port: u16,
    node_key: Ed25519KeyMaterial,
    peer_node: &str,
    peer_pub: &Ed25519KeyMaterial,
    peer_port: u16,
    dials: bool,
    root: &std::path::Path,
    abode: Ed25519KeyMaterial,
    peers: Vec<ReplicationPeer>,
    push_interval: Duration,
) -> Node {
    let k = kernel(&node_key);
    let cfg = TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(node_id.into()),
        listen_addr: format!("127.0.0.1:{port}"),
        peers: vec![PeerConfig {
            node_id: NodeId(peer_node.into()),
            pubkey_hex: peer_pub.public_hex().to_string(),
            dial_addr: if dials { Some(format!("127.0.0.1:{peer_port}")) } else { None },
        }],
    };
    let transport_id = k
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_key),
            Box::new(TransportTcp::new(cfg)),
        )
        .expect("transport admits");
    k.bind_role(Role::new(Role::TRANSPORT), transport_id);

    let store = Arc::new(FsBestiaryStore::new(root, abode).unwrap());
    let curator = Arc::new(DeterministicCurator::default());
    let daemon = BestiaryDaemon::new(
        store,
        curator,
        BestiaryConfig {
            anti_entropy_interval: push_interval,
            compaction_interval: Duration::ZERO,
            replication_peers: peers,
            ..BestiaryConfig::local()
        },
    );
    let daemon_id = k
        .load_instance(signed_boot_manifest("bestiary-daemon", &node_key), Box::new(daemon))
        .expect("daemon admits");
    k.bind_role(Role::new(Role::REGISTRY), daemon_id);
    Node { kernel: k, daemon_id }
}

fn wait_for_peer_event(rx: &InboxReceiver, peer: &str, event: &str, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.schema == "peer_event" => {
                if let Ok(ev) = serde_json::from_slice::<PeerEvent>(&env.payload) {
                    if ev.peer == peer && ev.event == event {
                        return true;
                    }
                }
            }
            _ => continue,
        }
    }
    false
}

fn reply_for(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<Vec<u8>> {
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

/// List B's entries (over transport) and test `pred`, polling until satisfied or the budget expires.
fn poll_b<F: Fn(&[SyncEntry]) -> bool>(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    b: &Node,
    corr_base: u64,
    pred: F,
    budget: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + budget;
    let mut corr = corr_base;
    while std::time::Instant::now() < deadline {
        corr += 1;
        let _ = bus.send(
            Dispatch::to(
                Address::Node(NodeId(NODE_B.into()), b.daemon_id),
                serde_json::to_vec(&RegistryOp::ListEntries { realm: Some(RealmId::new(REALM)) })
                    .unwrap(),
            )
            .with_schema("registry.op")
            .with_corr(corr)
            .with_reply_to(Address::Creature(probe)),
        );
        if let Some(bytes) = reply_for(rx, corr, Duration::from_secs(2)) {
            if let Ok(RegistryReply::Entries { entries }) =
                serde_json::from_slice::<RegistryReply>(&bytes)
            {
                if pred(&entries) {
                    return true;
                }
            }
        }
        std::thread::sleep(Duration::from_millis(80));
    }
    false
}

/// Send a crafted `PushEntries` from A to B over transport, returning the `PushAck`.
fn send_push(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    b: &Node,
    entries: Vec<SignedSyncEntry>,
    corr: u64,
) -> BestiaryReply {
    bus.send(
        Dispatch::to(
            Address::Node(NodeId(NODE_B.into()), b.daemon_id),
            BestiaryOp::PushEntries { entries }.to_bytes(),
        )
        .with_schema("bestiary.op")
        .with_corr(corr)
        .with_reply_to(Address::Creature(probe)),
    )
    .expect("push dispatched to B");
    let bytes = reply_for(rx, corr, scaled(Duration::from_secs(5))).expect("PushAck from B");
    serde_json::from_slice(&bytes).unwrap()
}

#[test]
fn bestiary_replication_converges_with_sticky_quarantine_and_federated_tombstone() {
    let node_a_key = Ed25519KeyMaterial::from_seed([0xA0; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xB0; 32]).unwrap();
    let abode_a = Ed25519KeyMaterial::from_seed([0xA9; 32]).unwrap();
    let abode_b = Ed25519KeyMaterial::from_seed([0xB9; 32]).unwrap();
    let src_abode = Ed25519KeyMaterial::from_seed([0x5C; 32]).unwrap();
    let realm = RealmId::new(REALM);

    let root_a = TempRoot::new("A");
    let root_b = TempRoot::new("B");
    let root_src = TempRoot::new("src");

    // B boots first (passive); A dials B and PUSHes to B's daemon every ~120ms.
    let b = boot(
        NODE_B,
        PORT_B,
        node_b_key.clone(),
        NODE_A,
        &node_a_key,
        PORT_A,
        false,
        &root_b.0,
        abode_b,
        Vec::new(),
        Duration::ZERO,
    );
    let a = boot(
        NODE_A,
        PORT_A,
        node_a_key.clone(),
        NODE_B,
        &node_b_key,
        PORT_B,
        true,
        &root_a.0,
        abode_a,
        vec![ReplicationPeer { node: NodeId(NODE_B.into()), daemon: b.daemon_id, realm: None }],
        Duration::from_millis(120),
    );

    let (probe, bus, rx) = a.kernel.open_endpoint(Capabilities::default());
    a.kernel.router().subscribe(aether::Topic::new(aether::Topic::PROPRIOCEPTION), probe);
    assert!(
        wait_for_peer_event(&rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5))),
        "A↔B handshake must complete before replicating"
    );

    // ---- (1) Convergence: A publishes X locally; the worker pushes it; B converges. ----
    let x_bytes = b"artifact-X".to_vec();
    let x_hash = sha256_hex(&x_bytes);
    bus.send(
        Dispatch::to(
            Address::Creature(a.daemon_id),
            serde_json::to_vec(&RegistryOp::PublishInRealm {
                manifest: Manifest::new("x", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                artifact: x_bytes.clone(),
                realm: realm.clone(),
            })
            .unwrap(),
        )
        .with_schema("registry.op")
        .with_corr(1)
        .with_reply_to(Address::Creature(probe)),
    )
    .expect("publish X on A");
    assert!(reply_for(&rx, 1, scaled(Duration::from_secs(3))).is_some(), "A acks the publish");

    assert!(
        poll_b(
            &bus,
            &rx,
            probe,
            &b,
            1_000,
            |es| es.iter().any(|e| e.artifact_hash == x_hash),
            scaled(Duration::from_secs(12))
        ),
        "X must converge to B via the autonomous PUSH worker"
    );

    // ---- (2) A tampered push is rejected (bytes don't match the declared hash). ----
    let src = FsBestiaryStore::new(&root_src.0, src_abode.clone()).unwrap();
    use bestiary::BestiaryStore;
    let w_bytes = b"artifact-W".to_vec();
    let w_hash = sha256_hex(&w_bytes);
    src.put(&realm, Manifest::new("w", "0.1.0", Backend::Daemon, "gawd_creature_v1"), w_bytes)
        .unwrap();
    let mut tampered = src.signed_entries(Some(&realm)).unwrap();
    tampered.retain(|e| e.sync.as_ref().is_some_and(|s| s.artifact_hash == w_hash));
    if let Some(s) = tampered[0].sync.as_mut() {
        s.artifact = b"DIFFERENT".to_vec(); // bytes no longer hash to w_hash
    }
    match send_push(&bus, &rx, probe, &b, tampered, 2) {
        BestiaryReply::PushAck { accepted, rejected } => {
            assert_eq!(accepted, 0);
            assert_eq!(rejected, 1, "tampered push rejected");
        }
        other => panic!("expected PushAck, got {other:?}"),
    }
    assert!(
        !poll_b(
            &bus,
            &rx,
            probe,
            &b,
            2_000,
            |es| es.iter().any(|e| e.artifact_hash == w_hash),
            Duration::from_millis(600)
        ),
        "the tampered artifact W must NOT have landed on B"
    );

    // ---- (3) Sticky quarantine: a crafted quarantine for X lands on B; A keeps re-pushing a plain X
    //          (the unaware peer), and B's quarantine is NOT cleared. ----
    // Build a quarantine-bearing push for X from a source store holding the same bytes.
    let root_srcx = TempRoot::new("srcx");
    let src_x = FsBestiaryStore::new(&root_srcx.0, src_abode.clone()).unwrap();
    src_x
        .put(
            &realm,
            Manifest::new("x", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            x_bytes.clone(),
        )
        .unwrap();
    src_x
        .quarantine(
            &realm,
            &x_hash,
            QuarantineNotice {
                reason: "observed apoptosis".into(),
                attesting_peers: vec!["src".into()],
            },
        )
        .unwrap();
    let q_push = src_x.signed_entries(Some(&realm)).unwrap();
    match send_push(&bus, &rx, probe, &b, q_push, 3) {
        BestiaryReply::PushAck { rejected, .. } => {
            assert_eq!(rejected, 0, "quarantine push accepted")
        }
        other => panic!("expected PushAck, got {other:?}"),
    }
    assert!(
        poll_b(
            &bus,
            &rx,
            probe,
            &b,
            3_000,
            |es| es.iter().any(|e| e.artifact_hash == x_hash && e.quarantine.is_some()),
            scaled(Duration::from_secs(5))
        ),
        "X must be quarantined on B"
    );
    // Let A's worker re-push plain X several times, then confirm B is STILL quarantined (sticky).
    std::thread::sleep(scaled(Duration::from_millis(600)));
    assert!(
        poll_b(
            &bus,
            &rx,
            probe,
            &b,
            3_500,
            |es| es.iter().any(|e| e.artifact_hash == x_hash && e.quarantine.is_some()),
            scaled(Duration::from_secs(3))
        ),
        "an unaware peer's plain re-push must NOT clear B's quarantine on X (sticky)"
    );

    // ---- (4)+(5) Signed reputation federates, then a tombstone evicts — on a SOURCE-ONLY artifact Z
    //      that A never holds (so A's worker can't resurrect it). ----
    let z_bytes = b"artifact-Z-source-only".to_vec();
    let z_hash = sha256_hex(&z_bytes);
    let root_srcz = TempRoot::new("srcz");
    let src_z = FsBestiaryStore::new(&root_srcz.0, src_abode.clone()).unwrap();
    src_z
        .put(&realm, Manifest::new("z", "0.1.0", Backend::Daemon, "gawd_creature_v1"), z_bytes)
        .unwrap();
    // A signed promotion score so merge takes it as verified-greater.
    let score = 0.91f32;
    let sig = src_abode.sign(&ReputationScore::promotion_payload(&z_hash, &realm, score, None));
    src_z
        .attest(
            &realm,
            &z_hash,
            ReputationScore {
                score,
                attesting_realm: None,
                signed_by: Some(src_abode.public_hex().to_string()),
                signature: Some(sig),
            },
        )
        .unwrap();
    let z_push = src_z.signed_entries(Some(&realm)).unwrap();
    match send_push(&bus, &rx, probe, &b, z_push, 4) {
        BestiaryReply::PushAck { rejected, .. } => assert_eq!(rejected, 0, "Z push accepted"),
        other => panic!("expected PushAck, got {other:?}"),
    }
    assert!(
        poll_b(
            &bus,
            &rx,
            probe,
            &b,
            4_000,
            |es| es.iter().any(|e| e.artifact_hash == z_hash
                && e.reputation.as_ref().is_some_and(|r| (r.score - score).abs() < 1e-6)),
            scaled(Duration::from_secs(5))
        ),
        "Z must land on B carrying its signed (verified-greater) reputation score"
    );
    // Now tombstone Z at the source and federate the eviction.
    src_z.tombstone(&realm, &z_hash).unwrap();
    let tomb = src_z.signed_entries(Some(&realm)).unwrap();
    assert!(tomb.iter().any(|e| e.sync.is_none()), "the push set carries a tombstone for Z");
    match send_push(&bus, &rx, probe, &b, tomb, 5) {
        BestiaryReply::PushAck { rejected, .. } => {
            assert_eq!(rejected, 0, "tombstone push accepted")
        }
        other => panic!("expected PushAck, got {other:?}"),
    }
    assert!(
        poll_b(
            &bus,
            &rx,
            probe,
            &b,
            5_000,
            |es| !es.iter().any(|e| e.artifact_hash == z_hash),
            scaled(Duration::from_secs(5))
        ),
        "the tombstone must federate and permanently evict Z on B (A never re-pushes Z)"
    );

    a.kernel.shutdown_all(Deadline::from_millis(2000));
    b.kernel.shutdown_all(Deadline::from_millis(2000));
}
