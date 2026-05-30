//! Cross-node Abode migration over `transport-tcp`: the admit path.
//!
//! Static ports `19_955 / 19_956` (distinct from the other cross-node suites' ports). The rejection path
//! lives in [`abode_restore_admission_rejected.rs`](abode_restore_admission_rejected.rs) on
//! different ports — same convention as the other cross-node suites (one
//! transport-tcp-using test per file so parallel `cargo test` doesn't collide on the bind).
//!
//! ## What this test proves
//!
//! Sanctum A migrates an Abode to Sanctum B over `transport-tcp`; B verifies the Abode-key
//! signature, runs the injected `AbodeAllowlistPolicy`, activates the Abode; A's migrator
//! transitions `Authoritative → Migrated { to: B }`; further snapshot requests on A return empty
//! (the hand-off is explicit).
//!
//! ## What this test deliberately is NOT
//!
//! - Not a transport test (transport-tcp is already exercised by `m2_two_node`).
//! - Not a fork test (single-active-fork only; fork is the reconciler's job).
//! - Not a Realm/Omega test.

use std::sync::Arc;
use std::time::Duration;

use abode_migrator::{AbodeMigrator, MigratorMsg, SCHEMA};
use aether::{
    Address, CreatureId, Deadline, Dispatch, InboxReceiver, NodeId, Role, StubSigner, Topic,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_abode_allowlist::AbodeAllowlistPolicy;
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

// ----- ports + node identities (distinct from m2_two_node, v01_end_to_end, distributor_cross_node,
//        realm_local_route, v02_end_to_end) -------------------------------------------------------

const PORT_A: u16 = 19_955;
const PORT_B: u16 = 19_956;
const NODE_A: &str = "m9-cross-node-A";
const NODE_B: &str = "m9-cross-node-B";

// ----- shared scaffolding ----------------------------------------------------------------------

fn slow_factor() -> u64 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}
fn scaled(d: Duration) -> Duration {
    d * (slow_factor() as u32)
}

fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m9-cross-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        128,
    )
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

fn recv_migrator_msg<F: Fn(&MigratorMsg) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    pred: F,
    budget: Duration,
) -> Option<MigratorMsg> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == SCHEMA => {
                if let Ok(msg) = MigratorMsg::parse(&env.payload) {
                    if pred(&msg) {
                        return Some(msg);
                    }
                }
            }
            _ => continue,
        }
    }
    None
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

// ----- per-node boot ----------------------------------------------------------------------------

struct NodeB {
    kernel: Arc<Kernel>,
    migrator_id: CreatureId,
}

/// B boots first. Its migrator binds an `AbodeAllowlistPolicy` configured by the test —
/// `accept_abode_key.is_some()` means an allowed migration; `None` means refuse everything (the
/// admission-rejected test).
fn boot_node_b(
    abode_for_b_allowlist: Option<&Ed25519KeyMaterial>,
    node_key: Ed25519KeyMaterial,
) -> NodeB {
    // Allowed authors for boot creatures: any operator who signed the test fixtures.
    let mut allowed = vec![node_key.public_hex().to_string()];
    if let Some(k) = abode_for_b_allowlist {
        allowed.push(k.public_hex().to_string());
    }
    let k = kernel(allowed);

    let peer_a_pub = Ed25519KeyMaterial::from_seed([0xAA; 32]).unwrap();
    let cfg = TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(NODE_B.into()),
        listen_addr: format!("127.0.0.1:{PORT_B}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_A.into()),
            pubkey_hex: peer_a_pub.public_hex().to_string(),
            dial_addr: Some(format!("127.0.0.1:{PORT_A}")), // B dials A
        }],
    };
    let transport_id = k
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_key),
            Box::new(TransportTcp::new(cfg)),
        )
        .expect("B transport-tcp admits");
    k.bind_role(Role::new(Role::TRANSPORT), transport_id);

    // B's migrator. Abode key is fresh-per-Sanctum (the migrator signs its OWN snapshots, not
    // ones it admits — so this key doesn't have to match A's). The allowlist gates which Abodes
    // B will accept as restores.
    let b_self_abode = Ed25519KeyMaterial::from_seed([0xC0; 32]).unwrap();
    let policy = match abode_for_b_allowlist {
        Some(k) => Box::new(AbodeAllowlistPolicy::allowing(k.public_hex().to_string())),
        None => Box::new(AbodeAllowlistPolicy::new(vec![])), // refuse every restore
    };
    let migrator = AbodeMigrator::new(NodeId(NODE_B.into()), b_self_abode, policy);
    let migrator_id = k
        .load_instance(signed_boot_manifest("abode-migrator-b", &node_key), Box::new(migrator))
        .expect("B migrator admits");
    k.bind_role(Role::new(Role::ABODE_MIGRATOR), migrator_id);

    NodeB { kernel: k, migrator_id }
}

struct NodeA {
    kernel: Arc<Kernel>,
    migrator_id: CreatureId,
    probe_id: CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

/// A boots second. Its migrator holds the Abode the test will migrate to B.
fn boot_node_a(abode: &Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeA {
    let allowed = vec![abode.public_hex().to_string(), node_key.public_hex().to_string()];
    let k = kernel(allowed);

    let peer_b_pub = Ed25519KeyMaterial::from_seed([0xBB; 32]).unwrap();
    let cfg = TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(NODE_A.into()),
        listen_addr: format!("127.0.0.1:{PORT_A}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_B.into()),
            pubkey_hex: peer_b_pub.public_hex().to_string(),
            dial_addr: None, // A is passive — B dials in
        }],
    };
    let transport_id = k
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_key),
            Box::new(TransportTcp::new(cfg)),
        )
        .expect("A transport-tcp admits");
    k.bind_role(Role::new(Role::TRANSPORT), transport_id);

    // A's migrator. The Abode it owns is the one the test will hand off.
    let policy = Box::new(AbodeAllowlistPolicy::allowing(abode.public_hex().to_string()));
    let migrator = AbodeMigrator::new(NodeId(NODE_A.into()), abode.clone(), policy);
    let migrator_id = k
        .load_instance(signed_boot_manifest("abode-migrator-a", &node_key), Box::new(migrator))
        .expect("A migrator admits");
    k.bind_role(Role::new(Role::ABODE_MIGRATOR), migrator_id);

    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    k.router().subscribe(Topic::new(Topic::PROPRIOCEPTION), probe_id);

    NodeA { kernel: k, migrator_id, probe_id, probe_bus, probe_rx }
}

// =================================================================================================
// abode_migrate_cross_node — A migrates Abode to B; B admits via allowlist; A becomes Migrated
// =================================================================================================

/// A holds the Abode; B's allowlist trusts A's Abode key; the migrate
/// orchestration succeeds end-to-end across the wire.
#[test]
fn abode_migrate_cross_node_b_admits_via_allowlist() {
    // One Abode key — A is its current body, B will become its new body. B's allowlist contains
    // this Abode key (the allow case).
    let abode = Ed25519KeyMaterial::from_seed([0x99u8; 32]).unwrap();
    let node_a_key = Ed25519KeyMaterial::from_seed([0xAAu8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xBBu8; 32]).unwrap();

    let b = boot_node_b(Some(&abode), node_b_key);
    let a = boot_node_a(&abode, node_a_key);

    // Gate on peer_connected — transport-tcp silently drops envelopes before the handshake settles.
    let handshake_ok =
        wait_for_peer_event(&a.probe_rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5)));
    assert!(handshake_ok, "A↔B transport handshake must complete before issuing the Migrate");

    // ----- Seed A's migrator with state ---------------------------------------------------------

    let set_state_corr = 1u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Creature(a.migrator_id),
                MigratorMsg::SetState { payload: b"cross-node-self".to_vec() }.to_bytes(),
            )
            .with_schema(SCHEMA)
            .with_corr(set_state_corr)
            .with_reply_to(Address::Creature(a.probe_id)),
        )
        .expect("SetState admits on A");
    let reply = recv_migrator_msg(
        &a.probe_rx,
        set_state_corr,
        |m| matches!(m, MigratorMsg::StateSet),
        scaled(Duration::from_secs(3)),
    )
    .expect("StateSet from A");
    assert!(matches!(reply, MigratorMsg::StateSet));

    // ----- The migration ------------------------------------------------------------------------

    let migrate_corr = 2u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Creature(a.migrator_id),
                MigratorMsg::Migrate {
                    destination_node: NodeId(NODE_B.into()),
                    destination_migrator: b.migrator_id,
                }
                .to_bytes(),
            )
            .with_schema(SCHEMA)
            .with_corr(migrate_corr)
            .with_reply_to(Address::Creature(a.probe_id)),
        )
        .expect("Migrate admits on A");
    // A's migrator emits RestoreRequest → transport-tcp ships to B → B's migrator admits → B
    // ships RestoreResponse{admitted:true} → A's migrator transitions Migrated → A's migrator
    // emits MigrateAck back to the probe at the original corr.
    let ack = recv_migrator_msg(
        &a.probe_rx,
        migrate_corr,
        |m| matches!(m, MigratorMsg::MigrateAck { .. }),
        scaled(Duration::from_secs(10)),
    )
    .expect("MigrateAck across the wire");
    match ack {
        MigratorMsg::MigrateAck { migrated_to } => {
            assert_eq!(migrated_to, NodeId(NODE_B.into()));
        }
        other => panic!("expected MigrateAck, got {other:?}"),
    }

    // ----- Status on A: Migrated; A's payload gone ----------------------------------------------

    let status_a_corr = 3u64;
    a.probe_bus
        .send(
            Dispatch::to(Address::Creature(a.migrator_id), MigratorMsg::StatusQuery.to_bytes())
                .with_schema(SCHEMA)
                .with_corr(status_a_corr)
                .with_reply_to(Address::Creature(a.probe_id)),
        )
        .expect("StatusQuery admits on A");
    let status_a = recv_migrator_msg(
        &a.probe_rx,
        status_a_corr,
        |m| matches!(m, MigratorMsg::StatusReply { .. }),
        scaled(Duration::from_secs(3)),
    )
    .expect("A's status reply");
    match status_a {
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. } => {
            assert_eq!(state, "migrated");
            assert_eq!(migrated_to, Some(NodeId(NODE_B.into())));
            assert_eq!(payload_len, 0);
        }
        other => panic!("expected StatusReply, got {other:?}"),
    }

    // ----- Status on B (across the wire): Authoritative; payload matches -----------------------

    let status_b_corr = 4u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Node(NodeId(NODE_B.into()), b.migrator_id),
                MigratorMsg::StatusQuery.to_bytes(),
            )
            .with_schema(SCHEMA)
            .with_corr(status_b_corr)
            .with_reply_to(Address::Creature(a.probe_id)),
        )
        .expect("cross-node StatusQuery to B admits");
    let status_b = recv_migrator_msg(
        &a.probe_rx,
        status_b_corr,
        |m| matches!(m, MigratorMsg::StatusReply { .. }),
        scaled(Duration::from_secs(8)),
    )
    .expect("B's status reply across the wire");
    match status_b {
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. } => {
            assert_eq!(state, "authoritative");
            assert!(migrated_to.is_none());
            assert_eq!(payload_len, b"cross-node-self".len());
        }
        other => panic!("expected StatusReply, got {other:?}"),
    }

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
