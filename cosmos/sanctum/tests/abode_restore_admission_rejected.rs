//! Cross-node Abode migration over `transport-tcp`: the policy-reject path.
//!
//! Static ports `19_957 / 19_958` (distinct from `abode_migrate_cross_node`'s `19_955 / 19_956`
//! so the two cross-node migration tests can run in parallel under `cargo test`).
//!
//! ## What this test proves
//!
//! B's `AbodeAllowlistPolicy` does NOT include A's Abode key, so B's migrator runs all the
//! substrate-shipped gates, then the injected policy rejects, and B replies
//! `RestoreResponse { admitted: false, reason: "restore-policy: …" }`. A's migrator receives the
//! `MigrateFailed { reason }` carrying the structured prefix and stays Authoritative — the
//! source's Abode is undisturbed by a refused migration.
//!
//! Same setup as `abode_migrate_cross_node` minus the allowlist entry; documents the IoC
//! discipline ("substrate ships no model — operator's policy decides") with a fail-closed default.

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

// ----- ports + node identities (distinct from abode_migrate_cross_node) ------------------------

const PORT_A: u16 = 19_957;
const PORT_B: u16 = 19_958;
const NODE_A: &str = "m9-reject-node-A";
const NODE_B: &str = "m9-reject-node-B";

// ----- shared scaffolding (copied verbatim from abode_migrate_cross_node — convention is one
//        cross-node test per file rather than a shared helper module, since each test owns its
//        ports and node identities) ----------------------------------------------------------

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
        Arc::new(StubSigner::new("m9-cross-node-reject")),
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

// ----- per-node boot (mirrors abode_migrate_cross_node, with the empty allowlist as the
//        admission-reject knob) ----------------------------------------------------------------

struct NodeB {
    kernel: Arc<Kernel>,
    migrator_id: CreatureId,
}

fn boot_node_b(node_key: Ed25519KeyMaterial) -> NodeB {
    let allowed = vec![node_key.public_hex().to_string()];
    let k = kernel(allowed);

    let peer_a_pub = Ed25519KeyMaterial::from_seed([0xCC; 32]).unwrap();
    let cfg = TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(NODE_B.into()),
        listen_addr: format!("127.0.0.1:{PORT_B}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_A.into()),
            pubkey_hex: peer_a_pub.public_hex().to_string(),
            dial_addr: Some(format!("127.0.0.1:{PORT_A}")),
        }],
    };
    let transport_id = k
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_key),
            Box::new(TransportTcp::new(cfg)),
        )
        .expect("B transport-tcp admits");
    k.bind_role(Role::new(Role::TRANSPORT), transport_id);

    // EMPTY allowlist — every restore rejected. The IoC discipline's fail-closed default:
    // a Sanctum that hasn't decided what to trust trusts nothing.
    let b_self_abode = Ed25519KeyMaterial::from_seed([0xC1; 32]).unwrap();
    let policy = Box::new(AbodeAllowlistPolicy::new(vec![]));
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

fn boot_node_a(abode: &Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeA {
    let allowed = vec![abode.public_hex().to_string(), node_key.public_hex().to_string()];
    let k = kernel(allowed);

    let peer_b_pub = Ed25519KeyMaterial::from_seed([0xDD; 32]).unwrap();
    let cfg = TransportConfig {
        self_key: node_key.clone(),
        self_node: NodeId(NODE_A.into()),
        listen_addr: format!("127.0.0.1:{PORT_A}"),
        peers: vec![PeerConfig {
            node_id: NodeId(NODE_B.into()),
            pubkey_hex: peer_b_pub.public_hex().to_string(),
            dial_addr: None,
        }],
    };
    let transport_id = k
        .load_instance(
            signed_boot_manifest("transport-tcp", &node_key),
            Box::new(TransportTcp::new(cfg)),
        )
        .expect("A transport-tcp admits");
    k.bind_role(Role::new(Role::TRANSPORT), transport_id);

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
// abode_restore_admission_rejected — B's policy refuses; A stays Authoritative
// =================================================================================================

#[test]
fn abode_restore_admission_rejected_leaves_source_authoritative() {
    // Distinct seeds from abode_migrate_cross_node — even running in parallel they don't share
    // any cryptographic material.
    let abode = Ed25519KeyMaterial::from_seed([0x77u8; 32]).unwrap();
    let node_a_key = Ed25519KeyMaterial::from_seed([0xCCu8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xDDu8; 32]).unwrap();

    let b = boot_node_b(node_b_key);
    let a = boot_node_a(&abode, node_a_key);

    let handshake_ok =
        wait_for_peer_event(&a.probe_rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5)));
    assert!(handshake_ok, "A↔B transport handshake must complete first");

    // Seed A's state.
    let set_state_corr = 1u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Creature(a.migrator_id),
                MigratorMsg::SetState { payload: b"protected-self".to_vec() }.to_bytes(),
            )
            .with_schema(SCHEMA)
            .with_corr(set_state_corr)
            .with_reply_to(Address::Creature(a.probe_id)),
        )
        .expect("SetState admits");
    let _ = recv_migrator_msg(
        &a.probe_rx,
        set_state_corr,
        |m| matches!(m, MigratorMsg::StateSet),
        scaled(Duration::from_secs(3)),
    )
    .expect("StateSet");

    // Attempt migration.
    let migrate_corr = 2u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Creature(a.migrator_id),
                MigratorMsg::Migrate {
                    destination_node: NodeId(NODE_B.into()),
                    destination_migrator: b.migrator_id,
                    // Refusal path — admitted:false carries no witness, so no anchor is needed.
                    expected_responder_pubkey: None,
                }
                .to_bytes(),
            )
            .with_schema(SCHEMA)
            .with_corr(migrate_corr)
            .with_reply_to(Address::Creature(a.probe_id)),
        )
        .expect("Migrate admits");

    // Expect MigrateFailed with the structured `restore-policy:` prefix.
    let failed = recv_migrator_msg(
        &a.probe_rx,
        migrate_corr,
        |m| matches!(m, MigratorMsg::MigrateFailed { .. }),
        scaled(Duration::from_secs(10)),
    )
    .expect("MigrateFailed across the wire");
    match failed {
        MigratorMsg::MigrateFailed { reason } => {
            assert!(
                reason.contains("restore-policy:"),
                "structured prefix names the rejecting gate; got: `{reason}`",
            );
            assert!(
                reason.contains("not on the allowlist"),
                "policy reason rides verbatim across the wire; got: `{reason}`",
            );
        }
        other => panic!("expected MigrateFailed, got {other:?}"),
    }

    // A's migrator MUST still be Authoritative — a rejected restore never transitions the source.
    let status_a_corr = 3u64;
    a.probe_bus
        .send(
            Dispatch::to(Address::Creature(a.migrator_id), MigratorMsg::StatusQuery.to_bytes())
                .with_schema(SCHEMA)
                .with_corr(status_a_corr)
                .with_reply_to(Address::Creature(a.probe_id)),
        )
        .expect("StatusQuery admits");
    let status = recv_migrator_msg(
        &a.probe_rx,
        status_a_corr,
        |m| matches!(m, MigratorMsg::StatusReply { .. }),
        scaled(Duration::from_secs(3)),
    )
    .expect("status reply on A");
    match status {
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. } => {
            assert_eq!(state, "authoritative", "rejection must not seal the source migrator",);
            assert!(migrated_to.is_none());
            assert_eq!(payload_len, b"protected-self".len());
        }
        other => panic!("expected StatusReply, got {other:?}"),
    }

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
