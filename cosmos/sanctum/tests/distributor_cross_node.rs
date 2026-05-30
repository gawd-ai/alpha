//! Cross-node integration test for `distributor-requirements` over `transport-tcp`.
//!
//! Two Sanctums on static ports `19_920 / 19_921` (distinct from `m2_two_node`'s 19_900/01 and
//! `v01_end_to_end`'s 19_910/11). The flow:
//!
//! 1. **Node B boots first** with: transport-tcp + echo_B (advertised cpu:4) + advertiser_B
//!    (carrying that offer). We capture `advertiser_B_id` for the distributor's peer table.
//! 2. **Node A boots second** with: transport-tcp + echo_A (advertised cpu:2) + advertiser_A
//!    (carrying that offer) + **distributor-requirements** whose `peer_advertisers` includes
//!    `(NodeId("node-B"), advertiser_B_id)`.
//! 3. **The probe on A** subscribes to PROPRIOCEPTION and waits for `peer_connected` for node-B
//!    (the transport handshake completes; cross-node addressable).
//! 4. **The probe on A** issues `Intent{outcome:"reverse", requirements:["cpu >= 4"]}` addressed
//!    to the bound distributor.
//! 5. **A's distributor consults**: emits SEER `placement` Queries to advertiser_A *and* to
//!    `Address::Node("node-B", advertiser_B_id)`. transport-tcp on A ships the latter to B.
//! 6. **advertiser_A answers** with no matches (cpu:2 < cpu:4); **advertiser_B answers** with the
//!    cpu:4 echo_B offer; transport-tcp on B ships the answer back to A.
//! 7. **A's distributor reconciles**: the only fit is echo_B → routes the Intent to
//!    `Address::Node("node-B", echo_B_id)`.
//! 8. **echo_B receives the Intent**, reverses + tags, replies to `reply_to` (preserved across all
//!    hops). transport-tcp on B ships the reply back to A.
//! 9. **The probe on A** receives the reply tagged 'B'. Cross-node placement loop closed.
//!
//! ## What this test is, and isn't
//!
//! - It is the cross-node placement proof: distributor on A, SEER `placement` Query reaches B,
//!   answer crosses back, Intent routes via Address::Node, reply returns.
//! - It is not a stress test (the per-creature distributor unit suite already covers parking, reconciliation,
//!   topic isolation, malformed payloads). The cross-node test is the *composition* proof.
//! - It is not a transport test — transport-tcp is exercised by `m2_two_node` already.

use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    Intent, NodeId, Outcome, Role, StubSigner,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use distributor_requirements::{Distributor, PickModel};
use embodiment_advertiser::{EmbodimentAdvertiser, OfferEntry};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use seer::topics::placement;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

// ----- ports + node identities (distinct from v01_end_to_end + m2_two_node) ---------------------

const PORT_A: u16 = 19_920;
const PORT_B: u16 = 19_921;
const NODE_A: &str = "m7-node-A";
const NODE_B: &str = "m7-node-B";

// ----- shared scaffolding -----------------------------------------------------------------------

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
        Arc::new(StubSigner::new("m7-cross-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        128,
    )
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    // Boot creatures (transport, echo, advertiser, distributor) have no shipped artifact; the
    // policy still requires a valid signature so we sign with an allowlisted key.
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

/// Tagged echo: replies with `tag + payload reversed`. Same shape as in `distributor_local.rs`.
struct TaggedEcho {
    tag: u8,
}
impl TaggedEcho {
    fn new(tag: u8) -> Self {
        TaggedEcho { tag }
    }
}
impl Creature for TaggedEcho {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let mut reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        let mut out = vec![self.tag];
        out.append(&mut reversed);
        Outcome::reply(&env, out)
    }
}

/// Receive an envelope matching a corr + predicate (drops other envelopes — proprio events, late
/// SEER traffic, etc.).
fn recv_match<F: Fn(&Envelope) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    pred: F,
    budget: Duration,
) -> Option<Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && pred(&env) => return Some(env),
            _ => continue,
        }
    }
    None
}

/// Wait for a `peer_event` payload on the probe's inbox naming a specific peer + event. Used to
/// gate the test on transport handshake completion before issuing the Intent (otherwise the SEER
/// Query gets dropped silently by transport-tcp's pre-handshake guard).
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

// ----- node B (booted first; lends advertiser_B_id to A) ---------------------------------------

struct NodeB {
    kernel: Arc<Kernel>,
    advertiser_id: CreatureId,
    #[allow(dead_code)]
    echo_id: CreatureId,
}

fn boot_node_b(abode: &Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeB {
    let allowlist = vec![abode.public_hex().to_string(), node_key.public_hex().to_string()];
    let k = kernel(allowlist);

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

    // The placement target on B.
    let echo_b = TaggedEcho::new(b'B');
    let echo_b_id = k
        .load_instance(signed_boot_manifest("echo-b", &node_key), Box::new(echo_b))
        .expect("echo-b admits");

    // B's advertiser knows about one local offer: echo_b at cpu:4.
    let adv_b = EmbodimentAdvertiser::new(
        NodeId(NODE_B.into()),
        vec![OfferEntry {
            creature_id: echo_b_id,
            embodiment: placement::Embodiment {
                cpu: 4,
                mem_bytes: 8 * 1024 * 1024 * 1024,
                accelerators: vec![],
                jurisdiction: Some("ca".into()),
                connectivity: Some("wired".into()),
                sensors: vec![],
            },
        }],
    );
    let advertiser_id = k
        .load_instance(signed_boot_manifest("embodiment-advertiser", &node_key), Box::new(adv_b))
        .expect("B advertiser admits");

    NodeB { kernel: k, advertiser_id, echo_id: echo_b_id }
}

// ----- node A (booted second; distributor's peer table includes B's advertiser_id) -------------

struct NodeA {
    kernel: Arc<Kernel>,
    probe_id: CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_node_a(
    abode: &Ed25519KeyMaterial,
    node_key: Ed25519KeyMaterial,
    b_advertiser_id: CreatureId,
) -> NodeA {
    let allowlist = vec![abode.public_hex().to_string(), node_key.public_hex().to_string()];
    let k = kernel(allowlist);

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

    // Local echo target on A (the cpu:2 offer — won't match cpu>=4 but proves the local
    // advertiser is consulted alongside the peer one).
    let echo_a = TaggedEcho::new(b'A');
    let echo_a_id = k
        .load_instance(signed_boot_manifest("echo-a", &node_key), Box::new(echo_a))
        .expect("echo-a admits");

    // A's advertiser: one local offer at cpu:2.
    let adv_a = EmbodimentAdvertiser::new(
        NodeId(NODE_A.into()),
        vec![OfferEntry {
            creature_id: echo_a_id,
            embodiment: placement::Embodiment {
                cpu: 2,
                mem_bytes: 4 * 1024 * 1024 * 1024,
                accelerators: vec![],
                jurisdiction: Some("us".into()),
                connectivity: Some("wired".into()),
                sensors: vec![],
            },
        }],
    );
    let advertiser_a_id = k
        .load_instance(signed_boot_manifest("embodiment-advertiser", &node_key), Box::new(adv_a))
        .expect("A advertiser admits");

    // The distributor knows about *both* advertisers: the local one + B's (via peer_advertisers).
    let distributor = Distributor::new(
        NodeId(NODE_A.into()),
        vec![advertiser_a_id],
        vec![(NodeId(NODE_B.into()), b_advertiser_id)],
        PickModel::FirstFit,
        10_000,
        1024,
    );
    let distributor_id = k
        .load_instance(
            signed_boot_manifest("distributor-requirements", &node_key),
            Box::new(distributor),
        )
        .expect("A distributor admits");
    k.bind_role(Role::new(Role::DISTRIBUTOR), distributor_id);

    // Probe — subscribed to PROPRIOCEPTION so we can gate on peer_connected.
    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    k.router().subscribe(aether::Topic::new(aether::Topic::PROPRIOCEPTION), probe_id);

    NodeA { kernel: k, probe_id, probe_bus, probe_rx }
}

// =================================================================================================
// The cross-node placement loop test
// =================================================================================================

#[test]
fn distributor_cross_node_match() {
    // Three keys: one shared Abode (signs creature authorship), two per-node transport keys.
    let abode = Ed25519KeyMaterial::from_seed([0x07u8; 32]).unwrap();
    let node_a_key = Ed25519KeyMaterial::from_seed([0xAAu8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xBBu8; 32]).unwrap();

    // Boot B first so we can hand A the advertiser_id for the distributor's peer table.
    let b = boot_node_b(&abode, node_b_key);
    let a = boot_node_a(&abode, node_a_key, b.advertiser_id);

    // Gate on peer_connected before issuing the Intent — transport-tcp drops envelopes silently
    // until the handshake completes, and there's no point in racing the test against that.
    let handshake_ok =
        wait_for_peer_event(&a.probe_rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5)));
    assert!(handshake_ok, "A↔B transport handshake must complete before the placement consult");

    // Issue the cross-node-required Intent. A's local advertiser has cpu:2 (no match); B's has
    // cpu:4 (the only match). The distributor must consult both, reconcile to B, route to B.
    let intent_corr = 1u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Intent(Intent {
                    outcome: "reverse-string".into(),
                    requirements: vec!["cpu >= 4".into()],
                }),
                b"hello-cross-node".to_vec(),
            )
            .with_reply_to(Address::Creature(a.probe_id))
            .with_corr(intent_corr),
        )
        .expect("Intent admits + routes to A's bound distributor");

    // The reply must come from echo_B (tag 'B'), reversed across the wire. The reply traverses:
    //   echo_B(reverse) → transport_tcp_B(ship) → transport_tcp_A(deliver) → probe_A.
    let reply = recv_match(
        &a.probe_rx,
        intent_corr,
        |e| !e.payload.is_empty() && e.payload[0] == b'B',
        scaled(Duration::from_secs(8)),
    )
    .expect("echo_B reply arrives across the wire on the same corr");

    let reversed: Vec<u8> = b"hello-cross-node".iter().copied().rev().collect();
    let mut expected = vec![b'B'];
    expected.extend_from_slice(&reversed);
    assert_eq!(
        reply.payload, expected,
        "cross-node placement loop closed: tagged 'B' + reversed payload"
    );

    // Clean shutdown — drives transport-tcp's listener/dialer/reader/writer joins.
    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
