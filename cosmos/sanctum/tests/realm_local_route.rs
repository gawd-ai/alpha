//! Cross-node Realm-routing integration test for `cosmos/creatures/prototypes/gateways/realm-gateway` over
//! `transport-tcp`.
//!
//! Two Sanctums on static ports `19_930 / 19_931` (distinct from `m2_two_node`'s 19_900/01,
//! `v01_end_to_end`'s 19_910/11, and
//! `distributor_cross_node`'s 19_920/21). The flow:
//!
//! 1. **Node B boots first** with: transport-tcp + a `TaggedEcho` creature (`echo_b_id`). The
//!    plain `Address::Creature(echo_b_id)` delivery on B is unaffected — `realm-gateway`
//!    on A does NOT change anything about how B receives or replies. The Realm wrap is purely
//!    A's concern.
//! 2. **Node A boots second** with: transport-tcp + realm-gateway. realm-gateway's config maps
//!    Realm `"crew"` → `NodeId("realm-node-B")`. The role binding is on
//!    [`Role::REALM_GATEWAY`].
//! 3. **The probe on A** subscribes to PROPRIOCEPTION and waits for `peer_connected` for node-B
//!    (transport-tcp's silent-drop-before-handshake would race the test otherwise).
//! 4. **The probe on A** sends `Realm("crew", Creature(echo_b_id))` with a payload + corr +
//!    reply_to.
//! 5. **A's router** dispatches the Realm-addressed envelope to A's realm-gateway (per
//!    [`Address::Realm` → `Role::REALM_GATEWAY`] in the router).
//! 6. **A's realm-gateway** unwraps: realm `"crew"` → peer `"realm-node-B"`; inner target is
//!    `Creature(echo_b_id)`. Rewrites the dispatch as `Node("realm-node-B", echo_b_id)`,
//!    preserving reply_to + corr + schema + payload byte-for-byte.
//! 7. **A's transport-tcp** ships the Node-addressed envelope across to B.
//! 8. **B's transport-tcp** delivers it to echo_b_id, which replies (reverses payload, tags 'B').
//!    Transport ships the reply back to the original `reply_to` (the probe on A).
//! 9. **The probe on A** receives the reply at the original corr.
//!
//! ## What this test proves
//!
//! - The address grain composes: same envelope, just one more layer of dispatch (realm-gateway
//!   between sender and transport). The substrate ships the address shape; the gateway *creature*
//!   resolves the Realm.
//! - reply_to / corr / schema / payload survive the realm-gateway hop intact (fire-and-correlate
//!   discipline).
//! - `Address::Realm` envelopes route correctly when a gateway is bound; the `Address::Node`
//!   path on B is unaffected.

use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    NodeId, Outcome, RealmId, Role, StubSigner,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use realm_gateway::{RealmGateway, RealmGatewayConfig};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

// ----- ports + node identities (distinct from m2_two_node, v01_end_to_end, distributor_cross_node)
// ---------------------------------------------------------------------------------------------

const PORT_A: u16 = 19_930;
const PORT_B: u16 = 19_931;
const NODE_A: &str = "m8-realm-node-A";
const NODE_B: &str = "realm-node-B"; // matches realm-gateway's peer mapping

// ----- shared scaffolding (mirrors distributor_cross_node.rs) ----------------------------------

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
        Arc::new(StubSigner::new("m8-realm")),
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

/// Tagged echo — reverses the payload and prepends a tag byte. Same shape as in
/// `distributor_cross_node.rs` (kept inline rather than shared, per the test-suite convention).
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

/// Reflects the inbound envelope's `commitment` slot back as its reply payload (empty when the slot
/// arrived as `None`). Lets the test prove a commitment survived realm-gateway's Realm→Node rewrite
/// AND the transport hop end-to-end — the gateway-unit proof is in `cosmos/creatures/prototypes/gateways/realm-gateway`, this is
/// the over-the-wire half.
struct CommitmentEcho;
impl Creature for CommitmentEcho {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let body = env.header.commitment.clone().unwrap_or_default().into_bytes();
        Outcome::reply(&env, body)
    }
}

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

// ----- node B (booted first; the Realm peer) ---------------------------------------------------

struct NodeB {
    kernel: Arc<Kernel>,
    echo_id: CreatureId,
    /// Commitment-reflecting target for the commitment wire proof.
    commitment_echo_id: CreatureId,
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

    // The Realm-routed target. The realm-gateway on A re-addresses the envelope to
    // Node(NODE_B, echo_id); B's transport delivers it to this creature.
    let echo_b = TaggedEcho::new(b'B');
    let echo_id = k
        .load_instance(signed_boot_manifest("echo-b", &node_key), Box::new(echo_b))
        .expect("echo-b admits");

    // A second Realm-routed target that reflects the commitment slot it received.
    let commitment_echo_id = k
        .load_instance(signed_boot_manifest("commitment-echo", &node_key), Box::new(CommitmentEcho))
        .expect("commitment-echo admits");

    NodeB { kernel: k, echo_id, commitment_echo_id }
}

// ----- node A (booted second; binds realm-gateway with NODE_B in its Realm table) --------------

struct NodeA {
    kernel: Arc<Kernel>,
    probe_id: CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_node_a(abode: &Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeA {
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

    // The realm-gateway: knows Realm "crew" → peer NODE_B. When the probe sends a Realm-addressed
    // envelope, the router dispatches here; this creature unwraps and re-routes as Node(NODE_B, _).
    // A realm-gateway is the `realm-gateway` routing *policy* wrapped by the crate-owned
    // `realm::serve` mechanism (which does the Realm→Node rewrite + byte-preservation).
    let gw = realm::serve(RealmGateway::new(
        RealmGatewayConfig::new().with(RealmId::new("crew"), NodeId(NODE_B.into())),
    ));
    let gw_id = k
        .load_instance(signed_boot_manifest("realm-gateway", &node_key), Box::new(gw))
        .expect("realm-gateway admits");
    k.bind_role(Role::new(Role::REALM_GATEWAY), gw_id);

    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    k.router().subscribe(aether::Topic::new(aether::Topic::PROPRIOCEPTION), probe_id);

    NodeA { kernel: k, probe_id, probe_bus, probe_rx }
}

// =================================================================================================
// The Realm-routing loop test
// =================================================================================================

#[test]
fn realm_local_route() {
    // One Abode key (signs creature authorship across both nodes — same Realm == same authorship
    // trust); two per-node transport keys (node identity stays distinct from Abode).
    let abode = Ed25519KeyMaterial::from_seed([0x08u8; 32]).unwrap();
    let node_a_key = Ed25519KeyMaterial::from_seed([0xAAu8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xBBu8; 32]).unwrap();

    // Boot B first so A can address B's Creature(echo_id) when the realm-gateway translates the
    // Realm envelope. Same boot order as distributor_cross_node.
    let b = boot_node_b(&abode, node_b_key);
    let a = boot_node_a(&abode, node_a_key);

    // Gate on peer_connected: transport-tcp silently drops envelopes addressed to a not-yet-
    // connected peer (the dial/handshake takes a moment), and there's no point racing the test.
    let handshake_ok =
        wait_for_peer_event(&a.probe_rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5)));
    assert!(
        handshake_ok,
        "A↔B transport handshake must complete before issuing the Realm envelope"
    );

    // The key Realm-routing dispatch: Realm("crew", Creature(echo_id on B)). The router dispatches
    // to realm-gateway on A; realm-gateway rewrites to Node(NODE_B, echo_id); transport ships;
    // B delivers locally.
    let corr = 1u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Realm {
                    realm: RealmId::new("crew"),
                    target: Box::new(Address::Creature(b.echo_id)),
                },
                b"hello-realm".to_vec(),
            )
            .with_reply_to(Address::Creature(a.probe_id))
            .with_corr(corr)
            .with_schema("test"),
        )
        .expect("Realm envelope admits + dispatches to A's realm-gateway");

    // The reply must be tagged 'B' (proves it came from echo_b on the peer node) and contain the
    // reversed payload. The reply path: echo_b(reverse) → transport_b(ship) → transport_a(deliver)
    // → probe_a. corr preserved end-to-end.
    let reply = recv_match(
        &a.probe_rx,
        corr,
        |e| !e.payload.is_empty() && e.payload[0] == b'B',
        scaled(Duration::from_secs(8)),
    )
    .expect("echo_b reply arrives across the wire on the same corr");

    let reversed: Vec<u8> = b"hello-realm".iter().copied().rev().collect();
    let mut expected = vec![b'B'];
    expected.extend_from_slice(&reversed);
    assert_eq!(reply.payload, expected, "Realm-routing loop closed: tagged 'B' + reversed payload");

    // ---- A Realm envelope carrying a commitment keeps it across the gateway + the wire ----
    // The commitment-echo on B answers with whatever commitment it received, so a match proves the
    // slot survived realm-gateway's Realm→Node rewrite AND transport's serialize/deliver hop. The
    // probe→gateway send propagates `Dispatch.commitment` into the header (bus seal), so this is the
    // full end-to-end path, not just the in-creature rewrite (which the realm-gateway unit covers).
    let commit_corr = 2u64;
    let commitment = "commit-realm-xyz-789";
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Realm {
                    realm: RealmId::new("crew"),
                    target: Box::new(Address::Creature(b.commitment_echo_id)),
                },
                b"with-commitment".to_vec(),
            )
            .with_reply_to(Address::Creature(a.probe_id))
            .with_corr(commit_corr)
            .with_commitment(commitment)
            .with_schema("test"),
        )
        .expect("commitment-carrying Realm envelope dispatches to A's realm-gateway");

    let commit_reply = recv_match(
        &a.probe_rx,
        commit_corr,
        |e| !e.payload.is_empty(),
        scaled(Duration::from_secs(8)),
    )
    .expect("commitment-echo reply arrives across the wire on the same corr");
    assert_eq!(
        commit_reply.payload,
        commitment.as_bytes(),
        "the commitment slot survived realm-gateway's Realm→Node rewrite + the transport hop (M8-12)"
    );

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
