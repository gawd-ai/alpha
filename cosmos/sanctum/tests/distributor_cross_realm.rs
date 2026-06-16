//! **Cross-Realm placement over `transport-tcp`** — Beat B.
//!
//! Two Sanctums in two Realms on static ports `19_964 / 19_965`: A in Realm `crew`, B in Realm
//! `guests`. Where `distributor_cross_node` proves placement across *Nodes within one Realm* (Node
//! grain), this proves placement across a *Realm boundary* (Omega grain) — an agent is embodied on a
//! peer Realm's Sanctum and an Intent is routed to it, which is the embodiment half of the v0.5.0
//! "AIs interacting across the mesh" story.
//!
//! Topology (deliberately minimal):
//! - **A** (`crew`): transport + registry + `omega-federator` (OMEGA_GATEWAY, mapping `guests`→B) +
//!   `distributor-requirements` (`with_realm(crew)`, `with_peer_realm_advertisers([(guests, adv_B)])`,
//!   no local advertisers) + a probe.
//! - **B** (`guests`): transport + the placement target `echo_B` + an `embodiment-advertiser`
//!   `in_realm(guests)` advertising `echo_B`. B needs no federator of its own here: A's federator
//!   forwards the Omega-addressed Query/Intent as a plain `Node(B, …)` delivery, and B's answers ride
//!   `reply_to` back over the same transport link.
//!
//! Flow:
//! 1. The probe on A issues `Intent{outcome, requirements:["cpu >= 4"]}` to the bound distributor.
//! 2. A's distributor fans a placement Query to `Address::Omega{guests, Creature(adv_B)}`; A's
//!    federator routes it into Realm `guests` to `adv_B` on B.
//! 3. `adv_B` answers with the `echo_B` offer tagged Realm `guests`; the answer rides `reply_to` back
//!    to A's distributor.
//! 4. A's distributor reconciles and routes the Intent via `Address::Omega{guests, Node(B, echo_B)}`;
//!    A's federator forwards it into `guests`; `echo_B` receives it and replies.
//! 5. The reply (tagged 'B', payload reversed) returns to the probe on A. Cross-Realm placement closed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    Intent, NodeId, Outcome, RealmId, Role, StubSigner,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use distributor_requirements::{Distributor, PickModel};
use embodiment_advertiser::{EmbodimentAdvertiser, OfferEntry};
use omega_federator::{FederatorConfig, OmegaFederator};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use seer::topics::placement;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

const PORT_A: u16 = 19_964;
const PORT_B: u16 = 19_965;
const NODE_A: &str = "xrealm-A";
const NODE_B: &str = "xrealm-B";
const REALM_A: &str = "crew";
const REALM_B: &str = "guests";

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
        Arc::new(StubSigner::new("xrealm")),
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

/// Tagged echo: replies with `tag + payload reversed`. The placement target.
struct TaggedEcho {
    tag: u8,
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

// ----- node B (Realm `guests`; booted first; lends adv_B id to A) -------------------------------

struct NodeB {
    kernel: Arc<Kernel>,
    advertiser_id: CreatureId,
}

fn boot_node_b(node_key: Ed25519KeyMaterial) -> NodeB {
    let allowlist = vec![node_key.public_hex().to_string()];
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

    // The placement target living on the peer Realm.
    let echo_b_id = k
        .load_instance(
            signed_boot_manifest("echo-b", &node_key),
            Box::new(TaggedEcho { tag: b'B' }),
        )
        .expect("echo-b admits");

    // B's advertiser declares it's in Realm `guests` and offers echo_b at cpu:4.
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
    )
    .in_realm(RealmId::new(REALM_B));
    let advertiser_id = k
        .load_instance(signed_boot_manifest("embodiment-advertiser", &node_key), Box::new(adv_b))
        .expect("B advertiser admits");

    NodeB { kernel: k, advertiser_id }
}

// ----- node A (Realm `crew`; the distributor + federator side) ----------------------------------

struct NodeA {
    kernel: Arc<Kernel>,
    probe_id: CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_node_a(node_key: Ed25519KeyMaterial, b_advertiser_id: CreatureId) -> NodeA {
    let allowlist = vec![node_key.public_hex().to_string()];
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

    // Registry (the federator wants a local registry id) + federator mapping `guests` → B.
    let registry_id = k
        .load_instance(
            signed_boot_manifest("registry-mem", &node_key),
            Box::new(RegistryMem::new()),
        )
        .expect("A registry admits");
    k.bind_role(Role::new(Role::REGISTRY), registry_id);

    let mut realm_to_peer = HashMap::new();
    realm_to_peer.insert(RealmId::new(REALM_B), NodeId(NODE_B.into()));
    let federator = OmegaFederator::new(FederatorConfig {
        self_node: NodeId(NODE_A.into()),
        self_realm: RealmId::new(REALM_A),
        local_registry: registry_id,
        abode_key: Ed25519KeyMaterial::from_seed([0xA9; 32]).unwrap(),
        realm_to_peer,
        weigher: Box::new(RoundRobinReputation::new()),
    });
    let federator_id = k
        .load_instance(signed_boot_manifest("omega-federator", &node_key), Box::new(federator))
        .expect("A federator admits");
    k.bind_role(Role::new(Role::OMEGA_GATEWAY), federator_id);

    // The distributor: no local advertisers — its only advertiser is across the Realm boundary.
    let distributor =
        Distributor::new(NodeId(NODE_A.into()), vec![], vec![], PickModel::FirstFit, 10_000)
            .with_realm(RealmId::new(REALM_A))
            .with_peer_realm_advertisers(vec![(RealmId::new(REALM_B), b_advertiser_id)]);
    let distributor_id = k
        .load_instance(
            signed_boot_manifest("distributor-requirements", &node_key),
            Box::new(distributor),
        )
        .expect("A distributor admits");
    k.bind_role(Role::new(Role::DISTRIBUTOR), distributor_id);

    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    k.router().subscribe(aether::Topic::new(aether::Topic::PROPRIOCEPTION), probe_id);

    NodeA { kernel: k, probe_id, probe_bus, probe_rx }
}

#[test]
fn distributor_places_across_a_realm_boundary() {
    let node_a_key = Ed25519KeyMaterial::from_seed([0xAAu8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xBBu8; 32]).unwrap();

    // Boot B first so we can hand A the advertiser id for its cross-Realm advertiser table.
    let b = boot_node_b(node_b_key);
    let a = boot_node_a(node_a_key, b.advertiser_id);

    assert!(
        wait_for_peer_event(&a.probe_rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5))),
        "A↔B transport handshake must complete before the cross-Realm consult"
    );

    let intent_corr = 1u64;
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Intent(Intent {
                    outcome: "reverse-string".into(),
                    requirements: vec!["cpu >= 4".into()],
                }),
                b"hello-cross-realm".to_vec(),
            )
            .with_reply_to(Address::Creature(a.probe_id))
            .with_corr(intent_corr),
        )
        .expect("Intent admits + routes to A's bound distributor");

    // The reply must come from echo_B (tag 'B'), reversed — proving the Intent reached a creature on
    // the peer Realm via Omega placement and the reply returned to the original requester on A.
    let reply = recv_match(
        &a.probe_rx,
        intent_corr,
        |e| !e.payload.is_empty() && e.payload[0] == b'B',
        scaled(Duration::from_secs(10)),
    )
    .expect("echo_B reply arrives across the Realm boundary on the same corr");

    let reversed: Vec<u8> = b"hello-cross-realm".iter().copied().rev().collect();
    let mut expected = vec![b'B'];
    expected.extend_from_slice(&reversed);
    assert_eq!(
        reply.payload, expected,
        "cross-Realm placement loop closed: Intent placed on a `guests` Sanctum, reply tagged 'B'"
    );

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
