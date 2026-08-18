//! **Arbitrary application traffic across the Omega, over `transport-tcp`.**
//!
//! Static ports `19_962 / 19_963` (one transport-tcp test per file so parallel `cargo test` doesn't
//! collide on the bind). Two Sanctums in two Realms: A in Realm `crew`, B in Realm `guests`. Each
//! runs `transport-tcp` (TRANSPORT), `registry-mem` (REGISTRY — the federator wants a local
//! registry), and `omega-federator` (OMEGA_GATEWAY). B *also* runs a plain application creature —
//! `EchoAgent`, the stand-in for "an agent on a peer Realm": not a system organ, just a creature
//! that answers an envelope on its own schema.
//!
//! What this proves — the v0.5.0 rail, end-to-end over the wire:
//!
//! - An `Address::Omega{realm: guests, target: Creature(echo)}` envelope from A's probe is routed by
//!   A's federator into Realm `guests`, delivered to B's `EchoAgent`, which replies — and the reply
//!   returns to the *original* requester on A. The earlier `omega_federation_cross_node` test proved
//!   Omega routing only for a system `registry.op`; this proves it for **arbitrary application
//!   traffic** (a private schema + payload), which is what two AIs interacting across the mesh need.
//! - The same holds for the `Node(gateway, echo)` target form — the shape a cross-Realm placement
//!   offer carries (it tags the answering Sanctum's node). Both round-trip identically.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, BusHandle, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope,
    InboxReceiver, NodeId, Outcome, RealmId, Role, StubSigner,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use omega_federator::{FederatorConfig, OmegaFederator};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

const PORT_A: u16 = 19_962;
const PORT_B: u16 = 19_963;
const NODE_A: &str = "omega-app-A";
const NODE_B: &str = "omega-app-B";
const REALM_A: &str = "crew";
const REALM_B: &str = "guests";
const APP_SCHEMA: &str = "app.ping";

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

/// A plain application creature — the stand-in for "agent B". Not a registry, not a gateway; it just
/// answers an application envelope on [`APP_SCHEMA`] by replying `pong:<payload>` to the request's
/// `reply_to` (the original requester, preserved across the Omega gateway *and* the transport
/// reply_to rewrite). The simplest possible "receive a turn, answer it" creature.
struct EchoAgent;

impl Creature for EchoAgent {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != APP_SCHEMA {
            return Outcome::none();
        }
        let mut reply = b"pong:".to_vec();
        reply.extend_from_slice(&env.payload);
        Outcome::reply(&env, reply)
    }
}

fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("omega-app")),
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

struct Node {
    kernel: Arc<Kernel>,
    echo_id: Option<CreatureId>,
    probe_id: CreatureId,
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
}

/// Boot a node: transport (dialing or passive) + a registry + a federator mapping the peer Realm to
/// the peer node. When `with_echo`, also loads the `EchoAgent` application creature and returns its id.
#[allow(clippy::too_many_arguments)]
fn boot(
    node_id: &str,
    self_realm: &str,
    port: u16,
    node_key: Ed25519KeyMaterial,
    peer_node: &str,
    peer_pub: &Ed25519KeyMaterial,
    peer_realm: &str,
    peer_port: u16,
    dials: bool,
    abode_key: Ed25519KeyMaterial,
    with_echo: bool,
) -> Node {
    let allowed = vec![node_key.public_hex().to_string()];
    let k = kernel(allowed);
    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    if dials {
        k.router().subscribe(aether::Topic::new(aether::Topic::PROPRIOCEPTION), probe_id);
    }

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

    let registry_id = k
        .load_instance(
            signed_boot_manifest("registry-mem", &node_key),
            Box::new(RegistryMem::new()),
        )
        .expect("registry admits");
    k.bind_role(Role::new(Role::REGISTRY), registry_id);

    let mut realm_to_peer = HashMap::new();
    realm_to_peer.insert(RealmId::new(peer_realm), NodeId(peer_node.into()));
    let federator = OmegaFederator::new(FederatorConfig {
        self_node: NodeId(node_id.into()),
        self_realm: RealmId::new(self_realm),
        local_registry: registry_id,
        abode_key,
        realm_to_peer,
        weigher: Box::new(RoundRobinReputation::new()),
    });
    let federator_id = k
        .load_instance(signed_boot_manifest("omega-federator", &node_key), Box::new(federator))
        .expect("federator admits");
    k.bind_role(Role::new(Role::OMEGA_GATEWAY), federator_id);

    let echo_id = if with_echo {
        Some(
            k.load_instance(signed_boot_manifest("echo-agent", &node_key), Box::new(EchoAgent))
                .expect("echo agent admits"),
        )
    } else {
        None
    };

    Node { kernel: k, echo_id, probe_id, probe_bus, probe_rx }
}

/// Send an application envelope to `to` and wait for the `pong:` reply matching `corr`.
fn app_roundtrip(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    to: Address,
    payload: &[u8],
    corr: u64,
    budget: Duration,
) -> Option<Vec<u8>> {
    bus.send(
        Dispatch::to(to, payload.to_vec())
            .with_schema(APP_SCHEMA)
            .with_corr(corr)
            .with_reply_to(Address::Creature(probe)),
    )
    .ok()?;
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == APP_SCHEMA => {
                return Some(env.payload);
            }
            _ => continue,
        }
    }
    None
}

#[test]
fn omega_routes_arbitrary_application_traffic_across_realms() {
    let node_a_key = Ed25519KeyMaterial::from_seed([0x1A; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0x1B; 32]).unwrap();
    let abode_a = Ed25519KeyMaterial::from_seed([0x2A; 32]).unwrap();
    let abode_b = Ed25519KeyMaterial::from_seed([0x2B; 32]).unwrap();

    // B boots first (A dials B); B carries the EchoAgent (the agent living on the peer Realm).
    let b = boot(
        NODE_B,
        REALM_B,
        PORT_B,
        node_b_key.clone(),
        NODE_A,
        &node_a_key,
        REALM_A,
        PORT_A,
        false,
        abode_b,
        true,
    );
    let echo_id = b.echo_id.expect("B booted the echo agent");

    // A boots second and dials B.
    let a = boot(
        NODE_A,
        REALM_A,
        PORT_A,
        node_a_key.clone(),
        NODE_B,
        &node_b_key,
        REALM_B,
        PORT_B,
        true,
        abode_a,
        false,
    );

    // A's probe subscribed before its dialing transport started, so the sender-side writer is ready.
    let probe = a.probe_id;
    let bus = a.probe_bus;
    let rx = a.probe_rx;

    assert!(
        wait_for_peer_event(&rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5))),
        "A↔B handshake must complete before routing application traffic"
    );

    // ---- (1) Omega(guests, Creature(echo)): an application envelope reaches the agent on the peer
    //      Realm and the reply comes back to A's probe. ----
    let reply = app_roundtrip(
        &bus,
        &rx,
        probe,
        Address::Omega {
            realm: RealmId::new(REALM_B),
            target: Box::new(Address::Creature(echo_id)),
        },
        b"hello",
        1,
        scaled(Duration::from_secs(8)),
    );
    assert_eq!(
        reply.as_deref(),
        Some(b"pong:hello".as_slice()),
        "an Omega(guests, Creature(echo)) application envelope must reach B's EchoAgent and the reply must return to A"
    );

    // ---- (2) Omega(guests, Node(NODE_B, echo)): the placement-offer target form round-trips too. ----
    let reply = app_roundtrip(
        &bus,
        &rx,
        probe,
        Address::Omega {
            realm: RealmId::new(REALM_B),
            target: Box::new(Address::Node(NodeId(NODE_B.into()), echo_id)),
        },
        b"world",
        2,
        scaled(Duration::from_secs(8)),
    );
    assert_eq!(
        reply.as_deref(),
        Some(b"pong:world".as_slice()),
        "an Omega(guests, Node(gateway, echo)) application envelope must round-trip the same way"
    );

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
