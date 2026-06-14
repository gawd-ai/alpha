//! **Cross-node sender authentication, end-to-end (B4).**
//!
//! A node has one ed25519 identity: it signs its bus envelopes with the *same* key it authenticates
//! transport links with. So a peer that authenticated this node at the handshake can verify the
//! envelopes it signs. The receiving transport does exactly that, at the wire boundary (before it
//! reseals `from`), and stamps the proven [`Origin`](aether::Origin) onto the delivered frame plus a
//! non-enforcing [`OriginVerdict`](aether::OriginVerdict) on `PROPRIOCEPTION`.
//!
//! These tests prove the parts only a *real two-node channel* can:
//! - `cross_node_traffic_is_verified_and_attributed` — A→B over TCP: B's transport verifies the
//!   signature under the key it authenticated and stamps `origin = node-A`; the recipient sees it and
//!   B publishes a `Verified` verdict.
//! - `a_mismatched_bus_signer_is_flagged_bad_sig_at_the_peer` — a node whose bus signer is *not* its
//!   link key (a misconfigured/compromised signer) is caught: B reconstructs the signed bytes, the
//!   signature fails under the authenticated key, and B publishes `BadSig` — content-signing doing
//!   real work over the (otherwise plaintext) channel.
//! - `policy_origin_forgets_a_peer_on_a_bad_verdict` — the injected `policy-origin` creature closes
//!   the loop in-process: a non-`Verified` verdict drives the reversible `TransportCtl::Forget`.
//! - `local_traffic_carries_no_origin` — a same-node send is `origin: None` (consumers read that as
//!   "Local"); the transport never invents an origin for local traffic.
//!
//! The per-verdict matrix (BadSig / Unresolved / replay drop / forget mechanics) is unit-tested in
//! `transport-tcp` and `policy-origin`; here we prove the wiring holds over the real socket.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, BusHandle, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier, InboxReceiver, NodeId,
    Origin, OriginEvent, OriginVerdict, Role, Topic, ORIGIN_EVENT_SCHEMA,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use policy_origin::OriginDefense;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};
use transport_tcp::{
    PeerConfig, PeerEvent, TransportConfig, TransportCtl, TransportCtlReply, TransportTcp,
    CTL_SCHEMA,
};

const NODE_A: &str = "node-A";
const NODE_B: &str = "node-B";

fn free_loopback_pair() -> (u16, u16) {
    let a = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port A");
    let b = TcpListener::bind("127.0.0.1:0").expect("reserve loopback port B");
    let ports = (a.local_addr().unwrap().port(), b.local_addr().unwrap().port());
    drop((a, b));
    ports
}

fn boot_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

/// A kernel whose bus signer **is** its ed25519 node identity (the unification under test), with the
/// permissive dev policy so admission isn't the subject. `set_node_identity` makes the router's
/// local verify-on-route real too.
fn node_kernel(node_key: &Ed25519KeyMaterial) -> Arc<Kernel> {
    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(node_key.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(DevPolicy),
        128,
    );
    k.set_node_identity(node_key.public_hex().to_string());
    k
}

/// A kernel whose bus signer is a **different** key than its declared node identity — a node that
/// signs its envelopes with the wrong key. Its frames will not verify under the key a peer
/// authenticates at the handshake.
fn mismatched_kernel(bus_key: &Ed25519KeyMaterial) -> Arc<Kernel> {
    let k = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(bus_key.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(DevPolicy),
        128,
    );
    k.set_node_identity(bus_key.public_hex().to_string());
    k
}

struct KernelCleanup {
    kernels: Vec<Arc<Kernel>>,
}
impl KernelCleanup {
    fn new() -> Self {
        KernelCleanup { kernels: Vec::new() }
    }
    fn push(&mut self, k: &Arc<Kernel>) {
        self.kernels.push(k.clone());
    }
}
impl Drop for KernelCleanup {
    fn drop(&mut self) {
        for k in &self.kernels {
            k.shutdown_all(Deadline::from_millis(2000));
        }
    }
}

fn wait_for_peer_event(rx: &InboxReceiver, peer: &str, event: &str, budget: Duration) -> bool {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(env) if env.header.schema == "peer_event" => {
                if let Ok(ev) = serde_json::from_slice::<PeerEvent>(&env.payload) {
                    if ev.peer == peer && ev.event == event {
                        return true;
                    }
                }
            }
            Ok(_) => continue,
            Err(_) => return false,
        }
    }
    false
}

/// Wait for the transport's origin verdict for `peer` on the PROPRIOCEPTION stream.
fn wait_for_origin_verdict(
    rx: &InboxReceiver,
    peer: &str,
    budget: Duration,
) -> Option<OriginEvent> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(env) if env.header.schema == ORIGIN_EVENT_SCHEMA => {
                if let Ok(ev) = serde_json::from_slice::<OriginEvent>(&env.payload) {
                    if ev.origin_node.0 == peer {
                        return Some(ev);
                    }
                }
            }
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
    None
}

fn recv_with_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<aether::Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            Ok(_) => continue,
            Err(_) => return None,
        }
    }
    None
}

/// Boot a node's transport: load it with the attestation grant and bind it to `Role::TRANSPORT`.
fn boot_transport(k: &Kernel, cfg: TransportConfig) {
    let t = k
        .load_transport_instance(boot_manifest("transport-tcp"), Box::new(TransportTcp::new(cfg)))
        .expect("transport admits");
    k.bind_role(Role::new(Role::TRANSPORT), t);
}

#[test]
fn cross_node_traffic_is_verified_and_attributed() {
    let mut cleanup = KernelCleanup::new();
    let (port_a, port_b) = free_loopback_pair();
    let key_a = Ed25519KeyMaterial::from_seed([0xA1; 32]).unwrap();
    let key_b = Ed25519KeyMaterial::from_seed([0xB2; 32]).unwrap();

    // A: passive (B dials it).
    let k_a = node_kernel(&key_a);
    cleanup.push(&k_a);
    boot_transport(
        &k_a,
        TransportConfig {
            self_key: key_a.clone(),
            self_node: NodeId(NODE_A.into()),
            listen_addr: format!("127.0.0.1:{port_a}"),
            peers: vec![PeerConfig {
                node_id: NodeId(NODE_B.into()),
                pubkey_hex: key_b.public_hex().to_string(),
                dial_addr: None,
            }],
        },
    );
    let (_probe_a, bus_a, _rx_a) = k_a.open_endpoint(Capabilities::default());

    // B: dials A; has a target creature + a PROPRIOCEPTION observer.
    let k_b = node_kernel(&key_b);
    cleanup.push(&k_b);
    boot_transport(
        &k_b,
        TransportConfig {
            self_key: key_b.clone(),
            self_node: NodeId(NODE_B.into()),
            listen_addr: format!("127.0.0.1:{port_b}"),
            peers: vec![PeerConfig {
                node_id: NodeId(NODE_A.into()),
                pubkey_hex: key_a.public_hex().to_string(),
                dial_addr: Some(format!("127.0.0.1:{port_a}")),
            }],
        },
    );
    let (target_b, _bus_tb, rx_target) = k_b.open_endpoint(Capabilities::default());
    let (events_b, _bus_eb, rx_events) = k_b.open_endpoint(Capabilities::default());
    k_b.subscribe(Topic::new(Topic::PROPRIOCEPTION), events_b);

    assert!(
        wait_for_peer_event(&rx_events, NODE_A, "peer_connected", Duration::from_secs(10)),
        "B did not observe A connecting"
    );

    // A sends to a creature on B over the authenticated channel.
    bus_a
        .send(
            Dispatch::to(Address::Node(NodeId(NODE_B.into()), target_b), b"hello".to_vec())
                .with_corr(7),
        )
        .expect("send A→B");

    // The recipient on B sees the frame stamped with the authenticated origin.
    let delivered = recv_with_corr(&rx_target, 7, Duration::from_secs(10))
        .expect("the cross-node frame reached the target on B");
    assert_eq!(
        delivered.header.origin,
        Some(Origin::node(NodeId(NODE_A.into()))),
        "the delivered frame is attributed to the authenticated peer node-A"
    );

    // And B publishes a Verified verdict for node-A.
    let verdict = wait_for_origin_verdict(&rx_events, NODE_A, Duration::from_secs(10))
        .expect("B published an origin verdict for node-A");
    assert_eq!(verdict.verdict, OriginVerdict::Verified);
    assert_eq!(verdict.target, target_b);
}

#[test]
fn a_mismatched_bus_signer_is_flagged_bad_sig_at_the_peer() {
    let mut cleanup = KernelCleanup::new();
    let (port_a, port_b) = free_loopback_pair();
    // A's *link* identity is key_a; its *bus signer* is a different key — so its envelopes won't
    // verify under the pubkey B authenticated at the handshake.
    let key_a = Ed25519KeyMaterial::from_seed([0xA1; 32]).unwrap();
    let bus_key_a = Ed25519KeyMaterial::from_seed([0xCC; 32]).unwrap();
    let key_b = Ed25519KeyMaterial::from_seed([0xB2; 32]).unwrap();

    let k_a = mismatched_kernel(&bus_key_a);
    cleanup.push(&k_a);
    boot_transport(
        &k_a,
        TransportConfig {
            self_key: key_a.clone(), // the handshake still proves key_a
            self_node: NodeId(NODE_A.into()),
            listen_addr: format!("127.0.0.1:{port_a}"),
            peers: vec![PeerConfig {
                node_id: NodeId(NODE_B.into()),
                pubkey_hex: key_b.public_hex().to_string(),
                dial_addr: None,
            }],
        },
    );
    let (_probe_a, bus_a, _rx_a) = k_a.open_endpoint(Capabilities::default());

    let k_b = node_kernel(&key_b);
    cleanup.push(&k_b);
    boot_transport(
        &k_b,
        TransportConfig {
            self_key: key_b.clone(),
            self_node: NodeId(NODE_B.into()),
            listen_addr: format!("127.0.0.1:{port_b}"),
            peers: vec![PeerConfig {
                node_id: NodeId(NODE_A.into()),
                pubkey_hex: key_a.public_hex().to_string(),
                dial_addr: Some(format!("127.0.0.1:{port_a}")),
            }],
        },
    );
    let (target_b, _bus_tb, _rx_target) = k_b.open_endpoint(Capabilities::default());
    let (events_b, _bus_eb, rx_events) = k_b.open_endpoint(Capabilities::default());
    k_b.subscribe(Topic::new(Topic::PROPRIOCEPTION), events_b);

    assert!(
        wait_for_peer_event(&rx_events, NODE_A, "peer_connected", Duration::from_secs(10)),
        "B did not observe A connecting"
    );

    bus_a
        .send(
            Dispatch::to(Address::Node(NodeId(NODE_B.into()), target_b), b"hello".to_vec())
                .with_corr(9),
        )
        .expect("send A→B");

    let verdict = wait_for_origin_verdict(&rx_events, NODE_A, Duration::from_secs(10))
        .expect("B published an origin verdict for node-A");
    assert_eq!(
        verdict.verdict,
        OriginVerdict::BadSig,
        "a frame signed with the wrong key is caught as BadSig, not waved through"
    );
}

#[test]
fn policy_origin_forgets_a_peer_on_a_bad_verdict() {
    // In-process: prove the verdict→policy→action loop wires up — a BadSig verdict drives
    // policy-origin to pull the reversible Forget lever, and the transport drops the peer.
    let mut cleanup = KernelCleanup::new();
    // A real but never-answered dial target so "ghost" enters the member set with a dial address.
    let (ghost_port, _b) = free_loopback_pair();
    let key = Ed25519KeyMaterial::from_seed([0x5A; 32]).unwrap();
    let ghost_key = Ed25519KeyMaterial::from_seed([0x60; 32]).unwrap();

    let k = node_kernel(&key);
    cleanup.push(&k);
    boot_transport(
        &k,
        TransportConfig {
            self_key: key.clone(),
            self_node: NodeId("self".into()),
            listen_addr: "127.0.0.1:0".into(),
            peers: vec![PeerConfig {
                node_id: NodeId("ghost".into()),
                pubkey_hex: ghost_key.public_hex().to_string(),
                dial_addr: Some(format!("127.0.0.1:{ghost_port}")),
            }],
        },
    );

    // Load the reference defense policy (forget on the first non-Verified verdict) + subscribe it.
    let policy = k
        .load_instance(
            boot_manifest("policy-origin"),
            Box::new(OriginDefense::new().with_threshold(1)),
        )
        .expect("policy-origin admits");
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), policy);

    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    // "ghost" starts in the member set.
    assert!(
        members(&bus, probe, &rx, 1).contains(&"ghost".to_string()),
        "ghost is a configured member before the verdict"
    );

    // Inject a BadSig verdict for "ghost" onto PROPRIOCEPTION (as the transport would on a forged
    // frame). policy-origin consumes it and emits Forget to the transport.
    let ev = OriginEvent {
        origin_node: NodeId("ghost".into()),
        target: probe,
        corr: None,
        verdict: OriginVerdict::BadSig,
    };
    bus.send(
        Dispatch::to(
            Address::Topic(Topic::new(Topic::PROPRIOCEPTION)),
            serde_json::to_vec(&ev).unwrap(),
        )
        .with_schema(ORIGIN_EVENT_SCHEMA),
    )
    .expect("publish verdict");

    // The peer is forgotten (poll: the policy + the Forget op are async).
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut corr = 2;
    let forgotten = loop {
        if !members(&bus, probe, &rx, corr).contains(&"ghost".to_string()) {
            break true;
        }
        if std::time::Instant::now() > deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(50));
        corr += 1;
    };
    assert!(forgotten, "policy-origin's Forget dropped ghost from the member set");
}

/// Query the transport's member node-ids via a `TransportCtl::Members` round-trip.
fn members(
    bus: &BusHandle,
    _probe: aether::CreatureId,
    rx: &InboxReceiver,
    corr: u64,
) -> Vec<String> {
    bus.send(
        Dispatch::to(Address::Role(Role::new(Role::TRANSPORT)), TransportCtl::Members.to_bytes())
            .with_schema(CTL_SCHEMA)
            .with_corr(corr),
    )
    .expect("send Members");
    match recv_with_corr(rx, corr, Duration::from_secs(2))
        .and_then(|e| TransportCtlReply::parse(&e.payload))
    {
        Some(TransportCtlReply::Members { members, .. }) => {
            members.into_iter().map(|m| m.node_id).collect()
        }
        _ => Vec::new(),
    }
}

#[test]
fn local_traffic_carries_no_origin() {
    let key = Ed25519KeyMaterial::from_seed([0x7C; 32]).unwrap();
    let k = node_kernel(&key);
    let (target, _bus_t, rx) = k.open_endpoint(Capabilities::default());
    let (_sender, bus, _rx_s) = k.open_endpoint(Capabilities::default());
    bus.send(Dispatch::to(Address::Creature(target), b"local".to_vec()).with_corr(3))
        .expect("local send");
    let env = recv_with_corr(&rx, 3, Duration::from_secs(2)).expect("local frame delivered");
    assert_eq!(env.header.origin, None, "same-node traffic has no cross-node origin");
    k.shutdown_all(Deadline::from_millis(1000));
}
