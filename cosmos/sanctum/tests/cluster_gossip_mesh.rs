//! **Dynamic clustering: a many-to-many mesh self-forms from one seed, over real TCP.**
//!
//! Three Sanctums, each running `transport-tcp` in **gossip (cluster) mode**. Node A is the seed; B
//! and C are configured only with A as their seed (they know how to reach A, nothing else). The
//! operator introduces B and C to A once each (the `Connect` control op — the allow-AI-gated cluster
//! join in production). From there **gossip completes the mesh**: A tells B about C and C about B,
//! they dial each other, and all three converge to a full mesh — no node was pre-configured with all
//! its peers (the O(N²) static config this replaces).
//!
//! Exit: every node's `Members` query reports the other two as connected.
//!
//! Ephemeral loopback ports (reserved up front, like `m2_two_node`), so parallel `cargo test` doesn't
//! collide.

use std::net::TcpListener;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, InboxReceiver, NodeId, Role, StubSigner,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{
    PeerConfig, TransportConfig, TransportCtl, TransportCtlReply, TransportTcp, CTL_SCHEMA,
};

fn free_loopback_ports(n: usize) -> Vec<u16> {
    let ls: Vec<TcpListener> =
        (0..n).map(|_| TcpListener::bind("127.0.0.1:0").expect("reserve port")).collect();
    ls.iter().map(|l| l.local_addr().unwrap().port()).collect()
}

fn kernel(allowed: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("cluster")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed)),
        128,
    )
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

struct Node {
    kernel: Arc<Kernel>,
    transport: CreatureId,
    probe: CreatureId,
    bus: BusHandle,
    rx: InboxReceiver,
}

/// Boot a node: a transport in gossip mode (advertising `addr`), with optional seed peers, plus a
/// probe endpoint to drive control ops.
fn boot(node_id: &str, key: &Ed25519KeyMaterial, addr: &str, seeds: Vec<PeerConfig>) -> Node {
    let k = kernel(vec![key.public_hex().to_string()]);
    let cfg = TransportConfig {
        self_key: key.clone(),
        self_node: NodeId(node_id.into()),
        listen_addr: addr.into(),
        peers: seeds,
    };
    let transport = k
        .load_instance(
            signed_boot_manifest("transport-tcp", key),
            Box::new(TransportTcp::new(cfg).with_gossip(Some(addr.into()))),
        )
        .expect("transport admits");
    k.bind_role(Role::new(Role::TRANSPORT), transport);
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    Node { kernel: k, transport, probe, bus, rx }
}

/// Send a control op to `node`'s transport and wait (bounded) for its correlated reply.
fn ctl(node: &Node, op: TransportCtl, corr: u64, budget: Duration) -> Option<TransportCtlReply> {
    node.bus
        .send(
            Dispatch::to(Address::Creature(node.transport), op.to_bytes())
                .with_schema(CTL_SCHEMA)
                .with_corr(corr)
                .with_reply_to(Address::Creature(node.probe)),
        )
        .ok()?;
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match node.rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) => {
                return TransportCtlReply::parse(&env.payload)
            }
            _ => continue,
        }
    }
    None
}

/// How many of this node's known members are currently connected.
fn connected_count(node: &Node, corr: u64) -> usize {
    match ctl(node, TransportCtl::Members, corr, Duration::from_secs(2)) {
        Some(TransportCtlReply::Members { members, .. }) => {
            members.iter().filter(|m| m.connected).count()
        }
        _ => 0,
    }
}

#[test]
fn three_nodes_self_form_a_full_mesh_from_one_seed() {
    let ports = free_loopback_ports(3);
    let (pa, pb, pc) = (ports[0], ports[1], ports[2]);
    let addr = |p: u16| format!("127.0.0.1:{p}");

    let ka = Ed25519KeyMaterial::from_seed([0xA1; 32]).unwrap();
    let kb = Ed25519KeyMaterial::from_seed([0xB2; 32]).unwrap();
    let kc = Ed25519KeyMaterial::from_seed([0xC3; 32]).unwrap();

    // The seed peer entry every newcomer is handed: how to reach + authenticate A.
    let seed_a = PeerConfig {
        node_id: NodeId("A".into()),
        pubkey_hex: ka.public_hex().to_string(),
        dial_addr: Some(addr(pa)),
    };

    // A is the seed (knows no one yet); B and C know only A.
    let a = boot("A", &ka, &addr(pa), vec![]);
    let b = boot("B", &kb, &addr(pb), vec![seed_a.clone()]);
    let c = boot("C", &kc, &addr(pc), vec![seed_a]);

    // The operator introduces B and C to A (the cluster join). A admits + dials each; from here gossip
    // tells B about C and C about B, and the mesh completes itself.
    assert!(
        matches!(
            ctl(
                &a,
                TransportCtl::Connect {
                    node_id: "B".into(),
                    pubkey_hex: kb.public_hex().to_string(),
                    addr: addr(pb),
                },
                1,
                Duration::from_secs(3),
            ),
            Some(TransportCtlReply::Connecting { .. })
        ),
        "A accepts the introduction of B"
    );
    assert!(
        matches!(
            ctl(
                &a,
                TransportCtl::Connect {
                    node_id: "C".into(),
                    pubkey_hex: kc.public_hex().to_string(),
                    addr: addr(pc),
                },
                2,
                Duration::from_secs(3),
            ),
            Some(TransportCtlReply::Connecting { .. })
        ),
        "A accepts the introduction of C"
    );

    // Converge: every node must end up connected to the other two — proving gossip filled in the
    // edges nobody configured (A↔B and A↔C were introduced; B↔C was discovered).
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut corr = 100u64;
    let meshed = loop {
        corr += 3;
        let ca = connected_count(&a, corr);
        let cb = connected_count(&b, corr + 1);
        let cc = connected_count(&c, corr + 2);
        if ca >= 2 && cb >= 2 && cc >= 2 {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(150));
    };
    assert!(meshed, "the three nodes did not converge to a full mesh from one seed via gossip");

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
    c.kernel.shutdown_all(Deadline::from_millis(1500));
}
