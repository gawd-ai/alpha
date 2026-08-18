//! **Cross-node `Steer{abort}`**: a SEER `Steer` envelope crossing `transport-tcp`
//! aborts a pending SEER exchange on a *remote* node.
//!
//! `seer_steer_abort.rs` proves `Steer{abort}` single-Sanctum and topic-agnostic. The cross-node
//! suites (`distributor_cross_node` / `realm_local_route` / `omega_federation_cross_node`) prove
//! that a placement/route *match* crosses the wire — but none proves a *Steer* does.
//! Steer is "routed like any envelope (by address)"; the load-bearing consequence is that it must
//! abort a parked exchange on a peer exactly as it does locally. This test closes that gap.
//!
//! Static ports `19_970 / 19_971` (distinct from the other cross-node suites — one transport-tcp test
//! per file so a parallel `cargo test` doesn't collide on the bind). Flow:
//!
//! 1. **B boots first** with transport-tcp + a `PlacementConsumer` (parks a non-trivial REQUEST on a
//!    SEER `Query`, resumes on `Answer`, aborts on `Steer{abort}`). **A boots second** (passive; B
//!    dials in), with the probe.
//! 2. The probe on A waits for `peer_connected`, then sends a non-trivial REQUEST to
//!    `Node(B, consumer)` with `reply_to = Creature(probe)`.
//! 3. B's transport rewrites the inbound `reply_to` to `Node(A, probe)`; B's consumer parks the
//!    exchange and Queries back along it. A reads the `Query` → proof B has parked.
//! 4. A sends `Steer{abort}` on the *same corr* to `Node(B, consumer)`.
//! 5. B's consumer drops the parked exchange and emits a terminal Failed `Answer` to the parked
//!    `reply_to` (`Node(A, probe)`). A reads the terminal Failed → cross-node abort closed.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    NodeId, Outcome, Role, StubSigner,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use seer::{SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

// ----- ports + node identities (distinct from every other transport-tcp test) -------------------

const PORT_A: u16 = 19_970;
const PORT_B: u16 = 19_971;
const NODE_A: &str = "x1-steer-node-A";
const NODE_B: &str = "x1-steer-node-B";
const REQUEST_SCHEMA: &str = "request";

// ----- timing scaffolding (mirrors the other cross-node helpers) --------------------------------

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
        Arc::new(StubSigner::new("x1-steer")),
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

// ----- the consumer (a trimmed copy of seer_steer_abort.rs's PlacementConsumer) -----------------
//
// Parks a non-trivial REQUEST on a SEER Query, resumes on a matching Answer, aborts on a
// Steer{abort}. The terminal envelope is itself an `Answer { query_id: 0 }` (the "no precursor
// query" convention) — success and abort differ only by body. Kept inline per the test-suite
// convention (cross-node tests don't share creatures).
struct PlacementConsumer {
    bound_topic: SeerTopic,
    pending: HashMap<u64, (u64, Address)>, // corr → (query_id, reply_to)
    next_query_id: u64,
}

impl PlacementConsumer {
    fn new(bound_topic: SeerTopic) -> Self {
        PlacementConsumer { bound_topic, pending: HashMap::new(), next_query_id: 0 }
    }
}

impl Creature for PlacementConsumer {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema == REQUEST_SCHEMA {
            return self.on_request(env);
        }
        if env.header.schema != SEER_SCHEMA {
            return Outcome::none();
        }
        let seer = match SeerEnvelope::parse(&env.payload) {
            Ok(o) => o,
            Err(_) => return Outcome::none(),
        };
        if seer.topic != self.bound_topic {
            return Outcome::none();
        }
        match seer.kind {
            SeerKind::Answer { query_id, body } => self.on_answer(seer.corr, query_id, body),
            SeerKind::Steer { kind, .. } => self.on_steer(seer.corr, &kind),
            _ => Outcome::none(),
        }
    }
}

impl PlacementConsumer {
    fn on_request(&mut self, env: Envelope) -> Outcome {
        let corr = env.header.corr.unwrap_or(0);
        // After transport's inbound rewrite this is `Node(A, probe)`, so the Query (and the eventual
        // terminal) route back to the originator across the wire.
        let reply_to = env.reply_target();

        self.next_query_id = self.next_query_id.wrapping_add(1);
        let query_id = self.next_query_id;
        self.pending.insert(corr, (query_id, reply_to.clone()));

        let query = SeerEnvelope::query(
            self.bound_topic,
            corr,
            query_id,
            &serde_json::json!({ "question": String::from_utf8_lossy(&env.payload), "options": ["node-A", "node-B"] }),
        );
        Outcome::send(
            Dispatch::to(reply_to, query.to_bytes()).with_schema(SEER_SCHEMA).with_corr(corr),
        )
    }

    fn on_answer(&mut self, corr: u64, query_id: u64, body: serde_json::Value) -> Outcome {
        let Some((parked_qid, reply_to)) = self.pending.get(&corr).cloned() else {
            return Outcome::none();
        };
        if parked_qid != query_id {
            return Outcome::none();
        }
        self.pending.remove(&corr);
        let terminal = SeerEnvelope::answer(
            self.bound_topic,
            corr,
            0,
            &serde_json::json!({ "placed_to": body, "reason": "answered" }),
        );
        Outcome::send(
            Dispatch::to(reply_to, terminal.to_bytes()).with_schema(SEER_SCHEMA).with_corr(corr),
        )
    }

    fn on_steer(&mut self, corr: u64, verb: &str) -> Outcome {
        if verb != "abort" {
            return Outcome::none(); // ignoring other verbs is contract-compliant
        }
        let Some((_qid, reply_to)) = self.pending.remove(&corr) else {
            return Outcome::none();
        };
        let terminal = SeerEnvelope::answer(
            self.bound_topic,
            corr,
            0,
            &serde_json::json!({ "failed": "aborted", "reason": "steer" }),
        );
        Outcome::send(
            Dispatch::to(reply_to, terminal.to_bytes()).with_schema(SEER_SCHEMA).with_corr(corr),
        )
    }
}

// ----- receive helpers --------------------------------------------------------------------------

fn recv_seer<F: Fn(&SeerEnvelope) -> bool>(
    rx: &InboxReceiver,
    corr: u64,
    pred: F,
    budget: Duration,
) -> Option<SeerEnvelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == SEER_SCHEMA => {
                if let Ok(o) = SeerEnvelope::parse(&env.payload) {
                    if pred(&o) {
                        return Some(o);
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

fn is_query(o: &SeerEnvelope) -> bool {
    matches!(o.kind, SeerKind::Query { .. })
}
fn is_terminal_answer(o: &SeerEnvelope) -> bool {
    matches!(o.kind, SeerKind::Answer { query_id: 0, .. })
}

// ----- node B (booted first; hosts the consumer) ------------------------------------------------

struct NodeB {
    kernel: Arc<Kernel>,
    consumer_id: CreatureId,
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

    let consumer_id = k
        .load_instance(
            signed_boot_manifest("placement-consumer", &node_key),
            Box::new(PlacementConsumer::new(SeerTopic::Placement)),
        )
        .expect("placement consumer admits");

    NodeB { kernel: k, consumer_id }
}

// ----- node A (booted second; the probe + steer driver) -----------------------------------------

struct NodeA {
    kernel: Arc<Kernel>,
    probe_id: CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

fn boot_node_a(abode: &Ed25519KeyMaterial, node_key: Ed25519KeyMaterial) -> NodeA {
    let allowlist = vec![abode.public_hex().to_string(), node_key.public_hex().to_string()];
    let k = kernel(allowlist);

    // `peer_connected` is live, non-replayed evidence; observe it before B can finish dialing A.
    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());
    k.router().subscribe(aether::Topic::new(aether::Topic::PROPRIOCEPTION), probe_id);

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

    NodeA { kernel: k, probe_id, probe_bus, probe_rx }
}

// =================================================================================================

#[test]
fn steer_abort_aborts_a_parked_exchange_on_a_peer_node() {
    let abode = Ed25519KeyMaterial::from_seed([0x10u8; 32]).unwrap();
    let node_a_key = Ed25519KeyMaterial::from_seed([0xAAu8; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xBBu8; 32]).unwrap();

    // B first (B dials A); A second (passive).
    let b = boot_node_b(&abode, node_b_key);
    let a = boot_node_a(&abode, node_a_key);

    let handshake_ok =
        wait_for_peer_event(&a.probe_rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5)));
    assert!(handshake_ok, "A↔B transport handshake must complete before the cross-node REQUEST");

    let corr = 700u64;

    // 1) A → B: a non-trivial REQUEST. B parks + Queries back. reply_to = Creature(probe) is rewritten
    //    to Node(A, probe) by B's transport on receipt, so the Query (and later the terminal) come
    //    home.
    a.probe_bus
        .send(
            Dispatch::to(
                Address::Node(NodeId(NODE_B.into()), b.consumer_id),
                b"place a heavy job".to_vec(),
            )
            .with_schema(REQUEST_SCHEMA)
            .with_reply_to(Address::Creature(a.probe_id))
            .with_corr(corr),
        )
        .expect("REQUEST dispatches to the consumer on B");

    // 2) Wait for the Query to arrive back on A — proof the consumer on B parked the exchange.
    let query = recv_seer(&a.probe_rx, corr, is_query, scaled(Duration::from_secs(8)))
        .expect("Query crosses back from B's consumer (it parked)");
    assert_eq!(query.topic, SeerTopic::Placement);
    let query_id = match query.kind {
        SeerKind::Query { query_id, .. } => query_id,
        other => panic!("expected Query, got {other:?}"),
    };
    assert!(query_id > 0, "the consumer assigned a parked query_id");

    // 3) A → B: Steer{abort} on the same corr. It crosses the wire like any envelope.
    let steer = SeerEnvelope::steer(
        SeerTopic::Placement,
        corr,
        "abort",
        &serde_json::json!({ "reason": "operator changed mind" }),
    );
    a.probe_bus
        .send(
            Dispatch::to(Address::Node(NodeId(NODE_B.into()), b.consumer_id), steer.to_bytes())
                .with_schema(SEER_SCHEMA)
                .with_reply_to(Address::Creature(a.probe_id))
                .with_corr(corr),
        )
        .expect("Steer{abort} dispatches to the consumer on B");

    // 4) B drops the parked exchange and ships a terminal Failed Answer back to A.
    let terminal = recv_seer(&a.probe_rx, corr, is_terminal_answer, scaled(Duration::from_secs(8)))
        .expect("terminal Failed Answer crosses back after the cross-node Steer{abort}");
    assert_eq!(terminal.topic, SeerTopic::Placement);
    match terminal.kind {
        SeerKind::Answer { query_id: 0, body } => {
            assert_eq!(body["failed"], "aborted", "body signals the abort");
            assert_eq!(body["reason"], "steer", "reason names the steer trigger");
        }
        other => panic!("expected terminal Answer{{query_id:0}}, got {other:?}"),
    }

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}
