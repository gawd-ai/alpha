//! **Omega federation over `transport-tcp`.**
//!
//! Static ports `19_960 / 19_961` (distinct from the other cross-node suites — one transport-tcp test
//! per file so parallel `cargo test` doesn't collide on the bind). Two Sanctums in two Realms:
//! A in Realm `crew`, B in Realm `guests`. Each runs `transport-tcp` (TRANSPORT), `registry-mem`
//! (REGISTRY), and `omega-federator` (OMEGA_GATEWAY).
//!
//! What this proves, end-to-end over the wire:
//!
//! 1. **Pull-based anti-entropy** (#2/#3). A pulls Realm `guests` from B; B's artifact `Y` arrives
//!    in A's registry, pinned to `guests`. Then B pulls Realm `crew` from A; A's artifact `X`
//!    arrives in B's registry (the setup for reputation).
//! 2. **Signed reputation propagation** (#4/#7). A federates a `0.95` score for `X` to B over the
//!    SEER consensus topic; B verifies the observer signature, applies the **injected**
//!    `RoundRobinReputation` weigher, and records the score tagged with the attesting Realm `crew`.
//! 3. **Cross-Realm quarantine path** (#8). A federates a quarantine notice for `X` to B; B marks
//!    `X` quarantined in its registry (the path the immune-response reacts to).
//!
//! The admission-gate-holds property (T2, #5) is in `omega_admission_gate_holds.rs` (in-process);
//! the unsigned-delta rejection (#7) is also covered by an `omega-federator` unit test.

use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, InboxReceiver, NodeId, RealmId, Role,
    StubSigner,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use omega_federator::{FederatorConfig, FederatorMsg, OmegaFederator};
use policy_signed::SignedPolicy;
use registry_mem::{RegistryMem, RegistryOp, RegistryReply};
use reputation_roundrobin::RoundRobinReputation;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};
use std::collections::HashMap;
use transport_tcp::{PeerConfig, PeerEvent, TransportConfig, TransportTcp};

const PORT_A: u16 = 19_960;
const PORT_B: u16 = 19_961;
const NODE_A: &str = "m10-fed-A";
const NODE_B: &str = "m10-fed-B";
const REALM_A: &str = "crew";
const REALM_B: &str = "guests";

// ----- timing scaffolding (mirrors the migration cross-node helper) ------------------------------------

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
        Arc::new(StubSigner::new("m10-fed")),
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

/// Send a registry op to `to` and wait for the `registry.reply` matching `corr`. Used both for
/// driving (the federator's realm-scoped Publish is internal; here the probe reads) and for polling.
fn registry_roundtrip(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    to: Address,
    op: RegistryOp,
    corr: u64,
    budget: Duration,
) -> Option<RegistryReply> {
    bus.send(
        Dispatch::to(to, serde_json::to_vec(&op).unwrap())
            .with_schema("registry.op")
            .with_corr(corr)
            .with_reply_to(Address::Creature(probe)),
    )
    .ok()?;
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) if env.header.corr == Some(corr) && env.header.schema == "registry.reply" => {
                return serde_json::from_slice::<RegistryReply>(&env.payload).ok();
            }
            _ => continue,
        }
    }
    None
}

/// Poll a registry (local or cross-node) with `ListEntries` until `pred` is satisfied by the
/// returned entries, or the budget expires. Returns whether it was satisfied. Each poll uses a
/// fresh corr.
#[allow(clippy::too_many_arguments)] // test helper: explicit bus/rx/probe/predicate/budget params
fn poll_entries<F: Fn(&[registry_mem::SyncEntry]) -> bool>(
    bus: &BusHandle,
    rx: &InboxReceiver,
    probe: CreatureId,
    to: Address,
    realm: Option<RealmId>,
    corr_base: u64,
    pred: F,
    budget: Duration,
) -> bool {
    let deadline = std::time::Instant::now() + budget;
    let mut corr = corr_base;
    while std::time::Instant::now() < deadline {
        corr += 1;
        if let Some(RegistryReply::Entries { entries }) = registry_roundtrip(
            bus,
            rx,
            probe,
            to.clone(),
            RegistryOp::ListEntries { realm: realm.clone() },
            corr,
            Duration::from_secs(2),
        ) {
            if pred(&entries) {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

// ----- per-node boot ----------------------------------------------------------------------------

struct Node {
    kernel: Arc<Kernel>,
    registry_id: CreatureId,
    federator_id: CreatureId,
    probe_id: CreatureId,
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
}

/// Boot a node: transport (dialing or passive) + a registry pre-seeded with `seed` + a federator
/// mapping the peer Realm to the peer node.
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
    seed: Option<(RealmId, Manifest, Vec<u8>)>,
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

    // Registry, pre-seeded before boxing (interior mutability via the direct publish_in API).
    let registry = RegistryMem::new();
    if let Some((realm, manifest, bytes)) = seed {
        registry.publish_in(realm, manifest, bytes);
    }
    let registry_id = k
        .load_instance(signed_boot_manifest("registry-mem", &node_key), Box::new(registry))
        .expect("registry admits");
    k.bind_role(Role::new(Role::REGISTRY), registry_id);

    // Federator. We need its local_registry id (known above). realm_to_peer maps the OTHER realm
    // to the peer node so Omega routing + control-op addressing resolve.
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

    Node { kernel: k, registry_id, federator_id, probe_id, probe_bus, probe_rx }
}

// =================================================================================================

#[test]
fn omega_federation_pull_reputation_and_quarantine_across_realms() {
    let node_a_key = Ed25519KeyMaterial::from_seed([0xA0; 32]).unwrap();
    let node_b_key = Ed25519KeyMaterial::from_seed([0xB0; 32]).unwrap();
    let abode_a = Ed25519KeyMaterial::from_seed([0xA9; 32]).unwrap();
    let abode_b = Ed25519KeyMaterial::from_seed([0xB9; 32]).unwrap();

    // Artifacts: X lives in A's Realm (crew), Y in B's Realm (guests).
    let x_bytes = b"artifact-X-from-crew".to_vec();
    let y_bytes = b"artifact-Y-from-guests".to_vec();
    let x_hash = sha256_hex(&x_bytes);
    let y_hash = sha256_hex(&y_bytes);

    // B boots first (A dials B); B seeded with Y@guests.
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
        Some((
            RealmId::new(REALM_B),
            Manifest::new("y", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            y_bytes.clone(),
        )),
    );
    // A boots second, dials B; A seeded with X@crew.
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
        abode_a.clone(),
        Some((
            RealmId::new(REALM_A),
            Manifest::new("x", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            x_bytes.clone(),
        )),
    );

    // A's probe subscribed before its dialing transport started, so the sender-side writer is ready.
    let probe = a.probe_id;
    let bus = a.probe_bus;
    let rx = a.probe_rx;

    assert!(
        wait_for_peer_event(&rx, NODE_B, "peer_connected", scaled(Duration::from_secs(5))),
        "A↔B handshake must complete before federating"
    );

    // ---- (1) Pull anti-entropy: A pulls `guests` from B → A learns Y@guests ----
    bus.send(
        Dispatch::to(
            Address::Creature(a.federator_id),
            FederatorMsg::PullFrom {
                source_realm: RealmId::new(REALM_B),
                peer_node: NodeId(NODE_B.into()),
                peer_registry: b.registry_id,
            }
            .to_bytes(),
        )
        .with_schema(omega_federator::SCHEMA)
        .with_corr(1)
        .with_reply_to(Address::Creature(probe)),
    )
    .expect("PullFrom dispatched on A");

    let a_has_y = poll_entries(
        &bus,
        &rx,
        probe,
        Address::Creature(a.registry_id),
        Some(RealmId::new(REALM_B)),
        1_000,
        |entries| {
            entries.iter().any(|e| e.artifact_hash == y_hash && e.realm == RealmId::new(REALM_B))
        },
        scaled(Duration::from_secs(10)),
    );
    assert!(a_has_y, "after pull, A's registry must list Y tagged with Realm `guests`");

    // ---- set up reputation target: B pulls `crew` from A → B learns X@crew ----
    bus.send(
        Dispatch::to(
            Address::Node(NodeId(NODE_B.into()), b.federator_id),
            FederatorMsg::PullFrom {
                source_realm: RealmId::new(REALM_A),
                peer_node: NodeId(NODE_A.into()),
                peer_registry: a.registry_id,
            }
            .to_bytes(),
        )
        .with_schema(omega_federator::SCHEMA)
        .with_corr(2)
        .with_reply_to(Address::Creature(probe)),
    )
    .expect("cross-node PullFrom to B dispatched");

    let b_has_x = poll_entries(
        &bus,
        &rx,
        probe,
        Address::Node(NodeId(NODE_B.into()), b.registry_id),
        Some(RealmId::new(REALM_A)),
        2_000,
        |entries| {
            entries.iter().any(|e| e.artifact_hash == x_hash && e.realm == RealmId::new(REALM_A))
        },
        scaled(Duration::from_secs(10)),
    );
    assert!(b_has_x, "after B pulls crew, B's registry must hold X@crew (reputation target)");

    // ---- (2) Signed reputation propagation: A federates score 0.95 for X@crew to B ----
    bus.send(
        Dispatch::to(
            Address::Creature(a.federator_id),
            FederatorMsg::FederateReputation {
                artifact_hash: x_hash.clone(),
                realm: RealmId::new(REALM_A),
                score: 0.95,
                peer_node: NodeId(NODE_B.into()),
                peer_federator: b.federator_id,
            }
            .to_bytes(),
        )
        .with_schema(omega_federator::SCHEMA)
        .with_corr(3)
        .with_reply_to(Address::Creature(probe)),
    )
    .expect("FederateReputation dispatched on A");

    let b_scored_x = poll_entries(
        &bus,
        &rx,
        probe,
        Address::Node(NodeId(NODE_B.into()), b.registry_id),
        Some(RealmId::new(REALM_A)),
        3_000,
        |entries| {
            entries.iter().any(|e| {
                e.artifact_hash == x_hash
                    && e.reputation.as_ref().is_some_and(|r| {
                        (r.score - 0.95).abs() < 1e-6
                            && r.attesting_realm == Some(RealmId::new(REALM_A))
                    })
            })
        },
        scaled(Duration::from_secs(10)),
    );
    assert!(
        b_scored_x,
        "B's registry must reflect X's 0.95 score tagged with attesting Realm `crew` (signed, weight 1.0)"
    );

    // ---- (3) Cross-Realm quarantine path: A federates a quarantine notice for X@crew to B ----
    bus.send(
        Dispatch::to(
            Address::Creature(a.federator_id),
            FederatorMsg::FederateQuarantine {
                artifact_hash: x_hash.clone(),
                realm: RealmId::new(REALM_A),
                reason: "apoptosis observed on node-A".into(),
                peer_node: NodeId(NODE_B.into()),
                peer_federator: b.federator_id,
            }
            .to_bytes(),
        )
        .with_schema(omega_federator::SCHEMA)
        .with_corr(4)
        .with_reply_to(Address::Creature(probe)),
    )
    .expect("FederateQuarantine dispatched on A");

    let b_quarantined_x = poll_entries(
        &bus,
        &rx,
        probe,
        Address::Node(NodeId(NODE_B.into()), b.registry_id),
        Some(RealmId::new(REALM_A)),
        4_000,
        |entries| {
            entries.iter().any(|e| {
                e.artifact_hash == x_hash
                    && e.quarantine.as_ref().is_some_and(|q| q.reason.contains("apoptosis"))
            })
        },
        scaled(Duration::from_secs(10)),
    );
    assert!(b_quarantined_x, "B's registry must mark X quarantined after the cross-Realm notice");

    // ---- (3b) Pull carries BOTH signals over the wire. B's X now holds a
    //      reputation score AND a quarantine notice. A re-pulls `crew` from B; the merged entry on A
    //      must carry BOTH. The federator's both-signal merge is unit-tested in-process; this proves
    //      the `ListEntries` reply actually *serializes and ships* both the reputation and quarantine
    //      slots across transport-tcp, not just one. A already has X@crew natively (seeded), so the
    //      pull republishes (resetting signals) then re-applies both from the pulled SyncEntry — the
    //      local-FIFO ordering contract guarantees publish precedes the re-applies. ----
    bus.send(
        Dispatch::to(
            Address::Creature(a.federator_id),
            FederatorMsg::PullFrom {
                source_realm: RealmId::new(REALM_A),
                peer_node: NodeId(NODE_B.into()),
                peer_registry: b.registry_id,
            }
            .to_bytes(),
        )
        .with_schema(omega_federator::SCHEMA)
        .with_corr(6)
        .with_reply_to(Address::Creature(probe)),
    )
    .expect("re-pull crew from B dispatched on A");

    let a_has_both_signals = poll_entries(
        &bus,
        &rx,
        probe,
        Address::Creature(a.registry_id),
        Some(RealmId::new(REALM_A)),
        6_000,
        |entries| {
            entries.iter().any(|e| {
                e.artifact_hash == x_hash
                    && e.reputation.as_ref().is_some_and(|r| (r.score - 0.95).abs() < 1e-6)
                    && e.quarantine.as_ref().is_some_and(|q| q.reason.contains("apoptosis"))
            })
        },
        scaled(Duration::from_secs(10)),
    );
    assert!(
        a_has_both_signals,
        "after re-pulling crew from B, A's X must carry BOTH the pulled reputation score and the quarantine notice — both survived the ListEntries wire round-trip (M10-4)"
    );

    // ---- (4) Cross-Realm routing (criterion #1 "replaces the stub" + criterion #6's routing
    //      mechanism). An `Address::Omega{realm: guests, target: Creature(b_registry)}` envelope
    //      from A is routed by A's federator to B's registry; B replies; the answer returns to A's
    //      probe. The stub would have answered with a deferral — the real federator routes.
    //      (T6's full guarantee — an *unchanged* distributor placing cross-Realm — rests on the
    //      Node-grain transport path already proven by `distributor_cross_node`; the federator owns
    //      this Omega routing seam.) ----
    let routed = registry_roundtrip(
        &bus,
        &rx,
        probe,
        Address::Omega {
            realm: RealmId::new(REALM_B),
            target: Box::new(Address::Creature(b.registry_id)),
        },
        RegistryOp::ListEntries { realm: Some(RealmId::new(REALM_B)) },
        5,
        scaled(Duration::from_secs(8)),
    );
    match routed {
        Some(RegistryReply::Entries { entries }) => {
            assert!(
                entries.iter().any(|e| e.artifact_hash == y_hash),
                "an Omega-addressed query to Realm `guests` must reach B's registry and return Y"
            );
        }
        other => panic!("cross-Realm routed query must return Entries from B; got {other:?}"),
    }

    a.kernel.shutdown_all(Deadline::from_millis(1500));
    b.kernel.shutdown_all(Deadline::from_millis(1500));
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}
