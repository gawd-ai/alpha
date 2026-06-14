//! **`omega serve` federates with an alpha client over `transport-tcp`.**
//!
//! Static ports `19_990 / 19_991` (free — distinct from every sanctum/omni cross-node pair in
//! `19_900..=19_983`; one transport-tcp test per file so parallel `cargo test` doesn't collide on the
//! bind). Boots the **Ω server** through the real `omega serve` composition recipe
//! ([`omega::serve::boot_gateway`]) and a peer **α client** node, and proves the gateway the binary
//! stands up actually does cross-node federation:
//!
//! 1. **Cross-Realm routing (the real federator, not the stub).** α addresses an
//!    `Address::Omega{realm: crew, target: Creature(ω-registry)}`; α's federator routes it to the Ω
//!    node; Ω's registry answers; the reply returns to α. The `omega-gateway` stub would have replied
//!    with a deferral — the real federator the recipe binds routes.
//! 2. **Pull anti-entropy.** α pulls Realm `crew` from Ω; the seeded artifact `X` lands in α's local
//!    registry, pinned to `crew`.
//!
//! Both nodes boot via the same `boot_gateway` recipe `omega serve` uses, so this is a direct proof of
//! that recipe (an Omega-routing client legitimately binds a federator too; the α/Ω split is about the
//! binary's defaults/posture, not a capability fence).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, BusHandle, CreatureId, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier,
    InboxReceiver, NodeId, RealmId,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use omega::serve::{boot_gateway, GatewayConfig, GatewayIds};
use policy_dev::DevPolicy;
use registry_mem::{RegistryOp, RegistryReply};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};
use transport_tcp::PeerEvent;

const PORT_OMEGA: u16 = 19_990;
const PORT_ALPHA: u16 = 19_991;
const NODE_OMEGA: &str = "omega-1";
const NODE_ALPHA: &str = "alpha-1";

// ----- timing scaffolding (mirrors the omega_federation_cross_node helper) -----------------------

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

/// Build a kernel with the node's ed25519 identity + dev policy, then boot the `omega serve` gateway
/// recipe into it. The node key signs the bus (so cross-node origins verify), authenticates transport,
/// and is the federator's Abode key — one identity per node, exactly as `omega serve` does.
fn boot_node(
    node_id: &str,
    realm: &str,
    port: u16,
    node_key: Ed25519KeyMaterial,
    seeds: Vec<String>,
    realm_to_peer: HashMap<RealmId, NodeId>,
) -> (Arc<Kernel>, GatewayIds) {
    // `Kernel::new` already returns `Arc<Kernel>`.
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(node_key.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(DevPolicy),
        128,
    );
    kernel.set_node_identity(node_key.public_hex().to_string());
    let cfg = GatewayConfig {
        node_id: node_id.to_string(),
        self_realm: RealmId::new(realm),
        listen: format!("127.0.0.1:{port}"),
        seeds,
        realm_to_peer,
        node_key,
    };
    let ids = boot_gateway(&kernel, &cfg).expect("gateway recipe boots");
    (kernel, ids)
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

/// Send a registry op to `to` and wait for the `registry.reply` matching `corr`.
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

/// Poll a registry with `ListEntries` until `pred` holds over the returned entries, or the budget
/// expires. Each poll uses a fresh corr.
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

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

// =================================================================================================

#[test]
fn omega_serve_gateway_federates_with_an_alpha_client() {
    let omega_key = Ed25519KeyMaterial::from_seed([0xC0; 32]).unwrap();
    let alpha_key = Ed25519KeyMaterial::from_seed([0xA0; 32]).unwrap();

    let x_bytes = b"artifact-X-from-crew".to_vec();
    let x_hash = sha256_hex(&x_bytes);

    // ---- Ω server: a federation/gateway Sanctum booted via the real `omega serve` recipe ----
    // transport-tcp is no-TOFU: the inbound handshake authenticates the dialer against the allowlist,
    // which seeds only from configured peers. A real 2-node mesh therefore configures BOTH sides with
    // each other (mirroring `omega_federation_cross_node.rs`, which lists peers on both ends); an
    // operator does the same with `--seed` on each node (or `cluster join` at runtime).
    let omega_seeds =
        vec![format!("{NODE_ALPHA}@127.0.0.1:{PORT_ALPHA}#{}", alpha_key.public_hex())];
    let (omega_kernel, omega) =
        boot_node(NODE_OMEGA, "crew", PORT_OMEGA, omega_key.clone(), omega_seeds, HashMap::new());

    // Seed X@crew into Ω's registry (locally, over Ω's own probe — no transport needed).
    let (omega_probe, omega_bus, omega_rx) = omega_kernel.open_endpoint(Capabilities::default());
    omega_bus
        .send(
            Dispatch::to(
                Address::Creature(omega.registry),
                serde_json::to_vec(&RegistryOp::Publish {
                    manifest: Manifest::new("x", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                    artifact: x_bytes.clone(),
                    realm: Some(RealmId::new("crew")),
                })
                .unwrap(),
            )
            .with_schema("registry.op")
            .with_corr(100)
            .with_reply_to(Address::Creature(omega_probe)),
        )
        .expect("seed publish dispatched on Ω");
    assert!(
        poll_entries(
            &omega_bus,
            &omega_rx,
            omega_probe,
            Address::Creature(omega.registry),
            Some(RealmId::new("crew")),
            100,
            |es| es.iter().any(|e| e.artifact_hash == x_hash),
            scaled(Duration::from_secs(5)),
        ),
        "X@crew must be in Ω's registry after the seed publish"
    );

    // ---- α client: dials Ω, maps Realm `crew` → the Ω node so Omega routing resolves ----
    let mut a_routes = HashMap::new();
    a_routes.insert(RealmId::new("crew"), NodeId(NODE_OMEGA.into()));
    let alpha_seeds =
        vec![format!("{NODE_OMEGA}@127.0.0.1:{PORT_OMEGA}#{}", omega_key.public_hex())];
    let (alpha_kernel, alpha) =
        boot_node(NODE_ALPHA, "guests", PORT_ALPHA, alpha_key.clone(), alpha_seeds, a_routes);

    let (alpha_probe, alpha_bus, alpha_rx) = alpha_kernel.open_endpoint(Capabilities::default());
    alpha_kernel.router().subscribe(aether::Topic::new(aether::Topic::PROPRIOCEPTION), alpha_probe);

    assert!(
        wait_for_peer_event(
            &alpha_rx,
            NODE_OMEGA,
            "peer_connected",
            scaled(Duration::from_secs(5))
        ),
        "α↔Ω handshake must complete before federating"
    );

    // ---- (1) Cross-Realm routing (the real federator, not the stub) ----
    let routed = registry_roundtrip(
        &alpha_bus,
        &alpha_rx,
        alpha_probe,
        Address::Omega {
            realm: RealmId::new("crew"),
            target: Box::new(Address::Creature(omega.registry)),
        },
        RegistryOp::ListEntries { realm: Some(RealmId::new("crew")) },
        5,
        scaled(Duration::from_secs(8)),
    );
    match routed {
        Some(RegistryReply::Entries { entries }) => assert!(
            entries.iter().any(|e| e.artifact_hash == x_hash),
            "the Omega-routed query must reach Ω's registry and return X — the real federator routes; the stub would have deferred"
        ),
        other => panic!("cross-Realm routed query must return Entries from Ω; got {other:?}"),
    }

    // ---- (2) Pull anti-entropy: α pulls Realm `crew` from Ω → X lands in α's local registry ----
    alpha_bus
        .send(
            Dispatch::to(
                Address::Creature(alpha.federator),
                omega_federator::FederatorMsg::PullFrom {
                    source_realm: RealmId::new("crew"),
                    peer_node: NodeId(NODE_OMEGA.into()),
                    peer_registry: omega.registry,
                }
                .to_bytes(),
            )
            .with_schema(omega_federator::SCHEMA)
            .with_corr(1)
            .with_reply_to(Address::Creature(alpha_probe)),
        )
        .expect("PullFrom dispatched on α");

    assert!(
        poll_entries(
            &alpha_bus,
            &alpha_rx,
            alpha_probe,
            Address::Creature(alpha.registry),
            Some(RealmId::new("crew")),
            1_000,
            |es| es.iter().any(|e| e.artifact_hash == x_hash),
            scaled(Duration::from_secs(10)),
        ),
        "after pulling Realm `crew` from Ω, α's local registry must hold X@crew"
    );

    omega_kernel.shutdown_all(Deadline::from_millis(1500));
    alpha_kernel.shutdown_all(Deadline::from_millis(1500));
}
