//! Omega-stub-routing integration test for `cosmos/creatures/prototypes/gateways/omega-gateway` (in-process,
//! no transport needed because the Omega-gateway stub never goes off-node — it always replies
//! `DeferredToV03`).
//!
//! ## What this test proves
//!
//! - `Address::Omega` envelopes route to the bound [`Role::OMEGA_GATEWAY`] creature (the
//!   IoC discipline, extended to federation depth — same socket pattern as the realm-gateway
//!   case in `realm_local_route.rs`).
//! - The bound stub replies with the structured `omega.deferred` schema; reason variant
//!   `DeferredToV03`; realm preserved.
//! - reply_to + corr survive the gateway hop intact.
//! - **The substrate ships the address grain, not the federation mechanism** — the
//!   commitment is that a real federation creature slots in on this same socket without
//!   retrofitting any envelope path (the S2 mitigation).

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, CreatureId, Deadline, Dispatch, RealmId, Role, StubSigner};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use omega_gateway::{OmegaDeferredReason, OmegaDeferredReply, OmegaGateway};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

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
        Arc::new(StubSigner::new("m8-omega")),
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

#[test]
fn omega_stub_route() {
    let node_key = Ed25519KeyMaterial::from_seed([0x09u8; 32]).unwrap();
    let k = kernel(vec![node_key.public_hex().to_string()]);

    // Bind omega-gateway on the OMEGA_GATEWAY socket. Any Address::Omega envelope now
    // dispatches here per the router's IoC rule (Address::Omega → Role::OMEGA_GATEWAY).
    let gw_id = k
        .load_instance(
            signed_boot_manifest("omega-gateway", &node_key),
            Box::new(OmegaGateway::new()),
        )
        .expect("omega-gateway admits");
    k.bind_role(Role::new(Role::OMEGA_GATEWAY), gw_id);

    // Probe — the requester. No subscriptions needed; the omega-gateway dispatches its reply
    // straight to reply_to.
    let (probe_id, probe_bus, probe_rx) = k.open_endpoint(Capabilities::default());

    // Address::Omega envelope: realm + inner target. Realm name names the addressed Realm in
    // the Omega (the federation of Realms); target is an opaque inner address (which the
    // stub never actually inspects — its commitment is the structured `DeferredToV03` reply).
    let corr = 7u64;
    probe_bus
        .send(
            Dispatch::to(
                Address::Omega {
                    realm: RealmId::new("global"),
                    target: Box::new(Address::Creature(CreatureId(99))),
                },
                b"ignored-by-v02-stub".to_vec(),
            )
            .with_reply_to(Address::Creature(probe_id))
            .with_corr(corr)
            .with_schema("ping"),
        )
        .expect("Omega envelope dispatches via the router to the bound gateway");

    // The reply must arrive on the probe's inbox at the same corr, schema = omega.deferred,
    // body = OmegaDeferredReply { realm: "global", reason: DeferredToV03, details: Some(...) }.
    let reply_env = probe_rx
        .recv_timeout(scaled(Duration::from_secs(2)))
        .expect("omega-gateway responds within its in-process budget");
    assert_eq!(reply_env.header.corr, Some(corr), "corr preserved");
    assert_eq!(reply_env.header.schema, "omega.deferred", "the v0.2 wire schema");
    let reply: OmegaDeferredReply = serde_json::from_slice(&reply_env.payload)
        .expect("payload deserializes as the v0.2 OmegaDeferredReply schema");
    assert_eq!(reply.realm, RealmId::new("global"), "realm name preserved");
    assert_eq!(
        reply.reason,
        OmegaDeferredReason::DeferredToV03,
        "v0.2 commitment: every Omega envelope gets DeferredToV03"
    );
    assert!(reply.details.is_some(), "an operator-facing hint accompanies the deferral");

    k.shutdown_all(Deadline::from_millis(1000));
}
