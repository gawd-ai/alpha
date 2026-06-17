//! ADR-0044: the shared node-boot recipe in `omni`. Both composition-root poles — the α `alpha node`
//! front door and the Ω `omega serve` gateway (and the MCP-hub boot path) — delegate node-identity
//! minting, cluster-transport boot, and the HTTP-surface sense wiring to `omni`, so the security- and
//! correctness-sensitive parts live in exactly one place. This pins the two directly-testable helpers:
//! `derive_node_key` (identity minting) and `boot_http_surface` (listener bind + sense wiring + load).
//! `boot_cluster` is exercised by the cross-node integration suites.

use std::sync::Arc;

use aether::{Creature, CreatureCtx, Deadline, Envelope, Outcome, StubSigner, StubVerifier};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;

use omni::{boot_http_surface, derive_node_key};

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    )
}

/// A trivial in-process creature standing in for the HTTP surface — proves the recipe loads whatever
/// surface the caller supplies, without the `surface-http` crate (which depends on `omni`).
struct Noop;
impl Creature for Noop {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

#[test]
fn derive_node_key_is_deterministic_loads_a_seed_and_generates_when_absent() {
    let seed_hex = "ab".repeat(32); // 64 hex chars = a 32-byte seed
    let a = derive_node_key(Some(&seed_hex)).expect("valid seed loads");
    let b = derive_node_key(Some(&seed_hex)).expect("valid seed loads");
    assert!(!a.generated, "an explicit seed is loaded, not generated");
    assert_eq!(a.key.public_hex(), b.key.public_hex(), "same seed → same identity (deterministic)");

    // A malformed seed is rejected, not silently coerced.
    assert!(derive_node_key(Some("not-hex")).is_err());
    assert!(derive_node_key(Some("abcd")).is_err(), "wrong length is rejected");

    // No seed → a fresh, generated identity.
    assert!(derive_node_key(None).expect("fresh keygen").generated);
}

#[test]
fn boot_http_surface_binds_the_listener_then_loads_the_supplied_surface() {
    let kernel = kernel();
    let listen = "127.0.0.1:0".parse().unwrap();

    // The recipe binds the listener BEFORE building the surface (so a port conflict surfaces
    // synchronously), then hands the listener + the drain-less sense receiver to the caller's factory.
    let mut bound_port = None;
    let id = boot_http_surface(&kernel, listen, |listener, _sense_rx| {
        bound_port = Some(listener.local_addr().unwrap().port());
        Ok(Box::new(Noop) as Box<dyn Creature>)
    })
    .expect("surface boots");

    assert!(
        bound_port.is_some_and(|p| p != 0),
        "omni binds the listener (real port) before the surface is constructed"
    );
    // The surface was actually loaded onto the kernel — unloading the returned id succeeds.
    assert!(kernel.unload(id, Deadline::default()).is_ok(), "the loaded surface unloads cleanly");
}
