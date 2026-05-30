//! Hot-swapping a bound *infrastructure* creature while the bus keeps flowing.
//!
//! VISION.md leads with "the substrate is self-hosting — its own organs are hot-swappable daemons of
//! the same kind it runs. An AI can re-author the substrate, not just the workloads on it." The
//! `m1_reload_loop` test proves a *workload* (echo) reloads 1000× RSS-stable — but echo is not an
//! organ. This test proves the real claim: a creature **bound to a Role** (here `Role::DISTRIBUTOR`,
//! the placement organ's socket) is swapped for a different implementation *mid-traffic* — unbind →
//! unload → load the replacement → rebind — and the next Intent is served by the new model, with the
//! kernel, the router, and the requester's endpoint never torn down. The Role socket is the seam;
//! swapping what fills it is how an AI re-authors the substrate's own organs (IoC).
//!
//! Self-contained: two minimal resolver creatures (`ResolverA`/`ResolverB`) stand in for two
//! placement implementations, so the test exercises the *substrate's* hot-swap capability
//! (`bind_role`/`unbind_role`/`unload`/`load_instance` on a live, bound socket) rather than any one
//! distributor's resolution internals.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Deadline, Dispatch, Intent, Outcome, Role, StubSigner, StubVerifier};
use aether::{Creature, CreatureCtx, Envelope};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::{Admission, Kernel, Policy};
use sigil::{Backend, Capabilities, Manifest};

struct AllowAll;
impl Policy for AllowAll {
    fn admit(&self, _m: &Manifest, _e: &Admission) -> Result<(), String> {
        Ok(())
    }
}

/// A placement organ that tags every reply with its own label, so a test can tell *which* bound
/// creature served a given Intent.
struct Resolver(&'static str);
impl Creature for Resolver {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let mut body = self.0.as_bytes().to_vec();
        body.push(b':');
        body.extend_from_slice(&env.payload);
        Outcome::reply(&env, body)
    }
}

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("hot-swap")),
        Arc::new(StubVerifier),
        Arc::new(AllowAll),
        64,
    )
}

fn boot_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

fn place(
    bus: &aether::BusHandle,
    rx: &aether::InboxReceiver,
    corr: u64,
) -> Result<Vec<u8>, aether::RouteError> {
    bus.send(
        Dispatch::to(
            Address::Intent(Intent { outcome: "place".into(), requirements: vec![] }),
            b"work".to_vec(),
        )
        .with_reply_to(Address::Creature(bus.id()))
        .with_corr(corr),
    )?;
    // Skip any stray fan-out envelopes; wait for our correlated reply.
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        if let Ok(env) = rx.recv_timeout(Duration::from_millis(200)) {
            if env.header.corr == Some(corr) {
                return Ok(env.payload);
            }
        }
    }
    panic!("no placement reply for corr {corr}");
}

#[test]
fn a_bound_organ_is_hot_swapped_mid_traffic_without_tearing_down_the_bus() {
    let k = kernel();
    let (_probe, bus, rx) = k.open_endpoint(Capabilities::default());

    // Organ A bound to the DISTRIBUTOR socket; an Intent is served by A.
    let a = k.load_instance(boot_manifest("placement-A"), Box::new(Resolver("A"))).unwrap();
    k.bind_role(Role::new(Role::DISTRIBUTOR), a);
    assert_eq!(place(&bus, &rx, 1).unwrap(), b"A:work", "Intent served by organ A");

    // ── Hot-swap the placement organ for a different implementation, mid-traffic ──
    // The kernel and the requester's endpoint are NEVER torn down; only the bound creature changes.
    k.router().unbind_role(&Role::new(Role::DISTRIBUTOR)); // socket momentarily empty
                                                           // With nothing bound, an Intent is a clean NoProvider — not a crash, not a hang (the bus is up).
    let gap = bus
        .send(
            Dispatch::to(
                Address::Intent(Intent { outcome: "place".into(), requirements: vec![] }),
                b"work".to_vec(),
            )
            .with_reply_to(Address::Creature(bus.id())),
        )
        .unwrap_err();
    assert!(
        matches!(gap, aether::RouteError::NoProvider(_)),
        "during the swap the socket is cleanly empty, got {gap:?}"
    );

    k.unload(a, Deadline::default()).unwrap(); // retire organ A
    let b = k.load_instance(boot_manifest("placement-B"), Box::new(Resolver("B"))).unwrap();
    k.bind_role(Role::new(Role::DISTRIBUTOR), b); // the new model takes the socket

    // The very next Intent is served by B — the substrate re-authored its own placement organ live.
    assert_eq!(
        place(&bus, &rx, 2).unwrap(),
        b"B:work",
        "Intent now served by the swapped-in organ B"
    );

    // Continuity: the requester endpoint that talked to A still works against B — same bus, same
    // kernel, same router; only the organ behind the socket changed.
    assert!(k.is_loaded(b));
    assert!(!k.is_loaded(a));
    k.shutdown_all(Deadline::default());
}
