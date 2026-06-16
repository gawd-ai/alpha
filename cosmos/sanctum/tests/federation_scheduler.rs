//! Self-driving anti-entropy: the `federation-scheduler` companion drives the federator on its own
//! clock, and backs off under the federator's pending-pull backpressure.
//!
//! The scheduler's unit tests cover its ack bookkeeping directly. This test proves the *live* loop:
//! a real [`Kernel`] runs a stub federator and the scheduler pointed at it. The stub records every
//! `PullFrom` it receives and (optionally) acks it. Two scenarios:
//!
//! 1. **It self-drives.** With acks flowing, the scheduler emits `PullFrom` round after round on its
//!    interval — no operator poke — and every pull carries the configured target.
//! 2. **It backs off.** With acks withheld and `max_in_flight = 2`, the in-flight counter climbs and
//!    the scheduler stops at exactly two pulls rather than flooding a federator that never answers.
//!
//! This is the mechanism that turns the operator-poked federator into the headline of v0.4.2 — the Ω
//! pole reconciling itself — without adding a clock to the substrate (the cadence is this creature).

use std::sync::{Arc, Mutex};
use std::time::Duration;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, NodeId, Outcome,
    RealmId,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use federation_scheduler::{FederationScheduler, PullTarget};
use omega_federator::{FederatorMsg, SCHEMA as FEDERATOR_SCHEMA};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Manifest};

/// A stub federator: records every `PullFrom` it receives; acks each with `Accepted` iff `ack`.
struct RecordingFederator {
    seen: Arc<Mutex<Vec<(RealmId, NodeId, CreatureId)>>>,
    ack: bool,
}

impl Creature for RecordingFederator {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != FEDERATOR_SCHEMA {
            return Outcome::none();
        }
        match FederatorMsg::parse_bounded(&env.payload) {
            Ok(FederatorMsg::PullFrom { source_realm, peer_node, peer_registry }) => {
                self.seen.lock().unwrap().push((source_realm, peer_node, peer_registry));
                if self.ack {
                    let reply = FederatorMsg::Accepted { note: "recorded".into() };
                    Outcome::send(
                        Dispatch::reply_to_env(&env, reply.to_bytes())
                            .with_schema(FEDERATOR_SCHEMA),
                    )
                } else {
                    Outcome::none()
                }
            }
            _ => Outcome::none(),
        }
    }
}

fn make_kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("federation-scheduler-test")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

fn target() -> PullTarget {
    PullTarget::new(RealmId::new("alpha"), NodeId("node-B".into()), CreatureId(7))
}

#[test]
fn scheduler_self_drives_pulls_on_its_cadence() {
    let kernel = make_kernel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let fed = kernel
        .load_instance(
            manifest("recording-federator"),
            Box::new(RecordingFederator { seen: seen.clone(), ack: true }),
        )
        .expect("stub federator admits");

    let scheduler =
        FederationScheduler::new(Address::Creature(fed), vec![target()], Duration::from_millis(80));
    kernel
        .load_instance(manifest("federation-scheduler"), Box::new(scheduler))
        .expect("scheduler admits");

    // ~5 intervals. With acks flowing, every round fires.
    std::thread::sleep(Duration::from_millis(460));
    kernel.shutdown_all(Deadline::default());

    let pulls = seen.lock().unwrap().clone();
    assert!(
        pulls.len() >= 3,
        "cadence should fire repeatedly with acks flowing, got {}",
        pulls.len()
    );
    for (realm, node, reg) in &pulls {
        assert_eq!(realm, &RealmId::new("alpha"), "pull carries the configured realm");
        assert_eq!(node, &NodeId("node-B".into()), "pull carries the configured peer node");
        assert_eq!(reg, &CreatureId(7), "pull carries the configured peer registry");
    }
}

#[test]
fn scheduler_backs_off_under_backpressure_when_acks_stop() {
    let kernel = make_kernel();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let fed = kernel
        .load_instance(
            manifest("recording-federator-noack"),
            Box::new(RecordingFederator { seen: seen.clone(), ack: false }),
        )
        .expect("stub federator admits");

    // One target, max_in_flight = 2: round 1 (in_flight 0→1) and round 2 (1→2) fire; round 3 needs
    // 2+1=3 > 2 → skipped forever, since no ack ever frees a slot.
    let scheduler =
        FederationScheduler::new(Address::Creature(fed), vec![target()], Duration::from_millis(60))
            .with_max_in_flight(2);
    kernel
        .load_instance(manifest("federation-scheduler-bp"), Box::new(scheduler))
        .expect("scheduler admits");

    // ~8 intervals — far more than the two the cap allows.
    std::thread::sleep(Duration::from_millis(520));
    kernel.shutdown_all(Deadline::default());

    let n = seen.lock().unwrap().len();
    assert_eq!(n, 2, "with no acks and max_in_flight=2, exactly two pulls then back off, got {n}");
}
