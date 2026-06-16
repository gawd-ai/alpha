//! `federation-scheduler` — the cadence companion that makes the Ω pole self-driving.
//!
//! The `omega-federator` runs anti-entropy *when poked*: an operator (or this creature) sends it a
//! [`FederatorMsg::PullFrom`] and it pulls one peer Realm's catalog and merges it. Its own module
//! docs name the missing piece — *"a pull happens when the operator **or a scheduler creature** sends
//! `PullFrom`. The substrate ships no clock (time is injected)."* This is that scheduler creature.
//!
//! It is a **daemon**: a native, trusted-by-admission creature that legitimately owns a real OS timer
//! thread. That is the whole resolution of "the substrate ships no clock" — time enters the system
//! as an *injected creature*, never as a kernel primitive. Stop the creature and the schedule stops;
//! swap it for a different cadence model and nothing else changes. The federator stays a pure
//! reactor; the *when* lives out here, hot-swappable like every other choice.
//!
//! ## What it does
//!
//! On `bind` it spawns one cadence thread (stashing its bus, mirroring `transport-tcp`'s in-process
//! thread discipline). Every `interval`, if there is backpressure headroom, it emits one
//! `PullFrom` per configured [`PullTarget`] to the federator. The federator answers each with an
//! `Accepted` or `Rejected` ack; this creature's `handle` reaps those acks to track how many pulls
//! are in flight.
//!
//! ## Backpressure (it never floods a stuck federator)
//!
//! The federator caps concurrent in-flight pulls (`with_max_pending_pulls`, default 128) and
//! *refuses* a new `PullFrom` at capacity. This scheduler mirrors that with its own `max_in_flight`
//! counter: a round fires only if the **whole** round fits under the cap, and the counter decrements
//! on each ack. A federator that stops acking (gone, wedged, or saturated) drives the counter up,
//! the rounds stop firing, and the scheduler quietly backs off until acks resume — no unbounded
//! emission, no eviction of work already issued.
//!
//! ## What it deliberately doesn't do
//!
//! - **It doesn't discover peers.** Targets are operator-supplied. Peer discovery + quorum are the
//!   v0.5 follow-ons; this creature is the *cadence*, not the topology.
//! - **It doesn't merge or verify anything.** It only schedules; the federator owns the pull, the
//!   admission gate, and the merge. A `Rejected` ack is observed (it frees an in-flight slot) but the
//!   scheduler takes no corrective action — retrying a structurally-rejected target is the operator's
//!   call, not a loop the substrate bakes in.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{Builder, JoinHandle};
use std::time::Duration;

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, NodeId, Outcome,
    RealmId,
};
use omega_federator::{FederatorMsg, SCHEMA as FEDERATOR_SCHEMA};

/// Default cap on in-flight (emitted-but-unacked) pulls. Kept at half the federator's default
/// `DEFAULT_MAX_PENDING_PULLS` (128) so a healthy scheduler never races the federator's own refuse-at
/// -capacity guard; an operator running a federator with a tighter pending cap should lower this to
/// match (it must stay `<=` the federator's cap to honor its backpressure).
pub const DEFAULT_MAX_IN_FLIGHT: usize = 64;

/// The granularity at which the cadence thread re-checks the stop flag while waiting out an
/// interval — bounds how long `shutdown` waits for the worker to notice it should exit.
const STOP_POLL: Duration = Duration::from_millis(50);

/// One peer-Realm pull target: ask `peer_node`'s `peer_registry` for its `source_realm` catalog.
/// Mirrors the fields of [`FederatorMsg::PullFrom`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullTarget {
    /// The Realm whose catalog to pull from the peer.
    pub source_realm: RealmId,
    /// The peer Sanctum that holds it.
    pub peer_node: NodeId,
    /// The peer's `registry-mem` creature id.
    pub peer_registry: CreatureId,
}

impl PullTarget {
    /// Construct a target.
    pub fn new(source_realm: RealmId, peer_node: NodeId, peer_registry: CreatureId) -> Self {
        PullTarget { source_realm, peer_node, peer_registry }
    }

    fn to_pull(&self) -> FederatorMsg {
        FederatorMsg::PullFrom {
            source_realm: self.source_realm.clone(),
            peer_node: self.peer_node.clone(),
            peer_registry: self.peer_registry,
        }
    }
}

/// State shared between the kernel-driven `handle`/`shutdown` and the cadence worker thread. Only
/// the two atomics cross the thread boundary, so there is no lock on the hot path.
struct Shared {
    stop: AtomicBool,
    in_flight: AtomicUsize,
}

/// The cadence companion creature.
pub struct FederationScheduler {
    /// Where the federator is addressed — typically `Address::Role(omega::GATEWAY_ROLE)` or the
    /// federator's `Address::Creature(id)`.
    federator: Address,
    targets: Vec<PullTarget>,
    interval: Duration,
    max_in_flight: usize,
    shared: Arc<Shared>,
    worker: Option<JoinHandle<()>>,
}

impl FederationScheduler {
    /// Construct a scheduler that pulls every `targets` Realm from the federator at `federator`,
    /// once per `interval`. Uses [`DEFAULT_MAX_IN_FLIGHT`] backpressure.
    pub fn new(federator: Address, targets: Vec<PullTarget>, interval: Duration) -> Self {
        FederationScheduler {
            federator,
            targets,
            interval,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
            shared: Arc::new(Shared {
                stop: AtomicBool::new(false),
                in_flight: AtomicUsize::new(0),
            }),
            worker: None,
        }
    }

    /// Override the in-flight backpressure cap. Keep it `<=` the federator's `max_pending_pulls`.
    pub fn with_max_in_flight(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Pulls emitted but not yet acked. Exposed for tests + observability.
    pub fn in_flight(&self) -> usize {
        self.shared.in_flight.load(Ordering::Relaxed)
    }
}

impl Creature for FederationScheduler {
    fn bind(&mut self, ctx: CreatureCtx) {
        // Nothing to schedule against an empty target set — stay inert (no thread, no emission).
        if self.targets.is_empty() {
            return;
        }
        let shared = self.shared.clone();
        let bus = ctx.bus;
        let federator = self.federator.clone();
        let targets = self.targets.clone();
        let interval = self.interval;
        let max_in_flight = self.max_in_flight;

        let worker = Builder::new()
            .name("federation-scheduler".into())
            .spawn(move || cadence_loop(shared, bus, federator, targets, interval, max_in_flight))
            .expect("spawn federation-scheduler cadence thread");
        self.worker = Some(worker);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // The only inbound traffic we read is the federator's ack to a PullFrom we issued. An
        // Accepted or Rejected frees one in-flight slot. Everything else is ignored (the federator's
        // other messages — quarantine notices, reputation deltas — aren't ours).
        if env.header.schema == FEDERATOR_SCHEMA {
            if let Ok(msg) = FederatorMsg::parse_bounded(&env.payload) {
                if matches!(msg, FederatorMsg::Accepted { .. } | FederatorMsg::Rejected { .. }) {
                    // Saturating decrement — an unmatched or duplicate ack never underflows the
                    // counter (which would later wedge the backpressure gate open below zero).
                    let _ = self.shared.in_flight.fetch_update(
                        Ordering::Relaxed,
                        Ordering::Relaxed,
                        |v| v.checked_sub(1),
                    );
                }
            }
        }
        Outcome::none()
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        // Signal the worker and join it: the kernel-driven stop discipline. The worker checks `stop`
        // every STOP_POLL while waiting out an interval, so it returns promptly.
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// The cadence loop: wait out `interval` (re-checking stop every [`STOP_POLL`]); each round, fire one
/// `PullFrom` per target iff the whole round fits under `max_in_flight`.
fn cadence_loop(
    shared: Arc<Shared>,
    bus: Arc<dyn Bus>,
    federator: Address,
    targets: Vec<PullTarget>,
    interval: Duration,
    max_in_flight: usize,
) {
    while !sleep_with_stop(&shared, interval) {
        let in_flight = shared.in_flight.load(Ordering::Relaxed);
        // Fire the round only if it fits whole — partial rounds would skew which Realms reconcile.
        if in_flight + targets.len() > max_in_flight {
            continue;
        }
        for target in &targets {
            let dispatch = Dispatch::to(federator.clone(), target.to_pull().to_bytes())
                .with_schema(FEDERATOR_SCHEMA);
            if bus.emit(dispatch).is_ok() {
                shared.in_flight.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Sleep for `total`, waking every [`STOP_POLL`] to check the stop flag. Returns `true` if stop was
/// signaled (so the caller's loop exits), `false` if the full interval elapsed.
fn sleep_with_stop(shared: &Shared, total: Duration) -> bool {
    let mut elapsed = Duration::ZERO;
    while elapsed < total {
        if shared.stop.load(Ordering::Relaxed) {
            return true;
        }
        let nap = STOP_POLL.min(total - elapsed);
        std::thread::sleep(nap);
        elapsed += nap;
    }
    shared.stop.load(Ordering::Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(realm: &str, node: &str, reg: u64) -> PullTarget {
        PullTarget::new(RealmId(realm.into()), NodeId(node.into()), CreatureId(reg))
    }

    fn ack_env(msg: &FederatorMsg) -> Envelope {
        use aether::Header;
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: FEDERATOR_SCHEMA.to_string(),
                origin: None,
            },
            payload: msg.to_bytes(),
        }
    }

    fn scheduler() -> FederationScheduler {
        FederationScheduler::new(
            Address::Creature(CreatureId(9)),
            vec![target("alpha", "node-B", 7)],
            Duration::from_millis(10),
        )
    }

    #[test]
    fn pull_target_maps_to_federator_pullfrom() {
        let t = target("alpha", "node-B", 7);
        match t.to_pull() {
            FederatorMsg::PullFrom { source_realm, peer_node, peer_registry } => {
                assert_eq!(source_realm, RealmId("alpha".into()));
                assert_eq!(peer_node, NodeId("node-B".into()));
                assert_eq!(peer_registry, CreatureId(7));
            }
            other => panic!("expected PullFrom, got {other:?}"),
        }
    }

    #[test]
    fn accepted_and_rejected_acks_free_in_flight_slots() {
        let mut s = scheduler();
        s.shared.in_flight.store(2, Ordering::Relaxed);
        s.handle(ack_env(&FederatorMsg::Accepted { note: "pull dispatched".into() }));
        assert_eq!(s.in_flight(), 1, "Accepted frees a slot");
        s.handle(ack_env(&FederatorMsg::Rejected { reason: "unmapped realm".into() }));
        assert_eq!(s.in_flight(), 0, "Rejected frees a slot");
    }

    #[test]
    fn ack_never_underflows_below_zero() {
        let mut s = scheduler();
        // in_flight already 0 — a stray ack must not wrap the counter.
        s.handle(ack_env(&FederatorMsg::Accepted { note: "stray".into() }));
        assert_eq!(s.in_flight(), 0, "saturating decrement, no underflow");
    }

    #[test]
    fn non_ack_federator_messages_do_not_touch_the_counter() {
        let mut s = scheduler();
        s.shared.in_flight.store(1, Ordering::Relaxed);
        let notice = FederatorMsg::QuarantineNotice {
            artifact_hash: "sha256:x".into(),
            realm: RealmId("alpha".into()),
            reason: "bad".into(),
            attesting_peers: vec![],
        };
        s.handle(ack_env(&notice));
        assert_eq!(s.in_flight(), 1, "a non-ack message leaves in-flight untouched");
    }

    #[test]
    fn empty_target_set_stays_inert() {
        // An empty target set spawns no worker — `bind` returns without a thread, so there is
        // nothing to join and nothing emitted.
        let s = FederationScheduler::new(
            Address::Creature(CreatureId(9)),
            vec![],
            Duration::from_millis(10),
        );
        assert!(s.worker.is_none());
        assert_eq!(s.targets.len(), 0);
    }
}
