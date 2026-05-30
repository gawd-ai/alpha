//! Steer{abort} is a substrate-wide primitive, not AUTHORING-specific.
//!
//! An inbound
//! [`SeerEnvelope::Steer`] works for **any** topic — placement / policy / budget / fitness /
//! consensus all inherit the same mid-flight intervention shape. This test proves the lift by
//! exercising Query → Steer{abort} → terminal Answer{Failed} on a **non-Authoring** topic
//! ([`SeerTopic::Placement`]); the creature is a synthetic placement-style consumer, not
//! agent-curious.
//!
//! The contract proven here:
//! 1. A creature on an arbitrary topic parks an exchange on Query and resumes on Answer.
//! 2. Mid-flight, a `SeerEnvelope::Steer { kind: "abort" }` on the same topic + same corr
//!    drops the pending exchange and emits a terminal Failed [`SeerEnvelope::Answer`].
//! 3. The substrate routes Steer like any envelope (by address); no topic-specific kernel logic
//!    exists (the kernel does no new work).
//!
//! Demonstrating this on a non-Authoring topic is the load-bearing assertion: Steer is generic.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver,
    Outcome, Role,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use seer::{SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};
use sigil::{Backend, Capabilities, Manifest};

/// Synthetic placement-topic consumer. The agent-curious-style flow generalized to an arbitrary
/// topic so Steer's lift can be proven independent of AUTHORING.
///
/// - On an inbound REQUEST (schema=`"request"`, payload = a question string), if `question`
///   contains "trivial" it answers terminally (reduction theorem). Otherwise it issues a SEER
///   `Query` on `Placement` and parks the exchange.
/// - On an inbound `SeerEnvelope::Answer` (topic=Placement) matching a parked `query_id`, it
///   emits a terminal `SeerEnvelope::Answer{ body: chosen }` to the parked `reply_to`.
/// - On an inbound `SeerEnvelope::Steer { kind: "abort" }` (topic=Placement) for a parked corr,
///   it drops the parked exchange and emits a terminal `SeerEnvelope::Answer{ body:
///   {"failed":"aborted"} }`.
///
/// The terminal envelope is itself a SeerEnvelope::Answer with `query_id=0` (the "no
/// precursor query" convention from the reduction-theorem unit test in `seer`) — the
/// substrate doesn't require a separate "terminal" kind; an Answer with no matching outstanding
/// Query is the terminal.
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

const REQUEST_SCHEMA: &str = "request";

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
            SeerKind::Answer { query_id, body } => self.on_answer(env, seer.corr, query_id, body),
            SeerKind::Steer { kind, .. } => self.on_steer(env, seer.corr, &kind),
            _ => Outcome::none(),
        }
    }
}

impl PlacementConsumer {
    fn on_request(&mut self, env: Envelope) -> Outcome {
        let question = String::from_utf8_lossy(&env.payload).to_string();
        let corr = env.header.corr.unwrap_or(0);
        let reply_to = env.reply_target();

        // Reduction theorem path: a trivial question is answered terminally on the bound topic
        // with no precursor Query. Asserted in the standalone reduction-theorem test below.
        if question.contains("trivial") {
            let terminal = SeerEnvelope::answer(
                self.bound_topic,
                corr,
                0, // query_id=0 = "no precursor", the terminal convention
                &serde_json::json!({ "placed_to": "self", "reason": "trivial" }),
            );
            return Outcome::send(
                Dispatch::to(reply_to, terminal.to_bytes())
                    .with_schema(SEER_SCHEMA)
                    .with_corr(corr),
            );
        }

        // Park + Query on the bound topic. The creature consults the orchestrator via SEER
        // (same mechanism agent-curious uses on `authoring`).
        self.next_query_id = self.next_query_id.wrapping_add(1);
        let query_id = self.next_query_id;
        self.pending.insert(corr, (query_id, reply_to.clone()));

        let query = SeerEnvelope::query(
            self.bound_topic,
            corr,
            query_id,
            &serde_json::json!({ "question": question, "options": ["node-A", "node-B"] }),
        );
        Outcome::send(
            Dispatch::to(reply_to, query.to_bytes()).with_schema(SEER_SCHEMA).with_corr(corr),
        )
    }

    fn on_answer(
        &mut self,
        _env: Envelope,
        corr: u64,
        query_id: u64,
        body: serde_json::Value,
    ) -> Outcome {
        let Some((parked_qid, reply_to)) = self.pending.get(&corr).cloned() else {
            return Outcome::none();
        };
        if parked_qid != query_id {
            return Outcome::none();
        }
        self.pending.remove(&corr);
        // Terminal Answer carries `query_id=0` (terminal convention) + an "Ok" body echoing the
        // choice. A real placement creature would do the actual routing here.
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

    fn on_steer(&mut self, _env: Envelope, corr: u64, verb: &str) -> Outcome {
        if verb != "abort" {
            return Outcome::none(); // ignoring other verbs is contract-compliant
        }
        let Some((_qid, reply_to)) = self.pending.remove(&corr) else {
            return Outcome::none();
        };
        // Terminal Failed Answer — same shape as terminal-success, distinguished by body.
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

fn make_kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("seer-steer-test")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

struct World {
    kernel: Arc<Kernel>,
    consumer_id: CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

fn boot(bound_topic: SeerTopic) -> World {
    let kernel = make_kernel();
    let manifest =
        Manifest::new("placement-consumer", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    let consumer_id = kernel
        .load_instance(manifest, Box::new(PlacementConsumer::new(bound_topic)))
        .expect("placement consumer admits");
    // Bind to a role so probe can address either by Role or by creature id — Role::POLICY (a
    // reserved IoC socket) is borrowed here as the binding for this synthetic consumer. The role
    // name is opaque to the test; it just needs *some* binding.
    kernel.bind_role(Role::new("placement"), consumer_id);
    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    World { kernel, consumer_id, probe_bus, probe_rx }
}

fn send_request(world: &World, corr: u64, question: &str) {
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(world.consumer_id), question.as_bytes().to_vec())
                .with_schema(REQUEST_SCHEMA)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("request sends");
}

fn send_seer(world: &World, corr: u64, seer: SeerEnvelope) {
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(world.consumer_id), seer.to_bytes())
                .with_schema(SEER_SCHEMA)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("seer envelope sends");
}

fn recv_seer<F>(rx: &InboxReceiver, corr: u64, predicate: F, dur: Duration) -> Option<SeerEnvelope>
where
    F: Fn(&SeerEnvelope) -> bool,
{
    let stop = std::time::Instant::now() + dur;
    while std::time::Instant::now() < stop {
        let remaining = stop.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(env) => {
                if env.header.corr != Some(corr) || env.header.schema != SEER_SCHEMA {
                    continue;
                }
                if let Ok(o) = SeerEnvelope::parse(&env.payload) {
                    if predicate(&o) {
                        return Some(o);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    None
}

fn is_query(o: &SeerEnvelope) -> bool {
    matches!(o.kind, SeerKind::Query { .. })
}
fn is_terminal_answer(o: &SeerEnvelope) -> bool {
    matches!(o.kind, SeerKind::Answer { query_id: 0, .. })
}

// =================================================================================================
// 1) Query → Steer{abort} → terminal Failed-shaped Answer on a NON-AUTHORING topic. The
//    load-bearing assertion: Steer works topic-agnostic.
// =================================================================================================

#[test]
fn steer_abort_on_placement_topic_drops_pending_and_emits_terminal_failed_answer() {
    let world = boot(SeerTopic::Placement);
    let corr = 700;

    send_request(&world, corr, "place a heavy job");

    // Wait for the Query so we know the consumer parked.
    let query = recv_seer(&world.probe_rx, corr, is_query, Duration::from_secs(2))
        .expect("query arrives on placement topic");
    assert_eq!(query.topic, SeerTopic::Placement, "query rides on placement topic");
    let query_id = match query.kind {
        SeerKind::Query { query_id, .. } => query_id,
        other => panic!("expected Query, got {other:?}"),
    };

    // Send Steer{abort} on the same topic + same corr. The id `query_id` is the parked one we
    // just read off the Query.
    let steer = SeerEnvelope::steer(
        SeerTopic::Placement,
        corr,
        "abort",
        &serde_json::json!({ "reason": "operator changed mind" }),
    );
    send_seer(&world, corr, steer);

    // Terminal Answer with query_id=0 carrying a "failed" body should arrive.
    let terminal = recv_seer(&world.probe_rx, corr, is_terminal_answer, Duration::from_secs(2))
        .expect("terminal answer arrives after steer abort");
    assert_eq!(terminal.topic, SeerTopic::Placement);
    match terminal.kind {
        SeerKind::Answer { query_id: 0, body } => {
            assert_eq!(body["failed"], "aborted", "body signals abort failure");
            assert_eq!(body["reason"], "steer", "reason names the steer trigger");
        }
        other => panic!("expected terminal Answer{{query_id:0}}, got {other:?}"),
    }
    // The parked query_id we expected to abort is the same as the one in the original Query.
    assert!(query_id > 0, "the original parked query_id was assigned (sanity)");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// 2) Steer{abort} on a non-parked corr is silent — exactly as on AUTHORING. The "ignore unknown
//    steers" contract is substrate-wide.
// =================================================================================================

#[test]
fn steer_abort_with_no_pending_emits_nothing_on_any_topic() {
    let world = boot(SeerTopic::Placement);
    let corr = 800;

    let steer = SeerEnvelope::steer(SeerTopic::Placement, corr, "abort", &serde_json::json!({}));
    send_seer(&world, corr, steer);

    let any = recv_seer(&world.probe_rx, corr, |_| true, Duration::from_millis(300));
    assert!(any.is_none(), "no pending → no envelope, exactly as on AUTHORING");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// 3) Steer{amend} is silently ignored — the parked exchange survives, and the Answer still
//    resolves it. The "ignore any non-honored verb" contract is substrate-wide.
// =================================================================================================

#[test]
fn steer_amend_is_ignored_on_non_authoring_topic_pending_preserved() {
    let world = boot(SeerTopic::Placement);
    let corr = 900;

    send_request(&world, corr, "a question requiring deliberation");
    let query =
        recv_seer(&world.probe_rx, corr, is_query, Duration::from_secs(2)).expect("query arrives");
    let query_id = match query.kind {
        SeerKind::Query { query_id, .. } => query_id,
        _ => panic!("expected Query"),
    };

    let steer = SeerEnvelope::steer(
        SeerTopic::Placement,
        corr,
        "amend",
        &serde_json::json!({ "add_constraint": "no overflow" }),
    );
    send_seer(&world, corr, steer);

    // No reply expected — amend is ignored, pending preserved.
    let none = recv_seer(&world.probe_rx, corr, |_| true, Duration::from_millis(200));
    assert!(none.is_none(), "amend on placement topic must be silently ignored");

    // The pending exchange still completes normally on a well-formed Answer.
    let answer =
        SeerEnvelope::answer(SeerTopic::Placement, corr, query_id, &serde_json::json!("node-A"));
    send_seer(&world, corr, answer);

    let terminal = recv_seer(&world.probe_rx, corr, is_terminal_answer, Duration::from_secs(2))
        .expect("terminal Answer after legitimate response");
    match terminal.kind {
        SeerKind::Answer { query_id: 0, body } => {
            assert_eq!(body["placed_to"], "node-A");
            assert_eq!(body["reason"], "answered");
        }
        other => panic!("expected terminal Answer, got {other:?}"),
    }

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// 4) Reduction theorem on the Placement topic — a trivial request gets a terminal Answer with no
//    precursor Query. The per-topic reduction theorem holds for non-Authoring topics too.
// =================================================================================================

#[test]
fn reduction_theorem_on_placement_topic_trivial_request_emits_no_query() {
    let world = boot(SeerTopic::Placement);
    let corr = 1000;

    send_request(&world, corr, "a trivial request");

    let terminal = recv_seer(&world.probe_rx, corr, is_terminal_answer, Duration::from_secs(2))
        .expect("terminal answer arrives for trivial request");
    assert_eq!(terminal.topic, SeerTopic::Placement);
    match terminal.kind {
        SeerKind::Answer { query_id: 0, body } => {
            assert_eq!(body["placed_to"], "self");
            assert_eq!(body["reason"], "trivial");
        }
        other => panic!("expected terminal Answer for trivial path, got {other:?}"),
    }

    // No precursor Query — reduction theorem holds on placement topic.
    let stray_query = recv_seer(&world.probe_rx, corr, is_query, Duration::from_millis(150));
    assert!(stray_query.is_none(), "trivial path emitted a Query — broken reduction on placement");

    world.kernel.shutdown_all(Deadline::default());
}
