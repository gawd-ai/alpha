//! Topic isolation across the substrate-wide SEER primitive.
//!
//! Same wire schema (`"seer"`), same `corr` (`42` in both halves), two different
//! [`SeerTopic`]s. The substrate has NO router-level topic discrimination: it routes by
//! address. Topic walls are enforced at the consumer layer — a creature bound to topic A reads
//! the SeerEnvelope, sees `topic != mine`, and silently drops. There is no Failed reply on
//! cross-topic, because that would be the substrate adjudicating a model dispute via the
//! creature.
//!
//! This test proves the wall holds when same-corr envelopes flow at the same time to two
//! creatures bound to different topics. Each creature receives only the envelopes for *its*
//! topic (delivered by address; filtered by topic at decode time). The corr collision is
//! deliberate — it would matter if the substrate were tracking SEER conversations by `corr`
//! alone (it isn't, by design).

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use aether::{
    Address, Bus, Creature, CreatureCtx, Deadline, Dispatch, Envelope, InboxReceiver, Outcome, Role,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use seer::{SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};
use sigil::{Backend, Capabilities, Manifest};

/// A test creature that consumes SEER envelopes on exactly one topic; envelopes on other
/// topics are silently dropped (the substrate-wide topic-isolation discipline). Every accepted
/// envelope is appended to a shared log so the test can assert what reached the creature.
///
/// The reply contract: on a `SeerEnvelope::Answer` for the bound topic, the creature emits a
/// terminal SEER Answer on the same topic, addressed back to the requester via `reply_to`,
/// echoing the original body so the test can verify *which* envelope crossed.
struct TopicConsumer {
    bound_topic: SeerTopic,
    seen: Arc<Mutex<Vec<(SeerTopic, SeerKind)>>>,
}

impl TopicConsumer {
    fn new(bound_topic: SeerTopic, seen: Arc<Mutex<Vec<(SeerTopic, SeerKind)>>>) -> Self {
        TopicConsumer { bound_topic, seen }
    }
}

impl Creature for TopicConsumer {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SEER_SCHEMA {
            return Outcome::none();
        }
        let seer = match SeerEnvelope::parse(&env.payload) {
            Ok(o) => o,
            Err(_) => return Outcome::none(),
        };
        if seer.topic != self.bound_topic {
            // Substrate-wide topic-isolation discipline: drop silently. No Failed reply (that
            // would be the substrate adjudicating cross-topic via this creature).
            return Outcome::none();
        }
        self.seen.lock().unwrap().push((seer.topic, seer.kind.clone()));
        // Echo back the body on a terminal Answer (same topic, same corr, same query_id) so the
        // test can verify wire delivery for matched topics.
        let echo = match seer.kind {
            SeerKind::Answer { query_id, body } => {
                SeerEnvelope::answer(seer.topic, seer.corr, query_id, &body)
            }
            // For any non-Answer kind (Query/Steer/Progress/Thought), reply with a synthetic
            // Answer signalling "received" — the test doesn't drive these but keeping the
            // creature responsive to its bound topic is the contract.
            other => SeerEnvelope::answer(
                seer.topic,
                seer.corr,
                0,
                &serde_json::json!({ "echoed_kind": format!("{other:?}") }),
            ),
        };
        let to = env.header.reply_to.unwrap_or(env.header.from);
        Outcome::send(
            Dispatch::to(to, echo.to_bytes()).with_schema(SEER_SCHEMA).with_corr(seer.corr),
        )
    }
}

fn make_kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("seer-topic-test")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

/// Boot world: kernel + two consumers (one on Authoring, one on Placement) + a probe endpoint.
struct World {
    kernel: Arc<Kernel>,
    authoring_id: aether::CreatureId,
    placement_id: aether::CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
    seen_authoring: Arc<Mutex<Vec<(SeerTopic, SeerKind)>>>,
    seen_placement: Arc<Mutex<Vec<(SeerTopic, SeerKind)>>>,
}

fn boot() -> World {
    let kernel = make_kernel();
    let seen_authoring: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_placement: Arc<Mutex<Vec<_>>> = Arc::new(Mutex::new(Vec::new()));

    let a_manifest =
        Manifest::new("topic-consumer-authoring", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    let authoring_id = kernel
        .load_instance(
            a_manifest,
            Box::new(TopicConsumer::new(SeerTopic::Authoring, seen_authoring.clone())),
        )
        .expect("authoring consumer admits");

    let p_manifest =
        Manifest::new("topic-consumer-placement", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    let placement_id = kernel
        .load_instance(
            p_manifest,
            Box::new(TopicConsumer::new(SeerTopic::Placement, seen_placement.clone())),
        )
        .expect("placement consumer admits");

    // Bind each on its own Role so the probe can address by Role for one scenario; for
    // cross-topic we address by creature id directly.
    kernel.bind_role(Role::new(Role::AUTHORING), authoring_id);
    kernel.bind_role(Role::new("placement"), placement_id);

    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    World {
        kernel,
        authoring_id,
        placement_id,
        probe_bus,
        probe_rx,
        seen_authoring,
        seen_placement,
    }
}

/// Send a SeerEnvelope to `to`, addressed at the probe's reply_to.
fn send_seer(world: &World, to: Address, seer: SeerEnvelope) {
    world
        .probe_bus
        .emit(
            Dispatch::to(to, seer.to_bytes())
                .with_schema(SEER_SCHEMA)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(seer.corr),
        )
        .expect("probe sends seer envelope");
}

/// Drain the probe inbox for `dur` collecting every SEER envelope; returns the decoded list.
fn drain_seer(rx: &InboxReceiver, dur: Duration) -> Vec<SeerEnvelope> {
    let stop = std::time::Instant::now() + dur;
    let mut out = Vec::new();
    while std::time::Instant::now() < stop {
        let remaining = stop.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(env) => {
                if env.header.schema == SEER_SCHEMA {
                    if let Ok(o) = SeerEnvelope::parse(&env.payload) {
                        out.push(o);
                    }
                }
            }
            Err(_) => continue,
        }
    }
    out
}

// =================================================================================================
// 1) Same corr, two topics — each envelope reaches only the creature bound to its topic.
// =================================================================================================

#[test]
fn same_corr_envelopes_do_not_cross_topic_walls() {
    let world = boot();
    let corr = 42;

    // Two envelopes, both with corr=42 — one on Authoring topic addressed to the authoring
    // consumer, one on Placement topic addressed to the placement consumer. The substrate has
    // no router-level topic concept; isolation is by the creatures' topic discrimination at
    // decode time.
    let auth_answer = SeerEnvelope::answer(
        SeerTopic::Authoring,
        corr,
        1,
        &serde_json::json!({ "from": "authoring-side" }),
    );
    send_seer(&world, Address::Creature(world.authoring_id), auth_answer.clone());

    let plc_answer = SeerEnvelope::answer(
        SeerTopic::Placement,
        corr,
        1,
        &serde_json::json!({ "from": "placement-side" }),
    );
    send_seer(&world, Address::Creature(world.placement_id), plc_answer.clone());

    // Collect the echoes for ~500ms — both creatures echo back their bound-topic envelopes.
    let echoes = drain_seer(&world.probe_rx, Duration::from_millis(500));
    assert_eq!(echoes.len(), 2, "two echoes expected (one per creature)");

    let mut got_auth = false;
    let mut got_plc = false;
    for e in &echoes {
        match e.topic {
            SeerTopic::Authoring => got_auth = true,
            SeerTopic::Placement => got_plc = true,
            other => panic!("unexpected topic in echo: {other:?}"),
        }
        assert_eq!(e.corr, corr, "echo preserves corr=42");
    }
    assert!(got_auth, "authoring-side echo missing — wall over-isolated");
    assert!(got_plc, "placement-side echo missing — wall over-isolated");

    // Per-creature `seen` logs prove the isolation: each creature saw only its bound topic.
    let auth_seen = world.seen_authoring.lock().unwrap().clone();
    let plc_seen = world.seen_placement.lock().unwrap().clone();
    assert_eq!(auth_seen.len(), 1, "authoring saw exactly one envelope");
    assert_eq!(plc_seen.len(), 1, "placement saw exactly one envelope");
    assert_eq!(auth_seen[0].0, SeerTopic::Authoring, "authoring's seen entry is Authoring topic");
    assert_eq!(plc_seen[0].0, SeerTopic::Placement, "placement's seen entry is Placement topic");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// 2) An envelope on the wrong topic, delivered (by address) to the wrong creature, is dropped
//    silently — no Failed reply, no panic, no log entry.
// =================================================================================================

#[test]
fn cross_topic_envelope_to_wrong_consumer_is_silently_dropped() {
    let world = boot();
    let corr = 99;

    // Address a Placement-topic envelope to the AUTHORING consumer. The substrate delivers by
    // address — the authoring creature receives the envelope — but the creature's topic check
    // drops it on the floor.
    let wrong = SeerEnvelope::answer(
        SeerTopic::Placement,
        corr,
        7,
        &serde_json::json!({ "should": "be ignored" }),
    );
    send_seer(&world, Address::Creature(world.authoring_id), wrong);

    // Drain for a short window — no echoes expected (the creature dropped the envelope).
    let echoes = drain_seer(&world.probe_rx, Duration::from_millis(300));
    assert!(echoes.is_empty(), "cross-topic envelope produced unexpected echoes: {echoes:?}");

    // The authoring consumer's `seen` log is empty: the envelope was filtered out at decode.
    let auth_seen = world.seen_authoring.lock().unwrap().clone();
    assert!(auth_seen.is_empty(), "authoring consumer's seen log should be empty: {auth_seen:?}");

    // And the placement consumer didn't see anything either (the envelope wasn't addressed to it).
    let plc_seen = world.seen_placement.lock().unwrap().clone();
    assert!(plc_seen.is_empty(), "placement consumer should not have seen anything: {plc_seen:?}");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// 3) Multiple topics interleaving on the same corr — independent ordering, no envelope-id reuse.
//    Verifies the substrate's at-most-once delivery per (address, topic) pair under same-corr
//    pressure.
// =================================================================================================

#[test]
fn many_same_corr_envelopes_across_topics_stay_segregated() {
    let world = boot();
    let corr = 7;
    let n = 5; // five round-trips on each topic, all same corr

    for i in 0..n {
        let a = SeerEnvelope::answer(
            SeerTopic::Authoring,
            corr,
            i as u64,
            &serde_json::json!({ "iter": i, "side": "auth" }),
        );
        send_seer(&world, Address::Creature(world.authoring_id), a);

        let p = SeerEnvelope::answer(
            SeerTopic::Placement,
            corr,
            i as u64,
            &serde_json::json!({ "iter": i, "side": "plc" }),
        );
        send_seer(&world, Address::Creature(world.placement_id), p);
    }

    let echoes = drain_seer(&world.probe_rx, Duration::from_secs(1));
    assert_eq!(echoes.len(), n * 2, "expected {} echoes ({} per topic)", n * 2, n);

    let auth_count = echoes.iter().filter(|e| e.topic == SeerTopic::Authoring).count();
    let plc_count = echoes.iter().filter(|e| e.topic == SeerTopic::Placement).count();
    assert_eq!(auth_count, n, "authoring topic echo count");
    assert_eq!(plc_count, n, "placement topic echo count");

    // Each creature's seen log is exactly `n` entries, all on its bound topic.
    let auth_seen = world.seen_authoring.lock().unwrap().clone();
    let plc_seen = world.seen_placement.lock().unwrap().clone();
    assert_eq!(auth_seen.len(), n);
    assert_eq!(plc_seen.len(), n);
    for (t, _k) in &auth_seen {
        assert_eq!(*t, SeerTopic::Authoring);
    }
    for (t, _k) in &plc_seen {
        assert_eq!(*t, SeerTopic::Placement);
    }

    world.kernel.shutdown_all(Deadline::default());
}
