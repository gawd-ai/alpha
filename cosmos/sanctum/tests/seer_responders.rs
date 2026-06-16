//! Live standing-consumer proof for the four reference SEER responders.
//!
//! The unit tests in each `responder-*` crate drive `handle()` directly. This test proves the
//! *standing* claim: each responder is loaded on a real [`Kernel`], a SEER `Query` is routed to it
//! **by address through the bus**, and its typed `Answer` ships back to a probe endpoint on the
//! request's `reply_to`. That is the end-to-end path an operator (or another creature) uses to
//! consult one of the reserved topics — `policy` / `budget` / `fitness` / `curation` — which until
//! now had a typed body but no creature to stand on them.
//!
//! Each responder is loaded under [`DevPolicy`] (admit-all), bound to no Role — the probe addresses
//! it directly by [`aether::CreatureId`], mirroring how a distributor addresses an advertiser on a
//! peer. The reply discipline is the shared `seer::responder` skeleton's: `reply_to` first, else the
//! sender.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Bus, CreatureId, Deadline, Dispatch, InboxReceiver};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use seer::{topics, SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};
use sigil::{Backend, Capabilities, Manifest};

use responder_budget::BudgetResponder;
use responder_curation::CurationResponder;
use responder_fitness::FitnessResponder;
use responder_policy::PolicyResponder;

fn make_kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("seer-responders-test")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn load(kernel: &Arc<Kernel>, name: &str, creature: Box<dyn aether::Creature>) -> CreatureId {
    let manifest = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    kernel.load_instance(manifest, creature).expect("responder admits under dev policy")
}

/// Send a SEER `Query` to `to`, with the probe as `reply_to`, and return the single decoded Answer
/// envelope the responder ships back (panics if none arrives within the window).
fn consult<B: serde::Serialize>(
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    to: CreatureId,
    topic: SeerTopic,
    body: &B,
) -> SeerEnvelope {
    let corr = 4242;
    let query = SeerEnvelope::query(topic, corr, 1, body);
    bus.emit(
        Dispatch::to(Address::Creature(to), query.to_bytes())
            .with_schema(SEER_SCHEMA)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(corr),
    )
    .expect("probe emits query");

    let stop = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < stop {
        let remaining = stop.saturating_duration_since(std::time::Instant::now());
        if let Ok(env) = rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            if env.header.schema == SEER_SCHEMA {
                if let Ok(seer) = SeerEnvelope::parse(&env.payload) {
                    assert_eq!(seer.corr, corr, "answer preserves the query corr");
                    return seer;
                }
            }
        }
    }
    panic!("no SEER answer on topic {topic:?} within the window");
}

fn answer_body<T: serde::de::DeserializeOwned>(seer: &SeerEnvelope) -> T {
    match &seer.kind {
        SeerKind::Answer { body, .. } => serde_json::from_value(body.clone()).expect("answer body"),
        other => panic!("expected Answer, got {other:?}"),
    }
}

#[test]
fn all_four_reserved_topics_are_live_standing_consults() {
    let kernel = make_kernel();

    let policy_id =
        load(&kernel, "responder-policy", Box::new(PolicyResponder::allowlist(["sha256:ok"])));
    let budget_id = load(&kernel, "responder-budget", Box::new(BudgetResponder::with_ceiling(100)));
    let fitness_id = load(&kernel, "responder-fitness", Box::new(FitnessResponder::constant(0.5)));
    let curation_id = load(
        &kernel,
        "responder-curation",
        Box::new(CurationResponder::new(["sha256:bad"], [] as [&str; 0])),
    );

    let (_probe, bus, rx) = kernel.open_endpoint(Capabilities::default());

    // policy — listed hash admits, unlisted denies.
    let admit: topics::policy::AnswerBody = answer_body(&consult(
        &bus,
        &rx,
        policy_id,
        SeerTopic::Policy,
        &topics::policy::QueryBody { manifest_hash: "sha256:ok".into() },
    ));
    assert!(admit.admit, "allowlisted manifest is admitted");
    let deny: topics::policy::AnswerBody = answer_body(&consult(
        &bus,
        &rx,
        policy_id,
        SeerTopic::Policy,
        &topics::policy::QueryBody { manifest_hash: "sha256:nope".into() },
    ));
    assert!(!deny.admit, "unlisted manifest is denied");

    // budget — granted up to the ceiling.
    let grant: topics::budget::AnswerBody = answer_body(&consult(
        &bus,
        &rx,
        budget_id,
        SeerTopic::Budget,
        &topics::budget::QueryBody { request_units: 250, justification: "near cap".into() },
    ));
    assert!(grant.granted && grant.granted_units == 100, "ceiling-capped grant");

    // fitness — the constant rater's score, clamped.
    let score: topics::fitness::AnswerBody = answer_body(&consult(
        &bus,
        &rx,
        fitness_id,
        SeerTopic::Fitness,
        &topics::fitness::QueryBody {
            candidate_hash: "sha256:cand".into(),
            criterion: "success-rate".into(),
        },
    ));
    assert_eq!(score.score, 0.5);

    // curation — quarantine-listed artifact is withheld; everything else kept.
    let q: topics::curation::AnswerBody = answer_body(&consult(
        &bus,
        &rx,
        curation_id,
        SeerTopic::Curation,
        &topics::curation::QueryBody {
            realm: "global".into(),
            artifact_hash: "sha256:bad".into(),
            manifest_hash: "sha256:m".into(),
        },
    ));
    assert_eq!(q.decision, "quarantine");
    let keep: topics::curation::AnswerBody = answer_body(&consult(
        &bus,
        &rx,
        curation_id,
        SeerTopic::Curation,
        &topics::curation::QueryBody {
            realm: "global".into(),
            artifact_hash: "sha256:fresh".into(),
            manifest_hash: "sha256:m".into(),
        },
    ));
    assert_eq!(keep.decision, "keep");

    kernel.shutdown_all(Deadline::default());
}

/// A Query on the wrong topic, delivered (by address) to a responder bound to a different topic, is
/// dropped silently — no Answer, no panic. Mirrors the substrate-wide topic-isolation discipline,
/// proven here through the live bus rather than a direct `handle()` call.
#[test]
fn wrong_topic_query_to_a_responder_is_silently_dropped() {
    let kernel = make_kernel();
    let policy_id = load(&kernel, "responder-policy", Box::new(PolicyResponder::admit_all()));
    let (_probe, bus, rx) = kernel.open_endpoint(Capabilities::default());

    // A budget Query addressed to the policy responder — delivered, but dropped at its topic check.
    let corr = 9;
    let wrong = SeerEnvelope::query(
        SeerTopic::Budget,
        corr,
        1,
        &topics::budget::QueryBody { request_units: 1, justification: "x".into() },
    );
    bus.emit(
        Dispatch::to(Address::Creature(policy_id), wrong.to_bytes())
            .with_schema(SEER_SCHEMA)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(corr),
    )
    .expect("probe emits wrong-topic query");

    let mut answers = 0usize;
    let stop = std::time::Instant::now() + Duration::from_millis(250);
    while std::time::Instant::now() < stop {
        let remaining = stop.saturating_duration_since(std::time::Instant::now());
        if let Ok(env) = rx.recv_timeout(remaining.min(Duration::from_millis(50))) {
            if env.header.schema == SEER_SCHEMA {
                answers += 1;
            }
        }
    }
    assert_eq!(answers, 0, "wrong-topic query must produce no answer");

    kernel.shutdown_all(Deadline::default());
}
