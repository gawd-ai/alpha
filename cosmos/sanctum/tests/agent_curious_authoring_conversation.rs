//! Integration coverage for
//! [`agent_curious::AgentCurious`], a consumer of the
//! `AuthoringQuery`/`AuthoringAnswer` curiosity / alimentation seam. Those
//! schemas ride the substrate-wide [`SeerEnvelope`] on the `authoring` topic; the
//! **behavioral contract is byte-identical** to AUTHORING-only schemas —
//! topic-keyed SeerEnvelope on a single schema string (`"seer"`).
//!
//! Each scenario boots an in-process kernel, loads `AgentCurious` bound to `Role::AUTHORING`, and
//! exercises one shape of the conversation contract on the **real bus** (not a unit-test
//! `handle()` call):
//!
//! 1. [`template_match_replies_terminally_no_query`] — reduction theorem: a request matching a
//!    template emits only a terminal `AuthoringReply`. No SEER traffic; the conversation
//!    collapses to single-shot. Wire-identical to agent-templated for that request.
//! 2. [`unmatched_request_drives_query_then_terminal_reply_on_answer`] — the happy path
//!    on the SEER wire: probe → Request, creature → `SeerEnvelope::{Thought, Progress,
//!    Query}` (topic=Authoring), probe → `SeerEnvelope::Answer`, creature → terminal Reply.
//!    Proves the `(corr, query_id)` pairing key survives the real bus + that the creature's
//!    pending state resumes on the right answer.
//! 3. [`steer_abort_mid_conversation_cancels_pending_and_emits_failed_reply`] — proves the
//!    inbound `SeerEnvelope::Steer` seam: probe → Request, creature → Query, probe → Steer
//!    {abort}, creature → terminal Failed reply. The orchestrator's mid-flight veto reaches the
//!    creature and the parked exchange is dropped.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Bus, Deadline, Dispatch, Envelope, InboxReceiver, Role};
use agent_curious::{schema, AgentCurious};
use agent_templated::{AuthoringError, AuthoringReply, AuthoringRequest};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use seer::{topics, SeerEnvelope, SeerKind, SeerTopic};
use sigil::{Backend, Capabilities, Manifest};

fn make_kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("m6-node")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

/// Boot world for one test: kernel + AgentCurious bound on AUTHORING + a probe endpoint
/// the test sends/receives through.
struct World {
    kernel: Arc<Kernel>,
    /// The agent's creature id — the probe needs it to address SEER Answer / Steer directly at
    /// the creature (rather than at `Role::AUTHORING`, which would broadcast to every AUTHORING
    /// creature on the node; in this test there's only one, but addressing direct is the
    /// contract the ADR sets — the orchestrator learns `from` off the Query envelope).
    agent_id: aether::CreatureId,
    probe_bus: aether::BusHandle,
    probe_rx: InboxReceiver,
}

fn boot() -> World {
    let kernel = make_kernel();
    let agent_manifest =
        Manifest::new("agent-curious", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    let agent_id = kernel
        .load_instance(agent_manifest, Box::new(AgentCurious::new()))
        .expect("agent-curious admits");
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);

    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    World { kernel, agent_id, probe_bus, probe_rx }
}

/// Receive one envelope whose `corr` matches `corr` *and* whose `schema` matches `wanted_schema`.
/// Drops envelopes that don't match (stray proprio events, late envelopes from a previous step).
/// Returns `None` if `deadline` elapses with no match.
fn recv_matching_schema(
    rx: &InboxReceiver,
    corr: u64,
    wanted_schema: &str,
    deadline: Duration,
) -> Option<Envelope> {
    let stop = std::time::Instant::now() + deadline;
    while std::time::Instant::now() < stop {
        let remaining = stop.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) => {
                if env.header.corr == Some(corr) && env.header.schema == wanted_schema {
                    return Some(env);
                }
                // Otherwise drop the envelope and keep waiting — it's an out-of-step message we
                // don't care about for this assertion.
            }
            Err(_) => continue,
        }
    }
    None
}

/// Receive the next SEER envelope whose `corr` matches and whose `SeerKind` matches the
/// `predicate` (lets a test distinguish a Query from a Progress when both ride schema=seer).
fn recv_seer<F>(
    rx: &InboxReceiver,
    corr: u64,
    predicate: F,
    deadline: Duration,
) -> Option<(Envelope, SeerEnvelope)>
where
    F: Fn(&SeerKind) -> bool,
{
    let stop = std::time::Instant::now() + deadline;
    while std::time::Instant::now() < stop {
        let remaining = stop.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(200))) {
            Ok(env) => {
                if env.header.corr != Some(corr) || env.header.schema != schema::SEER {
                    continue;
                }
                if let Ok(seer) = SeerEnvelope::parse(&env.payload) {
                    if seer.topic == SeerTopic::Authoring && predicate(&seer.kind) {
                        return Some((env, seer));
                    }
                }
            }
            Err(_) => continue,
        }
    }
    None
}

/// Send an `AuthoringRequest` JSON payload to the agent at `Role::AUTHORING` (the request entry
/// is *not* a SEER envelope — it's the authoring entry).
fn send_request(world: &World, corr: u64, req: &AuthoringRequest) {
    let bytes = serde_json::to_vec(req).expect("request serializes");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), bytes)
                .with_schema(schema::REQUEST)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("send request to AUTHORING");
}

/// Send a SEER envelope to the agent directly (Answer/Steer follow-ups address the agent's
/// creature id, learned from the Query's `from`).
fn send_seer(world: &World, corr: u64, seer: SeerEnvelope) {
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(world.agent_id), seer.to_bytes())
                .with_schema(schema::SEER)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("send seer envelope to agent");
}

// =================================================================================================
// 1) Reduction theorem on the real bus — template match emits no SEER traffic.
// =================================================================================================

#[test]
fn template_match_replies_terminally_no_query() {
    let world = boot();
    let corr = 1;

    let req = AuthoringRequest {
        request: "write a daemon that reverses a string".into(),
        ..Default::default()
    };
    send_request(&world, corr, &req);

    let env = recv_matching_schema(&world.probe_rx, corr, schema::REPLY, Duration::from_secs(2))
        .expect("template-match emits a terminal reply within budget");
    assert_eq!(env.header.schema, schema::REPLY);
    let reply: AuthoringReply = serde_json::from_slice(&env.payload).expect("reply decodes");
    match reply {
        AuthoringReply::Authored(r) => {
            assert_eq!(r.crate_name, "reverse-daemon");
            assert_eq!(r.template, "agent-curious/reverse");
        }
        AuthoringReply::Failed(e) => panic!("expected Authored, got Failed({e:?})"),
    }

    // Reduction theorem: there should be **no** SEER envelope on the wire for this corr.
    let stray =
        recv_matching_schema(&world.probe_rx, corr, schema::SEER, Duration::from_millis(150));
    assert!(stray.is_none(), "template match emitted SEER envelopes — broken reduction theorem");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// 2) Embryo happy path — Request → SEER Query → SEER Answer → Reply roundtrip across the bus.
// =================================================================================================

#[test]
fn unmatched_request_drives_query_then_terminal_reply_on_answer() {
    let world = boot();
    let corr = 42;

    let req = AuthoringRequest {
        request: "compute the LZ77 entropy of an mp3".into(),
        ..Default::default()
    };
    send_request(&world, corr, &req);

    // The creature emits Thought + Progress + Query in one Outcome, all on schema=seer, all
    // topic=Authoring. Receive each by kind discrimination — the bus may interleave with proprio
    // events; recv_seer filters by kind predicate.
    let (_thought_env, thought_seer) = recv_seer(
        &world.probe_rx,
        corr,
        |k| matches!(k, SeerKind::Thought { .. }),
        Duration::from_secs(2),
    )
    .expect("thought arrives within budget");
    match thought_seer.kind {
        SeerKind::Thought { channel, content } => {
            assert_eq!(channel, "internal", "thought is internal-channel reasoning");
            assert!(content.contains("LZ77"), "thought references original request");
        }
        other => panic!("expected Thought, got {other:?}"),
    }

    let (_progress_env, progress_seer) = recv_seer(
        &world.probe_rx,
        corr,
        |k| matches!(k, SeerKind::Progress { .. }),
        Duration::from_secs(2),
    )
    .expect("progress arrives within budget");
    match progress_seer.kind {
        SeerKind::Progress { stage, .. } => assert_eq!(stage, "awaiting_answer"),
        other => panic!("expected Progress, got {other:?}"),
    }

    let (query_env, query_seer) = recv_seer(
        &world.probe_rx,
        corr,
        |k| matches!(k, SeerKind::Query { .. }),
        Duration::from_secs(2),
    )
    .expect("query arrives within budget");
    let query_id = match query_seer.kind {
        SeerKind::Query { query_id, body } => {
            let q: topics::authoring::QueryBody =
                serde_json::from_value(body).expect("authoring query body decodes");
            assert_eq!(query_seer.corr, corr, "query corr matches request corr");
            assert_eq!(
                q.options.as_deref(),
                Some(
                    ["reverse".to_string(), "fetch_url_title".to_string(), "abort".to_string()]
                        .as_slice()
                )
            );
            query_id
        }
        other => panic!("expected Query, got {other:?}"),
    };
    // The query carries the agent's creature id in `from` — that's how the orchestrator knows where
    // to send the Answer. Sanity-check that it's our loaded agent (not some bus stub).
    assert_eq!(query_env.header.from, Address::Creature(world.agent_id));

    // Probe answers with "reverse" — addressed *directly* at the agent's creature id, via SEER.
    let answer_body = topics::authoring::AnswerBody { content: "reverse".into() };
    let answer = SeerEnvelope::answer(SeerTopic::Authoring, corr, query_id, &answer_body);
    send_seer(&world, corr, answer);

    let reply_env =
        recv_matching_schema(&world.probe_rx, corr, schema::REPLY, Duration::from_secs(2))
            .expect("terminal reply arrives after answer");
    let reply: AuthoringReply = serde_json::from_slice(&reply_env.payload).expect("reply decodes");
    match reply {
        AuthoringReply::Authored(r) => {
            assert_eq!(r.crate_name, "reverse-daemon");
            assert_eq!(r.template, "agent-curious/reverse");
        }
        AuthoringReply::Failed(e) => {
            panic!("expected Authored after reverse answer, got Failed({e:?})")
        }
    }

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// 3) Steer{abort} mid-conversation cancels the pending exchange and emits a Failed terminal reply.
// =================================================================================================

#[test]
fn steer_abort_mid_conversation_cancels_pending_and_emits_failed_reply() {
    let world = boot();
    let corr = 500;

    let req =
        AuthoringRequest { request: "do something nondeterministic".into(), ..Default::default() };
    send_request(&world, corr, &req);

    // Wait for the Query so we know the creature is parked.
    let (_query_env, _query_seer) = recv_seer(
        &world.probe_rx,
        corr,
        |k| matches!(k, SeerKind::Query { .. }),
        Duration::from_secs(2),
    )
    .expect("query arrives before steer");

    // Probe changes its mind — emit Steer{abort} addressed at the agent's creature id.
    let steer = SeerEnvelope::steer(SeerTopic::Authoring, corr, "abort", &serde_json::json!({}));
    send_seer(&world, corr, steer);

    let reply_env =
        recv_matching_schema(&world.probe_rx, corr, schema::REPLY, Duration::from_secs(2))
            .expect("terminal Failed reply arrives after steer abort");
    let reply: AuthoringReply = serde_json::from_slice(&reply_env.payload).expect("reply decodes");
    match reply {
        AuthoringReply::Failed(AuthoringError::NoTemplate { request }) => {
            assert_eq!(request, "do something nondeterministic");
        }
        other => panic!("expected Failed(NoTemplate) after steer abort, got {other:?}"),
    }

    world.kernel.shutdown_all(Deadline::default());
}
