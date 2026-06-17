//! `responder` — consumer-side SEER helpers: inbound classification + the standing-responder skeleton.
//!
//! Every creature that consumes the SEER bus — a *responder* that answers `Query`s, or an
//! *initiator* like `agent-curious` that sends a `Query` and handles the `Answer`/`Steer` back —
//! starts each inbound envelope the same way: is it even a SEER envelope, did it parse, is it on my
//! topic? [`classify`] is that shared gate; [`Inbound`] is its four-way verdict. A responder treats
//! every non-`Ours` verdict as "drop"; an initiator can act differently per variant (e.g. reply with
//! a structured failure on `Malformed`, dispatch on the `Ours` kind).
//!
//! [`respond_query`] builds the full *standing-responder* skeleton on top of [`classify`]:
//!
//! 1. [`classify`] — not-SEER / malformed / wrong-topic all drop; only an `Ours` envelope continues.
//! 2. Accept only [`SeerKind::Query`]; an `Answer`/`Steer`/`Progress`/`Thought` arriving at a
//!    responder means someone confused it for an initiator — dropped silently.
//! 3. Typed-decode the body to the topic's `QueryBody`; shape-check it; if both pass, run the
//!    injected decision and reply on the request's `reply_to` (falling back to its `from`).
//!
//! So a new standing responder is just *a topic + a typed body + a decision* — see [`respond_query`].
//! Every responder drop is silent and allocation-bounded, the same posture the consult creatures
//! already commit to.

use aether::{Dispatch, Envelope, Outcome};
use serde::{de::DeserializeOwned, Serialize};

use crate::{SeerEnvelope, SeerKind, SeerParseError, SeerTopic, SCHEMA};

/// The verdict of [`classify`]: what an inbound envelope is, relative to a bound `topic`.
///
/// A responder maps everything but [`Inbound::Ours`] to a silent drop. A conversation initiator may
/// branch per variant — `agent-curious` routes [`Inbound::NotSeer`] to its authoring-request entry,
/// answers [`Inbound::Malformed`] with a structured failure, drops [`Inbound::OtherTopic`], and
/// dispatches on the [`Inbound::Ours`] kind.
pub enum Inbound {
    /// Not a SEER envelope at all — `header.schema` isn't [`SCHEMA`]. (For a consumer that also
    /// handles a non-SEER entry envelope, this is where it routes.)
    NotSeer,
    /// A SEER-schema envelope whose payload didn't parse (malformed or over [`crate::MAX_SEER_ENVELOPE_BYTES`]).
    /// The topic couldn't even be read; the error is carried so the caller can surface it.
    Malformed(SeerParseError),
    /// A well-formed SEER envelope on a *different* topic — topic isolation by creature
    /// discrimination; a responder drops it.
    OtherTopic,
    /// A well-formed SEER envelope on the bound `topic` — consume its [`SeerEnvelope::kind`].
    Ours(SeerEnvelope),
}

/// Classify an inbound envelope against a bound `topic`: the shared first gate for every SEER
/// consumer (responder and initiator alike). Reads `header.schema`, then [`SeerEnvelope::parse_bounded`],
/// then the topic — see [`Inbound`] for the four outcomes. Pure; allocates only the parsed envelope.
pub fn classify(env: &Envelope, topic: SeerTopic) -> Inbound {
    if env.header.schema != SCHEMA {
        return Inbound::NotSeer;
    }
    let seer = match SeerEnvelope::parse_bounded(&env.payload) {
        Ok(s) => s,
        Err(e) => return Inbound::Malformed(e),
    };
    if seer.topic != topic {
        return Inbound::OtherTopic;
    }
    Inbound::Ours(seer)
}

/// Drive the standard standing-responder skeleton for one `Query` on `topic`.
///
/// Returns [`Outcome::none`] for every envelope that isn't a well-shaped SEER `Query` on `topic`
/// (wrong schema, malformed/oversized payload, wrong topic, non-`Query` kind, undecodable or
/// shape-invalid body). For a valid one it calls `decide` and returns a single SEER `Answer`
/// addressed via [`Dispatch::reply_to_env`] with the request's `corr` preserved — the same reply
/// discipline `embodiment-advertiser` uses, so transport rewrites `reply_to` on the cross-node path
/// and the answer ships back to a local or peer requester without the responder knowing which.
///
/// - `Q` — the topic's `QueryBody` (one of [`crate::topics`]).
/// - `A` — the topic's `AnswerBody`.
/// - `query_ok` — a pure shape check on the decoded query (reject hostile/oversized inputs *before*
///   deciding); return `false` to drop silently. Pass `|_| true` to accept any decodable body.
/// - `decide` — the injected model: the *only* part a concrete responder writes. May capture and
///   mutate the responder's own state (it runs at most once per call).
///
/// `decide` runs only after `query_ok` passes, so a responder never has to re-validate inside it.
pub fn respond_query<Q, A>(
    env: &Envelope,
    topic: SeerTopic,
    query_ok: impl FnOnce(&Q) -> bool,
    decide: impl FnOnce(Q) -> A,
) -> Outcome
where
    Q: DeserializeOwned,
    A: Serialize,
{
    respond_query_corr(env, topic, query_ok, |_corr, q| decide(q))
}

/// Like [`respond_query`], but `decide` also receives the conversation `corr`. The `corr` is needed
/// when the answer body binds itself to the turn it answers — e.g. the `dialogue` topic's app-signed
/// provenance (ADR-0038) signs over `(corr, prompt, reply)`. [`respond_query`] is the zero-corr
/// special case, so existing responders that don't bind to `corr` are unaffected.
pub fn respond_query_corr<Q, A>(
    env: &Envelope,
    topic: SeerTopic,
    query_ok: impl FnOnce(&Q) -> bool,
    decide: impl FnOnce(u64, Q) -> A,
) -> Outcome
where
    Q: DeserializeOwned,
    A: Serialize,
{
    // (1) Shared inbound gate: not-SEER / malformed / wrong-topic all drop silently — a responder
    // has no "I couldn't parse you" reply channel; answering one would imply it adjudicates wire
    // mismatches, which it doesn't.
    let seer = match classify(env, topic) {
        Inbound::Ours(s) => s,
        Inbound::NotSeer | Inbound::Malformed(_) | Inbound::OtherTopic => return Outcome::none(),
    };
    // (2) Only the answering move is ours.
    let (query_id, body) = match seer.kind {
        SeerKind::Query { query_id, body } => (query_id, body),
        _ => return Outcome::none(),
    };
    // (3) Typed-decode + shape-check, then decide.
    let q: Q = match serde_json::from_value(body) {
        Ok(q) => q,
        Err(_) => return Outcome::none(),
    };
    if !query_ok(&q) {
        return Outcome::none();
    }
    let answer_body = decide(seer.corr, q);
    let answer = SeerEnvelope::answer(topic, seer.corr, query_id, &answer_body);
    let dispatch =
        Dispatch::reply_to_env(env, answer.to_bytes()).with_schema(SCHEMA).with_corr(seer.corr);
    Outcome::send(dispatch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Header};
    use serde::Deserialize;

    #[derive(Serialize, Deserialize)]
    struct Q {
        n: u64,
    }
    #[derive(Serialize, Deserialize)]
    struct A {
        doubled: u64,
    }

    fn env_with(schema: &str, payload: Vec<u8>) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(99)),
                reply_to: Some(Address::Creature(CreatureId(11))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(7),
                commitment: None,
                schema: schema.to_string(),
                origin: None,
            },
            payload,
        }
    }

    fn query_env(topic: SeerTopic, n: u64) -> Envelope {
        let q = SeerEnvelope::query(topic, 7, 3, &Q { n });
        env_with(SCHEMA, q.to_bytes())
    }

    fn double(env: &Envelope, topic: SeerTopic) -> Outcome {
        respond_query::<Q, A>(env, topic, |q| q.n < 1000, |q| A { doubled: q.n * 2 })
    }

    #[test]
    fn answers_a_valid_query_on_its_topic() {
        let out = double(&query_env(SeerTopic::Policy, 21), SeerTopic::Policy);
        assert_eq!(out.dispatches.len(), 1, "exactly one answer per query");
        let d = &out.dispatches[0];
        assert_eq!(d.schema, SCHEMA);
        assert_eq!(d.corr, Some(7), "request corr preserved");
        // reply addressed at the request's reply_to.
        assert_eq!(d.to, Address::Creature(CreatureId(11)));
        let ans = SeerEnvelope::parse(&d.payload).unwrap();
        assert_eq!(ans.topic, SeerTopic::Policy);
        match ans.kind {
            SeerKind::Answer { query_id, body } => {
                assert_eq!(query_id, 3, "query_id echoed");
                let a: A = serde_json::from_value(body).unwrap();
                assert_eq!(a.doubled, 42);
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn drops_wrong_topic_schema_kind_and_shape() {
        // Wrong topic (bound to Policy, query on Budget).
        assert!(double(&query_env(SeerTopic::Budget, 1), SeerTopic::Policy).dispatches.is_empty());
        // Wrong schema.
        assert!(double(&env_with("text/plain", b"x".to_vec()), SeerTopic::Policy)
            .dispatches
            .is_empty());
        // Malformed payload.
        assert!(double(&env_with(SCHEMA, b"not json".to_vec()), SeerTopic::Policy)
            .dispatches
            .is_empty());
        // Oversized payload (over the bounded-parse cap).
        assert!(double(
            &env_with(SCHEMA, vec![b'{'; crate::MAX_SEER_ENVELOPE_BYTES + 1]),
            SeerTopic::Policy
        )
        .dispatches
        .is_empty());
        // shape-check rejects (n >= 1000).
        assert!(double(&query_env(SeerTopic::Policy, 5000), SeerTopic::Policy)
            .dispatches
            .is_empty());
        // Non-Query kind.
        let ans = SeerEnvelope::answer(SeerTopic::Policy, 7, 0, &A { doubled: 0 });
        assert!(double(&env_with(SCHEMA, ans.to_bytes()), SeerTopic::Policy).dispatches.is_empty());
    }

    #[test]
    fn reply_falls_back_to_from_when_no_reply_to() {
        let mut env = query_env(SeerTopic::Fitness, 4);
        env.header.reply_to = None;
        env.header.from = Address::Creature(CreatureId(33));
        let out = respond_query::<Q, A>(&env, SeerTopic::Fitness, |_| true, |q| A { doubled: q.n });
        assert_eq!(out.dispatches[0].to, Address::Creature(CreatureId(33)));
    }

    #[test]
    fn classify_returns_the_four_verdicts() {
        // NotSeer — wrong schema.
        assert!(matches!(
            classify(&env_with("text/plain", b"x".to_vec()), SeerTopic::Policy),
            Inbound::NotSeer
        ));
        // Malformed — SEER schema, unparseable payload (carries the error for the caller to surface).
        assert!(matches!(
            classify(&env_with(SCHEMA, b"not json".to_vec()), SeerTopic::Policy),
            Inbound::Malformed(_)
        ));
        // Malformed — oversized payload surfaces a TooLarge whose Display says "too large".
        match classify(
            &env_with(SCHEMA, vec![b'{'; crate::MAX_SEER_ENVELOPE_BYTES + 1]),
            SeerTopic::Policy,
        ) {
            Inbound::Malformed(e) => assert!(e.to_string().contains("too large")),
            _ => panic!("expected Malformed for an oversized payload"),
        }
        // OtherTopic — well-formed, wrong topic.
        assert!(matches!(
            classify(&query_env(SeerTopic::Budget, 1), SeerTopic::Policy),
            Inbound::OtherTopic
        ));
        // Ours — well-formed on the bound topic.
        assert!(matches!(
            classify(&query_env(SeerTopic::Policy, 1), SeerTopic::Policy),
            Inbound::Ours(_)
        ));
    }
}
