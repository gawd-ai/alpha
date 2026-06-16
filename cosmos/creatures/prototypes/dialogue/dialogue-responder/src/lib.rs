//! `dialogue-responder` — the reference standing consumer for the SEER `dialogue` topic.
//!
//! The *peer* half of the agent-to-agent dialogue seam. It binds a SEER inbox and answers every
//! dialogue `Query` (a conversation *turn*) with an injected [`Responder`] model — the reference
//! [`EchoResponder`] echoes the prompt back, proving the round-trip. A real deployment forks the
//! decision into an LLM call while keeping the standing-responder skeleton from [`seer::responder`];
//! the decision is the only part a concrete agent writes.
//!
//! Because the answer rides the request's `reply_to` (rewritten by transport on the cross-node path),
//! the responder doesn't know — or need to know — whether its partner is local, on a peer node, or in
//! a peer Realm reached through the Omega gateway. The same creature is the conversation peer in all
//! three topologies, which is what lets the v0.5.0 "two AIs across the mesh" story drop onto this
//! exact seam.
//!
//! ## What it deliberately doesn't do
//!
//! - **It doesn't initiate.** A responder only answers turns addressed to it; the
//!   `dialogue-initiator` is the side that opens a conversation and names the peer.
//! - **It doesn't time out, and never replies to a malformed turn.** A turn it can't decode, on the
//!   wrong topic, or over the topic's size cap is dropped silently — the shared consult posture.

use aether::{Creature, CreatureCtx, Envelope, Outcome};
use seer::{responder::respond_query, topics::dialogue, SeerTopic};

/// The injected conversation model: given the peer's turn (`prompt`), produce this responder's reply.
/// The one part a concrete conversational agent writes; everything else is the shared skeleton.
pub trait Responder: Send {
    fn respond(&self, prompt: &str) -> String;
}

/// The reference [`Responder`]: echo the prompt back with a short tag, so a test (and a human reading
/// the sense-tape) can see the turn made the full round-trip. NOT a model — the placeholder an
/// LLM-backed agent replaces.
pub struct EchoResponder;

impl Responder for EchoResponder {
    fn respond(&self, prompt: &str) -> String {
        format!("echo: {prompt}")
    }
}

/// The reference dialogue responder. Stateless across turns: every Query is answered by the same
/// injected model, so retries and reordering don't change the reply.
pub struct DialogueResponder {
    model: Box<dyn Responder>,
}

impl DialogueResponder {
    /// Build a responder over an injected [`Responder`] model.
    pub fn new(model: Box<dyn Responder>) -> Self {
        DialogueResponder { model }
    }

    /// Build the reference echo responder.
    pub fn echo() -> Self {
        DialogueResponder::new(Box::new(EchoResponder))
    }

    fn decide(&self, q: dialogue::QueryBody) -> dialogue::AnswerBody {
        dialogue::AnswerBody { reply: self.model.respond(&q.prompt) }
    }
}

impl Creature for DialogueResponder {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Standing-responder skeleton: schema / bounded-parse / topic-isolation / Query-only / shape
        // check, then our decision. A turn whose prompt is over the topic cap is dropped silently.
        respond_query::<dialogue::QueryBody, dialogue::AnswerBody>(
            &env,
            SeerTopic::Dialogue,
            |q| q.prompt.len() <= dialogue::MAX_TURN_BYTES,
            |q| self.decide(q),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, CreatureId, Dispatch, Header};
    use seer::{SeerEnvelope, SeerKind, SCHEMA as SEER_SCHEMA};

    fn seer_env(corr: u64, payload: Vec<u8>) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(11)),
                to: Address::Creature(CreatureId(99)),
                reply_to: Some(Address::Creature(CreatureId(11))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: SEER_SCHEMA.to_string(),
                origin: None,
            },
            payload,
        }
    }

    fn turn(corr: u64, query_id: u64, prompt: &str) -> Envelope {
        let q = SeerEnvelope::query(
            SeerTopic::Dialogue,
            corr,
            query_id,
            &dialogue::QueryBody { prompt: prompt.into() },
        );
        seer_env(corr, q.to_bytes())
    }

    fn decode_reply(d: &Dispatch) -> String {
        let env = SeerEnvelope::parse(&d.payload).expect("seer envelope");
        match env.kind {
            SeerKind::Answer { body, .. } => {
                serde_json::from_value::<dialogue::AnswerBody>(body).expect("answer body").reply
            }
            other => panic!("expected Answer, got {other:?}"),
        }
    }

    #[test]
    fn answers_a_dialogue_turn_with_the_injected_model() {
        let mut r = DialogueResponder::echo();
        let out = r.handle(turn(7, 1, "hello peer"));
        assert_eq!(out.dispatches.len(), 1, "exactly one answer per turn");
        assert_eq!(decode_reply(&out.dispatches[0]), "echo: hello peer");
    }

    #[test]
    fn drops_wrong_topic_and_oversized_turns_silently() {
        let mut r = DialogueResponder::echo();
        // Wrong topic.
        let q = SeerEnvelope::query(SeerTopic::Placement, 1, 1, &serde_json::json!({"x": 1}));
        assert!(r.handle(seer_env(1, q.to_bytes())).dispatches.is_empty());
        // Oversized prompt.
        let big = "x".repeat(dialogue::MAX_TURN_BYTES + 1);
        assert!(r.handle(turn(2, 1, &big)).dispatches.is_empty());
    }

    #[test]
    fn injected_model_drives_the_reply() {
        struct Shout;
        impl Responder for Shout {
            fn respond(&self, prompt: &str) -> String {
                prompt.to_uppercase()
            }
        }
        let mut r = DialogueResponder::new(Box::new(Shout));
        let out = r.handle(turn(1, 1, "quiet"));
        assert_eq!(decode_reply(&out.dispatches[0]), "QUIET");
    }
}
