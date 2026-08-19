//! `dialogue-initiator` — the reference *opening* half of the agent-to-agent dialogue seam.
//!
//! Every other SEER consumer answers *upward* — back to whoever asked it. A dialogue initiator is the
//! exception the v0.5.0 "two AIs interacting" story needs: it opens a conversation by sending a turn
//! to a **named peer** it was configured with, not to its own requester. On a `START_SCHEMA` trigger
//! it emits a SEER `dialogue` `Query` to that peer (with `reply_to` pointed back at itself), parks the
//! original requester keyed by the conversation `corr`, and when the peer's `Answer` returns it relays
//! the reply to the original requester on the original `corr`.
//!
//! The peer is a plain [`Address`], so the *same* creature opens a dialogue with a local peer
//! (`Creature`), a peer on another node (`Node`), or an agent in another Realm
//! (`Omega{realm, …}`) — the conversation composes with cross-node and cross-Realm routing unchanged.
//! That is the whole point: in v0.5.0 the peer is `Omega{other_realm, Creature(other_agent)}` and two
//! model-backed agents converse across the mesh with no new wire.
//!
//! It reuses [`seer::responder::classify`] as its inbound gate — the same four-way verdict the
//! responders use — because an initiator is *also* a SEER consumer (of the `Answer`) that additionally
//! handles a non-SEER trigger. The reduction theorem holds: a single turn + reply is a one-shot
//! consult; the `(corr, query_id)` thread admits an arbitrarily long back-and-forth without new wire.

use std::collections::HashMap;
use std::sync::Arc;

use aether::{Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome, Verifier};
use seer::{
    responder::{classify, Inbound},
    topics::dialogue::{self, Provenance},
    SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA,
};
use serde::{Deserialize, Serialize};

/// Schema of the trigger that opens a conversation. Its payload is the opening prompt (UTF-8); its
/// `reply_to` (or `from`) is where the peer's eventual reply is relayed.
pub const START_SCHEMA: &str = "dialogue.start";

/// Schema of the relayed result the initiator sends back to the original requester. Distinct from
/// SEER — it's the closing reply to the trigger's originator, not an in-conversation envelope.
pub const RESULT_SCHEMA: &str = "dialogue.result";

/// Schema of a terminal *failure* the initiator relays to a conversation's original requester when it
/// abandons the conversation (the parked entry was evicted under pending-pressure, or the peer's reply
/// broke the turn-size/shape/provenance contract, or the peer sent an admissible
/// `Steer { kind: "abort" }`). When a peer signer is pinned, an abort is admissible only when its
/// payload is an existing signed [`dialogue::AnswerBody`] bound to the parked `(corr, prompt)` and
/// abort reason; unauthenticated aborts cannot evict live pending state.
/// Distinct from [`RESULT_SCHEMA`] so a requester never mistakes an abandonment for a real reply —
/// the same "structured terminal reply, never silent abandonment" discipline
/// `distributor-requirements` commits to with its no-provider reply.
pub const FAILED_SCHEMA: &str = "dialogue.failed";

/// Default cap on conversations awaiting a peer reply. At capacity a new trigger evicts the **oldest**
/// parked conversation (notifying its abandoned originator on [`FAILED_SCHEMA`]) rather than refusing
/// the new one — so a handful of dead peers can't permanently wedge the initiator into refuse-new.
/// `0` (via [`DialogueInitiator::with_max_pending`]) is the explicit lab/demo unbounded opt-out.
pub const DEFAULT_MAX_PENDING: usize = 128;

/// Query id of the one opening turn currently parked per conversation corr.
const OPENING_QUERY_ID: u64 = 1;

/// One app-signed dialogue turn retained after provenance verification and before the initiator
/// reduces the answer to the plaintext [`RESULT_SCHEMA`] reply.
///
/// This is a composition-local audit record, not a new wire shape. Keeping the original
/// [`dialogue::AnswerBody`] lets an evidence writer later re-check the peer signature over the exact
/// `(corr, prompt, reply)` tuple. The `query_id` remains explicit because it is part of the parked
/// SEER exchange even though the current answer signature deliberately binds only corr + prompt +
/// reply (ADR-0038).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct VerifiedDialogueTurn {
    pub corr: u64,
    pub query_id: u64,
    pub prompt: String,
    pub answer: dialogue::AnswerBody,
}

/// Nonblocking composition-local sink for signer-verified dialogue turns.
///
/// Implementations MUST bound retained state and MUST NOT perform network or unbounded filesystem
/// work on the creature drain thread. A sink failure is terminal for that conversation: Alpha will
/// not return a successful plaintext result while silently omitting its requested audit evidence.
pub trait VerifiedTurnSink: Send + Sync {
    fn record_verified_turn(&self, turn: VerifiedDialogueTurn) -> Result<(), String>;
}

/// The terminal failure body relayed on [`FAILED_SCHEMA`]. `reason` is free-form audit prose; the
/// schema is the dispatch key (a requester branches on the schema, then surfaces the reason).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DialogueFailed {
    /// Human-readable reason the conversation was abandoned.
    pub reason: String,
}

impl DialogueFailed {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// A conversation awaiting the peer's reply: where to relay it, on which corr/query, and the prompt
/// that opened it (kept so the relay can recompute the app-signed provenance payload, ADR-0038).
struct Pending {
    reply_to: Address,
    orig_corr: Option<u64>,
    prompt: String,
    query_id: u64,
}

impl Pending {
    /// Build the terminal failure dispatch for this conversation's original requester (on its own
    /// corr, on [`FAILED_SCHEMA`]). Used when the conversation is abandoned rather than answered.
    fn failed(&self, reason: &str) -> Dispatch {
        let body = DialogueFailed { reason: reason.to_string() };
        let mut d = Dispatch::to(self.reply_to.clone(), body.to_bytes()).with_schema(FAILED_SCHEMA);
        if let Some(c) = self.orig_corr {
            d = d.with_corr(c);
        }
        d
    }
}

/// The reference dialogue initiator.
pub struct DialogueInitiator {
    /// The conversation partner — local (`Creature`), cross-node (`Node`), or cross-Realm
    /// (`Omega{realm, …}`). The whole seam's flexibility lives in this being a plain `Address`.
    peer: Address,
    /// Conversations awaiting a peer reply, keyed by the conversation corr.
    pending: HashMap<u64, Pending>,
    /// Monotone source of conversation corrs. Seeded high so it doesn't collide with a requester's
    /// own small corrs.
    next_corr: u64,
    /// Cap on parked conversations; `0` = unbounded (explicit opt-out).
    max_pending: usize,
    /// This initiator's own id, stashed at `bind`, so the peer's `Answer` is addressed back here
    /// regardless of how many hops it crosses.
    me: Option<CreatureId>,
    /// Optional verify **mechanism** for app-signed dialogue provenance (ADR-0038). When set, the
    /// relay checks the peer's signature over `(corr, prompt, reply)` before relaying — end-to-end
    /// authenticity that survives the relay even though the transport `Origin` is hop-by-hop. `None`
    /// is the reference posture (relay unverified, wire-identical to before provenance existed).
    verifier: Option<Arc<dyn Verifier>>,
    /// Optional expected peer signer (hex pubkey). With a verifier configured, the relay requires
    /// replies and terminal aborts to be signed *by this key*. Abort handling is always fail-closed
    /// once the key is pinned: without a verifier, or with an invalid abort, it leaves the live turn
    /// pending so an unauthenticated peer cannot terminate somebody else's conversation.
    expect_signer: Option<String>,
    /// Optional in-memory/nonblocking audit hook invoked only after cryptographic provenance and
    /// the expected signer (when pinned) have both been verified.
    verified_turn_sink: Option<Arc<dyn VerifiedTurnSink>>,
}

impl DialogueInitiator {
    /// Open conversations with `peer`. `peer` may be any address — a local creature, a peer node, or
    /// `Omega{realm, Creature(agent)}` for an agent in another Realm.
    pub fn new(peer: Address) -> Self {
        DialogueInitiator {
            peer,
            pending: HashMap::new(),
            next_corr: 900_000,
            max_pending: DEFAULT_MAX_PENDING,
            me: None,
            verifier: None,
            expect_signer: None,
            verified_turn_sink: None,
        }
    }

    /// Verify app-signed provenance (ADR-0038) on every relayed reply with `verifier`. A reply whose
    /// signature is *present but invalid* (tampered/forged) fails the conversation on
    /// [`FAILED_SCHEMA`] instead of being relayed as authentic. An *unsigned* reply still relays
    /// (lenient) unless an expected signer is also pinned via [`Self::with_expected_signer`].
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = Some(verifier);
        self
    }

    /// Pin the peer's expected signer (hex pubkey). With [`Self::with_verifier`], a relayed reply
    /// must be signed by exactly this key or the conversation fails. A terminal abort always enters
    /// the strict posture: it must carry a signed [`dialogue::AnswerBody`] from exactly this key,
    /// bound to the pending corr, prompt, and reason. If no verifier is configured, or verification
    /// fails, the abort is ignored and the turn remains pending.
    pub fn with_expected_signer(mut self, signer_pubkey: impl Into<String>) -> Self {
        self.expect_signer = Some(signer_pubkey.into());
        self
    }

    /// Retain each successfully verified signed answer before relaying its plaintext reply.
    ///
    /// The sink is deliberately additive and local: it changes neither Envelope nor SEER. If a
    /// sink is configured without a verifier, unsigned/unchecked replies fail instead of being
    /// mislabelled as verified evidence. Configure [`Self::with_verifier`] and, for a pinned peer,
    /// [`Self::with_expected_signer`] on the same initiator.
    pub fn with_verified_turn_sink(mut self, sink: Arc<dyn VerifiedTurnSink>) -> Self {
        self.verified_turn_sink = Some(sink);
        self
    }

    /// Override the parked-conversation cap. `0` selects the explicit unbounded opt-out (lab/demo
    /// workloads only); production deployments MUST set a finite cap. (The unified escape-hatch
    /// convention — see `docs/design/substrate.md`.)
    pub fn with_max_pending(mut self, max_pending: usize) -> Self {
        self.max_pending = max_pending;
        self
    }

    /// Seed the conversation-corr counter (determinism for tests).
    pub fn with_corr_seed(mut self, seed: u64) -> Self {
        self.next_corr = seed;
        self
    }

    /// Conversations currently awaiting a peer reply. Tests + observability; not a wire contract.
    pub fn pending_conversations(&self) -> usize {
        self.pending.len()
    }

    fn on_start(&mut self, env: Envelope) -> Outcome {
        let Some(me) = self.me else {
            return Outcome::none(); // before bind — a kernel-lifecycle race; drop, never panic.
        };
        // The opening prompt is the trigger payload as UTF-8, bounded to the topic's turn cap.
        if env.payload.len() > dialogue::MAX_TURN_BYTES {
            return Outcome::none();
        }
        let prompt = match std::str::from_utf8(&env.payload) {
            Ok(prompt) => prompt.to_owned(),
            Err(_) => return Outcome::none(),
        };

        // Pending-pressure guard: at capacity, evict the OLDEST parked conversation (smallest corr —
        // `next_corr` is monotone, so smallest == oldest) and relay a terminal failure to its
        // abandoned originator, then open the new conversation. Refusing the *new* one instead would
        // let a handful of dead peers permanently wedge the initiator into refuse-new — the parked
        // entry has no other exit than a matching Answer. This mirrors `distributor-requirements`'
        // PendingEvicted discipline: a bounded table that keeps accepting, never silent abandonment.
        let mut dispatches: Vec<Dispatch> = Vec::new();
        if self.max_pending != 0 && self.pending.len() >= self.max_pending {
            if let Some(&oldest) = self.pending.keys().min() {
                if let Some(p) = self.pending.remove(&oldest) {
                    dispatches.push(
                        p.failed("dialogue initiator at capacity; oldest conversation evicted"),
                    );
                }
            }
        }

        let corr = self.next_corr;
        self.next_corr = self.next_corr.wrapping_add(1);
        self.pending.insert(
            corr,
            Pending {
                reply_to: env.reply_target(),
                orig_corr: env.header.corr,
                prompt: prompt.clone(),
                query_id: OPENING_QUERY_ID,
            },
        );

        // Send the opening turn to the named peer; reply_to points back here so the Answer returns.
        let q = SeerEnvelope::query(
            SeerTopic::Dialogue,
            corr,
            OPENING_QUERY_ID,
            &dialogue::QueryBody { prompt },
        );
        dispatches.push(
            Dispatch::to(self.peer.clone(), q.to_bytes())
                .with_schema(SEER_SCHEMA)
                .with_corr(corr)
                .with_reply_to(Address::Creature(me)),
        );
        Outcome { dispatches, budget_signal: None }
    }

    fn on_answer(&mut self, corr: u64, query_id: u64, body: serde_json::Value) -> Outcome {
        // Pair on the complete SEER thread identity. A stale/spoofed query_id on a live corr is not
        // an answer to this exchange and MUST NOT evict it; the legitimate answer can still arrive.
        let Some(pending) = self.pending.get(&corr) else {
            return Outcome::none(); // late/unknown conversation; drop silently.
        };
        if pending.query_id != query_id {
            return Outcome::none();
        }

        // A matching answer is terminal even when its body is malformed. Consume exactly once,
        // then surface a structured failure rather than silently losing the original requester.
        let Some(p) = self.pending.remove(&corr) else {
            return Outcome::none();
        };
        let answer: dialogue::AnswerBody = match serde_json::from_value(body) {
            Ok(a) => a,
            Err(_) => return Outcome::send(p.failed("peer returned a malformed dialogue answer")),
        };
        // The reply is held to the same turn cap the prompt side already enforces — a peer that
        // breaks the contract fails the conversation rather than having an over-cap turn relayed.
        if answer.reply.len() > dialogue::MAX_TURN_BYTES {
            return Outcome::send(p.failed("peer reply exceeded the dialogue turn cap"));
        }
        // App-signed provenance gate (ADR-0038). The transport `Origin` is hop-by-hop and does NOT
        // survive this relay — so end-to-end "which agent answered" is the *message* signature, not
        // the transport path. When a verifier is configured we check it before relaying: a tampered
        // or forged signature (`Invalid`) fails the conversation rather than being passed off as
        // authentic; an unsigned reply fails only if a signer was pinned (else it relays, lenient).
        let mut provenance_verified = false;
        if let Some(verifier) = &self.verifier {
            match answer.verify_provenance(corr, &p.prompt, verifier.as_ref()) {
                Provenance::Verified(pk) => {
                    if let Some(expected) = &self.expect_signer {
                        if &pk != expected {
                            return Outcome::send(
                                p.failed("peer reply signed by an unexpected agent key"),
                            );
                        }
                    }
                    provenance_verified = true;
                }
                Provenance::Invalid => {
                    return Outcome::send(p.failed("peer reply failed provenance verification"));
                }
                Provenance::Unsigned => {
                    if self.expect_signer.is_some() {
                        return Outcome::send(
                            p.failed("peer reply was unsigned but a signer was required"),
                        );
                    }
                }
            }
        }
        if let Some(sink) = &self.verified_turn_sink {
            if !provenance_verified {
                return Outcome::send(
                    p.failed("dialogue evidence sink requires a signer-verified peer reply"),
                );
            }
            let turn = VerifiedDialogueTurn {
                corr,
                query_id,
                prompt: p.prompt.clone(),
                answer: answer.clone(),
            };
            let recorded = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                sink.record_verified_turn(turn)
            }));
            match recorded {
                Ok(Ok(())) => {}
                Ok(Err(reason)) => {
                    return Outcome::send(
                        p.failed(&format!("could not retain verified dialogue evidence: {reason}")),
                    )
                }
                Err(_) => {
                    return Outcome::send(p.failed("verified dialogue evidence sink panicked"))
                }
            }
        }
        // Relay the peer's reply to the original requester, on its own corr.
        let mut d = Dispatch::to(p.reply_to, answer.reply.into_bytes()).with_schema(RESULT_SCHEMA);
        if let Some(c) = p.orig_corr {
            d = d.with_corr(c);
        }
        Outcome::send(d)
    }

    fn on_abort(&mut self, corr: u64, payload: serde_json::Value) -> Outcome {
        let Some(pending) = self.pending.get(&corr) else {
            return Outcome::none(); // late/unknown abort; no live requester to notify.
        };

        // An abort is a destructive terminal move: validate it before removing pending state. A
        // pinned peer reuses the existing AnswerBody provenance shape, with `reply` carrying the
        // reason. Its signature already binds `(corr, prompt, reply)`, so no parallel abort crypto
        // contract is needed. Legacy string payloads remain accepted only in the unpinned posture.
        let signed_reason = if let Some(expected) = &self.expect_signer {
            let Some(verifier) = &self.verifier else {
                return Outcome::none();
            };
            let answer: dialogue::AnswerBody = match serde_json::from_value(payload) {
                Ok(answer) => answer,
                Err(_) => return Outcome::none(),
            };
            if answer.reply.len() > dialogue::MAX_TURN_BYTES {
                return Outcome::none();
            }
            match answer.verify_provenance(corr, &pending.prompt, verifier.as_ref()) {
                Provenance::Verified(key) if &key == expected => answer.reply,
                Provenance::Verified(_) | Provenance::Unsigned | Provenance::Invalid => {
                    return Outcome::none()
                }
            }
        } else {
            // Preserve the pre-provenance responder contract. New signed abort objects are also
            // terminal here; without a pinned identity there is intentionally no key policy.
            match payload {
                serde_json::Value::String(reason) => reason,
                body => serde_json::from_value::<dialogue::AnswerBody>(body)
                    .map(|answer| answer.reply)
                    .unwrap_or_else(|_| "peer supplied no abort reason".to_string()),
            }
        };

        let Some(p) = self.pending.remove(&corr) else {
            return Outcome::none();
        };
        Outcome::send(p.failed(&format!("peer aborted the dialogue turn: {signed_reason}")))
    }
}

impl Creature for DialogueInitiator {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // The shared inbound SEER gate (same four-way verdict the responders use). An initiator is a
        // SEER consumer of the peer's `Answer` that ALSO handles a non-SEER trigger — exactly the
        // initiator shape `classify` exists for.
        match classify(&env, SeerTopic::Dialogue) {
            Inbound::Ours(seer) => match seer.kind {
                SeerKind::Answer { query_id, body } => self.on_answer(seer.corr, query_id, body),
                SeerKind::Steer { kind, payload } if kind == "abort" => {
                    self.on_abort(seer.corr, payload)
                }
                // Query/Progress/Thought and non-abort Steer are not terminal moves for the opening
                // exchange. Ignore them without consuming the parked turn.
                _ => Outcome::none(),
            },
            Inbound::NotSeer => {
                if env.header.schema == START_SCHEMA {
                    self.on_start(env)
                } else {
                    Outcome::none()
                }
            }
            Inbound::Malformed(_) | Inbound::OtherTopic => Outcome::none(),
        }
    }
}

#[cfg(test)]
impl DialogueInitiator {
    /// For tests that drive `handle` directly (no kernel bind), set the `me` slot manually.
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::Header;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingTurnSink(Mutex<Vec<VerifiedDialogueTurn>>);

    impl VerifiedTurnSink for RecordingTurnSink {
        fn record_verified_turn(&self, turn: VerifiedDialogueTurn) -> Result<(), String> {
            self.0.lock().unwrap_or_else(|poison| poison.into_inner()).push(turn);
            Ok(())
        }
    }

    fn env(
        schema: &str,
        payload: Vec<u8>,
        corr: Option<u64>,
        reply_to: Option<Address>,
    ) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(CreatureId(5)),
                reply_to,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr,
                commitment: None,
                schema: schema.into(),
                origin: None,
            },
            payload,
        }
    }

    fn initiator() -> DialogueInitiator {
        let mut i =
            DialogueInitiator::new(Address::Creature(CreatureId(42))).with_corr_seed(700_000);
        i.set_me_for_tests(CreatureId(5));
        i
    }

    #[test]
    fn start_sends_a_dialogue_turn_to_the_named_peer_and_parks() {
        let mut i = initiator();
        let out = i.handle(env(
            START_SCHEMA,
            b"hello agent".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));
        assert_eq!(out.dispatches.len(), 1, "one opening turn");
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Creature(CreatureId(42)), "addressed to the named peer");
        assert_eq!(d.schema, SEER_SCHEMA);
        assert_eq!(d.reply_to, Some(Address::Creature(CreatureId(5))), "reply_to points back here");
        let seer = SeerEnvelope::parse(&d.payload).unwrap();
        assert_eq!(seer.topic, SeerTopic::Dialogue);
        assert_eq!(seer.corr, 700_000, "conversation corr from the seed");
        match seer.kind {
            SeerKind::Query { query_id, body } => {
                assert_eq!(query_id, OPENING_QUERY_ID);
                let q: dialogue::QueryBody = serde_json::from_value(body).unwrap();
                assert_eq!(q.prompt, "hello agent");
            }
            other => panic!("expected Query, got {other:?}"),
        }
        assert_eq!(i.pending_conversations(), 1, "conversation parked awaiting the reply");
    }

    #[test]
    fn answer_is_relayed_to_the_original_requester_on_its_corr() {
        let mut i = initiator();
        // Open with the requester's corr = 1, reply_to = creature 100.
        i.handle(env(
            START_SCHEMA,
            b"hi".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));
        // The peer answers on the conversation corr (700_000).
        let ans = SeerEnvelope::answer(
            SeerTopic::Dialogue,
            700_000,
            1,
            &dialogue::AnswerBody::unsigned("echo: hi"),
        );
        let out = i.handle(env(SEER_SCHEMA, ans.to_bytes(), Some(700_000), None));
        assert_eq!(out.dispatches.len(), 1, "the reply is relayed");
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Creature(CreatureId(100)), "relayed to the original requester");
        assert_eq!(d.schema, RESULT_SCHEMA);
        assert_eq!(d.corr, Some(1), "on the original requester's corr");
        assert_eq!(d.payload, b"echo: hi");
        assert_eq!(i.pending_conversations(), 0, "conversation completed and dropped");
    }

    #[test]
    fn a_stray_answer_for_an_unknown_conversation_is_dropped() {
        let mut i = initiator();
        let ans = SeerEnvelope::answer(
            SeerTopic::Dialogue,
            999,
            1,
            &dialogue::AnswerBody::unsigned("nobody asked"),
        );
        let out = i.handle(env(SEER_SCHEMA, ans.to_bytes(), Some(999), None));
        assert!(out.dispatches.is_empty(), "no parked conversation for corr 999 → dropped");
    }

    #[test]
    fn mismatched_query_id_does_not_evict_the_live_conversation() {
        let mut i = initiator();
        i.handle(env(
            START_SCHEMA,
            b"hi".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));

        // Even a malformed body cannot terminate the exchange when its query_id is stale/spoofed.
        let wrong = SeerEnvelope {
            topic: SeerTopic::Dialogue,
            corr: 700_000,
            kind: SeerKind::Answer {
                query_id: OPENING_QUERY_ID + 1,
                body: serde_json::json!({"reply": 7}),
            },
        };
        let out = i.handle(env(SEER_SCHEMA, wrong.to_bytes(), Some(700_000), None));
        assert!(out.dispatches.is_empty());
        assert_eq!(i.pending_conversations(), 1, "mismatch leaves the legitimate turn parked");

        let matching = SeerEnvelope::answer(
            SeerTopic::Dialogue,
            700_000,
            OPENING_QUERY_ID,
            &dialogue::AnswerBody::unsigned("echo: hi"),
        );
        let out = i.handle(env(SEER_SCHEMA, matching.to_bytes(), Some(700_000), None));
        assert_eq!(out.dispatches.len(), 1);
        assert_eq!(out.dispatches[0].schema, RESULT_SCHEMA);
        assert_eq!(out.dispatches[0].payload, b"echo: hi");
        assert_eq!(i.pending_conversations(), 0);
    }

    #[test]
    fn matching_malformed_answer_is_a_terminal_failure() {
        let mut i = initiator();
        i.handle(env(
            START_SCHEMA,
            b"hi".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));
        let malformed = SeerEnvelope {
            topic: SeerTopic::Dialogue,
            corr: 700_000,
            kind: SeerKind::Answer {
                query_id: OPENING_QUERY_ID,
                body: serde_json::json!({"reply": 7}),
            },
        };
        let out = i.handle(env(SEER_SCHEMA, malformed.to_bytes(), Some(700_000), None));
        assert_eq!(out.dispatches.len(), 1);
        assert_eq!(out.dispatches[0].schema, FAILED_SCHEMA);
        assert_eq!(out.dispatches[0].corr, Some(1));
        let failed = DialogueFailed::parse(&out.dispatches[0].payload).expect("failure body");
        assert!(failed.reason.contains("malformed"));
        assert_eq!(i.pending_conversations(), 0, "a matching malformed answer is terminal");
    }

    #[test]
    fn matching_abort_is_a_terminal_failure_but_other_steers_do_not_evict() {
        let mut i = initiator();
        i.handle(env(
            START_SCHEMA,
            b"hi".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));

        let info =
            SeerEnvelope::steer(SeerTopic::Dialogue, 700_000, "info", &serde_json::json!({}));
        assert!(i
            .handle(env(SEER_SCHEMA, info.to_bytes(), Some(700_000), None))
            .dispatches
            .is_empty());
        assert_eq!(i.pending_conversations(), 1, "non-abort steer is advisory");

        let abort =
            SeerEnvelope::steer(SeerTopic::Dialogue, 700_000, "abort", &"model call failed");
        let out = i.handle(env(SEER_SCHEMA, abort.to_bytes(), Some(700_000), None));
        assert_eq!(out.dispatches.len(), 1);
        assert_eq!(out.dispatches[0].schema, FAILED_SCHEMA);
        assert_eq!(out.dispatches[0].corr, Some(1));
        let failed = DialogueFailed::parse(&out.dispatches[0].payload).expect("failure body");
        assert!(failed.reason.contains("aborted"));
        assert_eq!(i.pending_conversations(), 0);
    }

    #[test]
    fn pinned_abort_rejects_plain_unsigned_and_wrong_key_before_consuming_pending() {
        use aether::{Ed25519Signer, Ed25519Verifier, Signer as _};

        let (peer, _peer_seed) = Ed25519Signer::generate().expect("peer key");
        let (impostor, _impostor_seed) = Ed25519Signer::generate().expect("impostor key");
        let mut i = initiator()
            .with_verifier(Arc::new(Ed25519Verifier))
            .with_expected_signer(peer.public_key());
        i.handle(env(
            START_SCHEMA,
            b"hi".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));

        let plain =
            SeerEnvelope::steer(SeerTopic::Dialogue, 700_000, "abort", &"model call failed");
        assert!(i
            .handle(env(SEER_SCHEMA, plain.to_bytes(), Some(700_000), None))
            .dispatches
            .is_empty());
        assert_eq!(i.pending_conversations(), 1, "a legacy unsigned abort cannot evict a pin");

        let unsigned = SeerEnvelope::steer(
            SeerTopic::Dialogue,
            700_000,
            "abort",
            &dialogue::AnswerBody::unsigned("model call failed"),
        );
        assert!(i
            .handle(env(SEER_SCHEMA, unsigned.to_bytes(), Some(700_000), None))
            .dispatches
            .is_empty());
        assert_eq!(i.pending_conversations(), 1, "an unsigned AnswerBody also keeps pending");

        let wrong_key = SeerEnvelope::steer(
            SeerTopic::Dialogue,
            700_000,
            "abort",
            &dialogue::AnswerBody::signed(700_000, "hi", "model call failed", &impostor),
        );
        assert!(i
            .handle(env(SEER_SCHEMA, wrong_key.to_bytes(), Some(700_000), None))
            .dispatches
            .is_empty());
        assert_eq!(
            i.pending_conversations(),
            1,
            "a valid signature from the wrong key keeps pending"
        );

        let wrong_turn = SeerEnvelope::steer(
            SeerTopic::Dialogue,
            700_000,
            "abort",
            &dialogue::AnswerBody::signed(
                700_000,
                "a different pending prompt",
                "model call failed",
                &peer,
            ),
        );
        assert!(i
            .handle(env(SEER_SCHEMA, wrong_turn.to_bytes(), Some(700_000), None))
            .dispatches
            .is_empty());
        assert_eq!(
            i.pending_conversations(),
            1,
            "even the expected key cannot replay an abort across prompts"
        );

        let mut tampered_reason =
            dialogue::AnswerBody::signed(700_000, "hi", "model call failed", &peer);
        tampered_reason.reply = "a different reason".into();
        let tampered = SeerEnvelope::steer(SeerTopic::Dialogue, 700_000, "abort", &tampered_reason);
        assert!(i
            .handle(env(SEER_SCHEMA, tampered.to_bytes(), Some(700_000), None))
            .dispatches
            .is_empty());
        assert_eq!(
            i.pending_conversations(),
            1,
            "the signed reason cannot be changed before termination"
        );

        let valid = SeerEnvelope::steer(
            SeerTopic::Dialogue,
            700_000,
            "abort",
            &dialogue::AnswerBody::signed(700_000, "hi", "model call failed", &peer),
        );
        let out = i.handle(env(SEER_SCHEMA, valid.to_bytes(), Some(700_000), None));
        assert_eq!(out.dispatches.len(), 1, "the expected peer can terminate its turn");
        assert_eq!(out.dispatches[0].schema, FAILED_SCHEMA);
        let failed = DialogueFailed::parse(&out.dispatches[0].payload).expect("failure body");
        assert!(failed.reason.contains("model call failed"), "signed reason is preserved");
        assert_eq!(i.pending_conversations(), 0, "valid signed abort consumes exactly once");
    }

    #[test]
    fn wrong_topic_and_non_trigger_schemas_are_dropped() {
        let mut i = initiator();
        // A placement answer is on the wrong topic.
        let other = SeerEnvelope::answer(SeerTopic::Placement, 700_000, 1, &serde_json::json!({}));
        assert!(i
            .handle(env(SEER_SCHEMA, other.to_bytes(), Some(700_000), None))
            .dispatches
            .is_empty());
        // A random non-trigger schema is ignored.
        assert!(i.handle(env("text/plain", b"hi".to_vec(), None, None)).dispatches.is_empty());
    }

    #[test]
    fn capacity_evicts_oldest_conversation_and_notifies_its_originator() {
        let mut i = DialogueInitiator::new(Address::Creature(CreatureId(42)))
            .with_corr_seed(1)
            .with_max_pending(1);
        i.set_me_for_tests(CreatureId(5));
        // First conversation parks (originator = creature 100, on corr 1).
        let out1 = i.handle(env(
            START_SCHEMA,
            b"a".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));
        assert_eq!(out1.dispatches.len(), 1, "one opening turn");
        assert_eq!(i.pending_conversations(), 1);
        // Second start at capacity: evict the oldest (originator 100) AND open the new conversation —
        // never a permanent refuse-new wedge, never silent abandonment of the evicted requester.
        let out2 = i.handle(env(
            START_SCHEMA,
            b"b".to_vec(),
            Some(2),
            Some(Address::Creature(CreatureId(200))),
        ));
        assert_eq!(
            out2.dispatches.len(),
            2,
            "a failed-notice for the evicted originator + the new turn"
        );
        let failed = out2
            .dispatches
            .iter()
            .find(|d| d.schema == FAILED_SCHEMA)
            .expect("the evicted originator is notified, not silently abandoned");
        assert_eq!(
            failed.to,
            Address::Creature(CreatureId(100)),
            "notice goes to the evicted originator"
        );
        assert_eq!(failed.corr, Some(1), "on its own corr");
        assert!(DialogueFailed::parse(&failed.payload).is_ok(), "structured failure body");
        // The new conversation is parked; the evicted one is gone — the table stays bounded at 1.
        assert_eq!(i.pending_conversations(), 1, "evicted one dropped, new one parked");
    }

    #[test]
    fn an_over_cap_peer_reply_fails_the_conversation_instead_of_relaying() {
        let mut i = initiator();
        i.handle(env(
            START_SCHEMA,
            b"hi".to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));
        // The peer answers on the conversation corr with a reply over the turn cap.
        let big = "x".repeat(dialogue::MAX_TURN_BYTES + 1);
        let ans = SeerEnvelope::answer(
            SeerTopic::Dialogue,
            700_000,
            1,
            &dialogue::AnswerBody::unsigned(big),
        );
        let out = i.handle(env(SEER_SCHEMA, ans.to_bytes(), Some(700_000), None));
        assert_eq!(out.dispatches.len(), 1, "the over-cap reply is not relayed");
        assert_eq!(
            out.dispatches[0].schema, FAILED_SCHEMA,
            "the requester is told the conversation failed"
        );
        assert_eq!(out.dispatches[0].corr, Some(1), "on the original requester's corr");
        assert_eq!(i.pending_conversations(), 0, "conversation consumed");
    }

    // ── ADR-0038: app-signed provenance verified at the relay ────────────────────────────────────

    use aether::{Ed25519Signer, Ed25519Verifier, Signer as _};

    /// Drive a full conversation through a (possibly verifying) initiator and return its relayed
    /// dispatch. `make_answer` builds the peer's answer body for the conversation's corr.
    fn run_conversation(
        mut i: DialogueInitiator,
        prompt: &str,
        make_answer: impl FnOnce(u64, &str) -> dialogue::AnswerBody,
    ) -> Dispatch {
        i.handle(env(
            START_SCHEMA,
            prompt.as_bytes().to_vec(),
            Some(1),
            Some(Address::Creature(CreatureId(100))),
        ));
        let corr = 700_000; // from `initiator()`'s corr seed
        let ans = SeerEnvelope::answer(SeerTopic::Dialogue, corr, 1, &make_answer(corr, prompt));
        let out = i.handle(env(SEER_SCHEMA, ans.to_bytes(), Some(corr), None));
        assert_eq!(out.dispatches.len(), 1, "exactly one relayed dispatch");
        out.dispatches.into_iter().next().unwrap()
    }

    #[test]
    fn a_verifying_initiator_relays_a_validly_signed_reply() {
        let (signer, _seed) = Ed25519Signer::generate().unwrap();
        let pubkey = signer.public_key();
        let i = initiator().with_verifier(Arc::new(Ed25519Verifier)).with_expected_signer(pubkey);
        let d = run_conversation(i, "hi", |corr, prompt| {
            dialogue::AnswerBody::signed(corr, prompt, "echo: hi", &signer)
        });
        assert_eq!(d.schema, RESULT_SCHEMA, "a valid signature relays normally");
        assert_eq!(d.payload, b"echo: hi");
    }

    #[test]
    fn verified_turn_sink_retains_the_exact_signed_body_before_plaintext_relay() {
        let (signer, _seed) = Ed25519Signer::generate().unwrap();
        let sink = Arc::new(RecordingTurnSink::default());
        let i = initiator()
            .with_verifier(Arc::new(Ed25519Verifier))
            .with_expected_signer(signer.public_key())
            .with_verified_turn_sink(sink.clone());
        let expected = dialogue::AnswerBody::signed(700_000, "hi", "echo: hi", &signer);
        let d = run_conversation(i, "hi", |_corr, _prompt| expected.clone());
        assert_eq!(d.schema, RESULT_SCHEMA);
        assert_eq!(d.payload, b"echo: hi");
        assert_eq!(
            *sink.0.lock().unwrap_or_else(|poison| poison.into_inner()),
            vec![VerifiedDialogueTurn {
                corr: 700_000,
                query_id: OPENING_QUERY_ID,
                prompt: "hi".into(),
                answer: expected,
            }]
        );
    }

    #[test]
    fn evidence_sink_never_labels_an_unsigned_lenient_reply_as_verified() {
        let sink = Arc::new(RecordingTurnSink::default());
        let i = initiator().with_verified_turn_sink(sink.clone());
        let d =
            run_conversation(i, "hi", |_corr, _prompt| dialogue::AnswerBody::unsigned("echo: hi"));
        assert_eq!(d.schema, FAILED_SCHEMA);
        assert!(sink.0.lock().unwrap_or_else(|poison| poison.into_inner()).is_empty());
    }

    #[test]
    fn a_verifying_initiator_fails_a_tampered_reply() {
        let (signer, _seed) = Ed25519Signer::generate().unwrap();
        let i = initiator().with_verifier(Arc::new(Ed25519Verifier));
        let d = run_conversation(i, "hi", |corr, prompt| {
            // Sign the honest reply, then tamper the content — the signature no longer matches.
            let mut a = dialogue::AnswerBody::signed(corr, prompt, "echo: hi", &signer);
            a.reply = "FORGED".into();
            a
        });
        assert_eq!(d.schema, FAILED_SCHEMA, "a tampered reply must not be relayed as authentic");
    }

    #[test]
    fn a_verifying_initiator_fails_a_reply_from_the_wrong_signer() {
        let (peer, _s1) = Ed25519Signer::generate().unwrap();
        let (impostor, _s2) = Ed25519Signer::generate().unwrap();
        let i = initiator()
            .with_verifier(Arc::new(Ed25519Verifier))
            .with_expected_signer(peer.public_key());
        let d = run_conversation(i, "hi", |corr, prompt| {
            // Validly signed, but by the wrong key.
            dialogue::AnswerBody::signed(corr, prompt, "echo: hi", &impostor)
        });
        assert_eq!(d.schema, FAILED_SCHEMA, "a reply from an unexpected signer fails");
    }

    #[test]
    fn a_pinned_initiator_fails_an_unsigned_reply_but_a_lenient_one_relays_it() {
        // With an expected signer pinned, an unsigned reply fails.
        let (peer, _s) = Ed25519Signer::generate().unwrap();
        let pinned = initiator()
            .with_verifier(Arc::new(Ed25519Verifier))
            .with_expected_signer(peer.public_key());
        let d = run_conversation(pinned, "hi", |_c, _p| dialogue::AnswerBody::unsigned("echo: hi"));
        assert_eq!(d.schema, FAILED_SCHEMA, "unsigned fails when a signer is required");

        // A verifier without a pinned signer is lenient: an unsigned reply still relays.
        let lenient = initiator().with_verifier(Arc::new(Ed25519Verifier));
        let d =
            run_conversation(lenient, "hi", |_c, _p| dialogue::AnswerBody::unsigned("echo: hi"));
        assert_eq!(d.schema, RESULT_SCHEMA, "unsigned relays when no signer is pinned");
        assert_eq!(d.payload, b"echo: hi");
    }
}
