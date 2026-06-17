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
/// broke the turn-size contract). Distinct from [`RESULT_SCHEMA`] so a requester never mistakes an
/// abandonment for a real reply — the same "structured terminal reply, never silent abandonment"
/// discipline `distributor-requirements` commits to with its no-provider reply.
pub const FAILED_SCHEMA: &str = "dialogue.failed";

/// Default cap on conversations awaiting a peer reply. At capacity a new trigger evicts the **oldest**
/// parked conversation (notifying its abandoned originator on [`FAILED_SCHEMA`]) rather than refusing
/// the new one — so a handful of dead peers can't permanently wedge the initiator into refuse-new.
/// `0` (via [`DialogueInitiator::with_max_pending`]) is the explicit lab/demo unbounded opt-out.
pub const DEFAULT_MAX_PENDING: usize = 128;

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

/// A conversation awaiting the peer's reply: where to relay it, on which corr, and the prompt that
/// opened it (kept so the relay can recompute the app-signed provenance payload, ADR-0038).
struct Pending {
    reply_to: Address,
    orig_corr: Option<u64>,
    prompt: String,
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
    /// Optional expected peer signer (hex pubkey). When set (and a verifier is configured), the relay
    /// additionally requires the reply to be signed *by this key* — an unsigned or wrong-key reply
    /// fails the conversation rather than being relayed as if authentic.
    expect_signer: Option<String>,
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

    /// Pin the peer's expected signer (hex pubkey). Implies verification: a relayed reply must be
    /// signed by exactly this key, or the conversation fails. No effect without a verifier set.
    pub fn with_expected_signer(mut self, signer_pubkey: impl Into<String>) -> Self {
        self.expect_signer = Some(signer_pubkey.into());
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
        let prompt = String::from_utf8_lossy(&env.payload).into_owned();

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
            },
        );

        // Send the opening turn to the named peer; reply_to points back here so the Answer returns.
        let q = SeerEnvelope::query(SeerTopic::Dialogue, corr, 1, &dialogue::QueryBody { prompt });
        dispatches.push(
            Dispatch::to(self.peer.clone(), q.to_bytes())
                .with_schema(SEER_SCHEMA)
                .with_corr(corr)
                .with_reply_to(Address::Creature(me)),
        );
        Outcome { dispatches, budget_signal: None }
    }

    fn on_answer(&mut self, seer: SeerEnvelope) -> Outcome {
        let SeerKind::Answer { body, .. } = seer.kind else {
            return Outcome::none(); // Steer/Progress/Thought/Query — not the move we await.
        };
        let Some(p) = self.pending.remove(&seer.corr) else {
            return Outcome::none(); // late/unknown conversation; drop silently.
        };
        let answer: dialogue::AnswerBody = match serde_json::from_value(body) {
            Ok(a) => a,
            Err(_) => return Outcome::none(),
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
        if let Some(verifier) = &self.verifier {
            match answer.verify_provenance(seer.corr, &p.prompt, verifier.as_ref()) {
                Provenance::Verified(pk) => {
                    if let Some(expected) = &self.expect_signer {
                        if &pk != expected {
                            return Outcome::send(
                                p.failed("peer reply signed by an unexpected agent key"),
                            );
                        }
                    }
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
        // Relay the peer's reply to the original requester, on its own corr.
        let mut d = Dispatch::to(p.reply_to, answer.reply.into_bytes()).with_schema(RESULT_SCHEMA);
        if let Some(c) = p.orig_corr {
            d = d.with_corr(c);
        }
        Outcome::send(d)
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
            Inbound::Ours(seer) => self.on_answer(seer),
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
            SeerKind::Query { body, .. } => {
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
