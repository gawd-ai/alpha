//! `dialogue-responder` — the reference standing consumer for the SEER `dialogue` topic.
//!
//! The *peer* half of the agent-to-agent dialogue seam. It binds a SEER inbox and answers every
//! dialogue `Query` (a conversation *turn*) with an injected [`Responder`] model — the reference
//! [`EchoResponder`] echoes the prompt back, proving the round-trip. [`DialogueMind`] is the
//! additive, production-shaped path: it runs a blocking [`mind::Model`] off the kernel drain thread,
//! signs the existing [`dialogue::AnswerBody`] for both answers and abort reasons, and bounds model
//! input and worker concurrency.
//!
//! Because the answer rides the request's `reply_to` (rewritten by transport on the cross-node path),
//! the responder doesn't know — or need to know — whether its partner is local, on a peer node, or in
//! a peer Realm reached through the Omega gateway. The same creature is the conversation peer in all
//! three topologies, which is what lets v0.5.0 compose three role-scoped live minds through ordinary
//! pairwise turns without claiming a broadcast/group-chat or general-agent protocol.
//!
//! ## What it deliberately doesn't do
//!
//! - **It doesn't initiate.** A responder only answers turns addressed to it; the
//!   `dialogue-initiator` is the side that opens a conversation and names the peer.
//! - **It doesn't impose a model-call timeout, and never replies to a malformed turn.** A turn it
//!   can't decode, on the wrong topic, or over the topic's size cap is dropped silently — the shared
//!   consult posture. The injected model transport owns its own call timeout.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use aether::{Address, Bus, Creature, CreatureCtx, Deadline, Dispatch, Envelope, Outcome, Signer};
use mind::{Model, Prompt};
use seer::{
    responder::{classify, respond_query_corr, Inbound},
    topics::dialogue,
    SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA,
};

/// Default maximum number of blocking dialogue model calls in flight at once.
///
/// `0` via [`DialogueMind::with_max_in_flight_model_requests`] is the explicit lab/demo opt-out.
pub const DEFAULT_MAX_IN_FLIGHT_MODEL_REQUESTS: usize = 8;

/// Maximum bytes accepted for the injected model's standing system instructions.
pub const MAX_MODEL_INSTRUCTIONS_BYTES: usize = dialogue::MAX_TURN_BYTES;

/// Maximum bytes accepted from one model completion before it is signed or put on the wire.
pub const MAX_MODEL_OUTPUT_BYTES: usize = dialogue::MAX_TURN_BYTES;

/// The bounded completion budget handed to the injected model for one dialogue turn.
pub const DEFAULT_MODEL_MAX_TOKENS: u32 = 4096;

const MODEL_TEMPERATURE: f32 = 0.2;
const ABORT_BUSY: &str = "dialogue model is at its in-flight request limit";
const ABORT_NOT_BOUND: &str = "dialogue model is not bound to a bus";
const ABORT_MODEL_ERROR: &str = "dialogue model call failed";
const ABORT_MODEL_PANIC: &str = "dialogue model call panicked";
const ABORT_OUTPUT_TOO_LARGE: &str = "dialogue model output exceeded the dialogue turn cap";
const ABORT_SPAWN_FAILED: &str = "dialogue model worker could not be started";

/// Invalid construction input for [`DialogueMind`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DialogueMindConfigError {
    /// The standing system instructions exceed [`MAX_MODEL_INSTRUCTIONS_BYTES`].
    InstructionsTooLarge { bytes: usize, max_bytes: usize },
}

impl std::fmt::Display for DialogueMindConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialogueMindConfigError::InstructionsTooLarge { bytes, max_bytes } => {
                write!(f, "dialogue model instructions are {bytes} bytes; maximum is {max_bytes}")
            }
        }
    }
}

impl std::error::Error for DialogueMindConfigError {}

/// Poison-tolerant lock acquisition. Each lock below guards a plain `Option`/`Vec` with no
/// half-applied invariant, so a poisoned worker lock can safely yield its inner value.
#[inline]
fn mlock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Join completed workers and return the number still in flight.
fn reap_finished_workers(workers: &Mutex<Vec<JoinHandle<()>>>) -> usize {
    let mut guard = mlock(workers);
    let mut remaining = Vec::with_capacity(guard.len());
    for handle in std::mem::take(&mut *guard) {
        if handle.is_finished() {
            let _ = handle.join();
        } else {
            remaining.push(handle);
        }
    }
    let len = remaining.len();
    *guard = remaining;
    len
}

/// Reuse the dialogue answer's frozen provenance shape for a terminal abort: `reply` carries the
/// reason, and its existing signature binds the exact `(corr, prompt, reason)`. This keeps abort
/// authentication inside one app-signed contract instead of inventing a parallel wire type.
fn signed_abort(
    corr: u64,
    prompt: &str,
    reason: &'static str,
    signer: &dyn Signer,
) -> SeerEnvelope {
    let body = dialogue::AnswerBody::signed(corr, prompt, reason, signer);
    SeerEnvelope::steer(SeerTopic::Dialogue, corr, "abort", &body)
}

fn abort_dispatch(
    to: Address,
    corr: u64,
    prompt: &str,
    reason: &'static str,
    signer: &dyn Signer,
) -> Dispatch {
    let steer = signed_abort(corr, prompt, reason, signer);
    Dispatch::to(to, steer.to_bytes()).with_schema(SEER_SCHEMA).with_corr(corr)
}

fn abort_outcome(
    env: &Envelope,
    corr: u64,
    prompt: &str,
    reason: &'static str,
    signer: &dyn Signer,
) -> Outcome {
    Outcome::send(abort_dispatch(env.reply_target(), corr, prompt, reason, signer))
}

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
///
/// An optional [`Signer`] gives this agent an *identity*: when present, every answer carries
/// app-signed provenance (ADR-0038) — a signature over `(corr, prompt, reply)` proving *which agent*
/// produced the reply, end-to-end, regardless of how many fabric hops it crosses. Without a signer
/// (the reference echo path) answers are unsigned, wire-identical to the pre-provenance shape.
pub struct DialogueResponder {
    model: Box<dyn Responder>,
    signer: Option<Box<dyn Signer>>,
}

impl DialogueResponder {
    /// Build a responder over an injected [`Responder`] model (unsigned answers — no agent identity).
    pub fn new(model: Box<dyn Responder>) -> Self {
        DialogueResponder { model, signer: None }
    }

    /// Build a responder that signs every answer with `signer` (ADR-0038 app-signed provenance).
    pub fn signed(model: Box<dyn Responder>, signer: Box<dyn Signer>) -> Self {
        DialogueResponder { model, signer: Some(signer) }
    }

    /// Build the reference echo responder (unsigned).
    pub fn echo() -> Self {
        DialogueResponder::new(Box::new(EchoResponder))
    }

    fn decide(&self, corr: u64, q: dialogue::QueryBody) -> dialogue::AnswerBody {
        let reply = self.model.respond(&q.prompt);
        match &self.signer {
            Some(s) => dialogue::AnswerBody::signed(corr, &q.prompt, reply, s.as_ref()),
            None => dialogue::AnswerBody::unsigned(reply),
        }
    }
}

impl Creature for DialogueResponder {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Standing-responder skeleton: schema / bounded-parse / topic-isolation / Query-only / shape
        // check, then our decision. A turn whose prompt is over the topic cap is dropped silently.
        respond_query_corr::<dialogue::QueryBody, dialogue::AnswerBody>(
            &env,
            SeerTopic::Dialogue,
            |q| q.prompt.len() <= dialogue::MAX_TURN_BYTES,
            |corr, q| self.decide(corr, q),
        )
    }
}

/// A signed, model-backed dialogue peer whose blocking calls never run on the kernel drain thread.
///
/// Construction requires both the model and signer explicitly: there is no default/fake fallback and
/// no unsigned model-backed posture. Valid dialogue queries are decoded and bounded synchronously;
/// each accepted turn then owns one capped worker. Success emits the existing signed
/// [`dialogue::AnswerBody`]. A model error, panic, over-cap output, worker-pressure refusal, or OS
/// thread-spawn failure emits the existing SEER `Steer { kind: "abort" }` convention on the same
/// dialogue `corr`. Its payload is the existing signed [`dialogue::AnswerBody`], binding the corr,
/// prompt, and failure reason so a signer-pinned initiator can authenticate the terminal move before
/// consuming its parked request.
pub struct DialogueMind {
    model: Arc<dyn Model>,
    signer: Arc<dyn Signer>,
    instructions: Arc<str>,
    /// Gates new work and supplies the fast path for suppressing a stopped worker's answer/abort.
    /// BusHandle's sender-lifecycle gate is the authoritative no-emission-after-deregister boundary.
    stop: Arc<AtomicBool>,
    /// Joinable worker ownership, reaped on subsequent requests and at shutdown.
    workers: Mutex<Vec<JoinHandle<()>>>,
    /// Maximum concurrently blocking model calls. `0` is the explicit unbounded opt-out.
    max_in_flight: usize,
    /// Captured creature bus authority for off-drain replies.
    bus: Mutex<Option<Arc<dyn Bus>>>,
}

impl DialogueMind {
    /// Construct a model-backed dialogue peer with bounded standing `instructions`.
    ///
    /// The returned peer signs every successful answer with `signer`. Instructions over
    /// [`MAX_MODEL_INSTRUCTIONS_BYTES`] are rejected before the creature can be loaded.
    pub fn new(
        model: Arc<dyn Model>,
        signer: Arc<dyn Signer>,
        instructions: impl Into<String>,
    ) -> Result<Self, DialogueMindConfigError> {
        let instructions = instructions.into();
        if instructions.len() > MAX_MODEL_INSTRUCTIONS_BYTES {
            return Err(DialogueMindConfigError::InstructionsTooLarge {
                bytes: instructions.len(),
                max_bytes: MAX_MODEL_INSTRUCTIONS_BYTES,
            });
        }
        Ok(DialogueMind {
            model,
            signer,
            instructions: Arc::from(instructions),
            stop: Arc::new(AtomicBool::new(false)),
            workers: Mutex::new(Vec::new()),
            max_in_flight: DEFAULT_MAX_IN_FLIGHT_MODEL_REQUESTS,
            bus: Mutex::new(None),
        })
    }

    /// Share an external stop flag, primarily for composition-level lifecycle coordination.
    pub fn with_stop(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = stop;
        self
    }

    /// Cap concurrently blocking model requests. `0` is an explicit unbounded lab/demo opt-out.
    pub fn with_max_in_flight_model_requests(mut self, max_in_flight: usize) -> Self {
        self.max_in_flight = max_in_flight;
        self
    }

    /// Reap completed workers and report the number still in flight.
    pub fn in_flight_model_requests(&self) -> usize {
        reap_finished_workers(&self.workers)
    }
}

impl Creature for DialogueMind {
    fn bind(&mut self, ctx: CreatureCtx) {
        *mlock(&self.bus) = Some(ctx.bus);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Preserve the standing responder's inbound posture: wrong schema/topic, malformed SEER,
        // non-Query moves, malformed query bodies, and over-cap prompts are silent drops. No model
        // is reached until every cheap gate has passed.
        let seer = match classify(&env, SeerTopic::Dialogue) {
            Inbound::Ours(seer) => seer,
            Inbound::NotSeer | Inbound::Malformed(_) | Inbound::OtherTopic => {
                return Outcome::none()
            }
        };
        let (query_id, body) = match seer.kind {
            SeerKind::Query { query_id, body } => (query_id, body),
            _ => return Outcome::none(),
        };
        let query: dialogue::QueryBody = match serde_json::from_value(body) {
            Ok(query) => query,
            Err(_) => return Outcome::none(),
        };
        if query.prompt.len() > dialogue::MAX_TURN_BYTES {
            return Outcome::none();
        }

        // During unload, refuse new work rather than create a worker that shutdown must detach.
        if self.stop.load(Ordering::Relaxed) {
            return Outcome::none();
        }

        let in_flight = reap_finished_workers(&self.workers);
        if self.max_in_flight != 0 && in_flight >= self.max_in_flight {
            eprintln!(
                "dialogue-mind: in-flight worker cap reached ({in_flight}/{}); aborting turn",
                self.max_in_flight
            );
            return abort_outcome(&env, seer.corr, &query.prompt, ABORT_BUSY, self.signer.as_ref());
        }

        let Some(bus) = mlock(&self.bus).as_ref().cloned() else {
            return abort_outcome(
                &env,
                seer.corr,
                &query.prompt,
                ABORT_NOT_BOUND,
                self.signer.as_ref(),
            );
        };

        // Capture routing and turn identity while the envelope is still on the drain thread.
        let reply_addr = env.reply_target();
        let corr = seer.corr;
        let prompt = query.prompt;
        let request = Prompt {
            system_prompt: self.instructions.to_string(),
            user_prompt: prompt.clone(),
            max_tokens: DEFAULT_MODEL_MAX_TOKENS,
            temperature: MODEL_TEMPERATURE,
        };
        let model = self.model.clone();
        let signer = self.signer.clone();
        let stop = self.stop.clone();
        let worker_prompt = prompt.clone();

        let spawn = Builder::new().name("dialogue-mind-worker".to_string()).spawn(move || {
            run_model_worker(
                model,
                signer,
                request,
                worker_prompt,
                bus,
                reply_addr,
                corr,
                query_id,
                stop,
            );
        });
        match spawn {
            Ok(handle) => mlock(&self.workers).push(handle),
            Err(error) => {
                eprintln!("dialogue-mind: failed to spawn worker: {error}");
                return abort_outcome(
                    &env,
                    corr,
                    &prompt,
                    ABORT_SPAWN_FAILED,
                    self.signer.as_ref(),
                );
            }
        }
        Outcome::none()
    }

    fn shutdown(&mut self, deadline: Deadline) {
        self.stop.store(true, Ordering::Relaxed);

        // Poll finished handles within the unload budget. A blocking model call cannot be forcibly
        // interrupted, so leave a margin for the kernel and detach bounded stragglers. Detached
        // workers are safe here because this is an in-process creature; after returning they see
        // `stop` and suppress their wire emission before exiting.
        let budget = deadline.0.saturating_sub(Duration::from_millis(100));
        let start = Instant::now();
        loop {
            let mut remaining = Vec::new();
            for handle in std::mem::take(&mut *mlock(&self.workers)) {
                if handle.is_finished() {
                    let _ = handle.join();
                } else {
                    remaining.push(handle);
                }
            }
            let all_joined = remaining.is_empty();
            *mlock(&self.workers) = remaining;
            if all_joined || start.elapsed() >= budget {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        mlock(&self.workers).clear();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_model_worker(
    model: Arc<dyn Model>,
    signer: Arc<dyn Signer>,
    request: Prompt,
    prompt: String,
    bus: Arc<dyn Bus>,
    reply_addr: Address,
    corr: u64,
    query_id: u64,
    stop: Arc<AtomicBool>,
) {
    use std::panic::{catch_unwind, AssertUnwindSafe};

    // Catch the entire injected decision, including signing. A panicking model becomes a signed
    // terminal abort. A panicking signer is caught too, but cannot honestly produce an authenticated
    // terminal move; the second guarded signing attempt below therefore drops rather than emits an
    // unsigned abort that could evict a pinned initiator.
    let result =
        catch_unwind(AssertUnwindSafe(|| -> Result<dialogue::AnswerBody, &'static str> {
            let completion = model.complete(request).map_err(|_| ABORT_MODEL_ERROR)?;
            if completion.content.len() > MAX_MODEL_OUTPUT_BYTES {
                return Err(ABORT_OUTPUT_TOO_LARGE);
            }
            Ok(dialogue::AnswerBody::signed(corr, &prompt, completion.content, signer.as_ref()))
        }));

    let response = match catch_unwind(AssertUnwindSafe(|| match result {
        Ok(Ok(answer)) => SeerEnvelope::answer(SeerTopic::Dialogue, corr, query_id, &answer),
        Ok(Err(reason)) => signed_abort(corr, &prompt, reason, signer.as_ref()),
        Err(_) => signed_abort(corr, &prompt, ABORT_MODEL_PANIC, signer.as_ref()),
    })) {
        Ok(response) => response,
        Err(_) => {
            // A signer that itself panics cannot produce an authentic abort. Drop rather than emit
            // an unsigned terminal move that a pinned initiator must (correctly) refuse.
            eprintln!("dialogue-mind: signer panicked while producing a terminal response");
            return;
        }
    };

    // Fast-path a worker finishing after shutdown. If deregistration races after this check, the
    // BusHandle lifecycle gate still rejects the stale sender before it can enqueue.
    if stop.load(Ordering::Relaxed) {
        return;
    }

    let dispatch =
        Dispatch::to(reply_addr, response.to_bytes()).with_schema(SEER_SCHEMA).with_corr(corr);
    if let Err(error) = bus.emit(dispatch) {
        eprintln!("dialogue-mind: dropped off-drain response: {error}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{BusError, CreatureId, Header};
    use mind::{Completion, FakeModel, ModelError, SlowModel};
    use sigil::{Backend, Manifest};

    /// A recording bus, so a model worker's off-drain emit is observable without a kernel.
    struct MockBus {
        me: CreatureId,
        sent: Mutex<Vec<Dispatch>>,
    }

    impl Bus for MockBus {
        fn emit(&self, dispatch: Dispatch) -> Result<(), BusError> {
            mlock(&self.sent).push(dispatch);
            Ok(())
        }

        fn whoami(&self) -> CreatureId {
            self.me
        }
    }

    struct FixedModel {
        content: String,
        expected_instructions: Option<String>,
    }

    impl FixedModel {
        fn replying(content: impl Into<String>) -> Self {
            FixedModel { content: content.into(), expected_instructions: None }
        }

        fn expecting(content: impl Into<String>, instructions: impl Into<String>) -> Self {
            FixedModel { content: content.into(), expected_instructions: Some(instructions.into()) }
        }
    }

    impl Model for FixedModel {
        fn complete(&self, request: Prompt) -> Result<Completion, ModelError> {
            if let Some(expected) = &self.expected_instructions {
                assert_eq!(&request.system_prompt, expected);
                assert_eq!(request.user_prompt, "hello peer");
                assert_eq!(request.max_tokens, DEFAULT_MODEL_MAX_TOKENS);
                assert_eq!(request.temperature, MODEL_TEMPERATURE);
            }
            Ok(Completion {
                content: self.content.clone(),
                model: "fixed-dialogue-model".to_string(),
                usage: None,
                provider: None,
            })
        }

        fn describe(&self) -> String {
            "fixed-dialogue-model".to_string()
        }
    }

    struct PanicModel;

    impl Model for PanicModel {
        fn complete(&self, _request: Prompt) -> Result<Completion, ModelError> {
            panic!("simulated dialogue model panic")
        }

        fn describe(&self) -> String {
            "panic-dialogue-model".to_string()
        }
    }

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

    fn bind_with_mock(mind: &mut DialogueMind) -> Arc<MockBus> {
        let bus = Arc::new(MockBus { me: CreatureId(99), sent: Mutex::new(Vec::new()) });
        mind.bind(CreatureCtx {
            me: CreatureId(99),
            bus: bus.clone(),
            manifest: Manifest::new("dialogue-mind", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        });
        bus
    }

    fn model_mind(model: Arc<dyn Model>, instructions: &str) -> DialogueMind {
        let (signer, _seed) = aether::Ed25519Signer::generate().expect("keygen");
        DialogueMind::new(model, Arc::new(signer), instructions).expect("valid mind config")
    }

    fn wait_for_dispatch(bus: &MockBus) -> Dispatch {
        for _ in 0..400 {
            if let Some(dispatch) = mlock(&bus.sent).first().cloned() {
                return dispatch;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("dialogue model worker did not emit")
    }

    fn wait_for_slow_model(model: &SlowModel) {
        for _ in 0..400 {
            if model.has_entered() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("slow dialogue model did not start")
    }

    fn wait_for_slow_model_finish(model: &SlowModel) {
        for _ in 0..400 {
            if model.has_finished() {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("slow dialogue model did not finish")
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

    fn decode_abort(d: &Dispatch, prompt: &str) -> String {
        use aether::Ed25519Verifier;
        use seer::topics::dialogue::Provenance;

        let env = SeerEnvelope::parse(&d.payload).expect("seer envelope");
        match env.kind {
            SeerKind::Steer { kind, payload } => {
                assert_eq!(kind, "abort");
                let body: dialogue::AnswerBody =
                    serde_json::from_value(payload).expect("signed abort AnswerBody");
                assert!(matches!(
                    body.verify_provenance(env.corr, prompt, &Ed25519Verifier),
                    Provenance::Verified(_)
                ));
                body.reply
            }
            other => panic!("expected abort Steer, got {other:?}"),
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

    #[test]
    fn a_signed_responder_attaches_verifiable_provenance_bound_to_the_turn() {
        // ADR-0038: with an agent identity, every answer carries a signature over (corr, prompt,
        // reply) that a requester can verify end-to-end, regardless of relay hops.
        use aether::{Ed25519Signer, Ed25519Verifier, Signer as _};
        use seer::topics::dialogue::Provenance;

        let (signer, _seed) = Ed25519Signer::generate().expect("keygen");
        let pubkey = signer.public_key();
        let mut r = DialogueResponder::signed(Box::new(EchoResponder), Box::new(signer));

        // corr=7 prompt="hello peer" (matches `turn`).
        let out = r.handle(turn(7, 1, "hello peer"));
        let env = SeerEnvelope::parse(&out.dispatches[0].payload).expect("seer envelope");
        let SeerKind::Answer { body, .. } = env.kind else { panic!("expected Answer") };
        let answer: dialogue::AnswerBody = serde_json::from_value(body).expect("answer body");

        assert_eq!(answer.signer_pubkey.as_deref(), Some(pubkey.as_str()));
        match answer.verify_provenance(7, "hello peer", &Ed25519Verifier) {
            Provenance::Verified(pk) => assert_eq!(pk, pubkey),
            other => panic!("expected Verified, got {other:?}"),
        }
    }

    #[test]
    fn an_unsigned_responder_leaves_provenance_absent() {
        let mut r = DialogueResponder::echo();
        let out = r.handle(turn(7, 1, "hi"));
        let env = SeerEnvelope::parse(&out.dispatches[0].payload).unwrap();
        let SeerKind::Answer { body, .. } = env.kind else { panic!("expected Answer") };
        let answer: dialogue::AnswerBody = serde_json::from_value(body).unwrap();
        assert!(answer.signer_pubkey.is_none() && answer.signature.is_none());
    }

    #[test]
    fn dialogue_mind_answers_off_drain_with_signed_existing_answer_shape() {
        use aether::{Ed25519Signer, Ed25519Verifier, Signer as _};
        use seer::topics::dialogue::Provenance;

        let (signer, _seed) = Ed25519Signer::generate().expect("keygen");
        let public_key = signer.public_key();
        let mut mind = DialogueMind::new(
            Arc::new(FixedModel::expecting("model reply", "answer as a peer")),
            Arc::new(signer),
            "answer as a peer",
        )
        .expect("valid configuration");
        assert_eq!(mind.max_in_flight, 8, "the production default is eight workers");
        let bus = bind_with_mock(&mut mind);

        let outcome = mind.handle(turn(7, 23, "hello peer"));
        assert!(outcome.dispatches.is_empty(), "blocking model work is off-drain");

        let dispatch = wait_for_dispatch(&bus);
        assert_eq!(dispatch.to, Address::Creature(CreatureId(11)));
        assert_eq!(dispatch.schema, SEER_SCHEMA);
        assert_eq!(dispatch.corr, Some(7));
        let envelope = SeerEnvelope::parse(&dispatch.payload).expect("seer answer");
        let SeerKind::Answer { query_id, body } = envelope.kind else { panic!("expected Answer") };
        assert_eq!(query_id, 23, "the answered query_id is preserved");
        let answer: dialogue::AnswerBody = serde_json::from_value(body).expect("answer body");
        assert_eq!(answer.reply, "model reply");
        assert_eq!(answer.signer_pubkey.as_deref(), Some(public_key.as_str()));
        assert!(matches!(
            answer.verify_provenance(7, "hello peer", &Ed25519Verifier),
            Provenance::Verified(key) if key == public_key
        ));

        mind.shutdown(Deadline::default());
    }

    #[test]
    fn dialogue_mind_rejects_oversized_instructions_at_construction() {
        let (signer, _seed) = aether::Ed25519Signer::generate().expect("keygen");
        let result = DialogueMind::new(
            Arc::new(FixedModel::replying("unused")),
            Arc::new(signer),
            "x".repeat(MAX_MODEL_INSTRUCTIONS_BYTES + 1),
        );
        assert!(matches!(
            result,
            Err(DialogueMindConfigError::InstructionsTooLarge {
                bytes,
                max_bytes: MAX_MODEL_INSTRUCTIONS_BYTES
            }) if bytes == MAX_MODEL_INSTRUCTIONS_BYTES + 1
        ));
    }

    fn assert_async_model_abort(model: Arc<dyn Model>, expected_reason: &str) {
        let mut mind = model_mind(model, "answer briefly");
        let bus = bind_with_mock(&mut mind);
        let outcome = mind.handle(turn(31, 4, "hello"));
        assert!(outcome.dispatches.is_empty(), "accepted model calls are asynchronous");
        let dispatch = wait_for_dispatch(&bus);
        assert_eq!(dispatch.corr, Some(31));
        assert_eq!(decode_abort(&dispatch, "hello"), expected_reason);
        mind.shutdown(Deadline::default());
    }

    #[test]
    fn model_error_panic_and_oversized_output_each_emit_abort() {
        assert_async_model_abort(Arc::new(FakeModel::erroring()), ABORT_MODEL_ERROR);
        assert_async_model_abort(Arc::new(PanicModel), ABORT_MODEL_PANIC);
        assert_async_model_abort(
            Arc::new(FixedModel::replying("x".repeat(MAX_MODEL_OUTPUT_BYTES + 1))),
            ABORT_OUTPUT_TOO_LARGE,
        );
    }

    #[test]
    fn in_flight_model_calls_are_capped_and_overflow_aborts_synchronously() {
        let slow = Arc::new(SlowModel::new());
        let mut mind =
            model_mind(slow.clone(), "answer briefly").with_max_in_flight_model_requests(1);
        let bus = bind_with_mock(&mut mind);

        let first = mind.handle(turn(40, 1, "first"));
        assert!(first.dispatches.is_empty());
        wait_for_slow_model(&slow);
        assert_eq!(mind.in_flight_model_requests(), 1);

        let second = mind.handle(turn(41, 1, "second"));
        assert_eq!(second.dispatches.len(), 1, "over-cap turn aborts without a worker");
        assert_eq!(second.dispatches[0].corr, Some(41));
        assert_eq!(decode_abort(&second.dispatches[0], "second"), ABORT_BUSY);
        assert!(mlock(&bus.sent).is_empty(), "the blocked first worker has not emitted");

        // Shutdown is deadline-bounded and suppresses the detached worker's eventual answer.
        mind.shutdown(Deadline::from_millis(110));
        slow.release();
        wait_for_slow_model_finish(&slow);
        std::thread::sleep(Duration::from_millis(30));
        assert!(mlock(&bus.sent).is_empty(), "a stopped worker emits no late answer");
    }
}
