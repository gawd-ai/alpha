//! `agent-curious` — reference `Role::AUTHORING` creature that *consumes the SEER
//! primitive* on the `authoring` topic.
//!
//! Where [`agent_templated`] is the minimal single-shot reference (Request → Reply), this creature
//! demonstrates that the wire admits a richer conversation **without forcing one**. On a template
//! match it still emits only the terminal [`AuthoringReply`] (the **reduction theorem**: a curious
//! agent collapses to a single-shot agent when curiosity isn't needed). On a request it can't
//! template-match, it consults the originating orchestrator via a [`SeerEnvelope::query`] on
//! [`SeerTopic::Authoring`] — the *curiosity / alimentation* seam — and completes terminally
//! when the orchestrator's matching [`SeerEnvelope::answer`] arrives back.
//!
//! ## Why a *curious* agent
//!
//! Without a Query/Answer seam, the framework structurally forecloses a *feeding* / *curious*
//! authoring shape. That pattern lives in `seer` so every consult-and-reconcile socket —
//! placement, policy, budget, fitness, consensus — speaks the same shape. **agent-curious is the
//! topic-`authoring` consumer of that primitive**, on a topic-keyed SeerEnvelope.
//!
//! ## Conversation shape
//!
//! 1. Orchestrator emits `AuthoringRequest{ request, … }` on `corr=N` to `Role::AUTHORING`, with
//!    `reply_to` pointing at itself. (The REQUEST entry is *not* a SEER envelope — it's the
//!    entry to the AUTHORING role; SEER shapes the *conversation* between request and
//!    terminal reply, not the request itself.)
//! 2. If the request matches a template, the creature emits a terminal `AuthoringReply::Authored`
//!    on `corr=N` and the conversation ends. **(Reduction theorem path — no SEER traffic.)**
//! 3. If no template matches, the creature emits — in one [`Outcome`] — a
//!    `SeerEnvelope::Thought` (narrating *why* it's consulting), a `SeerEnvelope::Progress
//!    { stage: "awaiting_answer" }`, and a `SeerEnvelope::Query{ query_id: K }` carrying a
//!    typed [`topics::authoring::QueryBody`]. It then **parks** the pending exchange
//!    (`corr → PendingExchange{ request, reply_to, query_id }`) and returns.
//! 4. The orchestrator answers with `SeerEnvelope::Answer{ query_id: K }` on `corr=N` carrying
//!    a typed [`topics::authoring::AnswerBody{ content }`], addressed to the creature (the
//!    creature's id was the `from` on the Query). The creature looks up the parked
//!    exchange by `(corr, query_id)`, maps `content` to a template (or to a Failed reply), and
//!    emits the terminal `AuthoringReply` on `corr=N` to the parked `reply_to`.
//! 5. An orchestrator that changes its mind mid-conversation may emit `SeerEnvelope::Steer{
//!    kind: "abort" }` on `corr=N` to the creature; the creature drops the pending exchange and
//!    emits a Failed reply on `corr=N`. Other `kind`s are ignored (the "a creature can
//!    ignore steers" guarantee, a substrate-wide property).
//!
//! ## Topic discrimination (S1)
//!
//! agent-curious is bound to the `authoring` topic. A SeerEnvelope arriving with any other
//! topic (placement / policy / budget / fitness / consensus) is dropped — no model in the
//! substrate decides what cross-topic means; that's the consumer's call. The creature checks
//! `seer.topic == Authoring` and silently ignores otherwise (no Failed reply on the wrong
//! topic — that would be the substrate adjudicating a model dispute).
//!
//! ## What this creature *deliberately* doesn't do (still — embryo discipline)
//!
//! - It doesn't consult anyone *other* than the originating orchestrator. SEER
//!   Queries may address any `Role`/`Topic`/peer (consult-N-somethings, race, weighted consensus,
//!   "pre-decided, consult for show"); the seam is here, the *resolution model* stays an
//!   injected concern. agent-curious uses the cheapest of all models: ask the requester.
//! - It doesn't multi-step Queries (one outstanding query per `corr` at a time). The wire admits
//!   a richer dialogue (multiple `query_id`s per `corr`); a future curious agent grows into that
//!   without a substrate change. A second ambiguous request on a parked `corr` is refused rather
//!   than overwriting the live exchange.
//! - It doesn't time out pending exchanges itself. *Time is injected policy, never fabric* — an
//!   orchestrator that wants a deadline rides it on top, never inside.
//! - It does cap the number of parked exchanges by default. That is a memory/resource floor, not a
//!   timeout policy; `with_max_pending(0)` is the explicit lab/demo opt-out.

use std::collections::HashMap;

use aether::{Address, Creature, CreatureCtx, Dispatch, Envelope, Outcome};
use agent_templated::{
    authoring_request_preview, decode_authoring_request, AuthoringError, AuthoringReply,
    AuthoringRequest, AuthoringResponse,
};
use build_cargo::ManifestStub;
use seer::responder::{classify, Inbound};
use seer::{topics, SeerEnvelope, SeerKind, SeerTopic, SCHEMA as SEER_SCHEMA};
use sigil::{Capabilities, Entrypoint, NetCapability};

/// Default number of concurrently parked authoring consults. `0` in
/// [`AgentCurious::with_max_pending`] means unbounded.
pub const DEFAULT_MAX_PENDING_EXCHANGES: usize = 128;
/// Maximum original-request bytes copied into SEER Thought/Query context. The full request is still
/// parked for the terminal answer path; this cap bounds conversational fan-out.
pub const MAX_REQUEST_SEER_PREVIEW_BYTES: usize = 8 * 1024;
/// Maximum answer-content bytes scanned when mapping a SEER answer to this creature's choices.
pub const MAX_ANSWER_CLASSIFIER_BYTES: usize = 8 * 1024;
/// Maximum answer-content bytes echoed in an `Invalid` reply for an unrecognized answer.
pub const MAX_ANSWER_ERROR_PREVIEW_BYTES: usize = 1024;

/// Schema strings the creature reads on inbound envelopes + emits on outbound. The
/// REQUEST/REPLY entry-and-exit constants (those are *not* SEER — they bracket the
/// conversation, they don't ride inside it) stand apart from the five conversation schemas
/// (Query / Answer / Steer / Progress / Thought), which all ride the single `schema::SEER` schema
/// with `topic=authoring` discrimination at the payload layer.
pub mod schema {
    /// The entry — what an orchestrator submits to `Role::AUTHORING`. Carries an
    /// [`AuthoringRequest`](agent_templated::AuthoringRequest) JSON payload (no SEER wrapping;
    /// this envelope precedes the conversation).
    pub const REQUEST: &str = "authoring.request";
    /// The terminal — what the creature emits to end a conversation. Carries an
    /// [`AuthoringReply`](agent_templated::AuthoringReply) JSON payload.
    pub const REPLY: &str = "authoring.reply";
    /// The SEER schema — every Query/Answer/Steer/Progress/Thought between
    /// orchestrator and creature rides here, discriminated by `SeerEnvelope.topic`.
    pub const SEER: &str = super::SEER_SCHEMA;
}

/// Pending state for one parked exchange. Keyed by the originating `AuthoringRequest`'s `corr` in
/// [`AgentCurious::pending`]; the `query_id` lets the creature reject a `SeerEnvelope::Answer`
/// whose `(corr, query_id)` pair doesn't match (a stale answer from a previous round, say).
#[derive(Clone, Debug)]
struct PendingExchange {
    /// Verbatim text of the original `AuthoringRequest.request`. Stored so the creature can
    /// re-attempt template matching when the answer arrives ("the orchestrator said use the
    /// reverse approach for *this* original ask").
    request: String,
    /// Where the terminal reply should land — the original orchestrator. Preserved from the
    /// original request's `reply_to` (falling back to its `from`).
    reply_to: Address,
    /// The query the creature is currently awaiting. The matching SEER `Answer` carries the
    /// same id; an answer with a different id is rejected (defends against a stale answer racing
    /// in).
    query_id: u64,
}

/// The reply contract for an Answer: which option did the orchestrator pick?
///
/// The mapping `content → option` is *creature policy*, not substrate. SEER keeps the
/// AnswerBody.content field opaque prose; here we substring-match the same way
/// [`AgentTemplated`](agent_templated::AgentTemplated) keyword-matches the request. A richer
/// curious agent that takes structured JSON in `content` is a creature swap, not a wire change.
enum AnswerChoice {
    Reverse,
    FetchUrlTitle,
    Abort,
    Unknown,
}

fn parse_answer(content: &str) -> AnswerChoice {
    let lower = prefix_on_char_boundary(content, MAX_ANSWER_CLASSIFIER_BYTES).to_ascii_lowercase();
    if lower.contains("abort") {
        return AnswerChoice::Abort;
    }
    if lower.contains("reverse") {
        return AnswerChoice::Reverse;
    }
    if lower.contains("fetch") {
        return AnswerChoice::FetchUrlTitle;
    }
    AnswerChoice::Unknown
}

fn prefix_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

fn bounded_preview(s: &str, max: usize) -> String {
    let prefix = prefix_on_char_boundary(s, max);
    if prefix.len() == s.len() {
        prefix.to_string()
    } else {
        format!("{prefix}\n... (truncated; {} bytes total)", s.len())
    }
}

/// The curious authoring creature. Stateful: parks pending exchanges by `corr`.
///
/// **Concurrency.** `handle` takes `&mut self`, and the kernel routes envelopes to a creature's
/// inbox single-threaded per creature (see `aether::Bus`), so the `HashMap` is never accessed
/// concurrently. The whole creature is `Send` but not `Sync`, matching every other reference
/// creature in the workspace.
pub struct AgentCurious {
    pending: HashMap<u64, PendingExchange>,
    /// Monotonically increasing across the creature's lifetime — only assigned when parking. The
    /// embryo's reservation that one `corr` thread may hold several outstanding queries; this
    /// creature only ever uses one at a time, but the id is still per-creature-unique so a future
    /// multi-query shape doesn't break the matching contract.
    next_query_id: u64,
    /// Maximum number of parked exchanges held at once. An orchestrator that never answers a
    /// consult would otherwise leak a `pending` entry per unanswered request forever. At capacity a
    /// new request is refused with a structured failure (the existing in-flight exchanges are kept —
    /// refuse-new, never evict-live). **`0` means unbounded** and should be reserved for lab/demo
    /// deployments that intentionally accept unbounded pending state.
    max_pending: usize,
}

impl Default for AgentCurious {
    fn default() -> Self {
        Self {
            pending: HashMap::new(),
            next_query_id: 0,
            max_pending: DEFAULT_MAX_PENDING_EXCHANGES,
        }
    }
}

impl AgentCurious {
    pub fn new() -> Self {
        AgentCurious::default()
    }

    /// Cap the number of concurrently-parked exchanges. `0` disables the cap. At capacity, a new
    /// consult is refused with `AuthoringError::Invalid` rather than growing the pending table
    /// without bound.
    pub fn with_max_pending(mut self, max_pending: usize) -> Self {
        self.max_pending = max_pending;
        self
    }

    /// How many exchanges are currently parked awaiting an Answer or a Steer{abort}. Exposed
    /// for tests + observability; **not** part of the wire contract.
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    fn allocate_query_id(&mut self) -> u64 {
        self.next_query_id = self.next_query_id.wrapping_add(1);
        self.next_query_id
    }
}

impl Creature for AgentCurious {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Every inbound envelope starts at the shared SEER gate ([`seer::responder::classify`]).
        // This creature is the conversation *initiator*, so its four branches differ from a plain
        // responder's "drop everything but Ours":
        // - `NotSeer` (empty/REQUEST schema) → the conversation *entry*: an `AuthoringRequest`.
        // - `Malformed` → a structured Failed reply (we can't tell Answer from Steer, but the
        //   orchestrator deserves to know its message didn't land).
        // - `OtherTopic` → drop (topic isolation; the substrate doesn't adjudicate cross-topic).
        // - `Ours` → kind-dispatch: act on the orchestrator's `Answer`/`Steer`, ignore
        //   `Query`/`Progress`/`Thought` (it asks; it doesn't answer asks, and Progress/Thought are
        //   the orchestrator's own observability).
        match classify(&env, SeerTopic::Authoring) {
            Inbound::NotSeer => self.on_request(env),
            Inbound::Malformed(e) => reply_failed(
                &env,
                AuthoringError::Invalid { message: format!("malformed seer envelope: {e}") },
            ),
            Inbound::OtherTopic => Outcome::none(),
            Inbound::Ours(seer) => match seer.kind {
                SeerKind::Answer { query_id, body } => {
                    self.on_answer(env, seer.corr, query_id, body)
                }
                SeerKind::Steer { kind, .. } => self.on_steer(seer.corr, &kind),
                SeerKind::Query { .. } | SeerKind::Progress { .. } | SeerKind::Thought { .. } => {
                    Outcome::none()
                }
            },
        }
    }
}

impl AgentCurious {
    fn on_request(&mut self, env: Envelope) -> Outcome {
        let req: AuthoringRequest = match decode_authoring_request(&env.payload) {
            Ok(r) => r,
            Err(e) => return reply_failed(&env, e),
        };
        let corr = env.header.corr.unwrap_or(0);
        let reply_to = env.reply_target();

        // Template match → reduction-theorem path. No SEER envelopes emitted; the wire here is
        // byte-identical to a templated agent's reply for the same request.
        if let Some(resp) = try_template(&req.request) {
            return reply_authored(&env, resp);
        }

        // One pending exchange per corr thread. A duplicate ambiguous request is a stale/replayed
        // or confused conversation starter; refusing it preserves the live exchange's query_id and
        // reply target instead of overwriting pending state.
        if self.pending.contains_key(&corr) {
            eprintln!(
                "agent-curious: corr {corr} already has a pending consult; refusing new consult for `{}`",
                bounded_preview(&req.request, MAX_REQUEST_SEER_PREVIEW_BYTES)
            );
            return reply_failed(
                &env,
                AuthoringError::Invalid {
                    message: format!(
                        "authoring agent busy: corr {corr} already has a pending consult"
                    ),
                },
            );
        }

        // Pending-pressure guard (resilience): refuse a new consult at capacity rather than leak a
        // pending entry forever when an orchestrator never answers. Refuse-new keeps every in-flight
        // exchange intact (we never evict a live one). `0` disables the cap.
        if self.max_pending != 0 && self.pending.len() >= self.max_pending {
            eprintln!(
                "agent-curious: pending table at capacity ({}); refusing new consult for `{}`",
                self.max_pending,
                bounded_preview(&req.request, MAX_REQUEST_SEER_PREVIEW_BYTES)
            );
            return reply_failed(
                &env,
                AuthoringError::Invalid {
                    message: "authoring agent busy: pending-consult table at capacity".to_string(),
                },
            );
        }

        // No template → consult. One Outcome carries Thought (observable reasoning) +
        // Progress (we've parked) + Query (the actual question), all on topic `authoring`. The
        // orchestrator may render all three; a simple orchestrator that only consumes Query
        // still works (Thought/Progress are additive observability, never required).
        let query_id = self.allocate_query_id();
        let options =
            vec!["reverse".to_string(), "fetch_url_title".to_string(), "abort".to_string()];
        let request_preview = bounded_preview(&req.request, MAX_REQUEST_SEER_PREVIEW_BYTES);

        let thought = SeerEnvelope::thought(
            SeerTopic::Authoring,
            corr,
            "internal",
            &format!(
                "no template matched the request `{}` — consulting the orchestrator",
                request_preview
            ),
        );
        let progress = SeerEnvelope::progress(
            SeerTopic::Authoring,
            corr,
            "awaiting_answer",
            None,
            Some(&format!("query_id={query_id} open")),
        );
        let query_body = topics::authoring::QueryBody {
            question: format!("no template for `{request_preview}` — which approach should I use?"),
            options: Some(options),
            deadline_ms: None,
        };
        let query = SeerEnvelope::query(SeerTopic::Authoring, corr, query_id, &query_body);

        self.pending.insert(
            corr,
            PendingExchange { request: req.request.clone(), reply_to: reply_to.clone(), query_id },
        );

        let mut out = Outcome::none();
        out.push(seer_dispatch(&reply_to, thought, corr));
        out.push(seer_dispatch(&reply_to, progress, corr));
        out.push(seer_dispatch(&reply_to, query, corr));
        out
    }

    fn on_answer(
        &mut self,
        env: Envelope,
        corr: u64,
        query_id: u64,
        body: serde_json::Value,
    ) -> Outcome {
        let answer: topics::authoring::AnswerBody = match serde_json::from_value(body) {
            Ok(a) => a,
            Err(e) => {
                return reply_failed(
                    &env,
                    AuthoringError::Invalid {
                        message: format!("malformed authoring answer body: {e}"),
                    },
                );
            }
        };

        // Pairing check: an answer whose (corr, query_id) doesn't match the parked exchange is
        // a stale / spoofed message. The creature drops it on the floor — *no* terminal reply —
        // so the live parked exchange can still be resolved by the right answer. We deliberately
        // *don't* tell the late answerer "no" (no envelope back); that's the conservative move
        // for a creature whose model is "the orchestrator that started this thread is the only
        // legitimate answerer". A richer creature could disambiguate via auth.
        let pending = match self.pending.get(&corr) {
            Some(p) if p.query_id == query_id => p.clone(),
            _ => return Outcome::none(),
        };

        // Consume the pending exchange (success or failure — either way the conversation ends).
        //
        // **Asymmetry with the stale-(corr, query_id) drop above, deliberate:** a
        // matched answer whose *content* is unrecognized (`AnswerChoice::Unknown` below) consumes
        // the exchange and ends it with a terminal `Invalid` — the orchestrator answered the right
        // thread, just with something this creature can't act on, so it gets one shot. A stale
        // (corr, query_id) mismatch, by contrast, is dropped *without* consuming, because it isn't
        // an answer to *this* live exchange at all (a late/duplicate/spoofed message) — so the real
        // answer can still resolve it. "Answered the wrong thing once" and "wasn't answering this
        // thread" are genuinely different cases; an orchestrator that wants to retry an ambiguous
        // answer opens a fresh exchange. A richer creature could instead re-park + `Steer{amend}`.
        self.pending.remove(&corr);

        let resp_or_err = match parse_answer(&answer.content) {
            AnswerChoice::Reverse => Ok(template_reverse_string("agent-curious/reverse")),
            AnswerChoice::FetchUrlTitle => {
                Ok(template_fetch_url_title("agent-curious/fetch-url-title"))
            }
            AnswerChoice::Abort => Err(AuthoringError::NoTemplate {
                request: authoring_request_preview(&pending.request),
            }),
            AnswerChoice::Unknown => Err(AuthoringError::Invalid {
                message: format!(
                    "unrecognized answer content: `{}`",
                    bounded_preview(&answer.content, MAX_ANSWER_ERROR_PREVIEW_BYTES)
                ),
            }),
        };

        let payload = match resp_or_err {
            Ok(resp) => AuthoringReply::Authored(resp).to_bytes(),
            Err(e) => AuthoringReply::Failed(e).to_bytes(),
        };
        Outcome::send(
            Dispatch::to(pending.reply_to, payload).with_schema(schema::REPLY).with_corr(corr),
        )
    }

    fn on_steer(&mut self, corr: u64, verb: &str) -> Outcome {
        // A creature can ignore steers entirely. Only
        // `abort` is acted on. `amend` / `info` would need the creature to revise
        // mid-flight, which is the *next* step past the embryo.
        if verb != "abort" {
            return Outcome::none();
        }

        let Some(pending) = self.pending.remove(&corr) else {
            // No parked exchange under this corr — nothing to abort, no reply to emit.
            return Outcome::none();
        };

        let payload = AuthoringReply::Failed(AuthoringError::NoTemplate {
            request: authoring_request_preview(&pending.request),
        })
        .to_bytes();
        Outcome::send(
            Dispatch::to(pending.reply_to, payload).with_schema(schema::REPLY).with_corr(corr),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------------------------

/// Wrap a [`SeerEnvelope`] in a [`Dispatch`] addressed to `to`, propagating `corr` onto the
/// envelope header. The creature emits SEER envelopes only through this helper so the schema
/// string + corr propagation never desync between sites.
fn seer_dispatch(to: &Address, seer: SeerEnvelope, corr: u64) -> Dispatch {
    Dispatch::to(to.clone(), seer.to_bytes()).with_schema(schema::SEER).with_corr(corr)
}

/// Build a terminal `AuthoringReply::Authored` Outcome addressed at `env`'s reply_to (or sender).
fn reply_authored(env: &Envelope, resp: AuthoringResponse) -> Outcome {
    let payload = AuthoringReply::Authored(resp).to_bytes();
    Outcome::send(Dispatch::reply_to_env(env, payload).with_schema(schema::REPLY))
}

/// Build a terminal `AuthoringReply::Failed` Outcome addressed at `env`'s reply_to (or sender).
fn reply_failed(env: &Envelope, err: AuthoringError) -> Outcome {
    let payload = AuthoringReply::Failed(err).to_bytes();
    Outcome::send(Dispatch::reply_to_env(env, payload).with_schema(schema::REPLY))
}

/// Tries the same keyword-template match as `agent-templated`, returning a fully-formed
/// `AuthoringResponse` on hit. Keeping this self-contained means agent-curious doesn't need to
/// reach into agent-templated for the private template helpers — both creatures may diverge their
/// template sets independently as the embryo evolves.
fn try_template(request: &str) -> Option<AuthoringResponse> {
    let lower = request.to_ascii_lowercase();
    if lower.contains("reverse") {
        return Some(template_reverse_string("agent-curious/reverse"));
    }
    if lower.contains("fetch") && lower.contains("title") && lower.contains("url") {
        return Some(template_fetch_url_title("agent-curious/fetch-url-title"));
    }
    None
}

const REVERSE_STRING_SOURCE: &str = r#"use forge::prelude::*;

#[derive(Default)]
pub struct ReverseDaemon;

impl Creature for ReverseDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }
}

forge::declare_creature!(ReverseDaemon);
"#;

fn template_reverse_string(template_label: &str) -> AuthoringResponse {
    AuthoringResponse {
        crate_name: "reverse-daemon".to_string(),
        crate_version: "0.1.0".to_string(),
        source: REVERSE_STRING_SOURCE.to_string(),
        manifest_stub: ManifestStub {
            name: "reverse-daemon".to_string(),
            version: "0.1.0".to_string(),
            entrypoints: vec![Entrypoint {
                name: "handle".to_string(),
                signature: "(Envelope) -> Outcome".to_string(),
            }],
            capabilities: Capabilities::default(),
            provides: vec![],
        },
        deps: vec![],
        template: template_label.to_string(),
    }
}

const FETCH_URL_TITLE_SOURCE: &str = r#"use forge::prelude::*;

const MAX_URL_BYTES: usize = 8 * 1024;

#[derive(Default)]
pub struct FetchUrlTitle;

impl Creature for FetchUrlTitle {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.payload.len() > MAX_URL_BYTES {
            return Outcome::reply(
                &env,
                format!("<error: url too large: exceeds {} byte limit>", MAX_URL_BYTES).into_bytes(),
            );
        }
        // Inline simple body — agent-curious ships the same template *shape* as agent-templated
        // (the curious agent demonstrates the embryo's conversation seam, not template breadth).
        let url = String::from_utf8_lossy(&env.payload).to_string();
        Outcome::reply(&env, format!("<would fetch {url}>").into_bytes())
    }
}

forge::declare_creature!(FetchUrlTitle);
"#;

fn template_fetch_url_title(template_label: &str) -> AuthoringResponse {
    AuthoringResponse {
        crate_name: "fetch-url-title".to_string(),
        crate_version: "0.1.0".to_string(),
        source: FETCH_URL_TITLE_SOURCE.to_string(),
        manifest_stub: ManifestStub {
            name: "fetch-url-title".to_string(),
            version: "0.1.0".to_string(),
            entrypoints: vec![Entrypoint {
                name: "handle".to_string(),
                signature: "(Envelope) -> Outcome".to_string(),
            }],
            capabilities: Capabilities { net: NetCapability::Outbound, ..Default::default() },
            provides: vec![],
        },
        deps: vec![],
        template: template_label.to_string(),
    }
}

// =================================================================================================
// Tests
// =================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{CreatureId, Header};

    fn make_env(schema_str: &str, corr: u64, payload: Vec<u8>) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: Some(Address::Creature(CreatureId(1))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: schema_str.to_string(),
                origin: None,
            },
            payload,
        }
    }

    fn request_env(corr: u64, text: &str) -> Envelope {
        let req = AuthoringRequest { request: text.to_string(), ..Default::default() };
        make_env(schema::REQUEST, corr, serde_json::to_vec(&req).unwrap())
    }

    fn seer_env(corr: u64, seer: SeerEnvelope) -> Envelope {
        make_env(schema::SEER, corr, seer.to_bytes())
    }

    fn answer_env(corr: u64, query_id: u64, content: &str) -> Envelope {
        let body = topics::authoring::AnswerBody { content: content.to_string() };
        let o = SeerEnvelope::answer(SeerTopic::Authoring, corr, query_id, &body);
        seer_env(corr, o)
    }

    fn steer_env(corr: u64, verb: &str) -> Envelope {
        let o = SeerEnvelope::steer(SeerTopic::Authoring, corr, verb, &serde_json::json!({}));
        seer_env(corr, o)
    }

    fn decode_reply(d: &Dispatch) -> AuthoringReply {
        serde_json::from_slice(&d.payload).expect("reply decodes")
    }

    fn decode_seer(d: &Dispatch) -> SeerEnvelope {
        SeerEnvelope::parse(&d.payload).expect("seer envelope decodes")
    }

    // -------------------------------------------------------------------------------------------
    // Reduction theorem — a template match still produces *only* a terminal reply (no SEER).
    // -------------------------------------------------------------------------------------------

    #[test]
    fn template_match_reduces_to_single_terminal_reply() {
        let mut a = AgentCurious::new();
        let out = a.handle(request_env(1, "please write a daemon that REVERSES a string"));
        assert_eq!(out.dispatches.len(), 1, "exactly one dispatch on template match");
        let d = &out.dispatches[0];
        assert_eq!(d.schema, schema::REPLY);
        assert_eq!(d.corr, Some(1));
        match decode_reply(d) {
            AuthoringReply::Authored(r) => {
                assert_eq!(r.crate_name, "reverse-daemon");
                assert_eq!(r.template, "agent-curious/reverse");
            }
            AuthoringReply::Failed(e) => panic!("expected Authored, got Failed({e:?})"),
        }
        assert_eq!(a.pending_len(), 0, "template match never parks");
    }

    #[test]
    fn fetch_url_title_template_also_reduces_to_terminal_reply() {
        let mut a = AgentCurious::new();
        let out = a.handle(request_env(7, "fetch the title from a URL please"));
        assert_eq!(out.dispatches.len(), 1);
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Authored(r) => {
                assert_eq!(r.crate_name, "fetch-url-title");
                assert_eq!(r.template, "agent-curious/fetch-url-title");
                assert!(r.source.contains("const MAX_URL_BYTES"));
                assert!(r.source.contains("url too large"));
            }
            other => panic!("expected fetch-url-title authored, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    // -------------------------------------------------------------------------------------------
    // Query/Answer roundtrip — the embryo's centerpiece, now on the SEER wire.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn unmatched_request_emits_thought_progress_and_query_and_parks() {
        let mut a = AgentCurious::new();
        let out = a.handle(request_env(42, "compute the LZ77 entropy of an mp3"));
        assert_eq!(out.dispatches.len(), 3, "Thought + Progress + Query in one Outcome");

        // All three dispatches ride on schema::SEER; the discrimination is by SeerKind.
        for d in &out.dispatches {
            assert_eq!(d.schema, schema::SEER, "all conversation envelopes are SEER");
        }

        let thought = decode_seer(&out.dispatches[0]);
        assert_eq!(thought.topic, SeerTopic::Authoring);
        assert_eq!(thought.corr, 42);
        match thought.kind {
            SeerKind::Thought { channel, content } => {
                assert_eq!(channel, "internal");
                assert!(content.contains("LZ77"), "thought references the original request");
            }
            other => panic!("expected Thought, got {other:?}"),
        }

        let progress = decode_seer(&out.dispatches[1]);
        match progress.kind {
            SeerKind::Progress { stage, fraction, note } => {
                assert_eq!(stage, "awaiting_answer");
                assert!(fraction.is_none(), "fraction absent when the creature has no estimate");
                assert!(note.is_some(), "progress carries the query_id note");
            }
            other => panic!("expected Progress, got {other:?}"),
        }

        let query = decode_seer(&out.dispatches[2]);
        match query.kind {
            SeerKind::Query { query_id, body } => {
                assert_eq!(query_id, 1, "first query allocated id 1");
                let q: topics::authoring::QueryBody = serde_json::from_value(body).unwrap();
                assert_eq!(
                    q.options.as_deref(),
                    Some(
                        ["reverse".to_string(), "fetch_url_title".to_string(), "abort".to_string()]
                            .as_slice()
                    )
                );
                assert!(q.deadline_ms.is_none(), "deadline is orchestrator-set, not creature-set");
            }
            other => panic!("expected Query, got {other:?}"),
        }

        assert_eq!(a.pending_len(), 1, "parked one exchange under corr=42");
    }

    #[test]
    fn unmatched_request_uses_bounded_seer_preview_and_terminal_preview() {
        let mut a = AgentCurious::new();
        let full_request =
            format!("ambiguous {} tail-marker", "x".repeat(MAX_REQUEST_SEER_PREVIEW_BYTES + 4096));
        let out = a.handle(request_env(43, &full_request));
        assert_eq!(out.dispatches.len(), 3);

        for d in &out.dispatches {
            assert!(
                d.payload.len() < seer::MAX_SEER_ENVELOPE_BYTES,
                "SEER dispatch stayed under bounded parse cap: {}",
                d.payload.len()
            );
            SeerEnvelope::parse_bounded(&d.payload).expect("bounded SEER parser accepts context");
        }

        match decode_seer(&out.dispatches[0]).kind {
            SeerKind::Thought { content, .. } => {
                assert!(content.contains("truncated"), "thought marks the preview: {content}");
                assert!(
                    !content.contains(&"x".repeat(MAX_REQUEST_SEER_PREVIEW_BYTES + 1)),
                    "thought must not contain the full oversized request"
                );
            }
            other => panic!("expected Thought, got {other:?}"),
        }

        let query_id = match decode_seer(&out.dispatches[2]).kind {
            SeerKind::Query { query_id, body } => {
                let q: topics::authoring::QueryBody = serde_json::from_value(body).unwrap();
                assert!(q.question.contains("truncated"), "query marks the preview");
                assert!(
                    !q.question.contains(&"x".repeat(MAX_REQUEST_SEER_PREVIEW_BYTES + 1)),
                    "query must not contain the full oversized request"
                );
                query_id
            }
            other => panic!("expected Query, got {other:?}"),
        };

        let aborted = a.handle(answer_env(43, query_id, "abort"));
        match decode_reply(&aborted.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::NoTemplate { request }) => {
                assert!(request.contains("truncated"), "terminal reply marks preview: {request}");
                assert!(
                    !request.contains(
                        &"x".repeat(agent_templated::MAX_AUTHORING_ERROR_PREVIEW_BYTES + 1)
                    ),
                    "terminal NoTemplate reply must not retain the full oversized request"
                );
                assert!(request.len() < full_request.len(), "terminal error echo is bounded");
            }
            other => panic!("expected Failed(NoTemplate), got {other:?}"),
        }
    }

    #[test]
    fn duplicate_corr_request_is_refused_without_overwriting_pending_exchange() {
        let mut a = AgentCurious::new();
        let first = a.handle(request_env(44, "first ambiguous"));
        assert_eq!(first.dispatches.len(), 3, "first request parks and emits SEER");
        assert_eq!(a.pending_len(), 1);

        let duplicate = a.handle(request_env(44, "second ambiguous"));
        assert_eq!(a.pending_len(), 1, "duplicate corr must not overwrite the pending exchange");
        assert_eq!(duplicate.dispatches.len(), 1, "duplicate corr gets one terminal reply");
        assert_eq!(duplicate.dispatches[0].schema, schema::REPLY);
        match decode_reply(&duplicate.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("already has a pending consult"), "{message}");
            }
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }

        let aborted = a.handle(steer_env(44, "abort"));
        match decode_reply(&aborted.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::NoTemplate { request }) => {
                assert_eq!(request, "first ambiguous", "original pending request was preserved");
            }
            other => panic!("expected Failed(NoTemplate), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn answer_with_reverse_resumes_with_terminal_reply() {
        let mut a = AgentCurious::new();
        let first = a.handle(request_env(100, "do that thing with strings"));
        let query = decode_seer(&first.dispatches[2]);
        let query_id = match query.kind {
            SeerKind::Query { query_id, .. } => query_id,
            _ => panic!("expected Query"),
        };

        let out = a.handle(answer_env(100, query_id, "reverse"));
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        assert_eq!(d.schema, schema::REPLY);
        assert_eq!(d.corr, Some(100));
        match decode_reply(d) {
            AuthoringReply::Authored(r) => {
                assert_eq!(r.crate_name, "reverse-daemon");
                assert_eq!(r.template, "agent-curious/reverse");
            }
            other => panic!("expected Authored, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0, "parked exchange consumed on answer");
    }

    #[test]
    fn answer_with_fetch_url_title_resumes_with_terminal_reply() {
        let mut a = AgentCurious::new();
        let first = a.handle(request_env(101, "do a network thing"));
        let q = decode_seer(&first.dispatches[2]);
        let qid = match q.kind {
            SeerKind::Query { query_id, .. } => query_id,
            _ => panic!("expected Query"),
        };

        let out = a.handle(answer_env(101, qid, "fetch_url_title"));
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "fetch-url-title"),
            other => panic!("expected Authored, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn answer_with_abort_yields_failed_reply_no_template() {
        let mut a = AgentCurious::new();
        let first = a.handle(request_env(200, "totally novel request"));
        let q = decode_seer(&first.dispatches[2]);
        let qid = match q.kind {
            SeerKind::Query { query_id, .. } => query_id,
            _ => panic!("expected Query"),
        };

        let out = a.handle(answer_env(200, qid, "abort"));
        let d = &out.dispatches[0];
        assert_eq!(d.schema, schema::REPLY);
        match decode_reply(d) {
            AuthoringReply::Failed(AuthoringError::NoTemplate { request }) => {
                assert_eq!(request, "totally novel request");
            }
            other => panic!("expected Failed(NoTemplate), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn unknown_answer_content_yields_failed_invalid() {
        let mut a = AgentCurious::new();
        let first = a.handle(request_env(300, "another novel one"));
        let q = decode_seer(&first.dispatches[2]);
        let qid = match q.kind {
            SeerKind::Query { query_id, .. } => query_id,
            _ => panic!("expected Query"),
        };

        let out = a.handle(answer_env(300, qid, "make it sing"));
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("unrecognized answer content"), "got {message}");
            }
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0, "exchange consumed even on Invalid (the convo is over)");
    }

    #[test]
    fn answer_classifier_scans_only_the_bounded_prefix() {
        assert!(matches!(parse_answer("please reverse it"), AnswerChoice::Reverse));
        let late_keyword = format!("{} reverse", "x".repeat(MAX_ANSWER_CLASSIFIER_BYTES + 1));
        assert!(
            matches!(parse_answer(&late_keyword), AnswerChoice::Unknown),
            "a choice keyword beyond the classifier cap is ignored"
        );
    }

    #[test]
    fn unknown_answer_content_error_uses_bounded_preview() {
        let mut a = AgentCurious::new();
        let first = a.handle(request_env(301, "another novel two"));
        let q = decode_seer(&first.dispatches[2]);
        let qid = match q.kind {
            SeerKind::Query { query_id, .. } => query_id,
            _ => panic!("expected Query"),
        };

        let huge_unknown = "x".repeat(MAX_ANSWER_ERROR_PREVIEW_BYTES + 4096);
        let out = a.handle(answer_env(301, qid, &huge_unknown));
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("truncated"), "got {message}");
                assert!(
                    message.len() < MAX_ANSWER_ERROR_PREVIEW_BYTES + 256,
                    "message should contain only a bounded preview; len={}",
                    message.len()
                );
                assert!(
                    !message.contains(&"x".repeat(MAX_ANSWER_ERROR_PREVIEW_BYTES + 1)),
                    "message should not echo the full oversized answer"
                );
            }
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0, "matched unknown answer still consumes the exchange");
    }

    // -------------------------------------------------------------------------------------------
    // Steer — embryo-level mid-flight intervention, on the SEER wire.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn steer_abort_drops_pending_and_emits_failed_reply() {
        let mut a = AgentCurious::new();
        let _ = a.handle(request_env(500, "uncertain"));
        assert_eq!(a.pending_len(), 1);

        let out = a.handle(steer_env(500, "abort"));
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        assert_eq!(d.schema, schema::REPLY);
        assert_eq!(d.corr, Some(500));
        match decode_reply(d) {
            AuthoringReply::Failed(AuthoringError::NoTemplate { request }) => {
                assert_eq!(request, "uncertain");
            }
            other => panic!("expected Failed(NoTemplate), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn steer_abort_with_no_pending_is_silent_no_reply() {
        let mut a = AgentCurious::new();
        let out = a.handle(steer_env(999, "abort"));
        assert!(out.dispatches.is_empty(), "no pending → no reply");
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn steer_amend_is_ignored_pending_preserved() {
        // "a creature can ignore steers and the original request-reply still
        // completes." amend/info are not honored; pending stays parked.
        let mut a = AgentCurious::new();
        let _ = a.handle(request_env(600, "ambiguous"));
        assert_eq!(a.pending_len(), 1);

        let out = a.handle(steer_env(600, "amend"));
        assert!(out.dispatches.is_empty(), "amend ignored → no reply");
        assert_eq!(a.pending_len(), 1, "amend is ignored, pending preserved");

        // The exchange can still complete normally with a valid answer.
        let query_id = 1; // we know the first allocation is id=1
        let resumed = a.handle(answer_env(600, query_id, "reverse"));
        match decode_reply(&resumed.dispatches[0]) {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
            other => panic!("expected Authored, got {other:?}"),
        }
    }

    // -------------------------------------------------------------------------------------------
    // Topic isolation — a SEER envelope on a non-authoring topic is dropped silently.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn seer_envelope_on_non_authoring_topic_is_silently_dropped() {
        let mut a = AgentCurious::new();
        // Pre-park an exchange so we can prove it's *not* consumed by a wrong-topic envelope.
        let _ = a.handle(request_env(700, "ambiguous one"));
        assert_eq!(a.pending_len(), 1);

        // A SEER Answer with the *right* corr+query_id but the *wrong* topic must be ignored
        // — the creature is bound to topic Authoring; cross-topic adjudication isn't substrate.
        let body = topics::authoring::AnswerBody { content: "reverse".into() };
        let wrong_topic = SeerEnvelope::answer(SeerTopic::Placement, 700, 1, &body);
        let out = a.handle(seer_env(700, wrong_topic));
        assert!(out.dispatches.is_empty(), "wrong-topic envelope must not emit a reply");
        assert_eq!(a.pending_len(), 1, "pending preserved across wrong-topic answer");

        // The right-topic answer still resolves the parked exchange.
        let resumed = a.handle(answer_env(700, 1, "reverse"));
        match decode_reply(&resumed.dispatches[0]) {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
            other => panic!("expected Authored, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    // -------------------------------------------------------------------------------------------
    // Defensive — pairing key enforcement.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn answer_with_mismatched_query_id_is_silently_dropped() {
        // A stale answer whose query_id doesn't match the parked exchange is ignored. The
        // exchange remains parked so the *right* answer can still resolve it. We don't even
        // emit a Failed reply — the late answerer doesn't know whether it's "their" exchange.
        let mut a = AgentCurious::new();
        let _ = a.handle(request_env(710, "first novel"));
        assert_eq!(a.pending_len(), 1);

        let out = a.handle(answer_env(710, 999, "reverse"));
        assert!(out.dispatches.is_empty(), "mismatched query_id silently dropped");
        assert_eq!(a.pending_len(), 1, "pending preserved across stale answer");

        // The right answer (query_id=1) still completes the exchange.
        let resumed = a.handle(answer_env(710, 1, "reverse"));
        match decode_reply(&resumed.dispatches[0]) {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
            other => panic!("expected Authored, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn answer_for_unknown_corr_is_silently_dropped() {
        let mut a = AgentCurious::new();
        let out = a.handle(answer_env(404, 1, "reverse"));
        assert!(out.dispatches.is_empty(), "unknown corr → no reply, no panic");
    }

    #[test]
    fn malformed_request_yields_invalid_failed_reply() {
        let mut a = AgentCurious::new();
        let mut env = request_env(800, "");
        env.payload = b"{ not json".to_vec();
        let out = a.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { .. }) => {}
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0, "malformed request never parks");
    }

    #[test]
    fn oversized_request_yields_invalid_failed_reply_and_never_parks() {
        let mut a = AgentCurious::new();
        let env = make_env(
            schema::REQUEST,
            801,
            vec![b'{'; agent_templated::MAX_AUTHORING_REQUEST_BYTES + 1],
        );
        let out = a.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("too large"), "unexpected message: {message}");
            }
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0, "oversized request never parks");
    }

    #[test]
    fn malformed_seer_envelope_yields_invalid_failed_reply() {
        // A malformed *outer* SeerEnvelope (not parseable JSON) returns a Failed reply (we
        // can't even know whether it was meant to be an Answer or a Steer). A malformed *body*
        // inside a well-formed envelope (next test) is handled separately.
        let mut a = AgentCurious::new();
        let _ = a.handle(request_env(900, "ambiguous one"));
        let mut env = answer_env(900, 1, "reverse");
        env.payload = b"not json at all".to_vec();
        let out = a.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { .. }) => {}
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        // The pending exchange should still be parked — a malformed envelope is *not* the
        // legitimate end of the conversation. Only a well-formed (corr, query_id)-matching
        // answer or a Steer{abort} consumes the pending state.
        assert_eq!(a.pending_len(), 1, "malformed envelope does not consume pending");
    }

    #[test]
    fn oversized_seer_envelope_yields_invalid_failed_reply_and_preserves_pending() {
        let mut a = AgentCurious::new();
        let _ = a.handle(request_env(905, "ambiguous one"));
        let mut env = answer_env(905, 1, "reverse");
        env.payload = vec![b'{'; seer::MAX_SEER_ENVELOPE_BYTES + 1];
        let out = a.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("too large"), "unexpected message: {message}");
            }
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 1, "oversized envelope does not consume pending");
    }

    #[test]
    fn malformed_answer_body_yields_invalid_failed_reply() {
        // The outer SeerEnvelope is well-formed, but the inner Answer body doesn't decode as
        // AnswerBody (it's missing the `content` field). Return a Failed reply; preserve the
        // parked exchange so a well-formed retry can still complete it.
        let mut a = AgentCurious::new();
        let _ = a.handle(request_env(910, "ambiguous two"));
        let bad_body = serde_json::json!({ "not_content": 42 });
        let seer = SeerEnvelope::answer(SeerTopic::Authoring, 910, 1, &bad_body);
        let out = a.handle(seer_env(910, seer));
        assert_eq!(out.dispatches.len(), 1);
        match decode_reply(&out.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { .. }) => {}
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        assert_eq!(a.pending_len(), 1, "malformed body does not consume pending");
    }

    // -------------------------------------------------------------------------------------------
    // Concurrent pending — two corr threads coexist.
    // -------------------------------------------------------------------------------------------

    #[test]
    fn two_concurrent_pending_exchanges_resolve_independently() {
        let mut a = AgentCurious::new();
        let _ = a.handle(request_env(1000, "first ambiguous"));
        let _ = a.handle(request_env(1001, "second ambiguous"));
        assert_eq!(a.pending_len(), 2);

        // Answer the second first — orderings shouldn't matter.
        let q2_id = 2; // we know allocations are sequential
        let out_b = a.handle(answer_env(1001, q2_id, "fetch_url_title"));
        match decode_reply(&out_b.dispatches[0]) {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "fetch-url-title"),
            other => panic!("expected fetch-url-title authored, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 1, "1001 resolved, 1000 still pending");

        let out_a = a.handle(answer_env(1000, 1, "reverse"));
        match decode_reply(&out_a.dispatches[0]) {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
            other => panic!("expected reverse-daemon authored, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0);
    }

    #[test]
    fn max_pending_refuses_new_consult_at_capacity_and_keeps_in_flight() {
        // Cap at 1: the first ambiguous request parks; the second is refused (not parked), and the
        // first exchange stays in flight (refuse-new, never evict-live). `0` is the explicit
        // unbounded opt-out.
        let mut a = AgentCurious::new().with_max_pending(1);
        let out1 = a.handle(request_env(2000, "first ambiguous"));
        assert_eq!(a.pending_len(), 1, "first ambiguous request parks");
        assert!(
            out1.dispatches.iter().any(|d| d.schema == schema::SEER),
            "first request emits SEER (consult)"
        );

        let out2 = a.handle(request_env(2001, "second ambiguous"));
        assert_eq!(a.pending_len(), 1, "at capacity: second request is NOT parked");
        // The refusal is a single terminal Failed(Invalid) reply, no SEER consult.
        assert_eq!(out2.dispatches.len(), 1, "refusal is one terminal reply");
        match decode_reply(&out2.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("capacity"), "refusal explains the cap: {message}");
            }
            other => panic!("expected Failed(Invalid) at capacity, got {other:?}"),
        }

        // The first exchange is still resolvable — it was never evicted.
        let resumed = a.handle(answer_env(2000, 1, "reverse"));
        match decode_reply(&resumed.dispatches[0]) {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
            other => panic!("expected the kept exchange to resolve, got {other:?}"),
        }
        assert_eq!(a.pending_len(), 0, "kept exchange resolved; table drains");
    }

    #[test]
    fn default_pending_cap_refuses_new_consult_and_zero_opt_out_is_unbounded() {
        let mut bounded = AgentCurious::new();
        for i in 0..DEFAULT_MAX_PENDING_EXCHANGES {
            let out = bounded.handle(request_env(3000 + i as u64, "ambiguous"));
            assert!(
                out.dispatches.iter().any(|d| d.schema == schema::SEER),
                "request {i} parks under the default cap"
            );
        }
        assert_eq!(bounded.pending_len(), DEFAULT_MAX_PENDING_EXCHANGES);

        let refused = bounded.handle(request_env(3999, "ambiguous"));
        assert_eq!(
            bounded.pending_len(),
            DEFAULT_MAX_PENDING_EXCHANGES,
            "default-cap refusal does not park another exchange"
        );
        match decode_reply(&refused.dispatches[0]) {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("capacity"), "refusal explains the cap: {message}");
            }
            other => panic!("expected Failed(Invalid) at default capacity, got {other:?}"),
        }

        let mut unbounded = AgentCurious::new().with_max_pending(0);
        for i in 0..=DEFAULT_MAX_PENDING_EXCHANGES {
            let out = unbounded.handle(request_env(5000 + i as u64, "ambiguous"));
            assert!(
                out.dispatches.iter().any(|d| d.schema == schema::SEER),
                "unbounded opt-out parks request {i}"
            );
        }
        assert_eq!(unbounded.pending_len(), DEFAULT_MAX_PENDING_EXCHANGES + 1);
    }
}
