//! `agent-templated` — reference `Role::AUTHORING` creature for the self-authoring loop.
//!
//! Bound to `Role::AUTHORING`, this creature takes an
//! [`AuthoringRequest`] (natural-language outcome + optional `prev_error` for retry) and replies
//! with an [`AuthoringResponse`] (source + manifest stub + cargo deps) or an [`AuthoringError`]
//! when no template matches.
//!
//! ## Why a *template-matched* agent
//!
//! What matters is the **loop** — author → build → admit → load →
//! invoke, with structured recovery on a compile error — not LLM quality. A pattern-matched
//! agent makes the loop's tests **deterministic and offline**, which is the only sane place to
//! prove the seam. A real LLM-backed agent (Claude / GPT / local) is the same shape on the same
//! socket: it consumes `AuthoringRequest`, produces `AuthoringResponse`. Swapping it in is a
//! creature swap, not a substrate change — exactly the inversion-of-control payoff.
//!
//! ## Templates
//!
//! - **reverse-string** — matches "reverse"; emits a creature that reverses its envelope payload.
//! - **reverse-critter** / **uppercase-critter** — matches "critter" (the script tier); the latter
//!   when the request also mentions "upper". Emit Rhai source built by `build-critter` (no cargo).
//! - **fetch-url-title** — matches "fetch" + "title" + "url"; emits a creature that HTTP-GETs the
//!   URL in its payload and replies with the page's `<title>` text. Uses std-only HTTP (no
//!   external deps) so a cold cargo cache doesn't dominate test time.
//! - **recovery drill** — a request whose text starts with [`DRILL_PREFIX`] and no `prev_error`
//!   returns intentionally broken Rust (proving the build creature reports a structured Compile
//!   failure); the second call with the prefix still set and a populated `prev_error` returns a
//!   fixed reverse-string creature. The prefix is private to this
//!   creature — a real LLM-backed agent ignores it as ordinary prompt text.
//!
//! No template matched ⇒ structured `AuthoringError::NoTemplate` (never a panic, never a placeholder).

use aether::{Creature, CreatureCtx, Dispatch, Envelope, Outcome};
use build_cargo::{CargoDep, ManifestStub};
use serde::{Deserialize, Serialize};
use sigil::{Capabilities, Entrypoint, NetCapability};

/// What an orchestrator (test, REPL, future planner-creature) submits to the authoring socket.
/// **Substrate-wide contract** — every creature bound to `Role::AUTHORING` consumes this; an
/// LLM-backed agent and the templated reference both speak the same shape.
///
/// ## Two fields, no test-only knobs
///
/// The contract carries no test-only flag. The broken-then-fixed recovery drill rides a string
/// convention private to the templated agent (see [`DRILL_PREFIX`]) rather than a field on the
/// shared contract, so production agents drop nothing and ignore nothing.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AuthoringRequest {
    /// Free-form natural-language outcome — what the operator/agent wants. The template matcher
    /// is keyword-based; a real LLM agent would consume the same field as-is.
    pub request: String,
    /// `Some(stderr)` on a retry — the build creature's structured failure. The agent uses this
    /// to revise. Real LLM-backed agents read the stderr substance; the templated agent uses it
    /// as the boolean "did the previous attempt fail?" for the drill transition.
    #[serde(default)]
    pub prev_error: Option<String>,
}

/// Templated-agent-internal convention: any request whose text *starts with* this prefix puts the
/// templated agent into recovery-drill mode (drill+no prev_error → broken source; drill+prev_error
/// → fixed source). The prefix is meaningless to any other AUTHORING creature — an LLM-backed
/// agent would treat it as part of the prompt and ignore the convention. This keeps a test concern
/// off the substrate's wire contract.
pub const DRILL_PREFIX: &str = "[drill]";

/// Maximum direct bus payload accepted for an [`AuthoringRequest`].
///
/// HTTP/control entry points already cap their bodies before they reach AUTHORING. This guard is
/// for direct bus envelopes addressed to `Role::AUTHORING`, including model-backed or curious
/// agents that consume this shared wire contract.
pub const MAX_AUTHORING_REQUEST_BYTES: usize = 1024 * 1024;

/// Decode an inbound authoring request with the substrate-wide request-size guard.
///
/// `agent-templated` owns the shared AUTHORING request/reply shapes, so the model-backed and
/// curious authoring creatures call this helper rather than carrying private JSON limits.
pub fn decode_authoring_request(payload: &[u8]) -> Result<AuthoringRequest, AuthoringError> {
    if payload.len() > MAX_AUTHORING_REQUEST_BYTES {
        return Err(AuthoringError::Invalid {
            message: format!(
                "authoring request payload too large: {} bytes exceeds {} byte limit",
                payload.len(),
                MAX_AUTHORING_REQUEST_BYTES
            ),
        });
    }
    serde_json::from_slice(payload).map_err(|e| AuthoringError::Invalid {
        message: format!("malformed authoring request: {e}"),
    })
}

/// What the agent emits when a template matches: enough to hand straight to the BUILD socket.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoringResponse {
    pub crate_name: String,
    pub crate_version: String,
    pub source: String,
    pub manifest_stub: ManifestStub,
    pub deps: Vec<CargoDep>,
    /// Which template fired — telemetry for the operator + a stable knob the test asserts on.
    pub template: String,
}

/// Wire-level reply type carried in the [`Envelope::payload`] when this creature is bound to
/// [`Role::AUTHORING`](aether::Role::AUTHORING) and answered via the bus.
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "reply", rename_all = "snake_case")]
// Short-lived wire message (serialized to JSON, sent on the bus); the variant-size difference is
// immaterial here.
#[allow(clippy::large_enum_variant)]
pub enum AuthoringReply {
    Authored(AuthoringResponse),
    Failed(AuthoringError),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AuthoringError {
    /// No template matched the request. A real agent might emit a tentative draft here; the
    /// templated reference is honest about its scope and reports the miss.
    NoTemplate { request: String },
    /// Wire shape was malformed.
    Invalid { message: String },
}

impl AuthoringReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Authoring as conversation, not RPC
// ─────────────────────────────────────────────────────────────────────────────────────────────
//
// AUTHORING is framed as `Request → Response`, single-shot. The bus already carries `corr`
// — nothing in the wire enforces single-shot, it's a *convention* that the SDK shape baked in.
// The exchange is a `corr`-correlated *thread* of envelopes, with the
// terminal `AuthoringReply` as the only required envelope. Around that thread the fabric reserves
// four additional schemas:
//
// - **Progress** (outbound from creature) — "I'm at stage X, ~40% done."
// - **Thought** (outbound) — observable narration of internal/external reasoning. The Loop 2
//   selection signal: a creature whose deliberation is observable is selectable by reasoning
//   quality, not just outcome.
// - **Steer** (inbound to creature) — orchestrator / human / peer butting in mid-flight with new
//   info, amendment, or abort.
// - **Query** + **Answer** (outbound + inbound) — the creature *actively seeking* external input
//   ("should I use approach A or B?" "what's the schema of this thing?"). Curiosity / alimentation
//   — without this seam the framework structurally precludes a feeding/curious authoring shape.
//
// **Reduction theorem.** Any conversation reduces to a single `AuthoringReply` by dropping the
// intermediates. The simplest creature (agent-templated) emits only the terminal reply
// and the wire shape stays minimal. Richer creatures bind to the additional
// schemas without a substrate change.
//
// **Not authoring-specific in principle.** Query/Answer in particular generalizes to a run-time
// Query/Answer at the bus level (any creature consulting any something). Here the schemas are
// scoped to authoring (under the AUTHORING role's `corr`-correlated thread).

/// Observable progress within an authoring exchange. Outbound from the
/// authoring creature, addressed to the originating orchestrator (via `reply_to` on the original
/// request), correlated by `corr` to the request being worked on.
///
/// Fields are optional past `stage`: a creature that knows its progress can fill `fraction`; one
/// that doesn't measure leaves it `None`. `note` is freeform narration the orchestrator can
/// surface verbatim. **Not required**: a simple creature never emits Progress and the loop stays
/// minimal.
///
/// Schema: `"authoring_progress"`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoringProgress {
    pub corr: u64,
    pub stage: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fraction: Option<f32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Observable narration of the creature's reasoning. Outbound from the
/// authoring creature; `channel` distinguishes deliberation the operator may consider internal
/// (`"internal"`) from prose the creature wants to surface as external content (`"external"`).
///
/// Making deliberation observable is the Loop 2 selection signal: a creature whose reasoning is
/// visible is selectable by reasoning quality, not just by outcome — the immune loop's audit
/// material. **Not required**: a simple creature never emits Thought.
///
/// Schema: `"authoring_thought"`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoringThought {
    pub corr: u64,
    pub channel: String,
    pub content: String,
}

/// Inbound mid-flight intervention from an orchestrator (human or creature)
/// into a live authoring exchange. `kind` discriminates the operator's intent: `"amend"`
/// (additional constraint / refinement), `"abort"` (stop work), `"info"` (here's something the
/// creature didn't have). `payload` is opaque to the substrate — the creature interprets it per
/// its `kind`.
///
/// Whether (and how) a creature acts on a steer is its model; the fabric just delivers. **Not
/// required**: a creature can ignore steers and the original request-reply still completes.
///
/// Schema: `"authoring_steer"`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoringSteer {
    pub corr: u64,
    pub kind: String,
    pub payload: serde_json::Value,
}

/// **Curiosity / alimentation seam.** Outbound from the authoring creature: the
/// creature *actively seeking* external input ("should I use approach A or B?" "what's the schema
/// of this thing?"). Addressed by default to the originating orchestrator (via `reply_to` of the
/// request that started the exchange), but the creature is free to address it to a `Role`,
/// `Topic`, or any other address — that's the creature's model.
///
/// `query_id` is local to this exchange's `corr` thread (a creature may have several outstanding
/// queries; `query_id` lets it match each [`AuthoringAnswer`] to the right one). `deadline_ms` is
/// advisory — the fabric does not enforce timeouts (time is injected policy, never fabric); a
/// creature awaiting an answer past its deadline decides for itself how to proceed.
///
/// Schema: `"authoring_query"`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoringQuery {
    pub corr: u64,
    pub query_id: u64,
    pub question: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_ms: Option<u64>,
}

/// Inbound reply to an [`AuthoringQuery`], matched by `(corr, query_id)`.
/// `content` is the answerer's prose; richer encodings (a structured choice, a tool result, an
/// embedded artifact) ride as a stringified JSON to keep the wire small. The fabric
/// doesn't define what a "good" answer is.
///
/// Schema: `"authoring_answer"`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AuthoringAnswer {
    pub corr: u64,
    pub query_id: u64,
    pub content: String,
}

/// The creature. Stateless — every decision derives from the request itself, which keeps the agent
/// safe to share across worker threads and trivially replayable in tests.
#[derive(Default)]
pub struct AgentTemplated;

impl AgentTemplated {
    pub fn new() -> Self {
        AgentTemplated
    }

    /// Direct (non-bus) author — convenience for tests and the orchestrator path.
    pub fn author(&self, req: &AuthoringRequest) -> Result<AuthoringResponse, AuthoringError> {
        // Templated-agent-internal recovery-drill mode: any request that *starts with*
        // `DRILL_PREFIX` engages the broken→fixed transition. The prefix is private to this
        // creature — other AUTHORING bindees won't recognize it (and they don't need to;
        // recovery-drill is a test convention, not a substrate primitive).
        let drill_body = req.request.strip_prefix(DRILL_PREFIX).map(|rest| rest.trim_start());
        if drill_body.is_some() {
            return Ok(if req.prev_error.is_some() {
                template_reverse_string("recovery-drill-fixed")
            } else {
                template_recovery_drill_broken()
            });
        }
        let lower = req.request.to_ascii_lowercase();
        // A critter (script tier) request — checked before the daemon "reverse" template so a
        // request like "reverse a string as a critter" authors the Rhai script, not the native
        // daemon. The caller routes a critter response to `build-critter` (no cargo), not build-cargo.
        if lower.contains("critter") {
            // Within the critter tier, a request mentioning "upper(case)" authors the uppercase
            // template; everything else falls back to the reverse critter.
            if lower.contains("upper") {
                return Ok(template_uppercase_critter());
            }
            return Ok(template_reverse_critter());
        }
        if lower.contains("reverse") {
            return Ok(template_reverse_string("reverse-daemon"));
        }
        if lower.contains("fetch") && lower.contains("title") && lower.contains("url") {
            return Ok(template_fetch_url_title());
        }
        Err(AuthoringError::NoTemplate { request: req.request.clone() })
    }
}

impl Creature for AgentTemplated {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reply = match decode_authoring_request(&env.payload) {
            Ok(req) => match self.author(&req) {
                Ok(resp) => AuthoringReply::Authored(resp),
                Err(e) => AuthoringReply::Failed(e),
            },
            Err(e) => AuthoringReply::Failed(e),
        };
        let payload = reply.to_bytes();
        Outcome::send(Dispatch::reply_to_env(&env, payload).with_schema("authoring.reply"))
    }
}

// ---------------------------------------------------------------------------------------------
// Templates. Each is a self-contained `&'static str` source so the agent has zero external assets.
// The source must compile against `forge` alone (no extra deps unless the template declares
// them in `deps`), and produce a creature with a `handle(Envelope) -> Outcome` that matches the
// stated outcome on the corresponding test fixture.
// ---------------------------------------------------------------------------------------------

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

// The critter (script tier) template: Rhai source, not Rust. A critter ships as source text and is
// authored without cargo — `build-critter` validates + signs it. `handle(env)` returns a Blob that
// the critter engine turns into a reply; this one reverses the inbound payload byte-for-byte.
const REVERSE_CRITTER_SOURCE: &str = r#"// reverse-critter — reverses its envelope payload (script tier).
fn handle(env) {
    let src = env.payload;
    let out = blob();
    let i = src.len();
    while i > 0 {
        i -= 1;
        out.push(src[i]);
    }
    out
}
"#;

fn template_reverse_critter() -> AuthoringResponse {
    AuthoringResponse {
        crate_name: "reverse-critter".to_string(),
        crate_version: "0.1.0".to_string(),
        source: REVERSE_CRITTER_SOURCE.to_string(),
        manifest_stub: ManifestStub {
            name: "reverse-critter".to_string(),
            version: "0.1.0".to_string(),
            entrypoints: vec![Entrypoint {
                name: "handle".to_string(),
                signature: "(env) -> reply".to_string(),
            }],
            capabilities: Capabilities::default(),
            provides: vec![],
        },
        deps: vec![],
        template: "reverse-critter".to_string(),
    }
}

// The uppercase critter template (script tier): ASCII-uppercases the payload byte-for-byte. Pure
// blob arithmetic — no Blob→String conversion (the critter engine has none) — so it round-trips any
// bytes. Authored when the request mentions "upper" (e.g. `author --critter "uppercase the message"`).
const UPPERCASE_CRITTER_SOURCE: &str = r#"// uppercase-critter — ASCII-uppercases its envelope payload (script tier).
fn handle(env) {
    let src = env.payload;
    let out = blob();
    let i = 0;
    while i < src.len() {
        let b = src[i];
        // 'a'..='z' (97..=122) → subtract 32 to reach 'A'..='Z'; all other bytes pass through.
        if b >= 97 && b <= 122 {
            out.push(b - 32);
        } else {
            out.push(b);
        }
        i += 1;
    }
    out
}
"#;

fn template_uppercase_critter() -> AuthoringResponse {
    AuthoringResponse {
        crate_name: "uppercase-critter".to_string(),
        crate_version: "0.1.0".to_string(),
        source: UPPERCASE_CRITTER_SOURCE.to_string(),
        manifest_stub: ManifestStub {
            name: "uppercase-critter".to_string(),
            version: "0.1.0".to_string(),
            entrypoints: vec![Entrypoint {
                name: "handle".to_string(),
                signature: "(env) -> reply".to_string(),
            }],
            capabilities: Capabilities::default(),
            provides: vec![],
        },
        deps: vec![],
        template: "uppercase-critter".to_string(),
    }
}

// std-only HTTP. Avoids pulling `ureq` (and `rustls` etc.) into the cargo cache for the test —
// adds tens of seconds of cold-cargo time per fresh build. The request is HTTP/1.0 to a single
// localhost host; a real fetch-url agent would obviously want `ureq` or `reqwest`. The loop is
// what's under test here, not the http client's robustness.
const FETCH_URL_TITLE_SOURCE: &str = r#"use forge::prelude::*;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

const MAX_URL_BYTES: usize = 8 * 1024;
const MAX_HTTP_RESPONSE_BYTES: usize = 1024 * 1024;

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
        let url = match std::str::from_utf8(&env.payload) {
            Ok(s) => s.trim().to_string(),
            Err(_) => return Outcome::reply(&env, b"<invalid utf8>".to_vec()),
        };
        let title = match fetch_title(&url) {
            Ok(t) => t,
            Err(e) => format!("<error: {}>", e),
        };
        Outcome::reply(&env, title.into_bytes())
    }
}

fn fetch_title(url: &str) -> Result<String, String> {
    let parsed = parse_url(url).ok_or_else(|| "bad url".to_string())?;
    let mut stream = TcpStream::connect((parsed.host.as_str(), parsed.port))
        .map_err(|e| e.to_string())?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    let req = format!(
        "GET {} HTTP/1.0\r\nHost: {}\r\nConnection: close\r\n\r\n",
        parsed.path, parsed.host
    );
    stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
    let mut buf = Vec::new();
    let mut limited = stream.take(MAX_HTTP_RESPONSE_BYTES as u64 + 1);
    limited.read_to_end(&mut buf).map_err(|e| e.to_string())?;
    if buf.len() > MAX_HTTP_RESPONSE_BYTES {
        return Err(format!(
            "response too large: exceeds {} byte limit",
            MAX_HTTP_RESPONSE_BYTES
        ));
    }
    let s = String::from_utf8_lossy(&buf);
    let body_start = s.find("\r\n\r\n").map(|i| i + 4).unwrap_or(0);
    let body = &s[body_start..];
    let lower = body.to_ascii_lowercase();
    let open = lower.find("<title>").ok_or_else(|| "no <title>".to_string())?;
    let after = &body[open + 7..];
    let lower_after = &lower[open + 7..];
    let close = lower_after.find("</title>").ok_or_else(|| "no </title>".to_string())?;
    Ok(after[..close].trim().to_string())
}

struct ParsedUrl { host: String, port: u16, path: String }

fn parse_url(url: &str) -> Option<ParsedUrl> {
    let s = url.strip_prefix("http://")?;
    let (host_port, path_rest) = match s.split_once('/') {
        Some((h, p)) => (h, format!("/{}", p)),
        None => (s, "/".to_string()),
    };
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().ok()?),
        None => (host_port.to_string(), 80u16),
    };
    Some(ParsedUrl { host, port, path: path_rest })
}

forge::declare_creature!(FetchUrlTitle);
"#;

fn template_fetch_url_title() -> AuthoringResponse {
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
            // Outbound net is *declared* here; the engine enforces it. The manifest is the sole
            // metadata source (R6), so the policy seeing this can already decide whether to
            // admit on a strict-net node.
            capabilities: Capabilities { net: NetCapability::Outbound, ..Default::default() },
            provides: vec![],
        },
        deps: vec![],
        template: "fetch-url-title".to_string(),
    }
}

// Intentionally invalid Rust — a stray identifier outside any item. Cargo reports a clear
// "expected item" error from rustc, which the build creature returns as `BuildErrorKind::Compile`
// with the stderr substance the agent reads on retry. The drill's second call returns the working
// reverse template (see `author`), proving the retry-with-prev_error path makes progress.
const RECOVERY_DRILL_BROKEN_SOURCE: &str = r#"
deliberately_broken_for_m3_recovery_drill_no_item_here
"#;

fn template_recovery_drill_broken() -> AuthoringResponse {
    AuthoringResponse {
        crate_name: "reverse-daemon".to_string(),
        crate_version: "0.1.0".to_string(),
        source: RECOVERY_DRILL_BROKEN_SOURCE.to_string(),
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
        template: "recovery-drill-broken".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_reverse_template_on_reverse_in_the_request() {
        let r = AgentTemplated::new()
            .author(&AuthoringRequest {
                request: "please write a daemon that REVERSES a string".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.crate_name, "reverse-daemon");
        assert_eq!(r.template, "reverse-daemon");
        assert!(r.source.contains("ReverseDaemon"));
    }

    #[test]
    fn authored_reverse_critter_template_on_critter_keyword() {
        let r = AgentTemplated::new()
            .author(&AuthoringRequest {
                request: "reverse the bytes critter".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.crate_name, "reverse-critter");
        assert_eq!(r.template, "reverse-critter");
        assert!(r.source.contains("fn handle(env)"));
    }

    #[test]
    fn authored_uppercase_critter_template_on_upper_keyword() {
        // "critter" routes to the script tier; "upper" selects the uppercase template over reverse.
        let r = AgentTemplated::new()
            .author(&AuthoringRequest {
                request: "uppercase the message critter".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.crate_name, "uppercase-critter");
        assert_eq!(r.template, "uppercase-critter");
        assert!(r.source.contains("fn handle(env)"));
        assert!(
            r.source.contains("b - 32"),
            "uppercase logic should subtract 32 from lowercase bytes"
        );
    }

    #[test]
    fn matches_fetch_url_title_on_combined_keywords() {
        let r = AgentTemplated::new()
            .author(&AuthoringRequest {
                request: "fetch the title from a URL".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(r.crate_name, "fetch-url-title");
        assert_eq!(r.template, "fetch-url-title");
        assert!(r.source.contains("fetch_title"));
    }

    #[test]
    fn fetch_url_title_template_caps_response_buffering() {
        let r = AgentTemplated::new()
            .author(&AuthoringRequest {
                request: "fetch the title from a URL".into(),
                ..Default::default()
            })
            .unwrap();
        assert!(r.source.contains("const MAX_HTTP_RESPONSE_BYTES"));
        assert!(r.source.contains("stream.take(MAX_HTTP_RESPONSE_BYTES as u64 + 1)"));
        assert!(r.source.contains("response too large"));
        assert!(r.source.contains("const MAX_URL_BYTES"));
        assert!(r.source.contains("url too large"));
    }

    #[test]
    fn unmatched_request_yields_no_template_error_not_panic() {
        let e = AgentTemplated::new()
            .author(&AuthoringRequest {
                request: "compute the LZ77 entropy of an mp3 stream".into(),
                ..Default::default()
            })
            .unwrap_err();
        match e {
            AuthoringError::NoTemplate { request } => assert!(request.contains("LZ77")),
            other => panic!("expected NoTemplate, got {other:?}"),
        }
    }

    #[test]
    fn recovery_drill_broken_first_then_fixed_second() {
        let a = AgentTemplated::new();
        // Drill prefix + no prev_error → broken source. The prefix is private to this creature;
        // a real LLM-backed authoring agent would just see it as part of the prompt and ignore it.
        let first = a
            .author(&AuthoringRequest {
                request: format!("{DRILL_PREFIX} reverse a string"),
                prev_error: None,
            })
            .unwrap();
        assert_eq!(first.template, "recovery-drill-broken");
        assert!(first.source.contains("deliberately_broken"));
        // Drill prefix + prev_error → fixed source (uses the reverse template).
        let second = a
            .author(&AuthoringRequest {
                request: format!("{DRILL_PREFIX} reverse a string"),
                prev_error: Some("error[E0601]: expected item, found ...".into()),
            })
            .unwrap();
        assert_eq!(second.template, "recovery-drill-fixed");
        assert!(second.source.contains("ReverseDaemon"));
    }

    #[test]
    fn drill_prefix_is_required_to_engage_drill_mode() {
        // Without the prefix, the same text follows ordinary keyword matching — the reverse
        // template, not the broken-source drill. This is the bedrock guarantee that production
        // requests can't accidentally trigger a drill.
        let a = AgentTemplated::new();
        let r = a
            .author(&AuthoringRequest { request: "reverse a string".into(), prev_error: None })
            .unwrap();
        assert_eq!(r.template, "reverse-daemon", "no prefix → no drill");
    }

    #[test]
    fn malformed_bus_request_yields_invalid_reply_not_panic() {
        use aether::{Address, CreatureId, Header};
        let mut a = AgentTemplated::new();
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "".into(),
            },
            payload: b"{ not json".to_vec(),
        };
        let out = a.handle(env);
        let r: AuthoringReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        assert!(
            matches!(r, AuthoringReply::Failed(AuthoringError::Invalid { .. })),
            "expected Invalid Failed reply, got {r:?}"
        );
    }

    #[test]
    fn oversized_bus_request_yields_invalid_reply_before_json_parse() {
        use aether::{Address, CreatureId, Header};
        let mut a = AgentTemplated::new();
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "".into(),
            },
            payload: vec![b'{'; MAX_AUTHORING_REQUEST_BYTES + 1],
        };
        let out = a.handle(env);
        let r: AuthoringReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match r {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("too large"), "unexpected message: {message}");
            }
            other => panic!("expected Invalid Failed reply, got {other:?}"),
        }
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────
    // Wire roundtrip for the five authoring conversation schemas.
    // The agent-templated creature itself emits only AuthoringReply.
    // These tests lock the wire so a downstream creature that binds to the richer surface gets a
    // stable shape, and a future migration breaks here first.
    // ─────────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn authoring_progress_roundtrips_with_and_without_optional_fields() {
        let full = AuthoringProgress {
            corr: 42,
            stage: "compiling".into(),
            fraction: Some(0.4),
            note: Some("crate graph resolved".into()),
        };
        let bytes = serde_json::to_vec(&full).unwrap();
        let back: AuthoringProgress = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.corr, 42);
        assert_eq!(back.stage, "compiling");
        assert_eq!(back.fraction, Some(0.4));
        assert_eq!(back.note.as_deref(), Some("crate graph resolved"));

        let minimal =
            AuthoringProgress { corr: 7, stage: "started".into(), fraction: None, note: None };
        let bytes = serde_json::to_vec(&minimal).unwrap();
        // skip_serializing_if = Option::is_none → the JSON should not even mention the absent fields
        let json = String::from_utf8(bytes.clone()).unwrap();
        assert!(!json.contains("fraction"));
        assert!(!json.contains("note"));
        let back: AuthoringProgress = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.corr, 7);
        assert!(back.fraction.is_none() && back.note.is_none());
    }

    #[test]
    fn authoring_thought_roundtrips_for_internal_and_external_channels() {
        for channel in ["internal", "external"] {
            let t = AuthoringThought {
                corr: 99,
                channel: channel.into(),
                content: format!("{} reasoning", channel),
            };
            let bytes = serde_json::to_vec(&t).unwrap();
            let back: AuthoringThought = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(back.channel, channel);
            assert_eq!(back.content, format!("{} reasoning", channel));
        }
    }

    #[test]
    fn authoring_steer_roundtrips_with_opaque_payload() {
        let s = AuthoringSteer {
            corr: 1,
            kind: "amend".into(),
            payload: serde_json::json!({ "add_constraint": "no panics" }),
        };
        let bytes = serde_json::to_vec(&s).unwrap();
        let back: AuthoringSteer = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.kind, "amend");
        assert_eq!(back.payload["add_constraint"], "no panics");
    }

    #[test]
    fn authoring_query_and_answer_roundtrip_with_matching_query_id() {
        let q = AuthoringQuery {
            corr: 5,
            query_id: 17,
            question: "use approach A or B?".into(),
            options: Some(vec!["A".into(), "B".into()]),
            deadline_ms: Some(5_000),
        };
        let q_bytes = serde_json::to_vec(&q).unwrap();
        let q_back: AuthoringQuery = serde_json::from_slice(&q_bytes).unwrap();
        assert_eq!(q_back.query_id, 17);
        assert_eq!(q_back.options.as_deref(), Some(["A".to_string(), "B".to_string()].as_slice()));

        let a = AuthoringAnswer { corr: 5, query_id: 17, content: "B".into() };
        let bytes = serde_json::to_vec(&a).unwrap();
        let a_back: AuthoringAnswer = serde_json::from_slice(&bytes).unwrap();
        // The pairing key — (corr, query_id) — survives the wire intact.
        assert_eq!((a_back.corr, a_back.query_id), (q_back.corr, q_back.query_id));
        assert_eq!(a_back.content, "B");

        // Minimal-shape query (no options, no deadline) elides the optional fields from the wire.
        let minimal = AuthoringQuery {
            corr: 5,
            query_id: 18,
            question: "open-ended?".into(),
            options: None,
            deadline_ms: None,
        };
        let json = String::from_utf8(serde_json::to_vec(&minimal).unwrap()).unwrap();
        assert!(!json.contains("options"), "absent options must not appear: {json}");
        assert!(!json.contains("deadline_ms"), "absent deadline_ms must not appear: {json}");
    }
}
