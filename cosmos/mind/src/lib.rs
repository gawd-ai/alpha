//! `mind` — the injected **model seam** for the Alpha substrate.
//!
//! This crate carries the seam where a real model is *injected* into the fabric: the [`Model`] trait
//! plus its request/reply types. It is the literal embodiment of the champion line **"ASI is the
//! fabric, not the model."** — the substrate ships the socket; a Claude / GPT / local model (and, in
//! time, a vision or other model) plugs into it through this trait.
//!
//! ## Why a leaf crate (not a module inside `agent-mind`)
//!
//! Three consumers need the model seam: the model-backed author (`agent-mind`), the Bestiary
//! curator, and the off-drain dialogue peer (`DialogueMind` in `dialogue-responder`). The Bestiary
//! contract crate must depend only on leaf/contract crates and **never** on a creature crate. A shared
//! [`Model`] living inside `agent-mind` would force the Bestiary and dialogue peer to depend on that
//! creature to reach it — a contract → creature edge in the former case. A leaf crate is the only
//! shape that serves all three cleanly. This crate therefore depends on nothing from the substrate.
//!
//! ## Models
//!
//! - `OpenAiModel` (feature `openai`) — POSTs `chat/completions` to any OpenAI-compatible server:
//!   api.openai.com over TLS, or a local Ollama / LM-Studio at `http://localhost:11434/v1`.
//!   Constructed from a [`ModelConfig`] supplied by the composition root — **this crate never reads
//!   the environment** (model selection is the operator's, per node instance).
//! - [`FakeModel`] (zero-dep) — canned, substring-keyed responses; proves the author loop (including
//!   the compile-error retry) hermetically, with no network.
//! - [`SlowModel`] (zero-dep) — [`complete`](Model::complete) blocks until explicitly released: the
//!   instrument for the off-drain-worker shutdown/join test.
//!
//! `complete` is **blocking by contract** — a worker thread owns the wait (the author runs the call
//! off the kernel drain thread).

use serde::{Deserialize, Serialize};
#[cfg(feature = "openai")]
use std::io::Read;
use std::time::Duration;

/// A marker the prompt builder writes into the user prompt on a retry (when `prev_error` is set),
/// and the one [`FakeModel`] keys on to switch from broken to fixed source. Defined here so the two
/// sites (the prompt builder in `agent-mind`, the fake model here) never drift.
pub const RETRY_MARKER: &str = "PREVIOUS COMPILE ERROR";

/// A marker the *critter-tier* system prompt embeds, and the one [`FakeModel`] keys on to return a
/// Rhai critter instead of a native daemon. Defined here so the prompt builder (in `agent-mind`) and
/// the fake model never drift on which tier was requested.
pub const CRITTER_TIER_MARKER: &str = "CRITTER-TIER";

/// A marker the typed-Function critter prompt embeds. It is checked before the broader
/// [`CRITTER_TIER_MARKER`] so [`FakeModel`] can exercise the exact typed wire contract while the
/// existing critter fake remains unchanged.
pub const TYPED_FUNCTION_CRITTER_MARKER: &str = "TYPED-FUNCTION-CRITTER";

/// A marker for the one audited typed-Function native profile. Native code shares the host process,
/// so this selects a byte-exact trusted-by-admission fixture rather than general model-authored
/// Rust. Checked before the generic daemon response in [`FakeModel`].
pub const TYPED_FUNCTION_DAEMON_MARKER: &str = "TYPED-FUNCTION-DAEMON";

/// A marker for the one audited typed-Function WASM profile. The Beast uses the existing
/// no-import `memory + alloc + handle` ABI: proof, route, and Function identity verification stay
/// in the host adapter, while the guest sees and returns only application JSON.
pub const TYPED_FUNCTION_BEAST_MARKER: &str = "TYPED-FUNCTION-BEAST";

/// What an author/curator hands the model. Plain data — assembled on the drain thread, then moved to
/// a worker that performs the (blocking) call.
#[derive(Debug, Clone)]
pub struct Prompt {
    pub system_prompt: String,
    pub user_prompt: String,
    pub max_tokens: u32,
    pub temperature: f32,
}

/// Where a model lives and how to reach it — **plain data**, supplied by the composition root (the
/// operator surface), never read from the environment by this crate. Carrying it as a value is what
/// lets a node bind different models per instance (and, later, per realm / per sanctum) instead of a
/// single process-global.
#[derive(Debug, Clone)]
pub struct ModelConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
}

/// Token accounting, when the model reports it (observability — see the author's threat model).
/// Additive/optional on [`Completion`]: `OpenAiModel` fills it; the fakes leave it `None`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenUsage {
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Provider-reported receipt metadata for one model call.
///
/// These fields improve traceability but are not cryptographic proof of which model weights
/// produced a completion: an OpenAI-compatible endpoint controls every value. Evidence consumers
/// must label them provider-reported and anchor trust in the configured endpoint plus their own
/// signed run record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProviderReceipt {
    /// Response-object id reported in the JSON body.
    pub response_id: Option<String>,
    /// Request id reported in the HTTP response headers, when the endpoint supplies one.
    pub request_id: Option<String>,
    /// Model id explicitly reported in the response body (never a client-side fallback).
    pub reported_model: Option<String>,
    /// First choice's terminal reason, when present.
    pub finish_reason: Option<String>,
    /// Whether the client explicitly requested provider-side storage. Alpha's stock adapter always
    /// sends `store: false`; retaining the value makes that posture evidence-visible.
    pub store_requested: bool,
}

/// What the model returns. `content` is the raw completion text the consumer parses; `model` is the
/// best available model label (reported value, falling back to the configured request label for
/// compatibility); `usage` and `provider` are optional telemetry.
#[derive(Debug, Clone)]
pub struct Completion {
    pub content: String,
    pub model: String,
    pub usage: Option<TokenUsage>,
    pub provider: Option<ProviderReceipt>,
}

/// A model call failure. Carried as a structured error so the consumer can branch (and so the author
/// maps it to a structured `AuthoringError::Invalid` rather than panicking).
#[derive(Debug, Clone)]
pub enum ModelError {
    /// Connect / read / DNS / TLS failure — the request never produced an HTTP status.
    Transport(String),
    /// The server returned a non-2xx status; `body` is the (truncated) response text. It may contain
    /// provider-reflected prompt or credential material, so [`Display`](std::fmt::Display) never
    /// includes it. Callers must treat direct field access and `Debug` output as sensitive.
    Http { status: u16, body: String },
    /// The response was received but could not be decoded into the expected shape.
    Decode(String),
    /// Misconfiguration (e.g. an unusable base URL).
    Config(String),
}

impl std::fmt::Display for ModelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModelError::Transport(m) => write!(f, "model transport error: {m}"),
            ModelError::Http { status, .. } => {
                write!(f, "model http {status} (response body withheld)")
            }
            ModelError::Decode(m) => write!(f, "model decode error: {m}"),
            ModelError::Config(m) => write!(f, "model config error: {m}"),
        }
    }
}

impl std::error::Error for ModelError {}

/// The injected model seam. The fabric ships this trait; a real model is bound through it.
///
/// `complete` is **blocking** — the consumer is responsible for running it off any latency-sensitive
/// thread (the author runs it on a dedicated worker, never the kernel drain thread).
pub trait Model: Send + Sync {
    fn complete(&self, req: Prompt) -> Result<Completion, ModelError>;
    /// A short human/telemetry label for the bound model (used in the author's structured log line).
    fn describe(&self) -> String;
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// FakeModel — hermetic, zero-dep. Proves the author loop offline.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// How a [`FakeModel`] responds, independent of the prompt's substance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeMode {
    /// Always return a valid reverse-daemon (the happy path).
    AlwaysGood,
    /// Return intentionally-broken source until the prompt carries [`RETRY_MARKER`], then the fixed
    /// source — proves the compile-error → `prev_error` → re-author retry loop with no network.
    BrokenThenFixed,
    /// Always fail with a transport error — proves a model error becomes a structured `Failed`
    /// reply and the node survives.
    AlwaysError,
}

/// A canned, network-free [`Model`]. The response is the **two-fenced-block** contract a real model
/// is asked to produce (a ```rust source block + a ```json manifest-stub block).
pub struct FakeModel {
    mode: FakeMode,
    model: String,
}

impl FakeModel {
    pub fn new(mode: FakeMode) -> Self {
        FakeModel { mode, model: "fake-model".to_string() }
    }
    /// Always returns a valid reverse-daemon.
    pub fn always_good() -> Self {
        FakeModel::new(FakeMode::AlwaysGood)
    }
    /// Broken source first, fixed source once the prompt carries [`RETRY_MARKER`].
    pub fn broken_then_fixed() -> Self {
        FakeModel::new(FakeMode::BrokenThenFixed)
    }
    /// Always errors.
    pub fn erroring() -> Self {
        FakeModel::new(FakeMode::AlwaysError)
    }
}

impl Model for FakeModel {
    fn complete(&self, req: Prompt) -> Result<Completion, ModelError> {
        // The fake mirrors a real model: it answers in the tier the (critter vs daemon) system
        // prompt asked for, so the hermetic loop covers both build paths.
        let typed_function_beast = req.system_prompt.contains(TYPED_FUNCTION_BEAST_MARKER);
        let typed_function_daemon = req.system_prompt.contains(TYPED_FUNCTION_DAEMON_MARKER);
        let typed_function_critter = req.system_prompt.contains(TYPED_FUNCTION_CRITTER_MARKER);
        let critter = req.system_prompt.contains(CRITTER_TIER_MARKER);
        let good = if typed_function_beast {
            GOOD_TYPED_FUNCTION_BEAST_RESPONSE
        } else if typed_function_daemon {
            GOOD_TYPED_FUNCTION_DAEMON_RESPONSE
        } else if typed_function_critter {
            GOOD_TYPED_FUNCTION_CRITTER_RESPONSE
        } else if critter {
            GOOD_CRITTER_RESPONSE
        } else {
            GOOD_REVERSE_RESPONSE
        };
        let broken = if typed_function_beast {
            BROKEN_TYPED_FUNCTION_BEAST_RESPONSE
        } else if typed_function_daemon {
            BROKEN_TYPED_FUNCTION_DAEMON_RESPONSE
        } else if typed_function_critter {
            BROKEN_TYPED_FUNCTION_CRITTER_RESPONSE
        } else if critter {
            BROKEN_CRITTER_RESPONSE
        } else {
            BROKEN_REVERSE_RESPONSE
        };
        let content = match self.mode {
            FakeMode::AlwaysGood => good,
            FakeMode::AlwaysError => {
                return Err(ModelError::Transport("simulated model failure".to_string()))
            }
            FakeMode::BrokenThenFixed => {
                if req.user_prompt.contains(RETRY_MARKER) {
                    good
                } else {
                    broken
                }
            }
        };
        Ok(Completion {
            content: content.to_string(),
            model: self.model.clone(),
            usage: None,
            provider: None,
        })
    }

    fn describe(&self) -> String {
        self.model.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// SlowModel — blocks until released. The instrument for the off-drain shutdown/join test.
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// A [`Model`] whose [`complete`](Model::complete) blocks until [`release`](Self::release) is called,
/// with observable enter/finish flags. Lets a test drive a worker that is *provably* still in-flight
/// and assert the author's best-effort shutdown contract.
pub struct SlowModel {
    gate: std::sync::Mutex<bool>,
    cv: std::sync::Condvar,
    entered: std::sync::atomic::AtomicBool,
    finished: std::sync::atomic::AtomicBool,
    model: String,
}

impl SlowModel {
    pub fn new() -> Self {
        SlowModel {
            gate: std::sync::Mutex::new(false),
            cv: std::sync::Condvar::new(),
            entered: std::sync::atomic::AtomicBool::new(false),
            finished: std::sync::atomic::AtomicBool::new(false),
            model: "slow-model".to_string(),
        }
    }
    /// Unblock the in-flight (or next) `complete` call.
    pub fn release(&self) {
        let mut g = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        *g = true;
        self.cv.notify_all();
    }
    /// `true` once a `complete` call has entered and started waiting.
    pub fn has_entered(&self) -> bool {
        self.entered.load(std::sync::atomic::Ordering::SeqCst)
    }
    /// `true` once a `complete` call has returned (the worker is about to exit).
    pub fn has_finished(&self) -> bool {
        self.finished.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl Default for SlowModel {
    fn default() -> Self {
        SlowModel::new()
    }
}

impl Model for SlowModel {
    fn complete(&self, _req: Prompt) -> Result<Completion, ModelError> {
        self.entered.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut g = self.gate.lock().unwrap_or_else(|p| p.into_inner());
        while !*g {
            g = self.cv.wait(g).unwrap_or_else(|p| p.into_inner());
        }
        self.finished.store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(Completion {
            content: GOOD_REVERSE_RESPONSE.to_string(),
            model: self.model.clone(),
            usage: None,
            provider: None,
        })
    }

    fn describe(&self) -> String {
        self.model.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// OpenAiModel — the real HTTP path (feature `openai`).
// ─────────────────────────────────────────────────────────────────────────────────────────────

/// Maximum successful HTTP response bytes read by the OpenAI-compatible model client.
#[cfg(feature = "openai")]
pub const MAX_OPENAI_HTTP_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
/// Maximum non-2xx HTTP response body bytes retained in [`ModelError::Http`].
#[cfg(feature = "openai")]
pub const MAX_OPENAI_HTTP_ERROR_BODY_BYTES: usize = 4096;

/// An OpenAI-compatible chat-completions model. Covers api.openai.com (TLS) and local
/// OpenAI-compatible servers (Ollama / LM-Studio) — `Authorization: Bearer` is sent only when an
/// API key is present, so a keyless local server works unchanged. Built from a [`ModelConfig`] the
/// composition root supplies (no environment is read here).
#[cfg(feature = "openai")]
pub struct OpenAiModel {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub timeout: Duration,
}

#[cfg(feature = "openai")]
impl OpenAiModel {
    /// Construct from an explicit [`ModelConfig`]. Infallible — a missing key just means no
    /// `Authorization` header (the local-server case).
    pub fn new(cfg: ModelConfig) -> Self {
        OpenAiModel {
            base_url: cfg.base_url,
            model: cfg.model,
            api_key: cfg.api_key,
            timeout: cfg.timeout,
        }
    }
}

#[cfg(feature = "openai")]
impl Model for OpenAiModel {
    fn complete(&self, req: Prompt) -> Result<Completion, ModelError> {
        validate_model_endpoint(&self.base_url, self.api_key.is_some())?;
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": req.system_prompt },
                { "role": "user", "content": req.user_prompt },
            ],
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
            // Make provider-side retention an explicit operator-visible choice. The stock adapter
            // never opts into storage; Alpha persists its own bounded evidence bundle instead.
            "store": false,
        });
        let body = serde_json::to_string(&body).map_err(|e| ModelError::Decode(e.to_string()))?;

        // Real models take seconds, but one call still needs an overall deadline: connect/read-only
        // limits permit an indefinitely blocked write or trickling body. The author's shutdown is
        // best-effort and polling-bounded rather than clamping this below the configured model call
        // budget. A separate smaller connect cap still detects a dead host quickly.
        let agent = ureq::AgentBuilder::new()
            // Evidence names the configured origin. Refuse redirects so a response can never be
            // attributed to that origin after actually coming from another endpoint.
            .redirects(0)
            .timeout(self.timeout)
            .timeout_connect(Duration::from_secs(10).min(self.timeout))
            .timeout_read(self.timeout)
            .build();
        let mut request = agent.post(&url).set("content-type", "application/json");
        if let Some(key) = &self.api_key {
            request = request.set("authorization", &format!("Bearer {key}"));
        }
        let resp = match request.send_string(&body) {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let text = read_error_body_bounded(r);
                return Err(ModelError::Http { status: code, body: text });
            }
            Err(e) => return Err(ModelError::Transport(e.to_string())),
        };
        let request_id = resp.header("x-request-id").map(str::to_owned);
        let text = read_success_body_bounded(resp)?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| ModelError::Decode(e.to_string()))?;
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| {
                ModelError::Decode("no choices[0].message.content in response".to_string())
            })?
            .to_string();
        let reported_model = bounded_receipt_field(&v, "model")?;
        let response_id = bounded_receipt_field(&v, "id")?;
        let finish_reason = v["choices"][0]["finish_reason"]
            .as_str()
            .map(str::to_owned)
            .map(|value| bound_receipt_value("finish_reason", value))
            .transpose()?;
        let request_id =
            request_id.map(|value| bound_receipt_value("x-request-id", value)).transpose()?;
        let model = reported_model.clone().unwrap_or_else(|| self.model.clone());
        let usage = parse_usage(&v["usage"]);
        Ok(Completion {
            content,
            model,
            usage,
            provider: Some(ProviderReceipt {
                response_id,
                request_id,
                reported_model,
                finish_reason,
                store_requested: false,
            }),
        })
    }

    fn describe(&self) -> String {
        self.model.clone()
    }
}

#[cfg(feature = "openai")]
const MAX_PROVIDER_RECEIPT_FIELD_BYTES: usize = 1024;

#[cfg(feature = "openai")]
fn bound_receipt_value(label: &str, value: String) -> Result<String, ModelError> {
    if value.is_empty() || value.len() > MAX_PROVIDER_RECEIPT_FIELD_BYTES {
        return Err(ModelError::Decode(format!(
            "provider {label} must contain 1..={MAX_PROVIDER_RECEIPT_FIELD_BYTES} bytes"
        )));
    }
    Ok(value)
}

#[cfg(feature = "openai")]
fn bounded_receipt_field(
    body: &serde_json::Value,
    field: &str,
) -> Result<Option<String>, ModelError> {
    body[field]
        .as_str()
        .map(str::to_owned)
        .map(|value| bound_receipt_value(field, value))
        .transpose()
}

/// Refuse URL-embedded user-info and refuse to send a bearer credential over cleartext except to an
/// exact loopback host. A keyless local compatible server remains supported over HTTP; all
/// non-loopback credentialed endpoints must use HTTPS.
#[cfg(feature = "openai")]
fn validate_model_endpoint(base_url: &str, has_api_key: bool) -> Result<(), ModelError> {
    let trimmed = base_url.trim();
    let (is_https, rest) = if let Some(rest) = trimmed.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(ModelError::Config(
            "model base URL must use https://, or http:// for an explicit local compatible server"
                .to_string(),
        ));
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(ModelError::Config(
            "model endpoint has an invalid authority; URL user-info is forbidden".to_string(),
        ));
    }
    if is_https {
        return Ok(());
    }
    if !has_api_key {
        return Ok(());
    }
    let host = if let Some(bracketed) = authority.strip_prefix('[') {
        let Some((host, suffix)) = bracketed.split_once(']') else {
            return Err(ModelError::Config(
                "credentialed model HTTP endpoint has an invalid IPv6 authority".to_string(),
            ));
        };
        if !suffix.is_empty()
            && (!suffix.starts_with(':')
                || suffix[1..].is_empty()
                || !suffix[1..].bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(ModelError::Config(
                "credentialed model HTTP endpoint has an invalid port".to_string(),
            ));
        }
        host
    } else {
        let (host, port) = authority.rsplit_once(':').unwrap_or((authority, ""));
        if authority.contains(':') && (port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(ModelError::Config(
                "credentialed model HTTP endpoint has an invalid port".to_string(),
            ));
        }
        host
    };
    if matches!(host, "localhost" | "127.0.0.1" | "::1") {
        Ok(())
    } else {
        Err(ModelError::Config(
            "refusing to send a model API key over non-loopback http://; use https://".to_string(),
        ))
    }
}

/// Truncate `s` to at most `max` bytes, never splitting a UTF-8 char (`String::truncate` panics on a
/// non-char-boundary — a non-ASCII error body would otherwise crash any consumer not wrapping the
/// call in `catch_unwind`).
#[cfg(feature = "openai")]
fn truncate_on_char_boundary(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
}

#[cfg(feature = "openai")]
fn read_body_bytes_bounded(
    resp: ureq::Response,
    max: usize,
) -> Result<(Vec<u8>, bool), std::io::Error> {
    let mut bytes = Vec::new();
    let mut reader = resp.into_reader().take(max as u64 + 1);
    reader.read_to_end(&mut bytes)?;
    let truncated = bytes.len() > max;
    if truncated {
        bytes.truncate(max);
    }
    Ok((bytes, truncated))
}

#[cfg(feature = "openai")]
fn read_success_body_bounded(resp: ureq::Response) -> Result<String, ModelError> {
    let (bytes, truncated) = read_body_bytes_bounded(resp, MAX_OPENAI_HTTP_RESPONSE_BYTES)
        .map_err(|e| ModelError::Transport(e.to_string()))?;
    if truncated {
        return Err(ModelError::Decode(format!(
            "model response too large: exceeds {} byte limit",
            MAX_OPENAI_HTTP_RESPONSE_BYTES
        )));
    }
    String::from_utf8(bytes).map_err(|e| ModelError::Decode(e.to_string()))
}

#[cfg(feature = "openai")]
fn read_error_body_bounded(resp: ureq::Response) -> String {
    let Ok((bytes, truncated)) = read_body_bytes_bounded(resp, MAX_OPENAI_HTTP_ERROR_BODY_BYTES)
    else {
        return String::new();
    };
    let mut text = String::from_utf8_lossy(&bytes).into_owned();
    truncate_on_char_boundary(&mut text, MAX_OPENAI_HTTP_ERROR_BODY_BYTES);
    if truncated {
        text.push_str("\n... (truncated)");
    }
    text
}

#[cfg(feature = "openai")]
fn parse_usage(v: &serde_json::Value) -> Option<TokenUsage> {
    let prompt_tokens = u32::try_from(v["prompt_tokens"].as_u64()?).ok()?;
    let completion_tokens = u32::try_from(v["completion_tokens"].as_u64()?).ok()?;
    let total_tokens = match v["total_tokens"].as_u64() {
        Some(total) => u32::try_from(total).ok()?,
        None => prompt_tokens.checked_add(completion_tokens)?,
    };
    Some(TokenUsage { prompt_tokens, completion_tokens, total_tokens })
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// Canned responses for FakeModel / SlowModel. The two-fenced-block contract a real model is asked to
// emit: a ```rust forge-creature source block + a ```json manifest-stub block. The source must
// compile against `forge` alone and produce a reverse-string daemon (so the full author → build →
// admit → load → run loop is provable offline).
// ─────────────────────────────────────────────────────────────────────────────────────────────

const GOOD_REVERSE_RESPONSE: &str = r#"Here is a creature that reverses its envelope payload.

```rust
use forge::prelude::*;

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
```

And the manifest stub:

```json
{
  "name": "reverse-daemon",
  "version": "0.1.0",
  "entrypoints": [{ "name": "handle", "signature": "(Envelope) -> Outcome" }],
  "provides": []
}
```
"#;

// A structurally-complete forge creature (so it passes the author's truncation backstop — it has
// `declare_creature!`) that is intentionally invalid RUST: a stray identifier outside any item plus a
// reference to an undefined type. rustc reports a clear error, which build-cargo returns as a
// structured Compile failure — proving the compile-error → prev_error → re-author retry path, where
// the failure lives at BUILD (not at the author's parse stage).
const BROKEN_REVERSE_RESPONSE: &str = r#"Here is the creature:

```rust
use forge::prelude::*;

deliberately_broken_for_agent_mind_retry_drill_no_item_here

forge::declare_creature!(ReverseDaemon);
```

Manifest stub:

```json
{
  "name": "reverse-daemon",
  "version": "0.1.0",
  "entrypoints": [{ "name": "handle", "signature": "(Envelope) -> Outcome" }],
  "provides": []
}
```
"#;

// The critter (script) tier: Rhai source, no `declare_creature!`, validated + signed by build-critter
// (no cargo). `fn handle(env)` returns a blob the critter engine turns into a reply.
const GOOD_CRITTER_RESPONSE: &str = r#"Here is a Rhai critter that reverses its payload.

```rhai
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
```

```json
{
  "name": "reverse-critter",
  "version": "0.1.0",
  "entrypoints": [{ "name": "handle", "signature": "(env) -> reply" }],
  "provides": []
}
```
"#;

// A critter that defines `fn handle` (so it passes the author's truncation backstop) but is invalid
// Rhai — build-critter's compile check rejects it. Mirrors the daemon broken fixture: the failure
// lives at BUILD, not at the author's parse stage.
const BROKEN_CRITTER_RESPONSE: &str = r#"Here is a critter:

```rhai
fn handle(env) { let x = ; x }
```

```json
{ "name": "reverse-critter", "version": "0.1.0", "entrypoints": [{ "name": "handle", "signature": "(env) -> reply" }], "provides": [] }
```
"#;

// The typed Beast fake is the reviewed no-import WAT profile. WasmEngine verifies the signed call,
// exact route, and manifest-derived FunctionId before this module sees only canonical inline JSON;
// the host then wraps the returned application JSON with the verified AttemptId.
const GOOD_TYPED_FUNCTION_BEAST_RESPONSE: &str = r#"```wat
(module
  (memory (export "memory") 1)

  (func (export "alloc") (param $len i32) (result i32)
    (i32.const 1024))

  (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
    (local $cursor i32)
    (local $end i32)
    (local $digit i32)
    (local $value i32)
    (local $sign i32)
    (local $doubled i32)
    (local $magnitude i32)
    (local $digits i32)
    (local $out i32)

    (if (i32.lt_u (local.get $len) (i32.const 11))
      (then (return (i64.const 0))))
    (if (i32.gt_u (local.get $len) (i32.const 18))
      (then (return (i64.const 0))))
    (if (i64.ne
          (i64.load (local.get $ptr))
          (i64.const 0x2265756c6176227b))
      (then (return (i64.const 0))))
    (if (i32.ne
          (i32.load8_u offset=8 (local.get $ptr))
          (i32.const 58))
      (then (return (i64.const 0))))

    (local.set $end
      (i32.add (local.get $ptr) (i32.sub (local.get $len) (i32.const 1))))
    (if (i32.ne (i32.load8_u (local.get $end)) (i32.const 125))
      (then (return (i64.const 0))))
    (local.set $cursor (i32.add (local.get $ptr) (i32.const 9)))
    (local.set $sign (i32.const 1))
    (if (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 45))
      (then
        (local.set $sign (i32.const -1))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))))
    (if (i32.ge_u (local.get $cursor) (local.get $end))
      (then (return (i64.const 0))))
    (if (i32.and
          (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 48))
          (i32.lt_u (i32.add (local.get $cursor) (i32.const 1)) (local.get $end)))
      (then (return (i64.const 0))))

    (block $digits_done
      (loop $parse_digit
        (br_if $digits_done (i32.ge_u (local.get $cursor) (local.get $end)))
        (local.set $digit (i32.load8_u (local.get $cursor)))
        (if (i32.or
              (i32.lt_u (local.get $digit) (i32.const 48))
              (i32.gt_u (local.get $digit) (i32.const 57)))
          (then (return (i64.const 0))))
        (local.set $value
          (i32.add
            (i32.mul (local.get $value) (i32.const 10))
            (i32.sub (local.get $digit) (i32.const 48))))
        (if (i32.gt_u (local.get $value) (i32.const 1000000))
          (then (return (i64.const 0))))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))
        (br $parse_digit)))

    (if (i32.eq (local.get $sign) (i32.const -1))
      (then (local.set $value (i32.sub (i32.const 0) (local.get $value)))))
    (local.set $doubled (i32.mul (local.get $value) (i32.const 2)))

    (i64.store
      (i32.const 4096)
      (i64.const 0x656c62756f64227b))
    (i32.store offset=8
      (i32.const 4096)
      (i32.const 0x003a2264))
    (local.set $out (i32.const 4107))
    (if (i32.lt_s (local.get $doubled) (i32.const 0))
      (then
        (i32.store8 (local.get $out) (i32.const 45))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (local.set $magnitude (i32.sub (i32.const 0) (local.get $doubled))))
      (else (local.set $magnitude (local.get $doubled))))

    (loop $write_reverse
      (i32.store8
        (i32.add (i32.const 4200) (local.get $digits))
        (i32.add
          (i32.const 48)
          (i32.rem_u (local.get $magnitude) (i32.const 10))))
      (local.set $digits (i32.add (local.get $digits) (i32.const 1)))
      (local.set $magnitude (i32.div_u (local.get $magnitude) (i32.const 10)))
      (br_if $write_reverse (i32.ne (local.get $magnitude) (i32.const 0))))

    (block $copy_done
      (loop $copy_digit
        (br_if $copy_done (i32.eqz (local.get $digits)))
        (local.set $digits (i32.sub (local.get $digits) (i32.const 1)))
        (i32.store8
          (local.get $out)
          (i32.load8_u (i32.add (i32.const 4200) (local.get $digits))))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (br $copy_digit)))
    (i32.store8 (local.get $out) (i32.const 125))
    (local.set $out (i32.add (local.get $out) (i32.const 1)))

    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 4096)) (i64.const 32))
      (i64.extend_i32_u (i32.sub (local.get $out) (i32.const 4096))))))
```

```json
{
  "name": "double-int-beast",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

// A complete-looking but noncanonical WAT response: AgentMind rejects it at the exact-source gate,
// and a retry remains in Beast mode and returns the reviewed module above.
const BROKEN_TYPED_FUNCTION_BEAST_RESPONSE: &str = r#"```wat
(module
  ;; deliberately_broken_for_typed_beast_retry
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 0))
  (func (export "handle") (param i32 i32) (result i64) (i64.const 0)))
```

```json
{
  "name": "double-int-beast",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

// Native code shares the host process. This fake therefore exercises only AgentMind's legacy
// byte-exact trusted-by-admission profile; it is not a precedent for accepting arbitrary
// model-authored Rust. Current v0.5 approved mode accepts a source-free IR and trusted-lowers it.
// The legacy source uses forge's typed helpers so the generated crate needs no additional deps.
const GOOD_TYPED_FUNCTION_DAEMON_RESPONSE: &str = r#"```rust
use forge::prelude::*;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct DoubleSignedDaemon {
    manifest_content_address: Option<String>,
}

impl Creature for DoubleSignedDaemon {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.manifest_content_address = ctx.manifest.content_address;
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        let Some(manifest_content_address) = self.manifest_content_address.as_deref() else {
            return Outcome::none();
        };
        let Ok(call) = forge::function::parse_call(&env) else {
            return Outcome::none();
        };
        if call.function.manifest_content_address != manifest_content_address
            || call.function.entrypoint != "double_signed"
        {
            return Outcome::none();
        }
        let Ok(mut input) =
            forge::function::from_inline::<BTreeMap<String, i64>>(&call.input)
        else {
            return Outcome::none();
        };
        if input.len() != 1 {
            return Outcome::none();
        }
        let Some(value) = input.remove("value") else {
            return Outcome::none();
        };
        if !(-1_000_000..=1_000_000).contains(&value) {
            return Outcome::none();
        }
        let Some(doubled) = value.checked_mul(2) else {
            return Outcome::none();
        };
        let output = BTreeMap::from([("doubled", doubled)]);
        forge::function::success(&env, call.attempt, &output)
            .map(Outcome::send)
            .unwrap_or_else(|_| Outcome::none())
    }
}

forge::declare_creature!(DoubleSignedDaemon);
```

```json
{
  "name": "double-int-daemon",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

// Structurally complete enough to reach AgentMind's exact-source gate, but deliberately different
// from the audited native source. A retry must stay in typed-daemon mode and return the fixed pair.
const BROKEN_TYPED_FUNCTION_DAEMON_RESPONSE: &str = r#"```rust
use forge::prelude::*;

deliberately_broken_for_typed_daemon_retry

forge::declare_creature!(DoubleSignedDaemon);
```

```json
{
  "name": "double-int-daemon",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

// The typed-Function critter fake is intentionally one narrow, exact capability. Its manifest is
// consumed by agent-mind's strict contract validator; its source then crosses build-critter's real
// Rhai compile/signing gate and ScriptEngine's proof-bearing Function-call gate.
const GOOD_TYPED_FUNCTION_CRITTER_RESPONSE: &str = r#"```rhai
fn handle(env) {
    if env.schema != "gawd.function.call.v1" || env.text_truncated {
        return ();
    }
    if !function_call_verify(env.text, env.from, env.to) {
        return ();
    }

    let message = json_parse(env.text);
    if message.operation != "call" {
        return ();
    }
    let invocation = message["call"];
    if invocation.function.entrypoint != "double_signed" || invocation.input.kind != "inline" {
        return ();
    }
    let input = invocation.input.value;
    if type_of(input) != "map" || input.len() != 1 || !input.contains("value") {
        return ();
    }
    let value = input.value;
    if type_of(value) != "i64" || value < -1000000 || value > 1000000 {
        return ();
    }

    json_stringify(#{
        operation: "result",
        result: #{
            attempt: invocation.attempt,
            outcome: #{
                Ok: #{ kind: "inline", value: #{ doubled: value * 2 } }
            }
        }
    })
}
```

```json
{
  "name": "double-int-critter",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

// A deliberately broken typed response retained to prove FakeModel keeps its legacy typed-mode
// selection across retries. That byte-exact profile accepts only its audited canonical source, so
// this first answer is rejected at author validation rather than reaching BuildCritter. Current
// v0.5 approved mode instead accepts a strict source-free IR and uses trusted lowering.
const BROKEN_TYPED_FUNCTION_CRITTER_RESPONSE: &str = r#"```rhai
fn handle(env) {
    if env.schema != "gawd.function.call.v1" || env.text_truncated {
        return ();
    }
    if !function_call_verify(env.text, env.from, env.to) {
        return ();
    }
    let message = json_parse(env.text);
    if message.operation != "call" {
        return ();
    }
    let invocation = message["call"];
    if invocation.function.entrypoint != "double_signed" || invocation.input.kind != "inline" {
        return ();
    }
    let input = invocation.input.value;
    if type_of(input) != "map" || input.len() != 1 || !input.contains("value") {
        return ();
    }
    let value = input.value;
    if type_of(value) != "i64" || value < -1000000 || value > 1000000 {
        return ();
    }
    let deliberately_broken = ;
    json_stringify(#{
        operation: "result",
        result: #{
            attempt: invocation.attempt,
            outcome: #{ Ok: #{ kind: "inline", value: #{ doubled: value * 2 } } }
        }
    })
}
```

```json
{
  "name": "double-int-critter",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn req(user: &str) -> Prompt {
        Prompt {
            system_prompt: "sys".to_string(),
            user_prompt: user.to_string(),
            max_tokens: 1024,
            temperature: 0.0,
        }
    }

    fn req_with_system(system: &str, user: &str) -> Prompt {
        Prompt {
            system_prompt: system.to_string(),
            user_prompt: user.to_string(),
            max_tokens: 1024,
            temperature: 0.0,
        }
    }

    #[test]
    fn fake_always_good_returns_two_fenced_blocks() {
        let r = FakeModel::always_good().complete(req("reverse a string")).unwrap();
        assert!(r.content.contains("```rust"), "carries a rust block");
        assert!(r.content.contains("```json"), "carries a json manifest stub");
        assert!(r.content.contains("ReverseDaemon"));
        assert!(r.usage.is_none(), "fake leaves usage None");
        assert!(r.provider.is_none(), "fixture responses are not provider receipts");
    }

    #[test]
    fn fake_broken_then_fixed_switches_on_retry_marker() {
        let model = FakeModel::broken_then_fixed();
        let first = model.complete(req("reverse a string")).unwrap();
        assert!(first.content.contains("deliberately_broken"), "first call returns broken source");
        let retry = model
            .complete(req(&format!("reverse a string\n\n{RETRY_MARKER}: error[E0601]...")))
            .unwrap();
        assert!(retry.content.contains("ReverseDaemon"), "retry returns fixed source");
    }

    #[test]
    fn fake_typed_function_response_carries_exact_route_attempt_and_contract_shape() {
        let response = FakeModel::always_good()
            .complete(req_with_system(
                &format!("{CRITTER_TIER_MARKER} {TYPED_FUNCTION_CRITTER_MARKER}"),
                "double one integer",
            ))
            .unwrap();
        for required in [
            "function_call_verify(env.text, env.from, env.to)",
            "attempt: invocation.attempt",
            "gawd.function.call.v1",
            "\"effect\": \"idempotent\"",
            "\"minimum\": -1000000",
            "\"maximum\": 2000000",
            "doubled: value * 2",
        ] {
            assert!(response.content.contains(required), "typed fake is missing {required}");
        }
    }

    #[test]
    fn fake_typed_function_retry_preserves_the_typed_mode() {
        let system = format!("{CRITTER_TIER_MARKER} {TYPED_FUNCTION_CRITTER_MARKER}");
        let model = FakeModel::broken_then_fixed();
        let first = model.complete(req_with_system(&system, "double one integer")).unwrap();
        assert!(first.content.contains("deliberately_broken"));
        let fixed = model
            .complete(req_with_system(
                &system,
                &format!("double one integer\n{RETRY_MARKER}: parse error"),
            ))
            .unwrap();
        assert!(!fixed.content.contains("deliberately_broken"));
        assert!(fixed.content.contains("doubled: value * 2"));
    }

    #[test]
    fn fake_typed_function_beast_response_carries_no_import_wat_and_shared_contract() {
        let system = format!(
            "{CRITTER_TIER_MARKER} {TYPED_FUNCTION_CRITTER_MARKER} {TYPED_FUNCTION_DAEMON_MARKER} {TYPED_FUNCTION_BEAST_MARKER}"
        );
        let response = FakeModel::always_good()
            .complete(req_with_system(&system, "double one integer in a Beast"))
            .unwrap();
        for required in [
            "```wat",
            "(memory (export \"memory\") 1)",
            "(func (export \"alloc\")",
            "(func (export \"handle\")",
            "0x2265756c6176227b",
            "0x656c62756f64227b",
            "double-int-beast",
            "gawd.function.call.v1",
            "\"effect\": \"idempotent\"",
            "\"minimum\": -1000000",
            "\"maximum\": 2000000",
        ] {
            assert!(response.content.contains(required), "typed Beast fake is missing {required}");
        }
        for forbidden in ["(import ", "function_call_verify", "DoubleSignedDaemon"] {
            assert!(
                !response.content.contains(forbidden),
                "the Beast marker must select only the no-import WAT response: {forbidden}"
            );
        }
    }

    #[test]
    fn fake_typed_function_beast_retry_preserves_beast_mode() {
        let model = FakeModel::broken_then_fixed();
        let first = model
            .complete(req_with_system(TYPED_FUNCTION_BEAST_MARKER, "double one integer in WASM"))
            .unwrap();
        assert!(first.content.contains("deliberately_broken_for_typed_beast_retry"));
        assert!(!first.content.contains("0x2265756c6176227b"));

        let fixed = model
            .complete(req_with_system(
                TYPED_FUNCTION_BEAST_MARKER,
                &format!("double one integer in WASM\n{RETRY_MARKER}: rejected source drift"),
            ))
            .unwrap();
        assert!(!fixed.content.contains("deliberately_broken_for_typed_beast_retry"));
        assert!(fixed.content.contains("0x2265756c6176227b"));
        assert!(fixed.content.contains("double-int-beast"));
    }

    #[test]
    fn fake_typed_function_daemon_response_carries_identity_route_and_contract_shape() {
        let system = format!(
            "{CRITTER_TIER_MARKER} {TYPED_FUNCTION_CRITTER_MARKER} {TYPED_FUNCTION_DAEMON_MARKER}"
        );
        let response = FakeModel::always_good()
            .complete(req_with_system(&system, "double one integer natively"))
            .unwrap();
        for required in [
            "DoubleSignedDaemon",
            "ctx.manifest.content_address",
            "forge::function::parse_call(&env)",
            "call.function.manifest_content_address != manifest_content_address",
            "forge::function::from_inline::<BTreeMap<String, i64>>(&call.input)",
            "input.len() != 1",
            "value.checked_mul(2)",
            "forge::function::success(&env, call.attempt, &output)",
            "gawd.function.call.v1",
            "\"effect\": \"idempotent\"",
            "\"minimum\": -1000000",
            "\"maximum\": 2000000",
        ] {
            assert!(response.content.contains(required), "typed daemon fake is missing {required}");
        }
        assert!(
            !response.content.contains("function_call_verify"),
            "the daemon marker wins over broader critter markers"
        );
    }

    #[test]
    fn fake_typed_function_daemon_retry_preserves_the_native_mode() {
        let model = FakeModel::broken_then_fixed();
        let first = model
            .complete(req_with_system(TYPED_FUNCTION_DAEMON_MARKER, "double one integer natively"))
            .unwrap();
        assert!(first.content.contains("deliberately_broken_for_typed_daemon_retry"));

        let fixed = model
            .complete(req_with_system(
                TYPED_FUNCTION_DAEMON_MARKER,
                &format!("double one integer natively\n{RETRY_MARKER}: rejected source drift"),
            ))
            .unwrap();
        assert!(!fixed.content.contains("deliberately_broken_for_typed_daemon_retry"));
        assert!(fixed.content.contains("DoubleSignedDaemon"));
        assert!(fixed.content.contains("forge::function::success"));
    }

    #[test]
    fn fake_erroring_returns_transport_error() {
        let e = FakeModel::erroring().complete(req("anything")).unwrap_err();
        assert!(matches!(e, ModelError::Transport(_)), "got {e:?}");
    }

    #[test]
    fn slow_model_blocks_until_released() {
        use std::sync::Arc;
        let slow = Arc::new(SlowModel::new());
        assert!(!slow.has_entered());
        let s2 = slow.clone();
        let h = std::thread::spawn(move || s2.complete(req("x")).unwrap());
        // Wait until the worker is provably inside complete().
        for _ in 0..200 {
            if slow.has_entered() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(slow.has_entered(), "complete() entered");
        assert!(!slow.has_finished(), "still blocked before release");
        slow.release();
        let reply = h.join().unwrap();
        assert!(slow.has_finished());
        assert!(reply.content.contains("ReverseDaemon"));
    }

    #[test]
    fn model_error_display_is_structured() {
        let displayed =
            ModelError::Http { status: 401, body: "reflected-secret-and-prompt".into() }
                .to_string();
        assert!(displayed.contains("401"));
        assert!(!displayed.contains("reflected-secret-and-prompt"));
    }

    #[cfg(feature = "openai")]
    #[test]
    fn openai_usage_parser_rejects_out_of_range_counts() {
        let huge = serde_json::json!({
            "prompt_tokens": (u32::MAX as u64) + 1,
            "completion_tokens": 1,
            "total_tokens": (u32::MAX as u64) + 2,
        });
        assert_eq!(parse_usage(&huge), None, "oversized counters must not wrap");

        let overflowing_sum = serde_json::json!({
            "prompt_tokens": u32::MAX,
            "completion_tokens": 1,
        });
        assert_eq!(
            parse_usage(&overflowing_sum),
            None,
            "missing total_tokens must not overflow prompt+completion"
        );
    }

    #[cfg(feature = "openai")]
    #[test]
    fn openai_usage_parser_accepts_bounded_counts() {
        let usage = serde_json::json!({
            "prompt_tokens": 12,
            "completion_tokens": 34,
            "total_tokens": 46,
        });
        assert_eq!(
            parse_usage(&usage),
            Some(TokenUsage { prompt_tokens: 12, completion_tokens: 34, total_tokens: 46 })
        );
    }

    #[cfg(feature = "openai")]
    #[test]
    fn credentialed_cleartext_model_endpoint_is_loopback_only() {
        for local in
            ["http://localhost:11434/v1", "http://127.0.0.1:8080/v1", "http://[::1]:9000/v1"]
        {
            validate_model_endpoint(local, true).expect("exact loopback is allowed");
        }
        validate_model_endpoint("https://api.openai.com/v1", true)
            .expect("TLS endpoint is allowed");
        validate_model_endpoint("http://models.example.test/v1", false)
            .expect("a keyless compatible endpoint remains an explicit operator choice");
        for userinfo in
            ["https://user:secret@api.openai.com/v1", "http://user:secret@localhost:11434/v1"]
        {
            assert!(
                validate_model_endpoint(userinfo, false).is_err(),
                "URL user-info must be refused even without a bearer key"
            );
        }
        for unsafe_url in [
            "http://models.example.test/v1",
            "http://127.0.0.1.example.test/v1",
            "ftp://localhost/v1",
            "http://user@localhost/v1",
        ] {
            assert!(
                validate_model_endpoint(unsafe_url, true).is_err(),
                "a bearer credential must not be sent to {unsafe_url}"
            );
        }
    }

    #[cfg(feature = "openai")]
    #[test]
    fn provider_receipt_fields_are_bounded_and_do_not_invent_missing_values() {
        let body = serde_json::json!({"id": "chatcmpl-1", "model": "reported-model"});
        assert_eq!(bounded_receipt_field(&body, "id").unwrap().as_deref(), Some("chatcmpl-1"));
        assert_eq!(
            bounded_receipt_field(&body, "model").unwrap().as_deref(),
            Some("reported-model")
        );
        assert_eq!(bounded_receipt_field(&body, "missing").unwrap(), None);
        let oversized = serde_json::json!({"id": "x".repeat(MAX_PROVIDER_RECEIPT_FIELD_BYTES + 1)});
        assert!(bounded_receipt_field(&oversized, "id").is_err());
    }
}
