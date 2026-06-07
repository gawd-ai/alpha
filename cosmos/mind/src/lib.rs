//! `mind` — the injected **model seam** for the Alpha substrate.
//!
//! This crate carries the seam where a real model is *injected* into the fabric: the [`Model`] trait
//! plus its request/reply types. It is the literal embodiment of the champion line **"ASI is the
//! fabric, not the model."** — the substrate ships the socket; a Claude / GPT / local model (and, in
//! time, a vision or other model) plugs into it through this trait.
//!
//! ## Why a leaf crate (not a module inside `agent-mind`)
//!
//! Two consumers need the model seam: the model-backed author (`agent-mind`) **and** the Bestiary
//! curator. The Bestiary contract crate must depend only on leaf/contract crates and **never** on a
//! creature crate. A shared [`Model`] living inside `agent-mind` would force the Bestiary to depend
//! on a creature to reach it — a contract → creature edge. A leaf crate is the only shape that serves
//! both cleanly. This crate therefore depends on nothing from the substrate.
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
use std::time::Duration;

/// A marker the prompt builder writes into the user prompt on a retry (when `prev_error` is set),
/// and the one [`FakeModel`] keys on to switch from broken to fixed source. Defined here so the two
/// sites (the prompt builder in `agent-mind`, the fake model here) never drift.
pub const RETRY_MARKER: &str = "PREVIOUS COMPILE ERROR";

/// A marker the *critter-tier* system prompt embeds, and the one [`FakeModel`] keys on to return a
/// Rhai critter instead of a native daemon. Defined here so the prompt builder (in `agent-mind`) and
/// the fake model never drift on which tier was requested.
pub const CRITTER_TIER_MARKER: &str = "CRITTER-TIER";

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

/// What the model returns. `content` is the raw completion text the consumer parses; `model` is the
/// model id the backend actually used; `usage` is optional accounting.
#[derive(Debug, Clone)]
pub struct Completion {
    pub content: String,
    pub model: String,
    pub usage: Option<TokenUsage>,
}

/// A model call failure. Carried as a structured error so the consumer can branch (and so the author
/// maps it to a structured `AuthoringError::Invalid` rather than panicking).
#[derive(Debug, Clone)]
pub enum ModelError {
    /// Connect / read / DNS / TLS failure — the request never produced an HTTP status.
    Transport(String),
    /// The server returned a non-2xx status; `body` is the (truncated) response text.
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
            ModelError::Http { status, body } => write!(f, "model http {status}: {body}"),
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
        let critter = req.system_prompt.contains(CRITTER_TIER_MARKER);
        let good = if critter { GOOD_CRITTER_RESPONSE } else { GOOD_REVERSE_RESPONSE };
        let broken = if critter { BROKEN_CRITTER_RESPONSE } else { BROKEN_REVERSE_RESPONSE };
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
        Ok(Completion { content: content.to_string(), model: self.model.clone(), usage: None })
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
        })
    }

    fn describe(&self) -> String {
        self.model.clone()
    }
}

// ─────────────────────────────────────────────────────────────────────────────────────────────
// OpenAiModel — the real HTTP path (feature `openai`).
// ─────────────────────────────────────────────────────────────────────────────────────────────

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
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                { "role": "system", "content": req.system_prompt },
                { "role": "user", "content": req.user_prompt },
            ],
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        });
        let body = serde_json::to_string(&body).map_err(|e| ModelError::Decode(e.to_string()))?;

        // Generous read timeout (real models take seconds). The author's shutdown is best-effort and
        // deadline-bounded by polling-join, NOT by clamping this timeout — a clamp short enough to
        // fit a 1s unload deadline would make every real model call fail. The connect timeout is
        // capped so a dead host is detected quickly.
        let agent = ureq::AgentBuilder::new()
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
                let mut text = r.into_string().unwrap_or_default();
                truncate_on_char_boundary(&mut text, 4096);
                return Err(ModelError::Http { status: code, body: text });
            }
            Err(e) => return Err(ModelError::Transport(e.to_string())),
        };
        let text = resp.into_string().map_err(|e| ModelError::Transport(e.to_string()))?;
        let v: serde_json::Value =
            serde_json::from_str(&text).map_err(|e| ModelError::Decode(e.to_string()))?;
        let content = v["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| {
                ModelError::Decode("no choices[0].message.content in response".to_string())
            })?
            .to_string();
        let model = v["model"].as_str().unwrap_or(&self.model).to_string();
        let usage = parse_usage(&v["usage"]);
        Ok(Completion { content, model, usage })
    }

    fn describe(&self) -> String {
        self.model.clone()
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
fn parse_usage(v: &serde_json::Value) -> Option<TokenUsage> {
    let prompt_tokens = v["prompt_tokens"].as_u64()? as u32;
    let completion_tokens = v["completion_tokens"].as_u64()? as u32;
    let total_tokens =
        v["total_tokens"].as_u64().map(|x| x as u32).unwrap_or(prompt_tokens + completion_tokens);
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

    #[test]
    fn fake_always_good_returns_two_fenced_blocks() {
        let r = FakeModel::always_good().complete(req("reverse a string")).unwrap();
        assert!(r.content.contains("```rust"), "carries a rust block");
        assert!(r.content.contains("```json"), "carries a json manifest stub");
        assert!(r.content.contains("ReverseDaemon"));
        assert!(r.usage.is_none(), "fake leaves usage None");
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
        assert!(ModelError::Http { status: 401, body: "no".into() }.to_string().contains("401"));
    }
}
