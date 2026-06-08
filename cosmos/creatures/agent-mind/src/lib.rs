//! `agent-mind` — the real, model-backed `Role::AUTHORING` creature.
//!
//! Where `agent-templated` keyword-matches canned source and `agent-curious` consults over SEER,
//! `agent-mind` asks a **real model** (an injected [`Model`]) to write the source + manifest stub. It
//! binds the same `Role::AUTHORING` socket and speaks the same wire contract (`AuthoringRequest` in,
//! [`AuthoringReply`] out on schema `"authoring.reply"`) — a creature swap, not a substrate change.
//! This is the literal "ASI is the fabric, not the model": the model is injected through the `mind`
//! leaf-crate trait; the fabric ships only the socket.
//!
//! ## Construction is the security boundary — no `declare_creature!`, no `Default`
//!
//! The `forge::declare_creature!` macro expands a no-arg `extern "C"`
//! constructor that calls `Default::default()`. A `.so`-loaded `agent-mind` would therefore silently
//! construct via `Default` — and the only sane no-arg default is a hermetic fake with no real model.
//! That is a dangerous, silent substitution of a fake model for a real one. So the construction
//! surface is **only** [`AgentMind::new`] (taking the model explicitly), and the creature is bound
//! **in-process only** via `kernel.load_instance`, exactly as `agent-templated`/`agent-curious` are.
//! It is **never** shipped as a `.so`.
//!
//! ## Threading — the slow call runs off the kernel drain thread
//!
//! `Creature::handle` runs on the kernel drain thread; a model call is slow. `agent-mind` mirrors
//! `transport-tcp`'s self-owned worker lifecycle (`stop` flag + a joinable handle set + the captured
//! `Arc<dyn Bus>`), NOT `forge::spawn` — whose managed-thread registry is installed only on the
//! `.so` FFI path, so an in-process `forge::spawn` would leak a never-joined thread. `handle`
//! assembles the request, spawns a worker via `std::thread::Builder`, and returns immediately; the
//! worker performs the blocking call and emits the reply off-drain through the captured bus.
//!
//! ## Shutdown is honest best-effort
//!
//! A worker already blocked inside a model call cannot be interrupted. [`shutdown`](AgentMind) sets
//! `stop` (gating *new* work + suppressing a stopped worker's reply) and joins, **deadline-bounded
//! by polling** so it returns inside the kernel's unload budget. Any straggler is detached: because
//! `agent-mind` is in-process only, a detached worker returns into no unmapped code — it finishes its
//! (now-stopped) call and exits cleanly. The residual is a bounded, in-process thread that lingers
//! for the call's duration, never a use-after-free.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{Builder, JoinHandle};
use std::time::{Duration, Instant};

use aether::{Address, Bus, Creature, CreatureCtx, Deadline, Dispatch, Envelope, Outcome};
use agent_templated::{decode_authoring_request, AuthoringError, AuthoringReply};
use sha2::{Digest, Sha256};

mod prompt;

// Re-export the model contract so a composition root can construct a model without depending on the
// `mind` crate directly. `pub use` also brings these names into scope for this module.
#[cfg(feature = "openai")]
pub use mind::OpenAiModel;
pub use mind::{
    Completion, FakeMode, FakeModel, Model, ModelConfig, ModelError, Prompt, SlowModel, TokenUsage,
};

/// The schema every AUTHORING reply rides on the bus (the established convention `agent-templated`
/// uses).
const AUTHORING_REPLY_SCHEMA: &str = "authoring.reply";

/// Poison-tolerant `Mutex` acquisition: a worker panicking while holding a lock must not wedge the
/// drain thread on the next acquire. Each lock guards a plain `Option`/`Vec` with no half-broken
/// invariant, so recovering the guard is sound (mirrors `transport-tcp::mlock`).
#[inline]
fn mlock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The model-backed author.
pub struct AgentMind {
    model: Arc<dyn Model>,
    /// Optional SEER `Thought` target — when set, each completion emits an observable narration
    /// (the Loop-2 selection signal). Off by default.
    seer_to: Option<Address>,
    /// Gates *new* work and suppresses a stopped worker's reply. Shared with every spawned worker.
    stop: Arc<AtomicBool>,
    /// In-flight worker handles, joined (best-effort, deadline-bounded) at shutdown.
    workers: Mutex<Vec<JoinHandle<()>>>,
    /// The creature's bus authority, captured at bind. Cloned out (guard dropped) before any emit.
    bus: Mutex<Option<Arc<dyn Bus>>>,
}

impl AgentMind {
    /// The one construction surface: the model is injected explicitly, so a fake can never be
    /// silently substituted for a real model.
    pub fn new(model: Arc<dyn Model>) -> Self {
        AgentMind {
            model,
            seer_to: None,
            stop: Arc::new(AtomicBool::new(false)),
            workers: Mutex::new(Vec::new()),
            bus: Mutex::new(None),
        }
    }

    /// Emit an observable SEER `Thought` (internal channel) to `to` per completion.
    pub fn with_seer(mut self, to: Address) -> Self {
        self.seer_to = Some(to);
        self
    }

    /// Share an external `stop` flag (so a test can observe / drive the shutdown gate).
    pub fn with_stop(mut self, stop: Arc<AtomicBool>) -> Self {
        self.stop = stop;
        self
    }

    /// A hermetic always-good author for tests (no real model).
    #[cfg(test)]
    pub fn fake() -> Self {
        AgentMind::new(Arc::new(FakeModel::always_good()))
    }
}

impl Creature for AgentMind {
    fn bind(&mut self, ctx: CreatureCtx) {
        *mlock(&self.bus) = Some(ctx.bus);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Decode on the drain thread; a malformed request is a synchronous Failed (no worker).
        let req = match decode_authoring_request(&env.payload) {
            Ok(r) => r,
            Err(e) => {
                let reply = AuthoringReply::Failed(e);
                return Outcome::send(
                    Dispatch::reply_to_env(&env, reply.to_bytes())
                        .with_schema(AUTHORING_REPLY_SCHEMA),
                );
            }
        };

        // During unload we refuse new work rather than spawn a worker that will be detached.
        if self.stop.load(Ordering::Relaxed) {
            return Outcome::none();
        }

        // Capture the reply target + corr now so the worker never needs the (otherwise moved)
        // envelope — mirrors `Dispatch::reply_to_env` semantics (reply_to, else from; preserve corr).
        let reply_addr = env.header.reply_to.clone().unwrap_or_else(|| env.header.from.clone());
        let reply_corr = env.header.corr;

        // Assemble the model request on the drain thread (cheap), move the slow call off-drain.
        let tier = prompt::tier_of(&req);
        let model_req = prompt::build_request(&req);
        let model = self.model.clone();
        let stop = self.stop.clone();
        let seer_to = self.seer_to.clone();
        let model_label = self.model.describe();
        let Some(bus) = mlock(&self.bus).as_ref().cloned() else {
            // Not bound (should not happen on the in-process path) — fail synchronously.
            let reply = AuthoringReply::Failed(AuthoringError::Invalid {
                message: "agent-mind is not bound to a bus".to_string(),
            });
            return Outcome::send(
                Dispatch::reply_to_env(&env, reply.to_bytes()).with_schema(AUTHORING_REPLY_SCHEMA),
            );
        };

        // Reap finished workers so the set doesn't grow unbounded under sustained authoring.
        mlock(&self.workers).retain(|h| !h.is_finished());

        let spawn = Builder::new().name("agent-mind-worker".to_string()).spawn(move || {
            run_worker(
                model,
                model_req,
                bus,
                reply_addr,
                reply_corr,
                stop,
                seer_to,
                model_label,
                tier,
            );
        });
        match spawn {
            Ok(h) => mlock(&self.workers).push(h),
            Err(e) => {
                // Thread-limit edge: don't leave the requester hanging — fail synchronously. `env`
                // was not captured by the (dropped) closure, so it is still ours to reply from.
                eprintln!("agent-mind: failed to spawn worker thread: {e}");
                let reply = AuthoringReply::Failed(AuthoringError::Invalid {
                    message: format!("agent-mind worker spawn failed: {e}"),
                });
                return Outcome::send(
                    Dispatch::reply_to_env(&env, reply.to_bytes())
                        .with_schema(AUTHORING_REPLY_SCHEMA),
                );
            }
        }
        Outcome::none()
    }

    fn shutdown(&mut self, deadline: Deadline) {
        self.stop.store(true, Ordering::Relaxed);
        // Best-effort, deadline-bounded polling join. Leave a margin below the kernel's unload
        // deadline so this returns before the kernel's done-signal times out; for a tiny deadline
        // the budget collapses to ~0 and we return immediately (still within the deadline).
        let budget = deadline.0.saturating_sub(Duration::from_millis(100));
        let start = Instant::now();
        loop {
            let mut remaining = Vec::new();
            for h in std::mem::take(&mut *mlock(&self.workers)) {
                if h.is_finished() {
                    let _ = h.join();
                } else {
                    remaining.push(h);
                }
            }
            let all_joined = remaining.is_empty();
            *mlock(&self.workers) = remaining;
            if all_joined || start.elapsed() >= budget {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        // Detach any stragglers (bounded, in-process residual; documented in docs/design/substrate.md):
        // a still-blocked worker, on returning, sees `stop` set and drops its reply, then exits.
        mlock(&self.workers).clear();
    }
}

/// The off-drain worker body: run the (blocking) model call, map it to an [`AuthoringReply`], and
/// emit it through the captured bus — unless we were stopped mid-flight, in which case the reply is
/// dropped (and even an emit would be a clean `NoSuchModule`, never a use-after-free).
#[allow(clippy::too_many_arguments)]
fn run_worker(
    model: Arc<dyn Model>,
    req: Prompt,
    bus: Arc<dyn Bus>,
    reply_addr: Address,
    reply_corr: Option<u64>,
    stop: Arc<AtomicBool>,
    seer_to: Option<Address>,
    model_label: String,
    tier: prompt::Tier,
) {
    use std::panic::{catch_unwind, AssertUnwindSafe};
    // R9 floor: a panicking model must not unwind out of this thread into nothing.
    let result = catch_unwind(AssertUnwindSafe(|| model.complete(req)));
    let (reply, usage) = match result {
        Ok(Ok(completion)) => {
            let usage = completion.usage.clone();
            (map_reply(tier, completion), usage)
        }
        Ok(Err(e)) => (
            AuthoringReply::Failed(AuthoringError::Invalid {
                message: format!("model error: {e}"),
            }),
            None,
        ),
        Err(_) => (
            AuthoringReply::Failed(AuthoringError::Invalid {
                message: "model call panicked".to_string(),
            }),
            None,
        ),
    };

    // Stopped while the call was in flight → drop the reply WITHOUT logging or emitting. The work is
    // being discarded; an "authored" line for a dropped reply would be a misleading audit record.
    if stop.load(Ordering::Relaxed) {
        return;
    }

    // Observability: exactly one structured line per *delivered* completion — both outcomes.
    log_completion(&reply, &model_label, usage.as_ref());

    if let Some(to) = seer_to {
        let summary = match &reply {
            AuthoringReply::Authored(r) => {
                format!(
                    "authored `{}` ({} bytes) via agent-mind/{model_label}",
                    r.crate_name,
                    r.source.len()
                )
            }
            AuthoringReply::Failed(e) => {
                format!("authoring failed via agent-mind/{model_label}: {e:?}")
            }
        };
        let env = seer::SeerEnvelope::thought(
            seer::SeerTopic::Authoring,
            reply_corr.unwrap_or(0),
            "internal",
            &summary,
        );
        let mut thought = Dispatch::to(to, env.to_bytes()).with_schema(seer::SCHEMA);
        if let Some(c) = reply_corr {
            thought = thought.with_corr(c);
        }
        if let Err(e) = bus.emit(thought) {
            eprintln!("agent-mind: dropped SEER thought: {e}");
        }
    }

    let mut dispatch =
        Dispatch::to(reply_addr, reply.to_bytes()).with_schema(AUTHORING_REPLY_SCHEMA);
    if let Some(c) = reply_corr {
        dispatch = dispatch.with_corr(c);
    }
    if let Err(e) = bus.emit(dispatch) {
        // The creature may have been deregistered between the stop-check and here; a clean route
        // error, not a UAF. Surface it so a dropped reply is discoverable.
        eprintln!("agent-mind: dropped authoring reply: {e}");
    }
}

/// Parse the model completion into an [`AuthoringReply`] for the requested tier (fail-closed).
fn map_reply(tier: prompt::Tier, completion: Completion) -> AuthoringReply {
    match prompt::parse_response(tier, &completion.content) {
        Ok(resp) => AuthoringReply::Authored(resp),
        Err(e) => AuthoringReply::Failed(e),
    }
}

/// One structured observability line per delivered completion — authored-source sha256 + the
/// tier/model template label + token usage on success; the structured error on a fail-closed miss.
fn log_completion(reply: &AuthoringReply, model_label: &str, usage: Option<&mind::TokenUsage>) {
    match reply {
        AuthoringReply::Authored(resp) => {
            let src_hash = sha256_hex(resp.source.as_bytes());
            eprintln!(
                "agent-mind: authored crate={} source_sha256={src_hash} template={}/{model_label} usage={usage:?}",
                resp.crate_name, resp.template
            );
        }
        AuthoringReply::Failed(e) => {
            eprintln!("agent-mind: authoring FAILED via agent-mind/{model_label}: {e:?}");
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let digest = Sha256::digest(bytes);
    let mut s = String::with_capacity(64);
    for b in digest.iter() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{BusError, CreatureId, Header};
    use sigil::{Backend, Manifest};

    /// A recording bus, so the off-drain emit is observable without a kernel.
    struct MockBus {
        me: CreatureId,
        sent: Mutex<Vec<Dispatch>>,
    }
    impl Bus for MockBus {
        fn emit(&self, d: Dispatch) -> Result<(), BusError> {
            mlock(&self.sent).push(d);
            Ok(())
        }
        fn whoami(&self) -> CreatureId {
            self.me
        }
    }

    fn request_env(payload: Vec<u8>, corr: u64) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(2)),
                to: Address::Creature(CreatureId(9)),
                reply_to: Some(Address::Creature(CreatureId(2))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: "authoring.request".into(),
            },
            payload,
        }
    }

    fn bind_with_mock(agent: &mut AgentMind) -> Arc<MockBus> {
        let bus = Arc::new(MockBus { me: CreatureId(9), sent: Mutex::new(Vec::new()) });
        let ctx = CreatureCtx {
            me: CreatureId(9),
            bus: bus.clone(),
            manifest: Manifest::new("agent-mind", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
        };
        agent.bind(ctx);
        bus
    }

    #[test]
    fn off_drain_worker_emits_authored_reply_through_the_bus() {
        let mut agent = AgentMind::fake();
        let bus = bind_with_mock(&mut agent);
        let payload = serde_json::to_vec(&agent_templated::AuthoringRequest {
            request: "reverse a string".into(),
            ..Default::default()
        })
        .unwrap();
        let out = agent.handle(request_env(payload, 7));
        assert!(
            out.dispatches.is_empty(),
            "handle returns immediately; the worker emits off-drain"
        );
        // Wait for the worker to emit.
        let mut got = None;
        for _ in 0..400 {
            if let Some(d) = mlock(&bus.sent).first().cloned() {
                got = Some(d);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let d = got.expect("worker emitted a reply");
        assert_eq!(d.schema, AUTHORING_REPLY_SCHEMA);
        assert_eq!(d.corr, Some(7), "corr is preserved across the off-drain hop");
        assert_eq!(d.to, Address::Creature(CreatureId(2)), "reply goes to the requester");
        let reply: AuthoringReply = serde_json::from_slice(&d.payload).unwrap();
        match reply {
            AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
            other => panic!("expected Authored, got {other:?}"),
        }
        agent.shutdown(Deadline::default());
    }

    #[test]
    fn malformed_request_yields_synchronous_invalid_reply() {
        let mut agent = AgentMind::fake();
        let _bus = bind_with_mock(&mut agent);
        let out = agent.handle(request_env(b"{ not json".to_vec(), 1));
        assert_eq!(out.dispatches.len(), 1, "malformed request answers synchronously");
        let reply: AuthoringReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        assert!(matches!(reply, AuthoringReply::Failed(AuthoringError::Invalid { .. })));
        agent.shutdown(Deadline::default());
    }

    #[test]
    fn oversized_request_yields_synchronous_invalid_reply_without_worker() {
        let mut agent = AgentMind::fake();
        let bus = bind_with_mock(&mut agent);
        let out = agent
            .handle(request_env(vec![b'{'; agent_templated::MAX_AUTHORING_REQUEST_BYTES + 1], 2));
        assert_eq!(out.dispatches.len(), 1, "oversized request answers synchronously");
        let reply: AuthoringReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match reply {
            AuthoringReply::Failed(AuthoringError::Invalid { message }) => {
                assert!(message.contains("too large"), "unexpected message: {message}");
            }
            other => panic!("expected Failed(Invalid), got {other:?}"),
        }
        assert!(mlock(&bus.sent).is_empty(), "oversized request must not start a worker");
        agent.shutdown(Deadline::default());
    }

    #[test]
    fn model_error_becomes_a_failed_reply() {
        let mut agent = AgentMind::new(Arc::new(FakeModel::erroring()));
        let bus = bind_with_mock(&mut agent);
        let payload = serde_json::to_vec(&agent_templated::AuthoringRequest {
            request: "reverse".into(),
            ..Default::default()
        })
        .unwrap();
        agent.handle(request_env(payload, 3));
        let mut got = None;
        for _ in 0..400 {
            if let Some(d) = mlock(&bus.sent).first().cloned() {
                got = Some(d);
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let reply: AuthoringReply = serde_json::from_slice(&got.unwrap().payload).unwrap();
        assert!(matches!(reply, AuthoringReply::Failed(AuthoringError::Invalid { .. })));
        agent.shutdown(Deadline::default());
    }

    #[test]
    fn stopped_worker_drops_its_reply() {
        // A worker that finishes after `stop` is set must not emit.
        let slow = Arc::new(SlowModel::new());
        let mut agent = AgentMind::new(slow.clone());
        let bus = bind_with_mock(&mut agent);
        let payload = serde_json::to_vec(&agent_templated::AuthoringRequest {
            request: "reverse".into(),
            ..Default::default()
        })
        .unwrap();
        agent.handle(request_env(payload, 5));
        // Wait until the worker is provably in-flight, then shut down (sets stop), then release.
        for _ in 0..400 {
            if slow.has_entered() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(slow.has_entered());
        agent.shutdown(Deadline::from_millis(150)); // returns promptly; detaches the blocked worker
        slow.release();
        for _ in 0..400 {
            if slow.has_finished() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(slow.has_finished(), "worker finished after release");
        // Give the worker a beat to (not) emit.
        std::thread::sleep(Duration::from_millis(30));
        assert!(mlock(&bus.sent).is_empty(), "a stopped worker drops its reply");
    }
}
