//! [`ControlCore`] — the bus-facing control translator.
//!
//! Node control is dogfooded onto GAWD's own [`Envelope`] bus. A surface (the REPL, the HTTP/WS
//! plane, the MCP hub) sends a [`Verb`] as the payload of a `control_verb` envelope addressed to
//! [`Role::CONTROL`](aether::Role::CONTROL); the bound `ControlCore` runs it against the live node
//! and replies with a [`VerbResult`] as a `control_result` envelope. Remote control is the *same*
//! envelope crossing the mesh to a peer node's `Role::CONTROL` (the reply routes back over the
//! transport), so a control surface never needs a second protocol.
//!
//! `ControlCore` is the node's **co-located, privileged control organ**: it holds an `Arc<Kernel>`
//! and reuses the shared [`run_verb`] core verbatim (zero divergence from the REPL). Loading it is a
//! privileged act; ordinary creatures still cannot reach the kernel. The IoC win is at
//! the *interface* — control is plain bus traffic — and remote control works because the Verb
//! travels to the remote node's *own* `ControlCore`, which drives its *own* kernel (you can't
//! decompose `author` into remote role-addressed sub-requests, which is exactly why the MCP server
//! is itself a sanctum).
//!
//! **Reads bypass the single responder.** A cold `author` is a real `cargo build` (tens
//! of seconds). If every verb queued behind one worker, a build would head-of-line-block a `status`.
//! So `handle` answers the fast, probe-free verbs (`status`/`list`/`journal`/`bind`/`unload`/`load`/
//! …) **inline** on the kernel's drain thread (microseconds), and forwards only the request/reply
//! verbs (`author`/`send`/`intent`/`cluster`/…) to a single worker that owns a probe endpoint. A
//! build in the worker never blocks an inline `status`.

use std::sync::mpsc::{self, Sender};
use std::sync::{Arc, Weak};
use std::thread::JoinHandle;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope, Outcome, Topic,
};
use sanctum::Kernel;
use sigil::Capabilities;

use serde_json::json;

use crate::{run_verb, AiControl, Verb, VerbCtx, VerbResult};

/// Schema of an inbound control envelope: its payload is a JSON [`Verb`]. A surface addresses these
/// to [`Role::CONTROL`](aether::Role::CONTROL) (local) or `Address::Node(peer, control_id)` (remote).
pub const CONTROL_SCHEMA: &str = "control_verb";
/// Schema of the reply envelope: its payload is a JSON [`VerbResult`], correlated by the request's
/// `corr`.
pub const CONTROL_RESULT_SCHEMA: &str = "control_result";
/// Schema of a progress frame published on the SEER topic during a long verb (e.g. `author`'s
/// "compiling…"), correlated to the command by its `corr` so a streaming surface can attribute it.
pub const CONTROL_PROGRESS_SCHEMA: &str = "control_progress";

/// The SEER topic control progress rides on (the same channel the HTTP/WS surface tails).
const SEER_TOPIC: &str = "seer";

/// Where a surface routes a control [`Verb`]: this node's own [`Role::CONTROL`](aether::Role::CONTROL), or a peer node's
/// control plane reached over the mesh (the surface having joined the cluster). Shared by every
/// surface creature (`surface-http`, `surface-mcp`) so the local/remote choice is one concept.
#[derive(Clone, Debug)]
pub enum ControlTarget {
    /// This node's own `Role::CONTROL` binding.
    Local,
    /// A peer node's control organ, addressed by node id + the peer's control [`CreatureId`] (the peer
    /// prints it at boot). The reply routes back over the transport's `reply_to` rewrite.
    Node { node: String, control_id: u64 },
}

impl ControlTarget {
    /// The bus address a `control_verb` envelope is sent to for this target.
    pub fn address(&self) -> Address {
        match self {
            ControlTarget::Local => Address::Role(aether::Role::new(aether::Role::CONTROL)),
            ControlTarget::Node { node, control_id } => {
                Address::Node(aether::NodeId(node.clone()), CreatureId(*control_id))
            }
        }
    }
}

/// A job for the orchestration worker: the verb plus where its [`VerbResult`] reply goes.
struct Job {
    verb: Verb,
    reply_to: Address,
    corr: Option<u64>,
}

/// The control translator creature. Bound to [`Role::CONTROL`](aether::Role::CONTROL) at boot.
pub struct ControlCore {
    /// A `Weak` ref — **not** `Arc` — so `ControlCore` (which lives inside the kernel's `loaded`
    /// map) does not form a strong cycle with the kernel that would defeat its `Drop`-based
    /// auto-shutdown (F10). Mirrors the kernel's own control listener. An upgrade-fail means the
    /// node is gone, and every method becomes a quiet no-op.
    kernel: Weak<Kernel>,
    ai: Arc<AiControl>,
    critter_builder: Option<CreatureId>,
    transport: Option<CreatureId>,
    /// Set in [`bind`](ControlCore::bind): the channel feeding the orchestration worker. Dropping it
    /// (on `shutdown`) closes the worker's `recv` so the thread exits.
    job_tx: Option<Sender<Job>>,
    worker: Option<JoinHandle<()>>,
}

impl ControlCore {
    /// Construct the control organ over a live kernel + the shared allow-AI gate. `critter_builder`
    /// is the no-cargo builder's id (for `author --critter`); `transport` is the TRANSPORT organ's
    /// id when clustered (for the `cluster` verbs) — both mirror the REPL's [`VerbCtx`] wiring. The
    /// kernel is held weakly (see the field doc).
    pub fn new(
        kernel: &Arc<Kernel>,
        ai: Arc<AiControl>,
        critter_builder: Option<CreatureId>,
        transport: Option<CreatureId>,
    ) -> Self {
        Self {
            kernel: Arc::downgrade(kernel),
            ai,
            critter_builder,
            transport,
            job_tx: None,
            worker: None,
        }
    }
}

/// Whether a verb needs a request/reply probe endpoint (and so runs on the worker, off the drain
/// thread). The fast, probe-free verbs are answered inline so a cold `author` can't block them.
fn needs_probe(verb: &Verb) -> bool {
    matches!(
        verb,
        Verb::Author { .. }
            | Verb::AuthorCritter { .. }
            // The registry/bestiary verbs do a request/reply round-trip to Role::REGISTRY (unlike the
            // inline `Load`), so they need the worker's probe endpoint.
            | Verb::RegistryPublish { .. }
            | Verb::RegistryFetch { .. }
            | Verb::RegistryList { .. }
            | Verb::BestiaryProve { .. }
            | Verb::Send { .. }
            | Verb::Intent { .. }
            | Verb::Cluster
            | Verb::ClusterJoin { .. }
    )
}

/// Build the `control_result` reply Outcome for an inline verb: reply to the request's
/// `reply_target` (preserving `corr`), tagged so the surface can tell a result from a sense frame.
fn reply(env: &Envelope, res: VerbResult) -> Outcome {
    let payload = serde_json::to_vec(&res).unwrap_or_else(|_| b"{}".to_vec());
    Outcome::send(Dispatch::reply_to_env(env, payload).with_schema(CONTROL_RESULT_SCHEMA))
}

impl Creature for ControlCore {
    fn bind(&mut self, _ctx: CreatureCtx) {
        let Some(kernel) = self.kernel.upgrade() else { return };
        // The orchestration worker owns its own probe endpoint (request/reply to AUTHORING/BUILD/a
        // target creature). Opened from the kernel here — `ControlCore` is the privileged control
        // organ. The probe's `BusHandle` holds the router (not the kernel), so it does not revive
        // the weak cycle; replies it emits carry the probe's identity, but the surface correlates
        // by `corr`, so `from` is immaterial.
        let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
        let (tx, rx) = mpsc::channel::<Job>();
        self.job_tx = Some(tx);

        let weak = self.kernel.clone();
        let ai = self.ai.clone();
        let cb = self.critter_builder;
        let tr = self.transport;
        let spawned = std::thread::Builder::new().name("omni-worker".into()).spawn(move || {
            // One verb at a time, sharing one corr space (no cross-talk) — exactly the daemon
            // API's probe-worker discipline, now driven by envelopes instead of HTTP.
            while let Ok(job) = rx.recv() {
                let Job { verb, reply_to, corr } = job;
                // Upgrade per job: hold a strong ref only for the duration of `run_verb`, so a
                // dropped node lets the worker exit. If the kernel is already gone, stop.
                let Some(kernel) = weak.upgrade() else { break };
                // Per-job progress → the SEER topic, correlated by the command's `corr` so a
                // streaming surface attributes "compiling…" to the right author call.
                let mut progress = |line: &str| {
                    let frame = json!({ "corr": corr, "line": line });
                    let _ = probe_bus.send(
                        Dispatch::to(
                            Address::Topic(Topic::new(SEER_TOPIC)),
                            frame.to_string().into_bytes(),
                        )
                        .with_schema(CONTROL_PROGRESS_SCHEMA),
                    );
                };
                let mut ctx = VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, cb, &ai, true);
                ctx.transport = tr;
                let res = run_verb(verb, &mut ctx, &mut progress);
                let payload = serde_json::to_vec(&res).unwrap_or_else(|_| b"{}".to_vec());
                let mut d = Dispatch::to(reply_to, payload).with_schema(CONTROL_RESULT_SCHEMA);
                if let Some(c) = corr {
                    d = d.with_corr(c);
                }
                let _ = probe_bus.send(d);
            }
        });
        match spawned {
            Ok(h) => self.worker = Some(h),
            Err(e) => {
                // No worker → the orchestration verbs error out (the dropped `rx` makes the next
                // `job_tx.send` fail, which `handle` reports). Inline reads are unaffected.
                eprintln!("omni: failed to spawn the orchestration worker: {e}");
            }
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // We only speak the control contract; anything else delivered here is ignored (R9).
        if env.header.schema != CONTROL_SCHEMA {
            return Outcome::none();
        }
        let verb = match serde_json::from_slice::<Verb>(&env.payload) {
            Ok(v) => v,
            Err(e) => {
                return reply(
                    &env,
                    VerbResult::err(
                        json!({ "error": "bad-control-verb", "detail": e.to_string() }),
                        format!("control: could not parse the verb: {e}"),
                    ),
                )
            }
        };

        if needs_probe(&verb) {
            // Hand the request/reply verb to the worker; it emits the reply when done. `handle`
            // returns immediately, so a cold `author` never stalls the kernel's drain thread.
            let job = Job { verb, reply_to: env.reply_target(), corr: env.header.corr };
            match &self.job_tx {
                Some(tx) if tx.send(job).is_ok() => Outcome::none(),
                _ => reply(
                    &env,
                    VerbResult::err(
                        json!({ "error": "control-worker-unavailable" }),
                        "control: the orchestration worker is unavailable",
                    ),
                ),
            }
        } else {
            // Fast, probe-free verb — answer inline. `gated: true`: control over the bus is a
            // remote front-end, so the allow-AI gate applies exactly as it does on the HTTP plane
            // (the local REPL, which is never gated, drives `run_verb` directly, not via the bus).
            let Some(kernel) = self.kernel.upgrade() else { return Outcome::none() };
            let mut noop = |_: &str| {};
            let mut ctx = VerbCtx::no_probe(&kernel, self.critter_builder, &self.ai, true);
            ctx.transport = self.transport;
            let res = run_verb(verb, &mut ctx, &mut noop);
            reply(&env, res)
        }
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        // Close the job channel so the worker's `recv` returns `Err` and the thread exits, then
        // join it (kernel-driven teardown: no leaked thread at the post-shutdown tid snapshot).
        self.job_tx = None;
        if let Some(w) = self.worker.take() {
            let _ = w.join();
        }
    }
}
