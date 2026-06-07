//! The ABI seam — one kernel-facing trait every tier implements, plus what a creature emits.

use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sigil::Manifest;

use crate::address::{Address, CreatureId};
use crate::bus::Bus;
use crate::envelope::Envelope;

/// What a creature emits — only the fields it controls. The bus seals identity (`from`), order
/// (`seq`) and permission (`sig`); the router seals time (`stamp`). A creature cannot forge them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Dispatch {
    pub to: Address,
    /// Where the eventual reply should go (preserved across relays). `None` → the immediate sender.
    pub reply_to: Option<Address>,
    pub payload: Vec<u8>,
    pub schema: String,
    pub corr: Option<u64>,
    pub commitment: Option<String>,
}

impl Dispatch {
    /// A bare dispatch to an address with a byte payload.
    pub fn to(to: Address, payload: Vec<u8>) -> Self {
        Dispatch {
            to,
            reply_to: None,
            payload,
            schema: String::new(),
            corr: None,
            commitment: None,
        }
    }
    pub fn with_schema(mut self, schema: impl Into<String>) -> Self {
        self.schema = schema.into();
        self
    }
    pub fn with_corr(mut self, corr: u64) -> Self {
        self.corr = Some(corr);
        self
    }
    /// Address replies somewhere other than this sender (a requester points them at itself; a relay
    /// preserves the original requester's address).
    pub fn with_reply_to(mut self, addr: Address) -> Self {
        self.reply_to = Some(addr);
        self
    }
    /// Attach (or relay) the commit-and-reveal slot. Used by relays — e.g. the realm-gateway
    /// — that must carry a sender's commitment forward without owning the scheme.
    pub fn with_commitment(mut self, commit: impl Into<String>) -> Self {
        self.commitment = Some(commit.into());
        self
    }

    /// Build a reply to `env`: addressed to [`Envelope::reply_target`] (its `reply_to` if set, else
    /// its `from`), with the request's `corr` preserved (fire-and-correlate) and `schema` defaulted
    /// to the request's — override the schema with [`Dispatch::with_schema`] when the reply carries a
    /// distinct one. The single home for reply construction;
    /// [`Outcome::reply`] is a thin wrapper over it.
    pub fn reply_to_env(env: &Envelope, payload: Vec<u8>) -> Self {
        Dispatch {
            to: env.reply_target(),
            reply_to: None,
            payload,
            schema: env.header.schema.clone(),
            corr: env.header.corr,
            commitment: None,
        }
    }
}

/// Severity of a [`BudgetSignal`] — limits as gradients.
///
/// The framework distinguishes *advisory* trajectory signals from *terminal* limit hits. Both
/// levels are live: the wasm (beast) engine emits [`SignalLevel::Warn`] at an operator-declared
/// threshold *before* the trap, and [`SignalLevel::Hard`] when the limit is actually hit. The
/// fabric never decides what counts as graceful; that's the injected policy's job.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SignalLevel {
    /// Advisory — the creature crossed an operator-configured threshold (e.g. 90% of the fuel cap)
    /// but the hard limit hasn't been hit. **Live:** the wasm engine emits this after a
    /// successful handle whose consumption crossed `capabilities.budget_warn_at`, and the kernel
    /// honors the policy's `KernelControl::ExtendBudget` reply. The native engine has no metering,
    /// so it never emits `Warn` — only `Hard`.
    Warn,
    /// The hard limit was hit; the creature trapped. Emitted by every metering engine on a breach.
    Hard,
}

/// Which quantitative dimension a [`BudgetSignal`] is about.
///
/// `Fuel`, `Memory`, and `Wall` are engine-enforced kinds where a tier can measure them. The beast
/// tier enforces all three; other tiers enforce the subset they can measure. A policy reacting to
/// "this handle took 30s" binds to the same shape as a fuel breach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum LimitKind {
    /// `cpu_ms` budget (wasmtime fuel for beasts).
    Fuel,
    /// `mem_bytes` budget (linear-memory grow refused by the limiter for beasts).
    Memory,
    /// `wall_ms` budget (per-envelope wall time). Engine-enforced for the **beast** tier via wasmtime
    /// epoch interruption (one engine-global ticker); other tiers leave it unenforced.
    Wall,
}

/// The raw scalars the fabric measures and ships alongside a [`BudgetSignal`].
///
/// The fabric ships the **numerator and denominator** from which any tolerance / velocity / curve
/// model can be computed. A "progress looks steady, grant grace" model, a "last 1% hides 1000% of
/// the work" abuser detector, an exponential-backoff escalator — all live in the injected policy.
/// The substrate's commitment is the *shape*, not per-field exactitude: a value an engine can't
/// measure cheaply is zero, and a richer engine later fills it without changing the wire.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetVector {
    /// Amount consumed of the limited dimension in this call (fuel units for `Fuel`, bytes for
    /// `Memory`, ms for `Wall`). Best-effort.
    pub consumed: u64,
    /// The declared cap (per-envelope for `Fuel`, total for `Memory`, per-envelope for `Wall`).
    /// `0` means "no cap declared" (the dev default).
    pub limit: u64,
    /// How many envelopes the creature emitted in the current handle call. Lets a policy tell
    /// "useful work then ran out" apart from "no progress then ran out" without subscribing to
    /// FITNESS separately.
    pub dispatches_this_envelope: u32,
    /// Wall-clock ms the engine measured for this handle call. Best-effort; an engine that doesn't
    /// measure wall time leaves this at zero.
    pub wall_ms_elapsed: u64,
    /// How many envelopes this creature has handled since `bind`. Lets a policy weigh "first-call"
    /// differently from "100th-call" without per-creature bookkeeping. Best-effort.
    pub envelopes_since_load: u64,
}

/// A signal from the fabric to the policy about a creature's relationship to a quantitative limit.
/// Limits as gradients.
///
/// **Fabric, not model.** The substrate ships the level + the kind + the vector; what counts as
/// graceful, abusive, or worth granting grace lives entirely in an injected policy creature.
/// The wasm engine fills both levels — `Warn` at the operator-declared
/// threshold and `Hard` on the trap; the wire also accepts richer trajectory signals
/// (multi-envelope velocity) under the same type as engines grow, without a creature-side migration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BudgetSignal {
    pub level: SignalLevel,
    pub kind: LimitKind,
    pub vector: BudgetVector,
}

impl BudgetSignal {
    /// Construct a `Hard` signal — emitted when the limit was hit and the creature trapped.
    pub fn hard(kind: LimitKind, vector: BudgetVector) -> Self {
        BudgetSignal { level: SignalLevel::Hard, kind, vector }
    }
    /// Construct a `Warn` signal — emitted by the wasm engine when a successful handle crossed the
    /// operator-declared `budget_warn_at` threshold before the trap.
    pub fn warn(kind: LimitKind, vector: BudgetVector) -> Self {
        BudgetSignal { level: SignalLevel::Warn, kind, vector }
    }
}

/// The result of handling one envelope: zero or more envelopes to emit. (A creature may also send
/// proactively via its [`BusHandle`](crate::BusHandle); both paths go through the one router.)
///
/// **Local-delivery ordering contract.** The kernel drains `dispatches` in
/// **push order** (it iterates the `Vec` front-to-back, calling `BusHandle::send` on each), and a
/// local creature's inbox is a **single-consumer FIFO** channel. So two dispatches in the *same*
/// `Outcome` addressed to the *same* local creature arrive at that creature in the order they were
/// pushed. A creature may rely on this for a local same-target sequence — e.g. a `PublishInRealm`
/// pushed before its `AttestFitness` lands first (`omega-federator`'s anti-entropy merge). The
/// guarantee is **local only**: `transport-tcp` offers no cross-node / cross-creature ordering, so
/// a sequence whose target may be off-node must confirm step *n* before emitting step *n+1* rather
/// than rely on push order.
///
/// **`budget_signal` is the IoC seam** for resource-limit observations (see [`BudgetSignal`]).
/// The default is `None` — a creature that emits no signal (native, the plain beast, every test
/// path) keeps the same shape, so this is **additive**: the engine that detects a trap (or a
/// threshold crossing) fills it; everyone else ignores it; the kernel publishes a proprio event
/// when it's present.
#[derive(Clone, Debug, Default)]
pub struct Outcome {
    pub dispatches: Vec<Dispatch>,
    pub budget_signal: Option<BudgetSignal>,
}

impl Outcome {
    pub fn none() -> Self {
        Outcome::default()
    }
    pub fn send(d: Dispatch) -> Self {
        Outcome { dispatches: vec![d], budget_signal: None }
    }
    /// Mark this outcome as carrying a [`BudgetSignal`]. The dispatches list is usually empty (the
    /// creature trapped before producing a reply on a `Hard` signal), but a `Warn` signal rides
    /// alongside the creature's normal reply on a successful handle — `budget_signal` is metadata,
    /// not a discriminant.
    pub fn budget_signal(signal: BudgetSignal) -> Self {
        Outcome { dispatches: Vec::new(), budget_signal: Some(signal) }
    }
    /// Reply to `env`: to its `reply_to` if set (the original requester, across relays), else to its
    /// immediate `from`. Preserves the correlation id (fire-and-correlate). A thin wrapper over
    /// [`Dispatch::reply_to_env`].
    pub fn reply(env: &Envelope, payload: Vec<u8>) -> Self {
        Outcome::send(Dispatch::reply_to_env(env, payload))
    }
    pub fn push(&mut self, d: Dispatch) {
        self.dispatches.push(d);
    }
}

/// The unload-safety bound: the budget the kernel allows a creature's `shutdown` before it proceeds
/// with teardown. This is the *one* deliberately real-time quantity (so unload can't hang) —
/// distinct from logical envelope `stamp`. Any *envelope* SLA is injected policy, not this.
#[derive(Clone, Copy, Debug)]
pub struct Deadline(pub Duration);

impl Deadline {
    pub fn from_millis(ms: u64) -> Self {
        Deadline(Duration::from_millis(ms))
    }
}
impl Default for Deadline {
    fn default() -> Self {
        Deadline::from_millis(1000)
    }
}

/// What the kernel hands a creature at `bind`: its identity, its bus authority, its manifest. This
/// is a creature's **only** ambient authority — there is no global to reach for, which is also what
/// lets a sandboxed beast be real (it can reach nothing else).
pub struct CreatureCtx {
    pub me: CreatureId,
    /// The creature's only outward authority — an abstract [`Bus`], so the same `Creature`
    /// works in-process (a real `BusHandle`) or across FFI (a native shim that serializes).
    ///
    /// **`Arc<dyn Bus>` (not `Box`) by design:** a creature that spawns worker threads
    /// (the transport-tcp listener+dialers, a future logging fan-out, anything with a managed
    /// `forge::spawn`) needs to share its bus across those threads. The arc costs nothing on
    /// the single-owner path (native FFI: one drop on `destroy`) and unlocks the multi-thread
    /// path without a clone-box dance on the `Bus` trait.
    pub bus: Arc<dyn Bus>,
    pub manifest: Manifest,
}

/// The one kernel-facing trait, across all tiers. `handle` is the only interaction verb — a
/// single entrypoint rather than a family of per-concern method traits.
pub trait Creature: Send {
    /// Called once after load, before any `handle`. The creature stashes its [`CreatureCtx`].
    fn bind(&mut self, ctx: CreatureCtx);

    /// Handle one envelope; return envelopes to emit. Should not panic on hostile input — a panic
    /// is caught at the boundary and routed to this creature's unload, never fatal to the kernel.
    fn handle(&mut self, env: Envelope) -> Outcome;

    /// Graceful stop within `deadline`. **Kernel-driven**: the creature does no teardown of its own
    /// lifecycle; it only releases what it owns.
    fn shutdown(&mut self, deadline: Deadline) {
        let _ = deadline;
    }
}
