//! sanctum — the GAWD kernel: a tiny, **model-free** core doing exactly three jobs.
//!
//! 1. **Lifecycle** — load/unload creatures via the tier engines (`anima`).
//! 2. **Routing** — own the bus [`Router`] (the address table, role bindings, topics, journal).
//! 3. **Admission** — run the verify *mechanism*, consult the injected *policy* for the decision.
//!
//! It holds no capability and no model of its own, which is why it stays small and is the fixed
//! fabric an AI cannot re-author — everything woven *on* it (logging, transport, the resolver, the
//! policy, every app) is a hot-swappable creature.
//!
//! **Unload is kernel-driven.** The kernel — not the creature — owns each creature's drain thread.
//! Unload deregisters (so no new envelopes
//! arrive), lets the drain thread finish in-flight work and `shutdown`, then drops the loaded module
//! in field-declaration order (instance → tier resources, i.e. native `destroy` then `dlclose`),
//! and joins the thread — in one place.

use std::collections::{HashMap, HashSet};
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::thread::JoinHandle;

use aether::{
    Address, BudgetSignal, BudgetVector, BusHandle, Creature, CreatureCtx, CreatureId, Deadline,
    Dispatch, Envelope, InboxReceiver, LimitKind, Role, RouteError, Router, SignalLevel, Signer,
    Topic, Verifier,
};
use anima::{Artifact, BudgetControl, Engine, EngineError, LoadedModule};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sigil::{Backend, Capabilities, Manifest, ManifestError};

/// Poison-tolerant `Mutex` acquisition (R9 fabric-integrity floor): recover the guard instead of
/// cascading one panic into permanent kernel-wide lock failure. Sound for the kernel's locks — they
/// guard plain owned maps (`loaded`, `control_thread`) with no cross-field invariant a mid-section
/// panic could leave half-broken. Especially load-bearing on the `Drop` / `shutdown_all` teardown
/// path: a panic from a poisoned `.lock().unwrap()` *during unwind* would abort the whole process
/// via double-panic, defeating the very isolation R9 exists to provide.
#[inline]
fn mlock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Kernel control ops are tiny (`Unload`, `ExtendBudget`). Cap them before serde so a hostile
/// envelope cannot hide a huge ignored JSON field inside an otherwise-valid control op.
const MAX_KERNEL_CONTROL_BYTES: usize = 64 * 1024;

/// The FITNESS topic, allocated once — used both to *check* for subscribers (the no-listener
/// fast-path that avoids doubling bus traffic on the per-envelope sense) and, when one exists, to
/// address the event. (PROPRIOCEPTION events fire only on load/unload/leak, so that path is not a
/// hot loop and is not gated.)
fn fitness_topic() -> &'static Topic {
    static T: OnceLock<Topic> = OnceLock::new();
    T.get_or_init(|| Topic::new(Topic::FITNESS))
}

/// Admission **policy** — the injected decision-maker. The kernel runs the *mechanism* (validate,
/// verify, content-address); a `Policy` supplies the *model* (what to require, which roots to trust).
/// Injected at construction; making it a hot-swappable bus creature bound to [`Role::POLICY`]
/// is a later step (it avoids an admission bootstrap). The fabric ships the gate + this socket,
/// never a model of its own.
pub trait Policy: Send + Sync {
    fn admit(&self, manifest: &Manifest, evidence: &Admission) -> Result<(), String>;
}

/// What the admission *mechanism* observed, handed to the injected [`Policy`] for the decision.
///
/// Two integrity facts ride here, and they're distinct on purpose:
/// - `content_address_matches` is **self-consistency of the manifest** — does the declared
///   `content_address` equal `sha256(name || version || build_hash)`? Cheap, no artifact read.
/// - `artifact_hash_matches` is **the artifact-to-manifest binding** — does
///   `sha256(artifact bytes)` equal the manifest's `provenance.build_hash`? This is the real
///   "did the bytes get tampered with on the wire / on disk" check, and it is the gate behind
///   bit-flip rejection. Computed when an artifact is in hand (`load`); skipped when an in-process
///   `Creature` is installed without an artifact (`load_instance`, boot creatures).
///
/// `had_artifact` lets a policy tell the dynamic-load case apart from the boot-creature case
/// without overloading `Option`-vs-`Option` semantics — a strict policy enforces build_hash only
/// when there *were* bytes to hash.
#[derive(Clone, Debug)]
pub struct Admission {
    pub signature_present: bool,
    pub signature_valid: bool,
    pub content_address_declared: Option<String>,
    /// `Some(true/false)` if the manifest declared a content address (whether it matches recompute);
    /// `None` if it declared none.
    pub content_address_matches: Option<bool>,
    /// Whether the manifest declared a `provenance.build_hash` (the artifact-bytes hash).
    pub artifact_hash_declared: bool,
    /// `Some(true/false)` if both an artifact is present and a `build_hash` was declared;
    /// `None` if no artifact (in-process load) or no `build_hash` to compare against.
    pub artifact_hash_matches: Option<bool>,
    /// `true` on `Kernel::load` (an artifact was on hand), `false` on `Kernel::load_instance`.
    /// Lets the policy decide whether the artifact-hash gate applies at all.
    pub had_artifact: bool,
}

/// Liveness sense (proprioception) — operating-model Loops 1/4. Published on load/unload.
#[derive(Serialize, Deserialize, Debug)]
pub struct Proprioception {
    pub creature: u64,
    pub event: String,
}

/// Outcome sense (fitness) — operating-model Loop 2 (selection). Published per handled envelope.
#[derive(Serialize, Deserialize, Debug)]
pub struct Fitness {
    pub creature: u64,
    pub ok: bool,
}

/// A creature's relationship to a declared resource limit. Published on
/// the proprioception topic when an engine surfaces [`aether::Outcome::budget_signal`].
/// **Best-effort, observability only**: the kernel never decides what to do next — an *injected*
/// policy creature subscribes and decides (kill, demote-tier, raise budget, grant grace,
/// log-and-continue). The substrate ships the signal; the model is hot-swappable.
///
/// String `level`/`kind` (not enums) so non-Rust subscribers don't need to link `aether`'s types:
/// `level` is `"warn"` | `"hard"`; `kind` is `"fuel"` | `"memory"` | `"wall"`. The `vector` carries
/// raw scalars from which any tolerance / velocity / curve model can be computed by the policy
/// creature — the fabric ships numerator + denominator, never the curve. Wasm and script engines
/// emit fuel/memory warnings where supported and hard wall breaches; wall is hard-only because the
/// deadline is detected when it expires rather than at a predictive warning threshold.
#[derive(Serialize, Deserialize, Debug)]
pub struct BudgetSignalEvent {
    pub creature: u64,
    pub level: String,
    pub kind: String,
    pub vector: BudgetVector,
}

/// **Creature-initiated grace ask.** A creature realizing it's going to need
/// more resource than its declared cap allows can publish this on the proprioception topic; an
/// injected policy creature reads, weighs the `justification` against whatever trajectory model it
/// has, and either issues `KernelControl::ExtendBudget` or ignores. Fabric ships the schema +
/// addressing seam; policy decides when (and whether) to grant.
///
/// No engine/SDK helper publishes this automatically; a creature that wants grace sends a
/// `budget_request` envelope, and an injected policy such as `policy_budget::BudgetGraceful`
/// consumes it and may grant `ExtendBudget`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BudgetRequest {
    pub creature: u64,
    pub fuel: Option<u64>,
    pub mem_bytes: Option<u64>,
    pub wall_ms: Option<u64>,
    pub justification: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SenseDecodeError {
    #[error("sense event payload too large: {len} bytes exceeds {limit} byte limit")]
    TooLarge { len: usize, limit: usize },
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

fn decode_sense_payload<T: DeserializeOwned>(payload: &[u8]) -> Result<T, SenseDecodeError> {
    if payload.len() > aether::MAX_SENSE_EVENT_BYTES {
        return Err(SenseDecodeError::TooLarge {
            len: payload.len(),
            limit: aether::MAX_SENSE_EVENT_BYTES,
        });
    }
    Ok(serde_json::from_slice(payload)?)
}

pub fn decode_budget_signal_event(payload: &[u8]) -> Result<BudgetSignalEvent, SenseDecodeError> {
    decode_sense_payload(payload)
}

pub fn decode_budget_request(payload: &[u8]) -> Result<BudgetRequest, SenseDecodeError> {
    decode_sense_payload(payload)
}

#[derive(Debug, thiserror::Error)]
pub enum KernelError {
    #[error("admission rejected: {0}")]
    AdmissionRejected(String),
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    #[error("no engine configured for backend {0:?}")]
    NoEngine(Backend),
    #[error(transparent)]
    Engine(#[from] EngineError),
    #[error("no such creature: {0:?}")]
    NoSuchModule(CreatureId),
    /// The creature's drain thread did not exit within the unload deadline. The kernel returns
    /// (abandoning the drain) so the caller — and the reload loop — never hangs on a misbehaving
    /// creature. The thread continues running detached; its eventual `dlclose` is a bounded leak
    /// rather than UB. **The reload loop reads this as "this cycle leaked one library."**
    #[error("unload {0:?} exceeded deadline; drain abandoned (bounded leak, not UB)")]
    UnloadTimeout(CreatureId),
}

struct Loaded {
    /// Surfaced by [`Kernel::roster`] for a `list`/status introspection surface.
    name: String,
    /// Surfaced by [`Kernel::roster`].
    backend: Backend,
    /// Immutable manifest identity retained for model-free deployment liveness checks.
    manifest_content_address: Option<String>,
    /// Artifact-byte pin declared by the admitted manifest.
    artifact_build_hash: Option<String>,
    /// SHA-256 recomputed from the artifact bytes actually passed to [`Kernel::load`]. `None` for
    /// in-process boot creatures because they have no artifact boundary.
    artifact_sha256: Option<String>,
    drain: JoinHandle<()>,
    deadline_ms: Arc<AtomicU64>,
    /// Sent once by the drain thread as the last thing it does (after the safe-unload drop sequence).
    /// `recv_timeout` is the kernel's join-with-timeout primitive — `JoinHandle::join` has no built-in
    /// timeout, and a misbehaving creature must not hang the kernel forever.
    done_signal: Receiver<()>,
    /// The creature's live resource-ceiling control, `Some` for metered wasm and script tiers. Held
    /// here (not on the drain thread that owns the instance) so [`Kernel::extend_budget`] can lift a
    /// budget on a `KernelControl::ExtendBudget` grant without reaching across the thread boundary.
    budget: Option<BudgetControl>,
}

/// Model-free identity of one currently routable creature.
///
/// This exposes only immutable admission facts needed to compare a durable deployment pin with the
/// process-local `CreatureId` that currently occupies it. Trust and placement decisions remain in
/// injected creatures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadedManifestIdentity {
    pub creature: CreatureId,
    pub manifest_content_address: Option<String>,
    /// Author-declared `Manifest.provenance.build_hash`.
    pub artifact_build_hash: Option<String>,
    /// Hash of the bytes actually admitted and loaded, independent of admission policy. Function
    /// deployment liveness must use this fact rather than trusting the manifest declaration.
    pub artifact_sha256: Option<String>,
}

pub struct Kernel {
    router: Arc<Router>,
    engines: HashMap<Backend, Arc<dyn Engine>>,
    signer: Arc<dyn Signer>,
    /// Shared kernel-owned sender for terminal lifecycle facts emitted after a creature has crossed
    /// the deregistration boundary. Every clone shares one sequence counter for [`aether::KERNEL_ID`].
    lifecycle_bus: BusHandle,
    verifier: Arc<dyn Verifier>,
    policy: Arc<dyn Policy>,
    loaded: Mutex<HashMap<CreatureId, Loaded>>,
    /// **Control listener.** Drains envelopes addressed to [`Address::Kernel`] and dispatches
    /// [`KernelControl`] ops (e.g. `Unload`). Stored so `Drop` can join cleanly. `None` only inside
    /// the `Kernel::new` window before the thread is spawned — never observable from outside.
    control_thread: Mutex<Option<JoinHandle<()>>>,
}

/// The kernel's control op vocabulary. Envelopes addressed to [`Address::Kernel`] with
/// `schema = "kernel_control"` carry one of these as a JSON payload. The kernel's control
/// listener dispatches them. This is how an *injected* creature (a budget policy, a future
/// supervision creature) asks the kernel to act — IoC-pure: no creature ever holds an
/// `Arc<Kernel>` directly.
///
/// `ExtendBudget` is **honored** — the listener asks the selected tier's live budget control to lift
/// each supported dimension (see [`Kernel::extend_budget`]). Future ops
/// (Load, Reload, RotateRole, ProvisionEndpoint) can be added without changing the dispatcher's
/// shape — that's why it's an enum.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op")]
pub enum KernelControl {
    /// Unload the named creature (deregister → drain → engine-unload). Best-effort:
    /// the kernel's `unload` carries its own deadline + leak-path semantics; the requester gets
    /// no synchronous reply (control is fire-and-forget by design — an answer would need a
    /// reply_to / corr round-trip the requester is free to add later).
    Unload { module: u64 },
    /// **Honored, per dimension.** Raise a live creature's resource caps so an injected
    /// policy can grant grace after a `Warn`-level [`BudgetSignalEvent`] (or a creature's
    /// `BudgetRequest`). Each field is `Option<u64>`: `Some(new_cap)` lifts the named dimension to
    /// that value, `None` leaves it untouched. The control listener calls [`Kernel::extend_budget`],
    /// which returns a per-dimension [`ExtendOutcome`]. What each tier can live-lift: **beast (wasm)**
    /// — fuel, memory, and wall (the live fuel cell, the live `ResourceLimiter` mem cell, and the live
    /// epoch wall cell); **critter (Rhai)** — fuel (operation budget) and wall (the `on_progress`
    /// watchdog), but **not** memory (its structural caps are fixed at load); **native** — none
    /// (trusted-by-admission, no live control). A dimension a tier cannot honor is reported
    /// `Unenforceable` and surfaced by the listener — never a silent no-op.
    ExtendBudget { module: u64, fuel: Option<u64>, mem_bytes: Option<u64>, wall_ms: Option<u64> },
}

/// One dimension's result inside an [`ExtendOutcome`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtendDim {
    /// The grant left this dimension untouched (`None` on the wire).
    NotRequested,
    /// The tier honored the live lift — the creature's next handle runs with the new cap.
    Applied,
    /// The tier accepts this dimension on the wire but cannot honor a *live* lift (e.g. native's
    /// no-metering, or a critter memory lift). Reported, never silently dropped.
    Unenforceable,
}

impl ExtendDim {
    fn for_request(requested: bool, enforces: bool) -> Self {
        match (requested, enforces) {
            (false, _) => ExtendDim::NotRequested,
            (true, true) => ExtendDim::Applied,
            (true, false) => ExtendDim::Unenforceable,
        }
    }
}

/// The per-dimension outcome of a [`Kernel::extend_budget`] grant. The honest-fail floor: an
/// `ExtendBudget` can never silently no-op — the caller learns exactly which dimensions took effect,
/// which the tier cannot honor, and whether the creature was even live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtendOutcome {
    /// No live creature matched the id — the whole grant was a no-op.
    pub unknown_creature: bool,
    pub fuel: ExtendDim,
    pub mem: ExtendDim,
    pub wall: ExtendDim,
}

impl ExtendOutcome {
    fn unknown() -> Self {
        ExtendOutcome {
            unknown_creature: true,
            fuel: ExtendDim::NotRequested,
            mem: ExtendDim::NotRequested,
            wall: ExtendDim::NotRequested,
        }
    }
    /// Whether at least one requested dimension was actually applied.
    pub fn any_applied(&self) -> bool {
        [self.fuel, self.mem, self.wall].contains(&ExtendDim::Applied)
    }
    /// Whether any requested dimension could not be honored by the creature's tier.
    pub fn any_unenforceable(&self) -> bool {
        [self.fuel, self.mem, self.wall].contains(&ExtendDim::Unenforceable)
    }
}

impl Kernel {
    pub fn new(
        engines: Vec<Arc<dyn Engine>>,
        signer: Arc<dyn Signer>,
        verifier: Arc<dyn Verifier>,
        policy: Arc<dyn Policy>,
        inbox_capacity: usize,
    ) -> Arc<Kernel> {
        let router = Arc::new(Router::new(verifier.clone(), inbox_capacity));
        let mut map: HashMap<Backend, Arc<dyn Engine>> = HashMap::new();
        for e in engines {
            map.insert(e.backend(), e);
        }
        // **Control inbox.** Register the kernel's own inbox under the reserved KERNEL_ID; the
        // dispatcher thread (spawned just below, once the `Arc<Kernel>` exists) listens on it.
        // Done BEFORE the kernel is wrapped so the receiver belongs to the listener.
        let control_rx = router.register_kernel();
        // Terminal lifecycle facts are known only after the creature has been deregistered, when
        // its own BusHandle is intentionally stale. Keep one kernel-owned handle and clone it into
        // drains so every KERNEL_ID emission shares a single monotone sequence counter.
        let lifecycle_bus = BusHandle::new(aether::KERNEL_ID, router.clone(), signer.clone());
        let kernel = Arc::new(Kernel {
            router,
            engines: map,
            signer,
            lifecycle_bus,
            verifier,
            policy,
            loaded: Mutex::new(HashMap::new()),
            control_thread: Mutex::new(None),
        });
        // Spawn the control dispatcher with a `Weak` ref — the kernel can drop normally; when it
        // does, the router's senders close and `recv` returns `Err` → thread exits cleanly.
        let weak = Arc::downgrade(&kernel);
        match std::thread::Builder::new()
            .name("sanctum-control".into())
            .spawn(move || run_control_listener(weak, control_rx))
        {
            Ok(join) => *mlock(&kernel.control_thread) = Some(join),
            Err(e) => eprintln!(
                "sanctum: failed to spawn control listener; KernelControl envelopes disabled: {e}"
            ),
        }
        kernel
    }

    /// The bus router — for binding roles (IoC sockets), subscribing to topics, opening endpoints.
    pub fn router(&self) -> Arc<Router> {
        self.router.clone()
    }

    /// Admission: the *mechanism* (structural validation + signature verification + content-address
    /// recompute + artifact-bytes hash, if an artifact is in hand) then the injected *policy*.
    /// The manifest is the one metadata source (**R6**).
    ///
    /// `artifact` is `None` on `load_instance` (in-process boot creature — no bytes to hash) and
    /// `Some(&art)` on `load`. The mechanism never decides on the evidence; it just gathers and
    /// hands it to the policy. The policy decides what counts as enough.
    fn admit(
        &self,
        manifest: &Manifest,
        artifact: Option<&Artifact>,
    ) -> Result<Option<String>, KernelError> {
        manifest.validate()?;
        let sig = manifest.provenance.signature.clone();
        let signature_present = sig.is_some();
        let signature_valid = match (&manifest.provenance.author, &sig) {
            (Some(author), Some(s)) => self.verifier.verify(author, &manifest.signing_payload(), s),
            _ => false,
        };
        let content_address_matches =
            manifest.content_address.as_ref().map(|a| *a == manifest.compute_content_address());
        // **Artifact integrity gate.** Hash the actual bytes (file or in-memory) and compare to
        // the manifest's declared `provenance.build_hash`. A bit-flip anywhere in flight produces
        // a mismatch; the policy then rejects. We do this BEFORE engine `load` — the artifact
        // bytes never reach `dlopen` if the hash doesn't match. For native sources `Kernel::load`
        // has already streamed the one opened source descriptor into a retained stage (sealed
        // memfd on Linux/Android, random/read-only without a same-UID claim elsewhere);
        // this reads that stage's construction hash, and NativeEngine later dlopens the same stage.
        // The path source remains O(1) memory and uncapped while byte-materializing tiers retain
        // `anima::MAX_ARTIFACT_BYTES`.
        let artifact_hash_declared = manifest.provenance.build_hash.is_some();
        let actual_artifact_hash = artifact
            .map(|artifact| {
                artifact.sha256_hex().map_err(|error| {
                    KernelError::AdmissionRejected(format!(
                        "artifact unreadable for integrity check: {error}"
                    ))
                })
            })
            .transpose()?;
        let artifact_hash_matches = actual_artifact_hash
            .as_ref()
            .zip(manifest.provenance.build_hash.as_ref())
            .map(|(actual, expected)| actual == expected);
        let evidence = Admission {
            signature_present,
            signature_valid,
            content_address_declared: manifest.content_address.clone(),
            content_address_matches,
            artifact_hash_declared,
            artifact_hash_matches,
            had_artifact: artifact.is_some(),
        };
        self.policy.admit(manifest, &evidence).map_err(KernelError::AdmissionRejected)?;
        Ok(actual_artifact_hash)
    }

    /// Load a creature from an artifact through its tier engine — the dynamic path (native `.so`,
    /// wasm, or Rhai). One path for all three tiers, differing only by `abi.backend` (**R1**, **R3**).
    pub fn load(&self, manifest: Manifest, artifact: Artifact) -> Result<CreatureId, KernelError> {
        let engine = self
            .engines
            .get(&manifest.abi.backend)
            .ok_or(KernelError::NoEngine(manifest.abi.backend))?
            .clone();
        // Resolve the mechanism before touching artifact bytes. A Sanctum without this tier must
        // report `NoEngine` deterministically even when the supplied path is not locally readable;
        // admission and byte hashing still happen before the selected engine sees the artifact.
        // Validate before staging so a structurally invalid manifest cannot make us copy a large
        // native source. Preparation then produces one representation shared by admission and the
        // engine: native streams into a retained sealed/best-effort stage; beast/critter paths are
        // opened once into bounded bytes.
        manifest.validate()?;
        let artifact = artifact.prepare_for_load(&manifest)?;
        let artifact_sha256 = self.admit(&manifest, Some(&artifact))?;
        let loaded = engine.load(&artifact, &manifest)?;
        Ok(self.install(manifest, loaded, false, artifact_sha256))
    }

    /// Install an already-constructed **in-process** creature (a boot creature: the transport
    /// gateway, the example resolver, a logger). Same admission + bus citizenship as a loaded
    /// artifact — it simply isn't a dynamic artifact, so the artifact-hash check is skipped.
    pub fn load_instance(
        &self,
        manifest: Manifest,
        instance: Box<dyn Creature>,
    ) -> Result<CreatureId, KernelError> {
        self.admit(&manifest, None)?;
        Ok(self.install(manifest, LoadedModule::new(instance, Box::new(())), false, None))
    }

    /// Like [`load_instance`](Kernel::load_instance), but grants this creature the **boot-only
    /// origin-attestation** capability — the privilege to seal an authenticated cross-node
    /// [`Origin`](aether::Origin) on inbound frames via [`Bus::emit_attested`](aether::Bus::emit_attested).
    /// This is the *only* way to obtain that grant; reserved for the transport gateway. A transport
    /// loaded through the ordinary path still relays, but without origin attribution.
    pub fn load_transport_instance(
        &self,
        manifest: Manifest,
        instance: Box<dyn Creature>,
    ) -> Result<CreatureId, KernelError> {
        self.admit(&manifest, None)?;
        Ok(self.install(manifest, LoadedModule::new(instance, Box::new(())), true, None))
    }

    /// Record this node's bus-signing public key — its ed25519 node identity, the same key the
    /// transport authenticates links with. With it set, the router's verify-on-delivery resolves the
    /// local sender's key and becomes a real check (instead of always exercising the negative
    /// branch). Call once at boot, after [`new`](Kernel::new), when the node has a cluster identity.
    pub fn set_node_identity(&self, pubkey: impl Into<String>) {
        self.router.set_local_pubkey(pubkey.into());
    }

    /// Register + spawn the drain thread. The kernel owns the thread (kernel-driven lifecycle).
    ///
    /// `attesting` grants the **boot-only origin-attestation** capability to this creature's
    /// `BusHandle` (see [`BusHandle::new_attesting`]). It is `true` only for the transport, loaded
    /// through [`load_transport_instance`](Kernel::load_transport_instance) — never for a dynamic
    /// artifact — so a loaded creature can never seal a cross-node origin.
    fn install(
        &self,
        manifest: Manifest,
        mut loaded: LoadedModule,
        attesting: bool,
        artifact_sha256: Option<String>,
    ) -> CreatureId {
        // Lift the live fuel-ceiling control out BEFORE the LoadedModule moves into the
        // drain thread — the kernel keeps it (keyed by CreatureId) so a later ExtendBudget reaches the
        // creature; the drain only needs instance + resources for unload.
        let budget = loaded.budget.take();
        let caps = manifest.capabilities.clone();
        let (id, rx) = self.router.register(caps);
        let bus = if attesting {
            BusHandle::new_attesting(id, self.router.clone(), self.signer.clone())
        } else {
            BusHandle::new(id, self.router.clone(), self.signer.clone())
        };
        let ctx = CreatureCtx { me: id, bus: Arc::new(bus.clone()), manifest: manifest.clone() };
        let deadline_ms = Arc::new(AtomicU64::new(Deadline::default().0.as_millis() as u64));
        let router = self.router.clone();
        let lifecycle_bus = self.lifecycle_bus.clone();
        let dl = deadline_ms.clone();
        // Drain → kernel completion signal. Capacity 1: the drain sends exactly one `()` at the very
        // end (or its sender drops on the rare case the drain panics outside the catch_unwinds — in
        // which case `recv_timeout` returns `Disconnected`, still observable as "thread is gone").
        let (done_tx, done_signal) = mpsc::sync_channel::<()>(1);
        let drain = std::thread::spawn(move || {
            run_drain(loaded, ctx, bus, lifecycle_bus, rx, id, router, dl, done_tx)
        });
        mlock(&self.loaded).insert(
            id,
            Loaded {
                name: manifest.name,
                backend: manifest.abi.backend,
                manifest_content_address: manifest.content_address,
                artifact_build_hash: manifest.provenance.build_hash,
                artifact_sha256,
                drain,
                deadline_ms,
                done_signal,
                budget,
            },
        );
        id
    }

    /// **Honor a budget grant, per dimension.** Lift a live creature's per-handle ceilings so its
    /// next handle runs with the new budget, and report — per dimension — what actually took effect.
    /// Each tier declares which dimensions it can live-lift on its [`BudgetControl`]: the beast (wasm)
    /// tier lifts fuel + memory + wall; the critter tier lifts fuel + wall (not memory); native is
    /// trusted-by-admission with no metering and exposes no control. A requested dimension a tier
    /// cannot honor returns [`ExtendDim::Unenforceable`] (the caller learns it was not honored, never
    /// a silent lie); an unknown creature returns [`ExtendOutcome::unknown_creature`].
    pub fn extend_budget(
        &self,
        module: CreatureId,
        fuel: Option<u64>,
        mem_bytes: Option<u64>,
        wall_ms: Option<u64>,
    ) -> ExtendOutcome {
        let loaded = mlock(&self.loaded);
        let Some(entry) = loaded.get(&module) else { return ExtendOutcome::unknown() };
        let Some(budget) = &entry.budget else {
            // Native: no live budget control, so every requested dimension is unenforceable.
            return ExtendOutcome {
                unknown_creature: false,
                fuel: ExtendDim::for_request(fuel.is_some(), false),
                mem: ExtendDim::for_request(mem_bytes.is_some(), false),
                wall: ExtendDim::for_request(wall_ms.is_some(), false),
            };
        };
        // Apply each requested-and-enforceable dimension to the live cell; report the rest honestly.
        if let (Some(cap), true) = (fuel, budget.enforces_fuel()) {
            budget.set_fuel(cap);
        }
        if let (Some(cap), true) = (mem_bytes, budget.enforces_mem()) {
            budget.set_mem(cap);
        }
        if let (Some(cap), true) = (wall_ms, budget.enforces_wall()) {
            budget.set_wall_ms(cap);
        }
        ExtendOutcome {
            unknown_creature: false,
            fuel: ExtendDim::for_request(fuel.is_some(), budget.enforces_fuel()),
            mem: ExtendDim::for_request(mem_bytes.is_some(), budget.enforces_mem()),
            wall: ExtendDim::for_request(wall_ms.is_some(), budget.enforces_wall()),
        }
    }

    /// Kernel-driven unload: set the shutdown budget, deregister (no new envelopes → the drain
    /// thread's `recv` disconnects), then **wait with timeout** for the drain to signal it has
    /// finished the safe-unload drop sequence (`shutdown` → drop instance → drop tier resources,
    /// i.e. `dlclose` **last**). After this, routing to `id` is a clean `NoSuchModule`, never UB.
    ///
    /// On deadline expiry the drain is **abandoned** (`JoinHandle` dropped, thread continues
    /// detached) and `UnloadTimeout` returned. This is the F9 honesty: native is trusted-by-admission,
    /// but a misbehaving creature must never hang the substrate. The detached drain eventually
    /// completes its drop sequence (or doesn't); the thread-count guard catches the doesn't-case
    /// and prevents `dlclose` of a `.so` whose threads are still live — bounded leak, not UAF.
    pub fn unload(&self, id: CreatureId, deadline: Deadline) -> Result<(), KernelError> {
        let entry = mlock(&self.loaded).remove(&id);
        let Some(entry) = entry else {
            return Err(KernelError::NoSuchModule(id));
        };
        entry.deadline_ms.store(deadline.0.as_millis() as u64, Ordering::Relaxed);
        self.router.deregister(id);
        match entry.done_signal.recv_timeout(deadline.0) {
            Ok(()) => {
                // Drain signaled completion of the drop sequence. The JoinHandle is then trivial to
                // wait on — the thread is already exiting. We join it to reap the OS thread handle
                // (a JoinHandle dropped without join detaches; here we want the reap).
                let _ = entry.drain.join();
                Ok(())
            }
            Err(RecvTimeoutError::Timeout) => {
                // The drain didn't finish the drop sequence in budget. We abandon it (the thread
                // runs on detached) and return — never hang the substrate. Log it so the bounded
                // .so leak is discoverable at the kernel, not just inferable from the proprio event.
                eprintln!(
                    "sanctum: unload of {id:?} exceeded its deadline; drain abandoned \
                     (bounded library leak, not UB)"
                );
                Err(KernelError::UnloadTimeout(id))
            }
            Err(RecvTimeoutError::Disconnected) => {
                // Drain panicked outside every catch_unwind (extremely unlikely — every step is
                // wrapped). The thread is gone; reap and report success: the creature IS off the bus,
                // which is the user-facing meaning of unload.
                let _ = entry.drain.join();
                Ok(())
            }
        }
    }

    /// Reap entries whose drain thread has self-exited (the creature panicked and pulled itself off
    /// the bus, so the caller never had reason to `unload`). Without this, every panic leaves a
    /// ghost entry in `Kernel.loaded` — fine for one cycle, a slow leak across an extended run.
    /// **F8.** Idempotent; called at the end of `shutdown_all`.
    pub fn reap_done(&self) {
        let mut loaded = mlock(&self.loaded);
        let done: Vec<CreatureId> = loaded
            .iter()
            .filter_map(|(id, e)| match e.done_signal.try_recv() {
                Ok(()) => Some(*id),
                Err(mpsc::TryRecvError::Disconnected) => Some(*id),
                Err(mpsc::TryRecvError::Empty) => None,
            })
            .collect();
        for id in done {
            if let Some(entry) = loaded.remove(&id) {
                let _ = entry.drain.join();
            }
        }
    }

    /// Bind a creature into an IoC socket (e.g. the resolver into [`Role::DISTRIBUTOR`]).
    pub fn bind_role(&self, role: Role, id: CreatureId) {
        self.router.bind_role(role, id);
    }

    /// Bind a local IoC socket and explicitly expose that exact binding to authenticated remote
    /// [`Address::NodeRole`] delivery. Ordinary [`bind_role`](Self::bind_role)
    /// remains local-only and overwrites any prior exposure, so remote reachability is opt-in at the
    /// trusted composition root rather than a manifest capability a creature can self-assert.
    pub fn bind_remote_role(&self, role: Role, id: CreatureId) {
        self.router.bind_remote_role(role, id);
    }

    /// The creature currently bound to `role`, if any. This reports role sockets only; it cannot
    /// prove that a particular decision model is subscribed to a topic. For example, ADR-0041's
    /// `policy-origin` baseline is a `PROPRIOCEPTION` subscriber, not an `IMMUNE_RESPONSE` role
    /// filling, so its composition root tracks that wiring explicitly.
    pub fn role_binding(&self, role: &Role) -> Option<CreatureId> {
        self.router.role_binding(role)
    }

    /// Subscribe a creature to a topic (e.g. a logger to proprioception).
    pub fn subscribe(&self, topic: Topic, id: CreatureId) {
        self.router.subscribe(topic, id);
    }

    /// Open a bare bus endpoint with no creature/drain thread: the REPL and tests use it to inject
    /// envelopes and read replies directly.
    pub fn open_endpoint(&self, caps: Capabilities) -> (CreatureId, BusHandle, InboxReceiver) {
        let (id, rx) = self.router.register(caps);
        let bus = BusHandle::new(id, self.router.clone(), self.signer.clone());
        (id, bus, rx)
    }

    /// Put an envelope on the bus directly (the kernel as a sender; used by the control surface).
    pub fn route(&self, env: Envelope) -> Result<(), RouteError> {
        self.router.route(env)
    }

    /// Whether a creature is currently routable.
    pub fn is_loaded(&self, id: CreatureId) -> bool {
        self.router.is_registered(id)
    }

    /// Return the immutable manifest/artifact identity currently occupying an exact local id.
    ///
    /// `None` means the target is absent (or has already self-deregistered after a fault). Callers
    /// must compare both pins they rely on; numeric `CreatureId`s are process-local and may be reused
    /// after restart.
    pub fn loaded_manifest_identity(&self, id: CreatureId) -> Option<LoadedManifestIdentity> {
        if !self.router.is_registered(id) {
            return None;
        }
        mlock(&self.loaded).get(&id).map(|loaded| LoadedManifestIdentity {
            creature: id,
            manifest_content_address: loaded.manifest_content_address.clone(),
            artifact_build_hash: loaded.artifact_build_hash.clone(),
            artifact_sha256: loaded.artifact_sha256.clone(),
        })
    }

    /// How many creatures the kernel still has installed (including ghost entries from
    /// panic-self-deregister that have not yet been reaped). Useful for the reload loop's
    /// "no entry pile-up" assertion and for the F8 reap test.
    pub fn loaded_count(&self) -> usize {
        mlock(&self.loaded).len()
    }

    /// A snapshot of installed creatures — `(id, name, backend)` — for a `list`/node-status
    /// introspection surface (e.g. the daemon REPL). Reads the per-creature bookkeeping the kernel
    /// already keeps. Order is unspecified (a `HashMap` snapshot); callers sort if they want a
    /// stable view.
    pub fn roster(&self) -> Vec<(CreatureId, String, Backend)> {
        mlock(&self.loaded).iter().map(|(id, e)| (*id, e.name.clone(), e.backend)).collect()
    }

    /// Unload everything — clean node shutdown. Reaps any drain-finished entries afterwards so the
    /// kernel's loaded map is empty at exit (F8 — ghosts from panic-self-deregister get collected).
    ///
    /// **Unloads in reverse load order** (latest-bound first). `CreatureId`s are monotone, so a
    /// descending sort is reverse-chronological. This matters for the thread-count guard: that
    /// guard compares each dynamically loaded native creature's pre-bind tid snapshot against its
    /// post-shutdown one, and the snapshot is process-global. Tearing down latest-first means a
    /// native creature being unloaded only overlaps with *earlier*-bound creatures — whose drain
    /// threads were already present in its pre-bind snapshot, so they don't read as "leaked."
    /// Unloading in arbitrary order instead makes every still-loaded later creature's drain look
    /// like a fresh thread, tripping the bounded-leak path spuriously on a perfectly clean native
    /// unload. (The real fix for the underlying noise is per-creature thread accounting; this
    /// ordering removes the common false positive.)
    pub fn shutdown_all(&self, deadline: Deadline) {
        let mut ids: Vec<CreatureId> = mlock(&self.loaded).keys().copied().collect();
        ids.sort_unstable_by_key(|id| std::cmp::Reverse(id.0)); // descending = reverse load order
        for id in ids {
            let _ = self.unload(id, deadline);
        }
        self.reap_done();
    }
}

/// **F10**: dropping the kernel triggers a clean `shutdown_all` so a forgotten kernel does not
/// leave drain threads orphaned (and on native, libraries un-`dlclose`d). This fires only when the
/// last `Arc<Kernel>` is released, which is exactly when "the kernel is going away."
impl Drop for Kernel {
    fn drop(&mut self) {
        // Use the default deadline here — the Drop path is best-effort cleanup, not a place to
        // negotiate budgets. Any creature that needs more time should be unloaded explicitly.
        self.shutdown_all(Deadline::default());
        // **Control listener teardown.** Deregister the kernel inbox (closes the senders →
        // the listener's `recv` returns Err → thread exits its loop), then join. Best-effort: a
        // wedged listener should not block the drop path indefinitely — but the loop has no
        // sleep, no blocking call other than `recv`, so exit is immediate in practice.
        self.router.deregister(aether::KERNEL_ID);
        if let Some(j) = mlock(&self.control_thread).take() {
            let _ = j.join();
        }
    }
}

/// Snapshot the process's current thread IDs from `/proc/self/task/`. Linux-only; returns `None`
/// elsewhere so the **thread-count guard** silently no-ops on non-Linux (Linux-first;
/// other OSes can grow their own primitive later).
///
/// For a [`LoadedModule`] that owns a dynamically loaded native library, the guard compares
/// pre-bind and post-shutdown snapshots: any tid present after but not before indicates the
/// creature spawned a thread that didn't exit by `shutdown` (either it bypassed the SDK's managed
/// `spawn` and went raw, or its managed thread is still hanging). The kernel reacts by refusing to
/// `dlclose` that creature's library — a bounded leak rather than a UAF when a runaway thread later
/// dereferences now-unmapped code. Other module kinds never call this helper during unload.
///
/// Honest limit: a native module's snapshot includes ALL process tids, so concurrent activity from
/// other creatures can pollute its delta. The reload-loop test runs sequentially (no concurrent
/// loads) so its readings are clean; production concurrency may produce false positives → bounded
/// native-library leaks. The proper fix is per-creature thread accounting.
fn snapshot_tids() -> Option<HashSet<u32>> {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_dir("/proc/self/task").ok().map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter_map(|e| e.file_name().to_str().and_then(|s| s.parse::<u32>().ok()))
                .collect()
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// A creature's drain loop, owned by the kernel. Binds the creature, then delivers envelopes one at
/// a time, isolating any panic (R9). On stop (inbox disconnected or fault) it tears the creature
/// down in the safe order.
///
/// **Every call into the creature is panic-isolated.** `bind`, `handle`, `shutdown`, and the final
/// drop are each wrapped in `catch_unwind` — a panicking creature never crashes the kernel or
/// leaves the drain thread half-torn-down. The drop-ordering invariant (instance → resources,
/// native: `destroy` then `dlclose`) holds whether the creature behaves or not.
// The explicit loop/match below keeps the drain thread's panic-isolation + cleanup control flow
// legible; both lints are about style here, not a bug.
#[allow(clippy::too_many_arguments, clippy::while_let_loop)]
fn run_drain(
    mut loaded: LoadedModule,
    ctx: CreatureCtx,
    bus: BusHandle,
    lifecycle_bus: BusHandle,
    rx: InboxReceiver,
    me: CreatureId,
    router: Arc<Router>,
    deadline_ms: Arc<AtomicU64>,
    done_tx: SyncSender<()>,
) {
    // **Native-library thread guard, snapshot 1 of 2.** Only a dynamically loaded native module
    // can unmap executable code when its tier resources drop. In-process creatures and the
    // wasm/script engines therefore skip the process-wide snapshots entirely: their unrelated
    // runtime threads must never trigger the native `dlclose` leak path. Linux-only; `None` means
    // no guard (non-Linux fallback — accept the narrower contract there).
    let guard_unmanaged_threads = loaded.requires_unmanaged_thread_guard();
    let pre_bind_tids = if guard_unmanaged_threads { snapshot_tids() } else { None };

    // bind(ctx) may panic (in-process creatures only — native catches inside the SDK glue and
    // signals via RC_PANIC on the first `handle`). A panic here means we never enter the loop;
    // we go straight to cleanup so the safe-unload ordering still runs.
    let bind_ok = std::panic::catch_unwind(AssertUnwindSafe(|| loaded.instance.bind(ctx))).is_ok();
    if bind_ok {
        publish_proprio(&bus, me, "loaded");
        loop {
            match rx.recv() {
                Ok(env) => {
                    let result =
                        std::panic::catch_unwind(AssertUnwindSafe(|| loaded.instance.handle(env)));
                    match result {
                        Ok(outcome) => {
                            // Engine-surfaced budget signal: publish a
                            // proprio event with the full level/kind/vector trajectory so an
                            // *injected* policy creature can decide what to do (kill, demote, raise
                            // the budget, grant grace). The kernel itself never decides.
                            // The signal rides on PROPRIOCEPTION (observability), not
                            // FITNESS (a budget event isn't a creature "bug," it's a declared-quota
                            // trajectory event).
                            let mut budget_signal = outcome.budget_signal;
                            if let Some(signal) = budget_signal.as_mut() {
                                // **Kernel-side enrichment.** The engine can't
                                // see the outcome's dispatches list (it returns the Outcome and
                                // hands it off); the kernel can. Fill in `dispatches_this_envelope`
                                // here so an injected policy reading the vector gets the full
                                // bus-view trajectory: "did the creature emit work before the
                                // signal fired?" A productive Warn from a beast that replied (one
                                // dispatch) reads as `dispatches_this_envelope = 1`, which is what
                                // [`policy_budget::BudgetGraceful`]'s productive classifier needs.
                                signal.vector.dispatches_this_envelope =
                                    outcome.dispatches.len() as u32;
                            }
                            // Fitness here reflects "did the creature reply with useful work?"; a
                            // Hard signal with no dispatches is `false`. Without dispatches the
                            // request was effectively lost — which is exactly the signal Loop 2's
                            // selection wants to see. A Warn signal WITH dispatches is still
                            // `useful=true` — the creature did work and got a warning.
                            // Captured BEFORE we move `dispatches` into the bus.
                            let useful = !outcome.dispatches.is_empty() || budget_signal.is_none();
                            for d in outcome.dispatches {
                                // A creature's reply/work is its only output. Dropping it on a full
                                // or unreachable target with no trace is exactly the "a migration can
                                // hang indefinitely" failure the abode-migrator docs warn about.
                                // Keep best-effort delivery (never block the drain) but make a drop
                                // *discoverable*. Capture the small address/corr before `send` moves
                                // `d` — never clone the (possibly large) payload.
                                let (to, corr) = (d.to.clone(), d.corr);
                                if let Err(e) = bus.send(d) {
                                    eprintln!(
                                        "alpha: drain {me:?} dropped a dispatch to {to:?} \
                                         (corr={corr:?}): {e}"
                                    );
                                }
                            }
                            // Publish the per-envelope fitness fact before the budget event. A
                            // budget subscriber may synchronously request unload; work and sense
                            // produced by this completed handle must cross the sender-liveness
                            // boundary before that control reaction can make `bus` stale.
                            publish_fitness(&bus, &router, me, useful);
                            if let Some(signal) = budget_signal {
                                publish_budget_signal(&bus, me, signal);
                            }
                        }
                        Err(_panic) => {
                            // Creature-fault isolation (R9): a panic in `handle` (in-process OR
                            // propagated from a native creature via RC_PANIC) is caught here, never
                            // fatal to the kernel. Pull this one creature off the bus and tear down.
                            publish_fitness(&bus, &router, me, false);
                            router.deregister(me);
                            break;
                        }
                    }
                }
                Err(_) => break, // inbox disconnected → kernel-driven unload requested
            }
        }
    } else {
        // bind panicked — the creature never became routable from its own POV. Surface a fitness
        // failure and pull it off the bus before cleanup.
        publish_fitness(&bus, &router, me, false);
        router.deregister(me);
    }
    // Cleanup is panic-isolated end-to-end so a poisoned creature still gets torn down in the
    // safe order. Each step is best-effort: a panic in any one of them does not stop the next.
    let ms = deadline_ms.load(Ordering::Relaxed);
    let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
        loaded.instance.shutdown(Deadline::from_millis(ms))
    }));

    // **Native-library thread guard, snapshot 2 of 2.** For an opted-in native module, take it
    // AFTER user `shutdown` returns. The SDK has already `join_all`-ed managed threads by this
    // point, so any tid that's new vs `pre_bind_tids` is an UNMANAGED leak. Other module kinds
    // skip this block and proceed directly to their normal resource drop.
    //
    // **Two-snapshot persistence check** (the false-positive guard). Process-level tid
    // monitoring is noisy: libtest worker threads, runtime-internal helpers (cargo, the rust test
    // harness), other creatures' transient threads — all can appear in a single snapshot then be
    // gone moments later, producing a phantom "leak." We take an immediate snapshot, and if it
    // shows any delta we take a SECOND one 50ms later. A real runaway thread is in both; a
    // transient is only in the first. The intersection is the persistent leak set. Fast path
    // (no extra sleep) when the immediate delta is already clean — overwhelmingly the common case.
    let leaked_tids: HashSet<u32> = if guard_unmanaged_threads {
        match (&pre_bind_tids, snapshot_tids()) {
            (Some(pre), Some(post)) => {
                let immediate: HashSet<u32> = post.difference(pre).copied().collect();
                if immediate.is_empty() {
                    immediate
                } else {
                    // Possible leak: re-poll after a short grace so transient threads can exit.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    match snapshot_tids() {
                        Some(later) => immediate.intersection(&later).copied().collect(),
                        None => immediate,
                    }
                }
            }
            _ => HashSet::new(), // no guard on non-Linux; fall through to normal drop
        }
    } else {
        HashSet::new()
    };

    if leaked_tids.is_empty() {
        // The creature crossed the router's deregistration boundary before its inbox disconnected,
        // so its BusHandle must stay stale. The kernel publishes this terminal fact on its behalf.
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            publish_proprio(&lifecycle_bus, me, "unloaded")
        }));
        // `LoadedModule` fields drop in declaration order: instance (native `destroy`, library
        // still mapped) → resources (`dlclose`). This single drop *is* the safe-unload ordering.
        // We catch in case a creature's `Drop` panics (its destroy callback is already panic-
        // isolated by the SDK glue, so native won't propagate; this covers in-process creatures).
        let _ = std::panic::catch_unwind(AssertUnwindSafe(move || drop(loaded)));
    } else {
        // **Leak path.** The creature left at least one thread alive across its `shutdown`. Drop
        // the `instance` (so native `destroy` runs while the library IS still mapped — a clean
        // shutdown callback for the creature's own state), but leak the `resources` so the
        // library never gets `dlclose`d. The runaway thread keeps dereferencing live mapped code:
        // bounded leak (one `.so` per misbehavior), not UAF.
        //
        // The proprio event below is observable only to a subscriber; also log directly so a
        // headless node names *which* thread(s) leaked the library — the operator can tell a real
        // runaway from the self-acknowledged false positive the process-global guard can produce.
        eprintln!(
            "sanctum: {me:?} left thread(s) {leaked_tids:?} alive across shutdown; leaking its \
             library (never dlclose'd) to avoid a use-after-free — bounded leak, not UB"
        );
        let _ = std::panic::catch_unwind(AssertUnwindSafe(|| {
            publish_proprio(&lifecycle_bus, me, "unload_leaked_resources")
        }));
        let _ = std::panic::catch_unwind(AssertUnwindSafe(move || {
            let (instance, resources) = loaded.into_parts();
            drop(instance); // destroy runs while library is still mapped
                            // `Box::leak` discards the destructor: `Library` never drops → `dlclose` never runs →
                            // the `.so` stays mapped → the runaway thread runs into live code (not UAF). Cost: one
                            // permanently-mapped library per misbehavior, observable via the proprio event above.
            let _: &'static mut (dyn std::any::Any + Send) = Box::leak(resources);
        }));
    }

    // The final act of this drain thread: signal the kernel that the drop sequence completed. The
    // kernel's `unload` uses `recv_timeout` on this channel — receiving `Ok(())` proves we passed
    // the drop step (or the leak step, on the misbehavior path).
    let _ = done_tx.send(());
}

fn publish_proprio(bus: &BusHandle, me: CreatureId, event: &str) {
    let p = Proprioception { creature: me.0, event: event.to_string() };
    let payload = aether::wire::to_bytes(&p);
    let _ = bus.send(
        Dispatch::to(Address::Topic(Topic::new(Topic::PROPRIOCEPTION)), payload)
            .with_schema("proprioception"),
    );
}

fn publish_fitness(bus: &BusHandle, router: &Router, me: CreatureId, ok: bool) {
    // Per-envelope sense (fires on *every* handled envelope). Skip the serialize + route entirely
    // when nothing is bound to FITNESS — otherwise the kernel doubles bus traffic (a second full
    // routing op: clock advance, verify, journal push, fan-out) for an event no one consumes. Loop 2
    // (selection) is unchanged whenever a selector/relay IS subscribed.
    if !router.has_subscribers(fitness_topic()) {
        return;
    }
    let f = Fitness { creature: me.0, ok };
    let payload = aether::wire::to_bytes(&f);
    let _ = bus.send(
        Dispatch::to(Address::Topic(fitness_topic().clone()), payload).with_schema("fitness"),
    );
}

/// The kernel's control dispatcher. Drains envelopes addressed to [`Address::Kernel`],
/// parses [`KernelControl`] payloads, and acts. Holds a `Weak<Kernel>` so the kernel can drop
/// without a cycle; an upgrade-fail means the kernel is gone and the thread exits.
///
/// Best-effort by design: a malformed payload is logged-and-skipped (no panic; R9). An unknown
/// op variant is forward-compatible (serde rejects, we skip).
fn run_control_listener(kernel: std::sync::Weak<Kernel>, rx: InboxReceiver) {
    while let Ok(env) = rx.recv() {
        let Some(k) = kernel.upgrade() else { break };
        let op = match decode_kernel_control(&env) {
            Ok(op) => op,
            Err(ControlDecodeError::Oversized { len, limit }) => {
                eprintln!(
                    "sanctum: control listener skipped an oversized payload from {:?} \
                     (corr={:?}, {len} bytes, limit {limit})",
                    env.header.from, env.header.corr
                );
                continue;
            }
            Err(ControlDecodeError::Malformed(e)) => {
                eprintln!(
                    "sanctum: control listener skipped a malformed payload from {:?} \
                     (corr={:?}, {} bytes): {e}",
                    env.header.from,
                    env.header.corr,
                    env.payload.len()
                );
                continue;
            }
        };
        // Isolate the op dispatch exactly as the drain isolates `handle` (R9). A panic here — a
        // future fallible control op, or a recovered-but-inconsistent poisoned lock — must NOT kill
        // this thread: if it did, every subsequent KernelControl envelope would route into a dead
        // inbox with no error, silently bricking the IoC control surface.
        let outcome = std::panic::catch_unwind(AssertUnwindSafe(|| match op {
            KernelControl::Unload { module } => {
                if let Err(e) = k.unload(CreatureId(module), Deadline::default()) {
                    // e.g. UnloadTimeout (a bounded .so leak). Control is fire-and-forget, so the
                    // requester gets no reply — the kernel logs rather than dropping it entirely.
                    eprintln!(
                        "sanctum: control Unload of module {module} did not complete cleanly: {e}"
                    );
                }
            }
            KernelControl::ExtendBudget { module, fuel, mem_bytes, wall_ms } => {
                // Lift the creature's live per-handle ceilings so an injected policy's grace grant
                // (after a `Warn`, or anticipating a `Hard`) actually takes effect on the next handle.
                // The honest-fail floor: `extend_budget` reports per dimension, and any dimension the
                // creature's tier cannot live-lift is surfaced here — never a silent no-op.
                let outcome = k.extend_budget(CreatureId(module), fuel, mem_bytes, wall_ms);
                if outcome.unknown_creature {
                    eprintln!(
                        "sanctum: control ExtendBudget for module {module} matched no live creature \
                         (no-op; fuel={fuel:?}, mem_bytes={mem_bytes:?}, wall_ms={wall_ms:?})"
                    );
                } else if outcome.any_unenforceable() {
                    eprintln!(
                        "sanctum: control ExtendBudget for module {module} was only partly honored — \
                         this creature's tier cannot live-lift every requested dimension \
                         (fuel={:?}, mem={:?}, wall={:?})",
                        outcome.fuel, outcome.mem, outcome.wall
                    );
                }
            }
        }));
        if outcome.is_err() {
            eprintln!("sanctum: a kernel control op panicked (isolated; listener continues)");
        }
    }
}

#[derive(Debug)]
enum ControlDecodeError {
    Oversized { len: usize, limit: usize },
    Malformed(String),
}

fn decode_kernel_control(env: &Envelope) -> Result<KernelControl, ControlDecodeError> {
    if env.payload.len() > MAX_KERNEL_CONTROL_BYTES {
        return Err(ControlDecodeError::Oversized {
            len: env.payload.len(),
            limit: MAX_KERNEL_CONTROL_BYTES,
        });
    }
    // Be permissive on schema — we accept any envelope addressed to the kernel that parses as
    // `KernelControl`. A stricter dispatcher could require `schema == "kernel_control"`.
    serde_json::from_slice::<KernelControl>(&env.payload)
        .map_err(|e| ControlDecodeError::Malformed(e.to_string()))
}

/// Publish a [`BudgetSignalEvent`] on the PROPRIOCEPTION topic.
/// Best-effort: a flooded inbox / disconnected fan-out subscriber must not stall the drain. The
/// kernel publishes the *fact* (level + kind + vector); an injected policy creature decides the
/// response (lever 6). String `level`/`kind` so a subscriber written in any language can match
/// without linking `aether`'s enums. The schema is `"budget_signal"`; older code that knew only
/// terminal breaches should treat `"hard"` as the compatible budget-kill case.
fn publish_budget_signal(bus: &BusHandle, me: CreatureId, signal: BudgetSignal) {
    let level_str = match signal.level {
        SignalLevel::Warn => "warn",
        SignalLevel::Hard => "hard",
    };
    let kind_str = match signal.kind {
        LimitKind::Fuel => "fuel",
        LimitKind::Memory => "memory",
        LimitKind::Wall => "wall",
    };
    let p = BudgetSignalEvent {
        creature: me.0,
        level: level_str.to_string(),
        kind: kind_str.to_string(),
        vector: signal.vector,
    };
    let payload = aether::wire::to_bytes(&p);
    let _ = bus.send(
        Dispatch::to(Address::Topic(Topic::new(Topic::PROPRIOCEPTION)), payload)
            .with_schema("budget_signal"),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Outcome, StubSigner, StubVerifier};
    use anima::{NativeEngine, ScriptEngine, WasmEngine};
    use std::time::Duration;

    // Identity beast: memory + bump `alloc` + `handle` returning packed (ptr<<32 | len).
    const IDENTITY_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $bump (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $p i32)
            (local.set $p (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $len)))
            (local.get $p))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len)))))
    "#;

    struct AllowAll;
    impl Policy for AllowAll {
        fn admit(&self, _m: &Manifest, _e: &Admission) -> Result<(), String> {
            Ok(())
        }
    }
    struct DenyAll;
    impl Policy for DenyAll {
        fn admit(&self, _m: &Manifest, _e: &Admission) -> Result<(), String> {
            Err("dev policy denies everything".into())
        }
    }

    fn kernel(policy: Arc<dyn Policy>) -> Arc<Kernel> {
        Kernel::new(
            vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
            Arc::new(StubSigner::new("node")),
            Arc::new(StubVerifier),
            policy,
            64,
        )
    }

    fn beast() -> (Manifest, Artifact) {
        (
            Manifest::new("echo-beast", "0.1.0", Backend::Beast, "gawd_creature_v1"),
            Artifact::Bytes(wat::parse_str(IDENTITY_WAT).unwrap()),
        )
    }

    fn critter() -> (Manifest, Artifact) {
        (
            Manifest::new("echo-critter", "0.1.0", Backend::Critter, "gawd_critter_v1"),
            Artifact::Bytes(b"fn handle(env) { env.payload }".to_vec()),
        )
    }

    /// `extend_budget` is tier-honest **per dimension** — the honest-fail floor. It reports, for each
    /// of fuel/mem/wall, whether the lift was applied, is unenforceable on that creature's tier, or
    /// wasn't requested, plus whether the creature was even live. This locks: the unknown-creature
    /// no-op, native (no metering → every dimension unenforceable), the beast (fuel + mem + wall all
    /// live), and the critter (fuel + wall live, mem unenforceable).
    #[test]
    fn extend_budget_reports_each_dimension_per_tier() {
        struct Noop;
        impl Creature for Noop {
            fn bind(&mut self, _ctx: CreatureCtx) {}
            fn handle(&mut self, _env: Envelope) -> Outcome {
                Outcome::none()
            }
        }
        let k = kernel(Arc::new(AllowAll));

        // (1) A creature that doesn't exist → the whole grant is a no-op.
        let unknown = k.extend_budget(CreatureId(9999), Some(1_000), None, None);
        assert!(unknown.unknown_creature && !unknown.any_applied(), "unknown creature → no-op");

        // (2) Native has no live BudgetControl → every requested dimension is Unenforceable (an honest
        // report, never a silent lie), and nothing is applied.
        let native_id = k
            .load_instance(
                Manifest::new("noop", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                Box::new(Noop),
            )
            .expect("native admits");
        let native = k.extend_budget(native_id, Some(1_000), Some(1), Some(1));
        assert!(!native.unknown_creature && !native.any_applied(), "native applies nothing");
        assert_eq!(native.fuel, ExtendDim::Unenforceable);
        assert_eq!(native.mem, ExtendDim::Unenforceable);
        assert_eq!(native.wall, ExtendDim::Unenforceable);

        // (3) The beast (wasm) tier live-lifts ALL THREE dimensions now (live fuel cell, live
        // ResourceLimiter mem cell, live epoch wall cell). A dimension left `None` is NotRequested.
        let (m, a) = beast();
        let beast_id = k.load(m, a).expect("beast loads");
        let beast = k.extend_budget(beast_id, Some(50_000), Some(64 * 1024), Some(20));
        assert_eq!(beast.fuel, ExtendDim::Applied, "beast fuel lifts");
        assert_eq!(beast.mem, ExtendDim::Applied, "beast memory lifts (live ResourceLimiter cell)");
        assert_eq!(beast.wall, ExtendDim::Applied, "beast wall lifts (live epoch cell)");
        let beast_partial = k.extend_budget(beast_id, None, Some(1), None);
        assert_eq!(beast_partial.fuel, ExtendDim::NotRequested);
        assert_eq!(beast_partial.mem, ExtendDim::Applied);
        assert!(beast_partial.any_applied() && !beast_partial.any_unenforceable());

        // (4) The critter tier live-lifts fuel + wall, but its memory caps are structural and fixed at
        // load → a mem lift is honestly Unenforceable, not silently dropped.
        let (m, a) = critter();
        let critter_id = k.load(m, a).expect("critter loads");
        let critter = k.extend_budget(critter_id, Some(50_000), Some(1), Some(20));
        assert_eq!(critter.fuel, ExtendDim::Applied, "critter op budget lifts");
        assert_eq!(critter.wall, ExtendDim::Applied, "critter wall lifts (on_progress watchdog)");
        assert_eq!(critter.mem, ExtendDim::Unenforceable, "critter memory cap is fixed at load");

        k.unload(critter_id, Deadline::default()).unwrap();
        k.unload(beast_id, Deadline::default()).unwrap();
        k.unload(native_id, Deadline::default()).unwrap();
    }

    #[test]
    fn loads_routes_and_unloads_a_beast_cleanly() {
        let k = kernel(Arc::new(AllowAll));
        let (m, a) = beast();
        let id = k.load(m, a).unwrap();
        let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
        bus.send(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .unwrap();
        let reply = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(reply.payload, b"abc"); // identity beast round-trip through the kernel

        k.unload(id, Deadline::default()).unwrap();
        assert!(!k.is_loaded(id));
        // post-unload routing is a clean error, not UB (R2)
        let err = bus.send(Dispatch::to(Address::Creature(id), b"x".to_vec())).unwrap_err();
        assert!(matches!(err, RouteError::NoSuchModule(_)));
        k.shutdown_all(Deadline::default());
    }

    #[test]
    fn composition_explicitly_selects_remote_role_exposure() {
        struct Noop;
        impl Creature for Noop {
            fn bind(&mut self, _ctx: CreatureCtx) {}
            fn handle(&mut self, _env: Envelope) -> Outcome {
                Outcome::none()
            }
        }

        let kernel = kernel(Arc::new(AllowAll));
        let id = kernel
            .load_instance(
                Manifest::new("remote-role", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                Box::new(Noop),
            )
            .unwrap();
        let role = Role::new("executor");

        kernel.bind_role(role.clone(), id);
        assert_eq!(kernel.router().remote_role_binding(&role), None);
        kernel.bind_remote_role(role.clone(), id);
        assert_eq!(kernel.router().remote_role_binding(&role), Some(id));
        kernel.bind_role(role.clone(), id);
        assert_eq!(
            kernel.router().remote_role_binding(&role),
            None,
            "ordinary rebind returns the socket to local-only"
        );

        kernel.unload(id, Deadline::default()).unwrap();
        assert_eq!(kernel.router().remote_role_binding(&role), None);
    }

    #[test]
    fn admission_policy_can_reject_a_load() {
        let k = kernel(Arc::new(DenyAll));
        let (m, a) = beast();
        assert!(matches!(k.load(m, a), Err(KernelError::AdmissionRejected(_))));
    }

    #[test]
    fn loaded_identity_retains_actual_artifact_hash_under_permissive_admission() {
        let k = kernel(Arc::new(AllowAll));
        let (mut manifest, artifact) = beast();
        let actual = artifact.sha256_hex().expect("fixture artifact hashes");
        let declared = "0".repeat(64);
        assert_ne!(actual, declared);
        manifest.provenance.build_hash = Some(declared.clone());

        let id =
            k.load(manifest, artifact).expect("permissive policy admits mismatched declaration");
        let identity = k.loaded_manifest_identity(id).expect("loaded identity exists");
        assert_eq!(identity.artifact_build_hash.as_deref(), Some(declared.as_str()));
        assert_eq!(identity.artifact_sha256.as_deref(), Some(actual.as_str()));

        k.shutdown_all(Deadline::default());
    }

    #[test]
    fn no_engine_for_an_unconfigured_backend() {
        let k = Kernel::new(
            vec![Arc::new(WasmEngine::new())], // wasm only
            Arc::new(StubSigner::new("n")),
            Arc::new(StubVerifier),
            Arc::new(AllowAll),
            64,
        );
        let m = Manifest::new("d", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        assert!(matches!(k.load(m, Artifact::Path("/x.so".into())), Err(KernelError::NoEngine(_))));
    }

    struct PanicInstance;
    impl Creature for PanicInstance {
        fn bind(&mut self, _ctx: CreatureCtx) {}
        fn handle(&mut self, _env: Envelope) -> Outcome {
            panic!("creature boom (this panic is caught and isolated — expected in this test)");
        }
    }

    #[test]
    fn a_panicking_creature_is_isolated_not_fatal() {
        let k = kernel(Arc::new(AllowAll));
        let (m, a) = beast();
        let healthy = k.load(m, a).unwrap();
        let panic_id = k
            .load_instance(
                Manifest::new("boom", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                Box::new(PanicInstance),
            )
            .unwrap();
        let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

        // Poison the panicking creature.
        let _ = bus.send(Dispatch::to(Address::Creature(panic_id), b"boom".to_vec()));

        // It self-deregisters; wait (bounded) until it is off the bus.
        let mut gone = false;
        for _ in 0..200 {
            if !k.is_loaded(panic_id) {
                gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(gone, "a panicking creature must be pulled off the bus");

        // The kernel and a healthy creature are unaffected — the fabric did not crash.
        bus.send(
            Dispatch::to(Address::Creature(healthy), b"ok".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .unwrap();
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap().payload, b"ok");
        k.shutdown_all(Deadline::default());
    }

    #[test]
    fn proprioception_stream_carries_liveness() {
        let k = kernel(Arc::new(AllowAll));
        let (sub, _bus, rx) = k.open_endpoint(Capabilities::default());
        k.subscribe(Topic::new(Topic::PROPRIOCEPTION), sub);
        let (m, a) = beast();
        let _id = k.load(m, a).unwrap();
        let ev = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let p: Proprioception = serde_json::from_slice(&ev.payload).unwrap();
        assert_eq!(p.event, "loaded");
        k.shutdown_all(Deadline::default());
    }

    // ---- Unload hygiene closure (F8 + F9 + F10) ----

    /// A creature that sleeps far longer than any reasonable unload deadline. Models the worst-case
    /// misbehavior the kernel must survive: a `shutdown` that never returns.
    struct HangInstance;
    impl Creature for HangInstance {
        fn bind(&mut self, _ctx: CreatureCtx) {}
        fn handle(&mut self, _env: Envelope) -> Outcome {
            Outcome::none()
        }
        fn shutdown(&mut self, _deadline: Deadline) {
            // 60s — long enough that any honest test deadline expires first; short enough that the
            // test harness wraps up in a bounded amount of real time after the assertion fires.
            std::thread::sleep(Duration::from_secs(60));
        }
    }

    #[test]
    fn f9_unload_returns_timeout_when_drain_does_not_finish_in_budget() {
        let k = kernel(Arc::new(AllowAll));
        let id = k
            .load_instance(
                Manifest::new("hang", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                Box::new(HangInstance),
            )
            .unwrap();
        let start = std::time::Instant::now();
        let err = k.unload(id, Deadline::from_millis(100)).unwrap_err();
        let elapsed = start.elapsed();
        assert!(
            matches!(err, KernelError::UnloadTimeout(unloaded) if unloaded == id),
            "expected UnloadTimeout, got {err:?}"
        );
        // The bound is the substance of F9 — never hang the substrate beyond the budget.
        assert!(
            elapsed < Duration::from_millis(500),
            "unload must return within ~deadline + slack, not block on the drain ({elapsed:?})"
        );
        // The router is deregistered even though the drain was abandoned (router state is owned by
        // the kernel, not the drain).
        assert!(!k.is_loaded(id));
        // (The drain thread is still running detached and will outlive this test by ~60s; that is
        // exactly the bounded-leak/no-UB tradeoff Option B accepts for trusted-by-admission native.)
    }

    #[test]
    fn f8_reap_done_collects_ghost_entries_from_self_deregistered_creatures() {
        let k = kernel(Arc::new(AllowAll));
        let id = k
            .load_instance(
                Manifest::new("boom", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                Box::new(PanicInstance),
            )
            .unwrap();
        assert_eq!(k.loaded_count(), 1);
        let (_probe, bus, _rx) = k.open_endpoint(Capabilities::default());
        let _ = bus.send(Dispatch::to(Address::Creature(id), b"boom".to_vec()));
        // Wait until the creature has pulled itself off the bus (panic isolated → router.deregister).
        for _ in 0..200 {
            if !k.is_loaded(id) {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!k.is_loaded(id));
        // Pre-reap: the entry is a ghost — drain has exited, kernel still has the bookkeeping.
        // Give the drain thread a beat to finish the drop sequence and `done_tx.send(())`.
        for _ in 0..200 {
            // try_recv returns Ok or Disconnected once drain has exited; reap_done is idempotent so
            // calling it repeatedly is fine — the loop just confirms the state converged.
            k.reap_done();
            if k.loaded_count() == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(k.loaded_count(), 0, "reap_done must collect drain-exited ghost entries");
    }

    #[test]
    fn f10_dropping_the_kernel_shuts_down_loaded_creatures() {
        // We can observe the Drop side-effect by subscribing to proprioception OUTSIDE the kernel
        // being dropped: open an endpoint on a SECOND kernel? No — the topic is per-router. Simpler:
        // assert via a thread-of-execution signal. The HangInstance's drop won't run within the
        // default deadline (60s sleep), so for THIS test we use the well-behaved beast.
        let (sub_tx, sub_rx) = std::sync::mpsc::channel::<()>();
        // A creature whose shutdown sends a signal.
        struct SignalShutdown(Option<std::sync::mpsc::Sender<()>>);
        impl Creature for SignalShutdown {
            fn bind(&mut self, _ctx: CreatureCtx) {}
            fn handle(&mut self, _env: Envelope) -> Outcome {
                Outcome::none()
            }
            fn shutdown(&mut self, _deadline: Deadline) {
                if let Some(tx) = self.0.take() {
                    let _ = tx.send(());
                }
            }
        }
        {
            let k = kernel(Arc::new(AllowAll));
            let _id = k
                .load_instance(
                    Manifest::new("sig", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
                    Box::new(SignalShutdown(Some(sub_tx))),
                )
                .unwrap();
            // k drops here — the last Arc<Kernel> goes out of scope.
        }
        // shutdown must have run (F10: Drop auto-shutdown_all). With no Drop impl, this would hang
        // indefinitely; with it, the signal arrives well within the default deadline.
        sub_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("dropping the kernel must trigger shutdown on loaded creatures");
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────
    // Wire roundtrip for the signal-event / request / extend-budget shapes. The behavior
    // is wired (the engine emits Warn; ExtendBudget is honored — see budget_extend_honored.rs
    // and anima::wasm_extend_budget_lifts_the_live_fuel_cap_mid_life); these tests lock the wire.
    // ─────────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn budget_signal_event_roundtrips_with_full_vector() {
        let ev = BudgetSignalEvent {
            creature: 12,
            level: "hard".into(),
            kind: "fuel".into(),
            vector: aether::BudgetVector {
                consumed: 8_000,
                limit: 10_000,
                dispatches_this_envelope: 0,
                wall_ms_elapsed: 3,
                envelopes_since_load: 1,
            },
        };
        let bytes = serde_json::to_vec(&ev).unwrap();
        let back: BudgetSignalEvent = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.creature, 12);
        assert_eq!(back.level, "hard");
        assert_eq!(back.kind, "fuel");
        assert_eq!(back.vector.consumed, 8_000);
        assert_eq!(back.vector.envelopes_since_load, 1);
    }

    #[test]
    fn budget_signal_decode_rejects_oversized_payload_before_json_decode() {
        let payload = vec![b'{'; aether::MAX_SENSE_EVENT_BYTES + 1];
        match decode_budget_signal_event(&payload) {
            Err(SenseDecodeError::TooLarge { len, limit }) => {
                assert_eq!(len, aether::MAX_SENSE_EVENT_BYTES + 1);
                assert_eq!(limit, aether::MAX_SENSE_EVENT_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn budget_request_roundtrips_with_optional_dimensions() {
        let r = BudgetRequest {
            creature: 7,
            fuel: Some(50_000),
            mem_bytes: None,
            wall_ms: Some(500),
            justification: "near-completion grace ask".into(),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: BudgetRequest = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.creature, 7);
        assert_eq!(back.fuel, Some(50_000));
        assert!(back.mem_bytes.is_none());
        assert_eq!(back.wall_ms, Some(500));
    }

    #[test]
    fn budget_request_decode_accepts_valid_payload_under_limit() {
        let r = BudgetRequest {
            creature: 7,
            fuel: Some(50_000),
            mem_bytes: None,
            wall_ms: None,
            justification: "near-completion grace ask".into(),
        };
        let bytes = serde_json::to_vec(&r).unwrap();
        let back = decode_budget_request(&bytes).unwrap();
        assert_eq!(back.creature, 7);
        assert_eq!(back.fuel, Some(50_000));
    }

    #[test]
    fn kernel_control_extend_budget_roundtrips_through_serde_tag_op() {
        let op = KernelControl::ExtendBudget {
            module: 3,
            fuel: Some(20_000),
            mem_bytes: Some(1024 * 1024),
            wall_ms: None,
        };
        let bytes = serde_json::to_vec(&op).unwrap();
        let back: KernelControl = serde_json::from_slice(&bytes).unwrap();
        match back {
            KernelControl::ExtendBudget { module, fuel, mem_bytes, wall_ms } => {
                assert_eq!(module, 3);
                assert_eq!(fuel, Some(20_000));
                assert_eq!(mem_bytes, Some(1024 * 1024));
                assert!(wall_ms.is_none());
            }
            other => panic!("expected ExtendBudget, got {other:?}"),
        }
        // The serde tag = "op" discipline must hold: the JSON's "op" key names the variant.
        let json = String::from_utf8(serde_json::to_vec(&op).unwrap()).unwrap();
        assert!(json.contains("\"op\":\"ExtendBudget\""), "tag=op JSON shape changed: {json}");
    }

    #[test]
    fn kernel_control_unload_still_roundtrips_unchanged_pre_embryo_shape() {
        // Wire-compat assertion: adding ExtendBudget must not change Unload's JSON.
        let op = KernelControl::Unload { module: 99 };
        let json = String::from_utf8(serde_json::to_vec(&op).unwrap()).unwrap();
        assert!(json.contains("\"op\":\"Unload\""));
        assert!(json.contains("\"module\":99"));
        let back: KernelControl = serde_json::from_slice(json.as_bytes()).unwrap();
        assert!(matches!(back, KernelControl::Unload { module: 99 }));
    }

    #[test]
    fn kernel_control_decoder_rejects_oversized_payload_before_json_parse() {
        let mut payload = br#"{"op":"Unload","module":7,"ignored":""#.to_vec();
        payload.extend(std::iter::repeat_n(b'x', MAX_KERNEL_CONTROL_BYTES + 1));
        payload.extend_from_slice(br#""}"#);
        let env = Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Kernel,
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(7),
                commitment: None,
                schema: "kernel_control".into(),
                origin: None,
            },
            payload,
        };

        let err = decode_kernel_control(&env).unwrap_err();
        assert!(
            matches!(
                err,
                ControlDecodeError::Oversized {
                    len,
                    limit: MAX_KERNEL_CONTROL_BYTES
                } if len > MAX_KERNEL_CONTROL_BYTES
            ),
            "expected oversized control error, got {err:?}"
        );

        let normal = Envelope {
            payload: serde_json::to_vec(&KernelControl::Unload { module: 7 }).unwrap(),
            ..env
        };
        assert!(matches!(
            decode_kernel_control(&normal).unwrap(),
            KernelControl::Unload { module: 7 }
        ));
    }
}
