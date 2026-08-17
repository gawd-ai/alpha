//! `immune-response` — the keystone creature for the operating model's **Loop 4 (Defend / immune
//! system)**.
//!
//! The substrate carries the *shape* of defense: the kernel senses a creature's health on
//! [`Topic::PROPRIOCEPTION`](aether::Topic::PROPRIOCEPTION) (including lifecycle + budget signals), the
//! registry carries a reversible [`quarantine`](registry_mem::QuarantineNotice) marker, and the
//! `omega-federator` carries the cross-Realm quarantine *path* (`FederateQuarantine` →
//! `QuarantineNotice`). This creature closes the loop: it watches a set of creatures, senses
//! their faults on the proprioception stream, and **quarantines the offending artifact** on the
//! registry — reversibly (T5). It honors inbound cross-Realm quarantine notices through an
//! **injected** trust gate (T2 — a peer can't quarantine your creatures unless you trust it).
//!
//! ## The anti-feedback dual (why this creature CAN subscribe to its topic, when the selector can't)
//!
//! The `fitness-selector` carries a hard rule: it must **not** subscribe to
//! [`Topic::FITNESS`](aether::Topic::FITNESS), because the kernel publishes a fitness event after
//! **every** handle — so a drain-thread creature subscribed to FITNESS would feed on its own events
//! (a 1-in-1-out livelock). The immune-response is the **dual**, and the dual is good news:
//! [`Topic::PROPRIOCEPTION`](aether::Topic::PROPRIOCEPTION) also carries origin, peer, build, and
//! maintenance observations, but this creature discriminates schemas and consumes only **lifecycle**
//! events (`"loaded"` / `"unloaded"` / `"unload_leaked_resources"`) and **budget signals**. Those
//! consumed events are tied to *load/unload/breach*, **never to a plain handle**. So when the
//! immune-response handles a proprioception envelope, the kernel publishes a *fitness* event for it
//! (on FITNESS, which it does not subscribe to) — and **no** new proprioception event. Handling one
//! never produces another.
//! The immune-response is therefore fed by a **direct topic subscription** — real automatic Loop-4
//! sensing, no relay needed — unlike the selector. (As defense-in-depth it still drops events
//! naming its own [`CreatureId`]: a creature is never its own immune trigger; self-apoptosis on
//! budget is the budget-policy creature's job, a different role.)
//!
//! ## What triggers a quarantine
//!
//! Only for a **watched** creature (the operator registers `CreatureId → (realm, artifact_hash)` with
//! [`ImmuneMsg::Watch`], exactly as the fitness-selector does — a proprioception event names only
//! the numeric [`CreatureId`], never the content address, because the kernel is model-free):
//!
//! - **Local, trusted (no gate).** These come from the kernel's own sensing of *this node's*
//!   creatures, so they need no trust check:
//!   - a `"budget_signal"`-schema event with `level == "hard"` (the apoptosis-level breach);
//!   - a `"proprioception"`-schema event with `event == "unload_leaked_resources"` (the creature
//!     left a thread / `'static` leak behind on unload — a misbehaving specimen);
//!   - an operator/detector [`ImmuneMsg::Report`] op (the path a fitness-failure relay, a panic
//!     detector, or an external monitor uses — the immune-response does **not** subscribe to
//!     FITNESS to find failures, for the same self-feedback reason the selector doesn't; a relay
//!     or detector feeds it via `Report`).
//! - **Inbound, trust-gated (T2).** A [`omega_federator::FederatorMsg::QuarantineNotice`]
//!   arriving from a peer (the operator routes a peer federator's notice *here* instead of to the
//!   federator's own unconditional writer) is honored **only if** the injected
//!   [`QuarantineTrust`] honors its `attesting_peers` for the `realm`. Otherwise it is dropped — a
//!   peer you don't trust cannot quarantine your creatures.
//!
//! The watch map is bounded by default ([`DEFAULT_MAX_WATCHED_MODULES`]) so hostile or accidental
//! control traffic cannot grow immune-response memory without bound. At capacity, a `Watch` for a
//! new module is refused while updates to an already-watched module remain allowed. Operators can
//! set `with_max_watched(0)` when they explicitly want an unbounded lab/replay workload; the local
//! issued set remains bounded by the watched modules. Watch fields, quarantine reasons, and inbound
//! peer-attestation lists are also shape-capped before retention or registry/federation writes.
//!
//! ## What stays the substrate's, not this creature's
//!
//! - **Quarantine is reversible (T5).** The immune-response writes
//!   [`RegistryOp::MarkQuarantine`]; a re-publish of the same `(realm, artifact_hash)` clears it
//!   (the registry's rule). The substrate never permanently blacklists — that's a policy decision.
//! - **The trust model is injected (IoC / T2).** *Whether* to honor a peer's notice is a
//!   [`QuarantineTrust`] the operator binds (`cosmos/creatures/prototypes/policies/policy-quarantine-trust-all`,
//!   `policy-quarantine-trust-realm`); the substrate ships only the shape + the path.
//! - **Quarantine is a marker, not a gate.** Marking an entry quarantined does not unload anything
//!   or block a load by itself. An admission policy decides what to do with the marker
//!   (`cosmos/creatures/prototypes/policies/policy-quarantine-aware` *rejects* a quarantined entry even when it is also a
//!   verified promotion — **defense overrides selection**; contrast `policy-prefer-promoted`,
//!   which admits the same entry). Selection rewards; the immune system punishes; the substrate
//!   enforces neither.
//!
//! ## Why defense and selection are separate creatures (and roles)
//!
//! Selection only *promotes*; it never retires the unfit. Defense only *quarantines*;
//! it never promotes. A slow creature (low fitness) is not a hostile one (a fault), and conflating
//! reward with punishment would let one look like the other. They are bound to different roles
//! ([`Role::FITNESS_SELECTOR`](aether::Role::FITNESS_SELECTOR) vs
//! [`Role::IMMUNE_RESPONSE`](aether::Role::IMMUNE_RESPONSE)) and sense different streams (FITNESS
//! vs PROPRIOCEPTION) precisely so the operating model keeps reward and defense legible.

use std::collections::{HashMap, HashSet};

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, NodeId, Outcome, RealmId,
    MAX_SENSE_EVENT_BYTES,
};
use omega_federator::FederatorMsg;
use registry_mem::{QuarantineNotice, RegistryOp};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// Wire schema for the immune-response's own control ops + replies. Single schema + a `kind`-tagged
/// enum, same convention as `fitness-selector` / `omega-federator` / `abode-migrator`.
pub const SCHEMA: &str = "immune.response";

/// The schema the kernel publishes its per-load/unload liveness event under (see `sanctum`'s
/// `publish_proprio`). Mirrors `sanctum::Proprioception` (`{"creature":u64,"event":String}`) without
/// depending on the kernel crate (modules never depend on the kernel — the crate-layout rule);
/// the integration test pins the shape by injecting the kernel's own `Proprioception` bytes.
pub const PROPRIO_SCHEMA: &str = "proprioception";

/// The schema the kernel publishes a budget signal under, also on the PROPRIOCEPTION topic (see
/// `sanctum`'s `publish_budget_signal`). Mirrors `sanctum::BudgetSignalEvent`'s leading fields
/// (`creature` / `level` / `kind`; the `vector` is ignored here — the immune-response acts on the
/// breach *level*, not the raw scalars, which are a budget *policy*'s concern).
pub const BUDGET_SIGNAL_SCHEMA: &str = "budget_signal";

/// The registry op schema — what the immune-response writes its quarantines under (matches the
/// literal `registry-mem` reads on every op).
const REGISTRY_OP_SCHEMA: &str = "registry.op";

/// The proprioception `event` value that means a creature leaked resources on unload (a misbehaving
/// specimen — the detached-thread / leaked-`'static` case). A local quarantine trigger.
const EVENT_LEAKED: &str = "unload_leaked_resources";

/// The budget-signal `level` that means an apoptosis-level breach. A local quarantine trigger.
const LEVEL_HARD: &str = "hard";

/// Default maximum number of distinct creature ids retained in the watch map.
///
/// `0` is reserved as an explicit opt-out via [`ImmuneResponse::with_max_watched`].
pub const DEFAULT_MAX_WATCHED_MODULES: usize = 4_096;

/// Maximum serialized operator control message decoded before JSON parsing (R9 hostile-input floor).
/// Matches the crate's other decode caps (sense + federator), so every wire decode is bounded.
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum retained bytes for a watch-map text field (`realm`, `artifact_hash`).
pub const MAX_WATCH_FIELD_BYTES: usize = 512;
/// Maximum quarantine reason bytes written to the registry or federated onward.
pub const MAX_QUARANTINE_REASON_BYTES: usize = 1024;
/// Maximum peer attestations accepted on one inbound quarantine notice.
pub const MAX_QUARANTINE_ATTESTING_PEERS: usize = 64;
/// Maximum retained bytes for one peer id inside an inbound quarantine notice.
pub const MAX_QUARANTINE_ATTESTING_PEER_BYTES: usize = 256;

// ===================================================================================================
// Deserialize mirrors of the kernel's proprioception-topic events (no kernel dependency)
// ===================================================================================================

/// Deserialize mirror of `sanctum::Proprioception`. `serde` ignores any extra fields, so a kernel
/// that adds a field stays compatible; a *rename* of `creature`/`event` breaks the integration test
/// (which feeds the kernel's own bytes), not silently here.
#[derive(Clone, Debug, Deserialize)]
struct ProprioWire {
    creature: u64,
    event: String,
}

/// Deserialize mirror of the leading fields of `sanctum::BudgetSignalEvent`. The `vector` field is
/// deliberately absent — `serde` ignores it on the wire; the immune-response keys off the breach
/// `level`, never the raw scalars (those drive a budget *policy*, a different creature).
#[derive(Clone, Debug, Deserialize)]
struct BudgetSignalWire {
    creature: u64,
    level: String,
    #[allow(dead_code)] // parsed for completeness / forward-compat; reaction keys off `level`.
    kind: String,
}

fn decode_sense_wire<T: DeserializeOwned>(payload: &[u8]) -> Option<T> {
    if payload.len() > MAX_SENSE_EVENT_BYTES {
        return None;
    }
    serde_json::from_slice(payload).ok()
}

// ===================================================================================================
// Injected trust model (IoC / T2)
// ===================================================================================================

/// *Whether* to honor an inbound cross-Realm quarantine notice — the **injected** trust model. The
/// substrate ships none; `cosmos/creatures/prototypes/policies/policy-quarantine-trust-all` (honors everything — reference,
/// never production) and `policy-quarantine-trust-realm` (honors only a configured peer set) are
/// the references. Operators write their own (quorum-of-N-peers, realm-allowlist, reputation-gated)
/// and bind it.
///
/// `attesting_peers` is the set of peer ids (node or Realm ids, the operator's vocabulary) that
/// vouched for the quarantine; `realm` is the Realm the artifact lives in. Returns `true` to apply
/// the quarantine locally, `false` to drop the notice. This is the **T2 choke point** for inbound
/// defense: a peer cannot quarantine your creatures unless your trust model says so.
pub trait QuarantineTrust: Send + Sync {
    fn honors(&self, attesting_peers: &[String], realm: &RealmId) -> bool;
}

// ===================================================================================================
// Control / reply messages (schema = SCHEMA)
// ===================================================================================================

/// Every immune-response message on [`SCHEMA`]: operator control ops + the creature's replies.
///
/// Forward-compat: new variants at the END are additive; reordering/renaming is a wire break (same
/// discipline as the other creatures' tagged enums).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImmuneMsg {
    // ----- operator → immune-response (control plane) -----
    /// Register the registry key a creature's faults quarantine. `module` is the numeric
    /// [`CreatureId`] the kernel's proprioception/budget event names; `(realm, artifact_hash)` is the
    /// registry key the operator knows it was loaded from. Mirrors the fitness-selector's watch map.
    Watch { module: u64, realm: RealmId, artifact_hash: String },
    /// Inject a fault report directly — the path a fitness-failure relay, a panic detector, or an
    /// external monitor uses to flag a watched creature (the immune-response does not subscribe to
    /// FITNESS itself, for the self-feedback reason in the module docs). A `Report` for an
    /// unwatched module is [`Ignored`](Self::Ignored).
    Report { module: u64, reason: String },
    /// Read-only dump of the immune-response's view.
    StatusQuery,

    // ----- immune-response → operator (replies) -----
    /// Acknowledges a [`Watch`](Self::Watch).
    Watching { module: u64 },
    /// A watched creature was quarantined (names the registry key it landed on).
    Quarantined { module: u64, artifact_hash: String, reason: String },
    /// A trigger was declined (unwatched creature, or an untrusted inbound notice).
    Ignored { reason: String },
    /// The result of a [`StatusQuery`](Self::StatusQuery): watch count + the sorted creature ids this
    /// immune-response has locally quarantined.
    StatusReply { watched: usize, issued: Vec<u64> },
}

impl ImmuneMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

// ===================================================================================================
// The immune-response
// ===================================================================================================

/// Optional cross-Realm propagation wiring. When set, every *local* quarantine the immune-response
/// issues is also federated outward: it sends a [`FederatorMsg::FederateQuarantine`] to the local
/// `omega-federator`, which ships a [`FederatorMsg::QuarantineNotice`] to the peer. Reuses the
/// federation wire verbatim — no federator edit.
pub struct PropagationConfig {
    /// The local `omega-federator` creature id (the creature that ships the notice off-node).
    pub local_federator: CreatureId,
    /// The peer node to federate the quarantine to.
    pub peer_node: NodeId,
    /// The peer's `omega-federator` creature id (the `peer_federator` of the `FederateQuarantine`).
    pub peer_recipient: CreatureId,
}

/// Construction config — the operator wires this before `Kernel::load_instance`.
pub struct ImmuneConfig {
    /// This node — seeded as the lone `attesting_peer` on every locally-issued quarantine, so a peer
    /// that later receives it (via propagation) knows who flagged it.
    pub self_node: NodeId,
    /// The local `registry-mem` creature id — where quarantine markers land.
    pub local_registry: CreatureId,
    /// The injected trust model for inbound cross-Realm notices (T2). Substrate ships none.
    pub trust: Box<dyn QuarantineTrust>,
    /// Optional cross-Realm propagation of locally-issued quarantines. `None` = node-local defense.
    pub propagation: Option<PropagationConfig>,
}

/// The immune-response creature.
pub struct ImmuneResponse {
    cfg: ImmuneConfig,
    me: Option<CreatureId>,
    /// `CreatureId → (realm, artifact_hash)` — the operator-populated resolution of a fault event's
    /// numeric creature id to a registry key (the same watch-map rationale as the fitness-selector).
    watch: HashMap<CreatureId, (RealmId, String)>,
    /// Creatures this immune-response has locally quarantined (for `StatusQuery` observability).
    issued: HashSet<CreatureId>,
    /// Maximum number of distinct watched creatures retained at once. At capacity a `Watch` for a
    /// *new* creature is refused; already-watched creatures can still be updated. **`0` means
    /// unbounded** and must be selected explicitly via [`ImmuneResponse::with_max_watched`].
    max_watched: usize,
}

impl ImmuneResponse {
    pub fn new(cfg: ImmuneConfig) -> Self {
        ImmuneResponse {
            cfg,
            me: None,
            watch: HashMap::new(),
            issued: HashSet::new(),
            max_watched: DEFAULT_MAX_WATCHED_MODULES,
        }
    }

    /// Cap the number of distinct watched modules tracked.
    ///
    /// The default is [`DEFAULT_MAX_WATCHED_MODULES`]. At capacity a `Watch` for a *new* module is
    /// refused rather than growing the watch map without bound; already-watched modules keep their
    /// update path. Pass `0` to opt out and make the watch map unbounded.
    pub fn with_max_watched(mut self, max_watched: usize) -> Self {
        self.max_watched = max_watched;
        self
    }

    fn can_insert_watch(&self, module: CreatureId) -> bool {
        self.max_watched == 0
            || self.watch.contains_key(&module)
            || self.watch.len() < self.max_watched
    }

    fn watch_shape_error(realm: &RealmId, artifact_hash: &str) -> Option<String> {
        if realm.0.len() > MAX_WATCH_FIELD_BYTES {
            return Some(format!(
                "watch realm too large: {} bytes exceeds {} byte limit",
                realm.0.len(),
                MAX_WATCH_FIELD_BYTES
            ));
        }
        if artifact_hash.len() > MAX_WATCH_FIELD_BYTES {
            return Some(format!(
                "watch artifact_hash too large: {} bytes exceeds {} byte limit",
                artifact_hash.len(),
                MAX_WATCH_FIELD_BYTES
            ));
        }
        None
    }

    fn insert_watch(&mut self, module: CreatureId, realm: RealmId, artifact_hash: String) -> bool {
        if let Some(reason) = Self::watch_shape_error(&realm, &artifact_hash) {
            eprintln!("immune-response: {reason}");
            return false;
        }
        if !self.can_insert_watch(module) {
            eprintln!(
                "immune-response: watch map at capacity ({}); refusing watch for new module {}",
                self.max_watched, module.0
            );
            return false;
        }
        self.watch.insert(module, (realm, artifact_hash));
        true
    }

    /// Seed a watch entry at construction (tests / an operator who knows the map up front).
    pub fn watching(
        mut self,
        module: CreatureId,
        realm: RealmId,
        artifact_hash: impl Into<String>,
    ) -> Self {
        self.insert_watch(module, realm, artifact_hash.into());
        self
    }

    /// How many creatures are watched.
    pub fn watched_count(&self) -> usize {
        self.watch.len()
    }

    /// How many distinct modules this immune-response has locally quarantined.
    pub fn issued_count(&self) -> usize {
        self.issued.len()
    }

    fn me_id(&self) -> Option<CreatureId> {
        self.me
    }
}

impl Creature for ImmuneResponse {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        match env.header.schema.as_str() {
            // PROPRIOCEPTION-topic events (we are subscribed — safe; see module docs).
            BUDGET_SIGNAL_SCHEMA => self.on_budget_signal(&env),
            PROPRIO_SCHEMA => self.on_proprioception(&env),
            // Inbound cross-Realm quarantine notice (trust-gated).
            omega_federator::SCHEMA => self.on_federator_msg(&env),
            // Our own control plane.
            SCHEMA => self.on_control(&env),
            // Misbind / stray — never crash (R9).
            _ => Outcome::none(),
        }
    }
}

impl ImmuneResponse {
    // ----- proprioception-topic sensing (local, trusted) ---------------------------------------

    fn on_budget_signal(&mut self, env: &Envelope) -> Outcome {
        let Some(ev) = decode_sense_wire::<BudgetSignalWire>(&env.payload) else {
            return Outcome::none(); // R9: malformed event → drop, never panic.
        };
        // Only a *hard* breach is a defense trigger; a `warn` is a budget-policy concern,
        // not a quarantine.
        if ev.level != LEVEL_HARD {
            return Outcome::none();
        }
        // Reuse the already-parsed `ev.kind` rather than re-deserializing the whole envelope a
        // second time via `ev_kind(env)` (the redundant parse this replaces). (T17)
        self.quarantine_watched(
            CreatureId(ev.creature),
            format!("hard budget breach ({})", ev.kind),
        )
    }

    fn on_proprioception(&mut self, env: &Envelope) -> Outcome {
        let Some(ev) = decode_sense_wire::<ProprioWire>(&env.payload) else {
            return Outcome::none();
        };
        // `loaded` / `unloaded` are normal lifecycle — not faults. Only a leaked-resources unload is
        // a defense trigger (a misbehaving specimen left state behind).
        if ev.event != EVENT_LEAKED {
            return Outcome::none();
        }
        self.quarantine_watched(CreatureId(ev.creature), "leaked resources on unload".to_string())
    }

    /// Quarantine a watched module's artifact (the local, no-reply path used by the topic triggers).
    /// Drops the event if the module is unwatched or is our own id (anti-feedback defense-in-depth).
    fn quarantine_watched(&mut self, module: CreatureId, reason: String) -> Outcome {
        // Defense-in-depth: a creature is never its own immune trigger. Self-apoptosis on budget is
        // the budget-policy creature's job (a different role); reacting to our own fault here could
        // also feed a quarantine→republish→reload cycle. Drop it.
        if Some(module) == self.me {
            return Outcome::none();
        }
        let Some((realm, hash)) = self.watch.get(&module).cloned() else {
            return Outcome::none(); // not watched — defense is scoped to watched creatures.
        };
        self.issued.insert(module);
        self.emit_quarantine(hash, realm, reason)
    }

    /// Build the `MarkQuarantine` write to the local registry, plus the optional cross-Realm
    /// `FederateQuarantine` to the local federator. The shared core of every local quarantine.
    fn emit_quarantine(&self, artifact_hash: String, realm: RealmId, reason: String) -> Outcome {
        let Some(me) = self.me_id() else {
            return Outcome::none();
        };
        let reason = bounded_text(&reason, MAX_QUARANTINE_REASON_BYTES);
        let op = RegistryOp::MarkQuarantine {
            artifact_hash: artifact_hash.clone(),
            realm: realm.clone(),
            reason: reason.clone(),
            attesting_peers: vec![self.cfg.self_node.0.clone()],
        };
        let mut out = Outcome::send(
            Dispatch::to(Address::Creature(self.cfg.local_registry), op.to_bytes())
                .with_schema(REGISTRY_OP_SCHEMA)
                .with_reply_to(Address::Creature(me)),
        );
        // If propagation is wired, federate the quarantine outward via the local federator (reuses
        // the FederateQuarantine wire — no federator edit). The federator signs/ships the notice.
        if let Some(prop) = &self.cfg.propagation {
            let fed = FederatorMsg::FederateQuarantine {
                artifact_hash,
                realm,
                reason,
                peer_node: prop.peer_node.clone(),
                peer_federator: prop.peer_recipient,
            };
            out.dispatches.push(
                Dispatch::to(Address::Creature(prop.local_federator), fed.to_bytes())
                    .with_schema(omega_federator::SCHEMA)
                    .with_reply_to(Address::Creature(me)),
            );
        }
        out
    }

    // ----- inbound cross-Realm notice (trust-gated — T2) ----------------------------------------

    fn on_federator_msg(&mut self, env: &Envelope) -> Outcome {
        let Ok(msg) = FederatorMsg::parse_bounded(&env.payload) else {
            return Outcome::none(); // R9: never panic on malformed input.
        };
        match msg {
            FederatorMsg::QuarantineNotice { artifact_hash, realm, reason, attesting_peers } => {
                self.on_inbound_notice(artifact_hash, realm, reason, attesting_peers)
            }
            // Any other federator message routed here (control ops, replies) isn't ours to act on.
            _ => Outcome::none(),
        }
    }

    fn on_inbound_notice(
        &mut self,
        artifact_hash: String,
        realm: RealmId,
        reason: String,
        attesting_peers: Vec<String>,
    ) -> Outcome {
        let reason = bounded_text(&reason, MAX_QUARANTINE_REASON_BYTES);
        if !inbound_notice_shape_admits(&artifact_hash, &realm, &reason, &attesting_peers) {
            return Outcome::none();
        }
        // T2: the injected trust model is the only choke point for inbound defense. A peer we don't
        // trust gets no write — the notice is dropped silently (fire-and-forget, like the
        // federator's own inbound path; no chatty reply back to a peer we just refused).
        if !self.cfg.trust.honors(&attesting_peers, &realm) {
            return Outcome::none();
        }
        // Honored: write the quarantine into the local registry verbatim, carrying the peer's
        // attesting set (not ours — this is the peer's attestation, not a fresh local one). No
        // propagation re-forward: we apply an inbound notice, we don't bounce it onward (the
        // operator schedules multi-hop, not the creature — same no-gossip stance as the federator).
        let Some(me) = self.me_id() else {
            return Outcome::none();
        };
        let op = RegistryOp::MarkQuarantine { artifact_hash, realm, reason, attesting_peers };
        Outcome::send(
            Dispatch::to(Address::Creature(self.cfg.local_registry), op.to_bytes())
                .with_schema(REGISTRY_OP_SCHEMA)
                .with_reply_to(Address::Creature(me)),
        )
    }

    // ----- control plane (operator → immune-response) ------------------------------------------

    fn on_control(&mut self, env: &Envelope) -> Outcome {
        if env.payload.len() > MAX_CONTROL_MESSAGE_BYTES {
            return Outcome::none(); // R9: refuse oversized operator input before JSON decode.
        }
        let Ok(msg) = ImmuneMsg::parse(&env.payload) else {
            return Outcome::none(); // R9: never panic on malformed input.
        };
        match msg {
            ImmuneMsg::Watch { module, realm, artifact_hash } => {
                let shape_error = Self::watch_shape_error(&realm, &artifact_hash);
                if shape_error.is_none()
                    && self.insert_watch(CreatureId(module), realm, artifact_hash)
                {
                    reply(env, ImmuneMsg::Watching { module })
                } else {
                    reply(
                        env,
                        ImmuneMsg::Ignored {
                            reason: shape_error.unwrap_or_else(|| {
                                format!(
                                    "immune-response watch map at capacity ({})",
                                    self.max_watched
                                )
                            }),
                        },
                    )
                }
            }
            ImmuneMsg::Report { module, reason } => self.on_report(env, module, reason),
            ImmuneMsg::StatusQuery => self.on_status(env),
            // Replies arriving inbound (echo / misdirected) — we issue these, never consume them.
            ImmuneMsg::Watching { .. }
            | ImmuneMsg::Quarantined { .. }
            | ImmuneMsg::Ignored { .. }
            | ImmuneMsg::StatusReply { .. } => Outcome::none(),
        }
    }

    fn on_report(&mut self, env: &Envelope, module: u64, reason: String) -> Outcome {
        let mid = CreatureId(module);
        let reason = bounded_text(&reason, MAX_QUARANTINE_REASON_BYTES);
        // The same self-guard the topic triggers apply in `quarantine_watched`, so the
        // "a creature is never its own immune trigger" invariant holds on EVERY path — not just the
        // kernel-sensed ones. (A `Report` is an operator control-plane op, so it cannot self-feed the
        // way a topic event could; this guard is for *uniformity* with the invariant, not anti-feedback.)
        if Some(mid) == self.me {
            return reply(env, ImmuneMsg::Ignored { reason: "refusing to quarantine self".into() });
        }
        match self.watch.get(&mid).cloned() {
            Some((realm, hash)) => {
                if self.me_id().is_none() {
                    return reply(
                        env,
                        ImmuneMsg::Ignored { reason: "immune-response not bound yet".into() },
                    );
                }
                self.issued.insert(mid);
                let mut out = self.emit_quarantine(hash.clone(), realm, reason.clone());
                let ack = reply(env, ImmuneMsg::Quarantined { module, artifact_hash: hash, reason });
                out.dispatches.extend(ack.dispatches);
                out
            }
            None => reply(
                env,
                ImmuneMsg::Ignored {
                    reason: format!(
                        "module {module} is not watched; immune-response defends only watched creatures"
                    ),
                },
            ),
        }
    }

    fn on_status(&self, env: &Envelope) -> Outcome {
        let mut issued: Vec<u64> = self.issued.iter().map(|m| m.0).collect();
        issued.sort_unstable(); // HashSet order is nondeterministic — sort for a stable reply.
        reply(env, ImmuneMsg::StatusReply { watched: self.watch.len(), issued })
    }
}

#[doc(hidden)]
impl ImmuneResponse {
    /// For tests that drive `handle` directly without a kernel `bind`.
    #[cfg(test)]
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

// ----- helpers --------------------------------------------------------------------------------

/// Reply to the envelope's `reply_to` (or `from`) with an immune-response message + SCHEMA + corr.
fn reply(env: &Envelope, msg: ImmuneMsg) -> Outcome {
    Outcome::send(Dispatch::reply_to_env(env, msg.to_bytes()).with_schema(SCHEMA))
}

fn inbound_notice_shape_admits(
    artifact_hash: &str,
    realm: &RealmId,
    reason: &str,
    attesting_peers: &[String],
) -> bool {
    QuarantineNotice::mark_shape_error(artifact_hash, realm, reason, attesting_peers).is_none()
}

fn bounded_text(s: &str, max: usize) -> String {
    prefix_on_char_boundary(s, max).to_string()
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

// ===================================================================================================
// Tests
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::Header;

    const REGISTRY: CreatureId = CreatureId(50);
    const ME: CreatureId = CreatureId(9);
    const SELF_NODE: &str = "node-A";
    const REALM: &str = "crew";

    /// A trust model that honors everything (the unit-test default; the reference is
    /// `cosmos/creatures/prototypes/policies/policy-quarantine-trust-all`).
    struct TrustAll;
    impl QuarantineTrust for TrustAll {
        fn honors(&self, _peers: &[String], _realm: &RealmId) -> bool {
            true
        }
    }

    /// A trust model that honors nothing — proves the T2 gate drops an untrusted notice.
    struct TrustNone;
    impl QuarantineTrust for TrustNone {
        fn honors(&self, _peers: &[String], _realm: &RealmId) -> bool {
            false
        }
    }

    fn immune_with(
        trust: Box<dyn QuarantineTrust>,
        propagation: Option<PropagationConfig>,
    ) -> ImmuneResponse {
        let cfg = ImmuneConfig {
            self_node: NodeId(SELF_NODE.into()),
            local_registry: REGISTRY,
            trust,
            propagation,
        };
        let mut i = ImmuneResponse::new(cfg);
        i.set_me_for_tests(ME);
        i
    }

    fn immune() -> ImmuneResponse {
        immune_with(Box::new(TrustAll), None)
    }

    fn header(to: Address, schema: &str, corr: Option<u64>) -> Header {
        Header {
            from: Address::Creature(CreatureId(100)),
            to,
            reply_to: Some(Address::Creature(CreatureId(100))),
            seq: 0,
            causal: vec![],
            stamp: 0,
            sig: String::new(),
            corr,
            commitment: None,
            schema: schema.into(),
            origin: None,
        }
    }

    fn control_env(msg: ImmuneMsg, corr: u64) -> Envelope {
        Envelope {
            header: header(Address::Creature(ME), SCHEMA, Some(corr)),
            payload: msg.to_bytes(),
        }
    }

    /// A budget-signal envelope as the kernel publishes it (schema `budget_signal`, on the
    /// PROPRIOCEPTION topic — but routed to us directly in unit tests via the schema).
    fn budget_env(module: u64, level: &str, kind: &str) -> Envelope {
        let payload = serde_json::to_vec(&serde_json::json!({
            "creature": module,
            "level": level,
            "kind": kind,
            "vector": { "consumed": 10, "limit": 5, "dispatches_this_envelope": 0,
                        "wall_ms_elapsed": 0, "envelopes_since_load": 1 }
        }))
        .unwrap();
        Envelope { header: header(Address::Creature(ME), BUDGET_SIGNAL_SCHEMA, None), payload }
    }

    fn proprio_env(module: u64, event: &str) -> Envelope {
        let payload =
            serde_json::to_vec(&serde_json::json!({ "creature": module, "event": event })).unwrap();
        Envelope { header: header(Address::Creature(ME), PROPRIO_SCHEMA, None), payload }
    }

    fn parse_reply(d: &Dispatch) -> ImmuneMsg {
        ImmuneMsg::parse(&d.payload).unwrap()
    }

    fn parse_op(d: &Dispatch) -> RegistryOp {
        serde_json::from_slice(&d.payload).unwrap()
    }

    fn watch_env(module: u64, artifact_hash: impl Into<String>, corr: u64) -> Envelope {
        control_env(
            ImmuneMsg::Watch {
                module,
                realm: RealmId::new(REALM),
                artifact_hash: artifact_hash.into(),
            },
            corr,
        )
    }

    fn watch_target(i: &mut ImmuneResponse, module: u64) {
        i.handle(watch_env(module, format!("h{module}"), 1));
    }

    // ----- Watch + StatusQuery ----

    #[test]
    fn watch_registers_a_key_and_acks() {
        let mut i = immune();
        let out = i.handle(control_env(
            ImmuneMsg::Watch { module: 7, realm: RealmId::new(REALM), artifact_hash: "h7".into() },
            3,
        ));
        assert_eq!(i.watched_count(), 1);
        match parse_reply(&out.dispatches[0]) {
            ImmuneMsg::Watching { module } => assert_eq!(module, 7),
            other => panic!("expected Watching, got {other:?}"),
        }
        assert_eq!(out.dispatches[0].corr, Some(3));
    }

    #[test]
    fn watch_fields_are_size_capped_before_retention() {
        let mut i = immune();
        let out = i.handle(control_env(
            ImmuneMsg::Watch {
                module: 7,
                realm: RealmId::new(REALM),
                artifact_hash: "h".repeat(MAX_WATCH_FIELD_BYTES + 1),
            },
            4,
        ));
        match parse_reply(&out.dispatches[0]) {
            ImmuneMsg::Ignored { reason } => {
                assert!(reason.contains("artifact_hash too large"), "reason: {reason}");
            }
            other => panic!("expected Ignored, got {other:?}"),
        }
        assert_eq!(i.watched_count(), 0, "oversized watch field is not retained");
    }

    #[test]
    fn max_watched_refuses_new_watch_at_capacity_but_allows_update() {
        let mut i = immune().with_max_watched(1);

        let first = i.handle(watch_env(7, "h7", 3));
        match parse_reply(&first.dispatches[0]) {
            ImmuneMsg::Watching { module } => assert_eq!(module, 7),
            other => panic!("expected Watching, got {other:?}"),
        }
        assert_eq!(i.watched_count(), 1);

        let overflow = i.handle(watch_env(8, "h8", 4));
        match parse_reply(&overflow.dispatches[0]) {
            ImmuneMsg::Ignored { reason } => {
                assert!(reason.contains("capacity"), "reason: {reason}");
            }
            other => panic!("expected Ignored, got {other:?}"),
        }
        assert_eq!(i.watched_count(), 1, "new module refused at capacity");

        let update = i.handle(watch_env(7, "h7-updated", 5));
        match parse_reply(&update.dispatches[0]) {
            ImmuneMsg::Watching { module } => assert_eq!(module, 7),
            other => panic!("expected Watching, got {other:?}"),
        }
        assert_eq!(i.watched_count(), 1, "existing watch updates at capacity");

        let out = i
            .handle(control_env(ImmuneMsg::Report { module: 7, reason: "manual fault".into() }, 6));
        let mark = out
            .dispatches
            .iter()
            .find(|d| d.schema == REGISTRY_OP_SCHEMA)
            .expect("updated watch key is quarantined");
        match parse_op(mark) {
            RegistryOp::MarkQuarantine { artifact_hash, .. } => {
                assert_eq!(artifact_hash, "h7-updated")
            }
            other => panic!("expected MarkQuarantine, got {other:?}"),
        }
    }

    #[test]
    fn default_max_watched_is_bounded_and_zero_opt_out_is_unbounded() {
        let mut i = immune();
        let base = 1_000u64;

        for offset in 0..DEFAULT_MAX_WATCHED_MODULES {
            let module = base + offset as u64;
            let _ = i.handle(watch_env(module, format!("h{module}"), 1));
        }
        assert_eq!(i.watched_count(), DEFAULT_MAX_WATCHED_MODULES);

        let overflow = base + DEFAULT_MAX_WATCHED_MODULES as u64;
        let out = i.handle(watch_env(overflow, format!("h{overflow}"), 2));
        match parse_reply(&out.dispatches[0]) {
            ImmuneMsg::Ignored { reason } => {
                assert!(reason.contains("capacity"), "reason: {reason}");
            }
            other => panic!("expected Ignored, got {other:?}"),
        }
        assert_eq!(i.watched_count(), DEFAULT_MAX_WATCHED_MODULES);

        let mut unbounded = immune().with_max_watched(0);
        for offset in 0..=DEFAULT_MAX_WATCHED_MODULES {
            let module = 20_000 + offset as u64;
            let _ = unbounded.handle(watch_env(module, format!("h{module}"), 1));
        }
        assert_eq!(unbounded.watched_count(), DEFAULT_MAX_WATCHED_MODULES + 1);
    }

    #[test]
    fn status_query_reports_watch_count_and_issued() {
        let mut i = immune();
        watch_target(&mut i, 7);
        i.handle(budget_env(7, LEVEL_HARD, "fuel")); // quarantines 7
        let out = i.handle(control_env(ImmuneMsg::StatusQuery, 2));
        match parse_reply(&out.dispatches[0]) {
            ImmuneMsg::StatusReply { watched, issued } => {
                assert_eq!(watched, 1);
                assert_eq!(issued, vec![7]);
            }
            other => panic!("expected StatusReply, got {other:?}"),
        }
    }

    // ----- local trigger: hard budget signal ----

    #[test]
    fn hard_budget_signal_quarantines_a_watched_creature() {
        let mut i = immune();
        watch_target(&mut i, 7);
        let out = i.handle(budget_env(7, LEVEL_HARD, "fuel"));
        let mark = out
            .dispatches
            .iter()
            .find(|d| d.schema == REGISTRY_OP_SCHEMA)
            .expect("a MarkQuarantine");
        assert_eq!(mark.to, Address::Creature(REGISTRY));
        match parse_op(mark) {
            RegistryOp::MarkQuarantine { artifact_hash, realm, reason, attesting_peers } => {
                assert_eq!(artifact_hash, "h7");
                assert_eq!(realm, RealmId::new(REALM));
                assert!(reason.contains("hard budget breach"), "reason: {reason}");
                assert!(reason.contains("fuel"), "reason names the dimension: {reason}");
                assert_eq!(
                    attesting_peers,
                    vec![SELF_NODE.to_string()],
                    "seeded with our own node id"
                );
            }
            other => panic!("expected MarkQuarantine, got {other:?}"),
        }
        assert_eq!(i.issued_count(), 1);
    }

    #[test]
    fn warn_budget_signal_does_not_quarantine() {
        // A `warn`-level signal is a budget-policy concern (grace / demote), never a defense trigger.
        let mut i = immune();
        watch_target(&mut i, 7);
        let out = i.handle(budget_env(7, "warn", "fuel"));
        assert!(out.dispatches.is_empty(), "a warn must not quarantine");
        assert_eq!(i.issued_count(), 0);
    }

    #[test]
    fn budget_signal_for_an_unwatched_creature_is_ignored() {
        let mut i = immune();
        // Never watched module 7.
        let out = i.handle(budget_env(7, LEVEL_HARD, "fuel"));
        assert!(out.dispatches.is_empty(), "defense is scoped to watched creatures");
    }

    #[test]
    fn oversized_budget_signal_is_dropped_without_quarantine() {
        let mut i = immune();
        watch_target(&mut i, 7);
        let env = Envelope {
            header: header(Address::Creature(ME), BUDGET_SIGNAL_SCHEMA, None),
            payload: vec![b'{'; MAX_SENSE_EVENT_BYTES + 1],
        };
        let out = i.handle(env);
        assert!(out.dispatches.is_empty(), "oversized budget signal is ignored");
        assert_eq!(i.issued_count(), 0);
    }

    #[test]
    fn drops_a_budget_signal_naming_its_own_id() {
        // Anti-feedback defense-in-depth: a creature is never its own immune trigger.
        let mut i = immune();
        watch_target(&mut i, ME.0); // even if (mis)watched, the self-guard fires first
        let out = i.handle(budget_env(ME.0, LEVEL_HARD, "fuel"));
        assert!(out.dispatches.is_empty(), "must not quarantine itself");
        assert_eq!(i.issued_count(), 0);
    }

    // ----- local trigger: leaked-resources unload ----

    #[test]
    fn leaked_resources_unload_quarantines_a_watched_creature() {
        let mut i = immune();
        watch_target(&mut i, 8);
        let out = i.handle(proprio_env(8, EVENT_LEAKED));
        let mark = out
            .dispatches
            .iter()
            .find(|d| d.schema == REGISTRY_OP_SCHEMA)
            .expect("a MarkQuarantine");
        match parse_op(mark) {
            RegistryOp::MarkQuarantine { artifact_hash, reason, .. } => {
                assert_eq!(artifact_hash, "h8");
                assert!(reason.contains("leaked resources"), "reason: {reason}");
            }
            other => panic!("expected MarkQuarantine, got {other:?}"),
        }
    }

    #[test]
    fn normal_lifecycle_events_do_not_quarantine() {
        // `loaded` / `unloaded` are health, not faults — the safe-subscription point (these are the
        // events the immune-response receives constantly without reacting; only a leak triggers).
        let mut i = immune();
        watch_target(&mut i, 8);
        assert!(i.handle(proprio_env(8, "loaded")).dispatches.is_empty());
        assert!(i.handle(proprio_env(8, "unloaded")).dispatches.is_empty());
        assert_eq!(i.issued_count(), 0);
    }

    #[test]
    fn oversized_proprioception_event_is_dropped_without_quarantine() {
        let mut i = immune();
        watch_target(&mut i, 8);
        let env = Envelope {
            header: header(Address::Creature(ME), PROPRIO_SCHEMA, None),
            payload: vec![b'{'; MAX_SENSE_EVENT_BYTES + 1],
        };
        let out = i.handle(env);
        assert!(out.dispatches.is_empty(), "oversized proprioception event is ignored");
        assert_eq!(i.issued_count(), 0);
    }

    // ----- operator Report ----

    #[test]
    fn report_quarantines_a_watched_creature_and_acks() {
        let mut i = immune();
        watch_target(&mut i, 7);
        let out = i.handle(control_env(
            ImmuneMsg::Report { module: 7, reason: "panicked in handle".into() },
            5,
        ));
        // A MarkQuarantine to the registry + a Quarantined ack to the operator.
        assert!(out.dispatches.iter().any(|d| d.schema == REGISTRY_OP_SCHEMA), "registry write");
        let ack = out.dispatches.iter().find(|d| d.schema == SCHEMA).expect("Quarantined ack");
        match parse_reply(ack) {
            ImmuneMsg::Quarantined { module, artifact_hash, reason } => {
                assert_eq!(module, 7);
                assert_eq!(artifact_hash, "h7");
                assert_eq!(reason, "panicked in handle");
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
        assert_eq!(ack.corr, Some(5));
    }

    #[test]
    fn report_reason_is_capped_before_registry_write_and_reply() {
        let mut i = immune();
        watch_target(&mut i, 7);
        let long_reason = format!("{}tail-marker", "x".repeat(MAX_QUARANTINE_REASON_BYTES + 4096));
        let out = i.handle(control_env(ImmuneMsg::Report { module: 7, reason: long_reason }, 5));
        let mark =
            out.dispatches.iter().find(|d| d.schema == REGISTRY_OP_SCHEMA).expect("registry write");
        match parse_op(mark) {
            RegistryOp::MarkQuarantine { reason, .. } => {
                assert_eq!(reason.len(), MAX_QUARANTINE_REASON_BYTES);
                assert!(!reason.contains("tail-marker"), "registry reason is bounded");
            }
            other => panic!("expected MarkQuarantine, got {other:?}"),
        }
        let ack = out.dispatches.iter().find(|d| d.schema == SCHEMA).expect("ack");
        match parse_reply(ack) {
            ImmuneMsg::Quarantined { reason, .. } => {
                assert_eq!(reason.len(), MAX_QUARANTINE_REASON_BYTES);
                assert!(!reason.contains("tail-marker"), "reply reason is bounded");
            }
            other => panic!("expected Quarantined, got {other:?}"),
        }
    }

    #[test]
    fn report_reason_cap_preserves_utf8_boundary() {
        let text = "é".repeat(MAX_QUARANTINE_REASON_BYTES / 2 + 1);
        let bounded = bounded_text(&text, MAX_QUARANTINE_REASON_BYTES + 1);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert_eq!(bounded.len(), MAX_QUARANTINE_REASON_BYTES);
    }

    #[test]
    fn report_for_own_id_is_ignored() {
        // The self-guard applies on the Report path too (uniformity with the topic triggers): even an
        // explicit operator Report naming our own id is refused, so "a creature is never its own
        // immune trigger" holds on every path.
        let mut i = immune();
        watch_target(&mut i, ME.0); // even if (mis)watched, the self-guard fires first
        let out =
            i.handle(control_env(ImmuneMsg::Report { module: ME.0, reason: "self".into() }, 7));
        assert!(
            out.dispatches.iter().all(|d| d.schema != REGISTRY_OP_SCHEMA),
            "no self-quarantine write"
        );
        match parse_reply(out.dispatches.iter().find(|d| d.schema == SCHEMA).unwrap()) {
            ImmuneMsg::Ignored { reason } => assert!(reason.contains("self"), "reason: {reason}"),
            other => panic!("expected Ignored, got {other:?}"),
        }
        assert_eq!(i.issued_count(), 0);
    }

    #[test]
    fn report_for_an_unwatched_creature_is_ignored() {
        let mut i = immune();
        let out =
            i.handle(control_env(ImmuneMsg::Report { module: 99, reason: "noise".into() }, 6));
        assert!(out.dispatches.iter().all(|d| d.schema != REGISTRY_OP_SCHEMA), "no registry write");
        match parse_reply(out.dispatches.iter().find(|d| d.schema == SCHEMA).unwrap()) {
            ImmuneMsg::Ignored { reason } => {
                assert!(reason.contains("not watched"), "reason: {reason}")
            }
            other => panic!("expected Ignored, got {other:?}"),
        }
    }

    // ----- inbound cross-Realm notice (trust-gated, T2) ----

    fn notice_env(attesting_peers: Vec<String>) -> Envelope {
        let msg = FederatorMsg::QuarantineNotice {
            artifact_hash: "bad".into(),
            realm: RealmId::new(REALM),
            reason: "peer apoptosis".into(),
            attesting_peers,
        };
        Envelope {
            header: header(Address::Creature(ME), omega_federator::SCHEMA, None),
            payload: msg.to_bytes(),
        }
    }

    #[test]
    fn trusted_inbound_notice_marks_quarantine() {
        let mut i = immune_with(Box::new(TrustAll), None);
        let out = i.handle(notice_env(vec!["node-B".into()]));
        let mark = out
            .dispatches
            .iter()
            .find(|d| d.schema == REGISTRY_OP_SCHEMA)
            .expect("a MarkQuarantine");
        match parse_op(mark) {
            RegistryOp::MarkQuarantine { artifact_hash, realm, attesting_peers, .. } => {
                assert_eq!(artifact_hash, "bad");
                assert_eq!(realm, RealmId::new(REALM));
                // The peer's attesting set is carried verbatim (not replaced with ours).
                assert_eq!(attesting_peers, vec!["node-B".to_string()]);
            }
            other => panic!("expected MarkQuarantine, got {other:?}"),
        }
    }

    #[test]
    fn untrusted_inbound_notice_is_dropped() {
        // T2: a peer we don't trust cannot quarantine our creatures.
        let mut i = immune_with(Box::new(TrustNone), None);
        let out = i.handle(notice_env(vec!["attacker".into()]));
        assert!(out.dispatches.is_empty(), "an untrusted notice produces no registry write");
    }

    #[test]
    fn inbound_notice_with_oversized_attesting_peer_is_dropped_before_registry_write() {
        let mut i = immune_with(Box::new(TrustAll), None);
        let out = i.handle(notice_env(vec!["p".repeat(MAX_QUARANTINE_ATTESTING_PEER_BYTES + 1)]));
        assert!(out.dispatches.is_empty(), "oversized peer id makes notice fail closed");
    }

    #[test]
    fn inbound_notice_with_malformed_short_fields_is_dropped_before_registry_write() {
        let mut i = immune_with(Box::new(TrustAll), None);
        let cases = [
            FederatorMsg::QuarantineNotice {
                artifact_hash: "bad\0hash".into(),
                realm: RealmId::new(REALM),
                reason: "peer apoptosis".into(),
                attesting_peers: vec!["node-B".into()],
            },
            FederatorMsg::QuarantineNotice {
                artifact_hash: "bad".into(),
                realm: RealmId::new("bad:realm"),
                reason: "peer apoptosis".into(),
                attesting_peers: vec!["node-B".into()],
            },
            FederatorMsg::QuarantineNotice {
                artifact_hash: "bad".into(),
                realm: RealmId::new(REALM),
                reason: "bad\0reason".into(),
                attesting_peers: vec!["node-B".into()],
            },
            FederatorMsg::QuarantineNotice {
                artifact_hash: "bad".into(),
                realm: RealmId::new(REALM),
                reason: "peer apoptosis".into(),
                attesting_peers: vec!["node\0B".into()],
            },
        ];

        for msg in cases {
            let out = i.handle(Envelope {
                header: header(Address::Creature(ME), omega_federator::SCHEMA, None),
                payload: msg.to_bytes(),
            });
            assert!(out.dispatches.is_empty(), "malformed notice should fail closed");
        }
    }

    #[test]
    fn trusted_inbound_notice_reason_is_capped_before_registry_write() {
        let mut i = immune_with(Box::new(TrustAll), None);
        let msg = FederatorMsg::QuarantineNotice {
            artifact_hash: "bad".into(),
            realm: RealmId::new(REALM),
            reason: format!("{}tail-marker", "x".repeat(MAX_QUARANTINE_REASON_BYTES + 4096)),
            attesting_peers: vec!["node-B".into()],
        };
        let out = i.handle(Envelope {
            header: header(Address::Creature(ME), omega_federator::SCHEMA, None),
            payload: msg.to_bytes(),
        });
        let mark = out
            .dispatches
            .iter()
            .find(|d| d.schema == REGISTRY_OP_SCHEMA)
            .expect("trusted notice writes quarantine");
        match parse_op(mark) {
            RegistryOp::MarkQuarantine { reason, .. } => {
                assert_eq!(reason.len(), MAX_QUARANTINE_REASON_BYTES);
                assert!(!reason.contains("tail-marker"), "registry reason is bounded");
            }
            other => panic!("expected MarkQuarantine, got {other:?}"),
        }
    }

    #[test]
    fn oversized_federator_notice_is_dropped_without_quarantine() {
        let mut i = immune_with(Box::new(TrustAll), None);
        let env = Envelope {
            header: header(Address::Creature(ME), omega_federator::SCHEMA, None),
            payload: vec![b'{'; omega_federator::MAX_FEDERATOR_MESSAGE_BYTES + 1],
        };
        let out = i.handle(env);
        assert!(out.dispatches.is_empty(), "oversized federator message is ignored");
        assert_eq!(i.issued_count(), 0);
    }

    #[test]
    fn oversized_control_message_is_dropped_before_json_decode() {
        let mut i = immune_with(Box::new(TrustAll), None);
        let env = Envelope {
            header: header(Address::Creature(ME), SCHEMA, Some(1)),
            payload: vec![b'{'; MAX_CONTROL_MESSAGE_BYTES + 1],
        };
        let out = i.handle(env);
        assert!(out.dispatches.is_empty(), "oversized operator control message is ignored (R9)");
    }

    // ----- propagation ----

    #[test]
    fn local_quarantine_federates_outward_when_propagation_is_configured() {
        let mut i = immune_with(
            Box::new(TrustAll),
            Some(PropagationConfig {
                local_federator: CreatureId(70),
                peer_node: NodeId("node-B".into()),
                peer_recipient: CreatureId(71),
            }),
        );
        watch_target(&mut i, 7);
        let out = i.handle(budget_env(7, LEVEL_HARD, "fuel"));
        // A MarkQuarantine to the registry AND a FederateQuarantine to the local federator.
        assert!(
            out.dispatches
                .iter()
                .any(|d| d.to == Address::Creature(REGISTRY) && d.schema == REGISTRY_OP_SCHEMA),
            "registry write present"
        );
        let fed = out
            .dispatches
            .iter()
            .find(|d| d.to == Address::Creature(CreatureId(70)))
            .expect("FederateQuarantine to the local federator");
        assert_eq!(fed.schema, omega_federator::SCHEMA);
        match FederatorMsg::parse(&fed.payload).unwrap() {
            FederatorMsg::FederateQuarantine {
                artifact_hash, peer_node, peer_federator, ..
            } => {
                assert_eq!(artifact_hash, "h7");
                assert_eq!(peer_node, NodeId("node-B".into()));
                assert_eq!(peer_federator, CreatureId(71));
            }
            other => panic!("expected FederateQuarantine, got {other:?}"),
        }
    }

    #[test]
    fn inbound_notice_does_not_re_federate_even_with_propagation_configured() {
        // We apply an inbound notice; we don't bounce it onward (no gossip — the operator schedules
        // multi-hop, not the creature). So an inbound notice yields exactly one dispatch.
        let mut i = immune_with(
            Box::new(TrustAll),
            Some(PropagationConfig {
                local_federator: CreatureId(70),
                peer_node: NodeId("node-B".into()),
                peer_recipient: CreatureId(71),
            }),
        );
        let out = i.handle(notice_env(vec!["node-B".into()]));
        assert_eq!(
            out.dispatches.len(),
            1,
            "inbound notice writes the registry only, never re-federates"
        );
        assert_eq!(out.dispatches[0].to, Address::Creature(REGISTRY));
    }

    // ----- misbind / hostile (R9) ----

    #[test]
    fn malformed_control_payload_does_not_panic() {
        let mut i = immune();
        let env = Envelope {
            header: header(Address::Creature(ME), SCHEMA, None),
            payload: b"{not json".to_vec(),
        };
        assert!(i.handle(env).dispatches.is_empty());
    }

    #[test]
    fn report_before_bind_replies_ignored_and_does_not_quarantine() {
        let mut i = immune();
        i.me = None;
        watch_target(&mut i, 7);

        let out = i
            .handle(control_env(ImmuneMsg::Report { module: 7, reason: "manual fault".into() }, 2));

        assert_eq!(out.dispatches.len(), 1);
        match parse_reply(&out.dispatches[0]) {
            ImmuneMsg::Ignored { reason } => assert!(reason.contains("not bound"), "{reason}"),
            other => panic!("expected Ignored, got {other:?}"),
        }
    }

    #[test]
    fn malformed_budget_signal_does_not_panic() {
        let mut i = immune();
        watch_target(&mut i, 7);
        let env = Envelope {
            header: header(Address::Creature(ME), BUDGET_SIGNAL_SCHEMA, None),
            payload: b"{not json".to_vec(),
        };
        assert!(i.handle(env).dispatches.is_empty());
    }

    #[test]
    fn unknown_schema_is_a_no_op() {
        let mut i = immune();
        let env = Envelope {
            header: header(Address::Creature(ME), "some.other.schema", None),
            payload: b"x".to_vec(),
        };
        assert!(i.handle(env).dispatches.is_empty());
    }

    #[test]
    fn immune_msg_wire_roundtrips() {
        let m = ImmuneMsg::Report { module: 3, reason: "x".into() };
        assert_eq!(ImmuneMsg::parse(&m.to_bytes()).unwrap(), m);
    }
}
