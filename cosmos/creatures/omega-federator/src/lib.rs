//! `omega-federator` — the keystone federation creature: the real
//! [`Role::OMEGA_GATEWAY`](aether::Role::OMEGA_GATEWAY) consumer. It brings Loop 5 (Acculturate)
//! and the federation half of Loops 2/4 online:
//!
//! 1. **Cross-Realm routing.** An [`Address::Omega { realm, target }`](aether::Address::Omega)
//!    envelope is resolved by looking up the peer Sanctum mapped to `realm` and re-routing
//!    `Node(peer, target)` — the bus then carries it via the bound `Role::TRANSPORT`. Same
//!    composition-by-depth discipline as `cosmos/creatures/prototypes/gateways/realm-gateway`. The
//!    retained Realm→peer map is bounded and shape-checked at construction; use
//!    [`OmegaFederator::new_with_realm_peer_limit`] with `0` only for lab/demo configs that
//!    intentionally accept an unbounded route table.
//! 2. **Pull-based anti-entropy.** On a `PullFrom` control op the federator asks a peer Realm's
//!    `registry-mem` for its catalog ([`RegistryOp::ListEntries`]) and merges every entry into the
//!    *local* registry via the [`RegistryOp::Publish`] write path (tagged with the
//!    entry's own Realm). Pull, not gossip — enough for multi-Realm reconciliation; the
//!    receiving Sanctum's admission gate still re-verifies every artifact on load (T2). In-flight
//!    unanswered pulls are capped by default; `with_max_pending_pulls(0)` is the explicit lab/demo
//!    opt-out.
//! 3. **Signed reputation propagation.** On a `FederateReputation` control op the federator signs a
//!    [`ReputationDelta`] with the **observer's Abode key** (T3 — a self-reported/unsigned delta is
//!    rejected at ingest without ever touching the registry) and ships it as a SEER
//!    [`Consensus`](seer::SeerTopic::Consensus)-topic envelope to a peer federator. The
//!    receiver verifies the signature, applies its **injected** [`ReputationWeigher`] (the weight
//!    model — substrate ships none; see `cosmos/creatures/prototypes/reputation/reputation-roundrobin`), and writes
//!    [`RegistryOp::AttestFitness`] tagged with the attesting Realm. Malformed or oversized identity
//!    fields are dropped before the federator can echo them into audit events or registry writes.
//! 4. **Cross-Realm quarantine path.** On a `FederateQuarantine` control op the federator ships a
//!    [`FederatorMsg::QuarantineNotice`] to a peer federator, which writes
//!    [`RegistryOp::MarkQuarantine`] (reversible — T5) into its local registry. The federator ships
//!    the *path*; the immune-response creature decides what triggers a notice and how to react. The
//!    federator rejects oversized quarantine keys, reasons, and attesting-peer lists on outbound,
//!    inbound, and pulled anti-entropy paths before forwarding them.
//!
//! ## What stays the substrate's, not the federator's
//!
//! - **Admission is the only choke point (T2).** The federator never bypasses it. Pulled artifacts
//!   land in the registry; loading one still runs the operator's admission policy (signature,
//!   build-hash recompute, allowlist). A peer that advertises a forged artifact pollutes nothing —
//!   the gate refuses it on load.
//! - **The weight model is injected (IoC).** How much a peer's attestation counts is a
//!   [`ReputationWeigher`] the operator binds; the substrate ships only the shape + the SEER topic.
//! - **Reputation is computed, not asserted (T3).** Every delta carries the observer's signature;
//!   an unsigned delta, or one signed by a key the verifier rejects, never updates the registry.
//!
//! ## What the federator deliberately does NOT do
//!
//! - **No timer-driven anti-entropy schedule.** A pull happens when the operator (or a scheduler
//!   creature) sends `PullFrom`. The substrate ships no clock (time is injected).
//! - **No gossip / transitive flooding.** A pull scopes to the named peer Realm; the federator does
//!   not re-advertise what it pulled. Multi-hop propagation is the operator's to schedule.
//! - **No placement relay.** Cross-Realm *placement* (Loop 3) rides the unchanged
//!   `distributor-requirements` over the Node grain (transport peering); the federator owns
//!   registry-state federation, not per-consult relay.

use std::collections::HashMap;

use aether::{
    Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, NodeId, Outcome, RealmId, Topic,
};
use bestiary::{artifact_hash_shape_error, QuarantineNotice, MAX_REGISTRY_SIGNAL_FIELD_BYTES};
use registry_mem::{RegistryOp, RegistryReply};
use seer::{SeerEnvelope, SeerKind, SeerTopic};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::{Ed25519KeyMaterial, Ed25519Verifier, Verifier};
use std::sync::Arc;

/// Wire schema for the federator's own control + inter-federator messages (everything that isn't
/// an Omega-routed envelope or a SEER reputation delta). Single schema + a `kind`-tagged enum,
/// same convention as `abode-migrator` and `distributor-requirements`.
pub const SCHEMA: &str = "omega.federator";

/// The registry's reply schema — the federator filters pull replies by it. Mirrors the literal
/// `registry-mem` writes on every reply.
const REGISTRY_REPLY_SCHEMA: &str = "registry.reply";
/// Cap on a pull reply (`ListEntries` → `Entries`) before decode. A pull reply is the **one** path
/// that aggregates a whole Realm's catalogue — every `SyncEntry` with its artifact bytes — so it is
/// bounded *separately* from a single registry op (which carries at most one artifact). An `Entries`
/// reply above this cap is dropped with a log and its parked pull is reclaimed, so a too-large
/// snapshot is observable and recoverable (retry a narrower Realm scope) rather than a silent drop.
const MAX_REGISTRY_REPLY_BYTES: usize = 256 * 1024 * 1024;
/// Maximum bytes decoded for one [`FederatorMsg`] control/inter-federator payload.
pub const MAX_FEDERATOR_MESSAGE_BYTES: usize = 1024 * 1024;
/// Default cap for in-flight anti-entropy pulls. `0` in
/// [`OmegaFederator::with_max_pending_pulls`] means unbounded.
pub const DEFAULT_MAX_PENDING_PULLS: usize = 128;
/// Default maximum Realm→peer mappings retained for Omega routing.
pub const DEFAULT_MAX_FEDERATOR_REALM_PEERS: usize = 1024;
/// Maximum bytes in a Realm name retained in the route table.
pub const MAX_FEDERATOR_REALM_BYTES: usize = sigil::MAX_MANIFEST_REALM_BYTES;
/// Maximum bytes in a peer node id retained in the route table.
pub const MAX_FEDERATOR_NODE_ID_BYTES: usize = 256;

/// Proprioception event the federator emits when it drops a **malformed reputation attestation** —
/// a non-finite score or a delta whose observer signature didn't verify. Lets the
/// defense loop or an operator observe a peer spraying junk attestations; the bus bounds the
/// fan-out (R9), so the surfacing can't itself be turned into an OOM. Distinct from the *expected*
/// "un-peered Realm → weight 0" drop, which is silent (counted only).
pub const INGEST_DROP_SCHEMA: &str = "federation.ingest_drop";

/// Per-failure-mode reputation-ingest rejection counters. Lets a test or an
/// operator tell a quiet federation from one being sprayed with junk deltas. The two
/// *malformed-attestation* modes (`non_finite_score`, `bad_signature`) also emit an
/// [`INGEST_DROP_SCHEMA`] proprioception event; the routine modes (`malformed`, `unweighted`) only
/// count — emitting on them would amplify parse noise / expected un-peered traffic onto the
/// proprioception topic.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IngestRejections {
    /// Undecodable SEER envelope or undecodable delta body — couldn't even read an attestation.
    pub malformed: u64,
    /// Delta carried a non-finite (`NaN`/±∞) score (an out-of-range magnitude off the wire).
    pub non_finite_score: u64,
    /// Delta's observer signature didn't verify under its declared key, or was absent (T3).
    pub bad_signature: u64,
    /// Injected weigher returned a non-finite or ≤0 weight — an un-peered Realm (expected) or a
    /// hostile weigher (guarded). Counted, not surfaced.
    pub unweighted: u64,
}

/// The body of an [`INGEST_DROP_SCHEMA`] proprioception event.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IngestDropEvent {
    /// The malformed-attestation mode: `"non_finite_score"` | `"bad_signature"`.
    pub reason: String,
    /// The attestation's *claimed* observer key — **unverified** (the drop happened at/before the
    /// signature gate). An audit hint, never a trust assertion.
    pub observer_key: String,
    /// The attestation's claimed observer Realm.
    pub observer_realm: String,
}

// ===================================================================================================
// Reputation delta (rides the SEER Consensus topic; signed by the observer — T3)
// ===================================================================================================

/// A signed, content-addressed reputation observation propagated between Realms. Carried as the
/// body of a SEER [`Consensus`](SeerTopic::Consensus)-topic `Answer` envelope.
///
/// **T3 — reputation is computed, not asserted.** The delta is signed by the *observing* Abode key.
/// A receiver verifies the signature before crediting anything; an unsigned delta (or one whose
/// signature doesn't verify under `observer_key`) is dropped without touching the registry. The
/// substrate doesn't *enforce* that observer ≠ subject — it provides the structure; the injected
/// [`ReputationWeigher`] discounts self-attestation if the operator's model says so (IoC).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReputationDelta {
    /// The artifact this observation is about (`sha256(artifact_bytes)` hex).
    pub artifact_hash: String,
    /// The Realm the artifact lives in (the registry key alongside `artifact_hash`).
    pub realm: RealmId,
    /// The observed score (the injected criterion's range; the bundled scorers use `[0.0, 1.0]`).
    pub score: f32,
    /// The Realm that made the observation — federation provenance, stored as
    /// [`ReputationScore::attesting_realm`](registry_mem::ReputationScore::attesting_realm).
    pub observer_realm: RealmId,
    /// The observer's Abode public key (the signer). The verifier checks `signature` against this.
    pub observer_key: String,
    /// ed25519 signature over [`signing_payload`](Self::signing_payload). `None` = unsigned, which
    /// a strict ingest rejects (the federator requires signed deltas).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl ReputationDelta {
    /// Bytes a signature commits to: the delta with `signature` cleared. Same discipline as
    /// `abode::AbodeSnapshot::signing_payload` (the `abode` crate).
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.signature = None;
        aether::wire::to_bytes(&clone)
    }

    /// Sign in place with the observer's key. Caller ensures `self.observer_key == key.public_hex()`.
    pub fn sign(&mut self, key: &Ed25519KeyMaterial) {
        self.signature = Some(key.sign(&self.signing_payload()));
    }

    /// Verify the signature against `observer_key`. `None` signature → `false`.
    pub fn verify(&self, verifier: &dyn Verifier) -> bool {
        match self.signature.as_deref() {
            Some(sig) => verifier.verify(&self.observer_key, &self.signing_payload(), sig),
            None => false,
        }
    }
}

// ===================================================================================================
// Injected weight model (IoC)
// ===================================================================================================

/// How much a peer's attestation counts — the **injected** reputation weight model. The substrate
/// ships none; `cosmos/creatures/prototypes/reputation/reputation-roundrobin` is the reference (everyone weighs `1.0`). Operators
/// write their own (sliding average, EWMA, VRF-weighted, realm-allowlist) and bind it.
///
/// Returns a multiplier in `[0.0, ∞)`. `0.0` discards the attestation entirely (e.g. an
/// un-peered Realm); `1.0` credits it verbatim. The federator stores `score * weight`.
pub trait ReputationWeigher: Send + Sync {
    fn weight(&self, observer_key: &str, observer_realm: &RealmId) -> f32;
}

/// A trivial weigher that credits every signed attestation at `1.0`. Used by the crate's unit
/// tests; the operator-facing reference is `cosmos/creatures/prototypes/reputation/reputation-roundrobin`.
/// NEVER appropriate as a production trust model (it trusts every signer equally).
pub struct UnitWeigher;

impl ReputationWeigher for UnitWeigher {
    fn weight(&self, _observer_key: &str, _observer_realm: &RealmId) -> f32 {
        1.0
    }
}

// ===================================================================================================
// Structured no-route reply (Omega routing)
// ===================================================================================================

/// Why an Omega envelope couldn't be routed. Tagged on `"kind"` so an orchestrator dispatches
/// on the variant, not on prose (same discipline as `realm-gateway`'s `NoRealmRouteReason`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NoOmegaRouteReason {
    /// No peer mapped for the named Realm in the federator's view.
    UnmappedRealm,
    /// Only `target = Creature(m)` is forwarded (matches the realm-gateway limit); nested
    /// grain (Role/Topic/Intent/Realm/Omega) is a later enhancement.
    UnsupportedTarget,
}

/// Structured reply when an Omega envelope can't be routed. Schema = `omega.no_route`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NoOmegaRouteReply {
    pub reason: NoOmegaRouteReason,
    pub realm: RealmId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

impl NoOmegaRouteReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

// ===================================================================================================
// Control / inter-federator messages (schema = SCHEMA)
// ===================================================================================================

/// Every federator message on [`SCHEMA`]: operator control ops + the inter-federator quarantine
/// notice + the federator's replies. Reputation deltas ride the SEER consensus topic, not this
/// enum (criterion 4: reputation propagates over SEER).
///
/// Forward-compat: new variants at the END are additive; reordering/renaming is a wire break.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FederatorMsg {
    // ----- operator → federator (control plane) -----
    /// Run one anti-entropy pull from a peer Realm: ask `peer_node`'s registry for its
    /// `source_realm` catalog and merge it locally.
    PullFrom { source_realm: RealmId, peer_node: NodeId, peer_registry: CreatureId },
    /// Sign a reputation observation with this federator's Abode key and ship it to a peer
    /// federator over the SEER consensus topic.
    FederateReputation {
        artifact_hash: String,
        realm: RealmId,
        score: f32,
        peer_node: NodeId,
        peer_federator: CreatureId,
    },
    /// Ship a quarantine notice to a peer federator (the cross-Realm defense path; the
    /// immune-response reacts).
    FederateQuarantine {
        artifact_hash: String,
        realm: RealmId,
        reason: String,
        peer_node: NodeId,
        peer_federator: CreatureId,
    },

    // ----- peer federator → this federator (cross-node) -----
    /// An inbound quarantine notice from a peer federator — write it into the local registry.
    QuarantineNotice {
        artifact_hash: String,
        realm: RealmId,
        reason: String,
        #[serde(default)]
        attesting_peers: Vec<String>,
    },

    // ----- federator → operator (replies) -----
    /// A control op was accepted (the work was dispatched). Pulls/propagations complete
    /// asynchronously; observe the result on the local registry.
    Accepted { note: String },
    /// A control op was rejected before any work (e.g. unmapped Realm).
    Rejected { reason: String },
}

impl FederatorMsg {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
    pub fn parse_bounded(bytes: &[u8]) -> Result<Self, FederatorMsgParseError> {
        if bytes.len() > MAX_FEDERATOR_MESSAGE_BYTES {
            return Err(FederatorMsgParseError::TooLarge {
                len: bytes.len(),
                limit: MAX_FEDERATOR_MESSAGE_BYTES,
            });
        }
        Self::parse(bytes).map_err(FederatorMsgParseError::Json)
    }
}

#[derive(Debug)]
pub enum FederatorMsgParseError {
    TooLarge { len: usize, limit: usize },
    Json(serde_json::Error),
}

// ===================================================================================================
// The federator
// ===================================================================================================

/// Construction config — the operator wires this before `Kernel::load_instance`.
///
/// **Reserved corr range.** The federator allocates its own consult corrs (for anti-entropy
/// `ListEntries` and SEER reputation deltas) starting at `3_000_000` and counting up (see
/// `OmegaFederator::alloc_corr`). It keys `pending_pulls` by that corr, so an operator
/// control op MUST NOT reuse a corr in `[3_000_000, u64::MAX)` — a collision would let an unrelated
/// reply resolve the wrong parked pull. Operator-driven corrs stay small (the cross-node test uses
/// `1..=5`); the gap is deliberate, mirroring `abode-migrator`'s `1_000_000` seed. The split is
/// documented here rather than enforced in the type.
pub struct FederatorConfig {
    /// This federator's own node.
    pub self_node: NodeId,
    /// The Realm this federator belongs to (tagged as `observer_realm` on outbound attestations).
    pub self_realm: RealmId,
    /// The local `registry-mem` creature id — where pulls merge and reputation/quarantine land.
    pub local_registry: CreatureId,
    /// This federator's Abode authorship key — signs outbound reputation deltas (T3).
    pub abode_key: Ed25519KeyMaterial,
    /// `realm → peer` map for Omega routing (single peer per Realm, like realm-gateway).
    pub realm_to_peer: HashMap<RealmId, NodeId>,
    /// Injected weight model. Substrate ships none.
    pub weigher: Box<dyn ReputationWeigher>,
}

/// In-flight anti-entropy pull, keyed by the `ListEntries` consult corr.
struct PendingPull {
    source_realm: RealmId,
}

/// The federator creature.
pub struct OmegaFederator {
    cfg: FederatorConfig,
    me: Option<CreatureId>,
    verifier: Arc<dyn Verifier>,
    pending_pulls: HashMap<u64, PendingPull>,
    next_consult_corr: u64,
    ingest_rejections: IngestRejections,
    /// Maximum number of in-flight anti-entropy pulls held at once. A peer registry that never
    /// answers a `ListEntries` would otherwise leak a `pending_pulls` entry per pull forever. At
    /// capacity a new pull is refused (the in-flight pulls are kept — refuse-new, never evict-live).
    /// **`0` means unbounded** and should be reserved for lab/demo deployments that intentionally
    /// accept unbounded pending state.
    max_pending_pulls: usize,
}

impl OmegaFederator {
    pub fn new(cfg: FederatorConfig) -> Self {
        Self::new_with_realm_peer_limit(cfg, DEFAULT_MAX_FEDERATOR_REALM_PEERS)
    }

    /// Construct with an explicit Realm→peer route-table cap. `max_realm_peers == 0` disables the
    /// cap for lab/demo configurations.
    pub fn new_with_realm_peer_limit(mut cfg: FederatorConfig, max_realm_peers: usize) -> Self {
        cfg.realm_to_peer = retain_valid_realm_peers(cfg.realm_to_peer, max_realm_peers);
        OmegaFederator {
            cfg,
            me: None,
            verifier: Arc::new(Ed25519Verifier),
            pending_pulls: HashMap::new(),
            next_consult_corr: 3_000_000,
            ingest_rejections: IngestRejections::default(),
            max_pending_pulls: DEFAULT_MAX_PENDING_PULLS,
        }
    }

    /// Number of retained Realm→peer mappings. Exposed for tests and diagnostics.
    pub fn realm_peer_count(&self) -> usize {
        self.cfg.realm_to_peer.len()
    }

    /// Cap the number of concurrently in-flight anti-entropy pulls. `0` disables the cap. At
    /// capacity, a new `PullFrom` is refused with a `Rejected` ack rather than growing the
    /// pending-pulls table without bound when a peer never answers.
    pub fn with_max_pending_pulls(mut self, max_pending_pulls: usize) -> Self {
        self.max_pending_pulls = max_pending_pulls;
        self
    }

    /// Reputation-ingest rejection counters — observability for junk-delta sprays.
    pub fn ingest_rejections(&self) -> &IngestRejections {
        &self.ingest_rejections
    }

    /// Swap the verifier (tests that drive `handle` with a deterministic stub).
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Pin the consult-corr seed for deterministic tests.
    pub fn with_consult_corr_seed(mut self, seed: u64) -> Self {
        self.next_consult_corr = seed;
        self
    }

    /// Whether an anti-entropy pull is in flight.
    pub fn has_pending_pull(&self) -> bool {
        !self.pending_pulls.is_empty()
    }

    /// Number of in-flight anti-entropy pulls. Exposed for tests and operator-facing diagnostics;
    /// not part of the wire contract.
    pub fn pending_pull_count(&self) -> usize {
        self.pending_pulls.len()
    }

    fn alloc_corr(&mut self) -> u64 {
        let c = self.next_consult_corr;
        self.next_consult_corr = self.next_consult_corr.wrapping_add(1);
        c
    }

    /// Collapse `peer_node == self_node` to a local [`Address::Creature`]; otherwise
    /// [`Address::Node`]. Same self-collapse the distributor + migrator use so a same-Sanctum
    /// target doesn't route through `transport-tcp` (which has no peer named "self").
    fn addr_for(&self, peer_node: &NodeId, creature: CreatureId) -> Address {
        if *peer_node == self.cfg.self_node {
            Address::Creature(creature)
        } else {
            Address::Node(peer_node.clone(), creature)
        }
    }

    fn me_id(&self) -> Option<CreatureId> {
        self.me
    }
}

/// The federator binds [`Role::OMEGA_GATEWAY`](aether::Role::OMEGA_GATEWAY) (named
/// `omega::GATEWAY_ROLE` by the Ω contract crate) and *resolves* Omega addresses. The `omega` concept
/// crate deliberately exposes no routing seam trait — the two gateways diverge too far for a
/// shared per-envelope `resolve` (this federator's
/// behavior is stateful anti-entropy + signed reputation + a quarantine path, not a pure decision), so
/// its routing lives entirely in [`Creature::handle`] below.
impl Creature for OmegaFederator {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // 1. Omega-addressed envelope → route it (the IoC OMEGA_GATEWAY job).
        if let Address::Omega { realm, target } = &env.header.to {
            return self.route_omega(&env, realm.clone(), target.as_ref().clone());
        }
        // 2. Addressed to us as a module → dispatch by schema.
        match env.header.schema.as_str() {
            seer::SCHEMA => self.on_seer(&env),
            REGISTRY_REPLY_SCHEMA => self.on_registry_reply(&env),
            SCHEMA => self.on_control(&env),
            // Misbind / stray — never crash (R9).
            _ => Outcome::none(),
        }
    }
}

impl OmegaFederator {
    // ----- Omega routing --------------------------------------------------------------------

    fn route_omega(&mut self, env: &Envelope, realm: RealmId, target: Address) -> Outcome {
        let peer = match self.cfg.realm_to_peer.get(&realm) {
            Some(p) => p.clone(),
            None => {
                return Outcome::send(self.no_route(
                    env,
                    realm.clone(),
                    NoOmegaRouteReason::UnmappedRealm,
                    Some(format!(
                        "omega-federator has no peer mapped for realm `{}`; configure realm_to_peer",
                        realm.0
                    )),
                ));
            }
        };
        let target_module = match target {
            Address::Creature(m) => m,
            other => {
                return Outcome::send(self.no_route(
                    env,
                    realm,
                    NoOmegaRouteReason::UnsupportedTarget,
                    Some(format!(
                        "v0.3 omega-federator forwards only `Omega(R, Creature(m))`; got {other:?}"
                    )),
                ));
            }
        };

        // Re-route Node(peer, target). Preserve reply_to / corr / schema / payload / commitment
        // byte-for-byte so the eventual responder answers the *original* requester — exactly the
        // realm-gateway discipline, so a cross-Realm SEER consult (placement, etc.) round-trips.
        let reply_to = env.reply_target();
        let mut d = Dispatch::to(self.addr_for(&peer, target_module), env.payload.clone())
            .with_schema(&env.header.schema)
            .with_reply_to(reply_to);
        if let Some(corr) = env.header.corr {
            d = d.with_corr(corr);
        }
        if let Some(commit) = &env.header.commitment {
            d = d.with_commitment(commit.clone());
        }
        Outcome::send(d)
    }

    fn no_route(
        &self,
        env: &Envelope,
        realm: RealmId,
        reason: NoOmegaRouteReason,
        details: Option<String>,
    ) -> Dispatch {
        let reply = NoOmegaRouteReply { reason, realm, details };
        Dispatch::reply_to_env(env, reply.to_bytes()).with_schema("omega.no_route")
    }

    // ----- control plane (operator → federator) -------------------------------------------------

    fn on_control(&mut self, env: &Envelope) -> Outcome {
        let Ok(msg) = FederatorMsg::parse_bounded(&env.payload) else {
            return Outcome::none(); // R9: never panic on malformed input.
        };
        match msg {
            FederatorMsg::PullFrom { source_realm, peer_node, peer_registry } => {
                self.on_pull_from(env, source_realm, peer_node, peer_registry)
            }
            FederatorMsg::FederateReputation {
                artifact_hash,
                realm,
                score,
                peer_node,
                peer_federator,
            } => self.on_federate_reputation(
                env,
                artifact_hash,
                realm,
                score,
                peer_node,
                peer_federator,
            ),
            FederatorMsg::FederateQuarantine {
                artifact_hash,
                realm,
                reason,
                peer_node,
                peer_federator,
            } => self.on_federate_quarantine(
                env,
                artifact_hash,
                realm,
                reason,
                peer_node,
                peer_federator,
            ),
            FederatorMsg::QuarantineNotice { artifact_hash, realm, reason, attesting_peers } => {
                self.on_inbound_quarantine(artifact_hash, realm, reason, attesting_peers)
            }
            // Replies arriving inbound (echo / misdirected) — the federator issues these, never
            // consumes them.
            FederatorMsg::Accepted { .. } | FederatorMsg::Rejected { .. } => Outcome::none(),
        }
    }

    fn on_pull_from(
        &mut self,
        env: &Envelope,
        source_realm: RealmId,
        peer_node: NodeId,
        peer_registry: CreatureId,
    ) -> Outcome {
        let Some(me) = self.me_id() else {
            return reply(env, FederatorMsg::Rejected { reason: "federator not bound yet".into() });
        };
        if let Some(message) = federation_endpoint_shape_error(&source_realm, &peer_node) {
            return reply(env, FederatorMsg::Rejected { reason: message });
        }
        // Pending-pressure guard (resilience): refuse a new pull at capacity rather than leak a
        // pending entry forever when a peer registry never answers. Refuse-new keeps every in-flight
        // pull intact. `0` disables the cap.
        if self.max_pending_pulls != 0 && self.pending_pulls.len() >= self.max_pending_pulls {
            eprintln!(
                "omega-federator: pending-pulls table at capacity ({}); refusing pull from realm {}",
                self.max_pending_pulls, source_realm.0
            );
            return reply(
                env,
                FederatorMsg::Rejected {
                    reason: "federator busy: pending-pulls table at capacity".into(),
                },
            );
        }

        // Ask the peer registry for its `source_realm` catalog; park the pull keyed by the consult
        // corr. The merge happens when the Entries reply arrives (on_registry_reply).
        let corr = self.alloc_corr();
        self.pending_pulls.insert(corr, PendingPull { source_realm: source_realm.clone() });
        let op = RegistryOp::ListEntries { realm: Some(source_realm) };
        let d = Dispatch::to(self.addr_for(&peer_node, peer_registry), op.to_bytes())
            .with_schema("registry.op")
            .with_corr(corr)
            .with_reply_to(Address::Creature(me));
        // Acknowledge the operator immediately; the merge is asynchronous.
        let ack = reply(env, FederatorMsg::Accepted { note: "pull dispatched".into() });
        let mut out = Outcome::send(d);
        out.dispatches.extend(ack.dispatches);
        out
    }

    fn on_federate_reputation(
        &mut self,
        env: &Envelope,
        artifact_hash: String,
        realm: RealmId,
        score: f32,
        peer_node: NodeId,
        peer_federator: CreatureId,
    ) -> Outcome {
        let Some(me) = self.me_id() else {
            return reply(env, FederatorMsg::Rejected { reason: "federator not bound yet".into() });
        };
        if let Some(message) = registry_key_shape_error(&artifact_hash, &realm) {
            return reply(env, FederatorMsg::Rejected { reason: message });
        }
        if let Some(message) = peer_node_shape_error("federator", "peer_node", &peer_node) {
            return reply(env, FederatorMsg::Rejected { reason: message });
        }
        if !score.is_finite() {
            return reply(
                env,
                FederatorMsg::Rejected { reason: "reputation score must be finite".into() },
            );
        }
        // Build + sign the delta with our Abode key (T3). observer_realm = our Realm.
        let mut delta = ReputationDelta {
            artifact_hash,
            realm,
            score,
            observer_realm: self.cfg.self_realm.clone(),
            observer_key: self.cfg.abode_key.public_hex().to_string(),
            signature: None,
        };
        delta.sign(&self.cfg.abode_key);

        // Ride the SEER Consensus topic as a terminal Answer. `query_id = 0` is the SEER "no
        // precursor Query" convention (the same one `seer`'s reduction-theorem test uses:
        // a single terminal Answer with `query_id: 0`). A reputation delta is unsolicited — there
        // was no Query — so it is always a terminal `Answer { query_id: 0 }`; `on_seer` matches on
        // the topic + the signed `observer_key`, never on a query pairing, so the convention is
        // descriptive here, not load-bearing.
        let corr = self.alloc_corr();
        let seer = SeerEnvelope::answer(SeerTopic::Consensus, corr, 0, &delta);
        let d = Dispatch::to(self.addr_for(&peer_node, peer_federator), seer.to_bytes())
            .with_schema(seer::SCHEMA)
            .with_corr(corr)
            .with_reply_to(Address::Creature(me));
        let ack = reply(env, FederatorMsg::Accepted { note: "reputation delta shipped".into() });
        let mut out = Outcome::send(d);
        out.dispatches.extend(ack.dispatches);
        out
    }

    fn on_federate_quarantine(
        &mut self,
        env: &Envelope,
        artifact_hash: String,
        realm: RealmId,
        reason: String,
        peer_node: NodeId,
        peer_federator: CreatureId,
    ) -> Outcome {
        let Some(me) = self.me_id() else {
            return reply(env, FederatorMsg::Rejected { reason: "federator not bound yet".into() });
        };
        if let Some(message) = registry_key_shape_error(&artifact_hash, &realm).or_else(|| {
            QuarantineNotice::mark_shape_error(
                &artifact_hash,
                &realm,
                &reason,
                std::slice::from_ref(&self.cfg.self_node.0),
            )
        }) {
            return reply(env, FederatorMsg::Rejected { reason: message });
        }
        if let Some(message) = peer_node_shape_error("federator", "peer_node", &peer_node) {
            return reply(env, FederatorMsg::Rejected { reason: message });
        }
        // Ship the notice to the peer federator. attesting_peers seeded with our own node id.
        let notice = FederatorMsg::QuarantineNotice {
            artifact_hash,
            realm,
            reason,
            attesting_peers: vec![self.cfg.self_node.0.clone()],
        };
        let corr = self.alloc_corr();
        let d = Dispatch::to(self.addr_for(&peer_node, peer_federator), notice.to_bytes())
            .with_schema(SCHEMA)
            .with_corr(corr)
            .with_reply_to(Address::Creature(me));
        let ack = reply(env, FederatorMsg::Accepted { note: "quarantine notice shipped".into() });
        let mut out = Outcome::send(d);
        out.dispatches.extend(ack.dispatches);
        out
    }

    fn on_inbound_quarantine(
        &mut self,
        artifact_hash: String,
        realm: RealmId,
        reason: String,
        attesting_peers: Vec<String>,
    ) -> Outcome {
        if let Some(message) = registry_key_shape_error(&artifact_hash, &realm).or_else(|| {
            QuarantineNotice::mark_shape_error(&artifact_hash, &realm, &reason, &attesting_peers)
        }) {
            eprintln!(
                "omega-federator: dropped inbound quarantine notice for {artifact_hash} in realm {}: {message}",
                realm.0
            );
            return Outcome::none();
        }
        // Write the quarantine into the local registry (reversible — T5). No reply to the peer:
        // fire-and-forget defense signal. The local immune-response creature acts on it.
        let op = RegistryOp::MarkQuarantine { artifact_hash, realm, reason, attesting_peers };
        let Some(me) = self.me_id() else {
            return Outcome::none();
        };
        Outcome::send(
            Dispatch::to(Address::Creature(self.cfg.local_registry), op.to_bytes())
                .with_schema("registry.op")
                .with_reply_to(Address::Creature(me)),
        )
    }

    // ----- reputation ingest (SEER consensus) ---------------------------------------------------

    fn on_seer(&mut self, env: &Envelope) -> Outcome {
        let Ok(seer) = SeerEnvelope::parse_bounded(&env.payload) else {
            self.ingest_rejections.malformed += 1;
            return Outcome::none();
        };
        // Only the Consensus topic carries reputation deltas; other topics aren't ours (not a junk
        // attestation — a misroute; not counted).
        if seer.topic != SeerTopic::Consensus {
            return Outcome::none();
        }
        let body = match seer.kind {
            SeerKind::Answer { body, .. } => body,
            // A Query/Steer/Progress/Thought on consensus isn't a delta we ingest (not counted).
            _ => return Outcome::none(),
        };
        let Ok(delta) = serde_json::from_value::<ReputationDelta>(body) else {
            self.ingest_rejections.malformed += 1;
            return Outcome::none();
        };
        if let Some(message) = reputation_delta_shape_error(&delta) {
            self.ingest_rejections.malformed += 1;
            eprintln!("omega-federator: dropped malformed reputation delta: {message}");
            return Outcome::none();
        }

        // R9 / adversarial-numeric guard. `score: f32` is attacker-controlled wire
        // data: JSON has no NaN/∞ literals, but an out-of-range magnitude (`{"score": 1e400}`)
        // deserializes to `f32::INFINITY`. A non-finite score must never reach the registry — it
        // would poison every downstream selection and defense read of this entry. Drop
        // it before the signature check (cheaper) — a non-finite score is malformed regardless of
        // who signed it.
        if !delta.score.is_finite() {
            self.ingest_rejections.non_finite_score += 1;
            return self.emit_ingest_drop(
                "non_finite_score",
                &delta.observer_key,
                &delta.observer_realm,
            );
        }

        // T3: a delta that isn't validly signed by its declared observer key never updates the
        // registry. This is the "reputation is computed, not asserted" gate.
        if !delta.verify(self.verifier.as_ref()) {
            self.ingest_rejections.bad_signature += 1;
            return self.emit_ingest_drop(
                "bad_signature",
                &delta.observer_key,
                &delta.observer_realm,
            );
        }

        // Injected weight model decides how much to credit (IoC). The weigher is *operator code*,
        // so its output is untrusted too: reject NaN / ±∞ / ≤0 in one finite-positive gate. A bare
        // `weight <= 0.0` would let a NaN through (`NaN <= 0.0` is `false` by IEEE-754), and
        // `score * NaN` would then write NaN into the registry. `0.0` still means "ignore" (an
        // un-peered Realm); only a finite positive weight credits the attestation. This drop is
        // *expected* (un-peered Realms are routine), so it's counted but not surfaced.
        let weight = self.cfg.weigher.weight(&delta.observer_key, &delta.observer_realm);
        if !weight.is_finite() || weight <= 0.0 {
            self.ingest_rejections.unweighted += 1;
            return Outcome::none();
        }

        // Apply: AttestFitness into the local registry, tagged with the observer's Realm. Peer
        // reputation is stored *unsigned* (signed_by/signature = None): its provenance is the
        // `attesting_realm` tag, not a promotion signature. The observer signed the *delta* (a
        // different payload, already verified above at the T3 gate) — that signature doesn't
        // commit to the ReputationScore promotion claim, so forwarding it would not verify. A
        // *local* promotion (the fitness-selector) is what carries signed_by/signature.
        let op = RegistryOp::AttestFitness {
            artifact_hash: delta.artifact_hash,
            realm: delta.realm,
            score: delta.score * weight,
            attesting_realm: Some(delta.observer_realm),
            signed_by: None,
            signature: None,
        };
        let Some(me) = self.me_id() else {
            return Outcome::none();
        };
        Outcome::send(
            Dispatch::to(Address::Creature(self.cfg.local_registry), op.to_bytes())
                .with_schema("registry.op")
                .with_reply_to(Address::Creature(me)),
        )
    }

    /// Surface a malformed-attestation drop as an [`INGEST_DROP_SCHEMA`] proprioception event.
    /// Best-effort + observable: the fan-out is bounded by the bus (R9), so a peer
    /// spraying junk can't OOM the topic — it just makes itself visible to the defense loop. The
    /// event carries the *claimed* (unverified) observer key/Realm as an audit hint.
    fn emit_ingest_drop(
        &self,
        reason: &'static str,
        observer_key: &str,
        observer_realm: &RealmId,
    ) -> Outcome {
        let ev = IngestDropEvent {
            reason: reason.to_string(),
            observer_key: observer_key.to_string(),
            observer_realm: observer_realm.0.clone(),
        };
        Outcome::send(
            Dispatch::to(
                Address::Topic(Topic::new(Topic::PROPRIOCEPTION)),
                aether::wire::to_bytes(&ev),
            )
            .with_schema(INGEST_DROP_SCHEMA),
        )
    }

    // ----- anti-entropy merge (registry Entries reply) ------------------------------------------

    fn on_registry_reply(&mut self, env: &Envelope) -> Outcome {
        // An oversized pull reply cannot be merged, but it must not be dropped silently while its
        // parked pull leaks forever. Log it and reclaim the matching pending slot so the operator
        // can retry a narrower Realm scope. (A malformed-but-in-bound reply still drops below.)
        if env.payload.len() > MAX_REGISTRY_REPLY_BYTES {
            if let Some(corr) = env.header.corr {
                if self.pending_pulls.remove(&corr).is_some() {
                    eprintln!(
                        "omega-federator: dropped an oversized pull reply ({} bytes > {} cap) for \
                         corr {corr}; pull slot reclaimed — retry with a narrower Realm scope",
                        env.payload.len(),
                        MAX_REGISTRY_REPLY_BYTES
                    );
                }
            }
            return Outcome::none();
        }
        // Only Entries replies matter (pull results). Other registry replies (Published from our
        // own merge writes, etc.) are acknowledgements we drop.
        let Some(reply) = parse_registry_reply(&env.payload) else {
            return Outcome::none();
        };
        let entries = match reply {
            RegistryReply::Entries { entries } => entries,
            // A corr-matching non-Entries reply is the *terminal* answer to a pull that cannot be
            // merged — most importantly the source registry's `RegistryReply::Error` when its own
            // `ListEntries` snapshot artifact-byte cap refuses an over-cap pull. Reclaim the parked
            // slot (mirroring the oversized-payload path above) or anti-entropy wedges after the pull
            // cap fills. Our own merge-write acks carry no corr, so they never match a parked pull.
            other => {
                if let Some(corr) = env.header.corr {
                    if self.pending_pulls.remove(&corr).is_some() {
                        eprintln!(
                            "omega-federator: pull reply for corr {corr} was {other:?}, not Entries; \
                             slot reclaimed — retry with a narrower Realm scope"
                        );
                    }
                }
                return Outcome::none();
            }
        };
        // Match the pull by corr; a reply with no matching pending is stale/duplicate — drop.
        let Some(corr) = env.header.corr else {
            return Outcome::none();
        };
        let Some(me) = self.me_id() else {
            return Outcome::none();
        };
        let Some(pending) = self.pending_pulls.remove(&corr) else {
            return Outcome::none();
        };

        // Merge each entry into the LOCAL registry, **pinned to the Realm we asked for** — not the
        // Realm the peer tags on the entry. This is a T2-aligned guard: a scoped pull of Realm X
        // can only ever write Realm X locally, so a peer can't smuggle entries into a Realm we
        // didn't pull.
        //
        // For each entry we emit up to three ops in order: `Publish` (which resets both
        // signals to `None` — for `quarantine` that reset IS the T5 reversibility rule; for
        // `reputation` it's just the clean-slate side effect of a (re)publish), then
        // `AttestFitness` and/or `MarkQuarantine` to re-apply the pulled signals.
        //
        // **Ordering precondition.** `AttestFitness`/`MarkQuarantine` are no-ops
        // (`NotFound`, never a panic) unless the entry already exists, so each re-apply must land
        // *after* its `Publish`. We rely on the **documented `aether::Outcome` local-delivery
        // contract**: dispatches in one Outcome drain in push-order into a local module's
        // single-consumer FIFO inbox, so the publish precedes its attest/mark for the same entry.
        // That contract is **local-only** — a reconciler federating to a *remote* registry must
        // confirm the publish reply before re-applying rather than rely on inbox FIFO (transport
        // gives no cross-node ordering). `self.cfg.local_registry` is local by construction here.
        let realm = pending.source_realm;
        let mut out = Outcome::none();
        for e in entries {
            if let Some(message) = pulled_sync_entry_shape_error(&e) {
                self.ingest_rejections.malformed += 1;
                eprintln!(
                    "omega-federator: dropped malformed pulled entry for {} in requested realm {}: {message}",
                    e.artifact_hash, realm.0
                );
                continue;
            }
            let pub_op = RegistryOp::Publish {
                manifest: e.manifest,
                artifact: e.artifact,
                realm: Some(realm.clone()),
            };
            out.dispatches.push(
                Dispatch::to(Address::Creature(self.cfg.local_registry), pub_op.to_bytes())
                    .with_schema("registry.op")
                    .with_reply_to(Address::Creature(me)),
            );
            // Same adversarial-numeric guard as `on_seer`: a pulled `score: f32` is
            // peer-supplied wire data, and a non-finite value (`1e400` → `f32::INFINITY`) would
            // poison every downstream selection / defense read of this entry. Drop a
            // non-finite pulled score before forwarding the AttestFitness — the guarded
            // twin of the on_seer guard. (T10)
            if let Some(rep) = e.reputation {
                if !rep.score.is_finite() {
                    self.ingest_rejections.non_finite_score += 1;
                } else if let Some(message) = rep.attest_shape_error(&e.artifact_hash, &realm) {
                    self.ingest_rejections.malformed += 1;
                    eprintln!(
                        "omega-federator: dropped malformed pulled reputation for {} in realm {}: {message}",
                        e.artifact_hash, realm.0
                    );
                } else {
                    // Pulled reputation is forwarded **unchanged** — NOT re-weighted by our local
                    // `weigher`. The score in a `SyncEntry` was already weighted by the Realm that
                    // attested it (over its own SEER consensus ingest); re-applying our weight here
                    // would double-count. The local weight model applies only to *signed deltas
                    // arriving live over SEER* (`on_seer`), where we are the first observer to credit
                    // them.
                    let attest = RegistryOp::AttestFitness {
                        artifact_hash: e.artifact_hash.clone(),
                        realm: realm.clone(),
                        score: rep.score,
                        attesting_realm: rep.attesting_realm,
                        // Forward any promotion signature verbatim so a pulled promotion stays
                        // verifiable on the puller (the signature commits to artifact_hash + realm +
                        // score, which are preserved across the pull — the realm is pinned, so a
                        // signature made for realm X re-verifies only if the entry is pinned to X).
                        signed_by: rep.signed_by,
                        signature: rep.signature,
                    };
                    out.dispatches.push(
                        Dispatch::to(Address::Creature(self.cfg.local_registry), attest.to_bytes())
                            .with_schema("registry.op")
                            .with_reply_to(Address::Creature(me)),
                    );
                }
            }
            if let Some(q) = e.quarantine {
                if let Some(message) = QuarantineNotice::mark_shape_error(
                    &e.artifact_hash,
                    &realm,
                    &q.reason,
                    &q.attesting_peers,
                ) {
                    eprintln!(
                        "omega-federator: dropped pulled quarantine marker for {} in realm {}: {message}",
                        e.artifact_hash, realm.0
                    );
                } else {
                    let mark = RegistryOp::MarkQuarantine {
                        artifact_hash: e.artifact_hash.clone(),
                        realm: realm.clone(),
                        reason: q.reason,
                        attesting_peers: q.attesting_peers,
                    };
                    out.dispatches.push(
                        Dispatch::to(Address::Creature(self.cfg.local_registry), mark.to_bytes())
                            .with_schema("registry.op")
                            .with_reply_to(Address::Creature(me)),
                    );
                }
            }
        }
        out
    }
}

#[doc(hidden)]
impl OmegaFederator {
    /// For tests that drive `handle` directly without a kernel `bind`.
    #[cfg(test)]
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

// ----- helpers --------------------------------------------------------------------------------

fn parse_registry_reply(payload: &[u8]) -> Option<RegistryReply> {
    parse_registry_reply_with_limit(payload, MAX_REGISTRY_REPLY_BYTES)
}

fn parse_registry_reply_with_limit(payload: &[u8], limit: usize) -> Option<RegistryReply> {
    if payload.len() > limit {
        return None;
    }
    serde_json::from_slice(payload).ok()
}

fn field_shape_error(scope: &str, field: &str, value: &str) -> Option<String> {
    if value.len() > MAX_REGISTRY_SIGNAL_FIELD_BYTES {
        Some(format!(
            "{scope} {field} too large: {} bytes exceeds {} byte limit",
            value.len(),
            MAX_REGISTRY_SIGNAL_FIELD_BYTES
        ))
    } else if value.contains('\0') {
        Some(format!("{scope} {field} contains NUL byte"))
    } else {
        None
    }
}

fn realm_field_shape_error(scope: &str, field: &str, realm: &RealmId) -> Option<String> {
    if let Some(message) = field_shape_error(scope, field, &realm.0) {
        return Some(message);
    }
    if !realm.is_valid() {
        return Some(format!("{scope} {field} is not a valid RealmId"));
    }
    None
}

fn peer_node_shape_error(scope: &str, field: &str, peer_node: &NodeId) -> Option<String> {
    if !node_id_shape_is_valid(peer_node) {
        return Some(format!(
            "{scope} {field} must be 1..={MAX_FEDERATOR_NODE_ID_BYTES} ASCII [A-Za-z0-9._-] bytes"
        ));
    }
    None
}

fn registry_key_shape_error(artifact_hash: &str, realm: &RealmId) -> Option<String> {
    artifact_hash_shape_error(artifact_hash)
        .map(|message| format!("federator {message}"))
        .or_else(|| realm_field_shape_error("federator", "realm", realm))
}

fn pulled_sync_entry_shape_error(entry: &registry_mem::SyncEntry) -> Option<String> {
    if let Some(message) = artifact_hash_shape_error(&entry.artifact_hash) {
        return Some(message);
    }
    let actual = sha256_hex(&entry.artifact);
    if actual != entry.artifact_hash {
        return Some(format!(
            "artifact_hash does not match artifact bytes: advertised {}, actual {actual}",
            entry.artifact_hash
        ));
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn federation_endpoint_shape_error(source_realm: &RealmId, peer_node: &NodeId) -> Option<String> {
    realm_field_shape_error("federator", "source_realm", source_realm)
        .or_else(|| peer_node_shape_error("federator", "peer_node", peer_node))
}

fn retain_valid_realm_peers(
    mappings: HashMap<RealmId, NodeId>,
    max_mappings: usize,
) -> HashMap<RealmId, NodeId> {
    let mut retained = HashMap::new();
    for (realm, peer) in mappings {
        insert_realm_peer_mapping(&mut retained, realm, peer, max_mappings);
    }
    retained
}

fn insert_realm_peer_mapping(
    mappings: &mut HashMap<RealmId, NodeId>,
    realm: RealmId,
    peer: NodeId,
    max_mappings: usize,
) {
    if let Some(reason) = realm_peer_mapping_shape_error(&realm, &peer) {
        eprintln!("omega-federator: {reason}");
        return;
    }
    if max_mappings != 0 && !mappings.contains_key(&realm) && mappings.len() >= max_mappings {
        eprintln!(
            "omega-federator: realm_to_peer table at capacity ({max_mappings}); refusing realm {}",
            realm.0
        );
        return;
    }
    mappings.insert(realm, peer);
}

fn realm_peer_mapping_shape_error(realm: &RealmId, peer: &NodeId) -> Option<String> {
    if !realm.is_valid() || realm.0.len() > MAX_FEDERATOR_REALM_BYTES || realm.0.contains('\0') {
        return Some(format!(
            "realm_to_peer realm must be valid, NUL-free, and <= {MAX_FEDERATOR_REALM_BYTES} bytes"
        ));
    }
    if !node_id_shape_is_valid(peer) {
        return Some(format!(
            "realm_to_peer peer_node must be 1..={MAX_FEDERATOR_NODE_ID_BYTES} ASCII [A-Za-z0-9._-] bytes"
        ));
    }
    None
}

fn node_id_shape_is_valid(node: &NodeId) -> bool {
    let s = node.0.as_str();
    !s.is_empty()
        && s.len() <= MAX_FEDERATOR_NODE_ID_BYTES
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn reputation_delta_shape_error(delta: &ReputationDelta) -> Option<String> {
    registry_key_shape_error(&delta.artifact_hash, &delta.realm)
        .or_else(|| {
            realm_field_shape_error("reputation delta", "observer_realm", &delta.observer_realm)
        })
        .or_else(|| field_shape_error("reputation delta", "observer_key", &delta.observer_key))
        .or_else(|| {
            delta
                .signature
                .as_deref()
                .and_then(|signature| field_shape_error("reputation delta", "signature", signature))
        })
}

/// Reply to the envelope's `reply_to` (or `from`) with a federator message + SCHEMA + corr.
fn reply(env: &Envelope, msg: FederatorMsg) -> Outcome {
    Outcome::send(Dispatch::reply_to_env(env, msg.to_bytes()).with_schema(SCHEMA))
}

// ===================================================================================================
// Tests
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::Header;
    use bestiary::{MAX_QUARANTINE_ATTESTING_PEER_BYTES, MAX_QUARANTINE_REASON_BYTES};
    use registry_mem::ReputationScore;

    const SELF_NODE: &str = "node-A";
    const SELF_REALM: &str = "crew";
    const PEER_NODE: &str = "node-B";
    const REGISTRY: CreatureId = CreatureId(50);
    const ME: CreatureId = CreatureId(9);

    fn key(seed: u8) -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([seed; 32]).unwrap()
    }

    fn fed(seed: u8) -> OmegaFederator {
        let mut map = HashMap::new();
        map.insert(RealmId::new("guests"), NodeId(PEER_NODE.into()));
        let cfg = FederatorConfig {
            self_node: NodeId(SELF_NODE.into()),
            self_realm: RealmId::new(SELF_REALM),
            local_registry: REGISTRY,
            abode_key: key(seed),
            realm_to_peer: map,
            weigher: Box::new(UnitWeigher),
        };
        let mut f = OmegaFederator::new(cfg).with_consult_corr_seed(700_000);
        f.set_me_for_tests(ME);
        f
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

    fn control_env(msg: FederatorMsg, corr: u64) -> Envelope {
        Envelope {
            header: header(Address::Creature(ME), SCHEMA, Some(corr)),
            payload: msg.to_bytes(),
        }
    }

    fn parse_op(d: &Dispatch) -> RegistryOp {
        serde_json::from_slice(&d.payload).unwrap()
    }

    fn artifact_hash(bytes: &[u8]) -> String {
        sha256_hex(bytes)
    }

    // ----- ReputationDelta sign/verify (T3) ----

    #[test]
    fn reputation_delta_sign_then_verify_round_trips() {
        let k = key(0xA1);
        let mut delta = ReputationDelta {
            artifact_hash: artifact_hash(b"reputation-target"),
            realm: RealmId::new("crew"),
            score: 0.9,
            observer_realm: RealmId::new("crew"),
            observer_key: k.public_hex().to_string(),
            signature: None,
        };
        assert!(!delta.verify(&Ed25519Verifier), "unsigned must not verify");
        delta.sign(&k);
        assert!(delta.verify(&Ed25519Verifier), "signed verifies under observer_key");
    }

    #[test]
    fn reputation_delta_tamper_after_signing_fails_verify() {
        let k = key(0xA2);
        let mut delta = ReputationDelta {
            artifact_hash: artifact_hash(b"reputation-target"),
            realm: RealmId::new("crew"),
            score: 0.5,
            observer_realm: RealmId::new("crew"),
            observer_key: k.public_hex().to_string(),
            signature: None,
        };
        delta.sign(&k);
        delta.score = 1.0; // tamper after signing
        assert!(!delta.verify(&Ed25519Verifier));
    }

    // ----- Omega routing ----

    #[test]
    fn routes_omega_module_target_to_mapped_peer_preserving_reply_state() {
        let mut f = fed(0xB1);
        let env = Envelope {
            header: header(
                Address::Omega {
                    realm: RealmId::new("guests"),
                    target: Box::new(Address::Creature(CreatureId(42))),
                },
                "seer",
                Some(5),
            ),
            payload: b"consult-body".to_vec(),
        };
        let out = f.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Node(NodeId(PEER_NODE.into()), CreatureId(42)));
        assert_eq!(d.corr, Some(5));
        assert_eq!(d.schema, "seer");
        assert_eq!(d.payload, b"consult-body");
        // reply_to preserved (so the cross-Realm responder answers the original requester).
        assert_eq!(d.reply_to, Some(Address::Creature(CreatureId(100))));
    }

    #[test]
    fn unmapped_realm_yields_structured_no_route() {
        let mut f = fed(0xB2);
        let env = Envelope {
            header: header(
                Address::Omega {
                    realm: RealmId::new("unknown"),
                    target: Box::new(Address::Creature(CreatureId(1))),
                },
                "seer",
                Some(7),
            ),
            payload: b"x".to_vec(),
        };
        let d = &f.handle(env).dispatches[0];
        assert_eq!(d.schema, "omega.no_route");
        let reply: NoOmegaRouteReply = serde_json::from_slice(&d.payload).unwrap();
        assert_eq!(reply.reason, NoOmegaRouteReason::UnmappedRealm);
        assert_eq!(reply.realm, RealmId::new("unknown"));
    }

    #[test]
    fn route_table_config_is_sanitized_at_construction() {
        let mut map = HashMap::new();
        map.insert(RealmId::new("guests"), NodeId(PEER_NODE.into()));
        map.insert(RealmId::new("bad:realm"), NodeId("node-C".into()));
        map.insert(RealmId::new("bad-peer"), NodeId("bad peer".into()));
        map.insert(RealmId::new("bad-nul\0"), NodeId("node-D".into()));
        let mut f = OmegaFederator::new(FederatorConfig {
            self_node: NodeId(SELF_NODE.into()),
            self_realm: RealmId::new(SELF_REALM),
            local_registry: REGISTRY,
            abode_key: key(0xB4),
            realm_to_peer: map,
            weigher: Box::new(UnitWeigher),
        });
        f.set_me_for_tests(ME);

        assert_eq!(f.realm_peer_count(), 1);

        let routed = f.handle(Envelope {
            header: header(
                Address::Omega {
                    realm: RealmId::new("guests"),
                    target: Box::new(Address::Creature(CreatureId(42))),
                },
                "seer",
                Some(8),
            ),
            payload: b"x".to_vec(),
        });
        assert_eq!(
            routed.dispatches[0].to,
            Address::Node(NodeId(PEER_NODE.into()), CreatureId(42))
        );

        let refused = f.handle(Envelope {
            header: header(
                Address::Omega {
                    realm: RealmId::new("bad:realm"),
                    target: Box::new(Address::Creature(CreatureId(42))),
                },
                "seer",
                Some(9),
            ),
            payload: b"x".to_vec(),
        });
        let reply: NoOmegaRouteReply =
            serde_json::from_slice(&refused.dispatches[0].payload).unwrap();
        assert_eq!(reply.reason, NoOmegaRouteReason::UnmappedRealm);
    }

    #[test]
    fn route_table_cap_is_bounded_and_zero_opt_out_is_unbounded() {
        let mut capped_map = HashMap::new();
        capped_map.insert(RealmId::new("a"), NodeId("node-a".into()));
        capped_map.insert(RealmId::new("b"), NodeId("node-b".into()));
        let capped = OmegaFederator::new_with_realm_peer_limit(
            FederatorConfig {
                self_node: NodeId(SELF_NODE.into()),
                self_realm: RealmId::new(SELF_REALM),
                local_registry: REGISTRY,
                abode_key: key(0xB5),
                realm_to_peer: capped_map,
                weigher: Box::new(UnitWeigher),
            },
            1,
        );
        assert_eq!(capped.realm_peer_count(), 1);

        let mut unbounded_map = HashMap::new();
        unbounded_map.insert(RealmId::new("a"), NodeId("node-a".into()));
        unbounded_map.insert(RealmId::new("b"), NodeId("node-b".into()));
        let unbounded = OmegaFederator::new_with_realm_peer_limit(
            FederatorConfig {
                self_node: NodeId(SELF_NODE.into()),
                self_realm: RealmId::new(SELF_REALM),
                local_registry: REGISTRY,
                abode_key: key(0xB6),
                realm_to_peer: unbounded_map,
                weigher: Box::new(UnitWeigher),
            },
            0,
        );
        assert_eq!(unbounded.realm_peer_count(), 2);
    }

    #[test]
    fn non_module_omega_target_yields_unsupported_target() {
        let mut f = fed(0xB3);
        let env = Envelope {
            header: header(
                Address::Omega {
                    realm: RealmId::new("guests"),
                    target: Box::new(Address::Role(aether::Role::new("policy"))),
                },
                "seer",
                Some(1),
            ),
            payload: b"x".to_vec(),
        };
        let d = &f.handle(env).dispatches[0];
        let reply: NoOmegaRouteReply = serde_json::from_slice(&d.payload).unwrap();
        assert_eq!(reply.reason, NoOmegaRouteReason::UnsupportedTarget);
    }

    // ----- PullFrom → ListEntries + parked pending ----

    #[test]
    fn pull_from_emits_list_entries_to_peer_registry_and_parks_pending() {
        let mut f = fed(0xC1);
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            11,
        ));
        // Two dispatches: the ListEntries to the peer + the Accepted ack to the operator.
        assert_eq!(out.dispatches.len(), 2);
        let list = out
            .dispatches
            .iter()
            .find(|d| d.to == Address::Node(NodeId(PEER_NODE.into()), CreatureId(60)))
            .expect("ListEntries addressed to peer registry");
        assert_eq!(list.reply_to, Some(Address::Creature(ME)));
        match parse_op(list) {
            RegistryOp::ListEntries { realm } => assert_eq!(realm, Some(RealmId::new("guests"))),
            other => panic!("expected ListEntries, got {other:?}"),
        }
        assert!(f.has_pending_pull());
    }

    #[test]
    fn pull_from_before_bind_replies_rejected_and_parks_nothing() {
        let mut f = fed(0xC2);
        f.me = None;

        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            12,
        ));

        assert_eq!(out.dispatches.len(), 1);
        match FederatorMsg::parse(&out.dispatches[0].payload).unwrap() {
            FederatorMsg::Rejected { reason } => assert!(reason.contains("not bound"), "{reason}"),
            other => panic!("expected Rejected, got {other:?}"),
        }
        assert!(!f.has_pending_pull());
    }

    #[test]
    fn outbound_federation_controls_reject_malformed_peer_node_before_dispatch() {
        let mut f = fed(0xC9);
        let messages = vec![
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId("bad peer".into()),
                peer_registry: CreatureId(60),
            },
            FederatorMsg::FederateReputation {
                artifact_hash: artifact_hash(b"reputation-target"),
                realm: RealmId::new("crew"),
                score: 0.95,
                peer_node: NodeId("bad peer".into()),
                peer_federator: CreatureId(70),
            },
            FederatorMsg::FederateQuarantine {
                artifact_hash: artifact_hash(b"quarantine-target"),
                realm: RealmId::new("crew"),
                reason: "apoptosis".into(),
                peer_node: NodeId("bad peer".into()),
                peer_federator: CreatureId(70),
            },
        ];

        for (idx, msg) in messages.into_iter().enumerate() {
            let out = f.handle(control_env(msg, 20 + idx as u64));

            assert_eq!(out.dispatches.len(), 1, "only a Rejected reply is emitted");
            assert!(
                !out.dispatches.iter().any(|d| matches!(d.to, Address::Node(..))),
                "malformed peer_node is never promoted into an address header"
            );
            match FederatorMsg::parse(&out.dispatches[0].payload).unwrap() {
                FederatorMsg::Rejected { reason } => {
                    assert!(reason.contains("peer_node"), "{reason}");
                }
                other => panic!("expected Rejected, got {other:?}"),
            }
        }
        assert!(!f.has_pending_pull());
    }

    #[test]
    fn max_pending_pulls_refuses_new_pull_at_capacity_and_keeps_in_flight() {
        // Cap in-flight pulls at 1. The first PullFrom parks; a second is refused with a Rejected
        // ack (no ListEntries dispatched), and the first pull stays in flight. `0` is the explicit
        // unbounded opt-out.
        let mut f = fed(0xC2).with_max_pending_pulls(1);
        let pull = |realm: &str| {
            control_env(
                FederatorMsg::PullFrom {
                    source_realm: RealmId::new(realm),
                    peer_node: NodeId(PEER_NODE.into()),
                    peer_registry: CreatureId(60),
                },
                11,
            )
        };

        let out1 = f.handle(pull("guests"));
        assert_eq!(out1.dispatches.len(), 2, "first pull: ListEntries + Accepted ack");
        assert!(f.has_pending_pull(), "first pull parked");

        // At capacity: the second pull is refused — a single Rejected ack, no ListEntries.
        let out2 = f.handle(pull("visitors"));
        assert!(
            !out2
                .dispatches
                .iter()
                .any(|d| matches!(parse_op_opt(d), Some(RegistryOp::ListEntries { .. }))),
            "no ListEntries dispatched at capacity"
        );
        match FederatorMsg::parse(&out2.dispatches[0].payload) {
            Ok(FederatorMsg::Rejected { reason }) => {
                assert!(reason.contains("capacity"), "refusal explains the cap: {reason}");
            }
            other => panic!("expected Rejected at capacity, got {other:?}"),
        }
        // The first pull is still in flight — refuse-new never evicted it.
        assert!(f.has_pending_pull(), "first pull still in flight after refusal");
    }

    #[test]
    fn default_pending_pull_cap_refuses_new_pull_and_zero_opt_out_is_unbounded() {
        let pull = || {
            control_env(
                FederatorMsg::PullFrom {
                    source_realm: RealmId::new("guests"),
                    peer_node: NodeId(PEER_NODE.into()),
                    peer_registry: CreatureId(60),
                },
                11,
            )
        };

        let mut bounded = fed(0xC3);
        for i in 0..DEFAULT_MAX_PENDING_PULLS {
            let out = bounded.handle(pull());
            assert!(
                out.dispatches
                    .iter()
                    .any(|d| matches!(parse_op_opt(d), Some(RegistryOp::ListEntries { .. }))),
                "pull {i} dispatches ListEntries under the default cap"
            );
        }
        assert_eq!(bounded.pending_pull_count(), DEFAULT_MAX_PENDING_PULLS);

        let refused = bounded.handle(pull());
        assert!(
            !refused
                .dispatches
                .iter()
                .any(|d| matches!(parse_op_opt(d), Some(RegistryOp::ListEntries { .. }))),
            "default-cap refusal does not dispatch another pull"
        );
        match FederatorMsg::parse(&refused.dispatches[0].payload) {
            Ok(FederatorMsg::Rejected { reason }) => {
                assert!(reason.contains("capacity"), "refusal explains the cap: {reason}");
            }
            other => panic!("expected Rejected at default capacity, got {other:?}"),
        }
        assert_eq!(
            bounded.pending_pull_count(),
            DEFAULT_MAX_PENDING_PULLS,
            "refusal does not park another pending pull"
        );

        let mut unbounded = fed(0xC4).with_max_pending_pulls(0);
        for i in 0..=DEFAULT_MAX_PENDING_PULLS {
            let out = unbounded.handle(pull());
            assert!(
                out.dispatches
                    .iter()
                    .any(|d| matches!(parse_op_opt(d), Some(RegistryOp::ListEntries { .. }))),
                "unbounded opt-out dispatches pull {i}"
            );
        }
        assert_eq!(unbounded.pending_pull_count(), DEFAULT_MAX_PENDING_PULLS + 1);
    }

    fn parse_op_opt(d: &Dispatch) -> Option<RegistryOp> {
        serde_json::from_slice(&d.payload).ok()
    }

    #[test]
    fn registry_entries_reply_merges_into_local_registry_pinned_to_requested_realm() {
        let mut f = fed(0xC2).with_consult_corr_seed(800_000);
        // Park a pull by issuing PullFrom; capture the consult corr from the ListEntries dispatch.
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            1,
        ));
        let corr = out
            .dispatches
            .iter()
            .find(|d| matches!(d.to, Address::Node(..)))
            .unwrap()
            .corr
            .unwrap();

        // Peer returns one entry tagged (deceptively) with realm "crew" — the puller must pin it to
        // the requested realm "guests" (T2 guard).
        let artifact = b"y-bytes".to_vec();
        let sync = registry_mem::SyncEntry {
            artifact_hash: artifact_hash(&artifact),
            realm: RealmId::new("crew"),
            manifest: sigil::Manifest::new(
                "y",
                "0.1.0",
                sigil::Backend::Daemon,
                "gawd_creature_v1",
            ),
            artifact,
            reputation: Some(ReputationScore::unsigned(0.7, Some(RealmId::new("guests")))),
            quarantine: None,
        };
        let reply_env = Envelope {
            header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(corr)),
            payload: RegistryReply::Entries { entries: vec![sync] }.to_bytes(),
        };
        let out = f.handle(reply_env);
        assert!(!f.has_pending_pull(), "pull resolved");
        // Expect Publish(guests) then AttestFitness(guests) — both pinned to requested realm.
        let pubs: Vec<_> = out.dispatches.iter().map(parse_op).collect();
        assert!(
            matches!(&pubs[0], RegistryOp::Publish { realm: Some(realm), .. } if *realm == RealmId::new("guests"))
        );
        assert!(
            matches!(&pubs[1], RegistryOp::AttestFitness { realm, .. } if *realm == RealmId::new("guests"))
        );
    }

    #[test]
    fn registry_entries_reply_drops_entry_when_advertised_hash_mismatches_artifact() {
        let mut f = fed(0xC8).with_consult_corr_seed(805_000);
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            1,
        ));
        let corr = out
            .dispatches
            .iter()
            .find(|d| matches!(d.to, Address::Node(..)))
            .unwrap()
            .corr
            .unwrap();

        let artifact = b"actual-pulled-bytes".to_vec();
        let sync = registry_mem::SyncEntry {
            artifact_hash: artifact_hash(b"different-bytes"),
            realm: RealmId::new("guests"),
            manifest: sigil::Manifest::new(
                "mismatch",
                "0.1.0",
                sigil::Backend::Daemon,
                "gawd_creature_v1",
            ),
            artifact,
            reputation: Some(ReputationScore::unsigned(0.8, Some(RealmId::new("crew")))),
            quarantine: Some(registry_mem::QuarantineNotice {
                reason: "peer flagged".into(),
                attesting_peers: vec!["node-B".into()],
            }),
        };
        let reply_env = Envelope {
            header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(corr)),
            payload: RegistryReply::Entries { entries: vec![sync] }.to_bytes(),
        };

        let out = f.handle(reply_env);

        assert!(!f.has_pending_pull(), "terminal Entries reply still resolves the parked pull");
        assert!(
            out.dispatches.is_empty(),
            "a mismatched pulled entry must not publish bytes or replay attached signals"
        );
        assert_eq!(f.ingest_rejections().malformed, 1);
    }

    #[test]
    fn entries_reply_with_unmatched_corr_is_ignored() {
        let mut f = fed(0xC3);
        let reply_env = Envelope {
            header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(999)),
            payload: RegistryReply::Entries { entries: vec![] }.to_bytes(),
        };
        assert!(f.handle(reply_env).dispatches.is_empty());
    }

    #[test]
    fn registry_reply_parser_drops_payload_over_limit_before_json_decode() {
        let payload = RegistryReply::Entries { entries: vec![] }.to_bytes();
        let parsed = parse_registry_reply_with_limit(&payload, payload.len());
        assert!(matches!(parsed, Some(RegistryReply::Entries { entries }) if entries.is_empty()));

        let oversized = parse_registry_reply_with_limit(&payload, payload.len() - 1);
        assert!(oversized.is_none(), "payload over the configured limit is ignored");
    }

    /// The merge has *two* independent re-apply arms (reputation, quarantine). The pinned-realm
    /// test only exercises the reputation arm; this proves a single pulled `SyncEntry` carrying
    /// BOTH signals re-applies BOTH — the exact path fitness and quarantine federate through.
    /// Expect three ops in order:
    /// Publish → AttestFitness → MarkQuarantine, all pinned to the requested realm.
    #[test]
    fn registry_entries_reply_reapplies_both_reputation_and_quarantine() {
        let mut f = fed(0xC4).with_consult_corr_seed(810_000);
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            1,
        ));
        let corr = out
            .dispatches
            .iter()
            .find(|d| matches!(d.to, Address::Node(..)))
            .unwrap()
            .corr
            .unwrap();

        let artifact = b"z-bytes".to_vec();
        let sync = registry_mem::SyncEntry {
            artifact_hash: artifact_hash(&artifact),
            realm: RealmId::new("crew"), // deceptive tag — puller must pin to requested "guests"
            manifest: sigil::Manifest::new(
                "z",
                "0.1.0",
                sigil::Backend::Daemon,
                "gawd_creature_v1",
            ),
            artifact,
            reputation: Some(ReputationScore::unsigned(0.8, Some(RealmId::new("crew")))),
            quarantine: Some(registry_mem::QuarantineNotice {
                reason: "peer flagged".into(),
                attesting_peers: vec!["node-B".into()],
            }),
        };
        let reply_env = Envelope {
            header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(corr)),
            payload: RegistryReply::Entries { entries: vec![sync] }.to_bytes(),
        };
        let ops: Vec<_> = f.handle(reply_env).dispatches.iter().map(parse_op).collect();
        assert_eq!(ops.len(), 3, "publish + attest + quarantine for an entry with both signals");
        assert!(
            matches!(&ops[0], RegistryOp::Publish { realm: Some(realm), .. } if *realm == RealmId::new("guests"))
        );
        assert!(matches!(&ops[1], RegistryOp::AttestFitness { realm, score, .. }
            if *realm == RealmId::new("guests") && (*score - 0.8).abs() < 1e-6));
        assert!(matches!(&ops[2], RegistryOp::MarkQuarantine { realm, reason, .. }
            if *realm == RealmId::new("guests") && reason == "peer flagged"));
    }

    #[test]
    fn registry_entries_reply_drops_oversized_quarantine_signal_before_forwarding() {
        let mut f = fed(0xC6).with_consult_corr_seed(830_000);
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            1,
        ));
        let corr = out
            .dispatches
            .iter()
            .find(|d| matches!(d.to, Address::Node(..)))
            .unwrap()
            .corr
            .unwrap();

        let artifact = b"z-bytes".to_vec();
        let sync = registry_mem::SyncEntry {
            artifact_hash: artifact_hash(&artifact),
            realm: RealmId::new("guests"),
            manifest: sigil::Manifest::new(
                "z",
                "0.1.0",
                sigil::Backend::Daemon,
                "gawd_creature_v1",
            ),
            artifact,
            reputation: None,
            quarantine: Some(registry_mem::QuarantineNotice {
                reason: "x".repeat(MAX_QUARANTINE_REASON_BYTES + 1),
                attesting_peers: vec!["node-B".into()],
            }),
        };
        let reply_env = Envelope {
            header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(corr)),
            payload: RegistryReply::Entries { entries: vec![sync] }.to_bytes(),
        };
        let ops: Vec<_> = f.handle(reply_env).dispatches.iter().map(parse_op).collect();

        assert_eq!(ops.len(), 1, "only Publish is forwarded for a malformed marker");
        assert!(
            matches!(&ops[0], RegistryOp::Publish { realm: Some(realm), .. } if *realm == RealmId::new("guests"))
        );
        assert!(
            !ops.iter().any(|op| matches!(op, RegistryOp::MarkQuarantine { .. })),
            "oversized pulled quarantine signal was not forwarded to the registry"
        );
    }

    #[test]
    fn registry_entries_reply_drops_malformed_reputation_signal_before_forwarding() {
        let mut f = fed(0xC7).with_consult_corr_seed(840_000);
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            1,
        ));
        let corr = out
            .dispatches
            .iter()
            .find(|d| matches!(d.to, Address::Node(..)))
            .unwrap()
            .corr
            .unwrap();

        let artifact = b"r-bytes".to_vec();
        let sync = registry_mem::SyncEntry {
            artifact_hash: artifact_hash(&artifact),
            realm: RealmId::new("guests"),
            manifest: sigil::Manifest::new(
                "r",
                "0.1.0",
                sigil::Backend::Daemon,
                "gawd_creature_v1",
            ),
            artifact,
            reputation: Some(ReputationScore::unsigned(0.8, Some(RealmId::new("bad:realm")))),
            quarantine: None,
        };
        let reply_env = Envelope {
            header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(corr)),
            payload: RegistryReply::Entries { entries: vec![sync] }.to_bytes(),
        };
        let ops: Vec<_> = f.handle(reply_env).dispatches.iter().map(parse_op).collect();

        assert_eq!(ops.len(), 1, "only Publish is forwarded for a malformed marker");
        assert!(
            matches!(&ops[0], RegistryOp::Publish { realm: Some(realm), .. } if *realm == RealmId::new("guests"))
        );
        assert!(
            !ops.iter().any(|op| matches!(op, RegistryOp::AttestFitness { .. })),
            "malformed pulled reputation signal was not forwarded to the registry"
        );
        assert_eq!(f.ingest_rejections().malformed, 1);
    }

    #[test]
    fn pull_answered_with_a_registry_error_reclaims_its_parked_slot() {
        // A source registry whose `ListEntries` snapshot artifact-byte cap refuses an over-cap pull
        // answers with `RegistryReply::Error`, not `Entries`. That terminal reply cannot be merged,
        // but it must free the parked pull or anti-entropy wedges after the pull cap fills.
        let mut f = fed(0xC7).with_consult_corr_seed(840_000);
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            1,
        ));
        let corr = out
            .dispatches
            .iter()
            .find(|d| matches!(d.to, Address::Node(..)))
            .unwrap()
            .corr
            .unwrap();
        assert_eq!(f.pending_pull_count(), 1, "pull is parked awaiting its Entries reply");

        let error_reply = Envelope {
            header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(corr)),
            payload: RegistryReply::Error {
                message: "registry snapshot too large: 9000 artifact bytes exceeds 4 byte limit"
                    .into(),
            }
            .to_bytes(),
        };
        let out = f.handle(error_reply);
        assert!(out.dispatches.is_empty(), "an Error pull reply forwards nothing");
        assert_eq!(
            f.pending_pull_count(),
            0,
            "the parked pull slot is reclaimed on a non-Entries terminal reply"
        );
    }

    /// A pull resolves on the first matching
    /// Entries reply; a duplicate carrying the same (now-popped) corr is a replay and must be a
    /// silent no-op — `pending_pulls.remove` returns `None`, no second merge fires.
    #[test]
    fn duplicate_entries_reply_is_ignored_after_pull_resolves() {
        let mut f = fed(0xC5).with_consult_corr_seed(820_000);
        let out = f.handle(control_env(
            FederatorMsg::PullFrom {
                source_realm: RealmId::new("guests"),
                peer_node: NodeId(PEER_NODE.into()),
                peer_registry: CreatureId(60),
            },
            1,
        ));
        let corr = out
            .dispatches
            .iter()
            .find(|d| matches!(d.to, Address::Node(..)))
            .unwrap()
            .corr
            .unwrap();
        let make_reply = || {
            let artifact = b"y-bytes".to_vec();
            Envelope {
                header: header(Address::Creature(ME), REGISTRY_REPLY_SCHEMA, Some(corr)),
                payload: RegistryReply::Entries {
                    entries: vec![registry_mem::SyncEntry {
                        artifact_hash: artifact_hash(&artifact),
                        realm: RealmId::new("guests"),
                        manifest: sigil::Manifest::new(
                            "y",
                            "0.1.0",
                            sigil::Backend::Daemon,
                            "gawd_creature_v1",
                        ),
                        artifact,
                        reputation: None,
                        quarantine: None,
                    }],
                }
                .to_bytes(),
            }
        };
        assert_eq!(f.handle(make_reply()).dispatches.len(), 1, "first reply merges (one Publish)");
        assert!(!f.has_pending_pull(), "pull resolved");
        assert!(f.handle(make_reply()).dispatches.is_empty(), "duplicate reply is a silent no-op");
    }

    // ----- reputation ingest (SEER consensus, T3) ----

    fn signed_delta(seed: u8, score: f32) -> ReputationDelta {
        let k = key(seed);
        let mut d = ReputationDelta {
            artifact_hash: artifact_hash(b"reputation-target"),
            realm: RealmId::new("crew"),
            score,
            observer_realm: RealmId::new("crew"),
            observer_key: k.public_hex().to_string(),
            signature: None,
        };
        d.sign(&k);
        d
    }

    fn seer_consensus_env(delta: &ReputationDelta, corr: u64) -> Envelope {
        let seer = SeerEnvelope::answer(SeerTopic::Consensus, corr, 0, delta);
        Envelope {
            header: header(Address::Creature(ME), seer::SCHEMA, Some(corr)),
            payload: seer.to_bytes(),
        }
    }

    #[test]
    fn signed_reputation_delta_writes_attest_fitness_tagged_with_observer_realm() {
        let mut f = fed(0xD1);
        let expected_hash = artifact_hash(b"reputation-target");
        let out = f.handle(seer_consensus_env(&signed_delta(0xEE, 0.95), 1));
        assert_eq!(out.dispatches.len(), 1);
        match parse_op(&out.dispatches[0]) {
            RegistryOp::AttestFitness {
                artifact_hash,
                realm,
                score,
                attesting_realm,
                signed_by,
                signature,
            } => {
                assert_eq!(artifact_hash, expected_hash);
                assert_eq!(realm, RealmId::new("crew"));
                assert_eq!(score, 0.95); // UnitWeigher: score * 1.0
                assert_eq!(attesting_realm, Some(RealmId::new("crew")));
                // Peer reputation lands UNSIGNED — its provenance is attesting_realm, not a
                // promotion signature. Only a local fitness-selector promotion is signed.
                assert!(
                    signed_by.is_none() && signature.is_none(),
                    "peer reputation is stored unsigned"
                );
            }
            other => panic!("expected AttestFitness, got {other:?}"),
        }
    }

    #[test]
    fn oversized_consensus_seer_is_counted_as_malformed_without_registry_write() {
        let mut f = fed(0xD0);
        let env = Envelope {
            header: header(Address::Creature(ME), seer::SCHEMA, Some(1)),
            payload: vec![b'{'; seer::MAX_SEER_ENVELOPE_BYTES + 1],
        };
        let out = f.handle(env);
        assert!(out.dispatches.is_empty(), "oversized consensus SEER must not write registry");
        assert_eq!(f.ingest_rejections().malformed, 1);
    }

    #[test]
    fn oversized_reputation_delta_field_is_malformed_without_echo_event() {
        let mut f = fed(0xD0);
        let mut delta = signed_delta(0xEE, 0.95);
        delta.observer_key = "k".repeat(MAX_REGISTRY_SIGNAL_FIELD_BYTES + 1);

        let out = f.handle(seer_consensus_env(&delta, 1));

        assert!(
            out.dispatches.is_empty(),
            "oversized claimed key must not be echoed to registry or proprioception"
        );
        assert_eq!(f.ingest_rejections().malformed, 1);
        assert_eq!(
            f.ingest_rejections().bad_signature,
            0,
            "shape rejection happens before the signature gate"
        );
    }

    #[test]
    fn malformed_reputation_delta_identity_is_rejected_without_echo_event() {
        let mut f = fed(0xD1);
        let mut bad_realm = signed_delta(0xEE, 0.95);
        bad_realm.observer_realm = RealmId::new("bad:realm");
        let mut nul_key = signed_delta(0xEE, 0.95);
        nul_key.observer_key.push('\0');

        for delta in [bad_realm, nul_key] {
            let out = f.handle(seer_consensus_env(&delta, 1));

            assert!(
                out.dispatches.is_empty(),
                "malformed claimed identity must not be echoed to registry or proprioception"
            );
        }
        assert_eq!(f.ingest_rejections().malformed, 2);
        assert_eq!(
            f.ingest_rejections().bad_signature,
            0,
            "shape rejection happens before the signature gate"
        );
    }

    #[test]
    fn unsigned_reputation_delta_is_rejected_without_touching_registry() {
        // T3: a delta that isn't validly signed never updates the registry. The drop
        // is *observable* — a `federation.ingest_drop` proprioception event surfaces it (so the
        // defense loop sees a peer spraying junk) while still writing NOTHING to the registry.
        let mut f = fed(0xD2);
        let mut delta = signed_delta(0xEE, 0.95);
        delta.signature = None; // strip the signature
        let out = f.handle(seer_consensus_env(&delta, 1));
        // Invariant preserved: no registry-bound dispatch.
        assert!(
            !out.dispatches.iter().any(|d| matches!(d.to, Address::Creature(m) if m == REGISTRY)),
            "unsigned delta produces no registry write"
        );
        // New observability: exactly one proprioception ingest-drop event, reason "bad_signature".
        assert_eq!(out.dispatches.len(), 1, "the only emit is the ingest-drop event");
        let d = &out.dispatches[0];
        assert!(matches!(&d.to, Address::Topic(t) if t.0 == Topic::PROPRIOCEPTION));
        assert_eq!(d.schema, INGEST_DROP_SCHEMA);
        let ev: IngestDropEvent = serde_json::from_slice(&d.payload).unwrap();
        assert_eq!(ev.reason, "bad_signature");
        assert_eq!(f.ingest_rejections().bad_signature, 1);
    }

    #[test]
    fn reputation_delta_with_zero_weight_is_ignored() {
        struct ZeroWeigher;
        impl ReputationWeigher for ZeroWeigher {
            fn weight(&self, _k: &str, _r: &RealmId) -> f32 {
                0.0
            }
        }
        let mut map = HashMap::new();
        map.insert(RealmId::new("guests"), NodeId(PEER_NODE.into()));
        let mut f = OmegaFederator::new(FederatorConfig {
            self_node: NodeId(SELF_NODE.into()),
            self_realm: RealmId::new(SELF_REALM),
            local_registry: REGISTRY,
            abode_key: key(0xD3),
            realm_to_peer: map,
            weigher: Box::new(ZeroWeigher),
        });
        f.set_me_for_tests(ME);
        let out = f.handle(seer_consensus_env(&signed_delta(0xEE, 0.95), 1));
        assert!(out.dispatches.is_empty(), "weight 0.0 discards the attestation");
    }

    #[test]
    fn nan_weight_discards_attestation_without_corrupting_registry() {
        // R9: a buggy/hostile injected weigher returning NaN
        // must NOT slip past the credit gate — `NaN <= 0.0` is `false`, so a bare `<= 0.0` check
        // would let `score * NaN = NaN` reach the registry. The `is_finite()` half of the gate
        // catches it.
        struct NanWeigher;
        impl ReputationWeigher for NanWeigher {
            fn weight(&self, _k: &str, _r: &RealmId) -> f32 {
                f32::NAN
            }
        }
        let mut map = HashMap::new();
        map.insert(RealmId::new("guests"), NodeId(PEER_NODE.into()));
        let mut f = OmegaFederator::new(FederatorConfig {
            self_node: NodeId(SELF_NODE.into()),
            self_realm: RealmId::new(SELF_REALM),
            local_registry: REGISTRY,
            abode_key: key(0xDA),
            realm_to_peer: map,
            weigher: Box::new(NanWeigher),
        });
        f.set_me_for_tests(ME);
        let out = f.handle(seer_consensus_env(&signed_delta(0xEE, 0.95), 1));
        assert!(
            out.dispatches.is_empty(),
            "NaN weight must discard, never write NaN to the registry"
        );
    }

    #[test]
    fn non_finite_score_delta_is_rejected_before_it_reaches_the_registry() {
        // R9: `score` is attacker-controlled wire
        // data. A peer crafts a body whose number overflows f32 (`1e40` is finite as the JSON's
        // f64 but narrows to `f32::INFINITY`). The `is_finite()` guard drops it BEFORE the
        // signature check, so it never reaches the weigher or the registry — and we don't even
        // need a valid signature to prove the guard fires.
        let mut f = fed(0xDB);
        let body = serde_json::json!({
            "artifact_hash": artifact_hash(b"reputation-target"),
            "realm": "crew",
            "score": 1e40,                 // overflows f32 → +∞ after `from_value::<ReputationDelta>`
            "observer_realm": "crew",
            "observer_key": "whatever",
            "signature": "anything"
        });
        let seer = SeerEnvelope::answer(SeerTopic::Consensus, 1, 0, &body);
        let env = Envelope {
            header: header(Address::Creature(ME), seer::SCHEMA, Some(1)),
            payload: seer.to_bytes(),
        };
        // Sanity: the body really does decode to a non-finite score (guard precondition).
        let decoded: ReputationDelta = serde_json::from_value(body).unwrap();
        assert!(!decoded.score.is_finite(), "test fixture must produce a non-finite score");
        let out = f.handle(env);
        // Invariant preserved: nothing reaches the registry.
        assert!(
            !out.dispatches.iter().any(|d| matches!(d.to, Address::Creature(m) if m == REGISTRY)),
            "non-finite score must never touch the registry"
        );
        // The drop is surfaced as a `non_finite_score` ingest-drop event + counted.
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        assert!(matches!(&d.to, Address::Topic(t) if t.0 == Topic::PROPRIOCEPTION));
        assert_eq!(d.schema, INGEST_DROP_SCHEMA);
        assert_eq!(f.ingest_rejections().non_finite_score, 1);
    }

    // ----- FederateReputation emits a signed SEER consensus envelope ----

    #[test]
    fn federate_reputation_ships_signed_delta_on_seer_consensus_topic() {
        let mut f = fed(0xF1);
        let hash = artifact_hash(b"reputation-target");
        let out = f.handle(control_env(
            FederatorMsg::FederateReputation {
                artifact_hash: hash,
                realm: RealmId::new("crew"),
                score: 0.95,
                peer_node: NodeId(PEER_NODE.into()),
                peer_federator: CreatureId(70),
            },
            3,
        ));
        let seer_d = out
            .dispatches
            .iter()
            .find(|d| d.schema == seer::SCHEMA)
            .expect("a SEER envelope was emitted");
        assert_eq!(seer_d.to, Address::Node(NodeId(PEER_NODE.into()), CreatureId(70)));
        let seer = SeerEnvelope::parse(&seer_d.payload).unwrap();
        assert_eq!(seer.topic, SeerTopic::Consensus);
        let body = match seer.kind {
            SeerKind::Answer { body, .. } => body,
            other => panic!("expected Answer, got {other:?}"),
        };
        let delta: ReputationDelta = serde_json::from_value(body).unwrap();
        assert!(delta.verify(&Ed25519Verifier), "shipped delta is signed by our Abode key");
        assert_eq!(delta.observer_realm, RealmId::new(SELF_REALM));
    }

    // ----- quarantine path ----

    #[test]
    fn federate_quarantine_ships_notice_then_inbound_writes_mark_quarantine() {
        let mut f = fed(0xA9);
        let hash = artifact_hash(b"quarantine-target");
        // Outbound: FederateQuarantine → a QuarantineNotice to the peer federator.
        let out = f.handle(control_env(
            FederatorMsg::FederateQuarantine {
                artifact_hash: hash.clone(),
                realm: RealmId::new("crew"),
                reason: "apoptosis".into(),
                peer_node: NodeId(PEER_NODE.into()),
                peer_federator: CreatureId(70),
            },
            4,
        ));
        let notice_d = out
            .dispatches
            .iter()
            .find(|d| d.to == Address::Node(NodeId(PEER_NODE.into()), CreatureId(70)))
            .expect("notice to peer federator");
        assert!(matches!(
            FederatorMsg::parse(&notice_d.payload).unwrap(),
            FederatorMsg::QuarantineNotice { .. }
        ));

        // Inbound: a QuarantineNotice arriving writes MarkQuarantine to the local registry.
        let inbound = Envelope {
            header: header(Address::Creature(ME), SCHEMA, None),
            payload: FederatorMsg::QuarantineNotice {
                artifact_hash: hash.clone(),
                realm: RealmId::new("crew"),
                reason: "apoptosis on peer".into(),
                attesting_peers: vec!["node-B".into()],
            }
            .to_bytes(),
        };
        let out = f.handle(inbound);
        match parse_op(&out.dispatches[0]) {
            RegistryOp::MarkQuarantine { artifact_hash, realm, .. } => {
                assert_eq!(artifact_hash, hash);
                assert_eq!(realm, RealmId::new("crew"));
            }
            other => panic!("expected MarkQuarantine, got {other:?}"),
        }
    }

    #[test]
    fn federate_quarantine_rejects_oversized_reason_before_ship() {
        let mut f = fed(0xAA);
        let out = f.handle(control_env(
            FederatorMsg::FederateQuarantine {
                artifact_hash: artifact_hash(b"quarantine-target"),
                realm: RealmId::new("crew"),
                reason: "x".repeat(MAX_QUARANTINE_REASON_BYTES + 1),
                peer_node: NodeId(PEER_NODE.into()),
                peer_federator: CreatureId(70),
            },
            4,
        ));

        assert!(
            !out.dispatches
                .iter()
                .any(|d| d.to == Address::Node(NodeId(PEER_NODE.into()), CreatureId(70))),
            "oversized quarantine control is not shipped to the peer"
        );
        match FederatorMsg::parse(&out.dispatches[0].payload) {
            Ok(FederatorMsg::Rejected { reason }) => {
                assert!(reason.contains("reason too large"), "{reason}");
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    #[test]
    fn inbound_quarantine_with_oversized_peer_is_dropped_before_registry_write() {
        let mut f = fed(0xAB);
        let inbound = Envelope {
            header: header(Address::Creature(ME), SCHEMA, None),
            payload: FederatorMsg::QuarantineNotice {
                artifact_hash: artifact_hash(b"quarantine-target"),
                realm: RealmId::new("crew"),
                reason: "apoptosis on peer".into(),
                attesting_peers: vec!["p".repeat(MAX_QUARANTINE_ATTESTING_PEER_BYTES + 1)],
            }
            .to_bytes(),
        };

        assert!(
            f.handle(inbound).dispatches.is_empty(),
            "oversized inbound quarantine marker must not reach the registry"
        );
    }

    // ----- hostile / misbind ----

    #[test]
    fn malformed_control_payload_does_not_panic() {
        let mut f = fed(0x01);
        let env = Envelope {
            header: header(Address::Creature(ME), SCHEMA, None),
            payload: b"{not json".to_vec(),
        };
        assert!(f.handle(env).dispatches.is_empty());
    }

    #[test]
    fn oversized_federator_message_is_dropped_before_json_decode() {
        let mut f = fed(0x03);
        let env = Envelope {
            header: header(Address::Creature(ME), SCHEMA, None),
            payload: vec![b'{'; MAX_FEDERATOR_MESSAGE_BYTES + 1],
        };
        assert!(f.handle(env).dispatches.is_empty());
        match FederatorMsg::parse_bounded(&vec![b'{'; MAX_FEDERATOR_MESSAGE_BYTES + 1]) {
            Err(FederatorMsgParseError::TooLarge { len, limit }) => {
                assert_eq!(len, MAX_FEDERATOR_MESSAGE_BYTES + 1);
                assert_eq!(limit, MAX_FEDERATOR_MESSAGE_BYTES);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    #[test]
    fn unknown_schema_is_a_no_op() {
        let mut f = fed(0x02);
        let env = Envelope {
            header: header(Address::Creature(ME), "some.other.schema", None),
            payload: b"x".to_vec(),
        };
        assert!(f.handle(env).dispatches.is_empty());
    }
}
