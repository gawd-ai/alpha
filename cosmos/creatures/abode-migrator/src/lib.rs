//! `abode-migrator` — the single-active-fork Abode hand-off creature: the real consumer of
//! the [`abode`] snapshot shape (a top-level crate).
//!
//! It rides the `AbodeSnapshot` + `AbodeRestore` types on the contract, the substrate-shipped
//! integrity/signing primitives (in the [`abode`] crate), and the migrator's own thin wire
//! protocol over the bus — no envelope path retrofits.
//!
//! ## What it does
//!
//! Bound to `Role::ABODE_MIGRATOR` on every Sanctum. One creature per Sanctum holds at most one
//! Abode at a time and exposes three operations to the local operator + one to peer migrators:
//!
//! - `SetState { payload }` *(local op)* — seed or replace the authoritative local Abode state.
//!   Transitions `Empty → Authoritative`. Rejected while a migration is in flight.
//! - `SnapshotRequest` *(local op)* — wraps the current state with [`SCHEMA_V0_3_MAGIC`], signs
//!   with the Abode key, returns an [`AbodeSnapshot`] the operator can inspect or hand to another
//!   subsystem. Pure read, allowed in any state.
//! - `Migrate { destination_node, destination_migrator }` *(local op)* — orchestrates the
//!   single-active-fork hand-off. Steps: take a snapshot → sign → ship `RestoreRequest` (carrying
//!   an unguessable per-migration challenge) to the destination's migrator → await a
//!   `RestoreResponse` that echoes the challenge and names the destination node, so a misrouted or
//!   spoofed reply can't seal the source and lose the self. On `admitted: true`, transitions
//!   `Authoritative → Migrated { to: destination_node }` and replies `MigrateAck` to the operator.
//!   The source's Abode is now non-authoritative; further `SetState` / `Migrate` /
//!   `SnapshotRequest` reject. (T5 in spirit: hand-off is explicit; no two-active-fork window.)
//! - `RestoreRequest { snapshot, note }` *(peer op)* — admission's only public surface. Bounds the
//!   serialized migrator message before JSON decode, then runs the substrate-shipped gates
//!   ([`AbodeSnapshot::assert_payload_size`] →
//!   [`assert_integrity`](AbodeSnapshot::assert_integrity) →
//!   [`verify_signature`](AbodeSnapshot::verify_signature) if signatures are required) before
//!   consulting the injected [`RestorePolicy`]. On admit: transitions `Empty →
//!   Authoritative { payload: unwrap(snapshot.payload_bytes) }` and replies
//!   `RestoreResponse { admitted: true }`. While `Authoritative`, rejects; fork/merge is a separate
//!   reconciler path, not this hand-off path. While `Migrated`, rejects (the sealed migrator
//!   never reverts to authority).
//!
//! ## State machine
//!
//! ```text
//!     ┌─────────┐  SetState   ┌─────────────────┐  Migrate{ok}  ┌────────────┐
//!     │  Empty  │ ──────────► │ Authoritative   │ ────────────► │  Migrated  │
//!     │         │ ◄────────── │ { payload }     │               │  { to }    │
//!     └─────────┘  Restore{ok} └─────────────────┘               └────────────┘
//!         ▲          (peer)            │                                │
//!         │                            │ SetState (replaces)            │ (sealed: all
//!         └────────────────────────────┘                                │  ops reject
//!                                                                       │  except Status)
//! ```
//!
//! ## What this creature deliberately does NOT do
//!
//! - **No fork / merge.** This creature is single-active-fork hand-off only. Fork (two Sanctums
//!   simultaneously authoritative) and merge (reconcile divergent forks) live in
//!   `creatures/abode-reconciler`. RestoreRequest at an `Authoritative` migrator rejects
//!   structurally and tells the caller to use the reconciler path.
//! - **No checkpoint scheduler.** *When* the operator calls `SnapshotRequest` is injected policy
//!   on top of the migrator; the substrate ships no schedule.
//! - **No snapshot durability.** A snapshot returned from `SnapshotRequest` is yours to keep,
//!   ship, persist, or discard. The migrator's only storage is the in-memory authoritative
//!   payload.
//! - **No proprioception emission.** The creature is minimal — the operator drives
//!   visibility via `StatusQuery`. The fitness-selector and immune-response may
//!   want migrator events on the proprio topic; that arrives when an integration test
//!   needs it (YAGNI).
//! - **No failure feedback or timeout on a migration in flight.** Once `Migrate` ships the
//!   `RestoreRequest`, the migrator parks `pending` and waits for the matching `RestoreResponse`.
//!   The substrate routes dispatches best-effort — a dispatch that fails to route is dropped by
//!   the kernel (`let _ = bus.send(d)`), never surfaced back to the creature — and the migrator
//!   runs no timer. So if the `RestoreRequest` never routes (peer migrator unbound →
//!   `NoSuchModule`, transport inbox full → `Backpressure`, no transport bound → `NoProvider`) or
//!   the `RestoreResponse` is lost (peer dies mid-handle), the migration stays in flight
//!   *indefinitely* and every further `SetState` / `Migrate` rejects with "migration in flight".
//!   Detect the wedge via `StatusQuery` (`StatusReply.in_flight_migration == true`) and recover by
//!   unloading + reloading the migrator (a fresh `Empty` instance). A richer multi-Realm migrator may
//!   add a timeout / retry / consult `omega-federator` for a healthy peer; this migrator targets
//!   one explicit peer and leaves in-flight recovery to the operator.
//!
//! ## Fabric-not-model preserved
//!
//! The migrator is a *creature* the operator binds to `Role::ABODE_MIGRATOR` — never substrate.
//! Operators may write their own (`my-org-abode-migrator`) with richer snapshot encoding, retry
//! semantics, or fork mechanics, and bind it instead. The substrate ships only the snapshot
//! shape, the integrity primitives, and the role socket.

use std::sync::Arc;

use abode::{AbodeSnapshot, DEFAULT_MAX_PAYLOAD_BYTES};
use aether::{Address, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, NodeId, Outcome};
use serde::{Deserialize, Serialize};
use sigil::crypto::{fresh_seed, hex_encode};
use sigil::{Ed25519KeyMaterial, Ed25519Verifier, Verifier};

/// Wire schema for every migrator envelope (request + reply, local + cross-node). Single schema +
/// a `kind`-tagged enum keeps the wire surface uniform; consumers filter by `schema` and then
/// dispatch on the enum variant. Same convention as `seer::SCHEMA`.
pub const SCHEMA: &str = "abode.migrator";

/// Fixed allowance for non-payload JSON fields in one migrator message.
const MIGRATOR_MESSAGE_OVERHEAD_BYTES: usize = 256 * 1024;

/// Maximum bytes accepted for node ids carried in migrator control metadata. The transport member
/// gate uses the same shape: ASCII alnum plus `.`, `_`, `-`.
const MAX_MIGRATOR_NODE_ID_BYTES: usize = 256;
/// Human/operator note attached to a `RestoreRequest`. Currently unused by this reference migrator,
/// but still bounded before any reply path can echo adjacent metadata.
const MAX_MIGRATOR_NOTE_BYTES: usize = 4 * 1024;
/// Human-readable refusal text emitted by policy or peers. Kept large enough for diagnostics, small
/// enough that policy output cannot become an unbounded reflected payload.
const MAX_MIGRATOR_REASON_BYTES: usize = 4 * 1024;
/// A challenge minted by this migrator is 32 random bytes rendered as 64 hex chars. Allow a little
/// room for future encodings, but reject metadata strings that are really payloads.
const MAX_MIGRATOR_CHALLENGE_BYTES: usize = 128;
const ED25519_PUBLIC_KEY_HEX_BYTES: usize = 64;
const ED25519_SIGNATURE_HEX_BYTES: usize = 128;

/// The pre-parse ceiling for a serialized [`MigratorMsg`], derived from the instance's
/// `max_payload_bytes`. The largest accepted migrator messages carry one raw state payload
/// (`SetState`) or one snapshot (`RestoreRequest` / `SnapshotReply`). `Vec<u8>` serializes as a JSON
/// array, where one byte can occupy up to four wire bytes (`255,`), so the cap allows one max-sized
/// payload at worst-case JSON expansion plus fixed metadata overhead.
fn max_migrator_message_bytes(max_payload_bytes: usize) -> usize {
    max_payload_bytes.saturating_mul(4).saturating_add(MIGRATOR_MESSAGE_OVERHEAD_BYTES)
}

/// 4-byte magic prefix this hand-off migrator writes at the head of
/// [`AbodeSnapshot::payload_bytes`]. A migrator that receives an unknown prefix rejects with
/// [`SnapshotSchemaError::UnknownPrefix`] (the T1 mitigation). **Convention, not
/// contract** — the `abode` crate keeps `payload_bytes` opaque; this magic is the migrator's choice of
/// how to make its own bytes version-dispatchable.
pub const SCHEMA_V0_3_MAGIC: [u8; 4] = *b"v3.0";

/// Wrap raw Abode state bytes with the v3.0 schema prefix, producing the
/// [`AbodeSnapshot::payload_bytes`] form this hand-off migrator ships. The producer side of the T1
/// dispatch.
pub fn wrap_payload_v0_3(state: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SCHEMA_V0_3_MAGIC.len() + state.len());
    out.extend_from_slice(&SCHEMA_V0_3_MAGIC);
    out.extend_from_slice(state);
    out
}

/// Unwrap [`AbodeSnapshot::payload_bytes`] back into the raw Abode state, refusing anything that
/// doesn't carry the v3.0 magic. The consumer side of the T1 dispatch.
pub fn unwrap_payload_v0_3(bytes: &[u8]) -> Result<&[u8], SnapshotSchemaError> {
    if bytes.len() < SCHEMA_V0_3_MAGIC.len() {
        return Err(SnapshotSchemaError::TooShort { len: bytes.len() });
    }
    let (prefix, rest) = bytes.split_at(SCHEMA_V0_3_MAGIC.len());
    if prefix != SCHEMA_V0_3_MAGIC {
        let mut prefix_arr = [0u8; 4];
        prefix_arr.copy_from_slice(prefix);
        return Err(SnapshotSchemaError::UnknownPrefix(prefix_arr));
    }
    Ok(rest)
}

/// Failure modes for [`unwrap_payload_v0_3`]. Distinct from `SnapshotError` because these are
/// the *migrator's* choice of how to dispatch its own payload bytes — the substrate doesn't see
/// the prefix at all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SnapshotSchemaError {
    /// `payload_bytes.len() < SCHEMA_V0_3_MAGIC.len()` — not even a prefix.
    TooShort { len: usize },
    /// First 4 bytes didn't match the v3.0 magic. The receiver is this hand-off migrator and the
    /// snapshot was produced by something else — another migrator version, a bug, or an attacker who
    /// knows the wire shape.
    UnknownPrefix([u8; 4]),
}

impl std::fmt::Display for SnapshotSchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotSchemaError::TooShort { len } => write!(
                f,
                "snapshot payload too short: {len} bytes (need at least {} for v3.0 schema prefix)",
                SCHEMA_V0_3_MAGIC.len()
            ),
            SnapshotSchemaError::UnknownPrefix(prefix) => {
                let prefix_repr = std::str::from_utf8(prefix)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|_| format!("{prefix:02x?}"));
                write!(f, "snapshot payload has unknown schema prefix `{prefix_repr}` (this hand-off migrator only decodes v3.0)")
            }
        }
    }
}

impl std::error::Error for SnapshotSchemaError {}

/// Operator-injected restore policy. The migrator consults this **after** the substrate-shipped
/// gates ([`AbodeSnapshot::assert_payload_size`] / `assert_integrity` / `verify_signature`) pass.
/// The substrate ships no implementation — see
/// `cosmos/creatures/prototypes/policies/policy-abode-allowlist`
/// for a minimal reference. Operators write their own with realm-membership checks,
/// jurisdiction filters, body-capability gates, anything.
///
/// ## Why this is a Rust trait, not a SEER consult
///
/// Two IoC shapes are possible: a `Box<dyn RestorePolicy>` trait object (the same shape the
/// admission `Policy` pattern uses) or a SEER `policy`-topic consult creature. The trait wins:
/// (a) the admission gate is already shaped this way (consistency across the substrate);
/// (b) restore decisions are synchronous on the migrator's `handle` call — a SEER consult
/// requires a pending table, async parking, and a way to time out, none of which this minimal
/// migrator wants; (c) an operator who wants SEER consultation can write a `RestorePolicy`
/// impl that wraps a SEER `Query` + waits for the answer (it just won't be this reference).
pub trait RestorePolicy: Send + Sync {
    /// Decide whether to admit this restore. Returns `Ok(())` for admit, `Err(reason)` for reject
    /// with a structured reason audited by the migrator + included in the peer's
    /// `RestoreResponse` for orchestrator-side dispatch.
    fn admit(&self, snapshot: &AbodeSnapshot) -> Result<(), String>;
}

/// A trivial `RestorePolicy` for unit tests. Admits
/// every snapshot. NEVER appropriate for production — see `cosmos/creatures/prototypes/policies/policy-abode-allowlist`
/// for the bare-minimum real policy shape.
pub struct PermissiveRestorePolicy;

impl RestorePolicy for PermissiveRestorePolicy {
    fn admit(&self, _snapshot: &AbodeSnapshot) -> Result<(), String> {
        Ok(())
    }
}

/// The migrator's current state. Single-active-fork: a migrator is `Empty` (just
/// booted, no Abode), `Authoritative` (owns the Abode), or `Migrated` (handed off, sealed).
///
/// **Why `Migrated` is sealed**: the promise is *explicit hand-off* — the moment
/// the destination acknowledges, the source's Abode is non-authoritative. Letting the source
/// revert to `Authoritative` (e.g. via `SetState`) would create the very fork-window the
/// reconciler's CRDT semantics are designed to handle properly. The invariant stays tight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbodeState {
    /// Just-booted migrator, no Abode seeded. Accepts `SetState` (operator seed) or
    /// `RestoreRequest` (incoming migration from a peer). Both transition to `Authoritative`.
    Empty,
    /// Authoritative for the Abode whose payload is held. Accepts `SetState` (replace),
    /// `SnapshotRequest` (export), `Migrate` (hand off). Rejects `RestoreRequest` (fork — the
    /// reconciler's job) with a structured reason.
    Authoritative { payload: Vec<u8> },
    /// Handed off to peer `to`. Sealed — every op except `StatusQuery` rejects. To begin again,
    /// the operator unloads and reloads the migrator (a fresh `Empty` instance).
    Migrated { to: NodeId },
}

impl AbodeState {
    /// Short human-readable name for audit + structured reply.
    pub fn variant_name(&self) -> &'static str {
        match self {
            AbodeState::Empty => "empty",
            AbodeState::Authoritative { .. } => "authoritative",
            AbodeState::Migrated { .. } => "migrated",
        }
    }
}

/// In-flight migration: a `Migrate` op shipped a `RestoreRequest` to a peer migrator, and we're
/// awaiting the matching `RestoreResponse` on `consult_corr`. Stash enough to (a) reply to the
/// original operator at the original corr / reply_to, (b) tell them which destination acked.
#[derive(Debug, Clone)]
struct PendingMigration {
    consult_corr: u64,
    destination_node: NodeId,
    /// Unguessable per-migration nonce minted in `on_migrate` and carried in the `RestoreRequest`.
    /// Only a migrator that actually received the request learns it; the matching `RestoreResponse`
    /// must echo it back, so a misrouted/spoofed reply on the same `corr` can't seal the source
    /// (responder authentication).
    challenge: String,
    operator_reply_to: Address,
    operator_corr: Option<u64>,
    /// The pre-shared trust anchor: the pubkey the operator expects the destination to sign its
    /// witness under, pinned on the `Migrate` op. `None` falls back to the legacy challenge/node guard
    /// (weaker, but never weaker than v0.4.0). The load-bearing addition that turns a self-consistent
    /// responder signature into a *trusted* one (M9-2).
    expected_responder_pubkey: Option<String>,
    /// The source snapshot's `state_hash`, parked at migrate time so the requester reconstructs the
    /// responder witness from its own knowledge — not from the now-mutable `Authoritative` state.
    snapshot_state_hash: String,
}

/// Every wire message the migrator speaks. Single tagged enum on schema [`SCHEMA`].
///
/// **Forward compatibility**: adding a new variant at the END is fine (serde rejects unknown
/// kinds rather than misclassifying — adversarial in the right direction). Reordering or
/// renaming an existing variant breaks the wire — same discipline as the snapshot signing
/// payload above. Treat as a wire format change if you do it.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MigratorMsg {
    // ----- operator → migrator (local control plane) -----
    /// Seed or replace the authoritative state with raw bytes. Operator's view, no schema
    /// prefix — the migrator adds the prefix internally when building snapshots. Rejected
    /// while migrated or while a migration is in flight.
    SetState {
        payload: Vec<u8>,
    },
    /// Take a snapshot of the current authoritative state. The reply carries the snapshot with
    /// the schema prefix already wrapped + the migrator's signature already attached.
    SnapshotRequest,
    /// Orchestrate a single-active-fork migration to the destination peer's migrator. Replies
    /// `MigrateAck { migrated_to }` on success or `MigrateFailed { reason }` otherwise.
    Migrate {
        destination_node: NodeId,
        destination_migrator: CreatureId,
        /// The pre-shared trust anchor (M9-2): the Abode pubkey (hex) the operator expects the
        /// destination migrator to sign its responder witness under. `#[serde(default)]` so an
        /// operator who omits it falls back to the legacy challenge/node-only guard (additive,
        /// non-breaking). With it pinned, a forged responder keypair is refused even though its
        /// signature verifies under itself.
        #[serde(default)]
        expected_responder_pubkey: Option<String>,
    },
    /// Read-only query of the migrator's current state. Always allowed. Reply: `StatusReply`.
    StatusQuery,

    // ----- peer migrator → this migrator (cross-node admission) -----
    /// The admission op a peer migrator ships when it wants to migrate its Abode here. The
    /// substrate-shipped gates run first; then the injected `RestorePolicy`. Reply:
    /// `RestoreResponse`.
    RestoreRequest {
        snapshot: AbodeSnapshot,
        note: Option<String>,
        /// Per-migration challenge nonce (hex) the source minted. The responder MUST echo it in the
        /// `RestoreResponse` so the source can tell a genuine reply from a misrouted/spoofed one on
        /// the same `corr`. Only a migrator that actually received this request knows it.
        #[serde(default)]
        challenge: String,
    },

    // ----- replies (migrator → operator OR migrator → peer migrator) -----
    StateSet,
    SnapshotReply {
        snapshot: AbodeSnapshot,
    },
    MigrateAck {
        migrated_to: NodeId,
    },
    MigrateFailed {
        reason: String,
    },
    StatusReply {
        state: String,
        migrated_to: Option<NodeId>,
        payload_len: usize,
        signed_snapshots_required: bool,
        max_payload_bytes: usize,
        in_flight_migration: bool,
    },
    /// Reply to a peer's `RestoreRequest`. `admitted: true` means *this* migrator now owns the
    /// Abode; the peer can transition `Authoritative → Migrated { to: this_node }`.
    RestoreResponse {
        admitted: bool,
        reason: Option<String>,
        /// Echo of the `RestoreRequest.challenge`. The source accepts the response only if this
        /// matches the parked migration's challenge — right `corr` alone is not enough.
        #[serde(default)]
        challenge: String,
        /// The responding migrator's own node id, asserted *in-band*. The source checks it equals
        /// the `destination_node` it shipped to. In-band (not the envelope `from`, which transport
        /// reseals to the local transport creature's id) so a legitimate cross-node reply is not
        /// falsely rejected.
        #[serde(default)]
        responder_node: NodeId,
        /// **Responder witness** (M9-2) — a hex ed25519 signature, by the responder's Abode key, over
        /// `(source abode_key ‖ state_hash ‖ challenge ‖ responder_node ‖ responder_pubkey)`. Present
        /// only on an `admitted: true` reply (a refusal ran no admission, so carries no witness).
        /// `#[serde(default)]` so an old/unsigned responder deserializes to `None`.
        #[serde(default)]
        responder_signature: Option<String>,
        /// The Abode pubkey (hex) the witness verifies under — the responder's own identity, *not* the
        /// source key. The requester verifies the signature under this AND binds it to the pre-shared
        /// anchor (`expected_responder_pubkey`). `#[serde(default)]` → `None` for an old responder.
        #[serde(default)]
        responder_pubkey: Option<String>,
    },
}

impl MigratorMsg {
    /// Serialize to wire bytes. Returns empty `Vec` on the (cannot-happen) serde failure path —
    /// the receiving migrator drops a zero-length envelope silently as malformed (which is the
    /// honest outcome). Pair with `debug_assert!` in debug builds via a future polish pass if
    /// we ever see this in the wild.
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }

    /// Parse from wire bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// The abode-migrator creature.
pub struct AbodeMigrator {
    /// This migrator's own routing handle — stashed at `bind`; used as `reply_to` on outbound
    /// `RestoreRequest`s so the peer's `RestoreResponse` comes back here regardless of how many
    /// transport hops it crossed.
    me: Option<CreatureId>,
    /// This Sanctum's own [`NodeId`]. Used to collapse `destination_node == self_node` to a
    /// local [`Address::Creature`] address — otherwise `transport-tcp` would receive a
    /// `Node(self, _)` envelope addressed at itself and have no peer to ship it to. Same
    /// discipline as [`distributor-requirements::Distributor`]'s `self_node` field.
    self_node: NodeId,
    /// The Abode's authorship private key. Held privately; signs every outbound snapshot.
    abode_key: Ed25519KeyMaterial,
    /// Snapshot of the Abode's authorship public key — pinned at construction so we can declare
    /// `AbodeSnapshot.abode_key` without re-deriving from the private key every snapshot.
    abode_key_public_hex: String,
    /// Current state. See [`AbodeState`].
    state: AbodeState,
    /// Injected restore policy. Substrate ships none.
    restore_policy: Box<dyn RestorePolicy>,
    /// Substrate-shipped admission ceiling for inbound `payload_bytes`. Defaults to
    /// [`DEFAULT_MAX_PAYLOAD_BYTES`]; operator raises (or lowers) at construction.
    max_payload_bytes: usize,
    /// Whether to require a signature on every inbound `RestoreRequest.snapshot`. Default
    /// `true`; operator flips for a sealed test harness or a single-tenant lab.
    require_signed_snapshots: bool,
    /// Whether to require a cryptographic **responder witness** on every admitting `RestoreResponse`
    /// before sealing the source (M9-2). Default `true`: an old/unsigned responder cannot seal a
    /// migration that demands proof. Operator flips for a sealed lab via
    /// [`with_unsigned_responder_allowed`](AbodeMigrator::with_unsigned_responder_allowed).
    require_signed_responders: bool,
    /// Verifier used by the substrate's `verify_signature` gate. Default `Ed25519Verifier`;
    /// operator swaps for tests that want a deterministic stub.
    verifier: Arc<dyn Verifier>,
    /// In-flight migration awaiting `RestoreResponse` on `consult_corr`. `None` when idle.
    pending: Option<PendingMigration>,
    /// Source of consult corrs for outbound `RestoreRequest`s. Starts at a high seed by default
    /// so it doesn't collide with operator-chosen corrs (which usually start small). Same
    /// discipline as `distributor-requirements::Distributor::next_consult_corr`.
    next_consult_corr: u64,
}

impl AbodeMigrator {
    /// Build with sensible defaults: permissive [`Ed25519Verifier`] + substrate-default size
    /// ceiling + signatures required + consult corr seed 1_000_000. Use the builder methods to
    /// override.
    pub fn new(
        self_node: NodeId,
        abode_key: Ed25519KeyMaterial,
        restore_policy: Box<dyn RestorePolicy>,
    ) -> Self {
        let abode_key_public_hex = abode_key.public_hex().to_string();
        AbodeMigrator {
            me: None,
            self_node,
            abode_key,
            abode_key_public_hex,
            state: AbodeState::Empty,
            restore_policy,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            require_signed_snapshots: true,
            require_signed_responders: true,
            verifier: Arc::new(Ed25519Verifier),
            pending: None,
            next_consult_corr: 1_000_000,
        }
    }

    /// Override the substrate-default size ceiling. Operators with large Abodes raise this
    /// at boot; operators on small bodies lower it.
    pub fn with_max_payload_bytes(mut self, max: usize) -> Self {
        self.max_payload_bytes = max;
        self
    }

    /// Allow unsigned snapshots (a sealed test harness or single-tenant lab). Production binds
    /// `require_signed_snapshots = true` (the default) and never calls this.
    pub fn with_unsigned_snapshots_allowed(mut self) -> Self {
        self.require_signed_snapshots = false;
        self
    }

    /// Allow an unsigned/legacy responder to seal a migration — skips the M9-2 responder-witness
    /// check and falls back to the challenge/node guard alone. A sealed-lab posture; production binds
    /// `require_signed_responders = true` (the default) and never calls this. Mirrors
    /// [`with_unsigned_snapshots_allowed`](AbodeMigrator::with_unsigned_snapshots_allowed).
    pub fn with_unsigned_responder_allowed(mut self) -> Self {
        self.require_signed_responders = false;
        self
    }

    /// Swap the verifier (rare — tests that drive `handle` directly may want a stub).
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Pin the consult-corr seed for tests that need deterministic outbound corrs.
    pub fn with_consult_corr_seed(mut self, seed: u64) -> Self {
        self.next_consult_corr = seed;
        self
    }

    /// Read-only accessor for tests + status queries.
    pub fn state(&self) -> &AbodeState {
        &self.state
    }

    /// Whether a migration is currently in flight.
    pub fn has_pending_migration(&self) -> bool {
        self.pending.is_some()
    }
}

impl Creature for AbodeMigrator {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA {
            // Not ours. Other schemas may reach this creature via misbind or a stray topic;
            // silently ignore (consistent with distributor / realm-gateway).
            return Outcome::none();
        }
        let max_message_bytes = max_migrator_message_bytes(self.max_payload_bytes);
        if env.payload.len() > max_message_bytes {
            return reply(
                &env,
                MigratorMsg::MigrateFailed {
                    reason: format!(
                        "migrator message {} bytes exceeds max {} bytes",
                        env.payload.len(),
                        max_message_bytes
                    ),
                },
            );
        }
        let Ok(msg) = MigratorMsg::parse(&env.payload) else {
            // Malformed payload from somewhere; drop silently. The fabric-integrity floor (R9)
            // says we never panic on hostile input.
            return Outcome::none();
        };
        match msg {
            MigratorMsg::SetState { payload } => self.on_set_state(&env, payload),
            MigratorMsg::SnapshotRequest => self.on_snapshot_request(&env),
            MigratorMsg::Migrate {
                destination_node,
                destination_migrator,
                expected_responder_pubkey,
            } => self.on_migrate(
                &env,
                destination_node,
                destination_migrator,
                expected_responder_pubkey,
            ),
            MigratorMsg::StatusQuery => self.on_status_query(&env),
            MigratorMsg::RestoreRequest { snapshot, note, challenge } => {
                self.on_restore_request(&env, snapshot, note, challenge)
            }
            MigratorMsg::RestoreResponse {
                admitted,
                reason,
                challenge,
                responder_node,
                responder_signature,
                responder_pubkey,
            } => self.on_restore_response(
                &env,
                admitted,
                reason,
                challenge,
                responder_node,
                responder_signature,
                responder_pubkey,
            ),
            // Replies arriving as inbound (echo, replay, or a misdirected envelope) — drop.
            // The migrator is the *issuer* of these variants, never the consumer.
            MigratorMsg::StateSet
            | MigratorMsg::SnapshotReply { .. }
            | MigratorMsg::MigrateAck { .. }
            | MigratorMsg::MigrateFailed { .. }
            | MigratorMsg::StatusReply { .. } => Outcome::none(),
        }
    }
}

impl AbodeMigrator {
    // ----- operator-facing handlers ------------------------------------------------------------

    fn on_set_state(&mut self, env: &Envelope, payload: Vec<u8>) -> Outcome {
        let wrapped_len = SCHEMA_V0_3_MAGIC.len().saturating_add(payload.len());
        if wrapped_len > self.max_payload_bytes {
            return reply(
                env,
                MigratorMsg::MigrateFailed {
                    reason: format!(
                        "set_state rejected: wrapped payload {wrapped_len} bytes exceeds max snapshot payload {} bytes",
                        self.max_payload_bytes
                    ),
                },
            );
        }
        if self.pending.is_some() {
            return reply(
                env,
                MigratorMsg::MigrateFailed {
                    reason: "set_state rejected: migration in flight".into(),
                },
            );
        }
        match &self.state {
            AbodeState::Empty | AbodeState::Authoritative { .. } => {
                self.state = AbodeState::Authoritative { payload };
                reply(env, MigratorMsg::StateSet)
            }
            AbodeState::Migrated { to } => reply(env, MigratorMsg::MigrateFailed {
                reason: format!(
                    "set_state rejected: migrator is sealed (migrated to `{}`); unload + reload to begin again",
                    to.0
                ),
            }),
        }
    }

    fn on_snapshot_request(&mut self, env: &Envelope) -> Outcome {
        // Always allowed (pure read), but in `Migrated` the payload is empty by design.
        let payload = match &self.state {
            AbodeState::Empty => Vec::new(),
            AbodeState::Authoritative { payload } => payload.clone(),
            AbodeState::Migrated { .. } => Vec::new(),
        };
        let snapshot = self.build_signed_snapshot(payload);
        reply(env, MigratorMsg::SnapshotReply { snapshot })
    }

    fn on_migrate(
        &mut self,
        env: &Envelope,
        destination_node: NodeId,
        destination_migrator: CreatureId,
        expected_responder_pubkey: Option<String>,
    ) -> Outcome {
        if !node_id_shape_is_valid(&destination_node) {
            return reply(
                env,
                MigratorMsg::MigrateFailed {
                    reason: format!(
                        "migrate rejected: destination_node must be 1..={MAX_MIGRATOR_NODE_ID_BYTES} ASCII [A-Za-z0-9._-] bytes"
                    ),
                },
            );
        }
        if !optional_hex_shape_is_valid(
            expected_responder_pubkey.as_deref(),
            ED25519_PUBLIC_KEY_HEX_BYTES,
        ) {
            return reply(
                env,
                MigratorMsg::MigrateFailed {
                    reason:
                        "migrate rejected: expected_responder_pubkey must be a 64-character hex ed25519 public key"
                            .into(),
                },
            );
        }
        if self.pending.is_some() {
            return reply(
                env,
                MigratorMsg::MigrateFailed {
                    reason: "migrate rejected: another migration is in flight".into(),
                },
            );
        }
        let payload = match &self.state {
            AbodeState::Empty => {
                return reply(
                    env,
                    MigratorMsg::MigrateFailed {
                        reason: "migrate rejected: no authoritative state to migrate".into(),
                    },
                );
            }
            AbodeState::Migrated { to } => {
                return reply(
                    env,
                    MigratorMsg::MigrateFailed {
                        reason: format!(
                            "migrate rejected: migrator is sealed (already migrated to `{}`)",
                            to.0
                        ),
                    },
                );
            }
            AbodeState::Authoritative { payload } => payload.clone(),
        };

        let Some(me_id) = self.me else {
            return reply(
                env,
                MigratorMsg::MigrateFailed {
                    reason: "migrate rejected: migrator not bound yet".into(),
                },
            );
        };
        let snapshot = self.build_signed_snapshot(payload);
        let consult_corr = self.next_consult_corr;
        self.next_consult_corr = self.next_consult_corr.wrapping_add(1);

        // Park the pending — we'll resolve when RestoreResponse arrives on consult_corr. Save
        // the operator's reply_to / corr so we can answer them when the peer acks.
        let operator_reply_to = env.reply_target();
        let operator_corr = env.header.corr;
        // Mint an unguessable per-migration challenge. Only the migrator that actually
        // receives this RestoreRequest learns it; the matching RestoreResponse must echo it, so a
        // misrouted or spoofed reply on the same corr can't seal the source and lose the self.
        let challenge_seed = match fresh_seed() {
            Ok(seed) => seed,
            Err(e) => {
                return reply(
                    env,
                    MigratorMsg::MigrateFailed {
                        reason: format!("migrate rejected: could not mint challenge: {e}"),
                    },
                )
            }
        };
        let challenge = hex_encode(&challenge_seed);
        self.pending = Some(PendingMigration {
            consult_corr,
            destination_node: destination_node.clone(),
            challenge: challenge.clone(),
            operator_reply_to,
            operator_corr,
            expected_responder_pubkey,
            // Park our own snapshot's state_hash so we can reconstruct the responder witness without
            // re-deriving it from the (soon-to-be-sealed) Authoritative state.
            snapshot_state_hash: snapshot.state_hash.clone(),
        });

        // Build the RestoreRequest. reply_to points at this migrator so the peer's
        // RestoreResponse comes back here regardless of how many hops it crosses. If the
        // destination is this same Sanctum (a same-Sanctum migrator-to-migrator hand-off, which
        // the `abode_migrate_local` integration test exercises) we collapse to a local
        // [`Address::Creature`] — sending `Node(self, _)` would route to `transport-tcp` which has
        // no peer named "self" and would drop the envelope. Same self-collapse the distributor
        // does on local offers.
        let dest_addr = if destination_node == self.self_node {
            Address::Creature(destination_migrator)
        } else {
            Address::Node(destination_node, destination_migrator)
        };
        let request = MigratorMsg::RestoreRequest { snapshot, note: None, challenge };
        let mut d = Dispatch::to(dest_addr, request.to_bytes())
            .with_schema(SCHEMA)
            .with_corr(consult_corr)
            .with_reply_to(Address::Creature(me_id));
        // Carry any commitment forward (no current caller sets it; future-proofing parity with
        // the realm-gateway).
        if let Some(commit) = &env.header.commitment {
            d = d.with_commitment(commit.clone());
        }
        Outcome::send(d)
    }

    fn on_status_query(&mut self, env: &Envelope) -> Outcome {
        let payload_len = match &self.state {
            AbodeState::Authoritative { payload } => payload.len(),
            _ => 0,
        };
        let migrated_to = match &self.state {
            AbodeState::Migrated { to } => Some(to.clone()),
            _ => None,
        };
        reply(
            env,
            MigratorMsg::StatusReply {
                state: self.state.variant_name().to_string(),
                migrated_to,
                payload_len,
                signed_snapshots_required: self.require_signed_snapshots,
                max_payload_bytes: self.max_payload_bytes,
                in_flight_migration: self.pending.is_some(),
            },
        )
    }

    // ----- peer-facing handlers ----------------------------------------------------------------

    fn on_restore_request(
        &mut self,
        env: &Envelope,
        snapshot: AbodeSnapshot,
        note: Option<String>,
        challenge: String,
    ) -> Outcome {
        if !optional_len_is_valid(note.as_deref(), MAX_MIGRATOR_NOTE_BYTES)
            || !challenge_shape_is_valid(&challenge)
        {
            return reply(
                env,
                MigratorMsg::RestoreResponse {
                    admitted: false,
                    reason: Some("restore rejected: malformed migrator metadata".into()),
                    // Do not reflect an oversized or malformed challenge.
                    challenge: String::new(),
                    responder_node: self.self_node.clone(),
                    responder_signature: None,
                    responder_pubkey: None,
                },
            );
        }
        // Every reply echoes the request's `challenge` and stamps this migrator's own node id in
        // band, so the source can authenticate the response — see `on_restore_response`.
        let self_node = self.self_node.clone();
        let respond = |admitted: bool, reason: Option<String>| {
            reply(
                env,
                MigratorMsg::RestoreResponse {
                    admitted,
                    reason: reason.map(bounded_reason),
                    challenge: challenge.clone(),
                    responder_node: self_node.clone(),
                    // A refusal ran no admission, so it carries no witness (M9-2). Only the
                    // `admitted: true` exit below attaches one.
                    responder_signature: None,
                    responder_pubkey: None,
                },
            )
        };

        // Fork-window check first: this hand-off migrator refuses RestoreRequests while already
        // authoritative. Fork/merge is handled by the reconciler path, not by
        // silently creating a second active fork here. `Migrated` likewise refuses — sealed.
        match &self.state {
            AbodeState::Authoritative { .. } => {
                return respond(
                    false,
                    Some(
                        "restore rejected: this hand-off migrator is already authoritative; use abode-reconciler for fork/merge semantics"
                            .into(),
                    ),
                );
            }
            AbodeState::Migrated { to } => {
                return respond(
                    false,
                    Some(format!(
                        "restore rejected: this migrator is sealed (migrated to `{}`)",
                        to.0
                    )),
                );
            }
            AbodeState::Empty => {}
        }

        // Substrate-shipped gate #1: size. BEFORE any deserialization-into-state.
        if let Err(e) = snapshot.assert_payload_size(self.max_payload_bytes) {
            return respond(false, Some(format!("substrate-gate:size: {e}")));
        }
        // Substrate-shipped gate #2: integrity (state_hash recompute). A bit-flipped snapshot
        // dies here, before any policy.
        if let Err(e) = snapshot.assert_integrity() {
            return respond(false, Some(format!("substrate-gate:integrity: {e}")));
        }
        // Substrate-shipped gate #3: signature (if required).
        if self.require_signed_snapshots {
            if let Err(e) = snapshot.verify_signature(self.verifier.as_ref()) {
                return respond(false, Some(format!("substrate-gate:signature: {e}")));
            }
        }

        // Schema dispatch (migrator's own — T1 mitigation). This hand-off migrator only decodes
        // v3.0 payloads and rejects unknown prefixes structurally.
        let inner = match unwrap_payload_v0_3(&snapshot.payload_bytes) {
            Ok(b) => b.to_vec(),
            Err(e) => {
                return respond(false, Some(format!("migrator-gate:schema: {e}")));
            }
        };

        // Injected policy. Only AFTER substrate + schema gates pass; substrate ships none.
        if let Err(reason) = self.restore_policy.admit(&snapshot) {
            return respond(false, Some(format!("restore-policy: {}", bounded_reason(reason))));
        }

        // All gates passed. Activate, then sign a responder witness (M9-2) so the source can prove
        // this body actually ran the gates and is the anchored destination. The witness binds the
        // proof to THIS snapshot (`abode_key` + `state_hash`), THIS migration (`challenge`), and THIS
        // responder identity (`responder_node` + our own `responder_pubkey`) — so it can't be replayed
        // onto another snapshot/migration or claimed by another node. We sign over the *source's*
        // `snapshot.abode_key` (the body, known to both) but our *own* pubkey is the identity.
        self.state = AbodeState::Authoritative { payload: inner };
        let responder_pubkey = self.abode_key_public_hex.clone();
        let witness = responder_witness_payload(
            &snapshot.abode_key,
            &snapshot.state_hash,
            &challenge,
            &self_node.0,
            &responder_pubkey,
        );
        let responder_signature = self.abode_key.sign(&witness);
        reply(
            env,
            MigratorMsg::RestoreResponse {
                admitted: true,
                reason: None,
                challenge,
                responder_node: self_node,
                responder_signature: Some(responder_signature),
                responder_pubkey: Some(responder_pubkey),
            },
        )
    }

    #[allow(clippy::too_many_arguments)] // mirrors the RestoreResponse wire shape one-to-one
    fn on_restore_response(
        &mut self,
        env: &Envelope,
        admitted: bool,
        reason: Option<String>,
        challenge: String,
        responder_node: NodeId,
        responder_signature: Option<String>,
        responder_pubkey: Option<String>,
    ) -> Outcome {
        let reason = reason.map(bounded_reason);
        if !challenge_shape_is_valid(&challenge)
            || !node_id_shape_is_valid(&responder_node)
            || !optional_hex_shape_is_valid(
                responder_signature.as_deref(),
                ED25519_SIGNATURE_HEX_BYTES,
            )
            || !optional_hex_shape_is_valid(
                responder_pubkey.as_deref(),
                ED25519_PUBLIC_KEY_HEX_BYTES,
            )
        {
            return Outcome::none();
        }
        // Match against pending by corr. A response without a matching pending is a late /
        // duplicate / spurious reply; drop silently.
        let pending = match (env.header.corr, self.pending.take()) {
            (Some(corr), Some(p)) if p.consult_corr == corr => p,
            (_, p) => {
                // Restore the un-matched pending (we shouldn't have removed it).
                self.pending = p;
                return Outcome::none();
            }
        };

        // **Responder authentication.** Matching `corr` alone is not
        // enough: transport reseals the envelope `from` to the *local transport creature's* id, so
        // the origin node is not trustworthy there (an earlier `from`-node guard wrongly rejected
        // every legitimate cross-node reply — hence the in-band approach). We instead require the
        // response to (a) echo the unguessable per-migration `challenge` that only a migrator which
        // actually received our `RestoreRequest` could know, and (b) assert in-band that it IS the
        // `destination_node` we shipped to. Either mismatch means a misrouted or spoofed reply:
        // refuse it, KEEP the self authoritative, and re-park the pending so a genuine later
        // response can still complete the migration. (A fully cryptographic responder signature
        // belongs to the fork/merge protocol rework.)
        if challenge != pending.challenge || responder_node != pending.destination_node {
            eprintln!(
                "abode-migrator: REFUSED RestoreResponse on corr {} — responder authentication \
                 failed (expected destination node `{}`, got `{}`; challenge match: {}); staying \
                 Authoritative",
                pending.consult_corr,
                pending.destination_node.0,
                responder_node.0,
                challenge == pending.challenge,
            );
            self.pending = Some(pending);
            return Outcome::none();
        }

        if admitted {
            // **Responder witness** (M9-2). The challenge/node guard above proves the reply came back
            // on the right correlation from a party claiming the right node — but not that it actually
            // ran the six admission gates and is the *anchored* destination. Require a cryptographic
            // witness before sealing. Each failure is a hard refuse that KEEPS the self authoritative
            // and re-parks the pending (a genuine later reply can still complete the migration).
            if self.require_signed_responders {
                // (1) Witness present. An old/unsigned responder cannot seal a migration that
                //     demands proof (the sealed-lab posture opts out via with_unsigned_responder_allowed).
                let (sig, pubkey) = match (&responder_signature, &responder_pubkey) {
                    (Some(s), Some(p)) => (s, p),
                    _ => {
                        eprintln!(
                            "abode-migrator: REFUSED RestoreResponse on corr {} — a signed responder \
                             is required but the response carried no witness; staying Authoritative",
                            pending.consult_corr
                        );
                        self.pending = Some(pending);
                        return Outcome::none();
                    }
                };
                // (2) Signature verifies. Reconstruct the witness from our OWN knowledge (never the
                //     response body): our snapshot's abode_key + state_hash, our challenge, the
                //     destination we shipped to, and the responder's claimed pubkey.
                let witness = responder_witness_payload(
                    &self.abode_key_public_hex,
                    &pending.snapshot_state_hash,
                    &pending.challenge,
                    &pending.destination_node.0,
                    pubkey,
                );
                if !self.verifier.verify(pubkey, &witness, sig) {
                    eprintln!(
                        "abode-migrator: REFUSED RestoreResponse on corr {} — the responder witness \
                         signature did not verify; staying Authoritative",
                        pending.consult_corr
                    );
                    self.pending = Some(pending);
                    return Outcome::none();
                }
                // (3) Anchor binding. A self-consistent signature is not enough: bind the responder
                //     pubkey to the pre-shared anchor pinned at migrate time. A forged keypair verifies
                //     under itself (step 2) but fails here. With no anchor pinned, the protection
                //     degrades to the legacy challenge/node guard (documented weaker posture).
                if let Some(anchor) = &pending.expected_responder_pubkey {
                    if anchor != pubkey {
                        eprintln!(
                            "abode-migrator: REFUSED RestoreResponse on corr {} — responder pubkey \
                             does not match the pinned anchor; staying Authoritative",
                            pending.consult_corr
                        );
                        self.pending = Some(pending);
                        return Outcome::none();
                    }
                }
            }
            // Hand-off complete: source becomes sealed; tell operator.
            self.state = AbodeState::Migrated { to: pending.destination_node.clone() };
            Outcome::send(operator_reply(
                pending.operator_reply_to,
                pending.operator_corr,
                MigratorMsg::MigrateAck { migrated_to: pending.destination_node },
            ))
        } else {
            // Peer refused. Source stays Authoritative; tell operator with the structured reason.
            Outcome::send(operator_reply(
                pending.operator_reply_to,
                pending.operator_corr,
                MigratorMsg::MigrateFailed {
                    reason: bounded_reason(
                        reason.unwrap_or_else(|| "peer refused restore (no reason given)".into()),
                    ),
                },
            ))
        }
    }

    /// Build a signed, integrity-valid snapshot from raw state payload. Wraps with the v3.0 schema
    /// prefix so receivers can dispatch on it.
    fn build_signed_snapshot(&self, raw_payload: Vec<u8>) -> AbodeSnapshot {
        let wrapped = wrap_payload_v0_3(&raw_payload);
        let mut s = AbodeSnapshot::new(self.abode_key_public_hex.clone(), wrapped);
        s.sign(&self.abode_key);
        s
    }
}

// ----- helpers --------------------------------------------------------------------------------

/// The canonical, byte-stable bytes a **responder witness** commits to (M9-2): the source snapshot's
/// `abode_key` + `state_hash` (binds the proof to THIS snapshot/body), the per-migration `challenge`
/// (THIS migration), and the responder's `node` + `pubkey` (THIS responder identity). Both the signer
/// (`on_restore_request`, admitting exit) and the verifier (`on_restore_response`) call this, so the
/// bytes are identical on each side. Deterministic via `aether::wire::to_bytes` — the same byte-stable
/// encoder the snapshot signing payload uses; the `responder_witness_payload_is_locked_to_a_known_fixture`
/// tripwire pins the exact bytes so a field re-order can't silently invalidate witnesses in flight.
fn responder_witness_payload(
    source_abode_key: &str,
    source_state_hash: &str,
    challenge: &str,
    responder_node: &str,
    responder_pubkey: &str,
) -> Vec<u8> {
    aether::wire::to_bytes(&(
        source_abode_key,
        source_state_hash,
        challenge,
        responder_node,
        responder_pubkey,
    ))
}

fn node_id_shape_is_valid(node: &NodeId) -> bool {
    let s = node.0.as_str();
    !s.is_empty()
        && s.len() <= MAX_MIGRATOR_NODE_ID_BYTES
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn optional_len_is_valid(value: Option<&str>, max: usize) -> bool {
    match value {
        Some(s) => s.len() <= max,
        None => true,
    }
}

fn challenge_shape_is_valid(challenge: &str) -> bool {
    challenge.len() <= MAX_MIGRATOR_CHALLENGE_BYTES
        && challenge.bytes().all(|b| b.is_ascii_hexdigit())
}

fn optional_hex_shape_is_valid(value: Option<&str>, exact_len: usize) -> bool {
    match value {
        Some(s) => s.len() == exact_len && s.bytes().all(|b| b.is_ascii_hexdigit()),
        None => true,
    }
}

fn bounded_reason(reason: String) -> String {
    bounded_string(reason, MAX_MIGRATOR_REASON_BYTES)
}

fn bounded_string(mut value: String, max_bytes: usize) -> String {
    const TRUNCATED_SUFFIX: &str = "...[truncated]";
    if value.len() <= max_bytes {
        return value;
    }
    let mut keep = max_bytes.saturating_sub(TRUNCATED_SUFFIX.len());
    while keep > 0 && !value.is_char_boundary(keep) {
        keep -= 1;
    }
    value.truncate(keep);
    value.push_str(TRUNCATED_SUFFIX);
    value
}

/// Reply to the envelope's `reply_to` (or `from`) with a migrator message + SCHEMA + the
/// envelope's corr. Same as `Outcome::reply` but uses MigratorMsg's wire form.
fn reply(env: &Envelope, msg: MigratorMsg) -> Outcome {
    Outcome::send(Dispatch::reply_to_env(env, msg.to_bytes()).with_schema(SCHEMA))
}

/// Reply to the original operator who issued a `Migrate` — uses the saved reply_to/corr, NOT
/// the inbound envelope's (which belong to the peer's RestoreResponse).
fn operator_reply(to: Address, corr: Option<u64>, msg: MigratorMsg) -> Dispatch {
    let mut d = Dispatch::to(to, msg.to_bytes()).with_schema(SCHEMA);
    if let Some(c) = corr {
        d = d.with_corr(c);
    }
    d
}

#[doc(hidden)]
impl AbodeMigrator {
    /// For tests that drive `handle` directly (no kernel `bind`).
    #[cfg(test)]
    pub fn set_me_for_tests(&mut self, me: CreatureId) {
        self.me = Some(me);
    }
}

// ===================================================================================================
// Tests
// ===================================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{CreatureId, Header};

    fn key(seed: u8) -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([seed; 32]).unwrap()
    }

    fn build_migrator(k: Ed25519KeyMaterial) -> AbodeMigrator {
        let mut m =
            AbodeMigrator::new(NodeId("test-node".into()), k, Box::new(PermissiveRestorePolicy));
        m.set_me_for_tests(CreatureId(7));
        m
    }

    fn op_env(msg: MigratorMsg, corr: u64) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(CreatureId(7)),
                reply_to: Some(Address::Creature(CreatureId(100))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: msg.to_bytes(),
        }
    }

    // ----- wrap/unwrap helpers ----

    #[test]
    fn wrap_then_unwrap_round_trips_state_bytes() {
        let raw = b"the self lives here";
        let wrapped = wrap_payload_v0_3(raw);
        assert_eq!(&wrapped[..4], &SCHEMA_V0_3_MAGIC);
        let back = unwrap_payload_v0_3(&wrapped).unwrap();
        assert_eq!(back, raw);
    }

    #[test]
    fn unwrap_rejects_unknown_prefix_with_structured_error() {
        // T1 mitigation: a snapshot with an unknown prefix returns UnknownPrefix; the migrator
        // translates this into RestoreResponse{admitted: false, reason: ...} (see the
        // on_restore_request test below).
        let bytes = b"v999and some payload";
        let err = unwrap_payload_v0_3(bytes).unwrap_err();
        assert!(matches!(err, SnapshotSchemaError::UnknownPrefix(p) if &p == b"v999"));
    }

    #[test]
    fn unwrap_rejects_too_short_input() {
        let err = unwrap_payload_v0_3(b"abc").unwrap_err();
        assert!(matches!(err, SnapshotSchemaError::TooShort { len: 3 }));
    }

    // ----- state machine: SetState, SnapshotRequest, StatusQuery ----

    #[test]
    fn set_state_transitions_empty_to_authoritative_and_replies_state_set() {
        let mut m = build_migrator(key(0xA1));
        assert_eq!(m.state(), &AbodeState::Empty);
        let out = m.handle(op_env(MigratorMsg::SetState { payload: b"abc".to_vec() }, 1));
        assert_eq!(out.dispatches.len(), 1);
        let reply: MigratorMsg = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        assert!(matches!(reply, MigratorMsg::StateSet));
        assert_eq!(m.state(), &AbodeState::Authoritative { payload: b"abc".to_vec() });
    }

    #[test]
    fn set_state_replaces_existing_authoritative_payload() {
        let mut m = build_migrator(key(0xA2));
        m.handle(op_env(MigratorMsg::SetState { payload: b"old".to_vec() }, 1));
        m.handle(op_env(MigratorMsg::SetState { payload: b"new".to_vec() }, 2));
        assert_eq!(m.state(), &AbodeState::Authoritative { payload: b"new".to_vec() });
    }

    #[test]
    fn set_state_rejects_payload_that_cannot_fit_snapshot_ceiling_after_wrapping() {
        let mut m = build_migrator(key(0xA9)).with_max_payload_bytes(SCHEMA_V0_3_MAGIC.len() + 3);
        let out = m.handle(op_env(MigratorMsg::SetState { payload: b"toolong".to_vec() }, 1));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::MigrateFailed { reason } => {
                assert!(reason.contains("set_state rejected"), "got: {reason}");
                assert!(reason.contains("exceeds max snapshot payload"), "got: {reason}");
            }
            other => panic!("expected MigrateFailed, got {other:?}"),
        }
        assert_eq!(m.state(), &AbodeState::Empty);
    }

    #[test]
    fn oversized_migrator_message_is_rejected_before_json_decode() {
        let mut m = build_migrator(key(0xAA)).with_max_payload_bytes(8);
        let max_message_bytes = max_migrator_message_bytes(8);
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(CreatureId(7)),
                reply_to: Some(Address::Creature(CreatureId(100))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(77),
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: vec![b'{'; max_message_bytes + 1],
        };
        let out = m.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        assert_eq!(out.dispatches[0].corr, Some(77));
        match MigratorMsg::parse(&out.dispatches[0].payload).unwrap() {
            MigratorMsg::MigrateFailed { reason } => {
                assert!(reason.contains("exceeds max"), "got: {reason}");
            }
            other => panic!("expected MigrateFailed, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_request_returns_signed_integrity_valid_snapshot_with_v3_magic() {
        let k = key(0xA3);
        let pub_hex = k.public_hex().to_string();
        let mut m = build_migrator(k);
        m.handle(op_env(MigratorMsg::SetState { payload: b"the-self".to_vec() }, 1));
        let out = m.handle(op_env(MigratorMsg::SnapshotRequest, 2));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        let snapshot = match reply {
            MigratorMsg::SnapshotReply { snapshot } => snapshot,
            other => panic!("expected SnapshotReply, got {other:?}"),
        };
        // The snapshot's abode_key matches our pubkey.
        assert_eq!(snapshot.abode_key, pub_hex);
        // The payload carries the magic prefix + the raw state.
        let unwrapped = unwrap_payload_v0_3(&snapshot.payload_bytes).unwrap();
        assert_eq!(unwrapped, b"the-self");
        // Substrate gates: integrity passes, signature verifies under our own pubkey.
        snapshot.assert_integrity().expect("integrity");
        snapshot.verify_signature(&Ed25519Verifier).expect("signature");
    }

    #[test]
    fn status_query_reports_state_and_migrator_config() {
        let mut m = build_migrator(key(0xA4));
        let out = m.handle(op_env(MigratorMsg::StatusQuery, 1));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::StatusReply {
                state,
                migrated_to,
                payload_len,
                signed_snapshots_required,
                max_payload_bytes,
                in_flight_migration,
            } => {
                assert_eq!(state, "empty");
                assert!(migrated_to.is_none());
                assert_eq!(payload_len, 0);
                assert!(signed_snapshots_required);
                assert_eq!(max_payload_bytes, DEFAULT_MAX_PAYLOAD_BYTES);
                assert!(!in_flight_migration);
            }
            other => panic!("expected StatusReply, got {other:?}"),
        }
    }

    // ----- Migrate orchestration: emits RestoreRequest with correct address + corr ----

    #[test]
    fn migrate_emits_restore_request_to_destination_node_with_signed_snapshot_and_parks_pending() {
        let mut m = build_migrator(key(0xA5)).with_consult_corr_seed(500_000);
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        let out = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            2,
        ));
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        // Addressed cross-node.
        assert_eq!(d.to, Address::Node(NodeId("peer-B".into()), CreatureId(99)));
        // Consult corr is the migrator's seed, not the operator's corr.
        assert_eq!(d.corr, Some(500_000));
        // reply_to points back at this migrator.
        assert_eq!(d.reply_to, Some(Address::Creature(CreatureId(7))));
        assert_eq!(d.schema, SCHEMA);
        // Payload is a RestoreRequest with a signed snapshot.
        let msg = MigratorMsg::parse(&d.payload).unwrap();
        let snapshot = match msg {
            MigratorMsg::RestoreRequest { snapshot, .. } => snapshot,
            other => panic!("expected RestoreRequest, got {other:?}"),
        };
        snapshot.verify_signature(&Ed25519Verifier).expect("snapshot signed");
        assert!(m.has_pending_migration());
        // Source not yet migrated (waiting for response).
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
    }

    #[test]
    fn migrate_from_empty_returns_migrate_failed_no_authoritative_state() {
        let mut m = build_migrator(key(0xA6));
        let out = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            1,
        ));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        assert!(
            matches!(reply, MigratorMsg::MigrateFailed { reason } if reason.contains("no authoritative"))
        );
    }

    #[test]
    fn migrate_before_bind_replies_failed_and_parks_nothing() {
        let mut m = build_migrator(key(0xA8));
        m.me = None;
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));

        let out = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            2,
        ));

        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        assert!(
            matches!(reply, MigratorMsg::MigrateFailed { reason } if reason.contains("not bound"))
        );
        assert!(!m.has_pending_migration());
    }

    #[test]
    fn migrate_rejects_malformed_destination_metadata_before_parking() {
        let mut m = build_migrator(key(0xAB));
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));

        let out = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("bad node".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            2,
        ));
        match MigratorMsg::parse(&out.dispatches[0].payload).unwrap() {
            MigratorMsg::MigrateFailed { reason } => {
                assert!(reason.contains("destination_node"), "got: {reason}");
            }
            other => panic!("expected MigrateFailed, got {other:?}"),
        }
        assert!(!m.has_pending_migration());
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));

        let out = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: Some("f".repeat(63)),
            },
            3,
        ));
        match MigratorMsg::parse(&out.dispatches[0].payload).unwrap() {
            MigratorMsg::MigrateFailed { reason } => {
                assert!(reason.contains("expected_responder_pubkey"), "got: {reason}");
            }
            other => panic!("expected MigrateFailed, got {other:?}"),
        }
        assert!(!m.has_pending_migration());
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
    }

    #[test]
    fn double_migrate_is_rejected_with_in_flight_reason() {
        let mut m = build_migrator(key(0xA7));
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            2,
        ));
        let out = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("C".into()),
                destination_migrator: CreatureId(98),
                expected_responder_pubkey: None,
            },
            3,
        ));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        assert!(
            matches!(reply, MigratorMsg::MigrateFailed { reason } if reason.contains("in flight"))
        );
    }

    // ----- RestoreRequest admission: substrate gates + injected policy ----

    fn make_signed_snapshot(
        signer_key: u8,
        declared_key: Option<u8>,
        payload: &[u8],
    ) -> AbodeSnapshot {
        let signer = key(signer_key);
        let declared = declared_key.map(key).unwrap_or_else(|| signer.clone());
        let wrapped = wrap_payload_v0_3(payload);
        let mut s = AbodeSnapshot::new(declared.public_hex().to_string(), wrapped);
        s.sign(&signer);
        s
    }

    fn peer_restore_env(snapshot: AbodeSnapshot, corr: u64) -> Envelope {
        peer_restore_env_with(snapshot, corr, None, String::new())
    }

    fn peer_restore_env_with(
        snapshot: AbodeSnapshot,
        corr: u64,
        note: Option<String>,
        challenge: String,
    ) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Node(NodeId("peer".into()), CreatureId(33)),
                to: Address::Creature(CreatureId(7)),
                reply_to: Some(Address::Node(NodeId("peer".into()), CreatureId(33))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: MigratorMsg::RestoreRequest { snapshot, note, challenge }.to_bytes(),
        }
    }

    /// Extract the per-migration challenge from the `RestoreRequest` a migrator emits on `Migrate`,
    /// so a test can echo it back the way a real destination migrator does.
    fn challenge_of(out: &Outcome) -> String {
        match MigratorMsg::parse(&out.dispatches[0].payload).unwrap() {
            MigratorMsg::RestoreRequest { challenge, .. } => challenge,
            other => panic!("expected RestoreRequest, got {other:?}"),
        }
    }

    /// Extract the signed snapshot from the `RestoreRequest` a migrator emits on `Migrate`, so a test
    /// can read its `state_hash` to reconstruct the responder witness the way a real destination does.
    fn snapshot_of(out: &Outcome) -> AbodeSnapshot {
        match MigratorMsg::parse(&out.dispatches[0].payload).unwrap() {
            MigratorMsg::RestoreRequest { snapshot, .. } => snapshot,
            other => panic!("expected RestoreRequest, got {other:?}"),
        }
    }

    /// Build a `RestoreResponse` envelope as a peer migrator would, with an explicit `challenge`
    /// and `responder_node` but **no witness** — for the legacy challenge/node guard (paired with a
    /// migrator built `.with_unsigned_responder_allowed()`). The witness path has its own builder.
    fn restore_response_env(
        corr: u64,
        admitted: bool,
        reason: Option<String>,
        challenge: String,
        responder_node: NodeId,
    ) -> Envelope {
        restore_response_env_signed(corr, admitted, reason, challenge, responder_node, None, None)
    }

    /// As [`restore_response_env`] but with the optional M9-2 responder witness
    /// (`responder_signature` + `responder_pubkey`) so a test can drive the cryptographic gate.
    #[allow(clippy::too_many_arguments)] // a test builder mirroring the full RestoreResponse wire shape
    fn restore_response_env_signed(
        corr: u64,
        admitted: bool,
        reason: Option<String>,
        challenge: String,
        responder_node: NodeId,
        responder_signature: Option<String>,
        responder_pubkey: Option<String>,
    ) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Node(NodeId("peer-B".into()), CreatureId(99)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(corr),
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: MigratorMsg::RestoreResponse {
                admitted,
                reason,
                challenge,
                responder_node,
                responder_signature,
                responder_pubkey,
            }
            .to_bytes(),
        }
    }

    #[test]
    fn restore_admits_well_formed_signed_snapshot_with_permissive_policy() {
        let mut m = build_migrator(key(0xB1));
        let snapshot = make_signed_snapshot(0xC1, None, b"the-self");
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        assert!(
            matches!(reply, MigratorMsg::RestoreResponse { admitted: true, .. }),
            "permissive policy + valid signed snapshot must admit"
        );
        // Migrator is now Authoritative with the unwrapped raw payload.
        assert_eq!(m.state(), &AbodeState::Authoritative { payload: b"the-self".to_vec() });
    }

    #[test]
    fn restore_request_rejects_malformed_metadata_without_echoing_huge_challenge() {
        let mut m = build_migrator(key(0xBA));
        let snapshot = make_signed_snapshot(0xCA, None, b"the-self");
        let out = m.handle(peer_restore_env_with(
            snapshot,
            9,
            Some("n".repeat(MAX_MIGRATOR_NOTE_BYTES + 1)),
            "a".repeat(MAX_MIGRATOR_CHALLENGE_BYTES + 1),
        ));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::RestoreResponse {
                admitted: false,
                reason: Some(reason),
                challenge,
                ..
            } => {
                assert!(reason.contains("malformed migrator metadata"), "got: {reason}");
                assert!(challenge.is_empty(), "malformed challenge must not be reflected");
            }
            other => panic!("expected RestoreResponse(admitted=false), got {other:?}"),
        }
        assert_eq!(m.state(), &AbodeState::Empty);
    }

    #[test]
    fn restore_rejects_unsigned_snapshot_when_signatures_required() {
        let mut m = build_migrator(key(0xB2));
        // Build a snapshot but don't sign it.
        let snapshot = AbodeSnapshot::new("any-key".to_string(), wrap_payload_v0_3(b"x"));
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::RestoreResponse { admitted: false, reason: Some(r), .. } => {
                assert!(r.contains("substrate-gate:signature"));
                assert!(r.contains("absent"));
            }
            other => {
                panic!("expected RestoreResponse(admitted=false, signature absent), got {other:?}")
            }
        }
        assert_eq!(m.state(), &AbodeState::Empty);
    }

    #[test]
    fn restore_admits_unsigned_when_migrator_explicitly_allows() {
        let mut m = AbodeMigrator::new(
            NodeId("test-node".into()),
            key(0xB3),
            Box::new(PermissiveRestorePolicy),
        )
        .with_unsigned_snapshots_allowed();
        m.set_me_for_tests(CreatureId(7));
        let snapshot = AbodeSnapshot::new("anon".to_string(), wrap_payload_v0_3(b"y"));
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        assert!(matches!(reply, MigratorMsg::RestoreResponse { admitted: true, .. }));
    }

    #[test]
    fn restore_rejects_tampered_payload_at_integrity_gate() {
        let mut m = build_migrator(key(0xB4));
        let mut snapshot = make_signed_snapshot(0xC4, None, b"original");
        // Tamper the payload AFTER signing, without re-deriving state_hash. The integrity gate
        // catches it before the signature gate gets a chance.
        snapshot.payload_bytes = wrap_payload_v0_3(b"replaced");
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::RestoreResponse { admitted: false, reason: Some(r), .. } => {
                assert!(r.contains("substrate-gate:integrity"));
            }
            other => panic!("expected integrity gate rejection, got {other:?}"),
        }
    }

    #[test]
    fn restore_rejects_oversize_payload_at_size_gate_before_deserialization() {
        let mut m = AbodeMigrator::new(
            NodeId("test-node".into()),
            key(0xB5),
            Box::new(PermissiveRestorePolicy),
        )
        .with_max_payload_bytes(128);
        m.set_me_for_tests(CreatureId(7));
        let big = vec![0u8; 1024];
        let snapshot = make_signed_snapshot(0xC5, None, &big);
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::RestoreResponse { admitted: false, reason: Some(r), .. } => {
                assert!(r.contains("substrate-gate:size"));
            }
            other => panic!("expected size gate rejection, got {other:?}"),
        }
    }

    #[test]
    fn restore_rejects_unknown_schema_prefix_at_migrator_gate() {
        // T1 mitigation: a snapshot whose payload starts with v4.0 (or any non-v3.0 prefix) is
        // rejected by this hand-off migrator with a structured reason. The substrate doesn't see
        // the prefix.
        let mut m = build_migrator(key(0xB6));
        // Build a signed snapshot whose payload uses a v999 prefix (not the v3.0 magic).
        let signer = key(0xC6);
        let mut payload = b"v999".to_vec();
        payload.extend_from_slice(b"future-encoding");
        let mut snapshot = AbodeSnapshot::new(signer.public_hex().to_string(), payload);
        snapshot.sign(&signer);
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::RestoreResponse { admitted: false, reason: Some(r), .. } => {
                assert!(r.contains("migrator-gate:schema"), "got: {r}");
                assert!(r.contains("unknown schema prefix"));
            }
            other => panic!("expected schema gate rejection, got {other:?}"),
        }
    }

    #[test]
    fn restore_consults_injected_policy_and_returns_its_reason() {
        struct DenyAll;
        impl RestorePolicy for DenyAll {
            fn admit(&self, _s: &AbodeSnapshot) -> Result<(), String> {
                Err("denied by my-org policy".into())
            }
        }
        let mut m = AbodeMigrator::new(NodeId("test-node".into()), key(0xB7), Box::new(DenyAll));
        m.set_me_for_tests(CreatureId(7));
        let snapshot = make_signed_snapshot(0xC7, None, b"x");
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::RestoreResponse { admitted: false, reason: Some(r), .. } => {
                assert!(r.contains("restore-policy"));
                assert!(r.contains("denied by my-org policy"));
            }
            other => panic!("expected policy rejection, got {other:?}"),
        }
    }

    #[test]
    fn restore_while_authoritative_points_callers_to_the_reconciler_path() {
        // This hand-off migrator is single-active-fork only. A migrator that's already
        // authoritative refuses a peer's RestoreRequest with a structured reason and points callers
        // at the reconciler path.
        let mut m = build_migrator(key(0xB8));
        m.handle(op_env(MigratorMsg::SetState { payload: b"local".to_vec() }, 1));
        let snapshot = make_signed_snapshot(0xC8, None, b"peer");
        let out = m.handle(peer_restore_env(snapshot, 9));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::RestoreResponse { admitted: false, reason: Some(r), .. } => {
                assert!(r.contains("abode-reconciler"), "got: {r}");
            }
            other => panic!("expected fork rejection, got {other:?}"),
        }
        // Local Abode is undisturbed.
        assert_eq!(m.state(), &AbodeState::Authoritative { payload: b"local".to_vec() });
    }

    // ----- Migrate full round-trip: on_restore_response transitions source to Migrated ----

    #[test]
    fn on_restore_response_admitted_transitions_source_to_migrated_and_replies_migrate_ack() {
        // Direct unit test: emulate the response envelope arriving from the peer back to A's
        // migrator after on_migrate parked a pending. A's migrator transitions to Migrated and
        // replies MigrateAck to the operator at the original corr.
        // Legacy challenge/node guard only (no witness): opt out of the M9-2 signed-responder gate.
        let mut m = build_migrator(key(0xD1))
            .with_consult_corr_seed(2000)
            .with_unsigned_responder_allowed();
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        let mig = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            555, // operator's original corr
        ));
        // The peer "responds" — same consult_corr the migrator emitted, echoing the challenge it
        // minted and asserting it is the destination node (the authentication contract).
        let response_env =
            restore_response_env(2000, true, None, challenge_of(&mig), NodeId("peer-B".into()));
        let out = m.handle(response_env);
        // Source now sealed.
        assert_eq!(m.state(), &AbodeState::Migrated { to: NodeId("peer-B".into()) });
        assert!(!m.has_pending_migration());
        // Reply went to the operator at the original corr.
        let d = &out.dispatches[0];
        assert_eq!(d.corr, Some(555));
        assert_eq!(d.to, Address::Creature(CreatureId(100))); // the operator probe
        let reply = MigratorMsg::parse(&d.payload).unwrap();
        match reply {
            MigratorMsg::MigrateAck { migrated_to } => {
                assert_eq!(migrated_to, NodeId("peer-B".into()));
            }
            other => panic!("expected MigrateAck, got {other:?}"),
        }
    }

    #[test]
    fn on_restore_response_denied_leaves_source_authoritative_and_replies_migrate_failed() {
        let mut m = build_migrator(key(0xD2)).with_consult_corr_seed(3000);
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        let mig = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            777,
        ));
        let response_env = restore_response_env(
            3000,
            false,
            Some("policy says no".into()),
            challenge_of(&mig),
            NodeId("peer-B".into()),
        );
        let out = m.handle(response_env);
        // Source NOT migrated.
        assert_eq!(m.state(), &AbodeState::Authoritative { payload: b"S".to_vec() });
        assert!(!m.has_pending_migration());
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        assert!(
            matches!(reply, MigratorMsg::MigrateFailed { reason } if reason.contains("policy says no"))
        );
    }

    #[test]
    fn restore_response_with_mismatched_corr_is_silently_ignored() {
        let mut m = build_migrator(key(0xD3)).with_consult_corr_seed(4000);
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            1,
        ));
        // Response with the WRONG corr (4001 instead of 4000) — should not pop pending. The
        // challenge / responder are irrelevant here: the corr mismatch drops it before the auth gate.
        let response_env =
            restore_response_env(4001, true, None, String::new(), NodeId("peer-B".into()));
        let out = m.handle(response_env);
        assert!(out.dispatches.is_empty(), "spurious response is silently dropped");
        assert!(m.has_pending_migration(), "pending preserved");
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
    }

    #[test]
    fn restore_response_with_malformed_metadata_preserves_pending() {
        let mut m = build_migrator(key(0xD4))
            .with_consult_corr_seed(4100)
            .with_unsigned_responder_allowed();
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        let mig = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            44,
        ));

        let out = m.handle(restore_response_env(
            4100,
            true,
            None,
            "f".repeat(MAX_MIGRATOR_CHALLENGE_BYTES + 1),
            NodeId("peer-B".into()),
        ));
        assert!(out.dispatches.is_empty(), "malformed response metadata is dropped");
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
        assert!(m.has_pending_migration(), "pending preserved for a genuine later response");

        let out = m.handle(restore_response_env(
            4100,
            true,
            None,
            challenge_of(&mig),
            NodeId("peer-B".into()),
        ));
        assert_eq!(m.state(), &AbodeState::Migrated { to: NodeId("peer-B".into()) });
        assert!(!m.has_pending_migration());
        assert!(matches!(
            MigratorMsg::parse(&out.dispatches[0].payload).unwrap(),
            MigratorMsg::MigrateAck { .. }
        ));
    }

    #[test]
    fn denied_restore_response_reason_is_bounded_before_operator_reply() {
        let mut m = build_migrator(key(0xD5)).with_consult_corr_seed(4200);
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        let mig = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            45,
        ));

        let out = m.handle(restore_response_env(
            4200,
            false,
            Some("x".repeat(MAX_MIGRATOR_REASON_BYTES + 1024)),
            challenge_of(&mig),
            NodeId("peer-B".into()),
        ));
        let reply = MigratorMsg::parse(&out.dispatches[0].payload).unwrap();
        match reply {
            MigratorMsg::MigrateFailed { reason } => {
                assert!(reason.len() <= MAX_MIGRATOR_REASON_BYTES, "len: {}", reason.len());
                assert!(reason.ends_with("[truncated]"), "got suffix in: {reason}");
            }
            other => panic!("expected MigrateFailed, got {other:?}"),
        }
    }

    #[test]
    fn on_restore_response_failing_responder_auth_is_refused_then_genuine_one_completes() {
        // A RestoreResponse on the CORRECT corr but from the wrong origin — or echoing the
        // wrong challenge — must NOT seal the source. Only the genuine reply (right corr + right
        // challenge + the destination node we shipped to) completes the migration.
        // This test exercises the legacy challenge/node guard; opt out of the M9-2 witness gate so
        // the genuine (right corr + challenge + node) reply at the end completes the migration.
        let mut m = build_migrator(key(0xE9))
            .with_consult_corr_seed(5000)
            .with_unsigned_responder_allowed();
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        let mig = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("peer-B".into()),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: None,
            },
            42,
        ));
        let good_challenge = challenge_of(&mig);

        // (a) right corr + right challenge, but the responder claims to be a DIFFERENT node.
        let out = m.handle(restore_response_env(
            5000,
            true,
            None,
            good_challenge.clone(),
            NodeId("attacker".into()),
        ));
        assert!(out.dispatches.is_empty(), "a wrong-origin response must produce no MigrateAck");
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }), "self stays authoritative");
        assert!(m.has_pending_migration(), "pending preserved for a genuine later response");

        // (b) right corr + right node, but the WRONG challenge (a party that never saw the request).
        let out = m.handle(restore_response_env(
            5000,
            true,
            None,
            "0badc0de".into(),
            NodeId("peer-B".into()),
        ));
        assert!(out.dispatches.is_empty());
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
        assert!(m.has_pending_migration());

        // (c) the genuine response — right corr + challenge + destination node — completes it.
        let out = m.handle(restore_response_env(
            5000,
            true,
            None,
            good_challenge,
            NodeId("peer-B".into()),
        ));
        assert_eq!(m.state(), &AbodeState::Migrated { to: NodeId("peer-B".into()) });
        assert!(!m.has_pending_migration());
        assert!(matches!(
            MigratorMsg::parse(&out.dispatches[0].payload).unwrap(),
            MigratorMsg::MigrateAck { .. }
        ));
    }

    // ----- M9-2: responder witness authentication ----

    #[test]
    fn on_restore_response_without_responder_signature_proof_is_refused() {
        // With require_signed_responders = true (the default), an admitting RestoreResponse must carry
        // a witness that (2) verifies AND (3) matches the pinned anchor. A missing witness, a bad
        // signature, or a forged keypair unbound to the anchor is refused (self stays Authoritative,
        // pending re-parked); only the genuine, anchor-matching, correctly-signed reply completes it.
        let src = key(0xF1);
        let src_pub = src.public_hex().to_string();
        let responder = key(0xF2);
        let responder_pub = responder.public_hex().to_string();
        let dest = NodeId("peer-B".into());

        // Build the source, pinning the responder's pubkey as the trust anchor on the Migrate op.
        let mut m = build_migrator(src).with_consult_corr_seed(6000);
        m.handle(op_env(MigratorMsg::SetState { payload: b"S".to_vec() }, 1));
        let mig = m.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: dest.clone(),
                destination_migrator: CreatureId(99),
                expected_responder_pubkey: Some(responder_pub.clone()),
            },
            42,
        ));
        let challenge = challenge_of(&mig);
        let state_hash = snapshot_of(&mig).state_hash;
        // Build the witness signature a given signer would produce for a given claimed pubkey.
        let witness_sig = |signer: &Ed25519KeyMaterial, pubkey: &str| -> String {
            signer.sign(&responder_witness_payload(
                &src_pub,
                &state_hash,
                &challenge,
                &dest.0,
                pubkey,
            ))
        };

        // (a) Right corr + challenge + node, but NO witness → refused (a signed responder is required).
        let out = m.handle(restore_response_env(6000, true, None, challenge.clone(), dest.clone()));
        assert!(out.dispatches.is_empty(), "a witness-less response must not seal the source");
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
        assert!(m.has_pending_migration(), "pending re-parked for a genuine later reply");

        // (b) Anchor-matching pubkey but a BOGUS signature → refused at the verify step.
        let out = m.handle(restore_response_env_signed(
            6000,
            true,
            None,
            challenge.clone(),
            dest.clone(),
            Some("0".repeat(128)),
            Some(responder_pub.clone()),
        ));
        assert!(out.dispatches.is_empty(), "an unverifiable witness must be refused");
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
        assert!(m.has_pending_migration());

        // (c) A FORGED keypair: its signature verifies under itself (step 2) but the pubkey is not the
        //     pinned anchor (step 3) → refused. This is the load-bearing case the anchor exists for.
        let forger = key(0xFF);
        let forger_pub = forger.public_hex().to_string();
        let out = m.handle(restore_response_env_signed(
            6000,
            true,
            None,
            challenge.clone(),
            dest.clone(),
            Some(witness_sig(&forger, &forger_pub)),
            Some(forger_pub),
        ));
        assert!(out.dispatches.is_empty(), "a forged, unbound responder is refused at the anchor");
        assert!(matches!(m.state(), AbodeState::Authoritative { .. }));
        assert!(m.has_pending_migration());

        // (d) The genuine, anchor-matching, correctly-signed response → completes to Migrated.
        let genuine_sig = witness_sig(&responder, &responder_pub);
        let out = m.handle(restore_response_env_signed(
            6000,
            true,
            None,
            challenge.clone(),
            dest.clone(),
            Some(genuine_sig),
            Some(responder_pub),
        ));
        assert_eq!(m.state(), &AbodeState::Migrated { to: dest });
        assert!(!m.has_pending_migration());
        assert!(matches!(
            MigratorMsg::parse(&out.dispatches[0].payload).unwrap(),
            MigratorMsg::MigrateAck { .. }
        ));
    }

    #[test]
    fn responder_round_trip_signs_a_witness_the_requester_verifies() {
        // End-to-end at the unit level: the responder's on_restore_request signs a witness on the
        // admitting exit, and the requester's on_restore_response verifies it (no anchor pinned →
        // the witness is still required and must verify, only the anchor-binding step is skipped).
        let responder_key = key(0x5A);
        let responder_pub = responder_key.public_hex().to_string();
        let mut responder = build_migrator(responder_key);
        // Source builds a real snapshot so the responder signs over genuine (abode_key, state_hash).
        let mut source = build_migrator(key(0x5B)).with_consult_corr_seed(7000);
        source.handle(op_env(MigratorMsg::SetState { payload: b"the-self".to_vec() }, 1));
        let mig = source.handle(op_env(
            MigratorMsg::Migrate {
                destination_node: NodeId("test-node".into()), // responder's self_node
                destination_migrator: CreatureId(7),
                expected_responder_pubkey: None,
            },
            9,
        ));
        let snapshot = snapshot_of(&mig);
        let challenge = challenge_of(&mig);

        // Drive the responder with the source's RestoreRequest.
        let req = Envelope {
            header: Header {
                from: Address::Node(NodeId("src".into()), CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: Some(Address::Node(NodeId("src".into()), CreatureId(1))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(7000),
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: MigratorMsg::RestoreRequest { snapshot, note: None, challenge }.to_bytes(),
        };
        let resp_out = responder.handle(req);
        let resp = MigratorMsg::parse(&resp_out.dispatches[0].payload).unwrap();
        let (admitted, responder_signature, responder_pubkey) = match resp {
            MigratorMsg::RestoreResponse {
                admitted,
                responder_signature,
                responder_pubkey,
                ..
            } => (admitted, responder_signature, responder_pubkey),
            other => panic!("expected RestoreResponse, got {other:?}"),
        };
        assert!(admitted, "permissive policy admits");
        assert!(responder_signature.is_some(), "an admitting reply carries a witness");
        assert_eq!(responder_pubkey.as_deref(), Some(responder_pub.as_str()));

        // Feed it back to the source — the witness verifies and the migration completes.
        let response_env = restore_response_env_signed(
            7000,
            true,
            None,
            challenge_of(&mig),
            NodeId("test-node".into()),
            responder_signature,
            responder_pubkey,
        );
        let out = source.handle(response_env);
        assert_eq!(source.state(), &AbodeState::Migrated { to: NodeId("test-node".into()) });
        assert!(matches!(
            MigratorMsg::parse(&out.dispatches[0].payload).unwrap(),
            MigratorMsg::MigrateAck { .. }
        ));
    }

    #[test]
    fn responder_witness_payload_is_locked_to_a_known_fixture() {
        // Pin the exact witness bytes for a fixed input. A field re-order or a non-byte-stable
        // encoding would change these bytes and silently invalidate every responder signature in
        // flight; this tripwire fires first. (Mirrors AbodeSnapshot::signing_payload_hash_is_locked.)
        let payload = responder_witness_payload(
            "source-abode-key",
            "state-hash-abc",
            "challenge-xyz",
            "responder-node",
            "responder-pubkey",
        );
        assert_eq!(
            String::from_utf8(payload).unwrap(),
            r#"["source-abode-key","state-hash-abc","challenge-xyz","responder-node","responder-pubkey"]"#,
            "the responder witness payload shape/encoding changed — in-flight responder signatures would break"
        );
    }

    // ----- malformed input + wrong schema ----

    #[test]
    fn malformed_payload_does_not_panic_and_returns_no_outcome() {
        let mut m = build_migrator(key(0xE1));
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: SCHEMA.into(),
            },
            payload: b"{not json".to_vec(),
        };
        let out = m.handle(env);
        assert!(out.dispatches.is_empty());
    }

    #[test]
    fn wrong_schema_is_silently_ignored() {
        let mut m = build_migrator(key(0xE2));
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(100)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "some.other.schema".into(),
            },
            payload: MigratorMsg::StatusQuery.to_bytes(),
        };
        let out = m.handle(env);
        assert!(out.dispatches.is_empty());
    }
}
