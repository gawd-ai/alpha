//! Addressing — the two modes the operating model's loops require, composed by depth.
//!
//! **Identity addressing** ([`Address::Creature`] / [`Node`](Address::Node) /
//! [`Kernel`](Address::Kernel) / [`Topic`](Address::Topic)) talks to *this* creature/node.
//! **Capability addressing** ([`Address::Role`] / [`Intent`](Address::Intent)) routes to *whoever*
//! is bound to fill it — the inversion-of-control socket. Both are the *same envelope*, resolved
//! differently by the [`Router`](crate::Router); that symmetry is integration risk **R8**.
//!
//! **Federation grain** ([`Realm`](Address::Realm) /
//! [`Omega`](Address::Omega)). Both wrap an inner address (the *target* in the named federation
//! grain), and both resolve via a bound gateway creature (`realm-gateway` / `omega-gateway`) —
//! same IoC discipline as the `Intent → Distributor` and `Node → Transport` cases. Real Omega
//! federation (`creatures/omega-federator`) rides the existing socket, keeping the
//! shape-first discipline without changing the envelope.

use serde::{Deserialize, Serialize};

/// A creature's routing handle, assigned by the kernel at load. Monotone and never reused, so a
/// stale id simply isn't in the table after unload (no aliasing) — the routing half of safe unload.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CreatureId(pub u64);

/// A node's transport identity — distinct from an Abode's authorship identity.
/// `Default` is the empty id (`NodeId("")`) — an "unset" placeholder that can never equal a real
/// node, used as the serde fallback for an absent in-band `responder_node`.
#[derive(Clone, Default, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct NodeId(pub String);

// RealmId is the federation address grain AND a trust assertion on `Provenance`
// (the author claims their work belongs to this Realm — sigil's `Provenance.realm`). Since
// sigil is the base contract crate and aether depends on it (not the other way around),
// the canonical definition lives there and aether re-exports it. This way both uses see the same
// type without circularity.
pub use sigil::RealmId;

/// An inversion-of-control socket name: `"distributor"`, `"policy"`, `"transport"`, … A creature
/// bound to a role *is* the model for that concern; the fabric ships the socket, never the model.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Role(pub String);

impl Role {
    /// The Distributor hook — `Intent` envelopes route to whoever fills this.
    pub const DISTRIBUTOR: &'static str = "distributor";
    /// The off-node egress — `Node`-addressed envelopes route to whoever fills this.
    pub const TRANSPORT: &'static str = "transport";
    /// The admission decision-maker.
    pub const POLICY: &'static str = "policy";
    /// The Bestiary seed — publish/fetch artifacts by content address. The fabric ships the socket,
    /// the in-memory `creatures/registry-mem` is one local creature that fills it; cross-Realm
    /// anti-entropy/reputation layers on top through `creatures/omega-federator`.
    pub const REGISTRY: &'static str = "registry";
    /// The **authoring** seam. An `AuthoringRequest` (NL intent + optional retry
    /// context) routes to whoever fills this; the bound creature produces Rust source + a manifest
    /// stub for the BUILD socket to compile. The reference example (`creatures/agent-templated`) is a
    /// pattern-matched template; a real LLM-backed agent is the same shape on the same socket.
    pub const AUTHORING: &'static str = "authoring";
    /// The **build** seam. A `BuildRequest` (source + manifest stub + signing
    /// key + sandbox kind) routes to whoever fills this; the bound creature compiles, hashes, signs,
    /// and returns a manifest+artifact pair admissible by `Kernel::load`. The reference
    /// (`creatures/build-cargo`) shells out to cargo with an operator-opt-in sandbox; alternative
    /// builders (cross-compile, AOT-from-wasm, distributed build farm) plug into the same socket.
    pub const BUILD: &'static str = "build";
    /// **Realm-gateway.** [`Address::Realm`] envelopes route to whoever
    /// fills this. The bound creature unwraps the inner target and re-routes — locally for
    /// same-Realm peers, via [`Role::TRANSPORT`] for cross-Realm. The reference example
    /// (`cosmos/creatures/prototypes/gateways/realm-gateway`) is the gateway shape; richer peering policy remains an
    /// injected creature concern.
    pub const REALM_GATEWAY: &'static str = "realm-gateway";
    /// **Omega-gateway.** [`Address::Omega`] envelopes route to whoever
    /// fills this. The Omega is the federation of Realms; `creatures/omega-federator` fills this
    /// socket with real pull anti-entropy, signed reputation, and cross-Realm routing.
    pub const OMEGA_GATEWAY: &'static str = "omega-gateway";
    /// **Abode-migrator.** A consumer of the top-level `abode` crate's shape: a long-lived creature
    /// on every Sanctum that snapshots the local Abode state, ships `abode::AbodeRestore` envelopes to a peer migrator,
    /// and admits incoming snapshots via an injected restore policy. The substrate ships the
    /// socket; the operator binds a model (single-active-fork hand-off; fork/merge is the
    /// reconciler's job).
    pub const ABODE_MIGRATOR: &'static str = "abode-migrator";
    /// **Fitness-selector.** A consumer of
    /// operating-model Loop 2 (author → select → promote): a long-lived creature that aggregates the
    /// kernel's [`crate::Topic::FITNESS`] signal per watched creature, scores each by an **injected**
    /// `FitnessScorer`, and writes a *signed, self-verifying* promotion onto the registry's
    /// reputation slot. The substrate ships the socket + the fitness signal + the registry slot + the
    /// signing payload shape; the operator binds the *criterion* (T4 / IoC). The reference scorers
    /// (`cosmos/creatures/prototypes/scorers/scorer-success-rate` / `scorer-latency` / `scorer-roundrobin`) are creatures like
    /// any other; a richer LLM-judged or peer-comparative selector is the same shape on this socket.
    /// Selection only *promotes* — retiring the unfit is the immune-response on a different role.
    pub const FITNESS_SELECTOR: &'static str = "fitness-selector";
    /// **Immune-response.** A consumer of operating-model Loop 4 (Defend): a long-lived creature that subscribes to the
    /// kernel's [`crate::Topic::PROPRIOCEPTION`] stream, senses faults on *watched* creatures (a
    /// `hard` budget breach, a leaked-resources unload, or an injected fault `Report`), and writes a
    /// **reversible** quarantine marker onto the registry. It honors inbound cross-Realm quarantine
    /// notices through an **injected** `QuarantineTrust` gate (T2 — a peer can't quarantine your
    /// creatures unless you trust it). The substrate ships the socket + the proprioception stream +
    /// the registry's reversible quarantine slot + the federation path; the operator binds the trust
    /// *model* (IoC). It is the dual of the fitness-selector: defense *quarantines*, never promotes,
    /// on a different role and a different sense stream — so reward and defense stay legible.
    pub const IMMUNE_RESPONSE: &'static str = "immune-response";
    /// **Abode-reconciler** — the fork+merge half of the distributed self. Where
    /// [`Role::ABODE_MIGRATOR`] does single-active-fork *hand-off*, the reconciler *merges* two
    /// divergent snapshots of the same Abode (a healed partition, a rejoined offline fork) into one
    /// authoritative snapshot via an **injected** CRDT merge model, re-signed by the Abode key. The
    /// substrate ships the socket + the snapshot verify/sign primitives; the conflict-free *lattice*
    /// is the operator's model (IoC). The reference (`cosmos/creatures/prototypes/merge/merge-lww-map`) is an LWW-Element-Map;
    /// a domain that needs OR-Set / RGA / a bespoke join-semilattice binds its own.
    pub const ABODE_RECONCILER: &'static str = "abode-reconciler";
    /// **Control.** The node's own control plane, dogfooded onto the bus: a
    /// `Verb` envelope (schema `control_verb`) routes to whoever fills this, and the bound
    /// [`ControlCore`](../../omni/struct.ControlCore.html) translator runs it against the
    /// live node and replies with a `VerbResult` envelope (schema `control_result`). Every control
    /// surface — the REPL, the HTTP/WS plane, the MCP hub — is a thin client of this one socket, and
    /// remote control is the *same* envelope crossing the mesh to a peer node's `Role::CONTROL`. The
    /// substrate ships the socket; the operator loads the control organ (loading a privileged surface
    /// is itself a privileged act).
    pub const CONTROL: &'static str = "control";

    pub fn new(s: impl Into<String>) -> Self {
        Role(s.into())
    }
}

/// A publish/subscribe channel for fan-out (telemetry, proprioception, fitness, …).
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct Topic(pub String);

impl Topic {
    /// Liveness / sense stream (operating-model Loops 1/4).
    pub const PROPRIOCEPTION: &'static str = "proprioception";
    /// Outcome / fitness stream (operating-model Loop 2 selection).
    pub const FITNESS: &'static str = "fitness";

    pub fn new(s: impl Into<String>) -> Self {
        Topic(s.into())
    }
}

/// The unit of work as an *address*: a desired outcome + requirements, naming no creature. The
/// Distributor (an injected creature bound to [`Role::DISTRIBUTOR`]) resolves it to a concrete
/// creature. The fabric carries it; it never resolves it.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct Intent {
    /// Free-form outcome descriptor (e.g. `"reverse-string"`).
    pub outcome: String,
    /// Requirements an injected matcher weighs against a node's embodiment. Opaque to the fabric.
    #[serde(default)]
    pub requirements: Vec<String>,
}

/// Where an envelope is going (or coming from).
///
/// **Composition by depth**: [`Realm`](Self::Realm) and [`Omega`](Self::Omega) wrap
/// an inner `target`, so a federation-grain envelope is the *same envelope* with one more layer of
/// resolution — not a parallel routing system.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum Address {
    /// Identity: a specific local creature.
    Creature(CreatureId),
    /// Identity: a creature on a peer node — routed *off-node* via the bound `transport` creature.
    /// "Route off-node" is not a new subsystem; it is one more delivery case (**R4**).
    Node(NodeId, CreatureId),
    /// The kernel's own control surface.
    Kernel,
    /// Fan-out to every subscriber of a topic.
    Topic(Topic),
    /// Capability: whoever is bound to this role (IoC socket). Unbound → `NoProvider`.
    Role(Role),
    /// Capability: the Distributor hook — resolve + place this work. Unbound → `NoProvider`.
    Intent(Intent),
    /// Federation: address `target` in [`Realm`](RealmId) `realm`. Resolved by the bound
    /// [`Role::REALM_GATEWAY`] creature, which unwraps `target` and re-routes — locally for
    /// same-Realm peers, via [`Role::TRANSPORT`] for cross-Realm. Unbound → `NoProvider`. The
    /// `target` is itself an `Address` so a Realm envelope can name any destination (Creature /
    /// Node / Role / Intent / Topic / Kernel) inside the named Realm — composition by depth.
    ///
    /// **Capability grain:** the bus-level `capabilities.calls` gate authorizes a
    /// `Realm` target by the Realm *name* (`realm:<id>`), **not** by the inner `target` — trust
    /// composes at the Realm, the unit a peering decision is actually made at. Source-side caps do
    /// not gate intra-Realm targets; the receiving Sanctum's own local admission gate is the only
    /// check after the gateway unwraps. See `router::caps_allow`.
    Realm { realm: RealmId, target: Box<Address> },
    /// Federation: address `target` in [`Realm`](RealmId) `realm`, reached via Omega discovery
    /// (federation of Realms). Resolved by the bound [`Role::OMEGA_GATEWAY`] creature.
    /// `creatures/omega-federator` uses this
    /// address grain for real cross-Realm routing and anti-entropy.
    Omega { realm: RealmId, target: Box<Address> },
}

/// Maximum federation-wrapper nesting depth [`crate::Envelope::parse`] accepts. Federation
/// uses at most one wrapper (`Realm(_, Creature)`) or two (`Omega(_, Realm(_, _))`);
/// the ceiling is generous so a real multi-grain federation creature has headroom, while still
/// rejecting a pathological `Omega(Realm(Realm(…)))` before any gateway tries to unwrap it (R9
/// fabric-integrity floor). `serde_json` already bounds *parse* recursion at 128, so
/// this is a semantic ceiling the substrate owns — not a stack-overflow guard.
pub const MAX_ADDRESS_NESTING_DEPTH: usize = 8;

impl Address {
    /// Federation-wrapper nesting depth: how many [`Realm`](Self::Realm) / [`Omega`](Self::Omega)
    /// layers wrap the innermost identity/capability target. A non-federation address
    /// (Creature/Node/Kernel/Topic/Role/Intent) is depth 0; `Realm(_, Creature)` is depth 1;
    /// `Omega(_, Realm(_, Creature))` is depth 2. **Iterative** (no recursion) so computing it is
    /// itself safe on a hostile, deeply-wrapped input.
    pub fn nesting_depth(&self) -> usize {
        let mut depth = 0;
        let mut cur = self;
        while let Address::Realm { target, .. } | Address::Omega { target, .. } = cur {
            depth += 1;
            cur = target;
        }
        depth
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wrap(inner: Address, layers: usize) -> Address {
        let mut a = inner;
        for _ in 0..layers {
            a = Address::Realm { realm: RealmId::local(), target: Box::new(a) };
        }
        a
    }

    #[test]
    fn nesting_depth_counts_only_federation_wrappers() {
        assert_eq!(Address::Creature(CreatureId(1)).nesting_depth(), 0);
        assert_eq!(Address::Kernel.nesting_depth(), 0);
        assert_eq!(wrap(Address::Creature(CreatureId(1)), 1).nesting_depth(), 1);
        // Mixed Realm/Omega still counts every wrapper layer.
        let mixed = Address::Omega {
            realm: RealmId::local(),
            target: Box::new(wrap(Address::Creature(CreatureId(1)), 1)),
        };
        assert_eq!(mixed.nesting_depth(), 2);
    }

    #[test]
    fn nesting_depth_is_iterative_and_handles_deep_input_without_overflow() {
        // 10_000 wrappers — a recursive counter would blow the stack; the iterative one is fine.
        let deep = wrap(Address::Creature(CreatureId(1)), 10_000);
        assert_eq!(deep.nesting_depth(), 10_000);
    }
}
