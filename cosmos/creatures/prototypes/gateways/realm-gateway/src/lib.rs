//! `realm-gateway` — a **reference** Realm-gateway routing policy.
//!
//! A creature bound to `Role::REALM_GATEWAY` resolves [`Address::Realm`] envelopes by looking up the
//! peer mapped to the named [`RealmId`] and re-routing through the bus — `Node(peer, target)` so the
//! bound `Role::TRANSPORT` creature carries the envelope cross-Sanctum. This reference supplies that
//! **decision**; the envelope **mechanism** (the Realm→Node rewrite that preserves `reply_to` / `corr`
//! / `commitment` / `schema` / payload byte-for-byte, and the structured failure reply) is owned by
//! the [`realm`] crate via [`realm::serve`]. A loadable gateway is therefore just
//! `realm::serve(RealmGateway::new(cfg))`.
//!
//! ## What this policy decides
//!
//! - A single-peer-per-Realm `HashMap<RealmId, NodeId>` config.
//! - **Inner target = `Address::Creature(m)`**: [`RealmResolution::Forward`] to the mapped peer —
//!   `realm::serve` rewrites the destination to `Node(peer, m)` and preserves the rest.
//! - Inner target = anything else (Role/Topic/Intent/Realm/Omega): [`RealmResolution::NoRoute`]
//!   with [`UnsupportedTarget`](NoRealmRouteReason::UnsupportedTarget). A richer gateway can add
//!   nested-unwrap support without changing the socket.
//! - Unmapped Realm: [`NoRoute`](RealmResolution::NoRoute) with
//!   [`UnmappedRealm`](NoRealmRouteReason::UnmappedRealm).
//!
//! ## What this policy does NOT do
//!
//! - **No same-Sanctum same-Realm shortcut.** If `target` lives on *this* Sanctum, the operator
//!   addresses it directly (`Creature(m)` / `Role(…)`), not via `Realm(local, …)` — that's the
//!   semantic for `Address::Realm`: deliver via some *other* Sanctum in the named Realm.
//! - **No multi-peer selection.** A real Realm has many member Sanctums; a richer gateway can pick
//!   one (round-robin, weight, jurisdiction match). This reference maps one peer per Realm.
//! - **No retry / fan-out / inner-target rewrite.** Those need bus state and a destination shape
//!   beyond the single-peer `Forward(NodeId)` the [`realm::serve`] mechanism models; a gateway that
//!   wants them implements [`aether::Creature`] directly instead of going through `serve`.
//!
//! ## Fabric-not-model preserved
//!
//! Like every prototype in `cosmos/creatures/prototypes/`, this is the *model* an operator binds — never
//! substrate. The substrate ships the `Role::REALM_GATEWAY` socket; the `realm` crate owns the
//! invariant rewrite mechanism; this creature owns only the (replaceable) routing decision. Operators
//! may write their own `RealmRouting` (richer Realm-membership semantics) and `realm::serve` it
//! instead.

use std::collections::HashMap;

use aether::{Address, NodeId, RealmId};
// The `realm` concept crate owns the gateway seam — the structured `realm.no_route` wire
// contract, the `RealmRouting` decision trait, and the `serve` mechanism that turns a decision into a
// loadable creature. Re-export the wire types so consumers (and this creature's tests) can still name
// them via `realm_gateway::…`.
pub use realm::route::{NoRealmRouteReason, NoRealmRouteReply};
use realm::{RealmResolution, RealmRouting};

/// Construction config — the `realm → peer` table an operator wires up before
/// `realm::serve`-ing this policy into a loadable creature.
#[derive(Clone, Debug, Default)]
pub struct RealmGatewayConfig {
    /// `realm → peer` mapping. A single peer per Realm in this reference; richer gateways may grow
    /// to many.
    pub realm_to_peer: HashMap<RealmId, NodeId>,
}

impl RealmGatewayConfig {
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder-style add of one Realm→peer mapping.
    pub fn with(mut self, realm: RealmId, peer: NodeId) -> Self {
        self.realm_to_peer.insert(realm, peer);
        self
    }

    /// Builder-style bulk add of many Realm→peer mappings at once — for operators
    /// with N Realms, instead of chaining `.with(...)` N times. Accepts any iterable of pairs (a
    /// `Vec`, an array, a `HashMap`).
    pub fn with_many(mut self, mappings: impl IntoIterator<Item = (RealmId, NodeId)>) -> Self {
        self.realm_to_peer.extend(mappings);
        self
    }
}

/// The realm-gateway routing **policy**.
///
/// Stateless beyond its config: every decision is a pure function of the inbound realm + inner
/// target and the [`RealmGatewayConfig`] table — exactly the [`RealmRouting`] contract. Wrap it with
/// [`realm::serve`] to get a loadable creature; the crate-owned mechanism does the rest.
pub struct RealmGateway {
    cfg: RealmGatewayConfig,
}

impl Default for RealmGateway {
    /// An empty-config policy. An operator who `serve`s it with no `with(...)` mappings will see
    /// every Realm envelope come back as `UnmappedRealm`.
    fn default() -> Self {
        RealmGateway::new(RealmGatewayConfig::new())
    }
}

impl RealmGateway {
    pub fn new(cfg: RealmGatewayConfig) -> Self {
        RealmGateway { cfg }
    }
}

/// The realm-gateway's routing decision — the `realm` crate owns this seam and the
/// `serve` mechanism over it; this creature is one (operator-replaceable) implementation.
impl RealmRouting for RealmGateway {
    fn resolve(&self, realm: &RealmId, target: &Address) -> RealmResolution {
        match self.cfg.realm_to_peer.get(realm) {
            // Unmapped Realm → structured reply, never silent.
            None => RealmResolution::NoRoute(NoRealmRouteReason::UnmappedRealm),
            // Mapped, but only `Creature(m)` targets unwrap. Nested grain (Role, Topic, Intent,
            // another Realm/Omega) is honestly outside this reference gateway's scope.
            Some(peer) => match target {
                Address::Creature(_) => RealmResolution::Forward(peer.clone()),
                _ => RealmResolution::NoRoute(NoRealmRouteReason::UnsupportedTarget),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Creature, CreatureId};

    // The *decision* lives here (this creature's policy); the envelope *mechanism* (Realm→Node
    // rewrite, byte-preservation, no-route reply) is tested in the `realm` crate's `serve` tests.

    #[test]
    fn mapped_creature_target_forwards_to_the_mapped_peer() {
        let cfg = RealmGatewayConfig::new().with(RealmId::new("crew"), NodeId("node-b".into()));
        let gw = RealmGateway::new(cfg);
        let r = gw.resolve(&RealmId::new("crew"), &Address::Creature(CreatureId(42)));
        assert_eq!(r, RealmResolution::Forward(NodeId("node-b".into())));
    }

    #[test]
    fn unmapped_realm_resolves_to_no_route_unmapped() {
        let gw = RealmGateway::default(); // no peers mapped
        let r = gw.resolve(&RealmId::new("unknown"), &Address::Creature(CreatureId(7)));
        assert_eq!(r, RealmResolution::NoRoute(NoRealmRouteReason::UnmappedRealm));
    }

    #[test]
    fn mapped_non_creature_target_resolves_to_no_route_unsupported() {
        let cfg = RealmGatewayConfig::new().with(RealmId::new("crew"), NodeId("node-b".into()));
        let gw = RealmGateway::new(cfg);
        let r = gw.resolve(&RealmId::new("crew"), &Address::Role(aether::Role::new("policy")));
        assert_eq!(r, RealmResolution::NoRoute(NoRealmRouteReason::UnsupportedTarget));
    }

    #[test]
    fn with_many_bulk_adds_mappings() {
        let cfg = RealmGatewayConfig::new().with_many([
            (RealmId::new("a"), NodeId("na".into())),
            (RealmId::new("b"), NodeId("nb".into())),
        ]);
        let gw = RealmGateway::new(cfg);
        assert_eq!(
            gw.resolve(&RealmId::new("b"), &Address::Creature(CreatureId(1))),
            RealmResolution::Forward(NodeId("nb".into()))
        );
    }

    #[test]
    fn served_policy_is_a_loadable_creature_that_does_the_node_rewrite() {
        // The composition this crate exists to demonstrate: a gateway = `realm::serve(MyRouter)`.
        // (The exhaustive byte-preservation assertions live in the `realm` crate.)
        let cfg = RealmGatewayConfig::new().with(RealmId::new("crew"), NodeId("node-b".into()));
        let mut creature = realm::serve(RealmGateway::new(cfg));
        let env = aether::Envelope {
            header: aether::Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Realm {
                    realm: RealmId::new("crew"),
                    target: Box::new(Address::Creature(CreatureId(42))),
                },
                reply_to: Some(Address::Creature(CreatureId(99))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(5),
                commitment: None,
                schema: "test".into(),
            },
            payload: b"hello".to_vec(),
        };
        let d = &creature.handle(env).dispatches[0];
        assert_eq!(d.to, Address::Node(NodeId("node-b".into()), CreatureId(42)));
        assert_eq!(d.payload, b"hello");
    }
}
