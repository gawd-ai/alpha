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
//! - The retained mapping table is bounded and shape-checked by default. Use
//!   [`RealmGateway::new_with_limit`] with `0` only for lab/demo setups that intentionally accept an
//!   unbounded table.
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

/// Default maximum Realm→peer mappings retained by this reference gateway.
pub const DEFAULT_MAX_REALM_GATEWAY_MAPPINGS: usize = 1024;
/// Maximum bytes in a Realm name retained by the gateway.
pub const MAX_REALM_GATEWAY_REALM_BYTES: usize = sigil::MAX_MANIFEST_REALM_BYTES;
/// Maximum bytes in a peer node id retained by the gateway.
pub const MAX_REALM_GATEWAY_NODE_ID_BYTES: usize = 256;

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
        insert_mapping(&mut self.realm_to_peer, realm, peer, DEFAULT_MAX_REALM_GATEWAY_MAPPINGS);
        self
    }

    /// Builder-style bulk add of many Realm→peer mappings at once — for operators
    /// with N Realms, instead of chaining `.with(...)` N times. Accepts any iterable of pairs (a
    /// `Vec`, an array, a `HashMap`).
    pub fn with_many(mut self, mappings: impl IntoIterator<Item = (RealmId, NodeId)>) -> Self {
        self = self.with_many_and_limit(mappings, DEFAULT_MAX_REALM_GATEWAY_MAPPINGS);
        self
    }

    /// Builder-style bulk add with an explicit retained mapping cap. `0` selects the explicit
    /// unbounded opt-out (lab/demo workloads only); production deployments MUST set a finite cap.
    /// (The unified escape-hatch convention — see `docs/design/substrate.md`.) Pair with
    /// [`RealmGateway::new_with_limit`] if the live gateway should also retain more than the default.
    pub fn with_many_and_limit(
        mut self,
        mappings: impl IntoIterator<Item = (RealmId, NodeId)>,
        max_mappings: usize,
    ) -> Self {
        for (realm, peer) in mappings {
            insert_mapping(&mut self.realm_to_peer, realm, peer, max_mappings);
        }
        self
    }

    /// Number of retained mappings, useful for tests and observability.
    pub fn mapping_count(&self) -> usize {
        self.realm_to_peer.len()
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
        Self::new_with_limit(cfg, DEFAULT_MAX_REALM_GATEWAY_MAPPINGS)
    }

    /// Build with an explicit retained mapping cap. `max_mappings == 0` disables the cap.
    pub fn new_with_limit(mut cfg: RealmGatewayConfig, max_mappings: usize) -> Self {
        cfg.realm_to_peer = retain_valid_mappings(cfg.realm_to_peer, max_mappings);
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

fn retain_valid_mappings(
    mappings: HashMap<RealmId, NodeId>,
    max_mappings: usize,
) -> HashMap<RealmId, NodeId> {
    let mut retained = HashMap::new();
    for (realm, peer) in mappings {
        insert_mapping(&mut retained, realm, peer, max_mappings);
    }
    retained
}

fn insert_mapping(
    mappings: &mut HashMap<RealmId, NodeId>,
    realm: RealmId,
    peer: NodeId,
    max_mappings: usize,
) {
    if let Some(reason) = mapping_shape_error(&realm, &peer) {
        eprintln!("realm-gateway: {reason}");
        return;
    }
    if max_mappings != 0 && !mappings.contains_key(&realm) && mappings.len() >= max_mappings {
        eprintln!(
            "realm-gateway: mapping table at capacity ({max_mappings}); refusing realm {}",
            realm.0
        );
        return;
    }
    mappings.insert(realm, peer);
}

fn mapping_shape_error(realm: &RealmId, peer: &NodeId) -> Option<String> {
    if !realm.is_valid() || realm.0.len() > MAX_REALM_GATEWAY_REALM_BYTES || realm.0.contains('\0')
    {
        return Some(format!(
            "realm must be valid, NUL-free, and <= {MAX_REALM_GATEWAY_REALM_BYTES} bytes"
        ));
    }
    if !node_id_shape_is_valid(peer) {
        return Some(format!(
            "peer node id must be 1..={MAX_REALM_GATEWAY_NODE_ID_BYTES} ASCII [A-Za-z0-9._-] bytes"
        ));
    }
    None
}

fn node_id_shape_is_valid(node: &NodeId) -> bool {
    let s = node.0.as_str();
    !s.is_empty()
        && s.len() <= MAX_REALM_GATEWAY_NODE_ID_BYTES
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
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
    fn config_builder_bounds_and_shape_checks_mappings() {
        let cfg = RealmGatewayConfig::new().with_many_and_limit(
            [
                (RealmId::new("crew"), NodeId("node-a".into())),
                (RealmId::new("guests"), NodeId("node-b".into())),
                (RealmId::new("bad:realm"), NodeId("node-c".into())),
                (RealmId::new("bad-nul\0"), NodeId("node-d".into())),
                (RealmId::new("bad-peer"), NodeId("bad peer".into())),
            ],
            1,
        );

        assert_eq!(cfg.mapping_count(), 1);
        let gw = RealmGateway::new(cfg);
        assert_eq!(
            gw.resolve(&RealmId::new("crew"), &Address::Creature(CreatureId(1))),
            RealmResolution::Forward(NodeId("node-a".into()))
        );
        assert_eq!(
            gw.resolve(&RealmId::new("guests"), &Address::Creature(CreatureId(1))),
            RealmResolution::NoRoute(NoRealmRouteReason::UnmappedRealm)
        );
    }

    #[test]
    fn gateway_new_sanitizes_direct_config_and_zero_limit_is_unbounded() {
        let mut direct = RealmGatewayConfig::new();
        direct.realm_to_peer.insert(RealmId::new("crew"), NodeId("node-a".into()));
        direct.realm_to_peer.insert(RealmId::new("bad:realm"), NodeId("node-b".into()));
        direct.realm_to_peer.insert(RealmId::new("bad-peer"), NodeId("bad peer".into()));

        let gw = RealmGateway::new(direct);
        assert_eq!(
            gw.resolve(&RealmId::new("crew"), &Address::Creature(CreatureId(1))),
            RealmResolution::Forward(NodeId("node-a".into()))
        );
        assert_eq!(
            gw.resolve(&RealmId::new("bad:realm"), &Address::Creature(CreatureId(1))),
            RealmResolution::NoRoute(NoRealmRouteReason::UnmappedRealm)
        );

        let cfg = RealmGatewayConfig::new().with_many_and_limit(
            [
                (RealmId::new("crew"), NodeId("node-a".into())),
                (RealmId::new("guests"), NodeId("node-b".into())),
            ],
            0,
        );
        let gw = RealmGateway::new_with_limit(cfg, 0);
        assert_eq!(
            gw.resolve(&RealmId::new("guests"), &Address::Creature(CreatureId(1))),
            RealmResolution::Forward(NodeId("node-b".into()))
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
                origin: None,
            },
            payload: b"hello".to_vec(),
        };
        let d = &creature.handle(env).dispatches[0];
        assert_eq!(d.to, Address::Node(NodeId("node-b".into()), CreatureId(42)));
        assert_eq!(d.payload, b"hello");
    }
}
