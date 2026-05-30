//! realm — the GAWD **trust domain**.
//!
//! A **Realm** is a mesh of peer Sanctums that have chosen to trust one another — the grain at
//! which membership, peering, and shared policy are reasoned about above any single body. The
//! *address grain* `Address::Realm` lives in [`aether`], where the [`Router`] binds
//! it and dispatches a realm-addressed [`Envelope`] to the bound realm-gateway creature.
//!
//! **What this crate owns.** The realm-gateway **seam** *and the routing mechanism
//! over it*: the [`GATEWAY_ROLE`] socket, the structured [`route`] wire contract, the decision-only
//! [`RealmRouting`] trait, and [`serve`] — which wraps a `RealmRouting` policy into a loadable gateway
//! [`Creature`](aether::Creature), owning the invariant `Realm`→`Node` envelope rewrite (preserve
//! `reply_to` / `corr` / `commitment` / `schema` / payload). The gateway
//! *policy* stays injected (the `realm-gateway` creature — IoC); the crate owns the seam and
//! the mechanism, never the routing decision.
//!
//! **Still embryonic.** The realm-level *authority* the grain will ultimately answer to is
//! not built yet; the [`Realm`] newtype carries only identity today, a home that already exists so that
//! authority lands as growth rather than as a brand-new top-level concept later. The grain rule (see
//! the `omega` crate): **a Realm deals with its Sanctums; the Omega deals with Realms.** So the
//! authority that lands here is the per-Sanctum-within-this-Realm work — membership and peering (who
//! may join, what is shared), placing Abodes across *its* Sanctums, and routine backup of them —
//! leaving only the cross-Realm / separation cases to Ω. Layering:
//! `sigil → aether → {seer, abode, realm} → omega`.
//!
//! ```
//! use realm::{Realm, RealmId};
//! let r = Realm::new(RealmId::new("crew-of-the-mary-celeste"));
//! assert_eq!(r.id().0, "crew-of-the-mary-celeste");
//! ```
//!
//! [`aether`]: aether
//! [`Router`]: aether::Router
//! [`Envelope`]: aether::Envelope

use serde::{Deserialize, Serialize};

/// The realm identity — the address grain `aether` routes on (re-exported from there so a Realm and
/// its `Address::Realm { realm, .. }` name the *same* type, never two that drift).
pub use aether::RealmId;

/// The `Role` an injected realm-gateway binds. Named by the crate that owns the
/// concept, so an implementation references `realm::GATEWAY_ROLE` rather than a bare string — the
/// crate is the home the injected gateway answers to.
pub const GATEWAY_ROLE: &str = aether::Role::REALM_GATEWAY;

/// A trust domain: a named mesh of peer Sanctums.
///
/// **Embryo.** It carries identity today; realm-level membership, peering, and authority (who is in
/// the mesh, who may join, what is shared) land here as the federation thickens. The shape is
/// deliberately a thin newtype so adding fields later is
/// forward-compatible rather than a re-home.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Realm {
    id: RealmId,
}

impl Realm {
    /// Name a trust domain by its [`RealmId`].
    pub fn new(id: RealmId) -> Self {
        Self { id }
    }

    /// The realm's identity — the same grain `aether`'s router dispatches `Address::Realm` on.
    pub fn id(&self) -> &RealmId {
        &self.id
    }
}

// ---------------------------------------------------------------------------------------------
// The realm-gateway seam — the crate owns the contract an injected gateway fulfills.
// ---------------------------------------------------------------------------------------------

/// The structured **wire contract** a realm-gateway emits when it cannot deliver an `Address::Realm`
/// envelope. Owned by this crate (the seam), not by any one gateway creature, so a consumer parses a
/// routing failure by depending on `realm` — never on a specific gateway example.
pub mod route {
    use super::RealmId;
    use serde::{Deserialize, Serialize};

    /// Why a Realm envelope couldn't be delivered. Tagged on `kind` so an orchestrator dispatches on
    /// the variant, not on substring matches against free-form prose.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum NoRealmRouteReason {
        /// No peer is mapped for the named Realm.
        UnmappedRealm,
        /// The gateway only unwraps `Realm(R, Creature(m))` targets; a nested grain (Role, Topic,
        /// Intent, another Realm/Omega) is outside the reference gateway's scope.
        UnsupportedTarget,
    }

    /// Structured reply emitted when a Realm envelope can't be delivered.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct NoRealmRouteReply {
        pub reason: NoRealmRouteReason,
        /// The realm the envelope named — included verbatim so the requester can correlate by Realm,
        /// not just by corr.
        pub realm: RealmId,
        /// Optional human-readable elaboration. Elided from the wire when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub details: Option<String>,
    }

    impl NoRealmRouteReply {
        /// The wire schema string for a `realm.no_route` envelope — the contract a downstream
        /// orchestrator matches on.
        pub const SCHEMA: &'static str = "realm.no_route";

        /// Build a structured no-route reply for a `realm`/`reason`, filling a generic,
        /// gateway-agnostic `details` hint from the reason. Used by [`serve`](crate::serve) so the
        /// crate — not the injected router — owns the failure wire shape; an operator's richer
        /// gateway that wants bespoke prose constructs the struct directly.
        pub fn new(realm: RealmId, reason: NoRealmRouteReason) -> Self {
            let details = match &reason {
                NoRealmRouteReason::UnmappedRealm => {
                    format!("no peer is mapped for realm `{}`", realm.0)
                }
                NoRealmRouteReason::UnsupportedTarget => "a realm gateway forwards only \
                     `Realm(R, Creature(m))` targets; a nested grain (Role, Topic, Intent, \
                     another Realm/Omega) is unsupported"
                    .to_string(),
            };
            Self { reason, realm, details: Some(details) }
        }

        /// Serialize to the canonical bus bytes (`aether::wire`).
        pub fn to_bytes(&self) -> Vec<u8> {
            aether::wire::to_bytes(self)
        }
    }
}

/// The decision a [`RealmRouting`] gateway returns for one realm-addressed envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RealmResolution {
    /// Forward to this peer Sanctum: the gateway rewrites `Realm(realm, target)` → `Node(peer,
    /// target)` and the bound `Role::TRANSPORT` carries it cross-Sanctum.
    Forward(aether::NodeId),
    /// No route — reply with this structured reason ([`route::NoRealmRouteReason`]).
    NoRoute(route::NoRealmRouteReason),
}

/// The **realm-gateway seam**: the *policy* a creature bound to [`GATEWAY_ROLE`] supplies —
/// resolving an `Address::Realm { realm, target }` envelope to a forwarding decision. This is the
/// **decision only**; the *mechanism* (inspecting the envelope, rewriting the destination grain while
/// preserving the rest byte-for-byte, emitting the structured failure reply) is owned by the crate via
/// [`serve`]. Fabric/model: only the peer choice varies between gateways; the envelope mechanics do
/// not, so they belong to the fabric.
///
/// **IoC note.** The *runtime* injection is the bus + Role binding: the router
/// dispatches realm-addressed envelopes to whatever creature is bound to [`GATEWAY_ROLE`]. A creature
/// is built by wrapping a `RealmRouting` in [`serve`]; the reference `realm-gateway` does exactly that.
/// The crate owns the seam *and the mechanism*; the injected router owns only the routing policy.
pub trait RealmRouting {
    /// Resolve a realm-addressed envelope (its [`RealmId`] and inner `target` address) to a
    /// [`RealmResolution`]. A pure decision: no bus handle, no I/O — given the realm and inner target,
    /// where (if anywhere) does it go?
    fn resolve(&self, realm: &RealmId, target: &aether::Address) -> RealmResolution;
}

/// Wrap a [`RealmRouting`] policy into a loadable realm-gateway [`Creature`](aether::Creature).
///
/// **This is where the seam becomes load-bearing.** The crate owns the invariant *mechanism* — the
/// part a hand-written gateway repeatedly gets wrong (the commitment-drop class of bug):
///
/// - inspect the inbound envelope; only `Address::Realm { realm, target }` is ours (anything else is a
///   misbind or a racing in-flight envelope → `Outcome::none()`, never a crash);
/// - on [`Forward(peer)`](RealmResolution::Forward), rewrite the destination grain
///   `Realm(R, Creature(m))` → `Node(peer, m)` while **preserving `reply_to`, `corr`, `commitment`,
///   `schema`, and the payload bytes** — only the destination changes;
/// - on [`NoRoute(reason)`](RealmResolution::NoRoute), emit the structured
///   [`realm.no_route`](route::NoRealmRouteReply) reply back to the requester.
///
/// The injected `router` supplies only the [`resolve`](RealmRouting::resolve) decision. A gateway is
/// therefore just `realm::serve(MyRouter)`.
///
/// **When *not* to use `serve`.** The wrapper is pure-decision and stateless: its `bind` keeps no bus
/// handle or self-id. A gateway that needs to queue, retry on transport failure, fan a Realm out to
/// many peers, or rewrite the *inner* target implements [`Creature`](aether::Creature) directly — the
/// `Forward(NodeId)` shape deliberately models the single-peer preserve-and-forward case and nothing
/// more.
pub fn serve<R: RealmRouting + Send + 'static>(router: R) -> RealmGatewayCreature<R> {
    RealmGatewayCreature { router }
}

/// The [`Creature`](aether::Creature) [`serve`] builds around a [`RealmRouting`] policy — the crate's
/// envelope-preservation mechanism over an injected routing decision. Construct it via [`serve`].
pub struct RealmGatewayCreature<R> {
    router: R,
}

impl<R: RealmRouting + Send + 'static> aether::Creature for RealmGatewayCreature<R> {
    fn bind(&mut self, _ctx: aether::CreatureCtx) {
        // The served seam is pure-decision: `resolve` computes the forwarding decision from the
        // envelope alone, so the wrapper needs no bus handle or self-id. Stateful gateways (queue,
        // retry, membership consults) implement `Creature` directly instead of going through `serve`.
    }

    fn handle(&mut self, env: aether::Envelope) -> aether::Outcome {
        use aether::{Address, Dispatch, Outcome};

        // Only Realm-addressed envelopes are ours.
        let (realm, target) = match &env.header.to {
            Address::Realm { realm, target } => (realm.clone(), target.as_ref().clone()),
            _ => return Outcome::none(),
        };

        match self.router.resolve(&realm, &target) {
            RealmResolution::Forward(peer) => {
                // The seam's contract: `Forward` is only valid for a `Creature` inner target (the one
                // grain this single-peer rewrite knows how to express as `Node(peer, m)`). A router
                // that returns `Forward` for any other grain has violated the contract → no-op,
                // never a crash.
                let Address::Creature(m) = target else {
                    return Outcome::none();
                };
                // Rewrite Realm(R, Creature(m)) → Node(peer, m). Preserve reply_to (so the final
                // responder answers the *original* requester), corr (so the requester correlates),
                // schema, the payload bytes, and the commitment slot (a Realm envelope may carry a
                // commit-and-reveal payload the receiving Realm must verify). The bound
                // `Role::TRANSPORT` carries it cross-Sanctum.
                let reply_to = env.reply_target();
                let mut d = Dispatch::to(Address::Node(peer, m), env.payload)
                    .with_schema(env.header.schema)
                    .with_reply_to(reply_to);
                if let Some(corr) = env.header.corr {
                    d = d.with_corr(corr);
                }
                if let Some(commit) = env.header.commitment {
                    d = d.with_commitment(commit);
                }
                Outcome::send(d)
            }
            RealmResolution::NoRoute(reason) => {
                let reply = route::NoRealmRouteReply::new(realm, reason);
                Outcome::send(
                    Dispatch::reply_to_env(&env, reply.to_bytes())
                        .with_schema(route::NoRealmRouteReply::SCHEMA),
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_carries_its_identity_and_round_trips() {
        let r = Realm::new(RealmId::new("eu-west"));
        assert_eq!(r.id(), &RealmId::new("eu-west"));
        let bytes = serde_json::to_vec(&r).unwrap();
        let back: Realm = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn realm_id_is_aether_realm_id() {
        // The re-export must be the *same* type aether routes on — not a parallel definition.
        let _: aether::RealmId = RealmId::local();
    }

    // -- The `serve` mechanism ---------------------------------------------------------
    //
    // These exercise the crate-owned envelope plumbing — the invariant the seam lifts off every
    // gateway. The *decision* (`resolve`) is tested where the policy lives (the `realm-gateway`
    // creature); here a fixed `TestRouter` lets us assert the mechanism in isolation.

    use aether::{Address, Creature, CreatureId, Envelope, Header, NodeId};

    /// A router that returns a pre-set resolution regardless of input — isolates the `serve`
    /// mechanism from any real routing policy.
    struct TestRouter(RealmResolution);
    impl RealmRouting for TestRouter {
        fn resolve(&self, _realm: &RealmId, _target: &Address) -> RealmResolution {
            self.0.clone()
        }
    }

    fn realm_env(realm: &str, inner: Address, payload: &[u8]) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Realm { realm: RealmId::new(realm), target: Box::new(inner) },
                reply_to: Some(Address::Creature(CreatureId(99))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(5),
                commitment: None,
                schema: "test".into(),
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn serve_forward_rewrites_realm_to_node_preserving_reply_state() {
        // The crucial mechanism: Realm(crew, Creature(42)) → Node(peer, 42), with reply_to / corr /
        // schema / payload carried through byte-for-byte. Only the destination grain changes.
        let mut gw = serve(TestRouter(RealmResolution::Forward(NodeId("node-b".into()))));
        let out = gw.handle(realm_env("crew", Address::Creature(CreatureId(42)), b"hello"));
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        assert_eq!(d.to, Address::Node(NodeId("node-b".into()), CreatureId(42)));
        assert_eq!(d.corr, Some(5));
        assert_eq!(d.reply_to, Some(Address::Creature(CreatureId(99))));
        assert_eq!(d.schema, "test");
        assert_eq!(d.payload, b"hello");
    }

    #[test]
    fn serve_forward_carries_the_commitment_slot_across_the_rewrite() {
        // The bug class this mechanism exists to make impossible — a commit-and-reveal slot
        // dropped during the Realm→Node rewrite.
        let mut gw = serve(TestRouter(RealmResolution::Forward(NodeId("node-b".into()))));
        let mut env = realm_env("crew", Address::Creature(CreatureId(42)), b"hello");
        env.header.commitment = Some("commit-abc123".into());
        let d = &gw.handle(env).dispatches[0];
        assert_eq!(d.commitment.as_deref(), Some("commit-abc123"));
    }

    #[test]
    fn serve_no_route_emits_structured_reply_to_the_requester() {
        let mut gw =
            serve(TestRouter(RealmResolution::NoRoute(route::NoRealmRouteReason::UnmappedRealm)));
        let out = gw.handle(realm_env("unknown", Address::Creature(CreatureId(7)), b"x"));
        let d = &out.dispatches[0];
        assert_eq!(d.schema, "realm.no_route");
        assert_eq!(d.to, Address::Creature(CreatureId(99))); // back to reply_to
        assert_eq!(d.corr, Some(5));
        let reply: route::NoRealmRouteReply = serde_json::from_slice(&d.payload).unwrap();
        assert_eq!(reply.reason, route::NoRealmRouteReason::UnmappedRealm);
        assert_eq!(reply.realm, RealmId::new("unknown"));
        assert!(reply.details.is_some(), "serve fills a generic hint");
    }

    #[test]
    fn serve_non_realm_envelope_is_a_no_op() {
        // A misbind or in-flight non-Realm envelope: no-op, never a crash.
        let mut gw = serve(TestRouter(RealmResolution::Forward(NodeId("node-b".into()))));
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: String::new(),
            },
            payload: b"x".to_vec(),
        };
        assert!(gw.handle(env).dispatches.is_empty());
    }

    #[test]
    fn serve_forward_on_non_creature_target_is_a_defensive_no_op() {
        // Contract: `Forward` is only valid for a `Creature` inner target. A router that violates it
        // (here: Forward for a Role target) must not crash the gateway — `serve` no-ops.
        let mut gw = serve(TestRouter(RealmResolution::Forward(NodeId("node-b".into()))));
        let env = realm_env("crew", Address::Role(aether::Role::new("policy")), b"x");
        assert!(gw.handle(env).dispatches.is_empty());
    }

    #[test]
    fn no_realm_route_reply_new_fills_a_reason_specific_hint() {
        let unmapped = route::NoRealmRouteReply::new(
            RealmId::new("crew"),
            route::NoRealmRouteReason::UnmappedRealm,
        );
        assert!(unmapped.details.as_deref().unwrap().contains("crew"));
        let unsupported = route::NoRealmRouteReply::new(
            RealmId::local(),
            route::NoRealmRouteReason::UnsupportedTarget,
        );
        assert!(unsupported.details.as_deref().unwrap().contains("Creature"));
    }
}
