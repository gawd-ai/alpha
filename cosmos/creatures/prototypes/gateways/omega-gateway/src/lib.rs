//! `omega-gateway` — a **reference** Omega-gateway creature.
//!
//! The **Omega** is the federation of [`Realm`](aether::RealmId)s — the substrate's outermost address
//! grain. `creatures/omega-federator` is the real federation creature; this reference is a
//! stub that supplies **the shape, not the mechanism** (the address grain lands early so federation
//! does not retrofit every envelope path):
//!
//! This stub creature accepts any [`Address::Omega`] envelope and replies with a structured
//! `OmegaDeferred` payload — a wire commitment that says "the substrate received this
//! correctly; the federation mechanism is elsewhere." Orchestrators that want real federation bind
//! `creatures/omega-federator` (or their own Omega creature) on the
//! `Role::OMEGA_GATEWAY` socket and ignore this reference.
//!
//! ## Why a stub and not nothing
//!
//! Without a bound creature, `Address::Omega` envelopes would hit `RouteError::NoProvider`
//! and there would be no structured-reply contract to lock down. The stub
//! means: (a) the structured `OmegaDeferred` reply schema (`omega.deferred`) exists for
//! orchestrators to recognize; (b) integration tests can exercise the Omega dispatch path
//! end-to-end; (c) operators know exactly what socket to bind their real creature to.
//!
//! ## Fabric-not-model preserved
//!
//! Like every other prototype in `cosmos/creatures/prototypes/`, this is a *creature* the operator binds — never
//! substrate. The real federation creature uses the same shape, just a different implementation.
//! The substrate ships only the `Role::OMEGA_GATEWAY` socket and the [`Address::Omega`]
//! grain.

use aether::{Address, Creature, CreatureCtx, Dispatch, Envelope, Outcome};
// The `omega.deferred` wire contract is owned by the `omega` concept crate (the seam),
// not by this stub. Re-exported so consumers (and this stub's tests, and the
// `omega_stub_route` integration test) can still name them via `omega_gateway::…`.
pub use omega::deferred::{OmegaDeferredReason, OmegaDeferredReply};

// `OmegaDeferredReason` / `OmegaDeferredReply` live in `omega::deferred` —
// the concept crate owns the wire contract; they are re-exported above.

/// The stub creature.
///
/// Stateless — every Omega envelope produces the same structured `DeferredToV03` reply,
/// computed purely from the inbound envelope. A real federation creature that issues outbound
/// queries, tracks anti-entropy state, or talks to a discovery service will stash [`CreatureCtx`] in
/// [`bind`](Creature::bind); this stub does not.
pub struct OmegaGateway;

impl OmegaGateway {
    pub fn new() -> Self {
        OmegaGateway
    }
}

impl Default for OmegaGateway {
    fn default() -> Self {
        Self::new()
    }
}

impl Creature for OmegaGateway {
    fn bind(&mut self, _ctx: CreatureCtx) {
        // The stub is stateless; real federation creatures keep their own context.
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Only Omega-addressed envelopes are ours. Anything else (misbind, in-flight Creature
        // envelope) is a no-op — never a crash. Consistent with realm-gateway and the
        // round-robin distributor.
        let realm = match &env.header.to {
            Address::Omega { realm, .. } => realm.clone(),
            _ => return Outcome::none(),
        };

        // The stub's commitment: every Omega envelope gets a structured `DeferredToV03`
        // reply. No federation discovery, no routing, no silent drop. A real federation creature
        // replaces this entire body.
        let reply = OmegaDeferredReply {
            realm: realm.clone(),
            reason: OmegaDeferredReason::DeferredToV03,
            // Static hint — the target Realm is already the structured `realm` field above, so we
            // don't interpolate it again here (no duplication).
            details: Some(
                "omega-gateway is the historical v0.2 stub; bind omega-federator or your \
                 own federation creature on Role::OMEGA_GATEWAY to resolve Omega addresses \
                 (target Realm is in the `realm` field)"
                    .to_string(),
            ),
        };
        Outcome::send(
            Dispatch::reply_to_env(&env, reply.to_bytes()).with_schema(OmegaDeferredReply::SCHEMA),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{CreatureId, Header, RealmId};

    fn omega_env(realm: &str) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Omega {
                    realm: RealmId::new(realm),
                    target: Box::new(Address::Creature(CreatureId(42))),
                },
                reply_to: Some(Address::Creature(CreatureId(99))),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(11),
                commitment: None,
                schema: "ping".into(),
                origin: None,
            },
            payload: b"ping-body".to_vec(),
        }
    }

    #[test]
    fn every_omega_envelope_gets_a_structured_deferred_to_v03_reply() {
        let mut gw = OmegaGateway::new();
        let env = omega_env("global");
        let out = gw.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        assert_eq!(d.schema, "omega.deferred", "wire schema is the v0.2 commitment");
        // Reply goes back to the requester.
        assert_eq!(d.to, Address::Creature(CreatureId(99)));
        assert_eq!(d.corr, Some(11));
        let reply: OmegaDeferredReply = serde_json::from_slice(&d.payload).unwrap();
        assert_eq!(reply.realm, RealmId::new("global"));
        assert_eq!(reply.reason, OmegaDeferredReason::DeferredToV03);
        assert!(reply.details.is_some(), "include an operator hint");
    }

    #[test]
    fn non_omega_envelope_is_a_no_op() {
        // A misbind or in-flight envelope routed here: no-op, not a crash. Same discipline as
        // realm-gateway and the round-robin distributor.
        let mut gw = OmegaGateway::new();
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
                schema: "".into(),
                origin: None,
            },
            payload: b"x".to_vec(),
        };
        assert!(gw.handle(env).dispatches.is_empty());
    }

    #[test]
    fn deferred_reply_wire_round_trips_and_details_is_optional() {
        let reply = OmegaDeferredReply {
            realm: RealmId::new("global"),
            reason: OmegaDeferredReason::DeferredToV03,
            details: Some("note".into()),
        };
        let bytes = reply.to_bytes();
        let back: OmegaDeferredReply = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(back.realm, reply.realm);
        assert_eq!(back.reason, reply.reason);
        assert_eq!(back.details.as_deref(), Some("note"));

        let reply = OmegaDeferredReply {
            realm: RealmId::local(),
            reason: OmegaDeferredReason::DeferredToV03,
            details: None,
        };
        let wire = String::from_utf8(reply.to_bytes()).unwrap();
        assert!(!wire.contains("details"), "None elides");
    }
}
