//! aether — the GAWD bus: a **single logical spine**.
//!
//! One typed, signed, ordered [`Envelope`] carries *every* interaction — creature↔creature (local),
//! node↔node (remote = "route off-node"), kernel control, and telemetry — and the same object
//! travels the whole lifecycle (author→load→run→ship→publish). The [`Router`] owns a read-mostly
//! address table of per-creature **bounded inboxes** (backpressure, never OOM — R9), the IoC
//! **role-binding** table (capability addressing — R8), topic fan-out, and the history journal.
//!
//! Design invariants this crate enforces:
//! - **Same envelope local and remote** — transport is one more delivery case, not a subsystem (R4).
//! - **Trust primitives are structural** — `seq`/`stamp`/`sig`/`corr`/`commitment` are header
//!   fields, set by the fabric, present before any message (R5). A creature emits a [`Dispatch`]
//!   and cannot forge them.
//! - **The fabric ships sockets, not models** — `Intent`/`Role` route to a *bound* creature; with
//!   none bound the router returns `NoProvider` and supplies nothing of its own (lever 6 / R8).
//! - **No ambient global** — a creature's only authority is the [`BusHandle`] in its [`CreatureCtx`];
//!   there is no global ambient authority to reach for, which is also what makes a sandboxed beast real.

mod address;
mod bus;
mod envelope;
/// The native ABI seam (the C representation of [`Creature`]) — shared by the host loader
/// (`anima`) and the authoring SDK (`forge`).
pub mod ffi;
mod instance;
mod origin;
mod router;
/// Shared wire-serialization helpers (`to_bytes` / `to_value`) with a `debug_assert!` tripwire on
/// the cannot-happen serialize-failure path. The single disposition for the serialize-failure
/// path — see the module docs.
pub mod wire;

// `abode` (the distributed-self snapshot contract) and `seer`
// (the consult-and-reconcile primitive) are first-class top-level crates that depend
// on `aether`, not submodules of it. The federation *address grain* (`Address::Realm` /
// `Address::Omega`) stays here — the router binds it — while `realm` and `omega` carry the
// trust-domain and Ω authority above the bus.

pub use address::{
    node_role_capability_key, Address, CreatureId, Intent, NodeId, RealmId, Role, Topic,
    MAX_ADDRESS_NESTING_DEPTH,
};
pub use bus::{Bus, BusError, BusHandle, Ed25519Signer, Signer, StubSigner};
pub use envelope::{
    Envelope, EnvelopeError, Header, ENVELOPE_SIGNING_DOMAIN, MAX_ENVELOPE_HEADER_BYTES,
};
pub use instance::{
    BudgetSignal, BudgetVector, Creature, CreatureCtx, Deadline, Dispatch, LimitKind, Outcome,
    SignalLevel,
};
pub use origin::{Origin, OriginEvent, OriginVerdict, ORIGIN_EVENT_SCHEMA};
pub use router::{InboxReceiver, JournalEntry, RouteError, Router, KERNEL_ID};

/// Default maximum JSON payload size for high-volume sense-topic events.
///
/// The router bounds queues, but topic consumers still parse opaque payloads after delivery.
/// Proprioception, fitness, and budget-signal consumers use this cap before JSON decode so a
/// directly addressed or fanned-out sense event cannot force unbounded allocation in an observer
/// or policy creature. Larger artifacts and registry operations have their own domain limits.
pub const MAX_SENSE_EVENT_BYTES: usize = 1024 * 1024;

// One trust vocabulary across the workspace: the verify mechanism lives in the contract crate.
pub use sigil::{Ed25519KeyMaterial, Ed25519Verifier, StubVerifier, Verifier};

#[cfg(test)]
mod tests {
    use super::*;
    use sigil::Capabilities;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn router() -> Arc<Router> {
        Arc::new(Router::new(Arc::new(StubVerifier), 16))
    }
    fn bus(r: &Arc<Router>, me: CreatureId) -> BusHandle {
        BusHandle::new(me, r.clone(), Arc::new(StubSigner::new("test")))
    }
    fn nested_realm_address(layers: usize) -> Address {
        let mut a = Address::Creature(CreatureId(7));
        for _ in 0..layers {
            a = Address::Realm { realm: RealmId::local(), target: Box::new(a) };
        }
        a
    }

    #[derive(Default)]
    struct CountingSigner {
        calls: AtomicUsize,
    }

    impl Signer for CountingSigner {
        fn sign(&self, _payload: &[u8]) -> String {
            self.calls.fetch_add(1, Ordering::SeqCst);
            "counted".to_string()
        }
        fn public_key(&self) -> String {
            "counting-signer".to_string()
        }
    }

    #[test]
    fn delivers_creature_addressed_and_seals_fabric_fields() {
        let r = router();
        let (target, rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        b.send(Dispatch::to(Address::Creature(target), b"abc".to_vec())).unwrap();
        let env = rx.recv().unwrap();
        assert_eq!(env.payload, b"abc");
        assert_eq!(env.header.from, Address::Creature(sender)); // fabric-set identity
        assert!(!env.header.sig.is_empty()); // sig present (R5)
        assert!(env.header.stamp > 0); // router-set logical time
        assert_eq!(env.header.origin, None, "an ordinary send carries no cross-node origin");
    }

    #[test]
    fn an_ordinary_handle_cannot_attest_a_cross_node_origin() {
        // Forging a cross-node origin is structurally impossible for a normal creature: `Dispatch`
        // can't express one, and the only door — `emit_attested` — refuses on a non-attesting
        // handle. So a local creature can never make a recipient believe a message came from a peer.
        let r = router();
        let (_target, _rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        assert!(!b.may_attest(), "the default handle has no attestation grant");
        let denied = b.emit_attested(
            Dispatch::to(Address::Creature(_target), b"forge".to_vec()),
            Origin::node(NodeId("victim-node".into())),
        );
        assert!(matches!(denied, Err(BusError::Denied)), "non-attesting emit_attested is refused");
    }

    #[test]
    fn an_attesting_handle_seals_the_origin_into_the_signed_envelope() {
        // The transport's grant (`new_attesting`) is the one handle that may stamp origin. The
        // origin reaches the recipient *and* rides inside the signed bytes — re-signing the
        // delivered envelope reproduces its `sig`, but doing so after clearing `origin` does not.
        let r = router();
        let (target, rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let signer = Arc::new(StubSigner::new("transport"));
        let b = BusHandle::new_attesting(sender, r.clone(), signer.clone());
        assert!(b.may_attest());

        let origin = Origin::node(NodeId("node-A".into()));
        b.emit_attested(Dispatch::to(Address::Creature(target), b"hi".to_vec()), origin.clone())
            .unwrap();
        let env = rx.recv().unwrap();
        assert_eq!(
            env.header.origin,
            Some(origin),
            "the authenticated origin reached the recipient"
        );

        // `origin` is covered by the signature: the present sig matches signing_payload with origin,
        // and a tampered (origin-stripped) view would not reproduce it.
        assert_eq!(signer.sign(&env.signing_payload()), env.header.sig);
        let mut stripped = env.clone();
        stripped.header.origin = None;
        assert_ne!(
            signer.sign(&stripped.signing_payload()),
            env.header.sig,
            "clearing origin must change the signed bytes — origin is inside the signature"
        );
    }

    #[test]
    fn remote_role_resolution_requires_both_host_exposure_and_the_attesting_grant() {
        let r = router();
        let (first, _first_rx) = r.register(Capabilities::default());
        let (second, _second_rx) = r.register(Capabilities::default());
        let (ordinary_id, _ordinary_rx) = r.register(Capabilities::default());
        let (transport_id, _transport_rx) = r.register(Capabilities::default());
        let role = Role::new("executor");
        let ordinary = bus(&r, ordinary_id);
        let attesting = BusHandle::new_attesting(
            transport_id,
            r.clone(),
            Arc::new(StubSigner::new("transport")),
        );

        r.bind_role(role.clone(), first);
        assert_eq!(ordinary.remote_role_target(&role), None);
        assert_eq!(attesting.remote_role_target(&role), None, "local binding is not exposed");

        r.bind_remote_role(role.clone(), first);
        assert_eq!(
            ordinary.remote_role_target(&role),
            None,
            "ordinary creatures cannot inspect it"
        );
        assert_eq!(attesting.remote_role_target(&role), Some(first));

        r.bind_role(role.clone(), second);
        assert_eq!(
            attesting.remote_role_target(&role),
            None,
            "an ordinary rebind clears prior exposure rather than inheriting it"
        );
        r.bind_remote_role(role.clone(), second);
        assert_eq!(attesting.remote_role_target(&role), Some(second));
        r.deregister(second);
        assert_eq!(attesting.remote_role_target(&role), None, "unload revokes exposure");
    }

    #[test]
    fn local_verify_on_route_is_real_once_a_node_identity_is_set() {
        // The router's verify-on-delivery used to always run against an empty key (a no-op negative
        // branch). With a node identity, `public_key_of` resolves the local sender's key, so a
        // genuine ed25519 signature actually verifies — and an absent identity demonstrably does not.
        use std::sync::Mutex;
        struct Recording {
            inner: Ed25519Verifier,
            last: Mutex<Option<(String, bool)>>,
        }
        impl Verifier for Recording {
            fn verify(&self, pk: &str, payload: &[u8], sig: &str) -> bool {
                let ok = self.inner.verify(pk, payload, sig);
                *self.last.lock().unwrap() = Some((pk.to_string(), ok));
                ok
            }
        }

        let key = Ed25519KeyMaterial::from_seed([7u8; 32]).unwrap();

        // With the identity set: the local pubkey is resolved and the real signature verifies.
        let rec = Arc::new(Recording { inner: Ed25519Verifier, last: Mutex::new(None) });
        let r = Arc::new(Router::new(rec.clone(), 16));
        r.set_local_pubkey(key.public_hex().to_string());
        let (target, rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let b = BusHandle::new(sender, r.clone(), Arc::new(Ed25519Signer::new(key.clone())));
        b.send(Dispatch::to(Address::Creature(target), b"payload".to_vec())).unwrap();
        rx.recv().unwrap();
        let (pk, ok) = rec.last.lock().unwrap().clone().expect("verify was invoked");
        assert_eq!(
            pk,
            key.public_hex(),
            "router resolves the local node pubkey for a local sender"
        );
        assert!(ok, "a genuine local signature verifies under the resolved key");

        // Without the identity: the key is empty and the same genuine signature cannot verify —
        // proving the resolution is load-bearing, not incidental.
        let rec2 = Arc::new(Recording { inner: Ed25519Verifier, last: Mutex::new(None) });
        let r2 = Arc::new(Router::new(rec2.clone(), 16));
        let (target2, rx2) = r2.register(Capabilities::default());
        let (sender2, _s2) = r2.register(Capabilities::default());
        let b2 = BusHandle::new(sender2, r2.clone(), Arc::new(Ed25519Signer::new(key)));
        b2.send(Dispatch::to(Address::Creature(target2), b"payload".to_vec())).unwrap();
        rx2.recv().unwrap();
        let (pk2, ok2) = rec2.last.lock().unwrap().clone().expect("verify was invoked");
        assert_eq!(pk2, "", "no node identity → no resolvable local key");
        assert!(!ok2, "an empty key cannot verify a real signature");
    }

    #[test]
    fn oversized_headers_are_refused_before_signing_or_journaling() {
        let r = router();
        let (target, _rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let signer = Arc::new(CountingSigner::default());
        let b = BusHandle::new(sender, r.clone(), signer.clone());

        let err = b
            .send(
                Dispatch::to(Address::Creature(target), Vec::new())
                    .with_schema("x".repeat(MAX_ENVELOPE_HEADER_BYTES + 1)),
            )
            .unwrap_err();

        assert!(
            matches!(
                err,
                RouteError::HeaderTooLarge {
                    len,
                    limit
                } if len > MAX_ENVELOPE_HEADER_BYTES && limit == MAX_ENVELOPE_HEADER_BYTES
            ),
            "oversized header rejected with the dedicated route error: {err:?}"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0, "oversized header was not signed");
        assert!(
            r.journal_snapshot().is_empty(),
            "oversized header was not retained in the journal"
        );
    }

    #[test]
    fn overdeep_federation_addresses_are_refused_before_signing_or_gateway_delivery() {
        let r = router();
        let (realm_gw, realm_rx) = r.register(Capabilities::default());
        r.bind_role(Role::new(Role::REALM_GATEWAY), realm_gw);
        let (sender, _s) = r.register(Capabilities::default());
        let signer = Arc::new(CountingSigner::default());
        let b = BusHandle::new(sender, r.clone(), signer.clone());

        let err = b
            .send(Dispatch::to(nested_realm_address(MAX_ADDRESS_NESTING_DEPTH + 1), Vec::new()))
            .unwrap_err();

        assert!(
            matches!(
                err,
                RouteError::TooDeep {
                    depth,
                    max
                } if depth == MAX_ADDRESS_NESTING_DEPTH + 1 && max == MAX_ADDRESS_NESTING_DEPTH
            ),
            "overdeep destination rejected with the dedicated route error: {err:?}"
        );
        assert_eq!(signer.calls.load(Ordering::SeqCst), 0, "overdeep header was not signed");
        assert!(
            realm_rx.try_recv().is_err(),
            "overdeep federation address was not delivered to the gateway"
        );
        assert!(r.journal_snapshot().is_empty(), "overdeep header was not retained in the journal");
    }

    #[test]
    fn direct_route_rejects_overdeep_from_endpoint_before_delivery() {
        let r = router();
        let (target, rx) = r.register(Capabilities::default());
        let env = Envelope {
            header: Header {
                from: nested_realm_address(MAX_ADDRESS_NESTING_DEPTH + 1),
                to: Address::Creature(target),
                reply_to: None,
                seq: 0,
                causal: Vec::new(),
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: String::new(),
                origin: None,
            },
            payload: Vec::new(),
        };

        let err = r.route(env).unwrap_err();
        assert!(
            matches!(err, RouteError::TooDeep { depth, max }
                if depth == MAX_ADDRESS_NESTING_DEPTH + 1 && max == MAX_ADDRESS_NESTING_DEPTH),
            "overdeep source rejected with the dedicated route error: {err:?}"
        );
        assert!(rx.try_recv().is_err(), "overdeep source envelope was not delivered");
        assert!(
            r.journal_snapshot().is_empty(),
            "overdeep source envelope was not retained in the journal"
        );
    }

    #[test]
    fn seq_is_per_sender_monotone_and_stamp_advances() {
        let r = router();
        let (target, rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        b.send(Dispatch::to(Address::Creature(target), b"1".to_vec())).unwrap();
        b.send(Dispatch::to(Address::Creature(target), b"2".to_vec())).unwrap();
        let e1 = rx.recv().unwrap();
        let e2 = rx.recv().unwrap();
        assert_eq!(e1.header.seq, 0);
        assert_eq!(e2.header.seq, 1); // per-sender monotone order
        assert!(e2.header.stamp > e1.header.stamp); // logical clock advances (change of state)
    }

    #[test]
    fn unbound_role_and_intent_return_no_provider() {
        let r = router();
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        // no resolver bound → the fabric supplies no model (R8 / lever 6).
        let err =
            b.send(Dispatch::to(Address::Intent(Intent::default()), b"".to_vec())).unwrap_err();
        assert!(matches!(err, RouteError::NoProvider(_)));
        let err =
            b.send(Dispatch::to(Address::Role(Role::new("nobody")), b"".to_vec())).unwrap_err();
        assert!(matches!(err, RouteError::NoProvider(_)));
    }

    /// The federation grains (`Realm`, `Omega`) route to their
    /// bound gateway creature, same one-line dispatch as `Node → Transport` and `Intent →
    /// Distributor`. Unbound → `NoProvider` (the fabric supplies no federation model). This is the
    /// same IoC discipline (R8) extended to federation depth.
    #[test]
    fn unbound_realm_and_omega_gateways_return_no_provider() {
        let r = router();
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        let err = b
            .send(Dispatch::to(
                Address::Realm {
                    realm: RealmId::new("test"),
                    target: Box::new(Address::Creature(CreatureId(7))),
                },
                b"x".to_vec(),
            ))
            .unwrap_err();
        assert!(matches!(err, RouteError::NoProvider(_)));
        let err = b
            .send(Dispatch::to(
                Address::Omega {
                    realm: RealmId::new("any"),
                    target: Box::new(Address::Role(Role::new("anything"))),
                },
                b"x".to_vec(),
            ))
            .unwrap_err();
        assert!(matches!(err, RouteError::NoProvider(_)));
    }

    /// `Realm` and `Omega` envelopes route to their bound gateway creature; the
    /// inner `target` rides intact for the gateway to unwrap. Symmetrical with `Intent →
    /// Distributor`: the router dispatches once; the bound creature owns the resolution model.
    #[test]
    fn realm_and_omega_route_to_their_bound_gateways() {
        let r = router();
        let (realm_gw, realm_rx) = r.register(Capabilities::default());
        let (empy_gw, empy_rx) = r.register(Capabilities::default());
        r.bind_role(Role::new(Role::REALM_GATEWAY), realm_gw);
        r.bind_role(Role::new(Role::OMEGA_GATEWAY), empy_gw);
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        // Realm envelope → realm-gateway, inner target preserved verbatim.
        let to_realm = Address::Realm {
            realm: RealmId::new("crew"),
            target: Box::new(Address::Creature(CreatureId(42))),
        };
        b.send(Dispatch::to(to_realm.clone(), b"hello-realm".to_vec())).unwrap();
        let env = realm_rx.recv().unwrap();
        assert_eq!(
            env.header.to, to_realm,
            "router preserves the full Realm address for the gateway to unwrap"
        );
        assert_eq!(env.payload, b"hello-realm");
        // Omega envelope → omega-gateway, identical discipline.
        let to_empy = Address::Omega {
            realm: RealmId::new("federation"),
            target: Box::new(Address::Creature(CreatureId(99))),
        };
        b.send(Dispatch::to(to_empy.clone(), b"hello-empy".to_vec())).unwrap();
        let env = empy_rx.recv().unwrap();
        assert_eq!(env.header.to, to_empy);
        assert_eq!(env.payload, b"hello-empy");
    }

    #[test]
    fn node_role_routes_to_transport_without_local_resolution() {
        let r = router();
        let (transport, transport_rx) = r.register(Capabilities::default());
        r.bind_role(Role::new(Role::TRANSPORT), transport);
        let (sender, _sender_rx) = r.register(Capabilities::default());
        let target = Address::NodeRole(NodeId("peer-b".into()), Role::new("executor"));

        bus(&r, sender).send(Dispatch::to(target.clone(), b"work".to_vec())).unwrap();

        let envelope = transport_rx.recv().unwrap();
        assert_eq!(envelope.header.to, target, "transport receives the unresolved capability");
        assert_eq!(envelope.payload, b"work");
    }

    /// Wire-format round-trip for every `Address` variant,
    /// including the federation grains. The Realm/Omega shapes serialize symmetrically with
    /// the identity/capability variants: same envelope, more depth (composition by depth, not a new wire format —
    /// S5 mitigation). Inner `target` is a `Box<Address>` so a federation envelope
    /// can name any destination — Creature / Node / Role / Intent / Topic / Kernel — inside the
    /// named Realm. This test catches a future field change that would silently break federation
    /// envelopes (e.g. dropping `target` from serialization or renaming `realm`).
    #[test]
    fn every_address_variant_round_trips_through_json_including_federation_grains() {
        use serde_json;
        let cases: Vec<Address> = vec![
            Address::Creature(CreatureId(7)),
            Address::Node(NodeId("peer".into()), CreatureId(7)),
            Address::NodeRole(NodeId("peer".into()), Role::new("executor")),
            Address::Kernel,
            Address::Topic(Topic::new("proprio")),
            Address::Role(Role::new("distributor")),
            Address::Intent(Intent {
                outcome: "reverse".into(),
                requirements: vec!["cpu_at_least:1".into()],
            }),
            // The federation grains. Inner target spans the identity/capability grains so the box-of-address
            // composition is exercised end-to-end (not just the trivial Creature-inside-Realm case).
            Address::Realm {
                realm: RealmId::new("crew-of-the-mary-celeste"),
                target: Box::new(Address::Creature(CreatureId(11))),
            },
            Address::Realm {
                realm: RealmId::local(),
                target: Box::new(Address::Role(Role::new("policy"))),
            },
            Address::Omega {
                realm: RealmId::new("eu-west"),
                target: Box::new(Address::Node(NodeId("peer-b".into()), CreatureId(3))),
            },
            // Nesting: Omega wrapping a Realm wrapping a Creature — pathological but a real
            // federation may compose grains. Wire round-trip must survive.
            Address::Omega {
                realm: RealmId::new("global"),
                target: Box::new(Address::Realm {
                    realm: RealmId::new("local-cluster"),
                    target: Box::new(Address::Creature(CreatureId(5))),
                }),
            },
        ];
        for a in &cases {
            let bytes = serde_json::to_vec(a).expect("serialize");
            let back: Address = serde_json::from_slice(&bytes).expect("deserialize");
            assert_eq!(*a, back, "round-trip failed for {a:?}");
        }
    }

    #[test]
    fn node_role_is_additive_without_changing_the_existing_node_wire() {
        assert_eq!(
            serde_json::to_string(&Address::Node(NodeId("peer".into()), CreatureId(7))).unwrap(),
            r#"{"Node":["peer",7]}"#,
            "the shipped numeric Node representation remains byte-identical"
        );
        assert_eq!(
            serde_json::to_string(&Address::NodeRole(NodeId("peer".into()), Role::new("executor")))
                .unwrap(),
            r#"{"NodeRole":["peer","executor"]}"#
        );
    }

    #[test]
    fn intent_routes_to_the_bound_distributor() {
        let r = router();
        let (resolver, rrx) = r.register(Capabilities::default());
        r.bind_role(Role::new(Role::DISTRIBUTOR), resolver);
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        b.send(Dispatch::to(
            Address::Intent(Intent { outcome: "reverse".into(), requirements: vec![] }),
            b"hi".to_vec(),
        ))
        .unwrap();
        let env = rrx.recv().unwrap(); // delivered to the bound resolver
        assert!(matches!(env.header.to, Address::Intent(_)));
        assert_eq!(env.payload, b"hi");
    }

    #[test]
    fn deregister_makes_routing_fail_cleanly_not_ub() {
        let r = router();
        let (target, rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        r.deregister(target);
        drop(rx);
        let err = b.send(Dispatch::to(Address::Creature(target), b"x".to_vec())).unwrap_err();
        assert!(matches!(err, RouteError::NoSuchModule(_)));
    }

    #[test]
    fn bounded_inbox_sheds_on_flood_without_blocking_or_oom() {
        let r = Arc::new(Router::new(Arc::new(StubVerifier), 4)); // tiny inbox
        let (target, _rx) = r.register(Capabilities::default()); // never drained
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        let mut backpressured = false;
        for _ in 0..1000 {
            match b.send(Dispatch::to(Address::Creature(target), vec![0u8; 8])) {
                Ok(()) => {}
                Err(RouteError::Backpressure(_)) => backpressured = true,
                other => panic!("unexpected: {other:?}"),
            }
        }
        // A flood into a bounded inbox sheds via Backpressure — it never grows unbounded.
        assert!(backpressured);
    }

    #[test]
    fn envelope_round_trips_through_bytes_for_off_node() {
        // R4: local and remote use the SAME envelope type; remote is "serialize at the boundary."
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: None,
                seq: 7,
                causal: vec![],
                stamp: 9,
                sig: "stub:abc".into(),
                corr: Some(42),
                commitment: None,
                schema: "text".into(),
                origin: None,
            },
            payload: b"payload".to_vec(),
        };
        let bytes = env.to_bytes();
        let back = Envelope::parse(&bytes).unwrap();
        assert_eq!(back.payload, env.payload);
        assert_eq!(back.header.seq, 7);
        assert_eq!(back.header.corr, Some(42));
    }

    #[test]
    fn malformed_envelope_bytes_error_without_panic() {
        assert!(Envelope::parse(b"{garbage").is_err());
        assert!(Envelope::parse(&[0xff, 0xfe]).is_err());
    }

    #[test]
    fn verify_is_invoked_on_delivery() {
        struct Counting(AtomicUsize);
        impl Verifier for Counting {
            fn verify(&self, _k: &str, _p: &[u8], _s: &str) -> bool {
                self.0.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
        let v = Arc::new(Counting(AtomicUsize::new(0)));
        let r = Arc::new(Router::new(v.clone(), 16));
        let (target, rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let b = BusHandle::new(sender, r.clone(), Arc::new(StubSigner::new("k")));
        b.send(Dispatch::to(Address::Creature(target), b"x".to_vec())).unwrap();
        let _ = rx.recv().unwrap();
        // The verify mechanism must be invoked on delivery (R5) — the model decides what to do.
        assert!(v.0.load(Ordering::Relaxed) >= 1);
    }

    #[test]
    fn topic_fan_out_reaches_all_subscribers() {
        let r = router();
        let (a, arx) = r.register(Capabilities::default());
        let (c, crx) = r.register(Capabilities::default());
        let t = Topic::new(Topic::PROPRIOCEPTION);
        r.subscribe(t.clone(), a);
        r.subscribe(t.clone(), c);
        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        b.send(Dispatch::to(Address::Topic(t), b"alive".to_vec())).unwrap();
        assert_eq!(arx.recv().unwrap().payload, b"alive");
        assert_eq!(crx.recv().unwrap().payload, b"alive");
    }

    #[test]
    fn duplicate_topic_subscribe_is_idempotent() {
        let r = router();
        let (a, arx) = r.register(Capabilities::default());
        let t = Topic::new(Topic::PROPRIOCEPTION);
        r.subscribe(t.clone(), a);
        r.subscribe(t.clone(), a);
        r.subscribe(t.clone(), a);

        let (sender, _s) = r.register(Capabilities::default());
        let b = bus(&r, sender);
        b.send(Dispatch::to(Address::Topic(t), b"once".to_vec())).unwrap();

        assert_eq!(arx.recv().unwrap().payload, b"once");
        assert!(
            matches!(arx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)),
            "duplicate subscribe should not duplicate fan-out deliveries"
        );
    }

    #[test]
    fn subscribe_past_max_topics_is_refused_but_existing_still_accept() {
        // ADR-0037: bound the distinct-topic table (defense-in-depth; subscribe is host-only).
        let r = Arc::new(Router::new(Arc::new(StubVerifier), 16).with_max_topics(2));
        let (a, _arx) = r.register(Capabilities::default());
        let (b, _brx) = r.register(Capabilities::default());
        r.subscribe(Topic::new("t1"), a);
        r.subscribe(Topic::new("t2"), a);
        // Table is at the cap of 2 distinct topics — a third *new* topic is refused.
        r.subscribe(Topic::new("t3"), a);
        assert!(r.has_subscribers(&Topic::new("t1")));
        assert!(r.has_subscribers(&Topic::new("t2")));
        assert!(!r.has_subscribers(&Topic::new("t3")), "new topic past cap must be refused");
        // An *existing* topic still accepts a new subscriber even at the cap.
        r.subscribe(Topic::new("t1"), b);
        assert!(r.has_subscribers(&Topic::new("t1")));
    }

    #[test]
    fn max_topics_zero_is_unbounded_opt_out() {
        // ADR-0042 escape-hatch convention: 0 disables the cap (lab/demo posture).
        let r = Arc::new(Router::new(Arc::new(StubVerifier), 16).with_max_topics(0));
        let (a, _arx) = r.register(Capabilities::default());
        for i in 0..50 {
            r.subscribe(Topic::new(format!("t{i}")), a);
        }
        assert!(r.has_subscribers(&Topic::new("t49")));
    }

    /// `Ed25519Signer` plugs into the `Signer` slot the same way `StubSigner` does — proving
    /// the stub→real swap is a *configuration* change, not a shape change. The signature sealed
    /// onto the envelope verifies under the matching `Ed25519Verifier`+pubkey, so any consumer that
    /// knows the sender's Abode key can prove authorship.
    ///
    /// **What this test deliberately does *not* assert:** that `Router`'s verify-on-every-route
    /// path *succeeds* under real ed25519. The router's `public_key_of(from)` is currently a stub
    /// returning `""`, so router-side verify-on-delivery exercises the verifier's
    /// negative branch and would always fail to validate under real crypto. Teaching the router to
    /// resolve each `CreatureId` → its Abode pubkey is **deferred to the cross-node membership work**.
    /// What matters — and is tested under `m2_two_node` — is that the **transport** does the
    /// real handshake against the peer's known pubkey, and that **admission** verifies the manifest
    /// `provenance.signature` against the declared `provenance.author` (an Abode key). Those are
    /// the load-bearing trust gates; envelope-sig-on-every-route stays present-but-stub-verified.
    #[test]
    fn ed25519_signer_seals_a_sig_that_verifies_under_its_own_pubkey() {
        let material = Ed25519KeyMaterial::from_seed([9u8; 32]).unwrap();
        let pk_hex = material.public_hex().to_string();
        let signer = Arc::new(Ed25519Signer::new(material));
        let r = router(); // uses the StubVerifier — see above
        let (target, rx) = r.register(Capabilities::default());
        let (sender, _s) = r.register(Capabilities::default());
        let b = BusHandle::new(sender, r.clone(), signer);
        b.send(Dispatch::to(Address::Creature(target), b"abc".to_vec())).unwrap();
        let env = rx.recv().unwrap();
        // The sealed sig is real ed25519 over the envelope's signing payload, valid under the
        // signer's own pubkey — what a properly-wired verifier (with the pubkey resolved) would
        // confirm. The router-side verifier is the stub, deliberately.
        assert!(!env.header.sig.is_empty());
        let v = Ed25519Verifier;
        assert!(v.verify(&pk_hex, &env.signing_payload(), &env.header.sig));
        // and a tampered payload fails verification — the structural property we care about
        let mut tampered = env.clone();
        tampered.payload = b"xyz".to_vec();
        assert!(!v.verify(&pk_hex, &tampered.signing_payload(), &tampered.header.sig));
    }

    /// `Capabilities.calls` is the *bus-level* capability gate at the one
    /// router choke point. This pair locks the
    /// gate's behavior: allowed destinations pass; disallowed destinations return
    /// [`RouteError::Denied`]; `"*"` is the explicit wildcard; empty `calls` means unrestricted
    /// (the dev default — opt-in, never imposed).
    #[test]
    fn calls_capability_denies_unlisted_destinations_and_permits_listed() {
        let r = router();
        let (allowed_target, allowed_rx) = r.register(Capabilities::default());
        let (forbidden_target, _frx) = r.register(Capabilities::default());
        let allowed_addr = format!("creature:{}", allowed_target.0);
        // The sender's caps allowlist names only `allowed_target` — the call-gate must shut the
        // other addresses, even ones held by registered creatures.
        let restricted = Capabilities { calls: vec![allowed_addr], ..Capabilities::default() };
        let (sender, _s) = r.register(restricted);
        let b = bus(&r, sender);
        // allowed: passes the gate, delivered.
        b.send(Dispatch::to(Address::Creature(allowed_target), b"ok".to_vec())).unwrap();
        assert_eq!(allowed_rx.recv().unwrap().payload, b"ok");
        // disallowed: the one bus-level choke point rejects with Denied — before any delivery.
        let err = b
            .send(Dispatch::to(Address::Creature(forbidden_target), b"nope".to_vec()))
            .unwrap_err();
        assert!(matches!(err, RouteError::Denied { from } if from == sender));
    }

    #[test]
    fn calls_capability_wildcard_admits_every_destination() {
        let r = router();
        let (a, arx) = r.register(Capabilities::default());
        let (b_id, brx) = r.register(Capabilities::default());
        // `"*"` is the documented wildcard — restricts to "anywhere" without listing.
        let wild = Capabilities { calls: vec!["*".into()], ..Capabilities::default() };
        let (sender, _s) = r.register(wild);
        let bus_h = bus(&r, sender);
        bus_h.send(Dispatch::to(Address::Creature(a), b"hi-a".to_vec())).unwrap();
        bus_h.send(Dispatch::to(Address::Creature(b_id), b"hi-b".to_vec())).unwrap();
        assert_eq!(arx.recv().unwrap().payload, b"hi-a");
        assert_eq!(brx.recv().unwrap().payload, b"hi-b");
    }

    #[test]
    fn node_role_capability_accepts_exact_or_existing_coarse_node_authority() {
        let r = router();
        let (transport, transport_rx) = r.register(Capabilities::default());
        r.bind_role(Role::new(Role::TRANSPORT), transport);
        let target = Address::NodeRole(NodeId("peer-b".into()), Role::new("executor"));
        let exact = node_role_capability_key(&NodeId("peer-b".into()), &Role::new("executor"));

        for (calls, payload) in
            [(vec![exact], b"exact".as_slice()), (vec!["node:peer-b".into()], b"coarse".as_slice())]
        {
            let (sender, _sender_rx) =
                r.register(Capabilities { calls, ..Capabilities::default() });
            bus(&r, sender).send(Dispatch::to(target.clone(), payload.to_vec())).unwrap();
            assert_eq!(transport_rx.recv().unwrap().payload, payload);
        }

        let (denied, _denied_rx) = r.register(Capabilities {
            calls: vec!["role:executor".into()],
            ..Capabilities::default()
        });
        let error = bus(&r, denied).send(Dispatch::to(target, b"denied".to_vec())).unwrap_err();
        assert!(matches!(error, RouteError::Denied { from } if from == denied));
        assert!(transport_rx.try_recv().is_err(), "denied NodeRole never reaches transport");
    }

    #[test]
    fn node_role_capability_key_is_injective_across_adversarial_component_boundaries() {
        let first_node = NodeId("a/b".into());
        let first_role = Role::new("c");
        let second_node = NodeId("a".into());
        let second_role = Role::new("b/c");
        let first = node_role_capability_key(&first_node, &first_role);
        let second = node_role_capability_key(&second_node, &second_role);

        assert_ne!(first, second, "component boundaries are committed by byte length");

        let r = router();
        let (transport, transport_rx) = r.register(Capabilities::default());
        r.bind_role(Role::new(Role::TRANSPORT), transport);
        let (sender, _sender_rx) =
            r.register(Capabilities { calls: vec![first], ..Capabilities::default() });
        let bus = bus(&r, sender);
        bus.send(Dispatch::to(Address::NodeRole(first_node, first_role), b"first".to_vec()))
            .unwrap();
        assert_eq!(transport_rx.recv().unwrap().payload, b"first");
        let error = bus
            .send(Dispatch::to(Address::NodeRole(second_node, second_role), b"collision".to_vec()))
            .unwrap_err();
        assert!(matches!(error, RouteError::Denied { from } if from == sender));
    }

    /// The `BudgetSignal` wire shape (level + kind + vector) serde-roundtrips
    /// for every level and kind variant. The wire is the substrate's commitment: a downstream policy
    /// creature that binds to this shape today gets the same shape when richer engines (Warn-emitters,
    /// Wall-enforcers) come online. The roundtrip lock is what makes this a *seam*, not just
    /// a type definition.
    #[test]
    fn budget_signal_roundtrips_for_every_level_and_kind() {
        for level in [SignalLevel::Warn, SignalLevel::Hard] {
            for kind in [LimitKind::Fuel, LimitKind::Memory, LimitKind::Wall] {
                let s = BudgetSignal {
                    level,
                    kind,
                    vector: BudgetVector {
                        consumed: 1234,
                        limit: 4096,
                        dispatches_this_envelope: 2,
                        wall_ms_elapsed: 17,
                        envelopes_since_load: 99,
                    },
                };
                let bytes = serde_json::to_vec(&s).unwrap();
                let back: BudgetSignal = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(
                    s, back,
                    "BudgetSignal must roundtrip for level={level:?} kind={kind:?}"
                );
            }
        }
        // Default vector is the "engine didn't measure" shape — also stable.
        let default_vec = BudgetVector::default();
        let bytes = serde_json::to_vec(&default_vec).unwrap();
        let back: BudgetVector = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(default_vec, back);
    }

    /// **Determinism tripwire** for `Envelope::signing_payload`. Same risk-class as the manifest
    /// version: a future field whose serialization isn't byte-stable (a `HashMap`, a float, etc.)
    /// would silently break cross-node signature verification — this test fires the alarm
    /// before that lands.
    ///
    /// This hash was deliberately re-pinned in 0.4.1 when envelope signing gained the
    /// `GAWD-ENVELOPE-v1:` domain prefix ([`ENVELOPE_SIGNING_DOMAIN`]) and the `origin` field. For a
    /// **local** envelope (`origin: None`) the `origin` field serializes to nothing (it's
    /// `skip_serializing_if` and last), so the *only* byte that moved versus 0.4.0 is the domain
    /// prefix. The companion `..._with_origin_is_locked` test pins the cross-node shape.
    #[test]
    fn envelope_signing_payload_hash_is_locked_to_a_known_fixture() {
        use sha2::{Digest, Sha256};
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: Some(Address::Creature(CreatureId(99))),
                seq: 7,
                causal: vec![3, 5],
                stamp: 1234, // must be cleared inside signing_payload — its value here is a red herring
                sig: "must-be-stripped".into(),
                corr: Some(42),
                commitment: Some("commit-abc".into()),
                schema: "test".into(),
                origin: None,
            },
            payload: b"hello world".to_vec(),
        };
        let mut h = Sha256::new();
        h.update(env.signing_payload());
        let hex = format!("{:x}", h.finalize());
        // The `Address::Creature` serde variant tag carried in the envelope header's `from`/`to`
        // is part of the signed bytes this hash commits to, as is the `GAWD-ENVELOPE-v1:` prefix.
        const EXPECTED: &str = "c63fcfe37530a7921f7fd54edd8b9ed370088e41a6ba808f0a3e024d303747ac";
        assert_eq!(
            hex, EXPECTED,
            "envelope signing_payload tripwire fired; investigate field changes"
        );
    }

    /// Signed-wire tripwire for the additive [`Address::NodeRole`] variant. The legacy Creature
    /// fixture above remains pinned independently; this one commits the exact named JSON variant,
    /// node, and role bytes that a source transport signs and a destination transport verifies.
    #[test]
    fn envelope_signing_payload_with_node_role_is_locked() {
        use sha2::{Digest, Sha256};
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::NodeRole(NodeId("node/B:1".into()), Role::new("function/executor:v1")),
                reply_to: Some(Address::Creature(CreatureId(99))),
                seq: 7,
                causal: vec![3, 5],
                stamp: 1234,
                sig: "must-be-stripped".into(),
                corr: Some(42),
                commitment: Some("commit-abc".into()),
                schema: "test".into(),
                origin: None,
            },
            payload: b"hello world".to_vec(),
        };
        let mut h = Sha256::new();
        h.update(env.signing_payload());
        let hex = format!("{:x}", h.finalize());
        const EXPECTED: &str = "92fa0bbae120bf4e64513b3cb6a5ed1e01e6ee8497634b80d9795582c8b19f73";
        assert_eq!(
            hex, EXPECTED,
            "NodeRole signing_payload tripwire fired; investigate Address serialization"
        );
    }

    /// Determinism tripwire for the **cross-node** signing payload — an envelope carrying an
    /// authenticated [`Origin`]. Locks the byte layout the receiving transport verifies against
    /// (origin is the last signed field), so a drift in `Origin`'s serialization that would make a
    /// legitimate cross-node frame read as `BadSig` fails CI here instead of in the field.
    #[test]
    fn envelope_signing_payload_with_origin_is_locked() {
        use sha2::{Digest, Sha256};
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: Some(Address::Creature(CreatureId(99))),
                seq: 7,
                causal: vec![3, 5],
                stamp: 1234,
                sig: "must-be-stripped".into(),
                corr: Some(42),
                commitment: Some("commit-abc".into()),
                schema: "test".into(),
                origin: Some(Origin::node(NodeId("node-A".into()))),
            },
            payload: b"hello world".to_vec(),
        };
        let mut h = Sha256::new();
        h.update(env.signing_payload());
        let hex = format!("{:x}", h.finalize());
        const EXPECTED: &str = "4d2916603060eae997dd0cdb904f49de0e81e5c6d36e92be8193ca1cc976de0d";
        assert_eq!(
            hex, EXPECTED,
            "with-origin signing_payload tripwire fired; investigate Origin serialization"
        );
    }
}
