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
    Address, CreatureId, Intent, NodeId, RealmId, Role, Topic, MAX_ADDRESS_NESTING_DEPTH,
};
pub use bus::{Bus, BusError, BusHandle, Ed25519Signer, Signer, StubSigner};
pub use envelope::{Envelope, EnvelopeError, Header};
pub use instance::{
    BudgetSignal, BudgetVector, Creature, CreatureCtx, Deadline, Dispatch, LimitKind, Outcome,
    SignalLevel,
};
pub use router::{InboxReceiver, JournalEntry, RouteError, Router, KERNEL_ID};

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
            },
            payload: b"hello world".to_vec(),
        };
        let mut h = Sha256::new();
        h.update(env.signing_payload());
        let hex = format!("{:x}", h.finalize());
        // The `Address::Creature` serde variant tag carried in the envelope header's `from`/`to`
        // is part of the signed bytes this hash commits to.
        const EXPECTED: &str = "5d33ccda105238d47fa824d5c0a6598b9c4a4512fee7b23ca3042001d7aa51be";
        assert_eq!(
            hex, EXPECTED,
            "envelope signing_payload tripwire fired; investigate field changes"
        );
    }
}
