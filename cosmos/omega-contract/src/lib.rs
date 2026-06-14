//! omega-contract — the **Ω** wire contract + reserved seam (the lean leaf of the Ω pole).
//!
//! GAWD's cosmology is a **closed membrane**: `alpha` is **α** (the front door — every stimulus
//! enters and every product leaves through it) and `omega` is **Ω** (the ceiling).
//! Everything that exists, exists *between* α and Ω; the only things outside the membrane are
//! *stimuli* (inputs) and *products* (outputs). A [`Realm`] is a mesh of peer Sanctums
//! (see the [`realm`] crate); the **Omega** is the set-of-Realms — the outermost authority that
//! provides *common services* to the Realms beneath it.
//!
//! **What this crate owns.** A lean but real role: the Omega-gateway socket
//! ([`GATEWAY_ROLE`]) and the [`deferred`] wire contract the federation seam answers with. It is *not*
//! a routing crate (its gateways diverge too far to share a mechanism; see [`GATEWAY_ROLE`]),
//! and the **Ω authority** itself — the [`OmegaServices`] seam below — is reserved, not yet built.
//! Reserving it now means that authority arrives as an *implementation of an existing concept*, never
//! as a new top-level layer bolted on later.
//!
//! **Why a separate leaf crate.** The Ω pole's *body* — the `omega serve` server that boots a
//! federation/gateway Sanctum — lives in the root `omega` crate, which depends on the kernel and the
//! federation creatures. This contract is split out so a stub gateway (`omega-gateway`) or an
//! orchestrator can parse an `omega.deferred` reply by depending on **this** lean crate (just
//! `realm` + `aether` + `serde`), never on the heavy server. The `omega` crate re-exports
//! [`deferred`], [`GATEWAY_ROLE`], and [`OmegaServices`], so the public path `omega::deferred` /
//! `omega::GATEWAY_ROLE` keeps resolving.
//!
//! ## The grain rule: Omega deals with **Realms**; Realms deal with **Sanctums**
//!
//! The reserved services are deliberately stated at **Realm grain**. As much as possible, anything
//! *within* a Realm — placing Abodes across its Sanctums, admitting a Sanctum, backing one up — is the
//! [`realm`] layer's job (a Realm deals with its Sanctums). The Omega reaches below Realm grain
//! *only* when Realms are being **separated, merged, or specially handled** (partition, federation
//! split, cross-Realm custody). It is the authority over the set-of-Realms, not a second per-Sanctum
//! manager.
//!
//! ## Reserved services (shape now, implementation later)
//!
//! Things no single Realm — and nothing *outside* GAWD — should own:
//!
//! - **Cross-Realm placement** — deciding *which Realm* hosts (or re-hosts) an Abode, and moving it
//!   across a Realm boundary as the federation shifts. (Placement *across the Sanctums inside* one
//!   Realm stays the Realm's own distributor.)
//! - **Realm gating** — admitting and quarantining whole *Realms* into the federation
//!   ([`OmegaServices::admits`] takes a [`RealmId`], not a Sanctum). (Admitting *Sanctums* into a
//!   Realm is that Realm's gate.)
//! - **Cross-Realm / terminal custody** — the durability backstop: ensuring a Realm (and, when one is
//!   partitioned or specially handled, the Sanctums it can no longer cover) can be reconstituted.
//!   Built on the [`abode`](https://docs.rs/abode) snapshot contract; the routine per-Sanctum
//!   snapshot/backup *within* a Realm is realm-owned, and the Omega is where that custody finally
//!   terminates.
//! - **Self-containment** — removing dependencies on anything *outside* GAWD (no persisting through
//!   host disk I/O); the Omega is where "GAWD keeps its own state" terminates.
//!
//! ```
//! use omega_contract::OmegaServices;
//! // The seam is a trait; it ships no implementation — only the shape future authority binds to.
//! fn _is_object_safe(_: &dyn OmegaServices) {}
//! ```

use realm::{Realm, RealmId};

/// The `Role` an injected Omega-gateway / federator binds. Named by the crate that
/// owns Ω, so a binding references `omega::GATEWAY_ROLE` rather than a bare string.
///
/// Unlike [`realm`](https://docs.rs/realm), `omega` deliberately does **not** define a routing seam
/// trait: the two Omega gateways diverge at the root — the `omega-gateway`
/// stub defers every address while the real `omega-federator` runs stateful anti-entropy, signed
/// reputation, and a quarantine path — so there is no single per-envelope `resolve` mechanism worth
/// lifting to the crate. Ω's real future seam is [`OmegaServices`] (cross-realm authority), not
/// routing. The crate owns the socket name and the [`deferred`] wire contract; each gateway owns its
/// own routing.
pub const GATEWAY_ROLE: &str = aether::Role::OMEGA_GATEWAY;

/// The structured **wire contract** the Omega stub emits — owned by this crate (the
/// seam), not by the stub creature, so a consumer parses a `omega.deferred` reply by depending on
/// `omega-contract`. A real federation creature emits its own richer replies under other schemas.
pub mod deferred {
    use realm::RealmId;
    use serde::{Deserialize, Serialize};

    /// Why the Omega-gateway stub didn't resolve. Tagged on `kind` so an orchestrator dispatches on
    /// the variant, never on substring matches against prose.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case")]
    pub enum OmegaDeferredReason {
        /// Marker: the address grain is wired, but the stub does not resolve it.
        DeferredToV03,
    }

    /// Structured reply emitted for every Omega envelope by the stub.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct OmegaDeferredReply {
        /// The Realm the envelope addressed in the Omega.
        pub realm: RealmId,
        /// Why the gateway did not resolve.
        pub reason: OmegaDeferredReason,
        /// Optional human-readable elaboration. Elided when `None`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub details: Option<String>,
    }

    impl OmegaDeferredReply {
        /// The wire schema string for an `omega.deferred` envelope.
        pub const SCHEMA: &'static str = "omega.deferred";

        /// Serialize to the canonical bus bytes (`aether::wire`).
        pub fn to_bytes(&self) -> Vec<u8> {
            aether::wire::to_bytes(self)
        }
    }
}

/// The reserved seam for **Omega-level common services** — the Ω authority a future federation
/// binds.
///
/// **Embryo.** Every method below is the *shape* of a service, not a live
/// contract; the signatures will be refined before the first implementation lands (no consumer pins
/// them yet, by design — same discipline as the reserved `seer` topics). The trait is object-safe so
/// it can be held as a `dyn OmegaServices` once an implementation exists.
pub trait OmegaServices {
    /// The Realms currently under this Omega's authority. The set-of-sets membership: a Realm is
    /// a mesh of Sanctums; the Omega is the mesh of Realms.
    fn realms(&self) -> Vec<Realm>;

    /// Whether `realm` is admitted into the federation — the Omega's outer gate, at **Realm
    /// grain** (which *Realms* belong), distinct from a Realm's own gate over which *Sanctums* may
    /// join it (reserved — see "Realm gating" and the grain rule in the crate docs).
    fn admits(&self, realm: &RealmId) -> bool;
}
