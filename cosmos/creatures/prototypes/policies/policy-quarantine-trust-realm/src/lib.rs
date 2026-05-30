//! `TrustRealmQuarantine` — a **reference** injected [`QuarantineTrust`] that honors an inbound
//! cross-Realm quarantine notice only when at least one of its `attesting_peers` is in a
//! **per-Realm** trusted set.
//!
//! This is the realistic reference for `immune-response`'s trust socket (T2): the operator declares,
//! per Realm, which peers it trusts to flag a creature, and a notice is applied only if a trusted
//! peer vouched for it. Realm-scoping matters — a peer you trust to police the `guests` Realm should
//! not be able to quarantine creatures in `crew`. (`cosmos/creatures/prototypes/policies/policy-quarantine-trust-all` is the
//! non-discriminating contrast.) Richer models — quorum-of-N, reputation-weighted, time-decayed —
//! are the operator's to write; the substrate ships only the socket.

use std::collections::{HashMap, HashSet};

use aether::RealmId;
use immune_response::QuarantineTrust;

/// Honors a notice iff at least one attesting peer is in the trusted set **for that Realm**. A Realm
/// with no configured trusted set trusts no one (fail-closed — an unknown Realm's notices are
/// dropped, never honored by default).
#[derive(Default)]
pub struct TrustRealmQuarantine {
    trusted: HashMap<RealmId, HashSet<String>>,
}

impl TrustRealmQuarantine {
    pub fn new() -> Self {
        TrustRealmQuarantine { trusted: HashMap::new() }
    }

    /// Builder: trust `peer` to flag creatures in `realm`.
    pub fn trust(mut self, realm: RealmId, peer: impl Into<String>) -> Self {
        self.trusted.entry(realm).or_default().insert(peer.into());
        self
    }
}

impl QuarantineTrust for TrustRealmQuarantine {
    fn honors(&self, attesting_peers: &[String], realm: &RealmId) -> bool {
        match self.trusted.get(realm) {
            Some(set) => attesting_peers.iter().any(|p| set.contains(p)),
            None => false, // fail-closed: a Realm with no trusted peers honors nothing.
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honors_only_a_trusted_peer_in_the_matching_realm() {
        let t = TrustRealmQuarantine::new().trust(RealmId::new("crew"), "node-B");
        // Trusted peer, matching realm → honored.
        assert!(t.honors(&["node-B".into()], &RealmId::new("crew")));
        // Trusted peer present among several → honored.
        assert!(t.honors(&["x".into(), "node-B".into()], &RealmId::new("crew")));
        // Right peer, WRONG realm → dropped (realm-scoped).
        assert!(!t.honors(&["node-B".into()], &RealmId::new("guests")));
        // Untrusted peer, matching realm → dropped.
        assert!(!t.honors(&["attacker".into()], &RealmId::new("crew")));
        // Empty attesting set → dropped.
        assert!(!t.honors(&[], &RealmId::new("crew")));
    }

    #[test]
    fn unknown_realm_is_fail_closed() {
        let t = TrustRealmQuarantine::new(); // nothing configured
        assert!(!t.honors(&["node-B".into()], &RealmId::new("crew")));
    }
}
