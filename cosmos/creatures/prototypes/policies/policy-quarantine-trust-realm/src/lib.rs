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
//!
//! The retained trust table is bounded by default. `0` on the builder caps is the explicit
//! lab/demo opt-out, matching the other reference policies with retained state.

use std::collections::{HashMap, HashSet};

use aether::RealmId;
use immune_response::{
    QuarantineTrust, MAX_QUARANTINE_ATTESTING_PEER_BYTES, MAX_WATCH_FIELD_BYTES,
};

/// Default maximum number of Realms retained in the trust table.
pub const DEFAULT_MAX_TRUSTED_REALMS: usize = 1024;
/// Default maximum trusted peers retained per Realm.
pub const DEFAULT_MAX_TRUSTED_PEERS_PER_REALM: usize = 1024;

/// Honors a notice iff at least one attesting peer is in the trusted set **for that Realm**. A Realm
/// with no configured trusted set trusts no one (fail-closed — an unknown Realm's notices are
/// dropped, never honored by default).
pub struct TrustRealmQuarantine {
    trusted: HashMap<RealmId, HashSet<String>>,
    max_realms: usize,
    max_peers_per_realm: usize,
}

impl Default for TrustRealmQuarantine {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustRealmQuarantine {
    pub fn new() -> Self {
        TrustRealmQuarantine {
            trusted: HashMap::new(),
            max_realms: DEFAULT_MAX_TRUSTED_REALMS,
            max_peers_per_realm: DEFAULT_MAX_TRUSTED_PEERS_PER_REALM,
        }
    }

    /// Cap the number of Realms retained in the trust table. `0` disables the cap.
    pub fn with_max_trusted_realms(mut self, max_realms: usize) -> Self {
        self.max_realms = max_realms;
        self
    }

    /// Cap the number of trusted peers retained per Realm. `0` disables the cap.
    pub fn with_max_trusted_peers_per_realm(mut self, max_peers_per_realm: usize) -> Self {
        self.max_peers_per_realm = max_peers_per_realm;
        self
    }

    /// Builder: trust `peer` to flag creatures in `realm`.
    pub fn trust(mut self, realm: RealmId, peer: impl Into<String>) -> Self {
        let peer = peer.into();
        if let Some(reason) = trusted_entry_shape_error(&realm, &peer) {
            eprintln!("policy-quarantine-trust-realm: {reason}");
            return self;
        }
        if self.max_realms != 0
            && !self.trusted.contains_key(&realm)
            && self.trusted.len() >= self.max_realms
        {
            eprintln!(
                "policy-quarantine-trust-realm: trust table at capacity ({} realms); refusing realm {}",
                self.max_realms, realm.0
            );
            return self;
        }
        let peers = self.trusted.entry(realm).or_default();
        if self.max_peers_per_realm != 0
            && !peers.contains(&peer)
            && peers.len() >= self.max_peers_per_realm
        {
            eprintln!(
                "policy-quarantine-trust-realm: trusted-peer set at capacity ({} peers); refusing peer",
                self.max_peers_per_realm
            );
            return self;
        }
        peers.insert(peer);
        self
    }

    /// Number of Realms with at least one trusted peer. Useful for tests and observability.
    pub fn trusted_realm_count(&self) -> usize {
        self.trusted.len()
    }

    /// Number of trusted peers retained for `realm`.
    pub fn trusted_peer_count(&self, realm: &RealmId) -> usize {
        self.trusted.get(realm).map_or(0, HashSet::len)
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

fn trusted_entry_shape_error(realm: &RealmId, peer: &str) -> Option<String> {
    if realm.0.is_empty() || realm.0.len() > MAX_WATCH_FIELD_BYTES || realm.0.contains('\0') {
        return Some(format!(
            "trusted realm must be 1..={MAX_WATCH_FIELD_BYTES} bytes and contain no NUL"
        ));
    }
    if peer.is_empty() || peer.len() > MAX_QUARANTINE_ATTESTING_PEER_BYTES || peer.contains('\0') {
        return Some(format!(
            "trusted peer must be 1..={MAX_QUARANTINE_ATTESTING_PEER_BYTES} bytes and contain no NUL"
        ));
    }
    None
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

    #[test]
    fn retained_trust_table_is_bounded_and_shape_checked_by_default() {
        let crew = RealmId::new("crew");
        let t = TrustRealmQuarantine::new()
            .with_max_trusted_realms(1)
            .with_max_trusted_peers_per_realm(1)
            .trust(crew.clone(), "node-B")
            .trust(crew.clone(), "node-C")
            .trust(RealmId::new("guests"), "node-D")
            .trust(RealmId::new(""), "node-E")
            .trust(RealmId::new("crew\0"), "node-F")
            .trust(crew.clone(), "x".repeat(MAX_QUARANTINE_ATTESTING_PEER_BYTES + 1));

        assert_eq!(t.trusted_realm_count(), 1);
        assert_eq!(t.trusted_peer_count(&crew), 1);
        assert!(t.honors(&["node-B".into()], &crew));
        assert!(!t.honors(&["node-C".into()], &crew), "second peer refused at cap");
        assert!(!t.honors(&["node-D".into()], &RealmId::new("guests")), "second realm refused");
    }

    #[test]
    fn zero_caps_are_explicit_unbounded_opt_outs() {
        let crew = RealmId::new("crew");
        let guests = RealmId::new("guests");
        let t = TrustRealmQuarantine::new()
            .with_max_trusted_realms(0)
            .with_max_trusted_peers_per_realm(0)
            .trust(crew.clone(), "node-B")
            .trust(crew.clone(), "node-C")
            .trust(guests.clone(), "node-D");

        assert_eq!(t.trusted_realm_count(), 2);
        assert_eq!(t.trusted_peer_count(&crew), 2);
        assert!(t.honors(&["node-C".into()], &crew));
        assert!(t.honors(&["node-D".into()], &guests));
    }
}
