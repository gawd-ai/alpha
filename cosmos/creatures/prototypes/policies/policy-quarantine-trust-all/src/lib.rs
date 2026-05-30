//! `TrustAllQuarantine` — a **reference** injected [`QuarantineTrust`] that honors every inbound
//! cross-Realm quarantine notice, regardless of who attested it.
//!
//! This is the bare-minimum reference for `immune-response`'s trust socket, and a deliberately
//! **unsafe** one: with it bound, *any* peer that can reach your immune-response can quarantine your
//! creatures (it is the defense-side analogue of `cosmos/creatures/prototypes/scorers/scorer-roundrobin` or
//! `reputation-roundrobin` — non-discriminating, useful only to exercise the path). The realistic
//! reference is `cosmos/creatures/prototypes/policies/policy-quarantine-trust-realm`, which honors only a configured peer set.
//! A production trust model is quorum-of-N, reputation-gated, or realm-allowlisted — the operator's
//! to write and bind. The substrate ships the [`QuarantineTrust`] *socket*; never a trust *model*.

use aether::RealmId;
use immune_response::QuarantineTrust;

/// Honors every inbound quarantine notice. Reference only — never production.
pub struct TrustAllQuarantine;

impl QuarantineTrust for TrustAllQuarantine {
    fn honors(&self, _attesting_peers: &[String], _realm: &RealmId) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn honors_anything_even_an_empty_attesting_set() {
        let t = TrustAllQuarantine;
        assert!(t.honors(&[], &RealmId::new("crew")));
        assert!(t.honors(&["whoever".into()], &RealmId::new("guests")));
    }
}
