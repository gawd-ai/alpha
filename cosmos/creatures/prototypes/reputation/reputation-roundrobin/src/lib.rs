//! `reputation-roundrobin` — a **reference** injected [`ReputationWeigher`].
//!
//! The simplest possible weight model: **every signed attestation weighs `1.0`** — one peer, one
//! vote, no preference. It mirrors the round-robin distributor's "everyone gets an equal turn"
//! posture, applied to reputation: the federator credits any peer whose delta verifies (T3) at
//! face value.
//!
//! This is the bare-minimum reference, exactly as `cosmos/creatures/prototypes/policies/policy-abode-allowlist` is for the
//! migrator's `RestorePolicy`. A real operator writes their own —
//! a sliding average, EWMA, a Realm allowlist that returns `0.0` for un-peered Realms, a
//! VRF-weighted scheme — and binds it instead. The substrate ships only the trait + the SEER
//! consensus topic the deltas ride; **never a weight model of its own** (IoC).
//!
//! ## What this reference deliberately doesn't do
//!
//! - **No discounting of self-attestation.** A production weigher would return `0.0` (or a steep
//!   discount) when `observer_realm` is the subject's own Realm — the T3 "observer == subject is
//!   meaningless" rule. This reference trusts every signer equally; that's only safe in a lab.
//! - **No reputation history.** Each attestation is weighed in isolation; a real model would fold
//!   the observer's track record into the weight.

use aether::RealmId;
use omega_federator::ReputationWeigher;

/// Weighs every observer at `1.0`. Stateless.
pub struct RoundRobinReputation;

impl RoundRobinReputation {
    pub fn new() -> Self {
        RoundRobinReputation
    }
}

impl Default for RoundRobinReputation {
    fn default() -> Self {
        Self::new()
    }
}

impl ReputationWeigher for RoundRobinReputation {
    fn weight(&self, _observer_key: &str, _observer_realm: &RealmId) -> f32 {
        1.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weighs_every_observer_at_one() {
        let w = RoundRobinReputation::new();
        assert_eq!(w.weight("any-key", &RealmId::new("crew")), 1.0);
        assert_eq!(w.weight("other-key", &RealmId::new("guests")), 1.0);
    }
}
