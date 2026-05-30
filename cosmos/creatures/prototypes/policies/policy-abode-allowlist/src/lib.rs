//! `AbodeAllowlistPolicy` — a **reference** injected [`RestorePolicy`] that admits a snapshot
//! only when its `abode_key` is on the operator's allowlist.
//!
//! Mirror of the `policy-signed` creature pattern: a tiny
//! struct that implements the substrate-shipped trait. The substrate's `abode-migrator` runs
//! its three integrity gates (size, sha256, signature) BEFORE consulting this policy, so by the
//! time `admit` is called the bytes are known sound + the signature has verified under
//! `abode_key`. This policy answers exactly one question: *do I trust this `abode_key` for this
//! Sanctum body?*
//!
//! ### What this reference deliberately doesn't do
//!
//! - **No body-capability checks.** A real production policy would compare `snapshot.requires`
//!   against the local Sanctum's advertised embodiment (from `creatures/embodiment-advertiser`'s
//!   view of cpu/mem/accelerators/jurisdiction). Out of scope for this minimal reference.
//! - **No Realm-membership lookup.** A real policy could use `snapshot.realm` to refuse Abodes
//!   from un-peered Realms before doing key work. Out of scope.
//! - **No revocation.** A key on the allowlist stays admissible forever. A real policy would
//!   consult a revocation list + check the snapshot's authorship timestamp (once one exists).
//!
//! Operators write their own (`my-org-abode-allowlist`, `realm-aware-abode-policy`, …) and
//! pass it to `AbodeMigrator::new`. The substrate ships only the trait + this minimum reference.

use abode::AbodeSnapshot;
use abode_migrator::RestorePolicy;

/// Allowlist by hex-encoded Abode public key — the same form as
/// `sigil::Provenance::author`.
pub struct AbodeAllowlistPolicy {
    /// Hex-encoded Abode pubkeys this operator accepts a restore from. Empty = refuse every
    /// restore (a fail-closed dev posture). For "any key" semantics, use a no-op policy in your
    /// own creature, never substrate.
    pub allowed_abode_keys: Vec<String>,
}

impl AbodeAllowlistPolicy {
    pub fn new(allowed_abode_keys: Vec<String>) -> Self {
        AbodeAllowlistPolicy { allowed_abode_keys }
    }

    /// Convenience: one key. The common single-Abode case.
    pub fn allowing(one: impl Into<String>) -> Self {
        AbodeAllowlistPolicy { allowed_abode_keys: vec![one.into()] }
    }
}

impl RestorePolicy for AbodeAllowlistPolicy {
    fn admit(&self, snapshot: &AbodeSnapshot) -> Result<(), String> {
        if self.allowed_abode_keys.iter().any(|k| k == &snapshot.abode_key) {
            Ok(())
        } else {
            Err(format!(
                "abode_key `{}` is not on the allowlist ({} keys allowed)",
                snapshot.abode_key,
                self.allowed_abode_keys.len()
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use abode_migrator::wrap_payload_v0_3;

    fn snapshot_with_key(k: &str) -> AbodeSnapshot {
        AbodeSnapshot::new(k.to_string(), wrap_payload_v0_3(b"state"))
    }

    #[test]
    fn admits_when_key_on_allowlist() {
        let p = AbodeAllowlistPolicy::allowing("abode-alex");
        assert!(p.admit(&snapshot_with_key("abode-alex")).is_ok());
    }

    #[test]
    fn refuses_when_key_off_allowlist_with_structured_reason() {
        let p = AbodeAllowlistPolicy::new(vec!["abode-alex".into(), "abode-bob".into()]);
        let err = p.admit(&snapshot_with_key("abode-mallory")).unwrap_err();
        assert!(err.contains("abode-mallory"));
        assert!(err.contains("not on the allowlist"));
        assert!(err.contains("2 keys allowed"));
    }

    #[test]
    fn empty_allowlist_refuses_every_restore() {
        // fail-closed dev posture: an operator who hasn't decided yet rejects every restore
        let p = AbodeAllowlistPolicy::new(vec![]);
        assert!(p.admit(&snapshot_with_key("anyone")).is_err());
    }
}
