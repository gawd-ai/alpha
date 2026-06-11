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

/// Default maximum retained Abode keys in the reference restore allowlist.
pub const DEFAULT_MAX_ALLOWED_ABODE_KEYS: usize = 1024;
/// Maximum bytes in an allowlisted Abode key. Mirrors the manifest provenance author cap.
pub const MAX_ALLOWED_ABODE_KEY_BYTES: usize = sigil::MAX_MANIFEST_PROVENANCE_FIELD_BYTES;

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
        Self::new_with_key_limit(allowed_abode_keys, DEFAULT_MAX_ALLOWED_ABODE_KEYS)
    }

    /// Construct with an explicit retained-key cap. `max_allowed_keys == 0` disables the cap for
    /// lab/demo configurations.
    pub fn new_with_key_limit(allowed_abode_keys: Vec<String>, max_allowed_keys: usize) -> Self {
        AbodeAllowlistPolicy {
            allowed_abode_keys: retain_allowed_abode_keys(allowed_abode_keys, max_allowed_keys),
        }
    }

    /// Convenience: one key. The common single-Abode case.
    pub fn allowing(one: impl Into<String>) -> Self {
        Self::new(vec![one.into()])
    }

    /// Number of retained Abode keys after constructor sanitization.
    pub fn allowed_key_count(&self) -> usize {
        self.allowed_abode_keys.len()
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

fn retain_allowed_abode_keys(keys: Vec<String>, max_keys: usize) -> Vec<String> {
    let mut retained = Vec::new();
    for key in keys {
        insert_allowed_abode_key(&mut retained, key, max_keys);
    }
    retained
}

fn insert_allowed_abode_key(retained: &mut Vec<String>, key: String, max_keys: usize) {
    if let Some(reason) = allowed_abode_key_shape_error(&key) {
        eprintln!("policy-abode-allowlist: {reason}");
        return;
    }
    if retained.iter().any(|existing| existing == &key) {
        return;
    }
    if max_keys != 0 && retained.len() >= max_keys {
        eprintln!(
            "policy-abode-allowlist: Abode allowlist at capacity ({max_keys}); refusing additional key"
        );
        return;
    }
    retained.push(key);
}

fn allowed_abode_key_shape_error(key: &str) -> Option<String> {
    if key.is_empty() || key.len() > MAX_ALLOWED_ABODE_KEY_BYTES || key.contains('\0') {
        return Some(format!(
            "allowed Abode key must be 1..={MAX_ALLOWED_ABODE_KEY_BYTES} bytes and NUL-free"
        ));
    }
    None
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

    #[test]
    fn constructor_sanitizes_deduplicates_and_bounds_allowlist() {
        let oversized = "a".repeat(MAX_ALLOWED_ABODE_KEY_BYTES + 1);
        let p = AbodeAllowlistPolicy::new_with_key_limit(
            vec![
                "abode-alex".into(),
                "".into(),
                "bad\0key".into(),
                oversized,
                "abode-alex".into(),
                "abode-bob".into(),
            ],
            1,
        );

        assert_eq!(p.allowed_key_count(), 1);
        assert!(p.admit(&snapshot_with_key("abode-alex")).is_ok());
        let err = p.admit(&snapshot_with_key("abode-bob")).unwrap_err();
        assert!(err.contains("1 keys allowed"));
    }

    #[test]
    fn zero_key_limit_is_explicit_unbounded_opt_out() {
        let p = AbodeAllowlistPolicy::new_with_key_limit(
            vec!["abode-alex".into(), "abode-bob".into()],
            0,
        );

        assert_eq!(p.allowed_key_count(), 2);
        assert!(p.admit(&snapshot_with_key("abode-alex")).is_ok());
        assert!(p.admit(&snapshot_with_key("abode-bob")).is_ok());
    }
}
