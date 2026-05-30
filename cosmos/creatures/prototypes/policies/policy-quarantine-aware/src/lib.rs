//! `QuarantineAwarePolicy` — a **reference** injected [`Policy`] that refuses a **quarantined**
//! creature *before* it applies a fitness-promotion gate. It is the consumer side of the
//! quarantine marker (the producer is `immune-response`), and it makes the headline
//! defense-vs-selection interaction concrete:
//!
//! > **Defense overrides selection.** A creature that is *both* a verified, at-threshold
//! > promotion *and* quarantined is **rejected** — the quarantine check runs first. Bind
//! > `cosmos/creatures/prototypes/policies/policy-prefer-promoted` against the *same* registry entry and it is *admitted*
//! > (prefer-promoted only checks the promotion; it never reads the quarantine slot). Same bytes,
//! > same registry, opposite verdict — because the two policies encode different operator stances.
//!
//! Neither verdict is the substrate's: the registry stores a reputation score *and* a reversible
//! quarantine marker and enforces nothing on either (T7 / T5 / IoC). An operator who wants "prefer
//! the proven, but never run the flagged" binds **this** policy; one who only cares about fitness
//! binds prefer-promoted. The fabric expresses the model; it never *is* the model.
//!
//! ## What it checks (in order)
//!
//! Given the candidate manifest, it locates the registry entry by the manifest's own provenance
//! (`provenance.build_hash` = the `artifact_hash` key; `provenance.realm` or [`RealmId::local`]):
//! 1. `provenance.build_hash` present, and the `(realm, artifact_hash)` entry exists — else reject.
//! 2. **Quarantine first.** If the entry carries a [`quarantine`](registry_mem::Entry::quarantine)
//!    marker → **reject** with its reason. Reversible (T5): once the offending artifact is
//!    re-published under the same key the marker clears and this check passes again.
//! 3. **Then the promotion gate** (identical to `policy-prefer-promoted`): a `ReputationScore` is
//!    present, finite, `>= min_score`, and carries a signature that
//!    [`promotion_verifies`](registry_mem::ReputationScore::promotion_verifies) for the entry.
//!
//! ## What this reference deliberately doesn't do
//!
//! - **No which-key / which-peer-to-trust model.** It reads the quarantine marker as authoritative
//!   (the `immune-response`'s injected `QuarantineTrust` already gated *whether* a peer's notice
//!   was written); this policy decides only *what to do* with a marker that exists.
//! - **No author allowlist of its own.** Like prefer-promoted, it checks promotion + quarantine,
//!   not the manifest's signer. A real policy composes this with a signer gate (`policy-signed`).

use std::sync::Arc;

use registry_mem::RegistryMem;
use sanctum::{Admission, Policy};
use sigil::{Ed25519Verifier, Manifest, RealmId, Verifier};

/// Reject a quarantined creature; otherwise admit only a verified, at-or-above-threshold promotion.
pub struct QuarantineAwarePolicy {
    /// The registry the immune-response marks and the fitness-selector promotes. Held as a shared
    /// handle so the policy reads the *same* store (in-process; the established registry-consulting
    /// policy pattern — `Policy::admit` does not receive the registry).
    registry: Arc<RegistryMem>,
    /// Minimum promotion score to admit (in the selector's units).
    min_score: f32,
    /// The signature-verify mechanism (injected — `Ed25519Verifier` in production; a stub in tests).
    verifier: Arc<dyn Verifier>,
}

impl QuarantineAwarePolicy {
    /// Default: verify with `Ed25519Verifier`.
    pub fn new(registry: Arc<RegistryMem>, min_score: f32) -> Self {
        QuarantineAwarePolicy { registry, min_score, verifier: Arc::new(Ed25519Verifier) }
    }

    /// Swap the verifier (tests that want a deterministic stub).
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = verifier;
        self
    }
}

impl Policy for QuarantineAwarePolicy {
    fn admit(&self, manifest: &Manifest, _evidence: &Admission) -> Result<(), String> {
        let hash = manifest.provenance.build_hash.as_deref().ok_or_else(|| {
            "quarantine-aware: manifest declares no provenance.build_hash — cannot locate a registry \
             entry to check"
                .to_string()
        })?;
        let realm = manifest.provenance.realm.clone().unwrap_or_else(RealmId::local);

        let entry = self.registry.fetch_in(&realm, hash).ok_or_else(|| {
            format!(
                "quarantine-aware: no registry entry for ({}, {}) — only known creatures admit",
                realm.0, hash
            )
        })?;

        // ---- DEFENSE FIRST: a quarantined creature is refused, even if it is also promoted. ----
        if let Some(q) = &entry.quarantine {
            return Err(format!(
                "quarantine-aware: ({}, {}) is quarantined ({}) — defense overrides selection",
                realm.0, hash, q.reason
            ));
        }

        // ---- THEN selection: the same promotion gate as prefer-promoted. ----
        let rep = entry.reputation.ok_or_else(|| {
            format!(
                "quarantine-aware: ({}, {}) carries no reputation — not promoted",
                realm.0, hash
            )
        })?;
        if !rep.score.is_finite() {
            return Err("quarantine-aware: stored reputation score is non-finite".into());
        }
        if rep.score < self.min_score {
            return Err(format!(
                "quarantine-aware: score {} is below the minimum {}",
                rep.score, self.min_score
            ));
        }
        if !rep.promotion_verifies(hash, &realm, self.verifier.as_ref()) {
            return Err(
                "quarantine-aware: promotion signature does not verify (unsigned, or signed by a key \
                 that doesn't match the stored claim)"
                    .into(),
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_mem::{QuarantineNotice, ReputationScore};
    use sigil::{Backend, Ed25519KeyMaterial};

    fn manifest(hash: &str, realm: &str) -> Manifest {
        let mut m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.provenance.build_hash = Some(hash.to_string());
        m.provenance.realm = Some(RealmId::new(realm));
        m
    }

    fn evidence() -> Admission {
        Admission {
            signature_present: true,
            signature_valid: true,
            content_address_declared: None,
            content_address_matches: None,
            artifact_hash_declared: true,
            artifact_hash_matches: Some(true),
            had_artifact: true,
        }
    }

    /// Seed one entry, optionally promoted (signed) and/or quarantined. Returns (registry, hash, realm, key).
    fn seeded(
        promote: bool,
        quarantine: bool,
    ) -> (Arc<RegistryMem>, String, RealmId, Ed25519KeyMaterial) {
        let registry = RegistryMem::new();
        let realm = RealmId::new("crew");
        let key = Ed25519KeyMaterial::from_seed([0x5A; 32]).unwrap();
        let m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        let hash = registry.publish_in(realm.clone(), m, b"candidate-bytes".to_vec());
        if promote {
            let score = 0.95f32;
            let sig =
                key.sign(&ReputationScore::promotion_payload(&hash, &realm, score, Some(&realm)));
            registry.attest_fitness(
                &realm,
                &hash,
                ReputationScore {
                    score,
                    attesting_realm: Some(realm.clone()),
                    signed_by: Some(key.public_hex().to_string()),
                    signature: Some(sig),
                },
            );
        }
        if quarantine {
            registry.mark_quarantine(
                &realm,
                &hash,
                QuarantineNotice {
                    reason: "hard budget breach".into(),
                    attesting_peers: vec!["node-A".into()],
                },
            );
        }
        (Arc::new(registry), hash, realm, key)
    }

    #[test]
    fn admits_a_verified_promotion_that_is_not_quarantined() {
        let (registry, hash, _realm, _k) = seeded(true, false);
        let p = QuarantineAwarePolicy::new(registry, 0.8);
        assert!(p.admit(&manifest(&hash, "crew"), &evidence()).is_ok());
    }

    #[test]
    fn rejects_a_promoted_but_quarantined_creature_defense_overrides_selection() {
        // THE HEADLINE: the entry is BOTH a verified promotion AND quarantined. quarantine-aware
        // rejects it (quarantine first), while prefer-promoted (a different policy) would admit it.
        let (registry, hash, _realm, _k) = seeded(true, true);
        let p = QuarantineAwarePolicy::new(registry, 0.8);
        let err = p.admit(&manifest(&hash, "crew"), &evidence()).unwrap_err();
        assert!(err.contains("quarantined"), "got: {err}");
        assert!(err.contains("defense overrides selection"), "got: {err}");
    }

    #[test]
    fn rejects_a_quarantined_creature_even_with_no_promotion() {
        let (registry, hash, _realm, _k) = seeded(false, true);
        let p = QuarantineAwarePolicy::new(registry, 0.8);
        let err = p.admit(&manifest(&hash, "crew"), &evidence()).unwrap_err();
        assert!(err.contains("quarantined"), "got: {err}");
    }

    #[test]
    fn re_publishing_clears_quarantine_and_admits_again_t5_reversibility() {
        // T5: quarantine is reversible. A re-publish of the same (realm, hash) clears the marker
        // (and the reputation) — re-attest the promotion and the same candidate admits again.
        let (registry, hash, realm, key) = seeded(true, true);
        let p = QuarantineAwarePolicy::new(registry.clone(), 0.8);
        assert!(p.admit(&manifest(&hash, "crew"), &evidence()).is_err(), "quarantined → rejected");

        // Re-publish the SAME bytes (same key) — clears both signals (T5).
        let m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        let hash2 = registry.publish_in(realm.clone(), m, b"candidate-bytes".to_vec());
        assert_eq!(hash2, hash, "same bytes → same key");
        // Re-earn the promotion (the immune marker is gone; the creature proved itself again).
        let score = 0.95f32;
        let sig = key.sign(&ReputationScore::promotion_payload(&hash, &realm, score, Some(&realm)));
        registry.attest_fitness(
            &realm,
            &hash,
            ReputationScore {
                score,
                attesting_realm: Some(realm.clone()),
                signed_by: Some(key.public_hex().to_string()),
                signature: Some(sig),
            },
        );
        assert!(
            p.admit(&manifest(&hash, "crew"), &evidence()).is_ok(),
            "quarantine cleared → admits"
        );
    }

    #[test]
    fn rejects_an_unpromoted_unquarantined_creature() {
        // Not quarantined, but never promoted either → fails the promotion gate.
        let (registry, hash, _realm, _k) = seeded(false, false);
        let p = QuarantineAwarePolicy::new(registry, 0.8);
        let err = p.admit(&manifest(&hash, "crew"), &evidence()).unwrap_err();
        assert!(err.contains("not promoted"), "got: {err}");
    }

    #[test]
    fn rejects_when_not_in_registry() {
        let (registry, _hash, _realm, _k) = seeded(false, false);
        let p = QuarantineAwarePolicy::new(registry, 0.8);
        let err = p.admit(&manifest("not-a-real-hash", "crew"), &evidence()).unwrap_err();
        assert!(err.contains("no registry entry"), "got: {err}");
    }
}
