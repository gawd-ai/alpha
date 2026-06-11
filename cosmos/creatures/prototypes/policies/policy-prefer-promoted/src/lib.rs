//! `PreferPromotedPolicy` — a **reference** injected [`Policy`] that admits a creature only when the
//! registry carries a **verified** fitness promotion for it at or above a minimum score.
//!
//! This is the consumer side of the signed-promotion contract (the producer is
//! `fitness-selector`). It proves the load-bearing claim of operating-model Loop 2: *selection
//! pressure is a policy choice, not a substrate gate* (T7). The substrate stores a reputation score
//! on the registry and enforces nothing; an operator who wants "only run creatures that have proven
//! themselves" binds **this** policy, and the gate begins to prefer the promoted. The contrast is
//! the whole point — with `AllowAll` (or `cosmos/creatures/prototypes/policies/policy-dev`) bound, the very same un-promoted
//! manifest admits. The fabric expresses the model; it never *is* the model.
//!
//! ## What it checks (in order)
//!
//! Given the candidate manifest, it locates the registry entry by the manifest's own provenance:
//! 1. `provenance.build_hash` must be present — it *is* the registry's `artifact_hash` key. No
//!    hash → can't locate a promotion → reject.
//! 2. `provenance.realm` (or [`RealmId::local`] when absent) + the hash form the `(realm,
//!    artifact_hash)` key. No entry there → reject (only *known* creatures can be promoted).
//! 3. The entry must carry a `ReputationScore` — a creature with no reputation is un-promoted.
//! 4. The score must be finite and `>= min_score`.
//! 5. If constructed with a trusted-selector allowlist, the score's `signed_by` key must be on that
//!    bounded list.
//! 6. The score must carry a promotion signature that **verifies** for that exact
//!    `(artifact_hash, realm, score, attesting_realm)` claim under the injected verifier
//!    (`ReputationScore::promotion_verifies`). An unsigned score (peer reputation, a test
//!    attestation) is *not* a verified promotion — it's refused. A signature replayed from another
//!    entry fails because the claim binds the key.
//!
//! ## What this reference deliberately doesn't do
//!
//! - **No author allowlist / signature gate of its own.** It checks *promotion*, not *provenance of
//!   the manifest*. A real admission policy composes both — require a trusted signer (à la
//!   `cosmos/creatures/prototypes/policies/policy-signed`) **and** a verified promotion. Kept single-axis so the promotion contract is
//!   legible; the composition is an operator's `and`-of-policies.
//! - **No global which-key-to-trust model.** The policy can be constructed with a bounded allowlist
//!   of selector Abode keys, but the substrate never chooses those keys. `new` keeps the historical
//!   lab posture and accepts any key that signs a valid promotion; use
//!   [`PreferPromotedPolicy::new_trusting_selectors`] or
//!   [`PreferPromotedPolicy::with_trusted_selectors`] for a production trust root.
//!
//! Operators write their own (`promoted-by-my-selector`, `quorum-of-3-realms`, …) and pass it to
//! `Kernel::new`. The substrate ships the gate + the [`Policy`] socket; never a selection model.

use std::sync::Arc;

use registry_mem::RegistryMem;
use sanctum::{Admission, Policy};
use sigil::{Ed25519Verifier, Manifest, RealmId, Verifier};

/// Default maximum retained selector roots in the reference trust list.
pub const DEFAULT_MAX_TRUSTED_SELECTORS: usize = 1_024;
/// Maximum bytes in a trusted selector key retained by this reference policy.
pub const MAX_TRUSTED_SELECTOR_BYTES: usize = 128;

/// Admit only creatures with a verified, at-or-above-threshold promotion in the registry.
pub struct PreferPromotedPolicy {
    /// The registry the selector writes promotions to. Held as a shared handle so the policy reads
    /// the *same* store the fitness-selector attests onto (in-process; like the migrator's
    /// registry-holding policies). Admission `Policy::admit` does not receive the registry — so a
    /// registry-consulting policy holds it directly, the established pattern.
    registry: Arc<RegistryMem>,
    /// Minimum promotion score to admit (in the selector's units).
    min_score: f32,
    /// The signature-verify mechanism (injected — `Ed25519Verifier` in production; a stub in tests).
    verifier: Arc<dyn Verifier>,
    /// Optional trusted selector Abode keys. Empty with `allow_any_selector == false` is fail-closed.
    trusted_selectors: Vec<String>,
    /// Historical/lab posture: any key with a valid promotion signature is accepted.
    allow_any_selector: bool,
}

impl PreferPromotedPolicy {
    /// Lab/default posture: verify with `Ed25519Verifier` and accept any valid promotion signer.
    ///
    /// Use [`Self::new_trusting_selectors`] or [`Self::with_trusted_selectors`] to pin a bounded
    /// selector trust root.
    pub fn new(registry: Arc<RegistryMem>, min_score: f32) -> Self {
        PreferPromotedPolicy {
            registry,
            min_score,
            verifier: Arc::new(Ed25519Verifier),
            trusted_selectors: Vec::new(),
            allow_any_selector: true,
        }
    }

    /// Strict posture: admit only promotions signed by one of these selector Abode keys.
    ///
    /// The retained list is trimmed, deduplicated, shape-checked, and capped at
    /// [`DEFAULT_MAX_TRUSTED_SELECTORS`]. An empty resulting list fails closed.
    pub fn new_trusting_selectors(
        registry: Arc<RegistryMem>,
        min_score: f32,
        trusted_selectors: Vec<String>,
    ) -> Self {
        Self::new(registry, min_score).with_trusted_selectors(trusted_selectors)
    }

    /// Bind a trusted-selector allowlist using the default retained-key cap.
    pub fn with_trusted_selectors(self, trusted_selectors: Vec<String>) -> Self {
        self.with_trusted_selector_limit(trusted_selectors, DEFAULT_MAX_TRUSTED_SELECTORS)
    }

    /// Bind a trusted-selector allowlist with an explicit retained-key cap.
    ///
    /// `max_trusted_selectors == 0` disables the cap for lab/demo workloads.
    pub fn with_trusted_selector_limit(
        mut self,
        trusted_selectors: Vec<String>,
        max_trusted_selectors: usize,
    ) -> Self {
        self.trusted_selectors =
            sanitize_trusted_selectors(trusted_selectors, max_trusted_selectors);
        self.allow_any_selector = false;
        self
    }

    /// Explicitly return to the lab posture that trusts any valid promotion signer.
    pub fn any_verified_selector(mut self) -> Self {
        self.trusted_selectors.clear();
        self.allow_any_selector = true;
        self
    }

    /// Number of selector trust roots retained after constructor sanitization.
    pub fn trusted_selector_count(&self) -> usize {
        self.trusted_selectors.len()
    }

    /// Swap the verifier (tests that want a deterministic stub).
    pub fn with_verifier(mut self, verifier: Arc<dyn Verifier>) -> Self {
        self.verifier = verifier;
        self
    }
}

impl Policy for PreferPromotedPolicy {
    fn admit(&self, manifest: &Manifest, _evidence: &Admission) -> Result<(), String> {
        let hash = manifest.provenance.build_hash.as_deref().ok_or_else(|| {
            "prefer-promoted: manifest declares no provenance.build_hash — cannot locate a registry \
             entry to check for a promotion"
                .to_string()
        })?;
        let realm = manifest.provenance.realm.clone().unwrap_or_else(RealmId::local);

        let entry = self.registry.fetch_in(&realm, hash).ok_or_else(|| {
            format!(
                "prefer-promoted: no registry entry for ({}, {}) — only known, promoted creatures admit",
                realm.0, hash
            )
        })?;
        let rep = entry.reputation.ok_or_else(|| {
            format!("prefer-promoted: ({}, {}) carries no reputation — not promoted", realm.0, hash)
        })?;

        if !rep.score.is_finite() {
            return Err("prefer-promoted: stored reputation score is non-finite".into());
        }
        if rep.score < self.min_score {
            return Err(format!(
                "prefer-promoted: score {} is below the minimum {}",
                rep.score, self.min_score
            ));
        }
        if !self.allow_any_selector {
            let selector = rep.signed_by.as_deref().ok_or_else(|| {
                "prefer-promoted: promotion has no signed_by selector for the trust allowlist"
                    .to_string()
            })?;
            if !self.trusted_selectors.iter().any(|trusted| trusted == selector) {
                return Err(format!(
                    "prefer-promoted: selector `{selector}` is not in the trust allowlist"
                ));
            }
        }
        if !rep.promotion_verifies(hash, &realm, self.verifier.as_ref()) {
            return Err(
                "prefer-promoted: promotion signature does not verify (unsigned, or signed by a key \
                 that doesn't match the stored claim)"
                    .into(),
            );
        }
        Ok(())
    }
}

fn sanitize_trusted_selectors(selectors: Vec<String>, max_keys: usize) -> Vec<String> {
    let mut out = Vec::new();
    for raw in selectors {
        if max_keys != 0 && out.len() >= max_keys {
            eprintln!(
                "policy-prefer-promoted: selector trust list at capacity ({max_keys}); refusing additional key"
            );
            break;
        }
        let key = raw.trim();
        if !trusted_selector_key_is_valid(key) || out.iter().any(|existing| existing == key) {
            continue;
        }
        out.push(key.to_string());
    }
    out
}

fn trusted_selector_key_is_valid(key: &str) -> bool {
    !key.is_empty() && key.len() <= MAX_TRUSTED_SELECTOR_BYTES && !key.as_bytes().contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_mem::ReputationScore;
    use sigil::{Backend, Ed25519KeyMaterial};

    fn manifest(hash: &str, realm: Option<&str>) -> Manifest {
        let mut m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.provenance.build_hash = Some(hash.to_string());
        m.provenance.realm = realm.map(RealmId::new);
        m
    }

    // Admission evidence the kernel would hand a policy — irrelevant to prefer-promoted (it reads
    // the registry, not the evidence), so a default-ish value suffices.
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

    /// Seed a registry with one entry, optionally promoted with a signature by `signer` declaring
    /// `declared_by` as `signed_by`. Returns (registry, hash, realm).
    fn seeded(
        score: Option<f32>,
        signer: Option<&Ed25519KeyMaterial>,
        declared_by: Option<String>,
    ) -> (Arc<RegistryMem>, String, RealmId) {
        let registry = RegistryMem::new();
        let realm = RealmId::new("crew");
        let bytes = b"candidate-bytes".to_vec();
        let m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        let hash = registry.publish_in(realm.clone(), m, bytes);
        if let Some(score) = score {
            let (signed_by, signature) = match (signer, declared_by) {
                (Some(k), Some(decl)) => {
                    let payload =
                        ReputationScore::promotion_payload(&hash, &realm, score, Some(&realm));
                    (Some(decl), Some(k.sign(&payload)))
                }
                _ => (None, None),
            };
            registry.attest_fitness(
                &realm,
                &hash,
                ReputationScore {
                    score,
                    attesting_realm: Some(realm.clone()),
                    signed_by,
                    signature,
                },
            );
        }
        (Arc::new(registry), hash, realm)
    }

    #[test]
    fn admits_a_verified_promotion_at_or_above_threshold() {
        let selector_key = Ed25519KeyMaterial::from_seed([0x5A; 32]).unwrap();
        let pk = selector_key.public_hex().to_string();
        let (registry, hash, _realm) = seeded(Some(0.9), Some(&selector_key), Some(pk));
        let p = PreferPromotedPolicy::new(registry, 0.8);
        assert!(p.admit(&manifest(&hash, Some("crew")), &evidence()).is_ok());
    }

    #[test]
    fn rejects_when_not_in_registry() {
        let (registry, _hash, _realm) = seeded(None, None, None);
        let p = PreferPromotedPolicy::new(registry, 0.8);
        let err = p.admit(&manifest("not-a-real-hash", Some("crew")), &evidence()).unwrap_err();
        assert!(err.contains("no registry entry"));
    }

    #[test]
    fn rejects_when_present_but_unpromoted() {
        let (registry, hash, _realm) = seeded(None, None, None); // published, never attested
        let p = PreferPromotedPolicy::new(registry, 0.8);
        let err = p.admit(&manifest(&hash, Some("crew")), &evidence()).unwrap_err();
        assert!(err.contains("not promoted"), "got: {err}");
    }

    #[test]
    fn rejects_below_threshold() {
        let k = Ed25519KeyMaterial::from_seed([0x5B; 32]).unwrap();
        let pk = k.public_hex().to_string();
        let (registry, hash, _realm) = seeded(Some(0.4), Some(&k), Some(pk));
        let p = PreferPromotedPolicy::new(registry, 0.8);
        let err = p.admit(&manifest(&hash, Some("crew")), &evidence()).unwrap_err();
        assert!(err.contains("below the minimum"), "got: {err}");
    }

    #[test]
    fn rejects_unsigned_promotion() {
        // A score with no signature is not a *verified* promotion — peer reputation / a test
        // attestation. prefer-promoted refuses it.
        let (registry, hash, _realm) = seeded(Some(0.95), None, None);
        let p = PreferPromotedPolicy::new(registry, 0.8);
        let err = p.admit(&manifest(&hash, Some("crew")), &evidence()).unwrap_err();
        assert!(err.contains("does not verify"), "got: {err}");
    }

    #[test]
    fn rejects_forged_signature() {
        // signed_by claims one key, but the signature was made by a DIFFERENT key → verify fails.
        let real = Ed25519KeyMaterial::from_seed([0x5C; 32]).unwrap();
        let attacker = Ed25519KeyMaterial::from_seed([0x66; 32]).unwrap();
        // declared_by = the honest key's pubkey, but signed by the attacker.
        let (registry, hash, _realm) =
            seeded(Some(0.95), Some(&attacker), Some(real.public_hex().to_string()));
        let p = PreferPromotedPolicy::new(registry, 0.8);
        let err = p.admit(&manifest(&hash, Some("crew")), &evidence()).unwrap_err();
        assert!(err.contains("does not verify"), "got: {err}");
    }

    #[test]
    fn rejects_manifest_without_build_hash() {
        let (registry, _hash, _realm) = seeded(None, None, None);
        let p = PreferPromotedPolicy::new(registry, 0.8);
        let mut m = Manifest::new("candidate", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.provenance.realm = Some(RealmId::new("crew"));
        let err = p.admit(&m, &evidence()).unwrap_err();
        assert!(err.contains("no provenance.build_hash"), "got: {err}");
    }

    #[test]
    fn trusted_selector_allowlist_admits_trusted_signer() {
        let selector_key = Ed25519KeyMaterial::from_seed([0x5D; 32]).unwrap();
        let pk = selector_key.public_hex().to_string();
        let (registry, hash, _realm) = seeded(Some(0.9), Some(&selector_key), Some(pk.clone()));
        let p = PreferPromotedPolicy::new_trusting_selectors(registry, 0.8, vec![pk]);
        assert!(p.admit(&manifest(&hash, Some("crew")), &evidence()).is_ok());
    }

    #[test]
    fn trusted_selector_allowlist_rejects_untrusted_signer() {
        let trusted = Ed25519KeyMaterial::from_seed([0x5E; 32]).unwrap();
        let untrusted = Ed25519KeyMaterial::from_seed([0x5F; 32]).unwrap();
        let (registry, hash, _realm) =
            seeded(Some(0.9), Some(&untrusted), Some(untrusted.public_hex().to_string()));
        let p = PreferPromotedPolicy::new_trusting_selectors(
            registry,
            0.8,
            vec![trusted.public_hex().to_string()],
        );
        let err = p.admit(&manifest(&hash, Some("crew")), &evidence()).unwrap_err();
        assert!(err.contains("trust allowlist"), "got: {err}");
    }

    #[test]
    fn trusted_selector_allowlist_is_sanitized_deduplicated_and_capped() {
        let p = PreferPromotedPolicy::new(Arc::new(RegistryMem::new()), 0.8)
            .with_trusted_selector_limit(
                vec![
                    "".into(),
                    " selector-a ".into(),
                    "selector-a".into(),
                    "x".repeat(MAX_TRUSTED_SELECTOR_BYTES + 1),
                    "selector-b".into(),
                    "selector-c".into(),
                ],
                2,
            );

        assert_eq!(p.trusted_selector_count(), 2);
        assert!(!p.allow_any_selector);
        assert_eq!(p.trusted_selectors, vec!["selector-a", "selector-b"]);
    }

    #[test]
    fn zero_trusted_selector_limit_is_explicit_unbounded_opt_out() {
        let p = PreferPromotedPolicy::new(Arc::new(RegistryMem::new()), 0.8)
            .with_trusted_selector_limit(vec!["selector-a".into(), "selector-b".into()], 0);
        assert_eq!(p.trusted_selector_count(), 2);
    }
}
