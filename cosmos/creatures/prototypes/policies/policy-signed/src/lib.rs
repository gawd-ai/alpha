//! `SignedPolicy` — a **reference** injected [`Policy`] that demands real provenance.
//!
//! Required for admission:
//! - a signature is present **and** the verifier validated it (`signature_valid`);
//! - the manifest declares `provenance.build_hash` **and** the actual artifact bytes hashed to it
//!   (`artifact_hash_matches == Some(true)`);
//! - if a `content_address` is declared on the manifest, it must equal what the receiver computes
//!   from the manifest body (`content_address_matches == Some(true)`). Mismatch = the producer's
//!   claim about *what manifest this is* doesn't match the bytes the receiver sees → reject. This
//!   gate binds the whole manifest body, so differently-capable manifests can't share an address;
//! - the manifest's `provenance.author` must be in the retained author allowlist unless the policy
//!   was explicitly constructed with [`SignedPolicy::any_signed_author`] (the Abode-key allowlist —
//!   the *root model* the verifier deliberately doesn't own).
//!
//! This is the contract for "the AI didn't sneak in unauthored bytes," which also
//! means "the manifest the producer signed is the manifest the receiver got." It is an
//! **reference**, not a substrate default — operators write their own policy creatures with their
//! own allowlists. The fabric ships the gate (admission's evidence-gathering mechanism) and the
//! socket ([`Policy`]); it never ships a model of trust.

use sanctum::{Admission, Policy};
use sigil::Manifest;

/// Default maximum retained author roots in the reference allowlist.
pub const DEFAULT_MAX_ALLOWED_AUTHORS: usize = 1024;
/// Maximum bytes in an allowlisted author key. Mirrors the manifest provenance field cap.
pub const MAX_ALLOWED_AUTHOR_BYTES: usize = sigil::MAX_MANIFEST_PROVENANCE_FIELD_BYTES;

/// The signed admission policy.
///
/// Prefer the constructors: they sanitize and cap the retained author list. Direct struct literals
/// remain available for custom test/lab postures, but callers that use them own the shape of the
/// retained `allowed_authors` vector.
pub struct SignedPolicy {
    /// Hex-encoded Abode pubkeys this operator trusts. The strict constructors fail closed even if
    /// this list is empty after sanitization; [`SignedPolicy::any_signed_author`] is the explicit
    /// opt-out that accepts any well-formed signature while still rejecting unsigned and
    /// integrity-failed loads.
    pub allowed_authors: Vec<String>,
    /// When `true`, the manifest must declare a `build_hash` and the hash must match. Default true;
    /// flip to `false` for an operator who explicitly wants integrity off for a test environment.
    pub require_artifact_hash: bool,
    /// Explicitly disables the author-root allowlist check while keeping the signature and integrity
    /// gates. Prefer [`SignedPolicy::any_signed_author`] over setting this field directly.
    pub allow_any_author: bool,
}

impl SignedPolicy {
    /// Strict default: a bounded allowlist of trusted authors, integrity check on. Use
    /// [`SignedPolicy::any_signed_author`] for the explicit open-author development posture.
    pub fn new(allowed_authors: Vec<String>) -> Self {
        Self::new_with_author_limit(allowed_authors, DEFAULT_MAX_ALLOWED_AUTHORS)
    }

    /// Construct with an explicit retained-author cap. `max_allowed_authors == 0` disables the cap
    /// for lab/demo configurations.
    pub fn new_with_author_limit(allowed_authors: Vec<String>, max_allowed_authors: usize) -> Self {
        SignedPolicy {
            allowed_authors: retain_allowed_author_keys(allowed_authors, max_allowed_authors),
            require_artifact_hash: true,
            allow_any_author: false,
        }
    }

    /// "Any well-formed signature": integrity on, but anyone may author. The right shape for a
    /// development node that still wants the bytes-and-sigs gates honored.
    pub fn any_signed_author() -> Self {
        SignedPolicy {
            allowed_authors: vec![],
            require_artifact_hash: true,
            allow_any_author: true,
        }
    }

    /// Number of retained author roots after constructor sanitization.
    pub fn allowed_author_count(&self) -> usize {
        self.allowed_authors.len()
    }
}

impl Policy for SignedPolicy {
    fn admit(&self, manifest: &Manifest, evidence: &Admission) -> Result<(), String> {
        if !evidence.signature_present {
            return Err("unsigned manifest rejected".into());
        }
        if !evidence.signature_valid {
            return Err("manifest signature did not verify".into());
        }
        // The artifact-bytes gate only applies to dynamic loads (`Kernel::load`). In-process
        // boot creatures (`Kernel::load_instance`: transport, registry, resolver) have no
        // bytes — `had_artifact == false`. A strict policy still demands a valid signature on
        // them, just not an artifact-bytes match.
        if self.require_artifact_hash && evidence.had_artifact {
            match evidence.artifact_hash_matches {
                Some(true) => {}
                Some(false) => {
                    return Err(
                        "artifact bytes do not match provenance.build_hash (integrity)".into()
                    )
                }
                None => {
                    // Dynamic load with no `build_hash` declared — strict mode rejects, since
                    // there's nothing for the receiver to recompute against.
                    return Err(
                        "strict policy requires `provenance.build_hash` to bind artifact bytes"
                            .into(),
                    );
                }
            }
        }
        // Content-address self-consistency. If the manifest declared one, it MUST be the one the
        // receiver computes — otherwise the producer is claiming to have signed a different
        // manifest than the receiver is looking at. We don't *require* declaration here (some
        // operators may legitimately omit it pending the federation story); we just refuse
        // false claims. A future stricter policy can demand presence as well.
        if let Some(false) = evidence.content_address_matches {
            return Err(
                "manifest content_address does not match the receiver's recompute (identity drift)"
                    .into(),
            );
        }
        if !self.allow_any_author {
            match &manifest.provenance.author {
                Some(a) if self.allowed_authors.iter().any(|p| p == a) => {}
                Some(a) => return Err(format!("author `{a}` is not in the trust allowlist")),
                None => return Err("manifest declared no author".into()),
            }
        }
        Ok(())
    }
}

fn retain_allowed_author_keys(keys: Vec<String>, max_keys: usize) -> Vec<String> {
    let mut retained = Vec::new();
    for key in keys {
        insert_allowed_author_key(&mut retained, key, max_keys);
    }
    retained
}

fn insert_allowed_author_key(retained: &mut Vec<String>, key: String, max_keys: usize) {
    if let Some(reason) = allowed_author_key_shape_error(&key) {
        eprintln!("policy-signed: {reason}");
        return;
    }
    if retained.iter().any(|existing| existing == &key) {
        return;
    }
    if max_keys != 0 && retained.len() >= max_keys {
        eprintln!(
            "policy-signed: author allowlist at capacity ({max_keys}); refusing additional key"
        );
        return;
    }
    retained.push(key);
}

fn allowed_author_key_shape_error(key: &str) -> Option<String> {
    if key.is_empty() || key.len() > MAX_ALLOWED_AUTHOR_BYTES || key.contains('\0') {
        return Some(format!(
            "allowed author must be 1..={MAX_ALLOWED_AUTHOR_BYTES} bytes and NUL-free"
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil::{Backend, Manifest};

    fn ev(sig: bool, valid: bool, hash_declared: bool, hash_matches: Option<bool>) -> Admission {
        Admission {
            signature_present: sig,
            signature_valid: valid,
            content_address_declared: None,
            content_address_matches: None,
            artifact_hash_declared: hash_declared,
            artifact_hash_matches: hash_matches,
            // Unit tests construct evidence as-if a dynamic load happened; the boot-creature
            // case (had_artifact=false) is exercised in `m2_two_node` via the kernel.
            had_artifact: true,
        }
    }

    fn m(author: Option<&str>) -> Manifest {
        let mut x = Manifest::new("t", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        if let Some(a) = author {
            x.provenance.author = Some(a.into());
        }
        x
    }

    #[test]
    fn rejects_unsigned() {
        let p = SignedPolicy::any_signed_author();
        assert!(p.admit(&m(Some("k")), &ev(false, false, true, Some(true))).is_err());
    }

    #[test]
    fn rejects_invalid_signature() {
        let p = SignedPolicy::any_signed_author();
        assert!(p.admit(&m(Some("k")), &ev(true, false, true, Some(true))).is_err());
    }

    #[test]
    fn rejects_bitflipped_artifact() {
        let p = SignedPolicy::any_signed_author();
        assert!(p.admit(&m(Some("k")), &ev(true, true, true, Some(false))).is_err());
    }

    #[test]
    fn rejects_manifest_without_build_hash_in_strict_mode() {
        let p = SignedPolicy::any_signed_author();
        assert!(p.admit(&m(Some("k")), &ev(true, true, false, None)).is_err());
    }

    #[test]
    fn admits_in_process_boot_creature_with_signature_but_no_artifact_hash() {
        // Boot creatures (transport, registry) load via `load_instance` — no artifact bytes, so
        // `had_artifact == false`. A strict policy still requires a signature, but the build-hash
        // gate doesn't apply: there is nothing to recompute against.
        let p = SignedPolicy::any_signed_author();
        let ev = Admission {
            signature_present: true,
            signature_valid: true,
            content_address_declared: None,
            content_address_matches: None,
            artifact_hash_declared: false,
            artifact_hash_matches: None,
            had_artifact: false,
        };
        assert!(p.admit(&m(Some("k")), &ev).is_ok());
    }

    #[test]
    fn admits_signed_integrity_matched() {
        let p = SignedPolicy::any_signed_author();
        assert!(p.admit(&m(Some("k")), &ev(true, true, true, Some(true))).is_ok());
    }

    #[test]
    fn rejects_mismatched_content_address() {
        // The manifest declared a content_address; admission recomputed; they disagree → reject.
        // This is the gate that catches a forwarder substituting one manifest for another behind
        // the same artifact bytes.
        let p = SignedPolicy::any_signed_author();
        let ev = Admission {
            signature_present: true,
            signature_valid: true,
            content_address_declared: Some("sha256:claimed".into()),
            content_address_matches: Some(false),
            artifact_hash_declared: true,
            artifact_hash_matches: Some(true),
            had_artifact: true,
        };
        let err = p.admit(&m(Some("k")), &ev).unwrap_err();
        assert!(err.contains("content_address"), "reason must name the gate: {err}");
    }

    #[test]
    fn admits_when_content_address_is_omitted() {
        // The receiver does not require declaration — only refuses a *false* claim. An operator
        // running pre-federation can still admit manifests that omit the field.
        let p = SignedPolicy::any_signed_author();
        let ev = Admission {
            signature_present: true,
            signature_valid: true,
            content_address_declared: None,
            content_address_matches: None,
            artifact_hash_declared: true,
            artifact_hash_matches: Some(true),
            had_artifact: true,
        };
        assert!(p.admit(&m(Some("k")), &ev).is_ok());
    }

    #[test]
    fn allowlist_admits_known_author_rejects_unknown() {
        let p = SignedPolicy::new(vec!["abode-alex".into()]);
        assert!(p.admit(&m(Some("abode-alex")), &ev(true, true, true, Some(true))).is_ok());
        assert!(p.admit(&m(Some("abode-mallory")), &ev(true, true, true, Some(true))).is_err());
        assert!(p.admit(&m(None), &ev(true, true, true, Some(true))).is_err());
    }

    #[test]
    fn empty_constructor_allowlist_fails_closed() {
        let p = SignedPolicy::new(vec![]);
        assert!(p.admit(&m(Some("abode-alex")), &ev(true, true, true, Some(true))).is_err());
        assert!(p.admit(&m(None), &ev(true, true, true, Some(true))).is_err());
    }

    #[test]
    fn constructor_sanitizes_deduplicates_and_bounds_allowlist() {
        let oversized = "a".repeat(MAX_ALLOWED_AUTHOR_BYTES + 1);
        let p = SignedPolicy::new_with_author_limit(
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

        assert_eq!(p.allowed_author_count(), 1);
        assert!(p.admit(&m(Some("abode-alex")), &ev(true, true, true, Some(true))).is_ok());
        assert!(p.admit(&m(Some("abode-bob")), &ev(true, true, true, Some(true))).is_err());
    }

    #[test]
    fn zero_author_limit_is_explicit_unbounded_opt_out() {
        let p =
            SignedPolicy::new_with_author_limit(vec!["abode-alex".into(), "abode-bob".into()], 0);

        assert_eq!(p.allowed_author_count(), 2);
        assert!(p.admit(&m(Some("abode-alex")), &ev(true, true, true, Some(true))).is_ok());
        assert!(p.admit(&m(Some("abode-bob")), &ev(true, true, true, Some(true))).is_ok());
    }
}
