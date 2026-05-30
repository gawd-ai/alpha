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
//! - if `allowed_authors` is non-empty, the manifest's `provenance.author` must be in it (the
//!   Abode-key allowlist — the *root model* the verifier deliberately doesn't own).
//!
//! This is the contract for "the AI didn't sneak in unauthored bytes," which also
//! means "the manifest the producer signed is the manifest the receiver got." It is an
//! **reference**, not a substrate default — operators write their own policy creatures with their
//! own allowlists. The fabric ships the gate (admission's evidence-gathering mechanism) and the
//! socket ([`Policy`]); it never ships a model of trust.

use sanctum::{Admission, Policy};
use sigil::Manifest;

/// The signed admission policy.
pub struct SignedPolicy {
    /// Hex-encoded Abode pubkeys this operator trusts. Empty = accept any well-formed signature
    /// regardless of which key signed (still rejects unsigned and integrity-failed loads — only
    /// the *root-list* check is disabled).
    pub allowed_authors: Vec<String>,
    /// When `true`, the manifest must declare a `build_hash` and the hash must match. Default true;
    /// flip to `false` for an operator who explicitly wants integrity off for a test environment.
    pub require_artifact_hash: bool,
}

impl SignedPolicy {
    /// Strict default: an allowlist of trusted authors, integrity check on.
    pub fn new(allowed_authors: Vec<String>) -> Self {
        SignedPolicy { allowed_authors, require_artifact_hash: true }
    }

    /// "Any well-formed signature": integrity on, but anyone may author. The right shape for a
    /// development node that still wants the bytes-and-sigs gates honored.
    pub fn any_signed_author() -> Self {
        SignedPolicy { allowed_authors: vec![], require_artifact_hash: true }
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
        if !self.allowed_authors.is_empty() {
            match &manifest.provenance.author {
                Some(a) if self.allowed_authors.iter().any(|p| p == a) => {}
                Some(a) => return Err(format!("author `{a}` is not in the trust allowlist")),
                None => return Err("manifest declared no author".into()),
            }
        }
        Ok(())
    }
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
}
