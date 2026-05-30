//! Permissive dev policy — a **reference** injected [`Policy`] (not substrate).
//!
//! Admits every well-formed manifest, regardless of signature or provenance. Real-world policies
//! demand a valid signature by a known authoring key, a matching content address, opt-in capability
//! sets, etc. The fabric ships *none* of those defaults; this reference exists to prove the socket.

use sanctum::{Admission, Policy};
use sigil::Manifest;

pub struct DevPolicy;

impl Policy for DevPolicy {
    fn admit(&self, _manifest: &Manifest, _evidence: &Admission) -> Result<(), String> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil::Backend;

    #[test]
    fn admits_a_well_formed_manifest() {
        let m = Manifest::new("c", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        let evidence = Admission {
            signature_present: false,
            signature_valid: false,
            content_address_declared: None,
            content_address_matches: None,
            artifact_hash_declared: false,
            artifact_hash_matches: None,
            had_artifact: false,
        };
        assert!(DevPolicy.admit(&m, &evidence).is_ok());
    }
}
