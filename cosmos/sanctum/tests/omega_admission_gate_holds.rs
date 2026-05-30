//! **T2: federation never bypasses admission.**
//!
//! In-process (no transport, no ports): the property under test is about the *admission gate*, not
//! the wire. A peer Realm advertises an artifact signed by a key the receiving Realm does not
//! trust. The federator's anti-entropy would land that artifact in the local `registry-mem` (the
//! registry is a dumb store — it holds whatever is published). The guarantee is that **loading it
//! still runs the operator's admission policy**, which refuses it: no creature from an untrusted
//! signer ever runs, no matter who advertised it.
//!
//! This is the load-bearing half of T2 — "reputation deltas are signals the admission policy may
//! consult; they never bypass the gate." We simulate the post-pull state (forged artifact sitting
//! in the registry) and prove the gate holds on load.

use std::sync::Arc;

use aether::StubSigner;
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use registry_mem::RegistryMem;
use sanctum::{Kernel, KernelError};
use sha2::{Digest, Sha256};
use sigil::{Backend, Ed25519KeyMaterial, Ed25519Verifier, Manifest};

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn kernel(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("m10-gate")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        64,
    )
}

/// Sign a manifest with `key` over `artifact` (a real, valid signature with a matching build_hash —
/// the point is the *signer* isn't trusted, not that the manifest is otherwise malformed). Setting
/// build_hash ensures the strict `SignedPolicy` integrity gate passes, so the ONLY rejection cause
/// is the untrusted author.
fn signed_by(name: &str, key: &Ed25519KeyMaterial, artifact: &[u8]) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.build_hash = Some(sha256_hex(artifact));
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

#[test]
fn forged_artifact_pulled_from_a_peer_realm_is_refused_at_admission() {
    // The receiving Realm trusts exactly one Abode key.
    let trusted = Ed25519KeyMaterial::from_seed([0x11u8; 32]).unwrap();
    // A foreign Realm signs an artifact with a key the receiver has never trusted.
    let attacker = Ed25519KeyMaterial::from_seed([0x66u8; 32]).unwrap();

    let k = kernel(vec![trusted.public_hex().to_string()]);

    // Simulate the post-anti-entropy state: the forged artifact has landed in the local registry
    // (a federator pull is a dumb store-and-forward; the registry holds what it's handed).
    let registry = RegistryMem::new();
    let bytes = b"forged-artifact-bytes".to_vec();
    let forged = signed_by("totally-legit-promise", &attacker, &bytes);
    let realm = aether::RealmId::new("crew");
    let hash = registry.publish_in(realm.clone(), forged, bytes);

    // The artifact IS in the registry — federation delivered it.
    let entry = registry.fetch_in(&realm, &hash).expect("forged artifact sits in the registry");

    // But loading it runs admission, which refuses: the signer isn't on the allowlist. T2 holds —
    // federation delivered bytes, the gate refused the creature; nothing untrusted ever runs.
    let result = k.load(entry.manifest, Artifact::Bytes(entry.artifact));
    assert!(
        matches!(result, Err(KernelError::AdmissionRejected(_))),
        "a forged-signer artifact must be refused at admission regardless of who advertised it; got {result:?}"
    );

    // Sanity: the SAME artifact bytes signed by the trusted key WOULD admit — proving it's the
    // signer, not the bytes, that the gate rejects (and that re-publishing under a trusted signature
    // is the legitimate path — T5 reversibility's sibling at the admission layer).
    let legit = signed_by("totally-legit-promise", &trusted, b"forged-artifact-bytes");
    let legit_hash = registry.publish_in(realm.clone(), legit, b"forged-artifact-bytes".to_vec());
    let legit_entry = registry.fetch_in(&realm, &legit_hash).unwrap();
    // NativeEngine will fail to load the bogus bytes as a real .so, but admission must pass FIRST —
    // so we assert the error is NOT an AdmissionRejected (it gets past the gate to the engine).
    let result = k.load(legit_entry.manifest, Artifact::Bytes(legit_entry.artifact));
    assert!(
        !matches!(result, Err(KernelError::AdmissionRejected(_))),
        "trusted-signer artifact must pass the admission gate (engine-load failure is fine); got {result:?}"
    );
}
