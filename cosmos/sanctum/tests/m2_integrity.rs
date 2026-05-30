//! **Integrity gates fire before any load.**
//!
//! Three properties:
//! - **(b) bit-flip rejected.** A manifest declares its artifact's `build_hash`, the manifest is
//!   signed, the signature verifies — but a single byte in the artifact has changed. The kernel's
//!   admission gate hashes the bytes, computes a mismatch, and rejects *before* the engine sees
//!   anything. No `dlopen` of foreign mutated code.
//! - **(c) unsigned manifest rejected.** Even with a matching artifact hash, a manifest without
//!   `provenance.signature` is refused by the signed-policy creature.
//! - **(c') unknown-author rejected.** A signed manifest from a key the policy doesn't trust is
//!   refused — the policy's *allowlist* is the model the verifier deliberately doesn't own.
//!
//! All three fire on the same surface (`Kernel::load`), so the same admission code path covers
//! both the dynamic-load and the ship-and-load cases.

use std::sync::Arc;

use aether::{Ed25519Verifier, StubSigner};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use sanctum::{Kernel, KernelError};
use sha2::{Digest, Sha256};
use sigil::{Backend, Ed25519KeyMaterial, Manifest};

mod support;
use support::native_cdylib;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn kernel_with_signed_policy(allowed_authors: Vec<String>) -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(allowed_authors)),
        64,
    )
}

/// Build a properly-signed manifest for a path-on-disk artifact, declaring the bytes hash. The
/// real handle the substrate threads through: author key signs the canonical payload; receiver's
/// verifier re-runs the same hash.
fn signed_manifest(name: &str, artifact_bytes: &[u8], abode: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(abode.public_hex().to_string());
    m.provenance.build_hash = Some(sha256_hex(artifact_bytes));
    // signature commits to the manifest with the signature field cleared (`signing_payload`).
    let sig = abode.sign(&m.signing_payload());
    m.provenance.signature = Some(sig);
    m
}

#[test]
fn b_bit_flipped_artifact_is_rejected_before_any_load() {
    // The real on-disk artifact gives us a real hash, so the test is honest about how the path
    // hash is computed (file read + sha256). We then write a mutated copy beside it and admit
    // with the ORIGINAL manifest — the receiver's recomputed hash mismatches the manifest's
    // `build_hash`, admission rejects, the engine never sees the bytes.
    let real_so = native_cdylib("echo_daemon");
    let real_bytes = std::fs::read(&real_so).expect("read real .so");

    // Author the manifest with the REAL hash and a valid signature.
    let abode = Ed25519KeyMaterial::from_seed([7u8; 32]).unwrap();
    let manifest = signed_manifest("echo-daemon", &real_bytes, &abode);

    // Write a bit-flipped copy of the artifact next to it. We mutate the very last byte so the
    // hash differs but the file size matches (the more honest tamper — partial header tampering
    // would never even parse as ELF).
    let mut bad_bytes = real_bytes.clone();
    let last = bad_bytes.len() - 1;
    bad_bytes[last] ^= 0x01;
    let bad_so = real_so.parent().unwrap().join("libecho_daemon.bitflip.so");
    std::fs::write(&bad_so, &bad_bytes).expect("write tampered .so");

    let k = kernel_with_signed_policy(vec![abode.public_hex().to_string()]);
    let err = k.load(manifest, Artifact::Path(bad_so.clone())).expect_err("must reject");
    // The error MUST be admission-rejected (the policy / mechanism), not engine — the bytes never
    // reached `dlopen`. A different error class would mean the integrity gate failed open.
    match err {
        KernelError::AdmissionRejected(msg) => {
            assert!(
                msg.contains("integrity") || msg.contains("bytes"),
                "rejection message names the integrity gate; got: {msg}"
            );
        }
        other => panic!(
            "expected AdmissionRejected for bit-flipped artifact, got {other:?} \
             — integrity gate failed open"
        ),
    }
    // Cleanup; ignore failures (test isolation, not the assertion).
    let _ = std::fs::remove_file(&bad_so);
}

#[test]
fn c_unsigned_manifest_is_rejected_even_with_matching_bytes() {
    let real_so = native_cdylib("echo_daemon");
    let real_bytes = std::fs::read(&real_so).expect("read real .so");
    let mut m = Manifest::new("echo-daemon", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.build_hash = Some(sha256_hex(&real_bytes));
    // intentionally NO author, NO signature

    let k = kernel_with_signed_policy(vec![]); // any signed author OK; unsigned still rejected
    let err = k.load(m, Artifact::Path(real_so)).expect_err("unsigned must reject");
    assert!(
        matches!(err, KernelError::AdmissionRejected(ref s) if s.contains("unsigned")),
        "unsigned manifest must yield AdmissionRejected, got {err:?}"
    );
}

#[test]
fn c_prime_signature_from_unknown_author_is_rejected_under_an_allowlist() {
    let real_so = native_cdylib("echo_daemon");
    let real_bytes = std::fs::read(&real_so).expect("read real .so");

    let trusted = Ed25519KeyMaterial::from_seed([1u8; 32]).unwrap();
    let attacker = Ed25519KeyMaterial::from_seed([2u8; 32]).unwrap();

    // Attacker signs with their OWN key.
    let m = signed_manifest("echo-daemon", &real_bytes, &attacker);

    // Policy trusts ONLY `trusted`, not `attacker`.
    let k = kernel_with_signed_policy(vec![trusted.public_hex().to_string()]);
    let err = k.load(m, Artifact::Path(real_so)).expect_err("attacker key must reject");
    assert!(
        matches!(err, KernelError::AdmissionRejected(ref s) if s.contains("allowlist")),
        "untrusted author must yield AdmissionRejected, got {err:?}"
    );
}

#[test]
fn happy_path_a_signed_manifest_with_matching_bytes_admits() {
    // Positive control: with the right author, the right hash, and the right signature, admission
    // passes and the creature loads + runs. Proves the gates aren't accidentally over-rejecting.
    use aether::{Address, Deadline, Dispatch};
    use sigil::Capabilities;
    use std::time::Duration;

    let real_so = native_cdylib("echo_daemon");
    let real_bytes = std::fs::read(&real_so).expect("read real .so");
    let abode = Ed25519KeyMaterial::from_seed([42u8; 32]).unwrap();
    let m = signed_manifest("echo-daemon", &real_bytes, &abode);

    let k = kernel_with_signed_policy(vec![abode.public_hex().to_string()]);
    let id = k.load(m, Artifact::Path(real_so)).expect("happy path must admit + load");
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(Address::Creature(id), b"abc".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .unwrap();
    let reply = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(reply.payload, b"cba");
    k.shutdown_all(Deadline::default());
}
