//! **Integrity gates fire before any load.**
//!
//! Four properties:
//! - **(b) bit-flip rejected.** A manifest declares its artifact's `build_hash`, the manifest is
//!   signed, the signature verifies — but a single byte in the artifact has changed. The kernel's
//!   admission gate hashes the bytes, computes a mismatch, and rejects *before* the engine sees
//!   anything. No `dlopen` of foreign mutated code.
//! - **(c) unsigned manifest rejected.** Even with a matching artifact hash, a manifest without
//!   `provenance.signature` is refused by the signed-policy creature.
//! - **(c') unknown-author rejected.** A signed manifest from a key the policy doesn't trust is
//!   refused — the policy's *allowlist* is the model the verifier deliberately doesn't own.
//! - **(d) exact native bytes.** A deterministic engine hook replaces a path after admission; the
//!   recorded hash and executing code remain the staged pre-swap bytes. Path and byte-backed stages
//!   are retained through the loaded lifetime and removed only after clean `dlclose`.
//!
//! All fire on the same surface (`Kernel::load`), so the same admission code path covers dynamic,
//! shipped-byte, and bounded sandboxed path loads.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use aether::{Ed25519Verifier, StubSigner};
use anima::{Artifact, Engine, EngineError, LoadedModule, NativeEngine, ScriptEngine, WasmEngine};
use policy_signed::SignedPolicy;
use sanctum::{Kernel, KernelError};
use sha2::{Digest, Sha256};
use sigil::{Backend, Ed25519KeyMaterial, Manifest};

mod support;
use support::native_cdylib;

static NEXT_SWAP_DIR: AtomicU64 = AtomicU64::new(0);

struct SwapDir(PathBuf);

impl SwapDir {
    fn new() -> Self {
        for _ in 0..1024 {
            let sequence = NEXT_SWAP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("sanctum-native-swap-{}-{sequence}", std::process::id()));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self(path),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("create native swap fixture {}: {error}", path.display()),
            }
        }
        panic!("could not allocate native swap fixture directory");
    }
}

impl Drop for SwapDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Test engine that changes the operator-controlled source path at the old hash→dlopen seam, then
/// delegates to the real native loader. Before exact staging, admission hashed v1 and this hook made
/// NativeEngine reopen/load v2. With staging, the hook can change only the now-unused source path.
struct SwapSourceBeforeNativeLoad {
    source: PathBuf,
    replacement: PathBuf,
    staged_path: Arc<Mutex<Option<PathBuf>>>,
}

impl Engine for SwapSourceBeforeNativeLoad {
    fn backend(&self) -> Backend {
        Backend::Daemon
    }

    fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        *self.staged_path.lock().unwrap_or_else(|poison| poison.into_inner()) =
            artifact.staged_native_path().map(PathBuf::from);
        #[cfg(target_os = "windows")]
        std::fs::remove_file(&self.source).map_err(|error| {
            EngineError::Load(format!("remove native swap destination: {error}"))
        })?;
        std::fs::rename(&self.replacement, &self.source)
            .map_err(|error| EngineError::Load(format!("swap native source path: {error}")))?;
        NativeEngine.load(artifact, manifest)
    }
}

struct CaptureNativeStage {
    staged_path: Arc<Mutex<Option<PathBuf>>>,
}

impl Engine for CaptureNativeStage {
    fn backend(&self) -> Backend {
        Backend::Daemon
    }

    fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        *self.staged_path.lock().unwrap_or_else(|poison| poison.into_inner()) =
            artifact.staged_native_path().map(PathBuf::from);
        NativeEngine.load(artifact, manifest)
    }
}

/// Engine hook for the bounded beast/critter path. It replaces the operator source only after
/// admission, then observes the representation the selected engine would consume.
struct SwapSourceBeforePortableLoad {
    backend: Backend,
    source: PathBuf,
    replacement: PathBuf,
    observed_bytes: Arc<Mutex<Option<Vec<u8>>>>,
}

impl Engine for SwapSourceBeforePortableLoad {
    fn backend(&self) -> Backend {
        self.backend
    }

    fn load(&self, artifact: &Artifact, _manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        #[cfg(target_os = "windows")]
        std::fs::remove_file(&self.source).map_err(|error| {
            EngineError::Load(format!("remove portable swap destination: {error}"))
        })?;
        std::fs::rename(&self.replacement, &self.source)
            .map_err(|error| EngineError::Load(format!("swap portable source path: {error}")))?;
        *self.observed_bytes.lock().unwrap_or_else(|poison| poison.into_inner()) =
            Some(artifact.read_bytes()?);
        Ok(LoadedModule::new(Box::new(NoopCreature), Box::new(())))
    }
}

struct NoopCreature;

impl aether::Creature for NoopCreature {
    fn bind(&mut self, _ctx: aether::CreatureCtx) {}

    fn handle(&mut self, _env: aether::Envelope) -> aether::Outcome {
        aether::Outcome::none()
    }

    fn shutdown(&mut self, _deadline: aether::Deadline) {}
}

fn overwrite_staged_file(path: &std::path::Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut permissions = std::fs::metadata(path)?.permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o600);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)?;
    std::fs::write(path, bytes)
}

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
    signed_manifest_for_backend(name, artifact_bytes, abode, Backend::Daemon, "gawd_creature_v1")
}

fn signed_manifest_for_backend(
    name: &str,
    artifact_bytes: &[u8],
    abode: &Ed25519KeyMaterial,
    backend: Backend,
    abi_tag: &str,
) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", backend, abi_tag);
    m.provenance.author = Some(abode.public_hex().to_string());
    m.provenance.build_hash = Some(sha256_hex(artifact_bytes));
    // signature commits to the manifest with the signature field cleared (`signing_payload`).
    let sig = abode.sign(&m.signing_payload());
    m.provenance.signature = Some(sig);
    m
}

#[test]
fn beast_and_critter_source_swaps_cannot_diverge_from_admission_bytes() {
    use aether::Deadline;

    for (index, (backend, abi_tag)) in
        [(Backend::Beast, "gawd_creature_v1"), (Backend::Critter, anima::CRITTER_ABI_TAG)]
            .into_iter()
            .enumerate()
    {
        let v1 = format!("portable-v1-{backend:?}").into_bytes();
        let v2 = format!("portable-v2-{backend:?}").into_bytes();
        let fixture = SwapDir::new();
        let source = fixture.0.join(format!("selected-{index}"));
        let replacement = fixture.0.join(format!("replacement-{index}"));
        std::fs::write(&source, &v1).unwrap();
        std::fs::write(&replacement, &v2).unwrap();

        let observed_bytes = Arc::new(Mutex::new(None));
        let engine = SwapSourceBeforePortableLoad {
            backend,
            source: source.clone(),
            replacement,
            observed_bytes: observed_bytes.clone(),
        };
        let abode = Ed25519KeyMaterial::from_seed([60 + index as u8; 32]).unwrap();
        let manifest = signed_manifest_for_backend(
            &format!("portable-swap-{index}"),
            &v1,
            &abode,
            backend,
            abi_tag,
        );
        let kernel = Kernel::new(
            vec![Arc::new(engine)],
            Arc::new(StubSigner::new("test-node")),
            Arc::new(Ed25519Verifier),
            Arc::new(SignedPolicy::new(vec![abode.public_hex().to_string()])),
            64,
        );

        let id = kernel
            .load(manifest, Artifact::Path(source.clone()))
            .expect("prepared portable bytes remain loadable after source swap");
        assert_eq!(std::fs::read(&source).unwrap(), v2, "engine hook replaced the source");
        assert_eq!(
            observed_bytes.lock().unwrap_or_else(|poison| poison.into_inner()).as_deref(),
            Some(v1.as_slice()),
            "{backend:?} engine must receive the admission-hashed v1 bytes"
        );
        kernel.unload(id, Deadline::default()).unwrap();
    }
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

#[test]
fn native_source_path_swap_cannot_diverge_loaded_bytes_from_admission_identity() {
    use aether::{Address, Deadline, Dispatch};
    use sigil::Capabilities;
    use std::time::Duration;

    let v1_bytes = std::fs::read(native_cdylib("echo_daemon")).expect("read native v1");
    let v2_bytes = std::fs::read(native_cdylib("echo_daemon_v2")).expect("read native v2");
    let fixture = SwapDir::new();
    let source = fixture.0.join("selected.so");
    let replacement = fixture.0.join("replacement.so");
    std::fs::write(&source, &v1_bytes).expect("write selected v1 source");
    std::fs::write(&replacement, &v2_bytes).expect("write replacement v2 source");

    let staged_path = Arc::new(Mutex::new(None));
    let engine = SwapSourceBeforeNativeLoad {
        source: source.clone(),
        replacement,
        staged_path: staged_path.clone(),
    };
    let abode = Ed25519KeyMaterial::from_seed([43u8; 32]).unwrap();
    let manifest = signed_manifest("echo-daemon-swap-proof", &v1_bytes, &abode);
    let kernel = Kernel::new(
        vec![Arc::new(engine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![abode.public_hex().to_string()])),
        64,
    );

    let id = kernel
        .load(manifest, Artifact::Path(source.clone()))
        .expect("the admitted v1 stage loads even after the source path is replaced");
    assert_eq!(std::fs::read(&source).unwrap(), v2_bytes, "the engine hook really replaced v1");
    let stage =
        staged_path.lock().unwrap_or_else(|poison| poison.into_inner()).clone().expect(
            "Kernel must give NativeEngine the admission-hashed stage, not the source path",
        );
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let stage_dir = stage.parent().unwrap().to_path_buf();
    assert_eq!(std::fs::read(&stage).unwrap(), v1_bytes, "the retained stage is admitted v1");
    let identity = kernel.loaded_manifest_identity(id).expect("loaded identity");
    let v1_hash = sha256_hex(&v1_bytes);
    assert_eq!(identity.artifact_sha256.as_deref(), Some(v1_hash.as_str()));

    let (probe, bus, rx) = kernel.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(Address::Creature(id), b"abc".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .unwrap();
    let reply = rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(reply.payload, b"cba", "v1 must run; v2 would append its 0x02 sentinel");

    assert!(stage.exists(), "the exact stage remains while the module is loaded");
    kernel.unload(id, Deadline::default()).unwrap();
    assert!(!stage.exists(), "clean unload releases the staged artifact after dlclose");
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    assert!(!stage_dir.exists(), "clean unload removes the private staging directory");
}

#[test]
fn native_bytes_use_one_admission_hashed_stage_for_the_loaded_lifetime() {
    use aether::Deadline;

    let bytes = std::fs::read(native_cdylib("echo_daemon")).expect("read native bytes");
    let abode = Ed25519KeyMaterial::from_seed([44u8; 32]).unwrap();
    let manifest = signed_manifest("echo-daemon-byte-stage", &bytes, &abode);
    let staged_path = Arc::new(Mutex::new(None));
    let kernel = Kernel::new(
        vec![Arc::new(CaptureNativeStage { staged_path: staged_path.clone() })],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![abode.public_hex().to_string()])),
        64,
    );

    let id = kernel.load(manifest, Artifact::Bytes(bytes.clone())).expect("native bytes load");
    let stage = staged_path
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
        .expect("native bytes must be staged before admission and engine load");
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let stage_dir = stage.parent().unwrap().to_path_buf();
    assert_eq!(std::fs::read(&stage).unwrap(), bytes);
    assert!(stage.exists(), "native byte stage is retained with the loaded library");

    kernel.unload(id, Deadline::default()).unwrap();
    assert!(!stage.exists(), "native byte stage is released only after dlclose");
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    assert!(!stage_dir.exists(), "native byte staging directory is removed on clean unload");
}

#[test]
fn caller_prepared_native_stage_obeys_the_platform_trust_boundary() {
    let v1_bytes = std::fs::read(native_cdylib("echo_daemon")).expect("read native v1");
    let v2_bytes = std::fs::read(native_cdylib("echo_daemon_v2")).expect("read native v2");
    let abode = Ed25519KeyMaterial::from_seed([45u8; 32]).unwrap();
    let manifest = signed_manifest("external-prepared-stage", &v1_bytes, &abode);

    // This is deliberately the public pre-stage path a caller could retain. Linux makes it a sealed
    // kernel capability and safely reuses it; the non-Linux fallback must treat it as mutable and
    // copy/remeasure at the Kernel boundary.
    let external = Artifact::Bytes(v1_bytes.clone())
        .prepare_for_load(&manifest)
        .expect("external caller can prepare a native artifact");
    let external_path = external.staged_native_path().unwrap().to_path_buf();

    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        use aether::Deadline;

        overwrite_staged_file(&external_path, &v2_bytes)
            .expect_err("sealed memfd must reject same-UID chmod/write tampering");
        assert_eq!(std::fs::read(&external_path).unwrap(), v1_bytes);
        let loaded_stage = Arc::new(Mutex::new(None));
        let kernel = Kernel::new(
            vec![Arc::new(CaptureNativeStage { staged_path: loaded_stage.clone() })],
            Arc::new(StubSigner::new("test-node")),
            Arc::new(Ed25519Verifier),
            Arc::new(SignedPolicy::new(vec![abode.public_hex().to_string()])),
            64,
        );
        let id = kernel.load(manifest, external).expect("sealed prepared stage loads");
        assert_eq!(
            loaded_stage.lock().unwrap_or_else(|poison| poison.into_inner()).as_ref(),
            Some(&external_path),
            "Kernel may safely reuse the already sealed capability"
        );
        kernel.unload(id, Deadline::default()).unwrap();
        assert!(!external_path.exists(), "unload closes the last retained memfd capability");
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    {
        overwrite_staged_file(&external_path, &v2_bytes).unwrap();
        let kernel = kernel_with_signed_policy(vec![abode.public_hex().to_string()]);
        let error = kernel.load(manifest, external).expect_err(
            "Kernel must freshly copy/hash the mutated fallback and reject its v1 manifest",
        );
        assert!(
            matches!(error, KernelError::AdmissionRejected(ref detail)
                if detail.contains("integrity") || detail.contains("bytes")),
            "mutated caller stage must fail at fresh admission, got {error:?}"
        );
        assert!(!external_path.exists(), "the untrusted caller stage is cleaned after restaging");
    }
}

#[test]
fn caller_prepared_native_stage_is_rejected_for_a_non_native_backend() {
    let daemon = Manifest::new("native-stage", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    let staged = Artifact::Bytes(b"not a real library".to_vec())
        .prepare_for_load(&daemon)
        .expect("prepare native fixture");
    let stage_path = staged.staged_native_path().unwrap().to_path_buf();
    let beast = Manifest::new("wrong-tier", "0.1.0", Backend::Beast, "gawd_creature_v1");
    let kernel = Kernel::new(
        vec![Arc::new(WasmEngine::new())],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![])),
        64,
    );

    let error = kernel
        .load(beast, staged)
        .expect_err("a native stage must never cross into a non-native engine");
    assert!(
        matches!(error, KernelError::Engine(EngineError::Load(ref detail))
            if detail.contains("non-daemon")),
        "cross-tier staged artifact must fail before admission/load, got {error:?}"
    );
    assert!(!stage_path.exists(), "rejected cross-tier stage is cleaned");
}

#[test]
fn native_engine_load_failure_cleans_the_kernel_owned_stage() {
    let bytes = b"not an ELF shared object".to_vec();
    let abode = Ed25519KeyMaterial::from_seed([46u8; 32]).unwrap();
    let manifest = signed_manifest("invalid-native", &bytes, &abode);
    let staged_path = Arc::new(Mutex::new(None));
    let kernel = Kernel::new(
        vec![Arc::new(CaptureNativeStage { staged_path: staged_path.clone() })],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![abode.public_hex().to_string()])),
        64,
    );

    let error = kernel
        .load(manifest, Artifact::Bytes(bytes))
        .expect_err("invalid native bytes must fail in dlopen");
    assert!(matches!(error, KernelError::Engine(EngineError::Load(_))));
    let stage = staged_path
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .clone()
        .expect("the real native engine received a prepared stage");
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    let stage_dir = stage.parent().unwrap().to_path_buf();
    assert!(!stage.exists(), "failed dlopen drops and removes the staged file");
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    assert!(!stage_dir.exists(), "failed dlopen removes the staging directory");
}
