//! The model-backed authoring loop, end-to-end — hermetic (no network).
//!
//! `agent-mind` binds `Role::AUTHORING` exactly like `agent-templated`, but asks an injected
//! [`mind::Model`] for the source + manifest stub. These tests use the zero-dep [`mind::FakeModel`] /
//! [`mind::SlowModel`] so the full author → build → admit → load → run loop (and the off-drain-worker
//! shutdown contract) is provable offline, with the same kernel admission gates the real path uses.
//!
//! Coverage:
//! - **happy path** — `loop_reverse_authored_built_loaded_run_correct` (FakeModel always-good).
//! - **compile-error retry via the real `prev_error` prompt path** —
//!   `loop_compile_error_recovers_via_prev_error_then_builds` (FakeModel broken→fixed).
//! - **model error → structured Failed, node survives** — `backend_error_yields_failed_reply`.
//! - **off-drain emit delivers when the worker completes** — `offdrain_emit_delivers_reply`.
//! - **in-flight unload is bounded + drops the reply, no thread leak** —
//!   `inflight_unload_is_bounded_and_drops_reply` (SlowModel, the load-bearing shutdown test).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, Bus, BusHandle, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier, InboxReceiver,
    Role,
};
use agent_mind::AgentMind;
use agent_templated::{AuthoringReply, AuthoringRequest, AuthoringResponse};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use build_cargo::{BuildCargo, BuildConfig, BuildErrorKind, BuildOp, BuildReply, Sandbox};
use build_critter::{BuildCritter, BuildCritterOp};
use mind::{FakeModel, Model, SlowModel};
use policy_signed::SignedPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};

fn slow_factor() -> u64 {
    std::env::var("GAWD_SLOW_TEST")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n >= 1)
        .unwrap_or(1)
}
fn scaled(d: Duration) -> Duration {
    d * (slow_factor() as u32)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

/// Share one canonical authoring cache across Omni, demos, and every Cargo-backed authoring proof.
/// build-cargo materializes a process-unique work dir + per-build cargo crate name, so sharing is
/// collision-safe; the repository's serial defaults avoid lock contention.
fn shared_build_cache() -> PathBuf {
    workspace_root().join("target").join("gawd-build-cache")
}

struct World {
    kernel: Arc<Kernel>,
    agent_id: aether::CreatureId,
    /// build-critter, addressed by id (the no-cargo script-tier builder).
    critter_build_id: aether::CreatureId,
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
}

fn build_world(model: Arc<dyn Model>) -> World {
    let abode = Ed25519KeyMaterial::from_seed([23u8; 32]).expect("ed25519 from seed");
    let author_label = abode.public_hex().to_string();

    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(abode.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![author_label.clone()])),
        128,
    );

    // agent-mind on Role::AUTHORING — the model-backed author under test.
    let agent_id = kernel
        .load_instance(signed_boot_manifest("agent-mind", &abode), Box::new(AgentMind::new(model)))
        .expect("agent-mind admits");
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);

    // build-cargo on Role::BUILD — compiles + signs the authored daemon source.
    let mut build_cfg = BuildConfig::with_workspace_root(
        workspace_root().join("cosmos"),
        abode.clone(),
        author_label.clone(),
    );
    build_cfg.target_dir = shared_build_cache();
    build_cfg.sandbox = Sandbox::None;
    build_cfg.cargo_timeout = scaled(Duration::from_secs(300));
    let build_id = kernel
        .load_instance(
            signed_boot_manifest("build-cargo", &abode),
            Box::new(BuildCargo::new(build_cfg)),
        )
        .expect("build-cargo admits");
    kernel.bind_role(Role::new(Role::BUILD), build_id);

    // build-critter — the no-cargo script-tier builder, addressed by id (the sandboxed safe-tier path).
    let critter_build_id = kernel
        .load_instance(
            signed_boot_manifest("build-critter", &abode),
            Box::new(BuildCritter::new(abode.clone(), author_label)),
        )
        .expect("build-critter admits");

    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    World { kernel, agent_id, critter_build_id, probe_bus, probe_rx }
}

fn signed_boot_manifest(name: &str, abode: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(abode.public_hex().to_string());
    m.provenance.signature = Some(abode.sign(&m.signing_payload()));
    m
}

/// Send an `AuthoringRequest` to `Role::AUTHORING` and wait for the (off-drain) reply.
fn author(world: &World, req: AuthoringRequest, corr: u64) -> AuthoringReply {
    let payload = serde_json::to_vec(&req).expect("serialize AuthoringRequest");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("send to authoring");
    let env = recv_with_corr(&world.probe_rx, corr, scaled(Duration::from_secs(5)))
        .expect("authoring reply");
    serde_json::from_slice(&env.payload).expect("deserialize AuthoringReply")
}

fn author_ok(world: &World, req: AuthoringRequest, corr: u64) -> AuthoringResponse {
    match author(world, req, corr) {
        AuthoringReply::Authored(r) => r,
        AuthoringReply::Failed(e) => panic!("authoring failed: {e:?}"),
    }
}

fn build(world: &World, resp: &AuthoringResponse, corr: u64) -> BuildReply {
    let op = BuildOp::Build {
        crate_name: resp.crate_name.clone(),
        crate_version: resp.crate_version.clone(),
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
        deps: resp.deps.clone(),
    };
    let payload = serde_json::to_vec(&op).expect("serialize BuildOp");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::BUILD)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("send to build");
    let env = recv_with_corr(&world.probe_rx, corr, scaled(Duration::from_secs(360)))
        .expect("build reply");
    serde_json::from_slice(&env.payload).expect("deserialize BuildReply")
}

fn recv_with_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<aether::Envelope> {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            Ok(_) => continue,
            Err(_) => continue,
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn count_threads() -> usize {
    std::fs::read_dir("/proc/self/task").map(|d| d.count()).unwrap_or(0)
}

// =================================================================================================
// (1) happy path: model authors a reverse daemon, built, loaded, correct output.
// =================================================================================================

#[test]
fn loop_reverse_authored_built_loaded_run_correct() {
    let world = build_world(Arc::new(FakeModel::always_good()));

    let resp = author_ok(
        &world,
        AuthoringRequest {
            request: "write a daemon that reverses a string".into(),
            ..Default::default()
        },
        1,
    );
    assert_eq!(resp.crate_name, "reverse-daemon");
    assert_eq!(resp.template, "agent-mind", "the model-backed author labels its output");

    let (manifest, artifact) = match build(&world, &resp, 2) {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => {
            panic!("expected Built, got Failed({kind:?}): {message}\n--- stderr ---\n{stderr}")
        }
    };
    assert!(manifest.provenance.signature.is_some(), "build creature signs");

    let id =
        world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("authored creature loads");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(3),
        )
        .expect("send to authored creature");
    let echo = recv_with_corr(&world.probe_rx, 3, scaled(Duration::from_secs(5)))
        .expect("authored replies");
    assert_eq!(echo.payload, b"cba", "model-authored reverse-daemon reverses bytes");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (1b) the sandboxed critter (script) tier: a critter request routes the model to Rhai output, which
//      build-critter validates + signs (no cargo) and the ScriptEngine loads + runs. This is the
//      "safe tier" opt-in — proving it actually works with the model author, not just agent-templated.
// =================================================================================================

#[test]
fn loop_critter_authored_built_loaded_run_correct() {
    let world = build_world(Arc::new(FakeModel::always_good()));

    let resp = author_ok(
        &world,
        AuthoringRequest { request: "reverse the bytes as a critter".into(), ..Default::default() },
        1,
    );
    assert_eq!(resp.template, "agent-mind-critter", "a critter request authors the script tier");
    assert!(resp.source.contains("fn handle(env)"), "model authored Rhai, not Rust");

    let op = BuildCritterOp::Author {
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
    };
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(world.critter_build_id), op.to_bytes())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(2),
        )
        .expect("send to build-critter");
    let env = recv_with_corr(&world.probe_rx, 2, scaled(Duration::from_secs(10)))
        .expect("build-critter reply");
    let (manifest, artifact) = match serde_json::from_slice::<BuildReply>(&env.payload).unwrap() {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, .. } => {
            panic!("critter build failed ({kind:?}): {message}")
        }
    };

    let id = world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("critter loads");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(3),
        )
        .expect("send to authored critter");
    let echo = recv_with_corr(&world.probe_rx, 3, scaled(Duration::from_secs(5)))
        .expect("authored critter replies");
    assert_eq!(echo.payload, b"cba", "model-authored reverse-critter reverses bytes");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (2) compile-error retry via the real prev_error prompt path: broken → fixed.
// =================================================================================================

#[test]
fn loop_compile_error_recovers_via_prev_error_then_builds() {
    let world = build_world(Arc::new(FakeModel::broken_then_fixed()));

    // First attempt (no prev_error) → the fake returns intentionally broken source → Compile failure.
    let broken = author_ok(
        &world,
        AuthoringRequest {
            request: "write a daemon that reverses a string".into(),
            ..Default::default()
        },
        1,
    );
    let stderr = match build(&world, &broken, 2) {
        BuildReply::Failed { kind: BuildErrorKind::Compile, stderr, .. } => stderr,
        BuildReply::Failed { kind, message, .. } => {
            panic!("expected Compile, got {kind:?}: {message}")
        }
        BuildReply::Built { .. } => panic!("broken source must not Build"),
    };
    assert!(!stderr.is_empty(), "compile failure carries stderr substance");

    // Second attempt WITH the real prev_error → the fake (keying on the retry marker the prompt
    // builder injects) returns the fixed source → Build succeeds.
    let fixed = author_ok(
        &world,
        AuthoringRequest {
            request: "write a daemon that reverses a string".into(),
            prev_error: Some(stderr),
        },
        3,
    );
    let (manifest, artifact) = match build(&world, &fixed, 4) {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => {
            panic!("recovery expected Built, got Failed({kind:?}): {message}\n{stderr}")
        }
    };
    let id = world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("recovered build loads");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"xyz".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(5),
        )
        .expect("send to recovered creature");
    let echo = recv_with_corr(&world.probe_rx, 5, scaled(Duration::from_secs(5)))
        .expect("recovered replies");
    assert_eq!(echo.payload, b"zyx");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (3) model error → structured Failed reply, node survives.
// =================================================================================================

#[test]
fn backend_error_yields_failed_reply() {
    let world = build_world(Arc::new(FakeModel::erroring()));

    match author(&world, AuthoringRequest { request: "reverse".into(), ..Default::default() }, 1) {
        AuthoringReply::Failed(_) => {}
        AuthoringReply::Authored(r) => panic!("expected Failed, got Authored({})", r.crate_name),
    }
    // The node survived: the agent is still bound and answers again (another Failed), no crash.
    match author(
        &world,
        AuthoringRequest { request: "reverse again".into(), ..Default::default() },
        2,
    ) {
        AuthoringReply::Failed(_) => {}
        other => panic!("expected a second Failed, got {other:?}"),
    }

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (4a) off-drain emit delivers the reply once the (slow) worker completes in time.
// =================================================================================================

#[test]
fn offdrain_emit_delivers_reply() {
    let slow = Arc::new(SlowModel::new());
    let world = build_world(slow.clone());

    let payload =
        serde_json::to_vec(&AuthoringRequest { request: "reverse".into(), ..Default::default() })
            .unwrap();
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(1),
        )
        .expect("send to authoring");

    // The worker is provably in-flight (blocked in the model) — handle has already returned.
    wait_until(|| slow.has_entered(), Duration::from_secs(2));
    assert!(slow.has_entered(), "worker entered the model call off-drain");

    // Release in time → the worker emits the reply through the captured bus.
    slow.release();
    let env = recv_with_corr(&world.probe_rx, 1, scaled(Duration::from_secs(5)))
        .expect("off-drain worker delivered the reply");
    match serde_json::from_slice::<AuthoringReply>(&env.payload).unwrap() {
        AuthoringReply::Authored(r) => assert_eq!(r.crate_name, "reverse-daemon"),
        other => panic!("expected Authored, got {other:?}"),
    }

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (4b) in-flight unload is bounded, drops the reply cleanly, and leaks no thread (the load-bearing
//      shutdown test the instant-fake happy path does NOT cover).
// =================================================================================================

#[test]
fn inflight_unload_is_bounded_and_drops_reply() {
    let slow = Arc::new(SlowModel::new());
    let world = build_world(slow.clone());

    #[cfg(target_os = "linux")]
    let before = count_threads();

    let payload =
        serde_json::to_vec(&AuthoringRequest { request: "reverse".into(), ..Default::default() })
            .unwrap();
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(1),
        )
        .expect("send to authoring");
    wait_until(|| slow.has_entered(), Duration::from_secs(2));
    assert!(slow.has_entered() && !slow.has_finished(), "worker is provably still in-flight");

    // Unload with a short deadline while the worker is blocked: shutdown must return promptly
    // (deadline-bounded polling join), detaching the straggler rather than hanging.
    let t = Instant::now();
    let _ = world.kernel.unload(
        world.agent_id,
        Deadline::from_millis(scaled(Duration::from_millis(300)).as_millis() as u64),
    );
    let elapsed = t.elapsed();
    assert!(
        elapsed < scaled(Duration::from_secs(3)),
        "in-flight unload must be bounded, took {elapsed:?}"
    );

    // Release the straggler. Because shutdown set `stop`, the worker drops its reply on return —
    // and even an emit would be a clean NoSuchModule (agent-mind is in-process; no unmapped code).
    slow.release();
    wait_until(|| slow.has_finished(), Duration::from_secs(2));
    assert!(slow.has_finished(), "the detached worker finished cleanly after release");

    // No reply was delivered for corr=1 (the stopped worker dropped it).
    assert!(
        recv_with_corr(&world.probe_rx, 1, Duration::from_millis(300)).is_none(),
        "a stopped worker must not deliver its reply"
    );

    // The detached worker thread does not persist (it ran to completion and exited).
    #[cfg(target_os = "linux")]
    {
        std::thread::sleep(Duration::from_millis(200));
        let after = count_threads();
        assert!(after <= before, "worker thread must not leak (before={before}, after={after})");
    }

    world.kernel.shutdown_all(Deadline::default());
}

fn wait_until(mut cond: impl FnMut() -> bool, budget: Duration) {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if cond() {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
