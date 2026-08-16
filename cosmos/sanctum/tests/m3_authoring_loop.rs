//! The self-authoring loop, end-to-end.
//!
//! One in-process kernel with two creatures bound:
//! - `agent-templated` on `Role::AUTHORING` — produces source + manifest stub from a request.
//! - `build-cargo` on `Role::BUILD` — compiles, signs, returns admissible `(manifest, artifact)`.
//!
//! The kernel's admission gates (signed policy + entrypoint validation) approve
//! the result; `Kernel::load` admits via the safe loader; the new creature is invoked end-to-end.
//!
//! ## Exit criteria covered
//! - **(a) reverse-string daemon authored, built, loaded, correct output** —
//!   `loop_a_reverse_string_authored_built_loaded_run_correct`.
//! - **(b) harder request (fetch URL → title)** —
//!   `loop_b_fetch_url_title_authored_built_loaded_run_against_local_http_server`.
//! - **(c) compile error auto-recovers within a retry budget, node never crashes** —
//!   `loop_c_compile_error_recovers_in_retry_budget_without_crashing_the_node`.
//! - **(d) manifest/entrypoints violation rejected at load with structured reason** —
//!   `loop_d_inadmissible_manifest_rejected_at_load_with_structured_reason`.
//! - **(e) compile runs in an operator-opt-in sandbox** —
//!   `loop_e_sandbox_seam_is_invoked_when_operator_opts_in`.
//!
//! ## Wall-clock honesty
//! Cargo invocations dominate. The first build in a fresh `target/gawd-build-cache/` compiles
//! forge + aether + sigil + sha2 + serde_json + serde + libloading + ring + thiserror —
//! 30–60s cold. Subsequent builds reuse those artifacts and finish in <5s. The tests run safely
//! under the repository's serial test default: each test gets its own `LoopWorld` (kernel + agent +
//! build creature), and `BuildCargo` materializes a process-unique `work_dir` per invocation so
//! two parallel builds for the same `crate_name` (multiple tests build `reverse-daemon`) can't
//! collide and fingerprint-poison each other. They share a single cargo target dir so
//! transitive deps (forge + aether + …) compile once and are cached for every subsequent
//! invocation; cargo's own file lock serializes concurrent invocations against that target.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use aether::{
    Address, Bus, BusHandle, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier, InboxReceiver,
    Role,
};
use agent_templated::{
    AgentTemplated, AuthoringReply, AuthoringRequest, AuthoringResponse, DRILL_PREFIX,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use build_cargo::{BuildCargo, BuildConfig, BuildErrorKind, BuildOp, BuildReply, Sandbox};
use policy_signed::SignedPolicy;
use sanctum::{Kernel, KernelError};
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Entrypoint, Manifest, ManifestError};

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

/// Absolute path to the true workspace root. `CARGO_MANIFEST_DIR` for sanctum is
/// `<root>/cosmos/sanctum`, so the root that owns `target/` is two levels up. The build
/// creature's path-dep base is `<root>/cosmos` (where forge/aether/sigil live).
fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

/// Canonical Cargo target directory shared by every authoring test/demo. It is separate from the
/// workspace's own `target/debug` graph, while process-unique authored crate names and serial
/// repository defaults make cross-harness reuse collision-safe.
fn shared_build_cache() -> PathBuf {
    workspace_root().join("target").join("gawd-build-cache")
}

/// The world for an authoring loop: kernel, agent endpoint id, build endpoint id, and the Abode signing
/// key the build creature seals its manifests with (also the only allowlisted author).
struct LoopWorld {
    kernel: Arc<Kernel>,
    /// Probe endpoint the test uses to send to agent/build and receive replies.
    probe_bus: BusHandle,
    probe_rx: InboxReceiver,
    /// Abode key — referenced so the test can also sign things directly when needed (criterion d
    /// uses this).
    abode: Ed25519KeyMaterial,
    /// What `author_label` the build creature writes into `provenance.author` — also what we
    /// put on the policy allowlist.
    author_label: String,
}

fn build_loop_world(sandbox: Sandbox) -> LoopWorld {
    // ---- keys ----
    // One Abode key. The build creature signs every authored manifest with this key; the
    // SignedPolicy on the kernel allowlists exactly its hex pubkey.
    let abode = Ed25519KeyMaterial::from_seed([19u8; 32]).expect("ed25519 from seed");
    let author_label = abode.public_hex().to_string();

    // ---- kernel ----
    // SignedPolicy with allowlist = [abode.pubkey] enforces (i) every load carries a signature,
    // (ii) the signature verifies, (iii) the artifact bytes hash matches `build_hash`, (iv) the
    // author is on the allowlist. That admission contract is honored by the authoring outputs unchanged —
    // the whole point is that build-cargo produces results that *already* satisfy it.
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(abode.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![author_label.clone()])),
        128,
    );

    // ---- agent on Role::AUTHORING ----
    // Boot-creature signed manifest (no artifact bytes; admission's artifact-hash gate skips on
    // `had_artifact == false`). We sign with the Abode key so the policy allowlist accepts it.
    let agent_manifest = signed_boot_manifest("agent-templated", &abode);
    let agent_id = kernel
        .load_instance(agent_manifest, Box::new(AgentTemplated::new()))
        .expect("agent admits");
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);

    // ---- build on Role::BUILD ----
    let build_manifest = signed_boot_manifest("build-cargo", &abode);
    let mut build_cfg = BuildConfig::with_workspace_root(
        workspace_root().join("cosmos"),
        abode.clone(),
        author_label.clone(),
    );
    build_cfg.target_dir = shared_build_cache();
    build_cfg.sandbox = sandbox;
    // 5-minute budget per cargo invocation: comfortable for the cold first build (forge +
    // aether + transitive crates can take 60s on a debug-mode test runner) and gates a runaway
    // before it hangs the test.
    build_cfg.cargo_timeout = scaled(Duration::from_secs(300));
    let build_id = kernel
        .load_instance(build_manifest, Box::new(BuildCargo::new(build_cfg)))
        .expect("build-cargo admits");
    kernel.bind_role(Role::new(Role::BUILD), build_id);

    // ---- probe endpoint for the test ----
    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());

    LoopWorld { kernel, probe_bus, probe_rx, abode, author_label }
}

fn signed_boot_manifest(name: &str, abode: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(abode.public_hex().to_string());
    let sig = abode.sign(&m.signing_payload());
    m.provenance.signature = Some(sig);
    m
}

/// Send an `AuthoringRequest` to `Role::AUTHORING` and wait for the reply. Returns
/// `AuthoringResponse` on success, panics with the structured failure otherwise (test ergonomics).
fn author(world: &LoopWorld, req: AuthoringRequest, corr: u64) -> AuthoringResponse {
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
    let reply: AuthoringReply = serde_json::from_slice(&env.payload).expect("deserialize reply");
    match reply {
        AuthoringReply::Authored(r) => r,
        AuthoringReply::Failed(e) => panic!("authoring failed: {e:?}"),
    }
}

/// Send a `BuildOp::Build` to `Role::BUILD` and wait for the reply. Returns the raw reply so the
/// test can pattern-match on Built vs Failed.
fn build(world: &LoopWorld, op: BuildOp, corr: u64) -> BuildReply {
    let payload = serde_json::to_vec(&op).expect("serialize BuildOp");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Role(Role::new(Role::BUILD)), payload)
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(corr),
        )
        .expect("send to build");
    // Cargo wall-clock budget: 6× the build creature's own timeout to leave headroom for the bus
    // round-trip; the build creature kills its child at its own (configured) cargo_timeout, so the
    // outer recv just has to outlast that.
    let env = recv_with_corr(&world.probe_rx, corr, scaled(Duration::from_secs(360)))
        .expect("build reply");
    serde_json::from_slice(&env.payload).expect("deserialize BuildReply")
}

fn build_op_from(resp: &AuthoringResponse) -> BuildOp {
    BuildOp::Build {
        crate_name: resp.crate_name.clone(),
        crate_version: resp.crate_version.clone(),
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
        deps: resp.deps.clone(),
    }
}

fn recv_with_corr(rx: &InboxReceiver, corr: u64, budget: Duration) -> Option<aether::Envelope> {
    let deadline = std::time::Instant::now() + budget;
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(500))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            Ok(_) => continue, // a stray (e.g. proprio) envelope; keep waiting for our corr
            Err(_) => continue,
        }
    }
    None
}

// =================================================================================================
// (a) reverse-string daemon authored, built, loaded, correct output — zero human edits.
// =================================================================================================

#[test]
fn loop_a_reverse_string_authored_built_loaded_run_correct() {
    let world = build_loop_world(Sandbox::None);

    let resp = author(
        &world,
        AuthoringRequest {
            request: "write a daemon that reverses a string".into(),
            ..Default::default()
        },
        1,
    );
    assert_eq!(resp.crate_name, "reverse-daemon");
    assert_eq!(resp.template, "reverse-daemon");

    let reply = build(&world, build_op_from(&resp), 2);
    let (manifest, artifact) = match reply {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => panic!(
            "expected Built, got Failed({kind:?}): {message}\n--- cargo stderr ---\n{stderr}"
        ),
    };
    // Substantive assertions about what the build produced. The author label + signature must
    // come from the BUILD creature (not the agent); the build_hash must equal sha256(artifact).
    assert_eq!(manifest.provenance.author.as_deref(), Some(world.author_label.as_str()));
    assert!(manifest.provenance.signature.is_some(), "build creature must sign");
    assert!(manifest.provenance.build_hash.is_some(), "build_hash must be set");

    // Admit + load through the kernel — the safe path. The signed policy is in effect, so any
    // tampering would fail here.
    let id = world
        .kernel
        .load(manifest, Artifact::Bytes(artifact))
        .expect("authored creature admits and loads through Kernel::load");

    // Round-trip a payload. The reverse template makes `cba` from `abc`.
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(3),
        )
        .expect("send to authored creature");
    let echo = recv_with_corr(&world.probe_rx, 3, scaled(Duration::from_secs(5)))
        .expect("authored creature replies");
    assert_eq!(echo.payload, b"cba", "authored reverse-daemon reverses bytes");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (b) harder request: fetch URL → title.
// =================================================================================================

#[test]
fn loop_b_fetch_url_title_authored_built_loaded_run_against_local_http_server() {
    let world = build_loop_world(Sandbox::None);

    let resp = author(
        &world,
        AuthoringRequest {
            request: "write a daemon that will fetch a url and return the title".into(),
            ..Default::default()
        },
        1,
    );
    assert_eq!(resp.crate_name, "fetch-url-title");

    let reply = build(&world, build_op_from(&resp), 2);
    let (manifest, artifact) = match reply {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => panic!(
            "fetch-url-title build expected Built, got Failed({kind:?}): {message}\n---\n{stderr}"
        ),
    };
    let id = world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("admits and loads");

    // Stand up a tiny in-test HTTP server that returns a known title. Listening on an ephemeral
    // port keeps the test parallel-safe; we read the bound port from the listener after binding.
    let (port, server_done) = spawn_one_shot_http_server(
        b"<!doctype html><html><head><title>GAWD M3 fetch demo</title></head><body>hello</body></html>"
            .to_vec(),
    );

    let url = format!("http://127.0.0.1:{port}/page");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), url.into_bytes())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(3),
        )
        .expect("send url to authored creature");
    let reply = recv_with_corr(&world.probe_rx, 3, scaled(Duration::from_secs(10)))
        .expect("authored fetch-url-title replies");
    let title = String::from_utf8_lossy(&reply.payload).to_string();
    assert_eq!(
        title, "GAWD M3 fetch demo",
        "authored creature extracts <title> from a real HTTP fetch"
    );

    // The server thread exits after one request; join for hygiene.
    let _ = server_done.join();

    let (port, server_done) = spawn_one_shot_http_server(vec![b'x'; 1024 * 1024 + 1]);
    let url = format!("http://127.0.0.1:{port}/too-large");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), url.into_bytes())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(4),
        )
        .expect("send oversized-response url to authored creature");
    let reply = recv_with_corr(&world.probe_rx, 4, scaled(Duration::from_secs(10)))
        .expect("authored fetch-url-title replies to oversized response");
    let message = String::from_utf8_lossy(&reply.payload).to_string();
    assert!(
        message.contains("response too large"),
        "authored creature reports the response cap, got {message:?}"
    );
    let _ = server_done.join();

    world.kernel.shutdown_all(Deadline::default());
}

/// A one-shot HTTP/1.0 responder on `127.0.0.1:0` (ephemeral port). Returns `(port, join_handle)`.
/// Serves `body` with a known minimal response, then closes. Test-grade only.
fn spawn_one_shot_http_server(body: Vec<u8>) -> (u16, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        if let Ok((mut s, _)) = listener.accept() {
            // Read request bytes until EOF or `\r\n\r\n`; we don't actually care what the request
            // looks like — the authored creature opens, sends GET, reads, closes.
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            let mut buf = [0u8; 4096];
            let _ = s.read(&mut buf);
            let headers = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = s.write_all(headers.as_bytes());
            let _ = s.write_all(&body);
            let _ = s.shutdown(std::net::Shutdown::Write);
        }
    });
    (port, handle)
}

// =================================================================================================
// (c) compile error auto-recovers within a retry budget, node never crashes.
// =================================================================================================

#[test]
fn loop_c_compile_error_recovers_in_retry_budget_without_crashing_the_node() {
    let world = build_loop_world(Sandbox::None);

    // Drill prefix + no prev_error — the templated agent returns intentionally broken source.
    // The `[drill]` prefix is private to `agent-templated`; a real LLM-backed authoring creature
    // would treat it as ordinary prompt text and ignore the convention — exactly the point of
    // moving the drill knob off the substrate-wide `AuthoringRequest` contract.
    let bad = author(
        &world,
        AuthoringRequest {
            request: format!("{DRILL_PREFIX} write a daemon that reverses a string"),
            ..Default::default()
        },
        1,
    );
    assert_eq!(bad.template, "recovery-drill-broken");
    let bad_reply = build(&world, build_op_from(&bad), 2);
    let stderr = match bad_reply {
        BuildReply::Failed { kind: BuildErrorKind::Compile, stderr, .. } => stderr,
        BuildReply::Failed { kind, message, .. } => {
            panic!("expected Compile failure, got Failed({kind:?}): {message}")
        }
        BuildReply::Built { .. } => panic!("intentionally broken source must not Build"),
    };
    assert!(!stderr.is_empty(), "cargo stderr must carry the compile error substance");

    // The node is unharmed: the build creature is still bound, the agent is still bound. We use
    // the kernel to confirm both are still loaded — a panic anywhere in the build path would
    // have pulled the creature off the bus (or, worse, crashed the kernel).
    // We assert this by simply running the SUCCESS path next: the same kernel, same creatures,
    // but the drill's second call (with `prev_error` populated) returns a fixed source.
    let fixed = author(
        &world,
        AuthoringRequest {
            request: format!("{DRILL_PREFIX} write a daemon that reverses a string"),
            prev_error: Some(stderr),
        },
        3,
    );
    assert_eq!(fixed.template, "recovery-drill-fixed");
    let good_reply = build(&world, build_op_from(&fixed), 4);
    let (manifest, artifact) = match good_reply {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, stderr, .. } => {
            panic!("expected recovery to Build, got Failed({kind:?}): {message}\n{stderr}")
        }
    };

    // Loaded + invoked correctly — the loop made progress after a structured failure, with no
    // restart, no node crash. The retry budget consumed one extra cycle.
    let id =
        world.kernel.load(manifest, Artifact::Bytes(artifact)).expect("recovered build admits");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"xyz".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(5),
        )
        .expect("send to recovered creature");
    let echo = recv_with_corr(&world.probe_rx, 5, scaled(Duration::from_secs(5)))
        .expect("recovered creature replies");
    assert_eq!(echo.payload, b"zyx");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (d) manifest/entrypoints violation rejected at load with a structured reason.
// =================================================================================================

/// Two flavours: (i) the manifest validation gate fires structurally even without going through the
/// build (cheap unit-test-shaped assertion); (ii) the gate fires through `Kernel::load` so the
/// substrate-side wiring is honest. We do both to make the failure mode unambiguous.
#[test]
fn loop_d_inadmissible_manifest_rejected_at_load_with_structured_reason() {
    let world = build_loop_world(Sandbox::None);

    // ---- (i) the validation-mechanism level: duplicate entrypoint names ----
    let mut tampered = Manifest::new("rogue", "0.1.0", Backend::Daemon, "gawd_creature_v1");
    tampered.entrypoints = vec![
        Entrypoint::new("handle", "(Envelope) -> Outcome"),
        Entrypoint::new("handle", "(Envelope) -> Outcome"),
    ];
    let err = tampered.validate().unwrap_err();
    match err {
        ManifestError::Invalid(m) => {
            assert!(m.contains("duplicate entrypoint"), "validation must name the violation: {m}")
        }
        other => panic!("expected Invalid, got {other:?}"),
    }

    // ---- (ii) the kernel-load-path level: same violation, surfaced as AdmissionRejected ----
    // Sign the bad manifest so the SignedPolicy doesn't reject earlier on signature shape — we
    // want the rejection to come from the entrypoint gate inside the admission mechanism.
    let mut bad = tampered.clone();
    bad.provenance.author = Some(world.author_label.clone());
    bad.provenance.signature = Some(world.abode.sign(&bad.signing_payload()));

    // We do NOT need real artifact bytes for this test — the manifest validation fires FIRST
    // (before the artifact-hash check), so a fake artifact will do; the kernel will reject on
    // the structural shape and never read the bytes.
    let err = world.kernel.load(bad, Artifact::Bytes(b"not actually a .so".to_vec())).unwrap_err();
    match err {
        KernelError::Manifest(ManifestError::Invalid(m)) => assert!(
            m.contains("duplicate entrypoint"),
            "kernel surfaces the structural reason: {m}"
        ),
        KernelError::AdmissionRejected(m) => {
            assert!(m.contains("duplicate entrypoint"), "rejection should name the violation: {m}")
        }
        other => panic!("expected manifest-shape rejection, got {other:?}"),
    }

    // Sanity: the node is unharmed — the next sound load still works.
    let resp = author(
        &world,
        AuthoringRequest { request: "reverse a string".into(), ..Default::default() },
        1,
    );
    let reply = build(&world, build_op_from(&resp), 2);
    let (m, a) = match reply {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        other => panic!("post-rejection build must still work: {other:?}"),
    };
    let id = world.kernel.load(m, Artifact::Bytes(a)).expect("post-rejection load succeeds");
    world
        .probe_bus
        .emit(
            Dispatch::to(Address::Creature(id), b"ok".to_vec())
                .with_reply_to(Address::Creature(world.probe_bus.id()))
                .with_corr(7),
        )
        .expect("send after rejection-survived");
    let echo = recv_with_corr(&world.probe_rx, 7, scaled(Duration::from_secs(5))).unwrap();
    assert_eq!(echo.payload, b"ko");

    world.kernel.shutdown_all(Deadline::default());
}

// =================================================================================================
// (e) compile runs in an operator-opt-in sandbox.
// =================================================================================================

/// The seam is a `Custom(Vec<String>)` prefix the operator supplies. We prove it's wired by
/// supplying a prefix that points at a nonexistent binary: the spawn fails fast, and the build
/// creature returns a structured `BuildErrorKind::Io` (sandbox-prefix spawn failure) — never a
/// surprise success that bypassed the wrapper.
#[test]
fn loop_e_sandbox_seam_is_invoked_when_operator_opts_in() {
    let nonexistent = "/does/not/exist/sandbox/wrapper".to_string();
    let world = build_loop_world(Sandbox::Custom(vec![nonexistent.clone(), "--isolate".into()]));

    let resp = author(
        &world,
        AuthoringRequest { request: "reverse a string".into(), ..Default::default() },
        1,
    );
    let reply = build(&world, build_op_from(&resp), 2);
    match reply {
        BuildReply::Failed { kind: BuildErrorKind::Io, message, .. } => {
            assert!(
                message.contains("spawn cargo") || message.contains("No such"),
                "io failure must reference the spawn step: {message}"
            );
        }
        BuildReply::Failed { kind, message, .. } => panic!(
            "expected Io spawn failure proving the sandbox prefix was attempted, got {kind:?}: {message}"
        ),
        BuildReply::Built { .. } => {
            panic!("the sandbox prefix MUST be invoked — Built means it was bypassed")
        }
    }

    // Sanity: with Sandbox::None on a fresh world, the same author/build sequence succeeds, so
    // the failure above is *because* of the operator-opt-in wrapper, not anything else.
    let world_none = build_loop_world(Sandbox::None);
    let resp = author(
        &world_none,
        AuthoringRequest { request: "reverse a string".into(), ..Default::default() },
        1,
    );
    match build(&world_none, build_op_from(&resp), 2) {
        BuildReply::Built { .. } => {}
        other => panic!("Sandbox::None must Build for the contrast assertion to hold: {other:?}"),
    }

    world.kernel.shutdown_all(Deadline::default());
    world_none.kernel.shutdown_all(Deadline::default());
}
