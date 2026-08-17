//! walkthrough — Alpha's GAWD substrate loop, narrated in your terminal.
//!
//! This binary is a thin **narration wrapper** over the exact code paths the integration tests in
//! `cosmos/sanctum/tests/` already prove (`m3_authoring_loop.rs`, `abode_migrate_local.rs`). It exists for
//! one reason: the most striking properties of the substrate — *a reference authoring agent writes,
//! compiles, signs, and runs a creature with no operator edits after the request*, and *a running self
//! performs a cryptographically continuous hand-off between two bodies* — were only ever observable inside
//! `#[test]` functions. Here the phases run against live kernels (the hand-off itself stays within
//! one) and narrate each gate as it passes;
//! `abode_migrate_cross_node.rs` separately proves the transport variant across two Sanctums.
//!
//! Run it:  `cargo run -p walkthrough`
//! (The first run compiles the authored creature's dependencies and is slow — 30–60s — while the
//! shared cargo cache warms; subsequent runs finish in a few seconds.)
//!
//! Everything here uses only the public crate APIs an operator would drive — there is no demo-only
//! back door into the kernel.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{Address, BusHandle, Deadline, Dispatch, Envelope, InboxReceiver, NodeId, Role};
use aether::{Ed25519Signer, Ed25519Verifier};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};

use abode_migrator::{AbodeMigrator, MigratorMsg, SCHEMA as MIGRATOR_SCHEMA};
use agent_templated::{AgentTemplated, AuthoringReply, AuthoringRequest, AuthoringResponse};
use build_cargo::{BuildCargo, BuildConfig, BuildOp, BuildReply, Sandbox};
use build_critter::{BuildCritter, BuildCritterOp};
use policy_abode_allowlist::AbodeAllowlistPolicy;
use policy_signed::SignedPolicy;

// ----- narration ---------------------------------------------------------------------------------

fn banner(title: &str) {
    println!("\n\x1b[1m{title}\x1b[0m");
    println!("{}", "─".repeat(title.chars().count()));
}
fn step(msg: &str) {
    println!("\x1b[36m▸\x1b[0m {msg}");
}
fn ok(msg: &str) {
    println!("  \x1b[32m✓\x1b[0m {msg}");
}
fn note(msg: &str) {
    println!("    {msg}");
}
/// First 12 hex chars of a key/hash — enough to be recognizable without filling the line.
fn short(s: &str) -> String {
    s.chars().take(12).collect()
}

// ----- shared scaffolding (mirrors the authoring / migration test harnesses) ---------------------

fn workspace_root() -> std::path::PathBuf {
    // CARGO_MANIFEST_DIR for this crate is <root>/demos/walkthrough; the true workspace root is two
    // levels up. (build-cargo compiles the authored creature against the SDK crates under
    // <root>/cosmos, so this must resolve to the actual root, not <root>/demos.)
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .map(std::path::PathBuf::from)
        .unwrap_or(manifest_dir)
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

/// Send a dispatch and wait (bounded) for the reply correlated by `corr`.
fn request_reply(
    bus: &BusHandle,
    rx: &InboxReceiver,
    d: Dispatch,
    corr: u64,
    budget: Duration,
) -> Option<Envelope> {
    bus.send(d).ok()?;
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(250))) {
            Ok(env) if env.header.corr == Some(corr) => return Some(env),
            _ => continue, // stray proprio/fitness envelope — keep waiting for our corr
        }
    }
    None
}

// =================================================================================================
// Phase 1 — Self-authoring: a reference agent writes, compiles, signs, and runs with no operator edits.
// =================================================================================================

fn phase_self_authoring() -> Result<(), String> {
    banner("Phase 1 · Self-authoring — a reference agent writes, compiles, signs, and runs code");

    // One Abode key: the authoring identity. The kernel's admission policy allowlists exactly its
    // pubkey, so only work signed by this self is admitted.
    let abode = Ed25519KeyMaterial::from_seed([19u8; 32]).map_err(|e| format!("key: {e}"))?;
    let author = abode.public_hex().to_string();
    note(&format!("Abode (authoring identity): {}…", short(&author)));

    // A live kernel: three engines, real ed25519 signing/verification, a SignedPolicy that requires
    // a valid signature from an allowlisted author + an artifact-hash match. The same gates the
    // tests use — nothing is loosened for the demo.
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(abode.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![author.clone()])),
        128,
    );

    // Self-host the authoring organs: the agent (AUTHORING socket) + the builder (BUILD socket).
    let agent_id = kernel
        .load_instance(
            signed_boot_manifest("agent-templated", &abode),
            Box::new(AgentTemplated::new()),
        )
        .map_err(|e| format!("agent admits: {e}"))?;
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);

    // The SDK crates the authored creature builds against live under cosmos/. One canonical cache
    // under the true workspace root's target/ is shared by all authoring demos/tests; process-unique
    // crate names plus serial defaults make reuse safe and avoid duplicate cold SDK graphs.
    let mut build_cfg = BuildConfig::with_workspace_root(
        workspace_root().join("cosmos"),
        abode.clone(),
        author.clone(),
    );
    build_cfg.target_dir = workspace_root().join("target").join("gawd-build-cache");
    build_cfg.sandbox = Sandbox::None; // operator's choice; the sandbox seam is exercised in m3 tests
    build_cfg.cargo_timeout = Duration::from_secs(300);
    let build_id = kernel
        .load_instance(
            signed_boot_manifest("build-cargo", &abode),
            Box::new(BuildCargo::new(build_cfg)),
        )
        .map_err(|e| format!("build-cargo admits: {e}"))?;
    kernel.bind_role(Role::new(Role::BUILD), build_id);
    ok("substrate booted: AUTHORING + BUILD organs are themselves creatures on the bus");

    let (probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    let reply_to = Address::Creature(probe_id);

    // 1) Ask, in English, for a capability.
    let request = "write a daemon that reverses a string";
    step(&format!("asking the AUTHORING agent (in English): “{request}”"));
    let auth_payload =
        serde_json::to_vec(&AuthoringRequest { request: request.into(), ..Default::default() })
            .map_err(|e| e.to_string())?;
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), auth_payload)
            .with_reply_to(reply_to.clone())
            .with_corr(1),
        1,
        Duration::from_secs(5),
    )
    .ok_or("no reply from the AUTHORING agent")?;
    let resp: AuthoringResponse =
        match serde_json::from_slice::<AuthoringReply>(&env.payload).map_err(|e| e.to_string())? {
            AuthoringReply::Authored(r) => r,
            AuthoringReply::Failed(e) => return Err(format!("authoring failed: {e:?}")),
        };
    ok(&format!(
        "the agent authored crate `{}` ({} bytes of Rust) — no operator edits after the request",
        resp.crate_name,
        resp.source.len()
    ));

    // 2) Compile + sign it. This shells out to a real `cargo build` and seals the result with the
    //    Abode key — the provenance the kernel will check.
    step("handing the source to the BUILD organ → real `cargo build` + ed25519 sign…");
    note("(first run warms the dependency cache and is slow; later runs are fast)");
    let t0 = Instant::now();
    let build_op = BuildOp::Build {
        crate_name: resp.crate_name.clone(),
        crate_version: resp.crate_version.clone(),
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
        deps: resp.deps.clone(),
    };
    let build_payload = serde_json::to_vec(&build_op).map_err(|e| e.to_string())?;
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(Address::Role(Role::new(Role::BUILD)), build_payload)
            .with_reply_to(reply_to.clone())
            .with_corr(2),
        2,
        Duration::from_secs(360),
    )
    .ok_or("no reply from the BUILD organ")?;
    let (manifest, artifact) =
        match serde_json::from_slice::<BuildReply>(&env.payload).map_err(|e| e.to_string())? {
            BuildReply::Built { manifest, artifact } => (manifest, artifact),
            BuildReply::Failed { kind, message, stderr, .. } => {
                return Err(format!(
                    "build failed ({kind:?}): {message}\n--- cargo stderr ---\n{stderr}"
                ))
            }
        };
    let elapsed = t0.elapsed();
    let build_hash = manifest.provenance.build_hash.clone().unwrap_or_default();
    let sig = manifest.provenance.signature.clone().unwrap_or_default();
    ok(&format!(
        "compiled in {:.1}s · {} bytes of native code",
        elapsed.as_secs_f64(),
        artifact.len()
    ));
    ok(&format!(
        "signed by abode {}… · build_hash {}… · sig {}…",
        short(&author),
        short(&build_hash),
        short(&sig)
    ));

    // 3) Admit + hot-load through the kernel. The SignedPolicy verifies the signature, checks the
    //    author allowlist, and recomputes sha256(artifact) == build_hash — any tampering fails here.
    step("admitting through the kernel (signature verifies + author allowlisted + hash matches)…");
    let id = kernel
        .load(manifest, Artifact::Bytes(artifact))
        .map_err(|e| format!("admission/load rejected: {e}"))?;
    ok(&format!("admitted and hot-loaded into the live node as creature id={}", id.0));

    // 4) Use it. The freshly-authored creature reverses bytes.
    step("sending “abc” to the creature the reference agent just wrote…");
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(Address::Creature(id), b"abc".to_vec()).with_reply_to(reply_to).with_corr(3),
        3,
        Duration::from_secs(5),
    )
    .ok_or("no reply from the authored creature")?;
    if env.payload.as_slice() != b"cba" {
        return Err(format!(
            "the authored reverse creature returned {:?}, expected byte-exact `cba`",
            String::from_utf8_lossy(&env.payload)
        ));
    }
    let got = String::from_utf8_lossy(&env.payload);
    ok(&format!(
        "got back “{got}”  — the reference agent authored, compiled, signed, and ran that code."
    ));

    kernel.shutdown_all(Deadline::default());
    Ok(())
}

// =================================================================================================
// Phase 1b — The third tier: a critter (script) authored and run with NO compiler, in milliseconds.
// =================================================================================================

fn phase_critter() -> Result<(), String> {
    banner("Phase 1b · The third tier — a critter (script), authored and run without a compiler");
    note("(Phase 1 shelled out to a real `cargo build` for the native daemon. A critter ships as source — no cargo, no .so — yet loads through the SAME admission → engine → router path, metered and sandboxed.)");

    let abode = Ed25519KeyMaterial::from_seed([0x1Cu8; 32]).map_err(|e| format!("key: {e}"))?;
    let author = abode.public_hex().to_string();
    note(&format!("Abode (authoring identity): {}…", short(&author)));

    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(abode.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![author.clone()])),
        128,
    );

    // The same authoring agent (AUTHORING) + the no-cargo critter builder (BUILD).
    let agent_id = kernel
        .load_instance(
            signed_boot_manifest("agent-templated", &abode),
            Box::new(AgentTemplated::new()),
        )
        .map_err(|e| format!("agent admits: {e}"))?;
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);
    let build_id = kernel
        .load_instance(
            signed_boot_manifest("build-critter", &abode),
            Box::new(BuildCritter::new(abode.clone(), author.clone())),
        )
        .map_err(|e| format!("build-critter admits: {e}"))?;
    kernel.bind_role(Role::new(Role::BUILD), build_id);
    ok("substrate booted: AUTHORING + a no-cargo BUILD organ (build-critter) on the bus");

    let (probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    let reply_to = Address::Creature(probe_id);

    // 1) Ask for a critter, in English.
    let request = "write a critter that reverses a string";
    step(&format!("asking the AUTHORING agent (in English): “{request}”"));
    let auth_payload =
        serde_json::to_vec(&AuthoringRequest { request: request.into(), ..Default::default() })
            .map_err(|e| e.to_string())?;
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), auth_payload)
            .with_reply_to(reply_to.clone())
            .with_corr(1),
        1,
        Duration::from_secs(5),
    )
    .ok_or("no reply from the AUTHORING agent")?;
    let resp: AuthoringResponse =
        match serde_json::from_slice::<AuthoringReply>(&env.payload).map_err(|e| e.to_string())? {
            AuthoringReply::Authored(r) => r,
            AuthoringReply::Failed(e) => return Err(format!("authoring failed: {e:?}")),
        };
    ok(&format!(
        "the agent authored `{}` ({} bytes of Rhai) — no operator edits after the request",
        resp.crate_name,
        resp.source.len()
    ));

    // 2) Build = compile-check + sign. No subprocess, no compiler toolchain.
    step("handing the source to the BUILD organ → Rhai compile-check + ed25519 sign (no cargo)…");
    let t0 = Instant::now();
    let op = BuildCritterOp::Author {
        source: resp.source.clone(),
        manifest_stub: resp.manifest_stub.clone(),
    };
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(Address::Role(Role::new(Role::BUILD)), op.to_bytes())
            .with_reply_to(reply_to.clone())
            .with_corr(2),
        2,
        Duration::from_secs(5),
    )
    .ok_or("no reply from build-critter")?;
    let (manifest, artifact) =
        match serde_json::from_slice::<BuildReply>(&env.payload).map_err(|e| e.to_string())? {
            BuildReply::Built { manifest, artifact } => (manifest, artifact),
            BuildReply::Failed { kind, message, .. } => {
                return Err(format!("critter build failed ({kind:?}): {message}"))
            }
        };
    let elapsed = t0.elapsed();
    ok(&format!(
        "validated + signed in {:.2} ms — the artifact IS {} bytes of source (no .so; portable)",
        elapsed.as_secs_f64() * 1000.0,
        artifact.len()
    ));

    // 3) Admit + hot-load through the very same kernel path the daemon used.
    step("admitting through the kernel (signature verifies + author allowlisted + hash matches)…");
    let id = kernel
        .load(manifest, Artifact::Bytes(artifact))
        .map_err(|e| format!("admission/load rejected: {e}"))?;
    ok(&format!(
        "admitted + hot-loaded the critter as creature id={} — metered + sandboxed by the engine",
        id.0
    ));

    // 4) Run it.
    step("sending “abc” to the critter the reference agent just wrote…");
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(Address::Creature(id), b"abc".to_vec()).with_reply_to(reply_to).with_corr(3),
        3,
        Duration::from_secs(5),
    )
    .ok_or("no reply from the critter")?;
    if env.payload.as_slice() != b"cba" {
        return Err(format!(
            "the authored reverse critter returned {:?}, expected byte-exact `cba`",
            String::from_utf8_lossy(&env.payload)
        ));
    }
    ok(&format!(
        "got back “{}”  — authored, signed, loaded, and run with no compiler in the loop.",
        String::from_utf8_lossy(&env.payload)
    ));

    kernel.shutdown_all(Deadline::default());
    Ok(())
}

// =================================================================================================
// Phase 2 — Migration: a local two-body hand-off, with signed, verified continuity.
// =================================================================================================

fn phase_migration() -> Result<(), String> {
    banner("Phase 2 · Migration — a signed hand-off between two bodies in one Sanctum");
    note("(local and repeatable here; cosmos/sanctum/tests/abode_migrate_cross_node.rs proves the cross-Sanctum variant over two real TCP sockets)");

    let abode = Ed25519KeyMaterial::from_seed([0xA9u8; 32]).map_err(|e| format!("key: {e}"))?;
    let abode_pub = abode.public_hex().to_string();
    note(&format!("Abode (the self): {}…", short(&abode_pub)));

    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(abode.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![abode_pub.clone()])),
        128,
    );

    let node = NodeId("demo-node".into());
    // Body B (destination) — admits an incoming self only if its injected policy trusts the Abode.
    let dest = AbodeMigrator::new(
        node.clone(),
        abode.clone(),
        Box::new(AbodeAllowlistPolicy::allowing(abode_pub.clone())),
    );
    let dest_id = kernel
        .load_instance(signed_boot_manifest("abode-migrator-B", &abode), Box::new(dest))
        .map_err(|e| format!("dest migrator admits: {e}"))?;
    // Body A (source) — currently holds the authoritative self.
    let src = AbodeMigrator::new(
        node.clone(),
        abode.clone(),
        Box::new(AbodeAllowlistPolicy::allowing(abode_pub.clone())),
    );
    let src_id = kernel
        .load_instance(signed_boot_manifest("abode-migrator-A", &abode), Box::new(src))
        .map_err(|e| format!("src migrator admits: {e}"))?;
    kernel.bind_role(Role::new(Role::ABODE_MIGRATOR), src_id);
    ok("two Abode bodies loaded — acknowledged local hand-off (not a crash-safe authority fence)");

    let (probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    let reply_to = Address::Creature(probe_id);

    // Seed the self's state on body A.
    step("seeding the self's state on body A: counter=42");
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(
            Address::Creature(src_id),
            MigratorMsg::SetState { payload: b"counter=42".to_vec() }.to_bytes(),
        )
        .with_schema(MIGRATOR_SCHEMA)
        .with_corr(1)
        .with_reply_to(reply_to.clone()),
        1,
        Duration::from_secs(3),
    )
    .ok_or("no StateSet reply")?;
    match MigratorMsg::parse(&env.payload) {
        Ok(MigratorMsg::StateSet) => ok("body A is authoritative, holding the self's state"),
        other => return Err(format!("expected StateSet, got {other:?}")),
    }

    // Migrate A → B. The migrator snapshots, signs, ships, B verifies integrity + signature + admits.
    step("migrating the self  A → B  (snapshot · sign · ship · verify · admit)…");
    let env = request_reply(
        &probe_bus,
        &probe_rx,
        Dispatch::to(
            Address::Creature(src_id),
            MigratorMsg::Migrate {
                destination_node: node.clone(),
                destination_migrator: dest_id,
                // Local hand-off in the demo — the dest migrator signs a witness the source verifies;
                // no pre-shared anchor pinned (M9-2 falls back to the challenge/node guard for binding).
                expected_responder_pubkey: None,
            }
            .to_bytes(),
        )
        .with_schema(MIGRATOR_SCHEMA)
        .with_corr(2)
        .with_reply_to(reply_to.clone()),
        2,
        Duration::from_secs(5),
    )
    .ok_or("no MigrateAck — migration did not complete")?;
    match MigratorMsg::parse(&env.payload) {
        Ok(MigratorMsg::MigrateAck { migrated_to }) if migrated_to == node => {
            ok(&format!("body B admitted the self; A acknowledges hand-off to {}", migrated_to.0))
        }
        Ok(MigratorMsg::MigrateAck { migrated_to }) => {
            return Err(format!(
                "MigrateAck named unexpected destination `{}` (expected `{}`)",
                migrated_to.0, node.0
            ))
        }
        other => return Err(format!("expected MigrateAck, got {other:?}")),
    }

    // Confirm the transition on both bodies.
    let status = |id, corr| -> Result<MigratorMsg, String> {
        let env = request_reply(
            &probe_bus,
            &probe_rx,
            Dispatch::to(Address::Creature(id), MigratorMsg::StatusQuery.to_bytes())
                .with_schema(MIGRATOR_SCHEMA)
                .with_corr(corr)
                .with_reply_to(reply_to.clone()),
            corr,
            Duration::from_secs(3),
        )
        .ok_or("no StatusReply")?;
        MigratorMsg::parse(&env.payload).map_err(|e| format!("parse status: {e}"))
    };

    step("verifying both bodies…");
    match status(src_id, 3)? {
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. }
            if state == "migrated" && migrated_to.as_ref() == Some(&node) && payload_len == 0 =>
        {
            ok("body A → state=\"migrated\", payload_len=0  (the self has left A)");
        }
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. } => {
            return Err(format!(
                "body A ended in state={state:?}, migrated_to={migrated_to:?}, payload_len={payload_len}; expected migrated to `{}` with no retained payload",
                node.0
            ));
        }
        other => return Err(format!("expected source StatusReply, got {other:?}")),
    }
    match status(dest_id, 4)? {
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. }
            if state == "authoritative"
                && migrated_to.is_none()
                && payload_len == b"counter=42".len() =>
        {
            ok(&format!(
                "body B → state=\"authoritative\", payload_len={payload_len}  (the self is now authoritative on B)"
            ));
        }
        MigratorMsg::StatusReply { state, migrated_to, payload_len, .. } => {
            return Err(format!(
                "body B ended in state={state:?}, migrated_to={migrated_to:?}, payload_len={payload_len}; expected authoritative with {} payload bytes",
                b"counter=42".len()
            ));
        }
        other => return Err(format!("expected destination StatusReply, got {other:?}")),
    }

    kernel.shutdown_all(Deadline::from_millis(1500));
    Ok(())
}

/// Run the narrated walkthrough to completion. Invoked by the `walkthrough` binary and by
/// `alpha demo walkthrough`.
pub fn run() {
    println!("\x1b[1mAlpha — the GAWD substrate loop, live in your terminal\x1b[0m");
    println!("A reference agent authors and ships running code; a running self performs a signed local hand-off. Watch:");

    if let Err(e) = phase_self_authoring() {
        eprintln!("\n\x1b[31mPhase 1 failed:\x1b[0m {e}");
        std::process::exit(1);
    }
    if let Err(e) = phase_critter() {
        eprintln!("\n\x1b[31mPhase 1b failed:\x1b[0m {e}");
        std::process::exit(1);
    }
    if let Err(e) = phase_migration() {
        eprintln!("\n\x1b[31mPhase 2 failed:\x1b[0m {e}");
        std::process::exit(1);
    }

    banner("Done");
    println!(
        "Everything above ran against live kernels through the same admission → engine → router"
    );
    println!(
        "path the test suite uses. The cross-Sanctum version (two real TCP sockets) is proven in"
    );
    println!("cosmos/sanctum/tests/abode_migrate_cross_node.rs.\n");
}
