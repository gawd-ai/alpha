//! bestiary-live — live-model authoring into a durable Bestiary, narrated in your terminal.
//!
//! `walkthrough` proves the authoring loop with a deterministic *template* author and an in-memory
//! registry. This demo runs the **real** thing end to end:
//!
//! 1. a **live model** authors a creature from an English request (with a bounded compile-error
//!    retry) on the sandboxed **critter** tier — the demo binds the *critter* builder, so the BUILD
//!    socket only ever produces sandboxed scripts and a prompt-injectable author cannot mint native
//!    code here (the author's threat model: containment lives at the route + admission layer, not the
//!    prompt);
//! 2. `build-critter` compile-checks + ed25519-signs it, and the kernel admits + hot-loads + runs it;
//! 3. it is published into a **durable Bestiary** (`bestiary-daemon` over `FsBestiaryStore`) — a
//!    realm-hashed, content-addressed, signed-log store with the safe deterministic curator bound —
//!    and a **verifiable `EntryProof`** is obtained and checked;
//! 4. a fresh store handle opens the same on-disk root and **recovers** the persisted signed journal;
//! 5. a second independent store accepts the self-verifying entry through the same monotonic merge
//!    used by `PushEntries`, re-signs it under its own identity, and **converges**. This last phase is
//!    deliberately store-level; the demo does not claim to exercise node transport replication.
//!
//! It is **opt-in and key-gated**: with `ALPHA_LLM_MODEL` unset it prints a hint and exits 0, so CI
//! never invokes a network call. Everything else uses only the public APIs an operator would drive.
//!
//! Run it (needs a model + `--features openai`):
//! ```text
//! ALPHA_LLM_BASE_URL=https://api.openai.com/v1 ALPHA_LLM_API_KEY=sk-... \
//!   ALPHA_LLM_MODEL=gpt-4o-mini cargo run -p bestiary-live --features openai
//! ```
//! To see the durable Bestiary *without* a model (hermetic): `ALPHA_DURABLE_BESTIARY=1 cargo run -p
//! federation`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, BusHandle, Deadline, Dispatch, Ed25519Signer, Ed25519Verifier, Envelope,
    InboxReceiver, Role,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest, RealmId};

use agent_mind::AgentMind;
use agent_templated::{AuthoringReply, AuthoringRequest};
use bestiary::{
    BestiaryOp, BestiaryReply, BestiaryStore, DeterministicCurator, FsBestiaryStore, RegistryOp,
    RegistryReply, BESTIARY_OP_SCHEMA, REGISTRY_OP_SCHEMA,
};
use bestiary_daemon::{BestiaryConfig, BestiaryDaemon};
use build_cargo::BuildReply;
use build_critter::{BuildCritter, BuildCritterOp};
use mind::Model;
use policy_signed::SignedPolicy;

const DEFAULT_LLM_MAX_ATTEMPTS: u32 = 3;
const MAX_LLM_MAX_ATTEMPTS: u32 = 5;
#[cfg(feature = "openai")]
const DEFAULT_LLM_TIMEOUT_SECS: u32 = 60;
#[cfg(feature = "openai")]
const MAX_LLM_TIMEOUT_SECS: u32 = 90;

const DEMO_TEMP_ROOT_PREFIX: &str = "alpha-bestiary-live";
const DEMO_TEMP_ROOT_MARKER: &str = ".alpha-bestiary-live-owned";

fn bounded_positive_env(name: &str, default: u32, max: u32) -> Result<u32, String> {
    match std::env::var(name) {
        Ok(raw) => {
            let value = raw
                .parse::<u32>()
                .map_err(|_| format!("{name} must be an integer in 1..={max}, got {raw:?}"))?;
            if !(1..=max).contains(&value) {
                return Err(format!("{name} must be in 1..={max}, got {value}"));
            }
            Ok(value)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("{name} must be valid UTF-8 and in 1..={max}"))
        }
    }
}

/// A per-process demo root that removes only a freshly created, marker-owned directory.
///
/// The unarmed state uses non-recursive cleanup. Recursive cleanup is enabled only after the exact
/// root path and private marker have both been established, and re-validates both before deletion.
struct DemoTempRoot {
    base: PathBuf,
    path: PathBuf,
    name: String,
    marker_payload: String,
    armed: bool,
}

impl DemoTempRoot {
    fn create(slot: &str) -> Result<Self, String> {
        if !matches!(slot, "A" | "B") {
            return Err(format!("invalid bestiary-live temp-root slot {slot:?}"));
        }

        let base = std::env::temp_dir();
        let pid = std::process::id();
        let name = format!("{DEMO_TEMP_ROOT_PREFIX}-{slot}-{pid}");
        let path = base.join(&name);
        if path.parent() != Some(base.as_path())
            || path.file_name() != Some(std::ffi::OsStr::new(&name))
        {
            return Err(format!("refusing unexpected bestiary-live temp root {}", path.display()));
        }

        std::fs::create_dir(&path).map_err(|error| {
            format!(
                "create private bestiary-live temp root {} (refusing to reuse an existing path): {error}",
                path.display()
            )
        })?;

        let marker_payload = format!("alpha-bestiary-live temp root v1\npid={pid}\nslot={slot}\n");
        let mut root = Self { base, path, name, marker_payload, armed: false };
        root.write_marker()?;
        root.armed = true;
        Ok(root)
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn validate_path(&self) -> Result<(), String> {
        let expected = self.base.join(&self.name);
        if self.path != expected
            || self.path.parent() != Some(self.base.as_path())
            || self.path.file_name() != Some(std::ffi::OsStr::new(&self.name))
        {
            return Err(format!(
                "refusing cleanup for unexpected bestiary-live path {}",
                self.path.display()
            ));
        }
        Ok(())
    }

    fn marker_path(&self) -> PathBuf {
        self.path.join(DEMO_TEMP_ROOT_MARKER)
    }

    fn write_marker(&self) -> Result<(), String> {
        let marker_path = self.marker_path();
        let mut marker =
            std::fs::OpenOptions::new().write(true).create_new(true).open(&marker_path).map_err(
                |error| format!("create ownership marker {}: {error}", marker_path.display()),
            )?;
        marker
            .write_all(self.marker_payload.as_bytes())
            .and_then(|()| marker.sync_all())
            .map_err(|error| format!("write ownership marker {}: {error}", marker_path.display()))
    }

    fn cleanup_unarmed(&self) -> Result<(), String> {
        self.validate_path()?;
        let marker_path = self.marker_path();
        match std::fs::remove_file(&marker_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!("remove incomplete marker {}: {error}", marker_path.display()));
            }
        }
        match std::fs::remove_dir(&self.path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(format!("remove unarmed root {}: {error}", self.path.display())),
        }
    }

    fn cleanup_owned(&self) -> Result<(), String> {
        self.validate_path()?;
        let root_meta = match std::fs::symlink_metadata(&self.path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(format!("inspect root {}: {error}", self.path.display())),
        };
        if !root_meta.file_type().is_dir() {
            return Err(format!("refusing cleanup: {} is not a directory", self.path.display()));
        }

        let marker_path = self.marker_path();
        let marker_meta = std::fs::symlink_metadata(&marker_path).map_err(|error| {
            format!("inspect ownership marker {}: {error}", marker_path.display())
        })?;
        if !marker_meta.file_type().is_file() {
            return Err(format!(
                "refusing cleanup: ownership marker {} is not a regular file",
                marker_path.display()
            ));
        }
        let marker = std::fs::read_to_string(&marker_path)
            .map_err(|error| format!("read ownership marker {}: {error}", marker_path.display()))?;
        if marker != self.marker_payload {
            return Err(format!(
                "refusing cleanup: ownership marker {} does not match this process",
                marker_path.display()
            ));
        }

        std::fs::remove_dir_all(&self.path)
            .map_err(|error| format!("remove demo-owned root {}: {error}", self.path.display()))
    }
}

impl Drop for DemoTempRoot {
    fn drop(&mut self) {
        let result = if self.armed { self.cleanup_owned() } else { self.cleanup_unarmed() };
        if let Err(error) = result {
            eprintln!("bestiary-live: temp-root cleanup warning: {error}");
        }
    }
}

// ----- narration (matches the walkthrough house style) -------------------------------------------

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
fn short(s: &str) -> String {
    s.chars().take(12).collect()
}

fn signed_boot_manifest(name: &str, key: &Ed25519KeyMaterial) -> Manifest {
    let mut m = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    m.provenance.author = Some(key.public_hex().to_string());
    m.provenance.signature = Some(key.sign(&m.signing_payload()));
    m
}

/// Send a dispatch and wait (bounded) for the reply correlated by `corr`, skipping stray sense
/// envelopes. (`agent-mind` here emits no SEER traffic — it is bound without a seer target — so the
/// only `corr`-matching envelope is the terminal reply.)
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
            _ => continue,
        }
    }
    None
}

// ----- model selection (the only feature-gated part) ---------------------------------------------

/// Build the live model from the `ALPHA_LLM_*` environment. The `mind` crate never reads the
/// environment itself — this demo *is* the operator surface, so it reads the env and constructs the
/// `ModelConfig` here.
#[cfg(feature = "openai")]
fn make_model(model_id: String, timeout: Duration) -> Option<Arc<dyn Model>> {
    let base_url = std::env::var("ALPHA_LLM_BASE_URL")
        .unwrap_or_else(|_| "https://api.openai.com/v1".to_string());
    let api_key = std::env::var("ALPHA_LLM_API_KEY").ok().filter(|s| !s.is_empty());
    let cfg = mind::ModelConfig { base_url, model: model_id, api_key, timeout };
    Some(Arc::new(mind::OpenAiModel::new(cfg)))
}

/// Without the `openai` feature there is no model backend linked in — the demo prints a rebuild hint.
#[cfg(not(feature = "openai"))]
fn make_model(_model_id: String) -> Option<Arc<dyn Model>> {
    None
}

fn print_hint() {
    println!(
        "\x1b[1mbestiary-live\x1b[0m — a real model authors a creature that lands in a durable"
    );
    println!(
        "Bestiary with a verifiable entry proof, journal recovery, and store-level convergence."
    );
    println!();
    println!("This demo is opt-in and needs a model. Set ALPHA_LLM_MODEL and build with --features openai:");
    println!();
    println!("    ALPHA_LLM_BASE_URL=https://api.openai.com/v1 \\");
    println!("    ALPHA_LLM_API_KEY=sk-... \\");
    println!("    ALPHA_LLM_MODEL=gpt-4o-mini \\");
    println!("    cargo run -p bestiary-live --features openai");
    println!();
    println!(
        "Or point ALPHA_LLM_BASE_URL at a local Ollama / LM-Studio (http://localhost:11434/v1)."
    );
    println!("To see the durable Bestiary WITHOUT a model (hermetic): ALPHA_DURABLE_BESTIARY=1 cargo run -p federation");
    println!();
    println!("(ALPHA_LLM_MODEL is unset — skipping. This is not a failure.)");
}

fn print_no_backend_hint(model_id: &str) {
    println!(
        "bestiary-live: ALPHA_LLM_MODEL={model_id} is set, but this binary was built WITHOUT the model backend."
    );
    println!("Rebuild with the feature:   cargo run -p bestiary-live --features openai");
    println!("(skipping — not a failure.)");
}

/// Run the demo. Invoked by the `bestiary-live` binary and by `alpha demo bestiary-live`.
pub fn run(_args: &[String]) {
    let model_id = match std::env::var("ALPHA_LLM_MODEL") {
        Ok(m) if !m.trim().is_empty() => m,
        _ => {
            print_hint();
            return;
        }
    };
    #[cfg(feature = "openai")]
    let selected_model = {
        let timeout_secs = bounded_positive_env(
            "ALPHA_LLM_TIMEOUT_SECS",
            DEFAULT_LLM_TIMEOUT_SECS,
            MAX_LLM_TIMEOUT_SECS,
        )
        .unwrap_or_else(|error| {
            eprintln!("bestiary-live: invalid configuration: {error}");
            std::process::exit(2);
        });
        make_model(model_id.clone(), Duration::from_secs(u64::from(timeout_secs)))
    };
    #[cfg(not(feature = "openai"))]
    let selected_model = make_model(model_id.clone());

    let Some(model) = selected_model else {
        print_no_backend_hint(&model_id);
        return;
    };
    let max_attempts = bounded_positive_env(
        "ALPHA_LLM_MAX_ATTEMPTS",
        DEFAULT_LLM_MAX_ATTEMPTS,
        MAX_LLM_MAX_ATTEMPTS,
    )
    .unwrap_or_else(|error| {
        eprintln!("bestiary-live: invalid configuration: {error}");
        std::process::exit(2);
    });

    println!(
        "\x1b[1mAlpha — a real model authors into a durable Bestiary, live in your terminal\x1b[0m"
    );
    println!(
        "Model: {model_id}. Watch a creature be authored, run, persisted, proven, and merged into an independent store.\n"
    );

    if let Err(e) = demo(model, &model_id, max_attempts) {
        eprintln!("\n\x1b[31mbestiary-live failed:\x1b[0m {e}");
        std::process::exit(1);
    }

    banner("Done");
    println!(
        "Everything above ran against a live kernel through the same admission → engine → router"
    );
    println!("and the durable-store paths the integration tests prove:");
    println!("  cosmos/sanctum/tests/agent_mind_authoring_loop.rs        (model author → build → load → run)");
    println!("  cosmos/sanctum/tests/bestiary_durable_local.rs           (publish · prove · persist · GC)");
    println!("  cosmos/sanctum/tests/bestiary_replication_cross_node.rs  (the separate cross-node PushEntries proof)\n");
}

fn demo(model: Arc<dyn Model>, model_id: &str, max_attempts: u32) -> Result<(), String> {
    // Construct both guards before anything that can return early. They delete only their exact,
    // freshly created, marker-owned roots after all later stores and the kernel have dropped.
    let root_a = DemoTempRoot::create("A")?;
    let root_b = DemoTempRoot::create("B")?;

    let abode = Ed25519KeyMaterial::from_seed([0xB5u8; 32]).map_err(|e| format!("key: {e}"))?;
    let author = abode.public_hex().to_string();
    let realm = RealmId::new("bestiary-live");

    // A live kernel: three engines, real signing/verification, a SignedPolicy allowlisting exactly
    // this Abode — the same gates the tests use.
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(Ed25519Signer::new(abode.clone())),
        Arc::new(Ed25519Verifier),
        Arc::new(SignedPolicy::new(vec![author.clone()])),
        128,
    );

    banner("Booting — a model-backed author + a no-cargo builder + a DURABLE registry");

    // AUTHORING = the model-backed author (in-process only; the model is injected by value).
    let agent_id = kernel
        .load_instance(
            signed_boot_manifest("agent-mind", &abode),
            Box::new(AgentMind::new(model.clone())),
        )
        .map_err(|e| format!("agent-mind admits: {e}"))?;
    kernel.bind_role(Role::new(Role::AUTHORING), agent_id);

    // BUILD = the no-cargo critter builder. Binding the *critter* builder is the threat-model choice:
    // the BUILD socket only ever produces sandboxed scripts, so a prompt-injectable author cannot mint
    // native code here regardless of what it emits — containment lives at the route, not the prompt.
    let build_id = kernel
        .load_instance(
            signed_boot_manifest("build-critter", &abode),
            Box::new(BuildCritter::new(abode.clone(), author.clone())),
        )
        .map_err(|e| format!("build-critter admits: {e}"))?;
    kernel.bind_role(Role::new(Role::BUILD), build_id);

    // REGISTRY = a durable Bestiary daemon over an on-disk, signed-log store (store A). We keep the
    // `store_a` handle to read its signed entries for the store-level convergence phase.
    let store_a = Arc::new(
        FsBestiaryStore::new(root_a.path(), abode.clone())
            .map_err(|e| format!("bestiary store A: {e}"))?,
    );
    let daemon = BestiaryDaemon::new(
        store_a.clone(),
        Arc::new(DeterministicCurator::default()),
        BestiaryConfig::local(),
    );
    let reg_id = kernel
        .load_instance(signed_boot_manifest("bestiary-daemon", &abode), Box::new(daemon))
        .map_err(|e| format!("bestiary-daemon admits: {e}"))?;
    kernel.bind_role(Role::new(Role::REGISTRY), reg_id);
    ok(&format!(
        "AUTHORING (model: {model_id}) + BUILD + a durable REGISTRY are all creatures on the bus"
    ));
    note(&format!("Bestiary root: {}", root_a.path().display()));

    let (probe_id, bus, rx) = kernel.open_endpoint(Capabilities::default());
    let reply_to = Address::Creature(probe_id);
    let mut corr = 0u64;

    // --- Phase 1 — a real model authors a critter, with a bounded compile-error retry -------------
    banner("Phase 1 · A real model authors, signs, and runs a creature");
    let request = "write a critter that reverses a string";
    let mut prev_error: Option<String> = None;
    let mut built: Option<(Manifest, Vec<u8>)> = None;
    for attempt in 1..=max_attempts {
        step(&format!(
            "attempt {attempt}/{max_attempts}: asking the model (in English): “{request}”"
        ));
        let req = AuthoringRequest { request: request.into(), prev_error: prev_error.clone() };
        let payload = serde_json::to_vec(&req).map_err(|e| e.to_string())?;
        corr += 1;
        let env = request_reply(
            &bus,
            &rx,
            Dispatch::to(Address::Role(Role::new(Role::AUTHORING)), payload)
                .with_reply_to(reply_to.clone())
                .with_corr(corr),
            corr,
            Duration::from_secs(90),
        )
        .ok_or("no reply from agent-mind (the model call timed out?)")?;
        let resp = match serde_json::from_slice::<AuthoringReply>(&env.payload)
            .map_err(|e| e.to_string())?
        {
            AuthoringReply::Authored(r) => r,
            AuthoringReply::Failed(e) => return Err(format!("authoring failed: {e:?}")),
        };
        ok(&format!(
            "the model authored `{}` ({} bytes of Rhai)",
            resp.crate_name,
            resp.source.len()
        ));

        let op = BuildCritterOp::Author {
            source: resp.source.clone(),
            manifest_stub: resp.manifest_stub.clone(),
        };
        corr += 1;
        let env = request_reply(
            &bus,
            &rx,
            Dispatch::to(Address::Role(Role::new(Role::BUILD)), op.to_bytes())
                .with_reply_to(reply_to.clone())
                .with_corr(corr),
            corr,
            Duration::from_secs(10),
        )
        .ok_or("no reply from build-critter")?;
        match serde_json::from_slice::<BuildReply>(&env.payload).map_err(|e| e.to_string())? {
            BuildReply::Built { manifest, artifact } => {
                ok(&format!(
                    "compile-checked + ed25519-signed ({} bytes of source)",
                    artifact.len()
                ));
                built = Some((manifest, artifact));
                break;
            }
            BuildReply::Failed { kind, message, stderr, .. } => {
                note(&format!(
                    "build failed ({kind:?}): {message} — feeding the error back to the model"
                ));
                prev_error = Some(if stderr.is_empty() { message } else { stderr });
            }
        }
    }
    let (manifest, artifact) = built.ok_or_else(|| {
        format!("the model did not produce a buildable critter within {max_attempts} attempt(s)")
    })?;

    // Keep copies for publishing — `load` consumes the originals.
    let manifest_for_pub = manifest.clone();
    let artifact_for_pub = artifact.clone();

    step("admitting through the kernel (signature verifies + author allowlisted + hash matches)…");
    let id = kernel
        .load(manifest, Artifact::Bytes(artifact))
        .map_err(|e| format!("admission/load rejected: {e}"))?;
    ok(&format!("admitted + hot-loaded as creature id={} (sandboxed critter tier)", id.0));

    corr += 1;
    let env = request_reply(
        &bus,
        &rx,
        Dispatch::to(Address::Creature(id), b"abc".to_vec())
            .with_reply_to(reply_to.clone())
            .with_corr(corr),
        corr,
        Duration::from_secs(5),
    )
    .ok_or("no reply from the authored critter")?;
    if env.payload.as_slice() != b"cba" {
        return Err(format!(
            "the model-authored reverse critter returned {:?}, expected byte-exact `cba`",
            String::from_utf8_lossy(&env.payload)
        ));
    }
    ok(&format!(
        "ran it: “abc” → “{}” — a real model wrote running code",
        String::from_utf8_lossy(&env.payload)
    ));

    // --- Phase 2 — publish into the durable Bestiary + a verifiable proof -------------------------
    banner("Phase 2 · Into the durable Bestiary — publish, then prove");
    let op = RegistryOp::Publish {
        manifest: manifest_for_pub,
        artifact: artifact_for_pub,
        realm: Some(realm.clone()),
    };
    corr += 1;
    let env = request_reply(
        &bus,
        &rx,
        Dispatch::to(
            Address::Role(Role::new(Role::REGISTRY)),
            serde_json::to_vec(&op).map_err(|e| e.to_string())?,
        )
        .with_schema(REGISTRY_OP_SCHEMA)
        .with_reply_to(reply_to.clone())
        .with_corr(corr),
        corr,
        Duration::from_secs(10),
    )
    .ok_or("no publish reply from the durable registry")?;
    let artifact_hash =
        match serde_json::from_slice::<RegistryReply>(&env.payload).map_err(|e| e.to_string())? {
            RegistryReply::Published { artifact_hash, .. } => artifact_hash,
            other => return Err(format!("expected Published, got {other:?}")),
        };
    ok(&format!(
        "published into Realm `{}` — a signed on-disk log + a content-addressed blob ({}…)",
        realm.0,
        short(&artifact_hash)
    ));

    let pop = BestiaryOp::ProveEntry { artifact_hash: artifact_hash.clone(), realm: realm.clone() };
    corr += 1;
    let env = request_reply(
        &bus,
        &rx,
        Dispatch::to(
            Address::Role(Role::new(Role::REGISTRY)),
            serde_json::to_vec(&pop).map_err(|e| e.to_string())?,
        )
        .with_schema(BESTIARY_OP_SCHEMA)
        .with_reply_to(reply_to.clone())
        .with_corr(corr),
        corr,
        Duration::from_secs(10),
    )
    .ok_or("no prove reply from the durable registry")?;
    let proof =
        match serde_json::from_slice::<BestiaryReply>(&env.payload).map_err(|e| e.to_string())? {
            BestiaryReply::EntryProof { proof } => proof,
            other => return Err(format!("expected EntryProof, got {other:?}")),
        };
    if !proof.verify(&Ed25519Verifier) {
        return Err("the EntryProof failed to verify".into());
    }
    ok(&format!(
        "got a standalone EntryProof — attester {}…, first_seen {} — verified ✓ (survives compaction)",
        short(&proof.attester),
        proof.first_seen
    ));

    // --- Phase 3 — durability: a fresh store recovers the signed journal --------------------------
    banner("Phase 3 · Durability — a fresh store recovers the signed journal from disk");
    store_a.flush().map_err(|e| format!("flush: {e}"))?;
    let store_a2 = FsBestiaryStore::new(root_a.path(), abode.clone())
        .map_err(|e| format!("reopen store A: {e}"))?;
    let replayed = store_a2.recover().map_err(|e| format!("recover: {e}"))?;
    let survived = store_a2.get(&realm, &artifact_hash).map_err(|e| format!("get: {e}"))?;
    if survived.is_none() {
        return Err("the fresh store handle did not recover the persisted entry".into());
    }
    ok(&format!(
        "a brand-new store replayed {replayed} signed record(s) and still has the creature — persisted"
    ));

    // --- Phase 4 — store seam: an independent replica converges via the monotonic lattice ----------
    banner("Phase 4 · Store-level convergence — an independent replica merges signed entries");
    let abode_b = Ed25519KeyMaterial::from_seed([0xB6u8; 32]).map_err(|e| format!("key B: {e}"))?;
    let store_b = FsBestiaryStore::new(root_b.path(), abode_b)
        .map_err(|e| format!("bestiary store B: {e}"))?;
    let entries =
        store_a.signed_entries(Some(&realm)).map_err(|e| format!("signed_entries: {e}"))?;
    let mut accepted = 0usize;
    for entry in entries {
        if store_b.merge_push(entry).is_ok() {
            accepted += 1;
        }
    }
    let converged = store_b.get(&realm, &artifact_hash).map_err(|e| format!("get B: {e}"))?;
    if converged.is_none() {
        return Err("independent store B did not converge on the signed entry".into());
    }
    ok(&format!(
        "store B ingested {accepted} entr(y/ies), re-signed under its own identity, and now has the creature"
    ));
    note("This phase calls the store merge seam directly. BestiaryOp::PushEntries uses that seam over the bus, but node transport replication is not exercised here.");
    note(&format!(
        "the daemon's injected Curator decides keep/promote/GC — this demo binds DeterministicCurator (safe-by-default); bind AICurator({}) for an AI-curated gene pool",
        model.describe()
    ));

    kernel.shutdown_all(Deadline::from_millis(2000));
    Ok(())
}
