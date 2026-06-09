//! `build-cargo` — reference `Role::BUILD` creature for the self-authoring loop.
//!
//! Bound to `Role::BUILD`, this creature consumes a [`BuildOp::Build`]
//! envelope (authored source + manifest stub + cargo deps + sandbox kind) and replies with a
//! [`BuildReply::Built`] (signed manifest + artifact bytes admissible by `Kernel::load`) or a
//! [`BuildReply::Failed`] (structured failure the agent can feed back as `prev_error` on retry).
//!
//! ## Mechanism vs model
//!
//! The seam is "source + stub → (manifest, artifact)"; the *strategy* — which compiler, which
//! sandbox, which artifact format — is supplied by whoever's bound. This creature implements one
//! strategy (cargo + cdylib + signed manifest); alternative builders (cross-compile, AOT-from-wasm,
//! distributed farm) plug into the same socket. Sandbox composition is the same way — `Sandbox::Custom`
//! takes an arbitrary command prefix (`["bwrap", ...]`, `["firejail", ...]`, `["docker", "run", ...]`),
//! so the operator's containment model lives entirely in operator config, never in build-cargo.
//!
//! ## What this creature does NOT do
//!
//! - It does not author code (that's the [`Role::AUTHORING`](aether::Role::AUTHORING) seam).
//! - It does not load the artifact (that's the kernel's job, via the safe loader).
//! - It does not publish (that's the registry's job).
//! - It does not retry — the *agent* feeds back `prev_error` and re-authors; this creature is a pure
//!   compile-once function. Stateless on purpose: the loop's intelligence lives in the agent.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Process-wide monotonic counter ensuring every `run_build` materializes a uniquely-named
/// `work_dir`, even when two BuildCargo instances in the same process invoke a build for the same
/// `crate_name` within the same microsecond. A bare `{pid}-{nanos}-{crate_name}` formula
/// collides under exactly that pattern in a parallel test run: two parallel builds for
/// `reverse-daemon` would race-write `src/lib.rs` into the same path, and cargo's package-level
/// fingerprint cache would then service the second invocation from the first's compile output —
/// yielding a "successful" build of source that was never actually compiled. Counter is process-
/// local on purpose; cross-process uniqueness is already covered by `process::id()`.
static WORK_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// BUILD requests carry source + metadata, not artifacts. Bound the bus payload before JSON parsing
/// so a misbehaving authoring creature cannot force unbounded deserialization in the build organ.
const MAX_BUILD_OP_BYTES: usize = 8 * 1024 * 1024;
/// The authored Rust source lands in a temp workspace and then in cargo. Keep it roomy for generated
/// code while refusing pathological model output before any filesystem or compiler work starts.
const MAX_AUTHORED_SOURCE_BYTES: usize = 4 * 1024 * 1024;
/// Build metadata is interpolated into paths, Cargo.toml, manifest fields, and telemetry. Keep each
/// field small enough that a valid under-cap request cannot amplify into giant temp paths/events.
const MAX_CARGO_NAME_BYTES: usize = 128;
const MAX_CARGO_VERSION_BYTES: usize = 128;
const MAX_BUILD_DEPS: usize = 64;
const MAX_CARGO_DEP_FIELD_BYTES: usize = 4096;
const MAX_CARGO_DEP_FEATURES: usize = 64;
const MAX_CARGO_FEATURE_BYTES: usize = 256;
const MAX_BUILD_EVENT_FIELD_BYTES: usize = 4 * 1024;
pub const MAX_MANIFEST_STUB_ENTRYPOINTS: usize = 64;
pub const MAX_MANIFEST_STUB_ENTRYPOINT_NAME_BYTES: usize = 128;
pub const MAX_MANIFEST_STUB_ENTRYPOINT_SIGNATURE_BYTES: usize = 512;
pub const MAX_MANIFEST_STUB_PROVIDES: usize = 64;
pub const MAX_MANIFEST_STUB_PROVIDES_BYTES: usize = 128;
pub const MAX_MANIFEST_STUB_CAPABILITY_ITEMS: usize = 128;
pub const MAX_MANIFEST_STUB_CAPABILITY_FIELD_BYTES: usize = 512;
/// A built artifact is returned as bus bytes and then often loaded directly. Keep the compiler output
/// bounded too; a successful build that emits a giant cdylib is still not an acceptable artifact for
/// this in-process authoring loop.
const MAX_BUILT_ARTIFACT_BYTES: u64 = 128 * 1024 * 1024;

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome, Topic,
    MAX_SENSE_EVENT_BYTES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::crypto::Ed25519KeyMaterial;
use sigil::{Abi, Backend, Capabilities, Entrypoint, Manifest, Provenance};

/// What an authoring agent submits for compilation. Carries everything the build needs to be
/// reproducible: source text, dependency closure, manifest stub. Crosses the bus as JSON inside
/// an [`Envelope::payload`].
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BuildOp {
    Build {
        /// Crate name (must match the manifest stub's `name`; build-cargo asserts).
        crate_name: String,
        /// Crate version string, fed straight into the generated Cargo.toml.
        crate_version: String,
        /// `src/lib.rs` contents.
        source: String,
        /// Manifest stub the agent supplied — `name`/`version`/`abi.target`/etc. are filled
        /// against the host triple; `provenance` is populated by this creature.
        manifest_stub: ManifestStub,
        /// Additional `[dependencies]` entries. `forge` is added automatically.
        #[serde(default)]
        deps: Vec<CargoDep>,
    },
}

/// What the agent supplies for the manifest's authored half. The build creature fills in `abi.target`
/// (host triple), `provenance.author`/`source_hash`/`build_hash`/`signature`, and
/// `content_address`.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct ManifestStub {
    pub name: String,
    pub version: String,
    #[serde(default)]
    pub entrypoints: Vec<Entrypoint>,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub provides: Vec<String>,
}

/// A `[dependencies]` line the build generates into Cargo.toml.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CargoDep {
    pub name: String,
    pub spec: CargoDepSpec,
}

/// How a dependency resolves.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CargoDepSpec {
    /// `foo = "1.2"` — registry/cache resolution. Connectivity policy is left to the sandbox.
    Version(String),
    /// `foo = { path = "..." }` — path dep. The workspace SDK crates resolve this way.
    Path(PathBuf),
    /// `foo = { path = "...", features = ["..."] }` — features and optional flag for fine control.
    PathFeatures { path: PathBuf, features: Vec<String> },
}

/// Replies from the build creature, also carried as JSON in [`Envelope::payload`].
#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "reply", rename_all = "snake_case")]
// Short-lived wire message: built once, serialized to JSON, sent on the bus, matched once — the
// variant-size difference never lives on a hot stack path.
#[allow(clippy::large_enum_variant)]
pub enum BuildReply {
    /// Compile succeeded; manifest is fully populated (provenance signed) and artifact bytes hash
    /// to `provenance.build_hash` — `Kernel::load(manifest, Artifact::Bytes(artifact))` works.
    Built {
        manifest: Manifest,
        /// Hex-encoded `.so` bytes (same wire trick as `registry-mem`).
        #[serde(with = "sigil::crypto::hex_bytes")]
        artifact: Vec<u8>,
    },
    /// Compile (or sandbox / IO / timeout) failed. Structured so the agent can branch on `kind` and
    /// feed `stderr` back as `prev_error`. The node does not crash on a bad source.
    Failed {
        kind: BuildErrorKind,
        message: String,
        /// `cargo` stderr (truncated to 64 KiB) — the substance an agent reasons over.
        stderr: String,
        /// `cargo` stdout (truncated to 16 KiB).
        stdout: String,
    },
}

/// The shape of a build failure. Discriminator the agent uses to decide whether retry is worthwhile.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BuildErrorKind {
    /// `cargo build` exited non-zero (the usual case: a syntax/type error in the authored source).
    Compile,
    /// The cargo invocation didn't finish within `BuildConfig.cargo_timeout`.
    Timeout,
    /// The sandbox wrapper itself failed to launch or rejected the inner command. The operator's
    /// containment model gets to be specific in its own `stderr`.
    Sandbox,
    /// File / dir / spawn IO failure outside cargo (writing the workspace, reading the .so).
    Io,
    /// Request validation failed before any cargo invocation (mismatched names, empty source, etc.).
    Invalid,
    /// The cargo invocation produced no detectable `.so` — typically a `[lib]` misconfig.
    NoArtifact,
}

impl BuildReply {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

/// Proprioception events the build creature publishes on the
/// [`Topic::PROPRIOCEPTION`](aether::Topic::PROPRIOCEPTION) topic so operators / monitor creatures
/// can observe the loop. **Best-effort, never load-bearing** — admission / load decisions never
/// consult proprio; this is for human/observer eyes and for telemetry creatures.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum BuildEvent {
    /// A `BuildOp::Build` arrived; the creature is about to materialize a workspace and shell out.
    BuildStarted { crate_name: String, crate_version: String },
    /// A `BuildOp::Build` produced an admissible (signed, hashed) `(manifest, artifact)`.
    BuildSucceeded {
        crate_name: String,
        crate_version: String,
        /// Hex sha256 of the produced artifact bytes — same value the registry would index by.
        artifact_hash: String,
    },
    /// A `BuildOp::Build` failed. The discriminator lets observer creatures route by kind
    /// (compile vs sandbox vs timeout) without re-parsing the full reply.
    BuildFailed { crate_name: String, kind: BuildErrorKind, message: String },
}

/// Operator-opt-in sandbox seam. `None` = run cargo directly (the default — the threat model is
/// trusted operator authoring against their own substrate). `Custom(prefix)` prepends an arbitrary
/// command prefix to `cargo`, so the operator's containment model (bwrap / firejail / nsjail /
/// docker / podman / a custom wrapper) lives in operator config — build-cargo is agnostic.
///
/// **Why a `Custom`-prefix design instead of an enum-per-sandbox?** Each containment tool has its
/// own mount/cap/syscall vocabulary; baking a few into build-cargo would (a) duplicate operator
/// knowledge and (b) freeze the contract long before we know which one wins. A prefix takes minutes
/// to wire and the operator can re-tune without touching this creature.
#[derive(Clone, Debug, Default)]
pub enum Sandbox {
    /// No wrapping. The cargo invocation runs in the build-cargo process's environment, in a
    /// dedicated temp workspace directory.
    #[default]
    None,
    /// Prepend `prefix` to the argv. E.g. `["bwrap", "--ro-bind", "/", "/", "--dev", "/dev",
    /// "--proc", "/proc", "--tmpfs", "/tmp", "--unshare-net"]` (operator's call). build-cargo
    /// appends `cargo build ...` after the prefix; the wrapper takes over from there.
    Custom(Vec<String>),
}

/// What the operator configures for build-cargo at construction.
#[derive(Clone)]
pub struct BuildConfig {
    /// Where temp build workspaces are materialized. Each build gets a unique subdirectory of this.
    /// Default: `std::env::temp_dir()`.
    pub work_root: PathBuf,
    /// Cargo target directory. Sharing one across builds means SDK / aether / sigil don't
    /// recompile per request — a fresh `target/` would multiply the first request's wall-clock by
    /// 10× or more. Default: `<work_root>/build-cargo-target` (per-process scratch).
    pub target_dir: PathBuf,
    /// Absolute path to the workspace root that owns `forge` / `aether` / `sigil` —
    /// the path-dep base. Build-cargo auto-adds `forge` as a path dep so the authored creature
    /// has the FFI macro and the typed prelude. Default: detected via `CARGO_MANIFEST_DIR/../../`.
    pub gawd_workspace_root: PathBuf,
    /// Hard timeout per cargo invocation. Default 180 s — generous enough for a cold first build
    /// against the SDK, short enough that a runaway never hangs the node.
    pub cargo_timeout: Duration,
    /// Operator-opt-in sandbox wrapping (see [`Sandbox`]).
    pub sandbox: Sandbox,
    /// Abode signing key — fills `provenance.signature` on every successful build.
    pub signing_key: Ed25519KeyMaterial,
    /// Author identity in `provenance.author` (typically the Abode public key hex). Stored so the
    /// agent / submitter does not have to know the operator's key layout.
    pub author_label: String,
}

impl BuildConfig {
    /// Convenience: build-cargo defaults parameterised by `(workspace_root, signing_key, author)`.
    pub fn with_workspace_root(
        gawd_workspace_root: PathBuf,
        signing_key: Ed25519KeyMaterial,
        author_label: impl Into<String>,
    ) -> Self {
        let work_root = std::env::temp_dir();
        let target_dir = work_root.join("build-cargo-target");
        BuildConfig {
            work_root,
            target_dir,
            gawd_workspace_root,
            cargo_timeout: Duration::from_secs(180),
            sandbox: Sandbox::None,
            signing_key,
            author_label: author_label.into(),
        }
    }
}

/// The build creature.
pub struct BuildCargo {
    config: BuildConfig,
    /// Serializes cargo invocations against the shared target dir. Two concurrent `cargo build`s
    /// in the same target directory contend on cargo's own lockfile, but contention is implemented
    /// by *waiting on a file lock* — and cargo's wait diagnostics are noisy enough that we'd rather
    /// queue at the bus layer where we can publish a "build queued" proprio event later.
    cargo_lock: Mutex<()>,
    /// Bus + identity, captured at `bind` time, so proprio events can be published as builds start,
    /// succeed, or fail. `None` outside the bound state (direct `build()` callers — tests).
    bus_ctx: Mutex<Option<(Arc<dyn Bus>, CreatureId)>>,
}

impl BuildCargo {
    pub fn new(config: BuildConfig) -> Self {
        BuildCargo { config, cargo_lock: Mutex::new(()), bus_ctx: Mutex::new(None) }
    }

    fn publish_proprio(&self, event: BuildEvent) {
        // Best-effort: a proprio publish must never fail-loud (R9 — observability is not a
        // load-bearing path). Missing bus = silent skip, exactly what happens for direct `build()`.
        let Some((bus, _me)) = self.bus_ctx.lock().unwrap_or_else(|p| p.into_inner()).clone()
        else {
            return;
        };
        let payload = aether::wire::to_bytes(&event);
        if payload.len() > MAX_SENSE_EVENT_BYTES {
            eprintln!(
                "build-cargo: dropping oversized build_event proprio payload ({} bytes > {} cap)",
                payload.len(),
                MAX_SENSE_EVENT_BYTES
            );
            return;
        }
        let _ = bus.emit(
            Dispatch::to(Address::Topic(Topic::new(Topic::PROPRIOCEPTION)), payload)
                .with_schema("build_event"),
        );
    }

    /// Direct (non-bus) build — convenience for tests and a future "operator REPL" path. Bus callers
    /// go through [`Creature::handle`] with a [`BuildOp::Build`].
    pub fn build(&self, req: BuildRequest) -> BuildReply {
        let crate_name = bounded_event_text(&req.crate_name);
        let crate_version = bounded_event_text(&req.crate_version);
        self.publish_proprio(BuildEvent::BuildStarted {
            crate_name: crate_name.clone(),
            crate_version: crate_version.clone(),
        });
        match self.run_build(req) {
            Ok((manifest, artifact)) => {
                let artifact_hash =
                    manifest.provenance.build_hash.clone().unwrap_or_else(|| sha256_hex(&artifact));
                self.publish_proprio(BuildEvent::BuildSucceeded {
                    crate_name,
                    crate_version,
                    artifact_hash,
                });
                BuildReply::Built { manifest, artifact }
            }
            Err(failure) => {
                self.publish_proprio(BuildEvent::BuildFailed {
                    crate_name,
                    kind: failure.kind.clone(),
                    message: bounded_event_text(&failure.message),
                });
                BuildReply::Failed {
                    kind: failure.kind,
                    message: failure.message,
                    stderr: truncate(failure.stderr, 64 * 1024),
                    stdout: truncate(failure.stdout, 16 * 1024),
                }
            }
        }
    }

    fn run_build(&self, req: BuildRequest) -> Result<(Manifest, Vec<u8>), BuildFailure> {
        // 1. Validate the request shape before touching disk — fail fast on the obvious typos so
        //    the agent gets a precise error before paying the cargo wall-clock cost.
        if req.crate_name.trim().is_empty() {
            return Err(BuildFailure::invalid("crate_name is empty"));
        }
        validate_text_len("crate_name", &req.crate_name, MAX_CARGO_NAME_BYTES)?;
        validate_text_len("manifest_stub.name", &req.manifest_stub.name, MAX_CARGO_NAME_BYTES)?;
        if req.crate_name != req.manifest_stub.name {
            return Err(BuildFailure::invalid(format!(
                "crate_name `{}` does not match manifest_stub.name `{}`",
                req.crate_name, req.manifest_stub.name
            )));
        }
        validate_text_len("crate_version", &req.crate_version, MAX_CARGO_VERSION_BYTES)?;
        validate_text_len(
            "manifest_stub.version",
            &req.manifest_stub.version,
            MAX_CARGO_VERSION_BYTES,
        )?;
        if req.crate_version != req.manifest_stub.version {
            return Err(BuildFailure::invalid(format!(
                "crate_version `{}` does not match manifest_stub.version `{}`",
                req.crate_version, req.manifest_stub.version
            )));
        }
        if req.source.trim().is_empty() {
            return Err(BuildFailure::invalid("source is empty"));
        }
        if req.source.len() > MAX_AUTHORED_SOURCE_BYTES {
            return Err(BuildFailure::invalid(format!(
                "source is {} bytes, exceeds {} byte limit",
                req.source.len(),
                MAX_AUTHORED_SOURCE_BYTES
            )));
        }
        // crate names with whitespace / slashes would break Cargo.toml — cargo would reject anyway,
        // but a structured Invalid here is more honest than a Compile reply with a cargo error.
        if !req.crate_name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(BuildFailure::invalid(format!(
                "crate_name `{}` is not a valid cargo crate name (alphanumeric / `-` / `_`)",
                req.crate_name
            )));
        }
        // `crate_version` lands in Cargo.toml's `[package] version` field. Cargo will fully validate
        // semver, but gate the interpolation shape here so a malformed version is a structured
        // Invalid reply rather than TOML structure injection or a noisy cargo parse error.
        if !is_cargo_package_version(&req.crate_version) {
            return Err(BuildFailure::invalid(format!(
                "crate_version `{}` is not a safe Cargo package version (ASCII alphanumeric / `.`, `-`, `+`)",
                req.crate_version
            )));
        }
        validate_deps(&req.deps)?;
        validate_manifest_stub(&req.manifest_stub)?;

        // 2. Pick a cargo-side crate name unique to this build. The agent-facing `req.crate_name`
        //    (e.g. `reverse-daemon`) is preserved in the manifest — that's what creatures and
        //    operators see — but cargo gets `{name}-bP{pid}c{counter}` so this build has its own
        //    fingerprint slot and its own `lib<unique>.so` output. Why this is load-bearing:
        //    cargo's per-package fingerprint hash is keyed by `name@version` (the source path
        //    does NOT discriminate it in the hash that names `target/release/.fingerprint/<name>-XXX/`).
        //    Two ephemeral builds with the same `name@version` therefore collide on the same
        //    fingerprint slot; once the first succeeds, every subsequent cargo invocation for
        //    the same `name@version` (regardless of source content) sees "lib up to date" and
        //    returns success without recompiling — even when the new source is broken. This bites
        //    under parallel test execution: a valid `reverse-daemon` build populates the
        //    fingerprint, then a broken `reverse-daemon` build is served a cached success and
        //    reports `Built` when it should report `Failed{Compile}`.
        //    Per-build cargo-name uniqueness eliminates the collision without breaking SDK / aether
        //    dep caching (those keep their canonical names, so cargo reuses their fingerprints).
        let counter = WORK_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let cargo_crate_name = format!("{}-bP{}c{}", req.crate_name, std::process::id(), counter);

        // Materialize a fresh build workspace under `work_root`. Path uniqueness comes from the
        // same `(pid, counter)` pair plus `nanos` for human-readable ordering.
        let work_dir = self.config.work_root.join(format!(
            "build-cargo-{}-{}-{}-{}",
            std::process::id(),
            now_nanos(),
            counter,
            req.crate_name
        ));
        std::fs::create_dir_all(work_dir.join("src")).map_err(|e| {
            BuildFailure::io(format!("create work dir {}: {e}", work_dir.display()))
        })?;

        // Drop-guard for tempdir removal — runs whether we succeed, fail in cargo, or panic. The
        // shared target dir survives across builds (see BuildConfig.target_dir); only the per-build
        // workspace is ephemeral.
        struct CleanupOnDrop {
            work_dir: PathBuf,
            target_dir: PathBuf,
            cargo_crate_name: String,
        }
        impl Drop for CleanupOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.work_dir);
                // Also reap THIS build's unique outputs from the SHARED target dir (the cdylib +
                // depfile + fingerprint) — otherwise every authored creature leaves a few-MB `.so`
                // in `release/` forever, an unbounded disk leak on a long-lived authoring node. (T15)
                reap_build_artifacts(&self.target_dir, &self.cargo_crate_name);
            }
        }
        let _cleanup = CleanupOnDrop {
            work_dir: work_dir.clone(),
            target_dir: self.config.target_dir.clone(),
            cargo_crate_name: cargo_crate_name.clone(),
        };

        // 3. Write Cargo.toml + src/lib.rs. The Cargo.toml `name` is the per-build cargo crate
        //    name; the source is unchanged (the rename is invisible to the source — no item
        //    inside `src/lib.rs` references the crate name itself).
        let cargo_toml = generate_cargo_toml(
            &cargo_crate_name,
            &req.crate_version,
            &self.config.gawd_workspace_root,
            &req.deps,
        );
        std::fs::write(work_dir.join("Cargo.toml"), &cargo_toml)
            .map_err(|e| BuildFailure::io(format!("write Cargo.toml: {e}")))?;
        std::fs::write(work_dir.join("src").join("lib.rs"), &req.source)
            .map_err(|e| BuildFailure::io(format!("write src/lib.rs: {e}")))?;
        // A nested `.gitignore` keeps the temp tree from polluting any wrapping git repo if the
        // operator points work_root inside their checkout.
        let _ = std::fs::write(work_dir.join(".gitignore"), "target\n");

        // 4. Run cargo build under the lock + sandbox + timeout. The target-dir is shared across
        //    builds so SDK / aether do not recompile per request.
        let _guard = self.cargo_lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut cargo_out = self
            .invoke_cargo(&work_dir)
            .map_err(|e| BuildFailure::io(format!("spawn cargo: {e}")))?;
        // A `try_wait` I/O fault is neither a timeout nor a compile failure — report it as Io so the
        // agent doesn't burn its retry budget treating a host fault as a (re-triable) compile error.
        if let Some(e) = cargo_out.wait_error.take() {
            return Err(BuildFailure {
                kind: BuildErrorKind::Io,
                message: format!("waiting on the cargo subprocess failed: {e}"),
                stderr: cargo_out.stderr,
                stdout: cargo_out.stdout,
            });
        }
        if let Some(timed_out) = cargo_out.timed_out_kind() {
            return Err(BuildFailure {
                kind: timed_out,
                message: format!("cargo build exceeded the {:?} budget", self.config.cargo_timeout),
                stderr: cargo_out.stderr,
                stdout: cargo_out.stdout,
            });
        }
        if !cargo_out.status_success {
            // A real sandbox-prefix spawn failure (e.g. a typo'd `bwrap` path) surfaces earlier from
            // `cmd.spawn()` as `BuildFailure::io`; a non-zero cargo exit here is a Compile failure.
            return Err(BuildFailure {
                kind: BuildErrorKind::Compile,
                message: format!("cargo build exited with status {}", cargo_out.status_code),
                stderr: cargo_out.stderr,
                stdout: cargo_out.stdout,
            });
        }

        // 5. Locate the produced cdylib. Cargo converts `-` → `_` in the lib name unless [lib].name
        //    is set; we use the default (cargo's transform). The lookup uses the per-build cargo
        //    crate name, which is unique to this invocation — no race with concurrent builds for
        //    the same agent-facing crate.
        let lib_basename = lib_filename(&cargo_crate_name);
        let lib_path = self.config.target_dir.join("release").join(&lib_basename);
        let artifact_bytes =
            read_file_bounded(&lib_path, "produced cdylib", MAX_BUILT_ARTIFACT_BYTES).map_err(
                |e| BuildFailure {
                    kind: BuildErrorKind::NoArtifact,
                    message: e,
                    stderr: cargo_out.stderr.clone(),
                    stdout: cargo_out.stdout.clone(),
                },
            )?;

        // 6. Compute hashes, populate provenance, sign. The signature commits to the manifest with
        //    `signature` field cleared (Manifest::signing_payload), so re-verification on the
        //    receiving side is independent of the producer.
        let source_hash = sha256_hex(req.source.as_bytes());
        let build_hash = sha256_hex(&artifact_bytes);
        let mut manifest = Manifest {
            name: req.manifest_stub.name.clone(),
            version: req.manifest_stub.version.clone(),
            abi: Abi {
                backend: Backend::Daemon,
                abi_tag: aether::ffi::ABI_TAG.to_string(),
                target: vec![host_triple()],
            },
            entrypoints: req.manifest_stub.entrypoints.clone(),
            capabilities: req.manifest_stub.capabilities.clone(),
            requirements: Default::default(),
            provenance: Provenance {
                author: Some(self.config.author_label.clone()),
                source_hash: Some(source_hash),
                build_hash: Some(build_hash.clone()),
                signature: None,
                // build-cargo doesn't claim a Realm — federation participation is operator policy,
                // not a build-time decision. A future per-build Realm assertion can come from
                // operator config. `None` serializes as omitted.
                realm: None,
            },
            content_address: None,
            provides: req.manifest_stub.provides.clone(),
        };
        // **Signing order is load-bearing.** `signing_payload()` strips only `provenance.signature`,
        // not `content_address` — so the content address must be set BEFORE signing, otherwise the
        // verifier on the other side recomputes `signing_payload` over a manifest whose
        // `content_address` was populated *after* the producer signed and the signature drifts.
        // (Caught when the loop runs end-to-end through `Kernel::load`.)
        manifest.content_address = Some(manifest.compute_content_address());
        let signature = self.config.signing_key.sign(&manifest.signing_payload());
        manifest.provenance.signature = Some(signature);

        // 7. Sanity: validate. If the agent supplied a stub that fails the entrypoint gate,
        //    this fires *here* — the build does not silently emit an inadmissible
        //    manifest. The agent then sees a structured `Invalid` reply and revises.
        manifest.validate().map_err(|e| BuildFailure {
            kind: BuildErrorKind::Invalid,
            message: format!("authored manifest fails validation: {e}"),
            stderr: cargo_out.stderr.clone(),
            stdout: cargo_out.stdout.clone(),
        })?;

        Ok((manifest, artifact_bytes))
    }

    fn invoke_cargo(&self, work_dir: &PathBuf) -> std::io::Result<CargoRun> {
        // Build the argv: optional sandbox prefix + cargo + flags.
        let mut argv: Vec<String> = match &self.config.sandbox {
            Sandbox::None => Vec::new(),
            Sandbox::Custom(prefix) => prefix.clone(),
        };
        argv.push("cargo".to_string());
        argv.push("build".to_string());
        argv.push("--release".to_string());
        argv.push("--manifest-path".to_string());
        argv.push(work_dir.join("Cargo.toml").display().to_string());
        argv.push("--target-dir".to_string());
        argv.push(self.config.target_dir.display().to_string());
        // Quiet so cargo doesn't spew "compiling X" lines into stderr (still get errors).
        argv.push("--quiet".to_string());

        if argv.is_empty() {
            // Defensive — shouldn't happen because we always push "cargo".
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty argv"));
        }
        let mut cmd = Command::new(&argv[0]);
        cmd.args(&argv[1..])
            .current_dir(work_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let started = Instant::now();
        let mut child = cmd.spawn()?;

        // **Drain stdout/stderr CONCURRENTLY with the wait.** cargo's pipe buffers are ~64 KiB; an
        // error-heavy build that writes more than that BLOCKS on `write` until someone reads. The
        // old code only read AFTER `wait` returned — so on a noisy failure cargo never exited,
        // `try_wait` spun to the full timeout, and `cargo_lock` was held the entire window, stalling
        // every queued build. The deadlock trigger was the very diagnostic stderr the authoring
        // agent needs. Two reader threads `read`-to-EOF into bounded buffers while the main thread
        // polls for exit + enforces the timeout. (We keep the poll loop rather than pull in
        // `wait_timeout` — the deliberate no-extra-dep stance; the timeout is in minutes.)
        let stdout_pipe = child.stdout.take();
        let stderr_pipe = child.stderr.take();
        let stdout_reader = std::thread::spawn(move || drain_pipe_capped(stdout_pipe, CAPTURE_CAP));
        let stderr_reader = std::thread::spawn(move || drain_pipe_capped(stderr_pipe, CAPTURE_CAP));

        let (status_opt, wait_error) = loop {
            match child.try_wait() {
                Ok(Some(s)) => break (Some(s), None),
                Ok(None) => {
                    if started.elapsed() >= self.config.cargo_timeout {
                        let _ = child.kill();
                        let _ = child.wait();
                        break (None, None);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                // A `try_wait` failure is an I/O fault on our side, NOT a timeout — report it as
                // such (the old code conflated it with both Timeout and sandbox-failure). (T15)
                Err(e) => break (None, Some(e.to_string())),
            }
        };
        // The child has exited / been killed / errored: its pipe write-ends are closed, so the
        // readers hit EOF and return. Join them to collect the full captured output.
        let stdout = stdout_reader.join().unwrap_or_default();
        let stderr = stderr_reader.join().unwrap_or_default();
        if let Some(e) = &wait_error {
            eprintln!("build-cargo: waiting on the cargo subprocess failed: {e}");
        }
        let (status_code, status_success, timed_out) = match status_opt {
            Some(s) => (s.code().unwrap_or(-1), s.success(), false),
            // No status AND no wait_error ⇒ we killed it on timeout; a wait_error is reported by
            // the caller as Io, not Timeout.
            None => (-1, false, wait_error.is_none()),
        };
        // A sandbox prefix that fails to launch (`ENOENT` from a typo'd `bwrap` path, for
        // example) lands as a spawn error from `cmd.spawn()` — surfaced above as `BuildFailure::io`.
        // A sandbox prefix whose inner cargo invocation failed with a sandbox-specific exit status
        // can't be distinguished from compile failure here in the general case; the test (e) covers
        // the spawn-failure case explicitly.
        Ok(CargoRun { status_code, status_success, timed_out, wait_error, stdout, stderr })
    }
}

/// `BuildOp::Build` payload, already split into its fields for the direct `build()` helper. The bus
/// path goes via JSON deserialization first; this is a convenience shape for tests.
#[derive(Clone)]
pub struct BuildRequest {
    pub crate_name: String,
    pub crate_version: String,
    pub source: String,
    pub manifest_stub: ManifestStub,
    pub deps: Vec<CargoDep>,
}

struct CargoRun {
    status_code: i32,
    status_success: bool,
    timed_out: bool,
    /// `Some` if `try_wait` itself errored (an I/O fault on our side, distinct from a timeout or a
    /// compile failure). The caller maps it to [`BuildErrorKind::Io`].
    wait_error: Option<String>,
    stdout: String,
    stderr: String,
}

impl CargoRun {
    fn timed_out_kind(&self) -> Option<BuildErrorKind> {
        if self.timed_out {
            Some(BuildErrorKind::Timeout)
        } else {
            None
        }
    }
}

struct BuildFailure {
    kind: BuildErrorKind,
    message: String,
    stderr: String,
    stdout: String,
}

impl BuildFailure {
    fn invalid(msg: impl Into<String>) -> Self {
        BuildFailure {
            kind: BuildErrorKind::Invalid,
            message: msg.into(),
            stderr: String::new(),
            stdout: String::new(),
        }
    }
    fn io(msg: impl Into<String>) -> Self {
        BuildFailure {
            kind: BuildErrorKind::Io,
            message: msg.into(),
            stderr: String::new(),
            stdout: String::new(),
        }
    }
}

impl Creature for BuildCargo {
    fn bind(&mut self, ctx: CreatureCtx) {
        // Capture the bus + this creature's CreatureId so build events can be published on the
        // proprioception topic. Done at bind (not construction) because the bus only exists once
        // the creature is registered with the router.
        *self.bus_ctx.lock().unwrap_or_else(|p| p.into_inner()) = Some((ctx.bus, ctx.me));
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reply = if env.payload.len() > MAX_BUILD_OP_BYTES {
            BuildReply::Failed {
                kind: BuildErrorKind::Invalid,
                message: format!(
                    "build op payload is {} bytes, exceeds {} byte limit",
                    env.payload.len(),
                    MAX_BUILD_OP_BYTES
                ),
                stderr: String::new(),
                stdout: String::new(),
            }
        } else {
            match serde_json::from_slice::<BuildOp>(&env.payload) {
                Ok(BuildOp::Build { crate_name, crate_version, source, manifest_stub, deps }) => {
                    self.build(BuildRequest {
                        crate_name,
                        crate_version,
                        source,
                        manifest_stub,
                        deps,
                    })
                }
                Err(e) => BuildReply::Failed {
                    kind: BuildErrorKind::Invalid,
                    message: format!("malformed build op: {e}"),
                    stderr: String::new(),
                    stdout: String::new(),
                },
            }
        };
        let payload = reply.to_bytes();
        Outcome::send(Dispatch::reply_to_env(&env, payload).with_schema("build.reply"))
    }
}

fn generate_cargo_toml(
    crate_name: &str,
    crate_version: &str,
    workspace_root: &Path,
    extra_deps: &[CargoDep],
) -> String {
    // Path deps use absolute paths so the temp workspace doesn't have to live under the Alpha
    // workspace root. `escape_toml_path` handles spaces / backslashes on the operator's host.
    let sdk_path = workspace_root.join("forge");
    let mut s = String::new();
    s.push_str("[package]\n");
    s.push_str(&format!("name = \"{crate_name}\"\n"));
    s.push_str(&format!("version = {}\n", toml_string(crate_version)));
    s.push_str("edition = \"2021\"\n");
    // The authored creature inherits the workspace's allocator invariant — no custom allocators —
    // implicitly: it has no `#[global_allocator]` because the template doesn't add one. The
    // generated Cargo.toml does NOT belong to the Alpha workspace (it's standalone), so the
    // workspace `[workspace]` invariant comment doesn't propagate; the agent must know not to add
    // one. The substrate's safeguard is the allocator-tied FFI: misuse manifests as UAF on unload.
    s.push_str("\n[lib]\ncrate-type = [\"cdylib\"]\n");

    s.push_str("\n[dependencies]\n");
    s.push_str(&format!("forge = {{ path = {} }}\n", toml_string(&sdk_path.display().to_string())));
    for dep in extra_deps {
        let line = match &dep.spec {
            CargoDepSpec::Version(v) => format!("{} = {}\n", dep.name, toml_string(v)),
            CargoDepSpec::Path(p) => {
                format!("{} = {{ path = {} }}\n", dep.name, toml_string(&p.display().to_string()))
            }
            CargoDepSpec::PathFeatures { path, features } => {
                let feats = features
                    .iter()
                    .map(|f| toml_string(f).to_string())
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "{} = {{ path = {}, features = [{}] }}\n",
                    dep.name,
                    toml_string(&path.display().to_string()),
                    feats
                )
            }
        };
        s.push_str(&line);
    }

    // `[profile.release]` defaults are fine here; LTO + strip add minutes and the artifact-hash
    // gate doesn't care about size. The signing path commits to whatever bytes cargo produced.
    s
}

/// Minimal TOML string escaping — wrap in `"..."`, escape `\` and `"`. The crate name / version
/// validation upstream means we never see embedded newlines, and we never serialize array-of-table.
fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

fn is_cargo_package_version(s: &str) -> bool {
    !s.trim().is_empty()
        && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '+'))
}

fn validate_deps(deps: &[CargoDep]) -> Result<(), BuildFailure> {
    if deps.len() > MAX_BUILD_DEPS {
        return Err(BuildFailure::invalid(format!(
            "dependency list has {} entries, exceeds {} entry limit",
            deps.len(),
            MAX_BUILD_DEPS
        )));
    }

    let mut seen = std::collections::HashSet::new();
    for dep in deps {
        validate_text_len("dependency name", &dep.name, MAX_CARGO_NAME_BYTES)?;
        if dep.name == "forge" {
            return Err(BuildFailure::invalid(
                "dependency `forge` is reserved; build-cargo injects the SDK dependency",
            ));
        }
        if !seen.insert(dep.name.as_str()) {
            return Err(BuildFailure::invalid(format!("duplicate dependency `{}`", dep.name)));
        }
        // Validate dependency names + interpolated strings BEFORE they reach Cargo.toml. The dep
        // NAME lands in TOML *key* position UNESCAPED (`{name} = ...`), so a name containing a
        // newline + `]` could inject a `[profile.release]` table or an extra build-dependency beyond
        // the structured grant. Versions / paths / features pass through `toml_string` (quote +
        // backslash escaped), but a literal control char (newline) would still break the basic
        // string — reject those too. (T10)
        if !dep.name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_') {
            return Err(BuildFailure::invalid(format!(
                "dependency name `{}` is not a valid cargo crate name (alphanumeric / `-` / `_`)",
                dep.name
            )));
        }
        match &dep.spec {
            CargoDepSpec::Version(v) => {
                validate_dep_text(&dep.name, "version", v, MAX_CARGO_DEP_FIELD_BYTES)?;
            }
            CargoDepSpec::Path(p) => {
                validate_dep_text(
                    &dep.name,
                    "path",
                    &p.display().to_string(),
                    MAX_CARGO_DEP_FIELD_BYTES,
                )?;
            }
            CargoDepSpec::PathFeatures { path, features } => {
                validate_dep_text(
                    &dep.name,
                    "path",
                    &path.display().to_string(),
                    MAX_CARGO_DEP_FIELD_BYTES,
                )?;
                if features.len() > MAX_CARGO_DEP_FEATURES {
                    return Err(BuildFailure::invalid(format!(
                        "dependency `{}` has {} features, exceeds {} feature limit",
                        dep.name,
                        features.len(),
                        MAX_CARGO_DEP_FEATURES
                    )));
                }
                for feature in features {
                    if feature.trim().is_empty() {
                        return Err(BuildFailure::invalid(format!(
                            "dependency `{}` has an empty feature name",
                            dep.name
                        )));
                    }
                    validate_dep_text(&dep.name, "feature", feature, MAX_CARGO_FEATURE_BYTES)?;
                }
            }
        }
    }
    Ok(())
}

fn validate_dep_text(
    dep_name: &str,
    field: &str,
    value: &str,
    max: usize,
) -> Result<(), BuildFailure> {
    validate_text_len(&format!("dependency `{dep_name}` {field}"), value, max)?;
    if value.chars().any(|c| c.is_control()) {
        return Err(BuildFailure::invalid(format!(
            "dependency `{dep_name}` has a {field} containing control characters"
        )));
    }
    Ok(())
}

fn validate_text_len(label: &str, value: &str, max: usize) -> Result<(), BuildFailure> {
    if value.len() > max {
        Err(BuildFailure::invalid(format!(
            "{label} is {} bytes, exceeds {} byte limit",
            value.len(),
            max
        )))
    } else {
        Ok(())
    }
}

fn validate_manifest_stub(stub: &ManifestStub) -> Result<(), BuildFailure> {
    validate_manifest_stub_shape(stub, Backend::Daemon, aether::ffi::ABI_TAG, vec![host_triple()])
        .map_err(BuildFailure::invalid)
}

/// Validate the authored manifest half before a builder performs expensive work.
///
/// This enforces the same structural gate as [`Manifest::validate`] plus bounded metadata/list sizes
/// so a valid under-cap build request cannot inflate into a giant signed manifest or bus reply.
pub fn validate_manifest_stub_shape(
    stub: &ManifestStub,
    backend: Backend,
    abi_tag: &str,
    target: Vec<String>,
) -> Result<(), String> {
    validate_stub_text_len("manifest_stub.name", &stub.name, MAX_CARGO_NAME_BYTES)?;
    validate_stub_text_len("manifest_stub.version", &stub.version, MAX_CARGO_VERSION_BYTES)?;
    validate_stub_list_len(
        "manifest_stub.entrypoints",
        stub.entrypoints.len(),
        MAX_MANIFEST_STUB_ENTRYPOINTS,
    )?;
    for ep in &stub.entrypoints {
        validate_stub_text_len(
            "manifest_stub.entrypoints[].name",
            &ep.name,
            MAX_MANIFEST_STUB_ENTRYPOINT_NAME_BYTES,
        )?;
        validate_stub_text_len(
            "manifest_stub.entrypoints[].signature",
            &ep.signature,
            MAX_MANIFEST_STUB_ENTRYPOINT_SIGNATURE_BYTES,
        )?;
    }
    validate_stub_list_len(
        "manifest_stub.provides",
        stub.provides.len(),
        MAX_MANIFEST_STUB_PROVIDES,
    )?;
    for role in &stub.provides {
        validate_stub_text_len("manifest_stub.provides[]", role, MAX_MANIFEST_STUB_PROVIDES_BYTES)?;
    }
    validate_stub_string_list(
        "manifest_stub.capabilities.fs",
        &stub.capabilities.fs,
        MAX_MANIFEST_STUB_CAPABILITY_ITEMS,
        MAX_MANIFEST_STUB_CAPABILITY_FIELD_BYTES,
    )?;
    validate_stub_string_list(
        "manifest_stub.capabilities.calls",
        &stub.capabilities.calls,
        MAX_MANIFEST_STUB_CAPABILITY_ITEMS,
        MAX_MANIFEST_STUB_CAPABILITY_FIELD_BYTES,
    )?;

    let mut manifest =
        Manifest::new(stub.name.clone(), stub.version.clone(), backend, abi_tag.to_string());
    manifest.abi.target = target;
    manifest.entrypoints = stub.entrypoints.clone();
    manifest.capabilities = stub.capabilities.clone();
    manifest.provides = stub.provides.clone();
    manifest.validate().map_err(|e| format!("manifest_stub fails validation: {e}"))
}

fn validate_stub_string_list(
    label: &str,
    values: &[String],
    max_entries: usize,
    max_field_bytes: usize,
) -> Result<(), String> {
    validate_stub_list_len(label, values.len(), max_entries)?;
    for value in values {
        validate_stub_text_len(&format!("{label}[]"), value, max_field_bytes)?;
    }
    Ok(())
}

fn validate_stub_list_len(label: &str, len: usize, max: usize) -> Result<(), String> {
    if len > max {
        Err(format!("{label} has {len} entries, exceeds {max} entry limit"))
    } else {
        Ok(())
    }
}

fn validate_stub_text_len(label: &str, value: &str, max: usize) -> Result<(), String> {
    if value.len() > max {
        Err(format!("{label} is {} bytes, exceeds {max} byte limit", value.len()))
    } else {
        Ok(())
    }
}

/// Reap this build's UNIQUE outputs from the SHARED target dir so they don't accumulate forever.
/// Each ephemeral build uses a unique cargo crate name and is never reused (see the
/// fingerprint-collision note in `run_build`), so removing its outputs is safe — and the canonical
/// SDK/aether dep caches (different names) are left untouched, preserving cross-build dep reuse.
/// Best-effort: every operation ignores errors. (T15)
fn reap_build_artifacts(target_dir: &Path, cargo_crate_name: &str) {
    let release = target_dir.join("release");
    let lib_stem = format!("lib{}", cargo_crate_name.replace('-', "_"));
    // release/lib<stem>.{so,dylib,dll} + the .d depfile.
    let _ = std::fs::remove_file(release.join(lib_filename(cargo_crate_name)));
    let _ = std::fs::remove_file(release.join(format!("{lib_stem}.d")));
    // release/deps/lib<stem>-<hash>.{so,d}
    remove_entries_with_prefix(&release.join("deps"), &lib_stem, false);
    // release/.fingerprint/<cargo_crate_name>-<hash>/
    remove_entries_with_prefix(&release.join(".fingerprint"), cargo_crate_name, true);
}

/// Remove files (`dirs=false`) or directories (`dirs=true`) directly under `dir` whose file name
/// starts with `prefix`. Best-effort; ignores all errors.
fn remove_entries_with_prefix(dir: &Path, prefix: &str, dirs: bool) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if name.starts_with(prefix) {
            if dirs {
                let _ = std::fs::remove_dir_all(entry.path());
            } else {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
}

fn lib_filename(crate_name: &str) -> String {
    // Cargo replaces `-` with `_` in the default lib name and prefixes `lib` on Unix.
    let stem = crate_name.replace('-', "_");
    if cfg!(target_os = "windows") {
        format!("{stem}.dll")
    } else if cfg!(target_os = "macos") {
        format!("lib{stem}.dylib")
    } else {
        format!("lib{stem}.so")
    }
}

fn host_triple() -> String {
    // `rustc -vV` carries the triple, but we hardcode the conventional Linux x86_64
    // string — the only target this codebase currently runs on. Future: detect at build-cargo
    // construction (one rustc invocation) and cache. The fabric still doesn't *interpret* the
    // string — it's metadata for a future Distributor matcher.
    "x86_64-unknown-linux-gnu".to_string()
}

/// Bytes of captured cargo output retained per stream. We keep *draining* past this (so the child
/// never blocks on a full pipe — the whole point of reading concurrently), but bound the memory we
/// hold for a build that spews unboundedly. Generous headroom above the 64 KiB/16 KiB the reply
/// truncates to, so no real diagnostic is lost.
const CAPTURE_CAP: usize = 1024 * 1024;

/// Read a child pipe to EOF, RETAINING at most `cap` bytes but always consuming the rest so the
/// child can never block on a full pipe buffer (the deadlock the concurrent reader threads exist to
/// prevent). On a read error, append a marker so a truncated capture is *discoverable* rather than
/// silently short. Best-effort; never panics (R9).
fn drain_pipe_capped(pipe: Option<impl std::io::Read + Send + 'static>, cap: usize) -> String {
    let Some(mut p) = pipe else { return String::new() };
    let mut kept: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        match std::io::Read::read(&mut p, &mut scratch) {
            Ok(0) => break,
            Ok(n) => {
                if kept.len() < cap {
                    let take = n.min(cap - kept.len());
                    kept.extend_from_slice(&scratch[..take]);
                }
                // bytes past `cap` are read (draining the pipe) but discarded
            }
            Err(_) => {
                kept.extend_from_slice(b"\n[build-cargo: output read error; capture truncated]");
                break;
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

fn prefix_on_char_boundary(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut cut = max;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    &s[..cut]
}

fn bounded_event_text(s: &str) -> String {
    let prefix = prefix_on_char_boundary(s, MAX_BUILD_EVENT_FIELD_BYTES);
    if prefix.len() == s.len() {
        prefix.to_string()
    } else {
        format!("{prefix}\n... (truncated; {} bytes total)", s.len())
    }
}

fn truncate(mut s: String, max: usize) -> String {
    if s.len() > max {
        let cut = prefix_on_char_boundary(&s, max).len();
        s.truncate(cut);
        s.push_str("\n... (truncated)");
    }
    s
}

fn read_file_bounded(path: &Path, label: &str, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("{label} {} unreadable: {e}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{label} {} is not a regular file", path.display()));
    }
    if metadata.len() > max_bytes {
        return Err(format!(
            "{label} {} is {} bytes, exceeds {} byte limit",
            path.display(),
            metadata.len(),
            max_bytes
        ));
    }

    let file =
        File::open(path).map_err(|e| format!("{label} {} unreadable: {e}", path.display()))?;
    let mut reader = file.take(max_bytes.saturating_add(1));
    let mut bytes = Vec::with_capacity(metadata.len().min(1024 * 1024) as usize);
    reader
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{label} {} read failed: {e}", path.display()))?;
    if u64::try_from(bytes.len()).map_or(true, |len| len > max_bytes) {
        return Err(format!(
            "{label} {} grew past {} byte limit while reading",
            path.display(),
            max_bytes
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signing_key() -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::generate().expect("ed25519 keygen").0
    }

    #[test]
    fn lib_filename_follows_cargo_dash_to_underscore() {
        assert_eq!(lib_filename("reverse-daemon"), "libreverse_daemon.so");
        assert_eq!(lib_filename("plain"), "libplain.so");
    }

    #[test]
    fn generate_cargo_toml_includes_path_dep_to_sdk() {
        let toml = generate_cargo_toml(
            "x",
            "0.1.0-alpha.1+build.7",
            &PathBuf::from("/tmp/gawd"),
            &[CargoDep { name: "ureq".into(), spec: CargoDepSpec::Version("2".into()) }],
        );
        assert!(toml.contains("crate-type = [\"cdylib\"]"));
        assert!(toml.contains("version = \"0.1.0-alpha.1+build.7\""));
        assert!(toml.contains("forge = { path = \"/tmp/gawd/forge\" }"));
        assert!(toml.contains("ureq = \"2\""));
    }

    #[test]
    fn invalid_request_yields_invalid_reply_not_panic() {
        // R9: a malformed BuildRequest is a structured error, never a node crash.
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let reply = bc.build(BuildRequest {
            crate_name: "".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub::default(),
            deps: vec![],
        });
        match reply {
            BuildReply::Failed { kind, .. } => assert_eq!(kind, BuildErrorKind::Invalid),
            BuildReply::Built { .. } => panic!("empty crate_name should never produce Built"),
        }
    }

    #[test]
    fn crate_name_must_match_manifest_stub_name() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let reply = bc.build(BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub { name: "bar".into(), ..Default::default() },
            deps: vec![],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("does not match"), "{message}");
            }
            _ => panic!("name mismatch should yield Invalid"),
        }
    }

    #[test]
    fn crate_version_must_match_manifest_stub_version() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let reply = bc.build(BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.2.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("does not match"), "{message}");
            }
            _ => panic!("version mismatch should yield Invalid"),
        }
    }

    #[test]
    fn crate_version_rejects_toml_structure_injection_before_disk() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let injected = "0.1.0\"\n[profile.release]\npanic = \"abort";
        let reply = bc.build(BuildRequest {
            crate_name: "foo".into(),
            crate_version: injected.into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: injected.into(),
                ..Default::default()
            },
            deps: vec![],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("safe Cargo package version"), "{message}");
            }
            _ => panic!("version injection should yield Invalid"),
        }
    }

    #[test]
    fn oversized_crate_metadata_is_rejected_before_paths_or_cargo() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let long_name = "a".repeat(MAX_CARGO_NAME_BYTES + 1);
        let reply = bc.build(BuildRequest {
            crate_name: long_name.clone(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: long_name,
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("crate_name"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("oversized crate metadata should yield Invalid"),
        }
    }

    #[test]
    fn too_many_dependencies_are_rejected_before_cargo() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let dep = CargoDep { name: "dep".into(), spec: CargoDepSpec::Version("1".into()) };
        let reply = bc.build(BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![dep; MAX_BUILD_DEPS + 1],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("dependency list"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("too many dependencies should yield Invalid"),
        }
    }

    #[test]
    fn dependency_shape_caps_are_rejected_before_cargo() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let reply = bc.build(BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![CargoDep {
                name: "dep".into(),
                spec: CargoDepSpec::PathFeatures {
                    path: PathBuf::from("/tmp/dep"),
                    features: (0..=MAX_CARGO_DEP_FEATURES).map(|i| format!("f{i}")).collect(),
                },
            }],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("features"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("too many dependency features should yield Invalid"),
        }

        let reply = bc.build(BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![CargoDep {
                name: "dep".into(),
                spec: CargoDepSpec::Version("1".repeat(MAX_CARGO_DEP_FIELD_BYTES + 1)),
            }],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("dependency `dep` version"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("oversized dependency version should yield Invalid"),
        }
    }

    #[test]
    fn duplicate_and_reserved_dependencies_are_rejected_structurally() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let base = || BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![],
        };

        let mut duplicate = base();
        duplicate.deps = vec![
            CargoDep { name: "dep".into(), spec: CargoDepSpec::Version("1".into()) },
            CargoDep { name: "dep".into(), spec: CargoDepSpec::Version("2".into()) },
        ];
        match bc.build(duplicate) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("duplicate dependency"), "{message}");
            }
            _ => panic!("duplicate dependency should yield Invalid"),
        }

        let mut reserved = base();
        reserved.deps =
            vec![CargoDep { name: "forge".into(), spec: CargoDepSpec::Version("1".into()) }];
        match bc.build(reserved) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("reserved"), "{message}");
            }
            _ => panic!("reserved forge dependency should yield Invalid"),
        }
    }

    #[test]
    fn invalid_manifest_stub_shape_is_rejected_before_cargo() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let base = || BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![],
        };

        let mut duplicate_ep = base();
        duplicate_ep.manifest_stub.entrypoints = vec![
            Entrypoint { name: "handle".into(), signature: "(Envelope) -> Outcome".into() },
            Entrypoint { name: "handle".into(), signature: "(Envelope) -> Outcome".into() },
        ];
        match bc.build(duplicate_ep) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("manifest_stub"), "{message}");
                assert!(message.contains("duplicate entrypoint"), "{message}");
            }
            _ => panic!("duplicate entrypoints should yield Invalid before cargo"),
        }

        let mut duplicate_provides = base();
        duplicate_provides.manifest_stub.provides = vec!["policy".into(), "policy".into()];
        match bc.build(duplicate_provides) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("manifest_stub"), "{message}");
                assert!(message.contains("duplicate provides"), "{message}");
            }
            _ => panic!("duplicate provides should yield Invalid before cargo"),
        }
    }

    #[test]
    fn manifest_stub_size_caps_are_rejected_before_cargo() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let base = || BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "// anything".into(),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![],
        };

        let mut too_many_entrypoints = base();
        too_many_entrypoints.manifest_stub.entrypoints = (0..=MAX_MANIFEST_STUB_ENTRYPOINTS)
            .map(|i| Entrypoint {
                name: format!("handle_{i}"),
                signature: "(Envelope) -> Outcome".into(),
            })
            .collect();
        match bc.build(too_many_entrypoints) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("manifest_stub.entrypoints"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("oversized entrypoint list should yield Invalid before cargo"),
        }

        let mut oversized_call_cap = base();
        oversized_call_cap.manifest_stub.capabilities.calls =
            vec!["role:".to_string() + &"x".repeat(MAX_MANIFEST_STUB_CAPABILITY_FIELD_BYTES + 1)];
        match bc.build(oversized_call_cap) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("manifest_stub.capabilities.calls"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("oversized capability call should yield Invalid before cargo"),
        }
    }

    #[test]
    fn build_text_truncation_respects_utf8_boundaries() {
        let s = format!("{}é", "a".repeat(7));
        let out = truncate(s, 8);
        assert!(out.starts_with("aaaaaaa\n..."), "{out:?}");

        let event =
            bounded_event_text(&format!("{}é", "a".repeat(MAX_BUILD_EVENT_FIELD_BYTES - 1)));
        assert!(event.contains("truncated"), "{event:?}");
    }

    #[test]
    fn oversized_source_is_rejected_before_disk() {
        let bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let reply = bc.build(BuildRequest {
            crate_name: "foo".into(),
            crate_version: "0.1.0".into(),
            source: "x".repeat(MAX_AUTHORED_SOURCE_BYTES + 1),
            manifest_stub: ManifestStub {
                name: "foo".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("oversized source should yield Invalid"),
        }
    }

    #[test]
    fn oversized_built_artifact_file_is_rejected_before_reading() {
        let dir = std::env::temp_dir().join(format!(
            "build-cargo-artifact-bound-{}-{}",
            std::process::id(),
            now_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("libhuge.so");
        std::fs::File::create(&path).unwrap().set_len(MAX_BUILT_ARTIFACT_BYTES + 1).unwrap();

        let err = read_file_bounded(&path, "produced cdylib", MAX_BUILT_ARTIFACT_BYTES)
            .expect_err("oversized artifact file should be refused before read");
        assert!(err.contains("produced cdylib"), "{err}");
        assert!(err.contains("exceeds"), "{err}");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_build_op_on_the_bus_yields_failed_reply_not_panic() {
        use aether::{Address, CreatureId, Header};
        let mut bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "".into(),
            },
            payload: b"{ not json".to_vec(),
        };
        let out = bc.handle(env);
        let r: BuildReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        assert!(
            matches!(r, BuildReply::Failed { kind: BuildErrorKind::Invalid, .. }),
            "expected Invalid Failed reply, got {r:?}"
        );
    }

    #[test]
    fn oversized_build_op_payload_is_rejected_before_json_parse() {
        use aether::{Address, CreatureId, Header};
        let mut bc = BuildCargo::new(BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent"),
            signing_key(),
            "tester",
        ));
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(7)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "".into(),
            },
            payload: vec![b'{'; MAX_BUILD_OP_BYTES + 1],
        };
        let out = bc.handle(env);
        let r: BuildReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        match r {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("build op payload"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            _ => panic!("oversized build op should yield Invalid"),
        }
    }
}
