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
//! ## Resource boundary
//!
//! Authored Cargo runs default to one build job and one codegen unit. On Unix, every invocation gets
//! a private process group. Timeout/error paths kill and reap the complete normal tree; after even a
//! successful or compile-failed Cargo leader exits, build-cargo also kills any residual group members
//! before inspecting the cache or artifact. A custom wrapper must not deliberately escape that group
//! by creating a new session; on non-Unix hosts the wrapper/operator must provide equivalent
//! process-tree containment because the standard-library fallback can guarantee only direct-child
//! termination.
//!
//! The shared target cache has a finite default budget. It is checked before Cargo, periodically
//! while Cargo runs, and after exit with a bounded traversal that rejects symlinks, special files,
//! scan errors, excessive depth, and excessive entry counts. Periodic accounting detects an
//! application-level overshoot on the next sample; it cannot limit bytes written inside that
//! interval, so deployments requiring a strict hard disk cap must also use a filesystem quota.
//! Authored Cargo gets an isolated
//! `target_dir/.cargo-home`, so downloaded registry indexes/crates and unpacked sources live inside
//! this same generated-state budget rather than silently growing the operator's global Cargo home.
//! Every process sharing the cache also locks its retained `.alpha-build-cargo.lock` before the
//! preflight scan and Cargo spawn. Lock acquisition polls without spinning and consumes the same
//! wall-time budget as compilation, so two Alpha nodes cannot silently compile against the cache at
//! once or wait forever for one another.
//! That isolation intentionally does not inherit the operator's global Cargo config, credentials,
//! or warmed registry cache. Deployments that require an offline cache, source replacement, or an
//! authenticated/private registry must explicitly provision equivalent configuration in the
//! budgeted home (and inject credentials through their chosen provider); pointing authored Cargo
//! back at the unbudgeted global home would reopen the disk boundary.
//!
//! ## What this creature does NOT do
//!
//! - It does not author code (that's the [`Role::AUTHORING`](aether::Role::AUTHORING) seam).
//! - It does not load the artifact (that's the kernel's job, via the safe loader).
//! - It does not publish (that's the registry's job).
//! - It does not retry — the *agent* feeds back `prev_error` and re-authors; this creature is a pure
//!   compile-once function. Stateless on purpose: the loop's intelligence lives in the agent.

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt},
    process::CommandExt,
};

/// Process-wide monotonic counter ensuring every `run_build` materializes a uniquely-named
/// `work_dir`, even when two BuildCargo instances in the same process invoke a build for the same
/// `crate_name` within the same microsecond. A bare `{pid}-{nanos}-{crate_name}` formula
/// collides under exactly that pattern in a parallel test run: two parallel builds for
/// `reverse-daemon` would race-write `src/lib.rs` into the same path, and cargo's package-level
/// fingerprint cache would then service the second invocation from the first's compile output —
/// yielding a "successful" build of source that was never actually compiled. Counter is process-
/// local on purpose; an independent OS-random nonce below supplies crash/PID-reuse safety.
static WORK_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Entropy added to every Cargo package identity. Sixteen bytes keep the generated package/path
/// bounded while making identity reuse after a crash plus OS PID/counter reuse negligible.
const BUILD_ID_NONCE_BYTES: usize = 16;

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
/// Default ceiling for shared authored-Cargo state (target artifacts plus the nested Cargo home). It
/// is deliberately generous relative to the current cold SDK graph (~250 MiB) but finite: novel
/// dependency/version requests must not turn a long-lived authoring node into an unbounded disk sink.
pub const DEFAULT_MAX_TARGET_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Directory accounting is iterative and stops after this many entries even when their logical byte
/// total is small. That keeps a hostile many-empty-files tree from making the budget check itself
/// unbounded. Exceeding the accounting budget fails the build closed.
const MAX_TARGET_ACCOUNTING_ENTRIES: usize = 100_000;
/// Cargo target trees are shallow. Refuse pathological nesting instead of growing the traversal
/// stack without a structural bound.
const MAX_TARGET_ACCOUNTING_DEPTH: usize = 64;
/// Re-account periodically while Cargo is live. The final post-exit check closes the interval after
/// the last sample; this cadence limits overshoot without turning metadata walks into a hot loop.
const TARGET_ACCOUNTING_INTERVAL: Duration = Duration::from_secs(10);
/// Registry indexes, crate archives, and unpacked dependency sources belong to generated authoring
/// state and must be covered by the same target-cache accounting/cleanup boundary.
const AUTHORED_CARGO_HOME_DIR: &str = ".cargo-home";
/// Advisory lock shared by every build-cargo process using the same generated cache. Cargo's own
/// target/package locks preserve cache integrity but allow unrelated root packages to compile in
/// parallel; this retained regular file supplies Alpha's one-compile-at-a-time resource boundary.
const CACHE_LOCK_FILE: &str = ".alpha-build-cargo.lock";
/// Cross-process/local lock contention is polled rather than spun or blocked past the build budget.
const CACHE_LOCK_POLL: Duration = Duration::from_millis(50);
/// Never let an inherited pipe held by a broken/escaping wrapper keep the build lock forever after
/// the child has exited or been terminated. Normal Cargo closes both streams immediately.
const PIPE_DRAIN_GRACE: Duration = Duration::from_secs(2);

use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome, Topic,
    MAX_SENSE_EVENT_BYTES,
};
use ring::rand::{SecureRandom, SystemRandom};
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
    /// Compile (or sandbox / IO / capacity / timeout) failed. Structured so the agent can branch on
    /// `kind` and feed `stderr` back as `prev_error`. The node does not crash on a bad source.
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
    /// The generated target cache exceeded its finite byte/shape budget or could not be accounted
    /// safely. This is an operator resource condition; retrying different source cannot repair it.
    Capacity,
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
    /// (compile vs sandbox vs timeout vs capacity) without re-parsing the full reply.
    BuildFailed { crate_name: String, kind: BuildErrorKind, message: String },
}

/// Operator-opt-in sandbox seam. `None` = run cargo directly (the default — the threat model is
/// trusted operator authoring against their own substrate). `Custom(prefix)` prepends an arbitrary
/// command prefix to `cargo`, so the operator's containment model (bwrap / firejail / nsjail /
/// docker / podman / a custom wrapper) lives in operator config — build-cargo is agnostic.
///
/// On Unix, the wrapper and everything it launches must remain in build-cargo's private process
/// group. A wrapper that calls `setsid` (or otherwise moves descendants into another group/session)
/// assumes responsibility for killing and reaping that escaped tree. On non-Unix hosts, where the
/// standard library has no portable process-group primitive, production wrappers must provide the
/// platform's equivalent containment (for example, a Windows Job Object).
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
    /// 10× or more. It must be absolute. The isolated authored-Cargo home lives below it at
    /// `.cargo-home`, keeping downloaded dependencies in the same generated-cache budget; the
    /// retained `.alpha-build-cargo.lock` serializes all processes sharing it. Default:
    /// `<work_root>/build-cargo-target`. This deliberately does not inherit global Cargo-home
    /// config, credentials, or cached registries; operators using mirrors/private registries/offline
    /// mode must explicitly provision the isolated home without moving it outside the byte budget.
    pub target_dir: PathBuf,
    /// Maximum conservatively accounted bytes retained below [`Self::target_dir`]. On Unix each
    /// entry contributes the larger of logical length and allocated blocks. Default: 4 GiB.
    /// Accounting is iterative, entry/depth-bounded, rejects symlinks and special files, runs before
    /// Cargo, every ten seconds while it is live, and once after it exits. `0` is a one-byte
    /// fail-closed ceiling, not an unbounded opt-out. Cargo can write during the sampling interval,
    /// so put the cache on an operator-enforced filesystem quota when a strict hard cap is required.
    pub max_target_bytes: u64,
    /// Absolute path to the workspace root that owns `forge` / `aether` / `sigil` —
    /// the path-dep base. Build-cargo auto-adds `forge` as a path dep so the authored creature
    /// has the FFI macro and the typed prelude. Default: detected via `CARGO_MANIFEST_DIR/../../`.
    pub gawd_workspace_root: PathBuf,
    /// Hard timeout for shared-cache lock wait plus one Cargo invocation. Default 180 s — generous
    /// enough for a cold first build against the SDK, short enough that contention/runaway work
    /// never hangs the node.
    pub cargo_timeout: Duration,
    /// Maximum Cargo crate-build jobs for one authored creature. Default `1`: live authoring must
    /// not monopolize the node merely because it has many logical CPUs. `0` is normalized to `1`.
    /// An operator may raise this deliberately on a dedicated build node.
    pub cargo_jobs: usize,
    /// Release-profile codegen units for authored creatures. Default `1`, preventing one rustc from
    /// bypassing `cargo_jobs` with parallel LLVM workers. `0` is normalized to `1`; dedicated build
    /// nodes may opt into a higher value explicitly.
    pub cargo_codegen_units: usize,
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
            max_target_bytes: DEFAULT_MAX_TARGET_BYTES,
            gawd_workspace_root,
            cargo_timeout: Duration::from_secs(180),
            cargo_jobs: 1,
            cargo_codegen_units: 1,
            sandbox: Sandbox::None,
            signing_key,
            author_label: author_label.into(),
        }
    }
}

/// The build creature.
pub struct BuildCargo {
    config: BuildConfig,
    /// First-level serialization for concurrent direct callers of this one instance. A retained
    /// advisory file inside `target_dir` supplies the cross-instance/process boundary too.
    cargo_lock: Mutex<()>,
    /// Bus + identity, captured at `bind` time, so proprio events can be published as builds start,
    /// succeed, or fail. `None` outside the bound state (direct `build()` callers — tests).
    bus_ctx: Mutex<Option<(Arc<dyn Bus>, CreatureId)>>,
}

impl BuildCargo {
    pub fn new(config: BuildConfig) -> Self {
        BuildCargo { config, cargo_lock: Mutex::new(()), bus_ctx: Mutex::new(None) }
    }

    fn check_target_budget(&self, phase: &str) -> Result<u64, String> {
        if !self.config.target_dir.is_absolute() {
            return Err(format!(
                "cargo target cache check {phase} refused relative target path {:?}; target_dir must be absolute",
                self.config.target_dir
            ));
        }
        let limit = self.config.max_target_bytes.max(1);
        account_target_tree(
            &self.config.target_dir,
            limit,
            MAX_TARGET_ACCOUNTING_ENTRIES,
            MAX_TARGET_ACCOUNTING_DEPTH,
        )
        .map_err(|error| {
            format!(
                "cargo target cache check {phase} failed for {:?} ({} byte limit): {error}. \
                 Stop every authoring build using this cache, then reclaim exactly it with \
                 `cargo clean --target-dir {:?}`",
                self.config.target_dir, limit, self.config.target_dir
            )
        })
    }

    fn acquire_local_cargo_lock(
        &self,
        budget_started: Instant,
    ) -> Result<MutexGuard<'_, ()>, BuildFailure> {
        loop {
            match self.cargo_lock.try_lock() {
                Ok(guard) => return Ok(guard),
                // The lock protects no partially-mutated data, only admission to Cargo, so poison
                // does not make the cache unsafe. Recover the guard exactly as the old blocking
                // acquisition did.
                Err(std::sync::TryLockError::Poisoned(poison)) => return Ok(poison.into_inner()),
                Err(std::sync::TryLockError::WouldBlock) => {
                    let Some(sleep_for) = self.lock_poll_delay(budget_started) else {
                        return Err(BuildFailure::capacity(format!(
                            "local authoring build queue for {:?} remained busy for the {:?} build budget; retry after the active build finishes",
                            self.config.target_dir, self.config.cargo_timeout
                        )));
                    };
                    std::thread::sleep(sleep_for);
                }
            }
        }
    }

    fn acquire_cross_process_cache_lock(
        &self,
        budget_started: Instant,
    ) -> Result<File, BuildFailure> {
        if !self.config.target_dir.is_absolute() {
            return Err(BuildFailure::capacity(format!(
                "refused relative Cargo cache path {:?}; target_dir must be absolute",
                self.config.target_dir
            )));
        }
        reject_symlink_path_components(&self.config.target_dir).map_err(|error| {
            BuildFailure::capacity(format!(
                "refused unsafe Cargo cache path {:?}: {error}",
                self.config.target_dir
            ))
        })?;
        std::fs::create_dir_all(&self.config.target_dir).map_err(|error| {
            BuildFailure::io(format!(
                "create Cargo cache directory {}: {error}",
                self.config.target_dir.display()
            ))
        })?;
        // Recheck after creation so a raced symlink or non-directory never reaches the lock open.
        reject_symlink_path_components(&self.config.target_dir).map_err(|error| {
            BuildFailure::capacity(format!(
                "refused unsafe Cargo cache path {:?} after creation: {error}",
                self.config.target_dir
            ))
        })?;
        let target_metadata =
            std::fs::symlink_metadata(&self.config.target_dir).map_err(|error| {
                BuildFailure::io(format!(
                    "inspect Cargo cache directory {}: {error}",
                    self.config.target_dir.display()
                ))
            })?;
        if !target_metadata.is_dir() || target_metadata.file_type().is_symlink() {
            return Err(BuildFailure::capacity(format!(
                "Cargo cache path {} is not a non-symlink directory",
                self.config.target_dir.display()
            )));
        }

        let lock_path = self.config.target_dir.join(CACHE_LOCK_FILE);
        if let Some(metadata) = symlink_metadata_if_present(&lock_path).map_err(|error| {
            BuildFailure::io(format!("inspect Cargo cache lock {}: {error}", lock_path.display()))
        })? {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(BuildFailure::capacity(format!(
                    "Cargo cache lock {} is not a retained regular file",
                    lock_path.display()
                )));
            }
        }
        let lock_file = open_retained_cache_lock(&lock_path).map_err(|error| {
            BuildFailure::io(format!("open Cargo cache lock {}: {error}", lock_path.display()))
        })?;
        verify_open_cache_lock(&lock_path, &lock_file).map_err(BuildFailure::capacity)?;

        loop {
            match lock_file.try_lock() {
                Ok(()) => return Ok(lock_file),
                Err(std::fs::TryLockError::WouldBlock) => {
                    let Some(sleep_for) = self.lock_poll_delay(budget_started) else {
                        return Err(BuildFailure::capacity(format!(
                            "shared Cargo cache {:?} remained locked by another authoring process for the {:?} build budget; retry after that build finishes",
                            self.config.target_dir, self.config.cargo_timeout
                        )));
                    };
                    std::thread::sleep(sleep_for);
                }
                Err(std::fs::TryLockError::Error(error)) => {
                    return Err(BuildFailure::io(format!(
                        "lock shared Cargo cache {}: {error}",
                        lock_path.display()
                    )))
                }
            }
        }
    }

    fn lock_poll_delay(&self, budget_started: Instant) -> Option<Duration> {
        let remaining = self.config.cargo_timeout.checked_sub(budget_started.elapsed())?;
        if remaining.is_zero() {
            None
        } else {
            Some(remaining.min(CACHE_LOCK_POLL))
        }
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
        //    operators see — but Cargo gets the fixed-width `alpha-authored-b{random}` so this
        //    build has its own fingerprint slot and its own `lib<unique>.so` output without
        //    amplifying a maximum-length agent-facing name into a filesystem component. Why this
        //    is load-bearing:
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
        //    PID + process-local counter alone are insufficient after a hard crash: the OS may
        //    reuse the PID while crash-left output remains. A fresh OS-random nonce makes the new
        //    identity independent of all previous process lifetimes and fails closed if entropy is
        //    unavailable.
        let counter = WORK_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
        let nonce = fresh_build_id_nonce().map_err(BuildFailure::io)?;
        let cargo_crate_name = cargo_crate_identity(&nonce);

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
        struct WorkDirCleanup {
            work_dir: PathBuf,
        }
        impl Drop for WorkDirCleanup {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.work_dir);
            }
        }
        let _work_dir_cleanup = WorkDirCleanup { work_dir: work_dir.clone() };

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

        // 4. Run cargo build under the local + cross-process locks, sandbox, and shared timeout. The
        //    target-dir is shared so SDK / aether do not recompile per request. Account it while
        //    holding both locks, immediately before spawning Cargo; a pre-existing over-cap,
        //    malformed, or unaccountable cache fails closed without launching a compiler.
        let build_budget_started = Instant::now();
        let _local_guard = self.acquire_local_cargo_lock(build_budget_started)?;
        let _cache_lock = self.acquire_cross_process_cache_lock(build_budget_started)?;

        // Declared after both lock guards so it runs BEFORE either lock is released, including on
        // every early return below. A second Alpha process therefore cannot acquire the cache and
        // preflight-account a just-finished build's otherwise-doomed unique artifact.
        struct BuildArtifactCleanup {
            target_dir: PathBuf,
            cargo_crate_name: String,
            active: bool,
        }
        impl BuildArtifactCleanup {
            fn cleanup(&mut self) -> Result<(), String> {
                if !self.active {
                    return Ok(());
                }
                self.active = false;
                reap_build_artifacts(&self.target_dir, &self.cargo_crate_name)
            }
        }
        impl Drop for BuildArtifactCleanup {
            fn drop(&mut self) {
                if !self.active {
                    return;
                }
                // Reap THIS build's unique outputs from the SHARED target dir (the cdylib + depfile
                // + fingerprint). SDK/aether dependency outputs remain reusable. An early compile
                // failure keeps its primary structured result; unsafe/incomplete cleanup is still
                // diagnosed and will fail the next mandatory cache accounting pass closed.
                if let Err(error) = reap_build_artifacts(&self.target_dir, &self.cargo_crate_name) {
                    eprintln!(
                        "build-cargo: unique artifact cleanup for {} was incomplete: {error}",
                        self.cargo_crate_name
                    );
                }
            }
        }
        let mut artifact_cleanup = BuildArtifactCleanup {
            target_dir: self.config.target_dir.clone(),
            cargo_crate_name: cargo_crate_name.clone(),
            active: true,
        };

        self.check_target_budget("before build").map_err(BuildFailure::capacity)?;
        let remaining_cargo_budget = self
            .config
            .cargo_timeout
            .checked_sub(build_budget_started.elapsed())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                BuildFailure::capacity(format!(
                    "the {:?} authoring build budget expired while waiting for and preflight-checking shared Cargo cache {:?}; Cargo was not started",
                    self.config.cargo_timeout, self.config.target_dir
                ))
            })?;
        let mut cargo_out = self
            .invoke_cargo(&work_dir, remaining_cargo_budget)
            .map_err(|e| BuildFailure::io(format!("spawn cargo: {e}")))?;
        if let Some(mut e) = cargo_out.resource_error.take() {
            if let Some(terminate_error) = cargo_out.wait_error.take() {
                e.push_str(&format!(". Process-tree teardown also failed: {terminate_error}"));
            }
            return Err(BuildFailure {
                kind: BuildErrorKind::Capacity,
                message: e,
                stderr: cargo_out.stderr,
                stdout: cargo_out.stdout,
            });
        }
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
                message: format!(
                    "authoring build exceeded the total {:?} budget (shared-cache lock wait and Cargo execution use one budget)",
                    self.config.cargo_timeout
                ),
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
        // The bytes are now owned in memory; remove this one-use Cargo identity before releasing
        // the shared-cache lock. Refusing a symlink/special/ambiguous cleanup as Capacity is safer
        // than returning success while known unique outputs will accumulate on every request.
        artifact_cleanup.cleanup().map_err(|error| {
            BuildFailure::capacity(format!(
                "unique Cargo artifact cleanup for `{cargo_crate_name}` failed safely: {error}. Stop authoring builds using {:?}, inspect it without following symlinks, then reclaim exactly it with `cargo clean --target-dir {:?}`",
                self.config.target_dir, self.config.target_dir
            ))
        })?;

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

    fn invoke_cargo(
        &self,
        work_dir: &PathBuf,
        cargo_timeout: Duration,
    ) -> std::io::Result<CargoRun> {
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
        argv.push("--jobs".to_string());
        argv.push(self.config.cargo_jobs.max(1).to_string());
        // Quiet so cargo doesn't spew "compiling X" lines into stderr (still get errors).
        argv.push("--quiet".to_string());

        if argv.is_empty() {
            // Defensive — shouldn't happen because we always push "cargo".
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "empty argv"));
        }
        let mut cmd = Command::new(&argv[0]);
        let authored_cargo_home = self.config.target_dir.join(AUTHORED_CARGO_HOME_DIR);
        cmd.args(&argv[1..])
            .current_dir(work_dir)
            // The generated manifest is a standalone workspace and cannot rely on Alpha's root
            // profile/config discovery. Carry the resource boundary into nested Cargo explicitly.
            .env("CARGO_INCREMENTAL", "0")
            // Never inherit the operator's unbudgeted global Cargo cache: novel version deps must
            // consume the same finite generated-state allowance as target artifacts.
            .env("CARGO_HOME", authored_cargo_home)
            .env(
                "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
                self.config.cargo_codegen_units.max(1).to_string(),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        configure_compile_process_group(&mut cmd);

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
        let stdout_reader = match spawn_pipe_reader(stdout_pipe, "stdout") {
            Ok(reader) => reader,
            Err(error) => {
                let terminate_error = terminate_compile_tree(&mut child).err();
                return Err(pipe_reader_spawn_error(error, terminate_error));
            }
        };
        let stderr_reader = match spawn_pipe_reader(stderr_pipe, "stderr") {
            Ok(reader) => reader,
            Err(error) => {
                let terminate_error = terminate_compile_tree(&mut child).err();
                return Err(pipe_reader_spawn_error(error, terminate_error));
            }
        };

        let mut next_target_check = Instant::now() + TARGET_ACCOUNTING_INTERVAL;
        let mut timed_out = false;
        let mut wait_error = None;
        let mut resource_error = None;
        let mut cancel_pipe_readers = false;
        let status_opt = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    // `try_wait` reaped the Cargo leader, but a build script can have left a
                    // background descendant in the inherited private process group. Sweep that
                    // group before the post-build cache scan or artifact read: otherwise a reply
                    // could return while unowned work keeps consuming CPU and disk. Preserve the
                    // leader's real status; teardown failure is reported separately as Io.
                    #[cfg(unix)]
                    if let Err(error) = terminate_residual_compile_group(child.id()) {
                        cancel_pipe_readers = true;
                        wait_error = Some(format!(
                            "terminating residual cargo process group after leader exit failed: {error}"
                        ));
                    }
                    break Some(status);
                }
                Ok(None) => {
                    if started.elapsed() >= cargo_timeout {
                        timed_out = true;
                        cancel_pipe_readers = true;
                        if let Err(error) = terminate_compile_tree(&mut child) {
                            wait_error = Some(format!(
                                "terminating timed-out cargo process tree failed: {error}"
                            ));
                        }
                        break None;
                    }
                    if Instant::now() >= next_target_check {
                        if let Err(error) = self.check_target_budget("while build was running") {
                            resource_error = Some(error);
                            cancel_pipe_readers = true;
                            if let Err(error) = terminate_compile_tree(&mut child) {
                                wait_error = Some(format!(
                                    "terminating over-budget cargo process tree failed: {error}"
                                ));
                            }
                            break None;
                        }
                        next_target_check = Instant::now() + TARGET_ACCOUNTING_INTERVAL;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                // A `try_wait` failure is an I/O fault on our side, NOT a timeout — report it as
                // such. Terminate the complete process group before collecting the pipe readers:
                // killing only Cargo could leave rustc/lld holding those pipes open indefinitely.
                Err(error) => {
                    cancel_pipe_readers = true;
                    let mut message = error.to_string();
                    if let Err(terminate_error) = terminate_compile_tree(&mut child) {
                        message.push_str(&format!(
                            "; terminating cargo process tree also failed: {terminate_error}"
                        ));
                    }
                    wait_error = Some(message);
                    break None;
                }
            }
        };

        // Close the sampling interval after Cargo exits. A cache that crossed the ceiling between
        // the last watchdog tick and process completion is still a failed build. The just-produced
        // root cdylib is included here and is reaped by CleanupOnDrop after the caller consumes it.
        // If the residual-group sweep itself failed, do not touch cache state whose producer may
        // still be live. That teardown fault remains the primary structured Io result.
        if status_opt.is_some() && wait_error.is_none() {
            if let Err(error) = self.check_target_budget("after build") {
                resource_error = Some(error);
            }
        }
        // A normal Cargo tree closes both write ends immediately. Keep collection bounded anyway:
        // a misconfigured Custom wrapper may have deliberately escaped the process group and kept an
        // inherited pipe open. That violates the wrapper contract above, but must not retain the
        // global cargo lock or turn a `try_wait` error into an unbounded join.
        if cancel_pipe_readers {
            // On Unix the readers poll their cancellation flag, drop the read descriptors, and
            // return within a bounded interval. In particular, a `try_wait` error cannot leave a
            // reader blocked forever even when a contract-violating wrapper escaped the group and
            // retained the corresponding write descriptor.
            stdout_reader.cancel();
            stderr_reader.cancel();
        }
        let (stdout, stderr) = receive_pipe_captures(stdout_reader, stderr_reader);
        if let Some(e) = &wait_error {
            eprintln!("build-cargo: waiting on the cargo subprocess failed: {e}");
        }
        let (status_code, status_success) = match status_opt {
            Some(s) => (s.code().unwrap_or(-1), s.success()),
            None => (-1, false),
        };
        // A sandbox prefix that fails to launch (`ENOENT` from a typo'd `bwrap` path, for
        // example) lands as a spawn error from `cmd.spawn()` — surfaced above as `BuildFailure::io`.
        // A sandbox prefix whose inner cargo invocation failed with a sandbox-specific exit status
        // can't be distinguished from compile failure here in the general case; the test (e) covers
        // the spawn-failure case explicitly.
        Ok(CargoRun {
            status_code,
            status_success,
            timed_out,
            wait_error,
            resource_error,
            stdout,
            stderr,
        })
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
    /// A pre/post/watchdog target-cache accounting failure. Kept distinct from `wait_error` so a
    /// cache limit is reported as [`BuildErrorKind::Capacity`] with exact cleanup guidance even after
    /// the process tree stopped.
    resource_error: Option<String>,
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

#[derive(Debug)]
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
    fn capacity(msg: impl Into<String>) -> Self {
        BuildFailure {
            kind: BuildErrorKind::Capacity,
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
    // implicitly: the template never installs a process-wide custom allocator. The
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

    // This manifest is standalone, so it cannot rely on Alpha's root profiles. Keep incremental
    // graphs off and within-crate codegen serial by default; `BuildConfig` carries an explicit env
    // override for operators who dedicate more CPU to authoring. LTO + strip remain off because
    // they add minutes and the artifact-hash gate commits to whatever bytes Cargo produced.
    s.push_str("\n[profile.release]\nincremental = false\ncodegen-units = 1\n");
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

/// Account the target cache without ever following a symbolic link. The traversal is iterative and
/// bounded by both entry count and depth; every inability to describe the complete in-scope tree is
/// an error, because treating an unreadable or structurally pathological cache as empty would turn
/// the disk ceiling into an opt-out. The sole exception is a path confirmed `NotFound` after Cargo
/// exposed it through `read_dir`: atomic rename/remove churn makes that an honest vanished entry for
/// this soft sample. Hard links are deliberately counted once per directory entry, which may
/// over-count logical bytes but never under-count them.
fn account_target_tree(
    root: &Path,
    max_bytes: u64,
    max_entries: usize,
    max_depth: usize,
) -> Result<u64, String> {
    reject_symlink_path_components(root)?;
    let root_metadata = match symlink_metadata_if_present(root) {
        Ok(Some(metadata)) => metadata,
        Ok(None) => return Ok(0),
        Err(error) => {
            return Err(format!("cannot inspect target root {}: {error}", root.display()))
        }
    };
    let root_type = root_metadata.file_type();
    if root_type.is_symlink() {
        return Err(format!("target root {} is a symbolic link", root.display()));
    }
    if !root_type.is_dir() {
        return Err(format!("target root {} is not a directory", root.display()));
    }
    if max_entries == 0 {
        return Err("target accounting entry limit is zero".to_string());
    }

    let mut accounted_bytes = retained_metadata_bytes(&root_metadata)?;
    if accounted_bytes > max_bytes {
        return Err(format!(
            "accounted at least {accounted_bytes} bytes, exceeds {max_bytes} byte limit"
        ));
    }
    let mut accounted_entries = 1usize;
    let mut pending = vec![(root.to_path_buf(), 0usize)];

    while let Some((directory, depth)) = pending.pop() {
        let directory_metadata = match symlink_metadata_if_present(&directory) {
            Ok(Some(metadata)) => metadata,
            // Cargo atomically renames and removes intermediate directories. A path confirmed
            // absent at this instant contributes zero to this soft scan; the mandatory post-scan
            // (and a filesystem quota, when strict) closes the admitted race window.
            Ok(None) => continue,
            Err(error) => {
                return Err(format!(
                    "cannot re-inspect target directory {}: {error}",
                    directory.display()
                ))
            }
        };
        if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
            return Err(format!(
                "target directory {} changed type during accounting",
                directory.display()
            ));
        }
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "cannot read target directory {}: {error}",
                    directory.display()
                ))
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => {
                    return Err(format!(
                        "cannot enumerate target directory {}: {error}",
                        directory.display()
                    ))
                }
            };
            accounted_entries = accounted_entries
                .checked_add(1)
                .ok_or_else(|| "target accounting entry count overflowed".to_string())?;
            if accounted_entries > max_entries {
                return Err(format!("target accounting exceeded {max_entries} entry limit"));
            }

            let path = entry.path();
            let metadata = match symlink_metadata_if_present(&path) {
                Ok(Some(metadata)) => metadata,
                Ok(None) => continue,
                Err(error) => {
                    return Err(format!("cannot inspect target entry {}: {error}", path.display()))
                }
            };
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                return Err(format!("target entry {} is a symbolic link", path.display()));
            }
            if !file_type.is_file() && !file_type.is_dir() {
                return Err(format!(
                    "target entry {} is neither a regular file nor a directory",
                    path.display()
                ));
            }

            accounted_bytes = accounted_bytes
                .checked_add(retained_metadata_bytes(&metadata)?)
                .ok_or_else(|| "target cache byte count overflowed".to_string())?;
            if accounted_bytes > max_bytes {
                return Err(format!(
                    "accounted at least {accounted_bytes} bytes, exceeds {max_bytes} byte limit"
                ));
            }

            if file_type.is_dir() {
                let child_depth = depth
                    .checked_add(1)
                    .ok_or_else(|| "target accounting depth overflowed".to_string())?;
                if child_depth > max_depth {
                    return Err(format!(
                        "target entry {} exceeds {max_depth} level depth limit",
                        path.display()
                    ));
                }
                pending.push((path, child_depth));
            }
        }
    }

    Ok(accounted_bytes)
}

/// Cargo uses rename-then-remove heavily. Normalize only a confirmed `NotFound` into absence so a
/// legitimate ephemeral entry does not make the watchdog flaky; every other inspection error is
/// preserved for the caller's fail-closed diagnostic.
fn symlink_metadata_if_present(path: &Path) -> std::io::Result<Option<std::fs::Metadata>> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn open_retained_cache_lock(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path)
}

/// Confirm that the opened lock still names the regular file inspected through the cache path. On
/// Unix the device/inode comparison closes the pre-open rename race; `O_NOFOLLOW` closes the final
/// symlink race. The file is retained permanently (zero-length) and is never unlinked on unlock.
fn verify_open_cache_lock(path: &Path, file: &File) -> Result<(), String> {
    let path_metadata = std::fs::symlink_metadata(path).map_err(|error| {
        format!("cannot re-inspect Cargo cache lock {}: {error}", path.display())
    })?;
    let open_metadata = file.metadata().map_err(|error| {
        format!("cannot inspect opened Cargo cache lock {}: {error}", path.display())
    })?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.is_file()
        || !open_metadata.is_file()
    {
        return Err(format!("Cargo cache lock {} is not a regular file", path.display()));
    }
    #[cfg(unix)]
    if path_metadata.dev() != open_metadata.dev() || path_metadata.ino() != open_metadata.ino() {
        return Err(format!(
            "Cargo cache lock {} changed identity while it was opened",
            path.display()
        ));
    }
    Ok(())
}

/// Use the larger of logical length and filesystem-reported allocation on Unix. That is conservative
/// for both sparse files (logical wins) and many tiny files/directories (allocated blocks win).
fn retained_metadata_bytes(metadata: &std::fs::Metadata) -> Result<u64, String> {
    #[cfg(unix)]
    {
        let allocated = metadata
            .blocks()
            .checked_mul(512)
            .ok_or_else(|| "target cache allocated byte count overflowed".to_string())?;
        Ok(metadata.len().max(allocated))
    }
    #[cfg(not(unix))]
    {
        Ok(metadata.len())
    }
}

/// Reject a symlink in any existing component before opening the target root. `symlink_metadata` on
/// the final path alone would otherwise follow a symlinked ancestor before it had a chance to inspect
/// that final entry. Missing suffixes are valid (Cargo will create them), but parent traversal is not.
fn reject_symlink_path_components(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(component, std::path::Component::ParentDir) {
            return Err(format!(
                "target path {} contains an unnormalized parent component",
                path.display()
            ));
        }
        current.push(component.as_os_str());
        match std::fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(format!(
                    "target path component {} is a symbolic link",
                    current.display()
                ))
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => {
                return Err(format!(
                    "cannot inspect target path component {}: {error}",
                    current.display()
                ))
            }
        }
    }
    Ok(())
}

/// Put the command leader in a private process group before `spawn`. Cargo, rustc, build scripts,
/// and linkers inherit it, allowing timeout/error cleanup to address the complete normal tree.
#[cfg(unix)]
fn configure_compile_process_group(command: &mut Command) {
    let _ = command.process_group(0);
}

/// There is no portable standard-library process-group API off Unix. The direct-child fallback in
/// `terminate_compile_tree` is paired with the documented requirement that Custom wrappers provide
/// platform-native tree containment.
#[cfg(not(unix))]
fn configure_compile_process_group(_command: &mut Command) {}

/// After the Cargo leader has exited and `try_wait` has preserved its real status, kill any
/// background build-script/compiler descendants still occupying the invocation's private group.
/// `ESRCH` is the expected no-residual-work case. Every other failure is a teardown I/O fault: the
/// caller must not inspect or return an artifact while it cannot establish that producers stopped.
#[cfg(unix)]
fn terminate_residual_compile_group(child_id: u32) -> Result<(), String> {
    let process_group = libc::pid_t::try_from(child_id)
        .map_err(|_| format!("child pid {child_id} does not fit pid_t"))?;
    // SAFETY: `configure_compile_process_group` made the child PID the private process-group ID
    // before spawn. A negative PID addresses the group, and the checked positive child ID cannot
    // refer to this host process's separate group.
    let rc = unsafe { libc::kill(-process_group, libc::SIGKILL) };
    if rc == 0 {
        Ok(())
    } else {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(format!("kill process group {process_group}: {error}"))
        }
    }
}

/// Kill every member of the private Unix process group and reap its leader. `SIGKILL` is deliberate:
/// this path runs only after a hard timeout/resource fault or an indeterminate `try_wait` error, and
/// a graceful signal would let compilers continue allocating the very resource whose bound fired.
#[cfg(unix)]
fn terminate_compile_tree(child: &mut Child) -> Result<(), String> {
    let mut failures = Vec::new();
    let mut group_signal_delivered = false;
    let mut group_was_missing = false;
    let process_group = match libc::pid_t::try_from(child.id()) {
        Ok(pid) => Some(pid),
        Err(_) => {
            failures.push(format!("child pid {} does not fit pid_t", child.id()));
            None
        }
    };

    if let Some(process_group) = process_group {
        // SAFETY: `configure_compile_process_group` made the child PID the process-group ID before
        // spawn. Passing its negative to `kill` addresses that group; it can never address this host
        // process's separate group. The PID is positive and representable as `pid_t` above.
        let rc = unsafe { libc::kill(-process_group, libc::SIGKILL) };
        if rc == 0 {
            group_signal_delivered = true;
        } else {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ESRCH) {
                group_was_missing = true;
            } else {
                failures.push(format!("kill process group {process_group}: {error}"));
            }
        }
    }

    // Signal the leader directly too. This closes the only case in which a contract-violating
    // wrapper moved itself out of the group while leaving descendants behind in the original group,
    // and prevents `wait` from blocking merely because the expected group had already disappeared.
    let leader_can_be_reaped = match child.kill() {
        Ok(()) => {
            if group_was_missing {
                failures.push(format!(
                    "expected cargo process group was absent while leader {} was still running",
                    child.id()
                ));
            }
            true
        }
        Err(error) if process_is_gone_error(&error) => true,
        Err(error) => {
            failures.push(format!("kill cargo leader {}: {error}", child.id()));
            group_signal_delivered
        }
    };

    if leader_can_be_reaped {
        if let Err(error) = child.wait() {
            failures.push(format!("reap cargo leader {}: {error}", child.id()));
        }
    } else {
        failures.push(format!(
            "cargo leader {} was not reaped because termination could not be confirmed",
            child.id()
        ));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Portable fallback: terminate and reap the direct child. This does not pretend to contain
/// descendants; non-Unix production configurations must make `Sandbox::Custom` own a platform job
/// or equivalent tree and tear it down when the wrapper process is killed.
#[cfg(not(unix))]
fn terminate_compile_tree(child: &mut Child) -> Result<(), String> {
    let mut failures = Vec::new();
    let leader_can_be_reaped = match child.kill() {
        Ok(()) => true,
        Err(error) if process_is_gone_error(&error) => true,
        Err(error) => {
            failures.push(format!("kill cargo wrapper {}: {error}", child.id()));
            false
        }
    };
    if leader_can_be_reaped {
        if let Err(error) = child.wait() {
            failures.push(format!("reap cargo wrapper {}: {error}", child.id()));
        }
    } else {
        failures.push(format!(
            "cargo wrapper {} was not reaped because termination could not be confirmed",
            child.id()
        ));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn process_is_gone_error(error: &std::io::Error) -> bool {
    if error.kind() == std::io::ErrorKind::InvalidInput {
        return true;
    }
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ESRCH) {
        return true;
    }
    false
}

/// Reap this build's UNIQUE outputs from the SHARED target dir so they don't accumulate forever.
/// Each ephemeral build uses a unique cargo crate name and is never reused (see the
/// fingerprint-collision note in `run_build`), so removing its outputs is safe — and the canonical
/// SDK/aether dep caches (different names) are left untouched, preserving cross-build dep reuse.
///
/// Cleanup is fail-closed and lstat-based. It first proves every traversed parent is a real
/// directory, then removes only regular files or validated directory trees. Symbolic links and
/// special files are left untouched and diagnosed; cleanup never turns an authored Cargo pathname
/// into an authority to traverse somewhere else. (T15)
fn reap_build_artifacts(target_dir: &Path, cargo_crate_name: &str) -> Result<(), String> {
    reject_symlink_path_components(target_dir)?;
    if !cleanup_directory_exists(target_dir, "target cache")? {
        return Ok(());
    }

    let release = target_dir.join("release");
    if !cleanup_directory_exists(&release, "Cargo release directory")? {
        return Ok(());
    }

    let lib_stem = format!("lib{}", cargo_crate_name.replace('-', "_"));
    let mut failures = Vec::new();
    // release/lib<stem>.{so,dylib,dll} + the .d depfile.
    collect_cleanup_result(
        &mut failures,
        remove_regular_artifact(&release.join(lib_filename(cargo_crate_name))),
    );
    collect_cleanup_result(
        &mut failures,
        remove_regular_artifact(&release.join(format!("{lib_stem}.d"))),
    );
    // release/deps/lib<stem>-<hash>.{so,d}
    collect_cleanup_result(
        &mut failures,
        remove_entries_with_prefix(
            &release.join("deps"),
            &format!("{lib_stem}-"),
            CleanupEntryKind::RegularFile,
        ),
    );
    // release/.fingerprint/<cargo_crate_name>-<hash>/
    collect_cleanup_result(
        &mut failures,
        remove_entries_with_prefix(
            &release.join(".fingerprint"),
            &format!("{cargo_crate_name}-"),
            CleanupEntryKind::DirectoryTree,
        ),
    );

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[derive(Clone, Copy)]
enum CleanupEntryKind {
    RegularFile,
    DirectoryTree,
}

fn collect_cleanup_result(failures: &mut Vec<String>, result: Result<(), String>) {
    if let Err(error) = result {
        failures.push(error);
    }
}

/// Confirm that a cleanup parent is either absent or an actual directory. `read_dir` follows a
/// symlink passed as its argument, so every parent is lstat-checked immediately before traversal.
fn cleanup_directory_exists(dir: &Path, label: &str) -> Result<bool, String> {
    let Some(metadata) = symlink_metadata_if_present(dir)
        .map_err(|error| format!("cannot inspect {label} {}: {error}", dir.display()))?
    else {
        return Ok(false);
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!("refusing cleanup: {label} {} is a symbolic link", dir.display()));
    }
    if !file_type.is_dir() {
        return Err(format!("refusing cleanup: {label} {} is not a directory", dir.display()));
    }
    Ok(true)
}

fn remove_regular_artifact(path: &Path) -> Result<(), String> {
    let Some(metadata) = symlink_metadata_if_present(path)
        .map_err(|error| format!("cannot inspect cleanup candidate {}: {error}", path.display()))?
    else {
        return Ok(());
    };
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(format!("refusing cleanup: candidate {} is a symbolic link", path.display()));
    }
    if !file_type.is_file() {
        return Err(format!(
            "refusing cleanup: candidate {} is not a regular file",
            path.display()
        ));
    }
    std::fs::remove_file(path)
        .map_err(|error| format!("remove regular artifact {}: {error}", path.display()))
}

/// Remove files or directory trees directly under `dir` whose UTF-8 Cargo name starts with the
/// exact build-identity prefix. Enumeration errors and non-UTF-8 names fail conservatively instead
/// of being flattened away.
fn remove_entries_with_prefix(
    dir: &Path,
    prefix: &str,
    kind: CleanupEntryKind,
) -> Result<(), String> {
    if !cleanup_directory_exists(dir, "Cargo artifact directory")? {
        return Ok(());
    }
    let rd = std::fs::read_dir(dir).map_err(|error| {
        format!("cannot enumerate cleanup directory {}: {error}", dir.display())
    })?;
    let mut failures = Vec::new();
    for entry in rd {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                failures.push(format!("cannot enumerate an entry in {}: {error}", dir.display()));
                continue;
            }
        };
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            failures.push(format!(
                "refusing cleanup in {}: non-UTF-8 entry name cannot be matched safely",
                dir.display()
            ));
            continue;
        };
        if name.starts_with(prefix) {
            let result = match kind {
                CleanupEntryKind::RegularFile => remove_regular_artifact(&entry.path()),
                CleanupEntryKind::DirectoryTree => remove_validated_artifact_tree(&entry.path()),
            };
            collect_cleanup_result(&mut failures, result);
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Validate a one-use fingerprint tree before recursive removal. Cargo has stopped, its private
/// process group has been swept, and the cross-process cache lock is still held, so legitimate
/// writers cannot race this pass. `remove_dir_all` itself does not follow symlinks; the pre-pass
/// additionally refuses to unlink symlinks or special nodes that were already present.
fn remove_validated_artifact_tree(root: &Path) -> Result<(), String> {
    validate_artifact_cleanup_tree(root)?;
    std::fs::remove_dir_all(root)
        .map_err(|error| format!("remove artifact directory {}: {error}", root.display()))
}

fn validate_artifact_cleanup_tree(root: &Path) -> Result<(), String> {
    let mut entries_seen = 0usize;
    let mut pending = vec![(root.to_path_buf(), 0usize)];

    while let Some((path, depth)) = pending.pop() {
        entries_seen = entries_seen
            .checked_add(1)
            .ok_or_else(|| "artifact cleanup entry count overflowed".to_string())?;
        if entries_seen > MAX_TARGET_ACCOUNTING_ENTRIES {
            return Err(format!(
                "refusing cleanup: artifact tree {} exceeds {} entry limit",
                root.display(),
                MAX_TARGET_ACCOUNTING_ENTRIES
            ));
        }
        let Some(metadata) = symlink_metadata_if_present(&path).map_err(|error| {
            format!("cannot inspect artifact cleanup entry {}: {error}", path.display())
        })?
        else {
            // A confirmed absent entry cannot be traversed or removed.
            continue;
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            return Err(format!(
                "refusing cleanup: artifact tree entry {} is a symbolic link",
                path.display()
            ));
        }
        if file_type.is_file() {
            continue;
        }
        if !file_type.is_dir() {
            return Err(format!(
                "refusing cleanup: artifact tree entry {} is not a regular file or directory",
                path.display()
            ));
        }
        if depth >= MAX_TARGET_ACCOUNTING_DEPTH {
            return Err(format!(
                "refusing cleanup: artifact tree entry {} exceeds {} level depth limit",
                path.display(),
                MAX_TARGET_ACCOUNTING_DEPTH
            ));
        }
        let children = std::fs::read_dir(&path).map_err(|error| {
            format!("cannot enumerate artifact tree {}: {error}", path.display())
        })?;
        for child in children {
            let child = child.map_err(|error| {
                format!("cannot enumerate an entry in artifact tree {}: {error}", path.display())
            })?;
            pending.push((child.path(), depth + 1));
        }
    }
    Ok(())
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

/// One output-drain worker and its cancellation handle. Dropping the receiver requests cancellation
/// too, covering partial setup when the second reader cannot be spawned.
struct PipeReader {
    receiver: Option<mpsc::Receiver<String>>,
    cancel: Arc<AtomicBool>,
}

impl PipeReader {
    fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(unix)]
trait CapturedPipe: std::io::Read + std::os::fd::AsRawFd + Send {}

#[cfg(unix)]
impl<T> CapturedPipe for T where T: std::io::Read + std::os::fd::AsRawFd + Send {}

#[cfg(not(unix))]
trait CapturedPipe: std::io::Read + Send {}

#[cfg(not(unix))]
impl<T> CapturedPipe for T where T: std::io::Read + Send {}

fn spawn_pipe_reader<R>(pipe: Option<R>, stream: &'static str) -> std::io::Result<PipeReader>
where
    R: CapturedPipe + 'static,
{
    let (sender, receiver) = mpsc::sync_channel(1);
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let _reader =
        std::thread::Builder::new().name(format!("build-cargo-{stream}")).spawn(move || {
            let capture = drain_pipe_capped(pipe, CAPTURE_CAP, &worker_cancel);
            let _ = sender.send(capture);
        })?;
    Ok(PipeReader { receiver: Some(receiver), cancel })
}

fn pipe_reader_spawn_error(
    error: std::io::Error,
    terminate_error: Option<String>,
) -> std::io::Error {
    let kind = error.kind();
    let mut message = format!("spawn cargo output reader: {error}");
    if let Some(terminate_error) = terminate_error {
        message
            .push_str(&format!("; terminating cargo process tree also failed: {terminate_error}"));
    }
    std::io::Error::new(kind, message)
}

fn receive_pipe_captures(stdout: PipeReader, stderr: PipeReader) -> (String, String) {
    let deadline = Instant::now() + PIPE_DRAIN_GRACE;
    (
        receive_pipe_capture(stdout, "stdout", deadline),
        receive_pipe_capture(stderr, "stderr", deadline),
    )
}

fn receive_pipe_capture(mut reader: PipeReader, stream: &str, deadline: Instant) -> String {
    let receiver = reader.receiver.take().expect("pipe reader receiver is present");
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(capture) => capture,
        Err(mpsc::RecvTimeoutError::Timeout) => format!(
            "[build-cargo: {stream} pipe remained open after process-tree teardown; capture abandoned]"
        ),
        Err(mpsc::RecvTimeoutError::Disconnected) => {
            format!("[build-cargo: {stream} output reader stopped without a capture]")
        }
    }
}

/// Read a child pipe to EOF, RETAINING at most `cap` bytes but always consuming the rest so the
/// child can never block on a full pipe buffer (the deadlock the concurrent reader threads exist to
/// prevent). On a read error, append a marker so a truncated capture is *discoverable* rather than
/// silently short. Best-effort; never panics (R9).
#[cfg(not(unix))]
fn drain_pipe_capped(
    pipe: Option<impl CapturedPipe + 'static>,
    cap: usize,
    cancel: &AtomicBool,
) -> String {
    let Some(mut p) = pipe else { return String::new() };
    let mut kept: Vec<u8> = Vec::new();
    let mut scratch = [0u8; 8192];
    loop {
        if cancel.load(Ordering::Relaxed) {
            append_capture_marker(&mut kept, cap, b"\n[build-cargo: output capture cancelled]");
            break;
        }
        match std::io::Read::read(&mut p, &mut scratch) {
            Ok(0) => break,
            Ok(n) => {
                append_capture_bytes(&mut kept, cap, &scratch[..n]);
                // bytes past `cap` are read (draining the pipe) but discarded
            }
            Err(_) => {
                append_capture_marker(
                    &mut kept,
                    cap,
                    b"\n[build-cargo: output read error; capture truncated]",
                );
                break;
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

/// Unix child pipes are polled rather than held in an uninterruptible blocking `read`. The worker
/// therefore observes cancellation and drops its descriptor even if a broken Custom wrapper moved
/// out of the private process group while retaining the write end.
#[cfg(unix)]
fn drain_pipe_capped(
    pipe: Option<impl CapturedPipe + 'static>,
    cap: usize,
    cancel: &AtomicBool,
) -> String {
    const POLL_MILLIS: libc::c_int = 100;
    let Some(mut pipe) = pipe else { return String::new() };
    let mut kept = Vec::new();
    let mut scratch = [0u8; 8192];
    let mut descriptor = libc::pollfd {
        fd: pipe.as_raw_fd(),
        events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
        revents: 0,
    };
    loop {
        if cancel.load(Ordering::Relaxed) {
            append_capture_marker(&mut kept, cap, b"\n[build-cargo: output capture cancelled]");
            break;
        }
        descriptor.revents = 0;
        // SAFETY: `descriptor` points to one initialized `pollfd` for the duration of this call.
        // The worker exclusively owns `pipe`, so its descriptor remains valid until this function
        // returns and drops it.
        let ready = unsafe { libc::poll(&mut descriptor, 1, POLL_MILLIS) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            append_capture_marker(
                &mut kept,
                cap,
                format!("\n[build-cargo: output poll error: {error}; capture truncated]")
                    .as_bytes(),
            );
            break;
        }
        if ready == 0 {
            continue;
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            append_capture_marker(
                &mut kept,
                cap,
                b"\n[build-cargo: output descriptor became invalid; capture truncated]",
            );
            break;
        }
        match std::io::Read::read(&mut pipe, &mut scratch) {
            Ok(0) => break,
            Ok(n) => append_capture_bytes(&mut kept, cap, &scratch[..n]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                append_capture_marker(
                    &mut kept,
                    cap,
                    format!("\n[build-cargo: output read error: {error}; capture truncated]")
                        .as_bytes(),
                );
                break;
            }
        }
    }
    String::from_utf8_lossy(&kept).into_owned()
}

fn append_capture_bytes(kept: &mut Vec<u8>, cap: usize, bytes: &[u8]) {
    if kept.len() < cap {
        let take = bytes.len().min(cap - kept.len());
        kept.extend_from_slice(&bytes[..take]);
    }
}

fn append_capture_marker(kept: &mut Vec<u8>, cap: usize, marker: &[u8]) {
    append_capture_bytes(kept, cap, marker);
}

fn now_nanos() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn fresh_build_id_nonce() -> Result<[u8; BUILD_ID_NONCE_BYTES], String> {
    let mut nonce = [0u8; BUILD_ID_NONCE_BYTES];
    SystemRandom::new().fill(&mut nonce).map_err(|_| {
        "OS RNG unavailable while allocating a unique Cargo build identity".to_string()
    })?;
    Ok(nonce)
}

fn cargo_crate_identity(nonce: &[u8; BUILD_ID_NONCE_BYTES]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut nonce_hex = String::with_capacity(BUILD_ID_NONCE_BYTES * 2);
    for byte in nonce {
        nonce_hex.push(char::from(HEX[usize::from(byte >> 4)]));
        nonce_hex.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    format!("alpha-authored-b{nonce_hex}")
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

    struct TempTree(PathBuf);

    impl TempTree {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "build-cargo-{label}-{}-{}",
                std::process::id(),
                now_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create isolated test tree");
            TempTree(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn signing_key() -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::generate().expect("ed25519 keygen").0
    }

    #[test]
    fn lib_filename_follows_cargo_dash_to_underscore() {
        assert_eq!(lib_filename("reverse-daemon"), "libreverse_daemon.so");
        assert_eq!(lib_filename("plain"), "libplain.so");
    }

    #[test]
    fn cargo_identity_survives_pid_and_counter_reuse_without_invoking_cargo() {
        let first_nonce = fresh_build_id_nonce().unwrap();
        let mut second_nonce = fresh_build_id_nonce().unwrap();
        if second_nonce == first_nonce {
            // Keep the structural assertion deterministic even under a mocked RNG while still
            // exercising production entropy above.
            second_nonce[0] ^= 1;
        }
        // The legacy identity inputs (same request name, PID 42, counter 0) are deliberately absent:
        // a fresh process lifetime cannot reproduce the Cargo identity without reproducing 128 bits
        // from the OS RNG too.
        let first = cargo_crate_identity(&first_nonce);
        let after_process_restart = cargo_crate_identity(&second_nonce);

        assert_ne!(first, after_process_restart);
        assert_eq!(first.len(), "alpha-authored-b".len() + BUILD_ID_NONCE_BYTES * 2);
        assert!(first.len() < 64, "the generated Cargo package name stays compact");
        assert!(first.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
        }));
        assert_eq!(first.strip_prefix("alpha-authored-b").unwrap().len(), BUILD_ID_NONCE_BYTES * 2);
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
        assert!(toml.contains("[profile.release]\nincremental = false\ncodegen-units = 1"));
    }

    #[test]
    fn build_config_defaults_nested_cargo_to_one_job_and_one_codegen_unit() {
        let config =
            BuildConfig::with_workspace_root(PathBuf::from("/tmp/gawd"), signing_key(), "tester");
        assert_eq!(config.cargo_jobs, 1);
        assert_eq!(config.cargo_codegen_units, 1);
        assert_eq!(config.max_target_bytes, DEFAULT_MAX_TARGET_BYTES);
    }

    #[test]
    fn target_accounting_is_finite_and_fails_closed_over_budget() {
        let tree = TempTree::new("target-accounting");
        let target = tree.path().join("target");
        std::fs::create_dir_all(target.join("release/deps")).unwrap();
        std::fs::write(target.join("release/libone.so"), b"1234").unwrap();
        std::fs::write(target.join("release/deps/libtwo.rlib"), b"567890").unwrap();

        let accounted = account_target_tree(&target, u64::MAX, 32, 8).unwrap();
        assert!(accounted >= 10, "regular file bytes must be included");
        assert_eq!(account_target_tree(&target, accounted, 32, 8).unwrap(), accounted);
        let error = account_target_tree(&target, accounted - 1, 32, 8)
            .expect_err("one byte below the measured tree must fail closed");
        assert!(error.contains("exceeds"), "{error}");

        let missing = tree.path().join("not-created");
        assert_eq!(account_target_tree(&missing, 1, 1, 1).unwrap(), 0);
    }

    #[test]
    fn vanished_accounting_entry_is_absent_without_masking_other_errors() {
        let tree = TempTree::new("target-vanished-entry");
        let transient = tree.path().join("cargo-rename-temp");
        std::fs::write(&transient, b"temporary").unwrap();
        std::fs::remove_file(&transient).unwrap();

        assert!(
            symlink_metadata_if_present(&transient).unwrap().is_none(),
            "a path removed between read_dir and metadata is an honest zero-byte observation"
        );
        assert!(symlink_metadata_if_present(tree.path()).unwrap().is_some());
    }

    #[test]
    fn shared_cache_lock_is_retained_and_contention_is_bounded_capacity() {
        let tree = TempTree::new("shared-cache-lock");
        let target = tree.path().join("target");

        let mut first_config = BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent-workspace"),
            signing_key(),
            "first",
        );
        first_config.target_dir = target.clone();
        first_config.cargo_timeout = Duration::from_millis(100);
        let first = BuildCargo::new(first_config);
        let held = first.acquire_cross_process_cache_lock(Instant::now()).unwrap();

        let lock_path = target.join(CACHE_LOCK_FILE);
        assert!(std::fs::symlink_metadata(&lock_path).unwrap().is_file());

        let mut second_config = BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent-workspace"),
            signing_key(),
            "second",
        );
        second_config.target_dir = target.clone();
        second_config.cargo_timeout = Duration::from_millis(20);
        let second = BuildCargo::new(second_config);
        let failure = second
            .acquire_cross_process_cache_lock(Instant::now())
            .expect_err("a separately-opened handle must not bypass the held cache lock");
        assert_eq!(failure.kind, BuildErrorKind::Capacity);
        assert!(failure.message.contains("locked by another authoring process"));

        drop(held);
        let reacquired = second.acquire_cross_process_cache_lock(Instant::now()).unwrap();
        drop(reacquired);
        assert!(lock_path.is_file(), "unlock retains the regular coordination file");
    }

    #[test]
    fn target_accounting_refuses_entry_and_depth_exhaustion() {
        let entries_tree = TempTree::new("target-entry-cap");
        std::fs::write(entries_tree.path().join("one"), b"").unwrap();
        std::fs::write(entries_tree.path().join("two"), b"").unwrap();
        let entry_error = account_target_tree(entries_tree.path(), u64::MAX, 2, 8)
            .expect_err("the root plus two files exceeds a two-entry traversal budget");
        assert!(entry_error.contains("entry limit"), "{entry_error}");

        let depth_tree = TempTree::new("target-depth-cap");
        std::fs::create_dir_all(depth_tree.path().join("one/two")).unwrap();
        let depth_error = account_target_tree(depth_tree.path(), u64::MAX, 8, 1)
            .expect_err("a second nested directory exceeds a one-level depth budget");
        assert!(depth_error.contains("depth limit"), "{depth_error}");
    }

    #[test]
    fn unique_artifact_cleanup_removes_only_the_selected_regular_tree() {
        let tree = TempTree::new("artifact-cleanup-safe");
        let target = tree.path().join("target");
        let release = target.join("release");
        let deps = release.join("deps");
        let fingerprints = release.join(".fingerprint");
        let cargo_name = "bounded-bP7c11";
        let lib_stem = "libbounded_bP7c11";
        std::fs::create_dir_all(&deps).unwrap();
        std::fs::create_dir_all(fingerprints.join(format!("{cargo_name}-abc/nested"))).unwrap();
        let root_lib = release.join(lib_filename(cargo_name));
        let root_depfile = release.join(format!("{lib_stem}.d"));
        let hashed_lib = deps.join(format!("{lib_stem}-abc.so"));
        let unrelated = deps.join("libbounded_bP7c110-keep.so");
        std::fs::write(&root_lib, b"root").unwrap();
        std::fs::write(&root_depfile, b"depfile").unwrap();
        std::fs::write(&hashed_lib, b"hashed").unwrap();
        std::fs::write(&unrelated, b"other build").unwrap();
        std::fs::write(fingerprints.join(format!("{cargo_name}-abc/nested/state")), b"fingerprint")
            .unwrap();

        reap_build_artifacts(&target, cargo_name).unwrap();

        assert!(!root_lib.exists());
        assert!(!root_depfile.exists());
        assert!(!hashed_lib.exists());
        assert!(!fingerprints.join(format!("{cargo_name}-abc")).exists());
        assert!(unrelated.is_file(), "a longer build identity must not prefix-collide");
    }

    #[cfg(unix)]
    #[test]
    fn unique_artifact_cleanup_refuses_symlinked_parents_and_candidates() {
        use std::os::unix::fs::symlink;

        let parent_tree = TempTree::new("artifact-cleanup-linked-parent");
        let target = parent_tree.path().join("target");
        let outside_release = parent_tree.path().join("outside-release");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::create_dir_all(&outside_release).unwrap();
        let cargo_name = "bounded-bP8c12";
        let outside_artifact = outside_release.join(lib_filename(cargo_name));
        std::fs::write(&outside_artifact, b"must remain").unwrap();
        symlink(&outside_release, target.join("release")).unwrap();

        let parent_error = reap_build_artifacts(&target, cargo_name)
            .expect_err("cleanup must not traverse a symlinked release parent");
        assert!(parent_error.contains("symbolic link"), "{parent_error}");
        assert!(outside_artifact.is_file());

        let candidate_tree = TempTree::new("artifact-cleanup-linked-candidate");
        let candidate_target = candidate_tree.path().join("target");
        let release = candidate_target.join("release");
        let deps = release.join("deps");
        let fingerprint = release.join(".fingerprint").join(format!("{cargo_name}-abc"));
        let outside_file = candidate_tree.path().join("outside-file");
        std::fs::create_dir_all(&deps).unwrap();
        std::fs::create_dir_all(&fingerprint).unwrap();
        std::fs::write(&outside_file, b"must remain").unwrap();
        symlink(&outside_file, release.join(lib_filename(cargo_name))).unwrap();
        symlink(&outside_file, fingerprint.join("escape")).unwrap();

        let candidate_error = reap_build_artifacts(&candidate_target, cargo_name)
            .expect_err("cleanup must refuse symlink candidates at every depth");
        assert!(candidate_error.contains("symbolic link"), "{candidate_error}");
        assert!(outside_file.is_file());
        assert!(release.join(lib_filename(cargo_name)).is_symlink());
        assert!(fingerprint.is_dir(), "an unsafe fingerprint tree must be left intact");
    }

    #[cfg(unix)]
    #[test]
    fn unique_artifact_cleanup_refuses_special_files() {
        use std::os::unix::net::UnixListener;

        // Unix-domain socket paths are commonly capped at 108 bytes. Keep this fixture's label and
        // matching Cargo stem deliberately short so the safety assertion is portable across CI
        // checkout depths instead of failing while the socket itself is created.
        let tree = TempTree::new("s");
        let target = tree.path().join("target");
        let deps = target.join("release/deps");
        std::fs::create_dir_all(&deps).unwrap();
        let cargo_name = "b";
        let special = deps.join("libb-special.sock");
        let _listener = UnixListener::bind(&special).unwrap();

        let error = reap_build_artifacts(&target, cargo_name)
            .expect_err("cleanup must not unlink a matching special file");
        assert!(error.contains("not a regular file"), "{error}");
        assert!(std::fs::symlink_metadata(&special).is_ok());
    }

    #[cfg(unix)]
    #[test]
    fn target_accounting_rejects_symlinks_without_following_them() {
        use std::os::unix::fs::symlink;

        let tree = TempTree::new("target-symlink");
        let target = tree.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let outside = tree.path().join("outside");
        std::fs::write(&outside, b"outside-target-bytes").unwrap();
        symlink(&outside, target.join("escape")).unwrap();

        let error = account_target_tree(&target, u64::MAX, 8, 2)
            .expect_err("a target-cache symlink must fail closed, not be traversed");
        assert!(error.contains("symbolic link"), "{error}");

        let real_parent = tree.path().join("real-parent");
        std::fs::create_dir_all(real_parent.join("nested-target")).unwrap();
        let linked_parent = tree.path().join("linked-parent");
        symlink(&real_parent, &linked_parent).unwrap();
        let ancestor_error =
            account_target_tree(&linked_parent.join("nested-target"), u64::MAX, 8, 2)
                .expect_err("a symlinked target ancestor must fail closed, not be traversed");
        assert!(ancestor_error.contains("symbolic link"), "{ancestor_error}");
    }

    #[test]
    fn over_budget_preflight_is_capacity_and_never_spawns_cargo() {
        let tree = TempTree::new("target-preflight");
        let target = tree.path().join("target");
        std::fs::create_dir(&target).unwrap();
        let root_bytes = std::fs::symlink_metadata(&target).unwrap().len();
        std::fs::write(target.join("excess"), b"xx").unwrap();

        let mut config = BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent-workspace"),
            signing_key(),
            "tester",
        );
        config.work_root = tree.path().join("work");
        config.target_dir = target.clone();
        config.max_target_bytes = root_bytes + 1;
        // If preflight ordering regresses, this impossible executable turns the result into Io.
        config.sandbox =
            Sandbox::Custom(vec![tree.path().join("must-not-run").display().to_string()]);

        let reply = BuildCargo::new(config).build(BuildRequest {
            crate_name: "bounded".into(),
            crate_version: "0.1.0".into(),
            source: "pub fn bounded() {}".into(),
            manifest_stub: ManifestStub {
                name: "bounded".into(),
                version: "0.1.0".into(),
                ..Default::default()
            },
            deps: vec![],
        });
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Capacity);
                assert!(message.contains("cargo clean --target-dir"), "{message}");
                assert!(message.contains(&target.display().to_string()), "{message}");
            }
            BuildReply::Built { .. } => panic!("an over-budget target must not compile"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_and_reaps_the_nested_wrapper_process_group() {
        let tree = TempTree::new("process-group-timeout");
        let work_dir = tree.path().join("work");
        std::fs::create_dir(&work_dir).unwrap();
        let marker = tree.path().join("escaped-descendant");

        let mut config = BuildConfig::with_workspace_root(
            PathBuf::from("/nonexistent-workspace"),
            signing_key(),
            "tester",
        );
        config.target_dir = tree.path().join("target");
        config.cargo_timeout = Duration::from_millis(100);
        config.sandbox = Sandbox::Custom(vec![
            "/bin/sh".into(),
            "-c".into(),
            "(sleep 1; printf leaked > \"$1\") & sleep 2".into(),
            "build-cargo-timeout-test".into(),
            marker.display().to_string(),
        ]);

        let started = Instant::now();
        let run =
            BuildCargo::new(config).invoke_cargo(&work_dir, Duration::from_millis(100)).unwrap();
        assert!(run.timed_out);
        assert!(run.wait_error.is_none(), "group teardown failed: {:?}", run.wait_error);
        assert!(started.elapsed() < PIPE_DRAIN_GRACE + Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(1_200));
        assert!(!marker.exists(), "a nested process survived the timeout and wrote its marker");
    }

    #[cfg(unix)]
    #[test]
    fn leader_exit_status_is_preserved_while_residual_group_is_killed() {
        let tree = TempTree::new("process-group-normal-exit");
        let marker = tree.path().join("residual-descendant");
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("(sleep 1; printf leaked > \"$1\") & exit 7")
            .arg("build-cargo-normal-exit-test")
            .arg(&marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_compile_process_group(&mut command);
        let mut child = command.spawn().unwrap();
        let child_id = child.id();
        let status = child.wait().unwrap();
        assert_eq!(status.code(), Some(7), "leader status is the compile result");

        terminate_residual_compile_group(child_id).unwrap();

        assert_eq!(status.code(), Some(7), "group cleanup must not rewrite status");
        std::thread::sleep(Duration::from_millis(1_200));
        assert!(!marker.exists(), "a descendant survived normal leader exit");
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
            Entrypoint::new("handle", "(Envelope) -> Outcome"),
            Entrypoint::new("handle", "(Envelope) -> Outcome"),
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
                contract: None,
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
                origin: None,
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
                origin: None,
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
