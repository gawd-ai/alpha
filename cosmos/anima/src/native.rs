//! The native (daemon) tier: `libloading` + the `extern "C"` POD-only seam (`aether::ffi`).
//!
//! The host loads the `.so`, calls its one constructor to get a POD vtable, and wraps it in
//! [`NativeInstance`]. Envelopes cross to the creature as bytes (`handle`); the creature's dispatches
//! cross back as bytes through a host callback handed over at `bind`. No Rust trait object crosses.

use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "android", target_os = "linux"))]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use aether::ffi::{
    BindCtxFfi, CreatureVTableV1, NativeCtor, ABI_TAG, NATIVE_CTOR_SYMBOL, RC_BACKPRESSURE,
    RC_DENIED, RC_DESERIALIZE, RC_INVALID_ARG, RC_NO_PROVIDER, RC_NO_SUCH_MODULE, RC_OK,
    RC_OTHER_ROUTE, RC_PANIC,
};
use aether::{Bus, Creature, CreatureCtx, Deadline, Dispatch, Envelope, Outcome, RouteError};
use libloading::{Library, Symbol};
use sigil::{Backend, Manifest};

use crate::{Artifact, Engine, EngineError, LoadedModule};

/// Serialized `Dispatch` bytes accepted from a native creature's FFI send callback.
///
/// `Dispatch::payload` still uses serde_json's ordinary byte-array representation at the FFI seam, so
/// a max-sized artifact payload can expand to roughly four bytes of JSON per byte plus commas and
/// routing fields. Keep the ceiling large enough for that worst-case legitimate local dispatch while
/// still refusing unbounded guest-provided lengths before we build a slice or deserialize.
const MAX_NATIVE_DISPATCH_BYTES: usize = (crate::MAX_ARTIFACT_BYTES as usize * 5) + (1024 * 1024);

fn native_dispatch_len_is_valid(len: usize) -> bool {
    len <= MAX_NATIVE_DISPATCH_BYTES
}

pub struct NativeEngine;

impl Engine for NativeEngine {
    fn backend(&self) -> Backend {
        Backend::Daemon
    }

    fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        if manifest.abi.backend != Backend::Daemon {
            return Err(EngineError::WrongBackend {
                engine: Backend::Daemon,
                manifest: manifest.abi.backend,
            });
        }
        if manifest.abi.abi_tag != ABI_TAG {
            return Err(EngineError::AbiMismatch {
                expected: ABI_TAG.to_string(),
                got: manifest.abi.abi_tag.clone(),
            });
        }
        // The guest re-parses the manifest at bind through `Manifest::parse`, whose pre-decode cap
        // is `sigil::MAX_MANIFEST_BYTES`. JSON escaping can expand a validate-passing manifest past
        // that wire cap (control chars serialize 6x), and a failed guest-side parse would silently
        // bind the creature with a placeholder self-view — fail the load loudly here instead.
        let manifest_wire_len = serde_json::to_vec(manifest).map(|b| b.len()).unwrap_or(usize::MAX);
        if manifest_wire_len > sigil::MAX_MANIFEST_BYTES {
            return Err(EngineError::Load(format!(
                "manifest serializes to {manifest_wire_len} bytes, exceeds the {} byte guest \
                 re-parse limit",
                sigil::MAX_MANIFEST_BYTES
            )));
        }
        // `dlopen` reopens a pathname, so admission must never hash one path and let the engine open
        // a mutable source path later. Kernel loads arrive as `StagedNative`: a retained sealed
        // memfd on Linux/Android, or a random private/read-only best-effort file elsewhere, whose
        // digest was computed while those exact bytes were written. Direct Engine callers get the
        // same mechanism here.
        // Source paths stream with O(1) memory and no size cap; shipped bytes keep their existing
        // finite materialization cap.
        let stage = match artifact {
            Artifact::StagedNative(stage) => stage.clone(),
            Artifact::Path(path) => Arc::new(NativeArtifactStage::from_path(path, &manifest.name)?),
            Artifact::Bytes(bytes) => {
                if crate::artifact_len_exceeds_limit(bytes.len(), crate::MAX_ARTIFACT_BYTES) {
                    return Err(EngineError::Load(format!(
                        "shipped native artifact is {} bytes, exceeds {} byte limit",
                        bytes.len(),
                        crate::MAX_ARTIFACT_BYTES
                    )));
                }
                Arc::new(NativeArtifactStage::from_bytes(bytes, &manifest.name)?)
            }
        };
        let path = stage.path().to_path_buf();

        // SAFETY: loading foreign code is inherently unsafe — native is *trusted-by-admission*
        // (the honest containment limit; foreign/mobile code arrives only in sandboxed tiers, never
        // here).
        let lib = unsafe { Library::new(&path) }
            .map_err(|e| EngineError::Load(format!("dlopen {}: {e}", path.display())))?;

        let vtable: *mut CreatureVTableV1 = {
            let ctor: Symbol<NativeCtor> = unsafe { lib.get(NATIVE_CTOR_SYMBOL) }
                .map_err(|e| EngineError::Load(format!("symbol gawd_creature_v1: {e}")))?;
            // This is a non-unwinding C ABI: a panic must be caught *inside* the guest before it
            // reaches this call. `forge::declare_creature!` does so and returns null on failure;
            // independently authored native creatures must uphold the same ABI rule.
            ctor()
            // `ctor` (a borrow of `lib`) is dropped here, so `lib` can move into resources below.
        };
        if vtable.is_null() {
            return Err(EngineError::Load("constructor returned a null vtable".into()));
        }

        let instance = NativeInstance { vtable, host_ctx: None };
        // Resources hold the library AND its exact staged artifact. Field declaration order is the
        // drop order — `lib` first (`dlclose`), `_stage` second (close memfd or unlink fallback).
        // The kernel leak path leaks this whole resources value, deliberately retaining both the
        // mapping and the pathname for a runaway native thread rather than risking UAF.
        let resources = NativeResources { lib, _stage: stage };
        Ok(LoadedModule::new(Box::new(instance), Box::new(resources)).with_unmanaged_thread_guard())
    }
}

/// Native tier's `LoadedModule::resources` payload. Holds the dlopen'd library plus the exact
/// staged artifact guard that closes/unlinks its backing capability once the library unloads.
/// **Neither field is read after construction** — their purpose is drop order (`dlclose`, then
/// cleanup), so the `dead_code` lint would fire without explicit suppression.
#[allow(dead_code)]
struct NativeResources {
    lib: Library,
    _stage: Arc<NativeArtifactStage>,
}

/// One native artifact copied into a retained load capability. Linux/Android use a sealed memfd;
/// other targets use an OS-random private temporary directory and read-only file without claiming
/// same-UID immutability.
///
/// Construction fields are private. Copying hashes every successfully written chunk; Linux then
/// seals against write/grow/shrink and re-hashes the sealed bytes before admission trusts them.
/// `Arc` clones extend one cleanup lifetime through `dlclose` (or the deliberate leak path).
pub struct NativeArtifactStage {
    backing: NativeStageBacking,
    path: PathBuf,
    sha256_hex: String,
}

enum NativeStageBacking {
    #[cfg(any(target_os = "android", target_os = "linux"))]
    SealedMemfd(memfd::Memfd),
    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    PrivateTemp { directory: PathBuf },
}

impl NativeArtifactStage {
    pub(super) fn from_path(source_path: &Path, name_hint: &str) -> Result<Self, EngineError> {
        let mut source = std::fs::File::open(source_path).map_err(|e| {
            EngineError::Load(format!("open native source {}: {e}", source_path.display()))
        })?;
        let metadata = source.metadata().map_err(|e| {
            EngineError::Load(format!("inspect native source {}: {e}", source_path.display()))
        })?;
        if !metadata.is_file() {
            return Err(EngineError::Load(format!(
                "native source {} is not a regular file",
                source_path.display()
            )));
        }
        Self::copy_from(&mut source, name_hint, Some(source_path))
    }

    pub(super) fn from_bytes(bytes: &[u8], name_hint: &str) -> Result<Self, EngineError> {
        Self::copy_from(&mut std::io::Cursor::new(bytes), name_hint, None)
    }

    fn copy_from(
        source: &mut dyn std::io::Read,
        name_hint: &str,
        source_path: Option<&Path>,
    ) -> Result<Self, EngineError> {
        use sha2::Digest;
        use std::io::Write;

        let (mut stage, mut target) = Self::create(name_hint)?;
        let mut hasher = sha2::Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer).map_err(|error| {
                EngineError::Load(match source_path {
                    Some(path) => format!("read native source {}: {error}", path.display()),
                    None => format!("read shipped native artifact: {error}"),
                })
            })?;
            if read == 0 {
                break;
            }
            target.write_all(&buffer[..read]).map_err(|error| {
                EngineError::Load(format!(
                    "write native staging artifact {}: {error}",
                    stage.path.display()
                ))
            })?;
            hasher.update(&buffer[..read]);
        }
        target.flush().map_err(|error| {
            EngineError::Load(format!(
                "flush native staging artifact {}: {error}",
                stage.path.display()
            ))
        })?;
        let streamed_sha256 = format!("{:x}", hasher.finalize());
        stage.finish(target, streamed_sha256)?;
        Ok(stage)
    }

    fn create(name_hint: &str) -> Result<(Self, std::fs::File), EngineError> {
        let safe_name = safe_temp_name_hint(name_hint);

        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            use std::os::fd::AsRawFd;

            let memfd = memfd::MemfdOptions::default()
                .allow_sealing(true)
                .create(format!("gawd-native-{safe_name}"))
                .map_err(|error| {
                    EngineError::Load(format!("create native staging memfd: {error}"))
                })?;
            let target = memfd.as_file().try_clone().map_err(|error| {
                EngineError::Load(format!("duplicate native staging memfd writer: {error}"))
            })?;
            let path = unique_proc_fd_path(memfd.as_raw_fd());
            std::fs::metadata(&path).map_err(|error| {
                EngineError::Load(format!(
                    "native staging requires an accessible /proc/self/fd capability {}: {error}",
                    path.display()
                ))
            })?;
            Ok((
                Self {
                    backing: NativeStageBacking::SealedMemfd(memfd),
                    path,
                    sha256_hex: String::new(),
                },
                target,
            ))
        }

        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            for _ in 0..128 {
                let random_suffix = random_stage_suffix()?;
                let directory =
                    std::env::temp_dir().join(format!("gawd-native-{random_suffix}-{safe_name}"));
                match create_private_directory(&directory) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => {
                        return Err(EngineError::Load(format!(
                            "create native staging directory {}: {error}",
                            directory.display()
                        )))
                    }
                }

                let path = directory.join("artifact.so");
                let stage = Self {
                    backing: NativeStageBacking::PrivateTemp { directory },
                    path: path.clone(),
                    sha256_hex: String::new(),
                };
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                return match options.open(&path) {
                    Ok(file) => Ok((stage, file)),
                    Err(error) => Err(EngineError::Load(format!(
                        "create native staging artifact {}: {error}",
                        path.display()
                    ))),
                };
            }
            Err(EngineError::Load(
                "could not allocate a random private native staging directory after 128 attempts"
                    .into(),
            ))
        }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    fn finish(
        &mut self,
        target: std::fs::File,
        streamed_sha256: String,
    ) -> Result<(), EngineError> {
        drop(target);
        let NativeStageBacking::SealedMemfd(memfd) = &self.backing;
        let required = [
            memfd::FileSeal::SealShrink,
            memfd::FileSeal::SealGrow,
            memfd::FileSeal::SealWrite,
            memfd::FileSeal::SealSeal,
        ];
        memfd.add_seals(&required).map_err(|error| {
            EngineError::Load(format!("seal native staging memfd {}: {error}", self.path.display()))
        })?;

        // A same-UID process can enumerate `/proc/<pid>/fd` while the copy is in progress. Hash only
        // after all seals are installed and require it to equal the streaming digest, detecting any
        // write that raced construction. The bytes cannot change after this comparison.
        let sealed_sha256 = hash_open_path(&self.path, "sealed native staging memfd")?;
        if sealed_sha256 != streamed_sha256 {
            return Err(EngineError::Load(format!(
                "native staging bytes changed before sealing {}",
                self.path.display()
            )));
        }
        self.sha256_hex = sealed_sha256;
        Ok(())
    }

    #[cfg(not(any(target_os = "android", target_os = "linux")))]
    fn finish(
        &mut self,
        target: std::fs::File,
        streamed_sha256: String,
    ) -> Result<(), EngineError> {
        make_staged_file_read_only(&target, &self.path)?;
        // Ephemeral staging is not crash-durable, so flush errors matter but fsync would not add an
        // identity property. This fallback is random/private/read-only best effort, not a claim that
        // the same UID cannot restore write permission.
        drop(target);
        self.sha256_hex = streamed_sha256;
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn construction_sha256_hex(&self) -> &str {
        &self.sha256_hex
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub(crate) fn is_kernel_sealed(&self) -> Result<bool, EngineError> {
        let NativeStageBacking::SealedMemfd(memfd) = &self.backing;
        let seals = memfd.seals().map_err(|error| {
            EngineError::Load(format!("inspect native staging memfd seals: {error}"))
        })?;
        Ok([
            memfd::FileSeal::SealShrink,
            memfd::FileSeal::SealGrow,
            memfd::FileSeal::SealWrite,
            memfd::FileSeal::SealSeal,
        ]
        .iter()
        .all(|seal| seals.contains(seal)))
    }
}

impl Drop for NativeArtifactStage {
    fn drop(&mut self) {
        // Ordinary unload reaches here after dlclose; the deliberate native leak path retains the
        // guard. Linux cleanup is the memfd closing after this body. Other targets unlink/rmdir.
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            #[cfg(not(unix))]
            if let Ok(metadata) = std::fs::metadata(&self.path) {
                let mut permissions = metadata.permissions();
                permissions.set_readonly(false);
                let _ = std::fs::set_permissions(&self.path, permissions);
            }
            let _ = std::fs::remove_file(&self.path);
            let NativeStageBacking::PrivateTemp { directory } = &self.backing;
            let _ = std::fs::remove_dir(directory);
        }
    }
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn create_private_directory(path: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)) {
            let _ = std::fs::remove_dir(path);
            return Err(error);
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn make_staged_file_read_only(file: &std::fs::File, path: &Path) -> Result<(), EngineError> {
    let mut permissions = file
        .metadata()
        .map_err(|error| {
            EngineError::Load(format!(
                "inspect native staging artifact {}: {error}",
                path.display()
            ))
        })?
        .permissions();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        permissions.set_mode(0o400);
    }
    #[cfg(not(unix))]
    permissions.set_readonly(true);
    file.set_permissions(permissions).map_err(|error| {
        EngineError::Load(format!("protect native staging artifact {}: {error}", path.display()))
    })
}

#[cfg(not(any(target_os = "android", target_os = "linux")))]
fn random_stage_suffix() -> Result<String, EngineError> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|error| EngineError::Load(format!("obtain native staging randomness: {error}")))?;
    Ok(random.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn hash_open_path(path: &Path, description: &str) -> Result<String, EngineError> {
    use sha2::Digest;
    use std::io::Read;

    let mut file = std::fs::File::open(path).map_err(|error| {
        EngineError::Load(format!("open {description} {}: {error}", path.display()))
    })?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).map_err(|error| {
            EngineError::Load(format!("read {description} {}: {error}", path.display()))
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Produce a process-unique spelling of the retained descriptor capability without introducing a
/// mutable symlink. Each `./` or `../fd/` component resolves back to `/proc/self/fd`, but the unique
/// complete string prevents the dynamic loader's pathname cache from confusing a newly allocated
/// memfd with an older DSO after the kernel reuses its numeric descriptor. All 64 counter bits are
/// encoded in a bounded (< 512 byte) path, so a spelling repeats only after exhausting the full
/// process-local `u64` namespace; unlike temp-name probing, there is no finite collision loop or
/// filesystem object an attacker can pre-create.
#[cfg(any(target_os = "android", target_os = "linux"))]
fn unique_proc_fd_path(raw_fd: std::os::fd::RawFd) -> PathBuf {
    static NEXT_PATH_ID: AtomicU64 = AtomicU64::new(0);

    let id = NEXT_PATH_ID.fetch_add(1, Ordering::Relaxed);
    let mut path = String::from("/proc/self/fd/");
    for bit in 0..u64::BITS {
        if id & (1_u64 << bit) == 0 {
            path.push_str("./");
        } else {
            path.push_str("../fd/");
        }
    }
    path.push_str(&raw_fd.to_string());
    PathBuf::from(path)
}

fn safe_temp_name_hint(name_hint: &str) -> String {
    const MAX_SAFE_NAME_BYTES: usize = 64;
    let mut safe_name = String::new();
    for c in name_hint.chars() {
        if safe_name.len() >= MAX_SAFE_NAME_BYTES {
            break;
        }
        safe_name.push(if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' });
    }
    if safe_name.is_empty() {
        "creature".into()
    } else {
        safe_name
    }
}

/// Host-side wrapper over a creature's POD vtable. Implements [`Creature`] by marshalling
/// across the C boundary.
struct NativeInstance {
    vtable: *mut CreatureVTableV1,
    /// The send context handed to the creature at bind; kept alive until `destroy` so the creature's
    /// callback never dangles.
    host_ctx: Option<Box<HostSendCtx>>,
}

// SAFETY: the vtable points into a `Library` kept alive in `LoadedModule.resources` and dropped only
// AFTER this instance (drop ordering). A creature is driven by a single drain thread, so the raw
// pointer is never shared concurrently.
unsafe impl Send for NativeInstance {}

/// The host end of the creature's send callback: it owns the creature's abstract bus (the host-side
/// real `BusHandle` wrapped as an `Arc<dyn Bus>` — same Arc the kernel handed via `CreatureCtx`).
struct HostSendCtx {
    bus: std::sync::Arc<dyn Bus>,
}

/// Creature→host bus bridge: deserialize one [`Dispatch`] and route it. Distinct `RC_*` codes per
/// failure shape so a creature can act on backpressure differently from `NoSuchModule` (R9). Wraps
/// the body in `catch_unwind` so a panic in the host's bus stack never unwinds across `extern "C"`
/// — unwinding across the C ABI is undefined behavior.
extern "C" fn host_bus_send(host_ctx: *mut c_void, ptr: *const u8, len: usize) -> i32 {
    if host_ctx.is_null() || ptr.is_null() {
        return RC_INVALID_ARG;
    }
    if !native_dispatch_len_is_valid(len) {
        return RC_DESERIALIZE;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `host_ctx` is the pointer we handed the creature at bind; it points at a live
        // `HostSendCtx` (kept in `NativeInstance.host_ctx`). `ptr/len` describe the creature buffer.
        let hc = unsafe { &*(host_ctx as *const HostSendCtx) };
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
        let dispatch: Dispatch = match serde_json::from_slice(bytes) {
            Ok(d) => d,
            Err(_) => return RC_DESERIALIZE,
        };
        match hc.bus.emit(dispatch) {
            Ok(()) => RC_OK,
            Err(e) => route_error_rc(&e),
        }
    }));
    match result {
        Ok(rc) => rc,
        Err(_) => RC_PANIC, // a panic inside the host bus is contained; never unwinds across FFI
    }
}

/// Map a `BusError` (which wraps the router's `RouteError` for the in-process bus the host holds)
/// to the FFI rc shared with native creatures.
fn route_error_rc(e: &aether::BusError) -> i32 {
    use aether::BusError::*;
    match e {
        Route(RouteError::NoSuchModule(_)) => RC_NO_SUCH_MODULE,
        Route(RouteError::NoProvider(_)) => RC_NO_PROVIDER,
        Route(RouteError::Backpressure(_)) => RC_BACKPRESSURE,
        Route(RouteError::Denied { .. }) => RC_DENIED,
        _ => RC_OTHER_ROUTE,
    }
}

impl Creature for NativeInstance {
    fn bind(&mut self, ctx: CreatureCtx) {
        // Route through the established "cannot-fail for plain data" serialize seam (it `debug_assert`s
        // the impossible failure loud in dev and degrades to empty in release) rather than a bare
        // `unwrap_or_default()` that swallows it silently. (T17)
        let manifest_bytes = aether::wire::to_bytes(&ctx.manifest);
        // HostSendCtx holds the bus once for the lifetime of the native instance — single owner; no
        // need to share it with worker threads (creature-spawned threads exist on the *guest* side
        // of the FFI; the host-side bus stays here).
        let host_ctx = Box::new(HostSendCtx { bus: ctx.bus });
        // A stable heap address (moving the Box later does not move its contents).
        let host_ctx_ptr = (&*host_ctx as *const HostSendCtx as *mut HostSendCtx) as *mut c_void;
        let ffi_ctx = BindCtxFfi {
            creature_id: ctx.me.0,
            manifest_ptr: manifest_bytes.as_ptr(),
            manifest_len: manifest_bytes.len(),
            host_ctx: host_ctx_ptr,
            send: host_bus_send,
        };
        // SAFETY: vtable is non-null (checked at load); `ffi_ctx`/`manifest_bytes` outlive the call.
        unsafe {
            ((*self.vtable).bind)((*self.vtable).data, &ffi_ctx as *const BindCtxFfi);
        }
        self.host_ctx = Some(host_ctx); // keep the send-ctx alive until destroy
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        let bytes = env.to_bytes();
        // SAFETY: the library is mapped for this instance's lifetime; bytes outlive the call.
        let rc =
            unsafe { ((*self.vtable).handle)((*self.vtable).data, bytes.as_ptr(), bytes.len()) };
        if rc == RC_PANIC {
            // The creature panicked inside the SDK glue and the FFI seam caught it. Re-panic on
            // the host side so the kernel's `run_drain` catch_unwind sees it and pulls the creature
            // off the bus — the same isolation path the in-process case already takes.
            panic!("native creature panicked in handle (contained at FFI seam, unloading)");
        }
        // A native creature emits via the send callback during `handle`, so nothing to return here.
        Outcome::none()
    }

    fn shutdown(&mut self, deadline: Deadline) {
        // SAFETY: still bound; library mapped.
        unsafe {
            ((*self.vtable).shutdown)((*self.vtable).data, deadline.0.as_millis() as u64);
        }
    }
}

impl Drop for NativeInstance {
    fn drop(&mut self) {
        // SAFETY: runs while the library is still mapped (resources drop AFTER this instance). After
        // `destroy` the creature makes no further callbacks, so dropping `host_ctx` next is safe.
        // The vtable's `destroy` is panic-isolated inside the SDK glue (`forge::glue::destroy`),
        // so a panic in the user's `Drop` never unwinds across this `extern "C"` boundary.
        //
        // CROSS-ALLOCATOR FREE: `Box::from_raw` here frees memory the creature allocated inside its
        // `.so` (via `Box::into_raw` in the `declare_creature!` macro). This is only sound while both
        // sides share one allocator — see the workspace `Cargo.toml` invariant (no process-wide
        // custom allocator). A future ABI extension will move this free to the
        // creature side (a `gawd_creature_v1_destroy(vtable)` symbol or a vtable drop slot).
        unsafe {
            ((*self.vtable).destroy)((*self.vtable).data);
            drop(Box::from_raw(self.vtable));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct SourceFile(PathBuf);

    impl SourceFile {
        fn new(bytes: &[u8]) -> Self {
            static NEXT_SOURCE: AtomicU64 = AtomicU64::new(0);
            for _ in 0..1024 {
                let id = NEXT_SOURCE.fetch_add(1, Ordering::Relaxed);
                let path = std::env::temp_dir()
                    .join(format!("anima-native-source-{}-{id}", std::process::id()));
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true);
                match options.open(&path) {
                    Ok(mut file) => {
                        use std::io::Write;
                        file.write_all(bytes).unwrap();
                        return Self(path);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(error) => panic!("create source fixture: {error}"),
                }
            }
            panic!("could not allocate source fixture")
        }
    }

    impl Drop for SourceFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn native_byte_stages_are_private_unique_hashed_and_cleaned() {
        let bytes = b"not actually a shared object";

        let a = NativeArtifactStage::from_bytes(bytes, "same/name").expect("first stage");
        let b = NativeArtifactStage::from_bytes(bytes, "same/name").expect("second stage");

        assert_ne!(a.path, b.path, "same content/name loads must not reuse one load capability");
        assert_eq!(std::fs::read(&a.path).unwrap(), bytes);
        assert_eq!(std::fs::read(&b.path).unwrap(), bytes);
        assert_eq!(a.sha256_hex, format!("{:x}", sha2::Sha256::digest(bytes)));
        assert_eq!(b.sha256_hex, a.sha256_hex);
        #[cfg(any(target_os = "android", target_os = "linux"))]
        {
            assert!(a.is_kernel_sealed().unwrap());
            assert!(b.is_kernel_sealed().unwrap());
            assert!(a.path.starts_with("/proc/self/fd"));
            assert!(b.path.starts_with("/proc/self/fd"));
        }
        #[cfg(all(unix, not(any(target_os = "android", target_os = "linux"))))]
        {
            use std::os::unix::fs::PermissionsExt;
            let NativeStageBacking::PrivateTemp { directory: a_dir } = &a.backing;
            let NativeStageBacking::PrivateTemp { directory: b_dir } = &b.backing;
            assert_ne!(a_dir, b_dir);
            assert_eq!(std::fs::metadata(a_dir).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(std::fs::metadata(&a.path).unwrap().permissions().mode() & 0o777, 0o400);
        }

        let a_path = a.path.clone();
        let b_path = b.path.clone();
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        let (a_dir, b_dir) = {
            let NativeStageBacking::PrivateTemp { directory: a_dir } = &a.backing;
            let NativeStageBacking::PrivateTemp { directory: b_dir } = &b.backing;
            (a_dir.clone(), b_dir.clone())
        };
        drop(a);
        drop(b);
        assert!(!a_path.exists(), "first stage capability disappears on drop");
        assert!(!b_path.exists(), "second stage capability disappears on drop");
        #[cfg(not(any(target_os = "android", target_os = "linux")))]
        {
            assert!(!a_dir.exists(), "first private stage directory is removed on drop");
            assert!(!b_dir.exists(), "second private stage directory is removed on drop");
        }
    }

    #[test]
    fn native_path_stage_is_independent_of_a_later_source_path_swap() {
        let source = SourceFile::new(b"source-v1");

        let staged = NativeArtifactStage::from_path(&source.0, "loaded").unwrap();
        std::fs::write(&source.0, b"replacement-v2").unwrap();

        assert_eq!(std::fs::read(staged.path()).unwrap(), b"source-v1");
        assert_eq!(
            staged.construction_sha256_hex(),
            format!("{:x}", sha2::Sha256::digest(b"source-v1"))
        );
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    #[test]
    fn sealed_native_stage_rejects_same_uid_overwrite() {
        let stage = NativeArtifactStage::from_bytes(b"sealed-v1", "sealed").unwrap();

        let error = std::fs::write(stage.path(), b"replacement-v2")
            .expect_err("WRITE/GROW/SHRINK seals must reject mutation through /proc/self/fd");
        assert_ne!(error.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(std::fs::read(stage.path()).unwrap(), b"sealed-v1");
        assert!(stage.is_kernel_sealed().unwrap());
    }

    #[test]
    fn native_temp_name_hint_is_bounded_and_ascii_safe() {
        let safe = safe_temp_name_hint(&format!("bad/name:{}", "x".repeat(10_000)));

        assert!(safe.len() <= 64);
        assert!(safe.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')));
        assert!(safe.starts_with("bad_name_"));
        assert_eq!(safe_temp_name_hint(""), "creature");
    }

    #[test]
    fn native_dispatch_length_gate_is_large_but_finite() {
        assert!(native_dispatch_len_is_valid(0));
        assert!(native_dispatch_len_is_valid(MAX_NATIVE_DISPATCH_BYTES));
        assert!(!native_dispatch_len_is_valid(MAX_NATIVE_DISPATCH_BYTES + 1));
    }
}
