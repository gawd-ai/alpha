//! The native (daemon) tier: `libloading` + the `extern "C"` POD-only seam (`aether::ffi`).
//!
//! The host loads the `.so`, calls its one constructor to get a POD vtable, and wraps it in
//! [`NativeInstance`]. Envelopes cross to the creature as bytes (`handle`); the creature's dispatches
//! cross back as bytes through a host callback handed over at `bind`. No Rust trait object crosses.

use std::os::raw::c_void;
use std::panic::{catch_unwind, AssertUnwindSafe};

use aether::ffi::{
    BindCtxFfi, CreatureVTableV1, NativeCtor, ABI_TAG, NATIVE_CTOR_SYMBOL, RC_BACKPRESSURE,
    RC_DENIED, RC_DESERIALIZE, RC_INVALID_ARG, RC_NO_PROVIDER, RC_NO_SUCH_MODULE, RC_OK,
    RC_OTHER_ROUTE, RC_PANIC,
};
use aether::{Bus, Creature, CreatureCtx, Deadline, Dispatch, Envelope, Outcome, RouteError};
use libloading::{Library, Symbol};
use sigil::{Backend, Manifest};

use crate::{Artifact, Engine, EngineError, LoadedModule};

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
        // **Native-from-bytes.** When the substrate ships a creature over the wire (an
        // `Artifact::Bytes`), we spill it to a unique temp file and `dlopen` that — `dlopen`'s
        // entrypoint requires a path. The temp file's lifetime is bound to the resources so it
        // is removed when (and only after) the library unmaps on the safe unload path. The
        // leak path (`Box::leak` on resources) consequently leaks both library and tempfile
        // together — a consistent bounded leak.
        let (path, tempfile) = match artifact {
            Artifact::Path(p) => (p.clone(), None),
            Artifact::Bytes(bytes) => {
                let spilled = spill_to_tempfile(bytes, &manifest.name)?;
                let path = spilled.path.clone();
                (path, Some(spilled))
            }
        };

        // SAFETY: loading foreign code is inherently unsafe — native is *trusted-by-admission*
        // (the honest containment limit; foreign/mobile code arrives only in sandboxed tiers, never
        // here).
        let lib = unsafe { Library::new(&path) }
            .map_err(|e| EngineError::Load(format!("dlopen {}: {e}", path.display())))?;

        let vtable: *mut CreatureVTableV1 = {
            let ctor: Symbol<NativeCtor> = unsafe { lib.get(NATIVE_CTOR_SYMBOL) }
                .map_err(|e| EngineError::Load(format!("symbol gawd_creature_v1: {e}")))?;
            // The constructor is foreign `extern "C"` code: trusted-by-admission, but a panic in it
            // must NOT unwind across the C ABI (that is UB). Isolate it like every other FFI seam in
            // this file — a panicking ctor becomes a clean `Load` error, not a process abort. (T7)
            match catch_unwind(AssertUnwindSafe(|| ctor())) {
                Ok(v) => v,
                Err(_) => return Err(EngineError::Load("native constructor panicked".into())),
            }
            // `ctor` (a borrow of `lib`) is dropped here, so `lib` can move into resources below.
        };
        if vtable.is_null() {
            return Err(EngineError::Load("constructor returned a null vtable".into()));
        }

        let instance = NativeInstance { vtable, host_ctx: None };
        // Resources hold the library AND the optional tempfile guard. Field declaration order
        // is the drop order — `lib` first (dlclose runs), `_tempfile` second (file unlinked).
        // On Linux unlinking after dlclose is the conventional / safest order; even unlinking
        // earlier would be sound because the inode persists while the file is mapped, but the
        // explicit ordering is the version we want documented in code.
        let resources = NativeResources { lib, _tempfile: tempfile };
        Ok(LoadedModule::new(Box::new(instance), Box::new(resources)))
    }
}

/// Native tier's `LoadedModule::resources` payload. Holds the dlopen'd library plus, when the
/// artifact arrived as in-memory bytes (the ship path), a tempfile guard that unlinks the
/// spilled file once the library unloads. **Neither field is read after construction** — the
/// whole purpose of holding them is the destructor (`dlclose` on `lib`, unlink on `_tempfile`),
/// so the `dead_code` lint would fire without explicit suppression.
#[allow(dead_code)]
struct NativeResources {
    lib: Library,
    _tempfile: Option<SpilledArtifact>,
}

/// A tempfile that auto-removes on drop. Avoids pulling in the `tempfile` crate: the only thing we
/// need is "create a unique path, write bytes, remove on drop." The path is content-addressed for
/// debuggability — if a load fails, the operator sees the same hash that's in the manifest.
struct SpilledArtifact {
    path: std::path::PathBuf,
}

impl Drop for SpilledArtifact {
    fn drop(&mut self) {
        // Best-effort cleanup. A failed unlink (no permission, race) leaves the file on disk —
        // honestly visible to the operator, not silently swallowed via panic.
        let _ = std::fs::remove_file(&self.path);
    }
}

fn spill_to_tempfile(bytes: &[u8], name_hint: &str) -> Result<SpilledArtifact, EngineError> {
    use sha2::Digest;
    use std::io::Write;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_SPILL_ID: AtomicU64 = AtomicU64::new(0);

    // Filename: gawd-<pid>-<spill-id>-<hash8>-<name>.so. The monotonically increasing spill id makes
    // two same-process loads of the same content/name distinct, while `create_new` below prevents us
    // from ever truncating a stale or concurrently-created path.
    let mut h = sha2::Sha256::new();
    h.update(bytes);
    let digest = format!("{:x}", h.finalize());
    let safe_name = safe_temp_name_hint(name_hint);

    for _ in 0..1024 {
        let spill_id = NEXT_SPILL_ID.fetch_add(1, Ordering::Relaxed);
        let filename =
            format!("gawd-{}-{}-{}-{}.so", std::process::id(), spill_id, &digest[..8], safe_name);
        let path = std::env::temp_dir().join(filename);

        let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(EngineError::Load(format!("create tempfile {}: {e}", path.display())))
            }
        };
        if let Err(e) = file.write_all(bytes) {
            let _ = std::fs::remove_file(&path);
            return Err(EngineError::Load(format!("write tempfile {}: {e}", path.display())));
        }
        // Close the file handle (via drop) before we hand the path to dlopen — keeping the writer
        // open through dlopen is fine on Linux but unnecessary, and we want the file's bytes flushed.
        drop(file);
        return Ok(SpilledArtifact { path });
    }

    Err(EngineError::Load(
        "could not allocate a unique native tempfile path after 1024 attempts".into(),
    ))
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
        // sides share one allocator — see the workspace `Cargo.toml` invariant ("no custom
        // `#[global_allocator]`"). A future ABI extension will move this free to the
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

    #[test]
    fn native_byte_spills_use_unique_create_new_paths() {
        let bytes = b"not actually a shared object";

        let a = spill_to_tempfile(bytes, "same/name").expect("first spill");
        let b = spill_to_tempfile(bytes, "same/name").expect("second spill");

        assert_ne!(a.path, b.path, "same content/name loads must not reuse a tempfile path");
        assert_eq!(std::fs::read(&a.path).unwrap(), bytes);
        assert_eq!(std::fs::read(&b.path).unwrap(), bytes);

        let a_path = a.path.clone();
        let b_path = b.path.clone();
        drop(a);
        drop(b);
        assert!(!a_path.exists(), "first spill unlinks on drop");
        assert!(!b_path.exists(), "second spill unlinks on drop");
    }

    #[test]
    fn native_temp_name_hint_is_bounded_and_ascii_safe() {
        let safe = safe_temp_name_hint(&format!("bad/name:{}", "x".repeat(10_000)));

        assert!(safe.len() <= 64);
        assert!(safe.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-')));
        assert!(safe.starts_with("bad_name_"));
        assert_eq!(safe_temp_name_hint(""), "creature");
    }
}
