//! forge — the creature-authoring surface.
//!
//! A creature author writes a Rust type, `impl Creature for MyType`, derives `Default`, and
//! calls [`declare_creature!`] once. The macro emits the **single `extern "C"` POD-only constructor**
//! the host loader looks for (`gawd_creature_v1`), and the glue that bridges across the C ABI to the
//! user's typed `bind` / `handle` / `shutdown` — one loader path, not two parallel ones
//! (**R1**, lever 4: one module concept).
//!
//! This crate depends only on aether + sigil — **never on the kernel**. Creatures don't get
//! to call into the kernel; they emit envelopes through a [`Bus`] (real handle if
//! in-process, [`NativeBus`] shim if loaded as a `.so`).

use std::os::raw::c_void;

use aether::ffi::{
    BusSendFn, RC_BACKPRESSURE, RC_DENIED, RC_NO_PROVIDER, RC_NO_SUCH_MODULE, RC_OK, RC_PANIC,
};
use aether::{Bus, BusError, CreatureId, Dispatch};

// Re-export the FFI types so the macro can reference them via `$crate::ffi::…`.
pub use aether::ffi;

pub use managed::{spawn, try_spawn};

/// Diagnostics must never become a second panic at a native ABI boundary. `eprintln!` panics when
/// stderr fails; this helper treats both write failures and panicking formatters as best-effort and
/// deliberately leaks an adversarial panic payload whose `Drop` itself panics.
fn best_effort_stderr(args: std::fmt::Arguments<'_>) {
    use std::io::Write;

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let stderr = std::io::stderr();
        let mut stderr = stderr.lock();
        let _ = stderr.write_fmt(args);
        let _ = stderr.write_all(b"\n");
    }));
    if let Err(payload) = result {
        std::mem::forget(payload);
    }
}

/// Creature-side bus shim for native daemons (`.so`). Wraps the host-supplied send callback so the
/// creature uses the same [`Bus`] API in-process or across FFI. Cheap to clone (just a fn pointer +
/// raw pointer + id).
#[derive(Clone, Copy)]
pub struct NativeBus {
    send: BusSendFn,
    host_ctx: *mut c_void,
    me: CreatureId,
}

// SAFETY: a creature is single-driver (the host's drain thread calls `handle` serially), and the
// host callback (`host_bus_send`) is reentrant-safe — it only deserializes + routes, holding no
// per-creature state across calls. The raw pointer outlives the bus (kept alive by the host
// `NativeInstance.host_ctx` until `destroy`).
unsafe impl Send for NativeBus {}
unsafe impl Sync for NativeBus {}

impl NativeBus {
    pub fn new(send: BusSendFn, host_ctx: *mut c_void, me: CreatureId) -> Self {
        NativeBus { send, host_ctx, me }
    }
}

impl Bus for NativeBus {
    fn emit(&self, d: Dispatch) -> Result<(), BusError> {
        let bytes = serde_json::to_vec(&d).map_err(|e| BusError::Serialize(e.to_string()))?;
        let rc = (self.send)(self.host_ctx, bytes.as_ptr(), bytes.len());
        match rc {
            RC_OK => Ok(()),
            RC_NO_SUCH_MODULE => Err(BusError::NoSuchModule),
            RC_NO_PROVIDER => Err(BusError::NoProvider),
            RC_BACKPRESSURE => Err(BusError::Backpressure),
            RC_DENIED => Err(BusError::Denied),
            // RC_PANIC reaching here would mean the host's bus stack panicked under us; surface as
            // a generic FFI failure rather than swallowing.
            RC_PANIC => Err(BusError::Ffi(RC_PANIC)),
            other => Err(BusError::Ffi(other)),
        }
    }
    fn whoami(&self) -> CreatureId {
        self.me
    }
}

/// **The thread discipline for native creatures.** A native daemon that spawns a thread —
/// e.g. a long-running watcher, a periodic sensor — must register it with the SDK so the safe-unload
/// sequence can join it before the host `dlclose`s the library. A thread originating from the `.so`
/// that survives `dlclose` reaches into now-unmapped code and dereferences a dangling vtable: the
/// canonical native-unload UAF.
///
/// **The discipline:** use [`spawn`] (the SDK function), never `std::thread::spawn` directly. The
/// SDK joins all spawn-registered threads in `shutdown` before returning to the host. Authors that
/// need to fail synchronously on OS thread-limit errors can use [`try_spawn`]. Threads spawned via
/// the raw stdlib path are invisible to the SDK and would UAF on unload — except the kernel's
/// belt-and-braces *thread-count guard* notices the leak and refuses to `dlclose` (the library leaks
/// instead — bounded, not UB; see `sanctum::run_drain`).
///
/// **Limits to be honest about:**
/// - Threads spawned by code reached *outside* a managed callback (`bind`/`handle`/`shutdown`) — for
///   example from inside a child thread that itself calls `spawn` — fall back to `std::thread::spawn`
///   and are *not* registered. The kernel guard is what catches that.
/// - Threads that don't return (`spawn(name, || loop {})`) cannot be joined; the discipline is to
///   carry a stop signal (an `Arc<AtomicBool>` or a channel) and check it. The SDK does *not* enforce
///   this — it's a discipline.
///
/// Beasts (WASM) have no native unload UAF class (drop the Store and all linear memory + tables are
/// gone), so this primitive is native-tier territory.
pub mod managed {
    use std::cell::RefCell;
    use std::io;
    use std::sync::{Arc, Mutex};
    use std::thread::{Builder, JoinHandle};

    /// Per-creature thread registry. The SDK glue installs a clone of this into the current
    /// thread-local so the user's `bind`/`handle`/`shutdown` see it via [`super::spawn`], then joins
    /// all registered threads at `shutdown` before returning to the host.
    pub struct Threads {
        handles: Mutex<Vec<JoinHandle<()>>>,
    }

    impl Threads {
        pub fn new() -> Arc<Self> {
            Arc::new(Threads { handles: Mutex::new(Vec::new()) })
        }

        pub fn try_spawn<F: FnOnce() + Send + 'static>(&self, name: &str, f: F) -> io::Result<()> {
            validate_thread_name(name)?;
            let h = Builder::new().name(name.to_string()).spawn(f)?;
            self.handles.lock().unwrap_or_else(|p| p.into_inner()).push(h);
            Ok(())
        }

        pub fn spawn<F: FnOnce() + Send + 'static>(&self, name: &str, f: F) {
            if let Err(e) = self.try_spawn(name, f) {
                crate::best_effort_stderr(format_args!(
                    "forge: failed to spawn managed thread {:?}: {e}",
                    thread_name_for_log(name)
                ));
            }
        }

        /// Drain the registry and join every thread. Called by the SDK glue's `shutdown` BEFORE
        /// returning to the host. A misbehaving closure that never returns will hang here; the
        /// kernel's `unload` deadline is the wider bound that prevents the whole substrate from
        /// hanging.
        pub fn join_all(&self) {
            let handles: Vec<JoinHandle<()>> =
                std::mem::take(&mut *self.handles.lock().unwrap_or_else(|p| p.into_inner()));
            for h in handles {
                let _ = h.join();
            }
        }

        /// How many threads are still registered (not yet joined). Test helper.
        pub fn len(&self) -> usize {
            self.handles.lock().unwrap_or_else(|p| p.into_inner()).len()
        }
        pub fn is_empty(&self) -> bool {
            self.len() == 0
        }
    }

    thread_local! {
        static ACTIVE: RefCell<Option<Arc<Threads>>> = const { RefCell::new(None) };
    }

    /// Install the registry for the current callback. The SDK glue calls this at the start of each
    /// `bind`/`handle`/`shutdown` and `clear()` at the end so the thread-local matches the active
    /// creature only during its calls.
    pub fn set_active(threads: Arc<Threads>) {
        ACTIVE.with(|cell| *cell.borrow_mut() = Some(threads));
    }
    pub fn clear() {
        ACTIVE.with(|cell| cell.borrow_mut().take());
    }
    fn current() -> Option<Arc<Threads>> {
        ACTIVE.with(|cell| cell.borrow().clone())
    }

    fn validate_thread_name(name: &str) -> io::Result<()> {
        if name.bytes().any(|b| b == 0) {
            Err(io::Error::new(io::ErrorKind::InvalidInput, "thread name contains NUL byte"))
        } else {
            Ok(())
        }
    }

    fn thread_name_for_log(name: &str) -> String {
        const MAX_LOG_CHARS: usize = 128;
        let mut out: String = name.chars().take(MAX_LOG_CHARS).collect();
        if name.chars().nth(MAX_LOG_CHARS).is_some() {
            out.push_str("...");
        }
        out
    }

    /// Spawn a thread registered with the active creature so the SDK joins it on `shutdown`.
    /// Outside a managed callback (e.g. from a child thread) falls back to a raw stdlib spawn — the
    /// kernel's thread-count guard catches that as a leaked thread and refuses `dlclose`, bounding
    /// the consequence to a leaked library rather than UAF.
    pub fn spawn<F: FnOnce() + Send + 'static>(name: &str, f: F) {
        if let Err(e) = try_spawn(name, f) {
            crate::best_effort_stderr(format_args!(
                "forge: failed to spawn thread {:?}: {e}",
                thread_name_for_log(name)
            ));
        }
    }

    /// Fallible form of [`spawn`]. Inside a managed callback the thread is registered with the
    /// active creature and joined on `shutdown`; outside one it falls back to a raw stdlib spawn.
    /// Spawn failures are returned to the caller instead of being hidden.
    pub fn try_spawn<F: FnOnce() + Send + 'static>(name: &str, f: F) -> io::Result<()> {
        match current() {
            Some(t) => t.try_spawn(name, f),
            None => {
                validate_thread_name(name)?;
                Builder::new().name(name.to_string()).spawn(f).map(|_| ())
            }
        }
    }
}

/// Internal glue the `declare_creature!` macro expands into. Public-but-hidden so the macro can refer
/// to it; not part of the creature-facing API.
///
/// **Every glue function, including construction, catches panics** (`std::panic::catch_unwind`)
/// before returning across the
/// `extern "C"` boundary. Unwinding across `extern "C"` is undefined behavior — the catch is the
/// fabric-integrity floor (R9) for the FFI seam, mirroring the kernel-side `catch_unwind` in
/// `run_drain`. A panic in `handle` returns [`ffi::RC_PANIC`](aether::ffi::RC_PANIC) so the host can
/// pull the creature off the bus; panics in `bind`/`shutdown`/`destroy` are caught and swallowed
/// (the creature is being unloaded anyway).
#[doc(hidden)]
pub mod glue {
    use std::os::raw::c_void;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    use aether::ffi::{BindCtxFfi, RC_DESERIALIZE, RC_OK, RC_PANIC};
    use aether::{Bus, Creature, CreatureCtx, CreatureId, Deadline, Envelope};
    use sigil::{Backend, Manifest};

    use crate::NativeBus;

    /// Best-effort extraction of a panic payload's message (the common `&str` / `String` cases) so a
    /// caught creature panic in `bind` / `handle` / `shutdown` / `Drop` is *discoverable* rather than
    /// silently swallowed. We still catch (R9) — this only names what happened.
    fn panic_msg(p: &(dyn std::any::Any + Send)) -> &str {
        if let Some(s) = p.downcast_ref::<&str>() {
            s
        } else if let Some(s) = p.downcast_ref::<String>() {
            s.as_str()
        } else {
            "(non-string panic payload)"
        }
    }

    /// Wraps the user's `Creature` and keeps its native bus alive between `bind` and `destroy`.
    /// `poisoned` is flipped if `handle` ever panics so subsequent calls short-circuit and the host
    /// is told to unload — a panicked creature does not get a second `handle` invocation.
    /// `threads` is the managed-spawn registry: every thread the creature spawns via
    /// [`crate::spawn`] is recorded here and joined in `shutdown` before the host can `dlclose`.
    pub struct CreatureBox<T: Creature> {
        pub user: T,
        pub bus: Option<NativeBus>,
        pub poisoned: bool,
        pub threads: std::sync::Arc<crate::managed::Threads>,
    }

    impl<T: Creature> CreatureBox<T> {
        pub fn new(user: T) -> Self {
            CreatureBox {
                user,
                bus: None,
                poisoned: false,
                threads: crate::managed::Threads::new(),
            }
        }
    }

    extern "C" fn bind_entry<T: Creature>(data: *mut c_void, ctx: *const BindCtxFfi) {
        // The outer catch covers infrastructure/error-reporting code as well as user callbacks.
        // SAFETY: this entry is installed only in the vtable paired with `CreatureBox<T>`.
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| unsafe { bind::<T>(data, ctx) })) {
            unsafe { (*(data as *mut CreatureBox<T>)).poisoned = true };
            std::mem::forget(payload);
        }
    }

    extern "C" fn handle_entry<T: Creature>(
        data: *mut c_void,
        env_ptr: *const u8,
        env_len: usize,
    ) -> i32 {
        // SAFETY: this entry is installed only in the vtable paired with `CreatureBox<T>`.
        match catch_unwind(AssertUnwindSafe(|| unsafe { handle::<T>(data, env_ptr, env_len) })) {
            Ok(rc) => rc,
            Err(payload) => {
                unsafe { (*(data as *mut CreatureBox<T>)).poisoned = true };
                std::mem::forget(payload);
                RC_PANIC
            }
        }
    }

    extern "C" fn shutdown_entry<T: Creature>(data: *mut c_void, deadline_ms: u64) {
        // SAFETY: this entry is installed only in the vtable paired with `CreatureBox<T>`.
        if let Err(payload) =
            catch_unwind(AssertUnwindSafe(|| unsafe { shutdown::<T>(data, deadline_ms) }))
        {
            std::mem::forget(payload);
        }
    }

    extern "C" fn destroy_entry<T: Creature>(data: *mut c_void) {
        // SAFETY: this entry is installed only in the vtable paired with `CreatureBox<T>`.
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| unsafe { destroy::<T>(data) })) {
            std::mem::forget(payload);
        }
    }

    /// Construct the complete native vtable without allowing `T::default` or allocation-adjacent
    /// user code to unwind across the exported non-unwinding C ABI. A null result is the ABI's
    /// fail-closed construction error; the native loader already rejects it as `EngineError::Load`.
    pub fn construct<T: Creature + Default>() -> *mut crate::ffi::CreatureVTableV1 {
        match catch_unwind(AssertUnwindSafe(|| {
            let user = T::default();
            let cb = Box::new(CreatureBox::<T>::new(user));
            let data = Box::into_raw(cb) as *mut c_void;
            let vtable = crate::ffi::CreatureVTableV1 {
                data,
                bind: bind_entry::<T>,
                handle: handle_entry::<T>,
                shutdown: shutdown_entry::<T>,
                destroy: destroy_entry::<T>,
            };
            Box::into_raw(Box::new(vtable))
        })) {
            Ok(vtable) => vtable,
            Err(payload) => {
                crate::best_effort_stderr(format_args!(
                    "forge: creature panicked during construction ({})",
                    panic_msg(&*payload)
                ));
                std::mem::forget(payload);
                std::ptr::null_mut()
            }
        }
    }

    /// Drop guard that clears the managed-thread thread-local on any exit — Ok return *or* panic
    /// unwinding through it. Without this, a panic in user code would leave a stale `Arc<Threads>`
    /// in the thread-local; the next creature on this thread would silently inherit it.
    struct ActiveThreadsGuard;
    impl Drop for ActiveThreadsGuard {
        fn drop(&mut self) {
            crate::managed::clear();
        }
    }

    /// # Safety
    /// `data` must point to a `CreatureBox<T>` allocated by the macro's constructor; `ctx` must
    /// point to a valid `BindCtxFfi` whose pointers are live for the duration of this call.
    pub unsafe fn bind<T: Creature>(data: *mut c_void, ctx: *const BindCtxFfi) {
        let cb = &mut *(data as *mut CreatureBox<T>);
        let ffi = &*ctx;
        let me = CreatureId(ffi.creature_id);
        let nb = NativeBus::new(ffi.send, ffi.host_ctx, me);
        cb.bus = Some(nb);
        let manifest_bytes = std::slice::from_raw_parts(ffi.manifest_ptr, ffi.manifest_len);
        // A creature must not panic on a malformed manifest the host handed it (R9). Fall back to a
        // minimal placeholder so binding still proceeds; the creature can also inspect ctx.manifest.
        let manifest = Manifest::parse(manifest_bytes).unwrap_or_else(|_| {
            Manifest::new("(unparseable manifest)", "0.0.0", Backend::Daemon, aether::ffi::ABI_TAG)
        });
        let bus_arc: std::sync::Arc<dyn aether::Bus> = std::sync::Arc::new(nb);
        let module_ctx = CreatureCtx { me, bus: bus_arc, manifest };
        // Install the thread-local registry so any `forge::spawn` from inside user `bind`
        // registers with THIS creature. Guard clears on every exit (Ok or panic-unwind).
        crate::managed::set_active(cb.threads.clone());
        let _g = ActiveThreadsGuard;
        // A panic in user `bind` would unwind across `extern "C"` (UB). Catch it; mark poisoned so
        // the first `handle` returns RC_PANIC and the host unloads us.
        if let Err(e) = catch_unwind(AssertUnwindSafe(|| cb.user.bind(module_ctx))) {
            cb.poisoned = true;
            crate::best_effort_stderr(format_args!(
                "forge: creature panicked in bind ({}); marking poisoned — the host will unload it",
                panic_msg(&*e)
            ));
            std::mem::forget(e);
        }
    }

    /// # Safety
    /// `data` must point to a `CreatureBox<T>` from `bind`; `env_ptr`/`env_len` describe a valid
    /// byte buffer.
    pub unsafe fn handle<T: Creature>(
        data: *mut c_void,
        env_ptr: *const u8,
        env_len: usize,
    ) -> i32 {
        let cb = &mut *(data as *mut CreatureBox<T>);
        if cb.poisoned {
            return RC_PANIC; // a previous call panicked or `bind` failed; do not run user code again
        }
        let bytes = std::slice::from_raw_parts(env_ptr, env_len);
        let env = match Envelope::parse(bytes) {
            Ok(e) => e,
            Err(_) => return RC_DESERIALIZE, // malformed envelope is a clean status, never a panic
        };
        // Install thread-local registry so `forge::spawn` calls from inside `handle` register
        // with THIS creature (a creature may legitimately spawn workers from handle, not just bind).
        crate::managed::set_active(cb.threads.clone());
        let _g = ActiveThreadsGuard;
        let result = catch_unwind(AssertUnwindSafe(|| cb.user.handle(env)));
        let outcome = match result {
            Ok(o) => o,
            Err(e) => {
                // Creature-fault isolation at the FFI seam (R9). Mark poisoned so we never call user
                // code again — its state is unknown after the unwind — and tell the host to unload.
                cb.poisoned = true;
                crate::best_effort_stderr(format_args!(
                    "forge: creature panicked in handle ({})",
                    panic_msg(&*e)
                ));
                std::mem::forget(e);
                return RC_PANIC;
            }
        };
        // Send the user's outcome dispatches back to the host via the native bus. The host's
        // `NativeInstance::handle` returns `Outcome::none()` — the work happens through this loop.
        // This is a native creature's ONLY egress; dropping a dispatch silently here loses its work
        // with no trace, so surface a failed emit (best-effort delivery is unchanged). (T8)
        if let Some(bus) = &cb.bus {
            for d in outcome.dispatches {
                if let Err(e) = bus.emit(d) {
                    crate::best_effort_stderr(format_args!(
                        "forge: creature {:?} dropped a dispatch: {e}",
                        bus.whoami()
                    ));
                }
            }
        }
        RC_OK
    }

    /// # Safety
    /// `data` must point to a `CreatureBox<T>` from `bind`.
    pub unsafe fn shutdown<T: Creature>(data: *mut c_void, deadline_ms: u64) {
        let cb = &mut *(data as *mut CreatureBox<T>);
        if cb.poisoned {
            // Do not run poisoned user code; the kernel will drop us next. We STILL join any
            // managed threads — they may carry on after `bind` panicked and would UAF on `dlclose`.
            cb.threads.join_all();
            return;
        }
        // Install the registry so user `shutdown` can still spawn (e.g. a fast cleanup worker) and
        // see it joined below.
        crate::managed::set_active(cb.threads.clone());
        let _g = ActiveThreadsGuard;
        // A panicking `shutdown` is swallowed — we are unloading the creature anyway. The host
        // proceeds to `destroy`/`dlclose` regardless. Name it so the panic isn't wholly invisible.
        if let Err(e) =
            catch_unwind(AssertUnwindSafe(|| cb.user.shutdown(Deadline::from_millis(deadline_ms))))
        {
            crate::best_effort_stderr(format_args!(
                "forge: creature panicked in shutdown ({})",
                panic_msg(&*e)
            ));
            std::mem::forget(e);
        }
        // **The join barrier.** Every thread the creature registered via `forge::spawn` is
        // joined HERE — before the kernel runs `destroy` and `dlclose`. This is the discipline
        // that makes Option B (handle/generation + thread-join + dlclose-last) sound. A creature
        // whose threads never return will hang here until the kernel's unload deadline catches it
        // (run_drain → done_signal → KernelError::UnloadTimeout), at which point the drain is
        // abandoned detached and the kernel's thread-count guard refuses `dlclose` (bounded leak).
        if let Err(payload) = catch_unwind(AssertUnwindSafe(|| cb.threads.join_all())) {
            std::mem::forget(payload);
        }
    }

    /// # Safety
    /// `data` must point to a `CreatureBox<T>` allocated by the macro's constructor and not yet
    /// destroyed.
    pub unsafe fn destroy<T: Creature>(data: *mut c_void) {
        // Drop may panic if the user's `T::drop` panics — catch it so we never unwind across
        // `extern "C"`. The Box is freed either way (catch_unwind owns the closure result).
        let bx = Box::from_raw(data as *mut CreatureBox<T>);
        if let Err(e) = catch_unwind(AssertUnwindSafe(move || drop(bx))) {
            crate::best_effort_stderr(format_args!(
                "forge: creature panicked in Drop during destroy ({})",
                panic_msg(&*e)
            ));
            std::mem::forget(e);
        }
    }
}

/// Declare a creature: one `extern "C"` POD-only constructor (`gawd_creature_v1`) plus the C ABI vtable
/// of glue functions that bridge to the user's `Creature` impl. The user's type must impl
/// `Creature + Default`.
///
/// ```ignore
/// use forge::prelude::*;
///
/// #[derive(Default)]
/// pub struct EchoDaemon;
/// impl Creature for EchoDaemon {
///     fn bind(&mut self, _ctx: CreatureCtx) {}
///     fn handle(&mut self, env: Envelope) -> Outcome {
///         let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
///         Outcome::reply(&env, reversed)
///     }
/// }
/// forge::declare_creature!(EchoDaemon);
/// ```
#[macro_export]
macro_rules! declare_creature {
    ($t:ty) => {
        #[no_mangle]
        pub extern "C" fn gawd_creature_v1() -> *mut $crate::ffi::CreatureVTableV1 {
            $crate::glue::construct::<$t>()
        }
    };
}

/// What a creature commonly imports.
pub mod prelude {
    pub use aether::{
        Address, Bus, BusError, Creature, CreatureCtx, CreatureId, Deadline, Dispatch, Envelope,
        Header, Intent, NodeId, Outcome, Role, Topic,
    };
    pub use sigil::{
        Abi, Backend, Capabilities, Entrypoint, Manifest, NetCapability, Provenance, Requirements,
    };
}

/// Typed Function helpers for the existing single [`Creature::handle`](aether::Creature::handle)
/// boundary.
///
/// A Function is not a second ABI. The executor sends one versioned
/// [`gawdfn::FunctionCallMessageV1`] through an ordinary [`Envelope`](aether::Envelope), and author
/// code demultiplexes the signed entrypoint name here. These helpers keep the schema tag, bounds,
/// immutable identity check, and reply correlation identical across native, WASM, and Rhai
/// adapters; they make no placement, retry, trust, or scheduling decision.
pub mod function {
    use std::fmt;

    use aether::{Address, CreatureId, Dispatch, Envelope};
    use gawdfn::{
        AttemptId, ControlDispositionV1, ExecutionControlV1, FunctionCallMessageV1, FunctionCallV1,
        FunctionId, FunctionResultV1, SignedRecordV1, Validate, ValueRefV1, MAX_JOB_MESSAGE_BYTES,
        SCHEMA_CALL_V1,
    };
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    /// A bounded failure at the typed-call adapter. This is a wire/identity error, never an
    /// execution-policy verdict.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum FunctionWireError {
        WrongSchema { actual: String },
        TooLarge { len: usize, limit: usize },
        Decode(String),
        UnexpectedOperation,
        Invalid(String),
        WrongFunction { expected: FunctionId, actual: FunctionId },
        NotInline,
    }

    impl fmt::Display for FunctionWireError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::WrongSchema { actual } => {
                    write!(f, "expected schema `{SCHEMA_CALL_V1}`, received `{actual}`")
                }
                Self::TooLarge { len, limit } => {
                    write!(f, "function message is {len} bytes, exceeds {limit}")
                }
                Self::Decode(error) => write!(f, "cannot decode function message: {error}"),
                Self::UnexpectedOperation => f.write_str("expected a function call operation"),
                Self::Invalid(error) => write!(f, "invalid function message: {error}"),
                Self::WrongFunction { expected, actual } => write!(
                    f,
                    "call targets {}#{}, expected {}#{}",
                    actual.manifest_content_address,
                    actual.entrypoint,
                    expected.manifest_content_address,
                    expected.entrypoint
                ),
                Self::NotInline => f.write_str("value is a blob reference, not inline JSON"),
            }
        }
    }

    impl std::error::Error for FunctionWireError {}

    /// Build a correlated call dispatch. `reply_to` is explicit because an executor may use a
    /// dedicated endpoint instead of its creature identity.
    pub fn call(
        to: Address,
        reply_to: Address,
        corr: u64,
        call: FunctionCallV1,
    ) -> Result<Dispatch, FunctionWireError> {
        call.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        let message = FunctionCallMessageV1::Call { call: Box::new(call) };
        let payload = serde_json::to_vec(&message)
            .map_err(|error| FunctionWireError::Decode(error.to_string()))?;
        ensure_bound(payload.len())?;
        Ok(Dispatch::to(to, payload)
            .with_schema(SCHEMA_CALL_V1)
            .with_reply_to(reply_to)
            .with_corr(corr))
    }

    /// Decode and structurally validate any typed Function call from an Envelope.
    pub fn parse_call(env: &Envelope) -> Result<FunctionCallV1, FunctionWireError> {
        if env.header.schema != SCHEMA_CALL_V1 {
            return Err(FunctionWireError::WrongSchema { actual: env.header.schema.clone() });
        }
        ensure_bound(env.payload.len())?;
        let message: FunctionCallMessageV1 = serde_json::from_slice(&env.payload)
            .map_err(|error| FunctionWireError::Decode(error.to_string()))?;
        let FunctionCallMessageV1::Call { call } = message else {
            return Err(FunctionWireError::UnexpectedOperation);
        };
        call.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        require_executor_route(
            env,
            &call.executor_dispatch.payload.executor_creature,
            &call.executor_dispatch.payload.target_creature,
        )?;
        Ok(*call)
    }

    fn require_executor_route(
        env: &Envelope,
        executor_route: &str,
        target_route: &str,
    ) -> Result<(), FunctionWireError> {
        let executor = canonical_creature_id(executor_route, "executor")?;
        let target = canonical_creature_id(target_route, "target")?;
        if env.header.from != Address::Creature(executor) {
            return Err(FunctionWireError::Invalid(
                "function call did not arrive from its grant-pinned executor".into(),
            ));
        }
        if env.header.to != Address::Creature(target) {
            return Err(FunctionWireError::Invalid(
                "function call did not arrive at its grant-pinned deployment target".into(),
            ));
        }
        Ok(())
    }

    fn canonical_creature_id(
        value: &str,
        label: &'static str,
    ) -> Result<CreatureId, FunctionWireError> {
        let parsed = value.parse::<u64>().map_err(|_| {
            FunctionWireError::Invalid(format!(
                "function {label} route is not a numeric CreatureId"
            ))
        })?;
        if parsed == 0 || parsed.to_string() != value {
            return Err(FunctionWireError::Invalid(format!(
                "function {label} route is not one canonical positive CreatureId"
            )));
        }
        Ok(CreatureId(parsed))
    }

    /// Decode a call and require the immutable signed Function identity expected by this adapter.
    pub fn parse_call_for(
        env: &Envelope,
        expected: &FunctionId,
    ) -> Result<FunctionCallV1, FunctionWireError> {
        let call = parse_call(env)?;
        if &call.function != expected {
            return Err(FunctionWireError::WrongFunction {
                expected: expected.clone(),
                actual: call.function,
            });
        }
        Ok(call)
    }

    /// Decode and verify one Home-endorsed cooperative control for its exact attempt.
    ///
    /// This verifies the old Home's exact durable acceptance event, the current Home endorsement,
    /// original execution grant, stable-executor current-route signature, schema/size bounds, and
    /// both envelope endpoints before application code can observe the command.
    pub fn parse_control(
        env: &Envelope,
    ) -> Result<(AttemptId, SignedRecordV1<ExecutionControlV1>), FunctionWireError> {
        if env.header.schema != SCHEMA_CALL_V1 {
            return Err(FunctionWireError::WrongSchema { actual: env.header.schema.clone() });
        }
        ensure_bound(env.payload.len())?;
        let message: FunctionCallMessageV1 = serde_json::from_slice(&env.payload)
            .map_err(|error| FunctionWireError::Decode(error.to_string()))?;
        message.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        let FunctionCallMessageV1::Control { control } = message else {
            return Err(FunctionWireError::UnexpectedOperation);
        };
        require_executor_route(
            env,
            &control.executor_dispatch.payload.executor_creature,
            &control.executor_dispatch.payload.target_creature,
        )?;
        Ok((control.attempt, *control.endorsement))
    }

    /// Build a correlation-preserving reply to a typed Function call.
    pub fn reply(
        request: &Envelope,
        result: FunctionResultV1,
    ) -> Result<Dispatch, FunctionWireError> {
        result.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        let message = FunctionCallMessageV1::Result { result };
        let payload = serde_json::to_vec(&message)
            .map_err(|error| FunctionWireError::Decode(error.to_string()))?;
        ensure_bound(payload.len())?;
        Ok(Dispatch::reply_to_env(request, payload).with_schema(SCHEMA_CALL_V1))
    }

    /// Build a successful, correlation-preserving typed Function reply from one serializable
    /// inline value. The caller supplies the exact [`AttemptId`] decoded from the authenticated
    /// call; this helper never reconstructs or substitutes it.
    pub fn success<T: Serialize>(
        request: &Envelope,
        attempt: AttemptId,
        value: &T,
    ) -> Result<Dispatch, FunctionWireError> {
        reply(request, FunctionResultV1 { attempt, outcome: Ok(inline(value)?) })
    }

    /// Report cooperative progress to the executor that issued `request`. The executor, not the
    /// target, signs the durable Job receipt after authenticating the deployment sender.
    pub fn progress(
        request: &Envelope,
        attempt: AttemptId,
        sequence: u64,
        progress: ValueRefV1,
    ) -> Result<Dispatch, FunctionWireError> {
        attempt.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        if sequence == 0 {
            return Err(FunctionWireError::Invalid("progress sequence must be non-zero".into()));
        }
        progress.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        call_observation(request, FunctionCallMessageV1::Progress { attempt, sequence, progress })
    }

    /// Report a cooperative checkpoint reference to the issuing executor.
    pub fn checkpoint(
        request: &Envelope,
        attempt: AttemptId,
        sequence: u64,
        checkpoint: ValueRefV1,
    ) -> Result<Dispatch, FunctionWireError> {
        attempt.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        if sequence == 0 {
            return Err(FunctionWireError::Invalid("checkpoint sequence must be non-zero".into()));
        }
        checkpoint.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        call_observation(
            request,
            FunctionCallMessageV1::Checkpoint { attempt, sequence, checkpoint },
        )
    }

    /// Truthfully acknowledge a cooperative control after the target has applied or refused it.
    pub fn control_result(
        request: &Envelope,
        disposition: ControlDispositionV1,
        detail: Option<String>,
    ) -> Result<Dispatch, FunctionWireError> {
        let (attempt, control) = parse_control(request)?;
        call_observation(
            request,
            FunctionCallMessageV1::ControlResult {
                attempt,
                control: control.payload.caller_request.payload.control,
                disposition,
                detail,
            },
        )
    }

    fn call_observation(
        request: &Envelope,
        message: FunctionCallMessageV1,
    ) -> Result<Dispatch, FunctionWireError> {
        message.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        let payload = serde_json::to_vec(&message)
            .map_err(|error| FunctionWireError::Decode(error.to_string()))?;
        ensure_bound(payload.len())?;
        Ok(Dispatch::reply_to_env(request, payload).with_schema(SCHEMA_CALL_V1))
    }

    /// Convert a serializable value into the bounded inline-JSON form used by a Function call.
    pub fn inline<T: Serialize>(value: &T) -> Result<ValueRefV1, FunctionWireError> {
        let value = serde_json::to_value(value)
            .map_err(|error| FunctionWireError::Decode(error.to_string()))?;
        let value = ValueRefV1::Inline { value };
        value.validate().map_err(|error| FunctionWireError::Invalid(error.to_string()))?;
        Ok(value)
    }

    /// Decode bounded inline JSON. Blob resolution deliberately remains a `job-blob` concern.
    pub fn from_inline<T: DeserializeOwned>(value: &ValueRefV1) -> Result<T, FunctionWireError> {
        let ValueRefV1::Inline { value } = value else {
            return Err(FunctionWireError::NotInline);
        };
        serde_json::from_value(value.clone())
            .map_err(|error| FunctionWireError::Decode(error.to_string()))
    }

    fn ensure_bound(len: usize) -> Result<(), FunctionWireError> {
        if len > MAX_JOB_MESSAGE_BYTES {
            Err(FunctionWireError::TooLarge { len, limit: MAX_JOB_MESSAGE_BYTES })
        } else {
            Ok(())
        }
    }
}

/// **SEER helpers.** Typed wrappers that build a [`Dispatch`] carrying a
/// `seer::SeerEnvelope` on the `seer::SCHEMA` schema string (the `seer` crate). **No
/// models** (S7 mitigation): the helpers serialize the topic-typed body the caller hands in;
/// they never decide what to ask, when to retry, or how to reconcile. That's the consumer's
/// model.
///
/// Pattern: `bus.emit(forge::seer::query(to, topic, corr, query_id, &body))?`. Equivalent to
/// building the `seer::SeerEnvelope` by hand and wrapping in a [`Dispatch`];
/// the helpers exist so the schema string + corr propagation never desync between sites.
pub mod seer {
    // `::seer` (leading `::`) is the external `seer` crate — disambiguated from this module, which
    // is also named `seer` (forge's public helper surface, `forge::seer::*`).
    use ::seer::{SeerEnvelope, SeerTopic, SCHEMA};
    use aether::{Address, Dispatch};
    use serde::Serialize;

    /// Build a Dispatch carrying a [`SeerEnvelope::query`]. The `body` is serialized to
    /// `serde_json::Value`; the per-topic typed body lives in
    /// `seer::topics`. `corr` propagates to the envelope header so journal/router see
    /// the conversation id at the wire level.
    pub fn query<T: Serialize>(
        to: Address,
        topic: SeerTopic,
        corr: u64,
        query_id: u64,
        body: &T,
    ) -> Dispatch {
        let env = SeerEnvelope::query(topic, corr, query_id, body);
        Dispatch::to(to, env.to_bytes()).with_schema(SCHEMA).with_corr(corr)
    }

    /// Build a Dispatch carrying a [`SeerEnvelope::answer`] matched to a prior Query by
    /// `(corr, query_id)`. The pairing key survives the wire — a respondent that answers a
    /// different `query_id` than the one parked on the consumer side is dropped (the consumer
    /// has no way to know which conversation the answer belongs to).
    pub fn answer<T: Serialize>(
        to: Address,
        topic: SeerTopic,
        corr: u64,
        query_id: u64,
        body: &T,
    ) -> Dispatch {
        let env = SeerEnvelope::answer(topic, corr, query_id, body);
        Dispatch::to(to, env.to_bytes()).with_schema(SCHEMA).with_corr(corr)
    }

    /// Build a Dispatch carrying a [`SeerEnvelope::steer`]. `verb` is convention (`"abort"` |
    /// `"amend"` | `"info"` are the established ones); `payload` is opaque to the substrate.
    /// Whether the consumer acts on it is the consumer's model — ignoring a steer is contract-
    /// compliant.
    pub fn steer<T: Serialize>(
        to: Address,
        topic: SeerTopic,
        corr: u64,
        verb: &str,
        payload: &T,
    ) -> Dispatch {
        let env = SeerEnvelope::steer(topic, corr, verb, payload);
        Dispatch::to(to, env.to_bytes()).with_schema(SCHEMA).with_corr(corr)
    }

    /// Build a Dispatch carrying a [`SeerEnvelope::progress`]. `fraction`/`note` elide from
    /// the wire when `None` — a minimal-progress creature ships a tight envelope.
    pub fn progress(
        to: Address,
        topic: SeerTopic,
        corr: u64,
        stage: &str,
        fraction: Option<f32>,
        note: Option<&str>,
    ) -> Dispatch {
        let env = SeerEnvelope::progress(topic, corr, stage, fraction, note);
        Dispatch::to(to, env.to_bytes()).with_schema(SCHEMA).with_corr(corr)
    }

    /// Build a Dispatch carrying a [`SeerEnvelope::thought`]. `channel` is `"internal"`
    /// (deliberation; the Loop 2 selection signal) or `"external"` (prose surfaced as content).
    pub fn thought(
        to: Address,
        topic: SeerTopic,
        corr: u64,
        channel: &str,
        content: &str,
    ) -> Dispatch {
        let env = SeerEnvelope::thought(topic, corr, channel, content);
        Dispatch::to(to, env.to_bytes()).with_schema(SCHEMA).with_corr(corr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{Address, Dispatch};
    use std::sync::atomic::{AtomicUsize, Ordering};

    static FAKE_SENDS: AtomicUsize = AtomicUsize::new(0);

    struct DropPanics;

    impl Drop for DropPanics {
        fn drop(&mut self) {
            panic!("panic payload drop fault specimen")
        }
    }

    struct PanickingDefault;

    impl Default for PanickingDefault {
        fn default() -> Self {
            std::panic::panic_any(DropPanics)
        }
    }

    impl aether::Creature for PanickingDefault {
        fn bind(&mut self, _ctx: aether::CreatureCtx) {}

        fn handle(&mut self, _env: aether::Envelope) -> aether::Outcome {
            aether::Outcome::none()
        }
    }

    #[test]
    fn panicking_default_with_panicking_payload_drop_is_a_null_result_not_an_abi_unwind() {
        assert!(glue::construct::<PanickingDefault>().is_null());
    }

    extern "C" fn fake_send(_ctx: *mut c_void, _ptr: *const u8, _len: usize) -> i32 {
        FAKE_SENDS.fetch_add(1, Ordering::Relaxed);
        0
    }

    #[test]
    fn native_bus_emit_serializes_and_invokes_the_callback() {
        let bus = NativeBus::new(fake_send, std::ptr::null_mut(), CreatureId(7));
        let before = FAKE_SENDS.load(Ordering::Relaxed);
        bus.emit(Dispatch::to(Address::Creature(CreatureId(9)), b"x".to_vec())).unwrap();
        assert!(FAKE_SENDS.load(Ordering::Relaxed) > before);
        assert_eq!(bus.whoami(), CreatureId(7));
    }

    extern "C" fn failing_send(_ctx: *mut c_void, _ptr: *const u8, _len: usize) -> i32 {
        42
    }

    #[test]
    fn native_bus_surfaces_a_callback_failure() {
        let bus = NativeBus::new(failing_send, std::ptr::null_mut(), CreatureId(1));
        match bus.emit(Dispatch::to(Address::Creature(CreatureId(2)), vec![])) {
            Err(BusError::Ffi(42)) => {}
            other => panic!("expected Ffi(42), got {other:?}"),
        }
    }

    extern "C" fn backpressure_send(_ctx: *mut c_void, _ptr: *const u8, _len: usize) -> i32 {
        ffi::RC_BACKPRESSURE
    }
    extern "C" fn no_such_module_send(_ctx: *mut c_void, _ptr: *const u8, _len: usize) -> i32 {
        ffi::RC_NO_SUCH_MODULE
    }
    extern "C" fn no_provider_send(_ctx: *mut c_void, _ptr: *const u8, _len: usize) -> i32 {
        ffi::RC_NO_PROVIDER
    }

    #[test]
    fn managed_spawn_registers_and_join_all_joins() {
        use std::sync::atomic::AtomicUsize;
        let threads = managed::Threads::new();
        managed::set_active(threads.clone());
        let _g = scopeguard_clear(); // ensure ACTIVE is cleared even on assertion failure
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let before = COUNTER.load(Ordering::Relaxed);
        spawn("test-counter", || {
            COUNTER.fetch_add(1, Ordering::Relaxed);
        });
        spawn("test-counter", || {
            COUNTER.fetch_add(1, Ordering::Relaxed);
        });
        assert_eq!(threads.len(), 2, "two spawned threads register in the active set");
        threads.join_all();
        assert!(threads.is_empty(), "join_all drains the registry");
        assert_eq!(
            COUNTER.load(Ordering::Relaxed) - before,
            2,
            "both managed threads ran to completion (join was real)"
        );
    }

    #[test]
    fn managed_try_spawn_registers_and_surfaces_invalid_names() {
        use std::io::ErrorKind;
        use std::sync::atomic::AtomicUsize;

        let threads = managed::Threads::new();
        managed::set_active(threads.clone());
        let _g = scopeguard_clear(); // ensure ACTIVE is cleared even on assertion failure
        static RAN: AtomicUsize = AtomicUsize::new(0);
        let before = RAN.load(Ordering::Relaxed);

        managed::try_spawn("try-counter", || {
            RAN.fetch_add(1, Ordering::Relaxed);
        })
        .expect("valid managed try_spawn succeeds");
        assert_eq!(threads.len(), 1, "try_spawn registers with the active managed set");
        threads.join_all();
        assert_eq!(RAN.load(Ordering::Relaxed) - before, 1);

        let err = managed::try_spawn("bad\0name", || {
            RAN.fetch_add(1, Ordering::Relaxed);
        })
        .expect_err("invalid thread name returns an error instead of panicking");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert!(threads.is_empty(), "invalid spawn is not registered");
    }

    #[test]
    fn managed_spawn_outside_active_set_falls_back_to_raw() {
        // No `set_active` call — the spawn falls back to std::thread::spawn (fire-and-forget).
        // The kernel's thread-count guard catches these as leaked tids on a real creature; here we
        // just confirm the path doesn't panic and doesn't try to register into a nonexistent set.
        use std::sync::atomic::AtomicUsize;
        managed::clear(); // belt: ensure no stale ACTIVE from a parallel test
        static RAN: AtomicUsize = AtomicUsize::new(0);
        let before = RAN.load(Ordering::Relaxed);
        spawn("fallback-raw", || {
            RAN.fetch_add(1, Ordering::Relaxed);
        });
        // Give the raw thread a moment to run (it's not joinable from here).
        for _ in 0..100 {
            if RAN.load(Ordering::Relaxed) > before {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(RAN.load(Ordering::Relaxed) > before, "raw fallback thread runs");
    }

    #[test]
    fn unmanaged_try_spawn_surfaces_invalid_names_without_panicking() {
        use std::io::ErrorKind;
        use std::sync::atomic::AtomicUsize;

        managed::clear(); // belt: ensure no stale ACTIVE from a parallel test
        static RAN: AtomicUsize = AtomicUsize::new(0);
        let before = RAN.load(Ordering::Relaxed);

        let err = try_spawn("bad\0name", || {
            RAN.fetch_add(1, Ordering::Relaxed);
        })
        .expect_err("invalid raw-fallback thread name returns an error instead of panicking");
        assert_eq!(err.kind(), ErrorKind::InvalidInput);
        assert_eq!(RAN.load(Ordering::Relaxed), before, "invalid spawn does not run the worker");
    }

    /// Tiny drop-guard helper for tests to be panic-safe about clearing the thread-local.
    fn scopeguard_clear() -> impl Drop {
        struct G;
        impl Drop for G {
            fn drop(&mut self) {
                managed::clear();
            }
        }
        G
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────
    // Seer helpers build typed wrappers; they never decide topic semantics.
    // ─────────────────────────────────────────────────────────────────────────────────────────

    #[test]
    fn seer_query_helper_builds_dispatch_with_correct_schema_and_corr() {
        use ::seer::{SeerEnvelope, SeerKind, SeerTopic, SCHEMA};
        use serde_json::json;

        let to = Address::Creature(CreatureId(7));
        let d = crate::seer::query(to.clone(), SeerTopic::Authoring, 42, 1, &json!({"q":"?"}));
        assert_eq!(d.schema, SCHEMA, "helper uses the canonical seer schema");
        assert_eq!(d.corr, Some(42), "corr propagates onto the envelope header for the router");
        assert_eq!(d.to, to);
        let env = SeerEnvelope::parse(&d.payload).expect("payload decodes as SeerEnvelope");
        assert_eq!(env.topic, SeerTopic::Authoring);
        assert_eq!(env.corr, 42);
        match env.kind {
            SeerKind::Query { query_id: 1, body } => assert_eq!(body["q"], "?"),
            other => panic!("expected Query{{query_id:1}}, got {other:?}"),
        }
    }

    #[test]
    fn seer_answer_helper_pairs_corr_and_query_id() {
        use ::seer::{SeerEnvelope, SeerKind, SeerTopic};

        let to = Address::Creature(CreatureId(3));
        let d = crate::seer::answer(to, SeerTopic::Placement, 100, 17, &"node-A");
        let env = SeerEnvelope::parse(&d.payload).unwrap();
        match env.kind {
            SeerKind::Answer { query_id: 17, body } => {
                assert_eq!(body, serde_json::json!("node-A"))
            }
            other => panic!("expected Answer{{query_id:17}}, got {other:?}"),
        }
        assert_eq!(env.topic, SeerTopic::Placement);
        assert_eq!(env.corr, 100);
    }

    #[test]
    fn seer_steer_helper_carries_opaque_payload() {
        use ::seer::{SeerEnvelope, SeerKind, SeerTopic};
        let d = crate::seer::steer(
            Address::Creature(CreatureId(1)),
            SeerTopic::Budget,
            55,
            "abort",
            &serde_json::json!({ "reason": "operator changed mind" }),
        );
        let env = SeerEnvelope::parse(&d.payload).unwrap();
        match env.kind {
            SeerKind::Steer { kind, payload } => {
                assert_eq!(kind, "abort");
                assert_eq!(payload["reason"], "operator changed mind");
            }
            other => panic!("expected Steer, got {other:?}"),
        }
    }

    #[test]
    fn seer_progress_helper_elides_absent_optional_fields() {
        use ::seer::SeerEnvelope;
        let d = crate::seer::progress(
            Address::Creature(CreatureId(2)),
            ::seer::SeerTopic::Authoring,
            8,
            "started",
            None,
            None,
        );
        let json = String::from_utf8(d.payload.clone()).unwrap();
        assert!(!json.contains("fraction"), "absent fraction must not appear: {json}");
        assert!(!json.contains("note"), "absent note must not appear: {json}");
        // The envelope still decodes cleanly.
        let _ = SeerEnvelope::parse(&d.payload).expect("decodes with the absent optionals");
    }

    #[test]
    fn seer_thought_helper_distinguishes_internal_and_external() {
        use ::seer::{SeerEnvelope, SeerKind};
        for channel in ["internal", "external"] {
            let d = crate::seer::thought(
                Address::Creature(CreatureId(4)),
                ::seer::SeerTopic::Authoring,
                3,
                channel,
                "narration",
            );
            let env = SeerEnvelope::parse(&d.payload).unwrap();
            match env.kind {
                SeerKind::Thought { channel: c, content } => {
                    assert_eq!(c, channel);
                    assert_eq!(content, "narration");
                }
                other => panic!("expected Thought, got {other:?}"),
            }
        }
    }

    #[test]
    fn function_helpers_preserve_schema_corr_and_immutable_identity() {
        use aether::{Envelope, Header};
        use gawdfn::{
            canonical_hash, AbodeKeyBindingV1, AttemptId, AuthoritySigner, DeliveryModeV1,
            DeploymentId, DeploymentReceiptV1, Ed25519SeedSigner, ExecutionGrantV1,
            ExecutorDispatchV1, FunctionCallV1, FunctionId, HomeAuthorityV1, HomeId, JobId,
            OperationalCapabilityV1, OperationalKeyGrantV1, SignedRecordV1, SCHEMA_CALL_V1,
            SCHEMA_EXECUTE_V1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1,
        };

        let function = FunctionId {
            manifest_content_address: format!("sha256:{}", "a".repeat(64)),
            entrypoint: "summarize".into(),
        };
        let root = Ed25519SeedSigner::from_seed([31; 32]).unwrap();
        let operational = Ed25519SeedSigner::from_seed([32; 32]).unwrap();
        let executor = Ed25519SeedSigner::from_seed([33; 32]).unwrap();
        let home = HomeId::new(root.public_key());
        let authority = HomeAuthorityV1 {
            abode: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                AbodeKeyBindingV1 {
                    abode: home.clone(),
                    root_public_key: root.public_key().into(),
                    issued_at_unix_ms: None,
                },
                &root,
            )
            .unwrap(),
            operational: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                OperationalKeyGrantV1 {
                    home: home.clone(),
                    epoch: 1,
                    operational_public_key: operational.public_key().into(),
                    valid_from_unix_ms: None,
                    expires_at_unix_ms: None,
                    capabilities: vec![OperationalCapabilityV1::JobHome],
                    evidence: vec![],
                },
                &root,
            )
            .unwrap(),
            prepared: None,
        };
        let attempt = AttemptId { home: home.clone(), job: JobId::new("job-1"), number: 1 };
        let deployment = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentReceiptV1 {
                deployment: DeploymentId::new("deployment-forge-test"),
                function: function.clone(),
                artifact_hash: format!("sha256:{}", "b".repeat(64)),
                realm: "realm-a".into(),
                node: "node-a".into(),
                executor: executor.public_key().into(),
                executor_creature: "10".into(),
                creature: "20".into(),
                evidence: vec![],
                registered_at_unix_ms: None,
            },
            &executor,
        )
        .unwrap();
        let input = crate::function::inline(&serde_json::json!({"text":"hello"})).unwrap();
        let grant = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionGrantV1 {
                attempt: attempt.clone(),
                request_hash: format!("sha256:{}", "c".repeat(64)),
                home_epoch: 1,
                home_route_sequence: 1,
                home_realm: "realm-a".into(),
                home_node: "home-node".into(),
                home_coordinator: "30".into(),
                owner: home,
                authority,
                function: function.clone(),
                deployment,
                input: input.clone(),
                delivery: DeliveryModeV1::AtMostOnce,
                grant_sequence: 1,
                issued_at_unix_ms: None,
                deadline_unix_ms: None,
            },
            &operational,
        )
        .unwrap();
        let executor_dispatch = SignedRecordV1::sign(
            SCHEMA_CALL_V1,
            ExecutorDispatchV1 {
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                deployment: grant.payload.deployment.payload.deployment.clone(),
                executor_creature: "10".into(),
                target_creature: "20".into(),
            },
            &executor,
        )
        .unwrap();
        let call = FunctionCallV1 {
            attempt,
            function: function.clone(),
            input,
            grant: Box::new(grant),
            executor_dispatch,
        };
        let from = Address::Creature(CreatureId(10));
        let to = Address::Creature(CreatureId(20));
        let dispatch = crate::function::call(to.clone(), from.clone(), 77, call.clone()).unwrap();
        assert_eq!(dispatch.schema, SCHEMA_CALL_V1);
        assert_eq!(dispatch.corr, Some(77));
        assert_eq!(dispatch.reply_to, Some(from.clone()));

        let env = Envelope {
            header: Header {
                from,
                to,
                reply_to: dispatch.reply_to,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: dispatch.corr,
                commitment: None,
                schema: dispatch.schema,
                origin: None,
            },
            payload: dispatch.payload,
        };
        assert_eq!(crate::function::parse_call_for(&env, &function).unwrap(), call);

        let wrong = FunctionId {
            manifest_content_address: format!("sha256:{}", "b".repeat(64)),
            entrypoint: "summarize".into(),
        };
        assert!(matches!(
            crate::function::parse_call_for(&env, &wrong),
            Err(crate::function::FunctionWireError::WrongFunction { .. })
        ));

        let progress = crate::function::progress(
            &env,
            call.attempt.clone(),
            1,
            crate::function::inline(&serde_json::json!({"stage":"reading"})).unwrap(),
        )
        .unwrap();
        assert_eq!(progress.schema, SCHEMA_CALL_V1);
        assert_eq!(progress.corr, Some(77));
        assert_eq!(progress.to, Address::Creature(CreatureId(10)));
        let message: gawdfn::FunctionCallMessageV1 =
            serde_json::from_slice(&progress.payload).unwrap();
        assert!(matches!(message, gawdfn::FunctionCallMessageV1::Progress { sequence: 1, .. }));
    }

    #[test]
    fn function_success_preserves_attempt_corr_and_inline_value() {
        use std::collections::BTreeMap;

        use aether::{Envelope, Header};
        use gawdfn::{AttemptId, FunctionCallMessageV1, HomeId, JobId, SCHEMA_CALL_V1};

        let attempt = AttemptId {
            home: HomeId::new("home-forge-success"),
            job: JobId::new("job-forge-success"),
            number: 2,
        };
        let request = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(10)),
                to: Address::Creature(CreatureId(20)),
                reply_to: Some(Address::Creature(CreatureId(30))),
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: Some(77),
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: vec![],
        };
        let output = BTreeMap::from([("doubled".to_string(), -14_i64)]);

        let dispatch = crate::function::success(&request, attempt.clone(), &output).unwrap();
        assert_eq!(dispatch.to, Address::Creature(CreatureId(30)));
        assert_eq!(dispatch.corr, Some(77));
        assert_eq!(dispatch.schema, SCHEMA_CALL_V1);

        let message: FunctionCallMessageV1 = serde_json::from_slice(&dispatch.payload).unwrap();
        let FunctionCallMessageV1::Result { result } = message else {
            panic!("success helper must emit a Function result");
        };
        assert_eq!(result.attempt, attempt, "the authenticated AttemptId is echoed exactly");
        let value = result.outcome.expect("success carries an Ok value");
        assert_eq!(crate::function::from_inline::<BTreeMap<String, i64>>(&value).unwrap(), output);

        let mut invalid_attempt = attempt;
        invalid_attempt.number = 0;
        assert!(matches!(
            crate::function::success(&request, invalid_attempt, &output),
            Err(crate::function::FunctionWireError::Invalid(_))
        ));
    }

    #[test]
    fn function_control_helpers_verify_endorsement_and_echo_exact_attempt() {
        use aether::{Envelope, Header};
        use gawdfn::{
            canonical_hash, AbodeKeyBindingV1, AuthoritySigner, ControlDispositionV1, ControlId,
            DeliveryModeV1, DeploymentId, DeploymentReceiptV1, Ed25519SeedSigner,
            ExecutionControlV1, ExecutionGrantV1, ExecutorControlDispatchV1, FunctionCallMessageV1,
            FunctionControlV1, FunctionId, HomeAuthorityV1, HomeId, JobControlKindV1, JobControlV1,
            JobEventKindV1, JobEventV1, JobHandleV1, JobId, JobStateV1, OperationalCapabilityV1,
            OperationalKeyGrantV1, SignedRecordV1, ValueRefV1, SCHEMA_CALL_V1, SCHEMA_EXECUTE_V1,
            SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1, SCHEMA_JOB_V1,
        };

        let root = Ed25519SeedSigner::from_seed([41; 32]).unwrap();
        let operational = Ed25519SeedSigner::from_seed([42; 32]).unwrap();
        let executor = Ed25519SeedSigner::from_seed([43; 32]).unwrap();
        let home = HomeId::new(root.public_key());
        let authority = HomeAuthorityV1 {
            abode: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                AbodeKeyBindingV1 {
                    abode: home.clone(),
                    root_public_key: root.public_key().into(),
                    issued_at_unix_ms: None,
                },
                &root,
            )
            .unwrap(),
            operational: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                OperationalKeyGrantV1 {
                    home: home.clone(),
                    epoch: 1,
                    operational_public_key: operational.public_key().into(),
                    valid_from_unix_ms: None,
                    expires_at_unix_ms: None,
                    capabilities: vec![
                        OperationalCapabilityV1::JobHome,
                        OperationalCapabilityV1::JobControl,
                    ],
                    evidence: vec![],
                },
                &root,
            )
            .unwrap(),
            prepared: None,
        };
        let attempt =
            gawdfn::AttemptId { home: home.clone(), job: JobId::new("job-control"), number: 1 };
        let control_id = ControlId::new("control-1");
        let caller_request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobControlV1 {
                handle: JobHandleV1 { home: home.clone(), job: attempt.job.clone() },
                expected_home_epoch: 1,
                control: control_id.clone(),
                issued_at_unix_ms: None,
                kind: JobControlKindV1::Cancel { reason: "stop".into() },
            },
            &root,
        )
        .unwrap();
        let accepted_event = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobEventV1 {
                handle: caller_request.payload.handle.clone(),
                home_epoch: 1,
                authority: authority.clone(),
                sequence: 2,
                occurred_at_unix_ms: None,
                state_after: JobStateV1::Running,
                cancel_requested: true,
                kind: JobEventKindV1::ControlRequested {
                    request: Box::new(caller_request.clone()),
                    attempt: Some(attempt.clone()),
                },
                foreign_receipt: None,
            },
            &operational,
        )
        .unwrap();
        let function = FunctionId {
            manifest_content_address: format!("sha256:{}", "a".repeat(64)),
            entrypoint: "controlled".into(),
        };
        let deployment = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentReceiptV1 {
                deployment: DeploymentId::new("control-deployment"),
                function: function.clone(),
                artifact_hash: format!("sha256:{}", "b".repeat(64)),
                realm: "realm-a".into(),
                node: "node-a".into(),
                executor: executor.public_key().into(),
                executor_creature: "10".into(),
                creature: "20".into(),
                evidence: vec![],
                registered_at_unix_ms: None,
            },
            &executor,
        )
        .unwrap();
        let grant = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionGrantV1 {
                attempt: attempt.clone(),
                request_hash: format!("sha256:{}", "c".repeat(64)),
                home_epoch: 1,
                home_route_sequence: 1,
                home_realm: "realm-a".into(),
                home_node: "home-node".into(),
                home_coordinator: "30".into(),
                owner: home,
                authority: authority.clone(),
                function,
                deployment,
                input: ValueRefV1::Inline { value: serde_json::json!({"value": 1}) },
                delivery: DeliveryModeV1::AtMostOnce,
                grant_sequence: 1,
                issued_at_unix_ms: None,
                deadline_unix_ms: None,
            },
            &operational,
        )
        .unwrap();
        let endorsed = SignedRecordV1::sign(
            SCHEMA_EXECUTE_V1,
            ExecutionControlV1 {
                caller_request,
                accepted_event: Box::new(accepted_event),
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                home_epoch: 1,
                home_route_sequence: 1,
                home_sequence: 2,
                home_realm: "realm-a".into(),
                home_node: "home-node".into(),
                home_coordinator: "30".into(),
                authority,
            },
            &operational,
        )
        .unwrap();
        let dispatch = SignedRecordV1::sign(
            SCHEMA_CALL_V1,
            ExecutorControlDispatchV1 {
                attempt: attempt.clone(),
                grant_hash: canonical_hash(&grant).unwrap(),
                control_hash: canonical_hash(&endorsed).unwrap(),
                deployment: grant.payload.deployment.payload.deployment.clone(),
                executor_creature: "10".into(),
                target_creature: "20".into(),
            },
            &executor,
        )
        .unwrap();
        let proof = FunctionControlV1 {
            attempt: attempt.clone(),
            endorsement: Box::new(endorsed.clone()),
            grant: Box::new(grant.clone()),
            executor_dispatch: dispatch,
        };
        let envelope = |from: u64, to: u64, message: FunctionCallMessageV1| Envelope {
            header: Header {
                from: Address::Creature(CreatureId(from)),
                to: Address::Creature(CreatureId(to)),
                reply_to: None,
                seq: 1,
                causal: vec![],
                stamp: 1,
                sig: "test".into(),
                corr: Some(77),
                commitment: None,
                schema: SCHEMA_CALL_V1.into(),
                origin: None,
            },
            payload: serde_json::to_vec(&message).unwrap(),
        };
        let request =
            envelope(10, 20, FunctionCallMessageV1::Control { control: Box::new(proof.clone()) });
        let (parsed_attempt, parsed_control) = crate::function::parse_control(&request).unwrap();
        assert_eq!(parsed_attempt, attempt);
        assert_eq!(parsed_control, endorsed);

        let reply = crate::function::control_result(
            &request,
            ControlDispositionV1::Rejected,
            Some("already stopped".into()),
        )
        .unwrap();
        let reply: FunctionCallMessageV1 = serde_json::from_slice(&reply.payload).unwrap();
        assert!(matches!(
            reply,
            FunctionCallMessageV1::ControlResult {
                attempt: echoed_attempt,
                control,
                disposition: ControlDispositionV1::Rejected,
                ..
            } if echoed_attempt == attempt && control == control_id
        ));

        let wrong_sender =
            envelope(11, 20, FunctionCallMessageV1::Control { control: Box::new(proof.clone()) });
        assert!(matches!(
            crate::function::parse_control(&wrong_sender),
            Err(crate::function::FunctionWireError::Invalid(_))
        ));

        let wrong_target =
            envelope(10, 21, FunctionCallMessageV1::Control { control: Box::new(proof.clone()) });
        assert!(matches!(
            crate::function::parse_control(&wrong_target),
            Err(crate::function::FunctionWireError::Invalid(_))
        ));

        let mut wrong_hash = proof.clone();
        wrong_hash.executor_dispatch.payload.control_hash = format!("sha256:{}", "d".repeat(64));
        wrong_hash.executor_dispatch =
            SignedRecordV1::sign(SCHEMA_CALL_V1, wrong_hash.executor_dispatch.payload, &executor)
                .unwrap();
        let wrong_hash =
            envelope(10, 20, FunctionCallMessageV1::Control { control: Box::new(wrong_hash) });
        assert!(matches!(
            crate::function::parse_control(&wrong_hash),
            Err(crate::function::FunctionWireError::Invalid(_))
        ));

        let mut forged = proof;
        forged.endorsement.payload.home_sequence += 1;
        let forged = envelope(10, 20, FunctionCallMessageV1::Control { control: Box::new(forged) });
        assert!(matches!(
            crate::function::parse_control(&forged),
            Err(crate::function::FunctionWireError::Invalid(_))
        ));
    }

    #[test]
    fn function_inline_decoder_refuses_unresolved_blobs() {
        use gawdfn::{BlobRefV1, ValueRefV1};

        let value = ValueRefV1::Blob {
            blob: BlobRefV1 {
                digest: format!("sha256:{}", "c".repeat(64)),
                size: 1,
                media_type: "application/json".into(),
            },
        };
        let decoded = crate::function::from_inline::<serde_json::Value>(&value);
        assert_eq!(decoded.unwrap_err(), crate::function::FunctionWireError::NotInline);
    }

    #[test]
    fn native_bus_maps_distinct_rcs_to_distinct_busserror_variants() {
        // R9 floor is only observable if a creature can act on backpressure differently from
        // NoSuchModule. The FFI rc carries that distinction; NativeBus::emit decodes it.
        let dispatch = || Dispatch::to(Address::Creature(CreatureId(2)), vec![]);

        let bp = NativeBus::new(backpressure_send, std::ptr::null_mut(), CreatureId(1));
        let err = bp.emit(dispatch()).unwrap_err();
        assert!(matches!(err, BusError::Backpressure), "got {err:?}");
        assert!(err.is_backpressure(), "is_backpressure() must classify the FFI variant");
        assert!(!err.is_unreachable());

        let nsm = NativeBus::new(no_such_module_send, std::ptr::null_mut(), CreatureId(1));
        let err = nsm.emit(dispatch()).unwrap_err();
        assert!(matches!(err, BusError::NoSuchModule), "got {err:?}");
        assert!(err.is_unreachable());
        assert!(!err.is_backpressure());

        let np = NativeBus::new(no_provider_send, std::ptr::null_mut(), CreatureId(1));
        let err = np.emit(dispatch()).unwrap_err();
        assert!(matches!(err, BusError::NoProvider), "got {err:?}");
        assert!(err.is_unreachable());
    }
}
