//! The native ABI seam — the C representation of [`Creature`](crate::Creature).
//!
//! Native daemons (`.so`) and the host meet here, and **only POD crosses**: integers, raw pointers,
//! and a vtable of `extern "C"` function pointers. No Rust trait object, `Box<dyn _>`, or
//! non-`repr(C)` type ever crosses — no fat-pointer hazard at `create_instance` (**R1**).
//!
//! Envelopes and dispatches cross as **serialized bytes** (ptr + len), so the creature holds no Rust
//! pointer into host types and the host holds only the opaque vtable into the creature. That is also
//! what makes unload clean (**R2**): run the creature's `destroy`, then `dlclose`, with nothing
//! dangling across the boundary.

use std::os::raw::c_void;

/// The ABI compatibility tag a native manifest must declare in `abi.abi_tag`. A mismatch is rejected
/// at load, before any symbol is called.
pub const ABI_TAG: &str = "gawd_creature_v1";

/// The single constructor symbol every native creature exports.
pub const NATIVE_CTOR_SYMBOL: &[u8] = b"gawd_creature_v1";

/// Return codes shared by every `extern "C"` boundary the host and a native creature meet across.
/// Distinct codes per failure shape so a creature can act on backpressure (retry later) differently
/// from `NoSuchModule` (give up) — the R9 floor is only useful if it is *observable*. `RC_PANIC`
/// lets the host detect that a creature unwound inside a glue function so it can pull the creature
/// off the bus rather than treating the call as successful.
pub const RC_OK: i32 = 0;
pub const RC_INVALID_ARG: i32 = 1;
pub const RC_DESERIALIZE: i32 = 2;
pub const RC_NO_SUCH_MODULE: i32 = 3;
pub const RC_NO_PROVIDER: i32 = 4;
pub const RC_BACKPRESSURE: i32 = 5;
pub const RC_DENIED: i32 = 6;
pub const RC_OTHER_ROUTE: i32 = 7;
/// A glue function caught a panic and returned cleanly across the C boundary. The host treats this
/// as "creature poisoned" and unloads it — never as success.
pub const RC_PANIC: i32 = 99;

/// Creature→host: deliver one serialized [`Dispatch`](crate::Dispatch). Returns `RC_OK` on success;
/// see the `RC_*` constants for distinct failure modes. Passed to the creature at `bind`; the
/// creature calls it (directly, or via the SDK's bus shim) to put envelopes on the bus — its only
/// outward authority, since there is no ambient global.
pub type BusSendFn =
    extern "C" fn(host_ctx: *mut c_void, dispatch_ptr: *const u8, dispatch_len: usize) -> i32;

/// What the host hands the creature at `bind`. POD only. The manifest pointer is valid only for the
/// duration of the `bind` call (the creature copies what it needs); `host_ctx` and `send` remain
/// valid until `destroy`.
#[repr(C)]
pub struct BindCtxFfi {
    pub creature_id: u64,
    pub manifest_ptr: *const u8,
    pub manifest_len: usize,
    pub host_ctx: *mut c_void,
    pub send: BusSendFn,
}

/// A loaded native creature as a POD vtable. The constructor returns `*mut CreatureVTableV1`. `data`
/// is the creature's own erased state pointer; the host never dereferences it, only hands it back to
/// the creature's own functions.
#[repr(C)]
pub struct CreatureVTableV1 {
    pub data: *mut c_void,
    pub bind: extern "C" fn(data: *mut c_void, ctx: *const BindCtxFfi),
    pub handle: extern "C" fn(data: *mut c_void, env_ptr: *const u8, env_len: usize) -> i32,
    pub shutdown: extern "C" fn(data: *mut c_void, deadline_ms: u64),
    pub destroy: extern "C" fn(data: *mut c_void),
}

/// The constructor signature the host looks up: `extern "C" fn() -> *mut CreatureVTableV1`.
/// It must never unwind across this non-unwinding ABI; the Forge-generated constructor catches a
/// panicking `Default` internally and returns null, which the host rejects as a load failure.
pub type NativeCtor = extern "C" fn() -> *mut CreatureVTableV1;
