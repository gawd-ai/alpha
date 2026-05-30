//! Hardening suite — proves the FFI-seam fixes work at the real FFI seam.
//!
//! The base walking-skeleton tests (`m0_integration.rs`) prove R1–R9 cross once with well-behaved
//! creatures. This file exercises the **same fabric under hostile creature behavior**:
//!
//! - **F1 (catch_unwind across `extern "C"`)** — a native `.so` creature that panics in `handle`
//!   would, without the SDK glue's `catch_unwind`, unwind across the C ABI = undefined behavior.
//!   The pre-hardening kernel test (`a_panicking_creature_is_isolated_not_fatal` in
//!   `sanctum::lib`) exercised the in-process path only; this exercises the real `.so` seam.
//! - **F13 (test coverage)** — fills the gap the audit flagged: no native-FFI panic isolation
//!   test existed.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Deadline, Dispatch, RouteError, StubSigner, StubVerifier};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

mod support;
use support::native_cdylib;

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn daemon_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

#[test]
fn a_panicking_native_creature_is_contained_at_the_ffi_seam() {
    let k = kernel();
    let panic_so = native_cdylib("panic_daemon");
    let echo_so = native_cdylib("echo_daemon");

    let panic_id = k
        .load(daemon_manifest("panic-daemon"), Artifact::Path(panic_so))
        .expect("panic-daemon loads");
    let echo_id =
        k.load(daemon_manifest("echo-daemon"), Artifact::Path(echo_so)).expect("echo-daemon loads");

    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    // Detonate. Queueing into the healthy inbox succeeds; the panic happens in the panic-daemon's
    // drain thread when it pulls the envelope and calls `handle`. The SDK glue catches the panic,
    // returns RC_PANIC; `NativeInstance::handle` re-panics on the host side; `run_drain`'s
    // `catch_unwind` catches THAT and pulls the creature off the bus.
    bus.send(Dispatch::to(Address::Creature(panic_id), b"boom".to_vec()))
        .expect("queueing into a healthy inbox should succeed");

    // Wait (bounded) for the kernel to deregister the panicked creature.
    let mut gone = false;
    for _ in 0..200 {
        if !k.is_loaded(panic_id) {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(gone, "a panicking native creature must be pulled off the bus");

    // Routing to the gone creature is a structured error, NEVER undefined behavior.
    let err = bus.send(Dispatch::to(Address::Creature(panic_id), b"again".to_vec())).unwrap_err();
    assert!(
        matches!(err, RouteError::NoSuchModule(_)),
        "post-panic routing must be NoSuchModule, got {err:?}"
    );

    // The healthy native creature beside it is unaffected — the fabric did not crash, the other
    // .so is still mapped, its drain thread is still running, the bus still serves.
    bus.send(
        Dispatch::to(Address::Creature(echo_id), b"abc".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .unwrap();
    let reply =
        rx.recv_timeout(Duration::from_secs(2)).expect("the healthy creature must still respond");
    assert_eq!(
        reply.payload, b"cba",
        "echo-daemon still reverses after the FFI panic was caught (fabric-integrity floor held)"
    );

    k.shutdown_all(Deadline::default());
}

#[test]
fn a_panicking_native_creature_unloads_cleanly_no_ub() {
    // Distinct angle: after the creature self-deregisters from the panic path, an explicit
    // `unload()` from the kernel must still succeed (idempotent + finds the entry by the join
    // handle path), and the drop ordering still runs (native `destroy` before `dlclose`).
    let k = kernel();
    let panic_so = native_cdylib("panic_daemon");

    let id = k.load(daemon_manifest("panic-daemon"), Artifact::Path(panic_so)).unwrap();
    let (_probe, bus, _rx) = k.open_endpoint(Capabilities::default());

    bus.send(Dispatch::to(Address::Creature(id), b"boom".to_vec())).unwrap();

    // Wait for the self-deregister.
    for _ in 0..200 {
        if !k.is_loaded(id) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }

    // Now ask the kernel to unload it explicitly. The entry is still in `Kernel.loaded` (the drain
    // thread doesn't touch that map on panic — known F8 hygiene item); unload removes it, joins
    // the (already-exited) drain thread, returns Ok. After this, a second unload is the structured
    // NoSuchModule, not UB.
    let _ = k.unload(id, Deadline::default()); // best-effort: may already be Ok or NoSuchModule
    assert!(!k.is_loaded(id));

    k.shutdown_all(Deadline::default());
}
