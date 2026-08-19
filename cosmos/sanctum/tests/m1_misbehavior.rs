//! A misbehaving creature (detached thread / leaked `'static`) is **detected +
//! contained, not UB**.
//!
//! Three cases prove the guard's scope and the native discipline + safety net together:
//!
//! - An **in-process instance** unloads normally even if an unrelated process thread starts after
//!   bind. It owns no dynamically loaded library, so process-wide TID noise cannot select the leak
//!   path.
//!
//! - **`welbehaved-thread-daemon`** spawns via the SDK's [`forge::spawn`] and signals stop in
//!   `shutdown`; the SDK joins the worker before the kernel `dlclose`s the library. Clean unload,
//!   no leak, no proprio "leaked" event — repeated 50× to prove the discipline survives many
//!   cycles.
//!
//! - **`runaway-thread-daemon`** spawns via raw `std::thread::spawn` (bypassing the SDK
//!   discipline) and never signals stop. The SDK joins zero threads. The kernel's pre-bind /
//!   post-shutdown tid snapshot sees the leaked thread and **refuses to `dlclose` the .so**:
//!   bounded leak (library stays mapped), no UAF when the runaway thread later dereferences live
//!   mapped code. The healthy creature beside it is unaffected — the fabric contains the violation.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{mpsc, Arc, Mutex, OnceLock};
use std::time::Duration;

use aether::{Address, Deadline, Dispatch, Topic};
use anima::{Artifact, Engine, EngineError, LoadedModule, NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::{Kernel, Proprioception};
use sigil::{Backend, Capabilities, Manifest};

mod support;
use support::native_cdylib;

/// **Serialize these tests.** The dynamically loaded native specimens share the process tid table,
/// which their thread-count guard reads from `/proc/self/task/`. Running them in parallel lets one
/// specimen's thread appear in another's post-shutdown snapshot — a false-positive triggering the
/// leak path.
///
/// This is the same limit the guard's doc names: per-creature thread tracking is future work; for
/// now the native guard counts at process granularity, so the test harness must serialize.
/// Production native unloads face the same false-positive rate under concurrency (a bounded leak,
/// not UAF — safe but noisy); in-process, WASM, and Rhai resources do not participate.
fn serial_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn kernel() -> Arc<Kernel> {
    kernel_with_native(Arc::new(NativeEngine))
}

fn kernel_with_native(native: Arc<dyn Engine>) -> Arc<Kernel> {
    Kernel::new(
        vec![native, Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("test-node")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

struct CaptureNativeStages {
    paths: Arc<Mutex<HashMap<String, PathBuf>>>,
}

impl Engine for CaptureNativeStages {
    fn backend(&self) -> Backend {
        Backend::Daemon
    }

    fn load(&self, artifact: &Artifact, manifest: &Manifest) -> Result<LoadedModule, EngineError> {
        if let Some(path) = artifact.staged_native_path() {
            self.paths
                .lock()
                .unwrap_or_else(|poison| poison.into_inner())
                .insert(manifest.name.clone(), path.to_path_buf());
        }
        let loaded = NativeEngine.load(artifact, manifest)?;
        assert!(
            loaded.requires_unmanaged_thread_guard(),
            "a module returned by NativeEngine must retain the dlclose safety guard"
        );
        Ok(loaded)
    }
}

fn daemon_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

/// Drain proprio events until either `target` arrives or the timeout expires. Returns the list of
/// events seen so the assertion can show what *was* there if the expected one wasn't.
fn drain_proprio_for(
    rx: &aether::InboxReceiver,
    target: &str,
    timeout: Duration,
) -> (bool, Vec<String>) {
    let deadline = std::time::Instant::now() + timeout;
    let mut seen = Vec::new();
    while std::time::Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            Ok(env) => {
                if let Ok(p) = serde_json::from_slice::<Proprioception>(&env.payload) {
                    seen.push(p.event.clone());
                    if p.event == target {
                        if matches!(target, "unloaded" | "unload_leaked_resources") {
                            assert_eq!(
                                env.header.from,
                                Address::Creature(aether::KERNEL_ID),
                                "terminal lifecycle facts must come from the live kernel handle, \
                                 never the stale creature handle"
                            );
                        }
                        return (true, seen);
                    }
                }
            }
            Err(_) => continue, // keep polling until deadline
        }
    }
    (false, seen)
}

#[test]
fn d1_welbehaved_thread_creature_unloads_cleanly_with_no_leak_event() {
    let _serial = serial_lock().lock().unwrap_or_else(|p| p.into_inner());
    let k = kernel();
    let so = native_cdylib("welbehaved_thread_daemon");

    let (sub, _b, rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), sub);

    let id = k.load(daemon_manifest("welbehaved-thread-daemon"), Artifact::Path(so)).unwrap();
    let (_loaded_seen, _) = drain_proprio_for(&rx, "loaded", Duration::from_secs(2));

    // Exercise it so the worker has been running a beat.
    let (probe, bus, prx) = k.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(Address::Creature(id), b"abc".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .unwrap();
    let reply = prx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(reply.payload, b"cba", "welbehaved daemon serves correctly while its worker runs");

    k.unload(id, Deadline::from_millis(1000))
        .expect("welbehaved unload must succeed within deadline");

    // The proprio bus must carry "unloaded" — NOT "unload_leaked_resources" — because the SDK
    // joined the managed worker before the kernel's tid snapshot fired.
    let (got_unloaded, seen) = drain_proprio_for(&rx, "unloaded", Duration::from_secs(2));
    assert!(got_unloaded, "expected proprio `unloaded`, saw {seen:?}");
    assert!(
        !seen.iter().any(|e| e == "unload_leaked_resources"),
        "welbehaved discipline must not trigger the leak path; events: {seen:?}"
    );

    k.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn d1_in_process_instance_ignores_unrelated_process_threads_at_unload() {
    struct Noop;
    impl aether::Creature for Noop {
        fn bind(&mut self, _ctx: aether::CreatureCtx) {}

        fn handle(&mut self, _env: aether::Envelope) -> aether::Outcome {
            aether::Outcome::none()
        }
    }

    let _serial = serial_lock().lock().unwrap_or_else(|p| p.into_inner());
    let k = kernel();
    let (sub, _bus, rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), sub);

    let id = k
        .load_instance(daemon_manifest("in-process-noop"), Box::new(Noop))
        .expect("in-process creature loads");
    let (_loaded_seen, _) = drain_proprio_for(&rx, "loaded", Duration::from_secs(2));

    // Start a persistent, unrelated process thread only after the creature has bound. The old
    // process-global guard classified this TID as belonging to the in-process creature and took
    // the native-library leak path even though there was no library to protect.
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let (ready_tx, ready_rx) = mpsc::sync_channel::<()>(0);
    let unrelated = std::thread::spawn(move || {
        ready_tx.send(()).expect("announce unrelated helper thread");
        let _ = stop_rx.recv();
    });
    ready_rx.recv().expect("unrelated helper thread is live");

    k.unload(id, Deadline::from_millis(500))
        .expect("unrelated process threads cannot impede an in-process unload");
    let (got_unloaded, seen) = drain_proprio_for(&rx, "unloaded", Duration::from_secs(2));

    stop_tx.send(()).expect("stop unrelated helper thread");
    unrelated.join().expect("join unrelated helper thread");

    assert!(got_unloaded, "in-process unload must take the normal drop path; events: {seen:?}");
    assert!(
        !seen.iter().any(|event| event == "unload_leaked_resources"),
        "in-process resources must never enter the native-library leak path; events: {seen:?}"
    );
    k.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn d2_runaway_thread_creature_triggers_the_kernel_leak_path_not_uaf() {
    let _serial = serial_lock().lock().unwrap_or_else(|p| p.into_inner());
    let stage_paths = Arc::new(Mutex::new(HashMap::new()));
    let k = kernel_with_native(Arc::new(CaptureNativeStages { paths: stage_paths.clone() }));
    let runaway_so = native_cdylib("runaway_thread_daemon");
    let echo_so = native_cdylib("echo_daemon");

    let (sub, _b, rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), sub);

    let runaway_id =
        k.load(daemon_manifest("runaway-thread-daemon"), Artifact::Path(runaway_so)).unwrap();
    let echo_id = k.load(daemon_manifest("echo-daemon"), Artifact::Path(echo_so)).unwrap();
    let runaway_stage = stage_paths
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .get("runaway-thread-daemon")
        .cloned()
        .expect("capture runaway's exact staged capability");
    assert!(runaway_stage.exists(), "runaway stage is retained while loaded");

    // Sanity: runaway is reachable before the misbehavior is detected.
    let (probe, bus, prx) = k.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(Address::Creature(runaway_id), b"ping".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .unwrap();
    let reply = prx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(reply.payload, b"gnip");

    // Unload the runaway. The SDK joins zero threads (the runaway is a raw `std::thread::spawn`).
    // The kernel's tid snapshot AFTER shutdown sees the leaked tid → it leaks resources rather
    // than `dlclose`, and publishes `unload_leaked_resources`.
    let _ = k.unload(runaway_id, Deadline::from_millis(500));

    let (got_leak_event, seen) =
        drain_proprio_for(&rx, "unload_leaked_resources", Duration::from_secs(3));
    assert!(
        got_leak_event,
        "kernel must publish `unload_leaked_resources` when a runaway tid is detected; events: {seen:?}"
    );
    assert!(
        runaway_stage.exists(),
        "the leak path must retain the exact native stage with the still-mapped library"
    );

    // The runaway is off the bus (router deregistered) — routing returns NoSuchModule, not UB.
    let err = bus.send(Dispatch::to(Address::Creature(runaway_id), b"x".to_vec())).unwrap_err();
    assert!(
        matches!(err, aether::RouteError::NoSuchModule(_)),
        "post-leak-unload routing must be NoSuchModule, got {err:?}"
    );

    // The healthy echo-daemon beside it is unaffected — the fabric contained the misbehavior.
    bus.send(
        Dispatch::to(Address::Creature(echo_id), b"abc".to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .unwrap();
    let healthy = prx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        healthy.payload, b"cba",
        "the healthy creature beside the misbehaver must keep serving (fabric-integrity floor)"
    );

    // NOTE: the runaway thread is *still running* after this test. Its `.so` is permanently
    // mapped (bounded leak). It will die when the test process exits. This is the intentional
    // tradeoff: bounded leak per misbehavior, no UAF, ever.
    k.shutdown_all(Deadline::from_millis(500));
}

#[test]
fn d3_welbehaved_creature_survives_repeated_load_unload_cycles_with_no_leak_path() {
    // Stability test: the discipline holds across many cycles. If `Threads::join_all` were buggy
    // (e.g. failed to drain on the 2nd call) or the SDK's thread-local set/clear leaked across
    // cycles, this test would either hang in unload or see a `unload_leaked_resources` event from
    // a later cycle picking up a tid that should have been joined.
    let _serial = serial_lock().lock().unwrap_or_else(|p| p.into_inner());
    let k = kernel();
    let so = native_cdylib("welbehaved_thread_daemon");

    let (sub, _b, rx) = k.open_endpoint(Capabilities::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), sub);

    const CYCLES: usize = 50;
    for _ in 0..CYCLES {
        let id = k
            .load(daemon_manifest("welbehaved-thread-daemon"), Artifact::Path(so.clone()))
            .expect("welbehaved load (cycle)");
        k.unload(id, Deadline::from_millis(1000)).expect("welbehaved unload (cycle)");
    }

    // Drain all proprio events: must contain `loaded`/`unloaded` pairs but NEVER
    // `unload_leaked_resources`. (We don't assert pair counts strictly — the proprio Topic also
    // fan-outs from the kernel's own bookkeeping creatures, and the m0 subscription order is
    // best-effort. The negative assertion is what matters.)
    let mut seen_leak = false;
    let deadline = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(env) => {
                if let Ok(p) = serde_json::from_slice::<Proprioception>(&env.payload) {
                    if p.event == "unload_leaked_resources" {
                        seen_leak = true;
                        break;
                    }
                }
            }
            Err(_) => continue,
        }
    }
    assert!(
        !seen_leak,
        "the welbehaved discipline must not trigger the kernel leak path across {CYCLES} cycles"
    );

    k.shutdown_all(Deadline::from_millis(500));
}
