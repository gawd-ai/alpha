//! Reload criterion: **≥1000× `load → route → unload → reload` of a *new version*, RSS-stable.**
//!
//! The loop alternates between two distinct native `.so`s — `echo-daemon` (v1, plain reversal) and
//! `echo-daemon-v2` (reversal + `0x02` sentinel) — so each cycle's reply distinguishes which
//! library is actually mapped. A silent cache that returned v1 forever would fail the per-cycle
//! freshness assertion, so the freshness + RSS-stable claims compose: the loader IS re-`mmap`-ing
//! every cycle, AND it's not leaking the previous library's memory.
//!
//! **Why this matters:** the kernel-driven deregister → join → `dlclose`-last unload
//! is only sound if the loop actually executes the full cycle in real RAM. The RSS-stable bar is
//! the empirical bound on the safe-unload story; ASan (the memcheck harness) provides the
//! semantic bound on UAF.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Deadline, Dispatch};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

mod support;
use support::native_cdylib;

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("test-node")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn daemon_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

/// `VmRSS` from `/proc/self/status` (kB). Linux-only — the RSS-stable assertion needs the
/// substrate's home platform; other OSes get the per-cycle freshness check but skip the RSS bound.
fn vm_rss_kb() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let s = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in s.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                return rest.split_whitespace().next()?.parse().ok();
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[test]
fn a_reload_loop_1000x_alternating_versions_freshness_and_rss_stability() {
    let v1_so = native_cdylib("echo_daemon");
    let v2_so = native_cdylib("echo_daemon_v2");

    let k = kernel();
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());

    // The artifacts are owned once — `Clone` (F14) lets the loop reuse them each cycle without
    // re-allocating PathBuf or copying bytes.
    let v1 = Artifact::Path(v1_so);
    let v2 = Artifact::Path(v2_so);

    const CYCLES: usize = 1000;
    const WARMUP: usize = 100;
    // Per-cycle RSS growth budget: dlopen's mapping is small (~50-200 kB) and our pad is generous.
    // 50 kB/cycle * 900 post-warmup cycles = 45 MB — well under absolute_floor.
    const PER_CYCLE_BUDGET_KB: u64 = 50;
    const ABSOLUTE_FLOOR_KB: u64 = 60 * 1024; // 60 MB hard ceiling

    let mut rss_at_warmup: Option<u64> = None;

    for cycle in 0..CYCLES {
        let (manifest, artifact, expected_suffix): (Manifest, &Artifact, &[u8]) = if cycle % 2 == 0
        {
            (daemon_manifest("echo-daemon"), &v1, b"") // v1: plain reversal
        } else {
            (daemon_manifest("echo-daemon-v2"), &v2, b"\x02") // v2: reversal + sentinel
        };
        let id = k
            .load(manifest, artifact.clone())
            .unwrap_or_else(|e| panic!("cycle {cycle} load failed: {e}"));
        // Per-cycle freshness probe — the reply MUST end in the version's expected suffix. A
        // silent cache returning v1 in a v2 cycle would fail here.
        bus.send(
            Dispatch::to(Address::Creature(id), b"abc".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .unwrap_or_else(|e| panic!("cycle {cycle} send failed: {e:?}"));
        let reply = rx
            .recv_timeout(Duration::from_secs(2))
            .unwrap_or_else(|e| panic!("cycle {cycle} no reply: {e:?}"));
        // v1 reply: b"cba"; v2 reply: b"cba\x02". Both end with the version suffix.
        assert!(
            reply.payload.ends_with(expected_suffix) && reply.payload.starts_with(b"cba"),
            "cycle {cycle}: expected payload starting with cba, ending with {expected_suffix:?}, got {:?}",
            reply.payload
        );
        k.unload(id, Deadline::from_millis(500))
            .unwrap_or_else(|e| panic!("cycle {cycle} unload failed: {e}"));

        // This is a correctness proof, not a throughput benchmark. Keep the public default suite
        // courteous so the 1000-cycle dlopen/dlclose loop does not monopolize a core.
        std::thread::sleep(Duration::from_millis(1));

        if cycle == WARMUP {
            rss_at_warmup = vm_rss_kb();
        }
    }

    // The kernel's `loaded` map must be empty — every cycle's unload reaped its entry.
    assert_eq!(
        k.loaded_count(),
        0,
        "kernel.loaded must be empty after {CYCLES} clean unload cycles (F8 ghost-entry leak guard)"
    );

    // RSS-stable assertion (Linux). On non-Linux this no-ops with a console hint — the freshness
    // check still ran. **Under ASan the assertion is intentionally skipped** because ASan's shadow
    // memory + per-allocation tracking inflates the per-cycle RSS by ~100 kB regardless of the
    // creature's behavior; ASan's oracle is its own SUMMARY-on-error mechanism (a UAF crashes the
    // test loudly), not the RSS budget. The harness sets `GAWD_SKIP_RSS_CHECK=1` when running
    // under sanitizer instrumentation.
    let skip_rss = std::env::var_os("GAWD_SKIP_RSS_CHECK").is_some();
    match (rss_at_warmup, vm_rss_kb()) {
        (Some(rss_warm), Some(rss_end)) => {
            let growth_kb = rss_end.saturating_sub(rss_warm);
            let post_warmup = (CYCLES - WARMUP) as u64;
            let budget_kb = (PER_CYCLE_BUDGET_KB * post_warmup).min(ABSOLUTE_FLOOR_KB);
            if skip_rss {
                eprintln!(
                    "[M1 reload-loop] {CYCLES} cycles; warmup RSS {rss_warm} kB → end {rss_end} kB \
                     (growth {growth_kb} kB) — RSS check SKIPPED (sanitizer mode; \
                     ASan's own oracle is authoritative for UAF/invalid-free)"
                );
            } else {
                assert!(
                    growth_kb <= budget_kb,
                    "RSS growth {growth_kb} kB over {post_warmup} post-warmup cycles exceeds budget {budget_kb} kB \
                     (warmup={rss_warm} kB, end={rss_end} kB). A real leak is sub-linear-free; this is the M1 floor."
                );
                eprintln!(
                    "[M1 reload-loop] {CYCLES} cycles; warmup RSS {rss_warm} kB → end {rss_end} kB (growth {growth_kb} kB, budget {budget_kb} kB)"
                );
            }
        }
        _ => {
            eprintln!("[M1 reload-loop] freshness verified over {CYCLES} cycles; RSS sampling unavailable on this platform");
        }
    }

    k.shutdown_all(Deadline::from_millis(500));
}
