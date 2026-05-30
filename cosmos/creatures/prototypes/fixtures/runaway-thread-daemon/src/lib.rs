//! A misbehaving specimen — a native daemon that spawns a runaway thread (raw `std::thread::spawn`,
//! NOT the SDK's managed [`forge::spawn`]). The thread never returns, so the SDK can't join it,
//! so the kernel's pre-bind / post-shutdown thread-count guard finds the leaked tid and refuses to
//! `dlclose` this `.so`: bounded leak (the library stays mapped), no UAF (the runaway thread runs
//! into live mapped code).
//!
//! This is the negative-space specimen for the **native** tier: it deliberately violates
//! the SDK discipline so we can prove the substrate contains the violation — *the discipline is the
//! happy path; the kernel guard is the floor.*

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use forge::prelude::*;

#[derive(Default)]
pub struct RunawayThreadDaemon {
    /// A flag the runaway thread checks; we never flip it, so the thread never exits — that's the
    /// misbehavior under test. (Carrying the flag at all is a hint: real creatures should both flip
    /// it in `shutdown` AND use [`forge::spawn`] so the SDK joins them.)
    stop: Arc<AtomicBool>,
}

impl Creature for RunawayThreadDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {
        // **The misbehavior**: raw `std::thread::spawn`. Bypasses [`forge::spawn`] entirely; the
        // SDK's `Threads` registry never learns about this thread; the SDK's `join_all` at shutdown
        // joins zero threads; the thread keeps running into the `.so`'s mapped code after the
        // creature's `shutdown` completes. The kernel's thread-count guard is what catches it.
        let stop = self.stop.clone();
        if let Err(e) =
            std::thread::Builder::new().name("runaway-misbehavior".into()).spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    // Touch `.so`-resident code in a small busy-ish loop. After kernel-leak of
                    // resources this is exactly the "execute against still-mapped library" path:
                    // bounded leak rather than UAF.
                    std::thread::sleep(std::time::Duration::from_millis(50));
                }
            })
        {
            eprintln!("runaway-thread-daemon: failed to spawn misbehavior thread: {e}");
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        // Pleasantly echo-like in the happy path so a sender can confirm the creature is reachable
        // before being torn down.
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }
    // No custom `shutdown`: we deliberately do NOT signal `stop`, so the runaway thread persists.
}

forge::declare_creature!(RunawayThreadDaemon);
