//! Positive specimen — a native daemon that spawns a background thread *correctly*: via the SDK's
//! managed [`forge::spawn`] (so the SDK's `Threads` registry collects the `JoinHandle`) AND
//! flipping a stop flag in `shutdown` (so the thread actually returns). The SDK's `join_all` reaps
//! it before the kernel `dlclose`s the library: no leaked tid, the thread-count guard sees a clean
//! delta, the `.so` unloads. This is the unload discipline working end-to-end.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use forge::prelude::*;

#[derive(Default)]
pub struct WelbehavedThreadDaemon {
    stop: Arc<AtomicBool>,
}

impl Creature for WelbehavedThreadDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {
        let stop = self.stop.clone();
        // **The discipline**: `forge::spawn` registers the JoinHandle into the active
        // `CreatureBox.threads`; the SDK joins it in `shutdown` BEFORE returning to the host.
        forge::spawn("welbehaved-worker", move || {
            while !stop.load(Ordering::Relaxed) {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        });
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }

    fn shutdown(&mut self, _deadline: Deadline) {
        // Signal the worker. The SDK's `join_all` (running AFTER this returns) will then complete
        // immediately — the worker sees `stop == true` on its next poll and returns.
        self.stop.store(true, Ordering::Relaxed);
    }
}

forge::declare_creature!(WelbehavedThreadDaemon);
