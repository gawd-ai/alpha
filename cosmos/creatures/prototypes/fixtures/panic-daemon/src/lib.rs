//! Hardening specimen — a native daemon that panics on demand to prove the FFI seam contains it.
//!
//! Behavior:
//! - On a payload starting with `boom`: **panics**. The SDK's `catch_unwind` (inside the
//!   `declare_creature!`-generated glue) catches it, marks the creature poisoned, and returns
//!   `aether::ffi::RC_PANIC` across the `extern "C"` boundary — never unwinding
//!   across the C ABI (which would be UB). The host's `NativeInstance::handle` observes the rc and
//!   re-panics on the host side so the kernel's existing `run_drain` `catch_unwind` catches it and
//!   pulls the creature off the bus.
//! - Otherwise: behaves like `echo-daemon`, reversing the payload.

use forge::prelude::*;

#[derive(Default)]
pub struct PanicDaemon;

impl Creature for PanicDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.payload.starts_with(b"boom") {
            panic!(
                "panic-daemon detonating on demand \
                 (this panic is caught at the FFI seam — expected when this test runs)"
            );
        }
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }
}

forge::declare_creature!(PanicDaemon);
