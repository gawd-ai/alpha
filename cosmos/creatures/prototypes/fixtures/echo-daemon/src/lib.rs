//! Walking-skeleton creature: a native daemon that reverses its envelope payload.
//!
//! This is the smallest possible creature against the SDK — the `declare_creature!` macro hides the
//! entire `extern "C"` POD-only FFI seam, leaving the author with a plain Rust `Creature`.

use forge::prelude::*;

#[derive(Default)]
pub struct EchoDaemon;

impl Creature for EchoDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }
}

forge::declare_creature!(EchoDaemon);
