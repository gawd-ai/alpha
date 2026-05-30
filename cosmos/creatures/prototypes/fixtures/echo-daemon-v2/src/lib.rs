//! Reload-loop counter-specimen — `echo-daemon` v2.
//!
//! Behavior: reverse the payload AND append `0x02` (the version sentinel). The reload-loop test
//! alternates between v1 and v2, asserting per cycle that the reply matches whichever version was
//! just loaded. That assertion is the proof that `Engine::load` actually re-`mmap`s the new `.so`
//! every cycle — a silent cache would keep returning v1's output regardless of which path was
//! handed in. The freshness test is what makes the RSS-stable claim meaningful.

use forge::prelude::*;

#[derive(Default)]
pub struct EchoDaemonV2;

impl Creature for EchoDaemonV2 {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let mut out: Vec<u8> = env.payload.iter().copied().rev().collect();
        out.push(0x02); // version sentinel — distinguishes v2 from v1's plain reversal
        Outcome::reply(&env, out)
    }
}

forge::declare_creature!(EchoDaemonV2);
