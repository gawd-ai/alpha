//! Live agent-to-agent dialogue proof on the SEER `dialogue` topic.
//!
//! The unit tests in `dialogue-initiator` / `dialogue-responder` drive `handle()` directly. This test
//! proves the *seam*: both creatures loaded on a real [`Kernel`], and a single trigger drives the full
//! conversation **through the bus** — initiator → responder (the turn) → initiator (the reply) → the
//! original requester (the relayed result). It is the in-process dress rehearsal for the v0.5.0
//! headline: swap the reference echo responder for an LLM-backed agent and point the initiator's peer
//! at `Omega{other_realm, …}` and the same path carries two AIs conversing across the mesh.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Bus, CreatureId, Deadline, Dispatch};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use dialogue_initiator::{DialogueInitiator, RESULT_SCHEMA, START_SCHEMA};
use dialogue_responder::DialogueResponder;
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

fn make_kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(aether::StubSigner::new("dialogue-seam-test")),
        Arc::new(aether::StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn load(kernel: &Arc<Kernel>, name: &str, creature: Box<dyn aether::Creature>) -> CreatureId {
    let manifest = Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1");
    kernel.load_instance(manifest, creature).expect("creature admits under dev policy")
}

#[test]
fn initiator_and_responder_hold_a_dialogue_through_the_bus() {
    let kernel = make_kernel();

    // The peer (responder) is loaded first so the initiator can name it as its conversation partner.
    let responder_id = load(&kernel, "dialogue-responder", Box::new(DialogueResponder::echo()));
    let initiator_id = load(
        &kernel,
        "dialogue-initiator",
        Box::new(DialogueInitiator::new(Address::Creature(responder_id)).with_corr_seed(500_000)),
    );

    let (_probe, bus, rx) = kernel.open_endpoint(Capabilities::default());

    // Open the conversation: a START trigger to the initiator, with the probe as reply_to.
    let corr = 1;
    bus.emit(
        Dispatch::to(Address::Creature(initiator_id), b"hello peer".to_vec())
            .with_schema(START_SCHEMA)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(corr),
    )
    .expect("probe opens the dialogue");

    // The whole conversation runs through the kernel drain: initiator → responder (turn) → initiator
    // (reply) → probe (relayed result). Wait for the RESULT on the original corr.
    let stop = std::time::Instant::now() + Duration::from_millis(1000);
    let mut result = None;
    while std::time::Instant::now() < stop {
        let remaining = stop.saturating_duration_since(std::time::Instant::now());
        if let Ok(env) = rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            if env.header.schema == RESULT_SCHEMA {
                assert_eq!(
                    env.header.corr,
                    Some(corr),
                    "result rides the original requester's corr"
                );
                result = Some(env.payload);
                break;
            }
        }
    }
    assert_eq!(
        result.as_deref(),
        Some(b"echo: hello peer".as_slice()),
        "the responder's reply to the initiator's turn is relayed back to the original requester"
    );

    kernel.shutdown_all(Deadline::default());
}
