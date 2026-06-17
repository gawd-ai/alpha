//! ADR-0041 clustered-boot posture. The transport publishes an `OriginVerdict` for every peer frame
//! but does not enforce it; enforcement is an injected `Role::IMMUNE_RESPONSE`. A clustered node with
//! none bound admits forged-signature frames, so the composition roots warn loudly at boot. This pins
//! `omni::warn_if_no_immune_response`: it warns (returns `true`) when no immune-response is bound, and
//! is a no-op (returns `false`) once one is — the substrate never silently enforces.

use std::sync::Arc;

use aether::{CreatureId, Role, StubSigner, StubVerifier};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;

use omni::warn_if_no_immune_response;

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    )
}

#[test]
fn warns_when_no_immune_response_is_bound_and_is_silent_once_one_is() {
    let kernel = kernel();

    // A clustered node with no immune-response bound: the posture check warns.
    assert!(
        warn_if_no_immune_response(&kernel),
        "no Role::IMMUNE_RESPONSE bound → the clustered-boot posture check must warn"
    );

    // Bind an immune-response (any creature on the role); the check is now a no-op.
    kernel.bind_role(Role::new(Role::IMMUNE_RESPONSE), CreatureId(99));
    assert!(
        !warn_if_no_immune_response(&kernel),
        "with an immune-response bound, the check must not warn"
    );
}
