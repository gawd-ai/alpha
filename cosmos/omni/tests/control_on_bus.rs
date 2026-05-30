//! Control on the bus. Boots a real node (three engines + the dev policy + the
//! substrate's own organs + the [`ControlCore`] translator) and drives it **purely by sending
//! `Verb` envelopes to `Role::CONTROL`** and reading `VerbResult` envelopes back — no in-process
//! `run_verb` call. This is the dogfooding claim: a control command is just bus traffic.

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Dispatch, Role, StubSigner, StubVerifier};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

use omni::{
    boot_control, boot_organs_with_monitor, recv_corr, AiControl, Verb, VerbResult, CONTROL_SCHEMA,
};

/// Boot a live node with control bound on `Role::CONTROL`. Returns the kernel + the shared gate.
fn node(allow_ai: bool) -> (Arc<Kernel>, Arc<AiControl>) {
    let kernel = Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        256,
    );
    // Self-host the organs (AUTHORING/BUILD/REGISTRY) without the stdout monitor; bind control.
    let critter_builder = boot_organs_with_monitor(&kernel, false).expect("organs boot");
    let ai = Arc::new(AiControl::new(allow_ai));
    boot_control(&kernel, &ai, Some(critter_builder), None).expect("control boots");
    (kernel, ai)
}

/// Drive one verb over the bus: ship it to `Role::CONTROL` and decode the `VerbResult` reply.
fn control(kernel: &Kernel, corr: u64, verb: &Verb) -> VerbResult {
    let (probe_id, bus, rx) = kernel.open_endpoint(Capabilities::default());
    let payload = serde_json::to_vec(verb).unwrap();
    bus.send(
        Dispatch::to(Address::Role(Role::new(Role::CONTROL)), payload)
            .with_schema(CONTROL_SCHEMA)
            .with_reply_to(Address::Creature(probe_id))
            .with_corr(corr),
    )
    .expect("control envelope routes to Role::CONTROL");
    let reply = recv_corr(&rx, corr, Duration::from_secs(20)).expect("a VerbResult reply");
    serde_json::from_slice::<VerbResult>(&reply.payload).expect("payload is a VerbResult")
}

#[test]
fn reads_run_inline_and_orchestration_runs_on_the_worker() {
    let (kernel, _ai) = node(true);

    // (1) `status` — a probe-free read answered inline on the drain thread.
    let res = control(&kernel, 1, &Verb::Status);
    assert!(res.ok, "status ok");
    assert_eq!(res.json.get("ai_allowed").and_then(|v| v.as_bool()), Some(true));

    // (2) Load an echo critter directly, then drive `list` + `send` over the bus.
    let echo = kernel
        .load(
            Manifest::new("echo-critter", "0.1.0", Backend::Critter, "gawd_critter_v1"),
            Artifact::Bytes(b"fn handle(env) { env.payload }".to_vec()),
        )
        .expect("echo critter loads");

    let res = control(&kernel, 2, &Verb::List);
    assert!(res.ok, "list ok");
    let names: Vec<&str> = res.json["creatures"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c.get("name").and_then(|n| n.as_str()))
        .collect();
    assert!(names.contains(&"echo-critter"), "roster lists the echo critter: {names:?}");

    // (3) `send` — an orchestration verb run on the worker (request/reply to the target creature),
    // its reply emitted back to us as a `control_result` envelope correlated by corr.
    let res = control(&kernel, 3, &Verb::Send { id: echo.0, text: "hello-bus".into(), node: None });
    assert!(res.ok, "send ok: {:?}", res.json);
    assert_eq!(res.json.get("reply").and_then(|v| v.as_str()), Some("hello-bus"));

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn sequential_worker_jobs_each_get_their_own_reply() {
    // Two orchestration (worker) verbs in a row must each get a distinct, correct reply — the regress
    // guard for per-job corr/probe reuse on the single ControlCore worker.
    let (kernel, _ai) = node(true);
    let echo = kernel
        .load(
            Manifest::new("echo-critter", "0.1.0", Backend::Critter, "gawd_critter_v1"),
            Artifact::Bytes(b"fn handle(env) { env.payload }".to_vec()),
        )
        .expect("echo critter loads");

    let a = control(&kernel, 10, &Verb::Send { id: echo.0, text: "one".into(), node: None });
    assert_eq!(
        a.json.get("reply").and_then(|v| v.as_str()),
        Some("one"),
        "first send: {:?}",
        a.json
    );
    let b = control(&kernel, 11, &Verb::Send { id: echo.0, text: "two".into(), node: None });
    assert_eq!(
        b.json.get("reply").and_then(|v| v.as_str()),
        Some("two"),
        "second send: {:?}",
        b.json
    );

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn the_allow_ai_gate_holds_over_the_bus() {
    // Gate OFF: a mutating verb (`send`) over the bus is refused with `ai-not-allowed`, while a
    // read (`status`) still answers — exactly the HTTP plane's posture.
    let (kernel, _ai) = node(false);
    let echo = kernel
        .load(
            Manifest::new("echo-critter", "0.1.0", Backend::Critter, "gawd_critter_v1"),
            Artifact::Bytes(b"fn handle(env) { env.payload }".to_vec()),
        )
        .expect("echo critter loads");

    let read = control(&kernel, 1, &Verb::Status);
    assert!(read.ok, "reads are never gated");

    let blocked = control(&kernel, 2, &Verb::Send { id: echo.0, text: "nope".into(), node: None });
    assert!(!blocked.ok, "a mutating verb is refused while allow-ai is off");
    assert!(blocked.is_gate_block(), "refusal is the allow-ai gate: {:?}", blocked.json);

    kernel.shutdown_all(aether::Deadline::default());
}
