//! Control on the bus. Boots a real node (three engines + the dev policy + the
//! substrate's own organs + the [`ControlCore`] translator) and drives it **purely by sending
//! `Verb` envelopes to `Role::CONTROL`** and reading `VerbResult` envelopes back — no in-process
//! `run_verb` call. This is the dogfooding claim: a control command is just bus traffic.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aether::{
    Address, Creature, CreatureCtx, Dispatch, Envelope, Outcome, Role, StubSigner, StubVerifier,
};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

use omni::{
    boot_control, boot_organs_with_monitor, recv_corr, AiControl, Verb, VerbResult,
    CONTROL_RESULT_SCHEMA, CONTROL_SCHEMA, CONTROL_WORKER_QUEUE_CAP, MAX_AI_STATUS_TEXT_CHARS,
    MAX_CONTROL_RESULT_BYTES, MAX_CONTROL_ROLE_NAME_BYTES, MAX_CONTROL_VERB_BYTES,
    MAX_PRESENTED_PAYLOAD_BYTES,
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
    control_payload(probe_id, &bus, &rx, corr, payload)
}

fn control_payload(
    probe_id: aether::CreatureId,
    bus: &aether::BusHandle,
    rx: &aether::InboxReceiver,
    corr: u64,
    payload: Vec<u8>,
) -> VerbResult {
    bus.send(
        Dispatch::to(Address::Role(Role::new(Role::CONTROL)), payload)
            .with_schema(CONTROL_SCHEMA)
            .with_reply_to(Address::Creature(probe_id))
            .with_corr(corr),
    )
    .expect("control envelope routes to Role::CONTROL");
    let reply = recv_corr(rx, corr, Duration::from_secs(20)).expect("a VerbResult reply");
    serde_json::from_slice::<VerbResult>(&reply.payload).expect("payload is a VerbResult")
}

struct NoReply;

impl Creature for NoReply {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, _env: Envelope) -> Outcome {
        Outcome::none()
    }
}

struct LargeReply;

impl Creature for LargeReply {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        Outcome::reply(&env, vec![b'a'; MAX_PRESENTED_PAYLOAD_BYTES + 1])
    }
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

#[test]
fn ai_status_over_the_bus_is_sanitized_before_storage_and_display() {
    let (kernel, _ai) = node(false);
    let set = control(
        &kernel,
        70,
        &Verb::AiStatus {
            working: true,
            activity: "write\n\x1b[2J".into(),
            message: format!("{}\rhidden", "m".repeat(MAX_AI_STATUS_TEXT_CHARS + 16)),
        },
    );

    assert!(set.ok, "ai-status is not allow-AI gated: {:?}", set.json);
    assert!(set.human.starts_with("[ai] write[2J: "));
    assert!(set.human.chars().all(|c| !c.is_control()));

    let status = control(&kernel, 71, &Verb::Status);
    let ai_status = &status.json["ai_status"];
    assert_eq!(ai_status["activity"].as_str(), Some("write[2J"));
    let msg = ai_status["message"].as_str().expect("message string");
    assert_eq!(msg.len(), MAX_AI_STATUS_TEXT_CHARS);
    assert!(msg.chars().all(|c| !c.is_control()));

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn bind_over_the_bus_rejects_malformed_role_names_before_retention() {
    let (kernel, _ai) = node(true);

    let valid = control(&kernel, 72, &Verb::Bind { role: "custom-role_1".into(), id: 1 });
    assert!(valid.ok, "bounded token role binds: {:?}", valid.json);

    for (corr, role) in [(73, ""), (74, "bad role"), (75, "bad\nrole")] {
        let rejected = control(&kernel, corr, &Verb::Bind { role: role.into(), id: 1 });
        assert!(!rejected.ok, "malformed role should be rejected: {role:?}");
        assert_eq!(rejected.json.get("error").and_then(|v| v.as_str()), Some("invalid-role-name"));
    }

    let oversized_role = "r".repeat(MAX_CONTROL_ROLE_NAME_BYTES + 1);
    let rejected = control(&kernel, 76, &Verb::Bind { role: oversized_role.clone(), id: 1 });
    assert!(!rejected.ok, "oversized role should be rejected");
    assert_eq!(rejected.json.get("error").and_then(|v| v.as_str()), Some("invalid-role-name"));
    assert_eq!(
        rejected.json.get("limit").and_then(|v| v.as_u64()),
        Some(MAX_CONTROL_ROLE_NAME_BYTES as u64)
    );

    let status = control(&kernel, 77, &Verb::Status);
    let roles = status.json["roles"].as_array().expect("roles array");
    assert!(roles.iter().any(|r| r["role"] == "custom-role_1"));
    assert!(
        !roles.iter().any(|r| r["role"].as_str() == Some(oversized_role.as_str())),
        "rejected oversized role was not retained"
    );

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn oversized_control_verb_payload_is_rejected_before_json_parse() {
    let (kernel, _ai) = node(true);
    let (probe_id, bus, rx) = kernel.open_endpoint(Capabilities::default());
    let payload = vec![b'{'; MAX_CONTROL_VERB_BYTES + 1];

    let res = control_payload(probe_id, &bus, &rx, 77, payload);
    assert!(!res.ok, "oversized control verb is refused");
    assert_eq!(res.json.get("error").and_then(|v| v.as_str()), Some("control-verb-too-large"));
    assert_eq!(res.json.get("limit").and_then(|v| v.as_u64()), Some(MAX_CONTROL_VERB_BYTES as u64));

    let read = control(&kernel, 78, &Verb::Status);
    assert!(read.ok, "node still answers after an oversized control verb");

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn oversized_control_result_is_replaced_before_emission() {
    let (kernel, _ai) = node(true);
    for i in 0..24u64 {
        let role = format!("{}-{i}", "role".repeat(16 * 1024));
        kernel.bind_role(Role::new(role), aether::CreatureId(1));
    }

    let status = control(&kernel, 120, &Verb::Status);
    assert!(!status.ok, "status result should be replaced with a bounded error before emission");
    assert_eq!(status.json.get("error").and_then(|v| v.as_str()), Some("control-result-too-large"));
    assert_eq!(
        status.json.get("limit").and_then(|v| v.as_u64()),
        Some(MAX_CONTROL_RESULT_BYTES as u64)
    );
    assert!(
        status.json.get("bytes").and_then(|v| v.as_u64()).unwrap()
            > MAX_CONTROL_RESULT_BYTES as u64
    );

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn send_reply_payload_is_previewed_when_too_large_for_control_surface() {
    let (kernel, _ai) = node(true);
    let large = kernel
        .load_instance(
            Manifest::new("large-reply", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(LargeReply),
        )
        .expect("large-reply creature loads");

    let res = control(&kernel, 88, &Verb::Send { id: large.0, text: "small".into(), node: None });
    assert!(res.ok, "send ok: {:?}", res.json);
    let reply = res.json.get("reply").and_then(|v| v.as_str()).expect("reply preview");
    assert_eq!(reply.len(), MAX_PRESENTED_PAYLOAD_BYTES);
    assert_eq!(
        res.json.get("reply_bytes").and_then(|v| v.as_u64()),
        Some((MAX_PRESENTED_PAYLOAD_BYTES + 1) as u64)
    );
    assert_eq!(res.json.get("reply_truncated").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(
        res.json.get("reply_limit").and_then(|v| v.as_u64()),
        Some(MAX_PRESENTED_PAYLOAD_BYTES as u64)
    );
    assert!(res.human.contains("truncated"), "human output names truncation: {}", res.human);

    kernel.shutdown_all(aether::Deadline::default());
}

#[test]
fn control_worker_queue_is_bounded_when_a_job_blocks() {
    let (kernel, _ai) = node(true);
    let blackhole = kernel
        .load_instance(
            Manifest::new("no-reply", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(NoReply),
        )
        .expect("no-reply creature loads");

    let (probe_id, bus, rx) = kernel.open_endpoint(Capabilities::default());
    let payload =
        serde_json::to_vec(&Verb::Send { id: blackhole.0, text: "blocked".into(), node: None })
            .unwrap();
    let first_corr = 1_000;
    for offset in 0..(CONTROL_WORKER_QUEUE_CAP as u64 + 8) {
        bus.send(
            Dispatch::to(Address::Role(Role::new(Role::CONTROL)), payload.clone())
                .with_schema(CONTROL_SCHEMA)
                .with_reply_to(Address::Creature(probe_id))
                .with_corr(first_corr + offset),
        )
        .expect("control envelope routes to Role::CONTROL");
    }

    let deadline = Instant::now() + Duration::from_secs(1);
    let mut saw_busy = false;
    while Instant::now() < deadline {
        let Ok(env) = rx.recv_timeout(Duration::from_millis(50)) else { continue };
        if env.header.schema != CONTROL_RESULT_SCHEMA {
            continue;
        }
        let res: VerbResult = serde_json::from_slice(&env.payload).expect("control result");
        if res.json.get("error").and_then(|v| v.as_str()) == Some("control-worker-busy") {
            saw_busy = true;
            assert_eq!(
                res.json.get("queue_cap").and_then(|v| v.as_u64()),
                Some(CONTROL_WORKER_QUEUE_CAP as u64)
            );
            break;
        }
    }
    assert!(saw_busy, "a blocked worker sheds excess jobs instead of growing the queue");

    kernel.shutdown_all(aether::Deadline::from_millis(3_000));
}
