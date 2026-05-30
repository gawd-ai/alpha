//! The critter (script) tier, end to end through the real kernel.
//!
//! The `anima` unit tests prove the Rhai engine in isolation; this suite proves the tier as a
//! first-class citizen of the *kernel*: a critter loads through the same `Kernel::load` path as a
//! daemon or a beast, runs on its own drain thread, and its budget signals flow through the same
//! PROPRIOCEPTION → injected-policy → unload chain. It also proves **Loop 1 for the tier** — an
//! agent authors a critter, `build-critter` signs it (no cargo), and the kernel loads + runs the
//! result — and guards the `abi_tag` contract between `build-critter` and `anima` against
//! drift (the authored manifest must be accepted by the real `ScriptEngine`).

use std::sync::Arc;
use std::time::Duration;

use aether::{Address, Creature, Deadline, Dispatch, StubSigner, StubVerifier, Topic};
use agent_templated::{AgentTemplated, AuthoringRequest};
use anima::{Artifact, NativeEngine, ScriptEngine, WasmEngine};
use build_cargo::{BuildReply, ManifestStub};
use build_critter::{BuildCritter, BuildCritterOp};
use policy_dev::DevPolicy;
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Ed25519KeyMaterial, Manifest};

const CRITTER_ABI_TAG: &str = "gawd_critter_v1";

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("critter-node")),
        Arc::new(StubVerifier),
        Arc::new(DevPolicy),
        128,
    )
}

fn critter_manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Critter, CRITTER_ABI_TAG)
}

/// Send `payload` to `target`, expecting it to reply within 2s; returns the reply bytes.
fn round_trip(k: &Arc<Kernel>, target: aether::CreatureId, payload: &[u8]) -> Vec<u8> {
    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    bus.send(
        Dispatch::to(Address::Creature(target), payload.to_vec())
            .with_reply_to(Address::Creature(probe)),
    )
    .expect("send to critter");
    rx.recv_timeout(Duration::from_secs(2)).expect("critter reply arrives").payload
}

/// The reference creature (`creatures/prototypes/critters/echo-critter/echo.rhai`) loads and echoes through the kernel.
#[test]
fn kernel_loads_and_runs_the_reference_echo_critter() {
    let k = kernel();
    let src = include_bytes!("../../creatures/prototypes/critters/echo-critter/echo.rhai");
    let id = k
        .load(critter_manifest("echo-critter"), Artifact::Bytes(src.to_vec()))
        .expect("the reference echo-critter loads through the real ScriptEngine");
    assert_eq!(round_trip(&k, id, b"hello critter"), b"hello critter");
    k.shutdown_all(Deadline::default());
}

/// **Loop 1 for the critter tier + the `abi_tag` drift guard.** The templated agent authors a Rhai
/// critter, `build-critter` validates + signs it (no cargo), and the kernel loads the *authored*
/// manifest through the real `ScriptEngine` and runs it — reversing its payload. If `build-critter`
/// and `anima` ever disagree on `gawd_critter_v1`, this `load` fails and the test trips.
#[test]
fn authored_critter_loads_through_the_real_engine_and_reverses() {
    // Author (agent-templated, pure fn — the bus-driven loop is exercised by walkthrough).
    let req =
        AuthoringRequest { request: "reverse a string as a critter".into(), prev_error: None };
    let resp = AgentTemplated::new().author(&req).expect("the critter template matches");
    assert_eq!(resp.template, "reverse-critter");

    // Build + sign (build-critter, pure fn).
    let key = Ed25519KeyMaterial::from_seed([9u8; 32]).expect("seed");
    let author = key.public_hex().to_string();
    let (manifest, artifact) =
        match BuildCritter::new(key, author).author(&resp.source, &resp.manifest_stub) {
            BuildReply::Built { manifest, artifact } => (manifest, artifact),
            BuildReply::Failed { kind, message, .. } => {
                panic!("authoring a critter failed ({kind:?}): {message}")
            }
        };
    assert_eq!(manifest.abi.backend, Backend::Critter);
    assert_eq!(manifest.abi.abi_tag, CRITTER_ABI_TAG);

    // Load through the real kernel (DRIFT GUARD: ScriptEngine must accept this manifest) and run.
    let k = kernel();
    let id = k
        .load(manifest, Artifact::Bytes(artifact))
        .expect("the authored critter must load through the real ScriptEngine (abi_tag agreement)");
    assert_eq!(round_trip(&k, id, b"abc"), b"cba", "the authored critter reverses its payload");
    k.shutdown_all(Deadline::default());
}

/// `build-critter` as a live bus creature: a `BuildCritterOp::Author` sent over the bus returns a
/// `BuildReply::Built` whose manifest + artifact load and run.
#[test]
fn build_critter_over_the_bus_produces_a_loadable_critter() {
    let k = kernel();
    let key = Ed25519KeyMaterial::from_seed([5u8; 32]).expect("seed");
    let author = key.public_hex().to_string();
    // Load build-critter as an in-process organ (a daemon-shaped boot manifest; DevPolicy admits).
    let build_id = k
        .load_instance(
            Manifest::new("build-critter", "0.1.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(BuildCritter::new(key, author)),
        )
        .expect("build-critter loads in-process");

    let (probe, bus, rx) = k.open_endpoint(Capabilities::default());
    let op = BuildCritterOp::Author {
        source: "fn handle(env) { env.payload }".to_string(),
        manifest_stub: ManifestStub {
            name: "bus-built-critter".to_string(),
            version: "0.1.0".to_string(),
            entrypoints: Vec::new(),
            capabilities: Default::default(),
            provides: Vec::new(),
        },
    };
    bus.send(
        Dispatch::to(Address::Creature(build_id), op.to_bytes())
            .with_reply_to(Address::Creature(probe)),
    )
    .expect("send the author op");
    let reply_env = rx.recv_timeout(Duration::from_secs(5)).expect("a BuildReply arrives");
    let (manifest, artifact) = match serde_json::from_slice::<BuildReply>(&reply_env.payload)
        .expect("a BuildReply")
    {
        BuildReply::Built { manifest, artifact } => (manifest, artifact),
        BuildReply::Failed { kind, message, .. } => panic!("build failed ({kind:?}): {message}"),
    };

    let id = k.load(manifest, Artifact::Bytes(artifact)).expect("bus-built critter loads");
    assert_eq!(round_trip(&k, id, b"xy"), b"xy");
    k.shutdown_all(Deadline::default());
}

/// A step-breaching critter drives the same apoptosis chain a beast does: the engine emits a
/// `Hard`/`Fuel` `BudgetSignal`, the kernel publishes a `BudgetSignalEvent` on PROPRIOCEPTION, and
/// an injected policy requests unload. Proves the kernel's budget path is tier-agnostic — the
/// critter's signal is honored exactly like wasm's, with no kernel change.
#[test]
fn step_breaching_critter_is_apoptosed_via_injected_policy() {
    use aether::{Bus, CreatureCtx};
    use policy_budget::BudgetApoptosis;

    let k = kernel();

    // A critter with a 1ms op budget that never returns → trips the cap on the first envelope.
    let mut greedy = critter_manifest("greedy-critter");
    greedy.capabilities.cpu_ms = 1;
    let greedy_id = k
        .load(greedy, Artifact::Bytes(b"fn handle(env) { let i = 0; loop { i += 1; } }".to_vec()))
        .expect("greedy critter loads");

    // The injected apoptosis policy, subscribed to PROPRIOCEPTION (mirrors m4_capability_sandbox).
    let (policy_id, policy_bus, policy_rx) = k.open_endpoint(Default::default());
    k.subscribe(Topic::new(Topic::PROPRIOCEPTION), policy_id);
    let policy_kernel_handle = k.clone();
    let _policy_thread = std::thread::Builder::new()
        .name("policy-budget-critter".into())
        .spawn(move || {
            let mut p = BudgetApoptosis::new();
            let bus: Arc<dyn Bus> = Arc::new(policy_bus.clone());
            p.bind(CreatureCtx {
                me: policy_id,
                bus,
                manifest: Manifest::new(
                    "policy-budget",
                    "0.1.0",
                    Backend::Daemon,
                    "gawd_creature_v1",
                ),
            });
            while let Ok(env) = policy_rx.recv() {
                for d in p.handle(env).dispatches {
                    let _ = policy_bus.send(d);
                }
            }
            drop(policy_kernel_handle);
        })
        .expect("spawn policy thread");

    // Poke the greedy critter once; its op-budget trap → proprio → policy → kernel unload.
    let (probe, probe_bus, _rx) = k.open_endpoint(Capabilities::default());
    probe_bus
        .send(
            Dispatch::to(Address::Creature(greedy_id), b"go".to_vec())
                .with_reply_to(Address::Creature(probe)),
        )
        .expect("poke the greedy critter");

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    let mut unloaded = false;
    while std::time::Instant::now() < deadline {
        if !k.is_loaded(greedy_id) {
            unloaded = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        unloaded,
        "critter op-budget breach → injected policy → kernel unload did not complete in 5s"
    );
    k.shutdown_all(Deadline::default());
}
