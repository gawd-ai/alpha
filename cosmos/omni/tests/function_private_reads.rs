//! Omni must preserve and verify the two-signature private-read proof, not merely deserialize the
//! snapshot/page nested inside it. A role provider that signs a well-formed response against the
//! wrong relay hash is authenticated transport traffic, but still not an answer to this request.

use std::sync::Arc;

use aether::{Creature, CreatureCtx, Dispatch, Envelope, Outcome, Role, StubSigner, StubVerifier};
use anima::ScriptEngine;
use gawdfn::{
    AbodeKeyBindingV1, AuthoritySigner, Ed25519SeedSigner, EventPageResponseV1, EventPageV1,
    EventQueryV1, HomeAuthorityV1, HomeId, JobControlKindV1, JobControlV1, JobEventKindV1,
    JobEventV1, JobHandleV1, JobMessageV1, JobStateV1, OperationalCapabilityV1,
    OperationalKeyGrantV1, SignedRecordV1, ValueRefV1, FUNCTION_HOME_ROLE, SCHEMA_HOME_V1,
    SCHEMA_JOB_V1,
};
use omni::{run_verb, AiControl, Verb, VerbCtx};
use sanctum::Kernel;
use sigil::{Backend, Capabilities, Manifest};

struct WrongHashHome {
    signer: Arc<Ed25519SeedSigner>,
    authority: HomeAuthorityV1,
}

struct WrongControlHashHome {
    signer: Arc<Ed25519SeedSigner>,
    authority: HomeAuthorityV1,
}

impl Creature for WrongControlHashHome {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let Ok(JobMessageV1::Control { request }) =
            serde_json::from_slice::<JobMessageV1>(&env.payload)
        else {
            return Outcome::none();
        };
        let event = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobEventV1 {
                handle: request.payload.handle.clone(),
                home_epoch: request.payload.expected_home_epoch,
                authority: self.authority.clone(),
                sequence: 1,
                occurred_at_unix_ms: None,
                state_after: JobStateV1::Running,
                cancel_requested: false,
                kind: JobEventKindV1::ControlRequested { request: request.clone(), attempt: None },
                foreign_receipt: None,
            },
            self.signer.as_ref(),
        )
        .unwrap();
        let reply = JobMessageV1::ControlAccepted {
            request_hash: format!("sha256:{}", "0".repeat(64)),
            event: Box::new(event),
        };
        Outcome::send(
            Dispatch::reply_to_env(&env, serde_json::to_vec(&reply).unwrap())
                .with_schema(SCHEMA_JOB_V1),
        )
    }
}

impl Creature for WrongHashHome {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA_JOB_V1 {
            return Outcome::none();
        }
        let Ok(JobMessageV1::Events { request }) =
            serde_json::from_slice::<JobMessageV1>(&env.payload)
        else {
            return Outcome::none();
        };
        let response = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventPageResponseV1 {
                // Valid hash syntax and a valid Home signature, but deliberately not the hash of
                // `request`, proving Omni checks application correlation after transport identity.
                request_hash: format!("sha256:{}", "0".repeat(64)),
                home_epoch: 1,
                authority: self.authority.clone(),
                page: EventPageV1 {
                    handle: request.payload.caller.payload.handle.clone(),
                    events: Vec::new(),
                    next_after_sequence: None,
                },
            },
            self.signer.as_ref(),
        )
        .unwrap();
        let reply = JobMessageV1::EventPage { response: Box::new(response) };
        Outcome::send(
            Dispatch::reply_to_env(&env, serde_json::to_vec(&reply).unwrap())
                .with_schema(SCHEMA_JOB_V1),
        )
    }
}

fn authority(
    root: &Ed25519SeedSigner,
    operational: &Ed25519SeedSigner,
) -> (HomeId, HomeAuthorityV1) {
    let home = HomeId::new(root.public_key());
    let abode = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        AbodeKeyBindingV1 {
            abode: home.clone(),
            root_public_key: root.public_key().into(),
            issued_at_unix_ms: None,
        },
        root,
    )
    .unwrap();
    let grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        OperationalKeyGrantV1 {
            home: home.clone(),
            epoch: 1,
            operational_public_key: operational.public_key().into(),
            valid_from_unix_ms: None,
            expires_at_unix_ms: None,
            capabilities: vec![OperationalCapabilityV1::JobHome],
            evidence: Vec::new(),
        },
        root,
    )
    .unwrap();
    (home, HomeAuthorityV1 { abode, operational: grant, prepared: None })
}

#[test]
fn omni_rejects_a_validly_signed_page_bound_to_the_wrong_relay_hash() {
    let kernel = Kernel::new(
        vec![Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        32,
    );
    let root = Ed25519SeedSigner::from_seed([61; 32]).unwrap();
    let operational = Arc::new(Ed25519SeedSigner::from_seed([62; 32]).unwrap());
    let relay = Ed25519SeedSigner::from_seed([63; 32]).unwrap();
    let (home, authority) = authority(&root, operational.as_ref());
    let provider = kernel
        .load_instance(
            Manifest::new("wrong-hash-home", "1.0.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(WrongHashHome { signer: operational, authority }),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_HOME_ROLE), provider);

    let caller_request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EventQueryV1 {
            handle: JobHandleV1 { home, job: gawdfn::JobId::new("private-job") },
            after_sequence: None,
            limit: 8,
            nonce: "one-use-read".into(),
        },
        &root,
    )
    .unwrap();
    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    let ai = AiControl::new(true);
    let mut ctx = VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, None, &ai, false);
    ctx.set_function_deployer(&relay);

    let result = run_verb(Verb::JobEvents { request: caller_request }, &mut ctx, &mut |_| {});

    assert!(!result.ok);
    assert_eq!(result.json["error"], "invalid-function-contract");
    assert_eq!(result.json["field"], "event page response");
    assert!(result.json["detail"].as_str().unwrap().contains("exact signed relay request"));
}

#[test]
fn omni_rejects_a_home_event_bound_to_the_wrong_control_request_hash() {
    let kernel = Kernel::new(
        vec![Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("test-node")),
        Arc::new(StubVerifier),
        Arc::new(policy_dev::DevPolicy),
        32,
    );
    let root = Ed25519SeedSigner::from_seed([71; 32]).unwrap();
    let operational = Arc::new(Ed25519SeedSigner::from_seed([72; 32]).unwrap());
    let (home, authority) = authority(&root, operational.as_ref());
    let provider = kernel
        .load_instance(
            Manifest::new("wrong-control-hash-home", "1.0.0", Backend::Daemon, "gawd_creature_v1"),
            Box::new(WrongControlHashHome { signer: operational, authority }),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_HOME_ROLE), provider);

    let handle = JobHandleV1 { home, job: gawdfn::JobId::new("private-control-job") };
    let caller_request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            handle,
            expected_home_epoch: 1,
            control: gawdfn::ControlId::new("steer-one-use"),
            issued_at_unix_ms: None,
            kind: JobControlKindV1::Steer {
                value: ValueRefV1::Inline { value: serde_json::json!({"pace": "slow"}) },
            },
        },
        &root,
    )
    .unwrap();
    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());
    let ai = AiControl::new(true);
    let mut ctx = VerbCtx::with_probe(&kernel, &probe_bus, &probe_rx, None, &ai, false);

    let result = run_verb(Verb::JobControl { request: caller_request }, &mut ctx, &mut |_| {});

    assert!(!result.ok);
    assert_eq!(result.json["error"], "invalid-function-contract");
    assert_eq!(result.json["field"], "control acceptance");
    assert!(result.json["detail"].as_str().unwrap().contains("exact signed request"));
}
