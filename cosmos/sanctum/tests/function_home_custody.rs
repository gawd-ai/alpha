//! Real-bus proof for the Function Home custody protocol.
//!
//! One bound destination creature stays at the coordinator named by the activated lease: before
//! activation it serves only proof-bearing custody operations; afterwards the same CreatureId hosts
//! the imported FunctionHome API. The checkpoint store stands in for a completed GX transfer. A
//! deterministic test KMS adapter proves exact Home-addressed sealed-value rewrap, durable Stage,
//! forged-but-unpersisted activation refusal, and proof-bearing restart status.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aether::{
    Address, CreatureId, Deadline, Dispatch, Envelope, InboxReceiver, Role, StubSigner,
    StubVerifier,
};
use anima::{NativeEngine, ScriptEngine, WasmEngine};
use function_home::{
    CustodyKeyRewrapper, FunctionHome, FunctionMetadata, FunctionTrust, HomeConfig,
    HomeCustodyDestination,
};
use function_locator::{FunctionLocator, LocatorCaps};
use gawdfn::{
    canonical_hash, verify_custody_prepared, verify_custody_rewrap_receipt, verify_custody_staged,
    verify_home_custody_status, verify_home_lease, AbodeKeyBindingV1, AuthoritySigner,
    CustodyGrantV1, CustodyRewrapEntryV1, CustodyRewrapReceiptV1, CustodyRewrapRequestV1,
    CustodyRewrapRequirementV1, CustodyRewrapSourceV1, CustodyStagedV1, DeliveryModeV1,
    DeploymentId, DeploymentReceiptV1, Ed25519SeedSigner, EffectClassV1, FunctionAlias, FunctionId,
    FunctionSelectorV1, HomeAuthorityV1, HomeCustodyPhaseV1, HomeId, HomeLocateV1, HomeMessageV1,
    JobAccessV1, JobGetRelayV1, JobGetV1, JobHandleV1, JobMessageV1, JobSubmitV1, LocateMessageV1,
    OperationalCapabilityV1, OperationalKeyGrantV1, PlacementDecisionV1, PolicyMessageV1,
    RecipientKeyBindingV1, RecipientKeyWrapV1, ResolutionReceiptV1, ResolvedFunctionV1,
    RetryDecisionV1, SealedValueV1, SignedRecordV1, ValueRefV1, FUNCTION_LOCATOR_ROLE,
    FUNCTION_POLICY_ROLE, SCHEMA_CUSTODY_REWRAP_V1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1,
    SCHEMA_JOB_V1, SCHEMA_LOCATE_V1, SCHEMA_POLICY_V1,
};
use job_blob_fs::{BlobCaps, FsJobBlobStore};
use sanctum::{Admission, Kernel, Policy};
use serde::Serialize;
use serde_json::json;
use sigil::{Backend, Capabilities, Manifest};

struct Admit;

impl Policy for Admit {
    fn admit(&self, _manifest: &Manifest, _evidence: &Admission) -> Result<(), String> {
        Ok(())
    }
}

struct Metadata;

impl FunctionMetadata for Metadata {
    fn effect(&self, _function: &ResolvedFunctionV1) -> EffectClassV1 {
        EffectClassV1::Idempotent
    }
}

struct Trust;

impl FunctionTrust for Trust {
    fn allow_resolution(&self, _: &SignedRecordV1<ResolutionReceiptV1>) -> Result<(), String> {
        Ok(())
    }

    fn allow_deployment(&self, _: &SignedRecordV1<DeploymentReceiptV1>) -> Result<(), String> {
        Ok(())
    }

    fn allow_executor_receipt(
        &self,
        _: &SignedRecordV1<gawdfn::ExecutionReceiptV1>,
        _: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        Ok(())
    }

    fn allow_placement_decision(
        &self,
        _: &SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<(), String> {
        Ok(())
    }

    fn allow_retry_decision(&self, _: &SignedRecordV1<RetryDecisionV1>) -> Result<(), String> {
        Ok(())
    }
}

fn kernel() -> Arc<Kernel> {
    Kernel::new(
        vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
        Arc::new(StubSigner::new("function-home-custody")),
        Arc::new(StubVerifier),
        Arc::new(Admit),
        128,
    )
}

fn manifest(name: &str) -> Manifest {
    Manifest::new(name, "0.1.0", Backend::Daemon, "gawd_creature_v1")
}

fn authority(
    root: &Ed25519SeedSigner,
    operational: &Ed25519SeedSigner,
    home: &HomeId,
    epoch: u64,
) -> HomeAuthorityV1 {
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
    let operational = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        OperationalKeyGrantV1 {
            home: home.clone(),
            epoch,
            operational_public_key: operational.public_key().into(),
            valid_from_unix_ms: None,
            expires_at_unix_ms: None,
            capabilities: vec![
                OperationalCapabilityV1::JobHome,
                OperationalCapabilityV1::JobControl,
                OperationalCapabilityV1::Custody,
                OperationalCapabilityV1::Locate,
            ],
            evidence: vec![],
        },
        root,
    )
    .unwrap();
    HomeAuthorityV1 { abode, operational, prepared: None }
}

fn recipient_binding(
    root: &Ed25519SeedSigner,
    proof: &Ed25519SeedSigner,
    encryption_byte: u8,
) -> SignedRecordV1<RecipientKeyBindingV1> {
    SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        RecipientKeyBindingV1 {
            abode: HomeId::new(root.public_key()),
            signing_public_key: proof.public_key().into(),
            encryption_public_key: format!("{encryption_byte:02x}").repeat(32),
            suite: "hpke-x25519".into(),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
        },
        root,
    )
    .unwrap()
}

type RewrapCall = (SignedRecordV1<CustodyRewrapRequestV1>, Vec<CustodyRewrapSourceV1>);

struct TestRewrapper {
    binding: SignedRecordV1<RecipientKeyBindingV1>,
    proof: Option<Arc<Ed25519SeedSigner>>,
    calls: Arc<Mutex<Vec<RewrapCall>>>,
}

impl CustodyKeyRewrapper for TestRewrapper {
    fn current_binding(&self) -> Result<SignedRecordV1<RecipientKeyBindingV1>, String> {
        Ok(self.binding.clone())
    }

    fn rewrap(
        &self,
        request: &SignedRecordV1<CustodyRewrapRequestV1>,
        inventory: &[CustodyRewrapSourceV1],
    ) -> Result<SignedRecordV1<CustodyRewrapReceiptV1>, String> {
        self.calls
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push((request.clone(), inventory.to_vec()));
        let proof =
            self.proof.as_deref().ok_or_else(|| "source test adapter cannot rewrap".to_string())?;
        signed_rewrap_receipt(&self.binding, proof, request.clone(), inventory)
    }
}

fn signed_rewrap_receipt(
    destination_binding: &SignedRecordV1<RecipientKeyBindingV1>,
    proof: &Ed25519SeedSigner,
    request: SignedRecordV1<CustodyRewrapRequestV1>,
    inventory: &[CustodyRewrapSourceV1],
) -> Result<SignedRecordV1<CustodyRewrapReceiptV1>, String> {
    let destination_binding_hash =
        canonical_hash(destination_binding).map_err(|error| error.to_string())?;
    let entries = inventory
        .iter()
        .enumerate()
        .map(|(index, source)| {
            Ok(CustodyRewrapEntryV1 {
                sealed_value_hash: source.sealed_value_hash.clone(),
                ciphertext: source.ciphertext.clone(),
                source_wrap_hash: canonical_hash(&source.source_wrap)
                    .map_err(|error| error.to_string())?,
                destination_wrap: RecipientKeyWrapV1 {
                    recipient: source.source_wrap.recipient.clone(),
                    binding_hash: destination_binding_hash.clone(),
                    encapsulated_key: format!("destination-encapsulated-{index}"),
                    wrapped_data_key: format!("destination-wrapped-key-{index}"),
                },
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    SignedRecordV1::sign(
        SCHEMA_CUSTODY_REWRAP_V1,
        CustodyRewrapReceiptV1 { request: Box::new(request), entries, evidence: vec![] },
        proof,
    )
    .map_err(|error| error.to_string())
}

fn signed_rewrap_request(
    prepared: &SignedRecordV1<gawdfn::CustodyPreparedV1>,
    signer: &Ed25519SeedSigner,
) -> SignedRecordV1<CustodyRewrapRequestV1> {
    let grant = &prepared.payload.grant;
    let requirement = grant.payload.destination_rewrap.as_ref().unwrap();
    SignedRecordV1::sign(
        SCHEMA_CUSTODY_REWRAP_V1,
        CustodyRewrapRequestV1 {
            home: grant.payload.home.clone(),
            handoff: grant.payload.handoff.clone(),
            prepared_hash: canonical_hash(prepared).unwrap(),
            grant_hash: prepared.payload.grant_hash.clone(),
            checkpoint_hash: prepared.payload.checkpoint_hash.clone(),
            requirement_hash: canonical_hash(requirement).unwrap(),
            inventory_hash: prepared.payload.rewrap_inventory_hash.clone().unwrap(),
            item_count: prepared.payload.rewrap_item_count.unwrap(),
        },
        signer,
    )
    .unwrap()
}

struct FunctionFixture {
    function: FunctionId,
    artifact: String,
    selector: FunctionSelectorV1,
    resolver: Ed25519SeedSigner,
    executor: Ed25519SeedSigner,
}

impl FunctionFixture {
    fn new() -> Self {
        Self {
            function: FunctionId {
                manifest_content_address: digest('a'),
                entrypoint: "compute".into(),
            },
            artifact: digest('b'),
            selector: FunctionSelectorV1::Alias {
                alias: FunctionAlias {
                    realm: "local".into(),
                    name: "custody-test".into(),
                    version: "1.0.0".into(),
                    entrypoint: "compute".into(),
                },
            },
            resolver: Ed25519SeedSigner::from_seed([83; 32]).unwrap(),
            executor: Ed25519SeedSigner::from_seed([84; 32]).unwrap(),
        }
    }

    fn submission(
        &self,
        owner: &Ed25519SeedSigner,
        home: &HomeId,
        key: &str,
        input: ValueRefV1,
    ) -> (
        SignedRecordV1<JobSubmitV1>,
        SignedRecordV1<ResolutionReceiptV1>,
        SignedRecordV1<DeploymentReceiptV1>,
    ) {
        let request = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobSubmitV1 {
                home: home.clone(),
                caller_idempotency_key: key.into(),
                function: self.selector.clone(),
                input,
                delivery: DeliveryModeV1::AtMostOnce,
                allow_duplicate_effects: false,
                parent: None,
                causal: vec![],
                access: JobAccessV1::default(),
                evidence: vec![],
                result_recipients: vec![],
                submitted_at_unix_ms: None,
            },
            owner,
        )
        .unwrap();
        let resolution = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            ResolutionReceiptV1 {
                selector: self.selector.clone(),
                function: self.function.clone(),
                artifact_hash: self.artifact.clone(),
                resolved_at_unix_ms: None,
                evidence: vec![],
            },
            &self.resolver,
        )
        .unwrap();
        let deployment = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentReceiptV1 {
                deployment: DeploymentId::new("custody-deployment"),
                function: self.function.clone(),
                artifact_hash: self.artifact.clone(),
                realm: "local".into(),
                node: "local".into(),
                executor: self.executor.public_key().into(),
                executor_creature: "41".into(),
                creature: "42".into(),
                registered_at_unix_ms: None,
                evidence: vec![],
            },
            &self.executor,
        )
        .unwrap();
        (request, resolution, deployment)
    }
}

fn send_rpc<T: Serialize>(
    bus: &aether::BusHandle,
    rx: &InboxReceiver,
    target: CreatureId,
    corr: u64,
    schema: &str,
    message: &T,
) -> Envelope {
    bus.send(
        Dispatch::to(Address::Creature(target), aether::wire::to_bytes(message))
            .with_schema(schema)
            .with_reply_to(Address::Creature(bus.id()))
            .with_corr(corr),
    )
    .unwrap();
    recv(rx, corr, schema)
}

fn recv(rx: &InboxReceiver, corr: u64, schema: &str) -> Envelope {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(!remaining.is_zero(), "timed out waiting for {schema} corr {corr}");
        if let Ok(env) = rx.recv_timeout(remaining.min(Duration::from_millis(100))) {
            if env.header.corr == Some(corr) && env.header.schema == schema {
                return env;
            }
        }
    }
}

fn digest(ch: char) -> String {
    format!("sha256:{}", ch.to_string().repeat(64))
}

fn job_get_message(
    bus: &aether::BusHandle,
    signer: &dyn AuthoritySigner,
    handle: JobHandleV1,
    nonce: &str,
) -> JobMessageV1 {
    let caller =
        SignedRecordV1::sign(SCHEMA_JOB_V1, JobGetV1 { handle, nonce: nonce.into() }, signer)
            .unwrap();
    let relay = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetRelayV1 {
            caller,
            reply_to: serde_json::to_string(&Address::Creature(bus.id())).unwrap(),
        },
        signer,
    )
    .unwrap();
    JobMessageV1::Get { request: Box::new(relay) }
}

#[test]
fn custody_bus_persists_exact_rewrap_refuses_unstaged_forgery_and_recovers_status() {
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let root_dir: PathBuf = std::env::temp_dir()
        .join(format!("alpha-function-home-custody-bus-{}-{unique}", std::process::id()));
    std::fs::create_dir_all(&root_dir).unwrap();
    let blob_store =
        Arc::new(FsJobBlobStore::open(root_dir.join("blobs"), BlobCaps::default()).unwrap());
    let owner = Arc::new(Ed25519SeedSigner::from_seed([80; 32]).unwrap());
    let source_key = Arc::new(Ed25519SeedSigner::from_seed([81; 32]).unwrap());
    let destination_key = Arc::new(Ed25519SeedSigner::from_seed([82; 32]).unwrap());
    let source_proof = Arc::new(Ed25519SeedSigner::from_seed([85; 32]).unwrap());
    let destination_proof = Arc::new(Ed25519SeedSigner::from_seed([86; 32]).unwrap());
    let home_id = HomeId::new(owner.public_key());
    let source_authority = authority(owner.as_ref(), source_key.as_ref(), &home_id, 1);
    let destination_authority = authority(owner.as_ref(), destination_key.as_ref(), &home_id, 2);
    let source_binding = recipient_binding(owner.as_ref(), source_proof.as_ref(), 0x31);
    let destination_binding = recipient_binding(owner.as_ref(), destination_proof.as_ref(), 0x32);
    let rewrap_requirement = CustodyRewrapRequirementV1 {
        source_binding: Box::new(source_binding.clone()),
        destination_binding: Box::new(destination_binding.clone()),
        evidence: vec![],
    };
    let ciphertext = blob_store
        .put_ref("application/vnd.gawd.test-ciphertext", b"home-addressed sealed test value")
        .unwrap();
    let source_wrap = RecipientKeyWrapV1 {
        recipient: home_id.clone(),
        binding_hash: canonical_hash(&source_binding).unwrap(),
        encapsulated_key: "source-encapsulated".into(),
        wrapped_data_key: "source-wrapped-data-key".into(),
    };
    let sealed = SealedValueV1 {
        ciphertext: ciphertext.clone(),
        suite: "hpke-x25519".into(),
        plaintext_digest: None,
        recipients: vec![source_wrap.clone()],
    };
    let sealed_input = ValueRefV1::Sealed { sealed: Box::new(sealed.clone()) };
    let rewrap_inventory = vec![CustodyRewrapSourceV1 {
        sealed_value_hash: canonical_hash(&sealed).unwrap(),
        ciphertext,
        source_wrap,
    }];
    let source_rewrap_calls = Arc::new(Mutex::new(Vec::new()));
    let destination_rewrap_calls = Arc::new(Mutex::new(Vec::new()));
    let function = FunctionFixture::new();

    let source_config = HomeConfig::for_creature(
        root_dir.join("source"),
        home_id.clone(),
        source_authority.clone(),
    )
    .with_location("local", "local");
    let source = FunctionHome::open_with_checkpoint_store_and_rewrapper(
        source_config.clone(),
        source_key.clone(),
        Arc::new(Metadata),
        Arc::new(Trust),
        blob_store.clone(),
        blob_store.clone(),
        Arc::new(TestRewrapper {
            binding: source_binding,
            proof: None,
            calls: source_rewrap_calls.clone(),
        }),
    )
    .unwrap();
    let (request, resolution, deployment) =
        function.submission(owner.as_ref(), &home_id, "before-move", sealed_input.clone());
    let accepted = source.submit(request, resolution, deployment).unwrap();
    let handle = match accepted {
        function_home::SubmitOutcome::Accepted { handle, .. } => handle,
        function_home::SubmitOutcome::Existing { .. } => panic!("new job expected"),
    };
    let checkpoint = source.create_checkpoint(None).unwrap();

    let mut destination_config = HomeConfig::for_creature(
        root_dir.join("destination"),
        home_id.clone(),
        destination_authority.clone(),
    )
    .with_location("local", "local");
    destination_config.epoch = 2;
    let grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyGrantV1 {
            home: home_id.clone(),
            handoff: gawdfn::HandoffId::new("bus-handoff"),
            from_epoch: 1,
            to_epoch: 2,
            source_authority,
            source_realm: "local".into(),
            source_node: "local".into(),
            destination_realm: "local".into(),
            destination_node: "local".into(),
            checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
            source_log_root: checkpoint.payload.log_root.clone(),
            destination_operational_key: destination_authority.operational.clone(),
            evidence: vec![],
            issued_at_unix_ms: None,
            destination_rewrap: Some(rewrap_requirement),
        },
        owner.as_ref(),
    )
    .unwrap();

    let kernel = kernel();
    let locator = kernel
        .load_instance(
            manifest("function-locator"),
            Box::new(FunctionLocator::new(LocatorCaps::default()).unwrap()),
        )
        .unwrap();
    kernel.bind_role(Role::new(FUNCTION_LOCATOR_ROLE), locator);
    let (policy_id, _policy_bus, policy_rx) = kernel.open_endpoint(Capabilities::default());
    kernel.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy_id);
    let source_id =
        kernel.load_instance(manifest("function-home-source"), Box::new(source)).unwrap();
    // Initial source bind re-emits its queued placement question; isolate destination recovery.
    let _ = policy_rx.recv_timeout(Duration::from_secs(2)).unwrap();

    let destination = HomeCustodyDestination::new_with_rewrapper(
        destination_config.clone(),
        destination_key.clone(),
        Arc::new(Metadata),
        Arc::new(Trust),
        blob_store.clone(),
        blob_store.clone(),
        Arc::new(TestRewrapper {
            binding: destination_binding.clone(),
            proof: Some(destination_proof.clone()),
            calls: destination_rewrap_calls.clone(),
        }),
    )
    .unwrap();
    let destination_id =
        kernel.load_instance(manifest("function-home-destination"), Box::new(destination)).unwrap();
    let (_probe_id, probe_bus, probe_rx) = kernel.open_endpoint(Capabilities::default());

    let read = job_get_message(&probe_bus, owner.as_ref(), handle.clone(), "before-active");
    let env = send_rpc(&probe_bus, &probe_rx, destination_id, 1, SCHEMA_JOB_V1, &read);
    assert!(matches!(
        serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap(),
        JobMessageV1::Error { error } if error.code == "home_inactive"
    ));

    let env = send_rpc(
        &probe_bus,
        &probe_rx,
        source_id,
        2,
        SCHEMA_HOME_V1,
        &HomeMessageV1::Prepare { grant: Box::new(grant), checkpoint: Box::new(checkpoint) },
    );
    let HomeMessageV1::Prepared { prepared } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("Prepared response")
    };
    verify_custody_prepared(&prepared).unwrap();
    assert_eq!(prepared.payload.source_coordinator, source_id.0.to_string());
    assert_eq!(prepared.payload.rewrap_item_count, Some(1));
    assert_eq!(
        prepared.payload.rewrap_inventory_hash,
        Some(gawdfn::custody_rewrap_inventory_hash(&rewrap_inventory).unwrap())
    );
    assert!(source_rewrap_calls.lock().unwrap().is_empty());

    let expected_request = signed_rewrap_request(&prepared, destination_key.as_ref());
    let expected_receipt = signed_rewrap_receipt(
        &destination_binding,
        destination_proof.as_ref(),
        expected_request.clone(),
        &rewrap_inventory,
    )
    .unwrap();
    verify_custody_rewrap_receipt(&expected_receipt, &prepared).unwrap();

    // Even a correctly signed receipt-shaped request cannot activate before that exact receipt was
    // produced by a durable Stage on this destination.
    let forged_staged = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyStagedV1 {
            prepared: prepared.clone(),
            prepared_hash: canonical_hash(prepared.as_ref()).unwrap(),
            grant_hash: prepared.payload.grant_hash.clone(),
            checkpoint_hash: prepared.payload.checkpoint_hash.clone(),
            destination_realm: "local".into(),
            destination_node: "local".into(),
            destination_coordinator: destination_id.0.to_string(),
            rewrap_receipt: Some(Box::new(expected_receipt.clone())),
        },
        destination_key.as_ref(),
    )
    .unwrap();
    verify_custody_staged(&forged_staged).unwrap();
    let env = send_rpc(
        &probe_bus,
        &probe_rx,
        destination_id,
        3,
        SCHEMA_HOME_V1,
        &HomeMessageV1::Activate { staged: Box::new(forged_staged) },
    );
    assert!(matches!(
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap(),
        HomeMessageV1::Error { .. }
    ));

    let stage = HomeMessageV1::Stage { prepared: prepared.clone() };
    let env = send_rpc(&probe_bus, &probe_rx, destination_id, 4, SCHEMA_HOME_V1, &stage);
    let HomeMessageV1::Staged { staged } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("Staged response")
    };
    verify_custody_staged(&staged).unwrap();
    assert_eq!(staged.payload.destination_coordinator, destination_id.0.to_string());
    assert_eq!(staged.payload.rewrap_receipt.as_deref(), Some(&expected_receipt));
    assert_eq!(
        *destination_rewrap_calls.lock().unwrap(),
        vec![(expected_request, rewrap_inventory.clone())]
    );
    let env = send_rpc(&probe_bus, &probe_rx, destination_id, 5, SCHEMA_HOME_V1, &stage);
    let HomeMessageV1::Staged { staged: retried } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("retried Staged response")
    };
    assert_eq!(retried, staged);
    assert_eq!(destination_rewrap_calls.lock().unwrap().len(), 1);

    let activate = HomeMessageV1::Activate { staged: staged.clone() };
    let env = send_rpc(&probe_bus, &probe_rx, destination_id, 6, SCHEMA_HOME_V1, &activate);
    let HomeMessageV1::Activated { lease } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("Activated response")
    };
    verify_home_lease(&lease).unwrap();
    assert_eq!(lease.payload.coordinator, destination_id.0.to_string());

    // Activation includes immediate recovery work for the imported queued Job.
    let policy_env = policy_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(policy_env.header.schema, SCHEMA_POLICY_V1);
    assert!(matches!(
        serde_json::from_slice::<PolicyMessageV1>(&policy_env.payload).unwrap(),
        PolicyMessageV1::SelectDeployment { question } if question.payload.job == handle
    ));

    let env = send_rpc(&probe_bus, &probe_rx, destination_id, 7, SCHEMA_HOME_V1, &activate);
    let HomeMessageV1::Activated { lease: retried_lease } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("retried Activated response")
    };
    assert_eq!(retried_lease, lease);

    let read = job_get_message(&probe_bus, owner.as_ref(), handle.clone(), "after-active");
    let env = send_rpc(&probe_bus, &probe_rx, destination_id, 8, SCHEMA_JOB_V1, &read);
    assert!(matches!(
        serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap(),
        JobMessageV1::Snapshot { response }
            if response.payload.snapshot.payload.home_epoch == 2
    ));

    let (request, resolution, deployment) = function.submission(
        owner.as_ref(),
        &home_id,
        "after-move",
        ValueRefV1::Inline { value: json!({"key": "after-move"}) },
    );
    let env = send_rpc(
        &probe_bus,
        &probe_rx,
        destination_id,
        9,
        SCHEMA_JOB_V1,
        &JobMessageV1::Submit {
            request: Box::new(request),
            resolution: Box::new(resolution),
            deployment: Box::new(deployment),
        },
    );
    assert!(matches!(
        serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap(),
        JobMessageV1::Accepted { .. }
    ));

    // The activated destination announces itself, and its source-signed return route causes the
    // frozen source to retain the exact redirect automatically.
    let env = send_rpc(
        &probe_bus,
        &probe_rx,
        locator,
        10,
        SCHEMA_LOCATE_V1,
        &LocateMessageV1::Locate {
            query: HomeLocateV1 { home: home_id.clone(), minimum_epoch: Some(2) },
        },
    );
    assert!(matches!(
        serde_json::from_slice::<LocateMessageV1>(&env.payload).unwrap(),
        LocateMessageV1::Location { location }
            if location.lease.payload.coordinator == destination_id.0.to_string()
    ));

    let env = send_rpc(
        &probe_bus,
        &probe_rx,
        source_id,
        11,
        SCHEMA_HOME_V1,
        &HomeMessageV1::Status { home: home_id.clone() },
    );
    let HomeMessageV1::StatusResult { status } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("source status")
    };
    verify_home_custody_status(&status).unwrap();
    assert!(matches!(status.payload.state, HomeCustodyPhaseV1::Frozen { redirect: Some(_), .. }));

    let env = send_rpc(
        &probe_bus,
        &probe_rx,
        destination_id,
        12,
        SCHEMA_HOME_V1,
        &HomeMessageV1::Status { home: home_id.clone() },
    );
    let HomeMessageV1::StatusResult { status } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("destination status")
    };
    verify_home_custody_status(&status).unwrap();
    assert!(matches!(
        status.payload.state,
        HomeCustodyPhaseV1::Active { staged: Some(ref staged), .. }
            if staged.payload.rewrap_receipt.as_deref() == Some(&expected_receipt)
    ));

    // A moved Home may restart at a different process-local CreatureId. Bind must recover the
    // active Home immediately, fsync a coordinator-only lease revision, and publish it to both the
    // locator and the frozen source without replaying Activate.
    kernel.unload(destination_id, Deadline::default()).unwrap();
    let restarted = HomeCustodyDestination::new_with_rewrapper(
        destination_config,
        destination_key,
        Arc::new(Metadata),
        Arc::new(Trust),
        blob_store.clone(),
        blob_store,
        Arc::new(TestRewrapper {
            binding: destination_binding,
            proof: Some(destination_proof),
            calls: destination_rewrap_calls,
        }),
    )
    .unwrap();
    let restarted_id = kernel
        .load_instance(manifest("function-home-destination-restarted"), Box::new(restarted))
        .unwrap();
    assert_ne!(restarted_id, destination_id);

    let read = job_get_message(&probe_bus, owner.as_ref(), handle, "after-restart");
    let env = send_rpc(&probe_bus, &probe_rx, restarted_id, 13, SCHEMA_JOB_V1, &read);
    assert!(matches!(
        serde_json::from_slice::<JobMessageV1>(&env.payload).unwrap(),
        JobMessageV1::Snapshot { response }
            if response.payload.snapshot.payload.home_epoch == 2
                && response.payload.snapshot.payload.spec.input == sealed_input
    ));

    let env = send_rpc(
        &probe_bus,
        &probe_rx,
        restarted_id,
        14,
        SCHEMA_HOME_V1,
        &HomeMessageV1::Status { home: home_id.clone() },
    );
    let HomeMessageV1::StatusResult { status } =
        serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
    else {
        panic!("restarted destination status")
    };
    verify_home_custody_status(&status).unwrap();
    assert!(matches!(
        status.payload.state,
        HomeCustodyPhaseV1::Active { staged: Some(ref staged), .. }
            if staged.payload.rewrap_receipt.as_deref() == Some(&expected_receipt)
    ));

    let deadline = Instant::now() + Duration::from_secs(5);
    let mut corr = 15;
    loop {
        let env = send_rpc(
            &probe_bus,
            &probe_rx,
            locator,
            corr,
            SCHEMA_LOCATE_V1,
            &LocateMessageV1::Locate {
                query: HomeLocateV1 { home: home_id.clone(), minimum_epoch: Some(2) },
            },
        );
        corr += 1;
        if matches!(
            serde_json::from_slice::<LocateMessageV1>(&env.payload).unwrap(),
            LocateMessageV1::Location { location }
                if location.lease.payload.coordinator == restarted_id.0.to_string()
                    && location.lease.payload.lease_sequence == 2
        ) {
            break;
        }
        assert!(Instant::now() < deadline, "locator did not retain coordinator revision");
    }

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let env = send_rpc(
            &probe_bus,
            &probe_rx,
            source_id,
            corr,
            SCHEMA_HOME_V1,
            &HomeMessageV1::Status { home: home_id.clone() },
        );
        corr += 1;
        let HomeMessageV1::StatusResult { status } =
            serde_json::from_slice::<HomeMessageV1>(&env.payload).unwrap()
        else {
            panic!("source status after destination restart")
        };
        verify_home_custody_status(&status).unwrap();
        if matches!(
            status.payload.state,
            HomeCustodyPhaseV1::Frozen { redirect: Some(lease), .. }
                if lease.payload.coordinator == restarted_id.0.to_string()
                    && lease.payload.lease_sequence == 2
        ) {
            break;
        }
        assert!(Instant::now() < deadline, "source did not replace its coordinator redirect");
    }

    drop(kernel);
    let _ = std::fs::remove_dir_all(root_dir);
}
