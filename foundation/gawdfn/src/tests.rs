use serde_json::json;

use crate::*;

fn digest(ch: char) -> String {
    format!("sha256:{}", ch.to_string().repeat(64))
}

fn home() -> HomeId {
    HomeId::new("abode-public-key")
}

fn function() -> FunctionId {
    FunctionId { manifest_content_address: digest('a'), entrypoint: "reverse".into() }
}

fn selector() -> FunctionSelectorV1 {
    FunctionSelectorV1::Alias {
        alias: FunctionAlias {
            realm: "local".into(),
            name: "text-tools".into(),
            version: "1.0.0".into(),
            entrypoint: "reverse".into(),
        },
    }
}

fn input() -> ValueRefV1 {
    ValueRefV1::Inline { value: json!({ "text": "hello" }) }
}

fn deployment(signer: &Ed25519SeedSigner) -> SignedRecordV1<DeploymentReceiptV1> {
    SignedRecordV1::sign(
        SCHEMA_FUNCTION_DEPLOY_V1,
        DeploymentReceiptV1 {
            deployment: DeploymentId::new("deployment-1"),
            function: function(),
            artifact_hash: digest('b'),
            realm: "local".into(),
            node: "node-a".into(),
            executor: signer.public_key().into(),
            executor_creature: "9".into(),
            creature: "11".into(),
            evidence: vec![],
            registered_at_unix_ms: None,
        },
        signer,
    )
    .unwrap()
}

fn authority(
    root: &Ed25519SeedSigner,
    operational: &Ed25519SeedSigner,
    epoch: u64,
) -> HomeAuthorityV1 {
    authority_with_schemas(root, operational, epoch, SCHEMA_HOME_V1, SCHEMA_HOME_V1)
}

fn authority_with_schemas(
    root: &Ed25519SeedSigner,
    operational: &Ed25519SeedSigner,
    epoch: u64,
    abode_schema: &str,
    operational_schema: &str,
) -> HomeAuthorityV1 {
    let home = HomeId::new(root.public_key());
    let abode = SignedRecordV1::sign(
        abode_schema,
        AbodeKeyBindingV1 {
            abode: home.clone(),
            root_public_key: root.public_key().into(),
            issued_at_unix_ms: None,
        },
        root,
    )
    .unwrap();
    let operational = SignedRecordV1::sign(
        operational_schema,
        OperationalKeyGrantV1 {
            home,
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

struct RewrapFixture {
    home: HomeId,
    requirement: CustodyRewrapRequirementV1,
    inventory: Vec<CustodyRewrapSourceV1>,
    prepared: SignedRecordV1<CustodyPreparedV1>,
    request: SignedRecordV1<CustodyRewrapRequestV1>,
    receipt: SignedRecordV1<CustodyRewrapReceiptV1>,
    staged: SignedRecordV1<CustodyStagedV1>,
}

fn rewrap_fixture() -> RewrapFixture {
    let root = Ed25519SeedSigner::from_seed([0x71; 32]).unwrap();
    let source = Ed25519SeedSigner::from_seed([0x72; 32]).unwrap();
    let destination = Ed25519SeedSigner::from_seed([0x73; 32]).unwrap();
    let source_proof = Ed25519SeedSigner::from_seed([0x74; 32]).unwrap();
    let destination_proof = Ed25519SeedSigner::from_seed([0x75; 32]).unwrap();
    let home = HomeId::new(root.public_key());
    let source_binding = recipient_binding(&root, &source_proof, 0x11);
    let destination_binding = recipient_binding(&root, &destination_proof, 0x22);
    let requirement = CustodyRewrapRequirementV1 {
        source_binding: Box::new(source_binding.clone()),
        destination_binding: Box::new(destination_binding.clone()),
        evidence: vec![],
    };
    let source_binding_hash = canonical_hash(&source_binding).unwrap();
    let inventory = vec![
        CustodyRewrapSourceV1 {
            sealed_value_hash: digest('1'),
            ciphertext: BlobRefV1 {
                digest: digest('3'),
                size: 31,
                media_type: "application/octet-stream".into(),
            },
            source_wrap: RecipientKeyWrapV1 {
                recipient: home.clone(),
                binding_hash: source_binding_hash.clone(),
                encapsulated_key: "source-encapsulated-1".into(),
                wrapped_data_key: "source-wrapped-key-1".into(),
            },
        },
        CustodyRewrapSourceV1 {
            sealed_value_hash: digest('2'),
            ciphertext: BlobRefV1 {
                digest: digest('4'),
                size: 32,
                media_type: "application/octet-stream".into(),
            },
            source_wrap: RecipientKeyWrapV1 {
                recipient: home.clone(),
                binding_hash: source_binding_hash,
                encapsulated_key: "source-encapsulated-2".into(),
                wrapped_data_key: "source-wrapped-key-2".into(),
            },
        },
    ];
    let inventory_hash = verify_custody_rewrap_inventory(&home, &requirement, &inventory).unwrap();
    let checkpoint = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        HomeCheckpointV1 {
            home: home.clone(),
            epoch: 1,
            high_water_mark: 7,
            log_root: digest('5'),
            state: BlobRefV1 {
                digest: digest('6'),
                size: 4096,
                media_type: "application/vnd.gawd.function-home-checkpoint".into(),
            },
            created_at_unix_ms: None,
        },
        &source,
    )
    .unwrap();
    let destination_authority = authority(&root, &destination, 2);
    let grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyGrantV1 {
            home: home.clone(),
            handoff: HandoffId::new("rewrap-1-2"),
            from_epoch: 1,
            to_epoch: 2,
            source_authority: authority(&root, &source, 1),
            source_realm: "realm-a".into(),
            source_node: "node-a".into(),
            destination_realm: "realm-b".into(),
            destination_node: "node-b".into(),
            checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
            source_log_root: checkpoint.payload.log_root.clone(),
            destination_operational_key: destination_authority.operational,
            evidence: vec![],
            issued_at_unix_ms: None,
            destination_rewrap: Some(requirement.clone()),
        },
        &root,
    )
    .unwrap();
    let prepared = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyPreparedV1 {
            grant: Box::new(grant.clone()),
            checkpoint: Box::new(checkpoint.clone()),
            grant_hash: canonical_hash(&grant).unwrap(),
            checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
            source_log_root: checkpoint.payload.log_root,
            source_coordinator: "source-home".into(),
            rewrap_inventory_hash: Some(inventory_hash.clone()),
            rewrap_item_count: Some(u32::try_from(inventory.len()).unwrap()),
        },
        &source,
    )
    .unwrap();
    let request = SignedRecordV1::sign(
        SCHEMA_CUSTODY_REWRAP_V1,
        CustodyRewrapRequestV1 {
            home: home.clone(),
            handoff: grant.payload.handoff.clone(),
            prepared_hash: canonical_hash(&prepared).unwrap(),
            grant_hash: prepared.payload.grant_hash.clone(),
            checkpoint_hash: prepared.payload.checkpoint_hash.clone(),
            requirement_hash: canonical_hash(&requirement).unwrap(),
            inventory_hash,
            item_count: u32::try_from(inventory.len()).unwrap(),
        },
        &destination,
    )
    .unwrap();
    let destination_binding_hash = canonical_hash(&destination_binding).unwrap();
    let entries = inventory
        .iter()
        .enumerate()
        .map(|(index, source)| CustodyRewrapEntryV1 {
            sealed_value_hash: source.sealed_value_hash.clone(),
            ciphertext: source.ciphertext.clone(),
            source_wrap_hash: canonical_hash(&source.source_wrap).unwrap(),
            destination_wrap: RecipientKeyWrapV1 {
                recipient: home.clone(),
                binding_hash: destination_binding_hash.clone(),
                encapsulated_key: format!("destination-encapsulated-{index}"),
                wrapped_data_key: format!("destination-wrapped-key-{index}"),
            },
        })
        .collect();
    let receipt = SignedRecordV1::sign(
        SCHEMA_CUSTODY_REWRAP_V1,
        CustodyRewrapReceiptV1 { request: Box::new(request.clone()), entries, evidence: vec![] },
        &destination_proof,
    )
    .unwrap();
    let staged = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyStagedV1 {
            prepared: Box::new(prepared.clone()),
            prepared_hash: canonical_hash(&prepared).unwrap(),
            grant_hash: prepared.payload.grant_hash.clone(),
            checkpoint_hash: prepared.payload.checkpoint_hash.clone(),
            destination_realm: "realm-b".into(),
            destination_node: "node-b".into(),
            destination_coordinator: "destination-home".into(),
            rewrap_receipt: Some(Box::new(receipt.clone())),
        },
        &destination,
    )
    .unwrap();
    RewrapFixture { home, requirement, inventory, prepared, request, receipt, staged }
}

#[test]
fn canonical_json_sorts_nested_object_keys() {
    let left = json!({ "z": { "b": 2, "a": 1 }, "a": 0 });
    let right = json!({ "a": 0, "z": { "a": 1, "b": 2 } });
    assert_eq!(canonical_json_bytes(&left).unwrap(), canonical_json_bytes(&right).unwrap());
    assert_eq!(canonical_hash(&left).unwrap(), canonical_hash(&right).unwrap());
}

#[test]
fn control_disposition_wire_names_are_frozen() {
    assert_eq!(
        serde_json::to_value([
            ControlDispositionV1::Applied,
            ControlDispositionV1::Rejected,
            ControlDispositionV1::Unsupported,
            ControlDispositionV1::TooLate,
        ])
        .unwrap(),
        json!(["applied", "rejected", "unsupported", "too_late"])
    );
}

#[test]
fn job_control_acceptance_binds_the_exact_request_and_durable_event() {
    let root = Ed25519SeedSigner::from_seed([0x51; 32]).unwrap();
    let operational = Ed25519SeedSigner::from_seed([0x52; 32]).unwrap();
    let home = HomeId::new(root.public_key());
    let handle = JobHandleV1 {
        home: home.clone(),
        job: derive_job_id(&home, "control-acceptance").unwrap(),
    };
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            handle: handle.clone(),
            expected_home_epoch: 1,
            control: ControlId::new("cancel-exact"),
            issued_at_unix_ms: None,
            kind: JobControlKindV1::Cancel { reason: "operator request".into() },
        },
        &root,
    )
    .unwrap();
    let request_hash = canonical_hash(&request).unwrap();
    let event = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobEventV1 {
            handle,
            home_epoch: 1,
            authority: authority(&root, &operational, 1),
            sequence: 2,
            occurred_at_unix_ms: None,
            state_after: JobStateV1::Running,
            cancel_requested: true,
            kind: JobEventKindV1::ControlRequested {
                request: Box::new(request.clone()),
                attempt: None,
            },
            foreign_receipt: None,
        },
        &operational,
    )
    .unwrap();

    verify_job_control_acceptance(&request, &request_hash, &event).unwrap();
    assert!(verify_job_control_acceptance(&request, &digest('9'), &event).is_err());

    let mut changed_payload = request.payload.clone();
    changed_payload.control = ControlId::new("cancel-other");
    let changed = SignedRecordV1::sign(SCHEMA_JOB_V1, changed_payload, &root).unwrap();
    let mismatched_event = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobEventV1 {
            kind: JobEventKindV1::ControlRequested { request: Box::new(changed), attempt: None },
            ..event.payload.clone()
        },
        &operational,
    )
    .unwrap();
    assert!(verify_job_control_acceptance(&request, &request_hash, &mismatched_event).is_err());

    let steer = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobControlV1 {
            control: ControlId::new("steer-exact"),
            kind: JobControlKindV1::Steer {
                value: ValueRefV1::Inline { value: json!({ "pace": "fast" }) },
            },
            ..request.payload.clone()
        },
        &root,
    )
    .unwrap();
    let attemptless_steer = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobEventV1 {
            cancel_requested: false,
            kind: JobEventKindV1::ControlRequested {
                request: Box::new(steer.clone()),
                attempt: None,
            },
            ..event.payload.clone()
        },
        &operational,
    )
    .unwrap();
    assert!(verify_job_control_acceptance(
        &steer,
        &canonical_hash(&steer).unwrap(),
        &attemptless_steer,
    )
    .is_err());
}

#[test]
fn job_id_is_deterministic_and_scoped_to_home() {
    let a = derive_job_id(&home(), "caller-key-17").unwrap();
    assert_eq!(a, derive_job_id(&home(), "caller-key-17").unwrap());
    assert_ne!(a, derive_job_id(&HomeId::new("another-abode"), "caller-key-17").unwrap());
    assert_ne!(a, derive_job_id(&home(), "caller-key-18").unwrap());
    assert!(derive_job_id(&home(), "").is_err());
}

#[test]
fn deployment_id_pins_the_live_target_and_location() {
    let id =
        derive_deployment_id(&function(), &digest('b'), "realm-a", "node-a", "creature-1").unwrap();
    assert_eq!(
        id,
        derive_deployment_id(&function(), &digest('b'), "realm-a", "node-a", "creature-1").unwrap()
    );
    assert_ne!(
        id,
        derive_deployment_id(&function(), &digest('b'), "realm-a", "node-a", "creature-2").unwrap()
    );
}

#[test]
fn signed_records_are_domain_separated_and_tamper_evident() {
    let signer = Ed25519SeedSigner::from_seed([7; 32]).unwrap();
    let mut record = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        EvidenceV1 {
            subject: "node-a".into(),
            claim: "healthy".into(),
            value: input(),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
        },
        &signer,
    )
    .unwrap();
    assert!(record.verify());
    record.payload.claim = "compromised".into();
    assert!(!record.verify());
    record.payload.claim = "healthy".into();
    record.schema = SCHEMA_HOME_V1.into();
    assert!(!record.verify());
}

#[test]
fn entrypoint_contract_requires_object_input_and_bounds_inline_schema() {
    let valid = EntrypointContractV1 {
        description: "Reverse text".into(),
        input_schema: SchemaRefV1::Inline {
            schema: json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "type": "object",
                "required": ["text"],
                "properties": { "text": { "type": "string" } }
            }),
        },
        output_schema: SchemaRefV1::Inline { schema: json!({ "type": "string" }) },
        error_schema: None,
        effect: EffectClassV1::ReadOnly,
        controls: FunctionControlsV1::default(),
    };
    valid.validate().unwrap();

    let mut invalid = valid.clone();
    invalid.input_schema = SchemaRefV1::Inline { schema: json!({ "type": "string" }) };
    assert!(matches!(invalid.validate(), Err(ContractError::Invalid(_))));

    invalid.input_schema = SchemaRefV1::Inline {
        schema: json!({ "type": "object", "description": "x".repeat(MAX_INLINE_SCHEMA_BYTES) }),
    };
    assert!(matches!(invalid.validate(), Err(ContractError::Limit(_))));
}

#[test]
fn submission_enforces_delivery_and_delegate_caps() {
    let mut request = JobSubmitV1 {
        home: home(),
        caller_idempotency_key: "caller-key".into(),
        function: selector(),
        input: input(),
        delivery: DeliveryModeV1::AtLeastOnce { max_attempts: 3 },
        allow_duplicate_effects: false,
        parent: None,
        causal: vec![],
        access: JobAccessV1::default(),
        evidence: vec![],
        result_recipients: vec![home()],
        submitted_at_unix_ms: None,
    };
    request.validate().unwrap();
    assert!(request.request_hash().unwrap().starts_with("sha256:"));

    request.delivery = DeliveryModeV1::AtLeastOnce { max_attempts: 0 };
    assert!(request.validate().is_err());
    request.delivery = DeliveryModeV1::AtMostOnce;
    request.access.readers =
        (0..=MAX_JOB_DELEGATES).map(|i| HomeId::new(format!("reader-{i}"))).collect();
    assert!(matches!(request.validate(), Err(ContractError::Limit(_))));
}

#[test]
fn sealed_values_require_a_bounded_inline_key_envelope() {
    let mut sealed = SealedValueV1 {
        ciphertext: BlobRefV1 {
            digest: digest('9'),
            size: 32,
            media_type: "application/octet-stream".into(),
        },
        suite: "hpke-x25519".into(),
        plaintext_digest: None,
        recipients: vec![],
    };
    assert!(matches!(sealed.validate(), Err(ContractError::Invalid(_))));

    sealed.recipients.push(RecipientKeyWrapV1 {
        recipient: home(),
        binding_hash: digest('8'),
        encapsulated_key: "encapsulated-public-key".into(),
        wrapped_data_key: "wrapped-data-key".into(),
    });
    sealed.validate().unwrap();
    ValueRefV1::Sealed { sealed: Box::new(sealed) }.validate().unwrap();
}

#[test]
fn accepted_job_pins_matching_function_artifact_and_deployment() {
    let signer = Ed25519SeedSigner::from_seed([9; 32]).unwrap();
    let deployment = deployment(&signer);
    let handle = JobHandleV1 { home: home(), job: derive_job_id(&home(), "caller-key").unwrap() };
    let mut spec = JobSpecV1 {
        handle: handle.clone(),
        root: handle,
        caller_idempotency_key: "caller-key".into(),
        request_hash: digest('c'),
        function: ResolvedFunctionV1 {
            requested: selector(),
            function: function(),
            artifact_hash: digest('b'),
            resolution: None,
        },
        deployment,
        input: input(),
        delivery: DeliveryModeV1::AtMostOnce,
        allow_duplicate_effects: false,
        parent: None,
        causal: vec![],
        access: JobAccessV1::default(),
        evidence: vec![],
        result_recipients: vec![home()],
        accepted_at_unix_ms: None,
    };
    spec.validate().unwrap();
    spec.deployment.payload.artifact_hash = digest('d');
    assert!(spec.validate().is_err());
}

#[test]
fn exact_resolution_and_embedded_receipt_cannot_rebind_identity() {
    let resolver = Ed25519SeedSigner::from_seed([0x19; 32]).unwrap();
    let exact = FunctionSelectorV1::Id { function: function() };
    let mut payload = ResolutionReceiptV1 {
        selector: exact.clone(),
        function: function(),
        artifact_hash: digest('b'),
        resolved_at_unix_ms: None,
        evidence: vec![],
    };
    payload.validate().unwrap();
    payload.function.entrypoint = "different".into();
    assert!(matches!(payload.validate(), Err(ContractError::Invalid(_))));

    payload.function = function();
    let signed = SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, payload, &resolver).unwrap();
    let mut resolved = ResolvedFunctionV1 {
        requested: exact,
        function: function(),
        artifact_hash: digest('b'),
        resolution: Some(signed),
    };
    resolved.validate().unwrap();
    resolved.resolution.as_mut().unwrap().payload.artifact_hash = digest('c');
    assert!(matches!(resolved.validate(), Err(ContractError::Crypto(_))));
}

#[test]
fn deployment_and_execution_receipts_bind_the_executor_key() {
    let executor = Ed25519SeedSigner::from_seed([0x21; 32]).unwrap();
    let impostor = Ed25519SeedSigner::from_seed([0x22; 32]).unwrap();
    let deployment = deployment(&executor);
    verify_deployment_receipt(&deployment).unwrap();
    let undeploy_payload = UndeployReceiptV1 {
        deployment: deployment.payload.deployment.clone(),
        executor: executor.public_key().into(),
        executor_creature: "17".into(),
    };
    let undeploy =
        SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, undeploy_payload.clone(), &executor)
            .unwrap();
    verify_undeploy_receipt(&undeploy).unwrap();
    let forged_undeploy =
        SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, undeploy_payload, &impostor).unwrap();
    assert!(matches!(verify_undeploy_receipt(&forged_undeploy), Err(ContractError::Invalid(_))));

    let root = Ed25519SeedSigner::from_seed([0x23; 32]).unwrap();
    let home_key = Ed25519SeedSigner::from_seed([0x24; 32]).unwrap();
    let receipt_home = HomeId::new(root.public_key());
    let attempt = AttemptId {
        home: receipt_home.clone(),
        job: derive_job_id(&receipt_home, "receipt-test").unwrap(),
        number: 1,
    };
    let grant = SignedRecordV1::sign(
        SCHEMA_EXECUTE_V1,
        ExecutionGrantV1 {
            attempt: attempt.clone(),
            request_hash: digest('4'),
            home_epoch: 1,
            home_route_sequence: 1,
            home_realm: "realm-a".into(),
            home_node: "node-a".into(),
            home_coordinator: "home-a".into(),
            owner: receipt_home,
            authority: authority(&root, &home_key, 1),
            function: function(),
            deployment,
            input: input(),
            delivery: DeliveryModeV1::AtMostOnce,
            grant_sequence: 1,
            issued_at_unix_ms: None,
            deadline_unix_ms: None,
        },
        &home_key,
    )
    .unwrap();
    let payload = ExecutionReceiptV1 {
        attempt,
        grant_hash: canonical_hash(&grant).unwrap(),
        executor: executor.public_key().into(),
        sequence: 1,
        observed_at_unix_ms: None,
        stage: ExecutionStageV1::Claimed,
    };
    let valid = SignedRecordV1::sign(SCHEMA_EXECUTE_V1, payload.clone(), &executor).unwrap();
    verify_execution_receipt(&valid, &grant).unwrap();

    let forged = SignedRecordV1::sign(SCHEMA_EXECUTE_V1, payload, &impostor).unwrap();
    assert!(matches!(verify_execution_receipt(&forged, &grant), Err(ContractError::Invalid(_))));
}

#[test]
fn private_read_responses_bind_the_complete_signed_relay_request() {
    let root = Ed25519SeedSigner::from_seed([0x25; 32]).unwrap();
    let operational = Ed25519SeedSigner::from_seed([0x26; 32]).unwrap();
    let executor = Ed25519SeedSigner::from_seed([0x27; 32]).unwrap();
    let relay = Ed25519SeedSigner::from_seed([0x28; 32]).unwrap();
    let home = HomeId::new(root.public_key());
    let handle =
        JobHandleV1 { home: home.clone(), job: derive_job_id(&home, "private-read").unwrap() };
    let authority = authority(&root, &operational, 1);
    let spec = JobSpecV1 {
        handle: handle.clone(),
        root: handle.clone(),
        caller_idempotency_key: "private-read".into(),
        request_hash: digest('3'),
        function: ResolvedFunctionV1 {
            requested: selector(),
            function: function(),
            artifact_hash: digest('b'),
            resolution: None,
        },
        deployment: deployment(&executor),
        input: input(),
        delivery: DeliveryModeV1::AtMostOnce,
        allow_duplicate_effects: false,
        parent: None,
        causal: vec![],
        access: JobAccessV1::default(),
        evidence: vec![],
        result_recipients: vec![],
        accepted_at_unix_ms: None,
    };
    let snapshot = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSnapshotV1 {
            spec: spec.clone(),
            state: JobStateV1::Queued,
            cancel_requested: false,
            home_epoch: 1,
            authority: authority.clone(),
            last_sequence: 1,
            current_attempt: None,
            result: None,
            error: None,
        },
        &operational,
    )
    .unwrap();
    let caller = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetV1 { handle: handle.clone(), nonce: "snapshot-nonce".into() },
        &root,
    )
    .unwrap();
    let request = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetRelayV1 { caller, reply_to: r#"{"creature":41}"#.into() },
        &relay,
    )
    .unwrap();
    let response = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSnapshotResponseV1 {
            request_hash: canonical_hash(&request).unwrap(),
            snapshot: Box::new(snapshot),
        },
        &operational,
    )
    .unwrap();
    verify_job_snapshot_response_for(&response, &request).unwrap();

    let replayed_route = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobGetRelayV1 {
            caller: request.payload.caller.clone(),
            reply_to: r#"{"creature":99}"#.into(),
        },
        &relay,
    )
    .unwrap();
    assert!(matches!(
        verify_job_snapshot_response_for(&response, &replayed_route),
        Err(ContractError::Invalid(_))
    ));

    let mut tampered = response.clone();
    tampered.payload.request_hash = digest('4');
    assert!(matches!(
        verify_job_snapshot_response_for(&tampered, &request),
        Err(ContractError::Crypto(_))
    ));
    let wrong_but_resigned = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobSnapshotResponseV1 {
            request_hash: digest('4'),
            snapshot: response.payload.snapshot.clone(),
        },
        &operational,
    )
    .unwrap();
    assert!(matches!(
        verify_job_snapshot_response_for(&wrong_but_resigned, &request),
        Err(ContractError::Invalid(_))
    ));

    let submitted = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobEventV1 {
            handle: handle.clone(),
            home_epoch: 1,
            authority: authority.clone(),
            sequence: 1,
            occurred_at_unix_ms: None,
            state_after: JobStateV1::Queued,
            cancel_requested: false,
            kind: JobEventKindV1::Submitted { spec: Box::new(spec) },
            foreign_receipt: None,
        },
        &operational,
    )
    .unwrap();
    let blocked = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobEventV1 {
            handle: handle.clone(),
            home_epoch: 1,
            authority: authority.clone(),
            sequence: 2,
            occurred_at_unix_ms: None,
            state_after: JobStateV1::Blocked,
            cancel_requested: false,
            kind: JobEventKindV1::Blocked { reason: "waiting".into() },
            foreign_receipt: None,
        },
        &operational,
    )
    .unwrap();
    let request_for = |after_sequence, limit, nonce: &str| {
        let caller = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryV1 { handle: handle.clone(), after_sequence, limit, nonce: nonce.into() },
            &root,
        )
        .unwrap();
        SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventQueryRelayV1 { caller, reply_to: r#"{"creature":41}"#.into() },
            &relay,
        )
        .unwrap()
    };
    let page_for = |request: &SignedRecordV1<EventQueryRelayV1>,
                    events: Vec<SignedRecordV1<JobEventV1>>,
                    next_after_sequence| {
        SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            EventPageResponseV1 {
                request_hash: canonical_hash(request).unwrap(),
                home_epoch: 1,
                authority: authority.clone(),
                page: EventPageV1 { handle: handle.clone(), events, next_after_sequence },
            },
            &operational,
        )
        .unwrap()
    };
    let event_request = request_for(None, 2, "events-nonce");
    let page = page_for(&event_request, vec![submitted.clone(), blocked.clone()], None);
    verify_event_page_response_for(&page, &event_request).unwrap();
    let mut wrong_page = page.clone();
    wrong_page.payload.request_hash = digest('5');
    assert!(verify_event_page_response_for(&wrong_page, &event_request).is_err());

    let over_limit = request_for(None, 1, "limit");
    assert!(matches!(
        verify_event_page_response_for(
            &page_for(&over_limit, vec![submitted.clone(), blocked.clone()], None),
            &over_limit,
        ),
        Err(ContractError::Limit(_))
    ));
    assert!(verify_event_page_response_for(
        &page_for(&event_request, vec![blocked.clone(), submitted.clone()], None),
        &event_request,
    )
    .is_err());
    let after_one = request_for(Some(1), 1, "after");
    assert!(verify_event_page_response_for(
        &page_for(&after_one, vec![submitted.clone()], None),
        &after_one,
    )
    .is_err());
    assert!(verify_event_page_response_for(
        &page_for(&event_request, vec![submitted, blocked], Some(1)),
        &event_request,
    )
    .is_err());
    assert!(verify_event_page_response_for(
        &page_for(&event_request, Vec::new(), Some(2)),
        &event_request,
    )
    .is_err());
}

#[test]
fn home_lease_authority_is_epoch_and_sequence_not_wall_clock() {
    let root = Ed25519SeedSigner::from_seed([0x31; 32]).unwrap();
    let source = Ed25519SeedSigner::from_seed([0x30; 32]).unwrap();
    let operational = Ed25519SeedSigner::from_seed([0x32; 32]).unwrap();
    let home = HomeId::new(root.public_key());
    let checkpoint = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        HomeCheckpointV1 {
            home: home.clone(),
            epoch: 1,
            high_water_mark: 3,
            log_root: digest('d'),
            state: BlobRefV1 {
                digest: digest('c'),
                size: 10,
                media_type: "application/octet-stream".into(),
            },
            created_at_unix_ms: None,
        },
        &source,
    )
    .unwrap();
    let mut destination_authority = authority(&root, &operational, 2);
    let grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyGrantV1 {
            home: home.clone(),
            handoff: HandoffId::new("handoff-2"),
            from_epoch: 1,
            to_epoch: 2,
            source_authority: authority(&root, &source, 1),
            source_realm: "source-realm".into(),
            source_node: "source-node".into(),
            destination_realm: "trusted-realm".into(),
            destination_node: "node-c".into(),
            checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
            source_log_root: digest('d'),
            destination_operational_key: destination_authority.operational.clone(),
            evidence: vec![],
            issued_at_unix_ms: None,
            destination_rewrap: None,
        },
        &root,
    )
    .unwrap();
    let prepared = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyPreparedV1 {
            grant: Box::new(grant.clone()),
            checkpoint: Box::new(checkpoint.clone()),
            grant_hash: canonical_hash(&grant).unwrap(),
            checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
            source_log_root: checkpoint.payload.log_root.clone(),
            source_coordinator: "home-source".into(),
            rewrap_inventory_hash: None,
            rewrap_item_count: None,
        },
        &source,
    )
    .unwrap();
    destination_authority.prepared = Some(Box::new(prepared));
    let lease = HomeLeaseV1 {
        home,
        epoch: 2,
        lease_sequence: 7,
        realm: "trusted-realm".into(),
        node: "node-c".into(),
        coordinator: "home-c".into(),
        authority: destination_authority,
        handoff: Some(HandoffId::new("handoff-2")),
        custody_grant: Some(Box::new(grant)),
        checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
        issued_at_unix_ms: None,
        expires_at_unix_ms: None,
    };
    lease.validate().unwrap();
    let signed = SignedRecordV1::sign(SCHEMA_LOCATE_V1, lease.clone(), &operational).unwrap();
    verify_home_lease(&signed).unwrap();

    let mut invalid = lease;
    invalid.lease_sequence = 0;
    assert!(invalid.validate().is_err());
}

#[test]
fn authority_chain_rejects_an_unrelated_operational_signer() {
    let root = Ed25519SeedSigner::from_seed([0x41; 32]).unwrap();
    let operational = Ed25519SeedSigner::from_seed([0x42; 32]).unwrap();
    let impostor = Ed25519SeedSigner::from_seed([0x43; 32]).unwrap();
    let home = HomeId::new(root.public_key());
    let lease = HomeLeaseV1 {
        home,
        epoch: 1,
        lease_sequence: 1,
        realm: "local".into(),
        node: "node-a".into(),
        coordinator: "home-a".into(),
        authority: authority(&root, &operational, 1),
        handoff: None,
        custody_grant: None,
        checkpoint_hash: digest('e'),
        issued_at_unix_ms: None,
        expires_at_unix_ms: None,
    };
    let signed = SignedRecordV1::sign(SCHEMA_LOCATE_V1, lease, &impostor).unwrap();
    assert!(matches!(verify_home_lease(&signed), Err(ContractError::Invalid(_))));
}

#[test]
fn authority_chain_rejects_validly_resigned_records_from_other_schema_domains() {
    let root = Ed25519SeedSigner::from_seed([0x45; 32]).unwrap();
    let operational = Ed25519SeedSigner::from_seed([0x46; 32]).unwrap();
    let executor = Ed25519SeedSigner::from_seed([0x47; 32]).unwrap();
    let home = HomeId::new(root.public_key());

    let wrong_abode = authority_with_schemas(&root, &operational, 1, SCHEMA_JOB_V1, SCHEMA_HOME_V1);
    assert!(wrong_abode.abode.verify());
    assert!(wrong_abode.operational.verify());
    assert!(matches!(
        wrong_abode.verify(&home, 1, OperationalCapabilityV1::JobHome),
        Err(ContractError::Invalid(_))
    ));

    let attempt = AttemptId {
        home: home.clone(),
        job: derive_job_id(&home, "wrong-authority-schema").unwrap(),
        number: 1,
    };
    let execution_grant = SignedRecordV1::sign(
        SCHEMA_EXECUTE_V1,
        ExecutionGrantV1 {
            attempt,
            request_hash: digest('1'),
            home_epoch: 1,
            home_route_sequence: 1,
            home_realm: "realm-a".into(),
            home_node: "node-a".into(),
            home_coordinator: "home-a".into(),
            owner: home.clone(),
            authority: wrong_abode.clone(),
            function: function(),
            deployment: deployment(&executor),
            input: input(),
            delivery: DeliveryModeV1::AtMostOnce,
            grant_sequence: 1,
            issued_at_unix_ms: None,
            deadline_unix_ms: None,
        },
        &operational,
    )
    .unwrap();
    assert!(execution_grant.verify());
    assert!(matches!(verify_execution_grant(&execution_grant), Err(ContractError::Invalid(_))));

    let wrong_operational =
        authority_with_schemas(&root, &operational, 1, SCHEMA_HOME_V1, SCHEMA_LOCATE_V1);
    assert!(wrong_operational.abode.verify());
    assert!(wrong_operational.operational.verify());
    let home_lease = SignedRecordV1::sign(
        SCHEMA_LOCATE_V1,
        HomeLeaseV1 {
            home: home.clone(),
            epoch: 1,
            lease_sequence: 1,
            realm: "realm-a".into(),
            node: "node-a".into(),
            coordinator: "home-a".into(),
            authority: wrong_operational,
            handoff: None,
            custody_grant: None,
            checkpoint_hash: digest('2'),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
        },
        &operational,
    )
    .unwrap();
    assert!(home_lease.verify());
    assert!(matches!(verify_home_lease(&home_lease), Err(ContractError::Invalid(_))));

    let destination = Ed25519SeedSigner::from_seed([0x48; 32]).unwrap();
    let destination_authority = authority(&root, &destination, 2);
    let custody_grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyGrantV1 {
            home,
            handoff: HandoffId::new("wrong-authority-schema"),
            from_epoch: 1,
            to_epoch: 2,
            source_authority: wrong_abode,
            source_realm: "realm-a".into(),
            source_node: "node-a".into(),
            destination_realm: "realm-b".into(),
            destination_node: "node-b".into(),
            checkpoint_hash: digest('3'),
            source_log_root: digest('4'),
            destination_operational_key: destination_authority.operational,
            evidence: vec![],
            issued_at_unix_ms: None,
            destination_rewrap: None,
        },
        &root,
    )
    .unwrap();
    assert!(custody_grant.verify());
    assert!(matches!(verify_custody_grant(&custody_grant), Err(ContractError::Invalid(_))));
}

#[test]
fn moved_authority_is_inert_until_the_source_signed_prepared_fence_exists() {
    let root = Ed25519SeedSigner::from_seed([0x61; 32]).unwrap();
    let source = Ed25519SeedSigner::from_seed([0x62; 32]).unwrap();
    let destination = Ed25519SeedSigner::from_seed([0x63; 32]).unwrap();
    let executor = Ed25519SeedSigner::from_seed([0x64; 32]).unwrap();
    let home = HomeId::new(root.public_key());
    let incomplete = authority(&root, &destination, 2);
    let handoff = HandoffId::new("not-yet-prepared");
    let pre_fence_grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyGrantV1 {
            home: home.clone(),
            handoff: handoff.clone(),
            from_epoch: 1,
            to_epoch: 2,
            source_authority: authority(&root, &source, 1),
            source_realm: "realm-a".into(),
            source_node: "node-a".into(),
            destination_realm: "realm-b".into(),
            destination_node: "node-b".into(),
            checkpoint_hash: digest('5'),
            source_log_root: digest('6'),
            destination_operational_key: incomplete.operational.clone(),
            evidence: vec![],
            issued_at_unix_ms: None,
            destination_rewrap: None,
        },
        &root,
    )
    .unwrap();
    verify_custody_grant(&pre_fence_grant).unwrap();
    assert!(matches!(
        incomplete.verify(&home, 2, OperationalCapabilityV1::JobHome),
        Err(ContractError::Invalid(_))
    ));

    let lease = SignedRecordV1::sign(
        SCHEMA_LOCATE_V1,
        HomeLeaseV1 {
            home: home.clone(),
            epoch: 2,
            lease_sequence: 1,
            realm: "realm-b".into(),
            node: "node-b".into(),
            coordinator: "home-b".into(),
            authority: incomplete.clone(),
            handoff: Some(handoff),
            custody_grant: Some(Box::new(pre_fence_grant)),
            checkpoint_hash: digest('5'),
            issued_at_unix_ms: None,
            expires_at_unix_ms: None,
        },
        &destination,
    )
    .unwrap();
    assert!(lease.verify());
    assert!(matches!(verify_home_lease(&lease), Err(ContractError::Invalid(_))));

    let attempt = AttemptId {
        home: home.clone(),
        job: derive_job_id(&home, "pre-fence-attempt").unwrap(),
        number: 1,
    };
    let query = SignedRecordV1::sign(
        SCHEMA_EXECUTE_V1,
        ExecutionQueryV1 {
            attempt: attempt.clone(),
            grant_hash: digest('7'),
            home_epoch: 2,
            home_route_sequence: 1,
            home_realm: "realm-b".into(),
            home_node: "node-b".into(),
            home_coordinator: "home-b".into(),
            authority: incomplete.clone(),
            query: ControlId::new("pre-fence-query"),
        },
        &destination,
    )
    .unwrap();
    assert!(query.verify());
    assert!(matches!(verify_execution_query(&query), Err(ContractError::Invalid(_))));

    let execution_grant = SignedRecordV1::sign(
        SCHEMA_EXECUTE_V1,
        ExecutionGrantV1 {
            attempt: attempt.clone(),
            request_hash: digest('8'),
            home_epoch: 2,
            home_route_sequence: 1,
            home_realm: "realm-b".into(),
            home_node: "node-b".into(),
            home_coordinator: "home-b".into(),
            owner: home.clone(),
            authority: incomplete.clone(),
            function: function(),
            deployment: deployment(&executor),
            input: input(),
            delivery: DeliveryModeV1::AtMostOnce,
            grant_sequence: 1,
            issued_at_unix_ms: None,
            deadline_unix_ms: None,
        },
        &destination,
    )
    .unwrap();
    assert!(execution_grant.verify());
    assert!(matches!(verify_execution_grant(&execution_grant), Err(ContractError::Invalid(_))));

    let event = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        JobEventV1 {
            handle: JobHandleV1 { home, job: attempt.job },
            home_epoch: 2,
            authority: incomplete,
            sequence: 1,
            occurred_at_unix_ms: None,
            state_after: JobStateV1::Queued,
            cancel_requested: false,
            kind: JobEventKindV1::Blocked { reason: "awaiting source fence".into() },
            foreign_receipt: None,
        },
        &destination,
    )
    .unwrap();
    assert!(event.verify());
    assert!(matches!(verify_job_event(&event), Err(ContractError::Invalid(_))));
}

#[test]
fn custody_grant_binds_source_authority_checkpoint_hash_and_tip() {
    let root = Ed25519SeedSigner::from_seed([0x51; 32]).unwrap();
    let source = Ed25519SeedSigner::from_seed([0x52; 32]).unwrap();
    let destination = Ed25519SeedSigner::from_seed([0x53; 32]).unwrap();
    let home = HomeId::new(root.public_key());
    let source_authority = authority(&root, &source, 1);
    let checkpoint = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        HomeCheckpointV1 {
            home: home.clone(),
            epoch: 1,
            high_water_mark: 12,
            log_root: digest('6'),
            state: BlobRefV1 {
                digest: digest('7'),
                size: 123,
                media_type: "application/vnd.gawd.function-home-checkpoint".into(),
            },
            created_at_unix_ms: None,
        },
        &source,
    )
    .unwrap();
    let destination_key = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        OperationalKeyGrantV1 {
            home: home.clone(),
            epoch: 2,
            operational_public_key: destination.public_key().into(),
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
        &root,
    )
    .unwrap();
    let grant = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        CustodyGrantV1 {
            home,
            handoff: HandoffId::new("handoff-1-2"),
            from_epoch: 1,
            to_epoch: 2,
            source_authority,
            source_realm: "realm-a".into(),
            source_node: "node-a".into(),
            destination_realm: "realm-c".into(),
            destination_node: "node-c".into(),
            checkpoint_hash: canonical_hash(&checkpoint).unwrap(),
            source_log_root: digest('6'),
            destination_operational_key: destination_key,
            evidence: vec![],
            issued_at_unix_ms: None,
            destination_rewrap: None,
        },
        &root,
    )
    .unwrap();
    verify_custody_grant(&grant).unwrap();
    verify_handoff_checkpoint(&grant, &checkpoint).unwrap();

    let mut wrong_tip = checkpoint;
    wrong_tip.payload.log_root = digest('8');
    assert!(verify_handoff_checkpoint(&grant, &wrong_tip).is_err());
}

#[test]
fn custody_rewrap_chain_binds_frozen_inventory_and_destination_kms_proof() {
    let fixture = rewrap_fixture();
    fixture.requirement.validate().unwrap();
    let inventory_hash =
        verify_custody_rewrap_inventory(&fixture.home, &fixture.requirement, &fixture.inventory)
            .unwrap();
    assert_eq!(Some(&inventory_hash), fixture.prepared.payload.rewrap_inventory_hash.as_ref());
    assert_eq!(inventory_hash, custody_rewrap_inventory_hash(&fixture.inventory).unwrap());
    verify_custody_grant(&fixture.prepared.payload.grant).unwrap();
    verify_custody_prepared(&fixture.prepared).unwrap();
    verify_custody_rewrap_request(&fixture.request, &fixture.prepared).unwrap();
    verify_custody_rewrap_receipt(&fixture.receipt, &fixture.prepared).unwrap();
    verify_custody_staged(&fixture.staged).unwrap();

    let source = Ed25519SeedSigner::from_seed([0x72; 32]).unwrap();
    let mut incomplete_prepared_payload = fixture.prepared.payload;
    incomplete_prepared_payload.rewrap_inventory_hash = None;
    let incomplete_prepared =
        SignedRecordV1::sign(SCHEMA_HOME_V1, incomplete_prepared_payload, &source).unwrap();
    assert!(verify_custody_prepared(&incomplete_prepared).is_err());
}

#[test]
fn absent_rewrap_fields_preserve_the_legacy_custody_wire() {
    #[derive(serde::Serialize)]
    struct LegacyGrant<'a> {
        home: &'a HomeId,
        handoff: &'a HandoffId,
        from_epoch: u64,
        to_epoch: u64,
        source_authority: &'a HomeAuthorityV1,
        source_realm: &'a str,
        source_node: &'a str,
        destination_realm: &'a str,
        destination_node: &'a str,
        checkpoint_hash: &'a str,
        source_log_root: &'a str,
        destination_operational_key: &'a SignedRecordV1<OperationalKeyGrantV1>,
        evidence: &'a [EvidenceRefV1],
        #[serde(skip_serializing_if = "Option::is_none")]
        issued_at_unix_ms: Option<u64>,
    }

    #[derive(serde::Serialize)]
    struct LegacyPrepared<'a> {
        grant: &'a SignedRecordV1<CustodyGrantV1>,
        checkpoint: &'a SignedRecordV1<HomeCheckpointV1>,
        grant_hash: &'a str,
        checkpoint_hash: &'a str,
        source_log_root: &'a str,
        source_coordinator: &'a str,
    }

    #[derive(serde::Serialize)]
    struct LegacyStaged<'a> {
        prepared: &'a SignedRecordV1<CustodyPreparedV1>,
        prepared_hash: &'a str,
        grant_hash: &'a str,
        checkpoint_hash: &'a str,
        destination_realm: &'a str,
        destination_node: &'a str,
        destination_coordinator: &'a str,
    }

    let fixture = rewrap_fixture();
    let root = Ed25519SeedSigner::from_seed([0x71; 32]).unwrap();
    let source = Ed25519SeedSigner::from_seed([0x72; 32]).unwrap();
    let destination = Ed25519SeedSigner::from_seed([0x73; 32]).unwrap();
    let mut grant_payload = fixture.prepared.payload.grant.payload.clone();
    grant_payload.destination_rewrap = None;
    let grant = SignedRecordV1::sign(SCHEMA_HOME_V1, grant_payload, &root).unwrap();
    let grant_legacy = LegacyGrant {
        home: &grant.payload.home,
        handoff: &grant.payload.handoff,
        from_epoch: grant.payload.from_epoch,
        to_epoch: grant.payload.to_epoch,
        source_authority: &grant.payload.source_authority,
        source_realm: &grant.payload.source_realm,
        source_node: &grant.payload.source_node,
        destination_realm: &grant.payload.destination_realm,
        destination_node: &grant.payload.destination_node,
        checkpoint_hash: &grant.payload.checkpoint_hash,
        source_log_root: &grant.payload.source_log_root,
        destination_operational_key: &grant.payload.destination_operational_key,
        evidence: &grant.payload.evidence,
        issued_at_unix_ms: grant.payload.issued_at_unix_ms,
    };
    assert_eq!(
        canonical_json_bytes(&grant.payload).unwrap(),
        canonical_json_bytes(&grant_legacy).unwrap()
    );

    let mut prepared_payload = fixture.prepared.payload.clone();
    prepared_payload.grant = Box::new(grant.clone());
    prepared_payload.grant_hash = canonical_hash(&grant).unwrap();
    prepared_payload.rewrap_inventory_hash = None;
    prepared_payload.rewrap_item_count = None;
    let prepared = SignedRecordV1::sign(SCHEMA_HOME_V1, prepared_payload, &source).unwrap();
    let prepared_legacy = LegacyPrepared {
        grant: &prepared.payload.grant,
        checkpoint: &prepared.payload.checkpoint,
        grant_hash: &prepared.payload.grant_hash,
        checkpoint_hash: &prepared.payload.checkpoint_hash,
        source_log_root: &prepared.payload.source_log_root,
        source_coordinator: &prepared.payload.source_coordinator,
    };
    assert_eq!(
        canonical_json_bytes(&prepared.payload).unwrap(),
        canonical_json_bytes(&prepared_legacy).unwrap()
    );

    let staged_payload = CustodyStagedV1 {
        prepared: Box::new(prepared.clone()),
        prepared_hash: canonical_hash(&prepared).unwrap(),
        grant_hash: prepared.payload.grant_hash.clone(),
        checkpoint_hash: prepared.payload.checkpoint_hash.clone(),
        destination_realm: "realm-b".into(),
        destination_node: "node-b".into(),
        destination_coordinator: "destination-home".into(),
        rewrap_receipt: None,
    };
    let staged_legacy = LegacyStaged {
        prepared: &staged_payload.prepared,
        prepared_hash: &staged_payload.prepared_hash,
        grant_hash: &staged_payload.grant_hash,
        checkpoint_hash: &staged_payload.checkpoint_hash,
        destination_realm: &staged_payload.destination_realm,
        destination_node: &staged_payload.destination_node,
        destination_coordinator: &staged_payload.destination_coordinator,
    };
    assert_eq!(
        canonical_json_bytes(&staged_payload).unwrap(),
        canonical_json_bytes(&staged_legacy).unwrap()
    );
    let staged = SignedRecordV1::sign(SCHEMA_HOME_V1, staged_payload, &destination).unwrap();
    verify_custody_grant(&grant).unwrap();
    verify_custody_prepared(&prepared).unwrap();
    verify_custody_staged(&staged).unwrap();
    let mut unsolicited_payload = staged.payload.clone();
    unsolicited_payload.rewrap_receipt = Some(Box::new(fixture.receipt));
    let unsolicited =
        SignedRecordV1::sign(SCHEMA_HOME_V1, unsolicited_payload, &destination).unwrap();
    assert!(verify_custody_staged(&unsolicited).is_err());

    let grant_json = serde_json::to_value(&grant.payload).unwrap();
    let prepared_json = serde_json::to_value(&prepared.payload).unwrap();
    let staged_json = serde_json::to_value(&staged.payload).unwrap();
    assert!(grant_json.get("destination_rewrap").is_none());
    assert!(prepared_json.get("rewrap_inventory_hash").is_none());
    assert!(prepared_json.get("rewrap_item_count").is_none());
    assert!(staged_json.get("rewrap_receipt").is_none());
    assert_eq!(serde_json::from_value::<CustodyGrantV1>(grant_json).unwrap(), grant.payload);
    assert_eq!(
        serde_json::from_value::<CustodyPreparedV1>(prepared_json).unwrap(),
        prepared.payload
    );
    assert_eq!(serde_json::from_value::<CustodyStagedV1>(staged_json).unwrap(), staged.payload);
}

#[test]
fn custody_rewrap_bindings_are_root_bound_distinct_and_key_plane_separated() {
    let fixture = rewrap_fixture();
    let root = Ed25519SeedSigner::from_seed([0x71; 32]).unwrap();
    let destination = Ed25519SeedSigner::from_seed([0x73; 32]).unwrap();
    let impostor = Ed25519SeedSigner::from_seed([0x76; 32]).unwrap();

    let wrong_schema = SignedRecordV1::sign(
        SCHEMA_JOB_V1,
        fixture.requirement.source_binding.payload.clone(),
        &root,
    )
    .unwrap();
    assert!(verify_recipient_key_binding(&wrong_schema).is_err());

    let wrong_root = SignedRecordV1::sign(
        SCHEMA_HOME_V1,
        fixture.requirement.source_binding.payload.clone(),
        &impostor,
    )
    .unwrap();
    assert!(verify_recipient_key_binding(&wrong_root).is_err());

    let mut tampered = fixture.requirement.source_binding.as_ref().clone();
    tampered.payload.encryption_public_key = "33".repeat(32);
    assert!(verify_recipient_key_binding(&tampered).is_err());

    let mut same_key_payload = fixture.requirement.destination_binding.payload.clone();
    same_key_payload.encryption_public_key =
        fixture.requirement.source_binding.payload.encryption_public_key.clone();
    let same_key = SignedRecordV1::sign(SCHEMA_HOME_V1, same_key_payload, &root).unwrap();
    let mut same_key_requirement = fixture.requirement.clone();
    *same_key_requirement.destination_binding = same_key;
    assert!(same_key_requirement.validate().is_err());

    let other_root = Ed25519SeedSigner::from_seed([0x77; 32]).unwrap();
    let other_proof = Ed25519SeedSigner::from_seed([0x78; 32]).unwrap();
    let mut wrong_home_requirement = fixture.requirement.clone();
    *wrong_home_requirement.destination_binding =
        recipient_binding(&other_root, &other_proof, 0x44);
    assert!(wrong_home_requirement.validate().is_err());

    let mut aliased_payload = fixture.requirement.destination_binding.payload.clone();
    aliased_payload.signing_public_key = destination.public_key().into();
    let aliased_binding = SignedRecordV1::sign(SCHEMA_HOME_V1, aliased_payload, &root).unwrap();
    let mut aliased_grant = fixture.prepared.payload.grant.payload.clone();
    let mut aliased_requirement = fixture.requirement.clone();
    *aliased_requirement.destination_binding = aliased_binding;
    aliased_grant.destination_rewrap = Some(aliased_requirement);
    let aliased_grant = SignedRecordV1::sign(SCHEMA_HOME_V1, aliased_grant, &root).unwrap();
    assert!(verify_custody_grant(&aliased_grant).is_err());

    let mut aliased_encryption_payload = fixture.requirement.destination_binding.payload.clone();
    aliased_encryption_payload.encryption_public_key = destination.public_key().into();
    let aliased_encryption =
        SignedRecordV1::sign(SCHEMA_HOME_V1, aliased_encryption_payload, &root).unwrap();
    let mut aliased_encryption_requirement = fixture.requirement;
    aliased_encryption_requirement.destination_binding = Box::new(aliased_encryption);
    let mut aliased_encryption_grant = fixture.prepared.payload.grant.payload.clone();
    aliased_encryption_grant.destination_rewrap = Some(aliased_encryption_requirement);
    let aliased_encryption_grant =
        SignedRecordV1::sign(SCHEMA_HOME_V1, aliased_encryption_grant, &root).unwrap();
    assert!(verify_custody_grant(&aliased_encryption_grant).is_err());
}

#[test]
fn custody_rewrap_inventory_is_bounded_canonical_and_exactly_source_bound() {
    let fixture = rewrap_fixture();
    let expected = custody_rewrap_inventory_hash(&fixture.inventory).unwrap();
    assert_eq!(expected, custody_rewrap_inventory_hash(&fixture.inventory).unwrap());

    let mut reversed = fixture.inventory.clone();
    reversed.reverse();
    assert!(custody_rewrap_inventory_hash(&reversed).is_err());

    let mut duplicate = fixture.inventory.clone();
    duplicate[1].sealed_value_hash = duplicate[0].sealed_value_hash.clone();
    assert!(custody_rewrap_inventory_hash(&duplicate).is_err());

    let mut wrong_binding = fixture.inventory.clone();
    wrong_binding[0].source_wrap.binding_hash = digest('a');
    assert!(verify_custody_rewrap_inventory(&fixture.home, &fixture.requirement, &wrong_binding,)
        .is_err());

    let mut wrong_recipient = fixture.inventory.clone();
    wrong_recipient[0].source_wrap.recipient = HomeId::new("other-home");
    assert!(
        verify_custody_rewrap_inventory(&fixture.home, &fixture.requirement, &wrong_recipient,)
            .is_err()
    );

    let oversized = (0..=MAX_CUSTODY_REWRAP_ITEMS)
        .map(|index| {
            let mut item = fixture.inventory[0].clone();
            item.sealed_value_hash = format!("sha256:{index:064x}");
            item
        })
        .collect::<Vec<_>>();
    assert!(matches!(custody_rewrap_inventory_hash(&oversized), Err(ContractError::Limit(_))));
}

#[test]
fn custody_rewrap_request_rejects_domain_signer_and_commitment_tampering() {
    let fixture = rewrap_fixture();
    let destination = Ed25519SeedSigner::from_seed([0x73; 32]).unwrap();
    let impostor = Ed25519SeedSigner::from_seed([0x76; 32]).unwrap();

    let wrong_schema =
        SignedRecordV1::sign(SCHEMA_HOME_V1, fixture.request.payload.clone(), &destination)
            .unwrap();
    assert!(verify_custody_rewrap_request(&wrong_schema, &fixture.prepared).is_err());

    let wrong_signer =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, fixture.request.payload.clone(), &impostor)
            .unwrap();
    assert!(verify_custody_rewrap_request(&wrong_signer, &fixture.prepared).is_err());

    let mut unsigned_tamper = fixture.request.clone();
    unsigned_tamper.payload.inventory_hash = digest('a');
    assert!(verify_custody_rewrap_request(&unsigned_tamper, &fixture.prepared).is_err());

    let mut resigned_payload = fixture.request.payload.clone();
    resigned_payload.requirement_hash = digest('b');
    let resigned =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, resigned_payload, &destination).unwrap();
    assert!(verify_custody_rewrap_request(&resigned, &fixture.prepared).is_err());

    let mut over_limit = fixture.request.payload;
    over_limit.item_count = u32::try_from(MAX_CUSTODY_REWRAP_ITEMS + 1).unwrap();
    let over_limit =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, over_limit, &destination).unwrap();
    assert!(matches!(
        verify_custody_rewrap_request(&over_limit, &fixture.prepared),
        Err(ContractError::Limit(_))
    ));
}

#[test]
fn custody_rewrap_receipt_rejects_incomplete_misdirected_and_resigned_proofs() {
    let fixture = rewrap_fixture();
    let destination = Ed25519SeedSigner::from_seed([0x73; 32]).unwrap();
    let destination_proof = Ed25519SeedSigner::from_seed([0x75; 32]).unwrap();
    let impostor = Ed25519SeedSigner::from_seed([0x76; 32]).unwrap();

    let wrong_schema =
        SignedRecordV1::sign(SCHEMA_HOME_V1, fixture.receipt.payload.clone(), &destination_proof)
            .unwrap();
    assert!(verify_custody_rewrap_receipt(&wrong_schema, &fixture.prepared).is_err());

    let wrong_signer =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, fixture.receipt.payload.clone(), &impostor)
            .unwrap();
    assert!(verify_custody_rewrap_receipt(&wrong_signer, &fixture.prepared).is_err());

    let mut missing_payload = fixture.receipt.payload.clone();
    missing_payload.entries.pop();
    let missing =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, missing_payload, &destination_proof)
            .unwrap();
    assert!(verify_custody_rewrap_receipt(&missing, &fixture.prepared).is_err());

    let mut reordered_payload = fixture.receipt.payload.clone();
    reordered_payload.entries.reverse();
    let reordered =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, reordered_payload, &destination_proof)
            .unwrap();
    assert!(verify_custody_rewrap_receipt(&reordered, &fixture.prepared).is_err());

    let mut changed_source_payload = fixture.receipt.payload.clone();
    changed_source_payload.entries[0].source_wrap_hash = digest('c');
    let changed_source =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, changed_source_payload, &destination_proof)
            .unwrap();
    assert!(verify_custody_rewrap_receipt(&changed_source, &fixture.prepared).is_err());

    let mut wrong_binding_payload = fixture.receipt.payload.clone();
    wrong_binding_payload.entries[0].destination_wrap.binding_hash = digest('d');
    let wrong_binding =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, wrong_binding_payload, &destination_proof)
            .unwrap();
    assert!(verify_custody_rewrap_receipt(&wrong_binding, &fixture.prepared).is_err());

    let mut wrong_recipient_payload = fixture.receipt.payload.clone();
    wrong_recipient_payload.entries[0].destination_wrap.recipient = HomeId::new("other-home");
    let wrong_recipient =
        SignedRecordV1::sign(SCHEMA_CUSTODY_REWRAP_V1, wrong_recipient_payload, &destination_proof)
            .unwrap();
    assert!(verify_custody_rewrap_receipt(&wrong_recipient, &fixture.prepared).is_err());

    let mut unsigned_tamper = fixture.receipt.clone();
    unsigned_tamper.payload.entries[0].destination_wrap.wrapped_data_key = "tampered".into();
    assert!(verify_custody_rewrap_receipt(&unsigned_tamper, &fixture.prepared).is_err());

    let mut missing_staged_payload = fixture.staged.payload.clone();
    missing_staged_payload.rewrap_receipt = None;
    let missing_staged =
        SignedRecordV1::sign(SCHEMA_HOME_V1, missing_staged_payload, &destination).unwrap();
    assert!(verify_custody_staged(&missing_staged).is_err());
}

#[test]
fn contract_names_and_role_names_are_frozen() {
    assert_eq!(SCHEMA_FUNCTION_DEPLOY_V1, "gawd.function.deploy.v1");
    assert_eq!(SCHEMA_JOB_V1, "gawd.function.job.v1");
    assert_eq!(SCHEMA_EXECUTE_V1, "gawd.function.execute.v1");
    assert_eq!(SCHEMA_CALL_V1, "gawd.function.call.v1");
    assert_eq!(SCHEMA_HOME_V1, "gawd.function.home.v1");
    assert_eq!(SCHEMA_CUSTODY_REWRAP_V1, "gawd.function.custody.rewrap.v1");
    assert_eq!(SCHEMA_LOCATE_V1, "gawd.function.locate.v1");
    assert_eq!(SCHEMA_POLICY_V1, "gawd.function.policy.v1");
    assert_eq!(FUNCTION_HOME_ROLE, "function-home");
    assert_eq!(FUNCTION_EXECUTOR_ROLE, "function-executor");
    assert_eq!(FUNCTION_RESOLVER_ROLE, "function-resolver");
    assert_eq!(FUNCTION_LOCATOR_ROLE, "function-locator");
    assert_eq!(FUNCTION_POLICY_ROLE, "function-policy");
}
