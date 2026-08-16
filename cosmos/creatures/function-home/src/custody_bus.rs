//! Aether adapter for destination-side custody staging and activation.
//!
//! This is deliberately separate from [`crate::FunctionHome`]: a staged destination must not open
//! the imported Job journal for writes until activation is fsynced. The adapter owns no policy and
//! no root key. It verifies the self-contained source/destination proof chain and delegates bytes
//! to the injected checkpoint store (which may be backed by GX or another transfer organ).

use crate::{
    activate_staged_handoff,
    custody::{
        destination_custody_status, merge_current_authority, refresh_active_destination_lease,
    },
    stage_handoff_with_rewrapper, CustodyKeyRewrapper, FunctionHome, FunctionMetadata,
    FunctionTrust, HomeConfig, HomeError, UnavailableCustodyKeyRewrapper,
};
use aether::{
    Address, Bus, Creature, CreatureCtx, CreatureId, Dispatch, Envelope, NodeId, Outcome, RealmId,
    Role,
};
use gawdfn::{
    AuthoritySigner, BlobAvailability, CheckpointBlobStore, HomeMessageV1, JobMessageV1,
    LocateMessageV1, ProtocolErrorV1, FUNCTION_LOCATOR_ROLE, MAX_JOB_MESSAGE_BYTES,
    MAX_REASON_BYTES, SCHEMA_HOME_V1, SCHEMA_JOB_V1, SCHEMA_LOCATE_V1,
};
use serde::Serialize;
use std::sync::Arc;

/// Cold-path creature that stages and activates one configured destination Home epoch.
pub struct HomeCustodyDestination {
    config: HomeConfig,
    signer: Arc<dyn AuthoritySigner>,
    metadata: Arc<dyn FunctionMetadata>,
    trust: Arc<dyn FunctionTrust>,
    values: Arc<dyn BlobAvailability>,
    checkpoint_blobs: Arc<dyn CheckpointBlobStore>,
    rewrapper: Arc<dyn CustodyKeyRewrapper>,
    active: Option<FunctionHome>,
    bound: Option<(CreatureId, Arc<dyn Bus>, sigil::Manifest)>,
    startup_error: Option<String>,
}

impl HomeCustodyDestination {
    pub fn new(
        config: HomeConfig,
        signer: Arc<dyn AuthoritySigner>,
        metadata: Arc<dyn FunctionMetadata>,
        trust: Arc<dyn FunctionTrust>,
        values: Arc<dyn BlobAvailability>,
        checkpoint_blobs: Arc<dyn CheckpointBlobStore>,
    ) -> Result<Self, HomeError> {
        Self::new_with_rewrapper(
            config,
            signer,
            metadata,
            trust,
            values,
            checkpoint_blobs,
            Arc::new(UnavailableCustodyKeyRewrapper),
        )
    }

    pub fn new_with_rewrapper(
        mut config: HomeConfig,
        signer: Arc<dyn AuthoritySigner>,
        metadata: Arc<dyn FunctionMetadata>,
        trust: Arc<dyn FunctionTrust>,
        values: Arc<dyn BlobAvailability>,
        checkpoint_blobs: Arc<dyn CheckpointBlobStore>,
        rewrapper: Arc<dyn CustodyKeyRewrapper>,
    ) -> Result<Self, HomeError> {
        merge_current_authority(&mut config)?;
        if config.epoch <= 1 {
            return Err(HomeError::Configuration(
                "a custody destination must be configured for a moved epoch".into(),
            ));
        }
        if signer.public_key()
            != config.authority.operational.payload.operational_public_key.as_str()
        {
            return Err(HomeError::Configuration(
                "custody destination signer is not the configured operational key".into(),
            ));
        }
        Ok(Self {
            config,
            signer,
            metadata,
            trust,
            values,
            checkpoint_blobs,
            rewrapper,
            active: None,
            bound: None,
            startup_error: None,
        })
    }

    fn recover_active_on_bind(&mut self, ctx: &CreatureCtx) -> Result<(), HomeError> {
        // A fresh destination has only the root grant and remains inert until Stage persists the
        // source Prepared fence proof.
        if self.config.authority.prepared.is_none() {
            return Ok(());
        }
        let Some(revision) = refresh_active_destination_lease(&self.config, self.signer.clone())?
        else {
            return Ok(());
        };
        let mut home = FunctionHome::open_with_checkpoint_store_and_rewrapper(
            self.config.clone(),
            self.signer.clone(),
            self.metadata.clone(),
            self.trust.clone(),
            self.values.clone(),
            self.checkpoint_blobs.clone(),
            self.rewrapper.clone(),
        )?;
        let recovery = home.bind_runtime(
            CreatureCtx { me: ctx.me, bus: ctx.bus.clone(), manifest: ctx.manifest.clone() },
            false,
        );
        self.active = Some(home);

        let activated = HomeMessageV1::Activated { lease: Box::new(revision.lease.clone()) };
        let _ = ctx.bus.emit(
            Dispatch::to(
                Address::Role(Role::new(FUNCTION_LOCATOR_ROLE)),
                aether::wire::to_bytes(&LocateMessageV1::Announce {
                    lease: revision.lease.clone(),
                }),
            )
            .with_schema(SCHEMA_LOCATE_V1),
        );
        if let Some(target) = routed_creature(
            &self.config.realm,
            &self.config.node,
            &revision.source_realm,
            &revision.source_node,
            &revision.source_coordinator,
        ) {
            let _ = ctx.bus.emit(
                Dispatch::to(target, aether::wire::to_bytes(&activated))
                    .with_schema(SCHEMA_HOME_V1),
            );
        }
        for dispatch in recovery.dispatches {
            let _ = ctx.bus.emit(dispatch);
        }
        Ok(())
    }

    fn activate(
        &mut self,
        env: &Envelope,
        staged: gawdfn::SignedRecordV1<gawdfn::CustodyStagedV1>,
    ) -> Outcome {
        let Some((me, bus, manifest)) = self.bound.clone() else {
            return reply_error(
                env,
                HomeError::State("custody destination was activated before bus bind".into()),
            );
        };
        let lease = match activate_staged_handoff(
            &self.config,
            self.signer.clone(),
            self.checkpoint_blobs.as_ref(),
            staged.clone(),
        ) {
            Ok(lease) => lease,
            Err(error) => return reply_error(env, error),
        };
        let mut activation_recovery = Outcome::none();
        if self.active.is_none() {
            let mut home = match FunctionHome::open_with_checkpoint_store_and_rewrapper(
                self.config.clone(),
                self.signer.clone(),
                self.metadata.clone(),
                self.trust.clone(),
                self.values.clone(),
                self.checkpoint_blobs.clone(),
                self.rewrapper.clone(),
            ) {
                Ok(home) => home,
                Err(error) => return reply_error(env, error),
            };
            activation_recovery = home.bind_runtime(CreatureCtx { me, bus, manifest }, false);
            self.active = Some(home);
        }
        let activated = HomeMessageV1::Activated { lease: Box::new(lease.clone()) };
        let mut outcome = reply(env, SCHEMA_HOME_V1, &activated);
        outcome.push(
            Dispatch::to(
                Address::Role(Role::new(FUNCTION_LOCATOR_ROLE)),
                aether::wire::to_bytes(&LocateMessageV1::Announce { lease: lease.clone() }),
            )
            .with_schema(SCHEMA_LOCATE_V1),
        );

        // Prepared carries a source-signed return route. Failure to parse it merely omits this
        // best-effort notification; it can never weaken the Frozen fence or the returned lease.
        let prepared = &staged.payload.prepared.payload;
        let grant = &prepared.grant.payload;
        if let Some(target) = routed_creature(
            &self.config.realm,
            &self.config.node,
            &grant.source_realm,
            &grant.source_node,
            &prepared.source_coordinator,
        ) {
            outcome.push(
                Dispatch::to(target, aether::wire::to_bytes(&activated))
                    .with_schema(SCHEMA_HOME_V1),
            );
        }
        for dispatch in activation_recovery.dispatches {
            outcome.push(dispatch);
        }
        outcome
    }
}

impl Creature for HomeCustodyDestination {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.config.coordinator = ctx.me.0.to_string();
        self.bound = Some((ctx.me, ctx.bus.clone(), ctx.manifest.clone()));
        if let Err(error) = self.recover_active_on_bind(&ctx) {
            self.active = None;
            self.startup_error = Some(error.to_string());
        }
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.payload.len() > MAX_JOB_MESSAGE_BYTES {
            return Outcome::none();
        }
        if let Some(error) = &self.startup_error {
            if env.header.schema == SCHEMA_HOME_V1 {
                return reply_protocol_error(&env, "home_recovery_failed", error.clone(), false);
            }
            if env.header.schema == SCHEMA_JOB_V1 {
                return reply(
                    &env,
                    SCHEMA_JOB_V1,
                    &JobMessageV1::Error {
                        error: ProtocolErrorV1 {
                            code: "home_inactive".into(),
                            message: error.clone(),
                            retryable: false,
                        },
                    },
                );
            }
            return Outcome::none();
        }
        if env.header.schema != SCHEMA_HOME_V1 {
            if let Some(home) = self.active.as_mut() {
                return home.handle(env);
            }
            if env.header.schema == SCHEMA_JOB_V1 {
                return reply(
                    &env,
                    SCHEMA_JOB_V1,
                    &JobMessageV1::Error {
                        error: ProtocolErrorV1 {
                            code: "home_inactive".into(),
                            message: "destination Home is staged but not activated".into(),
                            retryable: true,
                        },
                    },
                );
            }
            return Outcome::none();
        }
        let Ok(message) = serde_json::from_slice::<HomeMessageV1>(&env.payload) else {
            return reply_protocol_error(
                &env,
                "invalid_message",
                "cannot decode Home custody message".into(),
                false,
            );
        };
        match message {
            HomeMessageV1::Stage { prepared } => match stage_handoff_with_rewrapper(
                &self.config,
                self.signer.clone(),
                self.checkpoint_blobs.as_ref(),
                *prepared,
                self.rewrapper.clone(),
            ) {
                Ok(staged) => {
                    if let Err(error) = merge_current_authority(&mut self.config) {
                        return reply_error(&env, error);
                    }
                    reply(&env, SCHEMA_HOME_V1, &HomeMessageV1::Staged { staged: Box::new(staged) })
                }
                Err(error) => reply_error(&env, error),
            },
            HomeMessageV1::Activate { staged } => self.activate(&env, *staged),
            HomeMessageV1::Status { home } if home == self.config.home => {
                match destination_custody_status(&self.config, self.signer.clone()) {
                    Ok(status) => reply(
                        &env,
                        SCHEMA_HOME_V1,
                        &HomeMessageV1::StatusResult { status: Box::new(status) },
                    ),
                    Err(error) => reply_error(&env, error),
                }
            }
            HomeMessageV1::Status { .. } => reply_protocol_error(
                &env,
                "not_found",
                "custody adapter is configured for another Home".into(),
                false,
            ),
            other @ (HomeMessageV1::Prepare { .. }
            | HomeMessageV1::Prepared { .. }
            | HomeMessageV1::Staged { .. }
            | HomeMessageV1::Activated { .. }
            | HomeMessageV1::StatusResult { .. }
            | HomeMessageV1::Error { .. }) => {
                self.active.as_mut().map_or_else(Outcome::none, |home| {
                    let mut forwarded = env;
                    forwarded.payload = aether::wire::to_bytes(&other);
                    home.handle(forwarded)
                })
            }
        }
    }
}

fn routed_creature(
    local_realm: &str,
    local_node: &str,
    realm: &str,
    node: &str,
    coordinator: &str,
) -> Option<Address> {
    let raw = coordinator.parse::<u64>().ok()?;
    if raw == 0 || raw.to_string() != coordinator {
        return None;
    }
    let creature = CreatureId(raw);
    Some(if realm == local_realm && node == local_node {
        Address::Creature(creature)
    } else if realm == local_realm {
        Address::Node(NodeId(node.to_string()), creature)
    } else {
        Address::Omega {
            realm: RealmId::new(realm),
            target: Box::new(Address::Node(NodeId(node.to_string()), creature)),
        }
    })
}

fn reply<T: Serialize>(env: &Envelope, schema: &str, message: &T) -> Outcome {
    Outcome::send(Dispatch::reply_to_env(env, aether::wire::to_bytes(message)).with_schema(schema))
}

fn reply_error(env: &Envelope, error: HomeError) -> Outcome {
    let retryable = matches!(error, HomeError::Journal(_) | HomeError::Capacity(_));
    let code = match error {
        HomeError::Unauthorized(_) => "unauthorized",
        HomeError::NotFound(_) => "not_found",
        HomeError::Conflict(_) => "conflict",
        HomeError::Capacity(_) => "capacity",
        HomeError::Journal(_) => "storage",
        HomeError::Configuration(_)
        | HomeError::Invalid(_)
        | HomeError::State(_)
        | HomeError::Signing(_) => "invalid",
    };
    reply_protocol_error(env, code, error.to_string(), retryable)
}

fn reply_protocol_error(
    env: &Envelope,
    code: &str,
    mut message: String,
    retryable: bool,
) -> Outcome {
    if message.len() > MAX_REASON_BYTES {
        let mut end = MAX_REASON_BYTES;
        while !message.is_char_boundary(end) {
            end -= 1;
        }
        message.truncate(end);
    }
    reply(
        env,
        SCHEMA_HOME_V1,
        &HomeMessageV1::Error { error: ProtocolErrorV1 { code: code.into(), message, retryable } },
    )
}
