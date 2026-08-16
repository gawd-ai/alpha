//! Frozen schema names, role names, and pressure caps.

pub const SCHEMA_FUNCTION_DEPLOY_V1: &str = "gawd.function.deploy.v1";
pub const SCHEMA_JOB_V1: &str = "gawd.function.job.v1";
pub const SCHEMA_EXECUTE_V1: &str = "gawd.function.execute.v1";
pub const SCHEMA_CALL_V1: &str = "gawd.function.call.v1";
pub const SCHEMA_HOME_V1: &str = "gawd.function.home.v1";
/// Domain for destination-local data-key rewrap requests and receipts during Home custody moves.
pub const SCHEMA_CUSTODY_REWRAP_V1: &str = "gawd.function.custody.rewrap.v1";
pub const SCHEMA_LOCATE_V1: &str = "gawd.function.locate.v1";
pub const SCHEMA_POLICY_V1: &str = "gawd.function.policy.v1";

pub const FUNCTION_HOME_ROLE: &str = "function-home";
pub const FUNCTION_EXECUTOR_ROLE: &str = "function-executor";
pub const FUNCTION_RESOLVER_ROLE: &str = "function-resolver";
pub const FUNCTION_LOCATOR_ROLE: &str = "function-locator";
pub const FUNCTION_POLICY_ROLE: &str = "function-policy";

pub const MAX_INLINE_SCHEMA_BYTES: usize = 64 * 1024;
pub const MAX_INLINE_VALUE_BYTES: usize = 64 * 1024;
pub const MAX_PROGRESS_BYTES: usize = 64 * 1024;
pub const MAX_ERROR_BYTES: usize = 64 * 1024;
pub const MAX_JOB_MESSAGE_BYTES: usize = 1024 * 1024;
/// Maximum signed private-read `JobMessageV1` size emitted by a Home. The remaining 64 KiB of the
/// general Job-message budget is reserved for the complete relay proof and control/surface result
/// wrapper, so snapshots and event pages remain transportable without dropping their signatures.
pub const MAX_PRIVATE_READ_MESSAGE_BYTES: usize = MAX_JOB_MESSAGE_BYTES - 64 * 1024;
pub const MAX_JOB_ATTEMPTS: u8 = 64;
pub const MAX_JOB_DELEGATES: usize = 32;
pub const MAX_EVIDENCE_REFS: usize = 32;
pub const MAX_RESULT_RECIPIENTS: usize = 32;
/// Maximum unique Home-addressed sealed values covered by one custody rewrap proof.
pub const MAX_CUSTODY_REWRAP_ITEMS: usize = 64;
pub const MAX_EVENT_PAGE_ITEMS: usize = 256;
/// Maximum persisted Progress + Checkpoint observations for one execution attempt. Terminal and
/// control receipts do not consume this budget, so an over-chatty target can still finish cleanly.
pub const MAX_ATTEMPT_OBSERVATIONS: usize = 256;
/// Maximum unique cooperative controls retained for one Job at its Home and for one Attempt at an
/// executor. Exact ControlId retries and acknowledgements of retained controls remain valid at the
/// limit.
pub const MAX_JOB_CONTROLS: usize = 256;
/// Maximum recovery dispatches synchronously emitted by one executor recovery poke/bind. Durable
/// pending controls remain indexed and later pokes continue from a rotating volatile cursor.
pub const MAX_EXECUTOR_RECOVERY_DISPATCHES: usize = 64;
/// Maximum durable Home recovery work items emitted by one bind/manual batch. A bound Home uses
/// one authenticated self-poke per batch to finish the captured finite sweep.
pub const MAX_HOME_RECOVERY_DISPATCHES: usize = 64;
pub const MAX_CAUSAL_LINKS: usize = 32;
pub const MAX_ID_BYTES: usize = 256;
pub const MAX_NAME_BYTES: usize = 128;
pub const MAX_VERSION_BYTES: usize = 128;
pub const MAX_MEDIA_TYPE_BYTES: usize = 256;
pub const MAX_REASON_BYTES: usize = 4096;
pub const MAX_IDEMPOTENCY_KEY_BYTES: usize = 256;
pub const MAX_SIGNATURE_BYTES: usize = 512;
pub const MAX_PUBLIC_KEY_BYTES: usize = 512;

pub const JOB_ID_DOMAIN_V1: &[u8] = b"gawd.job.id.v1\0";
pub const DEPLOYMENT_ID_DOMAIN_V1: &str = "gawd.deployment.id.v1";
