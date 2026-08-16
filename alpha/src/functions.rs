//! Explicit outer composition for the reference Function/Job organs.
//!
//! The ordinary Alpha boot remains unchanged: Function roles are sockets and are unbound until an
//! operator selects fillings. `alpha node --functions <config.json>` selects this bounded reference
//! composition. The config contains public proof material and paths to node-local operational key
//! files. In particular, it has no field for an Abode root private key: callers (or a root service
//! inside the Abode boundary) sign submissions and epoch/custody grants externally.

use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Weak};
use std::time::Duration;

use aether::{Creature, CreatureId, RealmId, Role};
use bestiary::{BestiaryStore, CatalogEntry, DeterministicCurator, FsBestiaryStore};
use bestiary_daemon::{BestiaryConfig, BestiaryDaemon};
use function_executor::{
    DeploymentAdmission, DeploymentLiveness, ExecutorConfig, FunctionExecutor, StringAddressing,
};
use function_home::{FunctionHome, FunctionMetadata, FunctionTrust, HomeConfig};
use function_locator::{FunctionLocator, LocatorCaps};
use function_resolver::{FunctionCatalog, FunctionResolver};
use gawdfn::{
    validate_ed25519_public_key, AuthoritySigner, DeploymentReceiptV1, DeploymentRegistrationV1,
    Ed25519SeedSigner, EffectClassV1, FunctionSelectorV1, HomeAuthorityV1, HomeId,
    OperationalCapabilityV1, PlacementDecisionV1, ResolutionReceiptV1, ResolveRequestV1,
    RetryDecisionV1, SignedRecordV1, UndeployRequestV1, FUNCTION_EXECUTOR_ROLE, FUNCTION_HOME_ROLE,
    FUNCTION_LOCATOR_ROLE, FUNCTION_POLICY_ROLE, FUNCTION_RESOLVER_ROLE,
};
use job_blob_fs::{BlobCaps, FsJobBlobStore};
use policy_job_basic::{BasicJobPolicy, BasicPolicyCaps};
use sanctum::Kernel;
use serde::Deserialize;
use sigil::Ed25519KeyMaterial;

/// Maximum public Function runtime configuration bytes read at startup.
pub const MAX_FUNCTION_CONFIG_BYTES: u64 = 1024 * 1024;
/// A seed file contains exactly one 32-byte Ed25519 seed as 64 hexadecimal characters plus
/// optional surrounding ASCII whitespace.
pub const MAX_FUNCTION_SEED_FILE_BYTES: u64 = 256;
/// Persistent, protected inode on which one opt-in runtime takes its process-lifetime lock.
const FUNCTION_STATE_LOCK_FILE: &str = ".alpha-functions.lock";
/// Bound durable Function-catalog history without coupling local maintenance to replication. The
/// hourly cadence avoids repeatedly reading the bounded artifact snapshot and rewriting a quiet
/// catalog merely to save a small amount of journal history.
const FUNCTION_BESTIARY_COMPACTION_INTERVAL: Duration = Duration::from_secs(60 * 60);

fn function_bestiary_config() -> BestiaryConfig {
    let mut config = BestiaryConfig::local();
    config.compaction_interval = FUNCTION_BESTIARY_COMPACTION_INTERVAL;
    config
}

/// Public proof/configuration plus references to separately custodied operational secrets.
///
/// Relative paths are resolved against the directory containing this file, not the process's
/// working directory. Unknown fields are refused so a misspelled security setting cannot be
/// silently ignored.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionRuntimeConfig {
    pub version: u8,
    pub state_dir: PathBuf,
    pub realm: String,
    pub node: String,
    pub authority: HomeAuthorityV1,
    #[serde(default)]
    pub historical_authorities: Vec<HomeAuthorityV1>,
    pub home_operational_key_file: PathBuf,
    pub resolver: OperationalSignerRef,
    pub executor: OperationalSignerRef,
    pub policy: OperationalSignerRef,
    pub deployer: OperationalSignerRef,
    pub catalog: OperationalSignerRef,
}

/// One explicitly pinned operational identity and the protected seed file that must realize it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationalSignerRef {
    pub public_key: String,
    pub seed_file: PathBuf,
}

/// IDs and the one operational signer the outer control composition must retain.
pub struct FunctionRuntime {
    pub home: HomeId,
    pub catalog: CreatureId,
    pub resolver: CreatureId,
    pub executor: CreatureId,
    pub locator: CreatureId,
    pub policy: CreatureId,
    pub home_creature: CreatureId,
    pub function_deployer: Arc<dyn AuthoritySigner>,
    // Dropping this handle releases the OS lock. The node keeps `FunctionRuntime` alive for as long
    // as its loaded Function organs, preventing a second writer from opening the same state tree.
    _state_lock: fs::File,
}

/// Read and validate an opt-in runtime config. This performs no kernel mutation.
pub fn load_config(path: impl AsRef<Path>) -> Result<FunctionRuntimeConfig, String> {
    let path = path.as_ref();
    let text =
        super::read_text_file_bounded(path, MAX_FUNCTION_CONFIG_BYTES, "Function runtime config")?;
    let mut config: FunctionRuntimeConfig = serde_json::from_str(&text)
        .map_err(|error| format!("Function runtime config {}: {error}", path.display()))?;
    if config.version != 1 {
        return Err(format!(
            "Function runtime config version {} is unsupported (expected 1)",
            config.version
        ));
    }
    if config.state_dir.as_os_str().is_empty()
        || config.realm.trim().is_empty()
        || config.node.trim().is_empty()
    {
        return Err("Function runtime state_dir, realm, and node must be non-empty".into());
    }
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    resolve_relative(&mut config.state_dir, base);
    resolve_relative(&mut config.home_operational_key_file, base);
    for (label, signer) in [
        ("resolver", &mut config.resolver),
        ("executor", &mut config.executor),
        ("Function policy", &mut config.policy),
        ("function deployer", &mut config.deployer),
        ("Bestiary journal", &mut config.catalog),
    ] {
        validate_ed25519_public_key(label, &signer.public_key)
            .map_err(|error| format!("Function runtime config: {error}"))?;
        resolve_relative(&mut signer.seed_file, base);
    }
    Ok(config)
}

/// Load the durable reference organs and bind their contract-owned roles.
///
/// All validation and secret reads happen before the first creature is loaded. A corrupt Bestiary,
/// wrong journal key, invalid Home authority chain, insecure key file, or mismatched node identity
/// therefore refuses startup rather than leaving a knowingly partial Function runtime.
pub fn boot(
    kernel: &Arc<Kernel>,
    mut config: FunctionRuntimeConfig,
    command_node: Option<&str>,
) -> Result<FunctionRuntime, String> {
    if let Some(command_node) = command_node {
        if command_node != config.node {
            return Err(format!(
                "Function runtime node `{}` does not match --node-id `{command_node}`",
                config.node
            ));
        }
    }

    let home = config.authority.abode.payload.abode.clone();
    let epoch = config.authority.operational.payload.epoch;
    config
        .authority
        .verify(&home, epoch, OperationalCapabilityV1::JobHome)
        .map_err(|error| format!("Home authority: {error}"))?;
    config
        .authority
        .verify(&home, epoch, OperationalCapabilityV1::JobControl)
        .map_err(|error| format!("Home authority: {error}"))?;
    // Refuse an explicitly root-valued or reused operational identity before opening any secret
    // file. The Home key's public pin lives in the root-signed authority; every other pin is an
    // explicit public config field beside its seed-file reference.
    reject_root_or_reused_keys(
        &home,
        [
            config.authority.operational.payload.operational_public_key.as_str(),
            config.resolver.public_key.as_str(),
            config.executor.public_key.as_str(),
            config.policy.public_key.as_str(),
            config.deployer.public_key.as_str(),
            config.catalog.public_key.as_str(),
        ],
    )?;

    // Resolve and validate the directory, then take its one-writer guard before opening even the
    // operational seed files. Every durable organ below uses this canonical path, so lexical aliases
    // cannot accidentally obtain different lock files for the same state tree.
    config.state_dir = prepare_private_state_dir(&config.state_dir)?;
    let state_lock = acquire_state_lock(&config.state_dir)?;

    let seeds = Seeds::read(&config)?;
    let home_signer = Arc::new(Ed25519SeedSigner::from_seed(seeds.home).map_err(contract)?);
    let resolver_signer = Arc::new(Ed25519SeedSigner::from_seed(seeds.resolver).map_err(contract)?);
    let executor_signer = Arc::new(Ed25519SeedSigner::from_seed(seeds.executor).map_err(contract)?);
    let policy_signer = Arc::new(Ed25519SeedSigner::from_seed(seeds.policy).map_err(contract)?);
    let deployer_signer = Arc::new(Ed25519SeedSigner::from_seed(seeds.deployer).map_err(contract)?);
    let catalog_key = Ed25519KeyMaterial::from_seed(seeds.catalog)
        .map_err(|error| format!("catalog operational key: {error}"))?;
    configured_key(
        home_signer.public_key(),
        &config.authority.operational.payload.operational_public_key,
        "Home operational key file",
    )?;
    configured_key(resolver_signer.public_key(), &config.resolver.public_key, "resolver key file")?;
    configured_key(executor_signer.public_key(), &config.executor.public_key, "executor key file")?;
    configured_key(
        policy_signer.public_key(),
        &config.policy.public_key,
        "Function policy key file",
    )?;
    configured_key(
        deployer_signer.public_key(),
        &config.deployer.public_key,
        "function deployer key file",
    )?;
    configured_key(
        catalog_key.public_hex(),
        &config.catalog.public_key,
        "Bestiary journal key file",
    )?;
    // Stage every fallible durable open and constructor before mutating the Kernel. A later
    // `load_instance` can still fail (and the node then shuts the partial composition down), but
    // corrupt state, bad authority, or wrong keys cannot leave a process serving half a runtime.
    let catalog_store = Arc::new(
        FsBestiaryStore::new(config.state_dir.join("bestiary"), catalog_key)
            .map_err(|error| format!("durable Function Bestiary: {error}"))?,
    );
    catalog_store
        .recover()
        .map_err(|error| format!("durable Function Bestiary recovery: {error}"))?;
    let catalog_view: Arc<dyn BestiaryStore> = catalog_store;
    let catalog_daemon = BestiaryDaemon::new(
        catalog_view.clone(),
        Arc::new(DeterministicCurator::default()),
        function_bestiary_config(),
    );
    let catalog_adapter = Arc::new(DurableFunctionCatalog { store: catalog_view });
    let resolver_organ = FunctionResolver::new(resolver_signer.clone(), catalog_adapter.clone());

    let executor_config =
        ExecutorConfig::new(config.state_dir.join("executor"), executor_signer.public_key())
            .with_location(&config.realm, &config.node, "auto");
    let executor_organ = FunctionExecutor::open_with_liveness(
        executor_config,
        executor_signer.clone(),
        Arc::new(StringAddressing),
        Arc::new(PinnedDeploymentAdmission {
            owner: home.clone(),
            deployer: deployer_signer.public_key().to_string(),
            resolver: resolver_signer.public_key().to_string(),
        }),
        Arc::new(KernelDeploymentLiveness { kernel: Arc::downgrade(kernel) }),
    )
    .map_err(|error| format!("function-executor: {error}"))?;

    let locator_organ =
        FunctionLocator::open(config.state_dir.join("locator"), LocatorCaps::default())
            .map_err(|error| format!("function-locator: {error}"))?;

    let policy_organ = BasicJobPolicy::new(policy_signer.clone(), BasicPolicyCaps::default())
        .map_err(|error| format!("policy-job-basic: {error}"))?;

    let blobs = Arc::new(
        FsJobBlobStore::open(config.state_dir.join("blobs"), BlobCaps::default())
            .map_err(|error| format!("job-blob-fs: {error}"))?,
    );
    let mut home_config =
        HomeConfig::for_creature(config.state_dir.join("home"), home.clone(), config.authority)
            .with_location(&config.realm, &config.node);
    home_config.epoch = epoch;
    home_config.historical_authorities = config.historical_authorities;
    let trust = Arc::new(PinnedFunctionTrust {
        resolver: resolver_signer.public_key().to_string(),
        executor: executor_signer.public_key().to_string(),
        policy: policy_signer.public_key().to_string(),
        read_relay: deployer_signer.public_key().to_string(),
    });
    let home_organ = FunctionHome::open_with_checkpoint_store(
        home_config,
        home_signer,
        catalog_adapter,
        trust,
        blobs.clone(),
        blobs,
    )
    .map_err(|error| format!("function-home: {error}"))?;

    // REGISTRY: replace the default in-memory seed with the recovered durable Bestiary. The same
    // store handle is injected read-only into resolver/metadata, so publish and resolve cannot drift.
    let catalog = load(kernel, "bestiary-daemon", Box::new(catalog_daemon))?;
    kernel.bind_role(Role::new(Role::REGISTRY), catalog);

    let resolver = load(kernel, "function-resolver", Box::new(resolver_organ))?;
    kernel.bind_role(Role::new(FUNCTION_RESOLVER_ROLE), resolver);

    let executor = load(kernel, "function-executor", Box::new(executor_organ))?;
    kernel.bind_remote_role(Role::new(FUNCTION_EXECUTOR_ROLE), executor);

    let locator = load(kernel, "function-locator", Box::new(locator_organ))?;
    kernel.bind_role(Role::new(FUNCTION_LOCATOR_ROLE), locator);

    let policy = load(kernel, "policy-job-basic", Box::new(policy_organ))?;
    kernel.bind_role(Role::new(FUNCTION_POLICY_ROLE), policy);

    let home_creature = load(kernel, "function-home", Box::new(home_organ))?;
    kernel.bind_role(Role::new(FUNCTION_HOME_ROLE), home_creature);

    Ok(FunctionRuntime {
        home,
        catalog,
        resolver,
        executor,
        locator,
        policy,
        home_creature,
        function_deployer: deployer_signer,
        _state_lock: state_lock,
    })
}

fn load(kernel: &Kernel, name: &str, creature: Box<dyn Creature>) -> Result<CreatureId, String> {
    kernel
        .load_instance(omni::boot_manifest(name), creature)
        .map_err(|error| format!("{name}: {error}"))
}

fn resolve_relative(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

fn contract(error: gawdfn::ContractError) -> String {
    error.to_string()
}

struct Seeds {
    home: [u8; 32],
    resolver: [u8; 32],
    executor: [u8; 32],
    policy: [u8; 32],
    deployer: [u8; 32],
    catalog: [u8; 32],
}

impl Seeds {
    fn read(config: &FunctionRuntimeConfig) -> Result<Self, String> {
        Ok(Self {
            home: read_seed(&config.home_operational_key_file, "Home operational")?,
            resolver: read_seed(&config.resolver.seed_file, "resolver")?,
            executor: read_seed(&config.executor.seed_file, "executor")?,
            policy: read_seed(&config.policy.seed_file, "Function policy")?,
            deployer: read_seed(&config.deployer.seed_file, "function deployer")?,
            catalog: read_seed(&config.catalog.seed_file, "Bestiary journal")?,
        })
    }
}

fn read_seed(path: &Path, label: &str) -> Result<[u8; 32], String> {
    let path_meta = fs::symlink_metadata(path)
        .map_err(|error| format!("{label} key file {}: {error}", path.display()))?;
    if path_meta.file_type().is_symlink() || !path_meta.is_file() {
        return Err(format!(
            "{label} key file {} must be a regular non-symlink file",
            path.display()
        ));
    }
    let file = fs::File::open(path)
        .map_err(|error| format!("{label} key file {}: {error}", path.display()))?;
    let opened_meta =
        file.metadata().map_err(|error| format!("{label} key file {}: {error}", path.display()))?;
    if !opened_meta.is_file() {
        return Err(format!("{label} key file {} must be a regular file", path.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // Compare the already-open file with the path metadata. The subsequent read uses this open
        // descriptor, so a path swap cannot redirect the bytes after validation.
        if path_meta.dev() != opened_meta.dev() || path_meta.ino() != opened_meta.ino() {
            return Err(format!("{label} key file {} changed while opening", path.display()));
        }
        let mode = opened_meta.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "{label} key file {} is accessible by group/other (mode {:o}); require 0600 or stricter",
                path.display(),
                mode & 0o777
            ));
        }
    }
    if opened_meta.len() > MAX_FUNCTION_SEED_FILE_BYTES {
        return Err(format!(
            "{label} key file {} is {} bytes, exceeds {} byte limit",
            path.display(),
            opened_meta.len(),
            MAX_FUNCTION_SEED_FILE_BYTES
        ));
    }
    let mut bytes = Vec::with_capacity(opened_meta.len() as usize);
    file.take(MAX_FUNCTION_SEED_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{label} key file {}: {error}", path.display()))?;
    if bytes.len() as u64 > MAX_FUNCTION_SEED_FILE_BYTES {
        return Err(format!(
            "{label} key file {} exceeds {} byte limit",
            path.display(),
            MAX_FUNCTION_SEED_FILE_BYTES
        ));
    }
    let encoded = String::from_utf8(bytes)
        .map_err(|error| format!("{label} key file {} is not UTF-8: {error}", path.display()))?;
    let encoded = encoded.trim();
    if encoded.len() != 64 {
        return Err(format!("{label} key file must contain exactly 64 hexadecimal characters"));
    }
    let decoded = sigil::crypto::hex_decode(encoded)
        .ok_or_else(|| format!("{label} key file is not valid hexadecimal"))?;
    decoded.try_into().map_err(|_| format!("{label} key file must decode to exactly 32 bytes"))
}

fn reject_root_or_reused_keys<'a>(
    root: &HomeId,
    operational: impl IntoIterator<Item = &'a str>,
) -> Result<(), String> {
    let mut seen = BTreeSet::new();
    for key in operational {
        if key == root.as_str() {
            return Err(
                "an operational key equals the Abode root key; refusing to load root private material into the Function runtime"
                    .into(),
            );
        }
        if !seen.insert(key.to_string()) {
            return Err("Function runtime operational keys must be distinct custody domains".into());
        }
    }
    Ok(())
}

fn prepare_private_state_dir(path: &Path) -> Result<PathBuf, String> {
    if !path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700);
            builder
                .create(path)
                .map_err(|error| format!("Function state dir {}: {error}", path.display()))?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path)
            .map_err(|error| format!("Function state dir {}: {error}", path.display()))?;
    }
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Function state dir {}: {error}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!(
            "Function state dir {} must be a non-symlink directory",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "Function state dir {} is accessible by group/other (mode {:o}); require 0700 or stricter",
                path.display(),
                mode & 0o777
            ));
        }
    }

    // Use the resolved directory for both the lock and every durable store. This also removes `..`
    // and ancestor-symlink aliases that could otherwise make one state tree appear to have multiple
    // lock paths.
    let resolved = fs::canonicalize(path)
        .map_err(|error| format!("Function state dir {}: {error}", path.display()))?;
    let resolved_metadata = fs::symlink_metadata(&resolved)
        .map_err(|error| format!("Function state dir {}: {error}", resolved.display()))?;
    if resolved_metadata.file_type().is_symlink() || !resolved_metadata.is_dir() {
        return Err(format!(
            "Function state dir {} did not resolve to a directory",
            resolved.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != resolved_metadata.dev() || metadata.ino() != resolved_metadata.ino() {
            return Err(format!("Function state dir {} changed while resolving", path.display()));
        }
    }
    Ok(resolved)
}

fn acquire_state_lock(state_dir: &Path) -> Result<fs::File, String> {
    let path = state_dir.join(FUNCTION_STATE_LOCK_FILE);
    let before = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "Function state lock {} must be a regular non-symlink file",
                    path.display()
                ));
            }
            Some(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(format!("Function state lock {}: {error}", path.display()));
        }
    };

    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|error| format!("Function state lock {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("Function state lock {}: {error}", path.display()))?;
    let at_path = fs::symlink_metadata(&path)
        .map_err(|error| format!("Function state lock {}: {error}", path.display()))?;
    if at_path.file_type().is_symlink() || !opened.is_file() || !at_path.is_file() {
        return Err(format!(
            "Function state lock {} must be a regular non-symlink file",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // Check both a pre-existing path and the path after opening against the descriptor that we
        // actually retain. The state directory is private, but this also closes same-user path-swap
        // mistakes during startup.
        if before.as_ref().is_some_and(|metadata| {
            metadata.dev() != opened.dev() || metadata.ino() != opened.ino()
        }) || at_path.dev() != opened.dev()
            || at_path.ino() != opened.ino()
        {
            return Err(format!("Function state lock {} changed while opening", path.display()));
        }
        let mode = opened.permissions().mode();
        if mode & 0o077 != 0 {
            return Err(format!(
                "Function state lock {} is accessible by group/other (mode {:o}); require 0600 or stricter",
                path.display(),
                mode & 0o777
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = before;

    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(format!(
            "Function state dir {} is already in use by another Alpha Function runtime (exclusive lock {})",
            state_dir.display(),
            path.display()
        )),
        Err(fs::TryLockError::Error(error)) => Err(format!(
            "Function state lock {} could not be acquired exclusively: {error}",
            path.display()
        )),
    }
}

struct DurableFunctionCatalog {
    store: Arc<dyn BestiaryStore>,
}

impl DurableFunctionCatalog {
    fn realm_for(&self, selector: &FunctionSelectorV1) -> Option<RealmId> {
        match selector {
            // Aliases are explicitly Realm-scoped. An immutable FunctionId is not: the same signed
            // creature may be available in any number of Realms, and identical availability rows
            // collapse to the same function/artifact pin in the resolver.
            FunctionSelectorV1::Alias { alias } => Some(RealmId::new(&alias.realm)),
            FunctionSelectorV1::Id { .. } => None,
        }
    }

    fn entries(&self, selector: &FunctionSelectorV1) -> Result<Vec<CatalogEntry>, String> {
        let realm = self.realm_for(selector);
        self.store.list_metadata(realm.as_ref()).map_err(|error| error.to_string())
    }
}

impl FunctionCatalog for DurableFunctionCatalog {
    fn candidates(&self, request: &ResolveRequestV1) -> Result<Vec<CatalogEntry>, String> {
        self.entries(&request.selector)
    }
}

impl FunctionMetadata for DurableFunctionCatalog {
    fn effect(&self, function: &gawdfn::ResolvedFunctionV1) -> EffectClassV1 {
        self.entries(&function.requested)
            .ok()
            .and_then(|entries| {
                entries.into_iter().find_map(|entry| {
                    (entry.manifest.compute_content_address()
                        == function.function.manifest_content_address)
                        .then(|| {
                            entry
                                .manifest
                                .entrypoints
                                .into_iter()
                                .find(|candidate| candidate.name == function.function.entrypoint)
                                .and_then(|candidate| candidate.contract)
                                .map(|contract| contract.effect)
                        })
                        .flatten()
                })
            })
            .unwrap_or(EffectClassV1::Unknown)
    }
}

struct PinnedFunctionTrust {
    resolver: String,
    executor: String,
    policy: String,
    read_relay: String,
}

impl FunctionTrust for PinnedFunctionTrust {
    fn allow_resolution(
        &self,
        resolution: &SignedRecordV1<ResolutionReceiptV1>,
    ) -> Result<(), String> {
        exact_key(&resolution.signer, &self.resolver, "resolver")
    }

    fn allow_deployment(
        &self,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        exact_key(&deployment.signer, &self.executor, "executor")
    }

    fn allow_executor_receipt(
        &self,
        receipt: &SignedRecordV1<gawdfn::ExecutionReceiptV1>,
        deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        exact_key(&receipt.signer, &self.executor, "executor receipt")?;
        exact_key(&deployment.signer, &self.executor, "deployment executor")
    }

    fn allow_placement_decision(
        &self,
        decision: &SignedRecordV1<PlacementDecisionV1>,
    ) -> Result<(), String> {
        exact_key(&decision.signer, &self.policy, "placement policy")
    }

    fn allow_retry_decision(
        &self,
        decision: &SignedRecordV1<RetryDecisionV1>,
    ) -> Result<(), String> {
        exact_key(&decision.signer, &self.policy, "retry policy")
    }

    fn allow_read_relay(&self, relay: &str, caller: &str) -> Result<(), String> {
        if relay == caller {
            Ok(())
        } else {
            exact_key(relay, &self.read_relay, "job read relay")
        }
    }
}

fn exact_key(actual: &str, expected: &str, label: &str) -> Result<(), String> {
    (actual == expected)
        .then_some(())
        .ok_or_else(|| format!("{label} key is not the configured trust anchor"))
}

fn configured_key(actual: &str, expected: &str, label: &str) -> Result<(), String> {
    (actual == expected)
        .then_some(())
        .ok_or_else(|| format!("{label} does not derive its configured public key"))
}

struct PinnedDeploymentAdmission {
    owner: HomeId,
    deployer: String,
    resolver: String,
}

impl DeploymentAdmission for PinnedDeploymentAdmission {
    fn register(&self, request: &SignedRecordV1<DeploymentRegistrationV1>) -> Result<(), String> {
        exact_key(&request.signer, &self.deployer, "deployment attester")?;
        exact_key(&request.payload.resolution.signer, &self.resolver, "deployment resolver")?;
        (request.payload.authorization.payload.requested_by == self.owner)
            .then_some(())
            .ok_or_else(|| "deployment was not authorized by this Function Home's Abode".into())
    }

    fn undeploy(
        &self,
        request: &SignedRecordV1<UndeployRequestV1>,
        _deployment: &SignedRecordV1<DeploymentReceiptV1>,
    ) -> Result<(), String> {
        // `UndeployRequestV1` has no nested root authorization record. In this reference
        // composition it is therefore an operational deployer action, and the executor's prior
        // structural check already binds `request.signer == requested_by`.
        exact_key(&request.signer, &self.deployer, "undeployment attester")
    }
}

struct KernelDeploymentLiveness {
    kernel: Weak<Kernel>,
}

impl DeploymentLiveness for KernelDeploymentLiveness {
    fn target_is_live(
        &self,
        target: CreatureId,
        deployment: &DeploymentReceiptV1,
    ) -> Result<bool, String> {
        let kernel = self
            .kernel
            .upgrade()
            .ok_or_else(|| "the composing Kernel is no longer available".to_string())?;
        let Some(identity) = kernel.loaded_manifest_identity(target) else { return Ok(false) };
        let Some(deployment_hash) = normalized_sha256(&deployment.artifact_hash) else {
            return Ok(false);
        };
        let Some(loaded_hash) = identity.artifact_sha256.as_deref().and_then(normalized_sha256)
        else {
            return Ok(false);
        };
        Ok(identity.manifest_content_address.as_deref()
            == Some(deployment.function.manifest_content_address.as_str())
            && loaded_hash == deployment_hash)
    }
}

fn normalized_sha256(value: &str) -> Option<&str> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    (raw.len() == 64
        && raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then_some(raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use aether::{Deadline, Ed25519Signer, Ed25519Verifier};
    use anima::{NativeEngine, ScriptEngine, WasmEngine};
    use gawdfn::{
        sha256_digest, AbodeKeyBindingV1, DeliveryModeV1, DeploymentQueryV1, DeploymentRequestV1,
        EffectClassV1, EntrypointContractV1, FunctionId, JobAccessV1, JobSubmitV1,
        OperationalKeyGrantV1, SchemaRefV1, ValueRefV1, SCHEMA_FUNCTION_DEPLOY_V1, SCHEMA_HOME_V1,
        SCHEMA_JOB_V1,
    };
    use omni::{AiControl, Verb, VerbCtx};
    use policy_dev::DevPolicy;
    use sigil::{Backend, Entrypoint, Manifest};

    static NEXT_ROOT: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn function_bestiary_compacts_locally_without_enabling_replication() {
        let config = function_bestiary_config();
        assert_eq!(config.anti_entropy_interval, Duration::ZERO);
        assert!(config.replication_peers.is_empty());
        assert_eq!(config.compaction_interval, FUNCTION_BESTIARY_COMPACTION_INTERVAL);
        assert!(config.compaction_interval > Duration::ZERO);
    }

    struct TempRoot(PathBuf);

    impl TempRoot {
        fn new() -> Self {
            let n = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir()
                .join(format!("alpha-function-composition-{}-{n}", std::process::id()));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn seed_file(root: &Path, name: &str, byte: u8) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, sigil::crypto::hex_encode(&[byte; 32])).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    fn authority(root: &Ed25519SeedSigner, home: &Ed25519SeedSigner) -> HomeAuthorityV1 {
        let id = HomeId::new(root.public_key());
        HomeAuthorityV1 {
            abode: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                AbodeKeyBindingV1 {
                    abode: id.clone(),
                    root_public_key: root.public_key().to_string(),
                    issued_at_unix_ms: None,
                },
                root,
            )
            .unwrap(),
            operational: SignedRecordV1::sign(
                SCHEMA_HOME_V1,
                OperationalKeyGrantV1 {
                    home: id,
                    epoch: 1,
                    operational_public_key: home.public_key().to_string(),
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
            .unwrap(),
            prepared: None,
        }
    }

    fn fixture_config(root: &TempRoot) -> (PathBuf, HomeId) {
        let root_signer = Ed25519SeedSigner::from_seed([1; 32]).unwrap();
        let home_signer = Ed25519SeedSigner::from_seed([2; 32]).unwrap();
        let resolver_signer = Ed25519SeedSigner::from_seed([3; 32]).unwrap();
        let executor_signer = Ed25519SeedSigner::from_seed([4; 32]).unwrap();
        let policy_signer = Ed25519SeedSigner::from_seed([5; 32]).unwrap();
        let deployer_signer = Ed25519SeedSigner::from_seed([6; 32]).unwrap();
        let catalog_signer = Ed25519SeedSigner::from_seed([7; 32]).unwrap();
        let authority = authority(&root_signer, &home_signer);
        let home = authority.abode.payload.abode.clone();
        let keys = root.0.join("keys");
        fs::create_dir_all(&keys).unwrap();
        seed_file(&keys, "home.hex", 2);
        seed_file(&keys, "resolver.hex", 3);
        seed_file(&keys, "executor.hex", 4);
        seed_file(&keys, "policy.hex", 5);
        seed_file(&keys, "deployer.hex", 6);
        seed_file(&keys, "catalog.hex", 7);
        let config = serde_json::json!({
            "version": 1,
            "state_dir": "state",
            "realm": "crew",
            "node": "op",
            "authority": authority,
            "historical_authorities": [],
            "home_operational_key_file": "keys/home.hex",
            "resolver": {
                "public_key": resolver_signer.public_key(),
                "seed_file": "keys/resolver.hex"
            },
            "executor": {
                "public_key": executor_signer.public_key(),
                "seed_file": "keys/executor.hex"
            },
            "policy": {
                "public_key": policy_signer.public_key(),
                "seed_file": "keys/policy.hex"
            },
            "deployer": {
                "public_key": deployer_signer.public_key(),
                "seed_file": "keys/deployer.hex"
            },
            "catalog": {
                "public_key": catalog_signer.public_key(),
                "seed_file": "keys/catalog.hex"
            }
        });
        let path = root.0.join("functions.json");
        fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();
        (path, home)
    }

    fn kernel() -> Arc<Kernel> {
        let node_key = Ed25519KeyMaterial::from_seed([0x44; 32]).unwrap();
        Kernel::new(
            vec![Arc::new(NativeEngine), Arc::new(WasmEngine::new()), Arc::new(ScriptEngine)],
            Arc::new(Ed25519Signer::new(node_key)),
            Arc::new(Ed25519Verifier),
            Arc::new(DevPolicy),
            256,
        )
    }

    #[test]
    fn opt_in_boot_binds_a_reachable_durable_reference_runtime_without_root_key() {
        let root = TempRoot::new();
        let (path, expected_home) = fixture_config(&root);
        let config_text = fs::read_to_string(&path).unwrap();
        assert!(!config_text.contains("root_key_file"));
        assert!(!config_text.contains(&sigil::crypto::hex_encode(&[1; 32])));

        let kernel = kernel();
        let critter = omni::boot_organs_with_monitor(&kernel, false).unwrap();
        assert_eq!(kernel.role_binding(&Role::new(FUNCTION_HOME_ROLE)), None);
        assert_eq!(kernel.role_binding(&Role::new(FUNCTION_EXECUTOR_ROLE)), None);
        let runtime = boot(&kernel, load_config(&path).unwrap(), Some("op")).unwrap();
        assert_eq!(runtime.home, expected_home);
        assert_eq!(kernel.role_binding(&Role::new(Role::REGISTRY)), Some(runtime.catalog));
        assert_eq!(kernel.role_binding(&Role::new(FUNCTION_RESOLVER_ROLE)), Some(runtime.resolver));
        assert_eq!(kernel.role_binding(&Role::new(FUNCTION_EXECUTOR_ROLE)), Some(runtime.executor));
        assert_eq!(
            kernel.role_binding(&Role::new(FUNCTION_HOME_ROLE)),
            Some(runtime.home_creature)
        );
        assert_eq!(
            kernel.router().remote_role_binding(&Role::new(FUNCTION_EXECUTOR_ROLE)),
            Some(runtime.executor),
            "the opt-in Function composition explicitly exposes only its executor socket"
        );
        for local_only_role in [
            Role::REGISTRY,
            FUNCTION_RESOLVER_ROLE,
            FUNCTION_LOCATOR_ROLE,
            FUNCTION_POLICY_ROLE,
            FUNCTION_HOME_ROLE,
        ] {
            assert_eq!(
                kernel.router().remote_role_binding(&Role::new(local_only_role)),
                None,
                "Function composition must keep `{local_only_role}` local-only by default"
            );
        }
        assert!(root.0.join("state/bestiary/log").is_dir());
        assert!(root.0.join("state/home").is_dir());
        assert!(root.0.join("state/executor").is_dir());

        // Drive the ordinary control path all the way through Kernel load and durable executor
        // registration. The caller authorization is still signed outside the node by the fixture
        // Abode root; only the separately configured deployer attests the post-load registration.
        let artifact = b"fn handle(env) { env.payload }";
        let artifact_hash = sha256_digest(artifact);
        let mut manifest =
            Manifest::new("composed-function", "1.0.0", Backend::Critter, "gawd_critter_v1");
        manifest.entrypoints.push(Entrypoint {
            name: "run".into(),
            signature: SCHEMA_FUNCTION_DEPLOY_V1.into(),
            contract: Some(EntrypointContractV1 {
                description: "composition smoke echo".into(),
                input_schema: SchemaRefV1::Inline { schema: serde_json::json!({"type": "object"}) },
                output_schema: SchemaRefV1::Inline {
                    schema: serde_json::json!({"type": "object"}),
                },
                error_schema: None,
                effect: EffectClassV1::Idempotent,
                controls: Default::default(),
            }),
        });
        // Exercise the raw-manifest/prefixed-receipt normalization used by the Kernel liveness
        // adapter. Both spellings name the same canonical sha256 digest.
        manifest.provenance.build_hash = artifact_hash.strip_prefix("sha256:").map(str::to_owned);
        manifest.content_address = Some(manifest.compute_content_address());
        let manifest_path = root.0.join("function.manifest.json");
        let artifact_path = root.0.join("function.rhai");
        fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
        fs::write(&artifact_path, artifact).unwrap();

        let function = FunctionId {
            manifest_content_address: manifest.content_address.clone().unwrap(),
            entrypoint: "run".into(),
        };
        let selector = FunctionSelectorV1::Id { function: function.clone() };
        let root_signer = Ed25519SeedSigner::from_seed([1; 32]).unwrap();
        let resolver_signer = Ed25519SeedSigner::from_seed([3; 32]).unwrap();
        let request = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            DeploymentRequestV1 {
                requested_by: expected_home.clone(),
                function: selector.clone(),
                target_realm: "crew".into(),
                target_node: Some("op".into()),
                evidence: vec![],
                requested_at_unix_ms: None,
            },
            &root_signer,
        )
        .unwrap();
        let resolution = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            ResolutionReceiptV1 {
                selector,
                function,
                artifact_hash,
                resolved_at_unix_ms: None,
                evidence: vec![],
            },
            &resolver_signer,
        )
        .unwrap();
        let (_probe, bus, rx) = kernel.open_endpoint(Default::default());
        let ai = AiControl::new(true);
        let mut ctx = VerbCtx::with_probe(&kernel, &bus, &rx, Some(critter), &ai, false);
        ctx.set_function_deployer(runtime.function_deployer.as_ref());
        let deployed = omni::run_verb(
            Verb::FunctionDeploy {
                request: request.clone(),
                resolution: resolution.clone(),
                manifest_path: manifest_path.to_string_lossy().into_owned(),
                artifact_path: artifact_path.to_string_lossy().into_owned(),
            },
            &mut ctx,
            &mut |_| {},
        );
        assert!(deployed.ok, "Function deployment is usable: {}", deployed.human);
        let target = deployed.json["creature_id"].as_u64().unwrap();
        assert!(kernel.is_loaded(CreatureId(target)));
        let mut deployment: SignedRecordV1<DeploymentReceiptV1> =
            serde_json::from_value(deployed.json["deployment"].clone()).unwrap();

        // The durable lookup filters every row through exact Kernel identity. Seeing this row proves
        // the adapter matched creature id + manifest content address + artifact build hash.
        let result = omni::run_verb(
            Verb::FunctionDeployments {
                query: DeploymentQueryV1 {
                    function: None,
                    realm: Some("crew".into()),
                    node: Some("op".into()),
                    limit: 8,
                },
            },
            &mut ctx,
            &mut |_| {},
        );
        assert!(result.ok, "Function executor is reachable: {}", result.human);
        assert_eq!(result.json["deployments"].as_array().unwrap().len(), 1);

        // Exercise the complete explicit retirement join against the real durable executor. The
        // deployment pins its stable key and target; the executor fsyncs the tombstone before its
        // current-route acknowledgement, and only then may Omni retire the exact loaded bytes.
        let undeploy = SignedRecordV1::sign(
            SCHEMA_FUNCTION_DEPLOY_V1,
            UndeployRequestV1 {
                requested_by: HomeId::new(runtime.function_deployer.public_key()),
                deployment: deployment.payload.deployment.clone(),
                reason: Some("composition smoke retirement".into()),
            },
            runtime.function_deployer.as_ref(),
        )
        .unwrap();
        let retired = omni::run_verb(
            Verb::FunctionUndeploy { request: undeploy, deployment: deployment.clone() },
            &mut ctx,
            &mut |_| {},
        );
        assert!(retired.ok, "Function retirement is usable: {}", retired.human);
        assert_eq!(retired.json["durable_tombstone"], true);
        assert_eq!(retired.json["target_status"], "unloaded");
        assert!(!kernel.is_loaded(CreatureId(target)));
        let after_retirement = omni::run_verb(
            Verb::FunctionDeployments {
                query: DeploymentQueryV1 {
                    function: None,
                    realm: Some("crew".into()),
                    node: Some("op".into()),
                    limit: 8,
                },
            },
            &mut ctx,
            &mut |_| {},
        );
        assert!(after_retirement.ok);
        assert!(after_retirement.json["deployments"].as_array().unwrap().is_empty());

        // Retirement is not hidden auto-reload. A new explicit deployment obtains a new local
        // CreatureId and a new durable DeploymentId before it can be used by a Job.
        let redeployed = omni::run_verb(
            Verb::FunctionDeploy {
                request: request.clone(),
                resolution: resolution.clone(),
                manifest_path: manifest_path.to_string_lossy().into_owned(),
                artifact_path: artifact_path.to_string_lossy().into_owned(),
            },
            &mut ctx,
            &mut |_| {},
        );
        assert!(redeployed.ok, "explicit redeployment is usable: {}", redeployed.human);
        assert_ne!(redeployed.json["creature_id"].as_u64(), Some(target));
        deployment = serde_json::from_value(redeployed.json["deployment"].clone()).unwrap();

        // The same normal control context can submit into the configured Home. Acceptance is
        // durable before this verb returns; subsequent policy/executor work remains asynchronous.
        let submit = SignedRecordV1::sign(
            SCHEMA_JOB_V1,
            JobSubmitV1 {
                home: expected_home,
                caller_idempotency_key: "composition-smoke".into(),
                function: resolution.payload.selector.clone(),
                input: ValueRefV1::Inline { value: serde_json::json!({"message": "hello"}) },
                delivery: DeliveryModeV1::AtMostOnce,
                allow_duplicate_effects: false,
                parent: None,
                causal: vec![],
                access: JobAccessV1::default(),
                evidence: vec![],
                result_recipients: vec![],
                submitted_at_unix_ms: None,
            },
            &root_signer,
        )
        .unwrap();
        let accepted = omni::run_verb(
            Verb::JobSubmit {
                request: Box::new(submit),
                resolution: resolution.clone(),
                deployment,
            },
            &mut ctx,
            &mut |_| {},
        );
        assert!(accepted.ok, "durable Job submission is usable: {}", accepted.human);
        assert_eq!(accepted.json["accepted"], true);

        // A cryptographically valid but unconfigured resolver cannot substitute an alias/exact
        // result underneath the root-authorized request. Rejection happens at registration and the
        // just-loaded duplicate is rolled back.
        let foreign_resolver = Ed25519SeedSigner::from_seed([8; 32]).unwrap();
        let foreign_resolution =
            SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, resolution.payload, &foreign_resolver)
                .unwrap();
        let refused = omni::run_verb(
            Verb::FunctionDeploy {
                request,
                resolution: foreign_resolution,
                manifest_path: manifest_path.to_string_lossy().into_owned(),
                artifact_path: artifact_path.to_string_lossy().into_owned(),
            },
            &mut ctx,
            &mut |_| {},
        );
        assert!(!refused.ok);
        assert_eq!(refused.json["stage"], "register");
        assert_eq!(refused.json["rolled_back"], true);
        kernel.shutdown_all(Deadline::default());
    }

    #[test]
    fn startup_refuses_node_mismatch_before_loading_any_function_organ() {
        let root = TempRoot::new();
        let (path, _) = fixture_config(&root);
        let kernel = kernel();
        let before = kernel.loaded_count();
        let error = boot(&kernel, load_config(&path).unwrap(), Some("other-node"))
            .err()
            .expect("node mismatch must fail");
        assert!(error.contains("does not match --node-id"));
        assert_eq!(kernel.loaded_count(), before);
    }

    #[test]
    fn second_runtime_is_refused_before_seed_or_store_open() {
        let root = TempRoot::new();
        let (path, _) = fixture_config(&root);
        let first_kernel = kernel();
        let first_runtime = boot(&first_kernel, load_config(&path).unwrap(), Some("op")).unwrap();
        let lock_path = root.0.join("state").join(FUNCTION_STATE_LOCK_FILE);
        assert!(lock_path.is_file());

        // Even an otherwise valid second composition must fail before opening a seed. Making one
        // seed temporarily absent turns that ordering into an observable regression guard.
        let executor_seed = root.0.join("keys/executor.hex");
        let held_seed = root.0.join("keys/executor.held");
        fs::rename(&executor_seed, &held_seed).unwrap();
        let second_kernel = kernel();
        let error = boot(&second_kernel, load_config(&path).unwrap(), Some("op"))
            .err()
            .expect("a second writer must be refused without waiting");
        assert!(error.contains("already in use by another Alpha Function runtime"), "{error}");
        assert!(!error.contains("executor key file"), "the lock must precede seed reads: {error}");
        assert_eq!(second_kernel.loaded_count(), 0);
        fs::rename(&held_seed, &executor_seed).unwrap();

        first_kernel.shutdown_all(Deadline::default());
        drop(first_runtime);
    }

    #[test]
    fn state_lock_releases_when_function_runtime_is_dropped() {
        let root = TempRoot::new();
        let (path, _) = fixture_config(&root);
        let first_kernel = kernel();
        let first_runtime = boot(&first_kernel, load_config(&path).unwrap(), Some("op")).unwrap();
        let replacement_kernel = kernel();

        // The guard is owned by FunctionRuntime rather than a leaked global. Normal shutdown plus
        // dropping that runtime closes the descriptor, after which the same durable state recovers.
        first_kernel.shutdown_all(Deadline::default());
        let still_held = boot(&replacement_kernel, load_config(&path).unwrap(), Some("op"))
            .err()
            .expect("kernel shutdown alone must not release the runtime's state guard");
        assert!(still_held.contains("already in use by another Alpha Function runtime"));
        drop(first_runtime);
        let replacement = boot(&replacement_kernel, load_config(&path).unwrap(), Some("op"))
            .expect("dropping the first runtime must release its state lock");
        replacement_kernel.shutdown_all(Deadline::default());
        drop(replacement);
    }

    #[test]
    fn startup_refuses_an_operational_seed_that_misses_its_public_pin() {
        let root = TempRoot::new();
        let (path, _) = fixture_config(&root);
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let other = Ed25519SeedSigner::from_seed([9; 32]).unwrap();
        config["resolver"]["public_key"] = serde_json::json!(other.public_key());
        fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

        let kernel = kernel();
        let before = kernel.loaded_count();
        let error = boot(&kernel, load_config(&path).unwrap(), Some("op"))
            .err()
            .expect("seed/public identity mismatch must fail closed");
        assert!(error.contains("resolver key file does not derive"), "{error}");
        assert_eq!(kernel.loaded_count(), before);
    }

    #[test]
    fn explicitly_root_valued_operational_identity_is_refused_before_its_seed_is_opened() {
        let root = TempRoot::new();
        let (path, _) = fixture_config(&root);
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let abode_root = Ed25519SeedSigner::from_seed([1; 32]).unwrap();
        config["resolver"]["public_key"] = serde_json::json!(abode_root.public_key());
        config["resolver"]["seed_file"] = serde_json::json!("keys/intentionally-absent.hex");
        fs::write(&path, serde_json::to_vec_pretty(&config).unwrap()).unwrap();

        let kernel = kernel();
        let error = boot(&kernel, load_config(&path).unwrap(), Some("op"))
            .err()
            .expect("root identity must fail before any attempted seed read");
        assert!(error.contains("operational key equals the Abode root key"), "{error}");
        assert!(!error.contains("intentionally-absent"), "{error}");
        assert_eq!(kernel.loaded_count(), 0);
    }

    #[test]
    fn startup_refuses_a_corrupt_durable_catalog_before_loading_any_function_organ() {
        let root = TempRoot::new();
        let (path, _) = fixture_config(&root);
        let state = root.0.join("state");
        fs::create_dir_all(state.join("bestiary/log")).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        }
        fs::write(state.join("bestiary/log/corrupt.jsonl"), b"{not-json}\n").unwrap();

        let kernel = kernel();
        let before = kernel.loaded_count();
        let error = boot(&kernel, load_config(&path).unwrap(), Some("op"))
            .err()
            .expect("corrupt durable registry must fail closed");
        assert!(error.contains("durable Function Bestiary recovery"), "{error}");
        assert_eq!(kernel.loaded_count(), before);
    }

    #[test]
    fn liveness_hash_normalization_is_strict_and_prefix_agnostic() {
        let raw = "ab".repeat(32);
        assert_eq!(normalized_sha256(&raw), Some(raw.as_str()));
        assert_eq!(normalized_sha256(&format!("sha256:{raw}")), Some(raw.as_str()));
        assert_eq!(normalized_sha256(&raw.to_uppercase()), None);
        assert_eq!(normalized_sha256("sha256:abcd"), None);
    }

    #[cfg(unix)]
    #[test]
    fn startup_refuses_group_readable_operational_seed() {
        use std::os::unix::fs::PermissionsExt;

        let root = TempRoot::new();
        let (path, _) = fixture_config(&root);
        fs::set_permissions(root.0.join("keys/executor.hex"), fs::Permissions::from_mode(0o640))
            .unwrap();
        let kernel = kernel();
        let before = kernel.loaded_count();
        let error = boot(&kernel, load_config(&path).unwrap(), Some("op"))
            .err()
            .expect("weak seed permissions must fail");
        assert!(error.contains("accessible by group/other"));
        assert_eq!(kernel.loaded_count(), before);
    }
}
