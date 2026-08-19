//! `dialogue` — v0.5's executable acceptance story: three model-backed, independently signing agents
//! form a causal fan-out/fan-in collaboration across a Realm boundary, then turn their approved
//! request into one durable running capability.
//!
//! The credential-free fixture run is a regression/eval, not product evidence. The live run asks
//! three independently configured models for strict bounded decisions: the Builder originates an
//! affine capability, the Reviewer materially narrows its domain, the Contract Tester chooses the
//! actual local/cross-Realm cases, and the Builder approves the exact causal projection. The same
//! Builder model then confirms a source-free implementation IR for each tier; `AgentMind` lowers
//! that reviewed IR through audited native, WASM, and Rhai templates before `BuildCargo`,
//! `BuildBeast`, and `BuildCritter` sign the artifacts. A durable Bestiary returns a verified
//! `EntryProof` for each artifact, and all three are executed as typed Functions in two fresh worlds.
//!
//! The Contract Tester's chosen positive input drives three B-local Home/executor Jobs; its chosen
//! negative input drives three A-Home -> B-executor Jobs over authenticated TCP/Omega/NodeRole.
//!
//! All six Jobs use the existing at-most-once contract and must cross their typed effect boundary
//! exactly once.
//! No Envelope, SEER, Manifest, Function, or creature-ABI shape is special to this demo.
//!
//! `--live` requires the `openai` feature and an explicit persistent evidence directory. Transport
//! is authenticated, **not encrypted**; the narrated topology is loopback and must not be marketed
//! for confidential prompts.

mod collaboration;
mod decisions;
mod evidence;
pub mod function_proof;
pub mod verify;

use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use bestiary::{BestiaryStore, EntryProof, FsBestiaryStore};
use collaboration::{collaborate_and_build, preflight_live_configuration, CollaborationOutput};
pub use evidence::EvidenceReferenceV1;
use evidence::{
    ApprovalContributorV1, CollaborationApprovalSchemaV1, CollaborationApprovalSummaryV1,
    EngineRunSummaryV1, EngineTierV1, EvidenceDirectory, EvidenceSealV1, FinalRunSummarySchemaV1,
    FinalRunSummaryV1, SourceIdentityV1, TopologySummaryV1, VerifiedSignedDialogueTurnV1,
};
use function_proof::{prove_all_tiers, PublishedCapability, RetainedJobProofV1, TierJobProof};
use seer::topics::dialogue::Provenance;
use serde::{Deserialize, Serialize};
use sigil::{Backend, Ed25519KeyMaterial, Ed25519Verifier, Verifier};

#[derive(Debug)]
enum RunMode {
    Fixture,
    Live {
        evidence_dir: PathBuf,
        evidence_signing_key_file: PathBuf,
        forbidden_semantics: Vec<String>,
    },
}

impl RunMode {
    fn is_live(&self) -> bool {
        matches!(self, Self::Live { .. })
    }
}

fn normalize_semantic_digest(value: &str) -> Result<String, String> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    if raw.len() != 64
        || !raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("--forbid-semantic must be a lowercase SHA-256 digest".into());
    }
    Ok(format!("sha256:{raw}"))
}

fn bare_digest(value: &str) -> Result<String, String> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    if raw.len() != 64
        || !raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("expected a lowercase SHA-256 digest, received {value:?}"));
    }
    Ok(raw.to_string())
}

fn hash_bytes(bytes: &[u8]) -> String {
    gawdfn::sha256_digest(bytes)
        .strip_prefix("sha256:")
        .expect("sha256_digest always returns a prefixed digest")
        .to_string()
}

fn hash_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_vec(value).map(|bytes| hash_bytes(&bytes)).map_err(|error| error.to_string())
}

pub const EXECUTION_RESULT_EVIDENCE_SCHEMA_V1: &str = "gawd.dialogue.execution-result-evidence.v1";

/// A compact, top-level-summary-anchored pointer into one complete signed execution chain.
/// Every descriptive field is re-derived from the proof bundle during persistence and again after
/// the evidence directory has been sealed and reopened.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionResultEvidenceV1 {
    pub schema: String,
    pub execution_proof: EvidenceReferenceV1,
    pub terminal_receipt: EvidenceReferenceV1,
    pub function_id: String,
    pub job_home: String,
    pub job_id: String,
    pub input: i32,
    pub result: i32,
    pub attempt_count: u8,
    pub home_realm: String,
    pub home_node: String,
    pub home_coordinator: String,
    pub deployment_id: String,
    pub deployment_realm: String,
    pub deployment_node: String,
    pub executor_public_key: String,
    pub executor_creature: String,
    pub target_creature: String,
}

impl ExecutionResultEvidenceV1 {
    fn from_proof(
        proof: &RetainedJobProofV1,
        execution_proof: EvidenceReferenceV1,
        terminal_receipt: EvidenceReferenceV1,
    ) -> Result<Self, String> {
        proof.validate()?;
        let summary = Self {
            schema: EXECUTION_RESULT_EVIDENCE_SCHEMA_V1.into(),
            execution_proof,
            terminal_receipt,
            function_id: serde_json::to_string(&proof.grant.payload.function)
                .map_err(|error| error.to_string())?,
            job_home: proof.grant.payload.attempt.home.to_string(),
            job_id: proof.grant.payload.attempt.job.to_string(),
            input: proof.input_i32()?,
            result: proof.result_i32()?,
            attempt_count: proof.attempt_count(),
            home_realm: proof.grant.payload.home_realm.clone(),
            home_node: proof.grant.payload.home_node.clone(),
            home_coordinator: proof.grant.payload.home_coordinator.clone(),
            deployment_id: proof.deployment.payload.deployment.to_string(),
            deployment_realm: proof.deployment.payload.realm.clone(),
            deployment_node: proof.deployment.payload.node.clone(),
            executor_public_key: proof.deployment.payload.executor.clone(),
            executor_creature: proof
                .function_call
                .executor_dispatch
                .payload
                .executor_creature
                .clone(),
            target_creature: proof.function_call.executor_dispatch.payload.target_creature.clone(),
        };
        summary.validate_against(proof)?;
        Ok(summary)
    }

    pub fn validate_against(&self, proof: &RetainedJobProofV1) -> Result<(), String> {
        proof.validate()?;
        validate_execution_reference(&self.execution_proof)?;
        validate_execution_reference(&self.terminal_receipt)?;
        let expected = Self::from_validated_proof(
            proof,
            self.execution_proof.clone(),
            self.terminal_receipt.clone(),
        )?;
        if self != &expected {
            return Err("execution result summary changed its signed proof-derived fields".into());
        }
        Ok(())
    }

    fn from_validated_proof(
        proof: &RetainedJobProofV1,
        execution_proof: EvidenceReferenceV1,
        terminal_receipt: EvidenceReferenceV1,
    ) -> Result<Self, String> {
        Ok(Self {
            schema: EXECUTION_RESULT_EVIDENCE_SCHEMA_V1.into(),
            execution_proof,
            terminal_receipt,
            function_id: serde_json::to_string(&proof.grant.payload.function)
                .map_err(|error| error.to_string())?,
            job_home: proof.grant.payload.attempt.home.to_string(),
            job_id: proof.grant.payload.attempt.job.to_string(),
            input: proof.input_i32()?,
            result: proof.result_i32()?,
            attempt_count: proof.attempt_count(),
            home_realm: proof.grant.payload.home_realm.clone(),
            home_node: proof.grant.payload.home_node.clone(),
            home_coordinator: proof.grant.payload.home_coordinator.clone(),
            deployment_id: proof.deployment.payload.deployment.to_string(),
            deployment_realm: proof.deployment.payload.realm.clone(),
            deployment_node: proof.deployment.payload.node.clone(),
            executor_public_key: proof.deployment.payload.executor.clone(),
            executor_creature: proof
                .function_call
                .executor_dispatch
                .payload
                .executor_creature
                .clone(),
            target_creature: proof.function_call.executor_dispatch.payload.target_creature.clone(),
        })
    }

    /// Reproduce the offline verification path from only the sealed files named by this summary.
    pub fn verify_files(&self, proof_bytes: &[u8], receipt_bytes: &[u8]) -> Result<(), String> {
        if hash_bytes(proof_bytes) != self.execution_proof.sha256
            || hash_bytes(receipt_bytes) != self.terminal_receipt.sha256
        {
            return Err("execution result summary file digest does not match sealed bytes".into());
        }
        let proof: RetainedJobProofV1 =
            serde_json::from_slice(proof_bytes).map_err(|error| error.to_string())?;
        let receipt: gawdfn::SignedRecordV1<gawdfn::ExecutionReceiptV1> =
            serde_json::from_slice(receipt_bytes).map_err(|error| error.to_string())?;
        self.validate_against(&proof)?;
        if receipt != proof.terminal_receipt {
            return Err("standalone terminal receipt differs from the retained proof bundle".into());
        }
        Ok(())
    }
}

fn validate_execution_reference(reference: &EvidenceReferenceV1) -> Result<(), String> {
    if reference.file.is_empty()
        || reference.file.len() > 255
        || reference.file == "."
        || reference.file == ".."
        || reference.file.contains('/')
        || reference.file.contains('\\')
    {
        return Err("execution evidence reference is not one bounded basename".into());
    }
    if bare_digest(&reference.sha256)? != reference.sha256 {
        return Err("execution evidence reference must use a bare lowercase SHA-256".into());
    }
    Ok(())
}

fn verified_turn_evidence(
    output: &CollaborationOutput,
) -> Result<Vec<VerifiedSignedDialogueTurnV1>, String> {
    let expected = [
        ("builder", output.builder_signer.as_str()),
        ("reviewer", output.reviewer_signer.as_str()),
        ("contract-tester", output.contract_tester_signer.as_str()),
        ("builder", output.builder_signer.as_str()),
    ];
    if output.verified_turns.len() != expected.len() {
        return Err("live evidence requires exactly four verified dialogue turns".into());
    }
    let verifier = Ed25519Verifier;
    let mut records = Vec::with_capacity(expected.len());
    let mut predecessor_hashes = Vec::with_capacity(expected.len());
    for (ordinal, (turn, (role, signer))) in output.verified_turns.iter().zip(expected).enumerate()
    {
        match turn.answer.verify_provenance(turn.corr, &turn.prompt, &verifier) {
            Provenance::Verified(observed) if observed == signer => {}
            _ => return Err(format!("turn {ordinal} did not reverify under pinned {role} signer")),
        }
        let signed_answer = String::from_utf8(aether::wire::to_bytes(&turn.answer))
            .map_err(|_| "signed dialogue AnswerBody was not UTF-8 JSON".to_string())?;
        let record = VerifiedSignedDialogueTurnV1::from_verified_answer(
            ordinal as u64,
            role,
            turn.corr,
            hash_bytes(turn.prompt.as_bytes()),
            hash_bytes(turn.answer.reply.as_bytes()),
            signed_answer,
            signer,
            predecessor_hashes.clone(),
        )
        .map_err(|error| error.to_string())?;
        record.validate().map_err(|error| error.to_string())?;
        predecessor_hashes.push(hash_json(&record)?);
        records.push(record);
    }
    Ok(records)
}

fn approval_summary(
    output: &CollaborationOutput,
    turns: &[VerifiedSignedDialogueTurnV1],
) -> Result<CollaborationApprovalSummaryV1, String> {
    if turns.len() != 4 {
        return Err("approval summary requires four signed turns".into());
    }
    let turn_hashes = turns.iter().map(hash_json).collect::<Result<Vec<_>, _>>()?;
    let summary = CollaborationApprovalSummaryV1 {
        schema: CollaborationApprovalSchemaV1::V1,
        challenge_sha256: bare_digest(
            &output.challenge.hash().map_err(|error| error.to_string())?,
        )?,
        approved_profile_schema: decisions::FINAL_CAPABILITY_SCHEMA_V1.into(),
        approved_profile_sha256: bare_digest(&output.profile_digest)?,
        semantic_sha256: bare_digest(&output.approval.normalized_spec.semantic_digest)?,
        approval_payload_sha256: bare_digest(
            &output
                .approval
                .hash(&output.challenge, &output.draft, &output.review, &output.test_plan)
                .map_err(|error| error.to_string())?,
        )?,
        contributors: vec![
            ApprovalContributorV1 {
                role: "builder".into(),
                signer_public_key: output.builder_signer.clone(),
                signed_turn_sha256: turn_hashes[0].clone(),
            },
            ApprovalContributorV1 {
                role: "reviewer".into(),
                signer_public_key: output.reviewer_signer.clone(),
                signed_turn_sha256: turn_hashes[1].clone(),
            },
            ApprovalContributorV1 {
                role: "contract-tester".into(),
                signer_public_key: output.contract_tester_signer.clone(),
                signed_turn_sha256: turn_hashes[2].clone(),
            },
        ],
        final_builder_turn_sha256: turn_hashes[3].clone(),
    };
    summary.validate().map_err(|error| error.to_string())?;
    Ok(summary)
}

fn parse_mode(args: &[String]) -> Result<Option<RunMode>, String> {
    if args.iter().any(|argument| matches!(argument.as_str(), "--help" | "-h")) {
        println!(
            "usage: dialogue [--fixture] | --live --evidence-dir ABSOLUTE_NEW_PATH \\\n             --evidence-signing-key-file ABSOLUTE_0600_SEED [--forbid-semantic SHA256]..."
        );
        println!(
            "default/--fixture: credential-free regression and exact replay; not product evidence"
        );
        println!(
            "--live: three role-configured providers plus retained, externally sealed evidence"
        );
        println!("offline verification: dialogue verify-live --help");
        return Ok(None);
    }
    if args.is_empty() || args == ["--fixture"] {
        return Ok(Some(RunMode::Fixture));
    }
    let mut live = false;
    let mut fixture = false;
    let mut evidence_dir = None;
    let mut signing_key = None;
    let mut forbidden_semantics = Vec::new();
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--live" if !live => live = true,
            "--fixture" if !fixture => fixture = true,
            "--evidence-dir" => {
                index += 1;
                let value =
                    args.get(index).ok_or_else(|| "--evidence-dir requires a path".to_string())?;
                if evidence_dir.replace(PathBuf::from(value)).is_some() {
                    return Err("--evidence-dir may be supplied only once".into());
                }
            }
            "--evidence-signing-key-file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--evidence-signing-key-file requires a path".to_string())?;
                if signing_key.replace(PathBuf::from(value)).is_some() {
                    return Err("--evidence-signing-key-file may be supplied only once".into());
                }
            }
            "--forbid-semantic" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--forbid-semantic requires a digest".to_string())?;
                forbidden_semantics.push(normalize_semantic_digest(value)?);
            }
            other => return Err(format!("unknown or duplicate dialogue argument `{other}`")),
        }
        index += 1;
    }
    if !live || fixture {
        return Err("choose exactly one of --fixture or --live".into());
    }
    let evidence_dir = evidence_dir
        .ok_or_else(|| "--live requires --evidence-dir ABSOLUTE_NEW_PATH".to_string())?;
    let evidence_signing_key_file = signing_key.ok_or_else(|| {
        "--live requires --evidence-signing-key-file ABSOLUTE_0600_SEED".to_string()
    })?;
    forbidden_semantics.sort();
    forbidden_semantics.dedup();
    Ok(Some(RunMode::Live { evidence_dir, evidence_signing_key_file, forbidden_semantics }))
}

fn load_evidence_signing_key(path: &Path) -> Result<Ed25519KeyMaterial, String> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::RootDir | Component::Normal(_)))
    {
        return Err("evidence signing key path must be absolute and normalized".into());
    }
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("evidence signing key {}: {error}", path.display()))?;
    if canonical != path {
        return Err(format!(
            "evidence signing key path {} contains a symlink or noncanonical component",
            path.display()
        ));
    }
    let path_metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("evidence signing key {}: {error}", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err("evidence signing key must be a regular non-symlink file".into());
    }
    let file = fs::File::open(path)
        .map_err(|error| format!("evidence signing key {}: {error}", path.display()))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("evidence signing key {}: {error}", path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if path_metadata.dev() != opened.dev() || path_metadata.ino() != opened.ino() {
            return Err("evidence signing key changed while it was opened".into());
        }
        if opened.permissions().mode() & 0o077 != 0 {
            return Err("evidence signing key must be mode 0600 or stricter".into());
        }
    }
    if opened.len() > 128 {
        return Err("evidence signing key exceeds 128 bytes".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take(129)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read evidence signing key: {error}"))?;
    if bytes.len() > 128 {
        return Err("evidence signing key exceeds 128 bytes".into());
    }
    let seed = decode_evidence_signing_seed(&bytes)?;
    Ed25519KeyMaterial::from_seed(seed)
}

fn decode_evidence_signing_seed(bytes: &[u8]) -> Result<[u8; 32], String> {
    let encoded = match bytes {
        [encoded @ .., b'\n'] if encoded.len() == 64 => encoded,
        encoded if encoded.len() == 64 => encoded,
        _ => {
            return Err(
                "evidence signing key must contain exactly 64 lowercase hexadecimal bytes, optionally followed by one LF"
                    .into(),
            )
        }
    };
    if !encoded.iter().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte)) {
        return Err("evidence signing key must use lowercase hexadecimal only".into());
    }
    let encoded = std::str::from_utf8(encoded)
        .map_err(|_| "evidence signing key is not lowercase hexadecimal".to_string())?;
    sigil::crypto::hex_decode(encoded)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| "evidence signing key must decode to exactly 32 bytes".to_string())
}

fn banner(title: &str) {
    println!("\n\x1b[1m{title}\x1b[0m");
    println!("{}", "─".repeat(title.chars().count()));
}

fn step(message: &str) {
    println!("\x1b[36m▸\x1b[0m {message}");
}

fn ok(message: &str) {
    println!("  \x1b[32m✓\x1b[0m {message}");
}

fn note(message: &str) {
    println!("    {message}");
}

/// Marker-owned, process-unique demo state. Drop removes only the exact directory this process
/// created after re-validating its parent, name, type, and ownership marker.
struct DemoRoot {
    path: PathBuf,
    marker: PathBuf,
    removed: bool,
}

impl DemoRoot {
    fn create() -> Result<Self, String> {
        let parent = std::env::temp_dir();
        let unique =
            SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?.as_nanos();
        let name = format!("alpha-dialogue-v05-{}-{unique}", std::process::id());
        let path = parent.join(name);
        fs::create_dir(&path).map_err(|e| format!("create demo state {}: {e}", path.display()))?;
        let marker = path.join(".alpha-dialogue-v05-owned");
        if let Err(error) = fs::write(&marker, b"alpha-dialogue-v05\n") {
            let _ = fs::remove_dir(&path);
            return Err(format!("write demo ownership marker {}: {error}", marker.display()));
        }
        Ok(Self { path, marker, removed: false })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn owns_exact_path(&self) -> bool {
        let expected_parent = std::env::temp_dir();
        self.path.parent() == Some(expected_parent.as_path())
            && self
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("alpha-dialogue-v05-"))
            && fs::symlink_metadata(&self.path)
                .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_dir())
            && fs::symlink_metadata(&self.marker)
                .is_ok_and(|metadata| !metadata.file_type().is_symlink() && metadata.is_file())
            && fs::read(&self.marker).is_ok_and(|bytes| bytes.as_slice() == b"alpha-dialogue-v05\n")
    }

    /// Make normal-success cleanup part of the executable proof. `Drop` remains the best-effort
    /// fallback for early errors and unwinding, but a green demo may not silently leave state.
    fn cleanup(mut self) -> Result<(), String> {
        if !self.owns_exact_path() {
            return Err(format!(
                "refusing to remove state whose ownership changed: {}",
                self.path.display()
            ));
        }
        fs::remove_dir_all(&self.path)
            .map_err(|error| format!("remove owned state {}: {error}", self.path.display()))?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for DemoRoot {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        if self.owns_exact_path() {
            if let Err(error) = fs::remove_dir_all(&self.path) {
                eprintln!(
                    "dialogue: could not remove owned state {}: {error}",
                    self.path.display()
                );
            }
        } else {
            eprintln!(
                "dialogue: refusing to remove state whose ownership changed: {}",
                self.path.display()
            );
        }
    }
}

fn publish_and_recover(
    root: &Path,
    capabilities: Vec<PublishedCapability>,
) -> Result<Vec<(PublishedCapability, EntryProof)>, String> {
    if capabilities.len() != 3 {
        return Err(format!(
            "the v0.5 publication requires daemon, beast, and critter; received {} artifacts",
            capabilities.len()
        ));
    }
    let mut artifact_hashes = std::collections::BTreeSet::new();
    let mut content_addresses = std::collections::BTreeSet::new();
    for capability in &capabilities {
        capability.manifest.validate().map_err(|e| e.to_string())?;
        let author = capability
            .manifest
            .provenance
            .author
            .as_deref()
            .ok_or_else(|| format!("{} omitted provenance.author", capability.manifest.name))?;
        let signature =
            capability.manifest.provenance.signature.as_deref().ok_or_else(|| {
                format!("{} omitted provenance.signature", capability.manifest.name)
            })?;
        if !Ed25519Verifier.verify(author, &capability.manifest.signing_payload(), signature) {
            return Err(format!("{} manifest signature did not verify", capability.manifest.name));
        }
        let actual_artifact = gawdfn::sha256_digest(&capability.artifact);
        let expected_artifact = format!("sha256:{}", capability.artifact_hash);
        let actual_source = gawdfn::sha256_digest(&capability.source);
        let expected_source = format!("sha256:{}", capability.source_hash);
        if actual_artifact != expected_artifact
            || actual_source != expected_source
            || capability.manifest.provenance.source_hash.as_deref()
                != Some(capability.source_hash.as_str())
            || capability.manifest.provenance.build_hash.as_deref()
                != Some(capability.artifact_hash.as_str())
        {
            return Err(format!(
                "{} source/artifact bytes are not bound to provenance",
                capability.manifest.name
            ));
        }
        if capability.manifest.abi.backend == Backend::Critter
            && (capability.source != capability.artifact
                || capability.source_hash != capability.artifact_hash)
        {
            return Err("the critter identity build changed its exact source bytes".into());
        }
        let content_address = capability
            .manifest
            .content_address
            .as_deref()
            .ok_or_else(|| format!("{} omitted content_address", capability.manifest.name))?;
        if capability.manifest.compute_content_address() != content_address {
            return Err(format!("{} content address is stale", capability.manifest.name));
        }
        artifact_hashes.insert(capability.artifact_hash.clone());
        content_addresses.insert(content_address.to_string());
    }
    if artifact_hashes.len() != capabilities.len() || content_addresses.len() != capabilities.len()
    {
        return Err("the three backend artifacts must have distinct hashes and manifests".into());
    }
    let (store_key, _) = Ed25519KeyMaterial::generate().map_err(|e| e.to_string())?;
    let store_root = root.join("bestiary");
    let store = FsBestiaryStore::new(&store_root, store_key.clone()).map_err(|e| e.to_string())?;
    store.recover().map_err(|e| e.to_string())?;
    let mut proofs = Vec::with_capacity(capabilities.len());
    for capability in &capabilities {
        let hash = store
            .put(
                &aether::RealmId::new("builders"),
                capability.manifest.clone(),
                capability.artifact.clone(),
            )
            .map_err(|e| e.to_string())?;
        if hash != capability.artifact_hash {
            return Err(format!(
                "Bestiary keyed {} as {hash}, expected {}",
                capability.manifest.name, capability.artifact_hash
            ));
        }
        let proof = store
            .prove(&aether::RealmId::new("builders"), &hash)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "durable Bestiary returned no EntryProof".to_string())?;
        if !proof.verify(&Ed25519Verifier)
            || proof.attester != store_key.public_hex()
            || proof.realm != aether::RealmId::new("builders")
            || proof.artifact_hash != hash
            || Some(proof.manifest_hash.as_str()) != capability.manifest.content_address.as_deref()
        {
            return Err(
                "durable Bestiary EntryProof did not bind the exact manifest/artifact".into()
            );
        }
        proofs.push(proof);
    }
    store.flush().map_err(|e| e.to_string())?;
    drop(store);

    // Fresh handle + journal replay makes “durable publication” executable rather than a claim
    // about an in-memory Put response.
    let reopened = FsBestiaryStore::new(&store_root, store_key).map_err(|e| e.to_string())?;
    reopened.recover().map_err(|e| e.to_string())?;
    let mut recovered = Vec::with_capacity(capabilities.len());
    for (capability, proof) in capabilities.into_iter().zip(proofs) {
        let entry = reopened
            .get(&aether::RealmId::new("builders"), &capability.artifact_hash)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| {
                "published capability disappeared after Bestiary recovery".to_string()
            })?;
        if entry.artifact != capability.artifact || entry.manifest != capability.manifest {
            return Err("Bestiary recovery changed an exact published capability".into());
        }
        let recovered_proof = reopened
            .prove(&aether::RealmId::new("builders"), &capability.artifact_hash)
            .map_err(|e| e.to_string())?
            .ok_or_else(|| "recovered Bestiary returned no EntryProof".to_string())?;
        if recovered_proof != proof || !recovered_proof.verify(&Ed25519Verifier) {
            return Err("Bestiary recovery changed a signed EntryProof".into());
        }
        recovered.push((
            PublishedCapability {
                manifest: entry.manifest,
                artifact: entry.artifact,
                ..capability
            },
            recovered_proof,
        ));
    }
    reopened.flush().map_err(|e| e.to_string())?;
    Ok(recovered)
}

fn backend_evidence_name(backend: Backend) -> (&'static str, EngineTierV1) {
    match backend {
        Backend::Daemon => ("daemon", EngineTierV1::Daemon),
        Backend::Beast => ("beast", EngineTierV1::Beast),
        Backend::Critter => ("critter", EngineTierV1::Critter),
    }
}

fn workspace_root() -> Result<&'static Path, String> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "dialogue manifest is not under the workspace root".to_string())
}

fn persist_live_evidence(
    directory: &EvidenceDirectory,
    collaboration: &CollaborationOutput,
    published: &[(PublishedCapability, EntryProof)],
    proofs: &[TierJobProof],
    source_before: &SourceIdentityV1,
) -> Result<EvidenceSealV1, String> {
    if published.len() != 3 || proofs.len() != 3 || published.len() != proofs.len() {
        return Err("live evidence requires exactly three aligned engine proofs".into());
    }
    let turns = verified_turn_evidence(collaboration)?;
    let approval = approval_summary(collaboration, &turns)?;

    let model_calls = directory
        .write_json("model-calls.v1.json", &collaboration.model_calls)
        .map_err(|error| error.to_string())?;
    let replay_entries = directory
        .write_json("model-replay.v1.json", &collaboration.replay_entries)
        .map_err(|error| error.to_string())?;
    let signed_turns = directory
        .write_json("signed-dialogue-turns.v1.json", &turns)
        .map_err(|error| error.to_string())?;
    directory
        .write_json("challenge.v1.json", &collaboration.challenge)
        .map_err(|error| error.to_string())?;
    directory
        .write_json("builder-draft.v1.json", &collaboration.draft)
        .map_err(|error| error.to_string())?;
    directory
        .write_json("reviewer-decision.v1.json", &collaboration.review)
        .map_err(|error| error.to_string())?;
    directory
        .write_json("contract-test-plan.v1.json", &collaboration.test_plan)
        .map_err(|error| error.to_string())?;
    directory
        .write_json("final-approval.v1.json", &collaboration.approval)
        .map_err(|error| error.to_string())?;
    directory
        .write_json("approved-profile.v1.json", &collaboration.approval.normalized_spec)
        .map_err(|error| error.to_string())?;
    let approval_record = directory
        .write_json("collaboration-approval.v1.json", &approval)
        .map_err(|error| error.to_string())?;

    let mut engine_runs = Vec::with_capacity(3);
    let mut execution_result_files = Vec::with_capacity(6);
    for ((capability, entry_proof), proof) in published.iter().zip(proofs) {
        let (name, tier) = backend_evidence_name(capability.manifest.abi.backend);
        if proof.function.manifest_content_address
            != capability
                .manifest
                .content_address
                .as_deref()
                .ok_or_else(|| format!("{name} manifest omitted its content address"))?
        {
            return Err(format!("{name} evidence paired the wrong Function proof"));
        }
        proof.local_proof.validate_topology(
            "builders",
            "builder-executor",
            "builders",
            "builder-executor",
        )?;
        proof.remote_proof.validate_topology(
            "reviewers",
            "reviewer-home",
            "builders",
            "builder-executor",
        )?;
        if proof.local_proof.grant.payload.function != proof.function
            || proof.remote_proof.grant.payload.function != proof.function
            || proof.local_proof.grant.payload.attempt.home != proof.local.home
            || proof.local_proof.grant.payload.attempt.job != proof.local.job
            || proof.remote_proof.grant.payload.attempt.home != proof.remote.home
            || proof.remote_proof.grant.payload.attempt.job != proof.remote.job
            || proof.local_proof.terminal_receipt != proof.local_receipt
            || proof.remote_proof.terminal_receipt != proof.remote_receipt
            || proof.local_proof.input_i32()? != proof.local_input
            || proof.local_proof.result_i32()? != proof.local_result
            || proof.remote_proof.input_i32()? != proof.remote_input
            || proof.remote_proof.result_i32()? != proof.remote_result
        {
            return Err(format!("{name} retained execution chain changed its run summary"));
        }
        let source = directory
            .write_bytes(&format!("{name}-source.v1.bin"), &capability.source)
            .map_err(|error| error.to_string())?;
        let manifest = directory
            .write_json(&format!("{name}-manifest.v1.json"), &capability.manifest)
            .map_err(|error| error.to_string())?;
        let artifact = directory
            .write_bytes(&format!("{name}-artifact.v1.bin"), &capability.artifact)
            .map_err(|error| error.to_string())?;
        let entry_proof = directory
            .write_json(&format!("{name}-entry-proof.v1.json"), entry_proof)
            .map_err(|error| error.to_string())?;
        let local_receipt = directory
            .write_json(&format!("{name}-local-receipt.v1.json"), &proof.local_receipt)
            .map_err(|error| error.to_string())?;
        let remote_receipt = directory
            .write_json(&format!("{name}-remote-receipt.v1.json"), &proof.remote_receipt)
            .map_err(|error| error.to_string())?;
        let local_execution_proof = directory
            .write_json(&format!("{name}-local-execution-proof.v1.json"), &proof.local_proof)
            .map_err(|error| error.to_string())?;
        let remote_execution_proof = directory
            .write_json(&format!("{name}-cross-realm-execution-proof.v1.json"), &proof.remote_proof)
            .map_err(|error| error.to_string())?;
        let local_result_summary = ExecutionResultEvidenceV1::from_proof(
            &proof.local_proof,
            EvidenceReferenceV1 {
                file: local_execution_proof.file.clone(),
                sha256: local_execution_proof.sha256.clone(),
            },
            EvidenceReferenceV1 {
                file: local_receipt.file.clone(),
                sha256: local_receipt.sha256.clone(),
            },
        )?;
        let remote_result_summary = ExecutionResultEvidenceV1::from_proof(
            &proof.remote_proof,
            EvidenceReferenceV1 {
                file: remote_execution_proof.file.clone(),
                sha256: remote_execution_proof.sha256.clone(),
            },
            EvidenceReferenceV1 {
                file: remote_receipt.file.clone(),
                sha256: remote_receipt.sha256.clone(),
            },
        )?;
        let local_result = directory
            .write_json(&format!("{name}-local-result.v1.json"), &local_result_summary)
            .map_err(|error| error.to_string())?;
        let remote_result = directory
            .write_json(&format!("{name}-remote-result.v1.json"), &remote_result_summary)
            .map_err(|error| error.to_string())?;
        execution_result_files.push(EvidenceReferenceV1 {
            file: local_result.file.clone(),
            sha256: local_result.sha256.clone(),
        });
        execution_result_files.push(EvidenceReferenceV1 {
            file: remote_result.file.clone(),
            sha256: remote_result.sha256.clone(),
        });
        engine_runs.push(EngineRunSummaryV1 {
            tier,
            source_sha256: source.sha256,
            manifest_sha256: manifest.sha256,
            artifact_sha256: artifact.sha256,
            entry_proof_sha256: entry_proof.sha256,
            function_id: serde_json::to_string(&proof.function)
                .map_err(|error| error.to_string())?,
            local_job_receipt_sha256: local_receipt.sha256,
            cross_realm_job_receipt_sha256: remote_receipt.sha256,
            local_result_sha256: local_result.sha256,
            cross_realm_result_sha256: remote_result.sha256,
        });
    }

    let source_after =
        SourceIdentityV1::derive_clean(workspace_root()?).map_err(|error| error.to_string())?;
    source_after.require_matching_build_commit().map_err(|error| error.to_string())?;
    if &source_after != source_before {
        return Err("source, toolchain, or running binary changed during the live proof".into());
    }
    let summary = FinalRunSummaryV1 {
        schema: FinalRunSummarySchemaV1::V1,
        run_id: collaboration.challenge.challenge_nonce.clone(),
        challenge_sha256: bare_digest(
            &collaboration.challenge.hash().map_err(|error| error.to_string())?,
        )?,
        approval_summary_sha256: approval_record.sha256,
        source: source_after,
        topology: TopologySummaryV1 {
            authoring_realm: "builders".into(),
            authoring_node: "builder-agent".into(),
            execution_realm: "builders".into(),
            execution_node: "builder-executor".into(),
        },
        model_calls: EvidenceReferenceV1 { file: model_calls.file, sha256: model_calls.sha256 },
        replay_entries: EvidenceReferenceV1 {
            file: replay_entries.file,
            sha256: replay_entries.sha256,
        },
        signed_dialogue_turns: EvidenceReferenceV1 {
            file: signed_turns.file,
            sha256: signed_turns.sha256,
        },
        engine_runs,
    };
    summary.validate().map_err(|error| error.to_string())?;
    directory
        .write_json("final-run-summary.v1.json", &summary)
        .map_err(|error| error.to_string())?;
    let seal = directory.seal().map_err(|error| error.to_string())?;
    let verified =
        EvidenceDirectory::verify(directory.path(), &seal).map_err(|error| error.to_string())?;
    let final_bytes =
        verified.read("final-run-summary.v1.json").map_err(|error| error.to_string())?;
    let decoded: FinalRunSummaryV1 =
        serde_json::from_slice(&final_bytes).map_err(|error| error.to_string())?;
    decoded.validate().map_err(|error| error.to_string())?;
    let anchored_result_hashes = decoded
        .engine_runs
        .iter()
        .flat_map(|run| [&run.local_result_sha256, &run.cross_realm_result_sha256])
        .collect::<Vec<_>>();
    if anchored_result_hashes.len() != execution_result_files.len()
        || execution_result_files.iter().any(|reference| {
            anchored_result_hashes
                .iter()
                .filter(|hash| hash.as_str() == reference.sha256.as_str())
                .count()
                != 1
        })
    {
        return Err("final run summary did not uniquely anchor all six execution results".into());
    }
    for reference in &execution_result_files {
        let summary_bytes = verified.read(&reference.file).map_err(|error| error.to_string())?;
        if hash_bytes(&summary_bytes) != reference.sha256 {
            return Err("sealed execution result differs from its final-summary hash".into());
        }
        let result: ExecutionResultEvidenceV1 =
            serde_json::from_slice(&summary_bytes).map_err(|error| error.to_string())?;
        let mut anchor = None;
        for run in &decoded.engine_runs {
            for (local, result_hash, receipt_hash) in [
                (true, &run.local_result_sha256, &run.local_job_receipt_sha256),
                (false, &run.cross_realm_result_sha256, &run.cross_realm_job_receipt_sha256),
            ] {
                if result_hash == &reference.sha256
                    && anchor.replace((run, local, receipt_hash)).is_some()
                {
                    return Err("execution result has multiple final-summary anchors".into());
                }
            }
        }
        let (run, local, receipt_hash) = anchor
            .ok_or_else(|| "execution result has no exact final-summary anchor".to_string())?;
        if result.function_id.as_str() != run.function_id.as_str()
            || result.terminal_receipt.sha256.as_str() != receipt_hash.as_str()
            || result.attempt_count != 1
            || result.deployment_realm != "builders"
            || result.deployment_node != "builder-executor"
            || (local
                && (result.home_realm != "builders" || result.home_node != "builder-executor"))
            || (!local && (result.home_realm != "reviewers" || result.home_node != "reviewer-home"))
        {
            return Err(
                "execution result does not match its Function, receipt, topology, or attempt anchor"
                    .into(),
            );
        }
        let proof_bytes =
            verified.read(&result.execution_proof.file).map_err(|error| error.to_string())?;
        let receipt_bytes =
            verified.read(&result.terminal_receipt.file).map_err(|error| error.to_string())?;
        result.verify_files(&proof_bytes, &receipt_bytes)?;
    }
    if verified.index_sha256() != seal.index_sha256
        || verified.index().files.len() != seal.payload_files as usize
        || verified.path() != directory.path()
    {
        return Err("sealed evidence verification changed its exact directory/index".into());
    }
    Ok(seal)
}

fn run_inner(args: &[String]) -> Result<(), String> {
    let Some(mode) = parse_mode(args)? else { return Ok(()) };
    let live = mode.is_live();
    let forbidden_semantics = match &mode {
        RunMode::Fixture => &[][..],
        RunMode::Live { forbidden_semantics, .. } => forbidden_semantics.as_slice(),
    };
    let source_before = match &mode {
        RunMode::Fixture => None,
        RunMode::Live { evidence_dir, evidence_signing_key_file, .. } => {
            let root = workspace_root()?;
            if evidence_dir.starts_with(root) || evidence_signing_key_file.starts_with(root) {
                return Err(
                    "live evidence and its signing key must live outside the source worktree"
                        .into(),
                );
            }
            let identity =
                SourceIdentityV1::derive_clean(root).map_err(|error| error.to_string())?;
            identity.require_matching_build_commit().map_err(|error| error.to_string())?;
            Some(identity)
        }
    };
    let evidence_signer = match &mode {
        RunMode::Fixture => None,
        RunMode::Live { evidence_signing_key_file, .. } => {
            Some(load_evidence_signing_key(evidence_signing_key_file)?)
        }
    };
    if live {
        preflight_live_configuration()?;
    }
    // Claim the create-new evidence path only after every cheap source/key/provider preflight has
    // passed. A failure after this point leaves an incomplete private directory for forensics; it
    // is never accepted or packaged as evidence without a verified signed seal.
    let evidence_directory = match &mode {
        RunMode::Fixture => None,
        RunMode::Live { evidence_dir, .. } => {
            Some(EvidenceDirectory::create(evidence_dir).map_err(|error| error.to_string())?)
        }
    };

    let root = DemoRoot::create()?;
    banner("dialogue — three minds create a running capability across Realms");
    note(
        "reviewer (Realm A) ── Ω routing + authenticated TCP ── builder + contract tester (Realm B)",
    );
    note(if live {
        "live provider mode: three independent role-prefixed model configurations"
    } else {
        "hermetic mode: three strict scripted Models; one resource-bounded native Cargo build, no model network"
    });

    banner("1. collaborate — signer-verified draft, critique, tests, and approval");
    step("builder drafts the typed capability on Realm B");
    step("reviewer on Realm A rejects the missing negative-number edge");
    step("contract tester on Realm B derives the exact six-Job acceptance from both prior contributions");
    step("builder integrates both peers and signs the exact final approval");
    let collaboration = collaborate_and_build(root.path(), live, forbidden_semantics)?;
    ok("four causally linked model turns formed fan-out and fan-in on the existing dialogue/Omega wire");
    ok("the builder model authored the bounded semantics; trusted lowerers rendered all three tiers");
    ok("BuildCargo, BuildBeast, and BuildCritter built and signed the exact rendered sources");
    note(&format!(
        "approved semantic digest: {}",
        collaboration.approval.normalized_spec.semantic_digest
    ));

    banner("2. publish — three durable Bestiary proofs");
    let published = publish_and_recover(root.path(), collaboration.capabilities.clone())?;
    for (capability, proof) in &published {
        ok(&format!(
            "{:?} EntryProof survived recovery: artifact sha256:{}, manifest {}",
            capability.manifest.abi.backend,
            capability.artifact_hash,
            capability.manifest.content_address.as_deref().unwrap_or("<missing>")
        ));
        note(&format!("proof signature prefix: {}…", &proof.signature[..16]));
    }
    let capabilities =
        published.iter().map(|(capability, _)| capability.clone()).collect::<Vec<_>>();

    banner("3. execute — every engine in two isolated worlds");
    let artifact_author = capabilities
        .first()
        .ok_or_else(|| "the published capability suite is empty".to_string())?
        .manifest
        .provenance
        .author
        .clone()
        .ok_or_else(|| "published manifest lost its author".to_string())?;
    if capabilities.iter().any(|capability| {
        capability.manifest.provenance.author.as_deref() != Some(artifact_author.as_str())
    }) {
        return Err("backend artifacts were not signed by one pinned build identity".into());
    }
    let proofs = prove_all_tiers(
        root.path(),
        &capabilities,
        &artifact_author,
        &collaboration.approval.normalized_spec,
    )?;
    for (capability, proof) in capabilities.iter().zip(&proofs) {
        ok(&format!(
            "{:?}: B-local Job {} ran {} → {}; A→B Job {} ran {} → {}",
            capability.manifest.abi.backend,
            proof.local.job,
            proof.local_input,
            proof.local_result,
            proof.remote.job,
            proof.remote_input,
            proof.remote_result,
        ));
        note(&format!(
            "stable tier FunctionId: {}#{}",
            proof.function.manifest_content_address, proof.function.entrypoint
        ));
    }

    if let Some(directory) = &evidence_directory {
        let seal = persist_live_evidence(
            directory,
            &collaboration,
            &published,
            &proofs,
            source_before
                .as_ref()
                .ok_or_else(|| "live source identity was not initialized".to_string())?,
        )?;
        let signer = evidence_signer
            .as_ref()
            .ok_or_else(|| "live evidence signer was not initialized".to_string())?;
        let (seal_path, signed_seal) = directory
            .sign_and_write_seal_sibling_with_ed25519(seal.clone(), signer)
            .map_err(|error| error.to_string())?;
        signed_seal.verify_signature(&Ed25519Verifier).map_err(|error| error.to_string())?;
        ok(&format!(
            "retained live evidence index {} at {}; signed seal {}",
            seal.index_sha256,
            directory.path().display(),
            seal_path.display()
        ));
    }

    banner("done");
    note("Three independently signing model agents produced and used a new shareable capability.");
    note("Daemon, beast, and critter identities are distinct; their typed contract is byte-equal.");
    note(if live {
        "This live run retained provider-reported receipts, signed turns, replay, artifacts, and execution proofs."
    } else {
        "Fixture mode is a hermetic regression/eval only; it is not live-model product evidence."
    });
    note("TCP authentication proves peer identity, not prompt confidentiality.");
    root.cleanup()?;
    Ok(())
}

/// Run the public demo. Returning the error lets `main` print it and exit only after marker-owned
/// state has been dropped and cleaned.
pub fn run(args: &[String]) -> Result<(), String> {
    if args.first().is_some_and(|argument| argument == "verify-live") {
        let Some(inputs) = parse_verify_live_mode(&args[1..])? else {
            return Ok(());
        };
        let verified = verify::verify_live_evidence(&inputs)?;
        println!(
            "{}",
            serde_json::to_string(&verified)
                .map_err(|_| "verified result could not be serialized".to_string())?
        );
        return Ok(());
    }
    run_inner(args)
}

fn parse_verify_live_mode(
    args: &[String],
) -> Result<Option<verify::OfflineVerificationInputs>, String> {
    const USAGE: &str = "usage: dialogue verify-live --expected-seal-signer ED25519_PUBLIC_KEY --candidate-sha GIT_SHA --packaged-binary ABSOLUTE_PATH --evidence-dir ABSOLUTE_PATH --signed-seal ABSOLUTE_0600_PATH [--forbid-semantic SHA256]...";
    if args.iter().any(|argument| matches!(argument.as_str(), "--help" | "-h")) {
        println!("{USAGE}");
        println!(
            "success writes one compact, secret-free JSON object to stdout; refusal exits nonzero"
        );
        return Ok(None);
    }
    let mut expected_seal_signer_public_key = None;
    let mut candidate_sha = None;
    let mut packaged_binary_path = None;
    let mut evidence_dir = None;
    let mut signed_seal_path = None;
    let mut forbidden_prior_semantic_digests = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        index += 1;
        let value = args.get(index).ok_or_else(|| format!("{flag} requires one value\n{USAGE}"))?;
        match flag {
            "--expected-seal-signer" if expected_seal_signer_public_key.is_none() => {
                expected_seal_signer_public_key = Some(value.clone());
            }
            "--candidate-sha" if candidate_sha.is_none() => {
                candidate_sha = Some(value.clone());
            }
            "--packaged-binary" if packaged_binary_path.is_none() => {
                packaged_binary_path = Some(PathBuf::from(value));
            }
            "--evidence-dir" if evidence_dir.is_none() => {
                evidence_dir = Some(PathBuf::from(value));
            }
            "--signed-seal" if signed_seal_path.is_none() => {
                signed_seal_path = Some(PathBuf::from(value));
            }
            "--forbid-semantic" => forbidden_prior_semantic_digests.push(value.clone()),
            _ => {
                return Err(format!("unknown or duplicate verify-live argument `{flag}`\n{USAGE}"))
            }
        }
        index += 1;
    }
    Ok(Some(verify::OfflineVerificationInputs {
        expected_seal_signer_public_key: expected_seal_signer_public_key
            .ok_or_else(|| format!("verify-live requires --expected-seal-signer\n{USAGE}"))?,
        candidate_sha: candidate_sha
            .ok_or_else(|| format!("verify-live requires --candidate-sha\n{USAGE}"))?,
        packaged_binary_path: packaged_binary_path
            .ok_or_else(|| format!("verify-live requires --packaged-binary\n{USAGE}"))?,
        evidence_dir: evidence_dir
            .ok_or_else(|| format!("verify-live requires --evidence-dir\n{USAGE}"))?,
        signed_seal_path: signed_seal_path
            .ok_or_else(|| format!("verify-live requires --signed-seal\n{USAGE}"))?,
        forbidden_prior_semantic_digests,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_signing_seed_accepts_only_lowercase_hex_and_optional_single_lf() {
        let lowercase = "ab".repeat(32);
        assert!(decode_evidence_signing_seed(lowercase.as_bytes()).is_ok());
        assert!(decode_evidence_signing_seed(format!("{lowercase}\n").as_bytes()).is_ok());
        for refused in [
            format!(" {}", lowercase),
            format!("{} ", lowercase),
            format!("{}\r\n", lowercase),
            format!("{}\n\n", lowercase),
            lowercase.to_ascii_uppercase(),
        ] {
            assert!(decode_evidence_signing_seed(refused.as_bytes()).is_err());
        }
    }

    #[test]
    fn verify_live_cli_requires_every_external_pin() {
        let args = vec!["--candidate-sha".into(), "a".repeat(40)];
        assert!(parse_verify_live_mode(&args).is_err());
    }
}
