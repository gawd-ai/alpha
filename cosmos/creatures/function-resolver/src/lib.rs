//! Exact Bestiary function-alias resolver.
//!
//! Resolution is deliberately model-free: exact selector matching, structured-entrypoint presence,
//! immutable manifest/artifact pinning, and ambiguity refusal. Reputation, quarantine, and trust
//! evidence are preserved for injected policy; they do not silently rank candidates here.

#![forbid(unsafe_code)]

use aether::{Creature, CreatureCtx, CreatureId, Dispatch, Envelope, Outcome};
use bestiary::CatalogEntry;
use gawdfn::{
    AuthoritySigner, FunctionDeployMessageV1, FunctionId, FunctionSelectorV1, ProtocolErrorV1,
    ResolutionReceiptV1, ResolveRequestV1, ResolvedFunctionV1, SignedRecordV1, Validate,
    MAX_JOB_MESSAGE_BYTES, SCHEMA_FUNCTION_DEPLOY_V1,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use thiserror::Error;

/// Hard ceiling on one injected catalog snapshot considered by a single resolution.
pub const MAX_RESOLUTION_CANDIDATES: usize = 1_024;

/// Injected Bestiary view. A durable store, federated cache, or test snapshot can fill it.
pub trait FunctionCatalog: Send + Sync {
    fn candidates(&self, request: &ResolveRequestV1) -> Result<Vec<CatalogEntry>, String>;
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResolveError {
    #[error("invalid function selector: {0}")]
    Invalid(String),
    #[error("function selector was not found")]
    NotFound,
    #[error("function selector is ambiguous across {matches} immutable artifacts")]
    Ambiguous { matches: usize },
    #[error("catalog manifest is inconsistent: {0}")]
    Inconsistent(String),
    #[error("catalog source failed: {0}")]
    Catalog(String),
    #[error("catalog returned {candidates} candidates, limit is {limit}")]
    Capacity { candidates: usize, limit: usize },
    #[error("resolution request is unauthorized: {0}")]
    Unauthorized(String),
    #[error("cannot sign resolution: {0}")]
    Signing(String),
}

pub struct FunctionResolver {
    signer: Arc<dyn AuthoritySigner>,
    catalog: Arc<dyn FunctionCatalog>,
    me: Option<CreatureId>,
}

impl FunctionResolver {
    pub fn new(signer: Arc<dyn AuthoritySigner>, catalog: Arc<dyn FunctionCatalog>) -> Self {
        Self { signer, catalog, me: None }
    }

    pub fn resolve(
        &self,
        selector: FunctionSelectorV1,
        catalog: &[CatalogEntry],
        resolved_at_unix_ms: Option<u64>,
        evidence: Vec<gawdfn::EvidenceRefV1>,
    ) -> Result<ResolvedFunctionV1, ResolveError> {
        selector.validate().map_err(|error| ResolveError::Invalid(error.to_string()))?;
        if catalog.len() > MAX_RESOLUTION_CANDIDATES {
            return Err(ResolveError::Capacity {
                candidates: catalog.len(),
                limit: MAX_RESOLUTION_CANDIDATES,
            });
        }
        let mut matches = BTreeMap::<(String, String, String), FunctionId>::new();
        for row in catalog {
            let computed = row.manifest.compute_content_address();
            let entrypoint = match &selector {
                FunctionSelectorV1::Alias { alias } => {
                    if row.realm.0 != alias.realm
                        || row.manifest.name != alias.name
                        || row.manifest.version != alias.version
                    {
                        continue;
                    }
                    alias.entrypoint.as_str()
                }
                FunctionSelectorV1::Id { function } => {
                    if computed != function.manifest_content_address {
                        continue;
                    }
                    function.entrypoint.as_str()
                }
            };
            let Some(entry) =
                row.manifest.entrypoints.iter().find(|entry| entry.name == entrypoint)
            else {
                continue;
            };
            if entry.contract.is_none() {
                continue; // legacy advertised handles are not typed functions
            }
            row.manifest.validate().map_err(|error| {
                ResolveError::Inconsistent(format!(
                    "manifest `{}/{}` is invalid: {error}",
                    row.manifest.name, row.manifest.version
                ))
            })?;
            if row.manifest.content_address.as_deref() != Some(computed.as_str()) {
                return Err(ResolveError::Inconsistent(format!(
                    "manifest `{}/{}` declared {:?}, computed {computed}",
                    row.manifest.name, row.manifest.version, row.manifest.content_address
                )));
            }
            let artifact_hash = normalize_sha256(&row.artifact_hash).ok_or_else(|| {
                ResolveError::Inconsistent(format!(
                    "artifact hash `{}` is not SHA-256",
                    row.artifact_hash
                ))
            })?;
            let artifact_hex = artifact_hash.strip_prefix("sha256:").ok_or_else(|| {
                ResolveError::Inconsistent("normalized artifact hash lost its sha256 scheme".into())
            })?;
            if row.manifest.provenance.build_hash.as_deref() != Some(artifact_hex) {
                return Err(ResolveError::Inconsistent(format!(
                    "manifest `{}/{}` build hash does not bind catalog artifact {}",
                    row.manifest.name, row.manifest.version, artifact_hash
                )));
            }
            matches.insert(
                (computed.clone(), entrypoint.to_string(), artifact_hash),
                FunctionId {
                    manifest_content_address: computed,
                    entrypoint: entrypoint.to_string(),
                },
            );
        }
        if matches.is_empty() {
            return Err(ResolveError::NotFound);
        }
        if matches.len() != 1 {
            return Err(ResolveError::Ambiguous { matches: matches.len() });
        }
        let Some(((_, _, artifact_hash), function)) = matches.into_iter().next() else {
            return Err(ResolveError::Inconsistent(
                "unique resolution candidate disappeared before signing".into(),
            ));
        };
        let receipt = ResolutionReceiptV1 {
            selector: selector.clone(),
            function: function.clone(),
            artifact_hash: artifact_hash.clone(),
            resolved_at_unix_ms,
            evidence,
        };
        let resolution =
            SignedRecordV1::sign(SCHEMA_FUNCTION_DEPLOY_V1, receipt, self.signer.as_ref())
                .map_err(|error| ResolveError::Signing(error.to_string()))?;
        Ok(ResolvedFunctionV1 {
            requested: selector,
            function,
            artifact_hash,
            resolution: Some(resolution),
        })
    }

    fn resolve_request(
        &self,
        request: SignedRecordV1<ResolveRequestV1>,
    ) -> Result<SignedRecordV1<ResolutionReceiptV1>, ResolveError> {
        request.validate().map_err(|error| ResolveError::Invalid(error.to_string()))?;
        if request.schema != SCHEMA_FUNCTION_DEPLOY_V1
            || !request.verify()
            || request.signer != request.payload.requested_by.as_str()
        {
            return Err(ResolveError::Unauthorized("invalid requester signature".into()));
        }
        let catalog = self.catalog.candidates(&request.payload).map_err(ResolveError::Catalog)?;
        self.resolve(request.payload.selector, &catalog, None, request.payload.evidence)?
            .resolution
            .ok_or_else(|| ResolveError::Signing("resolution receipt missing".into()))
    }
}

impl Creature for FunctionResolver {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.me = Some(ctx.me);
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        if env.header.schema != SCHEMA_FUNCTION_DEPLOY_V1
            || env.payload.len() > MAX_JOB_MESSAGE_BYTES
        {
            return Outcome::none();
        }
        let Ok(FunctionDeployMessageV1::Resolve { request }) =
            serde_json::from_slice::<FunctionDeployMessageV1>(&env.payload)
        else {
            return Outcome::none();
        };
        let response = match self.resolve_request(request) {
            Ok(receipt) => FunctionDeployMessageV1::Resolved { receipt },
            Err(error) => FunctionDeployMessageV1::Error {
                error: ProtocolErrorV1 {
                    code: resolve_code(&error).into(),
                    message: bound_reason(error.to_string()),
                    retryable: matches!(error, ResolveError::Catalog(_)),
                },
            },
        };
        Outcome::send(
            Dispatch::reply_to_env(&env, aether::wire::to_bytes(&response))
                .with_schema(SCHEMA_FUNCTION_DEPLOY_V1),
        )
    }
}

fn normalize_sha256(value: &str) -> Option<String> {
    let raw = value.strip_prefix("sha256:").unwrap_or(value);
    (raw.len() == 64
        && raw.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| format!("sha256:{raw}"))
}

fn resolve_code(error: &ResolveError) -> &'static str {
    match error {
        ResolveError::NotFound => "not_found",
        ResolveError::Ambiguous { .. } => "ambiguous",
        ResolveError::Unauthorized(_) => "unauthorized",
        ResolveError::Catalog(_) => "catalog",
        ResolveError::Capacity { .. } => "capacity",
        ResolveError::Invalid(_) | ResolveError::Inconsistent(_) | ResolveError::Signing(_) => {
            "invalid"
        }
    }
}

fn bound_reason(mut reason: String) -> String {
    if reason.len() > gawdfn::MAX_REASON_BYTES {
        let mut end = gawdfn::MAX_REASON_BYTES;
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        reason.truncate(end);
    }
    reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::RealmId;
    use gawdfn::{
        Ed25519SeedSigner, EffectClassV1, EntrypointContractV1, FunctionAlias, SchemaRefV1,
    };
    use serde_json::json;
    use sigil::{Backend, Entrypoint, Manifest};

    struct EmptyCatalog;

    impl FunctionCatalog for EmptyCatalog {
        fn candidates(&self, _request: &ResolveRequestV1) -> Result<Vec<CatalogEntry>, String> {
            Ok(vec![])
        }
    }

    fn resolver() -> FunctionResolver {
        FunctionResolver::new(
            Arc::new(Ed25519SeedSigner::from_seed([31; 32]).unwrap()),
            Arc::new(EmptyCatalog),
        )
    }

    fn alias() -> FunctionSelectorV1 {
        FunctionSelectorV1::Alias {
            alias: FunctionAlias {
                realm: "realm-a".into(),
                name: "typed-worker".into(),
                version: "1.0.0".into(),
                entrypoint: "run".into(),
            },
        }
    }

    fn entry(structured: bool) -> CatalogEntry {
        let mut manifest =
            Manifest::new("typed-worker", "1.0.0", Backend::Daemon, "gawd_creature_v1");
        manifest.entrypoints.push(Entrypoint {
            name: "run".into(),
            signature: "gawd.function.call.v1".into(),
            contract: structured.then(|| EntrypointContractV1 {
                description: "typed test entrypoint".into(),
                input_schema: SchemaRefV1::Inline { schema: json!({"type": "object"}) },
                output_schema: SchemaRefV1::Inline { schema: json!({"type": "object"}) },
                error_schema: None,
                effect: EffectClassV1::Idempotent,
                controls: Default::default(),
            }),
        });
        manifest.provenance.build_hash = Some("b".repeat(64));
        manifest.content_address = Some(manifest.compute_content_address());
        CatalogEntry {
            artifact_hash: "b".repeat(64),
            realm: RealmId::new("realm-a"),
            manifest,
            reputation: None,
            quarantine: None,
        }
    }

    fn hash(ch: char) -> String {
        format!("sha256:{}", ch.to_string().repeat(64))
    }

    #[test]
    fn exact_alias_resolves_only_structured_entrypoint() {
        let row = entry(true);
        let expected_manifest = row.manifest.content_address.clone().unwrap();
        let resolved = resolver().resolve(alias(), &[row], None, vec![]).unwrap();
        assert_eq!(resolved.function.manifest_content_address, expected_manifest);
        assert_eq!(resolved.function.entrypoint, "run");
        assert_eq!(resolved.artifact_hash, hash('b'));
        assert!(resolved.resolution.unwrap().verify());
    }

    #[test]
    fn exact_function_id_resolves_the_same_immutable_artifact() {
        let row = entry(true);
        let function = FunctionId {
            manifest_content_address: row.manifest.content_address.clone().unwrap(),
            entrypoint: "run".into(),
        };
        let selector = FunctionSelectorV1::Id { function: function.clone() };
        let resolved = resolver().resolve(selector, &[row], None, vec![]).unwrap();
        assert_eq!(resolved.function, function);
        assert_eq!(resolved.artifact_hash, hash('b'));
    }

    #[test]
    fn catalog_snapshot_is_bounded_before_candidate_iteration() {
        let rows = vec![entry(true); MAX_RESOLUTION_CANDIDATES + 1];
        assert_eq!(
            resolver().resolve(alias(), &rows, None, vec![]),
            Err(ResolveError::Capacity {
                candidates: MAX_RESOLUTION_CANDIDATES + 1,
                limit: MAX_RESOLUTION_CANDIDATES,
            })
        );
    }

    #[test]
    fn bounded_protocol_reason_preserves_utf8_boundaries() {
        let reason = "€".repeat(gawdfn::MAX_REASON_BYTES);
        let bounded = bound_reason(reason);
        assert!(bounded.len() <= gawdfn::MAX_REASON_BYTES);
        assert!(bounded.is_char_boundary(bounded.len()));
    }

    #[test]
    fn alias_refuses_ambiguous_artifacts() {
        let first = entry(true);
        let mut second = first.clone();
        second.artifact_hash = "c".repeat(64);
        second.manifest.provenance.build_hash = Some("c".repeat(64));
        second.manifest.content_address = Some(second.manifest.compute_content_address());
        assert!(matches!(
            resolver().resolve(alias(), &[first, second], None, vec![]),
            Err(ResolveError::Ambiguous { matches: 2 })
        ));
    }

    #[test]
    fn manifest_build_hash_must_bind_the_catalog_artifact() {
        let mut row = entry(true);
        row.artifact_hash = "c".repeat(64);
        assert!(matches!(
            resolver().resolve(alias(), &[row], None, vec![]),
            Err(ResolveError::Inconsistent(message)) if message.contains("build hash")
        ));
    }

    #[test]
    fn stale_declared_content_address_fails_closed() {
        let mut row = entry(true);
        row.manifest.content_address = Some(hash('f'));
        assert!(matches!(
            resolver().resolve(alias(), &[row], None, vec![]),
            Err(ResolveError::Inconsistent(_))
        ));
    }

    #[test]
    fn legacy_unstructured_entrypoint_is_not_a_function() {
        assert_eq!(
            resolver().resolve(alias(), &[entry(false)], None, vec![]),
            Err(ResolveError::NotFound)
        );
    }
}
