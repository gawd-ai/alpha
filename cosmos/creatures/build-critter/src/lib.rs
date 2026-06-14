//! `build-critter` — the BUILD creature for the critter (script) tier.
//!
//! `build-cargo`'s own docs name the extension seam: *alternative builders ship as their own
//! creatures bound to the same `Role::BUILD` socket.* This is that sibling for the critter tier —
//! the **no-cargo** builder. Where `build-cargo` writes a `Cargo.toml`, shells out to a real
//! `cargo build`, finds a `.so`, and signs it, `build-critter` does the analog for a script: it
//! **validates the Rhai source compiles and defines `fn handle(env)`** (the critter analog of the
//! cargo compile gate, so a syntactically broken critter never ships), assembles a
//! [`Backend::Critter`] manifest (`abi_tag = gawd_critter_v1`, **artifact = the source bytes** — a
//! critter ships as source text), fills + ed25519-signs provenance with the operator's Abode key,
//! and replies with `build-cargo`'s [`BuildReply`]. Reusing that reply type means an authoring agent
//! and the demo / `alpha node` branch on the **same** `Built` / `Failed` shape across both builders.
//!
//! **Routing.** `Role::BUILD` is single-binding (`Router::bind_role` overwrites), so two builders
//! cannot share the socket; a caller authoring a critter addresses this creature directly by its
//! `CreatureId` (the demo holds both organ ids). The request vocabulary is distinct
//! ([`BuildCritterOp`]), so even if it ever received a daemon `BuildOp` it would simply fail to
//! parse and reply `Failed{Invalid}` — never a panic, never a bad artifact.

use aether::{Creature, CreatureCtx, Dispatch, Envelope, Outcome};
use build_cargo::{validate_manifest_stub_shape, BuildErrorKind, BuildReply, ManifestStub};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::crypto::hex_encode;
use sigil::{Abi, Backend, Ed25519KeyMaterial, Manifest, Provenance};

/// The critter ABI tag. **Must** equal `anima::CRITTER_ABI_TAG`; it is duplicated here rather
/// than depending on the heavyweight `anima` (wasmtime + rhai runtime) graph just for one
/// `&str`. The `authored_critter_loads_through_the_real_engine_and_reverses` integration test
/// (`sanctum/tests/critter_tier.rs`) loads a build-critter-authored manifest through the real kernel,
/// so any drift between the two tags fails CI by construction.
const CRITTER_ABI_TAG: &str = "gawd_critter_v1";

/// The entrypoint a critter must define (the kernel always drives this one function).
const HANDLE_FN: &str = "handle";
/// BUILD requests carry source + metadata, not artifacts. Bound the bus payload before JSON parsing
/// so a misbehaving authoring creature cannot force unbounded deserialization in the build organ.
const MAX_BUILD_CRITTER_OP_BYTES: usize = 8 * 1024 * 1024;
/// A critter ships as source text. Keep this roomy for generated scripts but reject pathological
/// model output before Rhai parsing/compilation.
const MAX_CRITTER_SOURCE_BYTES: usize = 4 * 1024 * 1024;

/// What an authoring agent sends to build a critter — the no-cargo analog of
/// [`build_cargo::BuildOp`]. A `#[serde(tag = "op")]` enum so future ops land additively.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BuildCritterOp {
    /// Compile-validate, assemble, sign, and return a loadable `(manifest, source-bytes)`.
    Author {
        /// The Rhai source the agent authored. Must define `fn handle(env)`.
        source: String,
        /// The manifest's authored half (name / version / entrypoints / capabilities / provides).
        /// `build-critter` fills `abi` (Critter / `gawd_critter_v1`), provenance, and content
        /// address — exactly the split `build-cargo` uses, so the same [`ManifestStub`] an agent
        /// produces for a daemon works for a critter.
        manifest_stub: ManifestStub,
    },
}

impl BuildCritterOp {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

/// The reference no-cargo BUILD creature. Holds only what signing needs — there is no cargo
/// workspace, target dir, timeout, or sandbox seam (a critter is never compiled by a subprocess).
pub struct BuildCritter {
    signing_key: Ed25519KeyMaterial,
    author_label: String,
}

impl BuildCritter {
    /// `signing_key` fills `provenance.signature` on every successful build; `author_label` is the
    /// `provenance.author` an admission policy's allowlist matches (typically the Abode public hex).
    pub fn new(signing_key: Ed25519KeyMaterial, author_label: impl Into<String>) -> Self {
        BuildCritter { signing_key, author_label: author_label.into() }
    }

    /// Validate → assemble → sign. Pure (no I/O), so it is the unit-test entrypoint too.
    pub fn author(&self, source: &str, stub: &ManifestStub) -> BuildReply {
        if source.trim().is_empty() {
            return failed(BuildErrorKind::Invalid, "source is empty".into());
        }
        if source.len() > MAX_CRITTER_SOURCE_BYTES {
            return failed(
                BuildErrorKind::Invalid,
                format!(
                    "source is {} bytes, exceeds {} byte limit",
                    source.len(),
                    MAX_CRITTER_SOURCE_BYTES
                ),
            );
        }
        if let Err(e) =
            validate_manifest_stub_shape(stub, Backend::Critter, CRITTER_ABI_TAG, Vec::new())
        {
            return failed(BuildErrorKind::Invalid, e);
        }

        // 1. Compile gate. A bare engine resolves the same syntax the runtime loader will; a parse
        //    error is the agent's to fix, so report it as `Compile` (re-triable), not `Invalid`.
        let mut engine = rhai::Engine::new();
        // Mirror the runtime loader (`anima`'s `ScriptEngine`): the Rhai dependency is built
        // with `no_module`, and runtime `eval` (dynamic code-gen) is disabled. A critter that uses
        // unavailable language surface is rejected HERE at author time as a compile error, not
        // silently signed and then refused at load — fail-fast, and the two engines stay in lock-step
        // on what compiles.
        engine.disable_symbol("eval");
        // Pin parse-time expression depth to Rhai's non-debug defaults so the author gate accepts
        // exactly what the runtime loader (`anima::ScriptEngine`) accepts, in both debug and
        // release. Rhai's defaults are halved in debug builds, so without this the gate and the loader
        // could disagree across profiles. Keep these two values identical to `ScriptEngine`.
        engine.set_max_expr_depths(64, 32);
        let ast = match engine.compile(source) {
            Ok(ast) => ast,
            Err(e) => {
                return failed(BuildErrorKind::Compile, format!("critter compile error: {e}"))
            }
        };
        if !ast.iter_functions().any(|f| f.name == HANDLE_FN) {
            return failed(
                BuildErrorKind::Invalid,
                format!("critter must define `fn {HANDLE_FN}(env)`; none found in the script"),
            );
        }

        // 2. Assemble. The artifact IS the UTF-8 source bytes (deterministic, content-addressable);
        //    `source_hash` and `build_hash` are therefore the same sha256 — honest for an
        //    identity "build". `target` is empty: a critter is portable source, not arch-pinned.
        let artifact = source.as_bytes().to_vec();
        let digest = sha256_hex(&artifact);
        let mut manifest = Manifest {
            name: stub.name.clone(),
            version: stub.version.clone(),
            abi: Abi {
                backend: Backend::Critter,
                abi_tag: CRITTER_ABI_TAG.to_string(),
                target: Vec::new(),
            },
            entrypoints: stub.entrypoints.clone(),
            capabilities: stub.capabilities.clone(),
            requirements: Default::default(),
            provenance: Provenance {
                author: Some(self.author_label.clone()),
                source_hash: Some(digest.clone()),
                build_hash: Some(digest),
                signature: None,
                realm: None,
            },
            content_address: None,
            provides: stub.provides.clone(),
        };
        // 3. Sign. **Signing order is load-bearing** (the same invariant `build-cargo` documents):
        //    `signing_payload()` strips only `provenance.signature`, not `content_address`, so the
        //    content address must be set BEFORE signing or the receiver's recomputed payload drifts.
        manifest.content_address = Some(manifest.compute_content_address());
        manifest.provenance.signature = Some(self.signing_key.sign(&manifest.signing_payload()));

        // 4. Sanity-gate the assembled manifest exactly as build-cargo does, so an inadmissible stub
        //    is reported here (the agent revises) rather than at `Kernel::load`.
        if let Err(e) = manifest.validate() {
            return failed(
                BuildErrorKind::Invalid,
                format!("authored critter manifest fails validation: {e}"),
            );
        }
        BuildReply::Built { manifest, artifact }
    }
}

impl Creature for BuildCritter {
    // Unlike `build-cargo`, this builder publishes no PROPRIOCEPTION `BuildEvent`: `author` is
    // synchronous and pure (no captured bus handle — `bind` is intentionally a no-op so the builder
    // stays the unit-test entrypoint), so a critter build leaves no nervous-system-tape entry.
    // Acceptable: build-cargo documents proprio as best-effort, never load-bearing.
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reply = if env.payload.len() > MAX_BUILD_CRITTER_OP_BYTES {
            failed(
                BuildErrorKind::Invalid,
                format!(
                    "build-critter op payload is {} bytes, exceeds {} byte limit",
                    env.payload.len(),
                    MAX_BUILD_CRITTER_OP_BYTES
                ),
            )
        } else {
            match serde_json::from_slice::<BuildCritterOp>(&env.payload) {
                Ok(BuildCritterOp::Author { source, manifest_stub }) => {
                    self.author(&source, &manifest_stub)
                }
                // Not our op (e.g. a daemon `BuildOp` mis-addressed here): a clean structured refusal,
                // never a panic on hostile input (R9).
                Err(e) => {
                    failed(BuildErrorKind::Invalid, format!("not a BuildCritterOp::Author: {e}"))
                }
            }
        };
        // Stamp the same `build.reply` schema header build-cargo sets, so both BUILD creatures are
        // indistinguishable to a schema-based router/telemetry filter — the shared `BuildReply` wire
        // body and the reply schema now agree across the two builders.
        Outcome::send(Dispatch::reply_to_env(&env, reply.to_bytes()).with_schema("build.reply"))
    }
}

fn failed(kind: BuildErrorKind, message: String) -> BuildReply {
    BuildReply::Failed { kind, message, stderr: String::new(), stdout: String::new() }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex_encode(hasher.finalize().as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sigil::Verifier;

    fn key() -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([7u8; 32]).expect("seed")
    }

    fn stub() -> ManifestStub {
        ManifestStub {
            name: "echo-critter".to_string(),
            version: "0.1.0".to_string(),
            entrypoints: Vec::new(),
            capabilities: Default::default(),
            provides: Vec::new(),
        }
    }

    #[test]
    fn authors_a_signed_loadable_critter_manifest() {
        let k = key();
        let author = k.public_hex().to_string();
        let bc = BuildCritter::new(k, author.clone());
        let reply = bc.author("fn handle(env) { env.payload }", &stub());
        let (manifest, artifact) = match reply {
            BuildReply::Built { manifest, artifact } => (manifest, artifact),
            BuildReply::Failed { kind, message, .. } => {
                panic!("unexpected failure {kind:?}: {message}")
            }
        };
        assert_eq!(manifest.abi.backend, Backend::Critter);
        assert_eq!(manifest.abi.abi_tag, CRITTER_ABI_TAG);
        assert_eq!(artifact, b"fn handle(env) { env.payload }", "artifact is the source bytes");
        assert_eq!(manifest.provenance.author.as_deref(), Some(author.as_str()));
        // The signature verifies against the signed payload (content_address was set before signing).
        let verifier = sigil::Ed25519Verifier;
        assert!(
            verifier.verify(
                &author,
                &manifest.signing_payload(),
                manifest.provenance.signature.as_deref().unwrap_or(""),
            ),
            "authored critter manifest must carry a valid signature"
        );
        assert_eq!(
            manifest.content_address.as_deref(),
            Some(manifest.compute_content_address().as_str()),
            "content address binds the manifest body"
        );
    }

    #[test]
    fn rejects_a_syntactically_broken_critter_as_compile_failure() {
        let bc = BuildCritter::new(key(), "author");
        match bc.author("fn handle(env) { this is not rhai", &stub()) {
            BuildReply::Failed { kind, .. } => assert_eq!(kind, BuildErrorKind::Compile),
            BuildReply::Built { .. } => panic!("a broken script must not build"),
        }
    }

    #[test]
    fn rejects_a_critter_with_no_handle_fn_as_invalid() {
        let bc = BuildCritter::new(key(), "author");
        match bc.author("fn nope(env) { env.payload }", &stub()) {
            BuildReply::Failed { kind, .. } => assert_eq!(kind, BuildErrorKind::Invalid),
            BuildReply::Built { .. } => panic!("a script with no `handle` must not build"),
        }
    }

    #[test]
    fn rejects_oversized_source_before_rhai_compile() {
        let bc = BuildCritter::new(key(), "author");
        match bc.author(&"x".repeat(MAX_CRITTER_SOURCE_BYTES + 1), &stub()) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("exceeds"), "{message}");
            }
            BuildReply::Built { .. } => panic!("oversized source must not build"),
        }
    }

    #[test]
    fn rejects_invalid_manifest_stub_before_rhai_compile() {
        let bc = BuildCritter::new(key(), "author");
        let mut stub = stub();
        stub.provides = vec!["policy".into(), "policy".into()];
        match bc.author("this is not valid rhai either", &stub) {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("manifest_stub"), "{message}");
                assert!(message.contains("duplicate provides"), "{message}");
            }
            BuildReply::Built { .. } => panic!("invalid manifest stub must not build"),
        }
    }

    #[test]
    fn rejects_imports_at_the_same_gate_as_the_runtime_loader() {
        let bc = BuildCritter::new(key(), "author");
        match bc.author("import \"helper\" as helper; fn handle(env) { env.payload }", &stub()) {
            BuildReply::Failed { kind, .. } => assert_eq!(kind, BuildErrorKind::Compile),
            BuildReply::Built { .. } => panic!("an importing script must not build"),
        }
    }

    #[test]
    fn a_non_author_payload_is_a_clean_invalid_reply_not_a_panic() {
        let mut bc = BuildCritter::new(key(), "author");
        let env = {
            use aether::{Address, CreatureId, Header};
            Envelope {
                header: Header {
                    from: Address::Creature(CreatureId(1)),
                    to: Address::Creature(CreatureId(2)),
                    reply_to: None,
                    seq: 0,
                    causal: vec![],
                    stamp: 0,
                    sig: String::new(),
                    corr: None,
                    commitment: None,
                    schema: String::new(),
                    origin: None,
                },
                payload: b"not json".to_vec(),
            }
        };
        let out = bc.handle(env);
        assert_eq!(out.dispatches.len(), 1, "always replies");
        let reply: BuildReply =
            serde_json::from_slice(&out.dispatches[0].payload).expect("a BuildReply");
        assert!(matches!(reply, BuildReply::Failed { kind: BuildErrorKind::Invalid, .. }));
    }

    #[test]
    fn oversized_author_payload_is_a_clean_invalid_reply_before_json_parse() {
        let mut bc = BuildCritter::new(key(), "author");
        let env = {
            use aether::{Address, CreatureId, Header};
            Envelope {
                header: Header {
                    from: Address::Creature(CreatureId(1)),
                    to: Address::Creature(CreatureId(2)),
                    reply_to: None,
                    seq: 0,
                    causal: vec![],
                    stamp: 0,
                    sig: String::new(),
                    corr: None,
                    commitment: None,
                    schema: String::new(),
                    origin: None,
                },
                payload: vec![b'{'; MAX_BUILD_CRITTER_OP_BYTES + 1],
            }
        };
        let out = bc.handle(env);
        assert_eq!(out.dispatches.len(), 1, "always replies");
        let reply: BuildReply =
            serde_json::from_slice(&out.dispatches[0].payload).expect("a BuildReply");
        match reply {
            BuildReply::Failed { kind, message, .. } => {
                assert_eq!(kind, BuildErrorKind::Invalid);
                assert!(message.contains("build-critter op payload"), "{message}");
                assert!(message.contains("exceeds"), "{message}");
            }
            BuildReply::Built { .. } => panic!("oversized payload must not build"),
        }
    }
}
