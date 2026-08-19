//! `build-beast` — the no-Cargo BUILD creature for the WASM beast tier.
//!
//! The author supplies WebAssembly text (WAT) and the same [`ManifestStub`] used by the native and
//! critter builders. This creature compiles WAT in-process, validates a closed core-WASM module with
//! the shipped `memory + alloc + handle` guest ABI, assembles a `Backend::Beast` manifest, and signs
//! the exact emitted `.wasm` bytes. It never invokes Cargo and needs no installed wasm32 target.
//!
//! `Role::BUILD` is single-binding, so callers that compose multiple builders address this creature
//! directly by its `CreatureId`, exactly as they do `build-critter`.

use aether::{ffi::ABI_TAG, Creature, CreatureCtx, Dispatch, Envelope, Outcome};
use build_cargo::{validate_manifest_stub_shape, BuildErrorKind, BuildReply, ManifestStub};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sigil::crypto::hex_encode;
use sigil::{Abi, Backend, Ed25519KeyMaterial, Manifest, Provenance};
use wasmparser::{
    Encoding, ExternalKind, FuncType, MemoryType, Parser, Payload, ValType, Validator,
};

const MAX_BUILD_BEAST_OP_BYTES: usize = 8 * 1024 * 1024;
const MAX_WAT_SOURCE_BYTES: usize = 4 * 1024 * 1024;
const MAX_BEAST_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const WASM_TARGET: &str = "wasm32-unknown-unknown";

/// A no-Cargo beast build request. The source is WAT; the artifact returned in [`BuildReply`] is
/// the compiled core-WASM binary.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BuildBeastOp {
    Author { source: String, manifest_stub: ManifestStub },
}

impl BuildBeastOp {
    pub fn to_bytes(&self) -> Vec<u8> {
        aether::wire::to_bytes(self)
    }
}

pub struct BuildBeast {
    signing_key: Ed25519KeyMaterial,
    author_label: String,
}

impl BuildBeast {
    pub fn new(signing_key: Ed25519KeyMaterial, author_label: impl Into<String>) -> Self {
        Self { signing_key, author_label: author_label.into() }
    }

    /// Compile, validate, assemble, content-address, and sign one beast. This is pure in-process
    /// work: no subprocess, Cargo target directory, network, filesystem, or ambient toolchain.
    pub fn author(&self, source: &str, stub: &ManifestStub) -> BuildReply {
        if source.trim().is_empty() {
            return failed(BuildErrorKind::Invalid, "source is empty".into());
        }
        if source.len() > MAX_WAT_SOURCE_BYTES {
            return failed(
                BuildErrorKind::Invalid,
                format!(
                    "WAT source is {} bytes, exceeds {} byte limit",
                    source.len(),
                    MAX_WAT_SOURCE_BYTES
                ),
            );
        }
        if let Err(error) = validate_manifest_stub_shape(
            stub,
            Backend::Beast,
            ABI_TAG,
            vec![WASM_TARGET.to_string()],
        ) {
            return failed(BuildErrorKind::Invalid, error);
        }

        let artifact = match wat::parse_str(source) {
            Ok(artifact) => artifact,
            Err(error) => {
                return failed(BuildErrorKind::Compile, format!("beast WAT compile error: {error}"))
            }
        };
        if artifact.len() > MAX_BEAST_ARTIFACT_BYTES {
            return failed(
                BuildErrorKind::Invalid,
                format!(
                    "compiled beast is {} bytes, exceeds {} byte limit",
                    artifact.len(),
                    MAX_BEAST_ARTIFACT_BYTES
                ),
            );
        }
        if let Err(error) = validate_guest_abi(&artifact) {
            return failed(BuildErrorKind::Compile, error);
        }

        let source_hash = sha256_hex(source.as_bytes());
        let build_hash = sha256_hex(&artifact);
        let mut manifest = Manifest {
            name: stub.name.clone(),
            version: stub.version.clone(),
            abi: Abi {
                backend: Backend::Beast,
                abi_tag: ABI_TAG.to_string(),
                target: vec![WASM_TARGET.to_string()],
            },
            entrypoints: stub.entrypoints.clone(),
            capabilities: stub.capabilities.clone(),
            requirements: Default::default(),
            provenance: Provenance {
                author: Some(self.author_label.clone()),
                source_hash: Some(source_hash),
                build_hash: Some(build_hash),
                signature: None,
                realm: None,
            },
            content_address: None,
            provides: stub.provides.clone(),
        };
        manifest.content_address = Some(manifest.compute_content_address());
        manifest.provenance.signature = Some(self.signing_key.sign(&manifest.signing_payload()));
        if let Err(error) = manifest.validate() {
            return failed(
                BuildErrorKind::Invalid,
                format!("authored beast manifest fails validation: {error}"),
            );
        }
        BuildReply::Built { manifest, artifact }
    }
}

impl Creature for BuildBeast {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let reply = if env.payload.len() > MAX_BUILD_BEAST_OP_BYTES {
            failed(
                BuildErrorKind::Invalid,
                format!(
                    "build-beast op payload is {} bytes, exceeds {} byte limit",
                    env.payload.len(),
                    MAX_BUILD_BEAST_OP_BYTES
                ),
            )
        } else {
            match serde_json::from_slice::<BuildBeastOp>(&env.payload) {
                Ok(BuildBeastOp::Author { source, manifest_stub }) => {
                    self.author(&source, &manifest_stub)
                }
                Err(error) => {
                    failed(BuildErrorKind::Invalid, format!("not a BuildBeastOp::Author: {error}"))
                }
            }
        };
        Outcome::send(Dispatch::reply_to_env(&env, reply.to_bytes()).with_schema("build.reply"))
    }
}

fn validate_guest_abi(bytes: &[u8]) -> Result<(), String> {
    Validator::new()
        .validate_all(bytes)
        .map_err(|error| format!("invalid core WASM module: {error}"))?;

    let mut types = Vec::<FuncType>::new();
    let mut functions = Vec::<u32>::new();
    let mut memories = Vec::<MemoryType>::new();
    let mut memory_export = None;
    let mut alloc_export = None;
    let mut handle_export = None;
    for payload in Parser::new(0).parse_all(bytes) {
        match payload.map_err(|error| format!("cannot inspect WASM module: {error}"))? {
            Payload::Version { encoding, .. } if encoding != Encoding::Module => {
                return Err("beast artifact must be a core WASM module, not a component".into())
            }
            Payload::TypeSection(reader) => {
                for ty in reader.into_iter_err_on_gc_types() {
                    types.push(ty.map_err(|error| format!("invalid function type: {error}"))?);
                }
            }
            Payload::ImportSection(reader) => {
                if let Some(import) = reader.into_imports().next() {
                    let import = import.map_err(|error| format!("invalid import: {error}"))?;
                    return Err(format!(
                        "beast imports are closed by construction; found `{}::{}`",
                        import.module, import.name
                    ));
                }
            }
            Payload::FunctionSection(reader) => {
                for ty in reader {
                    functions
                        .push(ty.map_err(|error| format!("invalid function section: {error}"))?);
                }
            }
            Payload::MemorySection(reader) => {
                for memory in reader {
                    memories
                        .push(memory.map_err(|error| format!("invalid memory section: {error}"))?);
                }
            }
            Payload::ExportSection(reader) => {
                for export in reader {
                    let export =
                        export.map_err(|error| format!("invalid export section: {error}"))?;
                    match export.name {
                        "memory" => memory_export = Some((export.kind, export.index)),
                        "alloc" => alloc_export = Some((export.kind, export.index)),
                        "handle" => handle_export = Some((export.kind, export.index)),
                        _ => {}
                    }
                }
            }
            Payload::StartSection { .. } => {
                return Err("beast modules may not execute a start function at load time".into())
            }
            _ => {}
        }
    }

    let memory_index = match memory_export {
        Some((ExternalKind::Memory, index)) => index,
        Some(_) => return Err("beast export `memory` is not linear memory".into()),
        None => return Err("beast export `memory` is missing".into()),
    };
    if memories.len() != 1 || memory_index != 0 {
        return Err("beast must define and export exactly one linear memory".into());
    }
    let memory = memories[0];
    if memory.memory64 || memory.shared || memory.page_size_log2.is_some() {
        return Err(
            "beast memory must be unshared wasm32 memory with the standard 64 KiB page size".into(),
        );
    }
    require_function_signature(
        "alloc",
        alloc_export,
        &functions,
        &types,
        &[ValType::I32],
        &[ValType::I32],
    )?;
    require_function_signature(
        "handle",
        handle_export,
        &functions,
        &types,
        &[ValType::I32, ValType::I32],
        &[ValType::I64],
    )
}

fn require_function_signature(
    name: &str,
    export: Option<(ExternalKind, u32)>,
    functions: &[u32],
    types: &[FuncType],
    params: &[ValType],
    results: &[ValType],
) -> Result<(), String> {
    let Some((kind, function_index)) = export else {
        return Err(format!("beast export `{name}` is missing"));
    };
    if kind != ExternalKind::Func {
        return Err(format!("beast export `{name}` is not a function"));
    }
    let type_index = *functions
        .get(function_index as usize)
        .ok_or_else(|| format!("beast export `{name}` has an invalid function index"))?;
    let function_type = types
        .get(type_index as usize)
        .ok_or_else(|| format!("beast export `{name}` has an invalid type index"))?;
    if function_type.params() != params || function_type.results() != results {
        return Err(format!(
            "beast export `{name}` has signature {function_type}, expected params {params:?} and results {results:?}"
        ));
    }
    Ok(())
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

    const IDENTITY_WAT: &str = r#"
        (module
          (memory (export "memory") 1)
          (global $bump (mut i32) (i32.const 1024))
          (func (export "alloc") (param $len i32) (result i32)
            (local $ptr i32)
            (local.set $ptr (global.get $bump))
            (global.set $bump (i32.add (global.get $bump) (local.get $len)))
            (local.get $ptr))
          (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
            (i64.or
              (i64.shl (i64.extend_i32_u (local.get $ptr)) (i64.const 32))
              (i64.extend_i32_u (local.get $len)))))
    "#;

    fn key() -> Ed25519KeyMaterial {
        Ed25519KeyMaterial::from_seed([17; 32]).expect("seed")
    }

    fn stub() -> ManifestStub {
        ManifestStub {
            name: "identity-beast".into(),
            version: "0.1.0".into(),
            entrypoints: vec![sigil::Entrypoint::new("handle", "bytes -> bytes")],
            capabilities: Default::default(),
            provides: vec![],
        }
    }

    #[test]
    fn authors_compiled_signed_beast_with_distinct_source_and_build_hashes() {
        let signing_key = key();
        let author = signing_key.public_hex().to_string();
        let builder = BuildBeast::new(signing_key, author.clone());
        let (manifest, artifact) = match builder.author(IDENTITY_WAT, &stub()) {
            BuildReply::Built { manifest, artifact } => (manifest, artifact),
            BuildReply::Failed { kind, message, .. } => {
                panic!("unexpected {kind:?} build failure: {message}")
            }
        };

        assert_eq!(manifest.abi.backend, Backend::Beast);
        assert_eq!(manifest.abi.abi_tag, ABI_TAG);
        assert_eq!(manifest.abi.target, vec![WASM_TARGET.to_string()]);
        assert_eq!(&artifact[..4], b"\0asm");
        let expected_source_hash = sha256_hex(IDENTITY_WAT.as_bytes());
        let expected_build_hash = sha256_hex(&artifact);
        assert_eq!(manifest.provenance.source_hash.as_deref(), Some(expected_source_hash.as_str()));
        assert_eq!(manifest.provenance.build_hash.as_deref(), Some(expected_build_hash.as_str()));
        assert_ne!(
            manifest.provenance.source_hash.as_deref(),
            manifest.provenance.build_hash.as_deref()
        );
        assert_eq!(
            manifest.content_address.as_deref(),
            Some(manifest.compute_content_address().as_str())
        );
        assert!(sigil::Ed25519Verifier.verify(
            &author,
            &manifest.signing_payload(),
            manifest.provenance.signature.as_deref().expect("signature"),
        ));
    }

    #[test]
    fn rejects_imports_start_functions_and_wrong_export_signatures_before_signing() {
        let builder = BuildBeast::new(key(), "author");
        let importing = IDENTITY_WAT.replacen(
            "(module",
            "(module (import \"ambient\" \"clock\" (func $clock))",
            1,
        );
        assert!(matches!(
            builder.author(&importing, &stub()),
            BuildReply::Failed { kind: BuildErrorKind::Compile, message, .. }
                if message.contains("imports are closed")
        ));

        let with_start = IDENTITY_WAT.replacen(
            "(memory (export \"memory\") 1)",
            "(func $start) (start $start) (memory (export \"memory\") 1)",
            1,
        );
        assert!(matches!(
            builder.author(&with_start, &stub()),
            BuildReply::Failed { kind: BuildErrorKind::Compile, message, .. }
                if message.contains("start function")
        ));

        let wrong_alloc = r#"
            (module
              (memory (export "memory") 1)
              (func (export "alloc") (param i64) (result i32) (i32.const 0))
              (func (export "handle") (param i32 i32) (result i64) (i64.const 0)))
        "#;
        assert!(matches!(
            builder.author(wrong_alloc, &stub()),
            BuildReply::Failed { kind: BuildErrorKind::Compile, message, .. }
                if message.contains("export `alloc`")
        ));
    }

    #[test]
    fn malformed_wat_and_manifest_are_structured_failures() {
        let builder = BuildBeast::new(key(), "author");
        assert!(matches!(
            builder.author("(module", &stub()),
            BuildReply::Failed { kind: BuildErrorKind::Compile, .. }
        ));
        let mut invalid_stub = stub();
        invalid_stub.name.clear();
        assert!(matches!(
            builder.author(IDENTITY_WAT, &invalid_stub),
            BuildReply::Failed { kind: BuildErrorKind::Invalid, .. }
        ));
    }

    #[test]
    fn malformed_bus_payload_returns_one_invalid_build_reply() {
        use aether::{Address, CreatureId, Header};

        let mut builder = BuildBeast::new(key(), "author");
        let env = Envelope {
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
        };
        let out = builder.handle(env);
        assert_eq!(out.dispatches.len(), 1);
        let reply: BuildReply = serde_json::from_slice(&out.dispatches[0].payload).unwrap();
        assert!(matches!(reply, BuildReply::Failed { kind: BuildErrorKind::Invalid, .. }));
    }
}
