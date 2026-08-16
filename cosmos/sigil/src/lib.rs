//! sigil — the creature contract *at rest / in transit*.
//!
//! One of GAWD's two contracts (the other is the `aether` envelope, the contract
//! *in motion*). A manifest describes a creature before it is admitted, loaded, shipped,
//! or published: who authored it, what tier it runs in, what it needs, what it may do,
//! and which hooks it can fill.
//!
//! This crate is **pure data + a verification _mechanism_**. It carries no policy (what to
//! trust) and no bus/kernel dependency: admission *policy* is an injected creature, and the
//! kernel *reads* this contract, it does not define it. Parsing never panics on hostile
//! input (R9) — malformed bytes become a structured [`ManifestError`].

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use gawdfn::EntrypointContractV1;
use gawdfn::Validate as _;

pub mod crypto;
pub use crypto::{Ed25519KeyMaterial, Ed25519Verifier};

/// Maximum JSON bytes accepted by [`Manifest::parse`] before decoding.
pub const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
/// Manifest metadata caps. These are intentionally generous for real manifests and small enough that
/// manifests remain metadata, not a bulk-data carrier or retained-memory amplifier.
pub const MAX_MANIFEST_NAME_BYTES: usize = 128;
pub const MAX_MANIFEST_VERSION_BYTES: usize = 128;
pub const MAX_MANIFEST_ABI_TAG_BYTES: usize = 128;
pub const MAX_MANIFEST_TARGETS: usize = 64;
pub const MAX_MANIFEST_TARGET_BYTES: usize = 256;
pub const MAX_MANIFEST_ENTRYPOINTS: usize = 64;
pub const MAX_MANIFEST_ENTRYPOINT_NAME_BYTES: usize = 128;
pub const MAX_MANIFEST_ENTRYPOINT_SIGNATURE_BYTES: usize = 512;
pub const MAX_MANIFEST_PROVIDES: usize = 64;
pub const MAX_MANIFEST_PROVIDES_BYTES: usize = 128;
pub const MAX_MANIFEST_CAPABILITY_ITEMS: usize = 128;
pub const MAX_MANIFEST_FS_PATH_BYTES: usize = 4096;
pub const MAX_MANIFEST_CALL_BYTES: usize = 512;
pub const MAX_MANIFEST_REQUIREMENT_ITEMS: usize = 128;
pub const MAX_MANIFEST_REQUIREMENT_FIELD_BYTES: usize = 256;
pub const MAX_MANIFEST_PROVENANCE_FIELD_BYTES: usize = 512;
pub const MAX_MANIFEST_REALM_BYTES: usize = 256;
pub const MAX_MANIFEST_CONTENT_ADDRESS_BYTES: usize = 128;

/// A **Realm** — a collective of Sanctums under shared trust (a distributed-self collective).
/// The same type appears in two places:
///
/// - **As an address grain** (`aether::Address::Realm`/`Omega`) — *routing* into a Realm via
///   the bound gateway creature.
/// - **As an authorship assertion** ([`Provenance::realm`]) — *the author claims this creature
///   belongs to that Realm*. The Abode key still signs; the Realm field is signed alongside it
///   (it rides inside the signing payload).
///
/// The canonical definition lives here in the contract crate because [`Provenance`] carries it,
/// and `aether` re-exports it from `aether::address` to keep the address-grain surface coherent.
///
/// A Realm is just a name; mechanisms (membership management, Realm-key, cross-Realm
/// peering policy) are creatures the operator binds. The `"local"` realm is the default for callers
/// that don't opt into federation.
#[derive(Clone, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
pub struct RealmId(pub String);

impl RealmId {
    /// The default Realm name — `"local"` — for non-federated callers.
    pub const LOCAL: &'static str = "local";

    /// Convenience constructor for the local realm.
    pub fn local() -> Self {
        RealmId(Self::LOCAL.into())
    }

    /// Construct a `RealmId` **without validation** — for trusted, literal, or already-validated
    /// names (config constants, [`RealmId::local`], test fixtures). For a name from an untrusted
    /// source (a peer's manifest `Provenance.realm`, an operator-typed Realm), prefer
    /// [`checked`](Self::checked), which enforces the [`is_valid`](Self::is_valid) invariant.
    pub fn new(s: impl Into<String>) -> Self {
        RealmId(s.into())
    }

    /// Construct a `RealmId` only if it satisfies [`is_valid`](Self::is_valid); otherwise `None`.
    /// The validating entry point for Realm names crossing a trust boundary.
    pub fn checked(s: impl Into<String>) -> Option<Self> {
        let r = RealmId(s.into());
        r.is_valid().then_some(r)
    }

    /// Whether this Realm name is well-formed: **non-empty after trimming, and free of `':'`**.
    /// The colon ban matters because the bus-level capability gate interpolates the
    /// name as `"realm:{name}"` / `"omega:{name}"` (`aether::router::caps_allow`); a name
    /// containing `':'` would produce an ambiguous cap key (`realm:x:y` reads as the inner target,
    /// not the Realm). The field stays `pub String` for serde round-trips and literal construction,
    /// so the substrate cannot *enforce* this on every value — but a creature admitting an
    /// untrusted Realm name should gate on it (or construct via [`checked`](Self::checked)).
    pub fn is_valid(&self) -> bool {
        !self.0.trim().is_empty() && !self.0.contains(':')
    }
}

impl Default for RealmId {
    fn default() -> Self {
        Self::local()
    }
}

/// Which execution tier — and thus which engine — runs a creature. GAWD's Bestiary
/// vocabulary; each maps 1:1 to an engine mechanism (see `anima`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    /// Native in-process `.so` (libloading). **Trusted-by-admission**: the fabric cannot
    /// fully contain malicious in-process native code, so foreign/mobile code never arrives
    /// as a daemon — only as a beast.
    Daemon,
    /// WASM (wasmtime). First-class, isolated by construction — the home of untrusted code.
    Beast,
    /// Script (interpreter). The critter tier is a metered, sandboxed Rhai interpreter.
    Critter,
}

/// The entry boundary descriptor: which engine, what compatibility tag, what targets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Abi {
    pub backend: Backend,
    /// Compatibility tag for the entry boundary (e.g. `"gawd_creature_v1"`); guards safe reload
    /// across versions.
    pub abi_tag: String,
    /// What the artifact was built to run on, as **opaque, open-ended** strings: arch-os triples,
    /// `"wasm32-unknown-unknown"`, or any future/unknown embodiment we cannot enumerate ahead of
    /// time (server, robot, satellite, edge, …). The fabric assigns this **no meaning** — it is
    /// advertised metadata an *injected* matcher (the Distributor) weighs against a node's
    /// advertised embodiment. Empty = unspecified / portable / unknown.
    #[serde(default)]
    pub target: Vec<String>,
}

/// A typed entry the creature exposes. The authoring target generates against `signature`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entrypoint {
    pub name: String,
    /// Legacy human-readable descriptor. It remains signed and stable for existing manifests.
    pub signature: String,
    /// Optional machine-readable Draft 2020-12 input/output/effect contract. It is additive
    /// metadata multiplexed through the existing creature `handle(Envelope)` ABI; it does not add
    /// an engine entrypoint. Eliding `None` preserves every legacy manifest/signing byte.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract: Option<EntrypointContractV1>,
}

impl Entrypoint {
    pub fn new(name: impl Into<String>, signature: impl Into<String>) -> Self {
        Self { name: name.into(), signature: signature.into(), contract: None }
    }
}

/// Network reach a creature declares. Enforced only when an operator opts in;
/// `net:none` blocks egress.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetCapability {
    /// No network. The safe default.
    #[default]
    None,
    /// Loopback / same-node only.
    Loopback,
    /// Outbound connections allowed.
    Outbound,
    /// Unrestricted.
    Any,
}

/// Bus-level + resource capabilities. Enforced ONLY when an operator opts in.
/// `calls` is the *bus-level* capability checked at the one router choke point (`may_send`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub fs: Vec<String>,
    #[serde(default)]
    pub net: NetCapability,
    /// Soft CPU budget (ms); 0 = unset.
    #[serde(default)]
    pub cpu_ms: u64,
    /// Soft memory budget (bytes); 0 = unset.
    #[serde(default)]
    pub mem_bytes: u64,
    /// Which addresses / intents / roles this creature may send to. Empty = unrestricted
    /// (dev default; tightened by injected policy later).
    #[serde(default)]
    pub calls: Vec<String>,
    /// **Opt-in advisory threshold.** If `Some(p)` where `p ∈ 0..=100`, the
    /// engine emits a `BudgetSignal::warn(...)` after a successful handle when the consumed
    /// fraction of `cpu_ms` or `mem_bytes` crosses `p%`. The engine only checks the dimensions
    /// the creature actually has a cap on (`cpu_ms > 0` for fuel, `mem_bytes > 0` for memory).
    /// `None` (the default) means no Warn ever fires. The threshold is operator-declared,
    /// not policy-decided: the fabric ships the *trigger*; the **injected** policy creature
    /// (`BudgetGraceful` or any other) decides whether the Warn earns grace, demotion, or kill.
    /// Values >100 are clamped at engine load time; `Some(0)` fires Warn on
    /// every successful handle (useful for forcing the path in tests).
    ///
    /// **`skip_serializing_if`** keeps the wire compact — a manifest that doesn't set this
    /// field omits the key, keeping the signing-payload determinism tripwire valid
    /// and not forcing every existing creature to re-sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_warn_at: Option<u8>,
    /// **Opt-in per-envelope wall-clock cap (ms).** `Some(n)` traps a creature that exceeds `n` ms of
    /// wall time in a single `handle`, surfacing a `Hard` `BudgetSignal { kind: Wall }` — the same
    /// gradient shape as a fuel or memory breach. Enforced for the **beast** tier via wasmtime epoch
    /// interruption (one engine-global ticker) and for the **critter** tier via the Rhai `on_progress`
    /// watchdog. The **daemon (native)** tier does not enforce it (trusted-by-admission, no in-process
    /// interruption point). `None` (the default) = unset = unlimited, mirroring the `cpu_ms == 0`
    /// convention.
    ///
    /// **`skip_serializing_if`** keeps the wire compact and the signing-payload determinism tripwire
    /// valid: a manifest that omits this key serializes it away, so no existing creature must re-sign.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wall_ms: Option<u64>,
}

/// What a host must offer for this creature to run. The Distributor matches these against a
/// node's advertised embodiment. Defined now, *matched* later.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Requirements {
    #[serde(default)]
    pub accelerators: Vec<String>,
    #[serde(default)]
    pub sensors: Vec<String>,
    #[serde(default)]
    pub min_mem_bytes: u64,
    #[serde(default)]
    pub connectivity: Option<String>,
    #[serde(default)]
    pub jurisdiction: Option<String>,
}

/// Authorship + integrity. `author` is the **Abode** key (the distributed *self*), not the
/// node key (which is for transport). Verification here is a *mechanism*; *which*
/// roots to trust is injected policy.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Provenance {
    /// The Abode public key (authorship identity), encoded (hex/base64).
    #[serde(default)]
    pub author: Option<String>,
    #[serde(default)]
    pub source_hash: Option<String>,
    #[serde(default)]
    pub build_hash: Option<String>,
    /// Signature over [`Manifest::signing_payload`]. Checked against `author` by the (injected)
    /// policy's roots, using `ring`/ed25519.
    #[serde(default)]
    pub signature: Option<String>,
    /// Optional Realm the author asserts this creature belongs to. The
    /// Abode key still signs; the Realm rides inside the signing payload, so a peer who knows
    /// "the author belongs to Realm X" can refuse manifests that don't claim Realm X (injected
    /// policy decision — the substrate just carries the field).
    ///
    /// `skip_serializing_if = Option::is_none` keeps the no-Realm wire shape compact and preserves
    /// signing-payload determinism: adding a Realm assertion is an explicit new signed claim, while
    /// omitting it leaves no `realm` key in the signed payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realm: Option<RealmId>,
}

/// A creature at rest / in transit. The sole metadata + permission source (no parallel system).
///
/// **Field order is part of the signed wire format.** `Manifest::signing_payload` is
/// `serde_json::to_vec(self_with_signature_cleared)`, and serde_json emits struct fields in
/// declaration order. Appending new optional fields is additive. **Reordering or renaming an
/// existing field invalidates signed manifests in flight.** If you need to do it, treat it as a
/// wire-format change — coordinated across nodes, lockstep with the
/// `signing_payload_hash_is_locked_to_a_known_fixture` tripwire test (which exists to catch silent
/// drift exactly like this).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub name: String,
    /// Semver string (validated as non-empty; full semver checks later).
    pub version: String,
    pub abi: Abi,
    #[serde(default)]
    pub entrypoints: Vec<Entrypoint>,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub requirements: Requirements,
    #[serde(default)]
    pub provenance: Provenance,
    /// Portable identity for *this manifest*: `sha256` over the manifest with the volatile fields
    /// (`provenance.signature` and `content_address` itself) cleared. Computed via
    /// [`Manifest::compute_content_address`]. Two creatures with identical artifact bytes but
    /// different capabilities / provides / entrypoints / requirements get **distinct**
    /// content addresses — the address is "what manifest is this," not "what bytes ran." See
    /// [`Manifest::identity_payload`] for the exact bytes that are hashed.
    #[serde(default)]
    pub content_address: Option<String>,
    /// Which hooks/roles this creature can fill (inversion of control): e.g.
    /// `["distributor", "policy"]`. Lets an operator bind it into a socket.
    #[serde(default)]
    pub provides: Vec<String>,
}

impl Manifest {
    /// A minimal creature manifest with sane defaults — convenience for creatures and tests.
    pub fn new(
        name: impl Into<String>,
        version: impl Into<String>,
        backend: Backend,
        abi_tag: impl Into<String>,
    ) -> Self {
        Manifest {
            name: name.into(),
            version: version.into(),
            abi: Abi { backend, abi_tag: abi_tag.into(), target: Vec::new() },
            entrypoints: Vec::new(),
            capabilities: Capabilities::default(),
            requirements: Requirements::default(),
            provenance: Provenance::default(),
            content_address: None,
            provides: Vec::new(),
        }
    }

    /// Parse a manifest from JSON bytes. **Never panics** on hostile input — malformed bytes
    /// or an unknown `abi.backend` become a structured error (R9 fabric-integrity floor).
    pub fn parse(bytes: &[u8]) -> Result<Manifest, ManifestError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::Invalid(format!(
                "manifest JSON is {} bytes, exceeds {} byte limit",
                bytes.len(),
                MAX_MANIFEST_BYTES
            )));
        }
        let m: Manifest =
            serde_json::from_slice(bytes).map_err(|e| ManifestError::Parse(e.to_string()))?;
        m.validate()?;
        Ok(m)
    }

    /// Structural validation run by admission's *mechanism* on every load.
    ///
    /// The entrypoint catalog and the `provides` advertisement are
    /// gated for shape too, so an authored manifest with a malformed entrypoints list (the
    /// obvious failure mode of a templated or LLM agent) is rejected at admission with a
    /// structured reason — never silently loaded with garbage metadata. R6 in spirit:
    /// the manifest is the sole metadata source, so the manifest *must* be coherent.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.name.trim().is_empty() {
            return Err(ManifestError::Invalid("missing `name`".into()));
        }
        if self.version.trim().is_empty() {
            return Err(ManifestError::Invalid("missing `version`".into()));
        }
        validate_text_len("name", &self.name, MAX_MANIFEST_NAME_BYTES)?;
        validate_text_len("version", &self.version, MAX_MANIFEST_VERSION_BYTES)?;
        validate_text_len("abi.abi_tag", &self.abi.abi_tag, MAX_MANIFEST_ABI_TAG_BYTES)?;
        if self.abi.abi_tag.trim().is_empty() {
            return Err(ManifestError::Invalid("abi.abi_tag must not be empty".into()));
        }
        validate_string_list(
            "abi.target",
            &self.abi.target,
            MAX_MANIFEST_TARGETS,
            MAX_MANIFEST_TARGET_BYTES,
        )?;
        // Entrypoint catalog: each entry must have a non-empty name + signature, no duplicates.
        // We do not require any specific name (`handle`) — the kernel's `handle(Envelope)` ABI is
        // the wire; entrypoints are advertised metadata an injected matcher/typer reads.
        validate_list_len("entrypoints", self.entrypoints.len(), MAX_MANIFEST_ENTRYPOINTS)?;
        let mut seen_entry: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for ep in &self.entrypoints {
            if ep.name.trim().is_empty() {
                return Err(ManifestError::Invalid("entrypoint has empty `name`".into()));
            }
            validate_text_len("entrypoint.name", &ep.name, MAX_MANIFEST_ENTRYPOINT_NAME_BYTES)?;
            if ep.signature.trim().is_empty() {
                return Err(ManifestError::Invalid(format!(
                    "entrypoint `{}` has empty `signature`",
                    ep.name
                )));
            }
            validate_text_len(
                "entrypoint.signature",
                &ep.signature,
                MAX_MANIFEST_ENTRYPOINT_SIGNATURE_BYTES,
            )?;
            if let Some(contract) = &ep.contract {
                contract.validate().map_err(|err| {
                    ManifestError::Invalid(format!(
                        "entrypoint `{}` has invalid structured contract: {err}",
                        ep.name
                    ))
                })?;
            }
            if !seen_entry.insert(ep.name.as_str()) {
                return Err(ManifestError::Invalid(format!("duplicate entrypoint `{}`", ep.name)));
            }
        }
        validate_capabilities_shape(&self.capabilities)?;
        validate_requirements_shape(&self.requirements)?;
        // `provides[]` is an IoC role advertisement; duplicates and empty strings make the binder's
        // job ambiguous and signal an authoring bug — fail loudly here, not silently at bind time.
        validate_list_len("provides", self.provides.len(), MAX_MANIFEST_PROVIDES)?;
        let mut seen_role: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for r in &self.provides {
            if r.trim().is_empty() {
                return Err(ManifestError::Invalid("`provides` contains empty role".into()));
            }
            validate_text_len("provides[]", r, MAX_MANIFEST_PROVIDES_BYTES)?;
            if !seen_role.insert(r.as_str()) {
                return Err(ManifestError::Invalid(format!("duplicate provides role `{r}`")));
            }
        }
        validate_provenance_shape(&self.provenance)?;
        if let Some(content_address) = &self.content_address {
            validate_text_len(
                "content_address",
                content_address,
                MAX_MANIFEST_CONTENT_ADDRESS_BYTES,
            )?;
        }
        // A declared Realm must be well-formed: `provenance.realm` flows into the bus capability key
        // as `realm:{name}` / `omega:{name}`, so a name containing `:` or whitespace would produce
        // an ambiguous cap key (`realm:x:y` reads as the inner target). Gate it at admission via the
        // existing `RealmId::is_valid` invariant rather than letting a malformed realm slip through
        // and surface only as a confusing capability downstream. (T10)
        if let Some(realm) = &self.provenance.realm {
            if !realm.is_valid() {
                return Err(ManifestError::Invalid(format!(
                    "provenance.realm `{}` is not a valid realm name (non-empty, no `:`/whitespace)",
                    realm.0
                )));
            }
        }
        Ok(())
    }

    /// Deterministic content address: `sha256:<hex>` over [`Manifest::identity_payload`]. Two
    /// creatures with identical artifact bytes but different manifest bodies (different
    /// capabilities, entrypoints, requirements, provides) hash to **different** content addresses,
    /// because they are different creatures at the manifest grain — that's what the address
    /// names. The receiver's admission can recompute and assert self-consistency against the
    /// `content_address` field the producer wrote.
    ///
    /// The algorithm hashes [`Self::identity_payload`] so it binds the whole signed shape — a hash
    /// over only `name + version + build_hash` would let differently-capable manifests collide,
    /// exactly the federation footgun the field name promises away.
    pub fn compute_content_address(&self) -> String {
        let mut h = Sha256::new();
        h.update(self.identity_payload());
        format!("sha256:{:x}", h.finalize())
    }

    /// Canonical bytes a signature commits to: the manifest with the `signature` field cleared.
    /// (JSON today; a canonical binary form can replace it without changing the seam.)
    ///
    /// **`content_address` rides INSIDE the signature.** This means the producer must set
    /// `content_address` before signing or the receiver will recompute `signing_payload` over a
    /// manifest whose `content_address` is `None` (or differs) and the signature mismatches —
    /// the signing-order discipline build-cargo's source follows.
    pub fn signing_payload(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.provenance.signature = None;
        // Serialization of a plain struct of strings/numbers cannot fail. `.expect` (not
        // `unwrap_or_default`) so a future fallible-Serialize field fails LOUDLY at the producer
        // rather than silently signing/verifying over empty bytes — a fail-loud, never fail-open
        // posture on this security-relevant path.
        serde_json::to_vec(&clone)
            .expect("manifest signing_payload is infallible for plain-data fields")
    }

    /// Bytes the content-address hashes over: the signing payload, additionally with
    /// `content_address` cleared. This makes the address a function of *only* the manifest's
    /// identity shape — not of its own previously-stamped value, which would be circular. The
    /// field is set after the address is computed; admission then re-derives and asserts
    /// self-consistency.
    pub fn identity_payload(&self) -> Vec<u8> {
        let mut clone = self.clone();
        clone.provenance.signature = None;
        clone.content_address = None;
        // See `signing_payload`: `.expect` keeps this fail-loud, never fail-open.
        serde_json::to_vec(&clone)
            .expect("manifest identity_payload is infallible for plain-data fields")
    }

    /// Whether this creature advertises that it can fill `role` (IoC binding).
    pub fn provides_role(&self, role: &str) -> bool {
        self.provides.iter().any(|r| r == role)
    }
}

fn validate_capabilities_shape(cap: &Capabilities) -> Result<(), ManifestError> {
    validate_string_list(
        "capabilities.fs",
        &cap.fs,
        MAX_MANIFEST_CAPABILITY_ITEMS,
        MAX_MANIFEST_FS_PATH_BYTES,
    )?;
    validate_string_list(
        "capabilities.calls",
        &cap.calls,
        MAX_MANIFEST_CAPABILITY_ITEMS,
        MAX_MANIFEST_CALL_BYTES,
    )?;
    Ok(())
}

fn validate_requirements_shape(req: &Requirements) -> Result<(), ManifestError> {
    validate_string_list(
        "requirements.accelerators",
        &req.accelerators,
        MAX_MANIFEST_REQUIREMENT_ITEMS,
        MAX_MANIFEST_REQUIREMENT_FIELD_BYTES,
    )?;
    validate_string_list(
        "requirements.sensors",
        &req.sensors,
        MAX_MANIFEST_REQUIREMENT_ITEMS,
        MAX_MANIFEST_REQUIREMENT_FIELD_BYTES,
    )?;
    validate_optional_text_len(
        "requirements.connectivity",
        req.connectivity.as_deref(),
        MAX_MANIFEST_REQUIREMENT_FIELD_BYTES,
    )?;
    validate_optional_text_len(
        "requirements.jurisdiction",
        req.jurisdiction.as_deref(),
        MAX_MANIFEST_REQUIREMENT_FIELD_BYTES,
    )?;
    Ok(())
}

fn validate_provenance_shape(prov: &Provenance) -> Result<(), ManifestError> {
    validate_optional_text_len(
        "provenance.author",
        prov.author.as_deref(),
        MAX_MANIFEST_PROVENANCE_FIELD_BYTES,
    )?;
    validate_optional_text_len(
        "provenance.source_hash",
        prov.source_hash.as_deref(),
        MAX_MANIFEST_PROVENANCE_FIELD_BYTES,
    )?;
    validate_optional_text_len(
        "provenance.build_hash",
        prov.build_hash.as_deref(),
        MAX_MANIFEST_PROVENANCE_FIELD_BYTES,
    )?;
    validate_optional_text_len(
        "provenance.signature",
        prov.signature.as_deref(),
        MAX_MANIFEST_PROVENANCE_FIELD_BYTES,
    )?;
    if let Some(realm) = &prov.realm {
        validate_text_len("provenance.realm", &realm.0, MAX_MANIFEST_REALM_BYTES)?;
    }
    Ok(())
}

fn validate_string_list(
    label: &str,
    values: &[String],
    max_items: usize,
    max_bytes: usize,
) -> Result<(), ManifestError> {
    validate_list_len(label, values.len(), max_items)?;
    let item_label = format!("{label}[]");
    for value in values {
        validate_text_len(&item_label, value, max_bytes)?;
    }
    Ok(())
}

fn validate_optional_text_len(
    label: &str,
    value: Option<&str>,
    max_bytes: usize,
) -> Result<(), ManifestError> {
    if let Some(value) = value {
        validate_text_len(label, value, max_bytes)?;
    }
    Ok(())
}

fn validate_list_len(label: &str, len: usize, max: usize) -> Result<(), ManifestError> {
    if len > max {
        return Err(ManifestError::Invalid(format!(
            "{label} has {len} entries, exceeds {max} entry limit"
        )));
    }
    Ok(())
}

fn validate_text_len(label: &str, value: &str, max: usize) -> Result<(), ManifestError> {
    if value.len() > max {
        return Err(ManifestError::Invalid(format!(
            "{label} is {} bytes, exceeds {max} byte limit",
            value.len()
        )));
    }
    Ok(())
}

/// The signature-verification **mechanism**. The *model* — which keys are trust roots — is
/// injected policy, not defined here. The real implementation is `ring`/ed25519.
pub trait Verifier: Send + Sync {
    /// Returns whether `signature` is a valid signature over `payload` by `public_key`.
    fn verify(&self, public_key: &str, payload: &[u8], signature: &str) -> bool;
}

/// A stand-in: treats any non-empty signature as valid. It exists so the signing/verifying
/// *boundary* is present (R5); it is **not** a trust root and must never ship as one.
pub struct StubVerifier;

impl Verifier for StubVerifier {
    fn verify(&self, _public_key: &str, _payload: &[u8], signature: &str) -> bool {
        !signature.is_empty()
    }
}

/// Errors from parsing/validating a manifest. Hostile input yields one of these — never a panic.
#[derive(Debug, thiserror::Error)]
pub enum ManifestError {
    #[error("manifest parse error: {0}")]
    Parse(String),
    #[error("invalid manifest: {0}")]
    Invalid(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn realm_id_validation_rejects_empty_whitespace_and_colon() {
        // Well-formed names.
        assert!(RealmId::local().is_valid());
        assert!(RealmId::new("crew-of-the-mary-celeste").is_valid());
        assert!(RealmId::checked("eu-west").is_some());
        // Ill-formed: empty / whitespace-only / colon (would produce an ambiguous `realm:x:y` cap key).
        assert!(!RealmId::new("").is_valid());
        assert!(!RealmId::new("   ").is_valid());
        assert!(!RealmId::new("x:y").is_valid());
        assert!(RealmId::checked("").is_none());
        assert!(RealmId::checked("a:b").is_none());
        // `new` still constructs the invalid value (unvalidated path) — only `checked` gates.
        assert_eq!(RealmId::new("x:y").0, "x:y");
    }

    fn daemon_json() -> &'static str {
        r#"{
            "name": "echo-daemon",
            "version": "0.1.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1", "target": ["x86_64-unknown-linux-gnu"] },
            "entrypoints": [{ "name": "handle", "signature": "(Envelope) -> Outcome" }],
            "provides": ["distributor"]
        }"#
    }

    #[test]
    fn parses_a_daemon_manifest() {
        let m = Manifest::parse(daemon_json().as_bytes()).expect("valid manifest parses");
        assert_eq!(m.name, "echo-daemon");
        assert_eq!(m.abi.backend, Backend::Daemon);
        assert_eq!(m.abi.abi_tag, "gawd_creature_v1");
        assert!(m.provides_role("distributor"));
        assert!(!m.provides_role("policy"));
        // Defaulted fields are present without being specified.
        assert_eq!(m.capabilities.net, NetCapability::None);
    }

    #[test]
    fn parses_a_beast_manifest() {
        let json = r#"{ "name": "echo-beast", "version": "0.1.0",
            "abi": { "backend": "beast", "abi_tag": "gawd_creature_v1", "target": ["wasm32-unknown-unknown"] } }"#;
        let m = Manifest::parse(json.as_bytes()).unwrap();
        assert_eq!(m.abi.backend, Backend::Beast);
    }

    #[test]
    fn rejects_missing_name_without_panic() {
        let json = r#"{ "name": "", "version": "0.1.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" } }"#;
        match Manifest::parse(json.as_bytes()) {
            Err(ManifestError::Invalid(_)) => {}
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn rejects_unknown_backend_without_panic() {
        // Hostile/unknown tier must error, never panic (R9).
        let json = r#"{ "name": "x", "version": "0.1.0",
            "abi": { "backend": "wormhole", "abi_tag": "v1" } }"#;
        assert!(matches!(Manifest::parse(json.as_bytes()), Err(ManifestError::Parse(_))));
    }

    #[test]
    fn rejects_malformed_json_without_panic() {
        assert!(matches!(Manifest::parse(b"{ not json"), Err(ManifestError::Parse(_))));
        assert!(matches!(Manifest::parse(&[0xff, 0xfe, 0x00]), Err(ManifestError::Parse(_))));
    }

    #[test]
    fn rejects_oversized_manifest_before_json_parse() {
        let bytes = vec![b' '; MAX_MANIFEST_BYTES + 1];
        let err = Manifest::parse(&bytes).unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(m) if m.contains("manifest JSON") && m.contains("exceeds")),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_oversized_manifest_metadata_fields_and_lists() {
        let mut m = Manifest::new(
            "n".repeat(MAX_MANIFEST_NAME_BYTES + 1),
            "0.1.0",
            Backend::Daemon,
            "gawd_creature_v1",
        );
        let err = m.validate().unwrap_err();
        assert!(matches!(&err, ManifestError::Invalid(msg) if msg.contains("name")), "{err:?}");

        m = Manifest::new("n", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.abi.target = vec!["x86_64-unknown-linux-gnu".into(); MAX_MANIFEST_TARGETS + 1];
        let err = m.validate().unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(msg) if msg.contains("abi.target")),
            "{err:?}"
        );

        m = Manifest::new("n", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.entrypoints =
            vec![Entrypoint::new("handle", "(Envelope) -> Outcome"); MAX_MANIFEST_ENTRYPOINTS + 1];
        let err = m.validate().unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(msg) if msg.contains("entrypoints")),
            "{err:?}"
        );

        m = Manifest::new("n", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.capabilities.calls = vec!["creature:*".into(); MAX_MANIFEST_CAPABILITY_ITEMS + 1];
        let err = m.validate().unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(msg) if msg.contains("capabilities.calls")),
            "{err:?}"
        );

        m = Manifest::new("n", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.requirements.connectivity = Some("c".repeat(MAX_MANIFEST_REQUIREMENT_FIELD_BYTES + 1));
        let err = m.validate().unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(msg) if msg.contains("requirements.connectivity")),
            "{err:?}"
        );

        m = Manifest::new("n", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.provenance.author = Some("a".repeat(MAX_MANIFEST_PROVENANCE_FIELD_BYTES + 1));
        let err = m.validate().unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(msg) if msg.contains("provenance.author")),
            "{err:?}"
        );

        m = Manifest::new("n", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.content_address =
            Some("sha256:".to_string() + &"a".repeat(MAX_MANIFEST_CONTENT_ADDRESS_BYTES));
        let err = m.validate().unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(msg) if msg.contains("content_address")),
            "{err:?}"
        );
    }

    // Entrypoint validation. The kernel's admission *mechanism* consults
    // `Manifest::validate`; this backs the "manifest/entrypoints violation
    // rejected at load with a structured reason" guarantee. Each case asserts a
    // distinct human-readable reason so an authoring agent can read the failure and revise.
    #[test]
    fn rejects_entrypoint_with_empty_name() {
        let json = r#"{ "name": "x", "version": "0.1.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "entrypoints": [{ "name": "", "signature": "(Envelope) -> Outcome" }] }"#;
        let err = Manifest::parse(json.as_bytes()).unwrap_err();
        assert!(matches!(&err, ManifestError::Invalid(m) if m.contains("empty `name`")), "{err:?}");
    }

    #[test]
    fn rejects_entrypoint_with_empty_signature() {
        let json = r#"{ "name": "x", "version": "0.1.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "entrypoints": [{ "name": "handle", "signature": "" }] }"#;
        let err = Manifest::parse(json.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(m) if m.contains("`handle`") && m.contains("signature")),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_duplicate_entrypoint_names() {
        let json = r#"{ "name": "x", "version": "0.1.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "entrypoints": [
                { "name": "handle", "signature": "(Envelope) -> Outcome" },
                { "name": "handle", "signature": "(Envelope) -> Outcome" }
            ] }"#;
        let err = Manifest::parse(json.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(m) if m.contains("duplicate entrypoint")),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_empty_provides_role() {
        let json = r#"{ "name": "x", "version": "0.1.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "provides": ["distributor", "  "] }"#;
        let err = Manifest::parse(json.as_bytes()).unwrap_err();
        assert!(matches!(&err, ManifestError::Invalid(m) if m.contains("empty role")), "{err:?}");
    }

    #[test]
    fn rejects_duplicate_provides_role() {
        let json = r#"{ "name": "x", "version": "0.1.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "provides": ["distributor", "distributor"] }"#;
        let err = Manifest::parse(json.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(m) if m.contains("duplicate provides")),
            "{err:?}"
        );
    }

    #[test]
    fn valid_entrypoints_and_provides_pass_validation() {
        // Regression: the existing fixture must still validate after the gate tightens.
        let m = Manifest::parse(daemon_json().as_bytes()).expect("existing fixture still valid");
        assert_eq!(m.entrypoints.len(), 1);
        assert_eq!(m.provides.len(), 1);
    }

    #[test]
    fn legacy_entrypoint_wire_is_byte_identical_when_contract_is_absent() {
        let entrypoint = Entrypoint::new("handle", "(Envelope) -> Outcome");
        assert_eq!(
            serde_json::to_string(&entrypoint).unwrap(),
            r#"{"name":"handle","signature":"(Envelope) -> Outcome"}"#
        );
        let parsed: Entrypoint =
            serde_json::from_str(r#"{"name":"handle","signature":"(Envelope) -> Outcome"}"#)
                .unwrap();
        assert_eq!(parsed, entrypoint);
    }

    #[test]
    fn structured_entrypoint_contract_is_signed_validated_metadata() {
        let mut manifest = Manifest::new("typed", "1.0.0", Backend::Beast, "gawd_creature_v1");
        manifest.entrypoints.push(Entrypoint {
            name: "reverse".into(),
            signature: "({text: string}) -> string".into(),
            contract: Some(EntrypointContractV1 {
                description: "Reverse text".into(),
                input_schema: gawdfn::SchemaRefV1::Inline {
                    schema: serde_json::json!({ "type": "object" }),
                },
                output_schema: gawdfn::SchemaRefV1::Inline {
                    schema: serde_json::json!({ "type": "string" }),
                },
                error_schema: None,
                effect: gawdfn::EffectClassV1::ReadOnly,
                controls: gawdfn::FunctionControlsV1 { progress: true, ..Default::default() },
            }),
        });
        manifest.validate().unwrap();
        let typed_address = manifest.compute_content_address();

        manifest.entrypoints[0].contract = None;
        assert_ne!(typed_address, manifest.compute_content_address());
    }

    #[test]
    fn structured_entrypoint_rejects_non_object_input_schema() {
        let json = r#"{
            "name": "typed", "version": "1.0.0",
            "abi": { "backend": "beast", "abi_tag": "gawd_creature_v1" },
            "entrypoints": [{
                "name": "bad", "signature": "(string) -> string",
                "contract": {
                    "description": "bad input root",
                    "input_schema": { "kind": "inline", "schema": { "type": "string" } },
                    "output_schema": { "kind": "inline", "schema": { "type": "string" } },
                    "effect": "unknown",
                    "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
                }
            }]
        }"#;
        let err = Manifest::parse(json.as_bytes()).unwrap_err();
        assert!(
            matches!(&err, ManifestError::Invalid(message) if message.contains("object root")),
            "{err:?}"
        );
    }

    #[test]
    fn content_address_is_deterministic_and_build_sensitive() {
        let mut m = Manifest::new("c", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        let a = m.compute_content_address();
        assert_eq!(a, m.compute_content_address());
        assert!(a.starts_with("sha256:"));
        m.provenance.build_hash = Some("deadbeef".into());
        assert_ne!(a, m.compute_content_address(), "build_hash must change the address");
    }

    /// `compute_content_address` binds the **whole manifest body**, not just
    /// `name + version + build_hash`. Two creatures whose artifact bytes are identical but whose
    /// manifest bodies differ in any other field MUST hash to different addresses — otherwise the
    /// content address isn't a portable identity for "what creature is this," it's a portable
    /// identity for "what bytes ran," and federation can't tell the difference between a benign
    /// and a hostile manifest carrying the same payload.
    #[test]
    fn content_address_binds_capabilities_provides_entrypoints_not_just_bytes() {
        let mut a = Manifest::new("c", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        a.provenance.build_hash = Some("aabbccdd".into());
        let addr_a = a.compute_content_address();

        // Same name+version+build_hash, different `provides` — must collide on the OLD algorithm,
        // must DIFFER on the new one.
        let mut b = a.clone();
        b.provides = vec!["distributor".into()];
        assert_ne!(addr_a, b.compute_content_address(), "provides must affect the address");

        // Different capabilities → different address.
        let mut c = a.clone();
        c.capabilities.net = NetCapability::Any;
        assert_ne!(addr_a, c.compute_content_address(), "capabilities must affect the address");

        // Different entrypoints → different address.
        let mut d = a.clone();
        d.entrypoints = vec![Entrypoint::new("handle", "(Envelope) -> Outcome")];
        assert_ne!(addr_a, d.compute_content_address(), "entrypoints must affect the address");

        // `content_address` itself does NOT affect the result (it would be circular).
        let mut e = a.clone();
        e.content_address = Some("sha256:whatever-the-producer-wrote".into());
        assert_eq!(addr_a, e.compute_content_address(), "content_address is self-stripped");

        // `provenance.signature` doesn't either (volatile by design).
        let mut f = a.clone();
        f.provenance.signature = Some("zzzz".into());
        assert_eq!(addr_a, f.compute_content_address(), "signature is self-stripped");
    }

    /// **Identity payload byte-stability tripwire** — sibling to the signing_payload one. If any
    /// future change reorders fields or adds non-deterministic types into the manifest tree, the
    /// content addresses every previously-published manifest drift and this test fails loudly.
    /// Pair with the signing_payload tripwire to catch silent wire-format breakage.
    #[test]
    fn identity_payload_hash_is_locked_to_a_known_fixture() {
        let fixture = Manifest {
            name: "tripwire".into(),
            version: "1.0.0".into(),
            abi: Abi {
                backend: Backend::Daemon,
                abi_tag: "gawd_creature_v1".into(),
                target: vec!["x86_64-unknown-linux-gnu".into()],
            },
            entrypoints: vec![Entrypoint {
                name: "handle".into(),
                signature: "(Envelope) -> Outcome".into(),
                contract: None,
            }],
            capabilities: Capabilities {
                fs: vec!["/tmp".into()],
                net: NetCapability::Loopback,
                cpu_ms: 100,
                mem_bytes: 1024,
                calls: vec!["creature:*".into()],
                budget_warn_at: None,
                wall_ms: None,
            },
            requirements: Requirements::default(),
            provenance: Provenance {
                author: Some("abode-key".into()),
                source_hash: Some("aabb".into()),
                build_hash: Some("ccdd".into()),
                signature: Some("must-be-stripped".into()),
                realm: None,
            },
            content_address: Some("sha256:also-must-be-stripped".into()),
            provides: vec!["distributor".into()],
        };
        // Stable across runs / machines because every field is a primitive / String / Vec /
        // struct / externally-tagged enum (no HashMap, no float).
        let addr = fixture.compute_content_address();
        // The fixture's `abi_tag` value `gawd_creature_v1` is part of the manifest bytes that this
        // content address commits to.
        const EXPECTED: &str =
            "sha256:aa81eab31132774ed7a356f632bc9be30afdce44b01c2743da29d375210b6a26";
        assert_eq!(
            addr, EXPECTED,
            "identity_payload byte-stability tripwire fired; investigate field/serialization changes"
        );
    }

    #[test]
    fn stub_verifier_requires_nonempty_signature() {
        let v = StubVerifier;
        assert!(v.verify("abode-key", b"payload", "sig"));
        assert!(!v.verify("abode-key", b"payload", ""));
    }

    #[test]
    fn signing_payload_excludes_the_signature() {
        let mut m = Manifest::new("s", "0.1.0", Backend::Beast, "gawd_creature_v1");
        let before = m.signing_payload();
        m.provenance.signature = Some("zzz".into());
        assert_eq!(before, m.signing_payload(), "signature must not be part of its own payload");
    }

    /// **Determinism tripwire.** `signing_payload` is byte-stable across runs and machines today
    /// because every field is a primitive, `String`, `Vec`, struct, or externally-tagged enum (no
    /// `HashMap` / `HashSet` / float). If a future change introduces a non-deterministic field
    /// (the obvious risk: a `HashMap<String, _>` in `Capabilities`), the hash here drifts and this
    /// test fails loudly — catching the drift before it turns into mysterious
    /// signature-verification failures across nodes.
    #[test]
    fn signing_payload_hash_is_locked_to_a_known_fixture() {
        let fixture = Manifest {
            name: "tripwire".into(),
            version: "1.0.0".into(),
            abi: Abi {
                backend: Backend::Daemon,
                abi_tag: "gawd_creature_v1".into(),
                target: vec!["x86_64-unknown-linux-gnu".into()],
            },
            entrypoints: vec![Entrypoint {
                name: "handle".into(),
                signature: "(Envelope) -> Outcome".into(),
                contract: None,
            }],
            capabilities: Capabilities {
                fs: vec!["/tmp".into()],
                net: NetCapability::Loopback,
                cpu_ms: 100,
                mem_bytes: 1024,
                calls: vec!["creature:*".into()],
                budget_warn_at: None,
                wall_ms: None,
            },
            requirements: Requirements {
                accelerators: vec![],
                sensors: vec![],
                min_mem_bytes: 0,
                connectivity: None,
                jurisdiction: None,
            },
            provenance: Provenance {
                author: Some("abode-key".into()),
                source_hash: Some("aabb".into()),
                build_hash: Some("ccdd".into()),
                signature: Some("must-be-stripped".into()),
                // `realm: None` is intentionally elided from the signing payload. If a future
                // change drops the skip-attribute (or reorders Provenance fields), this fixture hash
                // drifts and the signed-wire tripwire fires.
                realm: None,
            },
            content_address: Some("sha256:deadbeef".into()),
            provides: vec!["distributor".into()],
        };
        let mut h = Sha256::new();
        h.update(fixture.signing_payload());
        let hex = format!("{:x}", h.finalize());
        // The `abi_tag` value `gawd_creature_v1` is part of the signed payload this hash commits to.
        const EXPECTED: &str = "9297612162489aee7c03a256f05d94e645046b89210c4aeceea016b1ec924604";
        assert_eq!(
            hex, EXPECTED,
            "signing_payload byte-stability tripwire fired; investigate field changes"
        );
    }

    /// `realm: None` is not a signed claim; `realm: Some(...)` is. This test locks that distinction
    /// without making any public promise about pre-release artifact compatibility.
    #[test]
    fn realm_none_is_elided_but_realm_some_changes_the_signed_payload() {
        let mut m = Manifest::new("realm-none", "0.1.0", Backend::Daemon, "gawd_creature_v1");
        m.provenance.author = Some("abode-pubkey-hex".into());
        m.provenance.source_hash = Some("aabbccdd".into());
        m.provenance.build_hash = Some("eeff0011".into());
        assert!(m.provenance.realm.is_none(), "manifest has no Realm assertion");

        // The serialized payload (the bytes a signature commits to) must not mention `realm` at all.
        let payload = m.signing_payload();
        let payload_str = std::str::from_utf8(&payload).expect("signing payload is JSON-encoded");
        assert!(
            !payload_str.contains("\"realm\""),
            "realm-less signing payload must NOT contain a `realm` key, got:\n{payload_str}"
        );

        // Sign with a known keypair, then verify the no-Realm payload.
        let key = crate::crypto::Ed25519KeyMaterial::from_seed([7u8; 32]).expect("seed");
        let pk = key.public_hex().to_string();
        let sig = key.sign(&payload);
        let v = crate::crypto::Ed25519Verifier;
        assert!(v.verify(&pk, &payload, &sig), "realm-less manifest signature must verify");

        // A manifest WITH a Realm assertion produces DIFFERENT signed bytes.
        let mut m_realm = m.clone();
        m_realm.provenance.realm = Some(RealmId::new("crew"));
        let payload_realm = m_realm.signing_payload();
        assert_ne!(payload, payload_realm, "`realm: Some(...)` must change the signed payload");
        let payload_realm_str = std::str::from_utf8(&payload_realm).unwrap();
        assert!(
            payload_realm_str.contains("\"realm\""),
            "with realm set, signing payload includes the field, got:\n{payload_realm_str}"
        );
        // And the same key signs the realm-bearing payload cleanly.
        let sig_realm = key.sign(&payload_realm);
        assert!(v.verify(&pk, &payload_realm, &sig_realm), "manifest with realm signs+verifies");
        // The two signatures are NOT interchangeable: the realm field is inside the signed
        // commitment, not just decorative metadata).
        assert!(
            !v.verify(&pk, &payload_realm, &sig),
            "realm-less signature must NOT verify against realm-bearing payload"
        );
    }
}
