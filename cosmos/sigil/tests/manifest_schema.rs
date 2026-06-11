//! Drift guard for `manifest.schema.json` — the machine-readable JSON Schema (Draft 2020-12) that
//! AI agents and editors validate a `Manifest` against.
//!
//! The schema is a *published artifact*, so it must (a) accept every manifest the crate emits,
//! (b) reject malformed ones, and (c) never silently drift from the `sigil::Manifest` Rust
//! type. We do not pull a general JSON-Schema engine (GAWD keeps its tree lean — even in dev): the
//! schema uses a small, fixed keyword set, so a focused validator here is enough, and the real
//! protection is the **key-set parity** check against a fully-populated `Manifest` (below).
//!
//! When you add a field to `Manifest` (or a nested struct), this test fails until you add it to
//! `manifest.schema.json` *and* to the fully-populated fixture — the same discipline as the
//! `signing_payload`/`identity_payload` byte-stability tripwires in `lib.rs`.

use std::collections::BTreeSet;

use serde_json::{json, Value};
use sigil::{
    Abi, Backend, Capabilities, Entrypoint, Manifest, NetCapability, Provenance, RealmId,
    Requirements, MAX_MANIFEST_NAME_BYTES, MAX_MANIFEST_PROVIDES,
};

const SCHEMA_SRC: &str = include_str!("../manifest.schema.json");

fn schema() -> Value {
    serde_json::from_str(SCHEMA_SRC).expect("manifest.schema.json is valid JSON")
}

// ---------------------------------------------------------------------------------------------
// A minimal Draft-2020-12 validator — ONLY the keywords manifest.schema.json actually uses:
// `$ref` (to `#/$defs/*`), `type` (string or array of strings), `required`, `properties`,
// `additionalProperties: false`, `enum`, `items`, `minimum`, `maximum`, `maxLength`, `maxItems`.
// Anything else is ignored.
// Returns the list of validation errors (empty = valid).
// ---------------------------------------------------------------------------------------------

fn validate(schema: &Value, root: &Value, instance: &Value, path: &str, errs: &mut Vec<String>) {
    // `$ref` resolves against the root document and replaces the local schema (the only form we use
    // is `{"$ref": "#/$defs/Name"}`, with no sibling keywords).
    if let Some(Value::String(r)) = schema.get("$ref") {
        match resolve_ref(root, r) {
            Some(target) => validate(target, root, instance, path, errs),
            None => errs.push(format!("{path}: unresolvable $ref `{r}`")),
        }
        return;
    }

    if let Some(t) = schema.get("type") {
        if !type_matches(t, instance) {
            errs.push(format!("{path}: type mismatch (want {t}, got {})", kind_of(instance)));
            // Keep checking sub-keywords only when the coarse type lined up.
            return;
        }
    }

    if let Some(Value::Array(allowed)) = schema.get("enum") {
        if !allowed.iter().any(|a| a == instance) {
            errs.push(format!("{path}: value {instance} not in enum"));
        }
    }

    if let Some(n) = instance.as_f64() {
        if let Some(min) = schema.get("minimum").and_then(Value::as_f64) {
            if n < min {
                errs.push(format!("{path}: {n} < minimum {min}"));
            }
        }
        if let Some(max) = schema.get("maximum").and_then(Value::as_f64) {
            if n > max {
                errs.push(format!("{path}: {n} > maximum {max}"));
            }
        }
    }

    if let Some(s) = instance.as_str() {
        if let Some(max) = schema.get("maxLength").and_then(Value::as_u64) {
            let len = s.len() as u64;
            if len > max {
                errs.push(format!("{path}: string length {len} > maxLength {max}"));
            }
        }
    }

    if let Some(obj) = instance.as_object() {
        let props = schema.get("properties").and_then(Value::as_object);

        if let Some(Value::Array(required)) = schema.get("required") {
            for req in required {
                if let Some(name) = req.as_str() {
                    if !obj.contains_key(name) {
                        errs.push(format!("{path}: missing required `{name}`"));
                    }
                }
            }
        }

        let additional_allowed = schema.get("additionalProperties") != Some(&Value::Bool(false));
        for (key, val) in obj {
            match props.and_then(|p| p.get(key)) {
                Some(subschema) => validate(subschema, root, val, &format!("{path}/{key}"), errs),
                None if !additional_allowed => {
                    errs.push(format!("{path}: unexpected property `{key}`"));
                }
                None => {}
            }
        }
    }

    if let Some(arr) = instance.as_array() {
        if let Some(max) = schema.get("maxItems").and_then(Value::as_u64) {
            let len = arr.len() as u64;
            if len > max {
                errs.push(format!("{path}: array length {len} > maxItems {max}"));
            }
        }
        if let Some(items) = schema.get("items") {
            for (i, el) in arr.iter().enumerate() {
                validate(items, root, el, &format!("{path}/{i}"), errs);
            }
        }
    }
}

fn resolve_ref<'a>(root: &'a Value, r: &str) -> Option<&'a Value> {
    // Only local pointers of the form `#/a/b/c`.
    let pointer = r.strip_prefix('#')?;
    if pointer.is_empty() {
        return Some(root);
    }
    root.pointer(pointer)
}

fn type_matches(t: &Value, instance: &Value) -> bool {
    match t {
        Value::String(s) => matches_one(s, instance),
        Value::Array(types) => {
            types.iter().filter_map(Value::as_str).any(|s| matches_one(s, instance))
        }
        _ => true,
    }
}

fn matches_one(t: &str, v: &Value) -> bool {
    match t {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        "number" => v.is_number(),
        "integer" => v.is_i64() || v.is_u64(),
        _ => true,
    }
}

fn kind_of(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn assert_valid(instance: &Value, label: &str) {
    let schema = schema();
    let mut errs = Vec::new();
    validate(&schema, &schema, instance, "", &mut errs);
    assert!(errs.is_empty(), "{label} should validate, got: {errs:?}");
}

fn assert_invalid(instance: &Value, label: &str) {
    let schema = schema();
    let mut errs = Vec::new();
    validate(&schema, &schema, instance, "", &mut errs);
    assert!(!errs.is_empty(), "{label} should have failed validation but passed");
}

// ---------------------------------------------------------------------------------------------
// 1. The schema accepts what the crate emits — minimal valid manifest per tier.
// ---------------------------------------------------------------------------------------------

#[test]
fn minimal_manifest_per_tier_validates() {
    for (backend, abi_tag) in [
        (Backend::Daemon, "gawd_creature_v1"),
        (Backend::Beast, "gawd_creature_v1"),
        (Backend::Critter, "gawd_critter_v1"),
    ] {
        let m = Manifest::new("reverse", "0.1.0", backend, abi_tag);
        let v = serde_json::to_value(&m).unwrap();
        assert_valid(&v, &format!("minimal {backend:?} manifest"));
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Malformed manifests are rejected (the schema earns its keep as a contract).
// ---------------------------------------------------------------------------------------------

#[test]
fn malformed_manifests_are_rejected() {
    assert_invalid(
        &json!({ "version": "1.0.0", "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" } }),
        "missing `name`",
    );
    assert_invalid(
        &json!({ "name": "x", "version": "1.0.0", "abi": { "backend": "wombat", "abi_tag": "v" } }),
        "unknown backend",
    );
    assert_invalid(
        &json!({ "name": "x", "version": "1.0.0", "abi": { "abi_tag": "gawd_creature_v1" } }),
        "abi missing `backend`",
    );
    assert_invalid(
        &json!({
            "name": "x", "version": "1.0.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "smuggled": true
        }),
        "unknown top-level property",
    );
    assert_invalid(
        &json!({
            "name": "x", "version": "1.0.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "capabilities": { "net": "carrier-pigeon" }
        }),
        "unknown net capability",
    );
    assert_invalid(
        &json!({
            "name": "x".repeat(MAX_MANIFEST_NAME_BYTES + 1),
            "version": "1.0.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" }
        }),
        "name over maxLength",
    );
    assert_invalid(
        &json!({
            "name": "x", "version": "1.0.0",
            "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1" },
            "provides": vec!["policy"; MAX_MANIFEST_PROVIDES + 1]
        }),
        "provides over maxItems",
    );
}

// ---------------------------------------------------------------------------------------------
// 3. THE DRIFT GUARD — every key of a fully-populated Manifest is declared in the schema, and the
//    schema declares no key the struct doesn't emit. Both directions, top-level + every nested
//    object. Add a field to the struct (and this fixture) without updating the schema → this fails.
// ---------------------------------------------------------------------------------------------

fn fully_populated() -> Manifest {
    Manifest {
        name: "everything".into(),
        version: "1.0.0".into(),
        abi: Abi {
            backend: Backend::Daemon,
            abi_tag: "gawd_creature_v1".into(),
            target: vec!["x86_64-unknown-linux-gnu".into()],
        },
        entrypoints: vec![Entrypoint {
            name: "handle".into(),
            signature: "(Envelope) -> Outcome".into(),
        }],
        capabilities: Capabilities {
            fs: vec!["/tmp".into()],
            net: NetCapability::Outbound,
            cpu_ms: 50,
            mem_bytes: 1024,
            calls: vec!["creature:*".into()],
            budget_warn_at: Some(80),
            wall_ms: Some(250),
        },
        requirements: Requirements {
            accelerators: vec!["nvidia-a100".into()],
            sensors: vec!["lidar".into()],
            min_mem_bytes: 1024,
            connectivity: Some("wired".into()),
            jurisdiction: Some("us".into()),
        },
        provenance: Provenance {
            author: Some("abode-key".into()),
            source_hash: Some("aa".into()),
            build_hash: Some("bb".into()),
            signature: Some("cc".into()),
            realm: Some(RealmId::new("local")),
        },
        content_address: Some("sha256:deadbeef".into()),
        provides: vec!["distributor".into()],
    }
}

fn keys(v: &Value) -> BTreeSet<String> {
    v.as_object().expect("object").keys().cloned().collect()
}

fn schema_property_keys(schema: &Value, defs_pointer: Option<&str>) -> BTreeSet<String> {
    let node = match defs_pointer {
        Some(p) => schema.pointer(p).unwrap_or_else(|| panic!("schema missing {p}")),
        None => schema,
    };
    keys(node.get("properties").expect("subschema has `properties`"))
}

#[test]
fn fully_populated_manifest_validates_and_keys_match_schema() {
    let m = fully_populated();
    let v = serde_json::to_value(&m).unwrap();

    // It must validate (proves the schema accepts the richest legal manifest).
    assert_valid(&v, "fully-populated manifest");

    let schema = schema();

    // Top-level Manifest + each nested object: serialized keys === declared schema properties.
    // (instance JSON pointer, schema `$defs` pointer or None for the root)
    let pairs: &[(&str, Option<&str>)] = &[
        ("", None),
        ("/abi", Some("/$defs/Abi")),
        ("/entrypoints/0", Some("/$defs/Entrypoint")),
        ("/capabilities", Some("/$defs/Capabilities")),
        ("/requirements", Some("/$defs/Requirements")),
        ("/provenance", Some("/$defs/Provenance")),
    ];

    for (instance_ptr, defs_ptr) in pairs {
        let instance_node =
            v.pointer(instance_ptr).unwrap_or_else(|| panic!("fixture missing {instance_ptr}"));
        let want = keys(instance_node);
        let have = schema_property_keys(&schema, *defs_ptr);
        assert_eq!(
            want,
            have,
            "schema/struct key drift at `{}` — struct emits {want:?}, schema declares {have:?}. \
             Update manifest.schema.json (and the fixture) to match the Rust type.",
            if instance_ptr.is_empty() { "Manifest" } else { instance_ptr }
        );
    }
}
