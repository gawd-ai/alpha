//! Prompt assembly + response parsing for the model-backed author.
//!
//! Legacy authoring uses **two fenced blocks** — source plus a JSON manifest stub. Approved-profile
//! authoring instead accepts one strict, non-executable implementation record and lets audited
//! renderers produce Rust, WAT, or Rhai. Both paths fail closed: malformed or semantically drifting
//! output becomes [`AuthoringError::Invalid`], never a synthesized permissive default. Raw model
//! completions are capped before parsing so an injected model cannot force unbounded allocation.

use std::sync::Arc;

use agent_templated::{
    bounded_authoring_text, AuthoringError, AuthoringRequest, AuthoringResponse,
    MAX_AUTHORING_PREV_ERROR_BYTES, MAX_AUTHORING_REQUEST_TEXT_BYTES,
};
use build_cargo::ManifestStub;
use gawdfn::{
    EffectClassV1, EntrypointContractV1, FunctionControlsV1, SchemaRefV1, SCHEMA_CALL_V1,
};
use mind::{Prompt, RETRY_MARKER};
#[cfg(test)]
use mind::{
    TYPED_FUNCTION_BEAST_MARKER, TYPED_FUNCTION_CRITTER_MARKER, TYPED_FUNCTION_DAEMON_MARKER,
};
use serde_json::json;

use crate::profile::{
    is_reserved_request, ApprovedImplementationV1, ApprovedTier, ApprovedTypedProfile,
    APPROVED_IMPLEMENTATION_V1,
};

/// Maximum model-completion bytes parsed by the model-backed author.
///
/// This matches the build creatures' 8 MiB operation envelope scale: a 4 MiB source plus manifest
/// JSON/fence overhead fits, while an arbitrarily large model response is rejected before the fence
/// scanner copies block bodies.
pub const MAX_MODEL_COMPLETION_BYTES: usize = 8 * 1024 * 1024;
/// Approved replies contain only a small typed record, never executable source.
const MAX_APPROVED_IMPLEMENTATION_BYTES: usize = 16 * 1024;

/// One immutable authoring decision used for both prompt construction and response validation.
#[derive(Clone, Debug)]
pub(crate) enum AuthoringMode {
    Legacy(Tier),
    Approved { tier: ApprovedTier, profile: Arc<ApprovedTypedProfile> },
}

/// Resolve the request before a model worker is spawned.
///
/// `Some(profile)` is an approved-only posture. With no profile, legacy behavior is unchanged except
/// that the new reserved namespace fails closed instead of becoming a general native request.
pub(crate) fn resolve_mode(
    req: &AuthoringRequest,
    approved_profile: Option<&Arc<ApprovedTypedProfile>>,
) -> Result<AuthoringMode, AuthoringError> {
    if let Some(profile) = approved_profile {
        let Some(tier) = profile.tier_for_request(&req.request) else {
            return Err(AuthoringError::Invalid {
                message: "approved-only agent requires one exact digest-bound daemon, beast, or critter request"
                    .to_string(),
            });
        };
        return Ok(AuthoringMode::Approved { tier, profile: profile.clone() });
    }
    if is_reserved_request(&req.request) {
        return Err(AuthoringError::Invalid {
            message: "approved-profile request has no matching injected profile (fail-closed)"
                .to_string(),
        });
    }
    Ok(AuthoringMode::Legacy(tier_of(req)))
}

/// The one exact natural-language request that selects the legacy fixed typed-capability profile.
///
/// General critter authoring remains general: merely mentioning "function" (or a word such as
/// "functional") must not silently replace the requested behavior with `double_signed`. The
/// collaboration demo signs and forwards these exact bounded bytes, so equality here is also the
/// explicit bridge from its approved request into the narrow audited authoring profile.
pub const DOUBLE_SIGNED_CRITTER_REQUEST_V1: &str = "Author a typed Function as a critter named double-int-critter. Its double_signed entrypoint must use gawd.function.call.v1, accept exactly one signed integer value in -1000000..=1000000, return exactly one doubled integer in -2000000..=2000000, be idempotent, expose no controls, verify the executor route before parsing, and copy the exact AttemptId into FunctionResultV1.";

/// The exact request selecting the audited native counterpart of the legacy fixed typed capability.
///
/// Native creatures are trusted by admission and execute in-process, so this does not enable
/// general model-authored native code. It selects one byte-exact reviewed implementation whose
/// source and default-capability/no-provides manifest posture are checked before BuildCargo may
/// compile or sign it.
pub const DOUBLE_SIGNED_DAEMON_REQUEST_V1: &str = "Author a typed Function as a trusted-by-admission daemon named double-int-daemon. Its double_signed entrypoint must use gawd.function.call.v1, accept exactly one signed integer value in -1000000..=1000000, return exactly one doubled integer in -2000000..=2000000, be idempotent, expose no controls, verify the executor route before parsing, bind its own signed manifest identity, and copy the exact AttemptId into FunctionResultV1.";

/// The exact request selecting the audited no-import WASM counterpart of the legacy fixed capability.
///
/// The Beast never receives grant, route, Function identity, or Attempt identity bytes. The
/// WasmEngine authenticates those host-side and passes only canonical inline application JSON
/// through the existing `memory + alloc + handle` ABI, then wraps the returned JSON itself.
pub const DOUBLE_SIGNED_BEAST_REQUEST_V1: &str = "Author a typed Function as a sandboxed beast named double-int-beast. Its double_signed entrypoint must use gawd.function.call.v1, accept exactly one signed integer value in -1000000..=1000000, return exactly one doubled integer in -2000000..=2000000, be idempotent, expose no controls, use the no-import host adapter to verify its signed route and FunctionId before execution, and return only application JSON for host wrapping with the exact AttemptId.";

/// Which authoring shape the request asks for. Mirrors `agent-templated`'s tier routing, with a
/// narrow typed-Function specialization for both the sandboxed critter tier and the audited
/// trusted-by-admission native tier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Daemon,
    Critter,
    TypedFunctionCritter,
    TypedFunctionDaemon,
    TypedFunctionBeast,
}

/// Decide the tier from the request text (the control plane appends "critter" for `author --critter`).
pub fn tier_of(req: &AuthoringRequest) -> Tier {
    if req.request == DOUBLE_SIGNED_CRITTER_REQUEST_V1 {
        Tier::TypedFunctionCritter
    } else if req.request == DOUBLE_SIGNED_DAEMON_REQUEST_V1 {
        Tier::TypedFunctionDaemon
    } else if req.request == DOUBLE_SIGNED_BEAST_REQUEST_V1 {
        Tier::TypedFunctionBeast
    } else if req.request.to_ascii_lowercase().contains("critter") {
        Tier::Critter
    } else {
        Tier::Daemon
    }
}

/// System prompt for the native daemon tier: a single-file `forge` creature ending in
/// `declare_creature!`, std + forge only (the two-block contract has no slot for extra deps).
const DAEMON_SYSTEM_PROMPT: &str = r#"You are an authoring creature for the Alpha substrate (the GAWD fabric).
You receive a natural-language outcome and must produce ONE self-contained Rust source file for a
`forge` creature, plus a manifest stub.

Hard requirements for the Rust source:
- Start with `use forge::prelude::*;`.
- Define one public type that derives `Default` and `impl Creature for` it.
- Implement `fn bind(&mut self, _ctx: CreatureCtx) {}` and `fn handle(&mut self, env: Envelope) -> Outcome`.
- The creature's only output is the envelopes it returns from `handle` (reply with `Outcome::reply(&env, bytes)`).
- End the file with `forge::declare_creature!(YourType);`.
- Use only the standard library and `forge` (no external crates).

Respond with EXACTLY two fenced code blocks and nothing that must be parsed outside them:
1. A ```rust block containing the full source file.
2. A ```json block containing the manifest stub: an object with "name", "version", "entrypoints"
   (each {"name","signature"}), optional "capabilities", and "provides" (array). Declare any
   outbound network or filesystem capability the creature actually needs — under-declaring is a
   capability mis-declaration the admission policy may reject.

Worked example for "reverse a string":

```rust
use forge::prelude::*;

#[derive(Default)]
pub struct ReverseDaemon;

impl Creature for ReverseDaemon {
    fn bind(&mut self, _ctx: CreatureCtx) {}
    fn handle(&mut self, env: Envelope) -> Outcome {
        let reversed: Vec<u8> = env.payload.iter().copied().rev().collect();
        Outcome::reply(&env, reversed)
    }
}

forge::declare_creature!(ReverseDaemon);
```

```json
{ "name": "reverse-daemon", "version": "0.1.0", "entrypoints": [{ "name": "handle", "signature": "(Envelope) -> Outcome" }], "provides": [] }
```
"#;

// This is deliberately not the general daemon prompt. Native code shares Alpha's process and is
// trusted by admission, so this legacy fixed-profile regression lets the model seam select exactly
// one audited source/manifest pair; every variation is rejected before the compiler or signing key
// sees it. Current v0.5 approved mode accepts no source and uses trusted lowering instead. The
// TYPED-FUNCTION-DAEMON marker keeps the hermetic FakeModel on this exact legacy profile.
const TYPED_FUNCTION_DAEMON_SYSTEM_PROMPT: &str = r#"You are an authoring creature for the Alpha substrate (the GAWD fabric).
Author a TYPED-FUNCTION-DAEMON: the one audited trusted-by-admission native implementation below.
Do not generalize it, add dependencies or authority, change the source, or change the Function wire
contract, identity check, schemas, bounds, effect, controls, or entrypoint.

The exact manifest entrypoint is:
- name: `double_signed`
- signature: `gawd.function.call.v1`
- description: `Double a bounded signed integer.`
- input: an object with exactly one required `value` integer in -1000000..=1000000
- output: an object with exactly one required `doubled` integer in -2000000..=2000000
- no error schema; effect `idempotent`; progress/steer/cancel/checkpoint controls all false

Hard identity, causal, and runtime requirements for the Rust source:
- Bind and retain this creature's signed manifest `content_address`.
- Call `forge::function::parse_call(&env)` before decoding input. That helper verifies the signed
  Home grant, executor dispatch, exact executor-to-target route, message bound, and call structure.
- Require the call's manifest content address to equal the bound creature's own address and require
  entrypoint `double_signed` before decoding input.
- Decode only an inline `BTreeMap<String, i64>`, require exactly the `value` field, enforce the input
  bounds again at runtime, and use checked multiplication.
- Call `forge::function::success` with the EXACT `call.attempt` received from the authenticated call.
- Use only `std` and `forge`; no filesystem, network, clock, random, key, thread, or extra bus access.

Respond with EXACTLY these two fenced code blocks:

```rust
use forge::prelude::*;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct DoubleSignedDaemon {
    manifest_content_address: Option<String>,
}

impl Creature for DoubleSignedDaemon {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.manifest_content_address = ctx.manifest.content_address;
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        let Some(manifest_content_address) = self.manifest_content_address.as_deref() else {
            return Outcome::none();
        };
        let Ok(call) = forge::function::parse_call(&env) else {
            return Outcome::none();
        };
        if call.function.manifest_content_address != manifest_content_address
            || call.function.entrypoint != "double_signed"
        {
            return Outcome::none();
        }
        let Ok(mut input) =
            forge::function::from_inline::<BTreeMap<String, i64>>(&call.input)
        else {
            return Outcome::none();
        };
        if input.len() != 1 {
            return Outcome::none();
        }
        let Some(value) = input.remove("value") else {
            return Outcome::none();
        };
        if !(-1_000_000..=1_000_000).contains(&value) {
            return Outcome::none();
        }
        let Some(doubled) = value.checked_mul(2) else {
            return Outcome::none();
        };
        let output = BTreeMap::from([("doubled", doubled)]);
        forge::function::success(&env, call.attempt, &output)
            .map(Outcome::send)
            .unwrap_or_else(|_| Outcome::none())
    }
}

forge::declare_creature!(DoubleSignedDaemon);
```

```json
{
  "name": "double-int-daemon",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

/// The only model-returned native source admitted by the legacy fixed typed Function profile.
const TYPED_FUNCTION_DAEMON_SOURCE: &str = r#"use forge::prelude::*;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct DoubleSignedDaemon {
    manifest_content_address: Option<String>,
}

impl Creature for DoubleSignedDaemon {
    fn bind(&mut self, ctx: CreatureCtx) {
        self.manifest_content_address = ctx.manifest.content_address;
    }

    fn handle(&mut self, env: Envelope) -> Outcome {
        let Some(manifest_content_address) = self.manifest_content_address.as_deref() else {
            return Outcome::none();
        };
        let Ok(call) = forge::function::parse_call(&env) else {
            return Outcome::none();
        };
        if call.function.manifest_content_address != manifest_content_address
            || call.function.entrypoint != "double_signed"
        {
            return Outcome::none();
        }
        let Ok(mut input) =
            forge::function::from_inline::<BTreeMap<String, i64>>(&call.input)
        else {
            return Outcome::none();
        };
        if input.len() != 1 {
            return Outcome::none();
        }
        let Some(value) = input.remove("value") else {
            return Outcome::none();
        };
        if !(-1_000_000..=1_000_000).contains(&value) {
            return Outcome::none();
        }
        let Some(doubled) = value.checked_mul(2) else {
            return Outcome::none();
        };
        let output = BTreeMap::from([("doubled", doubled)]);
        forge::function::success(&env, call.attempt, &output)
            .map(Outcome::send)
            .unwrap_or_else(|_| Outcome::none())
    }
}

forge::declare_creature!(DoubleSignedDaemon);"#;

// The typed Beast uses the existing payload-only guest ABI without imports. WasmEngine owns every
// proof-bearing concern: it verifies the call, route, and manifest-derived FunctionId, provides only
// canonical inline JSON to `handle`, and wraps returned JSON with the exact verified AttemptId.
const TYPED_FUNCTION_BEAST_SYSTEM_PROMPT: &str = r#"You are an authoring creature for the Alpha substrate (the GAWD fabric).
Author a TYPED-FUNCTION-BEAST: the one audited no-import WebAssembly implementation below. Do not
generalize it, add imports, change the source, or change the Function contract, schemas, bounds,
effect, controls, or entrypoint.

The exact manifest entrypoint is:
- name: `double_signed`
- signature: `gawd.function.call.v1`
- description: `Double a bounded signed integer.`
- input: an object with exactly one required `value` integer in -1000000..=1000000
- output: an object with exactly one required `doubled` integer in -2000000..=2000000
- no error schema; effect `idempotent`; progress/steer/cancel/checkpoint controls all false

Hard host/guest boundary requirements:
- This is a no-import core-WASM module. Export only one standard wasm32 `memory`,
  `alloc(i32) -> i32`, and `handle(i32, i32) -> i64` (packed output pointer/length).
- Do not parse a Function envelope or claim to authenticate a proof inside WASM. Before `handle`,
  WasmEngine's host adapter verifies the signed Home grant, executor dispatch, exact
  executor-to-target route, and exact manifest-derived FunctionId.
- `handle` receives only canonical inline application JSON bytes. Accept exactly
  `{"value":N}` with N an integer in -1000000..=1000000; reject every other byte shape.
- Return only application JSON `{"doubled":2N}`. WasmEngine parses it as JSON and wraps it in
  `FunctionResultV1` with the EXACT verified AttemptId.
- No imports, WASI, start function, filesystem, network, clock, random, key, thread, or bus access.

Respond with EXACTLY these two fenced code blocks and nothing else:

```wat
(module
  (memory (export "memory") 1)

  (func (export "alloc") (param $len i32) (result i32)
    (i32.const 1024))

  (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
    (local $cursor i32)
    (local $end i32)
    (local $digit i32)
    (local $value i32)
    (local $sign i32)
    (local $doubled i32)
    (local $magnitude i32)
    (local $digits i32)
    (local $out i32)

    (if (i32.lt_u (local.get $len) (i32.const 11))
      (then (return (i64.const 0))))
    (if (i32.gt_u (local.get $len) (i32.const 18))
      (then (return (i64.const 0))))
    (if (i64.ne
          (i64.load (local.get $ptr))
          (i64.const 0x2265756c6176227b))
      (then (return (i64.const 0))))
    (if (i32.ne
          (i32.load8_u offset=8 (local.get $ptr))
          (i32.const 58))
      (then (return (i64.const 0))))

    (local.set $end
      (i32.add (local.get $ptr) (i32.sub (local.get $len) (i32.const 1))))
    (if (i32.ne (i32.load8_u (local.get $end)) (i32.const 125))
      (then (return (i64.const 0))))
    (local.set $cursor (i32.add (local.get $ptr) (i32.const 9)))
    (local.set $sign (i32.const 1))
    (if (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 45))
      (then
        (local.set $sign (i32.const -1))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))))
    (if (i32.ge_u (local.get $cursor) (local.get $end))
      (then (return (i64.const 0))))
    (if (i32.and
          (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 48))
          (i32.lt_u (i32.add (local.get $cursor) (i32.const 1)) (local.get $end)))
      (then (return (i64.const 0))))

    (block $digits_done
      (loop $parse_digit
        (br_if $digits_done (i32.ge_u (local.get $cursor) (local.get $end)))
        (local.set $digit (i32.load8_u (local.get $cursor)))
        (if (i32.or
              (i32.lt_u (local.get $digit) (i32.const 48))
              (i32.gt_u (local.get $digit) (i32.const 57)))
          (then (return (i64.const 0))))
        (local.set $value
          (i32.add
            (i32.mul (local.get $value) (i32.const 10))
            (i32.sub (local.get $digit) (i32.const 48))))
        (if (i32.gt_u (local.get $value) (i32.const 1000000))
          (then (return (i64.const 0))))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))
        (br $parse_digit)))

    (if (i32.eq (local.get $sign) (i32.const -1))
      (then (local.set $value (i32.sub (i32.const 0) (local.get $value)))))
    (local.set $doubled (i32.mul (local.get $value) (i32.const 2)))

    (i64.store
      (i32.const 4096)
      (i64.const 0x656c62756f64227b))
    (i32.store offset=8
      (i32.const 4096)
      (i32.const 0x003a2264))
    (local.set $out (i32.const 4107))
    (if (i32.lt_s (local.get $doubled) (i32.const 0))
      (then
        (i32.store8 (local.get $out) (i32.const 45))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (local.set $magnitude (i32.sub (i32.const 0) (local.get $doubled))))
      (else (local.set $magnitude (local.get $doubled))))

    (loop $write_reverse
      (i32.store8
        (i32.add (i32.const 4200) (local.get $digits))
        (i32.add
          (i32.const 48)
          (i32.rem_u (local.get $magnitude) (i32.const 10))))
      (local.set $digits (i32.add (local.get $digits) (i32.const 1)))
      (local.set $magnitude (i32.div_u (local.get $magnitude) (i32.const 10)))
      (br_if $write_reverse (i32.ne (local.get $magnitude) (i32.const 0))))

    (block $copy_done
      (loop $copy_digit
        (br_if $copy_done (i32.eqz (local.get $digits)))
        (local.set $digits (i32.sub (local.get $digits) (i32.const 1)))
        (i32.store8
          (local.get $out)
          (i32.load8_u (i32.add (i32.const 4200) (local.get $digits))))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (br $copy_digit)))
    (i32.store8 (local.get $out) (i32.const 125))
    (local.set $out (i32.add (local.get $out) (i32.const 1)))

    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 4096)) (i64.const 32))
      (i64.extend_i32_u (i32.sub (local.get $out) (i32.const 4096))))))
```

```json
{
  "name": "double-int-beast",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

/// The only model-returned WAT admitted by the legacy fixed Beast profile. Exact bytes keep the
/// no-import boundary and parser behavior reviewable; BuildBeast independently validates the core
/// module and ABI before it signs the compiled artifact. Exported through `agent_mind` so composed
/// builder/engine acceptance tests execute these exact reviewed bytes instead of copying a fixture.
pub const TYPED_FUNCTION_BEAST_SOURCE: &str = r#"(module
  (memory (export "memory") 1)

  (func (export "alloc") (param $len i32) (result i32)
    (i32.const 1024))

  (func (export "handle") (param $ptr i32) (param $len i32) (result i64)
    (local $cursor i32)
    (local $end i32)
    (local $digit i32)
    (local $value i32)
    (local $sign i32)
    (local $doubled i32)
    (local $magnitude i32)
    (local $digits i32)
    (local $out i32)

    (if (i32.lt_u (local.get $len) (i32.const 11))
      (then (return (i64.const 0))))
    (if (i32.gt_u (local.get $len) (i32.const 18))
      (then (return (i64.const 0))))
    (if (i64.ne
          (i64.load (local.get $ptr))
          (i64.const 0x2265756c6176227b))
      (then (return (i64.const 0))))
    (if (i32.ne
          (i32.load8_u offset=8 (local.get $ptr))
          (i32.const 58))
      (then (return (i64.const 0))))

    (local.set $end
      (i32.add (local.get $ptr) (i32.sub (local.get $len) (i32.const 1))))
    (if (i32.ne (i32.load8_u (local.get $end)) (i32.const 125))
      (then (return (i64.const 0))))
    (local.set $cursor (i32.add (local.get $ptr) (i32.const 9)))
    (local.set $sign (i32.const 1))
    (if (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 45))
      (then
        (local.set $sign (i32.const -1))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))))
    (if (i32.ge_u (local.get $cursor) (local.get $end))
      (then (return (i64.const 0))))
    (if (i32.and
          (i32.eq (i32.load8_u (local.get $cursor)) (i32.const 48))
          (i32.lt_u (i32.add (local.get $cursor) (i32.const 1)) (local.get $end)))
      (then (return (i64.const 0))))

    (block $digits_done
      (loop $parse_digit
        (br_if $digits_done (i32.ge_u (local.get $cursor) (local.get $end)))
        (local.set $digit (i32.load8_u (local.get $cursor)))
        (if (i32.or
              (i32.lt_u (local.get $digit) (i32.const 48))
              (i32.gt_u (local.get $digit) (i32.const 57)))
          (then (return (i64.const 0))))
        (local.set $value
          (i32.add
            (i32.mul (local.get $value) (i32.const 10))
            (i32.sub (local.get $digit) (i32.const 48))))
        (if (i32.gt_u (local.get $value) (i32.const 1000000))
          (then (return (i64.const 0))))
        (local.set $cursor (i32.add (local.get $cursor) (i32.const 1)))
        (br $parse_digit)))

    (if (i32.eq (local.get $sign) (i32.const -1))
      (then (local.set $value (i32.sub (i32.const 0) (local.get $value)))))
    (local.set $doubled (i32.mul (local.get $value) (i32.const 2)))

    (i64.store
      (i32.const 4096)
      (i64.const 0x656c62756f64227b))
    (i32.store offset=8
      (i32.const 4096)
      (i32.const 0x003a2264))
    (local.set $out (i32.const 4107))
    (if (i32.lt_s (local.get $doubled) (i32.const 0))
      (then
        (i32.store8 (local.get $out) (i32.const 45))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (local.set $magnitude (i32.sub (i32.const 0) (local.get $doubled))))
      (else (local.set $magnitude (local.get $doubled))))

    (loop $write_reverse
      (i32.store8
        (i32.add (i32.const 4200) (local.get $digits))
        (i32.add
          (i32.const 48)
          (i32.rem_u (local.get $magnitude) (i32.const 10))))
      (local.set $digits (i32.add (local.get $digits) (i32.const 1)))
      (local.set $magnitude (i32.div_u (local.get $magnitude) (i32.const 10)))
      (br_if $write_reverse (i32.ne (local.get $magnitude) (i32.const 0))))

    (block $copy_done
      (loop $copy_digit
        (br_if $copy_done (i32.eqz (local.get $digits)))
        (local.set $digits (i32.sub (local.get $digits) (i32.const 1)))
        (i32.store8
          (local.get $out)
          (i32.load8_u (i32.add (i32.const 4200) (local.get $digits))))
        (local.set $out (i32.add (local.get $out) (i32.const 1)))
        (br $copy_digit)))
    (i32.store8 (local.get $out) (i32.const 125))
    (local.set $out (i32.add (local.get $out) (i32.const 1)))

    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 4096)) (i64.const 32))
      (i64.extend_i32_u (i32.sub (local.get $out) (i32.const 4096))))))"#;

// The critter system prompt embeds CRITTER-TIER (the marker the fake backend keys on); keep it in
// the text so a swap to a real model is a no-op and the fake answers in the right tier.
const CRITTER_SYSTEM_PROMPT: &str = r#"You are an authoring creature for the Alpha substrate (the GAWD fabric).
Author a CRITTER-TIER creature: a single sandboxed Rhai script (the script tier), NOT Rust.

Hard requirements for the Rhai source:
- Define `fn handle(env) { ... }`. `env.payload` is a blob of the inbound bytes.
- Build the reply with `let out = blob();` then `out.push(byte);`, and return `out` as the last expression.
- No `import`, no `eval`, no host calls — a critter reaches nothing but its own script.
- Do NOT use `declare_creature!` (that is the native-tier macro); a critter is just the script.

Respond with EXACTLY two fenced code blocks and nothing else:
1. A ```rhai block containing the full Rhai script.
2. A ```json block with the manifest stub: "name", "version", "entrypoints" ({"name","signature"}),
   and "provides" (array).

Worked example for "reverse the bytes":

```rhai
fn handle(env) {
    let src = env.payload;
    let out = blob();
    let i = src.len();
    while i > 0 {
        i -= 1;
        out.push(src[i]);
    }
    out
}
```

```json
{ "name": "reverse-critter", "version": "0.1.0", "entrypoints": [{ "name": "handle", "signature": "(env) -> reply" }], "provides": [] }
```
"#;

// A deliberately narrow typed-Function prompt. This is a specialization of the critter tier, not a
// second Function protocol: it multiplexes the frozen gawd.function.call.v1 contract through the
// ordinary `handle(env)` script entrypoint and exposes only the pure bounded verification/JSON
// helpers already registered by build-critter and ScriptEngine.
const TYPED_FUNCTION_CRITTER_SYSTEM_PROMPT: &str = r#"You are an authoring creature for the Alpha substrate (the GAWD fabric).
Author a CRITTER-TIER TYPED-FUNCTION-CRITTER: one sandboxed Rhai script implementing the exact
bounded integer-doubling Function below. Do not produce Rust and do not change the Function wire
contract, field names, schemas, bounds, effect, controls, or entrypoint.

The exact manifest entrypoint is:
- name: `double_signed`
- signature: `gawd.function.call.v1`
- description: `Double a bounded signed integer.`
- input: an object with exactly one required `value` integer in -1000000..=1000000
- output: an object with exactly one required `doubled` integer in -2000000..=2000000
- no error schema; effect `idempotent`; progress/steer/cancel/checkpoint controls all false

Hard causal and route requirements for the Rhai source:
- Define `fn handle(env) { ... }`.
- Before parsing, require `env.schema == "gawd.function.call.v1"`, reject truncated text, and call
  `function_call_verify(env.text, env.from, env.to)`. This pure verifier authenticates the Home
  grant, executor dispatch, and exact executor-to-target route.
- Parse only after that verification with `json_parse(env.text)`, require operation `call`, require
  entrypoint `double_signed`, require inline input, then require an exact one-property input map whose
  `value` is an `i64`; enforce the input bounds again at runtime.
- Return `json_stringify(...)` containing a `FunctionResultV1`: operation `result`, the EXACT
  `invocation.attempt` received in the call (never a reconstructed AttemptId), and an `Ok` inline
  value `{ doubled: value * 2 }`.
- The only permitted host helpers are the pure bounded `function_call_verify`, `json_parse`, and
  `json_stringify` functions. No import, eval, filesystem, network, clock, random, key, or bus access.

Respond with EXACTLY two fenced code blocks and nothing else:
1. A ```rhai block containing the full Rhai script.
2. A ```json block containing this exact manifest stub shape.

```rhai
fn handle(env) {
    if env.schema != "gawd.function.call.v1" || env.text_truncated {
        return ();
    }
    if !function_call_verify(env.text, env.from, env.to) {
        return ();
    }

    let message = json_parse(env.text);
    if message.operation != "call" {
        return ();
    }
    let invocation = message["call"];
    if invocation.function.entrypoint != "double_signed" || invocation.input.kind != "inline" {
        return ();
    }
    let input = invocation.input.value;
    if type_of(input) != "map" || input.len() != 1 || !input.contains("value") {
        return ();
    }
    let value = input.value;
    if type_of(value) != "i64" || value < -1000000 || value > 1000000 {
        return ();
    }

    json_stringify(#{
        operation: "result",
        result: #{
            attempt: invocation.attempt,
            outcome: #{
                Ok: #{ kind: "inline", value: #{ doubled: value * 2 } }
            }
        }
    })
}
```

```json
{
  "name": "double-int-critter",
  "version": "0.1.0",
  "entrypoints": [{
    "name": "double_signed",
    "signature": "gawd.function.call.v1",
    "contract": {
      "description": "Double a bounded signed integer.",
      "input_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "value": { "type": "integer", "minimum": -1000000, "maximum": 1000000 } }, "required": ["value"], "additionalProperties": false } },
      "output_schema": { "kind": "inline", "schema": { "type": "object", "properties": { "doubled": { "type": "integer", "minimum": -2000000, "maximum": 2000000 } }, "required": ["doubled"], "additionalProperties": false } },
      "effect": "idempotent",
      "controls": { "progress": false, "steer": false, "cancel": false, "checkpoint": false }
    }
  }],
  "provides": []
}
```
"#;

/// Canonical source for the deliberately fixed legacy typed capability.
///
/// This is intentionally byte-exact after surrounding whitespace is trimmed. Treating a handful
/// of source substrings as semantic proof would let a model hide them in comments/dead code while
/// adding side effects or hard-coded examples. The current approved-profile path uses a strict
/// source-free IR plus trusted lowering; this legacy path instead accepts one audited pure
/// implementation and rejects every source variation before BuildCritter signs it.
const TYPED_FUNCTION_CRITTER_SOURCE: &str = r#"fn handle(env) {
    if env.schema != "gawd.function.call.v1" || env.text_truncated {
        return ();
    }
    if !function_call_verify(env.text, env.from, env.to) {
        return ();
    }

    let message = json_parse(env.text);
    if message.operation != "call" {
        return ();
    }
    let invocation = message["call"];
    if invocation.function.entrypoint != "double_signed" || invocation.input.kind != "inline" {
        return ();
    }
    let input = invocation.input.value;
    if type_of(input) != "map" || input.len() != 1 || !input.contains("value") {
        return ();
    }
    let value = input.value;
    if type_of(value) != "i64" || value < -1000000 || value > 1000000 {
        return ();
    }

    json_stringify(#{
        operation: "result",
        result: #{
            attempt: invocation.attempt,
            outcome: #{
                Ok: #{ kind: "inline", value: #{ doubled: value * 2 } }
            }
        }
    })
}"#;

fn typed_function_contract() -> EntrypointContractV1 {
    EntrypointContractV1 {
        description: "Double a bounded signed integer.".to_string(),
        input_schema: SchemaRefV1::Inline {
            schema: json!({
                "type": "object",
                "properties": {
                    "value": { "type": "integer", "minimum": -1_000_000, "maximum": 1_000_000 }
                },
                "required": ["value"],
                "additionalProperties": false
            }),
        },
        output_schema: SchemaRefV1::Inline {
            schema: json!({
                "type": "object",
                "properties": {
                    "doubled": { "type": "integer", "minimum": -2_000_000, "maximum": 2_000_000 }
                },
                "required": ["doubled"],
                "additionalProperties": false
            }),
        },
        error_schema: None,
        effect: EffectClassV1::Idempotent,
        controls: FunctionControlsV1::default(),
    }
}

/// Assemble the model request from an [`AuthoringRequest`]. The system prompt is tier-specific; on a
/// retry the structured compiler `prev_error` is appended under [`RETRY_MARKER`] so the model can fix
/// the previous attempt.
#[cfg(test)]
pub fn build_request(req: &AuthoringRequest) -> Prompt {
    build_request_for_mode(req, &AuthoringMode::Legacy(tier_of(req)))
}

pub(crate) fn build_request_for_mode(req: &AuthoringRequest, mode: &AuthoringMode) -> Prompt {
    let system_prompt = match mode {
        AuthoringMode::Legacy(tier) => legacy_system_prompt(*tier).to_string(),
        AuthoringMode::Approved { tier, .. } => approved_system_prompt(*tier),
    };
    let mut user_prompt = bounded_authoring_text(&req.request, MAX_AUTHORING_REQUEST_TEXT_BYTES);
    if let AuthoringMode::Approved { tier, profile } = mode {
        user_prompt.push_str("\n\nAPPROVED PROFILE (canonical JSON; semantic source of truth):\n");
        user_prompt.push_str(profile.canonical_spec());
        user_prompt.push_str("\nAPPROVED PROFILE DIGEST: ");
        user_prompt.push_str(profile.digest());
        user_prompt.push_str("\nREQUESTED TIER: ");
        user_prompt.push_str(tier.as_str());
    }
    if let Some(prev) = &req.prev_error {
        match mode {
            AuthoringMode::Legacy(_) => {
                let prev = bounded_authoring_text(prev, MAX_AUTHORING_PREV_ERROR_BYTES);
                user_prompt.push_str(&format!(
                    "\n\n{RETRY_MARKER} (your previous attempt failed to compile — read the error and fix it):\n{prev}"
                ));
            }
            AuthoringMode::Approved { .. } => {
                // The approved model never debugs generated code: templates are trusted host code.
                // Do not reflect a caller-controlled compiler error (which could contain source or
                // a completed record) back into this deliberately source-free prompt.
                user_prompt.push_str(&format!(
                    "\n\n{RETRY_MARKER} (the previous implementation record was refused — restate only the exact approved fields)"
                ));
            }
        }
    }
    let (max_tokens, temperature) = match mode {
        AuthoringMode::Legacy(_) => (4096, 0.2),
        AuthoringMode::Approved { .. } => (512, 0.0),
    };
    Prompt { system_prompt, user_prompt, max_tokens, temperature }
}

fn legacy_system_prompt(tier: Tier) -> &'static str {
    match tier {
        Tier::Daemon => DAEMON_SYSTEM_PROMPT,
        Tier::Critter => CRITTER_SYSTEM_PROMPT,
        Tier::TypedFunctionCritter => TYPED_FUNCTION_CRITTER_SYSTEM_PROMPT,
        Tier::TypedFunctionDaemon => TYPED_FUNCTION_DAEMON_SYSTEM_PROMPT,
        Tier::TypedFunctionBeast => TYPED_FUNCTION_BEAST_SYSTEM_PROMPT,
    }
}

fn approved_system_prompt(tier: ApprovedTier) -> String {
    let boundary = match tier {
        ApprovedTier::Daemon => {
            "Alpha's trusted renderer will produce native Rust that binds its signed manifest identity, verifies the authenticated Function call before decoding, uses checked i32 arithmetic, and continues the exact AttemptId."
        }
        ApprovedTier::Beast => {
            "Alpha's trusted renderer will produce a closed no-import/no-start core-WASM module. WasmEngine authenticates the Function proof, route, identity, and AttemptId before/after the payload-only guest call."
        }
        ApprovedTier::Critter => {
            "Alpha's trusted renderer will produce Rhai that verifies the Function proof and exact route before parsing and continues the exact AttemptId in its result."
        }
    };
    format!(
        "You are the Builder model confirming one causally approved bounded capability for Alpha's {} tier.\n\
The canonical approved profile and its sha256 digest are in the user message. Treat them as immutable.\n\
Return exactly one JSON object and no Markdown, prose, source code, dependencies, manifest, or authority.\n\
The object has exactly four fields: `schema`, `profile_digest`, `tier`, and `program`.\n\
`schema` must be `{APPROVED_IMPLEMENTATION_V1}`; `profile_digest` and `tier` must bind the request.\n\
`program` has exactly `kind`, `multiplier`, and `addend` and must faithfully restate the approved affine_i32_v1 program.\n\
Do not invent values, fields, code, capabilities, controls, or an alternate implementation. {boundary}",
        tier.as_str()
    )
}

/// Parse a model completion into an [`AuthoringResponse`] for `tier`. Fails closed (see module docs).
#[cfg(test)]
pub fn parse_response(tier: Tier, content: &str) -> Result<AuthoringResponse, AuthoringError> {
    parse_legacy_response(tier, content)
}

pub(crate) fn parse_response_for_mode(
    mode: &AuthoringMode,
    content: &str,
) -> Result<AuthoringResponse, AuthoringError> {
    match mode {
        AuthoringMode::Legacy(tier) => parse_legacy_response(*tier, content),
        AuthoringMode::Approved { tier, profile } => {
            parse_approved_response(profile, *tier, content)
        }
    }
}

fn parse_approved_response(
    profile: &ApprovedTypedProfile,
    tier: ApprovedTier,
    content: &str,
) -> Result<AuthoringResponse, AuthoringError> {
    if content.len() > MAX_APPROVED_IMPLEMENTATION_BYTES {
        return Err(AuthoringError::Invalid {
            message: format!(
                "approved implementation is {} bytes, exceeds {} byte limit (fail-closed)",
                content.len(),
                MAX_APPROVED_IMPLEMENTATION_BYTES
            ),
        });
    }
    let implementation: ApprovedImplementationV1 = serde_json::from_str(content.trim()).map_err(
        |error| AuthoringError::Invalid {
            message: format!(
                "approved implementation must be one strict JSON object with no extra content (fail-closed): {error}"
            ),
        },
    )?;
    profile.verify_implementation(tier, &implementation).map_err(|error| {
        AuthoringError::Invalid {
            message: format!("approved implementation does not match its signed profile: {error}"),
        }
    })?;
    let manifest_stub = profile.manifest_stub(tier);
    let source = profile.rendered_source(tier);
    Ok(AuthoringResponse {
        crate_name: manifest_stub.name.clone(),
        crate_version: manifest_stub.version.clone(),
        source,
        manifest_stub,
        deps: vec![],
        template: format!("agent-mind-approved-affine-i32-{}", tier.as_str()),
    })
}

fn parse_legacy_response(tier: Tier, content: &str) -> Result<AuthoringResponse, AuthoringError> {
    if content.len() > MAX_MODEL_COMPLETION_BYTES {
        return Err(AuthoringError::Invalid {
            message: format!(
                "model response too large: {} bytes exceeds {} byte limit (fail-closed)",
                content.len(),
                MAX_MODEL_COMPLETION_BYTES
            ),
        });
    }
    let (source_langs, required, template): (&[&str], &str, &str) = match tier {
        // A daemon must end in `declare_creature!`; a critter must define `fn handle`. The required
        // token is the fail-loud backstop against a truncated/partial model response.
        Tier::Daemon => (&["rust", "rs"], "declare_creature!", "agent-mind"),
        Tier::Critter => (&["rhai", "rust", "rs"], "fn handle", "agent-mind-critter"),
        Tier::TypedFunctionCritter => (&["rhai"], "fn handle", "agent-mind-function-critter"),
        Tier::TypedFunctionDaemon => {
            (&["rust", "rs"], "declare_creature!", "agent-mind-function-daemon")
        }
        Tier::TypedFunctionBeast => (&["wat"], "(export \"handle\")", "agent-mind-function-beast"),
    };
    let source = extract_fenced(content, source_langs).ok_or_else(|| AuthoringError::Invalid {
        message: format!("model response contained no {source_langs:?} source block"),
    })?;
    if !source.contains(required) {
        return Err(AuthoringError::Invalid {
            message: format!(
                "authored source is missing the required `{required}` — it looks truncated or incomplete (fail-closed)"
            ),
        });
    }
    let stub_json = extract_fenced(content, &["json"]).ok_or_else(|| AuthoringError::Invalid {
        message: "model response contained no ```json manifest stub block (fail-closed)"
            .to_string(),
    })?;
    let manifest_stub: ManifestStub =
        serde_json::from_str(stub_json.trim()).map_err(|e| AuthoringError::Invalid {
            message: format!("malformed manifest stub JSON (fail-closed): {e}"),
        })?;
    if manifest_stub.name.trim().is_empty() {
        return Err(AuthoringError::Invalid {
            message: "manifest stub has an empty name (fail-closed)".to_string(),
        });
    }
    if manifest_stub.version.trim().is_empty() {
        return Err(AuthoringError::Invalid {
            message: "manifest stub has an empty version (fail-closed)".to_string(),
        });
    }
    match tier {
        Tier::TypedFunctionCritter => {
            validate_typed_function_critter_response(&source, &manifest_stub)?
        }
        Tier::TypedFunctionDaemon => {
            validate_typed_function_daemon_response(&source, &manifest_stub)?
        }
        Tier::TypedFunctionBeast => {
            validate_typed_function_beast_response(&source, &manifest_stub)?
        }
        Tier::Daemon | Tier::Critter => {}
    }
    let mut source = source.trim_end().to_string();
    source.push('\n');
    Ok(AuthoringResponse {
        crate_name: manifest_stub.name.clone(),
        crate_version: manifest_stub.version.clone(),
        source,
        manifest_stub,
        deps: vec![],
        template: template.to_string(),
    })
}

/// Fail closed before signing when a typed answer drifts from the one contract this prompt can
/// currently implement. Both source and authored manifest posture are exact: there is no claim that
/// substring checks constitute Rhai semantic analysis. BuildCritter remains the independent syntax
/// gate and the composed ScriptEngine proof exercises authenticated positive/negative calls.
fn validate_typed_function_critter_response(
    source: &str,
    manifest_stub: &ManifestStub,
) -> Result<(), AuthoringError> {
    if !has_exact_typed_function_manifest(manifest_stub, "double-int-critter") {
        return Err(AuthoringError::Invalid {
            message: format!(
                "typed Function manifest must be the exact no-capability/no-provides `double-int-critter` v0.1.0 stub with one `double_signed` {SCHEMA_CALL_V1} entrypoint, the bounded idempotent contract, and all controls false (fail-closed)"
            ),
        });
    }
    if source.trim_end() != TYPED_FUNCTION_CRITTER_SOURCE {
        return Err(AuthoringError::Invalid {
            message: "typed Function source must exactly match the audited pure double_signed implementation; comments, dead code, side effects, and hard-coded examples are refused (fail-closed)".to_string(),
        });
    }
    Ok(())
}

/// The native tier shares Alpha's process, so accepting arbitrary model output would exceed its
/// trusted-by-admission posture. Admit only the reviewed implementation and exact manifest before
/// BuildCargo is allowed to compile or sign anything.
fn validate_typed_function_daemon_response(
    source: &str,
    manifest_stub: &ManifestStub,
) -> Result<(), AuthoringError> {
    if !has_exact_typed_function_manifest(manifest_stub, "double-int-daemon") {
        return Err(AuthoringError::Invalid {
            message: format!(
                "typed native Function manifest must be the exact no-capability/no-provides `double-int-daemon` v0.1.0 stub with one `double_signed` {SCHEMA_CALL_V1} entrypoint, the bounded idempotent contract, and all controls false (fail-closed)"
            ),
        });
    }
    if source.trim_end() != TYPED_FUNCTION_DAEMON_SOURCE {
        return Err(AuthoringError::Invalid {
            message: "typed native Function source must byte-match the audited trusted-by-admission double_signed implementation; comments, dead code, extra authority, and hard-coded examples are refused (fail-closed)".to_string(),
        });
    }
    Ok(())
}

/// The Beast's narrow authoring profile is byte-exact for the same reason as the native profile:
/// accepting merely similar WAT could add imports, a start function, hidden ambient behavior, or a
/// parser that disagrees with the signed contract. BuildBeast supplies an independent binary ABI
/// and no-import validation gate after this model-output gate.
fn validate_typed_function_beast_response(
    source: &str,
    manifest_stub: &ManifestStub,
) -> Result<(), AuthoringError> {
    if !has_exact_typed_function_manifest(manifest_stub, "double-int-beast") {
        return Err(AuthoringError::Invalid {
            message: format!(
                "typed Beast Function manifest must be the exact no-capability/no-provides `double-int-beast` v0.1.0 stub with one `double_signed` {SCHEMA_CALL_V1} entrypoint, the bounded idempotent contract, and all controls false (fail-closed)"
            ),
        });
    }
    if source.trim_end() != TYPED_FUNCTION_BEAST_SOURCE {
        return Err(AuthoringError::Invalid {
            message: "typed Beast Function source must byte-match the audited no-import double_signed WAT; leading whitespace, comments, source drift, extra authority, and hard-coded examples are refused (fail-closed)".to_string(),
        });
    }
    Ok(())
}

fn has_exact_typed_function_manifest(manifest_stub: &ManifestStub, name: &str) -> bool {
    let expected_contract = typed_function_contract();
    manifest_stub.entrypoints.len() == 1
        && manifest_stub.name == name
        && manifest_stub.version == "0.1.0"
        && manifest_stub.entrypoints[0].name == "double_signed"
        && manifest_stub.entrypoints[0].signature == SCHEMA_CALL_V1
        && manifest_stub.entrypoints[0].contract.as_ref() == Some(&expected_contract)
        && manifest_stub.capabilities == sigil::Capabilities::default()
        && manifest_stub.provides.is_empty()
}

/// Extract the body of the first fenced code block whose info string matches one of `langs`
/// (case-insensitive). **Line-oriented**: only a line whose first non-whitespace is ``` opens or
/// closes a fence, so an inner ` ``` ` *inside* a block (e.g. a `/// ```` rustdoc example in the
/// authored source) does NOT desync the scanner — the previous byte-`find` approach truncated valid
/// source at the first such inner fence. Scans every block so order (rust-then-json or json-first)
/// doesn't matter.
fn extract_fenced(content: &str, langs: &[&str]) -> Option<String> {
    let mut lines = content.lines();
    while let Some(line) = lines.next() {
        let trimmed = line.trim_start();
        let Some(info) = trimmed.strip_prefix("```") else { continue };
        // Opener: the info string is the rest of this line (the language tag).
        let is_match = langs.iter().any(|l| info.trim().eq_ignore_ascii_case(l));
        let mut body = String::new();
        let mut closed = false;
        for inner in lines.by_ref() {
            if inner.trim_start().starts_with("```") {
                closed = true;
                break;
            }
            body.push_str(inner);
            body.push('\n');
        }
        if !closed {
            // Unterminated fence — give up rather than return a half block.
            return None;
        }
        if is_match {
            return Some(body);
        }
        // Not our language: keep scanning after this block's close (the inner loop consumed it).
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::{AffineI32SpecV1, ApprovedProgramKindV1};
    use mind::{FakeModel, Model, CRITTER_TIER_MARKER};

    fn approved_profile() -> Arc<ApprovedTypedProfile> {
        let spec = AffineI32SpecV1 {
            kind: ApprovedProgramKindV1::AffineI32V1,
            slug: "triple-minus-five".into(),
            name: "Triple minus five".into(),
            entrypoint: "triple_minus_five".into(),
            description: "Multiply a bounded integer by three, then subtract five.".into(),
            input_min: -64,
            input_max: 64,
            multiplier: 3,
            addend: -5,
            local_input: 21,
            remote_input: -21,
        };
        let digest = ApprovedTypedProfile::canonical_digest(&spec).unwrap();
        Arc::new(ApprovedTypedProfile::from_approved(spec, &digest).unwrap())
    }

    #[test]
    fn approved_mode_routes_exact_requests_and_reserved_drift_fails_closed() {
        let profile = approved_profile();
        for tier in ApprovedTier::ALL {
            let request = AuthoringRequest { request: profile.request(tier), prev_error: None };
            assert!(matches!(
                resolve_mode(&request, Some(&profile)),
                Ok(AuthoringMode::Approved { tier: actual, .. }) if actual == tier
            ));
        }

        let drifted = AuthoringRequest {
            request: format!(
                "{}\nprofile=sha256:wrong\ntier=daemon",
                crate::APPROVED_TYPED_REQUEST_V1
            ),
            prev_error: None,
        };
        assert!(resolve_mode(&drifted, Some(&profile)).is_err());
        assert!(resolve_mode(&drifted, None).is_err());
        let unrelated = AuthoringRequest { request: "ordinary daemon".into(), prev_error: None };
        assert!(resolve_mode(&unrelated, Some(&profile)).is_err());
        assert!(matches!(resolve_mode(&unrelated, None), Ok(AuthoringMode::Legacy(Tier::Daemon))));
    }

    #[test]
    fn approved_prompt_binds_spec_and_constraints_without_embedding_source_or_answer() {
        let profile = approved_profile();
        let request = AuthoringRequest {
            request: profile.request(ApprovedTier::Daemon),
            prev_error: Some(
                "use forge::prelude::*; {\"schema\":\"alpha.approved_implementation.v1\"}".into(),
            ),
        };
        let mode = AuthoringMode::Approved { tier: ApprovedTier::Daemon, profile: profile.clone() };
        let prompt = build_request_for_mode(&request, &mode);
        assert!(prompt.user_prompt.contains(profile.canonical_spec()));
        assert!(prompt.user_prompt.contains(profile.digest()));
        assert!(prompt.user_prompt.contains(RETRY_MARKER));
        assert!(prompt.system_prompt.contains("exactly one JSON object"));
        assert!(prompt.system_prompt.contains("trusted renderer"));
        for forbidden in [
            "use forge::prelude::*",
            "(module",
            "fn handle(env)",
            "{\"schema\":\"alpha.approved_implementation.v1\"",
        ] {
            assert!(
                !prompt.system_prompt.contains(forbidden)
                    && !prompt.user_prompt.contains(forbidden),
                "approved prompt embedded forbidden completed source/answer: {forbidden}"
            );
        }
        assert_eq!(prompt.max_tokens, 512);
        assert_eq!(prompt.temperature, 0.0);
    }

    #[test]
    fn approved_response_strictly_validates_ir_then_renders_each_tier() {
        let profile = approved_profile();
        for tier in ApprovedTier::ALL {
            let mode = AuthoringMode::Approved { tier, profile: profile.clone() };
            let content = serde_json::to_string(&profile.implementation(tier)).unwrap();
            let response = parse_response_for_mode(&mode, &content).unwrap();
            assert_eq!(
                serde_json::to_value(&response.manifest_stub).unwrap(),
                serde_json::to_value(profile.manifest_stub(tier)).unwrap()
            );
            assert_eq!(response.source, profile.rendered_source(tier));
            assert!(response.deps.is_empty());
            assert!(response.template.ends_with(tier.as_str()));
        }
    }

    #[test]
    fn approved_response_rejects_raw_code_unknown_fields_and_semantic_drift() {
        let profile = approved_profile();
        let mode = AuthoringMode::Approved { tier: ApprovedTier::Daemon, profile: profile.clone() };
        for invalid in [
            "```rust\nuse forge::prelude::*;\n```".to_string(),
            format!(
                "{} trailing prose",
                serde_json::to_string(&profile.implementation(ApprovedTier::Daemon)).unwrap()
            ),
            {
                let mut value =
                    serde_json::to_value(profile.implementation(ApprovedTier::Daemon)).unwrap();
                value["source"] = json!("arbitrary native code");
                value.to_string()
            },
            {
                let mut value =
                    serde_json::to_value(profile.implementation(ApprovedTier::Daemon)).unwrap();
                value["program"]["multiplier"] = json!(4);
                value.to_string()
            },
            serde_json::to_string(&profile.implementation(ApprovedTier::Beast)).unwrap(),
        ] {
            assert!(
                parse_response_for_mode(&mode, &invalid).is_err(),
                "invalid approved completion was admitted: {invalid}"
            );
        }
        assert!(parse_response_for_mode(&mode, &"x".repeat(MAX_APPROVED_IMPLEMENTATION_BYTES + 1))
            .is_err());
    }

    #[test]
    fn tier_of_routes_on_the_critter_keyword() {
        assert_eq!(
            tier_of(&AuthoringRequest { request: "reverse a string".into(), ..Default::default() }),
            Tier::Daemon
        );
        assert_eq!(
            tier_of(&AuthoringRequest {
                request: "reverse it critter".into(),
                ..Default::default()
            }),
            Tier::Critter
        );
        assert_eq!(
            tier_of(&AuthoringRequest {
                request: DOUBLE_SIGNED_CRITTER_REQUEST_V1.into(),
                ..Default::default()
            }),
            Tier::TypedFunctionCritter
        );
        assert_eq!(
            tier_of(&AuthoringRequest {
                request: DOUBLE_SIGNED_DAEMON_REQUEST_V1.into(),
                ..Default::default()
            }),
            Tier::TypedFunctionDaemon
        );
        assert_eq!(
            tier_of(&AuthoringRequest {
                request: DOUBLE_SIGNED_BEAST_REQUEST_V1.into(),
                ..Default::default()
            }),
            Tier::TypedFunctionBeast
        );
        assert_eq!(
            tier_of(&AuthoringRequest {
                request: "write a functional logging critter".into(),
                ..Default::default()
            }),
            Tier::Critter,
            "an unrelated critter request must not select the fixed double_signed profile"
        );
        assert_eq!(
            tier_of(&AuthoringRequest {
                request: "write a functional native logging daemon".into(),
                ..Default::default()
            }),
            Tier::Daemon,
            "an unrelated native request must not select the audited double_signed profile"
        );
    }

    #[test]
    fn critter_prompt_carries_the_tier_marker() {
        let r = build_request(&AuthoringRequest {
            request: "reverse critter".into(),
            ..Default::default()
        });
        assert!(r.system_prompt.contains(CRITTER_TIER_MARKER), "critter prompt marks the tier");
        let d =
            build_request(&AuthoringRequest { request: "reverse".into(), ..Default::default() });
        assert!(!d.system_prompt.contains(CRITTER_TIER_MARKER), "daemon prompt does not");
    }

    #[test]
    fn typed_function_prompt_locks_schema_causality_and_route_verification() {
        let request = AuthoringRequest {
            request: DOUBLE_SIGNED_CRITTER_REQUEST_V1.into(),
            ..Default::default()
        };
        let prompt = build_request(&request);
        for required in [
            TYPED_FUNCTION_CRITTER_MARKER,
            SCHEMA_CALL_V1,
            "-1000000",
            "1000000",
            "-2000000",
            "2000000",
            "function_call_verify(env.text, env.from, env.to)",
            "EXACT",
            "invocation.attempt",
            "FunctionResultV1",
            "idempotent",
            "checkpoint controls all false",
            "input.len() != 1",
            "type_of(value) != \"i64\"",
        ] {
            assert!(prompt.system_prompt.contains(required), "prompt is missing {required}");
        }
    }

    #[test]
    fn typed_function_daemon_prompt_locks_identity_route_and_runtime_validation() {
        let request = AuthoringRequest {
            request: DOUBLE_SIGNED_DAEMON_REQUEST_V1.into(),
            ..Default::default()
        };
        let prompt = build_request(&request);
        for required in [
            TYPED_FUNCTION_DAEMON_MARKER,
            "trusted-by-admission",
            SCHEMA_CALL_V1,
            "ctx.manifest.content_address",
            "forge::function::parse_call(&env)",
            "call.function.manifest_content_address != manifest_content_address",
            "forge::function::from_inline::<BTreeMap<String, i64>>(&call.input)",
            "input.len() != 1",
            "(-1_000_000..=1_000_000).contains(&value)",
            "value.checked_mul(2)",
            "forge::function::success(&env, call.attempt, &output)",
        ] {
            assert!(prompt.system_prompt.contains(required), "prompt is missing {required}");
        }
    }

    #[test]
    fn typed_function_beast_prompt_locks_the_no_import_host_adapter_boundary() {
        let prompt = build_request(&AuthoringRequest {
            request: DOUBLE_SIGNED_BEAST_REQUEST_V1.into(),
            ..Default::default()
        });
        for required in [
            TYPED_FUNCTION_BEAST_MARKER,
            SCHEMA_CALL_V1,
            "no-import core-WASM module",
            "WasmEngine's host adapter verifies",
            "exact manifest-derived FunctionId",
            "receives only canonical inline application JSON bytes",
            "{\"value\":N}",
            "{\"doubled\":2N}",
            "EXACT verified AttemptId",
            "(memory (export \"memory\") 1)",
            "(func (export \"alloc\")",
            "(func (export \"handle\")",
        ] {
            assert!(prompt.system_prompt.contains(required), "prompt is missing {required}");
        }
        assert!(
            !prompt.system_prompt.contains("function_call_verify"),
            "the no-import Beast guest must not claim a script host verifier"
        );
    }

    fn good_typed_completion() -> String {
        let request = AuthoringRequest {
            request: DOUBLE_SIGNED_CRITTER_REQUEST_V1.into(),
            ..Default::default()
        };
        FakeModel::always_good().complete(build_request(&request)).unwrap().content
    }

    fn good_typed_daemon_completion() -> String {
        let request = AuthoringRequest {
            request: DOUBLE_SIGNED_DAEMON_REQUEST_V1.into(),
            ..Default::default()
        };
        FakeModel::always_good().complete(build_request(&request)).unwrap().content
    }

    fn good_typed_beast_completion() -> String {
        let request = AuthoringRequest {
            request: DOUBLE_SIGNED_BEAST_REQUEST_V1.into(),
            ..Default::default()
        };
        FakeModel::always_good().complete(build_request(&request)).unwrap().content
    }

    #[test]
    fn parse_response_accepts_only_the_exact_typed_function_contract() {
        let response =
            parse_response(Tier::TypedFunctionCritter, &good_typed_completion()).unwrap();
        assert_eq!(response.template, "agent-mind-function-critter");
        assert_eq!(response.crate_name, "double-int-critter");
        assert_eq!(response.manifest_stub.entrypoints.len(), 1);
        let entrypoint = &response.manifest_stub.entrypoints[0];
        assert_eq!(entrypoint.name, "double_signed");
        assert_eq!(entrypoint.signature, SCHEMA_CALL_V1);
        assert_eq!(entrypoint.contract.as_ref(), Some(&typed_function_contract()));
    }

    #[test]
    fn parse_response_accepts_only_the_exact_typed_native_function_contract() {
        let response =
            parse_response(Tier::TypedFunctionDaemon, &good_typed_daemon_completion()).unwrap();
        assert_eq!(response.template, "agent-mind-function-daemon");
        assert_eq!(response.crate_name, "double-int-daemon");
        assert_eq!(response.source, format!("{TYPED_FUNCTION_DAEMON_SOURCE}\n"));
        assert_eq!(response.manifest_stub.entrypoints.len(), 1);
        assert_eq!(response.manifest_stub.capabilities, sigil::Capabilities::default());
        assert!(response.manifest_stub.provides.is_empty());
        let entrypoint = &response.manifest_stub.entrypoints[0];
        assert_eq!(entrypoint.name, "double_signed");
        assert_eq!(entrypoint.signature, SCHEMA_CALL_V1);
        assert_eq!(entrypoint.contract.as_ref(), Some(&typed_function_contract()));
    }

    #[test]
    fn parse_response_accepts_only_the_exact_typed_beast_source_and_shared_contract() {
        let response =
            parse_response(Tier::TypedFunctionBeast, &good_typed_beast_completion()).unwrap();
        assert_eq!(response.template, "agent-mind-function-beast");
        assert_eq!(response.crate_name, "double-int-beast");
        assert_eq!(response.source, format!("{TYPED_FUNCTION_BEAST_SOURCE}\n"));
        assert_eq!(response.manifest_stub.capabilities, sigil::Capabilities::default());
        assert!(response.manifest_stub.provides.is_empty());
        assert_eq!(response.manifest_stub.entrypoints.len(), 1);
        let entrypoint = &response.manifest_stub.entrypoints[0];
        assert_eq!(entrypoint.name, "double_signed");
        assert_eq!(entrypoint.signature, SCHEMA_CALL_V1);
        assert_eq!(entrypoint.contract.as_ref(), Some(&typed_function_contract()));
    }

    #[test]
    fn parse_response_rejects_blank_drifted_or_leading_whitespace_beast_source() {
        let completion = good_typed_beast_completion();

        let blank = completion.replacen(TYPED_FUNCTION_BEAST_SOURCE, "   ", 1);
        let error = parse_response(Tier::TypedFunctionBeast, &blank).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("required")),
            "blank Beast source fails before build: {error:?}"
        );

        let drifted = completion.replacen("(i32.const 1000000)", "(i32.const 999999)", 1);
        let error = parse_response(Tier::TypedFunctionBeast, &drifted).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("byte-match")),
            "Beast parser drift fails before build: {error:?}"
        );

        let leading = completion.replacen("```wat\n(module", "```wat\n\n(module", 1);
        let error = parse_response(Tier::TypedFunctionBeast, &leading).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("leading whitespace")),
            "leading source whitespace fails closed: {error:?}"
        );

        let blank_version =
            completion.replacen("\"version\": \"0.1.0\"", "\"version\": \"   \"", 1);
        let error = parse_response(Tier::TypedFunctionBeast, &blank_version).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("empty version")),
            "blank manifest version fails before typed validation: {error:?}"
        );

        let extra_authority = completion.replacen(
            "\"provides\": []",
            "\"capabilities\": { \"net\": \"outbound\" }, \"provides\": []",
            1,
        );
        let error = parse_response(Tier::TypedFunctionBeast, &extra_authority).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("no-capability/no-provides")),
            "Beast manifest authority drift fails closed: {error:?}"
        );
    }

    #[test]
    fn parse_response_rejects_typed_native_source_manifest_or_version_drift() {
        let completion = good_typed_daemon_completion();

        let wrong_source = completion.replacen(
            "forge::function::parse_call(&env)",
            "forge::function::parse_call_for(&env, unreachable!())",
            1,
        );
        let error = parse_response(Tier::TypedFunctionDaemon, &wrong_source).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("byte-match")),
            "native source drift fails before compilation: {error:?}"
        );

        let leading_source = completion.replacen("```rust\nuse forge", "```rust\n\nuse forge", 1);
        let error = parse_response(Tier::TypedFunctionDaemon, &leading_source).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("byte-match")),
            "even leading source drift fails closed: {error:?}"
        );

        let wrong_manifest = completion.replacen("double-int-daemon", "other-daemon", 1);
        let error = parse_response(Tier::TypedFunctionDaemon, &wrong_manifest).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("manifest")),
            "native manifest identity drift fails closed: {error:?}"
        );

        let extra_authority = completion.replacen(
            "\"provides\": []",
            "\"capabilities\": { \"net\": \"outbound\" }, \"provides\": []",
            1,
        );
        let error = parse_response(Tier::TypedFunctionDaemon, &extra_authority).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("no-capability/no-provides")),
            "native extra authority fails closed: {error:?}"
        );

        let blank_version_and_source_drift = completion
            .replacen("\"version\": \"0.1.0\"", "\"version\": \"   \"", 1)
            .replacen("forge::function::parse_call(&env)", "untrusted_parse(&env)", 1);
        let error =
            parse_response(Tier::TypedFunctionDaemon, &blank_version_and_source_drift).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("empty version")),
            "blank version is rejected before typed source validation: {error:?}"
        );
    }

    #[test]
    fn parse_response_rejects_typed_contract_or_causal_route_drift() {
        let completion = good_typed_completion();
        let wrong_contract = completion.replacen("\"maximum\": 1000000", "\"maximum\": 999999", 1);
        let error = parse_response(Tier::TypedFunctionCritter, &wrong_contract).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("manifest")),
            "contract mismatch fails closed: {error:?}"
        );

        let wrong_route = completion.replacen(
            "function_call_verify(env.text, env.from, env.to)",
            "function_call_verify(env.text, env.to, env.from)",
            1,
        );
        let error = parse_response(Tier::TypedFunctionCritter, &wrong_route).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("audited pure")),
            "route mismatch fails closed: {error:?}"
        );

        let rebuilt_attempt = completion.replacen(
            "attempt: invocation.attempt",
            "attempt: #{ home: invocation.attempt.home, job: invocation.attempt.job, number: invocation.attempt.number }",
            1,
        );
        let error = parse_response(Tier::TypedFunctionCritter, &rebuilt_attempt).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("audited pure")),
            "AttemptId reconstruction fails closed: {error:?}"
        );

        let hidden_required_text = completion.replacen(
            "fn handle(env) {",
            "// function_call_verify(env.text, env.from, env.to)\n// attempt: invocation.attempt\nfn handle(env) { return `hard-coded`; }\nfn ignored(env) {",
            1,
        );
        let error = parse_response(Tier::TypedFunctionCritter, &hidden_required_text).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("dead code")),
            "required strings in comments/dead code cannot substitute for audited behavior: {error:?}"
        );

        let leading_source = completion.replacen("```rhai\nfn handle", "```rhai\n\nfn handle", 1);
        let error = parse_response(Tier::TypedFunctionCritter, &leading_source).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("audited pure")),
            "leading source drift cannot create a second canonical artifact: {error:?}"
        );

        let extra_capability = completion.replacen(
            "\"provides\": []",
            "\"capabilities\": { \"net\": \"outbound\" }, \"provides\": [\"policy\"]",
            1,
        );
        let error = parse_response(Tier::TypedFunctionCritter, &extra_capability).unwrap_err();
        assert!(
            matches!(&error, AuthoringError::Invalid { message } if message.contains("no-capability/no-provides")),
            "extra authority in the signed manifest fails closed: {error:?}"
        );
    }

    #[test]
    fn build_request_appends_prev_error_under_the_retry_marker() {
        let base = build_request(&AuthoringRequest { request: "reverse".into(), prev_error: None });
        assert!(!base.user_prompt.contains(RETRY_MARKER), "no marker without prev_error");
        let retry = build_request(&AuthoringRequest {
            request: "reverse".into(),
            prev_error: Some("error[E0601]: expected item".into()),
        });
        assert!(retry.user_prompt.contains(RETRY_MARKER));
        assert!(retry.user_prompt.contains("E0601"));
    }

    #[test]
    fn build_request_bounds_request_and_retry_text_before_prompting() {
        let request = format!("reverse {}", "x".repeat(MAX_AUTHORING_REQUEST_TEXT_BYTES + 4096));
        let prev_error = format!("error {}", "e".repeat(MAX_AUTHORING_PREV_ERROR_BYTES + 4096));
        let prompt = build_request(&AuthoringRequest {
            request: request.clone(),
            prev_error: Some(prev_error.clone()),
        });

        assert!(prompt.user_prompt.contains("truncated"), "prompt marks truncation");
        assert!(
            !prompt.user_prompt.contains(&"x".repeat(MAX_AUTHORING_REQUEST_TEXT_BYTES + 1)),
            "request text is bounded before prompt assembly"
        );
        assert!(
            !prompt.user_prompt.contains(&"e".repeat(MAX_AUTHORING_PREV_ERROR_BYTES + 1)),
            "retry context is bounded before prompt assembly"
        );
        assert!(prompt.user_prompt.len() < request.len() + prev_error.len());
    }

    #[test]
    fn extract_fenced_ignores_inner_rustdoc_fences() {
        // The exact desync the line-oriented scanner fixes: a rustdoc ``` fence inside the source.
        let content = "\
```rust
use forge::prelude::*;
/// # Example
/// ```
/// let x = 1;
/// ```
pub struct D;
forge::declare_creature!(D);
```
```json
{\"name\":\"d\",\"version\":\"0.1.0\"}
```";
        let r = parse_response(Tier::Daemon, content).unwrap();
        assert!(r.source.contains("declare_creature!"), "full source survives inner fences");
        assert!(r.source.contains("pub struct D"));
        assert_eq!(r.crate_name, "d");
    }

    #[test]
    fn parse_response_extracts_both_blocks_in_either_order() {
        let rust_first =
            "```rust\nforge::declare_creature!(X);\n```\n```json\n{\"name\":\"x\",\"version\":\"0.1.0\"}\n```";
        let r = parse_response(Tier::Daemon, rust_first).unwrap();
        assert_eq!(r.crate_name, "x");

        let json_first =
            "```json\n{\"name\":\"y\",\"version\":\"0.2.0\"}\n```\n```rust\nforge::declare_creature!(Y);\n```";
        let r = parse_response(Tier::Daemon, json_first).unwrap();
        assert_eq!(r.crate_name, "y");
        assert_eq!(r.crate_version, "0.2.0");
    }

    #[test]
    fn parse_response_critter_accepts_rhai_and_requires_fn_handle() {
        let ok = "```rhai\nfn handle(env) { env.payload }\n```\n```json\n{\"name\":\"c\",\"version\":\"0.1.0\"}\n```";
        let r = parse_response(Tier::Critter, ok).unwrap();
        assert_eq!(r.template, "agent-mind-critter");
        assert_eq!(r.crate_name, "c");

        let no_handle =
            "```rhai\nfn nope() {}\n```\n```json\n{\"name\":\"c\",\"version\":\"0.1.0\"}\n```";
        assert!(matches!(
            parse_response(Tier::Critter, no_handle),
            Err(AuthoringError::Invalid { .. })
        ));
    }

    #[test]
    fn parse_response_fails_closed_on_missing_source_block() {
        let e =
            parse_response(Tier::Daemon, "```json\n{\"name\":\"x\",\"version\":\"0.1.0\"}\n```")
                .unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "got {e:?}");
    }

    #[test]
    fn parse_response_rejects_oversized_completion_before_scanning() {
        let content = "x".repeat(MAX_MODEL_COMPLETION_BYTES + 1);
        let e = parse_response(Tier::Daemon, &content).unwrap_err();
        match e {
            AuthoringError::Invalid { message } => {
                assert!(message.contains("too large"), "got {message}");
                assert!(message.contains("fail-closed"), "got {message}");
            }
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_fails_closed_on_missing_json_stub() {
        let e =
            parse_response(Tier::Daemon, "```rust\nforge::declare_creature!(X);\n```").unwrap_err();
        match e {
            AuthoringError::Invalid { message } => assert!(message.contains("fail-closed")),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn parse_response_fails_closed_on_truncated_source_missing_macro() {
        // A rust block that lacks declare_creature! (e.g. truncated) is rejected, not passed to build.
        let e = parse_response(Tier::Daemon, "```rust\nuse forge::prelude::*;\n```\n```json\n{\"name\":\"x\",\"version\":\"0.1.0\"}\n```").unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "got {e:?}");
    }

    #[test]
    fn parse_response_fails_closed_on_malformed_json_stub() {
        let e = parse_response(
            Tier::Daemon,
            "```rust\nforge::declare_creature!(X);\n```\n```json\n{ not json\n```",
        )
        .unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "got {e:?}");
    }

    #[test]
    fn parse_response_rejects_blank_name_or_version() {
        for version in ["", "   "] {
            let content = format!(
                "```rust\nforge::declare_creature!(Z);\n```\n```json\n{{\"name\":\"z\",\"version\":{version:?}}}\n```"
            );
            let e = parse_response(Tier::Daemon, &content).unwrap_err();
            assert!(
                matches!(&e, AuthoringError::Invalid { message } if message.contains("empty version")),
                "blank version fails closed: {e:?}"
            );
        }
        let e = parse_response(
            Tier::Daemon,
            "```rust\nforge::declare_creature!(X);\n```\n```json\n{\"name\":\"\",\"version\":\"1\"}\n```",
        )
        .unwrap_err();
        assert!(matches!(e, AuthoringError::Invalid { .. }), "empty name fails closed: {e:?}");
    }
}
