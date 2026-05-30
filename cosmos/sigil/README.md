# sigil

`sigil` is GAWD's at-rest creature contract: manifest parsing, validation, content
addressing, provenance fields, capabilities, realm ids, and ed25519 signing/verification helpers.

It deliberately does not depend on the bus, engines, kernel, daemon, or any model creature. The
full workspace lives at <https://github.com/gawd-ai/alpha>; the architecture and design notes are in
the repository `docs/` tree.

This contract is pre-1.0 in Alpha's first public release. `Manifest` may still change when
correctness, security, or the operating model requires it.

---

## The manifest

A `Manifest` is the **sole** metadata + permission source for a creature — there is no parallel
config system. It is what admission reads, what travels with the artifact, and what a signature
commits to. The artifact bytes (the `.so` for a daemon, the `.wasm` for a beast, the `.rhai` source
for a critter) are *separate* — the manifest describes and authorizes them.

| Field | Type | Meaning |
|---|---|---|
| `name` | string (**required**) | Creature name. |
| `version` | string (**required**) | Semver string (validated non-empty; full semver later). |
| `abi` | `{ backend, abi_tag, target[] }` | Execution tier + entry-boundary compatibility tag + opaque target labels. |
| `entrypoints` | `[{ name, signature }]` | Advertised typed entries (e.g. `handle`). Each needs a non-empty `name` + `signature`; no duplicates. |
| `capabilities` | `Capabilities` | What the creature may do (see below). Enforced only when an operator opts in. |
| `requirements` | `Requirements` | What a host must offer (`accelerators`, `sensors`, `min_mem_bytes`, `connectivity?`, `jurisdiction?`). Matched by the Distributor against a node's embodiment. |
| `provenance` | `Provenance` | Authorship + integrity: `author?` (the **Abode** public key), `source_hash?`, `build_hash?`, `signature?`, `realm?`. |
| `content_address` | string? | `sha256:<hex>` over the manifest's identity shape. See *Signing & identity*. |
| `provides` | `[string]` | Which IoC roles this creature can fill (e.g. `["distributor", "policy"]`). |

**`abi.backend`** is one of `daemon` (native `.so`), `beast` (WASM), or `critter` (Rhai script) —
serialized lowercase. **`capabilities`** carries `fs[]`, `net` (`none` | `loopback` | `outbound` |
`any`, default `none`), `cpu_ms`, `mem_bytes`, `calls[]` (which addresses/roles/intents it may send
to — empty = unrestricted dev default), and the optional `budget_warn_at` threshold. Every
field except `name`/`version`/`abi` defaults, so a minimal manifest is small.

## Minimal valid manifest, per tier

The only structural requirements are a non-empty `name` + `version` and a well-formed `abi`. The
`abi_tag` is fixed per entry boundary; `target` may be empty (= portable/unspecified):

```jsonc
// daemon (native .so) — artifact: the compiled cdylib
{ "name": "reverse", "version": "0.1.0", "abi": { "backend": "daemon",  "abi_tag": "gawd_creature_v1"  } }

// beast (WASM) — artifact: the .wasm module
{ "name": "reverse", "version": "0.1.0", "abi": { "backend": "beast",   "abi_tag": "gawd_creature_v1"  } }

// critter (Rhai) — artifact: the .rhai source bytes themselves
{ "name": "reverse", "version": "0.1.0", "abi": { "backend": "critter", "abi_tag": "gawd_critter_v1" } }
```

A fuller, signable manifest adds an entrypoint, declared capabilities, what it provides, and signed
provenance:

```jsonc
{
  "name": "reverse",
  "version": "0.1.0",
  "abi": { "backend": "daemon", "abi_tag": "gawd_creature_v1", "target": ["x86_64-unknown-linux-gnu"] },
  "entrypoints": [ { "name": "handle", "signature": "(Envelope) -> Outcome" } ],
  "capabilities": { "net": "none", "cpu_ms": 50, "calls": [] },
  "provides": [],
  "provenance": { "author": "<hex ed25519 pubkey>", "realm": "local", "signature": "<hex sig>" },
  "content_address": "sha256:<hex>"
}
```

Construct one in Rust with `Manifest::new(name, version, backend, abi_tag)` and fill the rest, or
`Manifest::parse(bytes)` to validate untrusted JSON (never panics — malformed input becomes a
structured `ManifestError`).

## Machine-readable schema

A JSON Schema (Draft 2020-12) ships alongside this crate at
[`manifest.schema.json`](manifest.schema.json) — point an editor or an AI agent at it to validate or
autocomplete a manifest. It is **drift-guarded**: `tests/manifest_schema.rs` validates the manifests
the crate emits against it and asserts the schema's keys stay in lockstep with the `Manifest` Rust
type, so the published schema can never silently fall behind the contract.

## Signing & identity (read before you sign)

- **`content_address`** = `sha256:` over `identity_payload()` (the manifest with `signature` *and*
  `content_address` cleared). It binds the *whole* identity shape — two creatures with identical
  artifact bytes but different capabilities/provides/entrypoints get **distinct** addresses.
- **The signature** commits to `signing_payload()` (the manifest with only `signature` cleared) —
  so **`content_address` rides *inside* the signature.** This dictates the order:

  > **Set `content_address` (via `compute_content_address()`) *before* signing.** Sign first and the
  > receiver recomputes `signing_payload` over a manifest whose `content_address` is `None`/stale,
  > and verification fails. Admission re-derives and asserts self-consistency on every load.

- **Field order is part of the signed wire.** `signing_payload` is `serde_json::to_vec`, which emits
  fields in declaration order. **Appending new optional fields is additive; reordering or renaming an
  existing field invalidates signed manifests in flight** — treat it as a coordinated wire-format
  change, lockstep with the `signing_payload_hash_is_locked_to_a_known_fixture` tripwire test.

Verification (`Ed25519Verifier`) is a *mechanism* — *which* author keys to trust is an injected
admission-policy decision, never the substrate's.
