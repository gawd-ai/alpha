# ADR-0046 — Functions are typed creature entrypoints

- **Status:** Implemented (v0.4.4)
- **Drives:** [TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md) R1–R3, R15
- **Date:** 2026-08-16
- **Successor/erratum to:** [ADR-0043](ADR-0043-reserved-seam-register.md), row 13

## Context

Alpha already signs an `entrypoints[]` catalog into every creature manifest. Each entry has a name and
a `signature` documented as a typed descriptor whose structured schema would arrive later. The runtime,
however, deliberately has one boundary on every tier: `Creature::handle(Envelope) -> Outcome`.

“Function system” could therefore mean three different things:

1. named, typed entrypoints dispatched over the existing handle;
2. a fourth, serverless/ephemeral execution primitive with its own packaging and lifecycle;
3. dynamic export of each entrypoint as an MCP tool.

Only the first preserves Alpha's one-loadable-unit invariant and works uniformly for native, WASM, and
Rhai. The second duplicates creature admission/lifecycle/distribution. The third confuses one external
control surface with the portable mesh contract and makes tool catalogs churn whenever an alias moves.

ADR-0043 reserved “multi-entrypoint critter dispatch,” but its claimed exhaustive register missed the
separate structured-manifest-entrypoint seam already promised by `sigil::Entrypoint`. This ADR records
that erratum and distinguishes the two: typed application dispatch realizes the manifest seam; direct
engine calls to exported Rhai functions remain reserved.

## Decision

1. A **Function** is one named `sigil::Entrypoint` on a creature. It is not an artifact, tier, address,
   process, or kernel object.
2. Append an optional, serde-elided `gawdfn::EntrypointContractV1` to `sigil::Entrypoint`; retain the
   existing bounded `signature: String`. The structured contract names input/output schema and the
   behavioral declarations needed by adapters. Absence preserves the legacy manifest bytes.
3. Canonical identity is `gawdfn::FunctionId { manifest_content_address, entrypoint }`. The manifest
   content address binds the full signed definition; the artifact hash remains a separate byte-fetch
   fact in a deployment receipt.
4. Friendly `FunctionAlias` values are mutable resolver data. Submission resolves an alias to a signed
   `ResolvedFunctionV1` and durably pins that immutable result before any attempt. Alias rebinding never
   mutates accepted work.
5. Deployment is explicit: fetch/verify/admit/load the creature through the existing path, then register
   a `DeploymentReceiptV1`. Invocation refuses an inactive or mismatched deployment rather than hiding
   fetch/load inside “call.”
6. Calls ride `gawd.function.call.v1` as an ordinary payload delivered to the existing `handle` ABI.
   A Forge/target adapter verifies the Home grant plus the stable-executor-signed dispatch binding the
   current local executor route, target, deployment, and attempt before it demultiplexes the
   entrypoint name. No Function-specific address, Router path, Kernel invocation path, engine ABI, or
   `gawd_creature_v1` change is allowed. Cross-node recovery uses the generic, explicitly exposed
   `Address::NodeRole` routing mechanism; it resolves a live organ role and does not make Functions a
   new addressable runtime tier.
7. MCP/HTTP/REPL expose fixed generic operations such as resolve/deploy/submit/get. They do not mutate
   their catalogs to export one tool per live alias.

## Consequences

- Every tier gains the same function semantics without a parallel loader or containment story.
- Function identity is portable and immutable; aliases remain pleasant without becoming authority.
- Per-function security is declarative metadata within the creature's signed manifest, but lifecycle,
  admission, and unload remain at creature grain.
- A loaded creature may expose several Functions, yet a fault/unload still affects the creature as one
  unit. Authors who need independent isolation publish independent creatures.
- Generic MCP tools are less magical than dynamic tool export, but stable, auditable, and identical to
  the mesh/HTTP/REPL contract.
- Direct invocation of exported script/native symbols remains a separate, unresolved ABI question.

## Implementation sketch

- **Files:** `foundation/gawdfn` owns `EntrypointContractV1`, Function/deployment identities and schema
  constants; `cosmos/sigil` appends `Entrypoint.contract`; `cosmos/forge` gains optional dispatch
  helpers/adapters. The reference explicit deployment verb currently accepts bounded node-local
  Manifest/artifact paths, recomputes their identities, uses the existing Kernel admission/load path,
  and passes the exact Manifest/deployment facts to executor registration. A remote Registry/GX
  fetcher can supply the same bytes, but is not silently part of Function invocation (the Kernel
  roster is not a manifest registry).
- **Wire-additivity:** additive. A missing optional contract serializes byte-identically to v0.4.3. A
  present contract deliberately changes the manifest identity and signature. All function messages use
  new `gawd.function.*.v1` application schemas; Envelope and creature ABI bytes do not change.
- **Test:** legacy manifest serialization/content-address fixture; typed contract round-trip and tamper;
  two same-artifact manifests with different contracts produce different Function IDs; alias rebind
  after submit leaves the Job's pinned Function ID unchanged; unknown entrypoint/mismatched content
  address/inactive deployment fail closed on all three surfaces.

## Related

[ADR-0043](ADR-0043-reserved-seam-register.md) (erratum/successor relationship),
[ADR-0047](ADR-0047-jobs-have-home-and-execution-ledgers.md),
[TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md),
[`functions-and-jobs`](../design/functions-and-jobs.md).
