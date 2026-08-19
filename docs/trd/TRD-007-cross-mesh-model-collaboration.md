# TRD-007 — Cross-mesh live-model collaboration to an all-tier typed capability

- **Status:** Accepted (v0.5.0); not yet Met
- **Theme:** Product composition proof
- **Spawns:** [ADR-0049](../adr/ADR-0049-stage-v0.5-composition-and-mesh-autonomy.md)
- **Builds on:** [TRD-002](TRD-002-cross-node-relay-integrity.md),
  [TRD-004](TRD-004-reserved-seam-discipline.md), and
  [TRD-006](TRD-006-typed-functions-and-durable-jobs.md)
- **Invariants in play:** fabric, not model; one existing wire; application-signed identity; one
  loadable unit per artifact; durable proof before a product claim.

## Scope

v0.5.0 must prove one deliberately bounded product sentence: **on the exact release commit, three
role-configured live model instances make four causally linked, application-signed decisions across
two Realms; their accepted result is a fresh `affine_i32_v1` data program; trusted host code validates
and lowers that program into daemon, beast, and critter implementations; and all three signed,
durably recovered Functions complete local and cross-Realm Jobs.** The run must retain the provider
receipts and all material proof objects in a hash-indexed evidence directory, then bind that index to
an external operator-signed seal. Product acceptance first runs the exhaustive credential-free
`tools/local-validation.sh` gate on the frozen exact commit and prepares its report plus copied-binary
handoff. The unchanged commit then passes the short hosted sanity gate before the local
`tools/v05-live-acceptance.sh` ceremony consumes that handoff and uses the packaged candidate
binary's standalone
`dialogue verify-live` path to validate the retained bundle without a provider, Git, mutable store,
running Sanctum, or private key. GitHub receives neither provider/operator keys nor raw evidence.

The default/`--fixture` dialogue run is a hermetic regression and exact-replay check. It is valuable
mechanism evidence, but it is not evidence that models made the decisions and cannot make
TRD-007 Met. A live chat transcript without the retained artifacts, execution receipts, exact source
identity, and operator seal is also insufficient.

This milestone does **not** ask a model to emit Rust, WAT, Rhai, dependencies, capabilities, or other
executable text. It does not claim arbitrary-code synthesis or general agency. Models may choose
only one small, source-free intermediate representation:

```text
affine_i32_v1
input:  { "value": i32 } within one finite approved interval
output: { "result": checked(multiplier * value + addend) }
```

The admitted interval contains at most 257 values. Coefficients and all derived outputs are bounded
and checked; constant, identity, pure-negation, legacy signed-doubling, overflow, unknown fields, and
source-smuggling forms are rejected. The host exhaustively derives the interval truth table and its
semantic digest. A live candidate must differ semantically from the checked-in fixture and from every
prior accepted live capability supplied by the release operator.

## Required composition

```text
fresh nonce-bound challenge
          |
Builder live call: bounded affine draft D
          |
          +--> Reviewer live call: materially narrower domain R
          |
          +--> Contract Tester live call: exact ordered cases T over D + R
          |
Builder live call: exact normalized approval A over challenge + D + R + T
          |
host validates every record, predecessor hash, expected result, and semantic digest
          |
same Builder Model injection confirms three strict source-free implementation records
          |
trusted lowering             trusted lowering              trusted lowering
Rust template                no-import WAT template         Rhai template
     |                               |                           |
BuildCargo                       BuildBeast                  BuildCritter
     +---------------- three signed artifacts -----------------+
                              |
             durable Bestiary recovery + three EntryProofs
                              |
       one local and one A-Home -> B-executor Job per tier
                              |
  retained calls/receipts/turns/decisions/sources/artifacts/Job evidence
                              |
       hash-indexed evidence directory + external operator-signed seal
                              |
      offline exact-binary verifier + encrypted/raw and disclosure-safe packs
                              |
       immutable external retention + signed append-only acceptance record
```

The four Dialogue answers use pairwise-distinct agent signing identities. A signer-pinned initiator
verifies each existing `AnswerBody`; the host then decodes and validates its strict JSON record before
canonicalizing that record into later prompts. The final approval contains fixed-order predecessor
hashes and must be the exact normalized projection of the draft, review, and test plan. This is a
bounded causal fan-out/fan-in over pairwise Dialogue, not a broadcast/group-chat wire, arbitrary-N
workflow, quorum, consensus protocol, or durable multisignature transcript.

The same Builder `mind::Model` injection makes five live calls: draft, final approval, and one typed
implementation confirmation for each backend. Reviewer and Contract Tester make one call each, for
seven successful provider calls total. The three injected `Model` instances and application roles
must be distinct; they may deliberately share a provider or model product. Provider response IDs,
reported model IDs, finish reasons, and request IDs when available are provider-reported metadata,
not cryptographic proof of particular weights. Alpha's evidence attests what the configured endpoint
returned and what the signed run did with it.

## Requirements

- **R1 — Product acceptance uses live models.** The acceptance run MUST use `--live` and three
  separately configured Builder, Reviewer, and Contract Tester `mind::Model` instances. Each role
  MUST produce its required successful live completion. Scripted, fake, recorded/replay, copied, or
  fixture completions MUST NOT satisfy this requirement. The release-qualifying invocation MUST run
  through local `tools/v05-live-acceptance.sh` from the copied-binary handoff after that exact
  candidate passes local `tools/local-validation.sh` and short hosted sanity; a direct
  `dialogue --live` invocation is not the product gate. The
  hosted sanity gate MUST receive neither provider/operator keys nor raw evidence.
- **R2 — The run is fresh and bound to one exact source identity.** The challenge MUST contain a
  newly generated nonce. Its semantic truth-table digest MUST differ from the built-in fixture and
  every prior accepted live semantic digest supplied through `--forbid-semantic`. The run MUST start
  and finish on one clean exact Git commit. The live binary MUST embed the explicit
  `ALPHA_DIALOGUE_BUILD_COMMIT` supplied at compile time and require it to equal runtime HEAD;
  retained source identity MUST include that commit, the running dialogue binary's SHA-256, and the
  Rust toolchain identity. The exact binary MUST be retained beside the sealed evidence and match the
  recorded digest. A dirty worktree, missing/wrong embedded commit, changed HEAD, changed
  binary/toolchain identity, reused evidence path, or reused forbidden semantics MUST fail. These
  checks, the external seal, package digests, offline verifier report, and external acceptance record
  provide complementary provenance, not a reproducible-build proof.
- **R3 — Three signed agents make causal, material decisions.** Builder, Reviewer, and Contract
  Tester MUST have pairwise-distinct dialogue roles, application keys, and `Model` injections. The
  Builder proposes the bounded affine semantics; the Reviewer MUST narrow both domain boundaries;
  the Contract Tester MUST choose the actual negative-interior cross-Realm and positive-interior
  local inputs plus the exact ordered boundary/interior cases; and the Builder MUST return the exact
  normalized final projection. Every reply MUST verify under its pinned application signer. Every
  successor prompt MUST carry canonical, length-delimited validated predecessor records, and every
  record/hash/result mismatch MUST fail closed.
- **R4 — Model output is strict data, never executable source.** Decision and implementation records
  MUST reject unknown fields and obey their byte and numeric caps. The approved program family is
  exactly `affine_i32_v1`; models MUST NOT supply source, dependencies, manifest authority, tool calls,
  host calls, or an alternate program. The host MUST recompute all selected expected results, the
  exhaustive truth table, semantic digest, profile digest, and output bounds using checked arithmetic.
- **R5 — Trusted lowering is the only executable-code path.** After approval, the same Builder model
  MUST confirm exactly `{schema, profile_digest, tier, program}` for daemon, beast, and critter. Host
  validation MUST require the approved digest, tier, program kind, multiplier, and addend exactly.
  Audited host renderers—not completion text—MUST produce the Rust, no-import WAT, and Rhai bytes and
  the least-authority manifest stubs. This first profile is evidence of constrained typed synthesis,
  not arbitrary native-code authoring.
- **R6 — Every tier is genuinely built, signed, and durably recovered.** `BuildCargo`, `BuildBeast`,
  and `BuildCritter` MUST transform the trusted-lowered bytes into daemon, beast, and critter
  artifacts. Source/build hashes, content addresses, and manifest signatures MUST verify. After a
  fresh durable Bestiary recovery, all three exact entries and their `EntryProof`s MUST remain
  byte-identical and verifiable. A checked-in artifact, direct engine fixture, or source substitution
  MUST fail.
- **R7 — Equivalence and identity are explicit.** The host MUST recompute the complete approved affine
  truth table and require all three typed contracts to match its derived bounds. Exact equality with
  each audited, profile-parameterized trusted renderer is the full-domain semantic proof; the six
  tester-selected Jobs in R8 are runtime vectors, not an exhaustive per-point engine run. A builder
  substitution or renderer/source mismatch MUST fail. Backend-specific manifests MUST yield three
  distinct artifact hashes, content addresses, aliases, and `FunctionId`s. Each tier's immutable
  identity MUST remain stable across its local and cross-Realm Job worlds.
- **R8 — Six durable Jobs prove execution.** The Contract Tester's positive-interior value MUST drive
  one B-local at-most-once Job per tier; its negative-interior value MUST drive one A-Home →
  B-executor at-most-once Job per tier over authenticated TCP/Omega routing. Each MUST return the
  host-derived affine result with one successful attempt, one target delivery, and a verified signed
  terminal receipt. Retained evidence for each Job MUST include the caller-signed submission,
  Home-signed `Submitted`, `DispatchGranted`, and terminal events, the Home-signed terminal snapshot,
  the full contiguous event log, signed execution grant, exact `FunctionCall` with executor-signed
  dispatch route, deployment receipt, and terminal execution receipt. A final-summary-anchored result
  record MUST hash every per-Job bundle. These records prove the signed intended Home/deployment
  topology and one-attempt event history; they are not a packet capture or proof of every network hop.
  No direct creature call or rebuilt artifact may substitute.
- **R9 — The retained evidence is complete and replayable.** Live mode MUST retain exactly seven
  bounded model-call records and exact replay entries: five Builder, one Reviewer, and one Contract
  Tester. Every completed call MUST include a unique provider-reported response ID, a reported model
  ID, terminal `finish_reason=stop`, and `store_requested=false`; request ID and token usage are
  retained when reported. The bundle MUST also retain the sanitized endpoint origin/config (never API
  credentials), four signed turns, challenge and all decisions, approval/profile summaries, lowered
  sources, signed manifests/artifacts, Bestiary proofs, all six complete Job execution-proof bundles,
  the result record hashing them, and a final exact-source/run summary that anchors that record. Exact
  replay MUST reject prompt, role, ordinal, or completion drift. After generation, the standalone
  `dialogue verify-live` command MUST consume the exact packaged binary and independently pinned seal
  signer, candidate SHA, signed seal, evidence directory, and complete prior-semantic set. It MUST
  reconstruct and validate the entire causal/build/publication/execution chain offline and emit only
  the verified index, semantic, and binary digests plus the Builder, Reviewer, and Contract Tester
  requested-model labels recovered from the sealed call records on success.
- **R10 — Evidence retention and operator attestation fail closed.** The evidence directory MUST be
  a new absolute path outside the source worktree, have private permissions, refuse symlinks/reuse,
  and end with a verified SHA-256 index covering every payload file. A separate create-new seal file
  outside that directory MUST bind the index root and be signed by an operator-controlled Ed25519 key
  loaded from a private absolute file. The implementation verifies the signature; deciding whether
  that public key is an authorized release attester remains explicit operator policy. The complete
  plaintext bundle MUST be encrypted before transfer or upload; a separate disclosure-safe pack MUST
  exclude prompts/completions, credentials, and private keys while retaining the local validation
  report, exact binary, evidence index, signed seal, acceptance manifest, six-field verifier report,
  README, and hashes. A successful output directory MUST contain exactly the encrypted raw
  `.tar.gz.gpg` and disclosure-safe verification `.tar.gz`, and stdout MUST contain only its safe JSON
  summary. Secrets MUST never enter the evidence schema or GitHub. Before tagging, the release
  operator ceremony MUST move both packages and the exact binary directly, with digest verification,
  into an access-controlled immutable store retained for the supported release lifetime and retain
  the external promotion receipt.
- **R11 — Existing authority and wire contracts remain unchanged.** Dialogue approval, manifest
  provenance, `EntryProof`, deployment, Job acceptance/attempt/result, and the external evidence seal
  MUST verify under their stated keys/domains. Transport `Origin` remains hop-by-hop evidence. No new
  `Envelope`, address, SEER, Manifest, Function/Job, Bestiary, or creature-ABI wire shape is allowed.
  The typed beast uses the existing no-import host adapter and `memory + alloc + handle` payload ABI.
- **R12 — The proof is bounded and fail-loud.** Exactly one `BuildCargo` invocation is allowed, using
  the finite shared authoring cache, one Cargo job/codegen unit, disabled incremental compilation,
  serialization, and a hard timeout. `BuildBeast` and `BuildCritter` invoke no Cargo. Both Job worlds
  reuse the three outputs. Any missing live receipt, validation failure, partial build, proof mismatch,
  evidence write/seal failure, or cleanup failure MUST terminate without a product-success claim.
- **R13 — The release ceremony is local, exact, and externally anchored.** The candidate SHA MUST
  equal the `--exact-commit` input to the successful exhaustive local gate, checked-out `HEAD`,
  embedded build commit, final retained source identity, and the successful hosted sanity-gate SHA.
  The exhaustive local gate MUST build and copy/hash-pin the exact dialogue binary into its handoff.
  The same unchanged commit MUST subsequently pass the short hosted sanity gate without receiving
  provider/operator secrets or raw evidence. Only then may `tools/v05-live-acceptance.sh` verify its
  exact `--candidate-sha` and absolute `--validation-report` inputs, create the new absolute
  `--output-dir`, reference local secrets, run the same packaged bytes for generation and offline
  verification, encrypt the raw bundle, and produce the disclosure-safe pack. Before tagging, the
  release operator ceremony MUST verify immutable retention and record the verified output in an
  external signed/append-only acceptance and semantic registry. The registry record MUST stay
  external until the proven commit is tagged, so accepting the proof cannot mutate the commit it
  identifies. No retained provenance MUST be
  represented as proof of provider weights or reproducible compilation.

## Explicit non-goals

v0.5.0 does not establish general autonomous agency, open-ended planning, arbitrary source-code
generation, arbitrary typed schemas, a general workflow/agent framework, a model-quality benchmark,
or cryptographic attestation of provider weights. It does not add generic multi-language authoring,
dynamic MCP tool export, new trust/placement policy, exactly-once external effects, generic creature
migration, a broadcast/group-chat primitive, arbitrary-N orchestration, quorum/consensus, or a durable
group transcript. The three minds occupy two in-process Kernel nodes; this is not a three-process
deployment proof. The separate `cluster` runbook supplies that evidence. Discovery, operational
Realm/Omega authority, and dynamic advertisement remain successor work in ADR-0049.

## Acceptance

No row is Green from a fixture run or from mechanisms passing separately.

| Acceptance item | Required retained observation |
|---|---|
| Exact candidate | Clean exact Git commit, unchanged before/after; compile-time embedded commit equals runtime HEAD; exact running binary and its SHA-256 plus toolchain identity retained. |
| Freshness | Fresh nonce-bound challenge; semantic digest differs from the built-in fixture and every prior accepted digest supplied by the release operator. |
| Live provider calls | Seven completed calls: Builder ×5, Reviewer ×1, Contract Tester ×1; each has a unique provider response ID, reported model, `finish_reason=stop`, and `store_requested=false`. |
| Causal decisions | Four signer-verified pairwise turns; strict draft, materially narrowing review, five-case test plan, and exact final projection with validated predecessor hashes. |
| Strict IR and lowering | One bounded `affine_i32_v1` truth table; three exact source-free implementation confirmations; host validation and trusted Rust/WAT/Rhai lowering; no completion-supplied executable text. |
| Three artifacts | Three builder outputs with verified source/build hashes, content addresses, signatures, and recovered Bestiary `EntryProof`s. |
| Six executions | One local and one cross-Realm Job per distinct tier `FunctionId`, using tester-selected inputs and host-derived results, one successful attempt each. Each retained bundle carries caller/Home/executor signatures, the complete contiguous Home event history, grant/call/deployment/terminal receipts, and the intended route/topology; it does not claim packet-level traversal evidence. |
| Evidence bundle | Sanitized call configs, prompts/completions/replay, signed turns, decisions/approval, sources/artifacts/manifests, Bestiary proofs, six complete Job bundles, their hashed result record, and the anchoring final run summary all covered by the verified evidence index. |
| Operator attestation | External signed seal verifies over the exact evidence-index root under the release operator's authorized public key. |
| Offline verification | The packaged candidate binary's `dialogue verify-live` path accepts only with the pinned seal signer, candidate SHA, exact binary, signed seal, complete indexed evidence, and complete prior-semantic set; its six-field index/semantic/binary digest plus three sealed requested-model-label report is retained. |
| Exact local ceremony | Exhaustive local validation builds the binary and produces a report plus copied-binary handoff. The unchanged exact commit then passes short hosted sanity without keys or raw evidence. The local live tool verifies that handoff before secrets, the same bytes generate and verify evidence, and encrypted-raw/disclosure-safe packs are digest-pinned. The safe pack retains the validation report, exact binary, seal/index, acceptance manifest, six-field verifier report, README, and hashes. Before tag, the operator verifies immutable supported-lifetime retention and appends the external signed acceptance/semantic record. |
| Negative gates | Fixture/replay substitution, dirty/different commit, reused evidence path/semantics/provider response ID, missing receipt, source smuggling, unknown field, causal/hash/result drift, artifact/proof/route drift, partial execution, or evidence/seal failure is rejected. |
| Compatibility/resources | No wire/ABI change; one bounded native compile; no beast/critter Cargo invocation or per-world rebuild. |

### Frozen-candidate acceptance posture

The default scripted `dialogue` demo and deterministic test suites are regression evidence only.
They do not satisfy the live rows above. TRD-007 remains **Accepted, not Met**, ADR-0049 remains
**Accepted, not Implemented**, in the frozen v0.5.0 source candidate. Before that exact commit may be
tagged, all of the following must refer to it:

1. `tools/local-validation.sh` with `--exact-commit <40-hex-sha>` and
   `--output-dir <absolute-new-handoff-dir>` is Green for the exact clean candidate and produces its
   report plus copied binary;
2. short hosted sanity is Green for that exact unchanged commit without provider/operator keys or raw
   evidence;
3. local `tools/v05-live-acceptance.sh` consumes the validation handoff, runs a fresh proof with the
   complete external prior-semantic registry, and no tracked edit follows it;
4. the same packaged binary's `dialogue verify-live` command accepts the complete evidence under the
   independently pinned commit and seal signer;
5. the encrypted raw package, disclosure-safe pack, exact binary, and ceremony metadata move directly
   to immutable supported-lifetime storage; and
6. an external signed/append-only acceptance record names the commit/ceremony, validation-report and
   evidence-index digests, binary/package digests, authorized seal signer, provider/model labels,
   semantic digest, retention locations, and result.

The acceptance record must remain external until after the exact proven commit is tagged; editing
this file between proof and tag would invalidate the commit binding. A later commit may link the
record and advance status. The pending status in the tagged source is therefore not the acceptance
claim; the independently verified external record is.
