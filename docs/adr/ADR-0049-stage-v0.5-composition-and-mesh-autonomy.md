# ADR-0049 — Stage v0.5 composition before mesh autonomy

- **Status:** Accepted; not Implemented (candidate awaits exact-commit live acceptance)
- **Drives:** [TRD-007](../trd/TRD-007-cross-mesh-model-collaboration.md)
- **Date:** 2026-08-18
- **Successor to:** [ADR-0043](ADR-0043-reserved-seam-register.md) for milestone disposition only

## Context

[ADR-0043](ADR-0043-reserved-seam-register.md) correctly froze the shapes needed before v0.5.0, but
its historical register used one `realize-v0.5.0` label for two kinds of work:

1. the headline composition—live model-backed agents interacting over the already-live mesh; and
2. independent mesh-autonomy work—authority, membership, discovery, routing identity, and dynamic
   embodiment advertisement.

v0.4.4 subsequently landed typed Functions, durable Jobs, and portable Home custody. The meaningful
v0.5.0 proof can therefore be narrow and end-to-end: live models make causally dependent decisions,
one bounded typed program is host-validated and lowered into all three creature tiers, and the
resulting Functions complete durable Jobs. Folding membership, discovery, and advertisement into the
same gate would obscure what failed and turn a composition release into several substrate projects.

The earlier candidate treated deterministic/scripted models as sufficient acceptance and asked the
Builder model to emit executable Rust, WAT, and Rhai. That proves plumbing but not the intended
product claim, and accepting model-supplied native source would overstate the safety and generality of
this first milestone. The release decision instead needs genuine live calls with retained evidence
and a deliberately small executable family.

## Decision

1. **v0.5.0 acceptance requires one fresh retained live run.** The normative bar is TRD-007. A clean
   exact release commit must first pass push CI and then run `dialogue --live` with distinct Builder,
   Reviewer, and Contract Tester `mind::Model` injections in the reviewer-protected
   `v05-live-acceptance.yml` workflow. The workflow must retain its complete evidence bundle and
   create an external operator-signed seal over the evidence-index root. Scripted/default, fake,
   replayed, and ad hoc local runs remain useful regressions or exploratory evidence but are never
   product acceptance.
2. **Models decide a strict `affine_i32_v1` program, not executable source.** Four pairwise Dialogue
   turns produce a bounded Builder draft, a Reviewer decision that materially narrows both domain
   boundaries, a Contract Tester plan selecting the actual local/cross-Realm cases, and the Builder's
   exact normalized approval. Strict JSON decoding, unknown-field rejection, checked arithmetic,
   exhaustive bounded truth-table hashing, and fixed-order predecessor hashes make each contribution
   causal and material.
3. **Trusted host lowering is the execution boundary.** The same Builder model subsequently confirms
   three source-free `{profile_digest, tier, affine program}` records. `AgentMind` validates those
   records against the approved profile; audited host templates then produce the Rust, no-import WAT,
   and Rhai bytes and least-authority manifest stubs. `BuildCargo`, `BuildBeast`, and `BuildCritter`
   build and sign those bytes. A completion can neither inject source/dependencies/authority nor
   select an unreviewed program.
4. **Freshness is semantic, not cosmetic.** Live mode generates a fresh challenge nonce and rejects
   the checked-in fixture's exhaustive truth-table digest. The release operator must also pass every
   previously accepted live semantic digest through `--forbid-semantic`; changing names, prose,
   nonce, or test-vector choices cannot disguise reuse.
5. **The evidence distinguishes facts from claims.** Live acceptance retains seven calls: five from
   Builder and one each from Reviewer and Contract Tester. Provider response/request IDs, reported
   model, finish reason, and token usage are labeled provider-reported; they do not cryptographically
   attest model weights. Application signatures attest Dialogue answers and substrate proof objects.
   A private operator key signs the external evidence seal, while authorization of that public key
   remains release-operator policy. Workflow artifact attestations bind the copied binary and output
   packages to the GitHub workflow run; they complement those proofs but attest neither provider
   weights nor reproducible compilation.
6. **Evidence is durable and exact-commit-bound.** The newly created private evidence directory lives
   outside the worktree and retains sanitized endpoint origins/configuration, exact prompts and
   completions plus replay records, four signed turns, all decisions, the approved profile, lowered
   sources, manifests/artifacts, Bestiary proofs, and six complete per-Job execution bundles. Each
   bundle carries the caller-signed submission, contiguous Home-signed event history and terminal
   snapshot, signed grant, exact call plus executor-signed route, deployment receipt, and terminal
   execution receipt; an anchored result record hashes all six. These prove the signed intended
   topology and one-attempt history, not packet-level traversal. The final summary contains the clean
   Git commit, compile-time embedded build commit, running binary SHA-256, and toolchain. A verified
   hash index covers every payload file; the signed seal is a create-new sibling outside the indexed
   directory. The exact copied binary's standalone `dialogue verify-live` path then validates the
   pinned candidate, authorized seal signer, all evidence/causality/build/publication/execution links,
   and every prior accepted semantic digest without a provider, Git, mutable store, running Sanctum,
   or private key. The complete raw bundle is encrypted before transfer; an allowlisted safe pack
   excludes prompts/completions and secrets. Ninety-day Actions artifacts are staging only, so both
   packages, attestations, and run metadata move to immutable supported-lifetime storage before tag.
7. **Equivalence is not identity equality.** Backend is part of each signed manifest, so daemon,
   beast, and critter have distinct artifact hashes, content addresses, aliases, and `FunctionId`s.
   Their typed contract and approved affine behavior are equal. Each tier's identity is reused for
   one tester-selected local Job and one tester-selected A-Home → B-executor Job.
8. **v0.5.0 changes no wire or guest ABI.** It composes existing `mind::Model`, pairwise SEER
   Dialogue, signed provenance, author/build/sign, Bestiary/`EntryProof`, typed Function, and durable
   Job contracts. The typed beast retains the existing no-import host adapter and exported
   `memory + alloc + handle` ABI. No signed/serialized shape, address, topic, or Kernel route changes.
9. **The proof remains bounded.** One serialized, resource-capped `BuildCargo` invocation produces
   the native artifact; `BuildBeast` and `BuildCritter` invoke no Cargo; both Job worlds reuse the
   three outputs. Every model call, record, prompt, response, evidence file/directory, build, wait,
   and shutdown has an explicit bound or deadline.
10. **This is constrained typed synthesis, not arbitrary code or general agency.** The accepted
    family is one finite-domain affine `i32` transformation. The result does not establish open-ended
    planning, arbitrary source generation, a general agent framework, a provider-quality benchmark,
    arbitrary-N collaboration, broadcast/group chat, quorum/consensus, or cryptographic proof of
    model identity/weights.
11. **v0.5.1 targets operational authority, membership, and signed discovery.** It owns operational
    `OmegaServices`; Realm/Omega membership authority; signed discovery/bootstrap; and the
    authenticated node-key ↔ routing/`CreatureId`/Abode-identity map (ADR-0043 rows 1, 4, 12, 15).
12. **v0.5.2 targets dynamic capability and placement advertisement.** It owns ADR-0043 row 16:
    `OfferUpdate` plus runtime embodiment/capability advertisement.
13. **UDP application-envelope transport remains later and uncommitted.** Discovery may use
    datagrams or mDNS without promising arbitrary `aether::Envelope` carriage over UDP.
14. **The two-node topology is sufficient for this milestone.** Reviewer occupies in-process Kernel
   node A/Realm A; Builder and Contract Tester occupy node B/Realm B. Authenticated loopback TCP is
   real transport, but this is not a three-process deployment proof. The `cluster` runbook remains
   that separate proof.
15. **Acceptance state remains external until tag.** An append-only operator registry supplies the
    full set of previously accepted semantic digests to both live generation and offline
    verification, then records the new digest with the exact
    commit/workflow/index/binary/package/attestation and immutable-retention identities. It remains
    external until the proven commit is tagged; a tracked status or evidence-link edit before tag
    would create a different, unproved source identity.

## Consequences

- CI can prove every deterministic mechanism and negative gate without credentials, but CI alone can
  no longer make TRD-007 Met. Exact-commit live evidence is an explicit protected release ceremony
  after that same commit's push CI.
- The release retains enough sanitized material to replay and audit what each configured endpoint
  returned, which signed decisions were accepted, which code trusted lowering produced, and what ran.
- The model's creative authority is visible and narrow: choose one nontrivial bounded affine
  capability, review its domain, choose its cases, and approve the exact projection. Executable-code
  authority stays in audited host code and the existing builders/admission path.
- v0.5.1 and v0.5.2 can evolve mesh autonomy independently without being smuggled into the v0.5.0
  product claim.
- The frozen v0.5.0 source candidate keeps TRD-007 Accepted/not Met and this ADR Accepted/not
  Implemented until its external acceptance ceremony succeeds. Its version/changelog are committed
  before exact-commit CI and the retained, operator-sealed live run; post-proof metadata edits are a
  different, unproved commit. Workflow retention alone is insufficient: the encrypted/safe bundles
  and provenance records must be promoted from 90-day staging to the release-lifetime immutable
  store before tag. A later post-tag documentation commit links that record and advances status.

## Implementation sketch

- **Composition:** `dialogue` creates a fresh challenge, uses `DialogueMind` for the four signed live
  decisions, constructs `ApprovedTypedProfile`, and uses `AgentMind::approved_only` for the three
  Builder confirmations and trusted lowerings.
- **Evidence:** the recording model wrapper retains sanitized call metadata and exact replay; the
  demo writes bounded create-new evidence files, verifies their index, derives clean source identity,
  and writes a separately signed seal. The packaged binary's `dialogue verify-live` command verifies
  the full bundle offline under separately pinned trust inputs. Credentials are never serialized.
- **Build/execute:** `BuildCargo`, `BuildBeast`, and `BuildCritter` sign one artifact each; the durable
  Bestiary is reopened before proof; Function/Job compositions execute local and cross-Realm cases.
- **Wire posture:** zero change. Successor milestones require their own TRDs/ADRs and do not inherit
  pre-authorization for discovery, membership, advertisement, or UDP shapes.
- **Test posture:** default/`--fixture` plus focused tests cover deterministic regression, exact
  replay, schema/numeric/causal/freshness negatives, lowering/build/proof/Job behavior, evidence
  bounds/tamper checks, and OpenAI-feature compilation. Product acceptance additionally performs the
  fresh exact-commit protected-workflow `--live` run, the offline verifier, encrypted/private and
  disclosure-safe packages, workflow attestations, and immutable external retention.

## Related

[ADR-0038](ADR-0038-origin-stays-hop-by-hop.md),
[ADR-0043](ADR-0043-reserved-seam-register.md),
[ADR-0046](ADR-0046-functions-are-typed-creature-entrypoints.md),
[ADR-0047](ADR-0047-jobs-have-home-and-execution-ledgers.md),
[ADR-0048](ADR-0048-home-authority-moves-by-fenced-handoff.md),
[TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md), and
[TRD-007](../trd/TRD-007-cross-mesh-model-collaboration.md).
