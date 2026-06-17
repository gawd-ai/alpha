# TRD-004 — Reserved-seam & embryo discipline

- **Status:** Met (v0.4.3)
- **Theme:** Anti-churn
- **Spawns:** [ADR-0043](../adr/ADR-0043-reserved-seam-register.md) (the reserved-seam register)
- **Invariant in play:** *additive wire only (zero-retrofit)* — v0.5.0 lands as **composition**, not a
  rewrite, and introduces **no wire-format churn**.

## Scope

Alpha is full of **reserved seams**: a wire shape, an enum variant, an optional serde-elided field, or
a trait whose *shape* is shipped now but whose *consumer* arrives later. They are the mechanism by which
GAWD grows "as an implementation of an existing concept, never as a new top-level layer bolted on
later." That discipline only pays off if every reserved seam is **inventoried and classified** before
v0.5.0 — otherwise the v0.5.0 headline (LLM-backed agents conversing across the meshed Ω) risks landing
as a wire change rather than as a swap of reference creatures for real ones.

This TRD states the anti-churn requirement, requires the register to exist
([ADR-0043](../adr/ADR-0043-reserved-seam-register.md)), and requires every reserved seam to be
classified — **keep-reserved** (wire locked, document), **realize-in-v0.4.3**, or **realize-in-v0.5.0**
— each tagged with the v0.5.0 consumer that will fill it. It does not itself change any seam; it makes
the contract that the register encodes binding.

## Requirements

- **R1 — v0.5.0 introduces no wire churn.** Every shape the v0.5.0 headline needs MUST already exist —
  reserved-and-documented or realized in v0.4.3 — so that v0.5.0 is *composition only* (swap reference
  agents for LLM-backed ones). No serialized/signed wire type, enum variant, or field added in v0.4.2
  may need a *breaking* change to host v0.5.0. The two anchor shapes are the closed `SeerTopic` set
  (`cosmos/seer/src/lib.rs:98-135`) — `Dialogue` already shipped (`lib.rs:134`) — and the dialogue body
  module (`cosmos/seer/src/lib.rs:987-1007`), which v0.5.0's LLM agents speak *unchanged* because the
  peer is a plain `aether::Address` and the reduction theorem holds (`lib.rs:131-133`).
- **R2 — The register exists and is complete.** [ADR-0043](../adr/ADR-0043-reserved-seam-register.md)
  MUST enumerate **every** reserved seam in the tree (embryo trait, reserved enum variant, reserved
  topic, forward-compat optional field, and the deferred-marker comments). A seam is "reserved" if its
  shape is shipped but a consumer is not yet wired. The register is the single place this inventory
  lives; a new reserved seam added in v0.4.3 MUST be added to it in the same change.
- **R3 — Every reserved seam is classified, with its v0.5.0 consumer named.** Each entry MUST carry a
  disposition — **keep-reserved** / **realize-in-v0.4.3** / **realize-in-v0.5.0** — and the consumer
  that fills it (or "none — defense-in-depth shape" where the seam is intentionally consumerless). A
  reserved seam with no named consumer and no rationale for staying empty is a finding, not a decision.
- **R4 — Wire-locked seams are marked and frozen.** Each entry MUST state whether the seam is
  **WIRE-LOCKED** (a serialized/signed name that *cannot* change without breaking a deployed peer — e.g.
  `OmegaDeferredReason::DeferredToV03`, `cosmos/omega-contract/src/lib.rs:83-86, 102`, a LOCKED v0.2
  commitment) or **forward-compatible-optional** (an additive, serde-elided field whose absence is
  wire-identical to today — e.g. `AbodeSnapshot::realm`, `cosmos/abode/src/lib.rs:129-133). "Document"
  for a wire-locked seam means: record that the name is frozen; do not rename it during convergence.
- **R5 — Anything classified realize-in-v0.4.3 has acceptance criteria.** A seam the register promises
  to realize *this* cycle MUST point at the work (file + the test that proves it) so the v0.4.3 `/goal`
  pass can close it. The headline realize-in-v0.4.3 item is the **signed dialogue provenance** shape
  from [ADR-0038](../adr/ADR-0038-origin-stays-hop-by-hop.md): optional `signer_pubkey` + `signature` on
  the dialogue answer body, with one verify/tamper test. Reserving the *fields* (not the signing of the
  reference echo agent) is the v0.4.3 commitment; the LLM-backed dialogue agent is the v0.5.0 consumer
  that signs for real.
- **R6 — Realize-in-v0.5.0 seams stay shape-frozen until then.** A seam deferred to v0.5.0 MUST NOT have
  its shape churned in v0.4.3 "in passing." `OmegaServices` (`cosmos/omega-contract/src/lib.rs:118-127`)
  and the `Realm` authority newtype (`cosmos/realm/src/lib.rs:46-67`) may have signatures *refined*
  before their first implementation (no consumer pins them — `lib.rs:114-117`), but the convergence pass
  does not implement them; it confirms they remain unbound and documented as embryos.

## Findings register

| Reserved seam | file:line | Wire-lock | Disposition | v0.5.0 consumer | Status |
|---|---|---|---|---|---|
| `OmegaServices` embryo trait | `cosmos/omega-contract/src/lib.rs:118-127` | not wire (trait) | realize-v0.5.0 | omega-federator (Ω authority) | **Verified** |
| `OmegaDeferredReason::DeferredToV03` | `cosmos/omega-contract/src/lib.rs:83-86, 102` | **WIRE-LOCKED** (v0.2 commitment) | keep-reserved | none (stub emits it forever) | **Verified** |
| `OmegaDeferredReply::details` optional | `cosmos/omega-contract/src/lib.rs:96-97` | additive optional | keep-reserved | richer federator replies | **Verified** |
| `Realm` authority newtype | `cosmos/realm/src/lib.rs:46-67` | additive (newtype) | realize-v0.5.0 | per-Realm membership/peering | **Verified** |
| SEER `Policy` topic + responder | `cosmos/seer/src/lib.rs:107-109`; `prototypes/responders/responder-policy` | not wire (closed enum) | keep-reserved (live ref) | richer admission agent | **Verified** |
| SEER `Budget` topic + responder | `cosmos/seer/src/lib.rs:110-112`; `responders/responder-budget` | not wire | keep-reserved (live ref) | budget-negotiating agent | **Verified** |
| SEER `Fitness` topic + responder | `cosmos/seer/src/lib.rs:113-115`; `responders/responder-fitness` | not wire | keep-reserved (live ref) | LLM rater | **Verified** |
| SEER `Curation` topic + responder | `cosmos/seer/src/lib.rs:120-125`; `responders/responder-curation` | not wire | keep-reserved (live ref) | external LLM curator | **Verified** |
| `AbodeSnapshot::realm` optional | `cosmos/abode/src/lib.rs:129-133` | additive optional | keep-reserved | Realm-aware restore policy | **Verified** |
| `Embodiment::sensors` optional | `cosmos/seer/src/lib.rs:570-573` | additive (`#[serde(default)]`) | keep-reserved | sensor `Predicate` kind | **Verified** |
| **Signed dialogue provenance** (new) | `cosmos/seer/src/lib.rs:987-1007` (dialogue `AnswerBody`) | additive optional | **realize-v0.4.3** | LLM-backed dialogue agent | **Verified** |
| UDP/mDNS discovery beacon | `cosmos/creatures/transport-tcp/src/lib.rs:36` | not wire (comment) | realize-v0.5.0 | meshed-Ω discovery | **Verified** |
| Multi-entrypoint critter dispatch | `cosmos/anima/src/script.rs:52-54` | not wire (comment) | keep-reserved | richer critters | **Verified** |
| Per-engine tuning knob (critter) | `cosmos/anima/src/script.rs:56-62, 64-72` | not wire (comment) | keep-reserved | operator tuning | **Verified** |
| `CreatureId`→Abode-pubkey router map | `cosmos/aether/src/lib.rs:599-607` | not wire (stub verifier) | realize-v0.5.0 | cross-node membership | **Verified** |
| `OfferUpdate` schema | `cosmos/creatures/embodiment-advertiser/src/lib.rs:15-16` | additive (new schema) | realize-v0.5.0 | dynamic embodiment | **Verified** |
| Advisory `deadline_ms` (placement Query) | `cosmos/creatures/embodiment-advertiser/src/lib.rs:21-22` | additive optional | keep-reserved | deadline-aware advertiser | **Verified** |
| Bestiary `ReputationDelta` contract-crate hoist | `cosmos/creatures/bestiary-daemon/src/lib.rs:28-33` | not wire (refactor) | keep-reserved | direct `Consensus` ingest | **Verified** |
| ADR-0038 sketch cites `cosmos/seer/src/topics/` | (no such dir) | n/a | path-correction → `cosmos/seer/src/lib.rs:987` | — | **Verified** (drift) |

## Acceptance

- [ADR-0043](../adr/ADR-0043-reserved-seam-register.md) exists and lists every seam above with a
  disposition, a wire-lock note, and a named v0.5.0 consumer (or a recorded reason it stays
  consumerless). A grep/audit confirms no reserved trait, reserved `SeerTopic` variant, `deferred`/
  `reserved` doc-comment, or serde-elided forward-compat field is missing from the register.
- The one **realize-in-v0.4.3** seam (signed dialogue provenance) has landed its fields on the dialogue
  answer body (`cosmos/seer/src/lib.rs:1002-1006`) as `#[serde(default, skip_serializing_if = "Option::is_none")]`
  optionals, plus the verify/tamper test from [ADR-0038](../adr/ADR-0038-origin-stays-hop-by-hop.md) —
  proving content authenticity survives a relay that strips/changes transport origin.
- Every **keep-reserved** wire-locked name (`DeferredToV03`, the `omega.deferred`/`realm.no_route`
  schema strings, the closed `SeerTopic` set) is unchanged by the convergence pass; a tripwire or doc
  note records that these strings are frozen.
- A check confirms v0.5.0's stated headline shapes (closed `SeerTopic` incl. `Dialogue`, the dialogue
  body, cross-node/cross-Realm address routing) require **zero** new or changed wire — i.e. the
  composition claim holds.
