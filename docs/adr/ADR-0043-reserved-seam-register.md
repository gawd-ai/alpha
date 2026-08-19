# ADR-0043 — Reserved-seam disposition register

- **Status:** Accepted (v0.4.3) — this ADR *is* the deliverable (a disposition register, no code); its
  one "realize-in-v0.4.3" seam, signed dialogue provenance, landed via [ADR-0038](ADR-0038-origin-stays-hop-by-hop.md).
- **Drives:** [TRD-004](../trd/TRD-004-reserved-seam-discipline.md) R2–R6
- **Date:** 2026-06-16
- **Milestone successor:** [ADR-0049](ADR-0049-stage-v0.5-composition-and-mesh-autonomy.md)
  supersedes this register's historical `realize-v0.5.0` schedule; the seam inventory remains intact.

## Context

Alpha grows by **reserving shape now and binding a consumer later**: an embryo trait, a reserved
`SeerTopic` variant, an additive serde-elided field, or a `deferred`-marked plan in a doc-comment. This
is deliberate — it lets the v0.5.0 headline (LLM-backed agents conversing across the meshed Ω) land as
*composition* (swap reference creatures for real ones) rather than as a wire change. But the guarantee
only holds if every reserved seam is **inventoried and classified before v0.5.0**: which are frozen and
merely documented, which Alpha realizes this cycle, and which wait for their v0.5.0 consumer — and, for
each, whether the seam is a frozen wire name or an additive optional.

This ADR **is** that register. It is a pure decision/record: most rows change no code (they confirm a
seam stays reserved and frozen); the one row marked *realize-in-v0.4.3* points at its work. Every seam
below was verified against the code at the cited `file:line`.

## Decision

Adopt the register in the table below as the binding inventory. Each reserved seam is classified:

- **keep-reserved** — the shape is shipped and correct; bind nothing this cycle, do not churn it. For a
  **WIRE-LOCKED** name this also means *frozen*: the string must not be renamed.
- **realize-in-v0.4.3** — Alpha lands the seam this convergence cycle (fields + a test).
- **realize-in-v0.5.0** — the consumer arrives with v0.5.0; the shape stays frozen until then.

Wire-lock classes used in the table:

- **WIRE-LOCKED** — a serialized/signed name a deployed peer parses; renaming breaks the wire.
- **additive-optional** — a serde-elided optional / `#[serde(default)]` field; its absence is
  wire-identical to today, so adding it is zero-retrofit.
- **not-wire** — a trait, a closed-enum variant, a stub-only internal, or a `deferred` doc-comment; no
  serialized bytes change when it is realized.

### The register

| # | Reserved seam | file:line | Wire-lock | Disposition | v0.5.0 consumer | Note |
|---|---|---|---|---|---|---|
| 1 | `OmegaServices` embryo trait (`realms`, `admits`) | `cosmos/omega-contract/src/lib.rs:118-127` | not-wire (trait) | **realize-v0.5.0** | `omega-federator` as the Ω authority | Object-safe; no consumer pins it by design (`lib.rs:114-117`). Signatures may be *refined* before first impl; convergence does not implement it. |
| 2 | `OmegaDeferredReason::DeferredToV03` | `cosmos/omega-contract/src/lib.rs:83-86` (str `:102`) | **WIRE-LOCKED** | **keep-reserved** | none — `omega-gateway` stub emits it forever (`gateways/omega-gateway/src/lib.rs:75-77`) | A LOCKED v0.2 commitment: the variant *name* is on the wire (`omega.deferred` schema) and cannot change without breaking a parser. **Frozen.** |
| 3 | `OmegaDeferredReply::details` | `cosmos/omega-contract/src/lib.rs:96-97` | additive-optional | **keep-reserved** | a richer federator's reply prose | `#[serde(default, skip_serializing_if = "Option::is_none")]`; absent == today. |
| 4 | `Realm` authority newtype | `cosmos/realm/src/lib.rs:46-67` | additive (newtype) | **realize-v0.5.0** | per-Realm membership / peering / per-Sanctum work | Carries identity only today; a thin newtype so fields land forward-compatibly (`lib.rs:48-51`). Grain rule: Realm deals with Sanctums; Ω deals with Realms. |
| 5 | SEER `Policy` topic | `cosmos/seer/src/lib.rs:107-109` | not-wire (closed enum) | **keep-reserved** (live ref) | richer admission agent | Reference consumer ships: `prototypes/responders/responder-policy`. Generic SEER envelope already carries it; a richer body composes without wire change. |
| 6 | SEER `Budget` topic | `cosmos/seer/src/lib.rs:110-112` | not-wire | **keep-reserved** (live ref) | budget-negotiating agent | Ref: `responders/responder-budget`. Live budget path uses proprioception + `KernelControl::ExtendBudget`; the topic is the richer seam. |
| 7 | SEER `Fitness` topic | `cosmos/seer/src/lib.rs:113-115` | not-wire | **keep-reserved** (live ref) | LLM rater | Ref: `responders/responder-fitness`. Local selector uses an injected scorer + registry promotion today. |
| 8 | SEER `Curation` topic | `cosmos/seer/src/lib.rs:120-125` | not-wire | **keep-reserved** (live ref) | external LLM curator creature | Ref: `responders/responder-curation`. `bestiary::AICurator` curates in-process; this topic is the off-path *external* consult. |
| 9 | `AbodeSnapshot::realm` | `cosmos/abode/src/lib.rs:129-133` | additive-optional | **keep-reserved** | Realm-aware restore policy | `#[serde(default, skip_serializing_if = "Option::is_none")]`; lets a receiver refuse un-peered Realms before hash/sig work. |
| 10 | `Embodiment::sensors` | `cosmos/seer/src/lib.rs:570-573` | additive (`#[serde(default)]`) | **keep-reserved** | a sensor `Predicate` kind | Shipped but "not matched by any current `Predicate` kind yet" (`lib.rs:570-571`). |
| 11 | **Signed dialogue provenance** | `cosmos/seer/src/lib.rs:987-1007` (the dialogue `AnswerBody`, `:1002-1006`) | additive-optional | **realize-v0.4.3** | LLM-backed dialogue agent (signs for real) | New per [ADR-0038](ADR-0038-origin-stays-hop-by-hop.md): optional `signer_pubkey` + `signature` over `(corr, prompt-or-turn, reply)`. v0.4.3 lands the *fields* + one verify/tamper test; signing the reference echo agent is optional. |
| 12 | UDP/mDNS discovery beacon | `cosmos/creatures/transport-tcp/src/lib.rs:36` | not-wire (handshake unchanged) | **realize-v0.5.0** | meshed-Ω discovery | "Signed membership + a UDP/mDNS discovery beacon are the named next steps." TCP handshake stays as-is. |
| 13 | Multi-entrypoint critter dispatch | `cosmos/anima/src/script.rs:52-54` | not-wire | **keep-reserved** | richer critters | Kernel drives `fn handle(env)` only; multi-entrypoint deferred. ABI tag `gawd_critter_v1` unchanged. |
| 14 | Per-engine tuning knob (critter) | `cosmos/anima/src/script.rs:60-76` | not-wire | **keep-reserved** | operator tuning | `cpu_ms` / `mem_bytes` / `wall_ms` are per-creature dials today; the operation-rate/default-structure per-engine knob is deferred. |
| 15 | `CreatureId`→Abode-pubkey router map | `cosmos/aether/src/lib.rs:599-607` | not-wire (stub verifier returns `""`) | **realize-v0.5.0** | cross-node membership | Router-side verify-on-route is present-but-stub; teaching the router to resolve each `CreatureId`→pubkey is "deferred to the cross-node membership work." Load-bearing trust gates (transport handshake, admission) are real. |
| 16 | `OfferUpdate` schema | `cosmos/creatures/embodiment-advertiser/src/lib.rs:15-16` | additive (new schema) | **realize-v0.5.0** | dynamic embodiment advertisement | Offers are operator-supplied at construction today; a runtime-update schema is deferred. New schema = additive, never a retrofit. |
| 17 | Advisory `deadline_ms` (placement Query) | `cosmos/creatures/embodiment-advertiser/src/lib.rs:21-22` | additive-optional | **keep-reserved** | a deadline-aware advertiser | "Currently unused; reserved" — time is injected policy, not fabric. |
| 18 | Bestiary `ReputationDelta` contract-crate hoist | `cosmos/creatures/bestiary-daemon/src/lib.rs:28-33` | not-wire (refactor) | **keep-reserved** | direct SEER-`Consensus` ingest | Cross-node reputation federates over PUSH's verified-greater merge; hoisting the body to a contract crate is deferred (same family as the deferred policy generalization). |

### Path correction (recorded so it isn't re-litigated)

[ADR-0038](ADR-0038-origin-stays-hop-by-hop.md)'s implementation sketch cites `cosmos/seer/src/topics/`
for the dialogue body. **No such directory exists.** The dialogue body lives in the `dialogue` module of
`cosmos/seer/src/lib.rs:987-1007`; the signed-provenance fields (row 11) attach to its `AnswerBody`
(`lib.rs:1002-1006`, which contained only `reply: String` when this decision was written). The
realize-in-v0.4.3 work targeted that file and added the provenance fields recorded above.

### v0.4.4 erratum and successor

This register described itself as exhaustive, but missed a distinct reserved seam already documented
in `sigil::Entrypoint`: its `signature` was free-form text with “a structured schema later.” Row 13
tracks **direct multi-entrypoint critter engine dispatch**, which is not the same decision. The former
is signed Manifest metadata and an application adapter; the latter would change how the Rhai engine
calls exported functions.

[ADR-0046](ADR-0046-functions-are-typed-creature-entrypoints.md) is the successor record. v0.4.4
realizes the omitted metadata seam with an optional structured `gawdfn::EntrypointContractV1` and
dispatches it through the existing `Creature::handle(Envelope)` ABI. Row 13 remains **keep-reserved**:
the Kernel still drives `fn handle(env)` and `gawd_critter_v1` is unchanged. Recording the erratum here
preserves this ADR as the historical v0.4.3 inventory instead of silently rewriting its table.

### v0.5 milestone successor

[ADR-0049](ADR-0049-stage-v0.5-composition-and-mesh-autonomy.md) is authoritative for the forward
schedule. It moves rows 1, 4, 12, and 15—operational Omega/Realm authority, signed discovery, and the
authenticated node/routing/Abode identity map—to **v0.5.1**; row 16 (`OfferUpdate` and dynamic
capability/placement advertisement) to **v0.5.2**; and a UDP transport for arbitrary application
envelopes to **later/uncommitted**. Discovery may use datagrams in v0.5.1 without promising UDP
application carriage. These are successor targets, not implementation claims. The table above remains
the historical v0.4.3 decision, and its `keep-reserved` dispositions do not change.

## Consequences

- v0.5.0's headline becomes provably *composition*: every shape it needs is either keep-reserved-and-
  frozen or realized in v0.4.3, so swapping reference agents for LLM-backed ones touches no wire.
- The wire-locked names (`DeferredToV03`, the `omega.deferred` / `realm.no_route` schema strings, the
  closed `SeerTopic` set) are explicitly **frozen** — convergence cleanup cannot rename them.
- Embryos (`OmegaServices`, `Realm` authority, the router pubkey map, `OfferUpdate`) stay unbound and
  documented here under the historical v0.5.0 label; ADR-0049 supersedes that schedule with v0.5.1/
  v0.5.2 targets. This pass confirms they remain empty rather than half-implementing them.
- One concrete unit of v0.4.3 work falls out: land the signed-dialogue-provenance fields + verify test
  (row 11), per [ADR-0038](ADR-0038-origin-stays-hop-by-hop.md).

## Implementation sketch

- **Files:** This ADR is mostly record-only — rows 1–10 and 12–18 confirm a seam stays reserved and add
  no code. The single code-touching row is **row 11**: add optional `signer_pubkey: Option<String>` +
  `signature: Option<String>` (both `#[serde(default, skip_serializing_if = "Option::is_none")]`) to the
  dialogue `AnswerBody` at `cosmos/seer/src/lib.rs:1002-1006`, with a `sign`/`verify` helper over
  `(corr, prompt-or-turn, reply)`. Optionally sign in `prototypes/dialogue/dialogue-responder` and
  verify-on-relay in `dialogue-initiator`.
- **Wire-additivity:** **Additive only — the whole point is zero wire churn.** Every realized seam in
  this register is either additive (a new serde-elided optional, e.g. rows 9/11; or a new schema, row
  16) or not-wire (rows 1, 4, 12–15, 18). No serialized/signed name is renamed; the wire-locked rows
  (notably row 2, `DeferredToV03`) are frozen, not modified. Absent optional fields serialize
  byte-identically to today.
- **Test:** for row 11, a unit/integration test that a dialogue answer carrying a valid body signature
  verifies and a tampered `reply` fails — proving content authenticity survives a relay that strips or
  changes transport `Origin`. For the keep-reserved rows, the acceptance is an audit/grep (TRD-004
  acceptance) that no reserved seam is missing from this table and no wire-locked name drifted.

## Related

[ADR-0038](ADR-0038-origin-stays-hop-by-hop.md) (specifies the signed-dialogue-provenance shape this
register schedules as realize-in-v0.4.3); [TRD-004](../trd/TRD-004-reserved-seam-discipline.md) (the
anti-churn requirement this register satisfies); [TRD-001](../trd/TRD-001-substrate-resource-safety.md)
and [ADR-0042](ADR-0042-escape-hatch-policy.md) (the `0 = unbounded` opt-out is itself a documented
reserved posture, governed there rather than re-listed here); and
[ADR-0049](ADR-0049-stage-v0.5-composition-and-mesh-autonomy.md) (the authoritative forward milestone
schedule for this historical register).
