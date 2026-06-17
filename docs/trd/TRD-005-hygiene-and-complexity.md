# TRD-005 — Hygiene & complexity reduction

- **Status:** Met (v0.4.3)
- **Theme:** Hygiene
- **Spawns:** [ADR-0044](../adr/ADR-0044-omni-control-plane-dry.md) (shared `omni` control-plane boot)
- **References:** [ADR-0042](../adr/ADR-0042-escape-hatch-policy.md) (`with_max_*(0)` escape-hatch policy)
- **Invariant in play:** *the codebase makes sense* — no needless duplication, no rename residue, no
  undocumented load-bearing convention, and a fmt gate that is actually reliable.

## Scope

The convergence bar says "remove needless complexity … so that the system makes sense." This TRD
collects the documented hygiene residuals scattered across the tree and forces a disposition on each:
**CLOSE in v0.4.3** (do the work) or **DEFER** (record the rationale so it isn't re-litigated). Nothing
here changes runtime behavior or the signed/serialized wire; every requirement is composition,
documentation, formatting, or a clearly-scoped polish deferral. Each requirement cites the `file:line`
it ranges over.

## Requirements

- **R1 — De-duplicate the control-plane boot across both poles (CLOSE).** `alpha` and `omega`
  independently re-implement the node-identity + cluster-transport + HTTP/WS control-plane composition.
  The duplication is flagged in-code at `omega/src/serve.rs:431` ("*shared promotion into `omni` is a
  deferred DRY follow-up*"). Verified duplicated pairs: `NodeKeyBoot` struct (`alpha/src/node.rs:532` ≡
  `omega/src/serve.rs:432`), `derive_node_key` (`alpha/src/node.rs:540` ≡ `omega/src/serve.rs:439`),
  `boot_cluster` (`alpha/src/node.rs:561` ≡ `omega/src/serve.rs:459`), `boot_http_surface`
  (`alpha/src/node.rs:499` ≡ `omega/src/serve.rs:500`), plus the API-key resolution + control-plane
  composition block (`alpha/src/node.rs:255-303` ≈ `omega/src/serve.rs:243-285`). `boot_control` is
  *already* shared (`cosmos/omni/src/lib.rs:2176`) and called from both poles — proving the seam works.
  v0.4.3 MUST hoist the remaining helpers into `cosmos/omni` and call them from both poles. See ADR-0044.
- **R2 — Unbounded opt-outs follow one policy (CLOSE via ADR-0042; no re-decision here).** The
  `with_max_*(0) = unbounded` family is already decided in [ADR-0042](../adr/ADR-0042-escape-hatch-policy.md)
  (keep the opt-out; unify the doc phrasing; finite defaults; one CONTRIBUTING/substrate subsection).
  TRD-005 only **references** that decision — it does not re-open it. Acceptance is shared with TRD-001 R6.
- **R3 — Document the field-order signing invariant in `CONTRIBUTING.md` (CLOSE).** Struct field
  *declaration order* is part of the signed wire for the manifest signing payload
  (`cosmos/sigil/src/lib.rs:946`, `signing_payload_hash_is_locked_to_a_known_fixture`) and the abode
  snapshot (`cosmos/abode/src/lib.rs:451`, same-named tripwire; struct-doc warning at
  `cosmos/abode/src/lib.rs:101-106`). A sibling identity-payload tripwire also exists
  (`cosmos/sigil/src/lib.rs:878`). The tripwires exist and are verified; what is missing is an
  author-facing statement of the rule. v0.4.3 MUST add a short subsection to `CONTRIBUTING.md`
  ("Conventions", `CONTRIBUTING.md:230`): *appending fields at the end is forward-compatible; reordering
  or renaming an existing field of a signed struct invalidates every signature in flight and will fire
  the tripwire — change the fixture deliberately, never to silence the test.*
- **R4 — `cargo fmt` is a reliable gate under the pinned toolchain (CLOSE).** A known, pre-existing
  large fmt diff (~118 files) appears whenever `cargo fmt` runs with a rustfmt other than the pinned
  one. The toolchain is pinned at `rust-toolchain.toml` (`channel = "stable"`, `components = ["rustfmt",
  "clippy"]`). v0.4.3 MUST land **one clean `cargo fmt` run under the pinned toolchain** as an isolated
  formatting-only commit, so `cargo fmt --check` is afterward a trustworthy CI gate with no standing
  diff. (Cannot be run in this design pass — this requirement specifies the action and the toolchain
  source; the `/goal` pass executes it.)
- **R5a — Sweep `module`→`creature` prose in comments (CLOSE).** After the module→creature rename,
  scattered `.rs` comments still say "module". A scan finds **94** comment lines containing the word
  `module` across `cosmos/ alpha/ omega/`; the majority are *legitimate* Rust-language uses ("a wasm
  module", "this module's docs", "module constant", "a leaf crate, not a module" —
  e.g. `cosmos/anima/src/script.rs:104`, `cosmos/abode/src/lib.rs:105`, `cosmos/mind/src/lib.rs:8`) and
  MUST be left alone. The rename residue is the subset where "module" names a *creature* (e.g.
  `cosmos/sanctum/tests/budget_extend_honored.rs:77` "naming `module`"; the `Fitness { module, ok }` /
  `Observe { module, … }` prose in `cosmos/creatures/prototypes/scorers/scorer-latency/src/lib.rs:7-8`;
  the immune-response op prose `cosmos/creatures/immune-response/src/lib.rs:196-203`). v0.4.3 SHOULD
  rewrite only that subset to "creature"; the language-sense uses are out of scope.
- **R5b — Bare `module` wire field: freeze or rename-additive (DEFER, frozen wire name).** The
  module→creature rename deliberately did **not** touch a bare serialized field named `module`. Audit:
  the shipped sense structs were already migrated to `creature` (`Proprioception.creature`
  `cosmos/sanctum/src/lib.rs:101`, `Fitness.creature` `:108`, `BudgetSignalEvent.creature` `:125`,
  `BudgetRequest.creature` `:142`). The *only* residual bare wire field is in
  `KernelControl::{Unload, ExtendBudget}` (`cosmos/sanctum/src/lib.rs:242,253`), an
  `#[serde(tag = "op")]` enum whose `module` field is the serialized JSON key — confirmed live by the
  parse test `{"op":"Unload","module":7}` (`cosmos/sanctum/src/lib.rs:1485`) and the policy assertion
  `v.get("module")` (`cosmos/creatures/prototypes/policies/policy-budget/src/lib.rs:1047`). Renaming the
  key is a **wire change** and would break in-flight `KernelControl` envelopes — it violates the
  zero-retrofit / additive-only invariant. v0.4.3 MUST therefore **document `module` as a frozen wire
  name** at its definition (one doc-line on `KernelControl`) rather than rename it. (`Address::Kernel`
  is refused at the cross-node boundary per TRD-001 R5, so this key is local-bus-only and the freeze
  costs nothing.) A future additive rename is possible only as a *new* field with a deprecation window;
  not worth it for a local-only key.
- **R6 — `#[allow(dead_code)]` audit: clean bill (CLOSE — confirmed, no change).** A grep finds **6**
  occurrences across `cosmos/ alpha/ omega/`, each justified: one forward-compat destructor-only struct
  (`cosmos/anima/src/native.rs:126` — `lib`/`_tempfile` exist for `Drop`, not reads; documented at
  `:121-125`), one forward-compat parsed-for-completeness field
  (`cosmos/creatures/immune-response/src/lib.rs:155`), and four in tests
  (`cosmos/sanctum/tests/distributor_cross_node.rs:152`,
  `cosmos/sanctum/tests/m4_capability_sandbox.rs:156`,
  `cosmos/sanctum/tests/distributor_local.rs:102,404`). No production allow is unjustified; **none to
  remove.** This requirement is met by the audit itself; v0.4.3 keeps them as-is.
- **R7 — hex / byte-helper dedup: already consolidated (CLOSE — confirmed, no change).** The earlier
  handoff named "hex/op_bytes dedup." Verified: there is exactly **one** hex helper pair —
  `crypto::hex_encode` / `crypto::hex_decode` (`cosmos/sigil/src/crypto.rs:20,32`) — and every call site
  routes through it (`crypto::hex_*`). There is **no** duplicate hex implementation to consolidate.
  "`op_bytes`" is not a byte-encoding helper at all: it is the registry/bestiary *config cap* field
  `max_op_bytes` (`cosmos/creatures/registry-mem/src/lib.rs:208`,
  `cosmos/creatures/bestiary-daemon/src/lib.rs:132`) — a different concern, already singular per crate.
  This item is **closed as already-done**; no work in v0.4.3.
- **R8 — `Address` enum `Box` micro-optimization (DEFER post-0.5.0).** `Address::Realm` and
  `Address::Omega` each box their inner target (`cosmos/aether/src/address.rs:180,185` —
  `target: Box<Address>`). The `Box` is **required** for the recursive type (composition-by-depth: a
  Realm/Omega envelope wraps any inner `Address`); it cannot simply be removed. The only available move
  is a `Box`→`Arc` swap (cheaper clones for the common shallow case) or an enum-size tightening — pure
  **polish**, not a correctness or safety issue, and it would touch a load-bearing wire type
  (`Address` serde is shipped). v0.4.3 **DEFERS** this to post-0.5.0, recorded here so it isn't lost:
  revisit only if profiling shows `Address` clone/size on a hot path, and only as a wire-neutral change
  (serde representation of `Box<T>` and `Arc<T>` are identical, so the swap is wire-safe if taken).

## Findings register

| Finding | Status | Evidence |
|---|---|---|
| Control-plane boot duplicated in both poles | **Verified** | `omega/src/serve.rs:431` comment; helper pairs `alpha/src/node.rs:499,532,540,561` ≡ `omega/src/serve.rs:432,439,459,500` |
| `boot_control` already shared in `omni` (seam proven) | **Verified** | `cosmos/omni/src/lib.rs:2176`; called `alpha/src/node.rs:283`, `omega/src/serve.rs:266` |
| Signing field-order is load-bearing; tripwires exist | **Verified** | `cosmos/sigil/src/lib.rs:946,878`; `cosmos/abode/src/lib.rs:451`, doc `:101-106` |
| Field-order invariant not stated for authors | **Verified** | absent from `CONTRIBUTING.md` Conventions `:230` |
| rustfmt-version skew (~118-file diff); toolchain pinned | **Verified** (skew known) / **Needs-verify** (exact file count under pinned fmt — run in `/goal`) | `rust-toolchain.toml` |
| `module` prose residue in comments | **Verified** | 94 comment hits; rename-residue subset cited in R5a |
| Bare `module` wire field is local-bus `KernelControl` only | **Verified** | `cosmos/sanctum/src/lib.rs:242,253`; key proven `:1485`, `policy-budget/src/lib.rs:1047` |
| Shipped sense structs already use `creature` | **Verified** | `cosmos/sanctum/src/lib.rs:101,108,125,142` |
| `#[allow(dead_code)]` all justified (6 total, 1 prod, 1 fwd-compat, 4 tests) | **Verified** | citations in R6 |
| "hex/op_bytes dedup" still open | **Down-ranked** → already done | single helper `cosmos/sigil/src/crypto.rs:20,32`; `op_bytes` is a cap field, not a helper |
| `Address` `Box` is a correctness bug | **Down-ranked** → polish only | `Box` required for the recursive type `cosmos/aether/src/address.rs:180,185` |

## Acceptance

- **R1:** both `alpha node --listen` and `omega serve --listen` still boot their control plane (ControlCore
  on `Role::CONTROL` + `surface-http`) from the shared `omni` helper; no behavior change (see ADR-0044's
  test note). The `omega/src/serve.rs:431` deferral comment is gone.
- **R2:** met jointly with TRD-001 R6 — a grep/doc check shows every `with_max_*(0)` knob shares the
  ADR-0042 canonical phrasing.
- **R3:** `CONTRIBUTING.md` carries the field-order-of-signed-structs invariant; both tripwire tests
  (`cosmos/sigil`, `cosmos/abode`) still pass and are named in the text.
- **R4:** `cargo fmt --check` passes with no diff under the pinned toolchain (the standing ~118-file diff
  is gone), making fmt a green CI gate.
- **R5a:** a grep for "module" in `cosmos/ alpha/ omega/` comments returns only language-sense uses; the
  creature-naming residue is rewritten.
- **R5b:** `KernelControl`'s `module` field carries a one-line "frozen wire name" doc; no rename, no wire
  change.
- **R6 / R7:** no diff — the audit (this TRD) is the deliverable; both are recorded as already-clean.
- **R8:** deferred; the rationale above is the record. No v0.4.3 change.
