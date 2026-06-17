# ADR-0044 — `omni` shared control-plane composition

- **Status:** Implemented (v0.4.3) — see the implementation note below: `boot_http_surface` was hoisted
  via a surface-factory closure (not wholesale) because `surface-http` depends on `omni` (a wholesale
  move would cycle); the API-key resolution + banners stay pole-side for the same reason.
- **Drives:** [TRD-005](../trd/TRD-005-hygiene-and-complexity.md) R1
- **Date:** 2026-06-16

## Context

Alpha has two composition-root poles: the α front door (`alpha`) and the Ω gateway (`omega`). Both boot
the *same* node skeleton — derive the node's ed25519 identity, optionally bring up the gossip transport,
bind the `ControlCore` translator on `Role::CONTROL`, and load the `surface-http` creature for the
HTTP/WS control plane. Only one of those steps is shared today: `boot_control` already lives in
`cosmos/omni` (`cosmos/omni/src/lib.rs:2176`) and is called from both poles
(`alpha/src/node.rs:283`, `omega/src/serve.rs:266`), which proves the seam works. The rest is copied,
and the copy is flagged in-code at `omega/src/serve.rs:431`:
"*Copied from `alpha::node`; shared promotion into `omni` is a deferred DRY follow-up.*"

Verified duplication (`alpha` original ≡ `omega` copy):

- `NodeKeyBoot` struct — `alpha/src/node.rs:532` ≡ `omega/src/serve.rs:432`.
- `derive_node_key(cluster_key)` — `alpha/src/node.rs:540` ≡ `omega/src/serve.rs:439`.
- `boot_cluster(kernel, node_id, listen, seeds, key)` — `alpha/src/node.rs:561` ≡ `omega/src/serve.rs:459`.
- `boot_http_surface(kernel, listen, api_key)` — `alpha/src/node.rs:499` ≡ `omega/src/serve.rs:500`.
- The control-plane composition block itself — API-key resolution
  (`opts.api_key` → `SANCTUM_API_KEY` → `surface_http::generate_api_key`) followed by `boot_control` +
  `boot_http_surface` + the boot banner — `alpha/src/node.rs:255-303` ≈ `omega/src/serve.rs:243-285`.

The copies have already drifted in cosmetics (banner text, error-message prefixes, `note!` vs
`println!`) while the load-bearing logic — seed parsing, transport config, the dedicated drain-less
sense endpoint subscribed to PROPRIOCEPTION/FITNESS/`seer` — is identical and must stay identical. Two
copies of identity-and-transport boot is exactly the kind of needless complexity the convergence pass
exists to remove: a future fix (or a security change to how a node mints its key) would have to be made
twice, and a missed second edit is a silent divergence between the two poles.

## Decision

Hoist the duplicated boot into `cosmos/omni` and have both poles call it — the same move already made
for `boot_control`.

1. Promote the shared helpers into `cosmos/omni` (alongside `boot_control` / `boot_manifest`):
   - `NodeKeyBoot` + `derive_node_key(cluster_key: Option<&str>)`.
   - `boot_cluster(kernel, node_id, listen, seeds, &NodeKeyBoot) -> Result<CreatureId, String>`.
   - `boot_http_surface(kernel: &Arc<Kernel>, listen, api_key) -> Result<CreatureId, String>` (it already
     subscribes the drain-less sense endpoint to the canonical topics — that wiring becomes single-source).
2. Provide one `omni` recipe that composes the control plane end-to-end given what differs between poles
   — a small parameter set, not a copy. The differing inputs are exactly: the `critter_builder`
   `Option<CreatureId>` (α passes one; Ω passes `None`), the `transport` `Option<CreatureId>` (α passes
   its optional cluster transport; Ω passes `Some(ids.transport)`), and the listen/key/`AiControl`
   already threaded in. The recipe resolves the API key (the `opts.api_key` → `SANCTUM_API_KEY` →
   generate ladder), calls `boot_control`, calls `boot_http_surface`, and returns the two
   `CreatureId`s + the resolved key so each pole prints its own banner in its own voice.
3. `alpha` and `omega` keep ownership of their **CLI/opts parsing and their banners** (the parts that are
   legitimately different); they delegate the **mechanism** to `omni`. This matches the existing
   division where `boot_control` is shared but each pole writes its own "control: …" line.
4. Delete the `omega/src/serve.rs:431` "deferred DRY follow-up" note — the deferral is now closed.

`omni` is the correct home: it is the spine-only control-plane crate both poles already depend on, and
it already exports `boot_control` / `boot_manifest` / `workspace_root` for exactly this composition role.

## Consequences

- One source of truth for node-identity + cluster-transport + control-plane boot. A future change (e.g.
  to key derivation, seed-string format, or the sense-topic subscription set) is made once and both poles
  inherit it — the silent-divergence risk is gone.
- The two poles shrink to opts-parsing + a single `omni` call + a banner; their intent reads at a glance.
- One new `omni` parameter struct (or a few function args) to express the per-pole differences; this is
  smaller than the duplicated bodies it replaces.
- No new dependency edge: `alpha` and `omega` already depend on `omni`.
- A modest visibility change: the helpers move from pole-private (`pub(crate)`) to `pub` in `omni` (as
  `boot_control` already is). They remain composition-root tools, not creature-facing API.

## Implementation sketch

- **Files:**
  - `cosmos/omni/src/lib.rs` — add `NodeKeyBoot`, `derive_node_key`, `boot_cluster`, `boot_http_surface`,
    and a `boot_control_plane`-style recipe; re-export beside `boot_control`.
  - `alpha/src/node.rs` — delete the local `NodeKeyBoot`/`derive_node_key`/`boot_cluster`/
    `boot_http_surface` (`:499-598`, `:532-555`) and the inline composition block (`:255-303`); call the
    `omni` helpers/recipe, keep the opts parsing + `note!` banner.
  - `omega/src/serve.rs` — same deletion (`:431-524`, `:243-285`) + delegate; keep the opts parsing +
    `println!` banner; remove the `:431` deferral comment.
  - `alpha/src/mcp.rs` — uses `NodeKeyBoot` (per `cosmos/.../node.rs:531` "Shared with the MCP-hub boot
    path"); re-point it at the `omni` type so there is one definition.
- **Wire-additivity:** **None** — this is pure composition-root refactor (function/struct relocation).
  No serialized or signed type changes: `Address`, `Manifest`, `KernelControl`, the AUTHORING/CONTROL
  envelope schemas, and the transport handshake are all untouched. The node still mints the same key the
  same way and still loads the same creatures onto the same roles.
- **Test:** both poles must still boot their control plane. Assert that after the shared recipe runs, a
  `ControlCore` is bound on `Role::CONTROL` and a `surface-http` creature is loaded, for **both** the α
  path and the Ω path (extend the existing surface/control boot coverage, or a focused `omni` test that
  drives the recipe against an in-process `Kernel` and checks the two returned `CreatureId`s + role
  binding). The pre-existing `alpha` HTTP-surface and `omega serve` integration coverage must stay green
  unchanged — the refactor is behavior-preserving by construction.

## Implementation note (as built)

The sketch's "hoist `boot_http_surface` wholesale into `omni`" hit a constraint it didn't anticipate:
`surface-http` already depends on `omni` (it speaks the control vocabulary), so `omni` naming
`SurfaceHttp` — or `surface_http::generate_api_key` for the full `boot_control_plane` recipe — would
form a dependency **cycle**. As built:

- `NodeKeyBoot`, `derive_node_key`, `boot_cluster` moved into `omni` wholesale (identical bodies, no
  cycle). Both poles **and** the MCP-hub `join_mesh` now call `omni::boot_cluster`.
- `omni::boot_http_surface` single-sources the must-stay-identical wiring — the synchronous listener
  bind and the exact sense-topic subscription set (PROPRIOCEPTION + FITNESS + `seer`) — and takes a
  **surface-factory closure** `FnOnce(TcpListener, InboxReceiver) -> Box<dyn Creature>`, so the caller
  (which legitimately depends on `surface-http`) constructs the surface. No cycle, and the load-bearing
  part is one source of truth.
- API-key resolution + the per-pole boot banner stay pole-side (the key ladder calls
  `surface_http::generate_api_key`), so the thin `boot_control_plane` mega-recipe from the sketch was
  not introduced; the poles keep their opts/key/banner and delegate the mechanism. This is the same
  division as the existing `boot_control`.

## Related

ADR-0042 (escape-hatch policy — sibling hygiene decision under TRD-005); TRD-005 R1 (the duplication
ledger this closes); the existing `boot_control` promotion in `cosmos/omni/src/lib.rs:2176`, which this
extends to the rest of the boot path.
