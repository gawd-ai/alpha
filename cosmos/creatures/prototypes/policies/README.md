# policies — injected decision gates (NOT substrate)

Reference creatures for GAWD's injected **gate** sockets. They share the `policy-*` name because they
all encode an operator's *decision*, but they fill several distinct sockets — the table says which.
Each is the minimal readable reference; real deployments ship their own (`my-org-*`).

| Crate | Socket | Decides |
|---|---|---|
| `policy-dev` | admission `Policy` | admit everything (permissive dev policy) |
| `policy-signed` | admission `Policy` | admit only an Abode-signed manifest with a matching artifact hash |
| `policy-budget` | budget policy (PROPRIOCEPTION → `BudgetSignal`) | `BudgetApoptosis` (Hard→Unload) and `BudgetGraceful` (Warn→one-shot ExtendBudget) |
| `policy-prefer-promoted` | admission `Policy` | admit only a creature with a verified at-threshold fitness promotion (selection-as-policy, T7) |
| `policy-quarantine-aware` | admission `Policy` | reject a quarantined creature *before* the promotion gate — defense overrides selection |
| `policy-abode-allowlist` | `RestorePolicy` (abode-migrator) | admit an incoming Abode snapshot only when its `abode_key` is allow-listed |
| `policy-quarantine-trust-all` | `QuarantineTrust` (immune-response) | honor *every* inbound quarantine notice — reference only, never production |
| `policy-quarantine-trust-realm` | `QuarantineTrust` (immune-response) | honor a notice only from a peer in the per-Realm trusted set (the realistic reference) |

The substrate ships none of these decisions — it ships the sockets. See each crate's `lib.rs` header
and [`CONTRIBUTING.md`](../../../../CONTRIBUTING.md).
