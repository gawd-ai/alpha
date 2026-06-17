# ADR-0045 — Demo-registry coherence (the `cluster` demo)

- **Status:** Implemented (v0.4.3)
- **Drives:** [TRD-003](../trd/TRD-003-app-surface-coherence.md) R4, R7
- **Date:** 2026-06-16

## Context

`alpha demo list` prints only the entries in `demos/demos.json` (`alpha/src/demo.rs:111-122`) — five
runner-managed, single-process demos: walkthrough, federation, distribute, bestiary-live, dialogue. The
`cluster` demo is different: it is a multi-process runbook (`demos/cluster/*.sh` + `README.md`) that
stands up `omega serve` + two `alpha node`s on one mesh; it cannot be a single in-process spawn. It is
**not** in `demos.json`, so `alpha demo list` never shows it and `alpha demo run cluster` fails with
"unknown demo" — yet `demos/README.md` lists `cluster` in the *same table* as the managed demos (6 rows),
and `CHANGELOG.md` references it. The surfaces disagree about whether `cluster` exists.

This is a small fork, but a real one: either teach the registry about manual runbooks, or keep the
registry launch-only and make the docs/`list` honest about the asymmetry.

## Decision

**Teach `demos.json` (and `alpha demo`) about a manual runbook entry**, so `alpha demo list` is the single
source of truth:

1. Add `cluster` to `demos/demos.json` with a marker (e.g. `"manual": true` + a `"runbook"` path) that
   means *"listed, but not runner-launchable."*
2. `alpha demo list` shows it, tagged `(manual runbook)`.
3. `alpha demo run cluster` does **not** error — it prints the runbook pointer (`cd demos/cluster &&
   ./00-build.sh …`) and exits cleanly.
4. `demos/README.md`'s table and `alpha demo list` now agree (6 entries; one tagged manual).

Rationale: the alternative (keep the JSON launch-only, fix only the README) leaves `alpha demo run
cluster` failing with a bare "unknown demo" — a sharp edge for exactly the operator following the docs.
Making the registry the one place that knows every demo (and how each is run) is the coherent fix and
keeps the "one surface, no surprises" bar of TRD-003.

## Consequences

- `alpha demo list` becomes authoritative; docs can point at it without divergence.
- A tiny schema addition to `demos.json` (one optional field) and a branch in the runner.
- Future manual/multi-process demos use the same marker instead of silently dropping out of `list`.

## Implementation sketch

- **Files:** `demos/demos.json` (the `cluster` entry + `manual`/`runbook` field); `alpha/src/demo.rs`
  (list rendering tag + the `run` branch that prints the runbook instead of erroring); `demos/README.md`
  (note the tag). No change to the five managed demos.
- **Wire-additivity:** **None** — `demos.json` is a local launch manifest, not a network/signed wire; the
  new field is optional and additive.
- **Test:** an `alpha` test asserting `demo list` includes `cluster` tagged manual, and `demo run cluster`
  exits 0 with the runbook pointer (not "unknown demo").

## Related

TRD-003 (app-surface coherence); `demos/README.md`; `alpha/src/demo.rs`.
