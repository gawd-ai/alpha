# Release Checklist

Alpha releases are **source-first**: the `alpha` front door, engines, prototypes, and shipped
creatures are all built from the source tree. Nothing is published to a package registry — the
workspace is source-only (every member inherits `publish = false`), and on Alpha the distributable
unit is the creature, not a crate.

The public contract starts at the published release tag; pre-tag internal history carries no
backward-compatibility guarantee. Set `VERSION` once and reuse it throughout this checklist:

```sh
VERSION=vX.Y.Z   # the release being cut, e.g. v0.4.1
```

## Preflight

- Confirm the workspace version (`Cargo.toml` `[workspace.package] version`) equals `${VERSION#v}`.
- Set the `CHANGELOG.md` `## ${VERSION#v} - unreleased` heading's date to the publication date and
  confirm it matches the tag/release date.
- Confirm `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, and the
  design-note index agree on the release line and feature posture.
- Confirm local Markdown links resolve.
- Confirm the workspace stays source-only: no member is crates.io-publishable
  (every crate sets `publish.workspace = true`, inheriting `publish = false`).

## Gates

Run the release gates with courteous local defaults so contributor machines stay
responsive:

```sh
cargo fmt --all --check
git diff --check
CARGO_BUILD_JOBS=2 cargo clippy --locked --workspace --all-targets -- -D warnings
CARGO_BUILD_JOBS=2 cargo build --locked --workspace
CARGO_BUILD_JOBS=2 cargo test --locked --workspace -- --test-threads=1
RUSTDOCFLAGS='-D warnings' CARGO_BUILD_JOBS=2 cargo doc --locked --workspace --no-deps
cargo deny check
CARGO_BUILD_JOBS=2 cargo run --locked -p walkthrough
CARGO_BUILD_JOBS=2 cargo run --locked -p federation
```

The opt-in model-backed author (`agent-mind`) lives behind `--features openai` (it links `ureq`), so
the default gates above never exercise it. Run its feature gates too, and let `cargo deny` see the
network dependency tree (the allow-list is maintained unconditionally — `cargo deny` runs
`--all-features`, so it covers the `openai` tree regardless of release scope):

```sh
CARGO_BUILD_JOBS=2 cargo clippy --locked -p agent-mind --all-targets --features openai -- -D warnings
CARGO_BUILD_JOBS=2 cargo clippy --locked -p alpha --features openai -- -D warnings
CARGO_BUILD_JOBS=2 cargo test --locked -p agent-mind --features openai
cargo deny --all-features check
```

## Tagging

Do not call a tree released until the committed release tree is tagged.

```sh
git status --short
git ls-remote --tags origin "$VERSION"
git tag --points-at HEAD | grep "^${VERSION}$"
```

If `$VERSION` exists only as a stale local draft tag and no remote `$VERSION` exists, recreate it
after the release commit:

```sh
git tag -d "$VERSION"
git tag -a "$VERSION" -m "$VERSION"
```

Avoid pushing a truncated shorthand (e.g. `v0.4`) unless the release plan explicitly wants an alias;
delete any local shorthand after confirming no remote alias is intended.

Push only after the gates are green and the tag points at the intended commit:

```sh
git push origin HEAD
git push origin "$VERSION"
```
