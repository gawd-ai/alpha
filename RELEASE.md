# Release Checklist

This repository's v0.4.0 release is source-first: the `alpha` front door, engines,
prototypes, and shipped creatures are all built from the source tree. Nothing is
published to a package registry — the workspace is source-only (every member inherits
`publish = false`), and on Alpha the distributable unit is the creature, not a crate.

This is the first public release. Pre-public internal history does not require
backward compatibility; the public contract starts at the published release tag.

## Preflight

- Before tagging, set the `CHANGELOG.md` `0.4.0` date to the publication date and confirm it
  matches the tag/release date.
- Confirm `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, and
  the design-note index agree on the release line and feature posture.
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

## Tagging

Do not call a tree released until the committed release tree is tagged.

```sh
git status --short
git ls-remote --tags origin v0.4.0
git tag --points-at HEAD | grep '^v0.4.0$'
git tag --list 'v0.4'
```

If `v0.4.0` exists only as a stale local draft tag and no remote `v0.4.0` exists, recreate
it after the release commit:

```sh
git tag -d v0.4.0
git tag -a v0.4.0 -m 'v0.4.0'
```

If a local `v0.4` tag exists, treat it as a stale shorthand unless the release plan explicitly wants
an alias. Do not push it accidentally; delete the local shorthand after confirming no remote `v0.4`
is intended.

Push only after the gates are green and the tag points at the intended commit:

```sh
git push origin HEAD
git push origin v0.4.0
```
