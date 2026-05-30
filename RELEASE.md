# Release Checklist

This repository's v0.4.0 release is source-first. `sigil` is the only
crates.io-publishable member in this cut; the `alpha` front door, engines, prototypes,
and shipped creatures are built from the source tree.

This is the first public release. Pre-public internal history does not require
backward compatibility; the public contract starts at the published release tag.

## Preflight

- Before tagging, set the `CHANGELOG.md` `0.4.0` date to the publication date and confirm it
  matches the tag/release date.
- Confirm `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/ARCHITECTURE.md`, and
  the design-note index agree on the release line and feature posture.
- Confirm local Markdown links resolve.
- Confirm the publish surface is intentional: only `sigil` should be
  crates.io-publishable unless the release plan explicitly changes.

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
cargo package -p sigil --locked
CARGO_BUILD_JOBS=2 cargo run --locked -p walkthrough
CARGO_BUILD_JOBS=2 cargo run --locked -p federation
```

For crates.io publication, dry-run the contract crate first:

```sh
cargo publish -p sigil --locked --dry-run
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

Publish `sigil` only after the pushed tag and package dry-run are verified.
