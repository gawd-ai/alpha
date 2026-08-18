# Release Checklist

Alpha releases are **source-first**: the `alpha` front door, engines, prototypes, and shipped
creatures are all built from the source tree. Nothing is published to a package registry — the
workspace is source-only (every member inherits `publish = false`), and on Alpha the distributable
unit is the creature, not a crate.

The public contract starts at the published release tag; pre-tag internal history carries no
backward-compatibility guarantee. Set `VERSION` once and reuse it throughout this checklist:

```sh
VERSION=v0.4.4
PREVIOUS_VERSION=v0.4.3
RELEASE_DATE=2026-08-16
```

## Preflight

- Set the workspace version once in `Cargo.toml` (`[workspace.package] version`), promote the
  `CHANGELOG.md` `## Unreleased` heading to `## ${VERSION#v} - ${RELEASE_DATE}`, then run
  `cargo metadata --no-deps --format-version=1 >/dev/null` without `--locked` once to refresh the
  workspace-package records in `Cargo.lock` without compiling before any locked gate.
- Confirm `README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/ROADMAP.md`,
  `docs/ARCHITECTURE.md`, `docs/CONCEPTS.md`, `docs/TOPICS.md`, the TRD/ADR/design-note indices, and
  the operator quickstart agree on the release line and feature posture.
- Confirm local Markdown links resolve.
- Confirm the workspace stays source-only: no member is crates.io-publishable
  (every crate sets `publish.workspace = true`, inheriting `publish = false`).

## Gates

Run only the static preflight locally. It is fail-closed and does not compile the workspace:

```sh
set -eu
cargo fmt --all --check
git diff --check
git diff --check "$PREVIOUS_VERSION"..HEAD
cargo deny --all-features check
```

The complete heavyweight gate runs **once, only in CI**, on the pushed candidate. Do not repeat it
locally. CI pins every heavyweight command and its child process tree to one allowed CPU, uses one
Cargo job and one test thread, disables incremental output and clean-runner debug sections, never
caches `target/`, removes only rendered rustdoc output after that gate, cancels superseded runs on
the same ref, and has finite job timeouts. Its required phases are: workspace
Clippy, build, strict rustdoc, serial tests, alpha/omega version smokes, every runnable hermetic demo
(`walkthrough`, `federation`, `distribute`, and `dialogue`), the credential-free `bestiary-live`
startup path, cluster-runbook shell parsing plus its behavioral Steps 01–05 smoke, and the opt-in
`openai` Clippy/tests. The separate `cargo-deny` job evaluates all features.
`.github/workflows/ci.yml` is the executable source of truth for those commands.

Cargo does not garbage-collect stale local build variants. Use focused package checks while
iterating; inspect `target/` before reclaiming space and remove only explicit generated package
artifacts with `cargo clean -p <exact-package>`. Never remove runtime state, journals, keys, or
fixtures as build output.

## Tagging

Do not call a tree released until the committed release tree is clean, green in CI, tagged, and has
a public source release. The commands below intentionally refuse a published tag. If a local tag is
a stale unpublished draft, delete it only after the remote-tag check proves it was never published.

```sh
set -eu

tree_status="$(git status --porcelain=v1)" || {
  echo "could not inspect the release tree; refusing to continue" >&2
  exit 1
}
if test -n "$tree_status"; then
  echo "release tree is not clean" >&2
  exit 1
fi

remote_tags="$(git ls-remote --tags origin \
  "refs/tags/$VERSION" "refs/tags/$VERSION^{}")" || {
  echo "could not verify remote tag state; refusing to continue" >&2
  exit 1
}
if test -n "$remote_tags"; then
  echo "$VERSION is already published on origin" >&2
  exit 1
fi

if git show-ref --verify --quiet "refs/tags/$VERSION"; then
  git tag -d "$VERSION" # stale local draft; the remote check above proved it unpublished
fi

git push origin HEAD:master
release_commit="$(git rev-parse HEAD)" || exit 1
```

Stop here. The next block locates the push-triggered `CI` workflow for exactly `$release_commit`,
waits for the whole workflow (including its separate dependency-audit job), and fails closed unless
its final conclusion is `success`. Run it in the same shell, where `release_commit` remains set:

```sh
set -eu
ci_run_id=
ci_lookup_attempt=0
while test "$ci_lookup_attempt" -lt 30; do
  ci_run_id="$(gh run list --workflow ci.yml --event push --commit "$release_commit" --limit 1 \
    --json databaseId --jq '.[0].databaseId')" || exit 1
  if test -n "$ci_run_id" && test "$ci_run_id" != "null"; then
    break
  fi
  ci_lookup_attempt=$((ci_lookup_attempt + 1))
  sleep 2
done
if test -z "$ci_run_id" || test "$ci_run_id" = "null"; then
  echo "no CI workflow run appeared for $release_commit within 60 seconds" >&2
  exit 1
fi
gh run watch "$ci_run_id" --exit-status
ci_head="$(gh run view "$ci_run_id" --json headSha --jq '.headSha')" || exit 1
ci_conclusion="$(gh run view "$ci_run_id" --json conclusion --jq '.conclusion')" || exit 1
test "$ci_head" = "$release_commit"
test "$ci_conclusion" = "success"
```

Only after that exact-run check succeeds may the release be tagged. Continue in the same shell,
where `VERSION` and `release_commit` remain set:

```sh
set -eu
test "$(git rev-parse HEAD)" = "$release_commit"
git tag -a "$VERSION" -m "$VERSION — typed Functions and durable Jobs"
head_commit="$(git rev-parse HEAD)" || exit 1
tag_commit="$(git rev-parse "$VERSION^{commit}")" || exit 1
if test "$head_commit" != "$tag_commit"; then
  echo "$VERSION does not identify the release commit" >&2
  exit 1
fi
git push origin "refs/tags/$VERSION"
gh release create "$VERSION" --verify-tag \
  --title "Alpha $VERSION" --generate-notes
```

Avoid pushing a truncated shorthand (for example `v0.4`) unless the release plan explicitly wants an
alias. A GitHub Release is the public source-release record; this workspace is not published to a
package registry.
