# Release Checklist

Alpha releases are **source-first**: the `alpha` front door, engines, prototypes, and shipped
creatures are all built from the source tree. Nothing is published to a package registry — the
workspace is source-only (every member inherits `publish = false`), and on Alpha the distributable
unit is the creature, not a crate.

The public contract starts at the published release tag; pre-tag internal history carries no
backward-compatibility guarantee. The values below define the frozen v0.5.0 candidate:

```sh
VERSION=v0.5.0
PREVIOUS_VERSION=v0.4.4
RELEASE_DATE=2026-08-18
```

Commit this v0.5.0 workspace version and dated changelog **before** setting `release_commit`, running
CI, or collecting live evidence. Version or tracked status edits after the live run would create a
different, unproved commit. TRD-007/ADR-0049 deliberately remain
Accepted/not-Met/not-Implemented in the frozen candidate; the external ceremony must succeed before
tag, and a later post-tag documentation commit links that record and advances status.

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
`openai` Clippy/tests. The CI `dialogue` execution is explicitly `--fixture`: it is a mechanism
regression and cannot satisfy v0.5 product acceptance. The separate `cargo-deny` job evaluates all
features.
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

## Additional v0.5.0 live-acceptance gate

For the final v0.5.0 candidate—which must already contain its v0.5.0 version/changelog metadata—stop
after exact-commit CI and dispatch the protected
[`v0.5 live acceptance`](.github/workflows/v05-live-acceptance.yml) workflow before tagging. That
workflow is the authoritative product gate; scripted CI Models and an ad hoc local `--live` run
cannot replace it. Until the candidate and its retained evidence pass this ceremony, v0.5.0 remains
unaccepted and the tracked TRD/ADR statuses remain pending as described above.

Configure the GitHub environment named `v05-live-acceptance` with required reviewers and restrict
deployment to the final-candidate ref. Its protected configuration is:

- variables
  `ALPHA_DIALOGUE_{BUILDER,REVIEWER,CONTRACT_TESTER}_{MODEL,BASE_URL,TIMEOUT_SECS}`; and
- secrets `ALPHA_DIALOGUE_{BUILDER,REVIEWER,CONTRACT_TESTER}_API_KEY`,
  `V05_EVIDENCE_SIGNING_SEED_HEX`, `V05_EXPECTED_EVIDENCE_SIGNER`,
  `V05_PRIOR_SEMANTIC_REGISTRY_JSON`, `V05_EVIDENCE_ENCRYPTION_PUBLIC_KEY`, and
  `V05_EVIDENCE_ENCRYPTION_RECIPIENT`.

The three endpoints must use HTTPS or exact loopback HTTP and must not contain URL user-info. Each
timeout is an integer in `1..=120`. The signing secret is exactly one 32-byte Ed25519 seed encoded as
64 lowercase hexadecimal characters; its separately authorized public key is the 64-hex
`V05_EXPECTED_EVIDENCE_SIGNER`. The semantic registry is the complete external append-only JSON array
of prior accepted semantic SHA-256 digests; `[]` explicitly represents the first accepted run. The
encryption secret contains one armored OpenPGP public key and the recipient secret pins its full
fingerprint. Keep provider credentials role-scoped and keep the operator signing seed separate from
them.

Dispatch the workflow only after the exact `$release_commit` push CI above is Green. Select a ref
that still resolves to that commit and enter the same full lowercase object ID as `candidate_sha`.
The workflow independently requires `candidate_sha == github.sha == HEAD`, a clean checkout, and a
successful push-triggered `CI` run for that exact SHA. Record the resulting workflow run ID and wait
for its final conclusion:

```sh
set -eu
test "$(git rev-parse HEAD)" = "$release_commit"
tree_status="$(git status --porcelain=v1 --untracked-files=normal)" || exit 1
test -z "$tree_status"

# `master` must still resolve to $release_commit; the workflow fails if the selected ref differs.
gh workflow run v05-live-acceptance.yml --ref master -f candidate_sha="$release_commit"
# Select/record that exact workflow_dispatch run, then wait for it rather than a run for another SHA.
gh run list --workflow v05-live-acceptance.yml --event workflow_dispatch \
  --commit "$release_commit" --limit 10
: "${V05_ACCEPTANCE_RUN_ID:?set the recorded exact-SHA live-acceptance run ID}"
gh run watch "$V05_ACCEPTANCE_RUN_ID" --exit-status
test "$(gh run view "$V05_ACCEPTANCE_RUN_ID" --json headSha --jq '.headSha')" = "$release_commit"
test "$(gh run view "$V05_ACCEPTANCE_RUN_ID" --json conclusion --jq '.conclusion')" = success
```

The workflow builds with `ALPHA_DIALOGUE_BUILD_COMMIT=$release_commit` before any step references or
materializes a protected provider/operator secret. It copies the exact binary outside the checkout,
pins its SHA-256, then creates private `0600` credential files without shell tracing. The copied
binary performs the seven-call live run. A second invocation of those same packaged bytes performs
the generation-independent, provider-offline verification:

```text
dialogue verify-live \
  --expected-seal-signer <authorized-ed25519-public-key> \
  --candidate-sha <exact-release-commit> \
  --packaged-binary <exact-copied-dialogue-binary> \
  --evidence-dir <sealed-evidence-directory> \
  --signed-seal <external-signed-seal> \
  [--forbid-semantic <each-prior-accepted-digest>]...
```

That verifier takes no provider, Git, running Sanctum, or private-key dependency. It pins the
operator-authorized seal key, candidate SHA, exact binary bytes, complete sealed file set, all seven
calls/replay records, four signed causal decisions, semantic novelty, trusted-lowered sources and
three manifests/artifacts/Bestiary proofs, all six signed Job bundles and their result/summary hash
links. Its disclosure-safe success report contains exactly six fields: the verified index, semantic,
and binary SHA-256 digests plus the Builder, Reviewer, and Contract Tester requested-model labels
recovered from the sealed calls. The run fails closed unless Builder ×5, Reviewer ×1, and Contract
Tester ×1 have unique provider-reported response IDs, reported model IDs, terminal
`finish_reason=stop`, and `store_requested=false`; all strict causal decisions validate; and all
three tiers build, publish, and complete their local and cross-Realm Jobs. Those records prove signed
intended Home/deployment topology and one-attempt histories, not packet-level traversal. Provider
receipts remain traceability metadata, not cryptographic proof of model weights.

The workflow creates two packages only: an OpenPGP-encrypted raw bundle containing the private
prompts/completions and full evidence, and a disclosure-safe verification pack containing an
allowlisted exact binary, signed index/seal, acceptance manifest, verifier report, hashes, and no
prompt/completion bodies or credentials. Plaintext raw evidence never enters the upload directory.
It uses the pinned `actions/attest` action to create GitHub artifact attestations for the exact
copied binary, encrypted raw package, and safe package, then uploads both packages with 90-day
retention. Those Actions artifacts are **staging,
not release-lifetime storage**: before tagging, move the encrypted raw package, safe package,
attestations, and run metadata into an access-controlled immutable store retained for the supported
release lifetime. Verify all digests during that transfer.

Append the exact commit, workflow run ID/attempt, evidence-index digest, binary and package digests,
authorized seal signer, provider/model labels, newly accepted semantic digest, attestation subjects,
immutable retention locations, and result to the external signed/append-only acceptance registry.
Append the new semantic digest only after the offline verifier has accepted it; every later dispatch
must feed the complete prior set through `V05_PRIOR_SEMANTIC_REGISTRY_JSON`. GitHub provenance
attestations complement the Ed25519 seal and offline semantic/proof verification: they do not prove
provider weights or make the build reproducible.

Export the registry's resulting JSON record to an absolute local path and verify its native
signature/append-only proof with the external registry's own verifier. The record schema used by the
tag guard below is `alpha.v05-external-acceptance-record.v1`; it names the exact candidate and
workflow run, the verified evidence/binary/package digests, both immutable retention locations,
the exact binary/raw/safe attestation subjects, authorized evidence-seal signer, three role model
labels, and the external registry's signer/signature.
Record the exported file's SHA-256 separately. This explicit hand-off is intentional: Alpha does not
choose an operator's immutable-store or transparency-log implementation, while tagging must still
fail closed if the operator ceremony has not supplied its receipt.

Independently capture the expected values before consulting that record: the index/semantic/binary
digests and three sealed-call-derived role model labels from `dialogue verify-live`, the
encrypted-raw and verification-pack digests from the workflow outputs after download verification,
the workflow run attempt, the protected authorized seal signer, and the three verified GitHub
attestation subject digests. The downloaded verification pack's acceptance manifest binds those
verifier-derived labels back to the protected role configuration. Export the values under the
`V05_EXPECTED_*` names used below. A value copied only from the external record is not an independent
pin.

Do **not** edit TRD-007, release metadata, the workflow, or any tracked file between the proof and
tag. Any edit creates a different, unproved commit. A later post-tag documentation commit may link
the external acceptance record and advance document status. Publish the safe pack or individual
index/seal/report records only when that disclosure matches release policy; never publish or upload
plaintext raw evidence.

An operator-run fallback is qualifying only if release policy has approved an equivalent protected
environment and provenance issuer and it reproduces every workflow control above, including
build-before-secret handling, exact copied-binary pinning, the same `dialogue verify-live` command
with every pinned input/prior digest, encrypted-raw and allowlisted-safe packaging, artifact
attestations, immutable supported-lifetime retention, and the external append-only acceptance
record. A local `--live` run without any one of those controls is exploratory evidence, not a weaker
release path.

This gate proves one constrained finite-domain `affine_i32_v1` collaboration and trusted lowering to
daemon/beast/critter. It is not acceptance of arbitrary model-authored code, general agency,
provider-weight identity, a generic group protocol, or a three-process deployment.

Only after the required exact-run checks succeed may the release be tagged. Continue in the same shell,
where `VERSION` and `release_commit` remain set:

```sh
set -eu
test "$(git rev-parse HEAD)" = "$release_commit"
tree_status="$(git status \
  --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || exit 1
test -z "$tree_status"
if test "$VERSION" = v0.5.0; then
  : "${V05_ACCEPTANCE_RUN_ID:?set the accepted exact-SHA workflow run ID}"
  : "${V05_ACCEPTANCE_RUN_ATTEMPT:?set the accepted workflow run attempt}"
  : "${V05_EXTERNAL_ACCEPTANCE_RECORD:?set the absolute exported registry-record path}"
  : "${V05_EXTERNAL_ACCEPTANCE_RECORD_SHA256:?set its independently recorded SHA-256}"
  : "${V05_EXTERNAL_REGISTRY_VERIFIED:?set to yes only after registry-native verification}"
  : "${V05_EXPECTED_EVIDENCE_INDEX_SHA256:?set from dialogue verify-live}"
  : "${V05_EXPECTED_SEMANTIC_SHA256:?set from dialogue verify-live}"
  : "${V05_EXPECTED_DIALOGUE_BINARY_SHA256:?set from the verified workflow binary}"
  : "${V05_EXPECTED_ENCRYPTED_RAW_SHA256:?set from the downloaded encrypted raw package}"
  : "${V05_EXPECTED_VERIFICATION_PACK_SHA256:?set from the downloaded verification pack}"
  : "${V05_VERIFICATION_PACK:?set the absolute downloaded verification-pack path}"
  : "${V05_EXPECTED_EVIDENCE_SIGNER:?set the protected authorized evidence signer}"
  : "${V05_EXPECTED_BUILDER_MODEL:?set from the verified report/acceptance manifest}"
  : "${V05_EXPECTED_REVIEWER_MODEL:?set from the verified report/acceptance manifest}"
  : "${V05_EXPECTED_CONTRACT_TESTER_MODEL:?set from the verified report/acceptance manifest}"
  test "$V05_EXTERNAL_REGISTRY_VERIFIED" = yes
  case "$V05_ACCEPTANCE_RUN_ID" in
    ''|*[!0-9]*) echo "workflow run ID must be a positive decimal integer" >&2; exit 1 ;;
  esac
  case "$V05_ACCEPTANCE_RUN_ATTEMPT" in
    ''|*[!0-9]*) echo "workflow run attempt must be a positive decimal integer" >&2; exit 1 ;;
  esac
  test "$V05_ACCEPTANCE_RUN_ID" -gt 0
  test "$V05_ACCEPTANCE_RUN_ATTEMPT" -gt 0
  live_run="$(gh run view "$V05_ACCEPTANCE_RUN_ID" \
    --attempt "$V05_ACCEPTANCE_RUN_ATTEMPT" \
    --json databaseId,attempt,headSha,event,conclusion,workflowName)" || exit 1
  jq -e \
    --argjson id "$V05_ACCEPTANCE_RUN_ID" \
    --argjson attempt "$V05_ACCEPTANCE_RUN_ATTEMPT" \
    --arg commit "$release_commit" '
      .databaseId == $id
      and .attempt == $attempt
      and .headSha == $commit
      and .event == "workflow_dispatch"
      and .conclusion == "success"
      and .workflowName == "v0.5 live acceptance"
    ' <<EOF >/dev/null
$live_run
EOF
  case "$V05_EXTERNAL_ACCEPTANCE_RECORD" in
    /*) ;;
    *) echo "external acceptance record path must be absolute" >&2; exit 1 ;;
  esac
  test -f "$V05_EXTERNAL_ACCEPTANCE_RECORD"
  test ! -L "$V05_EXTERNAL_ACCEPTANCE_RECORD"
  case "$V05_VERIFICATION_PACK" in
    /*) ;;
    *) echo "verification pack path must be absolute" >&2; exit 1 ;;
  esac
  test -f "$V05_VERIFICATION_PACK"
  test ! -L "$V05_VERIFICATION_PACK"

  release_guard_dir="$(mktemp -d \
    "${TMPDIR:-/tmp}/alpha-v05-release-guard.XXXXXXXX")" || exit 1
  test -d "$release_guard_dir"
  test ! -L "$release_guard_dir"
  record_snapshot="$release_guard_dir/external-acceptance-record.json"
  verification_pack_snapshot="$release_guard_dir/alpha-v05-verification.tar.gz"
  cleanup_release_guard() {
    cleanup_status=$?
    trap - EXIT HUP INT TERM
    rm -f -- "$record_snapshot" "$verification_pack_snapshot" || cleanup_status=1
    rmdir -- "$release_guard_dir" || cleanup_status=1
    exit "$cleanup_status"
  }
  trap cleanup_release_guard EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  install -m 0600 "$V05_EXTERNAL_ACCEPTANCE_RECORD" "$record_snapshot"
  install -m 0600 "$V05_VERIFICATION_PACK" "$verification_pack_snapshot"
  record_sha="$(sha256sum "$record_snapshot" | awk '{print $1}')" || exit 1
  test "$record_sha" = "$V05_EXTERNAL_ACCEPTANCE_RECORD_SHA256"
  verification_pack_sha="$(sha256sum "$verification_pack_snapshot" | awk '{print $1}')" || exit 1
  test "$verification_pack_sha" = "$V05_EXPECTED_VERIFICATION_PACK_SHA256"
  test "$(tar -tzf "$verification_pack_snapshot" \
    | grep -Fxc './offline-verification-report.v1.json')" -eq 1
  verifier_report="$(tar -xOzf "$verification_pack_snapshot" \
    ./offline-verification-report.v1.json)" || exit 1
  printf '%s\n' "$verifier_report" | jq -e \
    --arg index "$V05_EXPECTED_EVIDENCE_INDEX_SHA256" \
    --arg semantic "$V05_EXPECTED_SEMANTIC_SHA256" \
    --arg binary "$V05_EXPECTED_DIALOGUE_BINARY_SHA256" \
    --arg builder_model "$V05_EXPECTED_BUILDER_MODEL" \
    --arg reviewer_model "$V05_EXPECTED_REVIEWER_MODEL" \
    --arg tester_model "$V05_EXPECTED_CONTRACT_TESTER_MODEL" '
      keys == [
        "binary_sha256",
        "builder_model",
        "contract_tester_model",
        "index_sha256",
        "reviewer_model",
        "semantic_sha256"
      ]
      and .index_sha256 == $index
      and .semantic_sha256 == $semantic
      and .binary_sha256 == $binary
      and .builder_model == $builder_model
      and .reviewer_model == $reviewer_model
      and .contract_tester_model == $tester_model
    ' >/dev/null
  test "$(tar -tzf "$verification_pack_snapshot" \
    | grep -Fxc './acceptance-manifest.v1.json')" -eq 1
  acceptance_manifest="$(tar -xOzf "$verification_pack_snapshot" \
    ./acceptance-manifest.v1.json)" || exit 1
  printf '%s\n' "$acceptance_manifest" | jq -e \
    --arg commit "$release_commit" \
    --arg run "$V05_ACCEPTANCE_RUN_ID" \
    --arg attempt "$V05_ACCEPTANCE_RUN_ATTEMPT" \
    --arg index "$V05_EXPECTED_EVIDENCE_INDEX_SHA256" \
    --arg semantic "$V05_EXPECTED_SEMANTIC_SHA256" \
    --arg binary "$V05_EXPECTED_DIALOGUE_BINARY_SHA256" \
    --arg seal_signer "$V05_EXPECTED_EVIDENCE_SIGNER" \
    --arg builder_model "$V05_EXPECTED_BUILDER_MODEL" \
    --arg reviewer_model "$V05_EXPECTED_REVIEWER_MODEL" \
    --arg tester_model "$V05_EXPECTED_CONTRACT_TESTER_MODEL" '
      .schema == "alpha.v05-live-acceptance-manifest.v1"
      and .candidate_sha == $commit
      and .workflow.run_id == $run
      and .workflow.run_attempt == $attempt
      and .binary.sha256 == $binary
      and .evidence.index_sha256 == $index
      and .evidence.expected_signer_public_key == $seal_signer
      and .offline_verification.semantic_sha256 == $semantic
      and .model_configs == {
        source: "sealed model-calls.v1.json via offline verification",
        provider: "openai-compatible",
        builder: {requested_model: $builder_model},
        reviewer: {requested_model: $reviewer_model},
        contract_tester: {requested_model: $tester_model}
      }
    ' >/dev/null
  jq -e \
    --arg commit "$release_commit" \
    --arg run "$V05_ACCEPTANCE_RUN_ID" \
    --arg attempt "$V05_ACCEPTANCE_RUN_ATTEMPT" \
    --arg index "$V05_EXPECTED_EVIDENCE_INDEX_SHA256" \
    --arg semantic "$V05_EXPECTED_SEMANTIC_SHA256" \
    --arg binary "$V05_EXPECTED_DIALOGUE_BINARY_SHA256" \
    --arg raw "$V05_EXPECTED_ENCRYPTED_RAW_SHA256" \
    --arg safe "$V05_EXPECTED_VERIFICATION_PACK_SHA256" \
    --arg seal_signer "$V05_EXPECTED_EVIDENCE_SIGNER" \
    --arg builder_model "$V05_EXPECTED_BUILDER_MODEL" \
    --arg reviewer_model "$V05_EXPECTED_REVIEWER_MODEL" \
    --arg tester_model "$V05_EXPECTED_CONTRACT_TESTER_MODEL" '
    def hex64: type == "string" and test("^[0-9a-f]{64}$");
    def valid_label: type == "string" and length > 0 and length <= 512;
    .schema == "alpha.v05-external-acceptance-record.v1"
    and .candidate_sha == $commit
    and (.workflow_run_id | tostring) == $run
    and (.workflow_run_attempt | tostring) == $attempt
    and .status == "accepted"
    and ([$index, $semantic, $binary, $raw, $safe] | all(.[]; hex64))
    and .evidence_index_sha256 == $index
    and .semantic_sha256 == $semantic
    and .binary_sha256 == $binary
    and .encrypted_raw.sha256 == $raw
    and .verification_pack.sha256 == $safe
    and (.encrypted_raw.immutable_uri | type == "string" and length > 0 and length <= 2048)
    and (.verification_pack.immutable_uri | type == "string" and length > 0 and length <= 2048)
    and .encrypted_raw.immutable_uri != .verification_pack.immutable_uri
    and .authorized_evidence_seal_signer == $seal_signer
    and ($seal_signer | hex64)
    and ([$builder_model, $reviewer_model, $tester_model] | all(.[]; valid_label))
    and .model_configs == {
      builder: {provider: "openai-compatible", requested_model: $builder_model},
      reviewer: {provider: "openai-compatible", requested_model: $reviewer_model},
      contract_tester: {provider: "openai-compatible", requested_model: $tester_model}
    }
    and .attestation_subjects == {
      binary_sha256: $binary,
      encrypted_raw_sha256: $raw,
      verification_pack_sha256: $safe
    }
    and ([.attestation_subjects[]] | unique | length) == 3
    and (.registry.signer | type == "string" and length > 0 and length <= 1024)
    and (.registry.signature | type == "string" and length > 0 and length <= 8192)
  ' "$record_snapshot" >/dev/null
fi
tag_message="$VERSION — typed Functions and durable Jobs"
if test "$VERSION" = v0.5.0; then
  tag_message="$VERSION — live collaboration to a bounded all-tier capability"
fi
test "$(git rev-parse HEAD)" = "$release_commit"
tree_status="$(git status \
  --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || exit 1
test -z "$tree_status"
git tag -a "$VERSION" -m "$tag_message" "$release_commit"
tag_commit="$(git rev-parse "$VERSION^{commit}")" || exit 1
if test "$release_commit" != "$tag_commit"; then
  echo "$VERSION does not identify the release commit" >&2
  exit 1
fi
git push origin "refs/tags/$VERSION"
gh release create "$VERSION" --verify-tag \
  --title "Alpha $VERSION" --generate-notes

# The protected ceremony already produced and attested its disclosure-safe verification pack.
# Attach a downloaded, digest-verified copy only when release disclosure policy permits it.
if test "$VERSION" = v0.5.0; then
  test -f "$verification_pack_snapshot"
  test ! -L "$verification_pack_snapshot"
  test "$(sha256sum "$verification_pack_snapshot" | awk '{print $1}')" \
    = "$V05_EXPECTED_VERIFICATION_PACK_SHA256"
  gh release upload "$VERSION" "$verification_pack_snapshot"
fi
```

Avoid pushing a truncated shorthand (for example `v0.4`) unless the release plan explicitly wants an
alias. A GitHub Release is the public source-release record; this workspace is not published to a
package registry.
