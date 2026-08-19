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

## Exact local validation

The exhaustive gate is local and authoritative. Run it once, after the final candidate is committed,
on one allowed CPU. It covers the whole workspace, strict rustdoc, Clippy, serial tests, public
entry points, all hermetic demos, the three-process cluster behavior, optional-provider cfg/tests,
supply-chain policy, and the v0.5 fixture. It also builds the exact OpenAI-enabled `dialogue` binary
with the candidate commit embedded, copies it outside the checkout, and emits a portable
`alpha.local-validation.v1` handoff. No provider or operator secret is read by this command.

Run these blocks in one shell after setting `VERSION`, `PREVIOUS_VERSION`, and `RELEASE_DATE` to the
values above. `ALPHA_RELEASE_HANDOFF_PARENT` must be an existing private absolute directory; the
candidate-specific child must not exist yet.

```sh
set -eu
umask 077
release_commit="$(git rev-parse 'HEAD^{commit}')" || exit 1
case "$release_commit" in
  [0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]* ) ;;
  *) echo "HEAD did not resolve to a commit" >&2; exit 1 ;;
esac
test "${#release_commit}" -eq 40
tree_status="$(git status \
  --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || exit 1
test -z "$tree_status"
: "${ALPHA_RELEASE_HANDOFF_PARENT:?set an existing private absolute directory}"
case "$ALPHA_RELEASE_HANDOFF_PARENT" in
  /*) ;;
  *) echo "ALPHA_RELEASE_HANDOFF_PARENT must be absolute" >&2; exit 1 ;;
esac
test -d "$ALPHA_RELEASE_HANDOFF_PARENT"
test ! -L "$ALPHA_RELEASE_HANDOFF_PARENT"
validation_dir="$ALPHA_RELEASE_HANDOFF_PARENT/alpha-${VERSION#v}-validation-$release_commit"
test ! -e "$validation_dir"
test ! -L "$validation_dir"
tools/local-validation.sh \
  --exact-commit "$release_commit" \
  --output-dir "$validation_dir"
validation_report="$validation_dir/local-validation.v1.json"
jq -e --arg commit "$release_commit" '
  .schema == "alpha.local-validation.v1"
  and .candidate_sha == $commit
  and .status == "passed"
  and .binary.file == "dialogue"
  and (.binary.sha256 | test("^[0-9a-f]{64}$"))
' "$validation_report" >/dev/null
```

Do not run the full gate again for the same commit. Focused package checks are the iteration loop;
the release command owns the sole exhaustive pass and serializes itself against another local gate.
Cargo does not garbage-collect stale local variants, so inspect `target/` before any focused reclaim
and never treat runtime state, journals, evidence, fixtures, or keys as build output.

## Hosted sanity

Push the unchanged validated commit, then require the short credential-free `CI` workflow for that
exact SHA to pass. Hosted CI is a merge/tag sanity signal—not the validation authority. It performs
format/hygiene/locked-graph checks, type-checks the public surfaces, runs lightweight model/wire
contract tests, and runs the all-feature dependency policy. It does not run the workspace suite,
demos, docs, cluster, or live models; it receives no provider/operator key or evidence.

```sh
set -eu
umask 077
test "$(git rev-parse 'HEAD^{commit}')" = "$release_commit"
tree_status="$(git status \
  --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || exit 1
test -z "$tree_status"
git push origin "$release_commit:refs/heads/master"

ci_run_id=
ci_lookup_attempt=0
while test "$ci_lookup_attempt" -lt 30; do
  ci_run_id="$(gh run list --workflow ci.yml --event push --commit "$release_commit" --limit 1 \
    --json databaseId --jq '.[0].databaseId')" || exit 1
  if test -n "$ci_run_id" && test "$ci_run_id" != null; then
    break
  fi
  ci_lookup_attempt=$((ci_lookup_attempt + 1))
  sleep 2
done
test -n "$ci_run_id"
test "$ci_run_id" != null
gh run watch "$ci_run_id" --exit-status
ci_run="$(gh run view "$ci_run_id" \
  --json databaseId,headSha,event,conclusion,workflowName)" || exit 1
jq -e --argjson id "$ci_run_id" --arg commit "$release_commit" '
  .databaseId == $id
  and .headSha == $commit
  and .event == "push"
  and .conclusion == "success"
  and .workflowName == "CI"
' <<EOF >/dev/null
$ci_run
EOF
```

## Local v0.5.0 live-acceptance gate

After the exact local gate and the unchanged commit's hosted sanity run are Green, perform the live
product proof locally. GitHub receives no provider key, operator signing seed, plaintext transcript,
raw evidence, or encrypted evidence. `tools/v05-live-acceptance.sh` accepts only the portable
validation handoff, snapshots the exact already-built binary before opening secrets, runs seven live
model calls, then invokes `dialogue verify-live` with the same bytes and no provider environment.
The command itself never rebuilds Alpha or invokes Cargo directly; the bounded capability proof does
perform its single nested native BuildCargo compile.

All input paths below are absolute, canonical, private regular files outside the checkout. Provider
endpoints must use HTTPS or exact loopback HTTP, contain no URL user-info, and use timeouts in
`1..=120`. The evidence signing file contains one 32-byte Ed25519 seed as 64 lowercase hex; the
expected signer is its separately authorized 64-hex public key. The prior-semantic registry is the
complete external append-only JSON array (`[]` for the first accepted run). The encryption public
key is armored OpenPGP and `--encryption-recipient` is its full fingerprint.

```sh
set -eu
umask 077
test "$(git rev-parse 'HEAD^{commit}')" = "$release_commit"
tree_status="$(git status \
  --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || exit 1
test -z "$tree_status"
: "${ALPHA_V05_LIVE_PARENT:?set an existing private absolute directory}"
live_output="$ALPHA_V05_LIVE_PARENT/alpha-v05-live-$release_commit"
live_result="$ALPHA_V05_LIVE_PARENT/alpha-v05-live-$release_commit.result.json"
test ! -e "$live_output"
test ! -e "$live_result"

tools/v05-live-acceptance.sh \
  --candidate-sha "$release_commit" \
  --validation-report "$validation_report" \
  --output-dir "$live_output" \
  --builder-model "$V05_BUILDER_MODEL" \
  --builder-base-url "$V05_BUILDER_BASE_URL" \
  --builder-timeout-secs "$V05_BUILDER_TIMEOUT_SECS" \
  --builder-api-key-file "$V05_BUILDER_API_KEY_FILE" \
  --reviewer-model "$V05_REVIEWER_MODEL" \
  --reviewer-base-url "$V05_REVIEWER_BASE_URL" \
  --reviewer-timeout-secs "$V05_REVIEWER_TIMEOUT_SECS" \
  --reviewer-api-key-file "$V05_REVIEWER_API_KEY_FILE" \
  --contract-tester-model "$V05_CONTRACT_TESTER_MODEL" \
  --contract-tester-base-url "$V05_CONTRACT_TESTER_BASE_URL" \
  --contract-tester-timeout-secs "$V05_CONTRACT_TESTER_TIMEOUT_SECS" \
  --contract-tester-api-key-file "$V05_CONTRACT_TESTER_API_KEY_FILE" \
  --evidence-signing-key-file "$V05_EVIDENCE_SIGNING_KEY_FILE" \
  --expected-evidence-signer "$V05_EXPECTED_EVIDENCE_SIGNER" \
  --prior-semantic-registry-file "$V05_PRIOR_SEMANTIC_REGISTRY_FILE" \
  --encryption-public-key-file "$V05_ENCRYPTION_PUBLIC_KEY_FILE" \
  --encryption-recipient "$V05_ENCRYPTION_RECIPIENT" \
  > "$live_result"

jq -e --arg commit "$release_commit" '
  .schema == "alpha.v05-local-live-acceptance-result.v1"
  and .status == "packaged"
  and .candidate_sha == $commit
  and ([
    .local_validation_report_sha256,
    .evidence_index_sha256,
    .semantic_sha256,
    .binary_sha256,
    .encrypted_raw.sha256,
    .verification_pack.sha256
  ] | all(.[]; type == "string" and test("^[0-9a-f]{64}$")))
  and (.evidence_signer | test("^[0-9a-f]{64}$"))
  and ([.builder_model, .reviewer_model, .contract_tester_model]
    | all(.[]; type == "string" and length > 0 and length <= 256))
  and .encrypted_raw.file == ("alpha-v05-" + $commit + "-raw.tar.gz.gpg")
  and .verification_pack.file == ("alpha-v05-" + $commit + "-verification.tar.gz")
' "$live_result" >/dev/null
test "$(sha256sum "$live_output/$(jq -r '.encrypted_raw.file' "$live_result")" \
  | awk '{print $1}')" = "$(jq -r '.encrypted_raw.sha256' "$live_result")"
test "$(sha256sum "$live_output/$(jq -r '.verification_pack.file' "$live_result")" \
  | awk '{print $1}')" = "$(jq -r '.verification_pack.sha256' "$live_result")"
```

The verifier is provider-, Git-, network-, and private-key-independent. It pins the authorized seal
key, candidate, binary bytes, complete 41-file evidence set, seven provider receipts/replay records,
four signed causal decisions, finite-domain semantic novelty, three trusted-lowered artifacts and
Bestiary proofs, and six complete signed Job histories. The live run fails unless Builder ×5,
Reviewer ×1, and Contract Tester ×1 have unique provider-reported response IDs/model IDs,
`finish_reason=stop`, and `store_requested=false`. Provider receipts are traceability metadata, not
cryptographic proof of model weights.

The output directory contains exactly two mode-0600 packages: OpenPGP-encrypted raw evidence and a
disclosure-safe verification pack. The safe pack contains only `dialogue`,
`local-validation.v1.json`, the signed evidence index/seal, `acceptance-manifest.v1.json`, the
six-field offline verifier report, `README.txt`, and `SHA256SUMS`. Never upload plaintext raw
evidence. Move both packages and the exact binary to access-controlled immutable storage retained
for the supported release lifetime, verify every digest on read-back, and retain the store receipts.

Then atomically append the newly accepted semantic digest and an
`alpha.v05-external-acceptance-record.v1` record to the operator's signed append-only registry. The
record must bind the exact candidate; validation-report, index, semantic, binary, and package
digests; authorized evidence signer; three verifier-derived requested-model labels; immutable URIs
and read-back receipts; prior/new registry checkpoints; registry signer/signature; and
`status="accepted"`. Verify that exported record with the registry's native verifier. Alpha does not
select an operator's immutable store or transparency-log implementation, so the verifier is supplied
as a private executable implementing the fixed interface used below. The external record stays
outside Git until after the tag; no tracked edit may follow the live proof.

This gate accepts one bounded `affine_i32_v1` collaboration and trusted lowering to daemon, beast,
and critter. It does not accept arbitrary source generation, general agency, provider-weight
identity, a generic group protocol, or a three-process deployment.

Only after retention and registry verification succeed may the exact proven commit be tagged. In
the same shell, set the absolute paths and independently recorded SHA-256 values below. The registry
verifier must live outside the candidate checkout, be pinned by an independently recorded SHA-256,
and accept
`verify-acceptance --record FILE --candidate-sha SHA`.

```sh
set -eu
umask 077
: "${V05_EXTERNAL_ACCEPTANCE_RECORD:?set the absolute exported registry record}"
: "${V05_EXTERNAL_ACCEPTANCE_RECORD_SHA256:?set its independently recorded SHA-256}"
: "${V05_EXTERNAL_REGISTRY_VERIFIER:?set the absolute registry-native verifier}"
: "${V05_EXTERNAL_REGISTRY_VERIFIER_SHA256:?set its independently recorded SHA-256}"

case "$V05_EXTERNAL_ACCEPTANCE_RECORD" in /*) ;; *) exit 1 ;; esac
case "$V05_EXTERNAL_REGISTRY_VERIFIER" in /*) ;; *) exit 1 ;; esac
case "$live_result" in /*) ;; *) exit 1 ;; esac
case "$live_output" in /*) ;; *) exit 1 ;; esac
release_repo_root="$(git rev-parse --show-toplevel)" || exit 1
release_repo_root="$(realpath -e "$release_repo_root")" || exit 1
case "$V05_EXTERNAL_ACCEPTANCE_RECORD" in
  "$release_repo_root"|"$release_repo_root"/*) exit 1 ;;
esac
case "$V05_EXTERNAL_REGISTRY_VERIFIER" in
  "$release_repo_root"|"$release_repo_root"/*) exit 1 ;;
esac
test -f "$V05_EXTERNAL_ACCEPTANCE_RECORD"
test ! -L "$V05_EXTERNAL_ACCEPTANCE_RECORD"
test "$(realpath -e "$V05_EXTERNAL_ACCEPTANCE_RECORD")" \
  = "$V05_EXTERNAL_ACCEPTANCE_RECORD"
test -f "$V05_EXTERNAL_REGISTRY_VERIFIER"
test ! -L "$V05_EXTERNAL_REGISTRY_VERIFIER"
test -x "$V05_EXTERNAL_REGISTRY_VERIFIER"
test "$(realpath -e "$V05_EXTERNAL_REGISTRY_VERIFIER")" \
  = "$V05_EXTERNAL_REGISTRY_VERIFIER"
test "$(stat -c '%u' "$V05_EXTERNAL_REGISTRY_VERIFIER")" = "$(id -u)"
test "$((8#$(stat -c '%a' "$V05_EXTERNAL_REGISTRY_VERIFIER") & 022))" -eq 0
test -f "$live_result"
test ! -L "$live_result"
test "$(realpath -e "$live_result")" = "$live_result"
test -d "$live_output"
test ! -L "$live_output"
test "$(realpath -e "$live_output")" = "$live_output"

release_guard_dir="$(mktemp -d \
  "${TMPDIR:-/tmp}/alpha-v05-release-guard.XXXXXXXX")" || exit 1
record_snapshot="$release_guard_dir/external-acceptance-record.json"
result_snapshot="$release_guard_dir/local-live-result.json"
pack_snapshot="$release_guard_dir/alpha-v05-$release_commit-verification.tar.gz"
verifier_snapshot="$release_guard_dir/registry-verifier"
pack_list="$release_guard_dir/pack.list"
pack_types="$release_guard_dir/pack.types"
pack_dir="$release_guard_dir/pack"
cleanup_release_guard() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  rm -f -- "$record_snapshot" "$result_snapshot" "$pack_snapshot" \
    "$verifier_snapshot" "$pack_list" "$pack_types" || cleanup_status=1
  rm -rf -- "$pack_dir" || cleanup_status=1
  rmdir -- "$release_guard_dir" || cleanup_status=1
  exit "$cleanup_status"
}
trap cleanup_release_guard EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
install -m 0600 "$V05_EXTERNAL_ACCEPTANCE_RECORD" "$record_snapshot"
chmod 0400 "$record_snapshot"
install -m 0600 "$live_result" "$result_snapshot"
install -m 0500 "$V05_EXTERNAL_REGISTRY_VERIFIER" "$verifier_snapshot"
test "$(sha256sum "$verifier_snapshot" | awk '{print $1}')" \
  = "$V05_EXTERNAL_REGISTRY_VERIFIER_SHA256"
jq -e --arg commit "$release_commit" '
  .schema == "alpha.v05-local-live-acceptance-result.v1"
  and .status == "packaged"
  and .candidate_sha == $commit
  and (keys == [
    "binary_sha256",
    "builder_model",
    "candidate_sha",
    "contract_tester_model",
    "encrypted_raw",
    "evidence_index_sha256",
    "evidence_signer",
    "local_validation_report_sha256",
    "reviewer_model",
    "schema",
    "semantic_sha256",
    "status",
    "verification_pack"
  ])
  and ([
    .local_validation_report_sha256,
    .evidence_index_sha256,
    .semantic_sha256,
    .binary_sha256,
    .encrypted_raw.sha256,
    .verification_pack.sha256,
    .evidence_signer
  ] | all(.[]; type == "string" and test("^[0-9a-f]{64}$")))
  and ([.builder_model, .reviewer_model, .contract_tester_model]
    | all(.[]; type == "string" and length > 0 and length <= 256))
  and .encrypted_raw.file == ("alpha-v05-" + $commit + "-raw.tar.gz.gpg")
  and .verification_pack.file == ("alpha-v05-" + $commit + "-verification.tar.gz")
' "$result_snapshot" >/dev/null
pack_name="alpha-v05-$release_commit-verification.tar.gz"
pack_source="$live_output/$pack_name"
test -f "$pack_source"
test ! -L "$pack_source"
test "$(realpath -e "$pack_source")" = "$pack_source"
install -m 0600 "$pack_source" "$pack_snapshot"

record_sha="$(sha256sum "$record_snapshot" | awk '{print $1}')" || exit 1
test "$record_sha" = "$V05_EXTERNAL_ACCEPTANCE_RECORD_SHA256"
pack_sha="$(sha256sum "$pack_snapshot" | awk '{print $1}')" || exit 1
test "$pack_sha" = "$(jq -r '.verification_pack.sha256' "$result_snapshot")"

# Refuse duplicate, special-type, linked, or unexpected archive members before extraction.
tar -tzf "$pack_snapshot" > "$pack_list"
tar -tvzf "$pack_snapshot" | awk '{print substr($1, 1, 1)}' > "$pack_types"
test "$(wc -l < "$pack_list")" -eq 9
test "$(LC_ALL=C sort -u "$pack_list" | wc -l)" -eq 9
test "$(grep -Fxc -- 'd' "$pack_types")" -eq 1
test "$(grep -Fxc -- '-' "$pack_types")" -eq 8
seal_member="./evidence-seal-$(jq -r '.evidence_index_sha256' "$result_snapshot").v1.json"
for expected_member in \
  ./ \
  ./SHA256SUMS \
  ./README.txt \
  ./acceptance-manifest.v1.json \
  ./dialogue \
  ./evidence-index.v1.json \
  "$seal_member" \
  ./local-validation.v1.json \
  ./offline-verification-report.v1.json; do
  test "$(grep -Fxc -- "$expected_member" "$pack_list")" -eq 1
done
mkdir -m 0700 "$pack_dir"
tar --extract --gzip --file "$pack_snapshot" --directory "$pack_dir" \
  --no-same-owner --no-same-permissions
test "$(find "$pack_dir" -mindepth 1 -maxdepth 1 -type f | wc -l)" -eq 8
test -z "$(find "$pack_dir" -mindepth 1 -maxdepth 1 ! -type f -print -quit)"
(cd "$pack_dir" && sha256sum --check --strict SHA256SUMS >/dev/null)

test "$(sha256sum "$pack_dir/dialogue" | awk '{print $1}')" \
  = "$(jq -r '.binary_sha256' "$result_snapshot")"
test "$(sha256sum "$pack_dir/local-validation.v1.json" | awk '{print $1}')" \
  = "$(jq -r '.local_validation_report_sha256' "$result_snapshot")"
test "$(sha256sum "$pack_dir/evidence-index.v1.json" | awk '{print $1}')" \
  = "$(jq -r '.evidence_index_sha256' "$result_snapshot")"
jq -e --arg commit "$release_commit" \
  --arg version "$VERSION" \
  --arg previous "$PREVIOUS_VERSION" \
  --arg release_date "$RELEASE_DATE" \
  --arg binary "$(jq -r '.binary_sha256' "$result_snapshot")" '
    .schema == "alpha.local-validation.v1"
    and .status == "passed"
    and .candidate_sha == $commit
    and .binary == {file: "dialogue", sha256: $binary}
    and .gate.release_version == $version
    and .gate.previous_version == $previous
    and .gate.release_date == $release_date
  ' "$pack_dir/local-validation.v1.json" >/dev/null
jq -e --slurpfile result "$result_snapshot" '
    keys == [
      "binary_sha256",
      "builder_model",
      "contract_tester_model",
      "index_sha256",
      "reviewer_model",
      "semantic_sha256"
    ]
    and .index_sha256 == $result[0].evidence_index_sha256
    and .semantic_sha256 == $result[0].semantic_sha256
    and .binary_sha256 == $result[0].binary_sha256
    and .builder_model == $result[0].builder_model
    and .reviewer_model == $result[0].reviewer_model
    and .contract_tester_model == $result[0].contract_tester_model
  ' "$pack_dir/offline-verification-report.v1.json" >/dev/null
jq -e --arg commit "$release_commit" --arg seal_file "${seal_member#./}" \
  --arg seal_sha "$(sha256sum "$pack_dir/${seal_member#./}" | awk '{print $1}')" \
  --arg verification_sha "$(sha256sum \
    "$pack_dir/offline-verification-report.v1.json" | awk '{print $1}')" \
  --slurpfile result "$result_snapshot" '
    .schema == "alpha.v05-local-live-acceptance-manifest.v1"
    and .candidate_sha == $commit
    and .local_validation == {
      report_file: "local-validation.v1.json",
      report_sha256: $result[0].local_validation_report_sha256,
      schema: "alpha.local-validation.v1"
    }
    and .binary == {file: "dialogue", sha256: $result[0].binary_sha256}
    and .evidence.index_file == "evidence-index.v1.json"
    and .evidence.index_sha256 == $result[0].evidence_index_sha256
    and .evidence.signed_seal_file == $seal_file
    and .evidence.signed_seal_sha256 == $seal_sha
    and .evidence.expected_signer_public_key == $result[0].evidence_signer
    and .offline_verification.report_file == "offline-verification-report.v1.json"
    and .offline_verification.report_sha256 == $verification_sha
    and .offline_verification.semantic_sha256 == $result[0].semantic_sha256
    and .model_configs == {
      source: "sealed model-calls.v1.json via offline verification",
      provider: "openai-compatible",
      builder: {requested_model: $result[0].builder_model},
      reviewer: {requested_model: $result[0].reviewer_model},
      contract_tester: {requested_model: $result[0].contract_tester_model}
    }
  ' "$pack_dir/acceptance-manifest.v1.json" >/dev/null
jq -e --arg index "$(jq -r '.evidence_index_sha256' "$result_snapshot")" \
  --arg signer "$(jq -r '.evidence_signer' "$result_snapshot")" '
    .seal.index_sha256 == $index and .signer_public_key == $signer
  ' "$pack_dir/${seal_member#./}" >/dev/null

"$verifier_snapshot" verify-acceptance \
  --record "$record_snapshot" --candidate-sha "$release_commit"
test "$(sha256sum "$record_snapshot" | awk '{print $1}')" = "$record_sha"

jq -e --arg commit "$release_commit" --slurpfile result "$result_snapshot" '
  def hex64: type == "string" and test("^[0-9a-f]{64}$");
  .schema == "alpha.v05-external-acceptance-record.v1"
  and .candidate_sha == $commit
  and .status == "accepted"
  and .local_validation_report_sha256 == $result[0].local_validation_report_sha256
  and .evidence_index_sha256 == $result[0].evidence_index_sha256
  and .semantic_sha256 == $result[0].semantic_sha256
  and .binary_sha256 == $result[0].binary_sha256
  and .encrypted_raw.sha256 == $result[0].encrypted_raw.sha256
  and .verification_pack.sha256 == $result[0].verification_pack.sha256
  and .authorized_evidence_seal_signer == $result[0].evidence_signer
  and .model_configs == {
    builder: {
      provider: "openai-compatible",
      requested_model: $result[0].builder_model
    },
    reviewer: {
      provider: "openai-compatible",
      requested_model: $result[0].reviewer_model
    },
    contract_tester: {
      provider: "openai-compatible",
      requested_model: $result[0].contract_tester_model
    }
  }
  and ([
    .local_validation_report_sha256,
    .evidence_index_sha256,
    .semantic_sha256,
    .binary_sha256,
    .encrypted_raw.sha256,
    .verification_pack.sha256,
    .authorized_evidence_seal_signer
  ] | all(.[]; hex64))
  and (.encrypted_raw.immutable_uri | type == "string" and length > 0 and length <= 2048)
  and (.verification_pack.immutable_uri | type == "string" and length > 0 and length <= 2048)
  and .encrypted_raw.immutable_uri != .verification_pack.immutable_uri
  and (.encrypted_raw.readback_receipt | type == "string" and length > 0 and length <= 8192)
  and (.verification_pack.readback_receipt | type == "string" and length > 0 and length <= 8192)
  and (.registry.previous_checkpoint | type == "string" and length > 0 and length <= 8192)
  and (.registry.new_checkpoint | type == "string" and length > 0 and length <= 8192)
  and .registry.previous_checkpoint != .registry.new_checkpoint
  and (.registry.signer | type == "string" and length > 0 and length <= 1024)
  and (.registry.signature | type == "string" and length > 0 and length <= 8192)
' "$record_snapshot" >/dev/null

# Re-query the exact hosted sanity signal immediately before tagging.
test "$VERSION" = v0.5.0
test "$PREVIOUS_VERSION" = v0.4.4
test "$RELEASE_DATE" = 2026-08-18
ci_run="$(gh run view "$ci_run_id" \
  --json databaseId,headSha,event,conclusion,workflowName)" || exit 1
jq -e --argjson id "$ci_run_id" --arg commit "$release_commit" '
  .databaseId == $id
  and .headSha == $commit
  and .event == "push"
  and .conclusion == "success"
  and .workflowName == "CI"
' <<EOF >/dev/null
$ci_run
EOF

test "$(git rev-parse 'HEAD^{commit}')" = "$release_commit"
tree_status="$(git status \
  --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" || exit 1
test -z "$tree_status"
if git show-ref --verify --quiet "refs/tags/$VERSION"; then
  echo "local tag already exists: $VERSION" >&2
  exit 1
fi
remote_tag="$(git ls-remote --tags origin "refs/tags/$VERSION")" || exit 1
test -z "$remote_tag"
tag_message="$VERSION — live collaboration to a bounded all-tier capability"
git tag -a "$VERSION" -m "$tag_message" "$release_commit"
test "$(git rev-parse "$VERSION^{commit}")" = "$release_commit"
git push origin "refs/tags/$VERSION"
gh release create "$VERSION" --verify-tag \
  --title "Alpha $VERSION" --generate-notes

# Attach only the already snapshotted, digest-verified disclosure-safe pack when policy permits.
test "$(sha256sum "$pack_snapshot" | awk '{print $1}')" = "$pack_sha"
gh release upload "$VERSION" "$pack_snapshot"
```

Avoid pushing a truncated shorthand (for example `v0.4`) unless the release plan explicitly wants an
alias. A GitHub Release is the public source-release record; this workspace is not published to a
package registry.
