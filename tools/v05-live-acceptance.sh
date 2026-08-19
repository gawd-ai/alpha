#!/usr/bin/env bash
# Local, exact-commit v0.5 live acceptance and evidence packaging.
#
# This orchestrator never invokes Cargo. It consumes the secret-free binary and validation report
# produced by tools/local-validation.sh, then introduces provider/operator material only for the
# live proof. The validated dialogue composition still performs its one bounded BuildCargo step.
# Hosted CI is a small sanity check, never this product gate.
set -euo pipefail
IFS=$'\n\t'
export LC_ALL=C

usage() {
  cat <<'EOF'
Usage:
  tools/v05-live-acceptance.sh \
    --candidate-sha SHA \
    --validation-report ABSOLUTE_LOCAL_VALIDATION_V1_JSON \
    --output-dir ABSOLUTE_NEW_DIRECTORY \
    --builder-model MODEL --builder-base-url URL --builder-timeout-secs SECONDS \
    --builder-api-key-file ABSOLUTE_PRIVATE_FILE \
    --reviewer-model MODEL --reviewer-base-url URL --reviewer-timeout-secs SECONDS \
    --reviewer-api-key-file ABSOLUTE_PRIVATE_FILE \
    --contract-tester-model MODEL --contract-tester-base-url URL \
    --contract-tester-timeout-secs SECONDS \
    --contract-tester-api-key-file ABSOLUTE_PRIVATE_FILE \
    --evidence-signing-key-file ABSOLUTE_PRIVATE_0600_SEED_FILE \
    --expected-evidence-signer LOWERCASE_ED25519_PUBLIC_KEY_HEX \
    --prior-semantic-registry-file ABSOLUTE_JSON_ARRAY \
    --encryption-public-key-file ABSOLUTE_ARMORED_OPENPGP_PUBLIC_KEY \
    --encryption-recipient FULL_OPENPGP_FINGERPRINT

The validation report must have schema alpha.local-validation.v1, status passed, the same exact
candidate SHA, and binary {file:"dialogue",sha256}. The binary is resolved as a regular non-symlink
sibling of the report. This orchestrator issues no direct Cargo command or additional Alpha build;
the live dialogue necessarily performs its one bounded nested BuildCargo compile. Secret values are
never accepted inline.

On success the create-new output directory contains exactly:
  alpha-v05-SHA-raw.tar.gz.gpg       encrypted full evidence, prompts, and transcript
  alpha-v05-SHA-verification.tar.gz  disclosure-safe verification pack

One compact, disclosure-safe JSON result is written to stdout. All other progress/errors go to
stderr. The external release operator must then immutably retain both files, verify them by digest,
and atomically append the semantic/result to the signed acceptance registry before tagging.
EOF
}

die() {
  printf 'v0.5 live acceptance: %s\n' "$*" >&2
  exit 1
}

declare -A seen_options=()
set_once() {
  local variable="$1" flag="$2" value="$3"
  [[ -z "${seen_options[$flag]:-}" ]] || die "duplicate $flag"
  seen_options["$flag"]=1
  printf -v "$variable" '%s' "$value"
}

candidate_sha=""
validation_report=""
output_dir=""
builder_model=""
builder_base_url=""
builder_timeout_secs=""
builder_api_key_file=""
reviewer_model=""
reviewer_base_url=""
reviewer_timeout_secs=""
reviewer_api_key_file=""
contract_tester_model=""
contract_tester_base_url=""
contract_tester_timeout_secs=""
contract_tester_api_key_file=""
evidence_signing_key_file=""
expected_evidence_signer=""
prior_semantic_registry_file=""
encryption_public_key_file=""
encryption_recipient=""

if (($# == 1)) && [[ "$1" == "--help" || "$1" == "-h" ]]; then
  usage
  exit 0
fi

while (($# > 0)); do
  flag="$1"
  shift
  (($# > 0)) || {
    usage >&2
    die "$flag requires one value"
  }
  value="$1"
  shift
  case "$flag" in
    --candidate-sha) set_once candidate_sha "$flag" "$value" ;;
    --validation-report) set_once validation_report "$flag" "$value" ;;
    --output-dir) set_once output_dir "$flag" "$value" ;;
    --builder-model) set_once builder_model "$flag" "$value" ;;
    --builder-base-url) set_once builder_base_url "$flag" "$value" ;;
    --builder-timeout-secs) set_once builder_timeout_secs "$flag" "$value" ;;
    --builder-api-key-file) set_once builder_api_key_file "$flag" "$value" ;;
    --reviewer-model) set_once reviewer_model "$flag" "$value" ;;
    --reviewer-base-url) set_once reviewer_base_url "$flag" "$value" ;;
    --reviewer-timeout-secs) set_once reviewer_timeout_secs "$flag" "$value" ;;
    --reviewer-api-key-file) set_once reviewer_api_key_file "$flag" "$value" ;;
    --contract-tester-model) set_once contract_tester_model "$flag" "$value" ;;
    --contract-tester-base-url) set_once contract_tester_base_url "$flag" "$value" ;;
    --contract-tester-timeout-secs) set_once contract_tester_timeout_secs "$flag" "$value" ;;
    --contract-tester-api-key-file) set_once contract_tester_api_key_file "$flag" "$value" ;;
    --evidence-signing-key-file) set_once evidence_signing_key_file "$flag" "$value" ;;
    --expected-evidence-signer) set_once expected_evidence_signer "$flag" "$value" ;;
    --prior-semantic-registry-file)
      set_once prior_semantic_registry_file "$flag" "$value"
      ;;
    --encryption-public-key-file) set_once encryption_public_key_file "$flag" "$value" ;;
    --encryption-recipient) set_once encryption_recipient "$flag" "$value" ;;
    -h|--help)
      usage >&2
      die "$flag must be used alone"
      ;;
    *)
      usage >&2
      die "unknown argument $flag"
      ;;
  esac
done

required_values=(
  candidate_sha validation_report output_dir
  builder_model builder_base_url builder_timeout_secs builder_api_key_file
  reviewer_model reviewer_base_url reviewer_timeout_secs reviewer_api_key_file
  contract_tester_model contract_tester_base_url contract_tester_timeout_secs
  contract_tester_api_key_file evidence_signing_key_file expected_evidence_signer
  prior_semantic_registry_file encryption_public_key_file encryption_recipient
)
for variable in "${required_values[@]}"; do
  [[ -n "${!variable:-}" ]] || {
    usage >&2
    die "required option for $variable is absent"
  }
done

[[ "$candidate_sha" =~ ^[0-9a-f]{40}$ ]] ||
  die "--candidate-sha must be one full lowercase 40-hex Git object ID"
[[ "$expected_evidence_signer" =~ ^[0-9a-f]{64}$ ]] ||
  die "--expected-evidence-signer must be 64 lowercase hexadecimal characters"
if [[ "$encryption_recipient" =~ ^[0-9A-Fa-f]{40}$ ]] ||
   [[ "$encryption_recipient" =~ ^[0-9A-Fa-f]{64}$ ]]; then
  encryption_recipient="${encryption_recipient^^}"
else
  die "--encryption-recipient must be one full OpenPGP fingerprint"
fi
for timeout_value in \
  "$builder_timeout_secs" "$reviewer_timeout_secs" "$contract_tester_timeout_secs"; do
  [[ "$timeout_value" =~ ^([1-9]|[1-9][0-9]|1[01][0-9]|120)$ ]] ||
    die "each model timeout must be an integer in 1..=120"
done
for label in "$builder_model" "$reviewer_model" "$contract_tester_model"; do
  (( ${#label} <= 256 )) || die "model labels must not exceed 256 characters"
  [[ ! "$label" =~ [[:cntrl:]] ]] || die "model labels must not contain control characters"
done
for origin in "$builder_base_url" "$reviewer_base_url" "$contract_tester_base_url"; do
  (( ${#origin} <= 2048 )) || die "provider base URLs must not exceed 2048 characters"
  [[ ! "$origin" =~ [[:cntrl:]] ]] ||
    die "provider base URLs must not contain control characters"
  [[ ! "$origin" =~ ^[[:space:]] && ! "$origin" =~ [[:space:]]$ ]] ||
    die "provider base URLs must not have surrounding whitespace"
  [[ "$origin" == https://* || "$origin" == http://* ]] ||
    die "provider base URLs must use a lowercase http or https scheme"
  [[ "$origin" != *"@"* ]] || die "provider base URLs must not contain URL user-info"
done

readonly script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly repo_root="$(cd -- "$script_dir/.." && pwd -P)"
cd -- "$repo_root"

for required_command in awk basename bash cat chmod cp dirname env find flock git gpg grep id \
  install jq mkdir mktemp nice ps realpath rm rustup sha256sum sleep stat tar taskset timeout; do
  command -v "$required_command" >/dev/null 2>&1 ||
    die "required command not found: $required_command"
done

actual_root="$(git rev-parse --show-toplevel)" || die "could not resolve repository root"
[[ "$(cd -- "$actual_root" && pwd -P)" == "$repo_root" ]] ||
  die "this script must run from its Alpha checkout"

path_is_inside_repo() {
  local path="$1"
  [[ "$path" == "$repo_root" || "$path" == "$repo_root/"* ]]
}

canonical_regular_file() {
  local supplied="$1" label="$2" canonical
  [[ "$supplied" == /* ]] || die "$label path must be absolute"
  [[ "$supplied" != *$'\n'* && "$supplied" != *$'\r'* ]] ||
    die "$label path must not contain line breaks"
  canonical="$(realpath -e -- "$supplied")" || die "could not resolve $label path"
  [[ "$canonical" == "$supplied" ]] || die "$label path must already be canonical"
  [[ -f "$canonical" && ! -L "$canonical" ]] ||
    die "$label must be one regular non-symlink file"
  printf '%s\n' "$canonical"
}

require_private_file() {
  local supplied="$1" label="$2" canonical mode owner links
  canonical="$(canonical_regular_file "$supplied" "$label")"
  path_is_inside_repo "$canonical" && die "$label must be outside the source worktree"
  mode="$(stat -c '%a' -- "$canonical")" || die "could not inspect $label mode"
  owner="$(stat -c '%u' -- "$canonical")" || die "could not inspect $label owner"
  links="$(stat -c '%h' -- "$canonical")" || die "could not inspect $label link count"
  [[ "$owner" == "$(id -u)" ]] || die "$label must be owned by the current user"
  (( (8#$mode & 077) == 0 )) || die "$label must grant no group/other permissions"
  [[ "$links" == "1" ]] || die "$label must have exactly one hard link"
  printf '%s\n' "$canonical"
}

require_clean_exact_tree() {
  local when="$1" head status
  head="$(git rev-parse --verify 'HEAD^{commit}')" || die "could not resolve HEAD $when"
  [[ "$head" == "$candidate_sha" ]] ||
    die "HEAD $when is $head, expected candidate $candidate_sha"
  status="$(git status --porcelain=v1 --untracked-files=normal --ignore-submodules=none)" ||
    die "could not inspect source tree $when"
  [[ -z "$status" ]] || {
    printf '%s\n' "$status" >&2
    die "source tree is not clean $when"
  }
}

require_clean_exact_tree "before live acceptance"

validation_report="$(canonical_regular_file "$validation_report" "validation report")"
path_is_inside_repo "$validation_report" &&
  die "validation report must be outside the source worktree"
[[ "$(stat -c '%a' -- "$validation_report")" == "600" ]] ||
  die "validation report must have mode 0600"
[[ "$(stat -c '%u' -- "$validation_report")" == "$(id -u)" ]] ||
  die "validation report must be owned by the current user"
[[ "$(stat -c '%h' -- "$validation_report")" == "1" ]] ||
  die "validation report must have exactly one hard link"
[[ "$(basename -- "$validation_report")" == "local-validation.v1.json" ]] ||
  die "validation report must retain its canonical local-validation.v1.json name"
[[ -s "$validation_report" ]] || die "validation report must not be empty"
(( $(stat -c '%s' -- "$validation_report") <= 1048576 )) ||
  die "validation report must not exceed 1 MiB"
validated_report_sha="$(sha256sum "$validation_report" | awk '{print $1}')" ||
  die "could not hash the validation report"
toolchain_file_sha="$(sha256sum "$repo_root/rust-toolchain.toml" | awk '{print $1}')" ||
  die "could not hash the candidate rust-toolchain.toml"

jq -e --arg candidate "$candidate_sha" --arg toolchain_file_sha "$toolchain_file_sha" '
  type == "object"
  and keys == ["binary", "candidate_sha", "gate", "schema", "status", "toolchain"]
  and .schema == "alpha.local-validation.v1"
  and .candidate_sha == $candidate
  and .status == "passed"
  and (.binary | type == "object")
  and (.binary | keys == ["file", "sha256"])
  and .binary.file == "dialogue"
  and (.binary.sha256 | type == "string" and test("^[0-9a-f]{64}$"))
  and (.gate | type == "object")
  and (.gate | keys == [
    "constraints",
    "end_head",
    "overall_timeout_seconds",
    "phase_count",
    "phases",
    "previous_version",
    "release_date",
    "release_version",
    "script",
    "selected_cpu",
    "start_head"
  ])
  and .gate.script == "tools/local-validation.sh"
  and .gate.release_version == "v0.5.0"
  and .gate.release_date == "2026-08-18"
  and .gate.previous_version == "v0.4.4"
  and .gate.start_head == $candidate
  and .gate.end_head == $candidate
  and .gate.phase_count == 28
  and .gate.phases == [
    "Pinned Rust toolchain and components",
    "Native safety source invariants",
    "Wasmtime serial-compilation invariant",
    "Formatting",
    "Patch hygiene",
    "Operator and cluster script syntax",
    "Locked dependency graph",
    "Dependency, license, and source policy (all features)",
    "Workspace Clippy (all targets, warnings denied)",
    "Workspace build",
    "Cluster behavior (boot, gossip, cross-run, remote MCP)",
    "Strict workspace rustdoc",
    "Reclaim rendered rustdoc only",
    "Full workspace tests (serial)",
    "Alpha entry point",
    "Omega entry point",
    "Walkthrough demo",
    "Federation demo",
    "Distribute demo",
    "Dialogue all-tier fixture",
    "OpenAI cfg: agent-mind Clippy",
    "OpenAI cfg: alpha Clippy",
    "OpenAI cfg: bestiary-live Clippy",
    "OpenAI cfg: dialogue Clippy",
    "OpenAI cfg: agent-mind tests",
    "OpenAI cfg: dialogue tests",
    "Bestiary no-credential startup",
    "Prepare exact-commit OpenAI dialogue binary"
  ]
  and .gate.constraints == {
    cargo_build_jobs: 1,
    cargo_incremental: false,
    rust_test_threads: 1,
    compiler_wrappers: false
  }
  and (.toolchain | type == "object")
  and (.toolchain | keys == [
    "active_toolchain",
    "cargo_verbose",
    "rust_toolchain_toml_sha256",
    "rustc_verbose"
  ])
  and (.toolchain.active_toolchain |
    type == "string" and test("^1\\.97\\.1-[0-9A-Za-z_.+-]+$") and length <= 256)
  and (.toolchain.cargo_verbose |
    type == "string"
    and length > 0
    and length <= 16384
    and test("^cargo 1\\.97\\.1( |\\n|$)"))
  and (.toolchain.rustc_verbose |
    type == "string"
    and length > 0
    and length <= 16384
    and test("(^|\\n)release: 1\\.97\\.1(\\n|$)"))
  and .toolchain.rust_toolchain_toml_sha256 == $toolchain_file_sha
' "$validation_report" >/dev/null || die "validation report did not pass its exact-candidate contract"
[[ "$(sha256sum "$validation_report" | awk '{print $1}')" == "$validated_report_sha" ]] ||
  die "validation report changed while its contract was checked"

validation_dir="$(dirname -- "$validation_report")"
validation_dir="$(cd -- "$validation_dir" && pwd -P)"
[[ "$(stat -c '%a' -- "$validation_dir")" == "700" ]] ||
  die "validation handoff directory must have mode 0700"
[[ "$(stat -c '%u' -- "$validation_dir")" == "$(id -u)" ]] ||
  die "validation handoff directory must be owned by the current user"
validated_binary="$validation_dir/dialogue"
validated_binary="$(canonical_regular_file "$validated_binary" "validated dialogue binary")"
path_is_inside_repo "$validated_binary" &&
  die "validated dialogue binary must be outside the source worktree"
[[ "$(stat -c '%a' -- "$validated_binary")" == "500" ]] ||
  die "validated dialogue binary must have mode 0500"
[[ "$(stat -c '%u' -- "$validated_binary")" == "$(id -u)" ]] ||
  die "validated dialogue binary must be owned by the current user"
[[ "$(stat -c '%h' -- "$validated_binary")" == "1" ]] ||
  die "validated dialogue binary must have exactly one hard link"
[[ -s "$validated_binary" ]] || die "validated dialogue binary must not be empty"
(( $(stat -c '%s' -- "$validated_binary") <= 536870912 )) ||
  die "validated dialogue binary must not exceed 512 MiB"
validated_binary_sha="$(jq -r '.binary.sha256' "$validation_report")"
[[ "$(sha256sum "$validated_binary" | awk '{print $1}')" == "$validated_binary_sha" ]] ||
  die "validated dialogue binary does not match the validation report"

validated_toolchain="$(jq -r '.toolchain.active_toolchain' "$validation_report")"
pinned_cargo="$(rustup which --toolchain "$validated_toolchain" cargo)" ||
  die "could not resolve the validated Cargo executable"
pinned_rustc="$(rustup which --toolchain "$validated_toolchain" rustc)" ||
  die "could not resolve the validated rustc executable"
pinned_cargo="$(realpath -e -- "$pinned_cargo")" || die "could not canonicalize validated Cargo"
pinned_rustc="$(realpath -e -- "$pinned_rustc")" || die "could not canonicalize validated rustc"
[[ -f "$pinned_cargo" && -x "$pinned_cargo" && ! -L "$pinned_cargo" ]] ||
  die "validated Cargo is not a regular executable"
[[ -f "$pinned_rustc" && -x "$pinned_rustc" && ! -L "$pinned_rustc" ]] ||
  die "validated rustc is not a regular executable"
toolchain_bin="$(dirname -- "$pinned_cargo")"
[[ "$(dirname -- "$pinned_rustc")" == "$toolchain_bin" ]] ||
  die "validated Cargo and rustc do not share one pinned toolchain directory"
live_path="$toolchain_bin:/usr/bin:/bin"

[[ "$output_dir" == /* ]] || die "--output-dir must be absolute"
[[ "$output_dir" != *$'\n'* && "$output_dir" != *$'\r'* ]] ||
  die "--output-dir must not contain line breaks"
requested_output_dir="$output_dir"
output_parent="$(dirname -- "$output_dir")"
output_parent="$(realpath -e -- "$output_parent")" || die "output parent does not exist"
[[ -d "$output_parent" && ! -L "$output_parent" ]] ||
  die "output parent must be a real directory"
output_dir="$(realpath -m -- "$output_dir")" || die "could not normalize output directory"
[[ "$output_dir" == "$requested_output_dir" ]] ||
  die "output directory must already be canonical"
[[ "$(dirname -- "$output_dir")" == "$output_parent" ]] ||
  die "output directory parent changed during canonicalization"
path_is_inside_repo "$output_dir" && die "output directory must be outside the source worktree"
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] ||
  die "output directory must not already exist"

# Serialize the full local gate and live ceremony across worktrees sharing this repository. The live
# program performs one bounded nested Cargo build, so also refuse any already-active compiler.
git_common_dir="$(git rev-parse --path-format=absolute --git-common-dir)" ||
  die "could not resolve Git common directory"
exec {gate_lock_fd}>"$git_common_dir/alpha-local-validation.lock" ||
  die "could not open the local validation/live lock"
flock -n "$gate_lock_fd" || die "local validation or live acceptance is already running"

compiler_processes="$(
  ps -eo pid=,stat=,comm=,args= | while IFS=' ' read -r pid state command arguments; do
    case "$state" in
      Z*|X*) continue ;;
    esac
    case "$command" in
      cargo|rustc|rustdoc|clippy-driver)
        printf '%s %s %s\n' "$pid" "$command" "$arguments"
        ;;
    esac
  done
)" || die "could not inspect active compiler processes"
[[ -z "$compiler_processes" ]] || {
  printf '%s\n' "$compiler_processes" >&2
  die "Cargo or a Rust compiler is already active; reuse or wait for that result"
}

allowed_cpus="$(LC_ALL=C taskset -pc $$)" || die "could not inspect allowed CPU set"
allowed_cpus="${allowed_cpus##*: }"
acceptance_cpu="${allowed_cpus%%,*}"
acceptance_cpu="${acceptance_cpu%%-*}"
[[ "$acceptance_cpu" =~ ^[0-9]+$ ]] ||
  die "could not select the first CPU from allowed set '$allowed_cpus'"
taskset --cpu-list "$acceptance_cpu" true || die "selected CPU is unavailable"

temp_parent="$(realpath -e -- "${TMPDIR:-/tmp}")" || die "could not resolve temporary parent"
private_root="$(mktemp -d "$temp_parent/alpha-v05-live.XXXXXXXX")" ||
  die "could not create private acceptance directory"
[[ -d "$private_root" && ! -L "$private_root" ]] || die "unsafe private directory"
chmod 0700 "$private_root"
printf '%s\n' 'alpha-v05-local-live-private-v1' > "$private_root/.owned"
chmod 0600 "$private_root/.owned"

output_created=0
live_pid=""
live_pgid=""
terminate_live_process_group() {
  local attempt
  [[ -n "$live_pid" ]] || return 0
  if [[ -n "$live_pgid" && "$live_pgid" == "$live_pid" ]]; then
    kill -TERM -- "-$live_pgid" 2>/dev/null || true
    for ((attempt = 0; attempt < 50; attempt++)); do
      kill -0 -- "-$live_pgid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 -- "-$live_pgid" 2>/dev/null; then
      kill -KILL -- "-$live_pgid" 2>/dev/null || true
    fi
  else
    kill -TERM -- "$live_pid" 2>/dev/null || true
    for ((attempt = 0; attempt < 50; attempt++)); do
      kill -0 -- "$live_pid" 2>/dev/null || break
      sleep 0.1
    done
    if kill -0 -- "$live_pid" 2>/dev/null; then
      kill -KILL -- "$live_pid" 2>/dev/null || true
    fi
  fi
  wait "$live_pid" 2>/dev/null || true
  live_pid=""
  live_pgid=""
}
cleanup() {
  local cleanup_status=$?
  trap - EXIT HUP INT TERM
  terminate_live_process_group
  if [[ -n "${private_root:-}" && -d "$private_root" ]]; then
    if [[ -f "$private_root/.owned" ]] &&
       [[ "$(<"$private_root/.owned")" == "alpha-v05-local-live-private-v1" ]]; then
      chmod -R u+rwX "$private_root" 2>/dev/null || cleanup_status=1
      rm -rf -- "$private_root" || cleanup_status=1
    else
      printf 'v0.5 live acceptance: private cleanup ownership check failed\n' >&2
      cleanup_status=1
    fi
  fi
  if (( cleanup_status != 0 && output_created == 1 )); then
    if [[ -f "$output_dir/.owned" ]] &&
       [[ "$(<"$output_dir/.owned")" == "alpha-v05-local-live-output-v1" ]]; then
      chmod -R u+rwX "$output_dir" 2>/dev/null || cleanup_status=1
      rm -rf -- "$output_dir" || cleanup_status=1
    else
      printf 'v0.5 live acceptance: output cleanup ownership check failed\n' >&2
      cleanup_status=1
    fi
  fi
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

install -d -m 0700 \
  "$private_root/input" "$private_root/secrets" "$private_root/gnupg" \
  "$private_root/raw-stage" "$private_root/safe-stage" "$private_root/tmp" \
  "$private_root/cargo-home"
report_snapshot="$private_root/input/local-validation.v1.json"
binary_snapshot="$private_root/input/dialogue"
report_source_sha="$(sha256sum "$validation_report" | awk '{print $1}')"
[[ "$report_source_sha" == "$validated_report_sha" ]] ||
  die "validation report changed before it was copied"
install -m 0600 "$validation_report" "$report_snapshot"
[[ "$(sha256sum "$validation_report" | awk '{print $1}')" == "$report_source_sha" ]] ||
  die "validation report changed while it was copied"
[[ "$(sha256sum "$report_snapshot" | awk '{print $1}')" == "$report_source_sha" ]] ||
  die "validation report copy changed"
binary_source_sha="$(sha256sum "$validated_binary" | awk '{print $1}')"
[[ "$binary_source_sha" == "$validated_binary_sha" ]] ||
  die "validated binary changed before it was copied"
install -m 0500 "$validated_binary" "$binary_snapshot"
[[ "$(sha256sum "$validated_binary" | awk '{print $1}')" == "$binary_source_sha" ]] ||
  die "validated binary changed while it was copied"
[[ "$(sha256sum "$binary_snapshot" | awk '{print $1}')" == "$validated_binary_sha" ]] ||
  die "validated binary copy changed"
require_clean_exact_tree "after validated-input snapshot"

# Secret paths are resolved and opened only after the validated binary has already been snapshotted.
builder_api_key_file="$(require_private_file "$builder_api_key_file" "Builder API key")"
reviewer_api_key_file="$(require_private_file "$reviewer_api_key_file" "Reviewer API key")"
contract_tester_api_key_file="$(
  require_private_file "$contract_tester_api_key_file" "Contract Tester API key"
)"
evidence_signing_key_file="$(
  require_private_file "$evidence_signing_key_file" "evidence signing seed"
)"
prior_semantic_registry_file="$(
  canonical_regular_file "$prior_semantic_registry_file" "prior semantic registry"
)"
path_is_inside_repo "$prior_semantic_registry_file" &&
  die "prior semantic registry must be outside the source worktree"
encryption_public_key_file="$(
  canonical_regular_file "$encryption_public_key_file" "encryption public key"
)"
path_is_inside_repo "$encryption_public_key_file" &&
  die "encryption public key must be outside the source worktree"

for private_input in "$builder_api_key_file" "$reviewer_api_key_file" \
  "$contract_tester_api_key_file"; do
  [[ -s "$private_input" ]] || die "private credential/key files must not be empty"
  (( $(stat -c '%s' -- "$private_input") <= 16384 )) ||
    die "provider credential files must not exceed 16 KiB"
done
[[ -s "$evidence_signing_key_file" ]] || die "evidence signing seed must not be empty"
(( $(stat -c '%s' -- "$evidence_signing_key_file") <= 128 )) ||
  die "evidence signing seed must not exceed 128 bytes"
(( $(stat -c '%s' -- "$prior_semantic_registry_file") <= 1048576 )) ||
  die "prior semantic registry must not exceed 1 MiB"
(( $(stat -c '%s' -- "$encryption_public_key_file") <= 1048576 )) ||
  die "encryption public key must not exceed 1 MiB"

builder_key_copy="$private_root/secrets/builder-api-key"
reviewer_key_copy="$private_root/secrets/reviewer-api-key"
tester_key_copy="$private_root/secrets/contract-tester-api-key"
signing_key_copy="$private_root/secrets/evidence-signing-seed.hex"
registry_copy="$private_root/input/prior-semantic-registry.json"
encryption_key_copy="$private_root/input/encryption-recipient.asc"
install -m 0600 "$builder_api_key_file" "$builder_key_copy"
install -m 0600 "$reviewer_api_key_file" "$reviewer_key_copy"
install -m 0600 "$contract_tester_api_key_file" "$tester_key_copy"
install -m 0600 "$evidence_signing_key_file" "$signing_key_copy"
install -m 0600 "$prior_semantic_registry_file" "$registry_copy"
install -m 0600 "$encryption_public_key_file" "$encryption_key_copy"

jq -e '
  type == "array"
  and all(.[]; type == "string" and test("^[0-9a-f]{64}$"))
  and length == (unique | length)
' "$registry_copy" >/dev/null || die "prior semantic registry must be a unique SHA-256 array"
jq -c '.' "$registry_copy" > "$private_root/input/registry.canonical.json"
install -m 0600 "$private_root/input/registry.canonical.json" "$registry_copy"
rm -f -- "$private_root/input/registry.canonical.json"
prior_count="$(jq -r 'length' "$registry_copy")" || die "could not count prior semantics"
[[ "$prior_count" =~ ^[0-9]+$ ]] || die "invalid prior semantic count"
(( prior_count <= 4096 )) || die "prior semantic registry exceeds the 4096-entry bound"
mapfile -t prior_semantics < <(jq -r '.[]' "$registry_copy")
(( ${#prior_semantics[@]} == prior_count )) || die "prior semantic extraction was incomplete"
registry_sha="$(sha256sum "$registry_copy" | awk '{print $1}')"

if grep -Fq 'BEGIN PGP PRIVATE KEY BLOCK' "$encryption_key_copy"; then
  die "encryption material must not contain a private OpenPGP key"
fi
grep -Fq 'BEGIN PGP PUBLIC KEY BLOCK' "$encryption_key_copy" ||
  die "encryption material is not an armored OpenPGP public key"
export GNUPGHOME="$private_root/gnupg"
gpg --batch --quiet --import "$encryption_key_copy"
if gpg --batch --with-colons --list-secret-keys 2>/dev/null | grep -q '^sec:'; then
  die "encryption key import unexpectedly contained private material"
fi
mapfile -t imported_fingerprints < <(
  gpg --batch --with-colons --list-keys 2>/dev/null |
    awk -F: '$1 == "pub" { want = 1; next } want && $1 == "fpr" { print $10; want = 0 }'
)
(( ${#imported_fingerprints[@]} == 1 )) ||
  die "encryption key file must contain exactly one primary public key"
[[ "${imported_fingerprints[0]}" == "$encryption_recipient" ]] ||
  die "encryption key does not match the pinned recipient fingerprint"

forbidden_args=()
for digest in "${prior_semantics[@]}"; do
  forbidden_args+=(--forbid-semantic "$digest")
done

evidence_dir="$private_root/evidence"
live_log="$private_root/dialogue-live.log"
live_env=(
  env -i
  "PATH=$live_path"
  "HOME=${HOME:?HOME is required for the pinned Rust toolchain}"
  "LC_ALL=C"
  "TMPDIR=$private_root/tmp"
  "CARGO_HOME=$private_root/cargo-home"
  "CARGO_BUILD_JOBS=1"
  "CARGO_INCREMENTAL=0"
  "CARGO_TERM_COLOR=never"
  "RUSTUP_TOOLCHAIN=1.97.1"
  "RUSTC=$pinned_rustc"
  "ALPHA_DIALOGUE_BUILDER_MODEL=$builder_model"
  "ALPHA_DIALOGUE_BUILDER_BASE_URL=$builder_base_url"
  "ALPHA_DIALOGUE_BUILDER_TIMEOUT_SECS=$builder_timeout_secs"
  "ALPHA_DIALOGUE_BUILDER_API_KEY_FILE=$builder_key_copy"
  "ALPHA_DIALOGUE_REVIEWER_MODEL=$reviewer_model"
  "ALPHA_DIALOGUE_REVIEWER_BASE_URL=$reviewer_base_url"
  "ALPHA_DIALOGUE_REVIEWER_TIMEOUT_SECS=$reviewer_timeout_secs"
  "ALPHA_DIALOGUE_REVIEWER_API_KEY_FILE=$reviewer_key_copy"
  "ALPHA_DIALOGUE_CONTRACT_TESTER_MODEL=$contract_tester_model"
  "ALPHA_DIALOGUE_CONTRACT_TESTER_BASE_URL=$contract_tester_base_url"
  "ALPHA_DIALOGUE_CONTRACT_TESTER_TIMEOUT_SECS=$contract_tester_timeout_secs"
  "ALPHA_DIALOGUE_CONTRACT_TESTER_API_KEY_FILE=$tester_key_copy"
)

printf 'v0.5 live acceptance: running exact candidate %s on CPU %s\n' \
  "$candidate_sha" "$acceptance_cpu" >&2
(
  cd -- "$repo_root"
  exec "${live_env[@]}" taskset --cpu-list "$acceptance_cpu" nice -n 10 \
    timeout --signal=TERM --kill-after=30s 1800s \
    "$binary_snapshot" \
      --live \
      --evidence-dir "$evidence_dir" \
      --evidence-signing-key-file "$signing_key_copy" \
      "${forbidden_args[@]}"
) >"$live_log" 2>&1 &
live_pid=$!
group_ready=0
child_exited=0
for ((attempt = 0; attempt < 50; attempt++)); do
  if ! kill -0 -- "$live_pid" 2>/dev/null; then
    child_exited=1
    break
  fi
  candidate_pgid="$(ps -o pgid= -p "$live_pid" 2>/dev/null || true)"
  candidate_pgid="${candidate_pgid//[[:space:]]/}"
  if [[ "$candidate_pgid" == "$live_pid" ]]; then
    live_pgid="$candidate_pgid"
    group_ready=1
    break
  fi
  sleep 0.02
done
if (( group_ready == 0 && child_exited == 0 )); then
  terminate_live_process_group
  die "could not establish a private process group for the live proof"
fi
live_status=0
if wait "$live_pid"; then
  live_status=0
else
  live_status=$?
fi
live_pid=""
live_pgid=""
if (( live_status != 0 )); then
  die "live dialogue proof failed; private transcript was withheld and cleaned"
fi

[[ -d "$evidence_dir" && ! -L "$evidence_dir" ]] || die "live evidence directory is absent"
index_file="$evidence_dir/evidence-index.v1.json"
[[ -f "$index_file" && ! -L "$index_file" ]] || die "evidence index is absent"
index_sha="$(sha256sum "$index_file" | awk '{print $1}')"
[[ "$index_sha" =~ ^[0-9a-f]{64}$ ]] || die "invalid evidence-index digest"
seal_file="$private_root/evidence-seal-${index_sha}.v1.json"
[[ -f "$seal_file" && ! -L "$seal_file" ]] || die "expected signed evidence seal is absent"
mapfile -t seal_files < <(
  find "$private_root" -maxdepth 1 -type f -name 'evidence-seal-*.v1.json' -print
)
(( ${#seal_files[@]} == 1 )) && [[ "${seal_files[0]}" == "$seal_file" ]] ||
  die "live run did not create exactly the expected evidence seal"
jq -e --arg index "$index_sha" --arg signer "$expected_evidence_signer" '
  .seal.index_sha256 == $index and .signer_public_key == $signer
' "$seal_file" >/dev/null || die "evidence seal does not match the pinned index/signer"

# Remove the temporary credential copies before the provider-independent verification process.
rm -f -- "$builder_key_copy" "$reviewer_key_copy" "$tester_key_copy" "$signing_key_copy"

verifier_report="$private_root/offline-verification-report.v1.json"
verifier_error="$private_root/offline-verification-error.log"
verifier_args=(
  verify-live
  --expected-seal-signer "$expected_evidence_signer"
  --candidate-sha "$candidate_sha"
  --packaged-binary "$binary_snapshot"
  --evidence-dir "$evidence_dir"
  --signed-seal "$seal_file"
)
for digest in "${prior_semantics[@]}"; do
  verifier_args+=(--forbid-semantic "$digest")
done
if ! env -i "PATH=$live_path" "LC_ALL=C" "TMPDIR=$private_root/tmp" \
  taskset --cpu-list "$acceptance_cpu" nice -n 10 \
  timeout --signal=TERM --kill-after=10s 300s \
  "$binary_snapshot" "${verifier_args[@]}" >"$verifier_report" 2>"$verifier_error"; then
  die "provider-independent verification refused the live evidence"
fi

jq -e \
  --arg index "$index_sha" \
  --arg binary "$validated_binary_sha" \
  --arg builder_model "$builder_model" \
  --arg reviewer_model "$reviewer_model" \
  --arg tester_model "$contract_tester_model" '
    type == "object"
    and keys == [
      "binary_sha256",
      "builder_model",
      "contract_tester_model",
      "index_sha256",
      "reviewer_model",
      "semantic_sha256"
    ]
    and .index_sha256 == $index
    and .binary_sha256 == $binary
    and (.semantic_sha256 | type == "string" and test("^[0-9a-f]{64}$"))
    and .builder_model == $builder_model
    and .reviewer_model == $reviewer_model
    and .contract_tester_model == $tester_model
  ' "$verifier_report" >/dev/null || die "offline verification report contract failed"
semantic_sha="$(jq -r '.semantic_sha256' "$verifier_report")"
verified_builder_model="$(jq -r '.builder_model' "$verifier_report")"
verified_reviewer_model="$(jq -r '.reviewer_model' "$verifier_report")"
verified_tester_model="$(jq -r '.contract_tester_model' "$verifier_report")"
for digest in "${prior_semantics[@]}"; do
  [[ "$digest" != "$semantic_sha" ]] || die "live semantic was already accepted"
done

[[ "$(sha256sum "$registry_copy" | awk '{print $1}')" == "$registry_sha" ]] ||
  die "prior semantic registry changed during acceptance"
[[ "$(sha256sum "$binary_snapshot" | awk '{print $1}')" == "$validated_binary_sha" ]] ||
  die "validated binary changed during acceptance"
[[ "$(sha256sum "$report_snapshot" | awk '{print $1}')" == "$report_source_sha" ]] ||
  die "validation report changed during acceptance"
require_clean_exact_tree "after live proof and offline verification"

binary_name="dialogue"
seal_name="$(basename -- "$seal_file")"
validation_sha="$report_source_sha"
seal_sha="$(sha256sum "$seal_file" | awk '{print $1}')"
verification_sha="$(sha256sum "$verifier_report" | awk '{print $1}')"
manifest_file="$private_root/acceptance-manifest.v1.json"
jq -n \
  --arg candidate_sha "$candidate_sha" \
  --arg validation_file "local-validation.v1.json" \
  --arg validation_sha "$validation_sha" \
  --arg binary_file "$binary_name" \
  --arg binary_sha "$validated_binary_sha" \
  --arg index_sha "$index_sha" \
  --arg seal_file "$seal_name" \
  --arg seal_sha "$seal_sha" \
  --arg signer "$expected_evidence_signer" \
  --arg verification_sha "$verification_sha" \
  --arg semantic_sha "$semantic_sha" \
  --arg builder_model "$verified_builder_model" \
  --arg reviewer_model "$verified_reviewer_model" \
  --arg tester_model "$verified_tester_model" \
  --arg registry_sha "$registry_sha" \
  --argjson prior_count "$prior_count" \
  --arg encryption_recipient "$encryption_recipient" '
    {
      schema: "alpha.v05-local-live-acceptance-manifest.v1",
      candidate_sha: $candidate_sha,
      local_validation: {
        report_file: $validation_file,
        report_sha256: $validation_sha,
        schema: "alpha.local-validation.v1"
      },
      binary: {file: $binary_file, sha256: $binary_sha},
      evidence: {
        directory: "evidence",
        index_file: "evidence-index.v1.json",
        index_sha256: $index_sha,
        signed_seal_file: $seal_file,
        signed_seal_sha256: $seal_sha,
        expected_signer_public_key: $signer
      },
      offline_verification: {
        report_file: "offline-verification-report.v1.json",
        report_sha256: $verification_sha,
        semantic_sha256: $semantic_sha
      },
      model_configs: {
        source: "sealed model-calls.v1.json via offline verification",
        provider: "openai-compatible",
        builder: {requested_model: $builder_model},
        reviewer: {requested_model: $reviewer_model},
        contract_tester: {requested_model: $tester_model}
      },
      prior_semantic_registry: {sha256: $registry_sha, entries: $prior_count},
      raw_bundle_encryption: {
        format: "OpenPGP",
        recipient_fingerprint: $encryption_recipient
      }
    }
  ' > "$manifest_file"
chmod 0600 "$manifest_file"

raw_stage="$private_root/raw-stage"
safe_stage="$private_root/safe-stage"
install -m 0500 "$binary_snapshot" "$raw_stage/$binary_name"
cp -a -- "$evidence_dir" "$raw_stage/evidence"
install -m 0600 "$seal_file" "$raw_stage/$seal_name"
install -m 0600 "$manifest_file" "$raw_stage/acceptance-manifest.v1.json"
install -m 0600 "$verifier_report" "$raw_stage/offline-verification-report.v1.json"
install -m 0600 "$registry_copy" "$raw_stage/prior-semantic-registry.json"
install -m 0600 "$report_snapshot" "$raw_stage/local-validation.v1.json"
install -m 0600 "$live_log" "$raw_stage/private-runner-transcript.log"

install -m 0500 "$binary_snapshot" "$safe_stage/$binary_name"
install -m 0600 "$index_file" "$safe_stage/evidence-index.v1.json"
install -m 0600 "$seal_file" "$safe_stage/$seal_name"
install -m 0600 "$manifest_file" "$safe_stage/acceptance-manifest.v1.json"
install -m 0600 "$verifier_report" "$safe_stage/offline-verification-report.v1.json"
install -m 0600 "$report_snapshot" "$safe_stage/local-validation.v1.json"
cat > "$safe_stage/README.txt" <<'EOF'
Alpha v0.5 local live-acceptance disclosure-safe verification pack.

This allowlisted pack contains no model prompts, completions, API credentials, operator seed, or
plaintext raw evidence. The signed index authenticates the separately retained encrypted evidence
after decryption; it does not make that private evidence public. The local validation report binds
the exact candidate and dialogue binary but is not a reproducible-build proof.
EOF
chmod 0600 "$safe_stage/README.txt"
(
  cd -- "$safe_stage"
  sha256sum \
    "$binary_name" \
    evidence-index.v1.json \
    "$seal_name" \
    acceptance-manifest.v1.json \
    offline-verification-report.v1.json \
    local-validation.v1.json \
    README.txt > SHA256SUMS
)
chmod 0600 "$safe_stage/SHA256SUMS"
mapfile -t safe_files < <(find "$safe_stage" -mindepth 1 -maxdepth 1 -type f -print)
(( ${#safe_files[@]} == 8 )) || die "disclosure-safe stage has unexpected file count"
if find "$safe_stage" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
  die "disclosure-safe stage contains a non-regular entry"
fi
(
  cd -- "$safe_stage"
  sha256sum --check --strict SHA256SUMS >/dev/null
) || die "disclosure-safe stage failed its own hash manifest"

raw_archive="$private_root/alpha-v05-${candidate_sha}-raw.tar.gz"
safe_archive="$private_root/alpha-v05-${candidate_sha}-verification.tar.gz"
tar --sort=name --owner=0 --group=0 --numeric-owner -C "$raw_stage" -czf "$raw_archive" .
tar --sort=name --owner=0 --group=0 --numeric-owner -C "$safe_stage" -czf "$safe_archive" .
chmod 0600 "$raw_archive" "$safe_archive"

encrypted_archive="$private_root/alpha-v05-${candidate_sha}-raw.tar.gz.gpg"
gpg --batch --yes --quiet --trust-model always \
  --recipient "$encryption_recipient" \
  --output "$encrypted_archive" \
  --encrypt "$raw_archive"
[[ -s "$encrypted_archive" ]] || die "encrypted raw evidence is empty"
gpg --batch --quiet --list-packets "$encrypted_archive" >/dev/null ||
  die "encrypted raw evidence is not a valid OpenPGP packet stream"

# Nothing is exposed outside the private directory until both complete packages exist.
[[ ! -e "$output_dir" && ! -L "$output_dir" ]] ||
  die "output directory appeared during acceptance"
(umask 077; mkdir -- "$output_dir") || die "could not atomically create output directory"
[[ -d "$output_dir" && ! -L "$output_dir" ]] || die "created output directory is invalid"
output_created=1
printf '%s\n' 'alpha-v05-local-live-output-v1' > "$output_dir/.owned"
chmod 0600 "$output_dir/.owned"
encrypted_output="$output_dir/alpha-v05-${candidate_sha}-raw.tar.gz.gpg"
safe_output="$output_dir/alpha-v05-${candidate_sha}-verification.tar.gz"
install -m 0600 "$encrypted_archive" "$encrypted_output"
install -m 0600 "$safe_archive" "$safe_output"
encrypted_sha="$(sha256sum "$encrypted_output" | awk '{print $1}')"
safe_sha="$(sha256sum "$safe_output" | awk '{print $1}')"
[[ "$(sha256sum "$encrypted_archive" | awk '{print $1}')" == "$encrypted_sha" ]] ||
  die "encrypted output changed while it was copied"
[[ "$(sha256sum "$safe_archive" | awk '{print $1}')" == "$safe_sha" ]] ||
  die "verification-pack output changed while it was copied"
mapfile -t output_files < <(find "$output_dir" -mindepth 1 -maxdepth 1 -type f -print)
(( ${#output_files[@]} == 3 )) || die "unexpected output-directory contents"
[[ -f "$encrypted_output" && ! -L "$encrypted_output" ]] || die "encrypted output is invalid"
[[ -f "$safe_output" && ! -L "$safe_output" ]] || die "verification output is invalid"
require_clean_exact_tree "before publishing local acceptance packages"

result_file="$private_root/disclosure-safe-result.v1.json"
jq -cn \
  --arg candidate_sha "$candidate_sha" \
  --arg index "$index_sha" \
  --arg semantic "$semantic_sha" \
  --arg binary "$validated_binary_sha" \
  --arg validation_sha "$validation_sha" \
  --arg signer "$expected_evidence_signer" \
  --arg builder_model "$verified_builder_model" \
  --arg reviewer_model "$verified_reviewer_model" \
  --arg tester_model "$verified_tester_model" \
  --arg encrypted_file "$(basename -- "$encrypted_output")" \
  --arg encrypted_sha "$encrypted_sha" \
  --arg safe_file "$(basename -- "$safe_output")" \
  --arg safe_sha "$safe_sha" '
    {
      schema: "alpha.v05-local-live-acceptance-result.v1",
      status: "packaged",
      candidate_sha: $candidate_sha,
      local_validation_report_sha256: $validation_sha,
      evidence_index_sha256: $index,
      evidence_signer: $signer,
      semantic_sha256: $semantic,
      binary_sha256: $binary,
      builder_model: $builder_model,
      reviewer_model: $reviewer_model,
      contract_tester_model: $tester_model,
      encrypted_raw: {file: $encrypted_file, sha256: $encrypted_sha},
      verification_pack: {file: $safe_file, sha256: $safe_sha}
    }
  ' > "$result_file"
chmod 0600 "$result_file"
result_json="$(<"$result_file")" || die "could not read the disclosure-safe result"

# Cleanup is part of the product gate. Remove the prompt/key-bearing private tree before making the
# packages permanent or emitting success; on failure the EXIT trap still owns and retracts outputs.
if [[ ! -f "$private_root/.owned" ]] ||
   [[ "$(<"$private_root/.owned")" != "alpha-v05-local-live-private-v1" ]]; then
  die "private cleanup ownership check failed before success publication"
fi
chmod -R u+rwX "$private_root" || die "could not make private acceptance state removable"
rm -rf -- "$private_root" || die "could not remove private acceptance state"
private_root=""

# There are no child processes or secrets left. Ignore termination during the two-command output
# commit so no signal can land between marker removal and the ownership-state transition.
trap '' HUP INT TERM
rm -f -- "$output_dir/.owned"
output_created=0
trap - EXIT HUP INT TERM
printf '%s\n' "$result_json"
