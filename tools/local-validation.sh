#!/usr/bin/env bash
# Exhaustive local validation for a frozen Alpha candidate.
#
# Hosted CI should stay a small, credential-free sanity check. This gate is the heavyweight proof:
# it mirrors the former full CI matrix on one allowed CPU and reuses one workspace target tree. The
# only separate build tree it permits is Alpha's intentional authoring cache at
# target/gawd-build-cache, selected internally by the authoring paths themselves.
set -euo pipefail
IFS=$'\n\t'

usage() {
  cat <<'EOF'
Usage: tools/local-validation.sh [--exact-commit <40-lowercase-hex-sha>]
                                 [--output-dir <absolute-new-directory>]

Run Alpha's complete credential-free validation gate locally. With --exact-commit, the gate also
requires HEAD to equal that object ID and the tracked/untracked/submodule-aware worktree to be clean
both before and after validation. --output-dir requires --exact-commit; after validation it creates
a mode-0700 directory outside the checkout containing local-validation.v1.json and the exact
mode-0500 OpenAI-enabled dialogue binary prepared for the separate live-proof command.
EOF
}

die() {
  printf 'local validation: %s\n' "$*" >&2
  exit 1
}

expected_commit=""
requested_output_dir=""
exact_commit_seen=0
output_dir_seen=0
readonly original_argument_count=$#
while (($# > 0)); do
  case "$1" in
    --exact-commit)
      (($# >= 2)) || die "--exact-commit requires an argument"
      ((exact_commit_seen == 0)) || die "--exact-commit was supplied more than once"
      exact_commit_seen=1
      expected_commit="$2"
      shift 2
      ;;
    --output-dir)
      (($# >= 2)) || die "--output-dir requires an argument"
      ((output_dir_seen == 0)) || die "--output-dir was supplied more than once"
      output_dir_seen=1
      requested_output_dir="$2"
      shift 2
      ;;
    -h|--help)
      ((original_argument_count == 1)) ||
        die "--help cannot be combined with validation arguments"
      usage
      exit 0
      ;;
    *)
      usage >&2
      exit 2
      ;;
  esac
done

if ((exact_commit_seen == 1)) && [[ ! "$expected_commit" =~ ^[0-9a-f]{40}$ ]]; then
  die "--exact-commit requires one full lowercase 40-hex object ID"
fi
if ((output_dir_seen == 1)) && [[ -z "$requested_output_dir" ]]; then
  die "--output-dir requires a non-empty path"
fi
if ((output_dir_seen == 1 && exact_commit_seen == 0)); then
  die "--output-dir requires --exact-commit"
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)" ||
  die "could not resolve the script directory"
readonly script_dir
repo_root="$(cd -- "$script_dir/.." && pwd -P)" ||
  die "could not resolve the repository directory"
readonly repo_root
cd -- "$repo_root"

actual_root="$(git rev-parse --show-toplevel)" ||
  die "could not resolve the repository root"
[[ "$(cd -- "$actual_root" && pwd -P)" == "$repo_root" ]] ||
  die "this script must run from its Alpha checkout"

for required_command in awk bash basename cargo cargo-deny chmod dirname env find flock git grep \
  install jq mkdir mktemp mv nice ps realpath rm rustc rustup sed sha256sum sort stat taskset \
  timeout; do
  command -v "$required_command" >/dev/null 2>&1 ||
    die "required command not found: $required_command"
done

[[ -z "${CARGO_BUILD_TARGET:-}" ]] ||
  die "CARGO_BUILD_TARGET must be unset for the native-host release gate"
ambient_profile_overrides="$(env | sed -n 's/^\(CARGO_PROFILE_[^=]*\)=.*/\1/p')" ||
  die "could not inspect Cargo profile overrides"
[[ -z "$ambient_profile_overrides" ]] || {
  printf '%s\n' "$ambient_profile_overrides" >&2
  die "caller-supplied CARGO_PROFILE_* overrides are not allowed"
}
for compiler_override in CARGO_BUILD_RUSTC CARGO_BUILD_RUSTDOC \
  CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER; do
  [[ -z "${!compiler_override:-}" ]] ||
    die "$compiler_override must be unset for the pinned release toolchain"
done
ambient_target_tools="$(env | sed -n 's/^\(CARGO_TARGET_.*_\(RUNNER\|LINKER\)\)=.*/\1/p')" ||
  die "could not inspect Cargo target-tool overrides"
[[ -z "$ambient_target_tools" ]] || {
  printf '%s\n' "$ambient_target_tools" >&2
  die "Cargo target runners/linkers must be unset for native execution"
}

# Cargo merges config from checkout ancestors and CARGO_HOME. Registry/network policy is allowed,
# but machine-local compiler/target/runner/flag selection would make target/debug or test execution
# ambiguous. Refuse those semantic build keys rather than silently validating a different posture.
declare -a cargo_configs=()
for config_name in .cargo/config.toml .cargo/config; do
  [[ ! -e "$repo_root/$config_name" ]] || cargo_configs+=("$repo_root/$config_name")
done
config_search_dir="$(dirname -- "$repo_root")"
while :; do
  for config_name in .cargo/config.toml .cargo/config; do
    [[ ! -e "$config_search_dir/$config_name" ]] ||
      cargo_configs+=("$config_search_dir/$config_name")
  done
  [[ "$config_search_dir" != / ]] || break
  config_search_dir="$(dirname -- "$config_search_dir")"
done
cargo_home_dir="${CARGO_HOME:-${HOME:?HOME is required when CARGO_HOME is unset}/.cargo}"
for config_name in config.toml config; do
  [[ ! -e "$cargo_home_dir/$config_name" ]] ||
    cargo_configs+=("$cargo_home_dir/$config_name")
done
for cargo_config in "${cargo_configs[@]}"; do
  [[ -f "$cargo_config" && -r "$cargo_config" ]] ||
    die "Cargo config is not a readable regular file: $cargo_config"
  config_violations="$(
    grep -inE \
      "^[[:space:]]*\[profile(\.|\])|^[[:space:]]*profile[[:space:]]*\.|^[[:space:]]*env[[:space:]]*\.|^[[:space:]]*(([A-Za-z0-9_.-]+)[[:space:]]*\.[[:space:]]*)?(target|runner|linker|rustc|rustdoc|rustflags|rustdocflags|rustc-wrapper|rustc-workspace-wrapper|rustc_bootstrap|alpha_(llm|dialogue)_[a-z0-9_]+|cargo_(build|target|encoded|profile)_[a-z0-9_]+)[[:space:]]*=" \
      "$cargo_config" || true
  )"
  [[ -z "$config_violations" ]] || {
    printf '%s\n' "$cargo_config" "$config_violations" >&2
    die "Cargo config selects release build semantics"
  }
  allow_serial_env=false
  [[ "$cargo_config" != "$repo_root/.cargo/config.toml" ]] || allow_serial_env=true
  env_violations="$(
    awk -v allow_serial="$allow_serial_env" '
      /^[[:space:]]*\[env\][[:space:]]*(#.*)?$/ { in_env = 1; next }
      /^[[:space:]]*\[/ { in_env = 0 }
      in_env && $0 !~ /^[[:space:]]*(#|$)/ {
        if (allow_serial == "true" \
            && $0 ~ /^[[:space:]]*RUST_TEST_THREADS[[:space:]]*=[[:space:]]*\{[[:space:]]*value[[:space:]]*=[[:space:]]*"1"[[:space:]]*,[[:space:]]*force[[:space:]]*=[[:space:]]*false[[:space:]]*\}[[:space:]]*(#.*)?$/) {
          next
        }
        print NR ":" $0
      }
    ' "$cargo_config"
  )" || die "could not inspect Cargo [env] entries in $cargo_config"
  [[ -z "$env_violations" ]] || {
    printf '%s\n' "$cargo_config" "$env_violations" >&2
    die "Cargo config contains a non-allowlisted [env] entry"
  }
done

# Ignore ambient compiler/toolchain selection. Resolve the exact checked-in channel through rustup,
# then put that toolchain's real binaries ahead of PATH for every phase. This prevents a caller's
# RUSTUP_TOOLCHAIN, RUSTC, RUSTDOC, or encoded flags from making an authoritative report describe a
# different compiler than the one that actually ran.
unset RUSTUP_TOOLCHAIN RUSTC RUSTDOC RUSTFLAGS RUSTDOCFLAGS RUSTC_BOOTSTRAP
# Empty encoded flags are an explicit highest-precedence override; merely unsetting them would
# expose target/build rustflags from a caller's Cargo environment or user-level config.
export CARGO_ENCODED_RUSTFLAGS=""
export CARGO_ENCODED_RUSTDOCFLAGS=""
unset CARGO_PROFILE_DEV_PANIC CARGO_PROFILE_TEST_PANIC CARGO_PROFILE_RELEASE_PANIC
mapfile -t pinned_channel_lines < <(
  sed -n 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"\([^"]*\)"[[:space:]]*$/\1/p' \
    rust-toolchain.toml
)
((${#pinned_channel_lines[@]} == 1)) ||
  die "rust-toolchain.toml must contain exactly one literal channel"
readonly pinned_channel="${pinned_channel_lines[0]}"
[[ "$pinned_channel" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
  die "rust-toolchain.toml must pin an exact Rust release"
export RUSTUP_TOOLCHAIN="$pinned_channel"
toolchain_cargo="$(rustup which --toolchain "$pinned_channel" cargo)" ||
  die "could not resolve Cargo for pinned Rust $pinned_channel"
toolchain_rustc="$(rustup which --toolchain "$pinned_channel" rustc)" ||
  die "could not resolve rustc for pinned Rust $pinned_channel"
toolchain_rustdoc="$(rustup which --toolchain "$pinned_channel" rustdoc)" ||
  die "could not resolve rustdoc for pinned Rust $pinned_channel"
toolchain_bin="$(cd -- "$(dirname -- "$toolchain_cargo")" && pwd -P)" ||
  die "could not resolve the pinned Rust binary directory"
[[ "$toolchain_rustc" == "$toolchain_bin/rustc" &&
   "$toolchain_rustdoc" == "$toolchain_bin/rustdoc" ]] ||
  die "pinned Rust components did not resolve from one toolchain directory"
export PATH="$toolchain_bin:$PATH"
hash -r
[[ "$(command -v cargo)" == "$toolchain_cargo" &&
   "$(command -v rustc)" == "$toolchain_rustc" &&
   "$(command -v rustdoc)" == "$toolchain_rustdoc" ]] ||
  die "could not activate the pinned Rust binaries"

start_head="$(git rev-parse --verify 'HEAD^{commit}')" ||
  die "could not resolve HEAD"
[[ "$start_head" =~ ^[0-9a-f]{40}$ ]] || die "HEAD did not resolve to a full object ID"

mapfile -t release_version_lines < <(
  sed -n 's/^VERSION=\(v[0-9][0-9A-Za-z.+-]*\)$/\1/p' RELEASE.md
)
((${#release_version_lines[@]} == 1)) ||
  die "RELEASE.md must contain exactly one literal VERSION=v... assignment"
readonly release_version="${release_version_lines[0]}"
[[ "$release_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] ||
  die "RELEASE.md has an invalid VERSION: $release_version"
readonly release_semver="${release_version#v}"
mapfile -t release_date_lines < <(
  sed -n 's/^RELEASE_DATE=\([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]\)$/\1/p' \
    RELEASE.md
)
((${#release_date_lines[@]} == 1)) ||
  die "RELEASE.md must contain exactly one literal RELEASE_DATE=YYYY-MM-DD assignment"
readonly release_date="${release_date_lines[0]}"
workspace_version="$(awk '
  /^\[workspace\.package\][[:space:]]*$/ { in_workspace_package = 1; next }
  /^\[/ { in_workspace_package = 0 }
  in_workspace_package && /^[[:space:]]*version[[:space:]]*=/ {
    line = $0
    sub(/^[^=]*=[[:space:]]*"/, "", line)
    sub(/".*$/, "", line)
    print line
  }
' Cargo.toml)" || die "could not read the workspace version"
[[ "$workspace_version" == "$release_semver" ]] ||
  die "Cargo.toml version $workspace_version does not match RELEASE.md $release_version"
grep -Fqx "## $release_semver - $release_date" CHANGELOG.md ||
  die "CHANGELOG.md does not contain the exact dated release heading"
if grep -Eq '^##[[:space:]]+Unreleased([[:space:]]|$)' CHANGELOG.md; then
  die "CHANGELOG.md still contains an Unreleased release heading"
fi

mapfile -t previous_version_lines < <(
  sed -n 's/^PREVIOUS_VERSION=\(v[0-9][0-9A-Za-z.+-]*\)$/\1/p' RELEASE.md
)
((${#previous_version_lines[@]} == 1)) ||
  die "RELEASE.md must contain exactly one literal PREVIOUS_VERSION=v... assignment"
readonly previous_version="${previous_version_lines[0]}"
[[ "$previous_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.+-][0-9A-Za-z.-]+)?$ ]] ||
  die "RELEASE.md has an invalid PREVIOUS_VERSION: $previous_version"
git rev-parse --verify --quiet "refs/tags/$previous_version^{commit}" >/dev/null ||
  die "the PREVIOUS_VERSION tag is not available locally: $previous_version"
git merge-base --is-ancestor "refs/tags/$previous_version^{commit}" HEAD ||
  die "HEAD is not descended from PREVIOUS_VERSION $previous_version"

canonical_output_dir=""
if [[ -n "$requested_output_dir" ]]; then
  [[ "$requested_output_dir" == /* && "$requested_output_dir" != / ]] ||
    die "--output-dir must be an absolute, non-root path"
  [[ "$requested_output_dir" != *$'\n'* && "$requested_output_dir" != *$'\r'* ]] ||
    die "--output-dir must not contain line breaks"
  while [[ "$requested_output_dir" != / && "$requested_output_dir" == */ ]]; do
    requested_output_dir="${requested_output_dir%/}"
  done
  output_name="${requested_output_dir##*/}"
  output_parent="${requested_output_dir%/*}"
  [[ -n "$output_parent" ]] || output_parent=/
  [[ "$output_name" != . && "$output_name" != .. && -n "$output_name" ]] ||
    die "--output-dir must name a new child directory"
  canonical_output_parent="$(cd -- "$output_parent" && pwd -P)" ||
    die "the --output-dir parent must already exist"
  canonical_output_dir="$canonical_output_parent/$output_name"
  [[ "$canonical_output_dir" != "$repo_root" &&
     "$canonical_output_dir" != "$repo_root/"* ]] ||
    die "--output-dir must be outside the checkout"
  [[ ! -e "$canonical_output_dir" && ! -L "$canonical_output_dir" ]] ||
    die "--output-dir must not already exist: $canonical_output_dir"
fi

tree_status() {
  git status --porcelain=v1 --untracked-files=normal --ignore-submodules=none
}

require_exact_tree() {
  local when="$1" current_head current_status
  current_head="$(git rev-parse --verify 'HEAD^{commit}')" ||
    die "could not resolve HEAD $when validation"
  [[ "$current_head" == "$expected_commit" ]] ||
    die "HEAD $when validation is $current_head, expected $expected_commit"
  current_status="$(tree_status)" ||
    die "could not inspect the worktree $when validation"
  [[ -z "$current_status" ]] || {
    printf '%s\n' "$current_status" >&2
    die "worktree is not clean $when validation"
  }
}

if [[ -n "$expected_commit" ]]; then
  require_exact_tree "before"
else
  printf 'local validation: validating working tree at HEAD %s (exact-clean mode is off)\n' \
    "$start_head"
fi

# Serialize this gate across worktrees sharing a Git directory. The retained empty lock file lives
# under Git metadata, not the source tree or target/, and prevents two local full gates from
# concurrently multiplying Wasmtime artifacts.
git_common_dir="$(git rev-parse --path-format=absolute --git-common-dir)" ||
  die "could not resolve the Git common directory"
readonly gate_lock="$git_common_dir/alpha-local-validation.lock"
exec {gate_lock_fd}>"$gate_lock" || die "could not open validation lock $gate_lock"
flock -n "$gate_lock_fd" || die "another local validation gate is already running"

# AGENTS.md requires checking for an active compiler before every new Cargo sequence. Once this
# check passes, the lock above prevents another instance of this gate from starting alongside it.
assert_no_active_compiler() {
  local compiler_processes
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
}

allowed_cpus="$(LC_ALL=C taskset -pc $$)" || die "could not inspect the allowed CPU set"
allowed_cpus="${allowed_cpus##*: }"
validation_cpu="${allowed_cpus%%,*}"
validation_cpu="${validation_cpu%%-*}"
[[ "$validation_cpu" =~ ^[0-9]+$ ]] ||
  die "could not select the first CPU from allowed set '$allowed_cpus'"
taskset --cpu-list "$validation_cpu" true ||
  die "selected CPU $validation_cpu is not available to this process"
readonly validation_cpu

# Match the constrained hosted profile and explicitly disable ambient compiler wrappers/caches.
# Cargo's normal registry/git download stores and workspace target/ are ordinary inputs/outputs;
# this script creates no additional compilation cache and cleans only rendered rustdoc.
export CARGO_BUILD_JOBS=1
export CARGO_INCREMENTAL=0
export CARGO_PROFILE_DEV_DEBUG=0
export CARGO_PROFILE_TEST_DEBUG=0
# Neutralize machine-local profile overrides. A separate tracked-source invariant below ensures a
# candidate cannot hide panic=abort behind this safe execution posture.
export CARGO_PROFILE_DEV_PANIC=unwind
export CARGO_PROFILE_TEST_PANIC=unwind
export CARGO_PROFILE_RELEASE_PANIC=unwind
export CARGO_TERM_COLOR=always
export RUST_TEST_THREADS=1
export CARGO_TARGET_DIR="$repo_root/target"
# Empty wrapper values explicitly override user/global Cargo config; merely unsetting them would
# permit a global sccache configuration to introduce an unaccounted compilation cache.
export RUSTC_WRAPPER=""
export RUSTC_WORKSPACE_WRAPPER=""
unset SCCACHE_DIR SCCACHE_CACHE_SIZE SCCACHE_IDLE_TIMEOUT

# This gate is deliberately credential-free. Live provider configuration belongs to the separate
# proof command and must never make a hermetic validation phase capable of contacting a model.
unset ALPHA_LLM_API_KEY ALPHA_LLM_BASE_URL ALPHA_LLM_MAX_ATTEMPTS ALPHA_LLM_MODEL \
  ALPHA_LLM_TIMEOUT_SECS
unset ALPHA_DIALOGUE_BUILD_COMMIT
for model_role in BUILDER REVIEWER CONTRACT_TESTER; do
  unset "ALPHA_DIALOGUE_${model_role}_API_KEY" \
    "ALPHA_DIALOGUE_${model_role}_API_KEY_FILE" \
    "ALPHA_DIALOGUE_${model_role}_BASE_URL" \
    "ALPHA_DIALOGUE_${model_role}_MODEL" \
    "ALPHA_DIALOGUE_${model_role}_TIMEOUT_SECS"
done

readonly overall_limit_seconds=21600
readonly validation_start_seconds=$SECONDS
phase_number=0
declare -a phase_names=()

run_phase() {
  local label="$1" requested_limit="$2" remaining effective_limit status elapsed
  shift 2
  [[ "$requested_limit" =~ ^[1-9][0-9]*$ ]] || die "invalid timeout for phase '$label'"

  elapsed=$((SECONDS - validation_start_seconds))
  remaining=$((overall_limit_seconds - elapsed))
  ((remaining > 0)) || die "the six-hour validation deadline expired before '$label'"
  effective_limit="$requested_limit"
  ((effective_limit <= remaining)) || effective_limit="$remaining"
  phase_number=$((phase_number + 1))
  phase_names+=("$label")

  printf '\n[%02d] %s (CPU %s, timeout %ss)\n' \
    "$phase_number" "$label" "$validation_cpu" "$effective_limit"
  assert_no_active_compiler
  if taskset --cpu-list "$validation_cpu" nice -n 10 \
      timeout --signal=TERM --kill-after=45s "${effective_limit}s" "$@"; then
    printf '[%02d] passed: %s\n' "$phase_number" "$label"
  else
    status=$?
    printf '[%02d] FAILED (%s): %s\n' "$phase_number" "$status" "$label" >&2
    return "$status"
  fi
}

toolchain_snapshot="$(umask 077; mktemp \
  "$git_common_dir/alpha-local-validation-toolchain.XXXXXXXX")" ||
  die "could not create the private toolchain snapshot"
[[ -f "$toolchain_snapshot" && ! -L "$toolchain_snapshot" ]] ||
  die "private toolchain snapshot is not a regular file"
cleanup_toolchain_snapshot() {
  local original_status="$?" cleanup_status=0
  trap - EXIT
  if [[ -n "${toolchain_snapshot:-}" ]]; then
    rm -f -- "$toolchain_snapshot" || cleanup_status=$?
  fi
  if ((original_status == 0 && cleanup_status != 0)); then
    original_status="$cleanup_status"
  fi
  exit "$original_status"
}
trap cleanup_toolchain_snapshot EXIT

run_phase "Pinned Rust toolchain and components" 300 bash -c '
  set -euo pipefail
  rustup show
  active_toolchain_full="$(rustup show active-toolchain)"
  active_toolchain="${active_toolchain_full%% *}"
  test -n "$active_toolchain"
  case "$active_toolchain" in
    *[!A-Za-z0-9._-]*) echo "invalid active toolchain token" >&2; exit 1 ;;
  esac
  rustc_verbose="$(rustc --version --verbose)"
  cargo_verbose="$(cargo --version --verbose)"
  toolchain_file_sha256="$(sha256sum rust-toolchain.toml)"
  toolchain_file_sha256="${toolchain_file_sha256%% *}"
  jq -cnS \
    --arg active "$active_toolchain" \
    --arg rustc "$rustc_verbose" \
    --arg cargo "$cargo_verbose" \
    --arg toolchain_file_sha256 "$toolchain_file_sha256" \
    "{active_toolchain:\$active,rustc_verbose:\$rustc,cargo_verbose:\$cargo,rust_toolchain_toml_sha256:\$toolchain_file_sha256}" \
    >"$1"
' _ "$toolchain_snapshot"
toolchain_json="$(<"$toolchain_snapshot")" || die "could not read toolchain metadata"
jq -e '
  type == "object"
  and (keys == ["active_toolchain", "cargo_verbose", "rust_toolchain_toml_sha256", "rustc_verbose"])
  and (.active_toolchain | type == "string" and length > 0)
  and (.cargo_verbose | type == "string" and length > 0)
  and (.rustc_verbose | type == "string" and length > 0)
  and (.rust_toolchain_toml_sha256 | test("^[0-9a-f]{64}$"))
' <<EOF >/dev/null || die "toolchain metadata is invalid"
$toolchain_json
EOF

toolchain_release="$(jq -r \
  '.rustc_verbose | capture("(^|\\n)release: (?<v>[^\\n]+)").v' \
  <<<"$toolchain_json")" || die "could not read the active rustc release"
[[ "$toolchain_release" == "$pinned_channel" ]] ||
  die "active rustc release $toolchain_release does not match pinned $pinned_channel"

run_phase "Native safety source invariants" 120 bash -c '
  set -euo pipefail
  panic_violations="$(
    while IFS= read -r -d "" cargo_file; do
      normalized="$(
        sed "s/[[:space:]]*#.*$//" "$cargo_file" | tr -d "[:space:]\\042\\047"
      )"
      case "$normalized" in
        *panic=abort*) printf "%s\n" "$cargo_file" ;;
      esac
    done < <(
      find . -path ./target -prune -o \
        \( -name Cargo.toml -o -path "./.cargo/*.toml" -o -path "./.cargo/config" \) \
        -type f -print0
    )
  )"
  if test -n "$panic_violations"; then
    printf "%s\n" "$panic_violations" >&2
    echo "tracked Cargo configuration enables panic=abort" >&2
    exit 1
  fi
  allocator_violations="$(
    find . -path ./target -prune -o -name "*.rs" -type f \
      -exec grep -HnF "global_allocator" {} + || true
  )"
  if test -n "$allocator_violations"; then
    printf "%s\n" "$allocator_violations" >&2
    echo "tracked Rust source declares a global allocator" >&2
    exit 1
  fi
'

run_phase "Wasmtime serial-compilation invariant" 120 bash -c '
  set -euo pipefail
  declarations="$(find . -path ./target -prune -o -name Cargo.toml -type f \
    -exec grep -lE "^[[:space:]]*wasmtime[[:space:]]*=" {} + | LC_ALL=C sort)"
  test "$declarations" = "./cosmos/anima/Cargo.toml"
  grep -Fqx \
    "wasmtime = { version = \"46.0.2\", default-features = false, features = [\"cranelift\", \"runtime\"] }" \
    cosmos/anima/Cargo.toml
  if grep -Eq "^name = \"rayon(-core)?\"$" Cargo.lock; then
    echo "Rayon entered Cargo.lock; refusing a compiler pool outside the one-CPU boundary" >&2
    exit 1
  fi
'

run_phase "Formatting" 300 cargo fmt --all --check

run_phase "Patch hygiene" 120 bash -c '
  set -euo pipefail
  git diff --check
  git diff --cached --check
  git diff --check "$1"..HEAD --
' _ "$previous_version"

run_phase "Operator and cluster script syntax" 120 bash -c '
  set -euo pipefail
  shopt -s nullglob
  scripts=(demos/cluster/*.sh tools/*.sh)
  ((${#scripts[@]} > 0))
  for script in "${scripts[@]}"; do
    test -x "$script"
    bash -n "$script"
  done
'

run_phase "Locked dependency graph" 300 bash -c \
  'cargo metadata --locked --no-deps --format-version 1 >/dev/null'

run_phase "Dependency, license, and source policy (all features)" 900 \
  cargo deny --all-features check

run_phase "Workspace Clippy (all targets, warnings denied)" 3600 \
  cargo clippy --locked --workspace --all-targets -- -D warnings

run_phase "Workspace build" 3600 cargo build --locked --workspace

# ci-smoke.sh creates the final component atomically and owns exact-incarnation teardown. The parent
# is private, fresh, and deliberately outside demos/cluster/run so this gate cannot adopt an
# operator's nodes. Keep failed diagnostics; remove the private parent only after a successful run.
temp_parent="$(cd -- "${TMPDIR:-/tmp}" && pwd -P)" ||
  die "could not resolve the temporary-directory parent"
cluster_parent="$(mktemp -d "$temp_parent/alpha-local-validation.XXXXXXXX")" ||
  die "could not create a private cluster diagnostics parent"
[[ -d "$cluster_parent" && ! -L "$cluster_parent" &&
   "$(basename -- "$cluster_parent")" == alpha-local-validation.* ]] ||
  die "mktemp returned an unsafe cluster diagnostics parent: $cluster_parent"
cluster_run="$cluster_parent/cluster"

if run_phase "Cluster behavior (boot, gossip, cross-run, remote MCP)" 240 \
    env -u A_REALM \
      -u A_HOST -u A_CPORT -u A_APORT -u A_KEY -u A_SEED \
      -u B_HOST -u B_CPORT -u B_APORT -u B_KEY -u B_SEED \
      -u C_HOST -u C_CPORT -u C_APORT -u C_KEY -u C_SEED \
      -u MCP_HUB_ID -u MCP_HUB_HOST -u MCP_HUB_CPORT -u MCP_HUB_SEED -u MCP_HUB_PUB \
      -u CLUSTER_CURL_CONNECT_TIMEOUT -u CLUSTER_CURL_MAX_TIME \
      ALPHA_CLUSTER_RUN="$cluster_run" \
      BIN="$repo_root/target/debug/alpha" \
      MCP="$repo_root/target/debug/alpha" \
      OMEGA="$repo_root/target/debug/omega" \
      demos/cluster/ci-smoke.sh; then
  # Only remove this invocation's mktemp-created diagnostics after ci-smoke's teardown succeeded.
  rm -rf -- "$cluster_parent"
  cluster_parent=""
else
  status=$?
  printf 'cluster diagnostics retained at %s\n' "$cluster_parent" >&2
  exit "$status"
fi

run_phase "Strict workspace rustdoc" 2700 \
  env -u CARGO_ENCODED_RUSTDOCFLAGS RUSTDOCFLAGS="-D warnings" \
    cargo doc --locked --workspace --no-deps
run_phase "Reclaim rendered rustdoc only" 300 cargo clean --doc

run_phase "Full workspace tests (serial)" 5400 \
  cargo test --locked --workspace -- --test-threads=1

run_phase "Alpha entry point" 120 cargo run --locked -p alpha -- version
run_phase "Omega entry point" 120 cargo run --locked -p omega -- version

run_phase "Walkthrough demo" 1200 cargo run --locked -p walkthrough
run_phase "Federation demo" 300 cargo run --locked -p federation
run_phase "Distribute demo" 600 cargo run --locked -p distribute
run_phase "Dialogue all-tier fixture" 600 target/debug/dialogue --fixture

run_phase "OpenAI cfg: agent-mind Clippy" 1800 \
  cargo clippy --locked -p agent-mind --all-targets --features openai -- -D warnings
run_phase "OpenAI cfg: alpha Clippy" 1800 \
  cargo clippy --locked -p alpha --features openai -- -D warnings
run_phase "OpenAI cfg: bestiary-live Clippy" 1800 \
  cargo clippy --locked -p bestiary-live --all-targets --features openai -- -D warnings
run_phase "OpenAI cfg: dialogue Clippy" 1800 \
  cargo clippy --locked -p dialogue --all-targets --features openai -- -D warnings
run_phase "OpenAI cfg: agent-mind tests" 1800 \
  cargo test --locked -p agent-mind --features openai -- --test-threads=1
run_phase "OpenAI cfg: dialogue tests" 1800 \
  cargo test --locked -p dialogue --features openai -- --test-threads=1
run_phase "Bestiary no-credential startup" 300 \
  env -u ALPHA_LLM_MODEL -u ALPHA_LLM_API_KEY \
    cargo run --locked -p bestiary-live --features openai

if [[ -n "$canonical_output_dir" ]]; then
  run_phase "Prepare exact-commit OpenAI dialogue binary" 3600 \
    env ALPHA_DIALOGUE_BUILD_COMMIT="$expected_commit" \
      cargo build --locked -p dialogue --features openai
fi

end_head="$(git rev-parse --verify 'HEAD^{commit}')" ||
  die "could not resolve HEAD after validation"
[[ "$end_head" == "$start_head" ]] ||
  die "HEAD changed during validation ($start_head -> $end_head)"
if [[ -n "$expected_commit" ]]; then
  require_exact_tree "after"
fi

if [[ -n "$canonical_output_dir" ]]; then
  source_binary="$repo_root/target/debug/dialogue"
  [[ -f "$source_binary" && ! -L "$source_binary" && -x "$source_binary" ]] ||
    die "prepared dialogue binary is not a regular executable: $source_binary"

  (umask 077; mkdir --mode=0700 -- "$canonical_output_dir") ||
    die "could not atomically create --output-dir: $canonical_output_dir"
  [[ -d "$canonical_output_dir" && ! -L "$canonical_output_dir" ]] ||
    die "created output path is not a real directory"
  [[ "$(stat -c '%a' -- "$canonical_output_dir")" == 700 ]] ||
    die "created output directory does not have mode 0700"

  packaged_binary="$canonical_output_dir/dialogue"
  install --mode=0500 -- "$source_binary" "$packaged_binary" ||
    die "could not copy the prepared dialogue binary"
  [[ -f "$packaged_binary" && ! -L "$packaged_binary" && -x "$packaged_binary" ]] ||
    die "copied dialogue binary is not a regular executable"
  [[ "$(stat -c '%a' -- "$packaged_binary")" == 500 ]] ||
    die "copied dialogue binary does not have mode 0500"
  packaged_binary="$(realpath -e -- "$packaged_binary")" ||
    die "could not canonicalize the copied dialogue binary"
  [[ "$packaged_binary" == "$canonical_output_dir/dialogue" ]] ||
    die "copied dialogue binary escaped the output directory"

  source_binary_sha256="$(sha256sum -- "$source_binary")" ||
    die "could not hash the built dialogue binary"
  source_binary_sha256="${source_binary_sha256%% *}"
  packaged_binary_sha256="$(sha256sum -- "$packaged_binary")" ||
    die "could not hash the copied dialogue binary"
  packaged_binary_sha256="${packaged_binary_sha256%% *}"
  [[ "$packaged_binary_sha256" =~ ^[0-9a-f]{64}$ &&
     "$packaged_binary_sha256" == "$source_binary_sha256" ]] ||
    die "copied dialogue binary does not match the validated build output"

  phases_json="$(printf '%s\n' "${phase_names[@]}" | jq -Rsc 'split("\n")[:-1]')" ||
    die "could not encode the validation phase list"
  [[ "$(jq 'length' <<<"$phases_json")" == "$phase_number" ]] ||
    die "validation phase count does not match its phase list"

  report_path="$canonical_output_dir/local-validation.v1.json"
  report_temp="$canonical_output_dir/.local-validation.v1.json.tmp"
  (umask 077; jq -cnS \
    --arg schema "alpha.local-validation.v1" \
    --arg candidate_sha "$expected_commit" \
    --arg status "passed" \
    --arg binary_file "dialogue" \
    --arg binary_sha256 "$packaged_binary_sha256" \
    --arg script "tools/local-validation.sh" \
    --arg release_version "$release_version" \
    --arg release_date "$release_date" \
    --arg previous_version "$previous_version" \
    --arg start_head "$start_head" \
    --arg end_head "$end_head" \
    --argjson selected_cpu "$validation_cpu" \
    --argjson phase_count "$phase_number" \
    --argjson phases "$phases_json" \
    --argjson overall_timeout_seconds "$overall_limit_seconds" \
    --argjson toolchain "$toolchain_json" \
    '{
      schema: $schema,
      candidate_sha: $candidate_sha,
      status: $status,
      binary: {file: $binary_file, sha256: $binary_sha256},
      gate: {
        script: $script,
        release_version: $release_version,
        release_date: $release_date,
        previous_version: $previous_version,
        start_head: $start_head,
        end_head: $end_head,
        selected_cpu: $selected_cpu,
        overall_timeout_seconds: $overall_timeout_seconds,
        phase_count: $phase_count,
        phases: $phases,
        constraints: {
          cargo_build_jobs: 1,
          cargo_incremental: false,
          rust_test_threads: 1,
          compiler_wrappers: false
        }
      },
      toolchain: $toolchain
    }' >"$report_temp") || die "could not write the local validation report"
  chmod 0600 -- "$report_temp" || die "could not set validation report mode"
  mv -T -- "$report_temp" "$report_path" || die "could not publish the validation report"
  [[ -f "$report_path" && ! -L "$report_path" ]] ||
    die "validation report is not a regular file"
  [[ "$(stat -c '%a' -- "$report_path")" == 600 ]] ||
    die "validation report does not have mode 0600"

  jq -e \
    --arg candidate "$expected_commit" \
    --arg sha "$packaged_binary_sha256" \
    --argjson phases "$phase_number" '
      .schema == "alpha.local-validation.v1"
      and .candidate_sha == $candidate
      and .status == "passed"
      and .binary == {file: "dialogue", sha256: $sha}
      and .gate.start_head == $candidate
      and .gate.end_head == $candidate
      and .gate.phase_count == $phases
      and ((.gate.phases | length) == $phases)
    ' "$report_path" >/dev/null || die "published validation report failed self-verification"

  post_report_binary_sha256="$(sha256sum -- "$packaged_binary")" ||
    die "could not rehash the packaged dialogue binary"
  post_report_binary_sha256="${post_report_binary_sha256%% *}"
  [[ "$post_report_binary_sha256" == "$packaged_binary_sha256" ]] ||
    die "packaged dialogue binary changed after report creation"
  require_exact_tree "after report creation"
  printf 'prepared live-proof handoff: %s\n' "$report_path"
fi

printf '\nlocal validation passed: %d phases on CPU %s at %s\n' \
  "$phase_number" "$validation_cpu" "$end_head"
