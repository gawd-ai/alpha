#!/usr/bin/env bash
# Native-unload verification — ASan half (criterion b).
#
# Runs the 1000× reload loop with the AddressSanitizer instrumentation enabled, so any use-after-
# free, invalid-free, or double-free anywhere on the `load → handle → unload → dlclose` path
# triggers an ASan SUMMARY and crashes the test loudly. A clean run (test passes, no SUMMARY
# output) is the acceptance bound for the native unload story.
#
# **Why ASan and not valgrind here:** ASan needs source recompile, which we have — every creature in
# the reload-loop is in-tree and trusted. We get speed + sensitivity. Valgrind is the right
# second oracle when artifacts arrive from outside (shipped over the wire / AI-authored) and we can
# no longer recompile freely.
#
# **Why -Z build-std:** ASan must instrument std too, otherwise allocations crossing the std
# boundary become opaque to the sanitizer and false-negative.
#
# **RSS skip:** ASan inflates RSS by ~100 kB per dlopen cycle (shadow memory + per-allocation
# bookkeeping), so the test's RSS-stable assertion would false-positive. We set
# `GAWD_SKIP_RSS_CHECK=1` to fall through to ASan's own SUMMARY-on-error oracle, which is
# authoritative for UAF/invalid-free regardless of resident memory growth.
#
# Native-unload verification — ASan lane.

set -euo pipefail

cd "$(dirname "$0")/../../../.."

# Keep sanitizer artifacts isolated from every ordinary target graph. The generated directory is
# the exact cleanup boundary: after validating its private marker, the EXIT/signal trap removes only
# this mktemp-owned directory and never touches the workspace's broad target/ tree.
ASAN_TARGET_TRIPLE="x86_64-unknown-linux-gnu"
ASAN_TARGET_DIR=""
ASAN_TARGET_MARKER=".alpha-m1-asan-owned"

clean_asan_target() {
    local status="$?" clean_status=0
    trap - EXIT
    trap '' HUP INT TERM

    if [[ -n "${ASAN_TARGET_DIR:-}" && -d "$ASAN_TARGET_DIR" ]]; then
        echo "[M1/asan] cleaning dedicated target: $ASAN_TARGET_DIR"
        # This is the exact directory returned by mktemp below. Validate both its generated basename
        # and private marker before recursive removal; never point cleanup at target/ or a caller path.
        if [[ "${ASAN_TARGET_DIR##*/}" == alpha-m1-asan.* && \
              -f "$ASAN_TARGET_DIR/$ASAN_TARGET_MARKER" ]]; then
            rm -rf -- "$ASAN_TARGET_DIR" || clean_status=$?
        else
            echo "[M1/asan] refusing to clean unverified target path: $ASAN_TARGET_DIR" >&2
            clean_status=1
        fi
    fi
    if ((status == 0 && clean_status != 0)); then
        status="$clean_status"
    fi
    exit "$status"
}

trap clean_asan_target EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

ASAN_TARGET_DIR="$(mktemp -d "${TMPDIR:-/tmp}/alpha-m1-asan.XXXXXXXX")"
if ! : >"$ASAN_TARGET_DIR/$ASAN_TARGET_MARKER"; then
    rmdir "$ASAN_TARGET_DIR" 2>/dev/null || true
    exit 1
fi
export CARGO_TARGET_DIR="$ASAN_TARGET_DIR"
export RUSTFLAGS='-Zsanitizer=address'
export RUSTDOCFLAGS='-Zsanitizer=address'
export GAWD_SKIP_RSS_CHECK=1
# The support helper treats this as an exclusive lookup root. That guarantees the reload loop opens
# the fixture cdylibs produced by this ASan build, never stale non-instrumented default-target copies.
export GAWD_NATIVE_FIXTURE_DIR="$CARGO_TARGET_DIR/$ASAN_TARGET_TRIPLE/release/deps"
# ASan output formatting: full stack symbolization on error.
export ASAN_OPTIONS="${ASAN_OPTIONS:-symbolize=1:detect_leaks=0}"

echo "[M1/asan] dedicated target: $CARGO_TARGET_DIR"
echo "[M1/asan] cargo +nightly test --locked -p sanctum --test m1_reload_loop --target $ASAN_TARGET_TRIPLE -Z build-std --release -- --nocapture --test-threads=1"
cargo +nightly test \
    --locked \
    -p sanctum \
    --test m1_reload_loop \
    --target "$ASAN_TARGET_TRIPLE" \
    -Z build-std \
    --release \
    -- --nocapture --test-threads=1

echo "[M1/asan] OK"
