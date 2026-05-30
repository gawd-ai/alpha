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

export RUSTFLAGS='-Zsanitizer=address'
export RUSTDOCFLAGS='-Zsanitizer=address'
export GAWD_SKIP_RSS_CHECK=1
# ASan output formatting: full stack symbolization on error.
export ASAN_OPTIONS="${ASAN_OPTIONS:-symbolize=1:detect_leaks=0}"

echo "[M1/asan] cargo +nightly test -p sanctum --test m1_reload_loop --target x86_64-unknown-linux-gnu -Z build-std --release"
cargo +nightly test \
    -p sanctum \
    --test m1_reload_loop \
    --target x86_64-unknown-linux-gnu \
    -Z build-std \
    --release \
    -- --nocapture

echo "[M1/asan] OK"
