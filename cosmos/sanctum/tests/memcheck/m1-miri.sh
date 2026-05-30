#!/usr/bin/env bash
# Native-unload verification — Miri half (criterion c).
#
# Miri does not run dlopen/FFI, so it cannot trace through the real `dlclose` path. What it CAN do
# is prove that the kernel's pure routing/revocation logic (the `register → deregister → route`
# state machine in `aether::Router`) is sound under the Rust memory model — no data races, no
# touching dropped memory, no aliasing violations.
#
# The revocation test `aether::tests::deregister_makes_routing_fail_cleanly_not_ub` is intentionally
# FFI-free: just register, deregister, send, assert NoSuchModule. If the routing table's
# read-side ever raced with deregister to produce a dangling reference, Miri would catch it here
# before the real `dlclose` path could turn the race into UB.
#
# Native-unload verification — Miri lane.

set -euo pipefail

cd "$(dirname "$0")/../../../.."

echo "[M1/miri] cargo +nightly miri test -p aether deregister_makes_routing_fail_cleanly_not_ub"
cargo +nightly miri test -p aether deregister_makes_routing_fail_cleanly_not_ub

echo "[M1/miri] OK"
