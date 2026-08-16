#!/usr/bin/env bash
# Foreign-bytes verification — Valgrind half (second independent oracle on foreign bytes).
#
# **Why valgrind for the wire path.** ASan is the right oracle when every creature in the reload
# loop is in-tree source the build can instrument. The substrate also loads artifacts that
# *arrived over the wire* — `m2_two_node` ships an `echo-daemon.so` from A to B, B spills it to a
# tempfile, dlopens it, runs it. From B's POV those bytes are foreign: B can't recompile them with
# ASan instrumentation. Valgrind needs no recompile (instruments at runtime), so it is the right
# oracle for the ship-and-load path, and the AI-authoring path reuses this exact harness.
#
# **What this catches.** memcheck (the default tool) catches: use-after-free, uninitialized
# reads, double-free, invalid free, leaks reachable from the test process at exit. It runs the
# real `m2_two_node` end-to-end — handshake, fetch, spill-to-tempfile, dlopen, route, reply —
# with both kernels in-process, so any UB anywhere on the *received-bytes* path fails the test.
#
# **What this does NOT catch.** Data races (helgrind / drd would, but they're noisy on Rust's
# standard concurrency primitives; we'll add them when they pay rent). Architectural soundness
# of the FFI seam (Miri owns that lane, separately, on the pure-logic revocation test).
#
# **Suppressions.** Some libloading / libc / dynamic-linker patterns produce known false
# positives — `dlclose` doesn't reclaim every bit of glibc-internal state, ed25519's RNG calls
# can show as "still reachable", etc. The suppression file `.valgrind.supp` next to this script
# starts empty; we'll add curated entries the first time CI flags a known-benign pattern.
#
# Native-unload verification — Valgrind lane (the third split: Miri on pure logic, ASan for
# trusted-source UAF, valgrind for foreign-bytes UAF).

set -euo pipefail

cd "$(dirname "$0")/../../../.."

# Locate the m2_two_node test binary. `cargo test --no-run` builds the test and its fixture
# cdylib dev-dependencies from the same source graph, so a preceding `cargo build --workspace`
# would only duplicate a much broader compile and another set of artifacts. We then re-invoke the
# exact binary under valgrind so the test's setup/teardown runs in the instrumented context.
# `--quiet` suppresses the "compiling" lines so the path is parsable. Root Cargo configuration
# keeps this forgotten/manual invocation to one build job with incremental output disabled.
echo "[M2/valgrind] cargo test --locked --no-run -p sanctum --test m2_two_node"
TEST_BIN=$(cargo test --locked --no-run -p sanctum --test m2_two_node --message-format=json 2>/dev/null \
    | jq -r 'select(.profile.test == true and (.target.name == "m2_two_node")) | .executable' \
    | tail -n1)

if [[ -z "${TEST_BIN}" || ! -x "${TEST_BIN}" ]]; then
    echo "[M2/valgrind] could not locate m2_two_node test binary"
    exit 1
fi
echo "[M2/valgrind] test binary: ${TEST_BIN}"

SUPP="$(pwd)/cosmos/sanctum/tests/memcheck/.valgrind.supp"
if [[ -f "${SUPP}" ]]; then
    SUPP_ARG="--suppressions=${SUPP}"
else
    SUPP_ARG=""
fi

# `--error-exitcode=1` makes any memcheck error fail the script (otherwise valgrind always
# exits 0 — its job is reporting, not gating). `--errors-for-leak-kinds=definite` lets
# "still reachable" reports through without failing CI; only `definite` leaks (genuinely
# unreachable allocations) gate. `--track-fds=yes` surfaces file-descriptor leaks (transport's
# tempfiles, listener sockets) which are interesting in their own right.
#
# `GAWD_SLOW_TEST=30` tells the test to scale every wall-clock budget by 30× — valgrind slows
# execution roughly 10–50× on memcheck, and 33 MB of JSON deserialization (a fetched artifact
# crossing the wire) is the heaviest single operation. Without this the publish/fetch timeouts
# fire long before the operations complete, the test FAILs, and we can't distinguish "real bug"
# from "valgrind is slow."
#
# **Honest limit:** even 30× isn't always enough for the full ship→fetch→admit→load path because
# each 33 MB JSON parse takes ~3 min per round-trip under memcheck and the cross-node fetch retries
# amplify it. The first run's verdict on the paths that DO complete (publish, transport setup,
# partial wire transit) is the authoritative signal here; the follow-up is a dedicated
# `m2_valgrind_smoke` test using a tiny artifact so memcheck covers the full path in <1 min.
export GAWD_SLOW_TEST=30

echo "[M2/valgrind] running test under memcheck (slow: ~2–10 min including JSON-of-33MB parses)"
valgrind \
    --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=definite \
    --errors-for-leak-kinds=definite \
    --error-exitcode=1 \
    --track-fds=yes \
    --num-callers=30 \
    ${SUPP_ARG} \
    "${TEST_BIN}" --test-threads=1 --nocapture

echo "[M2/valgrind] OK"
