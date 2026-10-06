#!/usr/bin/env bash
# **An onv-opening-only change leaves the agent's bytes alone** (omnuv's
# modular design, A5), measured with two real builds rather than assumed.
#
#     tests/packaging/reproducible_test.sh [<commit>]
#
# postinst restarts a unit when its bytes move, so A5 holds only if a rebuild
# with an edit to onv-opening's source alone gives an onv-provider binary
# byte-identical to the one before. restart_test.sh fakes that by repacking
# one file; this builds it. Two fresh clones of <commit> (HEAD by default),
# the second with one string in src/bin/onv-opening.rs changed, each built
# from nothing by packaging/build-deb.sh, as a release is built: onv-provider,
# onv-lease-expire and onv-workloadd must be byte-identical across the two,
# and onv-opening and the package version must differ.
#
# Two release builds from an empty target directory: minutes, not seconds,
# which is why packaging/check.sh does not run it on every check. Run it after
# a change to the build (build-deb.sh, the toolchain image, Cargo.toml's
# profile, a #[path] or a module shared by the binaries).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
commit="$(git -C "$ROOT" rev-parse "${1:-HEAD}")"
base="${TMPDIR:-/tmp}/onvt-repro"
# A run that died leaves its clones, root-owned by the build's container.
if [ -e "$base" ]; then
    echo "an earlier run left $base; remove it with:" >&2
    echo "    docker run --rm -v $(dirname "$base"):/p debian:trixie-slim rm -rf /p/onvt-repro" >&2
    exit 1
fi
mkdir -p "$base"
cleanup() {
    docker run --rm -v "$base:/w" debian:trixie-slim sh -c 'rm -rf /w/a /w/b' >/dev/null 2>&1 || true
    rmdir "$base" 2>/dev/null || true
}
trap cleanup EXIT

for side in a b; do
    git clone -q --no-local "$ROOT" "$base/$side"
    git -C "$base/$side" checkout -q --detach "$commit"
done
# One string the binary prints: a change that must reach onv-opening's bytes.
f="$base/b/src/bin/onv-opening.rs"
before="$(sha256sum "$f")"
sed -i 's/^onv-opening - the Omnuv provider opening.s applier$/onv-opening - the Omnuv provider opening applier, edited/' "$f"
if [ "$before" = "$(sha256sum "$f")" ]; then
    echo "FAIL  the edit to onv-opening's source changed nothing" >&2
    exit 1
fi

for side in a b; do
    echo "== building $side"
    if ! ONV_PACKAGE_OUT="$base/$side/dist" "$base/$side/packaging/build-deb.sh" > "$base/$side.log" 2>&1; then
        cat "$base/$side.log"
        echo "FAIL  the build of $side failed" >&2
        exit 1
    fi
done

bad=0
sum() { sha256sum "$1" | cut -d' ' -f1; }
for b in release/onv-provider release/onv-lease-expire musl/release/onv-workloadd; do
    sa="$(sum "$base/a/target/$b")" sb="$(sum "$base/b/target/$b")"
    if [ "$sa" = "$sb" ]; then
        echo "ok    $(basename "$b") is byte-identical: $sa"
    else
        echo "FAIL  $(basename "$b") moved with onv-opening's source: $sa, then $sb"; bad=1
    fi
done
sa="$(sum "$base/a/target/release/onv-opening")" sb="$(sum "$base/b/target/release/onv-opening")"
if [ "$sa" != "$sb" ]; then
    echo "ok    onv-opening moved: $sa, then $sb"
else
    echo "FAIL  onv-opening did not move with its own source: $sa"; bad=1
fi
va="$(cat "$base/a/dist/onv-provider_current.version")" vb="$(cat "$base/b/dist/onv-provider_current.version")"
if [ "$va" != "$vb" ]; then
    echo "ok    the version moved: $va, then $vb"
else
    echo "FAIL  the version did not move: $va"; bad=1
fi
if [ "$bad" -ne 0 ]; then
    echo "reproducible: some cases failed"
    exit 1
fi
echo "reproducible: every case passed"
