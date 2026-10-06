#!/usr/bin/env bash
# packaging/manifest.sh against packages made here: one that is right, which
# it must pass, and one for each way of being wrong, each of which it must
# refuse with its own reason. Fixtures, not a release build: the packages
# hold stand-in files, so this proves the check, and check.sh then runs the
# check on the package it really built.
#
#     tests/packaging/manifest_test.sh        last line "manifest: every case passed"
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")/../.."

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# A stand-in onv-workloadd, and its digest.
printf 'not really onv-workloadd\n' > "$work/workloadd"
good="$(sha256sum "$work/workloadd" | cut -d' ' -f1)"
other="$(printf 'another build\n' | sha256sum | cut -d' ' -f1)"

# fixture <name> <manifest text, or "-" for none> [<digest the agent carries>] [version]
fixture() {
    local name="$1" manifest="$2" carried="${3:-$good}" version="${4:-0.5.0+gabc1234}"
    local root
    root="$work/$name"
    mkdir -p "$root/DEBIAN" "$root/usr/bin"
    printf 'Package: onv-provider\nVersion: %s\nArchitecture: amd64\nMaintainer: test\nDescription: fixture\n' \
        "$version" > "$root/DEBIAN/control"
    printf 'agent bytes\0%s\0more agent bytes\n' "$carried" > "$root/usr/bin/onv-provider"
    if [ "$manifest" != - ]; then
        mkdir -p "$root/usr/share/onv-provider"
        printf '%s\n' "$manifest" > "$root/usr/share/onv-provider/manifest.json"
        printf '%s\n' "$manifest" > "$work/$name.beside.json"
    fi
    dpkg-deb --root-owner-group --build "$root" "$work/$name.deb" > /dev/null
}
right() { printf '{"package":"onv-provider","version":"%s","workloadd_sha256":"%s"}' "${2:-0.5.0+gabc1234}" "$1"; }

failures=0
# expect <name> pass|<reason grep> [beside file]
expect() {
    local name="$1" want="$2" rc=0
    local beside="${3-$work/$name.beside.json}"
    local args=("$work/$name.deb" "$work/workloadd")
    [ ! -f "$beside" ] || args+=("$beside")
    packaging/manifest.sh "${args[@]}" > "$work/$name.out" 2>&1 || rc=$?
    if [ "$want" = pass ]; then
        if [ "$rc" -ne 0 ]; then echo "FAIL $name: refused: $(cat "$work/$name.out")"; failures=$((failures + 1)); return; fi
    elif [ "$rc" -eq 0 ]; then
        echo "FAIL $name: passed, expected a refusal naming '$want'"; failures=$((failures + 1)); return
    elif ! grep -q -- "$want" "$work/$name.out"; then
        echo "FAIL $name: refused for another reason: $(cat "$work/$name.out")"; failures=$((failures + 1)); return
    fi
    echo "ok   $name"
}

fixture right "$(right "$good")"
expect right pass

fixture no-manifest -
expect no-manifest "holds no /usr/share/onv-provider/manifest.json"

fixture other-digest "$(right "$other")" "$other"
expect other-digest "the built onv-workloadd's is $good"

fixture upper-hex "$(right "${good^^}")" "${good^^}"
expect upper-hex "not 64 lowercase hex digits"

fixture short-hex "$(right "${good:0:63}")" "${good:0:63}"
expect short-hex "not 64 lowercase hex digits"

fixture not-json "workloadd_sha256=$good"
expect not-json "is not JSON"

fixture extra-key "{\"package\":\"onv-provider\",\"version\":\"0.5.0+gabc1234\",\"workloadd_sha256\":\"$good\",\"x\":1}"
expect extra-key "keys are"

fixture wrong-version "$(right "$good" 0.4.0)"
expect wrong-version "the package's is '0.5.0+gabc1234'"

fixture wrong-package "{\"package\":\"omnuv-provider\",\"version\":\"0.5.0+gabc1234\",\"workloadd_sha256\":\"$good\"}"
expect wrong-package "not 'onv-provider'"

fixture agent-differs "$(right "$good")" "$other"
expect agent-differs "the packaged agent does not carry $good"

fixture beside-differs "$(right "$good")"
printf '%s\n' "$(right "$other")" > "$work/beside-differs.beside.json"
expect beside-differs "is not the packaged manifest"

# Without a beside copy the package alone is held, and still passes.
expect right pass ""

if [ "$failures" -ne 0 ]; then
    echo "manifest: $failures case(s) failed"
    exit 1
fi
echo "manifest: every case passed"
