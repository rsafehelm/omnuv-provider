#!/usr/bin/env bash
# What the agent workspace must keep as it is split into crates (omnuv's
# modular design, A1): its members, and what the package installs.
#
#     packaging/baselines.sh members              the workspace's members
#     packaging/baselines.sh deb <file.deb>       the package's file list
#     packaging/baselines.sh workloadd <binary>   onv-workloadd's digest
#     ONV_BASELINE=write packaging/baselines.sh … records instead of comparing
#
# Each is compared with a file recorded beside this script, and a difference
# fails with the diff. A split that moves code changes neither: a member
# appears only in the change that declares it, and a file in the package only
# in the change that ships it, each re-recorded in that change on purpose.
#
#   packaging/workspace-members.txt   one package name a line, sorted, asked of
#                                     `cargo metadata`, never read from
#                                     Cargo.toml's text
#   packaging/deb-files.txt           mode and path of every file and directory
#                                     in the data archive, then each member of
#                                     the control archive; no size, owner or
#                                     date, which move with every build
#   packaging/workloadd-sha256.txt    the sha256 of the static onv-workloadd
#                                     build-deb.sh builds. It is compiled into
#                                     every inference worker's snippet
#                                     (worker.rs, WORKLOADD_SHA256), and a
#                                     changed snippet reboots the worker
#                                     (PROVIDER-31): a new digest restarts
#                                     every running inference worker once on
#                                     the first pass after the package is
#                                     installed. So it moves only when
#                                     re-recorded, in the change that moves it,
#                                     and that change says so. A new compiler
#                                     behind rust:1.98-alpine moves it too, and
#                                     is the same decision.
set -euo pipefail

# A package named relative to the caller's directory, resolved before the cd.
[ -z "${2:-}" ] || set -- "$1" "$(realpath -- "$2")"
cd "$(dirname "$0")/.."
export LC_ALL=C

compare() {
    local name="$1" actual="$2" recorded="packaging/$1"
    if [ "${ONV_BASELINE:-}" = write ]; then
        printf '%s\n' "$actual" > "$recorded"
        echo "baselines: $name recorded"
        return 0
    fi
    [ -f "$recorded" ] || { echo "baselines: $recorded is missing (ONV_BASELINE=write records it)" >&2; return 1; }
    if ! diff -u "$recorded" <(printf '%s\n' "$actual") >&2; then
        echo "baselines: $name differs from $recorded (- recorded, + now)" >&2
        return 1
    fi
    echo "baselines: $name as recorded"
}

case "${1:-}" in
members)
    # The members' names, from cargo's own reading of the workspace.
    metadata="$(cargo metadata --locked --no-deps --format-version 1)"
    actual="$(python3 -c '
import json, sys
m = json.load(sys.stdin)
members = set(m["workspace_members"])
print("\n".join(sorted(p["name"] for p in m["packages"] if p["id"] in members)))
' <<< "$metadata")"
    compare workspace-members.txt "$actual"
    ;;
deb)
    deb="${2:?usage: baselines.sh deb <file.deb>}"
    data="$(dpkg-deb --fsys-tarfile "$deb" | tar -tvf - | awk '{printf "%s", $1; for (i = 6; i <= NF; i++) printf " %s", $i; print ""}' | sort)"
    control="$(dpkg-deb --ctrl-tarfile "$deb" | tar -tf - | sed 's/^/control /' | sort)"
    compare deb-files.txt "$data"$'\n'"$control"
    ;;
workloadd)
    bin="${2:?usage: baselines.sh workloadd <binary>}"
    actual="$(sha256sum -- "$bin" | cut -d' ' -f1)"
    [[ "$actual" =~ ^[0-9a-f]{64}$ ]] || { echo "baselines: no digest for $bin" >&2; exit 1; }
    compare workloadd-sha256.txt "$actual"
    ;;
*)
    echo "usage: baselines.sh members | deb <file.deb> | workloadd <binary>" >&2
    exit 2
    ;;
esac
