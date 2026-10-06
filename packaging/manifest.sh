#!/usr/bin/env bash
# Holds the package's manifest to what was built (omnuv's modular design, A2).
#
#     packaging/manifest.sh <file.deb> <onv-workloadd> [<manifest beside the package>]
#
# The manifest, /usr/share/onv-provider/manifest.json, names the onv-workloadd
# this package was built with. It passes only when:
#
#   - it is in the package, one JSON object with exactly the keys package,
#     version and workloadd_sha256;
#   - package is onv-provider and version is the package's own Version;
#   - workloadd_sha256 is 64 lowercase hex digits, and is the sha256 of the
#     onv-workloadd binary given here, the one the build served beside it;
#   - the agent in the package carries that same digest, which it compiles
#     into every inference worker's snippet (worker.rs, WORKLOADD_SHA256);
#   - the copy written beside the package, when given, is byte for byte the
#     packaged one.
#
# Each refusal names what differed. tests/packaging/manifest_test.sh runs it
# against packages that are right and against each way of being wrong.
set -euo pipefail
export LC_ALL=C

deb="${1:?usage: manifest.sh <file.deb> <onv-workloadd> [<manifest beside>]}"
bin="${2:?usage: manifest.sh <file.deb> <onv-workloadd> [<manifest beside>]}"
beside="${3:-}"
path=usr/share/onv-provider/manifest.json

fail() { echo "manifest: $*" >&2; exit 1; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
dpkg-deb -x "$deb" "$work/root"
[ -f "$work/root/$path" ] || fail "the package holds no /$path"

# Read whole, the package's own Version passed in: one parser, which refuses
# anything but the object described above.
digest="$(python3 - "$work/root/$path" "$(dpkg-deb -f "$deb" Version)" <<'PY'
import json, re, sys
path, version = sys.argv[1], sys.argv[2]
try:
    m = json.load(open(path))
except ValueError as e:
    sys.exit(f"manifest: /{path.split('/root/', 1)[1]} is not JSON: {e}")
if not isinstance(m, dict) or set(m) != {"package", "version", "workloadd_sha256"}:
    keys = sorted(m) if isinstance(m, dict) else type(m).__name__
    sys.exit(f"manifest: keys are {keys}, not package, version, workloadd_sha256")
if m["package"] != "onv-provider":
    sys.exit(f"manifest: package is {m['package']!r}, not 'onv-provider'")
if m["version"] != version:
    sys.exit(f"manifest: version is {m['version']!r}, the package's is {version!r}")
d = m["workloadd_sha256"]
if not isinstance(d, str) or not re.fullmatch(r"[0-9a-f]{64}", d):
    sys.exit(f"manifest: workloadd_sha256 {d!r} is not 64 lowercase hex digits")
print(d)
PY
)"

built="$(sha256sum -- "$bin" | cut -d' ' -f1)"
[ "$digest" = "$built" ] || fail "workloadd_sha256 is $digest, the built onv-workloadd's is $built"

# The agent's copy is a string literal in its binary: counted, never assumed.
agent="$work/root/usr/bin/onv-provider"
[ -f "$agent" ] || fail "the package holds no /usr/bin/onv-provider"
grep -qaF -- "$digest" "$agent" || fail "the packaged agent does not carry $digest"

if [ -n "$beside" ]; then
    cmp -s -- "$work/root/$path" "$beside" || fail "$beside is not the packaged manifest"
fi
echo "manifest: onv-workloadd $digest, in the package, the agent and the build"
