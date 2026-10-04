#!/usr/bin/env bash
# The agent's checks, run on the machine at hand.
#
#     packaging/check.sh                  every section
#     packaging/check.sh package          some of them, in this order
#
# **They were .github/workflows/build.yml** until 26 September 2026, when the
# operator asked for Actions to go because its minutes had run out. The steps
# are the ones it ran, in its order, under its comments. Two things changed:
#
#   - shellcheck runs in a pinned container, since the workstation has none;
#   - the package is built into this run's own directory, not dist/. dist/ is
#     what deploy-agent.yml installs, and a check must never replace the
#     package a deploy ships.
#
# Sections, in order:
#     crate      build, test and clippy (warnings refused), then the review's
#                defect classes: semgrep's tests of its own rules, then src
#     package    shellcheck; the .deb built as a release is built; what it
#                holds; the Workload Agent static, and starting
#
# Stops at the first failure and names the step. Needs cargo and docker. In
# omnuv, `deployment/onv check` runs this as its `agent` stage.
set -euo pipefail

cd "$(dirname "$0")/.."
# **This tree's own target, whatever the caller's environment says.** A target
# shared by two worktrees of this package ran the other tree's tests, and
# three failed that were not this tree's (omnuv's TODO): cargo names a path
# package's build by its path within the workspace, the same in both trees,
# and judged the other tree's binary fresh.
export CARGO_TARGET_DIR="$PWD/target"
out="$(mktemp -d)"
current=""
finish() {
    local rc=$?
    rm -rf "$out"
    [ "$rc" -eq 0 ] || echo "FAILED: $current" >&2
    exit "$rc"
}
trap finish EXIT
step() { current="$1"; echo "== $1"; }

sections="${1:-crate,package}"
for s in ${sections//,/ }; do
    case "$s" in crate | package) ;; *) echo "check: unknown section $s" >&2; exit 2 ;; esac
done
want() { case ",$sections," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

SEMGREP_IMAGE=semgrep/semgrep:1.177.0
SHELLCHECK_IMAGE=koalaman/shellcheck:v0.11.0

if want crate; then
step "Build"
cargo build --locked --all-targets

step "Test"
cargo test --locked

step "Lints"
cargo clippy --locked --all-targets -- -D warnings

# The shapes Core's source review of 24 September 2026 found, one of
# them in this agent: the rules' own tests, then the tree.
step "The review's defect classes (semgrep), and the rules' own tests"
docker run --rm -v "$PWD:/src" -w /src "$SEMGREP_IMAGE" \
    semgrep --test --strict --metrics=off --config .semgrep/review-classes.yml .semgrep/review-classes.rs
docker run --rm -v "$PWD:/src" -w /src "$SEMGREP_IMAGE" \
    semgrep scan --strict --error --metrics=off --config .semgrep/review-classes.yml --exclude .semgrep src
fi

if want package; then
# **The package, not only the crate.** CI built and tested the crate and
# never built what is installed, so a broken maintainer script or a missing
# file reached a provider before anything noticed. This builds the .deb the
# same way a release is built and asserts what is inside it.
step "Maintainer scripts and the build script pass shellcheck"
docker run --rm -v "$PWD:/mnt:ro" -w /mnt "$SHELLCHECK_IMAGE" \
    packaging/deb/DEBIAN/postinst packaging/deb/DEBIAN/prerm packaging/deb/DEBIAN/postrm \
    packaging/build-deb.sh packaging/check.sh src/guest/onv-certificate.sh

# The script a web machine runs to fetch its project's certificate rides in
# its first-boot data, so this package never installs it: it is run instead,
# against a fake Core over TLS, every case of it (tests/guest/).
step "The guest's certificate fetch, run against a fake Core"
python3 tests/guest/onv_certificate_test.py

step "Build the package as a release is built"
ONV_PACKAGE_OUT="$out" ./packaging/build-deb.sh

# Each listing read whole before it is searched: a grep that stops at its
# first match can close a pipe the writer is still using.
step "The package holds the agent, its unit and its maintainer scripts"
deb="$out/onv-provider_current_amd64.deb"
listing="$(dpkg-deb -c "$deb")"
grep -q ' ./usr/bin/onv-provider$' <<< "$listing"
grep -q ' ./lib/systemd/system/onv-provider.service$' <<< "$listing"
for s in postinst prerm postrm; do dpkg-deb -I "$deb" "$s" > /dev/null; done
test "$(dpkg-deb -f "$deb" Version)" = "$(cat "$out/onv-provider_current.version")"

# The host timer (lifecycle phase 12). The packaged binary is run, not only
# listed: against a configuration that is not there it must refuse (exit 1,
# not the 2 of an unknown command), say so in its own file and in the audit
# log as `host-timer`, and touch nothing else.
step "The package holds the host timer, its postinst enables it, and the packaged binary runs it"
grep -q ' ./lib/systemd/system/onv-lease-expire.service$' <<< "$listing"
grep -q ' ./lib/systemd/system/onv-lease-expire.timer$' <<< "$listing"
postinst="$(dpkg-deb -I "$deb" postinst)"
grep -q '^ *systemctl enable --now onv-lease-expire.timer' <<< "$postinst"
dpkg-deb -x "$deb" "$out/root"
rc=0
OMNUV_LEASE_TIMER_LOG="$out/timer.log" OMNUV_AUDIT_LOG="$out/audit.log" \
    "$out/root/usr/bin/onv-provider" run-lease-expire --config "$out/absent.yaml" > "$out/timer.out" 2>&1 || rc=$?
test "$rc" -eq 1
grep -q 'refused' "$out/timer.log"
grep -q '"actor":"host-timer"' "$out/audit.log"

step "The Workload Agent is built, static, and starts"
kind="$(file "$out/workloadd/onv-workloadd")"
grep -q 'static' <<< "$kind"
"$out/workloadd/onv-workloadd" --check
fi
