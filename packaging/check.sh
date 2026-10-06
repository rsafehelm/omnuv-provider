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
#     crate      the workspace's members as recorded; build, test and clippy
#                of every member (warnings refused), then the review's defect
#                classes: semgrep's tests of its own rules, then src and crates
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
# omnuv's own pin for its PowerShell checks (deployment/check.sh).
PWSH_IMAGE=mcr.microsoft.com/powershell:7.5-ubuntu-24.04

if want crate; then
# **Every member, not the default one.** The root package is the workspace's
# only default member, so a bare `cargo test` skipped onv-generators and its
# golden files (omnuv's modular design, A1).
step "The workspace's members are the ones recorded"
packaging/baselines.sh members

step "Build"
cargo build --locked --workspace --all-targets

step "Test"
cargo test --locked --workspace

step "Lints"
cargo clippy --locked --workspace --all-targets -- -D warnings

# The shapes Core's source review of 24 September 2026 found, one of
# them in this agent: the rules' own tests, then the tree.
step "The review's defect classes (semgrep), and the rules' own tests"
docker run --rm -v "$PWD:/src" -w /src "$SEMGREP_IMAGE" \
    semgrep --test --strict --metrics=off --config .semgrep/review-classes.yml .semgrep/review-classes.rs
docker run --rm -v "$PWD:/src" -w /src "$SEMGREP_IMAGE" \
    semgrep scan --strict --error --metrics=off --config .semgrep/review-classes.yml --exclude .semgrep src crates
fi

if want package; then
# **The package, not only the crate.** CI built and tested the crate and
# never built what is installed, so a broken maintainer script or a missing
# file reached a provider before anything noticed. This builds the .deb the
# same way a release is built and asserts what is inside it.
step "Maintainer scripts and the build script pass shellcheck"
docker run --rm -v "$PWD:/mnt:ro" -w /mnt "$SHELLCHECK_IMAGE" \
    packaging/deb/DEBIAN/postinst packaging/deb/DEBIAN/prerm packaging/deb/DEBIAN/postrm \
    packaging/build-deb.sh packaging/check.sh packaging/baselines.sh crates/onv-generators/guest/onv-certificate.sh \
    tests/opening/nft_test.sh tests/opening/in_container.sh \
    tests/logs/rotate_test.sh tests/logs/in_container.sh

# The script a web machine runs to fetch its project's certificate rides in
# its first-boot data, so this package never installs it: it is run instead,
# against a fake Core over TLS, every case of it (tests/guest/).
step "The guest's certificate fetch, run against a fake Core"
python3 tests/guest/onv_certificate_test.py

# A Windows machine's first-boot script rides on its drive too
# (guest_windows.rs): the golden copy, run under pwsh against stand-ins for
# Windows' own commands, every case of it (tests/windows/harness.ps1). The
# verdict is the harness's exit status; its last line says so as well.
step "A Windows machine's first boot, run under pwsh"
docker run --rm --network none -v "$PWD:/a:ro" -w /a "$PWSH_IMAGE" \
    pwsh -NoLogo -NoProfile -NonInteractive -File /a/tests/windows/harness.ps1 > "$out/windows.log" 2>&1 \
    || { cat "$out/windows.log"; exit 1; }
test "$(tail -1 "$out/windows.log")" = "all checks passed"

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

# Every file, not only the ones named above: a split into crates moves
# source, never what is installed (omnuv's modular design, A1).
step "The package's file list is the one recorded"
packaging/baselines.sh deb "$deb"

# The digest the agent compiles into every inference worker's snippet: a new
# one reboots every running worker once (PROVIDER-31), so it moves only when
# re-recorded on purpose (A1b, where a pure move changed it unnoticed).
step "onv-workloadd's digest is the one recorded"
packaging/baselines.sh workloadd "$out/workloadd/onv-workloadd"

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

# The provider opening (opening.rs): its units in the package, enabled by its
# postinst, its table removed by its prerm; then the packaged binary applies
# and removes the rules in a disposable container, against the egress policy
# omnuv's play installs (tests/opening/).
step "The package holds the opening's applier, and its rules do what they say in a container"
grep -q ' ./lib/systemd/system/onv-opening.service$' <<< "$listing"
grep -q ' ./lib/systemd/system/onv-opening.path$' <<< "$listing"
grep -q '^ *systemctl enable --now onv-opening.path' <<< "$postinst"
grep -q 'nft delete table inet onv_opening' <<< "$(dpkg-deb -I "$deb" prerm)"
tests/opening/nft_test.sh "$out/root/usr/bin/onv-provider" > "$out/opening.log" 2>&1 || { cat "$out/opening.log"; exit 1; }
grep -q '^opening: every case passed$' "$out/opening.log"

# Supervision and log bounds (omnuv's modular design, A4): the journal's cap
# and the logs' rotation shipped as conffiles; then, in a disposable
# container, logrotate rotates /var/log/onv with the package's own file, the
# packaged binary appends to the new audit log, and systemd loads the agent's
# unit with nothing to say (tests/logs/).
step "The package caps the journal and rotates its logs, and systemd loads its unit"
grep -q ' ./etc/logrotate.d/onv-provider$' <<< "$listing"
grep -q ' ./etc/systemd/journald.conf.d/60-onv-provider.conf$' <<< "$listing"
conffiles="$(dpkg-deb -I "$deb" conffiles)"
grep -qx '/etc/logrotate.d/onv-provider' <<< "$conffiles"
grep -qx '/etc/systemd/journald.conf.d/60-onv-provider.conf' <<< "$conffiles"
tests/logs/rotate_test.sh "$out/root" > "$out/logs.log" 2>&1 || { cat "$out/logs.log"; exit 1; }
grep -q '^logs: every case passed$' "$out/logs.log"

step "The Workload Agent is built, static, and starts"
kind="$(file "$out/workloadd/onv-workloadd")"
grep -q 'static' <<< "$kind"
"$out/workloadd/onv-workloadd" --check
fi
