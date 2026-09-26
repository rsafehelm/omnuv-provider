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
    packaging/build-deb.sh packaging/check.sh

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

step "The Workload Agent is built, static, and starts"
kind="$(file "$out/workloadd/onv-workloadd")"
grep -q 'static' <<< "$kind"
"$out/workloadd/onv-workloadd" --check
fi
